%% The worker: its process body (one warmup iteration, the warmup
%% barrier, the main loop), one iteration, the session pump loop the
%% stream shape drives, and the round-trip comparison that decides
%% between a worker error and a data mismatch.

-module(loop_worker).

-export([shape_name/1, parse_shape/1, start/4]).

-include("loop.hrl").

%% One worker's private state: its plaintext, its generator, its
%% counters, and the error it stopped on.
-record(w, {
    id,
    run,
    plaintext = <<>>,
    payload_mode = fixed,
    seeded = false,
    rng = 0,
    iters = 0,
    bytes_enc = 0,
    bytes_dec = 0,
    nanos_enc = 0,
    nanos_dec = 0,
    failed = false,
    error = ""
}).

-spec shape_name(atom()) -> string().
shape_name(stream) -> "stream";
shape_name(message) -> "message";
shape_name(stream_one_shot) -> "stream_one_shot";
shape_name(both) -> "both".

-spec parse_shape(string()) -> {ok, atom()} | error.
parse_shape("stream") -> {ok, stream};
parse_shape("message") -> {ok, message};
parse_shape("stream_one_shot") -> {ok, stream_one_shot};
parse_shape("both") -> {ok, both};
parse_shape(_) -> error.

%% Concurrency mode. This binding runs shared-handle: BEAM processes
%% call the NIF concurrently on dirty schedulers, and one Pipeline
%% handle serves all of them, which the shared library permits after
%% construction. --goroutines is therefore the process count verbatim
%% and is never clamped. The handles are not captured here: every
%% iteration receives them with its read-lock grant, because a blob
%% reopen replaces them mid-run.
-spec start(#run{}, non_neg_integer(), binary(), pid()) -> pid().
start(Run, Id, Plaintext, Parent) ->
    Cfg = Run#run.cfg,
    W0 = #w{id = Id, run = Run, plaintext = Plaintext,
            payload_mode = Cfg#cfg.payload_mode,
            seeded = Cfg#cfg.seed =/= 0,
            rng = loop_payload:seed_worker(Cfg#cfg.seed, Id)},
    spawn(fun() -> body(W0, Parent) end).

%% The worker process body: one warmup iteration, the warmup barrier,
%% then the main loop until a stop is requested or the fixed
%% per-worker iteration budget (warmup included) is spent. A failing
%% warmup still passes both barriers so the launcher never waits on a
%% worker that has already given up.
body(W0, Parent) ->
    %% Warmup iteration — counted in the totals; its completion feeds
    %% the post-warmup baselines.
    W1 = iterate(W0, 0),
    Parent ! {warmup_done, self()},
    receive release -> ok end,
    W2 = case W1#w.failed of
             true -> W1;
             false -> main_loop(W1, 1)
         end,
    Parent ! {worker_done, self(), stats(W2, loop_size:now_ns())}.

main_loop(W, Iter) ->
    Run = W#w.run,
    Cfg = Run#run.cfg,
    Budget = Cfg#cfg.iterations,
    case (Budget > 0 andalso Iter >= Budget)
        orelse loop_state:stop_requested(Run#run.flags) of
        true -> W;
        false ->
            W1 = iterate(W, Iter),
            case W1#w.failed of
                true -> W1;
                false ->
                    case loop_ops:maintenance(Run, W1#w.id, Iter) of
                        ok -> main_loop(W1, Iter + 1);
                        {error, Text} -> fail(W1, Text)
                    end
            end
    end.

stats(W, FinishNs) ->
    #wstats{id = W#w.id, iters = W#w.iters,
            bytes_enc = W#w.bytes_enc, bytes_dec = W#w.bytes_dec,
            nanos_enc = W#w.nanos_enc, nanos_dec = W#w.nanos_dec,
            finish_ns = FinishNs,
            failed = W#w.failed, error = W#w.error}.

%% Records the worker's error text (first error wins) and requests a
%% stop of the whole run.
fail(W, Text) ->
    loop_state:request_stop((W#w.run)#run.flags),
    case W#w.failed of
        true -> W;
        false -> W#w{failed = true, error = Text}
    end.

%% ------------------------------------------------------------------
%% One iteration
%% ------------------------------------------------------------------

%% One iteration. In order: refill the plaintext under rotating mode;
%% take the read lock; pick the surface; encrypt (timed); decrypt
%% (timed); compare the round-trip with the plaintext; bump the
%% counters; release the lock. The whole round-trip runs under the
%% read lock so handle-mutating maintenance (rekey, blob reopen) never
%% lands between an encrypt and its matching decrypt — maintenance
%% runs after this returns, from the worker loop. The handles arrive
%% with the grant rather than from the worker's own state, because a
%% blob reopen swaps them.
iterate(W0, Iter) ->
    W = refill(W0, Iter),
    case W#w.failed of
        true -> W;
        false ->
            Run = W#w.run,
            {StreamPipe, MsgPipe} = loop_state:read_lock(Run#run.state),
            try round_trip(W, Iter, StreamPipe, MsgPipe) of
                {ok, W1} -> W1;
                {error, Text} -> fail(W, Text)
            after
                loop_state:read_unlock(Run#run.state)
            end
    end.

refill(W = #w{payload_mode = rotating}, _Iter) ->
    {Buf, Rng} = loop_payload:fill(rotating, W#w.seeded, W#w.rng,
                                   byte_size(W#w.plaintext)),
    W#w{plaintext = Buf, rng = Rng};
refill(W, _Iter) ->
    W.

round_trip(W, Iter, StreamPipe, MsgPipe) ->
    Shape = select_shape((W#w.run)#run.cfg, Iter),
    Plain = W#w.plaintext,
    case encrypt(Shape, StreamPipe, MsgPipe, Plain) of
        {error, What, Status, Detail} ->
            {error, cipher_error(W, Iter, Shape, "encrypt", What, Status, Detail)};
        {ok, Wire, EncNs} ->
            case decrypt(Shape, StreamPipe, MsgPipe, Wire) of
                {error, What, Status, Detail} ->
                    {error, cipher_error(W, Iter, Shape, "decrypt", What, Status, Detail)};
                {ok, Got, DecNs} ->
                    compare(W, Iter, Shape, Plain, Got),
                    {ok, W#w{iters = W#w.iters + 1,
                             bytes_enc = W#w.bytes_enc + byte_size(Plain),
                             bytes_dec = W#w.bytes_dec + byte_size(Got),
                             nanos_enc = W#w.nanos_enc + EncNs,
                             nanos_dec = W#w.nanos_dec + DecNs}}
            end
    end.

%% Shape dispatch. message is one whole-buffer call on the Single
%% Message Pipeline; stream_one_shot is one whole-buffer call on the
%% streaming Pipeline (the C ABI's ITB_Triple_EncryptStream, which
%% routes to the same one-shot stream entry the Go harness calls by
%% name); stream opens a session on the same streaming Pipeline and
%% drives the chunk loop from here. Under both the three rotate by
%% iteration number so the session path and the whole-buffer path
%% alternate on one handle inside every worker — the cross-path
%% state-reuse hazard this harness exists to catch.
select_shape(#cfg{shape = both}, Iter) ->
    case Iter rem 3 of
        0 -> stream;
        1 -> message;
        _ -> stream_one_shot
    end;
select_shape(#cfg{shape = Shape}, _Iter) ->
    Shape.

encrypt(stream, StreamPipe, _MsgPipe, Plain) ->
    timed(fun() -> pump(StreamPipe, encrypt, Plain) end);
encrypt(stream_one_shot, StreamPipe, _MsgPipe, Plain) ->
    timed(fun() -> one_call(itb3:encrypt_stream_one_shot(StreamPipe, Plain)) end);
encrypt(message, _StreamPipe, MsgPipe, Plain) ->
    timed(fun() -> one_call(itb3:encrypt_message(MsgPipe, Plain)) end).

decrypt(stream, StreamPipe, _MsgPipe, Wire) ->
    timed(fun() -> pump(StreamPipe, decrypt, Wire) end);
decrypt(stream_one_shot, StreamPipe, _MsgPipe, Wire) ->
    timed(fun() -> one_call(itb3:decrypt_stream_one_shot(StreamPipe, Wire)) end);
decrypt(message, _StreamPipe, MsgPipe, Wire) ->
    timed(fun() -> one_call(itb3:decrypt_message(MsgPipe, Wire)) end).

timed(Fun) ->
    T0 = loop_size:now_ns(),
    case Fun() of
        {ok, Out} -> {ok, Out, loop_size:now_ns() - T0};
        Error -> Error
    end.

%% A whole-buffer call names itself as the failing call, so the error
%% text carries the direction once rather than twice.
one_call({ok, Out}) -> {ok, Out};
one_call({error, {Status, Detail}}) -> {error, same, Status, Detail}.

%% ------------------------------------------------------------------
%% Stream pump
%% ------------------------------------------------------------------

%% Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
%% and ITB drives the chunk loop internally; the binding's session
%% surface has no reader / writer entry, so the caller drives it: open
%% a session, feed slices of at most 1 MiB, drain whatever the session
%% has produced after every write (a read before end never blocks),
%% end, then drain until the session reports finished (after end, a
%% read on an empty spool blocks until the terminal bytes arrive). The
%% loop is written here rather than delegated to the binding's pump
%% convenience so it stands in the utility, at the same place, in
%% every language.
pump(Pipe, Direction, Src) ->
    Begin = case Direction of
                encrypt -> itb3:encrypt_stream(Pipe);
                decrypt -> itb3:decrypt_stream(Pipe)
            end,
    case Begin of
        {error, {Status, Detail}} ->
            {error, "StreamBegin", Status, Detail};
        {ok, Session} ->
            Result = feed(Session, Src, []),
            itb3:stream_free(Session),
            Result
    end.

feed(Session, <<>>, Acc) ->
    case itb3:stream_end(Session) of
        {error, {Status, Detail}} -> {error, "StreamEnd", Status, Detail};
        ok -> drain_final(Session, Acc)
    end;
feed(Session, Src, Acc) ->
    N = min(byte_size(Src), ?LOOP_PUMP_SLICE),
    <<Slice:N/binary, Rest/binary>> = Src,
    case itb3:stream_write(Session, Slice) of
        {error, {Status, Detail}} -> {error, "StreamWrite", Status, Detail};
        ok ->
            case drain_ready(Session, Acc) of
                {error, _, _, _} = Err -> Err;
                {ok, Acc1} -> feed(Session, Rest, Acc1)
            end
    end.

drain_ready(Session, Acc) ->
    case itb3:stream_read(Session, ?LOOP_PUMP_SLICE) of
        {error, {Status, Detail}} -> {error, "StreamRead", Status, Detail};
        {ok, <<>>, _Finished} -> {ok, Acc};
        {ok, Data, _Finished} -> drain_ready(Session, [Data | Acc])
    end.

drain_final(Session, Acc) ->
    case itb3:stream_read(Session, ?LOOP_PUMP_SLICE) of
        {error, {Status, Detail}} -> {error, "StreamRead", Status, Detail};
        {ok, Data, true} -> {ok, iolist_to_binary(lists:reverse([Data | Acc]))};
        {ok, Data, false} -> drain_final(Session, [Data | Acc])
    end.

%% ------------------------------------------------------------------
%% Failure model
%% ------------------------------------------------------------------

%% Failure model. A cipher call that returns a non-OK status is a
%% worker error: it is recorded, the run is asked to stop, the other
%% workers finish their in-flight iteration, and the error is listed
%% in the summary with the FAIL verdict. A round-trip that returns OK
%% with different bytes is a data mismatch: the process terminates
%% here, without summary or cleanup, because the Pipeline state that
%% produced the wrong bytes is the evidence and nothing that runs
%% afterwards may touch it.
compare(_W, _Iter, _Shape, Plain, Plain) ->
    ok;
compare(W, Iter, Shape, Plain, Got) ->
    Off = binary:longest_common_prefix([Plain, Got]),
    Text = io_lib:format(
             "loop: DATA MISMATCH g~B iter ~B shape=~s: want ~B bytes, got ~B bytes, "
             "first difference at offset ~B: want ~s got ~s~n",
             [W#w.id, Iter, shape_name(Shape), byte_size(Plain), byte_size(Got),
              Off, hex_window(Plain, Off), hex_window(Got, Off)]),
    loop_main:emit(standard_error, Text),
    erlang:halt(3, [{flush, true}]).

%% Up to 16 bytes from Off as lowercase hex, or "-" when the buffer
%% has no bytes there.
hex_window(Bin, Off) when Off >= byte_size(Bin) ->
    "-";
hex_window(Bin, Off) ->
    N = min(16, byte_size(Bin) - Off),
    binary_to_list(binary:encode_hex(binary:part(Bin, Off, N), lowercase)).

cipher_error(W, Iter, Shape, Direction, same, Status, Detail) ->
    lists:flatten(io_lib:format("g~B iter ~B shape=~s: ~s: ~s",
                                [W#w.id, Iter, shape_name(Shape), Direction,
                                 loop_main:status_text(Status, Detail)]));
cipher_error(W, Iter, Shape, Direction, What, Status, Detail) ->
    lists:flatten(io_lib:format("g~B iter ~B shape=~s: ~s: ~s: ~s",
                                [W#w.id, Iter, shape_name(Shape), Direction, What,
                                 loop_main:status_text(Status, Detail)])).
