%% bench_stream — stream-pump throughput vs plaintext size (Streaming
%% Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Each iteration runs a
%% full incremental session (begin -> write 1 MiB slices, draining the
%% spool after each write -> end -> drain until finished -> free).
%%
%% Env-var overrides identical to bench_message (defaults match the
%% root Go BENCH3.md pin):
%%
%%   ITB_PROFILE        streaming-noaead-triple-v1
%%   ITB_INNER_HASH     areion512
%%   ITB_KEY_BITS       1024
%%   ITB_NONCE_BITS     512
%%   ITB_WITH_PARALLAX  false
%%   ITB_WITH_WRAPPER   false
%%   ITB_BENCH_MIN_SEC  5
%%
%% Invocation (from bindings/erlang, after ./build.sh):
%%   erlc -o bench bench/bench_stream.erl
%%   erl -noshell -pa _build/default/lib/itb/ebin -pa bench \
%%       -run bench_stream main run -run init stop

-module(bench_stream).

-export([main/1]).

-define(MIN_ITERS, 3).
-define(PUMP_BUF, 1 bsl 20).

main(_Args) ->
    %% Bench-scale allocation churn leaks Go scratch heap unboundedly
    %% without a soft memory cap + aggressive GC; the return values
    %% report the previous settings, not an error.
    _ = itb:set_memory_limit(512 bsl 20), %% 512 MiB soft cap
    _ = itb:set_gc_percent(20),           %% aggressive GC

    Profile = env("ITB_PROFILE", "streaming-noaead-triple-v1"),
    {ok, Pipe} = itb:init(Profile, bench_opts()),
    io:format("~-17s ~-8s ~s~n", ["bench", "size", "mb_per_sec"]),
    lists:foreach(
      fun(Size) ->
              %% CSPRNG-fill so plaintext content matches the root Go
              %% bench (crypto/rand). Not in the timing loop.
              Plain = crypto:strong_rand_bytes(Size),
              Run = fun() -> pump(Pipe, Plain) end,
              bench_case("stream_pump", Size, Run),
              %% Pre-encrypt one wire outside the decrypt timing loop.
              DecWire = pump_all(Pipe, Plain),
              RunDec = fun() -> pump_dec(Pipe, DecWire) end,
              bench_case("stream_pump-dec", Size, RunDec)
      end, [1 bsl 20, 16 bsl 20, 64 bsl 20]),
    ok = itb:free(Pipe).

%% ------------------------------------------------------------------
%% Pump: full incremental encrypt session over one buffer.
%% ------------------------------------------------------------------

pump(Pipe, Plain) ->
    {ok, Stream} = itb:encrypt_stream(Pipe),
    ok = feed(Stream, Plain),
    ok = itb:stream_end(Stream),
    ok = drain(Stream),
    ok = itb:stream_free(Stream).

feed(_Stream, <<>>) ->
    ok;
feed(Stream, Data) ->
    N = min(byte_size(Data), ?PUMP_BUF),
    <<Slice:N/binary, Rest/binary>> = Data,
    ok = itb:stream_write(Stream, Slice),
    ok = drain_ready(Stream),
    feed(Stream, Rest).

%% A read before end never blocks; drain whatever the chain has
%% produced so far to bound the Go-side spool.
drain_ready(Stream) ->
    case itb:stream_read(Stream, ?PUMP_BUF) of
        {ok, <<>>, _} -> ok;
        {ok, _, true} -> ok;
        {ok, _, false} -> drain_ready(Stream)
    end.

drain(Stream) ->
    case itb:stream_read(Stream, ?PUMP_BUF) of
        {ok, _, true} -> ok;
        {ok, _, false} -> drain(Stream)
    end.

%% Encrypt whole plain, collecting wire. Uses feed_noread so no
%% encoder-produced bytes are lost to drain_ready's read-and-discard
%% pattern: drain_ready's job in the `pump` shape is to bound the
%% Go-side spool during a throwaway encrypt, so it reads chunks off the
%% spool and drops them. In `pump_all` the wire needs to be preserved,
%% so any drain_ready call landing after a real encoder chunk has been
%% produced would silently drop that chunk. At small plaintext sizes
%% (single-chunk plaintexts fitting in the 16 MiB DefaultChunkSize) the
%% encoder emits nothing until stream_end and drain_ready during feed
%% is a no-op — but at multi-chunk sizes (64 MiB and above) the
%% encoder produces one output per full chunk consumed, and drain_ready
%% between feed slices can catch and drop those chunks before
%% drain_collect at end sees them.
%%
%% Go core wrapper-nonce batching fix (streams.go +
%% wrapper.NewWrapWriter) closes the earlier wrapper-nonce split-write
%% race so a single-chunk pump_all with plain feed would now produce a
%% wire whose nonce is not stranded, but drain_ready's byte-dropping
%% behaviour remains fundamentally incompatible with wire collection
%% across chunk boundaries.
pump_all(Pipe, Plain) ->
    {ok, Stream} = itb:encrypt_stream(Pipe),
    ok = feed_noread(Stream, Plain),
    ok = itb:stream_end(Stream),
    Wire = drain_collect(Stream, []),
    ok = itb:stream_free(Stream),
    Wire.

feed_noread(_Stream, <<>>) ->
    ok;
feed_noread(Stream, Data) ->
    N = min(byte_size(Data), ?PUMP_BUF),
    <<Slice:N/binary, Rest/binary>> = Data,
    ok = itb:stream_write(Stream, Slice),
    feed_noread(Stream, Rest).

drain_collect(Stream, Acc) ->
    case itb:stream_read(Stream, ?PUMP_BUF) of
        {ok, Chunk, true} -> iolist_to_binary(lists:reverse([Chunk | Acc]));
        {ok, Chunk, false} -> drain_collect(Stream, [Chunk | Acc])
    end.

%% Decrypt whole wire.
pump_dec(Pipe, Wire) ->
    {ok, Stream} = itb:decrypt_stream(Pipe),
    ok = feed(Stream, Wire),
    ok = itb:stream_end(Stream),
    ok = drain(Stream),
    ok = itb:stream_free(Stream).

%% ------------------------------------------------------------------
%% Timing loop: one untimed warm-up, then iterate until the wall-clock
%% budget is spent (with an iteration floor); print one table row.
%% ------------------------------------------------------------------

bench_case(Name, Size, Run) ->
    ok = Run(), %% warm-up
    Budget = min_seconds(),
    Start = erlang:monotonic_time(microsecond),
    Iters = loop(Run, Start, Budget, 0),
    Elapsed = (erlang:monotonic_time(microsecond) - Start) / 1.0e6,
    MB = Size * Iters / (1024 * 1024),
    io:format("~-17s ~-8s ~.1f~n", [Name, size_label(Size), MB / Elapsed]),
    ok.

loop(Run, Start, Budget, Iters) ->
    ok = Run(),
    Elapsed = (erlang:monotonic_time(microsecond) - Start) / 1.0e6,
    case Elapsed < Budget orelse Iters + 1 < ?MIN_ITERS of
        true -> loop(Run, Start, Budget, Iters + 1);
        false -> Iters + 1
    end.

size_label(Size) when Size >= (1 bsl 20) ->
    integer_to_list(Size bsr 20) ++ " MiB";
size_label(Size) ->
    integer_to_list(Size bsr 10) ++ " KiB".

min_seconds() ->
    case os:getenv("ITB_BENCH_MIN_SEC") of
        false -> 5.0;
        "" -> 5.0;
        Raw ->
            case string:to_float(Raw) of
                {F, _} when is_float(F), F > 0 -> F;
                _ ->
                    case string:to_integer(Raw) of
                        {I, _} when is_integer(I), I > 0 -> float(I);
                        _ -> 5.0
                    end
            end
    end.

%% ------------------------------------------------------------------
%% Bench-shape opts from env (defaults per bindings/BENCH.md).
%% ------------------------------------------------------------------

bench_opts() ->
    Base = [{<<"nonceBits">>, list_to_binary(env("ITB_NONCE_BITS", "512"))},
            {<<"keyBits">>, list_to_binary(env("ITB_KEY_BITS", "1024"))},
            {<<"withParallax">>, flag(env("ITB_WITH_PARALLAX", "false"))},
            {<<"withWrapper">>, flag(env("ITB_WITH_WRAPPER", "false"))}],
    Base1 = case env("ITB_INNER_HASH", "") of
        "" -> Base;
        Hash -> [{<<"innerHash">>, list_to_binary(Hash)} | Base]
    end,
    case env("ITB_MAC_NAME", "") of
        "" -> Base1;
        Mac -> [{<<"macName">>, list_to_binary(Mac)} | Base1]
    end.

flag(Raw) when Raw =:= "true"; Raw =:= "1" -> <<"true">>;
flag(_) -> <<"false">>.

env(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        "" -> Default;
        Value -> Value
    end.
