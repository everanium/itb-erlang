%% Long-run stress harness. The loop utility holds one Pipeline handle
%% per exercised cipher surface for minutes, hammers it with
%% concurrent encrypt -> decrypt -> compare round-trips from N worker
%% processes, rotates the outer masters and reopens the handle from
%% its session blob on a schedule, and reports whether the process
%% survived with every byte intact. It is the Erlang binding's
%% counterpart of the Go harness under tools/loop: the same flags, the
%% same round structure, the same summary in both renderings.
%%
%% The default shape is full production: the Streaming AEAD profile
%% with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
%% inner hash, 1024-bit keys, and the compile-in 512-bit nonce width,
%% driven through a stream session by three workers for five minutes
%% on 16 MiB plaintexts. Every worker owns a distinct CSPRNG-generated
%% plaintext held for the whole run, so any cross-call state leakage
%% inside the Pipeline surfaces as a data mismatch between workers
%% rather than cancelling out.
%%
%% A failure is one of two things. A cipher, rekey or load call that
%% returns a non-OK status is a worker error: the run stops, the
%% summary lists it, the verdict is FAIL and the exit code 1. A
%% round-trip that returns without error but with different bytes is a
%% data mismatch: the process terminates on the spot with exit code 3,
%% printing the worker, the iteration and the first differing offset,
%% and no summary — the state that produced the wrong bytes is the
%% evidence. A crash inside the shared library or the emulator has no
%% exit code of its own here; surfacing it is what the utility is for.
%%
%% Usage:
%%
%%   ./loop --duration 5m --goroutines 3 --shape stream --hash areion512 \
%%          --mac hmac-blake3 --payload-size 16MB --memlimit auto \
%%          --parallax on --wrapper on
%%
%% Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
%% then the partial summary prints.

-module(loop_main).

-behaviour(gen_event).

-export([start/0, log/2, emit/2, closed_pipe_filter/2, on_off/1, policy_label/1,
         status_text/2]).

%% Graceful stop. The signal handler below is installed into the
%% emulator's signal server in place of the default one, so a
%% termination signal sets the run's stop request instead of halting
%% the node from under an in-flight cipher call.
-export([init/1, handle_event/2, handle_call/2, handle_info/2,
         terminate/2, code_change/3]).

-include("loop.hrl").

%% ------------------------------------------------------------------
%% Logging
%% ------------------------------------------------------------------

%% Prints one prefixed status line to stdout.
%%
%% Erlang-specific. The line and its newline are handed to the io
%% server as one request: workers log concurrently during maintenance,
%% and a routine that emitted the text and the newline as two requests
%% would let another worker's line land between them.
-spec log(string(), [term()]) -> ok.
log(Format, Args) ->
    emit(standard_io, ["[loop] ", io_lib:format(Format, Args), $\n]).

err(Format, Args) ->
    emit(standard_error, ["loop: ", io_lib:format(Format, Args), $\n]).

%% Writes Data to Device as one request, and ends the process when the
%% device is gone. Every write of this utility goes through here.
%%
%% Erlang-specific. The emulator ignores SIGPIPE, so a consumer that
%% stops reading does not end the run the way it ends the reference:
%% the io server behind the closed descriptor exits, the write raises,
%% and the node would halt on its own terms with exit 1. The failed
%% write is answered with the exit code the signal would have produced,
%% 141, with nothing further printed and nothing flushed.
-spec emit(io:device(), iodata()) -> ok.
emit(Device, Data) ->
    try
        io:put_chars(Device, Data)
    catch
        _:_ -> erlang:halt(141, [{flush, false}])
    end.

%% Keeps the emulator's own report about the closed pipe off stderr.
%%
%% Erlang-specific. When stdout is a closed pipe the emulator's stdout
%% writer dies of epipe, and the terminal driver files an error report
%% about it before it stops; only then does the io server go away and
%% the failed write above end the process. The report therefore leaves
%% the driver ahead of the halt, and whether the default handler gets
%% it onto stderr first is a race the utility cannot win from the
%% failing write. The primary filter installed at start runs inside
%% the driver before the report reaches any handler and drops that one
%% report — the stdout writer, reason epipe — and no other, so every
%% other event the emulator files still prints.
install_closed_pipe_filter() ->
    ok = logger:add_primary_filter(loop_closed_pipe,
                                   {fun ?MODULE:closed_pipe_filter/2, none}).

-spec closed_pipe_filter(logger:log_event(), term()) -> stop | ignore.
closed_pipe_filter(#{msg := {Format, [epipe]},
                     meta := #{mfa := {user_drv, _, _}}}, _) ->
    case string:prefix(Format, "Writer crashed") of
        nomatch -> ignore;
        _ -> stop
    end;
closed_pipe_filter(_Event, _) ->
    ignore.

-spec on_off(boolean()) -> string().
on_off(true) -> "on";
on_off(false) -> "off".

%% "status <code>: <sentence>" — the numeric code the binding resolves
%% from the status the failing call returned, and the diagnostic that
%% call left behind, with nothing composed on this side of the
%% boundary. The sentence is taken whole however long it is: the
%% binding hands it over as a term the runtime owns, so no buffer
%% bounds it here.
-spec status_text(atom(), binary() | string()) -> string().
status_text(Status, Detail) ->
    lists:flatten(io_lib:format("status ~B: ~ts",
                                [itb3:status_code(Status), Detail])).

%% Renders an encoder policy env value for the summary: the raw string
%% when set, "default" when the shipped ladder applies.
-spec policy_label(string()) -> string().
policy_label(Name) ->
    case os:getenv(Name) of
        false -> "default";
        Value ->
            case string:trim(Value, leading, " \t") of
                "" -> "default";
                Trimmed -> Trimmed
            end
    end.

%% ------------------------------------------------------------------
%% Flags
%% ------------------------------------------------------------------

%% One command-line flag: its name, the type label the usage prints,
%% the kind that governs parsing and the default suffix, and its help
%% text. Values are validated after the whole line is parsed.
%%
%% The table is in alphabetical order, the order the usage prints.
flag_table() ->
    [{"barrier-fill", "int", int,
      "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)"},
     {"blob-cycle-every", "int", int64,
      "reopen each pipeline from its session blob every N iterations per worker; 0 = never"},
     {"blob-mode", "int", int,
      "container floor sizing mode: 1 (per-region, default) | 2 (per-container)"},
     {"chunk-size", "string", string,
      "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape"},
     {"drbg", "string", string,
      "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)"},
     {"duration", "duration", string,
      "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0"},
     {"gogc", "int", int,
      "GC trigger percentage; 0 = leave the runtime default"},
     {"gomaxprocs", "int", int,
      "Go runtime GOMAXPROCS override; 0 = inherit from the environment"},
     {"goroutines", "int", int,
      "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1"},
     {"hash", "string", string,
      "inner ITB hash primitive name"},
     {"iterations", "int", int64,
      "fixed per-worker iteration count; 0 = duration-based"},
     {"json-output", "", bool,
      "print the final summary as one compact JSON object instead of log lines"},
     {"key-bits", "int", int,
      "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)"},
     {"mac", "string", string,
      "MAC primitive name"},
     {"memlimit", "string", string,
      "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)"},
     {"memprofile", "string", string,
      "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none"},
     {"nonce-bits", "int", int,
      "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)"},
     {"parallax", "string", string,
      "parallax layer: on | off"},
     {"payload-mode", "string", string,
      "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii"},
     {"payload-size", "string", string,
      "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"},
     {"profile", "string", string,
      "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair"},
     {"rekey-every", "int", int64,
      "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never"},
     {"seed", "uint", uint64,
      "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts"},
     {"shape", "string", string,
      "cipher surface to exercise: stream | message | stream_one_shot | both"},
     {"wrapper", "string", string,
      "wrapper layer: on | off"}].

defaults() ->
    #{"barrier-fill" => 0, "blob-cycle-every" => 0, "blob-mode" => 1, "chunk-size" => "0",
      "drbg" => "", "duration" => "5m", "gogc" => 0, "gomaxprocs" => 0, "goroutines" => 3,
      "hash" => "areion512", "iterations" => 0, "json-output" => false,
      "key-bits" => 0, "mac" => "hmac-blake3", "memlimit" => "auto",
      "memprofile" => "", "nonce-bits" => 0, "parallax" => "on",
      "payload-mode" => "fixed", "payload-size" => "16MB", "profile" => "",
      "rekey-every" => 0, "seed" => 0, "shape" => "stream", "wrapper" => "on"}.

usage() ->
    D = defaults(),
    Lines =
        ["Usage of loop:\n"
         | [flag_usage(Name, Label, Kind, Help, maps:get(Name, D))
            || {Name, Label, Kind, Help} <- flag_table()]],
    emit(standard_error, Lines).

flag_usage(Name, Label, Kind, Help, Default) ->
    Head = case Label of
               "" -> ["  -", Name, "\n"];
               _ -> ["  -", Name, " ", Label, "\n"]
           end,
    %% Erlang-specific. The default-value suffix is composed by hand;
    %% a flag library that appends its own renders it itself.
    Suffix = case {Kind, Default} of
                 {int, 0} -> "";
                 {int, V} -> io_lib:format(" (default ~B)", [V]);
                 {string, ""} -> "";
                 {string, V} -> io_lib:format(" (default \"~s\")", [V]);
                 _ -> ""
             end,
    [Head, "    \t", Help, Suffix, "\n"].

%% Parses argv into the raw flag values. Accepts -name value,
%% --name value, -name=value and --name=value; a boolean flag takes no
%% value unless given as -name=true / -name=false. Returns
%% {ok, Values}, help, or error after printing the message.
parse_argv(Args) ->
    parse_argv(Args, defaults()).

parse_argv([], Values) ->
    {ok, Values};
parse_argv([Arg | Rest], Values) ->
    case Arg of
        [$-, C | _] when C =/= $\0 -> parse_flag(Arg, Rest, Values);
        _ ->
            err("unexpected positional arguments: [~s]", [Arg]),
            error
    end.

parse_flag(Arg, Rest, Values) ->
    Name0 = strip_dashes(Arg),
    case Name0 of
        "h" -> help;
        "help" -> help;
        _ ->
            {Name, Inline} = split_inline(Name0),
            case lists:keyfind(Name, 1, flag_table()) of
                false ->
                    err("flag provided but not defined: -~s", [Name]),
                    usage(),
                    error;
                {_, _, Kind, _} -> take_value(Name, Kind, Inline, Rest, Values)
            end
    end.

strip_dashes([$-, $- | Name]) -> Name;
strip_dashes([$- | Name]) -> Name.

split_inline(Arg) ->
    case string:split(Arg, "=") of
        [Name, Value] -> {Name, {value, Value}};
        [Name] -> {Name, none}
    end.

take_value(Name, Kind, Inline, Rest, Values) ->
    case value_of(Name, Kind, Inline, Rest) of
        needs_argument ->
            err("flag needs an argument: -~s", [Name]),
            error;
        {Value, Rest1} ->
            case assign(Kind, Value) of
                error ->
                    err("invalid value \"~s\" for flag -~s", [Value, Name]),
                    error;
                {ok, Parsed} ->
                    parse_argv(Rest1, maps:put(Name, Parsed, Values))
            end
    end.

value_of(_Name, _Kind, {value, V}, Rest) -> {V, Rest};
value_of(_Name, bool, none, Rest) -> {"true", Rest};
value_of(_Name, _Kind, none, [V | Rest]) -> {V, Rest};
value_of(_Name, _Kind, none, []) -> needs_argument.

assign(string, Value) ->
    {ok, Value};
assign(bool, "true") -> {ok, true};
assign(bool, "false") -> {ok, false};
assign(bool, _) -> error;
assign(uint64, [$- | _]) -> error;
assign(uint64, Value) -> integer_value(Value);
assign(int64, Value) -> integer_value(Value);
assign(int, Value) ->
    case integer_value(Value) of
        {ok, V} when V =< 2147483647, V >= -2147483647 -> {ok, V};
        _ -> error
    end.

integer_value(Value) ->
    case string:to_integer(Value) of
        {V, ""} when is_integer(V) -> {ok, V};
        _ -> error
    end.

%% ------------------------------------------------------------------
%% Validation
%% ------------------------------------------------------------------

%% Builds the resolved config from the parsed values. Returns
%% {ok, Cfg} or error after printing "loop: <message>" for the first
%% failing rule.
resolve(V) ->
    Duration = maps:get("duration", V),
    case loop_size:parse_duration(Duration) of
        {ok, Ns} when Ns > 0 -> resolve_iterations(V, Ns);
        _ ->
            err("--duration must be positive, got ~s", [Duration]),
            error
    end.

resolve_iterations(V, DurationNs) ->
    case maps:get("iterations", V) of
        Iterations when Iterations < 0 ->
            err("--iterations must be >= 0, got ~B", [Iterations]),
            error;
        Iterations -> resolve_workers(V, DurationNs, Iterations)
    end.

resolve_workers(V, DurationNs, Iterations) ->
    case maps:get("goroutines", V) of
        G when G < 1; G > ?LOOP_MAX_WORKERS ->
            err("--goroutines must be in 1..~B, got ~B", [?LOOP_MAX_WORKERS, G]),
            error;
        G ->
            Cfg = #cfg{duration_ns = DurationNs, iterations = Iterations,
                       workers_requested = G, workers = G},
            resolve_shape(V, Cfg)
    end.

resolve_shape(V, Cfg) ->
    Shape = maps:get("shape", V),
    case loop_worker:parse_shape(Shape) of
        error ->
            err("--shape must be stream | message | stream_one_shot | both, got \"~s\"",
                [Shape]),
            error;
        {ok, S} -> resolve_hash(V, Cfg#cfg{shape = S})
    end.

resolve_hash(V, Cfg) ->
    Hash = maps:get("hash", V),
    case lists:member(list_to_binary(Hash), itb3:hash_names()) of
        false ->
            err("--hash \"~s\" is not a registered hash primitive", [Hash]),
            error;
        true ->
            %% The MAC name is validated by Init: no registry
            %% enumeration for MAC primitives crosses the boundary.
            resolve_payload(V, Cfg#cfg{hash = Hash, mac = maps:get("mac", V)})
    end.

resolve_payload(V, Cfg) ->
    Size = maps:get("payload-size", V),
    case loop_size:parse_size(Size) of
        error ->
            err("--payload-size: invalid size \"~s\"", [Size]),
            error;
        {ok, N} when N < 1 ->
            err("--payload-size must be at least 1 byte", []),
            error;
        {ok, N} -> resolve_memlimit(V, Cfg#cfg{payload = N})
    end.

resolve_memlimit(V, Cfg) ->
    case maps:get("memlimit", V) of
        "auto" ->
            Limit = case Cfg#cfg.workers =< 3 of
                        true -> 1 bsl 30;
                        false -> 256 bsl 20
                    end,
            resolve_gogc(V, Cfg#cfg{memlimit_auto = true, memlimit = Limit});
        Size ->
            case loop_size:parse_size(Size) of
                error ->
                    err("--memlimit: invalid size \"~s\"", [Size]),
                    error;
                {ok, N} -> resolve_gogc(V, Cfg#cfg{memlimit = N})
            end
    end.

resolve_gogc(V, Cfg) ->
    case maps:get("gogc", V) of
        G when G < 0 ->
            err("--gogc must be >= 0, got ~B", [G]),
            error;
        G -> resolve_layers(V, Cfg#cfg{gogc = G})
    end.

resolve_layers(V, Cfg) ->
    case on_off_value(maps:get("parallax", V)) of
        error ->
            err("--parallax must be on | off, got \"~s\"", [maps:get("parallax", V)]),
            error;
        {ok, P} ->
            case on_off_value(maps:get("wrapper", V)) of
                error ->
                    err("--wrapper must be on | off, got \"~s\"", [maps:get("wrapper", V)]),
                    error;
                {ok, W} ->
                    resolve_profile(V, Cfg#cfg{parallax = P, wrapper = W})
            end
    end.

on_off_value("on") -> {ok, true};
on_off_value("off") -> {ok, false};
on_off_value(_) -> error.

resolve_profile(V, Cfg) ->
    case maps:get("profile", V) of
        "" -> resolve_key_bits(V, Cfg);
        Name ->
            case profile_surface(Name) of
                error -> error;
                {ok, Surface} ->
                    resolve_key_bits(V, Cfg#cfg{profile = Name,
                                                shape = narrow_shape(Cfg#cfg.shape, Surface)})
            end
    end.

%% Resolves a registered profile to the shape family its record's mode
%% exposes by reading the record through the binding's lookup: a mode
%% beginning with "streaming" exposes the stream surfaces, one
%% beginning with "singlemsg" the message surface, "blob-only" none.
profile_surface(Name) ->
    case itb3:lookup(Name) of
        {error, _} ->
            err("--profile \"~s\" is not a registered triple profile", [Name]),
            error;
        {ok, Record} ->
            Mode = maps:get(<<"mode">>, Record, <<>>),
            case binary:part(Mode, 0, min(9, byte_size(Mode))) of
                <<"streaming">> -> {ok, stream};
                <<"singlemsg">> -> {ok, message};
                _ ->
                    err("--profile \"~s\" carries no cipher surface (blob-only mode)", [Name]),
                    error
            end
    end.

%% Applies a --profile's surface to the requested shape: a
%% message-surface profile forces message; a stream-surface profile
%% keeps stream or stream_one_shot as requested and turns message or
%% both into stream.
narrow_shape(_Requested, message) -> message;
narrow_shape(stream_one_shot, stream) -> stream_one_shot;
narrow_shape(_Requested, stream) -> stream.

resolve_key_bits(V, Cfg) ->
    case maps:get("key-bits", V) of
        K when K =:= 0; K =:= 512; K =:= 1024; K =:= 2048 ->
            resolve_nonce_bits(V, Cfg#cfg{key_bits = K});
        K ->
            err("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got ~B", [K]),
            error
    end.

resolve_nonce_bits(V, Cfg) ->
    case maps:get("nonce-bits", V) of
        N when N =:= 0; N =:= 128; N =:= 256; N =:= 512 ->
            resolve_blob_mode(V, Cfg#cfg{nonce_bits = N});
        N ->
            err("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got ~B", [N]),
            error
    end.

resolve_blob_mode(V, Cfg) ->
    case maps:get("blob-mode", V) of
        M when M =:= 1; M =:= 2 ->
            resolve_barrier_fill(V, Cfg#cfg{blob_mode = M});
        M ->
            err("--blob-mode must be 1 (per-region) | 2 (per-container), got ~B", [M]),
            error
    end.

resolve_barrier_fill(V, Cfg) ->
    case maps:get("barrier-fill", V) of
        B when B =:= 0; B =:= 1; B =:= 2; B =:= 4; B =:= 8; B =:= 16; B =:= 32 ->
            %% The DRBG name is validated by Init: the C ABI enumerates
            %% no DRBG names.
            resolve_chunk_size(V, Cfg#cfg{barrier_fill = B, drbg = maps:get("drbg", V)});
        B ->
            err("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got ~B", [B]),
            error
    end.

resolve_chunk_size(V, Cfg) ->
    Size = maps:get("chunk-size", V),
    case loop_size:parse_size(Size) of
        error ->
            err("--chunk-size: invalid size \"~s\"", [Size]),
            error;
        {ok, N} -> resolve_gomaxprocs(V, Cfg#cfg{chunk_size = N})
    end.

resolve_gomaxprocs(V, Cfg) ->
    case maps:get("gomaxprocs", V) of
        G when G < 0 ->
            err("--gomaxprocs must be > 0 when specified, got ~B", [G]),
            error;
        G -> resolve_rekey(V, Cfg#cfg{gomaxprocs = G})
    end.

resolve_rekey(V, Cfg) ->
    case maps:get("rekey-every", V) of
        R when R < 0 ->
            err("--rekey-every must be >= 0, got ~B", [R]),
            error;
        R -> resolve_blob_cycle(V, Cfg#cfg{rekey_every = R})
    end.

resolve_blob_cycle(V, Cfg) ->
    case maps:get("blob-cycle-every", V) of
        B when B < 0 ->
            err("--blob-cycle-every must be >= 0, got ~B", [B]),
            error;
        B -> resolve_payload_mode(V, Cfg#cfg{blob_cycle_every = B})
    end.

resolve_payload_mode(V, Cfg) ->
    Mode = maps:get("payload-mode", V),
    case loop_payload:parse_mode(Mode) of
        error ->
            err("--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \"~s\"",
                [Mode]),
            error;
        {ok, M} ->
            {ok, Cfg#cfg{payload_mode = M,
                         seed = maps:get("seed", V),
                         json_output = maps:get("json-output", V),
                         memprofile = maps:get("memprofile", V)}}
    end.

%% ------------------------------------------------------------------
%% Pipelines
%% ------------------------------------------------------------------

%% Folds a keystream primitive into opts for any layer the named
%% profile leaves unfilled but the operator asked for.
%%
%% A profile built around a primitive that is safe only inside the
%% Interlocked Barrier ships with no parallax palette and no outer
%% cipher: both layers run outside the barrier, where that primitive
%% would stand bare, so the recipe leaves them unnamed rather than
%% naming a primitive that must not key them. Engaging either layer
%% therefore needs a keystream-capable primitive supplied from outside
%% the recipe; without it construction fails on a palette below its
%% minimum or an unnamed outer cipher, and the primitive that most
%% deserves stressing becomes the one that cannot be stressed with
%% those layers engaged.
%%
%% AES-CMAC is PRF-grade, so it is sound outside the Interlocked
%% Barrier, and it is the closest relative of the AES-based inner
%% primitive whose profiles need this fill. Overrides fold into the
%% resolved record the blob carries, so the receiver rebuilds the same
%% shape from the blob alone.
fill_keystream_layers(Name, WantParallax, WantWrapper) ->
    case itb3:lookup(Name) of
        {error, _} ->
            err("--profile \"~s\" is not a registered triple profile", [Name]),
            error;
        {ok, Record} ->
            PaletteOpts =
                case WantParallax andalso not maps:is_key(<<"palette">>, Record) of
                    true ->
                        Palette = [{parallaxPalette,
                                    string:join(lists:duplicate(3, ?KEYSTREAM_FILL_CIPHER), ",")}],
                        %% A recipe that never carried a palette never
                        %% carried a segment size either, and the
                        %% schedule rejects zero.
                        case maps:is_key(<<"segment">>, Record) of
                            true -> Palette;
                            false -> Palette ++ [{parallaxSegmentSize, "4093"}]
                        end;
                    false -> []
                end,
            OuterOpts =
                case WantWrapper andalso not maps:is_key(<<"outer">>, Record) of
                    true -> [{outerCipher, ?KEYSTREAM_FILL_CIPHER}];
                    false -> []
                end,
            {ok, PaletteOpts ++ OuterOpts}
    end.

%% Constructs one Pipeline against Profile with every flag-carried
%% override in the opts list (zero values included — the shared
%% library treats zero as "profile default"), then obtains the Init
%% blob once through save: the binding's init entry does not hand the
%% blob back, and the bytes are the ones Init produced. Later blob
%% reopens use the retained blob; save is never called again.
build_pipeline(Cfg, Profile) ->
    Base = [{innerHash, Cfg#cfg.hash},
            {macName, Cfg#cfg.mac},
            {withParallax, atom_to_list(Cfg#cfg.parallax)},
            {withWrapper, atom_to_list(Cfg#cfg.wrapper)},
            {keyBits, integer_to_list(Cfg#cfg.key_bits)},
            {nonceBits, integer_to_list(Cfg#cfg.nonce_bits)},
            {barrierFill, integer_to_list(Cfg#cfg.barrier_fill)},
            {drbg, Cfg#cfg.drbg},
            {chunkSize, integer_to_list(Cfg#cfg.chunk_size)}],
    Extra = case Cfg#cfg.profile of
                "" -> {ok, []};
                Name -> fill_keystream_layers(Name, Cfg#cfg.parallax, Cfg#cfg.wrapper)
            end,
    case Extra of
        error -> error;
        {ok, Fill} ->
            case Fill of
                [] -> ok;
                _ ->
                    err("~s leaves the requested keystream layers unnamed; ~s supplied for them",
                        [Cfg#cfg.profile, ?KEYSTREAM_FILL_CIPHER])
            end,
            case itb3:init(Profile, Base ++ Fill) of
                {error, {Status, Detail}} ->
                    err("Init(~s): ~s", [Profile, status_text(Status, Detail)]),
                    error;
                {ok, Pipe} ->
                    case itb3:save(Pipe) of
                        {error, {Status, Detail}} ->
                            err("Save(~s): ~s", [Profile, status_text(Status, Detail)]),
                            itb3:free(Pipe),
                            error;
                        {ok, Blob} ->
                            apply_blob_mode(Cfg, Profile, Pipe, Blob)
                    end
            end
    end.

%% The sizing mode is not an opts knob: under --blob-mode 2 the Init
%% blob is edited and the pipeline reopened from it, so the retained
%% blob (the one blob-cycle reopens from) carries the edited mode.
apply_blob_mode(#cfg{blob_mode = 1}, Profile, Pipe, Blob) ->
    log_pipeline_initialised(Profile, Blob),
    {ok, Pipe, Blob};
apply_blob_mode(#cfg{blob_mode = Mode}, Profile, Pipe, Blob) ->
    itb3:free(Pipe),
    case edit_inner_blob_mode(Blob, Mode) of
        {error, Detail} ->
            err("rewrite blob mode: ~ts", [Detail]),
            error;
        {ok, Edited} ->
            case itb3:load(Edited) of
                {error, {Status, Detail}} ->
                    err("reload Mode 2 blob: ~s", [status_text(Status, Detail)]),
                    error;
                {ok, Reloaded} ->
                    log_pipeline_initialised(Profile, Edited),
                    {ok, Reloaded, Edited}
            end
    end.

%% Sets the inner blob's integer "mode" (1 = per-region, 2 =
%% per-container) of a session blob through the OTP json module. The
%% profile record "p" carries its own string "mode"; the target is the
%% one under "ib". Integers and strings round-trip unchanged; only the
%% key order may differ.
edit_inner_blob_mode(Blob, Mode) ->
    try json:decode(Blob) of
        #{<<"ib">> := #{<<"mode">> := M} = Inner} = Session when is_integer(M) ->
            {ok, iolist_to_binary(json:encode(Session#{<<"ib">> := Inner#{<<"mode">> := Mode}}))};
        _ ->
            {error, "inner blob mode field not found"}
    catch
        error:Reason ->
            {error, io_lib:format("~p", [Reason])}
    end.

%% Prints the construction line with the recipe read back from the
%% blob the Pipeline handed out, not echoed from the flags: every
%% construction override is proven to have reached the library by the
%% value the receiver would see. Record values that are empty (a No
%% MAC profile's MAC, a mixed profile's single hash) print as "-".
log_pipeline_initialised(Profile, Blob) ->
    case itb3:inspect(Blob) of
        {error, {_Status, Detail}} ->
            log("pipeline initialised: profile=~s blob=~B bytes (inspect: ~ts)",
                [Profile, byte_size(Blob), Detail]);
        {ok, Record} ->
            Line = io_lib:format(
                "pipeline initialised: profile=~s blob=~B bytes hash=~s key-bits=~B "
                "nonce-bits=~B barrier-fill=~B chunk-size=~B mac=~s parallax=~s wrapper=~s",
                [Profile, byte_size(Blob),
                 record_str(Record, <<"hash">>), record_int(Record, <<"keybits">>),
                 record_int(Record, <<"nonce_bits">>), record_int(Record, <<"barrier_fill">>),
                 record_int(Record, <<"chunk">>), record_str(Record, <<"mac">>),
                 on_off(record_bool(Record, <<"parallax">>)),
                 on_off(record_bool(Record, <<"wrapper">>))]),
            ContainerMode = [" container-mode=2" || record_int(Record, <<"container_mode">>) =:= 2],
            Drbg = [[" drbg=", record_str(Record, <<"drbg">>)]
                    || record_str(Record, <<"drbg">>) =/= "-"],
            log("~ts", [[Line, ContainerMode, Drbg]])
    end.

record_int(Record, Key) ->
    case maps:get(Key, Record, 0) of
        V when is_integer(V) -> V;
        _ -> 0
    end.

record_str(Record, Key) ->
    case maps:get(Key, Record, <<>>) of
        <<>> -> "-";
        V when is_binary(V) -> unicode:characters_to_list(V);
        _ -> "-"
    end.

record_bool(Record, Key) ->
    maps:get(Key, Record, false) =:= true.

%% ------------------------------------------------------------------
%% Signals
%% ------------------------------------------------------------------

%% Graceful stop. A termination signal sets the run's stop request,
%% which every worker checks before starting an iteration, so the
%% signal interrupts nothing mid-call — the in-flight encrypt /
%% decrypt / compare completes, the worker returns, and the partial
%% summary prints with the verdict the completed iterations earned.
%% The emulator's own handler is removed first: it halts the node on
%% SIGTERM, which would end the run before the summary.
%%
%% Erlang-specific. SIGINT never reaches Erlang code: the emulator's
%% break handler owns it below the signal server, and os:set_signal/2
%% does not accept it at all. The launcher closes that gap by trapping
%% the interrupt itself and sending the emulator a termination signal,
%% which arrives here.
install_signals(Flags) ->
    _ = gen_event:delete_handler(erl_signal_server, erl_signal_handler, []),
    _ = gen_event:add_handler(erl_signal_server, ?MODULE, [Flags]),
    _ = os:set_signal(sigterm, handle),
    _ = os:set_signal(sigquit, handle),
    ok.

init([Flags]) -> {ok, Flags}.

handle_event(Signal, Flags) when Signal =:= sigterm; Signal =:= sigquit ->
    loop_state:request_stop(Flags),
    {ok, Flags};
handle_event(_Signal, Flags) ->
    {ok, Flags}.

handle_call(_Request, Flags) -> {ok, ok, Flags}.
handle_info(_Info, Flags) -> {ok, Flags}.
terminate(_Reason, _Flags) -> ok.
code_change(_Old, Flags, _Extra) -> {ok, Flags}.

%% ------------------------------------------------------------------
%% Run
%% ------------------------------------------------------------------

-spec start() -> no_return().
start() ->
    install_closed_pipe_filter(),
    erlang:halt(run(init:get_plain_arguments()), [{flush, true}]).

run(Args) ->
    case parse_argv(Args) of
        help -> usage(), 0;
        error -> 2;
        {ok, Values} ->
            case resolve(Values) of
                error -> 2;
                {ok, Cfg} -> shape_runtime(Cfg)
            end
    end.

%% Runtime shaping. A long run under allocation churn grows the Go
%% heap inside the shared library without bound unless a soft limit
%% paces the collector, so a limit is always in force: an explicit
%% --memlimit is set as given, and auto caps the heap only when the
%% runtime reports no limit at all (a limit already installed from the
%% environment is left standing). The GC percentage and GOMAXPROCS are
%% set only when their flag is non-zero — a zero flag skips the setter
%% rather than calling it with zero, because zero is a real value to
%% the GC-percent setter, and a call would clobber whatever the
%% environment installed. All of it lands before any Pipeline exists
%% so the baselines are taken under the shaped runtime.
shape_runtime(Cfg0) ->
    case Cfg0#cfg.memlimit_auto of
        true ->
            case itb3:set_memory_limit(-1) =:= 16#7FFFFFFFFFFFFFFF of
                true -> itb3:set_memory_limit(Cfg0#cfg.memlimit);
                false -> ok
            end;
        false ->
            itb3:set_memory_limit(Cfg0#cfg.memlimit)
    end,
    Cfg = Cfg0#cfg{memlimit = itb3:set_memory_limit(-1)},
    case Cfg#cfg.gogc > 0 of
        true -> itb3:set_gc_percent(Cfg#cfg.gogc);
        false -> ok
    end,
    case Cfg#cfg.gomaxprocs > 0 of
        true -> itb3:set_gomaxprocs(Cfg#cfg.gomaxprocs);
        false -> ok
    end,
    start_lines(Cfg),
    build(Cfg).

start_lines(Cfg) ->
    log("start: duration=~s iterations=~B goroutines=~B workers=~B concurrency=~s "
        "shape=~s hash=~s mac=~s payload=~s memlimit=~s parallax=~s wrapper=~s",
        [loop_size:human_duration(Cfg#cfg.duration_ns), Cfg#cfg.iterations,
         Cfg#cfg.workers_requested, Cfg#cfg.workers, ?LOOP_CONCURRENCY,
         loop_worker:shape_name(Cfg#cfg.shape), Cfg#cfg.hash, Cfg#cfg.mac,
         loop_size:human_bytes(Cfg#cfg.payload),
         loop_size:human_bytes(Cfg#cfg.memlimit),
         on_off(Cfg#cfg.parallax), on_off(Cfg#cfg.wrapper)]),
    log("overrides: profile=\"~s\" key-bits=~B nonce-bits=~B chunk-size=~s "
        "barrier-fill=~B gomaxprocs=~B rekey-every=~B blob-cycle-every=~B "
        "payload-mode=~s seed=~B json-output=~s~s~s",
        [Cfg#cfg.profile, Cfg#cfg.key_bits, Cfg#cfg.nonce_bits,
         loop_size:human_bytes(Cfg#cfg.chunk_size), Cfg#cfg.barrier_fill,
         Cfg#cfg.gomaxprocs, Cfg#cfg.rekey_every, Cfg#cfg.blob_cycle_every,
         loop_payload:mode_name(Cfg#cfg.payload_mode), Cfg#cfg.seed,
         atom_to_list(Cfg#cfg.json_output),
         case Cfg#cfg.blob_mode of
             1 -> "";
             M -> " blob-mode=" ++ integer_to_list(M)
         end,
         case Cfg#cfg.drbg of
             "" -> "";
             D -> " drbg=" ++ D
         end]),
    log("policy: microbatch-tiers=~s hashpool-starters=~s",
        [policy_label("ITB_MICROBATCH_TIERS"), policy_label("ITB_HASHPOOL_STARTERS")]).

%% Pipeline construction — one shared handle per exercised shape.
%% stream and stream_one_shot share the streaming handle.
build(Cfg) ->
    StreamProfile = case Cfg#cfg.profile of
                        "" -> ?DEFAULT_STREAM_PROFILE;
                        P -> P
                    end,
    MsgProfile = case Cfg#cfg.profile of
                     "" -> ?DEFAULT_MESSAGE_PROFILE;
                     P2 -> P2
                 end,
    WantStream = lists:member(Cfg#cfg.shape, [stream, stream_one_shot, both]),
    WantMsg = lists:member(Cfg#cfg.shape, [message, both]),
    case build_optional(WantStream, Cfg, StreamProfile) of
        error -> 1;
        {ok, StreamPipe, StreamBlob} ->
            case build_optional(WantMsg, Cfg, MsgProfile) of
                error -> 1;
                {ok, MsgPipe, MsgBlob} ->
                    launch(Cfg, {StreamProfile, StreamPipe, StreamBlob},
                           {MsgProfile, MsgPipe, MsgBlob})
            end
    end.

build_optional(false, _Cfg, _Profile) -> {ok, undefined, <<>>};
build_optional(true, Cfg, Profile) -> build_pipeline(Cfg, Profile).

launch(Cfg, {StreamProfile, StreamPipe, StreamBlob}, {MsgProfile, MsgPipe, MsgBlob}) ->
    Flags = loop_state:new_flags(),
    Counts = loop_state:new_counts(),
    State = loop_state:start(StreamPipe, MsgPipe, StreamBlob, MsgBlob,
                             StreamProfile, MsgProfile),
    Run = #run{cfg = Cfg, state = State, flags = Flags, counts = Counts,
               stream_profile = StreamProfile, msg_profile = MsgProfile},
    install_signals(Flags),

    %% Allocation posture. Per-worker plaintexts are built once and
    %% held for the whole run (rotating mode rebuilds them per
    %% iteration); the pump accumulator is a per-iteration iolist the
    %% collector reclaims, and the message and one-shot outputs are
    %% binaries the binding returns per call. Under the default fixed
    %% CSPRNG mode every worker's buffer is distinct, so cross-worker
    %% data crossover is detectable; pattern modes trade that property
    %% for content edge-case coverage.
    Plaintexts = [element(1, loop_payload:fill(Cfg#cfg.payload_mode,
                                               Cfg#cfg.seed =/= 0,
                                               loop_payload:seed_worker(Cfg#cfg.seed, I),
                                               Cfg#cfg.payload))
                  || I <- lists:seq(0, Cfg#cfg.workers - 1)],

    %% Warmup barrier. Every worker runs one iteration and waits; the
    %% clock starts only once all of them have paid their first-call
    %% costs (pool warm-up, lazy kernel dispatch, page faults on the
    %% payload buffers), and the RSS and pool baselines taken here
    %% describe a process that has already run the whole cipher path
    %% once per worker.
    WarmupStart = loop_size:now_ns(),
    Workers = [begin
                   Pid = loop_worker:start(Run, I, lists:nth(I + 1, Plaintexts), self()),
                   _ = monitor(process, Pid),
                   {Pid, I}
               end || I <- lists:seq(0, Cfg#cfg.workers - 1)],
    await_warmup(Workers),
    {RssWarmup, RssPeak0} = loop_summary:read_rss(),
    PoolWarmup = loop_summary:pool_snapshot(),
    WarmupNs = loop_size:now_ns() - WarmupStart,
    log("warmup: ~B workers x 1 iter completed in ~s (baseline rss=~s)",
        [Cfg#cfg.workers,
         loop_size:human_duration((WarmupNs + 50000000) div 100000000 * 100000000),
         loop_size:human_bytes(RssWarmup)]),

    %% Open the gate; in duration mode a timer asks the workers to
    %% stop once the deadline passes.
    StartNs = loop_size:now_ns(),
    [Pid ! release || {Pid, _Id} <- Workers],
    Timer = case Cfg#cfg.iterations of
                0 -> erlang:send_after(Cfg#cfg.duration_ns div 1000000, self(), deadline);
                _ -> undefined
            end,
    Stats = collect(Workers, Flags, []),
    _ = case Timer of
            undefined -> ok;
            _ -> erlang:cancel_timer(Timer)
        end,
    FinishNs = lists:max([StartNs | [S#wstats.finish_ns || S <- Stats]]),
    ElapsedNs = FinishNs - StartNs,
    {RssFinal, RssPeak} = loop_summary:read_rss(),
    PoolSteady = loop_summary:pool_snapshot(),

    case Cfg#cfg.memprofile of
        "" -> ok;
        Path ->
            case itb3:write_heap_profile(Path) of
                ok -> log("memprofile: heap profile written to ~s", [Path]);
                {error, {_Status, Detail}} -> err("memprofile: ~ts", [Detail])
            end
    end,

    Ordered = lists:keysort(#wstats.id, Stats),
    Rc = loop_summary:final(Run, Ordered, ElapsedNs,
                            {RssWarmup, max(RssPeak0, RssPeak), RssFinal},
                            {PoolWarmup, PoolSteady}),
    {LiveStream, LiveMsg} = loop_state:handles(State),
    free_pipe(LiveStream),
    free_pipe(LiveMsg),
    loop_state:stop_process(State),
    Rc.

free_pipe(undefined) -> ok;
free_pipe(Pipe) -> itb3:free(Pipe).

%% Every worker reports its warmup iteration before the clock starts.
%% A worker that died instead of reporting is not waited for: the
%% monitor turns its exit into the same arrival, and the run goes on
%% to the summary that will carry the failure.
await_warmup([]) ->
    ok;
await_warmup(Workers) ->
    receive
        {warmup_done, Pid} ->
            await_warmup(lists:keydelete(Pid, 1, Workers));
        {'DOWN', _MonRef, process, Pid, Reason} ->
            self() ! {worker_died, Pid, Reason},
            await_warmup(lists:keydelete(Pid, 1, Workers))
    end.

%% Waits for every worker, turning the duration deadline into the stop
%% request the workers poll. A worker that dies without reporting is
%% recorded as a worker error so the run cannot hang on it.
collect([], _Flags, Acc) ->
    Acc;
collect(Workers, Flags, Acc) ->
    receive
        deadline ->
            loop_state:request_stop(Flags),
            collect(Workers, Flags, Acc);
        {worker_done, Pid, Stats} ->
            _ = flush_down(Pid),
            collect(lists:keydelete(Pid, 1, Workers), Flags, [Stats | Acc]);
        {worker_died, Pid, Reason} ->
            collect_death(Workers, Flags, Acc, Pid, Reason);
        {'DOWN', _MonRef, process, Pid, Reason} ->
            collect_death(Workers, Flags, Acc, Pid, Reason)
    end.

collect_death(Workers, Flags, Acc, Pid, Reason) ->
    case lists:keyfind(Pid, 1, Workers) of
        false -> collect(Workers, Flags, Acc);
        {Pid, Id} ->
            loop_state:request_stop(Flags),
            collect(lists:keydelete(Pid, 1, Workers), Flags,
                    [died(Id, Pid, Reason) | Acc])
    end.

died(Id, Pid, Reason) ->
    #wstats{id = Id, finish_ns = loop_size:now_ns(), failed = true,
            error = lists:flatten(io_lib:format("g~B exited: ~p ~p", [Id, Pid, Reason]))}.

flush_down(Pid) ->
    receive {'DOWN', _MonRef, process, Pid, _Reason} -> ok after 0 -> ok end.
