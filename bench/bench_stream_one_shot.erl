%% bench_stream_one_shot — whole-buffer stream throughput vs plaintext
%% size (Streaming Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Each
%% iteration issues one itb:encrypt_stream_one_shot/2 or
%% itb:decrypt_stream_one_shot/2 call for callers holding the full
%% payload in memory — the whole-buffer fast path through libitb.
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
%%   erlc -o bench bench/bench_stream_one_shot.erl
%%   erl -noshell -pa _build/default/lib/itb/ebin -pa bench \
%%       -run bench_stream_one_shot main run -run init stop

-module(bench_stream_one_shot).

-export([main/1]).

-define(MIN_ITERS, 3).

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
              Run = fun() ->
                            {ok, _Wire} =
                                itb:encrypt_stream_one_shot(Pipe, Plain),
                            ok
                    end,
              bench_case("stream_one_shot", Size, Run),
              %% Pre-encrypt one wire outside the decrypt timing loop.
              {ok, DecWire} = itb:encrypt_stream_one_shot(Pipe, Plain),
              RunDec = fun() ->
                               {ok, _Plain} =
                                   itb:decrypt_stream_one_shot(Pipe, DecWire),
                               ok
                       end,
              bench_case("stream_one_shot-dec", Size, RunDec)
      end, [1 bsl 20, 16 bsl 20, 64 bsl 20]),
    ok = itb:free(Pipe).

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
