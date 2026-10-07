%% The final summary in both renderings, and the two measurements it
%% folds in that are not per-worker counters: the process resident
%% set and the shared library's pool counters.

-module(loop_summary).

-export([read_rss/0, pool_snapshot/0, final/5]).

-include("loop.hrl").

%% ------------------------------------------------------------------
%% Resident set
%% ------------------------------------------------------------------

%% The process's current resident set and its high-water mark in
%% bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
%% Both are zero on a platform without that file; the figures are
%% informational and never enter the verdict.
-spec read_rss() -> {non_neg_integer(), non_neg_integer()}.
read_rss() ->
    case file:read_file("/proc/self/status") of
        {ok, Bin} ->
            Lines = binary:split(Bin, <<"\n">>, [global]),
            lists:foldl(fun status_line/2, {0, 0}, Lines);
        _ -> {0, 0}
    end.

status_line(Line, {Cur, Peak}) ->
    case Line of
        <<"VmRSS:", Rest/binary>> -> {status_kb(Rest), Peak};
        <<"VmHWM:", Rest/binary>> -> {Cur, status_kb(Rest)};
        _ -> {Cur, Peak}
    end.

status_kb(Rest) ->
    case string:to_integer(string:trim(unicode:characters_to_list(Rest))) of
        {Kb, _} when is_integer(Kb) -> Kb * 1024;
        _ -> 0
    end.

%% ------------------------------------------------------------------
%% Pool counters
%% ------------------------------------------------------------------

%% Pool counters. The shared library keeps process-wide monotonic
%% totals at every pool checkout of its cipher core: per hash-array
%% tier the starter width, checkouts, constructor misses, regrow
%% replacements and bytes allocated; for the scratch byte pool and the
%% parallax chunk pool the checkouts, constructor misses, regrows and
%% regrow bytes. Two snapshots bracketing the main loop are
%% differenced into per-run hit / miss figures that tell whether a
%% pool keeps its items warm between calls or evicts them across GC
%% cycles. The slot layout is read from the library: slot 0 carries
%% the tier count T, tier i occupies the five slots at 1 + 5*i, and
%% the two byte pools occupy the eight slots at 1 + 5*T; the vector is
%% sized by the binding's length query, never by a constant.
-spec pool_snapshot() -> [integer()].
pool_snapshot() ->
    case itb3:pool_stats() of
        {ok, Slots} -> Slots;
        {error, _} -> []
    end.

%% The differenced pool figures of one run: a list of per-tier maps
%% and the two byte-pool maps.
pool_diff(Warmup, Steady) when length(Warmup) < 9; length(Steady) < 9 ->
    {[], zero_pool(), zero_pool()};
pool_diff(Warmup, Steady) ->
    W = list_to_tuple(Warmup),
    S = list_to_tuple(Steady),
    Tiers = element(1, S),
    Len = tuple_size(S),
    case Tiers < 0 orelse 1 + 5 * Tiers + 8 > Len of
        true -> {[], zero_pool(), zero_pool()};
        false ->
            TierList =
                [#{tier => I,
                   starter => element(2 + 5 * I, S),
                   get => element(3 + 5 * I, S) - element(3 + 5 * I, W),
                   new => element(4 + 5 * I, S) - element(4 + 5 * I, W),
                   regrow => element(5 + 5 * I, S) - element(5 + 5 * I, W),
                   new_bytes => element(6 + 5 * I, S) - element(6 + 5 * I, W)}
                 || I <- lists:seq(0, Tiers - 1)],
            Tail = 1 + 5 * Tiers,
            Buf = byte_pool(W, S, Tail),
            Chunk = byte_pool(W, S, Tail + 4),
            {[T || T <- TierList, maps:get(starter, T) =/= 0], Buf, Chunk}
    end.

byte_pool(W, S, Base) ->
    #{get => element(Base + 1, S) - element(Base + 1, W),
      new => element(Base + 2, S) - element(Base + 2, W),
      regrow => element(Base + 3, S) - element(Base + 3, W),
      regrow_bytes => element(Base + 4, S) - element(Base + 4, W)}.

zero_pool() ->
    #{get => 0, new => 0, regrow => 0, regrow_bytes => 0}.

%% Misses over checkouts as a percentage; zero when nothing was
%% checked out.
miss_percent(_Miss, Get) when Get =< 0 -> 0.0;
miss_percent(Miss, Get) -> 100.0 * Miss / Get.

%% ------------------------------------------------------------------
%% Summary
%% ------------------------------------------------------------------

%% Output contract. Both renderings are shared with the Go harness and
%% every other binding's loop utility field for field: the same lines
%% in the same order, the same keys in the same order, floats with a
%% fixed number of decimals so the JSON is byte-identical across
%% implementations. The Go harness alone adds its runtime-internal
%% lines after rss: and its runtime-internal keys after
%% parallax_chunk_pool; nothing here reproduces them because nothing
%% they read is reachable through the binding.
-spec final(#run{}, [#wstats{}], integer(),
            {non_neg_integer(), non_neg_integer(), non_neg_integer()},
            {[integer()], [integer()]}) -> 0 | 1.
final(Run, Stats, ElapsedNs, {RssWarmup, RssPeak, RssFinal}, {PoolWarmup, PoolSteady}) ->
    Cfg = Run#run.cfg,
    TotalIters = sum(Stats, #wstats.iters),
    TotalEnc = sum(Stats, #wstats.bytes_enc),
    TotalDec = sum(Stats, #wstats.bytes_dec),
    NanosEnc = sum(Stats, #wstats.nanos_enc),
    NanosDec = sum(Stats, #wstats.nanos_dec),
    Errors = [S#wstats.error || S <- Stats, S#wstats.failed],

    %% Throughput. Per-direction throughput divides the sum of every
    %% worker's wall time in that direction by the worker count — the
    %% equivalent single-stream wall time under N-way concurrency — so
    %% each direction reports the aggregate rate it sustained rather
    %% than collapsing to combined/2 (every iteration moves equal
    %% encrypt and decrypt bytes, so a total-elapsed denominator would
    %% give both directions the same figure). The combined rate keeps
    %% total elapsed as the one-glance overall figure.
    Workers = Cfg#cfg.workers,
    AvgEnc = case NanosEnc > 0 of true -> NanosEnc div Workers; false -> 0 end,
    AvgDec = case NanosDec > 0 of true -> NanosDec div Workers; false -> 0 end,

    RssDelta = RssFinal - RssWarmup,
    RssGrowth = case RssWarmup > 0 of
                    true -> 100.0 * RssDelta / RssWarmup;
                    false -> 0.0
                end,
    {TierList, Buf, Chunk} = pool_diff(PoolWarmup, PoolSteady),
    Pass = Errors =:= [],
    Rekeys = loop_state:count(Run#run.counts, rekeys),
    Cycles = loop_state:count(Run#run.counts, blob_cycles),
    Gomaxprocs = itb3:set_gomaxprocs(0),
    {StreamPipe, MsgPipe} = loop_state:handles(Run#run.state),
    StreamProfile = case StreamPipe of
                        undefined -> "";
                        _ -> Run#run.stream_profile
                    end,
    MsgProfile = case MsgPipe of
                     undefined -> "";
                     _ -> Run#run.msg_profile
                 end,
    Figures = #{total_iters => TotalIters, total_enc => TotalEnc,
                total_dec => TotalDec, avg_enc => AvgEnc, avg_dec => AvgDec,
                elapsed => ElapsedNs, errors => Errors, pass => Pass,
                rekeys => Rekeys, cycles => Cycles, gomaxprocs => Gomaxprocs,
                stream_profile => StreamProfile, msg_profile => MsgProfile,
                rss_warmup => RssWarmup, rss_peak => RssPeak,
                rss_final => RssFinal, rss_delta => RssDelta,
                rss_growth => RssGrowth, tiers => TierList,
                buf => Buf, chunk => Chunk, stats => Stats},
    case Cfg#cfg.json_output of
        true -> json(Cfg, Figures);
        false -> human(Cfg, Figures)
    end,
    case Pass of true -> 0; false -> 1 end.

sum(Stats, Field) ->
    lists:sum([element(Field, S) || S <- Stats]).

%% ------------------------------------------------------------------

json(Cfg, F) ->
    #{total_iters := TotalIters, total_enc := TotalEnc, total_dec := TotalDec,
      avg_enc := AvgEnc, avg_dec := AvgDec, elapsed := Elapsed,
      errors := Errors, pass := Pass, rekeys := Rekeys, cycles := Cycles,
      gomaxprocs := Gomaxprocs, stream_profile := StreamProfile,
      msg_profile := MsgProfile, rss_warmup := RssWarmup, rss_peak := RssPeak,
      rss_final := RssFinal, rss_growth := RssGrowth, tiers := Tiers,
      buf := Buf, chunk := Chunk, stats := Stats} = F,
    Text =
        ["{\"duration_seconds\":", f3(Elapsed / 1.0e9),
         ",\"iterations\":", int(TotalIters),
         ",\"per_worker_iterations\":[",
         lists:join(",", [int(S#wstats.iters) || S <- Stats]), "]",
         ",\"bytes_encrypted\":", int(TotalEnc),
         ",\"bytes_decrypted\":", int(TotalDec),
         ",\"encrypt_mb_per_sec\":", f1(loop_size:mb_per_sec(TotalEnc, AvgEnc)),
         ",\"decrypt_mb_per_sec\":", f1(loop_size:mb_per_sec(TotalDec, AvgDec)),
         ",\"combined_mb_per_sec\":", f1(loop_size:mb_per_sec(TotalEnc + TotalDec, Elapsed)),
         ",\"rekeys\":", int(Rekeys),
         ",\"blob_cycles\":", int(Cycles),
         ",\"worker_errors\":[", lists:join(",", [jstr(E) || E <- Errors]), "]",
         ",\"verdict\":", jstr(verdict(Pass)),
         ",\"shape\":", jstr(loop_worker:shape_name(Cfg#cfg.shape)),
         ",\"stream_profile\":", jstr(StreamProfile),
         ",\"message_profile\":", jstr(MsgProfile),
         ",\"hash\":", jstr(Cfg#cfg.hash),
         ",\"mac\":", jstr(Cfg#cfg.mac),
         ",\"payload_bytes\":", int(Cfg#cfg.payload),
         ",\"payload_mode\":", jstr(loop_payload:mode_name(Cfg#cfg.payload_mode)),
         ",\"seed\":", int(Cfg#cfg.seed),
         ",\"key_bits\":", int(Cfg#cfg.key_bits),
         ",\"nonce_bits\":", int(Cfg#cfg.nonce_bits),
         ",\"blob_mode\":", int(Cfg#cfg.blob_mode),
         ",\"drbg\":", jstr(Cfg#cfg.drbg),
         ",\"drbg_auto_tier\":", jstr(drbg_auto_tier()),
         ",\"chunk_size_bytes\":", int(Cfg#cfg.chunk_size),
         ",\"barrier_fill\":", int(Cfg#cfg.barrier_fill),
         ",\"parallax\":", jstr(loop_main:on_off(Cfg#cfg.parallax)),
         ",\"wrapper\":", jstr(loop_main:on_off(Cfg#cfg.wrapper)),
         ",\"goroutines_requested\":", int(Cfg#cfg.workers_requested),
         ",\"goroutines\":", int(Cfg#cfg.workers),
         ",\"concurrency\":", jstr(?LOOP_CONCURRENCY),
         ",\"gogc\":", jstr(integer_to_list(effective_gogc(Cfg#cfg.gogc))),
         ",\"memlimit_bytes\":", int(Cfg#cfg.memlimit),
         ",\"gomaxprocs\":", int(Gomaxprocs),
         ",\"microbatch_tiers\":", jstr(loop_main:policy_label("ITB_MICROBATCH_TIERS")),
         ",\"hashpool_starters\":", jstr(loop_main:policy_label("ITB_HASHPOOL_STARTERS")),
         ",\"rss_warmup_bytes\":", int(RssWarmup),
         ",\"rss_peak_bytes\":", int(RssPeak),
         ",\"rss_final_bytes\":", int(RssFinal),
         ",\"rss_growth_percent\":", f2(RssGrowth),
         ",\"hash_pool_tiers\":[", lists:join(",", [json_tier(T) || T <- Tiers]), "]",
         ",\"buf_pool\":", json_byte_pool(Buf),
         ",\"parallax_chunk_pool\":", json_byte_pool(Chunk),
         "}\n"],
    loop_main:emit(standard_io, Text).

json_tier(T) ->
    #{tier := I, starter := Starter, get := Get, new := New,
      regrow := Regrow, new_bytes := NewBytes} = T,
    ["{\"tier\":", int(I), ",\"starter\":", int(Starter),
     ",\"get\":", int(Get), ",\"new\":", int(New), ",\"regrow\":", int(Regrow),
     ",\"new_bytes\":", int(NewBytes),
     ",\"miss_percent\":", f2(miss_percent(New + Regrow, Get)), "}"].

json_byte_pool(P) ->
    #{get := Get, new := New, regrow := Regrow, regrow_bytes := RegrowBytes} = P,
    ["{\"get\":", int(Get), ",\"new\":", int(New), ",\"regrow\":", int(Regrow),
     ",\"regrow_bytes\":", int(RegrowBytes),
     ",\"miss_percent\":", f2(miss_percent(Regrow, Get)), "}"].

int(N) -> integer_to_list(N).

f1(V) -> io_lib:format("~.1f", [float(V)]).
f2(V) -> io_lib:format("~.2f", [float(V)]).
f3(V) -> io_lib:format("~.3f", [float(V)]).

%% One JSON string literal with the escapes JSON requires.
%% The fill cipher the auto DRBG tier selected on this host; empty
%% when the library cannot report it.
drbg_auto_tier() ->
    case itb3:drbg_auto_tier() of
        {ok, Tier} -> Tier;
        {error, _} -> ""
    end.

jstr(S) ->
    [$", [json_char(C) || C <- unicode:characters_to_list(iolist_to_binary(S))], $"].

json_char($") -> "\\\"";
json_char($\\) -> "\\\\";
json_char($\n) -> "\\n";
json_char($\r) -> "\\r";
json_char($\t) -> "\\t";
json_char(C) when C < 16#20 -> io_lib:format("\\u~4.16.0b", [C]);
json_char(C) -> C.

verdict(true) -> "PASS";
verdict(false) -> "FAIL".

%% The effective GC percentage as the runtime reports it: the query
%% form of the setter (a set-and-restore round trip inside the
%% library) so the field is the same whether the value came from the
%% flag, the environment, or the runtime default.
effective_gogc(Flag) when Flag > 0 -> Flag;
effective_gogc(_Flag) -> itb3:set_gc_percent(-1).

%% ------------------------------------------------------------------

human(Cfg, F) ->
    #{total_iters := TotalIters, total_enc := TotalEnc, total_dec := TotalDec,
      avg_enc := AvgEnc, avg_dec := AvgDec, elapsed := Elapsed,
      errors := Errors, pass := Pass, rekeys := Rekeys, cycles := Cycles,
      rss_warmup := RssWarmup, rss_peak := RssPeak, rss_final := RssFinal,
      rss_delta := RssDelta, rss_growth := RssGrowth, tiers := Tiers,
      buf := Buf, chunk := Chunk, stats := Stats} = F,
    loop_main:log("=== FINAL ===", []),
    loop_main:log("  duration: ~s",
                  [loop_size:human_duration((Elapsed + 500000) div 1000000 * 1000000)]),
    Parts = lists:join(" + ", [integer_to_list(S#wstats.iters) || S <- Stats]),
    loop_main:log("  iterations: ~s = ~B total", [Parts, TotalIters]),
    loop_main:log("  throughput: encrypt ~s, decrypt ~s, combined ~s",
                  [loop_size:human_rate(TotalEnc, AvgEnc),
                   loop_size:human_rate(TotalDec, AvgDec),
                   loop_size:human_rate(TotalEnc + TotalDec, Elapsed)]),
    loop_main:log("  bytes: ~s encrypted, ~s decrypted",
                  [loop_size:human_bytes(TotalEnc), loop_size:human_bytes(TotalDec)]),
    loop_main:log("  data integrity: ~B/~B PASS", [TotalIters, TotalIters]),
    loop_main:log("  concurrency: ~s, workers ~B (requested ~B)",
                  [?LOOP_CONCURRENCY, Cfg#cfg.workers, Cfg#cfg.workers_requested]),
    loop_main:log("  rss: warmup ~s, peak ~s, final ~s (delta ~s, ~.1f% growth)",
                  [loop_size:human_bytes(RssWarmup), loop_size:human_bytes(RssPeak),
                   loop_size:human_bytes(RssFinal), loop_size:human_bytes_signed(RssDelta),
                   float(RssGrowth)]),
    [human_tier(T) || T <- Tiers],
    loop_main:log("  buf pool: get ~B, regrow ~B (of which fresh ~B), miss ~.2f%, ~s regrown",
                  [maps:get(get, Buf), maps:get(regrow, Buf), maps:get(new, Buf),
                   float(miss_percent(maps:get(regrow, Buf), maps:get(get, Buf))),
                   loop_size:human_bytes(maps:get(regrow_bytes, Buf))]),
    loop_main:log("  parallax chunk pool: get ~B, regrow ~B (of which fresh ~B), "
                  "miss ~.2f%, ~s regrown",
                  [maps:get(get, Chunk), maps:get(regrow, Chunk), maps:get(new, Chunk),
                   float(miss_percent(maps:get(regrow, Chunk), maps:get(get, Chunk))),
                   loop_size:human_bytes(maps:get(regrow_bytes, Chunk))]),
    case Rekeys > 0 of
        true -> loop_main:log("  rekeys: ~B", [Rekeys]);
        false -> ok
    end,
    case Cycles > 0 of
        true -> loop_main:log("  blob cycles: ~B", [Cycles]);
        false -> ok
    end,
    [loop_main:log("  ERROR: ~s", [E]) || E <- Errors],
    case Pass of
        true -> loop_main:log("  verdict: PASS", []);
        false -> loop_main:log("  verdict: FAIL (errors=~B)", [length(Errors)])
    end.

human_tier(T) ->
    #{tier := I, starter := Starter, get := Get, new := New,
      regrow := Regrow, new_bytes := NewBytes} = T,
    loop_main:log("  hash pool tier ~B (starter ~B): get ~B, miss ~B (new ~B + regrow ~B), "
                  "miss ~.2f%, ~s allocated",
                  [I, Starter, Get, New + Regrow, New, Regrow,
                   float(miss_percent(New + Regrow, Get)),
                   loop_size:human_bytes(NewBytes)]).
