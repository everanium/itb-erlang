%% Plaintext content: the payload modes, the seeded per-worker
%% generator, and the buffer fill from the operating-system CSPRNG.

-module(loop_payload).

-export([mode_name/1, parse_mode/1, seed_worker/2, fill/4, random_bytes/1]).

%% Payload mode selector values for the --payload-mode flag.
%%
%%   - fixed: one CSPRNG-generated buffer per worker, held unchanged
%%     for the whole run (the default).
%%   - rotating: the buffer is regenerated before every iteration, so
%%     no two encrypt calls see the same plaintext.
%%   - pattern_zero / pattern_ff: degenerate constant fills (all 0x00 /
%%     all 0xFF) probing minimum-entropy plaintext handling.
%%   - pattern_ascii: a repeating 'A'..'Z' ramp probing low-entropy
%%     structured text.
-spec mode_name(atom()) -> string().
mode_name(fixed) -> "fixed";
mode_name(rotating) -> "rotating";
mode_name(pattern_zero) -> "pattern-zero";
mode_name(pattern_ff) -> "pattern-ff";
mode_name(pattern_ascii) -> "pattern-ascii".

-spec parse_mode(string()) -> {ok, atom()} | error.
parse_mode("fixed") -> {ok, fixed};
parse_mode("rotating") -> {ok, rotating};
parse_mode("pattern-zero") -> {ok, pattern_zero};
parse_mode("pattern-ff") -> {ok, pattern_ff};
parse_mode("pattern-ascii") -> {ok, pattern_ascii};
parse_mode(_) -> error.

%% Seeded plaintext. The seed makes plaintext content reproducible so
%% a failing iteration can be replayed with the same bytes; it governs
%% nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
%% so a seeded run is a reproduction aid and never a security test.
%% Each worker's stream is domain-separated by its id so seeded
%% workers still hold pairwise-distinct buffers under the fixed and
%% rotating modes. The generator is splitmix64: a few lines in any
%% language, which is why it is the one every binding uses.
-spec seed_worker(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
seed_worker(Seed, WorkerId) ->
    (Seed + WorkerId + 1) band 16#FFFFFFFFFFFFFFFF.

-define(M64, 16#FFFFFFFFFFFFFFFF).

splitmix64(State0) ->
    S = (State0 + 16#9E3779B97F4A7C15) band ?M64,
    Z1 = ((S bxor (S bsr 30)) * 16#BF58476D1CE4E5B9) band ?M64,
    Z2 = ((Z1 bxor (Z1 bsr 27)) * 16#94D049BB133111EB) band ?M64,
    {Z2 bxor (Z2 bsr 31), S}.

%% Draws N bytes from the operating-system CSPRNG.
-spec random_bytes(non_neg_integer()) -> binary().
random_bytes(N) ->
    crypto:strong_rand_bytes(N).

%% Builds one plaintext buffer according to the payload mode. The
%% fixed and rotating modes draw from the seeded generator when the
%% run is seeded and from the OS CSPRNG otherwise; the pattern modes
%% are deterministic regardless of the seed. Returns the buffer and
%% the generator state to carry into the next fill.
-spec fill(atom(), boolean(), non_neg_integer(), non_neg_integer()) ->
          {binary(), non_neg_integer()}.
fill(Mode, false, Rng, N) when Mode =:= fixed; Mode =:= rotating ->
    {random_bytes(N), Rng};
fill(Mode, true, Rng, N) when Mode =:= fixed; Mode =:= rotating ->
    seeded_fill(Rng, N, []);
fill(pattern_zero, _Seeded, Rng, N) ->
    {binary:copy(<<0>>, N), Rng};
fill(pattern_ff, _Seeded, Rng, N) ->
    {binary:copy(<<16#FF>>, N), Rng};
fill(pattern_ascii, _Seeded, Rng, N) ->
    {ascii_ramp(N), Rng}.

%% Eight little-endian bytes per generator draw, the last draw
%% truncated to the bytes the buffer still wants.
seeded_fill(Rng, N, Acc) when N =< 0 ->
    {iolist_to_binary(lists:reverse(Acc)), Rng};
seeded_fill(Rng, N, Acc) ->
    {V, Rng1} = splitmix64(Rng),
    Word = <<V:64/little>>,
    case N >= 8 of
        true -> seeded_fill(Rng1, N - 8, [Word | Acc]);
        false ->
            <<Head:N/binary, _/binary>> = Word,
            seeded_fill(Rng1, 0, [Head | Acc])
    end.

%% Byte i is 'A' + (i rem 26), built from one 26-byte period so a
%% large buffer costs a copy rather than a per-byte comprehension.
ascii_ramp(N) ->
    Period = list_to_binary(lists:seq($A, $Z)),
    Whole = binary:copy(Period, N div 26),
    Tail = binary:part(Period, 0, N rem 26),
    <<Whole/binary, Tail/binary>>.
