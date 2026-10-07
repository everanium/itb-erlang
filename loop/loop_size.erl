%% Size and duration parsing, the monotonic clock, and the human
%% renderings of sizes, rates and durations. Every rendering here is
%% part of the output contract shared with the Go harness and the
%% other bindings' loop utilities, so the formats are fixed to the
%% character, not to taste.

-module(loop_size).

-export([parse_size/1, parse_duration/1, now_ns/0,
         human_bytes/1, human_bytes_signed/1, human_rate/2,
         human_duration/1, mb_per_sec/2]).

%% Parses a human byte-size string ("16MB", "1MiB", "512K",
%% "1073741824") into a byte count. Every suffix is a binary multiple:
%% K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
%% bytes; matching is case-insensitive and surrounding whitespace is
%% trimmed. Returns {ok, Bytes} or error.
-spec parse_size(string()) -> {ok, non_neg_integer()} | error.
parse_size(S) ->
    Trimmed = string:trim(S),
    Upper = string:uppercase(Trimmed),
    case Upper of
        "" -> error;
        _ -> split_suffix(Upper)
    end.

split_suffix(Upper) ->
    Table = [{"KIB", 1 bsl 10}, {"KB", 1 bsl 10}, {"K", 1 bsl 10},
             {"MIB", 1 bsl 20}, {"MB", 1 bsl 20}, {"M", 1 bsl 20},
             {"GIB", 1 bsl 30}, {"GB", 1 bsl 30}, {"G", 1 bsl 30},
             {"B", 1}],
    {Digits, Mult} = match_suffix(Upper, Table),
    %% Whitespace may sit between the number and its unit ("16 MB").
    case string:trim(Digits, trailing) of
        "" -> error;
        D ->
            case lists:all(fun(C) -> C >= $0 andalso C =< $9 end, D) of
                true -> {ok, list_to_integer(D) * Mult};
                false -> error
            end
    end.

match_suffix(Upper, []) ->
    {Upper, 1};
match_suffix(Upper, [{Suffix, Mult} | Rest]) ->
    SL = length(Suffix),
    UL = length(Upper),
    case UL >= SL andalso lists:sublist(Upper, UL - SL + 1, SL) =:= Suffix of
        true -> {lists:sublist(Upper, UL - SL), Mult};
        false -> match_suffix(Upper, Rest)
    end.

%% Parses the Go duration grammar — a sequence of decimal numbers each
%% followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
%% "1h30m", "1.5s" — into nanoseconds. Returns {ok, Nanos} or error.
-spec parse_duration(string()) -> {ok, integer()} | error.
parse_duration("") ->
    error;
parse_duration(S) ->
    duration_parts(S, 0.0).

duration_parts([], Total) when Total =< 9.2e18 ->
    {ok, trunc(Total)};
duration_parts([], _Total) ->
    error;
duration_parts(S, Total) ->
    case number_prefix(S) of
        error -> error;
        {V, Rest} ->
            case unit_prefix(Rest) of
                error -> error;
                {Mult, Rest2} -> duration_parts(Rest2, Total + V * Mult)
            end
    end.

%% A decimal run with an optional fraction, the shape strtod accepts
%% here. A leading sign is not part of the grammar.
number_prefix([C | _] = S) when (C >= $0 andalso C =< $9) orelse C =:= $. ->
    {Digits, Rest} = lists:splitwith(
                       fun(Ch) -> (Ch >= $0 andalso Ch =< $9) orelse Ch =:= $. end, S),
    case string:to_float(Digits) of
        {Float, ""} -> {Float, Rest};
        _ ->
            case string:to_integer(Digits) of
                {Int, ""} -> {float(Int), Rest};
                _ -> error
            end
    end;
number_prefix(_) ->
    error.

unit_prefix(S) ->
    Units = [{"ns", 1.0}, {"us", 1.0e3}, {"ms", 1.0e6},
             {"s", 1.0e9}, {"m", 60.0e9}, {"h", 3600.0e9}],
    unit_prefix(S, Units).

unit_prefix(_S, []) ->
    error;
unit_prefix(S, [{Unit, Mult} | Rest]) ->
    UL = length(Unit),
    case lists:prefix(Unit, S) of
        true ->
            Tail = lists:nthtail(UL, S),
            %% A longer word starting with this unit is not this unit.
            case Tail of
                [C | _] when (C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z) ->
                    unit_prefix(S, Rest);
                _ -> {Mult, Tail}
            end;
        false -> unit_prefix(S, Rest)
    end.

%% Monotonic wall clock in nanoseconds.
-spec now_ns() -> integer().
now_ns() ->
    erlang:monotonic_time(nanosecond).

%% Renders a byte count with a binary-unit suffix: "1.0GiB",
%% "16.0MiB", "4.0KiB", "512B".
-spec human_bytes(integer()) -> string().
human_bytes(N) when N >= (1 bsl 30) ->
    fmt("~.1fGiB", [N / (1 bsl 30)]);
human_bytes(N) when N >= (1 bsl 20) ->
    fmt("~.1fMiB", [N / (1 bsl 20)]);
human_bytes(N) when N >= (1 bsl 10) ->
    fmt("~.1fKiB", [N / (1 bsl 10)]);
human_bytes(N) ->
    fmt("~BB", [N]).

%% Renders a possibly-negative byte delta with an explicit sign.
-spec human_bytes_signed(integer()) -> string().
human_bytes_signed(N) when N < 0 ->
    "-" ++ human_bytes(-N);
human_bytes_signed(N) ->
    "+" ++ human_bytes(N).

%% Binary MiB per second over a nanosecond window; 0 when the window
%% is unmeasured.
-spec mb_per_sec(integer(), integer()) -> float().
mb_per_sec(_Bytes, Ns) when Ns =< 0 ->
    0.0;
mb_per_sec(Bytes, Ns) ->
    Bytes / (1 bsl 20) / (Ns / 1.0e9).

%% Renders a throughput as "123.4MB/s" (binary MiB per second) or
%% "n/a" for an unmeasured window.
-spec human_rate(integer(), integer()) -> string().
human_rate(_Bytes, Ns) when Ns =< 0 ->
    "n/a";
human_rate(Bytes, Ns) ->
    fmt("~.1fMB/s", [mb_per_sec(Bytes, Ns)]).

%% Renders a duration the way Go's time.Duration prints: below one
%% second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
%% where the hour part appears when non-zero, the minute part when the
%% hour part appears or the minutes are non-zero, and the seconds
%% carry their fraction with trailing zeros removed ("5s", "5.003s",
%% "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
-spec human_duration(integer()) -> string().
human_duration(Ns0) ->
    Ns = abs(Ns0),
    if
        Ns =:= 0 -> "0s";
        Ns < 1000000000 ->
            Ms = Ns div 1000000,
            %% The remainder is scaled to nine digits so the fraction
            %% renderer is the same one the seconds branch uses.
            Frac = (Ns rem 1000000) * 1000,
            integer_to_list(Ms) ++ fraction(Frac) ++ "ms";
        true ->
            Hours = Ns div 3600000000000,
            Rem1 = Ns rem 3600000000000,
            Minutes = Rem1 div 60000000000,
            Rem2 = Rem1 rem 60000000000,
            Seconds = Rem2 div 1000000000,
            Frac = Rem2 rem 1000000000,
            HPart = case Hours > 0 of
                        true -> integer_to_list(Hours) ++ "h";
                        false -> ""
                    end,
            MPart = case Hours > 0 orelse Minutes > 0 of
                        true -> integer_to_list(Minutes) ++ "m";
                        false -> ""
                    end,
            HPart ++ MPart ++ integer_to_list(Seconds) ++ fraction(Frac) ++ "s"
    end.

%% The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
%% with trailing zeros removed; empty for zero.
fraction(0) ->
    "";
fraction(FracNs) ->
    Digits = string:pad(integer_to_list(FracNs), 9, leading, $0),
    case string:trim(lists:flatten(Digits), trailing, "0") of
        "" -> "";
        Trimmed -> "." ++ Trimmed
    end.

fmt(Format, Args) ->
    lists:flatten(io_lib:format(Format, Args)).
