%% A decrypt session fed a tampered wire fails with a sticky
%% mac_failure.
%%
%% A single bit flip can land in the container's CSPRNG residue —
%% over-sized container area that carries no payload — where the
%% decrypt legitimately completes clean. Successive flip positions are
%% therefore probed, each against a fresh session on a fresh copy of
%% the wire, until one lands in authenticated content; the observed
%% failure must be mac_failure and must be sticky. The probe is
%% black-box — no wire-layout knowledge is used.

-module(itb_stream_sticky_tests).

-include_lib("eunit/include/eunit.hrl").

sticky_test_() ->
    {timeout, 600, fun sticky_mac_failure/0}.

sticky_mac_failure() ->
    {Sender, Receiver} =
        itb_test_util:pair(<<"streaming-aead-triple-mac-v1">>, #{}),
    Plain = crypto:strong_rand_bytes(65536),
    Wire = itb_test_util:pump(Sender, encrypt, Plain),
    ?assert(probe(Receiver, Wire, 0)),
    ok = itb:free(Receiver),
    ok = itb:free(Sender).

%% Flip positions walk the wire body (starting at the 3/4 mark with a
%% 1031-byte stride) so the probe stays clear of the outer framing
%% header, whose corruption fails structurally before authentication.
probe(_Receiver, _Wire, Attempt) when Attempt >= 32 ->
    false;
probe(Receiver, Wire, Attempt) ->
    WireLen = byte_size(Wire),
    Pos = (WireLen * 3 div 4 + Attempt * 1031) rem WireLen,
    Tampered = itb_test_util:flip_byte(Wire, Pos),
    {ok, Stream} = itb:decrypt_stream(Receiver),
    %% The failure may surface on write (chain already failed) or on a
    %% later read — either way a read must eventually report it.
    _ = itb:stream_write(Stream, Tampered),
    _ = itb:stream_end(Stream),
    Result = drain_to_status(Stream),
    Verdict =
        case Result of
            clean ->
                next; %% flip landed in residue — try the next position
            {error, {mac_failure, _}} ->
                %% Sticky: a subsequent read reports a failure again.
                case itb:stream_read(Stream, 4096) of
                    {error, {mac_failure, _}} -> true;
                    Other -> {unexpected_second, Other}
                end;
            Other ->
                {unexpected_first, Other}
        end,
    ok = itb:stream_free(Stream),
    case Verdict of
        true -> true;
        next -> probe(Receiver, Wire, Attempt + 1);
        Unexpected -> ?assertEqual(sticky_mac_failure, Unexpected)
    end.

drain_to_status(Stream) ->
    case itb:stream_read(Stream, 4096) of
        {ok, _, true} -> clean;
        {ok, _, false} -> drain_to_status(Stream);
        {error, Reason} -> {error, Reason}
    end.
