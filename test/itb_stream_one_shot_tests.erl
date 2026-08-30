%% One-shot stream round trips (whole buffer in a single call) on the
%% Streaming AEAD and Non-AEAD profiles, wire cross-checks against the
%% incremental session path, and a tampered-wire rejection.

-module(itb_stream_one_shot_tests).

-include_lib("eunit/include/eunit.hrl").

aead_one_shot_test_() ->
    {timeout, 300, fun() ->
        round_trip(<<"streaming-aead-triple-mac-v1">>)
    end}.

noaead_one_shot_test_() ->
    {timeout, 300, fun() ->
        round_trip(<<"streaming-noaead-triple-v1">>)
    end}.

round_trip(Profile) ->
    {Sender, Receiver} = itb_test_util:pair(Profile, #{}),
    Payloads = [<<>>,
                <<0>>,
                <<"any text or binary data">>,
                crypto:strong_rand_bytes((1 bsl 18) + 12345)],
    lists:foreach(
      fun(Plain) ->
              {ok, Wire} = itb:encrypt_stream_one_shot(Sender, Plain),
              ?assert(Plain =:= <<>> orelse byte_size(Wire) > byte_size(Plain)),
              {ok, Back} = itb:decrypt_stream_one_shot(Receiver, Wire),
              ?assertEqual(Plain, Back)
      end, Payloads),
    ok = itb:free(Receiver),
    ok = itb:free(Sender).

%% A one-shot wire decodes through an incremental session, and a
%% session-produced wire decodes through the one-shot entry.
session_interop_test_() ->
    {timeout, 300, fun() ->
        {Sender, Receiver} =
            itb_test_util:pair(<<"streaming-aead-triple-mac-v1">>, #{}),
        Plain = crypto:strong_rand_bytes(262151),
        {ok, Wire} = itb:encrypt_stream_one_shot(Sender, Plain),
        ?assertEqual(Plain, itb_test_util:pump(Receiver, decrypt, Wire)),
        Wire2 = itb_test_util:pump(Sender, encrypt, Plain),
        {ok, Back} = itb:decrypt_stream_one_shot(Receiver, Wire2),
        ?assertEqual(Plain, Back),
        ok = itb:free(Receiver),
        ok = itb:free(Sender)
    end}.

%% A bit flip in authenticated wire content is rejected by the
%% Streaming AEAD profile's per-chunk MAC. A single flip can land in
%% the container's CSPRNG residue — where the decrypt legitimately
%% completes clean — so successive flip positions are probed until one
%% is rejected.
tampered_wire_test_() ->
    {timeout, 300, fun() ->
        {Sender, Receiver} =
            itb_test_util:pair(<<"streaming-aead-triple-mac-v1">>, #{}),
        Plain = crypto:strong_rand_bytes(65536),
        {ok, Wire} = itb:encrypt_stream_one_shot(Sender, Plain),
        ?assert(probe_flip(Receiver, Wire, 0)),
        ok = itb:free(Receiver),
        ok = itb:free(Sender)
    end}.

%% Probes successive flip positions until one is rejected; false only
%% if the whole wire is exhausted.
probe_flip(_Receiver, Wire, Pos) when Pos >= byte_size(Wire) ->
    false;
probe_flip(Receiver, Wire, Pos) ->
    Bad = itb_test_util:flip_byte(Wire, Pos),
    case itb:decrypt_stream_one_shot(Receiver, Bad) of
        {error, {_, _}} -> true;
        {ok, _} -> probe_flip(Receiver, Wire, Pos + 1)
    end.
