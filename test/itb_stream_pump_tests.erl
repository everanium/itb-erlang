%% Whole-buffer stream pump round trips (1 MiB feed / drain slices)
%% on the Streaming AEAD and Non-AEAD profiles.

-module(itb_stream_pump_tests).

-include_lib("eunit/include/eunit.hrl").

aead_pump_test_() ->
    {timeout, 300, fun() -> pump_round_trip(<<"streaming-aead-triple-mac-v1">>) end}.

noaead_pump_test_() ->
    {timeout, 300, fun() -> pump_round_trip(<<"streaming-noaead-triple-v1">>) end}.

pump_round_trip(Profile) ->
    {Sender, Receiver} = itb_test_util:pair(Profile, #{}),
    Plain = crypto:strong_rand_bytes((1 bsl 20) + 12345),
    Wire = itb_test_util:pump(Sender, encrypt, Plain),
    ?assert(byte_size(Wire) > byte_size(Plain)),
    Back = itb_test_util:pump(Receiver, decrypt, Wire),
    ?assertEqual(Plain, Back),
    ok = itb:free(Receiver),
    ok = itb:free(Sender).

%% Two sequential sessions on the same Pipeline stay independent.
sequential_sessions_test_() ->
    {timeout, 300, fun() ->
        {Sender, Receiver} =
            itb_test_util:pair(<<"streaming-aead-triple-mac-v1">>, #{}),
        Plain1 = crypto:strong_rand_bytes(200000),
        Plain2 = crypto:strong_rand_bytes(100000),
        Wire1 = itb_test_util:pump(Sender, encrypt, Plain1),
        Wire2 = itb_test_util:pump(Sender, encrypt, Plain2),
        ?assertEqual(Plain1, itb_test_util:pump(Receiver, decrypt, Wire1)),
        ?assertEqual(Plain2, itb_test_util:pump(Receiver, decrypt, Wire2)),
        ok = itb:free(Receiver),
        ok = itb:free(Sender)
    end}.

%% Go core rejects zero-payload streams uniformly with ErrEmptyInput
%% -> {bad_input, _}. The error surfaces on end or on the subsequent
%% drain when no bytes were written; a stream carrying no plaintext
%% produces no wire on this surface.
empty_pump_test_() ->
    {timeout, 120, fun() ->
        {ok, Sender} = itb:init(<<"streaming-aead-triple-mac-v1">>, #{}),
        {ok, Stream} = itb:encrypt_stream(Sender),
        EndResult = itb:stream_end(Stream),
        ReadResult = itb:stream_read(Stream, 1024),
        ?assert(case EndResult of
                    {error, {bad_input, _}} -> true;
                    _ -> false
                end
                orelse case ReadResult of
                           {error, {bad_input, _}} -> true;
                           _ -> false
                       end),
        ok = itb:stream_free(Stream),
        ok = itb:free(Sender)
    end}.
