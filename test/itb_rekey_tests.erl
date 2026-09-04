%% Init -> rekey -> load receiver with the rotated blob -> round trip.

-module(itb_rekey_tests).

-include_lib("eunit/include/eunit.hrl").

rekey_test_() ->
    {timeout, 120, fun rekey_round_trip/0}.

rekey_round_trip() ->
    {ok, Sender} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
    {ok, Before} = itb:save(Sender),

    Perm = binary:copy(<<16#11>>, 32),
    Wrap = binary:copy(<<16#22>>, 32),
    {ok, After} = itb:rekey(Sender, Perm, Wrap),
    ?assertNotEqual(Before, After),
    ?assertEqual({ok, After}, itb:save(Sender)),

    {ok, Receiver} = itb:load(After),
    Plain = <<"post-rekey payload">>,
    {ok, Wire} = itb:encrypt_message(Sender, Plain),
    {ok, Back} = itb:decrypt_message(Receiver, Wire),
    ?assertEqual(Plain, Back),

    ok = itb:free(Receiver),
    ok = itb:free(Sender).
