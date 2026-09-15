%% Init -> rekey -> load receiver with the rotated blob -> round trip.

-module(itb_rekey_tests).

-include_lib("eunit/include/eunit.hrl").

rekey_test_() ->
    {timeout, 120, fun rekey_round_trip/0}.

rekey_round_trip() ->
    {ok, Sender} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
    {ok, Before} = itb3:save(Sender),

    Perm = binary:copy(<<16#11>>, 32),
    Wrap = binary:copy(<<16#22>>, 32),
    {ok, After} = itb3:rekey(Sender, Perm, Wrap),
    ?assertNotEqual(Before, After),
    ?assertEqual({ok, After}, itb3:save(Sender)),

    {ok, Receiver} = itb3:load(After),
    Plain = <<"post-rekey payload">>,
    {ok, Wire} = itb3:encrypt_message(Sender, Plain),
    {ok, Back} = itb3:decrypt_message(Receiver, Wire),
    ?assertEqual(Plain, Back),

    ok = itb3:free(Receiver),
    ok = itb3:free(Sender).
