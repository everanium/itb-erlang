%% Single Message round trips across shipped profiles and payload
%% shapes (empty, 1 byte, structured, CSPRNG-filled).

-module(itb_message_tests).

-include_lib("eunit/include/eunit.hrl").

mac_profile_test_() ->
    {timeout, 240, fun() -> round_trips(<<"singlemsg-triple-mac-v1">>) end}.

nomac_profile_test_() ->
    {timeout, 240, fun() -> round_trips(<<"singlemsg-triple-nomac-v1">>) end}.

round_trips(Profile) ->
    {Sender, Receiver} = itb_test_util:pair(Profile, #{}),
    Payloads = [<<>>,
                <<0>>,
                <<"any text or binary data">>,
                binary:copy(<<16#00>>, 4096),
                binary:copy(<<16#FF>>, 4096),
                crypto:strong_rand_bytes(100000)],
    lists:foreach(
      fun(Plain) ->
              {ok, Wire} = itb:encrypt_message(Sender, Plain),
              ?assert(Plain =:= <<>> orelse Wire =/= Plain),
              {ok, Back} = itb:decrypt_message(Receiver, Wire),
              ?assertEqual(Plain, Back)
      end, Payloads),
    ok = itb:free(Receiver),
    ok = itb:free(Sender).

%% Two encryptions of the same plaintext must produce different wires
%% (fresh nonce per message).
wire_uniqueness_test_() ->
    {timeout, 120, fun() ->
        {ok, Sender} = itb:init(<<"singlemsg-triple-nomac-v1">>, #{}),
        Plain = crypto:strong_rand_bytes(4096),
        {ok, Wire1} = itb:encrypt_message(Sender, Plain),
        {ok, Wire2} = itb:encrypt_message(Sender, Plain),
        ?assertNotEqual(Wire1, Wire2),
        ok = itb:free(Sender)
    end}.

%% Opts pass-through: an explicit keyBits / nonceBits pair reaches Go
%% and the round trip still holds.
opts_pass_through_test_() ->
    {timeout, 120, fun() ->
        Opts = #{keyBits => 1024, nonceBits => 512},
        {Sender, Receiver} =
            itb_test_util:pair(<<"singlemsg-triple-mac-v1">>, Opts),
        Plain = crypto:strong_rand_bytes(8192),
        {ok, Wire} = itb:encrypt_message(Sender, Plain),
        {ok, Back} = itb:decrypt_message(Receiver, Wire),
        ?assertEqual(Plain, Back),
        ok = itb:free(Receiver),
        ok = itb:free(Sender)
    end}.
