%% Init -> blob -> Open -> encrypt_message -> decrypt_message round
%% trip on the MAC Single Message profile.

-module(itb_smoke_tests).

-include_lib("eunit/include/eunit.hrl").

smoke_round_trip_test_() ->
    {timeout, 120, fun smoke_round_trip/0}.

smoke_round_trip() ->
    {ok, Sender} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
    {ok, Blob} = itb:blob(Sender),
    ?assert(byte_size(Blob) > 0),

    {ok, Receiver} = itb:open(<<"singlemsg-triple-mac-v1">>, Blob, #{}),

    Plain = <<"smoke round-trip payload">>,
    {ok, Wire} = itb:encrypt_message(Sender, Plain),
    ?assertNotEqual(Plain, Wire),

    {ok, Back} = itb:decrypt_message(Receiver, Wire),
    ?assertEqual(Plain, Back),

    ok = itb:free(Receiver),
    ok = itb:free(Sender).

version_test() ->
    {ok, Version} = itb:version(),
    ?assert(byte_size(Version) > 0).

hashes_test() ->
    Hashes = itb:hashes(),
    ?assert(length(Hashes) > 0),
    lists:foreach(
      fun({Name, Width}) ->
              ?assert(is_binary(Name) andalso byte_size(Name) > 0),
              ?assert(is_integer(Width) andalso Width > 0)
      end, Hashes).

runtime_knobs_test() ->
    %% Negative values query without changing; the return is the
    %% previous setting.
    Prev = itb:set_memory_limit(-1),
    ?assert(is_integer(Prev)),
    ?assertEqual(Prev, itb:set_memory_limit(-1)),
    PrevGC = itb:set_gc_percent(-2),
    ?assert(is_integer(PrevGC)).
