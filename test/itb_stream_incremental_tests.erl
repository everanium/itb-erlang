%% Explicit write / end / read round trip with pathological batch
%% sizes (17-byte feed, 23-byte drain) across multiple chunks.

-module(itb_stream_incremental_tests).

-include_lib("eunit/include/eunit.hrl").

incremental_test_() ->
    {timeout, 600, fun incremental_round_trip/0}.

incremental_round_trip() ->
    %% Small chunk size so the 64 KiB payload spans many chunks.
    Opts = #{chunkSize => 4096},
    {Sender, Receiver} =
        itb_test_util:pair(<<"streaming-aead-triple-mac-v1">>, Opts),

    Plain = << <<(I rem 241)>> || I <- lists:seq(0, 65535) >>,

    Wire = itb_test_util:pump(Sender, encrypt, Plain, 17, 23),
    Back = itb_test_util:pump(Receiver, decrypt, Wire, 17, 23),
    ?assertEqual(Plain, Back),

    ok = itb:free(Receiver),
    ok = itb:free(Sender).

%% end/1 is idempotent; write after end fails with bad_input.
end_semantics_test_() ->
    {timeout, 120, fun() ->
        {ok, Pipe} = itb:init(<<"streaming-aead-triple-mac-v1">>, #{}),
        {ok, Stream} = itb:encrypt_stream(Pipe),
        ok = itb:stream_write(Stream, <<"payload">>),
        ok = itb:stream_end(Stream),
        ok = itb:stream_end(Stream),
        ?assertMatch({error, {bad_input, _}},
                     itb:stream_write(Stream, <<"late">>)),
        ok = itb:stream_free(Stream),
        ok = itb:free(Pipe)
    end}.
