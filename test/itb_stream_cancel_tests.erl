%% Freeing an encrypt session mid-flight releases resources cleanly
%% and leaves the Pipeline usable; dropped term references let the
%% resource destructors release as the backstop.

-module(itb_stream_cancel_tests).

-include_lib("eunit/include/eunit.hrl").

cancel_test_() ->
    {timeout, 240, fun cancel_mid_flight/0}.

cancel_mid_flight() ->
    {ok, Sender} = itb:init(<<"streaming-aead-triple-mac-v1">>, #{}),

    Chunk = crypto:strong_rand_bytes(100000),
    {ok, Stream} = itb:encrypt_stream(Sender),
    ok = itb:stream_write(Stream, Chunk),
    %% Freed here without end/1 — stream_free cancels the session.
    ok = itb:stream_free(Stream),

    %% The Pipeline stays usable after the cancelled session.
    {ok, Blob} = itb:save(Sender),
    {ok, Receiver} = itb:load(Blob),
    Plain = <<"after cancel">>,
    {ok, Wire} = itb:encrypt_message(Sender, Plain),
    {ok, Back} = itb:decrypt_message(Receiver, Wire),
    ?assertEqual(Plain, Back),

    ok = itb:free(Receiver),
    ok = itb:free(Sender).

%% Garbage collection releases a dropped mid-flight session + pipeline
%% pair without a crash (the stream resource pins its parent pipeline,
%% so destructor order is safe regardless of collection order).
gc_backstop_test_() ->
    {timeout, 240, fun() ->
        ok = make_and_drop(),
        erlang:garbage_collect(),
        timer:sleep(200),
        %% The NIF stays fully functional after the collected pair.
        {ok, Pipe} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
        {ok, Wire} = itb:encrypt_message(Pipe, <<"post-gc">>),
        ?assert(byte_size(Wire) > 0),
        ok = itb:free(Pipe)
    end}.

make_and_drop() ->
    {ok, Pipe} = itb:init(<<"streaming-aead-triple-mac-v1">>, #{}),
    {ok, Stream} = itb:encrypt_stream(Pipe),
    ok = itb:stream_write(Stream, <<"dropped mid-flight">>),
    ok.
