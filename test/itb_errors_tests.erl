%% Error-mapping surface: opaque-string relay, unknown profile,
%% tampered-wire MAC failure, freed-handle paths, profile registration
%% from a JSON record (with an 8-entry `hashes` constellation),
%% duplicate registration.

-module(itb_errors_tests).

-include_lib("eunit/include/eunit.hrl").

unknown_profile_test() ->
    {error, {unknown_profile, Detail}} = itb:init(<<"no-such-profile">>, #{}),
    ?assert(byte_size(Detail) > 0).

unknown_opts_key_test() ->
    %% Typoed lowercase s — the binding performs no key validation of
    %% its own; Go rejects the unknown key.
    ?assertMatch({error, {bad_input, _}},
                 itb:init(<<"singlemsg-triple-mac-v1">>,
                          #{chunksize => 4096})).

unknown_inner_hash_test() ->
    %% An unknown inner-hash name is relayed to Go and rejected there.
    ?assertMatch({error, _},
                 itb:init(<<"singlemsg-triple-mac-v1">>,
                          #{innerHash => <<"no-such-hash">>})).

malformed_blob_test() ->
    ?assertMatch({error, _}, itb:load(<<"not a session blob">>)).

%% A bit flip in authenticated wire content fails with mac_failure.
%% A single flip can land in the container's CSPRNG residue — where
%% the decrypt legitimately completes clean — so successive flip
%% positions are probed until one lands in authenticated content.
tampered_message_test_() ->
    {timeout, 300, fun() ->
        {Sender, Receiver} =
            itb_test_util:pair(<<"singlemsg-triple-mac-v1">>, #{}),
        Plain = crypto:strong_rand_bytes(4096),
        {ok, Wire} = itb:encrypt_message(Sender, Plain),
        ?assert(probe_flip(Receiver, Wire, 0)),
        ok = itb:free(Receiver),
        ok = itb:free(Sender)
    end}.

probe_flip(_Receiver, Wire, Pos) when Pos >= byte_size(Wire) ->
    false;
probe_flip(Receiver, Wire, Pos) ->
    Tampered = itb_test_util:flip_byte(Wire, Pos),
    case itb:decrypt_message(Receiver, Tampered) of
        {error, {mac_failure, _}} ->
            true;
        {ok, _} ->
            %% Flip landed in unauthenticated residue — next position.
            probe_flip(Receiver, Wire, Pos + 1);
        {error, {_, _}} ->
            %% A flip in the envelope framing may fail structurally
            %% before MAC verification; keep probing for a MAC hit.
            probe_flip(Receiver, Wire, Pos + 1)
    end.

freed_pipeline_test() ->
    {ok, Pipe} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
    ok = itb:free(Pipe),
    ok = itb:free(Pipe), %% idempotent
    ?assertMatch({error, {bad_handle, _}}, itb:encrypt_message(Pipe, <<"x">>)),
    ?assertMatch({error, {bad_handle, _}}, itb:save(Pipe)),
    ?assertMatch({error, {bad_handle, _}}, itb:encrypt_stream(Pipe)).

freed_stream_test_() ->
    {timeout, 120, fun() ->
        {ok, Pipe} = itb:init(<<"streaming-aead-triple-mac-v1">>, #{}),
        {ok, Stream} = itb:encrypt_stream(Pipe),
        ok = itb:stream_free(Stream),
        ok = itb:stream_free(Stream), %% idempotent
        ?assertMatch({error, {bad_handle, _}},
                     itb:stream_write(Stream, <<"x">>)),
        ?assertMatch({error, {bad_handle, _}}, itb:stream_end(Stream)),
        ?assertMatch({error, {bad_handle, _}}, itb:stream_read(Stream, 16)),
        ok = itb:free(Pipe)
    end}.

badarg_test() ->
    ?assertError(badarg, itb:encrypt_message(make_ref(), <<"x">>)),
    ?assertError(badarg, itb:stream_write(make_ref(), <<"x">>)),
    ?assertError(function_clause, itb:init(<<"p">>, not_opts)).

%% Register with an 8-entry width-256 hashes constellation, layers
%% off; the registered profile round-trips, is visible in the
%% catalogue, and a duplicate registration fails with profile_exists.
register_test_() ->
    {timeout, 240, fun() ->
        Hashes = [<<"blake3">>, <<"blake2s">>, <<"areion256">>, <<"blake2b256">>,
                  <<"chacha20">>, <<"blake3">>, <<"blake2s">>, <<"areion256">>],
        Profile = #{<<"mode">> => <<"singlemsg-nomac">>,
                    <<"width">> => 256,
                    <<"hashes">> => Hashes,
                    <<"keybits">> => 1024,
                    <<"parallax">> => false,
                    <<"wrapper">> => false},
        ok = itb:register(<<"erlang-binding-test-mixed">>, Profile),
        ?assert(lists:member(<<"erlang-binding-test-mixed">>, itb:profiles())),
        {ok, Record} = itb:lookup(<<"erlang-binding-test-mixed">>),
        ?assertEqual(Hashes, maps:get(<<"hashes">>, Record)),
        ?assertMatch({error, {profile_exists, _}},
                     itb:register(<<"erlang-binding-test-mixed">>, Profile)),
        %% Strict record decode on the Go side: an unknown key is
        %% rejected there, not by the binding.
        ?assertMatch({error, {bad_input, _}},
                     itb:register(<<"erlang-binding-test-badkey">>,
                                  <<"{\"mode\":\"singlemsg-nomac\",\"bogus\":1}">>)),
        {Sender, Receiver} =
            itb_test_util:pair(<<"erlang-binding-test-mixed">>, #{}),
        Plain = crypto:strong_rand_bytes(8192),
        {ok, Wire} = itb:encrypt_message(Sender, Plain),
        {ok, Back} = itb:decrypt_message(Receiver, Wire),
        ?assertEqual(Plain, Back),
        ok = itb:free(Receiver),
        ok = itb:free(Sender)
    end}.
