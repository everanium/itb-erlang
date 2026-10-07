%% Init -> save -> Load -> encrypt_message -> decrypt_message round
%% trip on the MAC Single Message profile, plus the persistence and
%% profile-catalogue surface.

-module(itb_smoke_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

smoke_round_trip_test_() ->
    {timeout, 120, fun smoke_round_trip/0}.

smoke_round_trip() ->
    {ok, Sender} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
    {ok, Blob} = itb3:save(Sender),
    ?assert(byte_size(Blob) > 0),

    {ok, Receiver} = itb3:load(Blob),

    Plain = <<"smoke round-trip payload">>,
    {ok, Wire} = itb3:encrypt_message(Sender, Plain),
    ?assertNotEqual(Plain, Wire),

    {ok, Back} = itb3:decrypt_message(Receiver, Wire),
    ?assertEqual(Plain, Back),

    ok = itb3:free(Receiver),
    ok = itb3:free(Sender).

version_test() ->
    {ok, Version} = itb3:version(),
    ?assert(byte_size(Version) > 0).

drbg_auto_tier_test() ->
    {ok, Tier} = itb3:drbg_auto_tier(),
    ?assert(lists:member(Tier, [<<"aes-256-ctr">>, <<"chacha20">>])).

save_load_round_trip_test_() ->
    {timeout, 120, fun() ->
        {ok, Sender} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
        {ok, Blob} = itb3:save(Sender),
        ?assertEqual({ok, Blob}, itb3:save(Sender)),
        {ok, Receiver} = itb3:load(Blob),
        ?assertEqual({ok, Blob}, itb3:save(Receiver)),
        {ok, Wire} = itb3:encrypt_message(Sender, <<"in-memory persist">>),
        ?assertEqual({ok, <<"in-memory persist">>},
                     itb3:decrypt_message(Receiver, Wire)),
        ok = itb3:free(Receiver),
        ok = itb3:free(Sender)
    end}.

save_f_load_f_round_trip_test_() ->
    {timeout, 120, fun() ->
        Dir = filename:join(os:getenv("TMPDIR", "/tmp"),
                            "itb-erlang-persist-" ++ os:getpid()),
        ok = file:make_dir(Dir),
        Path = filename:join(Dir, "session.blob"),
        {ok, Sender} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
        ok = itb3:save_f(Sender, Path),
        {ok, #file_info{mode = Mode}} = file:read_file_info(Path),
        ?assertEqual(8#600, Mode band 8#777),
        {ok, Receiver} = itb3:load_f(Path),
        ?assertEqual(itb3:save(Sender), itb3:save(Receiver)),
        {ok, Wire} = itb3:encrypt_message(Sender, <<"file persist">>),
        ?assertEqual({ok, <<"file persist">>},
                     itb3:decrypt_message(Receiver, Wire)),
        ?assertMatch({error, {bad_input, _}},
                     itb3:load_f(filename:join(Dir, "absent.blob"))),
        ok = itb3:free(Receiver),
        ok = itb3:free(Sender),
        ok = file:delete(Path),
        ok = file:del_dir(Dir)
    end}.

load_with_master_override_test_() ->
    {timeout, 120, fun() ->
        {ok, Sender} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
        Perm = binary:copy(<<16#31>>, 32),
        Wrap = binary:copy(<<16#32>>, 32),
        {ok, Rotated} = itb3:rekey(Sender, Perm, Wrap),
        {ok, Blob} = itb3:save(Sender),
        {ok, Receiver} = itb3:load(Blob, Perm, Wrap),
        ?assertEqual({ok, Rotated}, itb3:save(Receiver)),
        {ok, Wire} = itb3:encrypt_message(Sender, <<"master override">>),
        ?assertEqual({ok, <<"master override">>},
                     itb3:decrypt_message(Receiver, Wire)),
        ok = itb3:free(Receiver),
        ok = itb3:free(Sender)
    end}.

inspect_lookup_profiles_test() ->
    %% inspect carries the registry recipe plus the blob-only
    %% nonce_bits / barrier_fill inspection fields; lookup returns
    %% just the recipe.
    {ok, Pipe} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
    {ok, Blob} = itb3:save(Pipe),
    ok = itb3:free(Pipe),
    {ok, Record} = itb3:inspect(Blob),
    ?assertEqual(<<"singlemsg-triple-mac-v1">>, maps:get(<<"name">>, Record)),
    ?assertEqual(<<"singlemsg-mac">>, maps:get(<<"mode">>, Record)),
    ?assert(maps:get(<<"keybits">>, Record) > 0),
    ?assert(maps:is_key(<<"nonce_bits">>, Record)),
    ?assert(maps:is_key(<<"barrier_fill">>, Record)),
    {ok, Looked} = itb3:lookup(<<"singlemsg-triple-mac-v1">>),
    ?assertNot(maps:is_key(<<"nonce_bits">>, Looked)),
    ?assertNot(maps:is_key(<<"barrier_fill">>, Looked)),
    ?assertEqual(Looked,
                 maps:without([<<"nonce_bits">>, <<"barrier_fill">>, <<"container_mode">>], Record)),
    ?assertMatch({error, {bad_input, _}}, itb3:inspect(<<"not a blob">>)),
    ?assertMatch({error, {unknown_profile, _}}, itb3:lookup(<<"no-such-profile">>)),
    Names = itb3:profiles(),
    ?assert(lists:member(<<"singlemsg-triple-mac-v1">>, Names)),
    ?assertEqual(lists:sort(Names), Names),
    lists:foreach(
      fun(Name) ->
              {ok, R} = itb3:lookup(Name),
              ?assertEqual(Name, maps:get(<<"name">>, R))
      end, Names).

max_workers_test() ->
    {ok, Pipe} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
    ok = itb3:max_workers(Pipe, 2),
    ok = itb3:max_workers(Pipe, -1),    %% clamped to auto, never rejected
    ok = itb3:max_workers(Pipe, 10000), %% clamped to 256
    {ok, Wire} = itb3:encrypt_message(Pipe, <<"after cap change">>),
    ?assertEqual({ok, <<"after cap change">>}, itb3:decrypt_message(Pipe, Wire)),
    ok = itb3:free(Pipe),
    %% A negative init-time cap is clamped as well.
    {ok, Neg} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{maxWorkers => -1}),
    {ok, W2} = itb3:encrypt_message(Neg, <<"negative cap">>),
    ?assertEqual({ok, <<"negative cap">>}, itb3:decrypt_message(Neg, W2)),
    ok = itb3:free(Neg).

runtime_knobs_test() ->
    %% Negative values query without changing; the return is the
    %% previous setting.
    Prev = itb3:set_memory_limit(-1),
    ?assert(is_integer(Prev)),
    ?assertEqual(Prev, itb3:set_memory_limit(-1)),
    PrevGC = itb3:set_gc_percent(-2),
    ?assert(is_integer(PrevGC)).

%% The drbg opts key selects the fill primitive: the session round
%% trips through a loaded blob, inspect reports the key, and an
%% inspected record (inspection-only fields dropped) re-registers with
%% the key kept.
drbg_round_trip_test_() ->
    {timeout, 120, fun() ->
        lists:foreach(
          fun(Drbg) ->
                  {ok, Sender} = itb3:init(<<"singlemsg-triple-mac-v1">>,
                                           #{drbg => Drbg}),
                  {ok, Blob} = itb3:save(Sender),
                  {ok, Receiver} = itb3:load(Blob),
                  Plain = <<"drbg round-trip payload">>,
                  {ok, Wire} = itb3:encrypt_message(Receiver, Plain),
                  ?assertEqual({ok, Plain}, itb3:decrypt_message(Sender, Wire)),
                  {ok, Record} = itb3:inspect(Blob),
                  ?assertEqual(Drbg, maps:get(<<"drbg">>, Record)),
                  ok = itb3:free(Receiver),
                  ok = itb3:free(Sender)
          end, [<<"csprng">>, <<"aesitb128">>])
    end}.

drbg_unknown_name_test() ->
    {error, {recipe_primitive_unknown, Detail}} =
        itb3:init(<<"singlemsg-triple-mac-v1">>, #{drbg => <<"nope">>}),
    ?assertNotEqual(nomatch, binary:match(Detail, <<"nope">>)).

drbg_default_absent_test() ->
    {ok, Pipe} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
    {ok, Blob} = itb3:save(Pipe),
    ok = itb3:free(Pipe),
    {ok, Record} = itb3:inspect(Blob),
    ?assertNot(maps:is_key(<<"drbg">>, Record)),
    {ok, Looked} = itb3:lookup(<<"singlemsg-triple-mac-v1">>),
    ?assertNot(maps:is_key(<<"drbg">>, Looked)).

drbg_register_copy_keeps_key_test() ->
    {ok, Pipe} = itb3:init(<<"singlemsg-triple-mac-v1">>,
                           #{drbg => <<"csprng">>}),
    {ok, Blob} = itb3:save(Pipe),
    ok = itb3:free(Pipe),
    {ok, Record} = itb3:inspect(Blob),
    Copy = maps:without([<<"name">>, <<"nonce_bits">>, <<"barrier_fill">>,
                         <<"container_mode">>], Record),
    ok = itb3:register(<<"erlang-binding-test-drbg-copy">>, Copy),
    {ok, Looked} = itb3:lookup(<<"erlang-binding-test-drbg-copy">>),
    ?assertEqual(<<"csprng">>, maps:get(<<"drbg">>, Looked)).
