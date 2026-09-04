%% Init -> save -> Load -> encrypt_message -> decrypt_message round
%% trip on the MAC Single Message profile, plus the persistence and
%% profile-catalogue surface.

-module(itb_smoke_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

smoke_round_trip_test_() ->
    {timeout, 120, fun smoke_round_trip/0}.

smoke_round_trip() ->
    {ok, Sender} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
    {ok, Blob} = itb:save(Sender),
    ?assert(byte_size(Blob) > 0),

    {ok, Receiver} = itb:load(Blob),

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

save_load_round_trip_test_() ->
    {timeout, 120, fun() ->
        {ok, Sender} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
        {ok, Blob} = itb:save(Sender),
        ?assertEqual({ok, Blob}, itb:save(Sender)),
        {ok, Receiver} = itb:load(Blob),
        ?assertEqual({ok, Blob}, itb:save(Receiver)),
        {ok, Wire} = itb:encrypt_message(Sender, <<"in-memory persist">>),
        ?assertEqual({ok, <<"in-memory persist">>},
                     itb:decrypt_message(Receiver, Wire)),
        ok = itb:free(Receiver),
        ok = itb:free(Sender)
    end}.

save_f_load_f_round_trip_test_() ->
    {timeout, 120, fun() ->
        Dir = filename:join(os:getenv("TMPDIR", "/tmp"),
                            "itb-erlang-persist-" ++ os:getpid()),
        ok = file:make_dir(Dir),
        Path = filename:join(Dir, "session.blob"),
        {ok, Sender} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
        ok = itb:save_f(Sender, Path),
        {ok, #file_info{mode = Mode}} = file:read_file_info(Path),
        ?assertEqual(8#600, Mode band 8#777),
        {ok, Receiver} = itb:load_f(Path),
        ?assertEqual(itb:save(Sender), itb:save(Receiver)),
        {ok, Wire} = itb:encrypt_message(Sender, <<"file persist">>),
        ?assertEqual({ok, <<"file persist">>},
                     itb:decrypt_message(Receiver, Wire)),
        ?assertMatch({error, {bad_input, _}},
                     itb:load_f(filename:join(Dir, "absent.blob"))),
        ok = itb:free(Receiver),
        ok = itb:free(Sender),
        ok = file:delete(Path),
        ok = file:del_dir(Dir)
    end}.

load_with_master_override_test_() ->
    {timeout, 120, fun() ->
        {ok, Sender} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
        Perm = binary:copy(<<16#31>>, 32),
        Wrap = binary:copy(<<16#32>>, 32),
        {ok, Rotated} = itb:rekey(Sender, Perm, Wrap),
        {ok, Blob} = itb:save(Sender),
        {ok, Receiver} = itb:load(Blob, Perm, Wrap),
        ?assertEqual({ok, Rotated}, itb:save(Receiver)),
        {ok, Wire} = itb:encrypt_message(Sender, <<"master override">>),
        ?assertEqual({ok, <<"master override">>},
                     itb:decrypt_message(Receiver, Wire)),
        ok = itb:free(Receiver),
        ok = itb:free(Sender)
    end}.

inspect_lookup_profiles_test() ->
    {ok, Pipe} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
    {ok, Blob} = itb:save(Pipe),
    ok = itb:free(Pipe),
    {ok, Record} = itb:inspect(Blob),
    ?assertEqual(<<"singlemsg-triple-mac-v1">>, maps:get(<<"name">>, Record)),
    ?assertEqual(<<"singlemsg-mac">>, maps:get(<<"mode">>, Record)),
    ?assert(maps:get(<<"keybits">>, Record) > 0),
    ?assertEqual({ok, Record}, itb:lookup(<<"singlemsg-triple-mac-v1">>)),
    ?assertMatch({error, {bad_input, _}}, itb:inspect(<<"not a blob">>)),
    ?assertMatch({error, {unknown_profile, _}}, itb:lookup(<<"no-such-profile">>)),
    Names = itb:profiles(),
    ?assert(lists:member(<<"singlemsg-triple-mac-v1">>, Names)),
    ?assertEqual(lists:sort(Names), Names),
    lists:foreach(
      fun(Name) ->
              {ok, R} = itb:lookup(Name),
              ?assertEqual(Name, maps:get(<<"name">>, R))
      end, Names).

max_workers_test() ->
    {ok, Pipe} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
    ok = itb:max_workers(Pipe, 2),
    ok = itb:max_workers(Pipe, -1),    %% clamped to auto, never rejected
    ok = itb:max_workers(Pipe, 10000), %% clamped to 256
    {ok, Wire} = itb:encrypt_message(Pipe, <<"after cap change">>),
    ?assertEqual({ok, <<"after cap change">>}, itb:decrypt_message(Pipe, Wire)),
    ok = itb:free(Pipe),
    %% A negative init-time cap is clamped as well.
    {ok, Neg} = itb:init(<<"singlemsg-triple-mac-v1">>, #{maxWorkers => -1}),
    {ok, W2} = itb:encrypt_message(Neg, <<"negative cap">>),
    ?assertEqual({ok, <<"negative cap">>}, itb:decrypt_message(Neg, W2)),
    ok = itb:free(Neg).

runtime_knobs_test() ->
    %% Negative values query without changing; the return is the
    %% previous setting.
    Prev = itb:set_memory_limit(-1),
    ?assert(is_integer(Prev)),
    ?assertEqual(Prev, itb:set_memory_limit(-1)),
    PrevGC = itb:set_gc_percent(-2),
    ?assert(is_integer(PrevGC)).
