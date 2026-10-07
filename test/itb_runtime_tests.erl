%% The runtime-shaping knobs and the hash-registry enumeration: the
%% GOMAXPROCS setter and its query form, the heap-profile writer on a
%% good and on a rejected path, the pool-counter vector and its length
%% query, and the registry names init/2 accepts under `innerHash`.

-module(itb_runtime_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

%% Zero or a negative value queries without changing, so the query is
%% repeatable and the round trip restores what was in force.
set_gomaxprocs_test() ->
    Before = itb3:set_gomaxprocs(0),
    ?assert(Before > 0),
    ?assertEqual(Before, itb3:set_gomaxprocs(0)),
    Previous = itb3:set_gomaxprocs(2),
    ?assertEqual(Before, Previous),
    ?assertEqual(2, itb3:set_gomaxprocs(0)),
    ?assertEqual(2, itb3:set_gomaxprocs(Before)),
    ?assertEqual(Before, itb3:set_gomaxprocs(0)).

write_heap_profile_test() ->
    Path = filename:join(test_dir(), "heap.pprof"),
    ok = itb3:write_heap_profile(Path),
    {ok, #file_info{size = Size}} = read_info(Path),
    ?assert(Size > 0),
    ok = file:delete(Path).

%% A path that cannot be created is rejected, and the diagnostic the
%% library composed comes back with the status atom.
write_heap_profile_rejects_bad_path_test() ->
    Bad = filename:join([test_dir(), "no-such-directory", "heap.pprof"]),
    {error, {Status, Detail}} = itb3:write_heap_profile(Bad),
    ?assertEqual(bad_input, Status),
    ?assert(byte_size(Detail) > 0).

%% The slot count is read from the library, and the vector it fills
%% matches that count; slot 0 carries the tier count and the layout
%% 1 + 5*T + 8 follows from it.
pool_stats_test() ->
    Len = itb3:pool_stats_len(),
    ?assert(Len > 0),
    {ok, Slots} = itb3:pool_stats(),
    ?assertEqual(Len, length(Slots)),
    [Tiers | _] = Slots,
    ?assert(Tiers > 0),
    ?assertEqual(Len, 1 + 5 * Tiers + 8),
    ?assert(lists:all(fun(V) -> is_integer(V) andalso V >= 0 end, Slots)).

%% The counters are monotonic totals since library load, so a cipher
%% call between two snapshots can only move them upward.
pool_stats_monotonic_test_() ->
    {timeout, 120, fun pool_stats_monotonic/0}.

pool_stats_monotonic() ->
    {ok, Before} = itb3:pool_stats(),
    {ok, Pipe} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
    {ok, _Wire} = itb3:encrypt_message(Pipe, binary:copy(<<"x">>, 65536)),
    ok = itb3:free(Pipe),
    {ok, After} = itb3:pool_stats(),
    ?assertEqual(length(Before), length(After)),
    ?assert(lists:all(fun({A, B}) -> B >= A end,
                      lists:zip(Before, After))).

%% Every registry name is accepted as an inner hash, which is what
%% makes the enumeration usable for validating a primitive name.
hash_names_test_() ->
    {timeout, 300, fun hash_names/0}.

hash_names() ->
    Names = itb3:hash_names(),
    ?assert(length(Names) > 0),
    ?assert(lists:all(fun is_binary/1, Names)),
    ?assert(lists:member(<<"areion512">>, Names)),
    ?assertEqual(lists:usort(Names), lists:sort(Names)),
    lists:foreach(
      fun(Name) ->
              {ok, Pipe} = itb3:init(<<"singlemsg-triple-nomac-v1">>,
                                     #{innerHash => Name}),
              ok = itb3:free(Pipe)
      end, Names).

hash_names_rejects_unregistered_test() ->
    ?assertNot(lists:member(<<"no-such-primitive">>, itb3:hash_names())),
    ?assertMatch({error, {_, _}},
                 itb3:init(<<"singlemsg-triple-nomac-v1">>,
                           #{innerHash => <<"no-such-primitive">>})).

%% Every status atom an error tuple can carry resolves to the numeric
%% code the C ABI assigns it, and an atom outside the table resolves
%% to the internal-error code.
status_code_test() ->
    ?assertEqual(0, itb3:status_code(ok)),
    ?assertEqual(4, itb3:status_code(bad_input)),
    ?assertEqual(10, itb3:status_code(mac_failure)),
    ?assertEqual(13, itb3:status_code(unknown_profile)),
    ?assertEqual(26, itb3:status_code(profile_exists)),
    ?assertEqual(99, itb3:status_code(internal)),
    ?assertEqual(99, itb3:status_code(no_such_status)),
    %% The codes are distinct, so a diagnostic naming one names it
    %% unambiguously.
    Known = [ok, bad_hash, bad_key_bits, bad_handle, bad_input,
             buffer_too_small, encrypt_failed, decrypt_failed,
             seed_width_mix, bad_mac, mac_failure, blob_malformed_recipe,
             recipe_primitive_unknown, unknown_profile, blob_mode_mismatch,
             blob_malformed, blob_version_too_new, blob_too_many_opts,
             stream_truncated, stream_after_final, triple_closed,
             profile_exists],
    Codes = [itb3:status_code(S) || S <- Known],
    ?assertEqual(length(Codes), length(lists:usort(Codes))).

%% The atom a failing call hands back resolves through the same
%% accessor, so the pair (atom, code) is attributable to one call.
status_code_of_failing_call_test() ->
    {error, {Status, _Detail}} = itb3:lookup(<<"no-such-profile">>),
    ?assertEqual(unknown_profile, Status),
    ?assertEqual(13, itb3:status_code(Status)).

%% ------------------------------------------------------------------

test_dir() ->
    Dir = filename:join("/tmp", "itb-erlang-runtime-tests"),
    ok = filelib:ensure_path(Dir),
    Dir.

read_info(Path) ->
    file:read_file_info(Path).
