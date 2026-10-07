%% The state every worker shares: the Pipeline handles, the retained
%% blobs, the reader / writer lock that keeps iterations clear of
%% handle mutation, the stop request, and the rekey and blob-cycle
%% totals.
%%
%% Erlang-specific. BEAM has no reader / writer lock primitive, so the
%% lock is a process that owns the handles and hands them out: a
%% reader is granted immediately unless a writer holds or is waiting,
%% a writer waits until the last reader has left. The handles travel
%% with the grant rather than being cached by the worker, because a
%% blob reopen frees the running handle and swaps a fresh one in — a
%% worker holding the term from launch would be calling into a
%% released resource from the first cycle onwards. The lock holder is
%% monitored, so a worker that dies holding either side releases it
%% instead of wedging the run.

-module(loop_state).

-export([start/6, stop_process/1,
         read_lock/1, read_unlock/1, write_lock/1, write_unlock/2,
         handles/1,
         new_flags/0, request_stop/1, stop_requested/1,
         new_counts/0, bump/2, count/2]).

-include("loop.hrl").

%% Slot 1 of the atomics word carries the stop request; slots 1 and 2
%% of the counters array carry the rekey and blob-cycle totals.
-define(SLOT_STOP, 1).
-define(COUNT_REKEYS, 1).
-define(COUNT_BLOB_CYCLES, 2).

-record(st, {
    stream_pipe,      %% undefined unless the shape uses it
    msg_pipe,
    stream_blob = <<>>,
    msg_blob = <<>>,
    readers = [],     %% pids currently holding the read side
    writer = none,    %% {Pid, MonRef} holding the write side
    wait_readers = [],%% {Pid, Ref} queued behind a writer
    wait_writers = [],%% {Pid, Ref} queued behind the readers
    monitors = #{}    %% Pid => MonRef for every current holder
}).

%% ------------------------------------------------------------------
%% Stop request and counters — lock-free, so a worker's per-iteration
%% check never queues behind the lock process.
%% ------------------------------------------------------------------

new_flags() ->
    atomics:new(1, [{signed, false}]).

request_stop(Flags) ->
    atomics:put(Flags, ?SLOT_STOP, 1).

stop_requested(Flags) ->
    atomics:get(Flags, ?SLOT_STOP) =:= 1.

new_counts() ->
    counters:new(2, [write_concurrency]).

bump(Counts, rekeys) ->
    counters:add(Counts, ?COUNT_REKEYS, 1),
    counters:get(Counts, ?COUNT_REKEYS);
bump(Counts, blob_cycles) ->
    counters:add(Counts, ?COUNT_BLOB_CYCLES, 1),
    counters:get(Counts, ?COUNT_BLOB_CYCLES).

count(Counts, rekeys) -> counters:get(Counts, ?COUNT_REKEYS);
count(Counts, blob_cycles) -> counters:get(Counts, ?COUNT_BLOB_CYCLES).

%% ------------------------------------------------------------------
%% The lock process
%% ------------------------------------------------------------------

start(StreamPipe, MsgPipe, StreamBlob, MsgBlob, _StreamProfile, _MsgProfile) ->
    spawn_link(fun() ->
                       loop(#st{stream_pipe = StreamPipe, msg_pipe = MsgPipe,
                                stream_blob = StreamBlob, msg_blob = MsgBlob})
               end).

stop_process(Pid) ->
    Pid ! {shutdown, self()},
    receive {shutdown_ok, Pid} -> ok after 5000 -> ok end.

%% Grants the read side and hands back the handles in force at that
%% instant. Cipher calls run in the caller, not here: routing them
%% through this process would serialise every worker and remove the
%% shared-handle property the harness exists to exercise.
read_lock(Pid) ->
    call(Pid, read_lock).

read_unlock(Pid) ->
    Pid ! {read_unlock, self()},
    ok.

write_lock(Pid) ->
    call(Pid, write_lock).

%% Releases the write side, installing whatever the maintenance
%% produced. Updates is a map of the fields that changed.
write_unlock(Pid, Updates) ->
    Pid ! {write_unlock, self(), Updates},
    ok.

%% The handles without taking the lock, for the shutdown path after
%% every worker has returned.
handles(Pid) ->
    call(Pid, handles).

call(Pid, Request) ->
    Ref = make_ref(),
    Pid ! {Request, self(), Ref},
    receive
        {Ref, Reply} -> Reply
    end.

%% ------------------------------------------------------------------

loop(St) ->
    receive
        {read_lock, Pid, Ref} ->
            loop(request_read(St, Pid, Ref));
        {write_lock, Pid, Ref} ->
            loop(request_write(St, Pid, Ref));
        {read_unlock, Pid} ->
            loop(grant(release_reader(St, Pid)));
        {write_unlock, Pid, Updates} ->
            loop(grant(release_writer(apply_updates(St, Updates), Pid)));
        {handles, Pid, Ref} ->
            Pid ! {Ref, {St#st.stream_pipe, St#st.msg_pipe}},
            loop(St);
        {'DOWN', _MonRef, process, Pid, _Reason} ->
            %% A holder that died never sends its unlock; drop its
            %% claim so the run can finish instead of wedging.
            loop(grant(release_writer(release_reader(St, Pid), Pid)));
        {shutdown, Pid} ->
            Pid ! {shutdown_ok, self()},
            ok
    end.

request_read(St = #st{writer = none, wait_writers = []}, Pid, Ref) ->
    Pid ! {Ref, {St#st.stream_pipe, St#st.msg_pipe}},
    watch(St#st{readers = [Pid | St#st.readers]}, Pid);
request_read(St, Pid, Ref) ->
    St#st{wait_readers = St#st.wait_readers ++ [{Pid, Ref}]}.

request_write(St = #st{writer = none, readers = []}, Pid, Ref) ->
    Pid ! {Ref, {St#st.stream_pipe, St#st.msg_pipe,
                 St#st.stream_blob, St#st.msg_blob}},
    watch(St#st{writer = Pid}, Pid);
request_write(St, Pid, Ref) ->
    St#st{wait_writers = St#st.wait_writers ++ [{Pid, Ref}]}.

%% Writer preference: a queued writer goes first, so a steady stream
%% of iterations cannot starve a rekey that is already waiting.
grant(St = #st{writer = none, readers = [], wait_writers = [{Pid, Ref} | Rest]}) ->
    Pid ! {Ref, {St#st.stream_pipe, St#st.msg_pipe,
                 St#st.stream_blob, St#st.msg_blob}},
    watch(St#st{writer = Pid, wait_writers = Rest}, Pid);
grant(St = #st{writer = none, wait_writers = [], wait_readers = [_ | _]}) ->
    Waiting = St#st.wait_readers,
    [Pid ! {Ref, {St#st.stream_pipe, St#st.msg_pipe}} || {Pid, Ref} <- Waiting],
    lists:foldl(fun({Pid, _}, Acc) -> watch(Acc, Pid) end,
                St#st{readers = [P || {P, _} <- Waiting] ++ St#st.readers,
                      wait_readers = []},
                Waiting);
grant(St) ->
    St.

release_reader(St, Pid) ->
    case lists:member(Pid, St#st.readers) of
        true -> unwatch(St#st{readers = lists:delete(Pid, St#st.readers)}, Pid);
        false -> St
    end.

release_writer(St = #st{writer = Pid}, Pid) ->
    unwatch(St#st{writer = none}, Pid);
release_writer(St, _Pid) ->
    St.

apply_updates(St, Updates) ->
    maps:fold(fun(stream_pipe, V, S) -> S#st{stream_pipe = V};
                 (msg_pipe, V, S) -> S#st{msg_pipe = V};
                 (stream_blob, V, S) -> S#st{stream_blob = V};
                 (msg_blob, V, S) -> S#st{msg_blob = V}
              end, St, Updates).

watch(St, Pid) ->
    case maps:is_key(Pid, St#st.monitors) of
        true -> St;
        false -> St#st{monitors = maps:put(Pid, monitor(process, Pid),
                                           St#st.monitors)}
    end.

unwatch(St, Pid) ->
    case St#st.writer =:= Pid orelse lists:member(Pid, St#st.readers) of
        true -> St;
        false ->
            case maps:take(Pid, St#st.monitors) of
                {MonRef, Rest} ->
                    demonitor(MonRef, [flush]),
                    St#st{monitors = Rest};
                error -> St
            end
    end.
