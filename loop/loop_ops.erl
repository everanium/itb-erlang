%% The maintenance operations that mutate a live Pipeline handle
%% between iterations: master rotation (--rekey-every) and blob
%% reopen (--blob-cycle-every).

-module(loop_ops).

-export([maintenance/3]).

-include("loop.hrl").

%% Byte length of each fresh master drawn for a rotation. Matches the
%% size Init auto-generates for both the parallax and the wrapper
%% master.
-define(REKEY_MASTER_SIZE, 32).

%% Handle mutation. Runs the periodic Pipeline-mutating operations
%% after a completed iteration: master rotation (--rekey-every) and
%% blob reopen (--blob-cycle-every). Both intervals count per-worker
%% iterations; the warmup iteration (iter 0) never triggers because
%% the worker loop calls this for iter >= 1 only. Rekey rewrites the
%% outer-layer keying of a live handle and a blob reopen replaces the
%% handle outright; each takes the write lock, so in-flight cipher
%% calls on other workers drain before anything changes and no
%% encrypt is separated from its decrypt by either.
-spec maintenance(#run{}, non_neg_integer(), non_neg_integer()) ->
          ok | {error, string()}.
maintenance(Run, Id, Iter) ->
    Cfg = Run#run.cfg,
    case due(Cfg#cfg.rekey_every, Iter) of
        true ->
            case rekey_pipes(Run, Id, Iter) of
                ok -> blob_stage(Run, Id, Iter);
                {error, _} = Err -> Err
            end;
        false -> blob_stage(Run, Id, Iter)
    end.

blob_stage(Run, Id, Iter) ->
    Cfg = Run#run.cfg,
    case due(Cfg#cfg.blob_cycle_every, Iter) of
        true -> blob_cycle_pipes(Run, Id, Iter);
        false -> ok
    end.

due(0, _Iter) -> false;
due(Every, Iter) -> Iter rem Every =:= 0.

%% Master rotation. Rotates the parallax + wrapper masters on every
%% active Pipeline under the write lock and retains the refreshed blob
%% for subsequent blob reopens. Masters are drawn fresh from the OS
%% CSPRNG on every rotation regardless of --seed (master rotation is
%% pipeline keying, not plaintext content); a disabled layer passes no
%% bytes, which Rekey ignores. The eight inner seeds and the MAC key
%% are untouched by design — Rekey targets only the two outer-layer
%% master secrets.
rekey_pipes(Run, Id, Iter) ->
    Cfg = Run#run.cfg,
    Perm = master(Cfg#cfg.parallax),
    Wrap = master(Cfg#cfg.wrapper),
    {StreamPipe, MsgPipe, _StreamBlob, _MsgBlob} =
        loop_state:write_lock(Run#run.state),
    case rekey_one(StreamPipe, Perm, Wrap) of
        {error, Status, Detail} ->
            loop_state:write_unlock(Run#run.state, #{}),
            {error, op_error(Id, Iter, "Rekey", Run#run.stream_profile, Status, Detail)};
        {ok, StreamUpdate} ->
            case rekey_one(MsgPipe, Perm, Wrap) of
                {error, Status, Detail} ->
                    loop_state:write_unlock(Run#run.state, StreamUpdate),
                    {error, op_error(Id, Iter, "Rekey", Run#run.msg_profile, Status, Detail)};
                {ok, MsgUpdate} ->
                    Updates = maps:merge(rename(StreamUpdate, stream_blob),
                                         rename(MsgUpdate, msg_blob)),
                    loop_state:write_unlock(Run#run.state, Updates),
                    N = loop_state:bump(Run#run.counts, rekeys),
                    loop_main:log("rekey: g~B iter ~B rotated parallax + wrapper "
                                  "masters (rekey #~B)", [Id, Iter, N]),
                    ok
            end
    end.

master(true) -> loop_payload:random_bytes(?REKEY_MASTER_SIZE);
master(false) -> <<>>.

rekey_one(undefined, _Perm, _Wrap) ->
    {ok, #{}};
rekey_one(Pipe, Perm, Wrap) ->
    case itb3:rekey(Pipe, Perm, Wrap) of
        {ok, Blob} -> {ok, #{blob => Blob}};
        {error, {Status, Detail}} -> {error, Status, Detail}
    end.

rename(Update, Key) ->
    case maps:find(blob, Update) of
        {ok, Blob} -> #{Key => Blob};
        error -> #{}
    end.

%% Blob reopen. Reopens every active Pipeline from its retained blob
%% under the write lock: a fresh handle is loaded from the blob, the
%% running handle is freed, and the fresh one is swapped in, so every
%% later iteration round-trips through seeds and masters that survived
%% a blob crossing. The input is the blob Init or the latest Rekey
%% handed out, not a fresh Save: that is what a receiver holds, and
%% reopening from it proves the handed-out bytes rather than the live
%% state. The blob carries the Pipeline's full shape, so no override
%% reaches the reopen. On a Load failure the running handle stays and
%% the failure aborts the run.
blob_cycle_pipes(Run, Id, Iter) ->
    {StreamPipe, MsgPipe, StreamBlob, MsgBlob} =
        loop_state:write_lock(Run#run.state),
    case reopen(StreamPipe, StreamBlob) of
        {error, Status, Detail} ->
            loop_state:write_unlock(Run#run.state, #{}),
            {error, op_error(Id, Iter, "Load", Run#run.stream_profile, Status, Detail)};
        {ok, StreamFresh} ->
            case reopen(MsgPipe, MsgBlob) of
                {error, Status, Detail} ->
                    loop_state:write_unlock(Run#run.state, swap(stream_pipe, StreamPipe, StreamFresh)),
                    {error, op_error(Id, Iter, "Load", Run#run.msg_profile, Status, Detail)};
                {ok, MsgFresh} ->
                    Updates = maps:merge(swap(stream_pipe, StreamPipe, StreamFresh),
                                         swap(msg_pipe, MsgPipe, MsgFresh)),
                    loop_state:write_unlock(Run#run.state, Updates),
                    N = loop_state:bump(Run#run.counts, blob_cycles),
                    loop_main:log("blob-cycle: g~B iter ~B reopened from session "
                                  "blob (cycle #~B)", [Id, Iter, N]),
                    ok
            end
    end.

reopen(undefined, _Blob) ->
    {ok, undefined};
reopen(_Pipe, Blob) ->
    case itb3:load(Blob) of
        {ok, Fresh} -> {ok, Fresh};
        {error, {Status, Detail}} -> {error, Status, Detail}
    end.

%% The running handle is released only once its replacement is in
%% hand, so a failed Load leaves the Pipeline the run is using intact.
swap(_Key, _Old, undefined) ->
    #{};
swap(Key, Old, Fresh) ->
    itb3:free(Old),
    #{Key => Fresh}.

op_error(Id, Iter, Op, Profile, Status, Detail) ->
    lists:flatten(io_lib:format("g~B iter ~B: ~s(~s): ~s",
                                [Id, Iter, Op, Profile,
                                 loop_main:status_text(Status, Detail)])).
