%% itb_test_util — shared helpers for the EUnit suite. Not a test
%% module itself (no *_test functions).

-module(itb_test_util).

-export([pair/2, pump/3, pump/5, flip_byte/2]).

%% Sender + receiver pipelines over one profile / opts pair.
pair(Profile, Opts) ->
    {ok, Sender} = itb:init(Profile, Opts),
    {ok, Blob} = itb:blob(Sender),
    {ok, Receiver} = itb:open(Profile, Blob, Opts),
    {Sender, Receiver}.

%% Whole-buffer pump through an incremental session with 1 MiB feed /
%% drain slices: begin -> write slices (draining the spool after each
%% write) -> end -> drain until finished -> free.
pump(Pipe, Direction, Data) ->
    pump(Pipe, Direction, Data, 1 bsl 20, 1 bsl 20).

pump(Pipe, Direction, Data, WriteSlice, ReadSlice) ->
    {ok, Stream} = case Direction of
                       encrypt -> itb:encrypt_stream(Pipe);
                       decrypt -> itb:decrypt_stream(Pipe)
                   end,
    Acc0 = feed(Stream, Data, WriteSlice, ReadSlice, []),
    ok = itb:stream_end(Stream),
    Out = drain_all(Stream, ReadSlice, Acc0),
    ok = itb:stream_free(Stream),
    Out.

feed(_Stream, <<>>, _WriteSlice, _ReadSlice, Acc) ->
    Acc;
feed(Stream, Data, WriteSlice, ReadSlice, Acc) ->
    N = min(byte_size(Data), WriteSlice),
    <<Slice:N/binary, Rest/binary>> = Data,
    ok = itb:stream_write(Stream, Slice),
    %% A read before end never blocks; drain whatever the chain has
    %% produced so far to bound the Go-side spool.
    Acc1 = drain_ready(Stream, ReadSlice, Acc),
    feed(Stream, Rest, WriteSlice, ReadSlice, Acc1).

drain_ready(Stream, ReadSlice, Acc) ->
    case itb:stream_read(Stream, ReadSlice) of
        {ok, <<>>, _} -> Acc;
        {ok, Piece, false} -> drain_ready(Stream, ReadSlice, [Piece | Acc]);
        {ok, Piece, true} -> [Piece | Acc]
    end.

drain_all(Stream, ReadSlice, Acc) ->
    case itb:stream_read(Stream, ReadSlice) of
        {ok, Piece, true} ->
            iolist_to_binary(lists:reverse([Piece | Acc]));
        {ok, Piece, false} ->
            drain_all(Stream, ReadSlice, [Piece | Acc])
    end.

%% Copy of Wire with bit 0 of byte Pos flipped.
flip_byte(Wire, Pos) ->
    <<Head:Pos/binary, Byte, Tail/binary>> = Wire,
    <<Head/binary, (Byte bxor 1), Tail/binary>>.
