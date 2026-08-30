#!/usr/bin/env escript
%% eitb — command-line demonstrator for the ITB Erlang binding.
%%
%% Subcommands:
%%
%%   eitb version                                   library + binding versions
%%   eitb hashes                                    shipped hash primitive roster
%%   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
%%   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
%%
%% `encrypt` prints the session blob to stderr as hex; feed that hex
%% back to `decrypt` on the receiving side.
%%
%% The compiled binding (./build.sh in bindings/erlang) is resolved
%% relative to this script's location: ../_build/default/lib/itb/ebin.

-define(EITB_ERLANG_VERSION, "0.3.0").

main(Args) ->
    ok = add_binding_path(),
    Rc = dispatch(Args),
    halt(Rc).

dispatch(["version"]) ->
    cmd_version();
dispatch(["hashes"]) ->
    cmd_hashes();
dispatch(["encrypt", Profile, InFile, OutFile]) ->
    cmd_encrypt(Profile, InFile, OutFile);
dispatch(["decrypt", Profile, BlobHex, InFile, OutFile]) ->
    cmd_decrypt(Profile, BlobHex, InFile, OutFile);
dispatch(_) ->
    usage().

usage() ->
    io:format(standard_error,
              "usage: eitb version~n"
              "       eitb hashes~n"
              "       eitb encrypt <profile> <in-file> <out-file>~n"
              "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>~n",
              []),
    2.

add_binding_path() ->
    ScriptDir = filename:dirname(filename:absname(escript:script_name())),
    Ebin = filename:join([ScriptDir, "..", "_build", "default", "lib",
                          "itb", "ebin"]),
    case filelib:is_dir(Ebin) of
        true ->
            true = code:add_pathz(Ebin),
            ok;
        false ->
            io:format(standard_error,
                      "eitb: binding not built (~s missing); "
                      "run ./build.sh first~n", [Ebin]),
            halt(1)
    end.

fail(What, {Status, Detail}) ->
    io:format(standard_error, "eitb: ~s: ~p: ~s~n", [What, Status, Detail]),
    1.

%% Defensive Go-runtime pacing for cipher workloads on large files: a
%% soft memory cap + aggressive GC keep the scratch heap bounded. The
%% setter return values report the previous settings, not an error.
cap_go_runtime() ->
    _ = itb:set_memory_limit(512 bsl 20), %% 512 MiB soft cap
    _ = itb:set_gc_percent(20),           %% aggressive GC
    ok.

cmd_version() ->
    case itb:version() of
        {ok, Version} ->
            io:format("libitb ~s~n", [Version]),
            io:format("itb-erlang ~s~n", [?EITB_ERLANG_VERSION]),
            0;
        {error, Reason} ->
            fail("version", Reason)
    end.

cmd_hashes() ->
    lists:foldl(
      fun({Name, Width}, Index) ->
              io:format("~2b  ~-12s ~b bits~n", [Index, Name, Width]),
              Index + 1
      end, 0, itb:hashes()),
    0.

%% Profiles whose canonical name begins with "streaming-" route
%% through the streaming session pair instead of the Single Message
%% pair. A one-shot Streaming call is a session opened, fed the whole
%% payload, and drained to a single binary.
is_streaming_profile("streaming-" ++ _) -> true;
is_streaming_profile(_) -> false.

ensure_parent_dir(Path) ->
    filelib:ensure_dir(Path).

stream_one_shot(Pipe, Direction, Payload) ->
    BeginFn = case Direction of
                  encrypt -> fun itb:encrypt_stream/1;
                  decrypt -> fun itb:decrypt_stream/1
              end,
    case BeginFn(Pipe) of
        {error, Reason} ->
            {error, Reason};
        {ok, Session} ->
            try
                case itb:stream_write(Session, Payload) of
                    {error, WErr} ->
                        {error, WErr};
                    ok ->
                        case itb:stream_end(Session) of
                            {error, EErr} ->
                                {error, EErr};
                            ok ->
                                drain_stream(Session, [])
                        end
                end
            after
                ok = itb:stream_free(Session)
            end
    end.

drain_stream(Session, Acc) ->
    case itb:stream_read(Session) of
        {error, Reason} ->
            {error, Reason};
        {ok, Piece, true} ->
            {ok, iolist_to_binary(lists:reverse([Piece | Acc]))};
        {ok, Piece, false} ->
            drain_stream(Session, [Piece | Acc])
    end.

cmd_encrypt(Profile, InFile, OutFile) ->
    ok = cap_go_runtime(),
    case file:read_file(InFile) of
        {error, ReadErr} ->
            io:format(standard_error, "eitb: cannot read ~s: ~p~n",
                      [InFile, ReadErr]),
            1;
        {ok, Plain} ->
            case itb:init(Profile, #{}) of
                {error, Reason} ->
                    fail("init", Reason);
                {ok, Pipe} ->
                    Rc = encrypt_with(Pipe, Plain, Profile, InFile, OutFile),
                    ok = itb:free(Pipe),
                    Rc
            end
    end.

encrypt_with(Pipe, Plain, Profile, InFile, OutFile) ->
    Result =
        case is_streaming_profile(Profile) of
            true -> stream_one_shot(Pipe, encrypt, Plain);
            false -> itb:encrypt_message(Pipe, Plain)
        end,
    case Result of
        {error, Reason} ->
            fail("encrypt", Reason);
        {ok, Wire} ->
            ok = ensure_parent_dir(OutFile),
            case file:write_file(OutFile, Wire) of
                {error, WriteErr} ->
                    io:format(standard_error, "eitb: cannot write ~s: ~p~n",
                              [OutFile, WriteErr]),
                    1;
                ok ->
                    {ok, Blob} = itb:blob(Pipe),
                    io:format(standard_error, "~s~n",
                              [string:lowercase(binary:encode_hex(Blob))]),
                    io:format("encrypted ~s -> ~s (~b -> ~b bytes)~n",
                              [InFile, OutFile, byte_size(Plain),
                               byte_size(Wire)]),
                    0
            end
    end.

cmd_decrypt(Profile, BlobHex, InFile, OutFile) ->
    ok = cap_go_runtime(),
    case decode_hex(BlobHex) of
        error ->
            io:format(standard_error, "eitb: invalid blob hex~n", []),
            1;
        {ok, Blob} ->
            case file:read_file(InFile) of
                {error, ReadErr} ->
                    io:format(standard_error, "eitb: cannot read ~s: ~p~n",
                              [InFile, ReadErr]),
                    1;
                {ok, Wire} ->
                    decrypt_with(Profile, Blob, Wire, InFile, OutFile)
            end
    end.

decrypt_with(Profile, Blob, Wire, InFile, OutFile) ->
    case itb:open(Profile, Blob, #{}) of
        {error, Reason} ->
            fail("open", Reason);
        {ok, Pipe} ->
            Result =
                case is_streaming_profile(Profile) of
                    true -> stream_one_shot(Pipe, decrypt, Wire);
                    false -> itb:decrypt_message(Pipe, Wire)
                end,
            Rc = case Result of
                     {error, DecErr} ->
                         fail("decrypt", DecErr);
                     {ok, Plain} ->
                         ok = ensure_parent_dir(OutFile),
                         case file:write_file(OutFile, Plain) of
                             {error, WriteErr} ->
                                 io:format(standard_error,
                                           "eitb: cannot write ~s: ~p~n",
                                           [OutFile, WriteErr]),
                                 1;
                             ok ->
                                 io:format("decrypted ~s -> ~s "
                                           "(~b -> ~b bytes)~n",
                                           [InFile, OutFile, byte_size(Wire),
                                            byte_size(Plain)]),
                                 0
                         end
                 end,
            ok = itb:free(Pipe),
            Rc
    end.

decode_hex(Hex) when length(Hex) > 0, length(Hex) rem 2 =:= 0 ->
    try
        {ok, binary:decode_hex(list_to_binary(Hex))}
    catch
        error:_ -> error
    end;
decode_hex(_) ->
    error.
