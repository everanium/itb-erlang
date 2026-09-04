#!/usr/bin/env escript
%% eitb — command-line demonstrator for the ITB Erlang binding.
%%
%% Subcommands:
%%
%%   eitb version                                   library + binding versions
%%   eitb profiles                                  registered profile catalogue
%%   eitb inspect <blob-hex>                        profile record of a blob
%%   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
%%   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
%%
%% `encrypt` prints the session blob (itb:save/1) to stderr as hex;
%% feed that hex back to `decrypt` on the receiving side, which
%% reopens the session with itb:load/1 (the profile argument only
%% routes Single Message versus streaming). `profiles` lists the
%% registered profile catalogue one name per line; the profiles that
%% carry a cipher surface are the ones `encrypt` / `decrypt` accept.
%%
%% The compiled binding (./build.sh in bindings/erlang) is resolved
%% relative to this script's location: ../_build/default/lib/itb/ebin.

-define(EITB_ERLANG_VERSION, "0.4.1").

main(Args) ->
    ok = add_binding_path(),
    Rc = dispatch(Args),
    halt(Rc).

dispatch(["version"]) ->
    cmd_version();
dispatch(["profiles"]) ->
    cmd_profiles();
dispatch(["inspect", BlobHex]) ->
    cmd_inspect(BlobHex);
dispatch(["encrypt", Profile, InFile, OutFile]) ->
    cmd_encrypt(Profile, InFile, OutFile);
dispatch(["decrypt", Profile, BlobHex, InFile, OutFile]) ->
    cmd_decrypt(Profile, BlobHex, InFile, OutFile);
dispatch(_) ->
    usage().

usage() ->
    io:format(standard_error,
              "usage: eitb version~n"
              "       eitb profiles~n"
              "       eitb inspect <blob-hex>~n"
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

cmd_profiles() ->
    lists:foreach(fun(Name) -> io:format("~s~n", [Name]) end, itb:profiles()),
    0.

cmd_inspect(BlobHex) ->
    case decode_hex(BlobHex) of
        error ->
            io:format(standard_error, "eitb: invalid blob hex~n", []),
            1;
        {ok, Blob} ->
            case itb:inspect(Blob) of
                {error, Reason} ->
                    fail("inspect", Reason);
                {ok, Record} ->
                    io:format("~s~n", [json:encode(Record)]),
                    0
            end
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
                    {ok, Blob} = itb:save(Pipe),
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
    case itb:load(Blob) of
        {error, Reason} ->
            fail("load", Reason);
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
