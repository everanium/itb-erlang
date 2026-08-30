%% itb_nif — raw NIF stub declarations for the ITB Erlang binding.
%%
%% Private module: consumers use the `itb` module. Every function here
%% is replaced by its C implementation from priv/itb_nif.so at load
%% time; the Erlang bodies below only fire when the NIF failed to
%% load. Argument terms are already normalised by `itb` (binaries for
%% names / payloads, `[{KeyBin, ValBin}]` for opts pairs).

-module(itb_nif).

-export([init_nif/2, open_nif/5, blob_nif/1, rekey_nif/3, free_nif/1,
         encrypt_message_nif/2, decrypt_message_nif/2,
         encrypt_stream_one_shot_nif/2, decrypt_stream_one_shot_nif/2,
         encrypt_stream_begin_nif/1, decrypt_stream_begin_nif/1,
         stream_write_nif/2, stream_end_nif/1, stream_read_nif/2,
         stream_free_nif/1, register_profile_nif/2,
         version_nif/0, hash_count_nif/0, hash_name_nif/1, hash_width_nif/1,
         last_error_nif/0, set_memory_limit_nif/1, set_gc_percent_nif/1]).

-on_load(load/0).

load() ->
    So = case code:priv_dir(itb) of
             {error, bad_name} ->
                 %% Not on the code path as an application dir (e.g. an
                 %% ad-hoc -pa setup): resolve priv/ as the sibling of
                 %% this module's ebin dir.
                 Ebin = filename:dirname(code:which(?MODULE)),
                 filename:join([filename:dirname(Ebin), "priv", "itb_nif"]);
             Priv ->
                 filename:join(Priv, "itb_nif")
         end,
    erlang:load_nif(So, 0).

init_nif(_Profile, _Opts) ->
    erlang:nif_error(itb_nif_not_loaded).

open_nif(_Profile, _Blob, _Opts, _PermMaster, _WrapMaster) ->
    erlang:nif_error(itb_nif_not_loaded).

blob_nif(_Pipeline) ->
    erlang:nif_error(itb_nif_not_loaded).

rekey_nif(_Pipeline, _PermMaster, _WrapMaster) ->
    erlang:nif_error(itb_nif_not_loaded).

free_nif(_Pipeline) ->
    erlang:nif_error(itb_nif_not_loaded).

encrypt_message_nif(_Pipeline, _Plain) ->
    erlang:nif_error(itb_nif_not_loaded).

decrypt_message_nif(_Pipeline, _Wire) ->
    erlang:nif_error(itb_nif_not_loaded).

encrypt_stream_one_shot_nif(_Pipeline, _Plain) ->
    erlang:nif_error(itb_nif_not_loaded).

decrypt_stream_one_shot_nif(_Pipeline, _Wire) ->
    erlang:nif_error(itb_nif_not_loaded).

encrypt_stream_begin_nif(_Pipeline) ->
    erlang:nif_error(itb_nif_not_loaded).

decrypt_stream_begin_nif(_Pipeline) ->
    erlang:nif_error(itb_nif_not_loaded).

stream_write_nif(_Stream, _Data) ->
    erlang:nif_error(itb_nif_not_loaded).

stream_end_nif(_Stream) ->
    erlang:nif_error(itb_nif_not_loaded).

stream_read_nif(_Stream, _MaxBytes) ->
    erlang:nif_error(itb_nif_not_loaded).

stream_free_nif(_Stream) ->
    erlang:nif_error(itb_nif_not_loaded).

register_profile_nif(_Name, _Opts) ->
    erlang:nif_error(itb_nif_not_loaded).

version_nif() ->
    erlang:nif_error(itb_nif_not_loaded).

hash_count_nif() ->
    erlang:nif_error(itb_nif_not_loaded).

hash_name_nif(_Index) ->
    erlang:nif_error(itb_nif_not_loaded).

hash_width_nif(_Index) ->
    erlang:nif_error(itb_nif_not_loaded).

last_error_nif() ->
    erlang:nif_error(itb_nif_not_loaded).

set_memory_limit_nif(_Bytes) ->
    erlang:nif_error(itb_nif_not_loaded).

set_gc_percent_nif(_Pct) ->
    erlang:nif_error(itb_nif_not_loaded).
