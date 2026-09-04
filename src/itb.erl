%% itb — public API of the ITB Erlang binding.
%%
%% Thin proxy over the ITB C binding's Triple Pipeline surface
%% (bindings/c, itb.h) through the NIF shim in c_src/itb_nif.c. No
%% ITB construction logic lives in this binding: profile names, opts
%% keys, and every primitive name are opaque strings passed through to
%% Go for validation.
%%
%% Quick start:
%%
%%     {ok, Sender} = itb:init("singlemsg-triple-mac-v1", #{}),
%%     {ok, Blob} = itb:save(Sender),
%%     {ok, Receiver} = itb:load(Blob),
%%     {ok, Wire} = itb:encrypt_message(Sender, <<"hi">>),
%%     {ok, <<"hi">>} = itb:decrypt_message(Receiver, Wire),
%%     ok = itb:free(Receiver),
%%     ok = itb:free(Sender).
%%
%% Handles are NIF resources: dropping every term reference lets the
%% garbage collector release the Go-side state (libitb zeroes key
%% material internally), and `free/1` / `stream_free/1` release
%% eagerly. A stream session pins its parent pipeline, so the
%% pipeline can never be collected under a live session. Do not call
%% `free/1` on a handle another process is concurrently using —
%% single-owner discipline per handle, or drop references and let the
%% collector free.
%%
%% Errors follow the `{ok, Result} | {error, {Status, Detail}}` idiom:
%% `Status` is an atom mirroring the C binding's status table (e.g.
%% `mac_failure`, `bad_input`, `profile_exists`) and `Detail` is the
%% Go-side diagnostic binary fetched immediately after the failing
%% call (the underlying store is process-global last-write-wins, so
%% under concurrent use the text may belong to a different call; the
%% status atom is always attributable).

-module(itb).

-export([init/2, load/1, load/3, load_f/1, load_f/3,
         save/1, save_f/2, max_workers/2, rekey/3, free/1,
         encrypt_message/2, decrypt_message/2,
         encrypt_stream_one_shot/2, decrypt_stream_one_shot/2,
         encrypt_stream/1, decrypt_stream/1,
         stream_write/2, stream_end/1, stream_read/1, stream_read/2,
         stream_free/1,
         inspect/1, register/2, lookup/1, profiles/0,
         version/0, last_error/0,
         set_memory_limit/1, set_gc_percent/1]).

-export_type([pipeline/0, stream/0, opts/0, profile/0, reason/0]).

-type pipeline() :: reference().
%% Opaque NIF resource for a Triple Pipeline session.

-type stream() :: reference().
%% Opaque NIF resource for an incremental stream session.

-type opt_key() :: atom() | binary() | string().
-type opt_value() :: atom() | binary() | string() | integer().
-type opts() :: #{opt_key() => opt_value()} | [{opt_key(), opt_value()}].
%% Opts accumulate into the URL-query string consumed by libitb; the
%% binding performs no validation — Go rejects unknown keys and bad
%% values with a diagnostic in the error detail.

-type profile() :: #{binary() => binary() | integer() | boolean() | [binary()]}.
%% Profile record: the JSON object libitb emits from inspect/1 /
%% lookup/1 and accepts in register/2, decoded with the OTP `json`
%% module (keys <<"name">>, <<"mode">>, <<"width">>, <<"hash">>,
%% <<"hashes">>, <<"keybits">>, <<"mac">>, <<"tagstub">>, <<"chunk">>,
%% <<"wrapper">>, <<"outer">>, <<"parallax">>, <<"palette">>,
%% <<"segment">>; absent keys are optional fields at their zero value).

-type status() ::
    bad_hash | bad_key_bits | bad_handle | bad_input | buffer_too_small |
    encrypt_failed | decrypt_failed | seed_width_mix | bad_mac |
    mac_failure | blob_malformed_recipe | recipe_primitive_unknown |
    unknown_profile | blob_mode_mismatch | blob_malformed |
    blob_version_too_new | blob_too_many_opts | stream_truncated |
    stream_after_final | triple_closed | profile_exists | internal.

-type reason() :: {status(), Detail :: binary()}.

%% Default drain slice for stream_read/1.
-define(READ_BUF, 1 bsl 20).

%% ------------------------------------------------------------------
%% Pipeline lifecycle
%% ------------------------------------------------------------------

%% Constructs a fresh Pipeline against the named profile. Opts may be
%% an empty map / list for pure profile defaults. The session blob is
%% available through save/1.
-spec init(iodata() | atom(), opts()) -> {ok, pipeline()} | {error, reason()}.
init(Profile, Opts) ->
    itb_nif:init_nif(to_bin(Profile), opts_pairs(Opts)).

%% Reconstructs a Pipeline from a blob produced by save/1 or rekey/3,
%% using the blob-embedded masters. The blob's embedded profile
%% record is the sole structural source — no profile name, no opts.
-spec load(binary()) -> {ok, pipeline()} | {error, reason()}.
load(Blob) ->
    load(Blob, <<>>, <<>>).

%% As load/1 with explicit master overrides. Both masters must be
%% supplied (a half-supplied pair is rejected Go-side); pass
%% `<<>>` / `<<>>` for the blob-embedded masters.
-spec load(binary(), binary(), binary()) ->
          {ok, pipeline()} | {error, reason()}.
load(Blob, PermMaster, WrapMaster) ->
    itb_nif:load_nif(Blob, PermMaster, WrapMaster).

%% load/1 for a blob stored in a file; the file is read inside the
%% library.
-spec load_f(iodata()) -> {ok, pipeline()} | {error, reason()}.
load_f(Path) ->
    load_f(Path, <<>>, <<>>).

%% As load_f/1 with explicit master overrides.
-spec load_f(iodata(), binary(), binary()) ->
          {ok, pipeline()} | {error, reason()}.
load_f(Path, PermMaster, WrapMaster) ->
    itb_nif:load_f_nif(to_bin(Path), PermMaster, WrapMaster).

%% The current serialised session blob — the bytes init produced, the
%% bytes load re-marshalled, or the bytes of the latest rekey/3.
-spec save(pipeline()) -> {ok, binary()} | {error, reason()}.
save(Pipeline) ->
    itb_nif:save_nif(Pipeline).

%% Writes the current session blob to Path inside the library (mode
%% 0600; the containing directory must exist).
-spec save_f(pipeline(), iodata()) -> ok | {error, reason()}.
save_f(Pipeline, Path) ->
    itb_nif:save_f_nif(Pipeline, to_bin(Path)).

%% Sets the worker cap for every subsequent cipher call. N is clamped,
%% never rejected: N =< 0 selects auto, 1..256 pins the cap, larger
%% values are treated as 256. The cap is per-machine tuning and is
%% never written to the blob.
-spec max_workers(pipeline(), integer()) -> ok | {error, reason()}.
max_workers(Pipeline, N) ->
    itb_nif:max_workers_nif(Pipeline, N).

%% Rotates the parallax + wrapper masters and returns the refreshed
%% session blob (also observable through save/1). Must not run
%% concurrently with cipher calls or open stream sessions on the same
%% Pipeline.
-spec rekey(pipeline(), binary(), binary()) -> {ok, binary()} | {error, reason()}.
rekey(Pipeline, PermMaster, WrapMaster) ->
    itb_nif:rekey_nif(Pipeline, PermMaster, WrapMaster).

%% Eagerly closes (zeroing key material Go-side) and releases the
%% handle. Idempotent; subsequent calls on the handle fail with
%% `{error, {bad_handle, _}}`. Garbage collection of the last term
%% reference is the release backstop.
-spec free(pipeline()) -> ok.
free(Pipeline) ->
    itb_nif:free_nif(Pipeline).

%% ------------------------------------------------------------------
%% Single Message encrypt / decrypt
%% ------------------------------------------------------------------

%% One call, one self-contained wire.
-spec encrypt_message(pipeline(), iodata()) ->
          {ok, binary()} | {error, reason()}.
encrypt_message(Pipeline, Plain) ->
    itb_nif:encrypt_message_nif(Pipeline, Plain).

%% Receive-side counterpart of encrypt_message/2.
-spec decrypt_message(pipeline(), iodata()) ->
          {ok, binary()} | {error, reason()}.
decrypt_message(Pipeline, Wire) ->
    itb_nif:decrypt_message_nif(Pipeline, Wire).

%% ------------------------------------------------------------------
%% One-shot stream encrypt / decrypt
%% ------------------------------------------------------------------

%% One-shot stream encrypt for callers holding the whole plaintext in
%% memory: a single call through the Pipeline's stream chain. For
%% bounded-memory streaming use the incremental encrypt_stream/1
%% session.
-spec encrypt_stream_one_shot(pipeline(), iodata()) ->
          {ok, binary()} | {error, reason()}.
encrypt_stream_one_shot(Pipeline, Plain) ->
    itb_nif:encrypt_stream_one_shot_nif(Pipeline, Plain).

%% Receive-side counterpart of encrypt_stream_one_shot/2.
-spec decrypt_stream_one_shot(pipeline(), iodata()) ->
          {ok, binary()} | {error, reason()}.
decrypt_stream_one_shot(Pipeline, Wire) ->
    itb_nif:decrypt_stream_one_shot_nif(Pipeline, Wire).

%% ------------------------------------------------------------------
%% Incremental stream sessions
%% ------------------------------------------------------------------

%% Opens an incremental encrypt session (plaintext in, wire out). The
%% session must not outlive its Pipeline (it pins the pipeline term,
%% so dropping the pipeline reference alone never frees it early).
-spec encrypt_stream(pipeline()) -> {ok, stream()} | {error, reason()}.
encrypt_stream(Pipeline) ->
    itb_nif:encrypt_stream_begin_nif(Pipeline).

%% Receive-side counterpart (wire in, plaintext out).
-spec decrypt_stream(pipeline()) -> {ok, stream()} | {error, reason()}.
decrypt_stream(Pipeline) ->
    itb_nif:decrypt_stream_begin_nif(Pipeline).

%% Feeds Data into the session. Blocks (on a dirty scheduler) until
%% the cipher chain accepts the bytes; errors are sticky.
-spec stream_write(stream(), iodata()) -> ok | {error, reason()}.
stream_write(Stream, Data) ->
    itb_nif:stream_write_nif(Stream, Data).

%% Signals end-of-input. Idempotent; a write after end fails with
%% `{error, {bad_input, _}}`.
-spec stream_end(stream()) -> ok | {error, reason()}.
stream_end(Stream) ->
    itb_nif:stream_end_nif(Stream).

%% As stream_read/2 with a 1 MiB drain slice.
-spec stream_read(stream()) ->
          {ok, binary(), boolean()} | {error, reason()}.
stream_read(Stream) ->
    stream_read(Stream, ?READ_BUF).

%% Drains up to MaxBytes produced bytes. Returns `{ok, Data, Finished}`
%% — Data may be `<<>>` when nothing is currently available, and
%% Finished is `true` once the session has ended AND the output is
%% fully drained. Partial drains are the normal mode. After
%% stream_end/1, an empty-spool read blocks until the terminal bytes
%% arrive or the session errors.
-spec stream_read(stream(), pos_integer()) ->
          {ok, binary(), boolean()} | {error, reason()}.
stream_read(Stream, MaxBytes) ->
    itb_nif:stream_read_nif(Stream, MaxBytes).

%% Cancels (if still running) and eagerly releases the session. Safe
%% from any state — mid-flight, mid-error, or after a clean drain.
%% Idempotent; garbage collection is the release backstop.
-spec stream_free(stream()) -> ok.
stream_free(Stream) ->
    itb_nif:stream_free_nif(Stream).

%% ------------------------------------------------------------------
%% Profile catalogue
%% ------------------------------------------------------------------

%% Decodes the blob's embedded profile record without opening a
%% Pipeline. No registry read, no primitive probe.
-spec inspect(binary()) -> {ok, profile()} | {error, reason()}.
inspect(Blob) ->
    json_out(itb_nif:inspect_nif(Blob)).

%% Registers a profile record under Name so subsequent init/2 /
%% lookup/1 calls resolve it. Profile is the record as a map (the
%% shape inspect/1 / lookup/1 return) or an already-encoded JSON
%% binary; a <<"name">> key inside it, if present, must be empty or
%% equal to Name. Validation is performed by libitb; a duplicate name
%% fails with `{error, {profile_exists, _}}`.
-spec register(iodata() | atom(), profile() | iodata()) -> ok | {error, reason()}.
register(Name, Profile) when is_map(Profile) ->
    itb_nif:register_nif(to_bin(Name), iolist_to_binary(json:encode(Profile)));
register(Name, ProfileJson) ->
    itb_nif:register_nif(to_bin(Name), to_bin(ProfileJson)).

%% The profile record registered under Name (a shipped catalogue entry
%% or a prior register/2). An unknown name fails with
%% `{error, {unknown_profile, _}}`.
-spec lookup(iodata() | atom()) -> {ok, profile()} | {error, reason()}.
lookup(Name) ->
    json_out(itb_nif:lookup_nif(to_bin(Name))).

%% The sorted list of every registered profile name.
-spec profiles() -> [binary()].
profiles() ->
    {ok, Names} = json_out(itb_nif:profiles_nif()),
    Names.

json_out({ok, Json}) -> {ok, json:decode(Json)};
json_out({error, _} = Err) -> Err.

%% ------------------------------------------------------------------
%% Runtime + diagnostics
%% ------------------------------------------------------------------

%% The libitb library version string (e.g. <<"0.4.1">>).
-spec version() -> {ok, binary()} | {error, reason()}.
version() ->
    itb_nif:version_nif().

%% The Go-side diagnostic recorded by the most recent failing libitb
%% call (process-global last-write-wins; `<<>>` when none). The error
%% tuples already carry this detail — direct use is for ad-hoc
%% debugging only.
-spec last_error() -> binary().
last_error() ->
    itb_nif:last_error_nif().

%% Sets the Go runtime's soft heap limit in bytes; returns the
%% previous limit. A negative value queries without changing.
-spec set_memory_limit(integer()) -> integer().
set_memory_limit(Bytes) ->
    itb_nif:set_memory_limit_nif(Bytes).

%% Sets the Go GC trigger percentage; returns the previous value. A
%% negative value queries without changing.
-spec set_gc_percent(integer()) -> integer().
set_gc_percent(Pct) ->
    itb_nif:set_gc_percent_nif(Pct).

%% ------------------------------------------------------------------
%% Term normalisation
%% ------------------------------------------------------------------

-spec to_bin(iodata() | atom()) -> binary().
to_bin(Value) when is_binary(Value) -> Value;
to_bin(Value) when is_atom(Value) -> atom_to_binary(Value, utf8);
to_bin(Value) when is_list(Value) -> unicode:characters_to_binary(Value).

-spec val_bin(opt_value()) -> binary().
val_bin(true) -> <<"true">>;
val_bin(false) -> <<"false">>;
val_bin(Value) when is_integer(Value) -> integer_to_binary(Value);
val_bin(Value) -> to_bin(Value).

-spec opts_pairs(opts()) -> [{binary(), binary()}].
opts_pairs(Opts) when is_map(Opts) ->
    [{to_bin(K), val_bin(V)} || K := V <- Opts];
opts_pairs(Opts) when is_list(Opts) ->
    [{to_bin(K), val_bin(V)} || {K, V} <- Opts].
