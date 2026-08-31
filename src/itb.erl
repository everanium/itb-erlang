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
%%     {ok, Blob} = itb:blob(Sender),
%%     {ok, Receiver} = itb:open("singlemsg-triple-mac-v1", Blob, #{}),
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

-export([init/2, open/3, open/5, blob/1, rekey/3, free/1,
         encrypt_message/2, decrypt_message/2,
         encrypt_stream_one_shot/2, decrypt_stream_one_shot/2,
         encrypt_stream/1, decrypt_stream/1,
         stream_write/2, stream_end/1, stream_read/1, stream_read/2,
         stream_free/1,
         register_profile/2,
         version/0, hashes/0, last_error/0,
         set_memory_limit/1, set_gc_percent/1]).

-export_type([pipeline/0, stream/0, opts/0, reason/0]).

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

-type status() ::
    bad_hash | bad_key_bits | bad_handle | bad_input | buffer_too_small |
    encrypt_failed | decrypt_failed | seed_width_mix | bad_mac |
    mac_failure | blob_mode_mismatch | blob_malformed |
    blob_version_too_new | blob_too_many_opts | stream_truncated |
    stream_after_final | triple_closed | profile_exists | internal.

-type reason() :: {status(), Detail :: binary()}.

%% Default drain slice for stream_read/1.
-define(READ_BUF, 1 bsl 20).

%% ------------------------------------------------------------------
%% Pipeline lifecycle
%% ------------------------------------------------------------------

%% Constructs a fresh Pipeline against the named profile. Opts may be
%% an empty map / list for pure profile defaults.
-spec init(iodata() | atom(), opts()) -> {ok, pipeline()} | {error, reason()}.
init(Profile, Opts) ->
    itb_nif:init_nif(to_bin(Profile), opts_pairs(Opts)).

%% Reconstructs a Pipeline from a blob produced by a sender's init /
%% rekey, using the blob-embedded masters.
-spec open(iodata() | atom(), binary(), opts()) ->
          {ok, pipeline()} | {error, reason()}.
open(Profile, Blob, Opts) ->
    open(Profile, Blob, Opts, <<>>, <<>>).

%% As open/3 with explicit master overrides. Both masters must be
%% supplied non-empty (a half-supplied pair is rejected); pass
%% `<<>>` / `<<>>` for the blob-embedded masters.
-spec open(iodata() | atom(), binary(), opts(), binary(), binary()) ->
          {ok, pipeline()} | {error, reason()}.
open(Profile, Blob, Opts, PermMaster, WrapMaster) ->
    itb_nif:open_nif(to_bin(Profile), Blob, opts_pairs(Opts),
                     PermMaster, WrapMaster).

%% The exported session-bundle blob for the receiver side; refreshed
%% by rekey/3.
-spec blob(pipeline()) -> {ok, binary()} | {error, reason()}.
blob(Pipeline) ->
    itb_nif:blob_nif(Pipeline).

%% Rotates the parallax + wrapper masters and refreshes the blob. Must
%% not run concurrently with cipher calls or open stream sessions on
%% the same Pipeline.
-spec rekey(pipeline(), binary(), binary()) -> ok | {error, reason()}.
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
%% Profile registration
%% ------------------------------------------------------------------

%% Registers a user-defined Triple profile under Name; the opts follow
%% the register-profile grammar validated by Go. A duplicate name
%% fails with `{error, {profile_exists, _}}`.
-spec register_profile(iodata() | atom(), opts()) -> ok | {error, reason()}.
register_profile(Name, Opts) ->
    itb_nif:register_profile_nif(to_bin(Name), opts_pairs(Opts)).

%% ------------------------------------------------------------------
%% Runtime + diagnostics
%% ------------------------------------------------------------------

%% The libitb library version string (e.g. <<"0.3.1">>).
-spec version() -> {ok, binary()} | {error, reason()}.
version() ->
    itb_nif:version_nif().

%% The shipped hash primitive roster as `[{Name, WidthBits}]` in
%% canonical registry order.
-spec hashes() -> [{binary(), pos_integer()}].
hashes() ->
    Count = itb_nif:hash_count_nif(),
    [{itb_nif:hash_name_nif(I), itb_nif:hash_width_nif(I)}
     || I <- lists:seq(0, Count - 1)].

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
