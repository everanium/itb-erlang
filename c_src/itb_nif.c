/*
 * itb_nif.c — Erlang NIF shim for the ITB Erlang binding.
 *
 * Thin proxy over the ITB C binding (bindings/c): every entry wraps
 * one itb_pipeline_* / itb_stream_* / diagnostics call from <itb.h>
 * and relays opaque bytes plus status codes into Erlang terms. No ITB
 * construction logic lives here; profile names, opts keys, and every
 * primitive name are opaque strings validated Go-side. The
 * caller-allocated-buffer retry-once convention (pattern P1) is
 * handled inside libitb_c.a — this shim never calls libitb.so
 * directly.
 *
 * Scheduling. Cipher, stream, and session-lifecycle entries are
 * flagged ERL_NIF_DIRTY_JOB_CPU_BOUND: encrypt / decrypt is CPU-bound
 * and a stream read after end may block until the terminal bytes
 * arrive, either of which would stall a regular Erlang scheduler.
 * The cheap diagnostics entries (version / hashes / last_error) stay
 * on the regular schedulers.
 *
 * Handle lifetime. Pipelines and stream sessions are NIF resources.
 * The resource destructor is the release backstop when the last term
 * reference is garbage collected; the explicit free entries release
 * eagerly (atomically swapping the inner pointer so an explicit free
 * racing the destructor cannot double-free). A stream resource pins
 * its parent pipeline resource via enif_keep_resource, so the
 * pipeline destructor cannot run while a session term is alive.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <erl_nif.h>

#include "itb.h"

static ErlNifResourceType *g_pipeline_rt;
static ErlNifResourceType *g_stream_rt;

typedef struct {
    itb_pipeline *pipe; /* NULL after free */
} pipeline_res;

typedef struct {
    itb_stream *stream;  /* NULL after free */
    pipeline_res *parent; /* kept via enif_keep_resource */
} stream_res;

/* ------------------------------------------------------------------ */
/* Term helpers                                                        */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM make_bin(ErlNifEnv *env, const void *data, size_t len)
{
    ERL_NIF_TERM term;
    unsigned char *p = enif_make_new_binary(env, len, &term);
    if (len > 0) {
        memcpy(p, data, len);
    }
    return term;
}

static ERL_NIF_TERM status_to_atom(ErlNifEnv *env, itb_status st)
{
    const char *name;
    switch (st) {
    case ITB_STATUS_OK:                   name = "ok"; break;
    case ITB_STATUS_BAD_HASH:             name = "bad_hash"; break;
    case ITB_STATUS_BAD_KEY_BITS:         name = "bad_key_bits"; break;
    case ITB_STATUS_BAD_HANDLE:           name = "bad_handle"; break;
    case ITB_STATUS_BAD_INPUT:            name = "bad_input"; break;
    case ITB_STATUS_BUFFER_TOO_SMALL:     name = "buffer_too_small"; break;
    case ITB_STATUS_ENCRYPT_FAILED:       name = "encrypt_failed"; break;
    case ITB_STATUS_DECRYPT_FAILED:       name = "decrypt_failed"; break;
    case ITB_STATUS_SEED_WIDTH_MIX:       name = "seed_width_mix"; break;
    case ITB_STATUS_BAD_MAC:              name = "bad_mac"; break;
    case ITB_STATUS_MAC_FAILURE:          name = "mac_failure"; break;
    case ITB_STATUS_BLOB_MODE_MISMATCH:   name = "blob_mode_mismatch"; break;
    case ITB_STATUS_BLOB_MALFORMED:       name = "blob_malformed"; break;
    case ITB_STATUS_BLOB_VERSION_TOO_NEW: name = "blob_version_too_new"; break;
    case ITB_STATUS_BLOB_TOO_MANY_OPTS:   name = "blob_too_many_opts"; break;
    case ITB_STATUS_STREAM_TRUNCATED:     name = "stream_truncated"; break;
    case ITB_STATUS_STREAM_AFTER_FINAL:   name = "stream_after_final"; break;
    case ITB_STATUS_TRIPLE_CLOSED:        name = "triple_closed"; break;
    case ITB_STATUS_PROFILE_EXISTS:       name = "profile_exists"; break;
    default:                              name = "internal"; break;
    }
    return enif_make_atom(env, name);
}

/* {error, {StatusAtom, DetailBinary}} where Detail is the libitb
 * diagnostic fetched immediately after the failing call on the same
 * thread (the underlying store is process-global last-write-wins). */
static ERL_NIF_TERM make_error(ErlNifEnv *env, itb_status st)
{
    const char *diag = itb_last_error();
    return enif_make_tuple2(
        env, enif_make_atom(env, "error"),
        enif_make_tuple2(env, status_to_atom(env, st),
                         make_bin(env, diag, strlen(diag))));
}

/* Binding-side error with a fixed message (no libitb call failed). */
static ERL_NIF_TERM make_error_msg(ErlNifEnv *env, itb_status st,
                                   const char *msg)
{
    return enif_make_tuple2(
        env, enif_make_atom(env, "error"),
        enif_make_tuple2(env, status_to_atom(env, st),
                         make_bin(env, msg, strlen(msg))));
}

static ERL_NIF_TERM make_ok(ErlNifEnv *env, ERL_NIF_TERM value)
{
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), value);
}

/* Copies an iolist / binary term into a NUL-terminated C string
 * (enif_alloc'd; release with enif_free). NULL when the term is not
 * an iolist or allocation fails. */
static char *term_to_cstr(ErlNifEnv *env, ERL_NIF_TERM term)
{
    ErlNifBinary bin;
    if (!enif_inspect_iolist_as_binary(env, term, &bin)) {
        return NULL;
    }
    char *s = enif_alloc(bin.size + 1);
    if (s == NULL) {
        return NULL;
    }
    if (bin.size > 0) {
        memcpy(s, bin.data, bin.size);
    }
    s[bin.size] = '\0';
    return s;
}

/* Builds an itb_opts from a (possibly empty) list of {KeyBin, ValBin}
 * tuples. On success *out is NULL (empty list — profile defaults) or
 * a builder the caller releases with itb_opts_free. Returns 0 on a
 * malformed term (badarg), 1 on success, -1 on allocation failure. */
static int opts_from_list(ErlNifEnv *env, ERL_NIF_TERM list, itb_opts **out)
{
    *out = NULL;
    if (enif_is_empty_list(env, list)) {
        return 1;
    }
    if (!enif_is_list(env, list)) {
        return 0;
    }
    itb_opts *opts = itb_opts_new();
    if (opts == NULL) {
        return -1;
    }
    ERL_NIF_TERM head, tail = list;
    while (enif_get_list_cell(env, tail, &head, &tail)) {
        int arity = 0;
        const ERL_NIF_TERM *pair = NULL;
        if (!enif_get_tuple(env, head, &arity, &pair) || arity != 2) {
            itb_opts_free(opts);
            return 0;
        }
        char *key = term_to_cstr(env, pair[0]);
        char *val = term_to_cstr(env, pair[1]);
        if (key == NULL || val == NULL) {
            enif_free(key);
            enif_free(val);
            itb_opts_free(opts);
            return key == NULL && val == NULL ? 0 : -1;
        }
        itb_status st = itb_opts_set(opts, key, val);
        enif_free(key);
        enif_free(val);
        if (st != ITB_STATUS_OK) {
            itb_opts_free(opts);
            return -1;
        }
    }
    *out = opts;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Resource lifecycle                                                  */
/* ------------------------------------------------------------------ */

static void pipeline_dtor(ErlNifEnv *env, void *obj)
{
    (void)env;
    pipeline_res *r = obj;
    itb_pipeline *pipe = __atomic_exchange_n(&r->pipe, NULL, __ATOMIC_ACQ_REL);
    itb_pipeline_free(pipe); /* NULL-safe */
}

static void stream_dtor(ErlNifEnv *env, void *obj)
{
    (void)env;
    stream_res *r = obj;
    itb_stream *stream = __atomic_exchange_n(&r->stream, NULL, __ATOMIC_ACQ_REL);
    itb_stream_free(stream); /* NULL-safe; cancels a mid-flight session */
    pipeline_res *parent =
        __atomic_exchange_n(&r->parent, NULL, __ATOMIC_ACQ_REL);
    if (parent != NULL) {
        enif_release_resource(parent);
    }
}

static int get_pipeline(ErlNifEnv *env, ERL_NIF_TERM term, pipeline_res **out)
{
    return enif_get_resource(env, term, g_pipeline_rt, (void **)out);
}

static int get_stream(ErlNifEnv *env, ERL_NIF_TERM term, stream_res **out)
{
    return enif_get_resource(env, term, g_stream_rt, (void **)out);
}

static itb_pipeline *pipeline_ptr(pipeline_res *r)
{
    return __atomic_load_n(&r->pipe, __ATOMIC_ACQUIRE);
}

static itb_stream *stream_ptr(stream_res *r)
{
    return __atomic_load_n(&r->stream, __ATOMIC_ACQUIRE);
}

#define FREED_PIPELINE_MSG "pipeline handle already freed"
#define FREED_STREAM_MSG "stream handle already freed"

/* ------------------------------------------------------------------ */
/* Pipeline entries                                                    */
/* ------------------------------------------------------------------ */

/* init_nif(ProfileBin, OptsPairs) -> {ok, Pipeline} | {error, _} */
static ERL_NIF_TERM init_nif(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[])
{
    (void)argc;
    char *profile = term_to_cstr(env, argv[0]);
    if (profile == NULL) {
        return enif_make_badarg(env);
    }
    itb_opts *opts = NULL;
    int rc = opts_from_list(env, argv[1], &opts);
    if (rc <= 0) {
        enif_free(profile);
        return rc == 0 ? enif_make_badarg(env)
                       : make_error_msg(env, ITB_STATUS_INTERNAL,
                                        "opts allocation failed");
    }
    itb_pipeline *pipe = NULL;
    itb_status st = itb_pipeline_init(profile, opts, &pipe);
    enif_free(profile);
    itb_opts_free(opts);
    if (st != ITB_STATUS_OK) {
        return make_error(env, st);
    }
    pipeline_res *r = enif_alloc_resource(g_pipeline_rt, sizeof(*r));
    if (r == NULL) {
        itb_pipeline_free(pipe);
        return make_error_msg(env, ITB_STATUS_INTERNAL,
                              "resource allocation failed");
    }
    r->pipe = pipe;
    ERL_NIF_TERM term = enif_make_resource(env, r);
    enif_release_resource(r);
    return make_ok(env, term);
}

/* open_nif(ProfileBin, BlobBin, OptsPairs, PermBin, WrapBin)
 * -> {ok, Pipeline} | {error, _}
 * Empty Perm + Wrap means "use the blob-embedded masters". */
static ERL_NIF_TERM open_nif(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[])
{
    (void)argc;
    ErlNifBinary blob, perm, wrap;
    if (!enif_inspect_iolist_as_binary(env, argv[1], &blob) ||
        !enif_inspect_iolist_as_binary(env, argv[3], &perm) ||
        !enif_inspect_iolist_as_binary(env, argv[4], &wrap)) {
        return enif_make_badarg(env);
    }
    char *profile = term_to_cstr(env, argv[0]);
    if (profile == NULL) {
        return enif_make_badarg(env);
    }
    itb_opts *opts = NULL;
    int rc = opts_from_list(env, argv[2], &opts);
    if (rc <= 0) {
        enif_free(profile);
        return rc == 0 ? enif_make_badarg(env)
                       : make_error_msg(env, ITB_STATUS_INTERNAL,
                                        "opts allocation failed");
    }
    itb_pipeline *pipe = NULL;
    itb_status st = itb_pipeline_open(
        profile, blob.data, blob.size, opts,
        perm.size > 0 ? perm.data : NULL, perm.size,
        wrap.size > 0 ? wrap.data : NULL, wrap.size, &pipe);
    enif_free(profile);
    itb_opts_free(opts);
    if (st != ITB_STATUS_OK) {
        return make_error(env, st);
    }
    pipeline_res *r = enif_alloc_resource(g_pipeline_rt, sizeof(*r));
    if (r == NULL) {
        itb_pipeline_free(pipe);
        return make_error_msg(env, ITB_STATUS_INTERNAL,
                              "resource allocation failed");
    }
    r->pipe = pipe;
    ERL_NIF_TERM term = enif_make_resource(env, r);
    enif_release_resource(r);
    return make_ok(env, term);
}

/* blob_nif(Pipeline) -> {ok, Blob} | {error, _} */
static ERL_NIF_TERM blob_nif(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[])
{
    (void)argc;
    pipeline_res *r = NULL;
    if (!get_pipeline(env, argv[0], &r)) {
        return enif_make_badarg(env);
    }
    itb_pipeline *pipe = pipeline_ptr(r);
    if (pipe == NULL) {
        return make_error_msg(env, ITB_STATUS_BAD_HANDLE, FREED_PIPELINE_MSG);
    }
    return make_ok(env, make_bin(env, itb_pipeline_blob(pipe),
                                 itb_pipeline_blob_len(pipe)));
}

/* rekey_nif(Pipeline, PermBin, WrapBin) -> ok | {error, _} */
static ERL_NIF_TERM rekey_nif(ErlNifEnv *env, int argc,
                              const ERL_NIF_TERM argv[])
{
    (void)argc;
    pipeline_res *r = NULL;
    ErlNifBinary perm, wrap;
    if (!get_pipeline(env, argv[0], &r) ||
        !enif_inspect_iolist_as_binary(env, argv[1], &perm) ||
        !enif_inspect_iolist_as_binary(env, argv[2], &wrap)) {
        return enif_make_badarg(env);
    }
    itb_pipeline *pipe = pipeline_ptr(r);
    if (pipe == NULL) {
        return make_error_msg(env, ITB_STATUS_BAD_HANDLE, FREED_PIPELINE_MSG);
    }
    itb_status st = itb_pipeline_rekey(pipe, perm.data, perm.size,
                                       wrap.data, wrap.size);
    if (st != ITB_STATUS_OK) {
        return make_error(env, st);
    }
    return enif_make_atom(env, "ok");
}

/* free_nif(Pipeline) -> ok  (eager release; destructor is backstop) */
static ERL_NIF_TERM free_nif(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[])
{
    (void)argc;
    pipeline_res *r = NULL;
    if (!get_pipeline(env, argv[0], &r)) {
        return enif_make_badarg(env);
    }
    itb_pipeline *pipe = __atomic_exchange_n(&r->pipe, NULL, __ATOMIC_ACQ_REL);
    itb_pipeline_free(pipe); /* NULL-safe */
    return enif_make_atom(env, "ok");
}

/* Shared body for the Single Message cipher entries. */
static ERL_NIF_TERM message_call(ErlNifEnv *env, const ERL_NIF_TERM argv[],
                                 int encrypt)
{
    pipeline_res *r = NULL;
    ErlNifBinary src;
    if (!get_pipeline(env, argv[0], &r) ||
        !enif_inspect_iolist_as_binary(env, argv[1], &src)) {
        return enif_make_badarg(env);
    }
    itb_pipeline *pipe = pipeline_ptr(r);
    if (pipe == NULL) {
        return make_error_msg(env, ITB_STATUS_BAD_HANDLE, FREED_PIPELINE_MSG);
    }
    uint8_t *out = NULL;
    size_t out_len = 0;
    itb_status st =
        encrypt ? itb_pipeline_encrypt_message(pipe, src.data, src.size,
                                               &out, &out_len)
                : itb_pipeline_decrypt_message(pipe, src.data, src.size,
                                               &out, &out_len);
    if (st != ITB_STATUS_OK) {
        return make_error(env, st);
    }
    ERL_NIF_TERM bin = make_bin(env, out, out_len);
    itb_bytes_free(out);
    return make_ok(env, bin);
}

static ERL_NIF_TERM encrypt_message_nif(ErlNifEnv *env, int argc,
                                        const ERL_NIF_TERM argv[])
{
    (void)argc;
    return message_call(env, argv, 1);
}

static ERL_NIF_TERM decrypt_message_nif(ErlNifEnv *env, int argc,
                                        const ERL_NIF_TERM argv[])
{
    (void)argc;
    return message_call(env, argv, 0);
}

/* Shared body for the one-shot stream cipher entries: whole buffer
 * in, whole buffer out, a single FFI round trip through the
 * Pipeline's stream chain. */
static ERL_NIF_TERM stream_one_shot_call(ErlNifEnv *env,
                                         const ERL_NIF_TERM argv[],
                                         int encrypt)
{
    pipeline_res *r = NULL;
    ErlNifBinary src;
    if (!get_pipeline(env, argv[0], &r) ||
        !enif_inspect_iolist_as_binary(env, argv[1], &src)) {
        return enif_make_badarg(env);
    }
    itb_pipeline *pipe = pipeline_ptr(r);
    if (pipe == NULL) {
        return make_error_msg(env, ITB_STATUS_BAD_HANDLE, FREED_PIPELINE_MSG);
    }
    uint8_t *out = NULL;
    size_t out_len = 0;
    itb_status st =
        encrypt ? itb_pipeline_encrypt_stream_one_shot(pipe, src.data,
                                                       src.size, &out,
                                                       &out_len)
                : itb_pipeline_decrypt_stream_one_shot(pipe, src.data,
                                                       src.size, &out,
                                                       &out_len);
    if (st != ITB_STATUS_OK) {
        return make_error(env, st);
    }
    ERL_NIF_TERM bin = make_bin(env, out, out_len);
    itb_bytes_free(out);
    return make_ok(env, bin);
}

static ERL_NIF_TERM encrypt_stream_one_shot_nif(ErlNifEnv *env, int argc,
                                                const ERL_NIF_TERM argv[])
{
    (void)argc;
    return stream_one_shot_call(env, argv, 1);
}

static ERL_NIF_TERM decrypt_stream_one_shot_nif(ErlNifEnv *env, int argc,
                                                const ERL_NIF_TERM argv[])
{
    (void)argc;
    return stream_one_shot_call(env, argv, 0);
}

/* ------------------------------------------------------------------ */
/* Stream session entries                                              */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM stream_begin(ErlNifEnv *env, const ERL_NIF_TERM argv[],
                                 int encrypt)
{
    pipeline_res *r = NULL;
    if (!get_pipeline(env, argv[0], &r)) {
        return enif_make_badarg(env);
    }
    itb_pipeline *pipe = pipeline_ptr(r);
    if (pipe == NULL) {
        return make_error_msg(env, ITB_STATUS_BAD_HANDLE, FREED_PIPELINE_MSG);
    }
    itb_stream *stream = NULL;
    itb_status st = encrypt ? itb_pipeline_encrypt_stream_begin(pipe, &stream)
                            : itb_pipeline_decrypt_stream_begin(pipe, &stream);
    if (st != ITB_STATUS_OK) {
        return make_error(env, st);
    }
    stream_res *s = enif_alloc_resource(g_stream_rt, sizeof(*s));
    if (s == NULL) {
        itb_stream_free(stream);
        return make_error_msg(env, ITB_STATUS_INTERNAL,
                              "resource allocation failed");
    }
    s->stream = stream;
    /* Pin the parent pipeline resource so its destructor cannot run
     * while this session term is alive. */
    enif_keep_resource(r);
    s->parent = r;
    ERL_NIF_TERM term = enif_make_resource(env, s);
    enif_release_resource(s);
    return make_ok(env, term);
}

static ERL_NIF_TERM encrypt_stream_begin_nif(ErlNifEnv *env, int argc,
                                             const ERL_NIF_TERM argv[])
{
    (void)argc;
    return stream_begin(env, argv, 1);
}

static ERL_NIF_TERM decrypt_stream_begin_nif(ErlNifEnv *env, int argc,
                                             const ERL_NIF_TERM argv[])
{
    (void)argc;
    return stream_begin(env, argv, 0);
}

/* stream_write_nif(Stream, Data) -> ok | {error, _} */
static ERL_NIF_TERM stream_write_nif(ErlNifEnv *env, int argc,
                                     const ERL_NIF_TERM argv[])
{
    (void)argc;
    stream_res *s = NULL;
    ErlNifBinary src;
    if (!get_stream(env, argv[0], &s) ||
        !enif_inspect_iolist_as_binary(env, argv[1], &src)) {
        return enif_make_badarg(env);
    }
    itb_stream *stream = stream_ptr(s);
    if (stream == NULL) {
        return make_error_msg(env, ITB_STATUS_BAD_HANDLE, FREED_STREAM_MSG);
    }
    itb_status st = itb_stream_write(stream, src.data, src.size);
    if (st != ITB_STATUS_OK) {
        return make_error(env, st);
    }
    return enif_make_atom(env, "ok");
}

/* stream_end_nif(Stream) -> ok | {error, _} */
static ERL_NIF_TERM stream_end_nif(ErlNifEnv *env, int argc,
                                   const ERL_NIF_TERM argv[])
{
    (void)argc;
    stream_res *s = NULL;
    if (!get_stream(env, argv[0], &s)) {
        return enif_make_badarg(env);
    }
    itb_stream *stream = stream_ptr(s);
    if (stream == NULL) {
        return make_error_msg(env, ITB_STATUS_BAD_HANDLE, FREED_STREAM_MSG);
    }
    itb_status st = itb_stream_end(stream);
    if (st != ITB_STATUS_OK) {
        return make_error(env, st);
    }
    return enif_make_atom(env, "ok");
}

/* stream_read_nif(Stream, MaxBytes) -> {ok, Data, Finished} | {error, _} */
static ERL_NIF_TERM stream_read_nif(ErlNifEnv *env, int argc,
                                    const ERL_NIF_TERM argv[])
{
    (void)argc;
    stream_res *s = NULL;
    unsigned long max_bytes = 0;
    if (!get_stream(env, argv[0], &s) ||
        !enif_get_ulong(env, argv[1], &max_bytes) || max_bytes == 0) {
        return enif_make_badarg(env);
    }
    itb_stream *stream = stream_ptr(s);
    if (stream == NULL) {
        return make_error_msg(env, ITB_STATUS_BAD_HANDLE, FREED_STREAM_MSG);
    }
    ErlNifBinary bin;
    if (!enif_alloc_binary(max_bytes, &bin)) {
        return make_error_msg(env, ITB_STATUS_INTERNAL,
                              "binary allocation failed");
    }
    size_t n = 0;
    int finished = 0;
    itb_status st = itb_stream_read(stream, bin.data, bin.size, &n, &finished);
    if (st != ITB_STATUS_OK) {
        enif_release_binary(&bin);
        return make_error(env, st);
    }
    if (n < bin.size && !enif_realloc_binary(&bin, n)) {
        enif_release_binary(&bin);
        return make_error_msg(env, ITB_STATUS_INTERNAL,
                              "binary shrink failed");
    }
    return enif_make_tuple3(env, enif_make_atom(env, "ok"),
                            enif_make_binary(env, &bin),
                            enif_make_atom(env, finished ? "true" : "false"));
}

/* stream_free_nif(Stream) -> ok  (cancels a mid-flight session) */
static ERL_NIF_TERM stream_free_nif(ErlNifEnv *env, int argc,
                                    const ERL_NIF_TERM argv[])
{
    (void)argc;
    stream_res *s = NULL;
    if (!get_stream(env, argv[0], &s)) {
        return enif_make_badarg(env);
    }
    itb_stream *stream =
        __atomic_exchange_n(&s->stream, NULL, __ATOMIC_ACQ_REL);
    itb_stream_free(stream); /* NULL-safe */
    pipeline_res *parent =
        __atomic_exchange_n(&s->parent, NULL, __ATOMIC_ACQ_REL);
    if (parent != NULL) {
        enif_release_resource(parent);
    }
    return enif_make_atom(env, "ok");
}

/* ------------------------------------------------------------------ */
/* Profile registration + runtime + diagnostics                        */
/* ------------------------------------------------------------------ */

/* register_profile_nif(NameBin, OptsPairs) -> ok | {error, _} */
static ERL_NIF_TERM register_profile_nif(ErlNifEnv *env, int argc,
                                         const ERL_NIF_TERM argv[])
{
    (void)argc;
    char *name = term_to_cstr(env, argv[0]);
    if (name == NULL) {
        return enif_make_badarg(env);
    }
    itb_opts *opts = NULL;
    int rc = opts_from_list(env, argv[1], &opts);
    if (rc <= 0) {
        enif_free(name);
        return rc == 0 ? enif_make_badarg(env)
                       : make_error_msg(env, ITB_STATUS_INTERNAL,
                                        "opts allocation failed");
    }
    itb_status st = itb_register_profile(name, opts);
    enif_free(name);
    itb_opts_free(opts);
    if (st != ITB_STATUS_OK) {
        return make_error(env, st);
    }
    return enif_make_atom(env, "ok");
}

/* version_nif() -> {ok, VersionBin} | {error, _} */
static ERL_NIF_TERM version_nif(ErlNifEnv *env, int argc,
                                const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    const char *v = itb_version();
    if (v == NULL) {
        return make_error_msg(env, ITB_STATUS_INTERNAL,
                              "libitb version unavailable");
    }
    return make_ok(env, make_bin(env, v, strlen(v)));
}

/* hash_count_nif() -> integer() */
static ERL_NIF_TERM hash_count_nif(ErlNifEnv *env, int argc,
                                   const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    return enif_make_ulong(env, (unsigned long)itb_hash_count());
}

/* hash_name_nif(Index) -> NameBin (badarg out of range) */
static ERL_NIF_TERM hash_name_nif(ErlNifEnv *env, int argc,
                                  const ERL_NIF_TERM argv[])
{
    (void)argc;
    unsigned long index = 0;
    if (!enif_get_ulong(env, argv[0], &index)) {
        return enif_make_badarg(env);
    }
    const char *name = itb_hash_name(index);
    if (name == NULL) {
        return enif_make_badarg(env);
    }
    return make_bin(env, name, strlen(name));
}

/* hash_width_nif(Index) -> integer() (0 out of range) */
static ERL_NIF_TERM hash_width_nif(ErlNifEnv *env, int argc,
                                   const ERL_NIF_TERM argv[])
{
    (void)argc;
    unsigned long index = 0;
    if (!enif_get_ulong(env, argv[0], &index)) {
        return enif_make_badarg(env);
    }
    return enif_make_int(env, itb_hash_width(index));
}

/* last_error_nif() -> DetailBin */
static ERL_NIF_TERM last_error_nif(ErlNifEnv *env, int argc,
                                   const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    const char *diag = itb_last_error();
    return make_bin(env, diag, strlen(diag));
}

/* set_memory_limit_nif(Bytes) -> PreviousBytes */
static ERL_NIF_TERM set_memory_limit_nif(ErlNifEnv *env, int argc,
                                         const ERL_NIF_TERM argv[])
{
    (void)argc;
    ErlNifSInt64 bytes = 0;
    if (!enif_get_int64(env, argv[0], &bytes)) {
        return enif_make_badarg(env);
    }
    return enif_make_int64(env, itb_set_memory_limit(bytes));
}

/* set_gc_percent_nif(Pct) -> PreviousPct */
static ERL_NIF_TERM set_gc_percent_nif(ErlNifEnv *env, int argc,
                                       const ERL_NIF_TERM argv[])
{
    (void)argc;
    int pct = 0;
    if (!enif_get_int(env, argv[0], &pct)) {
        return enif_make_badarg(env);
    }
    return enif_make_int(env, itb_set_gc_percent(pct));
}

/* ------------------------------------------------------------------ */
/* Module registration                                                 */
/* ------------------------------------------------------------------ */

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    (void)priv_data;
    (void)load_info;
    g_pipeline_rt = enif_open_resource_type(
        env, NULL, "itb_pipeline", pipeline_dtor,
        ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    g_stream_rt = enif_open_resource_type(
        env, NULL, "itb_stream", stream_dtor,
        ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    return g_pipeline_rt != NULL && g_stream_rt != NULL ? 0 : -1;
}

static ErlNifFunc nif_funcs[] = {
    {"init_nif", 2, init_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"open_nif", 5, open_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"blob_nif", 1, blob_nif, 0},
    {"rekey_nif", 3, rekey_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"free_nif", 1, free_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"encrypt_message_nif", 2, encrypt_message_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"decrypt_message_nif", 2, decrypt_message_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"encrypt_stream_one_shot_nif", 2, encrypt_stream_one_shot_nif,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"decrypt_stream_one_shot_nif", 2, decrypt_stream_one_shot_nif,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"encrypt_stream_begin_nif", 1, encrypt_stream_begin_nif,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"decrypt_stream_begin_nif", 1, decrypt_stream_begin_nif,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"stream_write_nif", 2, stream_write_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"stream_end_nif", 1, stream_end_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"stream_read_nif", 2, stream_read_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"stream_free_nif", 1, stream_free_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"register_profile_nif", 2, register_profile_nif,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"version_nif", 0, version_nif, 0},
    {"hash_count_nif", 0, hash_count_nif, 0},
    {"hash_name_nif", 1, hash_name_nif, 0},
    {"hash_width_nif", 1, hash_width_nif, 0},
    {"last_error_nif", 0, last_error_nif, 0},
    {"set_memory_limit_nif", 1, set_memory_limit_nif,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"set_gc_percent_nif", 1, set_gc_percent_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

ERL_NIF_INIT(itb_nif, nif_funcs, load, NULL, NULL, NULL)
