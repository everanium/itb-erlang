## ITB Erlang Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the ITB C binding's Triple Pipeline surface
(`bindings/c`) via NIF. The NIF shim (`c_src/libitb3_nif.c`) **links the
C binding's static archive (`libitb3_c.a`) at compile time** plus
`libitb3.so` (`-litb3` with an embedded RPATH) — no runtime symbol
loading. Every hash-name / MAC-name / cipher-name / profile-name is
an opaque string passed through to Go for validation; the binding
carries no ITB construction logic. The public surface is one `itb3`
module (`init` / `load` / `load_f` / `save` / `save_f` / `rekey` /
`max_workers` / `free`, Single Message encrypt / decrypt, incremental
stream sessions with `stream_write` / `stream_end` / `stream_read`),
the profile catalogue (`inspect` / `register` / `lookup` /
`profiles`), and the Go runtime knobs. Handles are opaque NIF resources; the cipher entries run on
dirty CPU schedulers so multi-megabyte calls never stall the regular
Erlang schedulers. This is also the primary BEAM backend: Elixir /
Gleam / LFE bindings call the same `itb3` module over native BEAM
interop.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make erlang rebar3
```

Generic Linux: a Go toolchain, a C11 compiler, GNU make, Erlang/OTP
27+, and rebar3. macOS: the same via Homebrew; libitb3 builds as
`libitb3.dylib`.

## Build the shared library

The convenience driver builds `libitb3.so`, the C binding's static
archive, and the OTP application (the NIF shim compiles through the
rebar3 pre-hook) in one step:

```bash
./bindings/erlang/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared
make -C bindings/c build/libitb3_c.a
cd bindings/erlang && rebar3 compile
```

## Add to an Erlang project

The binding is a standard OTP application. Add the directory as a
checkout / path dependency in `rebar.config`:

```erlang
{deps, [{libitb3, {path, "/path/to/itb/bindings/erlang"}}]}.
```

The compiled NIF (`priv/libitb3_nif.so`) resolves `libitb3.so` through its
embedded RPATH into the repo `dist/` directory, so no
`LD_LIBRARY_PATH` is needed at runtime.

## Usage example

```erlang
{ok, Sender} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
{ok, Blob} = itb3:save(Sender),
{ok, Receiver} = itb3:load(Blob),

{ok, Wire} = itb3:encrypt_message(Sender, <<"any text or binary data">>),
{ok, Plain} = itb3:decrypt_message(Receiver, Wire),

ok = itb3:free(Receiver),
ok = itb3:free(Sender).

%% File-backed equivalent (persist across processes):
%% {ok, Sender} = itb3:init(<<"singlemsg-triple-mac-v1">>, #{}),
%% ok = itb3:save_f(Sender, "session.blob"),
%% {ok, Receiver} = itb3:load_f("session.blob").
```

Opts override the profile default at `itb3:init` (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette, worker
cap) as a map or proplist. The resolved shape is written into the
blob, so the receiver loads it with no opts of its own:

```erlang
Opts = #{chunkSize => 65536, withWrapper => false},
{ok, Sender} = itb3:init(<<"singlemsg-triple-mac-v1">>, Opts),
{ok, Blob} = itb3:save(Sender),
{ok, Receiver} = itb3:load(Blob).
```

`itb3:rekey/3` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the refreshed blob; the receiver picks up the
new masters through a fresh `itb3:load/1`:

```erlang
{ok, Blob2} = itb3:rekey(Sender, binary:copy(<<16#11>>, 32), binary:copy(<<16#22>>, 32)),
{ok, Receiver2} = itb3:load(Blob2).
```

## Persisting sessions

The blob is self-describing: it carries the profile record (mode,
width, primitives, key bits, MAC, layer switches) alongside the key
material, so a session reopens from the blob alone.

```erlang
{ok, Blob} = itb3:save(Sender),                  %% current blob (binary)
ok = itb3:save_f(Sender, "session.blob"),        %% written by libitb3, mode 0600
{ok, Receiver} = itb3:load(Blob),                %% reopen from bytes
{ok, Receiver} = itb3:load_f("session.blob"),    %% reopen from file
{ok, Receiver} = itb3:load(Blob, Perm, Wrap),    %% override the masters
{ok, Record} = itb3:inspect(Blob).               %% profile record, no Pipeline
```

`itb3:inspect/1` returns the record as a binary-keyed map decoded with
the OTP `json` module; absent keys are optional fields at their zero
value.

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `itb3:load/1` such a blob
through this binding returns `{error, {recipe_primitive_unknown, _}}`.

## Profile registry

```erlang
itb3:profiles(),                                 %% sorted [binary()]
itb3:lookup(<<"singlemsg-triple-mac-v1">>),      %% {ok, Record}; unknown -> unknown_profile
ok = itb3:register(<<"my-profile">>, #{
    <<"mode">> => <<"singlemsg-nomac">>,
    <<"width">> => 256,
    <<"hashes">> => [<<"blake3">>, <<"blake2s">>, <<"areion256">>, <<"blake2b256">>,
                     <<"chacha20">>, <<"blake3">>, <<"blake2s">>, <<"areion256">>],
    <<"keybits">> => 1024,
    <<"parallax">> => false,
    <<"wrapper">> => false}),
{ok, Sender} = itb3:init(<<"my-profile">>, #{}).
```

`itb3:register/2` takes the same record shape `inspect` / `lookup`
return (a map, or an already-encoded JSON binary); a `name` key
inside it, if present, must be empty or equal to the name argument.
Every rule — name pattern, reserved prefixes, field constraints,
primitive names — is enforced by libitb3; a duplicate name returns
`{error, {profile_exists, _}}`.

## Runtime tuning

`itb3:max_workers/2` sets the worker cap on a live Pipeline (`N =< 0`
selects auto, values above 256 are clamped). The cap is per-machine
tuning and is never written to the blob, so the receiver may pick
its own worker cap after `itb3:load/1`. The `maxWorkers` opts key
sets the same cap at `itb3:init/2`.

`itb3:encrypt_stream_one_shot/2` / `itb3:decrypt_stream_one_shot/2` put
a whole in-memory payload through the stream chain in a single call:

```erlang
{ok, Wire} = itb3:encrypt_stream_one_shot(Sender, Plain),
{ok, Plain} = itb3:decrypt_stream_one_shot(Receiver, Wire).
```

For bounded-memory streaming, the explicit `itb3:encrypt_stream/1` /
`itb3:decrypt_stream/1` sessions expose `itb3:stream_write/2` /
`itb3:stream_end/1` / `itb3:stream_read/2` for caller-driven loops:

```erlang
{ok, Stream} = itb3:encrypt_stream(Sender),
ok = itb3:stream_write(Stream, Chunk1),
ok = itb3:stream_write(Stream, Chunk2),
ok = itb3:stream_end(Stream),
%% Drain until {ok, Data, true}:
{ok, WirePiece, Finished} = itb3:stream_read(Stream, 1 bsl 20),
ok = itb3:stream_free(Stream).
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as
`{error, {Status, Detail}}` — `Status` an atom mirroring the C
binding's status table (e.g. `mac_failure`, `bad_input`,
`profile_exists`), `Detail` the Go-side diagnostic binary. Opts are a
map or proplist (`#{keyBits => 1024, nonceBits => 512}`) rendered
into the URL-query string libitb3 consumes.

Handle lifetime is garbage-collected: dropping every term reference
releases the Go-side state through the NIF resource destructor, and
`itb3:free/1` / `itb3:stream_free/1` release eagerly (both idempotent).
A stream session pins its parent pipeline resource, so the pipeline
is never collected under a live session.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb3 load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive GC
the Go scratch heap grows unboundedly under allocation churn:

```erlang
itb3:set_memory_limit(4 bsl 30), %% 4 GiB soft cap
itb3:set_gc_percent(100).         %% balanced GC
```

## Testing

```bash
./bindings/erlang/run_tests.sh
```

The harness builds `libitb3.so` + the C archive + the application,
then invokes `rebar3 eunit`. Positional arguments are forwarded to
rebar3 (e.g. `./run_tests.sh --module=itb_smoke_tests`). The suite
covers Single Message round trips per shipped profile, stream pumps,
incremental sessions with pathological batch sizes, tampered-wire
failure stickiness, mid-flight cancellation, garbage-collection
backstop release, rekey, save / load persistence (in memory and
through a file), inspect / lookup / profiles, the worker cap,
profile registration, and error mapping —
surface parity checks; the deep suite lives in Go under the shipped
tree.

## Benchmarking

```bash
./bindings/erlang/run_bench.sh
```

Micro-benches: `message` (encrypt_message) and `stream_pump`
(incremental encrypt session) throughput at 1 MiB / 16 MiB / 64 MiB,
reported as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=4GiB` + `ITB_GOGC=100` defaults (respecting caller
overrides) and the bench modules apply the same caps
programmatically. `./run_bench.sh message` / `./run_bench.sh stream`
runs one shape.

## itb3 CLI

The Go core ships an openssl-style CLI utility
[`itb3`](https://github.com/everanium/itb/tree/main/cmd/itb3/) that generates session blobs on disk
(`itb3 genblob <mode> <hash> -o blob.json`); this binding reopens
such blobs via `itb3:load_f/1`. `itb3` also encrypts / decrypts
payloads directly on disk (`-i` / `-o`) or through stdin / stdout,
rotates outer masters, and inspects stored blobs. See
[`cmd/itb3/README.md`](https://github.com/everanium/itb/blob/main/cmd/itb3/README.md) for the full
subcommand reference.

## eitb utility

An escript under `bindings/erlang/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests (build the binding first):

```bash
cd bindings/erlang
./eitb/eitb.erl version
./eitb/eitb.erl profiles
./eitb/eitb.erl inspect <blob-hex>
./eitb/eitb.erl encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./eitb/eitb.erl decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The `Detail` text in an error tuple comes from a process-global
  last-write-wins store on the Go side; under concurrent use it may
  belong to a different call. The status atom is always attributable.
- `itb3:rekey/3` must not run concurrently with cipher calls or open
  stream sessions on the same Pipeline.
- Single-owner discipline per handle: do not call `itb3:free/1` /
  `itb3:stream_free/1` while another process is mid-call on the same
  handle — free from the owning process, or drop every reference and
  let the resource destructor release.
- After `itb3:stream_end/1`, an empty-spool `itb3:stream_read/2` blocks
  (on a dirty scheduler) until the terminal bytes arrive or the
  session errors; the regular schedulers are unaffected.

## License

Apache-2.0 — see [LICENSE](https://github.com/everanium/itb/blob/main/LICENSE).
