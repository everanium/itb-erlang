# ITB Erlang Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the ITB C binding's Triple Pipeline surface
(`bindings/c`) via NIF. The NIF shim (`c_src/itb_nif.c`) **links the
C binding's static archive (`libitb_c.a`) at compile time** plus
`libitb.so` (`-litb` with an embedded RPATH) — no runtime symbol
loading. Every hash-name / MAC-name / cipher-name / profile-name is
an opaque string passed through to Go for validation; the binding
carries no ITB construction logic. The public surface is one `itb`
module (`init` / `open` / `rekey` / `free`, Single Message encrypt /
decrypt, incremental stream sessions with `stream_write` /
`stream_end` / `stream_read`), `register_profile`, and the Go runtime
knobs. Handles are opaque NIF resources; the cipher entries run on
dirty CPU schedulers so multi-megabyte calls never stall the regular
Erlang schedulers. This is also the primary BEAM backend: Elixir /
Gleam / LFE bindings call the same `itb` module over native BEAM
interop.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make erlang rebar3
```

Generic Linux: a Go toolchain, a C11 compiler, GNU make, Erlang/OTP
27+, and rebar3. macOS: the same via Homebrew; libitb builds as
`libitb.dylib`.

## Build the shared library

The convenience driver builds `libitb.so`, the C binding's static
archive, and the OTP application (the NIF shim compiles through the
rebar3 pre-hook) in one step:

```bash
./bindings/erlang/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
make -C bindings/c build/libitb_c.a
cd bindings/erlang && rebar3 compile
```

## Add to an Erlang project

The binding is a standard OTP application. Add the directory as a
checkout / path dependency in `rebar.config`:

```erlang
{deps, [{itb, {path, "/path/to/itb/bindings/erlang"}}]}.
```

The compiled NIF (`priv/itb_nif.so`) resolves `libitb.so` through its
embedded RPATH into the repo `dist/` directory, so no
`LD_LIBRARY_PATH` is needed at runtime.

## Usage example

```erlang
{ok, Sender} = itb:init(<<"singlemsg-triple-mac-v1">>, #{}),
{ok, Blob} = itb:blob(Sender),
{ok, Receiver} = itb:open(<<"singlemsg-triple-mac-v1">>, Blob, #{}),

{ok, Wire} = itb:encrypt_message(Sender, <<"any text or binary data">>),
{ok, Plain} = itb:decrypt_message(Receiver, Wire),

ok = itb:free(Receiver),
ok = itb:free(Sender).
```

Opts override the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette) as a
map or proplist passed to `itb:init` / `itb:open`:

```erlang
Opts = #{chunkSize => 65536, withWrapper => false},
{ok, Sender} = itb:init(<<"singlemsg-triple-mac-v1">>, Opts),
{ok, Blob} = itb:blob(Sender),
{ok, Receiver} = itb:open(<<"singlemsg-triple-mac-v1">>, Blob, Opts).
```

`itb:rekey/3` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`itb:blob/1` handshake:

```erlang
ok = itb:rekey(Sender, binary:copy(<<16#11>>, 32), binary:copy(<<16#22>>, 32)),
{ok, Blob2} = itb:blob(Sender),
{ok, Receiver2} = itb:open(<<"singlemsg-triple-mac-v1">>, Blob2, #{}).
```

`itb:encrypt_stream_one_shot/2` / `itb:decrypt_stream_one_shot/2` put
a whole in-memory payload through the stream chain in a single call:

```erlang
{ok, Wire} = itb:encrypt_stream_one_shot(Sender, Plain),
{ok, Plain} = itb:decrypt_stream_one_shot(Receiver, Wire).
```

For bounded-memory streaming, the explicit `itb:encrypt_stream/1` /
`itb:decrypt_stream/1` sessions expose `itb:stream_write/2` /
`itb:stream_end/1` / `itb:stream_read/2` for caller-driven loops:

```erlang
{ok, Stream} = itb:encrypt_stream(Sender),
ok = itb:stream_write(Stream, Chunk1),
ok = itb:stream_write(Stream, Chunk2),
ok = itb:stream_end(Stream),
%% Drain until {ok, Data, true}:
{ok, WirePiece, Finished} = itb:stream_read(Stream, 1 bsl 20),
ok = itb:stream_free(Stream).
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as
`{error, {Status, Detail}}` — `Status` an atom mirroring the C
binding's status table (e.g. `mac_failure`, `bad_input`,
`profile_exists`), `Detail` the Go-side diagnostic binary. Opts are a
map or proplist (`#{keyBits => 1024, nonceBits => 512}`) rendered
into the URL-query string libitb consumes.

Handle lifetime is garbage-collected: dropping every term reference
releases the Go-side state through the NIF resource destructor, and
`itb:free/1` / `itb:stream_free/1` release eagerly (both idempotent).
A stream session pins its parent pipeline resource, so the pipeline
is never collected under a live session.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive GC
the Go scratch heap grows unboundedly under allocation churn:

```erlang
itb:set_memory_limit(512 bsl 20), %% 512 MiB soft cap
itb:set_gc_percent(20).           %% aggressive GC
```

## Testing

```bash
./bindings/erlang/run_tests.sh
```

The harness builds `libitb.so` + the C archive + the application,
then invokes `rebar3 eunit`. Positional arguments are forwarded to
rebar3 (e.g. `./run_tests.sh --module=itb_smoke_tests`). The suite
covers Single Message round trips per shipped profile, stream pumps,
incremental sessions with pathological batch sizes, tampered-wire
failure stickiness, mid-flight cancellation, garbage-collection
backstop release, rekey, profile registration, and error mapping —
surface parity checks; the deep suite lives in Go under the shipped
tree.

## Benchmarking

```bash
./bindings/erlang/run_bench.sh
```

Micro-benches: `message` (encrypt_message) and `stream_pump`
(incremental encrypt session) throughput at 1 MiB / 16 MiB / 64 MiB,
reported as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` defaults (respecting caller
overrides) and the bench modules apply the same caps
programmatically. `./run_bench.sh message` / `./run_bench.sh stream`
runs one shape.

## eitb utility

An escript under `bindings/erlang/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests (build the binding first):

```bash
cd bindings/erlang
./eitb/eitb.erl version
./eitb/eitb.erl hashes
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
- `itb:rekey/3` must not run concurrently with cipher calls or open
  stream sessions on the same Pipeline.
- Single-owner discipline per handle: do not call `itb:free/1` /
  `itb:stream_free/1` while another process is mid-call on the same
  handle — free from the owning process, or drop every reference and
  let the resource destructor release.
- After `itb:stream_end/1`, an empty-spool `itb:stream_read/2` blocks
  (on a dirty scheduler) until the terminal bytes arrive or the
  session errors; the regular schedulers are unaffected.
