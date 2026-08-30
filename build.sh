#!/usr/bin/env bash
#
# build.sh -- one-step build for the Erlang binding: libitb.so + the C
# binding's static archive + the OTP application (NIF shim compiled by
# the rebar3 compile pre-hook). Prerequisites (Go, a C11 compiler, GNU
# make, Erlang/OTP 27+, rebar3) must be installed separately; see
# README.md "Prerequisites".
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#   CC=clang ./build.sh    # override the C compiler

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

cd "$REPO_ROOT"
echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared

echo "==> building C binding static archive (make, CC=${CC:-cc})"
make -C bindings/c build/libitb_c.a

cd "$SCRIPT_DIR"
echo "==> rebar3 compile (NIF shim via c_src pre-hook)"
rebar3 compile

echo "==> ready: ./run_tests.sh"
