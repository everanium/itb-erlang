#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Erlang binding:
# compiles the utility's modules (libitb3.so, the NIF shim and the OTP
# application are assumed built by build.sh) and execs it with every
# argument passed through.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

EBIN="$PWD/_build/default/lib/libitb3/ebin"
if [ ! -f "$EBIN/itb3.beam" ]; then
    echo "run_loop.sh: binding not compiled, run ./build.sh first: $EBIN" >&2
    exit 1
fi

erlc -I loop -o loop +warnings_as_errors loop/*.erl

exec ./loop/loop "$@"
