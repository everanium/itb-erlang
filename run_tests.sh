#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Erlang binding. Builds
# libitb.so + the C binding archive + the OTP application via
# build.sh, then invokes `rebar3 eunit`. Forwards any positional
# arguments through to rebar3 (e.g. one module via
# `--module=itb_smoke_tests`).
#
# Usage:
#   ./run_tests.sh                              # full suite
#   ./run_tests.sh --module=itb_smoke_tests     # one module

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

exec rebar3 eunit "$@"
