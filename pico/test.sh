#!/bin/sh
# pico/test.sh - portable host vector test, then SDK-gated firmware build.
# Always safe: no device access, no PE, no vendor binary, no network.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p /tmp/opencode

# 1. Host vectors: the embedded sources are compiled with plain cc.
cc -std=c99 -O2 -Wall -Wextra -I"$root/pico" \
   -o /tmp/opencode/test_pico_host \
   "$root/pico/test_host.c" "$root/pico/inspector.c" \
   "$root/pico/tea_core.c" -lm
/tmp/opencode/test_pico_host

# 2. Firmware build only when the Pico SDK is actually available.
if [ -n "${PICO_SDK_PATH:-}" ] && [ -f "$PICO_SDK_PATH/pico_sdk_init.cmake" ]; then
    cmake -S "$root/pico" -B /tmp/opencode/pico-build \
        -DPICO_SDK_PATH="$PICO_SDK_PATH"
    cmake --build /tmp/opencode/pico-build
    echo "pico firmware build: OK (PICO_SDK_PATH=$PICO_SDK_PATH)"
else
    echo "SKIP pico firmware build: PICO_SDK_PATH unset or SDK missing"
    echo "     gate: install Pico SDK, set PICO_SDK_PATH, attach a board"
fi
