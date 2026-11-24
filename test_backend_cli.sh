#!/bin/sh
# test_backend_cli.sh - CLI-level crypto backend selection coverage.
# Builds on cbm-tool: no device access, no writes to tracked files.
# All fixtures and captured output live in a fresh /tmp/opencode directory.
set -u

TOOL=${CBM_TOOL:-./cbm-tool}
PE_PATH=${CBM_PE_PATH:-/tmp/opencode/ap.exe}
NATIVE_LINE='Crypto backend: native (clean-room)'
PE_LINE='Crypto backend: PE harness (cross-check)'
CONTAINER_OK='Container mode: crypto roundtrip OK'

SCRATCH=$(mktemp -d /tmp/opencode/cbm-cli-backend.XXXXXX) || {
    printf 'FAIL: cannot create scratch directory\n'
    exit 1
}
FIXTURE=$SCRATCH/container.bin
MISSING_PE=$SCRATCH/no-such-ap.exe

passed=0
failed=0
skipped=0

TEST() { printf 'TEST: %s ... ' "$1"; }
PASS() { printf 'PASS\n'; passed=$((passed + 1)); }
FAIL_CASE() { printf 'FAIL: %s\n' "$1"; failed=$((failed + 1)); }
SKIP_CASE() { printf 'SKIP (%s)\n' "$1"; skipped=$((skipped + 1)); }

# 85688-byte container: header byte 0x00 (unencrypted), zeros elsewhere.
dd if=/dev/zero of="$FIXTURE" bs=85688 count=1 status=none || {
    printf 'FAIL: cannot create 85688-byte container fixture\n'
    exit 1
}

# $1 label, $2 PE path for this run, $3 expected backend line,
# $4 extra required output line, $5+ tool arguments.
run_case() {
    case_label=$1
    case_pe=$2
    case_expected=$3
    case_extra=$4
    shift 4
    out="$SCRATCH/$case_label.out"
    TEST "$case_label"
    if ! CBM_PE_PATH="$case_pe" "$TOOL" "$@" >"$out" 2>&1; then
        FAIL_CASE 'nonzero exit'
        return
    fi
    if ! grep -Fqx "$case_expected" "$out"; then
        FAIL_CASE "missing exact line: $case_expected"
        return
    fi
    if [ "$case_expected" = "$NATIVE_LINE" ]; then
        case_other=$PE_LINE
    else
        case_other=$NATIVE_LINE
    fi
    if grep -Fqx "$case_other" "$out"; then
        FAIL_CASE 'printed the other backend line'
        return
    fi
    if [ -n "$case_extra" ] && ! grep -Fq "$case_extra" "$out"; then
        FAIL_CASE "missing: $case_extra"
        return
    fi
    if grep -Fq 'unknown container option' "$out"; then
        FAIL_CASE 'backend flag not stripped before container parser'
        return
    fi
    PASS
}

printf '=== CLI Backend Selection Tests ===\n'

# Native must succeed even with a deliberately absent PE path.
run_case native-selftest "$MISSING_PE" "$NATIVE_LINE" 'All systems operational.' --native-crypto
run_case container-native-flag "$MISSING_PE" "$NATIVE_LINE" "$CONTAINER_OK" container "$FIXTURE" --native-crypto

if [ ! -f "$PE_PATH" ]; then
    TEST pe-selftest
    SKIP_CASE "PE $PE_PATH not present"
    TEST container-pe-flag
    SKIP_CASE "PE $PE_PATH not present"
else
    run_case pe-selftest "$PE_PATH" "$PE_LINE" 'TEA roundtrip OK (64 bytes)' --pe-crypto
    # Flag after "container <path>": parse_backend_flags() must strip it
    # before container_mode() sees the option list.
    run_case container-pe-flag "$PE_PATH" "$PE_LINE" "$CONTAINER_OK" container "$FIXTURE" --pe-crypto
fi

printf '\nScratch fixtures: %s\n' "$SCRATCH"
printf 'Results: %d passed, %d failed, %d skipped\n' "$passed" "$failed" "$skipped"
[ "$failed" -eq 0 ]
