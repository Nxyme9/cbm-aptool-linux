#!/bin/sh
# Wave 5K CTF end-to-end test: generate a fresh synthetic image, solve it,
# and check the exact planted flag. No device, no vendor binary, no committed
# image blob. Its summary line is outside the frozen `Results:` sums.
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOL="$ROOT/cbm-tool"
FLAG='CBMCTF{tea_cbc_clean_room_2026}'

passed=0
failed=0
check() {
    if [ "$2" -eq 0 ]; then
        printf 'TEST: %s ... PASS\n' "$1"
        passed=$((passed + 1))
    else
        printf 'TEST: %s ... FAIL\n' "$1"
        failed=$((failed + 1))
    fi
}

scratch=$(mktemp -d /tmp/opencode/cbm-ctf-test.XXXXXX) || exit 1
trap 'rm -rf "$scratch"' EXIT INT TERM
image="$scratch/disk.img"

if [ ! -x "$TOOL" ]; then
    printf 'TEST: cbm-tool is built ... FAIL\n'
    printf '\nCTF challenge: %d passed, %d failed\n' "$passed" "$((failed + 1))"
    exit 1
fi
check 'cbm-tool is built' 0

python3 "$ROOT/challenge/generate.py" --out "$image" --flag "$FLAG" \
    > "$scratch/generate.log" 2>&1
check 'generator exits 0 on a fresh image' $?

size=$(wc -c < "$image" 2>/dev/null || printf '0')
check 'generator writes a 64 MiB sparse image' \
    "$([ "$size" -eq 67108864 ] && printf '0' || printf '1')"

sig=$(dd if="$image" bs=1 skip=510 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')
check 'image has the DJ MBR 0x55aa signature' \
    "$([ "$sig" = '55aa' ] && printf '0' || printf '1')"

got=$(sh "$ROOT/solver/solve.sh" "$image" 2> "$scratch/solve.err")
solve_rc=$?
check 'solver exits 0 on a freshly generated image' "$solve_rc"
check 'solver recovers the exact planted flag' \
    "$([ "$got" = "$FLAG" ] && printf '0' || printf '1')"

printf '\nCTF challenge: %d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
