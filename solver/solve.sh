#!/bin/sh
# Wave 5K CTF solver: find the planted container with cbm-tool scan, decrypt
# each carved candidate with cbm-tool container --dump-plain, print the flag.
# Read-only on the image; all writes go to a scratch dir under /tmp/opencode.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TOOL="$ROOT/cbm-tool"

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s <image>\n' "$0" >&2
    exit 2
fi
image=$1
[ -f "$image" ] || { printf 'Error: image not found: %s\n' "$image" >&2; exit 2; }
[ -x "$TOOL" ] || { printf 'Error: build cbm-tool first (make)\n' >&2; exit 2; }

scratch=$(mktemp -d /tmp/opencode/cbm-ctf-solve.XXXXXX)
trap 'rm -rf "$scratch"' EXIT INT TERM
carves="$scratch/carves"
mkdir -p "$carves"

"$TOOL" scan "$image" --carve "$carves" --json "$scratch/report.json" \
    > "$scratch/scan.log" 2>&1 || {
    printf 'Error: scan failed:\n' >&2
    cat "$scratch/scan.log" >&2
    exit 1
}

flag=''
for carved in "$carves"/hit-*.cbm; do
    [ -f "$carved" ] || continue
    plain="$scratch/$(basename "$carved" .cbm).plain"
    if ! "$TOOL" container "$carved" --dump-plain "$plain" \
            > "$scratch/container.log" 2>&1; then
        continue
    fi
    candidate=$(grep -ao 'CBMCTF{[^}]*}' "$plain" 2>/dev/null | head -n 1 || true)
    if [ -n "$candidate" ]; then
        flag=$candidate
        break
    fi
done

if [ -z "$flag" ]; then
    printf 'Error: no flag found in carved candidates (see %s)\n' "$scratch/report.json" >&2
    exit 1
fi
printf '%s\n' "$flag"
