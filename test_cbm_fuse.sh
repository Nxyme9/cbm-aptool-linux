#!/bin/sh
# test_cbm_fuse.sh - gated FUSE3 mount test for cbm-fuse (Wave 5J).
#
# Gate order: fuse3 headers/pkg-config -> /dev/fuse -> real mount permission in
# a scratch dir under /tmp/opencode -> only then the artifact comparisons.
# A gate is not a failure: print "SKIP <reason>" and exit 0. No sudo, no device
# writes, no vendor PE; fixtures are synthetic files made with ./cbm-tool.
set -u

FUSE=${CBM_FUSE:-./cbm-fuse}
TOOL=${CBM_TOOL:-./cbm-tool}
EXPECT_HEATMAP=${CBM_FUSE_EXPECT_HEATMAP:-1}
OFFSET=4096
BODY_LEN=85687
CONTAINER_LEN=85688

passed=0
failed=0
PID=''
MNT=''
SCRATCH=''

TEST() { printf 'TEST: %s ... ' "$1"; }
PASS() { printf 'PASS\n'; passed=$((passed + 1)); }
FAIL_CASE() { printf 'FAIL: %s\n' "$1"; failed=$((failed + 1)); }
SKIP() { printf 'SKIP %s\n' "$1"; exit 0; }
DIE() { printf 'FAIL: %s\n' "$1"; exit 1; }

# shellcheck disable=SC2329  # invoked indirectly through the EXIT trap
cleanup() {
    if [ -n "$PID" ]; then
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
        PID=''
    fi
    if [ -n "$MNT" ] && [ -f "$MNT/layout.txt" ]; then
        fusermount3 -u "$MNT" >/dev/null 2>&1 || true
    fi
    if [ -n "$SCRATCH" ] && [ -d "$SCRATCH" ]; then
        rm -rf "$SCRATCH"
    fi
}
trap cleanup EXIT HUP INT TERM

wait_ready() {
    wr_dir=$1
    wr_pid=$2
    wr_i=0
    while [ "$wr_i" -lt 60 ]; do
        if [ -f "$wr_dir/layout.txt" ] &&
           head -c 1 "$wr_dir/layout.txt" >/dev/null 2>&1; then
            return 0
        fi
        kill -0 "$wr_pid" 2>/dev/null || return 1
        sleep 0.1
        wr_i=$((wr_i + 1))
    done
    return 1
}

assert_unmounted() {
    au_dir=$1
    au_i=0
    while [ -f "$au_dir/layout.txt" ] && [ "$au_i" -lt 30 ]; do
        sleep 0.1
        au_i=$((au_i + 1))
    done
    [ ! -f "$au_dir/layout.txt" ]
}

# ---- gate 1: toolchain and device node -----------------------------------
command -v pkg-config >/dev/null 2>&1 || SKIP 'pkg-config not installed'
pkg-config --exists fuse3 2>/dev/null || SKIP 'fuse3 pkg-config module missing'
hdr_ok=0
for hdr_dir in $(pkg-config --cflags-only-I fuse3 2>/dev/null | sed 's/^-I//'); do
    if [ -f "$hdr_dir/fuse3/fuse.h" ]; then hdr_ok=1; fi
done
if [ "$hdr_ok" -ne 1 ] && [ -f /usr/include/fuse3/fuse.h ]; then hdr_ok=1; fi
[ "$hdr_ok" -eq 1 ] || SKIP 'fuse3/fuse.h header missing'
[ -c /dev/fuse ] || SKIP '/dev/fuse not present'
if [ ! -r /dev/fuse ] || [ ! -w /dev/fuse ]; then
    SKIP '/dev/fuse not readable/writable by this user'
fi
command -v fusermount3 >/dev/null 2>&1 || SKIP 'fusermount3 not installed'
[ -x "$FUSE" ] || DIE "$FUSE not built (use the command in docs/fuse-view.md)"
[ -x "$TOOL" ] || DIE "$TOOL not built (run make)"

if ! mkdir -p /tmp/opencode 2>/dev/null; then
    SKIP '/tmp/opencode scratch root unavailable'
fi
SCRATCH=$(mktemp -d /tmp/opencode/cbm-fuse.XXXXXX) || \
    SKIP 'cannot create scratch dir under /tmp/opencode'

# Seed fixture for the permission probe: a valid, encrypted container made by
# cbm-tool itself (no device, no PE, no write-back).
SEED=$SCRATCH/seed.bin
PLAIN=$SCRATCH/plain.bin
dd if=/dev/zero of="$SEED" bs="$CONTAINER_LEN" count=1 status=none || \
    DIE 'cannot create seed container'
dd if=/dev/zero of="$PLAIN" bs="$BODY_LEN" count=1 status=none || \
    DIE 'cannot create plaintext fixture'
printf 'CBM-FUSE-GATE-STRING-0123456789' | \
    dd of="$PLAIN" bs=1 seek=1024 conv=notrunc status=none || \
    DIE 'cannot mark plaintext fixture'
"$TOOL" container "$SEED" --inject "$PLAIN" --output "$SCRATCH/container.bin" \
    >"$SCRATCH/seed-cli.out" 2>"$SCRATCH/seed-cli.err" || \
    DIE 'cbm-tool could not build the container fixture'

# ---- gate 2: real mount permission probe ---------------------------------
GATE_MNT=$SCRATCH/gate-mnt
mkdir "$GATE_MNT" || DIE 'cannot create gate mountpoint'
"$FUSE" "$SCRATCH/container.bin" "$GATE_MNT" -f -s \
    >"$SCRATCH/gate.log" 2>&1 &
GATE_PID=$!
if ! wait_ready "$GATE_MNT" "$GATE_PID"; then
    reason=$(grep -iE 'permission denied|operation not permitted|not authorized|device not found|no such device|not in fuse group|/dev/fuse' \
        "$SCRATCH/gate.log" 2>/dev/null | head -1)
    kill -TERM "$GATE_PID" 2>/dev/null || true
    wait "$GATE_PID" 2>/dev/null || true
    GATE_PID=''
    if [ -n "$reason" ]; then
        SKIP "FUSE mount not permitted ($reason)"
    fi
    printf 'FAIL: FUSE mount probe failed without a permission reason\n'
    cat "$SCRATCH/gate.log"
    exit 1
fi
kill -TERM "$GATE_PID" 2>/dev/null || true
wait "$GATE_PID" 2>/dev/null || true
GATE_PID=''
assert_unmounted "$GATE_MNT" || DIE 'gate mount did not unmount on SIGTERM'
printf 'GATE OK: fuse3 headers, /dev/fuse and mount permission verified\n'

# ---- fixture with a container at a non-zero offset -----------------------
IMAGE=$SCRATCH/image.bin
dd if=/dev/zero of="$IMAGE" bs="$OFFSET" count=1 status=none || \
    DIE 'cannot create image fixture'
dd if="$SCRATCH/container.bin" of="$IMAGE" bs="$OFFSET" seek=1 conv=notrunc \
    status=none || DIE 'cannot place container at offset'

MNT=$SCRATCH/mnt
mkdir "$MNT" || DIE 'cannot create test mountpoint'
"$FUSE" "$IMAGE" "$MNT" -f -s --container-offset "$OFFSET" --window-gib 26 \
    >"$SCRATCH/fuse.log" 2>&1 &
PID=$!
if ! wait_ready "$MNT" "$PID"; then
    printf 'FAIL: main FUSE mount did not become ready\n'
    cat "$SCRATCH/fuse.log"
    exit 1
fi

expected_list=$SCRATCH/expected.list
got_list=$SCRATCH/got.list
{
    printf '%s\n' layout.txt container.bin container.plain strings.txt \
        entropy.txt report.json
    if [ "$EXPECT_HEATMAP" = 1 ]; then printf '%s\n' heatmap.png; fi
} | LC_ALL=C sort > "$expected_list"
find "$MNT" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort > "$got_list"
TEST 'readdir lists exactly the documented virtual files'
if diff -u "$expected_list" "$got_list" > "$SCRATCH/list.diff" 2>&1; then
    PASS
else
    FAIL_CASE 'virtual file list differs'
    cat "$SCRATCH/list.diff"
fi

TEST 'container.bin equals the raw container bytes'
dd if="$IMAGE" bs=1 skip="$OFFSET" count="$CONTAINER_LEN" status=none \
    > "$SCRATCH/container.expected" 2>/dev/null
if cmp -s "$MNT/container.bin" "$SCRATCH/container.expected"; then PASS
else FAIL_CASE 'container.bin bytes differ'; fi

TEST 'container.plain equals --dump-plain output'
"$TOOL" container "$IMAGE" --offset "$OFFSET" \
    --dump-plain "$SCRATCH/plain.expected" >"$SCRATCH/cli-container.out" \
    2>"$SCRATCH/cli-container.err"
if cmp -s "$MNT/container.plain" "$SCRATCH/plain.expected"; then PASS
else FAIL_CASE 'container.plain differs from CLI dump'; fi

TEST 'strings.txt equals the CLI strings section'
awk '/^\[strings \(minimum length 4\)\]$/ {p=1; next} \
     /^\[known tokens\]$/ {p=0} p' "$SCRATCH/cli-container.out" | \
    sed '${/^$/d;}' > "$SCRATCH/strings.expected"
if cmp -s "$MNT/strings.txt" "$SCRATCH/strings.expected"; then PASS
else FAIL_CASE 'strings.txt differs from CLI section'; fi

TEST 'entropy.txt header equals container --json entropy_body'
"$TOOL" container "$IMAGE" --offset "$OFFSET" --json \
    > "$SCRATCH/container.json" 2>"$SCRATCH/container-json.err"
python3 - "$SCRATCH/container.json" "$SCRATCH/entropy.first" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as f:
    doc = json.load(f)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write("entropy_body %s\n" % doc["entropy_body"])
PY
head -n 1 "$MNT/entropy.txt" > "$SCRATCH/entropy.head"
if cmp -s "$SCRATCH/entropy.first" "$SCRATCH/entropy.head"; then PASS
else FAIL_CASE 'entropy_body header differs'; fi

TEST 'entropy.txt profile rows match the documented shape and count'
rows=$(( (BODY_LEN + 63) / 64 ))
tail -n +2 "$MNT/entropy.txt" > "$SCRATCH/entropy.profile"
if awk -v want="$rows" '
    NF == 4 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ &&
    $3 ~ /^[0-9]+\.[0-9][0-9][0-9][0-9][0-9][0-9]$/ &&
    ($4 == "constant" || $4 == "string" || $4 == "opaque") { n++ }
    END { exit (n == want ? 0 : 1) }
' "$SCRATCH/entropy.profile"; then PASS
else FAIL_CASE 'entropy profile rows are not the expected 64-byte profile'; fi

TEST 'layout.txt equals doctor CLI report'
"$TOOL" doctor "$IMAGE" --window-gib 26 > "$SCRATCH/doctor.expected" \
    2>"$SCRATCH/doctor.err"
if cmp -s "$MNT/layout.txt" "$SCRATCH/doctor.expected"; then PASS
else FAIL_CASE 'layout.txt differs from doctor output'; fi

TEST 'report.json agrees with bare --json CLI documents'
"$TOOL" doctor "$IMAGE" --window-gib 26 --json > "$SCRATCH/doctor.json" \
    2>"$SCRATCH/doctor-json.err"
"$TOOL" heatmap "$IMAGE" --json > "$SCRATCH/heatmap.json" \
    2>"$SCRATCH/heatmap-json.err"
if python3 - "$MNT/report.json" "$SCRATCH/container.json" \
    "$SCRATCH/doctor.json" "$SCRATCH/heatmap.json" "$EXPECT_HEATMAP" <<'PY'
import json
import sys

rep_path, cont_path, doc_path, heat_path, expect_heatmap = sys.argv[1:]

def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

rep = load(rep_path)
cont = load(cont_path)
doc = load(doc_path)
heat = load(heat_path)
assert rep["schema"] == "cbm/1" and rep["command"] == "fuse"
assert rep["status"] == "ok"
for key in ("header_byte", "encrypted", "body_len", "entropy_body", "roundtrip_ok"):
    assert rep["container"][key] == cont[key], (key, rep["container"][key], cont[key])
for key in ("mbr_valid", "partitions", "repair_performed", "dry_run"):
    assert rep["doctor"][key] == doc[key], (key, rep["doctor"][key], doc[key])
assert rep["doctor"]["window_gib"] == 26
for key in ("block_bytes", "samples", "width", "height"):
    assert rep["heatmap"][key] == heat[key], (key, rep["heatmap"][key], heat[key])
names = [entry["name"] for entry in rep["files"]]
want = ["layout.txt", "container.bin", "container.plain", "strings.txt",
        "entropy.txt", "report.json"]
if expect_heatmap == "1":
    want.append("heatmap.png")
assert names == want, (names, want)
PY
then
    PASS
else
    FAIL_CASE 'report.json fields differ from CLI JSON'
fi

if [ "$EXPECT_HEATMAP" = 1 ]; then
    TEST 'heatmap.png equals the 5F heatmap CLI PNG'
    "$TOOL" heatmap "$IMAGE" --out "$SCRATCH/heatmap.expected.png" \
        >"$SCRATCH/heatmap-cli.out" 2>"$SCRATCH/heatmap-cli.err"
    if cmp -s "$MNT/heatmap.png" "$SCRATCH/heatmap.expected.png"; then PASS
    else FAIL_CASE 'heatmap.png bytes differ from CLI output'; fi
fi

TEST 'write to an existing virtual file is refused'
if printf 'x' 2>"$SCRATCH/write.err" > "$MNT/layout.txt"; then
    FAIL_CASE 'write unexpectedly succeeded'
elif grep -qE 'Read-only file system|Permission denied' "$SCRATCH/write.err"; then
    PASS
else
    FAIL_CASE 'write refused without EROFS/EACCES'
fi

TEST 'creation of a new virtual file is refused'
if printf '' 2>"$SCRATCH/create.err" > "$MNT/new-file.txt"; then
    FAIL_CASE 'create unexpectedly succeeded'
elif grep -qE 'Read-only file system|Permission denied|Function not implemented' "$SCRATCH/create.err"; then
    PASS
else
    FAIL_CASE 'create refused without EROFS/EACCES'
fi

TEST 'no write callback is registered in cbm-fuse.c'
if grep -nE '\.[[:space:]]*(write|create|unlink|rename|chmod|truncate|setattr)[[:space:]]*=' \
        cbm-fuse.c > "$SCRATCH/callbacks.txt" 2>/dev/null; then
    FAIL_CASE 'a mutating FUSE callback is registered'
    cat "$SCRATCH/callbacks.txt"
else
    PASS
fi

TEST 'SIGTERM unmounts cleanly'
kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=''
if assert_unmounted "$MNT"; then PASS
else FAIL_CASE 'mount still visible after SIGTERM'; fi

TEST 'SIGINT unmounts cleanly'
"$FUSE" "$IMAGE" "$MNT" -f -s --container-offset "$OFFSET" \
    >"$SCRATCH/fuse-int.log" 2>&1 &
PID=$!
if wait_ready "$MNT" "$PID"; then
    kill -INT "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=''
    if assert_unmounted "$MNT"; then PASS
    else FAIL_CASE 'mount still visible after SIGINT'; fi
else
    FAIL_CASE 'second mount did not become ready'
    cat "$SCRATCH/fuse-int.log"
fi

printf '\nResults: %d passed, %d failed, 0 skipped\n' "$passed" "$failed"
printf 'Scratch: %s\n' "$SCRATCH"
if [ "$failed" -ne 0 ]; then exit 1; fi
exit 0
