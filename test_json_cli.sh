#!/bin/sh
# test_json_cli.sh - end-to-end checks for bare --json on every CLI mode.
# Synthetic fixtures only: no device, no PE, all output under /tmp/opencode.
set -u

TOOL=${CBM_TOOL:-./cbm-tool}
SCRATCH=$(mktemp -d /tmp/opencode/cbm-json-cli.XXXXXX) || {
    printf 'FAIL: cannot create scratch directory\n'
    exit 1
}
CONTAINER=$SCRATCH/container.bin
PLAIN_A=$SCRATCH/a.plain
PLAIN_B=$SCRATCH/b.plain
IMAGE=$SCRATCH/image.bin
DOCTOR_IMG=$SCRATCH/doctor.img
CORPUS=$SCRATCH/corpus
CDB_PE=$SCRATCH/cdb-export.pe
CDB_CAPTURE=$SCRATCH/cdb-capture.txt

passed=0
failed=0
TEST() { printf 'TEST: %s ... ' "$1"; }
PASS() { printf 'PASS\n'; passed=$((passed + 1)); }
FAIL_CASE() { printf 'FAIL: %s\n' "$1"; failed=$((failed + 1)); }

dd if=/dev/zero of="$CONTAINER" bs=85688 count=1 status=none || exit 1
dd if=/dev/zero of="$PLAIN_A" bs=85687 count=1 status=none || exit 1
cp "$PLAIN_A" "$PLAIN_B" || exit 1
printf 'Z' | dd of="$PLAIN_B" bs=1 seek=1000 conv=notrunc status=none || exit 1
dd if=/dev/zero of="$IMAGE" bs=1048576 count=2 status=none || exit 1
dd if=/dev/zero of="$DOCTOR_IMG" bs=512 count=1 status=none || exit 1
mkdir -p "$CORPUS" || exit 1

# Minimal PE32 with one export whose body is `ret 12`: no import table, no
# vendor code, and a valid stdcall callee for pe_call_void.
python3 - "$CDB_PE" <<'PY' || exit 1
import struct
import sys

buf = bytearray(0x400)

def p16(off, val):
    buf[off:off + 2] = struct.pack('<H', val)

def p32(off, val):
    buf[off:off + 4] = struct.pack('<I', val)

buf[0:2] = b'MZ'
p32(0x3c, 0x80)
buf[0x80:0x84] = b'PE\0\0'
p16(0x84, 0x14c)       # IMAGE_FILE_MACHINE_I386
p16(0x86, 1)           # one section
p16(0x94, 224)         # SizeOfOptionalHeader
p16(0x98, 0x10b)       # PE32 magic
p32(0x98 + 28, 0x400000)
p32(0x98 + 56, 0x140000)
p32(0x98 + 92, 16)     # NumberOfRvaAndSizes
p32(0x98 + 96, 0x1000) # export directory RVA
p32(0x98 + 100, 40)    # export directory size
buf[0x178:0x17d] = b'.text'
p32(0x180, 0x400)      # VirtualSize
p32(0x184, 0x1000)     # VirtualAddress
p32(0x188, 0x200)      # SizeOfRawData (0x200 + 0x200 = file length)
p32(0x18c, 0x200)      # PointerToRawData
p32(0x20c, 0x1060)     # export Name RVA
p32(0x210, 1)          # Base
p32(0x214, 1)          # NumberOfFunctions
p32(0x218, 1)          # NumberOfNames
p32(0x21c, 0x1040)     # AddressOfFunctions
p32(0x220, 0x1044)     # AddressOfNames
p32(0x224, 0x1048)     # AddressOfNameOrdinals
p32(0x240, 0x1050)     # EAT[0]
p32(0x244, 0x1054)     # ENT[0]
p16(0x248, 0)          # ordinal[0]
buf[0x250:0x253] = b'\xc2\x0c\x00'  # ret 12 (stdcall cleanup)
buf[0x254:0x25d] = b'MyExport\0'
buf[0x260:0x26e] = b'synthetic.dll\0'
with open(sys.argv[1], 'wb') as f:
    f.write(buf)
PY

# Validate one captured stdout document: exactly one JSON object, fixed prefix,
# required key set and (for arrays/objects) the published container types.
check_doc() {
    cd_file=$1
    cd_command=$2
    cd_keys=$3
    cd_status=$4
    python3 -c '
import json, sys
path, command, keys, status = sys.argv[1:5]
with open(path, "r", encoding="utf-8") as f:
    raw = f.read()
doc = json.loads(raw)
assert isinstance(doc, dict), type(doc)
assert doc["schema"] == "cbm/1", doc.get("schema")
assert doc["command"] == command, doc.get("command")
assert doc["status"] == status, doc.get("status")
required = set(keys.split(",")) | {"schema", "command", "status"}
missing = sorted(required - set(doc))
assert not missing, missing
for key in ("hits", "regions", "partitions"):
    if key in required:
        assert isinstance(doc[key], list), (key, type(doc[key]))
if "entropy" in required and command == "heatmap":
    assert isinstance(doc["entropy"], dict), type(doc["entropy"])
if status == "error":
    assert isinstance(doc["error"], str) and doc["error"], doc.get("error")
else:
    assert "error" not in doc, doc
' "$cd_file" "$cd_command" "$cd_keys" "$cd_status"
}

# $1 label, $2 expected rc, $3 command name, $4 required keys,
# $5 expected status, $6+ tool arguments (bare --json is appended).
run_case() {
    rc_label=$1
    rc_expected=$2
    rc_command=$3
    rc_keys=$4
    rc_status=$5
    shift 5
    rc_out=$SCRATCH/$rc_label.json
    rc_err=$SCRATCH/$rc_label.err
    TEST "$rc_label"
    "$TOOL" "$@" --json >"$rc_out" 2>"$rc_err"
    rc_got=$?
    if [ "$rc_got" -ne "$rc_expected" ]; then
        FAIL_CASE "exit $rc_got, expected $rc_expected"
        return
    fi
    if [ "$rc_status" = error ]; then
        if [ ! -s "$rc_err" ]; then
            FAIL_CASE 'no human error on stderr'
            return
        fi
    elif [ -s "$rc_err" ]; then
        FAIL_CASE 'unexpected stderr on success'
        return
    fi
    cd_log=$SCRATCH/$rc_label.python.log
    if ! check_doc "$rc_out" "$rc_command" "$rc_keys" "$rc_status" >"$cd_log" 2>&1; then
        FAIL_CASE "$(cat "$cd_log")"
        return
    fi
    PASS
}

printf '=== CLI JSON Contract Tests ===\n'

run_case container 0 container \
    'path,backend,header_byte,encrypted,body_len,entropy_body,roundtrip_ok' \
    ok container "$CONTAINER"
run_case diff 0 diff \
    'a,b,body_len_a,body_len_b,context,entropy_body_a,entropy_body_b,changed_ranges,changed_bytes' \
    ok diff "$PLAIN_A" "$PLAIN_B" --context 2
run_case fuzz 0 fuzz \
    'path,seed,rounds,mutations,out,corpus_verified' \
    ok fuzz "$CONTAINER" --mutate 2 --rounds 1 --seed 7 --out "$CORPUS"
run_case scan 0 scan \
    'path,start_lba,end_lba,candidates,all_hits,hits' \
    ok scan "$IMAGE" --all-hits
run_case heatmap 0 heatmap \
    'path,block_bytes,samples,width,height,entropy,regions' \
    ok heatmap "$IMAGE" --block 1 --width 16
run_case doctor 0 doctor \
    'path,window_gib,mbr_valid,partitions,repair_performed,dry_run' \
    ok doctor "$DOCTOR_IMG"
run_case cdb-capture 0 cdb-capture \
    'path,capture,export,called,events' \
    ok cdb-capture "$CDB_PE" --out "$CDB_CAPTURE" --export MyExport \
    --arg0 1 --arg1 2 --arg2 3

# Error paths keep their exit codes and still print a human message on stderr.
run_case container-error 1 container error \
    error container "$SCRATCH/missing.bin"
run_case diff-usage 2 diff error \
    error diff "$PLAIN_A"
run_case cdb-capture-usage 2 cdb-capture error \
    error cdb-capture --out "$SCRATCH/cdb-unused.txt"
run_case cdb-capture-missing-pe 2 cdb-capture error \
    error cdb-capture "$SCRATCH/no-such-cdb.pe" --out "$SCRATCH/cdb-unused.txt"
run_case cdb-capture-missing-export 1 cdb-capture error \
    error cdb-capture "$CDB_PE" --out "$SCRATCH/cdb-empty.txt" --export NoSuchExport

# A missing export still publishes the header: an empty capture is a result.
TEST cdb-capture-empty-header
if [ "$(head -n 1 "$SCRATCH/cdb-empty.txt")" = 'cbm-cdb-capture/1' ]; then
    PASS
else
    FAIL_CASE 'empty capture header not preserved'
fi

# scan/heatmap --json <path> sidecars stay byte-for-byte identical with and
# without an additional bare --json on the same command line.
check_sidecar() {
    sc_label=$1
    sc_kind=$2
    shift 2
    sc_a=$SCRATCH/$sc_label-a.json
    sc_b=$SCRATCH/$sc_label-b.json
    sc_out=$SCRATCH/$sc_label.stdout
    TEST "$sc_label-sidecar"
    "$TOOL" "$@" --json "$sc_a" >"$sc_out" 2>"$SCRATCH/$sc_label-a.err" || {
        FAIL_CASE 'first sidecar run failed'
        return
    }
    "$TOOL" "$@" --json "$sc_b" --json >"$sc_out" 2>"$SCRATCH/$sc_label-b.err" || {
        FAIL_CASE 'sidecar plus bare --json run failed'
        return
    }
    if ! cmp -s "$sc_a" "$sc_b"; then
        FAIL_CASE 'sidecar bytes changed'
        return
    fi
    if ! python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert isinstance(d, {"list":list,"dict":dict}[sys.argv[2]])' \
        "$sc_b" "$sc_kind" >"$SCRATCH/$sc_label.sidecar.log" 2>&1; then
        FAIL_CASE "$(cat "$SCRATCH/$sc_label.sidecar.log")"
        return
    fi
    if ! check_doc "$sc_out" "$sc_label" 'path' ok \
        >"$SCRATCH/$sc_label.stdout.log" 2>&1; then
        FAIL_CASE "$(cat "$SCRATCH/$sc_label.stdout.log")"
        return
    fi
    PASS
}

check_sidecar scan list scan "$IMAGE"
check_sidecar heatmap dict heatmap "$IMAGE" --block 1 --width 16

printf '\nScratch fixtures: %s\n' "$SCRATCH"
printf 'JSON CLI: %d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
