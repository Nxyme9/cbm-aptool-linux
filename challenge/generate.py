#!/usr/bin/env python3
"""Generate the synthetic 5K CTF disk image (no committed disk blob).

The image is a sparse 64 MiB regular file with:
  * LBA 0: nominal DJ MBR built from the same constants as cbm_layout.c;
  * LBA 4096: one TEA-encrypted CBM container whose plaintext body holds a flag.

The ciphertext is produced by the repository's own `cbm-tool container
--inject --output` path, so the challenge and the solver share one crypto
implementation. No device, vendor binary or real container is used.
"""
import argparse
import os
import pathlib
import struct
import subprocess
import sys
import tempfile

CONTAINER_SIZE = 85688
HEADER_SIZE = 1
BODY_LEN = CONTAINER_SIZE - HEADER_SIZE
IMAGE_BYTES = 64 * 1024 * 1024
PLANT_LBA = 4096
DEFAULT_FLAG = "CBMCTF{tea_cbc_clean_room_2026}"

# Nominal DJ geometry from cbm_layout.c (NOT vendor measurements).
BOOT_START, BOOT_SIZE = 2048, 1048576
OS_START, OS_SIZE = 1050624, 8388608
DATA_START, DATA_TYPE = 9439232, 0x07
WINDOW_GIB = 26


def mbr_bytes():
    mbr = bytearray(512)
    window_sectors = WINDOW_GIB * 2097152
    entries = (
        (0x0C, BOOT_START, BOOT_SIZE),
        (0x83, OS_START, OS_SIZE),
        (DATA_TYPE, DATA_START, window_sectors - DATA_START),
    )
    for i, (ptype, start, size) in enumerate(entries):
        off = 446 + i * 16
        mbr[off + 4] = ptype
        struct.pack_into("<II", mbr, off + 8, start, size)
    mbr[510] = 0x55
    mbr[511] = 0xAA
    return bytes(mbr)


def plaintext_body(flag):
    """Deterministic, non-periodic printable body with a flag token."""
    data = bytearray(BODY_LEN)
    state = 12345
    for i in range(BODY_LEN):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        r = state >> 24
        data[i] = 0 if r < 13 else 0x20 + (r % 95)
    flag_bytes = flag.encode("ascii")
    if not flag_bytes or len(flag_bytes) > 56 or any(c < 0x20 or c > 0x7E for c in flag_bytes):
        raise ValueError("flag must be 1..56 printable ASCII bytes")
    data[64:64 + len(flag_bytes)] = flag_bytes
    data[:8] = b"CBM-FORE"
    data[-8:] = b"NSIC-END"
    # The scanner's prefix/edge screen needs >=80% printable at both ends.
    for i in range(64):
        data[i] = data[i] or 0x20
        data[BODY_LEN - 1 - i] = data[BODY_LEN - 1 - i] or 0x20
    return bytes(data)


def encrypt_container(tool, plain_path, out_path):
    with tempfile.TemporaryDirectory(prefix="cbm-ctf-gen-", dir="/tmp/opencode") as tmp:
        seed = pathlib.Path(tmp) / "seed.cbm"
        seed.write_bytes(b"\x81" + bytes(BODY_LEN))
        result = subprocess.run(
            [tool, "container", str(seed), "--inject", str(plain_path),
             "--output", str(out_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            sys.stderr.write(result.stderr.decode("utf-8", "replace"))
            raise RuntimeError("cbm-tool container --inject failed")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="output image path (must not exist)")
    ap.add_argument("--flag", default=DEFAULT_FLAG, help="flag to plant")
    ap.add_argument("--tool", default=None, help="path to cbm-tool (default: repo build)")
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    root = pathlib.Path(__file__).resolve().parent.parent
    tool = args.tool or str(root / "cbm-tool")
    if not os.access(tool, os.X_OK):
        ap.error("cbm-tool is missing or not executable: build it with `make`")

    body = plaintext_body(args.flag)
    with tempfile.TemporaryDirectory(prefix="cbm-ctf-plain-", dir="/tmp/opencode") as tmp:
        plain = pathlib.Path(tmp) / "body.bin"
        plain.write_bytes(body)
        container = pathlib.Path(tmp) / "planted.cbm"
        encrypt_container(tool, str(plain), str(container))
        blob = container.read_bytes()
    if len(blob) != CONTAINER_SIZE:
        raise RuntimeError("generated container has wrong size")

    with out.open("xb") as f:
        f.write(mbr_bytes())
        f.seek(PLANT_LBA * 512)
        f.write(blob)
        f.truncate(IMAGE_BYTES)

    print("image: %s (%d bytes, sparse)" % (out, IMAGE_BYTES))
    print("container LBA: %d (offset %d)" % (PLANT_LBA, PLANT_LBA * 512))
    print("flag: %s" % args.flag)


if __name__ == "__main__":
    main()
