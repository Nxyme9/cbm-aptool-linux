# cbm-aptool-linux

Linux-native reverse-engineering of the Chipsbank CBMUsbDisk vendor protocol.

## What this is

A small C toolchain that ports the TEA-based encryption core and the CBM
container format used by the vendor APTool (`ap.exe`), and validates the
resulting host-side path against a real Chipsbank USB mass-storage device.

It does **not** redistribute any vendor binary and does **not** claim full
protocol parity. See [GAPS.md](GAPS.md) for the three honest gaps.

## Working, verified

- **TEA crypto core** — encrypt (`0x459da0`) / decrypt (`0x459d50`), block
  fn `0x459ec0`, state `0x531328`, key `1a2b3c4d5e6fTENG`, CBC XOR region
  `0x45a0ff`–`0x45a177`. Roundtrip verified up to 85687 bytes.
- **CBM container** — 85688 bytes: byte-0 header + TEA-encrypted body;
  `HLEN = ((filesize-511)&~7)+511`. Error strings: `File is encrypted!`,
  `Decrypt Faile!`.
- **Paced write path** — 40 MiB bursts with 45 s cooldowns.
- **Linux USB mass-storage layer** — `pread`/`pwrite`, `BLKGETSIZE64`,
  `_FILE_OFFSET_BITS 64` (handles >4 GiB offsets), offset-aware read/write.
- **MBR/DJ layout validator** — DJ_BOOT 512 MiB FAT32 / DJ_OS 4 GiB ext4 /
  DJ_DATA rest exFAT, 26 GiB MBR window, 28 GiB (28672 MiB) accepted stick.
- **NAND controller identity probe** — Chipsbank-class (VID 048d / PID 1234).

## Not recovered (see GAPS.md)

1. Vendor SCSI CDB set.
2. CBMUsbDisk.dll decryption (0/16 candidate keys yielded a valid PE).
3. BCH ECC / balanced erase (firmware-internal; host evidence only).

## Build

    make clean && make && make test

Requires gcc with 32-bit support (`gcc -m32`) and make. Expected: 25/25 PASS.

## Device validation

    ./cbm-tool /dev/sdX

See [docs/device-validation.md](docs/device-validation.md) (serial redacted).

## PE harness

The TEA core was recovered by running the vendor PE natively on Linux via an
mmap-at-ImageBase harness (no Wine). See [PE-HARNESS.md](PE-HARNESS.md).

## Supply your own ap.exe

This repository contains **no vendor binary**. You must supply your own
legally-obtained copy of APTool (`ap.exe`) and place it at
`/tmp/opencode/ap.exe`, or set `CBM_PE_PATH=/path/to/ap.exe`. The harness
loads it at runtime; it is never committed.

## License

MIT. See [LICENSE](LICENSE).