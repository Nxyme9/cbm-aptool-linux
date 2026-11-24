# cbm-aptool-linux

Linux-native reverse-engineering of the Chipsbank CBMUsbDisk vendor protocol.

## What this is

A small C toolchain that ports the TEA-based encryption core and the CBM
container format used by the vendor APTool (`ap.exe`), and validates the
resulting host-side path against a real Chipsbank USB mass-storage device.

It does **not** redistribute any vendor binary and does **not** claim full
protocol parity. See [GAPS.md](GAPS.md) for the four honest gaps.

## Working, verified

- **Native TEA cipher (default)** — pure-C clean-room implementation in
  `tea_native.{h,c}`, byte-identical to the vendor PE oracle on the golden
  vectors and equivalence probes. No `ap.exe` is needed to build or use it.
- **TEA crypto core (PE reference)** — encrypt (`0x459da0`) / decrypt
  (`0x459d50`), block fn `0x459ec0`, state `0x531328`, key
  `1a2b3c4d5e6fTENG`, CBC XOR region `0x45a0ff`–`0x45a177`. Roundtrip
  verified up to 85687 bytes.
- **CBM container** — 85688 bytes: byte-0 header + TEA-encrypted body;
  `HLEN = ((filesize-511)&~7)+511`. Error strings: `File is encrypted!`,
  `Decrypt Faile!`.
- **Paced write path** — 40 MiB bursts with 45 s cooldowns.
- **Linux USB mass-storage layer** — `pread`/`pwrite`, `BLKGETSIZE64`,
  `_FILE_OFFSET_BITS 64` (handles >4 GiB offsets), offset-aware read/write.
- **MBR/DJ layout validator** — DJ_BOOT 512 MiB FAT32 / DJ_OS 4 GiB ext4 /
  DJ_DATA rest exFAT, 26 GiB MBR window, 28 GiB (28672 MiB) accepted stick.
- **NAND controller identity probe** — Chipsbank-class (VID 048d / PID 1234).
- **CBM container tool** — `cbm-tool container <path>`: reads an 85688-byte
  container, TEA-decrypts the body, inspects it (hex dump, strings, stats,
  tokens), re-encrypts and verifies the roundtrip. Writes nothing by default;
  `--output <path>` and `--write-back` commit the re-encrypted container
  (block-device targets use paced writes). Also supports `--offset N`,
  `--hex-full`, `--min-string N`, `--dump-plain <path>` (write the decrypted
  85687-byte body) and `--inject <path>` (replace the body with an exact-size
  modified plaintext before re-encryption).

## Not recovered (see GAPS.md)

1. Vendor SCSI CDB set.
2. CBMUsbDisk.dll decryption (0/16 candidate keys yielded a valid PE) — no
   longer blocks normal use; the TEA core is native and PE-free.
3. BCH ECC / balanced erase (firmware-internal; host evidence only).
4. Container body field map beyond byte 0 — still incomplete; see Gap 4 in
   [GAPS.md](GAPS.md) and [docs/container-format.md](docs/container-format.md).

## Crypto backends

`cbm-tool` has two crypto backends behind one unchanged `tea_*` API:

- **native (default)** — the clean-room pure-C cipher in `tea_native.{h,c}`.
  No vendor binary, no `mmap`, no `ap.exe`. Every normal command, including
  `container` mode, uses this backend.
- **PE harness (opt-in)** — `--pe-crypto` runs the original vendor TEA cores
  through the reusable `pelib` fixed-base loader (`pe_load` / `pe_call_void` /
  `pe_unload`) as a cross-check. `tea_crypto.c` only dispatches to it; there is
  one PE loader in the codebase. It needs a user-supplied `ap.exe`. There is
  **no silent fallback**: if the requested backend cannot initialise, the
  command fails with an error.

`--native-crypto` selects the default explicitly; `--pe-crypto` selects the
cross-check (last flag wins). Flags are stripped before mode dispatch, so
they work in self-test, device-validation, `container`, `diff` and `fuzz`
modes, in any position:

    ./cbm-tool --native-crypto
    ./cbm-tool --pe-crypto
    ./cbm-tool --pe-crypto container container.bin
    ./cbm-tool container container.bin --pe-crypto --output container.reenc

`CBM_PE_PATH` overrides the PE location (default `/tmp/opencode/ap.exe`); the
native backend ignores it. In PE mode the tool runs `tea_native_selfcheck()`
before init and prints `PE self-check: PASS (native byte-identical to PE)`
when the clean-room cipher matches the vendor oracle. See
[ARCHITECTURE.md](ARCHITECTURE.md) §9 for the recovered tables, flag
sequences and golden vectors.

## Build

    make clean && make && make test

Requires gcc with 32-bit support (`gcc -m32`) and make. Expected: 113/113 PASS
across sixteen suites (tea 6, tea_native 8, cbm 5, paced 5, usb_mass 3,
layout 5, nand 3, cbm_file 5, cbm_inspect 9, pelib 19, decode 11,
backend_cli 4, diff 11, fuzz 5, scan 10, scan_report 4). The four 5A
PE-dependent cases (`tea_native` PE oracle, `test_tea` PE dispatch and the two
`test_backend_cli.sh` PE runs) skip (not fail) when no PE is supplied; eleven
`test_pelib` cases need the vendor PE and fail without it. The remaining 98
checks need no vendor binary.

## Device validation

    ./cbm-tool /dev/sdX

See [docs/device-validation.md](docs/device-validation.md) (serial redacted).

## Container inspection

    ./cbm-tool container container.bin
    ./cbm-tool container /dev/sdX --offset 1048576 --hex-full
    ./cbm-tool container container.bin --output container.reenc
    ./cbm-tool container container.bin --dump-plain body.bin
    ./cbm-tool container container.bin --inject body.mod.bin --output patched.bin
    ./cbm-tool container container.bin --inject body.mod.bin --write-back

Reads an 85688-byte CBM container, decrypts and inspects the body, then
re-encrypts it and verifies the roundtrip without modifying the target. Add
`--output <path>` to save the re-encrypted container to a new file, or
`--write-back` to replace the original (block devices use paced writes).
`--offset N` selects a byte offset on block devices; `--hex-full` dumps every
byte instead of the default first 320 + last 320; `--min-string N` sets the
minimum printable-string length (default 4).

### Content modification

`--dump-plain <path>` writes the decrypted 85687-byte body (header excluded).
Edit that file, then pass it back with `--inject <path>`; the inject file must
be exactly 85687 bytes. The header byte is preserved from the source container.
Combine with `--output` for a new container or `--write-back` for in-place
replacement (paced writes on block devices). Injection never changes the
encryption flag or the container size.

## Body diff, decoder and fuzz lab

    ./cbm-tool diff old.plain new.plain [--context N]
    ./cbm-tool fuzz container.bin --mutate 5 --rounds 2 --seed 42 --out ./corpus

`diff` reads two already-decrypted 85687-byte bodies (use
`container ... --dump-plain`) and prints merged changed ranges, a changed-byte
count, entropy for each side plus a signed delta, and a printable-density
heatmap. `--context N` merges spans separated by at most N bytes (default 3).
Swapping the two files yields the same ranges.

`fuzz` is an offline mutation lab: it decrypts one 85688-byte container,
applies deterministic xorshift64* mutations from `--seed`, re-encrypts, proves
`decrypt → encrypt` identity for every round, and writes only
`<out>/round-NNN.cbm` plus `<out>/manifest.txt`. It refuses a block-device
source and refuses when `--out` is missing, is a block device, or equals the
source path or its directory. The same `--seed/--mutate/--rounds` produce
byte-identical files. `--out` must already exist. See
[docs/container-format.md](docs/container-format.md) for the format and its
explicit **inferred** markers — the field map is deliberately incomplete.

## Read-only forensic scan

    ./cbm-tool scan <device-or-image> [--start LBA] [--end LBA] [--chunk MiB]
                    [--carve <dir>] [--json <report.json>]

`scan` sweeps an inclusive LBA range (512 bytes/LBA; `--start` defaults to 0,
`--end` to the last LBA, `--chunk` to 8 MiB with a 1 MiB minimum) in chunks
that overlap by 171888 bytes, and prints one deterministic row per **candidate**
(`offset header entropy sha256 token_count [offset:token]`). It is **read-only
by default**: no writes of any kind unless `--carve <dir>` or
`--json <report>` is given, and those write only to the explicit local paths.
`--carve` creates `<dir>` (mode 0755) and writes one exact 85688-byte
`hit-NNN-<offset>.cbm` per candidate in hit order; `--json` writes one JSON
array with fixed field order (`offset`, `header`, `entropy`, `sha256`,
`tokens` of `{offset, text}`), lowercase hex digests and locale-independent
fixed-point entropy (`%u.%06u`, never `%.6f`). Both refuse paths that resolve
to the source image (same `st_dev`/`st_ino` or a `realpath` match).

Detection uses the **structural probe** only: no magic list is supplied. No
magic value is known for this format (`docs/container-format.md`), so
`cbmv1001` and similar strings are **UNVERIFIED** and advisory at most. Hits
are **CANDIDATES, not confirmed containers**, and false positives/negatives
are possible: the scanner only probes 512-byte-aligned starts, and the
duplicate-hit suppression cannot report two genuinely distinct containers
whose starts are less than `CBM_CONTAINER_SIZE` (85688) bytes apart.
Real-device scanning remains a hardware-gated step, not part of the automated
suite; the tests use synthetic images only.

## PE framework

The TEA core was originally recovered by running the vendor PE natively on
Linux via an mmap-at-ImageBase harness (no Wine). The loader and call ABI now
live in the reusable `pelib.{h,c}` library: `pe_load` maps one PE at
`ImageBase 0x400000` with bounds-checked headers, `pe_rva_to_va` resolves
addresses, `pe_call_void` invokes a target with the packed three-word
`__stdcall` ABI, `pe_export` finds named exports and `pe_unload` releases the
image. `tea_crypto.c` uses it for the opt-in `--pe-crypto` cross-check, and the
`pe-call <pe-path> <rva|export> <hex-args>` CLI exposes the same API directly.
Neither is a runtime dependency of the default native backend. See
[PE-HARNESS.md](PE-HARNESS.md) and [ARCHITECTURE.md](ARCHITECTURE.md) §10.

## Supply your own ap.exe (PE cross-check only)

This repository contains **no vendor binary**. The default build and all
normal modes run the pure-C cipher and need no `ap.exe` at all. The optional
`--pe-crypto` backend and the PE-oracle equivalence test do need one: supply
your own legally-obtained copy of APTool (`ap.exe`) at
`/tmp/opencode/ap.exe`, or set `CBM_PE_PATH=/path/to/ap.exe`. The harness
loads it at runtime; it is never committed.
The PE-oracle equivalence test in `test_tea_native` reads the default path
`/tmp/opencode/ap.exe` only and does not honour `CBM_PE_PATH`; setting
`CBM_PE_PATH` relocates the tool's `--pe-crypto` backend only.

## License

MIT. See [LICENSE](LICENSE).
