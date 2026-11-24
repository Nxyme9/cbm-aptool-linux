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

Requires gcc with 32-bit support (`gcc -m32`), make and zlib (`-lz`, verified
with 32-bit zlib-ng 1.3.1). Observed on this tree (2026-11-24) with the full
chain `make clean && make && make test && sh test_backend_cli.sh`: **142 passing
checks across 20 `Results:` lines / 159 `TEST:` lines, 0 failures**.

Count history (honest, from the logs only): the earlier 126 figure was not
reproducible from the test logs — the 5F log sums to 111. The 131 figure was
the observed sum across 20 suites after Wave 5D (+3 layout, +12 doctor, +5 TUI).
The current 142 is that 131 plus 5 new doctor checks, 2 new TUI checks and
2 new shell CLI checks counted twice (inside `make test` and the explicit run).

Wave 5D adds three deterministic constructor checks to `test_layout` (5 -> 8),
the doctor suite (now 17 checks) and the TUI suite (now 7 checks). The shell
CLI suite appears twice in that log because the chain runs it both inside
`make test` and explicitly. All fixtures are synthetic regular files; no device
is required.

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

## Read-only entropy heatmap

    ./cbm-tool heatmap <device|image> [--block MiB] [--width N]
                    [--out <png>] [--json <report.json>]

`heatmap` samples the full image in fixed blocks (default 1 MiB, minimum 1)
via `cbm_file_read`, computes Shannon entropy with the shared decoder, and
renders a row-major 8-bit RGB PNG (blue 0 -> cyan -> green -> yellow -> red 8
bits/byte; empty pixels are grey). `--width` is 16..8192 (default 1024); image
height is `clamp(ceil(samples / width), 1, max(1, 1048576 / width))` with
`n == 0` giving height 1, pixel index `y*width + x` filled left-to-right then
top-to-bottom. The pixel count is capped at **1 Mi pixels**
(`CBM_HEATMAP_MAX_PIXELS`), bounding the pixel array to ~59 MB and the packed
RGB buffer to ~3 MB; the sample count is capped at **64 Mi samples** and
ranges over that cap are rejected.

`heatmap` is **READ-ONLY**: the source is opened only through `cbm_file_read`
plus a strictly `O_RDONLY` capacity probe for the full-device range. It writes
**nothing** unless `--out <png>` or `--json <path>` is given, and those two
paths are its only write targets. Both refuse paths that resolve to the source
image (shared `st_dev`/`st_ino`/`realpath` guard from the scan CLI). The text
summary is deterministic: fixed-point `%u.%06u` entropy with a literal `.`,
never `%.6f`, and no locale or time dependence.

Regions (MBR, DJ_BOOT, DJ_OS, DJ_DATA, TAIL) are **INFERRED from the MBR, not
verified**; each region line carries `inferred=yes`. A non-DJ or unparseable
MBR is reported as MBR+TAIL rather than forced into DJ names, and an unreadable
MBR degrades to TAIL only. The PNG is a **minimal self-written encoder**
(signature, IHDR, one IDAT with filter-0 scanlines compressed by zlib
`compress2` at level 9, IEND, zlib `crc32` on every chunk); no external image
library is used. A full 500 GiB device pass is a separate **hardware-gated**
step and is NOT implied by a green test run; the automated suite uses
synthetic regular files only.

## Guarded MBR doctor (repair is opt-in)

    ./cbm-tool doctor <device|image> [--window-gib 26|27|28]
    ./cbm-tool doctor <device|image> --repair-mbr --yes --backup <file>
                     [--window-gib 26|27|28]

`--window-gib` **defaults to 26**; the supported windows are 26, 27 and 28 GiB.
A negative value (e.g. `-1`) is a usage error (exit 2), never a silent wrap to
`ULLONG_MAX`.

The default is **READ-ONLY diagnosis**: any readable image is reported (DJ,
parsable non-DJ, or invalid signature) and nothing is written. Repair occurs
only when all three flags are present. The report prints `Repairable: yes|no
(reason)` from the same predicate the repair path gates on, so the verdict and
the write gate cannot disagree. Repair is authorised when either the first
512 bytes fail `cbm_layout_parse`, or they parse and are DJ-shaped (exactly
three non-empty entries) but fail `cbm_layout_validate`. A parseable non-DJ
(foreign) table is never silently rewritten; an already-valid DJ MBR is refused
because there is nothing to repair.

The backup path is refused first by the shared scan alias guard (same inode,
`realpath` match, or path under the source), before either path is opened.
Choose a `--backup` path in a directory you control and treat the backup as the
recovery artefact: the alias guard runs before the backup is created, so a
symlink swap in that directory is not re-checked (TOCTOU). The nominal candidate
is built by `cbm_layout_construct` and must pass `cbm_layout_parse` +
`cbm_layout_validate` with `disk_sectors = max(target_size/512,
CBM_EXPECTED_WINDOW_SECTORS)`. Repair then follows one fixed verified sequence:
read LBA 0 → write backup → re-read backup + `memcmp` → write the reconstructed
LBA 0 via `cbm_file_write` → read back + `memcmp` → report every step. Only LBA 0
of the target is ever written. A read-back failure names the backup path, and
the CLI prints every step flag on any repair failure. A target smaller than
`--window-gib` is refused (exit 1); missing flags or an aliased backup are exit
2. Exit codes: 0 success, 1 runtime/refusal, 2 usage.

Geometry is a **nominal convention from frozen spec Design Note 2, not a
vendor measurement**: DJ_BOOT LBA 2048 / 1048576 LBAs / type `0x0c`, DJ_OS LBA
1050624 / 8388608 LBAs / type `0x83`, DJ_DATA LBA 9439232 / window remainder /
type `0x07`, zero CHS bytes, signature `0x55AA`. Supported windows are 26..28
GiB; a 29 GiB request is rejected with an error containing `26..28`.

## Strictly read-only TUI

    ./cbm-tool tui <device|image>

Renders one ANSI frame from `cbm_tui_render`, a **pure** function of a supplied
state plus terminal dimensions: no tty probe inside the renderer, no file or
device I/O and no key-driven writes. State is gathered through the read-only
`doctor` report. The layout degrades from full 80x24 to compact 40x15 to tiny,
then to a single complete line at zero dimensions. `q`/ESC consumes one
keystroke; the target is never opened for writing.

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
