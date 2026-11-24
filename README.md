# nx-cbm-lab

Linux-native clean-room reverse-engineering lab for Chipsbank CBM USB sticks: TEA cipher, forensic scanner, container editor, MBR doctor + TUI, entropy heatmap — 178 passing checks, no vendor binary, honest gaps.

## What this is

A small C toolchain that ports the TEA-based encryption core and the CBM
container format used by the vendor APTool (`ap.exe`), and validates the
resulting host-side path against a real Chipsbank USB mass-storage device.

It does **not** redistribute any vendor binary and does **not** claim full
protocol parity. See [GAPS.md](GAPS.md) for the five honest gaps and their
exact closure gates.

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

`CBM_PE_PATH` is the only source of the PE path — there is no built-in default
and no silent fallback; `--pe-crypto` without it fails with an explicit error.
The native backend ignores it. The PE-dependent cases in `test_tea`,
`test_tea_native`, `test_pelib` and `test_cbm` also read `CBM_PE_PATH`; the
first three skip their PE-only cases when no usable PE is supplied, while
`test_cbm` takes the native fallback and passes 5/5 in both runs. The 4 skips
in the no-PE `Results:` sums come from `test_backend_cli.sh` (2 in each of its
two runs). In PE mode the tool runs
`tea_native_selfcheck()` before init and prints
`PE self-check: PASS (native byte-identical to PE)` when the clean-room cipher
matches the vendor oracle. See [ARCHITECTURE.md](ARCHITECTURE.md) §9 for the
recovered tables, flag sequences and golden vectors.

## Build

    make clean && make && make test

Requires gcc with 32-bit support (`gcc -m32`), make and zlib (`-lz`, verified
with 32-bit zlib-ng 1.3.1). Observed on this tree (HEAD `0ad881d`, 2026-11-24)
with the full chain `make clean && make && make test && sh test_backend_cli.sh`:
**178 passed, 0 failed, 0 skipped** with PE and **172 passed, 0 failed,
4 skipped** with no usable PE, each across 20 `Results:` lines. The separately
formatted `test_pelib` line reports 21 passes with PE and 10 without; those
counts are outside the `Results:` sums. Both runs exited 0 (`cli_exit=0`,
`build_exit=0`, `make_test_exit=0`).

Provenance: `/tmp/opencode/nohl-final-with-pe.log` and
`/tmp/opencode/nohl-final-without-pe.log`. No real device is touched; every
fixture is a synthetic regular file.

Wave 5D adds three deterministic constructor checks to `test_layout` (5 -> 8),
the doctor suite (now 24 checks) and the TUI suite (now 18 checks). The shell
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
                    [--carve <dir>] [--json <report.json>] [--all-hits]

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
are possible: the scanner only probes 512-byte-aligned starts. By default a
cluster of hits closer than one container (`CBM_CONTAINER_SIZE`, 85688 bytes)
is collapsed to its lowest offset; the opt-in `--all-hits` flag (scan-only,
after the image path) keeps **every** candidate, so two genuinely distinct
containers less than 85688 bytes apart can both be reported. That closes the
cluster-suppression limitation, not confirmation: a recovered magic/header
schema (Gap 4) and a real-container corpus are still required. Real-device
scanning remains a hardware-gated step, not part of the automated suite; the
tests use synthetic images only.

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
The first character must be an ASCII digit: `-1`, ` -1`, `abc`, an empty string
and any value outside `26..28` (including a huge digit string that would wrap
the byte arithmetic) are usage errors (exit 2) with no report and no write.

The default is **READ-ONLY diagnosis**: any readable image is reported (DJ,
parsable non-DJ, or invalid signature) and nothing is written. Repair occurs
only when all three flags are present. The report prints `Repairable: yes|no
(reason)` from the same predicate the repair path gates on, so the verdict and
the write gate cannot disagree. Repair is authorised when either the first
512 bytes fail `cbm_layout_parse`, or they parse and are DJ-shaped (exactly
three non-empty entries) but fail `cbm_layout_validate`. A parseable non-DJ
(foreign) table is never silently rewritten; an already-valid DJ MBR is refused
because there is nothing to repair.

The backup path is checked by the shared scan alias guard (same inode,
`realpath` match, or path under the source) before either path is opened, then
**re-checked immediately before the backup write**. The backup is claimed with
`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` and written through that descriptor after
an `fstat` inode comparison against the target opened `O_RDONLY`; a symlink or
hardlink swap cannot redirect the verified backup. An existing backup path is
a runtime refusal (exit 1) and leaves both files intact. Target sizing uses
`st_size` for regular files and `BLKGETSIZE64` for block devices (`st_size` is
zero there). The nominal candidate is built by `cbm_layout_construct` and must
pass `cbm_layout_parse` + `cbm_layout_validate` with
`disk_sectors = max(target_size/512, CBM_EXPECTED_WINDOW_SECTORS)`. Repair then
follows one fixed verified sequence: read LBA 0 → claim and write backup →
re-read backup + `memcmp` → write the reconstructed LBA 0 via `cbm_file_write`
→ read back + `memcmp` → report every step. Only LBA 0 of the target is ever
written. A completed-write read-back failure uses the prefix `FAILED (write
completed, verification failed):` and names the backup path; refusals before
the target write use `Refused:`. The CLI prints every step flag on any repair
failure. A target smaller than `--window-gib` is refused (exit 1); missing
flags or an aliased backup are exit 2. Exit codes: 0 success, 1 runtime/refusal,
2 usage.

Geometry is a **nominal convention from frozen spec Design Note 2, not a
vendor measurement**: DJ_BOOT LBA 2048 / 1048576 LBAs / type `0x0c`, DJ_OS LBA
1050624 / 8388608 LBAs / type `0x83`, DJ_DATA LBA 9439232 / window remainder /
type `0x07`, zero CHS bytes, signature `0x55AA`. Supported windows are 26..28
GiB; a 29 GiB request is rejected with an error containing `26..28`.

## Strictly read-only TUI

    ./cbm-tool tui <device|image>

Renders frames from `cbm_tui_render`, a **pure** function of a supplied
state plus terminal dimensions: no tty probe inside the renderer, no file or
device I/O and no key-driven writes. State is gathered through the read-only
`doctor` report: the window is derived from measured size (28/27/26 GiB that
fits), partition rows come from the device's actual first sector (unparsable ⇒
zero rows, `mbr_status=INVALID`), and `backend=` reflects `cbm_backend_get()`.
The full layout includes a two-row 16-byte-per-row hex view of that actual
sector; each `n`/`p` press moves it one 16-byte row and `q`/ESC exits. In tty mode the terminal
is set raw with `tcgetattr`/`cfmakeraw`/`tcsetattr` and always restored on exit;
piped input is consumed without blocking. Scan hits and entropy are shown as
`n/a` when this frame did not sample them — never fabricated zeros. The layout
degrades from full 80x24 to compact 40x15 to tiny, then to a single complete
line at zero dimensions. The target is never opened for writing.

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
`--pe-crypto` backend and the PE-oracle equivalence tests do need one: supply
your own legally-obtained copy of APTool (`ap.exe`) via
`CBM_PE_PATH=/path/to/your/ap.exe` (or as an explicit `pe-call` argument).
There is no default path: `--pe-crypto` without `CBM_PE_PATH` fails with an
explicit error, and the harness loads the PE at runtime without ever
committing it.
The PE-dependent cases in `test_tea`, `test_tea_native`, `test_pelib` and
`test_cbm` read the same `CBM_PE_PATH`; the first three skip their PE-only
cases when no usable PE is supplied, while `test_cbm` takes the native
fallback and still passes 5/5. The 4 skipped counted in the no-PE `Results:`
sums come from `test_backend_cli.sh` (2 in each of its two runs); the skips in
`test_tea` and `test_tea_native` appear only as `TEST:` lines, not in their
`Results:` lines, and `test_pelib` is reported on its own summary line (10
passes without PE vs 21 with PE). No vendor file is moved, renamed or deleted.

## License

MIT. See [LICENSE](LICENSE).
