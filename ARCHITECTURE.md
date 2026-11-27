# Architecture — nx-cbm-lab

Linux-native clean-room reverse-engineering lab for Chipsbank CBM USB sticks.
Each subsystem maps to one source file; all are exercised by the unit suite
(194 passed with PE / 188 passed with 4 skipped without a usable PE, across
twenty-one `Results:` lines including CLI backend selection) and the real-device
validation mode (`cbm-tool <blockdev>`). See [GAPS.md](GAPS.md) for count scope.

## 1. TEA crypto core (`tea_crypto.{h,c}`)

Recovered from the vendor PE by the mmap-at-ImageBase harness (see
[PE-HARNESS.md](PE-HARNESS.md)). `tea_crypto.c` is now the backend
dispatcher; the PE branch calls the shared loader in `pelib.{h,c}` (§10).
The native default is described in §9.

| Symbol | PE address | Role |
|---|---|---|
| encrypt | `0x459da0` | CBC encrypt, `__stdcall` |
| decrypt | `0x459d50` | CBC decrypt, `__stdcall` |
| block fn | `0x459ec0` | core block transform |
| state | `0x531328` | 16-byte state, zeroed before each call |
| key derivation | `0x4fc924` → `1a2b3c4d5e6fTENG` | keyidx = 12 |
| CBC XOR | `0x45a0ff`–`0x45a177` | chaining region |

- Key: `"1a2b3c4d5e6fTENG"` (16 bytes, `TEA_KEY_LEN`).
- Block size: 8 bytes (`TEA_BLOCK_SIZE`); state size: 16 bytes.
- State is zeroed before every encrypt/decrypt call by `pe_call_void`
  (`memset` of 16 bytes at RVA `0x131328` / VA `0x531328` inside the loaded
  image); `tea_crypto.c` does not reset it a second time.
- Roundtrip verified by `rtlen` (perfect inverse to L=85687) and `rttest`
  (match=1) probes before porting.

## 2. CBM container (`cbm_container.{h,c}`)

- Size: **85688 bytes** = 1-byte header + TEA-encrypted body.
- Byte 0 is the header; bytes 1..85687 are the TEA-encrypted body.
- `HLEN = ((filesize - 511) & ~7) + 511` (computed by `cbm_compute_hlen`).
- Vendor error strings surfaced during RE: `File is encrypted!`,
  `Decrypt Faile!`.
- Unit tests: `test_cbm` (5/5).

## 3. Paced writes (`paced_write.{h,c}`)

- Burst size: 40 MiB (`PACED_BURST_SIZE`).
- Cooldown: 45 s (`PACED_COOLDOWN_SEC`) between bursts.
- Prevents device lockup / controller reset on sustained writes.
- Unit tests: `test_paced` (5/5).

## 4. Linux USB mass-storage layer (`usb_mass.{h,c}`)

Standard Linux block I/O — no vendor SCSI CDBs required for the working path.

- Open: `open(2)` + `ioctl(BLKGETSIZE64)` for capacity.
- Read/write: `pread(2)` / `pwrite(2)`, offset-aware (`usb_mass_read_at`,
  `usb_mass_write_at`).
- `_FILE_OFFSET_BITS 64` defined so 32-bit builds handle >4 GiB offsets
  (scratch read at ~27.9 GiB initially failed before this fix).
- Capacity check: device must expose at least the 28 GiB window.
- Unit tests: `test_usb_mass` (3/3).

## 5. MBR / DJ layout validator (`cbm_layout.{h,c}`)

- Parses the MBR (sector 0), verifies signature `0x55AA`.
- Validates the DJ partition scheme within a 26 GiB window:
  - DJ_BOOT: 512 MiB, FAT32
  - DJ_OS: 4 GiB, ext4
  - DJ_DATA: remainder, exFAT
- Accepted stick capacity: 28 GiB (28672 MiB).
- Unit tests: `test_layout` (8/8).

## 6. NAND controller identity probe (`nand_info.{h,c}`)

- Host-observable only: reads sysfs/udev for VID/PID/vendor/model/driver.
- Classifies the controller as Chipsbank-class (VID 048d).
- Does **not** observe BCH ECC or balanced-erase policy (firmware-internal).
- Unit tests: `test_nand` (10/10).

## 7. Entry point (`main.c`)

- `cbm-tool` (no args): self-test (crypto/container/pacing/layout/nand logic).
- `cbm-tool <blockdev>`: self-test + real-device validation (read-only layout
  checks, then safe write/read/restore roundtrip in the unpartitioned tail
  outside the MBR window — no filesystem data touched).
- `cbm-tool container <path>`: file-level container mode — reads an
  85688-byte CBM container, TEA-decrypts the body, inspects it (hex dump,
  strings, stats, tokens), re-encrypts and verifies the roundtrip. Writes
  nothing unless `--output <path>` or `--write-back` is given (safe
  default); block-device targets use paced writes. Also supports `--offset`,
  `--hex-full`, `--min-string`, `--dump-plain <path>` (decrypted 85687-byte
  body) and `--inject <path>` (exact-size replacement body, re-encrypted with
  the header preserved).
- `cbm-tool diff <a.plain> <b.plain> [--context N]`: offline body diff via
  `cbm_diff_print` (changed ranges, changed-byte count, entropy delta and
  printable-density heatmap) and `cbm_decode_entropy`; no crypto, no device.
- `cbm-tool fuzz <container> --mutate N --rounds N --seed N [--out <dir>]`:
  deterministic offline mutation corpus via `cbm_fuzz_run`; refuses block
  devices and source-as-`--out`, writes only under `--out`.
- `cbm-tool scan <device> [--start LBA] [--end LBA] [--chunk MiB] [--carve <dir>]
  [--json <report>] [--all-hits]`: read-only forensic candidate scan via
  `cbm_scan_image` / `cbm_scan_image_ex` (`NULL, 0` magics — structural probe
  only); `--all-hits` is scan-only, follows the image path, and keeps every
  candidate instead of collapsing close clusters. Optional report writers in
  `cbm_scan_report.{h,c}`. No source write path; `--carve`/`--json` are
  pre-flighted with `cbm_scan_report_check_output` (realpath string match or
  `st_dev`/`st_ino`) and write only to the explicit paths. JSON field order is
  `offset`, `header`, `entropy`, `sha256`, `tokens`; entropy is integer
  fixed-point with a literal `.`, so output is locale-independent.
- `cbm-tool cdb-capture <pe-path> --out <capture-file> [--export <name>]
  [--arg0 N] [--arg1 N] [--arg2 N]`: loads a PE with the wave 5E import shims
  from `cdb_shim.{h,c}` and writes a deterministic control-code/input/CDB
  capture; the PE path is mandatory here and never falls back to
  `CBM_PE_PATH`. Writes only `--out`, never a device.
- Subcommand dispatch order in `main()`: `parse_backend_flags` → `container`
  → `diff` → `fuzz` → `scan` → `heatmap` → `doctor` → `tui` →
  `cdb-capture` → no-args self-test → `verify_device(argv[1])`.
  Exit codes: 0 ok, 1 runtime error, 2 usage error for `diff`/`fuzz`/`scan`/
  `cdb-capture`.
- PE path comes only from the `CBM_PE_PATH` env var (or an explicit argument
  to `pe-call`); there is no built-in default and no silent fallback.
  `--pe-crypto` without it fails with an explicit error. Only the opt-in PE
  backend reads it; the native default ignores it.

## 8. File-level container I/O (`cbm_file.{h,c}`, `cbm_inspect.{h,c}`)

### 8.1 cbm_file — file/device I/O abstraction

- `cbm_file_read(path, offset, buf, len)`: read `len` bytes at absolute byte
  offset into `buf`. Returns 0 on success, -1 on error.
- `cbm_file_write(path, offset, buf, len)`: write `len` bytes from `buf` at
  absolute byte offset. Block-device targets use paced writes (40 MiB bursts
  / 45 s cooldown); regular files are written directly. Returns 0 on success,
  -1 on error.
- `cbm_file_is_blockdev(path)`: return 1 when `path` is a block device, 0
  otherwise (including stat failure).
- Backs the container mode's read/write/roundtrip path, including
  block-device targets.
- Unit tests: `test_cbm_file` (5/5).

### 8.2 cbm_inspect — container inspection

- `cbm_inspect_hex(buf, len, max_bytes, out)`: hex dump with ASCII sidebar.
  When `max_bytes > 0`, shows the first `max_bytes/2` and last `max_bytes/2`
  bytes (or all bytes when `max_bytes >= len`); when 0, shows all bytes.
- `cbm_inspect_strings(buf, len, min_run, out)`: extracts runs of printable
  ASCII (0x20–0x7e) of length >= `min_run`, printing offset and string.
  Never reads past `buf+len`.
- `cbm_inspect_stats(buf, len, out)`: prints size, printable byte count,
  unique byte count and Shannon entropy.
- `cbm_inspect_tokens(buf, len, out)`: searches for known tokens and reports
  offset + token for each hit.
- Unit tests: `test_cbm_inspect` (9/9).

## 9. Clean-room cipher (`tea_native.{h,c}`) and backend selection

The default backend is a pure-C implementation of the CBM block cipher. Its
constants are recovered data dumped from the PE oracle — not vendor source —
and its core is a clean-room translation of PE `0x459ec0`. It processes
`floor(len / 8)` whole 8-byte blocks; trailing bytes of an odd-length buffer
are left untouched. State is a 16-byte local reset at the start of every call.

### 9.1 Recovered tables

Seventeen constant tables span PE virtual addresses `0x52a9b0`–`0x52ad0f`:

| Group | Tables (PE VA) |
|---|---|
| Bit/permutation | `BIT` `0x52ad08`, `T_INIT` `0x52a9b0`, `T_FINAL` `0x52a9f0`, `T_KEY` `0x52aa30`, `T_OUT` `0x52aab8`, `T_FEED` `0x52aae8` |
| Shift/state | `T_LEFT` `0x52aa68`, `T_RIGHT` `0x52aa78`, `T_STATE` `0x52aa88` |
| S-boxes | `SBOX0`–`SBOX7`, `0x52ab08`–`0x52acc8` |
| Core | per-block transform `0x459ec0` |

The rotation tables encode the two special key-schedule bits held in byte 3;
`T_LEFT`/`T_RIGHT` select the rotation direction for each of the 16 rounds.

### 9.2 Flag sequences

Each 8-byte block runs three 16-round cores against one persistent per-call
state. A flag of `0x50` is init (`0x10`) + final (`0x40`) permutation with
right key rotations; `0x70` adds left rotations (`0x20`).

| Direction | Core 1 | Core 2 | Core 3 |
|---|---|---|---|
| `tea_native_encrypt` | `0x50` | `0x70` | `0x50` |
| `tea_native_decrypt` | `0x70` | `0x50` | `0x70` |

Cores 1 and 3 use the low 8 key bytes; core 2 uses the high 8 (`key + 8`).

### 9.3 Golden vectors

Key `1a2b3c4d5e6fTENG`; ciphertext shown as hex. All three decrypt back to
the exact input.

| Vector | Plaintext | Ciphertext |
|---|---|---|
| A | `0000000000000000` (8 zero bytes) | `e66254b5da09fb31` |
| B | bytes `00..1f` (32 bytes) | `3dd24f1e5c7d940ef690cfcc84ddff02660d74c782b22e1e4015059980c24f01` |
| C | bytes `01..0f` (15 bytes, odd) | `1b787ed12c571f48090a0b0c0d0e0f` (only the first 8 bytes are encrypted) |

`test_tea_native` (8/8 with PE, 7/7 without a usable PE) also covers state
reset between calls, short-key rejection without buffer mutation, a 15-byte
exact-allocation bounds check, and backend flag parsing. Its PE-oracle
equivalence test compares native and PE ciphertext on deterministic inputs at
nine lengths (8, 16, 24, 32, 64, 15, 23, 31, 127) and skips when no usable
PE is supplied. That test reads `CBM_PE_PATH`, the same variable the tool's
`--pe-crypto` backend uses; there is no default vendor path.

### 9.4 Backend-selection flow

    main()
      -> parse_backend_flags()            strip --native-crypto / --pe-crypto
      -> cbm_backend_set()                store choice (native default)
      -> container mode may return early  (flags already stripped from argv)
      -> tea_init()  [tea_crypto.c]       native: g_ready = 1, no mmap
                                          PE: pe_load() holds the image at 0x400000
      -> tea_encrypt()/tea_decrypt()      dispatch to tea_native_* or pe_call_void()

There is no silent fallback: if the requested backend cannot initialise,
`tea_init` fails and `tea_encrypt`/`tea_decrypt` refuse to run. In PE mode
`main()` runs `tea_native_selfcheck()` *before* `tea_init()` — the selfcheck
maps and unmaps the PE at `0x400000` itself and would otherwise clobber the
live backend mapping — and prints `PE self-check: PASS ...` on a byte-identical
match. The PE remains the validation oracle, not a runtime dependency.

## 9b. Decoder, diff and fuzz lab

- `cbm_decode.{h,c}` (11/11): Shannon entropy and 64 B window classification
  (`constant`/`string`/`opaque`). These are local heuristics, **not** recovered
  vendor field types.
- `cbm_diff.{h,c}` (11/11): context-merged changed ranges, changed-byte count,
  locale-independent signed entropy delta, printable-density heatmap.
- `cbm_fuzz.{h,c}` (5/5): xorshift64* seeded only by `--seed`; per-round
  independent streams; each mutation XORs one body byte with a non-zero delta.
  Manifest records file names, sizes, SHA-256 digests and the mutation list in
  round order. Every round verifies re-decrypt equals the mutated plaintext
  before writing; byte 0 is copied unchanged.
- Safety: block-device source refused, `--out` must be an existing non-device
  directory distinct from the source path and its directory; output paths that
  resolve back to the source are refused; writes use stdio only, never
  `cbm_file_write` (the paced device writer).
- Format honesty: [docs/container-format.md](docs/container-format.md) labels
  every interpretation **inferred** and lists what remains unknown.

## 9c. Read-only scanner and report writers (`cbm_scan.{h,c}`, `cbm_scan_report.{h,c}`)

- `cbm_scan.{h,c}` (11/11): 512-byte-aligned structural probe → full
  85688-byte TEA decrypt → heuristic plausibility gate. `cbm_scan_image`
  reads in chunks with 171888-byte overlap, dedupes shifted/overlapping
  candidates by keeping the lowest offset per cluster, and returns hits
  ascending by offset. Only `cbm_file_read` is used; no write path.
- `cbm_scan_report.{h,c}` (4/4): JSON array writer with fixed field order,
  escaped token strings, 64 lowercase hex sha256 digits and fixed-point
  entropy (`%u.%06u` via integer math, never `%.6f`); carve writer which reads
  exactly `CBM_CONTAINER_SIZE` bytes per hit and writes
  `<dir>/hit-NNN-<offset>.cbm` (001-based) via stdio, creating `dir` with
  `mkdir(0755)`. Shared `cbm_scan_report_check_output` refuses aliases of the
  source by `realpath` match, identical `st_dev`/`st_ino`, or a source-as-parent
  path; no output is opened before that guard passes.
- Honesty: no magic value is known (`docs/container-format.md`); `cbmv1001`
  is **UNVERIFIED** and only advisory. Detection is structural-only in the
  CLI (`NULL, 0` magics). Hits are **CANDIDATES**, not confirmed containers;
  only aligned starts are probed. The default scan collapses one cluster to
  its lowest offset, while the scan-only opt-in `--all-hits` keeps every
  candidate, including two genuinely distinct containers starting less than
  85688 bytes apart. Confirmation still needs a recovered magic/header schema
  (Gap 4) and a real-container corpus. Real-device scanning is hardware-gated,
  not part of the suite.

## 9d. Whole-disk entropy heatmap (Wave 5F)

- `entropy_map.{h,c}` (8/8): chunked `cbm_file_read` sampling over
  `[start,end)` at 1 MiB blocks, entropy from `cbm_decode_entropy`, a
  deterministic row-major downsample (max/mean/min aggregation, entropy ramp
  blue -> cyan -> green -> yellow -> red), MBR-based region overlay
  (`MBR`, `DJ_BOOT`, `DJ_OS`, `DJ_DATA`, `TAIL`) and a fixed-point JSON sidecar.
  The sample count is capped at 64 Mi and ranges over the cap are rejected.
- `png_write.{h,c}` (5/5): self-written 8-bit RGB PNG encoder (signature,
  IHDR, one IDAT with zlib `compress2` level 9 over filter-0 scanlines, IEND,
  zlib `crc32` per chunk) plus a zlib-only decoder used by the tests to prove
  signature, chunk order, CRCs, IHDR fields and byte-exact round trip. No
  external image library.
- `heatmap_mode()` in `main.c` drives both and prints a deterministic text
  summary. It is **READ-ONLY**: the source is opened only via `cbm_file_read`
  plus the strictly `O_RDONLY` `image_last_lba()` capacity probe; `--out` and
  `--json` are the only write targets and reuse
  `cbm_scan_report_check_output` to refuse paths that alias the source.
  Without either flag nothing is written. Image height is
  `clamp(ceil(samples/width), 1, max(1, CBM_HEATMAP_MAX_PIXELS/width))` with
  `CBM_HEATMAP_MAX_PIXELS = 1048576`, and `n == 0` gives height 1. Regions are
  **INFERRED from the MBR, not verified**; a non-DJ or unparseable MBR is
  reported as MBR+TAIL instead of forced DJ names. A full 500 GiB device pass
  is a separate hardware-gated step, not implied by a green suite.

## 10. PE loader library (`pelib.{h,c}`)

One reusable fixed-base PE loader now serves the PE backend, the generic
`pe-call` CLI and `test_pelib`; `tea_crypto.c` no longer contains an mmap or
section-copy loop.

- `pe_load(img, path, hooks)` reads the PE, checks the DOS/PE headers, section
  table and every raw-data range with 64-bit bounds arithmetic, and maps it at
  `PE_BASE 0x400000` / `PE_MAPSZ 0x140000` with `MAP_FIXED_NOREPLACE`. A second
  concurrent image or an already-occupied base fails cleanly. `path` may be
  NULL/empty, in which case `CBM_PE_PATH` is used — there is no built-in
  default path. `tea_init` passes only an explicit, validated path so PE mode
  never silently falls back.
- `pe_rva_to_va(img, rva)` resolves an RVA within the declared image size.
- `pe_call_void(img, rva_or_va, arg, n)` packs `n` bytes (1-3 `uint32_t`
  words, 4-12 bytes) into `args[0..2]`, zero-fills missing words, zeroes the
  16-byte TEA state at RVA `0x131328`, and calls through a 3-argument
  `__stdcall` pointer (callee cleans the stack). `tea_encrypt` supplies
  `[&buf, len, &key]` with `n = 12`.
- `pe_export(img, name, &rva)` resolves named exports (absent in `ap.exe`).
- `pe_import_hook_t` entries patch named imports in the IAT after sections are
  mapped; hooks are matched case-insensitively, ordinals are skipped.
- `pe_unload(img)` munmaps the image and clears the singleton; it tolerates
  NULL and double unload. `tea_cleanup()` calls it once.
- `pe-call <pe-path> <rva|export-name> <hex-args>` exposes the same API from
  the shell. `test_pelib` (21 passes with PE; separately formatted
  `test_pelib: 10 passed, 0 failed` without a usable PE) covers loader
  failures, golden encrypt `e66254b5da09fb31`, decrypt roundtrip and IAT
  hook dispatch. The separately formatted `test_fwemu: 17 passed, 0 failed`
  line is outside the `Results:` sums.

## 10b. CDB capture shims (Wave 5E, `cdb_shim.{h,c}`)

Software-only tier 1 of Gap 1: one fixed-base PE is loaded with an import hook
table, and the shims write a deterministic text capture. No device node, USB
gadget, vendor PE or vendor DLL participates in any test.

- `cdb_capture_open(path)` refuses a directory, block or character device and a
  second concurrent capture, then writes the header `cbm-cdb-capture/1` and
  flushes every record as it ends. `cdb_capture_count()` counts those records.
- `cdb_shim_hooks()` covers `kernel32.dll` `DeviceIoControl`, `CreateFileA`,
  `CreateFileW` and `CloseHandle`; `cdb_shim_log_unknown()` records an import
  with no dedicated shim as `event=<dll>!<name>`.
- Every shim returns a synthetic Win32 success. `DeviceIoControl` zeroes
  `*lpBytesReturned` and up to 512 output bytes, never modifies the input
  buffer, and never touches a caller pointer when no capture is open.
- Only `IOCTL_SCSI_PASS_THROUGH` (`0x0004D004`, `Cdb[]` at offset 24) and
  `IOCTL_SCSI_PASS_THROUGH_DIRECT` (`0x0004D014`, `Cdb[]` at offset 28) decode
  a CDB, bounded by `CdbLength` (offset 6), 16 bytes and the real buffer
  length. Any other control code logs the raw input only.
- `test_cdb_shim` builds a synthetic PE with one `DeviceIoControl` import,
  calls the patched IAT slot, and compares the whole capture file byte for
  byte (`2a 00 00 00 00 00`), plus unknown-control, truncation, NULL-pointer,
  no-capture and `CreateFileA/W` escaping cases. `docs/cdb-table.md` is the
  observed/not-observed table; its vendor column reads `not observed` because
  G1-b (running the capture against the user's own PE) has not run.



    /dev/sdX
      -> usb_mass_open (BLKGETSIZE64 capacity)
      -> usb_mass_read_at (sector 0 MBR)
      -> cbm_layout_parse + cbm_layout_validate (DJ scheme)
      -> nand_info_probe (Chipsbank-class?)
      -> usb_mass_read_at/write_at/read_at (scratch roundtrip at LBA scratch)
      -> usb_mass_write_at (restore original sector)
      -> verify restored

## 10c. Synthetic firmware model (Wave 5L, `fwemu/`)

SYNTHETIC ONLY: no firmware image, ARM/8051 program, Unicorn or ARM toolchain
is used. The stdlib Python package models BCH(255, 223, t=4) syndromes and
decode, per-block erase counts with a lowest-count/lowest-index policy, and a
deterministic trace whose every line contains `synthetic`. `HookSink` exposes
syndrome, erase-count and MMIO register hooks for a future Unicorn runner;
`run_synthetic()` drives them in plain Python. Gap 3 stays open: the gate is a
firmware dump + CBM2199E/2199s/3380 datasheet + ECC counters. See
[docs/firmware-emulation.md](docs/firmware-emulation.md).

## 10d. Recon candidate finder (Wave 5M, `recon.{h,c}`)

`recon_file(path, report)` is a bounded, read-only PE32/PE32+ reader: it caps
the file at 64 MiB, bounds-checks e_lfanew, optional header and section table,
and builds a zero-filled virtual image limited to 256 MiB. The first section
with `IMAGE_SCN_MEM_EXECUTE` is scanned for `55 8b ec` prologues; each body is
capped at 8192 bytes and scored for delta immediates, XOR and shift byte
patterns, repeated `E8` targets, calls into delta-bearing functions, a stack
frame and a plausible size. Results are sorted by score desc / RVA asc, stored
up to 512 candidates, and printed or emitted as `cbm/1` JSON by
`recon_cli_ex` in `main.c`. `cbm-tool recon <pe> [--top N] [--all] [--json]`
is dispatched before the selftest/device path and never writes to the PE.
The method, exact scoring table, checklist and honest limits are in
[docs/universal-re.md](docs/universal-re.md); the `.mind`-style evidence
template is [docs/port-spec-template.md](docs/port-spec-template.md). G2
(CBMUsbDisk.dll internals + key derivation) remains OPEN and requires the DLL;
this wave closes only the method/tooling half. `test_recon` reports on its own
line (`test_recon: 13 passed, 0 failed` with `CBM_PE_PATH`; 7 passed plus a
SKIP line without it) outside the `Results:` sums.

## 10e. Derived vault (Wave 5Q, `vault.{h,c}`)

`vault_create/load/save` store key/value records inside exactly one
`CBM_CONTAINER_SIZE` (85688-byte) envelope: byte 0 is the preserved header
byte (bit 7 = encrypted) and bytes 1..85687 are the TEA body. The plaintext
body is a private format — FNV-1a 64 checksum, `CBMVLT01` magic, u16 version,
u16 count, u32 reserved, then records of `u16 label_len, u16 value_len,
label, value` in insertion order, zero-padded. It is a **derived** format: it
reuses the envelope and the clean-room TEA core but claims no vendor
compatibility. Labels are 1..63 printable ASCII bytes, values 0..4096 bytes,
at most 1024 records within the 85663-byte record budget; `put` replaces an
existing label in place. The key comes from `CBM_VAULT_KEY` (exactly 16
bytes); when unset the CLI uses the public `TEA_NATIVE_KEY` and prints an
explicit warning (obfuscation, not confidentiality). Wrong key, ciphertext
tamper and checksum tamper are all refused. Writes to a block device require
`--write-back`, and every write is read back and compared; `get`/`list` never
write. `vault_cli_ex` emits `cbm/1` JSON for all five commands and never emits
its own error document (`main.c` does that on a non-zero return). `test_vault`
reports on its own line (`test_vault: 18 passed, 0 failed`) outside the
`Results:` sums. Layout, limits and CLI usage: [docs/vault.md](docs/vault.md).

## Build

    make clean && make && make test

`CC = gcc`; `CFLAGS` adds `-Wformat=2 -Wshadow -Wstrict-prototypes
-Wmissing-prototypes -Wvla -fstack-protector-strong -fstack-clash-protection
-D_FORTIFY_SOURCE=2` to `-m32 -O2 -g -Wall -Wextra`, and `LDFLAGS` adds
`-Wl,-z,relro,-z,now`; the `cbm-tool` target also links `-lz`. Produces
`cbm-tool`, the `pe-call` CLI, twenty test binaries
and one shell CLI suite. Measured at HEAD `245119b` plus the wave 5E working
tree: 194 passed, 0 failed, 0 skipped with PE, and 188 passed, 0 failed,
4 skipped without a usable PE, each across 21 `Results:` lines (plus a
separately formatted `test_pelib` line: 21 / 10 passes, plus the separately
formatted `test_fwemu: 17 passed, 0 failed` line). Counts are from
`/tmp/opencode/nohl-final-with-pe.log` and
`/tmp/opencode/nohl-final-without-pe.log`; see [GAPS.md](GAPS.md).
