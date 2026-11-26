# Gaps — what this repo does NOT do

Honest accounting. This is a partial reverse-engineering with a working
host-side path, not a complete protocol clone. Claiming otherwise would
destroy credibility; these gaps are documented so users and reviewers know
exactly where the evidence stops.

## No vendor binary is needed

The build, `make test`, and every normal CLI mode — `container`, `diff`,
`fuzz`, `scan`, `heatmap`, `doctor` and `tui` — run with no vendor PE present
and `CBM_PE_PATH` unset. Decoding is a container-mode capability
(`container --dump-plain`), not a separate subcommand. The native TEA
implementation is the default backend; there is no compiled-in PE path and no
silent fallback. The PE harness is an **explicit opt-in cross-check**: set
`CBM_PE_PATH` to your own legally obtained PE before using `--pe-crypto`;
without it the command fails with
`Error: --pe-crypto requires CBM_PE_PATH (no vendor binary default)`. No vendor
binary, key leak or device serial is committed. Each gap below carries a
disposition and the exact gate for full closure; none is claimed closed
without evidence.

## Measured counts (scope)

Measured on this tree at HEAD `245119b` plus the wave 5E working-tree changes
listed in the log, from two fresh logs under `/tmp/opencode/`:

- `nohl-final-with-pe.log` (`CBM_PE_PATH` pointed at the user's own PE):
  **21 `Results:` lines summing to 194 passed, 0 failed, 0 skipped**; the
  separately formatted `test_pelib` line reads `test_pelib: 21 passed,
  0 failed`; the separately formatted `test_fwemu: 17 passed, 0 failed` line
  is likewise outside the sums.
- `nohl-final-without-pe.log` (no usable PE: a bogus `CBM_PE_PATH`, the user's
  file never moved or deleted): **21 `Results:` lines summing to 188 passed,
  0 failed, 4 skipped**; the separately formatted `test_pelib` line reads
  `test_pelib: 10 passed, 0 failed`.

Both logs record `worktree: dirty` and list the exact wave 5E files: the wave
was measured before its commit, and the committed tree is that same content.

Capture protocol: one shell per mode, with `export CBM_PE_PATH=...` in the same
scope as the test commands (not merely echoed). Each log records the live value
and whether the file exists; the no-PE SKIP reasons name the bogus path
`/tmp/opencode/does-not-exist.exe`, which makes the evidence checkable.

Scope: 194 and 188 are sums of the `Results:` lines only. The `test_pelib`
counts come from its own summary line and are **not** part of those sums. The
4 skipped in the no-PE `Results:` sums come entirely from the two
`test_backend_cli.sh` `Results:` lines (2 each); the PE-only skips in
`test_tea` and `test_tea_native` appear only as `TEST:` lines, not in those
sums, and `test_pelib`'s skips are reflected in its separate summary line
(11 fewer passes). Both runs end with `cli_exit=0`,
`build_exit=0` and `make_test_exit=0`; `vendor_literal_grep_exit=1` records
that the shipped-file grep found no vendor path literal. All fixtures are
synthetic regular files; no real device is touched.

## Gap 1 — Vendor SCSI CDB set not recovered

- **Disposition:** open, bounded. **Exact gate:** a `CBMUSBSys.sys` /
  `CBMUsbDrv*.dll` artifact or USB-capture hardware, then map each vendor CDB
  to a Linux equivalent.
- **What's missing:** the full `DeviceIoControl` CDB table issued by
  `CBMUsbDisk.dll` / `CBMUSBSys.sys`. We did not recover the vendor's
  proprietary command set.
- **What works instead:** the host-side path uses standard Linux block I/O
  (`open`, `pread`, `pwrite`, `ioctl(BLKGETSIZE64)`). Device validation
  passes (MBR, DJ layout, capacity, safe write/read/restore).
- **Host evidence:** `usb_mass.{h,c}` (offset-aware read/write), `cbm_layout`
  validation, real-device roundtrip at LBA 54526976. Wave 5E adds a
  software-only tier-1 capture (`cdb_shim.{h,c}`, `cbm-tool cdb-capture`) that
  logs control codes, input buffers and bounds-checked SCSI CDBs from PE
  imports; `test_cdb_shim` proves the format against a synthetic PE. It has
  **not** been run against the vendor PE (G1-b), so no vendor CDB is claimed:
  see `docs/cdb-table.md`, whose vendor column reads `not observed`.

## Gap 2 — CBMUsbDisk.dll decryption yielded 0/16 valid PEs

- **Disposition:** split — the practical crypto need is **closed** (native TEA
  core with golden vectors; no vendor binary needed); DLL internals remain
  **open**. **Exact gate:** a `CBMUsbDisk.dll` artifact and a correct key
  derivation.
- **What's missing:** the DLL ships TEA-encrypted (or otherwise packed).
  We probed 16 candidate keys; none produced a valid PE. The DLL's
  internal logic is therefore documented from static references only, not
  from a decrypted image.
- **What works instead:** the PE's TEA core itself is fully recovered and
  verified (`rtlen` perfect inverse to L=85687, `rttest` match=1), and
  reimplemented in pure C with golden vectors that are byte-identical to the
  PE oracle. The container format (85688 B, byte-0 header + TEA body) is
  implemented.
- **Host evidence:** `tea_native.{h,c}`, `tea_crypto.{h,c}` (dispatcher),
  `test_tea` (6/6 with PE, 5/5 without), `test_tea_native` (8/8 with PE,
  7/7 without), `cbm_container` (5/5), the separately formatted
  `test_pelib` line (21 passes with PE, 10 without), `test_backend_cli.sh`
  (15 passed with PE, 13 passed + 2 skipped without), `test_cbm_decode` (11/11),
  `test_cbm_fuzz` (5/5), `test_cbm_scan` (11/11) and
  `test_cbm_scan_report` (4/4), `test_entropy_map` (8/8) and
  `test_png_write` (5/5), `test_cbm_doctor` (24/24) and `test_cbm_tui`
  (18/18) — see the `Results:`-line sums above for the suite total.
- **What would close the DLL half:** identify the correct key derivation
  (possibly tied to controller identity / serial) or unpack the DLL by other
  means.

## Gap 3 — BCH ECC / balanced erase are firmware-internal

- **Disposition:** open, bounded. **Exact gate:** firmware dump + a
  CBM2199E / CBM2199s / CBM3380 datasheet + ECC counters.
- **What's missing:** the host cannot observe or control the NAND
  controller's BCH ECC strength, bad-block management, or balanced-erase
  policy. These live inside the Chipsbank firmware.
- **What works instead:** host-observable identity and geometry — controller
  VID/PID (048d/1234), partition layout, capacity, safe block I/O.
- **Host evidence:** `nand_info.{h,c}` probe (`Chipsbank-class: YES`, 10/10),
  `cbm_layout` validation (8/8), device capacity (500 GiB).

## Gap 4 — Container field map beyond byte 0 is incomplete

- **Disposition:** partially closed — outer layer implemented, body semantics
  inference only. **Exact gate:** vendor documentation or a decrypted
  serialiser PE plus a real-container corpus.
- **What's missing:** no vendor schema for the 85687-byte body was recovered.
  Its field names, record boundaries, checksums and optional segments are
  unknown; the outer size/header/body split is only an **inferred** reading of
  host-observable behaviour.
- **What works instead:** deterministic decryption, 64 B entropy/region
  classification and context-merged body diff give reproducible observations
  without asserting vendor semantics. See
  [docs/container-format.md](docs/container-format.md), where every
  interpretation is explicitly marked **inferred**.
- **Host evidence:** `cbm_container` (5/5), `cbm_decode` (11/11), `cbm_diff`
  (11/11), `cbm_fuzz` (5/5). The fuzz lab proves `decrypt → encrypt` identity,
  not semantic validity of mutated bodies.
- **What would close it:** vendor documentation or a decrypted DLL/PE with the
  container serialiser, plus corpus evidence of real field layouts.

## Gap 5 — the scanner finds candidates, not confirmed containers

- **Disposition:** limitation mitigated by the opt-in `--all-hits` flag;
  container **confirmation remains open**. **Exact gate:** a recovered
  magic/header schema (Gap 4) plus a real-container corpus.
- **What's missing:** no vendor magic value is known
  (`docs/container-format.md`); `cbmv1001` is **UNVERIFIED** and advisory at
  most. There is no oracle that can certify a reported offset as a genuine
  vendor container.
- **What works instead:** `cbm-tool scan` is a read-only structural probe on
  512-byte-aligned starts, with a full 85688-byte decrypt and a heuristic
  plausibility gate. It writes nothing unless `--carve`/`--json` is given, and
  those paths are refused when they resolve to the source image.
- **`--all-hits` (Task 3):** the default scan still collapses a cluster of
  hits closer than one container (85688 bytes) to its lowest offset. Passing
  `--all-hits` (scan-only, after the image path) keeps **every** candidate, so
  two genuinely distinct containers starting less than 85688 bytes apart can
  both be reported. This closes the cluster-suppression limitation; it does
  **not** certify either hit. Only aligned starts are probed, and shifted
  candidates may also appear; false positives and false negatives remain
  possible. Hits are CANDIDATES for follow-up with `container` mode, never
  confirmed containers. Real-device scanning is a hardware-gated step, not
  part of the automated suite.
- **What would close it:** the recovered magic/header schema from the vendor
  serialiser (Gap 4) and corpus evidence of real container boundaries.

## Summary

| Capability | Status |
|---|---|
| TEA crypto core | Native clean-room & verified; PE is an opt-in cross-check only |
| CBM container format | Outer layer implemented & tested; body field map **inferred**, incomplete |
| Paced writes | Implemented & tested |
| Linux USB mass-storage I/O | Implemented & tested |
| MBR/DJ layout validation | Implemented & tested |
| NAND controller identity | Host-observable probe |
| Vendor SCSI CDB set | **Not recovered** (Gap 1, open) |
| CBMUsbDisk.dll internals | **0/16 keys, not decrypted** (Gap 2, DLL half open; no longer blocks normal use) |
| BCH ECC / balanced erase | **Firmware-internal** (Gap 3, open) |
| Container body field map | **Inferred only** (Gap 4, partially closed) |
| Forensic scanner | Read-only candidate finder; `--all-hits` reports close hits (Gap 5, confirmation open) |

Suite counts: **194 passed, 0 failed, 0 skipped** with PE and **188 passed,
0 failed, 4 skipped** without a usable PE, each across 21 `Results:` lines on
this tree (2026-11-26); `test_pelib` is reported separately (21 / 10 passes).
The whole-image entropy heatmap is read-only by default, infers regions from
the MBR (never verified), caps samples at 64 Mi and pixels at 1 Mi, and a full
500 GiB device pass remains hardware-gated. This repo is an honest,
reproducible partial RE. It is not a complete protocol clone, and it is not a
vendor binary redistribution.
