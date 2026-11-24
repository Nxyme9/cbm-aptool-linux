# Gaps — what this repo does NOT do

Honest accounting. This is a partial reverse-engineering with a working
host-side path, not a complete protocol clone. Claiming otherwise would
destroy credibility; these gaps are documented so users and reviewers know
exactly where the evidence stops.

## Gap 1 — Vendor SCSI CDB set not recovered

- **What's missing:** the full `DeviceIoControl` CDB table issued by
  `CBMUsbDisk.dll` / `CBMUSBSys.sys`. We did not recover the vendor's
  proprietary command set.
- **What works instead:** the host-side path uses standard Linux block I/O
  (`open`, `pread`, `pwrite`, `ioctl(BLKGETSIZE64)`). Device validation
  passes (MBR, DJ layout, capacity, safe write/read/restore).
- **Host evidence:** `usb_mass.{h,c}` (offset-aware read/write), `cbm_layout`
  validation, real-device roundtrip at LBA 54526976.
- **What would close it:** reverse-engineer the `CBMUSBSys.sys` /
  `CBMUsbDrv*.dll` ioctl path and map each CDB to a Linux equivalent.

## Gap 2 — CBMUsbDisk.dll decryption yielded 0/16 valid PEs

**Status: no longer blocks normal use.** The TEA core from `ap.exe` is now a
native, PE-free C implementation (`tea_native.{h,c}`) and is the default
backend; no vendor binary is needed to build or run any normal mode. The PE
remains the validation oracle (opt-in `--pe-crypto` cross-check and the
oracle-equivalence test), not a runtime dependency. The `CBMUsbDisk.dll`
internals are still **not recovered** — this gap concerns that DLL, not the
crypto this repo ships.

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
  `test_tea` (6/6), `test_tea_native` (8/8), `cbm_container` (5/5),
  `test_pelib` (19/19), `test_backend_cli.sh` (7/7), `test_cbm_decode`
  (11/11), `test_cbm_fuzz` (5/5), `test_cbm_scan` (10/10) and
  `test_cbm_scan_report` (4/4), `test_entropy_map` (8/8) and
  `test_png_write` (5/5), `test_cbm_doctor` (24/24) and `test_cbm_tui` (11/11)
  — 155 checks across 20 `Results:` lines (172 `TEST:` lines) total.
- **What would close it:** identify the correct key derivation (possibly
  tied to controller identity / serial) or unpack the DLL by other means.

## Gap 3 — BCH ECC / balanced erase are firmware-internal

- **What's missing:** the host cannot observe or control the NAND
  controller's BCH ECC strength, bad-block management, or balanced-erase
  policy. These live inside the Chipsbank firmware.
- **What works instead:** host-observable identity and geometry — controller
  VID/PID (048d/1234), partition layout, capacity, safe block I/O.
- **Host evidence:** `nand_info.{h,c}` probe (`Chipsbank-class: YES`),
  `cbm_layout` validation, device capacity (500 GiB).
- **What would close it:** firmware dump + controller datasheet
  (CBM2199E / CBM2199s / CBM3380) and a vendor tool that exposes ECC
  counters.

## Gap 4 — Container field map beyond byte 0 is incomplete

- **What's missing:** no vendor schema for the 85687-byte body was recovered.
  Its field names, record boundaries, checksums and optional segments are
  unknown; the outer size/header/body split is only an **inferred** reading of
  host-observable behaviour.
- **What works instead:** deterministic decryption, 64 B entropy/region
  classification and context-merged body diff give reproducible observations
  without asserting vendor semantics. See
  [docs/container-format.md](docs/container-format.md), where every
  interpretation is explicitly marked **inferred**.
- **Host evidence:** `cbm_container`, `cbm_decode` (11/11), `cbm_diff` (11/11),
  `cbm_fuzz` (5/5). The fuzz lab proves `decrypt → encrypt` identity, not
  semantic validity of mutated bodies.
- **What would close it:** vendor documentation or a decrypted DLL/PE with the
  container serialiser, plus corpus evidence of real field layouts.

## Gap 5 — the scanner finds candidates, not confirmed containers

- **What's missing:** no vendor magic value is known (`docs/container-format.md`);
  `cbmv1001` is **UNVERIFIED** and advisory at most. There is no oracle that
  can certify a reported offset as a genuine vendor container.
- **What works instead:** `cbm-tool scan` is a read-only structural probe on
  512-byte-aligned starts, with a full 85688-byte decrypt and a heuristic
  plausibility gate. It writes nothing unless `--carve`/`--json` is given, and
  those paths are refused when they resolve to the source image.
- **Known limitation:** cluster suppression keeps the lowest offset in a group
  of hits closer than one container (85688 bytes), so **two genuinely distinct
  containers starting less than 85688 bytes apart cannot both be reported**.
  Only aligned starts are probed; false positives and false negatives are
  both possible. Hits are CANDIDATES for follow-up with `container` mode,
  never confirmed containers. Real-device scanning is a hardware-gated step,
  not part of the automated suite.
- **What would close it:** a recovered magic/header schema from the vendor
  serialiser (Gap 4) and corpus evidence of real container boundaries.

## Summary

| Capability | Status |
|---|---|
| TEA crypto core | Native clean-room & verified; PE is cross-check oracle |
| CBM container format | Outer layer implemented & tested; body field map **inferred**, incomplete |
| Paced writes | Implemented & tested |
| Linux USB mass-storage I/O | Implemented & tested |
| MBR/DJ layout validation | Implemented & tested |
| NAND controller identity | Host-observable probe |
| Vendor SCSI CDB set | **Not recovered** |
| CBMUsbDisk.dll internals | **0/16 keys, not decrypted** (no longer blocks normal use) |
| BCH ECC / balanced erase | **Firmware-internal** |
| Forensic scanner | Read-only candidate finder (aligned starts, unproven magic, < 85688-byte separation limit) |

Current suite: 155 passing checks across 20 `Results:` lines / 172 `TEST:`
lines (observed 2026-11-24; +3 layout constructor checks, +24 doctor, +11 TUI
and +3 shell CLI checks counted twice over the earlier 111-observation baseline). The whole-image
entropy heatmap is read-only by default, infers regions from the MBR (never
verified), caps samples at 64 Mi and pixels at 1 Mi, and a full 500 GiB device
pass remains hardware-gated. This repo is an honest, reproducible partial RE.
It is not a complete protocol clone, and it is not a vendor binary redistribution.
