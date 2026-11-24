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
  `test_tea` (5/5), `test_tea_native` (8/8), `cbm_container` (5/5).
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

## Summary

| Capability | Status |
|---|---|
| TEA crypto core | Native clean-room & verified; PE is cross-check oracle |
| CBM container format | Implemented & tested |
| Paced writes | Implemented & tested |
| Linux USB mass-storage I/O | Implemented & tested |
| MBR/DJ layout validation | Implemented & tested |
| NAND controller identity | Host-observable probe |
| Vendor SCSI CDB set | **Not recovered** |
| CBMUsbDisk.dll internals | **0/16 keys, not decrypted** (no longer blocks normal use) |
| BCH ECC / balanced erase | **Firmware-internal** |

This repo is an honest, reproducible partial RE. It is not a complete
protocol clone, and it is not a vendor binary redistribution.
