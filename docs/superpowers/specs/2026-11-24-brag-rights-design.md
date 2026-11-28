# Design: Brag-Rights Wave 5 (four additions)

Date: 2026-11-24
Status: draft (awaiting approval)

## Intent

Extend the published, Linux-native CBM APTool RE project with four additions
the user selected together ("DO ALL"):

1. Clean-room TEA: no vendor `ap.exe` needed for normal use.
2. Forensic scanner: find CBM containers anywhere on a block device.
3. Format decoder + fuzz lab: map and mutate the undocumented container body.
4. Doctor + live TUI: repair layouts and present the whole thing visually.

All four stay read-only by default. Every write path stays opt-in and backed
by a read-back verification. No vendor binaries or secrets are committed.

## Non-goals

- No vendor SCSI CDB recovery (Gap 1 stays open).
- No `CBMUsbDisk.dll` unpacking (Gap 2 stays open).
- No firmware ECC / erase-policy access (Gap 3 stays open).
- No claim that the container field map is complete; mark inferred fields.
- No destructive device operation available without explicit flags.

## Wave 5A — Clean-room TEA (`tea_native.{h,c}`)

### Approach

Reverse the 8-byte block function at PE `0x459ec0` and the key schedule at
`0x4fc924` by static disassembly of the local vendor PE, then implement the
same transform in pure C. CBC chaining is reproduced from the XOR region
`0x45a0ff`–`0x45a177` (state zeroed before each call, as today).

### Interface

```c
int tea_native_encrypt(unsigned char *buf, size_t len, const char *key);
int tea_native_decrypt(unsigned char *buf, size_t len, const char *key);
int tea_native_selfcheck(const char *pe_path); /* oracle comparison, dev only */
```

`tea_native_selfcheck` is the only place that needs `ap.exe`. It compares
native and PE output on many random buffers, including odd lengths, and
returns 0 only on byte-for-byte equality.

### Integration

- Default crypto backend becomes native; `--pe-crypto` forces the existing
  mmap harness so reviewers can cross-check against the vendor routine.
- `CBM_PE_PATH` is only consulted for `--pe-crypto` and the self-check.
- If the disassembly cannot be translated exactly, this wave ships as an
  opt-in `--native-crypto` behind the self-check, never as a silent fallback.

### Tests

`test_tea_native.c`: known vectors, odd-length roundtrip, and (when
`ap.exe` is present) oracle-equivalence over deterministic random inputs.

## Wave 5B — Forensic scanner (`cbm_scan.{h,c}`)

### Approach

Read the device in aligned chunks with overlap >= 85688 bytes, searching for
`cbmv1001` and any secondary magic recovered from the decrypted body. For
each hit, try a 85688-byte container parse at that offset, TEA-decrypt, and
record header byte, entropy, sha256, and a short token summary.

### Interface / CLI

```
cbm-tool scan <device> [--start LBA] [--end LBA] [--chunk MiB]
              [--carve <dir>] [--json <report>]
```

- Default: full device, read-only, no writes of any kind.
- `--carve` and `--json` write only to the given local paths.
- Synthetic test image with planted containers validates offset reporting.

### Tests

`test_cbm_scan.c`: empty image (0 hits), one container at known offset, two
containers near a chunk boundary (proves overlap), false-positive magic.

### Real run

A full 500 GiB read of `/dev/sde` is a live device probe. It is listed as a
separate gated step; no scan of the real stick happens during the build.

## Wave 5C — Format decoder + fuzz lab (`cbm_decode.{h,c}`, `cbm_diff.{h,c}`)

### Approach

Use the decrypted body as the unit of analysis. Produce an entropy profile
and byte-range map, then use differential analysis of controlled mutations
to label regions (constant, checksum-like, string-like, opaque). Publish the
result as `docs/container-format.md` with explicit "inferred" markers.

### CLI

```
cbm-tool diff <a.plain> <b.plain> [--context N]
cbm-tool fuzz <container> --mutate N --rounds N --seed N [--out <dir>]
```

- `diff`: changed ranges, changed-byte count, entropy delta, text heatmap.
- `fuzz`: deterministic seeded mutations → re-encrypt → verify roundtrip;
  writes only to `--out`, never to the source or a device.
- Both are offline; no vendor binary needed once 5A lands.

### Tests

`test_cbm_diff.c`: identical files (no ranges), single-byte change, adjacent
changes merge, reversed argument symmetry. `test_cbm_fuzz.c`: same seed gives
same corpus; every generated container passes decrypt→encrypt identity.

## Wave 5D — Doctor + live TUI (`cbm_doctor.{h,c}`, `cbm-tui.c`)

### Doctor

```
cbm-tool doctor <device>             # dry-run report only
cbm-tool doctor <device> --repair-mbr --yes --backup <file>
```

- Reuses `cbm_layout` to validate MBR + DJ partitions.
- With `--repair-mbr --yes`, writes a reconstructed MBR only after saving the
  original sector to `--backup`; verifies with read-back.
- Without all of `--repair-mbr --yes --backup`, zero writes. Refuse to run on
  a device whose capacity/layout does not match the known DJ scheme.

### TUI

`cbm-tool tui <device>` — a dependency-free ANSI terminal dashboard showing
device geometry, partition map, cached scan hits, a scrollable hex viewer of
the selected container, and crypto backend status. Read-only; no keys trigger
writes. Rendered through a pure function so it can be snapshot-tested.

### Tests

`test_cbm_doctor.c`: dry-run on a synthetic image leaves its hash unchanged;
repair on a corrupted synthetic MBR restores the expected partition table;
missing `--yes` or `--backup` is refused. `test_cbm_tui.c`: snapshot of the
render function for a fixed synthetic state.

## Build / docs

- `Makefile`: add new sources to `cbm-tool`, add 5 test targets.
- `README.md`: document all new modes with safe defaults.
- `ARCHITECTURE.md`: sections 9–12 for the new modules.
- `GAPS.md`: update Gap 2 note — native backend no longer needs the PE at
  runtime; PE remains the validation oracle only.
- `docs/container-format.md`: inferred field map (5C output).

## Verification (all required before claiming done)

1. `make clean && make && make test` — existing 40 tests plus new ones pass.
2. `tea_native_selfcheck` passes with the local vendor PE as oracle.
3. Synthetic scan image finds all planted containers at exact offsets.
4. Doctor dry-run leaves the synthetic image hash unchanged; repair restores
   the expected MBR; missing-safety-flag cases are refused.
5. Fuzz corpus is deterministic per seed and every container roundtrips.
6. `gitleaks detect --source . --no-git --redact` → no leaks.
7. Real-device full scan is a separate gated step, never implied by tests.

## Order of work

5A → 5C (both depend only on the crypto core) → 5B → 5D.
Each wave is one scoped commit after its tests pass. Nothing is pushed until
the user approves the pushed state.
