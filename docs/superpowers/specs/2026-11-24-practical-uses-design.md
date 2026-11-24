# Design: Practical-Uses Wave 5 (5P–5S, fifth complement)

Date: 2026-11-24
Status: draft (awaiting approval)

## Intent

The user selected all four directions from the fifth brainstorm batch. This
spec adds them to the nineteen waves already scoped in:

- `2026-11-24-brag-rights-design.md` (5A–5D)
- `2026-11-24-wild-ideas-design.md` (5E–5H)
- `2026-11-24-community-uses-design.md` (5I–5K)
- `2026-11-24-frontier-uses-design.md` (5L–5O)

Total program: nineteen waves. No code is written until the scope is approved.
Read-only by default; writes stay opt-in with read-back verification.

## 5P — BadUSB trust scanner (`trust.{h,c}`, `docs/device-trust.md`)

### Goal

Detect a Chipsbank-class stick that has been reflashed to present malicious
interfaces (e.g. an unexpected HID keyboard) or to emit unknown commands.

### Approach

- Fingerprint: VID/PID, USB interface descriptor list, MBR/DJ layout, CDB
  behaviour captured by 5E, and firmware marker if 5L obtained a dump.
- A baseline JSON captures the known-good profile of the validated `/dev/sde`
  (serials redacted). `cbm-tool trust <device> [--baseline <json>] [--json]`
  compares and reports each mismatch with a severity.
- Refuse to make any claim about firmware unless a real dump exists; mark
  descriptor-only findings as "host-observable".

### Tests

`test_trust.c`: identical baseline → trust; added HID interface → flagged;
unknown CDB → flagged; missing baseline → fail closed with a clear message.

## 5Q — CBM vault — secret store (`vault.{h,c}`, `docs/vault.md`)

### Goal

Repurpose the encrypted container as a portable secret store.

### Approach

- Honest framing: vault files are a **derived format** using the same TEA
  core and 85688-byte envelope; they are NOT guaranteed to be valid vendor
  containers. Say this in README and in the tool's own output.
- Record format: length-prefixed records (label, value) in the plaintext
  body, with a checksum over all records. Envelope header byte preserved.
- CLI: `cbm-tool vault init <file>`, `put <file> <label> <value>`,
  `get <file> <label>`, `list <file>`, `erase <file> <label>`.
- File-only by default. Any device target requires `--write-back` and the
  existing paced-write + read-back path.

### Tests

`test_vault.c`: put/get roundtrip, list ordering, erase, tamper detection
(checksum mismatch), wrong-key failure, and exact 85688-byte envelope size.

## 5R — exFAT undelete carver (`exfat_carver.{h,c}`, `docs/exfat-carving.md`)

### Goal

Recover deleted files from the DJ_DATA partition using the known layout.

### Approach

- Read-only parse of the exFAT boot sector, FAT, allocation bitmap and root
  directory from the DJ_DATA start LBA obtained via `cbm_layout`.
- Carve entries marked deleted whose metadata and data runs are still intact;
  write recovered bytes only to a caller-named local output directory.
- Scope limit: exFAT only, intact-metadata cases only. Fragmented or
  overwritten files are reported as unrecoverable, not guessed.

### Tests

`test_exfat_carver.c`: synthetic exFAT image with one intact deleted file →
recovered bytes match; one overwritten file → correctly reported lost;
corrupt boot sector → clean error.

## 5S — Live telemetry + Grafana (`telemetry.{h,c}`, `dashboards/cbm.json`)

### Goal

Expose tool and device metrics to the existing Prometheus/Grafana stack.

### Approach

- A local HTTP exporter (`cbm-tool telemetry --listen :PORT`) serving:
  device_present, device_capacity_bytes, scan_progress_ratio,
  containers_found, cdb_commands_total, entropy_blocks_total,
  last_validation_timestamp_seconds, crypto_backend_native.
- Read-only; never opens a device for writing. All values come from existing
  module state or a read-only probe.
- Commit a Grafana dashboard JSON with panels for the above metrics.

### Tests

`test_telemetry.c`: mock state → expected metric names and values; scrubbed
output contains no serial numbers or paths beyond the device basename.

## Updated dependency order

5A → 5G → 5C → 5B → 5E → 5F → 5D → 5H → 5I → 5J → 5K → 5M → 5L → 5N → 5O → 5P → 5Q → 5R → 5S

5P uses 5E's CDB capture and 5L's firmware marker. 5Q uses 5A's core.
5R uses 5B's reader and the layout parser. 5S reads state from all earlier
waves and lands last.

## Verification

1. `make clean && make && make test` after every wave.
2. 5P: baseline match and each anomaly flagged; no firmware claim without a dump.
3. 5Q: put/get/list/erase roundtrip; tamper and wrong-key cases refused.
4. 5R: synthetic exFAT carving recovers intact files and rejects lost ones.
5. 5S: exporter returns expected metrics with no serial leakage.
6. `gitleaks detect --source . --no-git --redact` → no leaks.
7. Hardware, firmware dump, full-device scans and device writes remain gated.

## Honest risks

- 5P cannot detect firmware-level compromise without a real firmware baseline.
- 5Q's derived format must not be advertised as vendor-compatible.
- 5R only handles intact-metadata deletions; coverage is deliberately narrow.
- 5S depends on the monitoring stack being reachable; exporter works standalone.
