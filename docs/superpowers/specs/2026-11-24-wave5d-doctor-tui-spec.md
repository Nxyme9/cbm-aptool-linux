---
title: 'Wave 5D — doctor + live TUI'
type: 'feature'
created: '2026-11-24'
baseline_commit: 'e45b7b6'
status: 'done'
context:
  - 'docs/superpowers/specs/2026-11-24-brag-rights-design.md'
  - 'AGENTS.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The tool can read a stick and validate the DJ layout, but it cannot tell a user *why* a stick is misbehaving, and it has no live view: diagnosing means dumping hex by hand. Repairing a damaged MBR requires an external partition tool that does not know the DJ geometry.

**Approach:** add two read-mostly modes. `cbm-tool doctor <device>` reports geometry, MBR/partition validity and crypto-backend status; with exactly `--repair-mbr --yes --backup <file>` it saves the original sector, writes the reconstructed DJ MBR, and verifies by read-back. `cbm-tool tui <device>` renders a dependency-free ANSI dashboard from the same data, through a pure render function so it is snapshot-testable.

## Boundaries & Constraints

**Always:**
- Dry-run is the default and performs zero writes; without all three of `--repair-mbr`, `--yes` and `--backup <file>` the tool writes nothing.
- Repair order is fixed: read the original 512-byte sector → write it to `--backup` → re-read the backup and compare bytes → write the new MBR → read back and compare → report.
- Block-device writes go through `cbm_file_write` (paced, 40 MiB bursts / 45 s cooldown); no raw `pwrite` on a device.
- Both modes refuse a target whose geometry does not match the DJ scheme (see Design Notes) and refuse any `--backup` path that resolves to the source image.
- The TUI is strictly read-only: no key, including quit, triggers a write, and it opens the source read-only.
- Tests use synthetic regular files under `/tmp/opencode` only; no test opens a real device.
- Exit codes: 0 success, 1 runtime error, 2 usage error.

**Ask First:**
- The DJ-scheme predicate used to authorise repair when the MBR itself is corrupt (Design Note 1).
- Any change to the repair write order or to what may be written without a backup.

**Never:**
- Writing an MBR without a verified backup.
- Partitioning, formatting, or touching any sector beyond LBA 0 during repair.
- A TUI keybinding that mutates state, or a TUI that opens the source `O_RDWR`.
- Claiming a repair succeeded without a read-back comparison.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Dry run | valid DJ image | report only; file hash unchanged | exit 0 |
| Repair | corrupt MBR + all three flags | backup written and verified, MBR rewritten, read-back matches | exit 0 |
| Missing `--yes` | `--repair-mbr --backup f` | no write, no backup | refuse, exit 2 |
| Missing `--backup` | `--repair-mbr --yes` | no write | refuse, exit 2 |
| Non-DJ geometry | capacity/layout mismatch | no write | refuse, exit 1 |
| Backup aliases source | `--backup <device>` | no write | refuse, exit 2 |
| TUI, no device | `tui` | usage | exit 2 |
| TUI, tiny terminal | < 60x20 | compact layout, no crash | exit 0 |

</frozen-after-approval>

## Code Map

- `cbm_layout.h` / `cbm_layout.c` — MBR parse + DJ validation the doctor reuses.
- `cbm_file.h` / `cbm_file.c` — read/write primitive, including paced block-device writes.
- `cbm_scan.h` — cached scan hits the TUI displays.
- `entropy_map.h` — optional entropy summary line for the TUI.
- `nand_info.c` — device/NAND facts for the geometry panel.
- `main.c` — dispatch after `heatmap`, before the legacy device path.
- `Makefile` — new sources plus `test_cbm_doctor` and `test_cbm_tui`.

## Tasks & Acceptance

**Execution:**
- [x] `cbm_doctor.h` / `cbm_doctor.c` — report struct, dry-run diagnosis, guarded repair — isolate every write behind one function so it can be audited alone.
- [x] `test_cbm_doctor.c` — dry-run hash unchanged; repair on a corrupted synthetic MBR restores the expected table; each missing flag is refused; backup aliasing is refused — prove the safety contract, not just the happy path.
- [x] `cbm_tui.c` (+ `cbm_tui.h` if a render signature is shared) — pure render function over a state struct plus a thin terminal loop — snapshot-testable without a tty.
- [x] `test_cbm_tui.c` — snapshot of the render function for a fixed synthetic state, including the tiny-terminal case.
- [x] `main.c` — `doctor` and `tui` subcommands, usage text, dispatch after `heatmap`.
- [x] `Makefile`, `README.md`, `ARCHITECTURE.md`, `GAPS.md` — build wiring, documented safe defaults, test counts.

**Acceptance Criteria:**
- Given a valid DJ image, when `doctor` runs without repair flags, then the image hash is unchanged and the report names the geometry.
- Given a corrupted MBR and all three flags, when `doctor` runs, then the backup matches the original sector and the read-back MBR matches the reconstructed one.
- Given any one missing flag, when `doctor --repair-mbr` runs, then nothing is written and the exit code is 2.
- Given a fixed synthetic state, when the render function runs, then its output is byte-identical across runs and matches the recorded snapshot.
- Given `tui` on an image, when any key is pressed, then no file on disk changes.

## Design Notes

1. **What "matches the known DJ scheme" means when the MBR is corrupt.** The device is ~500 GiB while the MBR window is ~26–28 GiB, so device capacity alone cannot prove the scheme. Recommendation: authorise repair only when (a) the target's first 512 bytes are unparseable or fail `cbm_layout_validate`, AND (b) the user supplies an explicit `--window-gib <N>` (default 26) that must be consistent with the device size, AND (c) the target is a block device or an image of at least that window. Without `--window-gib` the doctor reports the damage but refuses to repair. This keeps the tool from inventing a partition table on an arbitrary disk.
2. **Reconstruction source.** The expected table is computed from the DJ geometry (512 MiB FAT32 / 4 GiB ext4 / rest of the window as exFAT), not copied from another stick.
3. **Snapshot testing.** The TUI render takes a `const cbm_tui_state_t *` and a width/height and returns a heap string; the terminal loop only calls it and writes bytes. This keeps the ANSI output deterministic and testable.

## Verification

**Commands:**
- `make clean && make && make test` — expected: every suite green, including the two new ones.
- `gitleaks detect --source . --no-git --redact` — expected: no leaks.
- A dry-run/repair smoke on synthetic images under `/tmp/opencode` — expected: dry-run hash unchanged; repair produces the expected MBR; both hash and bytes shown in the report.

**Manual checks:**
- Inspect `git diff` for any write path outside the single repair function.
- Confirm no test opens `/dev/*`.

## Suggested Review Order

**Write-path safety (doctor)**

- The only function that writes the target: fixed read → backed-up and verified sector → validated candidate → LBA 0 → read-back sequence.
  [`cbm_doctor.c:250`](../../../cbm_doctor.c#L250)

- The single authorisation predicate shared by the report and the repair gate (unparseable OR DJ-shaped-but-invalid; foreign and valid DJ tables refused).
  [`cbm_doctor.c:115`](../../../cbm_doctor.c#L115)

- Atomic backup claim: `O_EXCL|O_NOFOLLOW`, then `fstat` device/inode comparison against the source before the MBR write.
  [`cbm_doctor.c:155`](../../../cbm_doctor.c#L155)

- Block devices sized with `BLKGETSIZE64`; regular files keep their exact `st_size`.
  [`cbm_doctor.c:43`](../../../cbm_doctor.c#L43)

- CLI gate: all three flags atomic, `--window-gib` 26..28 enforced in both dry-run and repair.
  [`cbm_doctor.c:403`](../../../cbm_doctor.c#L403)

- Failure wording separates a refusal from a post-write verification failure and always names the backup.
  [`cbm_doctor.c:366`](../../../cbm_doctor.c#L366)

**Diagnosis**

- Read-only report; the `Repairable:` line comes from the same predicate as the write gate.
  [`cbm_doctor.c:195`](../../../cbm_doctor.c#L195)

**TUI**

- Pure render entry point: no I/O, deterministic bytes, width-bounded.
  [`cbm_tui.c:251`](../../../cbm_tui.c#L251)

- One-row `n`/`p` scroll arithmetic, unit-tested in isolation.
  [`cbm_tui.c:239`](../../../cbm_tui.c#L239)

- Terminal loop: real size/window/MBR/backend, q/ESC exit, raw mode restored on every path.
  [`main.c:1171`](../../../main.c#L1171)

**Geometry**

- Nominal constructor (512 MiB FAT32 / 4 GiB ext4 / remainder exFAT); conventions documented, never claimed as measured.
  [`cbm_layout.c:28`](../../../cbm_layout.c#L28)

**Tests**

- Alias variants (hardlink, symlink, under-source) and the `O_EXCL` collision partial-step proof.
  [`test_cbm_doctor.c:574`](../../../test_cbm_doctor.c#L574)

- Read-back failure prefix and step reporting.
  [`test_cbm_doctor.c:639`](../../../test_cbm_doctor.c#L639)

- Exact-byte snapshot and the scroll-to-partition-table render.
  [`test_cbm_tui.c:74`](../../../test_cbm_tui.c#L74)

- Doctor dry-run `sha256sum` proof in the shell suite.
  [`test_backend_cli.sh:137`](../../../test_backend_cli.sh#L137)

**Dispatch and docs**

- `doctor` and `tui` dispatch before the legacy device path.
  [`main.c:1315`](../../../main.c#L1315)

- Observed totals and the documented safe defaults.
  [`README.md:87`](../../../README.md#L87)
