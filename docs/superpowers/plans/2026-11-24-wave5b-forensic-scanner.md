# Wave 5B: Forensic scanner (`cbm_scan`, `cbm-tool scan`)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]` checkboxes.

**Goal:** Find CBM containers anywhere inside a regular image or block device, read-only by default. Report each candidate with byte offset, header byte, decrypted-body entropy, sha256, and a short printable-token summary; optionally carve hits and emit a JSON report to explicit local paths.

**Architecture:** One library `cbm_scan.{h,c}` with a pure buffer scan primitive plus a chunked file/device walker. Detection is two-stage: (1) candidate offsets from configurable magic strings **and** an optional structural probe at 512-byte-aligned offsets; (2) a 85688-byte container parse + TEA decrypt + plausibility gate at each candidate. The `cbm-tool scan` CLI drives it. No device is read in tests — synthetic images only.

**Tech Stack:** C99, `gcc -m32 -Wall -Wextra -O2 -g`, existing `cbm_file_read`, `cbm_fuzz_sha256`, `cbm_decode_entropy`, `cbm_container`, `tea_*`.

**Spec:** `docs/superpowers/specs/2026-11-24-brag-rights-design.md` §Wave 5B (lines 61-89).

## Global Constraints

- **Read-only by default.** No writes of any kind unless `--carve <dir>` or `--json <path>` is explicitly given, and those write only to the given local paths. The scanner NEVER calls `cbm_file_write`.
- **No live device in build/tests.** All tests use synthetic regular files under `/tmp/opencode`. A full 500 GiB read of `/dev/sde` is a separate hardware-gated step, never implied by the build.
- `cbmv1001` from the spec is **UNVERIFIED** (see `docs/container-format.md:64`: magic values are explicitly unknown). Do NOT treat it as authoritative. Detection must work from the structural probe alone when no magic is configured; magic hits are candidates that still must pass the parse+decrypt+plausibility gate. Document this honestly.
- Chunked reads with overlap **>= 85688 bytes** (`CBM_CONTAINER_SIZE`) so a container straddling a chunk boundary is found exactly once. A test plants two containers near a chunk boundary and asserts exact offsets with no duplicates.
- LBA = 512 bytes. `--start`/`--end` are inclusive LBAs (default 0 to end of image); `--chunk MiB` default 8, minimum 1.
- Every reported hit records: byte offset (64-bit), header byte (byte 0 copied verbatim), decrypted-body entropy (via `cbm_decode_entropy`), sha256 of the **encrypted** 85688-byte container (via `cbm_fuzz_sha256`), and up to 8 printable tokens (runs >= 4 chars, `0x20-0x7e`) with their offsets.
- Plausibility gate must be explicit and documented as **heuristic**: decrypt must produce a body whose entropy/printable density is non-degenerate. Mark hits as candidates, not "confirmed containers". False-positive magic must be rejected by this gate.
- Bounds: every read guarded; 64-bit offset arithmetic; no read past chunk end; no 32-bit truncation of device offsets.
- Determinism: same image + options → same hit order (ascending offset) and same report bytes. Locale-independent numeric formatting (reuse the fixed-point `%u.%06u` pattern from `cbm_decode`; no `%.6f`).
- CLI: `cbm-tool scan <device> [--start LBA] [--end LBA] [--chunk MiB] [--carve <dir>] [--json <report>]`; exit 0 ok / 1 runtime error / 2 usage error. Dispatch in `main()` after `fuzz` and before the legacy device path, without colliding with `cbm-tool <blockdev>`.
- Current baseline: 99 checks across 14 suites. All prior checks stay green; new tests add to the count and docs are updated consistently.
- Build flags unchanged; no vendor binary/key/serial committed; TEA key stays allowlisted in `.gitleaks.toml`.

## Review Focus

- No device write path reachable from `scan`; `--carve`/`--json` write only to explicit paths and refuse to alias the source image.
- Overlap math correct: a container starting in the tail overlap of chunk N must be found once, not twice or zero times.
- Magic is advisory; structural probe alone finds a planted container with no magic present.
- Plausibility gate rejects false-positive magic without rejecting real planted containers.
- JSON escaping correct for token strings; no locale-dependent numbers.

---

### Task 1: `cbm_scan` core — buffer scan + chunked walker + synthetic-image tests

**Files:** Create `cbm_scan.h`, `cbm_scan.c`, `test_cbm_scan.c`; modify `Makefile`, `.gitignore`.

**Interfaces:**
- `typedef struct { unsigned long long offset; unsigned char header; double entropy; unsigned char sha256[32]; char tokens[8][64]; unsigned long long token_offsets[8]; size_t token_count; } cbm_scan_hit_t;`
- `size_t cbm_scan_buffer(const unsigned char *buf, size_t len, const char *const *magics, size_t nmagic, int structural, unsigned long long base_offset, cbm_scan_hit_t *out, size_t max);` — scan one contiguous buffer; returns hits written (capped); `base_offset` is the buffer's absolute byte offset so reported offsets are absolute.
- `int cbm_scan_image(const char *path, unsigned long long start_byte, unsigned long long end_byte, size_t chunk_bytes, const char *const *magics, size_t nmagic, cbm_scan_hit_t **out, size_t *out_count, char *err, size_t errlen);` — chunked walker using `cbm_file_read`; allocates the hit array; caller frees. Return 0 ok / -1 error with message.
- `void cbm_scan_free_hits(cbm_scan_hit_t *hits);`
- `void cbm_scan_print(FILE *out, const cbm_scan_hit_t *hits, size_t n);` — deterministic, locale-free text report.

- [ ] **Step 1: Write failing tests** in `test_cbm_scan.c`: `test_empty_image` (0 hits), `test_one_container_known_offset` (plant a valid 85688-byte container at a known offset in a scratch image; assert exact offset, header byte, sha256), `test_two_containers_chunk_boundary` (choose chunk size so two containers straddle a boundary; assert both offsets, no duplicates), `test_false_positive_magic` (magic bytes with garbage after them → 0 hits), `test_structural_no_magic` (valid container with its magic area zeroed → still found by structural probe), `test_range_lba` (`--start`/`--end` equivalent byte range excludes a planted container outside it), `test_short_image` (image smaller than one container → 0 hits, no over-read). RED = link failure.
- [ ] **Step 2: Implement `cbm_scan.{h,c}`**. Reuse `cbm_fuzz_sha256`, `cbm_decode_entropy`, `cbm_container` offsets, and the tea dispatcher; do not reimplement crypto, entropy or hashing. Magic comparison is case-sensitive byte match; NULL magic list means structural-only.
- [ ] **Step 3: Run tests** → all green; ASan build `-m32 -fsanitize=address` clean (exact-size buffers at chunk tails).
- [ ] **Step 4: Commit** scoped paths. Message: `feat(scan): add read-only chunked CBM container scanner`.

### Task 2: `scan` CLI + carve/JSON report writers

**Files:** Create `cbm_scan_report.{h,c}`, `test_cbm_scan_report.c`; modify `main.c`, `Makefile`, `.gitignore`, `README.md`, `ARCHITECTURE.md`, `GAPS.md`, `BRAG-RIGHTS.md`.

**Interfaces:**
- `int cbm_scan_write_json(const char *path, const cbm_scan_hit_t *hits, size_t n, char *err, size_t errlen);` — JSON array with fields `offset`, `header`, `entropy`, `sha256`, `tokens` (escaped); deterministic field order.
- `int cbm_scan_carve(const char *dir, const char *source, const cbm_scan_hit_t *hits, size_t n, char *err, size_t errlen);` — for each hit, read the exact 85688 bytes from `source` at `hit.offset` and write `<dir>/hit-NNN-<offset>.cbm` via stdio; refuse when `dir` resolves to the source image or its parent contains the source with the same inode. Never writes the source.
- CLI `scan_mode()` in `main.c` with the exact option grammar above, usage text, and exit codes.

- [ ] **Step 1: Write failing tests** in `test_cbm_scan_report.c`: `test_json_deterministic` (two writes byte-identical), `test_json_escape` (token containing `"` and `\` escaped), `test_carve_names_and_bytes` (carve from a synthetic image, assert file names and exact bytes), `test_carve_refuses_source_alias` (`--carve` pointing at the source file is rejected). RED.
- [ ] **Step 2:** Implement report writers and wire `scan` into `main.c` in the exact position; add Makefile targets; update docs with the new CLI and honest "magic unverified / structural probe" wording; update test counts.
- [ ] **Step 3:** `make clean && make && make test && sh test_backend_cli.sh` → all green; smoke `./cbm-tool scan <synthetic image> --json <tmp> --carve <tmpdir>` in `/tmp/opencode`; `gitleaks detect --source . --no-git --redact` → no leaks.
- [ ] **Step 4: Commit** scoped paths. Message: `feat(scan): add scan CLI with JSON report and carving`.

## Exit Criteria

- All prior checks green plus new scan suites; counts consistent across docs.
- Scanner is read-only by default; `--carve`/`--json` write only to explicit paths; no device touched in build/tests.
- Overlap and structural-only detection proven by tests; magic correctly treated as advisory.
- gitleaks clean; no vendor binary committed; final whole-branch review clean.
- Real-device scan remains an explicit hardware-gated step, not part of this wave.
