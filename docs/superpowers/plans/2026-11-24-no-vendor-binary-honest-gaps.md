# No-vendor-binary and honest-gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** make `no vendor binary needed` literal in build/tests/normal CLI modes, close the scanner's cluster-suppression limitation, harden compiler warnings, and give every remaining gap an honest disposition.

**Architecture:** keep the native TEA backend as the sole default; make the PE backend explicitly opt-in through `CBM_PE_PATH` with no silent `/tmp/opencode/ap.exe` fallback. Add an opt-in exhaustive scanner mode instead of weakening the default dedupe. Record measured counts from logs, never guessed.

**Tech Stack:** C (`gcc -m32 -Wall -Wextra -O2 -g`, `-lz`), POSIX shell tests, scoped git commits.

**Spec:** `docs/superpowers/specs/2026-11-24-no-vendor-binary-honest-gaps-design.md`

## Global Constraints

- No vendor binary, key leak or device serial is committed; TEA key stays allowlisted in `.gitleaks.toml`.
- No real device is touched; tests use synthetic regular files under `/tmp/opencode` only.
- `cbm_backend_from_arg`, `tea_init`, `tea_encrypt`, `tea_decrypt`, `cbm_backend_set/get` keep their signatures.
- `cbm_scan_image` keeps its signature; new capability is an added `cbm_scan_image_ex`.
- Zero hardcoded `/tmp/opencode/ap.exe` literals in shipped code, tests and CLI harness; historical `docs/superpowers/specs/*` and `docs/superpowers/plans/*` records stay untouched.
- Scoped commits only; no `git add .`/`-A`, no `--no-verify`, no stash, no deletions of user files.
- All numbers recorded in docs must be copied from measured logs produced on this tree.

## Review Focus

- Unset `CBM_PE_PATH` with `--pe-crypto`: must exit nonzero with a message naming `CBM_PE_PATH`, never a NULL `%s` or a crash. Test: `env -u CBM_PE_PATH ./cbm-tool --pe-crypto` in the CLI harness.
- `make test` with no vendor PE on the machine: PE-only cases skip honestly, native cases still pass, no FAIL. Test: run the full chain with `CBM_PE_PATH` pointed at a nonexistent file.
- Two distinct containers starting less than 85688 bytes apart: default scan reports one, `--all-hits` reports two. Test: synthetic image in `test_cbm_scan.c`.
- Sysfs paths longer than the destination buffers: bounded join returns -1 without truncation or warning. Test: `test_nand.c` long-path cases.
- Docs counts: with-PE and without-PE numbers come from two separate measured logs. Test: grep the docs against the two logs in the final review.

---

### Task 1: Vendor-binary independence (code + tests + CLI harness)

**Files:**
- Modify: `main.c:93-110,348-356,705-712,863-871`
- Modify: `pelib.c:17,198-201`
- Modify: `test_tea.c:18-28,86-96`
- Modify: `test_tea_native.c:11,127-135`
- Modify: `test_pelib.c:104-107` and every case that calls `real_pe_path()`
- Modify: `test_backend_cli.sh:8,80-96`
- Test: `test_backend_cli.sh`, `test_pelib`, `test_tea`, `test_tea_native`

**Interfaces:**
- Consumes: existing `tea_init(const char *)`, `cbm_backend_get()`, `pe_load(pe_image_t **, const char *, pe_import_hook_t *)`.
- Produces: no new public symbols. `pe_load(NULL, ...)` still reads `CBM_PE_PATH`; when that is unset/empty it fails with an error naming `CBM_PE_PATH` (no default path).

- [ ] **Step 1: write the failing CLI cases** in `test_backend_cli.sh`:
  - `pe-no-env`: `env -u CBM_PE_PATH ./cbm-tool --pe-crypto` exits nonzero and combined output contains `CBM_PE_PATH`.
  - `native-bogus-pe`: with `CBM_PE_PATH=$MISSING_PE`, `./cbm-tool --native-crypto` still exits 0 and prints `Crypto backend: native (clean-room)`.
  - Set `PE_PATH=${CBM_PE_PATH:-}` (no literal fallback). Keep the existing PE cases as SKIPs when no path/file is supplied.
  - Run `sh ./test_backend_cli.sh` and confirm the new cases FAIL before implementation.
- [ ] **Step 2: remove the production fallback** in `pelib.c` (delete `DEFAULT_PE_PATH`; `pe_load` uses env only, else errors) and in `main.c` (one helper returning `getenv("CBM_PE_PATH")` or NULL; guard `print_pe_selfcheck` against NULL; in each PE-mode branch, if backend is PE and path is NULL, print an error naming `CBM_PE_PATH` and exit nonzero before `tea_init`).
- [ ] **Step 3: make tests PE-optional** in `test_tea.c`, `test_tea_native.c`, `test_pelib.c`: replace literal defaults with env-only helpers; PE-only cases print `SKIP (CBM_PE_PATH not set)` and return without incrementing pass/fail; synthetic-PE cases and all native cases still run.
- [ ] **Step 4: verify** both modes and record logs:
  - `CBM_PE_PATH=/tmp/opencode/does-not-exist.exe sh ./test_backend_cli.sh` → 0 failures, PE cases SKIP.
  - `CBM_PE_PATH=/tmp/opencode/ap.exe sh ./test_backend_cli.sh` → PE cases PASS (oracle still works when user supplies it).
  - `CBM_PE_PATH=/tmp/opencode/does-not-exist.exe make clean && make && make test` → 0 failures.
  - `grep -rn '/tmp/opencode/ap.exe' main.c pelib.c test_tea.c test_tea_native.c test_pelib.c test_backend_cli.sh` → no matches.
  - Save both logs to `/tmp/opencode/nohl-with-pe.log` and `/tmp/opencode/nohl-without-pe.log`.
- [ ] **Step 5: commit** scoped paths with message `fix(pe): remove vendor binary defaults, make PE explicitly opt-in`.

### Task 2: Harden `nand_info.c` path truncation

**Files:**
- Modify: `nand_info.h`, `nand_info.c`, `test_nand.c`

**Interfaces:**
- Consumes: existing `nand_info_probe`, `nand_info_is_chipsbank`.
- Produces: `int nand_info_join_path(char *dst, size_t dstlen, const char *base, const char *leaf);` — returns 0 on success, -1 when the result would not fit; on -1 leaves `dst[0] = '\0'`; NUL-terminates on success.

- [ ] **Step 1: add failing tests** in `test_nand.c` for `nand_info_join_path`: normal join, base exactly filling buffer minus leaf, overflow by one byte, empty base, NULL arguments (all must fail cleanly with `dst` empty). Run `make test_nand && ./test_nand` → FAIL (symbol missing).
- [ ] **Step 2: implement the helper** in `nand_info.c` with explicit length arithmetic before writing, and replace the seven `snprintf` sites in `resolve_usb_dir`/`find_driver`/`nand_info_probe` with it.
- [ ] **Step 3: verify** `make clean && make 2>&1 | tee /tmp/opencode/nohl-build.log` contains zero `warning:` lines; `./test_nand` reports all PASS.
- [ ] **Step 4: commit** scoped paths with message `fix(nand): bound sysfs path joins and remove truncation warnings`.

### Task 3: Opt-in exhaustive scanner (`--all-hits`)

**Files:**
- Modify: `cbm_scan.h`, `cbm_scan.c`, `main.c`, `test_cbm_scan.c`

**Interfaces:**
- Consumes: existing `cbm_scan_image` and its hit array contract.
- Produces: `int cbm_scan_image_ex(const char *path, unsigned long long start_byte, unsigned long long end_byte, size_t chunk_bytes, const char *const *magics, size_t nmagic, int suppress_clusters, cbm_scan_hit_t **out, size_t *out_count, char *err, size_t errlen);` — identical behaviour to `cbm_scan_image` except `suppress_clusters == 0` keeps every candidate (including two distinct containers less than one container apart). `cbm_scan_image` delegates with `suppress_clusters = 1`. CLI flag: `--all-hits`, valid only with `scan`.

- [ ] **Step 1: add failing tests** in `test_cbm_scan.c`: build a synthetic image containing two structurally valid containers starting 4096 bytes apart; assert `cbm_scan_image` returns exactly 1 hit and `cbm_scan_image_ex(..., 0, ...)` returns exactly 2 hits with the expected offsets; assert `--all-hits` is rejected outside scan mode at CLI level. Run the test → FAIL (symbol/flag missing).
- [ ] **Step 2: implement `cbm_scan_image_ex`** by factoring the current body; keep ascending qsort, bounds checks and the 171888-byte overlap unchanged. Skip only the cluster-collapse loop when `suppress_clusters == 0`. Wire `--all-hits` into `main.c` scan flag parsing; reject it with exit 2 elsewhere.
- [ ] **Step 3: verify** `make clean && make && make test` → 0 failures; record the new pass count.
- [ ] **Step 4: commit** scoped paths with message `feat(scan): add opt-in --all-hits to report close containers`.

### Task 4: Honest gap ledger and measured documentation

**Files:**
- Modify: `GAPS.md`, `README.md`, `ARCHITECTURE.md`, `BRAG-RIGHTS.md`, `docs/container-format.md`, `docs/pe-call.md`

**Interfaces:**
- Consumes: measured logs `/tmp/opencode/nohl-with-pe.log`, `/tmp/opencode/nohl-without-pe.log`, final full-chain log.
- Produces: no code symbols.

- [ ] **Step 1: rewrite `GAPS.md`** so each of the five gaps has a `Disposition` line from the spec table: closed / partially closed / open + exact gate. State that no vendor binary is needed for build, test, container/decode/diff/fuzz/scan/doctor/tui; PE is an explicit opt-in cross-check. Remove the claim that the scanner cannot report close containers (Task 3 closes it) and replace it with the `--all-hits` note plus the still-open magic/schema confirmation gate.
- [ ] **Step 2: align README/ARCHITECTURE/BRAG-RIGHTS** counts with the measured with-PE and without-PE logs; document `--all-hits` and `CBM_PE_PATH`; keep the `nx-cbm-lab` name and 214-char description.
- [ ] **Step 3: verify** `grep -rnE '/tmp/opencode/ap.exe|\b155\b|\b172\b' README.md ARCHITECTURE.md GAPS.md BRAG-RIGHTS.md docs/container-format.md docs/pe-call.md` → no stale literals; every documented count appears in a measured log.
- [ ] **Step 4: commit** scoped paths with message `docs: publish honest gap dispositions and measured no-vendor counts`.

### Final verification (controller, not a task)

- Full chain with and without PE, ASan on doctor/TUI, shellcheck, gitleaks, zero compiler warnings, no device touched.
- Push to `feat/wave5-clean-tea` is a separate approval gate; do not push as part of a task.
