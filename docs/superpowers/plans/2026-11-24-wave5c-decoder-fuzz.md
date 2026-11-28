# Wave 5C: Format decoder + fuzz lab (`cbm_decode`, `cbm_diff`, `cbm_fuzz`)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]` checkboxes.

**Goal:** Turn the decrypted 85687-byte container body into an analysable object: entropy profile and region labels, a two-file diff with context merging, and a deterministic seeded fuzz lab that proves decrypt→encrypt identity while writing only to an explicit `--out` directory.

**Architecture:** Three small modules with one responsibility each. `cbm_decode` computes entropy and classifies byte ranges (constant / string-like / opaque). `cbm_diff` compares two plain bodies and reports merged change ranges plus entropy delta. `cbm_fuzz` mutates a container body deterministically, re-encrypts, verifies identity, and writes corpus files only under `--out`. CLI subcommands `diff` and `fuzz` are wired in `main.c` before the device path.

**Tech Stack:** C99, `gcc -m32 -Wall -Wextra -O2 -g`, existing `cbm_container`/`cbm_inspect`/`tea_crypto` modules, existing Makefile test harness.

**Spec:** `docs/superpowers/specs/2026-11-24-brag-rights-design.md` §Wave 5C (lines 91-117).

## Global Constraints

- Offline only: no device access, no vendor binary needed, no writes outside `--out`.
- `fuzz` MUST refuse a block-device target and MUST never write to the source container path.
- Determinism: the same `--seed`, `--mutate` and `--rounds` produce byte-identical corpus files and names. A test asserts this by hashing two runs.
- Identity: every generated container must satisfy `decrypt(body) → encrypt → identical body bytes` (TEA CBC roundtrip), and the 1-byte header must be preserved.
- `diff` output: changed ranges (merged when the gap between changes is `<= --context N`, default 3), changed-byte count, entropy delta for each side, and a printable-density ("text") heatmap. Swapping arguments must yield the same ranges (symmetry).
- No reads past `buf+len` anywhere; all lengths `size_t`; 32-bit overflow-safe arithmetic.
- CLI shapes (exact):
  - `cbm-tool diff <a.plain> <b.plain> [--context N]`
  - `cbm-tool fuzz <container> --mutate N --rounds N --seed N [--out <dir>]`
  - Subcommands are dispatched in `main()` BEFORE the block-device path, and must not collide with `cbm-tool <blockdev>` or `cbm-tool container`.
- `cbm-tool` with no args still runs the self-test; existing modes unchanged.
- Build flags unchanged. All 72 existing checks stay green; new tests add to the count.
- Docs: publish `docs/container-format.md` with explicit **inferred** markers; never claim the field map is complete. Keep test counts consistent across README.md / ARCHITECTURE.md / GAPS.md / BRAG-RIGHTS.md.
- No vendor binary, key leak, or device serial committed; TEA key stays allowlisted in `.gitleaks.toml`.

## Review Focus

- Bounds: every window/index computation uses `size_t` with an explicit `off + win <= len` guard; empty and 1-byte inputs are covered by tests.
- Determinism: no `time()`, no `rand()` without a seeded state, no address-dependent ordering, no locale-dependent formatting in file names or corpus content.
- Fuzz safety: `--out` directory required for writes; refuse `cbm_file_is_blockdev(source)`; refuse `--out` equal to the source path.
- Diff symmetry and merge semantics pinned by tests (identical files, one-byte change, adjacent merge, reversed args).
- `main.c` dispatch order: `diff`/`fuzz` recognized before `verify_device(argv[1])`; unknown option handling prints usage with exit 2.

---

### Task 1: `cbm_decode` — entropy profile and region classification

**Files:** Create `cbm_decode.h`, `cbm_decode.c`, `test_cbm_decode.c`; modify `Makefile`.

**Interfaces:**
- Produces:
  - `double cbm_decode_entropy(const unsigned char *buf, size_t len);` — Shannon entropy in bits/byte (0.0 for `len == 0`).
  - `typedef enum { CBM_REGION_CONSTANT, CBM_REGION_STRING, CBM_REGION_OPAQUE } cbm_region_kind_t;`
  - `typedef struct { size_t offset; size_t length; cbm_region_kind_t kind; } cbm_region_t;`
  - `size_t cbm_decode_regions(const unsigned char *buf, size_t len, cbm_region_t *out, size_t max);` — windowed classification (window 64 B): all-equal bytes → CONSTANT; printable density ≥ 0.85 → STRING; otherwise OPAQUE. Adjacent windows of the same kind merge into one region. Returns the number of regions written (capped at `max`), and `0` when `buf == NULL` or `len == 0`.
  - `void cbm_decode_profile(const unsigned char *buf, size_t len, FILE *out);` — prints per-window entropy to `out` as text rows `offset length entropy kind` (machine-readable enough to assert in tests).
- Consumes: nothing beyond libc (no TEA, no PE).

- [ ] **Step 1: Write failing tests** in `test_cbm_decode.c`: `test_entropy_constant` (all-zero 1024 B → 0.0), `test_entropy_uniform` (all 256 byte values once → 8.0 ± 1e-9), `test_entropy_empty` (0.0, no crash), `test_regions_constant` (4 KiB uniform → one CONSTANT region spanning it), `test_regions_string` (ASCII run → STRING region), `test_regions_opaque` (pseudo-random → OPAQUE), `test_regions_merge_adjacent` (two same-kind windows merge), `test_regions_cap` (max smaller than region count is honoured), `test_profile_does_not_read_past` (1-byte buffer, exact allocation). Run `make test_cbm_decode && ./test_cbm_decode` → link failure (RED).
- [ ] **Step 2: Implement `cbm_decode.{h,c}`** with the interfaces above; entropies computed from a 256-entry `size_t` histogram, no floating-point accumulation of per-byte logs beyond `log2`.
- [ ] **Step 3: Run tests** → all green; ASan build `-m32 -fsanitize=address` clean.
- [ ] **Step 4: Commit** scoped paths: `cbm_decode.h cbm_decode.c test_cbm_decode.c Makefile`. Message: `feat(decode): add entropy profile and container body region classifier`.

### Task 2: `cbm_diff` — two-body diff with context merging

**Files:** Create `cbm_diff.h`, `cbm_diff.c`, `test_cbm_diff.c`; modify `Makefile`.

**Interfaces:**
- Produces:
  - `typedef struct { size_t offset; size_t length; size_t changed; } cbm_diff_range_t;`
  - `size_t cbm_diff_ranges(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t context, cbm_diff_range_t *out, size_t max);` — byte-range diff of the common prefix plus a trailing change range when lengths differ. Ranges closer than `context` bytes merge. Returns the number of ranges written (capped).
  - `size_t cbm_diff_changed_bytes(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen);`
  - `void cbm_diff_print(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen, size_t context, FILE *out);` — prints range list, changed-byte count, entropy of each side (via `cbm_decode_entropy`), and a printable-density heatmap line per range.
- Consumes: `cbm_decode_entropy` from Task 1.

- [ ] **Step 1: Write failing tests** in `test_cbm_diff.c`: `test_identical_no_ranges` (0 ranges, 0 changed bytes), `test_single_byte_change` (1 range at the right offset, 1 changed byte), `test_adjacent_merge` (two changes 1 byte apart, context 3 → one range), `test_separate_ranges` (two changes 100 bytes apart, context 3 → two ranges), `test_reversed_symmetry` (swap a/b → same offsets and lengths), `test_length_difference` (b longer → trailing range reported), `test_empty_inputs` (both empty and one empty, no crash). RED.
- [ ] **Step 2: Implement `cbm_diff.{h,c}`** with context merging and entropy delta; no locale-dependent output.
- [ ] **Step 3: Run tests** → all green; ASan clean.
- [ ] **Step 4: Commit** scoped paths. Message: `feat(diff): add context-merged body diff with entropy delta`.

### Task 3: `cbm_fuzz` + CLI wiring + format docs

**Files:** Create `cbm_fuzz.h`, `cbm_fuzz.c`, `test_cbm_fuzz.c`, `docs/container-format.md`; modify `main.c`, `Makefile`, `README.md`, `ARCHITECTURE.md`, `GAPS.md`, `BRAG-RIGHTS.md`.

**Interfaces:**
- Produces:
  - `int cbm_fuzz_run(const char *container_path, const char *out_dir, unsigned mutate, unsigned rounds, unsigned long seed, char *err, size_t errlen);` — loads the 85688-byte container, decrypts the body, then for each round applies `mutate` deterministic mutations (xorshift64* seeded by `seed`), re-encrypts, verifies bytes changed back exactly, and writes `<out>/round-NNN.cbm` plus a `manifest.txt` with per-file sha256 and the mutation list. Returns 0 on success; refuses block devices.
  - CLI: `diff` and `fuzz` subcommands in `main.c` with usage text and exit codes (0 ok, 1 runtime error, 2 usage error).
- Consumes: `cbm_container` (encrypt/decrypt), `cbm_decode_entropy` and `cbm_diff_print` for the `diff` command, `cbm_file_read/write` for loading and output.

- [ ] **Step 1: Write failing tests** in `test_cbm_fuzz.c`: `test_same_seed_same_corpus` (two runs into two dirs → identical file names, sizes and sha256), `test_roundtrip_identity` (each corpus file decrypts to the mutated body and re-encrypts back byte-identically), `test_header_preserved` (byte 0 unchanged), `test_refuses_block_device` (a fake blockdev path fixture or skip with printed reason), `test_refuses_source_as_out` (out dir equal to source dir is rejected). RED.
- [ ] **Step 2:** Implement `cbm_fuzz.{h,c}`, wire `diff`/`fuzz` in `main.c` before the device path, add Makefile targets, write `docs/container-format.md` (entropy/region observations with **inferred** markers, honest incompleteness), update docs counts.
- [ ] **Step 3:** Run `make clean && make && make test && sh test_backend_cli.sh` → all green; smoke `./cbm-tool diff` and `./cbm-tool fuzz` on a scratch container in `/tmp/opencode`; `gitleaks detect --source . --no-git --redact` → no leaks.
- [ ] **Step 4: Commit** scoped paths. Message: `feat(fuzz): add deterministic fuzz lab and diff/fuzz CLI`.

## Exit Criteria

- New suites green; all prior checks still green; counts consistent across docs.
- `diff` and `fuzz` usable offline with no vendor binary; `fuzz` writes only under `--out`.
- `docs/container-format.md` published with inferred markers and honest gaps.
- gitleaks clean; no vendor binary committed; final whole-branch review clean.
