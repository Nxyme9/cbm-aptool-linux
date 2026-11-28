# Wave 5G: Wine-less PE framework (`pelib` + `pe-call`)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]` checkboxes.

**Goal:** Extract the mmap-at-ImageBase PE loader from `tea_crypto.c` into a reusable 32-bit PE library with a callable API, and prove it byte-identical to the current harness by calling the vendor TEA core through the generic interface.

**Architecture:** `pelib.{h,c}` owns header/section parsing, fixed-base mapping, RVA→VA translation, export lookup and optional DLL-import hooks. `tea_crypto.c` becomes a thin wrapper with unchanged observable behaviour. `pe-call` is an exploratory CLI that calls one RVA/export with a hex-encoded argument buffer.

**Tech Stack:** C99, `gcc -m32 -Wall -Wextra -O2 -g`, mmap-at-ImageBase (`BASE 0x400000`, `MAPSZ 0x140000`), existing Makefile/test harness.

**Spec:** `docs/superpowers/specs/2026-11-24-wild-ideas-design.md` §5G.

## Global Constraints

- API from spec (names/signatures exact):
  - `typedef struct pe_image pe_image_t;`
  - `int pe_load(pe_image_t **img, const char *path, const pe_import_hook_t *hooks);`
  - `int pe_call_void(pe_image_t *img, uint32_t rva_or_va, void *arg, size_t n);`
  - `void *pe_rva_to_va(pe_image_t *img, uint32_t rva);`
  - `int pe_export(pe_image_t *img, const char *name, uint32_t *out_rva);`
  - `void pe_unload(pe_image_t *img);`
- `pe_import_hook_t` lets callers supply stubs for selected DLL imports (substrate for 5E). Define its exact shape in `pelib.h`.
- Only 32-bit x86 PEs; ImageBase `0x400000`; no relocations applied; `__stdcall` call sites.
- One PE at a time (fixed base). `pe_load` fails cleanly if a mapping is already live; `pe_unload` releases it.
- Vendor PE path: `CBM_PE_PATH` env override, default `/tmp/opencode/ap.exe`. Never commit a vendor binary.
- Golden equivalence: calling TEA encrypt RVA `0x459da0` through `pe_call_void` on the 8-byte zero block with key `"1a2b3c4d5e6fTENG"` and state at `0x531328` zeroed must yield `e66254b5da09fb31`; decrypt `0x459d50` must roundtrip. Byte-identical to the current `tea_crypto.c` PE backend.
- `tea_crypto.{h,c}` public API and observable behaviour (backend lines, no silent fallback, 53 existing tests) must not change.
- Build flags unchanged. All 53 existing tests across 10 suites stay green.
- No vendor binary, key leak, or device serial committed; key stays allowlisted in `.gitleaks.toml`.

## Review Focus

- Bounds checks: header offsets (`e_lfanew`, section count/table, optional header size) validated before every read, including the 32-bit overflow case flagged in Wave 5A (`tea_crypto.c:87-93`). Pinned by malformed-PE tests.
- `pe_call_void` zero-initialises state at `0x531328` before the call and passes `__stdcall`. Pinned by golden-vector test through the generic API.
- `pe_unload` frees mapping and allows exactly one subsequent `pe_load`; no double-munmap. Pinned by load/unload/reload test.
- Import hooks actually dispatch (not just stored). Pinned by a test with a stub hook recording a call.
- `tea_crypto.c` wrapper keeps PE backend behaviour: PE-mode CLI test from 5A still passes.

---

### Task 1: `pelib` core loader + malformed-PE tests

**Files:** Create `pelib.h`, `pelib.c`, `test_pelib.c`; modify `Makefile`.

**Interfaces:**
- Consumes: PE layout constants from Global Constraints and `PE-HARNESS.md`.
- Produces: `pe_load`, `pe_rva_to_va`, `pe_unload` (exact signatures above) plus `pe_import_hook_t` definition. `pe_load` parses DOS/NT headers, validates all offsets with overflow-safe arithmetic, maps sections at ImageBase, populates hooks. `pe_rva_to_va` returns a pointer inside the mapped image for a valid RVA, `NULL` otherwise. `pe_unload` releases the mapping and clears the singleton.

- [ ] **Step 1: Write failing tests** in `test_pelib.c`: `test_load_real_pe` (load `/tmp/opencode/ap.exe` or `CBM_PE_PATH`, assert non-NULL, valid `pe_rva_to_va` for `0x59da0`), `test_bad_magic`, `test_truncated_header`, `test_section_table_overflow`, `test_unload_allows_reload`, `test_rva_out_of_range`. Run `make test_pelib && ./test_pelib` → link failure (RED).
- [ ] **Step 2: Implement `pelib.{h,c}`** with the three functions and bounds checks. Keep all parsing in one file; no caller changes yet.
- [ ] **Step 3: Run tests** → all green; ASan build `-m32 -fsanitize=address` clean.
- [ ] **Step 4: Commit** scoped paths: `pelib.h pelib.c test_pelib.c Makefile`. Message: `feat(pe): add reusable 32-bit PE loader with bounds checks`.

### Task 2: Generic call API, exports, import hooks, `pe-call` CLI

**Files:** Modify `pelib.h`, `pelib.c`, `test_pelib.c`; create `pe-call.c` and `docs/pe-call.md`; modify `Makefile`.

**Interfaces:**
- Produces: `pe_call_void`, `pe_export`, and `pe_import_hook_t` dispatch. `pe-call <pe-path> <rva|export-name> <hex-args>` maps the PE, calls the target with the decoded argument buffer, prints the buffer as hex after the call, and unloads. Exit 0 on success.
- Import hook struct: define `{ const char *dll; const char *name; void (*fn)(void); }` array terminated by a zero entry; dispatch when a target function calls a hooked import (test with a stub target if needed, or document the limits of static detection).

- [ ] **Step 1: Write failing tests** in `test_pelib.c`: `test_golden_encrypt_via_pelib` (zero 8-byte block → `e66254b5da09fb31`), `test_golden_decrypt_roundtrip`, `test_export_lookup` (look up a known export or assert clean not-found), `test_import_hook_dispatch`. RED.
- [ ] **Step 2:** Implement `pe_call_void` (zero state at `0x531328`, `__stdcall` function pointer), `pe_export` (parse export directory), hook dispatch, and `pe-call.c` CLI.
  - **Argument ABI (binding):** `arg` points to a packed array of `uint32_t` words; `n` is its byte length. The target is invoked through a `void (__attribute__((stdcall)) *)(uint32_t, uint32_t, uint32_t)` pointer with exactly three words (zero-fill missing words; reject `n > 12` or `n % 4 != 0` with -1). This matches the vendor TEA core signature `(unsigned char *buf, int len, const char *key)`: `args[0]` = address of the block (caller buffer is fine under -m32), `args[1]` = 8, `args[2]` = address of the key string. A 3-arg stdcall callee cleans its own stack, so the caller must not push extra words. Document this limit in `pelib.h`.
  - `pe-call <pe-path> <rva|export-name> <hex-args>` decodes `hex-args` as the packed little-endian uint32 word array, calls the target, then prints the decoded `arg` buffer back as hex so in-place mutations are visible.
- [ ] **Step 3:** `make clean && make && make test` → all green including 5A's 53 tests and new `test_pelib` cases; `pe-call` smoke on the TEA encrypt RVA matches the golden vector.
- [ ] **Step 4: Commit** scoped paths. Message: `feat(pe): add generic call/export/hook API and pe-call CLI`.

### Task 3: Refactor `tea_crypto.c` onto `pelib` + docs

**Files:** Modify `tea_crypto.c`, `README.md`, `ARCHITECTURE.md`, `PE-HARNESS.md`, `Makefile`.

**Interfaces:** `tea_*` public API unchanged; PE backend path uses `pe_load`/`pe_call_void`/`pe_unload` internally; native path untouched.

- [ ] **Step 1:** Run 5A's CLI backend test first (`make test-cli`) as the baseline contract.
- [ ] **Step 2:** Replace the mmap loader in `tea_crypto.c` with `pelib` calls; keep state-zero and `__stdcall` semantics. Do not change `cbm_backend_*` behaviour.
- [ ] **Step 3:** `make clean && make && make test && sh test_backend_cli.sh && gitleaks detect --source . --no-git --redact` → all green, no leaks.
- [ ] **Step 4:** Update docs: README (PE framework section), ARCHITECTURE (§10 pelib), PE-HARNESS (loader now in pelib). Keep test counts consistent across all docs.
- [ ] **Step 5: Commit** scoped paths. Message: `refactor(pe): move PE harness onto pelib and document framework`.

## Exit Criteria

- 53 existing tests green + new `test_pelib` cases; PE backend byte-identical through generic API.
- `pe-call` works on the vendor PE with the TEA RVA; no vendor binary committed.
- All docs consistent; gitleaks clean; final whole-branch review clean.
