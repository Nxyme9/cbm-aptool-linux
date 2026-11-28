# Wave 5A: Clean-Room TEA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reimplement the CBMUsbDisk block cipher in pure C, byte-identical to the vendor PE oracle, so normal builds no longer need `ap.exe`.

**Architecture:** Extract the constant tables and translate the per-block transform recovered from PE `0x459ec0` (called by `0x459d10` encrypt / `0x459cd0` decrypt with flag sequences 0x50/0x70/0x50 and 0x70/0x50/0x70). Keep the existing PE harness as an opt-in cross-check backend, not the default.

**Tech Stack:** C99, `gcc -m32`, existing Makefile/test harness, `objdump` for PE disassembly.

**Spec:** `docs/superpowers/specs/2026-11-24-brag-rights-design.md` (Wave 5A section).

## Global Constraints

- Key: `"1a2b3c4d5e6fTENG"` (16 bytes, `TEA_KEY_LEN`). Keyidx = 12.
- Block size 8 bytes (`TEA_BLOCK_SIZE`); state 16 bytes (`TEA_STATE_SIZE`) zeroed before each call.
- PE oracle addresses (read-only reference, never called at runtime by default): encrypt `0x459da0`, decrypt `0x459d50`, per-block wrapper encrypt `0x459d10`, decrypt `0x459cd0`, core `0x459ec0`, state `0x531328`, tables `0x52ad08` / `0x52aa30` / `0x52aa68` / `0x52a9b0`.
- Golden vectors (from the PE oracle, key above, state zeroed):
  - A: input 8 zero bytes → ciphertext `e66254b5da09fb31`
  - B: input bytes 0..31 → ciphertext `3dd24f1e5c7d940ef690cfcc84ddff02660d74c782b22e1e4015059980c24f01`
  - C: input bytes 1..15 (odd length) → ciphertext `1b787ed12c571f48090a0b0c0d0e0f`
  - All three decrypt back to their inputs exactly.
- Native backend must be byte-identical to the oracle before it becomes the default; if equivalence cannot be proven, ship it only behind `--native-crypto` and record that in GAPS.md. Never a silent fallback.
- No vendor binary, key leak, or device serial is committed. TEA key stays allowlisted in `.gitleaks.toml`.
- Build flags stay `CC=gcc`, `CFLAGS=-m32 -Wall -Wextra -O2 -g`. All existing 40 tests must remain green.
- Existing `tea_crypto.{h,c}` API (`tea_init`, `tea_encrypt`, `tea_decrypt`, `tea_cleanup`, `tea_is_ready`) keeps its signatures and behaviour for any caller that still uses the PE harness.

## Review Focus

- Odd-length buffers (15-, 85687-byte) — native must match oracle without reading past `buf+len`; pinned by golden vector C and `test_tea_native` odd-length case.
- State reset semantics — state zeroed before every call, including consecutive calls in one process; pinned by a two-call test asserting the second call equals the first on the same input.
- Key length enforcement — wrong-length key must fail cleanly, never index out of bounds; pinned by a short-key test expecting nonzero return.
- PE-oracle equivalence — native output must equal PE output on deterministic random buffers of many lengths; pinned by `tea_native_selfcheck` test when `ap.exe` is present.
- Backend selection — `--pe-crypto` must actually switch backends and `--native-crypto` must never silently fall back; pinned by a CLI-level test asserting which backend printed.

---

### Task 1: Native cipher core + golden-vector tests

**Files:**
- Create: `tea_native.h`, `tea_native.c`, `test_tea_native.c`
- Modify: `Makefile`

**Interfaces:**
- Consumes: key and golden vectors from Global Constraints; PE disassembly addresses for reference.
- Produces:
  - `int tea_native_encrypt(unsigned char *buf, size_t len, const char *key);`
  - `int tea_native_decrypt(unsigned char *buf, size_t len, const char *key);`
  - `int tea_native_selfcheck(const char *pe_path);`
  - Both encrypt/decrypt return 0 on success, nonzero on invalid key/length; operate in place; handle odd lengths.
  - `tea_native_selfcheck` returns 0 only when native and PE outputs are byte-identical on deterministic random buffers; nonzero if PE missing or mismatch.

- [ ] **Step 1: Write the failing test file**

`test_tea_native.c` must contain, with exact constants from Global Constraints:
- `test_vector_a`, `test_vector_b`, `test_vector_c`: load input, call `tea_native_encrypt`, assert ciphertext hex equals golden; then decrypt and assert original restored.
- `test_two_calls_state_reset`: encrypt the same 8-byte input twice in one process, assert equal ciphertexts.
- `test_short_key`: call with a 4-byte key, assert nonzero return and unchanged buffer.
- `test_odd_length_bounds`: compile/run under `-fsanitize=address` separately; assert no out-of-bounds on a 15-byte buffer.
- `test_selfcheck_when_pe_present`: if `/tmp/opencode/ap.exe` exists, assert `tea_native_selfcheck` returns 0; otherwise skip with a printed reason.

- [ ] **Step 2: Run the test to verify it fails**

Run: `make test_tea_native && ./test_tea_native`
Expected: link failure for undefined `tea_native_*` symbols (RED).

- [ ] **Step 3: Extract tables and implement the core in `tea_native.c`**

Dump the constant tables from the PE at the addresses in Global Constraints using `objdump`/`dd` on the raw file (VA → file offset via the `.text`/`.rdata` section headers). Translate the round function from `0x459ec0` and the flag sequences from `0x459d10`/`0x459cd0` into pure C. Implement the three public functions with the exact signatures in Interfaces. Keep tables as `static const` arrays generated from the dumped bytes, with a comment naming the source VA and that they are recovered constants, not vendor code.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `make test_tea_native && ./test_tea_native`
Expected: all vectors and state/key tests pass (GREEN); selfcheck passes when PE present, otherwise prints skip. Also run `gcc -m32 -fsanitize=address -g -I. -o /tmp/opencode/test_tea_native_asan test_tea_native.c tea_native.c && /tmp/opencode/test_tea_native_asan` — expect no sanitizer errors.

- [ ] **Step 5: Commit**

```bash
git add tea_native.h tea_native.c test_tea_native.c Makefile
git commit -m "feat(crypto): add pure-C CBM block cipher with golden vectors"
```

---

### Task 2: Backend selection in CLI and crypto dispatcher

**Files:**
- Modify: `main.c`, `Makefile`, `tea_crypto.c`

**Interfaces:**
- Consumes: `tea_native_*` from Task 1; existing `tea_init`/`tea_encrypt`/`tea_decrypt`/`tea_cleanup` API.
- Produces: CLI flags `--native-crypto` (default) and `--pe-crypto` (opt-in cross-check); no silent fallback. `selftest` prints the active backend and, under PE mode, may call `tea_native_selfcheck`.

- [ ] **Step 1: Write the failing test**

Add to `test_tea_native.c` a `test_backend_flag_parsing` that checks a helper `int cbm_backend_from_arg(const char *arg, int *backend)` returns 0 only for `--native-crypto`/`--pe-crypto` and sets a defined enum value. Declare the helper in a new `cbm_backend.h` (created here).

- [ ] **Step 2: Run the test to verify it fails**

Run: `make test_tea_native && ./test_tea_native`
Expected: link failure for `cbm_backend_from_arg` (RED).

- [ ] **Step 3: Implement backend selection**

Add `cbm_backend.h` with an enum (`CBM_BACKEND_NATIVE`, `CBM_BACKEND_PE`) and the parser. In `main.c`, parse the flags before `selftest`; default to native; native mode calls `tea_native_*` directly and prints `Crypto backend: native (clean-room)`; PE mode calls the existing `tea_init` path and prints `Crypto backend: PE harness (cross-check)`. In PE mode, additionally run `tea_native_selfcheck` when the PE is available and print its verdict. Do not change the signatures in `tea_crypto.h`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `make clean && make && make test`
Expected: all suites green including the new backend test; `./cbm-tool --native-crypto` prints the native backend line and completes self-test; `./cbm-tool --pe-crypto` prints the PE line and its self-check verdict.

- [ ] **Step 5: Commit**

```bash
git add cbm_backend.h main.c tea_crypto.c Makefile test_tea_native.c
git commit -m "feat(cli): default to clean-room crypto, keep PE backend opt-in"
```

---

### Task 3: Documentation and honest gaps

**Files:**
- Modify: `README.md`, `ARCHITECTURE.md`, `GAPS.md`

**Interfaces:**
- Consumes: behaviour from Tasks 1–2.

- [ ] **Step 1: Update README.md**

Add a "Crypto backends" section: native is default and needs no vendor binary; `--pe-crypto` is the cross-check; document `CBM_PE_PATH`. Keep existing usage examples valid.

- [ ] **Step 2: Update ARCHITECTURE.md**

Add a section 9 for `tea_native`: table addresses, flag sequences, golden vectors, and the backend-selection flow. Adjust the header line that says all tests pass to the new count.

- [ ] **Step 3: Update GAPS.md**

Record that Gap 2 no longer blocks normal use: the TEA core is now native and PE-free; the PE remains the validation oracle. Do not claim the DLL internals were recovered.

- [ ] **Step 4: Verify docs and full suite**

Run: `make clean && make && make test && gitleaks detect --source . --no-git --redact`
Expected: all tests pass; gitleaks reports no leaks (key allowlist intact).

- [ ] **Step 5: Commit**

```bash
git add README.md ARCHITECTURE.md GAPS.md
git commit -m "docs: describe clean-room crypto backend and PE cross-check"
```
