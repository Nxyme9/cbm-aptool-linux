# CBM File-Level Container Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `container` mode to `cbm-tool` that reads a complete 85688-byte CBM container from a file or block device, TEA-decrypts the body, inspects the plaintext, re-encrypts, verifies the roundtrip, and optionally writes back with paced writes.

**Architecture:** Two new modules (`cbm_file` for file/device I/O, `cbm_inspect` for inspection), a fix to `cbm_cbc_decrypt`/`encrypt` to handle non-multiple-of-8 lengths, and a new `container` mode in `main.c`. Safe default: no write without `--write-back` or `--output`.

**Tech Stack:** C (gcc -m32), TEA crypto (mmap-at-ImageBase PE harness), paced writes, USB mass-storage layer.

**Spec:** docs/superpowers/specs/2026-11-24-cbm-file-level-design.md

## Global Constraints

- CBM_CONTAINER_SIZE = 85688 (1 byte header + 85687 byte body).
- TEA key: "1a2b3c4d5e6fTENG" (16 bytes).
- Paced writes: 40 MiB bursts, 45 s cooldown.
- No vendor binaries committed (.exe/.dll/.sys).
- No hardcoded secrets or device serials.
- gitleaks clean (allowlist covers TEA key).
- All existing 25 tests must still pass.

## Review Focus

1. Non-multiple-of-8 body (85687 bytes) through TEA — must roundtrip exactly.
2. Device write-back safety — default must NOT write; --write-back required.
3. Offset handling on 32-bit build — _FILE_OFFSET_BITS 64 must be in effect.
4. Hex dump correctness for partial reads (max_bytes > len).
5. String extraction must not read past buffer boundary.
6. Paced write integration with cbm_file_write for block devices.

---

### Task 1: Fix cbm_cbc_decrypt/encrypt (remove % 8 guard)

**Files:**
- Modify: cbm_container.c:24-35

**Interfaces:**
- Produces: `cbm_cbc_decrypt(buf, 85687, key)` and `cbm_cbc_encrypt(buf, 85687, key)` now work.

- [ ] **Step 1: Remove the % 8 guard**

Edit cbm_container.c lines 24-35: remove the `if (body_len % 8 != 0) return -1;` lines from both functions.

- [ ] **Step 2: Build and verify existing tests still pass**

Run: `make clean && make && make test`
Expected: 25/25 PASS (cbm tests still pass with the guard removed).

- [ ] **Step 3: Commit**

```bash
git add cbm_container.c
git commit -m "fix(cbm): remove %8 guard — TEA handles arbitrary lengths (85687-byte body)"
```

---

### Task 2: Create cbm_file module (file/device I/O)

**Files:**
- Create: cbm_file.h, cbm_file.c
- Create: test_cbm_file.c

**Interfaces:**
- Produces: `cbm_file_read(path, offset, buf, len)`, `cbm_file_write(path, offset, buf, len)`, `cbm_file_is_blockdev(path)`.

- [ ] **Step 1: Write failing test**

Create test_cbm_file.c with tests for:
- cbm_file_is_blockdev on regular file returns 0
- cbm_file_read from temp file reads correct bytes
- cbm_file_write to temp file writes correct bytes
- cbm_file_read/write roundtrip on temp file

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -m32 -Wall -Wextra -O2 -g -o test_cbm_file test_cbm_file.c cbm_file.c && ./test_cbm_file`
Expected: FAIL (cbm_file.h not found or functions undefined).

- [ ] **Step 3: Implement cbm_file.h**

```c
#ifndef CBM_FILE_H
#define CBM_FILE_H
#include <stddef.h>
int cbm_file_read(const char *path, long long offset,
                  unsigned char *buf, size_t len);
int cbm_file_write(const char *path, long long offset,
                   const unsigned char *buf, size_t len);
int cbm_file_is_blockdev(const char *path);
#endif
```

- [ ] **Step 4: Implement cbm_file.c**

Use fopen/fread/fwrite for regular files. For block devices, use open/pread/pwrite with _FILE_OFFSET_BITS 64. cbm_file_write uses paced writes for block devices (via paced_write with a callback that calls pwrite).

- [ ] **Step 5: Run test to verify it passes**

Run: `gcc -m32 -Wall -Wextra -O2 -g -o test_cbm_file test_cbm_file.c cbm_file.c && ./test_cbm_file`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cbm_file.h cbm_file.c test_cbm_file.c
git commit -m "feat(cbmf): file-level CBM container I/O (read/write/blockdev detect)"
```

---

### Task 3: Create cbm_inspect module (inspection)

**Files:**
- Create: cbm_inspect.h, cbm_inspect.c
- Create: test_cbm_inspect.c

**Interfaces:**
- Produces: `cbm_inspect_hex`, `cbm_inspect_strings`, `cbm_inspect_stats`, `cbm_inspect_tokens`.

- [ ] **Step 1: Write failing test**

Create test_cbm_inspect.c with tests for:
- cbm_inspect_stats on known buffer produces correct printable count
- cbm_inspect_strings extracts "HELLO" from buffer with surrounding nulls
- cbm_inspect_hex doesn't crash on empty buffer

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -m32 -Wall -Wextra -O2 -g -o test_cbm_inspect test_cbm_inspect.c cbm_inspect.c && ./test_cbm_inspect`
Expected: FAIL.

- [ ] **Step 3: Implement cbm_inspect.h and cbm_inspect.c**

Hex dump with ASCII sidebar, string extraction (runs of printable ASCII >= min_run), stats (size, printable count, unique bytes, entropy), token search for known keywords.

- [ ] **Step 4: Run test to verify it passes**

Run: `gcc -m32 -Wall -Wextra -O2 -g -o test_cbm_inspect test_cbm_inspect.c cbm_inspect.c && ./test_cbm_inspect`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cbm_inspect.h cbm_inspect.c test_cbm_inspect.c
git commit -m "feat(cbmi): CBM container inspection (hex, strings, stats, tokens)"
```

---

### Task 4: Add container mode to main.c

**Files:**
- Modify: main.c

**Interfaces:**
- Consumes: cbm_file_read, cbm_file_write, cbm_file_is_blockdev, cbm_inspect_*, cbm_cbc_decrypt, cbm_cbc_encrypt, paced_write.
- Produces: `cbm-tool container <path> [options]` CLI mode.

- [ ] **Step 1: Add argument parsing for container mode**

Parse `container` subcommand and options: --offset, --write-back, --output, --hex-full, --min-string.

- [ ] **Step 2: Implement container flow**

1. Read 85688 bytes (cbm_file_read).
2. Print header byte.
3. Decrypt body (cbm_cbc_decrypt on buf+1, len=85687).
4. Inspect (stats, hex, strings, tokens).
5. Re-encrypt body.
6. Verify roundtrip (memcmp re-encrypted vs original).
7. If --write-back or --output: write (cbm_file_write).
8. If --write-back: read back, decrypt, verify == original plaintext.

- [ ] **Step 3: Build and test manually**

Run: `make clean && make && ./cbm-tool container /tmp/opencode/ap.cbm`
Expected: inspect output, roundtrip OK, no write.

- [ ] **Step 4: Test with --output**

Run: `./cbm-tool container /tmp/opencode/ap.cbm --output /tmp/opencode/ap_roundtrip.cbm`
Expected: output file created, identical to input.

- [ ] **Step 5: Commit**

```bash
git add main.c
git commit -m "feat(cbmf): container mode in cbm-tool (read/decrypt/inspect/re-encrypt/verify)"
```

---

### Task 5: Update Makefile and tests

**Files:**
- Modify: Makefile

**Interfaces:**
- Produces: test_cbm_file and test_cbm_inspect build targets.

- [ ] **Step 1: Add build rules for new tests**

Add test_cbm_file and test_cbm_inspect to TESTS list and build rules.

- [ ] **Step 2: Run full test suite**

Run: `make clean && make && make test`
Expected: all tests pass (25 existing + new).

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "build: add test_cbm_file and test_cbm_inspect to test suite"
```

---

### Task 6: Update documentation

**Files:**
- Modify: README.md, ARCHITECTURE.md

**Interfaces:**
- Produces: documented container mode.

- [ ] **Step 1: Update README.md**

Add container mode to "Working, verified" section. Add usage example.

- [ ] **Step 2: Update ARCHITECTURE.md**

Add section 8: File-level container I/O (cbm_file, cbm_inspect).

- [ ] **Step 3: Commit**

```bash
git add README.md ARCHITECTURE.md
git commit -m "docs: document container mode, cbm_file and cbm_inspect modules"
```

---

### Task 7: Final verification

- [ ] **Step 1: Full build + test**

Run: `make clean && make && make test`
Expected: all tests pass.

- [ ] **Step 2: Container mode smoke test**

Run: `./cbm-tool container /tmp/opencode/ap.cbm`
Expected: inspect output + roundtrip OK.

- [ ] **Step 3: gitleaks check**

Run: `gitleaks detect --source . --no-git`
Expected: no leaks found.

- [ ] **Step 4: No vendor binaries**

Run: `find . -path ./.git -prune -o \( -name '*.exe' -o -name '*.dll' -o -name '*.sys' \) -print`
Expected: empty (the .exe/.dll in /tmp/opencode are outside the repo).