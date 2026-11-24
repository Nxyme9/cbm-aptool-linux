# Design: File-Level CBM Container Tool

Date: 2026-11-24
Status: draft (awaiting approval)

## Intent

Add a `container` mode to `cbm-tool` that reads a complete 85688-byte CBM
container from a file or block device, TEA-decrypts the body, inspects the
plaintext (hex dump, printable strings, statistics, known-token search),
re-encrypts, verifies the roundtrip, and optionally writes the re-encrypted
container back to the target with paced writes.

## Goals

- Read/write complete 85688-byte containers as atomic units (file-level, not
  sector-level).
- Decrypt and inspect plaintext content.
- Prove encrypt∘decrypt identity (roundtrip verification).
- Optional write-back to prove device write path.
- Safe default: no write without explicit flag.

## Non-goals

- No modification of container content (inspect only).
- No SCSI CDB recovery (still blocked).
- No valid PE extraction (0/16 keys).

## Constraints

- TEA core handles non-multiple-of-8 lengths (body is 85687 bytes).
  `cbm_cbc_decrypt`/`cbm_cbc_encrypt` must be fixed to not require
  `body_len % 8 == 0`.
- Paced writes for device targets (40 MiB bursts, 45 s cooldown).
- No vendor binaries committed.
- No hardcoded secrets or serials.

## Approach: Unified file-or-device

Accepts a file path or block device + `--offset`. Reads 85688 B, decrypts,
inspects, re-encrypts, verifies in-memory. `--write-back` writes to target
with paced writes. Safe default: no write without flag.

## Design

### 1. Fix cbm_cbc_decrypt/encrypt

Remove the `body_len % 8 != 0` guard. The TEA core (PE 0x459d50/0x459da0)
handles arbitrary lengths (proven by rtlen up to 85687 bytes).

### 2. New module: cbm_file.{h,c}

File-level container I/O abstraction.

```c
int cbm_file_read(const char *path, long long offset,
                  unsigned char *buf, size_t len);
int cbm_file_write(const char *path, long long offset,
                   const unsigned char *buf, size_t len);
int cbm_file_is_blockdev(const char *path);
```

- `cbm_file_read`: open path, seek to offset, read len bytes.
  For block devices, uses pread (consistent with usb_mass layer).
- `cbm_file_write`: if block device, use paced writes (40 MiB bursts +
  45 s cooldown via paced_write). If regular file, write directly.
  Returns 0 on success.
- `cbm_file_is_blockdev`: stat + S_ISBLK.

### 3. New module: cbm_inspect.{h,c}

Container inspection utilities.

```c
void cbm_inspect_hex(const unsigned char *buf, size_t len,
                     size_t max_bytes, FILE *out);
void cbm_inspect_strings(const unsigned char *buf, size_t len,
                         size_t min_run, FILE *out);
void cbm_inspect_stats(const unsigned char *buf, size_t len, FILE *out);
void cbm_inspect_tokens(const unsigned char *buf, size_t len, FILE *out);
```

- `cbm_inspect_hex`: hex dump with ASCII sidebar. If max_bytes > 0,
  show first max_bytes/2 + last max_bytes/2. If 0, show all.
- `cbm_inspect_strings`: extract runs of printable ASCII (>= min_run).
  Print offset and string.
- `cbm_inspect_stats`: size, printable byte count, unique byte count,
  Shannon entropy estimate.
- `cbm_inspect_tokens`: search for known tokens (CBMUsb, SCSI, IOCTL,
  Vendor, etc.) in decrypted body.

### 4. main.c: new `container` mode

Usage: `cbm-tool container <path> [options]`

Options:
- `--offset N`     byte offset on block device (default 0)
- `--write-back`   write re-encrypted container back to target
- `--output <p>`   write re-encrypted container to different file
- `--hex-full`     full hex dump (default: first 256 + last 64)
- `--min-string N` minimum string length (default 4)

Flow:
1. Read 85688 bytes from source (cbm_file_read).
2. Print header byte (encrypted flag).
3. TEA-decrypt body (buf+1, len=85687).
4. Inspect: stats, hex dump, strings, token search.
5. TEA-re-encrypt body.
6. Verify: re-encrypted body == original ciphertext (roundtrip proof).
7. If --write-back or --output: write re-encrypted container to target
   with paced writes (cbm_file_write).
8. If --write-back: read back from target, decrypt, verify == original
   plaintext (device roundtrip proof).

### 5. Tests

- `test_cbm_file.c`: read/write roundtrip on temp file, blockdev detection.
- `test_cbm_inspect.c`: hex dump format, string extraction, stats.
- Update `test_cbm.c`: add test for cbm_cbc_decrypt with 85687-byte body.

### 6. Makefile

Add test_cbm_file and test_cbm_inspect to TESTS and build rules.

### 7. Documentation

- README.md: add container mode to "Working, verified" section.
- ARCHITECTURE.md: add section 8 (file-level container I/O).

## Files to create/modify

Create:
- cbm_file.h, cbm_file.c
- cbm_inspect.h, cbm_inspect.c
- test_cbm_file.c, test_cbm_inspect.c
- docs/superpowers/specs/2026-11-24-cbm-file-level-design.md (this file)

Modify:
- cbm_container.c (fix % 8 guard)
- main.c (add container mode)
- Makefile (add new tests)
- README.md, ARCHITECTURE.md

## Verification

- V1: build clean (make clean && make)
- V2: all tests pass (existing 25 + new tests)
- V3: container mode on /tmp/opencode/ap.cbm: inspect + roundtrip verify
- V4: container mode with --output: write to temp file, verify
- V5: container mode on /dev/sde with --offset (if container location known)
- V6: no vendor binaries, gitleaks clean