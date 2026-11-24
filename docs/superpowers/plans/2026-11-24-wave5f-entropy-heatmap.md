# Wave 5F: Whole-disk entropy heatmap (`entropy_map`, `png_write`, `cbm-tool heatmap`)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]` checkboxes.

**Goal:** Read any image or block device in fixed blocks, compute Shannon entropy per block, and render a PNG where colour encodes entropy, with a JSON sidecar carrying per-region statistics. Read-only by default: nothing is written unless `--out`/`--json` is given.

**Architecture:** Two libraries plus a CLI mode. `entropy_map.{h,c}` does the sampling (chunked reads via the existing `cbm_file_read` primitive), the downsampling aggregation, region classification (MBR / DJ_BOOT / DJ_OS / DJ_DATA / unpartitioned tail) and the deterministic JSON sidecar. `png_write.{h,c}` is a minimal RGB PNG encoder (IHDR/IDAT/IEND, filter 0 scanlines, zlib `compress2`, zlib `crc32`). `heatmap_mode()` in `main.c` drives them. Tests decode our own PNG with zlib and compare raw scanlines.

**Tech Stack:** C99, `gcc -m32 -Wall -Wextra -O2 -g`, zlib (`compress2`, `uncompress`, `crc32`, `crc32`-based chunk CRCs), existing `cbm_file_read`, `cbm_decode_entropy`, `cbm_layout_parse`.

**Spec:** `docs/superpowers/specs/2026-11-24-wild-ideas-design.md` §5F (lines 62-89).

## Global Constraints

- **Read-only by default.** `heatmap` opens the source only through `cbm_file_read` (regular files: `fopen "rb"`; block devices: `open O_RDONLY`). It NEVER calls `cbm_file_write`, `usb_mass_open`, or any `O_RDWR`/`O_WRONLY` open. Without `--out` and `--json` it writes nothing at all and prints a text summary to stdout.
- **No live device in build/tests.** All tests use synthetic regular files under `/tmp/opencode`. A full 500 GiB pass over `/dev/sde` is a separate hardware-gated step and is never implied by a green test run.
- **Reuse, do not fork.** Entropy MUST come from `cbm_decode_entropy` (Wave 5C's single implementation). Reads MUST come from `cbm_file_read` (Wave 5B's chunked reader). Do not add a second entropy routine, a second device-read path, or a second SHA/CRC implementation beyond zlib's `crc32`.
- **Determinism.** Same input + same options → byte-identical PNG and JSON. No `time()`, `rand()`, address ordering, or locale-dependent formatting. Entropy in JSON and text is fixed-point `%u.%06u` with a literal `.` (the Wave 5C/5B pattern); no `%.6f`.
- **Bounded memory.** Sample count is `ceil(range / block)`; reject ranges that would need more than 64 Mi samples with a clear error rather than allocating unbounded memory. All `size_t`/`unsigned long long` arithmetic overflow-checked.
- **No out-of-bounds reads.** Every read is clipped to the requested range; the final partial block is sampled at its true length; no read past `end_byte`.
- **PNG validity.** Every emitted file must decode with zlib: signature `89 50 4E 47 0D 0A 1A 0A`, then IHDR, IDAT, IEND in that order, correct length/type/CRC per chunk, 8-bit RGB (colour type 2), bit depth 8, no interlace, filter byte 0 per scanline.
- **zlib availability is verified** (32-bit `zlib-ng 1.3.1`, `/usr/lib32/libz.so`). Link `-lz` only in the rules that need it.
- CLI: `cbm-tool heatmap <device> [--block MiB] [--width N] [--out <png>] [--json <path>]`; exit 0 ok / 1 runtime error / 2 usage error. Dispatch in `main()` after `scan` and before the legacy device path. `cbm-tool` with no args still runs the self-test.
- Current baseline: **113 checks across 16 suites**. All prior checks stay green; new tests add to the count and docs are updated consistently.
- Build flags unchanged; no vendor binary/key/serial committed; TEA key stays allowlisted in `.gitleaks.toml`.

## Review Focus

- Entropy analytic cases are exact: all-zero block → 0.0, uniform-random block → ~8.0, half/half → two bands.
- PNG is genuinely decodable: zlib `uncompress` of IDAT yields exactly `height * (1 + width*3)` bytes with every filter byte 0, and the RGB values match the in-memory bitmap.
- Downsampling is deterministic and total: every sample contributes to exactly one pixel; `max/mean/min` aggregation cannot read outside its pixel's sample span.
- Read-only: no write path to the source; no `O_RDWR`; `--out`/`--json` are the only write targets and refuse to alias the source.
- Region overlay is honest: MBR/DJ_BOOT/DJ_OS/DJ_DATA/tail are labelled as **inferred** from the MBR, and a non-matching layout is reported as such rather than forced.
- Huge-device bounds: sample cap and pixel aggregation cannot overflow or allocate unbounded memory.

---

### Task 1: `entropy_map` — block sampling, downsampling, regions, JSON sidecar

**Files:** Create `entropy_map.h`, `entropy_map.c`, `test_entropy_map.c`; modify `Makefile`, `.gitignore`.

**Interfaces:**
- `typedef struct { unsigned long long offset; size_t length; double entropy; } cbm_entropy_sample_t;`
- `size_t cbm_entropy_blocks(const unsigned char *buf, size_t len, size_t block_bytes, unsigned long long base_offset, cbm_entropy_sample_t *out, size_t max);` — sample one contiguous buffer; the final block uses its true (shorter) length; returns samples written (capped); `len == 0` or `block_bytes == 0` → 0.
- `int cbm_entropy_map(const char *path, unsigned long long start_byte, unsigned long long end_byte, size_t block_bytes, cbm_entropy_sample_t **out, size_t *out_count, char *err, size_t errlen);` — chunked walker over `[start_byte, end_byte]` using `cbm_file_read`; allocates the sample array; caller frees with `free`. Returns 0 ok / -1 error with message. Rejects `block_bytes == 0`, `end < start`, ranges over the sample cap, and paths that cannot be read.
- `typedef struct { size_t index; size_t first_sample; size_t sample_count; double min, mean, max; unsigned char r, g, b; } cbm_heatmap_pixel_t;`
- `size_t cbm_entropy_downsample(const cbm_entropy_sample_t *samples, size_t n, size_t width, size_t height, cbm_heatmap_pixel_t *out, size_t max);` — maps sample `i` to pixel `(unsigned long long)i * (width*height) / n`; per pixel aggregates `min/mean/max` and a colour ramp (blue → cyan → green → yellow → red over 0..8 bits/byte); pixels with no samples get a neutral grey and `sample_count == 0`. Returns `width*height` written (capped at `max`).
- `typedef struct { const char *name; unsigned long long offset; unsigned long long length; size_t samples; double min, mean, max; int inferred; } cbm_entropy_region_t;`
- `size_t cbm_entropy_regions(const cbm_entropy_sample_t *samples, size_t n, const unsigned char *mbr, size_t mbr_len, cbm_entropy_region_t *out, size_t max);` — derives MBR (LBA 0), DJ_BOOT/DJ_OS/DJ_DATA from `cbm_layout_parse`, and the unpartitioned tail; computes per-region `min/mean/max` over the samples falling inside each region; marks `inferred = 1`; returns regions written.
- `int cbm_entropy_json(const char *path, const cbm_entropy_sample_t *samples, size_t n, const cbm_entropy_region_t *regions, size_t nregions, size_t width, size_t height, char *err, size_t errlen);` — deterministic JSON: `{"block_bytes":N,"samples":N,"width":N,"height":N,"entropy":{"min":D,"mean":D,"max":D},"regions":[{"name":"...","offset":N,"length":N,"samples":N,"min":D,"mean":D,"max":D,"inferred":true}]}` with fixed-point `%u.%06u` entropies and fixed field order.

- [ ] **Step 1: Write failing tests** in `test_entropy_map.c`: `test_zero_image_entropy_zero`, `test_random_image_entropy_eight` (deterministic xorshift fill, assert 7.9..8.0), `test_half_zero_half_random_two_bands` (first half all zero, second half random; assert first-band samples 0.0 and second-band ~8, and that the band boundary lands on the exact block), `test_block_offsets_and_lengths` (exact offset/length per sample incl. a short final block), `test_range_bounds` (start/end exclude samples outside, no over-read), `test_downsample_total_and_deterministic` (two runs byte-identical; every sample maps to exactly one pixel; `sample_count` sums to `n`), `test_regions_from_synthetic_mbr` (plant a valid DJ MBR, assert DJ_BOOT/DJ_OS/DJ_DATA offsets and lengths and `inferred == 1`; a non-DJ MBR yields a tail-only region set), `test_json_deterministic` (two writes byte-identical, exact fixed-point text, no comma decimal). RED = link failure.
- [ ] **Step 2: Implement `entropy_map.{h,c}`** reusing `cbm_decode_entropy` and `cbm_file_read`. Document the sample cap and the pixel-mapping formula in the header.
- [ ] **Step 3: Run tests** → green; ASan build `-m32 -fsanitize=address` clean (exact-size buffers at the final short block and at `n == 0`).
- [ ] **Step 4: Commit** scoped paths. Message: `feat(heatmap): add block entropy sampling, downsampling and region sidecar`.

### Task 2: `png_write` + `heatmap` CLI + docs

**Files:** Create `png_write.h`, `png_write.c`, `test_png_write.c`; modify `main.c`, `Makefile`, `.gitignore`, `README.md`, `ARCHITECTURE.md`, `GAPS.md`, `BRAG-RIGHTS.md`.

**Interfaces:**
- `int png_write_rgb(const char *path, const unsigned char *rgb, size_t width, size_t height, char *err, size_t errlen);` — writes an 8-bit RGB PNG: signature, IHDR, one IDAT (`compress2` level 9 over filter-0 scanlines), IEND; every chunk CRC via zlib `crc32`; returns 0 ok / -1 with message. Rejects `width == 0 || height == 0` and dimensions that overflow `size_t`.
- `int png_read_rgb(const char *path, unsigned char **rgb_out, size_t *width, size_t *height, char *err, size_t errlen);` — test-side decoder (also usable by callers): validates signature, walks chunks, checks CRCs, inflates IDAT, verifies filter bytes are 0, returns a malloc'd `width*height*3` buffer. This is what `test_png_write.c` uses to prove round-trip fidelity.
- CLI `heatmap_mode()` in `main.c`: parse `--block MiB` (default 1, min 1), `--width N` (default 1024, min 16, max 8192), `--out <png>`, `--json <path>`; refuse `--out`/`--json` paths that alias the source (`st_dev`/`st_ino` and `realpath`); read the MBR via `cbm_file_read`; call `cbm_entropy_map`, `cbm_entropy_downsample`, `cbm_entropy_regions`, print a text summary, then write the PNG and/or JSON only when asked. Exit 0/1/2.

- [ ] **Step 1: Write failing tests** in `test_png_write.c`: `test_png_signature_and_chunk_order` (signature, IHDR first, IDAT, IEND last, each CRC valid), `test_png_ihdr_fields` (width/height/bit depth 8/colour type 2/compression 0/filter 0/interlace 0), `test_png_roundtrip_rgb` (encode a known 7×5 gradient, decode with `png_read_rgb`, assert dimensions and every byte), `test_png_filter_bytes_zero` (inflated IDAT has `height` filter bytes all 0 and `height*(1+width*3)` total), `test_png_rejects_zero_dimensions`. RED = link failure.
- [ ] **Step 2:** Implement `png_write.{h,c}`; wire `heatmap_mode` into `main.c` after `scan`; extend the Makefile (`-lz` on the target and the PNG test); add the new test binary to `.gitignore`; update docs with the CLI, the read-only default, the sample cap, the inferred-region honesty, and the hardware-gated full-device note; update test counts everywhere.
- [ ] **Step 3:** `make clean && make && make test && sh test_backend_cli.sh` → all green; smoke `./cbm-tool heatmap <synthetic image> --out <tmp>/m.png --json <tmp>/m.json` under `/tmp/opencode`, verify the PNG decodes (via `png_read_rgb` in a scratch harness or `file`/`python3 -c` zlib check), verify the source hash is unchanged, verify the no-`--out` run writes nothing, verify exit 2 for a missing path and exit 1 for an unreadable path; `gitleaks detect --source . --no-git --redact` → no leaks.
- [ ] **Step 4: Commit** scoped paths. Message: `feat(heatmap): add PNG encoder and read-only heatmap CLI`.

## Exit Criteria

- All prior checks green plus both new suites; counts consistent across docs.
- Entropy analytic cases exact; PNG decodes with zlib to the exact in-memory RGB bytes.
- Read-only by default proven by tests and by the smoke run (source hash unchanged, no implicit files).
- Region overlay honest: inferred markers, non-DJ layout reported rather than forced.
- gitleaks clean; no vendor binary committed; final whole-branch review clean.
- A full 500 GiB device pass remains an explicit hardware-gated step, not part of this wave.
