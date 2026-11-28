# Wave 5H — browser WASM playground

`wasm/` is a local-only, no-install playground for CBM container bytes: TEA
decrypt/encrypt, entropy, printable strings, a two-body byte diff, an editable
hex viewer and a modified-container download. It follows
`docs/superpowers/specs/2026-11-24-wild-ideas-design.md` §5H (lines 125–147).
No vendor binary, device, PE loader or server is involved.

## Privacy

All processing is client-side. Files, keys and edits stay in the browser tab;
the page makes no request containing file data. The only automatic fetch is for
`playground.wasm` itself, from the same directory as `index.html`; on a
`file://` page that fetch is blocked, so the page offers a manual
`playground.wasm` picker instead. Nothing is uploaded and nothing is stored
after the tab closes.

## Toolchain: emcc blocker and the working route

`emcc` is **absent** on this machine (`command -v emcc` → nothing). The verified
route is Clang's wasm32 target with the system linker:

- `clang version 23.1.4`
- `wasm-ld` (LLD) `23.1.4`, found at `/usr/bin/wasm-ld`
- `node v26.13.0` with WebAssembly support

The build command below produced `wasm/playground.wasm` (8,504 bytes in the
recorded run). `--export-memory` is included because the hand-written JS needs
direct access to linear memory. The module has **zero imports** (verified by
`WebAssembly.Module.imports`), so no libc allocator, Emscripten runtime or PE
code is linked in.

### Build

From the repository root:

```sh
clang --target=wasm32 -nostdlib -O2 -Wl,--no-entry -Wl,--export-all -Wl,--export-memory -o wasm/playground.wasm wasm/playground.c
```

The `.wasm` artifact is deliberately kept in `wasm/` so a static host (e.g.
GitHub Pages) can serve it directly. No `.gitignore` rule was added for it, and
the pre-existing ignore rules were left untouched.

### Test

From the repository root:

```sh
node wasm/test.js
```

The harness loads the built module, checks that it has no imports, feeds the
golden vectors from `test_tea_native.c` (8 zero bytes, bytes 0..31, 15 odd
bytes), asserts decrypt→encrypt identity, checks the entropy cases from
`test_cbm_decode.c`, checks printable-run offsets, and checks the diff ranges
from `test_cbm_diff.c` with context 0 (including truncation and error codes).

Recorded full output of the exact command above:

```text
PASS static memory cap is 256 KiB and regions are distinct
PASS encrypt matches C golden vector A (8 zero bytes)
PASS decrypt of C golden vector A (8 zero bytes) returns plaintext
PASS decrypt -> encrypt identity A (8 zero bytes)
PASS encrypt matches C golden vector B (bytes 0..31)
PASS decrypt of C golden vector B (bytes 0..31) returns plaintext
PASS decrypt -> encrypt identity B (bytes 0..31)
PASS encrypt matches C golden vector C (15 bytes, odd)
PASS decrypt of C golden vector C (15 bytes, odd) returns plaintext
PASS decrypt -> encrypt identity C (15 bytes, odd)
PASS invalid key length is rejected without changing the buffer
PASS oversized input is rejected before any buffer read
PASS entropy of 1024 zero bytes is exactly 0
PASS entropy of bytes 0..255 once each is 8 +/- 1e-9
PASS entropy of a 4-symbol uniform body is 2 +/- 1e-9
PASS empty input has zero entropy
PASS printable scan lists runs of at least 4 bytes with correct offsets
PASS printable scan rejects an input over the cap
PASS diff of identical bodies has no ranges
PASS diff of one changed byte matches the C range vector
PASS diff with context 0 keeps non-touching changes separate
PASS diff of a length difference appends a trailing range
PASS diff caps writes at max_ranges
PASS diff rejects negative lengths
Results: 24 passed, 0 failed
```

Result: **24 passed, 0 failed**, exit 0.

## Static memory and the file-size cap

The module uses static buffers only: two 256 KiB file buffers, a 16-byte key
buffer, a 64 KiB string blob, 256 string descriptors and 4,096 diff range
triples. There is no heap and no allocator.

Each input file is capped at **262,144 bytes (256 KiB)**, matching one static
file buffer. The JS rejects a larger file before copying it into wasm memory;
the C functions also return `-2` (or `-1.0` for entropy) for an over-cap length,
before reading any buffer. The browser shows a clear `role="alert"` message
naming the file, its size and the cap; no oversized bytes are processed.
String scan additionally caps at 256 runs / 64 KiB of text (returns `-3` if the
results will not fit), and diff caps at 4,096 ranges.

## Exported C API

All pointers are wasm32 addresses into linear memory; lengths are `i32`.
Invalid pointers or negative lengths return `-1`; an over-cap length returns
`-2`. `tea_*` returns `0` on success.

| Export | Contract |
| --- | --- |
| `wasm_cap`, `wasm_blob_cap`, `wasm_string_max`, `wasm_diff_max` | static capacity getters |
| `wasm_buf_a`, `wasm_buf_b`, `wasm_key`, `wasm_string_blob`, `wasm_string_refs`, `wasm_diff_ranges` | static buffer base addresses |
| `tea_encrypt(buf, len, key, keylen)`, `tea_decrypt(...)` | in-place clean-room TEA; `keylen` must be 16; trailing bytes below 8 are untouched |
| `entropy_estimate(buf, len)` | Shannon entropy in bits/byte as `f64`, `-1.0` on error; base-2 log without libm, matching `cbm_decode.c` |
| `scan_strings(buf, len, blob, blob_cap, refs, max_refs)` | printable runs (0x20–0x7e, length ≥ 4, truncated to 63); refs are `(source_offset, blob_offset, length)` `u32` triples |
| `diff_two(a, alen, b, blen, out, max_ranges)` | two-body diff with context 0; out is `(offset, length, changed)` `u32` triples; identical to `cbm_diff_ranges(..., 0, ...)` |

The cipher tables and core logic are adapted from the clean-room `tea_native.c`
backend; constants were byte-compared against that file. No 32-bit host objects
are linked and no vendor PE is referenced.

## Using the page

Open `wasm/index.html` in a browser. Drop or choose a first file (drag/drop and
the labelled file input both work; the drop zone is focusable and responds to
Enter/Space), enter the 16-character key, then decrypt, inspect and edit bytes.
The hex viewer shows 32 rows per page with an editable two-digit byte field and
an ASCII sidebar; navigation has labelled buttons and a hex-offset jump field.
Stats, the entropy bar and its text alternative, the string list and the diff
list update from the same displayed bytes. Add a second file and press
**Compare files**; **Download modified container** exports the displayed bytes,
optionally re-encrypting them first. All controls are labelled and keyboard
accessible; status and error regions use `role="status"` / `role="alert"`.

## Known limits (honest gaps)

- No Emscripten build: `emcc` is absent, so the documented Clang route is the
  supported one. Browser compatibility was not exercised by an automated
  browser suite here; the wasm module itself is covered by `node wasm/test.js`.
- Files above 256 KiB are rejected; this is a static-memory playground, not a
  whole-image scanner.
- The diff uses context 0 and reports ranges, not a byte-level patch stream.
- String runs are capped at 256/63 characters and do not imply a container hit.
- `file://` pages need the manual `playground.wasm` picker because browsers
  block the local fetch; this is a browser rule, not an app server requirement.
- This wave does not change the C suites' measured pass counts in
  `README.md`, `GAPS.md` or `ARCHITECTURE.md`.
