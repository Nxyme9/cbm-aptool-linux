# Design: Wild-Ideas Wave 5 (5E–5H, complement to brag-rights spec)

Date: 2026-11-24
Status: draft (awaiting approval)

## Intent

The user selected all four wild directions in addition to 5A–5D in
`2026-11-24-brag-rights-design.md`. This spec covers the remaining four:

5E. USB honeypot + CDB capture — close the biggest documented RE gap.
5F. Whole-disk entropy heatmap — a single stunning forensic artifact.
5G. Wine-less PE framework — generalize the mmap harness into a library.
5H. Browser WASM playground — a shareable, zero-install demo.

Nothing here is approved to build until this doc is signed off. All waves
remain read-only by default; any write keeps the existing opt-in + read-back
rule. No vendor binaries or secrets are committed.

## Local prerequisites (checked 2026-11-24)

- `objdump`, `readelf`, `clang`, `python3`: present.
- `libz` headers + 32/64-bit libraries: present (used by 5F PNG writer).
- `emcc`: absent. 5H will use `clang --target=wasm32` with hand-written JS
  glue, not Emscripten. `wasm-ld` presence must be confirmed at build time;
  if absent, 5H ships as a documented non-goal rather than a broken build.
- USB-gadget-capable board: **unconfirmed**. 5E has a software fallback.

## 5E — USB honeypot + CDB capture (`cdb_shim.{h,c}`, `cdb_capture`)

### Goal

Recover the vendor SCSI CDB table that `GAPS.md` Gap 1 says is missing.

### Approach, tier 1 (software, no hardware)

Our existing harness already loads `ap.exe` at its ImageBase. Extend it to
parse the PE import table and bind imports to host-provided shim functions.
Shim `DeviceIoControl` (and the CBM DLL entry points where reachable) to log
the input buffer, control code, and CDB bytes to a capture file before
returning a safe synthetic success. Running `ap.exe` under this shim should
make the frontend emit its command stream without the stick attached.

### Approach, tier 2 (hardware, optional/gated)

If a USB-gadget-capable board is available, present a fake Chipsbank device
(VID 048d / PID 1234) with the DJ layout via ConfigFS or GadgetFS and log
every CBW/CDB the vendor tool sends. This captures driver-level traffic tier 1
cannot see. Running the vendor tool against the fake device is a gated step;
no such run happens during implementation.

### Output

`docs/cdb-table.md`: recovered control codes, CDB opcodes, buffer layouts,
and an explicit "observed / not observed" column. Do not claim completeness.

### Tests

`test_cdb_shim.c`: synthetic PE with one `DeviceIoControl` import; call it;
assert the logged buffer matches exactly; assert no host write occurs.

## 5F — Whole-disk entropy heatmap (`entropy_map.{h,c}`, `png_write.{h,c}`)

### Approach

Read the device in fixed blocks (default 1 MiB), compute Shannon entropy per
block, and render a PNG where colour encodes entropy. Overlay markers for the
MBR, the three DJ partitions, and the unpartitioned tail. Output both
`<name>.png` and a JSON sidecar with per-region statistics. Reuse the chunked
reader from 5B rather than a new I/O path.

Minimal PNG encoder: IHDR/IDAT/IEND with zlib `compress2`; no external image
library. 500 GiB at 1 MiB blocks = 512k samples, downsampled to a readable
image (default 1024 px wide) with max/mean/min aggregation.

### CLI

```
cbm-tool heatmap <device> [--block MiB] [--width N] [--out <png>] [--json <path>]
```

Read-only, no device writes. A full 500 GiB pass is a gated live probe.

### Tests

`test_entropy_map.c`: all-zero image → entropy 0; random image → ~8; known
half-zero/half-random image → correct two-band profile; PNG signature and
chunk order valid. `test_png_write.c`: decode our own PNG with zlib and check
dimensions and raw scanlines.

## 5G — Wine-less PE framework (`pelib.{h,c}`, `pe-call`)

### Approach

Extract the PE-loading part of `tea_init` into a reusable library:

```c
typedef struct pe_image pe_image_t;
int pe_load(pe_image_t **img, const char *path, const pe_import_hook_t *hooks);
int pe_call_void(pe_image_t *img, uint32_t rva_or_va, void *arg, size_t n);
void *pe_rva_to_va(pe_image_t *img, uint32_t rva);
int pe_export(pe_image_t *img, const char *name, uint32_t *out_rva);
void pe_unload(pe_image_t *img);
```

- Handles 32-bit PE headers/sections, ImageBase remapping, and `__stdcall`.
- `pe_import_hook_t` lets callers supply stubs for selected DLL imports
  (this is also the substrate for 5E tier 1).
- `pe-call` CLI calls one exported/RVA function with a hex-encoded argument
  buffer, for exploratory RE.
- Existing `tea_crypto.c` becomes a thin wrapper over `pelib`; its observable
  behaviour and tests must not change.

### Demonstration

Load `ap.exe` through `pelib`, call the TEA encrypt RVA, and compare with the
current harness output byte-for-byte. If a second vendor PE becomes available,
repeat with it to show the loader is genuinely general.

### Tests

`test_pelib.c`: header parse, section mapping, import hook dispatch, export
lookup, and the byte-identical TEA call through the generic API.

## 5H — Browser WASM playground (`wasm/`, `docs/wasm-playground.md`)

### Approach

Depends on 5A (clean-room TEA). Compile a small C API to wasm32 with
`clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--export-all`; use static
buffers (no libc allocator) and export functions that take pointer+length in
linear memory. Hand-written JS/HTML loads the module, copies a dropped file
into memory, and calls decrypt / inspect / diff / fuzz. No vendor binary, no
server, no install. GitHub Pages hosting is the publishing goal.

### UI

File drop zone, container hex viewer with ASCII sidebar, string list, stats,
entropy bar, diff against a second file, and a "download modified container"
button. Keyboard accessible, labelled controls, text alternatives for the
heatmap. All processing is client-side; show a clear privacy note.

### Tests

`wasm/test.js`: load module, feed known vectors, compare to C test vectors;
check decrypt→encrypt identity in-browser. If `wasm-ld` is unavailable, keep
the source and document the blocker instead of shipping a broken artifact.

## Dependency order (combined 8-wave program)

5A → 5G → 5C → 5B → 5E → 5F → 5D → 5H

- 5A unlocks 5H.
- 5G unlocks 5E tier 1.
- 5B unlocks 5F's reader.
- 5D's TUI can display cached 5B scan hits and 5F heatmap summary.

## Verification (in addition to each wave's own tests)

1. `make clean && make && make test` — all suites pass after every wave.
2. 5E: captured CDB buffer matches the synthetic shim input exactly.
3. 5F: PNG decodes to correct dimensions; entropy values match analytic cases.
4. 5G: generic PE call output is byte-identical to the current harness.
5. 5H: JS tests pass in a browser or Node with WebAssembly support.
6. `gitleaks detect --source . --no-git --redact` → no leaks.
7. Hardware honeypot, full-device scans, and any device write are separate
   gated steps; never implied by a green test run.

## Honest risks

- 5E tier 1 may show that the frontend delegates all CDBs to the encrypted
  DLL; then the capture is empty and Gap 1 stays open. Report that plainly.
- 5F's heatmap shows entropy, not semantics; hidden regions are candidates,
  not proof.
- 5G cannot load 64-bit PE images; scope stays 32-bit x86.
- 5H depends on toolchain availability confirmed at build time.
