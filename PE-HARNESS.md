# PE Harness — mmap-at-ImageBase

How the TEA crypto core was recovered from the vendor PE (`ap.exe`) and run
natively on Linux, without Wine or a VM.

## Problem

The vendor APTool is a 32-bit Windows PE (`ImageBase 0x400000`). Its TEA
cores live at fixed virtual addresses (`0x459da0`, `0x459d50`, `0x459ec0`)
and operate on a 16-byte state at `0x531328`. To call them we need the PE's
code and data present at those exact addresses, with the state region
writable and zeroed.

## Technique: mmap at ImageBase — now in `pelib`

The loader lives in `pelib.{h,c}`, not in `tea_crypto.c`. Constants:

    #define PE_BASE  0x400000u   // PE ImageBase
    #define PE_MAPSZ 0x140000u   // 1.25 MiB covering code + data

`pe_load(&img, path, hooks)` performs all the steps that were once inline:

1. Read the caller-supplied PE file into a buffer. When `path` is NULL/empty,
   `pe_load` uses `CBM_PE_PATH` only; there is no built-in default path and
   no silent fallback.
2. Validate DOS magic, `e_lfanew`, PE signature, section count, optional-header
   size and every section's raw range with 64-bit bounds arithmetic; check the
   declared ImageBase is `0x400000`.
3. `mmap((void*)PE_BASE, PE_MAPSZ, PROT_READ|PROT_WRITE|PROT_EXEC,
          MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0)` — reserves
   the exact VA and fails if someone else already owns it.
4. Copy headers and each section to `PE_BASE + VirtualAddress`.
5. Patch any caller-supplied `pe_import_hook_t` stubs into the IAT after all
   sections are mapped.
6. Hold the image as a singleton until `pe_unload(img)`.

`tea_init(PE)` calls `pe_load` and keeps the image; `tea_cleanup` calls
`pe_unload` once. `main.c` still runs `tea_native_selfcheck()` (which maps and
unmaps `0x400000` itself) *before* `tea_init`, so the two never collide.

## Calling convention

`pe_call_void(img, rva, arg, n)` is the single call path. It copies `n` bytes
(4-12, a multiple of 4) from `arg` into three `uint32_t` words, zero-fills
missing words, zeroes the 16-byte TEA state at VA `0x531328` (RVA `0x131328`),
then calls through:

    typedef void (__attribute__((stdcall)) *pe_fn3_t)(uint32_t, uint32_t, uint32_t);

The PE cores use `__stdcall` (callee cleans the stack), so no caller-side
stack adjustment is needed. `tea_encrypt`/`tea_decrypt` pass
`[&buf, (uint32_t)len, &key]` with `n = 12`; the 32-bit build makes pointer and
length words exact. The generic `pe-call` CLI exposes the same ABI from the
shell, and `pe_export` resolves named exports when a PE has them.

## Validation before porting

- `rtlen`: perfect inverse probe up to L=85687 bytes.
- `rttest`: roundtrip match=1.

Both probes ran the PE cores through this harness and confirmed the
cipher before any C port was written.

## Why not Wine

- Determinism: no VM, no Wine version drift, no hidden registry/state.
- Reproducibility: a single `gcc -m32` build runs on any x86-64 Linux.
- Static RE only: no runtime dependency on a Windows environment.
- No license/redistribution concern: the PE is loaded at runtime from a
  user-supplied path, never committed.

## Requirements

- 32-bit toolchain: `gcc -m32` (needs `libc6-dev-i386` / multilib).
- PE is optional: for the opt-in PE backend or PE tests, supply a legally
  obtained PE explicitly via `CBM_PE_PATH` (or as an explicit `pe-call`
  argument). There is no default path. All normal modes need no PE at all.
- PE's `ImageBase` must be `0x400000` (no relocations are applied).

## Limitations

- One PE at a time: `PE_BASE` is fixed; loading a second PE collides.
- No relocation table processing — the PE must already target
  `0x400000`.
- No Windows API resolution: imports are only patched when the caller passes
  matching `pe_import_hook_t` stubs; no Windows library is loaded or invoked.
- ASLR is not handled (irrelevant for this fixed-base PE).
- The PE binary itself is never committed or published.
- `test_pelib` (21 passes with PE; separately formatted `test_pelib: 10
  passed, 0 failed` without a usable PE) and `pe-call` exercise the library
  directly, including the golden TEA vector `e66254b5da09fb31` and IAT hook
  dispatch. No vendor binary is needed for the non-PE cases.