# PE Harness — mmap-at-ImageBase

How the TEA crypto core was recovered from the vendor PE (`ap.exe`) and run
natively on Linux, without Wine or a VM.

## Problem

The vendor APTool is a 32-bit Windows PE (`ImageBase 0x400000`). Its TEA
cores live at fixed virtual addresses (`0x459da0`, `0x459d50`, `0x459ec0`)
and operate on a 16-byte state at `0x531328`. To call them we need the PE's
code and data present at those exact addresses, with the state region
writable and zeroed.

## Technique: mmap at ImageBase

Constants (from `tea_crypto.c`):

    #define BASE   0x400000u   // PE ImageBase
    #define MAPSZ  0x140000u   // 1.25 MiB covering code + data

Steps (in `tea_init`):

1. Read the PE file into a buffer.
2. `mmap((void*)BASE, MAPSZ, PROT_READ|PROT_WRITE|PROT_EXEC,
          MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0)` — reserves the
   ImageBase region at the exact VA. `MAP_FIXED` is what makes the PE's
   hardcoded addresses valid.
3. Read `e_lfanew` from PE offset `0x3c` (`po = rd32(pe, 0x3c)`).
4. Section count `ns = rd16(pe, po+6)`; optional-header size
   `os = rd16(pe, po+20)`; section table `sh = po + 24 + os`.
5. Copy headers: `memcpy(BASE, pe, sh + ns*40)`.
6. For each section i: read VA (`rd32(s,12)`), raw size (`rd32(s,16)`),
   raw pointer (`rd32(s,20)`); `memcpy(BASE+va, pe+rp, rs)`.
7. Free the file buffer; set `g_ready = 1`.

The TEA cores are then callable as function pointers cast to `__stdcall`:

    typedef void (__attribute__((stdcall)) *encfn_t)(unsigned char *, int, const char *);
    encfn_t f = (encfn_t)(void *)0x459da0;

## Calling convention

The PE cores use `__stdcall` (callee cleans the stack). GCC's
`__attribute__((stdcall))` on the function-pointer type makes the call
site emit the correct convention. State at `0x531328` is zeroed
(`memset`) before every call.

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
- PE must be present at the configured path (default
  `/tmp/opencode/ap.exe`, overridable via `CBM_PE_PATH`).
- PE's `ImageBase` must be `0x400000` (no relocations are applied).

## Limitations

- One PE at a time: `BASE` is fixed; loading a second PE collides.
- No relocation table processing — the PE must already target
  `0x400000`.
- No import resolution — only self-contained internal cores (TEA) are
  called; no Windows APIs are invoked.
- ASLR is not handled (irrelevant for this fixed-base PE).
- The PE binary itself is never committed or published.