# pe-call

Invoke one function inside a 32-bit PE image from Linux, using `pelib`'s
fixed-base loader, and print the argument bytes after the call.

```
pe-call <pe-path> <rva|export-name> <hex-args>
```

Build with `make pe-call` (uses `CC=gcc`, `CFLAGS=-m32 -Wall -Wextra -O2 -g`).

## Arguments

- `<pe-path>`: PE32/i386 file with ImageBase `0x400000`. No relocations are
  applied, and only one PE can be loaded at a time.
- `<rva|export-name>`: a pure hex number is used as a target RVA, or as a VA
  when it is `>= 0x400000` (`pelib` accepts both). Anything else is looked up
  as a case-sensitive export name via `pe_export`; a failed lookup exits 1.
  An export name made only of hex digits cannot be addressed this way.
- `<hex-args>`: 8-24 hex digits (4-12 bytes), a multiple of 4. Byte pairs are
  decoded as packed little-endian `uint32_t` words: word 0 = first 4 bytes,
  word 1 = next 4, word 2 = last 4. Fewer than three words are zero-filled.
  The target is called through `void (__stdcall *)(uint32_t, uint32_t,
  uint32_t)`, so no extra words are pushed; more than 12 bytes is an error.

A zeroed page is mapped at fixed VA `0x600000` for the call so buffers such as
`0x00600100` are valid 32-bit pointers. If word 0 points inside that page, the
CLI also prints up to 64 bytes starting at that address after the call, making
in-place output visible. The page is unmapped and the PE unloaded on exit.

## Example: vendor TEA core

The vendor `ap.exe` encrypts an 8-byte zero block with the key at VA
`0x4fc924`; its encrypt core is at RVA `0x59da0` (VA `0x459da0`). Word 0 points
at the scratch buffer, word 1 is the length, word 2 is the key address:

```
$ pe-call /path/to/your/legally-obtained/ap.exe 0x59da0 000160000800000024c94f00
args: 000160000800000024c94f00
buffer@0x00600100: e66254b5da09fb310000...   # shortened; 64 bytes printed
```

`<pe-path>` is always explicit: there is no default vendor path and no vendor
binary in this repo. The same user-supplied path can be passed to the tool's
opt-in `--pe-crypto` backend through `CBM_PE_PATH`.

The same target also works as `0x459da0`. Decrypt at RVA `0x59d50` with the
ciphertext bytes written into the scratch buffer returns zeros.

## Exit status

- `0`: target called successfully.
- `1`: PE load, export lookup, scratch mapping, or call failed.
- `2`: wrong argument count or malformed `hex-args`.

`pe-call` invokes code from the PE directly; use it only with trusted images.
