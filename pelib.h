#ifndef PELIB_H
#define PELIB_H

#include <stddef.h>
#include <stdint.h>

/* Fixed-base 32-bit PE loader. One image at a time: the image is mapped at
 * ImageBase 0x400000 and no relocations are applied. */
#define PE_BASE 0x400000u
#define PE_MAPSZ 0x140000u

/* Caller-supplied stubs for DLL imports. The array is terminated by an entry
 * with a NULL dll/name/fn. At most PE_MAX_IMPORT_HOOKS entries are consumed. */
#define PE_MAX_IMPORT_HOOKS 64

typedef struct pe_image pe_image_t;

typedef struct pe_import_hook {
    const char *dll;
    const char *name;
    void (*fn)(void);
} pe_import_hook_t;

/* Load path (or CBM_PE_PATH, or /tmp/opencode/ap.exe when path is NULL/empty).
 * Returns 0 with *img set, or -1 with *img cleared. Fails if another image is
 * already loaded or if PE_BASE is occupied by somebody else. */
int pe_load(pe_image_t **img, const char *path, const pe_import_hook_t *hooks);

/* Translate an RVA to an address inside the mapped image; NULL if invalid. */
void *pe_rva_to_va(pe_image_t *img, uint32_t rva);

/* Unmap the image and clear the singleton. NULL and double unload are safe. */
void pe_unload(pe_image_t *img);

/* Generic call ABI (32-bit x86 / __stdcall only):
 *
 *   arg  points to a packed array of uint32_t words (native little-endian).
 *   n    is that array's byte length. Only three words are passed to the
 *        target, through a void (__stdcall *)(uint32_t, uint32_t, uint32_t)
 *        pointer: args[0], args[1], args[2]. Missing words are zero-filled.
 *        Rejects n > 12 or n % 4 != 0 (returns -1), and never pushes extra
 *        words: a 3-arg stdcall callee cleans its own stack.
 *   This matches the vendor TEA cores, e.g. (unsigned char *buf, int len,
 *   const char *key): words 0/1/2 are those three arguments. Before every
 *   call the 16-byte TEA state at VA 0x531328 (RVA 0x131328) is zeroed.
 *   rva_or_va is an RVA, or a VA inside the mapped PE (>= PE_BASE); both
 *   resolve through the same image. Returns 0 on success, -1 on bad input.
 */
int pe_call_void(pe_image_t *img, uint32_t rva_or_va, void *arg, size_t n);

/* Find a named export and return its RVA in *out_rva (0 on failure).
 * Returns 0 when found, -1 for a missing name, a forwarder, an invalid
 * export directory, or bad arguments. Export names are case-sensitive.
 * PEs with no export directory simply return -1. */
int pe_export(pe_image_t *img, const char *name, uint32_t *out_rva);

/* Hooks supplied to pe_load are installed into the PE's IAT: for every
 * imported (dll, name) pair matching a hook entry, the corresponding IAT
 * slot holds stub_fn's address when pe_load returns. Hook matching is
 * case-insensitive; ordinal-only imports cannot be matched by name.
 * No Windows API is resolved or invoked by this library. */

#endif /* PELIB_H */
