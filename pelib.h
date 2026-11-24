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

#endif /* PELIB_H */
