/* pelib.c - reusable 32-bit PE loader (mmap at fixed ImageBase)
 *
 * Mirrors the mmap-at-ImageBase technique in tea_crypto.c / PE-HARNESS.md,
 * with overflow-safe validation of every header offset before every read.
 * No caller is migrated yet; this is a standalone library.
 */
#define _GNU_SOURCE
#include "pelib.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>

#define DOS_HEADER_SIZE 64u
#define PE_SIG_SIZE 4u
#define COFF_HEADER_SIZE 20u
#define SECTION_HEADER_SIZE 40u
#define PE32_OPT_MIN 60u     /* SizeOfImage lives at optional-header +56 */
#define PE32_MAGIC 0x10bu
#define IMAGE_BASE_FIELD 28u
#define SIZE_OF_IMAGE_FIELD 56u
#define MAX_PE_FILE (256u * 1024u * 1024u)
#define DATA_DIR_COUNT_FIELD 92u
#define DATA_DIR_BASE 96u
#define EXPORT_DIR_SIZE 40u
#define IMPORT_DESC_SIZE 20u
#define TEA_STATE_RVA 0x131328u        /* VA 0x531328 - PE_BASE */
#define TEA_STATE_SIZE 16u

/* The binding: exactly three 32-bit args, __stdcall (callee cleans stack). */
typedef void (__attribute__((stdcall)) *pe_fn3_t)(uint32_t, uint32_t, uint32_t);

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

struct pe_image {
    void *base;
    uint32_t map_size;
    uint32_t image_size;
    uint32_t export_rva;
    uint32_t export_size;
    uint32_t import_rva;
    uint32_t import_size;
    pe_import_hook_t *hooks;
};

static pe_image_t *g_loaded;

static void pe_error(const char *msg) {
    fprintf(stderr, "pe_load: %s\n", msg);
}

static uint16_t rd16(const unsigned char *p, size_t o) {
    return (uint16_t)((uint16_t)p[o] | ((uint16_t)p[o + 1] << 8));
}

static uint32_t rd32(const unsigned char *p, size_t o) {
    return (uint32_t)p[o] | ((uint32_t)p[o + 1] << 8) |
           ((uint32_t)p[o + 2] << 16) | ((uint32_t)p[o + 3] << 24);
}

static void wr32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

/* All image-relative reads go through this 64-bit bounds check. */
static void *map_ptr(pe_image_t *img, uint64_t rva, uint64_t need) {
    if (!img || !img->base || !img->image_size) return NULL;
    if (rva > img->image_size || need > (uint64_t)img->image_size - rva)
        return NULL;
    return (unsigned char *)img->base + (size_t)rva;
}

/* NUL-terminated string inside the mapped image; never reads past the end. */
static char *image_str(pe_image_t *img, uint32_t rva, size_t *out_len) {
    unsigned char *p = map_ptr(img, rva, 1u);
    uint64_t i, max;
    if (!p) return NULL;
    max = (uint64_t)img->image_size - rva;
    for (i = 0; i < max; i++) {
        if (!p[i]) {
            if (out_len) *out_len = (size_t)i;
            return (char *)p;
        }
    }
    return NULL;
}

/* Install caller stubs into the IAT. Only named imports can be matched;
 * ordinal-only imports are skipped. Returns -1 on a malformed import table. */
static int patch_import_hooks(pe_image_t *img) {
    uint64_t off;
    if (!img->hooks || !img->import_rva || !img->import_size) return 0;

    for (off = 0; off + IMPORT_DESC_SIZE <= img->import_size;
         off += IMPORT_DESC_SIZE) {
        unsigned char *d = map_ptr(img, (uint64_t)img->import_rva + off,
                                   IMPORT_DESC_SIZE);
        uint32_t lookup, dll_rva, ft;
        char *dll;
        uint64_t k, max_thunks;

        if (!d) return -1;
        lookup = rd32(d, 0);          /* OriginalFirstThunk */
        dll_rva = rd32(d, 12);        /* Name */
        ft = rd32(d, 16);             /* FirstThunk == IAT */
        if (!lookup && !dll_rva && !ft) break;
        dll = image_str(img, dll_rva, NULL);
        if (!dll || !ft) return -1;
        if (!lookup) lookup = ft;     /* no OFT: the IAT is the lookup table */
        if (lookup >= img->image_size || ft >= img->image_size) return -1;

        max_thunks = ((uint64_t)img->image_size - lookup) / 4u;
        if (max_thunks > 0x10000u) max_thunks = 0x10000u;
        for (k = 0; k < max_thunks; k++) {
            unsigned char *thunk = map_ptr(img, (uint64_t)lookup + k * 4u, 4u);
            unsigned char *slot;
            uint32_t v;
            if (!thunk) return -1;
            v = rd32(thunk, 0);
            if (!v) break;            /* end of this descriptor's thunk list */
            slot = map_ptr(img, (uint64_t)ft + k * 4u, 4u);
            if (!slot) return -1;
            if (v & 0x80000000u) continue;   /* ordinal: no name to match */
            {
                char *nm;
                const pe_import_hook_t *h;
                /* IMAGE_IMPORT_BY_NAME is a 2-byte hint followed by a NUL
                 * name; the hint's high byte is often zero, so skip it
                 * before searching for the string terminator. */
                if (!map_ptr(img, v, 4u)) return -1;
                nm = image_str(img, v + 2u, NULL);
                if (!nm || !*nm) return -1;
                for (h = img->hooks; h->dll && h->name && h->fn; h++) {
                    if (strcasecmp(h->dll, dll) == 0 &&
                        strcasecmp(h->name, nm) == 0) {
                        wr32(slot, (uint32_t)(uintptr_t)h->fn);
                        break;
                    }
                }
            }
        }
    }
    return 0;
}

static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    long n;
    unsigned char *buf;

    if (!f) { pe_error("cannot open PE file"); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); pe_error("cannot seek PE file"); return NULL; }
    n = ftell(f);
    if (n < (long)DOS_HEADER_SIZE || n > (long)MAX_PE_FILE) {
        fclose(f);
        pe_error("PE file too small or too large");
        return NULL;
    }
    rewind(f);
    buf = malloc((size_t)n);
    if (!buf) { fclose(f); pe_error("out of memory"); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        free(buf);
        pe_error("short read on PE file");
        return NULL;
    }
    fclose(f);
    *out_len = (size_t)n;
    return buf;
}

int pe_load(pe_image_t **img, const char *path, const pe_import_hook_t *hooks) {
    unsigned char *pe = NULL;
    pe_image_t *image = NULL;
    const unsigned char *opt;
    uint64_t sh, table_end;
    uint32_t po, ns, os, declared_size, ndirs;
    void *m = MAP_FAILED;
    int mapped = 0;
    size_t n = 0, i;

    if (!img) return -1;
    *img = NULL;
    if (g_loaded) {
        pe_error("a PE image is already loaded; call pe_unload first");
        return -1;
    }
    if (!path || !*path) {
        const char *env = getenv("CBM_PE_PATH");
        if (!env || !*env) {
            pe_error("CBM_PE_PATH is not set; an explicit PE path is required");
            return -1;
        }
        path = env;
    }

    pe = read_file(path, &n);
    if (!pe) goto fail;

    if (pe[0] != 'M' || pe[1] != 'Z') { pe_error("bad DOS magic"); goto fail; }

    po = rd32(pe, 0x3c);
    if ((uint64_t)po + PE_SIG_SIZE + COFF_HEADER_SIZE > (uint64_t)n) {
        pe_error("e_lfanew points past end of file");
        goto fail;
    }
    if (memcmp(pe + po, "PE\0\0", PE_SIG_SIZE) != 0) {
        pe_error("bad PE signature");
        goto fail;
    }

    ns = rd16(pe, (size_t)po + 6);
    os = rd16(pe, (size_t)po + 20);
    if (os < PE32_OPT_MIN) {
        pe_error("optional header too small for PE32");
        goto fail;
    }

    /* All offset arithmetic is 64-bit so a 32-bit wrap cannot hide a bad
     * e_lfanew / section count / optional-header size from the bounds check. */
    sh = (uint64_t)po + PE_SIG_SIZE + COFF_HEADER_SIZE + (uint64_t)os;
    table_end = sh + (uint64_t)ns * SECTION_HEADER_SIZE;
    if (sh > (uint64_t)n || table_end > (uint64_t)n) {
        pe_error("section table points past end of file");
        goto fail;
    }
    if (table_end > (uint64_t)PE_MAPSZ) {
        pe_error("headers exceed the mapped image");
        goto fail;
    }

    opt = pe + (size_t)po + PE_SIG_SIZE + COFF_HEADER_SIZE;
    if (rd16(opt, 0) != PE32_MAGIC) { pe_error("not a PE32 image"); goto fail; }
    if (rd32(opt, IMAGE_BASE_FIELD) != PE_BASE) {
        pe_error("ImageBase is not 0x400000 (relocations are not applied)");
        goto fail;
    }

    image = calloc(1, sizeof *image);
    if (!image) { pe_error("out of memory"); goto fail; }
    declared_size = rd32(opt, SIZE_OF_IMAGE_FIELD);
    image->map_size = PE_MAPSZ;
    image->image_size = (declared_size && declared_size <= PE_MAPSZ)
                            ? declared_size : PE_MAPSZ;

    /* NumberOfRvaAndSizes lives at +92, but a valid PE32 optional header can
     * be as short as 60 bytes; guard the count read before performing it. */
    ndirs = (os >= DATA_DIR_BASE) ? rd32(opt, DATA_DIR_COUNT_FIELD) : 0u;
    if (ndirs > 0u && os >= DATA_DIR_BASE + 8u) {
        image->export_rva = rd32(opt, DATA_DIR_BASE);
        image->export_size = rd32(opt, DATA_DIR_BASE + 4u);
    }
    if (ndirs > 1u && os >= DATA_DIR_BASE + 16u) {
        image->import_rva = rd32(opt, DATA_DIR_BASE + 8u);
        image->import_size = rd32(opt, DATA_DIR_BASE + 12u);
    }

    if (hooks) {
        size_t hc = 0;
        while (hc < PE_MAX_IMPORT_HOOKS &&
               hooks[hc].dll && hooks[hc].name && hooks[hc].fn) hc++;
        if (hc) {
            image->hooks = calloc(hc + 1, sizeof *image->hooks);
            if (!image->hooks) { pe_error("out of memory"); goto fail; }
            memcpy(image->hooks, hooks, hc * sizeof *hooks);
        }
    }

    /* NOREPLACE fails with EEXIST if somebody else already owns BASE. The
     * exact-address check also covers kernels that ignore the flag. */
    m = mmap((void *)PE_BASE, PE_MAPSZ, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (m == MAP_FAILED || m != (void *)PE_BASE) {
        if (m != MAP_FAILED) munmap(m, PE_MAPSZ);
        m = MAP_FAILED;
        pe_error("ImageBase 0x400000 is unavailable or already mapped");
        goto fail;
    }
    mapped = 1;
    image->base = m;

    memcpy(m, pe, (size_t)table_end);
    for (i = 0; i < ns; i++) {
        const unsigned char *s = pe + (size_t)sh + i * SECTION_HEADER_SIZE;
        uint32_t va = rd32(s, 12);
        uint32_t rs = rd32(s, 16);
        uint32_t rp = rd32(s, 20);
        if (!rs) continue;
        if ((uint64_t)rp + rs > (uint64_t)n) {
            pe_error("section raw data points past end of file");
            goto fail;
        }
        if ((uint64_t)va + rs > (uint64_t)PE_MAPSZ) {
            pe_error("section virtual range exceeds mapped image");
            goto fail;
        }
        memcpy((unsigned char *)m + va, pe + rp, rs);
    }

    /* Install stubs only after all sections (including the IAT) are mapped. */
    if (patch_import_hooks(image) != 0) {
        pe_error("malformed import table while installing hooks");
        goto fail;
    }

    free(pe);
    g_loaded = image;
    *img = image;
    return 0;

fail:
    if (mapped) munmap(m, PE_MAPSZ);
    if (image) {
        free(image->hooks);
        free(image);
    }
    free(pe);
    return -1;
}

void *pe_rva_to_va(pe_image_t *img, uint32_t rva) {
    if (!img || !img->base || !img->image_size) return NULL;
    if (rva >= img->image_size) return NULL;
    return (unsigned char *)img->base + rva;
}

void pe_unload(pe_image_t *img) {
    if (!img || img != g_loaded) return;
    g_loaded = NULL;
    if (img->base && img->base != MAP_FAILED)
        munmap(img->base, img->map_size);
    free(img->hooks);
    free(img);
}

int pe_call_void(pe_image_t *img, uint32_t rva_or_va, void *arg, size_t n) {
    uint32_t words[3] = {0, 0, 0};
    uint64_t rva;
    unsigned char *state;
    pe_fn3_t fn;

    if (!img || !img->base) return -1;
    if (n > 12u || (n % 4u) != 0u) return -1;
    if (!arg && n) return -1;

    /* Accept either an RVA or a VA inside the mapped image. */
    rva = (rva_or_va >= PE_BASE) ? (uint64_t)rva_or_va - PE_BASE : rva_or_va;
    if (!map_ptr(img, rva, 1u)) return -1;
    state = map_ptr(img, TEA_STATE_RVA, TEA_STATE_SIZE);
    if (!state) return -1;

    if (n) memcpy(words, arg, n);             /* zero-fill words 1 and 2 */
    memset(state, 0, TEA_STATE_SIZE);         /* fresh state on every call */
    fn = (pe_fn3_t)(void *)((unsigned char *)img->base + (size_t)rva);
    fn(words[0], words[1], words[2]);          /* stdcall: callee cleans stack */
    return 0;
}

int pe_export(pe_image_t *img, const char *name, uint32_t *out_rva) {
    unsigned char *dir;
    uint32_t nfunc, nnames, eat, ent, ord;
    uint64_t i;

    if (!out_rva) return -1;
    *out_rva = 0;
    if (!img || !img->base || !name || !*name) return -1;
    if (!img->export_rva || img->export_size < EXPORT_DIR_SIZE) return -1;
    dir = map_ptr(img, img->export_rva, EXPORT_DIR_SIZE);
    if (!dir) return -1;

    nfunc = rd32(dir, 20);                    /* NumberOfFunctions */
    nnames = rd32(dir, 24);                   /* NumberOfNames */
    eat = rd32(dir, 28);                      /* AddressOfFunctions */
    ent = rd32(dir, 32);                      /* AddressOfNames */
    ord = rd32(dir, 36);                      /* AddressOfNameOrdinals */
    if (!nfunc || !nnames) return -1;
    if (!image_str(img, rd32(dir, 12), NULL)) return -1;  /* export DLL name */
    if (!map_ptr(img, eat, (uint64_t)nfunc * 4u) ||
        !map_ptr(img, ent, (uint64_t)nnames * 4u) ||
        !map_ptr(img, ord, (uint64_t)nnames * 2u)) return -1;

    for (i = 0; i < nnames; i++) {
        unsigned char *np = map_ptr(img, (uint64_t)ent + i * 4u, 4u);
        unsigned char *op = map_ptr(img, (uint64_t)ord + i * 2u, 2u);
        unsigned char *fp;
        char *candidate;
        uint32_t target, index;
        if (!np || !op) return -1;
        candidate = image_str(img, rd32(np, 0), NULL);
        if (!candidate) return -1;
        if (strcmp(candidate, name) != 0) continue;

        index = rd16(op, 0);
        if (index >= nfunc) return -1;        /* bad ordinal */
        fp = map_ptr(img, (uint64_t)eat + (uint64_t)index * 4u, 4u);
        if (!fp) return -1;
        target = rd32(fp, 0);
        if (!target) return -1;               /* unused EAT slot */
        /* A forwarder RVA points into the export directory, not at code. */
        if (target >= img->export_rva &&
            (uint64_t)target < (uint64_t)img->export_rva + img->export_size)
            return -1;
        *out_rva = target;
        return 0;
    }
    return -1;                                /* not found */
}
