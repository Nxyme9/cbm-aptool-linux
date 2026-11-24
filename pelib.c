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
#include <sys/mman.h>

#define DEFAULT_PE_PATH "/tmp/opencode/ap.exe"
#define DOS_HEADER_SIZE 64u
#define PE_SIG_SIZE 4u
#define COFF_HEADER_SIZE 20u
#define SECTION_HEADER_SIZE 40u
#define PE32_OPT_MIN 60u     /* SizeOfImage lives at optional-header +56 */
#define PE32_MAGIC 0x10bu
#define IMAGE_BASE_FIELD 28u
#define SIZE_OF_IMAGE_FIELD 56u
#define MAX_PE_FILE (256u * 1024u * 1024u)

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

struct pe_image {
    void *base;
    uint32_t map_size;
    uint32_t image_size;
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
    uint32_t po, ns, os, declared_size;
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
        path = (env && *env) ? env : DEFAULT_PE_PATH;
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
