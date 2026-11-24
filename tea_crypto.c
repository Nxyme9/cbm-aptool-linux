/* tea_crypto.c - CBMUsbDisk crypto dispatcher
 *
 * Backends:
 *   native (default) - clean-room pure-C cipher in tea_native.c
 *   PE harness       - mmap-at-ImageBase loader for the vendor TEA cores,
 *                      opt-in cross-check via --pe-crypto
 *
 * The public tea_* API keeps its signatures, so callers (cbm_container.c and
 * the existing test suites) automatically use the selected backend. There is
 * no silent fallback: if the requested backend cannot initialise, tea_init
 * fails and tea_encrypt/tea_decrypt refuse to run.
 *
 * PE cores: encrypt 0x459da0, decrypt 0x459d50, block fn 0x459ec0,
 * state 0x531328. PE functions use __stdcall (callee cleans stack).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "tea_crypto.h"
#include "cbm_backend.h"
#include "tea_native.h"

#define BASE 0x400000u
#define MAPSZ 0x140000u

typedef void (__attribute__((stdcall)) *encfn_t)(unsigned char *, int, const char *);
typedef void (__attribute__((stdcall)) *decfn_t)(unsigned char *, int, const char *);

static int g_ready = 0;
static int g_pe_mapped = 0;
static int g_backend = CBM_BACKEND_NATIVE;

int cbm_backend_from_arg(const char *arg, int *backend) {
    if (!arg || !backend) return -1;
    if (strcmp(arg, "--native-crypto") == 0) {
        *backend = CBM_BACKEND_NATIVE;
        return 0;
    }
    if (strcmp(arg, "--pe-crypto") == 0) {
        *backend = CBM_BACKEND_PE;
        return 0;
    }
    return -1;
}

void cbm_backend_set(int backend) {
    if (backend == CBM_BACKEND_NATIVE || backend == CBM_BACKEND_PE)
        g_backend = backend;
}

int cbm_backend_get(void) { return g_backend; }

static uint16_t rd16(const unsigned char *p, int o) {
    return (uint16_t)(p[o] | ((uint16_t)p[o + 1] << 8));
}
static uint32_t rd32(const unsigned char *p, int o) {
    return (uint32_t)p[o] | ((uint32_t)p[o + 1] << 8) |
           ((uint32_t)p[o + 2] << 16) | ((uint32_t)p[o + 3] << 24);
}

int tea_init(const char *pe_path) {
    if (g_ready) return 0;

    if (g_backend == CBM_BACKEND_NATIVE) {
        /* Pure-C cipher: no vendor binary, no mmap, no PE state to load. */
        g_ready = 1;
        return 0;
    }

    /* PE harness backend: map the vendor image at its ImageBase. */
    if (!pe_path || !pe_path[0]) return -1;
    FILE *f = fopen(pe_path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    if (n < 64) { fclose(f); return -1; }
    unsigned char *pe = malloc((size_t)n);
    if (!pe) { fclose(f); return -1; }
    if (fread(pe, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(pe); return -1; }
    fclose(f);

    uint32_t po = rd32(pe, 0x3c);
    uint16_t ns = rd16(pe, po + 6);
    uint16_t os = rd16(pe, po + 20);
    uint32_t sh = po + 24 + os;
    if ((size_t)sh + (size_t)ns * 40 > (size_t)n) { free(pe); return -1; }

    /* mmap at ImageBase (like rttest.c) */
    void *m = mmap((void *)BASE, MAPSZ, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (m == MAP_FAILED) { free(pe); return -1; }

    /* Load PE sections (exact same approach as rttest.c) */
    memcpy((void *)BASE, pe, sh + ns * 40);
    for (uint32_t i = 0; i < ns; i++) {
        const unsigned char *s = pe + sh + i * 40;
        uint32_t va = rd32(s, 12), rs = rd32(s, 16), rp = rd32(s, 20);
        if (rs && rp + rs <= (uint32_t)n)
            memcpy((void *)(BASE + va), pe + rp, rs);
    }
    free(pe);
    g_pe_mapped = 1;
    g_ready = 1;
    return 0;
}

void tea_cleanup(void) {
    if (g_pe_mapped) {
        munmap((void *)BASE, MAPSZ);
        g_pe_mapped = 0;
    }
    g_ready = 0;
}

int tea_is_ready(void) { return g_ready; }

int tea_encrypt(unsigned char *buf, size_t len, const char *key) {
    if (!g_ready) return -1;
    if (g_backend == CBM_BACKEND_NATIVE)
        return tea_native_encrypt(buf, len, key);
    encfn_t f = (encfn_t)(void *)0x459da0;
    /* Reset state before call */
    memset((void *)0x531328u, 0, TEA_STATE_SIZE);
    f(buf, (int)len, key);
    return 0;
}

int tea_decrypt(unsigned char *buf, size_t len, const char *key) {
    if (!g_ready) return -1;
    if (g_backend == CBM_BACKEND_NATIVE)
        return tea_native_decrypt(buf, len, key);
    decfn_t f = (decfn_t)(void *)0x459d50;
    memset((void *)0x531328u, 0, TEA_STATE_SIZE);
    f(buf, (int)len, key);
    return 0;
}
