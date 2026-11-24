/* tea_crypto.c - TEA-based CBMUsbDisk crypto implementation
 * Uses mmap-at-ImageBase PE harness to load TEA cores from the PE binary.
 * Cores: encrypt 0x459da0, decrypt 0x459d50, block fn 0x459ec0, state 0x531328
 * Key: "1a2b3c4d5e6fTENG"
 * IMPORTANT: PE functions use __stdcall calling convention (callee cleans stack)
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

#define BASE 0x400000u
#define MAPSZ 0x140000u

typedef void (__attribute__((stdcall)) *encfn_t)(unsigned char *, int, const char *);
typedef void (__attribute__((stdcall)) *decfn_t)(unsigned char *, int, const char *);

static int g_ready = 0;

static uint16_t rd16(const unsigned char *p, int o) {
    return (uint16_t)(p[o] | ((uint16_t)p[o + 1] << 8));
}
static uint32_t rd32(const unsigned char *p, int o) {
    return (uint32_t)p[o] | ((uint32_t)p[o + 1] << 8) |
           ((uint32_t)p[o + 2] << 16) | ((uint32_t)p[o + 3] << 24);
}

int tea_init(const char *pe_path) {
    if (g_ready) return 0;
    FILE *f = fopen(pe_path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    unsigned char *pe = malloc(n);
    if (fread(pe, 1, n, f) != (size_t)n) { fclose(f); free(pe); return -1; }
    fclose(f);

    /* mmap at ImageBase (like rttest.c) */
    void *m = mmap((void *)BASE, MAPSZ, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (m == MAP_FAILED) { free(pe); return -1; }

    /* Load PE sections (exact same approach as rttest.c) */
    uint32_t po = rd32(pe, 0x3c);
    uint16_t ns = rd16(pe, po + 6);
    uint16_t os = rd16(pe, po + 20);
    uint32_t sh = po + 24 + os;
    memcpy((void *)BASE, pe, sh + ns * 40);
    for (uint32_t i = 0; i < ns; i++) {
        const unsigned char *s = pe + sh + i * 40;
        uint32_t va = rd32(s, 12), rs = rd32(s, 16), rp = rd32(s, 20);
        if (rs && rp + rs <= (uint32_t)n)
            memcpy((void *)(BASE + va), pe + rp, rs);
    }
    free(pe);
    g_ready = 1;
    return 0;
}

void tea_cleanup(void) { g_ready = 0; munmap((void *)BASE, MAPSZ); }

int tea_is_ready(void) { return g_ready; }

int tea_encrypt(unsigned char *buf, size_t len, const char *key) {
    if (!g_ready) return -1;
    encfn_t f = (encfn_t)(void *)0x459da0;
    /* Reset state before call */
    memset((void *)0x531328u, 0, TEA_STATE_SIZE);
    f(buf, (int)len, key);
    return 0;
}

int tea_decrypt(unsigned char *buf, size_t len, const char *key) {
    if (!g_ready) return -1;
    decfn_t f = (decfn_t)(void *)0x459d50;
    memset((void *)0x531328u, 0, TEA_STATE_SIZE);
    f(buf, (int)len, key);
    return 0;
}
