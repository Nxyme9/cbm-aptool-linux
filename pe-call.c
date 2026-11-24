/* pe-call.c - invoke one target in a 32-bit PE through pelib and show args
 *
 * Usage: pe-call <pe-path> <rva|export-name> <hex-args>
 *
 * hex-args is a packed array of 1-3 little-endian uint32 words, written as
 * 8-24 hex digits (4-12 bytes, a multiple of 4). The words are passed to the
 * target through pelib's 3-word __stdcall ABI; missing words are zero-filled.
 *
 * A zero-filled scratch page at fixed VA 0x600000 is mapped for the duration
 * of the call: caller-supplied pointers such as 0x00600100 can be used as
 * buffers. If args[0] lands in that page, its bytes are printed after the call
 * so in-place output (e.g. TEA ciphertext) is observable.
 */
#define _GNU_SOURCE
#include "pelib.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define SCRATCH_VA 0x600000u
#define SCRATCH_SZ 0x1000u
#define MAX_ARG_BYTES 12u
#define DUMP_BYTES 64u

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s <pe-path> <rva|export-name> <hex-args>\n", argv0);
}

static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex pairs into bytes: the first four bytes are word 0, and so on. */
static int decode_args(const char *hex, unsigned char *out, size_t *out_n) {
    size_t len = strlen(hex), i;
    if (!len || len > MAX_ARG_BYTES * 2u || (len % 4u) != 0u) return -1;
    for (i = 0; i < len; i += 2u) {
        int hi = hex_digit((unsigned char)hex[i]);
        int lo = hex_digit((unsigned char)hex[i + 1u]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2u] = (unsigned char)((hi << 4) | lo);
    }
    *out_n = len / 2u;
    return 0;
}

/* Pure-hex targets are RVAs (or VAs >= PE_BASE); anything else is an export
 * name. A name made only of hex digits is therefore not addressable. */
static int parse_target(const char *s, uint32_t *out) {
    char *end;
    unsigned long v;
    if (!s || !*s || s[0] == '+' || s[0] == '-') return 0;
    errno = 0;
    v = strtoul(s, &end, 16);
    if (errno || *end || v > 0xffffffffUL) return 0;
    *out = (uint32_t)v;
    return 1;
}

static void dump_hex(const unsigned char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", p[i]);
}

int main(int argc, char **argv) {
    pe_image_t *img = NULL;
    unsigned char args[MAX_ARG_BYTES] = {0};
    unsigned char *scratch = MAP_FAILED;
    size_t n = 0, off, take;
    uint32_t target = 0, p0;
    int rc = 1;

    if (argc != 4) { usage(argv[0]); return 2; }
    if (decode_args(argv[3], args, &n) != 0) {
        fprintf(stderr, "pe-call: hex-args must be 4-12 bytes (8-24 hex digits), multiple of 4\n");
        return 2;
    }
    if (pe_load(&img, argv[1], NULL) != 0) {
        fprintf(stderr, "pe-call: cannot load PE: %s\n", argv[1]);
        return 1;
    }
    if (!parse_target(argv[2], &target) && pe_export(img, argv[2], &target) != 0) {
        fprintf(stderr, "pe-call: export not found: %s\n", argv[2]);
        goto done;
    }
    scratch = mmap((void *)(uintptr_t)SCRATCH_VA, SCRATCH_SZ,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (scratch == MAP_FAILED || scratch != (void *)(uintptr_t)SCRATCH_VA) {
        if (scratch != MAP_FAILED) munmap(scratch, SCRATCH_SZ);
        fprintf(stderr, "pe-call: scratch VA 0x%06x unavailable\n", SCRATCH_VA);
        scratch = MAP_FAILED;
        goto done;
    }
    if (pe_call_void(img, target, args, n) != 0) {
        fprintf(stderr, "pe-call: call to 0x%08x failed\n", target);
        goto done;
    }

    printf("args: ");
    dump_hex(args, n);
    putchar('\n');

    /* args[0] is often a buffer pointer; show what the target wrote there. */
    memcpy(&p0, args, sizeof p0);
    if (p0 >= SCRATCH_VA && (uint64_t)(p0 - SCRATCH_VA) < SCRATCH_SZ) {
        off = (size_t)(p0 - SCRATCH_VA);
        take = SCRATCH_SZ - off;
        if (take > DUMP_BYTES) take = DUMP_BYTES;
        printf("buffer@0x%08x: ", p0);
        dump_hex(scratch + off, take);
        putchar('\n');
    }
    rc = 0;

done:
    if (scratch != MAP_FAILED) munmap(scratch, SCRATCH_SZ);
    pe_unload(img);
    return rc;
}
