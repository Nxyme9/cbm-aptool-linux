#define _GNU_SOURCE
/* test_png_write.c - PNG encoder/decoder tests (Wave 5F Task 2).
 *
 * All fixtures are synthetic PNG files under a mkdtemp root in /tmp/opencode.
 * The decoder used for the round-trip check is png_read_rgb (zlib + stdio);
 * no image library and no device are involved.
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>

#include "png_write.h"

static int tests_passed = 0;
static int tests_failed = 0;
static char g_root[256];

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

#define W 7u
#define H 5u
#define ROWBYTES (1u + W * 3u)

#define T_IHDR 0x49484452UL /* "IHDR" */
#define T_IDAT 0x49444154UL /* "IDAT" */
#define T_IEND 0x49454e44UL /* "IEND" */

typedef struct {
    unsigned long type;   /* big-endian 4-byte type */
    unsigned long len;    /* data length */
    const unsigned char *data;
    unsigned long crc;    /* stored big-endian CRC */
} png_chunk_t;

static void path_of(char *out, size_t outlen, const char *sub) {
    size_t rootlen = strlen(g_root);
    size_t sublen = strlen(sub);
    if (rootlen + 1u + sublen + 1u > outlen) { out[0] = '\0'; return; }
    memcpy(out, g_root, rootlen);
    out[rootlen] = '/';
    memcpy(out + rootlen + 1u, sub, sublen + 1u);
}

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseeko(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    off_t end = ftello(f);
    if (end < 0 || fseeko(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    unsigned char *buf = (unsigned char *)malloc((size_t)end + 1u);
    if (!buf) { fclose(f); return NULL; }
    size_t got = end ? fread(buf, 1, (size_t)end, f) : 0;
    int bad = ferror(f) || got != (size_t)end;
    fclose(f);
    if (bad) { free(buf); return NULL; }
    buf[(size_t)end] = '\0';
    *len = (size_t)end;
    return buf;
}

static unsigned long be32(const unsigned char *p) {
    return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16) |
           ((unsigned long)p[2] << 8) | (unsigned long)p[3];
}

/* Known 7x5 gradient: distinct deterministic values in every channel. */
static void gradient(unsigned char *rgb) {
    for (unsigned int y = 0; y < H; y++) {
        for (unsigned int x = 0; x < W; x++) {
            unsigned char *p = rgb + (size_t)(y * W + x) * 3u;
            p[0] = (unsigned char)(x * 36u + y * 3u);
            p[1] = (unsigned char)(y * 51u + x * 5u);
            p[2] = (unsigned char)((x + y) * 17u);
        }
    }
}

/* Verify signature, chunk framing, every CRC, IEND-last and no trailing data.
 * Returns the ordered chunk list (the caller supplies capacity). */
static int parse_png(const unsigned char *buf, size_t len,
                     png_chunk_t *chunks, size_t max, size_t *nchunks) {
    static const unsigned char sig[8] = {
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
    };
    if (!buf || !chunks || !nchunks || len < 8u ||
        memcmp(buf, sig, sizeof(sig)) != 0) return -1;
    size_t pos = 8u, n = 0;
    while (pos < len) {
        if (len - pos < 12u || n >= max) return -1;
        unsigned long clen = be32(buf + pos);
        if ((size_t)clen > len - pos - 12u) return -1;
        png_chunk_t *c = &chunks[n];
        c->type = be32(buf + pos + 4u);
        c->len = clen;
        c->data = buf + pos + 8u;
        c->crc = be32(buf + pos + 8u + (size_t)clen);
        uLong crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, buf + pos + 4u, 4u);
        if (clen) crc = crc32(crc, buf + pos + 8u, (uInt)clen);
        if ((unsigned long)crc != c->crc) return -1;
        pos += 12u + (size_t)clen;
        n++;
        if (c->type == T_IEND) break;
    }
    if (n == 0u || pos != len) return -1; /* empty or trailing garbage */
    *nchunks = n;
    return 0;
}

/* ---- 1: signature, chunk order and CRCs --------------------------------- */

static void test_png_signature_and_chunk_order(void) {
    TEST("png_write_rgb: signature, IHDR/IDAT/IEND order, valid CRCs");
    char path[256];
    path_of(path, sizeof(path), "order.png");
    unsigned char rgb[W * H * 3u];
    gradient(rgb);
    char err[256] = {0};
    remove(path); /* a stale fixture must not make this pass */
    int ok = (png_write_rgb(path, rgb, W, H, err, sizeof(err)) == 0);
    size_t len = 0;
    unsigned char *buf = ok ? read_file(path, &len) : NULL;
    if (ok) ok = (buf != NULL);
    static const unsigned char sig[8] = {
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
    };
    if (ok) ok = (len >= 8u && memcmp(buf, sig, sizeof(sig)) == 0);
    png_chunk_t chunks[8];
    size_t nc = 0;
    if (ok) ok = (parse_png(buf, len, chunks, 8u, &nc) == 0);
    if (ok) ok = (nc == 3u && chunks[0].type == T_IHDR &&
                  chunks[1].type == T_IDAT && chunks[2].type == T_IEND &&
                  chunks[2].len == 0u);
    free(buf);
    if (ok) PASS(); else FAIL("PNG must be signature + IHDR + IDAT + IEND with valid CRCs");
}

/* ---- 2: IHDR fields ------------------------------------------------------ */

static void test_png_ihdr_fields(void) {
    TEST("png_write_rgb: IHDR is 8-bit RGB (type 2), no compression/filter/interlace");
    char path[256];
    path_of(path, sizeof(path), "ihdr.png");
    unsigned char rgb[W * H * 3u];
    gradient(rgb);
    char err[256] = {0};
    int ok = (png_write_rgb(path, rgb, W, H, err, sizeof(err)) == 0);
    size_t len = 0;
    unsigned char *buf = ok ? read_file(path, &len) : NULL;
    if (ok) ok = (buf != NULL);
    png_chunk_t chunks[8];
    size_t nc = 0;
    if (ok) ok = (parse_png(buf, len, chunks, 8u, &nc) == 0 && nc == 3u);
    if (ok) ok = (chunks[0].len == 13u);
    if (ok) {
        const unsigned char *d = chunks[0].data;
        ok = (be32(d) == (unsigned long)W && be32(d + 4u) == (unsigned long)H &&
              d[8] == 8u && d[9] == 2u && d[10] == 0u &&
              d[11] == 0u && d[12] == 0u);
    }
    free(buf);
    if (ok) PASS(); else FAIL("IHDR fields must be 7x5, depth 8, type 2, zeros");
}

/* ---- 3: byte-exact round trip through the decoder ----------------------- */

static void test_png_roundtrip_rgb(void) {
    TEST("png_read_rgb: 7x5 gradient decodes to exact width, height and every byte");
    char path[256];
    path_of(path, sizeof(path), "roundtrip.png");
    unsigned char rgb[W * H * 3u];
    gradient(rgb);
    char err[256] = {0};
    int ok = (png_write_rgb(path, rgb, W, H, err, sizeof(err)) == 0);
    unsigned char *dec = NULL;
    size_t w = 0, h = 0;
    if (ok) ok = (png_read_rgb(path, &dec, &w, &h, err, sizeof(err)) == 0);
    if (ok) ok = (w == (size_t)W && h == (size_t)H && dec != NULL);
    if (ok) ok = (memcmp(dec, rgb, sizeof(rgb)) == 0);
    free(dec);
    if (ok) PASS(); else FAIL("round-trip PNG must reproduce every RGB byte");
}

/* ---- 4: filter bytes are zero and the raw stream is exactly sized ------- */

static void test_png_filter_bytes_zero(void) {
    TEST("png_write_rgb: IDAT inflates to height*(1+width*3), all filter bytes 0");
    char path[256];
    path_of(path, sizeof(path), "filters.png");
    unsigned char rgb[W * H * 3u];
    gradient(rgb);
    char err[256] = {0};
    int ok = (png_write_rgb(path, rgb, W, H, err, sizeof(err)) == 0);
    size_t len = 0;
    unsigned char *buf = ok ? read_file(path, &len) : NULL;
    if (ok) ok = (buf != NULL);
    png_chunk_t chunks[8];
    size_t nc = 0;
    if (ok) ok = (parse_png(buf, len, chunks, 8u, &nc) == 0 && nc == 3u);
    if (ok) ok = (chunks[1].type == T_IDAT && chunks[1].len <= UINT_MAX);
    const size_t expected = (size_t)H * (size_t)ROWBYTES;
    unsigned char *raw = ok ? (unsigned char *)malloc(expected) : NULL;
    if (ok) ok = (raw != NULL);
    if (ok) {
        uLongf outlen = (uLongf)expected;
        int zr = uncompress(raw, &outlen, chunks[1].data,
                            (uLong)chunks[1].len);
        ok = (zr == Z_OK && (size_t)outlen == expected);
    }
    if (ok) {
        for (size_t y = 0; y < (size_t)H && ok; y++) {
            const unsigned char *row = raw + y * (size_t)ROWBYTES;
            ok = (row[0] == 0u &&
                  memcmp(row + 1u, rgb + y * (size_t)W * 3u,
                         (size_t)W * 3u) == 0);
        }
    }
    free(raw);
    free(buf);
    if (ok) PASS(); else FAIL("IDAT must inflate to filter-0 rows matching the RGB input");
}

/* ---- 5: degenerate dimensions and buffers are rejected ------------------ */

static void test_png_rejects_zero_dimensions(void) {
    TEST("png_write_rgb: zero dimensions/NULL/overflow rejected without a file");
    char p1[256], p2[256], p3[256], p4[256];
    path_of(p1, sizeof(p1), "zero-width.png");
    path_of(p2, sizeof(p2), "zero-height.png");
    path_of(p3, sizeof(p3), "null-rgb.png");
    path_of(p4, sizeof(p4), "overflow.png");
    unsigned char rgb[W * H * 3u];
    gradient(rgb);
    char err[256];
    int ok = 1;
    remove(p1); remove(p2); remove(p3); remove(p4);
    memset(err, 0, sizeof(err));
    ok = (png_write_rgb(p1, rgb, 0u, H, err, sizeof(err)) == -1 && err[0] != '\0');
    memset(err, 0, sizeof(err));
    ok = ok && (png_write_rgb(p2, rgb, W, 0u, err, sizeof(err)) == -1 && err[0] != '\0');
    memset(err, 0, sizeof(err));
    ok = ok && (png_write_rgb(p3, NULL, W, H, err, sizeof(err)) == -1 && err[0] != '\0');
    memset(err, 0, sizeof(err));
    ok = ok && (png_write_rgb(p4, rgb, (size_t)-1, 2u, err, sizeof(err)) == -1 &&
                err[0] != '\0');
    FILE *f = NULL;
    f = fopen(p1, "rb"); if (f) { fclose(f); ok = 0; }
    f = fopen(p2, "rb"); if (f) { fclose(f); ok = 0; }
    f = fopen(p3, "rb"); if (f) { fclose(f); ok = 0; }
    f = fopen(p4, "rb"); if (f) { fclose(f); ok = 0; }
    if (ok) PASS(); else FAIL("degenerate dimensions must fail without writing a file");
}

int main(void) {
    printf("=== PNG Write Tests ===\n");
    char tmpl[] = "/tmp/opencode/wave5f-png.XXXXXX";
    if (!mkdtemp(tmpl)) {
        printf("FAIL: mkdtemp failed\n");
        return 1;
    }
    snprintf(g_root, sizeof(g_root), "%s", tmpl);

    test_png_signature_and_chunk_order();
    test_png_ihdr_fields();
    test_png_roundtrip_rgb();
    test_png_filter_bytes_zero();
    test_png_rejects_zero_dimensions();

    printf("\nScratch fixtures: %s\n", g_root);
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
