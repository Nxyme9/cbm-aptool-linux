/* test_entropy_map.c - block entropy sampling, downsampling, region overlay
 * and JSON sidecar tests (Wave 5F Task 1).
 *
 * All fixtures are synthetic regular files under a mkdtemp root in
 * /tmp/opencode. No device is opened, read or written. The source image is
 * hashed before and after every map call to prove read-only behaviour.
 */
#define _GNU_SOURCE
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_decode.h"
#include "cbm_layout.h"
#include "entropy_map.h"

static int tests_passed = 0;
static int tests_failed = 0;
static char g_root[256];

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

#define BLOCK 256u
#define KP 1024u
#define MP (1024u * KP)

static void path_of(char *out, size_t outlen, const char *sub) {
    size_t rootlen = strlen(g_root);
    size_t sublen = strlen(sub);
    if (rootlen + 1u + sublen + 1u > outlen) { out[0] = '\0'; return; }
    memcpy(out, g_root, rootlen);
    out[rootlen] = '/';
    memcpy(out + rootlen + 1u, sub, sublen + 1u);
}

static int write_image(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t put = len ? fwrite(buf, 1, len, f) : 0;
    return (put == len && fclose(f) == 0) ? 0 : -1;
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

/* xorshift64* with a fixed seed: deterministic high-byte output. */
static uint64_t g_rng = 0x9e3779b97f4a7c15ULL;

static unsigned char rnd_byte(void) {
    g_rng ^= g_rng >> 12;
    g_rng ^= g_rng << 25;
    g_rng ^= g_rng >> 27;
    uint64_t v = g_rng * 0x2545f4914f6cdd1dULL;
    return (unsigned char)(v >> 56);
}

static void fill_random(unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) b[i] = rnd_byte();
}

static uint64_t hash_bytes(const unsigned char *b, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint64_t)b[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static double abs_diff(double a, double b) {
    return (a > b) ? (a - b) : (b - a);
}

static void put_u32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

/* Same DJ partition geometry as test_layout.c: three 0x83 partitions. */
static void build_dj_mbr(unsigned char *mbr) {
    const unsigned int starts[3] = {2048u, 1050624u, 9439232u};
    const unsigned int sizes[3]  = {1048576u, 8388608u, 45086720u};
    memset(mbr, 0, CBM_SECTOR_SIZE);
    for (int i = 0; i < 3; i++) {
        unsigned char *e = mbr + 446 + i * 16;
        e[0] = (i == 0) ? 0x80 : 0x00;
        e[4] = 0x83;
        put_u32(e + 8, starts[i]);
        put_u32(e + 12, sizes[i]);
    }
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
}

/* ---- 1: all-zero image -> exactly 0.0 ---------------------------------- */

static void test_zero_image_entropy_zero(void) {
    TEST("cbm_entropy_map: all-zero image -> exactly 0.0 per block");
    char img[256];
    path_of(img, sizeof(img), "zero.img");
    const size_t len = 3u * 1024u;
    unsigned char *buf = (unsigned char *)calloc(1, len);
    cbm_entropy_sample_t *s = NULL;
    size_t n = 0;
    char err[256] = {0};
    int ok = (buf != NULL);
    if (ok) ok = (write_image(img, buf, len) == 0);
    if (ok) ok = (cbm_entropy_map(img, 0, len, 1024, &s, &n, err, sizeof(err)) == 0);
    if (ok) ok = (n == 3u && s != NULL);
    if (ok) {
        for (size_t i = 0; i < n; i++) {
            if (s[i].entropy != 0.0 || s[i].length != 1024u ||
                s[i].offset != (unsigned long long)(i * 1024u)) { ok = 0; break; }
        }
    }
    /* Degenerate inputs return 0 samples without touching out. */
    if (ok) {
        cbm_entropy_sample_t one;
        memset(&one, 0x5a, sizeof(one));
        ok = (cbm_entropy_blocks(buf, 0, 512, 0, &one, 1) == 0 &&
              cbm_entropy_blocks(buf, 16, 0, 0, &one, 1) == 0 &&
              cbm_entropy_blocks(NULL, 16, 512, 0, &one, 1) == 0 &&
              one.length == (size_t)0x5a5a5a5a);
    }
    free(s);
    free(buf);
    if (ok) PASS(); else FAIL("zero image must produce exact zero entropy");
}

/* ---- 2: random image -> ~8 bits/byte ----------------------------------- */

static void test_random_image_entropy_eight(void) {
    TEST("cbm_entropy_map: xorshift64* image -> 7.9..8.0 bits/byte");
    char img[256];
    path_of(img, sizeof(img), "random.img");
    const size_t len = 4u * 4096u;
    unsigned char *buf = (unsigned char *)malloc(len);
    cbm_entropy_sample_t *s = NULL;
    size_t n = 0;
    char err[256] = {0};
    int ok = (buf != NULL);
    if (ok) { fill_random(buf, len); ok = (write_image(img, buf, len) == 0); }
    if (ok) ok = (cbm_entropy_map(img, 0, len, 4096, &s, &n, err, sizeof(err)) == 0);
    if (ok) ok = (n == 4u);
    if (ok) {
        for (size_t i = 0; i < n; i++) {
            if (s[i].entropy < 7.9 || s[i].entropy > 8.0) { ok = 0; break; }
        }
    }
    free(s);
    free(buf);
    if (ok) PASS(); else FAIL("random blocks must sample at ~8 bits/byte");
}

/* ---- 3: two exact entropy bands ---------------------------------------- */

static void test_half_zero_half_random_two_bands(void) {
    TEST("cbm_entropy_map: half zero / half random -> two exact bands");
    char img[256];
    path_of(img, sizeof(img), "bands.img");
    const size_t block = 4096u;
    const size_t len = 8u * block;
    unsigned char *buf = (unsigned char *)malloc(len);
    cbm_entropy_sample_t *s = NULL;
    size_t n = 0;
    char err[256] = {0};
    int ok = (buf != NULL);
    if (ok) {
        memset(buf, 0, len);
        fill_random(buf + 4u * block, 4u * block);
        ok = (write_image(img, buf, len) == 0);
    }
    if (ok) ok = (cbm_entropy_map(img, 0, len, block, &s, &n, err, sizeof(err)) == 0);
    if (ok) ok = (n == 8u);
    if (ok) {
        for (size_t i = 0; i < 4u; i++)
            if (s[i].entropy != 0.0) ok = 0;
        for (size_t i = 4u; i < 8u; i++)
            if (s[i].entropy < 7.9 || s[i].entropy > 8.0) ok = 0;
        if (s[4].offset != (unsigned long long)(4u * block)) ok = 0;
    }
    free(s);
    free(buf);
    if (ok) PASS(); else FAIL("band boundary must land on the exact block");
}

/* ---- 4: exact offsets/lengths incl. short final block ------------------ */

static void test_block_offsets_and_lengths(void) {
    TEST("cbm_entropy_blocks/map: exact offsets and short final block");
    char img[256];
    path_of(img, sizeof(img), "short.img");
    const size_t len = 3u * BLOCK + 37u;
    unsigned char *buf = (unsigned char *)malloc(len);
    unsigned char *exact = (unsigned char *)malloc(37u); /* ASan guard */
    cbm_entropy_sample_t direct[4];
    cbm_entropy_sample_t *s = NULL;
    size_t n = 0;
    char err[256] = {0};
    int ok = (buf != NULL && exact != NULL);
    if (ok) { fill_random(buf, len); memcpy(exact, buf + 3u * BLOCK, 37u); }
    if (ok) ok = (write_image(img, buf, len) == 0);
    if (ok) ok = (cbm_entropy_map(img, 0, len, BLOCK, &s, &n, err, sizeof(err)) == 0);
    if (ok) ok = (n == 4u);
    if (ok) {
        const size_t want_len[4] = {BLOCK, BLOCK, BLOCK, 37u};
        for (size_t i = 0; i < n; i++) {
            if (s[i].offset != (unsigned long long)(i * BLOCK) ||
                s[i].length != want_len[i]) ok = 0;
        }
    }
    /* Direct call on an exact-size buffer: no read past buf+37. */
    if (ok) {
        memset(direct, 0, sizeof(direct));
        size_t k = cbm_entropy_blocks(exact, 37u, BLOCK, 1000ULL, direct, 4);
        ok = (k == 1u && direct[0].offset == 1000ULL && direct[0].length == 37u &&
              abs_diff(direct[0].entropy, cbm_decode_entropy(exact, 37u)) < 1e-12);
    }
    if (ok) ok = (cbm_entropy_blocks(buf, len, BLOCK, 0, direct, 2) == 2u);
    free(s);
    free(exact);
    free(buf);
    if (ok) PASS(); else FAIL("block offsets/lengths or short final block wrong");
}

/* ---- 5: range bounds, rejection paths and read-only proof -------------- */

static void test_range_bounds(void) {
    TEST("cbm_entropy_map: [start,end) bounds, rejects bad args, no writes");
    char img[256];
    path_of(img, sizeof(img), "range.img");
    const size_t len = 10u * 512u;
    unsigned char *buf = (unsigned char *)malloc(len);
    cbm_entropy_sample_t *s = NULL;
    size_t n = 0;
    char err[256] = {0};
    uint64_t before = 0, after = 0;
    int ok = (buf != NULL);
    if (ok) { fill_random(buf, len); ok = (write_image(img, buf, len) == 0); }
    if (ok) { before = hash_bytes(buf, len); }
    if (ok) ok = (cbm_entropy_map(img, 512, 4096, 512, &s, &n, err, sizeof(err)) == 0);
    if (ok) ok = (n == 7u);
    if (ok) {
        for (size_t i = 0; i < n; i++) {
            if (s[i].offset < 512ULL ||
                s[i].offset + (unsigned long long)s[i].length > 4096ULL) ok = 0;
            if (s[i].offset != 512ULL + (unsigned long long)i * 512ULL) ok = 0;
        }
        if (n && s[n - 1u].offset + (unsigned long long)s[n - 1u].length != 4096ULL) ok = 0;
    }
    free(s); s = NULL; n = 0;
    if (ok) ok = (cbm_entropy_map(img, 1024, 1024, 512, &s, &n, err, sizeof(err)) == 0 &&
                  n == 0u && s == NULL);
    if (ok) { err[0] = 'x'; ok = (cbm_entropy_map(img, 4096, 512, 512, &s, &n, err, sizeof(err)) == -1 && err[0] != '\0'); }
    if (ok) { err[0] = 'x'; ok = (cbm_entropy_map(img, 0, len, 0, &s, &n, err, sizeof(err)) == -1 && err[0] != '\0'); }
    if (ok) {
        char missing[256];
        path_of(missing, sizeof(missing), "no-such-image.dat");
        err[0] = 'x';
        ok = (cbm_entropy_map(missing, 0, 512, 512, &s, &n, err, sizeof(err)) == -1 &&
              err[0] != '\0');
    }
    if (ok) {
        /* Over the cap: rejected before any read or allocation. */
        unsigned long long huge_end = CBM_ENTROPY_MAX_SAMPLES * 512ULL + 1ULL;
        err[0] = 'x';
        ok = (cbm_entropy_map(img, 0, huge_end, 512, &s, &n, err, sizeof(err)) == -1 &&
              strstr(err, "cap") != NULL);
    }
    if (ok) {
        size_t rlen = 0;
        unsigned char *after_buf = read_file(img, &rlen);
        ok = (after_buf != NULL && rlen == len);
        if (ok) after = hash_bytes(after_buf, rlen);
        free(after_buf);
        ok = ok && before == after;
    }
    free(s);
    free(buf);
    if (ok) PASS(); else FAIL("range bounds/rejections or source immutability wrong");
}

/* ---- 6: total, deterministic downsampling ------------------------------ */

static void test_downsample_total_and_deterministic(void) {
    TEST("cbm_entropy_downsample: total, two runs identical, ramp endpoints");
    char img[256];
    path_of(img, sizeof(img), "down.img");
    const size_t block = 64u;
    const size_t nsamples = 17u;
    const size_t width = 5u, height = 3u, total = 15u;
    unsigned char *buf = (unsigned char *)malloc(nsamples * block);
    cbm_entropy_sample_t *s = NULL;
    cbm_heatmap_pixel_t *a = NULL, *b = NULL;
    size_t n = 0;
    char err[256] = {0};
    int ok = (buf != NULL);
    if (ok) { fill_random(buf, nsamples * block); ok = (write_image(img, buf, nsamples * block) == 0); }
    if (ok) ok = (cbm_entropy_map(img, 0, nsamples * block, block, &s, &n, err, sizeof(err)) == 0);
    if (ok) ok = (n == nsamples);
    if (ok) {
        a = (cbm_heatmap_pixel_t *)malloc(total * sizeof(*a));
        b = (cbm_heatmap_pixel_t *)malloc(total * sizeof(*b));
        ok = (a != NULL && b != NULL);
    }
    if (ok) {
        /* Same initial padding on both sides: field values are compared
         * byte-for-byte, and struct padding is not written by the library. */
        memset(a, 0, total * sizeof(*a));
        memset(b, 0, total * sizeof(*b));
        ok = (cbm_entropy_downsample(s, n, width, height, a, total) == total &&
              cbm_entropy_downsample(s, n, width, height, b, total) == total);
    }
    if (ok) ok = (memcmp(a, b, total * sizeof(*a)) == 0);
    if (ok) {
        size_t sum = 0;
        double exp_min[15], exp_max[15], exp_sum[15];
        size_t exp_count[15], exp_first[15];
        for (size_t p = 0; p < total; p++) {
            exp_count[p] = 0; exp_first[p] = n;
            exp_min[p] = 0.0; exp_max[p] = 0.0; exp_sum[p] = 0.0;
        }
        for (size_t i = 0; i < n; i++) {
            size_t p = (size_t)((unsigned long long)i * (unsigned long long)total /
                                (unsigned long long)n);
            if (p >= total) { ok = 0; break; }
            if (exp_count[p] == 0) { exp_first[p] = i; exp_min[p] = s[i].entropy; exp_max[p] = s[i].entropy; }
            else {
                if (s[i].entropy < exp_min[p]) exp_min[p] = s[i].entropy;
                if (s[i].entropy > exp_max[p]) exp_max[p] = s[i].entropy;
            }
            exp_sum[p] += s[i].entropy;
            exp_count[p]++;
        }
        for (size_t p = 0; p < total && ok; p++) {
            if (a[p].index != p || a[p].sample_count != exp_count[p] ||
                a[p].first_sample != exp_first[p]) { ok = 0; break; }
            if (abs_diff(a[p].min, exp_min[p]) > 1e-12 ||
                abs_diff(a[p].max, exp_max[p]) > 1e-12 ||
                abs_diff(a[p].mean, exp_sum[p] / (double)exp_count[p]) > 1e-12) { ok = 0; break; }
            sum += a[p].sample_count;
        }
        if (ok) ok = (sum == n);
    }
    /* n < pixels: empty pixels are neutral grey with count 0; cap works. */
    if (ok) {
        ok = (cbm_entropy_downsample(s, 3, width, height, a, total) == total);
        if (ok) {
            size_t sum = 0;
            /* Empty-pixel contract: interior empties inherit the next occupied
             * pixel's first sample; trailing empties carry n (== 3 here). */
            size_t exp_first_sparse[15];
            size_t next_first = 3u;
            for (size_t p = total; p-- > 0;) {
                if (p % width == 0u && p / width < 3u) next_first = p / width;
                exp_first_sparse[p] = next_first;
            }
            for (size_t p = 0; p < total; p++) {
                sum += a[p].sample_count;
                if (a[p].sample_count == 0 &&
                    (a[p].first_sample != exp_first_sparse[p] ||
                     a[p].r != 128 || a[p].g != 128 || a[p].b != 128 ||
                     a[p].min != 0.0 || a[p].mean != 0.0 || a[p].max != 0.0)) ok = 0;
            }
            if (ok) ok = (sum == 3u);
        }
        if (ok) ok = (cbm_entropy_downsample(s, 3, width, height, b, 4) == 4u);
    }
    /* Ramp endpoints: 0 -> blue, 4 -> green, 8 -> red. */
    if (ok) {
        cbm_entropy_sample_t one;
        memset(&one, 0, sizeof(one));
        one.offset = 0; one.length = 64; one.entropy = 0.0;
        cbm_entropy_downsample(&one, 1, 1, 1, a, 1);
        ok = (a[0].r == 0 && a[0].g == 0 && a[0].b == 255);
        one.entropy = 4.0;
        cbm_entropy_downsample(&one, 1, 1, 1, a, 1);
        ok = ok && (a[0].r == 0 && a[0].g == 255 && a[0].b == 0);
        one.entropy = 8.0;
        cbm_entropy_downsample(&one, 1, 1, 1, a, 1);
        ok = ok && (a[0].r == 255 && a[0].g == 0 && a[0].b == 0);
    }
    free(a); free(b); free(s); free(buf);
    if (ok) PASS(); else FAIL("downsample must be total and deterministic");
}

/* ---- 7: region overlay from a synthetic MBR ---------------------------- */

static void test_regions_from_synthetic_mbr(void) {
    TEST("cbm_entropy_regions: DJ layout, honest non-DJ fallback");
    unsigned char mbr[CBM_SECTOR_SIZE];
    unsigned char bad[CBM_SECTOR_SIZE];
    cbm_entropy_sample_t s[5];
    cbm_entropy_region_t r[8];
    const unsigned long long b1 = 2048ULL * 512ULL;
    const unsigned long long b2 = 1050624ULL * 512ULL;
    const unsigned long long b3 = 9439232ULL * 512ULL;
    const unsigned long long b4 = 54525952ULL * 512ULL; /* end of DJ_DATA */
    int ok = 1;
    build_dj_mbr(mbr);
    memcpy(bad, mbr, sizeof(bad));
    bad[510] = 0x00; /* unparseable signature */

    memset(s, 0, sizeof(s));
    s[0].offset = 0;            s[0].length = 512; s[0].entropy = 1.0;
    s[1].offset = b1;           s[1].length = 512; s[1].entropy = 2.0;
    s[2].offset = b2;           s[2].length = 512; s[2].entropy = 3.0;
    s[3].offset = b3;           s[3].length = 512; s[3].entropy = 4.0;
    s[4].offset = b4 + 4096ULL; s[4].length = 512; s[4].entropy = 5.0;

    memset(r, 0xaa, sizeof(r));
    size_t nr = cbm_entropy_regions(s, 5, mbr, sizeof(mbr), r, 8);
    ok = (nr == 5u);
    if (ok) {
        const char *names[5] = {"MBR", "DJ_BOOT", "DJ_OS", "DJ_DATA", "TAIL"};
        const unsigned long long offs[5] = {0ULL, b1, b2, b3, b4};
        const unsigned long long lens[5] = {
            512ULL, 1048576ULL * 512ULL, 8388608ULL * 512ULL,
            45086720ULL * 512ULL, 4096ULL + 512ULL
        };
        for (size_t i = 0; i < 5u; i++) {
            if (strcmp(r[i].name, names[i]) != 0 || r[i].offset != offs[i] ||
                r[i].length != lens[i] || r[i].samples != 1u ||
                r[i].inferred != 1) { ok = 0; break; }
            if (abs_diff(r[i].min, (double)(i + 1u)) > 1e-12 ||
                abs_diff(r[i].mean, (double)(i + 1u)) > 1e-12 ||
                abs_diff(r[i].max, (double)(i + 1u)) > 1e-12) { ok = 0; break; }
        }
    }
    /* Bad signature: no DJ names, MBR + TAIL only, tail covers sampled bytes. */
    if (ok) {
        memset(r, 0, sizeof(r));
        nr = cbm_entropy_regions(s, 5, bad, sizeof(bad), r, 8);
        ok = (nr == 2u && strcmp(r[0].name, "MBR") == 0 &&
              r[0].length == 512ULL && strcmp(r[1].name, "TAIL") == 0 &&
              r[1].offset == 512ULL &&
              r[1].length == s[4].offset + (unsigned long long)s[4].length - 512ULL &&
              r[1].samples == 4u && r[0].inferred == 1 && r[1].inferred == 1);
        for (size_t i = 0; i < nr; i++) {
            if (strncmp(r[i].name, "DJ_", 3) == 0) ok = 0;
        }
    }
    if (ok) {
        ok = (cbm_entropy_regions(s, 5, mbr, sizeof(mbr), r, 2) == 2u &&
              cbm_entropy_regions(s, 0, mbr, sizeof(mbr), r, 8) == 0u &&
              cbm_entropy_regions(s, 5, mbr, sizeof(mbr), NULL, 8) == 0u);
    }
    /* No MBR buffer at all: TAIL only, covering every sampled byte. */
    if (ok) {
        memset(r, 0, sizeof(r));
        nr = cbm_entropy_regions(s, 5, NULL, 0, r, 8);
        ok = (nr == 1u && strcmp(r[0].name, "TAIL") == 0 &&
              r[0].offset == 0ULL &&
              r[0].length == s[4].offset + (unsigned long long)s[4].length &&
              r[0].samples == 5u &&
              r[0].min == 1.0 &&
              r[0].mean == 3.0 &&
              r[0].max == 5.0);
    }
    /* A region with no samples reports 0.0 for min/mean/max.
       With only the MBR sample, sampled_end=512 < last partition end: no TAIL
       is fabricated, so the honest overlay is MBR + 3 DJ partitions = 4. */
    if (ok) {
        nr = cbm_entropy_regions(s, 1, mbr, sizeof(mbr), r, 8);
        ok = (nr == 4u && r[1].samples == 0u &&
              r[1].min == 0.0 && r[1].mean == 0.0 && r[1].max == 0.0);
    }
    if (ok) PASS(); else FAIL("region overlay must be honest and inferred");
}

/* ---- 8: deterministic, locale-free JSON -------------------------------- */

static void test_json_deterministic(void) {
    TEST("cbm_entropy_json: byte-identical, exact fixed-point text");
    char a[256], b[256], c[256];
    path_of(a, sizeof(a), "a.json");
    path_of(b, sizeof(b), "b.json");
    path_of(c, sizeof(c), "c.json");
    cbm_entropy_sample_t s[4];
    cbm_entropy_region_t r[2];
    char err[256] = {0};
    static const char expected[] =
        "{\"block_bytes\":256,\"samples\":4,\"width\":2,\"height\":2,"
        "\"entropy\":{\"min\":0.000000,\"mean\":3.875000,\"max\":8.000000},"
        "\"regions\":[{\"name\":\"MBR\",\"offset\":0,\"length\":512,"
        "\"samples\":2,\"min\":0.000000,\"mean\":1.250000,\"max\":2.500000,"
        "\"inferred\":true},{\"name\":\"TAIL\",\"offset\":512,\"length\":512,"
        "\"samples\":2,\"min\":5.000000,\"mean\":6.500000,\"max\":8.000000,"
        "\"inferred\":true}]}\n";
    static const char expected_empty[] =
        "{\"block_bytes\":0,\"samples\":0,\"width\":8,\"height\":8,"
        "\"entropy\":{\"min\":0.000000,\"mean\":0.000000,\"max\":0.000000},"
        "\"regions\":[]}\n";
    memset(s, 0, sizeof(s));
    s[0].length = 256; s[0].entropy = 0.0;
    s[1].offset = 256; s[1].length = 256; s[1].entropy = 2.5;
    s[2].offset = 512; s[2].length = 256; s[2].entropy = 5.0;
    s[3].offset = 768; s[3].length = 256; s[3].entropy = 8.0;
    memset(r, 0, sizeof(r));
    r[0].name = "MBR";  r[0].offset = 0;   r[0].length = 512; r[0].samples = 2;
    r[0].min = 0.0; r[0].mean = 1.25; r[0].max = 2.5; r[0].inferred = 1;
    r[1].name = "TAIL"; r[1].offset = 512; r[1].length = 512; r[1].samples = 2;
    r[1].min = 5.0; r[1].mean = 6.5; r[1].max = 8.0; r[1].inferred = 1;

    size_t la = 0, lb = 0, lc = 0;
    unsigned char *ja = NULL, *jb = NULL, *jc = NULL;
    int ok = (cbm_entropy_json(a, s, 4, r, 2, 2, 2, err, sizeof(err)) == 0);
    if (ok) ok = (cbm_entropy_json(b, s, 4, r, 2, 2, 2, err, sizeof(err)) == 0);
    if (ok) {
        ja = read_file(a, &la);
        jb = read_file(b, &lb);
        ok = (ja != NULL && jb != NULL && la == sizeof(expected) - 1u &&
              la == lb && memcmp(ja, jb, la) == 0 &&
              memcmp(ja, expected, sizeof(expected) - 1u) == 0);
    }
    /* n == 0 emits valid JSON with empty arrays, not a malformed document. */
    if (ok) ok = (cbm_entropy_json(a, NULL, 0, NULL, 0, 8, 8, err, sizeof(err)) == 0);
    if (ok) {
        free(ja); ja = read_file(a, &la);
        ok = (ja != NULL && la == sizeof(expected_empty) - 1u &&
              memcmp(ja, expected_empty, sizeof(expected_empty) - 1u) == 0);
    }
    /* Comma-decimal locale must not corrupt fixed-point text. */
    const char *orig = setlocale(LC_NUMERIC, NULL);
    char *saved = orig ? strdup(orig) : NULL;
    if (ok) ok = (saved != NULL);
    if (ok) {
        static const char *const candidates[] = {
            "de_DE.UTF-8", "de_DE.utf8", "es_ES.UTF-8", "es_ES.utf8",
            "fr_FR.UTF-8", "fr_FR.utf8"
        };
        int chosen = 0;
        for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
            if (setlocale(LC_NUMERIC, candidates[i]) != NULL) {
                struct lconv *conv = localeconv();
                if (conv && conv->decimal_point && strcmp(conv->decimal_point, ".") != 0) {
                    chosen = 1;
                    break;
                }
            }
        }
        if (chosen) {
            /* Compare against the pinned full-JSON text: ja now holds the
             * n==0 document from the previous check. */
            ok = (cbm_entropy_json(c, s, 4, r, 2, 2, 2, err, sizeof(err)) == 0);
            if (ok) {
                jc = read_file(c, &lc);
                ok = (jc != NULL && lc == sizeof(expected) - 1u &&
                      memcmp(jc, expected, sizeof(expected) - 1u) == 0);
            }
        } /* else: no comma-decimal locale installed, fixed-point still proven */
        setlocale(LC_NUMERIC, saved);
    }
    free(saved);
    free(ja); free(jb); free(jc);
    if (ok) PASS(); else FAIL("JSON must be deterministic and locale-free");
}

int main(void) {
    printf("=== Entropy Map Tests ===\n");
    char tmpl[] = "/tmp/opencode/wave5f-entropy.XXXXXX";
    if (!mkdtemp(tmpl)) {
        printf("FAIL: mkdtemp failed\n");
        return 1;
    }
    snprintf(g_root, sizeof(g_root), "%s", tmpl);

    test_zero_image_entropy_zero();
    test_random_image_entropy_eight();
    test_half_zero_half_random_two_bands();
    test_block_offsets_and_lengths();
    test_range_bounds();
    test_downsample_total_and_deterministic();
    test_regions_from_synthetic_mbr();
    test_json_deterministic();

    printf("\nScratch fixtures: %s\n", g_root);
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
