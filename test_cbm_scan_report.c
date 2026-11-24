/* test_cbm_scan_report.c - JSON report + carving tests
 *
 * Synthetic images only: scratch regular files under /tmp/opencode, built
 * with the repository's own TEA encryptor and the allowlisted published test
 * key. No device is opened, read or written. RED phase: this suite links
 * against cbm_scan_report.c, which does not exist until Step 2.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cbm_container.h"
#include "cbm_file.h"
#include "cbm_fuzz.h"
#include "tea_crypto.h"

#include "cbm_scan.h"
#include "cbm_scan_report.h"

static int tests_passed = 0;
static int tests_failed = 0;
static char g_root[256];

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

#define BODY_LEN ((size_t)(CBM_CONTAINER_SIZE - CBM_HEADER_SIZE))
#define LBA 512ULL

static void path_of(char *out, size_t outlen, const char *sub) {
    snprintf(out, outlen, "%s/%s", g_root, sub);
}

/* NUL-terminated exact-size read; caller frees. Returns NULL on any error. */
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

static int write_image(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t put = len ? fwrite(buf, 1, len, f) : 0;
    return (put == len && fclose(f) == 0) ? 0 : -1;
}

/* Non-periodic printable body with a token at offset 0 (same fixture shape
 * as test_cbm_scan.c), then TEA-encrypt with the published test key. */
static void fill_body(unsigned char *body, size_t len) {
    unsigned int s = 12345u;
    for (size_t i = 0; i < len; i++) {
        s = s * 1664525u + 1013904223u;
        unsigned int r = s >> 24;
        body[i] = (r < 13u) ? 0u : (unsigned char)(0x20u + (r % 95u));
    }
    memcpy(body, "CBM-FORE", 8u);
    memcpy(body + len - 8u, "NSIC-END", 8u);
}

static int make_container(unsigned char *out, unsigned char header) {
    fill_body(out + CBM_HEADER_SIZE, BODY_LEN);
    out[0] = header;
    return cbm_cbc_encrypt(out + CBM_HEADER_SIZE, BODY_LEN, cbm_fuzz_tea_key);
}

static void base_hit(cbm_scan_hit_t *h, unsigned long long off,
                     unsigned char header) {
    memset(h, 0, sizeof(*h));
    h->offset = off;
    h->header = header;
    h->entropy = 4.25;
    memset(h->sha256, 0xab, sizeof(h->sha256));
}

static void set_token(cbm_scan_hit_t *h, unsigned idx,
                      unsigned long long off, const char *text) {
    snprintf(h->tokens[idx], sizeof(h->tokens[idx]), "%s", text);
    h->token_offsets[idx] = off;
    if (h->token_count <= idx) h->token_count = idx + 1u;
}

/* ---- test 1: deterministic JSON ---------------------------------------- */

static void test_json_deterministic(void) {
    TEST("cbm_scan_write_json: two writes byte-identical, schema-stable");
    char a[512], b[512];
    path_of(a, sizeof(a), "report-a.json");
    path_of(b, sizeof(b), "report-b.json");
    cbm_scan_hit_t hits[2];
    base_hit(&hits[0], 2048ULL, 0x5a);
    set_token(&hits[0], 0, 0ULL, "CBM-FORE");
    base_hit(&hits[1], 1048576ULL, 0x00);
    set_token(&hits[1], 0, 128ULL, "SECOND-TOKEN");

    char err[256];
    err[0] = '\0';
    size_t la = 0, lb = 0;
    unsigned char *ja = NULL, *jb = NULL;
    int ok = (cbm_scan_write_json(a, hits, 2, err, sizeof(err)) == 0);
    if (ok) ok = (cbm_scan_write_json(b, hits, 2, err, sizeof(err)) == 0);
    if (ok) {
        ja = read_file(a, &la);
        jb = read_file(b, &lb);
        ok = (ja != NULL && jb != NULL && la > 0 && la == lb &&
              memcmp(ja, jb, la) == 0);
    }
    if (ok) {
        /* Field order and exact types, fixed-point '.' and lowercase hex. */
        const char *s = (const char *)ja;
        ok = (strstr(s, "\"offset\": 2048") != NULL &&
              strstr(s, "\"header\": 90") != NULL &&
              strstr(s, "\"entropy\": 4.250000") != NULL &&
              strstr(s, "\"sha256\": \"abababababababababababababababab"
                         "abababababababababababababababab\"") != NULL &&
              strstr(s, "\"tokens\": [") != NULL &&
              strstr(s, "\"text\": \"CBM-FORE\"") != NULL &&
              strstr(s, "\"offset\": 1048576") != NULL &&
              strstr(s, "\"text\": \"SECOND-TOKEN\"") != NULL &&
              strstr(s, "4,25") == NULL &&
              ja[la - 1u] == '\n');
        if (!ok) printf("[json: %.160s] ", s);
    }
    free(ja);
    free(jb);
    if (ok) PASS(); else FAIL("JSON must be byte-identical with fixed field order");
}

/* ---- test 2: JSON string escaping -------------------------------------- */

static void test_json_escape(void) {
    TEST("cbm_scan_write_json: quotes, backslashes and controls escaped");
    char path[512];
    path_of(path, sizeof(path), "escape.json");
    cbm_scan_hit_t h;
    base_hit(&h, 4ULL * LBA, 0x5a);
    /* Raw token bytes: q " u \ o LF t e TAB x 0x01 z */
    set_token(&h, 0, 0ULL, "q\"u\\o\nte\tx\x01z");

    char err[256];
    err[0] = '\0';
    size_t len = 0;
    unsigned char *buf = NULL;
    int ok = (cbm_scan_write_json(path, &h, 1, err, sizeof(err)) == 0);
    if (ok) {
        buf = read_file(path, &len);
        ok = (buf != NULL);
    }
    if (ok) {
        const char *s = (const char *)buf;
        ok = (strstr(s, "\"text\": \"q\\\"u\\\\o\\nte\\tx\\u0001z\"") != NULL &&
              memchr(buf, 0x01, len) == NULL &&
              memchr(buf, '\t', len) == NULL);
        if (!ok) printf("[json: %.160s] ", s);
    }
    free(buf);
    if (ok) PASS(); else FAIL("JSON strings must escape quotes/backslash/control bytes");
}

/* ---- test 3: carve names and exact bytes ------------------------------- */

static void test_carve_names_and_bytes(void) {
    TEST("cbm_scan_carve: hit-NNN-offset names, exact 85688-byte bodies");
    char image[512], dir[512], out_a[640], out_b[640];
    path_of(image, sizeof(image), "carve.img");
    path_of(dir, sizeof(dir), "carved");

    const unsigned long long a = 4ULL * LBA;
    const unsigned long long b = 2048ULL * LBA;
    const size_t img_len = (size_t)(b + CBM_CONTAINER_SIZE + LBA);
    unsigned char *img = (unsigned char *)calloc(1, img_len);
    cbm_scan_hit_t *hits = NULL;
    size_t n = 0, la = 0, lb = 0, lsrc = 0;
    unsigned char *carved_a = NULL, *carved_b = NULL, *after = NULL;
    unsigned char before[32], hash_after[32];
    char err[256];
    err[0] = '\0';
    int ok = (img != NULL);
    if (ok) ok = (make_container(img + a, 0x5a) == 0 &&
                  make_container(img + b, 0xa5) == 0);
    if (ok) ok = (write_image(image, img, img_len) == 0);
    if (ok) cbm_fuzz_sha256(img, img_len, before);
    if (ok) ok = (cbm_scan_image(image, 0, (unsigned long long)img_len - 1u,
                                 3u * CBM_CONTAINER_SIZE, NULL, 0,
                                 &hits, &n, err, sizeof(err)) == 0);
    if (ok) ok = (n == 2 && hits[0].offset == a && hits[1].offset == b);
    if (ok) ok = (cbm_scan_carve(dir, image, hits, n, err, sizeof(err)) == 0);

    snprintf(out_a, sizeof(out_a), "%s/hit-001-%llu.cbm", dir, a);
    snprintf(out_b, sizeof(out_b), "%s/hit-002-%llu.cbm", dir, b);
    if (ok) {
        carved_a = read_file(out_a, &la);
        carved_b = read_file(out_b, &lb);
        ok = (carved_a != NULL && carved_b != NULL &&
              la == CBM_CONTAINER_SIZE && lb == CBM_CONTAINER_SIZE &&
              memcmp(carved_a, img + a, CBM_CONTAINER_SIZE) == 0 &&
              memcmp(carved_b, img + b, CBM_CONTAINER_SIZE) == 0);
    }
    if (ok) {
        after = read_file(image, &lsrc);
        ok = (after != NULL && lsrc == img_len);
        if (ok) cbm_fuzz_sha256(after, lsrc, hash_after);
        ok = ok && (memcmp(before, hash_after, sizeof(before)) == 0);
    }
    free(carved_a);
    free(carved_b);
    free(after);
    cbm_scan_free_hits(hits);
    free(img);
    if (ok) PASS(); else FAIL("carve names/bytes or source immutability mismatch");
}

/* ---- test 4: carve refuses the source image ---------------------------- */

static void test_carve_refuses_source_alias(void) {
    TEST("cbm_scan_carve: refuses --carve aliasing the source image");
    char image[512], sibling[640];
    path_of(image, sizeof(image), "alias.img");
    path_of(sibling, sizeof(sibling), "alias-hit-001-2048.cbm");
    const unsigned long long a = 4ULL * LBA;
    const size_t img_len = (size_t)(a + CBM_CONTAINER_SIZE + LBA);
    unsigned char *img = (unsigned char *)calloc(1, img_len);
    unsigned char *after = NULL;
    size_t lsrc = 0;
    unsigned char before[32], hash_after[32];
    cbm_scan_hit_t hit;
    char err[256];
    int ok = (img != NULL);
    if (ok) ok = (make_container(img + a, 0x5a) == 0);
    if (ok) ok = (write_image(image, img, img_len) == 0);
    if (ok) cbm_fuzz_sha256(img, img_len, before);
    base_hit(&hit, a, 0x5a);
    set_token(&hit, 0, 0ULL, "CBM-FORE");

    /* dir == source file, and dir == the source's own directory. */
    err[0] = 'x';
    if (ok) ok = (cbm_scan_carve(image, image, &hit, 1, err, sizeof(err)) == -1 &&
                  err[0] != '\0');
    if (ok) {
        err[0] = 'x';
        ok = (cbm_scan_carve(g_root, image, &hit, 1, err, sizeof(err)) == -1 &&
              err[0] != '\0');
    }
    if (ok) {
        after = read_file(image, &lsrc);
        ok = (after != NULL && lsrc == img_len);
        if (ok) cbm_fuzz_sha256(after, lsrc, hash_after);
        ok = ok && (memcmp(before, hash_after, sizeof(before)) == 0);
    }
    if (ok) {
        struct stat st;
        ok = (stat(sibling, &st) != 0); /* no carve file escaped into the dir */
    }
    free(after);
    free(img);
    if (ok) PASS(); else FAIL("carve must refuse a source alias and write nothing");
}

int main(void) {
    printf("=== Scan Report / Carve Tests ===\n");
    if (tea_init(NULL) != 0) {
        printf("FAIL: native crypto init failed\n");
        return 1;
    }
    char tmpl[] = "/tmp/opencode/cbm-report-test.XXXXXX";
    if (!mkdtemp(tmpl)) {
        printf("FAIL: mkdtemp failed\n");
        tea_cleanup();
        return 1;
    }
    snprintf(g_root, sizeof(g_root), "%s", tmpl);

    test_json_deterministic();
    test_json_escape();
    test_carve_names_and_bytes();
    test_carve_refuses_source_alias();

    printf("\nScratch fixtures: %s\n", g_root);
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    tea_cleanup();
    return tests_failed > 0 ? 1 : 0;
}
