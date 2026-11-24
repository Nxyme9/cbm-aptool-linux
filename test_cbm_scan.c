/* test_cbm_scan.c - read-only forensic scanner tests
 *
 * Synthetic images only: scratch regular files under /tmp/opencode and
 * exact-size heap buffers so ASan catches any read past a chunk/container
 * tail. No device is opened, read or written. Containers are built with the
 * repository's own TEA encryptor and the allowlisted published test key.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_container.h"
#include "cbm_file.h"
#include "cbm_fuzz.h"
#include "tea_crypto.h"

#include "cbm_scan.h"

static int tests_passed = 0;
static int tests_failed = 0;
static char g_root[256];

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

#define BODY_LEN ((size_t)(CBM_CONTAINER_SIZE - CBM_HEADER_SIZE))
#define LBA 512ULL
/* UNVERIFIED: advisory magic only; structural detection must not depend on it. */
static const char UNVERIFIED_MAGIC[] = "cbmv1001";

/* Non-zero, NON-PRINTABLE filler for shifted-window regression fixtures.
 * 0xa5 is outside printable ASCII (0x20-0x7e) and non-zero, so zero padding
 * cannot mask duplicate-hit regressions. Its steady-state TEA-CBC decryption
 * is constant (zero entropy), so filler-only windows fail the gate; a window
 * shifted inside a real container only passes when its tail reaches another
 * container's high-entropy ciphertext (the back-to-back fixture). */
#define NONPRINT_FILLER 0xa5u
static void fill_filler(unsigned char *buf, size_t len) {
    memset(buf, NONPRINT_FILLER, len);
}

static void path_of(char *out, size_t outlen, const char *sub) {
    snprintf(out, outlen, "%s/%s", g_root, sub);
}

static int write_image(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t put = len ? fwrite(buf, 1, len, f) : 0;
    return (put == len && fclose(f) == 0) ? 0 : -1;
}

/* Plaintext body: deterministic NON-PERIODIC printable bytes (a periodic body
 * makes shifted windows look plausible because this cipher self-synchronises).
 * ~5% NUL separators, printable head/tail markers: non-degenerate entropy,
 * high printable density, and a token at body offset 0. */
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

/* A complete synthetic container: byte 0 verbatim, TEA-encrypted body. */
static int make_container(unsigned char *out, unsigned char header) {
    fill_body(out + CBM_HEADER_SIZE, BODY_LEN);
    out[0] = header;
    return cbm_cbc_encrypt(out + CBM_HEADER_SIZE, BODY_LEN,
                           cbm_fuzz_tea_key);
}

static int sha_matches(const cbm_scan_hit_t *hit, const unsigned char *container) {
    unsigned char want[32];
    cbm_fuzz_sha256(container, CBM_CONTAINER_SIZE, want);
    return memcmp(hit->sha256, want, sizeof(want)) == 0;
}

static int scan(const char *path, unsigned long long start,
                unsigned long long end, size_t chunk,
                const char *const *magics, size_t nmagic,
                cbm_scan_hit_t **hits, size_t *count) {
    char err[256];
    err[0] = '\0';
    int rc = cbm_scan_image(path, start, end, chunk, magics, nmagic,
                            hits, count, err, sizeof(err));
    if (rc != 0) printf("[err: %s] ", err);
    return rc;
}

static void test_empty_image(void) {
    TEST("cbm_scan_image: empty image yields 0 hits");
    char path[512];
    path_of(path, sizeof(path), "empty.img");
    cbm_scan_hit_t *hits = NULL;
    size_t n = 99;
    int ok = (write_image(path, NULL, 0) == 0);
    if (ok) {
        int rc = scan(path, 0, 0, 1024184u, NULL, 0, &hits, &n);
        ok = (rc == 0 && n == 0 && hits == NULL);
    }
    cbm_scan_free_hits(hits);
    if (ok) PASS(); else FAIL("empty image must return 0 hits and a NULL array");
}

static void test_one_container_known_offset(void) {
    TEST("cbm_scan_buffer/image: one container at a known offset");
    char path[512];
    path_of(path, sizeof(path), "one.img");
    const size_t img_len = (size_t)(4u * LBA) + CBM_CONTAINER_SIZE + 512u;
    unsigned char *img = (unsigned char *)calloc(1, img_len);
    cbm_scan_hit_t *hits = NULL;
    size_t n = 0;
    int ok = (img != NULL);
    if (ok) ok = (make_container(img + 4u * LBA, 0x5a) == 0);
    if (ok) ok = (write_image(path, img, img_len) == 0);
    if (ok) {
        int rc = scan(path, 0, (unsigned long long)img_len - 1u,
                      3u * CBM_CONTAINER_SIZE, NULL, 0, &hits, &n);
        ok = (rc == 0 && n == 1);
        if (ok) {
            const cbm_scan_hit_t *h = &hits[0];
            ok = (h->offset == 4u * LBA && h->header == 0x5a &&
                  sha_matches(h, img + 4u * LBA) &&
                  h->entropy > 0.5 && h->entropy < 7.0 &&
                  h->token_count > 0 && h->token_offsets[0] == 0u &&
                  h->tokens[0][0] != '\0');
        }
    }
    cbm_scan_free_hits(hits);
    free(img);
    if (ok) PASS(); else FAIL("expected exact offset/header/sha256/entropy/tokens");
}

static void test_two_containers_chunk_boundary(void) {
    TEST("cbm_scan_image: two containers across a chunk boundary, no duplicates");
    char path[512];
    path_of(path, sizeof(path), "boundary.img");
    /* chunk=1048944 -> overlap=171888, stride=877056 (1713 LBAs). A starts
     * exactly at chunk 1's start (so chunk 1 re-scans it whole -> dedupe);
     * A ends at 962744, wholly inside chunk 1's overlap [877056, 1048944).
     * B starts at LBA 2048 = 1048576 and straddles chunk 0's boundary at
     * byte 1048944. A ends before B starts: no fixture overlap. */
    const size_t chunk = 1048944u;
    const unsigned long long a = 1713ULL * LBA;
    const unsigned long long b = 2048ULL * LBA;
    const size_t img_len = (size_t)(b + CBM_CONTAINER_SIZE + LBA);
    unsigned char *img = (unsigned char *)malloc(img_len);
    cbm_scan_hit_t *hits = NULL;
    size_t n = 0;
    int ok = (img != NULL);
    if (ok) {
        /* Non-zero non-printable filler: a shifted window cannot hide in
         * zero padding, so this fixture catches duplicate-hit regressions. */
        fill_filler(img, img_len);
        ok = (make_container(img + a, 0x5a) == 0 &&
              make_container(img + b, 0xa5) == 0);
    }
    if (ok) ok = (write_image(path, img, img_len) == 0);
    if (ok) {
        int rc = scan(path, 0, (unsigned long long)img_len - 1u, chunk,
                      NULL, 0, &hits, &n);
        ok = (rc == 0 && n == 2 &&
              hits[0].offset == a && hits[1].offset == b &&
              hits[0].header == 0x5a && hits[1].header == 0xa5 &&
              sha_matches(&hits[0], img + a) &&
              sha_matches(&hits[1], img + b));
    }
    cbm_scan_free_hits(hits);
    free(img);
    if (ok) PASS(); else FAIL("expected exactly 2 distinct offsets in ascending order");
}

static void test_false_positive_magic(void) {
    TEST("cbm_scan_image: magic bytes over garbage are rejected by plausibility gate");
    char path[512];
    path_of(path, sizeof(path), "false-magic.img");
    const size_t img_len = (size_t)LBA + CBM_CONTAINER_SIZE + 512u;
    unsigned char *img = (unsigned char *)calloc(1, img_len);
    cbm_scan_hit_t *hits = NULL;
    size_t n = 0;
    const char *const magics[] = { UNVERIFIED_MAGIC };
    int ok = (img != NULL);
    if (ok) {
        memcpy(img + LBA, UNVERIFIED_MAGIC, sizeof(UNVERIFIED_MAGIC) - 1u);
        unsigned int s = 0x12345678u;
        for (size_t i = sizeof(UNVERIFIED_MAGIC) - 1u; i < CBM_CONTAINER_SIZE; i++) {
            s = s * 1664525u + 1013904223u;
            img[LBA + i] = (unsigned char)(s >> 24);
        }
    }
    if (ok) ok = (write_image(path, img, img_len) == 0);
    if (ok) {
        int rc = scan(path, 0, (unsigned long long)img_len - 1u,
                      3u * CBM_CONTAINER_SIZE, magics, 1, &hits, &n);
        ok = (rc == 0 && n == 0);
    }
    if (ok) {
        /* Positive control: the same gate accepts a plausible container when
         * its 0x5a header byte is the (UNVERIFIED) single-byte magic. */
        unsigned char *one = (unsigned char *)malloc(CBM_CONTAINER_SIZE);
        cbm_scan_hit_t buf_hits[2];
        const char *const z[] = { "Z" };
        ok = (one != NULL);
        if (ok) ok = (make_container(one, 0x5a) == 0);
        if (ok) {
            memset(buf_hits, 0, sizeof(buf_hits));
            size_t h1 = cbm_scan_buffer(one, CBM_CONTAINER_SIZE, z, 1, 0,
                                        0, buf_hits, 2);
            ok = (h1 == 1 && buf_hits[0].offset == 0 &&
                  sha_matches(&buf_hits[0], one));
        }
        if (ok) {
            memset(buf_hits, 0, sizeof(buf_hits));
            size_t h2 = cbm_scan_buffer(one, CBM_CONTAINER_SIZE, NULL, 0, 0,
                                        0, buf_hits, 2);
            ok = (h2 == 0); /* no magic, no structural probe -> no candidate */
        }
        free(one);
    }
    cbm_scan_free_hits(hits);
    free(img);
    if (ok) PASS(); else FAIL("garbage after magic must yield 0 hits");
}

static void test_structural_no_magic(void) {
    TEST("cbm_scan_image: structural probe finds a container with magic zeroed");
    char path[512];
    path_of(path, sizeof(path), "no-magic.img");
    const size_t img_len = (size_t)(2u * LBA) + CBM_CONTAINER_SIZE + 512u;
    unsigned char *img = (unsigned char *)calloc(1, img_len);
    cbm_scan_hit_t *hits = NULL;
    size_t n = 0;
    const char *const magics[] = { UNVERIFIED_MAGIC };
    int ok = (img != NULL);
    if (ok) ok = (make_container(img + 2u * LBA, 0x00) == 0); /* magic area = 0 */
    if (ok) ok = (write_image(path, img, img_len) == 0);
    if (ok) {
        int rc = scan(path, 0, (unsigned long long)img_len - 1u,
                      3u * CBM_CONTAINER_SIZE, magics, 1, &hits, &n);
        ok = (rc == 0 && n == 1 && hits[0].offset == 2u * LBA &&
              hits[0].header == 0x00 &&
              sha_matches(&hits[0], img + 2u * LBA));
    }
    if (ok) {
        cbm_scan_hit_t buf_hits[2];
        memset(buf_hits, 0, sizeof(buf_hits));
        size_t no_magic = cbm_scan_buffer(img + 2u * LBA, CBM_CONTAINER_SIZE,
                                          magics, 1, 0, 2u * LBA,
                                          buf_hits, 2);
        memset(buf_hits, 0, sizeof(buf_hits));
        size_t structural = cbm_scan_buffer(img + 2u * LBA, CBM_CONTAINER_SIZE,
                                            magics, 1, 1, 2u * LBA,
                                            buf_hits, 2);
        ok = (no_magic == 0 && structural == 1);
    }
    cbm_scan_free_hits(hits);
    free(img);
    if (ok) PASS(); else FAIL("structural probe must not depend on magic bytes");
}

static void test_range_lba(void) {
    TEST("cbm_scan_image: inclusive byte range excludes a container outside it");
    char path[512];
    path_of(path, sizeof(path), "range.img");
    const unsigned long long a = 4ULL * LBA;
    const unsigned long long b = 200ULL * LBA; /* > one container past A */
    const size_t img_len = (size_t)(400ULL * LBA + LBA);
    unsigned char *img = (unsigned char *)calloc(1, img_len);
    cbm_scan_hit_t *hits = NULL;
    size_t n = 0;
    int ok = (img != NULL);
    if (ok) ok = (make_container(img + a, 0x5a) == 0 &&
                  make_container(img + b, 0x5a) == 0);
    if (ok) ok = (write_image(path, img, img_len) == 0);
    if (ok) {
        /* Start at LBA 172 = 88064, strictly past A's last byte (87736), so
         * A is wholly outside the range and its ciphertext is never read.
         * A straddling the start would only produce self-synchronised shifted
         * window candidates, not a range-exclusion failure. End at LBA 399. */
        int rc = scan(path, 172ULL * LBA, 400ULL * LBA - 1u,
                      3u * CBM_CONTAINER_SIZE, NULL, 0, &hits, &n);
        ok = (rc == 0 && n == 1 && hits[0].offset == b &&
              sha_matches(&hits[0], img + b));
    }
    if (ok) {
        cbm_scan_free_hits(hits);
        hits = NULL;
        n = 0;
        /* Container A starts at LBA 4: not fully inside [0, LBA 4). */
        int rc = scan(path, 0, a - 1u, 3u * CBM_CONTAINER_SIZE,
                      NULL, 0, &hits, &n);
        ok = (rc == 0 && n == 0);
    }
    cbm_scan_free_hits(hits);
    free(img);
    if (ok) PASS(); else FAIL("range must include only fully contained hits");
}

static void test_short_image(void) {
    TEST("cbm_scan_image/buffer: image shorter than one container yields 0 hits");
    char path[512];
    path_of(path, sizeof(path), "short.img");
    const size_t len = CBM_CONTAINER_SIZE - 1u;
    unsigned char *whole = (unsigned char *)malloc(CBM_CONTAINER_SIZE);
    unsigned char *short_buf = (unsigned char *)malloc(len); /* exact size */
    cbm_scan_hit_t *hits = NULL;
    size_t n = 0;
    int ok = (whole != NULL && short_buf != NULL);
    if (ok) ok = (make_container(whole, 0x5a) == 0);
    if (ok) {
        memcpy(short_buf, whole, len);
        ok = (write_image(path, short_buf, len) == 0);
    }
    if (ok) {
        int rc = scan(path, 0, (unsigned long long)len - 1u,
                      3u * CBM_CONTAINER_SIZE, NULL, 0, &hits, &n);
        ok = (rc == 0 && n == 0);
    }
    if (ok) {
        cbm_scan_hit_t buf_hits[2];
        memset(buf_hits, 0, sizeof(buf_hits));
        ok = (cbm_scan_buffer(short_buf, len, NULL, 0, 1, 0,
                              buf_hits, 2) == 0);
        /* Exact-size full container: must read exactly 85688 bytes. */
        memset(buf_hits, 0, sizeof(buf_hits));
        ok = ok && (cbm_scan_buffer(whole, CBM_CONTAINER_SIZE, NULL, 0, 1,
                                    0, buf_hits, 2) == 1);
    }
    cbm_scan_free_hits(hits);
    free(short_buf);
    free(whole);
    if (ok) PASS(); else FAIL("short image must not over-read or report a hit");
}

/* Two real containers as close as the 512-byte structural grid allows, with
 * non-zero non-printable filler. A shifted window of container 1 runs into
 * container 2's ciphertext, so zero padding cannot hide the duplicate class. */
static void test_back_to_back_containers(void) {
    TEST("cbm_scan_image: back-to-back containers suppress shifted windows");
    char path[512];
    path_of(path, sizeof(path), "back-to-back.img");
    /* 85688 is not a multiple of 512, so two containers cannot BOTH start on
     * the 512-byte grid at exactly A and A+CBM_CONTAINER_SIZE. Place B at the
     * first aligned offset at/after A+CBM_CONTAINER_SIZE: 168*512 = 86016
     * (a 328-byte filler gap). Shifted windows of A still land in B's body. */
    const unsigned long long a = 4ULL * LBA;
    const unsigned long long b = a + 168ULL * LBA;
    const size_t img_len = (size_t)(b + CBM_CONTAINER_SIZE + LBA);
    unsigned char *img = (unsigned char *)malloc(img_len);
    cbm_scan_hit_t *hits = NULL;
    size_t n = 0;
    int ok = (img != NULL);
    if (ok) {
        fill_filler(img, img_len);
        ok = (make_container(img + a, 0x5a) == 0 &&
              make_container(img + b, 0xa5) == 0);
    }
    if (ok) ok = (write_image(path, img, img_len) == 0);
    if (ok) {
        int rc = scan(path, 0, (unsigned long long)img_len - 1u,
                      4u * CBM_CONTAINER_SIZE, NULL, 0, &hits, &n);
        ok = (rc == 0 && n == 2 &&
              hits[0].offset == a && hits[1].offset == b &&
              hits[0].header == 0x5a && hits[1].header == 0xa5 &&
              sha_matches(&hits[0], img + a) &&
              sha_matches(&hits[1], img + b));
        if (!ok) printf("[n=%zu off0=%llu off1=%llu] ", n,
                        n > 0 ? hits[0].offset : 0ULL,
                        n > 1 ? hits[1].offset : 0ULL);
    }
    cbm_scan_free_hits(hits);
    free(img);
    if (ok) PASS(); else FAIL("expected exactly 2 hits at A and B, no shifted extras");
}

/* One real container in non-zero non-printable filler, image >= A+3 containers.
 * Before cluster suppression, self-synchronised shifted windows yield >1 hit. */
static void test_shifted_window_suppressed(void) {
    TEST("cbm_scan_image: one container in non-zero filler yields exactly one hit");
    char path[512];
    path_of(path, sizeof(path), "shifted.img");
    const unsigned long long a = 4ULL * LBA;
    const size_t img_len = (size_t)(a + 3ULL * CBM_CONTAINER_SIZE);
    unsigned char *img = (unsigned char *)malloc(img_len);
    cbm_scan_hit_t *hits = NULL;
    size_t n = 0;
    int ok = (img != NULL);
    if (ok) {
        fill_filler(img, img_len);
        ok = (make_container(img + a, 0x5a) == 0);
    }
    if (ok) ok = (write_image(path, img, img_len) == 0);
    if (ok) {
        int rc = scan(path, 0, (unsigned long long)img_len - 1u,
                      4u * CBM_CONTAINER_SIZE, NULL, 0, &hits, &n);
        ok = (rc == 0 && n == 1 && hits[0].offset == a &&
              hits[0].header == 0x5a && sha_matches(&hits[0], img + a));
        if (!ok) printf("[n=%zu off0=%llu] ", n,
                        n > 0 ? hits[0].offset : 0ULL);
    }
    cbm_scan_free_hits(hits);
    free(img);
    if (ok) PASS(); else FAIL("single container must yield exactly one hit");
}

/* chunk_bytes <= overlap underflows the stride in the pre-fix walker; the
 * guard must reject with an error and leave no partial results. Empty image
 * keeps the boundary probes fast and avoids the pre-fix stride==0 loop. */
static void test_chunk_size_guard(void) {
    TEST("cbm_scan_image: chunk sizes <= overlap are rejected, overlap+1 accepted");
    char path[512];
    path_of(path, sizeof(path), "guard-empty.img");
    const size_t overlap = 2u * (size_t)CBM_CONTAINER_SIZE + (size_t)LBA;
    int ok = (write_image(path, NULL, 0) == 0);
    if (ok) {
        size_t bad[2] = { (size_t)CBM_CONTAINER_SIZE + 1u, overlap };
        for (size_t i = 0; i < 2u; i++) {
            cbm_scan_hit_t dummy;
            cbm_scan_hit_t *hits = &dummy;
            size_t n = 99;
            char err[256];
            err[0] = '\0';
            int rc = cbm_scan_image(path, 0, 0, bad[i], NULL, 0,
                                    &hits, &n, err, sizeof(err));
            if (!(rc == -1 && err[0] != '\0' && hits == NULL && n == 0)) {
                printf("[chunk=%zu rc=%d err='%s' hits_null=%d n=%zu] ",
                       bad[i], rc, err, hits == NULL, n);
                ok = 0;
            }
        }
    }
    if (ok) {
        cbm_scan_hit_t dummy;
        cbm_scan_hit_t *hits = &dummy;
        size_t n = 99;
        char err[256];
        err[0] = '\0';
        int rc = cbm_scan_image(path, 0, 0, overlap + 1u, NULL, 0,
                                &hits, &n, err, sizeof(err));
        ok = (rc == 0 && hits == NULL && n == 0);
        if (!ok) printf("[overlap+1 rc=%d err='%s'] ", rc, err);
    }
    if (ok) PASS(); else FAIL("chunk <= overlap must be rejected with no partial results");
}

int main(void) {
    printf("=== Read-only CBM Scanner Tests ===\n");
    if (tea_init(NULL) != 0) {
        printf("FAIL: native crypto init failed\n");
        return 1;
    }
    char tmpl[] = "/tmp/opencode/cbm-scan-test.XXXXXX";
    if (!mkdtemp(tmpl)) {
        printf("FAIL: mkdtemp failed\n");
        tea_cleanup();
        return 1;
    }
    snprintf(g_root, sizeof(g_root), "%s", tmpl);

    test_empty_image();
    test_one_container_known_offset();
    test_two_containers_chunk_boundary();
    test_false_positive_magic();
    test_structural_no_magic();
    test_range_lba();
    test_short_image();
    test_back_to_back_containers();
    test_shifted_window_suppressed();
    test_chunk_size_guard();

    printf("\nScratch fixtures: %s\n", g_root);
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    tea_cleanup();
    return tests_failed > 0 ? 1 : 0;
}
