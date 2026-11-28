/* test_cbm_decode.c - CBM container decode entropy/region tests */
#define _GNU_SOURCE
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_decode.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

/* No libm in the standalone build: absolute difference without fabs(). */
static double abs_diff(double a, double b) {
    return (a > b) ? (a - b) : (b - a);
}

/* Deterministic pseudo-random bytes; seed/stream chosen so each 64 B window
 * has far fewer than 85% printable bytes and is not constant. */
static void fill_pseudo_random(unsigned char *b, size_t n, uint32_t seed) {
    for (size_t i = 0; i < n; i++) {
        seed = seed * 1664525u + 1013904223u;
        b[i] = (unsigned char)(seed >> 24);
    }
}

static void test_entropy_constant(void) {
    TEST("cbm_decode_entropy of 1024 zero bytes is exactly 0.0");
    unsigned char b[1024];
    memset(b, 0, sizeof(b));
    double h = cbm_decode_entropy(b, sizeof(b));
    if (h == 0.0) PASS(); else FAIL("constant entropy must be exactly 0.0");
}

static void test_entropy_uniform(void) {
    TEST("cbm_decode_entropy of bytes 0..255 once each is 8.0 +/- 1e-9");
    unsigned char b[256];
    for (size_t i = 0; i < sizeof(b); i++) b[i] = (unsigned char)i;
    double h = cbm_decode_entropy(b, sizeof(b));
    if (abs_diff(h, 8.0) < 1e-9) PASS();
    else FAIL("uniform 256-value entropy must be 8.0");
}

static void test_entropy_empty(void) {
    TEST("cbm_decode_entropy(NULL,0) and (buf,0) return 0.0 without crashing");
    unsigned char b[1] = {0x41};
    double h1 = cbm_decode_entropy(NULL, 0);
    double h2 = cbm_decode_entropy(b, 0);
    if (h1 == 0.0 && h2 == 0.0) PASS();
    else FAIL("empty entropy must be exactly 0.0");
}

static void test_regions_constant(void) {
    TEST("cbm_decode_regions: 4 KiB zeros -> one CONSTANT region [0,4096)");
    unsigned char b[4096];
    memset(b, 0, sizeof(b));
    cbm_region_t r[4];
    memset(r, 0, sizeof(r));
    size_t n = cbm_decode_regions(b, sizeof(b), r, 4);
    int ok = (n == 1 && r[0].offset == 0 && r[0].length == sizeof(b) &&
              r[0].kind == CBM_REGION_CONSTANT);
    if (ok) PASS(); else FAIL("4 KiB of one byte must merge into one CONSTANT region");
}

static void test_regions_string(void) {
    TEST("cbm_decode_regions: 64 printable varying bytes -> one STRING region");
    unsigned char b[64];
    for (size_t i = 0; i < sizeof(b); i++) b[i] = (unsigned char)('A' + (i % 26));
    cbm_region_t r[4];
    memset(r, 0, sizeof(r));
    size_t n = cbm_decode_regions(b, sizeof(b), r, 4);
    int ok = (n == 1 && r[0].offset == 0 && r[0].length == 64 &&
              r[0].kind == CBM_REGION_STRING);
    if (ok) PASS(); else FAIL("fully printable window must be STRING");
}

static void test_regions_opaque(void) {
    TEST("cbm_decode_regions: 256 pseudo-random bytes -> one OPAQUE region");
    unsigned char b[256];
    fill_pseudo_random(b, sizeof(b), 0x12345678u);
    cbm_region_t r[8];
    memset(r, 0, sizeof(r));
    size_t n = cbm_decode_regions(b, sizeof(b), r, 8);
    int ok = (n == 1 && r[0].offset == 0 && r[0].length == 256 &&
              r[0].kind == CBM_REGION_OPAQUE);
    if (ok) PASS(); else FAIL("low printable density must be OPAQUE");
}

static void test_regions_merge_adjacent(void) {
    TEST("cbm_decode_regions: two adjacent STRING windows merge; OPAQUE separate");
    unsigned char b[192];
    for (size_t i = 0; i < 128; i++) b[i] = (unsigned char)('a' + (i % 26));
    fill_pseudo_random(b + 128, 64, 0xdeadbeefu);
    cbm_region_t r[8];
    memset(r, 0, sizeof(r));
    size_t n = cbm_decode_regions(b, sizeof(b), r, 8);
    int ok = (n == 2 &&
              r[0].offset == 0   && r[0].length == 128 && r[0].kind == CBM_REGION_STRING &&
              r[1].offset == 128 && r[1].length == 64  && r[1].kind == CBM_REGION_OPAQUE);
    if (ok) PASS(); else FAIL("adjacent same-kind windows must merge into one region");
}

static void test_regions_cap(void) {
    TEST("cbm_decode_regions: max caps writes; NULL/empty return 0");
    unsigned char b[256];
    for (size_t i = 0; i < 64; i++)  b[i] = (unsigned char)('A' + (i % 26));
    memset(b + 64, 0, 64);
    fill_pseudo_random(b + 128, 64, 0x12345678u);
    for (size_t i = 192; i < 256; i++) b[i] = (unsigned char)('a' + (i % 26));

    cbm_region_t r[4];
    memset(r, 0, sizeof(r));
    size_t n = cbm_decode_regions(b, sizeof(b), r, 2);
    int ok = (n == 2 &&
              r[0].offset == 0   && r[0].length == 64 && r[0].kind == CBM_REGION_STRING &&
              r[1].offset == 64  && r[1].length == 64 && r[1].kind == CBM_REGION_CONSTANT);

    /* A zero cap must write nothing and return zero. */
    cbm_region_t z[1];
    memset(z, 0xaa, sizeof(z));
    z[0].offset = (size_t)-1;
    ok = ok && cbm_decode_regions(b, sizeof(b), z, 0) == 0;
    ok = ok && z[0].offset == (size_t)-1;

    ok = ok && cbm_decode_regions(NULL, 0, r, 4) == 0;
    ok = ok && cbm_decode_regions(b, 0, r, 4) == 0;
    if (ok) PASS(); else FAIL("region count must be capped at max");
}

static void test_profile_does_not_read_past(void) {
    TEST("cbm_decode_profile: exact 1-byte allocation, one correct row");
    unsigned char *b = (unsigned char *)malloc(1);
    if (!b) { FAIL("malloc(1)"); return; }
    b[0] = 'Z';

    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { free(b); FAIL("open_memstream"); return; }
    cbm_decode_profile(b, 1, m);
    fflush(m);
    int ok = (text != NULL && strcmp(text, "0 1 0.000000 constant\n") == 0);
    fclose(m);
    free(text);
    free(b);
    if (ok) PASS(); else FAIL("profile must print one row and stop at buf+len");
}

static void test_profile_rows(void) {
    TEST("cbm_decode_profile: one row per window with stable kind names");
    unsigned char b[192];
    memset(b, 'A', 64);
    for (size_t i = 64; i < 128; i++) b[i] = (unsigned char)('a' + (i % 26));
    fill_pseudo_random(b + 128, 64, 0xdeadbeefu);

    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_decode_profile(b, sizeof(b), m);
    fflush(m);
    size_t rows = 0;
    for (size_t i = 0; text && i < tlen; i++) if (text[i] == '\n') rows++;
    int ok = text && rows == 3 &&
             strstr(text, "0 64 0.000000 constant\n") != NULL &&
             strstr(text, "64 64 ") != NULL && strstr(text, " string\n") != NULL &&
             strstr(text, "128 64 ") != NULL && strstr(text, " opaque\n") != NULL;
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("profile row format/kind names wrong");
}

static void test_profile_locale_independent(void) {
    TEST("cbm_decode_profile: '.' decimal point under a comma-decimal locale");

    /* setlocale() returns a pointer to internal storage: copy it before any
     * candidate call overwrites it, and restore it on every exit path. */
    const char *original = setlocale(LC_NUMERIC, NULL);
    char *saved = original ? strdup(original) : NULL;
    if (!saved) { FAIL("cannot save LC_NUMERIC"); return; }

    static const char *const candidates[] = {
        "de_DE.UTF-8", "de_DE.utf8", "es_ES.UTF-8", "es_ES.utf8",
        "fr_FR.UTF-8", "fr_FR.utf8"
    };
    const char *chosen = NULL;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (setlocale(LC_NUMERIC, candidates[i]) != NULL) {
            struct lconv *lc = localeconv();
            if (lc && lc->decimal_point && strcmp(lc->decimal_point, ".") != 0) {
                chosen = candidates[i];
                break;
            }
        }
    }
    if (!chosen) {
        setlocale(LC_NUMERIC, saved);
        free(saved);
        printf("SKIP: no comma-decimal locale installed (tried de_DE/es_ES/fr_FR)\n");
        return;
    }
    printf("[%s] ", chosen);

    /* Constant window gives exactly 0.000000; printable window gives a
     * non-zero entropy that would also be corrupted by a comma separator. */
    unsigned char b[128];
    memset(b, 'A', 64);
    for (size_t i = 64; i < sizeof(b); i++) b[i] = (unsigned char)('a' + (i % 26));

    int ok = 0;
    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); }
    else {
        cbm_decode_profile(b, sizeof(b), m);
        fflush(m);
        ok = text && strstr(text, "0.000000") != NULL && strchr(text, ',') == NULL;
        fclose(m);
        free(text);
    }

    setlocale(LC_NUMERIC, saved); /* never leak the changed locale */
    free(saved);
    if (ok) PASS(); else FAIL("profile entropy must use a literal '.' decimal point");
}

int main(void) {
    printf("=== CBM Decode Tests ===\n");
    test_entropy_constant();
    test_entropy_uniform();
    test_entropy_empty();
    test_regions_constant();
    test_regions_string();
    test_regions_opaque();
    test_regions_merge_adjacent();
    test_regions_cap();
    test_profile_does_not_read_past();
    test_profile_rows();
    test_profile_locale_independent();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
