/* test_cbm_diff.c - two-body diff with context merging tests */
#define _GNU_SOURCE
#include <locale.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_decode.h"
#include "cbm_diff.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static int ranges_equal(const cbm_diff_range_t *x, size_t nx,
                        const cbm_diff_range_t *y, size_t ny) {
    if (nx != ny) return 0;
    for (size_t i = 0; i < nx; i++) {
        if (x[i].offset != y[i].offset || x[i].length != y[i].length ||
            x[i].changed != y[i].changed) return 0;
    }
    return 1;
}

static void test_identical_no_ranges(void) {
    TEST("cbm_diff_ranges: identical bodies produce no ranges and 0 changed bytes");
    unsigned char a[16], b[16];
    for (size_t i = 0; i < sizeof(a); i++) a[i] = b[i] = (unsigned char)i;

    cbm_diff_range_t r[4];
    memset(r, 0xaa, sizeof(r));
    size_t n = cbm_diff_ranges(a, sizeof(a), b, sizeof(b), 3, r, 4);
    int ok = (n == 0 && cbm_diff_changed_bytes(a, sizeof(a), b, sizeof(b)) == 0);

    /* A zero cap and a NULL out must not write or report ranges. */
    cbm_diff_range_t z[1];
    memset(z, 0x5a, sizeof(z));
    z[0].offset = (size_t)-1;
    ok = ok && cbm_diff_ranges(a, sizeof(a), b, sizeof(b), 3, z, 0) == 0;
    ok = ok && z[0].offset == (size_t)-1;
    ok = ok && cbm_diff_ranges(a, sizeof(a), b, sizeof(b), 3, NULL, 4) == 0;
    if (ok) PASS(); else FAIL("identical bodies must have no changes");
}

static void test_single_byte_change(void) {
    TEST("cbm_diff_ranges: one byte change -> one range at that offset");
    unsigned char a[16], b[16];
    for (size_t i = 0; i < sizeof(a); i++) a[i] = b[i] = (unsigned char)('a' + i);
    b[10] ^= 1u;

    cbm_diff_range_t r[4];
    memset(r, 0, sizeof(r));
    size_t n = cbm_diff_ranges(a, sizeof(a), b, sizeof(b), 3, r, 4);
    int ok = (n == 1 && r[0].offset == 10 && r[0].length == 1 &&
              r[0].changed == 1 &&
              cbm_diff_changed_bytes(a, sizeof(a), b, sizeof(b)) == 1);
    if (ok) PASS(); else FAIL("single byte change must be one range");
}

static void test_adjacent_merge(void) {
    TEST("cbm_diff_ranges: gap <= context merges; context 0 does not");
    unsigned char a[32], b[32];
    memset(a, 'A', sizeof(a));
    memcpy(b, a, sizeof(a));
    b[10] ^= 1u;
    b[12] ^= 1u;

    cbm_diff_range_t r[8];
    size_t n = cbm_diff_ranges(a, sizeof(a), b, sizeof(b), 3, r, 8);
    int ok = (n == 1 && r[0].offset == 10 && r[0].length == 3 &&
              r[0].changed == 2);

    /* Gap exactly equal to context (14 - (10+1) == 3) also merges. */
    memset(b, 'A', sizeof(b));
    b[10] ^= 1u;
    b[14] ^= 1u;
    n = cbm_diff_ranges(a, sizeof(a), b, sizeof(b), 3, r, 8);
    ok = ok && (n == 1 && r[0].offset == 10 && r[0].length == 5 &&
                r[0].changed == 2);

    /* context == 0 merges only touching spans: the gap-1 case stays split. */
    b[12] ^= 1u;
    n = cbm_diff_ranges(a, sizeof(a), b, sizeof(b), 0, r, 8);
    ok = ok && (n == 3 && r[0].offset == 10 && r[0].length == 1 &&
                r[1].offset == 12 && r[1].length == 1 &&
                r[2].offset == 14 && r[2].length == 1);
    if (ok) PASS(); else FAIL("range merging must use gap <= context");
}

static void test_separate_ranges(void) {
    TEST("cbm_diff_ranges: distant changes stay separate; max caps writes");
    unsigned char a[200], b[200];
    memset(a, 0x11, sizeof(a));
    memcpy(b, a, sizeof(a));
    b[20] = 0x22;
    b[120] = 0x33;

    cbm_diff_range_t r[8];
    memset(r, 0, sizeof(r));
    size_t n = cbm_diff_ranges(a, sizeof(a), b, sizeof(b), 3, r, 8);
    int ok = (n == 2 && r[0].offset == 20 && r[0].length == 1 &&
              r[0].changed == 1 && r[1].offset == 120 &&
              r[1].length == 1 && r[1].changed == 1);

    cbm_diff_range_t one[2];
    memset(one, 0, sizeof(one));
    n = cbm_diff_ranges(a, sizeof(a), b, sizeof(b), 3, one, 1);
    ok = ok && (n == 1 && one[0].offset == 20 && one[0].length == 1);
    if (ok) PASS(); else FAIL("distant changes must stay separate and honor max");
}

static void test_reversed_symmetry(void) {
    TEST("cbm_diff_ranges: swapping bodies gives identical ranges");
    unsigned char a[64], b[64];
    for (size_t i = 0; i < sizeof(a); i++) a[i] = b[i] = (unsigned char)i;
    b[5] ^= 1u;
    b[6] ^= 1u;
    b[40] ^= 1u;
    b[41] ^= 1u;
    b[42] ^= 1u;

    cbm_diff_range_t ab[8], ba[8];
    size_t nab = cbm_diff_ranges(a, sizeof(a), b, sizeof(b), 1, ab, 8);
    size_t nba = cbm_diff_ranges(b, sizeof(b), a, sizeof(a), 1, ba, 8);
    int ok = ranges_equal(ab, nab, ba, nba) &&
             cbm_diff_changed_bytes(a, sizeof(a), b, sizeof(b)) ==
             cbm_diff_changed_bytes(b, sizeof(b), a, sizeof(a));
    if (ok) PASS(); else FAIL("ranges must be symmetric under argument swap");
}

static void test_length_difference(void) {
    TEST("cbm_diff_ranges: trailing length difference is symmetric");
    unsigned char a[12], b[12];
    memset(a, 'Z', sizeof(a));
    memcpy(b, a, sizeof(b));

    cbm_diff_range_t ab[4], ba[4];
    size_t nab = cbm_diff_ranges(a, 8, b, 12, 3, ab, 4);
    size_t nba = cbm_diff_ranges(b, 12, a, 8, 3, ba, 4);
    int ok = (nab == 1 && nba == 1 && ab[0].offset == 8 &&
              ab[0].length == 4 && ab[0].changed == 4) &&
             ranges_equal(ab, nab, ba, nba) &&
             cbm_diff_changed_bytes(a, 8, b, 12) == 4 &&
             cbm_diff_changed_bytes(b, 12, a, 8) == 4;

    /* A trailing change adjacent to the prefix change merges into it. */
    b[9] = 'Q';
    nab = cbm_diff_ranges(a, 10, b, 12, 3, ab, 4);
    nba = cbm_diff_ranges(b, 12, a, 10, 3, ba, 4);
    ok = ok && (nab == 1 && ab[0].offset == 9 && ab[0].length == 3 &&
                ab[0].changed == 3) && ranges_equal(ab, nab, ba, nba);

    /* The longer side being first must not change the trailing range. */
    nab = cbm_diff_ranges(b, 12, a, 8, 3, ab, 4);
    ok = ok && (nab == 1 && ab[0].offset == 8 && ab[0].length == 4 &&
                ab[0].changed == 4);
    if (ok) PASS(); else FAIL("trailing difference must be [min,max) on both sides");
}

static void test_empty_inputs(void) {
    TEST("cbm_diff_ranges/print: empty and one-sided bodies are safe");
    cbm_diff_range_t r[4];
    memset(r, 0, sizeof(r));
    size_t n = cbm_diff_ranges(NULL, 0, NULL, 0, 3, r, 4);
    int ok = (n == 0 && cbm_diff_changed_bytes(NULL, 0, NULL, 0) == 0);

    unsigned char one[4] = {1, 2, 3, 4};
    n = cbm_diff_ranges(NULL, 0, one, sizeof(one), 3, r, 4);
    ok = ok && (n == 1 && r[0].offset == 0 && r[0].length == 4 &&
                r[0].changed == 4);
    memset(r, 0, sizeof(r));
    size_t nr = cbm_diff_ranges(one, sizeof(one), NULL, 0, 3, r, 4);
    ok = ok && (nr == 1 && r[0].offset == 0 && r[0].length == 4 &&
                r[0].changed == 4);

    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_diff_print(NULL, 0, NULL, 0, 3, m);
    cbm_diff_print(NULL, 0, one, sizeof(one), 3, m);
    cbm_diff_print(one, sizeof(one), NULL, 0, 3, m);
    fflush(m);
    ok = ok && text != NULL && strstr(text, "changed_bytes 0\n") != NULL &&
         strstr(text, "range 0 0 4 4\n") != NULL;
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("empty inputs must not crash or over-read");
}

static void test_exact_allocation_bounds(void) {
    TEST("cbm_diff_ranges/print: exact-size bodies never read past either end");
    unsigned char *a = (unsigned char *)malloc(1);
    unsigned char *b = (unsigned char *)malloc(2);
    unsigned char *c = (unsigned char *)malloc(1);
    unsigned char *d = (unsigned char *)malloc(1);
    if (!a || !b || !c || !d) {
        free(a); free(b); free(c); free(d);
        FAIL("malloc for exact-size bodies");
        return;
    }
    a[0] = 'A'; b[0] = 'A'; b[1] = 0x00;
    c[0] = 0x01; d[0] = 0xff;

    cbm_diff_range_t r[4];
    size_t n = cbm_diff_ranges(a, 1, b, 2, 0, r, 4);
    int ok = (n == 1 && r[0].offset == 1 && r[0].length == 1 &&
              r[0].changed == 1);
    size_t nr = cbm_diff_ranges(b, 2, a, 1, 0, r, 4);
    ok = ok && (nr == 1 && r[0].offset == 1 && r[0].length == 1 &&
                r[0].changed == 1);
    ok = ok && (cbm_diff_changed_bytes(a, 1, b, 2) == 1 &&
                cbm_diff_changed_bytes(b, 2, a, 1) == 1);

    /* Both sides exactly one byte, one change, maximal context. */
    n = cbm_diff_ranges(c, 1, d, 1, (size_t)-1, r, 4);
    ok = ok && (n == 1 && r[0].offset == 0 && r[0].length == 1 &&
                r[0].changed == 1);

    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { ok = 0; }
    else {
        cbm_diff_print(a, 1, b, 2, 0, m);
        cbm_diff_print(b, 2, a, 1, 0, m);
        cbm_diff_print(c, 1, d, 1, (size_t)-1, m);
        fflush(m);
        ok = ok && text != NULL &&
             strstr(text, "range 0 1 1 1\n") != NULL &&
             strstr(text, "changed_bytes 1\n") != NULL;
        fclose(m);
        free(text);
    }

    free(a); free(b); free(c); free(d);
    if (ok) PASS(); else FAIL("exact-size bodies must not be over-read");
}

static void test_print_rows(void) {
    TEST("cbm_diff_print: ranges, counts, entropy and heatmap are stable");
    unsigned char a[8] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    unsigned char b[8] = {'A', 'B', 'X', 'D', 'E', 'F', 'G', 'H'};
    double ea = cbm_decode_entropy(a, sizeof(a));
    double eb = cbm_decode_entropy(b, sizeof(b));
    unsigned sa = (unsigned)(ea * 1000000.0 + 0.5);
    unsigned sb = (unsigned)(eb * 1000000.0 + 0.5);

    char expected[512];
    snprintf(expected, sizeof(expected),
             "ranges 1\n"
             "changed_bytes 1\n"
             "entropy_a %u.%06u\n"
             "entropy_b %u.%06u\n"
             "entropy_delta +0.000000\n"
             "range 0 2 1 1\n"
             "heatmap 0 a=1/1 b=1/1 ################ ################\n",
             sa / 1000000u, sa % 1000000u, sb / 1000000u, sb % 1000000u);

    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_diff_print(a, sizeof(a), b, sizeof(b), 0, m);
    fflush(m);
    int ok = text != NULL && strcmp(text, expected) == 0;
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("print output does not match expected stable format");
}

static void test_print_entropy_delta_sign(void) {
    TEST("cbm_diff_print: entropy_delta sign follows entropy_a - entropy_b");
    unsigned char a[64], b[64];
    memset(a, 0, sizeof(a));                       /* entropy_a == 0 */
    for (size_t i = 0; i < sizeof(b); i++) b[i] = (unsigned char)(1 + i % 8);

    char *text = NULL;
    size_t tlen = 0;
    int ok = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }

    cbm_diff_print(a, sizeof(a), b, sizeof(b), 3, m);
    fflush(m);
    ok = text != NULL &&
         strstr(text, "entropy_a 0.000000\n") != NULL &&
         strstr(text, "entropy_b 3.000000\n") != NULL &&
         strstr(text, "entropy_delta -3.000000\n") != NULL &&
         strchr(text, ',') == NULL;
    fclose(m);
    free(text);

    text = NULL;
    tlen = 0;
    m = open_memstream(&text, &tlen);
    if (m) {
        cbm_diff_print(b, sizeof(b), a, sizeof(a), 3, m);
        fflush(m);
        ok = ok && text != NULL &&
             strstr(text, "entropy_delta +3.000000\n") != NULL &&
             strchr(text, ',') == NULL;
        fclose(m);
        free(text);
    } else {
        ok = 0;
    }

    if (ok) PASS(); else FAIL("entropy_delta must be negative when a < b and positive when a > b");
}

static void test_print_locale_independent(void) {
    TEST("cbm_diff_print: '.' decimal point under a comma-decimal locale");

    /* setlocale() returns internal storage: copy it and restore on all paths. */
    const char *original = setlocale(LC_NUMERIC, NULL);
    char *saved = original ? strdup(original) : NULL;
    if (!saved) { FAIL("cannot save LC_NUMERIC"); return; }

    static const char *const candidates[] = {
        "es_ES.UTF-8", "es_ES.utf8", "de_DE.UTF-8", "de_DE.utf8",
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

    unsigned char a[8] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    unsigned char b[8] = {'A', 'B', 'X', 'D', 'E', 'F', 'G', 'H'};
    char *text = NULL;
    size_t tlen = 0;
    int ok = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); }
    else {
        cbm_diff_print(a, sizeof(a), b, sizeof(b), 0, m);
        fflush(m);
        ok = text != NULL &&
             strstr(text, "entropy_a 3.000000\n") != NULL &&
             strstr(text, "entropy_b 3.000000\n") != NULL &&
             strchr(text, '.') != NULL && strchr(text, ',') == NULL;
        fclose(m);
        free(text);
    }

    setlocale(LC_NUMERIC, saved); /* never leak the changed locale */
    free(saved);
    if (ok) PASS(); else FAIL("print entropy must use a literal '.' decimal point");
}

int main(void) {
    printf("=== CBM Diff Tests ===\n");
    test_identical_no_ranges();
    test_single_byte_change();
    test_adjacent_merge();
    test_separate_ranges();
    test_reversed_symmetry();
    test_length_difference();
    test_empty_inputs();
    test_exact_allocation_bounds();
    test_print_rows();
    test_print_entropy_delta_sign();
    test_print_locale_independent();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
