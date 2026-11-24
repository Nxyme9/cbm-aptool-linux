/* test_cbm_inspect.c - CBM container inspection tests */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_inspect.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

/* Count non-overlapping occurrences of needle in hay. */
static int count_sub(const char *hay, const char *needle) {
    int n = 0;
    const char *p = hay;
    size_t len = strlen(needle);
    while (len > 0 && (p = strstr(p, needle)) != NULL) {
        n++;
        p += len;
    }
    return n;
}

static void test_stats_known_buffer(void) {
    TEST("cbm_inspect_stats on \"ABCD\"");
    const unsigned char b[] = {'A', 'B', 'C', 'D'};
    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_inspect_stats(b, sizeof(b), m);
    fflush(m);
    int ok = text && strstr(text, "size: 4") &&
             strstr(text, "printable: 4") &&
             strstr(text, "unique: 4") &&
             strstr(text, "entropy: 2.0000");
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("stats values wrong");
}

static void test_stats_empty(void) {
    TEST("cbm_inspect_stats on empty buffer");
    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_inspect_stats(NULL, 0, m);
    fflush(m);
    int ok = text && strstr(text, "size: 0") &&
             strstr(text, "printable: 0") &&
             strstr(text, "unique: 0") &&
             strstr(text, "entropy: 0.0000");
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("empty stats wrong");
}

static void test_strings_hello(void) {
    TEST("cbm_inspect_strings extracts HELLO once at offset 4");
    const unsigned char b[] = {0, 0, 0, 0, 'H', 'E', 'L', 'L', 'O', 0, 0x01, 0};
    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_inspect_strings(b, sizeof(b), 4, m);
    fflush(m);
    int ok = text && count_sub(text, "HELLO") == 1 &&
             strstr(text, "offset 4");
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("HELLO not found exactly once at offset 4");
}

static void test_strings_boundary_no_nul(void) {
    TEST("cbm_inspect_strings stops at buf+len (no NUL terminator)");
    /* Run at the very end of the buffer, no trailing NUL. Short leading run
     * must be rejected by min_run. */
    const unsigned char b[] = {'A', 'B', 'C', 0, 'D', 'E', 'F', 'G'};
    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_inspect_strings(b, sizeof(b), 4, m);
    fflush(m);
    int ok = text && count_sub(text, "DEFG") == 1 &&
             count_sub(text, "ABC") == 0 &&
             strstr(text, "offset 4");
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("boundary run handling wrong");
}

static void test_hex_empty(void) {
    TEST("cbm_inspect_hex on empty buffer does not crash");
    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_inspect_hex(NULL, 0, 0, m);
    fflush(m);
    int ok = (text != NULL && tlen == 0); /* chosen: empty -> no output */
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("empty hex should print nothing");
}

static void test_hex_max_bytes(void) {
    TEST("cbm_inspect_hex max_bytes=8 shows first 4 + last 4 only");
    unsigned char b[32];
    for (size_t i = 0; i < sizeof(b); i++) b[i] = (unsigned char)i;
    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_inspect_hex(b, sizeof(b), 8, m);
    fflush(m);
    int ok = text &&
             strstr(text, "00000000  00 01 02 03") &&
             strstr(text, "0000001c  1c 1d 1e 1f") &&
             strstr(text, "bytes omitted") &&
             strstr(text, " 10 ") == NULL &&       /* byte 0x10 hidden */
             strstr(text, "00000010") == NULL;     /* no middle row */
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("head/tail hex dump wrong");
}

static void test_hex_cap_at_least_len(void) {
    TEST("cbm_inspect_hex with max_bytes >= len dumps all");
    const unsigned char b[] = {'H', 'E', 'L', 'L', 'O'};
    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_inspect_hex(b, sizeof(b), 64, m);
    fflush(m);
    int ok = text && strstr(text, "HELLO") &&
             strstr(text, "bytes omitted") == NULL;
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("full hex dump wrong");
}

static void test_tokens(void) {
    TEST("cbm_inspect_tokens finds SCSI at offset 10");
    unsigned char b[20];
    memset(b, 0, sizeof(b));
    memcpy(b + 10, "SCSI", 4);
    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_inspect_tokens(b, sizeof(b), m);
    fflush(m);
    int ok = text && count_sub(text, "SCSI") == 1 &&
             strstr(text, "offset 10");
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("SCSI token not reported at offset 10");
}

static void test_tokens_none(void) {
    TEST("cbm_inspect_tokens on token-free buffer prints nothing");
    unsigned char b[32];
    memset(b, 0, sizeof(b));
    char *text = NULL;
    size_t tlen = 0;
    FILE *m = open_memstream(&text, &tlen);
    if (!m) { FAIL("open_memstream"); return; }
    cbm_inspect_tokens(b, sizeof(b), m);
    fflush(m);
    int ok = (text != NULL && tlen == 0);
    fclose(m);
    free(text);
    if (ok) PASS(); else FAIL("unexpected token hit on zero buffer");
}

int main(void) {
    printf("=== CBM Inspect Tests ===\n");
    test_stats_known_buffer();
    test_stats_empty();
    test_strings_hello();
    test_strings_boundary_no_nul();
    test_hex_empty();
    test_hex_max_bytes();
    test_hex_cap_at_least_len();
    test_tokens();
    test_tokens_none();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
