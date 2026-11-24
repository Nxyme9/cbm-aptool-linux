/* test_cbm_file.c - file-level CBM container I/O tests */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_file.h"

#define TEST_LEN 85688

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static const char *TMP_A = "/tmp/opencode/cbm_file_test_a.dat";
static const char *TMP_B = "/tmp/opencode/cbm_file_test_b.dat";

static void fill_pattern(unsigned char *buf, size_t len, unsigned seed) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (unsigned char)((i * 7 + seed) & 0xff);
    }
}

static void write_raw_file(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    if (len) fwrite(buf, 1, len, f);
    fclose(f);
}

static int read_raw_file(const char *path, unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = len ? fread(buf, 1, len, f) : 0;
    fclose(f);
    return (n == len) ? 0 : -1;
}

static void test_is_blockdev_regular_file(void) {
    TEST("cbm_file_is_blockdev on regular file");
    unsigned char b[16];
    fill_pattern(b, sizeof(b), 1);
    write_raw_file(TMP_A, b, sizeof(b));
    if (cbm_file_is_blockdev(TMP_A) == 0) {
        PASS();
    } else {
        FAIL("regular file reported as block device");
    }
}

static void test_read_from_file(void) {
    TEST("cbm_file_read from temp file");
    unsigned char w[64], r[64];
    fill_pattern(w, sizeof(w), 11);
    write_raw_file(TMP_A, w, sizeof(w));
    memset(r, 0, sizeof(r));
    if (cbm_file_read(TMP_A, 0, r, sizeof(r)) != 0) {
        FAIL("read failed");
        return;
    }
    if (memcmp(w, r, sizeof(w)) != 0) {
        FAIL("read bytes mismatch");
        return;
    }
    /* offset read */
    unsigned char r2[16];
    if (cbm_file_read(TMP_A, 8, r2, sizeof(r2)) != 0) {
        FAIL("offset read failed");
        return;
    }
    if (memcmp(w + 8, r2, sizeof(r2)) != 0) {
        FAIL("offset read bytes mismatch");
        return;
    }
    PASS();
}

static void test_write_to_file(void) {
    TEST("cbm_file_write to temp file");
    unsigned char w[64], r[64];
    fill_pattern(w, sizeof(w), 23);
    /* write into a fresh (non-existent) file */
    remove(TMP_B);
    if (cbm_file_write(TMP_B, 0, w, sizeof(w)) != 0) {
        FAIL("write failed");
        return;
    }
    if (read_raw_file(TMP_B, r, sizeof(r)) != 0) {
        FAIL("post-write raw read failed");
        return;
    }
    if (memcmp(w, r, sizeof(w)) != 0) {
        FAIL("written bytes mismatch");
        return;
    }
    /* write at an offset into an existing file, preserving the prefix */
    unsigned char base[32], expect[32];
    fill_pattern(base, sizeof(base), 0);
    write_raw_file(TMP_B, base, sizeof(base));
    memcpy(expect, base, sizeof(base));
    unsigned char patch[8];
    fill_pattern(patch, sizeof(patch), 99);
    memcpy(expect + 8, patch, sizeof(patch));
    if (cbm_file_write(TMP_B, 8, patch, sizeof(patch)) != 0) {
        FAIL("offset write failed");
        return;
    }
    if (read_raw_file(TMP_B, r, 32) != 0) {
        FAIL("post-offset-write raw read failed");
        return;
    }
    if (memcmp(expect, r, 32) != 0) {
        FAIL("offset write mismatch");
        return;
    }
    PASS();
}

static void test_roundtrip_container(void) {
    TEST("cbm_file write/read roundtrip (85688 B container)");
    unsigned char *w = malloc(TEST_LEN);
    unsigned char *r = malloc(TEST_LEN);
    if (!w || !r) {
        FAIL("malloc failed");
        free(w); free(r);
        return;
    }
    fill_pattern(w, TEST_LEN, 7);
    remove(TMP_A);
    if (cbm_file_write(TMP_A, 0, w, TEST_LEN) != 0) {
        FAIL("container write failed");
        free(w); free(r);
        return;
    }
    memset(r, 0, TEST_LEN);
    if (cbm_file_read(TMP_A, 0, r, TEST_LEN) != 0) {
        FAIL("container read failed");
        free(w); free(r);
        return;
    }
    if (memcmp(w, r, TEST_LEN) != 0) {
        FAIL("container roundtrip mismatch");
        free(w); free(r);
        return;
    }
    free(w); free(r);
    PASS();
}

static void test_error_paths(void) {
    TEST("cbm_file error paths");
    unsigned char b[8];
    if (cbm_file_read("/tmp/opencode/cbm_file_missing.dat", 0, b, sizeof(b)) != -1) {
        FAIL("read of missing path should fail");
        return;
    }
    if (cbm_file_read(NULL, 0, b, sizeof(b)) != -1) {
        FAIL("read with NULL path should fail");
        return;
    }
    if (cbm_file_write(NULL, 0, b, sizeof(b)) != -1) {
        FAIL("write with NULL path should fail");
        return;
    }
    PASS();
}

int main(void) {
    printf("=== CBM File I/O Tests ===\n");
    test_is_blockdev_regular_file();
    test_read_from_file();
    test_write_to_file();
    test_roundtrip_container();
    test_error_paths();
    remove(TMP_A);
    remove(TMP_B);
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
