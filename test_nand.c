/* test_nand.c - NAND controller identity probe tests */
#include <stdio.h>
#include <string.h>

#include "nand_info.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_is_chipsbank(void) {
    TEST("nand_info_is_chipsbank vid 048d");
    nand_info_t info;
    memset(&info, 0, sizeof(info));
    strcpy(info.vendor_id, "048d");
    if (!nand_info_is_chipsbank(&info)) { FAIL("should match"); return; }
    PASS();
}

static void test_not_chipsbank(void) {
    TEST("nand_info_is_chipsbank rejects other vid");
    nand_info_t info;
    memset(&info, 0, sizeof(info));
    strcpy(info.vendor_id, "0781");
    if (nand_info_is_chipsbank(&info)) { FAIL("should not match"); return; }
    PASS();
}

static void test_probe_missing(void) {
    TEST("nand_info_probe missing device fails");
    nand_info_t info;
    if (nand_info_probe("definitely_not_a_block_device", &info) != -1) {
        FAIL("should fail");
    } else { PASS(); }
}

static void test_join_path_normal(void) {
    char dst[64];
    TEST("nand_info_join_path normal join");
    if (nand_info_join_path(dst, sizeof(dst), "/sys/class/block", "sda") != 0 ||
        strcmp(dst, "/sys/class/block/sda") != 0) {
        FAIL("expected /sys/class/block/sda");
        return;
    }
    PASS();
}

static void test_join_path_base_fills_buffer(void) {
    char dst[sizeof("/sys/class/block")];
    TEST("nand_info_join_path base fills buffer, no room for leaf");
    if (nand_info_join_path(dst, sizeof(dst), "/sys/class/block", "sda") != -1 ||
        dst[0] != '\0') {
        FAIL("expected clean failure with empty dst");
        return;
    }
    PASS();
}

static void test_join_path_exact_fit(void) {
    char dst[sizeof("/sys/class/block/sda")];
    TEST("nand_info_join_path exact fit");
    if (nand_info_join_path(dst, sizeof(dst), "/sys/class/block", "sda") != 0 ||
        strcmp(dst, "/sys/class/block/sda") != 0) {
        FAIL("exact fit should succeed");
        return;
    }
    PASS();
}

static void test_join_path_overflow_one_byte(void) {
    char dst[sizeof("/sys/class/block/sda") - 1];
    TEST("nand_info_join_path overflow by one byte");
    if (nand_info_join_path(dst, sizeof(dst), "/sys/class/block", "sda") != -1 ||
        dst[0] != '\0') {
        FAIL("expected clean failure with empty dst");
        return;
    }
    PASS();
}

static void test_join_path_empty_base(void) {
    char dst[64];
    TEST("nand_info_join_path empty base");
    dst[0] = 'X';
    if (nand_info_join_path(dst, sizeof(dst), "", "sda") != -1 || dst[0] != '\0') {
        FAIL("expected clean failure with empty dst");
        return;
    }
    PASS();
}

static void test_join_path_null_args(void) {
    char dst[64];
    TEST("nand_info_join_path NULL arguments");
    if (nand_info_join_path(NULL, sizeof(dst), "/sys/class/block", "sda") != -1) {
        FAIL("NULL dst should fail");
        return;
    }
    dst[0] = 'X';
    if (nand_info_join_path(dst, sizeof(dst), NULL, "sda") != -1 || dst[0] != '\0') {
        FAIL("NULL base should clear dst");
        return;
    }
    dst[0] = 'X';
    if (nand_info_join_path(dst, sizeof(dst), "/sys/class/block", NULL) != -1 || dst[0] != '\0') {
        FAIL("NULL leaf should clear dst");
        return;
    }
    dst[0] = 'X';
    if (nand_info_join_path(dst, 0, "/sys/class/block", "sda") != -1 || dst[0] != 'X') {
        FAIL("zero dstlen should fail without writing");
        return;
    }
    PASS();
}

static void test_join_path_empty_leaf_copies_base(void) {
    char dst[sizeof("/sys/class/block")];
    TEST("nand_info_join_path empty leaf copies base");
    if (nand_info_join_path(dst, sizeof(dst), "/sys/class/block", "") != 0 ||
        strcmp(dst, "/sys/class/block") != 0) {
        FAIL("empty leaf should copy base");
        return;
    }
    PASS();
}

static void test_join_path_minimum_valid_tail(void) {
    static const char base[] = "/sys/class/block";
    char dst[sizeof(base) + 2]; /* strlen(base) + 3: '/', 1-char leaf, NUL */
    TEST("nand_info_join_path minimum valid tail");
    memset(dst, 'X', sizeof dst);
    if (nand_info_join_path(dst, strlen(base) + 3, base, "x") != 0 ||
        strcmp(dst, "/sys/class/block/x") != 0) {
        FAIL("3-byte tail with 1-char leaf should succeed");
        return;
    }
    PASS();
}

int main(void) {
    printf("=== NAND Controller Info Tests ===\n");
    test_is_chipsbank();
    test_not_chipsbank();
    test_probe_missing();
    test_join_path_normal();
    test_join_path_base_fills_buffer();
    test_join_path_exact_fit();
    test_join_path_minimum_valid_tail();
    test_join_path_overflow_one_byte();
    test_join_path_empty_base();
    test_join_path_null_args();
    test_join_path_empty_leaf_copies_base();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
