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

int main(void) {
    printf("=== NAND Controller Info Tests ===\n");
    test_is_chipsbank();
    test_not_chipsbank();
    test_probe_missing();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
