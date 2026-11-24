/* test_cbm.c - CBM container tests */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cbm_container.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_check_encrypted(void) {
    TEST("cbm_check_encrypted");
    unsigned char encrypted_header[1] = {0x80};
    unsigned char plain_header[1] = {0x00};
    if (cbm_check_encrypted(encrypted_header, 85688) == CBM_ERR_ENCRYPTED) {
        PASS();
    } else {
        FAIL("encrypted check failed");
    }
    if (cbm_check_encrypted(plain_header, 85688) == CBM_OK) {
        PASS();
    } else {
        FAIL("plain check failed");
    }
}

static void test_compute_hlen(void) {
    TEST("cbm_compute_hlen");
    /* HLEN = ((filesize-511)&~7)+511 */
    size_t hl = cbm_compute_hlen(85688);
    if (hl == ((85688 - 511) & ~7) + 511) {
        PASS();
    } else {
        FAIL("hlen mismatch");
    }
    hl = cbm_compute_hlen(512);
    if (hl == 511) {
        PASS();
    } else {
        FAIL("hlen small mismatch");
    }
}

int main(void) {
    printf("=== CBM Container Tests ===\n");
    test_check_encrypted();
    test_compute_hlen();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
