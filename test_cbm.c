/* test_cbm.c - CBM container tests */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cbm_container.h"
#include "tea_crypto.h"

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

static void test_cbc_odd_length(void) {
    TEST("cbm_cbc roundtrip 85687 bytes (non-multiple of 8)");
    const char *pe_path = getenv("CBM_PE_PATH");
    if (!pe_path || !pe_path[0]) pe_path = "/tmp/opencode/ap.exe";
    if (tea_init(pe_path) != 0) {
        FAIL("tea_init failed");
        return;
    }
    const size_t body_len = 85687;
    unsigned char *orig = (unsigned char *)malloc(body_len);
    unsigned char *buf = (unsigned char *)malloc(body_len);
    if (!orig || !buf) { FAIL("malloc failed"); free(orig); free(buf); return; }
    for (size_t i = 0; i < body_len; i++) orig[i] = (unsigned char)(i * 13 + 7);
    memcpy(buf, orig, body_len);

    const char *key = "1a2b3c4d5e6fTENG";
    if (cbm_cbc_encrypt(buf, body_len, key) != 0) {
        FAIL("encrypt failed");
        free(orig); free(buf); tea_cleanup(); return;
    }
    /* Encrypted data must differ from plaintext */
    if (memcmp(buf, orig, body_len) == 0) {
        FAIL("encrypt did not change data");
        free(orig); free(buf); tea_cleanup(); return;
    }
    if (cbm_cbc_decrypt(buf, body_len, key) != 0) {
        FAIL("decrypt failed");
        free(orig); free(buf); tea_cleanup(); return;
    }
    if (memcmp(buf, orig, body_len) != 0) {
        FAIL("roundtrip mismatch");
        free(orig); free(buf); tea_cleanup(); return;
    }
    PASS();
    free(orig);
    free(buf);
    tea_cleanup();
}

int main(void) {
    printf("=== CBM Container Tests ===\n");
    test_check_encrypted();
    test_compute_hlen();
    test_cbc_odd_length();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
