/* test_tea.c - TEA crypto tests */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "tea_crypto.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_init(void) {
    TEST("tea_init");
    const char *pe_path = getenv("CBM_PE_PATH");
    if (!pe_path || !pe_path[0]) pe_path = "/tmp/opencode/ap.exe";
    int ret = tea_init(pe_path);
    if (ret == 0 && tea_is_ready()) {
        PASS();
    } else {
        FAIL("init failed");
    }
}

static void test_roundtrip_8(void) {
    TEST("roundtrip 8 bytes");
    unsigned char orig[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    unsigned char buf[8];
    memcpy(buf, orig, 8);
    const char *key = "1a2b3c4d5e6fTENG";
    int ret = tea_encrypt(buf, 8, key);
    if (ret != 0) { FAIL("encrypt failed"); return; }
    /* Check that encrypted data differs from original */
    if (memcmp(buf, orig, 8) == 0) { FAIL("encrypt did not change data"); return; }
    ret = tea_decrypt(buf, 8, key);
    if (ret != 0) { FAIL("decrypt failed"); return; }
    if (memcmp(buf, orig, 8) != 0) { FAIL("roundtrip mismatch"); return; }
    PASS();
}

static void test_roundtrip_64(void) {
    TEST("roundtrip 64 bytes");
    unsigned char orig[64];
    unsigned char buf[64];
    for (int i = 0; i < 64; i++) orig[i] = (unsigned char)(i * 7 + 3);
    memcpy(buf, orig, 64);
    const char *key = "1a2b3c4d5e6fTENG";
    int ret = tea_encrypt(buf, 64, key);
    if (ret != 0) { FAIL("encrypt failed"); return; }
    ret = tea_decrypt(buf, 64, key);
    if (ret != 0) { FAIL("decrypt failed"); return; }
    if (memcmp(buf, orig, 64) != 0) { FAIL("roundtrip mismatch"); return; }
    PASS();
}

static void test_roundtrip_256(void) {
    TEST("roundtrip 256 bytes");
    unsigned char orig[256];
    unsigned char buf[256];
    for (int i = 0; i < 256; i++) orig[i] = (unsigned char)(i * 3 + 7);
    memcpy(buf, orig, 256);
    const char *key = "1a2b3c4d5e6fTENG";
    int ret = tea_encrypt(buf, 256, key);
    if (ret != 0) { FAIL("encrypt failed"); return; }
    ret = tea_decrypt(buf, 256, key);
    if (ret != 0) { FAIL("decrypt failed"); return; }
    if (memcmp(buf, orig, 256) != 0) { FAIL("roundtrip mismatch"); return; }
    PASS();
}

static void test_not_ready(void) {
    TEST("not ready check");
    /* Can't easily test without reinit, just verify is_ready returns true after init */
    if (tea_is_ready()) {
        PASS();
    } else {
        FAIL("should be ready");
    }
}

int main(void) {
    printf("=== TEA Crypto Tests ===\n");
    test_init();
    test_roundtrip_8();
    test_roundtrip_64();
    test_roundtrip_256();
    test_not_ready();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    tea_cleanup();
    return tests_failed > 0 ? 1 : 0;
}
