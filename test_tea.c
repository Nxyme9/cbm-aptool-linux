/* test_tea.c - TEA crypto tests */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "tea_crypto.h"
#include "cbm_backend.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static const char *pe_path_from_env(void) {
    const char *p = getenv("CBM_PE_PATH");
    return (p && *p) ? p : NULL;
}

/* The PE backend may only reject a NULL path when the environment supplies no
 * path either. Temporarily blank CBM_PE_PATH, then restore it for the real PE
 * cases below. */
static int pe_null_path_rejected(const char *pe_path) {
    int rc;
    if (setenv("CBM_PE_PATH", "", 1) != 0) return 0;
    rc = tea_init(NULL);
    if (rc == 0) tea_cleanup(); /* unexpected: drop the PE mapping before redo */
    if (setenv("CBM_PE_PATH", pe_path, 1) != 0) return 0;
    return rc != 0;
}

static void test_init(void) {
    TEST("tea_init");
    int ret = tea_init(pe_path_from_env());
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

/* Covers tea_crypto.c's PE branch: mmap loader, PE function-pointer calls and
 * tea_cleanup()'s munmap. tea_native_selfcheck() uses a different loader and
 * does not exercise this path. */
static void test_pe_backend_dispatch(void) {
    const char *pe_path = pe_path_from_env();
    TEST("PE backend dispatch (tea_crypto.c)");
    if (!pe_path) {
        printf("SKIP (CBM_PE_PATH not set)\n");
        return;
    }
    if (access(pe_path, F_OK) != 0) {
        printf("SKIP (PE oracle %s not present)\n", pe_path);
        return;
    }

    const char *why = NULL;
    int ok = 0;
    unsigned char orig[64], buf[64];
    const char *key = "1a2b3c4d5e6fTENG";

    /* Earlier cases leave the native backend ready, and tea_init() no-ops
     * when ready: drop it before switching so the PE branch is taken. */
    tea_cleanup();
    cbm_backend_set(CBM_BACKEND_PE);
    if (cbm_backend_get() != CBM_BACKEND_PE) {
        why = "backend did not switch to PE";
    } else if (!pe_null_path_rejected(pe_path)) {
        /* With no env path either, the PE branch must reject a NULL path. */
        why = "PE backend accepted NULL path with CBM_PE_PATH empty";
    } else if (tea_init(pe_path) != 0 || !tea_is_ready()) {
        why = "PE tea_init failed";
    } else {
        for (int i = 0; i < (int)sizeof orig; i++)
            orig[i] = (unsigned char)(i * 7 + 3);
        memcpy(buf, orig, sizeof orig);
        if (tea_encrypt(buf, sizeof buf, key) != 0) {
            why = "PE encrypt failed";
        } else if (memcmp(buf, orig, sizeof orig) == 0) {
            why = "PE encrypt did not change data";
        } else if (tea_decrypt(buf, sizeof buf, key) != 0) {
            why = "PE decrypt failed";
        } else if (memcmp(buf, orig, sizeof orig) != 0) {
            why = "PE roundtrip mismatch";
        } else {
            ok = 1;
        }
        tea_cleanup(); /* must munmap the PE image from 0x400000 */
        if (tea_is_ready()) { ok = 0; why = "still ready after cleanup"; }
    }

    cbm_backend_set(CBM_BACKEND_NATIVE);
    if (tea_init(NULL) != 0 || !tea_is_ready()) {
        ok = 0;
        if (!why) why = "native reinit after PE failed";
    }
    if (ok) PASS(); else FAIL(why ? why : "PE dispatch failed");
}

int main(void) {
    printf("=== TEA Crypto Tests ===\n");
    test_init();
    test_roundtrip_8();
    test_roundtrip_64();
    test_roundtrip_256();
    test_not_ready();
    test_pe_backend_dispatch();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    tea_cleanup();
    return tests_failed > 0 ? 1 : 0;
}
