/* test_tea_native.c - golden-vector tests for the clean-room cipher */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tea_native.h"

#define KEY TEA_NATIVE_KEY
#define PE_PATH "/tmp/opencode/ap.exe"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

static void to_hex(const unsigned char *buf, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[buf[i] >> 4];
        out[i * 2 + 1] = digits[buf[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static void check_vector(const char *name, const unsigned char *input,
                         size_t len, const char *golden) {
    unsigned char buf[64];
    char hex[128];
    TEST(name);
    memcpy(buf, input, len);
    if (tea_native_encrypt(buf, len, KEY) != 0) { FAIL("encrypt returned nonzero"); return; }
    to_hex(buf, len, hex);
    if (strcmp(hex, golden) != 0) {
        printf("\n  got      %s\n  expected %s\n", hex, golden);
        tests_failed++;
        return;
    }
    if (tea_native_decrypt(buf, len, KEY) != 0) { FAIL("decrypt returned nonzero"); return; }
    if (memcmp(buf, input, len) != 0) { FAIL("roundtrip mismatch"); return; }
    PASS();
}

static void test_vector_a(void) {
    const unsigned char in[8] = {0};
    check_vector("vector A (8 zero bytes)", in, sizeof in,
                 "e66254b5da09fb31");
}

static void test_vector_b(void) {
    unsigned char in[32];
    for (size_t i = 0; i < sizeof in; i++) in[i] = (unsigned char)i;
    check_vector("vector B (bytes 0..31)", in, sizeof in,
                 "3dd24f1e5c7d940ef690cfcc84ddff02660d74c782b22e1e4015059980c24f01");
}

static void test_vector_c(void) {
    const unsigned char in[15] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    check_vector("vector C (15 bytes, odd)", in, sizeof in,
                 "1b787ed12c571f48090a0b0c0d0e0f");
}

static void test_two_calls_state_reset(void) {
    TEST("two calls state reset");
    const unsigned char in[8] = {1,2,3,4,5,6,7,8};
    unsigned char a[8], b[8];
    memcpy(a, in, sizeof in);
    memcpy(b, in, sizeof in);
    if (tea_native_encrypt(a, sizeof a, KEY) != 0 ||
        tea_native_encrypt(b, sizeof b, KEY) != 0) { FAIL("encrypt returned nonzero"); return; }
    if (memcmp(a, b, sizeof a) != 0) { FAIL("second call differed from first"); return; }
    PASS();
}

static void test_short_key(void) {
    TEST("short key rejected");
    unsigned char buf[8];
    memset(buf, 0x5a, sizeof buf);
    unsigned char before[8];
    memcpy(before, buf, sizeof buf);
    if (tea_native_encrypt(buf, sizeof buf, "abcd") == 0) { FAIL("short key accepted"); return; }
    if (memcmp(buf, before, sizeof buf) != 0) { FAIL("buffer changed on failure"); return; }
    if (tea_native_decrypt(buf, sizeof buf, "abcd") == 0) { FAIL("short key accepted on decrypt"); return; }
    if (memcmp(buf, before, sizeof buf) != 0) { FAIL("buffer changed on decrypt failure"); return; }
    PASS();
}

static void test_odd_length_bounds(void) {
    /* ASan builds detect a read/write past this exact 15-byte allocation. */
    TEST("odd length bounds (15 bytes)");
    unsigned char *buf = malloc(15);
    if (!buf) { FAIL("malloc failed"); return; }
    for (int i = 0; i < 15; i++) buf[i] = (unsigned char)(i + 1);
    if (tea_native_encrypt(buf, 15, KEY) != 0) { FAIL("encrypt returned nonzero"); goto done; }
    for (int i = 8; i < 15; i++) {
        if (buf[i] != (unsigned char)(i + 1)) { FAIL("tail byte modified"); goto done; }
    }
    if (tea_native_decrypt(buf, 15, KEY) != 0) { FAIL("decrypt returned nonzero"); goto done; }
    for (int i = 0; i < 15; i++) {
        if (buf[i] != (unsigned char)(i + 1)) { FAIL("roundtrip mismatch"); goto done; }
    }
    PASS();
done:
    free(buf);
}

static void test_selfcheck_when_pe_present(void) {
    TEST("PE oracle equivalence");
    if (access(PE_PATH, F_OK) != 0) {
        printf("SKIP (PE oracle %s not present)\n", PE_PATH);
        return;
    }
    if (tea_native_selfcheck(PE_PATH) != 0) { FAIL("native/PE outputs differ"); return; }
    PASS();
}

int main(void) {
    printf("=== Native TEA Crypto Tests ===\n");
    test_vector_a();
    test_vector_b();
    test_vector_c();
    test_two_calls_state_reset();
    test_short_key();
    test_odd_length_bounds();
    test_selfcheck_when_pe_present();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
