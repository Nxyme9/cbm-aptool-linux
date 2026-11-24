/* test_paced.c - Paced write tests */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "paced_write.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_init(void) {
    TEST("paced_init");
    paced_writer_t pw;
    paced_init(&pw);
    if (pw.burst_bytes == 0 && pw.total_written == 0 && pw.last_burst_time == 0) {
        PASS();
    } else {
        FAIL("init failed");
    }
}

static void test_should_cooldown_initial(void) {
    TEST("should_cooldown initial");
    paced_writer_t pw;
    paced_init(&pw);
    if (paced_should_cooldown(&pw) == 0) {
        PASS();
    } else {
        FAIL("should not cooldown initially");
    }
}

static void test_record_burst(void) {
    TEST("record_burst");
    paced_writer_t pw;
    paced_init(&pw);
    paced_record_burst(&pw, 1000);
    if (pw.burst_bytes == 1000 && pw.total_written == 1000) {
        PASS();
    } else {
        FAIL("record failed");
    }
}

static void test_remaining_burst(void) {
    TEST("remaining_burst");
    paced_writer_t pw;
    paced_init(&pw);
    paced_record_burst(&pw, 1000);
    size_t rem = paced_remaining_burst(&pw);
    if (rem == PACED_BURST_SIZE - 1000) {
        PASS();
    } else {
        FAIL("remaining mismatch");
    }
}

static void test_cooldown_after_full_burst(void) {
    TEST("cooldown after full burst");
    paced_writer_t pw;
    paced_init(&pw);
    paced_record_burst(&pw, PACED_BURST_SIZE);
    if (paced_should_cooldown(&pw) == 1) {
        PASS();
    } else {
        FAIL("should cooldown after full burst");
    }
}

int main(void) {
    printf("=== Paced Write Tests ===\n");
    test_init();
    test_should_cooldown_initial();
    test_record_burst();
    test_remaining_burst();
    test_cooldown_after_full_burst();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
