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

/* Spy callback: record how paced_write splits a buffer into bursts. */
typedef struct {
    size_t calls;
    size_t bytes;
    size_t max_chunk;
} write_spy_t;

static int spy_write(const void *data, size_t len, void *ctx) {
    write_spy_t *spy = (write_spy_t *)ctx;
    (void)data;
    spy->calls++;
    spy->bytes += len;
    if (len > spy->max_chunk) spy->max_chunk = len;
    return 0;
}

static int fail_write(const void *data, size_t len, void *ctx) {
    (void)data; (void)len; (void)ctx;
    return -1;
}

/* Negative cooldown_sec is the test seam: the cooldown path still runs but
 * skips the 45 s wait, so no suite ever sleeps for a production threshold. */
static void test_paced_write_single_burst(void) {
    TEST("paced_write single burst");
    paced_writer_t pw;
    paced_init(&pw);
    pw.cooldown_sec = -1;
    unsigned char data[4096];
    write_spy_t spy = {0, 0, 0};
    if (paced_write(&pw, data, sizeof(data), spy_write, &spy) != 0) {
        FAIL("paced_write failed");
    } else if (spy.calls != 1 || spy.bytes != sizeof(data) ||
               pw.total_written != sizeof(data) || pw.burst_bytes != sizeof(data)) {
        FAIL("burst accounting mismatch");
    } else { PASS(); }
}

static void test_paced_write_cooldown_split(void) {
    TEST("paced_write cooldown between bursts");
    paced_writer_t pw;
    paced_init(&pw);
    pw.cooldown_sec = -1;
    pw.burst_bytes = PACED_BURST_SIZE - 100; /* force a cooldown after 100 bytes */
    unsigned char data[300];
    write_spy_t spy = {0, 0, 0};
    if (paced_write(&pw, data, sizeof(data), spy_write, &spy) != 0) {
        FAIL("paced_write failed");
    } else if (spy.calls != 2 || spy.bytes != sizeof(data) ||
               spy.max_chunk != 200 || pw.burst_bytes != 200) {
        FAIL("cooldown did not split into 100 + 200 bytes");
    } else { PASS(); }
}

static void test_paced_write_propagates_error(void) {
    TEST("paced_write propagates write_fn failure");
    paced_writer_t pw;
    paced_init(&pw);
    pw.cooldown_sec = -1;
    unsigned char data[16];
    if (paced_write(&pw, data, sizeof(data), fail_write, NULL) == 0) {
        FAIL("write_fn failure was swallowed");
    } else { PASS(); }
}

static void test_cooldown_resets_state(void) {
    TEST("paced_cooldown resets burst state");
    paced_writer_t pw;
    paced_init(&pw);
    pw.cooldown_sec = -1;
    paced_record_burst(&pw, PACED_BURST_SIZE);
    if (pw.last_burst_time == 0) { FAIL("no monotonic burst timestamp"); return; }
    paced_cooldown(&pw);
    if (pw.burst_bytes != 0 || pw.last_burst_time != 0 ||
        pw.total_written != PACED_BURST_SIZE) {
        FAIL("cooldown did not reset state");
    } else { PASS(); }
}

int main(void) {
    printf("=== Paced Write Tests ===\n");
    test_init();
    test_should_cooldown_initial();
    test_record_burst();
    test_remaining_burst();
    test_cooldown_after_full_burst();
    test_paced_write_single_burst();
    test_paced_write_cooldown_split();
    test_paced_write_propagates_error();
    test_cooldown_resets_state();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
