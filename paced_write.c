/* paced_write.c - Paced write controller implementation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "paced_write.h"

/* Monotonic seconds, offset by one so 0 stays the "no burst recorded" sentinel. */
static time_t paced_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 1;
    return (time_t)ts.tv_sec + 1;
}

void paced_init(paced_writer_t *pw) {
    if (!pw) return;
    pw->burst_bytes = 0;
    pw->last_burst_time = 0;
    pw->total_written = 0;
    pw->cooldown_sec = PACED_COOLDOWN_SEC;
}

int paced_should_cooldown(paced_writer_t *pw) {
    if (!pw) return 0;
    return (pw->burst_bytes >= PACED_BURST_SIZE) ? 1 : 0;
}

void paced_record_burst(paced_writer_t *pw, size_t bytes) {
    if (!pw) return;
    pw->burst_bytes += bytes;
    pw->total_written += bytes;
    if (pw->burst_bytes >= PACED_BURST_SIZE) {
        pw->last_burst_time = paced_now();
    }
}

void paced_cooldown(paced_writer_t *pw) {
    if (!pw || pw->last_burst_time == 0) return;
    time_t elapsed = paced_now() - pw->last_burst_time;
    if (elapsed < 0) elapsed = 0; /* no underflow into an overflowing wait */
    if (elapsed < pw->cooldown_sec) {
        struct timespec req;
        req.tv_sec = pw->cooldown_sec - elapsed;
        req.tv_nsec = 0;
        while (nanosleep(&req, &req) < 0 && errno == EINTR) { /* retry */ }
    }
    pw->burst_bytes = 0;
    pw->last_burst_time = 0;
}

size_t paced_remaining_burst(paced_writer_t *pw) {
    if (!pw) return 0;
    if (pw->burst_bytes >= PACED_BURST_SIZE) return 0;
    return PACED_BURST_SIZE - pw->burst_bytes;
}

int paced_write(paced_writer_t *pw, const void *data, size_t len,
                int (*write_fn)(const void *, size_t, void *), void *ctx) {
    if (!pw || !data || !write_fn) return -1;
    size_t offset = 0;
    while (offset < len) {
        /* Check if cooldown needed */
        if (paced_should_cooldown(pw)) {
            paced_cooldown(pw);
        }
        /* Determine how many bytes to write in this burst */
        size_t remaining = paced_remaining_burst(pw);
        if (remaining == 0) remaining = PACED_BURST_SIZE;
        size_t to_write = len - offset;
        if (to_write > remaining) to_write = remaining;
        /* Write */
        int ret = write_fn((const char *)data + offset, to_write, ctx);
        if (ret != 0) return -1;
        /* Record burst */
        paced_record_burst(pw, to_write);
        offset += to_write;
    }
    return 0;
}
