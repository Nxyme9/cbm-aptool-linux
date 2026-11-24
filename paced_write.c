/* paced_write.c - Paced write controller implementation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "paced_write.h"

void paced_init(paced_writer_t *pw) {
    if (!pw) return;
    pw->burst_bytes = 0;
    pw->last_burst_time = 0;
    pw->total_written = 0;
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
        pw->last_burst_time = time(NULL);
    }
}

void paced_cooldown(paced_writer_t *pw) {
    if (!pw || pw->last_burst_time == 0) return;
    time_t now = time(NULL);
    time_t elapsed = now - pw->last_burst_time;
    if (elapsed < PACED_COOLDOWN_SEC) {
        time_t wait = PACED_COOLDOWN_SEC - elapsed;
        sleep((unsigned int)wait);
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
