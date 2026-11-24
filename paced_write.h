/* paced_write.h - Paced write controller (40 MiB bursts + 45 s cooldowns) */
#ifndef PACED_WRITE_H
#define PACED_WRITE_H

#include <stddef.h>
#include <time.h>

#define PACED_BURST_SIZE (40 * 1024 * 1024)  /* 40 MiB */
#define PACED_COOLDOWN_SEC 45

typedef struct {
    size_t burst_bytes;
    time_t last_burst_time;
    size_t total_written;
} paced_writer_t;

void paced_init(paced_writer_t *pw);
int paced_should_cooldown(paced_writer_t *pw);
void paced_record_burst(paced_writer_t *pw, size_t bytes);
void paced_cooldown(paced_writer_t *pw);
size_t paced_remaining_burst(paced_writer_t *pw);
int paced_write(paced_writer_t *pw, const void *data, size_t len,
                int (*write_fn)(const void *, size_t, void *), void *ctx);

#endif /* PACED_WRITE_H */
