/* telemetry.h - read-only Prometheus telemetry exporter
 *
 * Exposes tool/device counters as Prometheus text over a local HTTP listener.
 * All device access is read-only (stat / O_RDONLY + BLKGETSIZE64). Counters
 * come from a caller-supplied key=value state file re-read on each scrape;
 * nothing here persists state or opens a device for writing.
 */
#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <signal.h>
#include <stddef.h>
#include <stdio.h>

#define TELEMETRY_LABEL_MAX 64u
#define TELEMETRY_PATH_MAX 512u

typedef struct {
    int device_present;
    unsigned long long device_capacity_bytes;
    double scan_progress_ratio;
    unsigned long long containers_found;
    unsigned long long cdb_commands_total;
    unsigned long long entropy_blocks_total;
    unsigned long long last_validation_timestamp_seconds;
    int crypto_backend_native;
    char device_label[TELEMETRY_LABEL_MAX]; /* scrubbed; safe to render */
    char device_path[TELEMETRY_PATH_MAX];   /* re-probed on each scrape */
    char state_file[TELEMETRY_PATH_MAX];    /* re-read on each scrape */
} telemetry_state_t;

void telemetry_state_init(telemetry_state_t *st);

/* Resolve path and keep only the final component; by-id serials and full
 * paths never reach the rendered output. Unresolvable paths become "unknown". */
int telemetry_scrub_device(const char *path, char *out, size_t outlen,
                           char *err, size_t errlen);

/* Read-only probe. A missing path is an absent device (present=0), not an
 * error. Regular files use their size; block devices use BLKGETSIZE64. */
int telemetry_probe_device(const char *path, telemetry_state_t *st,
                           char *err, size_t errlen);

/* Load key=value counters. Parsed into a temporary and committed only if
 * every line is valid; unknown keys and non-numeric values fail closed. */
int telemetry_load_state(const char *path, telemetry_state_t *st,
                         char *err, size_t errlen);

/* One Prometheus text exposition document (version 0.0.4). */
void telemetry_render(FILE *out, const telemetry_state_t *st);

/* Bind a listener. ":PORT" binds loopback only; HOST:PORT requires numeric
 * IPv4 ("0.0.0.0:PORT" is an explicit opt-in to expose the endpoint). */
int telemetry_listen(const char *addr, int *fd, char *err, size_t errlen);

/* Serve one accepted connection: refresh state, then answer GET /metrics,
 * GET /, or a 404/405. Refresh failures return 500, never stale values. */
void telemetry_handle_conn(int fd, telemetry_state_t *st);

/* Accept loop; stops when *stop becomes nonzero (SIGINT/SIGTERM in the CLI). */
int telemetry_serve(const char *addr, telemetry_state_t *st,
                    volatile sig_atomic_t *stop, char *err, size_t errlen);

/* cbm-tool telemetry --listen ADDR [--device PATH] [--state-file PATH]
 *   or cbm-tool telemetry --print [--device PATH] [--state-file PATH] [--json] */
int telemetry_cli_ex(int argc, char **argv, FILE *out, FILE *err, FILE *json);

#endif /* TELEMETRY_H */
