/* mesh_scan.h - read-only distributed mesh scan coordinator
 *
 * Splits an image/device byte range into overlapping ranges and dispatches each
 * to a worker. A worker is a transport-agnostic callback: the in-tree local
 * worker runs cbm_scan_image_ex read-only; a CLS-backed host adapter can supply
 * remote peers through the same signature. The aggregator deduplicates hits by
 * absolute offset and emits a combined report that ALWAYS names the execution
 * mode. With no peers it fails closed to local chunks and says so; it never
 * claims distributed execution that did not happen.
 */
#ifndef MESH_SCAN_H
#define MESH_SCAN_H

#include <stddef.h>
#include <stdio.h>

#include "cbm_scan.h"

#define MESH_MAX_RANGES 4096u

typedef enum {
    MESH_MODE_DISTRIBUTED = 0,
    MESH_MODE_LOCAL_FALLBACK = 1
} mesh_mode_t;

/* Scan one inclusive absolute byte range of `path`, read-only. The worker owns
 * the `hits` allocation (caller frees with cbm_scan_free_hits). Returns 0 on
 * success, -1 on failure with a message in err/errlen. `name` is a short label
 * used for diagnostics only; it is never emitted into a JSON report. */
typedef int (*mesh_worker_fn)(void *ctx, const char *name, const char *path,
                              unsigned long long start, unsigned long long end,
                              size_t chunk_bytes, cbm_scan_hit_t **hits,
                              size_t *count, char *err, size_t errlen);

typedef struct {
    char name[64];
    mesh_worker_fn fn;
    void *ctx;
} mesh_worker_t;

typedef struct {
    mesh_mode_t mode;
    size_t worker_count;    /* peers configured by the caller */
    size_t jobs_total;      /* ranges planned */
    size_t jobs_ok;         /* ranges answered by a peer */
    size_t local_retries;   /* ranges run locally (no peer or peer failed) */
    size_t ranges_scanned;
    cbm_scan_hit_t *hits;   /* malloc'd, ascending offset, deduplicated */
    size_t hit_count;
    char mode_detail[160];
} mesh_result_t;

/* Plan overlapping range START offsets covering [start,end]. Consecutive
 * starts differ by at most chunk_bytes; the overlap is 171888 bytes (two
 * containers plus one LBA) so a container straddling a boundary is wholly
 * inside at least one range. Returns the number written, capped at
 * max_ranges; returns 0 when the arguments are invalid. */
size_t mesh_plan_ranges(unsigned long long start, unsigned long long end,
                        size_t chunk_bytes, unsigned long long *ranges,
                        size_t max_ranges);

/* Deduplicate hits by absolute offset, in place, ascending. Returns the new
 * count. Exposed for direct testing of cross-range overlap collapse. */
size_t mesh_dedup(cbm_scan_hit_t *hits, size_t count);

/* Run the mesh scan. `workers` may be NULL / count 0 -> local fallback.
 * On success returns 0 and fills res; caller frees res->hits with
 * mesh_result_free. Returns -1 on error with a message in err/errlen. */
int mesh_scan_run(const char *path, unsigned long long start,
                  unsigned long long end, size_t chunk_bytes,
                  const mesh_worker_t *workers, size_t worker_count,
                  mesh_result_t *res, char *err, size_t errlen);

void mesh_result_free(mesh_result_t *res);

/* Emit one deterministic cbm/1 JSON document describing the result. */
void mesh_report_json(FILE *out, const mesh_result_t *res);

#endif /* MESH_SCAN_H */
