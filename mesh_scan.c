/* mesh_scan.c - read-only distributed mesh scan coordinator
 *
 * Pure orchestration: plan overlapping ranges, hand each to a transport-agnostic
 * worker (local in-tree, or a CLS-backed adapter), aggregate and deduplicate the
 * hits, and report the execution mode honestly. Never claims remote execution
 * that did not happen; a failed or absent peer falls back to a local read-only
 * scan of that range. No writes to the scanned image or device.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_container.h"
#include "cli_json.h"
#include "mesh_scan.h"

/* Two containers plus one LBA. Matches cbm_scan_image's chunk overlap so a
 * container straddling a range boundary is wholly inside at least one range. */
#define MESH_OVERLAP 171888ULL

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
}

size_t mesh_plan_ranges(unsigned long long start, unsigned long long end,
                        size_t chunk_bytes, unsigned long long *ranges,
                        size_t max_ranges) {
    if (!ranges || max_ranges == 0u || end < start ||
        (unsigned long long)chunk_bytes <= MESH_OVERLAP) return 0u;
    unsigned long long step = (unsigned long long)chunk_bytes - MESH_OVERLAP;
    size_t n = 0u;
    unsigned long long s = start;
    while (s <= end && n < max_ranges) {
        ranges[n++] = s;
        if (s > end - step) break; /* next start would exceed end */
        s += step;
    }
    return n;
}

static int cmp_hit_offset(const void *a, const void *b) {
    const cbm_scan_hit_t *x = (const cbm_scan_hit_t *)a;
    const cbm_scan_hit_t *y = (const cbm_scan_hit_t *)b;
    if (x->offset < y->offset) return -1;
    if (x->offset > y->offset) return 1;
    return 0;
}

size_t mesh_dedup(cbm_scan_hit_t *hits, size_t count) {
    if (!hits || count == 0u) return 0u;
    qsort(hits, count, sizeof(hits[0]), cmp_hit_offset);
    size_t w = 0u;
    for (size_t i = 0u; i < count; i++) {
        if (w > 0u && hits[i].offset == hits[w - 1u].offset) continue;
        if (w != i) hits[w] = hits[i];
        w++;
    }
    return w;
}

void mesh_result_free(mesh_result_t *res) {
    if (!res) return;
    cbm_scan_free_hits(res->hits);
    res->hits = NULL;
    res->hit_count = 0u;
}

/* Append h[0..hn] into the growing aggregate. Returns 0 on success. */
static int append_hits(cbm_scan_hit_t **all, size_t *n, size_t *cap,
                       const cbm_scan_hit_t *h, size_t hn) {
    if (hn == 0u) return 0;
    if (*n + hn > *cap) {
        size_t want = *cap ? *cap : 16u;
        while (want < *n + hn) {
            if (want > (size_t)-1 / 2u) return -1;
            want *= 2u;
        }
        cbm_scan_hit_t *grown = (cbm_scan_hit_t *)realloc(*all, want * sizeof(*grown));
        if (!grown) return -1;
        *all = grown;
        *cap = want;
    }
    memcpy(*all + *n, h, hn * sizeof(*h));
    *n += hn;
    return 0;
}

int mesh_scan_run(const char *path, unsigned long long start,
                  unsigned long long end, size_t chunk_bytes,
                  const mesh_worker_t *workers, size_t worker_count,
                  mesh_result_t *res, char *err, size_t errlen) {
    if (!res) {
        seterr(err, errlen, "mesh_scan_run: null result");
        return -1;
    }
    memset(res, 0, sizeof(*res));
    seterr(err, errlen, "");
    if (!path || start > end || (unsigned long long)chunk_bytes <= MESH_OVERLAP ||
        (worker_count > 0u && !workers)) {
        seterr(err, errlen, "mesh_scan_run: invalid arguments");
        return -1;
    }

    unsigned long long ranges[MESH_MAX_RANGES];
    size_t nr = mesh_plan_ranges(start, end, chunk_bytes, ranges, MESH_MAX_RANGES);
    if (nr == 0u) {
        seterr(err, errlen, "mesh_scan_run: cannot plan ranges");
        return -1;
    }

    res->worker_count = worker_count;
    res->jobs_total = nr;
    res->ranges_scanned = nr;

    cbm_scan_hit_t *all = NULL;
    size_t all_n = 0u, all_cap = 0u;
    int rc = -1;
    for (size_t i = 0u; i < nr; i++) {
        unsigned long long rs = ranges[i];
        unsigned long long re = rs + (unsigned long long)chunk_bytes - 1u;
        if (re > end) re = end;
        cbm_scan_hit_t *hits = NULL;
        size_t hn = 0u;
        int ok = 0;

        if (worker_count > 0u) {
            const mesh_worker_t *w = &workers[i % worker_count];
            char werr[256];
            werr[0] = '\0';
            ok = w->fn && w->fn(w->ctx, w->name, path, rs, re, chunk_bytes,
                               &hits, &hn, werr, sizeof(werr)) == 0;
            if (ok) res->jobs_ok++;
        }
        if (!ok) {
            /* Fail closed: absent or failed peer -> local read-only scan. */
            char lerr[256];
            lerr[0] = '\0';
            if (cbm_scan_image_ex(path, rs, re, chunk_bytes, NULL, 0u, 1,
                                  &hits, &hn, lerr, sizeof(lerr)) != 0) {
                seterr(err, errlen, lerr[0] ? lerr : "mesh_scan_run: local scan failed");
                goto out;
            }
            res->local_retries++;
        }
        if (append_hits(&all, &all_n, &all_cap, hits, hn) != 0) {
            seterr(err, errlen, "mesh_scan_run: out of memory aggregating hits");
            cbm_scan_free_hits(hits);
            goto out;
        }
        cbm_scan_free_hits(hits);
    }

    if (worker_count == 0u || res->jobs_ok == 0u) {
        res->mode = MESH_MODE_LOCAL_FALLBACK;
        snprintf(res->mode_detail, sizeof(res->mode_detail),
                 "no peer available; %zu ranges scanned locally in fallback mode", nr);
    } else {
        res->mode = MESH_MODE_DISTRIBUTED;
        if (res->local_retries > 0u)
            snprintf(res->mode_detail, sizeof(res->mode_detail),
                     "distributed across %zu of %zu ranges; %zu ranges retried locally",
                     res->jobs_ok, nr, res->local_retries);
        else
            snprintf(res->mode_detail, sizeof(res->mode_detail),
                     "distributed across %zu of %zu ranges", res->jobs_ok, nr);
    }

    res->hits = all;
    res->hit_count = mesh_dedup(all, all_n);
    all = NULL; /* ownership moved to res */
    rc = 0;

out:
    cbm_scan_free_hits(all);
    return rc;
}

void mesh_report_json(FILE *out, const mesh_result_t *res) {
    if (!out || !res) return;
    const char *mode = res->mode == MESH_MODE_DISTRIBUTED ? "distributed"
                                                          : "local_fallback";
    cbm_json_t j;
    memset(&j, 0, sizeof(j));
    cbm_json_object_begin(&j, out, "mesh-scan", "ok");
    cbm_json_field_string(&j, "mode", mode);
    cbm_json_field_string(&j, "mode_detail", res->mode_detail);
    cbm_json_field_u64(&j, "workers", (unsigned long long)res->worker_count);
    cbm_json_field_u64(&j, "jobs_total", (unsigned long long)res->jobs_total);
    cbm_json_field_u64(&j, "jobs_ok", (unsigned long long)res->jobs_ok);
    cbm_json_field_u64(&j, "local_retries", (unsigned long long)res->local_retries);
    cbm_json_field_u64(&j, "ranges_scanned", (unsigned long long)res->ranges_scanned);
    cbm_json_field_u64(&j, "hit_count", (unsigned long long)res->hit_count);
    cbm_json_array_begin(&j, "hits");
    for (size_t i = 0u; i < res->hit_count; i++) {
        const cbm_scan_hit_t *h = &res->hits[i];
        cbm_json_element_object(&j);
        cbm_json_field_u64(&j, "offset", h->offset);
        cbm_json_field_u64(&j, "header", h->header);
        cbm_json_field_fixed6(&j, "entropy", h->entropy);
        cbm_json_object_end(&j); /* closes the element object */
    }
    cbm_json_array_end(&j);
    cbm_json_end(&j);
}
