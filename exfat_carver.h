/* exfat_carver.h - read-only exFAT undelete carver (intact metadata only)
 *
 * Parses an exFAT volume at a caller-supplied byte offset (or at the DJ_DATA
 * partition start) and reports deleted files whose metadata is still intact.
 * Only files whose allocation-bitmap bits are all free, whose data run is
 * contiguous (NoFatChain) and whose clusters are in range are carved, and their
 * bytes are written ONLY to a caller-named local output directory. Fragmented,
 * reused or unverifiable files are reported unrecoverable, never guessed.
 */
#ifndef EXFAT_CARVER_H
#define EXFAT_CARVER_H

#include <stddef.h>
#include <stdio.h>

typedef enum {
    EXFAT_OUT_RECOVERED = 0,
    EXFAT_OUT_LOST = 1
} exfat_outcome_t;

typedef struct {
    char name[256];
    unsigned long long first_cluster;
    unsigned long long size;
    exfat_outcome_t outcome;
    char detail[160];
} exfat_entry_t;

typedef struct {
    exfat_entry_t *entries;
    size_t count;
    size_t capacity;
} exfat_report_t;

/* Carve the exFAT volume starting at byte offset `base` in `path` (regular
 * file or block device, always read-only). Recovered bytes are written only
 * into `outdir`, which must already exist. Returns 0 on success with `report`
 * filled (caller frees it with exfat_report_free), -1 on parse/IO error with
 * a message in err/errlen. */
int exfat_carve(const char *path, unsigned long long base, const char *outdir,
                exfat_report_t *report, char *err, size_t errlen);

/* As exfat_carve, but locate the exFAT partition (type 0x07) from the MBR. */
int exfat_carve_dj_data(const char *path, const char *outdir,
                        exfat_report_t *report, char *err, size_t errlen);

void exfat_report_free(exfat_report_t *report);

/* One deterministic cbm/1 JSON document describing the candidates. */
void exfat_report_json(FILE *out, const exfat_report_t *report);

#endif /* EXFAT_CARVER_H */
