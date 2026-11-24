/* cbm_doctor.h - guarded MBR diagnosis and repair (Wave 5D)
 *
 * `doctor` is a DIAGNOSIS tool first. cbm_doctor_report only reads the target;
 * it never opens it for writing and never refuses a readable image. The sole
 * write path is cbm_doctor_repair, which writes exactly one 512-byte sector
 * (LBA 0) after every authorisation condition is met:
 *   - explicit --repair-mbr + --yes + --backup at the CLI layer;
 *   - backup path pre-flighted with the shared cbm_scan_report_check_output
 *     guard before either path is opened;
 *   - the nominal candidate must pass cbm_layout_parse + cbm_layout_validate;
 *   - the current first sector must NOT already be a valid DJ MBR with a
 *     valid signature (a parsable non-DJ table is never overwritten).
 * Fixed sequence: read -> write backup -> re-read backup (memcmp) ->
 * write candidate LBA 0 -> read back (memcmp) -> report every step.
 *
 * The candidate geometry is NOMINAL (frozen spec Design Note 2), not measured
 * from a vendor stick: start LBA 2048, types 0x0c/0x83/0x07, zeroed CHS.
 */
#ifndef CBM_DOCTOR_H
#define CBM_DOCTOR_H

#include <stddef.h>
#include <stdio.h>

#include "cbm_layout.h"

typedef struct {
    int mbr_ok;             /* first sector parsed (valid 0x55AA signature) */
    int dj_ok;              /* parsed AND validated as the DJ layout */
    int window_consistent;  /* target size >= --window-gib window */
    int candidate_ok;       /* nominal candidate parses + validates */
    int part_count;         /* partitions found in the current first sector */
    unsigned long long size_bytes;
    unsigned long long window_gib;
    unsigned char candidate[CBM_SECTOR_SIZE]; /* nominal reconstruction */
    char verdict[128];
} cbm_doctor_report_t;

typedef struct {
    int step_read;
    int step_backup_written;
    int step_backup_verified;
    int step_mbr_written;
    int step_readback_verified;
    unsigned char original[CBM_SECTOR_SIZE];
    unsigned char reconstructed[CBM_SECTOR_SIZE];
    unsigned char readback[CBM_SECTOR_SIZE];
} cbm_doctor_repair_t;

/* Read-only diagnosis. Returns 0 for any readable image (including non-DJ),
 * -1 on I/O error with a message in err. No writes of any kind. */
int cbm_doctor_report(const char *path, unsigned long long window_gib,
                      cbm_doctor_report_t *out, char *err, size_t errlen);

/* Guarded repair. Returns 0 on success, 1 on runtime refusal/inconsistency,
 * 2 on usage error (alias or missing arguments). Writes only LBA 0 of `path`
 * and the single backup file `backup`, in the fixed verified sequence above. */
int cbm_doctor_repair(const char *path, const char *backup,
                      unsigned long long window_gib,
                      cbm_doctor_repair_t *out, char *err, size_t errlen);

/* Print one deterministic report (header, verdict, statuses and the nominal
 * candidate table) to out. */
void cbm_doctor_print_report(const cbm_doctor_report_t *r, FILE *out);

/* CLI entry: argv[0]=prog, argv[1]="doctor", argv[2]=target, options after.
 * Exit 0 success, 1 runtime/refusal, 2 usage (missing flags or alias). */
int cbm_doctor_cli(int argc, char **argv, FILE *out, FILE *errout);

#endif /* CBM_DOCTOR_H */
