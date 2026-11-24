/* cbm_doctor.h - guarded MBR diagnosis and repair (Wave 5D)
 *
 * `doctor` is a DIAGNOSIS tool first. cbm_doctor_report only reads the target;
 * it never opens it for writing and never refuses a readable image. The sole
 * write path is cbm_doctor_repair, which writes exactly one 512-byte sector
 * (LBA 0) after every authorisation condition is met:
 *   - explicit --repair-mbr + --yes + --backup at the CLI layer;
 *   - backup path pre-flighted with the shared cbm_scan_report_check_output
 *     guard before either path is opened, then re-checked immediately before
 *     the backup write and claimed with an O_EXCL|O_NOFOLLOW file descriptor
 *     whose inode is compared with the target's read-only descriptor;
 *   - the nominal candidate must pass cbm_layout_parse + cbm_layout_validate;
 *   - the shared repair_authorised() predicate must agree: either the first
 *     512 bytes fail cbm_layout_parse, OR they parse and are DJ-shaped
 *     (exactly three non-empty entries) but fail cbm_layout_validate. A
 *     parseable non-DJ (foreign) table and an already-valid DJ MBR are both
 *     refused. The report derives its `repairable` field from this SAME
 *     predicate, so diagnosis and repair can never disagree.
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
    int repairable;         /* SAME predicate the repair path gates on */
    int part_count;         /* partitions found in the current first sector */
    unsigned long long size_bytes;
    unsigned long long window_gib;
    unsigned char candidate[CBM_SECTOR_SIZE]; /* nominal reconstruction */
    char repair_reason[192]; /* why repairable is yes/no; always non-empty */
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

/* Print one deterministic report (header, verdict, statuses, the repairability
 * verdict and the nominal candidate table) to out. */
void cbm_doctor_print_report(const cbm_doctor_report_t *r, FILE *out);

/* Format the LBA-0 read-back failure message. Always names the backup path so
 * the original sector is recoverable; public for deterministic tests. */
void cbm_doctor_readback_error(char *err, size_t errlen, const char *backup);

/* Exact CLI error prefix for a repair failure. rc == -1 means LBA 0 was
 * already overwritten and only read-back verification failed; rc == 1 is a
 * refusal before the target write. Public so the distinction is testable. */
const char *cbm_doctor_failure_prefix(int rc);

/* Print the full repair step struct (all five step flags plus the backup path)
 * to out. The CLI calls this on EVERY repair failure so the operator can see
 * exactly which step completed and where the original sector was saved. */
void cbm_doctor_print_steps(const cbm_doctor_repair_t *r, FILE *out, const char *backup);

/* CLI entry: argv[0]=prog, argv[1]="doctor", argv[2]=target, options after.
 * Exit 0 success, 1 runtime/refusal, 2 usage (missing flags or alias). */
int cbm_doctor_cli(int argc, char **argv, FILE *out, FILE *errout);

/* Same CLI with an optional compact-JSON success object target. json_out NULL
 * keeps the prose-only behaviour; a non-NULL stream receives one object on
 * success (doctor is the layout JSON surface: no separate layout command). */
int cbm_doctor_cli_ex(int argc, char **argv, FILE *out, FILE *errout,
                      FILE *json_out);

#endif /* CBM_DOCTOR_H */
