/* cbm_doctor.c - guarded MBR diagnosis and repair (Wave 5D)
 *
 * DIAGNOSIS FIRST: cbm_doctor_report only reads the target and never refuses
 * a readable image. The sole write path is cbm_doctor_repair, which writes
 * exactly one 512-byte sector (LBA 0) and one explicit backup file, and only
 * after every authorisation condition has been met (see cbm_doctor.h).
 */
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cbm_doctor.h"
#include "cbm_file.h"
#include "cbm_layout.h"
#include "cbm_scan_report.h"

#define DJ_DEFAULT_WINDOW_GIB 26ULL
#define GIB_BYTES 1073741824ULL

static int seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
    return -1;
}

static int usageerr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
    return 2;
}

static int target_size(const char *path, unsigned long long *out) {
    struct stat st;
    if (!path || stat(path, &st) != 0 || st.st_size < 0) return -1;
    *out = (unsigned long long)st.st_size;
    return 0;
}

/* The validator requires at least the frozen 28 GiB window; a larger target
 * must not be shrunk into the check. */
static unsigned long long check_sectors(unsigned long long bytes) {
    unsigned long long s = bytes / CBM_SECTOR_SIZE;
    return s > CBM_EXPECTED_WINDOW_SECTORS ? s : CBM_EXPECTED_WINDOW_SECTORS;
}

/* Locale-independent fixed-point GiB with a literal '.', like the JSON writer. */
static void fixed_gib(unsigned long long bytes, char *dst, size_t len) {
    unsigned long long whole = bytes >> 30;
    unsigned long long frac = ((bytes & ((1ULL << 30) - 1ULL)) * 1000000ULL) >> 30;
    snprintf(dst, len, "%llu.%06llu", whole, frac);
}

static int parse_ull(const char *s, unsigned long long *out) {
    char *end = NULL;
    if (!s || !*s) return -1;
    /* strtoull("-1") yields ULLONG_MAX with errno == 0; reject any sign so a
     * negative --window-gib is a usage error (exit 2), never a silent 2^64-1. */
    if (*s == '-' || *s == '+') return -1;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return -1;
    *out = v;
    return 0;
}

static void reason_set(char *reason, size_t len, const char *fmt, ...) {
    if (!reason || !len) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, len, fmt, ap);
    va_end(ap);
}

/* THE SINGLE repair-authorisation predicate (Wave 5D review fix). It implements
 * exactly the frozen clause: repair is allowed when EITHER
 *   (a) the first 512 bytes FAIL cbm_layout_parse (bad/absent 0x55AA signature),
 *       OR
 *   (b) they parse AND are DJ-shaped (exactly three non-empty partition
 *       entries) AND FAIL cbm_layout_validate.
 * A parseable table that is NOT DJ-shaped (e.g. a legitimate foreign single-
 * partition disk) stays REFUSED: the shape test exists so we never silently
 * rewrite a foreign disk's partition table into the nominal DJ layout. An
 * already-valid DJ MBR is also refused (nothing to repair). Window/size
 * preconditions are folded in here too so `repairable` cannot disagree with
 * the repair path's early refusals.
 *
 * Both cbm_doctor_report (for the printed `repairable` verdict) and
 * cbm_doctor_repair (for the write gate) call THIS function. There is no
 * second, divergent copy of the authorisation rule.
 */
static int repair_authorised(const unsigned char *mbr, size_t mbrlen,
                             unsigned long long bytes,
                             unsigned long long window_gib,
                             char *reason, size_t reasonlen) {
    if (window_gib < 26ULL || window_gib > 28ULL) {
        reason_set(reason, reasonlen,
                   "window_gib %llu out of supported range 26..28", window_gib);
        return 0;
    }
    if (bytes < window_gib * GIB_BYTES) {
        reason_set(reason, reasonlen,
                   "target (%llu bytes) is smaller than --window-gib %llu GiB",
                   bytes, window_gib);
        return 0;
    }
    cbm_layout_t L;
    if (cbm_layout_parse(mbr, mbrlen, &L) != 0) {
        reason_set(reason, reasonlen,
                   "invalid MBR signature or unparsable table (clause a)");
        return 1; /* clause (a): unparsable sector may be reconstructed */
    }
    if (L.part_count != 3) {
        reason_set(reason, reasonlen,
                   "parsable non-DJ table with %d partition(s); refusing to "
                   "overwrite a foreign disk", L.part_count);
        return 0; /* parseable but not DJ-shaped -> foreign, refuse */
    }
    if (cbm_layout_validate(&L, check_sectors(bytes)) == 0) {
        reason_set(reason, reasonlen, "first sector is already a valid DJ MBR");
        return 0; /* nothing to repair */
    }
    reason_set(reason, reasonlen, "DJ-shaped table failed layout validation (clause b)");
    return 1; /* clause (b): broken DJ table may be reconstructed */
}

int cbm_doctor_report(const char *path, unsigned long long window_gib,
                      cbm_doctor_report_t *out, char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!path || !out) return seterr(err, errlen, "doctor: path and report required");
    memset(out, 0, sizeof(*out));
    out->window_gib = window_gib;

    unsigned long long bytes = 0;
    if (target_size(path, &bytes) != 0)
        return seterr(err, errlen, "doctor: cannot stat target");
    out->size_bytes = bytes;

    unsigned char mbr[CBM_SECTOR_SIZE];
    if (cbm_file_read(path, 0, mbr, sizeof(mbr)) != 0)
        return seterr(err, errlen, "doctor: cannot read first sector (LBA 0)");

    cbm_layout_t L;
    int parsed = (cbm_layout_parse(mbr, sizeof(mbr), &L) == 0);
    out->mbr_ok = parsed;
    out->part_count = parsed ? L.part_count : 0;
    out->dj_ok = parsed && (cbm_layout_validate(&L, check_sectors(bytes)) == 0);
    out->window_consistent = (window_gib >= 26ULL && window_gib <= 28ULL &&
                              bytes >= window_gib * GIB_BYTES);
    /* ONE shared predicate drives both this verdict and the repair write
     * gate; no input can be reported repairable yet refused (or vice versa). */
    out->repairable = repair_authorised(mbr, sizeof(mbr), bytes, window_gib,
                                       out->repair_reason, sizeof(out->repair_reason));

    /* Always build the nominal candidate, even for a non-DJ source: the
     * printed report shows what a repair WOULD write (never written here). */
    unsigned char cand[CBM_SECTOR_SIZE];
    char cerr[256] = {0};
    if (cbm_layout_construct(window_gib, cand, cerr, sizeof(cerr)) == 0) {
        cbm_layout_t CL;
        if (cbm_layout_parse(cand, sizeof(cand), &CL) == 0 &&
            cbm_layout_validate(&CL, check_sectors(bytes)) == 0) {
            out->candidate_ok = 1;
            memcpy(out->candidate, cand, sizeof(cand));
        }
    }

    if (out->dj_ok)
        snprintf(out->verdict, sizeof(out->verdict), "DJ layout valid");
    else if (out->mbr_ok)
        snprintf(out->verdict, sizeof(out->verdict),
                 "NON-DJ layout (parsable MBR, non-DJ geometry)");
    else
        snprintf(out->verdict, sizeof(out->verdict),
                 "NON-DJ layout (invalid MBR signature or unparsable table)");
    return 0;
}

int cbm_doctor_repair(const char *path, const char *backup,
                      unsigned long long window_gib,
                      cbm_doctor_repair_t *out, char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (out) memset(out, 0, sizeof(*out));
    if (!path || !backup || !out)
        return usageerr(err, errlen, "doctor repair: target, backup and result required");

    /* ONE alias guard, before opening either path. No second guard later. */
    char aerr[512] = {0};
    if (cbm_scan_report_check_output(backup, path, aerr, sizeof(aerr)) != 0) {
        if (err && errlen) snprintf(err, errlen, "backup refused: %s", aerr);
        return 2;
    }

    unsigned long long bytes = 0;
    if (target_size(path, &bytes) != 0)
        return seterr(err, errlen, "doctor repair: cannot stat target");
    if (window_gib < 26ULL || window_gib > 28ULL) {
        if (err && errlen)
            snprintf(err, errlen, "window_gib %llu out of supported range 26..28", window_gib);
        return 1;
    }
    if (bytes < window_gib * GIB_BYTES) {
        if (err && errlen)
            snprintf(err, errlen,
                     "target (%llu bytes) is smaller than --window-gib %llu GiB",
                     bytes, window_gib);
        return 1;
    }

    unsigned char cand[CBM_SECTOR_SIZE];
    char cerr[256] = {0};
    if (cbm_layout_construct(window_gib, cand, cerr, sizeof(cerr)) != 0) {
        if (err && errlen) snprintf(err, errlen, "nominal candidate: %s", cerr);
        return 1;
    }
    cbm_layout_t CL;
    unsigned long long ds = check_sectors(bytes);
    if (cbm_layout_parse(cand, sizeof(cand), &CL) != 0 ||
        cbm_layout_validate(&CL, ds) != 0)
        return seterr(err, errlen, "nominal candidate failed parse/validate; refusing");
    memcpy(out->reconstructed, cand, sizeof(cand));

    unsigned char current[CBM_SECTOR_SIZE];
    if (cbm_file_read(path, 0, current, sizeof(current)) != 0)
        return seterr(err, errlen, "doctor repair: cannot read first sector (LBA 0)");
    memcpy(out->original, current, sizeof(current));
    out->step_read = 1;

    /* ONE shared predicate is the write gate (same one the report used).
     * Parse-failure or DJ-shaped-but-invalid is authorised; a foreign table
     * or an already-valid DJ MBR is refused without touching the target. */
    char areason[256] = {0};
    if (!repair_authorised(current, sizeof(current), bytes, window_gib,
                           areason, sizeof(areason))) {
        if (err && errlen) snprintf(err, errlen, "%s", areason);
        return 1;
    }

    /* Fixed verified sequence. Only LBA 0 of `path` is ever written. */
    if (cbm_file_write(backup, 0, current, sizeof(current)) != 0)
        return seterr(err, errlen, "backup write failed; target untouched");
    out->step_backup_written = 1;

    unsigned char bcheck[CBM_SECTOR_SIZE];
    if (cbm_file_read(backup, 0, bcheck, sizeof(bcheck)) != 0 ||
        memcmp(bcheck, current, sizeof(current)) != 0)
        return seterr(err, errlen, "backup read-back mismatch; target untouched");
    out->step_backup_verified = 1;

    if (cbm_file_write(path, 0, cand, sizeof(cand)) != 0)
        return seterr(err, errlen, "LBA 0 write failed; backup is intact");
    out->step_mbr_written = 1;

    unsigned char readback[CBM_SECTOR_SIZE];
    if (cbm_file_read(path, 0, readback, sizeof(readback)) != 0 ||
        memcmp(readback, cand, sizeof(cand)) != 0) {
        /* Name the backup: it is the only copy of the original sector now. */
        cbm_doctor_readback_error(err, errlen, backup);
        return -1;
    }
    memcpy(out->readback, readback, sizeof(readback));
    out->step_readback_verified = 1;
    return 0;
}

void cbm_doctor_readback_error(char *err, size_t errlen, const char *backup) {
    if (!err || !errlen) return;
    snprintf(err, errlen,
             "LBA 0 read-back verification failed; original sector is in backup %s",
             backup ? backup : "(unknown)");
}

void cbm_doctor_print_steps(const cbm_doctor_repair_t *r, FILE *out, const char *backup) {
    if (!r || !out) return;
    fprintf(out, "Repair: read=%d backup_written=%d backup_verified=%d "
                 "mbr_written=%d readback_verified=%d backup=%s\n",
            r->step_read, r->step_backup_written, r->step_backup_verified,
            r->step_mbr_written, r->step_readback_verified,
            backup ? backup : "(unknown)");
}

void cbm_doctor_print_report(const cbm_doctor_report_t *r, FILE *out) {
    if (!r || !out) return;
    char size[64];
    fixed_gib(r->size_bytes, size, sizeof(size));
    fprintf(out, "CBM Doctor Report\n");
    fprintf(out, "Verdict: %s\n", r->verdict);
    fprintf(out, "MBR=%s DJ=%s window=%llu GiB size=%s GiB\n",
            r->mbr_ok ? "VALID" : "INVALID", r->dj_ok ? "VALID" : "INVALID",
            r->window_gib, size);
    fprintf(out, "Window consistent: %s\n", r->window_consistent ? "yes" : "no");
    fprintf(out, "Repairable: %s (%s)\n", r->repairable ? "yes" : "no",
            r->repair_reason[0] ? r->repair_reason : "not repairable");
    fprintf(out, "nominal reconstruction (candidate valid=%s):\n",
            r->candidate_ok ? "yes" : "no");
    cbm_layout_t L;
    if (cbm_layout_parse(r->candidate, CBM_SECTOR_SIZE, &L) == 0) {
        static const char *names[4] = {"DJ_BOOT", "DJ_OS", "DJ_DATA", "PART3"};
        for (int i = 0; i < L.part_count && i < 4; i++)
            fprintf(out, "PART %s start=%llu size=%llu type=0x%02x\n",
                    names[i], L.parts[i].start_lba, L.parts[i].size_lba,
                    L.parts[i].type);
    }
}

int cbm_doctor_cli(int argc, char **argv, FILE *out, FILE *errout) {
    FILE *o = out ? out : stdout;
    FILE *e = errout ? errout : stderr;
    char err[512] = {0};
    if (!argv || argc < 3 || !argv[2] || !argv[2][0]) {
        fprintf(e, "Usage: cbm-tool doctor <device|image> [--repair-mbr --yes "
                   "--backup <file>] [--window-gib 26|27|28]\n");
        return 2;
    }
    const char *path = argv[2];
    int do_repair = 0, do_yes = 0;
    const char *backup = NULL;
    unsigned long long window_gib = DJ_DEFAULT_WINDOW_GIB;

    for (int i = 3; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--repair-mbr") == 0) {
            do_repair = 1;
        } else if (strcmp(a, "--yes") == 0) {
            do_yes = 1;
        } else if (strcmp(a, "--backup") == 0) {
            if (++i >= argc || !argv[i][0]) {
                fprintf(e, "Error: --backup requires a file path\n");
                return 2;
            }
            backup = argv[i];
        } else if (strcmp(a, "--window-gib") == 0) {
            if (++i >= argc) {
                fprintf(e, "Error: --window-gib requires a non-negative integer\n");
                return 2;
            }
            if (parse_ull(argv[i], &window_gib) != 0) {
                fprintf(e, "Error: --window-gib requires a non-negative integer (got '%s')\n",
                        argv[i]);
                return 2;
            }
        } else {
            fprintf(e, "Error: unknown doctor option '%s'\n", a);
            return 2;
        }
    }

    /* All-or-nothing authorisation: any repair flag without the full trio is
     * a usage error, and nothing is written. */
    if (!do_repair) {
        if (do_yes || backup) {
            fprintf(e, "Error: --yes/--backup require --repair-mbr\n");
            return 2;
        }
        cbm_doctor_report_t r;
        if (cbm_doctor_report(path, window_gib, &r, err, sizeof(err)) != 0) {
            fprintf(e, "Error: %s\n", err);
            return 1;
        }
        cbm_doctor_print_report(&r, o);
        fprintf(o, "Dry run: no writes (read-only default).\n");
        return 0;
    }
    if (!do_yes || !backup) {
        fprintf(e, "Error: --repair-mbr requires both --yes and --backup <file>\n");
        return 2;
    }

    cbm_doctor_repair_t rep;
    int rc = cbm_doctor_repair(path, backup, window_gib, &rep, err, sizeof(err));
    if (rc == 2) {
        fprintf(e, "Error: %s\n", err);
        return 2;
    }
    if (rc != 0) {
        fprintf(e, "Refused: %s\n", err);
        cbm_doctor_print_steps(&rep, e, backup);
        return 1;
    }

    cbm_doctor_report_t r;
    if (cbm_doctor_report(path, window_gib, &r, err, sizeof(err)) == 0)
        cbm_doctor_print_report(&r, o);
    fprintf(o, "Repair: read=%d backup_written=%d backup_verified=%d "
              "mbr_written=%d readback_verified=%d backup=%s\n",
            rep.step_read, rep.step_backup_written, rep.step_backup_verified,
            rep.step_mbr_written, rep.step_readback_verified, backup);
    return 0;
}
