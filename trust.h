/* trust.h - BadUSB trust scanner (wave 5P)
 *
 * Compares an observed USB mass-storage fingerprint against a known-good
 * baseline and reports every mismatch with a severity. Observations are
 * host-observable descriptors (VID/PID, product, interface list) plus any CDB
 * behaviour captured by wave 5E; nothing here inspects firmware. A firmware
 * claim is refused unless a real dump exists.
 *
 * Baseline and observation files use the same small JSON schema:
 *   {
 *     "vid": "0x1234", "pid": "0x5678",
 *     "product": "Chipsbank USB Disk",
 *     "serial": "REDACTED",              // parsed but never stored or compared
 *     "interfaces": [ {"class": 8, "subclass": 6, "protocol": 80} ],
 *     "cdbs": ["28 00 00 00 00 00 00 00 10 00"],
 *     "firmware_marker": null            // or a string when a dump exists
 *   }
 */
#ifndef TRUST_H
#define TRUST_H

#include <stddef.h>
#include <stdio.h>

#define TRUST_MAX_IFACES 16
#define TRUST_MAX_CDBS 32
#define TRUST_CDB_LEN 16
#define TRUST_MAX_FINDINGS 64
#define TRUST_STR 64

typedef enum {
    TRUST_OK = 0,
    TRUST_ERR_ARG = 1,
    TRUST_ERR_IO = 2,
    TRUST_ERR_FORMAT = 3,
    TRUST_ERR_NO_BASELINE = 4
} trust_status_t;

typedef enum {
    TRUST_SEV_INFO = 0,
    TRUST_SEV_WARN = 1,
    TRUST_SEV_CRIT = 2
} trust_severity_t;

typedef struct {
    unsigned char cls;
    unsigned char subcls;
    unsigned char proto;
} trust_iface_t;

typedef struct {
    unsigned vid;
    unsigned pid;
    char product[TRUST_STR];
    trust_iface_t ifaces[TRUST_MAX_IFACES];
    size_t nifaces;
    unsigned char cdbs[TRUST_MAX_CDBS][TRUST_CDB_LEN];
    size_t cdb_len[TRUST_MAX_CDBS];
    size_t ncdbs;
    int has_fw_marker;
    char fw_marker[TRUST_STR];
} trust_profile_t;

typedef struct {
    trust_severity_t severity;
    char code[24];
    char detail[160];
} trust_finding_t;

typedef struct {
    trust_finding_t items[TRUST_MAX_FINDINGS];
    size_t count;
    size_t crit;
    size_t warn;
    size_t info;
    int truncated;
} trust_report_t;

void trust_zero(trust_profile_t *p);

/* Parse one profile from bounded JSON text. Unknown keys are ignored; a
 * missing vid/pid or a malformed value is TRUST_ERR_FORMAT. */
int trust_parse_profile(const char *text, trust_profile_t *p,
                        char *err, size_t errlen);

/* Read and parse a baseline/observation file (capped at 1 MiB). */
int trust_load_profile(const char *path, trust_profile_t *p,
                       char *err, size_t errlen);

/* Compare observed against baseline; findings are appended in a stable order
 * (identity, product, interfaces, CDBs, firmware claim). */
int trust_compare(const trust_profile_t *baseline,
                  const trust_profile_t *observed, trust_report_t *r,
                  char *err, size_t errlen);

/* Read-only sysfs observation for a USB block device. Never opens the device
 * for I/O. CDB behaviour and firmware markers are not observable here. */
int trust_observe_sysfs(const char *device, trust_profile_t *p,
                        char *err, size_t errlen);

/* CLI: cbm-tool trust <device|observation.json> --baseline <json> [--json]
 * Exit 0 = trusted, 1 = findings or fail-closed error, 2 = usage error.
 * Errors go to `err`; main.c emits the cbm/1 error document. */
int trust_cli_ex(int argc, char **argv, FILE *out, FILE *err, FILE *json);

#endif /* TRUST_H */
