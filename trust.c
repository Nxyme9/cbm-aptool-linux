/* trust.c - BadUSB trust scanner (wave 5P)
 *
 * Host-observable fingerprint comparison only. The scanner never opens the
 * device for I/O: a block device is observed through read-only sysfs
 * attributes, and an observation JSON can be supplied instead (that is what
 * the tests use, so no device is required).
 *
 * Nothing here reads or attests firmware. Findings are descriptor-level and
 * are labelled host-observable; a firmware claim is refused unless a real
 * dump supplied a marker.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>

#include "trust.h"
#include "cli_json.h"
#include "cbm_file.h"

#define TRUST_FILE_MAX (1024u * 1024u)

static void set_err(char *err, size_t errlen, const char *fmt, ...) {
    va_list ap;
    if (!err || errlen == 0) return;
    va_start(ap, fmt);
    (void)vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

void trust_zero(trust_profile_t *p) {
    if (p) memset(p, 0, sizeof *p);
}

/* ---- minimal JSON reader (flat schema, bounded) ----------------------- */

static const char *skip_ws(const char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

/* Return the value that follows a top-level "key". Depth-aware, so a nested
 * key with the same name cannot shadow the top-level one. */
static const char *find_top_key(const char *json, const char *key) {
    size_t klen = strlen(key);
    int depth = 0;
    const char *p = json;

    while (p && *p) {
        if (*p == '{' || *p == '[') { depth++; p++; continue; }
        if (*p == '}' || *p == ']') { depth--; p++; continue; }
        if (*p == '"') {
            const char *start = ++p;
            while (*p && *p != '"') {
                if (*p == '\\' && p[1]) p++;
                p++;
            }
            if (*p == '"') {
                size_t len = (size_t)(p - start);
                const char *after;
                p++;
                after = skip_ws(p);
                if (depth == 1 && *after == ':' && len == klen &&
                    strncmp(start, key, klen) == 0)
                    return skip_ws(after + 1);
            }
            continue;
        }
        p++;
    }
    return NULL;
}

static int parse_uint_at(const char *v, unsigned long max, unsigned *out) {
    char *end = NULL;
    unsigned long n;
    int base = 10;
    int quoted = 0;

    if (!v) return -1;
    v = skip_ws(v);
    if (*v == '"') { quoted = 1; v++; }
    if (v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) { base = 16; v += 2; }
    if (!isxdigit((unsigned char)v[0])) return -1;
    errno = 0;
    n = strtoul(v, &end, base);
    if (errno != 0 || end == v || n > max) return -1;
    if (quoted) {
        if (*end != '"') return -1;
        end++;
    }
    end = (char *)skip_ws(end);
    if (*end != ',' && *end != '}' && *end != ']') return -1;
    *out = (unsigned)n;
    return 0;
}

static int parse_string_at(const char *v, char *out, size_t cap) {
    size_t n = 0;

    if (!v || *v != '"') return -1;
    v++;
    while (*v && *v != '"') {
        unsigned char c = (unsigned char)*v++;
        if (c == '\\') {
            char e = *v++;
            switch (e) {
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            default: return -1;
            }
        }
        if (c < 0x20u) return -1;
        if (n + 1u >= cap) return -1;
        out[n++] = (char)c;
    }
    if (*v != '"') return -1;
    out[n] = '\0';
    return 0;
}

static int parse_iface_array(const char *v, trust_profile_t *p) {
    if (!v) return 0;
    if (*v != '[') return -1;
    v++;
    for (;;) {
        const char *end;
        char obj[256];
        size_t len;
        unsigned cls, sub, proto;

        v = skip_ws(v);
        if (*v == ']') return 0;
        if (*v != '{') return -1;
        end = v + 1;
        while (*end && *end != '}') {
            if (*end == '{' || *end == '[') return -1;
            end++;
        }
        if (*end != '}') return -1;
        len = (size_t)(end - v + 1);
        if (len >= sizeof obj) return -1;
        memcpy(obj, v, len);
        obj[len] = '\0';
        if (parse_uint_at(find_top_key(obj, "class"), 255u, &cls) != 0) return -1;
        if (parse_uint_at(find_top_key(obj, "subclass"), 255u, &sub) != 0) return -1;
        if (parse_uint_at(find_top_key(obj, "protocol"), 255u, &proto) != 0) return -1;
        if (p->nifaces >= TRUST_MAX_IFACES) return -1;
        p->ifaces[p->nifaces].cls = (unsigned char)cls;
        p->ifaces[p->nifaces].subcls = (unsigned char)sub;
        p->ifaces[p->nifaces].proto = (unsigned char)proto;
        p->nifaces++;
        v = skip_ws(end + 1);
        if (*v == ',') { v++; continue; }
        if (*v == ']') return 0;
        return -1;
    }
}

static int parse_cdb_string(const char *s, unsigned char *out, size_t *outlen) {
    size_t n = 0;
    while (*s) {
        char b[3];
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        if (!isxdigit((unsigned char)s[0]) || !isxdigit((unsigned char)s[1]))
            return -1;
        b[0] = s[0];
        b[1] = s[1];
        b[2] = '\0';
        if (n >= TRUST_CDB_LEN) return -1;
        out[n++] = (unsigned char)strtoul(b, NULL, 16);
        s += 2;
    }
    if (n == 0) return -1;
    *outlen = n;
    return 0;
}

static int parse_cdb_array(const char *v, trust_profile_t *p) {
    if (!v) return 0;
    if (*v != '[') return -1;
    v++;
    for (;;) {
        const char *start, *end;
        char text[TRUST_CDB_LEN * 3 + 2];
        size_t len;
        unsigned char bytes[TRUST_CDB_LEN];
        size_t nbytes = 0;

        v = skip_ws(v);
        if (*v == ']') return 0;
        if (*v != '"') return -1;
        start = v + 1;
        end = start;
        while (*end && *end != '"') {
            if (*end == '\\') return -1;
            end++;
        }
        if (*end != '"') return -1;
        len = (size_t)(end - start);
        if (len >= sizeof text) return -1;
        memcpy(text, start, len);
        text[len] = '\0';
        if (parse_cdb_string(text, bytes, &nbytes) != 0) return -1;
        if (p->ncdbs >= TRUST_MAX_CDBS) return -1;
        memset(p->cdbs[p->ncdbs], 0, TRUST_CDB_LEN);
        memcpy(p->cdbs[p->ncdbs], bytes, nbytes);
        p->cdb_len[p->ncdbs] = nbytes;
        p->ncdbs++;
        v = skip_ws(end + 1);
        if (*v == ',') { v++; continue; }
        if (*v == ']') return 0;
        return -1;
    }
}

int trust_parse_profile(const char *text, trust_profile_t *p,
                        char *err, size_t errlen) {
    const char *v;
    unsigned vid, pid;

    if (!text || !p) {
        set_err(err, errlen, "profile text is required");
        return TRUST_ERR_ARG;
    }
    trust_zero(p);
    if (!find_top_key(text, "vid") || !find_top_key(text, "pid")) {
        set_err(err, errlen, "profile needs both \"vid\" and \"pid\"");
        return TRUST_ERR_FORMAT;
    }
    if (parse_uint_at(find_top_key(text, "vid"), 0xffffu, &vid) != 0 ||
        parse_uint_at(find_top_key(text, "pid"), 0xffffu, &pid) != 0) {
        set_err(err, errlen, "\"vid\"/\"pid\" must be 16-bit numbers");
        return TRUST_ERR_FORMAT;
    }
    p->vid = vid;
    p->pid = pid;

    v = find_top_key(text, "product");
    if (v && parse_string_at(v, p->product, sizeof p->product) != 0) {
        set_err(err, errlen, "\"product\" must be a bounded string");
        return TRUST_ERR_FORMAT;
    }
    if (parse_iface_array(find_top_key(text, "interfaces"), p) != 0) {
        set_err(err, errlen, "\"interfaces\" must be an array of "
                             "class/subclass/protocol objects");
        return TRUST_ERR_FORMAT;
    }
    if (parse_cdb_array(find_top_key(text, "cdbs"), p) != 0) {
        set_err(err, errlen, "\"cdbs\" must be an array of hex byte strings "
                             "(max 16 bytes each)");
        return TRUST_ERR_FORMAT;
    }
    v = find_top_key(text, "firmware_marker");
    if (v && *v == '"') {
        if (parse_string_at(v, p->fw_marker, sizeof p->fw_marker) != 0) {
            set_err(err, errlen, "\"firmware_marker\" must be null or a "
                                 "bounded string");
            return TRUST_ERR_FORMAT;
        }
        p->has_fw_marker = 1;
    }
    /* "serial" is deliberately ignored: baselines store redacted serials. */
    return TRUST_OK;
}

int trust_load_profile(const char *path, trust_profile_t *p,
                       char *err, size_t errlen) {
    FILE *f;
    long sz;
    char *buf;
    int rc;

    if (!path || !path[0] || !p) {
        set_err(err, errlen, "profile path is required");
        return TRUST_ERR_ARG;
    }
    trust_zero(p);
    f = fopen(path, "rb");
    if (!f) {
        set_err(err, errlen, "cannot open '%s': %s", path, strerror(errno));
        return TRUST_ERR_IO;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
        (unsigned long)sz > TRUST_FILE_MAX || fseek(f, 0, SEEK_SET) != 0) {
        (void)fclose(f);
        set_err(err, errlen, "'%s' is not a readable profile (max %u bytes)",
                path, (unsigned)TRUST_FILE_MAX);
        return TRUST_ERR_IO;
    }
    buf = (char *)malloc((size_t)sz + 1u);
    if (!buf) {
        (void)fclose(f);
        set_err(err, errlen, "out of memory");
        return TRUST_ERR_IO;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        (void)fclose(f);
        set_err(err, errlen, "short read from '%s'", path);
        return TRUST_ERR_IO;
    }
    buf[sz] = '\0';
    (void)fclose(f);
    rc = trust_parse_profile(buf, p, err, errlen);
    free(buf);
    return rc;
}

/* ---- comparison ------------------------------------------------------- */

static void add_finding(trust_report_t *r, trust_severity_t sev,
                        const char *code, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static void add_finding(trust_report_t *r, trust_severity_t sev,
                        const char *code, const char *fmt, ...) {
    trust_finding_t *f;
    va_list ap;

    if (r->count >= TRUST_MAX_FINDINGS) {
        r->truncated = 1;
        return;
    }
    f = &r->items[r->count++];
    f->severity = sev;
    (void)snprintf(f->code, sizeof f->code, "%s", code);
    va_start(ap, fmt);
    (void)vsnprintf(f->detail, sizeof f->detail, fmt, ap);
    va_end(ap);
    if (sev == TRUST_SEV_CRIT) r->crit++;
    else if (sev == TRUST_SEV_WARN) r->warn++;
    else r->info++;
}

static int iface_present(const trust_profile_t *p, const trust_iface_t *i) {
    for (size_t k = 0; k < p->nifaces; k++)
        if (p->ifaces[k].cls == i->cls && p->ifaces[k].subcls == i->subcls &&
            p->ifaces[k].proto == i->proto)
            return 1;
    return 0;
}

static int cdb_present(const trust_profile_t *p, const unsigned char *cdb,
                       size_t len) {
    for (size_t k = 0; k < p->ncdbs; k++)
        if (p->cdb_len[k] == len && memcmp(p->cdbs[k], cdb, len) == 0)
            return 1;
    return 0;
}

int trust_compare(const trust_profile_t *baseline,
                  const trust_profile_t *observed, trust_report_t *r,
                  char *err, size_t errlen) {
    if (!baseline || !observed || !r) {
        set_err(err, errlen, "baseline, observation and report are required");
        return TRUST_ERR_ARG;
    }
    memset(r, 0, sizeof *r);

    if (baseline->vid != observed->vid || baseline->pid != observed->pid)
        add_finding(r, TRUST_SEV_CRIT, "usb-id",
                    "VID/PID %04x:%04x -> %04x:%04x",
                    baseline->vid, baseline->pid,
                    observed->vid, observed->pid);

    if (baseline->product[0] && observed->product[0] &&
        strcmp(baseline->product, observed->product) != 0)
        add_finding(r, TRUST_SEV_WARN, "product",
                    "product '%s' -> '%s'",
                    baseline->product, observed->product);

    for (size_t i = 0; i < baseline->nifaces; i++)
        if (!iface_present(observed, &baseline->ifaces[i]))
            add_finding(r, TRUST_SEV_WARN, "iface-missing",
                        "baseline interface %u/%u/%u is absent",
                        (unsigned)baseline->ifaces[i].cls,
                        (unsigned)baseline->ifaces[i].subcls,
                        (unsigned)baseline->ifaces[i].proto);

    for (size_t i = 0; i < observed->nifaces; i++) {
        const trust_iface_t *o = &observed->ifaces[i];
        if (iface_present(baseline, o)) continue;
        if (o->cls == 3)
            add_finding(r, TRUST_SEV_CRIT, "iface-extra-hid",
                        "unexpected HID interface %u/%u/%u",
                        (unsigned)o->cls, (unsigned)o->subcls,
                        (unsigned)o->proto);
        else
            add_finding(r, TRUST_SEV_WARN, "iface-extra",
                        "unexpected interface %u/%u/%u",
                        (unsigned)o->cls, (unsigned)o->subcls,
                        (unsigned)o->proto);
    }

    for (size_t i = 0; i < observed->ncdbs; i++)
        if (!cdb_present(baseline, observed->cdbs[i], observed->cdb_len[i]))
            add_finding(r, TRUST_SEV_WARN, "cdb-unknown",
                        "observed CDB %02x %02x ... (%zu bytes) is not in "
                        "the baseline",
                        (unsigned)observed->cdbs[i][0],
                        observed->cdb_len[i] > 1
                            ? (unsigned)observed->cdbs[i][1] : 0u,
                        observed->cdb_len[i]);

    if (observed->ncdbs == 0)
        add_finding(r, TRUST_SEV_INFO, "cdb-not-observed",
                    "no CDB behaviour supplied; run cdb-capture against your "
                    "own PE and pass the result as an observation");

    if (observed->has_fw_marker &&
        (!baseline->has_fw_marker ||
         strcmp(baseline->fw_marker, observed->fw_marker) != 0))
        add_finding(r, TRUST_SEV_WARN, "fw-marker-changed",
                    "firmware marker '%s' is not the baseline marker",
                    observed->fw_marker);
    else
        add_finding(r, TRUST_SEV_INFO, "fw-unverified",
                    "no firmware dump; every finding above is "
                    "host-observable only");

    return TRUST_OK;
}

/* ---- read-only sysfs observation -------------------------------------- */

static int read_text(const char *path, char *buf, size_t cap) {
    FILE *f;
    size_t n;

    if (!path || !buf || cap == 0) return -1;
    f = fopen(path, "r");
    if (!f) return -1;
    n = fread(buf, 1, cap - 1u, f);
    (void)fclose(f);
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' ' || buf[n - 1] == '\t'))
        buf[--n] = '\0';
    return n > 0 ? 0 : -1;
}

int trust_observe_sysfs(const char *device, trust_profile_t *p,
                        char *err, size_t errlen) {
    char base[256], link[PATH_MAX], dir[PATH_MAX], tmp[PATH_MAX + 320];
    char buf[TRUST_STR];
    const char *b;
    DIR *d;
    struct dirent *de;
    int found = 0;

    if (!device || !device[0] || !p) {
        set_err(err, errlen, "device path is required");
        return TRUST_ERR_ARG;
    }
    trust_zero(p);
    b = strrchr(device, '/');
    b = b ? b + 1 : device;
    if (strlen(b) >= sizeof base) {
        set_err(err, errlen, "device name is too long");
        return TRUST_ERR_ARG;
    }
    (void)snprintf(base, sizeof base, "%s", b);
    (void)snprintf(link, sizeof link, "/sys/class/block/%s/device", base);
    if (!realpath(link, dir)) {
        set_err(err, errlen,
                "cannot resolve sysfs USB path for '%s' (not a USB block "
                "device?); pass an observation JSON instead", device);
        return TRUST_ERR_IO;
    }
    for (int i = 0; i < 8; i++) {
        char *slash;
        (void)snprintf(tmp, sizeof tmp, "%s/idVendor", dir);
        if (access(tmp, R_OK) == 0) { found = 1; break; }
        slash = strrchr(dir, '/');
        if (!slash || slash == dir) break;
        *slash = '\0';
    }
    if (!found) {
        set_err(err, errlen,
                "no USB descriptor attributes above '%s'; pass an "
                "observation JSON instead", device);
        return TRUST_ERR_IO;
    }
    (void)snprintf(tmp, sizeof tmp, "%s/idVendor", dir);
    if (read_text(tmp, buf, sizeof buf) != 0) {
        set_err(err, errlen, "cannot read idVendor for '%s'", device);
        return TRUST_ERR_IO;
    }
    p->vid = (unsigned)strtoul(buf, NULL, 16);
    (void)snprintf(tmp, sizeof tmp, "%s/idProduct", dir);
    if (read_text(tmp, buf, sizeof buf) != 0) {
        set_err(err, errlen, "cannot read idProduct for '%s'", device);
        return TRUST_ERR_IO;
    }
    p->pid = (unsigned)strtoul(buf, NULL, 16);
    (void)snprintf(tmp, sizeof tmp, "%s/product", dir);
    if (read_text(tmp, p->product, sizeof p->product) != 0)
        p->product[0] = '\0';

    d = opendir(dir);
    if (!d) {
        set_err(err, errlen, "cannot list '%s'", dir);
        return TRUST_ERR_IO;
    }
    while ((de = readdir(d)) != NULL) {
        unsigned cls = 0, sub = 0, proto = 0;
        if (de->d_name[0] == '.' || !strchr(de->d_name, ':')) continue;
        if (p->nifaces >= TRUST_MAX_IFACES) break;
        (void)snprintf(tmp, sizeof tmp, "%s/%s/bInterfaceClass",
                       dir, de->d_name);
        if (read_text(tmp, buf, sizeof buf) != 0) continue;
        cls = (unsigned)strtoul(buf, NULL, 16);
        (void)snprintf(tmp, sizeof tmp, "%s/%s/bInterfaceSubClass",
                       dir, de->d_name);
        if (read_text(tmp, buf, sizeof buf) == 0)
            sub = (unsigned)strtoul(buf, NULL, 16);
        (void)snprintf(tmp, sizeof tmp, "%s/%s/bInterfaceProtocol",
                       dir, de->d_name);
        if (read_text(tmp, buf, sizeof buf) == 0)
            proto = (unsigned)strtoul(buf, NULL, 16);
        p->ifaces[p->nifaces].cls = (unsigned char)cls;
        p->ifaces[p->nifaces].subcls = (unsigned char)sub;
        p->ifaces[p->nifaces].proto = (unsigned char)proto;
        p->nifaces++;
    }
    (void)closedir(d);
    return TRUST_OK;
}

/* ---- CLI -------------------------------------------------------------- */

static void trust_usage(FILE *err, const char *prog) {
    if (!err) return;
    fprintf(err,
        "Usage: %s trust <device|observation.json> --baseline <json> [--json]\n"
        "Compares a host-observable USB fingerprint against a known-good\n"
        "baseline and reports each mismatch with a severity.\n"
        "  --baseline <json>   required; without it the scan fails closed\n"
        "Observation JSON keys: vid, pid, product, interfaces[], cdbs[],\n"
        "firmware_marker. Serials are never stored or compared.\n"
        "Findings are host-observable descriptors only; no firmware claim is\n"
        "made unless a real dump supplied a marker.\n",
        prog ? prog : "cbm-tool");
}

static const char *sev_name(trust_severity_t sev) {
    switch (sev) {
    case TRUST_SEV_CRIT: return "critical";
    case TRUST_SEV_WARN: return "warning";
    default: return "info";
    }
}

static void emit_json(FILE *json, const char *target, const char *baseline,
                      const trust_report_t *r, int trusted) {
    cbm_json_t j;

    if (!json) return;
    cbm_json_object_begin(&j, json, "trust", "ok");
    cbm_json_field_string(&j, "target", target);
    cbm_json_field_string(&j, "baseline", baseline);
    cbm_json_field_string(&j, "verdict", trusted ? "trusted" : "suspect");
    cbm_json_field_u64(&j, "critical", (unsigned long long)r->crit);
    cbm_json_field_u64(&j, "warning", (unsigned long long)r->warn);
    cbm_json_field_u64(&j, "info", (unsigned long long)r->info);
    cbm_json_field_string(&j, "firmware_claim",
                          "none (host-observable descriptors only)");
    cbm_json_array_begin(&j, "findings");
    for (size_t i = 0; i < r->count; i++) {
        cbm_json_element_object(&j);
        cbm_json_field_string(&j, "severity", sev_name(r->items[i].severity));
        cbm_json_field_string(&j, "code", r->items[i].code);
        cbm_json_field_string(&j, "detail", r->items[i].detail);
        cbm_json_object_end(&j);
    }
    cbm_json_array_end(&j);
    cbm_json_end(&j);
}

int trust_cli_ex(int argc, char **argv, FILE *out, FILE *err, FILE *json) {
    const char *target = NULL, *baseline_path = NULL;
    trust_profile_t baseline, observed;
    trust_report_t report;
    char msg[192];
    int rc, trusted;

    if (argc < 3) {
        trust_usage(err, argc > 0 ? argv[0] : NULL);
        return 2;
    }
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--baseline") == 0) {
            if (i + 1 >= argc) {
                if (err) fprintf(err, "Error: --baseline needs a path\n");
                return 2;
            }
            baseline_path = argv[++i];
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            if (err) fprintf(err, "Error: unknown trust option '%s'\n", argv[i]);
            trust_usage(err, argv[0]);
            return 2;
        } else if (!target) {
            target = argv[i];
        } else {
            if (err) fprintf(err, "Error: too many arguments for trust\n");
            trust_usage(err, argv[0]);
            return 2;
        }
    }
    if (!target) {
        trust_usage(err, argv[0]);
        return 2;
    }
    if (!baseline_path) {
        if (err)
            fprintf(err, "Error: --baseline <json> is required; refusing to "
                         "certify without a known-good profile (fail closed)\n");
        return 1;
    }

    rc = trust_load_profile(baseline_path, &baseline, msg, sizeof msg);
    if (rc != TRUST_OK) {
        if (err) fprintf(err, "Error: baseline: %s\n", msg);
        return 1;
    }
    if (cbm_file_is_blockdev(target))
        rc = trust_observe_sysfs(target, &observed, msg, sizeof msg);
    else
        rc = trust_load_profile(target, &observed, msg, sizeof msg);
    if (rc != TRUST_OK) {
        if (err) fprintf(err, "Error: observation: %s\n", msg);
        return 1;
    }
    rc = trust_compare(&baseline, &observed, &report, msg, sizeof msg);
    if (rc != TRUST_OK) {
        if (err) fprintf(err, "Error: %s\n", msg);
        return 1;
    }
    trusted = (report.crit == 0 && report.warn == 0);

    emit_json(json, target, baseline_path, &report, trusted);
    if (out) {
        fprintf(out, "trust: target=%s baseline=%s\n", target, baseline_path);
        for (size_t i = 0; i < report.count; i++)
            fprintf(out, "  [%s] %s: %s\n",
                    sev_name(report.items[i].severity),
                    report.items[i].code, report.items[i].detail);
        if (report.truncated)
            fprintf(out, "  (further findings suppressed at %d)\n",
                    TRUST_MAX_FINDINGS);
        fprintf(out, "trust: verdict=%s (%zu critical, %zu warning, "
                     "%zu info; host-observable descriptors only)\n",
                trusted ? "TRUSTED" : "SUSPECT",
                report.crit, report.warn, report.info);
    }
    return trusted ? 0 : 1;
}
