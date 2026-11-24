/* cbm_scan_report.c - deterministic JSON reports and container carving
 * for the read-only forensic scanner. See cbm_scan_report.h for contracts.
 *
 * The scanned image/device is opened read-only by cbm_file_read only. Every
 * write goes through stdio to an explicit --json/--carve path that has first
 * been checked against the source (realpath string match or st_dev/st_ino).
 * No printf floating conversion is used: entropy is integer fixed-point text
 * with a literal '.', so LC_NUMERIC cannot introduce a comma separator.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cbm_container.h"
#include "cbm_file.h"

#include "cbm_scan_report.h"

static int seterr(char *err, size_t errlen, const char *fmt, ...) {
    if (err && errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* Integer fixed-point text, identical to cbm_scan_print's scaling. Values
 * come from cbm_decode_entropy; no entropy math is duplicated here. */
static unsigned entropy_scaled(double value) {
    if (!(value > 0.0)) return 0u;
    if (value >= 8.0) return 8000000u;
    return (unsigned)(value * 1000000.0 + 0.5);
}

/* Write a bounded, JSON-escaped string. Token buffers are char[64] and are
 * NUL-terminated by the scanner, but the bound protects against a caller
 * passing an unterminated buffer. */
static int json_string(FILE *f, const char *s, size_t max) {
    if (fputc('"', f) == EOF) return -1;
    for (size_t i = 0; i < max && s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  if (fputs("\\\"", f) == EOF) return -1; break;
        case '\\': if (fputs("\\\\", f) == EOF) return -1; break;
        case '\b': if (fputs("\\b", f) == EOF) return -1; break;
        case '\f': if (fputs("\\f", f) == EOF) return -1; break;
        case '\n': if (fputs("\\n", f) == EOF) return -1; break;
        case '\r': if (fputs("\\r", f) == EOF) return -1; break;
        case '\t': if (fputs("\\t", f) == EOF) return -1; break;
        default:
            if (c < 0x20u || c == 0x7fu) {
                if (fprintf(f, "\\u%04x", (unsigned)c) < 0) return -1;
            } else if (fputc((int)c, f) == EOF) {
                return -1;
            }
        }
    }
    return (fputc('"', f) == EOF) ? -1 : 0;
}

int cbm_scan_write_json(const char *path, const cbm_scan_hit_t *hits,
                        size_t n, char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!path || !path[0] || (!hits && n > 0))
        return seterr(err, errlen, "path and hits are required");
    if (cbm_file_is_blockdev(path))
        return seterr(err, errlen, "JSON report must not be a block device: '%s'", path);

    FILE *f = fopen(path, "wb");
    if (!f)
        return seterr(err, errlen, "cannot open JSON report '%s': %s",
                      path, strerror(errno));

    int rc = -1;
    if (n == 0) {
        if (fputs("[]\n", f) != EOF) rc = 0;
    } else {
        if (fputs("[\n", f) != EOF) {
            rc = 0;
            for (size_t i = 0; i < n && rc == 0; i++) {
                const cbm_scan_hit_t *h = &hits[i];
                size_t nt = h->token_count > 8u ? 8u : h->token_count;
                unsigned scaled = entropy_scaled(h->entropy);
                if (fprintf(f,
                            "  {\n"
                            "    \"offset\": %llu,\n"
                            "    \"header\": %u,\n"
                            "    \"entropy\": %u.%06u,\n"
                            "    \"sha256\": \"",
                            h->offset, (unsigned)h->header,
                            scaled / 1000000u, scaled % 1000000u) < 0) {
                    rc = -1;
                    break;
                }
                for (size_t k = 0; k < 32u; k++) {
                    if (fprintf(f, "%02x", (unsigned)h->sha256[k]) < 0) {
                        rc = -1;
                        break;
                    }
                }
                if (rc != 0 || fputs("\",\n    \"tokens\": [\n", f) == EOF) {
                    rc = -1;
                    break;
                }
                for (size_t k = 0; k < nt && rc == 0; k++) {
                    if (fprintf(f, "      { \"offset\": %llu, \"text\": ",
                                h->token_offsets[k]) < 0 ||
                        json_string(f, h->tokens[k], 64u) != 0 ||
                        fputs(k + 1u < nt ? " },\n" : " }\n", f) == EOF)
                        rc = -1;
                }
                if (rc == 0 && fputs("    ]\n", f) == EOF) rc = -1;
                if (rc == 0 &&
                    fputs(i + 1u < n ? "  },\n" : "  }\n", f) == EOF)
                    rc = -1;
            }
            if (rc == 0 && fputs("]\n", f) == EOF) rc = -1;
        }
    }
    if (fflush(f) != 0) rc = -1;
    if (fclose(f) != 0) rc = -1;
    if (rc != 0) return seterr(err, errlen, "failed to write JSON report '%s'", path);
    return 0;
}

/* Split at the final '/', yielding "." or "/" for the root cases. */
static void parent_of(const char *path, char *out, size_t outlen) {
    const char *slash = strrchr(path, '/');
    if (!slash) {
        snprintf(out, outlen, ".");
    } else if (slash == path) {
        snprintf(out, outlen, "/");
    } else {
        size_t n = (size_t)(slash - path);
        if (n >= outlen) n = outlen - 1u;
        memcpy(out, path, n);
        out[n] = '\0';
    }
}

/* Identical inode when both paths exist (follows symlinks via stat). */
static int same_existing_file(const char *a, const char *b) {
    struct stat sa, sb;
    if (stat(a, &sa) != 0 || stat(b, &sb) != 0) return 0;
    return (sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino);
}

int cbm_scan_report_check_output(const char *path, const char *source,
                                 char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!path || !path[0] || !source || !source[0])
        return seterr(err, errlen, "output path and source are required");
    if (cbm_file_is_blockdev(path))
        return seterr(err, errlen, "refusing to write to block device '%s'", path);

    char src[PATH_MAX], out[PATH_MAX], parent[PATH_MAX];
    if (!realpath(source, src))
        return seterr(err, errlen, "cannot resolve source '%s'", source);
    if (same_existing_file(path, source))
        return seterr(err, errlen, "output '%s' is the source image", path);
    if (realpath(path, out) && strcmp(out, src) == 0)
        return seterr(err, errlen, "output '%s' resolves to the source image", path);

    /* A path under the source (source/child) must also be refused: its
     * parent resolves to the source file itself. */
    parent_of(path, parent, sizeof(parent));
    if (realpath(parent, out) && strcmp(out, src) == 0)
        return seterr(err, errlen, "output '%s' is under the source image", path);
    return 0;
}

int cbm_scan_carve(const char *dir, const char *source,
                   const cbm_scan_hit_t *hits, size_t n,
                   char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!dir || !dir[0] || !source || !source[0] || (!hits && n > 0))
        return seterr(err, errlen, "dir, source and hits are required");
    if (cbm_file_is_blockdev(dir))
        return seterr(err, errlen, "carve directory must not be a block device");

    char src[PATH_MAX], src_parent[PATH_MAX], dir_real[PATH_MAX];
    if (!realpath(source, src))
        return seterr(err, errlen, "cannot resolve source '%s'", source);
    parent_of(src, src_parent, sizeof(src_parent));

    if (realpath(dir, dir_real)) {
        if (strcmp(dir_real, src) == 0 || strcmp(dir_real, src_parent) == 0 ||
            same_existing_file(dir, source))
            return seterr(err, errlen,
                          "carve directory must not be the source or its directory");
    } else {
        char dp[PATH_MAX], dp_real[PATH_MAX];
        parent_of(dir, dp, sizeof(dp));
        if (realpath(dp, dp_real) && strcmp(dp_real, src) == 0)
            return seterr(err, errlen,
                          "carve directory is under the source image");
    }
    if (cbm_scan_report_check_output(dir, source, err, errlen) != 0) return -1;

    if (mkdir(dir, 0755) != 0) {
        struct stat st;
        if (errno != EEXIST || stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
            return seterr(err, errlen, "cannot create carve directory '%s': %s",
                          dir, strerror(errno));
    }

    size_t cap = strlen(dir) + 64u;
    char *outpath = (char *)malloc(cap);
    unsigned char *body = (unsigned char *)malloc(CBM_CONTAINER_SIZE);
    int rc = -1;
    if (!outpath || !body) {
        seterr(err, errlen, "out of memory for carve");
        goto out;
    }

    for (size_t i = 0; i < n; i++) {
        const cbm_scan_hit_t *h = &hits[i];
        if (h->offset > (unsigned long long)LLONG_MAX) {
            seterr(err, errlen, "hit offset %llu exceeds signed 64-bit", h->offset);
            goto out;
        }
        int written = snprintf(outpath, cap, "%s/hit-%03zu-%llu.cbm",
                               dir, i + 1u, h->offset);
        if (written < 0 || (size_t)written >= cap) {
            seterr(err, errlen, "carve path too long");
            goto out;
        }
        if (cbm_scan_report_check_output(outpath, source, err, errlen) != 0)
            goto out;
        if (cbm_file_read(source, (long long)h->offset, body,
                          CBM_CONTAINER_SIZE) != 0) {
            seterr(err, errlen, "cannot read %d bytes at offset %llu from source",
                   CBM_CONTAINER_SIZE, h->offset);
            goto out;
        }
        FILE *f = fopen(outpath, "wb");
        if (!f) {
            seterr(err, errlen, "cannot open carve file '%s': %s",
                   outpath, strerror(errno));
            goto out;
        }
        size_t put = fwrite(body, 1, CBM_CONTAINER_SIZE, f);
        int bad = (put != CBM_CONTAINER_SIZE || fflush(f) != 0);
        if (fclose(f) != 0) bad = 1;
        if (bad) {
            remove(outpath); /* no truncated carve artifact on failure */
            seterr(err, errlen, "failed to write carve file '%s'", outpath);
            goto out;
        }
    }
    rc = 0;
out:
    free(outpath);
    free(body);
    return rc;
}
