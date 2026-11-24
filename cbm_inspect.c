/* cbm_inspect.c - CBM container inspection implementation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "cbm_inspect.h"

static int is_printable(unsigned char c) {
    return c >= 0x20 && c <= 0x7e;
}

/* Base-2 logarithm without libm (the brief's standalone build command has no
 * -lm). Decompose x into exponent + mantissa in [1,2), then evaluate the
 * atanh series log2(m) = (2/ln2) * (t + t^3/3 + t^5/5 + ...) with
 * t = (m-1)/(m+1). Accurate to ~1e-9 over the range used here. Exact for
 * powers of two (mantissa == 1 -> t == 0). */
static double fast_log2(double x) {
    if (x <= 0.0) return 0.0;
    uint64_t bits;
    memcpy(&bits, &x, sizeof(bits));
    int e = (int)((bits >> 52) & 0x7ffu) - 1023;
    bits = (bits & 0x000fffffffffffffULL) | 0x3ff0000000000000ULL;
    double m;
    memcpy(&m, &bits, sizeof(m));
    double t = (m - 1.0) / (m + 1.0);
    double t2 = t * t;
    double term = t;
    double sum = t;
    for (int k = 1; k <= 7; k++) {
        term *= t2;
        sum += term / (double)(2 * k + 1);
    }
    return (double)e + 2.88539008177792681472 * sum;
}

/* Dump n bytes starting at absolute offset start, in 16-byte rows. */
static void dump_range(const unsigned char *buf, size_t start, size_t n,
                      FILE *out) {
    if (!buf || n == 0 || !out) return;
    size_t i;
    for (i = 0; i < n; i += 16) {
        size_t off = start + i;
        size_t chunk = (i + 16 <= n) ? 16 : (n - i);
        size_t end = off + chunk;
        fprintf(out, "%08zx  ", off);
        size_t k;
        for (k = 0; k < 16; k++) {
            if (off + k < end) {
                fprintf(out, "%02x ", buf[off + k]);
            } else {
                fputs("   ", out);
            }
        }
        fputc(' ', out);
        for (k = 0; k < 16; k++) {
            if (off + k < end) {
                unsigned char c = buf[off + k];
                fputc(is_printable(c) ? (int)c : '.', out);
            }
        }
        fputc('\n', out);
    }
}

void cbm_inspect_hex(const unsigned char *buf, size_t len,
                     size_t max_bytes, FILE *out) {
    if (!out) return;
    if (len == 0 || !buf) return;

    /* 0 means "all"; a cap >= len also means "all" (avoid duplicates). */
    if (max_bytes == 0 || max_bytes >= len) {
        dump_range(buf, 0, len, out);
        return;
    }

    size_t head = max_bytes / 2;
    size_t tail = max_bytes / 2;
    if (head + tail > len) { /* defensive (cannot happen for max_bytes < len) */
        head = len;
        tail = 0;
    }
    if (head > 0) dump_range(buf, 0, head, out);
    if (head + tail < len) {
        fprintf(out, "... (%zu bytes omitted) ...\n", len - head - tail);
    }
    if (tail > 0) dump_range(buf, len - tail, tail, out);
}

void cbm_inspect_strings(const unsigned char *buf, size_t len,
                         size_t min_run, FILE *out) {
    if (!out) return;
    if (!buf || len == 0) return;
    if (min_run == 0) min_run = 1; /* an empty run is not a string */

    size_t i = 0;
    while (i < len) {
        if (!is_printable(buf[i])) {
            i++;
            continue;
        }
        size_t j = i;
        while (j < len && is_printable(buf[j])) j++; /* never past buf+len */
        size_t run = j - i;
        if (run >= min_run) {
            fprintf(out, "offset %zu (0x%zx): %.*s\n",
                    i, i, (int)run, (const char *)(buf + i));
        }
        i = j; /* skip past the run */
    }
}

void cbm_inspect_stats(const unsigned char *buf, size_t len, FILE *out) {
    if (!out) return;
    size_t printable = 0;
    size_t counts[256];
    memset(counts, 0, sizeof(counts));

    if (buf) {
        for (size_t i = 0; i < len; i++) {
            unsigned char c = buf[i];
            counts[c]++;
            if (is_printable(c)) printable++;
        }
    }

    size_t unique = 0;
    for (int v = 0; v < 256; v++) {
        if (counts[v] > 0) unique++;
    }

    /* Shannon entropy in bits/byte: -sum(p * log2(p)). */
    double entropy = 0.0;
    if (len > 0 && buf) {
        for (int v = 0; v < 256; v++) {
            if (counts[v] == 0) continue;
            double p = (double)counts[v] / (double)len;
            entropy -= p * fast_log2(p);
        }
    }

    fprintf(out, "size: %zu\n", len);
    fprintf(out, "printable: %zu\n", printable);
    fprintf(out, "unique: %zu\n", unique);
    fprintf(out, "entropy: %.4f\n", entropy);
}

static const char *const TOKENS[] = {
    "CBMUsb",
    "CBMUsbDisk",
    "SCSI",
    "IOCTL",
    "Vendor",
    "Chipsbank",
    "USB",
    "NAND",
    "BCH",
    "TEA",
    "Decrypt",
    "Encrypt",
    "File is encrypted",
};

void cbm_inspect_tokens(const unsigned char *buf, size_t len, FILE *out) {
    if (!out) return;
    if (!buf || len == 0) return;

    size_t ntok = sizeof(TOKENS) / sizeof(TOKENS[0]);
    for (size_t t = 0; t < ntok; t++) {
        const char *tok = TOKENS[t];
        size_t tlen = strlen(tok);
        if (tlen == 0 || tlen > len) continue;
        for (size_t off = 0; off + tlen <= len; off++) {
            if (memcmp(buf + off, tok, tlen) == 0) {
                fprintf(out, "offset %zu (0x%zx): %s\n", off, off, tok);
            }
        }
    }
}
