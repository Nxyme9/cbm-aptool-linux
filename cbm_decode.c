/* cbm_decode.c - CBM container body entropy and region classification implementation */
#include <stdint.h>
#include <string.h>

#include "cbm_decode.h"

#define CBM_DECODE_WINDOW 64u

static int is_printable(unsigned char c) {
    return c >= 0x20 && c <= 0x7e;
}

/* Base-2 logarithm without libm (the standalone build command has no -lm).
 * Same approach as cbm_inspect's helper: decompose x into exponent + mantissa
 * in [1,2), then evaluate log2(m) = (2/ln2) * (t + t^3/3 + t^5/5 + ...) with
 * t = (m-1)/(m+1). Exact for powers of two (mantissa == 1 -> t == 0). */
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

double cbm_decode_entropy(const unsigned char *buf, size_t len) {
    size_t counts[256];
    memset(counts, 0, sizeof(counts));
    if (!buf || len == 0) return 0.0;

    for (size_t i = 0; i < len; i++) counts[buf[i]]++;

    double entropy = 0.0;
    for (int v = 0; v < 256; v++) {
        if (counts[v] == 0) continue;
        double p = (double)counts[v] / (double)len;
        entropy -= p * fast_log2(p);
    }
    return entropy;
}

/* n is always >= 1: callers only pass a nonempty window. */
static cbm_region_kind_t classify_window(const unsigned char *p, size_t n) {
    int all_equal = 1;
    for (size_t i = 1; i < n; i++) {
        if (p[i] != p[0]) { all_equal = 0; break; }
    }
    if (all_equal) return CBM_REGION_CONSTANT;

    size_t printable = 0;
    for (size_t i = 0; i < n; i++) {
        if (is_printable(p[i])) printable++;
    }
    /* printable / n >= 0.85 in exact integer arithmetic; n <= 64. */
    if (printable * 100u >= 85u * n) return CBM_REGION_STRING;
    return CBM_REGION_OPAQUE;
}

static const char *kind_name(cbm_region_kind_t kind) {
    switch (kind) {
    case CBM_REGION_CONSTANT: return "constant";
    case CBM_REGION_STRING:   return "string";
    case CBM_REGION_OPAQUE:   return "opaque";
    }
    return "opaque";
}

size_t cbm_decode_regions(const unsigned char *buf, size_t len,
                          cbm_region_t *out, size_t max) {
    if (!buf || len == 0 || !out || max == 0) return 0;

    size_t written = 0;
    size_t off = 0;
    while (off < len && written < max) {
        size_t n = (len - off < CBM_DECODE_WINDOW)
                   ? (len - off) : CBM_DECODE_WINDOW;
        cbm_region_kind_t kind = classify_window(buf + off, n);

        if (written > 0 && out[written - 1].kind == kind) {
            out[written - 1].length += n;
        } else {
            out[written].offset = off;
            out[written].length = n;
            out[written].kind = kind;
            written++;
        }
        off += n;
    }
    return written;
}

void cbm_decode_profile(const unsigned char *buf, size_t len, FILE *out) {
    if (!out || !buf || len == 0) return;

    size_t off = 0;
    while (off < len) {
        size_t n = (len - off < CBM_DECODE_WINDOW)
                   ? (len - off) : CBM_DECODE_WINDOW;
        cbm_region_kind_t kind = classify_window(buf + off, n);
        fprintf(out, "%zu %zu %.6f %s\n", off, n,
                cbm_decode_entropy(buf + off, n), kind_name(kind));
        off += n;
    }
}
