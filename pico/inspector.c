/* inspector.c - portable inspection helpers (see inspector.h). */
#include "inspector.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int pico_header_encrypted(unsigned char header) {
    return (header & 0x80u) != 0;
}

double pico_entropy(const unsigned char *buf, size_t len) {
    unsigned long hist[256];
    size_t i;
    double h = 0.0;
    if (!buf || len == 0) return 0.0;
    memset(hist, 0, sizeof(hist));
    for (i = 0; i < len; i++) hist[buf[i]]++;
    for (i = 0; i < 256; i++) {
        double p;
        if (!hist[i]) continue;
        p = (double)hist[i] / (double)len;
        h -= p * log2(p);
    }
    return h;
}

unsigned int pico_count_strings(const unsigned char *buf, size_t len,
                                unsigned int min_len) {
    unsigned int count = 0, run = 0;
    size_t i;
    if (!buf) return 0;
    if (min_len == 0) min_len = 1;
    for (i = 0; i < len; i++) {
        if (buf[i] >= 0x20u && buf[i] <= 0x7eu) {
            run++;
        } else {
            if (run >= min_len) count++;
            run = 0;
        }
    }
    if (run >= min_len) count++;
    return count;
}

static size_t appf(char *out, size_t cap, size_t used, const char *fmt, ...) {
    va_list ap;
    int n;
    if (used >= cap) return cap;
    va_start(ap, fmt);
    n = vsnprintf(out + used, cap - used, fmt, ap);
    va_end(ap);
    if (n < 0) return used;
    if ((size_t)n >= cap - used) return cap;
    return used + (size_t)n;
}

size_t pico_hexdump(const unsigned char *buf, size_t len, size_t limit,
                    char *out, size_t cap) {
    size_t used = 0, off;
    if (!out || cap == 0) return 0;
    if (limit > len) limit = len;
    for (off = 0; off < limit; off += 16) {
        unsigned int i, n = (unsigned int)(limit - off);
        if (n > 16) n = 16;
        used = appf(out, cap, used, "%04x: ", (unsigned int)off);
        for (i = 0; i < 16; i++) {
            if (i < n) used = appf(out, cap, used, "%02x", buf[off + i]);
            else       used = appf(out, cap, used, "  ");
            used = appf(out, cap, used, i == 7 ? "  " : " ");
        }
        used = appf(out, cap, used, " |");
        for (i = 0; i < n; i++) {
            unsigned char c = buf[off + i];
            used = appf(out, cap, used, "%c",
                        (c >= 0x20u && c <= 0x7eu) ? (int)c : '.');
        }
        used = appf(out, cap, used, "|\n");
    }
    /* Always terminate inside the buffer, even when the dump was truncated. */
    out[used < cap ? used : cap - 1] = '\0';
    return used;
}

void pico_inspect(unsigned char header, const unsigned char *body, size_t len,
                  pico_inspect_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->header = header;
    out->encrypted = pico_header_encrypted(header);
    if (!body || len == 0) return;
    out->entropy_bits = pico_entropy(body, len);
    out->strings = pico_count_strings(body, len, 4);
    out->hex_lines = (unsigned int)((len + 15) / 16);
}
