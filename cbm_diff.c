/* cbm_diff.c - two-body byte diff with context merging implementation */
#include <stdlib.h>

#include "cbm_decode.h"
#include "cbm_diff.h"

#define CBM_DIFF_SIZE_MAX ((size_t)-1)
#define CBM_DIFF_HEAT_CELLS 16u

/* Saturating end offset: never wraps even if the caller passes absurd lengths. */
static size_t range_end(size_t offset, size_t length) {
    if (offset > CBM_DIFF_SIZE_MAX - length) return CBM_DIFF_SIZE_MAX;
    return offset + length;
}

/* Append or merge one changed span. The merge decision uses the exact gap
 * between the previous span's end and this span's start; overlapping spans
 * have gap 0 and therefore always merge, including when context == 0. */
static void add_span(cbm_diff_range_t *out, size_t *written, size_t max,
                     size_t offset, size_t length, size_t changed,
                     size_t context) {
    if (*written > 0) {
        cbm_diff_range_t *prev = &out[*written - 1];
        size_t prev_end = range_end(prev->offset, prev->length);
        size_t gap = (offset >= prev_end) ? (offset - prev_end) : 0u;
        if (gap <= context) {
            size_t end = range_end(offset, length);
            if (end > prev_end) prev->length += end - prev_end;
            prev->changed += changed;
            return;
        }
    }
    if (*written < max) {
        out[*written].offset = offset;
        out[*written].length = length;
        out[*written].changed = changed;
        (*written)++;
    }
}

size_t cbm_diff_ranges(const unsigned char *a, size_t alen,
                       const unsigned char *b, size_t blen,
                       size_t context, cbm_diff_range_t *out, size_t max) {
    if (!out || max == 0) return 0;
    if (!a) alen = 0;
    if (!b) blen = 0;

    size_t common = (alen < blen) ? alen : blen;
    size_t written = 0;
    for (size_t i = 0; i < common; i++) {
        if (a[i] != b[i]) add_span(out, &written, max, i, 1u, 1u, context);
    }
    if (alen != blen) {
        /* Trailing range is identical whichever side is longer. */
        size_t length = (alen > blen) ? (alen - blen) : (blen - alen);
        add_span(out, &written, max, common, length, length, context);
    }
    return written;
}

size_t cbm_diff_changed_bytes(const unsigned char *a, size_t alen,
                              const unsigned char *b, size_t blen) {
    if (!a) alen = 0;
    if (!b) blen = 0;

    size_t common = (alen < blen) ? alen : blen;
    size_t changed = 0;
    for (size_t i = 0; i < common; i++) {
        if (a[i] != b[i]) changed++;
    }
    changed += (alen > blen) ? (alen - blen) : (blen - alen);
    return changed;
}

/* Fixed-point integer text with a literal '.', exactly as cbm_decode_profile.
 * Entropy is <= 8 bits/byte and so is any delta between two entropies; the
 * scaled value always fits an unsigned int on 32-bit. */
static void print_entropy(FILE *out, const char *label, double value,
                          int with_sign) {
    /* Keep the original signed value for the sign; scale only the magnitude so
     * a negative entropy delta prints '-' with a positive fixed-point part. */
    double mag = value < 0.0 ? -value : value;
    unsigned scaled = (unsigned)(mag * 1000000.0 + 0.5);
    if (with_sign) {
        fprintf(out, "%s %c%u.%06u\n", label, value < 0.0 ? '-' : '+',
                scaled / 1000000u, scaled % 1000000u);
    } else {
        fprintf(out, "%s %u.%06u\n", label,
                scaled / 1000000u, scaled % 1000000u);
    }
}

static int is_printable(unsigned char c) {
    return c >= 0x20 && c <= 0x7e;
}

/* Count printable bytes of one side inside [offset, offset+length), clipped
 * to that side's actual body. span reports the clipped byte count. */
static size_t printable_count(const unsigned char *buf, size_t buflen,
                              size_t offset, size_t length, size_t *span) {
    if (!buf || offset >= buflen) { *span = 0; return 0; }
    size_t end = range_end(offset, length);
    if (end > buflen) end = buflen;
    size_t n = end - offset;
    size_t printable = 0;
    for (size_t i = 0; i < n; i++) {
        if (is_printable(buf[offset + i])) printable++;
    }
    *span = n;
    return printable;
}

static void print_bar(FILE *out, size_t printable, size_t span) {
    unsigned cells = span ? (unsigned)(((double)printable / (double)span) *
                                       (double)CBM_DIFF_HEAT_CELLS + 0.5) : 0u;
    if (cells > CBM_DIFF_HEAT_CELLS) cells = CBM_DIFF_HEAT_CELLS;
    for (unsigned i = 0; i < cells; i++) fputc('#', out);
    for (unsigned i = cells; i < CBM_DIFF_HEAT_CELLS; i++) fputc('.', out);
}

void cbm_diff_print(const unsigned char *a, size_t alen,
                    const unsigned char *b, size_t blen,
                    size_t context, FILE *out) {
    if (!out) return;
    if (!a) alen = 0;
    if (!b) blen = 0;

    /* Grow until every range fits; the public API caps writes at the buffer
     * size, so a short call is indistinguishable from a genuinely small n. */
    size_t cap = 32u;
    cbm_diff_range_t *ranges = (cbm_diff_range_t *)malloc(cap * sizeof(*ranges));
    size_t n = 0;
    if (ranges) {
        n = cbm_diff_ranges(a, alen, b, blen, context, ranges, cap);
        while (n == cap && cap <= (CBM_DIFF_SIZE_MAX / sizeof(*ranges)) / 2u) {
            size_t next = cap * 2u;
            cbm_diff_range_t *grown = (cbm_diff_range_t *)realloc(
                ranges, next * sizeof(*ranges));
            if (!grown) break;
            ranges = grown;
            cap = next;
            n = cbm_diff_ranges(a, alen, b, blen, context, ranges, cap);
        }
    }

    double entropy_a = cbm_decode_entropy(a, alen);
    double entropy_b = cbm_decode_entropy(b, blen);
    double delta = entropy_a - entropy_b;

    fprintf(out, "ranges %zu\n", n);
    fprintf(out, "changed_bytes %zu\n", cbm_diff_changed_bytes(a, alen, b, blen));
    print_entropy(out, "entropy_a", entropy_a, 0);
    print_entropy(out, "entropy_b", entropy_b, 0);
    print_entropy(out, "entropy_delta", delta, 1);

    for (size_t i = 0; i < n; i++) {
        size_t span_a = 0, span_b = 0;
        size_t pa = printable_count(a, alen, ranges[i].offset,
                                    ranges[i].length, &span_a);
        size_t pb = printable_count(b, blen, ranges[i].offset,
                                    ranges[i].length, &span_b);
        fprintf(out, "range %zu %zu %zu %zu\n", i, ranges[i].offset,
                ranges[i].length, ranges[i].changed);
        fprintf(out, "heatmap %zu a=%zu/%zu b=%zu/%zu ", i, pa, span_a,
                pb, span_b);
        print_bar(out, pa, span_a);
        fputc(' ', out);
        print_bar(out, pb, span_b);
        fputc('\n', out);
    }
    free(ranges);
}
