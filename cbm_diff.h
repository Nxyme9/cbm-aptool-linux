/* cbm_diff.h - two-body byte diff with context merging */
#ifndef CBM_DIFF_H
#define CBM_DIFF_H

#include <stddef.h>
#include <stdio.h>

/* One contiguous changed span. changed counts differing bytes inside the
 * common prefix plus any trailing bytes contributed by a length difference. */
typedef struct {
    size_t offset;
    size_t length;
    size_t changed;
} cbm_diff_range_t;

/* Diff the common prefix of a[0..alen) and b[0..blen), then append a trailing
 * range [min(alen,blen), max(alen,blen)) when the lengths differ. Adjacent,
 * overlapping, or separated spans whose gap is <= context merge into one
 * range (context 0 merges only touching spans). Writes at most max ranges to
 * out and returns the number written. Returns 0 when out is NULL or max is 0.
 * NULL pointers are treated as zero-length bodies. Never reads past either
 * body's end; all boundary arithmetic is size_t overflow-safe. */
size_t cbm_diff_ranges(const unsigned char *a, size_t alen,
                       const unsigned char *b, size_t blen,
                       size_t context, cbm_diff_range_t *out, size_t max);

/* Count differing bytes in the common prefix plus |alen-blen|.
 * NULL pointers are treated as zero-length bodies. */
size_t cbm_diff_changed_bytes(const unsigned char *a, size_t alen,
                              const unsigned char *b, size_t blen);

/* Print the range list, changed-byte count, entropy of both bodies (via
 * cbm_decode_entropy) and a printable-density heatmap line per range. All
 * floating-point values use fixed-point integer text with a literal '.' so
 * output is identical under any LC_NUMERIC. Never reads past either body. */
void cbm_diff_print(const unsigned char *a, size_t alen,
                    const unsigned char *b, size_t blen,
                    size_t context, FILE *out);

#endif /* CBM_DIFF_H */
