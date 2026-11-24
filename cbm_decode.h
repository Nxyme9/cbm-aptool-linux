/* cbm_decode.h - CBM container body entropy and region classification */
#ifndef CBM_DECODE_H
#define CBM_DECODE_H

#include <stddef.h>
#include <stdio.h>

/* Shannon entropy in bits/byte from a 256-entry histogram.
 * Returns exactly 0.0 when buf is NULL or len is 0. Never reads past buf+len. */
double cbm_decode_entropy(const unsigned char *buf, size_t len);

/* Window (64 B) classification result. */
typedef enum {
    CBM_REGION_CONSTANT,
    CBM_REGION_STRING,
    CBM_REGION_OPAQUE
} cbm_region_kind_t;

typedef struct {
    size_t offset;
    size_t length;
    cbm_region_kind_t kind;
} cbm_region_t;

/* Classify buf in 64 B windows and merge adjacent windows of the same kind.
 * Writes at most max regions to out and returns the number written.
 * Returns 0 when buf is NULL, out is NULL, max is 0, or len is 0.
 * Never reads past buf+len. */
size_t cbm_decode_regions(const unsigned char *buf, size_t len,
                          cbm_region_t *out, size_t max);

/* Print one "offset length entropy kind" row per window to out using the
 * stable format "%zu %zu %.6f %s\n" and kind names constant/string/opaque.
 * Never reads past buf+len. */
void cbm_decode_profile(const unsigned char *buf, size_t len, FILE *out);

#endif /* CBM_DECODE_H */
