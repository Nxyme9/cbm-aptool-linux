/* entropy_map.h - whole-disk block entropy sampling, downsampling, region
 * classification and deterministic JSON sidecar.
 *
 * Read-only: the only source access is cbm_file_read (Wave 5B). Entropy is
 * always computed by cbm_decode_entropy (Wave 5C); there is no second entropy
 * routine and no second device-read path in this module.
 */
#ifndef ENTROPY_MAP_H
#define ENTROPY_MAP_H

#include <stddef.h>

/* Bounded memory: a range needing more than 64 Mi samples (67,108,864) is
 * rejected by cbm_entropy_map before any allocation or I/O. All products and
 * sums of offsets/counts are overflow-checked. */
#define CBM_ENTROPY_MAX_SAMPLES (64ULL * 1024ULL * 1024ULL)

/* Colour ramp for entropy in bits/byte (linear interpolation in 1e-6 fixed
 * point, integer arithmetic only):
 *   <= 0.0        blue     (  0,   0, 255)
 *   0.0 .. 2.0    blue  -> cyan     (  0, 255, 255)
 *   2.0 .. 4.0    cyan  -> green    (  0, 255,   0)
 *   4.0 .. 6.0    green -> yellow   (255, 255,   0)
 *   6.0 .. 8.0    yellow-> red      (255,   0,   0)
 *   >= 8.0        red      (255,   0,   0)
 * Breakpoints are exactly 0.0, 2.0, 4.0, 6.0 and 8.0 bits/byte. Pixels with
 * no samples are neutral grey (128,128,128). */
#define CBM_ENTROPY_RAMP_STOPS 5u

typedef struct {
    unsigned long long offset; /* absolute byte offset of this block */
    size_t length;             /* true block length (short for the last block) */
    double entropy;            /* bits/byte from cbm_decode_entropy */
} cbm_entropy_sample_t;

typedef struct {
    size_t index;              /* pixel index in row-major order */
    size_t first_sample;       /* first sample index mapped here, or next
                                * occupied pixel's first sample (n if last) */
    size_t sample_count;       /* number of samples mapped here (0 = grey) */
    double min, mean, max;     /* 0.0 when sample_count == 0 */
    unsigned char r, g, b;
} cbm_heatmap_pixel_t;

typedef struct {
    const char *name;          /* "MBR", "DJ_BOOT", "DJ_OS", "DJ_DATA", "TAIL" */
    unsigned long long offset;
    unsigned long long length;
    size_t samples;            /* samples fully inside the region */
    double min, mean, max;     /* 0.0 when samples == 0 */
    int inferred;              /* always 1: derived from the MBR, not verified */
} cbm_entropy_region_t;

/* Sample one contiguous buffer. block_bytes == 0, len == 0, buf == NULL or
 * out == NULL returns 0. Blocks start at base_offset and are block_bytes long,
 * except the final one which uses its true shorter length. Writes at most max
 * samples and returns the number written. */
size_t cbm_entropy_blocks(const unsigned char *buf, size_t len,
                          size_t block_bytes, unsigned long long base_offset,
                          cbm_entropy_sample_t *out, size_t max);

/* Walk the half-open byte range [start_byte, end_byte) in 8 MiB cbm_file_read
 * chunks, sampling block_bytes-sized blocks. Allocates *out (caller frees with
 * free); *out is NULL and *out_count is 0 for an empty range. Returns 0 on
 * success, -1 on error with a message in err. Rejects block_bytes == 0,
 * end_byte < start_byte, ranges needing more than CBM_ENTROPY_MAX_SAMPLES
 * samples, and unreadable paths. Never opens the source for writing. */
int cbm_entropy_map(const char *path, unsigned long long start_byte,
                    unsigned long long end_byte, size_t block_bytes,
                    cbm_entropy_sample_t **out, size_t *out_count,
                    char *err, size_t errlen);

/* Downsample n samples to at most max pixels. Pixel mapping is exact integer
 * arithmetic: sample i maps to pixel (unsigned long long)i * (width*height) / n
 * (computed as i*(total/n) + i*(total%n)/n, which is overflow-free for n <=
 * CBM_ENTROPY_MAX_SAMPLES). n == 0 leaves every pixel grey/empty. Returns the
 * pixel count width*height, capped at max (0 when width/height/out are 0). */
size_t cbm_entropy_downsample(const cbm_entropy_sample_t *samples, size_t n,
                              size_t width, size_t height,
                              cbm_heatmap_pixel_t *out, size_t max);

/* Derive regions from an MBR buffer: MBR [0,512) when a >=512-byte MBR buffer
 * is supplied, DJ_BOOT/DJ_OS/DJ_DATA when cbm_layout_parse +
 * cbm_layout_validate accept the DJ geometry, plus the unpartitioned TAIL up
 * to the last sampled byte. An unparseable or non-DJ MBR yields MBR + TAIL
 * only; with no MBR buffer at all, TAIL only. DJ names are never invented.
 * Every region has
 * inferred = 1. Statistics use samples fully inside each region; a region with
 * no samples reports 0.0 for min/mean/max. Returns regions written (<= max),
 * or 0 when n == 0 or out == NULL. */
size_t cbm_entropy_regions(const cbm_entropy_sample_t *samples, size_t n,
                           const unsigned char *mbr, size_t mbr_len,
                           cbm_entropy_region_t *out, size_t max);

/* Write a deterministic JSON sidecar to path. Field order and shape:
 * {"block_bytes":N,"samples":N,"width":N,"height":N,"entropy":{"min":D,
 * "mean":D,"max":D},"regions":[{"name":"...","offset":N,"length":N,
 * "samples":N,"min":D,"mean":D,"max":D,"inferred":true}]}\n
 * D is fixed-point %u.%06u with a literal '.' (never locale-dependent).
 * block_bytes is the largest sample length (0 when n == 0). n == 0 emits
 * valid JSON with empty arrays. Returns 0 or -1 with a message in err. */
int cbm_entropy_json(const char *path, const cbm_entropy_sample_t *samples,
                     size_t n, const cbm_entropy_region_t *regions,
                     size_t nregions, size_t width, size_t height,
                     char *err, size_t errlen);

#endif /* ENTROPY_MAP_H */
