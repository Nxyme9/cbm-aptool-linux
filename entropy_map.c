/* entropy_map.c - block entropy sampling, downsampling, regions and JSON.
 *
 * Read-only source access goes exclusively through cbm_file_read; entropy
 * goes exclusively through cbm_decode_entropy. No time(), rand(), address
 * ordering or floating formatting leaks into the emitted JSON.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_decode.h"
#include "cbm_file.h"
#include "cbm_layout.h"

#include "entropy_map.h"

#define CBM_ENTROPY_CHUNK (8u * 1024u * 1024u)
#define CBM_ENTROPY_SCALE 1000000ULL
#define CBM_ENTROPY_MAX_SCALED (8ULL * CBM_ENTROPY_SCALE)
#define CBM_ENTROPY_SEGMENT (2ULL * CBM_ENTROPY_SCALE)

static int seterr(char *err, size_t errlen, const char *fmt, ...) {
    if (err && errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* ---- block sampling ---------------------------------------------------- */

size_t cbm_entropy_blocks(const unsigned char *buf, size_t len,
                          size_t block_bytes, unsigned long long base_offset,
                          cbm_entropy_sample_t *out, size_t max) {
    if (!buf || !out || len == 0 || block_bytes == 0 || max == 0) return 0;

    size_t written = 0;
    size_t off = 0;
    while (off < len && written < max) {
        size_t n = (len - off < block_bytes) ? (len - off) : block_bytes;
        if (base_offset > ULLONG_MAX - (unsigned long long)off) break;
        out[written].offset = base_offset + (unsigned long long)off;
        out[written].length = n;
        out[written].entropy = cbm_decode_entropy(buf + off, n);
        written++;
        off += n; /* n <= len - off, so this cannot wrap size_t */
    }
    return written;
}

int cbm_entropy_map(const char *path, unsigned long long start_byte,
                    unsigned long long end_byte, size_t block_bytes,
                    cbm_entropy_sample_t **out, size_t *out_count,
                    char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!path || !path[0] || !out || !out_count || block_bytes == 0 ||
        end_byte < start_byte)
        return seterr(err, errlen,
                      "path, out and out_count are required; block_bytes must be > 0 and end >= start");
    *out = NULL;
    *out_count = 0;

    unsigned long long range = end_byte - start_byte; /* safe: end >= start */
    unsigned long long blocks = range / (unsigned long long)block_bytes;
    if (range % (unsigned long long)block_bytes) blocks++;
    if (blocks > CBM_ENTROPY_MAX_SAMPLES)
        return seterr(err, errlen,
                      "range needs %llu samples, cap is %llu",
                      blocks, CBM_ENTROPY_MAX_SAMPLES);
    if (blocks > (unsigned long long)(SIZE_MAX / sizeof(cbm_entropy_sample_t)))
        return seterr(err, errlen, "sample array size overflows size_t");
    if (start_byte > (unsigned long long)LLONG_MAX ||
        end_byte > (unsigned long long)LLONG_MAX)
        return seterr(err, errlen, "range is outside cbm_file_read's signed offsets");
    if (blocks == 0) return 0;

    /* Buffers are bounded by the range and by the 8 MiB chunk size. A huge
     * block_bytes never allocates more than the range itself. */
    size_t chunk_cap = (range < (unsigned long long)CBM_ENTROPY_CHUNK)
                       ? (size_t)range : CBM_ENTROPY_CHUNK;
    size_t carry_cap = block_bytes;
    if ((unsigned long long)carry_cap > range) {
        carry_cap = (range > (unsigned long long)SIZE_MAX)
                    ? SIZE_MAX : (size_t)range;
    }

    unsigned char *chunk = (unsigned char *)malloc(chunk_cap);
    unsigned char *carry = (unsigned char *)malloc(carry_cap);
    cbm_entropy_sample_t *samples =
        (cbm_entropy_sample_t *)malloc((size_t)blocks * sizeof(*samples));
    if (!chunk || !carry || !samples) {
        free(chunk); free(carry); free(samples);
        return seterr(err, errlen, "out of memory for %llu samples", blocks);
    }

    size_t written = 0;
    size_t carry_len = 0;
    unsigned long long pos = start_byte;
    unsigned long long block_start = start_byte;
    int rc = 0;

    while (pos < end_byte && written < (size_t)blocks) {
        unsigned long long remaining = end_byte - pos;
        size_t want = (remaining >= (unsigned long long)chunk_cap)
                      ? chunk_cap : (size_t)remaining;
        if (cbm_file_read(path, (long long)pos, chunk, want) != 0) {
            rc = seterr(err, errlen, "read failed at offset %llu", pos);
            break;
        }
        size_t i = 0;
        while (i < want) {
            size_t need = block_bytes - carry_len; /* carry_len < block_bytes */
            size_t take = (want - i < need) ? (want - i) : need;
            memcpy(carry + carry_len, chunk + i, take);
            carry_len += take;
            i += take;
            if (carry_len == block_bytes) {
                size_t k = cbm_entropy_blocks(carry, carry_len, block_bytes,
                                              block_start, samples + written,
                                              (size_t)blocks - written);
                if (k != 1u) {
                    rc = seterr(err, errlen, "internal block sampling failure");
                    break;
                }
                written += k;
                carry_len = 0;
                block_start += (unsigned long long)block_bytes;
            }
        }
        if (rc != 0) break;
        pos += (unsigned long long)want;
    }

    /* The final partial block is sampled at its true (shorter) length. */
    if (rc == 0 && carry_len > 0 && written < (size_t)blocks) {
        size_t k = cbm_entropy_blocks(carry, carry_len, block_bytes,
                                      block_start, samples + written,
                                      (size_t)blocks - written);
        if (k != 1u) rc = seterr(err, errlen, "internal final block failure");
        else written += k;
    }

    free(chunk);
    free(carry);
    if (rc != 0) {
        free(samples);
        return -1;
    }
    *out = samples;
    *out_count = written;
    return 0;
}

/* ---- downsampling ------------------------------------------------------ */

/* Exact equivalent of (unsigned long long)i * total / n without a 64-bit
 * product that could overflow: total = q*n + r, so i*total/n = i*q + i*r/n.
 * n <= 64 Mi keeps i*r below 2^52 even on a 32-bit build. */
static size_t sample_pixel(size_t i, size_t n, size_t total) {
    unsigned long long q = (unsigned long long)(total / n);
    unsigned long long r = (unsigned long long)(total % n);
    return (size_t)((unsigned long long)i * q +
                    ((unsigned long long)i * r) / (unsigned long long)n);
}

static unsigned fixed_scaled(double value) {
    if (!(value > 0.0)) return 0u;
    if (value >= 8.0) return (unsigned)CBM_ENTROPY_MAX_SCALED;
    return (unsigned)(value * (double)CBM_ENTROPY_SCALE + 0.5);
}

static void entropy_color(double value, unsigned char *r,
                          unsigned char *g, unsigned char *b) {
    static const unsigned char stops[CBM_ENTROPY_RAMP_STOPS][3] = {
        {  0,   0, 255}, /* blue   @ 0 */
        {  0, 255, 255}, /* cyan   @ 2 */
        {  0, 255,   0}, /* green  @ 4 */
        {255, 255,   0}, /* yellow @ 6 */
        {255,   0,   0}  /* red    @ 8 */
    };
    unsigned long long sc = (unsigned long long)fixed_scaled(value);
    if (sc > CBM_ENTROPY_MAX_SCALED) sc = CBM_ENTROPY_MAX_SCALED;
    unsigned long long seg = sc / CBM_ENTROPY_SEGMENT;
    unsigned long long frac = sc % CBM_ENTROPY_SEGMENT;
    if (seg >= CBM_ENTROPY_RAMP_STOPS - 1u) {
        *r = stops[CBM_ENTROPY_RAMP_STOPS - 1u][0];
        *g = stops[CBM_ENTROPY_RAMP_STOPS - 1u][1];
        *b = stops[CBM_ENTROPY_RAMP_STOPS - 1u][2];
        return;
    }
    for (unsigned c = 0; c < 3u; c++) {
        unsigned long long lo = stops[seg][c];
        unsigned long long hi = stops[seg + 1u][c];
        /* Rounded integer linear interpolation, no floating point. */
        unsigned long long v = lo * (CBM_ENTROPY_SEGMENT - frac) +
                               hi * frac + CBM_ENTROPY_SEGMENT / 2u;
        v /= CBM_ENTROPY_SEGMENT;
        if (c == 0) *r = (unsigned char)v;
        else if (c == 1) *g = (unsigned char)v;
        else *b = (unsigned char)v;
    }
}

size_t cbm_entropy_downsample(const cbm_entropy_sample_t *samples, size_t n,
                              size_t width, size_t height,
                              cbm_heatmap_pixel_t *out, size_t max) {
    if (!out || width == 0 || height == 0) return 0;
    if (width > SIZE_MAX / height) return 0;
    size_t total = width * height;
    size_t pixels = (total < max) ? total : max;
    if (pixels == 0) return 0;

    for (size_t p = 0; p < pixels; p++) {
        out[p].index = p;
        out[p].first_sample = n;
        out[p].sample_count = 0;
        out[p].min = 0.0;
        out[p].mean = 0.0;
        out[p].max = 0.0;
        out[p].r = 128;
        out[p].g = 128;
        out[p].b = 128;
    }
    if (!samples || n == 0) return pixels;

    /* Pass 1: first sample, count and min/max per pixel. */
    for (size_t i = 0; i < n; i++) {
        size_t p = sample_pixel(i, n, total);
        if (p >= pixels) continue; /* max < total: ignore pixels not emitted */
        cbm_heatmap_pixel_t *px = &out[p];
        if (px->sample_count == 0) {
            px->first_sample = i;
            px->min = samples[i].entropy;
            px->max = samples[i].entropy;
        } else {
            if (samples[i].entropy < px->min) px->min = samples[i].entropy;
            if (samples[i].entropy > px->max) px->max = samples[i].entropy;
        }
        px->sample_count++;
    }
    /* Empty pixels inherit the first sample at or after their position. */
    size_t next = n;
    for (size_t p = pixels; p-- > 0;) {
        if (out[p].sample_count == 0) out[p].first_sample = next;
        else next = out[p].first_sample;
    }
    /* Pass 2: sample order is ascending, so the sum is deterministic. */
    for (size_t i = 0; i < n; i++) {
        size_t p = sample_pixel(i, n, total);
        if (p < pixels) out[p].mean += samples[i].entropy;
    }
    for (size_t p = 0; p < pixels; p++) {
        if (out[p].sample_count > 0) {
            out[p].mean /= (double)out[p].sample_count;
            entropy_color(out[p].mean, &out[p].r, &out[p].g, &out[p].b);
        }
    }
    return pixels;
}

/* ---- region overlay ---------------------------------------------------- */

typedef struct {
    const char *name;
    unsigned long long offset;
    unsigned long long length;
} region_desc_t;

static unsigned long long sat_add(unsigned long long a, unsigned long long b) {
    return (b > ULLONG_MAX - a) ? ULLONG_MAX : a + b;
}

size_t cbm_entropy_regions(const cbm_entropy_sample_t *samples, size_t n,
                           const unsigned char *mbr, size_t mbr_len,
                           cbm_entropy_region_t *out, size_t max) {
    if (!samples || n == 0 || !out || max == 0) return 0;

    unsigned long long sampled_end = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned long long end = sat_add(samples[i].offset,
                                         (unsigned long long)samples[i].length);
        if (end > sampled_end) sampled_end = end;
    }

    region_desc_t descs[5];
    size_t ndesc = 0;
    int have_mbr = (mbr && mbr_len >= CBM_SECTOR_SIZE);
    if (have_mbr) {
        descs[ndesc].name = "MBR";
        descs[ndesc].offset = 0;
        descs[ndesc].length = CBM_SECTOR_SIZE;
        ndesc++;
    }

    cbm_layout_t layout;
    unsigned long long tail_start = have_mbr ? CBM_SECTOR_SIZE : 0ULL;
    if (have_mbr && cbm_layout_parse(mbr, mbr_len, &layout) == 0) {
        unsigned long long sampled_sectors = sampled_end / CBM_SECTOR_SIZE;
        unsigned long long disk_sectors = sampled_sectors >
                                          CBM_EXPECTED_WINDOW_SECTORS
                                          ? sampled_sectors
                                          : CBM_EXPECTED_WINDOW_SECTORS;
        if (cbm_layout_validate(&layout, disk_sectors) == 0) {
            static const char *const names[3] = {"DJ_BOOT", "DJ_OS", "DJ_DATA"};
            for (int i = 0; i < layout.part_count && i < 3; i++) {
                unsigned long long start_lba = layout.parts[i].start_lba;
                unsigned long long size_lba = layout.parts[i].size_lba;
                /* Guard the LBAs *before* scaling: checking the products
                 * afterwards would let a wrapped value through. */
                if (start_lba > ULLONG_MAX / CBM_SECTOR_SIZE ||
                    size_lba > ULLONG_MAX / CBM_SECTOR_SIZE) continue;
                unsigned long long off = start_lba * CBM_SECTOR_SIZE;
                unsigned long long len = size_lba * CBM_SECTOR_SIZE;
                descs[ndesc].name = names[i];
                descs[ndesc].offset = off;
                descs[ndesc].length = len;
                ndesc++;
                unsigned long long part_end = sat_add(off, len);
                if (part_end > tail_start) tail_start = part_end;
            }
        }
    }
    /* Non-DJ layouts simply leave no DJ descriptors. */
    if (sampled_end > tail_start) {
        descs[ndesc].name = "TAIL";
        descs[ndesc].offset = tail_start;
        descs[ndesc].length = sampled_end - tail_start;
        ndesc++;
    }

    size_t written = 0;
    for (size_t d = 0; d < ndesc && written < max; d++) {
        unsigned long long roff = descs[d].offset;
        unsigned long long rend = sat_add(roff, descs[d].length);
        cbm_entropy_region_t *reg = &out[written];
        reg->name = descs[d].name;
        reg->offset = roff;
        reg->length = descs[d].length;
        reg->samples = 0;
        reg->min = 0.0;
        reg->mean = 0.0;
        reg->max = 0.0;
        reg->inferred = 1;
        double sum = 0.0;
        for (size_t i = 0; i < n; i++) {
            if (samples[i].offset < roff || samples[i].offset >= rend) continue;
            double e = samples[i].entropy;
            if (reg->samples == 0) { reg->min = e; reg->max = e; }
            else {
                if (e < reg->min) reg->min = e;
                if (e > reg->max) reg->max = e;
            }
            sum += e;
            reg->samples++;
        }
        if (reg->samples > 0) reg->mean = sum / (double)reg->samples;
        written++;
    }
    return written;
}

/* ---- deterministic JSON sidecar ---------------------------------------- */

static int write_fixed(FILE *f, double value) {
    unsigned scaled = fixed_scaled(value);
    return (fprintf(f, "%u.%06u", scaled / 1000000u,
                    scaled % 1000000u) < 0) ? -1 : 0;
}

/* Escape every region name even though this module supplies literals. */
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
            } else if (fputc((int)c, f) == EOF) return -1;
        }
    }
    return (fputc('"', f) == EOF) ? -1 : 0;
}

int cbm_entropy_json(const char *path, const cbm_entropy_sample_t *samples,
                     size_t n, const cbm_entropy_region_t *regions,
                     size_t nregions, size_t width, size_t height,
                     char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!path || !path[0] || (!samples && n > 0) || (!regions && nregions > 0))
        return seterr(err, errlen, "path, samples and regions are required");
    if (cbm_file_is_blockdev(path))
        return seterr(err, errlen, "JSON sidecar must not be a block device: '%s'", path);

    FILE *f = fopen(path, "wb");
    if (!f)
        return seterr(err, errlen, "cannot open JSON sidecar '%s': %s",
                      path, strerror(errno));

    size_t block_bytes = 0;
    double mn = 0.0, mx = 0.0, sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        if (samples[i].length > block_bytes) block_bytes = samples[i].length;
        if (i == 0) { mn = samples[i].entropy; mx = samples[i].entropy; }
        else {
            if (samples[i].entropy < mn) mn = samples[i].entropy;
            if (samples[i].entropy > mx) mx = samples[i].entropy;
        }
        sum += samples[i].entropy;
    }
    double mean = n ? (sum / (double)n) : 0.0;

    int rc = 0;
    if (fprintf(f, "{\"block_bytes\":%zu,\"samples\":%zu,\"width\":%zu,"
                   "\"height\":%zu,\"entropy\":{\"min\":",
                block_bytes, n, width, height) < 0 ||
        write_fixed(f, mn) != 0 || fputs(",\"mean\":", f) == EOF ||
        write_fixed(f, mean) != 0 || fputs(",\"max\":", f) == EOF ||
        write_fixed(f, mx) != 0 || fputs("},\"regions\":[", f) == EOF) {
        rc = -1;
    }
    for (size_t i = 0; i < nregions && rc == 0; i++) {
        const cbm_entropy_region_t *r = &regions[i];
        if ((i && fputc(',', f) == EOF) ||
            fputs("{\"name\":", f) == EOF ||
            json_string(f, r->name ? r->name : "", 256u) != 0 ||
            fprintf(f, ",\"offset\":%llu,\"length\":%llu,\"samples\":%zu,"
                       "\"min\":", r->offset, r->length, r->samples) < 0 ||
            write_fixed(f, r->min) != 0 || fputs(",\"mean\":", f) == EOF ||
            write_fixed(f, r->mean) != 0 || fputs(",\"max\":", f) == EOF ||
            write_fixed(f, r->max) != 0 ||
            fputs(",\"inferred\":true}", f) == EOF) {
            rc = -1;
        }
    }
    if (rc == 0 && fputs("]}\n", f) == EOF) rc = -1;
    int flush_rc = fflush(f);
    int close_rc = fclose(f); /* always close, even when fflush fails */
    if (flush_rc != 0 || close_rc != 0) rc = -1;
    if (rc != 0)
        return seterr(err, errlen, "failed to write JSON sidecar '%s'", path);
    return 0;
}
