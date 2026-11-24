/* png_write.c - minimal self-written 8-bit RGB PNG encoder and its
 * test-side decoder. Uses only zlib (compress2/uncompress/crc32) and stdio;
 * no external image library and no source-image access.
 *
 * Layout: signature, IHDR, one IDAT (filter-0 scanlines compressed at
 * Z_BEST_COMPRESSION), IEND. Every chunk is length/type/data/CRC with the CRC
 * computed by zlib crc32 over type+data from crc32(0L, Z_NULL, 0).
 */
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "png_write.h"

#define PNG_CHUNK_MAX 0x7fffffffUL /* PNG spec: length is a 31-bit unsigned */
#define T_IHDR 0x49484452UL
#define T_IDAT 0x49444154UL
#define T_IEND 0x49454e44UL

static const unsigned char PNG_SIG[8] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
};

static void seterr(char *err, size_t errlen, const char *fmt, ...) {
    if (!err || !errlen) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* Only fill in a generic message when a more specific one was not set. */
static void seterr_if_empty(char *err, size_t errlen, const char *msg) {
    if (err && errlen && err[0] == '\0') seterr(err, errlen, "%s", msg);
}

static void put_be32(unsigned char *p, unsigned long v) {
    p[0] = (unsigned char)((v >> 24) & 0xffUL);
    p[1] = (unsigned char)((v >> 16) & 0xffUL);
    p[2] = (unsigned char)((v >> 8) & 0xffUL);
    p[3] = (unsigned char)(v & 0xffUL);
}

static unsigned long get_be32(const unsigned char *p) {
    return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16) |
           ((unsigned long)p[2] << 8) | (unsigned long)p[3];
}

/* Emit one chunk: 4-byte big-endian length, 4-byte type, data, CRC. */
static int write_chunk(FILE *f, const char type[4], const unsigned char *data,
                       unsigned long len, char *err, size_t errlen) {
    unsigned char head[8], tail[4];
    put_be32(head, len);
    memcpy(head + 4, type, 4);
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef *)type, 4);
    if (len) crc = crc32(crc, (const Bytef *)data, (uInt)len);
    put_be32(tail, (unsigned long)crc);
    if (fwrite(head, 1, 8, f) != 8 ||
        (len && fwrite(data, 1, (size_t)len, f) != (size_t)len) ||
        fwrite(tail, 1, 4, f) != 4) {
        seterr(err, errlen, "short PNG chunk write");
        return -1;
    }
    return 0;
}

int png_write_rgb(const char *path, const unsigned char *rgb,
                  size_t width, size_t height, char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!path || !*path || !rgb || !width || !height) {
        seterr(err, errlen, "png_write_rgb needs path, rgb and non-zero dimensions");
        return -1;
    }
#if SIZE_MAX > 0xffffffffULL
    if ((unsigned long long)width > 0xffffffffULL ||
        (unsigned long long)height > 0xffffffffULL) {
        seterr(err, errlen, "PNG dimensions exceed the 32-bit IHDR limit");
        return -1;
    }
#endif
    if (width > SIZE_MAX / 3u / height) {
        seterr(err, errlen, "width*height*3 overflows size_t");
        return -1;
    }
    size_t stride = width * 3u;
    if (height > SIZE_MAX / (stride + 1u)) {
        seterr(err, errlen, "PNG raw scanline buffer overflows size_t");
        return -1;
    }
    size_t raw_len = height * (stride + 1u);
    if (raw_len > (size_t)PNG_CHUNK_MAX) {
        seterr(err, errlen, "image too large for a single IDAT chunk");
        return -1;
    }
    uLongf bound = compressBound((uLong)raw_len);
    if ((unsigned long)bound > PNG_CHUNK_MAX) {
        seterr(err, errlen, "compressed image too large for a single IDAT chunk");
        return -1;
    }

    int rc = -1;
    unsigned char *raw = NULL, *z = NULL;
    FILE *f = NULL;
    raw = (unsigned char *)malloc(raw_len);
    z = (unsigned char *)malloc((size_t)bound);
    if (!raw || !z) {
        seterr(err, errlen, "out of memory building PNG scanlines");
        goto done;
    }
    for (size_t y = 0; y < height; y++) {
        unsigned char *dst = raw + y * (stride + 1u);
        dst[0] = 0u; /* filter type 0 (None) */
        memcpy(dst + 1u, rgb + y * stride, stride);
    }
    uLongf zlen = bound;
    if (compress2(z, &zlen, raw, (uLong)raw_len, Z_BEST_COMPRESSION) != Z_OK) {
        seterr(err, errlen, "zlib compress2 failed");
        goto done;
    }

    f = fopen(path, "wb");
    if (!f) {
        seterr(err, errlen, "cannot open PNG output '%s'", path);
        goto done;
    }
    if (fwrite(PNG_SIG, 1, 8, f) != 8) {
        seterr(err, errlen, "short PNG signature write");
        goto write_fail;
    }
    unsigned char ihdr[13];
    put_be32(ihdr, (unsigned long)width);
    put_be32(ihdr + 4, (unsigned long)height);
    ihdr[8] = 8u;  /* bit depth */
    ihdr[9] = 2u;  /* colour type 2 = RGB */
    ihdr[10] = 0u; /* compression 0 */
    ihdr[11] = 0u; /* filter method 0 */
    ihdr[12] = 0u; /* interlace 0 */
    if (write_chunk(f, "IHDR", ihdr, 13u, err, errlen) != 0 ||
        write_chunk(f, "IDAT", z, (unsigned long)zlen, err, errlen) != 0 ||
        write_chunk(f, "IEND", NULL, 0u, err, errlen) != 0)
        goto write_fail;
    if (fclose(f) != 0) {
        f = NULL;
        seterr(err, errlen, "failed to close PNG output '%s'", path);
        goto write_fail;
    }
    f = NULL;
    rc = 0;
    goto done;

write_fail:
    if (f) fclose(f);
    remove(path); /* never leave a partial file behind */
    seterr_if_empty(err, errlen, "PNG write failed");
done:
    free(z);
    free(raw);
    return rc;
}

/* Grow an IDAT accumulator, rejecting size_t and PNG chunk-limit overflow. */
static int append_idat(unsigned char **buf, size_t *len, size_t *cap,
                       const unsigned char *data, size_t n) {
    if (n > (size_t)PNG_CHUNK_MAX || n > SIZE_MAX - *len ||
        *len + n > (size_t)PNG_CHUNK_MAX) return -1;
    size_t need = *len + n;
    if (need > *cap) {
        size_t newcap = *cap ? *cap : 256u;
        while (newcap < need) {
            if (newcap > SIZE_MAX / 2u) { newcap = need; break; }
            newcap *= 2u;
        }
        unsigned char *p = (unsigned char *)realloc(*buf, newcap);
        if (!p) return -1;
        *buf = p;
        *cap = newcap;
    }
    if (n) memcpy(*buf + *len, data, n);
    *len = need;
    return 0;
}

int png_read_rgb(const char *path, unsigned char **rgb_out,
                 size_t *width, size_t *height, char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!path || !*path || !rgb_out || !width || !height) {
        seterr(err, errlen, "png_read_rgb needs path and all outputs");
        return -1;
    }
    *rgb_out = NULL;
    *width = 0;
    *height = 0;

    int rc = -1;
    FILE *f = NULL;
    unsigned char sig[8], head[8], crc_bytes[4], ihdr[13];
    unsigned char *data = NULL, *idat = NULL, *raw = NULL, *rgb = NULL;
    size_t idat_len = 0, idat_cap = 0;
    size_t w = 0, h = 0;
    int seen_ihdr = 0, seen_idat = 0, seen_iend = 0;

    f = fopen(path, "rb");
    if (!f) {
        seterr(err, errlen, "cannot open PNG '%s'", path);
        goto done;
    }
    if (fread(sig, 1, 8, f) != 8 || memcmp(sig, PNG_SIG, 8) != 0) {
        seterr(err, errlen, "bad PNG signature");
        goto done;
    }
    for (;;) {
        if (fread(head, 1, 8, f) != 8) {
            seterr(err, errlen, "truncated PNG chunk header");
            goto done;
        }
        unsigned long len = get_be32(head);
        unsigned long type = get_be32(head + 4);
        if (len > PNG_CHUNK_MAX) {
            seterr(err, errlen, "PNG chunk length exceeds the 31-bit limit");
            goto done;
        }
        if (!seen_ihdr && type != T_IHDR) {
            seterr(err, errlen, "IHDR must be the first PNG chunk");
            goto done;
        }
        if (seen_iend || (type == T_IHDR && seen_ihdr)) {
            seterr(err, errlen, "unexpected PNG chunk after IEND or second IHDR");
            goto done;
        }
        data = NULL;
        if (len) {
            data = (unsigned char *)malloc((size_t)len);
            if (!data || fread(data, 1, (size_t)len, f) != (size_t)len) {
                seterr(err, errlen, "truncated PNG chunk data");
                goto done;
            }
        }
        if (fread(crc_bytes, 1, 4, f) != 4) {
            seterr(err, errlen, "truncated PNG chunk CRC");
            goto done;
        }
        uLong crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, (const Bytef *)(head + 4), 4);
        if (len) crc = crc32(crc, (const Bytef *)data, (uInt)len);
        if (get_be32(crc_bytes) != (unsigned long)crc) {
            seterr(err, errlen, "PNG chunk CRC mismatch");
            goto done;
        }

        if (type == T_IHDR) {
            if (len != 13u) {
                seterr(err, errlen, "IHDR must be 13 bytes");
                goto done;
            }
            memcpy(ihdr, data, 13u);
            seen_ihdr = 1;
        } else if (type == T_IDAT) {
            if (append_idat(&idat, &idat_len, &idat_cap, data, (size_t)len) != 0) {
                seterr(err, errlen, "IDAT data too large or out of memory");
                goto done;
            }
            seen_idat = 1;
        } else if (type == T_IEND) {
            if (len != 0u || !seen_idat) {
                seterr(err, errlen, "IEND must be zero-length and follow IDAT");
                goto done;
            }
            seen_iend = 1;
        } else if ((type & 0x20000000UL) == 0) {
            /* Ancillary chunks are skipped; unknown critical ones are fatal. */
            seterr(err, errlen, "unknown critical PNG chunk type");
            goto done;
        }
        free(data);
        data = NULL;
        if (seen_iend) {
            if (fgetc(f) != EOF) {
                seterr(err, errlen, "trailing garbage after IEND");
                goto done;
            }
            break;
        }
    }

    if (!seen_ihdr || !seen_idat || !seen_iend) {
        seterr(err, errlen, "PNG needs IHDR, IDAT and IEND");
        goto done;
    }
    w = get_be32(ihdr);
    h = get_be32(ihdr + 4);
    if (w == 0u || h == 0u || ihdr[8] != 8u || ihdr[9] != 2u ||
        ihdr[10] != 0u || ihdr[11] != 0u || ihdr[12] != 0u) {
        seterr(err, errlen, "IHDR must be non-zero 8-bit RGB, unfiltered, non-interlaced");
        goto done;
    }
    if (w > SIZE_MAX / 3u || h > SIZE_MAX / (w * 3u)) {
        seterr(err, errlen, "PNG dimensions overflow size_t");
        goto done;
    }
    size_t stride = w * 3u;
    if (h > SIZE_MAX / (stride + 1u)) {
        seterr(err, errlen, "PNG scanline buffer overflows size_t");
        goto done;
    }
    size_t raw_len = h * (stride + 1u);
    size_t rgb_len = h * stride;
    raw = (unsigned char *)malloc(raw_len);
    rgb = (unsigned char *)malloc(rgb_len);
    if (!raw || !rgb) {
        seterr(err, errlen, "out of memory decoding PNG");
        goto done;
    }
    uLongf outlen = (uLongf)raw_len;
    if (uncompress(raw, &outlen, (const Bytef *)idat, (uLong)idat_len) != Z_OK ||
        (size_t)outlen != raw_len) {
        seterr(err, errlen, "IDAT does not inflate to the exact scanline size");
        goto done;
    }
    for (size_t y = 0; y < h; y++) {
        const unsigned char *row = raw + y * (stride + 1u);
        if (row[0] != 0u) {
            seterr(err, errlen, "unsupported PNG scanline filter");
            goto done;
        }
        memcpy(rgb + y * stride, row + 1u, stride);
    }
    *rgb_out = rgb;
    *width = w;
    *height = h;
    rgb = NULL;
    rc = 0;

done:
    if (f) fclose(f);
    free(data);
    free(idat);
    free(raw);
    free(rgb);
    return rc;
}
