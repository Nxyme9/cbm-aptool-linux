/* png_write.h - minimal 8-bit RGB PNG encoder and its test-side decoder.
 *
 * The encoder is self-written: signature, IHDR, one IDAT (zlib compress2 at
 * Z_BEST_COMPRESSION over filter-0 scanlines) and IEND, with every chunk CRC
 * computed by zlib crc32. No external image library is used. The decoder uses
 * only zlib + stdio and never touches the source image.
 *
 * Heatmap image mapping (also documented in README.md and the CLI usage):
 * the downsampled samples form a row-major grid, pixel index y*width + x,
 * filled left-to-right then top-to-bottom. For n samples,
 *   height = clamp(ceil(n / width), 1, max(1, CBM_HEATMAP_MAX_PIXELS/width))
 * with n == 0 giving height 1 (a valid grey image). The pixel count is capped
 * at CBM_HEATMAP_MAX_PIXELS (1 Mi pixels), bounding the pixel array at ~59 MB
 * and the packed RGB buffer at ~3 MB.
 */
#ifndef PNG_WRITE_H
#define PNG_WRITE_H

#include <stddef.h>

/* 1 Mi pixels: the hard upper bound on width*height for a heatmap image. */
#define CBM_HEATMAP_MAX_PIXELS ((size_t)1024u * (size_t)1024u)

/* Write an 8-bit RGB PNG (colour type 2, bit depth 8, no interlace) to path.
 * Rejects NULL rgb, zero dimensions and dimensions whose width*height*3
 * product overflows size_t. Returns 0 on success, -1 on failure with a
 * message in err when err/errlen are non-zero. A partial file is removed. */
int png_write_rgb(const char *path, const unsigned char *rgb,
                  size_t width, size_t height, char *err, size_t errlen);

/* Decode a PNG produced by png_write_rgb: verify the signature, walk chunks,
 * verify every CRC, require IHDR first and IEND last, accept one or more IDAT
 * chunks, inflate them, require exactly height*(1+width*3) raw bytes and a
 * zero filter byte on every scanline. Returns a malloc'd width*height*3 RGB
 * buffer (caller frees with free) and sets the width and height outputs. Returns 0 on
 * success, -1 on failure with a message in err. */
int png_read_rgb(const char *path, unsigned char **rgb_out,
                 size_t *width, size_t *height, char *err, size_t errlen);

#endif /* PNG_WRITE_H */
