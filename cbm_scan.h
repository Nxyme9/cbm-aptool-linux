/* cbm_scan.h - read-only, offline CBM container forensic scanner
 *
 * Detection is two-stage: candidate offsets come from (a) an optional
 * case-sensitive raw magic-string search and (b) an optional structural probe
 * at every 512-byte-aligned ABSOLUTE offset; each candidate is then subjected
 * to a full 85688-byte parse, TEA decrypt and HEURISTIC plausibility gate
 * (structural candidates get a cheap decrypted-prefix screen first; magic
 * candidates are never screened out before the full gate). The gate also
 * anchors container boundaries via decrypted head/tail printable density,
 * because this cipher can self-synchronise on shifted windows.
 * Hits are CANDIDATES, never "confirmed containers": no magic value is known
 * for this format (docs/container-format.md:64), so "cbmv1001" and any other
 * configured magic are UNVERIFIED and purely advisory. Do not claim
 * completeness: only 512-byte-aligned starts are probed structurally.
 *
 * Never writes to the scanned image or device. All reads are bounded by the
 * buffer length or the requested absolute byte range; offsets are 64-bit.
 */
#ifndef CBM_SCAN_H
#define CBM_SCAN_H

#include <stddef.h>
#include <stdio.h>

/* One candidate container. Offsets are absolute byte offsets in the image;
 * token_offsets are relative to the start of the DECRYPTED body. Tokens are
 * NUL-terminated printable runs (0x20-0x7e, length >= 4, truncated to 63
 * characters) from the decrypted body, at most 8, in ascending body order.
 * sha256 is the digest of the ENCRYPTED 85688-byte container. */
typedef struct {
    unsigned long long offset;
    unsigned char header;
    double entropy;
    unsigned char sha256[32];
    char tokens[8][64];
    unsigned long long token_offsets[8];
    size_t token_count;
} cbm_scan_hit_t;

/* Scan one contiguous buffer. Returns the number of hits written, capped at
 * max; returns 0 under any error or zero-match condition: null `buf` or `out`,
 * `max == 0`, buffer `len` shorter than one container (85688 bytes), bad computed
 * body length, uninitialized crypto, allocation failure, or zero candidates/gate
 * rejections. CALLERS MUST TREAT 0 AS “NO CANDIDATES IN THIS BUFFER”, NOT AS A
 * GUARANTEE THAT THE BUFFER IS CLEAN. Note: cbm_scan_buffer itself does not
 * suppress shifted self-synchronised duplicate hits; cluster suppression is
 * performed exclusively by cbm_scan_image across chunk boundaries.
 * base_offset is the buffer's absolute byte offset... */
size_t cbm_scan_buffer(const unsigned char *buf, size_t len,
                       const char *const *magics, size_t nmagic,
                       int structural, unsigned long long base_offset,
                       cbm_scan_hit_t *out, size_t max);

/* Scan the inclusive absolute byte range [start_byte, end_byte] of path in
 * chunk_bytes-sized chunks that overlap by 2 * 85688 + 512 = 171888 bytes
 * (two containers plus one LBA), so a container straddling any chunk boundary
 * is parsed in full and the overlap is wide enough to hold a whole earlier
 * container for dedupe. A container is reported only when its whole 85688
 * bytes lie inside the requested range. On success
 * returns 0, sets *out to a malloc'd ascending-offset hit array and *out_count
 * to its length (caller frees with cbm_scan_free_hits). Returns -1 on error
 * with a message in err when err/errlen are non-zero. chunk_bytes must exceed
 * the 171888-byte overlap (two containers plus one LBA). Uses cbm_file_read
 * only (regular files and block devices), never cbm_file_write. Delegates to
 * cbm_scan_image_ex with suppress_clusters = 1 (legacy dedupe). */
int cbm_scan_image(const char *path, unsigned long long start_byte,
                   unsigned long long end_byte, size_t chunk_bytes,
                   const char *const *magics, size_t nmagic,
                   cbm_scan_hit_t **out, size_t *out_count,
                   char *err, size_t errlen);

/* Identical to cbm_scan_image except for cluster suppression. With
 * suppress_clusters != 0 (the legacy default) only the lowest offset of each
 * group of candidates closer than one 85688-byte container is kept, so two
 * genuinely distinct containers started close together collapse to one hit.
 * With suppress_clusters == 0 every candidate is kept in ascending-offset
 * order, including all candidates in that close group. The hit-array contract,
 * error contract, bounds checks and 171888-byte chunk overlap are unchanged. */
int cbm_scan_image_ex(const char *path, unsigned long long start_byte,
                      unsigned long long end_byte, size_t chunk_bytes,
                      const char *const *magics, size_t nmagic,
                      int suppress_clusters,
                      cbm_scan_hit_t **out, size_t *out_count,
                      char *err, size_t errlen);

/* Free a hit array returned by cbm_scan_image (safe on NULL). */
void cbm_scan_free_hits(cbm_scan_hit_t *hits);

/* Print one deterministic, locale-independent row per hit to out:
 * "offset header %u.%06u sha256hex token_count [offset:token]...". Entropy is
 * fixed-point with exactly six decimals after a literal '.', never %.6f.
 * Hits are printed in the order supplied (ascending offset from
 * cbm_scan_image). No-op when out is NULL. */
void cbm_scan_print(FILE *out, const cbm_scan_hit_t *hits, size_t n);

#endif /* CBM_SCAN_H */
