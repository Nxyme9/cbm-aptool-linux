/* cbm_scan_report.h - deterministic JSON reports and container carving
 * for the read-only forensic scanner (cbm_scan.h).
 *
 * Neither writer opens the scanned image for writing. JSON output is an
 * ordered array, one object per hit, with locale-independent numbers; carve
 * output is one exact-size file per hit under an explicitly supplied
 * directory. Both refuse any output path that resolves to the source image.
 */
#ifndef CBM_SCAN_REPORT_H
#define CBM_SCAN_REPORT_H

#include <stddef.h>

#include "cbm_scan.h"

/* Write hits as one JSON array to path (stdio, "wb"). Field order is fixed:
 * offset, header, entropy, sha256, tokens; each token object is
 * {"offset": <number>, "text": "<escaped string>"}. offset/header/token
 * offsets are unsigned decimal integers; entropy is fixed-point
 * <whole>.<6 digits> with a literal '.', never %.6f, so LC_NUMERIC cannot
 * change the bytes; sha256 is 64 lowercase hex digits; strings escape '"',
 * '\\', control characters as \b \f \n \r \t or \u00xx (lowercase hex).
 * A trailing LF terminates the document. Returns 0 on success, -1 on error
 * with a message in err when err/errlen are non-zero. */
int cbm_scan_write_json(const char *path, const cbm_scan_hit_t *hits,
                        size_t n, char *err, size_t errlen);

/* For each hit read exactly CBM_CONTAINER_SIZE bytes from source at
 * hit.offset (cbm_file_read, never a write) and write
 * <dir>/hit-NNN-<offset>.cbm via stdio, NNN = zero-padded 3-digit hit index.
 * Hits are in the order supplied (ascending offset from cbm_scan_image).
 * Creates dir with mkdir(0755) when missing; refuses block-device dirs,
 * paths that resolve to the source (realpath string match or identical
 * st_dev/st_ino), the source's own directory, and any individual output
 * file that resolves back to the source. Returns 0 on success, -1 on error
 * with a message in err when err/errlen are non-zero. Never writes source. */
int cbm_scan_carve(const char *dir, const char *source,
                   const cbm_scan_hit_t *hits, size_t n,
                   char *err, size_t errlen);

/* Shared pre-flight guard for CLI --json/--carve values: returns 0 when
 * path is safe to open for writing, -1 when path resolves to source (same
 * st_dev/st_ino when both exist, realpath string match, or path's parent
 * resolving to source) with a message in err. scan_mode calls this before
 * either writer and before opening any output. */
int cbm_scan_report_check_output(const char *path, const char *source,
                                 char *err, size_t errlen);

#endif /* CBM_SCAN_REPORT_H */
