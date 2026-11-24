/* cbm_inspect.h - CBM container inspection utilities */
#ifndef CBM_INSPECT_H
#define CBM_INSPECT_H

#include <stddef.h>
#include <stdio.h>

/* Hex dump with ASCII sidebar. If max_bytes > 0, show first max_bytes/2
 * and last max_bytes/2 bytes (or all bytes when max_bytes >= len). If 0,
 * show all bytes. */
void cbm_inspect_hex(const unsigned char *buf, size_t len,
                     size_t max_bytes, FILE *out);

/* Extract runs of printable ASCII (0x20-0x7e) of length >= min_run.
 * Print offset and string. Never reads past buf+len. */
void cbm_inspect_strings(const unsigned char *buf, size_t len,
                         size_t min_run, FILE *out);

/* Print size, printable byte count, unique byte count, and Shannon entropy. */
void cbm_inspect_stats(const unsigned char *buf, size_t len, FILE *out);

/* Search for known tokens and report offset + token for each hit. */
void cbm_inspect_tokens(const unsigned char *buf, size_t len, FILE *out);

#endif /* CBM_INSPECT_H */
