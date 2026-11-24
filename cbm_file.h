/* cbm_file.h - file-level CBM container I/O (regular file or block device) */
#ifndef CBM_FILE_H
#define CBM_FILE_H

#include <stddef.h>

/* Read len bytes at absolute byte offset into buf. Returns 0 on success, -1 on error. */
int cbm_file_read(const char *path, long long offset,
                  unsigned char *buf, size_t len);

/* Write len bytes from buf at absolute byte offset. Block-device targets use
 * paced writes (40 MiB bursts / 45 s cooldown); regular files are written
 * directly. Returns 0 on success, -1 on error. */
int cbm_file_write(const char *path, long long offset,
                   const unsigned char *buf, size_t len);

/* Return 1 when path is a block device, 0 otherwise (including stat failure). */
int cbm_file_is_blockdev(const char *path);

#endif /* CBM_FILE_H */
