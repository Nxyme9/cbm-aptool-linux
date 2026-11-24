/* cbm_file.c - file-level CBM container I/O implementation
 *
 * Regular files: stdio (fopen/fseeko/fread/fwrite).
 * Block devices:  open/pread/pwrite with 64-bit offsets, and paced writes
 *                 (40 MiB bursts, 45 s cooldown) for the write path.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "cbm_file.h"
#include "paced_write.h"

int cbm_file_is_blockdev(const char *path) {
    struct stat st;
    if (!path || stat(path, &st) != 0) return 0;
    return S_ISBLK(st.st_mode) ? 1 : 0;
}

/* ---- regular file path ------------------------------------------------ */

static int read_regular(const char *path, long long offset,
                        unsigned char *buf, size_t len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseeko(fp, (off_t)offset, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    size_t got = fread(buf, 1, len, fp);
    fclose(fp);
    return (got == len) ? 0 : -1;
}

static int write_regular(const char *path, long long offset,
                         const unsigned char *buf, size_t len) {
    /* Prefer in-place update of an existing file; create only when missing. */
    FILE *fp = fopen(path, "r+b");
    if (!fp) {
        int saved_errno = errno;
        if (saved_errno == ENOENT) fp = fopen(path, "w+b");
    }
    if (!fp) return -1;
    if (fseeko(fp, (off_t)offset, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    size_t put = fwrite(buf, 1, len, fp);
    int rc = (put == len && fflush(fp) == 0) ? 0 : -1;
    if (rc == 0 && fsync(fileno(fp)) != 0) rc = -1;
    if (fclose(fp) != 0) rc = -1;
    return rc;
}

/* ---- block device path ------------------------------------------------ */

static int read_blockdev(const char *path, long long offset,
                         unsigned char *buf, size_t len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t got_total = 0;
    while (got_total < len) {
        ssize_t got = pread(fd, buf + got_total, len - got_total,
                            (off_t)offset + (off_t)got_total);
        if (got < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (got == 0) break; /* EOF */
        got_total += (size_t)got;
    }
    close(fd);
    return (got_total == len) ? 0 : -1;
}

/* Context for the paced_write callback: destination fd and running offset. */
typedef struct {
    int fd;
    off_t offset;
} pwrite_ctx_t;

static int pwrite_chunk(const void *data, size_t len, void *ctx) {
    pwrite_ctx_t *c = (pwrite_ctx_t *)ctx;
    const unsigned char *p = (const unsigned char *)data;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t wrote = pwrite(c->fd, p, remaining, c->offset);
        if (wrote < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (wrote == 0) return -1; /* no progress */
        p += (size_t)wrote;
        c->offset += (off_t)wrote;
        remaining -= (size_t)wrote;
    }
    return 0;
}

static int write_blockdev(const char *path, long long offset,
                          const unsigned char *buf, size_t len) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;

    paced_writer_t pw;
    paced_init(&pw);
    pwrite_ctx_t ctx;
    ctx.fd = fd;
    ctx.offset = (off_t)offset;

    int rc = paced_write(&pw, buf, len, pwrite_chunk, &ctx);
    if (rc == 0 && fsync(fd) != 0) rc = -1;
    close(fd);
    return rc;
}

/* ---- public API ------------------------------------------------------- */

int cbm_file_read(const char *path, long long offset,
                  unsigned char *buf, size_t len) {
    if (!path || (!buf && len > 0) || offset < 0) return -1;
    if (len == 0) return 0;
    if (cbm_file_is_blockdev(path)) return read_blockdev(path, offset, buf, len);
    return read_regular(path, offset, buf, len);
}

int cbm_file_write(const char *path, long long offset,
                   const unsigned char *buf, size_t len) {
    if (!path || (!buf && len > 0) || offset < 0) return -1;
    if (len == 0) return 0;
    if (cbm_file_is_blockdev(path)) return write_blockdev(path, offset, buf, len);
    return write_regular(path, offset, buf, len);
}
