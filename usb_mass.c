/* usb_mass.c - Linux USB mass-storage block device layer
 * Task 3 (AC #3): Linux USB mass-storage driver path.
 * Opens a USB mass-storage block device node (behind the Linux
 * usb-storage / SCSI mass-storage driver) and exposes byte-level
 * read/write plus capacity query for the CBM container payload.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "usb_mass.h"

int usb_mass_open(const char *path, usb_mass_dev_t *dev) {
    if (!dev) return -1;
    dev->fd = -1;
    dev->capacity = -1;
    if (!path) return -1;
    dev->fd = open(path, O_RDWR);
    if (dev->fd < 0) return -1;

    /* Block devices return -1 from lseek(fd, 0, SEEK_END); BLKGETSIZE64
     * is the authoritative host-side capacity query for usb-storage. */
    unsigned long long bytes = 0;
    if (ioctl(dev->fd, BLKGETSIZE64, &bytes) == 0) {
        dev->capacity = (long long)bytes;
    } else {
        long long end = (long long)lseek(dev->fd, 0, SEEK_END);
        if (end >= 0) {
            dev->capacity = end;
            lseek(dev->fd, 0, SEEK_SET);
        }
    }
    return 0;
}

int usb_mass_read_at(usb_mass_dev_t *dev, unsigned char *buf, size_t len, long long offset) {
    size_t done = 0;
    if (!dev || dev->fd < 0 || !buf || len == 0 || offset < 0) return -1;
    while (done < len) {
        ssize_t n = pread(dev->fd, buf + done, len - done,
                          (off_t)(offset + (long long)done));
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1; /* short file / unexpected EOF */
        done += (size_t)n;
    }
    return 0;
}

int usb_mass_write_at(usb_mass_dev_t *dev, const unsigned char *buf, size_t len, long long offset) {
    size_t done = 0;
    if (!dev || dev->fd < 0 || !buf || len == 0 || offset < 0) return -1;
    while (done < len) {
        ssize_t n = pwrite(dev->fd, buf + done, len - done,
                           (off_t)(offset + (long long)done));
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1; /* no progress: avoid an endless loop */
        done += (size_t)n;
    }
    return 0;
}

int usb_mass_read(usb_mass_dev_t *dev, unsigned char *buf, size_t len) {
    return usb_mass_read_at(dev, buf, len, 0);
}

int usb_mass_write(usb_mass_dev_t *dev, const unsigned char *buf, size_t len) {
    return usb_mass_write_at(dev, buf, len, 0);
}

long long usb_mass_capacity(const usb_mass_dev_t *dev) {
    if (!dev) return -1;
    return dev->capacity;
}

void usb_mass_close(usb_mass_dev_t *dev) {
    if (!dev) return;
    if (dev->fd >= 0) close(dev->fd);
    dev->fd = -1;
}
