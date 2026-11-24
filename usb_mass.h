/* usb_mass.h - Linux USB mass-storage block device layer
 * Task 3 (AC #3): Linux USB mass-storage driver path.
 * Binds the native tool to a USB mass-storage block device node
 * (behind the Linux usb-storage / SCSI mass-storage driver) and
 * exposes byte-level read/write plus capacity query for the CBM
 * container payload.
 */
#ifndef USB_MASS_H
#define USB_MASS_H

#include <stddef.h>

typedef struct {
    int fd;              /* open block device fd, -1 when closed */
    long long capacity; /* device size in bytes, -1 when unknown */
} usb_mass_dev_t;

int usb_mass_open(const char *path, usb_mass_dev_t *dev);
int usb_mass_read(usb_mass_dev_t *dev, unsigned char *buf, size_t len);
int usb_mass_write(usb_mass_dev_t *dev, const unsigned char *buf, size_t len);
/* Offset-aware variants: absolute byte offset (sector-aligned for block devices). */
int usb_mass_read_at(usb_mass_dev_t *dev, unsigned char *buf, size_t len, long long offset);
int usb_mass_write_at(usb_mass_dev_t *dev, const unsigned char *buf, size_t len, long long offset);
long long usb_mass_capacity(const usb_mass_dev_t *dev);
void usb_mass_close(usb_mass_dev_t *dev);

#endif /* USB_MASS_H */
