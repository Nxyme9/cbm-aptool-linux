/* nand_info.h - NAND controller identity probe (host-observable)
 *
 * The CBM2199E-class NAND controller (BCH ECC + balanced erase/wear
 * levelling) runs inside the USB stick firmware. From the Linux host we
 * cannot execute its ECC/erase policy; we CAN prove we are bound to the
 * correct controller class by reading sysfs USB identity + driver binding
 * and by validating the exposed partition geometry (cbm_layout).
 */
#ifndef NAND_INFO_H
#define NAND_INFO_H

#include <stddef.h>

typedef struct {
    char vendor_id[8];
    char product_id[8];
    char driver[64];
    char vendor[64];
    char model[64];
    char sysfs_path[256];
} nand_info_t;

/* Join base and leaf with one '/' into dst. An empty leaf copies base.
 * Returns 0 on success with dst NUL-terminated; -1 when base is empty or
 * the result would not fit, leaving dst[0] == '\0' when dstlen > 0
 * (also for NULL args; a zero-length dst is never written). */
int nand_info_join_path(char *dst, size_t dstlen, const char *base, const char *leaf);

/* Probe sysfs for the block device's USB controller identity.
 * Returns 0 on success, -1 if the device is not USB-attached. */
int nand_info_probe(const char *block_dev, nand_info_t *info);

/* Return 1 when vendor/product id matches a known Chipsbank controller. */
int nand_info_is_chipsbank(const nand_info_t *info);

#endif /* NAND_INFO_H */
