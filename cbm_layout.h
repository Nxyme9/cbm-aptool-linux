/* cbm_layout.h - CBM vendor MBR/partition layout validation
 * Validates the DJ_BOOT / DJ_OS / DJ_DATA partition window exposed by
 * the CBM2199E-class USB mass-storage controller.
 */
#ifndef CBM_LAYOUT_H
#define CBM_LAYOUT_H

#include <stddef.h>

#define CBM_SECTOR_SIZE 512
#define CBM_MBR_SIG_OFF 510
#define CBM_EXPECTED_WINDOW_SECTORS (28ULL * 1024 * 1024 * 1024 / CBM_SECTOR_SIZE)

typedef struct {
    unsigned char type;
    unsigned long long start_lba;
    unsigned long long size_lba;
} cbm_part_t;

typedef struct {
    unsigned long long disk_sectors;
    cbm_part_t parts[4];
    int part_count;
    int valid_mbr;
} cbm_layout_t;

/* Parse a 512-byte MBR buffer. Returns 0 on success. */
int cbm_layout_parse(const unsigned char *mbr, size_t len, cbm_layout_t *out);

/* Construct a nominal DJ layout (512M / 4G / remainder of window).
 * Returns 0 on success. LBA 2048, type/CHS conventions are nominal. */
int cbm_layout_construct(unsigned long long window_gib, unsigned char mbr[512], char *err, size_t errlen);

/* Validate the DJ partition layout (512M / 4G / remainder of the MBR window).
 * The constructed MBR window is 26..28 GiB (see cbm_layout_construct); the
 * accepted stick capacity is at least 28 GiB
 * (CBM_EXPECTED_WINDOW_SECTORS). Start LBAs must be ordered, non-overlapping
 * and wholly inside the disk. Returns 0 on a match. */
int cbm_layout_validate(const cbm_layout_t *layout, unsigned long long disk_sectors);

#endif /* CBM_LAYOUT_H */
