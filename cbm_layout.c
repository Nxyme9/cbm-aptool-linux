/* cbm_layout.c - CBM vendor MBR/partition layout validation */
#include <string.h>
#include "cbm_layout.h"

static unsigned int rd32(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

int cbm_layout_parse(const unsigned char *mbr, size_t len, cbm_layout_t *out) {
    if (!mbr || !out || len < CBM_SECTOR_SIZE) return -1;
    memset(out, 0, sizeof(*out));
    out->disk_sectors = 0;
    out->valid_mbr = (mbr[CBM_MBR_SIG_OFF] == 0x55 && mbr[CBM_MBR_SIG_OFF + 1] == 0xaa);
    if (!out->valid_mbr) return -1;

    for (int i = 0; i < 4; i++) {
        const unsigned char *e = mbr + 446 + (i * 16);
        unsigned int type = e[4];
        unsigned long long start = rd32(e + 8);
        unsigned long long size = rd32(e + 12);
        if (type == 0 || size == 0) continue;
        out->parts[out->part_count].type = (unsigned char)type;
        out->parts[out->part_count].start_lba = start;
        out->parts[out->part_count].size_lba = size;
        out->part_count++;
    }
    return 0;
}

int cbm_layout_validate(const cbm_layout_t *layout, unsigned long long disk_sectors) {
    if (!layout || !layout->valid_mbr || layout->part_count != 3) return -1;
    if (disk_sectors == 0 || disk_sectors < CBM_EXPECTED_WINDOW_SECTORS) return -1;

    /* DJ_BOOT 512 MiB, DJ_OS 4 GiB, DJ_DATA remainder of ~26 GiB window. */
    unsigned long long boot = layout->parts[0].size_lba * CBM_SECTOR_SIZE;
    unsigned long long os   = layout->parts[1].size_lba * CBM_SECTOR_SIZE;
    unsigned long long data = layout->parts[2].size_lba * CBM_SECTOR_SIZE;
    const unsigned long long MiB = 1024ULL * 1024;
    const unsigned long long GiB = 1024ULL * MiB;

    if (boot < 500 * MiB || boot > 520 * MiB) return -1;
    if (os   < 3 * GiB   || os   > 5 * GiB)   return -1;
    if (data < 15 * GiB  || data > 28 * GiB)  return -1;
    return 0;
}
