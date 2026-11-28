/* cbm_layout.c - CBM vendor MBR/partition layout validation */
#include <stdio.h>
#include <string.h>
#include "cbm_layout.h"

static unsigned int rd32(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static void wr32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

/* Nominal DJ geometry conventions (NOT vendor measurements). The validator
 * checks sizes only; the start LBA, type bytes and zeroed CHS below are the
 * documented nominal layout from the frozen spec Design Note 2. */
#define DJ_BOOT_START_LBA   2048ULL      /* conventional 1 MiB alignment */
#define DJ_BOOT_SIZE_LBA    1048576ULL   /* 512 MiB FAT32 */
#define DJ_OS_SIZE_LBA      8388608ULL   /* 4 GiB ext4 */
#define DJ_BOOT_TYPE        0x0c         /* FAT32 LBA */
#define DJ_OS_TYPE          0x83         /* Linux / ext4 */
#define DJ_DATA_TYPE        0x07         /* exFAT */

int cbm_layout_construct(unsigned long long window_gib, unsigned char mbr[512],
                         char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!mbr) {
        if (err && errlen) snprintf(err, errlen, "MBR buffer is required");
        return -1;
    }
    if (window_gib < 26ULL || window_gib > 28ULL) {
        /* Supported DJ window is 26..28 GiB; refuse without touching mbr. */
        if (err && errlen)
            snprintf(err, errlen,
                     "window_gib %llu out of supported range 26..28", window_gib);
        return -1;
    }

    unsigned long long boot_start = DJ_BOOT_START_LBA;
    unsigned long long os_start   = boot_start + DJ_BOOT_SIZE_LBA;   /* 1050624 */
    unsigned long long data_start = os_start + DJ_OS_SIZE_LBA;       /* 9439232 */
    unsigned long long window_sectors = window_gib * 2097152ULL;     /* GiB -> 512B sectors */
    unsigned long long data_size  = window_sectors - data_start;     /* remainder of window */

    memset(mbr, 0, CBM_SECTOR_SIZE);

    unsigned char *e0 = mbr + 446;
    unsigned char *e1 = e0 + 16;
    unsigned char *e2 = e1 + 16;
    e0[4] = DJ_BOOT_TYPE; wr32(e0 + 8, (unsigned int)boot_start); wr32(e0 + 12, (unsigned int)DJ_BOOT_SIZE_LBA);
    e1[4] = DJ_OS_TYPE;   wr32(e1 + 8, (unsigned int)os_start);   wr32(e1 + 12, (unsigned int)DJ_OS_SIZE_LBA);
    e2[4] = DJ_DATA_TYPE; wr32(e2 + 8, (unsigned int)data_start); wr32(e2 + 12, (unsigned int)data_size);

    mbr[CBM_MBR_SIG_OFF]     = 0x55;
    mbr[CBM_MBR_SIG_OFF + 1] = 0xaa;
    return 0;
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
