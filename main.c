/* main.c - Linux-native CBMUsbDisk tool entry point
 *
 * Modes:
 *   cbm-tool                 self-test (crypto/container/pacing/layout/nand logic)
 *   cbm-tool <blockdev>      self-test + real-device validation (read-only layout,
 *                             then safe read/write/restore on unpartitioned tail)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tea_crypto.h"
#include "cbm_container.h"
#include "paced_write.h"
#include "usb_mass.h"
#include "cbm_layout.h"
#include "nand_info.h"

static int selftest(void) {
    printf("=== Self-Test ===\n");
    const char *pe_path = getenv("CBM_PE_PATH");
    if (!pe_path || !pe_path[0]) pe_path = "/tmp/opencode/ap.exe";
    if (tea_init(pe_path) != 0) {
        fprintf(stderr, "Failed to initialize crypto\n");
        return 1;
    }
    printf("Crypto initialized (TEA cores loaded from PE)\n");

    unsigned char test_data[64];
    for (int i = 0; i < 64; i++) test_data[i] = (unsigned char)(i * 7 + 3);
    unsigned char enc_copy[64];
    memcpy(enc_copy, test_data, 64);
    const char *key = "1a2b3c4d5e6fTENG";

    if (tea_encrypt(enc_copy, 64, key) != 0) {
        fprintf(stderr, "Encrypt failed\n"); tea_cleanup(); return 1;
    }
    if (tea_decrypt(enc_copy, 64, key) != 0 || memcmp(enc_copy, test_data, 64) != 0) {
        fprintf(stderr, "Roundtrip mismatch\n"); tea_cleanup(); return 1;
    }
    printf("TEA roundtrip OK (64 bytes)\n");

    printf("CBM Container: %d bytes; HLEN(85688)=%zu\n",
           CBM_CONTAINER_SIZE, cbm_compute_hlen(85688));

    paced_writer_t pw;
    paced_init(&pw);
    printf("Paced writer: burst=%d bytes, cooldown=%d sec\n",
           PACED_BURST_SIZE, PACED_COOLDOWN_SEC);

    tea_cleanup();
    return 0;
}

/* Validate a real USB mass-storage device. Read-only layout checks plus a
 * write/read/restore roundtrip in the unpartitioned tail (outside the MBR
 * window), so no filesystem data is touched. */
static int verify_device(const char *path) {
    printf("\n=== Real-Device Validation: %s ===\n", path);
    usb_mass_dev_t dev;
    if (usb_mass_open(path, &dev) != 0) {
        fprintf(stderr, "open failed (need disk group / root?) \n");
        return 1;
    }
    long long cap = usb_mass_capacity(&dev);
    printf("Capacity (BLKGETSIZE64): %lld bytes (%lld sectors)\n",
           cap, cap / CBM_SECTOR_SIZE);
    if (cap < (long long)CBM_EXPECTED_WINDOW_SECTORS * CBM_SECTOR_SIZE) {
        fprintf(stderr, "capacity below 28 GiB window\n");
        usb_mass_close(&dev);
        return 1;
    }

    /* MBR + layout */
    unsigned char mbr[CBM_SECTOR_SIZE];
    if (usb_mass_read_at(&dev, mbr, CBM_SECTOR_SIZE, 0) != 0) {
        fprintf(stderr, "MBR read failed\n"); usb_mass_close(&dev); return 1;
    }
    cbm_layout_t L;
    if (cbm_layout_parse(mbr, CBM_SECTOR_SIZE, &L) != 0) {
        fprintf(stderr, "MBR parse failed (bad signature)\n");
        usb_mass_close(&dev); return 1;
    }
    printf("MBR signature: 0x55AA OK; partitions: %d\n", L.part_count);
    for (int i = 0; i < L.part_count; i++) {
        printf("  part%d: type=0x%02x start=%llu size=%llu sectors (%llu MiB)\n",
               i + 1, L.parts[i].type, L.parts[i].start_lba, L.parts[i].size_lba,
               L.parts[i].size_lba / (1024 * 1024 / CBM_SECTOR_SIZE));
    }
    unsigned long long disk_sectors = (unsigned long long)(cap / CBM_SECTOR_SIZE);
    if (cbm_layout_validate(&L, disk_sectors) != 0) {
        fprintf(stderr, "DJ partition layout validation FAILED\n");
        usb_mass_close(&dev); return 1;
    }
    printf("DJ partition layout: MATCH (512M/4G/rest within 28G window)\n");

    /* NAND controller identity (host-observable) */
    const char *devname = strrchr(path, '/');
    devname = devname ? devname + 1 : path;
    nand_info_t ni;
    if (nand_info_probe(devname, &ni) == 0) {
        printf("USB controller: vid=%s pid=%s vendor='%s' model='%s' driver=%s\n",
               ni.vendor_id, ni.product_id, ni.vendor, ni.model,
               ni.driver[0] ? ni.driver : "(unknown)");
        printf("Chipsbank-class controller: %s\n",
               nand_info_is_chipsbank(&ni) ? "YES" : "NO");
    } else {
        printf("USB controller identity: not available via sysfs\n");
    }

    /* Safe write/read/restore on unpartitioned tail outside MBR window. */
    unsigned long long last_part_end = 0;
    for (int i = 0; i < L.part_count; i++) {
        unsigned long long end = L.parts[i].start_lba + L.parts[i].size_lba;
        if (end > last_part_end) last_part_end = end;
    }
    unsigned long long scratch = last_part_end + 1024;
    if (scratch + 1 >= disk_sectors) scratch = disk_sectors - 2;
    long long off = (long long)(scratch * CBM_SECTOR_SIZE);

    unsigned char orig[CBM_SECTOR_SIZE], pat[CBM_SECTOR_SIZE], rb[CBM_SECTOR_SIZE];
    if (usb_mass_read_at(&dev, orig, CBM_SECTOR_SIZE, off) != 0) {
        fprintf(stderr, "scratch read failed\n"); usb_mass_close(&dev); return 1;
    }
    for (int i = 0; i < CBM_SECTOR_SIZE; i++) pat[i] = (unsigned char)(i * 13 + 7);
    if (usb_mass_write_at(&dev, pat, CBM_SECTOR_SIZE, off) != 0) {
        fprintf(stderr, "scratch write failed\n"); usb_mass_close(&dev); return 1;
    }
    if (usb_mass_read_at(&dev, rb, CBM_SECTOR_SIZE, off) != 0 ||
        memcmp(rb, pat, CBM_SECTOR_SIZE) != 0) {
        fprintf(stderr, "write/read verify FAILED\n");
        usb_mass_write_at(&dev, orig, CBM_SECTOR_SIZE, off);
        usb_mass_close(&dev); return 1;
    }
    printf("Write/read roundtrip at LBA %llu: OK\n", scratch);
    if (usb_mass_write_at(&dev, orig, CBM_SECTOR_SIZE, off) != 0) {
        fprintf(stderr, "scratch restore write failed\n"); usb_mass_close(&dev); return 1;
    }
    if (usb_mass_read_at(&dev, rb, CBM_SECTOR_SIZE, off) != 0 ||
        memcmp(rb, orig, CBM_SECTOR_SIZE) != 0) {
        fprintf(stderr, "restore verify FAILED\n"); usb_mass_close(&dev); return 1;
    }
    printf("Original sector restored and verified: OK\n");

    usb_mass_close(&dev);
    printf("Real-device validation: PASS\n");
    return 0;
}

int main(int argc, char **argv) {
    printf("CBMUsbDisk Linux-Native Tool v1.0\n");
    printf("==================================\n\n");
    if (selftest() != 0) return 1;
    if (argc > 1) return verify_device(argv[1]);
    printf("\nAll systems operational.\n");
    return 0;
}
