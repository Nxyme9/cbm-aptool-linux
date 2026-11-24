/* test_layout.c - CBM vendor MBR/partition layout validation tests */
#include <stdio.h>
#include <string.h>

#include "cbm_layout.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

/* Build a synthetic MBR matching the observed DJ layout (512B/4G/21.5G). */
static void build_mbr(unsigned char *mbr, unsigned long long disk_sectors) {
    memset(mbr, 0, CBM_SECTOR_SIZE);
    /* partition table starts at 446 */
    /* part 1: type 0x0c? use 0x83 (Linux), start 2048, size 1048576 (512 MiB) */
    unsigned int starts[3] = {2048, 1050624, 9439232};
    unsigned int sizes[3]  = {1048576, 8388608, 45086720};
    for (int i = 0; i < 3; i++) {
        unsigned char *e = mbr + 446 + i * 16;
        e[0] = 0x80; /* bootable for first */
        if (i != 0) e[0] = 0;
        e[4] = 0x83; /* type */
        /* start LBA at offset 8 */
        unsigned int s = starts[i];
        e[8] = (unsigned char)(s & 0xff);
        e[9] = (unsigned char)((s >> 8) & 0xff);
        e[10] = (unsigned char)((s >> 16) & 0xff);
        e[11] = (unsigned char)((s >> 24) & 0xff);
        unsigned int z = sizes[i];
        e[12] = (unsigned char)(z & 0xff);
        e[13] = (unsigned char)((z >> 8) & 0xff);
        e[14] = (unsigned char)((z >> 16) & 0xff);
        e[15] = (unsigned char)((z >> 24) & 0xff);
    }
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    (void)disk_sectors;
}

static void test_parse_valid(void) {
    TEST("cbm_layout_parse valid MBR");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_mbr(mbr, 0);
    cbm_layout_t L;
    if (cbm_layout_parse(mbr, CBM_SECTOR_SIZE, &L) != 0) { FAIL("parse failed"); return; }
    if (!L.valid_mbr) { FAIL("valid_mbr false"); return; }
    if (L.part_count != 3) { FAIL("part_count != 3"); return; }
    if (L.parts[0].size_lba != 1048576) { FAIL("part0 size"); return; }
    if (L.parts[1].size_lba != 8388608) { FAIL("part1 size"); return; }
    if (L.parts[2].size_lba != 45086720) { FAIL("part2 size"); return; }
    PASS();
}

static void test_parse_bad_signature(void) {
    TEST("cbm_layout_parse bad signature rejected");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_mbr(mbr, 0);
    mbr[510] = 0x00;
    cbm_layout_t L;
    if (cbm_layout_parse(mbr, CBM_SECTOR_SIZE, &L) != -1) { FAIL("should reject"); return; }
    PASS();
}

static void test_validate_ok(void) {
    TEST("cbm_layout_validate ok");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_mbr(mbr, 0);
    cbm_layout_t L;
    cbm_layout_parse(mbr, CBM_SECTOR_SIZE, &L);
    unsigned long long disk = 1048576000ULL; /* ~500 GiB in sectors */
    if (cbm_layout_validate(&L, disk) != 0) { FAIL("validate failed"); return; }
    PASS();
}

static void test_validate_too_small_disk(void) {
    TEST("cbm_layout_validate rejects small disk");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_mbr(mbr, 0);
    cbm_layout_t L;
    cbm_layout_parse(mbr, CBM_SECTOR_SIZE, &L);
    if (cbm_layout_validate(&L, 1000) != -1) { FAIL("should reject"); return; }
    PASS();
}

static void test_validate_wrong_partcount(void) {
    TEST("cbm_layout_validate rejects wrong partcount");
    unsigned char mbr[CBM_SECTOR_SIZE];
    memset(mbr, 0, CBM_SECTOR_SIZE);
    /* only 2 partitions */
    for (int i = 0; i < 2; i++) {
        unsigned char *e = mbr + 446 + i * 16;
        e[4] = 0x83;
        unsigned int z = 1048576;
        e[12] = (unsigned char)(z & 0xff);
        e[13] = (unsigned char)((z >> 8) & 0xff);
        e[14] = (unsigned char)((z >> 16) & 0xff);
        e[15] = (unsigned char)((z >> 24) & 0xff);
    }
    mbr[510] = 0x55; mbr[511] = 0xaa;
    cbm_layout_t L;
    cbm_layout_parse(mbr, CBM_SECTOR_SIZE, &L);
    if (cbm_layout_validate(&L, 1048576000ULL) != -1) { FAIL("should reject"); return; }
    PASS();
}

int main(void) {
    printf("=== CBM Layout Tests ===\n");
    test_parse_valid();
    test_parse_bad_signature();
    test_validate_ok();
    test_validate_too_small_disk();
    test_validate_wrong_partcount();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
