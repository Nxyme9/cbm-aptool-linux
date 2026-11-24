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

static unsigned int fixture_rd32(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

/* Nominal constructor: byte-exact, stable, and accepted by the existing
 * validator. The byte values are conventions from the frozen spec, NOT
 * measurements recovered from a vendor stick. */
static void test_construct_nominal_stable_and_valid(void) {
    TEST("cbm_layout_construct: nominal bytes stable and validator accepts candidate");
    unsigned char a[CBM_SECTOR_SIZE], b[CBM_SECTOR_SIZE];
    char err[128] = {0};
    if (cbm_layout_construct(26ULL, a, err, sizeof(err)) != 0) {
        FAIL("26 GiB construction failed"); return;
    }
    if (cbm_layout_construct(26ULL, b, err, sizeof(err)) != 0) {
        FAIL("second construction failed"); return;
    }
    if (memcmp(a, b, sizeof(a)) != 0) { FAIL("constructor not deterministic"); return; }
    if (a[510] != 0x55 || a[511] != 0xaa) { FAIL("signature"); return; }
    const unsigned char *e0 = a + 446;
    const unsigned char *e1 = e0 + 16;
    const unsigned char *e2 = e1 + 16;
    if (e0[0] != 0 || e1[0] != 0 || e2[0] != 0) { FAIL("boot flag must be 0"); return; }
    for (int i = 0; i < 3; i++) {
        const unsigned char *e = a + 446 + i * 16;
        for (int k = 1; k <= 3; k++) if (e[k] != 0) { FAIL("CHS must be zero"); return; }
        for (int k = 5; k <= 7; k++) if (e[k] != 0) { FAIL("CHS must be zero"); return; }
    }
    if (e0[4] != 0x0c || e1[4] != 0x83 || e2[4] != 0x07) { FAIL("type bytes"); return; }
    if (fixture_rd32(e0 + 8) != 2048u || fixture_rd32(e0 + 12) != 1048576u ||
        fixture_rd32(e1 + 8) != 1050624u || fixture_rd32(e1 + 12) != 8388608u ||
        fixture_rd32(e2 + 8) != 9439232u || fixture_rd32(e2 + 12) != 45086720u) {
        FAIL("start/size LBAs"); return;
    }
    cbm_layout_t L;
    if (cbm_layout_parse(a, CBM_SECTOR_SIZE, &L) != 0) { FAIL("parse candidate"); return; }
    if (cbm_layout_validate(&L, CBM_EXPECTED_WINDOW_SECTORS) != 0) {
        FAIL("validate candidate"); return;
    }
    PASS();
}

static void test_construct_27_window_validates(void) {
    TEST("cbm_layout_construct: 27 GiB window validates with honest floored disk size");
    unsigned char mbr[CBM_SECTOR_SIZE];
    char err[128] = {0};
    if (cbm_layout_construct(27ULL, mbr, err, sizeof(err)) != 0) {
        FAIL("27 GiB construction failed"); return;
    }
    cbm_layout_t L;
    if (cbm_layout_parse(mbr, CBM_SECTOR_SIZE, &L) != 0) { FAIL("parse"); return; }
    const unsigned long long expect_data = 27ULL * 2097152ULL - 9439232ULL;
    if (L.parts[2].size_lba != expect_data) { FAIL("27 GiB data remainder"); return; }
    if (cbm_layout_validate(&L, CBM_EXPECTED_WINDOW_SECTORS) != 0) {
        FAIL("27 GiB candidate must validate"); return;
    }
    PASS();
}

static void test_construct_rejects_out_of_window(void) {
    TEST("cbm_layout_construct: 29 GiB honestly rejected, buffer untouched");
    unsigned char mbr[CBM_SECTOR_SIZE];
    char err[128] = {0};
    memset(mbr, 0xa5, sizeof(mbr));
    if (cbm_layout_construct(29ULL, mbr, err, sizeof(err)) == 0) {
        FAIL("out-of-window must be rejected"); return;
    }
    if (!strstr(err, "26..28")) { FAIL("error must name supported window"); return; }
    for (size_t i = 0; i < sizeof(mbr); i++) {
        if (mbr[i] != 0xa5) { FAIL("buffer changed on rejection"); return; }
    }
    PASS();
}

int main(void) {
    printf("=== CBM Layout Tests ===\n");
    test_parse_valid();
    test_parse_bad_signature();
    test_validate_ok();
    test_validate_too_small_disk();
    test_validate_wrong_partcount();
    test_construct_nominal_stable_and_valid();
    test_construct_27_window_validates();
    test_construct_rejects_out_of_window();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
