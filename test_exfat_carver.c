/* test_exfat_carver.c - exFAT undelete carver tests
 *
 * Synthetic exFAT images only: scratch regular files under /tmp/opencode, no
 * device, no vendor binary. The test builds a tiny exFAT volume with an intact
 * deleted file, an overwritten (bitmap-reused) deleted file and a live file,
 * then checks the carver recovers only the intact one. Its own summary line is
 * outside the frozen `Results:` sums.
 */
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_file.h"
#include "cbm_layout.h"
#include "cli_json.h"

#include "exfat_carver.h"

static int tests_passed = 0;
static int tests_failed = 0;
static char g_root[128];

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() (printf("PASS\n"), tests_passed++)
#define FAIL(msg) (printf("FAIL: %s\n", msg), tests_failed++)

#define SECTOR 512u
#define IMAGE_SECTORS 16u
#define IMAGE_BYTES (IMAGE_SECTORS * SECTOR)
#define HEAP_SECTOR 9u
#define CLUSTER_BYTES SECTOR
#define DATA_START_LBA 9439232ULL /* nominal DJ_DATA start from cbm_layout */

static void path_of(char *out, size_t outlen, const char *sub) {
    snprintf(out, outlen, "%s/%s", g_root, sub);
}

static void put16(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
}

static void put32(unsigned char *p, unsigned long long v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

static void put64(unsigned char *p, unsigned long long v) {
    put32(p, v);
    put32(p + 4, v >> 32);
}

static unsigned char *cluster_ptr(unsigned char *img, unsigned long long cl) {
    return img + (HEAP_SECTOR + (unsigned)(cl - 2u)) * SECTOR;
}
/* Layout: cluster 2 = root dir, 3 = intact deleted data, 4 = overwritten
 * deleted data, 5 = allocation bitmap, 6 = live file data. cluster_count=5
 * means valid clusters 2..6. */

static void name_entry(unsigned char *e, const char *ascii) {
    memset(e, 0, 32);
    e[0] = 0xC1;
    size_t n = strlen(ascii);
    if (n > 15u) n = 15u;
    /* UTF-16LE name starts at offset 2; high bytes stay zero from memset. */
    for (size_t i = 0; i < n; i++) e[2 + (i * 2)] = (unsigned char)ascii[i];
}

static void stream_entry(unsigned char *e, unsigned long long cluster,
                         unsigned long long size) {
    memset(e, 0, 32);
    e[0] = 0xC0;
    e[1] = 0x02; /* NoFatChain: contiguous, metadata intact */
    put32(e + 4, cluster);
    put64(e + 8, size);
}

static void fill_volume(unsigned char *img) {
    unsigned char *boot = img;
    boot[0] = 0xEB; boot[1] = 0x76; boot[2] = 0x90;
    memcpy(boot + 3, "EXFAT   ", 8);
    boot[0x0B] = 9;  /* 512 bytes per sector */
    boot[0x0D] = 0;  /* 1 sector per cluster */
    put16(boot + 0x0E, 9);   /* reserved sectors: boot + 8 FAT sectors */
    boot[0x10] = 1;          /* one FAT */
    boot[0x11] = 0x80;
    put64(boot + 0x28, IMAGE_SECTORS);
    put32(boot + 0x30, 1);   /* FAT offset */
    put32(boot + 0x34, 8);   /* FAT length */
    put32(boot + 0x38, HEAP_SECTOR);
    put32(boot + 0x3C, 5);   /* cluster count: valid clusters 2..6 */
    put32(boot + 0x40, 2);   /* root directory cluster */
    boot[510] = 0x55; boot[511] = 0xAA;

    unsigned char *root = cluster_ptr(img, 2);
    memset(root + 0, 0, 32);
    root[0] = 0x81;          /* critical primary allocation bitmap */
    put32(root + 4, 5);      /* bitmap lives in cluster 5 */
    put64(root + 8, CLUSTER_BYTES); /* bitmap byte length */
    /* Intact deleted file: cluster 3 free in bitmap, data still present. */
    memset(root + 32, 0, 32);
    root[32] = 0xE5;
    root[33] = 2;            /* stream + name secondaries */
    stream_entry(root + 64, 3, 64);
    name_entry(root + 96, "INTACT.TXT");
    /* Overwritten deleted file: cluster 4 still marked allocated. */
    memset(root + 128, 0, 32);
    root[128] = 0xE5;
    root[129] = 2;
    stream_entry(root + 160, 4, 64);
    name_entry(root + 192, "LOST.TXT");
    /* Live file must never be carved. */
    memset(root + 224, 0, 32);
    root[224] = 0x85;
    root[225] = 2;
    stream_entry(root + 256, 6, 64);
    name_entry(root + 288, "LIVE.TXT");

    memset(cluster_ptr(img, 3), 'I', CLUSTER_BYTES);
    memset(cluster_ptr(img, 4), 'O', CLUSTER_BYTES);
    memset(cluster_ptr(img, 5), 0, CLUSTER_BYTES);
    /* Bitmap bit index = cluster - 2: cluster 4 -> byte 0, bit 2. */
    cluster_ptr(img, 5)[0] = 0x04;
}

static int build_image(const char *path) {
    unsigned char *img = (unsigned char *)calloc(IMAGE_BYTES, 1u);
    if (!img) return -1;
    fill_volume(img);
    FILE *f = fopen(path, "wb");
    int rc = -1;
    if (f) {
        rc = (fwrite(img, 1, IMAGE_BYTES, f) == IMAGE_BYTES && fclose(f) == 0) ? 0 : -1;
    }
    free(img);
    return rc;
}

/* A sparse image with the nominal MBR and the same exFAT volume at DJ_DATA. */
static int build_layout_image(const char *path) {
    unsigned char mbr[SECTOR], volume[IMAGE_BYTES];
    char err[256];
    cbm_layout_t layout;
    if (cbm_layout_construct(27ULL, mbr, err, sizeof(err)) != 0) return -1;
    if (cbm_layout_parse(mbr, SECTOR, &layout) != 0 || layout.part_count < 3) return -1;
    memset(volume, 0, sizeof(volume));
    fill_volume(volume);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int rc = -1;
    if (fwrite(mbr, 1, SECTOR, f) == SECTOR &&
        fseeko(f, (off_t)(layout.parts[2].start_lba * SECTOR), SEEK_SET) == 0 &&
        fwrite(volume, 1, sizeof(volume), f) == sizeof(volume)) rc = 0;
    if (fclose(f) != 0) rc = -1;
    return rc;
}

static const exfat_entry_t *find_entry(const exfat_report_t *rep, const char *name) {
    for (size_t i = 0; i < rep->count; i++)
        if (strcmp(rep->entries[i].name, name) == 0) return &rep->entries[i];
    return NULL;
}

static void test_intact_recovered(const char *image, const char *outdir) {
    TEST("intact deleted file is recovered byte-for-byte");
    exfat_report_t rep;
    char err[256];
    memset(&rep, 0, sizeof(rep));
    if (exfat_carve(image, 0ULL, outdir, &rep, err, sizeof(err)) != 0) {
        FAIL(err);
        return;
    }
    const exfat_entry_t *e = find_entry(&rep, "INTACT.TXT");
    int ok = (e != NULL) && (e->outcome == EXFAT_OUT_RECOVERED) && (e->size == 64);
    char out[256];
    path_of(out, sizeof(out), "out/INTACT.TXT");
    if (ok) {
        unsigned char got[64];
        FILE *f = fopen(out, "rb");
        ok = f && fread(got, 1, sizeof(got), f) == sizeof(got);
        if (f) fclose(f);
        for (size_t i = 0; ok && i < sizeof(got); i++) if (got[i] != 'I') ok = 0;
    }
    if (!ok || find_entry(&rep, "LIVE.TXT") != NULL) ok = 0;
    ok ? PASS() : FAIL("intact file missing, bytes differ, or live file carved");
    exfat_report_free(&rep);
}

static void test_lost_reported(const char *image, const char *outdir) {
    TEST("overwritten deleted file is reported lost, not guessed");
    exfat_report_t rep;
    char err[256];
    memset(&rep, 0, sizeof(rep));
    if (exfat_carve(image, 0ULL, outdir, &rep, err, sizeof(err)) != 0) {
        FAIL(err);
        return;
    }
    const exfat_entry_t *e = find_entry(&rep, "LOST.TXT");
    int ok = (e != NULL) && (e->outcome == EXFAT_OUT_LOST);
    char out[256];
    path_of(out, sizeof(out), "out/LOST.TXT");
    if (ok) {
        FILE *f = fopen(out, "rb");
        if (f) { ok = 0; fclose(f); } /* no guessed bytes written */
    }
    ok ? PASS() : FAIL("lost file misreported or guessed bytes written");
    exfat_report_free(&rep);
}

static void test_corrupt_boot(const char *image, const char *outdir) {
    TEST("corrupt boot sector fails cleanly");
    char bad[256];
    path_of(bad, sizeof(bad), "bad.img");
    FILE *src = fopen(image, "rb");
    FILE *dst = fopen(bad, "wb");
    int ok = (src && dst);
    if (ok) {
        unsigned char sector[SECTOR];
        ok = fread(sector, 1, SECTOR, src) == SECTOR;
        if (ok) {
            memset(sector + 3, 0, 8); /* erase EXFAT signature */
            ok = fwrite(sector, 1, SECTOR, dst) == SECTOR;
        }
        unsigned char rest[IMAGE_BYTES - SECTOR];
        if (ok && fread(rest, 1, sizeof(rest), src) == sizeof(rest))
            ok = fwrite(rest, 1, sizeof(rest), dst) == sizeof(rest);
        else ok = 0;
    }
    if (src) fclose(src);
    if (dst) fclose(dst);

    exfat_report_t rep;
    char err[256];
    memset(&rep, 0, sizeof(rep));
    memset(err, 0, sizeof(err));
    int rc = ok ? exfat_carve(bad, 0ULL, outdir, &rep, err, sizeof(err)) : -1;
    ok = (rc != 0) && (err[0] != '\0') && (rep.count == 0u);
    ok ? PASS() : FAIL("corrupt boot did not fail closed with an error");
    exfat_report_free(&rep);
}

static void test_json_report(const char *image, const char *outdir) {
    TEST("JSON report names outcomes without extra files");
    exfat_report_t rep;
    char err[256];
    char path[256];
    char buf[4096];
    memset(&rep, 0, sizeof(rep));
    if (exfat_carve(image, 0ULL, outdir, &rep, err, sizeof(err)) != 0) {
        FAIL(err);
        return;
    }
    path_of(path, sizeof(path), "out/report.json");
    FILE *f = fopen(path, "wb");
    int ok = f != NULL;
    if (f) {
        exfat_report_json(f, &rep);
        ok = (fclose(f) == 0);
    }
    size_t got = 0;
    if (ok) {
        f = fopen(path, "rb");
        if (f) {
            got = fread(buf, 1, sizeof(buf) - 1u, f);
            fclose(f);
        } else ok = 0;
    }
    buf[got] = '\0';
    if (!ok || strstr(buf, "\"outcome\":\"recovered\"") == NULL) ok = 0;
    if (!ok || strstr(buf, "\"outcome\":\"lost\"") == NULL) ok = 0;
    if (!ok || strstr(buf, "LIVE.TXT") != NULL) ok = 0;
    ok ? PASS() : FAIL("JSON missing recovered/lost outcomes or carved live file");
    exfat_report_free(&rep);
}

static void test_dj_data_partition(const char *outdir) {
    TEST("DJ_DATA start LBA from the MBR is used");
    char path[256];
    path_of(path, sizeof(path), "layout.img");
    if (build_layout_image(path) != 0) {
        FAIL("build_layout_image failed");
        return;
    }
    exfat_report_t rep;
    char err[256];
    memset(&rep, 0, sizeof(rep));
    if (exfat_carve_dj_data(path, outdir, &rep, err, sizeof(err)) != 0) {
        FAIL(err);
        return;
    }
    const exfat_entry_t *e = find_entry(&rep, "INTACT.TXT");
    int ok = (e != NULL) && (e->outcome == EXFAT_OUT_RECOVERED);
    ok ? PASS() : FAIL("DJ_DATA carve did not recover the intact file");
    exfat_report_free(&rep);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== exFAT Undelete Carver Tests ===\n");
    char tmpl[] = "/tmp/opencode/cbm-exfat-test.XXXXXX";
    if (!mkdtemp(tmpl)) {
        printf("FAIL: mkdtemp failed\n");
        return 1;
    }
    snprintf(g_root, sizeof(g_root), "%s", tmpl);
    char image[256], outdir[256], cmd[512];
    path_of(image, sizeof(image), "disk.img");
    path_of(outdir, sizeof(outdir), "out");
    if (build_image(image) != 0) {
        printf("FAIL: build_image failed\n");
        return 1;
    }
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", outdir);
    if (system(cmd) != 0) {
        printf("FAIL: mkdir failed\n");
        return 1;
    }

    test_intact_recovered(image, outdir);
    test_lost_reported(image, outdir);
    test_corrupt_boot(image, outdir);
    test_json_report(image, outdir);
    test_dj_data_partition(outdir);

    printf("\nScratch fixtures: %s\n", g_root);
    printf("test_exfat_carver: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
