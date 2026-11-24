/* test_cbm_doctor.c - guarded MBR repair + read-only diagnosis tests (Wave 5D).
 *
 * Every fixture is a synthetic sparse regular file under a mkdtemp root in
 * /tmp/opencode. No test opens a device node and no source image is opened
 * for writing except by cbm_doctor_repair on its explicit LBA-0 repair path.
 */
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cbm_doctor.h"
#include "cbm_file.h"
#include "cbm_layout.h"

static int tests_passed = 0;
static int tests_failed = 0;
static char g_root[256];

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)
#define GIB (1024ULL * 1024ULL * 1024ULL)

static void path_of(char *out, size_t outlen, const char *sub) {
    size_t a = strlen(g_root), b = strlen(sub);
    if (a + 1u + b + 1u > outlen) { out[0] = '\0'; return; }
    memcpy(out, g_root, a);
    out[a] = '/';
    memcpy(out + a + 1u, sub, b + 1u);
}

static void put_u32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

/* Nominal DJ table used only as a test fixture; values are from the frozen
 * spec, not recovered from hardware. */
static void build_dj_mbr(unsigned char *mbr) {
    const unsigned int starts[3] = {2048u, 1050624u, 9439232u};
    const unsigned int sizes[3]  = {1048576u, 8388608u, 45086720u};
    const unsigned char types[3] = {0x0c, 0x83, 0x07};
    memset(mbr, 0, CBM_SECTOR_SIZE);
    for (int i = 0; i < 3; i++) {
        unsigned char *e = mbr + 446 + i * 16;
        e[4] = types[i];
        put_u32(e + 8, starts[i]);
        put_u32(e + 12, sizes[i]);
    }
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
}

static void build_non_dj_mbr(unsigned char *mbr) {
    memset(mbr, 0, CBM_SECTOR_SIZE);
    unsigned char *e = mbr + 446;
    e[4] = 0x83;
    put_u32(e + 8, 2048u);
    put_u32(e + 12, 1024u); /* too small for the DJ validator */
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
}

static int make_image(const char *path, const unsigned char *mbr,
                      unsigned long long gib) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) return -1;
    int rc = ftruncate(fd, (off_t)(gib * GIB));
    close(fd);
    if (rc != 0) return -1;
    return cbm_file_write(path, 0, mbr, CBM_SECTOR_SIZE);
}

/* Cheap whole-relevant-state fingerprint: 64-bit FNV over the first sector
 * plus the exact byte size. The full-file SHA-256 check is done by the CLI
 * smoke script; hashing a 28 GiB sparse file in every test is not viable. */
static int fingerprint(const char *path, uint64_t *out) {
    struct stat st;
    unsigned char buf[512];
    if (stat(path, &st) != 0 || cbm_file_read(path, 0, buf, sizeof(buf)) != 0) return -1;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < sizeof(buf); i++) { h ^= buf[i]; h *= 1099511628211ULL; }
    uint64_t sz = (uint64_t)st.st_size;
    for (int i = 0; i < 8; i++) { h ^= (unsigned char)(sz >> (8 * i)); h *= 1099511628211ULL; }
    *out = h;
    return 0;
}

static FILE *open_sink(const char *name) {
    char p[256];
    path_of(p, sizeof(p), name);
    return fopen(p, "w");
}

static void test_dry_run_valid_dj_is_read_only(void) {
    TEST("doctor: dry run on valid DJ image is read-only and names geometry");
    char img[256], bak[256];
    path_of(img, sizeof(img), "valid-dj.img");
    path_of(bak, sizeof(bak), "valid-dj.bak");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr);
    uint64_t before = 0, after = 0;
    cbm_doctor_report_t r;
    char err[256] = {0};
    int ok = (make_image(img, mbr, 28ULL) == 0);
    if (ok) ok = (fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_report(img, 26LL, &r, err, sizeof(err)) == 0);
    if (ok) ok = (r.mbr_ok && r.dj_ok && r.window_consistent && r.candidate_ok);
    if (ok) ok = (r.part_count == 3 && r.size_bytes == 28ULL * GIB);
    if (ok) ok = (strstr(r.verdict, "DJ") != NULL);
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after);
    if (ok) ok = (access(bak, F_OK) != 0);
    if (ok) PASS(); else FAIL("dry run must report DJ and leave the image untouched");
}

static void test_dry_run_reports_non_dj(void) {
    TEST("doctor: dry run reports non-DJ target without refusing or writing");
    char img[256];
    path_of(img, sizeof(img), "non-dj.img");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_non_dj_mbr(mbr);
    cbm_doctor_report_t r;
    char err[256] = {0};
    uint64_t before = 0, after = 0;
    int ok = (make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_report(img, 26LL, &r, err, sizeof(err)) == 0);
    if (ok) ok = (r.mbr_ok && !r.dj_ok && strstr(r.verdict, "NON-DJ") != NULL);
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after);
    if (ok) PASS(); else FAIL("non-DJ must be diagnosed, not refused, in dry run");
}

static void test_repair_restores_validated_mbr(void) {
    TEST("doctor: repair verifies backup then read-back and restores valid table");
    char img[256], bak[256];
    path_of(img, sizeof(img), "repair.img");
    path_of(bak, sizeof(bak), "repair.bak");
    unsigned char good[CBM_SECTOR_SIZE], corrupt[CBM_SECTOR_SIZE];
    unsigned char backup_sector[CBM_SECTOR_SIZE], readback[CBM_SECTOR_SIZE];
    unsigned char tail_before[512], tail_after[512];
    build_dj_mbr(good);
    memcpy(corrupt, good, sizeof(good));
    corrupt[510] = 0x00; /* invalid signature: authorisation predicate (a) */
    cbm_doctor_repair_t out;
    char err[256] = {0};
    int ok = (make_image(img, corrupt, 28ULL) == 0);
    if (ok) ok = (cbm_file_read(img, 512, tail_before, sizeof(tail_before)) == 0);
    if (ok) ok = (cbm_doctor_repair(img, bak, 26LL, &out, err, sizeof(err)) == 0);
    if (ok) ok = (out.step_read && out.step_backup_written &&
                  out.step_backup_verified && out.step_mbr_written &&
                  out.step_readback_verified);
    if (ok) ok = (cbm_file_read(bak, 0, backup_sector, CBM_SECTOR_SIZE) == 0 &&
                  memcmp(backup_sector, corrupt, CBM_SECTOR_SIZE) == 0);
    if (ok) ok = (memcmp(out.original, corrupt, CBM_SECTOR_SIZE) == 0);
    if (ok) ok = (cbm_file_read(img, 0, readback, CBM_SECTOR_SIZE) == 0 &&
                  memcmp(readback, out.reconstructed, CBM_SECTOR_SIZE) == 0);
    if (ok) {
        cbm_layout_t L;
        ok = (cbm_layout_parse(readback, CBM_SECTOR_SIZE, &L) == 0 &&
              cbm_layout_validate(&L, CBM_EXPECTED_WINDOW_SECTORS) == 0);
    }
    if (ok) ok = (cbm_file_read(img, 512, tail_after, sizeof(tail_after)) == 0 &&
                  memcmp(tail_before, tail_after, sizeof(tail_before)) == 0);
    if (ok) PASS(); else FAIL("repair must verify backup, write LBA 0 and verify read-back");
}

static void test_missing_yes_refused(void) {
    TEST("doctor: --repair-mbr without --yes is exit-2 with no write");
    char img[256], bak[256];
    path_of(img, sizeof(img), "missing-yes.img");
    path_of(bak, sizeof(bak), "missing-yes.bak");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr); mbr[510] = 0;
    uint64_t before = 0, after = 0;
    char *av[] = {"cbm-tool", "doctor", img, "--repair-mbr", "--backup", bak, NULL};
    FILE *sink = open_sink("missing-yes.out");
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(6, av, sink, sink) == 2);
    if (ok) ok = (access(bak, F_OK) != 0 && fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("missing --yes must refuse without writing");
}

static void test_missing_backup_refused(void) {
    TEST("doctor: --repair-mbr --yes without --backup is exit-2 with no write");
    char img[256];
    path_of(img, sizeof(img), "missing-backup.img");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr); mbr[510] = 0;
    uint64_t before = 0, after = 0;
    char *av[] = {"cbm-tool", "doctor", img, "--repair-mbr", "--yes", NULL};
    FILE *sink = open_sink("missing-backup.out");
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(5, av, sink, sink) == 2);
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("missing --backup must refuse without writing");
}

static void test_missing_repair_flag_refused(void) {
    TEST("doctor: --yes with --backup but no --repair-mbr is exit-2");
    char img[256], bak[256];
    path_of(img, sizeof(img), "missing-repair.img");
    path_of(bak, sizeof(bak), "missing-repair.bak");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr); mbr[510] = 0;
    uint64_t before = 0, after = 0;
    char *av[] = {"cbm-tool", "doctor", img, "--yes", "--backup", bak, NULL};
    FILE *sink = open_sink("missing-repair.out");
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(6, av, sink, sink) == 2);
    if (ok) ok = (access(bak, F_OK) != 0 && fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("--yes/--backup without --repair-mbr must refuse");
}

static void test_backup_alias_refused(void) {
    TEST("doctor: --backup equal to source is exit-2 (CLI and API)");
    char img[256];
    path_of(img, sizeof(img), "alias.img");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr); mbr[510] = 0;
    uint64_t before = 0, after = 0;
    char *av[] = {"cbm-tool", "doctor", img, "--repair-mbr", "--yes", "--backup", img, NULL};
    FILE *sink = open_sink("alias.out");
    cbm_doctor_repair_t out;
    char err[256] = {0};
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(7, av, sink, sink) == 2);
    if (ok) ok = (cbm_doctor_repair(img, img, 26LL, &out, err, sizeof(err)) == 2);
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("backup alias must be refused before any write");
}

static void test_already_valid_refused(void) {
    TEST("doctor: repair refused when the first sector already passes validation");
    char img[256], bak[256];
    path_of(img, sizeof(img), "already-valid.img");
    path_of(bak, sizeof(bak), "already-valid.bak");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr);
    uint64_t before = 0, after = 0;
    char *av[] = {"cbm-tool", "doctor", img, "--repair-mbr", "--yes", "--backup", bak, NULL};
    FILE *sink = open_sink("already-valid.out");
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(7, av, sink, sink) == 1);
    if (ok) ok = (access(bak, F_OK) != 0 && fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("valid MBR must not be rewritten");
}

static void test_non_dj_refused_for_repair(void) {
    TEST("doctor: parses-but-non-DJ target is diagnosed and refused for repair");
    char img[256], bak[256];
    path_of(img, sizeof(img), "bad-layout.img");
    path_of(bak, sizeof(bak), "bad-layout.bak");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_non_dj_mbr(mbr);
    uint64_t before = 0, after = 0;
    char *av[] = {"cbm-tool", "doctor", img, "--repair-mbr", "--yes", "--backup", bak, NULL};
    FILE *sink = open_sink("bad-layout.out");
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(7, av, sink, sink) == 1);
    if (ok) ok = (access(bak, F_OK) != 0 && fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("non-DJ geometry must refuse repair");
}

static void test_window_inconsistency_refused(void) {
    TEST("doctor: target smaller than --window-gib is refused (exit 1)");
    char img[256], bak[256];
    path_of(img, sizeof(img), "small-window.img");
    path_of(bak, sizeof(bak), "small-window.bak");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr); mbr[510] = 0;
    uint64_t before = 0, after = 0;
    char *av[] = {"cbm-tool", "doctor", img, "--repair-mbr", "--yes",
                  "--backup", bak, "--window-gib", "27", NULL};
    FILE *sink = open_sink("small-window.out");
    int ok = (sink != NULL && make_image(img, mbr, 26ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(9, av, sink, sink) == 1);
    if (ok) ok = (access(bak, F_OK) != 0 && fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("inconsistent window must refuse repair");
}

static void test_report_text_shows_nominal_table(void) {
    TEST("doctor: printed report shows nominal candidate values and fixed point");
    char img[256];
    path_of(img, sizeof(img), "print.img");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr);
    cbm_doctor_report_t r;
    char err[256] = {0};
    FILE *sink = open_sink("report.out");
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0);
    char text[4096] = {0};
    if (ok) ok = (cbm_doctor_report(img, 26LL, &r, err, sizeof(err)) == 0);
    if (ok) cbm_doctor_print_report(&r, sink);
    /* Flush the buffered sink before re-opening the same path for reading. */
    if (ok && sink) fflush(sink);
    if (ok) {
        char p[256];
        path_of(p, sizeof(p), "report.out");
        FILE *rd = fopen(p, "rb");
        size_t n = rd ? fread(text, 1, sizeof(text) - 1u, rd) : 0;
        if (rd) fclose(rd);
        ok = (n > 0 && strstr(text, "nominal") != NULL &&
              strstr(text, "2048") != NULL && strstr(text, "0x0c") != NULL &&
              strstr(text, "28.000000 GiB") != NULL);
    }
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("report must show nominal table and fixed-point size");
}

static void test_cli_dry_run_non_dj_exit_zero(void) {
    TEST("doctor: CLI dry run on non-DJ readable image exits 0");
    char img[256];
    path_of(img, sizeof(img), "cli-dry.img");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_non_dj_mbr(mbr);
    uint64_t before = 0, after = 0;
    char *av[] = {"cbm-tool", "doctor", img, NULL};
    FILE *sink = open_sink("cli-dry.out");
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(3, av, sink, sink) == 0);
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("CLI dry run must exit 0 on a readable non-DJ image");
}

int main(void) {
    printf("=== CBM Doctor Tests ===\n");
    char tmpl[] = "/tmp/opencode/wave5d-doctor.XXXXXX";
    if (!mkdtemp(tmpl)) { printf("FAIL: mkdtemp failed\n"); return 1; }
    snprintf(g_root, sizeof(g_root), "%s", tmpl);

    test_dry_run_valid_dj_is_read_only();
    test_dry_run_reports_non_dj();
    test_repair_restores_validated_mbr();
    test_missing_yes_refused();
    test_missing_backup_refused();
    test_missing_repair_flag_refused();
    test_backup_alias_refused();
    test_already_valid_refused();
    test_non_dj_refused_for_repair();
    test_window_inconsistency_refused();
    test_report_text_shows_nominal_table();
    test_cli_dry_run_non_dj_exit_zero();

    printf("\nScratch fixtures: %s\n", g_root);
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
