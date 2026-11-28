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

/* DJ-shaped but invalid: valid 0x55AA signature and exactly three non-empty
 * entries, but the boot size is corrupted. This is authorisation clause (b). */
static void build_dj_shaped_invalid_mbr(unsigned char *mbr) {
    build_dj_mbr(mbr);
    put_u32(mbr + 446 + 12, 1000u); /* far below the 500 MiB validator floor */
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

static size_t read_sink_text(const char *name, char *buf, size_t len) {
    char p[256];
    path_of(p, sizeof(p), name);
    FILE *rd = fopen(p, "rb");
    size_t n = rd ? fread(buf, 1, len - 1u, rd) : 0;
    if (rd) fclose(rd);
    buf[n] = '\0';
    return n;
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
    char text[1024] = {0};
    cbm_doctor_repair_t out;
    char err[256] = {0};
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(7, av, sink, sink) == 2);
    if (ok && sink) fflush(sink);
    if (ok) read_sink_text("alias.out", text, sizeof(text));
    if (ok) ok = (strstr(text, "backup refused:") != NULL && strstr(text, "read=") == NULL);
    if (ok) ok = (cbm_doctor_repair(img, img, 26LL, &out, err, sizeof(err)) == 2);
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("backup alias must be refused before any write or step flag");
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
    cbm_doctor_report_t r;
    char err[256] = {0};
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_report(img, 26ULL, &r, err, sizeof(err)) == 0 && !r.repairable);
    if (ok) ok = (cbm_doctor_cli(7, av, sink, sink) == 1);
    if (ok) ok = (access(bak, F_OK) != 0 && fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("non-DJ geometry must refuse repair and report repairable=no");
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

static void test_dj_shaped_invalid_repaired_and_validates(void) {
    TEST("doctor: DJ-shaped invalid table is repaired and validates afterwards");
    char img[256], bak[256];
    path_of(img, sizeof(img), "dj-invalid.img");
    path_of(bak, sizeof(bak), "dj-invalid.bak");
    unsigned char mbr[CBM_SECTOR_SIZE], after[CBM_SECTOR_SIZE];
    build_dj_shaped_invalid_mbr(mbr);
    cbm_doctor_repair_t out;
    cbm_doctor_report_t r;
    char err[256] = {0};
    int ok = (make_image(img, mbr, 28ULL) == 0);
    if (ok) ok = (cbm_doctor_report(img, 26ULL, &r, err, sizeof(err)) == 0);
    if (ok) ok = (r.mbr_ok && r.part_count == 3 && !r.dj_ok && r.repairable);
    if (ok) ok = (cbm_doctor_repair(img, bak, 26ULL, &out, err, sizeof(err)) == 0);
    if (ok) ok = (cbm_file_read(img, 0, after, sizeof(after)) == 0);
    if (ok) {
        cbm_layout_t L;
        ok = (cbm_layout_parse(after, sizeof(after), &L) == 0 &&
              cbm_layout_validate(&L, CBM_EXPECTED_WINDOW_SECTORS) == 0);
    }
    if (ok) PASS(); else FAIL("DJ-shaped invalid table must repair to a valid DJ layout");
}

static void test_repairable_agreement_five_fixtures(void) {
    TEST("doctor: report repairable agrees with repair across five fixtures");
    static const struct {
        const char *name;
        int kind; /* 0 valid DJ, 1 corrupt sig, 2 DJ-shaped invalid, 3 foreign, 4 too small */
        unsigned long long window, gib;
        int expect_repairable;
    } cases[] = {
        {"agree-valid",   0, 26ULL, 28ULL, 0},
        {"agree-corrupt", 1, 26ULL, 28ULL, 1},
        {"agree-djinval", 2, 26ULL, 28ULL, 1},
        {"agree-foreign", 3, 26ULL, 28ULL, 0},
        {"agree-small",   1, 27ULL, 26ULL, 0},
    };
    int ok = 1;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char img[256], bakname[256], bak[256];
        unsigned char mbr[CBM_SECTOR_SIZE];
        path_of(img, sizeof(img), cases[i].name);
        snprintf(bakname, sizeof(bakname), "%s.bak", cases[i].name);
        path_of(bak, sizeof(bak), bakname);
        switch (cases[i].kind) {
            case 0: build_dj_mbr(mbr); break;
            case 1: build_dj_mbr(mbr); mbr[510] = 0; break;
            case 2: build_dj_shaped_invalid_mbr(mbr); break;
            case 3: build_non_dj_mbr(mbr); break;
            default: build_dj_mbr(mbr); mbr[510] = 0; break;
        }
        cbm_doctor_report_t r;
        cbm_doctor_repair_t out;
        char err[256] = {0};
        int rc = -1;
        if (ok) ok = (make_image(img, mbr, cases[i].gib) == 0);
        if (ok) ok = (cbm_doctor_report(img, cases[i].window, &r, err, sizeof(err)) == 0);
        if (ok) ok = (r.repairable == cases[i].expect_repairable);
        if (ok) ok = (r.repairable || r.repair_reason[0] != '\0');
        if (ok) rc = cbm_doctor_repair(img, bak, cases[i].window, &out, err, sizeof(err));
        if (ok) ok = ((rc == 0) == (r.repairable == 1));
        if (ok && !r.repairable) ok = (access(bak, F_OK) != 0);
    }
    if (ok) PASS(); else FAIL("report/repair authorisation verdicts must agree");
}

static void test_negative_window_gib_rejected(void) {
    TEST("doctor: negative --window-gib is exit 2 with no write");
    char img[256];
    path_of(img, sizeof(img), "neg-window.img");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr); mbr[510] = 0;
    uint64_t before = 0, after = 0;
    char *av[] = {"cbm-tool", "doctor", img, "--window-gib", "-1", NULL};
    FILE *sink = open_sink("neg-window.out");
    char text[1024] = {0};
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(5, av, sink, sink) == 2);
    if (ok && sink) fflush(sink);
    if (ok) {
        read_sink_text("neg-window.out", text, sizeof(text));
        ok = (strstr(text, "non-negative") != NULL && strstr(text, "-1") != NULL);
    }
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after);
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("negative --window-gib must be a usage error");
}

static void test_readback_error_names_backup(void) {
    TEST("doctor: read-back failure message names the backup path");
    char err[256] = {0};
    cbm_doctor_readback_error(err, sizeof(err), "/tmp/opencode/recovery.bak");
    int ok = (strstr(err, "/tmp/opencode/recovery.bak") != NULL &&
              strstr(err, "read-back") != NULL);
    if (ok) PASS(); else FAIL("read-back error must name the backup path");
}

static void test_cli_failure_prints_full_steps(void) {
    TEST("doctor: CLI repair refusal prints every step flag and the backup path");
    char img[256], bak[256];
    path_of(img, sizeof(img), "steps.img");
    path_of(bak, sizeof(bak), "steps.bak");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr); /* already valid => refused */
    char *av[] = {"cbm-tool", "doctor", img, "--repair-mbr", "--yes", "--backup", bak, NULL};
    FILE *sink = open_sink("steps.out");
    char text[4096] = {0};
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0);
    if (ok) ok = (cbm_doctor_cli(7, av, sink, sink) == 1);
    if (ok && sink) fflush(sink);
    if (ok) {
        read_sink_text("steps.out", text, sizeof(text));
        ok = (strstr(text, "Refused:") != NULL &&
              strstr(text, "read=1 backup_written=0 backup_verified=0 "
                           "mbr_written=0 readback_verified=0") != NULL &&
              strstr(text, bak) != NULL);
    }
    if (sink) fclose(sink);
    if (ok) PASS(); else FAIL("CLI must print the full step struct on repair failure");
}

/* A real block device cannot be used in a test: this suite is synthetic
 * regular files only. This fixture proves the regular-file sizing path still
 * returns the exact byte count; BLKGETSIZE64 remains hardware-gated. */
static void test_target_size_regular_file_exact_bytes(void) {
    TEST("doctor: regular-file target size is exact (block-device path needs hardware)");
    char img[256];
    path_of(img, sizeof(img), "size-regular.img");
    int fd = open(img, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    int ok = (fd >= 0 && ftruncate(fd, 600) == 0);
    if (fd >= 0) close(fd);
    cbm_doctor_report_t r;
    char err[256] = {0};
    if (ok) ok = (cbm_doctor_report(img, 26ULL, &r, err, sizeof(err)) == 0);
    if (ok) ok = (r.size_bytes == 600ULL && !r.window_consistent);
    if (ok) PASS(); else FAIL("regular file size must be exact; block device is INCONCLUSIVE here");
}

static void test_window_gib_out_of_range_refused_in_both_modes(void) {
    TEST("doctor: out-of-range/odd --window-gib exits 2 in dry-run and repair");
    char img[256], bak[256], out[256];
    path_of(img, sizeof(img), "window-edges.img");
    path_of(bak, sizeof(bak), "window-edges.bak");
    path_of(out, sizeof(out), "window-edges.out");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr); mbr[510] = 0; /* would be repairable with a legal window */
    static const char *bad[] = {" -1", "29", "17179869184", "", "abc"};
    uint64_t before = 0, after = 0;
    int ok = (make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    for (size_t i = 0; ok && i < sizeof(bad) / sizeof(bad[0]); i++) {
        char *dry_av[] = {"cbm-tool", "doctor", img, "--window-gib", (char *)bad[i], NULL};
        char *fix_av[] = {"cbm-tool", "doctor", img, "--repair-mbr", "--yes",
                          "--backup", bak, "--window-gib", (char *)bad[i], NULL};
        char text[1024] = {0};
        FILE *sink = fopen(out, "w");
        if (!sink) { ok = 0; break; }
        if (cbm_doctor_cli(5, dry_av, sink, sink) != 2) ok = 0;
        if (ok) ok = (access(bak, F_OK) != 0);
        if (ok && cbm_doctor_cli(9, fix_av, sink, sink) != 2) ok = 0;
        fflush(sink);
        fclose(sink);
        if (ok) read_sink_text("window-edges.out", text, sizeof(text));
        if (ok) ok = (strstr(text, "CBM Doctor Report") == NULL &&
                      strstr(text, "Dry run:") == NULL &&
                      strstr(text, "Repair:") == NULL);
        /* The two in-range-digit-but-illegal values name the supported range. */
        if (ok && (i == 1 || i == 2)) ok = (strstr(text, "26..28") != NULL);
    }
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after && access(bak, F_OK) != 0);
    if (ok) PASS(); else FAIL("illegal --window-gib must exit 2 before any report or write");
}

static void test_report_window_guard_avoids_overflow(void) {
    TEST("doctor: direct API report with huge window stays inconsistent (no wrap to zero)");
    char img[256];
    path_of(img, sizeof(img), "window-huge.img");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr);
    cbm_doctor_report_t r;
    char err[256] = {0};
    int ok = (make_image(img, mbr, 28ULL) == 0);
    if (ok) ok = (cbm_doctor_report(img, 17179869184ULL, &r, err, sizeof(err)) == 0);
    if (ok) ok = (!r.window_consistent && !r.repairable &&
                  strstr(r.repair_reason, "26..28") != NULL);
    if (ok) PASS(); else FAIL("report must range-check before multiplying window by GiB");
}

static void test_window_gib_26_still_works(void) {
    TEST("doctor: --window-gib 26 is still accepted");
    char img[256], out[256];
    path_of(img, sizeof(img), "window-26.img");
    path_of(out, sizeof(out), "window-26.out");
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr);
    char *av[] = {"cbm-tool", "doctor", img, "--window-gib", "26", NULL};
    FILE *sink = open_sink("window-26.out");
    char text[1024] = {0};
    uint64_t before = 0, after = 0;
    int ok = (sink != NULL && make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (cbm_doctor_cli(5, av, sink, sink) == 0);
    if (ok && sink) fflush(sink);
    if (sink) fclose(sink);
    if (ok) {
        read_sink_text("window-26.out", text, sizeof(text));
        ok = (strstr(text, "window=26 GiB") != NULL && strstr(text, "Dry run:") != NULL);
    }
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after);
    if (ok) PASS(); else FAIL("26 GiB window must remain the supported default");
}

static void test_backup_alias_variants_refused(void) {
    TEST("doctor: hardlink/symlink/under-source backups are exit 2 with no write");
    char img[256], hard[256], sym[256], under[320], out[256];
    path_of(img, sizeof(img), "alias-variants.img");
    path_of(hard, sizeof(hard), "alias-variants.hard");
    path_of(sym, sizeof(sym), "alias-variants.sym");
    path_of(out, sizeof(out), "alias-variants.out");
    snprintf(under, sizeof(under), "%s/child.bak", img);
    unsigned char mbr[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr); mbr[510] = 0;
    uint64_t before = 0, after = 0;
    int ok = (make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) ok = (link(img, hard) == 0 && symlink(img, sym) == 0);
    const char *variants[3] = {hard, sym, under};
    for (size_t i = 0; ok && i < 3; i++) {
        char *av[] = {"cbm-tool", "doctor", img, "--repair-mbr", "--yes",
                      "--backup", (char *)variants[i], NULL};
        FILE *sink = fopen(out, "w");
        char text[1024] = {0};
        if (!sink) { ok = 0; break; }
        if (cbm_doctor_cli(7, av, sink, sink) != 2) ok = 0;
        fflush(sink);
        fclose(sink);
        if (ok) read_sink_text("alias-variants.out", text, sizeof(text));
        if (ok) ok = (strstr(text, "backup refused:") != NULL &&
                      strstr(text, "Repair:") == NULL && strstr(text, "read=") == NULL);
    }
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after);
    if (ok) PASS(); else FAIL("every alias variant must be refused before opening the backup");
}

static void test_backup_creation_collision_shows_partial_steps(void) {
    TEST("doctor: existing backup is refused with read=1 backup_written=0 step flags");
    char img[256], bak[256], out[256];
    path_of(img, sizeof(img), "collision.img");
    path_of(bak, sizeof(bak), "collision.bak");
    path_of(out, sizeof(out), "collision.out");
    unsigned char mbr[CBM_SECTOR_SIZE], junk[CBM_SECTOR_SIZE], check[CBM_SECTOR_SIZE];
    build_dj_mbr(mbr); mbr[510] = 0;
    memset(junk, 0xa5, sizeof(junk));
    uint64_t before = 0, after = 0;
    int ok = (make_image(img, mbr, 28ULL) == 0 && fingerprint(img, &before) == 0);
    if (ok) {
        int fd = open(bak, O_CREAT | O_EXCL | O_WRONLY, 0600);
        ok = (fd >= 0 && write(fd, junk, sizeof(junk)) == (ssize_t)sizeof(junk));
        if (fd >= 0) close(fd);
    }
    char *av[] = {"cbm-tool", "doctor", img, "--repair-mbr", "--yes", "--backup", bak, NULL};
    FILE *sink = open_sink("collision.out");
    char text[2048] = {0};
    if (ok && !sink) ok = 0;
    if (ok) ok = (cbm_doctor_cli(7, av, sink, sink) == 1);
    if (ok && sink) fflush(sink);
    if (sink) fclose(sink);
    if (ok) {
        read_sink_text("collision.out", text, sizeof(text));
        ok = (strstr(text, "read=1 backup_written=0 backup_verified=0 "
                           "mbr_written=0 readback_verified=0") != NULL && strstr(text, bak) != NULL);
    }
    if (ok) ok = (cbm_file_read(bak, 0, check, sizeof(check)) == 0 &&
                  memcmp(check, junk, sizeof(check)) == 0);
    if (ok) ok = (fingerprint(img, &after) == 0 && before == after);
    if (ok) PASS(); else FAIL("backup collision must report real step flags and leave both files intact");
}

static void test_readback_failure_prefix_is_exact(void) {
    TEST("doctor: failure prefix distinguishes completed-write verification failure");
    char err[256] = {0};
    int ok = (strcmp(cbm_doctor_failure_prefix(-1),
                     "FAILED (write completed, verification failed):") == 0 &&
              strcmp(cbm_doctor_failure_prefix(1), "Refused:") == 0);
    cbm_doctor_readback_error(err, sizeof(err), "/tmp/opencode/recovery.bak");
    if (ok) ok = (strstr(err, "/tmp/opencode/recovery.bak") != NULL &&
                  strstr(err, "read-back") != NULL);
    if (ok) PASS(); else FAIL("exit -1 must use the completed-write failure prefix");
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
    test_dj_shaped_invalid_repaired_and_validates();
    test_repairable_agreement_five_fixtures();
    test_negative_window_gib_rejected();
    test_readback_error_names_backup();
    test_cli_failure_prints_full_steps();
    test_target_size_regular_file_exact_bytes();
    test_window_gib_out_of_range_refused_in_both_modes();
    test_report_window_guard_avoids_overflow();
    test_window_gib_26_still_works();
    test_backup_alias_variants_refused();
    test_backup_creation_collision_shows_partial_steps();
    test_readback_failure_prefix_is_exact();

    printf("\nScratch fixtures: %s\n", g_root);
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
