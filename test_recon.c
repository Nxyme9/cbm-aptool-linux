/* test_recon.c - wave 5M recon tests (no vendor path in source)
 *
 * Malformed inputs are built as byte arrays and written to scratch files
 * under /tmp/opencode via mkstemp, then unlinked immediately. The optional
 * real-PE cases read only CBM_PE_PATH; when it is unset or unreadable they
 * print one SKIP line and the suite still exits 0. No vendor file is ever
 * copied into the repository and no fixed vendor path is embedded here.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>

#include "recon.h"

#define SCRATCH_DIR "/tmp/opencode"
#define TARGET_RVA 0x59ec0u
#define PATCHED_BASE 0x600000u

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

static void put16(unsigned char *p, size_t o, uint16_t v) {
    p[o] = (unsigned char)(v & 0xffu);
    p[o + 1u] = (unsigned char)((v >> 8) & 0xffu);
}

static void put32(unsigned char *p, size_t o, uint32_t v) {
    p[o] = (unsigned char)(v & 0xffu);
    p[o + 1u] = (unsigned char)((v >> 8) & 0xffu);
    p[o + 2u] = (unsigned char)((v >> 16) & 0xffu);
    p[o + 3u] = (unsigned char)((v >> 24) & 0xffu);
}

static uint32_t get32(const unsigned char *p, size_t o) {
    return (uint32_t)p[o] | ((uint32_t)p[o + 1u] << 8) |
           ((uint32_t)p[o + 2u] << 16) | ((uint32_t)p[o + 3u] << 24);
}

static int scratch_path(char *path, size_t cap, const char *prefix) {
    char tmpl[96];
    int fd;
    (void)mkdir(SCRATCH_DIR, 0700);
    (void)snprintf(tmpl, sizeof(tmpl), SCRATCH_DIR "/%s-XXXXXX", prefix);
    fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    (void)close(fd);
    if (strlen(tmpl) >= cap) { (void)unlink(tmpl); return -1; }
    strcpy(path, tmpl);
    return 0;
}

static int write_scratch(const unsigned char *buf, size_t len,
                         char *path, size_t cap, const char *prefix) {
    FILE *f;
    if (scratch_path(path, cap, prefix) != 0) return -1;
    f = fopen(path, "wb");
    if (!f) { (void)unlink(path); return -1; }
    if (len && fwrite(buf, 1, len, f) != len) {
        (void)fclose(f);
        (void)unlink(path);
        return -1;
    }
    if (fclose(f) != 0) { (void)unlink(path); return -1; }
    return 0;
}

/* Minimal valid PE32 with one executable section and one prologue. */
static void make_pe(unsigned char *buf, size_t len) {
    size_t sh;
    memset(buf, 0, len);
    buf[0] = 'M';
    buf[1] = 'Z';
    put32(buf, 0x3c, 0x80u);
    memcpy(buf + 0x80, "PE\0\0", 4);
    put16(buf, 0x84, 0x14cu);        /* machine i386 */
    put16(buf, 0x86, 1u);            /* one section */
    put16(buf, 0x94, 224u);          /* SizeOfOptionalHeader */
    put16(buf, 0x98, 0x10bu);        /* PE32 magic */
    put32(buf, 0x98 + 28u, 0x400000u);
    put32(buf, 0x98 + 56u, 0x3000u); /* SizeOfImage */
    sh = 0x98u + 224u;
    memcpy(buf + sh, ".text", 5);
    put32(buf, sh + 8u, 0x1000u);    /* VirtualSize */
    put32(buf, sh + 12u, 0x1000u);   /* VirtualAddress */
    put32(buf, sh + 16u, 0x200u);    /* SizeOfRawData */
    put32(buf, sh + 20u, 0x200u);    /* PointerToRawData */
    put32(buf, sh + 36u, 0x60000020u); /* code | execute | read */
    buf[0x200] = 0x55u;
    buf[0x201] = 0x8bu;
    buf[0x202] = 0xecu;
    buf[0x203] = 0x83u;
    buf[0x204] = 0xecu;
    buf[0x205] = 0x08u;
    buf[0x206] = 0xc3u;
}

static void test_reject(const char *name, const unsigned char *buf, size_t len) {
    recon_report_t report;
    char path[128];
    memset(&report, 0, sizeof(report));
    TEST(name);
    if (write_scratch(buf, len, path, sizeof(path), "recon-bad") != 0) {
        FAIL("cannot write scratch file");
        return;
    }
    if (recon_file(path, &report) != -1) {
        (void)unlink(path);
        FAIL("malformed input was accepted");
        return;
    }
    (void)unlink(path);
    if (!report.error[0]) { FAIL("empty error message"); return; }
    PASS();
}

static void test_empty(void) {
    static const unsigned char none[1] = {0};
    test_reject("reject empty file", none, 0u);
}

static void test_mz_only(void) {
    static const unsigned char mz[2] = {'M', 'Z'};
    test_reject("reject MZ only", mz, sizeof(mz));
}

static void test_bad_signature(void) {
    unsigned char buf[0x400];
    make_pe(buf, sizeof(buf));
    buf[0x80] = 'X';
    test_reject("reject bad PE signature", buf, sizeof(buf));
}

static void test_bad_lfanew(void) {
    unsigned char buf[0x400];
    make_pe(buf, sizeof(buf));
    put32(buf, 0x3c, 0x10000000u);
    test_reject("reject e_lfanew out of range", buf, sizeof(buf));
}

static void test_bad_section_raw(void) {
    unsigned char buf[0x400];
    make_pe(buf, sizeof(buf));
    put32(buf, 0x98u + 224u + 20u, 0x1000u); /* raw pointer past EOF */
    test_reject("reject section raw beyond file", buf, sizeof(buf));
}

static void test_bad_image_size(void) {
    unsigned char buf[0x400];
    make_pe(buf, sizeof(buf));
    put32(buf, 0x98u + 56u, 0x20000000u); /* 512 MiB */
    test_reject("reject absurd SizeOfImage", buf, sizeof(buf));
}

static void test_random_binary(void) {
    unsigned char buf[65536];
    uint32_t state = 0x12345678u;
    size_t i;
    for (i = 0u; i < sizeof(buf); i++) {
        state = state * 1664525u + 1013904223u;
        buf[i] = (unsigned char)(state >> 24);
    }
    buf[0] = 'X'; /* deterministic: never an MZ file */
    buf[1] = 'Y';
    test_reject("reject random binary without crash", buf, sizeof(buf));
}

/* Read ImageBase straight from the file header so the test does not trust
 * the value reported by recon_file. */
static int file_image_base(const char *path, uint32_t *base) {
    unsigned char hdr[1024];
    FILE *f = fopen(path, "rb");
    uint32_t peoff, opt;
    uint16_t magic;
    size_t n;
    if (!f) return -1;
    n = fread(hdr, 1, sizeof(hdr), f);
    (void)fclose(f);
    if (n < 0x100u || hdr[0] != 'M' || hdr[1] != 'Z') return -1;
    peoff = get32(hdr, 0x3cu);
    if ((size_t)peoff + 24u + 32u > n) return -1;
    if (memcmp(hdr + peoff, "PE\0\0", 4) != 0) return -1;
    opt = peoff + 24u;
    magic = (uint16_t)(hdr[opt] | ((uint16_t)hdr[opt + 1u] << 8));
    if (magic == 0x10bu) *base = get32(hdr, opt + 28u);
    else if (magic == 0x20bu) *base = get32(hdr, opt + 24u);
    else return -1;
    return 0;
}

/* Copy the supplied PE to scratch and patch the PE32 ImageBase field. The
 * copy is unlinked by the caller; the original is opened read-only. */
static int patched_copy(const char *src, char *path, size_t cap) {
    FILE *f = fopen(src, "rb");
    unsigned char *buf = NULL;
    long size;
    uint32_t peoff, opt;
    char tmpl[96];
    int fd, rc = -1;

    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { (void)fclose(f); return -1; }
    size = ftell(f);
    if (size <= 0 || size > 64L * 1024L * 1024L ||
        fseek(f, 0, SEEK_SET) != 0) { (void)fclose(f); return -1; }
    buf = (unsigned char *)malloc((size_t)size);
    if (!buf || fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        (void)fclose(f);
        return -1;
    }
    (void)fclose(f);
    if (buf[0] != 'M' || buf[1] != 'Z') goto done;
    peoff = get32(buf, 0x3cu);
    opt = peoff + 24u;
    if ((uint64_t)peoff + 24u + 32u > (uint64_t)size ||
        memcmp(buf + peoff, "PE\0\0", 4) != 0 || buf[opt] != 0x0bu ||
        buf[opt + 1u] != 0x01u) goto done; /* PE32 only */
    put32(buf, opt + 28u, PATCHED_BASE);
    (void)snprintf(tmpl, sizeof(tmpl), SCRATCH_DIR "/recon-pe-XXXXXX");
    fd = mkstemp(tmpl);
    if (fd < 0) goto done;
    if (write(fd, buf, (size_t)size) != (ssize_t)size) {
        (void)close(fd);
        (void)unlink(tmpl);
        goto done;
    }
    (void)close(fd);
    if (strlen(tmpl) < cap) { strcpy(path, tmpl); rc = 0; }
    else (void)unlink(tmpl);

done:
    free(buf);
    return rc;
}

static const recon_candidate_t *find_rva(const recon_report_t *r, uint32_t rva) {
    uint32_t i;
    for (i = 0u; i < r->stored; i++)
        if (r->candidates[i].rva == rva) return &r->candidates[i];
    return NULL;
}

static void test_real_pe(const char *path) {
    recon_report_t report;
    recon_report_t patched;
    uint32_t header_base = 0u;
    const recon_candidate_t *target;
    const recon_candidate_t *patched_target;
    char scratch[128];
    uint32_t i;

    memset(&report, 0, sizeof(report));
    memset(&patched, 0, sizeof(patched));
    TEST("recon_file on supplied PE");
    if (recon_file(path, &report) != 0) {
        printf("(%s) ", report.error[0] ? report.error : "unknown error");
        FAIL("recon_file failed on supplied PE");
        return;
    }
    PASS();

    TEST("functions_scanned > 1000");
    if (report.functions_scanned <= 1000u) FAIL("too few functions");
    else PASS();

    TEST("known block function is a candidate");
    target = find_rva(&report, TARGET_RVA);
    if (!target) { FAIL("RVA 0x59ec0 missing"); return; }
    if (target->va != report.image_base + TARGET_RVA) { FAIL("VA mismatch"); return; }
    if (target->score < 20u) { FAIL("score below 20"); return; }
    PASS();

    TEST("scores are non-increasing");
    for (i = 1u; i < report.stored; i++)
        if (report.candidates[i].score > report.candidates[i - 1u].score) break;
    if (i < report.stored) FAIL("score order broken");
    else PASS();

    TEST("image_base matches PE header");
    if (file_image_base(path, &header_base) != 0) { FAIL("cannot read PE header"); return; }
    if (report.image_base != header_base) { FAIL("image_base mismatch"); return; }
    PASS();

    TEST("patched ImageBase changes VA (anti-hardcoding)");
    if (patched_copy(path, scratch, sizeof(scratch)) != 0) {
        FAIL("cannot create patched copy");
        return;
    }
    if (recon_file(scratch, &patched) != 0) {
        (void)unlink(scratch);
        FAIL("patched copy rejected");
        return;
    }
    patched_target = find_rva(&patched, TARGET_RVA);
    (void)unlink(scratch);
    if (!patched_target) { FAIL("patched RVA missing"); return; }
    if (patched_target->va != PATCHED_BASE + TARGET_RVA) {
        FAIL("patched VA not recomputed");
        return;
    }
    PASS();
}

int main(void) {
    const char *path = getenv("CBM_PE_PATH");
    struct stat st;
    int usable = 0;

    test_empty();
    test_mz_only();
    test_bad_signature();
    test_bad_lfanew();
    test_bad_section_raw();
    test_bad_image_size();
    test_random_binary();

    if (path && *path && stat(path, &st) == 0 && S_ISREG(st.st_mode))
        usable = 1;
    if (!usable) {
        printf("test_recon: SKIP (CBM_PE_PATH unset or unreadable)\n");
    } else {
        test_real_pe(path);
    }
    printf("test_recon: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
