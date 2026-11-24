/* test_pelib.c - bounds-checked 32-bit PE loader tests
 *
 * Malformed PEs are built as in-memory byte arrays and written to scratch
 * files under /tmp/opencode via mkstemp; they are unlinked immediately after
 * the load attempt. No vendor binary is ever written by this test.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

#include "pelib.h"

#define BASE PE_BASE
#define MAPSZ PE_MAPSZ
#define ENCRYPT_RVA 0x59da0u        /* VA 0x459da0 - ImageBase */
#define FAKE_SIZE 512u
#define FAKE_PEOFF 0x80u
#define FAKE_OPT 224u

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

static void put16(unsigned char *p, size_t o, uint16_t v) {
    p[o] = (unsigned char)(v & 0xffu);
    p[o + 1] = (unsigned char)((v >> 8) & 0xffu);
}

static void put32(unsigned char *p, size_t o, uint32_t v) {
    p[o] = (unsigned char)(v & 0xffu);
    p[o + 1] = (unsigned char)((v >> 8) & 0xffu);
    p[o + 2] = (unsigned char)((v >> 16) & 0xffu);
    p[o + 3] = (unsigned char)((v >> 24) & 0xffu);
}

/* Build a minimal, otherwise-valid PE32 image inside a scratch buffer.
 * Header fields are placed only when they fit, so out-of-range e_lfanew
 * cases can be expressed without any out-of-bounds writes in the test. */
static void make_pe(unsigned char *buf, size_t len, uint32_t peoff,
                    uint16_t ns, uint16_t optsz) {
    size_t opt;
    memset(buf, 0, len);
    buf[0] = 'M';
    buf[1] = 'Z';
    put32(buf, 0x3c, peoff);
    if ((uint64_t)peoff + 24u + optsz > (uint64_t)len) return;
    memcpy(buf + peoff, "PE\0\0", 4);
    put16(buf, peoff + 4, 0x14c);   /* IMAGE_FILE_MACHINE_I386 */
    put16(buf, peoff + 6, ns);
    put16(buf, peoff + 20, optsz);
    opt = (size_t)peoff + 24u;
    put16(buf, opt, 0x10b);         /* PE32 magic */
    put32(buf, opt + 28, BASE);     /* ImageBase */
    put32(buf, opt + 56, 0x1000u);  /* SizeOfImage */
}

static int write_temp(const unsigned char *buf, size_t len,
                      char *path, size_t cap) {
    char tmpl[] = "/tmp/opencode/pelib-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    if (len && write(fd, buf, len) != (ssize_t)len) {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    close(fd);
    if (strlen(tmpl) >= cap) { unlink(tmpl); return -1; }
    strcpy(path, tmpl);
    return 0;
}

static int load_bytes(pe_image_t **img, const unsigned char *buf, size_t len) {
    char path[64];
    int rc;
    if (write_temp(buf, len, path, sizeof path) != 0) return -1;
    rc = pe_load(img, path, NULL);
    unlink(path);
    return rc;
}

/* Every rejected image must fail cleanly: nonzero return and *img == NULL. */
static int expect_rejected(const unsigned char *buf, size_t len) {
    pe_image_t *img = (pe_image_t *)0x1;
    int rc = load_bytes(&img, buf, len);
    if (rc == 0) {
        if (img) pe_unload(img);
        return -1;
    }
    if (img != NULL) return -1;
    return 0;
}

static const char *real_pe_path(void) {
    const char *p = getenv("CBM_PE_PATH");
    return (p && *p) ? p : "/tmp/opencode/ap.exe";
}

static void hook_noop(void) { }

static void test_hooks_accepted(void) {
    pe_import_hook_t hooks[3];
    pe_image_t *img = NULL;
    TEST("terminated import hook array accepted");
    hooks[0].dll = "KERNEL32.dll";
    hooks[0].name = "Sleep";
    hooks[0].fn = hook_noop;
    hooks[1].dll = "USER32.dll";
    hooks[1].name = "MessageBoxA";
    hooks[1].fn = hook_noop;
    memset(&hooks[2], 0, sizeof hooks[2]);
    if (pe_load(&img, real_pe_path(), hooks) != 0 || !img) {
        FAIL("load with hooks failed");
        return;
    }
    PASS();
    pe_unload(img);
}

static void test_hook_scan_bounded(void) {
    pe_import_hook_t *hooks = calloc(PE_MAX_IMPORT_HOOKS, sizeof *hooks);
    pe_image_t *img = NULL;
    size_t i;
    TEST("unterminated import hook array scan is bounded");
    if (!hooks) { FAIL("out of memory"); return; }
    for (i = 0; i < PE_MAX_IMPORT_HOOKS; i++) {
        hooks[i].dll = "KERNEL32.dll";
        hooks[i].name = "Sleep";
        hooks[i].fn = hook_noop;
    }
    if (pe_load(&img, real_pe_path(), hooks) != 0 || !img) {
        FAIL("load with maximal hook array failed");
        free(hooks);
        return;
    }
    free(hooks);                 /* the image owns a copy */
    PASS();
    pe_unload(img);
}

static void test_load_real_pe(void) {
    pe_image_t *img = NULL;
    void *p;
    TEST("load real PE at fixed ImageBase");
    if (pe_load(&img, real_pe_path(), NULL) != 0 || !img) {
        FAIL("pe_load failed");
        return;
    }
    p = pe_rva_to_va(img, ENCRYPT_RVA);
    if (!p) { FAIL("encrypt RVA not mapped"); pe_unload(img); return; }
    if (p != (void *)(uintptr_t)(BASE + ENCRYPT_RVA)) {
        FAIL("encrypt RVA resolved to wrong VA");
        pe_unload(img);
        return;
    }
    PASS();
    pe_unload(img);
}

static void test_bad_magic(void) {
    unsigned char buf[FAKE_SIZE];
    TEST("bad DOS magic rejected");
    make_pe(buf, sizeof buf, FAKE_PEOFF, 0, FAKE_OPT);
    buf[0] = 'X';
    if (expect_rejected(buf, sizeof buf) != 0) { FAIL("bad DOS magic accepted"); return; }
    PASS();
}

static void test_bad_pe_signature(void) {
    unsigned char buf[FAKE_SIZE];
    TEST("bad PE signature rejected");
    make_pe(buf, sizeof buf, FAKE_PEOFF, 0, FAKE_OPT);
    buf[FAKE_PEOFF + 2] = 'X';
    if (expect_rejected(buf, sizeof buf) != 0) { FAIL("bad PE signature accepted"); return; }
    PASS();
}

static void test_truncated_header(void) {
    unsigned char buf[FAKE_SIZE];
    TEST("truncated DOS header rejected");
    make_pe(buf, sizeof buf, FAKE_PEOFF, 0, FAKE_OPT);
    if (expect_rejected(buf, 32) != 0) { FAIL("32-byte file accepted"); return; }
    PASS();
}

static void test_e_lfanew_out_of_range(void) {
    unsigned char buf[FAKE_SIZE];
    TEST("e_lfanew past EOF rejected");
    make_pe(buf, sizeof buf, 0x1000u, 0, FAKE_OPT);
    if (expect_rejected(buf, sizeof buf) != 0) { FAIL("out-of-range e_lfanew accepted"); return; }
    PASS();
}

static void test_optional_header_too_small(void) {
    unsigned char buf[FAKE_SIZE];
    TEST("too-small optional header rejected");
    make_pe(buf, sizeof buf, FAKE_PEOFF, 0, 8);
    if (expect_rejected(buf, sizeof buf) != 0) { FAIL("8-byte optional header accepted"); return; }
    PASS();
}

static void test_section_table_overflow(void) {
    unsigned char buf[FAKE_SIZE];
    TEST("section table offset overflow rejected");
    /* e_lfanew + 24 + optional size wraps in 32-bit arithmetic. */
    make_pe(buf, sizeof buf, 0xfffffff0u, 0, FAKE_OPT);
    if (expect_rejected(buf, sizeof buf) != 0) { FAIL("wrapped e_lfanew accepted"); return; }
    /* Section count * 40 runs past EOF. */
    make_pe(buf, sizeof buf, FAKE_PEOFF, 0xffffu, FAKE_OPT);
    if (expect_rejected(buf, sizeof buf) != 0) { FAIL("oversized section table accepted"); return; }
    PASS();
}

static void test_section_raw_out_of_bounds(void) {
    unsigned char buf[FAKE_SIZE];
    size_t sh = FAKE_PEOFF + 24u + FAKE_OPT;
    TEST("section raw range overflow rejected");
    make_pe(buf, sizeof buf, FAKE_PEOFF, 1, FAKE_OPT);
    put32(buf, sh + 12, 0x1000u);   /* VirtualAddress */
    put32(buf, sh + 16, 0x10000u);  /* SizeOfRawData: past EOF with RawPtr */
    put32(buf, sh + 20, 0x1ff00u);  /* PointerToRawData */
    if (expect_rejected(buf, sizeof buf) != 0) { FAIL("raw range past EOF accepted"); return; }
    /* rp + rs wraps to a small value in 32-bit arithmetic. */
    make_pe(buf, sizeof buf, FAKE_PEOFF, 1, FAKE_OPT);
    put32(buf, sh + 12, 0x1000u);
    put32(buf, sh + 16, 0xfffffff0u);
    put32(buf, sh + 20, 0x100u);
    if (expect_rejected(buf, sizeof buf) != 0) { FAIL("wrapped raw range accepted"); return; }
    PASS();
}

static void test_second_load_rejected(void) {
    pe_image_t *a = NULL, *b = (pe_image_t *)0x1;
    TEST("second concurrent load rejected");
    if (pe_load(&a, real_pe_path(), NULL) != 0 || !a) { FAIL("first pe_load failed"); return; }
    if (pe_load(&b, real_pe_path(), NULL) == 0) {
        FAIL("second pe_load accepted");
        pe_unload(b);
        pe_unload(a);
        return;
    }
    if (b != NULL) { FAIL("second img not cleared"); pe_unload(a); return; }
    PASS();
    pe_unload(a);
}

static void test_unload_allows_reload(void) {
    pe_image_t *a = NULL, *b = NULL;
    TEST("unload then reload succeeds; double unload harmless");
    if (pe_load(&a, real_pe_path(), NULL) != 0 || !a) { FAIL("first pe_load failed"); return; }
    pe_unload(a);
    pe_unload(a);               /* must not munmap twice */
    if (pe_load(&b, real_pe_path(), NULL) != 0 || !b) { FAIL("reload after unload failed"); return; }
    if (!pe_rva_to_va(b, ENCRYPT_RVA)) { FAIL("reloaded image missing encrypt RVA"); pe_unload(b); return; }
    PASS();
    pe_unload(b);
}

static void test_rva_out_of_range(void) {
    pe_image_t *img = NULL;
    TEST("out-of-range RVA returns NULL");
    if (pe_load(&img, real_pe_path(), NULL) != 0 || !img) { FAIL("pe_load failed"); return; }
    if (pe_rva_to_va(img, MAPSZ) != NULL || pe_rva_to_va(img, 0xffffffffu) != NULL) {
        FAIL("out-of-range RVA accepted");
        pe_unload(img);
        return;
    }
    if (pe_rva_to_va(NULL, ENCRYPT_RVA) != NULL) { FAIL("NULL image accepted"); pe_unload(img); return; }
    PASS();
    pe_unload(img);
}

#ifndef __SANITIZE_ADDRESS__
static void test_base_already_mapped(void) {
    void *squatter;
    pe_image_t *img = (pe_image_t *)0x1;
    TEST("pre-mapped ImageBase rejected");
    squatter = mmap((void *)BASE, MAPSZ, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (squatter == MAP_FAILED) { FAIL("could not reserve ImageBase for probe"); return; }
    if (pe_load(&img, real_pe_path(), NULL) == 0) {
        FAIL("pre-mapped ImageBase accepted");
        if (img) pe_unload(img);
        munmap(squatter, MAPSZ);
        return;
    }
    if (img != NULL) { FAIL("img not cleared"); munmap(squatter, MAPSZ); return; }
    munmap(squatter, MAPSZ);
    PASS();
}
#endif

int main(void) {
    test_load_real_pe();
    test_bad_magic();
    test_bad_pe_signature();
    test_truncated_header();
    test_e_lfanew_out_of_range();
    test_optional_header_too_small();
    test_section_table_overflow();
    test_section_raw_out_of_bounds();
    test_second_load_rejected();
    test_unload_allows_reload();
    test_rva_out_of_range();
    test_hooks_accepted();
    test_hook_scan_bounded();
#ifndef __SANITIZE_ADDRESS__
    test_base_already_mapped();
#endif
    printf("test_pelib: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
