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
#define DECRYPT_RVA 0x59d50u         /* VA 0x459d50 - ImageBase */
#define TEA_KEY "1a2b3c4d5e6fTENG"   /* allowlisted in .gitleaks.toml */
#define HOOK_IAT_RVA 0xf6068u        /* COMDLG32.dll!GetFileTitleA in ap.exe */

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
    return (p && *p) ? p : NULL;
}

/* Real-PE cases are opt-in research cross-checks: skip cleanly when no path
 * was supplied or the supplied file is absent, without counting pass/fail. */
#define SKIP_UNLESS_REAL_PE() do {                                      \
    const char *skip_pe_ = real_pe_path();                              \
    if (!skip_pe_) {                                                    \
        printf("SKIP (CBM_PE_PATH not set)\n");                         \
        return;                                                         \
    }                                                                   \
    if (access(skip_pe_, F_OK) != 0) {                                  \
        printf("SKIP (PE oracle %s not present)\n", skip_pe_);          \
        return;                                                         \
    }                                                                   \
} while (0)

/* No vendor binary may be inferred from a NULL path when the environment is
 * empty; the failure must be clean and must leave *img cleared. */
static void test_null_path_needs_env(void) {
    const char *saved = real_pe_path();
    pe_image_t *img = (pe_image_t *)0x1;
    int rc;
    TEST("NULL path rejected without CBM_PE_PATH");
    if (unsetenv("CBM_PE_PATH") != 0) { FAIL("cannot clear CBM_PE_PATH"); return; }
    rc = pe_load(&img, NULL, NULL);
    if (saved && setenv("CBM_PE_PATH", saved, 1) != 0) {
        FAIL("cannot restore CBM_PE_PATH");
        return;
    }
    if (rc == 0) {
        if (img) pe_unload(img);
        FAIL("NULL path accepted without CBM_PE_PATH");
    } else if (img != NULL) {
        FAIL("img not cleared");
    } else {
        PASS();
    }
}

static void hook_noop(void) { }

/* Real stdcall stub: the patched IAT slot is invoked with three words, so
 * the callee must clean those three words. Captures arguments for assertions. */
static int g_hook_calls;
static uint32_t g_hook_w[3];
static void __attribute__((stdcall)) hook_stub(uint32_t a, uint32_t b, uint32_t c) {
    g_hook_calls++;
    g_hook_w[0] = a;
    g_hook_w[1] = b;
    g_hook_w[2] = c;
}

static void test_hooks_accepted(void) {
    pe_import_hook_t hooks[3];
    pe_image_t *img = NULL;
    TEST("terminated import hook array accepted");
    SKIP_UNLESS_REAL_PE();
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
    SKIP_UNLESS_REAL_PE();
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
    SKIP_UNLESS_REAL_PE();
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

/* A 60-byte PE32 optional header is valid, but NumberOfRvaAndSizes at +92
 * lies past EOF when the file ends at the header. pe_load must not read it
 * before checking the optional-header size. The image is otherwise valid;
 * reserving ImageBase makes pe_load reject it *after* header parsing, so the
 * rejection path still reaches the would-be over-read (ASan catches it). */
static void test_short_optional_header_no_overread(void) {
    unsigned char buf[FAKE_PEOFF + 24u + 60u];
    void *squatter;
    TEST("short optional header: no data-directory over-read");
    make_pe(buf, sizeof buf, FAKE_PEOFF, 0, 60u);
    squatter = mmap((void *)BASE, MAPSZ, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (squatter == MAP_FAILED) { FAIL("could not reserve ImageBase for probe"); return; }
    if (expect_rejected(buf, sizeof buf) != 0) {
        munmap(squatter, MAPSZ);
        FAIL("short optional header not rejected cleanly");
        return;
    }
    munmap(squatter, MAPSZ);
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
    SKIP_UNLESS_REAL_PE();
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
    SKIP_UNLESS_REAL_PE();
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
    SKIP_UNLESS_REAL_PE();
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
    SKIP_UNLESS_REAL_PE();
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

/* ---- Task 2: generic call API, exports, hook dispatch ---- */

static void dump_hex(const unsigned char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", p[i]);
}

static void test_golden_encrypt_via_pelib(void) {
    pe_image_t *img = NULL;
    unsigned char block[8] = {0};
    const char *key = TEA_KEY;
    uint32_t args[3];
    static const unsigned char want[8] = {
        0xe6, 0x62, 0x54, 0xb5, 0xda, 0x09, 0xfb, 0x31
    };

    TEST("golden TEA encrypt via pe_call_void");
    SKIP_UNLESS_REAL_PE();
    if (pe_load(&img, real_pe_path(), NULL) != 0 || !img) {
        FAIL("pe_load failed"); return;
    }
    args[0] = (uint32_t)(uintptr_t)block;
    args[1] = 8u;
    args[2] = (uint32_t)(uintptr_t)key;

    if (pe_call_void(NULL, ENCRYPT_RVA, args, sizeof args) == 0) {
        FAIL("NULL image accepted"); pe_unload(img); return;
    }
    if (pe_call_void(img, ENCRYPT_RVA, args, 13) == 0) {
        FAIL("n > 12 accepted"); pe_unload(img); return;
    }
    if (pe_call_void(img, ENCRYPT_RVA, args, 5) == 0) {
        FAIL("n % 4 != 0 accepted"); pe_unload(img); return;
    }
    if (pe_call_void(img, ENCRYPT_RVA, args, sizeof args) != 0) {
        FAIL("pe_call_void failed"); pe_unload(img); return;
    }
    if (memcmp(block, want, sizeof want) != 0) {
        printf("got "); dump_hex(block, sizeof block); printf(" ");
        FAIL("ciphertext mismatch"); pe_unload(img); return;
    }
    /* The same VA must work as well as the RVA. */
    memset(block, 0, sizeof block);
    if (pe_call_void(img, BASE + ENCRYPT_RVA, args, sizeof args) != 0 ||
        memcmp(block, want, sizeof want) != 0) {
        FAIL("VA form of target failed"); pe_unload(img); return;
    }
    PASS();
    pe_unload(img);
}

static void test_golden_decrypt_roundtrip(void) {
    pe_image_t *img = NULL;
    unsigned char block[8] = {0xe6, 0x62, 0x54, 0xb5, 0xda, 0x09, 0xfb, 0x31};
    const unsigned char zeros[8] = {0};
    const char *key = TEA_KEY;
    uint32_t args[3];

    TEST("golden TEA decrypt roundtrip via pe_call_void");
    SKIP_UNLESS_REAL_PE();
    if (pe_load(&img, real_pe_path(), NULL) != 0 || !img) {
        FAIL("pe_load failed"); return;
    }
    args[0] = (uint32_t)(uintptr_t)block;
    args[1] = 8u;
    args[2] = (uint32_t)(uintptr_t)key;
    if (pe_call_void(img, DECRYPT_RVA, args, sizeof args) != 0) {
        FAIL("pe_call_void(decrypt) failed"); pe_unload(img); return;
    }
    if (memcmp(block, zeros, sizeof zeros) != 0) {
        printf("got "); dump_hex(block, sizeof block); printf(" ");
        FAIL("decrypt did not roundtrip to zeros"); pe_unload(img); return;
    }
    PASS();
    pe_unload(img);
}

static void test_export_lookup_real(void) {
    pe_image_t *img = NULL;
    uint32_t rva = 0xdeadbeefu;

    TEST("export lookup: clean not-found on real PE");
    SKIP_UNLESS_REAL_PE();
    if (pe_load(&img, real_pe_path(), NULL) != 0 || !img) {
        FAIL("real pe_load failed"); return;
    }
    if (pe_export(img, "NoSuchExport_5G", &rva) == 0 || rva != 0) {
        FAIL("bogus export accepted on vendor PE"); pe_unload(img); return;
    }
    if (pe_export(img, NULL, &rva) == 0) {
        FAIL("NULL export name accepted"); pe_unload(img); return;
    }
    PASS();
    pe_unload(img);
}

static void test_export_lookup_synthetic(void) {
    pe_image_t *img = NULL;
    uint32_t rva;
    unsigned char buf[1024];
    size_t opt = FAKE_PEOFF + 24u, sh = opt + FAKE_OPT;

    TEST("export lookup: synthetic export resolved");
    /* A tiny scratch PE exercises the found path without any vendor PE. */
    make_pe(buf, sizeof buf, FAKE_PEOFF, 1, FAKE_OPT);
    memcpy(buf + sh, ".text\0\0\0", 8);
    put32(buf, sh + 8, 0x400u);        /* VirtualSize */
    put32(buf, sh + 12, 0x1000u);      /* VirtualAddress */
    put32(buf, sh + 16, 0x200u);       /* SizeOfRawData */
    put32(buf, sh + 20, 0x200u);       /* PointerToRawData */
    put32(buf, opt + 56, 0x2000u);     /* SizeOfImage */
    put32(buf, opt + 92, 16u);         /* NumberOfRvaAndSizes */
    put32(buf, opt + 96, 0x1000u);     /* export directory RVA */
    put32(buf, opt + 100, 40u);        /* export directory size */
    /* The 40-byte export directory itself occupies file 0x200..0x227, so
     * EAT/ENT/ordinal tables must start after it, not inside it. */
    put32(buf, 0x200 + 12, 0x1050u);   /* export Name RVA */
    put32(buf, 0x200 + 16, 1u);        /* Base */
    put32(buf, 0x200 + 20, 1u);        /* NumberOfFunctions */
    put32(buf, 0x200 + 24, 1u);        /* NumberOfNames */
    put32(buf, 0x200 + 28, 0x1030u);   /* AddressOfFunctions */
    put32(buf, 0x200 + 32, 0x1034u);   /* AddressOfNames */
    put32(buf, 0x200 + 36, 0x1038u);   /* AddressOfNameOrdinals */
    put32(buf, 0x230, 0x1500u);        /* EAT[0] */
    put32(buf, 0x234, 0x1040u);        /* ENT[0] -> "MyExport" */
    put16(buf, 0x238, 0u);             /* ordinal[0] */
    memcpy(buf + 0x240, "MyExport", 9);
    memcpy(buf + 0x250, "synthetic.dll", 14);

    if (load_bytes(&img, buf, sizeof buf) != 0 || !img) {
        FAIL("synthetic pe_load failed"); return;
    }
    rva = 0;
    if (pe_export(img, "MyExport", &rva) != 0 || rva != 0x1500u) {
        printf("rva=%08x ", rva);
        FAIL("synthetic export not resolved"); pe_unload(img); return;
    }
    if (pe_export(img, "Missing", &rva) == 0 || rva != 0) {
        FAIL("missing name accepted on synthetic PE"); pe_unload(img); return;
    }
    PASS();
    pe_unload(img);
}

static void test_import_hook_dispatch(void) {
    pe_image_t *img = NULL;
    pe_import_hook_t hooks[2];
    uint32_t *slot;
    typedef void (__attribute__((stdcall)) *fn3_t)(uint32_t, uint32_t, uint32_t);

    TEST("import hook patched into IAT and dispatched");
    SKIP_UNLESS_REAL_PE();
    hooks[0].dll = "COMDLG32.dll";
    hooks[0].name = "GetFileTitleA";
    hooks[0].fn = (void (*)(void))(uintptr_t)hook_stub;
    memset(&hooks[1], 0, sizeof hooks[1]);
    if (pe_load(&img, real_pe_path(), hooks) != 0 || !img) {
        FAIL("load with hook failed"); return;
    }
    slot = (uint32_t *)pe_rva_to_va(img, HOOK_IAT_RVA);
    if (!slot) {
        FAIL("hook IAT slot not mapped"); pe_unload(img); return;
    }
    if (*slot != (uint32_t)(uintptr_t)hook_stub) {
        printf("slot=%08x stub=%08x ", *slot, (unsigned)(uintptr_t)hook_stub);
        FAIL("IAT slot not patched to stub"); pe_unload(img); return;
    }
    g_hook_calls = 0;
    g_hook_w[0] = g_hook_w[1] = g_hook_w[2] = 0;
    ((fn3_t)(void *)(uintptr_t)*slot)(0x11223344u, 0x55667788u, 0x99aabbccu);
    if (g_hook_calls != 1 || g_hook_w[0] != 0x11223344u ||
        g_hook_w[1] != 0x55667788u || g_hook_w[2] != 0x99aabbccu) {
        FAIL("hook stub not dispatched through IAT with args");
        pe_unload(img); return;
    }
    PASS();
    pe_unload(img);
}

int main(void) {
    test_null_path_needs_env();
    test_load_real_pe();
    test_bad_magic();
    test_bad_pe_signature();
    test_truncated_header();
    test_e_lfanew_out_of_range();
    test_optional_header_too_small();
    test_short_optional_header_no_overread();
    test_section_table_overflow();
    test_section_raw_out_of_bounds();
    test_second_load_rejected();
    test_unload_allows_reload();
    test_rva_out_of_range();
    test_hooks_accepted();
    test_hook_scan_bounded();
    test_golden_encrypt_via_pelib();
    test_golden_decrypt_roundtrip();
    test_export_lookup_real();
    test_export_lookup_synthetic();
    test_import_hook_dispatch();
#ifndef __SANITIZE_ADDRESS__
    test_base_already_mapped();
#endif
    printf("test_pelib: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
