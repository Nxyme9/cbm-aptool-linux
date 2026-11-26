/* test_cdb_shim.c - synthetic-PE CDB capture tests
 *
 * No vendor PE, no device node and no network: one tiny PE with a single
 * kernel32.dll!DeviceIoControl import is built in memory, written to a
 * mkstemp file under /tmp/opencode, loaded with the shim hook table, and
 * called through the patched IAT slot. Capture files live in a separate
 * mkdtemp scratch directory so an unexpected extra file is detectable.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>

#include "pelib.h"
#include "cdb_shim.h"

#define BASE PE_BASE
#define FAKE_PEOFF 0x80u
#define FAKE_OPT 224u
#define SEC_RVA 0x1000u
#define SEC_RAW 0x200u
#define SEC_SIZE 0x400u
#define IMPORT_SIZE 40u
#define OFT_RVA 0x1040u
#define IAT_RVA 0x1050u
#define DLL_RVA 0x1060u
#define HINT_RVA 0x1070u
#define CTRL_SPT 0x0004d004u

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

typedef int (__attribute__((stdcall)) *fn8_t)(uint32_t, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef void *(__attribute__((stdcall)) *fn7_t)(uint32_t, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t);
typedef int (__attribute__((stdcall)) *fn1_t)(uint32_t);

static char g_scratch[] = "/tmp/opencode/cdb-shim-XXXXXX";
static char g_pe[] = "/tmp/opencode/cdb-shim-pe-XXXXXX";

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

/* Minimal PE32 with one .idata section: one import descriptor, one OFT/IAT
 * slot, the DLL name and the IMAGE_IMPORT_BY_NAME for DeviceIoControl. */
static void make_import_pe(unsigned char *buf, size_t len) {
    size_t pe = FAKE_PEOFF, opt = pe + 24u, sh = opt + FAKE_OPT;

    memset(buf, 0, len);
    buf[0] = 'M';
    buf[1] = 'Z';
    put32(buf, 0x3c, (uint32_t)pe);
    memcpy(buf + pe, "PE\0\0", 4);
    put16(buf, pe + 4, 0x14c);        /* IMAGE_FILE_MACHINE_I386 */
    put16(buf, pe + 6, 1);            /* one section */
    put16(buf, pe + 20, (uint16_t)FAKE_OPT);
    put16(buf, opt, 0x10b);           /* PE32 */
    put32(buf, opt + 28, BASE);
    put32(buf, opt + 56, PE_MAPSZ);   /* pe_call_void's state lives at 0x131328 */
    put32(buf, opt + 92, 16u);        /* NumberOfRvaAndSizes */
    put32(buf, opt + 104, SEC_RVA);   /* data directory[1]: import RVA */
    put32(buf, opt + 108, IMPORT_SIZE);

    memcpy(buf + sh, ".idata\0\0", 8);
    put32(buf, sh + 8, SEC_SIZE);     /* VirtualSize */
    put32(buf, sh + 12, SEC_RVA);     /* VirtualAddress */
    put32(buf, sh + 16, SEC_SIZE);    /* SizeOfRawData */
    put32(buf, sh + 20, SEC_RAW);     /* PointerToRawData */

    /* Import descriptor at file 0x200 (RVA 0x1000); 0x214 is the zero
     * terminator. RVA 0x1040 -> file 0x240, etc. */
    put32(buf, 0x200, OFT_RVA);
    put32(buf, 0x200 + 12, DLL_RVA);
    put32(buf, 0x200 + 16, IAT_RVA);
    put32(buf, 0x240, HINT_RVA);      /* OriginalFirstThunk[0] */
    put32(buf, 0x250, HINT_RVA);      /* FirstThunk[0] - patched by pelib */
    memcpy(buf + 0x260, "kernel32.dll", 13);
    put16(buf, 0x270, 0);             /* IMAGE_IMPORT_BY_NAME hint */
    memcpy(buf + 0x272, "DeviceIoControl", 16);
}

static int write_file(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    int ok = f && fwrite(buf, 1, len, f) == len;
    if (f) fclose(f);
    return ok ? 0 : -1;
}

/* Read the whole capture file; the caller compares every byte, never a
 * substring. Returned buffer is NUL-terminated for easy diagnostics. */
static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    char *buf;
    long n;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || n > 65536) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = malloc((size_t)n + 1u);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    buf[n] = '\0';
    *out_len = (size_t)n;
    return buf;
}

static void expect_capture(const char *label, const char *path,
                           const char *want, size_t want_len,
                           size_t want_events) {
    size_t got_len = 0;
    char *got = read_file(path, &got_len);
    if (!got) { FAIL("cannot read capture file"); return; }
    if (got_len != want_len || memcmp(got, want, want_len) != 0) {
        printf("got=[%s] ", got);
        FAIL("capture bytes differ from expected text");
    } else if (cdb_capture_count() != want_events) {
        printf("count=%lu ", (unsigned long)cdb_capture_count());
        FAIL("capture count differs from record count");
    } else {
        PASS();
    }
    free(got);
    (void)label;
}

static void (*find_hook_fn(const char *name))(void) {
    const pe_import_hook_t *h = cdb_shim_hooks();
    for (; h && h->name && h->fn; h++)
        if (strcasecmp(h->name, name) == 0) return h->fn;
    return NULL;
}

static char *cap_path(const char *name) {
    static char path[256];
    snprintf(path, sizeof path, "%s/%s", g_scratch, name);
    return path;
}

/* The first test's scratch directory must gain exactly one file. */
static int only_capture_in_scratch(const char *name) {
    DIR *d = opendir(g_scratch);
    struct dirent *e;
    int seen = 0;
    if (!d) return -1;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (strcmp(e->d_name, name) != 0) { closedir(d); return -1; }
        seen++;
    }
    closedir(d);
    return seen == 1 ? 0 : -1;
}

static void test_iat_dispatch_and_exact_capture(void) {
    static const char want[] =
        "cbm-cdb-capture/1\n"
        "event=DeviceIoControl ctrl=0x0004d004 in_len=64 in=40 00 a5 a5 a5 a5 06 a5 a"
        "5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 2a 00 00 00 00 00 a5 a5 a5 a5"
        " a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 "
        "a5 a5 a5 a5 a5 cdb_len=6 cdb=2a 00 00 00 00 00\n";
    pe_image_t *img = NULL;
    uint32_t *slot;
    void (*ioctl_fn)(void);
    fn8_t fn;
    unsigned char in[64], before[64], out[64];
    uint32_t bytes = 0xdeadbeefu;
    int rc;
    char *path = cap_path("cap-1.txt");

    TEST("IAT dispatch writes byte-exact SCSI CDB capture");
    memset(in, 0xa5, sizeof in);
    put16(in, 0, (uint16_t)sizeof in);  /* SCSI_PASS_THROUGH.Length */
    in[6] = 6;                          /* CdbLength */
    in[24] = 0x2a;                      /* Cdb[0] */
    in[25] = in[26] = in[27] = in[28] = in[29] = 0;
    memcpy(before, in, sizeof in);
    memset(out, 0x5a, sizeof out);

    if (cdb_capture_open(path) != 0) { FAIL("capture open failed"); return; }
    if (pe_load(&img, g_pe, cdb_shim_hooks()) != 0 || !img) {
        FAIL("synthetic PE load failed");
        cdb_capture_close();
        return;
    }
    slot = (uint32_t *)pe_rva_to_va(img, IAT_RVA);
    ioctl_fn = find_hook_fn("DeviceIoControl");
    if (!slot || !ioctl_fn || *slot != (uint32_t)(uintptr_t)ioctl_fn) {
        printf("slot=%08x hook=%08x ", slot ? *slot : 0u,
               ioctl_fn ? (unsigned)(uintptr_t)ioctl_fn : 0u);
        FAIL("DeviceIoControl IAT slot not patched");
        pe_unload(img);
        cdb_capture_close();
        return;
    }
    fn = (fn8_t)(uintptr_t)*slot;
    rc = fn(0x1234u, CTRL_SPT, (uint32_t)(uintptr_t)in, (uint32_t)sizeof in,
            (uint32_t)(uintptr_t)out, (uint32_t)sizeof out,
            (uint32_t)(uintptr_t)&bytes, 0u);
    if (rc != 1) { FAIL("DeviceIoControl did not return TRUE"); }
    else if (memcmp(in, before, sizeof in) != 0) { FAIL("input buffer was modified"); }
    else if (bytes != 0u) { FAIL("BytesReturned was not zeroed"); }
    else {
        size_t i;
        for (i = 0; i < sizeof out; i++) {
            if (out[i] != 0) break;
        }
        if (i != sizeof out) FAIL("output buffer was not zeroed");
        else if (only_capture_in_scratch("cap-1.txt") != 0)
            FAIL("unexpected extra file in scratch directory");
        else expect_capture("scsi", path, want, sizeof want - 1u, 1u);
    }
    pe_unload(img);
    cdb_capture_close();
    unlink(path);
}

static void test_unknown_control_logs_raw_input(void) {
    static const char want[] =
        "cbm-cdb-capture/1\n"
        "event=DeviceIoControl ctrl=0x80000000 in_len=4 in=de ad be ef\n";
    unsigned char in[4] = {0xde, 0xad, 0xbe, 0xef};
    fn8_t fn = (fn8_t)(uintptr_t)find_hook_fn("DeviceIoControl");
    char *path = cap_path("cap-2.txt");

    TEST("unknown control code logs raw input only");
    if (!fn || cdb_capture_open(path) != 0) { FAIL("hook or capture open failed"); return; }
    if (fn(1u, 0x80000000u, (uint32_t)(uintptr_t)in, sizeof in, 0u, 0u, 0u, 0u) != 1)
        FAIL("unexpected shim return");
    else
        expect_capture("unknown", path, want, sizeof want - 1u, 1u);
    cdb_capture_close();
    unlink(path);
}

static void test_long_input_is_truncated(void) {
    unsigned char in[300];
    fn8_t fn = (fn8_t)(uintptr_t)find_hook_fn("DeviceIoControl");
    char want[4096];
    size_t pos = 0;
    size_t i;
    int n;
    char *path = cap_path("cap-3.txt");
    size_t got_len = 0;
    char *got;

    TEST("in_len > 256 appends truncated=1 and logs 256 bytes");
    memset(in, 0x11, sizeof in);
    n = snprintf(want + pos, sizeof want - pos,
                 "cbm-cdb-capture/1\nevent=DeviceIoControl ctrl=0x80000000 in_len=300 in=");
    pos += (size_t)n;
    for (i = 0; i < 256u; i++) {
        n = snprintf(want + pos, sizeof want - pos, "%s%02x", i ? " " : "", in[i]);
        pos += (size_t)n;
    }
    pos += (size_t)snprintf(want + pos, sizeof want - pos, " truncated=1\n");
    if (!fn || cdb_capture_open(path) != 0) { FAIL("hook or capture open failed"); return; }
    if (fn(1u, 0x80000000u, (uint32_t)(uintptr_t)in, sizeof in, 0u, 0u, 0u, 0u) != 1) {
        FAIL("unexpected shim return");
    } else {
        got = read_file(path, &got_len);
        if (!got) FAIL("cannot read capture file");
        else if (got_len != pos || memcmp(got, want, pos) != 0)
            FAIL("truncated capture bytes differ from expected text");
        else if (cdb_capture_count() != 1u)
            FAIL("capture count differs from record count");
        else PASS();
        free(got);
    }
    cdb_capture_close();
    unlink(path);
}

static void test_null_buffers_are_safe(void) {
    static const char want[] =
        "cbm-cdb-capture/1\n"
        "event=DeviceIoControl ctrl=0x0004d004 in_len=0 in=\n";
    fn8_t fn = (fn8_t)(uintptr_t)find_hook_fn("DeviceIoControl");
    char *path = cap_path("cap-4.txt");

    TEST("NULL input and NULL BytesReturned are safe");
    if (!fn || cdb_capture_open(path) != 0) { FAIL("hook or capture open failed"); return; }
    if (fn(0u, CTRL_SPT, 0u, 0u, 0u, 0u, 0u, 0u) != 1)
        FAIL("unexpected shim return");
    else
        expect_capture("null", path, want, sizeof want - 1u, 1u);
    cdb_capture_close();
    unlink(path);
}

static void test_shims_without_capture_write_nothing(void) {
    fn8_t ioctl = (fn8_t)(uintptr_t)find_hook_fn("DeviceIoControl");
    fn7_t create = (fn7_t)(uintptr_t)find_hook_fn("CreateFileA");
    fn1_t close = (fn1_t)(uintptr_t)find_hook_fn("CloseHandle");
    unsigned char in[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char out[8];
    uint32_t bytes = 0xabcdef01u;
    void *handle;

    TEST("synthetic success without a capture and no writes");
    memset(out, 0x5a, sizeof out);
    if (cdb_capture_path() != NULL || cdb_capture_count() != 0u) {
        FAIL("stale capture state"); return;
    }
    if (!ioctl || !create || !close) { FAIL("hook table incomplete"); return; }
    if (ioctl(1u, CTRL_SPT, (uint32_t)(uintptr_t)in, sizeof in,
              (uint32_t)(uintptr_t)out, sizeof out,
              (uint32_t)(uintptr_t)&bytes, 0u) != 1)
        FAIL("ioctl without capture did not return TRUE");
    else if (out[0] != 0x5a || bytes != 0xabcdef01u ||
             memcmp(in, "\1\2\3\4\5\6\7\10", sizeof in) != 0)
        FAIL("shim wrote without an open capture");
    else {
        handle = create(1u, 0u, 0u, 0u, 0u, 0u, 0u); /* bogus path pointer */
        if (!handle || handle == (void *)(uintptr_t)-1)
            FAIL("CreateFileA fake handle invalid");
        else if (close(1u) != 1)
            FAIL("CloseHandle did not return TRUE");
        else if (cdb_capture_count() != 0u || cdb_capture_path() != NULL)
            FAIL("capture state changed without a capture");
        else PASS();
    }
}

static void test_capture_guards(void) {
    const pe_import_hook_t *h = cdb_shim_hooks();
    int names = 0;
    char *path = cap_path("cap-5.txt");
    struct stat st;

    TEST("hook table and single-capture guards");
    for (; h && h->name && h->fn; h++) {
        if (strcasecmp(h->name, "DeviceIoControl") == 0 ||
            strcasecmp(h->name, "CreateFileA") == 0 ||
            strcasecmp(h->name, "CreateFileW") == 0 ||
            strcasecmp(h->name, "CloseHandle") == 0)
            names++;
    }
    if (names != 4) { FAIL("required hooks missing"); return; }
    if (stat(g_scratch, &st) != 0 || !S_ISDIR(st.st_mode)) {
        FAIL("scratch directory missing"); return;
    }
    if (cdb_capture_open(g_scratch) == 0) {
        FAIL("directory accepted as capture file"); return;
    }
    if (cdb_capture_open(path) != 0) { FAIL("capture open failed"); return; }
    if (cdb_capture_open(path) == 0 || cdb_capture_path() == NULL ||
        strcmp(cdb_capture_path(), path) != 0) {
        FAIL("second capture accepted or path not reported");
    } else PASS();
    cdb_capture_close();
    cdb_capture_close();              /* double close must be harmless */
    unlink(path);
}

static void test_create_file_lines(void) {
    static const char want[] =
        "cbm-cdb-capture/1\n"
        "event=CreateFileA path=C:\\x5ca\\x20b\\x25c\\x3dd\\x5cz access=0x80000000\n"
        "event=CreateFileW wide=1 path_hex=41004200\n"
        "event=kernel32.dll!Sleep\n";
    fn7_t create_a = (fn7_t)(uintptr_t)find_hook_fn("CreateFileA");
    fn7_t create_w = (fn7_t)(uintptr_t)find_hook_fn("CreateFileW");
    fn1_t close = (fn1_t)(uintptr_t)find_hook_fn("CloseHandle");
    const uint16_t wide[3] = {0x0041, 0x0042, 0x0000};
    const char *path_a = "C:\\a b%c=d\\z";
    char *path = cap_path("cap-6.txt");
    void *h;

    TEST("CreateFileA/W escaping and unknown-import record");
    if (!create_a || !create_w || !close || cdb_capture_open(path) != 0) {
        FAIL("hook or capture open failed"); return;
    }
    h = create_a((uint32_t)(uintptr_t)path_a, 0x80000000u, 0u, 0u, 0u, 0u, 0u);
    if (!h || h == (void *)(uintptr_t)-1) FAIL("CreateFileA fake handle invalid");
    else {
        h = create_w((uint32_t)(uintptr_t)wide, 0u, 0u, 0u, 0u, 0u, 0u);
        if (!h || h == (void *)(uintptr_t)-1) FAIL("CreateFileW fake handle invalid");
        else if (close((uint32_t)(uintptr_t)h) != 1) FAIL("CloseHandle did not return TRUE");
        else {
            cdb_shim_log_unknown("kernel32.dll", "Sleep");
            expect_capture("create", path, want, sizeof want - 1u, 3u);
        }
    }
    cdb_capture_close();
    unlink(path);
}

int main(void) {
    unsigned char buf[SEC_RAW + SEC_SIZE];
    int fd = mkstemp(g_pe);

    if (fd < 0 || mkdtemp(g_scratch) == NULL) {
        FAIL("scratch setup failed");
        printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
        return 1;
    }
    close(fd);                         /* write_file truncates and rewrites it */
    make_import_pe(buf, sizeof buf);
    if (write_file(g_pe, buf, sizeof buf) != 0) {
        FAIL("cannot write synthetic PE");
    } else {
        test_iat_dispatch_and_exact_capture();
        test_unknown_control_logs_raw_input();
        test_long_input_is_truncated();
        test_null_buffers_are_safe();
        test_shims_without_capture_write_nothing();
        test_capture_guards();
        test_create_file_lines();
    }
    unlink(g_pe);
    rmdir(g_scratch);
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
