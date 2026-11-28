/* cdb_shim.c - software-only Win32 import stubs with a deterministic capture
 *
 * The stubs are installed through pelib's IAT hook table. They never call a
 * Windows API and never touch a device. With no capture file open they only
 * return the synthetic success value; no caller pointer is read or written.
 */
#define _GNU_SOURCE
#include "cdb_shim.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CDB_LOG_IN_MAX 256u
#define CDB_ZERO_OUT_MAX 512u
#define CDB_PATH_SCAN_MAX 512u
#define CDB_WIDE_SCAN_MAX 256u
#define CDB_NAME_SCAN_MAX 256u
#define CDB_CTRL_SPT 0x0004d004u
#define CDB_CTRL_SPT_DIRECT 0x0004d014u
#define CDB_LENGTH_OFFSET 6u
#define CDB_SPT_ARRAY_OFFSET 24u
#define CDB_SPT_DIRECT_ARRAY_OFFSET 28u
#define CDB_ARRAY_SIZE 16u
#define CDB_FAKE_HANDLE ((void *)(uintptr_t)0x0cdbf00du)

static FILE *g_capture;
static char *g_capture_path;
static size_t g_events;

static size_t bounded_strlen(const char *s, size_t cap) {
    size_t n = 0;
    if (!s) return 0;
    while (n < cap && s[n] != '\0') n++;
    return n;
}

static int ranges_overlap(uint32_t a, uint32_t alen, uint32_t b, uint32_t blen) {
    uint64_t a0, a1, b0, b1;
    if (!a || !b || !alen || !blen) return 0;
    a0 = (uint64_t)a;
    a1 = a0 + alen;
    b0 = (uint64_t)b;
    b1 = b0 + blen;
    return a0 < b1 && b0 < a1;
}

static void write_hex_spaced(FILE *f, const unsigned char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (i) fputc(' ', f);
        fprintf(f, "%02x", p[i]);
    }
}

/* Printable ASCII is kept verbatim except space, '%', '=' and '\\', which
 * are escaped as \\xNN along with every non-printable byte. */
static void write_escaped_ascii(FILE *f, const char *s, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20u && c <= 0x7eu && c != ' ' && c != '%' &&
            c != '=' && c != '\\')
            fputc((int)c, f);
        else
            fprintf(f, "\\x%02x", (unsigned)c);
    }
}

/* Wide paths are published as raw little-endian UTF-16 code-unit bytes. */
static void write_wide_hex(FILE *f, const uint16_t *s, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        uint16_t unit;
        memcpy(&unit, s + i, sizeof unit);
        fprintf(f, "%02x%02x", (unsigned)(unit & 0xffu),
                (unsigned)((unit >> 8) & 0xffu));
    }
}

static void end_record(void) {
    if (!g_capture) return;
    (void)fputc('\n', g_capture);
    (void)fflush(g_capture);          /* a record is visible as soon as it ends */
    g_events++;
}

int cdb_capture_open(const char *path) {
    struct stat st;
    FILE *f;
    char *copy;
    size_t n;

    if (g_capture) {
        fprintf(stderr, "Error: cdb-capture --out: a capture is already open\n");
        return -1;
    }
    if (!path || !*path) {
        fprintf(stderr, "Error: cdb-capture --out needs a file path\n");
        return -1;
    }
    if (stat(path, &st) == 0) {
        if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode) || S_ISDIR(st.st_mode)) {
            fprintf(stderr,
                    "Error: cdb-capture --out refuses a device or directory: '%s'\n",
                    path);
            return -1;
        }
    } else if (errno != ENOENT) {
        fprintf(stderr, "Error: cdb-capture --out cannot stat '%s'\n", path);
        return -1;
    }
    f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Error: cdb-capture --out cannot create '%s'\n", path);
        return -1;
    }
    n = strlen(path) + 1u;
    copy = malloc(n);
    if (!copy) {
        fclose(f);
        fprintf(stderr, "Error: cdb-capture --out out of memory\n");
        return -1;
    }
    memcpy(copy, path, n);
    g_capture = f;
    g_capture_path = copy;
    g_events = 0;
    fprintf(g_capture, "cbm-cdb-capture/1\n");
    (void)fflush(g_capture);
    return 0;
}

void cdb_capture_close(void) {
    if (!g_capture) return;
    (void)fclose(g_capture);
    g_capture = NULL;
    free(g_capture_path);
    g_capture_path = NULL;
    g_events = 0;
}

size_t cdb_capture_count(void) {
    return g_events;
}

const char *cdb_capture_path(void) {
    return g_capture_path;
}

void cdb_shim_log_unknown(const char *dll, const char *name) {
    if (!g_capture || !dll || !name) return;
    fprintf(g_capture, "event=%.*s!%.*s",
            (int)bounded_strlen(dll, CDB_NAME_SCAN_MAX), dll,
            (int)bounded_strlen(name, CDB_NAME_SCAN_MAX), name);
    end_record();
}

static void log_device_io_control(uint32_t ctrl, uint32_t in_ptr, uint32_t in_len) {
    const unsigned char *p = in_ptr ? (const unsigned char *)(uintptr_t)in_ptr : NULL;
    size_t log_n = (in_len > CDB_LOG_IN_MAX) ? CDB_LOG_IN_MAX : (size_t)in_len;
    uint32_t cdb_offset;
    size_t declared;
    size_t avail;

    fprintf(g_capture, "event=DeviceIoControl ctrl=0x%08x in_len=%u in=",
            (unsigned)ctrl, (unsigned)in_len);
    if (p) write_hex_spaced(g_capture, p, log_n);
    if (in_len > CDB_LOG_IN_MAX) fputs(" truncated=1", g_capture);

    if (ctrl != CDB_CTRL_SPT && ctrl != CDB_CTRL_SPT_DIRECT) {
        end_record();
        return;
    }
    /* No CDB field is published without a bounds-checked source buffer. */
    cdb_offset = (ctrl == CDB_CTRL_SPT) ? CDB_SPT_ARRAY_OFFSET
                                        : CDB_SPT_DIRECT_ARRAY_OFFSET;
    if (!p || in_len <= CDB_LENGTH_OFFSET || in_len <= cdb_offset) {
        end_record();
        return;
    }
    declared = p[CDB_LENGTH_OFFSET];
    avail = (size_t)in_len - cdb_offset;
    if (declared > CDB_ARRAY_SIZE) declared = CDB_ARRAY_SIZE;
    if (declared > avail) declared = avail;
    fprintf(g_capture, " cdb_len=%u cdb=", (unsigned)declared);
    write_hex_spaced(g_capture, p + cdb_offset, declared);
    end_record();
}

static int __attribute__((stdcall)) shim_device_io_control(
        uint32_t handle, uint32_t ctrl, uint32_t in_ptr, uint32_t in_len,
        uint32_t out_ptr, uint32_t out_len, uint32_t bytes_ptr,
        uint32_t overlapped) {
    (void)handle;
    (void)overlapped;
    if (!g_capture) return 1;       /* synthetic success, no writes at all */

    if (bytes_ptr && !ranges_overlap(bytes_ptr, 4u, in_ptr, in_len))
        *(uint32_t *)(uintptr_t)bytes_ptr = 0u;
    if (out_ptr && out_len) {
        size_t n = (out_len > CDB_ZERO_OUT_MAX) ? CDB_ZERO_OUT_MAX : (size_t)out_len;
        if (!ranges_overlap(out_ptr, (uint32_t)n, in_ptr, in_len))
            memset((void *)(uintptr_t)out_ptr, 0, n);
    }
    log_device_io_control(ctrl, in_ptr, in_len);
    return 1;
}

static void *__attribute__((stdcall)) shim_create_file_a(
        uint32_t name_ptr, uint32_t access, uint32_t share, uint32_t security,
        uint32_t creation, uint32_t flags, uint32_t template_file) {
    (void)share;
    (void)security;
    (void)creation;
    (void)flags;
    (void)template_file;
    if (g_capture) {
        size_t n = bounded_strlen((const char *)(uintptr_t)name_ptr,
                                  CDB_PATH_SCAN_MAX);
        fprintf(g_capture, "event=CreateFileA path=");
        write_escaped_ascii(g_capture, (const char *)(uintptr_t)name_ptr, n);
        fprintf(g_capture, " access=0x%08x", (unsigned)access);
        end_record();
    }
    return CDB_FAKE_HANDLE;
}

static void *__attribute__((stdcall)) shim_create_file_w(
        uint32_t name_ptr, uint32_t access, uint32_t share, uint32_t security,
        uint32_t creation, uint32_t flags, uint32_t template_file) {
    (void)access;
    (void)share;
    (void)security;
    (void)creation;
    (void)flags;
    (void)template_file;
    if (g_capture && name_ptr) {
        const uint16_t *p = (const uint16_t *)(uintptr_t)name_ptr;
        size_t n = 0;
        while (n < CDB_WIDE_SCAN_MAX) {
            uint16_t unit;
            memcpy(&unit, p + n, sizeof unit);
            if (unit == 0) break;
            n++;
        }
        fprintf(g_capture, "event=CreateFileW wide=1 path_hex=");
        write_wide_hex(g_capture, p, n);
        end_record();
    }
    return CDB_FAKE_HANDLE;
}

static int __attribute__((stdcall)) shim_close_handle(uint32_t handle) {
    (void)handle;
    return 1;
}

static const pe_import_hook_t g_hooks[] = {
    {"kernel32.dll", "DeviceIoControl",
     (void (*)(void))(uintptr_t)shim_device_io_control},
    {"kernel32.dll", "CreateFileA",
     (void (*)(void))(uintptr_t)shim_create_file_a},
    {"kernel32.dll", "CreateFileW",
     (void (*)(void))(uintptr_t)shim_create_file_w},
    {"kernel32.dll", "CloseHandle",
     (void (*)(void))(uintptr_t)shim_close_handle},
    {NULL, NULL, NULL}
};

const pe_import_hook_t *cdb_shim_hooks(void) {
    return g_hooks;
}
