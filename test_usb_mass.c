/* test_usb_mass.c - Linux USB mass-storage block device layer tests */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "usb_mass.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static char tmp_path[64];

/* Unique per-run scratch file: mkstemp avoids pre-existing-file/symlink races. */
static int make_tmp_file(void) {
    char templ[] = "/tmp/opencode/usb_mass_test_XXXXXX";
    int fd = mkstemp(templ);
    if (fd < 0) return -1;
    close(fd);
    snprintf(tmp_path, sizeof(tmp_path), "%s", templ);
    return 0;
}

static void remove_tmp_file(void) {
    if (tmp_path[0]) unlink(tmp_path);
}

static void test_open_write_read_close(void) {
    TEST("usb_mass open/write/read/close");
    int fd = open(tmp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) close(fd);
    usb_mass_dev_t dev;
    if (usb_mass_open(tmp_path, &dev) != 0) { FAIL("open failed"); return; }
    if (usb_mass_capacity(&dev) != 0) { FAIL("capacity after truncate"); usb_mass_close(&dev); return; }
    unsigned char wbuf[64];
    for (int i = 0; i < 64; i++) wbuf[i] = (unsigned char)(i * 3 + 1);
    if (usb_mass_write(&dev, wbuf, 64) != 0) { FAIL("write failed"); usb_mass_close(&dev); return; }
    unsigned char rbuf[64];
    if (usb_mass_read(&dev, rbuf, 64) != 0) { FAIL("read failed"); usb_mass_close(&dev); return; }
    if (memcmp(wbuf, rbuf, 64) != 0) { FAIL("roundtrip mismatch"); }
    if (usb_mass_capacity(&dev) != 0) { FAIL("capacity changed after open/write"); }
    usb_mass_close(&dev);
    PASS();
}

static void test_open_missing_fails(void) {
    TEST("usb_mass open missing path fails");
    usb_mass_dev_t dev;
    if (usb_mass_open("/tmp/opencode/definitely_missing_usb_mass_test.dat", &dev) != -1) {
        FAIL("should fail on missing path");
    } else { PASS(); }
}

static void test_read_after_close_fails(void) {
    TEST("usb_mass read after close fails");
    int fd = open(tmp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) close(fd);
    usb_mass_dev_t dev;
    if (usb_mass_open(tmp_path, &dev) != 0) { FAIL("open failed"); return; }
    usb_mass_close(&dev);
    unsigned char b[8];
    if (usb_mass_read(&dev, b, 8) != -1) { FAIL("read after close should fail"); return; }
    PASS();
}

int main(void) {
    printf("=== USB Mass Storage Tests ===\n");
    TEST("mkstemp scratch file");
    if (make_tmp_file() != 0) {
        FAIL("mkstemp failed");
    } else {
        PASS();
        test_open_write_read_close();
        test_open_missing_fails();
        test_read_after_close_fails();
    }
    remove_tmp_file();
    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
