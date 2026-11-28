/* test_cbm_fuzz.c - deterministic fuzz lab tests
 *
 * All fixtures live in a fresh mkdtemp directory under /tmp/opencode. The
 * block-device refusal fixture is a symlink to an existing block node: the
 * code under test classifies it with stat() and refuses before any open/read.
 * No device is ever opened, read or written by this suite.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cbm_container.h"
#include "cbm_file.h"
#include "tea_crypto.h"

#include "cbm_fuzz.h"

static int tests_passed = 0;
static int tests_failed = 0;
static int tests_skipped = 0;
static char g_root[256];

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)
#define SKIP(msg) do { printf("SKIP (%s)\n", msg); tests_skipped++; } while(0)

#define BODY_LEN ((size_t)(CBM_CONTAINER_SIZE - CBM_HEADER_SIZE))

static void path_of(char *out, size_t outlen, const char *sub) {
    snprintf(out, outlen, "%s/%s", g_root, sub);
}

static void make_dir(const char *path) {
    mkdir(path, 0700);
}

static int write_file(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t put = len ? fwrite(buf, 1, len, f) : 0;
    int rc = (put == len && fclose(f) == 0) ? 0 : -1;
    return rc;
}

static int read_file(const char *path, unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t got = fread(buf, 1, len, f);
    int extra = fgetc(f) != EOF; /* reject oversized fixtures */
    fclose(f);
    return (got == len && !extra) ? 0 : -1;
}

static int file_size(const char *path, size_t *out) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return -1;
    *out = (size_t)st.st_size;
    return 0;
}

/* Synthetic encrypted container: byte 0 = 0x5a, deterministic body pattern. */
static int make_source(const char *path) {
    unsigned char *buf = (unsigned char *)malloc(CBM_CONTAINER_SIZE);
    if (!buf) return -1;
    for (size_t i = 0; i < CBM_CONTAINER_SIZE; i++) {
        buf[i] = (unsigned char)((i * 31u + 17u) & 0xffu);
    }
    buf[0] = 0x5a;
    if (cbm_cbc_encrypt(buf + CBM_HEADER_SIZE, BODY_LEN,
                        cbm_fuzz_tea_key) != 0) {
        free(buf);
        return -1;
    }
    int rc = write_file(path, buf, CBM_CONTAINER_SIZE);
    free(buf);
    return rc;
}

static int list_files(const char *dir, char names[][256], size_t max) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    size_t n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && n < max) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        snprintf(names[n], 256, "%s", e->d_name);
        n++;
    }
    closedir(d);
    /* readdir order is filesystem-dependent; sort for a stable comparison. */
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (strcmp(names[i], names[j]) > 0) {
                char tmp[256];
                strcpy(tmp, names[i]);
                strcpy(names[i], names[j]);
                strcpy(names[j], tmp);
            }
        }
    }
    return (int)n;
}

/* name + size + sha256 of every file in dir, including manifest.txt. */
static int fingerprint_dir(const char *dir, char *out, size_t outlen) {
    char names[32][256];
    int n = list_files(dir, names, 32);
    if (n < 0) return -1;
    out[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < n; i++) {
        char *path = NULL;
        if (asprintf(&path, "%s/%s", dir, names[i]) < 0) return -1;
        size_t size = 0;
        unsigned char digest[32], text[65];
        if (file_size(path, &size) != 0) { free(path); return -1; }
        FILE *f = fopen(path, "rb");
        if (!f) { free(path); return -1; }
        unsigned char *data = (unsigned char *)malloc(size ? size : 1);
        if (!data) { fclose(f); free(path); return -1; }
        size_t got = size ? fread(data, 1, size, f) : 0;
        fclose(f);
        free(path);
        if (got != size) { free(data); return -1; }
        cbm_fuzz_sha256(data, size, digest);
        free(data);
        for (size_t k = 0; k < 32; k++) {
            snprintf((char *)text + k * 2, 3, "%02x", digest[k]);
        }
        int written = snprintf(out + used, outlen - used, "%s %zu %s\n",
                               names[i], size, text);
        if (written < 0 || (size_t)written >= outlen - used) return -1;
        used += (size_t)written;
    }
    return 0;
}

static void test_same_seed_same_corpus(void) {
    TEST("cbm_fuzz_run: same seed/mutate/rounds produce byte-identical corpus");
    char src[1024], a[1024], b[1024], err[256];
    path_of(src, sizeof(src), "src/container.bin");
    path_of(a, sizeof(a), "seed-a");
    path_of(b, sizeof(b), "seed-b");
    make_dir(a);
    make_dir(b);

    unsigned char before[CBM_CONTAINER_SIZE];
    if (make_source(src) != 0 || read_file(src, before, sizeof(before)) != 0) {
        FAIL("cannot create source fixture");
        return;
    }

    err[0] = '\0';
    int rc1 = cbm_fuzz_run(src, a, 4, 3, 0x12345678UL, err, sizeof(err));
    err[0] = '\0';
    int rc2 = cbm_fuzz_run(src, b, 4, 3, 0x12345678UL, err, sizeof(err));
    char fa[2048], fb[2048];
    unsigned char after[CBM_CONTAINER_SIZE];
    int ok = (rc1 == 0 && rc2 == 0) &&
             fingerprint_dir(a, fa, sizeof(fa)) == 0 &&
             fingerprint_dir(b, fb, sizeof(fb)) == 0 &&
             strcmp(fa, fb) == 0 &&
             strstr(fa, "round-001.cbm ") != NULL &&
             strstr(fa, "round-003.cbm ") != NULL &&
             strstr(fa, "manifest.txt ") != NULL &&
             read_file(src, after, sizeof(after)) == 0 &&
             memcmp(before, after, sizeof(before)) == 0;
    if (ok) PASS(); else FAIL("two same-seed runs must match names/sizes/sha256 and leave source untouched");
}

static void test_roundtrip_identity(void) {
    TEST("cbm_fuzz_run: corpus decrypts to mutated body and re-encrypts identically");
    char src[1024], out[1024], err[256];
    path_of(src, sizeof(src), "src/container.bin");
    path_of(out, sizeof(out), "identity");
    make_dir(out);
    const unsigned long seed = 98765UL;
    const unsigned mutate = 3;
    err[0] = '\0';
    if (cbm_fuzz_run(src, out, mutate, 2, seed, err, sizeof(err)) != 0) {
        FAIL("fuzz run failed");
        return;
    }

    unsigned char *orig = (unsigned char *)malloc(CBM_CONTAINER_SIZE);
    unsigned char *corpus = (unsigned char *)malloc(CBM_CONTAINER_SIZE);
    unsigned char *got = (unsigned char *)malloc(CBM_CONTAINER_SIZE);
    unsigned char *want = (unsigned char *)malloc(CBM_CONTAINER_SIZE);
    unsigned char *reencrypt = (unsigned char *)malloc(CBM_CONTAINER_SIZE);
    int ok = (orig && corpus && got && want && reencrypt);
    if (ok) ok = (read_file(src, orig, CBM_CONTAINER_SIZE) == 0);

    for (unsigned round = 1; ok && round <= 2; round++) {
        char file[1200];
        snprintf(file, sizeof(file), "%s/round-%03u.cbm", out, round);
        if (read_file(file, corpus, CBM_CONTAINER_SIZE) != 0) { ok = 0; break; }

        memcpy(got, corpus, CBM_CONTAINER_SIZE);
        if (cbm_cbc_decrypt(got + CBM_HEADER_SIZE, BODY_LEN,
                            cbm_fuzz_tea_key) != 0) { ok = 0; break; }

        memcpy(want, orig, CBM_CONTAINER_SIZE);
        if (cbm_cbc_decrypt(want + CBM_HEADER_SIZE, BODY_LEN,
                            cbm_fuzz_tea_key) != 0) { ok = 0; break; }
        cbm_fuzz_mutate_body(want + CBM_HEADER_SIZE, BODY_LEN,
                             mutate, seed, round);
        if (memcmp(got + CBM_HEADER_SIZE, want + CBM_HEADER_SIZE,
                   BODY_LEN) != 0) { ok = 0; break; }

        memcpy(reencrypt, got, CBM_CONTAINER_SIZE);
        if (cbm_cbc_encrypt(reencrypt + CBM_HEADER_SIZE, BODY_LEN,
                            cbm_fuzz_tea_key) != 0) { ok = 0; break; }
        if (memcmp(reencrypt, corpus, CBM_CONTAINER_SIZE) != 0) { ok = 0; break; }
    }

    free(orig); free(corpus); free(got); free(want); free(reencrypt);
    if (ok) PASS(); else FAIL("roundtrip body identity must hold for every round");
}

static void test_header_preserved(void) {
    TEST("cbm_fuzz_run: every generated container preserves byte 0");
    char src[1024], out[1024];
    path_of(src, sizeof(src), "src/container.bin");
    path_of(out, sizeof(out), "identity");
    unsigned char source[CBM_CONTAINER_SIZE], corpus[CBM_CONTAINER_SIZE];
    int ok = (read_file(src, source, sizeof(source)) == 0 &&
              source[0] == 0x5a);
    for (unsigned round = 1; ok && round <= 2; round++) {
        char file[1200];
        snprintf(file, sizeof(file), "%s/round-%03u.cbm", out, round);
        ok = (read_file(file, corpus, sizeof(corpus)) == 0 &&
              corpus[0] == source[0]);
    }
    if (ok) PASS(); else FAIL("header byte must be unchanged in all corpus files");
}

static void test_refuses_block_device(void) {
    static const char *const candidates[] = {
        "/dev/zram0", "/dev/loop0", "/dev/sda", "/dev/nvme0n1", "/dev/vda"
    };
    const char *dev = NULL;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (cbm_file_is_blockdev(candidates[i])) { dev = candidates[i]; break; }
    }
    if (!dev) {
        TEST("cbm_fuzz_run: refuse a block-device source");
        SKIP("no block-device node available for stat-only fixture");
        return;
    }
    char link[1024], out[1024], err[256];
    path_of(link, sizeof(link), "fake-blockdev");
    path_of(out, sizeof(out), "blockdev-out");
    unlink(link);
    make_dir(out);
    TEST("cbm_fuzz_run: refuse a block-device source");
    if (symlink(dev, link) != 0) {
        SKIP("cannot create stat-only block-device symlink fixture");
        return;
    }
    err[0] = '\0';
    int rc = cbm_fuzz_run(link, out, 2, 2, 7UL, err, sizeof(err));
    char names[32][256];
    int n = list_files(out, names, 32);
    int ok = (rc != 0 && n == 0 && strstr(err, "block device") != NULL);
    unlink(link);
    if (ok) PASS(); else FAIL("block-device source must be refused before any write");
}

static void test_refuses_source_as_out(void) {
    TEST("cbm_fuzz_run: refuse --out equal to source file or source directory");
    char src[1024], err[256];
    path_of(src, sizeof(src), "src/container.bin");
    err[0] = '\0';
    int rc_dir = cbm_fuzz_run(src, "/tmp/opencode/cbm-fuzz-src-as-out-none", 2, 1, 5UL,
                              err, sizeof(err));
    /* Use the real source directory; the path above only forces the missing-dir
     * branch and is deliberately never created. */
    char srcdir[1024];
    snprintf(srcdir, sizeof(srcdir), "%s/src", g_root);
    err[0] = '\0';
    int rc = cbm_fuzz_run(src, srcdir, 2, 1, 5UL, err, sizeof(err));
    char names[32][256];
    int n = list_files(srcdir, names, 32);
    err[0] = '\0';
    int rc_file = cbm_fuzz_run(src, src, 2, 1, 5UL, err, sizeof(err));
    int ok = (rc_dir != 0 && rc != 0 && rc_file != 0 && n == 1 &&
              strcmp(names[0], "container.bin") == 0);
    if (ok) PASS(); else FAIL("out must not be the source path or its directory");
}

int main(void) {
    printf("=== Deterministic Fuzz Lab Tests ===\n");
    if (tea_init(NULL) != 0) {
        printf("FAIL: native crypto init failed\n");
        return 1;
    }
    char tmpl[] = "/tmp/opencode/cbm-fuzz-test.XXXXXX";
    if (!mkdtemp(tmpl)) {
        printf("FAIL: mkdtemp failed\n");
        tea_cleanup();
        return 1;
    }
    snprintf(g_root, sizeof(g_root), "%s", tmpl);
    char srcdir[1024];
    path_of(srcdir, sizeof(srcdir), "src");
    make_dir(srcdir);

    test_same_seed_same_corpus();
    test_roundtrip_identity();
    test_header_preserved();
    test_refuses_block_device();
    test_refuses_source_as_out();

    printf("\nScratch fixtures: %s\n", g_root);
    printf("Results: %d passed, %d failed, %d skipped\n",
           tests_passed, tests_failed, tests_skipped);
    tea_cleanup();
    return tests_failed > 0 ? 1 : 0;
}
