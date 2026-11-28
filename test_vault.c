/* test_vault.c - derived vault format tests (wave 5Q)
 *
 * Every fixture is a synthetic regular file under /tmp/opencode. No device is
 * opened and no vendor binary is read. The suite prints its own summary line
 * (`test_vault: N passed, M failed`) so the frozen `Results:` sums stay valid.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include "vault.h"
#include "cbm_container.h"
#include "cbm_file.h"
#include "tea_crypto.h"
#include "tea_native.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

static const char *g_dir = NULL;
static char g_paths[32][512];
static size_t g_path_count = 0;

static void path_for(const char *name, char *out, size_t outlen) {
    (void)snprintf(out, outlen, "%s/%s.vault", g_dir, name);
    if (g_path_count < (sizeof g_paths / sizeof g_paths[0]))
        (void)snprintf(g_paths[g_path_count++], sizeof g_paths[0], "%s", out);
}

static int file_size(const char *path, long long *out) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *out = (long long)st.st_size;
    return 0;
}

static int read_byte(const char *path, long long off, unsigned char *out) {
    return cbm_file_read(path, off, out, 1);
}

static size_t slurp(FILE *f, char *buf, size_t cap) {
    size_t n;
    if (!f || !buf || cap == 0) return 0;
    if (fflush(f) != 0) return 0;
    if (fseek(f, 0, SEEK_SET) != 0) return 0;
    n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    return n;
}

static int run_cli(int argc, char **argv, char *outbuf, size_t outcap,
                   char *errbuf, size_t errcap) {
    FILE *o = tmpfile();
    FILE *e = tmpfile();
    int rc;
    if (!o || !e) {
        if (o) fclose(o);
        if (e) fclose(e);
        return -1;
    }
    rc = vault_cli_ex(argc, argv, o, e, NULL);
    if (outbuf && outcap) (void)slurp(o, outbuf, outcap);
    if (errbuf && errcap) (void)slurp(e, errbuf, errcap);
    fclose(o);
    fclose(e);
    return rc;
}

/* ---- tests ------------------------------------------------------------ */

static void test_create_envelope(void) {
    char path[512], err[192] = {0};
    long long sz = 0;
    unsigned char hdr = 0;

    TEST("create writes exactly 85688 bytes with the encrypted header");
    path_for("create", path, sizeof path);
    if (vault_create(path, TEA_NATIVE_KEY, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    if (file_size(path, &sz) != 0 || sz != CBM_CONTAINER_SIZE) {
        FAIL("wrong file size");
        return;
    }
    if (read_byte(path, 0, &hdr) != 0 || hdr != CBM_VAULT_HEADER_BYTE) {
        FAIL("wrong header byte");
        return;
    }
    PASS();
}

static void test_create_refuses_existing(void) {
    char path[512], err[192] = {0};
    int rc;

    TEST("create refuses to overwrite an existing file");
    path_for("exists", path, sizeof path);
    if (vault_create(path, TEA_NATIVE_KEY, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    rc = vault_create(path, TEA_NATIVE_KEY, err, sizeof err);
    if (rc != VAULT_ERR_EXISTS) {
        FAIL("expected VAULT_ERR_EXISTS");
        return;
    }
    PASS();
}

static void test_empty_load(void) {
    char path[512], err[192] = {0};
    vault_t v;

    TEST("an empty vault loads with zero records");
    path_for("empty", path, sizeof path);
    if (vault_create(path, TEA_NATIVE_KEY, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    vault_zero(&v);
    if (vault_load(path, TEA_NATIVE_KEY, &v, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    if (v.count != 0) {
        FAIL("expected zero records");
        vault_free(&v);
        return;
    }
    vault_free(&v);
    PASS();
}

static void test_put_get_roundtrip(void) {
    char path[512], err[192] = {0};
    vault_t v, t;
    const char *a, *b;
    int ok;

    TEST("put/save/load/get roundtrip");
    path_for("roundtrip", path, sizeof path);
    if (vault_create(path, TEA_NATIVE_KEY, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    vault_zero(&v);
    if (vault_load(path, TEA_NATIVE_KEY, &v, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    if (vault_put(&v, "alpha", "secret-one", err, sizeof err) != VAULT_OK ||
        vault_put(&v, "beta", "secret-two", err, sizeof err) != VAULT_OK) {
        FAIL(err);
        vault_free(&v);
        return;
    }
    if (vault_save(path, TEA_NATIVE_KEY, &v, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        vault_free(&v);
        return;
    }
    vault_free(&v);

    vault_zero(&t);
    if (vault_load(path, TEA_NATIVE_KEY, &t, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    a = vault_get(&t, "alpha");
    b = vault_get(&t, "beta");
    ok = a && strcmp(a, "secret-one") == 0 && b && strcmp(b, "secret-two") == 0;
    vault_free(&t);
    if (!ok) {
        FAIL("values did not roundtrip");
        return;
    }
    PASS();
}

static void test_list_order(void) {
    char path[512], err[192] = {0};
    vault_t v, t;
    int ok;

    TEST("records list in insertion order");
    path_for("order", path, sizeof path);
    if (vault_create(path, TEA_NATIVE_KEY, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    vault_zero(&v);
    if (vault_load(path, TEA_NATIVE_KEY, &v, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    if (vault_put(&v, "alpha", "1", err, sizeof err) != VAULT_OK ||
        vault_put(&v, "beta", "2", err, sizeof err) != VAULT_OK ||
        vault_put(&v, "gamma", "3", err, sizeof err) != VAULT_OK) {
        FAIL(err);
        vault_free(&v);
        return;
    }
    if (vault_save(path, TEA_NATIVE_KEY, &v, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        vault_free(&v);
        return;
    }
    vault_free(&v);

    vault_zero(&t);
    if (vault_load(path, TEA_NATIVE_KEY, &t, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    ok = t.count == 3 && strcmp(t.records[0].label, "alpha") == 0 &&
         strcmp(t.records[1].label, "beta") == 0 &&
         strcmp(t.records[2].label, "gamma") == 0;
    vault_free(&t);
    if (!ok) {
        FAIL("insertion order was not preserved");
        return;
    }
    PASS();
}

static void test_replace_keeps_order(void) {
    vault_t v;
    char err[192] = {0};
    const char *got;
    int ok;

    TEST("put on an existing label replaces the value in place");
    vault_zero(&v);
    if (vault_put(&v, "alpha", "one", err, sizeof err) != VAULT_OK ||
        vault_put(&v, "beta", "two", err, sizeof err) != VAULT_OK ||
        vault_put(&v, "alpha", "rotated", err, sizeof err) != VAULT_OK) {
        FAIL(err);
        vault_free(&v);
        return;
    }
    got = vault_get(&v, "alpha");
    ok = v.count == 2 && strcmp(v.records[0].label, "alpha") == 0 &&
         got && strcmp(got, "rotated") == 0 &&
         strcmp(v.records[1].label, "beta") == 0;
    vault_free(&v);
    if (!ok) {
        FAIL("replace did not keep position or value");
        return;
    }
    PASS();
}

static void test_erase(void) {
    char path[512], err[192] = {0};
    vault_t v;
    const char *got;
    int ok;

    TEST("erase removes one record and refuses a missing label");
    path_for("erase", path, sizeof path);
    if (vault_create(path, TEA_NATIVE_KEY, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    vault_zero(&v);
    if (vault_load(path, TEA_NATIVE_KEY, &v, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    if (vault_put(&v, "alpha", "one", err, sizeof err) != VAULT_OK ||
        vault_put(&v, "beta", "two", err, sizeof err) != VAULT_OK) {
        FAIL(err);
        vault_free(&v);
        return;
    }
    if (vault_erase(&v, "alpha", err, sizeof err) != VAULT_OK) {
        FAIL(err);
        vault_free(&v);
        return;
    }
    got = vault_get(&v, "beta");
    ok = v.count == 1 && vault_get(&v, "alpha") == NULL &&
         got && strcmp(got, "two") == 0;
    if (ok && vault_erase(&v, "missing", err, sizeof err) != VAULT_ERR_NOT_FOUND)
        ok = 0;
    vault_free(&v);
    if (!ok) {
        FAIL("erase behaviour was wrong");
        return;
    }
    PASS();
}

static void test_wrong_key(void) {
    char path[512], err[192] = {0};
    vault_t v;
    int rc;

    TEST("wrong key is refused and leaves no records");
    path_for("wrongkey", path, sizeof path);
    if (vault_create(path, TEA_NATIVE_KEY, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    vault_zero(&v);
    rc = vault_load(path, "0000000000000000", &v, err, sizeof err);
    if (rc == VAULT_OK) {
        FAIL("wrong key accepted");
        vault_free(&v);
        return;
    }
    if (v.count != 0) {
        FAIL("failed load left records behind");
        vault_free(&v);
        return;
    }
    vault_free(&v);
    PASS();
}

static void test_ciphertext_tamper(void) {
    char path[512], err[192] = {0};
    unsigned char b = 0;
    vault_t v;

    TEST("a modified ciphertext byte is refused");
    path_for("tamper", path, sizeof path);
    if (vault_create(path, TEA_NATIVE_KEY, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    if (read_byte(path, 200, &b) != 0) {
        FAIL("cannot read fixture");
        return;
    }
    b ^= 0xffu;
    if (cbm_file_write(path, 200, &b, 1) != 0) {
        FAIL("cannot patch fixture");
        return;
    }
    vault_zero(&v);
    if (vault_load(path, TEA_NATIVE_KEY, &v, err, sizeof err) == VAULT_OK) {
        FAIL("tampered vault accepted");
        vault_free(&v);
        return;
    }
    vault_free(&v);
    PASS();
}

static void test_checksum_tamper(void) {
    char path[512], err[192] = {0};
    unsigned char raw[CBM_CONTAINER_SIZE];
    size_t body_len = cbm_compute_hlen(CBM_CONTAINER_SIZE);
    vault_t v, t;
    int rc;

    TEST("a checksum mismatch is refused after a plaintext edit");
    path_for("checksum", path, sizeof path);
    if (vault_create(path, TEA_NATIVE_KEY, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    vault_zero(&v);
    if (vault_load(path, TEA_NATIVE_KEY, &v, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    if (vault_put(&v, "alpha", "secret-one", err, sizeof err) != VAULT_OK ||
        vault_save(path, TEA_NATIVE_KEY, &v, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        vault_free(&v);
        return;
    }
    vault_free(&v);

    if (cbm_file_read(path, 0, raw, sizeof raw) != 0) {
        FAIL("cannot read fixture");
        return;
    }
    if (cbm_cbc_decrypt(raw + CBM_HEADER_SIZE, body_len, TEA_NATIVE_KEY) != 0) {
        FAIL("cannot decrypt fixture");
        return;
    }
    raw[CBM_HEADER_SIZE + 40] ^= 0x01u; /* inside the first record's value */
    if (cbm_cbc_encrypt(raw + CBM_HEADER_SIZE, body_len, TEA_NATIVE_KEY) != 0) {
        FAIL("cannot re-encrypt fixture");
        return;
    }
    if (cbm_file_write(path, 0, raw, sizeof raw) != 0) {
        FAIL("cannot write fixture");
        return;
    }

    vault_zero(&t);
    rc = vault_load(path, TEA_NATIVE_KEY, &t, err, sizeof err);
    if (rc == VAULT_OK) {
        FAIL("tampered checksum accepted");
        vault_free(&t);
        return;
    }
    if (rc != VAULT_ERR_AUTH) {
        FAIL("expected VAULT_ERR_AUTH");
        vault_free(&t);
        return;
    }
    vault_free(&t);
    PASS();
}

static void test_header_preserved(void) {
    char path[512], err[192] = {0};
    unsigned char b = 0x80u, hdr = 0;
    vault_t v;

    TEST("the envelope header byte is preserved across writes");
    path_for("header", path, sizeof path);
    if (vault_create(path, TEA_NATIVE_KEY, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    if (cbm_file_write(path, 0, &b, 1) != 0) {
        FAIL("cannot patch header");
        return;
    }
    vault_zero(&v);
    if (vault_load(path, TEA_NATIVE_KEY, &v, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        return;
    }
    if (vault_put(&v, "alpha", "one", err, sizeof err) != VAULT_OK ||
        vault_save(path, TEA_NATIVE_KEY, &v, err, sizeof err) != VAULT_OK) {
        FAIL(err);
        vault_free(&v);
        return;
    }
    vault_free(&v);
    if (read_byte(path, 0, &hdr) != 0 || hdr != 0x80u) {
        FAIL("header byte changed");
        return;
    }
    PASS();
}

static void test_label_validation(void) {
    vault_t v;
    char err[192] = {0};
    char longlabel[CBM_VAULT_LABEL_MAX + 2];
    int ok;

    TEST("labels must be 1..63 printable ASCII bytes");
    vault_zero(&v);
    ok = vault_put(&v, "", "x", err, sizeof err) == VAULT_ERR_ARG;
    memset(longlabel, 'a', sizeof longlabel);
    longlabel[sizeof longlabel - 1] = '\0';
    if (ok) ok = vault_put(&v, longlabel, "x", err, sizeof err) == VAULT_ERR_ARG;
    if (ok) ok = vault_put(&v, "ok", "x", err, sizeof err) == VAULT_OK;
    vault_free(&v);
    if (!ok) {
        FAIL("label validation was wrong");
        return;
    }
    PASS();
}

static void test_value_too_large(void) {
    vault_t v;
    char err[192] = {0};
    static char big[CBM_VAULT_VALUE_MAX + 2];
    int rc;

    TEST("values above the documented cap are refused");
    memset(big, 'x', sizeof big);
    big[sizeof big - 1] = '\0';
    vault_zero(&v);
    rc = vault_put(&v, "big", big, err, sizeof err);
    vault_free(&v);
    if (rc != VAULT_ERR_ARG) {
        FAIL("expected VAULT_ERR_ARG");
        return;
    }
    PASS();
}

static void test_capacity_full(void) {
    vault_t v;
    char err[192] = {0};
    static char big[CBM_VAULT_VALUE_MAX + 1];
    char label[16];
    int i, rc, ok = 1;

    TEST("the 21st 4096-byte record is refused with VAULT_ERR_FULL");
    memset(big, 'x', CBM_VAULT_VALUE_MAX);
    big[CBM_VAULT_VALUE_MAX] = '\0';
    vault_zero(&v);
    for (i = 0; i < 20 && ok; i++) {
        (void)snprintf(label, sizeof label, "k%02d", i);
        if (vault_put(&v, label, big, err, sizeof err) != VAULT_OK) ok = 0;
    }
    if (!ok) {
        FAIL(err);
        vault_free(&v);
        return;
    }
    (void)snprintf(label, sizeof label, "k20");
    rc = vault_put(&v, label, big, err, sizeof err);
    vault_free(&v);
    if (rc != VAULT_ERR_FULL) {
        FAIL("expected VAULT_ERR_FULL");
        return;
    }
    PASS();
}

static void test_not_a_vault(void) {
    char path[512];
    unsigned char zeros[CBM_CONTAINER_SIZE];
    vault_t v;
    char err[192] = {0};
    int rc;

    TEST("a zero-filled 85688-byte file is refused");
    path_for("zeros", path, sizeof path);
    memset(zeros, 0, sizeof zeros);
    if (cbm_file_write(path, 0, zeros, sizeof zeros) != 0) {
        FAIL("cannot write fixture");
        return;
    }
    vault_zero(&v);
    rc = vault_load(path, TEA_NATIVE_KEY, &v, err, sizeof err);
    vault_free(&v);
    if (rc != VAULT_ERR_FORMAT) {
        FAIL("expected VAULT_ERR_FORMAT");
        return;
    }
    PASS();
}

static void test_missing_file(void) {
    char path[512];
    vault_t v;
    char err[192] = {0};
    int rc;

    TEST("a missing vault file is an I/O error");
    path_for("absent", path, sizeof path);
    (void)unlink(path); /* not created; keep the registry entry */
    vault_zero(&v);
    rc = vault_load(path, TEA_NATIVE_KEY, &v, err, sizeof err);
    vault_free(&v);
    if (rc != VAULT_ERR_IO) {
        FAIL("expected VAULT_ERR_IO");
        return;
    }
    PASS();
}

static void test_cli_smoke(void) {
    char path[512], out[512], errbuf[512];
    char *init_argv[] = { "cbm-tool", "vault", "init", path, NULL };
    char *put_argv[] = { "cbm-tool", "vault", "put", path, "alpha", "secret-one", NULL };
    char *get_argv[] = { "cbm-tool", "vault", "get", path, "alpha", NULL };
    char *list_argv[] = { "cbm-tool", "vault", "list", path, NULL };
    int rc;

    TEST("CLI init/put/get/list roundtrip");
    path_for("cli", path, sizeof path);
    rc = run_cli(4, init_argv, out, sizeof out, errbuf, sizeof errbuf);
    if (rc != 0) { FAIL(errbuf); return; }
    rc = run_cli(6, put_argv, out, sizeof out, errbuf, sizeof errbuf);
    if (rc != 0) { FAIL(errbuf); return; }
    rc = run_cli(5, get_argv, out, sizeof out, errbuf, sizeof errbuf);
    if (rc != 0) { FAIL(errbuf); return; }
    if (strcmp(out, "secret-one\n") != 0) { FAIL("get output mismatch"); return; }
    rc = run_cli(4, list_argv, out, sizeof out, errbuf, sizeof errbuf);
    if (rc != 0) { FAIL(errbuf); return; }
    if (strcmp(out, "alpha\n") != 0) { FAIL("list output mismatch"); return; }
    PASS();
}

static void test_cli_json(void) {
    char path[512];
    FILE *o, *e, *j;
    char buf[512];
    char *argv[] = { "cbm-tool", "vault", "init", path, NULL };
    int rc;

    TEST("CLI emits a cbm/1 JSON document");
    path_for("json", path, sizeof path);
    o = tmpfile();
    e = tmpfile();
    j = tmpfile();
    if (!o || !e || !j) {
        if (o) fclose(o);
        if (e) fclose(e);
        if (j) fclose(j);
        FAIL("tmpfile failed");
        return;
    }
    rc = vault_cli_ex(4, argv, o, e, j);
    (void)slurp(j, buf, sizeof buf);
    fclose(o);
    fclose(e);
    fclose(j);
    if (rc != 0) { FAIL("init failed"); return; }
    if (!strstr(buf, "\"command\":\"vault\"") || !strstr(buf, "\"status\":\"ok\"")) {
        FAIL(buf);
        return;
    }
    PASS();
}

int main(void) {
    char tmpl[] = "/tmp/opencode/vault-test.XXXXXX";
    char *dir;

    dir = mkdtemp(tmpl);
    if (!dir) {
        printf("test_vault: cannot create scratch dir: %s\n", strerror(errno));
        return 1;
    }
    g_dir = dir;

    if (tea_init(NULL) != 0) {
        printf("test_vault: native crypto init failed\n");
        return 1;
    }

    test_create_envelope();
    test_create_refuses_existing();
    test_empty_load();
    test_put_get_roundtrip();
    test_list_order();
    test_replace_keeps_order();
    test_erase();
    test_wrong_key();
    test_ciphertext_tamper();
    test_checksum_tamper();
    test_header_preserved();
    test_label_validation();
    test_value_too_large();
    test_capacity_full();
    test_not_a_vault();
    test_missing_file();
    test_cli_smoke();
    test_cli_json();

    printf("test_vault: %d passed, %d failed\n", tests_passed, tests_failed);
    tea_cleanup();

    for (size_t i = 0; i < g_path_count; i++) (void)unlink(g_paths[i]);
    (void)rmdir(g_dir);
    return tests_failed ? 1 : 0;
}
