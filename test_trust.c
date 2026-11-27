/* test_trust.c - BadUSB trust scanner tests (wave 5P)
 *
 * Every fixture is a synthetic JSON file under /tmp/opencode. No device is
 * opened and no vendor binary is read. The suite prints its own summary line
 * (`test_trust: N passed, M failed`) so the frozen `Results:` sums stay valid.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "trust.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

static const char *g_dir = NULL;
static char g_paths[24][512];
static size_t g_path_count = 0;

static const char *BASE_JSON =
    "{\"vid\":\"0x1234\",\"pid\":\"0x5678\","
    "\"product\":\"Chipsbank USB Disk\",\"serial\":\"REDACTED\","
    "\"interfaces\":[{\"class\":8,\"subclass\":6,\"protocol\":80}],"
    "\"cdbs\":[\"28 00 00 00 00 00 00 00 10 00\"],"
    "\"firmware_marker\":null}";

static const char *HID_JSON =
    "{\"vid\":\"0x1234\",\"pid\":\"0x5678\","
    "\"product\":\"Chipsbank USB Disk\","
    "\"interfaces\":[{\"class\":8,\"subclass\":6,\"protocol\":80},"
    "{\"class\":3,\"subclass\":1,\"protocol\":1}],"
    "\"cdbs\":[\"28 00 00 00 00 00 00 00 10 00\"],"
    "\"firmware_marker\":null}";

static const char *VENDOR_JSON =
    "{\"vid\":\"0x1234\",\"pid\":\"0x5678\","
    "\"product\":\"Chipsbank USB Disk\","
    "\"interfaces\":[{\"class\":8,\"subclass\":6,\"protocol\":80},"
    "{\"class\":255,\"subclass\":0,\"protocol\":0}],"
    "\"cdbs\":[\"28 00 00 00 00 00 00 00 10 00\"],"
    "\"firmware_marker\":null}";

static const char *UNKNOWN_CDB_JSON =
    "{\"vid\":\"0x1234\",\"pid\":\"0x5678\","
    "\"product\":\"Chipsbank USB Disk\","
    "\"interfaces\":[{\"class\":8,\"subclass\":6,\"protocol\":80}],"
    "\"cdbs\":[\"2a 00 00 00 00 00 00 00 10 00\"],"
    "\"firmware_marker\":null}";

static const char *NO_CDB_JSON =
    "{\"vid\":\"0x1234\",\"pid\":\"0x5678\","
    "\"product\":\"Chipsbank USB Disk\","
    "\"interfaces\":[{\"class\":8,\"subclass\":6,\"protocol\":80}],"
    "\"cdbs\":[],\"firmware_marker\":null}";

static const char *WRONG_ID_JSON =
    "{\"vid\":\"0x9999\",\"pid\":\"0x5678\","
    "\"product\":\"Chipsbank USB Disk\","
    "\"interfaces\":[{\"class\":8,\"subclass\":6,\"protocol\":80}],"
    "\"cdbs\":[\"28 00 00 00 00 00 00 00 10 00\"],"
    "\"firmware_marker\":null}";

static const char *WRONG_PRODUCT_JSON =
    "{\"vid\":\"0x1234\",\"pid\":\"0x5678\","
    "\"product\":\"Evil Stick\","
    "\"interfaces\":[{\"class\":8,\"subclass\":6,\"protocol\":80}],"
    "\"cdbs\":[\"28 00 00 00 00 00 00 00 10 00\"],"
    "\"firmware_marker\":null}";

static const char *MISSING_IFACE_JSON =
    "{\"vid\":\"0x1234\",\"pid\":\"0x5678\","
    "\"product\":\"Chipsbank USB Disk\","
    "\"interfaces\":[{\"class\":8,\"subclass\":6,\"protocol\":0}],"
    "\"cdbs\":[\"28 00 00 00 00 00 00 00 10 00\"],"
    "\"firmware_marker\":null}";

static const char *FW_MARKER_JSON =
    "{\"vid\":\"0x1234\",\"pid\":\"0x5678\","
    "\"product\":\"Chipsbank USB Disk\","
    "\"interfaces\":[{\"class\":8,\"subclass\":6,\"protocol\":80}],"
    "\"cdbs\":[\"28 00 00 00 00 00 00 00 10 00\"],"
    "\"firmware_marker\":\"dump-v2\"}";

static const char *MALFORMED_JSON =
    "{\"pid\":\"0x5678\",\"product\":\"no vid here\"}";

static void path_for(const char *name, char *out, size_t outlen) {
    (void)snprintf(out, outlen, "%s/%s.json", g_dir, name);
    if (g_path_count < (sizeof g_paths / sizeof g_paths[0]))
        (void)snprintf(g_paths[g_path_count++], sizeof g_paths[0], "%s", out);
}

static int write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    size_t n = strlen(text);
    if (!f) return -1;
    if (fwrite(text, 1, n, f) != n) {
        (void)fclose(f);
        return -1;
    }
    return fclose(f) == 0 ? 0 : -1;
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
                   char *errbuf, size_t errcap, FILE *json) {
    FILE *o = tmpfile();
    FILE *e = tmpfile();
    int rc;
    if (!o || !e) {
        if (o) fclose(o);
        if (e) fclose(e);
        return -1;
    }
    rc = trust_cli_ex(argc, argv, o, e, json);
    if (outbuf && outcap) (void)slurp(o, outbuf, outcap);
    if (errbuf && errcap) (void)slurp(e, errbuf, errcap);
    fclose(o);
    fclose(e);
    return rc;
}

static int has_code(const trust_report_t *r, const char *code,
                    trust_severity_t sev) {
    for (size_t i = 0; i < r->count; i++)
        if (strcmp(r->items[i].code, code) == 0 &&
            r->items[i].severity == sev)
            return 1;
    return 0;
}

/* ---- tests ------------------------------------------------------------ */

static void test_parse_profile(void) {
    trust_profile_t p;
    char err[192] = {0};
    int ok;

    TEST("parse a full profile; serials are ignored");
    if (trust_parse_profile(BASE_JSON, &p, err, sizeof err) != TRUST_OK) {
        FAIL(err);
        return;
    }
    ok = p.vid == 0x1234u && p.pid == 0x5678u &&
         strcmp(p.product, "Chipsbank USB Disk") == 0 &&
         p.nifaces == 1 && p.ifaces[0].cls == 8 &&
         p.ifaces[0].subcls == 6 && p.ifaces[0].proto == 80 &&
         p.ncdbs == 1 && p.cdb_len[0] == 10 &&
         p.cdbs[0][0] == 0x28 && p.cdbs[0][9] == 0x00 &&
         p.has_fw_marker == 0;
    if (!ok) {
        FAIL("parsed fields are wrong");
        return;
    }
    PASS();
}

static void test_identical_is_trusted(void) {
    trust_profile_t a, b;
    trust_report_t r;
    char err[192] = {0};
    int ok;

    TEST("an identical observation is trusted");
    ok = trust_parse_profile(BASE_JSON, &a, err, sizeof err) == TRUST_OK &&
         trust_parse_profile(BASE_JSON, &b, err, sizeof err) == TRUST_OK &&
         trust_compare(&a, &b, &r, err, sizeof err) == TRUST_OK;
    if (!ok) { FAIL(err); return; }
    if (r.crit != 0 || r.warn != 0) { FAIL("unexpected warn/crit"); return; }
    if (!has_code(&r, "fw-unverified", TRUST_SEV_INFO)) {
        FAIL("firmware claim was not marked host-observable");
        return;
    }
    PASS();
}

static void test_hid_interface_flagged(void) {
    trust_profile_t a, b;
    trust_report_t r;
    char err[192] = {0};
    int ok;

    TEST("an added HID interface is flagged critical");
    ok = trust_parse_profile(BASE_JSON, &a, err, sizeof err) == TRUST_OK &&
         trust_parse_profile(HID_JSON, &b, err, sizeof err) == TRUST_OK &&
         trust_compare(&a, &b, &r, err, sizeof err) == TRUST_OK;
    if (!ok) { FAIL(err); return; }
    if (!has_code(&r, "iface-extra-hid", TRUST_SEV_CRIT) || r.crit == 0) {
        FAIL("HID interface was not flagged");
        return;
    }
    PASS();
}

static void test_extra_vendor_interface(void) {
    trust_profile_t a, b;
    trust_report_t r;
    char err[192] = {0};
    int ok;

    TEST("an added non-HID interface is a warning");
    ok = trust_parse_profile(BASE_JSON, &a, err, sizeof err) == TRUST_OK &&
         trust_parse_profile(VENDOR_JSON, &b, err, sizeof err) == TRUST_OK &&
         trust_compare(&a, &b, &r, err, sizeof err) == TRUST_OK;
    if (!ok) { FAIL(err); return; }
    if (!has_code(&r, "iface-extra", TRUST_SEV_WARN)) {
        FAIL("vendor interface was not flagged");
        return;
    }
    PASS();
}

static void test_unknown_cdb(void) {
    trust_profile_t a, b;
    trust_report_t r;
    char err[192] = {0};
    int ok;

    TEST("an unknown CDB is flagged");
    ok = trust_parse_profile(BASE_JSON, &a, err, sizeof err) == TRUST_OK &&
         trust_parse_profile(UNKNOWN_CDB_JSON, &b, err, sizeof err) == TRUST_OK &&
         trust_compare(&a, &b, &r, err, sizeof err) == TRUST_OK;
    if (!ok) { FAIL(err); return; }
    if (!has_code(&r, "cdb-unknown", TRUST_SEV_WARN)) {
        FAIL("unknown CDB was not flagged");
        return;
    }
    PASS();
}

static void test_missing_baseline_file(void) {
    char path[512];
    trust_profile_t p;
    char err[192] = {0};
    int rc;

    TEST("a missing baseline file fails closed");
    path_for("absent-baseline", path, sizeof path);
    (void)unlink(path);
    rc = trust_load_profile(path, &p, err, sizeof err);
    if (rc != TRUST_ERR_IO) { FAIL("expected TRUST_ERR_IO"); return; }
    PASS();
}

static void test_malformed_profile(void) {
    trust_profile_t p;
    char err[192] = {0};
    int rc;

    TEST("a profile without vid/pid is a format error");
    rc = trust_parse_profile(MALFORMED_JSON, &p, err, sizeof err);
    if (rc != TRUST_ERR_FORMAT) { FAIL("expected TRUST_ERR_FORMAT"); return; }
    PASS();
}

static void test_wrong_usb_id(void) {
    trust_profile_t a, b;
    trust_report_t r;
    char err[192] = {0};
    int ok;

    TEST("a VID/PID mismatch is critical");
    ok = trust_parse_profile(BASE_JSON, &a, err, sizeof err) == TRUST_OK &&
         trust_parse_profile(WRONG_ID_JSON, &b, err, sizeof err) == TRUST_OK &&
         trust_compare(&a, &b, &r, err, sizeof err) == TRUST_OK;
    if (!ok) { FAIL(err); return; }
    if (!has_code(&r, "usb-id", TRUST_SEV_CRIT)) {
        FAIL("usb-id mismatch was not critical");
        return;
    }
    PASS();
}

static void test_product_mismatch(void) {
    trust_profile_t a, b;
    trust_report_t r;
    char err[192] = {0};
    int ok;

    TEST("a product string change is a warning");
    ok = trust_parse_profile(BASE_JSON, &a, err, sizeof err) == TRUST_OK &&
         trust_parse_profile(WRONG_PRODUCT_JSON, &b, err, sizeof err) == TRUST_OK &&
         trust_compare(&a, &b, &r, err, sizeof err) == TRUST_OK;
    if (!ok) { FAIL(err); return; }
    if (!has_code(&r, "product", TRUST_SEV_WARN)) {
        FAIL("product change was not a warning");
        return;
    }
    PASS();
}

static void test_missing_baseline_iface(void) {
    trust_profile_t a, b;
    trust_report_t r;
    char err[192] = {0};
    int ok;

    TEST("a baseline interface that disappeared is a warning");
    ok = trust_parse_profile(BASE_JSON, &a, err, sizeof err) == TRUST_OK &&
         trust_parse_profile(MISSING_IFACE_JSON, &b, err, sizeof err) == TRUST_OK &&
         trust_compare(&a, &b, &r, err, sizeof err) == TRUST_OK;
    if (!ok) { FAIL(err); return; }
    if (!has_code(&r, "iface-missing", TRUST_SEV_WARN)) {
        FAIL("missing baseline interface was not flagged");
        return;
    }
    PASS();
}

static void test_fw_marker_changed(void) {
    trust_profile_t a, b;
    trust_report_t r;
    char err[192] = {0};
    int ok;

    TEST("a changed firmware marker is a warning");
    ok = trust_parse_profile(BASE_JSON, &a, err, sizeof err) == TRUST_OK &&
         trust_parse_profile(FW_MARKER_JSON, &b, err, sizeof err) == TRUST_OK &&
         trust_compare(&a, &b, &r, err, sizeof err) == TRUST_OK;
    if (!ok) { FAIL(err); return; }
    if (!has_code(&r, "fw-marker-changed", TRUST_SEV_WARN)) {
        FAIL("firmware marker change was not flagged");
        return;
    }
    PASS();
}

static void test_no_cdb_observed(void) {
    trust_profile_t a, b;
    trust_report_t r;
    char err[192] = {0};
    int ok;

    TEST("an observation without CDBs says so instead of guessing");
    ok = trust_parse_profile(BASE_JSON, &a, err, sizeof err) == TRUST_OK &&
         trust_parse_profile(NO_CDB_JSON, &b, err, sizeof err) == TRUST_OK &&
         trust_compare(&a, &b, &r, err, sizeof err) == TRUST_OK;
    if (!ok) { FAIL(err); return; }
    if (!has_code(&r, "cdb-not-observed", TRUST_SEV_INFO)) {
        FAIL("missing CDB observation was not reported");
        return;
    }
    PASS();
}

static void test_cli_trusted(void) {
    char base[512], obs[512], out[1024], errbuf[512];
    char *argv[6];
    int rc;

    TEST("CLI: identical observation exits 0 with TRUSTED");
    path_for("cli-base", base, sizeof base);
    path_for("cli-obs", obs, sizeof obs);
    if (write_file(base, BASE_JSON) != 0 || write_file(obs, BASE_JSON) != 0) {
        FAIL("cannot write fixtures");
        return;
    }
    argv[0] = (char *)"cbm-tool";
    argv[1] = (char *)"trust";
    argv[2] = obs;
    argv[3] = (char *)"--baseline";
    argv[4] = base;
    argv[5] = NULL;
    rc = run_cli(5, argv, out, sizeof out, errbuf, sizeof errbuf, NULL);
    if (rc != 0) { FAIL(errbuf); return; }
    if (!strstr(out, "verdict=TRUSTED")) { FAIL(out); return; }
    PASS();
}

static void test_cli_suspect(void) {
    char base[512], obs[512], out[1024], errbuf[512];
    char *argv[6];
    int rc;

    TEST("CLI: an added HID interface exits 1 with SUSPECT");
    path_for("cli-hid-base", base, sizeof base);
    path_for("cli-hid-obs", obs, sizeof obs);
    if (write_file(base, BASE_JSON) != 0 || write_file(obs, HID_JSON) != 0) {
        FAIL("cannot write fixtures");
        return;
    }
    argv[0] = (char *)"cbm-tool";
    argv[1] = (char *)"trust";
    argv[2] = obs;
    argv[3] = (char *)"--baseline";
    argv[4] = base;
    argv[5] = NULL;
    rc = run_cli(5, argv, out, sizeof out, errbuf, sizeof errbuf, NULL);
    if (rc != 1) { FAIL("expected exit 1"); return; }
    if (!strstr(out, "verdict=SUSPECT")) { FAIL(out); return; }
    PASS();
}

static void test_cli_fail_closed(void) {
    char obs[512], out[512], errbuf[512];
    char *argv[4];
    int rc;

    TEST("CLI: no baseline fails closed with a clear message");
    path_for("cli-nobase-obs", obs, sizeof obs);
    if (write_file(obs, BASE_JSON) != 0) { FAIL("cannot write fixture"); return; }
    argv[0] = (char *)"cbm-tool";
    argv[1] = (char *)"trust";
    argv[2] = obs;
    argv[3] = NULL;
    rc = run_cli(3, argv, out, sizeof out, errbuf, sizeof errbuf, NULL);
    if (rc != 1) { FAIL("expected exit 1"); return; }
    if (!strstr(errbuf, "fail closed")) { FAIL(errbuf); return; }
    PASS();
}

static void test_cli_json(void) {
    char base[512], obs[512], buf[1024], errbuf[512];
    char *argv[6];
    FILE *j;
    int rc;

    TEST("CLI: --json emits a cbm/1 document with the verdict");
    path_for("cli-json-base", base, sizeof base);
    path_for("cli-json-obs", obs, sizeof obs);
    if (write_file(base, BASE_JSON) != 0 || write_file(obs, BASE_JSON) != 0) {
        FAIL("cannot write fixtures");
        return;
    }
    j = tmpfile();
    if (!j) { FAIL("tmpfile failed"); return; }
    argv[0] = (char *)"cbm-tool";
    argv[1] = (char *)"trust";
    argv[2] = obs;
    argv[3] = (char *)"--baseline";
    argv[4] = base;
    argv[5] = NULL;
    rc = run_cli(5, argv, NULL, 0, errbuf, sizeof errbuf, j);
    (void)slurp(j, buf, sizeof buf);
    fclose(j);
    if (rc != 0) { FAIL(errbuf); return; }
    if (!strstr(buf, "\"command\":\"trust\"") ||
        !strstr(buf, "\"verdict\":\"trusted\"") ||
        !strstr(buf, "host-observable")) {
        FAIL(buf);
        return;
    }
    PASS();
}

int main(void) {
    char tmpl[] = "/tmp/opencode/trust-test.XXXXXX";
    char *dir;

    dir = mkdtemp(tmpl);
    if (!dir) {
        printf("test_trust: cannot create scratch dir: %s\n", strerror(errno));
        return 1;
    }
    g_dir = dir;

    test_parse_profile();
    test_identical_is_trusted();
    test_hid_interface_flagged();
    test_extra_vendor_interface();
    test_unknown_cdb();
    test_missing_baseline_file();
    test_malformed_profile();
    test_wrong_usb_id();
    test_product_mismatch();
    test_missing_baseline_iface();
    test_fw_marker_changed();
    test_no_cdb_observed();
    test_cli_trusted();
    test_cli_suspect();
    test_cli_fail_closed();
    test_cli_json();

    printf("test_trust: %d passed, %d failed\n", tests_passed, tests_failed);

    for (size_t i = 0; i < g_path_count; i++) (void)unlink(g_paths[i]);
    (void)rmdir(g_dir);
    return tests_failed ? 1 : 0;
}
