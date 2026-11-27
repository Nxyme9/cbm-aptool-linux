/* test_telemetry.c - Prometheus telemetry exporter tests
 *
 * Scratch regular files only: a fake device file and a symlink whose by-id
 * name carries a serial-like string, plus a key=value state file. No device,
 * no network beyond loopback, no vendor binary. The suite's own summary line
 * is outside the frozen `Results:` sums.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "telemetry.h"

static int tests_passed = 0;
static int tests_failed = 0;
static char g_root[128];
static telemetry_state_t g_http_state;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() (printf("PASS\n"), tests_passed++)
#define FAIL(msg) (printf("FAIL: %s\n", msg), tests_failed++)

static void path_of(char *out, size_t outlen, const char *sub) {
    snprintf(out, outlen, "%s/%s", g_root, sub);
}

static int write_bytes(const char *path, const void *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    int ok = fwrite(buf, 1, len, f) == len;
    if (fclose(f) != 0) ok = 0;
    return ok ? 0 : -1;
}

static char *render_alloc(const telemetry_state_t *st) {
    char *buf = NULL;
    size_t len = 0u;
    FILE *f = open_memstream(&buf, &len);
    if (!f) return NULL;
    telemetry_render(f, st);
    if (fclose(f) != 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

static void mock_state(telemetry_state_t *st) {
    telemetry_state_init(st);
    st->device_present = 1;
    st->device_capacity_bytes = 17179869184ULL;
    st->scan_progress_ratio = 0.25;
    st->containers_found = 3u;
    st->cdb_commands_total = 128u;
    st->entropy_blocks_total = 512u;
    st->last_validation_timestamp_seconds = 1764374400ULL;
    st->crypto_backend_native = 1;
    snprintf(st->device_label, sizeof(st->device_label), "%s", "sde");
}

static void test_render_metrics(void) {
    TEST("render emits all eight metrics with expected values");
    telemetry_state_t st;
    mock_state(&st);
    char *doc = render_alloc(&st);
    int ok = doc != NULL;
    const char *needles[] = {
        "device_present{device=\"sde\"} 1",
        "device_capacity_bytes{device=\"sde\"} 17179869184",
        "scan_progress_ratio 0.250000",
        "containers_found 3",
        "cdb_commands_total 128",
        "entropy_blocks_total 512",
        "last_validation_timestamp_seconds 1764374400",
        "crypto_backend_native 1"
    };
    for (size_t i = 0; ok && i < sizeof(needles) / sizeof(needles[0]); i++)
        if (strstr(doc, needles[i]) == NULL) ok = 0;
    free(doc);
    ok ? PASS() : FAIL("one or more metrics missing or mis-valued");
}

static void test_scrub_device(void) {
    TEST("device label scrubs by-id serials and paths");
    char link[256], out[128], err[128];
    path_of(link, sizeof(link), "by-id/usb-CBM_SERIAL123");
    if (symlink("../fake-dev", link) != 0) {
        FAIL("symlink setup failed");
        return;
    }
    int rc = telemetry_scrub_device(link, out, sizeof(out), err, sizeof(err));
    int ok = rc == 0 && strcmp(out, "fake-dev") == 0;
    if (ok && (strstr(out, "SERIAL") != NULL || strchr(out, '/') != NULL)) ok = 0;
    ok ? PASS() : FAIL("scrub did not reduce the by-id path to the resolved basename");
}

static void test_probe_regular(void) {
    TEST("probe reports a regular file's size read-only");
    telemetry_state_t st;
    char path[256], err[128];
    telemetry_state_init(&st);
    path_of(path, sizeof(path), "fake-dev");
    int rc = telemetry_probe_device(path, &st, err, sizeof(err));
    int ok = rc == 0 && st.device_present == 1 &&
             st.device_capacity_bytes == 4096ULL &&
             strcmp(st.device_label, "fake-dev") == 0;
    ok ? PASS() : FAIL("probe did not report present=1 and the exact size");
}

static void test_probe_missing(void) {
    TEST("probe of a missing path reports absent, not an error");
    telemetry_state_t st;
    char path[256], err[128];
    telemetry_state_init(&st);
    path_of(path, sizeof(path), "missing-dev");
    int rc = telemetry_probe_device(path, &st, err, sizeof(err));
    int ok = rc == 0 && st.device_present == 0 && st.device_capacity_bytes == 0ULL;
    ok ? PASS() : FAIL("missing device was not reported as absent");
}

static void test_state_load(void) {
    TEST("state file supplies the counters");
    telemetry_state_t st;
    char path[256], err[192];
    telemetry_state_init(&st);
    path_of(path, sizeof(path), "state.txt");
    int rc = telemetry_load_state(path, &st, err, sizeof(err));
    int ok = rc == 0 &&
             st.scan_progress_ratio == 0.75 &&
             st.containers_found == 9u &&
             st.cdb_commands_total == 42u &&
             st.entropy_blocks_total == 64u &&
             st.last_validation_timestamp_seconds == 1764374999ULL;
    ok ? PASS() : FAIL("state values were not loaded");
}

static void test_state_malformed(void) {
    TEST("malformed state fails closed without a partial update");
    telemetry_state_t st;
    char path[256], err[192];
    telemetry_state_init(&st);
    st.containers_found = 9u;
    path_of(path, sizeof(path), "bad-state.txt");
    const char *body = "containers_found=abc\n";
    if (write_bytes(path, body, strlen(body)) != 0) {
        FAIL("fixture write failed");
        return;
    }
    int rc = telemetry_load_state(path, &st, err, sizeof(err));
    int ok = rc != 0 && err[0] != '\0' && st.containers_found == 9u;
    ok ? PASS() : FAIL("malformed state was accepted or partially applied");
}

static int http_request(int lfd, const char *req, char *resp, size_t resplen) {
    struct sockaddr_in sa;
    socklen_t slen = sizeof(sa);
    if (getsockname(lfd, (struct sockaddr *)&sa, &slen) != 0) return -1;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) return -1;
    if (connect(cfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(cfd);
        return -1;
    }
    if (send(cfd, req, strlen(req), 0) < 0) {
        close(cfd);
        return -1;
    }
    int afd = accept(lfd, NULL, NULL);
    if (afd < 0) {
        close(cfd);
        return -1;
    }
    telemetry_handle_conn(afd, &g_http_state);
    close(afd);
    size_t got = 0u;
    for (;;) {
        ssize_t n = recv(cfd, resp + got, resplen - 1u - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
        if (got + 1u >= resplen) break;
    }
    resp[got] = '\0';
    close(cfd);
    return 0;
}

static void test_http_metrics(void) {
    TEST("/metrics serves Prometheus text with probed capacity and counters");
    char err[192], resp[8192];
    int lfd = -1;
    if (telemetry_listen("127.0.0.1:0", &lfd, err, sizeof(err)) != 0) {
        FAIL(err);
        return;
    }
    int rc = http_request(lfd, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n",
                          resp, sizeof(resp));
    close(lfd);
    int ok = rc == 0 && strstr(resp, "HTTP/1.1 200") != NULL;
    if (ok && strstr(resp, "Content-Type: text/plain; version=0.0.4") == NULL) ok = 0;
    if (ok && strstr(resp, "device_capacity_bytes{device=\"fake-dev\"} 4096") == NULL) ok = 0;
    if (ok && strstr(resp, "containers_found 9") == NULL) ok = 0;
    ok ? PASS() : FAIL("metrics response missing status, content type or values");
}

static void test_http_errors(void) {
    TEST("unknown path is 404 and non-GET is 405");
    char err[192], resp[4096];
    int lfd = -1;
    if (telemetry_listen("127.0.0.1:0", &lfd, err, sizeof(err)) != 0) {
        FAIL(err);
        return;
    }
    int ok = http_request(lfd, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n",
                          resp, sizeof(resp)) == 0 &&
             strstr(resp, "HTTP/1.1 404") != NULL;
    if (ok) {
        ok = http_request(lfd, "POST /metrics HTTP/1.1\r\nHost: x\r\n\r\n",
                          resp, sizeof(resp)) == 0 &&
             strstr(resp, "HTTP/1.1 405") != NULL;
    }
    close(lfd);
    ok ? PASS() : FAIL("wrong status for an unknown path or a non-GET method");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== Telemetry Exporter Tests ===\n");
    char tmpl[] = "/tmp/opencode/cbm-telemetry-test.XXXXXX";
    if (!mkdtemp(tmpl)) {
        printf("FAIL: mkdtemp failed\n");
        return 1;
    }
    snprintf(g_root, sizeof(g_root), "%s", tmpl);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s/by-id'", g_root);
    if (system(cmd) != 0) {
        printf("FAIL: mkdir failed\n");
        return 1;
    }
    unsigned char data[4096];
    memset(data, 0xAB, sizeof(data));
    char dev[256], state[256];
    path_of(dev, sizeof(dev), "fake-dev");
    path_of(state, sizeof(state), "state.txt");
    const char *state_body =
        "# mock state\n"
        "\n"
        "scan_progress_ratio=0.750000\n"
        "containers_found=9\n"
        "cdb_commands_total=42\n"
        "entropy_blocks_total=64\n"
        "last_validation_timestamp_seconds=1764374999\n";
    if (write_bytes(dev, data, sizeof(data)) != 0 ||
        write_bytes(state, state_body, strlen(state_body)) != 0) {
        printf("FAIL: fixture write failed\n");
        return 1;
    }
    telemetry_state_init(&g_http_state);
    snprintf(g_http_state.device_path, sizeof(g_http_state.device_path), "%s", dev);
    snprintf(g_http_state.state_file, sizeof(g_http_state.state_file), "%s", state);

    test_render_metrics();
    test_scrub_device();
    test_probe_regular();
    test_probe_missing();
    test_state_load();
    test_state_malformed();
    test_http_metrics();
    test_http_errors();

    printf("\nScratch fixtures: %s\n", g_root);
    printf("test_telemetry: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
