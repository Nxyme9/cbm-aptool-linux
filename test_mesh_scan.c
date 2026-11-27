/* test_mesh_scan.c - distributed mesh scan coordinator tests
 *
 * Synthetic images only: scratch regular files under /tmp/opencode. Two local
 * mock workers prove range splitting + aggregation; the offline fallback runs
 * the REAL read-only scanner locally and must find the same set. No device, no
 * vendor binary, and NO claim that a real CLS peer was contacted. Its own
 * summary line is outside the frozen `Results:` sums.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_container.h"
#include "cbm_file.h"
#include "cbm_fuzz.h"
#include "tea_crypto.h"

#include "cbm_scan.h"
#include "mesh_scan.h"

static int tests_passed = 0;
static int tests_failed = 0;
static char g_root[128];

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() (printf("PASS\n"), tests_passed++)
#define FAIL(msg) (printf("FAIL: %s\n", msg), tests_failed++)

#define BODY_LEN ((size_t)(CBM_CONTAINER_SIZE - CBM_HEADER_SIZE))
#define IMAGE_BYTES (512u * 1024u)
#define CHUNK (512u * 1024u)
/* All offsets are 512-byte aligned (the scanner probes aligned starts).
 * 358400 lies in the r0/r1 overlap so it is seen twice and dedup collapses it. */
static const unsigned long long PLANTED[] = {51200ULL, 204800ULL, 358400ULL};
#define NPLANTED (sizeof(PLANTED) / sizeof(PLANTED[0]))

static void path_of(char *out, size_t outlen, const char *sub) {
    snprintf(out, outlen, "%s/%s", g_root, sub);
}

static void fill_body(unsigned char *body, size_t len) {
    unsigned int s = 12345u;
    for (size_t i = 0; i < len; i++) {
        s = s * 1664525u + 1013904223u;
        unsigned int r = s >> 24;
        body[i] = (r < 13u) ? 0u : (unsigned char)(0x20u + (r % 95u));
    }
    memcpy(body, "CBM-FORE", 8u);
    memcpy(body + len - 8u, "NSIC-END", 8u);
}

static int make_container(unsigned char *out, unsigned char header) {
    fill_body(out + CBM_HEADER_SIZE, BODY_LEN);
    out[0] = header;
    return cbm_cbc_encrypt(out + CBM_HEADER_SIZE, BODY_LEN, cbm_fuzz_tea_key);
}

static int build_image(const char *path) {
    unsigned char *img = (unsigned char *)malloc(IMAGE_BYTES);
    unsigned char container[CBM_CONTAINER_SIZE];
    if (!img) return -1;
    memset(img, 0xa5u, IMAGE_BYTES);
    for (size_t i = 0; i < NPLANTED; i++) {
        if (make_container(container, (unsigned char)(0x81u + i)) != 0) {
            free(img);
            return -1;
        }
        memcpy(img + PLANTED[i], container, CBM_CONTAINER_SIZE);
    }
    FILE *f = fopen(path, "wb");
    int rc = -1;
    if (f) {
        rc = (fwrite(img, 1, IMAGE_BYTES, f) == IMAGE_BYTES && fclose(f) == 0) ? 0 : -1;
    }
    free(img);
    return rc;
}

static int has_offset(const mesh_result_t *res, unsigned long long off) {
    for (size_t i = 0; i < res->hit_count; i++)
        if (res->hits[i].offset == off) return 1;
    return 0;
}

static int all_planted(const mesh_result_t *res) {
    for (size_t i = 0; i < NPLANTED; i++)
        if (!has_offset(res, PLANTED[i])) return 0;
    return 1;
}

/* Mock worker: a transport stand-in. It reports the known planted containers
 * fully inside its assigned range without doing crypto (that is the scanner's
 * job, tested here via the offline fallback). Records invocations and a fail
 * flag so the coordinator's dispatch/fallback logic is what gets tested. */
typedef struct {
    int calls;
    int fail;
} mock_ctx_t;

static int mock_worker(void *ctx, const char *name, const char *path,
                       unsigned long long start, unsigned long long end,
                       size_t chunk, cbm_scan_hit_t **hits, size_t *count,
                       char *err, size_t errlen) {
    (void)path;
    (void)chunk;
    mock_ctx_t *m = (mock_ctx_t *)ctx;
    m->calls++;
    if (m->fail) {
        snprintf(err, errlen, "mock peer %s unreachable", name);
        return -1;
    }
    cbm_scan_hit_t *out = (cbm_scan_hit_t *)calloc(NPLANTED, sizeof(*out));
    if (!out) {
        snprintf(err, errlen, "mock peer out of memory");
        return -1;
    }
    size_t n = 0u;
    for (size_t i = 0u; i < NPLANTED; i++) {
        if (PLANTED[i] >= start && PLANTED[i] + CBM_CONTAINER_SIZE <= end) {
            out[n].offset = PLANTED[i];
            out[n].header = (unsigned char)(0x81u + i);
            n++;
        }
    }
    *hits = out;
    *count = n;
    return 0;
}

static void test_plan_ranges(void) {
    TEST("mesh_plan_ranges covers the image with overlap");
    unsigned long long ranges[64];
    size_t n = mesh_plan_ranges(0ULL, IMAGE_BYTES - 1u, CHUNK, ranges, 64u);
    int ok = n >= 2u && n <= 64u;
    if (ok && ranges[0] != 0ULL) ok = 0;
    for (size_t i = 1; ok && i < n; i++) {
        if (ranges[i] <= ranges[i - 1]) ok = 0;
        if (ranges[i] - ranges[i - 1] > CHUNK) ok = 0;
    }
    ok ? PASS() : FAIL("range coverage or overlap invalid");
}

static void test_offline_fallback(const char *path) {
    TEST("offline fallback scans locally and finds all containers");
    mesh_result_t res;
    char err[256];
    memset(&res, 0, sizeof(res));
    if (mesh_scan_run(path, 0ULL, IMAGE_BYTES - 1u, CHUNK, NULL, 0u,
                      &res, err, sizeof(err)) != 0) {
        FAIL(err);
        return;
    }
    int ok = (res.mode == MESH_MODE_LOCAL_FALLBACK) && all_planted(&res);
    if (!ok || strstr(res.mode_detail, "fallback") == NULL) ok = 0;
    ok ? PASS() : FAIL("fallback mode/hits/detail mismatch");
    mesh_result_free(&res);
}

static void test_two_mock_workers(const char *path) {
    TEST("two mock workers split and aggregate all containers");
    mock_ctx_t a = {0, 0}, b = {0, 0};
    mesh_worker_t workers[2];
    memset(workers, 0, sizeof(workers));
    snprintf(workers[0].name, sizeof(workers[0].name), "mock-a");
    workers[0].fn = mock_worker;
    workers[0].ctx = &a;
    snprintf(workers[1].name, sizeof(workers[1].name), "mock-b");
    workers[1].fn = mock_worker;
    workers[1].ctx = &b;

    mesh_result_t res;
    char err[256];
    memset(&res, 0, sizeof(res));
    if (mesh_scan_run(path, 0ULL, IMAGE_BYTES - 1u, CHUNK, workers, 2u,
                      &res, err, sizeof(err)) != 0) {
        FAIL(err);
        return;
    }
    int ok = (res.mode == MESH_MODE_DISTRIBUTED) && (a.calls > 0) && (b.calls > 0);
    if (!ok || res.jobs_ok != res.jobs_total || !all_planted(&res)) ok = 0;
    if (!ok || strstr(res.mode_detail, "fallback") != NULL) ok = 0;
    ok ? PASS() : FAIL("distributed mode/worker split/hits mismatch");
    mesh_result_free(&res);
}

static void test_partial_failure_retry(const char *path) {
    TEST("failed peer ranges are retried locally and reported honestly");
    mock_ctx_t a = {0, 0}, b = {0, 1};
    mesh_worker_t workers[2];
    memset(workers, 0, sizeof(workers));
    snprintf(workers[0].name, sizeof(workers[0].name), "mock-a");
    workers[0].fn = mock_worker;
    workers[0].ctx = &a;
    snprintf(workers[1].name, sizeof(workers[1].name), "mock-b");
    workers[1].fn = mock_worker;
    workers[1].ctx = &b;

    mesh_result_t res;
    char err[256];
    memset(&res, 0, sizeof(res));
    if (mesh_scan_run(path, 0ULL, IMAGE_BYTES - 1u, CHUNK, workers, 2u,
                      &res, err, sizeof(err)) != 0) {
        FAIL(err);
        return;
    }
    int ok = (res.mode == MESH_MODE_DISTRIBUTED) && (res.jobs_ok > 0) &&
             (res.local_retries > 0) && all_planted(&res);
    if (!ok || strstr(res.mode_detail, "local") == NULL) ok = 0;
    ok ? PASS() : FAIL("partial failure retry not reported honestly");
    mesh_result_free(&res);
}

static void test_dedup(void) {
    TEST("mesh_dedup removes cross-range duplicate hits");
    cbm_scan_hit_t hits[4];
    memset(hits, 0, sizeof(hits));
    hits[0].offset = 358400ULL;
    hits[1].offset = 51200ULL;
    hits[2].offset = 358400ULL;
    hits[3].offset = 204800ULL;
    size_t n = mesh_dedup(hits, 4u);
    int ok = (n == 3u) && (hits[0].offset == 51200ULL) &&
             (hits[1].offset == 204800ULL) && (hits[2].offset == 358400ULL);
    ok ? PASS() : FAIL("dedup did not collapse duplicate offsets");
}

static void test_report_json(const char *path) {
    TEST("mesh report JSON names the mode and hit count");
    mesh_result_t res;
    char err[256];
    char rpath[256];
    memset(&res, 0, sizeof(res));
    path_of(rpath, sizeof(rpath), "mesh.json");
    if (mesh_scan_run(path, 0ULL, IMAGE_BYTES - 1u, CHUNK, NULL, 0u,
                      &res, err, sizeof(err)) != 0) {
        FAIL(err);
        return;
    }
    FILE *f = fopen(rpath, "wb");
    int ok = f != NULL;
    if (f) {
        mesh_report_json(f, &res);
        ok = (fclose(f) == 0);
    }
    char buf[8192];
    size_t got = 0;
    if (ok) {
        f = fopen(rpath, "rb");
        if (f) {
            got = fread(buf, 1, sizeof(buf) - 1u, f);
            fclose(f);
        } else ok = 0;
    }
    buf[got] = '\0';
    if (!ok || strstr(buf, "\"mode\":\"local_fallback\"") == NULL) ok = 0;
    if (!ok || strstr(buf, "\"hit_count\":3") == NULL) ok = 0;
    if (!ok || strstr(buf, "mock-a") != NULL) ok = 0; /* no fabricated peer */
    ok ? PASS() : FAIL("JSON missing honest mode or hit count");
    mesh_result_free(&res);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== Distributed Mesh Scan Tests ===\n");
    if (tea_init(NULL) != 0) {
        printf("FAIL: native crypto init failed\n");
        return 1;
    }
    char tmpl[] = "/tmp/opencode/cbm-mesh-test.XXXXXX";
    if (!mkdtemp(tmpl)) {
        printf("FAIL: mkdtemp failed\n");
        tea_cleanup();
        return 1;
    }
    snprintf(g_root, sizeof(g_root), "%s", tmpl);
    char image[256];
    path_of(image, sizeof(image), "disk.img");
    if (build_image(image) != 0) {
        printf("FAIL: build_image failed\n");
        tea_cleanup();
        return 1;
    }

    test_plan_ranges();
    test_offline_fallback(image);
    test_two_mock_workers(image);
    test_partial_failure_retry(image);
    test_dedup();
    test_report_json(image);

    printf("\nScratch fixtures: %s\n", g_root);
    printf("test_mesh_scan: %d passed, %d failed\n", tests_passed, tests_failed);
    tea_cleanup();
    return tests_failed > 0 ? 1 : 0;
}
