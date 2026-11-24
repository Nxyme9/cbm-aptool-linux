/* test_cbm_tui.c - pure ANSI render snapshot / determinism tests (Wave 5D).
 *
 * No tty, no device and no filesystem access: the render function is called
 * with a fixed synthetic state and its exact bytes are asserted.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_tui.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

static void fixed_state(cbm_tui_state_t *st) {
    memset(st, 0, sizeof(*st));
    snprintf(st->target, sizeof(st->target), "/tmp/opencode/dj.img");
    st->size_bytes = 28ULL * 1024ULL * 1024ULL * 1024ULL;
    st->window_gib = 26ULL;
    st->is_blockdev = 0;
    snprintf(st->mbr_status, sizeof(st->mbr_status), "VALID");
    snprintf(st->dj_status, sizeof(st->dj_status), "VALID");
    snprintf(st->parts[0].name, sizeof(st->parts[0].name), "DJ_BOOT");
    st->parts[0].start_lba = 2048ULL;
    st->parts[0].sectors = 1048576ULL;
    st->parts[0].type = 0x0c;
    st->parts[0].inferred = 1;
    snprintf(st->parts[1].name, sizeof(st->parts[1].name), "DJ_OS");
    st->parts[1].start_lba = 1050624ULL;
    st->parts[1].sectors = 8388608ULL;
    st->parts[1].type = 0x83;
    st->parts[1].inferred = 1;
    snprintf(st->parts[2].name, sizeof(st->parts[2].name), "DJ_DATA");
    st->parts[2].start_lba = 9439232ULL;
    st->parts[2].sectors = 45086720ULL;
    st->parts[2].type = 0x07;
    st->parts[2].inferred = 1;
    st->part_count = 3;
    st->scan_hits = 3;
    st->last_hit_offset = 1048576ULL;
    st->entropy_min = 0.25;
    st->entropy_mean = 4.0;
    st->entropy_max = 7.75;
    snprintf(st->backend, sizeof(st->backend), "native");
    /* Deterministic first-sector fixture matching the pinned hex line below. */
    for (size_t i = 0; i < 32u; i++) st->hex[i] = (unsigned char)i;
    st->hex_len = sizeof(st->hex);
    st->hex_scroll = 0;
    st->term_width = 80;
    st->term_height = 24;
}

/* Hand-written expectation: every label, value and escape byte is pinned. */
static const char EXPECTED[] =
    "\033[H\033[2J"
    "\033[1;1HCBM DOCTOR / LIVE TUI [READ-ONLY]\033[K"
    "\033[2;1Hdevice=/tmp/opencode/dj.img size=28.000000 GiB blockdev=no\033[K"
    "\033[3;1HMBR=VALID DJ=VALID window=26 GiB\033[K"
    "\033[4;1HPART DJ_BOOT start=2048 sectors=1048576 type=0x0c inferred=yes\033[K"
    "\033[5;1HPART DJ_OS start=1050624 sectors=8388608 type=0x83 inferred=yes\033[K"
    "\033[6;1HPART DJ_DATA start=9439232 sectors=45086720 type=0x07 inferred=yes\033[K"
    "\033[7;1Hscan_hits=3 last_offset=1048576\033[K"
    "\033[8;1Hentropy min=0.250000 mean=4.000000 max=7.750000\033[K"
    "\033[9;1Hbackend=native term=80x24\033[K"
    "\033[10;1HHEX 0000:000102030405060708090a0b0c0d0e0f 0010:101112131415161718191a1b1c1d1e1f\033[K"
    "\033[11;1Hq/ESC quit (read-only, no key writes)\033[K"
    "\n";

static void test_snapshot_exact_bytes(void) {
    TEST("tui: fixed state renders an exact pinned snapshot");
    cbm_tui_state_t st;
    fixed_state(&st);
    char *got = cbm_tui_render(&st, 80, 24);
    int ok = (got != NULL && strlen(got) == sizeof(EXPECTED) - 1u &&
              memcmp(got, EXPECTED, sizeof(EXPECTED) - 1u) == 0);
    free(got);
    if (ok) PASS(); else FAIL("snapshot bytes differ from pinned expectation");
}

static void test_determinism(void) {
    TEST("tui: two renders of one state are byte-identical");
    cbm_tui_state_t st;
    fixed_state(&st);
    char *a = cbm_tui_render(&st, 80, 24);
    char *b = cbm_tui_render(&st, 80, 24);
    int ok = (a != NULL && b != NULL && strcmp(a, b) == 0);
    free(a); free(b);
    if (ok) PASS(); else FAIL("render must be deterministic");
}

/* Verify each cursor-addressed line is complete and its printable content
 * fits the requested width; a half-written ANSI sequence fails this check. */
static int lines_well_formed(const char *s, size_t width) {
    size_t pos = 0;
    int found = 0;
    for (;;) {
        const char *p = strstr(s + pos, "\033[");
        if (!p) break;
        const char *q = p + 2;
        if (*q < '0' || *q > '9') { pos = (size_t)(q - s); continue; }
        while (*q >= '0' && *q <= '9') q++;
        if (*q != ';' || strncmp(q, ";1H", 3) != 0) return 0;
        q += 3;
        size_t n = 0;
        while (strncmp(q, "\033[K", 3) != 0) {
            if (*q == '\0' || *q == '\033') return 0;
            n++; q++;
        }
        if (n > width) return 0;
        found++;
        pos = (size_t)(q + 3 - s);
    }
    return found > 0;
}

static void test_compact_terminal(void) {
    TEST("tui: 60x20 compact layout is non-empty, bounded and complete");
    cbm_tui_state_t st;
    fixed_state(&st);
    char *out = cbm_tui_render(&st, 60, 20);
    size_t n = out ? strlen(out) : 0;
    int ok = (n > 0 && strstr(out, "CBM TUI RO") != NULL &&
              strstr(out, "MBR=VALID") != NULL && strstr(out, "hits=3") != NULL &&
              lines_well_formed(out, 60));
    free(out);
    if (ok) PASS(); else FAIL("compact layout must stay bounded and readable");
}

static void test_tiny_terminal(void) {
    TEST("tui: 20x10 tiny layout does not crash and ends on a complete line");
    cbm_tui_state_t st;
    fixed_state(&st);
    char *out = cbm_tui_render(&st, 20, 10);
    size_t n = out ? strlen(out) : 0;
    int ok = (n >= 4 && strstr(out, "CBM TUI RO") != NULL &&
              memcmp(out + n - 4, "\033[K\n", 4) == 0 &&
              lines_well_formed(out, 20));
    free(out);
    if (ok) PASS(); else FAIL("tiny layout must be non-empty with whole escapes");
}

static void test_zero_dimensions(void) {
    TEST("tui: zero dimensions degrade to a single valid line");
    cbm_tui_state_t st;
    fixed_state(&st);
    char *out = cbm_tui_render(&st, 0, 0);
    size_t n = out ? strlen(out) : 0;
    int ok = (n >= 4 && lines_well_formed(out, 1));
    free(out);
    if (ok) PASS(); else FAIL("zero dimensions must not crash or truncate");
}

static void test_long_target_truncated_to_width(void) {
    TEST("tui: 255-char target is truncated to the requested width");
    cbm_tui_state_t st;
    fixed_state(&st);
    memset(st.target, 'X', sizeof(st.target) - 1u);
    st.target[sizeof(st.target) - 1u] = '\0';
    char *out = cbm_tui_render(&st, 80, 24);
    int ok = 0;
    if (out != NULL) {
        /* The full frame starts with \033[H\033[2J; skip it because the
         * line checker treats a digit followed by 'J' as malformed. */
        static const char CLEAR[] = "\033[H\033[2J";
        if (strncmp(out, CLEAR, sizeof(CLEAR) - 1u) == 0) {
            const char *body = out + sizeof(CLEAR) - 1u;
            ok = (strstr(body, "device=XXXX") != NULL &&
                  strstr(body, "size=28.000000 GiB") != NULL &&
                  strstr(body, "blockdev=no") != NULL &&
                  strstr(body, "backend=native") != NULL &&
                  lines_well_formed(body, 80));
        }
    }
    free(out);
    if (ok) PASS(); else FAIL("every rendered line must fit the requested width");
}

static void test_non_finite_entropy_deterministic(void) {
    TEST("tui: NaN/Inf/-0.0 entropy renders deterministically as 0.000000");
    cbm_tui_state_t st;
    fixed_state(&st);
    st.entropy_min = NAN;
    st.entropy_mean = INFINITY;
    st.entropy_max = -0.0;
    char *a = cbm_tui_render(&st, 80, 24);
    char *b = cbm_tui_render(&st, 80, 24);
    int ok = (a != NULL && b != NULL && strcmp(a, b) == 0 &&
              strstr(a, "entropy min=0.000000 mean=0.000000 max=0.000000") != NULL);
    free(a); free(b);
    if (ok) PASS(); else FAIL("non-finite/-0.0 entropy must clamp deterministically");
}

static void test_hex_line_uses_real_sector_bytes(void) {
    TEST("tui: hex line renders two real 16-byte rows from the first sector");
    cbm_tui_state_t st;
    fixed_state(&st);
    char *out = cbm_tui_render(&st, 80, 24);
    int ok = (out != NULL && strstr(out,
        "HEX 0000:000102030405060708090a0b0c0d0e0f "
        "0010:101112131415161718191a1b1c1d1e1f") != NULL &&
        lines_well_formed(out + 7, 80));
    free(out);
    if (ok) PASS(); else FAIL("hex dump must show the caller's real first-sector bytes");
}

static void test_hex_scroll_is_clamped(void) {
    TEST("tui: hex scroll clamps to the end of the sampled sector");
    cbm_tui_state_t st;
    fixed_state(&st);
    st.hex_scroll = 999u;
    char *out = cbm_tui_render(&st, 80, 24);
    int ok = (out != NULL && strstr(out, "HEX 0200:--------------------------------") != NULL &&
              lines_well_formed(out + 7, 80));
    free(out);
    if (ok) PASS(); else FAIL("hex scroll must clamp to hex_len/16");
}

static void test_no_scan_frame_says_not_sampled(void) {
    TEST("tui: zeroed scan/entropy values are shown as not sampled, not fabricated");
    cbm_tui_state_t st;
    fixed_state(&st);
    st.scan_hits = 0;
    st.last_hit_offset = 0;
    st.entropy_min = 0.0;
    st.entropy_mean = 0.0;
    st.entropy_max = 0.0;
    char *out = cbm_tui_render(&st, 80, 24);
    int ok = (out != NULL &&
              strstr(out, "scan_hits=n/a (no scan in this frame)") != NULL &&
              strstr(out, "entropy=n/a (not sampled in this frame)") != NULL &&
              strstr(out, "scan_hits=0 ") == NULL &&
              lines_well_formed(out + 7, 80));
    free(out);
    if (ok) PASS(); else FAIL("TUI must not fabricate scan or entropy data");
}

static void test_entropy_clamped_to_bits_per_byte(void) {
    TEST("tui: entropy above 8 bits/byte clamps to 8.000000");
    cbm_tui_state_t st;
    fixed_state(&st);
    st.entropy_min = -1.0;
    st.entropy_max = 9.0;
    char *out = cbm_tui_render(&st, 80, 24);
    int ok = (out != NULL &&
              strstr(out, "entropy min=0.000000 mean=4.000000 max=8.000000") != NULL);
    free(out);
    if (ok) PASS(); else FAIL("entropy must be clamped to [0,8] bits per byte");
}

int main(void) {
    printf("=== CBM TUI Tests ===\n");
    test_snapshot_exact_bytes();
    test_determinism();
    test_compact_terminal();
    test_tiny_terminal();
    test_zero_dimensions();
    test_long_target_truncated_to_width();
    test_non_finite_entropy_deterministic();
    test_hex_line_uses_real_sector_bytes();
    test_hex_scroll_is_clamped();
    test_no_scan_frame_says_not_sampled();
    test_entropy_clamped_to_bits_per_byte();
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
