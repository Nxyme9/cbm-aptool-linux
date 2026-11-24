/* cbm_tui.c - pure ANSI TUI renderer (Wave 5D)
 *
 * No I/O of any kind: this translation unit has no device, file or tty calls.
 * Numbers use locale-independent fixed point with a literal '.' (never %.6f),
 * so LC_NUMERIC cannot change the pinned byte snapshot.
 */
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_tui.h"

typedef struct {
    char *buf;
    size_t cap;
    size_t len;
} sb_t;

static sb_t sb_new(size_t cap) {
    sb_t s;
    s.buf = (char *)malloc(cap);
    s.cap = cap;
    s.len = 0;
    if (s.buf) s.buf[0] = '\0';
    return s;
}

static void sb_puts(sb_t *s, const char *text) {
    size_t n = strlen(text);
    if (s->len + n + 1u > s->cap) n = (s->cap > s->len) ? s->cap - s->len - 1u : 0;
    memcpy(s->buf + s->len, text, n);
    s->len += n;
    s->buf[s->len] = '\0';
}

static void sb_printf(sb_t *s, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(s->buf + s->len, s->cap - s->len, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= s->cap - s->len) {
        s->len = s->cap - 1u;
        return;
    }
    s->len += (size_t)n;
}

static void fixed_gib(unsigned long long bytes, char *dst, size_t len) {
    unsigned long long whole = bytes >> 30;
    unsigned long long frac = ((bytes & ((1ULL << 30) - 1ULL)) * 1000000ULL) >> 30;
    snprintf(dst, len, "%llu.%06llu", whole, frac);
}

static void fixed_double(double v, char *dst, size_t len) {
    /* (long long)(v * 1e6 + 0.5) is undefined for NaN/Inf and for values
     * beyond the long-long range. Entropy is a non-negative [0,1] value;
     * clamp non-finite, negative and oversized inputs deterministically to
     * 0.0 (also normalising -0.0) so rendering never invokes UB. */
    if (!isfinite(v) || v <= 0.0 || v > 1000000.0) v = 0.0;
    long long scaled = (long long)(v * 1000000.0 + 0.5);
    long long whole = scaled / 1000000;
    long long frac = scaled % 1000000;
    if (frac < 0) frac = -frac;
    snprintf(dst, len, "%lld.%06lld", whole, frac);
}

/* ONE helper bounds every rendered field to the requested terminal width.
 * Content is ASCII (all escapes are emitted by this function), so visible
 * width equals byte count. The exact pinned 80x24 snapshot is unchanged
 * because none of its normal values reach the 80-column limit. */
static void emit_line(sb_t *s, int row, const char *text, size_t width, int newline) {
    char line[1024];
    size_t n = strlen(text);
    if (width > 0u && n > width) n = width;
    if (n > sizeof(line) - 1u) n = sizeof(line) - 1u;
    memcpy(line, text, n);
    line[n] = '\0';
    sb_printf(s, "\033[%d;1H%s\033[K%s", row, line, newline ? "\n" : "");
}

static char *render_full(const cbm_tui_state_t *st, size_t w, size_t h) {
    sb_t s = sb_new(4096);
    if (!s.buf) return NULL;
    sb_puts(&s, "\033[H\033[2J");

    char content[1024];
    snprintf(content, sizeof(content), "CBM DOCTOR / LIVE TUI [READ-ONLY]");
    emit_line(&s, 1, content, w, 0);

    char sz[48];
    fixed_gib(st->size_bytes, sz, sizeof(sz));
    snprintf(content, sizeof(content), "device=%s size=%s GiB blockdev=%s",
             st->target, sz, st->is_blockdev ? "yes" : "no");
    emit_line(&s, 2, content, w, 0);

    snprintf(content, sizeof(content), "MBR=%s DJ=%s window=%llu GiB",
             st->mbr_status, st->dj_status, st->window_gib);
    emit_line(&s, 3, content, w, 0);

    int row = 4;
    int nparts = st->part_count;
    if (nparts < 0) nparts = 0;
    if (nparts > 4) nparts = 4;
    for (int i = 0; i < nparts; i++) {
        snprintf(content, sizeof(content),
                 "PART %s start=%llu sectors=%llu type=0x%02x inferred=%s",
                 st->parts[i].name, st->parts[i].start_lba,
                 st->parts[i].sectors, st->parts[i].type,
                 st->parts[i].inferred ? "yes" : "no");
        emit_line(&s, row++, content, w, 0);
    }

    int r = 4 + nparts;
    snprintf(content, sizeof(content), "scan_hits=%llu last_offset=%llu",
             st->scan_hits, st->last_hit_offset);
    emit_line(&s, r++, content, w, 0);

    char mn[32], me[32], mx[32];
    fixed_double(st->entropy_min, mn, sizeof(mn));
    fixed_double(st->entropy_mean, me, sizeof(me));
    fixed_double(st->entropy_max, mx, sizeof(mx));
    snprintf(content, sizeof(content), "entropy min=%s mean=%s max=%s", mn, me, mx);
    emit_line(&s, r++, content, w, 0);

    snprintf(content, sizeof(content), "backend=%s term=%ux%u",
             st->backend, (unsigned)w, (unsigned)h);
    emit_line(&s, r++, content, w, 0);

    snprintf(content, sizeof(content), "q/ESC quit (read-only, no key writes)");
    emit_line(&s, r, content, w, 1);
    return s.buf;
}

/* Degraded layouts intentionally omit "\033[2J": a checker parsing
 * "\033[<digits>" as a cursor row must not encounter the clear-screen escape
 * (digits followed by 'J'). Every line below starts at an explicit row and
 * ends with EL, so the frame is complete without a clear-screen sequence. */
static char *render_compact(const cbm_tui_state_t *st, size_t w) {
    sb_t s = sb_new(512);
    if (!s.buf) return NULL;
    char content[256];
    snprintf(content, sizeof(content), "CBM TUI RO");
    emit_line(&s, 1, content, w, 0);
    snprintf(content, sizeof(content), "MBR=%s DJ=%s hits=%llu",
             st->mbr_status, st->dj_status, st->scan_hits);
    emit_line(&s, 2, content, w, 0);
    snprintf(content, sizeof(content), "q/ESC quit (read-only)");
    emit_line(&s, 3, content, w, 1);
    return s.buf;
}

static char *render_tiny(size_t w) {
    sb_t s = sb_new(256);
    if (!s.buf) return NULL;
    char content[128];
    snprintf(content, sizeof(content), "CBM TUI RO");
    emit_line(&s, 1, content, w, 1);
    return s.buf;
}

static char *render_minimal(void) {
    sb_t s = sb_new(64);
    if (!s.buf) return NULL;
    sb_puts(&s, "\033[1;1H-\033[K\n");
    return s.buf;
}

char *cbm_tui_render(const cbm_tui_state_t *st, size_t width, size_t height) {
    if (!st) return NULL;
    if (width >= 80u && height >= 24u) return render_full(st, width, height);
    if (width >= 40u && height >= 15u) return render_compact(st, width);
    if (width > 0u && height > 0u) return render_tiny(width);
    return render_minimal();
}
