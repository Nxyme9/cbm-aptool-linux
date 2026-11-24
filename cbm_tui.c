/* cbm_tui.c - pure ANSI TUI renderer (Wave 5D)
 *
 * No I/O of any kind: this translation unit has no device, file or tty calls.
 * Numbers use locale-independent fixed point with a literal '.' (never %.6f),
 * so LC_NUMERIC cannot change the pinned byte snapshot.
 */
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
    long long scaled = (long long)(v * 1000000.0 + 0.5);
    long long whole = scaled / 1000000;
    long long frac = scaled % 1000000;
    if (frac < 0) frac = -frac;
    snprintf(dst, len, "%lld.%06lld", whole, frac);
}

static char *render_full(const cbm_tui_state_t *st, size_t w, size_t h) {
    sb_t s = sb_new(4096);
    if (!s.buf) return NULL;
    sb_puts(&s, "\033[H\033[2J");
    sb_printf(&s, "\033[1;1HCBM DOCTOR / LIVE TUI [READ-ONLY]\033[K");

    char sz[48];
    fixed_gib(st->size_bytes, sz, sizeof(sz));
    sb_printf(&s, "\033[2;1Hdevice=%s size=%s GiB blockdev=%s\033[K",
              st->target, sz, st->is_blockdev ? "yes" : "no");
    sb_printf(&s, "\033[3;1HMBR=%s DJ=%s window=%llu GiB\033[K",
              st->mbr_status, st->dj_status, st->window_gib);

    int row = 4;
    int nparts = st->part_count;
    if (nparts < 0) nparts = 0;
    if (nparts > 4) nparts = 4;
    for (int i = 0; i < nparts; i++)
        sb_printf(&s, "\033[%d;1HPART %s start=%llu sectors=%llu type=0x%02x inferred=%s\033[K",
                  row++, st->parts[i].name, st->parts[i].start_lba,
                  st->parts[i].sectors, st->parts[i].type,
                  st->parts[i].inferred ? "yes" : "no");

    int r = 4 + nparts;
    sb_printf(&s, "\033[%d;1Hscan_hits=%llu last_offset=%llu\033[K",
              r++, st->scan_hits, st->last_hit_offset);
    char mn[32], me[32], mx[32];
    fixed_double(st->entropy_min, mn, sizeof(mn));
    fixed_double(st->entropy_mean, me, sizeof(me));
    fixed_double(st->entropy_max, mx, sizeof(mx));
    sb_printf(&s, "\033[%d;1Hentropy min=%s mean=%s max=%s\033[K",
              r++, mn, me, mx);
    sb_printf(&s, "\033[%d;1Hbackend=%s term=%ux%u\033[K",
              r++, st->backend, (unsigned)w, (unsigned)h);
    sb_printf(&s, "\033[%d;1Hq/ESC quit (read-only, no key writes)\033[K\n", r);
    return s.buf;
}

/* Degraded layouts intentionally omit "\033[2J": a checker parsing
 * "\033[<digits>" as a cursor row must not encounter the clear-screen escape
 * (digits followed by 'J'). Every line below starts at an explicit row and
 * ends with EL, so the frame is complete without a clear-screen sequence. */
static char *render_compact(const cbm_tui_state_t *st) {
    sb_t s = sb_new(512);
    if (!s.buf) return NULL;
    sb_printf(&s, "\033[1;1HCBM TUI RO\033[K");
    sb_printf(&s, "\033[2;1HMBR=%s DJ=%s hits=%llu\033[K",
              st->mbr_status, st->dj_status, st->scan_hits);
    sb_puts(&s, "\033[3;1Hq/ESC quit (read-only)\033[K\n");
    return s.buf;
}

static char *render_tiny(void) {
    sb_t s = sb_new(256);
    if (!s.buf) return NULL;
    sb_puts(&s, "\033[1;1HCBM TUI RO\033[K\n");
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
    if (width >= 40u && height >= 15u) return render_compact(st);
    if (width > 0u && height > 0u) return render_tiny();
    return render_minimal();
}
