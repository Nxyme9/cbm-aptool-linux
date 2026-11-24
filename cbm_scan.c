/* cbm_scan.c - read-only, offline CBM container forensic scanner implementation
 *
 * Detect -> parse -> decrypt -> HEURISTIC plausibility gate. Nothing here
 * writes to the scanned image/device; cbm_file_read is the only I/O primitive.
 * Magic strings are advisory and UNVERIFIED (docs/container-format.md:64 says
 * magic values are unknown); structural probing works with no magic at all.
 */
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cbm_container.h"
#include "cbm_decode.h"
#include "cbm_file.h"
#include "cbm_fuzz.h"
#include "tea_crypto.h"

#include "cbm_scan.h"

#define CBM_SCAN_ALIGN 512ULL
#define CBM_SCAN_MAX_TOKENS 8u
#define CBM_SCAN_TOKEN_CHARS 64u

/* HEURISTIC plausibility thresholds. A decrypted body is a candidate only if
 * it is neither degenerate nor indistinguishable from random bytes:
 *   0.5 < Shannon entropy < 7.0 bits/byte,
 *   at least 60% of bytes are printable ASCII (0x20-0x7e), and
 *   at least one printable run of 4+ characters was extracted.
 * These numbers are an inference aid, not a format signature. False positives
 * and false negatives are both possible; hits are CANDIDATES only. */
#define CBM_SCAN_MIN_ENTROPY 0.5
#define CBM_SCAN_MAX_ENTROPY 7.0
#define CBM_SCAN_MIN_PRINTABLE_PCT 60u
#define CBM_SCAN_MIN_TOKEN_LEN 4u

/* Cheap screen for STRUCTURAL candidates only: decrypt an 8-byte-aligned
 * 64-byte prefix and require >= 80% printable plaintext before spending a
 * full 85687-byte decrypt. The native CBC core derives state only from prior
 * ciphertext blocks, so decrypting this prefix equals the first 64 bytes of
 * the full-body decrypt (verified against the core in an offline probe).
 * Magic-driven candidates skip the screen entirely, so advisory magic never
 * suppresses a full parse. */
#define CBM_SCAN_PREFIX_LEN 64u
#define CBM_SCAN_PREFIX_PCT 80u

/* Boundary anchor for the heuristic gate: this cipher self-synchronises, so
 * a window shifted a few LBAs can still decrypt most of a container's body
 * plausibly. Require both the first and last 64 plaintext bytes to be mostly
 * printable; shifted windows have garbage at the leading or trailing edge. */
#define CBM_SCAN_EDGE_LEN 64u
#define CBM_SCAN_EDGE_PCT 80u

static int seterr(char *err, size_t errlen, const char *fmt, ...) {
    if (err && errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

static int crypto_ready(void) {
    if (!tea_is_ready() && tea_init(NULL) != 0) return 0;
    return tea_is_ready();
}

static int is_printable(unsigned char c) {
    return c >= 0x20 && c <= 0x7e;
}

/* Case-sensitive raw-byte search; an empty or NULL magic is ignored. */
static int magic_in_window(const unsigned char *win, size_t win_len,
                           const char *const *magics, size_t nmagic) {
    if (!magics) return 0;
    for (size_t i = 0; i < nmagic; i++) {
        const char *m = magics[i];
        if (!m || !*m) continue;
        size_t mlen = strlen(m);
        if (mlen == 0 || mlen > win_len) continue;
        for (size_t j = 0; j + mlen <= win_len; j++) {
            if (memcmp(win + j, m, mlen) == 0) return 1;
        }
    }
    return 0;
}

/* Extract up to 8 NUL-terminated printable runs with body-relative offsets. */
static size_t extract_tokens(const unsigned char *body, size_t len,
                             char tokens[CBM_SCAN_MAX_TOKENS][CBM_SCAN_TOKEN_CHARS],
                             unsigned long long offsets[CBM_SCAN_MAX_TOKENS]) {
    size_t n = 0;
    size_t i = 0;
    while (i < len && n < CBM_SCAN_MAX_TOKENS) {
        if (!is_printable(body[i])) { i++; continue; }
        size_t start = i;
        while (i < len && is_printable(body[i])) i++;
        size_t run = i - start;
        if (run >= CBM_SCAN_MIN_TOKEN_LEN) {
            size_t copy = run < CBM_SCAN_TOKEN_CHARS - 1u
                          ? run : CBM_SCAN_TOKEN_CHARS - 1u;
            memcpy(tokens[n], body + start, copy);
            tokens[n][copy] = '\0';
            offsets[n] = (unsigned long long)start;
            n++;
        }
    }
    return n;
}

/* Cheap screen before the full decrypt; scratch holds the decrypted prefix. */
static int prefix_plausible(const unsigned char *cipher, unsigned char *scratch) {
    memcpy(scratch, cipher, CBM_SCAN_PREFIX_LEN);
    if (cbm_cbc_decrypt(scratch, CBM_SCAN_PREFIX_LEN,
                        cbm_fuzz_tea_key) != 0) return 0;
    size_t printable = 0;
    for (size_t i = 0; i < CBM_SCAN_PREFIX_LEN; i++) {
        if (is_printable(scratch[i])) printable++;
    }
    return printable * 100u >= (size_t)CBM_SCAN_PREFIX_PCT * CBM_SCAN_PREFIX_LEN;
}

/* HEURISTIC gate: decrypt already succeeded; judge the plaintext only. */
static int plausible(const unsigned char *body, size_t len, double entropy,
                     char tokens[CBM_SCAN_MAX_TOKENS][CBM_SCAN_TOKEN_CHARS],
                     unsigned long long offsets[CBM_SCAN_MAX_TOKENS],
                     size_t *token_count) {
    if (!(entropy > CBM_SCAN_MIN_ENTROPY) ||
        !(entropy < CBM_SCAN_MAX_ENTROPY)) return 0;

    size_t printable = 0;
    for (size_t i = 0; i < len; i++) {
        if (is_printable(body[i])) printable++;
    }
    /* Integer comparison; len is one container body (< 2^31 on any target). */
    if (printable * 100u < (size_t)CBM_SCAN_MIN_PRINTABLE_PCT * len) return 0;

    /* Reject windows whose boundaries are garbage: the true container starts
     * at a fresh CBC state, so a shifted window loses one edge. */
    if (len < 2u * CBM_SCAN_EDGE_LEN) return 0;
    size_t head = 0, tail = 0;
    for (size_t i = 0; i < CBM_SCAN_EDGE_LEN; i++) {
        if (is_printable(body[i])) head++;
        if (is_printable(body[len - CBM_SCAN_EDGE_LEN + i])) tail++;
    }
    if (head * 100u < (size_t)CBM_SCAN_EDGE_PCT * CBM_SCAN_EDGE_LEN ||
        tail * 100u < (size_t)CBM_SCAN_EDGE_PCT * CBM_SCAN_EDGE_LEN) return 0;

    size_t n = extract_tokens(body, len, tokens, offsets);
    if (n == 0) return 0;
    *token_count = n;
    return 1;
}

size_t cbm_scan_buffer(const unsigned char *buf, size_t len,
                       const char *const *magics, size_t nmagic,
                       int structural, unsigned long long base_offset,
                       cbm_scan_hit_t *out, size_t max) {
    if (!buf || !out || max == 0 || len < CBM_CONTAINER_SIZE) return 0;

    size_t body_len = cbm_compute_hlen(CBM_CONTAINER_SIZE);
    if (body_len < CBM_SCAN_PREFIX_LEN ||
        body_len + CBM_HEADER_SIZE != CBM_CONTAINER_SIZE)
        return 0;
    if (!crypto_ready()) return 0;

    unsigned char *body = (unsigned char *)malloc(body_len);
    if (!body) return 0;

    /* Structural granularity is 512-byte-aligned ABSOLUTE offsets, even when
     * a chunk starts at an unaligned absolute byte. */
    unsigned long long rem = base_offset % CBM_SCAN_ALIGN;
    unsigned long long abs_off = rem
                                 ? base_offset + (CBM_SCAN_ALIGN - rem)
                                 : base_offset;
    size_t written = 0;
    while (abs_off >= base_offset && written < max) {
        unsigned long long rel64 = abs_off - base_offset;
        if (rel64 > (unsigned long long)len) break;
        size_t rel = (size_t)rel64; /* rel <= len <= SIZE_MAX */
        if (len - rel < CBM_CONTAINER_SIZE) break;

        const unsigned char *win = buf + rel;
        int magic_hit = magic_in_window(win, CBM_CONTAINER_SIZE,
                                        magics, nmagic);
        if (!structural && !magic_hit) {
            abs_off += CBM_SCAN_ALIGN;
            continue;
        }
        if (!magic_hit && !prefix_plausible(win + CBM_HEADER_SIZE, body)) {
            abs_off += CBM_SCAN_ALIGN;
            continue;
        }

        memcpy(body, win + CBM_HEADER_SIZE, body_len);
        if (cbm_cbc_decrypt(body, body_len, cbm_fuzz_tea_key) != 0) {
            abs_off += CBM_SCAN_ALIGN;
            continue;
        }
        double entropy = cbm_decode_entropy(body, body_len);

        cbm_scan_hit_t cand;
        memset(&cand, 0, sizeof(cand));
        if (plausible(body, body_len, entropy,
                      cand.tokens, cand.token_offsets, &cand.token_count)) {
            cand.offset = abs_off;
            cand.header = win[0]; /* CBM_HEADER_SIZE == 1, copied verbatim */
            cand.entropy = entropy;
            cbm_fuzz_sha256(win, CBM_CONTAINER_SIZE, cand.sha256);
            out[written++] = cand;
        }

        if (abs_off > ULLONG_MAX - CBM_SCAN_ALIGN) break;
        abs_off += CBM_SCAN_ALIGN;
    }
    free(body);
    return written;
}

int cbm_scan_image(const char *path, unsigned long long start_byte,
                   unsigned long long end_byte, size_t chunk_bytes,
                   const char *const *magics, size_t nmagic,
                   cbm_scan_hit_t **out, size_t *out_count,
                   char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!path || !out || !out_count)
        return seterr(err, errlen, "path, out and out_count are required");
    *out = NULL;
    *out_count = 0;
    if (end_byte < start_byte)
        return seterr(err, errlen, "end byte is before start byte");
    if (chunk_bytes <= CBM_CONTAINER_SIZE)
        return seterr(err, errlen, "chunk must be larger than 85688 bytes");
    if (start_byte > (unsigned long long)LLONG_MAX ||
        end_byte > (unsigned long long)LLONG_MAX)
        return seterr(err, errlen, "byte range exceeds signed 64-bit offset");
    if (!crypto_ready())
        return seterr(err, errlen, "native crypto init failed");

    unsigned long long limit = end_byte;
    struct stat st;
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        if (st.st_size <= 0) return 0; /* empty image */
        unsigned long long file_end = (unsigned long long)st.st_size - 1u;
        if (file_end < limit) limit = file_end;
    }
    if (limit < start_byte || limit - start_byte + 1u < CBM_CONTAINER_SIZE)
        return 0; /* no room for a whole container in the range */

    unsigned char *chunk = (unsigned char *)malloc(chunk_bytes);
    if (!chunk) return seterr(err, errlen, "out of memory for scan chunk");

    cbm_scan_hit_t *hits = NULL;
    size_t count = 0, cap = 0;
    unsigned long long last_offset = 0;
    int have_last = 0;
    unsigned long long cur = start_byte;
    /* Overlap is two containers plus one LBA: the extra room lets one
     * container sit wholly inside the overlap (proving dedupe on re-scan)
     * while a second, separated container straddles the chunk boundary.
     * >= 85688 bytes is the hard requirement; this is strictly stronger. */
    const size_t overlap = 2u * CBM_CONTAINER_SIZE + (size_t)CBM_SCAN_ALIGN;
    const unsigned long long stride = (unsigned long long)chunk_bytes - overlap;

    for (;;) {
        unsigned long long remaining = limit - cur + 1u;
        size_t want = remaining > (unsigned long long)chunk_bytes
                      ? chunk_bytes : (size_t)remaining;
        if (want < CBM_CONTAINER_SIZE) break;

        if (cbm_file_read(path, (long long)cur, chunk, want) != 0) {
            seterr(err, errlen, "read failed at byte %llu", cur);
            free(hits);
            free(chunk);
            return -1;
        }

        /* At most one hit per aligned offset in this chunk; reserve enough
         * space so cbm_scan_buffer never truncates the chunk's hits. */
        size_t need = count + want / (size_t)CBM_SCAN_ALIGN + 2u;
        if (need < count || need > SIZE_MAX / sizeof(*hits)) {
            seterr(err, errlen, "hit array too large");
            free(hits);
            free(chunk);
            return -1;
        }
        if (need > cap) {
            size_t next = cap ? cap : 64u;
            while (next < need) {
                if (next > SIZE_MAX / 2u) { next = need; break; }
                next *= 2u;
            }
            if (next > SIZE_MAX / sizeof(*hits)) {
                seterr(err, errlen, "hit array too large");
                free(hits);
                free(chunk);
                return -1;
            }
            cbm_scan_hit_t *grown = (cbm_scan_hit_t *)realloc(
                hits, next * sizeof(*hits));
            if (!grown) {
                seterr(err, errlen, "out of memory for hits");
                free(hits);
                free(chunk);
                return -1;
            }
            hits = grown;
            cap = next;
        }

        size_t got = cbm_scan_buffer(chunk, want, magics, nmagic, 1,
                                     cur, hits + count, cap - count);
        /* The 85688-byte overlap re-scans earlier candidates. Hits ascend, so
         * dropping every offset already recorded dedupes exactly once. */
        size_t kept = 0;
        for (size_t i = 0; i < got; i++) {
            cbm_scan_hit_t *h = &hits[count + i];
            if (have_last && h->offset <= last_offset) continue;
            if (kept != i) hits[count + kept] = *h;
            last_offset = h->offset;
            have_last = 1;
            kept++;
        }
        count += kept;

        if (stride > limit - cur) break;
        cur += stride;
    }

    free(chunk);
    *out = hits;
    *out_count = count;
    return 0;
}

void cbm_scan_free_hits(cbm_scan_hit_t *hits) {
    free(hits);
}

void cbm_scan_print(FILE *out, const cbm_scan_hit_t *hits, size_t n) {
    if (!out) return;
    for (size_t i = 0; i < n; i++) {
        const cbm_scan_hit_t *h = &hits[i];
        /* Fixed-point text with a literal '.', as in cbm_decode_profile: no
         * printf floating conversion, so LC_NUMERIC cannot change the output. */
        unsigned scaled;
        if (!(h->entropy > 0.0)) scaled = 0u;
        else if (h->entropy >= 8.0) scaled = 8000000u;
        else scaled = (unsigned)(h->entropy * 1000000.0 + 0.5);

        fprintf(out, "%llu %u.%06u %02x", h->offset,
                scaled / 1000000u, scaled % 1000000u, h->header);
        for (size_t k = 0; k < 32; k++)
            fprintf(out, "%02x", h->sha256[k]);
        fprintf(out, " %zu", h->token_count);
        for (size_t k = 0; k < h->token_count; k++)
            fprintf(out, " %llu:%s", h->token_offsets[k], h->tokens[k]);
        fputc('\n', out);
    }
}
