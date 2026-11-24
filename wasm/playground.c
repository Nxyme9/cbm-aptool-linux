/* playground.c - self-contained wasm32 API for the browser playground.
 *
 * Clean-room TEA tables and core logic are adapted from tea_native.c (the
 * default native backend) with no libc allocator, no libc calls, no PE loader
 * and no vendor binary. All storage is static and bounded; every exported
 * function takes pointer+length pairs into linear memory. See
 * docs/wasm-playground.md for the build command and the 256 KiB file cap.
 */

#include <stddef.h>
#include <stdint.h>

#define WASM_CAP 262144u                 /* 256 KiB per input file */
#define WASM_BLOB_CAP 65536u             /* printable-string text blob */
#define WASM_STRING_MAX 256u             /* descriptor pairs (offset, length) */
#define WASM_DIFF_MAX 4096u              /* range triples (offset, length, changed) */
#define WASM_STRING_MIN 4u
#define WASM_STRING_TRUNC 63u

static unsigned char buf_a[WASM_CAP];
static unsigned char buf_b[WASM_CAP];
static unsigned char key_buf[16];
static unsigned char string_blob[WASM_BLOB_CAP];
static uint32_t string_refs[WASM_STRING_MAX * 3u];
static uint32_t diff_ranges[WASM_DIFF_MAX * 3u];

/* --- minimal byte helpers (no libc) ------------------------------------- */

static void bytes_copy(unsigned char *dst, const unsigned char *src,
                       unsigned int n) {
    unsigned int i;
    for (i = 0; i < n; i++) dst[i] = src[i];
}

static void bytes_zero(unsigned char *dst, unsigned int n) {
    unsigned int i;
    for (i = 0; i < n; i++) dst[i] = 0;
}

static int in_region(unsigned int p, unsigned int n, unsigned int base,
                     unsigned int size) {
    return p >= base && n <= size && (p - base) <= (size - n);
}

/* Accept only pointers into the module's own static regions, so a bad length
 * or pointer from JS is rejected before any read or write. */
static int valid_span(const void *ptr, unsigned int n) {
    unsigned int p = (unsigned int)(uintptr_t)ptr;
    unsigned int a = (unsigned int)(uintptr_t)buf_a;
    unsigned int b = (unsigned int)(uintptr_t)buf_b;
    unsigned int k = (unsigned int)(uintptr_t)key_buf;
    unsigned int bl = (unsigned int)(uintptr_t)string_blob;
    unsigned int rf = (unsigned int)(uintptr_t)string_refs;
    unsigned int rg = (unsigned int)(uintptr_t)diff_ranges;
    return in_region(p, n, a, WASM_CAP) || in_region(p, n, b, WASM_CAP) ||
           in_region(p, n, k, 16u) || in_region(p, n, bl, WASM_BLOB_CAP) ||
           in_region(p, n, rf, WASM_STRING_MAX * 3u * 4u) ||
           in_region(p, n, rg, WASM_DIFF_MAX * 3u * 4u);
}

/* --- clean-room TEA constants (recovered, not vendor source) ------------- */

static const unsigned char BIT[8] = {
    0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
};
static const unsigned char T_INIT[64] = {
    0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01, 0x3b, 0x33, 0x2b, 0x23, 0x1b, 0x13, 0x0b, 0x03,
    0x3d, 0x35, 0x2d, 0x25, 0x1d, 0x15, 0x0d, 0x05, 0x3f, 0x37, 0x2f, 0x27, 0x1f, 0x17, 0x0f, 0x07,
    0x38, 0x30, 0x28, 0x20, 0x18, 0x10, 0x08, 0x00, 0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02,
    0x3c, 0x34, 0x2c, 0x24, 0x1c, 0x14, 0x0c, 0x04, 0x3e, 0x36, 0x2e, 0x26, 0x1e, 0x16, 0x0e, 0x06
};
static const unsigned char T_FINAL[64] = {
    0x27, 0x07, 0x2f, 0x0f, 0x37, 0x17, 0x3f, 0x1f, 0x26, 0x06, 0x2e, 0x0e, 0x36, 0x16, 0x3e, 0x1e,
    0x25, 0x05, 0x2d, 0x0d, 0x35, 0x15, 0x3d, 0x1d, 0x24, 0x04, 0x2c, 0x0c, 0x34, 0x14, 0x3c, 0x1c,
    0x23, 0x03, 0x2b, 0x0b, 0x33, 0x13, 0x3b, 0x1b, 0x22, 0x02, 0x2a, 0x0a, 0x32, 0x12, 0x3a, 0x1a,
    0x21, 0x01, 0x29, 0x09, 0x31, 0x11, 0x39, 0x19, 0x20, 0x00, 0x28, 0x08, 0x30, 0x10, 0x38, 0x18
};
static const unsigned char T_KEY[56] = {
    0x38, 0x30, 0x28, 0x20, 0x18, 0x10, 0x08, 0x00, 0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01,
    0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02, 0x3b, 0x33, 0x2b, 0x23, 0x3e, 0x36, 0x2e, 0x26,
    0x1e, 0x16, 0x0e, 0x06, 0x3d, 0x35, 0x2d, 0x25, 0x1d, 0x15, 0x0d, 0x05, 0x3c, 0x34, 0x2c, 0x24,
    0x1c, 0x14, 0x0c, 0x04, 0x1b, 0x13, 0x0b, 0x03
};
static const unsigned char T_LEFT[16] = {
    0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01
};
static const unsigned char T_RIGHT[16] = {
    0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01
};
static const unsigned char T_STATE[48] = {
    0x1f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00
};
static const unsigned char T_OUT[48] = {
    0x0d, 0x10, 0x0a, 0x17, 0x00, 0x04, 0x02, 0x1b, 0x0e, 0x05, 0x14, 0x09, 0x16, 0x12, 0x0b, 0x03,
    0x19, 0x07, 0x0f, 0x06, 0x1a, 0x13, 0x0c, 0x01, 0x28, 0x33, 0x1e, 0x24, 0x2e, 0x36, 0x1d, 0x27,
    0x32, 0x2c, 0x20, 0x2f, 0x2b, 0x30, 0x26, 0x37, 0x21, 0x34, 0x2d, 0x29, 0x31, 0x23, 0x1c, 0x1f
};
static const unsigned char T_FEED[32] = {
    0x0f, 0x06, 0x13, 0x14, 0x1c, 0x0b, 0x1b, 0x10, 0x00, 0x0e, 0x16, 0x19, 0x04, 0x11, 0x1e, 0x09,
    0x01, 0x07, 0x17, 0x0d, 0x1f, 0x1a, 0x02, 0x08, 0x12, 0x0c, 0x1d, 0x05, 0x15, 0x0a, 0x03, 0x18
};
static const unsigned char SBOX0[64] = {
    0x0e, 0x04, 0x0d, 0x01, 0x02, 0x0f, 0x0b, 0x08, 0x03, 0x0a, 0x06, 0x0c, 0x05, 0x09, 0x00, 0x07,
    0x00, 0x0f, 0x07, 0x04, 0x0e, 0x02, 0x0d, 0x01, 0x0a, 0x06, 0x0c, 0x0b, 0x09, 0x05, 0x03, 0x08,
    0x04, 0x01, 0x0e, 0x08, 0x0d, 0x06, 0x02, 0x0b, 0x0f, 0x0c, 0x09, 0x07, 0x03, 0x0a, 0x05, 0x00,
    0x0f, 0x0c, 0x08, 0x02, 0x04, 0x09, 0x01, 0x07, 0x05, 0x0b, 0x03, 0x0e, 0x0a, 0x00, 0x06, 0x0d
};
static const unsigned char SBOX1[64] = {
    0x0f, 0x01, 0x08, 0x0e, 0x06, 0x0b, 0x03, 0x04, 0x09, 0x07, 0x02, 0x0d, 0x0c, 0x00, 0x05, 0x0a,
    0x03, 0x0d, 0x04, 0x07, 0x0f, 0x02, 0x08, 0x0e, 0x0c, 0x00, 0x01, 0x0a, 0x06, 0x09, 0x0b, 0x05,
    0x00, 0x0e, 0x07, 0x0b, 0x0a, 0x04, 0x0d, 0x01, 0x05, 0x08, 0x0c, 0x06, 0x09, 0x03, 0x02, 0x0f,
    0x0d, 0x08, 0x0a, 0x01, 0x03, 0x0f, 0x04, 0x02, 0x0b, 0x06, 0x07, 0x0c, 0x00, 0x05, 0x0e, 0x09
};
static const unsigned char SBOX2[64] = {
    0x0a, 0x00, 0x09, 0x0e, 0x06, 0x03, 0x0f, 0x05, 0x01, 0x0d, 0x0c, 0x07, 0x0b, 0x04, 0x02, 0x08,
    0x0d, 0x07, 0x00, 0x09, 0x03, 0x04, 0x06, 0x0a, 0x02, 0x08, 0x05, 0x0e, 0x0c, 0x0b, 0x0f, 0x01,
    0x0d, 0x06, 0x04, 0x09, 0x08, 0x0f, 0x03, 0x00, 0x0b, 0x01, 0x02, 0x0c, 0x05, 0x0a, 0x0e, 0x07,
    0x01, 0x0a, 0x0d, 0x00, 0x06, 0x09, 0x08, 0x07, 0x04, 0x0f, 0x0e, 0x03, 0x0b, 0x05, 0x02, 0x0c
};
static const unsigned char SBOX3[64] = {
    0x07, 0x0d, 0x0e, 0x03, 0x00, 0x06, 0x09, 0x0a, 0x01, 0x02, 0x08, 0x05, 0x0b, 0x0c, 0x04, 0x0f,
    0x0d, 0x08, 0x0b, 0x05, 0x06, 0x0f, 0x00, 0x03, 0x04, 0x07, 0x02, 0x0c, 0x01, 0x0a, 0x0e, 0x09,
    0x0a, 0x06, 0x09, 0x00, 0x0c, 0x0b, 0x07, 0x0d, 0x0f, 0x01, 0x03, 0x0e, 0x05, 0x02, 0x08, 0x04,
    0x03, 0x0f, 0x00, 0x06, 0x0a, 0x01, 0x0d, 0x08, 0x09, 0x04, 0x05, 0x0b, 0x0c, 0x07, 0x02, 0x0e
};
static const unsigned char SBOX4[64] = {
    0x02, 0x0c, 0x04, 0x01, 0x07, 0x0a, 0x0b, 0x06, 0x08, 0x05, 0x03, 0x0f, 0x0d, 0x00, 0x0e, 0x09,
    0x0e, 0x0b, 0x02, 0x0c, 0x04, 0x07, 0x0d, 0x01, 0x05, 0x00, 0x0f, 0x0a, 0x03, 0x09, 0x08, 0x06,
    0x04, 0x02, 0x01, 0x0b, 0x0a, 0x0d, 0x07, 0x08, 0x0f, 0x09, 0x0c, 0x05, 0x06, 0x03, 0x00, 0x0e,
    0x0b, 0x08, 0x0c, 0x07, 0x01, 0x0e, 0x02, 0x0d, 0x06, 0x0f, 0x00, 0x09, 0x0a, 0x04, 0x05, 0x03
};
static const unsigned char SBOX5[64] = {
    0x0c, 0x01, 0x0a, 0x0f, 0x09, 0x02, 0x06, 0x08, 0x00, 0x0d, 0x03, 0x04, 0x0e, 0x07, 0x05, 0x0b,
    0x0a, 0x0f, 0x04, 0x02, 0x07, 0x0c, 0x09, 0x05, 0x06, 0x01, 0x0d, 0x0e, 0x00, 0x0b, 0x03, 0x08,
    0x09, 0x0e, 0x0f, 0x05, 0x02, 0x08, 0x0c, 0x03, 0x07, 0x00, 0x04, 0x0a, 0x01, 0x0d, 0x0b, 0x06,
    0x04, 0x03, 0x02, 0x0c, 0x09, 0x05, 0x0f, 0x0a, 0x0b, 0x0e, 0x01, 0x07, 0x06, 0x00, 0x08, 0x0d
};
static const unsigned char SBOX6[64] = {
    0x04, 0x0b, 0x02, 0x0e, 0x0f, 0x00, 0x08, 0x0d, 0x03, 0x0c, 0x09, 0x07, 0x05, 0x0a, 0x06, 0x01,
    0x0d, 0x00, 0x0b, 0x07, 0x04, 0x09, 0x01, 0x0a, 0x0e, 0x03, 0x05, 0x0c, 0x02, 0x0f, 0x08, 0x06,
    0x01, 0x04, 0x0b, 0x0d, 0x0c, 0x03, 0x07, 0x0e, 0x0a, 0x0f, 0x06, 0x08, 0x00, 0x05, 0x09, 0x02,
    0x06, 0x0b, 0x0d, 0x08, 0x01, 0x04, 0x0a, 0x07, 0x09, 0x05, 0x00, 0x0f, 0x0e, 0x02, 0x03, 0x0c
};
static const unsigned char SBOX7[64] = {
    0x0d, 0x02, 0x08, 0x04, 0x06, 0x0f, 0x0b, 0x01, 0x0a, 0x09, 0x03, 0x0e, 0x05, 0x00, 0x0c, 0x07,
    0x01, 0x0f, 0x0d, 0x08, 0x0a, 0x03, 0x07, 0x04, 0x0c, 0x05, 0x06, 0x0b, 0x00, 0x0e, 0x09, 0x02,
    0x07, 0x0b, 0x04, 0x01, 0x09, 0x0c, 0x0e, 0x02, 0x00, 0x06, 0x0a, 0x0d, 0x0f, 0x03, 0x05, 0x08,
    0x02, 0x01, 0x0e, 0x07, 0x04, 0x0a, 0x08, 0x0d, 0x0f, 0x0c, 0x09, 0x00, 0x03, 0x05, 0x06, 0x0b
};

static const unsigned char *const SBOXES[8] = {
    SBOX0, SBOX1, SBOX2, SBOX3, SBOX4, SBOX5, SBOX6, SBOX7
};

static void perm(int n, const unsigned char *src, const unsigned char *table,
                 unsigned char *dst) {
    int i, j;
    for (i = 0; i < n; i++) {
        unsigned char v = 0;
        for (j = 0; j < 8; j++) {
            unsigned int p = table[i * 8 + j];
            if (src[p >> 3] & BIT[p & 7]) v |= BIT[j];
        }
        dst[i] = v;
    }
}

static void rot_left(unsigned char p[7]) {
    unsigned int carry = p[3] & 0x08;
    int j;
    for (j = 6; j >= 0; j--) {
        unsigned int bit = p[j] & 0x80;
        p[j] = (unsigned char)((p[j] << 1) | (carry ? 1u : 0u));
        carry = bit;
    }
    if (carry) p[3] |= 0x10;
    else p[3] &= (unsigned char)~0x10;
}

static void rot_right(unsigned char p[7]) {
    unsigned int carry = p[3] & 0x10;
    int j;
    for (j = 0; j < 7; j++) {
        unsigned int bit = p[j] & 0x01;
        p[j] = (unsigned char)((p[j] >> 1) | (carry ? 0x80u : 0u));
        carry = bit;
    }
    if (carry) p[3] |= 0x08;
    else p[3] &= (unsigned char)~0x08;
}

static void core(unsigned char *buf, const unsigned char *key, unsigned int flag,
                 unsigned char state[16]) {
    unsigned char a[4], b[4], p[7], feed[4];
    int r, i;

    if (flag & 0x10) perm(8, buf, T_INIT, state);
    bytes_copy(a, state, 4);
    bytes_copy(b, state + 4, 4);
    perm(7, key, T_KEY, p);

    for (r = 0; r < 16; r++) {
        int k, shifts = flag & 0x20 ? T_LEFT[r] : T_RIGHT[r];
        for (k = 0; k < shifts; k++) {
            if (flag & 0x20) rot_left(p); else rot_right(p);
        }

        perm(6, p, T_OUT, buf);
        perm(6, b, T_STATE, state);
        for (i = 0; i < 6; i++) state[i] ^= buf[i];

        {
            int x, out;
            const int pairs[2][2] = {{6, 8}, {3, 4}};
            for (i = 0; i < 2; i++) {
                x = pairs[i][0];
                out = pairs[i][1];
                buf[out - 1] = state[x - 1];
                buf[out - 2] = (unsigned char)(((state[x - 1] >> 6) & 0x03) |
                                               (state[x - 2] << 2));
                buf[out - 3] = (unsigned char)(((state[x - 2] >> 4) & 0x0f) |
                                               (state[x - 3] << 4));
                buf[out - 4] = (unsigned char)((state[x - 3] >> 2) & 0x3f);
            }
        }

        for (i = 0; i < 8; i++) {
            unsigned int t = buf[i] & 0x21;
            if (t & 1) t = (t & 0x20) | 0x10;
            buf[i] = (unsigned char)(t | ((buf[i] >> 1) & 0x0f));
        }
        for (i = 0; i < 8; i++) buf[i] = SBOXES[i][buf[i]];
        for (i = 0; i < 4; i++)
            buf[i] = (unsigned char)((buf[2 * i] << 4) | buf[2 * i + 1]);

        perm(4, buf, T_FEED, feed);
        for (i = 0; i < 4; i++) {
            unsigned char old_a = a[i];
            feed[i] ^= old_a;
            state[i] = feed[i];
            a[i] = b[i];
            b[i] = feed[i];
        }
    }

    for (i = 0; i < 4; i++) {
        state[i] = b[i];
        state[4 + i] = a[i];
    }
    if (flag & 0x40) perm(8, state, T_FINAL, buf);
}

/* --- exported API ------------------------------------------------------- */

int wasm_cap(void) { return (int)WASM_CAP; }
int wasm_blob_cap(void) { return (int)WASM_BLOB_CAP; }
int wasm_string_max(void) { return (int)WASM_STRING_MAX; }
int wasm_diff_max(void) { return (int)WASM_DIFF_MAX; }

unsigned char *wasm_buf_a(void) { return buf_a; }
unsigned char *wasm_buf_b(void) { return buf_b; }
unsigned char *wasm_key(void) { return key_buf; }
unsigned char *wasm_string_blob(void) { return string_blob; }
unsigned char *wasm_string_refs(void) { return (unsigned char *)string_refs; }
unsigned char *wasm_diff_ranges(void) { return (unsigned char *)diff_ranges; }

/* Returns 0 on success, -1 for bad pointers/key, -2 for an over-cap length. */
int tea_encrypt(unsigned char *buf, int len, const unsigned char *key, int keylen) {
    unsigned char state[16];
    unsigned int off, n;
    if (len < 0 || keylen != 16) return -1;
    if ((unsigned int)len > WASM_CAP) return -2;
    n = (unsigned int)len;
    if (!valid_span(buf, n) || !valid_span(key, 16u)) return -1;
    bytes_zero(state, 16);
    for (off = 0; off + 8u <= n; off += 8u) {
        core(buf + off, key, 0x50, state);
        core(buf + off, key + 8, 0x70, state);
        core(buf + off, key, 0x50, state);
    }
    return 0;
}

int tea_decrypt(unsigned char *buf, int len, const unsigned char *key, int keylen) {
    unsigned char state[16];
    unsigned int off, n;
    if (len < 0 || keylen != 16) return -1;
    if ((unsigned int)len > WASM_CAP) return -2;
    n = (unsigned int)len;
    if (!valid_span(buf, n) || !valid_span(key, 16u)) return -1;
    bytes_zero(state, 16);
    for (off = 0; off + 8u <= n; off += 8u) {
        core(buf + off, key, 0x70, state);
        core(buf + off, key + 8, 0x50, state);
        core(buf + off, key, 0x70, state);
    }
    return 0;
}

/* Base-2 log without libm: exactly the approach in cbm_decode.c. */
static double fast_log2(double x) {
    union { double d; uint64_t bits; } v;
    int e;
    double m, t, t2, term, sum;
    unsigned int k;
    if (x <= 0.0) return 0.0;
    v.d = x;
    e = (int)((v.bits >> 52) & 0x7ffu) - 1023;
    v.bits = (v.bits & 0x000fffffffffffffULL) | 0x3ff0000000000000ULL;
    m = v.d;
    t = (m - 1.0) / (m + 1.0);
    t2 = t * t;
    term = t;
    sum = t;
    for (k = 1; k <= 7; k++) {
        term *= t2;
        sum += term / (double)(2 * k + 1);
    }
    return (double)e + 2.88539008177792681472 * sum;
}

/* Shannon entropy in bits/byte; -1.0 on invalid input. */
double entropy_estimate(const unsigned char *buf, int len) {
    unsigned int counts[256];
    unsigned int i, n;
    double entropy = 0.0;
    if (len < 0) return -1.0;
    if ((unsigned int)len > WASM_CAP) return -1.0;
    n = (unsigned int)len;
    if (n != 0 && !valid_span(buf, n)) return -1.0;
    for (i = 0; i < 256; i++) counts[i] = 0;
    for (i = 0; i < n; i++) counts[buf[i]]++;
    for (i = 0; i < 256; i++) {
        double p;
        if (counts[i] == 0) continue;
        p = (double)counts[i] / (double)n;
        entropy -= p * fast_log2(p);
    }
    return entropy;
}

static int printable(unsigned char c) { return c >= 0x20 && c <= 0x7e; }

/* Writes (source_offset,blob_offset,length) triples into refs and text into
 * blob. Returns the number of runs, -1 for invalid arguments, -2 for an
 * over-cap input, or -3 when the output blob/ref array is too small (nothing
 * is written). */
int scan_strings(const unsigned char *buf, int len, unsigned char *blob,
                 int blob_cap, unsigned char *refs, int max_refs) {
    unsigned int i, n, bc, mr, used = 0, count = 0;
    if (len < 0 || blob_cap < 0 || max_refs < 0) return -1;
    if ((unsigned int)len > WASM_CAP) return -2;
    n = (unsigned int)len;
    bc = (unsigned int)blob_cap;
    mr = (unsigned int)max_refs;
    if (bc > WASM_BLOB_CAP) bc = WASM_BLOB_CAP;
    if (mr > WASM_STRING_MAX) mr = WASM_STRING_MAX;
    if (n != 0 && !valid_span(buf, n)) return -1;
    if (bc != 0 && !valid_span(blob, bc)) return -1;
    if (mr != 0 && !valid_span(refs, mr * 3u * 4u)) return -1;

    for (i = 0; i < n;) {
        unsigned int start, run;
        if (!printable(buf[i])) { i++; continue; }
        start = i;
        while (i < n && printable(buf[i])) i++;
        run = i - start;
        if (run < WASM_STRING_MIN) continue;
        if (run > WASM_STRING_TRUNC) run = WASM_STRING_TRUNC;
        if (count >= mr || used + run > bc) return -3;
        bytes_copy(blob + used, buf + start, run);
        {
            uint32_t *out = (uint32_t *)(void *)refs;
            out[count * 3u] = (uint32_t)start;
            out[count * 3u + 1u] = (uint32_t)used;
            out[count * 3u + 2u] = (uint32_t)run;
        }
        used += run;
        count++;
    }
    return (int)count;
}

static void add_span(uint32_t *out, unsigned int *written, unsigned int max,
                     unsigned int offset, unsigned int length,
                     unsigned int changed) {
    if (*written > 0) {
        uint32_t *prev = out + (*written - 1u) * 3u;
        unsigned int prev_end = prev[0] + prev[1];
        unsigned int gap = offset >= prev_end ? offset - prev_end : 0u;
        if (gap <= 0u) { /* context 0: merge touching and overlapping spans */
            unsigned int end = offset + length;
            if (end > prev_end) prev[1] += end - prev_end;
            prev[2] += changed;
            return;
        }
    }
    if (*written < max) {
        uint32_t *dst = out + (*written) * 3u;
        dst[0] = (uint32_t)offset;
        dst[1] = (uint32_t)length;
        dst[2] = (uint32_t)changed;
        (*written)++;
    }
}

/* Two-body byte diff with context 0, matching cbm_diff_ranges(..., 0, ...).
 * Writes (offset,length,changed) triples; returns the number written (capped
 * at max_ranges), -1 for invalid pointers, -2 for an over-cap length. */
int diff_two(const unsigned char *a, int alen, const unsigned char *b,
             int blen, unsigned char *out, int max_ranges) {
    unsigned int na, nb, common, i, written = 0, max;
    uint32_t *ranges = (uint32_t *)(void *)out;
    if (alen < 0 || blen < 0 || max_ranges < 0) return -1;
    if ((unsigned int)alen > WASM_CAP || (unsigned int)blen > WASM_CAP) return -2;
    na = (unsigned int)alen;
    nb = (unsigned int)blen;
    if ((na != 0 && !valid_span(a, na)) || (nb != 0 && !valid_span(b, nb)))
        return -1;
    if (max_ranges == 0) return 0;
    max = (unsigned int)max_ranges;
    if (max > WASM_DIFF_MAX) max = WASM_DIFF_MAX;
    if (!valid_span(out, max * 3u * 4u)) return -1;
    common = na < nb ? na : nb;
    for (i = 0; i < common; i++) {
        if (a[i] != b[i]) add_span(ranges, &written, max, i, 1u, 1u);
    }
    if (na != nb) {
        unsigned int start = common;
        unsigned int length = na > nb ? na - nb : nb - na;
        add_span(ranges, &written, max, start, length, length);
    }
    return (int)written;
}
