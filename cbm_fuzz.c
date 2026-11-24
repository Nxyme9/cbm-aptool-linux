/* cbm_fuzz.c - deterministic offline fuzz corpus lab implementation */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cbm_container.h"
#include "cbm_file.h"
#include "cbm_fuzz.h"
#include "tea_crypto.h"

/* Published RE artifact, intentionally allowlisted in .gitleaks.toml. */
const char cbm_fuzz_tea_key[] = "1a2b3c4d5e6fTENG";

#define CBM_FUZZ_PATH_MAX 4096

/* ---- error reporting --------------------------------------------------- */

static int failf(char *err, size_t errlen, const char *fmt, ...) {
    if (err && errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* ---- SHA-256 (self-contained; no libcrypto dependency) ----------------- */

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    unsigned char block[64];
    size_t used;
} sha256_ctx_t;

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t ror32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

static void sha256_transform(sha256_ctx_t *c, const unsigned char *block) {
    uint32_t w[64];
    for (unsigned i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               (uint32_t)block[i * 4 + 3];
    }
    for (unsigned i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (unsigned i = 0; i < 64; i++) {
        uint32_t s1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + SHA256_K[i] + w[i];
        uint32_t s0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(sha256_ctx_t *c) {
    static const uint32_t init[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    memcpy(c->h, init, sizeof(init));
    c->bits = 0;
    c->used = 0;
}

static void sha256_update(sha256_ctx_t *c, const unsigned char *data, size_t len) {
    c->bits += (uint64_t)len * 8u;
    while (len > 0) {
        size_t room = 64u - c->used;
        size_t take = (len < room) ? len : room;
        memcpy(c->block + c->used, data, take);
        c->used += take;
        data += take;
        len -= take;
        if (c->used == 64u) {
            sha256_transform(c, c->block);
            c->used = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *c, unsigned char out[32]) {
    uint64_t total = c->bits;
    c->block[c->used++] = 0x80u;
    if (c->used > 56u) {
        memset(c->block + c->used, 0, 64u - c->used);
        sha256_transform(c, c->block);
        c->used = 0;
    }
    memset(c->block + c->used, 0, 56u - c->used);
    for (unsigned i = 0; i < 8; i++) {
        c->block[56u + i] = (unsigned char)(total >> (56u - i * 8u));
    }
    sha256_transform(c, c->block);
    for (unsigned i = 0; i < 8; i++) {
        out[i * 4u]     = (unsigned char)(c->h[i] >> 24);
        out[i * 4u + 1u] = (unsigned char)(c->h[i] >> 16);
        out[i * 4u + 2u] = (unsigned char)(c->h[i] >> 8);
        out[i * 4u + 3u] = (unsigned char)c->h[i];
    }
}

void cbm_fuzz_sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    if (data && len) sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

static void digest_hex(const unsigned char digest[32], char out[65]) {
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        out[i * 2u]     = digits[digest[i] >> 4];
        out[i * 2u + 1u] = digits[digest[i] & 0x0fu];
    }
    out[64] = '\0';
}

/* ---- deterministic mutation stream ------------------------------------ */

static uint64_t fuzz_next(uint64_t *state) {
    /* xorshift64* (Marsaglia); no time(), rand() or address dependence. */
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

static uint64_t round_state(unsigned long seed, unsigned round) {
    uint64_t s = (uint64_t)seed ^ ((uint64_t)round * 0x9e3779b97f4a7c15ULL);
    /* splitmix64 finalizer gives every round an independent-looking stream. */
    s ^= s >> 30;
    s *= 0xbf58476d1ce4e5b9ULL;
    s ^= s >> 27;
    s *= 0x94d049bb133111ebULL;
    s ^= s >> 31;
    return s ? s : 0x9e3779b97f4a7c15ULL;
}

static void mutation_at(uint64_t *state, size_t len,
                        size_t *offset, unsigned char *delta) {
    uint64_t r_offset = fuzz_next(state);
    uint64_t r_delta = fuzz_next(state);
    *offset = (size_t)(r_offset % (uint64_t)len);
    /* 1..255 keeps every recorded mutation an actual byte change. */
    *delta = (unsigned char)((r_delta >> 33) % 255u + 1u);
}

void cbm_fuzz_mutate_body(unsigned char *body, size_t len, unsigned mutate,
                          unsigned long seed, unsigned round) {
    if (!body || len == 0) return;
    uint64_t state = round_state(seed, round);
    for (unsigned i = 0; i < mutate; i++) {
        size_t offset;
        unsigned char delta;
        mutation_at(&state, len, &offset, &delta);
        body[offset] ^= delta;
    }
}

/* ---- manifest buffer --------------------------------------------------- */

static int append_text(char **buf, size_t *len, size_t *cap,
                       const char *text, size_t n) {
    if (*len + n + 1u > *cap) {
        size_t next = *cap ? *cap : 4096u;
        while (next < *len + n + 1u) next *= 2u;
        char *grown = (char *)realloc(*buf, next);
        if (!grown) return -1;
        *buf = grown;
        *cap = next;
    }
    memcpy(*buf + *len, text, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

static int appendf(char **buf, size_t *len, size_t *cap,
                   const char *fmt, ...) {
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return -1;
    return append_text(buf, len, cap, tmp, (size_t)n);
}

/* ---- path safety ------------------------------------------------------- */

static int aliases_source(const char *path, const char *src_real) {
    char resolved[CBM_FUZZ_PATH_MAX];
    if (realpath(path, resolved) && strcmp(resolved, src_real) == 0) return 1;
    return 0;
}

static int write_corpus(const char *path, const unsigned char *header,
                        const unsigned char *cipher, size_t body_len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t h = fwrite(header, 1, CBM_HEADER_SIZE, f);
    size_t b = fwrite(cipher, 1, body_len, f);
    int rc = (h == CBM_HEADER_SIZE && b == body_len && fflush(f) == 0) ? 0 : -1;
    if (fclose(f) != 0) rc = -1;
    return rc;
}

/* ---- public API -------------------------------------------------------- */

int cbm_fuzz_run(const char *container_path, const char *out_dir,
                 unsigned mutate, unsigned rounds, unsigned long seed,
                 char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    if (!container_path || !container_path[0] || !out_dir || !out_dir[0]) {
        return failf(err, errlen, "source and --out are both required");
    }
    if (cbm_file_is_blockdev(container_path)) {
        return failf(err, errlen, "source is a block device: refusing (fuzz never writes to devices)");
    }
    if (cbm_file_is_blockdev(out_dir)) {
        return failf(err, errlen, "--out must not be a block device");
    }

    struct stat st;
    if (stat(out_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return failf(err, errlen, "--out must be an existing directory: '%s'", out_dir);
    }
    if (stat(container_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return failf(err, errlen, "source must be a regular file: '%s'", container_path);
    }
    if (st.st_size != (off_t)CBM_CONTAINER_SIZE) {
        return failf(err, errlen, "source must be exactly %d bytes (got %lld)",
                     CBM_CONTAINER_SIZE, (long long)st.st_size);
    }

    char src_real[CBM_FUZZ_PATH_MAX], out_real[CBM_FUZZ_PATH_MAX];
    char src_dir[CBM_FUZZ_PATH_MAX];
    if (!realpath(container_path, src_real) || !realpath(out_dir, out_real)) {
        return failf(err, errlen, "cannot resolve source or --out to an absolute path");
    }
    const char *slash = strrchr(src_real, '/');
    if (!slash) {
        snprintf(src_dir, sizeof(src_dir), ".");
    } else if (slash == src_real) {
        snprintf(src_dir, sizeof(src_dir), "/");
    } else {
        size_t n = (size_t)(slash - src_real);
        if (n >= sizeof(src_dir)) n = sizeof(src_dir) - 1u;
        memcpy(src_dir, src_real, n);
        src_dir[n] = '\0';
    }
    if (strcmp(out_real, src_real) == 0 || strcmp(out_real, src_dir) == 0) {
        return failf(err, errlen, "--out must not be the source path or its directory");
    }

    const size_t body_len = cbm_compute_hlen(CBM_CONTAINER_SIZE);
    if (body_len != (size_t)(CBM_CONTAINER_SIZE - CBM_HEADER_SIZE) || body_len == 0) {
        return failf(err, errlen, "unexpected container body length %zu", body_len);
    }
    if (tea_init(NULL) != 0) {
        return failf(err, errlen, "native crypto init failed");
    }

    int rc = -1;
    unsigned char *orig = (unsigned char *)malloc(CBM_CONTAINER_SIZE);
    unsigned char *base_plain = (unsigned char *)malloc(body_len);
    unsigned char *mutated = (unsigned char *)malloc(body_len);
    unsigned char *cipher = (unsigned char *)malloc(body_len);
    unsigned char *check = (unsigned char *)malloc(body_len);
    char *manifest = NULL;
    char *round_path = NULL;
    char *manifest_path = NULL;
    size_t manifest_len = 0, manifest_cap = 0;

    if (!orig || !base_plain || !mutated || !cipher || !check) {
        failf(err, errlen, "out of memory");
        goto out;
    }
    if (cbm_file_read(src_real, 0, orig, CBM_CONTAINER_SIZE) != 0) {
        failf(err, errlen, "failed to read %d bytes from source", CBM_CONTAINER_SIZE);
        goto out;
    }
    memcpy(base_plain, orig + CBM_HEADER_SIZE, body_len);
    if (cbm_cbc_decrypt(base_plain, body_len, cbm_fuzz_tea_key) != 0) {
        failf(err, errlen, "TEA decryption of container body failed");
        goto out;
    }

    unsigned char source_digest[32];
    char source_hex[65];
    cbm_fuzz_sha256(orig, CBM_CONTAINER_SIZE, source_digest);
    digest_hex(source_digest, source_hex);
    if (appendf(&manifest, &manifest_len, &manifest_cap,
                "cbm_fuzz manifest v1\nseed %lu\nmutate %u\nrounds %u\n"
                "body_len %zu\ncontainer_sha256 %s\n",
                seed, mutate, rounds, body_len, source_hex) != 0) {
        failf(err, errlen, "cannot build manifest");
        goto out;
    }

    for (unsigned round = 1; round <= rounds; round++) {
        char name[64];
        snprintf(name, sizeof(name), "round-%03u.cbm", round);
        free(round_path);
        round_path = NULL;
        if (asprintf(&round_path, "%s/%s", out_real, name) < 0) {
            failf(err, errlen, "cannot build round %u output path", round);
            goto out;
        }
        if (aliases_source(round_path, src_real)) {
            failf(err, errlen, "--out file resolves to the source container");
            goto out;
        }

        memcpy(mutated, base_plain, body_len);
        cbm_fuzz_mutate_body(mutated, body_len, mutate, seed, round);

        memcpy(cipher, mutated, body_len);
        if (cbm_cbc_encrypt(cipher, body_len, cbm_fuzz_tea_key) != 0) {
            failf(err, errlen, "TEA encryption failed in round %u", round);
            goto out;
        }
        /* Identity proof before touching the filesystem. */
        memcpy(check, cipher, body_len);
        if (cbm_cbc_decrypt(check, body_len, cbm_fuzz_tea_key) != 0 ||
            memcmp(check, mutated, body_len) != 0) {
            failf(err, errlen, "roundtrip identity failed in round %u", round);
            goto out;
        }
        if (write_corpus(round_path, orig, cipher, body_len) != 0) {
            failf(err, errlen, "failed to write '%s'", round_path);
            goto out;
        }

        unsigned char corpus_digest[32];
        char corpus_hex[65];
        unsigned char whole[CBM_CONTAINER_SIZE];
        memcpy(whole, orig, CBM_HEADER_SIZE);
        memcpy(whole + CBM_HEADER_SIZE, cipher, body_len);
        cbm_fuzz_sha256(whole, CBM_CONTAINER_SIZE, corpus_digest);
        digest_hex(corpus_digest, corpus_hex);
        if (appendf(&manifest, &manifest_len, &manifest_cap,
                    "round %03u %s %u %s mutations ", round, name,
                    CBM_CONTAINER_SIZE, corpus_hex) != 0) {
            failf(err, errlen, "cannot build manifest");
            goto out;
        }
        uint64_t state = round_state(seed, round);
        for (unsigned i = 0; i < mutate; i++) {
            size_t offset;
            unsigned char delta;
            mutation_at(&state, body_len, &offset, &delta);
            if (appendf(&manifest, &manifest_len, &manifest_cap, "%s%zu:%02x",
                        i ? "," : "", offset, (unsigned)delta) != 0) {
                failf(err, errlen, "cannot build manifest mutation list");
                goto out;
            }
        }
        if (append_text(&manifest, &manifest_len, &manifest_cap, "\n", 1u) != 0) {
            failf(err, errlen, "cannot finish manifest round");
            goto out;
        }
    }

    if (asprintf(&manifest_path, "%s/manifest.txt", out_real) < 0) {
        failf(err, errlen, "cannot build manifest output path");
        goto out;
    }
    if (aliases_source(manifest_path, src_real)) {
        failf(err, errlen, "--out manifest resolves to the source container");
        goto out;
    }
    FILE *mf = fopen(manifest_path, "wb");
    if (!mf) {
        failf(err, errlen, "cannot open '%s' for writing", manifest_path);
        goto out;
    }
    size_t put = manifest_len ? fwrite(manifest, 1, manifest_len, mf) : 0;
    int write_err = (put != manifest_len || fflush(mf) != 0);
    if (fclose(mf) != 0) write_err = 1;
    if (write_err) {
        failf(err, errlen, "failed to write '%s'", manifest_path);
        goto out;
    }
    rc = 0;
out:
    free(orig);
    free(base_plain);
    free(mutated);
    free(cipher);
    free(check);
    free(manifest);
    free(round_path);
    free(manifest_path);
    return rc;
}
