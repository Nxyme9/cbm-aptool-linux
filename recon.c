/* recon.c - read-only, bounded PE32 reader + candidate block-fn scorer
 *
 * Wave 5M. The scanner is deliberately simple: it builds a bounded virtual
 * image, takes 55 8b ec prologues in the first executable section as function
 * starts, and scores raw opcode/constant patterns. It does not decode x86
 * instructions or execute anything from the PE. See docs/universal-re.md.
 *
 * The CLI wrapper (recon_cli_ex) lives in main.c so the JSON document is
 * emitted through cli_json.h without forcing the unit test to link it.
 */
#include "recon.h"

#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define RECON_MAX_FILE_BYTES (64u * 1024u * 1024u)
#define RECON_MAX_IMAGE_BYTES (256u * 1024u * 1024u)
#define RECON_BODY_CAP 8192u
#define RECON_MAX_FUNCS 16384u
#define RECON_MAX_CALL_SLOTS 2048u
#define RECON_SCORE_MIN 20u

static void recon_set_error(recon_report_t *out, const char *msg) {
    if (!out || out->error[0]) return;
    if (!msg || !*msg) msg = "unspecified recon error";
    (void)snprintf(out->error, sizeof(out->error), "%s", msg);
}

static uint16_t rd16(const unsigned char *p) {
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Read a whole regular file with a hard size cap. No device, symlink target
 * resolution or directory traversal is performed beyond what fopen does. */
static int read_bounded_file(const char *path, unsigned char **data,
                             uint64_t *len, recon_report_t *out) {
    FILE *f = NULL;
    struct stat st;
    unsigned char *buf = NULL;

    if (!path || !*path) { recon_set_error(out, "recon: empty path"); return -1; }
    f = fopen(path, "rb");
    if (!f) { recon_set_error(out, "recon: cannot open file"); return -1; }
    if (fstat(fileno(f), &st) != 0) {
        recon_set_error(out, "recon: cannot stat file");
        (void)fclose(f);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        recon_set_error(out, "recon: not a regular file");
        (void)fclose(f);
        return -1;
    }
    if (st.st_size <= 0) {
        recon_set_error(out, "recon: empty file");
        (void)fclose(f);
        return -1;
    }
    if ((uint64_t)st.st_size > (uint64_t)RECON_MAX_FILE_BYTES) {
        recon_set_error(out, "recon: file exceeds 64 MiB cap");
        (void)fclose(f);
        return -1;
    }
    buf = (unsigned char *)malloc((size_t)st.st_size);
    if (!buf) {
        recon_set_error(out, "recon: out of memory reading file");
        (void)fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
        recon_set_error(out, "recon: short read");
        free(buf);
        (void)fclose(f);
        return -1;
    }
    (void)fclose(f);
    *data = buf;
    *len = (uint64_t)st.st_size;
    return 0;
}

typedef struct {
    uint32_t rva;
    uint32_t size;
    uint32_t byte_xor;
    uint32_t dword_xor;
    uint32_t shifts;
    uint32_t calls;
    uint32_t stack_frame;
    uint32_t delta_tea;
    uint32_t delta_alt;
    uint32_t repeated_call;
    uint32_t calls_delta;
    uint32_t score;
} recon_func_t;

typedef struct {
    uint32_t target;
    uint32_t count;
} recon_call_slot_t;

/* Raw-pattern features for one bounded function body. `func_rva` is the RVA
 * of byte 0 so E8 rel32 targets can be resolved to RVAs. */
static void scan_function(const unsigned char *code, uint32_t len,
                          uint32_t func_rva, recon_func_t *f) {
    recon_call_slot_t slots[RECON_MAX_CALL_SLOTS];
    uint32_t nslots = 0u;
    uint32_t i;

    memset(f, 0, sizeof(*f));
    f->rva = func_rva;
    f->size = len;
    for (i = 0u; i < len; i++) {
        unsigned char op = code[i];
        if (op == 0x30u || op == 0x32u) f->byte_xor++;
        else if (op == 0x31u || op == 0x33u) f->dword_xor++;
        if (i + 1u < len && op == 0xC1u) {
            unsigned char modreg = code[i + 1u];
            if ((modreg & 0x38u) == 0x20u || (modreg & 0x38u) == 0x28u)
                f->shifts++;
        }
        if (i + 2u < len && op == 0x83u && code[i + 1u] == 0xECu)
            f->stack_frame = 1u;
        if (i + 4u < len &&
            (rd32(code + i) == 0x9E3779B9u || rd32(code + i) == 0x61C88647u)) {
            if (rd32(code + i) == 0x9E3779B9u) f->delta_tea = 1u;
            else f->delta_alt = 1u;
        }
        if (op == 0xE8u) {
            int32_t rel = (int32_t)rd32(code + i + 1u);
            int64_t target = (int64_t)func_rva + (int64_t)i + 5 + (int64_t)rel;
            uint32_t k;
            f->calls++;
            if (target < 0 || target > (int64_t)UINT32_MAX) continue;
            for (k = 0u; k < nslots; k++)
                if (slots[k].target == (uint32_t)target) break;
            if (k == nslots) {
                if (nslots >= RECON_MAX_CALL_SLOTS) continue;
                slots[nslots].target = (uint32_t)target;
                slots[nslots].count = 1u;
                nslots++;
            } else if (++slots[k].count >= 3u) {
                f->repeated_call = 1u;
            }
        }
    }
}

static uint32_t score_function(const recon_func_t *f) {
    uint32_t score = 0u;
    uint32_t bx = f->byte_xor > 5u ? 5u : f->byte_xor;
    uint32_t dx = f->dword_xor > 6u ? 6u : f->dword_xor;
    uint32_t sh = f->shifts > 6u ? 6u : f->shifts;

    if (f->delta_tea) score += 40u;
    if (f->delta_alt) score += 25u;
    score += bx * 4u;
    score += dx * 2u;
    score += sh * 3u;
    if (f->calls_delta) score += 35u;
    if (f->repeated_call) score += 8u;
    if (f->stack_frame) score += 3u;
    if (f->size >= 64u && f->size <= 4096u) score += 5u;
    return score;
}

static int candidate_cmp(const void *a, const void *b) {
    const recon_candidate_t *ca = (const recon_candidate_t *)a;
    const recon_candidate_t *cb = (const recon_candidate_t *)b;
    if (ca->score != cb->score) return ca->score > cb->score ? -1 : 1;
    if (ca->rva != cb->rva) return ca->rva < cb->rva ? -1 : 1;
    return 0;
}

int recon_file(const char *path, recon_report_t *out) {
    unsigned char *file = NULL;
    unsigned char *image = NULL;
    recon_func_t *funcs = NULL;
    recon_candidate_t *above = NULL;
    uint32_t *delta_rvas = NULL;
    uint64_t file_len = 0u;
    uint32_t peoff, optsz, nsections, magic, opt, sect, i;
    uint32_t image_base = 0u, image_size = 0u;
    uint32_t exec_rva = 0u, exec_size = 0u;
    int have_exec = 0;
    uint32_t nfuncs = 0u, nfeat = 0u, ndelta = 0u, nabove = 0u;
    uint32_t prev = 0u, have_prev = 0u;
    int rc = -1;

    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (read_bounded_file(path, &file, &file_len, out) != 0) goto done;
    if (file_len < 0x40u) { recon_set_error(out, "recon: file too small for DOS header"); goto done; }
    if (file[0] != 'M' || file[1] != 'Z') {
        recon_set_error(out, "recon: missing MZ signature"); goto done;
    }
    peoff = rd32(file + 0x3cu);
    if ((uint64_t)peoff + 24u > file_len) {
        recon_set_error(out, "recon: e_lfanew out of range"); goto done;
    }
    if (memcmp(file + peoff, "PE\0\0", 4) != 0) {
        recon_set_error(out, "recon: missing PE\\0\\0 signature"); goto done;
    }
    nsections = rd16(file + peoff + 6u);
    optsz = rd16(file + peoff + 20u);
    if (optsz < 96u || (uint64_t)peoff + 24u + optsz > file_len) {
        recon_set_error(out, "recon: optional header out of range"); goto done;
    }
    opt = peoff + 24u;
    magic = rd16(file + opt);
    /* PE32+ uses the same section-table math; its 64-bit ImageBase lives at
     * opt+24, so its low 32 bits are reported here. */
    if (magic == 0x10bu) image_base = rd32(file + opt + 28u);
    else if (magic == 0x20bu) image_base = rd32(file + opt + 24u);
    else { recon_set_error(out, "recon: unsupported optional-header magic"); goto done; }
    image_size = rd32(file + opt + 56u);
    if (image_size < 0x1000u || image_size > RECON_MAX_IMAGE_BYTES) {
        recon_set_error(out, "recon: SizeOfImage out of range"); goto done;
    }
    if (nsections == 0u) { recon_set_error(out, "recon: no sections"); goto done; }
    sect = opt + optsz;
    if ((uint64_t)sect + (uint64_t)nsections * 40u > file_len) {
        recon_set_error(out, "recon: section table out of range"); goto done;
    }
    out->image_base = image_base;
    out->size_of_image = image_size;
    out->sections = (uint16_t)nsections;

    image = (unsigned char *)calloc(image_size, 1u);
    if (!image) { recon_set_error(out, "recon: out of memory for virtual image"); goto done; }

    for (i = 0u; i < nsections; i++) {
        const unsigned char *sh = file + sect + (uint32_t)i * 40u;
        uint32_t vsize = rd32(sh + 8u);
        uint32_t va = rd32(sh + 12u);
        uint32_t rawsz = rd32(sh + 16u);
        uint32_t rawptr = rd32(sh + 20u);
        uint32_t chars = rd32(sh + 36u);
        uint64_t copy;

        if (rawsz != 0u) {
            if ((uint64_t)rawptr + rawsz > file_len) {
                recon_set_error(out, "recon: section raw data beyond file"); goto done;
            }
            copy = rawsz;
            if ((uint64_t)va >= (uint64_t)image_size) copy = 0u;
            else if (copy > (uint64_t)image_size - va) copy = (uint64_t)image_size - va;
            if (copy != 0u) memcpy(image + va, file + rawptr, (size_t)copy);
        }
        if (!have_exec && (chars & 0x20000000u) != 0u) {
            uint64_t span = vsize ? (uint64_t)vsize : (uint64_t)rawsz;
            have_exec = 1;
            exec_rva = va;
            if ((uint64_t)va >= (uint64_t)image_size) span = 0u;
            else if (span > (uint64_t)image_size - va) span = (uint64_t)image_size - va;
            exec_size = (uint32_t)span;
        }
    }
    if (!have_exec || exec_size < 3u) {
        recon_set_error(out, "recon: no executable section with code"); goto done;
    }

    funcs = (recon_func_t *)calloc(RECON_MAX_FUNCS, sizeof(*funcs));
    delta_rvas = (uint32_t *)calloc(RECON_MAX_FUNCS, sizeof(*delta_rvas));
    if (!funcs || !delta_rvas) {
        recon_set_error(out, "recon: out of memory for function table"); goto done;
    }

    /* Function boundaries: 55 8b ec prologue to the next prologue or to the
     * end of the executable section, clamped to RECON_BODY_CAP. */
    for (i = 0u; i + 2u < exec_size; i++) {
        uint32_t start;
        uint32_t end;
        uint32_t len;
        uint32_t rva = exec_rva + i;
        if (image[rva] != 0x55u || image[rva + 1u] != 0x8Bu ||
            image[rva + 2u] != 0xECu) continue;
        nfuncs++;
        if (have_prev) {
            start = prev;
            end = rva;
            len = (end - start) > RECON_BODY_CAP ? RECON_BODY_CAP : end - start;
            if (nfeat < RECON_MAX_FUNCS) {
                scan_function(image + start, len, start, &funcs[nfeat]);
                nfeat++;
            }
        }
        prev = rva;
        have_prev = 1;
    }
    if (have_prev) {
        uint32_t start = prev;
        uint32_t end = exec_rva + exec_size;
        uint32_t len = (end - start) > RECON_BODY_CAP ? RECON_BODY_CAP : end - start;
        if (nfeat < RECON_MAX_FUNCS) {
            scan_function(image + start, len, start, &funcs[nfeat]);
            nfeat++;
        }
    }
    out->functions_scanned = nfuncs;

    for (i = 0u; i < nfeat; i++) {
        if ((funcs[i].delta_tea || funcs[i].delta_alt) &&
            ndelta < RECON_MAX_FUNCS) delta_rvas[ndelta++] = funcs[i].rva;
    }
    /* A call to any delta-bearing function is only known after the first
     * pass, so resolve E8 targets here. */
    for (i = 0u; i < nfeat; i++) {
        uint32_t j;
        uint32_t len = funcs[i].size;
        const unsigned char *code = image + funcs[i].rva;
        for (j = 0u; j + 4u < len; j++) {
            int32_t rel;
            int64_t target;
            uint32_t k;
            if (code[j] != 0xE8u) continue;
            rel = (int32_t)rd32(code + j + 1u);
            target = (int64_t)funcs[i].rva + (int64_t)j + 5 + (int64_t)rel;
            if (target < 0 || target > (int64_t)UINT32_MAX) continue;
            for (k = 0u; k < ndelta; k++) {
                if (delta_rvas[k] == (uint32_t)target) {
                    funcs[i].calls_delta = 1u;
                    break;
                }
            }
            if (funcs[i].calls_delta) break;
        }
    }

    above = (recon_candidate_t *)calloc(nfeat ? nfeat : 1u, sizeof(*above));
    if (!above) { recon_set_error(out, "recon: out of memory for candidates"); goto done; }
    for (i = 0u; i < nfeat; i++) {
        recon_candidate_t *c;
        uint32_t score = score_function(&funcs[i]);
        funcs[i].score = score;
        if (score < RECON_SCORE_MIN) continue;
        c = &above[nabove++];
        c->rva = funcs[i].rva;
        c->va = out->image_base + funcs[i].rva;
        c->size = funcs[i].size;
        c->score = score;
        c->byte_xor = funcs[i].byte_xor;
        c->dword_xor = funcs[i].dword_xor;
        c->shifts = funcs[i].shifts;
        c->calls = funcs[i].calls;
        c->delta_tea = funcs[i].delta_tea ? 1 : 0;
        c->delta_alt = funcs[i].delta_alt ? 1 : 0;
        c->calls_delta = funcs[i].calls_delta ? 1 : 0;
        c->repeated_call = funcs[i].repeated_call ? 1 : 0;
    }
    out->total_candidates = nabove;
    qsort(above, nabove, sizeof(*above), candidate_cmp);
    out->stored = nabove > RECON_MAX_CANDIDATES ? RECON_MAX_CANDIDATES : nabove;
    for (i = 0u; i < out->stored; i++) out->candidates[i] = above[i];
    rc = 0;

done:
    free(above);
    free(delta_rvas);
    free(funcs);
    free(image);
    free(file);
    if (rc != 0 && !out->error[0])
        recon_set_error(out, "recon: no executable section found");
    return rc;
}
