/* recon.h - read-only heuristic block-cipher function finder for PE32 files
 *
 * Wave 5M. This is a candidate generator, not a disassembler or a proof of
 * cryptography: see docs/universal-re.md for the scoring table and the
 * honest-limits section. No vendor path is compiled in; callers pass a path.
 */
#ifndef RECON_H
#define RECON_H

#include <stdint.h>
#include <stdio.h>

#define RECON_MAX_CANDIDATES 512u
#define RECON_MAX_ERROR 160u

typedef struct {
    uint32_t rva;
    uint32_t va;
    uint32_t size;
    uint32_t score;
    uint32_t byte_xor;   /* raw count of 0x30 / 0x32 bytes */
    uint32_t dword_xor;  /* raw count of 0x31 / 0x33 bytes */
    uint32_t shifts;     /* raw count of C1 /4 and C1 /5 encodings */
    uint32_t calls;      /* raw count of E8 rel32 opcodes */
    int delta_tea;       /* imm32 0x9E3779B9 present */
    int delta_alt;       /* imm32 0x61C88647 present */
    int calls_delta;     /* calls a delta-bearing function */
    int repeated_call;   /* one call target occurs >= 3 times */
} recon_candidate_t;

typedef struct {
    uint32_t image_base;
    uint32_t size_of_image;
    uint16_t sections;
    uint32_t functions_scanned;
    uint32_t total_candidates; /* all functions above threshold, not just stored */
    recon_candidate_t candidates[RECON_MAX_CANDIDATES];
    uint32_t stored;
    char error[RECON_MAX_ERROR];
} recon_report_t;

/* 0 = ok, -1 = error with out->error filled. out must be non-NULL. */
int recon_file(const char *path, recon_report_t *out);

/* CLI entry point used by main.c. Writes prose to out, diagnostics to err
 * and, when json is non-NULL, one cbm/1 document to json. Returns 0 ok,
 * 1 runtime error, 2 usage or input error. */
int recon_cli_ex(int argc, char **argv, FILE *out, FILE *err, FILE *json);

#endif /* RECON_H */
