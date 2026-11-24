/* cbm_fuzz.h - deterministic, offline fuzz corpus lab for CBM containers
 *
 * The lab never touches a device and never writes to the source container.
 * Corpus names, bytes and manifest text are a pure function of the inputs,
 * making two runs with the same seed/mutate/rounds byte-identical.
 */
#ifndef CBM_FUZZ_H
#define CBM_FUZZ_H

#include <stddef.h>

/* Published reverse-engineering artifact (allowlisted in .gitleaks.toml),
 * shared with the container CLI so fuzz and container modes use one cipher. */
extern const char cbm_fuzz_tea_key[];

/* Load one exact-size container, decrypt its body, then write `rounds`
 * deterministic mutated containers plus manifest.txt into `out_dir`.
 *
 * Returns 0 on success, -1 on any error (message copied to err when err and
 * errlen are non-zero). Refuses block-device sources, missing/aliasing --out,
 * wrong source sizes and any output path that resolves back to the source.
 * Writes only <out>/round-NNN.cbm and <out>/manifest.txt via stdio.
 * Crypto must be initialised by the caller (tea_init); this function does not
 * call tea_cleanup. */
int cbm_fuzz_run(const char *container_path, const char *out_dir,
                 unsigned mutate, unsigned rounds, unsigned long seed,
                 char *err, size_t errlen);

/* Apply `mutate` deterministic byte mutations to a decrypted body in place.
 * `round` is 1-based; each round derives an independent xorshift64* stream
 * from seed and round, so replaying one round never needs to replay others.
 * Each mutation XORs one byte with a non-zero delta drawn from the stream. */
void cbm_fuzz_mutate_body(unsigned char *body, size_t len, unsigned mutate,
                          unsigned long seed, unsigned round);

/* SHA-256 of len bytes; out receives the 32-byte digest in big-endian order.
 * Used by the manifest and by determinism tests; no external crypto library. */
void cbm_fuzz_sha256(const unsigned char *data, size_t len,
                     unsigned char out[32]);

#endif /* CBM_FUZZ_H */
