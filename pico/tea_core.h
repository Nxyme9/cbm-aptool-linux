/* tea_core.h - portable, POSIX-free subset of the clean-room CBM block cipher
 *
 * No PE loader, no mmap, no stdio, no device I/O: just the recovered tables and
 * the three-core transform. Compiles on the host test and on RP2040 with the
 * Pico SDK. State is per-call and identical to tea_native.c, so the vectors in
 * test_vectors.h must match the host implementation byte-for-byte.
 */
#ifndef PICO_TEA_CORE_H
#define PICO_TEA_CORE_H

#include <stddef.h>

#define PICO_TEA_KEY_LEN 16u
/* Recovered default key from the host clean-room cipher (TEA_NATIVE_KEY). */
#define PICO_CBM_KEY "1a2b3c4d5e6fTENG"

/* Encrypt/decrypt floor(len / 8) complete 8-byte blocks in place.
 * Returns 0 on success, 1 on a null buffer (with nonzero len) or a key whose
 * length is not PICO_TEA_KEY_LEN. Trailing bytes are left untouched. */
int pico_tea_encrypt(unsigned char *buf, size_t len, const char *key);
int pico_tea_decrypt(unsigned char *buf, size_t len, const char *key);

#endif /* PICO_TEA_CORE_H */
