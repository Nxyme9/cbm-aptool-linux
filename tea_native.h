/* tea_native.h - clean-room CBMUsbDisk block cipher interface */
#ifndef TEA_NATIVE_H
#define TEA_NATIVE_H

#include <stddef.h>

#define TEA_NATIVE_KEY "1a2b3c4d5e6fTENG"

/* Encrypt/decrypt buf in place; process floor(len / 8) complete blocks.
 * Return 0 on success, nonzero on invalid key or length. */
int tea_native_encrypt(unsigned char *buf, size_t len, const char *key);
int tea_native_decrypt(unsigned char *buf, size_t len, const char *key);

/* Compare native output with the PE oracle at pe_path on deterministic
 * buffers. Returns 0 only when every output is byte-identical. */
int tea_native_selfcheck(const char *pe_path);

#endif /* TEA_NATIVE_H */
