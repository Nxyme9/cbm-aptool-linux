/* tea_crypto.h - TEA-based CBMUsbDisk crypto interface
 * Port of PE cores 0x459da0 (encrypt) / 0x459d50 (decrypt)
 * Key: "1a2b3c4d5e6fTENG" (keyidx=12, derived via 0x4fc924)
 * State: 0x531328 (16 bytes, zeroed before each call)
 * Block fn: 0x459ec0 (flags 0x50/0x70/0x50 encrypt, 0x70/0x50/0x70 decrypt)
 * CBC XOR at 0x45a0ff-0x45a177
 */
#ifndef TEA_CRYPTO_H
#define TEA_CRYPTO_H

#include <stddef.h>

#define TEA_KEY_LEN 16
#define TEA_BLOCK_SIZE 8
#define TEA_STATE_SIZE 16

/* Initialize the crypto subsystem (loads PE at ImageBase).
 * Returns 0 on success, -1 on failure. */
int tea_init(const char *pe_path);

/* Encrypt buffer in place (CBC mode). Whole 8-byte blocks are processed; a
 * trailing partial block (len % 8) is left untouched, so odd lengths such as
 * the AC1 case of 85687 bytes roundtrip exactly. Returns 0 on success, -1 on
 * invalid arguments or backend failure. */
int tea_encrypt(unsigned char *buf, size_t len, const char *key);

/* Decrypt buffer in place (CBC mode). Same length rule as tea_encrypt.
 * Returns 0 on success, -1 on invalid arguments or backend failure. */
int tea_decrypt(unsigned char *buf, size_t len, const char *key);

/* Cleanup crypto subsystem. */
void tea_cleanup(void);

/* Check if crypto subsystem is initialized. */
int tea_is_ready(void);

#endif /* TEA_CRYPTO_H */
