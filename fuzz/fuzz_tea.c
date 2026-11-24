/* libFuzzer harness: clean-room TEA block codec.
 * No device, no PE, no vendor binary: native C core only. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tea_native.h"

#define MAX_BYTES (8u * 4096u)

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t len = (size / 8u) * 8u;
    unsigned char *buf, *orig;

    if (len == 0 || len > MAX_BYTES) return 0;
    buf = (unsigned char *)malloc(len);
    orig = (unsigned char *)malloc(len);
    if (!buf || !orig) { free(buf); free(orig); return 0; }

    memcpy(orig, data, len);
    memcpy(buf, orig, len);

    /* TEA encrypt/decrypt are exact inverses on whole 8-byte blocks.
     * Any mismatch is a codec regression and must crash the fuzz target. */
    if (tea_native_encrypt(buf, len, TEA_NATIVE_KEY) == 0 &&
        tea_native_decrypt(buf, len, TEA_NATIVE_KEY) == 0 &&
        memcmp(buf, orig, len) != 0) {
        abort();
    }

    /* Also exercise decryption of arbitrary ciphertext (no inverse assumed). */
    (void)tea_native_decrypt(orig, len, TEA_NATIVE_KEY);

    free(buf);
    free(orig);
    return 0;
}
