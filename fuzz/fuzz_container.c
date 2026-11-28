/* libFuzzer harness: container envelope helpers and CBC body codec.
 * Native TEA key only; no PE, no device, no vendor binary. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_container.h"
#include "tea_native.h"

#define MAX_BYTES (64u * 1024u)

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char *buf;
    size_t len;

    if (size == 0 || size > MAX_BYTES) return 0;

    (void)cbm_check_encrypted(data, size);
    (void)cbm_compute_hlen(size);

    len = (size / 8u) * 8u;
    if (len == 0) return 0;
    buf = (unsigned char *)malloc(len);
    if (!buf) return 0;
    memcpy(buf, data, len);

    /* Envelope helper must tolerate arbitrary ciphertext and lengths. */
    if (cbm_cbc_decrypt(buf, len, TEA_NATIVE_KEY) == 0)
        (void)cbm_cbc_encrypt(buf, len, TEA_NATIVE_KEY);

    free(buf);
    return 0;
}
