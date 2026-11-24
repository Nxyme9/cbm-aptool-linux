/* cbm_container.c - CBM container read/write implementation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "cbm_container.h"
#include "tea_crypto.h"

cbm_status_t cbm_check_encrypted(const unsigned char *header, size_t filesize) {
    if (!header || filesize < 1) return CBM_ERR_SIZE;
    /* byte-0 header: if high bit set, file is encrypted */
    if (header[0] & 0x80) return CBM_ERR_ENCRYPTED;
    return CBM_OK;
}

size_t cbm_compute_hlen(size_t filesize) {
    /* HLEN = ((filesize-511)&~7)+511 */
    if (filesize < 512) return 511;
    return ((filesize - 511) & ~7) + 511;
}

int cbm_cbc_decrypt(unsigned char *body, size_t body_len, const char *key) {
    if (!body || body_len == 0 || !key) return -1;
    /* TEA core handles arbitrary lengths (incl. 85687-byte container body) */
    return tea_decrypt(body, body_len, key);
}

int cbm_cbc_encrypt(unsigned char *body, size_t body_len, const char *key) {
    if (!body || body_len == 0 || !key) return -1;
    return tea_encrypt(body, body_len, key);
}
