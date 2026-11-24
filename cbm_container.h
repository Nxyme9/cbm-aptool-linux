/* cbm_container.h - CBM container read/write layer
 * Container format: 85688 B total, byte-0 header + TEA-encrypted body.
 * HLEN = ((filesize-511)&~7)+511, payload alignment at 1+aligned.
 * Error strings: "File is encrypted!", "Decrypt Faile!"
 */
#ifndef CBM_CONTAINER_H
#define CBM_CONTAINER_H

#include <stddef.h>

#define CBM_CONTAINER_SIZE 85688
#define CBM_HEADER_SIZE 1
#define CBM_ALIGN 511

typedef enum {
    CBM_OK = 0,
    CBM_ERR_ENCRYPTED = 1,
    CBM_ERR_DECRYPT_FAILED = 2,
    CBM_ERR_SIZE = 3,
    CBM_ERR_OK2 = 4
} cbm_status_t;

/* Check if file is encrypted (header flag). */
cbm_status_t cbm_check_encrypted(const unsigned char *header, size_t filesize);

/* Compute HLEN offset. */
size_t cbm_compute_hlen(size_t filesize);

/* Decrypt body in place with TEA. */
int cbm_cbc_decrypt(unsigned char *body, size_t body_len, const char *key);

/* Encrypt body in place with TEA. */
int cbm_cbc_encrypt(unsigned char *body, size_t body_len, const char *key);

#endif /* CBM_CONTAINER_H */
