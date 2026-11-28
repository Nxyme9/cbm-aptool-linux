/* vault.h - derived CBM-envelope secret store (wave 5Q)
 *
 * A vault file is exactly one CBM_CONTAINER_SIZE (85688) envelope: byte 0 is
 * the preserved header byte and bytes 1..85687 are the TEA-encrypted body.
 * The plaintext body is a private record format documented in docs/vault.md.
 * It is NOT a vendor container and no vendor compatibility is claimed.
 *
 * Callers must zero a vault_t before its first load:
 *     vault_t v; vault_zero(&v);
 * vault_load() frees any existing contents, including on a failed load.
 */
#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>
#include <stdio.h>

#define CBM_VAULT_KEY_LEN 16
#define CBM_VAULT_LABEL_MAX 63
#define CBM_VAULT_VALUE_MAX 4096
#define CBM_VAULT_MAGIC "CBMVLT01"
#define CBM_VAULT_HEADER_BYTE 0x81u /* encrypted flag | format version 1 */

typedef enum {
    VAULT_OK = 0,
    VAULT_ERR_IO = 1,
    VAULT_ERR_FORMAT = 2,
    VAULT_ERR_AUTH = 3,
    VAULT_ERR_EXISTS = 4,
    VAULT_ERR_NOT_FOUND = 5,
    VAULT_ERR_FULL = 6,
    VAULT_ERR_ARG = 7
} vault_status_t;

typedef struct {
    char *label;     /* NUL-terminated, 1..CBM_VAULT_LABEL_MAX bytes */
    char *value;     /* NUL-terminated, value_len bytes */
    size_t value_len;
} vault_record_t;

typedef struct {
    vault_record_t *records;
    size_t count;
    size_t cap;
} vault_t;

void vault_zero(vault_t *v);
void vault_free(vault_t *v);

/* Create an empty vault. Refuses to overwrite an existing regular file; a
 * block-device target is allowed here and gated by the CLI's --write-back. */
int vault_create(const char *path, const char *key, char *err, size_t errlen);

/* Read, decrypt, parse and authenticate one vault. */
int vault_load(const char *path, const char *key, vault_t *v,
               char *err, size_t errlen);

/* Encrypt and write the vault, then read the bytes back and compare. */
int vault_save(const char *path, const char *key, const vault_t *v,
               char *err, size_t errlen);

/* In-memory record operations. */
int vault_put(vault_t *v, const char *label, const char *value,
              char *err, size_t errlen);
const char *vault_get(const vault_t *v, const char *label);
int vault_erase(vault_t *v, const char *label, char *err, size_t errlen);

/* CLI entry point: cbm-tool vault <init|put|get|list|erase> ...
 * Errors go to `err`; main.c turns a non-zero return into a cbm/1 error
 * document, so this function never emits its own error JSON. */
int vault_cli_ex(int argc, char **argv, FILE *out, FILE *err, FILE *json);

#endif /* VAULT_H */
