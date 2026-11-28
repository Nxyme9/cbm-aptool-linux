/* vault.c - derived CBM-envelope secret store (wave 5Q)
 *
 * File layout (exactly CBM_CONTAINER_SIZE = 85688 bytes):
 *   byte 0        preserved envelope header byte (bit 7 = encrypted)
 *   bytes 1..     TEA-encrypted body (85687 bytes; the 8-byte TEA core
 *                 leaves the final 7 bytes untouched, and they stay zero)
 *
 * Plaintext body layout (little-endian integers):
 *   0..7    FNV-1a 64 checksum over body bytes 8..85686
 *   8..15   magic "CBMVLT01"
 *   16..17  format version (1)
 *   18..19  record count
 *   20..23  reserved (zero)
 *   24..    records: u16 label_len, u16 value_len, label, value
 *   ...     zero padding
 *
 * This is a derived format. It reuses the envelope and the clean-room TEA
 * core; it is not a vendor container and makes no vendor-compatibility claim.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <unistd.h>

#include "vault.h"
#include "cli_json.h"
#include "cbm_container.h"
#include "cbm_file.h"
#include "tea_crypto.h"
#include "tea_native.h"

#define VAULT_BODY_LEN ((size_t)(CBM_CONTAINER_SIZE - CBM_HEADER_SIZE))
#define VAULT_OFF_CHECKSUM 0u
#define VAULT_OFF_MAGIC 8u
#define VAULT_OFF_VERSION 16u
#define VAULT_OFF_COUNT 18u
#define VAULT_OFF_RESERVED 20u
#define VAULT_OFF_RECORDS 24u
#define VAULT_MAGIC_LEN 8u
#define VAULT_VERSION 1u
#define VAULT_MAX_RECORDS 1024u
#define VAULT_FNV_OFFSET UINT64_C(0xcbf29ce484222325)
#define VAULT_FNV_PRIME UINT64_C(0x100000001b3)

static void set_err(char *err, size_t errlen, const char *fmt, ...) {
    va_list ap;
    if (!err || errlen == 0) return;
    va_start(ap, fmt);
    (void)vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static void put16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
}

static uint16_t get16(const unsigned char *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

static void put64(unsigned char *p, uint64_t v) {
    for (unsigned i = 0; i < 8u; i++)
        p[i] = (unsigned char)((v >> (8u * i)) & 0xffu);
}

static uint64_t get64(const unsigned char *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8u; i++)
        v |= (uint64_t)p[i] << (8u * i);
    return v;
}

static uint64_t fnv1a(const unsigned char *p, size_t n) {
    uint64_t h = VAULT_FNV_OFFSET;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint64_t)p[i];
        h *= VAULT_FNV_PRIME;
    }
    return h;
}

static int key_ok(const char *key) {
    return key != NULL && strlen(key) == (size_t)CBM_VAULT_KEY_LEN;
}

static int label_ok(const char *label) {
    size_t n;
    if (!label) return 0;
    n = strlen(label);
    if (n == 0 || n > (size_t)CBM_VAULT_LABEL_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)label[i];
        if (c < 0x20u || c > 0x7eu) return 0;
    }
    return 1;
}

/* Native is the default backend; the PE backend is opt-in and must fail
 * loudly when it was selected without CBM_PE_PATH (tea_init does that). */
static int crypto_ready(void) {
    if (tea_is_ready()) return 0;
    return tea_init(getenv("CBM_PE_PATH"));
}

static size_t records_size(const vault_t *v) {
    size_t total = 0;
    for (size_t i = 0; i < v->count; i++)
        total += 4u + strlen(v->records[i].label) + v->records[i].value_len;
    return total;
}

void vault_zero(vault_t *v) {
    if (v) memset(v, 0, sizeof *v);
}

void vault_free(vault_t *v) {
    if (!v) return;
    for (size_t i = 0; i < v->count; i++) {
        free(v->records[i].label);
        free(v->records[i].value);
    }
    free(v->records);
    memset(v, 0, sizeof *v);
}

static int build_body(const vault_t *v, unsigned char *body,
                      char *err, size_t errlen) {
    size_t pos = VAULT_OFF_RECORDS;

    memset(body, 0, VAULT_BODY_LEN);
    memcpy(body + VAULT_OFF_MAGIC, CBM_VAULT_MAGIC, VAULT_MAGIC_LEN);
    put16(body + VAULT_OFF_VERSION, (uint16_t)VAULT_VERSION);
    put16(body + VAULT_OFF_COUNT, (uint16_t)v->count);
    put32(body + VAULT_OFF_RESERVED, 0u);

    for (size_t i = 0; i < v->count; i++) {
        size_t llen = strlen(v->records[i].label);
        size_t vlen = v->records[i].value_len;
        if (llen == 0 || llen > (size_t)CBM_VAULT_LABEL_MAX ||
            vlen > (size_t)CBM_VAULT_VALUE_MAX) {
            set_err(err, errlen, "record %zu is outside the format limits", i);
            return VAULT_ERR_FORMAT;
        }
        if (pos + 4u + llen + vlen > VAULT_BODY_LEN) {
            set_err(err, errlen, "vault capacity exceeded (%zu of %zu body bytes)",
                    pos + 4u + llen + vlen, VAULT_BODY_LEN);
            return VAULT_ERR_FULL;
        }
        put16(body + pos, (uint16_t)llen);
        put16(body + pos + 2u, (uint16_t)vlen);
        memcpy(body + pos + 4u, v->records[i].label, llen);
        memcpy(body + pos + 4u + llen, v->records[i].value, vlen);
        pos += 4u + llen + vlen;
    }

    put64(body + VAULT_OFF_CHECKSUM,
          fnv1a(body + VAULT_OFF_MAGIC, VAULT_BODY_LEN - VAULT_OFF_MAGIC));
    return VAULT_OK;
}

static int parse_body(const unsigned char *body, vault_t *v,
                      char *err, size_t errlen) {
    size_t pos = VAULT_OFF_RECORDS;
    uint16_t count;

    if (memcmp(body + VAULT_OFF_MAGIC, CBM_VAULT_MAGIC, VAULT_MAGIC_LEN) != 0) {
        set_err(err, errlen, "not a CBM vault or wrong key (magic mismatch)");
        return VAULT_ERR_AUTH;
    }
    if (get16(body + VAULT_OFF_VERSION) != (uint16_t)VAULT_VERSION) {
        set_err(err, errlen, "unsupported vault format version %u",
                (unsigned)get16(body + VAULT_OFF_VERSION));
        return VAULT_ERR_FORMAT;
    }
    count = get16(body + VAULT_OFF_COUNT);
    if (count > (uint16_t)VAULT_MAX_RECORDS) {
        set_err(err, errlen, "record count %u exceeds the format limit",
                (unsigned)count);
        return VAULT_ERR_FORMAT;
    }
    if (get64(body + VAULT_OFF_CHECKSUM) !=
        fnv1a(body + VAULT_OFF_MAGIC, VAULT_BODY_LEN - VAULT_OFF_MAGIC)) {
        set_err(err, errlen, "vault checksum mismatch (tampered or wrong key)");
        return VAULT_ERR_AUTH;
    }

    for (uint16_t i = 0; i < count; i++) {
        size_t llen, vlen;
        vault_record_t *rec;

        if (pos + 4u > VAULT_BODY_LEN) {
            set_err(err, errlen, "record %u header runs past the body", (unsigned)i);
            return VAULT_ERR_FORMAT;
        }
        llen = get16(body + pos);
        vlen = get16(body + pos + 2u);
        if (llen == 0 || llen > (size_t)CBM_VAULT_LABEL_MAX ||
            vlen > (size_t)CBM_VAULT_VALUE_MAX) {
            set_err(err, errlen, "record %u is outside the format limits", (unsigned)i);
            return VAULT_ERR_FORMAT;
        }
        if (pos + 4u + llen + vlen > VAULT_BODY_LEN) {
            set_err(err, errlen, "record %u runs past the body", (unsigned)i);
            return VAULT_ERR_FORMAT;
        }
        if (memchr(body + pos + 4u, 0, llen) != NULL) {
            set_err(err, errlen, "record %u label contains NUL", (unsigned)i);
            return VAULT_ERR_FORMAT;
        }
        if (v->count == v->cap) {
            size_t ncap = v->cap ? v->cap * 2u : 8u;
            vault_record_t *grown;
            if (ncap > (size_t)VAULT_MAX_RECORDS) ncap = (size_t)VAULT_MAX_RECORDS;
            grown = (vault_record_t *)realloc(v->records, ncap * sizeof *grown);
            if (!grown) {
                set_err(err, errlen, "out of memory");
                return VAULT_ERR_IO;
            }
            v->records = grown;
            v->cap = ncap;
        }
        rec = &v->records[v->count];
        rec->label = (char *)malloc(llen + 1u);
        rec->value = (char *)malloc(vlen + 1u);
        if (!rec->label || !rec->value) {
            free(rec->label);
            free(rec->value);
            rec->label = NULL;
            rec->value = NULL;
            set_err(err, errlen, "out of memory");
            return VAULT_ERR_IO;
        }
        memcpy(rec->label, body + pos + 4u, llen);
        rec->label[llen] = '\0';
        memcpy(rec->value, body + pos + 4u + llen, vlen);
        rec->value[vlen] = '\0';
        rec->value_len = vlen;
        v->count++;
        pos += 4u + llen + vlen;
    }

    for (; pos < VAULT_BODY_LEN; pos++) {
        if (body[pos] != 0) {
            set_err(err, errlen, "non-zero padding after the last record");
            return VAULT_ERR_FORMAT;
        }
    }
    return VAULT_OK;
}

int vault_create(const char *path, const char *key, char *err, size_t errlen) {
    unsigned char file[CBM_CONTAINER_SIZE];
    unsigned char check[CBM_CONTAINER_SIZE];
    vault_t empty;
    int rc;

    if (!path || !path[0]) {
        set_err(err, errlen, "vault path is required");
        return VAULT_ERR_ARG;
    }
    if (!key_ok(key)) {
        set_err(err, errlen, "key must be exactly %d bytes", CBM_VAULT_KEY_LEN);
        return VAULT_ERR_ARG;
    }
    if (!cbm_file_is_blockdev(path) && access(path, F_OK) == 0) {
        set_err(err, errlen, "refusing to overwrite existing file '%s'", path);
        return VAULT_ERR_EXISTS;
    }
    if (crypto_ready() != 0) {
        set_err(err, errlen, "crypto backend init failed");
        return VAULT_ERR_IO;
    }

    vault_zero(&empty);
    memset(file, 0, sizeof file);
    file[0] = CBM_VAULT_HEADER_BYTE;
    rc = build_body(&empty, file + CBM_HEADER_SIZE, err, errlen);
    if (rc != VAULT_OK) return rc;
    if (cbm_cbc_encrypt(file + CBM_HEADER_SIZE, VAULT_BODY_LEN, key) != 0) {
        set_err(err, errlen, "TEA encryption failed");
        return VAULT_ERR_IO;
    }
    if (cbm_file_write(path, 0, file, sizeof file) != 0) {
        set_err(err, errlen, "cannot write %d bytes to '%s'",
                CBM_CONTAINER_SIZE, path);
        return VAULT_ERR_IO;
    }
    if (cbm_file_read(path, 0, check, sizeof check) != 0 ||
        memcmp(check, file, sizeof file) != 0) {
        set_err(err, errlen, "read-back verification failed for '%s'", path);
        return VAULT_ERR_IO;
    }
    return VAULT_OK;
}

int vault_load(const char *path, const char *key, vault_t *v,
               char *err, size_t errlen) {
    unsigned char file[CBM_CONTAINER_SIZE];
    int rc;

    if (!path || !path[0] || !v) {
        set_err(err, errlen, "vault path is required");
        return VAULT_ERR_ARG;
    }
    if (!key_ok(key)) {
        set_err(err, errlen, "key must be exactly %d bytes", CBM_VAULT_KEY_LEN);
        return VAULT_ERR_ARG;
    }
    vault_free(v);
    if (crypto_ready() != 0) {
        set_err(err, errlen, "crypto backend init failed");
        return VAULT_ERR_IO;
    }
    if (cbm_file_read(path, 0, file, sizeof file) != 0) {
        set_err(err, errlen, "cannot read %d bytes from '%s'",
                CBM_CONTAINER_SIZE, path);
        return VAULT_ERR_IO;
    }
    if ((file[0] & 0x80u) == 0) {
        set_err(err, errlen, "not a vault envelope (header byte 0x%02x)",
                (unsigned)file[0]);
        return VAULT_ERR_FORMAT;
    }
    if (cbm_cbc_decrypt(file + CBM_HEADER_SIZE, VAULT_BODY_LEN, key) != 0) {
        set_err(err, errlen, "TEA decryption failed");
        return VAULT_ERR_IO;
    }
    rc = parse_body(file + CBM_HEADER_SIZE, v, err, errlen);
    if (rc != VAULT_OK) vault_free(v);
    return rc;
}

int vault_save(const char *path, const char *key, const vault_t *v,
               char *err, size_t errlen) {
    unsigned char file[CBM_CONTAINER_SIZE];
    unsigned char check[CBM_CONTAINER_SIZE];
    unsigned char hdr = 0;
    int rc;

    if (!path || !path[0] || !v) {
        set_err(err, errlen, "vault path is required");
        return VAULT_ERR_ARG;
    }
    if (!key_ok(key)) {
        set_err(err, errlen, "key must be exactly %d bytes", CBM_VAULT_KEY_LEN);
        return VAULT_ERR_ARG;
    }
    if (crypto_ready() != 0) {
        set_err(err, errlen, "crypto backend init failed");
        return VAULT_ERR_IO;
    }
    if (cbm_file_read(path, 0, &hdr, 1) != 0) {
        set_err(err, errlen, "vault '%s' does not exist; run 'vault init' first", path);
        return VAULT_ERR_IO;
    }
    if ((hdr & 0x80u) == 0) {
        set_err(err, errlen, "existing file '%s' is not a vault envelope", path);
        return VAULT_ERR_FORMAT;
    }

    memset(file, 0, sizeof file);
    file[0] = hdr; /* preserved, never rewritten */
    rc = build_body(v, file + CBM_HEADER_SIZE, err, errlen);
    if (rc != VAULT_OK) return rc;
    if (cbm_cbc_encrypt(file + CBM_HEADER_SIZE, VAULT_BODY_LEN, key) != 0) {
        set_err(err, errlen, "TEA encryption failed");
        return VAULT_ERR_IO;
    }
    if (cbm_file_write(path, 0, file, sizeof file) != 0) {
        set_err(err, errlen, "cannot write %d bytes to '%s'",
                CBM_CONTAINER_SIZE, path);
        return VAULT_ERR_IO;
    }
    if (cbm_file_read(path, 0, check, sizeof check) != 0 ||
        memcmp(check, file, sizeof file) != 0) {
        set_err(err, errlen, "read-back verification failed for '%s'", path);
        return VAULT_ERR_IO;
    }
    return VAULT_OK;
}

int vault_put(vault_t *v, const char *label, const char *value,
              char *err, size_t errlen) {
    size_t vlen, llen;

    if (!v || !value) {
        set_err(err, errlen, "vault and value are required");
        return VAULT_ERR_ARG;
    }
    if (!label_ok(label)) {
        set_err(err, errlen, "label must be 1..%d printable ASCII bytes",
                CBM_VAULT_LABEL_MAX);
        return VAULT_ERR_ARG;
    }
    vlen = strlen(value);
    llen = strlen(label);
    if (vlen > (size_t)CBM_VAULT_VALUE_MAX) {
        set_err(err, errlen, "value exceeds %d bytes", CBM_VAULT_VALUE_MAX);
        return VAULT_ERR_ARG;
    }

    for (size_t i = 0; i < v->count; i++) {
        if (strcmp(v->records[i].label, label) == 0) {
            size_t base = records_size(v);
            size_t old = v->records[i].value_len;
            char *grown;
            if (VAULT_OFF_RECORDS + base - old + vlen > VAULT_BODY_LEN) {
                set_err(err, errlen, "vault capacity exceeded");
                return VAULT_ERR_FULL;
            }
            grown = (char *)realloc(v->records[i].value, vlen + 1u);
            if (!grown) {
                set_err(err, errlen, "out of memory");
                return VAULT_ERR_IO;
            }
            memcpy(grown, value, vlen + 1u);
            v->records[i].value = grown;
            v->records[i].value_len = vlen;
            return VAULT_OK;
        }
    }

    if (VAULT_OFF_RECORDS + records_size(v) + 4u + llen + vlen > VAULT_BODY_LEN) {
        set_err(err, errlen, "vault capacity exceeded");
        return VAULT_ERR_FULL;
    }
    if (v->count == v->cap) {
        size_t ncap = v->cap ? v->cap * 2u : 8u;
        vault_record_t *grown;
        if (ncap > (size_t)VAULT_MAX_RECORDS) ncap = (size_t)VAULT_MAX_RECORDS;
        grown = (vault_record_t *)realloc(v->records, ncap * sizeof *grown);
        if (!grown) {
            set_err(err, errlen, "out of memory");
            return VAULT_ERR_IO;
        }
        v->records = grown;
        v->cap = ncap;
    }
    {
        vault_record_t *rec = &v->records[v->count];
        rec->label = (char *)malloc(llen + 1u);
        rec->value = (char *)malloc(vlen + 1u);
        if (!rec->label || !rec->value) {
            free(rec->label);
            free(rec->value);
            rec->label = NULL;
            rec->value = NULL;
            set_err(err, errlen, "out of memory");
            return VAULT_ERR_IO;
        }
        memcpy(rec->label, label, llen + 1u);
        memcpy(rec->value, value, vlen + 1u);
        rec->value_len = vlen;
        v->count++;
    }
    return VAULT_OK;
}

const char *vault_get(const vault_t *v, const char *label) {
    if (!v || !label) return NULL;
    for (size_t i = 0; i < v->count; i++)
        if (strcmp(v->records[i].label, label) == 0)
            return v->records[i].value;
    return NULL;
}

int vault_erase(vault_t *v, const char *label, char *err, size_t errlen) {
    if (!v || !label) {
        set_err(err, errlen, "vault and label are required");
        return VAULT_ERR_ARG;
    }
    for (size_t i = 0; i < v->count; i++) {
        if (strcmp(v->records[i].label, label) == 0) {
            free(v->records[i].label);
            free(v->records[i].value);
            memmove(&v->records[i], &v->records[i + 1],
                    (v->count - i - 1u) * sizeof *v->records);
            v->count--;
            return VAULT_OK;
        }
    }
    set_err(err, errlen, "label '%s' not found", label);
    return VAULT_ERR_NOT_FOUND;
}

/* ---- CLI -------------------------------------------------------------- */

static void vault_usage(FILE *err, const char *prog) {
    if (!err) return;
    fprintf(err,
        "Usage: %s vault <command> <file> [args] [--write-back]\n"
        "Commands:\n"
        "  init <file>                 create an empty vault\n"
        "  put <file> <label> <value>  add or replace a record\n"
        "  get <file> <label>          print one value\n"
        "  list <file>                 list labels in insertion order\n"
        "  erase <file> <label>        remove a record\n"
        "Key: CBM_VAULT_KEY (exactly 16 bytes); unset uses the public TEA key.\n"
        "Device targets require --write-back (paced write + read-back verify).\n"
        "Vault files are a DERIVED format, not vendor-compatible containers.\n",
        prog ? prog : "cbm-tool");
}

static int emit_init_json(FILE *json, const char *path) {
    cbm_json_t j;
    if (!json) return 0;
    cbm_json_object_begin(&j, json, "vault", "ok");
    cbm_json_field_string(&j, "action", "init");
    cbm_json_field_string(&j, "path", path);
    cbm_json_field_u64(&j, "envelope_bytes", (unsigned long long)CBM_CONTAINER_SIZE);
    cbm_json_field_bool(&j, "derived_format", 1);
    cbm_json_end(&j);
    return 1;
}

int vault_cli_ex(int argc, char **argv, FILE *out, FILE *err, FILE *json) {
    const char *pos[5];
    const char *cmd, *path, *label, *value, *key;
    char msg[192];
    int npos = 0, write_back = 0, rc, want;

    if (argc < 3) {
        vault_usage(err, argc > 0 ? argv[0] : NULL);
        return 2;
    }
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--write-back") == 0) {
            write_back = 1;
            continue;
        }
        if (a[0] == '-' && a[1] == '-') {
            if (err) fprintf(err, "Error: unknown vault option '%s'\n", a);
            vault_usage(err, argv[0]);
            return 2;
        }
        if (npos >= 5) {
            if (err) fprintf(err, "Error: too many arguments for vault\n");
            vault_usage(err, argv[0]);
            return 2;
        }
        pos[npos++] = a;
    }
    cmd = (npos >= 1) ? pos[0] : NULL;
    path = (npos >= 2) ? pos[1] : NULL;
    if (!cmd || !path) {
        vault_usage(err, argv[0]);
        return 2;
    }

    int is_init = strcmp(cmd, "init") == 0;
    int is_put = strcmp(cmd, "put") == 0;
    int is_get = strcmp(cmd, "get") == 0;
    int is_list = strcmp(cmd, "list") == 0;
    int is_erase = strcmp(cmd, "erase") == 0;
    if (!is_init && !is_put && !is_get && !is_list && !is_erase) {
        if (err) fprintf(err, "Error: unknown vault command '%s'\n", cmd);
        vault_usage(err, argv[0]);
        return 2;
    }
    want = (is_init || is_list) ? 2 : (is_put ? 4 : 3);
    if (npos != want) {
        if (err) fprintf(err, "Error: '%s' takes %d argument(s)\n", cmd, want - 1);
        vault_usage(err, argv[0]);
        return 2;
    }
    label = (npos >= 3) ? pos[2] : NULL;
    value = (npos >= 4) ? pos[3] : NULL;

    if ((is_init || is_put || is_erase) && cbm_file_is_blockdev(path) && !write_back) {
        if (err)
            fprintf(err, "Error: device target '%s' requires --write-back "
                         "(paced write + read-back verify)\n", path);
        return 1;
    }

    key = getenv("CBM_VAULT_KEY");
    if (key && key[0] == '\0') {
        if (err) fprintf(err, "Error: CBM_VAULT_KEY is set but empty\n");
        return 2;
    }
    if (!key) {
        key = TEA_NATIVE_KEY;
        if (err)
            fprintf(err, "Note: CBM_VAULT_KEY is unset; using the public default "
                         "TEA key (obfuscation, not confidentiality).\n");
    }
    if (strlen(key) != (size_t)CBM_VAULT_KEY_LEN) {
        if (err) fprintf(err, "Error: CBM_VAULT_KEY must be exactly %d bytes\n",
                         CBM_VAULT_KEY_LEN);
        return 2;
    }

    if (is_init) {
        rc = vault_create(path, key, msg, sizeof msg);
        if (rc != VAULT_OK) {
            if (err) fprintf(err, "Error: %s\n", msg);
            return 1;
        }
        (void)emit_init_json(json, path);
        if (out)
            fprintf(out, "vault: created '%s' (%d bytes, derived format)\n",
                    path, CBM_CONTAINER_SIZE);
        return 0;
    }

    if (is_put) {
        vault_t v;
        size_t vlen = strlen(value);
        vault_zero(&v);
        rc = vault_load(path, key, &v, msg, sizeof msg);
        if (rc == VAULT_OK) rc = vault_put(&v, label, value, msg, sizeof msg);
        if (rc == VAULT_OK) rc = vault_save(path, key, &v, msg, sizeof msg);
        vault_free(&v);
        if (rc != VAULT_OK) {
            if (err) fprintf(err, "Error: %s\n", msg);
            return 1;
        }
        if (json) {
            cbm_json_t j;
            cbm_json_object_begin(&j, json, "vault", "ok");
            cbm_json_field_string(&j, "action", "put");
            cbm_json_field_string(&j, "label", label);
            cbm_json_field_u64(&j, "value_len", (unsigned long long)vlen);
            cbm_json_end(&j);
        }
        if (out) fprintf(out, "vault: stored '%s' (%zu bytes)\n", label, vlen);
        return 0;
    }

    if (is_get) {
        vault_t v;
        const char *found;
        vault_zero(&v);
        rc = vault_load(path, key, &v, msg, sizeof msg);
        if (rc != VAULT_OK) {
            if (err) fprintf(err, "Error: %s\n", msg);
            return 1;
        }
        found = vault_get(&v, label);
        if (!found) {
            if (err) fprintf(err, "Error: label '%s' not found\n", label);
            vault_free(&v);
            return 1;
        }
        if (json) {
            cbm_json_t j;
            cbm_json_object_begin(&j, json, "vault", "ok");
            cbm_json_field_string(&j, "action", "get");
            cbm_json_field_string(&j, "label", label);
            cbm_json_field_string(&j, "value", found);
            cbm_json_end(&j);
        } else if (out) {
            fprintf(out, "%s\n", found);
        }
        vault_free(&v);
        return 0;
    }

    if (is_list) {
        vault_t v;
        vault_zero(&v);
        rc = vault_load(path, key, &v, msg, sizeof msg);
        if (rc != VAULT_OK) {
            if (err) fprintf(err, "Error: %s\n", msg);
            return 1;
        }
        if (json) {
            cbm_json_t j;
            cbm_json_object_begin(&j, json, "vault", "ok");
            cbm_json_field_string(&j, "action", "list");
            cbm_json_array_begin(&j, "records");
            for (size_t i = 0; i < v.count; i++) {
                cbm_json_element_object(&j);
                cbm_json_field_string(&j, "label", v.records[i].label);
                cbm_json_field_u64(&j, "value_len",
                                   (unsigned long long)v.records[i].value_len);
                cbm_json_object_end(&j);
            }
            cbm_json_array_end(&j);
            cbm_json_end(&j);
        } else if (out) {
            if (v.count == 0) fprintf(out, "(empty vault)\n");
            for (size_t i = 0; i < v.count; i++)
                fprintf(out, "%s\n", v.records[i].label);
        }
        vault_free(&v);
        return 0;
    }

    /* erase */
    {
        vault_t v;
        vault_zero(&v);
        rc = vault_load(path, key, &v, msg, sizeof msg);
        if (rc == VAULT_OK) rc = vault_erase(&v, label, msg, sizeof msg);
        if (rc == VAULT_OK) rc = vault_save(path, key, &v, msg, sizeof msg);
        vault_free(&v);
        if (rc != VAULT_OK) {
            if (err) fprintf(err, "Error: %s\n", msg);
            return 1;
        }
        if (json) {
            cbm_json_t j;
            cbm_json_object_begin(&j, json, "vault", "ok");
            cbm_json_field_string(&j, "action", "erase");
            cbm_json_field_string(&j, "label", label);
            cbm_json_end(&j);
        }
        if (out) fprintf(out, "vault: erased '%s'\n", label);
        return 0;
    }
}
