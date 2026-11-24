/* cli_json.h - tiny compact JSON emitter for `--json` CLI modes
 *
 * No third-party library. Every document begins with the fixed
 * {"schema":"cbm/1","command":"...","status":"ok"|"error"} prefix and ends
 * with one LF. Keys are emitted as escaped strings too, but callers use only
 * fixed literal keys. Numbers are locale-independent: unsigned/signed decimal
 * and fixed-point with exactly six digits after a literal '.'.
 */
#ifndef CLI_JSON_H
#define CLI_JSON_H

#include <stdio.h>

#define CBM_JSON_SCHEMA "cbm/1"
#define CBM_JSON_MAX_DEPTH 8u

typedef struct {
    FILE *out;
    unsigned depth;
    unsigned char first[CBM_JSON_MAX_DEPTH];
    unsigned char kind[CBM_JSON_MAX_DEPTH]; /* 0 = object, 1 = array */
    int bad;
} cbm_json_t;

/* Begin a document: schema, command, status. */
void cbm_json_object_begin(cbm_json_t *j, FILE *out,
                           const char *command, const char *status);

/* Add a field to the current object. */
void cbm_json_field_string(cbm_json_t *j, const char *key, const char *value);
void cbm_json_field_u64(cbm_json_t *j, const char *key, unsigned long long value);
void cbm_json_field_i64(cbm_json_t *j, const char *key, long long value);
void cbm_json_field_bool(cbm_json_t *j, const char *key, int value);
void cbm_json_field_fixed6(cbm_json_t *j, const char *key, double value);

/* Nested containers. array_begin/object_start take a key in the parent
 * object; element_object adds a new object to the current array. */
void cbm_json_array_begin(cbm_json_t *j, const char *key);
void cbm_json_array_end(cbm_json_t *j);
void cbm_json_object_start(cbm_json_t *j, const char *key);
void cbm_json_object_end(cbm_json_t *j);
void cbm_json_element_object(cbm_json_t *j);

/* Close every open nested container, then the root object and the document. */
void cbm_json_end(cbm_json_t *j);

/* One complete error document: prefix plus "error":"<message>". */
void cbm_json_error(FILE *out, const char *command, const char *message);

#endif /* CLI_JSON_H */
