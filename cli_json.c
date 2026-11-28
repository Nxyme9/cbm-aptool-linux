/* cli_json.c - compact, locale-independent JSON emission for the CLI */
#include "cli_json.h"

/* Escape '"', '\\', the short control escapes and every other C0 byte as
 * \u00xx (lowercase hex). Bytes >= 0x80 pass through unchanged: the fixed CLI
 * fields are ASCII or already-hex SHA-256 text. */
static void put_string(FILE *f, const char *s) {
    static const char hex[] = "0123456789abcdef";
    if (!f) return;
    if (fputc('"', f) == EOF) return;
    if (!s) s = "";
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"': (void)fputs("\\\"", f); break;
        case '\\': (void)fputs("\\\\", f); break;
        case '\b': (void)fputs("\\b", f); break;
        case '\f': (void)fputs("\\f", f); break;
        case '\n': (void)fputs("\\n", f); break;
        case '\r': (void)fputs("\\r", f); break;
        case '\t': (void)fputs("\\t", f); break;
        default:
            if (c < 0x20u) {
                (void)fputs("\\u00", f);
                (void)fputc(hex[c >> 4], f);
                (void)fputc(hex[c & 0x0fu], f);
            } else {
                (void)fputc((int)c, f);
            }
        }
    }
    (void)fputc('"', f);
}

/* Comma between fields (or array items); the first item has none. */
static void sep(cbm_json_t *j) {
    if (!j || !j->out) return;
    if (j->depth >= CBM_JSON_MAX_DEPTH) { j->bad = 1; return; }
    if (j->first[j->depth]) (void)fputc(',', j->out);
    else j->first[j->depth] = 1;
}

static void push(cbm_json_t *j, unsigned char kind) {
    if (!j || !j->out) return;
    if (j->depth + 1u >= CBM_JSON_MAX_DEPTH) { j->bad = 1; return; }
    j->depth++;
    j->first[j->depth] = 0;
    j->kind[j->depth] = kind;
}

static void pop(cbm_json_t *j) {
    if (!j || !j->out) return;
    if (j->depth == 0u) { j->bad = 1; return; }
    (void)fputc(j->kind[j->depth] == 1u ? ']' : '}', j->out);
    j->depth--;
}

void cbm_json_object_begin(cbm_json_t *j, FILE *out,
                           const char *command, const char *status) {
    if (!j) return;
    j->out = out;
    j->depth = 0u;
    j->bad = 0;
    for (unsigned i = 0; i < CBM_JSON_MAX_DEPTH; i++) {
        j->first[i] = 0;
        j->kind[i] = 0;
    }
    if (!out) { j->bad = 1; return; }
    (void)fputs("{\"schema\":", out);
    put_string(out, CBM_JSON_SCHEMA);
    (void)fputs(",\"command\":", out);
    put_string(out, command);
    (void)fputs(",\"status\":", out);
    put_string(out, status);
    j->first[0] = 1; /* status is the third field; the next one needs a comma */
}

void cbm_json_field_string(cbm_json_t *j, const char *key, const char *value) {
    if (!j || !j->out) return;
    sep(j);
    put_string(j->out, key);
    (void)fputc(':', j->out);
    put_string(j->out, value);
}

void cbm_json_field_u64(cbm_json_t *j, const char *key, unsigned long long value) {
    if (!j || !j->out) return;
    sep(j);
    put_string(j->out, key);
    (void)fprintf(j->out, ":%llu", value);
}

void cbm_json_field_i64(cbm_json_t *j, const char *key, long long value) {
    if (!j || !j->out) return;
    sep(j);
    put_string(j->out, key);
    (void)fprintf(j->out, ":%lld", value);
}

void cbm_json_field_bool(cbm_json_t *j, const char *key, int value) {
    if (!j || !j->out) return;
    sep(j);
    put_string(j->out, key);
    (void)fputs(value ? ":true" : ":false", j->out);
}

/* Entropy and other bounded [0,8] measurements use the same clamp as the
 * prose format in main.c, so JSON and text never disagree. */
void cbm_json_field_fixed6(cbm_json_t *j, const char *key, double value) {
    if (!j || !j->out) return;
    if (!(value > 0.0)) value = 0.0;
    if (value > 8.0) value = 8.0;
    unsigned long long scaled = (unsigned long long)(value * 1000000.0 + 0.5);
    if (scaled > 8000000ULL) scaled = 8000000ULL;
    sep(j);
    put_string(j->out, key);
    (void)fprintf(j->out, ":%llu.%06llu", scaled / 1000000ULL,
                  scaled % 1000000ULL);
}

void cbm_json_array_begin(cbm_json_t *j, const char *key) {
    if (!j || !j->out) return;
    sep(j);
    put_string(j->out, key);
    (void)fputs(":[", j->out);
    push(j, 1u);
}

void cbm_json_array_end(cbm_json_t *j) { pop(j); }

void cbm_json_object_start(cbm_json_t *j, const char *key) {
    if (!j || !j->out) return;
    sep(j);
    put_string(j->out, key);
    (void)fputs(":{", j->out);
    push(j, 0u);
}

void cbm_json_object_end(cbm_json_t *j) { pop(j); }

void cbm_json_element_object(cbm_json_t *j) {
    if (!j || !j->out) return;
    sep(j);
    (void)fputc('{', j->out);
    push(j, 0u);
}

void cbm_json_end(cbm_json_t *j) {
    if (!j || !j->out) return;
    while (j->depth > 0u) pop(j);
    (void)fputs("}\n", j->out);
}

void cbm_json_error(FILE *out, const char *command, const char *message) {
    cbm_json_t j;
    cbm_json_object_begin(&j, out, command, "error");
    cbm_json_field_string(&j, "error", message);
    cbm_json_end(&j);
}
