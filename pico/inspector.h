/* inspector.h - portable, SDK-free inspection helpers for the Pico inspector.
 *
 * These functions are pure analysis over caller-owned buffers: no USB, no
 * device I/O, no SDK headers. They are compiled into the host vector test and
 * into the firmware image unchanged, so the report logic is verified on-host
 * even when the firmware build is skipped.
 */
#ifndef PICO_INSPECTOR_H
#define PICO_INSPECTOR_H

#include <stddef.h>

#define PICO_CONTAINER_SIZE 85688u
#define PICO_BODY_LEN       85687u

typedef struct {
    unsigned char header;      /* byte 0 of the container */
    int encrypted;             /* pico_header_encrypted(header) */
    double entropy_bits;       /* Shannon entropy of the body, bits/byte */
    unsigned int strings;      /* printable runs >= 4 bytes */
    unsigned int hex_lines;    /* 16-byte lines in a full hex dump */
} pico_inspect_t;

/* Byte-0 flag: high bit set means the body is TEA-encrypted. */
int pico_header_encrypted(unsigned char header);

/* Shannon entropy over buf[0..len), in bits per byte (0.0 for empty/null). */
double pico_entropy(const unsigned char *buf, size_t len);

/* Count printable ASCII (0x20..0x7e) runs of length >= min_len. */
unsigned int pico_count_strings(const unsigned char *buf, size_t len,
                                unsigned int min_len);

/* Render a bounded 16-byte-per-line hex dump of buf[0..min(len,limit)).
 * NUL-terminates when space permits; returns the would-be/actual length. */
size_t pico_hexdump(const unsigned char *buf, size_t len, size_t limit,
                    char *out, size_t cap);

/* Fill a report struct from a decrypted body. */
void pico_inspect(unsigned char header, const unsigned char *body, size_t len,
                  pico_inspect_t *out);

#endif /* PICO_INSPECTOR_H */
