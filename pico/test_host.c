/* test_host.c - host-side verification of the portable Pico subset.
 *
 * Compiled with plain cc (no SDK, no device). The embedded codec and inspector
 * are the exact sources compiled into the firmware. Prints its own summary
 * line, outside the frozen `Results:` sums (same convention as test_vault).
 */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "tea_core.h"
#include "inspector.h"
#include "test_vectors.h"

static int passed, failed;

static void check(int ok, const char *name) {
    if (ok) {
        passed++;
        printf("  ok   %s\n", name);
    } else {
        failed++;
        printf("  FAIL %s\n", name);
    }
}

int main(void) {
    unsigned char b[32], orig[32];
    char dump[256];
    pico_inspect_t rep;

    /* Encryption matches the host cipher vectors byte-for-byte. */
    memcpy(b, pico_v_zero8_plain, 8);
    check(pico_tea_encrypt(b, 8, PICO_TEST_KEY) == 0 &&
          memcmp(b, pico_v_zero8_cipher, 8) == 0, "zero8 encrypt vector");

    memcpy(b, pico_v_seq16_plain, 16);
    check(pico_tea_encrypt(b, 16, PICO_TEST_KEY) == 0 &&
          memcmp(b, pico_v_seq16_cipher, 16) == 0, "seq16 encrypt vector");

    memcpy(b, pico_v_ascii24_plain, 24);
    check(pico_tea_encrypt(b, 24, PICO_TEST_KEY) == 0 &&
          memcmp(b, pico_v_ascii24_cipher, 24) == 0, "ascii24 encrypt vector");

    memcpy(b, pico_v_ff32_plain, 32);
    check(pico_tea_encrypt(b, 32, PICO_TEST_KEY) == 0 &&
          memcmp(b, pico_v_ff32_cipher, 32) == 0, "ff32 encrypt vector");

    /* Decryption inverts each vector back to its plaintext. */
    memcpy(b, pico_v_zero8_cipher, 8);
    check(pico_tea_decrypt(b, 8, PICO_TEST_KEY) == 0 &&
          memcmp(b, pico_v_zero8_plain, 8) == 0, "zero8 decrypt vector");

    memcpy(b, pico_v_seq16_cipher, 16);
    check(pico_tea_decrypt(b, 16, PICO_TEST_KEY) == 0 &&
          memcmp(b, pico_v_seq16_plain, 16) == 0, "seq16 decrypt vector");

    memcpy(b, pico_v_ascii24_cipher, 24);
    check(pico_tea_decrypt(b, 24, PICO_TEST_KEY) == 0 &&
          memcmp(b, pico_v_ascii24_plain, 24) == 0, "ascii24 decrypt vector");

    memcpy(b, pico_v_ff32_cipher, 32);
    check(pico_tea_decrypt(b, 32, PICO_TEST_KEY) == 0 &&
          memcmp(b, pico_v_ff32_plain, 32) == 0, "ff32 decrypt vector");

    /* 23 bytes: floor(23/8)=2 blocks; the trailing 7 bytes stay untouched. */
    memset(b, 0, sizeof(b));
    memcpy(b, pico_v_roundtrip23, 23);
    memcpy(orig, b, sizeof(b));
    check(pico_tea_encrypt(b, 23, PICO_TEST_KEY) == 0 &&
          memcmp(b + 16, orig + 16, 7) == 0 &&
          pico_tea_decrypt(b, 23, PICO_TEST_KEY) == 0 &&
          memcmp(b, orig, 32) == 0, "23-byte roundtrip, tail preserved");

    /* Invalid inputs fail closed, never silently process. */
    memset(b, 0, sizeof(b));
    check(pico_tea_encrypt(b, 8, "short") != 0, "short key rejected");
    check(pico_tea_decrypt(b, 8, "1234567890123456x") != 0,
          "long key rejected");
    check(pico_tea_encrypt(NULL, 8, PICO_TEST_KEY) != 0,
          "null buffer rejected");

    /* Header flag, entropy and string/hash helpers. */
    check(pico_header_encrypted(0x00) == 0 &&
          pico_header_encrypted(0x80) == 1, "header encrypted flag");

    memset(b, 0, sizeof(b));
    check(pico_entropy(b, 32) == 0.0, "entropy of constant buffer is 0");
    {
        unsigned char distinct[256];
        for (int i = 0; i < 256; i++) distinct[i] = (unsigned char)i;
        check(fabs(pico_entropy(distinct, 256) - 8.0) < 1e-9,
              "entropy of 256 distinct bytes is 8 bits");
    }

    {
        static const unsigned char corpus[] = "AB\0CDEF\0XY";
        check(pico_count_strings(corpus, sizeof(corpus) - 1, 4) == 1,
              "count strings >= 4");
    }

    {
        static const unsigned char hexin[] = {0x41, 0x42, 0x00, 0x43};
        memset(dump, 0, sizeof(dump));
        pico_hexdump(hexin, 4, 4, dump, sizeof(dump));
        check(strstr(dump, "41 42 00 43") != NULL &&
              strstr(dump, "|AB.C|") != NULL, "hexdump format");
    }

    memset(b, 0x41, sizeof(b));
    pico_inspect(0x80, b, 32, &rep);
    check(rep.encrypted == 1 && rep.header == 0x80 &&
          rep.strings == 1 && rep.hex_lines == 2,
          "inspector report fields");

    printf("test_pico_host: %d passed, %d failed\n", passed, failed);
    return failed != 0;
}
