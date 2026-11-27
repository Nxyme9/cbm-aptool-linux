/* firmware.c - RP2040 standalone CBM container inspector.
 *
 * Read-only with respect to the inspected source: container bytes arrive over
 * USB serial, are decrypted in RAM, and a report is printed over USB serial.
 * The board never opens, mounts or writes to a storage device.
 *
 * Built ONLY by pico/CMakeLists.txt with the Pico SDK. The portable logic
 * (tea_core.c, inspector.c) is the exact source compiled into the host vector
 * test, so the cipher and report helpers are verified on-host even when the
 * firmware build is skipped for lack of SDK/hardware. See docs/pico-inspector.md
 * for the verified/gated split, including the USB-mass-storage-host gap.
 */
#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "hardware/gpio.h"

#include "tea_core.h"
#include "inspector.h"

#define PIN_DUMP   5u   /* button: print plaintext hex over serial */
#define PIN_VERIFY 6u   /* button: decrypt/encrypt/decrypt roundtrip */

/* Static, not stack: RP2040 has ~8 KiB of stack, so 85 KiB buffers must live
 * in .bss. Total static footprint is ~171 KiB of the 264 KiB SRAM. */
static unsigned char image[PICO_CONTAINER_SIZE];
static unsigned char verify_buf[PICO_BODY_LEN];

/* Stream an exact-size container from USB serial into RAM. Returns 0 on
 * success; a short or oversized stream fails closed. */
static int load_container(unsigned char *dst) {
    size_t i;
    for (i = 0; i < PICO_CONTAINER_SIZE; i++) {
        int c = getchar();
        if (c == EOF) return -1;
        dst[i] = (unsigned char)c;
    }
    if (getchar() != EOF) return -1;   /* reject oversized input */
    return 0;
}

static void print_report(const pico_inspect_t *r) {
    printf("header=0x%02x encrypted=%d\n", r->header, r->encrypted);
    printf("body_len=%u entropy_bits=%.4f strings=%u hex_lines=%u\n",
           (unsigned)PICO_BODY_LEN, r->entropy_bits, r->strings, r->hex_lines);
}

int main(void) {
    pico_inspect_t rep;
    char line[160];

    stdio_init_all();
    gpio_init(PIN_DUMP);
    gpio_set_dir(PIN_DUMP, GPIO_IN);
    gpio_pull_up(PIN_DUMP);
    gpio_init(PIN_VERIFY);
    gpio_set_dir(PIN_VERIFY, GPIO_IN);
    gpio_pull_up(PIN_VERIFY);

    printf("cbm-pico-inspector: send exactly %u container bytes over USB serial\n",
           (unsigned)PICO_CONTAINER_SIZE);
    while (1) {
        if (load_container(image) != 0) {
            printf("ERR: expected exactly %u bytes\n",
                   (unsigned)PICO_CONTAINER_SIZE);
            sleep_ms(500);
            continue;
        }

        /* Decrypt in place; the source over serial is never written back. */
        if (pico_header_encrypted(image[0]) &&
            pico_tea_decrypt(image + 1, PICO_BODY_LEN, PICO_CBM_KEY) != 0) {
            printf("ERR: decrypt failed\n");
            continue;
        }
        pico_inspect(image[0], image + 1, PICO_BODY_LEN, &rep);
        print_report(&rep);

        /* First block of the plaintext body as a bounded hex line. */
        pico_hexdump(image + 1, 16, 16, line, sizeof(line));
        printf("first block:\n%s", line);

        /* Button A: plaintext hex dump of the first 256 bytes (capped to the
         * line buffer). The operator captures this on the host if a file is
         * wanted; the board writes to no device. */
        if (!gpio_get(PIN_DUMP)) {
            pico_hexdump(image + 1, 256, 256, line, sizeof(line));
            printf("dump:\n%s", line);
        }
        /* Button B: full-body roundtrip via a scratch copy, preserving the
         * plaintext in `image` for any following dump. */
        if (!gpio_get(PIN_VERIFY)) {
            memcpy(verify_buf, image + 1, PICO_BODY_LEN);
            pico_tea_encrypt(verify_buf, PICO_BODY_LEN, PICO_CBM_KEY);
            pico_tea_decrypt(verify_buf, PICO_BODY_LEN, PICO_CBM_KEY);
            printf("roundtrip=%s\n",
                   memcmp(verify_buf, image + 1, PICO_BODY_LEN) == 0
                       ? "ok" : "FAIL");
        }
        sleep_ms(500);
    }
}
