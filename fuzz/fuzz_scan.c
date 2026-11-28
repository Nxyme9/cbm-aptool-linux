/* libFuzzer harness: in-memory structural container scan.
 * The scanner is read-only; no file, device or PE is opened. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cbm_scan.h"
#include "cbm_container.h"
#include "tea_crypto.h"

/* Two containers plus one LBA of overlap, as required by cbm_scan_image. */
#define SCAN_BYTES (2u * CBM_CONTAINER_SIZE + 512u)
#define MAX_HITS 8u

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    /* Native clean-room backend: no vendor binary is loaded. */
    return tea_init(NULL) == 0 ? 0 : -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char *buf;
    cbm_scan_hit_t hits[MAX_HITS];
    const char *const magics[] = { "cbmv1001" };

    if (size == 0) return 0;
    buf = (unsigned char *)malloc(SCAN_BYTES);
    if (!buf) return 0;

    /* Repeat the fuzz input so the scanner always sees a full candidate
     * window without ever reading outside the allocation. */
    for (size_t i = 0; i < SCAN_BYTES; i++) buf[i] = data[i % size];

    (void)cbm_scan_buffer(buf, SCAN_BYTES, magics, 1u, 1u, 0ULL,
                          hits, MAX_HITS);
    free(buf);
    return 0;
}
