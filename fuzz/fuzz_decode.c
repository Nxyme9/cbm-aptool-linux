/* libFuzzer harness: entropy and region classification.
 * Pure functions only: no file, device or PE access. */
#include <stdint.h>
#include <stdlib.h>

#include "cbm_decode.h"

#define MAX_REGIONS 256u

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cbm_region_t regions[MAX_REGIONS];

    if (size == 0) return 0;

    (void)cbm_decode_entropy(data, size);
    (void)cbm_decode_regions(data, size, regions, MAX_REGIONS);
    return 0;
}
