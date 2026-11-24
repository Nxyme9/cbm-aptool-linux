/* libFuzzer harness: MBR parse, nominal construction and DJ validation.
 * Pure layout logic: no file, device or PE access. */
#include <stdint.h>
#include <string.h>

#include "cbm_layout.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char mbr[CBM_SECTOR_SIZE];
    unsigned char built[CBM_SECTOR_SIZE];
    cbm_layout_t layout;
    unsigned long long window_gib;
    char err[128];

    memset(mbr, 0, sizeof(mbr));
    if (size > 0) memcpy(mbr, data, size < sizeof(mbr) ? size : sizeof(mbr));

    memset(&layout, 0, sizeof(layout));
    if (cbm_layout_parse(mbr, sizeof(mbr), &layout) == 0)
        (void)cbm_layout_validate(&layout, layout.disk_sectors);

    /* Nominal geometry must reject impossible windows cleanly. */
    window_gib = (size >= 8u) ? (unsigned long long)(data[0] % 64u) : 26ULL;
    (void)cbm_layout_construct(window_gib, built, err, sizeof(err));
    return 0;
}
