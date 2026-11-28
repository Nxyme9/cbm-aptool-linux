/* cbm_tui.h - pure ANSI TUI renderer (Wave 5D)
 *
 * cbm_tui_render is a PURE function of its inputs: no tty, no device, no file
 * and no global state. The caller supplies all data gathered by read-only
 * diagnosis and terminal dimensions; the returned malloc'd string is owned by
 * the caller and must be free()d. The TUI never opens the target for writing.
 */
#ifndef CBM_TUI_H
#define CBM_TUI_H

#include <stddef.h>

typedef struct {
    char name[16];
    unsigned long long start_lba;
    unsigned long long sectors;
    unsigned char type;
    int inferred;
} cbm_tui_part_t;

typedef struct {
    char target[256];
    unsigned long long size_bytes;
    unsigned long long window_gib;
    int is_blockdev;
    char mbr_status[32];
    char dj_status[32];
    cbm_tui_part_t parts[4];
    int part_count;
    unsigned long long scan_hits;
    unsigned long long last_hit_offset;
    double entropy_min;
    double entropy_mean;
    double entropy_max;
    char backend[32];
    /* Caller-filled first-sector bytes for the scrollable two-row hex view.
     * hex_scroll is an index in 16-byte rows, clamped to [0, hex_len/16]. */
    unsigned char hex[512];
    size_t hex_len;
    size_t hex_scroll;
    size_t term_width;
    size_t term_height;
} cbm_tui_state_t;

/* Return a malloc'd ANSI frame for the given terminal size, or NULL on OOM.
 * Layout degrades from full (80x24) to compact (40x15) to tiny (>0) to a
 * single valid line (0 dimensions). Every cursor-addressed line is complete
 * (ends with EL) and content is bounded by the requested width. */
char *cbm_tui_render(const cbm_tui_state_t *st, size_t width, size_t height);

/* Move the hex view by ONE 16-byte row (not 16 rows) per key press.
 * 'n' adds 1 and 'p' subtracts 1 (floor 0); other keys leave scroll alone.
 * An empty buffer always yields 0; 'n' is clamped to hex_len/16 and to the
 * fixed hex buffer so the row index can never read past either. Pure (no I/O). */
size_t cbm_tui_hex_scroll(int key, size_t scroll, size_t hex_len);

#endif /* CBM_TUI_H */
