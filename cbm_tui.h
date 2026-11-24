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
    size_t term_width;
    size_t term_height;
} cbm_tui_state_t;

/* Return a malloc'd ANSI frame for the given terminal size, or NULL on OOM.
 * Layout degrades from full (80x24) to compact (40x15) to tiny (>0) to a
 * single valid line (0 dimensions). Every cursor-addressed line is complete
 * (ends with EL) and content is bounded by the requested width. */
char *cbm_tui_render(const cbm_tui_state_t *st, size_t width, size_t height);

#endif /* CBM_TUI_H */
