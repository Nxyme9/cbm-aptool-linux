/* cbm_backend.h - crypto backend selection shared by CLI and dispatcher. */
#ifndef CBM_BACKEND_H
#define CBM_BACKEND_H

typedef enum {
    CBM_BACKEND_NATIVE = 0,
    CBM_BACKEND_PE = 1
} cbm_backend_t;

/* Parse one CLI flag. Returns 0 and sets *backend for a recognised flag;
 * returns nonzero and leaves *backend untouched otherwise. */
int cbm_backend_from_arg(const char *arg, int *backend);

/* Store / read the selected backend (default: CBM_BACKEND_NATIVE). */
void cbm_backend_set(int backend);
int cbm_backend_get(void);

#endif /* CBM_BACKEND_H */
