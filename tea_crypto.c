/* tea_crypto.c - CBMUsbDisk crypto dispatcher
 *
 * Backends:
 *   native (default) - clean-room pure-C cipher in tea_native.c
 *   PE harness       - pelib fixed-base PE loader for the vendor TEA cores,
 *                      opt-in cross-check via --pe-crypto
 *
 * The public tea_* API keeps its signatures, so callers (cbm_container.c and
 * the existing test suites) automatically use the selected backend. There is
 * no silent fallback: if the requested backend cannot initialise, tea_init
 * fails and tea_encrypt/tea_decrypt refuse to run.
 *
 * PE cores: encrypt 0x459da0, decrypt 0x459d50, block fn 0x459ec0,
 * state 0x531328. PE functions use __stdcall (callee cleans stack).
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "tea_crypto.h"
#include "cbm_backend.h"
#include "tea_native.h"
#include "pelib.h"

/* PE-core entry points are specified as RVAs; pelib maps the image at
 * ImageBase 0x400000 and resolves them through the loaded image. */
#define TEA_ENCRYPT_RVA 0x59da0u   /* VA 0x459da0 */
#define TEA_DECRYPT_RVA 0x59d50u   /* VA 0x459d50 */

static int g_ready = 0;
static pe_image_t *g_pe_img = NULL;
static int g_backend = CBM_BACKEND_NATIVE;

int cbm_backend_from_arg(const char *arg, int *backend) {
    if (!arg || !backend) return -1;
    if (strcmp(arg, "--native-crypto") == 0) {
        *backend = CBM_BACKEND_NATIVE;
        return 0;
    }
    if (strcmp(arg, "--pe-crypto") == 0) {
        *backend = CBM_BACKEND_PE;
        return 0;
    }
    return -1;
}

void cbm_backend_set(int backend) {
    if (backend == CBM_BACKEND_NATIVE || backend == CBM_BACKEND_PE)
        g_backend = backend;
}

int cbm_backend_get(void) { return g_backend; }

/* Invoke one PE core through pelib's 3-word __stdcall ABI: args[0] is the
 * caller buffer address, args[1] the byte length and args[2] the key address.
 * pe_call_void also zeroes the 16-byte TEA state (VA 0x531328) immediately
 * before the call, so no second reset is done here. */
static int tea_call_pe(uint32_t rva, unsigned char *buf, size_t len,
                       const char *key) {
    uint32_t args[3];

    if (!g_pe_img || !buf || !key) return -1;
    args[0] = (uint32_t)(uintptr_t)buf;
    args[1] = (uint32_t)len;
    args[2] = (uint32_t)(uintptr_t)key;
    if ((size_t)args[1] != len) return -1; /* 32-bit length truncation */
    return pe_call_void(g_pe_img, rva, args, sizeof args);
}

int tea_init(const char *pe_path) {
    if (g_ready) return 0;

    if (g_backend == CBM_BACKEND_NATIVE) {
        /* Pure-C cipher: no vendor binary, no mmap, no PE state to load. */
        g_ready = 1;
        return 0;
    }

    /* PE backend: an explicit path is required (via pe_path or CBM_PE_PATH) —
     * no silent fallback to a default image when the caller asked for PE. */
    if (!pe_path || !pe_path[0]) {
        pe_path = getenv("CBM_PE_PATH");
        if (!pe_path || !pe_path[0]) return -1;
    }
    if (pe_load(&g_pe_img, pe_path, NULL) != 0) {
        g_pe_img = NULL;
        return -1;
    }
    g_ready = 1;
    return 0;
}

void tea_cleanup(void) {
    pe_unload(g_pe_img); /* idempotent; clears pelib's singleton */
    g_pe_img = NULL;
    g_ready = 0;
}

int tea_is_ready(void) { return g_ready; }

int tea_encrypt(unsigned char *buf, size_t len, const char *key) {
    if (!g_ready) return -1;
    if (g_backend == CBM_BACKEND_NATIVE)
        return tea_native_encrypt(buf, len, key);
    return tea_call_pe(TEA_ENCRYPT_RVA, buf, len, key);
}

int tea_decrypt(unsigned char *buf, size_t len, const char *key) {
    if (!g_ready) return -1;
    if (g_backend == CBM_BACKEND_NATIVE)
        return tea_native_decrypt(buf, len, key);
    return tea_call_pe(TEA_DECRYPT_RVA, buf, len, key);
}
