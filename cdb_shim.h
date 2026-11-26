/* cdb_shim.h - deterministic capture of SCSI CDBs at the PE import boundary
 *
 * Tier 1 (software only): the caller supplies these stubs as pelib import
 * hooks. Every stub returns a synthetic Win32 success; with no capture open
 * it writes nothing anywhere. No device node, vendor PE or hardware is used.
 */
#ifndef CDB_SHIM_H
#define CDB_SHIM_H

#include <stddef.h>
#include "pelib.h"

/* One capture at a time. Refuses directories, block/char devices and a
 * second concurrent capture. The path is an ordinary output file. */
int cdb_capture_open(const char *path);
void cdb_capture_close(void);
size_t cdb_capture_count(void);
const char *cdb_capture_path(void);   /* valid until close, NULL when closed */

/* NULL-terminated hook table for kernel32.dll imports. Hook names are
 * matched case-insensitively by pelib. */
const pe_import_hook_t *cdb_shim_hooks(void);

/* Record an import that has no dedicated shim: event=<dll>!<name>. */
void cdb_shim_log_unknown(const char *dll, const char *name);

#endif /* CDB_SHIM_H */
