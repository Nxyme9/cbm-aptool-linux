# exFAT undelete carver (`exfat_carver.{h,c}`) — Wave 5R

`exfat_carve` reads an exFAT volume **read-only** and reports deleted files
whose metadata is still intact. It is aimed at the DJ_DATA partition (type
`0x07`) of the known CBM layout, but also accepts any explicit byte offset for
offline images. Recovered bytes go **only** to a caller-named local output
directory; the source image or device is never written.

## What it does not claim

- It does not recover fragmented files: a stream entry without `NoFatChain` is
  reported `lost`, never reassembled by guessing.
- It does not recover overwritten files: if the allocation bitmap marks any
  data cluster as allocated (bit set), the entry is reported `lost` and no
  bytes are written.
- It does not carve live entries (`0x85`); only deleted entries (`0xE5`) are
  considered.
- A `lost` result means "the metadata is insufficient for a safe carve", not
  "the bytes no longer exist on the medium".
- This is a clean-room exFAT reader for the documented DJ layout; no vendor
  binary, no emulator and no real device is used in tests.

## API

```c
int exfat_carve(const char *path, unsigned long long base, const char *outdir,
                exfat_report_t *report, char *err, size_t errlen);
int exfat_carve_dj_data(const char *path, const char *outdir,
                        exfat_report_t *report, char *err, size_t errlen);
void exfat_report_free(exfat_report_t *report);
void exfat_report_json(FILE *out, const exfat_report_t *report);
```

- `path` may be a regular file or a block device; opens are read-only.
- `base` is the absolute byte offset of the volume (or derived from the MBR by
  `exfat_carve_dj_data`, which uses `cbm_layout_parse` and partition type
  `0x07`).
- `outdir` must already exist; it is the only place recovered bytes are
  written, using the UTF-16LE name decoded from the name entry.
- Return value: `0` on success with `report` filled (caller frees it), `-1` on
  parse or I/O error with a message in `err`.
- Each report entry has `name`, `first_cluster`, `size`, `outcome` (`recovered`
  or `lost`) and a `detail` reason. `exfat_report_json` emits one deterministic
  `cbm/1` document.

## What is validated before a carve

1. Boot sector signature `EXFAT   ` at offset 3 and `0x55AA` at offset 510.
2. Sector-size exponent in `[9,12]` (512..4096 bytes) and a valid cluster size.
3. Allocation bitmap entry (`0x81`) in the root directory, read from its
   recorded cluster with the recorded byte length (capped at 1 MiB).
4. For each deleted file entry (`0xE5`): contiguous stream (`NoFatChain` set),
   first cluster `>= 2`, all needed clusters inside the volume's cluster count,
   and every data cluster free in the bitmap.

Only when all four hold are bytes carved. Anything else becomes a `lost`
entry with a reason. Out-of-range bitmap indices fail closed as allocated.

## Limits

- Cluster heap and bitmap are read in bounded buffers; a bitmap larger than
  1 MiB is refused rather than trusted.
- Names are decoded from at most 15 UTF-16LE code units per name entry; in this
  clean-room reader ASCII-range code units are kept and others are skipped.
  This avoids path traversal from crafted names.
- exFAT only, intact-metadata cases only. FAT32 DJ_BOOT, ext4 DJ_OS,
  fragmented files, overwritten clusters and encrypted containers are out of
  scope.

## Tests

`test_exfat_carver` builds a synthetic 16-sector exFAT image under
`/tmp/opencode` with root cluster, allocation bitmap, one intact deleted file,
one overwritten deleted file and one live file. It checks:

1. the intact deleted file is recovered byte-for-byte and the live file is not
   carved;
2. the overwritten file is reported `lost` and no guessed bytes are written;
3. a corrupt boot sector fails cleanly with an error and an empty report;
4. the JSON report names both outcomes and omits the live file;
5. `exfat_carve_dj_data` locates the volume at the nominal DJ_DATA LBA from a
   synthetic MBR.

Its `test_exfat_carver: 5 passed, 0 failed` line is outside the frozen
`Results:` sums. No device, emulator or vendor binary is used.

## Honest gaps

- No real DJ_DATA partition from a physical device has been carved; hardware
  validation remains a separate gated step.
- Upcase tables, volume labels and multi-cluster root directories are parsed
  only for the allocation bitmap entry; other metadata is not interpreted.
- Deleted entries whose secondary entries were themselves overwritten are not
  recovered.
