# Wave 5J — read-only FUSE3 view

`cbm-fuse` is a read-only FUSE3 view of the existing CBM reverse-engineering
artifacts. It follows `docs/superpowers/specs/2026-11-24-community-uses-design.md`
§5J (lines 56–79). It presents a container or image as a flat directory of
virtual files; every byte is produced by helpers already used by `cbm-tool`.
No vendor PE is loaded, no device is opened for writing, and MBR repair is not
available through the mount.

## Usage

```text
cbm-fuse <container|image> <mountpoint> [--container-offset N] \
         [--window-gib 26|27|28] [--allow-device] [fuse options...]
```

`<mountpoint>` must already exist and be an empty directory. `<source>` must be
a regular file or a block device; a block device is refused unless
`--allow-device` is given, and is still read-only. `--container-offset` defaults
to 0, `--window-gib` defaults to 26, and ordinary libfuse options such as
`-f -s` are passed through. `fuse_main` owns SIGINT/SIGTERM handling and
unmounts cleanly; the binary restores the default SIGINT disposition first so a
process started from a background shell still gets that handler.

## Build

From the repository root, with `gcc`, `pkg-config` for `fuse3`, and zlib
available (`fuse3` 3.18.3 was measured here):

```sh
gcc -O2 -g -Wall -Wextra -Wformat=2 -Werror=format-security -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wvla -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64 -I. $(pkg-config --cflags fuse3) -DCBM_FUSE_WITH_HEATMAP=1 -o cbm-fuse cbm-fuse.c cbm_file.c paced_write.c cbm_container.c tea_crypto.c tea_native.c pelib.c cbm_inspect.c cbm_decode.c cbm_doctor.c cbm_layout.c cbm_scan_report.c entropy_map.c cli_json.c png_write.c $(pkg-config --libs fuse3) -lz
```

This is intentionally a documented command, not a Makefile target. The
`-DCBM_FUSE_WITH_HEATMAP=1` flag is the compile-time gate for the 5F PNG builder;
with it, `heatmap.png` is listed in the mount and the PNG sources are linked.
Without that flag, `heatmap.png` is not exposed and the `heatmap` object is
omitted from `report.json`. When testing such a build, run
`CBM_FUSE_EXPECT_HEATMAP=0 sh ./test_cbm_fuse.sh`.

## Virtual files and their provenance

| Path | Provenance |
| --- | --- |
| `/layout.txt` | The unmodified doctor prose report for `<source>` at the selected `--window-gib`, generated with `cbm_doctor_report` + `cbm_doctor_cli_ex` and the `main.c` banner. It is byte-for-byte `./cbm-tool doctor <source> --window-gib N` and is always a dry run. |
| `/container.bin` | Exactly 85688 bytes (`CBM_CONTAINER_SIZE`) read from `<source>` at `--container-offset` through `cbm_file_read`. |
| `/container.plain` | The 85687-byte body after `cbm_cbc_decrypt` with the native TEA key. `fv_prepare` proves `encrypt(decrypt(x)) == x` before exposing it; it matches `./cbm-tool container <source> --offset N --dump-plain`. |
| `/strings.txt` | `cbm_inspect_strings(body, 85687, 4, ...)`: the printable-string section with minimum length 4. |
| `/entropy.txt` | Fixed-point `entropy_body` header from `cbm_decode_entropy`, followed by the 64-byte `cbm_decode_profile` rows. |
| `/report.json` | One compact `cbm/1` object with nested `container`, `doctor`, optional `heatmap`, and `files` objects/arrays. Its scalar fields agree with the bare `--json` CLI reports. |
| `/heatmap.png` | Present only with `-DCBM_FUSE_WITH_HEATMAP=1`. Built lazily from `cbm_entropy_map` + `cbm_entropy_downsample` + `png_write_rgb` through a `memfd_create` path, so no on-disk artifact is created. Bytes match `./cbm-tool heatmap <source> --out ...` with the 1 MiB block / 1024 width defaults. |

## Read-only guarantee

The FUSE operation table registers only `getattr`, `readdir`, `open`, `read`,
and `destroy`; no `write`, `create`, `unlink`, `rename`, `chmod`, `truncate`, or
`setattr` callback exists. `open` rejects any write-mode or create/truncate/
append descriptor with `-EROFS`. The root is mode `0555` and virtual files are
mode `0444`. Source bytes are obtained with read-only `cbm_file_read` calls and
a strictly `O_RDONLY` size probe; there is no `--write-back`, no `pwrite`, no
device write, and no MBR repair path in the mount.

## Test gate

```sh
sh ./test_cbm_fuse.sh
```

The gate runs first and in this order: `pkg-config`/`fuse3` headers,
`/dev/fuse` as a readable/writable character device, `fusermount3`, and finally
a real mount permission probe in a scratch directory under `/tmp/opencode`.
Only after all four pass does the script compare each virtual file against the
direct CLI output, check write/create refusal, assert that no write callback is
registered, and verify clean SIGTERM/SIGINT unmounts. If a gate fails it prints
`SKIP <reason>` and exits 0. The script never uses `sudo`, never touches a real
device, and builds its containers from synthetic regular files.

## Out of scope

Device writes, MBR repair, vendor PE loading, and real-device validation are
deliberately out of scope for `cbm-fuse` and its test. The device-validation
workflow remains a separate human-gated step documented in
[device-validation.md](device-validation.md).
