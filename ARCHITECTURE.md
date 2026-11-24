# Architecture — cbm-aptool-linux

Linux-native port of the Chipsbank CBMUsbDisk vendor protocol. Each
subsystem maps to one source file; all are exercised by the unit suite
(39/39) and the real-device validation mode (`cbm-tool <blockdev>`).

## 1. TEA crypto core (`tea_crypto.{h,c}`)

Recovered from the vendor PE by the mmap-at-ImageBase harness (see
[PE-HARNESS.md](PE-HARNESS.md)).

| Symbol | PE address | Role |
|---|---|---|
| encrypt | `0x459da0` | CBC encrypt, `__stdcall` |
| decrypt | `0x459d50` | CBC decrypt, `__stdcall` |
| block fn | `0x459ec0` | core block transform |
| state | `0x531328` | 16-byte state, zeroed before each call |
| key derivation | `0x4fc924` → `1a2b3c4d5e6fTENG` | keyidx = 12 |
| CBC XOR | `0x45a0ff`–`0x45a177` | chaining region |

- Key: `"1a2b3c4d5e6fTENG"` (16 bytes, `TEA_KEY_LEN`).
- Block size: 8 bytes (`TEA_BLOCK_SIZE`); state size: 16 bytes.
- State is zeroed (`memset 0x531328, 0, 16`) before every encrypt/decrypt call.
- Roundtrip verified by `rtlen` (perfect inverse to L=85687) and `rttest`
  (match=1) probes before porting.

## 2. CBM container (`cbm_container.{h,c}`)

- Size: **85688 bytes** = 1-byte header + TEA-encrypted body.
- Byte 0 is the header; bytes 1..85687 are the TEA-encrypted body.
- `HLEN = ((filesize - 511) & ~7) + 511` (computed by `cbm_compute_hlen`).
- Vendor error strings surfaced during RE: `File is encrypted!`,
  `Decrypt Faile!`.
- Unit tests: `test_cbm` (4/4).

## 3. Paced writes (`paced_write.{h,c}`)

- Burst size: 40 MiB (`PACED_BURST_SIZE`).
- Cooldown: 45 s (`PACED_COOLDOWN_SEC`) between bursts.
- Prevents device lockup / controller reset on sustained writes.
- Unit tests: `test_paced` (5/5).

## 4. Linux USB mass-storage layer (`usb_mass.{h,c}`)

Standard Linux block I/O — no vendor SCSI CDBs required for the working path.

- Open: `open(2)` + `ioctl(BLKGETSIZE64)` for capacity.
- Read/write: `pread(2)` / `pwrite(2)`, offset-aware (`usb_mass_read_at`,
  `usb_mass_write_at`).
- `_FILE_OFFSET_BITS 64` defined so 32-bit builds handle >4 GiB offsets
  (scratch read at ~27.9 GiB initially failed before this fix).
- Capacity check: device must expose at least the 28 GiB window.
- Unit tests: `test_usb_mass` (3/3).

## 5. MBR / DJ layout validator (`cbm_layout.{h,c}`)

- Parses the MBR (sector 0), verifies signature `0x55AA`.
- Validates the DJ partition scheme within a 26 GiB window:
  - DJ_BOOT: 512 MiB, FAT32
  - DJ_OS: 4 GiB, ext4
  - DJ_DATA: remainder, exFAT
- Accepted stick capacity: 28 GiB (28672 MiB).
- Unit tests: `test_layout` (5/5).

## 6. NAND controller identity probe (`nand_info.{h,c}`)

- Host-observable only: reads sysfs/udev for VID/PID/vendor/model/driver.
- Classifies the controller as Chipsbank-class (VID 048d).
- Does **not** observe BCH ECC or balanced-erase policy (firmware-internal).
- Unit tests: `test_nand` (3/3).

## 7. Entry point (`main.c`)

- `cbm-tool` (no args): self-test (crypto/container/pacing/layout/nand logic).
- `cbm-tool <blockdev>`: self-test + real-device validation (read-only layout
  checks, then safe write/read/restore roundtrip in the unpartitioned tail
  outside the MBR window — no filesystem data touched).
- `cbm-tool container <path>`: file-level container mode — reads an
  85688-byte CBM container, TEA-decrypts the body, inspects it (hex dump,
  strings, stats, tokens), re-encrypts and verifies the roundtrip. Writes
  nothing unless `--output <path>` or `--write-back` is given (safe
  default); block-device targets use paced writes. Also supports `--offset`,
  `--hex-full` and `--min-string`.
- PE path overridable via `CBM_PE_PATH` env var (default
  `/tmp/opencode/ap.exe`).

## 8. File-level container I/O (`cbm_file.{h,c}`, `cbm_inspect.{h,c}`)

### 8.1 cbm_file — file/device I/O abstraction

- `cbm_file_read(path, offset, buf, len)`: read `len` bytes at absolute byte
  offset into `buf`. Returns 0 on success, -1 on error.
- `cbm_file_write(path, offset, buf, len)`: write `len` bytes from `buf` at
  absolute byte offset. Block-device targets use paced writes (40 MiB bursts
  / 45 s cooldown); regular files are written directly. Returns 0 on success,
  -1 on error.
- `cbm_file_is_blockdev(path)`: return 1 when `path` is a block device, 0
  otherwise (including stat failure).
- Backs the container mode's read/write/roundtrip path and the device
  validation flow.
- Unit tests: `test_cbm_file` (5/5).

### 8.2 cbm_inspect — container inspection

- `cbm_inspect_hex(buf, len, max_bytes, out)`: hex dump with ASCII sidebar.
  When `max_bytes > 0`, shows the first `max_bytes/2` and last `max_bytes/2`
  bytes (or all bytes when `max_bytes >= len`); when 0, shows all bytes.
- `cbm_inspect_strings(buf, len, min_run, out)`: extracts runs of printable
  ASCII (0x20–0x7e) of length >= `min_run`, printing offset and string.
  Never reads past `buf+len`.
- `cbm_inspect_stats(buf, len, out)`: prints size, printable byte count,
  unique byte count and Shannon entropy.
- `cbm_inspect_tokens(buf, len, out)`: searches for known tokens and reports
  offset + token for each hit.
- Unit tests: `test_cbm_inspect` (9/9).

## Data flow (device validation)

    /dev/sdX
      -> usb_mass_open (BLKGETSIZE64 capacity)
      -> usb_mass_read_at (sector 0 MBR)
      -> cbm_layout_parse + cbm_layout_validate (DJ scheme)
      -> nand_info_probe (Chipsbank-class?)
      -> usb_mass_read_at/write_at/read_at (scratch roundtrip at LBA scratch)
      -> usb_mass_write_at (restore original sector)
      -> verify restored

## Build

    make clean && make && make test

`CC = gcc`, `CFLAGS = -m32 -Wall -Wextra -O2 -g`. Produces `cbm-tool` plus
eight test binaries. All 39 tests pass.