# Device Validation — /dev/sde (Chipsbank)

Date: 2026-11-24. Serial redacted.

## Device

- Path: `/dev/sde`
- Controller: Chipsbank (VID 048d / PID 1234), usb-storage
- Capacity: 500 GiB (536870912000 bytes, BLKGETSIZE64)
- Driver: usb-storage

## Results

| Check | Result |
|---|---|
| MBR signature | `0x55AA` OK |
| Partition count | 3 (DJ_BOOT / DJ_OS / DJ_DATA) |
| DJ partition layout | MATCH (512 MiB / 4 GiB / rest, within 28 GiB window) |
| NAND controller identity | Chipsbank-class: YES |
| Capacity >= 28 GiB window | YES |
| Write/read roundtrip (scratch LBA) | OK |
| Original sector restored & verified | OK |
| Real-device validation overall | **PASS** |

## Scratch roundtrip location

LBA 54526976 (unpartitioned tail, outside the MBR/DJ window — no
filesystem data touched). Pattern written, read back, verified, original
sector restored and re-verified.

## Caveats (host-observable only)

- BCH ECC strength: not observable from host.
- Balanced-erase policy: not observable from host.
- Bad-block map: not observable from host.
- Controller firmware version: not queried.

These are firmware-internal (see [GAPS.md](../GAPS.md), Gap 3).