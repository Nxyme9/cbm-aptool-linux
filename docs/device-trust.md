# Device trust scanner (`cbm-tool trust`) — Wave 5P

`cbm-tool trust` compares a **host-observable** USB fingerprint against a
known-good baseline and reports every mismatch with a severity. It is aimed at
the BadUSB case: a Chipsbank-class stick that has been reflashed to expose an
unexpected interface (for example an HID keyboard) or to emit unknown commands.

## What it does not claim

- It never inspects firmware. Findings are descriptor-level and are labelled
  `host-observable`.
- It never opens the device for I/O. A block device is observed through
  read-only sysfs attributes; an observation JSON can be supplied instead.
- A firmware claim is refused unless a real dump supplied a marker. Even then
  the marker comparison is a warning, not an attestation.
- A clean result means "this fingerprint matches the baseline", not "this
  device is safe".

## Usage

```bash
# Observe a USB block device through sysfs (read-only) and compare
cbm-tool trust /dev/sde --baseline baseline.json

# Compare a previously captured observation (no device needed)
cbm-tool trust observation.json --baseline baseline.json

# Machine-readable result
cbm-tool trust observation.json --baseline baseline.json --json
```

- `--baseline <json>` is required. Without it the scan **fails closed** with
  `Error: --baseline <json> is required; refusing to certify ...`.
- Exit codes: `0` trusted, `1` findings or fail-closed error, `2` usage error.

## Profile schema

Baseline and observation files use the same small JSON object:

```json
{
  "vid": "0x1234",
  "pid": "0x5678",
  "product": "Chipsbank USB Disk",
  "serial": "REDACTED",
  "interfaces": [ { "class": 8, "subclass": 6, "protocol": 80 } ],
  "cdbs": ["28 00 00 00 00 00 00 00 10 00"],
  "firmware_marker": null
}
```

- `vid`, `pid`: required, 16-bit numbers (decimal or `0x` hex, quoted or bare).
- `product`: optional string, at most 63 bytes.
- `serial`: **parsed but never stored or compared**; baselines keep it
  redacted.
- `interfaces`: optional array of `class`/`subclass`/`protocol` objects
  (each 0..255), at most 16.
- `cdbs`: optional array of hex byte strings (1..16 bytes each), at most 32.
  These come from the wave 5E capture, not from the device.
- `firmware_marker`: `null`, or a string only when a real dump supplied one.

Files are capped at 1 MiB. Unknown keys are ignored.

## Severities

| Code | Severity | Meaning |
|---|---|---|
| `usb-id` | critical | VID/PID differs from the baseline |
| `iface-extra-hid` | critical | an HID interface (class 3) is present that the baseline does not list |
| `iface-extra` | warning | another unexpected interface is present |
| `iface-missing` | warning | a baseline interface is absent |
| `product` | warning | the product string changed |
| `cdb-unknown` | warning | an observed CDB is not in the baseline |
| `fw-marker-changed` | warning | the supplied firmware marker differs from the baseline |
| `cdb-not-observed` | info | no CDB behaviour was supplied |
| `fw-unverified` | info | no firmware dump exists; findings are host-observable only |

`trusted` means zero critical and zero warning findings. Info findings never
change the verdict.

## Sysfs observation limits

For a USB block device the scanner resolves
`/sys/class/block/<dev>/device`, walks up to the USB device directory, reads
`idVendor`, `idProduct`, `product`, and every `bInterfaceClass` /
`bInterfaceSubClass` / `bInterfaceProtocol` attribute. CDB behaviour and
firmware markers are not observable there, so they stay empty and the report
says so (`cdb-not-observed`, `fw-unverified`). If the sysfs path cannot be
resolved, the scan fails closed and tells you to pass an observation JSON
instead of guessing.

## Tests

`test_trust` covers parsing, identity/product/interface/CDB/firmware
comparisons, fail-closed behaviour and the JSON contract on synthetic files
under `/tmp/opencode`; no device and no vendor binary are used. Its summary
line (`test_trust: N passed, M failed`) is outside the frozen `Results:` sums.
