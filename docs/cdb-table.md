# CDB capture table (wave 5E / G1-a)

Status: **tier 1 only — software IAT shims, no hardware**. A synthetic PE is
loaded through `pelib` with `cdb_shim_hooks()`; `DeviceIoControl`,
`CreateFileA`, `CreateFileW` and `CloseHandle` return synthetic success values
and log their inputs. No device node, USB gadget, vendor PE or vendor DLL was
used to produce any row below.

**An empty capture is a valid published outcome. No completeness is claimed
here:** this table records only what the shims actually saw, and an untested
control code is not evidence that the frontend never uses it.

Risk stated in the wave 5E spec: **if the frontend delegates to the encrypted
DLL, the capture is empty and Gap 1 stays open.** G1-b (running the capture
against the user's own PE) has **not run**; every vendor-PE cell below is
`not observed`.

Tier 2 (a USB-gadget honeypot presenting VID 048d / PID 1234 and logging
CBW/CDB traffic) is **source-only and not run**. It remains a separate gated
hardware step; a green software test says nothing about it.

## Exact capture line format

The capture is a plain UTF-8/ASCII text file with LF endings, lowercase hex,
two digits per byte, single spaces between bytes and no trailing spaces.
Every logged line is one record; `cdb_capture_count()` counts those records.
The first line is always exactly:

```
cbm-cdb-capture/1
```

Each following line has one of these shapes:

```
event=DeviceIoControl ctrl=0x%08x in_len=%u in=%s[ truncated=1][ cdb_len=%u cdb=%s]
event=CreateFileA path=%s access=0x%08x
event=CreateFileW wide=1 path_hex=%s
event=<dll>!<name>
```

- `in=` is the raw input buffer in space-separated hex. Only the first 256
  bytes are logged; when `in_len > 256`, ` truncated=1` is appended **before**
  any `cdb` field. The input buffer is never modified.
- `cdb_len` / `cdb` appear **only** for `0x0004D004` and `0x0004D014`, and only
  when the buffer actually contains the CDB. The logged length is
  `min(CdbLength, 16, in_len - CdbOffset)`; a CDB that fails that bounds check
  is never claimed. No other control code is decoded.
- `CreateFileA` paths are escaped: printable ASCII is verbatim except space,
  `%`, `=` and `\`, each written as `\xNN`; other bytes are also `\xNN`.
- `path_hex` is the wide path's raw little-endian UTF-16 code-unit bytes, as
  contiguous lowercase hex, up to the first NUL.
- `event=<dll>!<name>` is for an import with no dedicated shim; it carries no
  invented fields. `CloseHandle` returns success and logs no record.

The CLI spelling is:

```
cbm-tool cdb-capture <pe-path> --out <capture-file> [--export <name>] [--arg0 N] [--arg1 N] [--arg2 N]
```

`<pe-path>` is mandatory for this mode and never falls back to `CBM_PE_PATH`.
A missing export still writes the header, exits 1, and preserves the empty
result.

## Observed / not observed

| Control code | Structure | CDB offset | Observed (synthetic) | Observed (vendor PE) | Notes |
| --- | --- | --- | --- | --- | --- |
| `0x0004D004` (`IOCTL_SCSI_PASS_THROUGH`) | `SCSI_PASS_THROUGH` | `Cdb[]` @ 24, `CdbLength` @ 6 | 6-byte CDB `2a 00 00 00 00 00` from `test_cdb_shim` | not observed | Input buffer verified byte-identical after the call; output zeroed to the 512-byte synthetic cap. |
| `0x0004D014` (`IOCTL_SCSI_PASS_THROUGH_DIRECT`) | `SCSI_PASS_THROUGH_DIRECT` | `Cdb[]` @ 28, `CdbLength` @ 6 | not observed | not observed | Decoding path implemented with the same bounds rule; no synthetic fixture exercised it. |
| any other code | none | none | raw `in=` only from `test_cdb_shim` (`0x80000000`) | not observed | Never decoded as a CDB; `truncated=1` proven at `in_len=300`. |

The synthetic fixture and its byte-exact expected capture live in
`test_cdb_shim.c`. Re-run the check with `make test_cdb_shim && ./test_cdb_shim`.
No row above comes from `ap.exe`, `CBMUSBSys.sys`, `CBMUsbDrv*.dll`, a serial
number or a USB capture.
