# Telemetry exporter (`cbm-tool telemetry`) — Wave 5S

`cbm-tool telemetry` serves tool and device metrics to the existing
Prometheus/Grafana stack. It is **read-only**: device access is a `stat()` for
regular files or an `O_RDONLY` open plus `BLKGETSIZE64` for block devices. It
never opens a device for writing and never captures USB serials in its output.

## What it does not claim

- It does not modify the device, the image, or any counter source.
- It does not authenticate callers. `:PORT` binds **loopback only**; binding a
  routable interface (`0.0.0.0:PORT`) is an explicit opt-in by the operator.
- Counters are **not persisted by the exporter**. They come from a key=value
  state file written by the caller (a scan/trust wrapper, a systemd unit, etc.)
  and are re-read on every `/metrics` scrape. A stale file means stale metrics;
  the exporter does not pretend they are live.
- A refresh failure returns HTTP 500 rather than the last known values, so a
  broken state source cannot be mistaken for a healthy scrape.
- `device_present` means "the supplied path is observable read-only", not "the
  device is genuine" or "the device is safe" (see `docs/device-trust.md`).

## Usage

```bash
# Serve on loopback; one-shot scrape for verification
cbm-tool telemetry --listen :9101 --device /dev/sde \
    --state-file /run/cbm/state.txt
curl http://127.0.0.1:9101/metrics

# Print one exposition document and exit (no banner, clean for redirection)
cbm-tool telemetry --print --device ./disk.img --state-file state.txt

# Same values as a cbm/1 JSON document
cbm-tool telemetry --print --device ./disk.img --json
```

`--listen ADDR` accepts `:PORT` (loopback only) or a numeric `HOST:PORT`. Use
SIGINT/SIGTERM to stop the server. `--print` and `--listen` are mutually
exclusive in practice: `--print` returns one document; `--listen` runs until
signalled.

## State file format

One `key=value` per line, `#` comments and blank lines allowed. Unknown keys,
non-numeric values, a ratio outside `[0,1]`, or a missing `=` fail the whole
load (no partial update). Recognised keys:

| Key | Meaning |
| --- | --- |
| `scan_progress_ratio` | Last scan progress, 0.0..1.0 |
| `containers_found` | Containers found by the last scan |
| `cdb_commands_total` | CDB commands seen by the last capture |
| `entropy_blocks_total` | Blocks measured by the last entropy map |
| `last_validation_timestamp_seconds` | Unix time of the last validation |

Device capacity/presence and the native-crypto flag are computed by the
exporter, not read from the state file.

## Metrics

| Metric | Type | Source |
| --- | --- | --- |
| `device_present{device="..."}` | gauge | read-only probe (1 = observable) |
| `device_capacity_bytes{device="..."}` | gauge | `stat` size / `BLKGETSIZE64` |
| `scan_progress_ratio` | gauge | state file |
| `containers_found` | counter | state file |
| `cdb_commands_total` | counter | state file |
| `entropy_blocks_total` | counter | state file |
| `last_validation_timestamp_seconds` | gauge | state file |
| `crypto_backend_native` | gauge | selected backend (1 = native TEA) |

The `device` label is the canonicalised final path component only: a `/dev/disk/by-id/usb-CBM_SERIAL...` symlink renders as its resolved `sde`-style
basename, never the serial-bearing by-id path. Unresolvable paths render as
`device="unknown"`. Out-of-range/control bytes in a label are replaced with `_`.

## Grafana

Import `dashboards/cbm.json` and select a Prometheus datasource when prompted.
It has one status panel per metric plus a time-series panel for the counters;
all queries use the metric names above with no hard-coded device label, so the
same dashboard works for images and devices.

## Tests

`test_telemetry` uses a synthetic regular file, a by-id-style symlink carrying
a fake serial, and a mock state file under `/tmp/opencode`. It checks all eight
metric names and values, serial/path scrubbing, the read-only probe (present and
absent), state-file loading and fail-closed parsing, a real loopback HTTP scrape
of `/metrics`, and 404/405 handling. Its own
`test_telemetry: 8 passed, 0 failed` line is outside the frozen `Results:`
sums. No real device, Prometheus server, Grafana instance or vendor binary is
needed.

## Honest gaps

- No live wiring from the scan/trust/entropy modules into the state file is
  included; the caller writes it. This exporter is the metrics endpoint, not a
  state collector.
- No authentication, TLS or rate limiting. Keep the bind on loopback unless a
  trusted network path is arranged separately.
- A real Prometheus/Grafana deployment has not been exercised in this suite;
  the dashboard JSON is committed but not integration-tested against a live
  Grafana instance.
- Block-device telemetry on real hardware remains a separate gated step.
