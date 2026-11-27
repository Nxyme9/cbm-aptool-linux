# Distributed mesh scan (`mesh_scan.{h,c}`) — Wave 5N

`mesh_scan` splits a read-only scan of an image or block device into overlapping
byte ranges, hands each range to a worker callback, and aggregates the hits into
one deduplicated report. It exists so container discovery can scale across
machines through the existing CLS fabric — but it is deliberately built so that
nothing it reports can be mistaken for work that did not happen.

## What it does not claim

- No CLS peer is contacted by this code. The only worker shipped in-tree runs
  the 5B scanner locally; a CLS adapter plugs into the same callback and is a
  seam, not shipped remote execution. The report says `distributed` only when at
  least one range was actually answered by a peer.
- Hits are **candidates**, exactly as in the scanner: no magic value is known
  for this format, and only 512-byte-aligned starts are probed structurally.
- Nothing writes to the scanned image or device. Workers are required to be
  read-only; the in-tree worker calls `cbm_scan_image_ex`, which never writes.
- There is no peer authentication or authorisation in this wave. Do not expose a
  mesh worker to an untrusted network and treat its hits as evidence.

## Range model

`mesh_plan_ranges(start, end, chunk_bytes, ranges, max_ranges)` produces the
start offset of each range covering the inclusive byte range `[start, end]`.
Consecutive starts differ by `chunk_bytes - 171888`, where 171888 is two
85688-byte containers plus one LBA — the same overlap `cbm_scan_image` uses, so
a container straddling a range boundary is wholly inside at least one range.
Consequences:

- `chunk_bytes` must be greater than 171888; otherwise planning fails with a
  hard error rather than silently missing boundary containers.
- At most `MESH_MAX_RANGES` (4096) starts are planned. A larger scan needs a
  larger chunk or several runs.
- The last range is clipped to `end`; the planner never reads past it.

## Worker contract

```c
typedef int (*mesh_worker_fn)(void *ctx, const char *name, const char *path,
                              unsigned long long start, unsigned long long end,
                              size_t chunk_bytes, cbm_scan_hit_t **hits,
                              size_t *count, char *err, size_t errlen);
```

- `start`/`end` are an inclusive absolute byte range, already clipped.
- The worker owns the `hits` allocation; the coordinator frees it with
  `cbm_scan_free_hits`.
- Return 0 on success, -1 on failure with a message in `err`.
- `name` is a short diagnostic label. It is never emitted into the JSON report,
  so a mock or peer name cannot leak into a machine-readable result.

`mesh_scan_run` dispatches ranges round-robin across the supplied workers. A
worker that is absent, returns an error, or is missing entirely causes that
range to be retried with a local read-only scan and counted in `local_retries`.
The range is never silently dropped.

`mesh_result_t.mode` is:

- `MESH_MODE_DISTRIBUTED` — at least one range was answered by a peer.
- `MESH_MODE_LOCAL_FALLBACK` — no peer answered anything; every range ran
  locally. `mode_detail` states this in words.

`mode_detail` always names how many of how many ranges ran where, including the
partial-failure case ("distributed across N of M ranges; K ranges retried
locally").

## Aggregation and JSON

Hits from overlapping ranges are sorted by absolute offset and collapsed by
`mesh_dedup` before reporting; the same container seen twice is one hit.
`mesh_report_json` writes one deterministic `cbm/1` document with command
`mesh-scan` and the fields `mode`, `mode_detail`, `workers`, `jobs_total`,
`jobs_ok`, `local_retries`, `ranges_scanned`, `hit_count`, and a `hits` array of
`offset`, `header` and `entropy`.

## CLS adapter seam

A CLS-backed worker implements `mesh_worker_fn` by sending
`{image id or path, start, end, chunk_bytes}` to a peer that runs the same
read-only scanner, then mapping the returned JSON hits into `cbm_scan_hit_t`.
Any transport error must return -1; the coordinator then falls back to a local
scan of that range, so a broken mesh degrades into a slower but honest scan
rather than a wrong one. Peer results are candidates like local results; the
report does not attribute individual hits to peers.

## Tests

`test_mesh_scan` runs six checks on a 512 KiB synthetic regular file with
containers planted at aligned offsets 51200, 204800 and 358400 (358400 sits in
the range overlap and exercises dedup):

1. range planning covers the image with the required overlap;
2. offline fallback finds every planted container with the real scanner and
   reports `local_fallback`;
3. two mock workers split the ranges and aggregate every container, reporting
   `distributed`;
4. a failing peer's ranges are retried locally and reported honestly;
5. `mesh_dedup` collapses cross-range duplicates in ascending order;
6. the JSON report names the mode and hit count and contains no worker name.

The suite prints `test_mesh_scan: 6 passed, 0 failed`, which is outside the
frozen `Results:` sums. No device and no vendor binary is used.

## Honest gaps

- No CLS transport is implemented in-tree; remote execution is untested by
  this suite, and the adapter is the caller's responsibility.
- No peer authentication, authorisation or result signing in this wave.
- Scanner caveats apply unchanged: aligned starts only, candidates not
  confirmations, unknown magic.
- A distributed scan of real hardware remains a separate gated step.
