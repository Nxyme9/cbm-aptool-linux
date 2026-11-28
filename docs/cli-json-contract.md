# CLI JSON contract (`cbm/1`)

Every CLI mode accepts a bare `--json` flag that prints **one compact JSON
object** on stdout and suppresses the human prose on stdout. It does not change
the mode's exit code, and it never writes to the target device or image unless
the mode's own explicit write flags are present. The emitter lives in
`cli_json.{h,c}`; there is no third-party JSON library.

## Envelope

Success and error objects share a fixed prefix, in this order:

```json
{"schema":"cbm/1","command":"<mode>","status":"ok", ...}
```

- `schema` is always the literal string `cbm/1`.
- `command` is the mode name: `container`, `diff`, `fuzz`, `scan`, `heatmap`,
  `doctor` or `cdb-capture`.
- `status` is `ok` on success or `error` on failure.
- An error object adds a single `"error"` string field. The string is the
  captured human error text with newlines/tabs collapsed to spaces.

```json
{"schema":"cbm/1","command":"container","status":"error","error":"Error: ..."}
```

On failure stdout carries only the error object; on success it carries only the
success object. The human error message is **always** replayed byte-for-byte on
stderr, including in JSON mode, so scripts can log it and humans can still read
it. Exit codes are exactly the same as prose mode (including `1` for a failed
operation and `2` for usage errors). A failed parse is visible as
`"status":"error"`; no partial success object is emitted.

Numbers are locale-independent. Entropy-style fields use six decimal places
and the same `[0,8]` clamp as the human output, so the two formats never
disagree. Strings escape `"` and `\` plus the standard short control escapes;
other C0 bytes become `\u00xx`.

## `--json` as a flag vs. as a sidecar path

`scan` and `heatmap` historically use `--json <report.json>` to write a JSON
**sidecar file**. That spelling is preserved byte-for-byte: `--json` followed
by a token that does not start with `-` is still a sidecar path, not the bare
flag. bare `--json` is recognised when it is the last token or the next token
starts with `-`. Both spellings may appear on one command line, in any order:

```sh
./cbm-tool scan disk.img --all-hits --json                 # bare: stdout object
./cbm-tool scan disk.img --json report.json                # sidecar only
./cbm-tool scan disk.img --json report.json --json         # both
```

`container`, `diff`, `fuzz`, `doctor` and `cdb-capture` have no sidecar, so
`--json` is always the bare flag in those modes. Note that the bare stdout object and the sidecar
file are **different documents**: the sidecar keeps its original shape
(`scan` writes an array of hits; `heatmap` writes an object with
`block_bytes`/`samples`/`width`/`height`/`entropy`/`regions`), while the bare
object uses the `cbm/1` envelope below.

## Stable fields by mode

Field names and scalar/array types are part of the contract. Additional fields
may be added later, but existing names and types will not change.

| mode | fields (after the envelope) |
| --- | --- |
| `container` | `path` (string), `backend` (string, `native` or `pe`), `header_byte` (u64), `encrypted` (bool), `body_len` (u64), `entropy_body` (fixed-6 number), `roundtrip_ok` (bool) |
| `diff` | `a`, `b` (strings), `body_len_a`, `body_len_b`, `context`, `entropy_body_a`, `entropy_body_b`, `changed_ranges`, `changed_bytes` (numbers; `changed_ranges` is the count of spans) |
| `fuzz` | `path` (string), `seed`, `rounds`, `mutations` (numbers), `out` (string), `corpus_verified` (bool) |
| `scan` | `path` (string), `start_lba`, `end_lba`, `candidates`, `all_hits` (number/number/number/bool), `hits` (array) |
| `scan.hits[]` | `offset`, `header` (numbers), `entropy` (fixed-6 number), `sha256` (string), `tokens` (array of `{"offset":N,"text":"..."}`) |
| `heatmap` | `path` (string), `block_bytes`, `samples`, `width`, `height` (numbers), `entropy` (object), `regions` (array) |
| `heatmap.entropy` | `min`, `mean`, `max` (fixed-6 numbers) |
| `heatmap.regions[]` | `name` (string), `offset`, `length`, `samples` (numbers), `min`, `mean`, `max` (fixed-6 numbers), `inferred` (bool) |
| `doctor` | `path` (string), `window_gib` (number), `mbr_valid` (bool), `partitions` (array), `repair_performed` (bool), `dry_run` (bool) |
| `doctor.partitions[]` | `name` (string), `start_lba`, `sectors`, `type` (numbers), `inferred` (bool) |
| `cdb-capture` | `path` (string, PE path), `capture` (string, output file), `export` (string, empty when absent), `called` (bool), `events` (number, capture records) |

The JSON reports only what was measured. In `doctor`, `partitions` is parsed
from the target's actual first sector; an unparsable sector yields `[]`, never
the nominal layout candidate presented as a measurement. `window_gib` is
derived from the measured image size.

## `doctor` is the layout JSON surface

There is **no separate `layout` subcommand**. MBR/layout inspection is the
`doctor` mode, and `doctor --json` is its machine-readable form. The
`cbm_layout_*` library functions remain available to C callers, but they are
not exposed as another CLI command.

## Verification

`test_json_cli.sh` builds synthetic fixtures under `/tmp/opencode` (including a
tiny PE32 with one export for `cdb-capture`) and checks all eight success modes,
four error modes, the missing-export empty-capture header, and the
scan/heatmap sidecar byte-for-byte behaviour using
`python3 -c 'import json,sys; ...'`. It is part of `make test` / `make ci`.
No device, hardware or vendor PE is involved.
