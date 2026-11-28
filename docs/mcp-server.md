# Read-only MCP server

`mcp_cbm_server.py` is a stdio MCP server that exposes six thin wrappers over
the locally built `./cbm-tool <mode> --json` CLI. It needs the Python `mcp`
SDK (already available here) and a **locally built `./cbm-tool`**:

```sh
make                      # builds ./cbm-tool at the repo root
python3 mcp_cbm_server.py # stdio transport; no network listener
```

An MCP client can launch it with command `python3` and argument
`mcp_cbm_server.py`, with the working directory set to this repo. Every tool
returns one parsed JSON object carrying `schema: "cbm/1"`, `command` and
`status`. Errors are JSON objects with an actionable `error` string that
includes the CLI exit code and stderr where available. Calls use an argv list
(no shell), resolve `./cbm-tool` relative to this file, and time out after
20 seconds.

| Tool | Required args | CLI mode | Purpose |
|---|---|---|---|
| `cbm_container_info` | `path` | `container` | header, size, entropy, token hits |
| `cbm_container_dump` | `path`, `output_path` | `container --dump-plain` | decrypt to a caller-named local plaintext file |
| `cbm_container_diff` | `path_a`, `path_b` | `diff` | changed ranges between two plaintext bodies |
| `cbm_device_layout` | `path` | `doctor` | MBR + DJ partition validation report |
| `cbm_device_scan` | `path` | `scan` | read-only container scan of an image or device |
| `cbm_entropy_profile` | `path` | `heatmap` | entropy summary for a file or device range |

`path` values must be plain local paths: URIs, UNC paths, flag-looking paths
and NUL bytes are rejected. Read tools accept local images and block devices;
they never open a target for writing.

## Read-only guarantee

Exactly six tools are registered, all annotated `readOnlyHint=True`,
`destructiveHint=False`, `idempotentHint=True`, `openWorldHint=False`. There is
**no** tool that writes to a device, repairs an MBR, carves to arbitrary
paths, injects a body, mutates a container or requests `--write-back`.

`cbm_container_dump` is the only tool that writes a file: decrypted plaintext
to a caller-named regular local path. It refuses device-like targets and any
`output_path` equal to (or aliasing) the input container. All other tools are
strictly read-only.

Device writes and MBR repair remain separate gated CLI operations that require
explicit human confirmation **outside** this server; see
[skills/cbm/SKILL.md](../skills/cbm/SKILL.md).

## Tests

`test_mcp_server.py` runs offline with synthetic regular-file fixtures under
`/tmp/opencode`: it checks the six registered tool names and annotations,
rejects write/repair tools, checks argv/JSON wiring for every tool, a real CLI
schema pass-through, device/input-path rejection, error text and timeout. It
is wired into `make test` (and `make ci`) on its own result line.
