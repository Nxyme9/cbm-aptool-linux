---
name: cbm
description: Read-only Chipsbank CBM container inspection through the local cbm-tool MCP server. Triggers include "cbm container", "aptool", "chipsbank", "cbmv1001", container decrypt/dump, device layout, scan and entropy questions.
---

# CBM container skill

Use this skill for offline inspection of CBM containers and read-only device
layout/scan questions. No vendor binary, no PE sample and no network are needed.

## Usage contract

1. Build the CLI locally with `make` so `./cbm-tool` exists at the repo root.
2. Start the stdio server with `python3 mcp_cbm_server.py` (Python `mcp` SDK).
3. Call one of the six tools with plain **local** paths. Every result is one
   JSON object with `schema: "cbm/1"`; errors carry an `error` string.
4. `cbm_container_dump(path, output_path)` writes decrypted plaintext to a
   caller-named **regular local file**. It refuses devices, URIs and any
   `output_path` that aliases the input path. It is the only local-file write.

| Tool | Required args | Read |
|---|---|---|
| `cbm_container_info` | `path` | container header, size, entropy, token hits |
| `cbm_container_dump` | `path`, `output_path` | decrypt to a local plaintext file |
| `cbm_container_diff` | `path_a`, `path_b` | changed ranges between plaintext bodies |
| `cbm_device_layout` | `path` | MBR + DJ partition validation report |
| `cbm_device_scan` | `path` | read-only container scan |
| `cbm_entropy_profile` | `path` | block entropy summary |

See [docs/mcp-server.md](../../docs/mcp-server.md) for setup and guarantees.

## Read-only rule

The server publishes **only** read-only tools: no device write, no MBR repair,
no carve, no container mutation and no `--write-back`/`--inject` flag is
reachable. Reading a local block device via `cbm_device_layout`,
`cbm_device_scan` or `cbm_entropy_profile` is allowed; writing to it is not.

Any device write or MBR repair requires a **separate human confirmation
outside this server** (run `./cbm-tool doctor ... --repair-mbr --yes --backup
<file>` yourself after verifying the backup). Never ask this server to perform
it, and never weaken the confirmation gate.
