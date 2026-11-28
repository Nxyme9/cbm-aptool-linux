# Design: Community-Uses Wave 5 (5I–5K, complement to prior two specs)

Date: 2026-11-24
Status: draft (awaiting approval)

## Intent

The user selected options 2, 3 and 4 from the last brainstorm round. This
spec adds three more waves to the eight already scoped in:

- `2026-11-24-brag-rights-design.md` (5A–5D)
- `2026-11-24-wild-ideas-design.md` (5E–5H)

Total program: eleven waves. No code is written until this scope is signed off.

## Local prerequisites (checked 2026-11-24)

- `/dev/fuse` exists; `libfuse3.so` / `libfuse3.so.4` are present.
- `fuse3.h` is **absent** — libfuse3 dev headers are not installed. 5J either
  needs a gated `libfuse3-dev` install or a libfuse2 fallback; verify at build
  time. If neither works, 5J ships as a documented non-goal, not a broken build.
- Python `mcp` module is importable; JSON stdlib is present. 5I is feasible.

## 5I — MCP server + agent skill

### Approach

Add a machine-readable `--json` output mode to the container, diff, scan and
layout commands. Then a thin Python stdio MCP server (`mcp_cbm_server.py`)
calls `cbm-tool` as a subprocess and returns parsed JSON. All exposed tools
are read-only — no write or device-modifying tool is published.

### Tools

| Tool | Purpose |
|---|---|
| `cbm_container_info` | header, size, entropy, token hits for a container |
| `cbm_container_dump` | decrypt to a caller-named local path |
| `cbm_container_diff` | changed ranges between two plaintext bodies |
| `cbm_device_layout` | MBR + DJ partition validation report |
| `cbm_device_scan` | read-only container scan of a device/image |
| `cbm_entropy_profile` | entropy summary for a file or device range |

### Agent skill

`SKILL.md` in the project skill directory with triggers (`cbm container`,
`aptool`, `chipsbank`, `cbmv1001`) and a short usage contract. It must state
the read-only rule and that device writes require a separate human gate.

### Tests

`test_mcp_server.py`: validate every tool schema, mock CLI output, and run one
end-to-end call against a synthetic container fixture. Assert no tool can
request a device write.

## 5J — FUSE mount view (`cbm-fuse.c`)

### Approach

A read-only FUSE filesystem that presents the RE artifacts as files:

```
/layout.txt        DJ partition validation report
/container.bin     raw 85688-byte container
/container.plain   TEA-decrypted body (on demand)
/strings.txt       extracted printable strings
/entropy.txt       entropy profile
/report.json       combined machine-readable report
/heatmap.png       present only if 5F is built
```

No write callbacks are registered; the mount is `FUSE_READONLY` in practice.
Reads are translated to `cbm_file_read` + decrypt/inspect helpers.

### Tests

`test_cbm_fuse.sh`: mount on a temp dir, read each expected file, compare to
the direct CLI output, unmount. Gated on FUSE headers + `/dev/fuse` access;
skipped with a clear reason otherwise.

## 5K — CTF challenge + write-up (`challenge/`, `WRITEUP.md`)

### Approach

Build a synthetic 64 MiB sparse disk image with a valid DJ MBR and a planted
CBM container whose decrypted body holds a flag. Ship:

- `challenge/disk.img` generator (script, not a committed binary blob)
- `challenge/README.md` — task statement and hints
- `solver/solve.sh` — uses `cbm-tool` to find and decrypt the container
- `WRITEUP.md` — the full RE journey: mmap-at-ImageBase harness, TEA key
  recovery, container structure, real-device validation, scanner, and the
  honest gaps. This is the primary "brag rights" artifact.

### Tests

Solver extracts the known flag from a freshly generated image. CI-friendly;
no hardware, no vendor binary, no real device.

## Updated dependency order

5A → 5G → 5C → 5B → 5E → 5F → 5D → 5H → 5I → 5J → 5K

5I needs the JSON modes added in earlier waves. 5J can show the 5F heatmap.
5K's write-up covers all prior waves, so it lands last.

## Verification

1. `make clean && make && make test` passes after every wave.
2. 5I: all MCP tools return schema-valid JSON; no write tool exists.
3. 5J: mount/unmount test passes, or skip is explicitly documented.
4. 5K: solver extracts the flag from a freshly generated image.
5. `gitleaks detect --source . --no-git --redact` → no leaks.
6. Hardware honeypot, full-device scans and device writes remain separate
   gated steps.

## Honest risks

- 5I's value depends on JSON output being stable across waves.
- 5J needs dev headers that are not currently installed (gated install).
- 5K is a teaching artifact; it must not imply the commercial tool is fully
  cloned. The three documented gaps stay open and stay stated.
