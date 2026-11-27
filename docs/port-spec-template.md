# Port-spec template (`.mind`-style, `cbm-port-spec/1`)

One file per vendor tool. Copy this block verbatim into
`mind/specs/<tool>-port-spec.mind` (or a local file with the same shape), then
replace only the values. Keep the five section keys: the point is to make
every port state its evidence, not just its conclusions.

```json
{
  "schema": "cbm-port-spec/1",
  "tool": "<vendor tool name>",
  "target": "<artifact id: PE hash / version / observed section map>",
  "sections": {
    "key_recovery": {
      "status": "unknown",
      "evidence": "<reproducible artifact or command output, else empty string>",
      "notes": "<where keys come from; device-specific material; open questions>"
    },
    "block_function": {
      "status": "unknown",
      "evidence": "<RVA/VA + hand-verified instruction sequence or golden vector>",
      "notes": "<round structure, input/output registers, candidate score>"
    },
    "state_layout": {
      "status": "unknown",
      "evidence": "<memory dump, hook trace or disassembly with addresses>",
      "notes": "<state size, offsets, zeroing/init discipline>"
    },
    "container_geometry": {
      "status": "unknown",
      "evidence": "<header dump / length algebra / roundtrip transcript>",
      "notes": "<header bytes, body offsets, length formula, padding>"
    }
  }
}
```

## How to fill it

`status` is one of `observed`, `inferred`, `unknown`. Use `observed` only when
you can point to a reproducible artifact (a saved command output, a golden
vector, a dump or a hand-verified instruction sequence with addresses);
otherwise downgrade to `inferred`. `unknown` is the honest default — leave it
there until evidence exists, and never promote a `recon` score alone to
`observed`. The `evidence` string names the artifact; `notes` records the
interpretation and what remains open. See [universal-re.md](universal-re.md)
for the checklist that generates the evidence.
