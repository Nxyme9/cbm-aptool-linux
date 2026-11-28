# Universal controller RE method (wave 5M)

## Purpose

Turn the one-off reverse engineering of APTool's TEA core into a repeatable
method for other Chinese USB controller tools. `recon` is a **read-only
candidate generator**: given a vendor PE32 it locates `55 8b ec` prologues in
the first executable section, measures byte-level patterns in each bounded
function body, scores them, and prints addresses for manual review. It does
not disassemble instructions, emulate code, execute code, or write to the PE.

Scoring is intentionally mechanical so two reviewers get the same ranked list
from the same file. It is not a claim that any ranked function is a cipher.

## Exact scoring table

One function body is at most 8192 bytes, from its prologue to the next
prologue or the end of the executable section. The score is the sum of:

| Condition | Points |
|---|---:|
| imm32 `0x9E3779B9` (TEA delta) appears anywhere in the body | +40 |
| imm32 `0x61C88647` (alt delta) appears anywhere in the body | +25 (both deltas add) |
| each byte-XOR opcode (`0x30` or `0x32`), capped at 5 opcodes | +4 each |
| each dword-XOR opcode (`0x31` or `0x33`), capped at 6 opcodes | +2 each |
| each `C1 /4` (`shl` imm) or `C1 /5` (`shr` imm), capped at 6 combined | +3 each |
| an `E8 rel32` call whose target RVA is a delta-bearing function | +35 |
| any single `E8` call target occurring 3 or more times in the body | +8 |
| a stack-frame `83 EC imm8` | +3 |
| body size 64..4096 bytes inclusive | +5 |

Candidate threshold: `score >= 20`. Candidates are sorted by score descending,
then RVA ascending. Up to 512 are stored; the report also gives the total
number above threshold. Printed counts in `byte_xor`, `dword_xor` and `shifts`
are raw measured counts; only the score applies the caps.

## How to run

    make clean && make
    ./cbm-tool recon /path/to/vendor.exe                 # top 20 (default)
    ./cbm-tool recon /path/to/vendor.exe --top 5
    ./cbm-tool recon /path/to/vendor.exe --all
    ./cbm-tool recon /path/to/vendor.exe --json

There is no built-in PE path. `recon <pe>` takes an explicit file path; the
tests use `CBM_PE_PATH` to locate an optionally supplied vendor PE. The PE is
required to be a regular file no larger than 64 MiB; `SizeOfImage` must be
between 0x1000 and 256 MiB. PE32 (magic `0x10b`) is the normal case; PE32+
(magic `0x20b`) is accepted, with its 64-bit ImageBase reported as low 32 bits
and the same section-table math. Non-PE input, an out-of-range section, or a
missing executable section returns exit code 2 with an explicit error.

## How to read the output

Prose begins with the file path, ImageBase, SizeOfImage, section count,
functions scanned and candidate count, followed by the table:

    VA RVA score size bx dx shf flags

`VA` is `ImageBase + RVA`, computed from the header on every run; `size` is the
bounded body length; `bx` / `dx` / `shf` are raw XOR and shift byte counts;
`flags` names the strongest evidence (`TEA-delta`, `ALT-delta`,
`calls-delta`, `repeat-call`). `--json` emits one `cbm/1` document with
`command: "recon"`, `status: "ok"`, and the same candidates in an array; on
input error it emits `cbm_json_error` with `status: "error"` and exit code 2.

## Honest limits

These are **heuristic candidates, not confirmation**. A hit is a lead for a
human reviewer, not proof of a block cipher, a TEA variant, or a key schedule.
Raw byte scanning counts opcodes inside immediates and data as well as
instructions, so `bx` / `dx` / `shf` can contain false positives. Delta
immediates may belong to a checksum or a table, not a cipher. Ranking is
evidence for manual review only: confirm the round function by hand before
claiming anything about a vendor tool. No result from `recon` closes a
reverse-engineering gap by itself.

## Checklist for a new tool

1. Map sections: confirm the PE architecture, ImageBase, section table and
   which section is executable; record their RVAs and sizes in the port spec.
2. Scan prologues: run `recon <pe> --all`, record functions scanned, total
   candidates and the top addresses with their scores and flags.
3. Read the candidate list: group repeated call targets and delta-bearing
   functions; pick the few bodies worth hand review. Keep the JSON output as
   the reproducible artifact.
4. Confirm the round function by hand: read the actual instructions, identify
   input/output state, shifts and XOR order, and check against known vectors.
5. Recover the key schedule: trace where round keys come from, including any
   derived or device-specific material; do not infer a key from a delta.
6. Record evidence: fill `docs/port-spec-template.md` with observed vs
   inferred vs unknown status and a reproducible artifact for every claim.

## Reproduce on a new vendor tool

Supply your own legally obtained PE as the explicit `<pe>` argument. Run the
default top-20 view first, then `--all --json` and save the JSON next to your
notes. For each candidate you pursue, cite file offset / RVA / VA, the score
breakdown, and the hand-verified instruction sequence. Start a fresh copy of
`docs/port-spec-template.md` for the new tool; leave every field `unknown`
until an artifact makes it `observed`. If no executable section is present or
the file is not PE32/PE32+, say so instead of forcing the method.

## Gate status

**G2 (CBMUsbDisk.dll internals + key derivation) remains OPEN** and requires
the DLL: `recon` does not decrypt the DLL or recover a device-specific key.
Wave 5M closes only the method/tooling half — the repeatable recon CLI, the
port-spec template and this checklist. It does not close the DLL half of Gap 2.
