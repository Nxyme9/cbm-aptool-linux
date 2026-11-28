# Design: no vendor binary needed, honest gap dispositions

Date: 2026-11-24
Status: approved by standing user directive ("DO ALL / address all issues / subagent-driven")
Baseline: `40306e5` on `feat/wave5-clean-tea`

## Intent and why

The published description says "no vendor binary, honest gaps". Today that is only
half true: the native TEA backend means normal use needs no `ap.exe`, but the code
still hardcodes `/tmp/opencode/ap.exe` as a silent fallback in four CLI modes, in
`pelib.c::pe_load`, in three test binaries and in the shell CLI harness. Some tests
silently SKIP when that path is absent, which hides coverage rather than proving
independence.

The user asked to address all five documented gaps and make the no-vendor claim
literal. Four gaps need artifacts or hardware this repo does not have; they cannot
be *closed* in software without inventing evidence. The honest program is therefore:
remove every vendor-binary dependency from build, test and normal modes; close the
one gap limitation that is closable in software (scanner cluster suppression);
harden the compiler warnings; and rewrite the gap ledger so each remaining gap has
an exact artifact/hardware gate.

## Goals

- Build, `make test`, the full chain and every normal CLI mode succeed with
  `CBM_PE_PATH` unset and no vendor PE file anywhere.
- Zero hardcoded `/tmp/opencode/ap.exe` path literals in shipped code, tests and
  the CLI harness (historical specs/plans are records and stay untouched).
- PE cross-check remains available, but only as an explicit opt-in with a
  user-supplied path; `--pe-crypto` without a path fails with a clear message.
- `nand_info.c` compiles with zero `-Wformat-truncation` warnings.
- Scanner can report two genuinely distinct containers whose starts are less than
  85688 bytes apart, via an opt-in flag; default behaviour is unchanged.
- `GAPS.md` gives every gap a disposition: closed / partially closed + gate /
  open + exact gate. No gap is claimed closed without evidence.

## Non-goals and anti-goals

- No vendor binary, key or device serial is ever committed or copied into the repo.
- No real device is touched; all tests use synthetic files under `/tmp/opencode`.
- No claim that the vendor CDB set, DLL internals, NAND firmware internals or a
  container magic/schema were recovered. Manufacturing a closure destroys the
  credibility the repo is built on.
- No deletion of user files. Verification of "no PE" uses a bogus `CBM_PE_PATH`
  override, never moving or removing the user's `/tmp/opencode/ap.exe`.

## Constraints

- Linux-native C, `gcc -m32 -Wall -Wextra -O2 -g`, `-lz`; no Wine/VM.
- Scoped commits only; no `git add .`/`-A`, no `--no-verify`, no stash.
- Existing backend API (`tea_init`, `cbm_backend_*`) keeps its signatures.
- `cbm_scan_image` keeps its signature; new capability goes in an added function.
- Test counts must be restated from measured logs, never guessed.

## Approaches considered

1. **Keep PE as an opt-in research backend, remove all defaults (chosen).**
   Preserves the Wave 5G framework and the byte-identical oracle cross-check while
   making the no-vendor claim literal. Cost: a few PE-specific tests become SKIPs
   when no path is supplied, so the no-PE run has a lower pass count than the
   oracle run; both numbers must be documented.
2. **Delete the PE backend, `pelib`, `pe-call` and their tests entirely.**
   Maximally simple, but throws away working research tooling and brag rights;
   rejected because the user asked to address gaps, not destroy evidence.
3. **Keep defaults but document them as optional.**
   Rejected: a hardcoded path is a silent dependency and a SKIP is not a pass.

## Dispositions for the five gaps

| Gap | Disposition | Exact gate for full closure |
|---|---|---|
| 1 — vendor SCSI CDB set | Open, bounded | `CBMUSBSys.sys` / `CBMUsbDrv*.dll` artifact or USB-capture hardware; host path already validated with standard block I/O |
| 2 — DLL 0/16 keys | Split: crypto practical need **closed** (native TEA, golden vectors); DLL internals open | `CBMUsbDisk.dll` artifact and a correct key derivation |
| 3 — BCH ECC / balanced erase | Open, bounded | firmware dump + CBM2199E/CBM2199s/CBM3380 datasheet + ECC counters |
| 4 — body field map | Partially closed: outer layer + inference only | vendor docs or decrypted serialiser PE + real-container corpus |
| 5 — scanner candidates | Limitation mitigated by opt-in `--all-hits`; confirmation still open | recovered magic/header schema (Gap 4) + corpus |

## What is left to the builder

Exact files, signatures, test names and commands are in the linked plan. The
builder may choose local variable names and helper placement, but not the public
signatures, flag spellings or the numbers pinned by tests.
