# Design: Frontier Wave 5 (5L–5O, fourth complement)

Date: 2026-11-24
Status: draft (awaiting approval)

## Intent

The user selected all four directions from the fourth brainstorm batch. This
spec adds them to the eleven waves already scoped in:

- `2026-11-24-brag-rights-design.md` (5A–5D)
- `2026-11-24-wild-ideas-design.md` (5E–5H)
- `2026-11-24-community-uses-design.md` (5I–5K)

Total program: fifteen waves. No code is written until the scope is approved.
Every wave stays read-only by default with opt-in, verified writes.

## Prerequisites / honesty

- Firmware dump from the stick is **not confirmed possible**; 5L has a
  reconstruction/simulation fallback and must report what it did not observe.
- Other vendor tools (Phison, Silicon Motion, JMicron) are **not local**;
  acquiring them is a gated download step. 5M's first deliverable is the
  framework and a documented method, not a claim about other chips.
- CLS mesh is live (1 peer, cls:5/34/38/39/53/97). 5N can use it when the
  fabric is reachable; single-machine fallback required.
- An RP2040 board is **unconfirmed**. 5O ships source + build instructions
  first; hardware validation is a separate gated step.

## 5L — Firmware emulation (`fwemu/`, `docs/firmware-emulation.md`)

### Goal

Attack Gap 3 (BCH ECC, bad-block management, balanced erase) by running
controller firmware under instrumentation.

### Approach

1. Attempt a read-only firmware dump over the recovered CDB path (5E). If the
   device refuses, preserve the attempt and evidence.
2. If no image is obtainable, build a *synthetic* firmware harness: a small
   ARM/8051 test program implementing the observable ECC/erase behaviour,
   run under Unicorn with hooks on MMIO and CDB registers. This demonstrates
   the instrumentation method without claiming to have real firmware.
3. Instrument BCH syndrome calculation and erase-count tracking; export a
   trace of which blocks would be touched by a write pattern.

### Tests

`test_fwemu.py`: known BCH syndrome vectors, erase-count monotonicity, and a
trace comparison for a fixed synthetic write workload. Clearly label every
result as "synthetic" unless a real dump was obtained.

## 5M — Universal controller RE framework (`pelib` extensions, `docs/universal-re.md`)

### Goal

Turn 5G's 32-bit PE loader + 5A's codec pattern into a repeatable method for
other Chinese USB controller tools.

### Approach

- A `recon` CLI: given a vendor PE, auto-locate candidate block-cipher
  functions by disassembly patterns (XOR loops, constant tables, state
  globals), score them, and emit a candidate list with addresses.
- A `.mind`-style port-spec template: key recovery, block function, state
  layout, container geometry, and an evidence column.
- Method doc with a checklist, so applying it to a new tool is mechanical.

### Tests

`test_recon.c`: run against local `ap.exe`; assert the known block function
`0x459ec0` appears in the candidate list; assert no crash on a random binary.

## 5N — Distributed mesh scan (`mesh_scan.{h,c}`, `docs/distributed-scan.md`)

### Goal

Scale container discovery across machines using the existing CLS fabric.

### Approach

- Split a device/image into byte ranges; dispatch range-scan jobs via CLS
  (cls:38 MCP / cls:39 sessions) to reachable peers.
- Each peer runs the 5B scanner read-only on its assigned range and returns
  hits as JSON; aggregator deduplicates and emits the combined report.
- Fail-closed: if no peer is available, run locally in chunks and say so.
  Never silently claim distributed execution.

### Tests

`test_mesh_scan.c`: two local mock workers split a synthetic image and find
all planted containers; offline fallback finds the same set locally.

## 5O — Pico hardware inspector (`pico/`, `docs/pico-inspector.md`)

### Goal

A $4 standalone board that reads and decrypts CBM containers.

### Approach

- Port the clean-room codec from 5A to a no_std C subset for RP2040.
- USB mass-storage host mode reads a container from a thumb drive; on-board
  USB serial prints header, entropy, strings and a hex dump.
- Buttons: dump plaintext to a file, verify roundtrip. No writes to the
  source device.
- Build instructions with the Pico SDK; source and tests committed, hardware
  validation gated on board availability.

### Tests

`pico/test_vectors.h` + host-side test: the embedded codec produces the same
vectors as 5A for a fixed corpus; `pico/test.sh` runs CMake build if the SDK
is present, otherwise documents the skip.

## Updated dependency order

5A → 5G → 5C → 5B → 5E → 5F → 5D → 5H → 5I → 5J → 5K → 5M → 5L → 5N → 5O

5M builds on 5G's loader and 5A's codec pattern. 5L builds on 5E's CDB path.
5N builds on 5B. 5O ports 5A. 5K's write-up now covers all previous waves.

## Verification

1. `make clean && make && make test` after every wave.
2. 5L: synthetic ECC/erase traces match analytic expectations; real-firmware
   claims appear only if a dump was actually obtained.
3. 5M: `recon` finds `0x459ec0` in `ap.exe`; no crash on random input.
4. 5N: mock-worker and offline scans find identical container sets.
5. 5O: embedded vectors equal 5A vectors; build skip documented if no SDK.
6. `gitleaks detect --source . --no-git --redact` → no leaks.
7. Firmware dumps, other-vendor downloads, hardware validation, full-device
   scans and device writes remain separate gated steps.

## Honest risks

- 5L may never obtain real firmware; the synthetic harness is a method demo.
- 5M cannot promise results on chips whose tools are unavailable.
- 5N depends on mesh availability; offline fallback is mandatory.
- 5O needs hardware we have not confirmed owning.
