# nx-cbm-lab: a clean-room RE write-up (wave 5K)

This is the "brag rights" story of a partial, reproducible reverse engineering of the Chipsbank CBM container used by APTool: what was recovered, the commands that reproduce it, and exactly where the evidence stops. It is not a claim of protocol parity. Every claim below is grounded in this repository's README.md, ARCHITECTURE.md, GAPS.md and docs/, and the measured numbers are the frozen chain recorded in README.md, not new measurements.

## What was recovered, and how

**1. mmap-at-ImageBase PE harness.** The TEA core was first recovered by running the vendor PE natively on Linux, without Wine, through an mmap-at-ImageBase harness. It is now the reusable `pelib.{h,c}`: `pe_load` bounds-checks headers and sections and maps at `PE_BASE 0x400000` with `MAP_FIXED_NOREPLACE`; `pe_rva_to_va` resolves addresses; `pe_call_void` packs one to three `__stdcall` words, zeroes the 16-byte state at RVA `0x131328`, and calls the target; `pe_export` and `pe_unload` complete the API. The recovery probes reported `rtlen` as a perfect inverse and `rttest match=1`. Recovered symbols: encrypt `0x459da0`, decrypt `0x459d50`, block core `0x459ec0`, state `0x531328`, key derivation `0x4fc924` yielding `1a2b3c4d5e6fTENG` (keyidx 12), and CBC XOR region `0x45a0ff`-`0x45a177`.

**2. Clean-room TEA key and core.** `tea_native.{h,c}` translates the block core from dumped constants rather than vendor source: seventeen constant tables at PE VAs `0x52a9b0`-`0x52ad0f`, flag sequences `0x50`/`0x70` across three 16-round cores (`0x50,0x70,0x50` encrypt; `0x70,0x50,0x70` decrypt), a per-call 16-byte state reset, and whole 8-byte blocks only (odd tails untouched). Golden vectors include eight zero bytes -> `e66254b5da09fb31`, bytes `00..1f`, and a 15-byte odd case; PE-oracle equivalence is checked at nine lengths. This native cipher is the default; the PE is a cross-check only.

**3. Container envelope.** `cbm_container.{h,c}` implements an 85688-byte container: byte 0 header, bytes 1..85687 TEA body, `HLEN = ((filesize - 511) & ~7) + 511`, and the observed error strings `File is encrypted!` and `Decrypt Faile!`. `container --dump-plain` and `--inject` move an exact-size body in and out while preserving the header byte. Body semantics beyond the outer split remain inferred.

**4. Scanner and decoder.** `cbm_decode` computes Shannon entropy and 64-byte `constant`/`string`/`opaque` windows as local heuristics, not vendor records. `cbm_scan` sweeps 512-byte-aligned starts in chunks overlapping by 171888 bytes, runs a full decrypt plus a plausibility gate, and prints deterministic candidate rows; it writes nothing unless `--carve` or `--json` is given, with alias guards on those paths. `--all-hits` keeps close candidates that the default cluster collapse would hide. `diff` reports context-merged ranges and a signed entropy delta; `fuzz` produces seeded xorshift64* corpora that verify decrypt->encrypt identity, not semantic validity. `cbmv1001` is UNVERIFIED and no magic list drives detection.

**5. Doctor and TUI.** `doctor` is read-only by default; repair needs `--repair-mbr --yes --backup`, supports 26/27/28 GiB windows, and follows a fixed sequence: read LBA 0, claim an exclusive no-follow backup, re-read and `memcmp`, write the reconstructed LBA 0, read back and `memcmp`. Geometry is a nominal convention from the frozen spec, not a vendor measurement; a parseable foreign MBR is never silently rewritten. `tui` renders a pure function of collected state plus terminal dimensions: no tty probe inside the renderer, no writes, and `n/a` instead of fabricated metrics.

**6. Recon.** `recon.{h,c}` and `cbm-tool recon <pe>` rank block-cipher candidates in a supplied PE32/PE32+ by `55 8b ec` prologues and a mechanical score (>=20: TEA deltas, XOR/shift opcodes, repeated calls, stack frame, body size). It is read-only, bounds each body at 8192 bytes and stores up to 512 candidates. A ranked hit is a lead for hand review, not confirmation; G2 stays open.

**7. Firmware emulation.** `fwemu/` is a synthetic Python model of BCH(255, 223, t=4) syndromes and decode, erase counts with a lowest-count/lowest-index policy, and deterministic traces whose every line says `synthetic`. `HookSink` exposes hooks for a future Unicorn runner. No firmware image, ARM/8051 program, Unicorn or ARM toolchain is involved, and Gap 3 is not closed.

**8. Trust and vault.** `trust` compares a host-observable USB fingerprint (VID/PID, product, interfaces, optional captured CDBs and marker) against a required baseline, never opens the device for I/O, and refuses firmware claims without a real dump; `serial` is parsed but never compared. The derived `vault` reuses the 85688-byte envelope and clean-room TEA core with a private `CBMVLT01` body and FNV-1a 64 checksum, takes a 16-byte `CBM_VAULT_KEY` (unset falls back to the public key with an explicit warning), and claims no vendor compatibility. Wave 5E's `cdb-capture` shims and the local WASM playground and FUSE view extend the same read-first posture; no vendor PE or hardware is needed for the tests.

## Reproduce it

```sh
cd <path-to-this-repo>
make clean && make && make test
sh test_backend_cli.sh
```

This needs gcc with 32-bit support (`gcc -m32`), make and zlib (`-lz`). The optional cross-check points `CBM_PE_PATH` at a legally obtained `ap.exe` and uses `--pe-crypto`; there is no default PE path and no silent fallback.

CTF challenge: generate the synthetic image, then run the solver on it.

```sh
python3 challenge/generate.py --out disk.img
sh solver/solve.sh disk.img
```

The measured counts quoted here are the frozen chain `make clean && make && make test && sh test_backend_cli.sh` recorded in README.md: 194 passed, 0 failed, 0 skipped with a usable PE and 188 passed, 0 failed, 4 skipped without one, each across 21 `Results:` lines. The separately formatted `test_pelib` line reports 21 passes with PE and 10 without, outside those sums; the 4 skips are attributed in README.md to `test_backend_cli.sh`. Every fixture in these runs is a synthetic regular file.

## Honest gaps

- **G1 - vendor SCSI CDB set:** open. Exact gate: a `CBMUSBSys.sys` / `CBMUsbDrv*.dll` artifact or USB-capture hardware. The 5E capture is software IAT shims against a synthetic PE; its vendor column reads `not observed`, and the gadget tier is source-only and not run.
- **G2 - CBMUsbDisk.dll internals and key derivation:** open, though the practical crypto need is closed. The DLL yielded 0/16 candidate keys producing a valid PE. Exact gate: the DLL artifact plus a correct key derivation, possibly tied to controller identity or serial. `recon` closes only the method/tooling half.
- **G3 - BCH ECC and balanced erase:** open. Exact gate: a firmware dump plus a CBM2199E/2199s/3380 datasheet plus ECC counters. `fwemu` is synthetic only, and the firmware-dump attempt was not run.
- **G4 - container body field map beyond byte 0:** partially closed at the outer layer only. Exact gate: vendor documentation or a decrypted serialiser PE plus a real-container corpus. Every body interpretation in `docs/container-format.md` is marked inferred.
- **G5 - scanner confirmation:** hits are candidates, not confirmed containers. Exact gate: the recovered magic/header schema from G4 plus a real-container corpus. `--all-hits` mitigates cluster suppression, not confirmation.

**Boundaries.** No vendor binary is committed; native TEA is the default; PE is opt-in via `CBM_PE_PATH`; no real device is used in tests. Real-device validation, full-image passes and hardware capture remain separate gated steps, not outcomes of a green test run.
