# Plan: capability closure, hardening and polish cycle

Date: 2026-11-24
Status: draft, awaiting approval. No implementation until this plan is signed off.
Base: `feat/wave5-clean-tea` @ `35013e3` (clean tree, PR #1 open)
Authority chain: the five wave specs under `docs/superpowers/specs/` remain binding
for *what* each wave does; this plan decides *order, gates and the honest ceiling*.

---

## 0. What "close all caps" can and cannot mean

Read as: close the **capability** backlog (13 queued waves), then harden and polish
the whole surface, then release.

The honest ceiling is stated up front because the repo's credibility rests on it:

| Class | Count | Can this cycle close it? |
|---|---|---|
| Software-closeable capability waves | 13 (5E, 5H–5O, 5P–5S) | **Yes** — implement, test, measure |
| Software-closeable gap portions | G2 crypto half (already closed), G4 outer layer (already closed), G5 `--all-hits` (already closed) | Already done; no re-litigation |
| Artifact-gated gaps | G1 (vendor CDB set), G2 DLL half, G4 body map, G5 confirmation | **No.** This cycle delivers the *gate*, the *acquisition request* and a reproducible *attempt*, never a claimed closure |
| Hardware/datasheet-gated gaps | G3 (BCH ECC, balanced erase) | **No.** 5L ships an explicitly synthetic harness |

**The cycle's success condition is therefore:** every software-closeable capability
implemented and proven by a command; every remaining gap carrying an exact gate line
with an artifact name and a re-runnable check; and zero documented number that is not
produced by a script from a measured log.

"Closed" for this plan means *the work is done and evidenced*. It never means a
hardware or vendor-artifact gap became solvable by writing more C.

---

## 1. Measured baseline (this tree, this machine)

| Fact | Value | How it was measured |
|---|---|---|
| Branch / HEAD | `feat/wave5-clean-tea` @ `35013e3` | `git rev-parse` |
| Tree | clean | `git status --porcelain` empty |
| Ahead of `main` | 42 commits (`5957179`) | `git log --oneline main..HEAD` |
| Remote / PR | branch and PR #1 at `35013e3`, OPEN, MERGEABLE | `git ls-remote`, PR state |
| Build | 0 warnings, 0 errors at `-m32 -Wall -Wextra -O2` | `/tmp/opencode/nohl-final-verify.log` |
| Suite with PE | 20 `Results:` lines = **178 passed / 0 failed / 0 skipped**; `test_pelib` 21 | `nohl-final-with-pe.log` |
| Suite without PE | 20 `Results:` lines = **172 / 0 / 4**; `test_pelib` 10 | `nohl-final-without-pe.log` |
| Test binaries | 19 in `TESTS` + `test_backend_cli.sh` harness | `Makefile` |
| Code size | 12,593 LOC across `*.c` / `*.h` | `wc -l` |
| TODO/FIXME/XXX/HACK in code | 0 | `grep -rnE` |
| CI | **none** — `.github/workflows/` absent | `ls` |
| Docs | 8 specs, 7 plans, 3 docs/, 6 top-level `.md` | `ls` |

### 1.1 Toolchain reality check (measured today, not assumed from the specs)

The wave specs carry 2026-11-24 "prerequisites" notes. Three of them are now stale.
This matters: two waves the specs call *blocked* are actually buildable.

| Probe | Result | Consequence |
|---|---|---|
| `emcc` | **missing** | 5H must use `clang --target=wasm32` as the spec's own fallback says |
| `wasm-ld` | `/usr/bin/wasm-ld` present | — |
| `clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--export-all` | **compiles**, produced a 729-byte module | **5H is unblocked** — no "documented non-goal" escape needed |
| `fuse3.h` | **present** at `/usr/include/fuse3/fuse.h`; `fuse.h` also present | **5J is unblocked** — the spec's "needs gated `libfuse3-dev` install" is obsolete |
| `/dev/fuse` | present, `crw-rw-rw-` | 5J mount test feasible |
| `python3 -c 'import mcp'` | ok | 5I feasible |
| `valgrind` | missing | sanitizers are the only memory oracle — see H2 |
| `gcc -m32 -fsanitize=address,undefined` | **links and runs** | full-suite ASan is feasible on the 32-bit build |
| `clang -fsanitize=fuzzer` at `-m32` and `-m64` | **both link** | H3 libFuzzer is feasible |
| `clang-tidy`, `scan-build`, `gcov` | present | H4 and H5 are feasible |
| `cppcheck`, `afl-fuzz`, `lcov` | missing | not used; gcov summary instead |
| `pelib` import hooks | **already implemented** (`PE_MAX_IMPORT_HOOKS 64`, `patch_import_hooks`) | **5E tier-1 substrate exists** — no loader work needed first |
| `--json` support | only `scan --json` and `heatmap --json` | 5I needs P2 (JSON everywhere) as a hard prerequisite |
| `--version` / `--help` | absent | P1 |

---

## 2. Inventory: what is actually open

Every row carries a **check command**, so "done" is a command and its output, never a
checkbox. This is deliberate: the previous program's most expensive review finding was
a documented claim that the log contradicted.

### 2.1 Capability waves

| Wave | Spec | Status | Class | Prereq | Size |
|---|---|---|---|---|---|
| 5A clean-room TEA | brag-rights | done | — | — | — |
| 5B forensic scanner | brag-rights | done | — | — | — |
| 5C decoder + fuzz lab | brag-rights | done | — | — | — |
| 5D doctor + TUI | brag-rights / wave5d | done | — | — | — |
| **5E** CDB honeypot + capture | wild-ideas | **queued** | S then A | pelib hooks (present) | M |
| 5F entropy heatmap | wild-ideas | done | — | — | — |
| 5G PE framework | wild-ideas | done | — | — | — |
| **5H** WASM playground | wild-ideas | **queued** | S | `wasm-ld` (present) | M |
| **5I** MCP server + skill | community | **queued** | S | **P2 JSON modes** | M |
| **5J** FUSE read-only view | community | **queued** | S | `fuse3.h` (present) | M |
| **5K** CTF + write-up | community | **queued** | S | waves it documents | M |
| **5L** firmware emulation | frontier | **queued** | S (synthetic only) + H gate | 5E path | L |
| **5M** universal RE framework | frontier | **queued** | S | 5G (done) | M |
| **5N** distributed mesh scan | frontier | **queued** | S | 5B (done) | M |
| **5O** Pico inspector | frontier | **queued** | S source + H gate | 5A (done) | L |
| **5P** BadUSB trust scanner | practical | **queued** | S then A | 5E, 5L marker | M |
| **5Q** CBM vault | practical | **queued** | S | 5A (done) | M |
| **5R** exFAT undelete carver | practical | **queued** | S | 5B reader + layout | L |
| **5S** telemetry exporter | practical | **queued** | S | all earlier state | M |

Class: **S** = software-closeable now, **A** = needs a vendor artifact, **H** = needs
hardware/datasheet. Thirteen waves remain.

### 2.2 Gap gates (the part that never closes by writing code)

| Gap | Exact gate | What this cycle does |
|---|---|---|
| G1 vendor CDB set | `CBMUSBSys.sys` / `CBMUsbDrv*.dll`, or USB capture | 5E tier-1 attempt; publish `docs/cdb-table.md` with observed/unobserved columns including an honest empty result |
| G2 DLL internals | `CBMUsbDisk.dll` + correct key derivation | Bounded derivation experiment (see 5M/G2 task); publish 0/N with the search space named |
| G3 BCH ECC / erase | firmware dump + CBM2199E/2199s/3380 datasheet + ECC counters | 5L synthetic harness, every output labelled synthetic |
| G4 body field map | vendor docs, or decrypted serialiser + real-container corpus | Corpus acquisition step (read-only, gated) + documented inferred map |
| G5 confirmation | recovered magic/schema + corpus | Corpus-consistency scoring as a *candidate-ranking* aid; still never called confirmed |

### 2.3 Deferred minors carried from the last program

| # | Item | Disposition |
|---|---|---|
| 1 | `tea_crypto.c` bare `return -1` does not name `CBM_PE_PATH` | H8 |
| 2 | `test_tea.c`, `test_pelib.c` reuse `getenv` pointers across `setenv`/`unsetenv` | P5 |
| 3 | `test_pelib.c` calloc before `SKIP` leaks hook array | P5 |
| 4 | `test_nand.c` missing minimal-valid-join boundary case | P5 |
| 5 | `test_backend_cli.sh` covers only two non-scan `--all-hits` cases | P5 |
| 6 | `main.c` rejects `scan --all-hits <path>` (flag before path) | P1 |
| 7 | `main.c` label `Hits:` vs count line `Candidates:` | P1 |
| 8 | `cbm_scan.c:229` comment says comparator is `cbm_scan_image`-only though `_ex` calls it | P5 |

Eight items. All cheap. None is a feature.

### 2.4 Hardening surface (measured as absent)

| # | Gap | Evidence it is absent |
|---|---|---|
| H1 | No exploit-mitigation flags | `CFLAGS = -m32 -Wall -Wextra -O2 -g` only; no `-fstack-protector-strong`, `-D_FORTIFY_SOURCE`, `-z relro` |
| H2 | Sanitizers cover 2 of 19 binaries | ASan doctor 24/24 and TUI 18/18 only; the other 17 run unsanitized |
| H3 | No coverage-guided fuzzing | `cbm_fuzz` is a deterministic lab, not libFuzzer/AFL |
| H4 | No static analysis in the loop | `clang-tidy`/`scan-build` present but unused; no target |
| H5 | No coverage number | no `make cov`, no reported figure |
| H6 | No written I/O safety contract | device open modes, `O_CLOEXEC`, symlink handling, carve TOCTOU undocumented |
| H7 | No integer/bounds audit | size math for blocks, samples, PNG dims, PE map untested at boundaries |
| H8 | No error-path audit | fail-closed is a convention, not a tested property |
| H9 | No supply-chain/CI enforcement | no workflows, no `-Werror`, gitleaks only run by hand |

### 2.5 Polish surface (measured as absent)

| # | Gap | Evidence |
|---|---|---|
| P1 | CLI inconsistency | no `--version`; `--all-hits` position-dependent; `Hits:`/`Candidates:` mismatch |
| P2 | `--json` only on 2 of 7 modes | `container`, `diff`, `layout`, `doctor`, `fuzz` have no machine-readable mode |
| P3 | Docs numbers are retyped by hand | counts live as literals in README/GAPS; drift is undetectable |
| P4 | No docs index, man page, CHANGELOG, CONTRIBUTING | `ls docs/` = 3 topic files |
| P5 | 5 test-hygiene minors | see 2.3 |
| P6 | No `--quiet`/`--no-color`; output units undocumented | `grep -- '--quiet'` = 0 |
| P7 | No terminal-restore-on-signal test for the TUI | TUI tests are render-pure |
| P8 | No issue/PR templates, no `SECURITY.md` | `.github/` absent |

---

## 3. Workstreams

### W1 — Gap closure (gates, not claims)

| ID | Work | Exit criterion |
|---|---|---|
| G1-a | 5E tier-1: bind `DeviceIoControl` (and reachable DLL entry points) through `pelib` hooks, log control code + input buffer + CDB | capture file produced by a synthetic PE test, byte-exact |
| G1-b | Run the capture against the user's own PE (opt-in, `CBM_PE_PATH`) | `docs/cdb-table.md` lists what was observed; an empty table is an acceptable, documented result |
| G1-c | Tier-2 USB-gadget honeypot source | source + instructions committed; **not run** — hardware gate |
| G2-a | Bounded key-derivation experiment for `CBMUsbDisk.dll` | search space named, 0/N result or a decrypt; either way evidence, not assertion |
| G3-a | 5L synthetic firmware harness | BCH vectors + erase-count traces pass; every line labelled synthetic |
| G4-a | Real-container corpus acquisition (read-only, gated live probe) | N containers extracted from the user's own device, structural consistency report |
| G5-a | Corpus-consistency scorer | ranks candidates by cross-container agreement; explicitly **not** a confirmation oracle |

### W2 — Capability waves

Executed in the dependency order fixed by the specs, with one insertion: **P2 (JSON)
moves ahead of 5I** because 5I's six MCP tools are thin wrappers over it.

```
5E → 5H → 5I → 5J → 5K → 5M → 5L → 5N → 5O → 5P → 5Q → 5R → 5S
                 ^
                 P2 (JSON everywhere) lands here, before 5I
```

Each wave is one scoped commit series, one test binary (or script) added to `TESTS`,
one spec-risk sentence reproduced in the docs, and a measured suite delta.

### W3 — Hardening

| ID | Work | Exit criterion |
|---|---|---|
| H1 | Harden flags: `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fstack-clash-protection -Wformat=2 -Werror=format-security -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wvla`; link `-Wl,-z,relro,-z,now` | 0 warnings; any per-file exception is listed with a reason |
| H2 | `make asan`: all 19 binaries + CLI harness under `-fsanitize=address,undefined` + LSAN | 0 leaks, 0 UB reports; the pelib fixed-map risk is resolved or documented |
| H3 | `make fuzz`: libFuzzer targets for container, decode/inspect, scan-image, MBR/layout | ≥1 CPU-hour per target, 0 crashes; corpus seeds committed (small) |
| H4 | `make analyze`: `clang-tidy` + `scan-build` over all translation units | triaged baseline; no new high-severity class |
| H5 | `make cov`: gcov summary per file | ≥85% line coverage on parser/decoder units; number published |
| H6 | I/O safety contract: read-only unless writing, `O_CLOEXEC`, symlink handling, carve TOCTOU, fsync+read-back | `docs/io-safety.md` + tests for each rule |
| H7 | Integer/bounds audit of every size computation | boundary tests at 0, 1, max-1, max |
| H8 | Error-path/fail-closed audit; every message names the flag or env var | deferred minor #1 fixed; no partial output on failure |
| H9 | Supply chain: gitleaks in CI, pinned actions, dependency inventory (zlib only), `-ffile-prefix-map` | CI job green; inventory in `docs/dependencies.md` |

### W4 — Polish

| ID | Work |
|---|---|
| P1 | CLI uniform: per-mode `--help`, `--version`, documented exit codes (0 ok / 1 runtime / 2 usage), every error prefixed and naming the offending flag; fixes minors #6 and #7 |
| P2 | `--json` on container, diff, layout, doctor, fuzz, scan, heatmap, with `schema: "cbm/1"` and stable field names |
| P3 | `scripts/check-counts.sh`: extract counts from a fresh log, compare to the literals in README/GAPS/ARCHITECTURE, fail on drift. Docs stop containing hand-typed numbers |
| P4 | `docs/README.md` index, `cbm-tool(1)` man page, CHANGELOG, CONTRIBUTING, refreshed ARCHITECTURE diagram |
| P5 | The five test-hygiene minors (#2–#5, #8) |
| P6 | `--quiet`, `--no-color`, colour only on a tty, labelled units in tables |
| P7 | TUI: terminal restore on SIGINT/SIGTERM, resize handling, cbreak teardown — with tests |
| P8 | `.github/ISSUE_TEMPLATE`, `PULL_REQUEST_TEMPLATE`, `SECURITY.md`, `.editorconfig` |

### W5 — Release and CI

| ID | Work | Gate |
|---|---|---|
| R1 | `.github/workflows/ci.yml`: gcc build+test, clang build (`-Werror`), asan, fuzz-smoke (60 s), shellcheck, gitleaks, `check-counts` | no vendor PE, no device, no network |
| R2 | Branch protection with required checks | **repo settings change — gated** |
| R3 | Version bump + tag + release tarball + CHANGELOG | **tag/publish — gated** |
| R4 | Merge PR #1 | **gated** |
| R5 | Publish the 5H playground to Pages | **deploy — gated** |

---

## 4. Sequencing

Seven phases. Each phase ends at a gate that must be *observed*, not assumed.

### Phase 0 — Ratchet (before any new feature)
H1, H2 (full), H3 (smoke only), P3, P5, R1 (CI skeleton).
**Why first:** thirteen waves landing on a base that cannot fail loudly multiplies
rework and re-creates the exact defect the last review caught — a doc claim the log
contradicted. The ratchet is the cheap insurance.
**Exit:** `make ci` green locally and in Actions; docs counts machine-checked.

### Phase 1 — Machine-facing capabilities
P2 → 5I (MCP) → 5H (WASM) → 5J (FUSE).
**Why here:** 5I and 5H are the two waves that make the project usable by someone who
will never build a 32-bit Linux binary. 5J reuses the same JSON surface.

### Phase 2 — Evidence waves
5E (CDB capture) → 5L (synthetic firmware, G3) → 5M (recon, G2-a).
**Why here:** 5E feeds 5P and 5L; 5M's `recon` is the tool G2-a needs. These are the
waves pointed most directly at the open gaps.

### Phase 3 — Scale and artefacts
5K (CTF + write-up) → 5N (mesh scan) → 5O (Pico source).
**Why here:** 5K documents Phases 0–2; 5N and 5O are demonstration surfaces, not
dependencies of anything else.

### Phase 4 — Data-facing capabilities
5R (exFAT carver) → 5Q (vault) → 5P (trust scanner) → 5S (telemetry).
**Why here:** 5R is the largest parser job and benefits from the hardened base; 5P
needs 5E's capture; 5S aggregates state from every earlier wave and must land last.

### Phase 5 — Hardening closure
H4, H5, H6, H7, H8, H9, plus a long H3 run (≥1 CPU-hour per target).
**Exit:** published coverage number; zero high-severity static findings; every
fail-closed rule has a test that proves it fails closed.

### Phase 6 — Polish and release
P1, P4, P6, P7, P8 → R2 (gated) → R3 (gated) → R4 (gated) → R5 (gated).

**Global gate after every wave:** `make ci` green, suite count measured and recorded,
no device node opened, no vendor path literal in shipped files.

---

## 5. Acceptance criteria

The cycle is done when all of these are true and each is backed by an artifact:

1. **13 waves landed.** Each has: source, a test registered in `TESTS`, a spec-risk
   sentence in its doc, and a measured suite delta.
2. **`make ci` green** on gcc and clang, 0 warnings under the H1 flag set, with
   `CBM_PE_PATH` unset and no `/dev/sd*` opened.
3. **Sanitizers cover 100% of binaries** — 0 leaks, 0 UBSan reports.
4. **Fuzzing**: 4 targets × ≥1 CPU-hour, 0 crashes, or a triaged report.
5. **Coverage** ≥85% line on parser/decoder units, number in the README.
6. **Static analysis**: no new high-severity class vs the Phase-0 baseline.
7. **Docs numbers are generated**, not typed: `scripts/check-counts.sh` passes and
   fails when a literal is corrupted (proven by a self-test).
8. **Five gap gates** each have: artifact name, acquisition route, reproducible check,
   and current status. No gap is marked closed without an evidence line.
9. **5E published as observed/unobserved** — an empty capture is a valid outcome.
10. **Every hardware/vendor step is a separate gated ask**, never implied by a green
    test run.
11. **Deferred minors: 8/8 closed**, each with the commit that closed it.
12. **Release**: version tagged, CHANGELOG written, CI required checks on the default
    branch.

---

## 6. Verification protocol

```sh
# from the worktree
make clean && make                       # 0 warnings under H1 flags
make test                                # recorded counts
CBM_PE_PATH=/tmp/opencode/does-not-exist.exe make test   # no-PE path must skip, not fail
make asan                                # all binaries, 0 leaks / 0 UB
make fuzz FUZZ_SECONDS=3600              # 4 targets
make analyze                             # clang-tidy + scan-build
make cov                                 # gcov summary
sh scripts/check-counts.sh               # docs literals vs fresh log
shellcheck test_backend_cli.sh
gitleaks detect --source . --no-git --redact
strace -f -e trace=openat ./test_cbm_scan 2>&1 | grep -c '/dev/sd'   # must be 0
```

Counts rule inherited from the last program: a documented number must be traceable to
a line in a log under `/tmp/opencode/`, and the log must show the live environment
that produced it.

---

## 7. Risks and honesty guards

| Risk | Guard |
|---|---|
| 5E captures nothing because the frontend delegates to the encrypted DLL | Publish the empty result. Gap 1 stays open. The spec already predicted this |
| 5L's synthetic harness gets read as "we emulated the firmware" | Every artifact line carries the word *synthetic*; the doc says so in the first paragraph |
| 5P's trust scanner over-claims firmware compromise detection | Descriptor-only findings labelled *host-observable*; firmware claims require a real dump |
| 5N claims distributed execution it did not perform | Fail-closed to local chunks, and the report says which ran |
| 5H ships a broken artifact because `emcc` is missing | Measured today: clang wasm32 + `wasm-ld` produce a module. If that regresses, the test skips with the reason and the wave is a documented non-goal — never a broken build |
| 32-bit ASan conflicts with `pelib`'s fixed `PE_BASE` mapping | Probe in H2 before promising it; if it conflicts, run those targets under 64-bit ASan or document the exception |
| New waves inflate doc counts that then drift | P3 lands in Phase 0, before any wave adds a number |
| Scope creep from "polish" | P-items are enumerated (P1–P8). Anything else is a new plan |
| Hardware steps get implied by green tests | Gated-ask rule: any `/dev/sd*`, firmware dump, vendor download, Pages deploy or tag is a separate ask |

**Non-goals:** a complete vendor protocol clone; any claim of firmware-level knowledge
without a dump; 64-bit PE support in `pelib`; Windows/macOS builds; vendor binary
redistribution.

---

## 8. Size and decision points

Relative size, not calendar promise: **S** ≤ one working session, **M** two to three,
**L** four or more.

| Phase | Contents | Size |
|---|---|---|
| 0 | H1, H2, H3-smoke, P3, P5, R1 | M |
| 1 | P2, 5I, 5H, 5J | L |
| 2 | 5E, 5L, 5M | L |
| 3 | 5K, 5N, 5O | M |
| 4 | 5R, 5Q, 5P, 5S | L |
| 5 | H4–H9, long fuzz | M |
| 6 | P1, P4, P6–P8, R2–R5 | M |

Decisions the user controls (not the implementer): whether to merge PR #1 before or
after this cycle, whether to tag a release, whether GitHub Pages publishing is wanted,
and whether the gated live probes (corpus acquisition from `/dev/sde`, USB honeypot)
run at all. Everything else in this plan is decidable from the repo and the specs.
