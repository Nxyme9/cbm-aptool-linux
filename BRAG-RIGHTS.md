# What else can we do with this? — the full brag-rights inventory

This is the answer to "what else can we use CBM APTool Linux for?" Everything
below builds on what already ships: a Linux-native RE tool that decrypts the
Chipsbank container, validates a real 500 GiB stick, and edits containers
reversibly — with no vendor binary in the repo.

Nineteen ideas, five tiers. Each is scoped in `docs/superpowers/specs/`.
Effort: **S** = days, **M** = weeks, **L** = research-grade.

---

## Tier 1 — Finish the core (highest credibility per hour)

| # | Idea | What it proves | Effort |
|---|---|---|---|
| 5A | **Clean-room TEA** | Reimplement the vendor cipher in pure C, byte-identical to the PE oracle. Tool runs with **zero** `ap.exe`. | S |
| 5B | **Forensic scanner** | Sweep all 500 GiB for hidden `cbmv1001` containers, carve + JSON report. Needle in a haystack. | S |
| 5C | **Decoder + fuzz lab** | `diff` two containers, seeded mutation fuzzing, and an honest field map of the undocumented format. | M |
| 5D | **Doctor + live TUI** | Repair corrupted MBR/DJ layout behind `--repair-mbr --yes --backup`, plus a terminal dashboard. | M |

## Tier 2 — Jaw-dropping demos (best for "holy shit" reactions)

| # | Idea | What it proves | Effort |
|---|---|---|---|
| 5E | **USB honeypot + CDB capture** | Impersonate a Chipsbank stick on a gadget board, log the vendor's proprietary commands. Closes **Gap 1**. | L |
| 5F | **Whole-disk entropy heatmap** | Render 500 GiB as a PNG showing partitions, slack and hidden regions. One image, instant wow. | S |
| 5G | **Wine-less PE framework** | Generalize the mmap-at-ImageBase loader into a reusable library for any 32-bit vendor PE. "Mini-Wine for RE." | M |
| 5H | **Browser WASM playground** | Drop a `.cbm` in a web page: decrypt, diff, fuzz, hex-view client-side. Shareable, no install. | M |

## Tier 3 — Community & integration (makes it a platform)

| # | Idea | What it proves | Effort |
|---|---|---|---|
| 5I | **MCP server + agent skill** | Expose decrypt/inspect/diff/scan as MCP tools so any LLM can drive the RE tool natively. | S |
| 5J | **FUSE mount view** | Mount the stick and its decrypted container as ordinary files (`/container.plain`, `/layout.txt`). | M |
| 5K | **CTF challenge + write-up** | Ship a synthetic-disk challenge and the full RE story. The primary recruitment/teaching artifact. | S |

## Tier 4 — Frontier research (the "nobody else has this" tier)

| # | Idea | What it proves | Effort |
|---|---|---|---|
| 5L | **Firmware emulation** | Run controller firmware under Unicorn/QEMU with instrumentation. Attacks **Gap 3** (ECC, erase policy). | L |
| 5M | **Universal controller RE framework** | Auto-locate cipher functions in any vendor PE; apply the method to Phison / Silicon Motion / JMicron. | L |
| 5N | **Distributed mesh scan** | Fan a container scan across machines over the live CLS fabric. Scale brag. | M |
| 5O | **Pico hardware inspector** | Port the codec to an RP2040 — a $4 board that reads and decrypts containers standalone. | M |

## Tier 5 — Practical products (turns the RE into a tool people keep)

| # | Idea | What it proves | Effort |
|---|---|---|---|
| 5P | **BadUSB trust scanner** | Fingerprint controller identity + CDB behaviour to flag reflashed/malicious sticks. Security brag. | M |
| 5Q | **CBM vault — secret store** | Repurpose the encrypted container as a portable, integrity-checked secret store. | S |
| 5R | **exFAT undelete carver** | Recover deleted files from DJ_DATA using the known layout. Real digital-forensics capability. | M |
| 5S | **Live telemetry + Grafana** | Prometheus exporter for device/scan metrics, dashboards in the existing monitoring stack. | S |

---

## If you only do three things

1. **5A clean-room TEA** — removes the vendor binary dependency. Everything else builds on it, and it's the single strongest "we actually reverse-engineered it" claim.
2. **5F entropy heatmap** — one command produces a shareable PNG of the whole 500 GiB stick. Cheapest instant jaw-drop.
3. **5K CTF + write-up** — turns the whole effort into a story other people can run and learn from. That's what earns real brag rights.

## Honest boundaries (keep these in every claim)

- Vendor SCSI CDB set (Gap 1), `CBMUsbDisk.dll` internals (Gap 2), and NAND ECC/erase policy (Gap 3) are **still open**. Several ideas above attack them; none claim them solved.
- No vendor binary, key leak, or device serial is committed. Keys are allowlisted, serials redacted.
- All write paths are opt-in with read-back verification; scans are read-only.
- Hardware-dependent ideas (5E gadget board, 5L firmware dump, 5O RP2040) are gated on hardware we haven't confirmed owning.

Full designs: `docs/superpowers/specs/`. At program start (5957179): 40/40 tests. Current: 72/72 tests, MIT.
