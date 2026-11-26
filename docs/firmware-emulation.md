# Synthetic firmware emulation (wave 5L) — SYNTHETIC ONLY

SYNTHETIC ONLY: no firmware image was obtained, no ARM/8051 program was run,
and Unicorn and an ARM toolchain are absent on this machine (Python 3.14.9
standard library only; `arm-none-eabi-gcc` and `sdcc` are not installed). This
harness is a model-level instrumented simulation that demonstrates the method;
it is not firmware emulation and makes no claim about CBM2199E, CBM2199s or
CBM3380 behaviour.

## What the harness models

- **BCH syndrome/decode:** a synthetic BCH(255, 223, t=4) code over GF(2^8)
  with primitive polynomial 0x11D and roots alpha^1..alpha^8. `encode` is
  systematic generator-polynomial division; `syndrome` evaluates the received
  polynomial at the eight roots; `decode` uses Berlekamp-Massey, Chien search
  and a small GF linear solve to correct at most four byte errors, returning a
  structured `DecodeResult` (`ok`, corrected `data`, `errors`, `syndrome`,
  `reason`). Damage beyond four bytes is **not reliably rejected**: it may be
  reported uncorrectable or silently mis-corrected to a *different* valid
  codeword, because bounded-distance decoding cannot detect that case. `ok=True`
  means "this is a codeword with at most four reported errors", not "the
  original was recovered". These parameters were chosen for the harness; they
  are NOT hardware parameters.
- **Erase-count tracking:** a synthetic, parameterised block/page geometry
  (default 64 blocks x 16 pages), a fixed logical-page-to-block write mapping
  and a per-block erase counter. Writes never erase; erases increment exactly
  one block.
- **Balanced erase:** choose the block with the lowest erase count, breaking
  ties by lowest block index.
- **Trace export:** deterministic records rendered as `synthetic op=... key=...`
  lines. `TraceRecord` rejects whitespace and control characters in `op`,
  field names and values, so a caller value cannot smuggle in a second,
  unlabelled line; `Trace.export()` re-checks every physical line for the word
  `synthetic`. No output can be read as observed firmware evidence. Example:
  `synthetic op=erase block=00 erase=1 reason=lowest-count`.
- **Hooks:** a Python sink for the syndrome, erase-count and MMIO-style
  register read/write events described below.

## Run it

From this repository root:

```
python3 -m py_compile fwemu/*.py test_fwemu.py
python3 test_fwemu.py          # test_fwemu: 17 passed, 0 failed
make test-fwemu
make test                      # same chain, with the fwemu line at the end
```

No emulator, compiler, device node, vendor PE, network or third-party Python
package is used. `test_fwemu.py` cross-checks BCH against an independent naive
GF implementation and naive long division inside the test itself.

## Hook interface for a future Unicorn runner

`fwemu/hooks.py` defines `HookSink`, with these methods:

| Method | Event it would attach to |
| --- | --- |
| `syndrome_hook(received)` | code hook at the firmware syndrome loop; returns S_1..S_8 |
| `erase_count_hook(block, count)` | code hook at the erase counter update |
| `mmio_write_hook(address, value)` | MMIO write hook on a controller register |
| `mmio_read_hook(address)` | MMIO read hook returning the modelled register |

A future Unicorn runner would subclass `HookSink`, call these from its UC hook
callbacks and feed the same `Trace`. `run_synthetic()` drives all four hooks in
plain Python today; `fwemu` never imports `unicorn`. There is no ARM code and no
emulated binary here.

## The firmware-dump attempt was NOT RUN

The read-only firmware-dump attempt over the recovered 5E CDB path was **NOT
RUN**. It needs a device node (for example `/dev/sdX`, gated hardware access)
and a vendor firmware-read CDB, which Gap 1 has not recovered: the 5E capture
table's vendor column reads `not observed`. `cbm-tool` has no firmware-dump
subcommand. The command below captures **CDB call traffic from the vendor PE**,
not firmware bytes, and only after those gates are cleared:

```
./cbm-tool cdb-capture /path/to/CBMUsbDisk.dll --out /tmp/opencode/fw-cdb-capture.txt
```

A byte-for-byte firmware dump would need a separate tool that this repo does
not contain, plus both a device node and a vendor firmware-read CDB. No device
node, vendor PE or vendor CDB was used, and the command above was not executed.

## Gap 3 stays open

Gap 3 (BCH ECC / balanced erase) is **not closed**. Exact gate: a firmware
dump + a CBM2199E/2199s/3380 datasheet + ECC counters. This harness only shows
how such behaviour would be instrumented; its passing tests are not evidence
about any real controller. Gap 1 (vendor CDB set) and Gap 3 remain open, and
this document makes no completeness claim.
