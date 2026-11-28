"""Synthetic firmware-emulation harness (model-level instrumented simulation).

No firmware image was obtained, no ARM/8051 program is executed, and no
hardware ECC counter is read. This package is a deterministic Python model of
the *method*, not evidence about CBM2199E/2199s/3380 firmware. Every emitted
trace line carries the word ``synthetic``.
"""

from .bch import (
    BCH_K,
    BCH_N,
    BCH_T,
    DecodeResult,
    decode,
    encode,
    gf_mul,
    generator,
    syndrome,
)
from .hooks import HookSink, SyntheticRun, run_synthetic
from .trace import Trace, TraceRecord
from .wear import WearModel

__all__ = [
    "BCH_K",
    "BCH_N",
    "BCH_T",
    "DecodeResult",
    "HookSink",
    "SyntheticRun",
    "Trace",
    "TraceRecord",
    "WearModel",
    "decode",
    "encode",
    "gf_mul",
    "generator",
    "run_synthetic",
    "syndrome",
]
