"""Instrumentation hooks for a future Unicorn runner (SYNTHETIC model only).

This module never imports unicorn. ``HookSink`` is the interface a future CPU
runner would call from its code/memory hooks: syndrome_hook on a BCH syndrome
calculation, erase_count_hook on a block erase, and the MMIO pair on register
accesses. ``run_synthetic`` drives the same interface in plain Python so the
method is testable without an emulator, an ARM toolchain or a firmware dump.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import bch
from .trace import Trace, TraceRecord
from .wear import WearModel


class HookSink:
    """Default Python hook implementations; subclass to attach real instrumentation."""

    def __init__(self, trace: Trace) -> None:
        self.trace = trace
        self.registers: dict[int, int] = {}

    def syndrome_hook(self, received: bytes) -> tuple[int, ...]:
        calculated = bch.syndrome(received)
        self.trace.emit(
            TraceRecord("hook.syndrome", (("nonzero", str(sum(v != 0 for v in calculated))),))
        )
        return calculated

    def erase_count_hook(self, block: int, count: int) -> int:
        self.trace.emit(
            TraceRecord("hook.erasecount", (("block", f"{block:02d}"), ("erase", str(count))))
        )
        return count

    def mmio_write_hook(self, address: int, value: int) -> None:
        self.registers[address] = value
        self.trace.emit(
            TraceRecord(
                "hook.mmio-write",
                (("addr", f"0x{address:04x}"), ("value", f"0x{value:02x}")),
            )
        )

    def mmio_read_hook(self, address: int) -> int:
        value = self.registers.get(address, 0)
        self.trace.emit(
            TraceRecord(
                "hook.mmio-read",
                (("addr", f"0x{address:04x}"), ("value", f"0x{value:02x}")),
            )
        )
        return value


@dataclass(frozen=True)
class SyntheticRun:
    trace: Trace
    decode: bch.DecodeResult
    wear: WearModel
    syndrome: tuple[int, ...]
    mmio_value: int


def run_synthetic() -> SyntheticRun:
    """Drive BCH + wear through the hook interface with fixed synthetic inputs."""
    trace = Trace()
    wear = WearModel(trace=trace)
    hooks = HookSink(trace)
    message = bytes((i * 37 + 11) & 0xFF for i in range(bch.BCH_K))
    codeword = bch.encode(message)
    received = bytearray(codeword)
    received[17] ^= 0x5A
    calculated = hooks.syndrome_hook(bytes(received))
    decoded = bch.decode(bytes(received))
    wear.apply_write_pattern((0, 1, 16, 17, 32, 64))
    block = wear.balanced_erase(reason="lowest-count")
    hooks.erase_count_hook(block, wear.erase_counts[block])
    hooks.mmio_write_hook(0x1000, 0x01)
    value = hooks.mmio_read_hook(0x1000)
    return SyntheticRun(trace, decoded, wear, calculated, value)
