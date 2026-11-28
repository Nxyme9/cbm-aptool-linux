"""SYNTHETIC block/page wear model.

Geometry (64 blocks x 16 pages) is chosen for this harness; it is NOT claimed
to match any CBM controller. Each state change emits a labelled trace record.
"""

from __future__ import annotations

from .trace import Trace, TraceRecord


class WearModel:
    """Fixed workload to block mapping plus a deterministic balanced-erase policy."""

    def __init__(
        self,
        blocks: int = 64,
        pages_per_block: int = 16,
        trace: Trace | None = None,
    ) -> None:
        if blocks <= 0 or pages_per_block <= 0:
            raise ValueError("blocks and pages_per_block must be positive")
        self.blocks = blocks
        self.pages_per_block = pages_per_block
        self.erase_counts = [0] * blocks
        self.trace = Trace() if trace is None else trace
        self.trace.emit(
            TraceRecord(
                "model.init",
                (("blocks", f"{blocks:02d}"), ("pages", f"{pages_per_block:02d}")),
            )
        )

    def _check_block(self, block: int) -> None:
        if not 0 <= block < self.blocks:
            raise ValueError(f"block {block} outside 0..{self.blocks - 1}")

    def write(self, page: int) -> TraceRecord:
        """Map a logical page to a block; writes do not erase anything."""
        if page < 0:
            raise ValueError("page must be non-negative")
        block = page // self.pages_per_block
        self._check_block(block)
        record = TraceRecord(
            "write",
            (
                ("page", f"{page:04d}"),
                ("block", f"{block:02d}"),
                ("block_page", f"{page % self.pages_per_block:02d}"),
            ),
        )
        self.trace.emit(record)
        return record

    def apply_write_pattern(self, pattern: tuple[int, ...] | list[int]) -> tuple[TraceRecord, ...]:
        return tuple(self.write(page) for page in pattern)

    def choose_erase_block(self, reason: str) -> int:
        """Lowest erase count, ties broken by lowest block index."""
        block = min(range(self.blocks), key=lambda index: (self.erase_counts[index], index))
        self.trace.emit(
            TraceRecord(
                "select",
                (
                    ("block", f"{block:02d}"),
                    ("erase", str(self.erase_counts[block])),
                    ("reason", reason),
                ),
            )
        )
        return block

    def erase(self, block: int, reason: str) -> TraceRecord:
        self._check_block(block)
        self.erase_counts[block] += 1
        record = TraceRecord(
            "erase",
            (
                ("block", f"{block:02d}"),
                ("erase", str(self.erase_counts[block])),
                ("reason", reason),
            ),
        )
        self.trace.emit(record)
        return record

    def balanced_erase(self, reason: str = "lowest-count") -> int:
        block = self.choose_erase_block(reason)
        self.erase(block, reason)
        return block
