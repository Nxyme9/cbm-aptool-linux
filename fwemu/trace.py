"""Deterministic synthetic trace export.

Every emitted line starts with the literal word ``synthetic`` and ``emit``
refuses anything else, so no exported line can be mistaken for observed
firmware or hardware evidence.
"""

from __future__ import annotations

from dataclasses import dataclass


def _check_token(name: str, value: str) -> None:
    """Reject empty, whitespace or control-character tokens.

    One record must render to exactly one physical line, so a caller-supplied
    value can never smuggle in a second, unlabelled line.
    """
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not value:
        raise ValueError(f"{name} must not be empty")
    for character in value:
        if character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F:
            raise ValueError(
                f"{name} must not contain whitespace or control characters: {value!r}"
            )


@dataclass(frozen=True)
class TraceRecord:
    op: str
    fields: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _check_token("op", self.op)
        for key, value in self.fields:
            _check_token("field name", key)
            _check_token(f"field {key!r} value", value)

    @property
    def text(self) -> str:
        parts = [f"op={self.op}"] + [f"{key}={value}" for key, value in self.fields]
        return "synthetic " + " ".join(parts)


class Trace:
    """Append-only in-memory trace with an exact, deterministic export."""

    def __init__(self) -> None:
        self._lines: list[str] = []

    def emit(self, record: TraceRecord) -> str:
        line = record.text
        if "synthetic" not in line.split():
            raise ValueError("every trace line must contain the word 'synthetic'")
        self._lines.append(line)
        return line

    @property
    def lines(self) -> tuple[str, ...]:
        return tuple(self._lines)

    def export(self) -> str:
        """Return all lines, each newline-terminated, in emission order."""
        text = "".join(f"{line}\n" for line in self._lines)
        for physical in text.splitlines():
            if "synthetic" not in physical.split():
                raise ValueError("every trace line must contain the word 'synthetic'")
        return text
