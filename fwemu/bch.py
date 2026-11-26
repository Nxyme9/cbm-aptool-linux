"""SYNTHETIC BCH model over GF(2^8), primitive polynomial 0x11D.

The parameters below (n=255, k=223, t=4, roots alpha^1..alpha^8) were chosen
for this harness so the arithmetic is checkable with the Python standard
library. They are SYNTHETIC: they are NOT claimed to match CBM2199E, CBM2199s
or CBM3380 hardware, and no firmware image was used to choose them.

Decoding limit (a property of bounded-distance decoding, not a bug): `decode`
corrects up to t=4 byte errors and returns `ok=False` for most heavier damage,
but damage beyond t can also land within distance t of a *different* codeword.
In that case the result is a valid codeword with a zero syndrome and at most
four reported errors, and it is silently wrong. `ok=True` therefore means
"this is a codeword", not "at most four bytes were corrupted".

Coefficients are little-endian bytes: index i is the coefficient of x^i.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass

BCH_N = 255
BCH_K = 223
BCH_T = 4
FIELD_POLY = 0x11D
PARITY = BCH_N - BCH_K  # 32 = degree of the generator

_EXP = [0] * 510
_LOG = [0] * 256


def _clmul(a: int, b: int) -> int:
    """Carry-less product reduced by 0x11D (table constructor only)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1D if high else 0)
        b >>= 1
    return result


def _build_tables() -> None:
    value = 1
    for i in range(255):
        _EXP[i] = value
        _LOG[value] = i
        value = _clmul(value, 2)
    for i in range(255, len(_EXP)):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def gf_mul(a: int, b: int) -> int:
    """Multiply two field elements via the synthetic log/antilog tables."""
    if not 0 <= a <= 0xFF or not 0 <= b <= 0xFF:
        raise ValueError("GF(2^8) elements must be bytes")
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(2^8) division by zero")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def gf_pow(a: int, exponent: int) -> int:
    if a == 0:
        return 0 if exponent else 1
    return _EXP[(_LOG[a] * exponent) % 255]


def _coset(leader: int) -> tuple[int, ...]:
    seen: set[int] = set()
    value = leader
    while value not in seen:
        seen.add(value)
        value = (value * 2) % 255
    return tuple(sorted(seen))


def _min_poly(leader: int) -> list[int]:
    poly = [1]
    for exponent in _coset(leader):
        factor = [gf_pow(2, exponent), 1]  # x + alpha^exponent
        product = [0] * (len(poly) + 1)
        for i, a in enumerate(poly):
            for j, b in enumerate(factor):
                product[i + j] ^= gf_mul(a, b)
        poly = product
    return poly


@functools.lru_cache(maxsize=1)
def generator() -> tuple[int, ...]:
    """Return the monic generator polynomial, low coefficient first."""
    poly = [1]
    for leader in (1, 3, 5, 7):  # roots alpha^1..alpha^8, degree 32
        factor = _min_poly(leader)
        product = [0] * (len(poly) + len(factor) - 1)
        for i, a in enumerate(poly):
            for j, b in enumerate(factor):
                product[i + j] ^= gf_mul(a, b)
        poly = product
    return tuple(poly)


def _evaluate(poly: list[int] | tuple[int, ...], x: int) -> int:
    acc = 0
    for coefficient in reversed(poly):
        acc = gf_mul(acc, x) ^ coefficient
    return acc


def encode(message: bytes) -> bytes:
    """Systematic encode: 32-byte remainder followed by the 223-byte message."""
    msg = bytes(message)
    if len(msg) != BCH_K:
        raise ValueError(f"message must be {BCH_K} bytes, got {len(msg)}")
    gen = generator()
    work = [0] * PARITY + list(msg)  # m(x) * x^32
    for j in range(BCH_N - 1, PARITY - 1, -1):
        coefficient = work[j]
        if coefficient:
            for i, gen_i in enumerate(gen):
                work[j - PARITY + i] ^= gf_mul(coefficient, gen_i)
    return bytes(work[:PARITY]) + msg


def syndrome(received: bytes) -> tuple[int, ...]:
    """Return S_1..S_8 for a received codeword (all zero iff it is clean)."""
    word = bytes(received)
    if len(word) != BCH_N:
        raise ValueError(f"received codeword must be {BCH_N} bytes, got {len(word)}")
    return tuple(_evaluate(word, gf_pow(2, i)) for i in range(1, 2 * BCH_T + 1))


@dataclass(frozen=True)
class DecodeResult:
    """Structured decode result; no printing and no global state."""

    ok: bool
    data: bytes  # corrected 255-byte codeword (original on failure)
    errors: tuple[tuple[int, int], ...]  # (position, error byte) pairs
    syndrome: tuple[int, ...]
    reason: str


def _berlekamp_massey(syndromes: tuple[int, ...]) -> list[int]:
    locator = [1]
    previous = [1]
    degree = 0
    shift = 1
    previous_discrepancy = 1
    for n in range(len(syndromes)):
        discrepancy = syndromes[n]
        for i in range(1, degree + 1):
            discrepancy ^= gf_mul(locator[i], syndromes[n - i])
        if discrepancy == 0:
            shift += 1
            continue
        saved = locator[:]
        scale = gf_div(discrepancy, previous_discrepancy)
        needed = len(previous) + shift
        if len(locator) < needed:
            locator += [0] * (needed - len(locator))
        for i, value in enumerate(previous):
            locator[i + shift] ^= gf_mul(scale, value)
        if 2 * degree <= n:
            degree = n + 1 - degree
            previous = saved
            previous_discrepancy = discrepancy
            shift = 1
        else:
            shift += 1
    return locator[: degree + 1]


def _solve(matrix: list[list[int]], values: list[int]) -> list[int] | None:
    """Gaussian elimination over GF(2^8); None means singular."""
    size = len(values)
    rows = [matrix[i][:] + [values[i]] for i in range(size)]
    for column in range(size):
        pivot = next((r for r in range(column, size) if rows[r][column]), None)
        if pivot is None:
            return None
        rows[column], rows[pivot] = rows[pivot], rows[column]
        inverse = gf_div(1, rows[column][column])
        rows[column] = [gf_mul(v, inverse) for v in rows[column]]
        for r in range(size):
            if r != column and rows[r][column]:
                factor = rows[r][column]
                rows[r] = [a ^ gf_mul(factor, b) for a, b in zip(rows[r], rows[column])]
    return [rows[i][size] for i in range(size)]


def decode(received: bytes) -> DecodeResult:
    """Correct up to 4 byte errors; heavier damage is rejected *or* mis-corrected.

    See the module docstring: beyond t=4 the decoder may return a different
    valid codeword with `ok=True`. That is inherent to bounded-distance
    decoding and is documented, not detected.
    """
    word = bytes(received)
    calculated = syndrome(word)

    def failure(reason: str) -> DecodeResult:
        return DecodeResult(False, word, (), calculated, reason)

    if not any(calculated):
        return DecodeResult(True, word, (), calculated, "clean")
    locator = _berlekamp_massey(calculated)
    if len(locator) - 1 > BCH_T:
        return failure("locator-degree-gt-4")

    positions: list[int] = []
    for position in range(BCH_N):
        inverse = gf_pow(2, (BCH_N - position) % BCH_N)  # alpha^-position
        if _evaluate(locator, inverse) == 0:
            positions.append(position)
    if len(positions) != len(locator) - 1:
        return failure("chien-root-mismatch")

    matrix = [
        [gf_pow(2, ((i + 1) * position) % BCH_N) for position in positions]
        for i in range(len(positions))
    ]
    magnitudes = _solve(matrix, list(calculated[: len(positions)]))
    if magnitudes is None:
        return failure("singular-magnitude-system")

    corrected = bytearray(word)
    errors: list[tuple[int, int]] = []
    for position, magnitude in zip(positions, magnitudes):
        corrected[position] ^= magnitude
        errors.append((position, magnitude))
    if any(syndrome(corrected)):
        return failure("post-correction-syndrome-nonzero")
    return DecodeResult(True, bytes(corrected), tuple(errors), calculated, "corrected")
