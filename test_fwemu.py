#!/usr/bin/env python3
"""Offline checks for the SYNTHETIC fwemu model: stdlib only, no device, no PE.

No firmware image was obtained and no ARM/8051 program is run. BCH vectors are
cross-checked against a deliberately naive independent implementation in this
file; trace lines are compared byte-for-byte and must all say "synthetic".
"""
from __future__ import annotations

import ast
import io
import random
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from fwemu import (  # noqa: E402
    BCH_K,
    BCH_N,
    BCH_T,
    Trace,
    TraceRecord,
    WearModel,
    decode,
    encode,
    generator,
    run_synthetic,
    syndrome,
)
from fwemu import bch as bch_module  # noqa: E402

MESSAGE = bytes((i * 37 + 11) & 0xFF for i in range(BCH_K))

# Derivation of EXPECTED_CODEWORD and NAIVE_GENERATOR (one-off script, no
# fwemu import): GF(2^8) with carry-less multiply reduced by 0x11D; minimal
# polynomials are the coset products for leaders 1,3,5,7; the codeword is the
# naive long-division remainder of m(x)*x^32 modulo g(x), followed by m(x).
# m[i] = (37*i + 11) mod 256. See docs/firmware-emulation.md.
NAIVE_GENERATOR = bytes.fromhex(
    "010001010101010100010000000001000101000101000100000101010001010101"
)
EXPECTED_CODEWORD = bytes.fromhex(
    "57b80870e030e0a849cb10a54a0f45ba96d693b1df00e8811a12ae0ee3f9a7e90"
    "b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186ab"
    "d0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7"
    "095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6eb10"
    "355a7fa4c9ee13385d82a7ccf1163b6085aacff4193e6388add2f71c41668bb0d"
    "5fa1f44698eb3d8fd22476c91b6db00254a6f94b9de03284d7297bce1062b5075"
    "9abfe4092e53789dc2e70c31567ba0c5ea0f34597ea3c8ed12375c81a6cbf0153"
    "a5f84a9cef3183d6287acd1f61b40658aafd4f91e43688db2d7fc21"
)
EXPECTED_TRACE = (
    "synthetic op=model.init blocks=08 pages=04\n"
    "synthetic op=write page=0000 block=00 block_page=00\n"
    "synthetic op=write page=0001 block=00 block_page=01\n"
    "synthetic op=write page=0004 block=01 block_page=00\n"
    "synthetic op=write page=0009 block=02 block_page=01\n"
    "synthetic op=write page=0017 block=04 block_page=01\n"
    "synthetic op=select block=00 erase=0 reason=lowest-count\n"
    "synthetic op=erase block=00 erase=1 reason=lowest-count\n"
)


def naive_mul(a: int, b: int) -> int:
    """Deliberately naive bit-at-a-time GF multiply (no log tables)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1D
        b >>= 1
    return result


def naive_pow(a: int, exponent: int) -> int:
    result = 1
    for _ in range(exponent):
        result = naive_mul(result, a)
    return result


def naive_evaluate(word: bytes, x: int) -> int:
    acc = 0
    for coefficient in reversed(word):
        acc = naive_mul(acc, x) ^ coefficient
    return acc


def naive_syndrome(word: bytes) -> tuple[int, ...]:
    """Brute-force evaluation of the received polynomial at alpha^1..alpha^8."""
    return tuple(naive_evaluate(word, naive_pow(2, i)) for i in range(1, 2 * BCH_T + 1))


def naive_encode(message: bytes) -> bytes:
    """Naive polynomial long division of m(x)*x^32 by the hardcoded generator."""
    work = [0] * (BCH_N - BCH_K) + list(message)
    for j in range(BCH_N - 1, BCH_N - BCH_K - 1, -1):
        coefficient = work[j]
        if coefficient:
            for i, generator_byte in enumerate(NAIVE_GENERATOR):
                work[j - (BCH_N - BCH_K) + i] ^= naive_mul(coefficient, generator_byte)
    return bytes(work[: BCH_N - BCH_K]) + bytes(message)


class FwemuTest(unittest.TestCase):
    def test_zero_message_encodes_to_zero_codeword(self) -> None:
        self.assertEqual(encode(bytes(BCH_K)), bytes(BCH_N))

    def test_hardcoded_bch_vector(self) -> None:
        result = encode(MESSAGE)
        self.assertEqual(len(result), BCH_N)
        self.assertEqual(result, EXPECTED_CODEWORD)
        self.assertEqual(result[BCH_N - BCH_K :], MESSAGE, "systematic message must survive")

    def test_clean_codeword_syndrome_is_zero(self) -> None:
        self.assertEqual(syndrome(EXPECTED_CODEWORD), (0,) * (2 * BCH_T))

    def test_single_byte_error_is_corrected(self) -> None:
        received = bytearray(EXPECTED_CODEWORD)
        received[17] ^= 0x5A
        result = decode(received)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.reason, "corrected")
        self.assertEqual(result.data, EXPECTED_CODEWORD)
        self.assertEqual(result.errors, ((17, 0x5A),))

    def test_four_errors_are_corrected(self) -> None:
        injected = ((7, 0x11), (58, 0x22), (129, 0x33), (200, 0x44))
        received = bytearray(EXPECTED_CODEWORD)
        for position, value in injected:
            received[position] ^= value
        result = decode(received)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.data, EXPECTED_CODEWORD)
        self.assertEqual(result.errors, injected)

    def test_this_five_error_pattern_is_rejected(self) -> None:
        """One benign >t pattern is rejected; that is not a guarantee (next test)."""
        received = bytearray(EXPECTED_CODEWORD)
        for position in (0, 1, 2, 3, 4):
            received[position] ^= 0x11
        result = decode(received)
        self.assertFalse(result.ok)
        self.assertEqual(result.data, bytes(received), "failure must not silently alter input")
        self.assertEqual(result.errors, ())
        self.assertNotEqual(naive_syndrome(received), (0,) * (2 * BCH_T))

    def test_ok_result_is_always_a_valid_codeword_with_at_most_t_errors(self) -> None:
        """The honest contract for >t damage, which cannot be detected.

        BCH(255,223,t=4) has designed distance 9, so a word five errors from one
        codeword can sit within four of another. This known pattern does exactly
        that: `decode` returns ok=True with four reported errors, a zero
        syndrome and data that is NOT the original codeword (distance 9). The
        invariant asserted here is the only one that holds: ok=True means "this
        is a valid codeword with at most t reported errors", never "the
        original was recovered".
        """
        known = bytearray(EXPECTED_CODEWORD)
        for position, value in ((63, 225), (68, 117), (90, 52), (123, 168), (217, 239)):
            known[position] ^= value
        patterns = [bytes(known)]
        rng = random.Random(20261126)
        for _ in range(200):
            sample = bytearray(EXPECTED_CODEWORD)
            for position in rng.sample(range(BCH_N), 5):
                sample[position] ^= rng.randrange(1, 256)
            patterns.append(bytes(sample))
        for received in patterns:
            result = decode(received)
            if result.ok:
                self.assertEqual(syndrome(result.data), (0,) * (2 * BCH_T))
                self.assertLessEqual(len(result.errors), BCH_T)
            else:
                self.assertEqual(result.data, received)
                self.assertEqual(result.errors, ())

    def test_trace_rejects_whitespace_and_control_characters(self) -> None:
        """A caller value can never smuggle in a second, unlabelled line."""
        for bad in ("x\nforged line", "x\rforged", "a b", "a\tb", "a\x00b", "a\x7fb"):
            with self.assertRaises(ValueError, msg=bad):
                TraceRecord("op", (("reason", bad),))
            with self.assertRaises(ValueError, msg=bad):
                TraceRecord(bad, ())
            with self.assertRaises(ValueError, msg=bad):
                TraceRecord("op", ((bad, "value"),))
        with self.assertRaises(ValueError):
            TraceRecord("", ())
        with self.assertRaises(TypeError):
            TraceRecord("op", (("reason", 7),))  # type: ignore[arg-type]

    def test_export_never_contains_an_unlabelled_line(self) -> None:
        trace = Trace()
        wear = WearModel(blocks=8, pages_per_block=4, trace=trace)
        wear.apply_write_pattern((0, 1, 4, 9, 17))
        wear.balanced_erase(reason="lowest-count")
        physical = trace.export().splitlines()
        self.assertEqual(len(physical), len(trace.lines))
        self.assertTrue(all("synthetic" in line.split() for line in physical))

    def test_naive_crosscheck_of_gf_encode_syndrome_and_decode(self) -> None:
        for a in range(256):
            for b in (0, 1, 2, 3, 0x80, 0x1D, 0xA5, 0xFF):
                self.assertEqual(
                    bch_module.gf_mul(a, b), naive_mul(a, b), f"gf_mul({a},{b})"
                )
        self.assertEqual(generator(), tuple(NAIVE_GENERATOR))
        self.assertEqual(encode(MESSAGE), naive_encode(MESSAGE))
        self.assertEqual(syndrome(EXPECTED_CODEWORD), naive_syndrome(EXPECTED_CODEWORD))

        received = bytearray(EXPECTED_CODEWORD)
        for position, value in ((7, 0x11), (58, 0x22), (129, 0x33), (200, 0x44)):
            received[position] ^= value
        self.assertEqual(syndrome(received), naive_syndrome(received))
        result = decode(received)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(naive_syndrome(result.data), (0,) * (2 * BCH_T))
        self.assertEqual(result.data, EXPECTED_CODEWORD)

    def test_erase_counts_are_monotonic_and_one_block_per_erase(self) -> None:
        wear = WearModel(blocks=8, pages_per_block=4, trace=Trace())
        wear.apply_write_pattern(tuple(range(0, 32, 3)))
        previous = list(wear.erase_counts)
        for _ in range(24):
            block = wear.balanced_erase(reason="monotonic")
            counts = wear.erase_counts
            self.assertEqual(counts[block], previous[block] + 1)
            deltas = [counts[i] - previous[i] for i in range(wear.blocks)]
            self.assertEqual(deltas.count(1), 1, deltas)
            self.assertEqual(deltas.count(0), wear.blocks - 1, deltas)
            self.assertTrue(all(delta >= 0 for delta in deltas), deltas)
            previous = list(counts)
        self.assertEqual(sum(previous), 24)

    def test_balanced_policy_prefers_lowest_erase_count(self) -> None:
        wear = WearModel(blocks=8, trace=Trace())
        wear.erase_counts[:] = [5, 5, 5, 5, 5, 5, 5, 2]
        self.assertEqual(wear.choose_erase_block("unequal"), 7)
        wear.erase_counts[:] = [5, 2, 5, 5, 5, 5, 5, 3]
        self.assertEqual(wear.choose_erase_block("unequal"), 1)

    def test_balanced_policy_breaks_ties_by_lowest_index(self) -> None:
        wear = WearModel(blocks=8, trace=Trace())
        self.assertEqual(wear.choose_erase_block("equal"), 0)
        for index in range(wear.blocks):
            wear.erase_counts[index] = 3
        self.assertEqual(wear.choose_erase_block("equal"), 0)
        for index in (0, 1):
            wear.erase_counts[index] = 4
        self.assertEqual(wear.choose_erase_block("equal"), 2)

    def test_fixed_workload_trace_is_byte_exact_and_labelled(self) -> None:
        trace = Trace()
        wear = WearModel(blocks=8, pages_per_block=4, trace=trace)
        wear.apply_write_pattern((0, 1, 4, 9, 17))
        wear.balanced_erase(reason="lowest-count")
        self.assertEqual(trace.export(), EXPECTED_TRACE)
        self.assertTrue(all("synthetic" in line.split() for line in trace.lines))

    def test_same_workload_twice_is_deterministic(self) -> None:
        first = run_synthetic()
        second = run_synthetic()
        self.assertEqual(first.trace.export(), second.trace.export())
        self.assertEqual(first.trace.export(), run_synthetic().trace.export())

    def test_hook_runner_drives_the_model(self) -> None:
        run = run_synthetic()
        self.assertTrue(run.decode.ok, run.decode.reason)
        self.assertEqual(run.decode.data, EXPECTED_CODEWORD)
        self.assertEqual(run.mmio_value, 0x01)
        self.assertEqual(len(run.syndrome), 2 * BCH_T)
        self.assertTrue(any(run.syndrome), "hook must report the injected error")
        self.assertEqual(syndrome(run.decode.data), (0,) * (2 * BCH_T))
        self.assertTrue(all("synthetic" in line.split() for line in run.trace.lines))

    def test_packages_import_only_stdlib(self) -> None:
        local = {"bch", "hooks", "trace", "wear"}
        forbidden = {"unicorn", "numpy", "pytest", "scipy", "torch", "mcp"}
        stdlib = set(sys.stdlib_module_names) | {"__future__"}
        package = ROOT / "fwemu"
        for path in sorted(package.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            for banned in forbidden:
                self.assertIsNone(
                    re.search(rf"\b(?:import|from)\s+{banned}\b", source),
                    f"{path.name} imports {banned}",
                )
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = {alias.name.split(".")[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    roots = {(node.module or "").split(".")[0]}
                else:
                    continue
                for root in roots:
                    self.assertTrue(
                        root in stdlib or root in local,
                        f"{path.name}: non-stdlib import {root}",
                    )


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output, verbosity=0).run(suite)
    failed = len(result.failures) + len(result.errors)
    print(f"test_fwemu: {result.testsRun - failed} passed, {failed} failed")
    if failed:
        sys.exit(1)
