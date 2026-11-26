from __future__ import annotations

import os
import unittest

import _bootstrap  # noqa: F401

import signatures

MARKER = b"SL33P_LAB_MARKER_9f2c1d7e"


class FindAllTests(unittest.TestCase):
    def test_overlapping_matches(self) -> None:
        self.assertEqual(signatures.find_all(b"aaaa", b"aa"), [0, 1, 2])

    def test_empty_needle(self) -> None:
        self.assertEqual(signatures.find_all(b"abc", b""), [])

    def test_no_match(self) -> None:
        self.assertEqual(signatures.find_all(b"abc", b"zz"), [])

    def test_marker_at_offset(self) -> None:
        blob = b"\x00" * 100 + MARKER + b"\x00" * 10
        self.assertEqual(signatures.marker_hits(blob, MARKER), [100])


class KeyHeuristicTests(unittest.TestCase):
    def test_random_32_bytes_look_like_a_key(self) -> None:
        self.assertTrue(signatures.looks_like_key(os.urandom(32)))

    def test_zeros_do_not(self) -> None:
        self.assertFalse(signatures.looks_like_key(b"\x00" * 32))

    def test_repeated_byte_does_not(self) -> None:
        self.assertFalse(signatures.looks_like_key(b"a" * 32))

    def test_wrong_length_does_not(self) -> None:
        self.assertFalse(signatures.looks_like_key(os.urandom(16)))


if __name__ == "__main__":
    unittest.main()
