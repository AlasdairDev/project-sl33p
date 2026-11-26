from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401

import entropy


class ShannonTests(unittest.TestCase):
    def test_empty_is_zero(self) -> None:
        self.assertEqual(entropy.shannon(b""), 0.0)

    def test_constant_is_zero(self) -> None:
        self.assertEqual(entropy.shannon(b"\x00" * 4096), 0.0)

    def test_uniform_byte_distribution_is_eight(self) -> None:
        self.assertAlmostEqual(entropy.shannon(bytes(range(256))), 8.0, places=6)

    def test_ascii_text_is_low(self) -> None:
        value = entropy.shannon(b"sl33p lab benign region slot 00001\n" * 100)
        self.assertLess(value, 5.0)

    def test_encrypted_looking_bytes_are_high(self) -> None:
        import os

        value = entropy.shannon(os.urandom(65536))
        self.assertGreater(value, 7.8)


class BlockTests(unittest.TestCase):
    def test_blocks_split_on_boundaries(self) -> None:
        data = b"\x00" * 4096 + bytes(range(256)) * 16
        blocks = entropy.block_entropies(data, 4096)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0], 0.0)
        self.assertGreater(blocks[1], 7.5)

    def test_trailing_partial_block_is_ignored(self) -> None:
        blocks = entropy.block_entropies(b"\x00" * 5000, 4096)
        self.assertEqual(len(blocks), 1)

    def test_mean_falls_back_for_short_input(self) -> None:
        self.assertEqual(entropy.mean_block_entropy(b"\x00" * 100), 0.0)

    def test_delta(self) -> None:
        self.assertAlmostEqual(entropy.entropy_delta(4.1, 7.9), 3.8)
        self.assertIsNone(entropy.entropy_delta(None, 7.9))


if __name__ == "__main__":
    unittest.main()
