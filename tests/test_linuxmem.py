from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401

import linuxmem
from models import MEM_MAPPED, MEM_PRIVATE, PAGE_NOACCESS

SAMPLE = """\
7f0000000000-7f0000001000 rw-p 00000000 00:00 0
7f0000001000-7f0000002000 ---p 00000000 00:00 0
7f0000002000-7f0000009000 r-xp 00000000 08:02 1234 /usr/lib/libfoo.so
7f0000009000-7f000000a000 r--p 00000000 00:00 0 [heap]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]
"""


class ProtectionMappingTests(unittest.TestCase):
    def test_noaccess(self) -> None:
        self.assertEqual(linuxmem.protect_from_perms("---p"), PAGE_NOACCESS)

    def test_rw(self) -> None:
        self.assertEqual(linuxmem.protect_from_perms("rw-p"), 0x04)

    def test_rx(self) -> None:
        self.assertEqual(linuxmem.protect_from_perms("r-xp"), 0x20)

    def test_read_only(self) -> None:
        self.assertEqual(linuxmem.protect_from_perms("r--p"), 0x02)

    def test_short_string_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            linuxmem.protect_from_perms("rw")


class MapsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.regions = linuxmem.parse_maps(SAMPLE)

    def test_line_count(self) -> None:
        self.assertEqual(len(self.regions), 5)

    def test_anonymous_is_private(self) -> None:
        first = self.regions[0]
        self.assertEqual(first.size, 4096)
        self.assertEqual(first.type, MEM_PRIVATE)
        self.assertEqual(first.protection, "RW")

    def test_noaccess_region(self) -> None:
        second = self.regions[1]
        self.assertFalse(second.readable)
        self.assertEqual(second.protection, "NOACCESS")

    def test_file_backed_is_mapped(self) -> None:
        third = self.regions[2]
        self.assertEqual(third.type, MEM_MAPPED)
        self.assertEqual(third.protection, "RX")

    def test_heap_is_private(self) -> None:
        self.assertEqual(self.regions[3].type, MEM_PRIVATE)

    def test_kernel_page_is_not_private(self) -> None:
        self.assertEqual(self.regions[4].type, MEM_MAPPED)

    def test_blank_lines_are_ignored(self) -> None:
        self.assertEqual(linuxmem.parse_maps("\n\n"), [])


if __name__ == "__main__":
    unittest.main()
