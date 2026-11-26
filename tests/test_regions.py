from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401

import regions
from models import MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PAGE_NOACCESS, Region


def region(base: int, size: int = 65536, protect: int = 0x04, mem_type: int = MEM_PRIVATE) -> Region:
    return Region(base=base, size=size, protect=protect, state=MEM_COMMIT, type=mem_type)


class DiffTests(unittest.TestCase):
    def test_protection_change_is_reported(self) -> None:
        before = [region(0x1000, protect=0x04)]
        after = [region(0x1000, protect=0x01)]
        changes = regions.diff(before, after)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].base, 0x1000)
        self.assertEqual(changes[0].protection_before, "RW")
        self.assertEqual(changes[0].protection_after, "NOACCESS")

    def test_no_change_is_silent(self) -> None:
        self.assertEqual(regions.diff([region(0x1000)], [region(0x1000)]), [])

    def test_new_region_is_not_a_flip(self) -> None:
        self.assertEqual(regions.diff([], [region(0x2000, protect=0x01)]), [])

    def test_size_change_is_treated_as_new(self) -> None:
        before = [region(0x1000, size=4096)]
        after = [region(0x1000, size=8192, protect=0x01)]
        self.assertEqual(regions.diff(before, after), [])


class ReadingPolicyTests(unittest.TestCase):
    def test_noaccess_is_not_readable(self) -> None:
        self.assertFalse(region(0x1000, protect=PAGE_NOACCESS).readable)

    def test_guard_page_is_not_readable(self) -> None:
        self.assertFalse(region(0x1000, protect=0x104).readable)

    def test_image_region_is_skipped(self) -> None:
        self.assertFalse(regions.worth_reading(region(0x1000, mem_type=MEM_IMAGE)))

    def test_small_region_is_skipped(self) -> None:
        self.assertFalse(regions.worth_reading(region(0x1000, size=512)))

    def test_normal_private_region_is_worth_reading(self) -> None:
        self.assertTrue(regions.worth_reading(region(0x1000)))


class InterestingBasesTests(unittest.TestCase):
    def test_changed_readable_region_is_selected(self) -> None:
        before = [region(0x1000)]
        after = [region(0x1000, protect=0x20)]  # RW -> RX, still readable
        changes = regions.diff(before, after)
        self.assertEqual(regions.interesting_bases(before, after, changes), {0x1000})

    def test_unreadable_changed_region_is_not_read(self) -> None:
        before = [region(0x1000)]
        after = [region(0x1000, protect=0x01)]
        changes = regions.diff(before, after)
        self.assertEqual(regions.interesting_bases(before, after, changes), set())

    def test_large_unrelated_region_is_not_selected(self) -> None:
        big = region(0x9000, size=8 * 1024 * 1024)
        bases = regions.interesting_bases([big], [big], [])
        self.assertEqual(bases, set())


if __name__ == "__main__":
    unittest.main()
