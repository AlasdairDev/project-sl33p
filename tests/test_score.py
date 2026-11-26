from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401

import score

BASE = 0x1F000000
SIZE = 65536


def finding(address: str, rule: str = "D2-entropy", confidence: float = 0.8, at: float = 1.0) -> dict:
    return {
        "address": address,
        "size": SIZE,
        "rule": rule,
        "confidence": confidence,
        "observed_at": at,
    }


class ScoreTests(unittest.TestCase):
    def test_expected_family_inside_truth_is_caught(self) -> None:
        case = {"name": "obf", "technique": "t", "expected": ["D2", "D6"]}
        result = score.score_case(
            case,
            [finding(f"0x{BASE:X}"), finding(f"0x{BASE:X}", rule="D6-key-recovery", confidence=0.99, at=1.4)],
            truth_base=BASE,
            truth_size=SIZE,
        )
        self.assertTrue(result.caught)
        self.assertEqual(result.detected, ["D2", "D6"])
        self.assertEqual(result.time_to_detect_s, 1.0)
        self.assertEqual(result.max_confidence, 0.99)

    def test_finding_outside_truth_does_not_count(self) -> None:
        case = {"name": "obf", "technique": "t", "expected": ["D2"]}
        result = score.score_case(
            case,
            [finding("0x90000000")],
            truth_base=BASE,
            truth_size=SIZE,
        )
        self.assertFalse(result.caught)
        self.assertEqual(result.detected, [])

    def test_missing_family_is_a_miss(self) -> None:
        case = {"name": "obf", "technique": "t", "expected": ["D2", "D6"]}
        result = score.score_case(
            case, [finding(f"0x{BASE:X}")], truth_base=BASE, truth_size=SIZE
        )
        self.assertFalse(result.caught)
        self.assertIn("D6", result.note)

    def test_low_confidence_is_ignored(self) -> None:
        case = {"name": "obf", "technique": "t", "expected": ["D2"]}
        result = score.score_case(
            case,
            [finding(f"0x{BASE:X}", confidence=0.4)],
            truth_base=BASE,
            truth_size=SIZE,
        )
        self.assertFalse(result.caught)

    def test_control_with_no_findings_passes(self) -> None:
        case = {"name": "control", "technique": "t", "kind": "control", "expected": []}
        result = score.score_case(case, [])
        self.assertTrue(result.caught)
        self.assertEqual(result.note, "control: no findings expected")

    def test_control_with_findings_is_a_false_positive(self) -> None:
        case = {"name": "control", "technique": "t", "kind": "control", "expected": []}
        result = score.score_case(case, [finding("0x100000", confidence=0.9)])
        self.assertFalse(result.caught)
        self.assertIn("false positive", result.note)


if __name__ == "__main__":
    unittest.main()
