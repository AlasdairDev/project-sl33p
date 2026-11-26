from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401

import make_capture
import replay
import rules


@unittest.skipUnless(make_capture.HAVE_AESGCM, "cryptography not installed")
class CaptureTests(unittest.TestCase):
    def test_capture_is_deterministic(self) -> None:
        first = json.dumps(make_capture.build_capture(), sort_keys=True)
        second = json.dumps(make_capture.build_capture(), sort_keys=True)
        self.assertEqual(first, second)

    def test_plaintext_matches_core_layout(self) -> None:
        data = make_capture.plaintext()
        self.assertEqual(len(data), make_capture.REGION_SIZE)
        self.assertTrue(data.startswith(b"SL33P_LAB_MARKER_9f2c1d7e\n"))
        self.assertEqual(data.count(b"SL33P_LAB_MARKER_9f2c1d7e"), 1)
        self.assertIn(b"sl33p lab benign region slot 00001", data)


@unittest.skipUnless(make_capture.HAVE_AESGCM, "cryptography not installed")
class ReplayTests(unittest.TestCase):
    def _findings(self) -> list:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capture.json"
            path.write_text(
                json.dumps(make_capture.build_capture(), sort_keys=True), encoding="utf-8"
            )
            capture = replay.load_capture(path)
            observations = replay.observations(capture)
            self.assertEqual(len(observations), 2)
            collected = []
            for observation in observations:
                collected.extend(rules.evaluate(observation))
            return rules.merge(collected)

    def test_replay_finds_entropy_and_marker(self) -> None:
        families = {rules.RULE_FAMILY.get(f.rule, f.rule) for f in self._findings()}
        self.assertIn("D1", families)  # marker back after wake
        self.assertIn("D2", families)  # entropy jumped while asleep

    @unittest.skipUnless(rules.HAVE_AESGCM, "cryptography not installed")
    def test_replay_recovers_the_payload(self) -> None:
        families = {rules.RULE_FAMILY.get(f.rule, f.rule) for f in self._findings()}
        self.assertIn("D6", families)

    def test_replay_has_no_false_positive_on_the_other_region(self) -> None:
        for finding in self._findings():
            self.assertNotEqual(finding.address, f"0x{make_capture.OTHER_BASE:X}")


if __name__ == "__main__":
    unittest.main()
