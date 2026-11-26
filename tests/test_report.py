from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401

import report


def sample_payload() -> dict:
    return report.build_hunt_payload(
        pid=1234,
        marker="SL33P_LAB_MARKER_9f2c1d7e",
        mode="replay",
        blind=True,
        duration_s=13.0,
        ticks=2,
        findings=[
            {
                "pid": 1234,
                "address": "0x1F000000",
                "size": 65536,
                "rule": "D2-entropy",
                "confidence": 0.8,
                "marker_present": False,
                "protection_before": "RW",
                "protection_after": "RW",
                "entropy": 7.99,
                "evidence": {"entropy_delta": 3.7},
                "observed_at": 1.0,
            }
        ],
        regions=[
            {
                "address": "0x1F000000",
                "size": 65536,
                "protection": "RW",
                "type": "PRIVATE",
                "entropy": 7.99,
            }
        ],
        rule_status={"D1": "enabled", "D6": "enabled"},
        generated_at="2026-01-01T00:00:00+00:00",
    )


class ReportTests(unittest.TestCase):
    def test_verdict_reflects_confidence(self) -> None:
        payload = sample_payload()
        self.assertEqual(payload["summary"]["verdict"], "SUSPICIOUS")
        self.assertEqual(payload["summary"]["max_confidence"], 0.8)

    def test_html_is_self_contained(self) -> None:
        html = report.render_html(sample_payload())
        lowered = html.lower()
        self.assertNotIn("http://", lowered)
        self.assertNotIn("https://", lowered)
        self.assertNotIn("<script", lowered)
        self.assertIn("D2-entropy", html)
        self.assertIn("0x1F000000", html)

    def test_html_escapes_evidence(self) -> None:
        payload = sample_payload()
        payload["findings"][0]["evidence"] = {"note": "<script>alert(1)</script>"}
        html = report.render_html(payload)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_json_writes_are_byte_identical(self) -> None:
        payload = sample_payload()
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "a.json"
            second = Path(tmp) / "b.json"
            report.write_json(first, payload)
            report.write_json(second, payload)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first.read_text(encoding="utf-8"), json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def test_matrix_payload_counts(self) -> None:
        payload = report.build_matrix_payload(
            cases=[
                {"name": "a", "caught": True, "detected": ["D1"], "expected": ["D1"]},
                {"name": "b", "caught": False, "detected": [], "expected": ["D3"]},
            ],
            generated_at="2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(payload["summary"], {"total": 2, "caught": 1, "missed": 1})
        html = report.render_html(payload)
        self.assertIn("Detection matrix", html)
        self.assertIn("missed", html)


if __name__ == "__main__":
    unittest.main()
