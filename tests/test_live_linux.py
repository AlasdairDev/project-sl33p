"""End-to-end test: spawn the real Linux core, hunt it, assert the verdict.

Every other test exercises a pure function. This one proves the pipeline the
project actually claims: a process seals its own region, and a separate
read-only process catches it.
"""

from __future__ import annotations

import json
import select
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "src" / "core-linux" / "core_linux.py"
HUNT = ROOT / "src" / "hunt" / "sl33p_hunt.py"

try:
    import cryptography  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux reference core only")
@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class LiveLinuxTests(unittest.TestCase):
    def _hunt(self, protect: str, extra: list[str] | None = None) -> tuple[dict, dict]:
        core = subprocess.Popen(
            [
                sys.executable,
                str(CORE),
                "--lab-ack",
                "--mode",
                "encrypt",
                "--protect",
                protect,
                "--awake",
                "1",
                "--sleep",
                "6",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            ready, _, _ = select.select([core.stdout], [], [], 10)
            self.assertTrue(ready, "core did not print a status line")
            status = json.loads(core.stdout.readline())
            self.assertEqual(status["event"], "ready")

            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "hunt.json"
                command = [
                    sys.executable,
                    str(HUNT),
                    "--pid",
                    str(status["pid"]),
                    "--duration",
                    "4",
                    "--interval",
                    "0.15",
                    "--quiet",
                    "--out",
                    str(out),
                ]
                if extra:
                    command.extend(extra)
                subprocess.run(
                    command,
                    check=False,
                    timeout=30,
                )
                payload = json.loads(out.read_text(encoding="utf-8"))
            return status, payload
        finally:
            core.terminate()
            try:
                core.wait(timeout=5)
            except subprocess.TimeoutExpired:
                core.kill()

    def test_noaccess_is_caught_by_metadata_only(self) -> None:
        status, payload = self._hunt("noaccess")
        rules = {finding["rule"] for finding in payload["findings"]}

        self.assertIn("D3-protection-flip", rules)
        self.assertIn("D4-orphan-noaccess", rules)
        # The hunter honours the protection attribute on purpose: no content
        # rules may fire against a NOACCESS region, even on Linux where the
        # kernel would let /proc/pid/mem read it.
        self.assertNotIn("D2-entropy", rules)
        self.assertNotIn("D6-key-recovery", rules)

        region = int(status["region"]["address"], 16)
        for finding in payload["findings"]:
            self.assertEqual(int(finding["address"], 16), region)

        # The marker may not be visible while the region is dormant. That is the
        # claim, and it is now a counter rather than an inference.
        self.assertEqual(payload["summary"]["marker_hits_while_dormant"], 0)

    def test_no_marker_signature_still_catches(self) -> None:
        _, payload = self._hunt("rw", ["--no-marker"])
        rules = {finding["rule"] for finding in payload["findings"]}

        self.assertEqual(payload["marker"], "")
        self.assertNotIn("D1-marker", rules)
        self.assertIn("D2-entropy", rules)
        self.assertIn("D6-key-recovery", rules)

    def test_readable_ciphertext_is_caught_by_content(self) -> None:
        status, payload = self._hunt("rw")
        rules = {finding["rule"] for finding in payload["findings"]}

        self.assertIn("D2-entropy", rules)
        self.assertIn("D6-key-recovery", rules)

        region = int(status["region"]["address"], 16)
        self.assertEqual(payload["summary"]["verdict"], "DETECTED")

        d2 = next(f for f in payload["findings"] if f["rule"] == "D2-entropy")
        d1 = next((f for f in payload["findings"] if f["rule"] == "D1-marker"), None)
        self.assertEqual(d2["phase"], "dormant")
        if d1 is not None:
            self.assertEqual(d1["phase"], "awake")
        for finding in payload["findings"]:
            self.assertEqual(int(finding["address"], 16), region)


if __name__ == "__main__":
    unittest.main()
