from __future__ import annotations

import unittest

import _bootstrap  # noqa: F401

import entropy
import make_capture
import rules
from models import MEM_COMMIT, MEM_PRIVATE, Region, RegionChange

MARKER = make_capture.MARKER.encode("ascii")
REGION_BASE = make_capture.REGION_BASE
REGION_SIZE = make_capture.REGION_SIZE
HEADER_BASE = make_capture.HEADER_BASE
HEADER_SIZE = make_capture.HEADER_SIZE


def region(base: int, size: int = REGION_SIZE, protect: int = 0x04) -> Region:
    return Region(base=base, size=size, protect=protect, state=MEM_COMMIT, type=MEM_PRIVATE)


def observation(
    *,
    baseline: list[Region],
    current: list[Region],
    reads: dict[int, bytes],
    changes: list[RegionChange] | None = None,
    cpu: float = 100.0,
    baseline_entropies: dict[int, float] | None = None,
    at: float = 1.0,
) -> rules.Observation:
    entropies = {base: entropy.mean_block_entropy(data) for base, data in reads.items() if data}
    if baseline_entropies is None:
        baseline_entropies = dict(entropies)
    return rules.Observation(
        pid=1234,
        at=at,
        baseline=baseline,
        current=current,
        changes=changes or [],
        reads=reads,
        entropies=entropies,
        baseline_entropies=baseline_entropies,
        cpu_delta_ms=cpu,
        marker=MARKER,
        window_seconds=0.25,
    )


def families(findings: list) -> set[str]:
    return {rules.RULE_FAMILY.get(finding.rule, finding.rule) for finding in findings}


class MarkerRuleTests(unittest.TestCase):
    def test_marker_in_plaintext_is_found(self) -> None:
        data = make_capture.plaintext()
        obs = observation(baseline=[region(REGION_BASE)], current=[region(REGION_BASE)], reads={REGION_BASE: data})
        findings = rules.evaluate(obs)
        self.assertIn("D1", families(findings))
        finding = next(item for item in findings if item.rule == "D1-marker")
        self.assertTrue(finding.marker_present)
        self.assertEqual(finding.evidence["offsets"][0], f"0x{REGION_BASE:X}")

    def test_absent_marker_produces_nothing(self) -> None:
        data = b"ordinary application data " * 2000
        obs = observation(baseline=[region(REGION_BASE)], current=[region(REGION_BASE)], reads={REGION_BASE: data})
        self.assertEqual(rules.evaluate(obs), [])


class EntropyRuleTests(unittest.TestCase):
    def test_encrypted_region_raises_entropy(self) -> None:
        plain = make_capture.plaintext()
        sealed = make_capture.AESGCM(make_capture.KEY).encrypt(make_capture.NONCE, plain, None)
        cipher = sealed[:-16]
        baseline_entropy = entropy.mean_block_entropy(plain)

        obs = observation(
            baseline=[region(REGION_BASE)],
            current=[region(REGION_BASE)],
            reads={REGION_BASE: cipher},
            baseline_entropies={REGION_BASE: baseline_entropy},
        )
        findings = rules.evaluate(obs)
        self.assertIn("D2", families(findings))
        finding = next(item for item in findings if item.rule == "D2-entropy")
        self.assertEqual(finding.confidence, 0.8)
        self.assertGreater(finding.evidence["entropy_delta"], 2.0)
        self.assertFalse(finding.marker_present)

    def test_stable_region_is_not_flagged(self) -> None:
        data = make_capture.plaintext()
        obs = observation(
            baseline=[region(REGION_BASE)],
            current=[region(REGION_BASE)],
            reads={REGION_BASE: data},
            baseline_entropies={REGION_BASE: entropy.mean_block_entropy(data)},
        )
        self.assertNotIn("D2", families(rules.evaluate(obs)))


class ProtectionRuleTests(unittest.TestCase):
    def test_noaccess_cycle_is_flagged_without_reading_memory(self) -> None:
        before = region(REGION_BASE, protect=0x04)
        after = region(REGION_BASE, protect=0x01)
        obs = observation(
            baseline=[before],
            current=[after],
            reads={},  # unreadable, exactly as it is on target
            changes=[RegionChange(base=REGION_BASE, size=REGION_SIZE, before=0x04, after=0x01)],
            cpu=2.0,
        )
        found = families(rules.evaluate(obs))
        self.assertIn("D3", found)
        self.assertIn("D4", found)
        self.assertIn("D5", found)

    def test_busy_process_does_not_get_idle_signal(self) -> None:
        before = region(REGION_BASE, protect=0x04)
        after = region(REGION_BASE, protect=0x01)
        obs = observation(
            baseline=[before],
            current=[after],
            reads={},
            changes=[RegionChange(base=REGION_BASE, size=REGION_SIZE, before=0x04, after=0x01)],
            cpu=400.0,
        )
        self.assertNotIn("D5", families(rules.evaluate(obs)))

    def test_region_already_noaccess_in_baseline_is_not_orphaned(self) -> None:
        before = region(REGION_BASE, protect=0x01)
        obs = observation(baseline=[before], current=[before], reads={})
        self.assertNotIn("D4", families(rules.evaluate(obs)))


class KeyRecoveryTests(unittest.TestCase):
    @unittest.skipUnless(rules.HAVE_AESGCM, "cryptography not installed")
    def test_key_in_memory_decrypts_the_region(self) -> None:
        plain = make_capture.plaintext()
        sealed = make_capture.AESGCM(make_capture.KEY).encrypt(make_capture.NONCE, plain, None)
        cipher, tag = sealed[:-16], sealed[-16:]
        header = make_capture.NONCE + tag + make_capture.KEY

        obs = observation(
            baseline=[region(REGION_BASE), region(HEADER_BASE, HEADER_SIZE)],
            current=[region(REGION_BASE), region(HEADER_BASE, HEADER_SIZE)],
            reads={REGION_BASE: cipher, HEADER_BASE: header},
            baseline_entropies={
                REGION_BASE: entropy.mean_block_entropy(plain),
                HEADER_BASE: entropy.mean_block_entropy(header),
            },
        )
        findings = rules.evaluate(obs)
        self.assertIn("D6", families(findings))
        finding = next(item for item in findings if item.rule == "D6-key-recovery")
        self.assertTrue(finding.evidence["decrypted_marker"])
        self.assertEqual(finding.evidence["header_address"], f"0x{HEADER_BASE:X}")

    @unittest.skipUnless(rules.HAVE_AESGCM, "cryptography not installed")
    def test_wrong_key_is_not_reported(self) -> None:
        plain = make_capture.plaintext()
        sealed = make_capture.AESGCM(bytes(32)).encrypt(make_capture.NONCE, plain, None)
        cipher = sealed[:-16]
        header = make_capture.NONCE + sealed[-16:] + make_capture.KEY

        obs = observation(
            baseline=[region(REGION_BASE)],
            current=[region(REGION_BASE), region(HEADER_BASE, HEADER_SIZE)],
            reads={REGION_BASE: cipher, HEADER_BASE: header},
            baseline_entropies={REGION_BASE: entropy.mean_block_entropy(plain)},
        )
        self.assertNotIn("D6", families(rules.evaluate(obs)))


class AggregationTests(unittest.TestCase):
    def test_noisy_or_is_bounded(self) -> None:
        findings = [
            rules.Finding(pid=1, address="0x1000", size=4096, rule="D3-protection-flip", confidence=0.85),
            rules.Finding(pid=1, address="0x1000", size=4096, rule="D4-orphan-noaccess", confidence=0.6),
            rules.Finding(pid=1, address="0x1000", size=4096, rule="D5-idle-thread", confidence=0.35),
        ]
        value = rules.aggregate_confidence(findings, "0x1000")
        self.assertGreater(value, 0.9)
        self.assertLessEqual(value, 0.99)

    def test_rule_status_reports_d6_state(self) -> None:
        self.assertIn("D6", rules.rule_status())


if __name__ == "__main__":
    unittest.main()
