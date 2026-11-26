"""Scoring: turn detector output into caught/missed against ground truth.

The runner knows where the region really is (it launched the process). The
hunter does not. The scoring uses that asymmetry: the hunter's blind output is
against ground truth the hunter never saw.
"""

from __future__ import annotations

from typing import Any

from models import CaseResult

RULE_FAMILY = {
    "D1-marker": "D1",
    "D2-entropy": "D2",
    "D3-protection-flip": "D3",
    "D4-orphan-noaccess": "D4",
    "D5-idle-thread": "D5",
    "D6-key-recovery": "D6",
}


def family(rule: str) -> str:
    return RULE_FAMILY.get(rule, rule.split("-")[0])


def _intersects(address: str, size: int, base: int, base_size: int) -> bool:
    try:
        start = int(address, 16)
    except (TypeError, ValueError):
        return False
    return start < base + base_size and base < start + size


def score_case(
    case: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    truth_base: int | None = None,
    truth_size: int | None = None,
    threshold: float = 0.6,
) -> CaseResult:
    expected = [str(item) for item in case.get("expected") or []]
    is_control = case.get("kind") == "control"

    relevant = findings
    if not is_control and truth_base is not None and truth_size is not None:
        relevant = [
            finding
            for finding in findings
            if _intersects(
                str(finding.get("address", "")),
                int(finding.get("size", 0)),
                truth_base,
                truth_size,
            )
        ]

    strong = [finding for finding in relevant if float(finding.get("confidence", 0.0)) >= threshold]
    detected = sorted({family(str(finding.get("rule", ""))) for finding in strong})

    if is_control:
        caught = not strong
        note = "control: no findings expected" if caught else "false positive on a normal app"
        time_to_detect = None if caught else min(
            (float(finding.get("observed_at", 0.0)) for finding in strong), default=None
        )
        return CaseResult(
            name=str(case.get("name")),
            technique=str(case.get("technique", "")),
            expected=expected,
            detected=detected,
            caught=bool(caught),
            time_to_detect_s=time_to_detect,
            max_confidence=max((float(f.get("confidence", 0.0)) for f in strong), default=0.0),
            finding_count=len(strong),
            note=note,
        )

    missing = [item for item in expected if item not in detected]
    caught = bool(expected) and not missing

    matching = [finding for finding in strong if family(str(finding.get("rule", ""))) in expected]

    def _delay(finding: dict) -> float:
        # Prefer the runner's event-relative measurement: time from the region
        # going dormant to the finding, not from the hunter's start.
        if "detected_after_event_s" in finding:
            return float(finding["detected_after_event_s"])
        return float(finding.get("observed_at", 0.0))

    time_to_detect = min((_delay(finding) for finding in matching), default=None)

    note = "" if caught else ("no expected detector fired" if not matching else f"missing {', '.join(missing)}")

    return CaseResult(
        name=str(case.get("name")),
        technique=str(case.get("technique", "")),
        expected=expected,
        detected=detected,
        caught=caught,
        time_to_detect_s=None if time_to_detect is None else round(time_to_detect, 3),
        max_confidence=max((float(f.get("confidence", 0.0)) for f in strong), default=0.0),
        finding_count=len(strong),
        note=note,
    )
