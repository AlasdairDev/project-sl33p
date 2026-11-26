"""Evidence rendering: JSON for machines, one self-contained HTML file for humans.

No CDN, no JavaScript, no fonts to fetch. The HTML opens offline, which is a
hard requirement for a lab that runs with networking removed.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "report" / "template.html"

_VERSION = "1.0.0"


def _verdict(findings: list[dict[str, Any]]) -> tuple[str, float]:
    if not findings:
        return ("NO FINDINGS", 0.0)
    best = max(float(item.get("confidence", 0.0)) for item in findings)
    if best >= 0.85:
        return ("DETECTED", best)
    if best >= 0.5:
        return ("SUSPICIOUS", best)
    return ("WEAK SIGNAL", best)


def build_hunt_payload(
    *,
    pid: int,
    marker: str,
    mode: str,
    blind: bool,
    duration_s: float,
    ticks: int,
    findings: list[dict[str, Any]],
    regions: list[dict[str, Any]],
    rule_status: dict[str, str],
    image: str | None = None,
    hints: dict[str, Any] | None = None,
    generated_at: str = "",
) -> dict[str, Any]:
    verdict, best = _verdict(findings)

    by_rule: dict[str, int] = {}
    for finding in findings:
        rule = str(finding.get("rule", "unknown"))
        by_rule[rule] = by_rule.get(rule, 0) + 1

    first = min((float(item.get("observed_at", 0.0)) for item in findings), default=None)
    dormant_findings = sum(1 for item in findings if item.get("phase") == "dormant")
    marker_while_dormant = sum(
        1
        for item in findings
        if item.get("rule") == "D1-marker" and item.get("phase") == "dormant"
    )

    return {
        "tool": "sl33p-hunt",
        "version": _VERSION,
        "generated_at": generated_at,
        "mode": mode,
        "blind": blind,
        "pid": pid,
        "image": image,
        "marker": marker,
        "duration_s": round(duration_s, 3),
        "ticks": ticks,
        "rule_status": rule_status,
        "hints": hints,
        "findings": findings,
        "regions": regions,
        "summary": {
            "verdict": verdict,
            "finding_count": len(findings),
            "max_confidence": best,
            "first_detect_s": None if first is None else round(first, 3),
            "dormant_findings": dormant_findings,
            "marker_hits_while_dormant": marker_while_dormant,
            "by_rule": dict(sorted(by_rule.items())),
        },
    }


def build_matrix_payload(
    *, cases: list[dict[str, Any]], generated_at: str = "", environment: dict[str, Any] | None = None
) -> dict[str, Any]:
    caught = sum(1 for case in cases if case.get("caught"))
    return {
        "tool": "sl33p-matrix",
        "version": _VERSION,
        "generated_at": generated_at,
        "environment": environment or {},
        "cases": cases,
        "summary": {
            "total": len(cases),
            "caught": caught,
            "missed": len(cases) - caught,
        },
    }


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _summary_cards(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    cards = []

    if payload["tool"] == "sl33p-matrix":
        cards = [
            ("cases", summary.get("total", 0)),
            ("caught", summary.get("caught", 0)),
            ("missed", summary.get("missed", 0)),
        ]
    else:
        cards = [
            ("verdict", summary.get("verdict", "-")),
            ("findings", summary.get("finding_count", 0)),
            ("max confidence", summary.get("max_confidence", 0)),
            ("first detect", f"{summary.get('first_detect_s')}s" if summary.get("first_detect_s") is not None else "-"),
        ]

    return "\n".join(
        f'<div class="card"><span class="card-label">{_esc(label)}</span>'
        f'<span class="card-value">{_esc(value)}</span></div>'
        for label, value in cards
    )


def _meta_line(payload: dict[str, Any]) -> str:
    bits = [
        f"tool <code>{_esc(payload.get('tool'))}</code>",
        f"version <code>{_esc(payload.get('version'))}</code>",
    ]
    for key in ("mode", "pid", "image", "duration_s", "ticks", "generated_at"):
        value = payload.get(key)
        if value not in (None, "", 0):
            bits.append(f"{_esc(key)} <code>{_esc(value)}</code>")
    if payload.get("blind"):
        bits.append("<code>blind</code> (no target self-report trusted)")
    return " &middot; ".join(bits)


def _rule_chips(payload: dict[str, Any]) -> str:
    status = payload.get("rule_status") or {}
    if not status:
        return ""
    return " ".join(
        f'<span class="chip{" chip-off" if "unavailable" in value else ""}">'
        f"{_esc(rule)}: {_esc(value)}</span>"
        for rule, value in status.items()
    )


def _case_rows(cases: list[dict[str, Any]]) -> str:
    rows = []
    for case in cases:
        caught = bool(case.get("caught"))
        badge = '<span class="badge ok">caught</span>' if caught else '<span class="badge bad">missed</span>'
        detected = ", ".join(case.get("detected") or []) or "-"
        rows.append(
            "<tr>"
            f"<td>{_esc(case.get('name'))}</td>"
            f"<td>{_esc(case.get('technique'))}</td>"
            f"<td>{_esc(', '.join(case.get('expected') or []))}</td>"
            f"<td>{_esc(detected)}</td>"
            f"<td>{badge}</td>"
            f"<td>{_esc(case.get('time_to_detect_s'))}</td>"
            f"<td>{_esc(case.get('max_confidence'))}</td>"
            f"<td>{_esc(case.get('note') or '')}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _finding_rows(findings: list[dict[str, Any]]) -> str:
    rows = []
    for finding in findings:
        evidence = json.dumps(finding.get("evidence") or {}, sort_keys=True)
        if len(evidence) > 160:
            evidence = evidence[:157] + "..."
        rows.append(
            "<tr>"
            f"<td>{_esc(finding.get('observed_at'))}</td>"
            f"<td><code>{_esc(finding.get('rule'))}</code></td>"
            f"<td>{_esc(finding.get('phase') or '-')}</td>"
            f"<td><code>{_esc(finding.get('address'))}</code></td>"
            f"<td>{_esc(finding.get('size'))}</td>"
            f"<td>{_esc(finding.get('protection_before') or '-')} &rarr; "
            f"{_esc(finding.get('protection_after') or '-')}</td>"
            f"<td>{_esc(finding.get('entropy'))}</td>"
            f"<td>{_esc(finding.get('confidence'))}</td>"
            f"<td><code>{_esc(evidence)}</code></td>"
            "</tr>"
        )
    return "\n".join(rows)


def _region_rows(regions: list[dict[str, Any]]) -> str:
    rows = []
    for region in regions:
        rows.append(
            "<tr>"
            f"<td><code>{_esc(region.get('address'))}</code></td>"
            f"<td>{_esc(region.get('size'))}</td>"
            f"<td>{_esc(region.get('protection'))}</td>"
            f"<td>{_esc(region.get('type'))}</td>"
            f"<td>{_esc(region.get('entropy'))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_html(payload: dict[str, Any], template_path: str | Path | None = None) -> str:
    template = Path(template_path or TEMPLATE_PATH).read_text(encoding="utf-8")

    cases = payload.get("cases") or []
    findings = payload.get("findings") or []
    regions = payload.get("regions") or []

    matrix = ""
    if cases:
        matrix = (
            "<section><h2>Detection matrix</h2>"
            "<table><thead><tr><th>case</th><th>technique</th><th>expected</th>"
            "<th>detected</th><th>result</th><th>time to detect (s)</th>"
            "<th>confidence</th><th>note</th></tr></thead><tbody>"
            f"{_case_rows(cases)}</tbody></table>"
            '<p class="note">Time to detect is measured from the start of the sleep window. '
            "0.0 means the first poll after the transition; the hunter polls every "
            f"{_esc((payload.get('environment') or {}).get('poll_interval_s', '?'))} s.</p>"
            "</section>"
        )

    findings_html = ""
    if findings:
        findings_html = (
            "<section><h2>Findings</h2>"
            "<table><thead><tr><th>t (s)</th><th>rule</th><th>phase</th><th>address</th><th>size</th>"
            "<th>protection</th><th>entropy</th><th>confidence</th><th>evidence</th>"
            "</tr></thead><tbody>"
            f"{_finding_rows(findings)}</tbody></table></section>"
        )
    elif payload["tool"] == "sl33p-hunt":
        findings_html = (
            "<section><h2>Findings</h2>"
            '<p class="empty">No rule fired. That is a result too: record it as a miss.</p>'
            "</section>"
        )

    regions_html = ""
    if regions:
        regions_html = (
            "<section><h2>Regions sampled</h2>"
            "<table><thead><tr><th>address</th><th>size</th><th>protection</th>"
            "<th>type</th><th>entropy</th></tr></thead><tbody>"
            f"{_region_rows(regions)}</tbody></table></section>"
        )

    return (
        template.replace("<!--SL33P:META-->", _meta_line(payload))
        .replace("<!--SL33P:SUMMARY-->", _summary_cards(payload))
        .replace("<!--SL33P:CHIPS-->", _rule_chips(payload))
        .replace("<!--SL33P:MATRIX-->", matrix)
        .replace("<!--SL33P:FINDINGS-->", findings_html)
        .replace("<!--SL33P:REGIONS-->", regions_html)
    )


def write_html(path: str | Path, payload: dict[str, Any], template_path: str | Path | None = None) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_html(payload, template_path), encoding="utf-8")
