"""The rule engine.

Six independent detectors, each producing a Finding with evidence and a
confidence. None of them trusts the core's stdout: the Observation passed in
is built from memory reads and VirtualQueryEx snapshots only.

D1  marker      readable pages contain the known marker
D2  entropy     a stable private region became significantly more random
D3  flip        a private region changed protection (RW -> NOACCESS/RX/RWX ...)
D4  orphan      a private NOACCESS region exists that the baseline did not have
D5  idle        the process burned ~no CPU while D3/D4 fired
D6  key         a key-shaped blob decrypts a readable private region (proof)
"""

from __future__ import annotations

from dataclasses import dataclass, field

import entropy as entropy_mod
import signatures
from models import (
    MEM_COMMIT,
    MEM_PRIVATE,
    PAGE_NOACCESS,
    Finding,
    Region,
    RegionChange,
    hexaddr,
    protection_name,
)

try:  # optional: only D6 needs a crypto library
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    HAVE_AESGCM = True
except Exception:  # pragma: no cover - depends on the host
    AESGCM = None  # type: ignore[assignment]
    HAVE_AESGCM = False

NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
HEADER_LEN = NONCE_LEN + TAG_LEN + KEY_LEN

RULE_FAMILY = {
    "D1-marker": "D1",
    "D2-entropy": "D2",
    "D3-protection-flip": "D3",
    "D4-orphan-noaccess": "D4",
    "D5-idle-thread": "D5",
    "D6-key-recovery": "D6",
}


@dataclass
class Observation:
    pid: int
    at: float
    baseline: list[Region]
    current: list[Region]
    changes: list[RegionChange]
    reads: dict[int, bytes]
    entropies: dict[int, float]
    baseline_entropies: dict[int, float]
    cpu_delta_ms: float | None
    marker: bytes
    window_seconds: float = 0.0
    dormant: dict[int, bool] = field(default_factory=dict)
    extra: dict[str, str] = field(default_factory=dict)


def _by_base(regions: list[Region]) -> dict[int, Region]:
    return {region.base: region for region in regions}


def _finding(
    obs: Observation,
    region: Region,
    rule: str,
    confidence: float,
    *,
    marker_present: bool = False,
    must_be_encrypted: bool = False,
    evidence: dict | None = None,
) -> Finding:
    baseline = _by_base(obs.baseline).get(region.base)
    before = baseline.protection if baseline else None

    if must_be_encrypted and before == region.protection:
        before = None

    return Finding(
        pid=obs.pid,
        address=hexaddr(region.base),
        size=region.size,
        rule=rule,
        confidence=confidence,
        phase="dormant" if obs.dormant.get(region.base) else "awake",
        marker_present=marker_present,
        protection_before=before,
        protection_after=region.protection,
        entropy=obs.entropies.get(region.base),
        evidence=evidence or {},
        observed_at=obs.at,
    )


# --- D1 --------------------------------------------------------------------


def rule_marker(obs: Observation) -> list[Finding]:
    current = _by_base(obs.current)
    findings: list[Finding] = []

    for base, data in obs.reads.items():
        region = current.get(base)
        if region is None or not data:
            continue
        hits = signatures.marker_hits(data, obs.marker)
        if not hits:
            continue
        findings.append(
            _finding(
                obs,
                region,
                "D1-marker",
                0.99,
                marker_present=True,
                evidence={
                    "offsets": [hexaddr(base + offset) for offset in hits[:3]],
                    "hit_count": len(hits),
                    "scanned_bytes": len(data),
                },
            )
        )
    return findings


# --- D2 --------------------------------------------------------------------


def rule_entropy(obs: Observation) -> list[Finding]:
    current = _by_base(obs.current)
    findings: list[Finding] = []

    for base, value in obs.entropies.items():
        region = current.get(base)
        if region is None or not region.private:
            continue

        previous = obs.baseline_entropies.get(base)
        delta = entropy_mod.entropy_delta(previous, value)
        if delta is None:
            continue

        confidence = 0.0
        if delta >= 2.0:
            confidence = 0.80
        elif delta >= 1.0:
            confidence = 0.50
        elif previous is not None and previous < 6.0 and value >= 7.8:
            confidence = 0.70

        if confidence <= 0:
            continue

        findings.append(
            _finding(
                obs,
                region,
                "D2-entropy",
                confidence,
                evidence={
                    "entropy_baseline": round(previous, 4) if previous is not None else None,
                    "entropy_current": round(value, 4),
                    "entropy_delta": round(delta, 4),
                    "sample_bytes": len(obs.reads.get(base, b"")),
                },
            )
        )
    return findings


# --- D3 --------------------------------------------------------------------


def rule_protection_flip(obs: Observation) -> list[Finding]:
    current = _by_base(obs.current)
    findings: list[Finding] = []

    for change in obs.changes:
        region = current.get(change.base)
        if region is None or not region.private or region.size < 4096:
            continue
        if change.before == change.after:
            continue

        after = protection_name(change.after)
        confidence = 0.85 if "NOACCESS" in after else 0.70
        finding = _finding(
            obs,
            region,
            "D3-protection-flip",
            confidence,
            evidence={
                "from": protection_name(change.before),
                "to": after,
                "region_size": change.size,
            },
        )
        finding.protection_before = protection_name(change.before)
        finding.protection_after = after
        findings.append(finding)
    return findings


# --- D4 --------------------------------------------------------------------


def rule_orphan_noaccess(obs: Observation) -> list[Finding]:
    baseline = _by_base(obs.baseline)
    findings: list[Finding] = []

    for region in obs.current:
        if not (region.private and region.committed):
            continue
        if region.size < 4096:
            continue
        if (region.protect & 0xFF) != PAGE_NOACCESS:
            continue

        prior = baseline.get(region.base)
        if prior is not None and (prior.protect & 0xFF) == PAGE_NOACCESS:
            continue  # it was already unreadable when we started; not a transition

        findings.append(
            _finding(
                obs,
                region,
                "D4-orphan-noaccess",
                0.60,
                evidence={
                    "reason": "private committed region became NOACCESS",
                    "present_in_baseline": prior is not None,
                    "baseline_protection": prior.protection if prior else None,
                },
            )
        )
    return findings


# --- D5 --------------------------------------------------------------------


def rule_idle_thread(obs: Observation, related: list[Finding]) -> list[Finding]:
    if obs.cpu_delta_ms is None or obs.cpu_delta_ms > 25.0:
        return []

    bases = {
        finding.address
        for finding in related
        if RULE_FAMILY.get(finding.rule) in ("D3", "D4")
    }
    if not bases:
        return []

    current = _by_base(obs.current)
    findings: list[Finding] = []
    for address in sorted(bases):
        region = current.get(int(address, 16))
        if region is None:
            continue
        findings.append(
            _finding(
                obs,
                region,
                "D5-idle-thread",
                0.35,
                evidence={
                    "cpu_delta_ms": round(obs.cpu_delta_ms, 3),
                    "window_seconds": round(obs.window_seconds, 3),
                    "reason": "process was idle while the region changed state",
                },
            )
        )
    return findings


# --- D6 --------------------------------------------------------------------


def _header_candidates(reads: dict[int, bytes], current: dict[int, Region]) -> list[tuple[int, int]]:
    """(header_base, ciphertext_region_base) candidates from small private regions."""
    headers: list[tuple[int, bytes]] = []
    for base, data in reads.items():
        region = current.get(base)
        if region is None or region.size > 8192 or len(data) < HEADER_LEN:
            continue
        nonce = data[:NONCE_LEN]
        tag = data[NONCE_LEN : NONCE_LEN + TAG_LEN]
        key = data[NONCE_LEN + TAG_LEN : HEADER_LEN]
        if nonce == b"\x00" * NONCE_LEN or tag == b"\x00" * TAG_LEN:
            continue
        if not signatures.looks_like_key(key):
            continue
        headers.append((base, bytes(key)))

    candidates: list[tuple[int, int]] = []
    for header_base, key in headers:
        for base, data in reads.items():
            region = current.get(base)
            if region is None or base == header_base:
                continue
            if not region.private or not region.readable:
                continue
            if len(data) != region.size or len(data) < 4096:
                continue
            if data[:NONCE_LEN] == b"\x00" * NONCE_LEN:
                continue
            candidates.append((header_base, base))
    return candidates


def rule_key_recovery(obs: Observation) -> list[Finding]:
    if not HAVE_AESGCM:
        return []

    current = _by_base(obs.current)
    findings: list[Finding] = []

    for header_base, ct_base in _header_candidates(obs.reads, current):
        header = obs.reads.get(header_base, b"")
        ciphertext = obs.reads.get(ct_base, b"")
        region = current.get(ct_base)
        if region is None or len(header) < HEADER_LEN:
            continue

        nonce = header[:NONCE_LEN]
        tag = header[NONCE_LEN : NONCE_LEN + TAG_LEN]
        key = header[NONCE_LEN + TAG_LEN : HEADER_LEN]

        try:
            # AESGCM expects ciphertext||tag as one buffer; the tag is not AAD.
            plaintext = AESGCM(bytes(key)).decrypt(
                bytes(nonce), ciphertext + bytes(tag), None
            )
        except Exception:
            continue

        marker_present = obs.marker in plaintext
        if not marker_present:
            continue

        findings.append(
            _finding(
                obs,
                region,
                "D6-key-recovery",
                0.99,
                marker_present=True,
                evidence={
                    "header_address": hexaddr(header_base),
                    "ciphertext_size": len(ciphertext),
                    "decrypted_marker": True,
                    "note": "payload recovered with the key found in the process",
                },
            )
        )

    return findings


# --- orchestration ---------------------------------------------------------


def evaluate(obs: Observation) -> list[Finding]:
    findings = []
    findings.extend(rule_marker(obs))
    findings.extend(rule_entropy(obs))
    findings.extend(rule_protection_flip(obs))
    findings.extend(rule_orphan_noaccess(obs))
    findings.extend(rule_idle_thread(obs, findings))
    findings.extend(rule_key_recovery(obs))
    return merge(findings)


def merge(findings: list[Finding]) -> list[Finding]:
    """One finding per (rule, address); keep the most confident observation."""
    best: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = finding.key()
        existing = best.get(key)
        if existing is None or finding.confidence > existing.confidence:
            best[key] = finding
    return sorted(best.values(), key=lambda item: (int(item.address, 16), item.rule))


def aggregate_confidence(findings: list[Finding], address: str) -> float:
    values = [finding.confidence for finding in findings if finding.address == address]
    remaining = 1.0
    for value in values:
        remaining *= 1.0 - max(0.0, min(1.0, value))
    return round(min(0.99, 1.0 - remaining), 3)


def rule_status() -> dict[str, str]:
    return {
        "D1": "enabled",
        "D2": "enabled",
        "D3": "enabled",
        "D4": "enabled",
        "D5": "enabled",
        "D6": "enabled" if HAVE_AESGCM else "unavailable (install cryptography)",
    }
