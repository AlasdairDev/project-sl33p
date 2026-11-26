"""Shared data model for the hunter, the report and the matrix runner.

Nothing here touches Win32; this module must import on Linux so the rule
engine can be unit-tested without a Windows box.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# --- Win32 constants we care about -----------------------------------------

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

_PROTECT_NAMES = {
    0x01: "NOACCESS",
    0x02: "R",
    0x04: "RW",
    0x08: "WC",
    0x10: "X",
    0x20: "RX",
    0x40: "RWX",
    0x80: "RWXC",
}

_PROTECT_MODIFIERS = {
    0x100: "GUARD",
    0x200: "NOCACHE",
    0x400: "WRITECOMBINE",
}

_STATE_NAMES = {MEM_COMMIT: "COMMIT", MEM_RESERVE: "RESERVE", MEM_FREE: "FREE"}
_TYPE_NAMES = {MEM_PRIVATE: "PRIVATE", MEM_MAPPED: "MAPPED", MEM_IMAGE: "IMAGE"}


def protection_name(protect: int) -> str:
    """Render a protection value the way a human reads it in Process Explorer."""
    base = protect & 0xFF
    name = _PROTECT_NAMES.get(base, f"0x{base:02x}")
    mods = [label for bit, label in _PROTECT_MODIFIERS.items() if protect & bit]
    return name + ("+" + "+".join(mods) if mods else "")


_PROTECT_FROM_NAME = {name: value for value, name in _PROTECT_NAMES.items()}


def protect_from_name(name: str) -> int:
    """Inverse of protection_name, for replay captures and case files."""
    return _PROTECT_FROM_NAME.get(name.split("+")[0].upper(), 0x04)


def state_name(state: int) -> str:
    return _STATE_NAMES.get(state, f"0x{state:x}")


def type_name(mem_type: int) -> str:
    return _TYPE_NAMES.get(mem_type, f"0x{mem_type:x}")


def hexaddr(value: int) -> str:
    return f"0x{value:X}"


# --- region model -----------------------------------------------------------


@dataclass(frozen=True)
class Region:
    base: int
    size: int
    protect: int
    state: int = MEM_COMMIT
    type: int = MEM_PRIVATE

    @property
    def end(self) -> int:
        return self.base + self.size

    @property
    def committed(self) -> bool:
        return self.state == MEM_COMMIT

    @property
    def private(self) -> bool:
        return self.type == MEM_PRIVATE

    @property
    def readable(self) -> bool:
        """PAGE_NOACCESS and PAGE_GUARD both make ReadProcessMemory fail."""
        return (self.protect & 0xFF) != PAGE_NOACCESS and not (self.protect & PAGE_GUARD)

    @property
    def protection(self) -> str:
        return protection_name(self.protect)


@dataclass(frozen=True)
class RegionChange:
    base: int
    size: int
    before: int
    after: int

    @property
    def protection_before(self) -> str:
        return protection_name(self.before)

    @property
    def protection_after(self) -> str:
        return protection_name(self.after)


# --- findings ---------------------------------------------------------------


@dataclass
class Finding:
    pid: int
    address: str
    size: int
    rule: str
    confidence: float
    phase: str = "awake"
    marker_present: bool = False
    protection_before: str | None = None
    protection_after: str | None = None
    entropy: float | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    observed_at: float = 0.0

    def key(self) -> tuple[str, str]:
        return (self.rule, self.address)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "address": self.address,
            "size": self.size,
            "rule": self.rule,
            "confidence": round(self.confidence, 3),
            "phase": self.phase,
            "marker_present": self.marker_present,
            "protection_before": self.protection_before,
            "protection_after": self.protection_after,
            "entropy": None if self.entropy is None else round(self.entropy, 4),
            "evidence": self.evidence,
            "observed_at": round(self.observed_at, 3),
        }


def noisy_or(confidences: list[float]) -> float:
    """Combine rule confidences. Capped below 1.0."""
    remaining = 1.0
    for value in confidences:
        remaining *= 1.0 - max(0.0, min(1.0, value))
    return round(min(0.99, 1.0 - remaining), 3)


@dataclass(frozen=True)
class CaseSpec:
    name: str
    technique: str
    expected_detectors: tuple[str, ...]
    sleep_seconds: int = 12


@dataclass
class CaseResult:
    name: str
    technique: str
    expected: list[str]
    detected: list[str]
    caught: bool
    time_to_detect_s: float | None
    max_confidence: float
    finding_count: int
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "technique": self.technique,
            "expected": self.expected,
            "detected": self.detected,
            "caught": self.caught,
            "time_to_detect_s": self.time_to_detect_s,
            "max_confidence": self.max_confidence,
            "finding_count": self.finding_count,
            "note": self.note,
        }
