"""Replay a captured memory snapshot sequence.

Two uses:

  1. exercise the rule engine on Linux, where no Windows process is available;
  2. re-derive a finding from stored evidence, so a report can be checked later.

A capture is JSON: {pid, marker, ticks: [{t, cpu_ms, regions: [...]}]} where a
region carries base/size/protect/type/state and optional data_b64.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

import entropy as entropy_mod
import regions as region_mod
from models import (
    MEM_COMMIT,
    MEM_IMAGE,
    MEM_MAPPED,
    MEM_PRIVATE,
    MEM_RESERVE,
    Region,
    protect_from_name,
)
from rules import Observation

_TYPE_FROM_NAME = {"PRIVATE": MEM_PRIVATE, "MAPPED": MEM_MAPPED, "IMAGE": MEM_IMAGE}
_STATE_FROM_NAME = {"COMMIT": MEM_COMMIT, "RESERVE": MEM_RESERVE, "FREE": 0x10000}


@dataclass(frozen=True)
class Capture:
    pid: int
    marker: bytes
    ticks: list[dict]


def _number(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f"not an address/size: {value!r}")


def load_capture(path: str | Path) -> Capture:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    pid = int(raw.get("pid", 0))
    marker = str(raw["marker"]).encode("utf-8")
    ticks = list(raw.get("ticks") or [])
    if not ticks:
        raise ValueError("capture has no ticks")
    return Capture(pid=pid, marker=marker, ticks=ticks)


def _decode_regions(tick: dict) -> tuple[list[Region], dict[int, bytes]]:
    regions: list[Region] = []
    data: dict[int, bytes] = {}

    for entry in tick.get("regions") or []:
        base = _number(entry["base"])
        region = Region(
            base=base,
            size=_number(entry["size"]),
            protect=protect_from_name(str(entry.get("protect", "RW"))),
            state=_STATE_FROM_NAME.get(str(entry.get("state", "COMMIT")).upper(), MEM_COMMIT),
            type=_TYPE_FROM_NAME.get(str(entry.get("type", "PRIVATE")).upper(), MEM_PRIVATE),
        )
        regions.append(region)

        if entry.get("data_b64"):
            data[base] = base64.b64decode(entry["data_b64"])

    return regions, data


def observations(capture: Capture) -> list[Observation]:
    baseline_regions, baseline_data = _decode_regions(capture.ticks[0])
    baseline_entropies = {
        base: entropy_mod.mean_block_entropy(blob)
        for base, blob in baseline_data.items()
        if blob
    }

    result: list[Observation] = []
    dormant: dict[int, bool] = {}
    previous_regions = baseline_regions
    previous_cpu = float(capture.ticks[0].get("cpu_ms", 0.0))
    previous_t = float(capture.ticks[0].get("t", 0.0))

    for tick in capture.ticks[1:]:
        current, data = _decode_regions(tick)
        at = float(tick.get("t", previous_t))
        cpu = float(tick.get("cpu_ms", previous_cpu))
        changes = region_mod.diff(previous_regions, current)
        entropies = {
            base: entropy_mod.mean_block_entropy(blob) for base, blob in data.items() if blob
        }
        for base, value in entropies.items():
            previous = baseline_entropies.get(base)
            if previous is not None:
                dormant[base] = (value - previous) >= 2.0
        current_by_base = {region.base: region for region in current}
        for change in changes:
            region = current_by_base.get(change.base)
            if region is not None:
                dormant[change.base] = region.protection != "RW"

        result.append(
            Observation(
                pid=capture.pid,
                at=at,
                baseline=baseline_regions,
                current=current,
                changes=changes,
                reads=data,
                entropies=entropies,
                baseline_entropies=baseline_entropies,
                cpu_delta_ms=cpu - previous_cpu,
                marker=capture.marker,
                window_seconds=at - previous_t,
                dormant=dict(dormant),
                extra={"source": "replay"},
            )
        )
        previous_regions = current
        previous_cpu = cpu
        previous_t = at

    return result
