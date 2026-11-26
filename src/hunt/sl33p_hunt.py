#!/usr/bin/env python3
"""sl33p-hunt: find a dormant, self-encrypted region in one process.

Read-only. One PID. No writes, no threads, no injection.

    python src/hunt/sl33p_hunt.py --pid 1234 --duration 20
    python src/hunt/sl33p_hunt.py --replay lab/captures/demo.json --html out.html
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import entropy as entropy_mod  # noqa: E402
import regions as region_mod  # noqa: E402
import replay as replay_mod  # noqa: E402
import report  # noqa: E402
import linuxmem  # noqa: E402
import rules  # noqa: E402
import winmem  # noqa: E402
from models import Region, hexaddr  # noqa: E402

DEFAULT_MARKER = "SL33P_LAB_MARKER_9f2c1d7e"

if sys.platform == "win32":
    BACKEND = winmem
elif sys.platform.startswith("linux"):
    BACKEND = linuxmem
else:
    BACKEND = None

SAMPLING_BUDGET = 32 * 1024 * 1024
MAX_REGIONS_PER_TICK = 512


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sample(
    proc: "winmem.TargetProcess", current: list[Region], bases: set[int] | None = None
) -> tuple[dict[int, bytes], dict[int, float]]:
    """Read the regions we care about, up to a per-tick budget."""
    selected = [region for region in current if region_mod.worth_reading(region)]
    if bases is not None:
        selected = [region for region in selected if region.base in bases]

    selected.sort(key=lambda region: region.size, reverse=True)
    selected = selected[:MAX_REGIONS_PER_TICK]

    reads: dict[int, bytes] = {}
    entropies: dict[int, float] = {}
    spent = 0

    for region in selected:
        length = region_mod.read_length(region)
        if spent + length > SAMPLING_BUDGET:
            continue
        try:
            data = proc.read(region.base, length)
        except BACKEND.Unreadable:
            continue
        except BACKEND.Win32Error:
            continue

        if not data:
            continue

        reads[region.base] = data
        entropies[region.base] = entropy_mod.mean_block_entropy(data)
        spent += len(data)

    return reads, entropies


def run_live(
    args: argparse.Namespace, marker: bytes
) -> tuple[list, list[Region], dict[int, float], dict, int, str | None]:
    if BACKEND is None:
        raise winmem.Unsupported("no memory backend for this platform")

    tries = 0
    while True:
        try:
            with BACKEND.TargetProcess(args.pid) as proc:
                image = proc.image_name()
                baseline = proc.regions()
                _, baseline_entropies = sample(proc, baseline)
                findings = []
                dormant: dict[int, bool] = {}
                previous = baseline
                last_entropies: dict[int, float] = dict(baseline_entropies)
                cpu_previous = proc.cpu_time_ms()
                started = time.monotonic()
                last_tick_at = 0.0
                ticks = 0

                while True:
                    elapsed = time.monotonic() - started
                    if elapsed >= args.duration:
                        break
                    time.sleep(max(0.02, min(args.interval, args.duration - elapsed)))

                    now = time.monotonic() - started
                    try:
                        current = proc.regions()
                    except BACKEND.Win32Error:
                        break

                    changes = region_mod.diff(previous, current)
                    bases = region_mod.interesting_bases(baseline, current, changes)
                    reads, entropies = sample(proc, current, bases)
                    cpu_now = proc.cpu_time_ms()

                    current_by_base = {region.base: region for region in current}
                    for base, value in entropies.items():
                        previous = baseline_entropies.get(base)
                        if previous is not None:
                            dormant[base] = (value - previous) >= 2.0
                    for change in changes:
                        region = current_by_base.get(change.base)
                        if region is not None:
                            dormant[change.base] = region.protection != "RW"

                    observation = rules.Observation(
                        pid=args.pid,
                        at=now,
                        baseline=baseline,
                        current=current,
                        changes=changes,
                        reads=reads,
                        entropies=entropies,
                        baseline_entropies=baseline_entropies,
                        cpu_delta_ms=cpu_now - cpu_previous,
                        marker=marker,
                        window_seconds=now - last_tick_at,
                        dormant=dict(dormant),
                    )

                    findings.extend(rules.evaluate(observation))
                    last_entropies.update(entropies)
                    previous = current
                    cpu_previous = cpu_now
                    last_tick_at = now
                    ticks += 1

                duration = time.monotonic() - started
                return (
                    rules.merge(findings),
                    previous,
                    last_entropies,
                    {"duration": duration, "ticks": ticks, "image": image},
                    0,
                    None,
                )
        except BACKEND.Win32Error as exc:
            # Process may have exited between launch and open.
            if tries >= 3:
                return [], [], {}, {"duration": 0.0, "ticks": 0, "image": None}, 5, str(exc)
            tries += 1
            time.sleep(0.25)


def run_replay(
    args: argparse.Namespace, marker: bytes
) -> tuple[list, list[Region], dict[int, float], dict, int, str | None]:
    capture = replay_mod.load_capture(args.replay)
    observations = replay_mod.observations(capture)
    findings = []
    for observation in observations:
        findings.extend(rules.evaluate(observation))
    last_regions = observations[-1].current if observations else []
    last_entropies = observations[-1].entropies if observations else {}
    return (
        rules.merge(findings),
        last_regions,
        last_entropies,
        {
            "duration": observations[-1].at if observations else 0.0,
            "ticks": len(observations),
            "image": None,
            "pid": capture.pid,
        },
        0,
        None,
    )


def region_table(regions: list[Region], entropies: dict[int, float]) -> list[dict]:
    rows = []
    for region in regions:
        if not (region.private and region.committed):
            continue
        rows.append(
            {
                "address": hexaddr(region.base),
                "size": region.size,
                "protection": region.protection,
                "type": "PRIVATE",
                "entropy": round(entropies[region.base], 4) if region.base in entropies else None,
            }
        )
    rows.sort(key=lambda row: int(row["address"], 16))
    return rows


def read_status_hint(path: str | None) -> dict | None:
    """Optional. Used for annotation only; never as evidence."""
    if not path:
        return None
    try:
        lines = [line for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return None
        return json.loads(lines[-1])
    except (OSError, ValueError):
        return None


def human_summary(payload: dict, out=sys.stderr) -> None:
    summary = payload["summary"]
    print(
        f"sl33p-hunt  pid={payload['pid']}  mode={payload['mode']}  ticks={payload['ticks']}  "
        f"blind={payload['blind']}",
        file=out,
    )
    print(f"marker     {payload['marker']}", file=out)
    if not payload["findings"]:
        print("findings   none", file=out)
    else:
        print(f"findings   {len(payload['findings'])}", file=out)
        for finding in payload["findings"]:
            print(
                f"  {finding['rule']:<20} {finding['address']:<12} "
                f"{finding['size']:>8}  conf={finding['confidence']:<5} "
                f"{finding['protection_before'] or '-'} -> {finding['protection_after'] or '-'}",
                file=out,
            )
    print(f"verdict    {summary['verdict']} (max confidence {summary['max_confidence']})", file=out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sl33p_hunt.py",
        description="Read-only detector for a dormant self-encrypted region.",
    )
    parser.add_argument("--pid", type=int, help="target process id (live mode)")
    parser.add_argument("--replay", help="replay a captured tick sequence (offline)")
    parser.add_argument("--marker", default=DEFAULT_MARKER, help="marker to scan for")
    parser.add_argument(
        "--no-marker",
        action="store_true",
        help="disable the signature entirely: proves content detection without knowing the payload",
    )
    parser.add_argument("--duration", type=float, default=15.0, help="seconds to observe")
    parser.add_argument("--interval", type=float, default=0.25, help="poll interval in seconds")
    parser.add_argument("--status", help="optional JSON status file (annotation only)")
    parser.add_argument("--out", help="write JSON evidence here")
    parser.add_argument("--html", help="write a self-contained HTML report here")
    parser.add_argument("--quiet", action="store_true", help="suppress the human summary")
    parser.add_argument("--version", action="version", version="sl33p-hunt 1.0.0")
    args = parser.parse_args(argv)

    if bool(args.pid) == bool(args.replay):
        parser.error("exactly one of --pid or --replay is required")

    if args.no_marker:
        args.marker = ""
    marker = args.marker.encode("utf-8")

    try:
        if args.replay:
            findings, last_regions, last_entropies, meta, code, error = run_replay(args, marker)
        else:
            findings, last_regions, last_entropies, meta, code, error = run_live(args, marker)
    except winmem.Unsupported as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4

    if error:
        print(f"error: {error}", file=sys.stderr)
        return code

    payload = report.build_hunt_payload(
        pid=int(meta.get("pid") or args.pid or 0),
        image=meta.get("image"),
        marker=args.marker,
        mode="replay" if args.replay else "live",
        blind=not bool(args.status),
        duration_s=meta.get("duration", 0.0),
        ticks=meta.get("ticks", 0),
        findings=[finding.to_dict() for finding in findings],
        regions=region_table(last_regions, last_entropies),
        rule_status=rules.rule_status(),
        hints=read_status_hint(args.status),
        generated_at=_utc_now(),
    )

    if args.out:
        report.write_json(args.out, payload)
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))

    if args.html:
        report.write_html(args.html, payload)

    if not args.quiet:
        human_summary(payload)

    return 0 if findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
