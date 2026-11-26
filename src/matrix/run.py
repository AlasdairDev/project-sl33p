#!/usr/bin/env python3
"""sl33p-matrix: run scenarios, hunt them blind, score the result.

    python src/matrix/run.py --dry-run
    python src/matrix/run.py --core src/core/bin/Release/net10.0/sl33p-core.exe
    python src/matrix/run.py --render report/out/matrix.json

Live runs require Windows (the core is a Windows binary). Rendering an existing
results file works anywhere, which is what keeps the report reproducible.
"""

from __future__ import annotations

import argparse
import json
import platform
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ON_LINUX = sys.platform.startswith("linux")
HUNTER_INTERVAL = 0.1
DEFAULT_CORE = (
    ROOT / "src" / "core-linux" / "core_linux.py"
    if ON_LINUX
    else ROOT / "src" / "core" / "bin" / "Release" / "net10.0" / "sl33p-core.exe"
)
HUNT_DIR = ROOT / "src" / "hunt"
sys.path.insert(0, str(HUNT_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import report  # noqa: E402
import score as scoring  # noqa: E402
from models import CaseResult  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_cases(path: Path) -> list[dict]:
    if yaml is None:
        raise SystemExit("error: PyYAML is required for cases.yml (pip install pyyaml)")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    cases = data.get("cases") if isinstance(data, dict) else data
    if not cases:
        raise SystemExit(f"error: no cases in {path}")
    return list(cases)


class CoreEvents:
    """Read the core's status stream in the background, with arrival times."""

    def __init__(self, proc: subprocess.Popen):
        self._events: list[tuple[float, dict]] = []
        self._cond = threading.Condition()
        threading.Thread(target=self._pump, args=(proc.stdout,), daemon=True).start()

    def _pump(self, stream) -> None:
        try:
            if stream is None:
                return
            for line in stream:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    payload = json.loads(line)
                except ValueError:
                    continue
                with self._cond:
                    self._events.append((time.monotonic(), payload))
                    self._cond.notify_all()
        finally:
            with self._cond:
                self._cond.notify_all()

    def wait(self, name: str, timeout: float) -> tuple[float, dict]:
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for stamp, payload in self._events:
                    if payload.get("event") == name:
                        return stamp, payload
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"core did not report '{name}' within {timeout:.0f}s")
                if not self._cond.wait(remaining):
                    raise TimeoutError(f"core did not report '{name}' within {timeout:.0f}s")


def core_command(args: argparse.Namespace) -> list[str]:
    core = Path(args.core).expanduser()
    if not core.exists():
        hint = (
            "run it directly with python3" if ON_LINUX
            else "build it inside the VM:  dotnet build src/core -c Release"
        )
        raise SystemExit(f"error: core not found at {core}\n       {hint}")
    if core.suffix.lower() == ".py":
        return [sys.executable, str(core)]
    if core.suffix.lower() == ".dll":
        return [args.dotnet, str(core)]
    return [str(core)]


def run_hunter(pid: int, duration: float, out_path: Path) -> list[dict]:
    command = [
        sys.executable,
        str(HUNT_DIR / "sl33p_hunt.py"),
        "--pid",
        str(pid),
        "--duration",
        f"{duration:.1f}",
        "--interval",
        str(HUNTER_INTERVAL),
        "--quiet",
        "--out",
        str(out_path),
    ]
    # No --status: the detector gets a PID and nothing else.
    subprocess.run(command, check=False, timeout=duration + 30)
    if not out_path.exists():
        raise RuntimeError(f"hunter produced no output for pid {pid}")
    return json.loads(out_path.read_text(encoding="utf-8")).get("findings", [])


def run_core_case(args: argparse.Namespace, case: dict, outdir: Path) -> tuple[list[dict], int | None, int | None]:
    sleep_seconds = int(case.get("sleep_seconds", 12))
    awake_seconds = int(case.get("awake_seconds", 3))
    command = core_command(args) + [
        "--lab-ack",
        "--mode",
        str(case.get("mode", "encrypt")),
        "--protect",
        str(case.get("protect", "rw")),
        "--awake",
        str(awake_seconds),
        "--sleep",
        str(sleep_seconds),
        "--cycles",
        "1",
    ]

    proc = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    events = CoreEvents(proc)
    try:
        # Ready, not asleep: the hunter needs a baseline taken while the region
        # is still plaintext, which is exactly how an always-on monitor works.
        ready_at, status = events.wait("ready", timeout=15)
        region = status.get("region") or {}
        truth_base = int(str(region.get("address", "0x0")), 16)
        truth_size = int(region.get("size", 0))

        hunt_started = time.monotonic()
        findings = run_hunter(
            int(status["pid"]),
            max(3.0, awake_seconds + sleep_seconds - 2.0),
            outdir / "findings" / f"{case['name']}.json",
        )

        # Measure detection from the scheduled start of the sleep window, not
        # from the hunter's start (the awake lead-in is not latency) and not
        # from the status line (the hunter can observe the change before the
        # core finishes printing). The poll interval is the resolution.
        if str(case.get("mode", "encrypt")) == "encrypt":
            flip_estimate = ready_at + awake_seconds
            for finding in findings:
                detected = hunt_started + float(finding.get("observed_at", 0.0))
                finding["detected_after_event_s"] = round(
                    max(0.0, detected - flip_estimate), 3
                )

        return findings, truth_base, truth_size
    finally:
        try:
            proc.wait(timeout=awake_seconds + sleep_seconds + 20)
        except subprocess.TimeoutExpired:
            proc.kill()
        if proc.returncode not in (0, None):
            stderr = (proc.stderr.read() if proc.stderr else "") or ""
            print(f"  core exit {proc.returncode}: {stderr.strip()[:200]}", file=sys.stderr)


def run_control_case(args: argparse.Namespace, case: dict, outdir: Path) -> tuple[list[dict], None, None]:
    process_name = str(case.get("process", "notepad.exe"))
    if ON_LINUX:
        command = case.get("process_linux") or ["sleep", "300"]
        if isinstance(command, str):
            command = [command]
    else:
        command = [process_name]
    proc = subprocess.Popen(command)
    try:
        time.sleep(2.0)
        findings = run_hunter(
            proc.pid,
            max(2.0, float(case.get("sleep_seconds", 10)) - 2.0),
            outdir / "findings" / f"{case['name']}.json",
        )
        return findings, None, None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def environment() -> dict:
    result = {
        "host": platform.platform(),
        "python": platform.python_version(),
        "architecture": platform.machine(),
        "poll_interval_s": HUNTER_INTERVAL,
    }
    try:
        result["dotnet"] = subprocess.run(
            ["dotnet", "--version"], capture_output=True, text=True, timeout=10, check=False
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        result["dotnet"] = None
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run.py", description="sl33p detection matrix")
    parser.add_argument("--cases", default=str(ROOT / "src" / "matrix" / "cases.yml"))
    parser.add_argument("--core", default=str(DEFAULT_CORE))
    parser.add_argument("--dotnet", default="dotnet", help="dotnet executable for .dll builds")
    parser.add_argument("--outdir", default=str(ROOT / "report" / "out"))
    parser.add_argument("--only", help="run one case by name")
    parser.add_argument("--threshold", type=float, default=0.6)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--render", help="re-render an existing matrix.json")
    parser.add_argument("--html", help="HTML output path (default <outdir>/matrix.html)")
    args = parser.parse_args(argv)

    if args.render:
        payload = json.loads(Path(args.render).read_text(encoding="utf-8"))
        html_path = Path(args.html) if args.html else Path(args.render).with_suffix(".html")
        report.write_html(html_path, payload)
        print(f"rendered {html_path}")
        return 0

    cases = load_cases(Path(args.cases))
    if args.only:
        cases = [case for case in cases if case.get("name") == args.only]
        if not cases:
            raise SystemExit(f"error: no case named {args.only}")

    if args.dry_run:
        print(f"{len(cases)} cases from {args.cases}")
        for case in cases:
            kind = case.get("kind", "core")
            print(f"  {case['name']:<22} {kind:<8} {case.get('technique', '')}")
        return 0

    outdir = Path(args.outdir)
    (outdir / "findings").mkdir(parents=True, exist_ok=True)
    results = []

    for case in cases:
        print(f"[case] {case['name']}", file=sys.stderr)
        kind = case.get("kind", "core")
        try:
            if kind == "control":
                findings, truth_base, truth_size = run_control_case(args, case, outdir)
            else:
                findings, truth_base, truth_size = run_core_case(args, case, outdir)

            result = scoring.score_case(
                case, findings, truth_base=truth_base, truth_size=truth_size, threshold=args.threshold
            )
        except Exception as exc:  # one broken case must not lose the whole matrix
            result = CaseResult(
                name=str(case.get("name")),
                technique=str(case.get("technique", "")),
                expected=[str(item) for item in case.get("expected") or []],
                detected=[],
                caught=False,
                time_to_detect_s=None,
                max_confidence=0.0,
                finding_count=0,
                note=f"runner error: {exc}",
            )
        results.append(result.to_dict())
        status = "caught" if result.caught else "missed"
        print(
            f"  {status}: detected={','.join(result.detected) or '-'} "
            f"ttd={result.time_to_detect_s}",
            file=sys.stderr,
        )

    payload = report.build_matrix_payload(
        cases=results, generated_at=utc_now(), environment=environment()
    )
    json_path = outdir / "matrix.json"
    html_path = Path(args.html) if args.html else outdir / "matrix.html"
    report.write_json(json_path, payload)
    report.write_html(html_path, payload)

    caught = payload["summary"]["caught"]
    total = payload["summary"]["total"]
    print(f"{caught}/{total} cases caught")
    print(f"json {json_path}")
    print(f"html {html_path}")
    return 0 if caught == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
