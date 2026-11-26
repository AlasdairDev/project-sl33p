#!/usr/bin/env python3
"""One-command verification for sl33p.

    python3 tools/verify.py            # env + tests + build + one live scenario
    python3 tools/verify.py --matrix   # also run the full 7-case matrix (~2 min)

Exit code 0 only if every step that ran passed. Use this before publishing, or
as the first thing you run on a fresh checkout.
"""

from __future__ import annotations

import argparse
import json
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
CORE = ROOT / "src" / "core-linux" / "core_linux.py"
HUNT = ROOT / "src" / "hunt" / "sl33p_hunt.py"
MATRIX = ROOT / "src" / "matrix" / "run.py"

ON_LINUX = sys.platform.startswith("linux")


class Step:
    def __init__(self, name: str):
        self.name = name
        self.status = "skip"
        self.detail = ""

    def ok(self, detail: str) -> "Step":
        self.status, self.detail = "ok", detail
        return self

    def fail(self, detail: str) -> "Step":
        self.status, self.detail = "FAIL", detail
        return self

    def skip(self, detail: str) -> "Step":
        self.status, self.detail = "skip", detail
        return self


def _run(command: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False
    )


def environment() -> dict:
    info = {"python": sys.version.split()[0], "platform": sys.platform}
    try:
        import cryptography

        info["cryptography"] = cryptography.__version__
    except ImportError:
        info["cryptography"] = None
    try:
        info["dotnet"] = _run(["dotnet", "--version"], timeout=20).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        info["dotnet"] = None
    return info


def step_tests() -> Step:
    step = Step("unit tests")
    started = time.monotonic()
    result = _run([PY, "-m", "unittest", "discover", "-s", "tests"])
    elapsed = time.monotonic() - started
    tail = (result.stderr or result.stdout).strip().splitlines()
    if result.returncode != 0:
        return step.fail(tail[-1] if tail else "unittest failed")
    count = next((line for line in tail if line.startswith("Ran ")), "ran")
    return step.ok(f"{count.replace('Ran ', '').replace(' in ', ', ')} ({elapsed:.1f}s)")


def step_build() -> Step:
    step = Step("core build")
    try:
        result = _run(["dotnet", "build", "src/core/sl33p.csproj", "-c", "Release", "--nologo", "-v", "q"])
    except (OSError, subprocess.SubprocessError) as exc:
        return step.skip(f"dotnet unavailable ({exc})")
    if result.returncode != 0:
        lines = (result.stdout or result.stderr).strip().splitlines()
        return step.fail(lines[-1] if lines else "build failed")
    warnings = next((line.strip() for line in result.stdout.splitlines() if "Warning(s)" in line), "0 warnings")
    errors = next((line.strip() for line in result.stdout.splitlines() if "Error(s)" in line), "0 errors")
    return step.ok(f"{warnings}, {errors}")


def step_scenario() -> Step:
    """Spawn the real core, hunt it blind, then let it wake and verify itself."""
    step = Step("live scenario")
    if not ON_LINUX:
        return step.skip("live scenario is implemented for the Linux reference core")

    proc = subprocess.Popen(
        [
            PY,
            str(CORE),
            "--lab-ack",
            "--mode",
            "encrypt",
            "--protect",
            "noaccess",
            "--awake",
            "2",
            "--sleep",
            "10",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready, _, _ = select.select([proc.stdout], [], [], 10)
        if not ready:
            return step.fail("core printed no status line")
        status = json.loads(proc.stdout.readline())
        if status.get("event") != "ready":
            return step.fail(f"unexpected first event: {status.get('event')}")

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "hunt.json"
            hunt = _run(
                [
                    PY,
                    str(HUNT),
                    "--pid",
                    str(status["pid"]),
                    "--duration",
                    "6",
                    "--interval",
                    "0.1",
                    "--quiet",
                    "--out",
                    str(out),
                ],
                timeout=60,
            )
            if not out.exists():
                return step.fail(f"hunter produced no JSON (exit {hunt.returncode})")
            payload = json.loads(out.read_text(encoding="utf-8"))

        rules = {finding["rule"] for finding in payload["findings"]}
        region = int(status["region"]["address"], 16)

        problems = []
        if "D3-protection-flip" not in rules:
            problems.append("no D3")
        if "D4-orphan-noaccess" not in rules:
            problems.append("no D4")
        if "D2-entropy" in rules or "D6-key-recovery" in rules:
            problems.append("content rules ran on NOACCESS")
        if payload["summary"]["marker_hits_while_dormant"] != 0:
            problems.append("marker visible while dormant")
        if any(int(f["address"], 16) != region for f in payload["findings"]):
            problems.append("finding outside the region")
        if problems:
            return step.fail("; ".join(problems))

        try:
            code = proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            return step.fail("core did not wake within 20s")
        if code != 0:
            return step.fail(f"core exited {code} after wake (verification failed)")

        return step.ok(
            "noaccess: "
            + " ".join(sorted(rules))
            + f", marker hits while dormant={payload['summary']['marker_hits_while_dormant']}, "
            "wake hash verified"
        )
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def step_matrix() -> Step:
    step = Step("matrix")
    if not ON_LINUX:
        return step.skip("matrix needs a live core; run it inside the VM on Windows")
    result = _run(
        [PY, str(MATRIX), "--outdir", "report/out-verify"], timeout=900
    )
    if result.returncode != 0:
        lines = (result.stdout or result.stderr).strip().splitlines()
        return step.fail(lines[-1] if lines else "matrix failed")
    line = next(
        (line for line in result.stdout.splitlines() if "cases caught" in line),
        "matrix finished",
    )
    return step.ok(line)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="verify the sl33p lab end to end")
    parser.add_argument("--matrix", action="store_true", help="also run the full matrix (~2 min)")
    parser.add_argument("--no-build", action="store_true", help="skip the C# build")
    args = parser.parse_args(argv)

    info = environment()
    print("sl33p verification")
    for key, value in info.items():
        print(f"  {key:<12} {value if value is not None else 'not found'}")
    print()

    steps = [step_tests()]
    if not args.no_build:
        steps.append(step_build())
    if info.get("cryptography") is None:
        steps.append(Step("live scenario").skip("cryptography not installed"))
        if args.matrix:
            steps.append(Step("matrix").skip("cryptography not installed"))
    else:
        steps.append(step_scenario())
        if args.matrix:
            steps.append(step_matrix())

    for step in steps:
        mark = {"ok": "[ok]  ", "FAIL": "[FAIL]", "skip": "[--]  "}[step.status]
        print(f"{mark} {step.name:<16} {step.detail}")

    failed = [step for step in steps if step.status == "FAIL"]
    print()
    print("PASS" if not failed else f"FAIL ({len(failed)} step(s))")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
