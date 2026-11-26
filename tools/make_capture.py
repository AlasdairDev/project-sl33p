"""Build a deterministic replay capture.

This is a synthetic fixture, not evidence from a live run. It exists so the
rule engine can be tested and demoed on Linux, and so `--replay` has a known
input. The key is a published test vector, not a secret.

The plaintext layout matches src/core/MemoryRegion.cs: the marker on line one,
then numbered ASCII filler to the end of the region.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    HAVE_AESGCM = True
except ImportError:  # pragma: no cover - keeps the module importable for tests
    AESGCM = None  # type: ignore[assignment]
    HAVE_AESGCM = False

MARKER = "SL33P_LAB_MARKER_9f2c1d7e"
REGION_BASE = 0x1F000000
REGION_SIZE = 65536
HEADER_BASE = 0x1F100000
HEADER_SIZE = 4096
OTHER_BASE = 0x1F200000
OTHER_SIZE = 8192

# Test vector. Never used by the core; never a real key.
KEY = bytes.fromhex(
    "8d4f2a91c37b05e6f1a8d9426c0b7e53a19f4c8d2e7b6035fa19c4d82b7e6f01"
)
NONCE = bytes.fromhex("00112233445566778899aabb")


def plaintext(marker: str = MARKER, size: int = REGION_SIZE) -> bytes:
    buffer = bytearray((marker + "\n").encode("ascii"))
    slot = 0
    while len(buffer) < size:
        buffer.extend(f"sl33p lab benign region slot {slot:05d}\n".encode("ascii"))
        slot += 1
    del buffer[size:]
    return bytes(buffer)


def _region(base: int, size: int, protect: str, data: bytes | None = None) -> dict:
    entry: dict = {
        "base": f"0x{base:X}",
        "size": size,
        "protect": protect,
        "type": "PRIVATE",
        "state": "COMMIT",
    }
    if data is not None:
        entry["data_b64"] = base64.b64encode(data).decode("ascii")
    return entry


def build_capture(pid: int = 4242) -> dict:
    if AESGCM is None:
        raise RuntimeError("generating a capture needs `cryptography` (pip install cryptography)")
    plain = plaintext()
    sealed = AESGCM(KEY).encrypt(NONCE, plain, None)
    cipher, tag = sealed[:-16], sealed[-16:]
    header = NONCE + tag + KEY
    other = b"\x00" * OTHER_SIZE

    return {
        "pid": pid,
        "marker": MARKER,
        "note": "synthetic replay fixture; see tools/make_capture.py",
        "ticks": [
            {
                "t": 0.0,
                "cpu_ms": 10.0,
                "regions": [
                    _region(REGION_BASE, REGION_SIZE, "RW", plain),
                    _region(HEADER_BASE, HEADER_SIZE, "RW", header),
                    _region(OTHER_BASE, OTHER_SIZE, "RW", other),
                ],
            },
            {
                "t": 1.0,
                "cpu_ms": 10.2,
                "regions": [
                    _region(REGION_BASE, REGION_SIZE, "RW", cipher),
                    _region(HEADER_BASE, HEADER_SIZE, "RW", header),
                    _region(OTHER_BASE, OTHER_SIZE, "RW", other),
                ],
            },
            {
                "t": 13.0,
                "cpu_ms": 10.4,
                "regions": [
                    _region(REGION_BASE, REGION_SIZE, "RW", plain),
                    _region(HEADER_BASE, HEADER_SIZE, "RW", header),
                    _region(OTHER_BASE, OTHER_SIZE, "RW", other),
                ],
            },
        ],
    }


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    if AESGCM is None:
        raise SystemExit("error: generating a capture needs `cryptography` (pip install cryptography)")

    parser = argparse.ArgumentParser(description="write a deterministic sl33p replay capture")
    parser.add_argument("--out", default=str(root / "lab" / "captures" / "demo.json"))
    parser.add_argument("--pid", type=int, default=4242)
    args = parser.parse_args(argv)

    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(build_capture(args.pid), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {target} ({target.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
