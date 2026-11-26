#!/usr/bin/env python3
"""sl33p-core (Linux reference implementation).

Same technique as the C# core, with mmap/mprotect instead of VirtualAlloc/
VirtualProtect: one self-owned region, marker inside, AES-256-GCM sealed in
place, protection flipped, wait, restore, decrypt, verify.

Two details exist because the first live run caught them:

1. The marker is never materialised as a string. It lives XOR-encoded and is
   written byte-by-byte into the region, so a scanner cannot find the marker in
   this process's heap while the region is sealed. (The first version kept the
   literal around and D1 found it in the interpreter's arena.)
2. The region is bracketed by read-only guard pages so the kernel cannot merge
   its VMA with a neighbour. Without that, /proc/<pid>/maps reported a 68 KiB
   region and D6 could not line up the ciphertext.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    sys.stderr.write("error: the Linux core needs `cryptography` (pip install cryptography)\n")
    raise SystemExit(3)

# "SL33P_LAB_MARKER_9f2c1d7e" XOR 0x5A. Never stored in the clear.
ENCODED_MARKER = bytes(
[
    0x09, 0x16, 0x69, 0x69, 0x0A, 0x05, 0x16, 0x1B,
    0x18, 0x05, 0x17, 0x1B, 0x08, 0x11, 0x1F, 0x08,
    0x05, 0x63, 0x3C, 0x68, 0x39, 0x6B, 0x3E, 0x6D,
    0x3F,
]
)
MARKER_MASK = 0x5A

PAGE = 4096
PROT_NONE = 0
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20

NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
HEADER_SIZE = 4096
CHUNK = 4096

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_long,
]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]

PROTECTIONS = {
    "rw": (PROT_READ | PROT_WRITE, "RW"),
    "noaccess": (PROT_NONE, "NOACCESS"),
    "rx": (PROT_READ | PROT_EXEC, "RX"),
}


def _die(message: str, code: int = 1) -> None:
    sys.stderr.write(f"error: {message}\n")
    raise SystemExit(code)


def _mmap(size: int) -> int:
    address = libc.mmap(
        None, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
    )
    if not address or address == ctypes.c_void_p(-1).value:
        _die(f"mmap failed: {os.strerror(ctypes.get_errno())}")
    return int(address)


def _mprotect(address: int, size: int, prot: int) -> None:
    if libc.mprotect(ctypes.c_void_p(address), size, prot) != 0:
        _die(f"mprotect failed: {os.strerror(ctypes.get_errno())}")


class Region:
    """One guarded allocation; `address` points at the usable middle page run."""

    def __init__(self, size: int):
        self.size = size
        self._map_size = size + 2 * PAGE
        self._base = _mmap(self._map_size)
        self.address = self._base + PAGE
        # Read-only guards keep this VMA from merging with an anonymous neighbour.
        _mprotect(self._base, PAGE, PROT_READ)
        _mprotect(self.address + size, PAGE, PROT_READ)
        self.protection = "RW"

    def read_at(self, offset: int, size: int) -> bytes:
        return ctypes.string_at(self.address + offset, size)

    def write_at(self, offset: int, data: bytes | bytearray) -> None:
        ctypes.memmove(self.address + offset, bytes(data), len(data))

    def read(self) -> bytes:
        return self.read_at(0, self.size)

    def sha256(self) -> str:
        return hashlib.sha256(self.read()).hexdigest()

    def protect(self, key: str) -> None:
        prot, name = PROTECTIONS[key]
        _mprotect(self.address, self.size, prot)
        self.protection = name

    def close(self) -> None:
        _mprotect(self._base, self._map_size, PROT_READ | PROT_WRITE)
        ctypes.memset(self._base, 0, self._map_size)
        libc.munmap(ctypes.c_void_p(self._base), self._map_size)


class Header(Region):
    """nonce | tag | key, exactly like the C# CryptoHeader."""

    def __init__(self) -> None:
        super().__init__(HEADER_SIZE)
        self._data = bytearray(HEADER_SIZE)

    def set_nonce(self, nonce: bytes) -> None:
        self._data[0:NONCE_LEN] = nonce
        self.write_at(0, self._data)

    def set_tag(self, tag: bytes) -> None:
        self._data[NONCE_LEN : NONCE_LEN + TAG_LEN] = tag
        self.write_at(0, self._data)

    def set_key(self, key: bytes) -> None:
        self._data[NONCE_LEN + TAG_LEN : NONCE_LEN + TAG_LEN + KEY_LEN] = key
        self.write_at(0, self._data)

    @property
    def nonce(self) -> bytes:
        return bytes(self._data[0:NONCE_LEN])

    @property
    def tag(self) -> bytes:
        return bytes(self._data[NONCE_LEN : NONCE_LEN + TAG_LEN])


def fill(region: Region) -> None:
    """Write the marker without ever building it as a Python object."""
    for index, value in enumerate(ENCODED_MARKER):
        ctypes.c_ubyte.from_address(region.address + index).value = value ^ MARKER_MASK
    ctypes.c_ubyte.from_address(region.address + len(ENCODED_MARKER)).value = 0x0A

    offset = len(ENCODED_MARKER) + 1
    slot = 0
    while offset < region.size:
        line = f"sl33p lab benign region slot {slot:05d}\n".encode("ascii")
        count = min(len(line), region.size - offset)
        ctypes.memmove(region.address + offset, line, count)
        offset += count
        slot += 1


def seal(region: Region, key: bytes, nonce: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    offset = 0
    while offset < region.size:
        count = min(CHUNK, region.size - offset)
        ciphertext = encryptor.update(region.read_at(offset, count))
        region.write_at(offset, ciphertext)
        offset += count
    encryptor.finalize()
    return encryptor.tag


def open_(region: Region, key: bytes, nonce: bytes, tag: bytes) -> None:
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    plain = bytearray(region.size)
    try:
        offset = 0
        while offset < region.size:
            count = min(CHUNK, region.size - offset)
            plain[offset : offset + count] = decryptor.update(region.read_at(offset, count))
            offset += count
        decryptor.finalize()
        region.write_at(0, plain)
    finally:
        plain[:] = b"\x00" * len(plain)


def status(event: str, options, region: Region, header: Header | None, marker_sha: str, cycle: int) -> None:
    state = "asleep" if event == "asleep" else "awake"
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        "pid": os.getpid(),
        "implementation": "linux",
        "mode": options.mode,
        "state": state,
        "cycle": cycle,
        "sleep_seconds": options.sleep,
        "awake_seconds": options.awake,
        "protect_mode": options.protect,
        "region": {
            "address": hex(region.address),
            "size": region.size,
            "protection": region.protection,
        },
        "header": None
        if header is None
        else {"address": hex(header.address), "size": header.size},
        "marker_sha256": marker_sha,
    }
    print(json.dumps(payload), flush=True)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="core_linux.py",
        description="sl33p lab-only self-process sleep obfuscation (Linux reference)",
    )
    parser.add_argument("--mode", choices=["plain", "encrypt"], default="encrypt")
    parser.add_argument("--protect", choices=list(PROTECTIONS), default="rw")
    parser.add_argument("--sleep", type=int, default=30)
    parser.add_argument("--awake", type=int, default=0)
    parser.add_argument("--cycles", type=int, default=1)
    parser.add_argument("--size", type=int, default=65536)
    parser.add_argument("--lab-ack", action="store_true")
    options = parser.parse_args(argv)

    if not 4096 <= options.size <= 1024 * 1024:
        parser.error("--size must be 4096..1048576")
    if not 1 <= options.sleep <= 86400:
        parser.error("--sleep must be 1..86400")
    if not 1 <= options.cycles <= 1000:
        parser.error("--cycles must be 1..1000")
    if not 0 <= options.awake <= 600:
        parser.error("--awake must be 0..600")
    if options.mode == "plain" and options.protect != "rw":
        parser.error("plain mode is the no-obfuscation baseline; it cannot change protection")
    if not options.lab_ack:
        parser.error("this is a lab-only tool and requires --lab-ack (see docs/scope.md)")

    return options


def run(options: argparse.Namespace) -> int:
    region = Region(options.size)
    header: Header | None = None
    key = b""

    try:
        fill(region)
        expected = region.sha256()

        if options.mode == "encrypt":
            header = Header()
            key = secrets.token_bytes(KEY_LEN)
            header.set_key(key)

        status("ready", options, region, header, expected, 0)

        # The hunter needs a baseline taken while the region is still plaintext.
        if options.awake:
            time.sleep(options.awake)

        for cycle in range(1, options.cycles + 1):
            if header is not None:
                nonce = secrets.token_bytes(NONCE_LEN)
                header.set_nonce(nonce)
                header.set_tag(seal(region, key, nonce))

            region.protect(options.protect)
            status("asleep", options, region, header, expected, cycle)

            time.sleep(options.sleep)

            region.protect("rw")

            if header is not None:
                open_(region, key, header.nonce, header.tag)

            actual = region.sha256()
            if actual != expected:
                _die(f"region verification failed on cycle {cycle}", 4)

            status("awake", options, region, header, actual, cycle)

        status("exit", options, region, header, expected, options.cycles)
        return 0
    finally:
        if header is not None:
            header.close()
        region.close()


if __name__ == "__main__":
    raise SystemExit(run(parse_args(None)))
