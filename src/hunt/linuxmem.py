"""Read-only process access on Linux, matching the winmem.py interface.

Same guard rails: one PID, read-only, no writes, no ptrace attach, no signals.
Reads come from /proc/<pid>/maps and /proc/<pid>/mem, which require the same
uid and ptrace permission (Yama ptrace_scope=0, CAP_SYS_PTRACE, or the target
opting in via PR_SET_PTRACER).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from models import (
    MEM_COMMIT,
    MEM_MAPPED,
    MEM_PRIVATE,
    PAGE_NOACCESS,
    Region,
    protection_name,
)

IS_LINUX = sys.platform.startswith("linux")


class Unsupported(RuntimeError):
    pass


class Win32Error(OSError):
    """Kept under the Windows name so the hunter's error handling is shared."""

    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        super().__init__(code, f"{operation} failed with errno {code}")


class Unreadable(Win32Error):
    pass


_PERM_BITS = {
    "r": 0x02,
    "w": 0x04,
    "x": 0x10,
}


def protect_from_perms(perms: str) -> int:
    """Map rwxp permission string to the Win32-style protection values.

    The rules compare names, not numbers, so '---p' has to render as NOACCESS
    and 'r-xp' as RX exactly like VirtualQueryEx would on Windows.
    """
    if len(perms) < 3:
        raise ValueError(f"bad permission string: {perms!r}")

    read, write, execute = perms[0], perms[1], perms[2]
    if read != "r" and write != "w" and execute != "x":
        return PAGE_NOACCESS
    if read == "r" and write == "w" and execute == "x":
        return 0x40  # RWX
    if read == "r" and execute == "x":
        return 0x20  # RX
    if execute == "x":
        return 0x10  # X
    if read == "r" and write == "w":
        return 0x04  # RW
    if read == "r":
        return 0x02  # R
    return 0x08  # write-only is not expressible on Linux; closest label


def parse_maps(text: str) -> list[Region]:
    regions: list[Region] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            continue

        address_range, perms = fields[0], fields[1]
        try:
            start_text, end_text = address_range.split("-")
            start, end = int(start_text, 16), int(end_text, 16)
        except ValueError:
            continue

        size = end - start
        if size <= 0:
            continue

        pathname = fields[5].strip() if len(fields) > 5 else ""
        # Anonymous mappings are the ones the rules care about. [heap] and [stack] are
        # anonymous too; [vdso]/[vvar]/[vsyscall] are kernel pages, not private
        # allocations, and the vsyscall page sits above 2^63 where pread cannot
        # address it.
        anonymous = not pathname or pathname in ("[heap]", "[stack]")
        mem_type = MEM_PRIVATE if anonymous else MEM_MAPPED

        regions.append(
            Region(
                base=start,
                size=size,
                protect=protect_from_perms(perms),
                state=MEM_COMMIT,
                type=mem_type,
            )
        )
    return regions


@dataclass(frozen=True)
class Sample:
    base: int
    size: int
    data: bytes
    protection: str


class TargetProcess:
    def __init__(self, pid: int, allow_system: bool = False):
        if not IS_LINUX:
            raise Unsupported("linuxmem requires Linux")
        if pid <= 0:
            raise ValueError("pid must be positive")
        if pid <= 1 and not allow_system:
            raise ValueError("refusing to inspect init (pid 1)")
        if pid == os.getpid():
            raise ValueError("refusing to inspect the hunter itself")
        self.pid = pid
        self._mem_fd: int | None = None

    def __enter__(self) -> "TargetProcess":
        try:
            self._mem_fd = os.open(f"/proc/{self.pid}/mem", os.O_RDONLY)
        except OSError as exc:
            raise Win32Error(exc.errno or 0, f"open /proc/{self.pid}/mem") from exc
        return self

    def __exit__(self, *_exc) -> None:
        if self._mem_fd is not None:
            os.close(self._mem_fd)
        self._mem_fd = None

    def _require(self) -> int:
        if self._mem_fd is None:
            raise Unsupported("process memory is not open")
        return self._mem_fd

    def regions(self) -> list[Region]:
        try:
            with open(f"/proc/{self.pid}/maps", encoding="utf-8") as handle:
                return parse_maps(handle.read())
        except OSError as exc:
            raise Win32Error(exc.errno or 0, f"read /proc/{self.pid}/maps") from exc

    def read(self, address: int, size: int) -> bytes:
        if size <= 0:
            return b""
        if address < 0 or address >= 1 << 63:
            raise Unreadable(0, f"address 0x{address:X} outside pread range")
        fd = self._require()
        try:
            data = os.pread(fd, size, address)
        except OSError as exc:
            raise Unreadable(exc.errno or 0, f"pread /proc/{self.pid}/mem") from exc
        if not data:
            raise Unreadable(5, f"pread /proc/{self.pid}/mem returned nothing")
        return data

    def cpu_time_ms(self) -> float:
        try:
            with open(f"/proc/{self.pid}/stat", encoding="utf-8") as handle:
                raw = handle.read()
        except OSError as exc:
            raise Win32Error(exc.errno or 0, f"read /proc/{self.pid}/stat") from exc

        # comm may contain spaces and parentheses; fields resume after the last ')'
        tail = raw[raw.rfind(")") + 2 :].split()
        try:
            ticks = int(tail[11]) + int(tail[12])
        except (IndexError, ValueError) as exc:
            raise Win32Error(0, "parse /proc stat") from exc
        return ticks * 1000.0 / os.sysconf("SC_CLK_TCK")

    def image_name(self) -> str:
        try:
            with open(f"/proc/{self.pid}/comm", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError as exc:
            raise Win32Error(exc.errno or 0, f"read /proc/{self.pid}/comm") from exc


__all__ = [
    "IS_LINUX",
    "Sample",
    "TargetProcess",
    "Unreadable",
    "Unsupported",
    "Win32Error",
    "parse_maps",
    "protect_from_perms",
    "protection_name",
]
