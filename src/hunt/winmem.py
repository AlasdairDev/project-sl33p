"""Read-only access to another process on Windows.

Every Win32 call in the project's defence side lives here. There is no
write primitive: no VirtualProtectEx, no WriteProcessMemory, no thread
creation. The hunter can look and nothing else.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from dataclasses import dataclass

from models import Region

IS_WINDOWS = sys.platform == "win32"

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
ERROR_PARTIAL_COPY = 299

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if IS_WINDOWS else None


class Unsupported(RuntimeError):
    """Raised when a Windows-only operation is attempted elsewhere."""


class Win32Error(OSError):
    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        super().__init__(code, f"{operation} failed with Win32 error {code}")


class Unreadable(Win32Error):
    """ReadProcessMemory returned nothing, usually PAGE_NOACCESS."""


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


if _kernel32 is not None:
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE

    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    _kernel32.VirtualQueryEx.restype = ctypes.c_size_t

    _kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _kernel32.ReadProcessMemory.restype = wintypes.BOOL

    _kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    _kernel32.GetProcessTimes.restype = wintypes.BOOL

    _kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
else:  # pragma: no cover - exercised implicitly on Linux
    _kernel32 = None


def _filetime_ms(value: wintypes.FILETIME) -> float:
    ticks = (value.dwHighDateTime << 32) | value.dwLowDateTime
    return ticks / 10_000.0  # 100 ns units -> ms


class TargetProcess:
    """A read-only handle to one process, with the guard rails the lab needs."""

    def __init__(self, pid: int, allow_system: bool = False):
        if not IS_WINDOWS:
            raise Unsupported("live memory inspection needs Windows; use --replay on Linux")

        if pid <= 0:
            raise ValueError("pid must be positive")
        if pid in (0, 4) and not allow_system:
            raise ValueError("refusing to inspect the System Idle Process or System (pid 0/4)")
        if pid == os.getpid():
            raise ValueError("refusing to inspect the hunter itself")

        self.pid = pid
        self._handle: int | None = None
        self._allow_system = allow_system

    def __enter__(self) -> "TargetProcess":
        if _kernel32 is None:
            raise Unsupported("kernel32 unavailable")
        handle = _kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid
        )
        if not handle:
            raise Win32Error(ctypes.get_last_error(), f"OpenProcess({self.pid})")
        self._handle = handle
        return self

    def __exit__(self, *_exc) -> None:
        if self._handle and _kernel32 is not None:
            _kernel32.CloseHandle(self._handle)
        self._handle = None

    def _require(self) -> int:
        if self._handle is None or _kernel32 is None:
            raise Unsupported("process handle is not open")
        return self._handle

    def regions(self) -> list[Region]:
        handle = self._require()
        info = MEMORY_BASIC_INFORMATION()
        size = ctypes.sizeof(info)
        address = 0
        result: list[Region] = []

        while True:
            written = _kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(address), ctypes.byref(info), size
            )
            if not written:
                break
            base = int(info.BaseAddress or 0)
            region_size = int(info.RegionSize)
            if region_size <= 0 or base < 0:
                break
            result.append(
                Region(
                    base=base,
                    size=region_size,
                    protect=int(info.Protect),
                    state=int(info.State),
                    type=int(info.Type),
                )
            )
            address = base + region_size
            if address >= 0x7FFF_FFFF_FFFF:
                break

        return result

    def read(self, address: int, size: int) -> bytes:
        handle = self._require()
        if size <= 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        ok = _kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read)
        )
        if not ok:
            error = ctypes.get_last_error()
            if read.value == 0:
                raise Unreadable(error, f"ReadProcessMemory({self.pid}, 0x{address:X})")
        return buffer.raw[: read.value]

    def cpu_time_ms(self) -> float:
        handle = self._require()
        created = wintypes.FILETIME()
        exited = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        ok = _kernel32.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        )
        if not ok:
            raise Win32Error(ctypes.get_last_error(), "GetProcessTimes")
        return _filetime_ms(kernel) + _filetime_ms(user)

    def image_name(self) -> str:
        handle = self._require()
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not _kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise Win32Error(ctypes.get_last_error(), "QueryFullProcessImageNameW")
        return buffer.value


@dataclass(frozen=True)
class Sample:
    base: int
    size: int
    data: bytes
    protection: str
