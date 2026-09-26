"""Per-process disk I/O on macOS.

psutil has no ``Process.io_counters`` on macOS, so every process would read 0 B.
The kernel keeps cumulative disk bytes per process in ``rusage_info`` (the same
source Apple's Activity Monitor uses). ``proc_pid_rusage`` returns it for the
current user's processes without elevated rights; other users' processes (root,
system daemons) stay unavailable and read as ``None``.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import sys

RUSAGE_INFO_V2 = 2


class RusageInfoV2(ctypes.Structure):
    _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [
        (name, ctypes.c_uint64)
        for name in (
            "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups", "ri_interrupt_wkups", "ri_pageins",
            "ri_wired_size", "ri_resident_size", "ri_phys_footprint", "ri_proc_start_abstime",
            "ri_proc_exit_abstime", "ri_child_user_time", "ri_child_system_time", "ri_child_pkg_idle_wkups",
            "ri_child_interrupt_wkups", "ri_child_pageins", "ri_child_elapsed_abstime",
            "ri_diskio_bytesread", "ri_diskio_byteswritten",
        )
    ]


_proc_pid_rusage = None
if sys.platform == "darwin":
    try:
        _libproc = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)
        _proc_pid_rusage = _libproc.proc_pid_rusage
        _proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(RusageInfoV2)]
        _proc_pid_rusage.restype = ctypes.c_int
    except (OSError, AttributeError):
        _proc_pid_rusage = None


def available() -> bool:
    return _proc_pid_rusage is not None


def disk_bytes(pid: int):
    """(bytes_read, bytes_written) since the process started, or None when the kernel refuses."""
    if _proc_pid_rusage is None or not isinstance(pid, int) or pid <= 0:
        return None
    info = RusageInfoV2()
    if _proc_pid_rusage(pid, RUSAGE_INFO_V2, ctypes.byref(info)) != 0:
        return None
    return int(info.ri_diskio_bytesread), int(info.ri_diskio_byteswritten)
