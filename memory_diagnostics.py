"""Resilient, bounded, local-only memory telemetry for Activity Monitor.

Every value comes from a measured macOS or psutil source. Source chains retry
within a fixed bound, retain prior valid evidence on transient failure, and
surface explicit source/error codes when no truthful measurement exists. The
service never signals a process, writes a report, uploads data, or repairs the
system automatically.
"""

from copy import deepcopy
from datetime import datetime, timezone
import os
import re
import subprocess
import sys
import threading
import time

import psutil


SCHEMA_VERSION = "ke.activity-monitor-memory-diagnostics.v2"
MIB = 1024 ** 2
GIB = 1024 ** 3
DEFAULT_SAMPLE_SECONDS = 12.0
DEFAULT_SOURCE_ATTEMPTS = 2
DEFAULT_SOURCE_RETRY_SECONDS = 0.05
PROCESS_GROWTH_MIN_BYTES = 128 * MIB
PROCESS_GROWTH_MIN_FINAL_BYTES = 256 * MIB
PROCESS_GROWTH_MIN_PERCENT = 20.0

READ_ONLY_BOUNDARY = {
    "mode": "local-read-only",
    "uploads": False,
    "savedReport": False,
    "processSignals": False,
    "processTermination": False,
    "restarts": False,
    "cleanup": False,
    "automaticRepair": False,
    "clipboardWrite": "explicit-user-action-only",
}

_CANARY_FAULT_ALIASES = {
    "memory-primary": "memory.psutil",
    "pressure-primary": "pressure.memory_pressure",
    "paging-primary": "paging.psutil",
    "compression-primary": "compression.vm_stat",
    "process-primary": "process.psutil",
    "swap-storage-primary": "swap-storage.psutil",
    "swap-capacity-primary": "swap-storage.psutil",
    "swap-used-primary": "swap-used.psutil",
}


class MemorySourceError(RuntimeError):
    """A sanitized source failure safe to expose in local UI evidence."""

    def __init__(self, code):
        self.code = str(code or "source_error")
        super().__init__(self.code)


class SourceChainError(RuntimeError):
    """Every bounded source for one metric failed."""

    def __init__(self, metric, attempts, failures):
        self.metric = metric
        self.attempts = int(attempts)
        self.failures = list(failures)
        super().__init__(f"{metric}:source_chain_failed")

    def public(self, *, label=None):
        return {
            "metric": self.metric,
            "label": label or self.metric,
            "code": "source_chain_failed",
            "attemptLimit": self.attempts,
            "failedSources": deepcopy(self.failures),
            "retryable": True,
        }


def _utc_iso(epoch):
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_percent(value):
    return max(0.0, min(100.0, float(value)))


def _bytes_label(value):
    value = max(0.0, float(value or 0))
    if value >= GIB:
        return f"{value / GIB:.1f} GB"
    return f"{value / MIB:.0f} MB"


def _parse_size_bytes(value):
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?)B?\s*", str(value or ""), re.IGNORECASE)
    if not match:
        return None
    multiplier = {"": 1, "K": 1024, "M": MIB, "G": GIB, "T": 1024 ** 4}[match.group(2).upper()]
    return int(float(match.group(1)) * multiplier)


def _parse_memory_pressure(text):
    match = re.search(
        r"System-wide memory free percentage:\s*([0-9]+(?:\.[0-9]+)?)%",
        text or "",
    )
    return _bounded_percent(match.group(1)) if match else None


def _parse_vm_stat(text):
    if not text:
        return None
    page_match = re.search(r"page size of\s+([0-9]+)\s+bytes", text, re.IGNORECASE)
    page_size = int(page_match.group(1)) if page_match else 4096
    fields = {}
    for line in text.splitlines():
        match = re.match(r"\s*\"?([^:\"]+)\"?:\s*([0-9]+)\.?\s*$", line)
        if not match:
            continue
        key = re.sub(r"[^a-z0-9]+", "_", match.group(1).strip().lower()).strip("_")
        fields[key] = int(match.group(2))
    if not fields:
        return None
    return {
        "pageSizeBytes": page_size,
        "compressions": fields.get("compressions"),
        "decompressions": fields.get("decompressions"),
        "pagesOccupied": fields.get("pages_occupied_by_compressor"),
        "pagesStored": fields.get("pages_stored_in_compressor"),
        "pagesFree": fields.get("pages_free"),
        "pagesActive": fields.get("pages_active"),
        "pagesInactive": fields.get("pages_inactive"),
        "pagesSpeculative": fields.get("pages_speculative"),
        "pagesWired": fields.get("pages_wired_down"),
        "pagesPurgeable": fields.get("pages_purgeable"),
        "pageIns": fields.get("pageins"),
        "pageOuts": fields.get("pageouts"),
        "swapIns": fields.get("swapins"),
        "swapOuts": fields.get("swapouts"),
    }


def _parse_swap_usage(text):
    match = re.search(r"\bused\s*=\s*([0-9]+(?:\.[0-9]+)?\s*[KMGT]B?)", text or "", re.IGNORECASE)
    return _parse_size_bytes(match.group(1)) if match else None


def _parse_top_summary(text):
    if not text:
        return None
    result = {}
    physical = re.search(
        r"PhysMem:\s*([^,]+?)\s+used\s*\(([^)]*)\),\s*([^\s,]+)\s+unused",
        text,
        re.IGNORECASE,
    )
    if physical:
        result["usedBytes"] = _parse_size_bytes(physical.group(1))
        result["unusedBytes"] = _parse_size_bytes(physical.group(3))
        wired = re.search(r"([^,]+?)\s+wired", physical.group(2), re.IGNORECASE)
        compressor = re.search(r"([^,]+?)\s+compressor", physical.group(2), re.IGNORECASE)
        result["wiredBytes"] = _parse_size_bytes(wired.group(1)) if wired else None
        result["compressorBytes"] = _parse_size_bytes(compressor.group(1)) if compressor else None
    paging = re.search(
        r"VM:.*?([0-9]+)\([^)]*\)\s+swapins,\s*([0-9]+)\([^)]*\)\s+swapouts",
        text,
        re.IGNORECASE,
    )
    if paging:
        result["swapIns"] = int(paging.group(1))
        result["swapOuts"] = int(paging.group(2))
    return result or None


def _parse_ps_processes(text, current_pid):
    rows = {}
    for line in (text or "").splitlines():
        match = re.match(r"\s*([0-9]+)\s+([0-9]+)\s+(.+?)\s*$", line)
        if not match:
            continue
        pid = int(match.group(1))
        if pid <= 0 or pid == current_pid:
            continue
        rss = int(match.group(2)) * 1024
        name = match.group(3).strip()[:120] or f"PID {pid}"
        rows[f"{pid}:{name}"] = {"pid": pid, "name": name, "rssBytes": rss}
    return rows


class MemoryDiagnosticsService:
    """Resolve live Memory rows and run one non-overlapping diagnostic."""

    def __init__(
        self,
        *,
        psutil_module=psutil,
        command_reader=None,
        statvfs_reader=os.statvfs,
        sleeper=time.sleep,
        clock=time.time,
        sample_seconds=DEFAULT_SAMPLE_SECONDS,
        platform_name=None,
        disk_path=None,
        current_pid=None,
        source_attempts=DEFAULT_SOURCE_ATTEMPTS,
        source_retry_seconds=DEFAULT_SOURCE_RETRY_SECONDS,
        faults=None,
    ):
        self._psutil = psutil_module
        self._command_reader = command_reader or self._default_command_reader
        self._statvfs_reader = statvfs_reader
        self._sleep = sleeper
        self._clock = clock
        self.sample_seconds = max(0.0, float(sample_seconds))
        self._platform_name = sys.platform if platform_name is None else platform_name
        self._disk_path = disk_path or (
            "/private/var/vm"
            if self._platform_name == "darwin" and os.path.isdir("/private/var/vm")
            else "/"
        )
        self._current_pid = os.getpid() if current_pid is None else int(current_pid)
        self._source_attempts = max(1, min(3, int(source_attempts)))
        self._source_retry_seconds = max(0.0, min(0.25, float(source_retry_seconds)))
        self._faults = set(faults) if faults is not None else self._environment_faults()
        self._run_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._last_valid_findings = {}
        self._last_base_memory = None

    @staticmethod
    def _environment_faults():
        if os.environ.get("KE_ACTIVITY_MONITOR_MEMORY_CANARY") != "1":
            return set()
        requested = {
            token.strip()
            for token in os.environ.get("KE_ACTIVITY_MONITOR_MEMORY_CANARY_FAULTS", "").split(",")
            if token.strip()
        }
        return {_CANARY_FAULT_ALIASES.get(token, token) for token in requested}

    @staticmethod
    def _default_command_reader(args, timeout):
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise MemorySourceError("timeout") from error
        except OSError as error:
            code = f"errno_{error.errno}" if error.errno is not None else type(error).__name__
            raise MemorySourceError(code) from error
        except subprocess.SubprocessError as error:
            raise MemorySourceError(type(error).__name__) from error
        if result.returncode != 0:
            raise MemorySourceError(f"exit_{result.returncode}")
        if not result.stdout or not result.stdout.strip():
            raise MemorySourceError("empty_output")
        return result.stdout.strip()

    @staticmethod
    def _error_code(error):
        if isinstance(error, MemorySourceError):
            return error.code
        if isinstance(error, OSError) and error.errno is not None:
            return f"errno_{error.errno}"
        return type(error).__name__

    def _command_text(self, args, timeout):
        text = self._command_reader(args, timeout)
        if not isinstance(text, str) or not text.strip():
            raise MemorySourceError("empty_output")
        return text.strip()

    def _resolve(self, metric, candidates):
        failures = []
        for attempt in range(1, self._source_attempts + 1):
            for index, (source, reader) in enumerate(candidates):
                try:
                    if source in self._faults:
                        raise MemorySourceError("injected_canary_fault")
                    value = reader()
                    if value is None:
                        raise MemorySourceError("no_data")
                    evidence = {
                        "selected": source,
                        "usedFallback": index > 0,
                        "attempt": attempt,
                        "attemptLimit": self._source_attempts,
                        "failures": deepcopy(failures),
                    }
                    return value, evidence
                except Exception as error:
                    failures.append({"source": source, "code": self._error_code(error), "attempt": attempt})
            if attempt < self._source_attempts and self._source_retry_seconds:
                self._sleep(self._source_retry_seconds)
        raise SourceChainError(metric, self._source_attempts, failures)

    @staticmethod
    def _attach_source(value, evidence):
        result = dict(value)
        result["source"] = evidence["selected"]
        result["sourceEvidence"] = deepcopy(evidence)
        return result

    def _psutil_memory(self):
        vm = self._psutil.virtual_memory()
        total = int(getattr(vm, "total", 0) or 0)
        available = int(getattr(vm, "available", -1))
        if total <= 0 or available < 0:
            raise MemorySourceError("invalid_memory_counters")
        used_value = getattr(vm, "used", None)
        used = int(total - available if used_value is None else used_value)
        return {
            "totalBytes": total,
            "availableBytes": max(0, min(total, available)),
            "usedBytes": max(0, min(total, used)),
            "wiredBytes": max(0, int(getattr(vm, "wired", 0) or 0)),
            "inactiveBytes": max(0, int(getattr(vm, "inactive", 0) or 0)),
        }

    def _vm_stat_memory(self):
        parsed = _parse_vm_stat(self._command_text(["/usr/bin/vm_stat"], 0.9))
        if not parsed:
            raise MemorySourceError("parse_error")
        total_text = self._command_text(["/usr/sbin/sysctl", "-n", "hw.memsize"], 0.6)
        try:
            total = int(total_text.strip())
        except ValueError as error:
            raise MemorySourceError("parse_error") from error
        page_size = int(parsed.get("pageSizeBytes") or 4096)
        required = (parsed.get("pagesFree"), parsed.get("pagesInactive"), parsed.get("pagesWired"))
        if total <= 0 or None in required:
            raise MemorySourceError("missing_memory_fields")
        available = (int(parsed["pagesFree"]) + int(parsed["pagesInactive"])) * page_size
        return {
            "totalBytes": total,
            "availableBytes": max(0, min(total, available)),
            "usedBytes": max(0, total - min(total, available)),
            "wiredBytes": max(0, int(parsed["pagesWired"]) * page_size),
            "inactiveBytes": max(0, int(parsed["pagesInactive"]) * page_size),
        }

    def _psutil_swap_used(self):
        swap = self._psutil.swap_memory()
        used = getattr(swap, "used", None)
        if used is None:
            raise MemorySourceError("missing_swap_used")
        return {"usedBytes": max(0, int(used))}

    def _sysctl_swap_used(self):
        used = _parse_swap_usage(self._command_text(["/usr/sbin/sysctl", "vm.swapusage"], 0.6))
        if used is None:
            raise MemorySourceError("parse_error")
        return {"usedBytes": used}

    def _pressure_command(self):
        observed = _parse_memory_pressure(self._command_text(["/usr/bin/memory_pressure", "-Q"], 0.9))
        if observed is None:
            raise MemorySourceError("parse_error")
        return {"headroomPercent": observed}

    @staticmethod
    def _pressure_from_memory(memory):
        if not memory:
            raise MemorySourceError("memory_dependency_failed")
        total = int(memory.get("totalBytes") or 0)
        available = int(memory.get("availableBytes") or 0)
        if total <= 0:
            raise MemorySourceError("invalid_memory_counters")
        return {"headroomPercent": available / total * 100.0}

    @staticmethod
    def _finish_pressure(value):
        headroom = _bounded_percent(value["headroomPercent"])
        state = "critical" if headroom < 8.0 else "pressure" if headroom < 18.0 else "normal"
        value = dict(value)
        value.update({"available": True, "state": state, "headroomPercent": round(headroom, 1), "pressurePercent": round(100.0 - headroom, 1)})
        return value

    def _paging_psutil(self):
        swap = self._psutil.swap_memory()
        values = (getattr(swap, "used", None), getattr(swap, "sin", None), getattr(swap, "sout", None))
        if None in values:
            raise MemorySourceError("missing_paging_fields")
        return {"usedBytes": max(0, int(values[0])), "swapInBytes": max(0, int(values[1])), "swapOutBytes": max(0, int(values[2]))}

    def _paging_vm_stat(self):
        parsed = _parse_vm_stat(self._command_text(["/usr/bin/vm_stat"], 0.9))
        if not parsed or None in (parsed.get("pageIns"), parsed.get("pageOuts")):
            raise MemorySourceError("missing_paging_fields")
        used = self._sysctl_swap_used()["usedBytes"]
        page_size = int(parsed.get("pageSizeBytes") or 4096)
        return {"usedBytes": used, "swapInBytes": max(0, int(parsed["pageIns"]) * page_size), "swapOutBytes": max(0, int(parsed["pageOuts"]) * page_size)}

    def _compressor_vm_stat(self):
        parsed = _parse_vm_stat(self._command_text(["/usr/bin/vm_stat"], 0.9))
        if not parsed or None in (parsed.get("compressions"), parsed.get("decompressions"), parsed.get("pagesOccupied")):
            raise MemorySourceError("missing_compressor_fields")
        return {
            "pageSizeBytes": int(parsed.get("pageSizeBytes") or 4096),
            "compressions": int(parsed["compressions"]),
            "decompressions": int(parsed["decompressions"]),
            "pagesOccupied": int(parsed["pagesOccupied"]),
            "activityDeltasAvailable": True,
        }

    def _compressor_top(self):
        parsed = _parse_top_summary(self._command_text(["/usr/bin/top", "-l", "1", "-n", "0", "-stats", "pid,command,mem"], 1.8))
        occupied = (parsed or {}).get("compressorBytes")
        if occupied is None:
            raise MemorySourceError("missing_compressor_fields")
        return {"pageSizeBytes": 1, "compressions": None, "decompressions": None, "pagesOccupied": int(occupied), "activityDeltasAvailable": False}

    def _process_psutil(self):
        rows = {}
        iterator = self._psutil.process_iter(["pid", "name", "create_time", "memory_info"])
        for process in iterator:
            try:
                info = process.info
                pid = int(info.get("pid") or 0)
                created = info.get("create_time")
                memory = info.get("memory_info")
                rss = int(getattr(memory, "rss", 0) or 0)
                if pid <= 0 or pid == self._current_pid or created is None or rss < 0:
                    continue
                key = f"{pid}:{float(created):.6f}"
                rows[key] = {"pid": pid, "name": str(info.get("name") or f"PID {pid}")[:120], "rssBytes": rss}
            except Exception:
                continue
        return rows

    def _process_ps(self):
        rows = _parse_ps_processes(self._command_text(["/bin/ps", "-axo", "pid=,rss=,comm="], 1.0), self._current_pid)
        if not rows:
            raise MemorySourceError("no_process_rows")
        return rows

    def _disk_psutil(self):
        disk = self._psutil.disk_usage(self._disk_path)
        total = int(getattr(disk, "total", 0) or 0)
        free = int(getattr(disk, "free", -1))
        if total <= 0 or free < 0:
            raise MemorySourceError("invalid_capacity")
        return {"path": self._disk_path, "totalBytes": total, "freeBytes": min(total, free)}

    def _disk_statvfs(self):
        stats = self._statvfs_reader(self._disk_path)
        fragment = int(getattr(stats, "f_frsize", 0) or getattr(stats, "f_bsize", 0) or 0)
        total = int(getattr(stats, "f_blocks", 0) or 0) * fragment
        free = int(getattr(stats, "f_bavail", 0) or 0) * fragment
        if total <= 0 or free < 0:
            raise MemorySourceError("invalid_capacity")
        return {"path": self._disk_path, "totalBytes": total, "freeBytes": min(total, free)}

    def _resolve_memory(self):
        value, source = self._resolve("memory", [("memory.psutil", self._psutil_memory), ("memory.vm_stat_sysctl", self._vm_stat_memory)])
        return self._attach_source(value, source)

    def _resolve_swap_used(self):
        value, source = self._resolve("swap-used", [("swap-used.psutil", self._psutil_swap_used), ("swap-used.sysctl", self._sysctl_swap_used)])
        return self._attach_source(value, source)

    def _resolve_pressure(self, memory):
        value, source = self._resolve("pressure", [("pressure.memory_pressure", self._pressure_command), ("pressure.memory_snapshot", lambda: self._pressure_from_memory(memory))])
        return self._attach_source(self._finish_pressure(value), source)

    def _resolve_paging(self):
        value, source = self._resolve("paging", [("paging.psutil", self._paging_psutil), ("paging.vm_stat_sysctl", self._paging_vm_stat)])
        return self._attach_source(value, source)

    def _resolve_compressor(self):
        value, source = self._resolve("compression", [("compression.vm_stat", self._compressor_vm_stat), ("compression.top", self._compressor_top)])
        return self._attach_source(value, source)

    def _resolve_processes(self):
        return self._resolve("process", [("process.psutil", self._process_psutil), ("process.ps", self._process_ps)])

    def _resolve_disk(self):
        value, source = self._resolve("swap-storage", [("swap-storage.psutil", self._disk_psutil), ("swap-storage.statvfs", self._disk_statvfs)])
        return self._attach_source(value, source)

    @staticmethod
    def _dedupe_failures(failures):
        unique = []
        seen = set()
        for failure in failures:
            key = (failure.get("source"), failure.get("code"), failure.get("attempt"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(deepcopy(failure))
        return unique

    @staticmethod
    def _failure_summary(errors):
        parts = []
        for error in errors:
            failed = error.get("failedSources") or []
            sources = ", ".join(dict.fromkeys(f"{row['source']}:{row['code']}" for row in failed))
            parts.append(f"{error.get('label') or error.get('metric')} ({sources or error.get('code')})")
        return "Measurement source chain failed after bounded retry: " + "; ".join(parts) + "."

    def _base_failure(self, errors, observed):
        with self._state_lock:
            retained = deepcopy(self._last_base_memory)
        if retained:
            retained.update({"ok": True, "stale": True, "freshness": "retained-last-valid", "staleSince": _utc_iso(observed), "sourceErrors": deepcopy(errors), "retryable": True, "actionLabel": "Retry"})
            return retained
        return {"ok": False, "code": "memory_source_chain_failed", "summary": self._failure_summary(errors), "errors": deepcopy(errors), "retryable": True, "actionLabel": "Retry", "stale": False}

    def base_snapshot(self):
        """Return the six base Memory rows through measured primary/fallback chains."""
        observed = float(self._clock())
        errors = []
        memory = swap = pressure = None
        try:
            memory = self._resolve_memory()
        except SourceChainError as error:
            errors.append(error.public(label="Base memory"))
        try:
            swap = self._resolve_swap_used()
        except SourceChainError as error:
            errors.append(error.public(label="Swap used"))
        try:
            pressure = self._resolve_pressure(memory)
        except SourceChainError as error:
            errors.append(error.public(label="Memory pressure"))
        if errors:
            return self._base_failure(errors, observed)
        total = int(memory["totalBytes"])
        used = int(memory["usedBytes"])
        wired = int(memory["wiredBytes"])
        result = {
            "ok": True,
            "total_gb": total / GIB,
            "used_gb": used / GIB,
            "available_gb": int(memory["availableBytes"]) / GIB,
            "percent": round(used / total * 100.0, 1) if total else 0.0,
            "wired_gb": wired / GIB,
            "inactive": int(memory["inactiveBytes"]),
            "used": used,
            "wired": wired,
            "swap_used_gb": int(swap["usedBytes"]) / GIB,
            "pressure": {
                "state": pressure["state"], "headroom_percent": pressure["headroomPercent"], "pressure_percent": pressure["pressurePercent"],
                "scope": "system-wide", "source": pressure["source"], "source_evidence": pressure["sourceEvidence"], "observed_at": observed,
                "detail": "Measured macOS reclaimable-memory headroom with a psutil-derived fallback.",
            },
            "sources": {"memory": memory["sourceEvidence"], "swapUsed": swap["sourceEvidence"], "pressure": pressure["sourceEvidence"]},
            "observed_at": observed, "observedAt": _utc_iso(observed), "stale": False, "freshness": "fresh", "retryable": False,
        }
        with self._state_lock:
            self._last_base_memory = deepcopy(result)
        return result

    def _capture(self):
        failures = {}
        def resolve(name, label, reader):
            try:
                return reader()
            except SourceChainError as error:
                failures[name] = error.public(label=label)
                return None
        memory = resolve("memory", "Base memory", self._resolve_memory)
        pressure = resolve("pressure", "Pressure", lambda: self._resolve_pressure(memory))
        paging = resolve("paging", "Swap activity", self._resolve_paging)
        compressor = resolve("compression", "Compression", self._resolve_compressor)
        process_result = resolve("process", "Process growth", self._resolve_processes)
        if process_result is not None:
            processes, process_source = process_result
        else:
            processes = process_source = None
        disk = resolve("swap-storage", "Swap storage", self._resolve_disk)
        return {"capturedAt": float(self._clock()), "memory": memory, "pressure": pressure, "paging": paging, "compressor": compressor, "processes": processes, "processSource": process_source, "disk": disk, "failures": failures}

    @staticmethod
    def _finding(identifier, label, status, summary, evidence, display_value=None):
        return {"id": identifier, "label": label, "status": status, "summary": summary, "displayValue": display_value or summary, "evidence": evidence, "stale": False}

    def _pressure_finding(self, final):
        pressure = final.get("pressure")
        if not pressure:
            return None
        state = pressure["state"]
        status = "critical" if state == "critical" else "attention" if state == "pressure" else "healthy"
        headroom = pressure["headroomPercent"]
        return self._finding("pressure", "Pressure", status, f"{headroom:.0f}% reclaimable headroom; pressure is {state}.", deepcopy(pressure), f"{headroom:.0f}% headroom")

    def _swap_finding(self, first, final, elapsed):
        before = first.get("paging")
        after = final.get("paging")
        if not before or not after:
            return None
        sin_before, sin_after = before.get("swapInBytes"), after.get("swapInBytes")
        sout_before, sout_after = before.get("swapOutBytes"), after.get("swapOutBytes")
        if None in (sin_before, sin_after, sout_before, sout_after):
            return None
        swap_in = max(0, int(sin_after) - int(sin_before))
        swap_out = max(0, int(sout_after) - int(sout_before))
        out_rate = swap_out / max(float(elapsed), 0.001)
        if swap_out >= 512 * MIB or out_rate >= 64 * MIB:
            status = "critical"
        elif swap_out >= 64 * MIB or out_rate >= 4 * MIB:
            status = "attention"
        else:
            status = "healthy"
        summary = f"Swap-out grew {_bytes_label(swap_out)} during the sample." if swap_out else f"No swap-out growth; {_bytes_label(after.get('usedBytes'))} remains allocated."
        return self._finding("swap", "Swap activity", status, summary, {"usedBytes": after.get("usedBytes"), "swapInBytesDelta": swap_in, "swapOutBytesDelta": swap_out, "swapOutBytesPerSecond": round(out_rate, 1), "sampleSeconds": round(float(elapsed), 2), "deltasAvailable": True, "sourceEvidence": deepcopy(after.get("sourceEvidence"))}, f"{_bytes_label(swap_out)} swap-out" if swap_out else "No swap-out growth")

    def _compressor_finding(self, first, final, elapsed):
        before = first.get("compressor")
        after = final.get("compressor")
        if not before or not after:
            return None
        page_size = int(after.get("pageSizeBytes") or before.get("pageSizeBytes") or 1)
        occupied = int(after.get("pagesOccupied") or 0) * page_size
        counters = (before.get("compressions"), after.get("compressions"), before.get("decompressions"), after.get("decompressions"))
        pressure_state = str((final.get("pressure") or {}).get("state") or "normal")
        if None in counters:
            status = "critical" if pressure_state == "critical" else "attention" if pressure_state == "pressure" else "healthy"
            return self._finding("compressor", "Compression", status, f"{_bytes_label(occupied)} compressor occupancy measured through the top fallback; activity delta is not exposed by that source.", {"occupiedBytes": occupied, "activityDeltasAvailable": False, "sourceEvidence": deepcopy(after.get("sourceEvidence"))}, f"{_bytes_label(occupied)} occupied")
        compressed = max(0, int(counters[1]) - int(counters[0])) * page_size
        decompressed = max(0, int(counters[3]) - int(counters[2])) * page_size
        rate = compressed / max(float(elapsed), 0.001)
        headroom = float((final.get("pressure") or {}).get("headroomPercent") or 100.0)
        status = "critical" if rate >= 256 * MIB and headroom < 15 else "attention" if rate >= 64 * MIB and headroom < 30 else "healthy"
        summary = f"Compressed {_bytes_label(compressed)} during the sample; {_bytes_label(occupied)} is occupied." if compressed else f"No new compression observed; {_bytes_label(occupied)} is occupied."
        return self._finding("compressor", "Compression", status, summary, {"compressedBytesDelta": compressed, "decompressedBytesDelta": decompressed, "compressionBytesPerSecond": round(rate, 1), "occupiedBytes": occupied, "pageSizeBytes": page_size, "activityDeltasAvailable": True, "sourceEvidence": deepcopy(after.get("sourceEvidence"))}, f"{_bytes_label(compressed)} compressed" if compressed else "No new compression")

    def _growth_finding(self, samples):
        if any(sample.get("processes") is None for sample in samples):
            return None
        process_sets = [sample.get("processes") or {} for sample in samples]
        common = set(process_sets[0])
        for rows in process_sets[1:]:
            common.intersection_update(rows)
        growing = []
        for key in common:
            observations = [rows[key] for rows in process_sets]
            values = [int(row.get("rssBytes") or 0) for row in observations]
            initial, middle, final = values[0], values[len(values) // 2], values[-1]
            growth = final - initial
            growth_percent = growth / max(initial, 1) * 100.0
            material = growth >= max(PROCESS_GROWTH_MIN_BYTES, initial * PROCESS_GROWTH_MIN_PERCENT / 100.0)
            trend_supported = middle >= initial + max(0, growth) * 0.15
            if material and final >= PROCESS_GROWTH_MIN_FINAL_BYTES and trend_supported:
                growing.append({"pid": observations[-1]["pid"], "name": observations[-1]["name"], "initialBytes": initial, "finalBytes": final, "growthBytes": growth, "growthPercent": round(growth_percent, 1), "samples": len(observations)})
        growing.sort(key=lambda row: (-row["growthBytes"], row["pid"]))
        growing = growing[:5]
        if growing:
            leader = growing[0]
            summary = f"{leader['name']} grew {_bytes_label(leader['growthBytes'])}; repeat the test before suspecting a leak."
            display_value = f"{leader['name']}: +{_bytes_label(leader['growthBytes'])}"
            status = "attention"
        else:
            summary, display_value, status = "No process crossed the material growth threshold during this bounded sample.", "No unusual growth", "healthy"
        return self._finding("process-growth", "Process growth", status, summary, {"items": growing, "minimumGrowthBytes": PROCESS_GROWTH_MIN_BYTES, "minimumGrowthPercent": PROCESS_GROWTH_MIN_PERCENT, "minimumFinalBytes": PROCESS_GROWTH_MIN_FINAL_BYTES, "claimBoundary": "Unusual growth is evidence to recheck, not a leak diagnosis.", "sourceEvidence": deepcopy(samples[-1].get("processSource"))}, display_value)

    def _disk_finding(self, final):
        disk = final.get("disk")
        if not disk:
            return None
        total = int(disk.get("totalBytes") or 0)
        free = int(disk.get("freeBytes") or 0)
        if total <= 0:
            return None
        free_percent = free / total * 100.0
        status = "critical" if free < 5 * GIB or free_percent < 3.0 else "attention" if free < 15 * GIB or free_percent < 8.0 else "healthy"
        return self._finding("swap-disk", "Swap storage", status, f"{_bytes_label(free)} free on the volume used by swap.", {"path": disk.get("path"), "freeBytes": free, "totalBytes": total, "freePercent": round(free_percent, 1), "scope": "local-volume-capacity", "sourceEvidence": deepcopy(disk.get("sourceEvidence"))}, f"{_bytes_label(free)} free")

    @staticmethod
    def _verdict(findings):
        statuses = {finding.get("status") for finding in findings}
        if "critical" in statuses:
            return "critical"
        if "attention" in statuses:
            return "attention"
        return "healthy"

    @staticmethod
    def _recommendations(findings, verdict):
        by_id = {finding["id"]: finding for finding in findings}
        recommendations = []
        if by_id.get("swap-disk", {}).get("status") == "critical":
            recommendations.append("Free local storage before relying on additional swap capacity.")
        if by_id.get("pressure", {}).get("status") == "critical":
            recommendations.append("Inspect the largest active apps and close only work you recognize and can safely stop.")
        if by_id.get("swap", {}).get("status") in {"attention", "critical"}:
            recommendations.append("Reduce active memory demand and rerun diagnostics to confirm swap-out has settled.")
        if by_id.get("process-growth", {}).get("status") == "attention":
            recommendations.append("Rerun diagnostics; sustained growth across runs is stronger evidence than one sample.")
        if not recommendations and verdict == "healthy":
            recommendations.append("No immediate memory action is indicated by this bounded sample.")
        if any(finding.get("stale") for finding in findings):
            recommendations.append("Retry the retained checks to refresh their measured source evidence.")
        return recommendations[:4]

    @staticmethod
    def _report_text(payload):
        lines = ["Activity Monitor Memory Diagnostics", f"Observed: {payload['finishedAt']}", f"Verdict: {payload['statusLabel']}", f"Sample: {payload['durationSeconds']:.1f} seconds", ""]
        for finding in payload["findings"]:
            freshness = "RETAINED" if finding.get("stale") else finding["status"].upper()
            lines.append(f"[{freshness}] {finding['label']}: {finding['summary']}")
        if payload.get("recommendations"):
            lines.extend(["", "Recommendations:"])
            lines.extend(f"- {item}" for item in payload["recommendations"])
        lines.extend(["", "Boundary: local read-only; no processes or workloads were changed."])
        return "\n".join(lines)

    def _busy_payload(self):
        return {"ok": False, "schemaVersion": SCHEMA_VERSION, "code": "diagnostic_in_progress", "verdict": "attention", "statusLabel": "Sampling", "summary": "A memory diagnostic is already sampling.", "sampleSeconds": self.sample_seconds, "retryable": False, "boundary": dict(READ_ONLY_BOUNDARY)}

    @staticmethod
    def _sample_error(samples, source_key, identifier, label):
        failures = []
        attempt_limit = 0
        for sample in samples:
            error = (sample.get("failures") or {}).get(source_key)
            if not error:
                continue
            failures.extend(deepcopy(error.get("failedSources") or []))
            attempt_limit = max(attempt_limit, int(error.get("attemptLimit") or 0))
        if not failures:
            failures.append({"source": f"{source_key}.derived", "code": "incomplete_sample", "attempt": 1})
        return {"metric": identifier, "label": label, "code": "source_chain_failed", "attemptLimit": attempt_limit or 1, "failedSources": MemoryDiagnosticsService._dedupe_failures(failures), "retryable": True}

    def _retain_or_error(self, identifier, error, finished):
        with self._state_lock:
            prior = deepcopy(self._last_valid_findings.get(identifier))
        if not prior:
            return None
        observed = prior.get("observedAt") or "an earlier sample"
        prior.update({"stale": True, "freshness": "retained-last-valid", "staleSince": _utc_iso(finished), "retryFailures": deepcopy(error.get("failedSources") or []), "summary": f"Retained measurement from {observed}: {prior['summary']}", "displayValue": f"{prior['displayValue']} · retained"})
        return prior

    @staticmethod
    def _selected_sources(samples):
        final = samples[-1]
        return {
            "pressure": deepcopy((final.get("pressure") or {}).get("sourceEvidence")),
            "swap": deepcopy((final.get("paging") or {}).get("sourceEvidence")),
            "compressor": deepcopy((final.get("compressor") or {}).get("sourceEvidence")),
            "process-growth": deepcopy(final.get("processSource")),
            "swap-disk": deepcopy((final.get("disk") or {}).get("sourceEvidence")),
        }

    def run(self):
        if not self._run_lock.acquire(blocking=False):
            return self._busy_payload()
        try:
            started = float(self._clock())
            samples = [self._capture()]
            interval = self.sample_seconds / 2.0
            for _ in range(2):
                self._sleep(interval)
                samples.append(self._capture())
            finished = float(self._clock())
            elapsed = max(finished - started, self.sample_seconds, 0.001)
            built = [
                ("pressure", "Pressure", "pressure", self._pressure_finding(samples[-1])),
                ("swap", "Swap activity", "paging", self._swap_finding(samples[0], samples[-1], elapsed)),
                ("compressor", "Compression", "compression", self._compressor_finding(samples[0], samples[-1], elapsed)),
                ("process-growth", "Process growth", "process", self._growth_finding(samples)),
                ("swap-disk", "Swap storage", "swap-storage", self._disk_finding(samples[-1])),
            ]
            findings, errors = [], []
            retained_count = 0
            observed_at = _utc_iso(finished)
            for identifier, label, source_key, finding in built:
                if finding is not None:
                    finding["observedAt"] = observed_at
                    finding["freshness"] = "fresh"
                    with self._state_lock:
                        self._last_valid_findings[identifier] = deepcopy(finding)
                    findings.append(finding)
                    continue
                error = self._sample_error(samples, source_key, identifier, label)
                retained = self._retain_or_error(identifier, error, finished)
                if retained is not None:
                    retained_count += 1
                    findings.append(retained)
                else:
                    errors.append(error)
            sources = self._selected_sources(samples)
            fallbacks = [identifier for identifier, source in sources.items() if source and source.get("usedFallback")]
            complete = not errors and len(findings) == 5
            verdict = self._verdict(findings) if findings else "attention"
            if errors:
                summary, status_label = self._failure_summary(errors), "Retry needed"
            elif retained_count:
                summary = f"Showing {retained_count} time-stamped retained measurement{'s' if retained_count != 1 else ''} while its sources await retry."
                status_label = f"{verdict.title()} · retained"
            else:
                summary = {"healthy": "No immediate memory issue was detected during this bounded sample.", "attention": "One or more measured checks deserve attention; no automatic action was taken.", "critical": "A measured memory or swap-capacity risk needs attention; no automatic action was taken."}[verdict]
                status_label = verdict.title()
            payload = {
                "ok": complete, "schemaVersion": SCHEMA_VERSION, "code": None if complete else "memory_source_chain_failed", "verdict": verdict, "statusLabel": status_label,
                "summary": summary, "startedAt": _utc_iso(started), "finishedAt": observed_at, "durationSeconds": round(elapsed, 2), "sampleSeconds": self.sample_seconds,
                "sampleCount": len(samples), "findings": findings, "errors": errors, "retryable": bool(errors or retained_count), "actionLabel": "Retry", "retainedCount": retained_count,
                "sources": sources, "fallbacksUsed": fallbacks, "recommendations": self._recommendations(findings, verdict), "boundary": dict(READ_ONLY_BOUNDARY),
            }
            if complete:
                payload["reportText"] = self._report_text(payload)
            return payload
        except Exception as error:
            code = self._error_code(error)
            return {
                "ok": False, "schemaVersion": SCHEMA_VERSION, "code": "diagnostic_internal_error", "verdict": "attention", "statusLabel": "Retry needed",
                "summary": f"Memory diagnostic orchestration failed with code {code}; measured values were not inferred.",
                "errors": [{"metric": "diagnostic", "label": "Memory diagnostics", "code": code, "attemptLimit": 1, "failedSources": [{"source": "diagnostic.orchestrator", "code": code, "attempt": 1}], "retryable": True}],
                "findings": [], "retryable": True, "actionLabel": "Retry", "sampleSeconds": self.sample_seconds, "boundary": dict(READ_ONLY_BOUNDARY),
            }
        finally:
            self._run_lock.release()
