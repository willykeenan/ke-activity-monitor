"""Read-only, fail-soft PowerSwarm run and process discovery.

The Activity Monitor never launches, resumes, cancels, or otherwise controls a
PowerSwarm run.  It reads the same durable run ledger used by the PowerSwarm
viewer and treats recorded completion separately from live PID observation.
"""

from __future__ import annotations

import copy
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

import psutil


SCHEMA_VERSION = "ke.activity-monitor-powerswarm.v1"
RUN_ID_RE = re.compile(r"^director_swarm_run_[0-9a-f]{20}$")
WORKER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
THREAD_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
RFC3339_TIMESTAMP_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<zone>Z|(?P<offset_sign>[+-])(?P<offset_hour>\d{2}):(?P<offset_minute>\d{2}))$",
    re.IGNORECASE,
)
TERMINAL_RUN_STATES = frozenset({"review-ready", "completed", "failed", "cancelled"})
VERIFIED_WORKER_STATES = frozenset({"verified", "review-ready", "succeeded", "completed"})
FAILED_WORKER_STATES = frozenset({"failed", "cancelled"})
QUEUED_WORKER_STATES = frozenset({"queued", "not-started", "worktree-ready"})
NESTED_CONTRACT = "ke.director.powerswarm-central-recursion.v1"
MAX_RUN_BYTES = 8 * 1024 * 1024
MAX_NESTED_BYTES = 4 * 1024 * 1024
MAX_BINDING_BYTES = 1024 * 1024
MAX_RECENT_RUNS = 12
MAX_SCAN_ENTRIES = 512
MAX_RECORDS = 64
MAX_TARGETS_PER_RUN = 128
MAX_ATTEMPTS_PER_STAGE = 32
MAX_ATTEMPTS_PER_WORKER = 64
MAX_NESTED_BRANCHES = 64
MAX_NESTED_LEAVES = 128
MAX_RETURNED_PROCESSES = 256
MAX_RECORD_CACHE_ENTRIES = 64
MAX_RECORD_CACHE_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_CACHE_ENTRIES = 16
MAX_SNAPSHOT_CACHE_BYTES = 8 * 1024 * 1024
MAX_LAST_GOOD_CACHE_ENTRIES = 16
MAX_LAST_GOOD_CACHE_BYTES = 8 * 1024 * 1024
PID_START_TOLERANCE_SECONDS = 1.0

RUN_STATES = frozenset(
    {
        "planned",
        "preflight",
        "worktree-ready",
        "coordinator-starting",
        "admitted-waiting-for-worker",
        "worker-live",
        "speed-dev",
        "bug-sweep",
        "review-ready",
        "queued",
        "running",
        "active",
        "checkpoint",
        "verified",
        "succeeded",
        "completed",
        "failed",
        "cancelled",
        "stale",
        "no-runs",
        "unavailable",
        "unknown",
    }
)
WORKER_STATES = RUN_STATES | frozenset({"not-started", "starting", "timed-out", "skipped"})
ATTEMPT_STATES = frozenset(
    {
        "not-started",
        "queued",
        "starting",
        "running",
        "succeeded",
        "completed",
        "failed",
        "cancelled",
        "timed-out",
        "killed",
        "skipped",
        "stale",
    }
)
CHECK_STATES = frozenset(
    {"not-started", "queued", "running", "succeeded", "completed", "failed", "cancelled", "timed-out", "skipped"}
)
TOOL_STATES = frozenset(
    {"not-started", "queued", "starting", "running", "active", "idle", "succeeded", "completed", "failed", "cancelled", "unavailable"}
)
STAGE_STATES = frozenset({"speed-dev", "bug-sweep", "director", "unknown"})
RUNTIME_STATES = frozenset({"grok-build", "grok-code", "grokcode", "grok", "unknown"})
RUNTIME_PROVIDER_IDS = frozenset({"xai"})
RUNTIME_MODEL_IDS_BY_PROVIDER = {"xai": frozenset({"grok-4.6"})}
SIGNAL_STATES = frozenset(
    {"sighup", "sigint", "sigquit", "sigkill", "sigterm", "sigstop", "sigabrt", "sigalrm", "sigpipe"}
)
CURRENT_LIVENESS_STATES = frozenset(
    {
        "active",
        "running",
        "worker-live",
        "coordinator-starting",
        "admitted-waiting-for-worker",
        "speed-dev",
        "bug-sweep",
        "starting",
    }
)


class ObserverError(RuntimeError):
    """Internal observer failure carrying only a stable, path-free code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _timestamp_datetime(value: Any) -> Optional[datetime]:
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            numeric = float(value)
            if not math.isfinite(numeric):
                return None
            if abs(numeric) >= 100_000_000_000:
                numeric /= 1000.0
            return datetime.fromtimestamp(numeric, timezone.utc)
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip()
        match = RFC3339_TIMESTAMP_RE.fullmatch(text)
        if match is None:
            return None
        year = int(match.group("year"))
        if year < 1:
            return None
        fraction = match.group("fraction") or ""
        microsecond = int((fraction + "000000")[:6])
        zone = match.group("zone")
        if zone.upper() == "Z":
            parsed_zone = timezone.utc
        else:
            offset_hour = int(match.group("offset_hour"))
            offset_minute = int(match.group("offset_minute"))
            if offset_hour > 23 or offset_minute > 59:
                return None
            offset_sign = match.group("offset_sign")
            if offset_sign == "-" and offset_hour == 0 and offset_minute == 0:
                # RFC3339 -00:00 states that the local offset is unknown. It
                # cannot be normalized into a definite UTC instant.
                return None
            offset = offset_hour * 60 + offset_minute
            parsed_zone = timezone(timedelta(minutes=offset if offset_sign == "+" else -offset))
        parsed = datetime(
            year,
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            microsecond,
            tzinfo=parsed_zone,
        )
        return parsed.astimezone(timezone.utc)
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _epoch(value: Any) -> Optional[float]:
    parsed = _timestamp_datetime(value)
    return parsed.timestamp() if parsed is not None else None


def _canonical_timestamp(value: Any) -> Optional[str]:
    parsed = _timestamp_datetime(value)
    if parsed is None:
        return None
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _bounded(value: Any, limit: int = 300) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text else None


def _enum(value: Any, allowed: frozenset[str], default: Optional[str] = None) -> Optional[str]:
    if not isinstance(value, str):
        return default
    candidate = value.strip().lower()
    return candidate if candidate in allowed else default


def _safe_identifier(value: Any, limit: int = 128) -> Optional[str]:
    candidate = _bounded(value, limit)
    if not candidate or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0," + str(limit - 1) + r"}", candidate):
        return None
    return candidate


def _runtime_identity(runtime: Mapping[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Return only a registered provider/model pair from the run ledger."""

    provider_id = _enum(runtime.get("providerId"), RUNTIME_PROVIDER_IDS)
    if provider_id is None:
        return None, None
    model_id = _enum(
        runtime.get("modelId"),
        RUNTIME_MODEL_IDS_BY_PROVIDER.get(provider_id, frozenset()),
    )
    if model_id is None:
        return None, None
    return provider_id, model_id


def _integer(value: Any, *, minimum: int = -2_147_483_648, maximum: int = 2_147_483_647) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        candidate = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return candidate if minimum <= candidate <= maximum else None


def _stale_state(value: Any) -> str:
    candidate = _enum(value, WORKER_STATES, "unknown") or "unknown"
    return "stale" if candidate in CURRENT_LIVENESS_STATES else candidate


def _error_code(error: Any, fallback: str = "observer-read-failed") -> str:
    if isinstance(error, ObserverError):
        return error.code
    if isinstance(error, (json.JSONDecodeError, UnicodeError)):
        return "observer-json-invalid"
    if isinstance(error, (PermissionError, psutil.AccessDenied)):
        return "observer-access-denied"
    return fallback


def _descriptor_security_supported() -> bool:
    return bool(
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in getattr(os, "supports_dir_fd", set())
    )


def _directory_flags() -> int:
    if not _descriptor_security_supported():
        raise ObserverError("observer-platform-unsupported")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_owned_root(path: Path, code: str) -> Optional[int]:
    """Open a configured root without following links and bind it to one inode."""

    flags = _directory_flags()
    try:
        descriptor = os.open(os.fspath(path), flags)
    except FileNotFoundError:
        return None
    except (OSError, TypeError, NotImplementedError) as error:
        raise ObserverError(code) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ObserverError(code)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_owned_directory_at(parent_fd: int, name: str, code: str) -> int:
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except (OSError, TypeError, NotImplementedError) as error:
        raise ObserverError(code) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ObserverError(code)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_owned_regular_at(parent_fd: int, name: str, max_bytes: int, code: str) -> Tuple[int, os.stat_result]:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError as error:
        raise ObserverError(f"{code}-not-found") from error
    except (OSError, TypeError, NotImplementedError) as error:
        raise ObserverError(code) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ObserverError(code)
        if metadata.st_size < 2 or metadata.st_size > max_bytes:
            raise ObserverError(f"{code}-size")
        return descriptor, metadata
    except Exception:
        os.close(descriptor)
        raise


def _descriptor_identity(metadata: os.stat_result) -> Tuple[int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mtime_ns),
        int(metadata.st_size),
    )


def _read_json_descriptor(
    descriptor: int,
    metadata: os.stat_result,
    *,
    code: str,
) -> Dict[str, Any]:
    chunks: List[bytes] = []
    remaining = int(metadata.st_size)
    while remaining:
        chunk = os.read(descriptor, min(remaining, 256 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    after = os.fstat(descriptor)
    if remaining or _descriptor_identity(after) != _descriptor_identity(metadata):
        raise ObserverError(f"{code}-changed")
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ObserverError(f"{code}-json") from error
    if not isinstance(payload, dict):
        raise ObserverError(f"{code}-json")
    return payload


def _read_private_json_at(
    parent_fd: int,
    name: str,
    max_bytes: int,
    code: str,
) -> Tuple[Dict[str, Any], Tuple[int, int, int, int]]:
    descriptor, metadata = _open_owned_regular_at(parent_fd, name, max_bytes, code)
    try:
        try:
            payload = _read_json_descriptor(descriptor, metadata, code=code)
        except ObserverError:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise ObserverError(code) from error
        return payload, _descriptor_identity(metadata)
    finally:
        os.close(descriptor)


def _attempts_for(target: Dict[str, Any], stage_key: str) -> Tuple[List[Dict[str, Any]], bool]:
    """Merge the two durable attempt projections without double counting."""

    stages = target.get("stages") if isinstance(target.get("stages"), dict) else {}
    durable_stage = stages.get(stage_key) if isinstance(stages.get(stage_key), dict) else {}
    durable = durable_stage.get("attempts") if isinstance(durable_stage.get("attempts"), list) else []
    evidence_root = (
        target.get("stageEvidence") if isinstance(target.get("stageEvidence"), dict) else {}
    )
    primary = evidence_root.get(stage_key) if isinstance(evidence_root.get(stage_key), list) else []
    truncated = len(durable) > MAX_ATTEMPTS_PER_STAGE or len(primary) > MAX_ATTEMPTS_PER_STAGE
    merged: Dict[int, Dict[str, Any]] = {}
    for candidate in durable[:MAX_ATTEMPTS_PER_STAGE]:
        if not isinstance(candidate, dict):
            continue
        try:
            number = int(candidate.get("attempt") or 0)
        except (TypeError, ValueError):
            continue
        merged[number] = dict(candidate)
    for candidate in primary[:MAX_ATTEMPTS_PER_STAGE]:
        if not isinstance(candidate, dict):
            continue
        try:
            number = int(candidate.get("attempt") or 0)
        except (TypeError, ValueError):
            continue
        existing = merged.get(number, {})
        combined = {**existing, **candidate}
        if isinstance(existing.get("killCheck"), dict) or isinstance(candidate.get("killCheck"), dict):
            combined["killCheck"] = {
                **(existing.get("killCheck") or {}),
                **(candidate.get("killCheck") or {}),
            }
        merged[number] = combined
    ordered = [merged[number] for number in sorted(merged)]
    if len(ordered) > MAX_ATTEMPTS_PER_STAGE:
        truncated = True
        ordered = ordered[:MAX_ATTEMPTS_PER_STAGE]
    return ordered, truncated


def _all_attempts(target: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], bool]:
    attempts: List[Dict[str, Any]] = []
    truncated = False
    for stage_key, stage_label in (("speedDev", "speed-dev"), ("bugSweep", "bug-sweep")):
        stage_attempts, stage_truncated = _attempts_for(target, stage_key)
        truncated = truncated or stage_truncated
        for attempt in stage_attempts:
            attempts.append({**attempt, "stage": stage_label})
    attempts.sort(key=lambda item: (_epoch(item.get("startedAt") or item.get("endedAt")) or 0.0, int(item.get("attempt") or 0)))
    if len(attempts) > MAX_ATTEMPTS_PER_WORKER:
        truncated = True
        attempts = attempts[:MAX_ATTEMPTS_PER_WORKER]
    return attempts, truncated


def _limited_targets(record: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], bool]:
    raw = record.get("targets") if isinstance(record.get("targets"), list) else []
    return [item for item in raw[:MAX_TARGETS_PER_RUN] if isinstance(item, dict)], len(raw) > MAX_TARGETS_PER_RUN


def _truncation(**flags: bool) -> Dict[str, Any]:
    truth = {
        "scannedEntries": bool(flags.get("scannedEntries")),
        "records": bool(flags.get("records")),
        "targets": bool(flags.get("targets")),
        "attempts": bool(flags.get("attempts")),
        "nestedBranches": bool(flags.get("nestedBranches")),
        "nestedLeaves": bool(flags.get("nestedLeaves")),
        "processes": bool(flags.get("processes")),
    }
    truth["any"] = any(truth.values())
    truth["limits"] = {
        "scannedEntries": MAX_SCAN_ENTRIES,
        "records": MAX_RECORDS,
        "returnedRecords": MAX_RECENT_RUNS,
        "targetsPerRun": MAX_TARGETS_PER_RUN,
        "attemptsPerStage": MAX_ATTEMPTS_PER_STAGE,
        "attemptsPerWorker": MAX_ATTEMPTS_PER_WORKER,
        "nestedBranches": MAX_NESTED_BRANCHES,
        "nestedLeaves": MAX_NESTED_LEAVES,
        "processes": MAX_RETURNED_PROCESSES,
        "recordCacheEntries": MAX_RECORD_CACHE_ENTRIES,
        "recordCacheBytes": MAX_RECORD_CACHE_BYTES,
        "snapshotCacheEntries": MAX_SNAPSHOT_CACHE_ENTRIES,
        "snapshotCacheBytes": MAX_SNAPSHOT_CACHE_BYTES,
        "lastGoodCacheEntries": MAX_LAST_GOOD_CACHE_ENTRIES,
        "lastGoodCacheBytes": MAX_LAST_GOOD_CACHE_BYTES,
    }
    return truth


class PowerSwarmService:
    """Project a compact, read-only view from PowerSwarm's durable ledger."""

    def __init__(
        self,
        runs_root: Optional[os.PathLike[str] | str] = None,
        bindings_root: Optional[os.PathLike[str] | str] = None,
        process_probe: Optional[Callable[[int, float], bool]] = None,
        cache_seconds: float = 1.5,
    ) -> None:
        home = Path.home()
        self.runs_root = Path(
            runs_root
            or os.environ.get("POWERSWARM_RUNS_ROOT")
            or home / ".grokcode" / "director-swarm" / "runs"
        )
        self.bindings_root = Path(
            bindings_root
            or os.environ.get("POWERSWARM_BINDINGS_ROOT")
            or home / ".grokcode" / "powerswarm-codex" / "bindings"
        )
        self._process_probe = process_probe
        self._cache_seconds = max(0.0, float(cache_seconds))
        self._lock = threading.Lock()
        self._record_cache: OrderedDict[
            str, Tuple[Tuple[int, int, int, int], Dict[str, Any], int]
        ] = OrderedDict()
        self._record_cache_bytes = 0
        self._snapshot_cache: OrderedDict[str, Tuple[float, Dict[str, Any], int]] = OrderedDict()
        self._snapshot_cache_bytes = 0
        self._last_good: OrderedDict[str, Tuple[Dict[str, Any], int]] = OrderedDict()
        self._last_good_cache_bytes = 0

    @staticmethod
    def unavailable(error: Any, *, stale: bool = False) -> Dict[str, Any]:
        code = _error_code(error)
        return {
            "ok": False,
            "schemaVersion": SCHEMA_VERSION,
            "state": "unavailable",
            "installed": False,
            "stale": bool(stale),
            "error": code,
            "errorCode": code,
            "observedAt": _iso_now(),
            "selectedRun": None,
            "counts": {"total": 0, "live": 0, "queued": 0, "verified": 0, "failed": 0, "stale": 0},
            "workers": [],
            "hierarchy": None,
            "nested": {"state": "none", "logicalDepth": 1, "processSpawnDepth": 1},
            "recentRuns": [],
            "processes": [],
            "truncation": _truncation(),
            "privacy": {"mode": "metadata-only", "outputsRead": False, "mutations": False},
        }

    @staticmethod
    def _projection_size(payload: Dict[str, Any]) -> int:
        try:
            return len(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
            )
        except (TypeError, ValueError, OverflowError):
            return max(MAX_SNAPSHOT_CACHE_BYTES, MAX_LAST_GOOD_CACHE_BYTES) + 1

    def _cache_record(
        self,
        run_id: str,
        identity: Tuple[int, int, int, int],
        payload: Dict[str, Any],
    ) -> None:
        existing = self._record_cache.pop(run_id, None)
        if existing:
            self._record_cache_bytes -= existing[2]
        size = max(0, int(identity[3]))
        if size > MAX_RECORD_CACHE_BYTES:
            return
        self._record_cache[run_id] = (identity, copy.deepcopy(payload), size)
        self._record_cache_bytes += size
        while (
            len(self._record_cache) > MAX_RECORD_CACHE_ENTRIES
            or self._record_cache_bytes > MAX_RECORD_CACHE_BYTES
        ):
            _, (_, _, evicted_size) = self._record_cache.popitem(last=False)
            self._record_cache_bytes -= evicted_size

    def _cache_snapshot(self, key: str, observed_at: float, payload: Dict[str, Any]) -> None:
        existing = self._snapshot_cache.pop(key, None)
        if existing:
            self._snapshot_cache_bytes -= existing[2]
        size = self._projection_size(payload)
        if size > MAX_SNAPSHOT_CACHE_BYTES:
            return
        self._snapshot_cache[key] = (observed_at, copy.deepcopy(payload), size)
        self._snapshot_cache_bytes += size
        while (
            len(self._snapshot_cache) > MAX_SNAPSHOT_CACHE_ENTRIES
            or self._snapshot_cache_bytes > MAX_SNAPSHOT_CACHE_BYTES
        ):
            _, (_, _, evicted_size) = self._snapshot_cache.popitem(last=False)
            self._snapshot_cache_bytes -= evicted_size

    def _cache_last_good(self, key: str, payload: Dict[str, Any]) -> None:
        existing = self._last_good.pop(key, None)
        if existing:
            self._last_good_cache_bytes -= existing[1]
        size = self._projection_size(payload)
        if size > MAX_LAST_GOOD_CACHE_BYTES:
            return
        self._last_good[key] = (copy.deepcopy(payload), size)
        self._last_good_cache_bytes += size
        while (
            len(self._last_good) > MAX_LAST_GOOD_CACHE_ENTRIES
            or self._last_good_cache_bytes > MAX_LAST_GOOD_CACHE_BYTES
        ):
            _, (_, evicted_size) = self._last_good.popitem(last=False)
            self._last_good_cache_bytes -= evicted_size

    @staticmethod
    def stale_projection(snapshot: Dict[str, Any], error_code: str) -> Dict[str, Any]:
        """Return historical metadata with every current-liveness claim removed."""

        payload = copy.deepcopy(snapshot)
        payload.update(
            {
                "stale": True,
                "state": "stale",
                "error": error_code,
                "errorCode": error_code,
                "observedAt": _iso_now(),
                "processes": [],
            }
        )
        workers = payload.get("workers") if isinstance(payload.get("workers"), list) else []
        for worker in workers[:MAX_TARGETS_PER_RUN]:
            if not isinstance(worker, dict):
                continue
            worker["processAlive"] = False
            worker["pid"] = None
            worker["state"] = _stale_state(worker.get("state"))
            worker["recordedState"] = _stale_state(worker.get("recordedState"))
        payload["workers"] = workers[:MAX_TARGETS_PER_RUN]
        counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
        counts["live"] = 0
        counts["stale"] = sum(
            1 for worker in payload["workers"] if isinstance(worker, dict) and worker.get("state") == "stale"
        )
        payload["counts"] = counts
        selected = payload.get("selectedRun")
        if isinstance(selected, dict):
            selected["coordinatorAlive"] = False
            selected["coordinatorPid"] = None
            selected["state"] = _stale_state(selected.get("state"))
            # A stale snapshot cannot make a current provider/model claim.
            selected["providerId"] = None
            selected["modelId"] = None
        recent_runs = payload.get("recentRuns") if isinstance(payload.get("recentRuns"), list) else []
        for recent in recent_runs[:MAX_RECENT_RUNS]:
            if not isinstance(recent, dict):
                continue
            recent["coordinatorAlive"] = False
            recent["active"] = False
            recent["state"] = _stale_state(recent.get("state"))
        payload["recentRuns"] = recent_runs[:MAX_RECENT_RUNS]

        def clear_hierarchy_liveness(node: Any, depth: int = 0) -> Optional[Dict[str, Any]]:
            if not isinstance(node, dict) or depth > 3:
                return None
            node.pop("pid", None)
            node.pop("coordinatorPid", None)
            if "processAlive" in node:
                node["processAlive"] = False
            if "state" in node:
                node["state"] = _stale_state(node.get("state"))
            children = node.get("children") if isinstance(node.get("children"), list) else []
            node["children"] = [
                child
                for child in (
                    clear_hierarchy_liveness(item, depth + 1)
                    for item in children[:MAX_NESTED_LEAVES]
                )
                if child is not None
            ]
            return node

        payload["hierarchy"] = clear_hierarchy_liveness(payload.get("hierarchy"))
        return payload

    def _probe(self, pid: Any, *, started_at: Any = None, ended_at: Any = None) -> bool:
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or ended_at:
            return False
        expected_start = _epoch(started_at)
        if expected_start is None:
            # PID liveness is accepted only when it can be joined to the exact
            # durable process-creation identity. A bare live PID is ambiguous.
            return False
        if self._process_probe is not None:
            try:
                return bool(self._process_probe(pid, expected_start))
            except Exception:
                return False
        try:
            process = psutil.Process(pid)
            if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
                return False
            # PowerSwarm records start time at launch. A one-second envelope
            # admits timestamp serialization jitter while rejecting both older
            # and newer processes that merely recycled the recorded PID.
            return abs(float(process.create_time()) - expected_start) <= PID_START_TOLERANCE_SECONDS
        except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError):
            return False

    def _record_from_run_fd(self, run_id: str, run_fd: int) -> Tuple[Dict[str, Any], Tuple[int, int, int, int]]:
        descriptor, metadata = _open_owned_regular_at(run_fd, "run.json", MAX_RUN_BYTES, "observer-run-ledger")
        identity = _descriptor_identity(metadata)
        cached = self._record_cache.get(run_id)
        try:
            if cached and cached[0] == identity:
                self._record_cache.move_to_end(run_id)
                return copy.deepcopy(cached[1]), identity
            payload = _read_json_descriptor(descriptor, metadata, code="observer-run-ledger")
        finally:
            os.close(descriptor)
        if payload.get("runId") != run_id:
            raise ObserverError("observer-run-identity-mismatch")
        self._cache_record(run_id, identity, payload)
        return payload, identity

    def _scan_records(self) -> Tuple[List[Dict[str, Any]], int, bool, Dict[str, bool]]:
        root_fd = _open_owned_root(self.runs_root, "observer-runs-root-untrusted")
        if root_fd is None:
            return [], 0, False, {"scannedEntries": False, "records": False}
        records: List[Dict[str, Any]] = []
        invalid = 0
        candidates: List[Tuple[int, str]] = []
        scanned_truncated = False
        records_truncated = False
        try:
            try:
                with os.scandir(root_fd) as entries:
                    for index, entry in enumerate(entries):
                        if index >= MAX_SCAN_ENTRIES:
                            scanned_truncated = True
                            break
                        if RUN_ID_RE.fullmatch(entry.name):
                            try:
                                hint = entry.stat(follow_symlinks=False)
                                modified = int(hint.st_mtime_ns) if stat.S_ISDIR(hint.st_mode) else 0
                            except OSError:
                                modified = 0
                            candidates.append((modified, entry.name))
            except (OSError, TypeError, NotImplementedError) as error:
                raise ObserverError("observer-runs-scan-failed") from error

            # Directory mtime is only a bounded selection hint; every chosen
            # directory and ledger is still reopened and verified by descriptor.
            candidates.sort(key=lambda item: (-item[0], item[1]))
            for index, (_, name) in enumerate(candidates):
                if index >= MAX_RECORDS:
                    records_truncated = True
                    break
                run_fd: Optional[int] = None
                try:
                    run_fd = _open_owned_directory_at(root_fd, name, "observer-run-directory-untrusted")
                    record, identity = self._record_from_run_fd(name, run_fd)
                except (OSError, ObserverError, UnicodeError, json.JSONDecodeError):
                    invalid += 1
                    if run_fd is not None:
                        os.close(run_fd)
                    continue
                coordinator = record.get("coordinator") if isinstance(record.get("coordinator"), dict) else {}
                coordinator_pid = coordinator.get("pid")
                state = _enum(record.get("status"), RUN_STATES, "unknown") or "unknown"
                coordinator_alive = state in CURRENT_LIVENESS_STATES and self._probe(
                    coordinator_pid,
                    started_at=coordinator.get("startedAt"),
                )
                records.append(
                    {
                        "record": record,
                        "runFd": run_fd,
                        "identity": identity,
                        "coordinatorAlive": coordinator_alive,
                        "active": coordinator_alive,
                        "sortEpoch": _epoch(record.get("updatedAt")) or (identity[2] / 1_000_000_000.0),
                    }
                )
            records.sort(key=lambda item: item["sortEpoch"], reverse=True)
            return records, invalid, True, {
                "scannedEntries": scanned_truncated,
                "records": records_truncated,
            }
        except Exception:
            for item in records:
                try:
                    os.close(item["runFd"])
                except OSError:
                    pass
            raise
        finally:
            os.close(root_fd)

    def _binding_from_root_fd(self, root_fd: int, run_id: str) -> Dict[str, Any]:
        binding, _ = _read_private_json_at(
            root_fd,
            f"{run_id}.json",
            MAX_BINDING_BYTES,
            "observer-binding",
        )
        return binding

    def _binding(self, run_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        root_fd: Optional[int] = None
        try:
            root_fd = _open_owned_root(self.bindings_root, "observer-bindings-root-untrusted")
            if root_fd is None:
                return None, None
            binding = self._binding_from_root_fd(root_fd, run_id)
        except Exception as error:
            code = _error_code(error, "observer-binding-invalid")
            if code == "observer-binding-not-found":
                return None, None
            return None, code
        finally:
            if root_fd is not None:
                os.close(root_fd)
        parent = binding.get("parent") if isinstance(binding.get("parent"), dict) else {}
        thread_id = parent.get("threadId")
        if (
            binding.get("runId") != run_id
            or parent.get("host") != "codex"
            or not isinstance(thread_id, str)
            or not THREAD_ID_RE.fullmatch(thread_id)
        ):
            return None, "observer-binding-invalid"
        return {
            "host": "codex",
            "threadId": thread_id,
            "turnId": _safe_identifier(parent.get("turnId"), 80),
            "title": _bounded(parent.get("title"), 160) or "Codex parent task",
            "agentName": _bounded(parent.get("agentName"), 100) or "Codex parent",
            "agentRole": _safe_identifier(parent.get("agentRole"), 80) or "owner",
            "exact": binding.get("confidence") == "exact",
            "source": _safe_identifier(binding.get("source"), 100) or "binding-ledger",
            "codexUrl": f"codex://threads/{thread_id}",
        }, None

    def _worker(self, target: Dict[str, Any], run_state: str) -> Dict[str, Any]:
        attempts, attempts_truncated = _all_attempts(target)
        live_attempt: Optional[Dict[str, Any]] = None
        for attempt in reversed(attempts):
            if str(attempt.get("status") or "") != "running":
                continue
            if self._probe(
                attempt.get("pid"),
                started_at=attempt.get("startedAt"),
                ended_at=attempt.get("endedAt"),
            ):
                live_attempt = attempt
                break
        latest = live_attempt or (attempts[-1] if attempts else None)
        pid = latest.get("pid") if isinstance(latest, dict) else None
        alive = bool(live_attempt)
        state = _enum(target.get("status"), WORKER_STATES, "queued") or "queued"
        terminal_before_start = (
            not attempts and run_state in {"failed", "cancelled"} and state in QUEUED_WORKER_STATES
        )
        if terminal_before_start:
            state = run_state
        elif latest:
            latest_state = _enum(latest.get("status"), ATTEMPT_STATES, state) or state
            kill_check = latest.get("killCheck") if isinstance(latest.get("killCheck"), dict) else {}
            if latest_state == "running":
                state = "running" if alive else "stale"
            elif _enum(kill_check.get("status"), CHECK_STATES) == "succeeded":
                state = "verified"
            elif latest_state:
                state = latest_state
        tool_burst = latest.get("toolBurst") if isinstance((latest or {}).get("toolBurst"), dict) else {}
        telemetry = tool_burst.get("telemetry") if isinstance(tool_burst.get("telemetry"), dict) else {}
        target_stages = target.get("stages") if isinstance(target.get("stages"), dict) else {}
        bug_sweep = target_stages.get("bugSweep") if isinstance(target_stages.get("bugSweep"), dict) else {}
        stage = _enum((latest or {}).get("stage"), STAGE_STATES)
        if stage is None:
            stage = (
                "bug-sweep"
                if _enum(bug_sweep.get("status"), WORKER_STATES, "not-started") != "not-started"
                else "speed-dev"
            )
        return {
            "id": _safe_identifier(target.get("targetId"), 128) or "unknown-worker",
            "aim": _bounded(target.get("aim"), 500),
            "state": state,
            "recordedState": _enum(target.get("status"), WORKER_STATES),
            "terminalReasonCode": (
                f"run-{run_state}-before-worker-admission"
                if terminal_before_start
                else "worker-terminal-reason-recorded"
                if target.get("terminalReason")
                else None
            ),
            "stage": stage,
            "attempt": _integer((latest or {}).get("attempt"), minimum=0, maximum=1_000_000) or 0,
            "attemptCount": len(attempts),
            "attemptsTruncated": attempts_truncated,
            "pid": pid if isinstance(pid, int) and pid > 0 else None,
            "processAlive": alive,
            "startedAt": _canonical_timestamp((latest or {}).get("startedAt")),
            "endedAt": _canonical_timestamp((latest or {}).get("endedAt")),
            "branch": _bounded(target.get("branch"), 300),
            "baseRevision": _bounded(target.get("baseRevision"), 80),
            "headRevision": _bounded(target.get("headRevision"), 80),
            "killCheck": _enum(((latest or {}).get("killCheck") or {}).get("status"), CHECK_STATES),
            "toolState": _enum(telemetry.get("status") or tool_burst.get("status"), TOOL_STATES),
            "errorCode": "worker-attempt-failed" if (latest or {}).get("error") else None,
        }

    @staticmethod
    def _counts(workers: Iterable[Dict[str, Any]]) -> Dict[str, int]:
        result = {"total": 0, "live": 0, "queued": 0, "verified": 0, "failed": 0, "stale": 0}
        for worker in workers:
            result["total"] += 1
            state = str(worker.get("state") or "unknown")
            if worker.get("processAlive") is True:
                result["live"] += 1
            if state in QUEUED_WORKER_STATES:
                result["queued"] += 1
            if state in VERIFIED_WORKER_STATES:
                result["verified"] += 1
            if state in FAILED_WORKER_STATES:
                result["failed"] += 1
            if state == "stale":
                result["stale"] += 1
        return result

    @staticmethod
    def _aggregate_state(children: List[Dict[str, Any]]) -> str:
        if any(child.get("processAlive") is True for child in children):
            return "running"
        states = {str(child.get("state") or "unknown") for child in children}
        if states and states.issubset(VERIFIED_WORKER_STATES):
            return "verified"
        if states & FAILED_WORKER_STATES:
            return "failed"
        if states and states.issubset(QUEUED_WORKER_STATES):
            return "queued"
        if "stale" in states:
            return "stale"
        return "mixed" if states else "empty"

    def _hierarchy(
        self,
        record: Dict[str, Any],
        run_fd: int,
        workers: List[Dict[str, Any]],
        targets_truncated: bool,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        direct = [
            {"kind": "worker", "id": worker["id"], "state": worker["state"], "processAlive": worker["processAlive"]}
            for worker in workers
        ]
        flat = {"kind": "run", "id": record["runId"], "children": direct}
        try:
            plan = self._read_nested_from_run_fd(run_fd)
            if targets_truncated:
                return flat, {
                    "state": "truncated",
                    "logicalDepth": 1,
                    "processSpawnDepth": 1,
                    "errorCode": "observer-nested-targets-truncated",
                    "truncatedBranches": False,
                    "truncatedLeaves": True,
                }
            if plan.get("contract") != NESTED_CONTRACT:
                raise ObserverError("observer-nested-contract-invalid")
            topology = plan.get("topology") if isinstance(plan.get("topology"), dict) else {}
            if (
                int(topology.get("logicalDepth") or 0) < 2
                or int(topology.get("processSpawnDepth") or 0) != 1
                or topology.get("rootOnlyProcessSpawn") is not True
            ):
                raise ObserverError("observer-nested-topology-invalid")
            run_plan = record.get("plan") if isinstance(record.get("plan"), dict) else {}
            execution = plan.get("executionPlan") if isinstance(plan.get("executionPlan"), dict) else {}
            if execution.get("planId") != run_plan.get("planId"):
                raise ObserverError("observer-nested-plan-mismatch")
            by_id = {worker["id"]: worker for worker in workers}
            seen: set[str] = set()
            branches: List[Dict[str, Any]] = []
            subdirectors = plan.get("subdirectors")
            if not isinstance(subdirectors, list) or not subdirectors:
                raise ObserverError("observer-nested-branches-invalid")
            if len(subdirectors) > MAX_NESTED_BRANCHES:
                return flat, {
                    "state": "truncated",
                    "logicalDepth": 1,
                    "processSpawnDepth": 1,
                    "errorCode": "observer-nested-branches-truncated",
                    "truncatedBranches": True,
                    "truncatedLeaves": False,
                }
            leaf_count = 0
            for proposal in subdirectors:
                if not isinstance(proposal, dict):
                    raise ObserverError("observer-nested-branch-invalid")
                identifier = proposal.get("subdirectorId")
                target_ids = proposal.get("targetIds")
                if not isinstance(identifier, str) or not WORKER_ID_RE.fullmatch(identifier):
                    raise ObserverError("observer-nested-branch-invalid")
                if not isinstance(target_ids, list) or not target_ids:
                    raise ObserverError("observer-nested-leaves-invalid")
                leaf_count += len(target_ids)
                if leaf_count > MAX_NESTED_LEAVES:
                    return flat, {
                        "state": "truncated",
                        "logicalDepth": 1,
                        "processSpawnDepth": 1,
                        "errorCode": "observer-nested-leaves-truncated",
                        "truncatedBranches": False,
                        "truncatedLeaves": True,
                    }
                children: List[Dict[str, Any]] = []
                for target_id in target_ids:
                    if not isinstance(target_id, str) or target_id in seen or target_id not in by_id:
                        raise ObserverError("observer-nested-ownership-invalid")
                    seen.add(target_id)
                    worker = by_id[target_id]
                    children.append(
                        {"kind": "worker", "id": target_id, "state": worker["state"], "processAlive": worker["processAlive"]}
                    )
                branches.append(
                    {
                        "kind": "subdirector",
                        "id": identifier,
                        "aim": _bounded(proposal.get("aim"), 500),
                        "state": self._aggregate_state([by_id[target_id] for target_id in target_ids]),
                        "children": children,
                    }
                )
            if seen != set(by_id):
                raise ObserverError("observer-nested-ownership-invalid")
            return (
                {"kind": "run", "id": record["runId"], "children": branches},
                {
                    "state": "observed",
                    "logicalDepth": int(topology.get("logicalDepth")),
                    "processSpawnDepth": 1,
                    "rootOnlyProcessSpawn": True,
                    "planId": _bounded(plan.get("planId"), 100),
                    "subdirectorCount": len(branches),
                    "truncatedBranches": False,
                    "truncatedLeaves": False,
                },
            )
        except (ObserverError, TypeError, ValueError) as error:
            if isinstance(error, ObserverError) and error.code == "observer-nested-plan-not-found":
                return flat, {
                    "state": "none",
                    "logicalDepth": 1,
                    "processSpawnDepth": 1,
                    "truncatedBranches": False,
                    "truncatedLeaves": False,
                }
            return flat, {
                "state": "invalid",
                "logicalDepth": 1,
                "processSpawnDepth": 1,
                "errorCode": _error_code(error, "observer-nested-invalid"),
                "truncatedBranches": False,
                "truncatedLeaves": False,
            }

    @staticmethod
    def _read_nested_from_run_fd(run_fd: int) -> Dict[str, Any]:
        plan, _ = _read_private_json_at(
            run_fd,
            "nested-plan.json",
            MAX_NESTED_BYTES,
            "observer-nested-plan",
        )
        return plan

    def _recent_run(self, item: Dict[str, Any]) -> Dict[str, Any]:
        record = item["record"]
        plan = record.get("plan") if isinstance(record.get("plan"), dict) else {}
        targets, targets_truncated = _limited_targets(record)
        return {
            "id": record["runId"],
            "state": _enum(record.get("status"), RUN_STATES, "unknown") or "unknown",
            "updatedAt": _canonical_timestamp(record.get("updatedAt")),
            "coordinatorAlive": bool(item["coordinatorAlive"]),
            "active": bool(item["active"]),
            "workerCount": len(targets),
            "workersTruncated": targets_truncated,
            "objective": _bounded(record.get("objective") or plan.get("objective"), 160) or "PowerSwarm run",
        }

    def _live_processes(self, records: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], bool, bool, bool]:
        """Return exact live coordinator and worker PIDs across every active run."""

        processes: List[Dict[str, Any]] = []
        seen_pids: set[int] = set()
        truncated = False
        targets_truncated = False
        attempts_truncated = False

        def append_process(process: Dict[str, Any]) -> bool:
            nonlocal truncated
            if len(processes) >= MAX_RETURNED_PROCESSES:
                truncated = True
                return False
            processes.append(process)
            return True

        for item in records:
            if not item.get("active"):
                continue
            record = item["record"]
            run_id = record["runId"]
            run_state = _enum(record.get("status"), RUN_STATES, "unknown") or "unknown"
            coordinator = record.get("coordinator") if isinstance(record.get("coordinator"), dict) else {}
            coordinator_pid = coordinator.get("pid")
            if item.get("coordinatorAlive") and isinstance(coordinator_pid, int) and coordinator_pid > 0:
                if not append_process({
                        "pid": coordinator_pid,
                        "role": "coordinator",
                        "runId": run_id,
                        "workerId": None,
                        "label": "PowerSwarm coordinator",
                        "state": run_state,
                        "stage": "director",
                        "confidence": "run-ledger",
                    }):
                    break
                seen_pids.add(coordinator_pid)
            targets, record_targets_truncated = _limited_targets(record)
            targets_truncated = targets_truncated or record_targets_truncated
            for target in targets:
                worker = self._worker(target, run_state)
                attempts_truncated = attempts_truncated or bool(worker.get("attemptsTruncated"))
                pid = worker.get("pid")
                if not worker.get("processAlive") or not isinstance(pid, int) or pid <= 0 or pid in seen_pids:
                    continue
                if not append_process({
                        "pid": pid,
                        "role": "worker",
                        "runId": run_id,
                        "workerId": worker["id"],
                        "label": worker["id"],
                        "state": worker["state"],
                        "stage": worker["stage"],
                        "confidence": "run-ledger",
                    }):
                    break
                seen_pids.add(pid)
            if truncated:
                break
        return processes, truncated, targets_truncated, attempts_truncated

    def _build_snapshot(self, run_id: Optional[str]) -> Dict[str, Any]:
        records: List[Dict[str, Any]] = []
        try:
            records, invalid, installed, scan_truncation = self._scan_records()
            if run_id:
                if not RUN_ID_RE.fullmatch(run_id):
                    raise ObserverError("observer-run-id-invalid")
                selected = next((item for item in records if item["record"].get("runId") == run_id), None)
                if selected is None:
                    raise ObserverError(
                        "observer-run-outside-limit" if scan_truncation["records"] else "observer-run-not-found"
                    )
            else:
                selected = next((item for item in records if item["active"]), None)
                if selected is None and records:
                    selected = records[0]
            if selected is None:
                payload = self.unavailable(ObserverError("observer-no-runs"))
                payload.update(
                    {
                        "ok": True,
                        "state": "no-runs",
                        "installed": installed,
                        "stale": False,
                        "error": None,
                        "errorCode": None,
                        "invalidRunCount": invalid,
                        "truncation": _truncation(**scan_truncation),
                    }
                )
                return payload

            record = selected["record"]
            run_state = _enum(record.get("status"), RUN_STATES, "unknown") or "unknown"
            targets, selected_targets_truncated = _limited_targets(record)
            workers = [self._worker(target, run_state) for target in targets]
            attempts_truncated = any(bool(worker.get("attemptsTruncated")) for worker in workers)
            counts = self._counts(workers)
            hierarchy, nested = self._hierarchy(
                record,
                selected["runFd"],
                workers,
                selected_targets_truncated,
            )
            plan = record.get("plan") if isinstance(record.get("plan"), dict) else {}
            product = plan.get("product") if isinstance(plan.get("product"), dict) else {}
            coordinator = record.get("coordinator") if isinstance(record.get("coordinator"), dict) else {}
            parent, parent_error = self._binding(record["runId"])
            coordinator_pid = coordinator.get("pid")
            processes, processes_truncated, live_targets_truncated, live_attempts_truncated = self._live_processes(records)
            top_state = (
                run_state
                if run_state in {"failed", "cancelled"}
                else "active"
                if counts["live"] or counts["queued"]
                else "checkpoint"
            )
            limits = record.get("limits") if isinstance(record.get("limits"), dict) else {}
            runtime = record.get("runtime") if isinstance(record.get("runtime"), dict) else {}
            provider_id, model_id = _runtime_identity(runtime)
            return {
                "ok": True,
                "schemaVersion": SCHEMA_VERSION,
                "state": top_state,
                "installed": installed,
                "stale": False,
                "error": None,
                "errorCode": None,
                "observedAt": _iso_now(),
                "generatedAt": _canonical_timestamp(record.get("updatedAt")),
                "selectedRun": {
                    "id": record["runId"],
                    "planId": _safe_identifier(plan.get("planId"), 100),
                    "objective": _bounded(record.get("objective") or plan.get("objective"), 1000) or "PowerSwarm run",
                    "product": _safe_identifier(product.get("productId"), 160),
                    "state": run_state,
                    "createdAt": _canonical_timestamp(record.get("createdAt")),
                    "updatedAt": _canonical_timestamp(record.get("updatedAt")),
                    "coordinatorPid": coordinator_pid if isinstance(coordinator_pid, int) and coordinator_pid > 0 else None,
                    "coordinatorAlive": bool(selected["coordinatorAlive"]),
                    "requestedWidth": _integer(limits.get("runConcurrency"), minimum=1, maximum=32_768),
                    "runtime": _enum(runtime.get("runtime"), RUNTIME_STATES, "grok-build") or "grok-build",
                    "providerId": provider_id,
                    "modelId": model_id,
                    "parent": parent,
                    "parentExact": bool(parent and parent.get("exact")),
                    "parentObserverCode": parent_error,
                },
                "counts": counts,
                "workers": workers,
                "hierarchy": hierarchy,
                "nested": nested,
                "recentRuns": [self._recent_run(item) for item in records[:MAX_RECENT_RUNS]],
                "invalidRunCount": invalid,
                "processes": processes,
                "truncation": _truncation(
                    scannedEntries=scan_truncation["scannedEntries"],
                    records=scan_truncation["records"] or len(records) > MAX_RECENT_RUNS,
                    targets=selected_targets_truncated or live_targets_truncated,
                    attempts=attempts_truncated or live_attempts_truncated,
                    nestedBranches=bool(nested.get("truncatedBranches")),
                    nestedLeaves=bool(nested.get("truncatedLeaves")),
                    processes=processes_truncated,
                ),
                "privacy": {"mode": "metadata-only", "outputsRead": False, "mutations": False},
            }
        finally:
            for item in records:
                try:
                    os.close(item["runFd"])
                except OSError:
                    pass

    def snapshot(self, run_id: Optional[str] = None, *, force: bool = False) -> Dict[str, Any]:
        key = run_id or "__auto__"
        now = time.monotonic()
        with self._lock:
            cached = self._snapshot_cache.get(key)
            if not force and cached and now - cached[0] < self._cache_seconds:
                self._snapshot_cache.move_to_end(key)
                return copy.deepcopy(cached[1])
            try:
                payload = self._build_snapshot(run_id)
            except Exception as error:
                code = _error_code(error)
                prior = self._last_good.get(key)
                if prior:
                    self._last_good.move_to_end(key)
                    payload = self.stale_projection(prior[0], code)
                else:
                    payload = self.unavailable(ObserverError(code), stale=True)
            if payload.get("ok") and not payload.get("stale"):
                self._cache_last_good(key, payload)
            self._cache_snapshot(key, now, payload)
            return payload

    @staticmethod
    def _attempt_detail(attempt: Dict[str, Any], probe: Callable[..., bool]) -> Dict[str, Any]:
        pid = attempt.get("pid")
        alive = str(attempt.get("status") or "") == "running" and probe(
            pid,
            started_at=attempt.get("startedAt"),
            ended_at=attempt.get("endedAt"),
        )
        kill = attempt.get("killCheck") if isinstance(attempt.get("killCheck"), dict) else {}
        tool = attempt.get("toolBurst") if isinstance(attempt.get("toolBurst"), dict) else {}
        telemetry = tool.get("telemetry") if isinstance(tool.get("telemetry"), dict) else {}
        return {
            "stage": _enum(attempt.get("stage"), STAGE_STATES, "unknown") or "unknown",
            "attempt": _integer(attempt.get("attempt"), minimum=0, maximum=1_000_000) or 0,
            "status": _enum(attempt.get("status"), ATTEMPT_STATES),
            "startedAt": _canonical_timestamp(attempt.get("startedAt")),
            "endedAt": _canonical_timestamp(attempt.get("endedAt")),
            "pid": pid if isinstance(pid, int) and pid > 0 else None,
            "processAlive": bool(alive),
            "exitCode": _integer(attempt.get("exitCode"), minimum=-255, maximum=255),
            "signal": _enum(attempt.get("signal"), SIGNAL_STATES),
            "errorCode": "worker-attempt-failed" if attempt.get("error") else None,
            "killCheck": {
                "status": _enum(kill.get("status"), CHECK_STATES),
                "exitCode": _integer(kill.get("exitCode"), minimum=-255, maximum=255),
                "startedAt": _canonical_timestamp(kill.get("startedAt")),
                "endedAt": _canonical_timestamp(kill.get("endedAt")),
                "errorCode": "kill-check-failed" if kill.get("error") else None,
            }
            if kill
            else None,
            "toolActivity": {
                "status": _enum(tool.get("status"), TOOL_STATES),
                "telemetryStatus": _enum(telemetry.get("status"), TOOL_STATES),
                "callCount": _integer(
                    (telemetry.get("metrics") or {}).get("callCount"), minimum=0, maximum=1_000_000_000
                )
                if isinstance(telemetry.get("metrics"), dict)
                else None,
            },
        }

    def worker_detail(self, run_id: str, worker_id: str) -> Dict[str, Any]:
        if not RUN_ID_RE.fullmatch(str(run_id or "")):
            return {"ok": False, "schemaVersion": SCHEMA_VERSION, "error": "observer-run-id-invalid", "errorCode": "observer-run-id-invalid"}
        if not WORKER_ID_RE.fullmatch(str(worker_id or "")):
            return {"ok": False, "schemaVersion": SCHEMA_VERSION, "error": "observer-worker-id-invalid", "errorCode": "observer-worker-id-invalid"}
        with self._lock:
            records: List[Dict[str, Any]] = []
            try:
                records, _, _, scan_truncation = self._scan_records()
                selected = next((item for item in records if item["record"].get("runId") == run_id), None)
                if selected is None:
                    raise ObserverError(
                        "observer-run-outside-limit" if scan_truncation["records"] else "observer-run-not-found"
                    )
                record = selected["record"]
                targets, targets_truncated = _limited_targets(record)
                target = next(
                    (
                        item
                        for item in targets
                        if item.get("targetId") == worker_id
                    ),
                    None,
                )
                if target is None:
                    raise ObserverError(
                        "observer-worker-outside-limit" if targets_truncated else "observer-worker-not-found"
                    )
                run_state = _enum(record.get("status"), RUN_STATES, "unknown") or "unknown"
                summary = self._worker(target, run_state)
                raw_attempts, attempts_truncated = _all_attempts(target)
                attempts = [self._attempt_detail(attempt, self._probe) for attempt in raw_attempts]
                return {
                    "ok": True,
                    "schemaVersion": SCHEMA_VERSION,
                    "kind": "powerswarm-worker-detail",
                    "observedAt": _iso_now(),
                    "run": {
                        "id": run_id,
                        "state": run_state,
                        "objective": _bounded((record.get("plan") or {}).get("objective"), 1000) or "PowerSwarm run",
                    },
                    "worker": summary,
                    "attempts": attempts,
                    "truncation": _truncation(
                        scannedEntries=scan_truncation["scannedEntries"],
                        records=scan_truncation["records"],
                        targets=targets_truncated,
                        attempts=attempts_truncated,
                    ),
                    "privacy": {"mode": "metadata-only", "outputsRead": False, "mutations": False},
                }
            except Exception as error:
                code = _error_code(error)
                return {"ok": False, "schemaVersion": SCHEMA_VERSION, "error": code, "errorCode": code}
            finally:
                for item in records:
                    try:
                        os.close(item["runFd"])
                    except OSError:
                        pass
