"""Read-only KE Guard status projection for Activity Monitor."""

import copy
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import threading
import time


SCHEMA_VERSION = "ke.activity-monitor-keguard.v1"
MAX_STATE_BYTES = 1024 * 1024
MAX_LEDGER_BYTES = 512 * 1024
MAX_LEDGER_ROWS = 400
DEFAULT_TICK_SECONDS = 60.0
MIN_STALE_SECONDS = 180.0
MIN_OFFLINE_SECONDS = 900.0
DEFAULT_READ_TIMEOUT_SECONDS = 0.75


def _finite_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _positive_epoch(value):
    value = _finite_number(value)
    return value if value is not None and value > 0 else None


def _iso(epoch):
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _parse_iso(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (OverflowError, TypeError, ValueError):
        return None


def _safe_pid(value):
    if isinstance(value, bool):
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _status_label(state):
    if state == "dry-run":
        return "DRY-RUN"
    return str(state).replace("-", " ").upper()


class GuardStatusError(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class GuardService:
    """Project KE Guard state into a compact, privacy-bounded UI contract.

    The service never imports or executes KE Guard. It reads current-user files,
    returns sanitized summaries, and retains its last valid projection when a
    later read fails.
    """

    def __init__(
        self,
        home=None,
        platform_name=None,
        clock=None,
        max_evidence=8,
        read_timeout_seconds=DEFAULT_READ_TIMEOUT_SECONDS,
        state_reader=None,
    ):
        self.home = Path(home) if home is not None else Path.home()
        self.platform_name = platform_name or platform.system()
        self.clock = clock or time.time
        self.base = self.home / "ke-agent-rooms" / "resource" / "keguard"
        self.state_path = self.base / "state.json"
        self.ledger_path = self.base / "ledger.jsonl"
        self.max_evidence = max(1, min(20, int(max_evidence)))
        self.read_timeout_seconds = max(0.01, min(5.0, float(read_timeout_seconds)))
        self._state_reader = state_reader or self._read_state_sync
        self._state_read_lock = threading.Lock()
        self._state_read_inflight = None
        self._last_valid = None

    @staticmethod
    def _base_payload(state, detail, *, supported, installed):
        return {
            "ok": False,
            "schemaVersion": SCHEMA_VERSION,
            "state": state,
            "statusLabel": _status_label(state),
            "supported": supported,
            "installed": installed,
            "available": False,
            "retained": False,
            "detail": detail,
            "configuredMode": None,
            "observedAt": None,
            "ageSeconds": None,
            "activeSuspects": {"count": 0, "items": []},
            "pendingRemediation": None,
            "kills24h": None,
            "trends": {"load": None, "diskFree": None},
            "recentEvidence": [],
            "ledgerAvailable": False,
            "killsWindowComplete": False,
            "privacy": GuardService._privacy(),
        }

    @staticmethod
    def _privacy():
        return {
            "mode": "sanitized-local-metadata",
            "readOnly": True,
            "rawLedgerBodiesReturned": False,
            "commandsReturned": False,
            "pathsReturned": False,
            "controlsExposed": False,
            "uploads": False,
        }

    def _read_state_sync(self):
        try:
            size = self.state_path.stat().st_size
        except FileNotFoundError as error:
            raise GuardStatusError("state_missing", "KE Guard state is not present.") from error
        except OSError as error:
            raise GuardStatusError("state_unreadable", "KE Guard state cannot be read.") from error
        if size <= 0 or size > MAX_STATE_BYTES:
            raise GuardStatusError("state_malformed", "KE Guard state has an invalid size.")
        try:
            with self.state_path.open("r", encoding="utf-8") as handle:
                state = json.load(handle)
        except OSError as error:
            raise GuardStatusError("state_unreadable", "KE Guard state cannot be read.") from error
        except (UnicodeError, json.JSONDecodeError) as error:
            raise GuardStatusError("state_malformed", "KE Guard state is malformed.") from error
        if not isinstance(state, dict) or not isinstance(state.get("daemon"), dict):
            raise GuardStatusError("state_malformed", "KE Guard state has an unsupported shape.")
        return state

    def _read_state(self):
        with self._state_read_lock:
            job = self._state_read_inflight
            if job is None:
                job = {"done": threading.Event(), "ok": None, "value": None}
                self._state_read_inflight = job

                def read_once():
                    try:
                        job["value"] = self._state_reader()
                        job["ok"] = True
                    except Exception as error:
                        job["value"] = error
                        job["ok"] = False
                    finally:
                        job["done"].set()

                threading.Thread(target=read_once, name="keguard-status-read", daemon=True).start()
        if not job["done"].wait(timeout=self.read_timeout_seconds):
            raise GuardStatusError("state_timeout", "KE Guard state read timed out.")
        with self._state_read_lock:
            if self._state_read_inflight is job:
                self._state_read_inflight = None
        ok, value = job["ok"], job["value"]
        if ok:
            if not isinstance(value, dict) or not isinstance(value.get("daemon"), dict):
                raise GuardStatusError("state_malformed", "KE Guard state has an unsupported shape.")
            return value
        if isinstance(value, GuardStatusError):
            raise value
        if isinstance(value, (OSError, PermissionError)):
            raise GuardStatusError("state_unreadable", "KE Guard state cannot be read.") from value
        raise GuardStatusError("state_malformed", "KE Guard state is malformed.") from value

    def _read_ledger(self):
        try:
            with self.ledger_path.open("rb") as handle:
                size = self.ledger_path.stat().st_size
                offset = max(0, size - MAX_LEDGER_BYTES)
                handle.seek(offset)
                raw = handle.read(MAX_LEDGER_BYTES)
        except FileNotFoundError:
            return [], False, False
        except OSError:
            return [], False, False
        lines = raw.decode("utf-8", "replace").splitlines()
        if offset and lines:
            lines = lines[1:]
        rotated_path = self.ledger_path.with_name(self.ledger_path.name + ".1")
        try:
            rotated_path.stat()
            rotated_present = True
        except FileNotFoundError:
            rotated_present = False
        except OSError:
            rotated_present = True
        complete = offset == 0 and len(lines) <= MAX_LEDGER_ROWS and not rotated_present
        rows = []
        for line in lines[-MAX_LEDGER_ROWS:]:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and isinstance(row.get("event"), str):
                rows.append(row)
        return rows, True, complete

    @staticmethod
    def _trend(ticks, field, threshold):
        points = []
        for tick in ticks[-20:]:
            if not isinstance(tick, dict):
                continue
            observed = _positive_epoch(tick.get("t"))
            value = _finite_number(tick.get(field))
            if observed is None or value is None:
                continue
            points.append({"observedAt": _iso(observed), "value": round(value, 3)})
        if not points:
            return None
        first = points[0]["value"]
        current = points[-1]["value"]
        delta = round(current - first, 3)
        direction = "steady"
        if delta > threshold:
            direction = "rising"
        elif delta < -threshold:
            direction = "falling"
        first_epoch = _parse_iso(points[0]["observedAt"])
        last_epoch = _parse_iso(points[-1]["observedAt"])
        return {
            "current": current,
            "delta": delta,
            "direction": direction,
            "samples": len(points),
            "windowSeconds": round(max(0.0, (last_epoch or 0) - (first_epoch or 0))),
            "points": points,
        }

    @staticmethod
    def _alert_label(key):
        key = str(key or "")
        if key == "disk_critical":
            return "Disk space is critical"
        if key == "disk_warn":
            return "Disk space is low"
        if key == "load_high":
            return "Sustained system load"
        if key == "registry_empty" or key.startswith("manifest_parse-"):
            return "CPU Workers protection is degraded"
        if key == "kill_suppressed":
            return "Runaway remediation was circuit-breaker limited"
        if key.startswith("churn-"):
            return "Suspicious process churn"
        if key.startswith("bigfile-"):
            return "Large growing file"
        return "KE Guard alert"

    @classmethod
    def _evidence_row(cls, row):
        event = row.get("event")
        observed = _iso(_parse_iso(row.get("ts")))
        pid = _safe_pid(row.get("pid"))
        if event == "alert":
            return {"observedAt": observed, "kind": "alert", "label": cls._alert_label(row.get("key")), "pid": None, "evidenceAvailable": False}
        labels = {
            "would_kill": ("dry-run", "Dry-run process remediation evaluated"),
            "kill_aborted": ("remediation", "Process remediation aborted after re-verification"),
            "kill_sigterm": ("remediation", "SIGTERM remediation issued"),
            "kill_sigkill": ("remediation", "SIGKILL escalation issued"),
            "kill_complete": ("remediation", "Process remediation completed"),
            "would_delete": ("dry-run", "Dry-run file remediation evaluated"),
            "delete": ("remediation", "Dead flood file removed"),
            "delete_failed": ("remediation", "File remediation failed"),
            "delete_declined": ("evidence", "File remediation declined after evidence review"),
        }
        if event not in labels:
            return None
        kind, label = labels[event]
        return {
            "observedAt": observed,
            "kind": kind,
            "label": label,
            "pid": pid,
            "evidenceAvailable": bool(row.get("evidence")),
        }

    @staticmethod
    def _suspects(state):
        items = []
        suspects = state.get("suspects")
        if not isinstance(suspects, dict):
            return {"count": 0, "items": []}
        for raw_pid, record in suspects.items():
            if not isinstance(record, dict):
                continue
            streak = _finite_number(record.get("streak")) or 0
            if streak <= 0:
                continue
            children = record.get("children") if isinstance(record.get("children"), list) else []
            items.append({
                "pid": _safe_pid(raw_pid),
                "streak": int(streak),
                "childCount": len(children),
            })
        items.sort(key=lambda item: (-item["streak"], item["pid"] or 0))
        return {"count": len(items), "items": items[:8]}

    @staticmethod
    def _pending(state):
        pending = state.get("pending_kill")
        if not isinstance(pending, dict):
            return None
        targets = pending.get("targets") if isinstance(pending.get("targets"), list) else []
        return {
            "kind": "process-remediation",
            "phase": "awaiting-reverification",
            "pid": _safe_pid(pending.get("pid")),
            "targetCount": len(targets),
            "queuedAt": _iso(_positive_epoch(pending.get("ts"))),
            "evidenceAvailable": bool(pending.get("evidence")),
        }

    def _project(self, state, now):
        daemon = state.get("daemon") or {}
        observed = _positive_epoch(daemon.get("last"))
        armed = daemon.get("armed") is True
        tick_seconds = _finite_number(daemon.get("tick")) or DEFAULT_TICK_SECONDS
        tick_seconds = max(1.0, min(3600.0, tick_seconds))
        stale_after = max(MIN_STALE_SECONDS, tick_seconds * 3.0)
        offline_after = max(MIN_OFFLINE_SECONDS, tick_seconds * 15.0)
        age = max(0.0, now - observed) if observed is not None else None
        if age is None or age > offline_after:
            status = "offline"
        elif age > stale_after:
            status = "stale"
        else:
            status = "armed" if armed else "dry-run"

        rows, ledger_available, ledger_complete = self._read_ledger()
        evidence = []
        for row in reversed(rows):
            safe = self._evidence_row(row)
            if safe is not None:
                evidence.append(safe)
            if len(evidence) >= self.max_evidence:
                break
        cutoff = now - 86400.0
        if ledger_available and not ledger_complete:
            timestamps = [_parse_iso(row.get("ts")) for row in rows]
            oldest = min((stamp for stamp in timestamps if stamp is not None), default=None)
            ledger_complete = oldest is not None and oldest <= cutoff
        kills_24h = None
        if ledger_available and ledger_complete:
            kills_24h = sum(
                1 for row in rows
                if row.get("event") == "kill_sigterm"
                and (_parse_iso(row.get("ts")) or 0) >= cutoff
            )

        ticks = state.get("ticks") if isinstance(state.get("ticks"), list) else []
        return {
            "ok": status in {"armed", "dry-run"},
            "schemaVersion": SCHEMA_VERSION,
            "state": status,
            "statusLabel": _status_label(status),
            "supported": True,
            "installed": True,
            "available": observed is not None,
            "retained": False,
            "detail": "Live KE Guard state." if status in {"armed", "dry-run"} else "KE Guard has not published a current observation.",
            "configuredMode": "armed" if armed else "dry-run",
            "observedAt": _iso(observed),
            "ageSeconds": None if age is None else round(age, 1),
            "tickSeconds": round(tick_seconds, 1),
            "staleAfterSeconds": round(stale_after, 1),
            "offlineAfterSeconds": round(offline_after, 1),
            "daemonPid": _safe_pid(daemon.get("pid")),
            "activeSuspects": self._suspects(state),
            "pendingRemediation": self._pending(state),
            "kills24h": kills_24h,
            "trends": {
                "load": self._trend(ticks, "load1", 0.5),
                "diskFree": self._trend(ticks, "free_gb", 0.05),
            },
            "recentEvidence": evidence,
            "ledgerAvailable": ledger_available,
            "killsWindowComplete": ledger_complete,
            "privacy": self._privacy(),
        }

    def _retained_after_error(self, error, now):
        payload = copy.deepcopy(self._last_valid)
        age = payload.get("ageSeconds")
        observed = _parse_iso(payload.get("observedAt"))
        if observed is not None:
            age = max(0.0, now - observed)
        offline_after = payload.get("offlineAfterSeconds") or MIN_OFFLINE_SECONDS
        state = "offline" if age is None or age > offline_after else "stale"
        payload.update({
            "ok": False,
            "state": state,
            "statusLabel": state.upper(),
            "retained": True,
            "detail": "Showing the last valid KE Guard snapshot after a transient read failure.",
            "ageSeconds": None if age is None else round(age, 1),
            "readErrorCode": error.code,
        })
        return payload

    def status(self):
        now = float(self.clock())
        if self.platform_name != "Darwin":
            return self._base_payload(
                "unsupported",
                "KE Guard is currently available only on macOS; Activity Monitor remains usable.",
                supported=False,
                installed=False,
            )
        try:
            installed = self.base.is_dir()
        except OSError:
            error = GuardStatusError("state_unreadable", "KE Guard install cannot be inspected.")
            if self._last_valid is not None:
                return self._retained_after_error(error, now)
            payload = self._base_payload(
                "offline",
                "KE Guard installation state cannot currently be inspected.",
                supported=True,
                installed=None,
            )
            payload["readErrorCode"] = error.code
            return payload
        if not installed and self._last_valid is None:
            return self._base_payload(
                "not-installed",
                "KE Guard is not installed for this user.",
                supported=True,
                installed=False,
            )
        try:
            payload = self._project(self._read_state(), now)
        except GuardStatusError as error:
            if self._last_valid is not None:
                return self._retained_after_error(error, now)
            payload = self._base_payload(
                "offline",
                "KE Guard is installed but no valid state is currently available.",
                supported=True,
                installed=installed,
            )
            payload["readErrorCode"] = error.code
            return payload
        self._last_valid = copy.deepcopy(payload)
        return payload
