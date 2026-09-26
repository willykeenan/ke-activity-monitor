"""Bounded read-only local sources for the flagship capability fabric.

The observers in this module intentionally avoid importing the owning KE
services.  Importing Ethos can seed/write its roster, and importing the Agent
Operations Board can initialize or mutate its database.  The flagship instead
opens existing source state read-only and returns a privacy-bounded projection.
"""

from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import quote


COMPANY_SCHEMA_VERSION = "ke.activity-monitor-company.v1"
BOARD_SCHEMA_VERSION = "ke.activity-monitor-operations-board.v1"

MAX_ROSTER_BYTES = 2 * 1024 * 1024
MAX_JOBS_BYTES = 8 * 1024 * 1024
MAX_BOARD_BYTES = 128 * 1024 * 1024
MAX_AGENTS = 200
MAX_JOBS = 2_000
MAX_INCIDENTS = 200

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_SAFE_CAPABILITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,119}$")
_PRIVATE_TEXT = re.compile(
    r"(?:/(?:Users|home|root|private|var|etc|tmp|Volumes|Applications|opt|Library|System)/[^\s'\"`,;)]*|"
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|"
    r"\b(?:sk|rk|pk|kek|xai|gsk|gh[pousr]|whsec|sbp)[-_][A-Za-z0-9._~+/-]{12,})",
    re.IGNORECASE,
)

_DARWIN_MNT_LOCAL = 0x00001000


class _DarwinFSID(ctypes.Structure):
    _fields_ = [("value", ctypes.c_int32 * 2)]


class _DarwinStatFS(ctypes.Structure):
    """Darwin ``struct statfs`` used only to prove a descriptor is local."""

    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _DarwinFSID),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _bounded(value: Any, limit: int = 160) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    elif type(value) in {int, float}:
        text = str(value)
    else:
        return ""
    text = text.strip().replace("\x00", "")
    if _PRIVATE_TEXT.search(text):
        return "[private metadata withheld]"
    return text[:limit]


def _owned_private_regular(metadata: os.stat_result) -> None:
    """Reject sources another user or an untrusted writer can replace."""

    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("source is not a regular file")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError("source is not owned by the current user")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("source is writable by another principal")


def _owned_private_directory(metadata: os.stat_result) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("source root is not a directory")
    if metadata.st_uid != os.getuid():
        raise ValueError("source root is not owned by the current user")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("source root is writable by another principal")


def _identity(metadata: os.stat_result) -> Tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_uid,
    )


def _stable_file_identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int, int, int]:
    return _identity(metadata) + (
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_directory_identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int, int]:
    return _identity(metadata) + (metadata.st_mtime_ns, metadata.st_ctime_ns)


def _require_descriptor_platform() -> None:
    required = (
        sys.platform == "darwin",
        hasattr(os, "getuid"),
        hasattr(os, "O_CLOEXEC"),
        hasattr(os, "O_DIRECTORY"),
        hasattr(os, "O_NOFOLLOW"),
        ctypes.sizeof(_DarwinStatFS) == 2168,
        os.open in getattr(os, "supports_dir_fd", set()),
        os.stat in getattr(os, "supports_dir_fd", set()),
        os.stat in getattr(os, "supports_follow_symlinks", set()),
    )
    if not all(required):
        raise OSError(errno.ENOTSUP, "descriptor-bound local source reads are unsupported")


def _require_local_filesystem(descriptor: int) -> None:
    filesystem = _DarwinStatFS()
    libc = ctypes.CDLL(None, use_errno=True)
    fstatfs = libc.fstatfs
    fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(_DarwinStatFS)]
    fstatfs.restype = ctypes.c_int
    if fstatfs(descriptor, ctypes.byref(filesystem)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if not filesystem.f_flags & _DARWIN_MNT_LOCAL:
        raise ValueError("source is not on a local filesystem")


def _absolute_without_links(path: Path | str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _require_descriptor_alias(path: str, expected: os.stat_result) -> None:
    """Prove Darwin's ``/dev/fd/N`` alias duplicates the validated file."""

    alias = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if _identity(os.fstat(alias)) != _identity(expected):
            raise ValueError("descriptor alias does not identify the validated source")
    finally:
        os.close(alias)


class _SecureDescriptor:
    """An open file plus every nofollow descriptor that proves its ancestry."""

    def __init__(
        self,
        *,
        root_path: Path,
        descriptors: Sequence[int],
        root_metadata: os.stat_result,
        edges: Sequence[Tuple[int, str, int, os.stat_result, bool]],
        directory_metadata: Sequence[Tuple[int, os.stat_result]],
    ) -> None:
        self.root_path = root_path
        self._descriptors = list(descriptors)
        self._root_metadata = root_metadata
        self._edges = list(edges)
        self._directory_metadata = list(directory_metadata)
        self.fd = self._descriptors[-1]
        self.metadata = self._edges[-1][3]

    def revalidate(self, *, stable_contents: bool = False) -> None:
        linked_root = os.stat(self.root_path, follow_symlinks=False)
        current_root = os.fstat(self._descriptors[0])
        if _identity(linked_root) != _identity(self._root_metadata):
            raise ValueError("trusted source root changed during read")
        if _identity(current_root) != _identity(self._root_metadata):
            raise ValueError("trusted source descriptor changed during read")
        _owned_private_directory(current_root)

        for descriptor, expected in self._directory_metadata:
            current = os.fstat(descriptor)
            if _stable_directory_identity(current) != _stable_directory_identity(expected):
                raise ValueError("trusted source directory changed during read")

        for parent, name, child, expected, is_directory in self._edges:
            linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
            current = os.fstat(child)
            if _identity(linked) != _identity(expected) or _identity(current) != _identity(expected):
                raise ValueError("trusted source path changed during read")
            if is_directory:
                _owned_private_directory(current)
            else:
                _owned_private_regular(current)

        if stable_contents and _stable_file_identity(os.fstat(self.fd)) != _stable_file_identity(
            self.metadata
        ):
            raise ValueError("source content changed during read")

    def close(self) -> None:
        while self._descriptors:
            descriptor = self._descriptors.pop()
            try:
                os.close(descriptor)
            except OSError:
                pass

    def __enter__(self) -> "_SecureDescriptor":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


def _secure_descriptor(
    path: Path | str,
    *,
    trusted_root: Path | str,
    before_leaf_open: Optional[Callable[[], None]] = None,
) -> _SecureDescriptor:
    """Open one local private file without ever reopening its validated pathname."""

    _require_descriptor_platform()
    candidate = _absolute_without_links(path)
    root = _absolute_without_links(trusted_root)
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise ValueError("source is outside its trusted root") from error
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} or "\x00" in part for part in parts):
        raise ValueError("source path is not a bounded descendant")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors: List[int] = []
    edges: List[Tuple[int, str, int, os.stat_result, bool]] = []
    try:
        root_descriptor = os.open(root, directory_flags)
        descriptors.append(root_descriptor)
        root_metadata = os.fstat(root_descriptor)
        linked_root = os.stat(root, follow_symlinks=False)
        _owned_private_directory(root_metadata)
        _require_local_filesystem(root_descriptor)
        if _identity(linked_root) != _identity(root_metadata):
            raise ValueError("trusted source root changed during open")

        parent = root_descriptor
        for component in parts[:-1]:
            child = os.open(component, directory_flags, dir_fd=parent)
            descriptors.append(child)
            metadata = os.fstat(child)
            linked = os.stat(component, dir_fd=parent, follow_symlinks=False)
            _owned_private_directory(metadata)
            _require_local_filesystem(child)
            if _identity(linked) != _identity(metadata):
                raise ValueError("trusted source directory changed during open")
            edges.append((parent, component, child, metadata, True))
            parent = child

        directory_metadata = [(item, os.fstat(item)) for item in descriptors]
        if before_leaf_open is not None:
            before_leaf_open()

        leaf = parts[-1]
        descriptor = os.open(leaf, file_flags, dir_fd=parent)
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        linked = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        _owned_private_regular(metadata)
        _require_local_filesystem(descriptor)
        if _identity(linked) != _identity(metadata):
            raise ValueError("trusted source file changed during open")
        edges.append((parent, leaf, descriptor, metadata, False))

        secured = _SecureDescriptor(
            root_path=root,
            descriptors=descriptors,
            root_metadata=root_metadata,
            edges=edges,
            directory_metadata=directory_metadata,
        )
        secured.revalidate()
        return secured
    except Exception:
        while descriptors:
            try:
                os.close(descriptors.pop())
            except OSError:
                pass
        raise


def _private_json(
    path: Path,
    max_bytes: int,
    *,
    trusted_root: Path,
    before_leaf_open: Optional[Callable[[], None]] = None,
) -> Any:
    with _secure_descriptor(
        path,
        trusted_root=trusted_root,
        before_leaf_open=before_leaf_open,
    ) as secured:
        before = secured.metadata
        if before.st_size < 2 or before.st_size > max_bytes:
            raise ValueError("source size is outside the observer boundary")
        chunks: List[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(secured.fd, min(remaining, 256 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != before.st_size:
            raise ValueError("source changed during read")
        secured.revalidate(stable_contents=True)
        payload = json.loads(raw.decode("utf-8"))
        secured.revalidate(stable_contents=True)
        return payload


class CompanyDiscovery:
    """Read the existing Ethos roster without seeding or modifying it."""

    def __init__(
        self,
        *,
        home: Path | str | None = None,
        roster_path: Path | str | None = None,
        jobs_path: Path | str | None = None,
        now=None,
        _before_roster_open: Optional[Callable[[], None]] = None,
        _before_jobs_open: Optional[Callable[[], None]] = None,
    ) -> None:
        base = _absolute_without_links(home if home is not None else Path.home())
        ethos = base / ".grokcode" / "ethos"
        self.roster_path = (
            _absolute_without_links(roster_path) if roster_path is not None else ethos / "roster.json"
        )
        self.jobs_path = (
            _absolute_without_links(jobs_path) if jobs_path is not None else ethos / "jobs.json"
        )
        self._roster_root = base if roster_path is None else self.roster_path.parent
        self._jobs_root = base if jobs_path is None else self.jobs_path.parent
        self._before_roster_open = _before_roster_open
        self._before_jobs_open = _before_jobs_open
        self._now = now or _utc_now

    @staticmethod
    def _unavailable(state: str, detail: str) -> Dict[str, Any]:
        return {
            "ok": False,
            "schemaVersion": COMPANY_SCHEMA_VERSION,
            "state": state,
            "observedAt": _utc_now(),
            "detail": detail,
            "summary": {"agents": 0, "enabled": 0, "teams": 0, "crewContracts": 0, "jobs": 0},
            "agents": [],
            "teams": [],
            "privacy": CompanyDiscovery._privacy(),
        }

    @staticmethod
    def _privacy() -> Dict[str, Any]:
        return {
            "mode": "metadata-only",
            "emailsReturned": False,
            "personasReturned": False,
            "chartersReturned": False,
            "brainPathsReturned": False,
            "allowlistsReturned": False,
            "jobBodiesReturned": False,
            "jobSubjectsReturned": False,
            "mutation": False,
        }

    def snapshot(self) -> Dict[str, Any]:
        try:
            payload = _private_json(
                self.roster_path,
                MAX_ROSTER_BYTES,
                trusted_root=self._roster_root,
                before_leaf_open=self._before_roster_open,
            )
        except FileNotFoundError:
            return self._unavailable("not-configured", "No existing Ethos roster is configured.")
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            return self._unavailable("unavailable", "The Ethos roster could not be read safely.")
        raw_agents = payload.get("agents") if isinstance(payload, dict) else None
        if not isinstance(raw_agents, list):
            return self._unavailable("unavailable", "The Ethos roster schema is unsupported.")

        agents: List[Dict[str, Any]] = []
        seen = set()
        for raw in raw_agents[:MAX_AGENTS]:
            if not isinstance(raw, dict):
                continue
            agent_id = str(raw.get("id") or "").strip()
            if not _IDENTIFIER.fullmatch(agent_id) or agent_id in seen:
                continue
            seen.add(agent_id)
            name = _bounded(raw.get("name"), 100) or agent_id
            role = _bounded(raw.get("role"), 100) or "Unassigned"
            team = _bounded(raw.get("team"), 100) or role
            agents.append(
                {
                    "id": agent_id,
                    "name": name,
                    "role": role,
                    "team": team,
                    "lead": raw.get("lead") is True,
                    "enabled": raw.get("enabled") is True,
                    "hiredAt": _bounded(raw.get("hired"), 80) or None,
                    "runtimeAttachment": _bounded(raw.get("model"), 100) or None,
                    "identityBoundary": "Agent identity is separate from its runtime attachment.",
                }
            )

        job_counts: Dict[str, Dict[str, int]] = {}
        total_jobs = 0
        jobs_state = "not-configured"
        try:
            jobs_payload = _private_json(
                self.jobs_path,
                MAX_JOBS_BYTES,
                trusted_root=self._jobs_root,
                before_leaf_open=self._before_jobs_open,
            )
            raw_jobs = jobs_payload.get("jobs") if isinstance(jobs_payload, dict) else None
            if isinstance(raw_jobs, list):
                jobs_state = "available"
                for raw in raw_jobs[:MAX_JOBS]:
                    if not isinstance(raw, dict):
                        continue
                    agent_id = str(raw.get("agentId") or "")
                    status_value = str(raw.get("status") or "unknown").strip().lower()
                    if agent_id not in seen or status_value not in {
                        "received", "working", "replied", "parked", "error"
                    }:
                        continue
                    counts = job_counts.setdefault(
                        agent_id,
                        {"received": 0, "working": 0, "replied": 0, "parked": 0, "error": 0},
                    )
                    counts[status_value] += 1
                    total_jobs += 1
        except FileNotFoundError:
            pass
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            jobs_state = "unavailable"

        for agent in agents:
            agent["jobs"] = job_counts.get(
                agent["id"],
                {"received": 0, "working": 0, "replied": 0, "parked": 0, "error": 0},
            )

        teams_by_name: Dict[str, List[Dict[str, Any]]] = {}
        for agent in agents:
            teams_by_name.setdefault(agent["team"], []).append(agent)
        teams = []
        team_ids = set()
        for name, members in sorted(teams_by_name.items(), key=lambda item: item[0].casefold()):
            stem = re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-") or "team"
            team_id = stem
            if team_id in team_ids:
                team_id = f"{stem}-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:8]}"
            team_ids.add(team_id)
            teams.append({
                "id": team_id,
                "name": name,
                "kind": "roster-team",
                "memberIds": [agent["id"] for agent in members],
                "leadIds": [agent["id"] for agent in members if agent["lead"]],
                "crewContract": False,
            })
        return {
            "ok": True,
            "schemaVersion": COMPANY_SCHEMA_VERSION,
            "state": "partial",
            "observedAt": self._now(),
            "detail": (
                "Persistent Ethos Agent roster observed. Roster teams are not promoted "
                "to durable Crew contracts without an owning Ethos contract."
            ),
            "summary": {
                "agents": len(agents),
                "enabled": sum(1 for item in agents if item["enabled"]),
                "teams": len(teams),
                "crewContracts": 0,
                "jobs": total_jobs,
                "jobsState": jobs_state,
            },
            "agents": agents,
            "teams": teams,
            "privacy": self._privacy(),
        }


class OperationsBoardDiscovery:
    """Read the board's current public-operational fields through SQLite RO."""

    def __init__(
        self,
        *,
        database_path: Path | str,
        now=None,
        trusted_root: Path | str | None = None,
        _before_database_open: Optional[Callable[[], None]] = None,
    ) -> None:
        self.database_path = _absolute_without_links(database_path)
        if trusted_root is not None:
            self._trusted_root = _absolute_without_links(trusted_root)
        else:
            home = _absolute_without_links(Path.home())
            try:
                self.database_path.relative_to(home)
                self._trusted_root = home
            except ValueError:
                self._trusted_root = self.database_path.parent
        self._before_database_open = _before_database_open
        self._now = now or _utc_now

    @staticmethod
    def _privacy() -> Dict[str, Any]:
        return {
            "mode": "metadata-only",
            "databasePathReturned": False,
            "writableScopesReturned": False,
            "incidentDetailsReturned": False,
            "safeActionsReturned": False,
            "eventPayloadsReturned": False,
            "mutation": False,
        }

    def _unavailable(self, state: str, detail: str) -> Dict[str, Any]:
        return {
            "ok": False,
            "schemaVersion": BOARD_SCHEMA_VERSION,
            "state": state,
            "observedAt": self._now(),
            "detail": detail,
            "counts": {"agents": 0, "activeOwners": 0, "open": 0, "acknowledged": 0, "needsHuman": 0},
            "agents": [],
            "incidents": [],
            "privacy": self._privacy(),
        }

    def snapshot(self) -> Dict[str, Any]:
        try:
            secured = _secure_descriptor(
                self.database_path,
                trusted_root=self._trusted_root,
                before_leaf_open=self._before_database_open,
            )
        except FileNotFoundError:
            return self._unavailable("not-configured", "The local Agent Operations Board is not configured.")
        except (OSError, ValueError):
            return self._unavailable("unavailable", "The local Agent Operations Board cannot be inspected.")

        with secured:
            metadata = secured.metadata
            if metadata.st_size < 1 or metadata.st_size > MAX_BOARD_BYTES:
                return self._unavailable(
                    "unavailable",
                    "The Agent Operations Board source is outside the read boundary.",
                )

            descriptor_path = f"/dev/fd/{secured.fd}"
            uri = "file:" + quote(descriptor_path, safe="/") + "?mode=ro&immutable=1"
            connection = None
            query_failed = False
            try:
                _require_descriptor_alias(descriptor_path, metadata)
                connection = sqlite3.connect(uri, uri=True, timeout=0.75)
                connection.row_factory = sqlite3.Row
                if hasattr(connection, "setlimit"):
                    connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
                    connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 64 * 1024)
                    connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 64)
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("PRAGMA busy_timeout=750")
                connection.execute("BEGIN")
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name IN ('agents','incidents')"
                    ).fetchall()
                }
                if tables != {"agents", "incidents"}:
                    raise ValueError("unsupported board schema")
                agent_rows = connection.execute(
                    "SELECT substr(agent_id,1,160) AS agent_id, "
                    "substr(team,1,160) AS team, substr(provider,1,80) AS provider, "
                    "substr(endpoint,1,160) AS endpoint, "
                    "substr(display_name,1,256) AS display_name, "
                    "substr(capabilities_json,1,8192) AS capabilities_json, priority, "
                    "substr(status,1,80) AS status, "
                    "substr(last_seen_at,1,96) AS last_seen_at "
                    "FROM agents ORDER BY team, priority, agent_id LIMIT ?",
                    (MAX_AGENTS,),
                ).fetchall()
                incident_rows = connection.execute(
                    "SELECT substr(incident_id,1,160) AS incident_id, "
                    "substr(team,1,160) AS team, substr(title,1,256) AS title, "
                    "substr(severity,1,80) AS severity, substr(status,1,80) AS status, "
                    "substr(required_capability,1,160) AS required_capability, "
                    "william_needed, substr(assigned_agent_id,1,160) AS assigned_agent_id, "
                    "substr(acknowledged_at,1,96) AS acknowledged_at, "
                    "substr(resolved_at,1,96) AS resolved_at, "
                    "substr(updated_at,1,96) AS updated_at "
                    "FROM incidents ORDER BY updated_at DESC LIMIT ?",
                    (MAX_INCIDENTS,),
                ).fetchall()
                _require_descriptor_alias(descriptor_path, metadata)
                secured.revalidate(stable_contents=True)
            except (OSError, sqlite3.Error, ValueError):
                query_failed = True
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except sqlite3.Error:
                        query_failed = True
            if query_failed:
                return self._unavailable(
                    "unavailable",
                    "The Agent Operations Board could not be queried read-only.",
                )

        agents: List[Dict[str, Any]] = []
        for row in agent_rows:
            agent_id = str(row["agent_id"] or "")
            endpoint = str(row["endpoint"] or "")
            if not _IDENTIFIER.fullmatch(agent_id) or not _IDENTIFIER.fullmatch(endpoint):
                continue
            try:
                capabilities_raw = json.loads(row["capabilities_json"] or "[]")
            except json.JSONDecodeError:
                capabilities_raw = []
            if not isinstance(capabilities_raw, list):
                capabilities_raw = []
            capabilities = [
                item
                for item in (_bounded(value, 120) for value in capabilities_raw[:50] if isinstance(value, str))
                if item and _SAFE_CAPABILITY.fullmatch(item)
            ]
            try:
                priority = int(row["priority"])
            except (TypeError, ValueError):
                priority = 100
            agents.append(
                {
                    "agentId": agent_id,
                    "provider": _bounded(row["provider"], 40),
                    "endpoint": endpoint,
                    "displayName": _bounded(row["display_name"], 120) or agent_id,
                    "team": _bounded(row["team"], 80),
                    "capabilities": capabilities,
                    "priority": priority,
                    "state": _bounded(row["status"], 30).upper() or "UNKNOWN",
                    "lastSeenAt": _bounded(row["last_seen_at"], 80) or None,
                }
            )

        incidents: List[Dict[str, Any]] = []
        for row in incident_rows:
            incident_id = str(row["incident_id"] or "")
            if not _IDENTIFIER.fullmatch(incident_id):
                continue
            assigned = str(row["assigned_agent_id"] or "")
            incidents.append(
                {
                    "incidentId": incident_id,
                    "team": _bounded(row["team"], 80),
                    "title": _bounded(row["title"], 180),
                    "severity": _bounded(row["severity"], 30).lower() or "unknown",
                    "state": _bounded(row["status"], 40).upper() or "UNKNOWN",
                    "requiredCapability": _bounded(row["required_capability"], 120),
                    "needsHuman": bool(row["william_needed"]),
                    "assignedAgentId": assigned if _IDENTIFIER.fullmatch(assigned) else None,
                    "acknowledgedAt": _bounded(row["acknowledged_at"], 80) or None,
                    "resolvedAt": _bounded(row["resolved_at"], 80) or None,
                    "updatedAt": _bounded(row["updated_at"], 80) or None,
                }
            )

        open_incidents = [item for item in incidents if item["state"] != "RESOLVED"]
        return {
            "ok": True,
            "schemaVersion": BOARD_SCHEMA_VERSION,
            "state": "available",
            "observedAt": self._now(),
            "readOnly": True,
            "detail": "Current registered owners and bounded incident metadata observed read-only.",
            "counts": {
                "agents": len(agents),
                "activeOwners": sum(1 for item in agents if item["state"] == "ACTIVE"),
                "open": len(open_incidents),
                "acknowledged": sum(1 for item in open_incidents if item["state"] == "ACKNOWLEDGED"),
                "needsHuman": sum(1 for item in open_incidents if item["needsHuman"]),
            },
            "agents": agents,
            "incidents": incidents,
            "privacy": self._privacy(),
        }


__all__ = [
    "BOARD_SCHEMA_VERSION",
    "COMPANY_SCHEMA_VERSION",
    "CompanyDiscovery",
    "OperationsBoardDiscovery",
]
