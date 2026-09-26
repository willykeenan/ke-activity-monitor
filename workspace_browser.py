"""Metadata-only Codex and Claude project navigation for Activity Monitor.

The workspace rail is intentionally a launcher and status projection, not a
provider database editor or transcript reader.  It exposes only whitelisted
project/session metadata, keeps view preferences in a separate mode-0600 file,
and launches an exact existing conversation only after a user click.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from typing import Callable

from dispatch_router import CodexAppServerClient, DispatchError, UUID_RE


SCHEMA_VERSION = "ke.activity-monitor-workspace.v1"
PREFERENCES_SCHEMA_VERSION = "ke.activity-monitor-workspace-preferences.v1"
FLAGSHIP_PREFERENCES_SCHEMA_VERSION = "ke.activity-monitor-flagship-preferences.v1"
FLAGSHIP_CAPABILITY_TABS = (
    "cpu",
    "memory",
    "energy",
    "disk",
    "network",
    "agents",
    "brain",
    "dispatch",
)
MAX_GLOBAL_STATE_BYTES = 2 * 1024 * 1024
MAX_PREFERENCES_BYTES = 256 * 1024
MAX_CODEX_THREADS = 1_000
MAX_CODEX_PROJECTS = 128
MAX_CLAUDE_PROJECTS = 128
MAX_CLAUDE_SESSIONS = 500
MAX_CLAUDE_PROJECT_SCAN_ENTRIES = 2_048
MAX_CLAUDE_SESSION_SCAN_ENTRIES = 4_096
MAX_CLAUDE_GLOBAL_SCAN_ENTRIES = 8_192
MAX_CLAUDE_REGISTRY_BYTES = 262_144
MAX_LABEL_CHARS = 180
PROJECT_ID_RE = re.compile(
    r"(?:local-[0-9a-f]{32}|claude-[0-9a-f]{24}|codex-unfiled|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)
CODEX_STATE_KEYS = {
    "local-projects",
    "project-order",
    "thread-project-assignments",
    "sidebar-project-thread-orders",
    "pinned-thread-ids",
    "pinned-project-ids",
    "projectless-thread-ids",
}


class WorkspaceError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_label(value: object, fallback: str) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return (text[:MAX_LABEL_CHARS] or fallback).strip()


def _safe_state(value: object) -> str:
    if isinstance(value, dict):
        value = value.get("type") or value.get("status")
    token = re.sub(r"[^a-z0-9 _-]", "", str(value or "unknown").lower()).strip()
    aliases = {
        "inprogress": "active",
        "in progress": "active",
        "running": "active",
        "notloaded": "not loaded",
        "not loaded": "not loaded",
        "idle": "idle",
        "completed": "completed",
        "failed": "failed",
        "active": "active",
    }
    return aliases.get(token, token[:32] or "unknown")


def _epoch(value: object, fallback: float = 0.0) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        result = float(value)
        if result > 10_000_000_000:
            result /= 1_000.0
        return max(0.0, result)
    if isinstance(value, str) and value:
        try:
            return max(0.0, datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
        except ValueError:
            pass
    return max(0.0, float(fallback))


def _regular_user_file(path: Path, *, max_bytes: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise WorkspaceError("metadata_missing", "Required local metadata is unavailable") from error
    except OSError as error:
        raise WorkspaceError("metadata_unreadable", "Required local metadata cannot be inspected") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise WorkspaceError("metadata_untrusted", "Local metadata is not a current-user regular file")
    if metadata.st_mode & 0o022:
        raise WorkspaceError("metadata_insecure", "Local metadata is writable by another user")
    if metadata.st_size < 2 or metadata.st_size > max_bytes:
        raise WorkspaceError("metadata_size_invalid", "Local metadata has an unsupported size")
    return metadata


class _JsonCharStream:
    """Tiny streaming JSON cursor that never retains skipped value bytes."""

    def __init__(self, handle):
        self.handle = handle
        self.buffer = ""
        self.index = 0
        self.pushed: str | None = None

    def get(self) -> str:
        if self.pushed is not None:
            value, self.pushed = self.pushed, None
            return value
        if self.index >= len(self.buffer):
            self.buffer = self.handle.read(16_384)
            self.index = 0
            if not self.buffer:
                return ""
        value = self.buffer[self.index]
        self.index += 1
        return value

    def unget(self, value: str) -> None:
        if value:
            if self.pushed is not None:
                raise WorkspaceError("codex_state_invalid", "Codex project metadata parser overflow")
            self.pushed = value

    def nonspace(self) -> str:
        value = self.get()
        while value and value.isspace():
            value = self.get()
        return value


def _json_string(stream: _JsonCharStream, *, retain: bool, limit: int = 4_096) -> str | None:
    if stream.get() != '"':
        raise WorkspaceError("codex_state_invalid", "Codex project metadata contains an invalid key")
    collected = ['"'] if retain else None
    escaped = False
    while True:
        value = stream.get()
        if not value:
            raise WorkspaceError("codex_state_invalid", "Codex project metadata ended inside a string")
        if collected is not None:
            if len(collected) >= limit:
                raise WorkspaceError("codex_state_invalid", "Codex project metadata key is too large")
            collected.append(value)
        if escaped:
            escaped = False
        elif value == "\\":
            escaped = True
        elif value == '"':
            break
    if collected is None:
        return None
    try:
        decoded = json.loads("".join(collected))
    except (ValueError, TypeError) as error:
        raise WorkspaceError("codex_state_invalid", "Codex project metadata contains an invalid string") from error
    if not isinstance(decoded, str):
        raise WorkspaceError("codex_state_invalid", "Codex project metadata contains a non-string key")
    return decoded


def _json_value_text(stream: _JsonCharStream, *, retain: bool, limit: int) -> str | None:
    """Consume one JSON value; skipped values are scanned but never retained."""
    first = stream.nonspace()
    if not first:
        raise WorkspaceError("codex_state_invalid", "Codex project metadata ended before a value")
    collected = [first] if retain else None
    if first == '"':
        escaped = False
        while True:
            value = stream.get()
            if not value:
                raise WorkspaceError("codex_state_invalid", "Codex project metadata ended inside a value")
            if collected is not None:
                collected.append(value)
            if escaped:
                escaped = False
            elif value == "\\":
                escaped = True
            elif value == '"':
                break
    elif first in "[{":
        closing = {"[": "]", "{": "}"}
        stack = [closing[first]]
        in_string = False
        escaped = False
        while stack:
            value = stream.get()
            if not value:
                raise WorkspaceError("codex_state_invalid", "Codex project metadata ended inside a value")
            if collected is not None:
                collected.append(value)
                if len(collected) > limit:
                    raise WorkspaceError("codex_state_invalid", "Whitelisted Codex metadata is too large")
            if in_string:
                if escaped:
                    escaped = False
                elif value == "\\":
                    escaped = True
                elif value == '"':
                    in_string = False
                continue
            if value == '"':
                in_string = True
            elif value in "[{":
                stack.append(closing[value])
            elif value == stack[-1]:
                stack.pop()
    else:
        while True:
            value = stream.get()
            if not value or value in ",}":
                stream.unget(value)
                break
            if collected is not None:
                collected.append(value)
                if len(collected) > limit:
                    raise WorkspaceError("codex_state_invalid", "Whitelisted Codex metadata is too large")
    return "".join(collected) if collected is not None else None


def _selective_json_object(path: Path, keys: set[str], *, max_bytes: int) -> dict:
    """Decode only named top-level values; unrelated values are never materialized."""
    _regular_user_file(path, max_bytes=max_bytes)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise WorkspaceError("metadata_unreadable", "Codex project metadata cannot be opened safely") from error
    result: dict = {}
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_size > max_bytes:
            raise WorkspaceError("metadata_untrusted", "Codex project metadata changed during inspection")
        with os.fdopen(descriptor, "r", encoding="utf-8", errors="strict") as handle:
            descriptor = -1
            stream = _JsonCharStream(handle)
            if stream.nonspace() != "{":
                raise WorkspaceError("codex_state_invalid", "Codex project metadata must be an object")
            while True:
                marker = stream.nonspace()
                if marker == "}":
                    break
                if marker != '"':
                    raise WorkspaceError("codex_state_invalid", "Codex project metadata contains an invalid key")
                stream.unget(marker)
                key = _json_string(stream, retain=True)
                if stream.nonspace() != ":":
                    raise WorkspaceError("codex_state_invalid", "Codex project metadata is missing a value separator")
                selected = key in keys
                raw = _json_value_text(stream, retain=selected, limit=max_bytes)
                if selected:
                    try:
                        result[key] = json.loads(raw)
                    except (ValueError, TypeError) as error:
                        raise WorkspaceError("codex_state_invalid", f"Codex metadata key {key} is malformed") from error
                delimiter = stream.nonspace()
                if delimiter == "}":
                    break
                if delimiter != ",":
                    raise WorkspaceError("codex_state_invalid", "Codex project metadata has an invalid delimiter")
    except UnicodeError as error:
        raise WorkspaceError("codex_state_invalid", "Codex project metadata is not valid UTF-8") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return result


def _private_user_directory(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise WorkspaceError("metadata_missing", "The local provider metadata directory is unavailable") from error
    except OSError as error:
        raise WorkspaceError("metadata_unreadable", "The local provider metadata directory cannot be inspected") from error
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise WorkspaceError("metadata_untrusted", "The local provider metadata directory is not current-user owned")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise WorkspaceError("metadata_insecure", "The local provider metadata directory is not private")
    return metadata


class WorkspacePreferences:
    """Small, separate, body-free view preferences store."""

    DEFAULTS = {
        "railCollapsed": False,
        "railWidth": 252,
        "expandedProjectIds": None,
        "visibleCodexProjectIds": None,
        "savedClaudeProjectIds": [],
        "savedClaudeProjectKeys": {},
        "claudeProjectDirectories": {},
        "providerFilters": {"codex": True, "claude": True},
        "collapsedCapabilityTabs": [],
        "lastSelected": None,
    }

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self._lock = threading.RLock()

    @staticmethod
    def _ids(values: object, limit: int = 128) -> list[str]:
        if not isinstance(values, list):
            return []
        result: list[str] = []
        for value in values:
            token = str(value or "")
            if token in result or not PROJECT_ID_RE.fullmatch(token):
                continue
            result.append(token)
            if len(result) >= limit:
                break
        return result

    @classmethod
    def normalize(cls, value: object) -> dict:
        source = value if isinstance(value, dict) else {}
        filters = source.get("providerFilters") if isinstance(source.get("providerFilters"), dict) else {}
        visible_source = source.get("visibleCodexProjectIds", None)
        visible = None if visible_source is None else [
            item for item in cls._ids(visible_source) if not item.startswith("claude-")
        ]
        expanded_source = source.get("expandedProjectIds", None)
        expanded = None if expanded_source is None else cls._ids(expanded_source)
        selected_source = source.get("lastSelected") if isinstance(source.get("lastSelected"), dict) else {}
        selected_provider = str(selected_source.get("provider") or "")
        selected_project = str(selected_source.get("projectId") or "")
        selected_conversation = str(selected_source.get("conversationId") or "")
        selected = None
        if (
            selected_provider in {"codex", "claude"}
            and PROJECT_ID_RE.fullmatch(selected_project)
            and UUID_RE.fullmatch(selected_conversation)
        ):
            selected = {
                "provider": selected_provider,
                "projectId": selected_project,
                "conversationId": selected_conversation,
            }
        directory_source = source.get("claudeProjectDirectories")
        directories: dict[str, str] = {}
        if isinstance(directory_source, dict):
            for project_id, directory in directory_source.items():
                project_id = str(project_id or "")
                directory = str(directory or "")
                if (
                    len(directories) >= MAX_CLAUDE_PROJECTS
                    or not project_id.startswith("claude-")
                    or not PROJECT_ID_RE.fullmatch(project_id)
                    or not directory.startswith("/")
                    or "\x00" in directory
                    or len(directory.encode("utf-8")) > 4_096
                ):
                    continue
                directories[project_id] = directory
        key_source = source.get("savedClaudeProjectKeys")
        project_keys: dict[str, str] = {}
        if isinstance(key_source, dict):
            for project_id, storage_key in key_source.items():
                project_id = str(project_id or "")
                storage_key = str(storage_key or "")
                derived = "claude-" + hashlib.sha256(storage_key.encode("utf-8")).hexdigest()[:24]
                if (
                    len(project_keys) >= MAX_CLAUDE_PROJECTS
                    or not project_id.startswith("claude-")
                    or not PROJECT_ID_RE.fullmatch(project_id)
                    or derived != project_id
                    or not re.fullmatch(r"[A-Za-z0-9-]{1,4096}", storage_key)
                ):
                    continue
                project_keys[project_id] = storage_key
        return {
            "railCollapsed": bool(source.get("railCollapsed", cls.DEFAULTS["railCollapsed"])),
            "railWidth": max(220, min(380, int(source.get("railWidth") or cls.DEFAULTS["railWidth"]))),
            "expandedProjectIds": expanded,
            "visibleCodexProjectIds": visible,
            "savedClaudeProjectIds": [
                item for item in cls._ids(source.get("savedClaudeProjectIds")) if item.startswith("claude-")
            ],
            "savedClaudeProjectKeys": project_keys,
            "claudeProjectDirectories": directories,
            "providerFilters": {
                "codex": bool(filters.get("codex", True)),
                "claude": bool(filters.get("claude", True)),
            },
            "collapsedCapabilityTabs": [
                tab
                for tab in FLAGSHIP_CAPABILITY_TABS
                if tab in (source.get("collapsedCapabilityTabs") or [])
            ]
            if isinstance(source.get("collapsedCapabilityTabs"), list)
            else [],
            "lastSelected": selected,
        }

    def read(self) -> dict:
        with self._lock:
            descriptors: list[int] = []
            try:
                directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                parent_fd = os.open(self.path.parent, directory_flags)
                descriptors.append(parent_fd)
                parent_metadata = os.fstat(parent_fd)
                if (
                    not stat.S_ISDIR(parent_metadata.st_mode)
                    or parent_metadata.st_uid != os.getuid()
                    or stat.S_IMODE(parent_metadata.st_mode) & 0o077
                ):
                    raise WorkspaceError("preferences_insecure", "Workspace preferences directory is not private")
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                preference_fd = os.open(self.path.name, flags, dir_fd=parent_fd)
                descriptors.append(preference_fd)
                metadata = os.fstat(preference_fd)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size < 2
                    or metadata.st_size > MAX_PREFERENCES_BYTES
                ):
                    raise WorkspaceError(
                        "preferences_insecure",
                        "Workspace preferences must be a bounded current-user mode-0600 regular file",
                    )
                chunks: list[bytes] = []
                remaining = metadata.st_size
                while remaining > 0:
                    chunk = os.read(preference_fd, min(16_384, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                value = json.loads(b"".join(chunks).decode("utf-8"))
                if value.get("schemaVersion") != PREFERENCES_SCHEMA_VERSION:
                    return dict(self.DEFAULTS)
                return self.normalize(value)
            except (WorkspaceError, OSError, ValueError, TypeError, AttributeError, UnicodeError):
                return self.normalize({})
            finally:
                for descriptor in reversed(descriptors):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    def write(self, value: object) -> dict:
        normalized = self.normalize(value)
        payload = {"schemaVersion": PREFERENCES_SCHEMA_VERSION, **normalized}
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            parent_fd = -1
            descriptor = -1
            temporary_name = self.path.name + f".tmp-{os.getpid()}-{time.time_ns()}"
            try:
                directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                parent_fd = os.open(self.path.parent, directory_flags)
                parent_metadata = os.fstat(parent_fd)
                if not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_uid != os.getuid():
                    raise WorkspaceError("preferences_insecure", "Workspace preferences directory is untrusted")
                if stat.S_IMODE(parent_metadata.st_mode) != 0o700:
                    os.fchmod(parent_fd, 0o700)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    descriptor = -1
                    json.dump(payload, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(
                    temporary_name,
                    self.path.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.fsync(parent_fd)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    if parent_fd >= 0:
                        os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                if parent_fd >= 0:
                    os.close(parent_fd)
            return normalized

    def update(self, patch: object) -> dict:
        current = self.read()
        if not isinstance(patch, dict):
            raise WorkspaceError("preferences_invalid", "Workspace preferences must be an object")
        allowed = set(self.DEFAULTS)
        current.update({key: patch[key] for key in patch if key in allowed})
        return self.write(current)


class WorkspaceService:
    """Build a bounded project/session tree and launch exact existing targets."""

    def __init__(
        self,
        *,
        home: str | Path | None = None,
        preferences_path: str | Path | None = None,
        codex_state_path: str | Path | None = None,
        claude_projects_path: str | Path | None = None,
        thread_loader: Callable[[], list[dict]] | None = None,
        board_command: list[str] | None = None,
        command_finder: Callable[[str], str | None] = shutil.which,
        launcher: Callable[[list[str], str | None], object] | None = None,
        brain_service=None,
        cache_seconds: float = 5.0,
    ):
        self.home = Path(home or Path.home()).expanduser().resolve()
        support = self.home / "Library" / "Application Support" / "KE Studios" / "Activity Monitor"
        self.preferences = WorkspacePreferences(preferences_path or support / "workspace-preferences.json")
        self.codex_state_path = Path(codex_state_path or self.home / ".codex" / ".codex-global-state.json")
        self.claude_projects_path = Path(claude_projects_path or self.home / ".claude" / "projects")
        self.thread_loader = thread_loader or self._load_codex_threads
        self.board_command = board_command if board_command is not None else [
            "/usr/bin/python3",
            str(self.home / "ke-agent-rooms" / "board" / "boardctl.py"),
            "status",
            "--event-limit",
            "0",
        ]
        self.command_finder = command_finder
        self.launcher = launcher or self._launch
        self.brain_service = brain_service
        self.cache_seconds = max(0.0, float(cache_seconds))
        self._lock = threading.RLock()
        self._cache: tuple[float, dict] | None = None
        self._open_index: dict[tuple[str, str], dict] = {}

    @staticmethod
    def _privacy() -> dict:
        return {
            "localOnly": True,
            "metadataOnly": True,
            "transcriptBodiesRead": False,
            "promptDraftsRead": False,
            "providerStateMutated": False,
            "providerDatabasesCopied": False,
            "credentialsRead": False,
            "preferencesMode": "0600",
            "openRequiresExplicitClick": True,
            "projectBrainsMetadataOnly": True,
            "projectBrainsAutoDelete": False,
        }

    @staticmethod
    def _brain_fields(association: dict | None, fallback_code: str | None = None) -> dict:
        child = association or {}
        return {
            "brainId": child.get("brainId"),
            "parentBrainId": child.get("parentBrainId"),
            "brainStatus": child.get("status") or ("unavailable" if fallback_code else "pending"),
            "brainLifecycleState": child.get("lifecycleState"),
            "brainErrorCode": child.get("errorCode") or fallback_code,
        }

    def _load_codex_state(self) -> dict:
        value = _selective_json_object(
            self.codex_state_path,
            CODEX_STATE_KEYS,
            max_bytes=MAX_GLOBAL_STATE_BYTES,
        )
        required = {
            "local-projects": dict,
            "project-order": list,
            "thread-project-assignments": dict,
            "sidebar-project-thread-orders": dict,
        }
        if not isinstance(value, dict) or any(not isinstance(value.get(key), kind) for key, kind in required.items()):
            raise WorkspaceError("codex_state_schema_invalid", "Codex project metadata has an unsupported schema")
        if value.get("projectless-thread-ids") is not None and not isinstance(value.get("projectless-thread-ids"), list):
            raise WorkspaceError("codex_state_schema_invalid", "Codex projectless task order has an unsupported schema")
        normalized = {
            key: value.get(key)
            for key in [*required, "pinned-thread-ids", "pinned-project-ids", "projectless-thread-ids"]
        }
        normalized["projectless-thread-ids"] = normalized.get("projectless-thread-ids") or []
        return normalized

    def _board_codex_states(self) -> dict[str, str]:
        if not self.board_command or not Path(self.board_command[0]).is_file():
            return {}
        try:
            result = subprocess.run(
                self.board_command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=2.5,
                check=False,
            )
            if result.returncode != 0 or len((result.stdout or "").encode("utf-8")) > 4 * 1024 * 1024:
                return {}
            payload = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError, TypeError):
            return {}
        states: dict[str, str] = {}
        for agent in payload.get("agents", []) if isinstance(payload, dict) else []:
            if not isinstance(agent, dict) or str(agent.get("provider") or "").lower() != "codex":
                continue
            endpoint = str(agent.get("endpoint") or "")
            if endpoint.startswith("codex:"):
                endpoint = endpoint[6:]
            if not UUID_RE.fullmatch(endpoint):
                continue
            try:
                observed = datetime.fromisoformat(str(agent.get("last_seen_at") or "").replace("Z", "+00:00"))
                if (datetime.now(tz=timezone.utc) - observed).total_seconds() > 900:
                    continue
            except (ValueError, TypeError):
                continue
            states[endpoint] = _safe_state(agent.get("status"))
        return states

    def _load_codex_threads(self) -> list[dict]:
        command = self._validated_executable(self.command_finder("codex"))
        if not command:
            return []
        client = CodexAppServerClient(command)
        rows: list[dict] = []
        try:
            client.start()
            cursor = None
            while len(rows) < MAX_CODEX_THREADS:
                params = {
                    "archived": False,
                    "limit": min(200, MAX_CODEX_THREADS - len(rows)),
                    "sortKey": "recency_at",
                    "sortDirection": "desc",
                    "useStateDbOnly": True,
                }
                if cursor:
                    params["cursor"] = cursor
                response = client.request("thread/list", params, timeout=8.0)
                page = response.get("data")
                if not isinstance(page, list):
                    break
                rows.extend(item for item in page if isinstance(item, dict))
                cursor = response.get("nextCursor")
                if not cursor or not page:
                    break
        finally:
            client.close()
        return rows[:MAX_CODEX_THREADS]

    @staticmethod
    def _thread_order(state: dict, project_id: str) -> list[str]:
        if project_id == "codex-unfiled":
            values = state.get("projectless-thread-ids")
            if not isinstance(values, list):
                return []
            return [str(item) for item in values if UUID_RE.fullmatch(str(item or ""))][:MAX_CODEX_THREADS]
        record = (state.get("sidebar-project-thread-orders") or {}).get(project_id)
        values = record.get("threadIds") if isinstance(record, dict) else record
        if not isinstance(values, list):
            return []
        return [str(item) for item in values if UUID_RE.fullmatch(str(item or ""))][:MAX_CODEX_THREADS]

    def _codex_projects(
        self,
        state: dict,
        raw_threads: list[dict],
        preferences: dict,
        owner_states: dict[str, str],
    ) -> tuple[list[dict], list[str], list[dict]]:
        warnings: list[str] = []
        projects = state["local-projects"]
        project_order = [
            str(item) for item in state["project-order"]
            if str(item) in projects and PROJECT_ID_RE.fullmatch(str(item))
        ][:MAX_CODEX_PROJECTS]
        omitted_projects = sorted(
            project_id
            for project_id in projects
            if project_id not in project_order and PROJECT_ID_RE.fullmatch(str(project_id or ""))
        )
        project_order.extend(omitted_projects[: max(0, MAX_CODEX_PROJECTS - len(project_order))])
        assignments = state["thread-project-assignments"]
        projectless = {
            str(item)
            for item in (state.get("projectless-thread-ids") or [])
            if UUID_RE.fullmatch(str(item or ""))
        }
        pinned = [str(item) for item in (state.get("pinned-thread-ids") or []) if UUID_RE.fullmatch(str(item or ""))]
        pinned_index = {thread_id: index + 1 for index, thread_id in enumerate(pinned)}
        pinned_projects = [
            str(item) for item in (state.get("pinned-project-ids") or [])
            if str(item) in projects and PROJECT_ID_RE.fullmatch(str(item))
        ]
        pinned_project_index = {project_id: index + 1 for index, project_id in enumerate(pinned_projects)}
        grouped: dict[str, list[dict]] = {project_id: [] for project_id in project_order}
        grouped["codex-unfiled"] = []

        for raw in raw_threads[:MAX_CODEX_THREADS]:
            thread_id = str(raw.get("id") or "")
            if not UUID_RE.fullmatch(thread_id):
                continue
            assignment_present = thread_id in assignments
            assignment = assignments.get(thread_id)
            project_id = None
            if not assignment_present and thread_id not in projectless:
                candidate = str(raw.get("projectId") or "")
                if candidate in projects:
                    project_id = candidate
            elif isinstance(assignment, dict) and assignment.get("projectKind") == "local":
                candidate = str(assignment.get("projectId") or "")
                if candidate in projects:
                    project_id = candidate
            project_id = project_id or "codex-unfiled"
            if project_id not in grouped:
                grouped[project_id] = []
                project_order.append(project_id)
            parent_id = str(raw.get("parentThreadId") or "")
            provider_state = _safe_state(raw.get("status"))
            owner_state = owner_states.get(thread_id)
            grouped[project_id].append(
                {
                    "id": thread_id,
                    "provider": "codex",
                    "title": _safe_label(raw.get("name") or raw.get("title"), f"Untitled task · {thread_id[:8]}"),
                    "state": owner_state or provider_state,
                    "stateSource": "Agent Board" if owner_state else "provider metadata",
                    "updatedAtEpoch": _epoch(raw.get("updatedAt") or raw.get("updated_at")),
                    "createdAtEpoch": _epoch(raw.get("createdAt") or raw.get("created_at")),
                    "parentId": parent_id if UUID_RE.fullmatch(parent_id) else None,
                    "depth": 0,
                    "pinned": thread_id in pinned_index,
                    "pinnedIndex": pinned_index.get(thread_id),
                    "canOpen": True,
                    "openLabel": "Open exact task in Codex",
                }
            )

        result: list[dict] = []
        expanded = set(preferences.get("expandedProjectIds") or [])
        for project_id in [*project_order, "codex-unfiled"]:
            if project_id in {item["id"] for item in result}:
                continue
            rows = grouped.get(project_id, [])
            explicit = self._thread_order(state, project_id)
            order = {thread_id: index for index, thread_id in enumerate(explicit)}
            rows.sort(key=lambda row: (order.get(row["id"], MAX_CODEX_THREADS), -row["updatedAtEpoch"], row["id"]))
            by_parent: dict[str, list[dict]] = {}
            ids = {row["id"] for row in rows}
            roots: list[dict] = []
            for row in rows:
                if row["parentId"] and row["parentId"] in ids:
                    by_parent.setdefault(row["parentId"], []).append(row)
                else:
                    roots.append(row)
            flattened: list[dict] = []
            visited: set[str] = set()

            def append_tree(row: dict, depth: int) -> None:
                if row["id"] in visited:
                    return
                visited.add(row["id"])
                item = dict(row)
                item["depth"] = min(depth, 4)
                flattened.append(item)
                for child in by_parent.get(row["id"], []):
                    append_tree(child, depth + 1)

            for row in roots:
                append_tree(row, 0)
            for row in rows:
                append_tree(row, 0)
            if project_id == "codex-unfiled":
                name = "Unfiled"
            else:
                record = projects.get(project_id)
                name = _safe_label(record.get("name") if isinstance(record, dict) else None, "Codex project")
            result.append(
                {
                    "id": project_id,
                    "provider": "codex",
                    "name": name,
                    "saved": True,
                    "pinned": project_id in pinned_project_index,
                    "pinnedIndex": pinned_project_index.get(project_id),
                    "expanded": project_id in expanded,
                    "conversationCount": len(flattened),
                    "activeCount": sum(row["state"] == "active" for row in flattened),
                    "conversations": flattened,
                }
            )
        available = [
            {
                "id": item["id"],
                "provider": "codex",
                "name": item["name"],
                "selected": preferences.get("visibleCodexProjectIds") is None
                or item["id"] in set(preferences.get("visibleCodexProjectIds") or []),
                "pinned": item["pinned"],
                "pinnedIndex": item["pinnedIndex"],
                "conversationCount": item["conversationCount"],
                "activeCount": item["activeCount"],
            }
            for item in result
        ]
        visible = preferences.get("visibleCodexProjectIds")
        if visible is not None:
            selected = set(visible)
            result = [item for item in result if item["id"] in selected]
        return result[: MAX_CODEX_PROJECTS + 1], warnings, available[: MAX_CODEX_PROJECTS + 1]

    def _claude_live_registry(self) -> dict[str, dict]:
        root = self.home / ".claude" / "sessions"
        root_fd = -1
        try:
            root_fd = self._open_private_directory(root)
            with os.scandir(root_fd) as iterator:
                names = sorted(
                    entry.name
                    for entry in iterator
                    if re.fullmatch(r"\d+\.json", entry.name)
                    and entry.is_file(follow_symlinks=False)
                )[:1_000]
        except (WorkspaceError, OSError):
            if root_fd >= 0:
                os.close(root_fd)
            return {}
        result: dict[str, dict] = {}
        try:
            for name in names:
                descriptor = -1
                try:
                    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(name, flags, dir_fd=root_fd)
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.getuid()
                        or stat.S_IMODE(metadata.st_mode) & 0o022
                        or metadata.st_size < 2
                        or metadata.st_size > MAX_CLAUDE_REGISTRY_BYTES
                    ):
                        continue
                    chunks: list[bytes] = []
                    remaining = MAX_CLAUDE_REGISTRY_BYTES + 1
                    while remaining > 0:
                        chunk = os.read(descriptor, min(16_384, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    raw = b"".join(chunks)
                    if len(raw) > MAX_CLAUDE_REGISTRY_BYTES:
                        continue
                    record = json.loads(raw.decode("utf-8"))
                    session_id = str(record.get("sessionId") or "")
                    if (
                        not UUID_RE.fullmatch(session_id)
                        or record.get("kind") != "interactive"
                        or record.get("peerProtocol") != 1
                    ):
                        continue
                    pid = int(record.get("pid") or 0)
                    if pid <= 1:
                        continue
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        continue
                    socket_path = Path(str(record.get("messagingSocketPath") or ""))
                    if not socket_path.is_absolute():
                        continue
                    try:
                        socket_metadata = socket_path.lstat()
                    except OSError:
                        continue
                    if (
                        not stat.S_ISSOCK(socket_metadata.st_mode)
                        or socket_metadata.st_uid != os.getuid()
                        or stat.S_IMODE(socket_metadata.st_mode) & 0o077
                    ):
                        continue
                    cwd = str(record.get("cwd") or "")
                    result[session_id] = {
                        "cwd": cwd if cwd.startswith("/") and "\x00" not in cwd else "",
                    }
                except (OSError, ValueError, TypeError, AttributeError, UnicodeError):
                    continue
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
        finally:
            if root_fd >= 0:
                os.close(root_fd)
        return result

    @staticmethod
    def _open_private_directory(path: str | Path, *, dir_fd: int | None = None) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, dir_fd=dir_fd)
        except OSError as error:
            raise WorkspaceError("metadata_unavailable", "Claude project metadata changed or is unavailable") from error
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            os.close(descriptor)
            raise WorkspaceError("metadata_insecure", "Claude project metadata is not a private current-user directory")
        return descriptor

    def _claude_projects(self, preferences: dict) -> tuple[list[dict], list[dict], list[str], dict[str, dict]]:
        warnings: list[str] = []
        saved = set(preferences["savedClaudeProjectIds"])
        saved_keys = {
            project_id: key
            for project_id, key in (preferences.get("savedClaudeProjectKeys") or {}).items()
            if project_id in saved
        }
        global_scan_remaining = MAX_CLAUDE_GLOBAL_SCAN_ENTRIES
        global_scan_capped = False
        root_fd = -1
        try:
            root_fd = self._open_private_directory(self.claude_projects_path)
            with os.scandir(root_fd) as iterator:
                directory_names: list[str] = list(saved_keys.values())
                seen_directory_names = set(directory_names)
                scanned = 0
                capped = False
                for entry in iterator:
                    global_scan_remaining -= 1
                    if global_scan_remaining < 0:
                        global_scan_capped = True
                        capped = True
                        break
                    scanned += 1
                    if scanned > MAX_CLAUDE_PROJECT_SCAN_ENTRIES:
                        capped = True
                        break
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name in seen_directory_names:
                            continue
                        directory_names.append(entry.name)
                        seen_directory_names.add(entry.name)
                if capped:
                    warnings.append(
                        f"Claude project scan is capped at {MAX_CLAUDE_PROJECT_SCAN_ENTRIES} metadata entries"
                    )
        except WorkspaceError as error:
            if root_fd >= 0:
                os.close(root_fd)
            return [], [], [str(error)], {}
        except OSError:
            if root_fd >= 0:
                os.close(root_fd)
            return [], [], ["Claude project metadata is unavailable"], {}
        directory_names.sort(
            key=lambda name: (
                "claude-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:24] not in saved,
                name.lower(),
                name,
            )
        )
        if len(directory_names) > MAX_CLAUDE_PROJECTS:
            warnings.append(
                f"Claude project catalog is capped at {MAX_CLAUDE_PROJECTS}; saved projects are retained first"
            )
            directory_names = directory_names[:MAX_CLAUDE_PROJECTS]
        live = self._claude_live_registry()
        projects: list[dict] = []
        available: list[dict] = []
        open_index: dict[str, dict] = {}
        remaining = MAX_CLAUDE_SESSIONS
        configured_directories = preferences.get("claudeProjectDirectories") or {}
        detected_saved_count = sum(
            1
            for name in directory_names
            if "claude-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:24] in saved
        )
        saved_quota = max(1, MAX_CLAUDE_SESSIONS // max(1, detected_saved_count))
        try:
            for encoded_name in directory_names:
                if remaining <= 0 or global_scan_remaining <= 0:
                    if global_scan_remaining <= 0:
                        global_scan_capped = True
                    warnings.append(f"Claude session catalog is capped at {MAX_CLAUDE_SESSIONS} metadata rows")
                    break
                project_fd = -1
                try:
                    project_fd = self._open_private_directory(encoded_name, dir_fd=root_fd)
                    with os.scandir(project_fd) as iterator:
                        file_rows = []
                        scanned = 0
                        for entry in iterator:
                            global_scan_remaining -= 1
                            if global_scan_remaining < 0:
                                global_scan_capped = True
                                break
                            scanned += 1
                            if scanned > MAX_CLAUDE_SESSION_SCAN_ENTRIES:
                                warnings.append(
                                    f"Claude session scan for {_safe_label(encoded_name, 'project')} is capped at "
                                    f"{MAX_CLAUDE_SESSION_SCAN_ENTRIES} metadata entries"
                                )
                                break
                            match = re.fullmatch(r"([0-9a-f-]{36})\.jsonl", entry.name, flags=re.IGNORECASE)
                            if not match or not entry.is_file(follow_symlinks=False):
                                continue
                            metadata = entry.stat(follow_symlinks=False)
                            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                                continue
                            file_rows.append((entry.name, match.group(1).lower(), metadata.st_mtime))
                    file_rows.sort(key=lambda row: (-row[2], row[0]))
                except (WorkspaceError, OSError):
                    continue
                finally:
                    if project_fd >= 0:
                        os.close(project_fd)
                project_id = "claude-" + hashlib.sha256(encoded_name.encode("utf-8")).hexdigest()[:24]
                configured_cwd = self._validated_project_directory(configured_directories.get(project_id))
                sessions: list[dict] = []
                friendly_name = Path(configured_cwd).name if configured_cwd else ""
                project_limit = min(remaining, saved_quota if project_id in saved else remaining)
                for _filename, session_id, modified in file_rows[:project_limit]:
                    if not UUID_RE.fullmatch(session_id):
                        continue
                    session_live = live.get(session_id) or {}
                    cwd = self._validated_project_directory(session_live.get("cwd")) or configured_cwd
                    if cwd and not friendly_name:
                        friendly_name = Path(cwd).name
                    state = "active" if session_id in live else "inactive"
                    can_resume = state == "inactive" and bool(cwd)
                    sessions.append(
                        {
                            "id": session_id,
                            "provider": "claude",
                            "title": f"Claude session · {session_id[:8]}",
                            "state": state,
                            "stateSource": "live private session registry" if state == "active" else "session file metadata",
                            "updatedAtEpoch": max(0.0, float(modified)),
                            "createdAtEpoch": 0.0,
                            "parentId": None,
                            "depth": 0,
                            "pinned": False,
                            "pinnedIndex": None,
                            "canOpen": can_resume,
                            "canDispatch": state == "active",
                            "openLabel": (
                                "Active in an existing Terminal; use that Terminal to avoid a duplicate owner"
                                if state == "active"
                                else "Resume exact session in Claude Code"
                                if can_resume
                                else "Choose this Claude project's folder to enable exact resume"
                            ),
                        }
                    )
                    open_index[session_id] = {"cwd": cwd, "projectId": project_id}
                remaining -= len(sessions)
                if not sessions:
                    continue
                name = _safe_label(
                    friendly_name or encoded_name.lstrip("-"),
                    f"Claude project · {project_id[-6:]}",
                )
                item = {
                    "id": project_id,
                    "provider": "claude",
                    "name": name,
                    "saved": project_id in saved,
                    "pinned": False,
                    "pinnedIndex": None,
                    "expanded": project_id in set(preferences.get("expandedProjectIds") or []),
                    "conversationCount": len(sessions),
                    "activeCount": sum(row["state"] == "active" for row in sessions),
                    "conversations": sessions,
                }
                available.append({key: item[key] for key in ("id", "provider", "name", "saved", "conversationCount", "activeCount")})
                available[-1].update({
                    "storageKey": encoded_name,
                    "directoryMapped": bool(configured_cwd),
                })
                if item["saved"]:
                    projects.append(item)
        finally:
            if root_fd >= 0:
                os.close(root_fd)
        if global_scan_capped:
            warnings.append(
                f"Claude metadata scanning is globally capped at {MAX_CLAUDE_GLOBAL_SCAN_ENTRIES} entries"
            )
        available.sort(key=lambda item: (not item["saved"], item["name"].lower(), item["id"]))
        projects.sort(key=lambda item: (item["name"].lower(), item["id"]))
        return projects, available, warnings, open_index

    def _companion_version(self, command: str | None) -> str | None:
        if not command:
            return None
        try:
            result = subprocess.run(
                [command, "--version"], stdin=subprocess.DEVNULL, capture_output=True,
                text=True, timeout=1.5, check=False,
            )
            lines = (result.stdout or result.stderr).splitlines()
            return _safe_label(lines[0], "unknown") if result.returncode == 0 and lines else None
        except (OSError, subprocess.SubprocessError, IndexError):
            return None

    @staticmethod
    def _validated_project_directory(value: object) -> str | None:
        candidate = str(value or "")
        if not candidate.startswith("/") or "\x00" in candidate:
            return None
        try:
            path = Path(candidate).resolve(strict=True)
            metadata = path.stat()
        except OSError:
            return None
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            return None
        return str(path)

    @staticmethod
    def _claude_storage_key(directory: str) -> str:
        return re.sub(r"[^A-Za-z0-9]", "-", directory)

    @staticmethod
    def _claude_resume_supported(command: str | None) -> bool:
        if not command:
            return False
        try:
            result = subprocess.run(
                [command, "--help"], stdin=subprocess.DEVNULL, capture_output=True,
                text=True, timeout=2.0, check=False,
            )
            help_text = (result.stdout or result.stderr)[:256_000]
            return result.returncode == 0 and "--resume" in help_text and "session ID" in help_text
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _validated_executable(command: str | None) -> str | None:
        if not command:
            return None
        try:
            path = Path(command).expanduser().resolve(strict=True)
            metadata = path.stat()
        except OSError:
            return None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.getuid()}
            or metadata.st_mode & 0o022
            or not os.access(path, os.X_OK)
        ):
            return None
        return str(path)

    def _companions(self) -> dict:
        codex = self._validated_executable(self.command_finder("codex"))
        claude = self._validated_executable(self.command_finder("claude"))
        chatgpt_app = Path("/Applications/ChatGPT.app").is_dir() if sys.platform == "darwin" else False
        visible_terminal = sys.platform == "darwin" and Path("/usr/bin/osascript").is_file()
        claude_resume = self._claude_resume_supported(claude)
        return {
            "codex": {
                "installed": bool(codex or chatgpt_app),
                "cliInstalled": bool(codex),
                "appInstalled": bool(chatgpt_app),
                "version": self._companion_version(codex),
                "exactOpenAvailable": bool(sys.platform == "darwin" and Path("/usr/bin/open").is_file() and chatgpt_app),
                "remediation": None if codex or chatgpt_app else "Install and sign in to Codex or the ChatGPT desktop app.",
            },
            "claude": {
                "installed": bool(claude),
                "cliInstalled": bool(claude),
                "version": self._companion_version(claude),
                "exactOpenAvailable": bool(claude and visible_terminal and claude_resume),
                "remediation": (
                    None if claude and visible_terminal and claude_resume
                    else "Install and sign in to Claude Code; a supported visible terminal launcher is also required."
                ),
            },
        }

    def snapshot(self, force: bool = False) -> dict:
        with self._lock:
            now = time.monotonic()
            if not force and self._cache and now - self._cache[0] < self.cache_seconds:
                return json.loads(json.dumps(self._cache[1]))
        preferences = self.preferences.read()
        warnings: list[str] = []
        codex_projects: list[dict] = []
        available_codex: list[dict] = []
        try:
            state = self._load_codex_state()
            codex_projects, codex_warnings, available_codex = self._codex_projects(
                state,
                self.thread_loader(),
                preferences,
                self._board_codex_states(),
            )
            warnings.extend(codex_warnings)
        except (WorkspaceError, DispatchError, OSError, subprocess.SubprocessError) as error:
            warnings.append(_safe_label(error, "Codex metadata is unavailable"))
        claude_projects, available_claude, claude_warnings, claude_open = self._claude_projects(preferences)
        warnings.extend(claude_warnings)
        projects = [*codex_projects, *claude_projects]
        project_brains = {
            "ok": False,
            "byProject": {},
            "counts": {"total": 0, "active": 0, "dormant": 0, "blocked": 0},
            "code": "project_brains_not_attached",
        }
        if self.brain_service is not None:
            project_brains = self.brain_service.sync_project_brains([
                {
                    "provider": project["provider"],
                    "projectId": project["id"],
                    "label": project["name"],
                }
                for project in projects
                if project["id"] != "codex-unfiled"
            ])
            if not project_brains.get("ok"):
                warnings.append("Project Brains are unavailable until the canonical KE Brain can be verified")
            elif project_brains.get("errors"):
                warnings.append(
                    f"{len(project_brains['errors'])} Project Brain operation(s) failed closed"
                )
        brain_index = project_brains.get("byProject") if isinstance(project_brains.get("byProject"), dict) else {}
        fallback_brain_code = None if project_brains.get("ok") else str(project_brains.get("code") or "project_brains_unavailable")

        def attach_brain(item: dict) -> None:
            key = f"{item.get('provider')}:{str(item.get('id') or '').lower()}"
            association = brain_index.get(key)
            fields = self._brain_fields(association, fallback_brain_code)
            item.update(fields)
            for conversation in item.get("conversations") or []:
                conversation.update({
                    "projectId": item["id"],
                    "projectName": item["name"],
                    "brainId": fields["brainId"],
                    "parentBrainId": fields["parentBrainId"],
                })

        for project in projects:
            attach_brain(project)
        for available in [*available_codex, *available_claude]:
            key = f"{available.get('provider')}:{str(available.get('id') or '').lower()}"
            available.update(self._brain_fields(brain_index.get(key), fallback_brain_code))
        filters = preferences["providerFilters"]
        projects = [item for item in projects if filters.get(item["provider"], True)]
        companions = self._companions()
        open_index: dict[tuple[str, str], dict] = {}
        for project in projects:
            for conversation in project["conversations"]:
                if not conversation.get("canOpen", True):
                    continue
                if project["provider"] == "codex":
                    open_index[("codex", conversation["id"])] = {"projectId": project["id"]}
                else:
                    open_index[("claude", conversation["id"])] = {
                        "projectId": project["id"], **claude_open.get(conversation["id"], {})
                    }
        payload = {
            "ok": True,
            "schemaVersion": SCHEMA_VERSION,
            "observedAt": _utc_now(),
            "projects": projects,
            "availableCodexProjects": available_codex,
            "availableClaudeProjects": available_claude,
            "companions": companions,
            "preferences": preferences,
            "counts": {
                "projects": len(projects),
                "conversations": sum(item["conversationCount"] for item in projects),
                "active": sum(item["activeCount"] for item in projects),
                "projectBrains": int((project_brains.get("counts") or {}).get("total") or 0),
                "activeProjectBrains": int((project_brains.get("counts") or {}).get("active") or 0),
                "dormantProjectBrains": int((project_brains.get("counts") or {}).get("dormant") or 0),
            },
            "projectBrainRegistryRevision": project_brains.get("registryRevision"),
            "warnings": warnings[:8],
            "privacy": self._privacy(),
        }
        with self._lock:
            self._open_index = open_index
            self._cache = (time.monotonic(), payload)
        return json.loads(json.dumps(payload))

    def routing_index(self, force: bool = False, cached_only: bool = False) -> dict[str, dict]:
        """Return only exact project/Brain associations for visible conversations."""
        if cached_only:
            with self._lock:
                if self._cache is None:
                    return {}
        snapshot = self.snapshot(force=force)
        index: dict[str, dict] = {}
        for project in snapshot.get("projects", []):
            association = {
                "provider": project.get("provider"),
                "projectId": project.get("id"),
                "projectName": project.get("name"),
                "brainId": project.get("brainId"),
                "parentBrainId": project.get("parentBrainId"),
                "brainStatus": project.get("brainStatus"),
            }
            for conversation in project.get("conversations", []):
                conversation_id = str(conversation.get("id") or "")
                if UUID_RE.fullmatch(conversation_id):
                    index[conversation_id] = dict(association)
        return index

    def update_preferences(self, patch: object) -> dict:
        updated = self.preferences.update(patch)
        with self._lock:
            self._cache = None
        return {"ok": True, "schemaVersion": SCHEMA_VERSION, "preferences": updated, "privacy": self._privacy()}

    def flagship_ui_preferences(self) -> dict:
        preferences = self.preferences.read()
        return {
            "ok": True,
            "schemaVersion": FLAGSHIP_PREFERENCES_SCHEMA_VERSION,
            "collapsedTabs": list(preferences.get("collapsedCapabilityTabs") or []),
            "storage": "private-local-preferences",
        }

    def set_flagship_fabric_collapsed(self, tab: str, collapsed: bool) -> dict:
        token = str(tab or "")
        if token not in FLAGSHIP_CAPABILITY_TABS:
            raise WorkspaceError("preferences_invalid", "That capability section cannot store a view preference")
        preferences = self.preferences.read()
        collapsed_tabs = set(preferences.get("collapsedCapabilityTabs") or [])
        if collapsed:
            collapsed_tabs.add(token)
        else:
            collapsed_tabs.discard(token)
        updated = self.preferences.update({
            "collapsedCapabilityTabs": [
                item for item in FLAGSHIP_CAPABILITY_TABS if item in collapsed_tabs
            ]
        })
        return {
            "ok": True,
            "schemaVersion": FLAGSHIP_PREFERENCES_SCHEMA_VERSION,
            "collapsedTabs": list(updated.get("collapsedCapabilityTabs") or []),
            "storage": "private-local-preferences",
        }

    def set_claude_project_saved(self, project_id: str, saved: bool) -> dict:
        token = str(project_id or "")
        snapshot = self.snapshot(force=True)
        available = {item["id"] for item in snapshot["availableClaudeProjects"]}
        if token not in available or not token.startswith("claude-"):
            raise WorkspaceError("claude_project_unknown", "Choose a currently detected Claude project")
        preferences = snapshot["preferences"]
        selected = list(preferences["savedClaudeProjectIds"])
        project_keys = dict(preferences.get("savedClaudeProjectKeys") or {})
        candidate = next((item for item in snapshot["availableClaudeProjects"] if item["id"] == token), None)
        if saved and token not in selected:
            selected.append(token)
        if saved and candidate:
            project_keys[token] = str(candidate.get("storageKey") or "")
        if not saved:
            selected = [item for item in selected if item != token]
            project_keys.pop(token, None)
        self.preferences.update({"savedClaudeProjectIds": selected, "savedClaudeProjectKeys": project_keys})
        with self._lock:
            self._cache = None
        return self.snapshot(force=True)

    def set_claude_project_directory(self, project_id: str, directory: str) -> dict:
        token = str(project_id or "")
        snapshot = self.snapshot(force=True)
        available = {item["id"] for item in snapshot["availableClaudeProjects"]}
        if token not in available or not token.startswith("claude-"):
            raise WorkspaceError("claude_project_unknown", "Choose a currently detected Claude project")
        validated = self._validated_project_directory(directory)
        if not validated:
            raise WorkspaceError(
                "claude_project_directory_invalid",
                "Choose an existing current-user project folder for this Claude project",
            )
        candidate = next(
            (item for item in snapshot["availableClaudeProjects"] if item["id"] == token),
            None,
        )
        storage_key = self._claude_storage_key(validated)
        derived_id = "claude-" + hashlib.sha256(storage_key.encode("utf-8")).hexdigest()[:24]
        if not candidate or candidate.get("storageKey") != storage_key or derived_id != token:
            raise WorkspaceError(
                "claude_project_directory_mismatch",
                "That folder does not match the selected Claude project metadata key",
            )
        mappings = dict(snapshot["preferences"].get("claudeProjectDirectories") or {})
        mappings[token] = validated
        self.preferences.update({"claudeProjectDirectories": mappings})
        with self._lock:
            self._cache = None
        return self.snapshot(force=True)

    @staticmethod
    def _launch(args: list[str], cwd: str | None) -> object:
        return subprocess.Popen(
            args,
            cwd=cwd or None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )

    def open_conversation(self, provider: str, conversation_id: str) -> dict:
        provider = str(provider or "").lower()
        conversation_id = str(conversation_id or "").lower()
        if provider not in {"codex", "claude"} or not UUID_RE.fullmatch(conversation_id):
            raise WorkspaceError("conversation_identity_invalid", "Choose one exact visible conversation")
        self.snapshot(force=True)
        with self._lock:
            target = dict(self._open_index.get((provider, conversation_id)) or {})
        if not target:
            raise WorkspaceError("conversation_stale", "That conversation is no longer in the current visible project set")
        if provider == "codex":
            opener = "/usr/bin/open"
            if sys.platform != "darwin" or not Path(opener).is_file():
                raise WorkspaceError("codex_native_open_unavailable", "Exact Codex opening is unavailable on this system")
            args = [opener, f"codex://threads/{conversation_id}"]
            cwd = None
            mode = "codex-url-scheme"
        else:
            command = self._validated_executable(self.command_finder("claude"))
            if not command:
                raise WorkspaceError("claude_cli_unavailable", "Install and sign in to Claude Code before resuming this session")
            if not self._claude_resume_supported(command):
                raise WorkspaceError(
                    "claude_exact_resume_unsupported",
                    "The installed Claude Code CLI does not advertise exact session-ID resume support",
                )
            if sys.platform != "darwin" or not Path("/usr/bin/osascript").is_file():
                raise WorkspaceError(
                    "claude_visible_terminal_unavailable",
                    "This build has no supported visible terminal adapter for Claude Code",
                )
            cwd_value = str(target.get("cwd") or "")
            cwd = cwd_value if cwd_value and Path(cwd_value).is_absolute() and Path(cwd_value).is_dir() else None
            if not cwd:
                raise WorkspaceError(
                    "claude_project_directory_required",
                    "Choose this Claude project's folder before resuming an inactive session",
                )
            args = [
                "/usr/bin/osascript",
                "-e", "on run argv",
                "-e", "set cliPath to item 1 of argv",
                "-e", "set projectPath to item 2 of argv",
                "-e", "set sessionId to item 3 of argv",
                "-e", 'set commandText to "cd -- " & quoted form of projectPath & " && exec " & quoted form of cliPath & " --resume " & quoted form of sessionId',
                "-e", 'tell application "Terminal" to activate',
                "-e", 'tell application "Terminal" to do script commandText',
                "-e", "end run",
                "--",
                command,
                cwd,
                conversation_id,
            ]
            cwd = None
            mode = "claude-visible-terminal-resume"
        try:
            self.launcher(args, cwd)
        except (OSError, subprocess.SubprocessError) as error:
            raise WorkspaceError("native_open_failed", "The companion app could not be launched") from error
        preferences = self.preferences.read()
        preferences["lastSelected"] = {
            "provider": provider,
            "projectId": target.get("projectId"),
            "conversationId": conversation_id,
        }
        self.preferences.write(preferences)
        with self._lock:
            self._cache = None
        return {
            "ok": True,
            "schemaVersion": SCHEMA_VERSION,
            "state": "launch requested",
            "provider": provider,
            "conversationId": conversation_id,
            "projectId": target.get("projectId"),
            "launchMode": mode,
            "nativeDestinationVerified": False,
            "privacy": self._privacy(),
        }
