"""Project-scoped embedded conversations and a full-access local Conductor.

This module deliberately has no UI dependency.  It provides the bounded service
surface needed by Activity Monitor to:

* read an exact visible Codex or Claude conversation only after an explicit
  host-mode click;
* send to that exact conversation without provider substitution;
* route a project request to a verified existing owner, or create exactly one
  project-scoped Conductor / PowerSwarm task when no suitable task exists; and
* retain only mode-0600, body-free idempotency and delivery receipts locally.

Provider transcripts remain the durable source of truth.  Message bodies are
never written to Activity Monitor's support directory.
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
import threading
import time
from typing import Callable
import uuid

from dispatch_router import (
    CodexAppServerClient,
    DesktopIpcClient,
    DispatchError,
    OWNER_DISCOVERY_FALLBACK_CODES,
    UUID_RE,
)


SCHEMA_VERSION = "ke.activity-monitor-conversation-host.v1"
STORE_SCHEMA_VERSION = "ke.activity-monitor-conversation-host-receipts.v1"
MAX_MESSAGE_BYTES = 900_000
MAX_STORE_BYTES = 512 * 1024
MAX_RECEIPTS = 256
MAX_MAPPINGS = 256
MAX_CREATION_GUARDS = 256
MAX_TRANSCRIPT_ITEMS = 240
MAX_TRANSCRIPT_TEXT_BYTES = 1_500_000
MAX_ITEM_TEXT_CHARS = 24_000
MAX_CLAUDE_TRANSCRIPT_BYTES = 8 * 1024 * 1024
RECONCILIATION_WINDOW_SECONDS = 24 * 60 * 60
AUTHORITATIVE_ACTIVE_SOURCES = {
    "agent board",
    "live private session registry",
    "activity monitor conductor",
}
ROUTING_STOP_WORDS = {
    "about", "after", "again", "also", "and", "are", "can", "could", "for",
    "from", "have", "into", "make", "please", "project", "request", "should",
    "that", "the", "then", "this", "through", "want", "with", "would", "you",
    "your",
}
POWERSWARM_RE = re.compile(r"\b(?:power\s*swarm|powerswarm|swarm)\b", re.IGNORECASE)
PUBLIC_RECEIPT_FIELDS = {
    "requestId", "projectKey", "provider", "destinationId", "destinationProvider",
    "routeKind", "state", "phase", "deliveryAttempted", "retrySafe",
    "reconciliationRequired", "clientUserMessageId", "turnId", "providerMessageId",
    "threadId", "creationRequestId", "code", "timestamp",
}


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_text(value: object, fallback: str = "Conversation operation failed", limit: int = 320) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] or fallback


def _safe_label(value: object, fallback: str, limit: int = 180) -> str:
    return _safe_text(value, fallback, limit)


def _tokens(value: object) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9][a-z0-9._+-]{2,}", str(value or "").lower())
        if token not in ROUTING_STOP_WORDS and not UUID_RE.fullmatch(token)
    }


def _epoch(value: object) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        result = float(value)
        return result / 1000.0 if result > 10_000_000_000 else max(0.0, result)
    if isinstance(value, str) and value:
        try:
            return max(0.0, datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
        except ValueError:
            return 0.0
    return 0.0


def _validated_executable(value: object) -> str | None:
    candidate = str(value or "")
    if not candidate or "\x00" in candidate:
        return None
    try:
        path = Path(candidate).expanduser().resolve(strict=True)
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


def _safe_public_receipt(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    result: dict[str, object] = {}
    for key in PUBLIC_RECEIPT_FIELDS:
        item = value.get(key)
        if isinstance(item, bool):
            result[key] = item
        elif isinstance(item, str) and item:
            cleaned = _safe_text(item, "", 320)
            if cleaned:
                result[key] = cleaned
    return result


class ConversationHostError(RuntimeError):
    """Safe error carrying the delivery phase without retaining message text."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        phase: str = "resolving",
        delivery_attempted: bool = False,
        retry_safe: bool | None = None,
        reconciliation_required: bool | None = None,
        receipt: dict | None = None,
    ):
        super().__init__(_safe_text(message))
        self.code = str(code or "conversation_host_failed")[:96]
        self.phase = str(phase or "resolving")[:64]
        self.delivery_attempted = bool(delivery_attempted)
        self.retry_safe = (not self.delivery_attempted) if retry_safe is None else bool(retry_safe)
        self.reconciliation_required = (
            self.delivery_attempted
            if reconciliation_required is None
            else bool(reconciliation_required)
        )
        self.receipt = dict(receipt or {})

    def public(self) -> dict:
        result = {
            "ok": False,
            "schemaVersion": SCHEMA_VERSION,
            "code": self.code,
            "error": str(self),
            "phase": self.phase,
            "deliveryAttempted": self.delivery_attempted,
            "retrySafe": self.retry_safe,
            "reconciliationRequired": self.reconciliation_required,
        }
        receipt = _safe_public_receipt(self.receipt)
        if receipt:
            result["receipt"] = receipt
        return result


class ReceiptStore:
    """Descriptor-bound, bounded, body-free delivery metadata."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self._lock = threading.RLock()

    @staticmethod
    def defaults() -> dict:
        return {
            "schemaVersion": STORE_SCHEMA_VERSION,
            "mappings": {},
            "creationGuards": {},
            "receipts": [],
        }

    @staticmethod
    def _safe_mapping_key(value: object) -> str | None:
        token = str(value or "")
        if 1 <= len(token) <= 320 and re.fullmatch(r"[A-Za-z0-9:._-]+", token):
            return token
        return None

    @classmethod
    def normalize(cls, value: object) -> dict:
        source = value if isinstance(value, dict) else {}
        mappings: dict[str, str] = {}
        raw_mappings = source.get("mappings")
        if isinstance(raw_mappings, dict):
            for raw_key, raw_id in raw_mappings.items():
                key = cls._safe_mapping_key(raw_key)
                thread_id = str(raw_id or "").lower()
                if key and UUID_RE.fullmatch(thread_id) and len(mappings) < MAX_MAPPINGS:
                    mappings[key] = thread_id
        creation_guards: dict[str, dict] = {}
        raw_guards = source.get("creationGuards")
        if isinstance(raw_guards, dict):
            for raw_key, raw_guard in raw_guards.items():
                key = cls._safe_mapping_key(raw_key)
                if not key or not isinstance(raw_guard, dict) or len(creation_guards) >= MAX_CREATION_GUARDS:
                    continue
                request_id = str(raw_guard.get("requestId") or "").lower()
                state = str(raw_guard.get("state") or "")
                timestamp = str(raw_guard.get("timestamp") or "")[:64]
                if UUID_RE.fullmatch(request_id) and state in {"attempting", "uncertain"} and timestamp:
                    creation_guards[key] = {
                        "requestId": request_id,
                        "state": state,
                        "timestamp": timestamp,
                    }
        receipts: list[dict] = []
        for raw in source.get("receipts", []) if isinstance(source.get("receipts"), list) else []:
            if not isinstance(raw, dict) or len(receipts) >= MAX_RECEIPTS:
                continue
            request_id = str(raw.get("requestId") or "").lower()
            digest = str(raw.get("sha256") or "").lower()
            project_key = cls._safe_mapping_key(raw.get("projectKey"))
            destination_id = str(raw.get("destinationId") or "").lower()
            if (
                not UUID_RE.fullmatch(request_id)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not project_key
                or (destination_id and not UUID_RE.fullmatch(destination_id))
            ):
                continue
            receipt = {
                "requestId": request_id,
                "sha256": digest,
                "projectKey": project_key,
                "provider": str(raw.get("provider") or "")[:16],
                "destinationId": destination_id or None,
                "destinationProvider": str(raw.get("destinationProvider") or "")[:16] or None,
                "routeKind": str(raw.get("routeKind") or "")[:64] or None,
                "state": str(raw.get("state") or "")[:64],
                "phase": str(raw.get("phase") or "")[:64],
                "deliveryAttempted": raw.get("deliveryAttempted") is True,
                "retrySafe": raw.get("retrySafe") is True,
                "reconciliationRequired": raw.get("reconciliationRequired") is True,
                "timestamp": str(raw.get("timestamp") or "")[:64],
                "instanceId": (
                    str(raw.get("instanceId") or "").lower()
                    if UUID_RE.fullmatch(str(raw.get("instanceId") or ""))
                    else None
                ),
                "clientUserMessageId": (
                    str(raw.get("clientUserMessageId") or "").lower()
                    if UUID_RE.fullmatch(str(raw.get("clientUserMessageId") or ""))
                    else None
                ),
                "turnId": (
                    str(raw.get("turnId") or "").lower()
                    if UUID_RE.fullmatch(str(raw.get("turnId") or ""))
                    else None
                ),
                "providerMessageId": (
                    str(raw.get("providerMessageId") or "").lower()
                    if UUID_RE.fullmatch(str(raw.get("providerMessageId") or ""))
                    else None
                ),
                "code": str(raw.get("code") or "")[:96] or None,
            }
            receipts.append(receipt)
        return {
            "schemaVersion": STORE_SCHEMA_VERSION,
            "mappings": mappings,
            "creationGuards": creation_guards,
            "receipts": receipts[:MAX_RECEIPTS],
        }

    @staticmethod
    def _validate_parent(metadata: os.stat_result) -> None:
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ConversationHostError(
                "receipt_store_insecure",
                "The conversation receipt directory is not a trusted current-user directory",
                phase="local receipt",
            )

    def _open_parent(self, *, create: bool) -> int:
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path.parent, flags)
        except OSError as error:
            raise ConversationHostError(
                "receipt_store_unavailable",
                "The conversation receipt directory cannot be opened safely",
                phase="local receipt",
            ) from error
        try:
            self._validate_parent(os.fstat(descriptor))
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    def read(self) -> dict:
        with self._lock:
            if not self.path.parent.exists():
                return self.defaults()
            parent_fd = -1
            descriptor = -1
            try:
                parent_fd = self._open_parent(create=False)
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(self.path.name, flags, dir_fd=parent_fd)
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size < 2
                    or metadata.st_size > MAX_STORE_BYTES
                ):
                    raise ConversationHostError(
                        "receipt_store_insecure",
                        "Conversation receipts must be a bounded current-user mode-0600 file",
                        phase="local receipt",
                    )
                chunks: list[bytes] = []
                remaining = metadata.st_size
                while remaining > 0:
                    chunk = os.read(descriptor, min(16_384, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                value = json.loads(b"".join(chunks).decode("utf-8"))
                if value.get("schemaVersion") != STORE_SCHEMA_VERSION:
                    return self.defaults()
                return self.normalize(value)
            except FileNotFoundError:
                return self.defaults()
            except ConversationHostError:
                raise
            except (OSError, ValueError, TypeError, AttributeError, UnicodeError) as error:
                raise ConversationHostError(
                    "receipt_store_unreadable",
                    "Conversation receipts could not be read safely",
                    phase="local receipt",
                ) from error
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                if parent_fd >= 0:
                    os.close(parent_fd)

    def write(self, value: object) -> dict:
        normalized = self.normalize(value)
        encoded = (json.dumps(normalized, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > MAX_STORE_BYTES:
            raise ConversationHostError(
                "receipt_store_too_large",
                "Conversation receipt metadata reached its bounded size limit",
                phase="local receipt",
            )
        with self._lock:
            parent_fd = self._open_parent(create=True)
            descriptor = -1
            temporary_name = f".{self.path.name}.tmp-{os.getpid()}-{time.time_ns()}"
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
                os.fchmod(descriptor, 0o600)
                offset = 0
                while offset < len(encoded):
                    offset += os.write(descriptor, encoded[offset:])
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                os.replace(temporary_name, self.path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                os.fsync(parent_fd)
                return normalized
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                os.close(parent_fd)

    def mutate(self, callback: Callable[[dict], object]) -> object:
        with self._lock:
            value = self.read()
            result = callback(value)
            self.write(value)
            return result


class CodexConversationTransport:
    """Exact Codex read/send/create transport with no fallback after send."""

    def __init__(
        self,
        command: str | None = None,
        *,
        desktop_ipc_path: str | Path | None = None,
        desktop_ipc_factory=DesktopIpcClient,
        client_factory=CodexAppServerClient,
        monitor_seconds: float = 6 * 60 * 60,
    ):
        self.command = _validated_executable(command or shutil.which("codex"))
        self.desktop_ipc_path = Path(desktop_ipc_path or Path.home() / ".codex" / "ipc" / "ipc.sock")
        self.desktop_ipc_factory = desktop_ipc_factory
        self.client_factory = client_factory
        self.monitor_seconds = max(0.05, float(monitor_seconds))
        self._active_lock = threading.RLock()
        self._active_app_servers: dict[str, dict] = {}

    def _client(self) -> CodexAppServerClient:
        if not self.command:
            raise ConversationHostError(
                "codex_companion_missing",
                "Install and sign in to Codex before using Activity Monitor as the conversation host",
                phase="owner preflight",
            )
        return self.client_factory(self.command)

    @staticmethod
    def _ipc_result(response: dict, method: str, owner_client_id: str) -> dict:
        if response.get("resultType") != "success":
            raise ConversationHostError(
                "codex_owner_delivery_failed",
                DesktopIpcClient.error_text(response),
                phase="exact-task resume/steer",
                delivery_attempted=True,
            )
        if response.get("method") not in {None, method}:
            raise ConversationHostError(
                "codex_owner_protocol_error",
                "Codex returned the wrong owner receipt",
                phase="exact-task resume/steer",
                delivery_attempted=True,
            )
        if response.get("handledByClientId") != owner_client_id:
            raise ConversationHostError(
                "codex_owner_mismatch",
                "Codex did not use the exact discovered task owner",
                phase="exact-task resume/steer",
                delivery_attempted=True,
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise ConversationHostError(
                "codex_owner_protocol_error",
                "Codex returned no exact owner result",
                phase="exact-task resume/steer",
                delivery_attempted=True,
            )
        nested = result.get("result")
        return nested if isinstance(nested, dict) else result

    @staticmethod
    def _inactive_steer(response: dict) -> bool:
        text = DesktopIpcClient.error_text(response).lower()
        return (
            "steerturninactiveerror" in text
            or "active turn already ended" in text
            or "no active turn to steer" in text
        )

    def _send_desktop(self, target: dict, message: str, request_id: str) -> dict | None:
        client = self.desktop_ipc_factory(self.desktop_ipc_path)
        try:
            try:
                discovery = client.request(
                    "thread-owner-discovery",
                    {"hostId": "local", "conversationId": target["id"]},
                    version=1,
                    timeout_ms=5000,
                )
            except DispatchError as error:
                if error.code in OWNER_DISCOVERY_FALLBACK_CODES:
                    return None
                raise ConversationHostError(error.code, str(error), phase="owner preflight") from error
            if discovery.get("resultType") != "success":
                if "no-client-found" in DesktopIpcClient.error_text(discovery).lower():
                    return None
                raise ConversationHostError(
                    "codex_owner_discovery_failed",
                    DesktopIpcClient.error_text(discovery),
                    phase="owner preflight",
                )
            owner_id = str(discovery.get("handledByClientId") or "").lower()
            if not UUID_RE.fullmatch(owner_id):
                raise ConversationHostError(
                    "codex_owner_discovery_failed",
                    "Codex returned no exact live task owner",
                    phase="owner preflight",
                )
            cwd = _validated_project_directory(target.get("cwd")) or str(Path.home())
            inputs = [{"type": "text", "text": message, "text_elements": []}]
            params = {
                "conversationId": target["id"],
                "clientUserMessageId": request_id,
                "input": inputs,
                "attachments": [],
                "restoreMessage": {
                    "id": str(uuid.uuid4()),
                    "text": message,
                    "context": {
                        "prompt": message,
                        "addedFiles": [],
                        "fileAttachments": [],
                        "ideContext": None,
                        "imageAttachments": [],
                        "workspaceRoots": [cwd],
                    },
                    "cwd": cwd,
                    "createdAt": int(time.time() * 1000),
                },
            }
            uncertain = {
                "clientUserMessageId": request_id,
                "ownerClientId": owner_id,
                "deliveryAttempted": True,
                "retrySafe": False,
                "reconciliationRequired": True,
                "phase": "exact-task resume/steer",
                "transport": "codex-desktop-owner-ipc",
            }
            try:
                response = client.request(
                    "thread-follower-steer-turn",
                    params,
                    version=1,
                    target_client_id=owner_id,
                    timeout_ms=12_000,
                )
                mode = "steer"
                if response.get("resultType") == "success":
                    result = self._ipc_result(response, "thread-follower-steer-turn", owner_id)
                elif self._inactive_steer(response):
                    started = client.request(
                        "thread-follower-start-turn",
                        {
                            "conversationId": target["id"],
                            "turnStartParams": {
                                "input": inputs,
                                "clientUserMessageId": request_id,
                                "cwd": cwd,
                                "effort": "ultra",
                            },
                        },
                        version=1,
                        target_client_id=owner_id,
                        timeout_ms=12_000,
                    )
                    result = self._ipc_result(started, "thread-follower-start-turn", owner_id)
                    mode = "start-after-inactive-steer"
                else:
                    raise ConversationHostError(
                        "codex_owner_delivery_failed",
                        DesktopIpcClient.error_text(response),
                        phase="exact-task resume/steer",
                        delivery_attempted=True,
                        receipt=uncertain,
                    )
            except ConversationHostError:
                raise
            except (DispatchError, OSError) as error:
                raise ConversationHostError(
                    getattr(error, "code", "codex_owner_delivery_uncertain"),
                    str(error),
                    phase="exact-task resume/steer",
                    delivery_attempted=True,
                    receipt=uncertain,
                ) from error
            turn = result.get("turn") if isinstance(result.get("turn"), dict) else result
            turn_id = str(turn.get("id") or turn.get("turnId") or result.get("turnId") or "").lower()
            if not UUID_RE.fullmatch(turn_id):
                raise ConversationHostError(
                    "codex_turn_receipt_missing",
                    "Codex accepted the text but returned no exact turn receipt",
                    phase="exact-task resume/steer",
                    delivery_attempted=True,
                    receipt=uncertain,
                )
            return {
                "state": "accepted",
                "phase": "accepted",
                "deliveryAttempted": True,
                "retrySafe": False,
                "reconciliationRequired": False,
                "clientUserMessageId": request_id,
                "turnId": turn_id,
                "ownerClientId": owner_id,
                "deliveryMode": mode,
                "transport": "codex-desktop-owner-ipc",
            }
        finally:
            client.close()

    @staticmethod
    def _inactive_app_server_steer(error: Exception) -> bool:
        text = str(error).lower()
        return any(
            phrase in text
            for phrase in (
                "no active turn",
                "active turn already ended",
                "turn is not active",
                "expected turn",
            )
        )

    def _monitor_app_server(self, thread_id: str, turn_id: str, client: object) -> None:
        deadline = time.monotonic() + self.monitor_seconds
        try:
            while time.monotonic() < deadline:
                message = client.next_notification(timeout=1.0)
                if not isinstance(message, dict):
                    continue
                method = str(message.get("method") or "")
                params = message.get("params") if isinstance(message.get("params"), dict) else {}
                event_turn = params.get("turn") if isinstance(params.get("turn"), dict) else {}
                if method == "turn/completed" and str(event_turn.get("id") or "").lower() == turn_id:
                    return
                if method == "_process/closed":
                    return
        finally:
            with self._active_lock:
                current = self._active_app_servers.get(thread_id)
                if isinstance(current, dict) and current.get("client") is client:
                    self._active_app_servers.pop(thread_id, None)
            client.close()

    def _register_app_server(self, thread_id: str, turn_id: str, client: object) -> None:
        with self._active_lock:
            self._active_app_servers[thread_id] = {"client": client, "turnId": turn_id}
        threading.Thread(
            target=self._monitor_app_server,
            args=(thread_id, turn_id, client),
            daemon=True,
            name=f"conversation-host-{thread_id[:8]}",
        ).start()

    def close(self) -> None:
        with self._active_lock:
            clients = [
                value.get("client")
                for value in self._active_app_servers.values()
                if isinstance(value, dict) and value.get("client") is not None
            ]
            self._active_app_servers.clear()
        for client in clients:
            client.close()

    def _send_active_app_server(self, target: dict, message: str, request_id: str) -> dict | None:
        with self._active_lock:
            active = self._active_app_servers.get(target["id"])
            if not isinstance(active, dict):
                return None
            client = active.get("client")
            turn_id = str(active.get("turnId") or "").lower()
            if client is None or not UUID_RE.fullmatch(turn_id):
                self._active_app_servers.pop(target["id"], None)
                return None
            params = {
                "threadId": target["id"],
                "expectedTurnId": turn_id,
                "input": [{"type": "text", "text": message, "text_elements": []}],
                "clientUserMessageId": request_id,
            }
            uncertain = {
                "clientUserMessageId": request_id,
                "turnId": turn_id,
                "deliveryAttempted": True,
                "retrySafe": False,
                "reconciliationRequired": True,
            }
            try:
                response = client.request("turn/steer", params, timeout=12.0)
                mode = "steer"
            except (DispatchError, OSError) as error:
                if self._inactive_app_server_steer(error):
                    self._active_app_servers.pop(target["id"], None)
                    client.close()
                    return None
                raise ConversationHostError(
                    getattr(error, "code", "codex_delivery_uncertain"),
                    str(error),
                    phase="exact-task resume/steer",
                    delivery_attempted=True,
                    receipt=uncertain,
                ) from error
            turn = response.get("turn") if isinstance(response.get("turn"), dict) else response
            observed_turn_id = str(turn.get("id") or turn.get("turnId") or turn_id).lower()
            if not UUID_RE.fullmatch(observed_turn_id):
                raise ConversationHostError(
                    "codex_turn_receipt_missing",
                    "Codex accepted the text but returned no exact turn receipt",
                    phase="exact-task resume/steer",
                    delivery_attempted=True,
                    receipt=uncertain,
                )
            active["turnId"] = observed_turn_id
            return {
                "state": "accepted",
                "phase": "accepted",
                "deliveryAttempted": True,
                "retrySafe": False,
                "reconciliationRequired": False,
                "clientUserMessageId": request_id,
                "turnId": observed_turn_id,
                "deliveryMode": mode,
                "transport": "codex-retained-app-server",
            }

    def send(self, target: dict, message: str, request_id: str) -> dict:
        retained = self._send_active_app_server(target, message, request_id)
        if retained is not None:
            return retained
        desktop = self._send_desktop(target, message, request_id)
        if desktop is not None:
            return desktop
        client = self._client()
        retained_client = False
        try:
            try:
                client.start()
                resumed = client.request(
                    "thread/resume",
                    {"threadId": target["id"], "excludeTurns": True},
                    timeout=8.0,
                )
            except (DispatchError, OSError) as error:
                raise ConversationHostError(
                    getattr(error, "code", "codex_resume_failed"),
                    str(error),
                    phase="owner preflight",
                    delivery_attempted=False,
                ) from error
            thread = resumed.get("thread") or {}
            if str(thread.get("id") or "").lower() != target["id"]:
                raise ConversationHostError(
                    "codex_identity_mismatch",
                    "Codex resumed a different task",
                    phase="owner preflight",
                )
            try:
                response = client.request(
                    "turn/start",
                    {
                        "threadId": target["id"],
                        "input": [{"type": "text", "text": message, "text_elements": []}],
                        "clientUserMessageId": request_id,
                        "cwd": _validated_project_directory(target.get("cwd")),
                        "effort": "ultra",
                    },
                    timeout=12.0,
                )
            except (DispatchError, OSError) as error:
                raise ConversationHostError(
                    getattr(error, "code", "codex_delivery_uncertain"),
                    str(error),
                    phase="exact-task resume/steer",
                    delivery_attempted=True,
                    receipt={
                        "clientUserMessageId": request_id,
                        "transport": "codex-exact-thread-app-server",
                    },
                ) from error
            turn = response.get("turn") or {}
            turn_id = str(turn.get("id") or "").lower()
            if not UUID_RE.fullmatch(turn_id):
                raise ConversationHostError(
                    "codex_turn_receipt_missing",
                    "Codex accepted the text but returned no exact turn receipt",
                    phase="exact-task resume/steer",
                    delivery_attempted=True,
                    receipt={
                        "clientUserMessageId": request_id,
                        "transport": "codex-exact-thread-app-server",
                    },
                )
            self._register_app_server(target["id"], turn_id, client)
            retained_client = True
            return {
                "state": "accepted",
                "phase": "accepted",
                "deliveryAttempted": True,
                "retrySafe": False,
                "reconciliationRequired": False,
                "clientUserMessageId": request_id,
                "turnId": turn_id,
                "transport": "codex-exact-thread-app-server",
            }
        finally:
            if not retained_client:
                client.close()

    def create_thread(self, *, cwd: str, title: str, developer_instructions: str) -> dict:
        directory = _validated_project_directory(cwd)
        if not directory:
            raise ConversationHostError(
                "project_directory_unavailable",
                "This project needs a verified local folder before Activity Monitor can create its task",
                phase="project preflight",
            )
        client = self._client()
        thread_id = ""
        try:
            try:
                client.start()
            except (DispatchError, OSError) as error:
                raise ConversationHostError(
                    getattr(error, "code", "codex_companion_start_failed"),
                    str(error),
                    phase="task creation preflight",
                    delivery_attempted=False,
                ) from error
            try:
                response = client.request(
                    "thread/start",
                    {
                        "cwd": directory,
                        "runtimeWorkspaceRoots": [directory],
                        "approvalPolicy": "never",
                        "sandbox": "danger-full-access",
                        "developerInstructions": developer_instructions,
                        "ephemeral": False,
                        "allowProviderModelFallback": False,
                        "personality": "pragmatic",
                    },
                    timeout=12.0,
                )
            except (DispatchError, OSError) as error:
                raise ConversationHostError(
                    getattr(error, "code", "codex_thread_creation_uncertain"),
                    "Codex may have created the project task, but returned no exact receipt",
                    phase="task creation",
                    delivery_attempted=True,
                ) from error
            thread = response.get("thread") or {}
            thread_id = str(thread.get("id") or "").lower()
            if not UUID_RE.fullmatch(thread_id):
                raise ConversationHostError(
                    "codex_thread_receipt_missing",
                    "Codex created no exact task receipt",
                    phase="task creation",
                    delivery_attempted=True,
                )
            try:
                client.request(
                    "thread/name/set",
                    {"threadId": thread_id, "name": _safe_label(title, "Project Conductor")},
                    timeout=6.0,
                )
            except (DispatchError, OSError) as error:
                raise ConversationHostError(
                    getattr(error, "code", "codex_thread_name_uncertain"),
                    "Codex created the task but its visible title could not be confirmed",
                    phase="task creation",
                    delivery_attempted=True,
                    receipt={"threadId": thread_id},
                ) from error
            return {
                "id": thread_id,
                "provider": "codex",
                "title": _safe_label(title, "Project Conductor"),
                "state": "idle",
                "stateSource": "Activity Monitor Conductor",
                "cwd": directory,
            }
        finally:
            client.close()

    def thread_exists(self, thread_id: str) -> bool:
        if not UUID_RE.fullmatch(str(thread_id or "")):
            return False
        client = self._client()
        try:
            client.start()
            result = client.request(
                "thread/read",
                {"threadId": thread_id, "includeTurns": False},
                timeout=6.0,
            )
            return str((result.get("thread") or {}).get("id") or "").lower() == thread_id.lower()
        except (DispatchError, ConversationHostError, OSError):
            return False
        finally:
            client.close()

    @staticmethod
    def _content_text(value: object) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            parts: list[str] = []
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    text = item.get("text") or item.get("content")
                    if isinstance(text, str):
                        parts.append(text)
            return "\n".join(parts)
        return ""

    @classmethod
    def _normalize_items(cls, turns: list[dict]) -> list[dict]:
        items: list[dict] = []
        used = 0
        for turn in turns:
            turn_id = str(turn.get("id") or "")
            for raw in turn.get("items", []) if isinstance(turn.get("items"), list) else []:
                if not isinstance(raw, dict) or len(items) >= MAX_TRANSCRIPT_ITEMS:
                    continue
                kind = str(raw.get("type") or "").lower().replace("_", "")
                role = None
                text = ""
                if kind == "usermessage":
                    role = "user"
                    text = cls._content_text(raw.get("content") or raw.get("text"))
                elif kind == "agentmessage":
                    role = "assistant"
                    text = cls._content_text(raw.get("text") or raw.get("content"))
                elif kind in {"commandexecution", "filechange", "mcp/toolcall", "dynamictoolcall", "toolcall"}:
                    role = "activity"
                    label = raw.get("name") or raw.get("command") or raw.get("status") or raw.get("type")
                    text = _safe_label(label, "Used a local tool", 180)
                if not role or not text:
                    continue
                text = text[:MAX_ITEM_TEXT_CHARS]
                encoded_size = len(text.encode("utf-8", errors="ignore"))
                if used + encoded_size > MAX_TRANSCRIPT_TEXT_BYTES:
                    return items
                used += encoded_size
                items.append({
                    "id": str(raw.get("id") or f"{turn_id}:{len(items)}")[:180],
                    "turnId": turn_id or None,
                    "role": role,
                    "text": text,
                    "status": str(raw.get("status") or "")[:32] or None,
                })
        return items

    def _read_from_client(self, client: object, target: dict) -> dict:
        try:
            result = client.request(
                "thread/turns/list",
                {
                    "threadId": target["id"],
                    "limit": 60,
                    "sortDirection": "desc",
                    "itemsView": "full",
                },
                timeout=10.0,
            )
            rows = result.get("data")
            if not isinstance(rows, list):
                raise ConversationHostError(
                    "codex_transcript_unavailable",
                    "Codex returned no exact conversation page",
                    phase="transcript read",
                )
            turns = [item for item in reversed(rows) if isinstance(item, dict)]
            return {
                "ok": True,
                "provider": "codex",
                "conversationId": target["id"],
                "title": target.get("title"),
                "items": self._normalize_items(turns),
                "nextCursor": result.get("nextCursor"),
            }
        except ConversationHostError:
            raise
        except (DispatchError, OSError) as error:
            raise ConversationHostError(
                getattr(error, "code", "codex_transcript_unavailable"),
                str(error),
                phase="transcript read",
            ) from error

    def read(self, target: dict) -> dict:
        with self._active_lock:
            active = self._active_app_servers.get(target["id"])
            if isinstance(active, dict) and active.get("client") is not None:
                return self._read_from_client(active["client"], target)
        client = self._client()
        try:
            client.start()
            return self._read_from_client(client, target)
        finally:
            client.close()


class ClaudeConversationTransport:
    """Exact Claude reads and sends without creating a second live owner."""

    def __init__(
        self,
        home: str | Path | None = None,
        command: str | None = None,
        *,
        live_sender: Callable[[dict, str, str], dict] | None = None,
        process_launcher: Callable[..., object] | None = None,
    ):
        self.home = Path(home or Path.home()).expanduser().resolve()
        self.command = _validated_executable(command or shutil.which("claude"))
        self.live_sender = live_sender
        self.process_launcher = process_launcher or subprocess.Popen

    def send(self, target: dict, message: str, request_id: str) -> dict:
        if str(target.get("state") or "").lower() == "active":
            if self.live_sender is None:
                raise ConversationHostError(
                    "claude_live_owner_required",
                    "This Claude session is active elsewhere; Activity Monitor refused to create a second writer",
                    phase="owner preflight",
                )
            try:
                receipt = self.live_sender(target, message, request_id)
            except ConversationHostError:
                raise
            except Exception as error:
                attempted = bool(getattr(error, "delivery_attempted", False))
                raise ConversationHostError(
                    getattr(error, "code", "claude_live_delivery_failed"),
                    str(error),
                    phase="exact-session delivery",
                    delivery_attempted=attempted,
                ) from error
            if not isinstance(receipt, dict):
                raise ConversationHostError(
                    "claude_receipt_invalid",
                    "Claude returned no exact delivery receipt",
                    phase="exact-session delivery",
                    delivery_attempted=True,
                )
            if receipt.get("socketWritten") is not True:
                raise ConversationHostError(
                    "claude_socket_not_confirmed",
                    "Claude did not confirm the private session write",
                    phase="exact-session delivery",
                    delivery_attempted=False,
                    receipt=receipt,
                )
            return {
                "state": "transcript observed" if receipt.get("transcriptObserved") else "uncertain after send",
                "phase": "transcript observed" if receipt.get("transcriptObserved") else "uncertain after send",
                "deliveryAttempted": True,
                "retrySafe": False,
                "reconciliationRequired": not bool(receipt.get("transcriptObserved")),
                "clientUserMessageId": request_id,
                "msgId": receipt.get("msgId"),
                "providerMessageId": receipt.get("msgId"),
                "transport": "claude-private-session-socket",
            }
        command = self.command
        cwd = _validated_project_directory(target.get("cwd"))
        if not command:
            raise ConversationHostError(
                "claude_companion_missing",
                "Install and sign in to Claude Code before using Activity Monitor as its host",
                phase="owner preflight",
            )
        if not cwd:
            raise ConversationHostError(
                "claude_project_directory_required",
                "Choose the exact Claude project folder before resuming this session in Activity Monitor",
                phase="project preflight",
            )
        args = [
            command,
            "-p",
            "--resume",
            target["id"],
            "--input-format",
            "text",
            "--output-format",
            "json",
            "--permission-mode",
            "bypassPermissions",
        ]
        read_fd = -1
        write_fd = -1
        launched = False
        try:
            read_fd, write_fd = os.pipe()
            self.process_launcher(
                args,
                cwd=cwd,
                stdin=read_fd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
            launched = True
            os.close(read_fd)
            read_fd = -1
            encoded = message.encode("utf-8")
            offset = 0
            while offset < len(encoded):
                offset += os.write(write_fd, encoded[offset:])
            os.close(write_fd)
            write_fd = -1
        except (OSError, subprocess.SubprocessError) as error:
            raise ConversationHostError(
                "claude_resume_write_uncertain" if launched else "claude_resume_failed",
                str(error),
                phase="exact-session delivery",
                delivery_attempted=launched,
                retry_safe=not launched,
                reconciliation_required=launched,
                receipt={"clientUserMessageId": request_id},
            ) from error
        finally:
            for descriptor in (write_fd, read_fd):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
        return {
            "state": "uncertain after send",
            "phase": "uncertain after send",
            "deliveryAttempted": True,
            "retrySafe": False,
            "reconciliationRequired": True,
            "clientUserMessageId": request_id,
            "transport": "claude-headless-exact-resume",
        }

    @staticmethod
    def _record_text(value: object) -> str:
        if isinstance(value, str):
            return value
        if not isinstance(value, list):
            return ""
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(parts)

    def read(self, target: dict) -> dict:
        project_key = str(target.get("projectKey") or "")
        session_id = str(target.get("id") or "").lower()
        if not re.fullmatch(r"[A-Za-z0-9-]{1,4096}", project_key) or not UUID_RE.fullmatch(session_id):
            raise ConversationHostError(
                "claude_transcript_identity_invalid",
                "Choose one exact visible Claude conversation",
                phase="transcript read",
            )
        descriptors: list[int] = []
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            root_fd = os.open(self.home / ".claude" / "projects", directory_flags)
            descriptors.append(root_fd)
            root_metadata = os.fstat(root_fd)
            if (
                not stat.S_ISDIR(root_metadata.st_mode)
                or root_metadata.st_uid != os.getuid()
                or stat.S_IMODE(root_metadata.st_mode) & 0o077
            ):
                raise ConversationHostError(
                    "claude_metadata_insecure",
                    "Claude project metadata is not private to the current user",
                    phase="transcript read",
                )
            project_fd = os.open(project_key, directory_flags, dir_fd=root_fd)
            descriptors.append(project_fd)
            project_metadata = os.fstat(project_fd)
            if (
                not stat.S_ISDIR(project_metadata.st_mode)
                or project_metadata.st_uid != os.getuid()
                or stat.S_IMODE(project_metadata.st_mode) & 0o077
            ):
                raise ConversationHostError(
                    "claude_metadata_insecure",
                    "The selected Claude project metadata is not private",
                    phase="transcript read",
                )
            file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            transcript_fd = os.open(f"{session_id}.jsonl", file_flags, dir_fd=project_fd)
            descriptors.append(transcript_fd)
            metadata = os.fstat(transcript_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise ConversationHostError(
                    "claude_transcript_untrusted",
                    "The selected Claude conversation is not a trusted current-user file",
                    phase="transcript read",
                )
            tail_bytes = min(max(0, metadata.st_size), MAX_CLAUDE_TRANSCRIPT_BYTES)
            start = max(0, metadata.st_size - tail_bytes)
            os.lseek(transcript_fd, start, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = tail_bytes
            while remaining > 0:
                chunk = os.read(transcript_fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if start and b"\n" in raw:
                raw = raw.split(b"\n", 1)[1]
            items: list[dict] = []
            used = 0
            for line in raw.splitlines():
                if not line or len(line) > 512 * 1024:
                    continue
                try:
                    record = json.loads(line.decode("utf-8"))
                except (UnicodeError, ValueError, TypeError):
                    continue
                if not isinstance(record, dict) or str(record.get("sessionId") or session_id).lower() != session_id:
                    continue
                kind = str(record.get("type") or "").lower()
                if kind not in {"user", "assistant"}:
                    continue
                message = record.get("message") if isinstance(record.get("message"), dict) else {}
                text = self._record_text(message.get("content") if message else record.get("content"))
                if not text:
                    continue
                text = text[:MAX_ITEM_TEXT_CHARS]
                used += len(text.encode("utf-8", errors="ignore"))
                if used > MAX_TRANSCRIPT_TEXT_BYTES or len(items) >= MAX_TRANSCRIPT_ITEMS:
                    break
                items.append({
                    "id": str(record.get("uuid") or f"{session_id}:{len(items)}")[:180],
                    "role": kind,
                    "text": text,
                    "timestamp": str(record.get("timestamp") or "")[:64] or None,
                })
            return {
                "ok": True,
                "provider": "claude",
                "conversationId": session_id,
                "title": target.get("title"),
                "items": items,
                "nextCursor": None,
            }
        except ConversationHostError:
            raise
        except OSError as error:
            raise ConversationHostError(
                "claude_transcript_unavailable",
                "The exact Claude conversation could not be opened safely",
                phase="transcript read",
            ) from error
        finally:
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError:
                    pass


class ConversationHostService:
    """Provider-neutral project command center and exact conversation host."""

    def __init__(
        self,
        workspace_loader: Callable[[bool], dict],
        *,
        home: str | Path | None = None,
        store_path: str | Path | None = None,
        codex_transport: object | None = None,
        claude_transport: object | None = None,
        full_access_checker: Callable[[], bool] | None = None,
        source_task_id: str = "01a02217-16e8-73b3-a10d-65562433569f",
    ):
        self.home = Path(home or Path.home()).expanduser().resolve()
        support = self.home / "Library" / "Application Support" / "KE Studios" / "Activity Monitor"
        self.store = ReceiptStore(store_path or support / "conversation-host-receipts.json")
        self.workspace_loader = workspace_loader
        self.codex = codex_transport or CodexConversationTransport()
        self.claude = claude_transport or ClaudeConversationTransport(home=self.home)
        self.full_access_checker = full_access_checker or self._default_full_access
        self.source_task_id = source_task_id
        self.instance_id = str(uuid.uuid4())
        self._locks_guard = threading.Lock()
        self._project_locks: dict[str, threading.RLock] = {}

    @staticmethod
    def privacy(*, body_read: bool = False) -> dict:
        return {
            "localOnly": True,
            "transcriptBodyRead": bool(body_read),
            "bodyReadRequiresExplicitClick": True,
            "transcriptBodiesPersistedByActivityMonitor": False,
            "queuedMessageBodiesPersistedByActivityMonitor": False,
            "receiptsDigestOnly": True,
            "receiptsMode": "0600",
            "credentialsRead": False,
            "providerDatabaseCopied": False,
            "providerPreserved": True,
        }

    def _default_full_access(self) -> bool:
        audit = self.home / ".codex" / "skills" / "maintain-full-access-plus" / "scripts" / "audit.zsh"
        if not audit.is_file():
            return False
        environment = dict(os.environ)
        environment["CODEX_THREAD_ID"] = self.source_task_id
        try:
            result = subprocess.run(
                [str(audit)],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=15.0,
                check=False,
                env=environment,
            )
            return result.returncode == 0 and "FULL_ACCESS_PLUS=healthy" in (result.stdout or "")
        except (OSError, subprocess.SubprocessError):
            return False

    def _require_full_access(self) -> None:
        if not self.full_access_checker():
            raise ConversationHostError(
                "full_access_unverified",
                "Activity Monitor could not verify Full Access before handing work to an agent",
                phase="full-access preflight",
            )

    def _snapshot(self, force: bool = False) -> dict:
        try:
            payload = self.workspace_loader(bool(force))
        except TypeError:
            payload = self.workspace_loader()
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise ConversationHostError(
                "workspace_unavailable",
                "The current visible project list is unavailable",
                phase="project preflight",
            )
        return payload

    @staticmethod
    def _project_key(provider: str, project_id: str) -> str:
        return f"{provider}:{project_id}"

    def _project(self, provider: str, project_id: str, *, force: bool = False) -> dict:
        provider = str(provider or "").lower()
        project_id = str(project_id or "")
        if provider not in {"codex", "claude"}:
            raise ConversationHostError(
                "provider_invalid",
                "Choose Codex or Claude from the visible project rail",
                phase="project preflight",
            )
        for raw in self._snapshot(force).get("projects", []):
            if not isinstance(raw, dict):
                continue
            if str(raw.get("provider") or "").lower() == provider and str(raw.get("id") or "") == project_id:
                project = dict(raw)
                project["provider"] = provider
                project["id"] = project_id
                project["name"] = _safe_label(project.get("name"), "Project")
                project["rootPath"] = (
                    project.get("rootPath")
                    or project.get("directory")
                    or project.get("cwd")
                )
                return project
        raise ConversationHostError(
            "project_not_visible",
            "That project is not in the current visible provider-filtered rail",
            phase="project preflight",
        )

    @staticmethod
    def _target(project: dict, conversation: dict) -> dict:
        target = dict(conversation)
        target.update({
            "id": str(conversation.get("id") or "").lower(),
            "provider": str(conversation.get("provider") or project["provider"]).lower(),
            "projectId": project["id"],
            "projectProvider": project["provider"],
            "projectName": project["name"],
            "cwd": conversation.get("cwd") or project.get("rootPath"),
            "projectKey": conversation.get("projectKey") or project.get("storageKey"),
            "title": _safe_label(conversation.get("title"), "Untitled conversation"),
        })
        return target

    def _conversation(self, provider: str, conversation_id: str, *, force: bool = False) -> tuple[dict, dict]:
        provider = str(provider or "").lower()
        conversation_id = str(conversation_id or "").lower()
        if provider not in {"codex", "claude"} or not UUID_RE.fullmatch(conversation_id):
            raise ConversationHostError(
                "conversation_identity_invalid",
                "Choose one exact visible conversation",
                phase="conversation preflight",
            )
        payload = self._snapshot(force)
        for project in payload.get("projects", []):
            if not isinstance(project, dict):
                continue
            for row in project.get("conversations", []) if isinstance(project.get("conversations"), list) else []:
                if (
                    isinstance(row, dict)
                    and str(row.get("provider") or project.get("provider") or "").lower() == provider
                    and str(row.get("id") or "").lower() == conversation_id
                ):
                    normalized_project = dict(project)
                    normalized_project["provider"] = str(project.get("provider") or provider).lower()
                    normalized_project["id"] = str(project.get("id") or "")
                    normalized_project["name"] = _safe_label(project.get("name"), "Project")
                    normalized_project["rootPath"] = (
                        project.get("rootPath") or project.get("directory") or project.get("cwd")
                    )
                    return normalized_project, self._target(normalized_project, row)
        raise ConversationHostError(
            "conversation_not_visible",
            "That conversation is no longer in the current visible project set",
            phase="conversation preflight",
        )

    def _conversation_or_mapped(
        self,
        provider: str,
        conversation_id: str,
        *,
        force: bool = False,
    ) -> tuple[dict, dict]:
        try:
            return self._conversation(provider, conversation_id, force=force)
        except ConversationHostError as error:
            if error.code != "conversation_not_visible" or str(provider or "").lower() != "codex":
                raise
        conversation_id = str(conversation_id or "").lower()
        if not UUID_RE.fullmatch(conversation_id):
            raise ConversationHostError(
                "conversation_identity_invalid",
                "Choose one exact visible conversation",
                phase="conversation preflight",
            )
        mapping_key = next(
            (
                key
                for key, thread_id in self.store.read().get("mappings", {}).items()
                if thread_id == conversation_id and key.count(":") >= 2
            ),
            None,
        )
        if not mapping_key:
            raise ConversationHostError(
                "conversation_not_visible",
                "That conversation is no longer in the current visible project set",
                phase="conversation preflight",
            )
        project_provider, remainder = mapping_key.split(":", 1)
        project_id, kind = remainder.rsplit(":", 1)
        project = self._project(project_provider, project_id, force=force)
        if not self.codex.thread_exists(conversation_id):
            raise ConversationHostError(
                "conversation_stale",
                "The mapped project agent no longer exists in Codex",
                phase="conversation preflight",
            )
        return project, {
            "id": conversation_id,
            "provider": "codex",
            "projectId": project["id"],
            "projectProvider": project["provider"],
            "projectName": project["name"],
            "title": self._conductor_title(project, kind),
            "state": "idle",
            "stateSource": "Activity Monitor Conductor",
            "cwd": project.get("rootPath"),
            "projectKey": project.get("storageKey"),
        }

    def _project_lock(self, project_key: str) -> threading.RLock:
        with self._locks_guard:
            return self._project_locks.setdefault(project_key, threading.RLock())

    def _destination_lock(self, target: dict) -> threading.RLock:
        return self._project_lock(f"destination:{target['provider']}:{target['id']}")

    @staticmethod
    def _mapping_key(project: dict, kind: str) -> str:
        return f"{project['provider']}:{project['id']}:{kind}"

    @staticmethod
    def _conductor_title(project: dict, kind: str) -> str:
        prefix = "PowerSwarm" if kind == "powerswarm" else "Conductor"
        return _safe_label(f"{prefix} · {project['name']}", prefix)

    @staticmethod
    def _developer_instructions(project: dict, kind: str) -> str:
        base = (
            "You are the project-scoped KE Conductor hosted by Activity Monitor. "
            f"Your immutable scope is {project['name']} ({project['provider']}:{project['id']}). "
            "Act on the operator's requests with full local tools and Full Access, while preserving explicit "
            "authority gates for sends, spend, deployment, release, deletion, credentials, and other "
            "consequential external effects. First inspect the current Agent Operations Board and route "
            "to the exact verified existing owner when one exists. If none exists, create at most one "
            "appropriate top-level project task and reconcile it before creating another. Accept rapid "
            "follow-ups as distinct requests with their fixed client IDs. Never use native Codex child "
            "agents; PowerSwarm/Grok is the only recursive multi-lane path. Report delivery and uncertainty "
            "truthfully and never blind-retry after a message may have been submitted."
        )
        if kind == "powerswarm":
            base += (
                " This task is the project's PowerSwarm owner. Invoke the installed powerswarm skill when "
                "the work qualifies, reuse a healthy existing run, and otherwise create exactly one governed "
                "PowerSwarm run with one writer per isolated lane."
            )
        return base

    @staticmethod
    def _existing_candidates(project: dict, kind: str, message: str) -> list[dict]:
        rows = [row for row in project.get("conversations", []) if isinstance(row, dict)]
        if kind == "powerswarm":
            rows = [row for row in rows if POWERSWARM_RE.search(str(row.get("title") or ""))]
        else:
            expected = f"conductor · {project['name']}".lower()
            conductors = [row for row in rows if str(row.get("title") or "").lower() == expected]
            if conductors:
                rows = conductors
            else:
                message_tokens = _tokens(message)
                scored: list[tuple[int, dict]] = []
                for row in rows:
                    source = str(row.get("stateSource") or "").lower()
                    active = str(row.get("state") or "").lower() == "active"
                    if not active or source not in AUTHORITATIVE_ACTIVE_SOURCES:
                        continue
                    overlap = len(message_tokens & _tokens(row.get("title")))
                    if overlap:
                        scored.append((overlap, row))
                if scored:
                    best = max(score for score, _ in scored)
                    rows = [row for score, row in scored if score == best]
                    if len(rows) != 1:
                        rows = []
                else:
                    rows = []
        rows.sort(
            key=lambda row: (
                str(row.get("state") or "").lower() != "active",
                str(row.get("stateSource") or "").lower() not in AUTHORITATIVE_ACTIVE_SOURCES,
                -_epoch(row.get("updatedAtEpoch") or row.get("updatedAt")),
                str(row.get("id") or ""),
            )
        )
        return rows

    def _mapped_target(self, project: dict, kind: str) -> dict | None:
        mapping_key = self._mapping_key(project, kind)
        thread_id = str(self.store.read().get("mappings", {}).get(mapping_key) or "").lower()
        if not UUID_RE.fullmatch(thread_id):
            return None
        for row in project.get("conversations", []):
            if isinstance(row, dict) and str(row.get("id") or "").lower() == thread_id:
                return self._target(project, row)
        if not self.codex.thread_exists(thread_id):
            return None
        return {
            "id": thread_id,
            "provider": "codex",
            "projectId": project["id"],
            "projectProvider": project["provider"],
            "projectName": project["name"],
            "title": self._conductor_title(project, kind),
            "state": "idle",
            "stateSource": "Activity Monitor Conductor",
            "cwd": project.get("rootPath"),
            "projectKey": project.get("storageKey"),
        }

    def _save_mapping(self, project: dict, kind: str, thread_id: str) -> None:
        mapping_key = self._mapping_key(project, kind)

        def update(value: dict) -> None:
            value["mappings"][mapping_key] = thread_id
            value["creationGuards"].pop(mapping_key, None)

        self.store.mutate(update)

    def _claim_creation_guard(self, project: dict, kind: str, request_id: str) -> dict | None:
        mapping_key = self._mapping_key(project, kind)

        def update(value: dict) -> dict | None:
            current = value["creationGuards"].get(mapping_key)
            if isinstance(current, dict) and current.get("requestId") != request_id:
                age = time.time() - _epoch(current.get("timestamp"))
                if 0 <= age <= RECONCILIATION_WINDOW_SECONDS:
                    return dict(current)
            value["creationGuards"][mapping_key] = {
                "requestId": request_id,
                "state": "attempting",
                "timestamp": _utc_now(),
            }
            return None

        return self.store.mutate(update)

    def _finish_creation_guard(self, project: dict, kind: str, request_id: str, *, uncertain: bool) -> None:
        mapping_key = self._mapping_key(project, kind)

        def update(value: dict) -> None:
            current = value["creationGuards"].get(mapping_key)
            if not isinstance(current, dict) or current.get("requestId") != request_id:
                return
            if uncertain:
                current.update({"state": "uncertain", "timestamp": _utc_now()})
            else:
                value["creationGuards"].pop(mapping_key, None)

        self.store.mutate(update)

    def _destination(
        self,
        project: dict,
        kind: str,
        message: str,
        request_id: str,
    ) -> tuple[dict, str]:
        project_key = self._project_key(project["provider"], project["id"])
        with self._project_lock(project_key):
            candidates = self._existing_candidates(project, kind, message)
            if candidates:
                target = self._target(project, candidates[0])
                route = "existing-powerswarm" if kind == "powerswarm" else (
                    "existing-conductor"
                    if str(target.get("title") or "").lower().startswith("conductor ·")
                    else "existing-owner"
                )
                if route in {"existing-powerswarm", "existing-conductor"}:
                    self._save_mapping(project, kind, target["id"])
                return target, route
            mapped = self._mapped_target(project, kind)
            if mapped:
                return mapped, f"existing-{kind}"
            cwd = _validated_project_directory(project.get("rootPath"))
            if not cwd:
                raise ConversationHostError(
                    "project_directory_unavailable",
                    "Choose or restore this project's exact local folder before creating its agent task",
                    phase="project preflight",
                )
            self._require_full_access()
            guard = self._claim_creation_guard(project, kind, request_id)
            if guard is not None:
                raise ConversationHostError(
                    "task_creation_reconciliation_required",
                    "A project agent may already have been created; reconcile that exact attempt "
                    "before creating another",
                    phase="task creation reconciliation",
                    delivery_attempted=False,
                    retry_safe=False,
                    reconciliation_required=True,
                    receipt={"creationRequestId": guard.get("requestId")},
                )
            try:
                created = self.codex.create_thread(
                    cwd=cwd,
                    title=self._conductor_title(project, kind),
                    developer_instructions=self._developer_instructions(project, kind),
                )
            except ConversationHostError as error:
                uncertain_id = str(error.receipt.get("threadId") or "").lower()
                if error.delivery_attempted and UUID_RE.fullmatch(uncertain_id):
                    self._save_mapping(project, kind, uncertain_id)
                elif error.delivery_attempted:
                    self._finish_creation_guard(project, kind, request_id, uncertain=True)
                else:
                    self._finish_creation_guard(project, kind, request_id, uncertain=False)
                raise
            try:
                self._save_mapping(project, kind, created["id"])
            except ConversationHostError as error:
                raise ConversationHostError(
                    "task_mapping_persist_failed",
                    "Codex created the project task, but Activity Monitor could not preserve its exact identity",
                    phase="task creation",
                    delivery_attempted=True,
                    retry_safe=False,
                    reconciliation_required=True,
                    receipt={"threadId": created["id"]},
                ) from error
            target = {
                **created,
                "projectId": project["id"],
                "projectProvider": project["provider"],
                "projectName": project["name"],
                "projectKey": project.get("storageKey"),
                "cwd": cwd,
            }
            return target, f"created-{kind}"

    def _claim(self, request_id: str, project_key: str, provider: str, digest: str) -> tuple[str, dict]:
        request_id = str(request_id or "").lower()
        if not UUID_RE.fullmatch(request_id):
            raise ConversationHostError(
                "client_request_id_invalid",
                "Each queued request needs one fixed UUID",
                phase="queue preflight",
            )

        def mutate(value: dict) -> tuple[str, dict]:
            now = datetime.now(tz=timezone.utc)
            for entry in value["receipts"]:
                if entry["requestId"] == request_id:
                    if entry["projectKey"] != project_key or entry["sha256"] != digest:
                        raise ConversationHostError(
                            "client_request_id_reused",
                            "That queue identity already belongs to a different request",
                            phase="queue preflight",
                        )
                    return "existing", dict(entry)
            for entry in value["receipts"]:
                if entry["projectKey"] != project_key or entry["sha256"] != digest:
                    continue
                if entry.get("state") == "failed before send" and entry.get("retrySafe") is True:
                    continue
                try:
                    observed = datetime.fromisoformat(str(entry.get("timestamp") or "").replace("Z", "+00:00"))
                    if observed.tzinfo is None:
                        observed = observed.replace(tzinfo=timezone.utc)
                    age = (now - observed.astimezone(timezone.utc)).total_seconds()
                except (TypeError, ValueError, OverflowError):
                    continue
                if 0 <= age <= RECONCILIATION_WINDOW_SECONDS and (
                    entry.get("deliveryAttempted") is True
                    or entry.get("reconciliationRequired") is True
                    or entry.get("state") in {
                        "attempting", "accepted", "working", "acknowledged", "completed",
                        "uncertain after send", "transcript observed", "reconciliation required",
                    }
                ):
                    return "conflict", dict(entry)
            entry = {
                "requestId": request_id,
                "sha256": digest,
                "projectKey": project_key,
                "provider": provider,
                "destinationId": None,
                "destinationProvider": None,
                "routeKind": None,
                "state": "attempting",
                "phase": "resolving",
                "deliveryAttempted": False,
                "retrySafe": True,
                "reconciliationRequired": False,
                "timestamp": _utc_now(),
                "instanceId": self.instance_id,
                "clientUserMessageId": request_id,
                "turnId": None,
                "providerMessageId": None,
                "code": None,
            }
            value["receipts"].insert(0, entry)
            del value["receipts"][MAX_RECEIPTS:]
            return "claimed", dict(entry)

        return self.store.mutate(mutate)

    def _update_receipt(self, request_id: str, **patch: object) -> dict:
        allowed = {
            "destinationId", "destinationProvider", "routeKind", "state", "phase",
            "deliveryAttempted", "retrySafe", "reconciliationRequired",
            "clientUserMessageId", "turnId", "providerMessageId", "code",
        }

        def mutate(value: dict) -> dict:
            entry = next((item for item in value["receipts"] if item["requestId"] == request_id), None)
            if entry is None:
                raise ConversationHostError(
                    "receipt_missing",
                    "The queued request receipt is unavailable",
                    phase="local receipt",
                )
            for key, item in patch.items():
                if key in allowed:
                    entry[key] = item
            entry["timestamp"] = _utc_now()
            return dict(entry)

        return self.store.mutate(mutate)

    @staticmethod
    def _public_receipt(entry: dict) -> dict:
        return {
            key: entry.get(key)
            for key in (
                "requestId", "projectKey", "provider", "destinationId", "destinationProvider",
                "routeKind", "state", "phase", "deliveryAttempted", "retrySafe",
                "reconciliationRequired", "clientUserMessageId", "turnId",
                "providerMessageId", "code", "timestamp",
            )
        }

    def _send(self, target: dict, message: str, request_id: str) -> dict:
        self._require_full_access()
        provider = str(target.get("provider") or "").lower()
        if provider == "codex":
            return self.codex.send(target, message, request_id)
        if provider == "claude":
            return self.claude.send(target, message, request_id)
        raise ConversationHostError(
            "destination_provider_invalid",
            "The selected destination provider is unsupported",
            phase="owner preflight",
        )

    def _assert_destination_reconciled(self, target: dict, request_id: str) -> None:
        now = time.time()
        for entry in self.store.read().get("receipts", []):
            if entry.get("requestId") == request_id:
                continue
            if (
                entry.get("destinationProvider") != target["provider"]
                or entry.get("destinationId") != target["id"]
            ):
                continue
            age = now - _epoch(entry.get("timestamp"))
            if not 0 <= age <= RECONCILIATION_WINDOW_SECONDS:
                continue
            stale_process_attempt = (
                entry.get("state") in {
                    "attempting", "resolving", "accepted", "working", "acknowledged",
                }
                and entry.get("instanceId") != self.instance_id
            )
            if entry.get("reconciliationRequired") is True or stale_process_attempt or entry.get("state") in {
                "uncertain after send", "reconciliation required",
            }:
                raise ConversationHostError(
                    "destination_reconciliation_required",
                    "A prior message to this exact conversation still needs reconciliation",
                    phase="destination reconciliation",
                    delivery_attempted=False,
                    retry_safe=False,
                    reconciliation_required=True,
                    receipt={
                        "requestId": entry.get("requestId"),
                        "destinationId": target["id"],
                        "destinationProvider": target["provider"],
                    },
                )

    def submit(self, provider: str, project_id: str, message: str, request_id: str) -> dict:
        original = str(message or "")
        if not original.strip():
            raise ConversationHostError(
                "message_empty",
                "Write a request for the project Conductor",
                phase="queue preflight",
            )
        if len(original.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ConversationHostError("message_too_large", "That request is too large", phase="queue preflight")
        project = self._project(provider, project_id, force=True)
        project_key = self._project_key(project["provider"], project["id"])
        digest = _sha256(original)
        claim_state, entry = self._claim(request_id, project_key, project["provider"], digest)
        if claim_state == "existing":
            return {
                "ok": entry.get("state") in {
                    "accepted", "working", "acknowledged", "completed", "transcript observed",
                },
                "schemaVersion": SCHEMA_VERSION,
                "idempotentReplay": True,
                "receipt": self._public_receipt(entry),
                "privacy": self.privacy(),
            }
        if claim_state == "conflict":
            raise ConversationHostError(
                "reconciliation_required",
                "This exact request may already have reached the project; reconcile it before sending again",
                phase=str(entry.get("phase") or entry.get("state") or "reconciliation"),
                delivery_attempted=True,
                retry_safe=False,
                reconciliation_required=True,
                receipt=entry,
            )
        kind = "powerswarm" if POWERSWARM_RE.search(original) else "conductor"
        try:
            target, route_kind = self._destination(project, kind, original, request_id)
            entry = self._update_receipt(
                request_id,
                destinationId=target["id"],
                destinationProvider=target["provider"],
                routeKind=route_kind,
                state="resolving",
                phase="owner preflight",
            )
            with self._destination_lock(target):
                self._assert_destination_reconciled(target, request_id)
                delivery = self._send(target, original, request_id)
                state = str(delivery.get("state") or "accepted")
                attempted = delivery.get("deliveryAttempted") is True
                reconciliation = delivery.get("reconciliationRequired") is True
                entry = self._update_receipt(
                    request_id,
                    state=state,
                    phase=str(delivery.get("phase") or state),
                    deliveryAttempted=attempted,
                    retrySafe=delivery.get("retrySafe") is True,
                    reconciliationRequired=reconciliation,
                    clientUserMessageId=delivery.get("clientUserMessageId") or request_id,
                    turnId=delivery.get("turnId"),
                    providerMessageId=delivery.get("providerMessageId"),
                )
            return {
                "ok": not reconciliation,
                "schemaVersion": SCHEMA_VERSION,
                "project": {
                    "provider": project["provider"],
                    "id": project["id"],
                    "name": project["name"],
                },
                "destination": {
                    "provider": target["provider"],
                    "id": target["id"],
                    "title": target["title"],
                },
                "receipt": self._public_receipt(entry),
                "privacy": self.privacy(),
            }
        except ConversationHostError as error:
            state = (
                "uncertain after send"
                if error.delivery_attempted
                else "reconciliation required"
                if error.reconciliation_required
                else "failed before send"
            )
            entry = self._update_receipt(
                request_id,
                state=state,
                phase=error.phase,
                deliveryAttempted=error.delivery_attempted,
                retrySafe=error.retry_safe,
                reconciliationRequired=error.reconciliation_required,
                code=error.code,
                clientUserMessageId=error.receipt.get("clientUserMessageId") or request_id,
                turnId=error.receipt.get("turnId"),
                providerMessageId=error.receipt.get("providerMessageId") or error.receipt.get("msgId"),
                destinationId=error.receipt.get("threadId") or entry.get("destinationId"),
            )
            raise ConversationHostError(
                error.code,
                str(error),
                phase=error.phase,
                delivery_attempted=error.delivery_attempted,
                retry_safe=error.retry_safe,
                reconciliation_required=error.reconciliation_required,
                receipt=entry,
            ) from error

    def send_conversation(self, provider: str, conversation_id: str, message: str, request_id: str) -> dict:
        project, target = self._conversation_or_mapped(provider, conversation_id, force=True)
        original = str(message or "")
        if not original.strip():
            raise ConversationHostError("message_empty", "Write a message first", phase="queue preflight")
        if len(original.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ConversationHostError("message_too_large", "That message is too large", phase="queue preflight")
        project_key = self._project_key(project["provider"], project["id"])
        claim_state, entry = self._claim(request_id, project_key, project["provider"], _sha256(original))
        if claim_state == "existing":
            return {
                "ok": entry.get("state") in {
                    "accepted", "working", "acknowledged", "completed", "transcript observed",
                },
                "schemaVersion": SCHEMA_VERSION,
                "idempotentReplay": True,
                "receipt": self._public_receipt(entry),
                "privacy": self.privacy(),
            }
        if claim_state == "conflict":
            raise ConversationHostError(
                "reconciliation_required",
                "This exact message may already have reached the conversation",
                phase=str(entry.get("phase") or "reconciliation"),
                delivery_attempted=True,
                retry_safe=False,
                reconciliation_required=True,
                receipt=entry,
            )
        try:
            self._update_receipt(
                request_id,
                destinationId=target["id"],
                destinationProvider=target["provider"],
                routeKind="exact-conversation",
                state="resolving",
                phase="owner preflight",
            )
            with self._destination_lock(target):
                self._assert_destination_reconciled(target, request_id)
                delivery = self._send(target, original, request_id)
                reconciliation = delivery.get("reconciliationRequired") is True
                entry = self._update_receipt(
                    request_id,
                    state=str(delivery.get("state") or "accepted"),
                    phase=str(delivery.get("phase") or "accepted"),
                    deliveryAttempted=delivery.get("deliveryAttempted") is True,
                    retrySafe=delivery.get("retrySafe") is True,
                    reconciliationRequired=reconciliation,
                    clientUserMessageId=delivery.get("clientUserMessageId") or request_id,
                    turnId=delivery.get("turnId"),
                    providerMessageId=delivery.get("providerMessageId"),
                )
            return {
                "ok": not reconciliation,
                "schemaVersion": SCHEMA_VERSION,
                "destination": {
                    "provider": target["provider"],
                    "id": target["id"],
                    "title": target["title"],
                },
                "receipt": self._public_receipt(entry),
                "privacy": self.privacy(),
            }
        except ConversationHostError as error:
            state = (
                "uncertain after send"
                if error.delivery_attempted
                else "reconciliation required"
                if error.reconciliation_required
                else "failed before send"
            )
            entry = self._update_receipt(
                request_id,
                state=state,
                phase=error.phase,
                deliveryAttempted=error.delivery_attempted,
                retrySafe=error.retry_safe,
                reconciliationRequired=error.reconciliation_required,
                code=error.code,
                clientUserMessageId=error.receipt.get("clientUserMessageId") or request_id,
                turnId=error.receipt.get("turnId"),
                providerMessageId=error.receipt.get("providerMessageId") or error.receipt.get("msgId"),
                destinationId=error.receipt.get("threadId") or target["id"],
            )
            raise ConversationHostError(
                error.code,
                str(error),
                phase=error.phase,
                delivery_attempted=error.delivery_attempted,
                retry_safe=error.retry_safe,
                reconciliation_required=error.reconciliation_required,
                receipt=entry,
            ) from error

    def read_conversation(self, provider: str, conversation_id: str) -> dict:
        _, target = self._conversation_or_mapped(provider, conversation_id, force=True)
        if target["provider"] == "codex":
            payload = self.codex.read(target)
        else:
            payload = self.claude.read(target)
        payload.update({
            "schemaVersion": SCHEMA_VERSION,
            "privacy": self.privacy(body_read=True),
        })
        return payload

    def reconcile_request(self, request_id: str) -> dict:
        """Observe an exact provider message ID without persisting transcript text."""
        request_id = str(request_id or "").lower()
        if not UUID_RE.fullmatch(request_id):
            raise ConversationHostError(
                "client_request_id_invalid",
                "Choose one exact queued request",
                phase="reconciliation",
            )
        entry = next(
            (item for item in self.store.read().get("receipts", []) if item.get("requestId") == request_id),
            None,
        )
        if entry is None:
            raise ConversationHostError(
                "receipt_missing",
                "That queued request has no local metadata receipt",
                phase="reconciliation",
            )
        provider = str(entry.get("destinationProvider") or "").lower()
        destination_id = str(entry.get("destinationId") or "").lower()
        if provider not in {"codex", "claude"} or not UUID_RE.fullmatch(destination_id):
            return {
                "ok": False,
                "schemaVersion": SCHEMA_VERSION,
                "state": entry.get("state"),
                "transcriptObserved": False,
                "receipt": self._public_receipt(entry),
                "privacy": self.privacy(),
            }
        _, target = self._conversation_or_mapped(provider, destination_id, force=True)
        transcript = self.codex.read(target) if provider == "codex" else self.claude.read(target)
        exact_ids = {
            str(value).lower()
            for value in (entry.get("clientUserMessageId"), entry.get("providerMessageId"))
            if UUID_RE.fullmatch(str(value or ""))
        }
        observed = bool(
            exact_ids
            and any(str(item.get("id") or "").lower() in exact_ids for item in transcript.get("items", []))
        )
        if observed:
            entry = self._update_receipt(
                request_id,
                state="transcript observed",
                phase="transcript observed",
                deliveryAttempted=True,
                retrySafe=False,
                reconciliationRequired=False,
            )
        return {
            "ok": observed,
            "schemaVersion": SCHEMA_VERSION,
            "state": entry.get("state"),
            "transcriptObserved": observed,
            "receipt": self._public_receipt(entry),
            "privacy": self.privacy(body_read=True),
        }

    def project_state(self, provider: str, project_id: str) -> dict:
        project = self._project(provider, project_id, force=True)
        store = self.store.read()
        project_key = self._project_key(project["provider"], project["id"])
        receipts = [
            self._public_receipt(item)
            for item in store["receipts"]
            if item.get("projectKey") == project_key
        ][:40]
        mapped = {
            key.rsplit(":", 1)[-1]: value
            for key, value in store["mappings"].items()
            if key.startswith(project_key + ":")
        }
        return {
            "ok": True,
            "schemaVersion": SCHEMA_VERSION,
            "project": {
                "provider": project["provider"],
                "id": project["id"],
                "name": project["name"],
                "conversationCount": int(project.get("conversationCount") or len(project.get("conversations") or [])),
                "brainId": project.get("brainId"),
            },
            "agents": mapped,
            "queue": receipts,
            "capabilities": {
                "nativeHost": True,
                "activityMonitorHost": True,
                "conductor": True,
                "powerSwarmExistingOrCreate": True,
                "rapidFollowups": True,
                "fullAccessRequired": True,
            },
            "privacy": self.privacy(),
        }
