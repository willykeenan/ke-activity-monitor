"""Governed project-scoped Obsidian Brain provisioning for Activity Monitor.

Project Brains are real nested Obsidian vaults beneath the canonical KE Brain.
Only bounded project identity metadata is persisted; repository paths, prompts,
conversation bodies, transcripts, and credentials are never accepted here.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from typing import Iterable


REGISTRY_SCHEMA_VERSION = "ke.activity-monitor-project-brains.v1"
CHILD_SCHEMA_VERSION = "ke.project-brain.v1"
REGISTRY_FILENAME = ".activity-monitor-project-brains.json"
LOCK_FILENAME = ".activity-monitor-project-brains.lock"
MARKER_FILENAME = ".ke-project-brain.json"
MANIFEST_FILENAME = "Project Brain.md"
PROJECT_FOLDERS = (".obsidian", "Inbox", "Decisions", "Reference", "Sessions")
MAX_PROJECT_BRAINS = 256
MAX_REGISTRY_BYTES = 512 * 1024
MAX_MARKER_BYTES = 32 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_LABEL_CHARS = 160
LABEL_POLICY_VERSION = "ke.project-brain-label-policy.v1"
RENAME_SWAP = 0x00000002
RENAME_EXCL = 0x00000004
FILE_IDENTITY_FIELDS = ("st_dev", "st_ino")
REGISTRY_ROOT_FIELDS = frozenset({"schemaVersion", "parentBrainId", "projects"})
REGISTRY_RECORD_FIELDS = frozenset({
    "provider",
    "projectId",
    "label",
    "directoryName",
    "brainId",
    "parentBrainId",
    "lifecycleState",
    "createdAt",
    "updatedAt",
})
PERSISTED_PROJECT_FIELDS = frozenset({
    "schema",
    "schemaVersion",
    "projects",
    "provider",
    "projectId",
    "label",
    "projectLabel",
    "directoryName",
    "brainId",
    "parentBrainId",
    "lifecycleState",
    "createdAt",
    "updatedAt",
})
CODEX_PROJECT_RE = re.compile(
    r"(?:local-[0-9a-f]{32}|codex-unfiled|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)
CLAUDE_PROJECT_RE = re.compile(r"claude-[0-9a-f]{24}", re.IGNORECASE)
DIRECTORY_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,55}--[0-9a-f]{12}")
UTC_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z"
)
PATH_LABEL_RE = re.compile(r"(?:^|\s)(?:/|~/|[a-z]:[\\/])", re.IGNORECASE)
CREDENTIAL_LABEL_RES = (
    # AWS access-key IDs. Match case-insensitively so a directory slug cannot
    # retain a lower-cased credential that the provider label check rejected.
    re.compile(
        r"(?<![a-z0-9])(?:a3t[a-z0-9]|akia|agpa|aida|aroa|aipa|anpa|anva|asia)[a-z0-9]{16}(?![a-z0-9])",
        re.IGNORECASE,
    ),
    # GitHub classic and fine-grained token forms, including the hyphenated
    # form that slug generation would otherwise place in a directory name.
    re.compile(r"(?<![a-z0-9])gh[pousr][-_][a-z0-9]{20,255}(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])github[-_]pat[-_][a-z0-9_-]{20,255}(?![a-z0-9])", re.IGNORECASE),
    # Slack bot/user/app/config token families and their slug-safe forms.
    re.compile(r"(?<![a-z0-9])xox[baprs]-[a-z0-9-]{10,255}(?![a-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![a-z0-9])xapp-[a-z0-9-]{10,255}(?![a-z0-9])", re.IGNORECASE),
    # Common explicit credential and secret labels. Word boundaries preserve
    # ordinary names such as Cybersecurity, KE Guard, and Cyber Defense.
    re.compile(
        r"(?:^|[^a-z0-9])(?:api[-_ ]?key|access[-_ ]?key|access[-_ ]?token|"
        r"authorization|bearer|client[-_ ]?secret|credential(?:s)?|password|passphrase|"
        r"private[-_ ]?key|secret(?:s)?|token(?:s)?|sk[-_](?:live|test|proj)?[-_a-z0-9]*)"
        r"(?:$|[^a-z0-9])",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
)


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _path_key(path: str | Path) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(os.path.expanduser(str(path)))))


def brain_id_for_path(path: str | Path) -> str:
    return "brain_" + hashlib.sha256(_path_key(path).encode("utf-8")).hexdigest()[:16]


def project_brain_id(provider: str, project_id: str) -> str:
    """Stable provider-project identity; independent of labels and path swaps."""
    key = _project_key(provider, project_id)
    return "brain_project_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


def _project_key(provider: str, project_id: str) -> str:
    return f"{provider}:{project_id.lower()}"


def _label_policy_violations(value: str) -> frozenset[str]:
    violations: set[str] = set()
    if PATH_LABEL_RE.search(value) or "/" in value or "\\" in value:
        violations.add("path")
    if any(pattern.search(value) for pattern in CREDENTIAL_LABEL_RES):
        violations.add("credential")
    return frozenset(violations)


def _label_is_sensitive(value: str) -> bool:
    return bool(_label_policy_violations(value))


def _persisted_label_is_safe(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > MAX_LABEL_CHARS:
        return False
    normalized = re.sub(r"[\x00-\x1f\x7f]+", " ", value)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized == value and not _label_policy_violations(value)


def _safe_label(value: object, fallback: str) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    if not text or _label_is_sensitive(text):
        text = fallback
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_LABEL_CHARS].strip()


def _directory_name(label: str, key: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", label.casefold()).strip("-")[:48]
    slug = slug or "project"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"{slug}--{digest}"


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not UTC_TIMESTAMP_RE.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _file_identity(metadata: os.stat_result) -> tuple[int, int]:
    return tuple(int(getattr(metadata, field)) for field in FILE_IDENTITY_FIELDS)


def _metadata_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    """Exact bounded-file observation used only for read-time attestation."""
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_uid),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _renameatx_np(
    source_fd: int,
    source_name: str,
    target_fd: int,
    target_name: str,
    flags: int,
) -> None:
    """Use Darwin's atomic rename extensions; never fall back unsafely."""
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameatx_np", None)
    if function is None:
        raise OSError(errno.ENOTSUP, "atomic no-replace rename is unavailable")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(
        int(source_fd),
        os.fsencode(source_name),
        int(target_fd),
        os.fsencode(target_name),
        int(flags),
    )
    if result != 0:
        observed_errno = ctypes.get_errno() or errno.EIO
        raise OSError(observed_errno, os.strerror(observed_errno), target_name)


def _rename_directory_noreplace(parent_fd: int, source_name: str, target_name: str) -> None:
    _renameatx_np(parent_fd, source_name, parent_fd, target_name, RENAME_EXCL)


def _rename_file_noreplace(parent_fd: int, source_name: str, target_name: str) -> None:
    _renameatx_np(parent_fd, source_name, parent_fd, target_name, RENAME_EXCL)


def _rename_file_exchange(parent_fd: int, source_name: str, target_name: str) -> None:
    _renameatx_np(parent_fd, source_name, parent_fd, target_name, RENAME_SWAP)


class ProjectBrainError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ProjectBrainRegistry:
    """Descriptor-bound registry and lifecycle manager for project Brains."""

    def __init__(
        self,
        *,
        home: str | Path | None = None,
        parent_root: str | Path | None = None,
        max_projects: int = MAX_PROJECT_BRAINS,
    ):
        self.home = Path(home or Path.home()).expanduser().resolve()
        self.parent_root = Path(parent_root or self.home / ".grokcode" / "brain").expanduser()
        if not self.parent_root.is_absolute():
            raise ValueError("Project Brain parent must be an absolute path")
        self.projects_root = self.parent_root / "GrokCode" / "Projects"
        self.max_projects = max(1, min(MAX_PROJECT_BRAINS, int(max_projects)))
        self._lock = threading.RLock()

    @staticmethod
    def privacy(
        persisted_records: Iterable[dict] = (),
        *,
        persisted_values_validated: bool = False,
    ) -> dict:
        persisted = set(PERSISTED_PROJECT_FIELDS)
        records = list(persisted_records)
        exact_values: list[str] = []
        value_policy_passed = bool(persisted_values_validated)
        for record in records:
            if not isinstance(record, dict):
                value_policy_passed = False
                continue
            label = record.get("label")
            directory_name = record.get("directoryName")
            if isinstance(label, str):
                exact_values.append(label)
            else:
                value_policy_passed = False
            if isinstance(directory_name, str):
                exact_values.append(directory_name)
            else:
                value_policy_passed = False
            if not _persisted_label_is_safe(label) or _label_policy_violations(str(directory_name or "")):
                value_policy_passed = False
        exact_violations: set[str] = set()
        for value in exact_values:
            exact_violations.update(_label_policy_violations(value))
        schema_path_fields = persisted & {"path", "cwd", "repositoryPath", "workspacePath"}
        schema_credential_fields = persisted & {"credential", "credentials", "token", "secret", "apiKey"}
        return {
            "localOnly": True,
            "projectMetadataOnly": True,
            "persistedFields": sorted(persisted),
            "repositoryPathsStored": bool(schema_path_fields or "path" in exact_violations or not value_policy_passed),
            "promptBodiesStored": bool(persisted & {"prompt", "promptBody", "messageBody"}),
            "transcriptBodiesStored": bool(persisted & {"transcript", "transcriptBody"}),
            "noteBodiesStored": bool(persisted & {"noteBody", "body", "content"}),
            "credentialsStored": bool(
                schema_credential_fields or "credential" in exact_violations or not value_policy_passed
            ),
            "labelsSanitized": value_policy_passed,
            "labelPolicyVersion": LABEL_POLICY_VERSION,
            "persistedValuesValidated": value_policy_passed,
            "persistedLabelCount": len(records),
            "promptBodiesRead": False,
            "transcriptBodiesRead": False,
            "noteBodiesRead": False,
            "credentialsRead": False,
            "automaticDeletion": False,
        }

    @staticmethod
    def _validate_directory(descriptor: int, *, private: bool = False) -> os.stat_result:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ProjectBrainError("directory_untrusted", "Project Brain storage is not a current-user directory")
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & 0o022:
            raise ProjectBrainError("directory_insecure", "Project Brain storage is writable by another user")
        if private and mode != 0o700:
            os.fchmod(descriptor, 0o700)
        return metadata

    def _open_absolute_directory(self, path: Path) -> int:
        if any(component in {"", ".", ".."} for component in path.parts[1:]):
            raise ProjectBrainError("parent_untrusted", "The canonical KE Brain path is invalid")
        try:
            path.relative_to(self.home)
        except ValueError as error:
            raise ProjectBrainError("parent_outside_home", "Project Brains must stay beneath the current user's home") from error
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = -1
        try:
            descriptor = os.open(path.anchor, flags)
            for component in path.parts[1:]:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            metadata = self._validate_directory(descriptor)
            home_device = self.home.stat().st_dev
            if metadata.st_dev != home_device:
                raise ProjectBrainError("parent_nonlocal", "Project Brains must use the local home filesystem")
            return descriptor
        except ProjectBrainError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except FileNotFoundError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise ProjectBrainError("parent_missing", "The canonical KE Brain is unavailable") from error
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise ProjectBrainError("parent_untrusted", "The canonical KE Brain cannot be securely opened") from error

    @staticmethod
    def _open_child_directory(parent_fd: int, name: str, *, private: bool = False) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except OSError as error:
            raise ProjectBrainError("child_untrusted", "A Project Brain directory is missing or untrusted") from error
        try:
            ProjectBrainRegistry._validate_directory(descriptor, private=private)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _directory_entry(parent_fd: int, name: str) -> os.stat_result | None:
        try:
            return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise ProjectBrainError("directory_untrusted", "Project Brain storage changed during validation") from error

    def _open_projects_root(self, *, create_projects: bool) -> tuple[int, int, int]:
        parent_fd = self._open_absolute_directory(self.parent_root)
        grok_fd = projects_fd = -1
        try:
            obsidian = self._directory_entry(parent_fd, ".obsidian")
            if (
                obsidian is None
                or not stat.S_ISDIR(obsidian.st_mode)
                or stat.S_ISLNK(obsidian.st_mode)
                or obsidian.st_uid != os.getuid()
                or stat.S_IMODE(obsidian.st_mode) & 0o022
            ):
                raise ProjectBrainError("parent_not_obsidian", "The canonical KE Brain is not an Obsidian vault")
            grok_fd = self._open_child_directory(parent_fd, "GrokCode")
            projects_meta = self._directory_entry(grok_fd, "Projects")
            if projects_meta is None:
                if not create_projects:
                    raise ProjectBrainError("projects_root_missing", "The KE Brain Projects area is unavailable")
                os.mkdir("Projects", 0o700, dir_fd=grok_fd)
                os.fsync(grok_fd)
            projects_fd = self._open_child_directory(grok_fd, "Projects")
            parent_meta = os.fstat(parent_fd)
            if os.fstat(projects_fd).st_dev != parent_meta.st_dev:
                raise ProjectBrainError("projects_nonlocal", "Project Brains must remain on the canonical Brain filesystem")
            return parent_fd, grok_fd, projects_fd
        except Exception:
            for descriptor in (projects_fd, grok_fd, parent_fd):
                if descriptor >= 0:
                    os.close(descriptor)
            raise

    @staticmethod
    def _read_regular_bytes_with_fingerprint(
        parent_fd: int,
        name: str,
        *,
        max_bytes: int,
        required_mode: int = 0o600,
    ) -> tuple[bytes, tuple[int, ...]]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = -1
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != required_mode
                or metadata.st_size < 2
                or metadata.st_size > max_bytes
            ):
                raise ProjectBrainError("metadata_untrusted", "Project Brain metadata is not a private bounded file")
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining > 0:
                chunk = os.read(descriptor, min(16_384, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            observed = os.fstat(descriptor)
            if (
                len(payload) != metadata.st_size
                or observed.st_dev != metadata.st_dev
                or observed.st_ino != metadata.st_ino
                or observed.st_size != metadata.st_size
                or observed.st_mtime_ns != metadata.st_mtime_ns
                or observed.st_ctime_ns != metadata.st_ctime_ns
            ):
                raise ProjectBrainError("metadata_changed", "Project Brain metadata changed while it was read")
            return payload, _metadata_fingerprint(observed)
        except FileNotFoundError:
            raise
        except ProjectBrainError:
            raise
        except OSError as error:
            raise ProjectBrainError("metadata_corrupt", "Project Brain metadata is invalid") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _read_regular_bytes_with_identity(
        parent_fd: int,
        name: str,
        *,
        max_bytes: int,
        required_mode: int = 0o600,
    ) -> tuple[bytes, tuple[int, int]]:
        payload, fingerprint = ProjectBrainRegistry._read_regular_bytes_with_fingerprint(
            parent_fd,
            name,
            max_bytes=max_bytes,
            required_mode=required_mode,
        )
        return payload, (fingerprint[0], fingerprint[1])

    @staticmethod
    def _require_snapshot_fingerprint(
        parent_fd: int,
        name: str,
        expected: tuple[int, ...],
    ) -> None:
        current = ProjectBrainRegistry._directory_entry(parent_fd, name)
        if current is None or _metadata_fingerprint(current) != expected:
            raise ProjectBrainError(
                "metadata_identity_changed",
                "Project Brain metadata changed after its bounded read",
            )

    @staticmethod
    def _read_regular_bytes(
        parent_fd: int,
        name: str,
        *,
        max_bytes: int,
        required_mode: int = 0o600,
    ) -> bytes:
        payload, _identity = ProjectBrainRegistry._read_regular_bytes_with_identity(
            parent_fd,
            name,
            max_bytes=max_bytes,
            required_mode=required_mode,
        )
        return payload

    @staticmethod
    def _read_regular_json_with_identity(
        parent_fd: int,
        name: str,
        *,
        max_bytes: int,
        required_mode: int = 0o600,
    ) -> tuple[dict, tuple[int, int]]:
        try:
            payload, identity = ProjectBrainRegistry._read_regular_bytes_with_identity(
                parent_fd,
                name,
                max_bytes=max_bytes,
                required_mode=required_mode,
            )
            value = json.loads(payload.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("not an object")
            return value, identity
        except FileNotFoundError:
            raise
        except ProjectBrainError:
            raise
        except (ValueError, TypeError, UnicodeError) as error:
            raise ProjectBrainError("metadata_corrupt", "Project Brain metadata is invalid") from error

    @staticmethod
    def _read_regular_json(
        parent_fd: int,
        name: str,
        *,
        max_bytes: int,
        required_mode: int = 0o600,
    ) -> dict:
        value, _identity = ProjectBrainRegistry._read_regular_json_with_identity(
            parent_fd,
            name,
            max_bytes=max_bytes,
            required_mode=required_mode,
        )
        return value

    @staticmethod
    def _write_atomic(
        parent_fd: int,
        name: str,
        payload: bytes,
        *,
        expected_identity: tuple[int, int] | None,
        mode: int = 0o600,
    ) -> None:
        temporary = f".{name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
        descriptor = -1
        temporary_identity: tuple[int, int] | None = None
        preserve_temporary = False
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(temporary, flags, mode, dir_fd=parent_fd)
            os.fchmod(descriptor, mode)
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fsync(descriptor)
            temporary_identity = _file_identity(os.fstat(descriptor))
            os.close(descriptor)
            descriptor = -1
            if expected_identity is None:
                try:
                    _rename_file_noreplace(parent_fd, temporary, name)
                except OSError as error:
                    if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                        raise ProjectBrainError(
                            "metadata_identity_changed",
                            "Project Brain metadata appeared during its atomic commit",
                        ) from error
                    raise ProjectBrainError(
                        "atomic_commit_unavailable",
                        "Project Brain metadata cannot be committed with no-replace guarantees",
                    ) from error
            else:
                current = ProjectBrainRegistry._directory_entry(parent_fd, name)
                if current is None or _file_identity(current) != expected_identity:
                    raise ProjectBrainError(
                        "metadata_identity_changed",
                        "Project Brain metadata changed before its atomic commit",
                    )
                try:
                    _rename_file_exchange(parent_fd, temporary, name)
                except OSError as error:
                    raise ProjectBrainError(
                        "atomic_commit_unavailable",
                        "Project Brain metadata cannot be identity-conditionally committed",
                    ) from error
                swapped = ProjectBrainRegistry._directory_entry(parent_fd, temporary)
                if swapped is None or _file_identity(swapped) != expected_identity:
                    target = ProjectBrainRegistry._directory_entry(parent_fd, name)
                    if (
                        target is not None
                        and temporary_identity is not None
                        and _file_identity(target) == temporary_identity
                    ):
                        try:
                            _rename_file_exchange(parent_fd, temporary, name)
                        except OSError:
                            preserve_temporary = True
                    else:
                        preserve_temporary = True
                    raise ProjectBrainError(
                        "metadata_identity_changed",
                        "Project Brain metadata changed during its atomic commit",
                    )
                os.unlink(temporary, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not preserve_temporary:
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass

    @staticmethod
    def _registry_default(parent_brain_id: str) -> dict:
        return {
            "schemaVersion": REGISTRY_SCHEMA_VERSION,
            "parentBrainId": parent_brain_id,
            "projects": {},
        }

    def _read_registry(
        self,
        projects_fd: int,
        parent_brain_id: str,
    ) -> tuple[dict, tuple[int, int] | None]:
        try:
            value, identity = self._read_regular_json_with_identity(
                projects_fd,
                REGISTRY_FILENAME,
                max_bytes=MAX_REGISTRY_BYTES,
            )
        except FileNotFoundError:
            return self._registry_default(parent_brain_id), None
        if set(value) != REGISTRY_ROOT_FIELDS:
            raise ProjectBrainError("registry_corrupt", "The Project Brain registry has unexpected fields")
        if value.get("schemaVersion") != REGISTRY_SCHEMA_VERSION:
            raise ProjectBrainError("registry_schema_invalid", "The Project Brain registry has an unsupported schema")
        if value.get("parentBrainId") != parent_brain_id:
            raise ProjectBrainError("registry_parent_mismatch", "The Project Brain registry belongs to another parent Brain")
        records = value.get("projects")
        if not isinstance(records, dict) or len(records) > self.max_projects:
            raise ProjectBrainError("registry_bounds_invalid", "The Project Brain registry exceeds its safe bounds")
        for key, record in records.items():
            if (
                not isinstance(key, str)
                or not isinstance(record, dict)
                or set(record) != REGISTRY_RECORD_FIELDS
            ):
                raise ProjectBrainError("registry_corrupt", "The Project Brain registry contains an invalid record")
            provider = str(record.get("provider") or "")
            project_id = str(record.get("projectId") or "").lower()
            directory_name = str(record.get("directoryName") or "")
            label = record.get("label")
            created_at = record.get("createdAt")
            updated_at = record.get("updatedAt")
            expected_suffix = "--" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
            if (
                key != _project_key(provider, project_id)
                or provider not in {"codex", "claude"}
                or not self._valid_project_id(provider, project_id)
                or not DIRECTORY_NAME_RE.fullmatch(directory_name)
                or not directory_name.endswith(expected_suffix)
                or record.get("parentBrainId") != parent_brain_id
                or record.get("brainId") != project_brain_id(provider, project_id)
                or record.get("lifecycleState") not in {"active", "dormant"}
                or not isinstance(label, str)
                or not _persisted_label_is_safe(label)
                or _label_policy_violations(directory_name)
                or not _valid_timestamp(created_at)
                or not _valid_timestamp(updated_at)
                or _timestamp_value(str(updated_at)) < _timestamp_value(str(created_at))
            ):
                raise ProjectBrainError("registry_corrupt", "The Project Brain registry contains an invalid record")
        return value, identity

    def _read_snapshot_registry(
        self,
        projects_fd: int,
        parent_brain_id: str,
    ) -> tuple[dict, tuple[int, ...] | None]:
        """Read and canonically bind the registry used for a public snapshot."""
        registry, registry_identity = self._read_registry(projects_fd, parent_brain_id)
        if registry_identity is None:
            if self._directory_entry(projects_fd, REGISTRY_FILENAME) is not None:
                raise ProjectBrainError(
                    "metadata_identity_changed",
                    "The Project Brain registry appeared during snapshot validation",
                )
            return registry, None
        payload, fingerprint = self._read_regular_bytes_with_fingerprint(
            projects_fd,
            REGISTRY_FILENAME,
            max_bytes=MAX_REGISTRY_BYTES,
        )
        if (fingerprint[0], fingerprint[1]) != registry_identity or payload != _json_bytes(registry):
            raise ProjectBrainError(
                "metadata_identity_changed",
                "The Project Brain registry changed during snapshot validation",
            )
        return registry, fingerprint

    @staticmethod
    def _valid_project_id(provider: str, project_id: str) -> bool:
        if provider == "codex":
            return bool(CODEX_PROJECT_RE.fullmatch(project_id))
        if provider == "claude":
            return bool(CLAUDE_PROJECT_RE.fullmatch(project_id))
        return False

    def _normalize_projects(self, projects: Iterable[dict]) -> list[dict]:
        normalized: list[dict] = []
        seen: set[str] = set()
        for item in projects:
            if not isinstance(item, dict):
                continue
            provider = str(item.get("provider") or "").lower()
            project_id = str(item.get("projectId") or item.get("id") or "").lower()
            if not self._valid_project_id(provider, project_id):
                continue
            key = _project_key(provider, project_id)
            if key in seen:
                continue
            seen.add(key)
            fallback_label = (
                f"{provider.title()} project · "
                f"{hashlib.sha256(key.encode('utf-8')).hexdigest()[:8]}"
            )
            normalized.append(
                {
                    "key": key,
                    "provider": provider,
                    "projectId": project_id,
                    "label": _safe_label(item.get("label") or item.get("name"), fallback_label),
                }
            )
            if len(normalized) >= self.max_projects:
                break
        return normalized

    @staticmethod
    def _marker(record: dict) -> dict:
        return {
            "schemaVersion": CHILD_SCHEMA_VERSION,
            "brainId": record["brainId"],
            "parentBrainId": record["parentBrainId"],
            "provider": record["provider"],
            "projectId": record["projectId"],
            "label": record["label"],
            "lifecycleState": record["lifecycleState"],
            "createdAt": record["createdAt"],
        }

    @staticmethod
    def _manifest(record: dict) -> bytes:
        identity = {
            "schema": CHILD_SCHEMA_VERSION,
            "brainId": record["brainId"],
            "parentBrainId": record["parentBrainId"],
            "provider": record["provider"],
            "projectId": record["projectId"],
            "projectLabel": record["label"],
            "lifecycleState": record["lifecycleState"],
        }
        body = (
            "# Project Brain\n\n"
            "This is a governed project child of the canonical KE Studios Brain. "
            "It stores project-specific knowledge without copying the parent Brain corpus.\n\n"
            "Bounded identity metadata:\n\n"
            + "\n".join(
                "    " + line
                for line in json.dumps(identity, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
            )
            + "\n"
        )
        return body.encode("utf-8")

    def _validate_marker(
        self,
        child_fd: int,
        record: dict,
        *,
        adopt_created_at: bool = False,
    ) -> tuple[dict, tuple[int, int]]:
        marker, marker_identity = self._read_regular_json_with_identity(
            child_fd,
            MARKER_FILENAME,
            max_bytes=MAX_MARKER_BYTES,
        )
        expected = self._marker(record)
        for key in ("schemaVersion", "brainId", "parentBrainId", "provider", "projectId"):
            if marker.get(key) != expected.get(key):
                raise ProjectBrainError("child_identity_mismatch", "A Project Brain path is owned by another identity")
        if adopt_created_at:
            if not _valid_timestamp(marker.get("createdAt")):
                raise ProjectBrainError("child_identity_mismatch", "A Project Brain identity timestamp is invalid")
            record["createdAt"] = marker["createdAt"]
            expected = self._marker(record)
        elif marker.get("createdAt") != expected.get("createdAt"):
            raise ProjectBrainError("child_identity_mismatch", "A Project Brain path is owned by another identity")
        return marker, marker_identity

    def _child_needs_refresh(
        self,
        child_fd: int,
        record: dict,
        marker: dict,
    ) -> tuple[bool, tuple[int, int] | None]:
        refresh = False
        if (
            marker.get("label") != record["label"]
            or marker.get("lifecycleState") != record["lifecycleState"]
            or stat.S_IMODE(os.fstat(child_fd).st_mode) != 0o700
        ):
            refresh = True
        if marker != self._marker(record):
            refresh = True
        try:
            manifest, manifest_identity = self._read_regular_bytes_with_identity(
                child_fd,
                MANIFEST_FILENAME,
                max_bytes=MAX_MANIFEST_BYTES,
            )
        except FileNotFoundError:
            manifest = None
            manifest_identity = None
        if manifest != self._manifest(record):
            refresh = True
        for folder in PROJECT_FOLDERS:
            metadata = self._directory_entry(child_fd, folder)
            if (
                metadata is None
                or not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                refresh = True
        return refresh, manifest_identity

    @staticmethod
    def _remove_temporary_child(projects_fd: int, name: str, child_fd: int) -> None:
        for filename in (MARKER_FILENAME, MANIFEST_FILENAME):
            try:
                os.unlink(filename, dir_fd=child_fd)
            except FileNotFoundError:
                pass
        for folder in PROJECT_FOLDERS:
            try:
                os.rmdir(folder, dir_fd=child_fd)
            except FileNotFoundError:
                pass
        try:
            os.rmdir(name, dir_fd=projects_fd)
        except FileNotFoundError:
            pass

    def _create_child(self, projects_fd: int, record: dict, *, adopt_orphan: bool = False) -> None:
        final_name = record["directoryName"]
        existing = self._directory_entry(projects_fd, final_name)
        if existing is not None:
            child_fd = self._open_child_directory(projects_fd, final_name, private=False)
            try:
                marker, marker_identity = self._validate_marker(
                    child_fd,
                    record,
                    adopt_created_at=adopt_orphan,
                )
                needs_refresh, manifest_identity = self._child_needs_refresh(child_fd, record, marker)
                if adopt_orphan or needs_refresh:
                    self._refresh_child(
                        child_fd,
                        record,
                        marker_identity=marker_identity,
                        manifest_identity=manifest_identity,
                    )
            finally:
                os.close(child_fd)
            return

        temporary = f".project-brain-tmp-{os.getpid()}-{secrets.token_hex(6)}"
        child_fd = -1
        created = False
        try:
            os.mkdir(temporary, 0o700, dir_fd=projects_fd)
            created = True
            child_fd = self._open_child_directory(projects_fd, temporary, private=True)
            for folder in PROJECT_FOLDERS:
                os.mkdir(folder, 0o700, dir_fd=child_fd)
            self._write_atomic(
                child_fd,
                MARKER_FILENAME,
                _json_bytes(self._marker(record)),
                expected_identity=None,
            )
            self._write_atomic(
                child_fd,
                MANIFEST_FILENAME,
                self._manifest(record),
                expected_identity=None,
            )
            os.fsync(child_fd)
            _rename_directory_noreplace(projects_fd, temporary, final_name)
            created = False
            os.fsync(projects_fd)
        except OSError as error:
            if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                raise ProjectBrainError("child_path_conflict", "A Project Brain path already exists without matching identity") from error
            raise
        finally:
            if created and child_fd >= 0:
                try:
                    self._remove_temporary_child(projects_fd, temporary, child_fd)
                except OSError:
                    pass
            if child_fd >= 0:
                os.close(child_fd)

    def _refresh_child(
        self,
        child_fd: int,
        record: dict,
        *,
        marker_identity: tuple[int, int],
        manifest_identity: tuple[int, int] | None,
    ) -> None:
        self._validate_directory(child_fd, private=True)
        for folder in PROJECT_FOLDERS:
            metadata = self._directory_entry(child_fd, folder)
            if metadata is None:
                os.mkdir(folder, 0o700, dir_fd=child_fd)
                continue
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise ProjectBrainError("child_structure_untrusted", "A Project Brain structure entry is untrusted")
            descriptor = self._open_child_directory(child_fd, folder, private=True)
            os.close(descriptor)
        self._write_atomic(
            child_fd,
            MARKER_FILENAME,
            _json_bytes(self._marker(record)),
            expected_identity=marker_identity,
        )
        self._write_atomic(
            child_fd,
            MANIFEST_FILENAME,
            self._manifest(record),
            expected_identity=manifest_identity,
        )
        os.fsync(child_fd)

    def _child_state(self, projects_fd: int, record: dict) -> dict:
        result = {
            "brainId": record["brainId"],
            "parentBrainId": record["parentBrainId"],
            "projectId": record["projectId"],
            "provider": record["provider"],
            "label": record["label"],
            "lifecycleState": record["lifecycleState"],
            "createdAt": record["createdAt"],
            "updatedAt": record["updatedAt"],
            "path": str(self.projects_root / record["directoryName"]),
            "pathDisplay": "~/.grokcode/brain/GrokCode/Projects/" + record["directoryName"],
            "status": "ready",
            "accessible": True,
        }
        child_fd = -1
        try:
            child_fd = self._open_child_directory(projects_fd, record["directoryName"], private=False)
            child_metadata = os.fstat(child_fd)
            projects_metadata = os.fstat(projects_fd)
            child_identity = _file_identity(child_metadata)
            if stat.S_IMODE(child_metadata.st_mode) != 0o700:
                raise ProjectBrainError("child_insecure", "A Project Brain directory is not private")
            if child_metadata.st_dev != projects_metadata.st_dev:
                raise ProjectBrainError("child_nonlocal", "A Project Brain directory is not on the local Brain filesystem")

            marker_payload, marker_fingerprint = self._read_regular_bytes_with_fingerprint(
                child_fd,
                MARKER_FILENAME,
                max_bytes=MAX_MARKER_BYTES,
            )
            manifest_payload, manifest_fingerprint = self._read_regular_bytes_with_fingerprint(
                child_fd,
                MANIFEST_FILENAME,
                max_bytes=MAX_MANIFEST_BYTES,
            )
            if marker_fingerprint[0] != child_metadata.st_dev or manifest_fingerprint[0] != child_metadata.st_dev:
                raise ProjectBrainError("child_metadata_nonlocal", "Project Brain metadata is not on the child filesystem")
            if marker_payload != _json_bytes(self._marker(record)):
                raise ProjectBrainError("child_marker_mismatch", "A Project Brain marker is not canonical")
            if manifest_payload != self._manifest(record):
                raise ProjectBrainError("child_manifest_mismatch", "A Project Brain manifest is not canonical")

            self._require_snapshot_fingerprint(child_fd, MARKER_FILENAME, marker_fingerprint)
            self._require_snapshot_fingerprint(child_fd, MANIFEST_FILENAME, manifest_fingerprint)
            current_child = self._directory_entry(projects_fd, record["directoryName"])
            if (
                current_child is None
                or _file_identity(current_child) != child_identity
                or not stat.S_ISDIR(current_child.st_mode)
                or stat.S_ISLNK(current_child.st_mode)
                or current_child.st_uid != os.getuid()
                or stat.S_IMODE(current_child.st_mode) != 0o700
                or current_child.st_dev != projects_metadata.st_dev
            ):
                raise ProjectBrainError("child_identity_changed", "A Project Brain directory changed during validation")
        except FileNotFoundError:
            result.update({"status": "blocked", "accessible": False, "errorCode": "child_metadata_missing"})
        except ProjectBrainError as error:
            result.update({"status": "blocked", "accessible": False, "errorCode": error.code})
        except OSError:
            result.update({"status": "blocked", "accessible": False, "errorCode": "child_metadata_untrusted"})
        finally:
            if child_fd >= 0:
                os.close(child_fd)
        return result

    @staticmethod
    def _public_payload(
        parent_root: Path,
        parent_brain_id: str,
        children: list[dict],
        *,
        ok: bool = True,
        persisted_records: Iterable[dict] = (),
        persisted_values_validated: bool = False,
    ) -> dict:
        by_project = {
            _project_key(child["provider"], child["projectId"]): child
            for child in children
        }
        revision_rows = [
            {
                key: child.get(key)
                for key in ("brainId", "parentBrainId", "provider", "projectId", "label", "lifecycleState", "status", "accessible")
            }
            for child in children
        ]
        revision = "project_brains_" + hashlib.sha256(
            json.dumps(revision_rows, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()[:20]
        return {
            "ok": ok,
            "schemaVersion": REGISTRY_SCHEMA_VERSION,
            "parent": {
                "brainId": parent_brain_id,
                "label": "KE Studios Brain",
                "path": str(parent_root),
                "pathDisplay": "~/.grokcode/brain",
            },
            "children": children,
            "byProject": by_project,
            "counts": {
                "total": len(children),
                "active": sum(child.get("lifecycleState") == "active" for child in children),
                "dormant": sum(child.get("lifecycleState") == "dormant" for child in children),
                "blocked": sum(not child.get("accessible", False) for child in children),
            },
            "registryRevision": revision,
            "privacy": ProjectBrainRegistry.privacy(
                persisted_records,
                persisted_values_validated=persisted_values_validated,
            ),
        }

    def snapshot(self) -> dict:
        """Read a metadata-only, fail-soft projection of registered children."""
        with self._lock:
            parent_brain_id = brain_id_for_path(self.parent_root)
            descriptors: tuple[int, int, int] | None = None
            try:
                descriptors = self._open_projects_root(create_projects=False)
                projects_fd = descriptors[2]
                registry, registry_fingerprint = self._read_snapshot_registry(projects_fd, parent_brain_id)
                children = [
                    self._child_state(projects_fd, record)
                    for _key, record in sorted(registry["projects"].items())
                ]
                children.sort(key=lambda item: (item["lifecycleState"] != "active", item["label"].casefold(), item["brainId"]))
                if registry_fingerprint is None:
                    if self._directory_entry(projects_fd, REGISTRY_FILENAME) is not None:
                        raise ProjectBrainError(
                            "metadata_identity_changed",
                            "The Project Brain registry appeared before snapshot attestation",
                        )
                else:
                    self._require_snapshot_fingerprint(
                        projects_fd,
                        REGISTRY_FILENAME,
                        registry_fingerprint,
                    )
                projection_validated = all(
                    child.get("status") == "ready" and child.get("accessible") is True
                    for child in children
                )
                payload = self._public_payload(
                    self.parent_root,
                    parent_brain_id,
                    children,
                    ok=projection_validated,
                    persisted_records=registry["projects"].values(),
                    persisted_values_validated=projection_validated,
                )
                if not projection_validated:
                    payload.update({
                        "state": "unavailable",
                        "code": "project_brain_persistence_untrusted",
                        "error": "One or more managed Project Brain surfaces failed exact validation",
                    })
                return payload
            except ProjectBrainError as error:
                payload = self._public_payload(self.parent_root, parent_brain_id, [], ok=False)
                payload.update({"state": "unavailable", "code": error.code, "error": str(error)})
                return payload
            finally:
                if descriptors:
                    for descriptor in reversed(descriptors):
                        os.close(descriptor)

    def sync(self, projects: Iterable[dict]) -> dict:
        """Provision active projects and mark unseen children dormant, never delete."""
        normalized = self._normalize_projects(projects)
        with self._lock:
            parent_brain_id = brain_id_for_path(self.parent_root)
            descriptors: tuple[int, int, int] | None = None
            lock_fd = -1
            try:
                descriptors = self._open_projects_root(create_projects=True)
                projects_fd = descriptors[2]
                # Validate an existing registry before creating even the lock
                # file, so corrupt metadata produces no new side effects.
                self._read_registry(projects_fd, parent_brain_id)
                lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                lock_fd = os.open(LOCK_FILENAME, lock_flags, 0o600, dir_fd=projects_fd)
                lock_meta = os.fstat(lock_fd)
                if (
                    not stat.S_ISREG(lock_meta.st_mode)
                    or lock_meta.st_uid != os.getuid()
                    or stat.S_IMODE(lock_meta.st_mode) != 0o600
                ):
                    raise ProjectBrainError("lock_untrusted", "The Project Brain registry lock is untrusted")
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                registry, registry_identity = self._read_registry(projects_fd, parent_brain_id)
                original_registry = json.loads(json.dumps(registry))
                records = {key: dict(value) for key, value in registry["projects"].items()}
                active_keys = {item["key"] for item in normalized}
                now = _utc_now()
                errors: list[dict] = []

                for key, record in records.items():
                    lifecycle = "active" if key in active_keys else "dormant"
                    if record["lifecycleState"] != lifecycle:
                        record["lifecycleState"] = lifecycle
                        record["updatedAt"] = now

                for item in normalized:
                    key = item["key"]
                    existing_record = records.get(key)
                    adopt_orphan = existing_record is None
                    if existing_record is None:
                        if len(records) >= self.max_projects:
                            errors.append({
                                "provider": item["provider"],
                                "projectId": item["projectId"],
                                "code": "project_limit_reached",
                            })
                            continue
                        directory_name = _directory_name(item["label"], key)
                        record = {
                            "provider": item["provider"],
                            "projectId": item["projectId"],
                            "label": item["label"],
                            "directoryName": directory_name,
                            "brainId": project_brain_id(item["provider"], item["projectId"]),
                            "parentBrainId": parent_brain_id,
                            "lifecycleState": "active",
                            "createdAt": now,
                            "updatedAt": now,
                        }
                    else:
                        record = dict(existing_record)
                        if record["label"] != item["label"] or record["lifecycleState"] != "active":
                            record["label"] = item["label"]
                            record["lifecycleState"] = "active"
                            record["updatedAt"] = now
                    try:
                        self._create_child(projects_fd, record, adopt_orphan=adopt_orphan)
                    except (ProjectBrainError, OSError) as error:
                        errors.append({
                            "provider": item["provider"],
                            "projectId": item["projectId"],
                            "code": getattr(error, "code", "child_provision_failed"),
                        })
                        continue
                    records[key] = record

                # Lifecycle changes are reflected in managed manifests. A
                # blocked child is retained in the registry and never removed.
                for key, record in records.items():
                    if key in active_keys:
                        continue
                    try:
                        self._create_child(projects_fd, record)
                    except (ProjectBrainError, OSError) as error:
                        errors.append({
                            "provider": record["provider"],
                            "projectId": record["projectId"],
                            "code": getattr(error, "code", "child_refresh_failed"),
                        })

                registry = {
                    "schemaVersion": REGISTRY_SCHEMA_VERSION,
                    "parentBrainId": parent_brain_id,
                    "projects": dict(sorted(records.items())),
                }
                encoded = _json_bytes(registry)
                if len(encoded) > MAX_REGISTRY_BYTES:
                    raise ProjectBrainError("registry_bounds_invalid", "The Project Brain registry exceeds its safe bounds")
                if registry != original_registry:
                    self._write_atomic(
                        projects_fd,
                        REGISTRY_FILENAME,
                        encoded,
                        expected_identity=registry_identity,
                    )
                persisted_registry, persisted_registry_fingerprint = self._read_snapshot_registry(
                    projects_fd,
                    parent_brain_id,
                )
                if persisted_registry != registry:
                    raise ProjectBrainError(
                        "metadata_identity_changed",
                        "The Project Brain registry does not match the committed snapshot",
                    )
                children = [
                    self._child_state(projects_fd, record)
                    for _key, record in sorted(persisted_registry["projects"].items())
                ]
                children.sort(key=lambda child: (child["lifecycleState"] != "active", child["label"].casefold(), child["brainId"]))
                if persisted_registry_fingerprint is None:
                    if persisted_registry["projects"] or self._directory_entry(projects_fd, REGISTRY_FILENAME) is not None:
                        raise ProjectBrainError(
                            "metadata_identity_changed",
                            "The Project Brain registry changed before attestation",
                        )
                else:
                    self._require_snapshot_fingerprint(
                        projects_fd,
                        REGISTRY_FILENAME,
                        persisted_registry_fingerprint,
                    )
                projection_validated = not errors and all(
                    child.get("status") == "ready" and child.get("accessible") is True
                    for child in children
                )
                payload = self._public_payload(
                    self.parent_root,
                    parent_brain_id,
                    children,
                    persisted_records=persisted_registry["projects"].values(),
                    persisted_values_validated=projection_validated,
                )
                surface_errors = [
                    {
                        "provider": child["provider"],
                        "projectId": child["projectId"],
                        "code": child.get("errorCode", "child_persistence_untrusted"),
                    }
                    for child in children
                    if child.get("accessible") is not True
                ]
                payload["errors"] = (errors + surface_errors)[:32]
                payload["state"] = "ready" if projection_validated else "degraded"
                return payload
            except ProjectBrainError as error:
                payload = self._public_payload(self.parent_root, parent_brain_id, [], ok=False)
                payload.update({"state": "unavailable", "code": error.code, "error": str(error), "errors": []})
                return payload
            except OSError:
                payload = self._public_payload(self.parent_root, parent_brain_id, [], ok=False)
                payload.update({
                    "state": "unavailable",
                    "code": "project_brain_io_failed",
                    "error": "Project Brain storage could not be updated safely",
                    "errors": [],
                })
                return payload
            finally:
                if lock_fd >= 0:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                    os.close(lock_fd)
                if descriptors:
                    for descriptor in reversed(descriptors):
                        os.close(descriptor)
