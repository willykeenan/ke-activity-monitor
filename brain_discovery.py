"""Private, metadata-only discovery and reversible structure for local AI brains.

The scanner fingerprints directory names, marker files, and filesystem metadata.
It never opens note bodies, vector indexes, transcripts, or credential files.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
import threading
import time

from project_brains import ProjectBrainError, ProjectBrainRegistry, brain_id_for_path


SCHEMA_VERSION = "ke.activity-monitor-brains.v1"
SETTINGS_SCHEMA_VERSION = "ke.activity-monitor-brain-settings.v2"
ROOT_FINGERPRINT_SCHEMA_VERSION = "ke.activity-monitor-brain-root-fingerprint.v1"
MAX_SETTINGS_BYTES = 512 * 1024
MAX_SETTINGS_ROOTS = 512
NOTE_EXTENSIONS = {".md", ".markdown", ".txt", ".canvas", ".org", ".rst"}
GENERIC_BRAIN_NAMES = {"brain", "brains", "vault", "vaults", "knowledge", "memory", "memories"}
SKIP_DIRECTORY_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".Trash",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "bower_components",
    "Pods",
    "DerivedData",
    "Caches",
    "cache",
    "build",
    "dist",
    "out",
    "target",
    "vendor",
    "SDKs",
}
ROOT_HEAVY_DIRECTORIES = {
    "Applications",
    "NonstopBuild",
    "Pictures",
    "Movies",
    "Music",
    "Public",
}
MANAGED_TYPES = {"Codex memory", "Claude memory", "KE Desktop brain", "Vector brain"}
STRUCTURE_FOLDERS = ("Inbox", "Projects", "Decisions", "Reference", "Archive")
KE_STRUCTURE_FOLDERS = ("Core", "Projects", "Decisions", "Footguns", "Sessions")
BROWSER_TEXT_EXTENSIONS = {".md", ".markdown", ".txt", ".canvas", ".org", ".rst"}
BROWSER_MAX_FILE_BYTES = 1024 * 1024
BROWSER_MAX_DIRECTORY_ITEMS = 1000
BROWSER_MAX_PAGE_SIZE = 100
_OPENAT_DIRECTORY_SUPPORTED = bool(
    os.open in getattr(os, "supports_dir_fd", set())
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_CLOEXEC")
)
_SCANDIR_DESCRIPTOR_SUPPORTED = os.scandir in getattr(os, "supports_fd", set())
SENSITIVE_DIRECTORY_NAMES = {
    ".aws",
    ".azure",
    ".gnupg",
    ".kube",
    ".password-store",
    ".ssh",
    "auth",
    "authentication",
    "credentials",
    "keychains",
    "keyring",
    "secrets",
    "tokens",
}
SENSITIVE_FILE_NAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "auth.json",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
    "token.json",
    "tokens.json",
}
SENSITIVE_FILE_STEMS = {
    "api-key",
    "api_key",
    "apikey",
    "auth",
    "authentication",
    "credential",
    "credentials",
    "password",
    "passwords",
    "passphrase",
    "private-key",
    "private_key",
    "secret",
    "secrets",
    "token",
    "tokens",
}
SENSITIVE_FILE_EXTENSIONS = {".jks", ".key", ".kdbx", ".keystore", ".p12", ".pem", ".pfx"}


def _iso_time(timestamp: float | None = None) -> str:
    value = time.time() if timestamp is None else float(timestamp)
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _path_key(path: str | Path) -> str:
    expanded = os.path.abspath(os.path.expanduser(str(path)))
    # Keep external-volume discovery lexical. ``realpath`` can synchronously
    # touch every path component and hang on an unavailable volume before our
    # scan deadline can be enforced. Home paths retain canonical symlink
    # resolution so saved connections and discovered paths remain stable.
    if expanded == "/Volumes" or expanded.startswith("/Volumes/"):
        return os.path.normcase(expanded)
    return os.path.normcase(os.path.realpath(expanded))


def _brain_id(path: str | Path) -> str:
    return brain_id_for_path(path)


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9 _.-]+", "", str(value or "")).strip(" .")
    return cleaned[:80] or "My AI Brain"


class BrainService:
    """Discover local brain roots and perform explicitly confirmed safe changes."""

    def __init__(
        self,
        home: str | Path | None = None,
        settings_path: str | Path | None = None,
        scan_roots: list[str | Path] | None = None,
        scan_seconds: float = 4.0,
        max_directories: int = 40000,
    ):
        input_home = Path(home or Path.home()).expanduser().absolute()
        self._input_home = input_home
        self.home = input_home.resolve()

        def rebase_home_path(value: str | Path) -> Path:
            raw = Path(value).expanduser().absolute()
            try:
                return self.home / raw.relative_to(input_home)
            except ValueError:
                return raw

        default_settings = (
            self.home
            / "Library"
            / "Application Support"
            / "KE Studios"
            / "Activity Monitor"
            / "brain-settings.json"
        )
        self.settings_path = rebase_home_path(settings_path) if settings_path else default_settings
        self.scan_roots = [Path(path).expanduser().absolute() for path in scan_roots] if scan_roots else None
        self.scan_seconds = max(0.25, float(scan_seconds))
        self.max_directories = max(100, int(max_directories))
        self._lock = threading.RLock()
        self._cache: dict | None = None
        self._cache_time = 0.0
        self._known: dict[str, dict] = {}
        self._known_ids: dict[str, dict] = {}
        self._browser_root_identities: dict[str, tuple[int, int]] = {}
        self._root_fingerprints: dict[str, dict] = {}
        self._inventory_revision = ""
        self._previews: dict[str, dict] = {}
        self._settings_state = {
            "trusted": True,
            "identity": None,
            "reason": "not-read",
        }
        self.project_brains = ProjectBrainRegistry(home=self.home)

    def sync_project_brains(self, projects: list[dict]) -> dict:
        """Provision selected provider projects and invalidate discovery state."""
        with self._lock:
            payload = self.project_brains.sync(projects)
            self._cache = None
            self._cache_time = 0.0
            return payload

    def project_brain_snapshot(self) -> dict:
        return self.project_brains.snapshot()

    @staticmethod
    def _settings_defaults() -> dict:
        return {
            "schemaVersion": SETTINGS_SCHEMA_VERSION,
            "connections": {},
            "optOuts": {},
            "operationIndex": {},
            "connected": [],
            "ignored": [],
        }

    @staticmethod
    def _lexical_path_key(path: str | Path) -> str:
        return os.path.normcase(os.path.abspath(os.path.expanduser(str(path))))

    def _path_beneath_home(self, path: str | Path) -> bool:
        try:
            Path(self._lexical_path_key(path)).relative_to(Path(self._lexical_path_key(self.home)))
            return True
        except ValueError:
            return False

    def _open_trusted_directory(
        self,
        path: str | Path,
        *,
        private: bool,
        create: bool = False,
    ) -> int:
        """Open a local current-user directory by nofollow descriptor traversal."""
        raw_target = Path(self._lexical_path_key(path))
        try:
            target = self.home / raw_target.relative_to(self._input_home)
        except ValueError:
            target = raw_target
        home = Path(self._lexical_path_key(self.home))
        try:
            relative = target.relative_to(home)
        except ValueError as error:
            raise ValueError("The configured Brain path must stay inside the current user's home") from error
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = -1
        try:
            descriptor = os.open(home.anchor, flags)
            for component in home.parts[1:]:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            home_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(home_metadata.st_mode)
                or home_metadata.st_uid != os.getuid()
                or stat.S_IMODE(home_metadata.st_mode) & 0o022
            ):
                raise ValueError("The current-user home directory is untrusted")
            home_device = int(home_metadata.st_dev)
            for component in relative.parts:
                try:
                    next_descriptor = os.open(component, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                    next_descriptor = os.open(component, flags, dir_fd=descriptor)
                metadata = os.fstat(next_descriptor)
                mode = stat.S_IMODE(metadata.st_mode)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or int(metadata.st_dev) != home_device
                    or mode & 0o022
                ):
                    os.close(next_descriptor)
                    raise ValueError("The configured Brain directory is not current-user-private local storage")
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            raise

    @staticmethod
    def _root_fingerprint_valid(value: object, expected_path: str | None = None) -> bool:
        if not isinstance(value, dict):
            return False
        if value.get("schemaVersion") != ROOT_FINGERPRINT_SCHEMA_VERSION:
            return False
        path = value.get("path")
        if not isinstance(path, str) or (expected_path is not None and path != expected_path):
            return False
        if (
            not isinstance(value.get("device"), int)
            or not isinstance(value.get("inode"), int)
            or not isinstance(value.get("birthTimeNs"), int)
        ):
            return False
        evidence = value.get("evidence")
        if not isinstance(evidence, list) or len(evidence) > 16 or not all(isinstance(item, str) for item in evidence):
            return False
        core = {
            "schemaVersion": ROOT_FINGERPRINT_SCHEMA_VERSION,
            "path": path,
            "device": value["device"],
            "inode": value["inode"],
            "birthTimeNs": value["birthTimeNs"],
            "owner": value.get("owner"),
            "evidence": evidence,
        }
        expected_digest = hashlib.sha256(
            json.dumps(core, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        return value.get("digest") == expected_digest

    def _root_fingerprint(
        self,
        path: str | Path,
        *,
        brain_type: str | None = None,
        private: bool = False,
    ) -> dict:
        key = self._lexical_path_key(path)
        descriptor = self._open_trusted_directory(key, private=private)
        try:
            metadata = os.fstat(descriptor)
            evidence: list[str] = []
            for marker in (".obsidian", "GrokCode", "MEMORY.md", "chroma.sqlite3"):
                try:
                    observed = os.stat(marker, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(observed.st_mode):
                    evidence.append(marker + "/")
                elif stat.S_ISREG(observed.st_mode):
                    evidence.append(marker)
            if brain_type == "KE Brain" and not {".obsidian/", "GrokCode/"}.issubset(evidence):
                raise ValueError("The configured KE Brain fingerprint is incomplete")
            if brain_type == "Codex memory" and "MEMORY.md" not in evidence:
                raise ValueError("The Codex Memory fingerprint is incomplete")
            if brain_type == "Obsidian vault" and ".obsidian/" not in evidence:
                raise ValueError("The Obsidian Brain fingerprint is incomplete")
            if brain_type == "Vector brain" and "chroma.sqlite3" not in evidence:
                raise ValueError("The vector Brain fingerprint is incomplete")
            if brain_type == "Claude memory":
                evidence.append("exact-claude-memory-path")
            core = {
                "schemaVersion": ROOT_FINGERPRINT_SCHEMA_VERSION,
                "path": key,
                "device": int(metadata.st_dev),
                "inode": int(metadata.st_ino),
                "birthTimeNs": int(float(getattr(metadata, "st_birthtime", 0.0)) * 1_000_000_000),
                "owner": int(metadata.st_uid),
                "evidence": sorted(set(evidence)),
            }
            return {
                **core,
                "digest": hashlib.sha256(
                    json.dumps(core, separators=(",", ":"), sort_keys=True).encode("utf-8")
                ).hexdigest(),
            }
        finally:
            os.close(descriptor)

    def _settings_operation_index(self, value: object) -> dict:
        if not isinstance(value, dict) or len(value) > 512:
            return {}
        backup_root = self._lexical_path_key(self.settings_path.parent / "Brain Backups")
        result = {}
        for operation_id, raw_path in value.items():
            if not isinstance(operation_id, str) or not isinstance(raw_path, str):
                continue
            path = self._lexical_path_key(raw_path)
            if path == backup_root or path.startswith(backup_root + os.sep):
                result[operation_id] = path
        return result

    def _normalize_settings(self, value: object) -> dict:
        if not isinstance(value, dict) or value.get("schemaVersion") != SETTINGS_SCHEMA_VERSION:
            raise ValueError("The Brain settings schema is unsupported")
        raw_connections = value.get("connections")
        raw_opt_outs = value.get("optOuts")
        if (
            not isinstance(raw_connections, dict)
            or not isinstance(raw_opt_outs, dict)
            or len(raw_connections) > MAX_SETTINGS_ROOTS
            or len(raw_opt_outs) > MAX_SETTINGS_ROOTS
        ):
            raise ValueError("The Brain settings root registry is invalid")
        connections: dict[str, dict] = {}
        for key, record in raw_connections.items():
            if not isinstance(key, str) or not isinstance(record, dict):
                raise ValueError("The Brain connection registry is invalid")
            if key != self._lexical_path_key(key) or not self._path_beneath_home(key):
                raise ValueError("A Brain connection path is outside trusted local storage")
            fingerprint = record.get("fingerprint")
            if record.get("path") != key or not self._root_fingerprint_valid(fingerprint, key):
                raise ValueError("A Brain connection fingerprint is invalid")
            source = record.get("source")
            if source not in {"explicit", "configured-root", "managed-memory", "created"}:
                raise ValueError("A Brain connection source is invalid")
            connections[key] = {"path": key, "fingerprint": fingerprint, "source": source}
        opt_outs: dict[str, dict] = {}
        for key, record in raw_opt_outs.items():
            if not isinstance(key, str) or not isinstance(record, dict):
                raise ValueError("The Brain opt-out registry is invalid")
            if key != self._lexical_path_key(key) or not self._path_beneath_home(key):
                raise ValueError("A Brain opt-out path is outside trusted local storage")
            state = record.get("state")
            fingerprint = record.get("fingerprint")
            if (
                record.get("path") != key
                or state not in {"disconnected", "ignored", "forgotten"}
                or (fingerprint is not None and not self._root_fingerprint_valid(fingerprint, key))
            ):
                raise ValueError("A Brain opt-out record is invalid")
            opt_outs[key] = {"path": key, "state": state, "fingerprint": fingerprint}
        settings = {
            "schemaVersion": SETTINGS_SCHEMA_VERSION,
            "connections": connections,
            "optOuts": opt_outs,
            "operationIndex": self._settings_operation_index(value.get("operationIndex")),
        }
        settings["connected"] = sorted(connections)
        settings["ignored"] = sorted(key for key, record in opt_outs.items() if record["state"] == "ignored")
        return settings

    def _legacy_settings_without_path_trust(self, value: object) -> dict | None:
        """Migrate only restrictive state; legacy pathname consent is discarded."""
        if (
            not isinstance(value, dict)
            or "schemaVersion" in value
            or not isinstance(value.get("connected", []), list)
            or not isinstance(value.get("ignored", []), list)
        ):
            return None
        settings = self._settings_defaults()
        opt_outs: dict[str, dict] = {}
        for raw_path in value.get("ignored", [])[:MAX_SETTINGS_ROOTS]:
            if not isinstance(raw_path, str):
                continue
            path = self._lexical_path_key(raw_path)
            if path != raw_path or not self._path_beneath_home(path):
                continue
            opt_outs[path] = {"path": path, "state": "ignored", "fingerprint": None}
        settings["optOuts"] = opt_outs
        settings["ignored"] = sorted(opt_outs)
        settings["operationIndex"] = self._settings_operation_index(value.get("operationIndex"))
        return settings

    def _read_settings(self) -> dict:
        defaults = self._settings_defaults()
        parent_fd = -1
        descriptor = -1
        try:
            parent_fd = self._open_trusted_directory(self.settings_path.parent, private=True)
            metadata = os.stat(self.settings_path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size < 2
                or metadata.st_size > MAX_SETTINGS_BYTES
            ):
                raise ValueError("Brain settings are not a private bounded file")
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            descriptor = os.open(self.settings_path.name, flags, dir_fd=parent_fd)
            observed = os.fstat(descriptor)
            if (observed.st_dev, observed.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise ValueError("Brain settings changed while they were opened")
            chunks: list[bytes] = []
            remaining = int(observed.st_size)
            while remaining > 0:
                chunk = os.read(descriptor, min(16_384, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if remaining or os.fstat(descriptor).st_mtime_ns != observed.st_mtime_ns:
                raise ValueError("Brain settings changed while they were read")
            value = json.loads(b"".join(chunks).decode("utf-8"))
            settings = self._legacy_settings_without_path_trust(value)
            reason = "legacy-path-trust-dropped" if settings is not None else "verified"
            if settings is None:
                settings = self._normalize_settings(value)
            self._settings_state = {
                "trusted": True,
                "identity": (int(observed.st_dev), int(observed.st_ino)),
                "reason": reason,
            }
            return settings
        except FileNotFoundError:
            self._settings_state = {"trusted": True, "identity": None, "reason": "absent"}
            return defaults
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as error:
            self._settings_state = {"trusted": False, "identity": None, "reason": type(error).__name__}
            return defaults
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if parent_fd >= 0:
                os.close(parent_fd)

    def _write_json_atomic(self, path: Path, value: dict) -> None:
        payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        parent_fd = self._open_trusted_directory(path.parent, private=True, create=True)
        try:
            try:
                metadata = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                expected_identity = None
            else:
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise ValueError("The local Brain metadata target is untrusted")
                expected_identity = (int(metadata.st_dev), int(metadata.st_ino))
            try:
                ProjectBrainRegistry._write_atomic(
                    parent_fd,
                    path.name,
                    payload,
                    expected_identity=expected_identity,
                )
            except ProjectBrainError as error:
                raise ValueError(str(error)) from error
        finally:
            os.close(parent_fd)

    def _write_settings(self, settings: dict) -> None:
        if not self._settings_state.get("trusted"):
            raise ValueError("Brain settings are untrusted and will not be overwritten")
        normalized = self._normalize_settings({
            "schemaVersion": SETTINGS_SCHEMA_VERSION,
            "connections": settings.get("connections") or {},
            "optOuts": settings.get("optOuts") or {},
            "operationIndex": settings.get("operationIndex") or {},
        })
        disk_value = {
            "schemaVersion": SETTINGS_SCHEMA_VERSION,
            "connections": normalized["connections"],
            "optOuts": normalized["optOuts"],
            "operationIndex": normalized["operationIndex"],
        }
        payload = (json.dumps(disk_value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        parent_fd = -1
        try:
            parent_fd = self._open_trusted_directory(self.settings_path.parent, private=True, create=True)
            ProjectBrainRegistry._write_atomic(
                parent_fd,
                self.settings_path.name,
                payload,
                expected_identity=self._settings_state.get("identity"),
            )
            observed = os.stat(self.settings_path.name, dir_fd=parent_fd, follow_symlinks=False)
            self._settings_state = {
                "trusted": True,
                "identity": (int(observed.st_dev), int(observed.st_ino)),
                "reason": "verified",
            }
        except ProjectBrainError as error:
            raise ValueError(str(error)) from error
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)

    def _default_scan_roots(self) -> list[Path]:
        # Never synchronously traverse /Volumes. A mounted but unavailable disk
        # can block in os.scandir indefinitely, beyond any Python deadline. The
        # bounded Spotlight query below covers indexed current-user storage and
        # only promotes external paths carrying an exact brain marker.
        return [self.home]

    def _explicit_paths(self) -> list[Path]:
        home = self.home
        paths = [
            home / ".grokcode" / "brain",
            home / ".codex" / "memories",
            home / ".claude" / "memory",
            home / ".claude" / "projects",
            home / "Documents" / "BANKBRAIN" / "brain",
            home / "Library" / "Application Support" / "Claude",
            home
            / "Library"
            / "Containers"
            / "dev.kestudios.desktop"
            / "Data"
            / "Library"
            / "Application Support"
            / "KE Desktop",
        ]
        verified: list[Path] = []
        for path in paths:
            descriptor = -1
            try:
                descriptor = self._open_trusted_directory(path, private=False)
                verified.append(Path(self._lexical_path_key(path)))
            except (OSError, ValueError):
                continue
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        return verified

    def _spotlight_paths(self, timeout: float) -> list[dict]:
        if sys.platform != "darwin" or not os.path.isfile("/usr/bin/mdfind"):
            return []
        query = (
            '(kMDItemFSName == ".obsidian"cd || kMDItemFSName == "MEMORY.md"cd || '
            'kMDItemFSName == "chroma.sqlite3"cd || kMDItemFSName == "brain"cd || '
            'kMDItemFSName == "brains"cd || kMDItemFSName == "vault"cd || '
            'kMDItemFSName == "memory"cd || kMDItemFSName == "memories"cd)'
        )
        try:
            result = subprocess.run(
                ["/usr/bin/mdfind", query],
                capture_output=True,
                text=True,
                timeout=max(0.25, timeout),
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return []
        paths: list[dict] = []
        for line in (result.stdout or "").splitlines()[:5000]:
            marker_path = Path(line.strip())
            name = marker_path.name
            lowered = name.lower()
            if lowered == ".obsidian":
                path = marker_path.parent
                marker = ".obsidian"
            elif lowered == "chroma.sqlite3":
                path = marker_path.parent
                marker = "chroma.sqlite3"
            elif name == "MEMORY.md":
                path = marker_path.parent
                marker = "MEMORY.md"
            else:
                path = marker_path
                marker = "name-only"
            paths.append({"path": path, "marker": marker})
        return paths

    def _is_home_path(self, path: Path) -> bool:
        try:
            Path(_path_key(path)).relative_to(Path(_path_key(self.home)))
            return True
        except ValueError:
            return False

    def _indexed_candidate(self, hit: dict) -> dict | None:
        """Build a credible external candidate without touching its volume."""
        path = Path(hit["path"])
        marker = str(hit.get("marker") or "")
        key = _path_key(path)
        lowered = key.lower()
        if marker == ".obsidian":
            brain_type = "Obsidian vault"
            evidence = [".obsidian (Spotlight index)"]
            managed = False
        elif marker == "chroma.sqlite3":
            brain_type = "Vector brain"
            evidence = ["chroma.sqlite3 (Spotlight index)"]
            managed = True
        elif marker == "MEMORY.md" and path.name.lower() == "memories" and "/.codex/" in lowered:
            brain_type = "Codex memory"
            evidence = ["MEMORY.md", ".codex/memories", "Spotlight index"]
            managed = True
        else:
            # A directory being named brain/memory/vault is not evidence by
            # itself, especially on external disks where probing may block.
            return None
        return {
            "id": _brain_id(path),
            "path": key,
            "type": brain_type,
            "evidence": evidence,
            "managed": managed,
            "configured": False,
            "indexedOnly": True,
            "accessState": "indexed",
        }

    def _skip_child(self, parent: Path, child: Path, depth: int) -> bool:
        name = child.name
        if name in SKIP_DIRECTORY_NAMES:
            return True
        if parent == self.home and name in ROOT_HEAVY_DIRECTORIES:
            return True
        if parent == self.home and name == "Library":
            return True
        if name.startswith("."):
            return True
        lowered = str(child).lower()
        return any(
            token in lowered
            for token in (
                "/node_modules/",
                "/library/developer/",
                "/contents/resources/",
                "/.git/",
            )
        )

    def _directory_names(self, path: Path) -> tuple[set[str], list[Path], int]:
        names: set[str] = set()
        children: list[Path] = []
        direct_note_count = 0
        descriptor = self._open_trusted_directory(path, private=False)
        try:
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    names.add(entry.name)
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            children.append(Path(path) / entry.name)
                        elif Path(entry.name).suffix.lower() in NOTE_EXTENSIONS:
                            direct_note_count += 1
                    except OSError:
                        continue
        finally:
            os.close(descriptor)
        return names, children, direct_note_count

    def _classify(self, path: Path, names: set[str], direct_notes: int) -> dict | None:
        raw = str(path)
        lowered = raw.lower()
        base = path.name.lower()
        if any(
            token in lowered
            for token in (
                "/node_modules/",
                "/library/developer/",
                "/sdk",
                "/contents/resources/",
                "/.git/",
                "/build/",
                "/dist/",
            )
        ):
            return None

        brain_type = None
        evidence: list[str] = []
        managed = False
        configured = False

        if ".obsidian" in names and "GrokCode" in names:
            brain_type = "KE Brain"
            evidence = [".obsidian", "GrokCode/"]
            configured = _path_key(path) == _path_key(self.home / ".grokcode" / "brain")
        elif ".obsidian" in names:
            brain_type = "Obsidian vault"
            evidence = [".obsidian"]
        elif base == "memories" and "MEMORY.md" in names and "/.codex/" in lowered:
            brain_type = "Codex memory"
            evidence = ["MEMORY.md", ".codex/memories"]
            managed = True
        elif base == "memory" and (
            "/.claude/" in lowered or "/application support/claude/" in lowered
        ):
            brain_type = "Claude memory"
            evidence = ["Claude memory root"]
            managed = True
        elif base == "brain" and "dev.kestudios.desktop" in lowered:
            brain_type = "KE Desktop brain"
            evidence = ["KE Desktop application container"]
            managed = True
        elif base == "brain" and "bankbrain" in lowered:
            brain_type = "BANKBRAIN"
            evidence = ["BANKBRAIN/brain"]
        elif "chroma.sqlite3" in names:
            brain_type = "Vector brain"
            evidence = ["chroma.sqlite3"]
            managed = True
        elif base in {"brain", "brains", "vault", "vaults", "knowledge"} and direct_notes:
            brain_type = "Markdown brain"
            evidence = [f"{direct_notes} top-level note file" + ("s" if direct_notes != 1 else "")]

        if not brain_type:
            return None
        return {
            "id": _brain_id(path),
            "path": _path_key(path),
            "type": brain_type,
            "evidence": evidence,
            "managed": managed,
            "configured": configured,
        }

    def _label(self, candidate: dict) -> str:
        path = Path(candidate["path"])
        brain_type = candidate["type"]
        if brain_type == "KE Brain":
            return "KE Studios Brain" if candidate.get("configured") else "KE Brain"
        if brain_type == "Codex memory":
            return "Codex Memory"
        if brain_type == "Claude memory":
            parent = path.parent.name
            return "Claude Memory" if parent in {"agent", "projects", "Claude"} else f"{parent} · Claude Memory"
        if brain_type == "KE Desktop brain":
            return "KE Desktop Brain" if path.parent.name != "agents" else "KE Desktop Agent Brain"
        if brain_type == "BANKBRAIN":
            return "BANKBRAIN"
        if path.name.lower() in GENERIC_BRAIN_NAMES and path.parent.name:
            return path.parent.name
        return path.name or brain_type

    def _measure(
        self,
        path: Path,
        deadline: float,
        expected_identity: tuple[int, int] | None = None,
    ) -> dict:
        notes = 0
        items = 0
        latest = 0.0
        truncated = False
        root_descriptor = self._open_trusted_directory(path, private=False)
        root_metadata = os.fstat(root_descriptor)
        if expected_identity is not None and (
            int(root_metadata.st_dev),
            int(root_metadata.st_ino),
        ) != expected_identity:
            os.close(root_descriptor)
            raise ValueError("The Brain root changed before metadata measurement")
        queue: deque[int] = deque([root_descriptor])
        inspected = 0
        latest = float(root_metadata.st_mtime)
        try:
            while queue:
                if time.monotonic() >= deadline or inspected >= 80000:
                    truncated = True
                    break
                current = queue.popleft()
                inspected += 1
                try:
                    with os.scandir(current) as entries:
                        for entry in entries:
                            try:
                                metadata = entry.stat(follow_symlinks=False)
                                if stat.S_ISDIR(metadata.st_mode):
                                    if entry.name not in SKIP_DIRECTORY_NAMES and not entry.name.startswith("."):
                                        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                                        child_descriptor = os.open(entry.name, flags, dir_fd=current)
                                        child_metadata = os.fstat(child_descriptor)
                                        if (
                                            child_metadata.st_uid != os.getuid()
                                            or child_metadata.st_dev != root_metadata.st_dev
                                            or stat.S_IMODE(child_metadata.st_mode) & 0o022
                                        ):
                                            os.close(child_descriptor)
                                        else:
                                            queue.append(child_descriptor)
                                    continue
                                if not stat.S_ISREG(metadata.st_mode):
                                    continue
                                items += 1
                                if Path(entry.name).suffix.lower() in NOTE_EXTENSIONS:
                                    notes += 1
                                latest = max(latest, float(metadata.st_mtime))
                            except OSError:
                                continue
                except OSError:
                    continue
                finally:
                    os.close(current)
        finally:
            while queue:
                os.close(queue.popleft())
        return {
            "noteCount": notes if not truncated else None,
            "itemCount": items if not truncated else None,
            "countState": "complete" if not truncated else "bounded",
            "lastActivity": _iso_time(latest) if latest else None,
        }

    def _scan_directories(self, roots: list[Path], deadline: float) -> tuple[dict[str, dict], dict]:
        candidates: dict[str, dict] = {}
        permissions: list[str] = []
        inspected = 0
        truncated = False
        queue: deque[tuple[Path, int]] = deque()
        seen: set[str] = set()
        for root in roots:
            descriptor = -1
            try:
                descriptor = self._open_trusted_directory(root, private=False)
                queue.append((root, 0))
            except (OSError, ValueError):
                continue
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

        while queue:
            if time.monotonic() >= deadline or inspected >= self.max_directories:
                truncated = True
                break
            path, depth = queue.popleft()
            key = _path_key(path)
            if key in seen:
                continue
            seen.add(key)
            inspected += 1
            try:
                names, children, direct_notes = self._directory_names(path)
            except PermissionError:
                if len(permissions) < 20:
                    permissions.append(key)
                if path.name.lower() in GENERIC_BRAIN_NAMES:
                    candidates[key] = {
                        "id": _brain_id(path),
                        "path": key,
                        "type": "Potential brain",
                        "evidence": ["brain-like directory name"],
                        "managed": True,
                        "configured": False,
                        "permissionDenied": True,
                    }
                continue
            except (OSError, ValueError):
                continue

            candidate = self._classify(path, names, direct_notes)
            if candidate:
                candidates[key] = candidate

            if depth >= 10:
                continue
            for child in children:
                if not self._skip_child(path, child, depth):
                    queue.append((child, depth + 1))
        return candidates, {
            "directoriesInspected": inspected,
            "truncated": truncated,
            "permissionDeniedCount": len(permissions),
            "permissionDeniedPaths": permissions,
        }

    def _auto_connection_source(self, candidate: dict, key: str) -> str | None:
        exact = self._lexical_path_key(key)
        if (
            candidate.get("type") == "KE Brain"
            and exact == self._lexical_path_key(self.home / ".grokcode" / "brain")
        ):
            return "configured-root"
        if (
            candidate.get("type") == "Codex memory"
            and exact == self._lexical_path_key(self.home / ".codex" / "memories")
        ):
            return "managed-memory"
        if candidate.get("type") != "Claude memory":
            return None
        allowed = {
            self._lexical_path_key(self.home / ".claude" / "memory"),
            self._lexical_path_key(
                self.home / "Library" / "Application Support" / "Claude" / "memory"
            ),
        }
        if exact in allowed:
            return "managed-memory"
        try:
            relative = Path(exact).relative_to(
                Path(self._lexical_path_key(self.home / ".claude" / "projects"))
            )
        except ValueError:
            return None
        if len(relative.parts) == 2 and relative.parts[-1] == "memory":
            return "managed-memory"
        return None

    @staticmethod
    def _connection_matches(record: object, fingerprint: dict | None) -> bool:
        return bool(
            isinstance(record, dict)
            and fingerprint is not None
            and record.get("path") == fingerprint.get("path")
            and record.get("fingerprint") == fingerprint
        )

    def scan(self, force: bool = False) -> dict:
        with self._lock:
            now = time.monotonic()
            if not force and self._cache and now - self._cache_time < 30.0:
                return json.loads(json.dumps(self._cache))

            started = time.monotonic()
            deadline = started + self.scan_seconds
            configured_roots = self.scan_roots or self._default_scan_roots()
            roots: list[Path] = []
            for configured_root in configured_roots:
                descriptor = -1
                try:
                    descriptor = self._open_trusted_directory(configured_root, private=True)
                    roots.append(Path(self._lexical_path_key(configured_root)))
                except (OSError, ValueError):
                    continue
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
            seeds = list(roots) + self._explicit_paths()
            spotlight_budget = min(1.5, max(0.25, deadline - time.monotonic()))
            spotlight = self._spotlight_paths(spotlight_budget)
            # Home candidates can be fingerprinted by the bounded directory
            # walk. External candidates stay metadata-only so an unavailable
            # mount cannot block the bridge thread.
            for hit in spotlight:
                path = Path(hit["path"])
                if not self._is_home_path(path):
                    continue
                descriptor = -1
                try:
                    descriptor = self._open_trusted_directory(path, private=False)
                    seeds.append(Path(self._lexical_path_key(path)))
                except (OSError, ValueError):
                    continue
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
            candidates, scan_state = self._scan_directories(seeds, deadline)

            project_hierarchy = self.project_brains.snapshot()
            if project_hierarchy.get("ok"):
                for child in project_hierarchy.get("children", []):
                    if not child.get("accessible"):
                        continue
                    key = _path_key(child["path"])
                    candidate = candidates.get(key) or {
                        "id": child["brainId"],
                        "path": key,
                        "type": "Project Brain",
                        "evidence": ["Activity Monitor project registry", ".obsidian"],
                        "managed": True,
                        "configured": True,
                    }
                    candidate.update({
                        "id": child["brainId"],
                        "path": key,
                        "type": "Project Brain",
                        "managed": True,
                        "configured": True,
                        "managedProjectChild": True,
                        "parentBrainId": child["parentBrainId"],
                        "projectId": child["projectId"],
                        "provider": child["provider"],
                        "projectBrainLifecycle": child["lifecycleState"],
                        "projectBrainLabel": child["label"],
                        "projectBrainAccessible": True,
                        "pathDisplay": child["pathDisplay"],
                    })
                    candidates[key] = candidate

            # Spotlight can identify a home candidate whose parent tree was
            # skipped, or a credible external brain marker. Only the former is
            # opened. External markers are surfaced from index metadata alone.
            indexed_external = 0
            rejected_name_only = 0
            for hit in spotlight:
                if time.monotonic() >= deadline:
                    scan_state["truncated"] = True
                    break
                path = Path(hit["path"])
                key = _path_key(path)
                if key in candidates:
                    continue
                if not self._is_home_path(path):
                    candidate = self._indexed_candidate(hit)
                    if candidate:
                        candidates[key] = candidate
                        indexed_external += 1
                    elif hit.get("marker") == "name-only":
                        rejected_name_only += 1
                    continue
                try:
                    names, _, direct_notes = self._directory_names(path)
                    candidate = self._classify(path, names, direct_notes)
                    if candidate:
                        candidates[key] = candidate
                except PermissionError:
                    if path.name.lower() in GENERIC_BRAIN_NAMES:
                        candidates[key] = {
                            "id": _brain_id(path),
                            "path": key,
                            "type": "Potential brain",
                            "evidence": ["brain-like directory name"],
                            "managed": True,
                            "configured": False,
                            "permissionDenied": True,
                        }
                except (OSError, ValueError):
                    continue

            settings = self._read_settings()
            connections = dict(settings.get("connections") or {})
            opt_outs = dict(settings.get("optOuts") or {})
            fingerprints: dict[str, dict] = {}
            auto_sources: dict[str, str] = {}
            for key, candidate in candidates.items():
                if candidate.get("indexedOnly") or candidate.get("permissionDenied"):
                    continue
                source = self._auto_connection_source(candidate, key)
                if source:
                    auto_sources[key] = source
                try:
                    fingerprints[key] = self._root_fingerprint(
                        key,
                        brain_type=candidate.get("type"),
                        private=bool(candidate.get("managedProjectChild")),
                    )
                except (OSError, ValueError):
                    candidate["permissionDenied"] = True
                    candidate["rootTrustState"] = "untrusted"

            settings_mutated = False
            if self._settings_state.get("trusted"):
                for key, source in auto_sources.items():
                    fingerprint = fingerprints.get(key)
                    if (
                        fingerprint is None
                        or key in opt_outs
                        or key in connections
                    ):
                        continue
                    connections[key] = {
                        "path": key,
                        "fingerprint": fingerprint,
                        "source": source,
                    }
                    settings_mutated = True
                if settings_mutated:
                    settings["connections"] = connections
                    settings["optOuts"] = opt_outs
                    try:
                        self._write_settings(settings)
                    except ValueError:
                        settings_mutated = False
                        settings = self._settings_defaults()
                        connections = {}
                        opt_outs = {}
                        self._settings_state = {
                            "trusted": False,
                            "identity": None,
                            "reason": "atomic-write-failed",
                        }

            brains = []
            for key, candidate in candidates.items():
                managed_project_child = bool(candidate.get("managedProjectChild"))
                fingerprint = fingerprints.get(key)
                permission_denied = bool(candidate.get("permissionDenied")) or (
                    managed_project_child and not candidate.get("projectBrainAccessible", False)
                )
                opt_out = opt_outs.get(key) if self._settings_state.get("trusted") else None
                connection = connections.get(key) if self._settings_state.get("trusted") else None
                identity_changed = bool(connection and not self._connection_matches(connection, fingerprint))
                if permission_denied:
                    status = "permission-denied"
                elif opt_out:
                    status = "ignored" if opt_out.get("state") == "ignored" else "discovered"
                elif managed_project_child:
                    status = "connected"
                elif self._connection_matches(connection, fingerprint):
                    status = "connected"
                else:
                    status = "discovered"
                measurement = {
                    "noteCount": None,
                    "itemCount": None,
                    "countState": "unavailable",
                    "lastActivity": None,
                }
                should_measure = not (
                    opt_out and opt_out.get("state") in {"ignored", "forgotten"}
                )
                if (
                    not permission_denied
                    and not candidate.get("indexedOnly")
                    and fingerprint is not None
                    and should_measure
                    and time.monotonic() < deadline
                ):
                    try:
                        measurement = self._measure(
                            Path(key),
                            min(deadline, time.monotonic() + 0.7),
                            (int(fingerprint["device"]), int(fingerprint["inode"])),
                        )
                    except (OSError, ValueError):
                        permission_denied = True
                        status = "permission-denied"
                brain = {
                    **candidate,
                    **measurement,
                    "permissionDenied": permission_denied,
                    "label": candidate.get("projectBrainLabel") or self._label(candidate),
                    "status": status,
                    "identityChanged": identity_changed,
                    "connectionSource": connection.get("source") if isinstance(connection, dict) else None,
                    "optOutState": opt_out.get("state") if isinstance(opt_out, dict) else None,
                    "canConnect": (
                        not permission_denied
                        and not managed_project_child
                        and not candidate.get("indexedOnly")
                    ),
                    "canBrowse": status == "connected" and not permission_denied and not candidate.get("indexedOnly"),
                    "canStructure": (
                        not managed_project_child
                        and not permission_denied
                        and not candidate.get("indexedOnly")
                        and candidate["type"] not in MANAGED_TYPES
                    ),
                    "pathDisplay": candidate.get("pathDisplay")
                    or ("~" + key[len(str(self.home)) :] if key.startswith(str(self.home)) else key),
                }
                brains.append(brain)

            known_keys = set(candidates)
            for key in sorted(set(connections) - known_keys):
                brains.append({
                    "id": _brain_id(key),
                    "path": key,
                    "pathDisplay": "~" + key[len(str(self.home)) :] if key.startswith(str(self.home)) else key,
                    "label": Path(key).name or "Connected Brain",
                    "type": "Connected brain",
                    "evidence": ["saved connection"],
                    "managed": False,
                    "configured": False,
                    "status": "offline",
                    "noteCount": None,
                    "itemCount": None,
                    "countState": "unavailable",
                    "lastActivity": None,
                    "canConnect": True,
                    "canBrowse": False,
                    "canStructure": False,
                    "identityChanged": False,
                    "connectionSource": connections[key].get("source"),
                    "optOutState": None,
                })

            status_order = {"connected": 0, "discovered": 1, "ignored": 2, "offline": 3, "permission-denied": 4}
            brains.sort(key=lambda item: (status_order.get(item["status"], 9), item["label"].lower(), item["path"].lower()))
            elapsed_ms = int((time.monotonic() - started) * 1000)
            summary = {
                "found": len(brains),
                "connected": sum(item["status"] == "connected" for item in brains),
                "discovered": sum(item["status"] == "discovered" for item in brains),
                "ignored": sum(item["status"] == "ignored" for item in brains),
                "offline": sum(item["status"] == "offline" for item in brains),
                "permissionDenied": sum(item["status"] == "permission-denied" for item in brains),
                "projectChildren": int((project_hierarchy.get("counts") or {}).get("total") or 0),
                "activeProjectChildren": int((project_hierarchy.get("counts") or {}).get("active") or 0),
                "dormantProjectChildren": int((project_hierarchy.get("counts") or {}).get("dormant") or 0),
            }
            browser_root_identities: dict[str, tuple[int, int]] = {}
            for item in brains:
                if not item.get("canBrowse"):
                    continue
                fingerprint = fingerprints.get(item["path"])
                if fingerprint is None:
                    continue
                browser_root_identities[item["id"]] = (
                    int(fingerprint["device"]),
                    int(fingerprint["inode"]),
                )

            revision_rows = [
                {
                    "id": item["id"],
                    "path": item["path"],
                    "status": item["status"],
                    "indexedOnly": bool(item.get("indexedOnly")),
                    "permissionDenied": bool(item.get("permissionDenied")),
                    "parentBrainId": item.get("parentBrainId"),
                    "projectId": item.get("projectId"),
                    "projectBrainLifecycle": item.get("projectBrainLifecycle"),
                    "identityChanged": bool(item.get("identityChanged")),
                    "rootFingerprintDigest": fingerprints.get(item["path"], {}).get("digest"),
                    "rootIdentity": list(browser_root_identities[item["id"]])
                    if item["id"] in browser_root_identities
                    else None,
                }
                for item in brains
            ]
            inventory_revision = "inventory_" + hashlib.sha256(
                json.dumps(revision_rows, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).hexdigest()[:20]
            payload = {
                "ok": True,
                "schemaVersion": SCHEMA_VERSION,
                "inventoryRevision": inventory_revision,
                "generatedAt": _iso_time(),
                "brains": brains,
                "summary": summary,
                "projectHierarchy": project_hierarchy,
                "scan": {
                    **scan_state,
                    "durationMs": elapsed_ms,
                    "scope": "current-user accessible local storage",
                    "roots": [str(path) for path in roots],
                    "spotlightCandidates": len(spotlight),
                    "coverage": "home filesystem metadata plus bounded all-storage Spotlight metadata",
                    "externalIndexedBrains": indexed_external,
                    "externalNameOnlyRejected": rejected_name_only,
                    "externalDirectoriesOpened": 0,
                    "contentRead": False,
                    "settingsTrusted": bool(self._settings_state.get("trusted")),
                },
                "privacy": {
                    "mode": "metadata-only",
                    "noteBodiesRead": False,
                    "uploads": False,
                    "credentialsUsed": False,
                    "mutationDuringDiscovery": settings_mutated,
                    "rootFingerprintsPersisted": True,
                    "settingsDescriptorVerified": bool(self._settings_state.get("trusted")),
                },
            }
            self._known = {item["path"]: item for item in brains}
            self._known_ids = {item["id"]: item for item in brains}
            self._browser_root_identities = browser_root_identities
            self._root_fingerprints = fingerprints
            self._inventory_revision = inventory_revision
            self._cache = payload
            self._cache_time = time.monotonic()
            return json.loads(json.dumps(payload))

    def _require_known(self, path: str, *, structure: bool = False) -> dict:
        key = _path_key(path)
        if key not in self._known:
            self.scan(force=True)
        brain = self._known.get(key)
        if not brain:
            raise ValueError("That brain is not in the current discovery inventory")
        if structure and not brain.get("canStructure"):
            raise ValueError("This application-managed brain cannot be restructured here")
        return brain

    @staticmethod
    def _browser_parts(relative_path: str | None) -> tuple[str, ...]:
        raw = str(relative_path or "")
        if "\x00" in raw or "\\" in raw:
            raise ValueError("That Brain path is invalid")
        if raw in {"", "."}:
            return ()
        pure = PurePosixPath(raw)
        if (
            pure.is_absolute()
            or (pure.parts and re.fullmatch(r"[A-Za-z]:", pure.parts[0]))
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise ValueError("Brain browsing only accepts a root-relative path")
        return tuple(pure.parts)

    @staticmethod
    def _is_sensitive_path(parts: tuple[str, ...], *, file_name: str | None = None) -> bool:
        if any(part.casefold() in SENSITIVE_DIRECTORY_NAMES for part in parts[:-1] if part):
            return True
        name = str(file_name if file_name is not None else (parts[-1] if parts else ""))
        lowered = name.casefold()
        suffix = Path(lowered).suffix
        stem = Path(lowered).stem
        tokenized_sensitive = bool(re.search(
            r"(?:^|[._ -])(api[-_ ]?key|auth(?:entication)?|credential(?:s)?|password(?:s)?|passphrase|private[-_ ]?key|secret(?:s)?|token(?:s)?)(?:$|[._ -])",
            stem,
        ))
        return (
            lowered in SENSITIVE_DIRECTORY_NAMES
            or lowered in SENSITIVE_FILE_NAMES
            or lowered.startswith(".env.")
            or stem in SENSITIVE_FILE_STEMS
            or tokenized_sensitive
            or suffix in SENSITIVE_FILE_EXTENSIONS
        )

    def _require_browsable(
        self,
        brain_id: str,
        inventory_revision: str,
    ) -> tuple[dict, Path, tuple[int, int]]:
        if not self._cache or time.monotonic() - self._cache_time >= 30.0:
            self.scan(force=True)
        if not inventory_revision or str(inventory_revision) != self._inventory_revision:
            raise ValueError("The Brain inventory changed. Refresh before browsing")
        brain = self._known_ids.get(str(brain_id))
        if not brain:
            raise ValueError("That Brain ID is not in the current inventory")
        if brain.get("indexedOnly"):
            raise ValueError("This Brain is Spotlight-indexed only and cannot be opened")
        status = str(brain.get("status") or "offline")
        if status == "discovered":
            raise ValueError("Connect this Brain before opening it")
        if status == "ignored":
            raise ValueError("Restore and connect this ignored Brain before opening it")
        if status == "permission-denied" or brain.get("permissionDenied"):
            raise ValueError("This Brain cannot be opened because filesystem permission was denied")
        if status != "connected":
            raise ValueError("This Brain is offline and cannot be opened")

        key = str(brain["path"])
        registered_child = False
        if brain.get("managedProjectChild"):
            hierarchy = self.project_brains.snapshot()
            registered_child = any(
                child.get("accessible")
                and child.get("brainId") == str(brain_id)
                and _path_key(child.get("path") or "") == key
                for child in hierarchy.get("children", [])
            )
        try:
            fingerprint = self._root_fingerprint(
                key,
                brain_type="Project Brain" if registered_child else brain.get("type"),
                private=registered_child,
            )
        except PermissionError as error:
            raise ValueError("This Brain cannot be opened because filesystem permission was denied") from error
        except (OSError, ValueError) as error:
            raise ValueError("The Brain root cannot be securely verified") from error
        if not registered_child:
            settings = self._read_settings()
            if not self._settings_state.get("trusted"):
                raise ValueError("Brain settings are untrusted. Repair them before browsing")
            opt_out = (settings.get("optOuts") or {}).get(key)
            if opt_out:
                if opt_out.get("state") == "ignored":
                    raise ValueError("This Brain is ignored and cannot be opened")
                raise ValueError("This Brain is opted out and cannot be opened")
            connection = (settings.get("connections") or {}).get(key)
            if not self._connection_matches(connection, fingerprint):
                raise ValueError("The Brain root identity changed. Reconnect it explicitly")
        try:
            root = Path(self._lexical_path_key(key))
        except (OSError, ValueError) as error:
            raise ValueError("This Brain is offline and cannot be opened") from error
        if self._lexical_path_key(root) != key or (
            not brain.get("managedProjectChild") and _brain_id(key) != str(brain_id)
        ):
            raise ValueError("The Brain root changed. Refresh before browsing")
        root_identity = self._browser_root_identities.get(str(brain_id))
        observed_identity = (int(fingerprint["device"]), int(fingerprint["inode"]))
        if root_identity is None or root_identity != observed_identity:
            raise ValueError("The Brain root cannot be verified. Refresh before browsing")
        return brain, root, root_identity

    def _resolve_browser_target(
        self,
        root: Path,
        relative_path: str | None,
        *,
        expected: str,
    ) -> tuple[Path, tuple[str, ...]]:
        parts = self._browser_parts(relative_path)
        if parts and self._is_sensitive_path(parts):
            raise ValueError("Credential-like and authentication paths cannot be opened")
        target = root
        for part in parts:
            candidate = target / part
            try:
                metadata = candidate.lstat()
            except PermissionError as error:
                raise ValueError("The selected Brain item is not readable") from error
            except OSError as error:
                raise ValueError("The selected Brain item is unavailable") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError("Symbolic links cannot be opened in the Brain viewer")
            target = candidate
        try:
            resolved = target.resolve(strict=True)
            resolved.relative_to(root)
        except ValueError as error:
            raise ValueError("The selected path escapes the connected Brain root") from error
        except PermissionError as error:
            raise ValueError("The selected Brain item is not readable") from error
        except OSError as error:
            raise ValueError("The selected Brain item is unavailable") from error
        if expected == "directory" and not resolved.is_dir():
            raise ValueError("The selected Brain item is not a folder")
        if expected == "file" and not resolved.is_file():
            raise ValueError("The selected Brain item is not a regular file")
        return resolved, parts

    @staticmethod
    def _secure_directory_descriptors_available(*, require_scandir: bool) -> bool:
        return _OPENAT_DIRECTORY_SUPPORTED and (
            not require_scandir or _SCANDIR_DESCRIPTOR_SUPPORTED
        )

    def _open_browser_directory(
        self,
        root: Path,
        parts: tuple[str, ...],
        expected_root_identity: tuple[int, int],
        *,
        require_scandir: bool,
    ) -> int:
        """Open an exact in-root directory without reopening a validated path.

        Each absolute-root and relative component is opened from the previously
        verified directory descriptor with ``O_NOFOLLOW``. The returned
        descriptor therefore remains bound to the checked inode even if a path
        is renamed or replaced while the request is in flight.
        """

        if not self._secure_directory_descriptors_available(require_scandir=require_scandir):
            raise ValueError("Secure Brain browsing is unavailable on this platform")
        if not root.is_absolute() or not root.anchor:
            raise ValueError("The Brain root cannot be securely opened")

        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = None
        try:
            descriptor = os.open(root.anchor, flags)
            for component in root.parts[1:]:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            observed_root = os.fstat(descriptor)
            if (int(observed_root.st_dev), int(observed_root.st_ino)) != expected_root_identity:
                raise ValueError("The Brain root changed. Refresh before browsing")
            for component in parts:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except ValueError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except PermissionError as error:
            if descriptor is not None:
                os.close(descriptor)
            raise ValueError("This Brain folder cannot be opened because permission was denied") from error
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            raise ValueError("This Brain folder changed or cannot be securely opened") from error

    @staticmethod
    def _breadcrumbs(brain: dict, parts: tuple[str, ...]) -> list[dict]:
        crumbs = [{"label": brain.get("label") or "Brain", "relativePath": ""}]
        for index, part in enumerate(parts):
            crumbs.append({"label": part, "relativePath": "/".join(parts[: index + 1])})
        return crumbs

    @classmethod
    def _entry_restriction(cls, parts: tuple[str, ...], kind: str) -> str | None:
        if kind == "symlink":
            return "Symbolic links are not opened"
        if cls._is_sensitive_path(parts):
            return "Credential-like or authentication item"
        if kind == "file" and Path(parts[-1]).suffix.casefold() not in BROWSER_TEXT_EXTENSIONS:
            return "Unsupported file type"
        if kind not in {"folder", "file"}:
            return "Filesystem metadata is unavailable"
        return None

    def list_directory(
        self,
        brain_id: str,
        inventory_revision: str,
        relative_path: str = "",
        page: int = 0,
        page_size: int = 60,
    ) -> dict:
        with self._lock:
            brain, root, root_identity = self._require_browsable(
                str(brain_id),
                str(inventory_revision),
            )
            _target, parts = self._resolve_browser_target(root, relative_path, expected="directory")
            try:
                requested_page = max(0, int(page))
                requested_size = min(BROWSER_MAX_PAGE_SIZE, max(1, int(page_size)))
            except (TypeError, ValueError) as error:
                raise ValueError("The requested Brain page is invalid") from error

            records: list[dict] = []
            truncated = False
            directory_descriptor = None
            try:
                directory_descriptor = self._open_browser_directory(
                    root,
                    parts,
                    root_identity,
                    require_scandir=True,
                )
                with os.scandir(directory_descriptor) as entries:
                    for index, entry in enumerate(entries):
                        if index >= BROWSER_MAX_DIRECTORY_ITEMS:
                            truncated = True
                            break
                        relative_parts = parts + (entry.name,)
                        kind = "symlink" if entry.is_symlink() else "unavailable"
                        size = None
                        modified = None
                        try:
                            metadata = entry.stat(follow_symlinks=False)
                            if not entry.is_symlink():
                                kind = "folder" if stat.S_ISDIR(metadata.st_mode) else "file" if stat.S_ISREG(metadata.st_mode) else "unavailable"
                            size = int(metadata.st_size) if kind == "file" else None
                            modified = _iso_time(metadata.st_mtime)
                        except OSError:
                            pass
                        restriction = self._entry_restriction(relative_parts, kind)
                        records.append({
                            "name": entry.name,
                            "relativePath": "/".join(relative_parts),
                            "kind": kind,
                            "sizeBytes": size,
                            "modifiedAt": modified,
                            "openable": restriction is None,
                            "restriction": restriction,
                        })
            except PermissionError as error:
                raise ValueError("This Brain folder cannot be listed because permission was denied") from error
            except OSError as error:
                raise ValueError("This Brain folder is unavailable") from error
            finally:
                if directory_descriptor is not None:
                    os.close(directory_descriptor)

            records.sort(
                key=lambda item: (
                    0 if item["kind"] == "folder" else 1 if item["kind"] == "file" else 2,
                    item["name"].casefold(),
                    item["name"],
                )
            )
            offset = requested_page * requested_size
            if requested_page and offset >= len(records):
                raise ValueError("That Brain directory page is no longer available")
            visible = records[offset : offset + requested_size]
            relative_value = "/".join(parts)
            parent_value = "/".join(parts[:-1]) if parts else None
            return {
                "ok": True,
                "schemaVersion": SCHEMA_VERSION,
                "view": "directory",
                "brainId": brain["id"],
                "inventoryRevision": self._inventory_revision,
                "brainLabel": brain.get("label") or "Brain",
                "relativePath": relative_value,
                "parentPath": parent_value,
                "breadcrumbs": self._breadcrumbs(brain, parts),
                "items": visible,
                "page": requested_page,
                "pageSize": requested_size,
                "hasPrevious": requested_page > 0,
                "hasMore": offset + requested_size < len(records),
                "itemCount": None if truncated else len(records),
                "boundedItemCount": len(records),
                "countState": "bounded" if truncated else "complete",
                "directoryLimit": BROWSER_MAX_DIRECTORY_ITEMS,
                "privacy": {
                    "mode": "metadata-only",
                    "noteBodiesRead": False,
                    "selectedBodyRead": False,
                    "uploads": False,
                    "credentialsUsed": False,
                    "persisted": False,
                },
            }

    def open_note(
        self,
        brain_id: str,
        inventory_revision: str,
        relative_path: str,
    ) -> dict:
        with self._lock:
            brain, root, root_identity = self._require_browsable(
                str(brain_id),
                str(inventory_revision),
            )
            target, parts = self._resolve_browser_target(root, relative_path, expected="file")
            if not parts:
                raise ValueError("Select one note inside the connected Brain")
            if self._is_sensitive_path(parts, file_name=parts[-1]):
                raise ValueError("Credential-like files and authentication stores cannot be opened")
            if target.suffix.casefold() not in BROWSER_TEXT_EXTENSIONS:
                raise ValueError("This file type is not supported by the read-only Brain viewer")
            try:
                before = target.lstat()
            except PermissionError as error:
                raise ValueError("The selected note cannot be read because permission was denied") from error
            except OSError as error:
                raise ValueError("The selected note is unavailable") from error
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("The selected Brain item is not a regular text note")
            if before.st_size > BROWSER_MAX_FILE_BYTES:
                raise ValueError("This note is too large for the bounded Brain viewer")

            if not self._secure_directory_descriptors_available(require_scandir=False):
                raise ValueError("Secure Brain browsing is unavailable on this platform")
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            descriptor = None
            directory_descriptor = None
            try:
                directory_descriptor = self._open_browser_directory(
                    root,
                    parts[:-1],
                    root_identity,
                    require_scandir=False,
                )
                descriptor = os.open(parts[-1], flags, dir_fd=directory_descriptor)
                observed = os.fstat(descriptor)
                if not stat.S_ISREG(observed.st_mode):
                    raise ValueError("The selected Brain item is not a regular text note")
                if (observed.st_dev, observed.st_ino) != (before.st_dev, before.st_ino):
                    raise ValueError("The selected note changed while it was being opened")
                if observed.st_size > BROWSER_MAX_FILE_BYTES:
                    raise ValueError("This note is too large for the bounded Brain viewer")
                chunks = []
                remaining = BROWSER_MAX_FILE_BYTES + 1
                while remaining > 0:
                    chunk = os.read(descriptor, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
            except PermissionError as error:
                raise ValueError("The selected note cannot be read because permission was denied") from error
            except OSError as error:
                raise ValueError("The selected note is unavailable") from error
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if directory_descriptor is not None:
                    os.close(directory_descriptor)
            if len(raw) > BROWSER_MAX_FILE_BYTES:
                raise ValueError("This note is too large for the bounded Brain viewer")
            if b"\x00" in raw:
                raise ValueError("Binary files cannot be opened in the Brain viewer")
            try:
                body = raw.decode("utf-8-sig", errors="strict")
            except UnicodeDecodeError as error:
                raise ValueError("The selected note is not valid UTF-8 text") from error
            return {
                "ok": True,
                "schemaVersion": SCHEMA_VERSION,
                "view": "note",
                "brainId": brain["id"],
                "inventoryRevision": self._inventory_revision,
                "brainLabel": brain.get("label") or "Brain",
                "relativePath": "/".join(parts),
                "parentPath": "/".join(parts[:-1]),
                "breadcrumbs": self._breadcrumbs(brain, parts),
                "kind": "file",
                "sizeBytes": int(observed.st_size),
                "modifiedAt": _iso_time(observed.st_mtime),
                "body": body,
                "renderMode": "plain-text",
                "privacy": {
                    "mode": "explicit-single-file",
                    "noteBodiesRead": True,
                    "selectedBodyRead": True,
                    "uploads": False,
                    "credentialsUsed": False,
                    "persisted": False,
                    "routed": False,
                },
            }

    def set_connected(self, path: str, connected: bool) -> dict:
        with self._lock:
            brain = self._require_known(path)
            if brain.get("managedProjectChild"):
                raise ValueError("Project Brain connections are governed by the project menu")
            key = brain["path"]
            settings = self._read_settings()
            if not self._settings_state.get("trusted"):
                raise ValueError("Brain settings are untrusted and cannot record this choice")
            connections = dict(settings.get("connections") or {})
            opt_outs = dict(settings.get("optOuts") or {})
            if connected:
                if brain.get("indexedOnly") or brain.get("permissionDenied"):
                    raise ValueError("This Brain cannot be securely connected")
                fingerprint = self._root_fingerprint(
                    key,
                    brain_type=brain.get("type"),
                    private=False,
                )
                connections[key] = {
                    "path": key,
                    "fingerprint": fingerprint,
                    "source": "explicit",
                }
                opt_outs.pop(key, None)
            else:
                previous = connections.pop(key, None)
                fingerprint = self._root_fingerprints.get(key)
                if fingerprint is None and isinstance(previous, dict):
                    fingerprint = previous.get("fingerprint")
                opt_outs[key] = {
                    "path": key,
                    "state": "disconnected",
                    "fingerprint": fingerprint,
                }
            settings["connections"] = connections
            settings["optOuts"] = opt_outs
            self._write_settings(settings)
            return self.scan(force=True)

    def repair_connection(self, expected_path: str, selected_path: str) -> dict:
        """Reconnect only after the user reselects the exact known root.

        This is the bounded permission/identity repair path.  Selecting a
        sibling, replacement alias, or unrelated directory never broadens the
        discovered root.  A fresh fingerprint is recorded only after the
        selected path is rescanned and classified as the same Brain root.
        """

        with self._lock:
            expected_key = _path_key(expected_path)
            selected_key = _path_key(selected_path)
            if selected_key != expected_key:
                raise ValueError("Choose the exact Brain folder shown in Activity Monitor")
            self.scan(force=True)
            brain = self._require_known(expected_key)
            if brain.get("indexedOnly") or brain.get("permissionDenied"):
                raise ValueError("macOS still has not granted access to this exact Brain folder")
            if brain.get("managedProjectChild"):
                # Managed Codex/Claude roots auto-connect from their verified
                # project registration. The native folder grant repairs access;
                # it must not create a second user-managed connection record.
                return self.scan(force=True)
            return self.set_connected(expected_key, True)

    def set_ignored(self, path: str, ignored: bool) -> dict:
        with self._lock:
            brain = self._require_known(path)
            if brain.get("managedProjectChild"):
                raise ValueError("Project Brains can be made dormant from the project menu but are never ignored")
            key = brain["path"]
            settings = self._read_settings()
            if not self._settings_state.get("trusted"):
                raise ValueError("Brain settings are untrusted and cannot record this choice")
            connections = dict(settings.get("connections") or {})
            opt_outs = dict(settings.get("optOuts") or {})
            if ignored:
                previous = connections.pop(key, None)
                fingerprint = self._root_fingerprints.get(key)
                if fingerprint is None and isinstance(previous, dict):
                    fingerprint = previous.get("fingerprint")
                opt_outs[key] = {
                    "path": key,
                    "state": "ignored",
                    "fingerprint": fingerprint,
                }
            else:
                opt_outs.pop(key, None)
            settings["connections"] = connections
            settings["optOuts"] = opt_outs
            self._write_settings(settings)
            return self.scan(force=True)

    def forget(self, path: str) -> dict:
        with self._lock:
            brain = self._require_known(path)
            if brain.get("managedProjectChild"):
                raise ValueError("Project Brains are retained by their project lifecycle")
            key = brain["path"]
            settings = self._read_settings()
            if not self._settings_state.get("trusted"):
                raise ValueError("Brain settings are untrusted and cannot record this choice")
            connections = dict(settings.get("connections") or {})
            previous = connections.pop(key, None)
            fingerprint = self._root_fingerprints.get(key)
            if fingerprint is None and isinstance(previous, dict):
                fingerprint = previous.get("fingerprint")
            opt_outs = dict(settings.get("optOuts") or {})
            opt_outs[key] = {
                "path": key,
                "state": "forgotten",
                "fingerprint": fingerprint,
            }
            settings["connections"] = connections
            settings["optOuts"] = opt_outs
            self._write_settings(settings)
            return self.scan(force=True)

    def create_brain(self, name: str = "My AI Brain") -> dict:
        with self._lock:
            safe_name = _safe_name(name)
            documents = self.home / "Documents"
            documents.mkdir(parents=True, exist_ok=True)
            target = documents / safe_name
            suffix = 2
            while target.exists():
                target = documents / f"{safe_name} {suffix}"
                suffix += 1
            target.mkdir()
            for folder in STRUCTURE_FOLDERS:
                (target / folder).mkdir()
            (target / ".obsidian").mkdir()
            readme = target / "README.md"
            with readme.open("w", encoding="utf-8") as handle:
                handle.write(
                    f"# {target.name}\n\n"
                    "A private local AI Brain. Your notes stay on this device unless you choose otherwise.\n"
                )
            settings = self._read_settings()
            if not self._settings_state.get("trusted"):
                raise ValueError("Brain settings are untrusted and cannot record the new Brain")
            key = self._lexical_path_key(target)
            fingerprint = self._root_fingerprint(key, brain_type="Obsidian vault", private=False)
            connections = dict(settings.get("connections") or {})
            connections[key] = {
                "path": key,
                "fingerprint": fingerprint,
                "source": "created",
            }
            opt_outs = dict(settings.get("optOuts") or {})
            opt_outs.pop(key, None)
            settings["connections"] = connections
            settings["optOuts"] = opt_outs
            self._write_settings(settings)
            inventory = self.scan(force=True)
            return {"ok": True, "createdPath": _path_key(target), "inventory": inventory}

    def preview_structure(self, path: str) -> dict:
        with self._lock:
            brain = self._require_known(path, structure=True)
            root = Path(brain["path"])
            base = root / "GrokCode" if brain["type"] == "KE Brain" and (root / "GrokCode").is_dir() else root
            recommendations = KE_STRUCTURE_FOLDERS if brain["type"] == "KE Brain" else STRUCTURE_FOLDERS
            existing = set()
            try:
                with os.scandir(base) as entries:
                    existing = {entry.name for entry in entries if entry.is_dir(follow_symlinks=False)}
            except OSError as error:
                raise ValueError(f"The brain structure cannot be inspected: {error}") from error
            create_paths = [str(base / name) for name in recommendations if name not in existing]
            preview_id = "preview_" + secrets.token_hex(10)
            preview = {
                "ok": True,
                "previewId": preview_id,
                "brainId": brain["id"],
                "path": brain["path"],
                "label": brain["label"],
                "generatedAt": _iso_time(),
                "expiresAtEpoch": time.time() + 600,
                "createDirectories": create_paths,
                "moveFiles": [],
                "deleteFiles": [],
                "summary": (
                    f"Create {len(create_paths)} missing navigation folder"
                    + ("s" if len(create_paths) != 1 else "")
                    + "; leave every existing file in place."
                    if create_paths
                    else "This brain already has the recommended navigation structure."
                ),
                "analysis": "Folder names and filesystem metadata only; note bodies were not read.",
                "backup": "A change manifest is saved before any folder is created.",
            }
            self._previews[preview_id] = preview
            return json.loads(json.dumps(preview))

    def apply_structure(self, preview_id: str, confirmation: str) -> dict:
        with self._lock:
            if confirmation != "APPLY":
                raise ValueError("Explicit confirmation is required")
            preview = self._previews.get(str(preview_id))
            if not preview or preview.get("expiresAtEpoch", 0) < time.time():
                raise ValueError("That structure preview is missing or expired")
            brain = self._require_known(preview["path"], structure=True)
            root = Path(brain["path"])
            operation_id = "brainop_" + secrets.token_hex(10)
            backup_root = (
                self.settings_path.parent
                / "Brain Backups"
                / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{operation_id[-8:]}"
            )
            backup_descriptor = self._open_trusted_directory(backup_root, private=True, create=True)
            os.close(backup_descriptor)
            manifest_path = backup_root / "manifest.json"
            manifest = {
                "schemaVersion": "ke.activity-monitor-brain-operation.v1",
                "operationId": operation_id,
                "brainPath": str(root),
                "createdAt": _iso_time(),
                "status": "prepared",
                "createdDirectories": [],
                "plannedDirectories": preview["createDirectories"],
                "existingContentMoved": False,
                "noteBodiesRead": False,
            }
            self._write_json_atomic(manifest_path, manifest)
            created: list[str] = []
            try:
                for raw_path in preview["createDirectories"]:
                    target = Path(raw_path)
                    target.relative_to(root)
                    target.mkdir()
                    created.append(str(target))
            except Exception:
                for raw_path in reversed(created):
                    try:
                        Path(raw_path).rmdir()
                    except OSError:
                        pass
                raise
            manifest["status"] = "applied"
            manifest["appliedAt"] = _iso_time()
            manifest["createdDirectories"] = created
            self._write_json_atomic(manifest_path, manifest)
            settings = self._read_settings()
            index = dict(settings.get("operationIndex") or {})
            index[operation_id] = str(manifest_path)
            settings["operationIndex"] = index
            self._write_settings(settings)
            self._previews.pop(str(preview_id), None)
            return {
                "ok": True,
                "operationId": operation_id,
                "createdDirectories": created,
                "backupManifest": str(manifest_path),
                "inventory": self.scan(force=True),
            }

    def rollback_structure(self, operation_id: str) -> dict:
        with self._lock:
            settings = self._read_settings()
            manifest_raw = (settings.get("operationIndex") or {}).get(str(operation_id))
            if not manifest_raw:
                raise ValueError("That Brain change cannot be found")
            manifest_path = Path(manifest_raw)
            try:
                with manifest_path.open("r", encoding="utf-8") as handle:
                    manifest = json.load(handle)
            except (OSError, ValueError) as error:
                raise ValueError("The Brain change manifest is unavailable") from error
            root = Path(manifest["brainPath"]).resolve()
            removed: list[str] = []
            retained: list[str] = []
            for raw_path in reversed(manifest.get("createdDirectories") or []):
                target = Path(raw_path).resolve()
                try:
                    target.relative_to(root)
                except ValueError:
                    retained.append(str(target))
                    continue
                try:
                    target.rmdir()
                    removed.append(str(target))
                except OSError:
                    retained.append(str(target))
            manifest["status"] = "rolled-back" if not retained else "rollback-partial"
            manifest["rolledBackAt"] = _iso_time()
            manifest["removedDirectories"] = removed
            manifest["retainedNonEmptyDirectories"] = retained
            self._write_json_atomic(manifest_path, manifest)
            return {
                "ok": not retained,
                "operationId": operation_id,
                "removedDirectories": removed,
                "retainedDirectories": retained,
                "message": (
                    "The Brain structure change was rolled back."
                    if not retained
                    else "Folders containing new content were preserved; nothing inside them was deleted."
                ),
                "inventory": self.scan(force=True),
            }
