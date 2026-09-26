"""Governed, current-user-only Cleanup & Speed workflow for Activity Monitor.

Analysis is metadata-first and begins only after an explicit API request.  A
cleanup execution can consume only an immutable, unexpired preview plan and
requires the exact confirmation ``CLEAN``.  Packaged automatic mutation fails
closed unless an injected platform adapter proves identity-conditional,
no-follow, no-replace move/delete/restore semantics.  Foundation's pathname
Trash API alone does not meet that contract, so it is discovery-only here and
is never used as a pathname fallback.
"""

import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import secrets
import selectors
import stat
import subprocess
import threading
import time


SCHEMA_VERSION = "ke.activity-monitor-cleanup.v1"
CACHE_TTL_SECONDS = 60.0
PLAN_TTL_SECONDS = 300.0
MAX_SCAN_ITEMS = 5000
MAX_SCAN_ROOTS = 64
MAX_SCAN_BYTES = 500 * 1024 * 1024 * 1024
MAX_SCAN_SECONDS = 15.0
MAX_PLAN_ITEMS = 500
MAX_PLAN_BYTES = 20 * 1024 * 1024 * 1024
MAX_REVEAL_ITEMS = 12
MAX_HELPER_OUTPUT_BYTES = 2 * 1024 * 1024
REVIEW_HELPER_SCHEMA_VERSION = "ke.activity-monitor-cleanup-helper.v1"
REVIEW_HELPER_CATEGORY_SECONDS = 2.0
MAX_HISTORY_ROWS = 1000
MAX_JOURNAL_BYTES = 1024 * 1024
STAGING_NAME = ".ke-activity-monitor-cleanup-staging"
MIN_LOG_AGE_DAYS = 7.0
IDENTITY_MUTATION_CONTRACT = "identity-conditional-nofollow-noreplace-v1"
SF_DATALESS = 0x40000000


CATEGORY_DEFINITIONS = {
    "app-caches": {
        "label": "App and user caches",
        "riskClass": "SAFE",
        "actionClass": "rebuildable-delete",
        "reversibility": "non-reversible",
        "semantics": "Selected cache data is expected to regenerate; app state and profiles are excluded.",
    },
    "logs-crash": {
        "label": "Logs and crash reports",
        "riskClass": "SAFE",
        "actionClass": "rebuildable-delete",
        "reversibility": "non-reversible",
        "semantics": "Selected old current-user diagnostic files are not required for app operation.",
    },
    "browser-cache": {
        "label": "Browser cache",
        "riskClass": "SAFE",
        "actionClass": "rebuildable-delete",
        "reversibility": "non-reversible",
        "semantics": "Only known cache roots are eligible and only while the browser is confirmed inactive.",
    },
    "package-manager-caches": {
        "label": "Package-manager download caches",
        "riskClass": "SAFE",
        "actionClass": "rebuildable-delete",
        "reversibility": "non-reversible",
        "semantics": "Downloaded package artifacts can be fetched again; manifests and installed environments are excluded.",
    },
    "developer-caches": {
        "label": "Xcode and developer build caches",
        "riskClass": "SAFE",
        "actionClass": "rebuildable-delete",
        "reversibility": "non-reversible",
        "semantics": "Known derived-data caches regenerate; source, archives, lockfiles, and active environments are excluded.",
    },
    "old-installers": {
        "label": "Old installers and archives",
        "riskClass": "RECOVERABLE",
        "actionClass": "trash",
        "reversibility": "recoverable-from-trash",
        "semantics": "Selected items move through the macOS Trash API; storage is not reclaimed until Trash is emptied separately.",
    },
    "downloads-large": {
        "label": "Large Downloads",
        "riskClass": "REVIEW REQUIRED",
        "actionClass": "review-only",
        "reversibility": "no-action",
        "semantics": "Large personal files require a human decision and are never automatically removed.",
    },
    "downloads-duplicates": {
        "label": "Download duplicates",
        "riskClass": "REVIEW REQUIRED",
        "actionClass": "review-only",
        "reversibility": "no-action",
        "semantics": "Byte hashing occurs only when explicitly selected; duplicate findings remain review-only.",
    },
    "trash": {
        "label": "Trash",
        "riskClass": "REVIEW REQUIRED",
        "actionClass": "empty-trash-separate",
        "reversibility": "irreversible-separate-confirmation",
        "semantics": "Empty Trash is never bundled with CLEAN and requires a separate stronger confirmation.",
    },
    "unused-apps-support": {
        "label": "Unused apps and support data",
        "riskClass": "REVIEW REQUIRED",
        "actionClass": "review-only",
        "reversibility": "no-action",
        "semantics": "Usage and dependency evidence is insufficient for automatic removal.",
    },
    "device-backups": {
        "label": "iOS and device backups",
        "riskClass": "REVIEW REQUIRED",
        "actionClass": "review-only",
        "reversibility": "no-action",
        "semantics": "Backups require review in the owning Apple workflow.",
    },
    "local-models": {
        "label": "Local model stores",
        "riskClass": "REVIEW REQUIRED",
        "actionClass": "review-only",
        "reversibility": "no-action",
        "semantics": "Models may be expensive to restore and require workload-aware review.",
    },
    "docker-vm": {
        "label": "Docker and VM data",
        "riskClass": "REVIEW REQUIRED",
        "actionClass": "review-only",
        "reversibility": "no-action",
        "semantics": "Container and virtual-machine data must be managed by the owning product.",
    },
    "project-artifacts": {
        "label": "Project artifacts",
        "riskClass": "REVIEW REQUIRED",
        "actionClass": "review-only",
        "reversibility": "no-action",
        "semantics": "Project dependencies and build trees require project-aware review; source and manifests stay protected.",
    },
    "time-machine": {
        "label": "Time Machine snapshots",
        "riskClass": "REVIEW REQUIRED",
        "actionClass": "review-only",
        "reversibility": "no-action",
        "semantics": "Snapshots are not modified by Cleanup & Speed and must be managed through macOS.",
    },
    "background-login": {
        "label": "Background and login performance",
        "riskClass": "REVIEW REQUIRED",
        "actionClass": "review-only",
        "reversibility": "no-action",
        "semantics": "Stopping processes or changing login items is a separate authority flow.",
    },
}


def _iso(epoch):
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _finite(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _digest(*values):
    material = "\x1f".join(str(value) for value in values).encode("utf-8", "replace")
    return hashlib.sha256(material).hexdigest()


class CleanupError(RuntimeError):
    def __init__(self, code, public_message):
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message


class FoundationTrashAdapter:
    """Discover Foundation Trash without granting unsafe pathname authority.

    ``trashItemAtURL`` has the correct macOS Trash semantics, but its source is
    a URL rather than an already-open descriptor plus expected identity.  That
    leaves an unavoidable final path-swap boundary.  Until a packaged adapter
    can preserve the reviewed identity through that platform call, recoverable
    automatic actions remain unavailable instead of emulating Trash or calling
    Foundation on a re-opened name.
    """

    def __init__(self):
        self.contract_version = None
        self.supports_identity_target = False
        self.available = False
        self.platform_available = False
        try:
            import Foundation  # type: ignore  # noqa: F401

            self.platform_available = True
        except Exception:
            self.platform_available = False


class UnavailableIdentityMutationAdapter:
    """Fail-closed packaged boundary for cleanup-target mutation."""

    available = False
    contract_version = None


class CleanupService:
    """Analyze, preview, and execute bounded cleanup without ambient authority."""

    def __init__(
        self,
        home=None,
        platform_name=None,
        uid=None,
        clock=None,
        monotonic=None,
        category_roots=None,
        state_root=None,
        current_app_path=None,
        open_handle_checker=None,
        browser_running_checker=None,
        trash_adapter=None,
        identity_mutation_adapter=None,
        performance_probe=None,
        cache_ttl_seconds=CACHE_TTL_SECONDS,
        plan_ttl_seconds=PLAN_TTL_SECONDS,
        max_scan_items=MAX_SCAN_ITEMS,
        max_scan_bytes=MAX_SCAN_BYTES,
        max_scan_seconds=MAX_SCAN_SECONDS,
        max_plan_items=MAX_PLAN_ITEMS,
        max_plan_bytes=MAX_PLAN_BYTES,
        before_action_hook=None,
        analysis_swap_hook=None,
        before_trash_hook=None,
        journal_swap_hook=None,
        reveal_handler=None,
        destination_opener=None,
        review_helper_command=None,
        review_helper_runner=None,
    ):
        self.home = (Path(home) if home is not None else Path.home()).resolve()
        self.platform_name = platform_name or platform.system()
        self.uid = os.geteuid() if uid is None else int(uid)
        self.clock = clock or time.time
        self.monotonic = monotonic or time.monotonic
        self.cache_ttl_seconds = max(1.0, min(300.0, float(cache_ttl_seconds)))
        self.plan_ttl_seconds = max(10.0, min(1800.0, float(plan_ttl_seconds)))
        self.max_scan_items = max(1, min(100000, int(max_scan_items)))
        self.max_scan_bytes = max(1, min(10 * 1024**4, int(max_scan_bytes)))
        self.max_scan_seconds = max(0.1, min(60.0, float(max_scan_seconds)))
        self.max_plan_items = max(1, min(5000, int(max_plan_items)))
        self.max_plan_bytes = max(1, min(1024**4, int(max_plan_bytes)))
        state_root_value = Path(state_root) if state_root is not None else self.home / "Library" / "Application Support" / "KE Activity Monitor" / "cleanup"
        if not state_root_value.is_absolute():
            state_root_value = self.home / state_root_value
        self.state_root = Path(os.path.abspath(os.fspath(state_root_value)))
        self.current_app_path = Path(current_app_path).resolve() if current_app_path else None
        self._open_handle_checker = open_handle_checker or self._default_open_handle_checker
        self._browser_running_checker = browser_running_checker or self._default_browser_running_checker
        self._trash_adapter = trash_adapter or FoundationTrashAdapter()
        self._identity_mutation_adapter = identity_mutation_adapter or UnavailableIdentityMutationAdapter()
        self._performance_probe = performance_probe or self._default_performance_probe
        self._before_action_hook = before_action_hook
        self._analysis_swap_hook = analysis_swap_hook
        self._before_trash_hook = before_trash_hook
        self._journal_swap_hook = journal_swap_hook
        self._reveal_handler = reveal_handler or self._default_reveal_handler
        self._destination_opener = destination_opener or self._default_destination_opener
        self._review_helper_command = tuple(review_helper_command or ())
        self._review_helper_runner = review_helper_runner
        self._category_roots = self._build_roots(category_roots)
        self._lock = threading.Lock()
        self._analysis_inflight = None
        self._analysis_jobs = {}
        self._analysis_internal = {}
        self._analysis_cache = None
        self._plans = {}
        self._execution_jobs = {}
        self._rollback = {}

    def _build_roots(self, override):
        if override is not None:
            roots = {}
            for category, paths in override.items():
                if category in CATEGORY_DEFINITIONS and isinstance(paths, (list, tuple)):
                    roots[category] = [
                        Path(path).resolve(strict=False)
                        for path in paths[:MAX_SCAN_ROOTS]
                    ]
            return roots
        return {
            "app-caches": [self.home / "Library" / "Caches"],
            "logs-crash": [self.home / "Library" / "Logs", self.home / "Library" / "Logs" / "DiagnosticReports"],
            "browser-cache": [
                self.home / "Library" / "Caches" / "Google" / "Chrome",
                self.home / "Library" / "Caches" / "com.apple.Safari",
                self.home / "Library" / "Caches" / "Firefox" / "Profiles",
            ],
            "package-manager-caches": [
                self.home / "Library" / "Caches" / "Homebrew",
                self.home / ".npm" / "_cacache",
                self.home / "Library" / "Caches" / "pip",
            ],
            "developer-caches": [self.home / "Library" / "Developer" / "Xcode" / "DerivedData"],
            "old-installers": [self.home / "Downloads"],
            "downloads-large": [self.home / "Downloads"],
            "downloads-duplicates": [self.home / "Downloads"],
            "trash": [self.home / ".Trash"],
            "device-backups": [self.home / "Library" / "Application Support" / "MobileSync" / "Backup"],
            "local-models": [self.home / ".ollama" / "models", self.home / ".cache" / "huggingface"],
            "docker-vm": [self.home / "Library" / "Containers" / "com.docker.docker" / "Data"],
            "project-artifacts": [self.home / "Developer", self.home / "Projects", self.home / "Code"],
            "background-login": [self.home / "Library" / "LaunchAgents"],
        }

    @staticmethod
    def _privacy(duplicate_analysis=False):
        return {
            "currentUserOnly": True,
            "metadataFirst": True,
            "fileBodiesRead": bool(duplicate_analysis),
            "fileBodyUse": (
                "explicit-bounded-duplicate-hash-only"
                if duplicate_analysis
                else "none"
            ),
            "credentialsRead": False,
            "fullDiskAccessExpandsProtectedScope": False,
            "networkCalls": False,
            "uploads": False,
            "shell": False,
            "absolutePathsReturned": False,
            "contentPersisted": False,
        }

    def _supported(self):
        return self.platform_name == "Darwin" and self.uid != 0

    def _require_supported(self):
        if not self._supported():
            raise CleanupError(
                "unsupported",
                "Cleanup & Speed requires current-user, non-root macOS execution.",
            )

    def _identity_mutations_available(self):
        adapter = self._identity_mutation_adapter
        return (
            bool(getattr(adapter, "available", False))
            and getattr(adapter, "contract_version", None) == IDENTITY_MUTATION_CONTRACT
            and callable(getattr(adapter, "move_noreplace", None))
            and callable(getattr(adapter, "delete_identity", None))
        )

    def _trash_identity_available(self):
        adapter = self._trash_adapter
        return (
            self._identity_mutations_available()
            and bool(getattr(adapter, "available", False))
            and bool(getattr(adapter, "supports_identity_target", False))
            and getattr(adapter, "contract_version", None) == IDENTITY_MUTATION_CONTRACT
            and callable(getattr(adapter, "trash_identity", None))
            and callable(getattr(adapter, "restore_identity", None))
        )

    def _require_identity_mutations(self):
        if not self._identity_mutations_available():
            raise CleanupError(
                "identity-mutation-unavailable",
                "Automatic cleanup is unavailable because this build cannot mutate the exact reviewed file identity atomically.",
            )

    def capabilities(self):
        identity_available = self._identity_mutations_available()
        trash_available = self._trash_identity_available()
        return {
            "schemaVersion": SCHEMA_VERSION,
            "supported": self._supported(),
            "automaticExecution": "available" if identity_available else "unavailable-fail-closed",
            "automaticExecutionReason": (
                "An identity-conditional no-follow no-replace mutation adapter is active."
                if identity_available
                else "This build has no identity-conditional no-follow no-replace mutation adapter; analysis and review remain available, but automatic changes do not."
            ),
            "trash": "available" if trash_available else "unavailable",
            "trashIdentityBoundary": (
                IDENTITY_MUTATION_CONTRACT
                if trash_available
                else "unavailable-fail-closed"
            ),
            "trashPlatformBoundary": (
                "The active adapter preserves the reviewed identity through platform Trash."
                if trash_available
                else "Foundation Trash accepts a URL rather than an identity-bound descriptor; no recoverable action is executable and no raw Trash move is used."
            ),
            "emptyTrash": "separate-not-available",
            "irreversibleDirectorySafety": (
                IDENTITY_MUTATION_CONTRACT if identity_available else "unavailable-fail-closed"
            ),
            "journalSafety": "descriptor-bound-nofollow-bounded-append-fail-closed",
            "planConfirmation": "typed-CLEAN",
            "scanStartsAutomatically": False,
            "finderReview": "available-exact-selection",
            "maxFinderRevealItems": MAX_REVEAL_ITEMS,
            "activityMonitorMutation": False,
            "reviewDestinations": ["storage-settings", "trash", "downloads"],
            "privacy": self._privacy(),
        }

    @staticmethod
    def _default_reveal_handler(paths):
        """Reveal already-validated paths without accepting shell text."""
        try:
            from AppKit import NSWorkspace  # type: ignore
            from Foundation import NSURL  # type: ignore

            urls = [NSURL.fileURLWithPath_(os.fspath(path)) for path in paths]
            NSWorkspace.sharedWorkspace().activateFileViewerSelectingURLs_(urls)
            return len(urls)
        except Exception:
            revealed = 0
            for path in paths:
                completed = subprocess.run(
                    ["/usr/bin/open", "-R", os.fspath(path)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    timeout=3.0,
                    check=False,
                )
                if completed.returncode == 0:
                    revealed += 1
            if revealed == 0:
                raise OSError("Finder reveal was unavailable")
            return revealed

    @staticmethod
    def _default_destination_opener(target):
        completed = subprocess.run(
            ["/usr/bin/open", os.fspath(target)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=3.0,
            check=False,
        )
        if completed.returncode != 0:
            raise OSError("Review destination was unavailable")
        return True

    def _relative_label(self, path):
        try:
            relative = Path(path).relative_to(self.home)
        except ValueError:
            return None
        if not relative.parts:
            return "~"
        return "~/" + relative.as_posix()

    def _contained(self, path):
        try:
            Path(path).relative_to(self.home)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_relative_to(path, parent):
        try:
            Path(path).relative_to(parent)
            return True
        except ValueError:
            return False

    @staticmethod
    def _nofollow_flags(*, directory=False):
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise CleanupError(
                "platform-safety-unavailable",
                "Descriptor-bound no-follow analysis is unavailable on this platform.",
            )
        flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
        if directory:
            flags |= os.O_DIRECTORY
        else:
            # A path can be swapped from a reviewed regular file to a FIFO
            # between lstat() and open().  O_NOFOLLOW protects links, while
            # O_NONBLOCK keeps that adversarial special-file swap cancellable.
            flags |= getattr(os, "O_NONBLOCK", 0)
        return flags

    @staticmethod
    def _same_identity(left, right):
        return (
            left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
            and left.st_uid == right.st_uid
            and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        )

    def _analysis_hook(self, phase, path):
        if self._analysis_swap_hook is not None:
            self._analysis_swap_hook(phase, Path(path))

    def _open_root_context(self, root):
        try:
            relative = Path(root).relative_to(self.home)
        except ValueError as error:
            raise CleanupError("analysis-path-swap", "Analysis root escaped the current-user home.") from error
        parts = relative.parts
        if not parts:
            raise CleanupError("analysis-path-swap", "The home root itself is never a cleanup root.")
        self._analysis_hook("before-root-open", root)
        current = os.open(os.fspath(self.home), self._nofollow_flags(directory=True))
        root_fd = None
        try:
            home_metadata = os.fstat(current)
            if home_metadata.st_uid != os.getuid():
                raise CleanupError("analysis-path-swap", "The current-user home identity is unsafe.")
            for part in parts[:-1]:
                next_fd = os.open(part, self._nofollow_flags(directory=True), dir_fd=current)
                os.close(current)
                current = next_fd
                metadata = os.fstat(current)
                if metadata.st_uid != os.getuid():
                    raise CleanupError("analysis-path-swap", "An analysis root component changed ownership.")
            parent_fd = current
            root_fd = os.open(parts[-1], self._nofollow_flags(directory=True), dir_fd=parent_fd)
            root_metadata = os.fstat(root_fd)
            if root_metadata.st_uid != os.getuid():
                raise CleanupError("analysis-path-swap", "The analysis root is not current-user owned.")
            self._analysis_hook("after-root-open", root)
            current_name = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if not self._same_identity(root_metadata, current_name):
                raise CleanupError("analysis-path-swap", "The analysis root changed after descriptor open.")
            return {"rootFd": root_fd, "parentFd": parent_fd, "name": parts[-1], "stat": root_metadata}
        except Exception:
            if root_fd is not None:
                os.close(root_fd)
            os.close(current)
            raise

    def _consume_scan_budget(self, budget, *, items=0, byte_count=0):
        if budget is None:
            return
        next_items = budget["items"] + max(0, int(items))
        next_bytes = budget["bytes"] + max(0, int(byte_count))
        if next_items > self.max_scan_items or next_bytes > self.max_scan_bytes:
            raise CleanupError("scan-limit", "Analysis reached its bounded item or byte limit.")
        budget["items"] = next_items
        budget["bytes"] = next_bytes

    def _measure_entry_fd(
        self,
        parent_fd,
        name,
        expected,
        cancel,
        deadline,
        path_hint,
        depth=0,
        scan_budget=None,
        count_current=True,
    ):
        if cancel.is_set():
            raise CleanupError("cancelled", "Analysis was cancelled.")
        if self.monotonic() > deadline:
            raise CleanupError("scan-time-limit", "Analysis reached its time limit.")
        self._analysis_hook("before-candidate-open" if depth == 0 else "before-nested-open", path_hint)
        is_directory = stat.S_ISDIR(expected.st_mode)
        if not (is_directory or stat.S_ISREG(expected.st_mode)):
            raise CleanupError(
                "unsupported-file-type",
                "Sockets, FIFOs, devices, and other special files are never cleanup candidates.",
            )
        if not is_directory:
            try:
                actual = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as error:
                raise CleanupError(
                    "analysis-path-swap",
                    "A metadata target changed before descriptor-relative revalidation.",
                ) from error
            expected_mtime_ns = int(getattr(expected, "st_mtime_ns", 0))
            actual_mtime_ns = int(getattr(actual, "st_mtime_ns", 0))
            if (
                not self._same_identity(expected, actual)
                or int(actual.st_size) != int(expected.st_size)
                or actual_mtime_ns != expected_mtime_ns
            ):
                raise CleanupError("analysis-path-swap", "A metadata target changed during analysis.")
            total_bytes = max(0, int(actual.st_size))
            if count_current:
                self._consume_scan_budget(scan_budget, items=1, byte_count=total_bytes)
            return total_bytes, 1, actual_mtime_ns
        try:
            descriptor = os.open(name, self._nofollow_flags(directory=True), dir_fd=parent_fd)
        except OSError as error:
            raise CleanupError("analysis-path-swap", "A metadata target changed before descriptor open.") from error
        try:
            actual = os.fstat(descriptor)
            if not self._same_identity(expected, actual) or actual.st_uid != os.getuid():
                raise CleanupError("analysis-path-swap", "A metadata target changed identity during analysis.")
            total_bytes = max(0, int(actual.st_size))
            if count_current:
                self._consume_scan_budget(scan_budget, items=1, byte_count=total_bytes)
            item_count = 1
            newest_mtime_ns = int(getattr(actual, "st_mtime_ns", 0))
            if is_directory:
                try:
                    entries = os.scandir(descriptor)
                except OSError as error:
                    raise CleanupError("analysis-unreadable", "A directory could not be enumerated safely.") from error
                try:
                    for entry in entries:
                        child_name = entry.name
                        if child_name in {"", ".", ".."}:
                            continue
                        if cancel.is_set():
                            raise CleanupError("cancelled", "Analysis was cancelled.")
                        try:
                            child_stat = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
                        except OSError as error:
                            raise CleanupError(
                                "analysis-unreadable",
                                "A nested metadata entry could not be verified safely.",
                            ) from error
                        child_hint = Path(path_hint) / child_name
                        protection = self._protection_reason(child_hint, child_stat)
                        if protection is not None:
                            raise CleanupError(
                                protection,
                                "A protected or link-like nested entry makes this candidate ineligible.",
                            )
                        child_bytes, child_items, child_newest = self._measure_entry_fd(
                            descriptor,
                            child_name,
                            child_stat,
                            cancel,
                            deadline,
                            child_hint,
                            depth + 1,
                            scan_budget,
                        )
                        total_bytes += child_bytes
                        item_count += child_items
                        newest_mtime_ns = max(newest_mtime_ns, child_newest)
                        if item_count > self.max_scan_items or total_bytes > self.max_scan_bytes:
                            raise CleanupError("scan-limit", "Analysis reached its bounded item or byte limit.")
                finally:
                    entries.close()
            return total_bytes, item_count, newest_mtime_ns
        finally:
            os.close(descriptor)

    def _hash_duplicate_candidate_at(self, parent_fd, name, expected, cancel, deadline, scan_budget=None):
        if not stat.S_ISREG(expected.st_mode):
            return None
        try:
            descriptor = os.open(name, self._nofollow_flags(), dir_fd=parent_fd)
        except OSError:
            return None
        digest = hashlib.sha256()
        try:
            actual = os.fstat(descriptor)
            if not self._same_identity(expected, actual) or actual.st_size > self.max_scan_bytes:
                return None
            remaining = max(0, int(actual.st_size))
            self._consume_scan_budget(scan_budget, byte_count=remaining)
            while remaining > 0:
                if cancel.is_set():
                    raise CleanupError("cancelled", "Duplicate analysis was cancelled.")
                if self.monotonic() > deadline:
                    raise CleanupError("scan-time-limit", "Duplicate analysis reached its time limit.")
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            if remaining != 0 or os.read(descriptor, 1):
                return None
            return digest.hexdigest()
        finally:
            os.close(descriptor)

    def _protection_reason(self, path, metadata=None):
        path = Path(path)
        if not self._contained(path):
            return "outside-current-user-home"
        try:
            metadata = metadata or path.lstat()
        except OSError:
            return "unreadable-metadata"
        if metadata.st_uid != os.getuid():
            return "other-owner"
        if stat.S_ISLNK(metadata.st_mode):
            return "symbolic-link"
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            return "unsupported-file-type"
        if int(getattr(metadata, "st_flags", 0)) & SF_DATALESS:
            return "dataless-object"
        try:
            relative = path.relative_to(self.home)
        except ValueError:
            return "outside-current-user-home"
        lower = tuple(part.casefold() for part in relative.parts)
        if not lower:
            return "home-root"
        protected_top = {"documents", "desktop", ".ssh", ".gnupg", ".aws", ".codex", ".claude", ".grokcode"}
        if lower[0] in protected_top:
            return "protected-root"
        protected_names = {
            ".git", "keychains", "mail", "messages", "cookies", "cookie", "login data",
            "passwords", "sessions", "session storage", "bookmarks", "history", "extensions",
            "credentials", "auth", "tokens", "brains", "brain", "memories", "memory",
        }
        if any(part in protected_names for part in lower):
            return "protected-data-class"
        basename = lower[-1]
        sensitive_names = {
            ".env", ".netrc", ".npmrc", ".pypirc", "id_rsa", "id_ed25519",
            "credentials.json", "token.json", "cookies.sqlite", "login data",
        }
        sensitive_suffixes = {".key", ".pem", ".p12", ".pfx", ".kdbx"}
        sensitive_markers = ("credential", "password", "cookie", "session", "token")
        if (
            basename in sensitive_names
            or basename.startswith(".env")
            or Path(basename).suffix in sensitive_suffixes
            or any(marker in basename for marker in sensitive_markers)
        ):
            return "protected-data-class"
        browser_profile_markers = {
            "application support/google/chrome",
            "application support/firefox/profiles",
            "library/safari",
        }
        joined = "/".join(lower)
        if any(marker in joined for marker in browser_profile_markers):
            return "browser-profile"
        if "ke-agent-rooms" in lower or "keguard" in lower:
            return "defense-receipt-or-state"
        if self.current_app_path is not None:
            try:
                path.relative_to(self.current_app_path)
                return "current-app"
            except ValueError:
                pass
        if any(part in {"activity monitor", "activity monitor.app", "ke activity monitor"} for part in lower):
            return "current-app"
        return None

    def _default_open_handle_checker(self, path):
        executable = "/usr/sbin/lsof"
        if not Path(executable).exists():
            return None
        try:
            metadata = os.lstat(path)
        except OSError:
            return None
        argv = (
            [executable, "-F", "p", "+D", os.fspath(path)]
            if stat.S_ISDIR(metadata.st_mode)
            else [executable, "-F", "p", "--", os.fspath(path)]
        )
        process = None
        selector = selectors.DefaultSelector()
        output_bytes = 0
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = self.monotonic() + 1.0
            while selector.get_map():
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    process.kill()
                    process.wait(timeout=0.2)
                    return None
                events = selector.select(timeout=min(0.05, remaining))
                if not events and process.poll() is not None:
                    events = [(key, None) for key in list(selector.get_map().values())]
                for key, _mask in events:
                    chunk = os.read(key.fileobj.fileno(), min(8192, 65537 - output_bytes))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output_bytes += len(chunk)
                    if output_bytes > 65536:
                        process.kill()
                        process.wait(timeout=0.2)
                        return None
            process.wait(timeout=max(0.01, deadline - self.monotonic()))
        except (OSError, subprocess.SubprocessError):
            if process is not None and process.poll() is None:
                process.kill()
            return None
        finally:
            selector.close()
            if process is not None and process.stdout is not None:
                process.stdout.close()
        if output_bytes > 0:
            return True
        if process.returncode in {0, 1}:
            return False
        return None

    @staticmethod
    def _default_browser_running_checker():
        names = ("Safari", "Google Chrome", "Firefox", "Microsoft Edge", "Brave Browser")
        for name in names:
            try:
                completed = subprocess.run(
                    ["/usr/bin/pgrep", "-x", name],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    timeout=0.5,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                return None
            if completed.returncode == 0:
                return True
            if completed.returncode not in {0, 1}:
                return None
        return False

    def _default_performance_probe(self):
        started = self.monotonic()
        try:
            os.statvfs(self.home)
            with os.scandir(self.home) as entries:
                for index, _entry in enumerate(entries):
                    if index >= 64:
                        break
        except OSError:
            return {"available": False, "latencyMs": None}
        elapsed = max(0.0, self.monotonic() - started)
        return {"available": True, "latencyMs": round(elapsed * 1000.0, 3)}

    def performance_assessment(self):
        if not self._supported():
            return {
                "schemaVersion": SCHEMA_VERSION,
                "state": "unsupported",
                "observedAt": None,
                "storage": {"state": "unknown", "freeBytes": None},
                "memoryPressureSwap": {"state": "unknown", "detail": "Current-user macOS execution is required."},
                "sustainedCpuLoad": {"state": "unknown", "normalizedPointLoad": None, "detail": "Current-user macOS execution is required."},
                "loginBackgroundItems": {"state": "not-connected", "detail": "No assessment ran."},
                "runawayProcesses": {"state": "not-connected", "detail": "No assessment ran."},
                "updateRestartNeeds": {"state": "not-connected", "detail": "No assessment ran."},
                "limitations": ["Cleanup & Speed is unavailable outside current-user, non-root macOS execution."],
            }
        try:
            disk = os.statvfs(self.home)
            free_bytes = int(disk.f_bavail * disk.f_frsize)
            total_bytes = int(disk.f_blocks * disk.f_frsize)
            free_ratio = free_bytes / total_bytes if total_bytes > 0 else None
        except OSError:
            free_bytes = None
            free_ratio = None
        try:
            load1 = float(os.getloadavg()[0])
            cpu_count = max(1, os.cpu_count() or 1)
            load_state = "point-attention" if load1 > cpu_count else "point-observed"
        except (OSError, TypeError, ValueError):
            load1 = None
            load_state = "unknown"
        storage_state = "unknown"
        if free_ratio is not None:
            storage_state = "critical" if free_ratio < 0.05 else "attention" if free_ratio < 0.15 else "observed"
        return {
            "schemaVersion": SCHEMA_VERSION,
            "observedAt": _iso(self.clock()),
            "storage": {"state": storage_state, "freeBytes": free_bytes},
            "memoryPressureSwap": {"state": "unknown", "detail": "No bounded published memory-pressure sample is connected to Cleanup & Speed."},
            "sustainedCpuLoad": {
                "state": "not-established" if load1 is not None else "unknown",
                "pointState": load_state,
                "normalizedPointLoad": None if load1 is None else round(load1 / max(1, os.cpu_count() or 1), 3),
                "detail": "One bounded load point cannot establish sustained load; a time-window sensor is not connected.",
            },
            "loginBackgroundItems": {"state": "review-only", "detail": "Changes require a separate user-authorized workflow."},
            "runawayProcesses": {"state": "not-connected", "detail": "Cleanup never stops processes."},
            "updateRestartNeeds": {"state": "not-connected", "detail": "Cleanup never installs updates or restarts the Mac."},
            "limitations": [
                "Cleanup cannot fix failing hardware, malware, thermal limits, application defects, or network performance.",
                "Process stopping, login-item changes, service disabling, update installation, reboot, quarantine, and policy changes are separate authority flows.",
            ],
        }

    @staticmethod
    def _is_old_installer(path, age_days):
        suffix = Path(path).suffix.casefold()
        return age_days >= 30.0 and suffix in {".dmg", ".pkg", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz"}

    @staticmethod
    def _is_project_artifact(path):
        name = Path(path).name.casefold()
        return name in {"node_modules", ".venv", "venv", "build", "dist", "deriveddata"}

    def _candidate_for(
        self,
        category,
        root,
        root_fd,
        name,
        metadata,
        root_metadata,
        cancel,
        deadline,
        options,
        disk_pressure,
        scan_budget=None,
    ):
        path = Path(root) / name
        reason = self._protection_reason(path, metadata)
        if reason:
            return None, reason
        if category == "app-caches":
            for browser_root in self._category_roots.get("browser-cache", []):
                try:
                    browser_root.relative_to(path)
                except ValueError:
                    continue
                return None, "specialized-browser-cache-required"
        definition = CATEGORY_DEFINITIONS[category]
        identity_available = self._identity_mutations_available()
        trash_available = self._trash_identity_available()
        action_class = definition["actionClass"]
        reversibility = definition["reversibility"]
        execution_state = "available"
        if definition["actionClass"] in {"rebuildable-delete", "trash"} and not identity_available:
            action_class = "review-only"
            reversibility = "no-action-identity-mutation-unavailable"
            execution_state = "identity-mutation-unavailable"
        elif category == "old-installers" and not trash_available:
            action_class = "review-only"
            reversibility = "no-action-trash-unavailable"
            execution_state = "trash-unavailable"
        now = float(self.clock())
        age_days = max(0.0, now - float(metadata.st_mtime)) / 86400.0
        if category == "logs-crash" and age_days < MIN_LOG_AGE_DAYS:
            return None, "log-too-recent"
        if category == "old-installers" and not self._is_old_installer(path, age_days):
            return None, None
        if category == "downloads-large" and (stat.S_ISDIR(metadata.st_mode) or metadata.st_size < 512 * 1024 * 1024):
            return None, None
        if category == "downloads-duplicates" and not options.get("duplicateAnalysis"):
            return None, None
        if category == "project-artifacts" and not self._is_project_artifact(path):
            return None, None
        if category == "browser-cache":
            browser_running = self._browser_running_checker()
            if browser_running is not False:
                return None, "browser-active-or-unverified"
        review_only = options.get("reviewOnly") is True
        if review_only:
            open_state = None
        else:
            open_state = self._open_handle_checker(path)
            if open_state is True:
                return None, "active-writer-or-handle"
            if open_state is None and definition["actionClass"] in {"rebuildable-delete", "trash"}:
                return None, "writer-state-unverified"
        candidate_deadline = min(deadline, self.monotonic() + 0.8) if review_only else deadline
        try:
            total_bytes, item_count, newest_mtime_ns = self._measure_entry_fd(
                root_fd,
                name,
                metadata,
                cancel,
                candidate_deadline,
                path,
                scan_budget=scan_budget,
                count_current=False,
            )
        except CleanupError as error:
            if error.code == "scan-time-limit" and review_only and self.monotonic() < deadline:
                raise CleanupError(
                    "candidate-time-limit",
                    "A large changing candidate exceeded its per-item review budget and was skipped.",
                ) from error
            raise
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if not self._same_identity(metadata, current):
            raise CleanupError("analysis-path-swap", "A candidate changed after descriptor-bound measurement.")
        if total_bytes <= 0:
            return None, None
        size_score = min(40, int(math.log2(max(1, total_bytes))) * 2)
        age_score = min(30, int(age_days // 7))
        pressure_score = 20 if disk_pressure == "critical" else 10 if disk_pressure == "attention" else 0
        risk_penalty = 25 if definition["riskClass"] == "REVIEW REQUIRED" else 10 if definition["riskClass"] == "RECOVERABLE" else 0
        score = max(0, min(100, size_score + age_score + pressure_score - risk_penalty))
        confidence = "high" if definition["riskClass"] == "SAFE" and open_state is False else "medium" if open_state is False or review_only else "low"
        candidate_id = _digest(category, self._relative_label(path), metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)[:20]
        relative_to_root = path.relative_to(root).as_posix()
        public_reason = definition["semantics"]
        if execution_state == "identity-mutation-unavailable":
            public_reason += " This build can analyze and review it, but automatic mutation is unavailable because exact identity-conditional action cannot be proven."
        elif execution_state == "trash-unavailable":
            public_reason += " Identity-preserving platform Trash is unavailable, so this remains review-only."
        public = {
            "id": candidate_id,
            "target": self._relative_label(path),
            "category": category,
            "bytes": total_bytes,
            "itemCount": item_count,
            "reason": public_reason,
            "confidence": confidence,
            "riskClass": definition["riskClass"],
            "actionClass": action_class,
            "reversibility": reversibility,
            "executionState": execution_state,
            "score": score,
            "factors": {
                "ageDays": round(age_days, 1),
                "sizeClass": "large" if total_bytes >= 1024**3 else "medium" if total_bytes >= 100 * 1024**2 else "small",
                "writerState": "not-checked-review-only" if review_only else "inactive",
                "runningOwnerApp": "inactive" if category == "browser-cache" else "not-applicable",
                "symlink": False,
                "ownership": "current-user",
                "containment": "current-user-home",
                "diskPressure": disk_pressure,
                "dependencyMarkers": "project-aware-review" if category == "project-artifacts" else "known-regeneration" if definition["riskClass"] == "SAFE" else "human-review",
            },
        }
        internal = {
            "public": public,
            "path": path,
            "root": root,
            "relativeToRoot": relative_to_root,
            "rootStat": {"dev": root_metadata.st_dev, "ino": root_metadata.st_ino, "uid": root_metadata.st_uid},
            "stat": {
                "dev": metadata.st_dev,
                "ino": metadata.st_ino,
                "uid": metadata.st_uid,
                "mode": stat.S_IFMT(metadata.st_mode),
                "size": metadata.st_size,
                "mtimeNs": metadata.st_mtime_ns,
                "treeBytes": total_bytes,
                "treeItems": item_count,
                "treeNewestMtimeNs": newest_mtime_ns,
            },
        }
        if category == "downloads-duplicates":
            content_digest = self._hash_duplicate_candidate_at(
                root_fd,
                name,
                metadata,
                cancel,
                deadline,
                scan_budget,
            )
            if content_digest is None:
                return None, "duplicate-hash-unavailable"
            internal["duplicateDigest"] = content_digest
        return internal, None

    def _analysis_options(self, options):
        options = options if isinstance(options, dict) else {}
        categories = options.get("categories")
        if not isinstance(categories, list):
            categories = list(CATEGORY_DEFINITIONS)
        categories = sorted({value for value in categories if value in CATEGORY_DEFINITIONS})
        return {
            "categories": categories,
            "duplicateAnalysis": options.get("duplicateAnalysis") is True,
            "reviewOnly": options.get("reviewOnly") is True,
        }

    def review_helper_bundle(self, category, result):
        """Serialize one isolated category without exporting absolute paths."""
        if category not in CATEGORY_DEFINITIONS or not isinstance(result, dict):
            raise CleanupError("helper-invalid", "The isolated metadata result was invalid.")
        analysis_id = str(result.get("analysisId") or "")
        with self._lock:
            analysis = self._analysis_internal.get(analysis_id)
            if analysis is None:
                raise CleanupError("helper-invalid", "The isolated metadata result was unavailable.")
            internal = [copy.deepcopy(item) for item in analysis["candidates"].values()]
        roots = list(self._category_roots.get(category, ()))
        encoded = []
        for item in internal:
            if item.get("public", {}).get("category") != category:
                continue
            try:
                root_index = next(index for index, root in enumerate(roots) if Path(root) == Path(item["root"]))
            except (KeyError, StopIteration):
                raise CleanupError("helper-invalid", "The isolated metadata root could not be encoded.")
            encoded.append(
                {
                    "public": copy.deepcopy(item["public"]),
                    "rootIndex": root_index,
                    "relativeToRoot": str(item["relativeToRoot"]),
                    "rootStat": copy.deepcopy(item["rootStat"]),
                    "stat": copy.deepcopy(item["stat"]),
                }
            )
        return {
            "schemaVersion": REVIEW_HELPER_SCHEMA_VERSION,
            "category": category,
            "result": copy.deepcopy(result),
            "internalCandidates": encoded,
        }

    @staticmethod
    def _helper_integer(value, *, minimum=0):
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise CleanupError("helper-invalid", "The isolated metadata result failed validation.")
        return int(value)

    def _import_review_helper_candidates(self, category, payload):
        if (
            not isinstance(payload, dict)
            or payload.get("schemaVersion") != REVIEW_HELPER_SCHEMA_VERSION
            or payload.get("category") != category
            or not isinstance(payload.get("internalCandidates"), list)
            or len(payload["internalCandidates"]) > self.max_scan_items
        ):
            raise CleanupError("helper-invalid", "The isolated metadata result failed validation.")
        roots = list(self._category_roots.get(category, ()))
        imported = []
        for encoded in payload["internalCandidates"]:
            if not isinstance(encoded, dict):
                raise CleanupError("helper-invalid", "The isolated metadata result failed validation.")
            root_index = self._helper_integer(encoded.get("rootIndex"))
            if root_index >= len(roots):
                raise CleanupError("helper-invalid", "The isolated metadata root failed validation.")
            relative = encoded.get("relativeToRoot")
            if not isinstance(relative, str) or not relative or len(relative) > 4096 or "\x00" in relative:
                raise CleanupError("helper-invalid", "The isolated metadata target failed validation.")
            relative_path = Path(relative)
            if relative_path.is_absolute() or any(part in {"", ".", ".."} for part in relative_path.parts):
                raise CleanupError("helper-invalid", "The isolated metadata target failed validation.")
            root = Path(roots[root_index])
            path = root.joinpath(*relative_path.parts)
            if not self._contained(path):
                raise CleanupError("helper-invalid", "The isolated metadata target escaped its root.")
            public = encoded.get("public")
            root_stat = encoded.get("rootStat")
            item_stat = encoded.get("stat")
            if (
                not isinstance(public, dict)
                or public.get("category") != category
                or not isinstance(public.get("id"), str)
                or len(public.get("id")) != 20
                or any(character not in "0123456789abcdef" for character in public.get("id"))
                or not isinstance(public.get("target"), str)
                or len(public.get("target")) > 4096
                or "\x00" in public.get("target")
                or os.path.isabs(public.get("target"))
                or not isinstance(root_stat, dict)
                or not isinstance(item_stat, dict)
            ):
                raise CleanupError("helper-invalid", "The isolated metadata candidate failed validation.")
            normalized_root_stat = {
                "dev": self._helper_integer(root_stat.get("dev")),
                "ino": self._helper_integer(root_stat.get("ino")),
                "uid": self._helper_integer(root_stat.get("uid")),
            }
            normalized_stat = {
                "dev": self._helper_integer(item_stat.get("dev")),
                "ino": self._helper_integer(item_stat.get("ino")),
                "uid": self._helper_integer(item_stat.get("uid")),
                "mode": self._helper_integer(item_stat.get("mode")),
                "size": self._helper_integer(item_stat.get("size")),
                "mtimeNs": self._helper_integer(item_stat.get("mtimeNs")),
                "treeBytes": self._helper_integer(item_stat.get("treeBytes")),
                "treeItems": self._helper_integer(item_stat.get("treeItems"), minimum=1),
                "treeNewestMtimeNs": self._helper_integer(item_stat.get("treeNewestMtimeNs")),
            }
            if (
                normalized_root_stat["uid"] != self.uid
                or normalized_stat["uid"] != self.uid
                or not (stat.S_ISREG(normalized_stat["mode"]) or stat.S_ISDIR(normalized_stat["mode"]))
                or public.get("target") != self._relative_label(path)
                or public.get("id") != _digest(
                    category,
                    public.get("target"),
                    normalized_stat["dev"],
                    normalized_stat["ino"],
                    normalized_stat["size"],
                    normalized_stat["mtimeNs"],
                )[:20]
                or self._helper_integer(public.get("bytes")) != normalized_stat["treeBytes"]
                or self._helper_integer(public.get("itemCount"), minimum=1) != normalized_stat["treeItems"]
                or self._helper_integer(public.get("score")) > 100
                or public.get("riskClass") != CATEGORY_DEFINITIONS[category]["riskClass"]
                or public.get("actionClass") not in {
                    "review-only",
                    "empty-trash-separate",
                    "rebuildable-delete",
                    "trash",
                }
                or public.get("confidence") not in {"low", "medium", "high"}
                or not isinstance(public.get("reason"), str)
                or len(public.get("reason")) > 4096
                or not isinstance(public.get("factors"), dict)
            ):
                raise CleanupError("helper-invalid", "The isolated metadata ownership failed validation.")
            safe_public = copy.deepcopy(public)
            if safe_public["actionClass"] != "empty-trash-separate":
                safe_public.update(
                    {
                        "actionClass": "review-only",
                        "reversibility": "no-action-review-only",
                        "executionState": "isolated-review-only",
                    }
                )
            imported.append(
                {
                    "public": safe_public,
                    "path": path,
                    "root": root,
                    "relativeToRoot": relative,
                    "rootStat": normalized_root_stat,
                    "stat": normalized_stat,
                }
            )
        return imported

    def _invoke_review_helper(self, category, timeout_seconds, cancel):
        if self._review_helper_runner is not None:
            payload = self._review_helper_runner(category, timeout_seconds, cancel)
            if not isinstance(payload, dict):
                raise CleanupError("helper-invalid", "The isolated metadata helper returned an invalid result.")
            return payload
        command = self._review_helper_command
        if (
            not command
            or len(command) > 4
            or any(not isinstance(value, str) or not value for value in command)
            or not os.path.isabs(command[0])
            or not os.access(command[0], os.X_OK)
        ):
            raise CleanupError("helper-unavailable", "The bounded metadata helper is unavailable.")
        request = json.dumps(
            {"schemaVersion": REVIEW_HELPER_SCHEMA_VERSION, "category": category},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        process = None
        try:
            process = subprocess.Popen(
                list(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
            )
            process.stdin.write(request)
            process.stdin.close()
            process.stdin = None
            started = self.monotonic()
            output = b""
            while True:
                if cancel.is_set():
                    raise CleanupError("cancelled", "Analysis was cancelled.")
                remaining = timeout_seconds - max(0.0, self.monotonic() - started)
                if remaining <= 0:
                    raise CleanupError("helper-time-limit", "A category exceeded its isolated metadata time slice.")
                try:
                    output, _stderr = process.communicate(timeout=min(0.2, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
            if process.returncode != 0 or len(output) > MAX_HELPER_OUTPUT_BYTES:
                raise CleanupError("helper-invalid", "The isolated metadata helper failed safely.")
            try:
                payload = json.loads(output.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise CleanupError("helper-invalid", "The isolated metadata helper returned an invalid result.") from error
            if not isinstance(payload, dict):
                raise CleanupError("helper-invalid", "The isolated metadata helper returned an invalid result.")
            return payload
        except CleanupError:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            raise
        except (OSError, subprocess.SubprocessError) as error:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            raise CleanupError("helper-unavailable", "The isolated metadata helper failed safely.") from error

    @staticmethod
    def _partial_helper_category(category, detail):
        definition = CATEGORY_DEFINITIONS[category]
        return {
            "id": category,
            "label": definition["label"],
            "state": "partial-review-only",
            "riskClass": definition["riskClass"],
            "actionClass": "review-only",
            "targetCount": 0,
            "bytes": 0,
            "excludedCount": 1,
            "detail": definition["semantics"] + " " + detail,
            "executableCount": 0,
        }

    def start_analysis(self, options=None):
        normalized = self._analysis_options(options)
        if not self._supported():
            return {
                "schemaVersion": SCHEMA_VERSION,
                "state": "unsupported",
                "detail": "Cleanup & Speed requires current-user, non-root macOS execution.",
            }
        key = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        now_mono = self.monotonic()
        with self._lock:
            if self._analysis_cache is not None and self._analysis_cache["key"] == key:
                age = max(0.0, now_mono - self._analysis_cache["completedMono"])
                if age <= self.cache_ttl_seconds:
                    result = copy.deepcopy(self._analysis_cache["result"])
                    result.update({"cached": True, "cacheAgeSeconds": round(age, 3), "stale": False})
                    return result
            if self._analysis_inflight is not None and self._analysis_inflight["state"] == "running":
                return {
                    "schemaVersion": SCHEMA_VERSION,
                    "state": "running",
                    "jobId": self._analysis_inflight["jobId"],
                    "reusedInFlight": True,
                    "scanStartedAutomatically": False,
                }
            job_id = secrets.token_hex(10)
            job = {
                "jobId": job_id,
                "state": "running",
                "cancel": threading.Event(),
                "options": normalized,
                "key": key,
                "startedAt": _iso(self.clock()),
                "result": None,
            }
            self._analysis_inflight = job
            self._analysis_jobs[job_id] = job
            threading.Thread(target=self._analysis_worker_entry, args=(job,), name="ke-cleanup-analysis", daemon=True).start()
            return {
                "schemaVersion": SCHEMA_VERSION,
                "state": "running",
                "jobId": job_id,
                "reusedInFlight": False,
                "scanStartedAutomatically": False,
            }

    def analysis_status(self, job_id):
        with self._lock:
            job = self._analysis_jobs.get(str(job_id))
            if job is None:
                return {"schemaVersion": SCHEMA_VERSION, "state": "not-found"}
            if job["result"] is not None:
                result = copy.deepcopy(job["result"])
                analysis = self._analysis_internal.get(str(result.get("analysisId")))
                if result.get("state") == "complete" and analysis is not None:
                    age = max(0.0, self.monotonic() - analysis["completedMono"])
                    result["cacheAgeSeconds"] = round(age, 3)
                    if age > self.cache_ttl_seconds:
                        result.update(
                            {
                                "state": "stale",
                                "sourceState": "complete",
                                "stale": True,
                                "actionable": False,
                                "detail": "The completed analysis exceeded its independent cache TTL; analyze storage again before review.",
                            }
                        )
                return result
            return {"schemaVersion": SCHEMA_VERSION, "state": job["state"], "jobId": job["jobId"], "startedAt": job["startedAt"]}

    def cancel_analysis(self, job_id):
        with self._lock:
            job = self._analysis_jobs.get(str(job_id))
            if job is None or job["state"] != "running":
                return {"ok": False, "state": "not-running"}
            job["cancel"].set()
        return {"ok": True, "state": "cancelling"}

    def _revalidate_reveal_candidate(self, item):
        context = None
        parent_fd = None
        try:
            context = self._open_root_context(item["root"])
            root_metadata = context["stat"]
            expected_root = item["rootStat"]
            if (
                root_metadata.st_dev != expected_root["dev"]
                or root_metadata.st_ino != expected_root["ino"]
                or root_metadata.st_uid != expected_root["uid"]
            ):
                raise CleanupError("reveal-target-changed", "A reviewed item changed; scan again before revealing it.")
            parts = Path(item["relativeToRoot"]).parts
            if not parts:
                raise CleanupError("reveal-target-unsafe", "A cleanup root cannot be revealed as a candidate.")
            parent_fd = self._open_parent_chain(context["rootFd"], parts[:-1])
            metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if not self._matches_expected(metadata, item["stat"]):
                raise CleanupError("reveal-target-changed", "A reviewed item changed; scan again before revealing it.")
            if self._protection_reason(item["path"], metadata) is not None:
                raise CleanupError("reveal-target-protected", "A reviewed item is now protected; it was not revealed.")
            return Path(item["path"])
        except CleanupError:
            raise
        except (OSError, ValueError) as error:
            raise CleanupError("reveal-target-changed", "A reviewed item changed; scan again before revealing it.") from error
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
            self._close_context(context)

    def reveal_candidates(self, analysis_id, item_ids):
        """Reveal exact reviewed identities in Finder; never mutate a candidate."""
        self._require_supported()
        if (
            not isinstance(item_ids, list)
            or not item_ids
            or len(item_ids) > MAX_REVEAL_ITEMS
            or any(not isinstance(value, str) or not value for value in item_ids)
            or len(set(item_ids)) != len(item_ids)
        ):
            raise CleanupError(
                "invalid-reveal-selection",
                f"Select between 1 and {MAX_REVEAL_ITEMS} distinct reviewed items.",
            )
        with self._lock:
            analysis = self._analysis_internal.get(str(analysis_id))
            if analysis is None:
                raise CleanupError("analysis-not-found", "The scan is no longer available; scan again.")
            if analysis.get("state") not in {"complete", "partial"}:
                raise CleanupError("analysis-incomplete", "Wait for a completed or partial scan before revealing items.")
            age = max(0.0, self.monotonic() - analysis["completedMono"])
            if age > self.cache_ttl_seconds:
                raise CleanupError("analysis-expired", "The scan expired; scan again before revealing items.")
            selected = [
                (item_id, copy.deepcopy(analysis["candidates"].get(item_id)))
                for item_id in item_ids
            ]
        valid_paths = []
        skipped = []
        for item_id, item in selected:
            if item is None:
                skipped.append({"id": item_id, "reason": "not-in-analysis"})
                continue
            try:
                valid_paths.append(self._revalidate_reveal_candidate(item))
            except CleanupError as error:
                skipped.append({"id": item_id, "reason": error.code})
        if not valid_paths:
            return {
                "schemaVersion": SCHEMA_VERSION,
                "ok": False,
                "state": "needs-rescan",
                "revealedCount": 0,
                "skippedCount": len(skipped),
                "skipped": skipped,
                "detail": "No selected item still matched the reviewed identity. Scan again.",
            }
        try:
            outcome = self._reveal_handler(tuple(valid_paths))
        except Exception as error:
            raise CleanupError("finder-unavailable", "Finder could not reveal the reviewed selection.") from error
        revealed_count = (
            max(0, min(len(valid_paths), outcome))
            if type(outcome) is int
            else len(valid_paths)
        )
        return {
            "schemaVersion": SCHEMA_VERSION,
            "ok": revealed_count > 0,
            "state": "revealed" if revealed_count > 0 else "finder-unavailable",
            "revealedCount": revealed_count,
            "skippedCount": len(skipped),
            "skipped": skipped,
            "detail": (
                f"Finder revealed {revealed_count} reviewed item{'s' if revealed_count != 1 else ''}. Nothing was deleted."
                if revealed_count > 0
                else "Finder did not reveal the reviewed selection."
            ),
        }

    def open_review_destination(self, destination):
        """Open one fixed macOS review destination; arbitrary paths and URLs are rejected."""
        self._require_supported()
        targets = {
            "storage-settings": "x-apple.systempreferences:com.apple.settings.Storage",
            "trash": self.home / ".Trash",
            "downloads": self.home / "Downloads",
        }
        if destination not in targets:
            raise CleanupError("invalid-review-destination", "That review destination is not available.")
        try:
            outcome = self._destination_opener(targets[destination])
        except Exception as error:
            raise CleanupError("review-destination-unavailable", "macOS could not open that review destination.") from error
        return {
            "schemaVersion": SCHEMA_VERSION,
            "ok": outcome is not False,
            "state": "opened" if outcome is not False else "unavailable",
            "destination": destination,
            "detail": "Opened the requested macOS review destination." if outcome is not False else "The requested macOS review destination was unavailable.",
        }

    def _analysis_worker_entry(self, job):
        try:
            if (
                job["options"].get("reviewOnly") is True
                and job["options"].get("duplicateAnalysis") is not True
                and (self._review_helper_command or self._review_helper_runner is not None)
            ):
                self._run_isolated_review_analysis(job)
            else:
                self._run_analysis(job)
        except Exception:
            result = {
                "schemaVersion": SCHEMA_VERSION,
                "state": "failed",
                "jobId": job["jobId"],
                "observedAt": _iso(self.clock()),
                "detail": "Analysis failed softly before an actionable plan could be created.",
                "errorCode": "analysis-internal-error",
                "categories": [],
                "candidates": [],
                "exclusions": [],
                "securityEvents": [],
                "stale": False,
                "cached": False,
                "privacy": self._privacy(job["options"].get("duplicateAnalysis") is True),
            }
            with self._lock:
                job["state"] = "failed"
                job["result"] = result
                if self._analysis_inflight is job:
                    self._analysis_inflight = None

    def _run_isolated_review_analysis(self, job):
        deadline = self.monotonic() + self.max_scan_seconds
        candidates = []
        categories = []
        exclusions = {}
        security_events = []
        failures = []
        cancelled = False
        assessment = self.performance_assessment()
        for category in job["options"]["categories"]:
            if job["cancel"].is_set():
                cancelled = True
                break
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                failures.append((category, "scan-time-limit"))
                exclusions["scan-time-limit"] = exclusions.get("scan-time-limit", 0) + 1
                categories.append(
                    self._partial_helper_category(
                        category,
                        "This category was skipped when the overall bounded review window ended.",
                    )
                )
                continue
            try:
                payload = self._invoke_review_helper(
                    category,
                    min(REVIEW_HELPER_CATEGORY_SECONDS, remaining),
                    job["cancel"],
                )
                if payload.get("schemaVersion") != REVIEW_HELPER_SCHEMA_VERSION or payload.get("category") != category:
                    raise CleanupError("helper-invalid", "The isolated metadata helper returned an invalid result.")
                child_result = payload.get("result")
                if not isinstance(child_result, dict) or child_result.get("state") not in {"complete", "partial"}:
                    raise CleanupError("helper-invalid", "The isolated metadata helper returned an invalid result.")
                imported = self._import_review_helper_candidates(category, payload)
                candidate_ids = {item["public"]["id"] for item in imported}
                if len(candidate_ids) != len(imported):
                    raise CleanupError("helper-invalid", "The isolated metadata helper returned duplicate identities.")
                candidates.extend(imported)
                child_rows = [
                    row for row in (child_result.get("categories") or [])
                    if isinstance(row, dict) and row.get("id") == category
                ]
                if len(child_rows) != 1:
                    raise CleanupError("helper-invalid", "The isolated metadata category summary was invalid.")
                category_row = copy.deepcopy(child_rows[0])
                category_row["label"] = CATEGORY_DEFINITIONS[category]["label"]
                category_row["riskClass"] = CATEGORY_DEFINITIONS[category]["riskClass"]
                if not isinstance(category_row.get("detail"), str) or len(category_row["detail"]) > 4096:
                    raise CleanupError("helper-invalid", "The isolated metadata category detail was invalid.")
                for field in ("targetCount", "bytes", "excludedCount", "executableCount"):
                    category_row[field] = self._helper_integer(category_row.get(field))
                if (
                    category_row["targetCount"] != len(imported)
                    or category_row["bytes"] != sum(item["public"]["bytes"] for item in imported)
                ):
                    raise CleanupError("helper-invalid", "The isolated metadata category totals were invalid.")
                category_row["actionClass"] = "review-only"
                category_row["executableCount"] = 0
                categories.append(category_row)
                for row in child_result.get("exclusions") or []:
                    if (
                        not isinstance(row, dict)
                        or not isinstance(row.get("reason"), str)
                        or not row["reason"]
                        or len(row["reason"]) > 80
                    ):
                        raise CleanupError("helper-invalid", "The isolated metadata exclusions were invalid.")
                    count = self._helper_integer(row.get("count"), minimum=1)
                    exclusions[row["reason"]] = exclusions.get(row["reason"], 0) + count
                for event in child_result.get("securityEvents") or []:
                    if not isinstance(event, dict):
                        continue
                    security_events.append(
                        {
                            "phase": str(event.get("phase") or "helper")[:64],
                            "category": category,
                            "swapPerformed": event.get("swapPerformed") is True,
                            "outcome": str(event.get("outcome") or "skipped")[:32],
                        }
                    )
                if child_result.get("state") != "complete":
                    failures.append((category, str(child_result.get("errorCode") or "category-partial")))
            except CleanupError as error:
                if error.code == "cancelled" or job["cancel"].is_set():
                    cancelled = True
                    break
                failures.append((category, error.code))
                exclusions[error.code] = exclusions.get(error.code, 0) + 1
                categories.append(
                    self._partial_helper_category(
                        category,
                        "Its isolated helper stopped safely; findings from other categories remain available.",
                    )
                )
        analysis_id = secrets.token_hex(10)
        state = "cancelled" if cancelled else "partial" if failures else "complete"
        result = {
            "schemaVersion": SCHEMA_VERSION,
            "state": state,
            "jobId": job["jobId"],
            "analysisId": analysis_id,
            "observedAt": _iso(self.clock()),
            "categories": categories,
            "candidates": sorted(
                (copy.deepcopy(item["public"]) for item in candidates),
                key=lambda item: (-item["score"], item["id"]),
            ),
            "exclusions": [{"reason": key, "count": value} for key, value in sorted(exclusions.items())],
            "totalCandidateBytes": sum(item["public"]["bytes"] for item in candidates),
            "stale": False,
            "cached": False,
            "scanStartedAutomatically": False,
            "duplicateBytesHashed": False,
            "privacy": self._privacy(False),
            "performanceAssessment": assessment,
            "securityEvents": security_events,
            "reviewOnly": True,
        }
        if state == "partial":
            result.update(
                {
                    "detail": "Some categories exceeded an isolated metadata boundary; available categories remain ranked for review.",
                    "errorCode": "helper-partial",
                }
            )
        elif state == "cancelled":
            result.update({"detail": "Analysis was cancelled.", "errorCode": "cancelled"})
        review_candidates, review_exclusions = self._deduplicate_plan_candidates(candidates)
        review_public = sorted(
            (copy.deepcopy(item["public"]) for item in review_candidates),
            key=lambda item: (-item["score"], -item["bytes"], item["id"]),
        )
        result.update(
            {
                "reviewCandidates": review_public,
                "reviewCandidateCount": len(review_public),
                "reviewCandidateBytes": sum(item["bytes"] for item in review_public),
                "reviewExclusions": review_exclusions,
            }
        )
        with self._lock:
            job["state"] = state
            job["result"] = result
            self._analysis_internal[analysis_id] = {
                "candidates": {item["public"]["id"]: item for item in candidates},
                "result": copy.deepcopy(result),
                "state": state,
                "completedMono": self.monotonic(),
            }
            if state == "complete":
                self._analysis_cache = {
                    "key": job["key"],
                    "completedMono": self.monotonic(),
                    "result": copy.deepcopy(result),
                }
            if self._analysis_inflight is job:
                self._analysis_inflight = None

    def _run_analysis(self, job):
        deadline = self.monotonic() + self.max_scan_seconds
        candidates = []
        exclusions = {}
        security_events = []
        categories = []
        assessment = self.performance_assessment()
        disk_pressure = assessment["storage"]["state"]
        error = None
        scan_budget = {"roots": 0, "items": 0, "bytes": 0}
        try:
            for category, definition in CATEGORY_DEFINITIONS.items():
                if category not in job["options"]["categories"]:
                    continue
                roots = sorted(
                    self._category_roots.get(category, []),
                    key=lambda value: (len(Path(value).parts), os.fspath(value)),
                )
                category_candidates = []
                category_excluded = 0
                opened_roots = []
                for root in roots:
                    scan_budget["roots"] += 1
                    if scan_budget["roots"] > MAX_SCAN_ROOTS:
                        raise CleanupError("scan-limit", "Analysis reached its bounded root limit.")
                    if any(
                        root == prior or (
                            len(Path(root).parts) > len(Path(prior).parts)
                            and self._is_relative_to(root, prior)
                        )
                        for prior in opened_roots
                    ):
                        exclusions["overlapping-analysis-root"] = exclusions.get("overlapping-analysis-root", 0) + 1
                        category_excluded += 1
                        continue
                    if job["cancel"].is_set():
                        raise CleanupError("cancelled", "Analysis was cancelled.")
                    context = None
                    try:
                        context = self._open_root_context(root)
                    except FileNotFoundError:
                        continue
                    except CleanupError as root_error:
                        reason = root_error.code
                        exclusions[reason] = exclusions.get(reason, 0) + 1
                        security_events.append({"phase": "root", "category": category, "swapPerformed": reason == "analysis-path-swap", "outcome": "skipped" if job["options"].get("reviewOnly") and reason == "analysis-path-swap" else "blocked"})
                        if job["options"].get("reviewOnly") and reason == "analysis-path-swap":
                            category_excluded += 1
                            continue
                        if reason in {"analysis-path-swap", "platform-safety-unavailable"}:
                            raise
                        continue
                    except OSError as root_error:
                        exclusions["analysis-path-swap"] = exclusions.get("analysis-path-swap", 0) + 1
                        security_events.append({"phase": "root", "category": category, "swapPerformed": True, "outcome": "skipped" if job["options"].get("reviewOnly") else "blocked"})
                        if job["options"].get("reviewOnly"):
                            category_excluded += 1
                            continue
                        raise CleanupError(
                            "analysis-path-swap",
                            "An analysis root changed during descriptor verification.",
                        ) from root_error
                    try:
                        opened_roots.append(root)
                        root_metadata = context["stat"]
                        root_reason = self._protection_reason(root, root_metadata)
                        if root_reason and category not in {"old-installers", "downloads-large", "downloads-duplicates"}:
                            exclusions[root_reason] = exclusions.get(root_reason, 0) + 1
                            continue
                        try:
                            entries = os.scandir(context["rootFd"])
                        except OSError as root_error:
                            exclusions["unreadable-root"] = exclusions.get("unreadable-root", 0) + 1
                            category_excluded += 1
                            if job["options"].get("reviewOnly"):
                                continue
                            raise CleanupError(
                                "analysis-unreadable",
                                "An analysis root could not be enumerated safely.",
                            ) from root_error
                        try:
                            for entry in entries:
                                entry_name = entry.name
                                if entry_name == STAGING_NAME:
                                    continue
                                self._consume_scan_budget(scan_budget, items=1)
                                if self.monotonic() > deadline:
                                    raise CleanupError("scan-time-limit", "Analysis reached its time limit.")
                                try:
                                    entry_metadata = os.stat(entry_name, dir_fd=context["rootFd"], follow_symlinks=False)
                                except OSError as metadata_error:
                                    exclusions["unreadable-metadata"] = exclusions.get("unreadable-metadata", 0) + 1
                                    category_excluded += 1
                                    if job["options"].get("reviewOnly"):
                                        continue
                                    raise CleanupError(
                                        "analysis-unreadable",
                                        "An analysis entry could not be verified safely.",
                                    ) from metadata_error
                                self._consume_scan_budget(
                                    scan_budget,
                                    byte_count=max(0, int(entry_metadata.st_size)),
                                )
                                try:
                                    internal, excluded = self._candidate_for(
                                        category,
                                        root,
                                        context["rootFd"],
                                        entry_name,
                                        entry_metadata,
                                        root_metadata,
                                        job["cancel"],
                                        deadline,
                                        job["options"],
                                        disk_pressure,
                                        scan_budget,
                                    )
                                except CleanupError as entry_error:
                                    if entry_error.code in {"cancelled", "scan-limit", "scan-time-limit"}:
                                        raise
                                    exclusions[entry_error.code] = exclusions.get(entry_error.code, 0) + 1
                                    category_excluded += 1
                                    if job["options"].get("reviewOnly") and entry_error.code in {"analysis-path-swap", "analysis-unreadable"}:
                                        if entry_error.code == "analysis-path-swap":
                                            security_events.append({"phase": "candidate-or-nested", "category": category, "swapPerformed": True, "outcome": "skipped"})
                                        continue
                                    if entry_error.code == "analysis-unreadable":
                                        raise
                                    if entry_error.code in {"analysis-path-swap", "platform-safety-unavailable"}:
                                        security_events.append({"phase": "candidate-or-nested", "category": category, "swapPerformed": entry_error.code == "analysis-path-swap", "outcome": "blocked"})
                                        raise
                                    continue
                                if excluded:
                                    exclusions[excluded] = exclusions.get(excluded, 0) + 1
                                    category_excluded += 1
                                if internal is not None:
                                    category_candidates.append(internal)
                                    if category != "downloads-duplicates":
                                        candidates.append(internal)
                        finally:
                            entries.close()
                    finally:
                        if context is not None:
                            os.close(context["rootFd"])
                            os.close(context["parentFd"])
                if category == "downloads-duplicates":
                    groups = {}
                    for item in category_candidates:
                        key = (item.get("duplicateDigest"), item["public"]["bytes"])
                        groups.setdefault(key, []).append(item)
                    category_candidates = [
                        item
                        for group in groups.values()
                        if len(group) > 1
                        for item in group
                    ]
                    for item in category_candidates:
                        item.pop("duplicateDigest", None)
                        item["public"]["reason"] = (
                            "An explicitly requested bounded byte comparison matched another Download; both remain review-only."
                        )
                    candidates.extend(category_candidates)
                state = "available" if roots else "not-available"
                if definition["actionClass"] in {"review-only", "empty-trash-separate"}:
                    state = "review-only" if roots else "not-available"
                if definition["actionClass"] in {"rebuildable-delete", "trash"} and not self._identity_mutations_available():
                    state = "review-only" if roots else "not-available"
                if category == "old-installers" and not self._trash_identity_available():
                    state = "review-only" if roots else "not-available"
                effective_action = definition["actionClass"]
                detail = definition["semantics"]
                if definition["actionClass"] in {"rebuildable-delete", "trash"} and not self._identity_mutations_available():
                    effective_action = "review-only"
                    detail += " Automatic mutation is unavailable in this build because the reviewed identity cannot be preserved atomically."
                elif category == "old-installers" and not self._trash_identity_available():
                    effective_action = "review-only"
                    detail += " Identity-preserving platform Trash is unavailable, so no automatic action is offered."
                categories.append(
                    {
                        "id": category,
                        "label": definition["label"],
                        "state": state,
                        "riskClass": definition["riskClass"],
                        "actionClass": effective_action,
                        "targetCount": len(category_candidates),
                        "bytes": sum(item["public"]["bytes"] for item in category_candidates),
                        "excludedCount": category_excluded,
                        "detail": detail,
                        "executableCount": sum(item["public"]["actionClass"] in {"rebuildable-delete", "trash"} for item in category_candidates),
                    }
                )
        except CleanupError as caught:
            error = caught
        analysis_id = secrets.token_hex(10)
        if error is not None:
            summarized = {row["id"] for row in categories}
            for category, definition in CATEGORY_DEFINITIONS.items():
                partial_items = [item for item in candidates if item["public"]["category"] == category]
                if not partial_items or category in summarized:
                    continue
                categories.append(
                    {
                        "id": category,
                        "label": definition["label"],
                        "state": "partial-review-only",
                        "riskClass": definition["riskClass"],
                        "actionClass": "review-only",
                        "targetCount": len(partial_items),
                        "bytes": sum(item["public"]["bytes"] for item in partial_items),
                        "excludedCount": 0,
                        "detail": definition["semantics"] + " This category is partial because the bounded scan stopped before the category completed.",
                        "executableCount": 0,
                    }
                )
            result = {
                "schemaVersion": SCHEMA_VERSION,
                "state": "cancelled" if error.code == "cancelled" else "partial",
                "jobId": job["jobId"],
                "analysisId": analysis_id,
                "observedAt": _iso(self.clock()),
                "detail": error.public_message,
                "errorCode": error.code,
                "categories": categories,
                "candidates": [copy.deepcopy(item["public"]) for item in candidates],
                "exclusions": [{"reason": key, "count": value} for key, value in sorted(exclusions.items())],
                "stale": False,
                "cached": False,
                "privacy": self._privacy(job["options"].get("duplicateAnalysis") is True),
                "performanceAssessment": assessment,
                "securityEvents": security_events,
            }
        else:
            result = {
                "schemaVersion": SCHEMA_VERSION,
                "state": "complete",
                "jobId": job["jobId"],
                "analysisId": analysis_id,
                "observedAt": _iso(self.clock()),
                "categories": categories,
                "candidates": sorted((copy.deepcopy(item["public"]) for item in candidates), key=lambda item: (-item["score"], item["id"])),
                "exclusions": [{"reason": key, "count": value} for key, value in sorted(exclusions.items())],
                "totalCandidateBytes": sum(item["public"]["bytes"] for item in candidates),
                "stale": False,
                "cached": False,
                "scanStartedAutomatically": False,
                "duplicateBytesHashed": bool(job["options"]["duplicateAnalysis"]),
                "privacy": self._privacy(job["options"].get("duplicateAnalysis") is True),
                "performanceAssessment": assessment,
                "securityEvents": security_events,
            }
        review_candidates, review_exclusions = self._deduplicate_plan_candidates(candidates)
        review_public = sorted(
            (copy.deepcopy(item["public"]) for item in review_candidates),
            key=lambda item: (-item["score"], -item["bytes"], item["id"]),
        )
        result.update(
            {
                "reviewOnly": bool(job["options"].get("reviewOnly")),
                "reviewCandidates": review_public,
                "reviewCandidateCount": len(review_public),
                "reviewCandidateBytes": sum(item["bytes"] for item in review_public),
                "reviewExclusions": review_exclusions,
                "totalCandidateBytes": sum(item["public"]["bytes"] for item in candidates),
                "scanStartedAutomatically": False,
            }
        )
        with self._lock:
            job["state"] = result["state"]
            job["result"] = result
            self._analysis_internal[analysis_id] = {
                "candidates": {item["public"]["id"]: item for item in candidates},
                "result": copy.deepcopy(result),
                "state": result["state"],
                "completedMono": self.monotonic(),
            }
            if result["state"] == "complete":
                self._analysis_cache = {"key": job["key"], "completedMono": self.monotonic(), "result": copy.deepcopy(result)}
            if self._analysis_inflight is job:
                self._analysis_inflight = None

    def _plan_public_digest(self, plan):
        material = copy.deepcopy(plan)
        material.pop("planDigest", None)
        return _digest(json.dumps(material, sort_keys=True, separators=(",", ":")))

    @staticmethod
    def _plan_action_rank(item):
        action = item["public"].get("actionClass")
        return {"review-only": 3, "empty-trash-separate": 3, "trash": 2, "rebuildable-delete": 1}.get(action, 4)

    def _deduplicate_plan_candidates(self, candidates):
        retained = []
        excluded_count = 0
        overlap_ids = set()
        ordered = sorted(
            candidates,
            key=lambda item: (item["public"].get("target") or "", item["public"].get("category") or "", item["public"]["id"]),
        )
        for item in ordered:
            exact_index = None
            for index, prior in enumerate(retained):
                same_identity = (
                    item["stat"]["dev"] == prior["stat"]["dev"]
                    and item["stat"]["ino"] == prior["stat"]["ino"]
                )
                if same_identity or item["path"] == prior["path"]:
                    exact_index = index
                    break
                if self._is_relative_to(item["path"], prior["path"]) or self._is_relative_to(prior["path"], item["path"]):
                    overlap_ids.add(item["public"]["id"])
                    overlap_ids.add(prior["public"]["id"])
            if exact_index is None:
                retained.append(item)
                continue
            prior = retained[exact_index]
            excluded_count += 1
            if self._plan_action_rank(item) > self._plan_action_rank(prior):
                retained[exact_index] = item
        if overlap_ids:
            retained = [item for item in retained if item["public"]["id"] not in overlap_ids]
            excluded_count += len(overlap_ids)
        exclusions = []
        if excluded_count:
            exclusions.append({"reason": "overlapping-or-duplicate-target", "count": excluded_count})
        return retained, exclusions

    def create_plan(self, analysis_id, selected_categories=None):
        self._require_supported()
        with self._lock:
            analysis = self._analysis_internal.get(str(analysis_id))
            if analysis is None:
                raise CleanupError("analysis-not-found", "The analysis is not available.")
            if analysis.get("state") != "complete":
                raise CleanupError(
                    "analysis-incomplete",
                    "Only a complete analysis can authorize an immutable cleanup plan.",
                )
            age = max(0.0, self.monotonic() - analysis["completedMono"])
            if age > self.cache_ttl_seconds:
                raise CleanupError("analysis-expired", "The analysis has expired; analyze storage again.")
            candidates = analysis["candidates"]
            if selected_categories is None:
                categories = set(CATEGORY_DEFINITIONS)
            elif isinstance(selected_categories, list):
                categories = {value for value in selected_categories if value in CATEGORY_DEFINITIONS}
            else:
                raise CleanupError("invalid-selection", "Category selection is invalid.")
            chosen = [item for item in candidates.values() if item["public"]["category"] in categories]
        chosen, plan_exclusions = self._deduplicate_plan_candidates(chosen)
        chosen.sort(key=lambda item: item["public"]["id"])
        if len(chosen) > self.max_plan_items or sum(item["public"]["bytes"] for item in chosen) > self.max_plan_bytes:
            raise CleanupError("plan-limit", "The requested plan exceeds the per-run safety ceiling.")
        plan_id = secrets.token_hex(12)
        observed = float(self.clock())
        expires_wall = observed + self.plan_ttl_seconds
        public = {
            "schemaVersion": SCHEMA_VERSION,
            "state": "review-required",
            "planId": plan_id,
            "analysisId": str(analysis_id),
            "createdAt": _iso(observed),
            "expiresAt": _iso(expires_wall),
            "entries": [copy.deepcopy(item["public"]) for item in chosen],
            "exclusions": copy.deepcopy(analysis["result"].get("exclusions", [])) + plan_exclusions,
            "limits": {"maxItems": self.max_plan_items, "maxBytes": self.max_plan_bytes},
            "confirmationRequired": "CLEAN",
            "emptyTrashBundled": False,
            "immutable": True,
        }
        public["planDigest"] = self._plan_public_digest(public)
        internal = {
            "public": copy.deepcopy(public),
            "entries": {item["public"]["id"]: item for item in chosen},
            "createdMono": self.monotonic(),
            "expiresMono": self.monotonic() + self.plan_ttl_seconds,
            "consumed": False,
        }
        with self._lock:
            self._plans[plan_id] = internal
        return copy.deepcopy(public)

    def _validate_execution_locked(self, plan_id, plan_digest, selected_ids, confirmation, *, consume):
        if confirmation != "CLEAN":
            raise CleanupError("confirmation-required", "Type CLEAN exactly to authorize the reviewed selection.")
        if not isinstance(selected_ids, list) or not selected_ids or any(not isinstance(value, str) for value in selected_ids):
            raise CleanupError("invalid-selection", "Select at least one reviewed plan item.")
        if len(set(selected_ids)) != len(selected_ids):
            raise CleanupError("invalid-selection", "Duplicate plan selections are not accepted.")
        internal = self._plans.get(str(plan_id))
        if internal is None:
            raise CleanupError("plan-not-found", "The cleanup plan is not available.")
        if internal.get("consumed"):
            raise CleanupError("plan-consumed", "This immutable cleanup plan has already been consumed.")
        if self.monotonic() > internal["expiresMono"]:
            raise CleanupError("plan-expired", "The cleanup plan expired; review a new plan.")
        expected = self._plan_public_digest(internal["public"])
        if plan_digest != expected or internal["public"].get("planDigest") != expected:
            raise CleanupError("plan-digest-mismatch", "The cleanup plan no longer matches the reviewed preview.")
        entries = []
        for item_id in selected_ids:
            item = internal["entries"].get(item_id)
            if item is None:
                raise CleanupError("invalid-selection", "A selected item is not in the current cleanup plan.")
            if item["public"]["actionClass"] not in {"rebuildable-delete", "trash"}:
                raise CleanupError("review-only", "Review-only categories cannot be executed by Cleanup.")
            entries.append(item)
        total_bytes = sum(item["public"]["bytes"] for item in entries)
        if len(entries) > self.max_plan_items or total_bytes > self.max_plan_bytes:
            raise CleanupError("plan-limit", "The selected work exceeds the per-run safety ceiling.")
        if consume:
            internal["consumed"] = True
        return internal, entries

    def _validate_execution(self, plan_id, plan_digest, selected_ids, confirmation):
        with self._lock:
            return self._validate_execution_locked(
                plan_id,
                plan_digest,
                selected_ids,
                confirmation,
                consume=False,
            )

    def start_execution(self, plan_id, plan_digest, selected_ids, confirmation):
        self._require_supported()
        run_id = secrets.token_hex(12)
        with self._lock:
            if any(row["state"] in {"running", "cancelling"} for row in self._execution_jobs.values()):
                raise CleanupError("cleanup-locked", "Another cleanup run is already active.")
            internal, entries = self._validate_execution_locked(
                plan_id,
                plan_digest,
                selected_ids,
                confirmation,
                consume=True,
            )
            job = {
                "runId": run_id,
                "state": "running",
                "cancel": threading.Event(),
                "result": None,
                "planId": str(plan_id),
                "planDigest": str(plan_digest),
                "entries": entries,
                "plan": internal,
                "startedAt": _iso(self.clock()),
            }
            self._execution_jobs[run_id] = job
        threading.Thread(target=self._execution_worker_entry, args=(job,), name="ke-cleanup-execution", daemon=True).start()
        return {"schemaVersion": SCHEMA_VERSION, "state": "running", "runId": run_id, "planId": str(plan_id)}

    def execution_status(self, run_id):
        with self._lock:
            job = self._execution_jobs.get(str(run_id))
            if job is None:
                return {"schemaVersion": SCHEMA_VERSION, "state": "not-found"}
            if job["result"] is not None:
                return copy.deepcopy(job["result"])
            return {
                "schemaVersion": SCHEMA_VERSION,
                "state": job["state"],
                "runId": job["runId"],
                "startedAt": job["startedAt"],
                "phase": job.get("phase", "starting"),
                "completedCount": int(job.get("completedCount", 0)),
                "currentIndex": job.get("currentIndex"),
                "totalCount": int(job.get("totalCount", len(job.get("entries") or []))),
            }

    def cancel_execution(self, run_id):
        with self._lock:
            job = self._execution_jobs.get(str(run_id))
            if job is None or job["state"] != "running":
                return {"ok": False, "state": "not-running"}
            job["state"] = "cancelling"
            job["cancel"].set()
        return {"ok": True, "state": "cancelling"}

    def _execution_worker_entry(self, job):
        try:
            self._run_execution(job)
        except Exception:
            result = {
                "schemaVersion": SCHEMA_VERSION,
                "state": "failed",
                "runId": job["runId"],
                "planId": job["planId"],
                "finishedAt": _iso(self.clock()),
                "outcomes": [],
                "completedCount": 0,
                "untouchedCount": None,
                "estimatedLogicalBytesRemoved": None,
                "movedToTrashLogicalBytes": None,
                "observedFreeSpaceDeltaBytes": None,
                "speedOutcome": {
                    "state": "not-established",
                    "measured": False,
                    "claim": "No system speed improvement was established.",
                },
                "detail": "Cleanup stopped at a fail-soft terminal boundary; consult recovery before another run.",
            }
            with self._lock:
                job["state"] = "failed"
                job["result"] = result

    def _journal_hook(self, phase, path):
        if self._journal_swap_hook is not None:
            self._journal_swap_hook(phase, Path(path))

    @staticmethod
    def _close_context(context):
        if not context:
            return
        for key in ("rootFd", "parentFd"):
            descriptor = context.get(key)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                context[key] = None

    @staticmethod
    def _write_all(descriptor, data):
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written

    @staticmethod
    def _fsync_fd(descriptor):
        try:
            os.fsync(descriptor)
        except OSError as error:
            raise CleanupError("journal-unavailable", "A durable cleanup phase boundary could not be recorded.") from error

    def _open_state_root(self, *, create):
        try:
            relative = self.state_root.relative_to(self.home)
        except ValueError as error:
            raise CleanupError("journal-unavailable", "Cleanup state must remain inside the current-user home.") from error
        if not relative.parts:
            raise CleanupError("journal-unavailable", "The home directory cannot be used as cleanup state storage.")
        self._journal_hook("before-state-root-open", self.state_root)
        try:
            current = os.open(os.fspath(self.home), self._nofollow_flags(directory=True))
        except OSError as error:
            raise CleanupError("journal-unavailable", "Cleanup state storage cannot be opened safely.") from error
        root_fd = None
        try:
            for index, component in enumerate(relative.parts):
                if component in {"", ".", ".."} or "/" in component:
                    raise CleanupError("journal-unavailable", "Cleanup state storage has an unsafe component.")
                is_last = index == len(relative.parts) - 1
                try:
                    next_fd = os.open(component, self._nofollow_flags(directory=True), dir_fd=current)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(component, mode=0o700, dir_fd=current)
                    self._fsync_fd(current)
                    next_fd = os.open(component, self._nofollow_flags(directory=True), dir_fd=current)
                metadata = os.fstat(next_fd)
                if metadata.st_uid != os.getuid() or not stat.S_ISDIR(metadata.st_mode):
                    os.close(next_fd)
                    raise CleanupError("journal-unavailable", "Cleanup state storage has unsafe ownership or type.")
                if is_last:
                    parent_fd = current
                    root_fd = next_fd
                    os.fchmod(root_fd, 0o700)
                    self._journal_hook("after-state-root-open", self.state_root)
                    named = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                    if not self._same_identity(metadata, named):
                        raise CleanupError("journal-path-swap", "Cleanup state storage changed during descriptor verification.")
                    return {"rootFd": root_fd, "parentFd": parent_fd, "name": component, "stat": metadata}
                os.close(current)
                current = next_fd
        except Exception:
            if root_fd is not None:
                os.close(root_fd)
            try:
                os.close(current)
            except OSError:
                pass
            raise

    def _open_state_file(self, name, flags, *, create_root, mode=0o600):
        if name not in {"journal.jsonl", "history.jsonl", "cleanup.lock"}:
            raise CleanupError("journal-unavailable", "Cleanup state filename is not allowlisted.")
        context = self._open_state_root(create=create_root)
        descriptor = None
        path = self.state_root / name
        try:
            self._journal_hook(f"before-{name}-open", path)
            descriptor = os.open(
                name,
                flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                mode,
                dir_fd=context["rootFd"],
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise CleanupError("journal-unavailable", "Cleanup state file ownership or type is unsafe.")
            os.fchmod(descriptor, 0o600)
            self._journal_hook(f"after-{name}-open", path)
            named = os.stat(name, dir_fd=context["rootFd"], follow_symlinks=False)
            if not self._same_identity(metadata, named):
                raise CleanupError("journal-path-swap", "Cleanup state file changed during descriptor verification.")
            return descriptor, context
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            self._close_context(context)
            raise

    @staticmethod
    def _parse_json_lines(raw, max_rows=None):
        rows = []
        corrupt = False
        lines = raw.splitlines(keepends=True)
        selected = lines if max_rows is None else lines[-max(1, int(max_rows)) :]
        for line in selected:
            if not line.endswith((b"\n", b"\r")):
                corrupt = True
                continue
            body = line.rstrip(b"\r\n")
            if not body:
                corrupt = True
                continue
            try:
                row = json.loads(body)
            except (UnicodeError, json.JSONDecodeError):
                corrupt = True
                continue
            if isinstance(row, dict):
                rows.append(row)
            else:
                corrupt = True
        return rows, corrupt

    @staticmethod
    def _read_bounded_fd(descriptor):
        metadata = os.fstat(descriptor)
        size = max(0, int(metadata.st_size))
        offset = max(0, size - MAX_JOURNAL_BYTES)
        os.lseek(descriptor, offset, os.SEEK_SET)
        remaining = MAX_JOURNAL_BYTES
        chunks = []
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if offset:
            first_break = raw.find(b"\n")
            raw = b"" if first_break < 0 else raw[first_break + 1 :]
        return raw, size > MAX_JOURNAL_BYTES

    def _prepare_bounded_append(self, descriptor, filename, encoded):
        metadata = os.fstat(descriptor)
        if metadata.st_size > MAX_JOURNAL_BYTES:
            raise CleanupError(
                "journal-oversize-unverified",
                "Cleanup state is oversized; further automatic state changes fail closed.",
            )
        if metadata.st_size + len(encoded) > MAX_JOURNAL_BYTES:
            raise CleanupError(
                "journal-capacity-reached" if filename == "journal.jsonl" else "history-capacity-reached",
                "Cleanup state reached its bounded capacity; automatic replacement is disabled to avoid a path race.",
            )
        os.lseek(descriptor, 0, os.SEEK_END)

    def _append_record(self, filename, row):
        encoded = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MAX_JOURNAL_BYTES:
            raise CleanupError("journal-unavailable", "A cleanup state record exceeds its bounded format.")
        descriptor = None
        context = None
        try:
            descriptor, context = self._open_state_file(
                filename,
                os.O_RDWR | os.O_CREAT,
                create_root=True,
            )
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._prepare_bounded_append(descriptor, filename, encoded)
            self._write_all(descriptor, encoded)
            self._fsync_fd(descriptor)
            self._fsync_fd(context["rootFd"])
        except CleanupError:
            raise
        except OSError as error:
            raise CleanupError("journal-unavailable", "Cleanup state could not be written durably.") from error
        finally:
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(descriptor)
            self._close_context(context)

    def _journal(self, row):
        allowed = {
            "entryId", "runId", "itemId", "state", "action", "rootKey", "rootDev", "rootIno",
            "rootUid", "originalRel", "stagingName", "bytes", "dev", "ino", "uid", "mode",
            "size", "mtimeNs", "observedAt",
        }
        safe = {key: value for key, value in row.items() if key in allowed}
        self._append_record("journal.jsonl", safe)

    def _history(self, row):
        allowed = {
            "runId", "itemId", "category", "outcome", "actionClass", "logicalBytesRemoved",
            "movedToTrashLogicalBytes", "swapPerformed", "observedAt", "reason",
        }
        safe = {key: value for key, value in row.items() if key in allowed}
        self._append_record("history.jsonl", safe)

    def _read_records(self, filename):
        descriptor = None
        context = None
        try:
            descriptor, context = self._open_state_file(filename, os.O_RDONLY, create_root=False)
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            raw, oversized = self._read_bounded_fd(descriptor)
            rows, corrupt = self._parse_json_lines(
                raw,
                None if filename == "journal.jsonl" else MAX_HISTORY_ROWS,
            )
            if corrupt:
                return [], oversized, (
                    "journal-corrupt-unverified"
                    if filename == "journal.jsonl"
                    else "history-corrupt-unverified"
                )
            return rows, oversized, None
        except FileNotFoundError:
            return [], False, None
        except CleanupError as error:
            return [], False, error.code
        except OSError:
            return [], False, "journal-unavailable"
        finally:
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(descriptor)
            self._close_context(context)

    @classmethod
    def _open_parent_chain(cls, root_fd, relative_parts):
        current = os.dup(root_fd)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            os.close(current)
            raise CleanupError("platform-safety-unavailable", "No-follow directory operations are unavailable.")
        try:
            for part in relative_parts:
                if part in {"", ".", ".."} or "/" in part:
                    raise CleanupError("path-unsafe", "The target path is not safe.")
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | nofollow | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=current,
                )
                os.close(current)
                current = next_fd
            return current
        except Exception:
            os.close(current)
            raise

    @staticmethod
    def _matches_identity_core(metadata, expected):
        return (
            not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == os.getuid()
            and metadata.st_dev == expected["dev"]
            and metadata.st_ino == expected["ino"]
            and stat.S_IFMT(metadata.st_mode) == expected["mode"]
        )

    @staticmethod
    def _matches_expected(metadata, expected):
        return (
            CleanupService._matches_identity_core(metadata, expected)
            and metadata.st_size == expected["size"]
            and metadata.st_mtime_ns == expected["mtimeNs"]
        )

    def _identity_move_noreplace(
        self,
        source_fd,
        source_name,
        destination_fd,
        destination_name,
        expected,
        *,
        allow_metadata_drift=False,
    ):
        self._require_identity_mutations()
        adapter_expected = copy.deepcopy(expected)
        adapter_expected["allowMetadataDrift"] = bool(allow_metadata_drift)
        try:
            self._identity_mutation_adapter.move_noreplace(
                source_fd,
                source_name,
                destination_fd,
                destination_name,
                adapter_expected,
            )
        except CleanupError:
            raise
        except Exception as error:
            raise CleanupError(
                "identity-mutation-failed-unverified",
                "The identity-conditional move failed before a safe outcome could be established.",
            ) from error
        try:
            moved = os.stat(destination_name, dir_fd=destination_fd, follow_symlinks=False)
        except OSError as error:
            raise CleanupError("path-swap", "The identity-conditional move result could not be verified.") from error
        matches = self._matches_identity_core(moved, expected) if allow_metadata_drift else self._matches_expected(moved, expected)
        if not matches:
            raise CleanupError("path-swap", "The identity-conditional move returned a different object.")

    def _identity_delete(self, parent_fd, name, expected):
        self._require_identity_mutations()
        try:
            self._identity_mutation_adapter.delete_identity(
                parent_fd,
                name,
                copy.deepcopy(expected),
            )
        except CleanupError:
            raise
        except Exception as error:
            raise CleanupError(
                "identity-mutation-failed-unverified",
                "The identity-conditional deletion failed before a safe outcome could be established.",
            ) from error

    def _open_action_context(self, item, cancel, *, invoke_hook):
        if invoke_hook and self._before_action_hook is not None:
            self._before_action_hook(copy.deepcopy(item["public"]), item["path"])
        if cancel.is_set():
            raise CleanupError("cancelled", "Cleanup was cancelled before any action began.")
        root_context = None
        parent_fd = None
        try:
            root_context = self._open_root_context(item["root"])
            root_metadata = root_context["stat"]
            expected_root = item["rootStat"]
            if (
                root_metadata.st_dev != expected_root["dev"]
                or root_metadata.st_ino != expected_root["ino"]
                or root_metadata.st_uid != expected_root["uid"]
            ):
                raise CleanupError("path-swap", "Cleanup stopped because the approved root changed.")
            relative_parts = Path(item["relativeToRoot"]).parts
            if not relative_parts:
                raise CleanupError("path-unsafe", "A cleanup root itself can never be selected.")
            parent_fd = self._open_parent_chain(root_context["rootFd"], relative_parts[:-1])
            name = relative_parts[-1]
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not self._matches_expected(metadata, item["stat"]):
                raise CleanupError("path-swap", "Cleanup stopped because target metadata changed.")
            if self._protection_reason(item["path"], metadata):
                raise CleanupError("target-now-protected", "Cleanup stopped because the target is now protected.")
            tree_bytes, tree_items, newest = self._measure_entry_fd(
                parent_fd,
                name,
                metadata,
                cancel,
                self.monotonic() + min(5.0, self.max_scan_seconds),
                item["path"],
            )
            after_measure = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not self._matches_expected(after_measure, item["stat"]):
                raise CleanupError("path-swap", "Cleanup stopped because the target changed during remeasurement.")
            expected = item["stat"]
            if tree_bytes != expected["treeBytes"] or tree_items != expected["treeItems"] or newest != expected["treeNewestMtimeNs"]:
                raise CleanupError("path-swap", "Cleanup stopped because the target tree changed.")
            writer = self._open_handle_checker(item["path"])
            if writer is True:
                raise CleanupError("active-writer-or-handle", "Cleanup stopped because the target is active.")
            if writer is None:
                raise CleanupError("writer-state-unverified", "Cleanup stopped because writer state is unknown.")
            after_writer = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not self._matches_expected(after_writer, item["stat"]):
                raise CleanupError("path-swap", "Cleanup stopped because the target changed after activity verification.")
            os.fstatvfs(root_context["rootFd"])
            return {
                "root": root_context,
                "parentFd": parent_fd,
                "name": name,
                "metadata": after_writer,
            }
        except CleanupError:
            if parent_fd is not None:
                os.close(parent_fd)
            self._close_context(root_context)
            raise
        except OSError as error:
            if parent_fd is not None:
                os.close(parent_fd)
            self._close_context(root_context)
            raise CleanupError("path-swap", "Cleanup stopped at a descriptor-bound path verification failure.") from error

    def _close_action_context(self, context):
        if not context:
            return
        parent_fd = context.get("parentFd")
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass
            context["parentFd"] = None
        self._close_context(context.get("root"))

    def _open_staging(self, root_fd):
        try:
            os.mkdir(STAGING_NAME, mode=0o700, dir_fd=root_fd)
            self._fsync_fd(root_fd)
        except FileExistsError:
            pass
        staging_fd = os.open(STAGING_NAME, self._nofollow_flags(directory=True), dir_fd=root_fd)
        metadata = os.fstat(staging_fd)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            os.close(staging_fd)
            raise CleanupError("staging-unsafe", "Private cleanup staging is not safe.")
        return staging_fd

    def _stage_item(self, job, item, action):
        self._require_identity_mutations()
        context = self._open_action_context(item, job["cancel"], invoke_hook=True)
        staging_fd = None
        moved = False
        entry_id = _digest(job["runId"], item["public"]["id"])[:24]
        staging_name = entry_id
        root_context = context["root"]
        record = {
            "entryId": entry_id,
            "runId": job["runId"],
            "itemId": item["public"]["id"],
            "state": "prepared",
            "action": action,
            "rootKey": _digest(self._relative_label(item["root"]))[:16],
            "rootDev": item["rootStat"]["dev"],
            "rootIno": item["rootStat"]["ino"],
            "rootUid": item["rootStat"]["uid"],
            "originalRel": item["relativeToRoot"],
            "stagingName": staging_name,
            "bytes": item["public"]["bytes"],
            "dev": item["stat"]["dev"],
            "ino": item["stat"]["ino"],
            "uid": item["stat"]["uid"],
            "mode": item["stat"]["mode"],
            "size": item["stat"]["size"],
            "mtimeNs": item["stat"]["mtimeNs"],
            "observedAt": _iso(self.clock()),
        }
        try:
            staging_fd = self._open_staging(root_context["rootFd"])
            try:
                os.stat(staging_name, dir_fd=staging_fd, follow_symlinks=False)
                raise CleanupError("staging-collision", "A private staging entry already exists.")
            except FileNotFoundError:
                pass
            self._journal(record)
            self._identity_move_noreplace(
                context["parentFd"],
                context["name"],
                staging_fd,
                staging_name,
                item["stat"],
            )
            moved = True
            self._fsync_fd(context["parentFd"])
            self._fsync_fd(staging_fd)
            moved_metadata = os.stat(staging_name, dir_fd=staging_fd, follow_symlinks=False)
            if not self._matches_expected(moved_metadata, item["stat"]):
                raise CleanupError("path-swap", "Cleanup stopped because staging identity changed.")
            record["state"] = "staged"
            try:
                self._journal(record)
            except Exception:
                try:
                    self._identity_move_noreplace(
                        staging_fd,
                        staging_name,
                        context["parentFd"],
                        context["name"],
                        item["stat"],
                    )
                    moved = False
                    self._fsync_fd(context["parentFd"])
                    self._fsync_fd(staging_fd)
                    restored = dict(record)
                    restored["state"] = "restored"
                    restored["observedAt"] = _iso(self.clock())
                    try:
                        self._journal(restored)
                    except CleanupError:
                        pass
                except CleanupError:
                    recovery = dict(record)
                    recovery["state"] = "recovery-required"
                    recovery["observedAt"] = _iso(self.clock())
                    try:
                        self._journal(recovery)
                    except CleanupError:
                        pass
                raise
            return {
                "action": context,
                "stagingFd": staging_fd,
                "stagingName": staging_name,
                "record": record,
                "item": item,
            }
        except Exception:
            if moved:
                try:
                    current = os.stat(staging_name, dir_fd=staging_fd, follow_symlinks=False)
                    if self._matches_expected(current, item["stat"]):
                        self._identity_move_noreplace(
                            staging_fd,
                            staging_name,
                            context["parentFd"],
                            context["name"],
                            item["stat"],
                        )
                        record["state"] = "restored"
                        record["observedAt"] = _iso(self.clock())
                        try:
                            self._journal(record)
                        except CleanupError:
                            pass
                except (CleanupError, OSError):
                    pass
            if staging_fd is not None:
                os.close(staging_fd)
            self._close_action_context(context)
            raise

    def _close_stage(self, stage):
        if not stage:
            return
        descriptor = stage.get("stagingFd")
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
            stage["stagingFd"] = None
        self._close_action_context(stage.get("action"))

    def _restore_stage_before_irreversible(self, stage):
        item = stage["item"]
        action = stage["action"]
        staging_fd = stage["stagingFd"]
        name = stage["stagingName"]
        current = os.stat(name, dir_fd=staging_fd, follow_symlinks=False)
        if not self._matches_expected(current, item["stat"]):
            raise CleanupError("path-swap", "The private staged target changed before action.")
        try:
            os.stat(action["name"], dir_fd=action["parentFd"], follow_symlinks=False)
            raise CleanupError("restore-target-exists", "The original location changed before staged rollback.")
        except FileNotFoundError:
            pass
        self._identity_move_noreplace(
            staging_fd,
            name,
            action["parentFd"],
            action["name"],
            item["stat"],
        )
        self._fsync_fd(staging_fd)
        self._fsync_fd(action["parentFd"])
        record = dict(stage["record"])
        record["state"] = "restored"
        record["observedAt"] = _iso(self.clock())
        self._journal(record)

    def _stage_and_delete(self, job, item):
        stage = self._stage_item(job, item, "rebuildable-delete")
        deleting_started = False
        try:
            record = dict(stage["record"])
            record["state"] = "deleting"
            record["observedAt"] = _iso(self.clock())
            self._journal(record)
            deleting_started = True
            expected = os.stat(stage["stagingName"], dir_fd=stage["stagingFd"], follow_symlinks=False)
            if not self._matches_expected(expected, item["stat"]):
                raise CleanupError("path-swap", "The staged cleanup target changed before deletion.")
            self._identity_delete(stage["stagingFd"], stage["stagingName"], item["stat"])
            self._fsync_fd(stage["stagingFd"])
            record["state"] = "completed"
            record["observedAt"] = _iso(self.clock())
            self._journal(record)
            return item["public"]["bytes"]
        except Exception:
            if deleting_started:
                record = dict(stage["record"])
                record["state"] = "partial-irreversible"
                record["observedAt"] = _iso(self.clock())
                try:
                    self._journal(record)
                except CleanupError:
                    pass
            else:
                try:
                    self._restore_stage_before_irreversible(stage)
                except CleanupError:
                    pass
            raise
        finally:
            self._close_stage(stage)

    def _verify_staged_for_trash(self, stage):
        item = stage["item"]
        fresh = self._open_root_context(item["root"])
        staging_fd = None
        try:
            expected_root = item["rootStat"]
            root_metadata = fresh["stat"]
            if root_metadata.st_dev != expected_root["dev"] or root_metadata.st_ino != expected_root["ino"]:
                raise CleanupError("path-swap", "The Trash staging root changed.")
            staging_fd = os.open(STAGING_NAME, self._nofollow_flags(directory=True), dir_fd=fresh["rootFd"])
            metadata = os.stat(stage["stagingName"], dir_fd=staging_fd, follow_symlinks=False)
            if not self._matches_expected(metadata, item["stat"]):
                raise CleanupError("path-swap", "The staged Trash target changed before the platform call.")
        except OSError as error:
            raise CleanupError("path-swap", "The staged Trash target could not be reverified.") from error
        finally:
            if staging_fd is not None:
                os.close(staging_fd)
            self._close_context(fresh)

    def _stage_and_trash(self, job, item):
        if not self._trash_identity_available():
            raise CleanupError(
                "trash-unavailable",
                "Identity-preserving macOS Trash support is unavailable; no pathname or raw Trash move was attempted.",
            )
        stage = self._stage_item(job, item, "trash")
        platform_called = False
        try:
            record = dict(stage["record"])
            record["state"] = "trash-inflight"
            record["observedAt"] = _iso(self.clock())
            self._journal(record)
            stage_path = item["root"] / STAGING_NAME / stage["stagingName"]
            if self._before_trash_hook is not None:
                self._before_trash_hook(stage_path, copy.deepcopy(item["public"]))
            self._verify_staged_for_trash(stage)
            platform_called = True
            try:
                receipt = self._trash_adapter.trash_identity(
                    stage["stagingFd"],
                    stage["stagingName"],
                    copy.deepcopy(item["stat"]),
                )
            except CleanupError:
                raise
            except Exception as error:
                raise CleanupError(
                    "trash-failed-unverified",
                    "The identity-preserving Trash adapter failed before a safe outcome could be established.",
                ) from error
            if not isinstance(receipt, dict):
                raise CleanupError("trash-failed-unverified", "The Trash adapter returned no identity receipt.")
            resulting_path = receipt.get("resultingPath")
            resulting_identity = receipt.get("resultingIdentity")
            if not isinstance(resulting_path, str) or not isinstance(resulting_identity, dict):
                raise CleanupError("trash-failed-unverified", "The Trash adapter returned an invalid identity receipt.")
            record["state"] = "trashed"
            record["observedAt"] = _iso(self.clock())
            self._journal(record)
            self._rollback[(job["runId"], item["public"]["id"])] = {
                "receipt": copy.deepcopy(receipt),
                "resultingPath": resulting_path,
                "resultingIdentity": copy.deepcopy(resulting_identity),
                "originalPath": item["path"],
                "root": item["root"],
                "relativeToRoot": item["relativeToRoot"],
                "expected": copy.deepcopy(item["stat"]),
            }
            return item["public"]["bytes"]
        except Exception:
            try:
                self._restore_stage_before_irreversible(stage)
            except (CleanupError, OSError):
                record = dict(stage["record"])
                record["state"] = "recovery-required" if not platform_called else "trash-inflight"
                record["observedAt"] = _iso(self.clock())
                try:
                    self._journal(record)
                except CleanupError:
                    pass
            raise
        finally:
            self._close_stage(stage)

    def _storage_snapshot(self):
        descriptor = None
        try:
            descriptor = os.open(os.fspath(self.home), self._nofollow_flags(directory=True))
            metadata = os.fstatvfs(descriptor)
            free = int(metadata.f_bavail * metadata.f_frsize)
            total = int(metadata.f_blocks * metadata.f_frsize)
            ratio = free / total if total > 0 else None
            state = "unknown" if ratio is None else "critical" if ratio < 0.05 else "attention" if ratio < 0.15 else "observed"
            return {"state": state, "freeBytes": free, "totalBytes": total}
        except OSError:
            return {"state": "unknown", "freeBytes": None, "totalBytes": None}
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _safe_probe(self):
        try:
            value = self._performance_probe()
        except Exception:
            return {"available": False, "latencyMs": None}
        return value if isinstance(value, dict) else {"available": False, "latencyMs": None}

    def _record_history_soft(self, job, outcome):
        try:
            self._history({"runId": job["runId"], **outcome})
            return True
        except Exception:
            return False

    def _reverify_plan_for_action(self, job, item):
        internal = job.get("plan")
        public = internal.get("public") if isinstance(internal, dict) else None
        entries = internal.get("entries") if isinstance(internal, dict) else None
        if not isinstance(public, dict) or not isinstance(entries, dict):
            raise CleanupError("plan-digest-mismatch", "The immutable cleanup plan is no longer available.")
        expected = self._plan_public_digest(public)
        if public.get("planDigest") != expected or job.get("planDigest") != expected:
            raise CleanupError("plan-digest-mismatch", "The cleanup plan changed after review.")
        if self.monotonic() > internal.get("expiresMono", -1):
            raise CleanupError("plan-expired", "The cleanup plan expired before this action; untouched items remain in place.")
        item_id = item.get("public", {}).get("id") if isinstance(item, dict) else None
        if not isinstance(item_id, str) or entries.get(item_id) is not item:
            raise CleanupError("invalid-selection", "The selected item is no longer bound to the reviewed plan.")

    def _acquire_cleanup_lock(self):
        descriptor = None
        context = None
        try:
            descriptor, context = self._open_state_file(
                "cleanup.lock",
                os.O_RDWR | os.O_CREAT,
                create_root=True,
            )
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor, context
        except CleanupError:
            if descriptor is not None:
                os.close(descriptor)
            self._close_context(context)
            raise
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            self._close_context(context)
            raise CleanupError(
                "cleanup-locked",
                "Another cleanup or recovery process holds the exclusive cleanup lock.",
            ) from error

    def _release_cleanup_lock(self, descriptor, context):
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)
        self._close_context(context)

    def _run_execution(self, job):
        outcomes = []
        stopped = False
        cancelled = False
        history_available = True
        cancellation_deferred = False
        pre_probe = self._safe_probe()
        before_storage = self._storage_snapshot()
        before_free = before_storage["freeBytes"]
        lock_fd = None
        lock_context = None
        try:
            lock_fd, lock_context = self._acquire_cleanup_lock()
            for index, item in enumerate(job["entries"]):
                with self._lock:
                    job["phase"] = "reverify"
                    job["currentIndex"] = index + 1
                    job["totalCount"] = len(job["entries"])
                    job["completedCount"] = sum(row["outcome"] in {"moved-to-trash", "deleted-rebuildable"} for row in outcomes)
                if job["cancel"].is_set():
                    cancelled = True
                    break
                try:
                    self._reverify_plan_for_action(job, item)
                    if item["public"]["actionClass"] == "trash":
                        with self._lock:
                            job["phase"] = "platform-trash"
                        logical_removed = self._stage_and_trash(job, item)
                        moved_to_trash = logical_removed
                        outcome_name = "moved-to-trash"
                    else:
                        with self._lock:
                            job["phase"] = "irreversible-delete"
                        logical_removed = self._stage_and_delete(job, item)
                        moved_to_trash = 0
                        outcome_name = "deleted-rebuildable"
                    outcome = {
                        "itemId": item["public"]["id"],
                        "target": item["public"]["target"],
                        "category": item["public"]["category"],
                        "outcome": outcome_name,
                        "actionClass": item["public"]["actionClass"],
                        "logicalBytesRemoved": logical_removed,
                        "movedToTrashLogicalBytes": moved_to_trash,
                        "swapPerformed": False,
                        "reason": "completed-after-descriptor-reverification",
                        "observedAt": _iso(self.clock()),
                    }
                    outcomes.append(outcome)
                    if not self._record_history_soft(job, outcome):
                        history_available = False
                        stopped = True
                        break
                    if job["cancel"].is_set():
                        cancelled = True
                        cancellation_deferred = True
                        break
                except CleanupError as error:
                    if error.code == "cancelled":
                        cancelled = True
                        break
                    swap = error.code in {"path-swap", "journal-path-swap"}
                    outcome = {
                        "itemId": item["public"]["id"],
                        "target": item["public"]["target"],
                        "category": item["public"]["category"],
                        "outcome": "stopped" if swap or error.code in {"active-writer-or-handle", "writer-state-unverified", "target-now-protected"} else "failed",
                        "actionClass": item["public"]["actionClass"],
                        "logicalBytesRemoved": 0,
                        "movedToTrashLogicalBytes": 0,
                        "swapPerformed": swap,
                        "reason": error.code,
                        "observedAt": _iso(self.clock()),
                    }
                    outcomes.append(outcome)
                    history_available = self._record_history_soft(job, outcome) and history_available
                    stopped = True
                    break
                except Exception:
                    outcome = {
                        "itemId": item["public"]["id"],
                        "target": item["public"]["target"],
                        "category": item["public"]["category"],
                        "outcome": "failed-unverified",
                        "actionClass": item["public"]["actionClass"],
                        "logicalBytesRemoved": 0,
                        "movedToTrashLogicalBytes": 0,
                        "swapPerformed": False,
                        "reason": "unexpected-action-failure",
                        "observedAt": _iso(self.clock()),
                    }
                    outcomes.append(outcome)
                    history_available = self._record_history_soft(job, outcome) and history_available
                    stopped = True
                    break
        except CleanupError as error:
            outcomes.append({
                "itemId": None,
                "target": None,
                "category": None,
                "outcome": "failed",
                "actionClass": None,
                "logicalBytesRemoved": 0,
                "movedToTrashLogicalBytes": 0,
                "swapPerformed": error.code in {"path-swap", "journal-path-swap"},
                "reason": error.code,
                "observedAt": _iso(self.clock()),
            })
            stopped = True
        finally:
            self._release_cleanup_lock(lock_fd, lock_context)
        after_storage = self._storage_snapshot()
        after_free = after_storage["freeBytes"]
        post_probe = self._safe_probe()
        before_latency = _finite(pre_probe.get("latencyMs")) if pre_probe.get("available") is True else None
        after_latency = _finite(post_probe.get("latencyMs")) if post_probe.get("available") is True else None
        probe_observed = before_latency is not None and after_latency is not None
        completed_count = sum(row["outcome"] in {"moved-to-trash", "deleted-rebuildable"} for row in outcomes)
        attempted_count = len([row for row in outcomes if row.get("itemId")])
        if cancelled and completed_count == 0:
            result_state = "cancelled"
        elif cancelled or stopped:
            result_state = "partial"
        else:
            result_state = "complete"
        observed_delta = None if before_free is None or after_free is None else after_free - before_free
        result = {
            "schemaVersion": SCHEMA_VERSION,
            "state": result_state,
            "runId": job["runId"],
            "planId": job["planId"],
            "finishedAt": _iso(self.clock()),
            "outcomes": outcomes,
            "completedCount": completed_count,
            "attemptedCount": attempted_count,
            "untouchedCount": max(0, len(job["entries"]) - attempted_count),
            "estimatedLogicalBytesRemoved": sum(row["logicalBytesRemoved"] for row in outcomes),
            "deletedRebuildableLogicalBytes": sum(
                row["logicalBytesRemoved"] for row in outcomes if row["outcome"] == "deleted-rebuildable"
            ),
            "movedToTrashLogicalBytes": sum(row["movedToTrashLogicalBytes"] for row in outcomes),
            "observedFreeSpaceDeltaBytes": observed_delta,
            "freeSpaceMeasurement": "independent-before-after-with-concurrent-filesystem-uncertainty" if observed_delta is not None else "unavailable",
            "storagePressureChange": {
                "before": before_storage["state"],
                "after": after_storage["state"],
                "changed": (
                    before_storage["state"] != after_storage["state"]
                    if "unknown" not in {before_storage["state"], after_storage["state"]}
                    else None
                ),
            },
            "attributedBytesReclaimed": None,
            "trashSpaceReclaimed": False,
            "emptyTrashBundled": False,
            "historyState": "available" if history_available else "unavailable",
            "cancellationDeferredUntilActionBoundary": cancellation_deferred,
            "speedOutcome": {
                "state": "probe-only" if probe_observed else "not-established",
                "measured": probe_observed,
                "beforeLatencyMs": before_latency,
                "afterLatencyMs": after_latency,
                "improvementPercent": None,
                "claim": "A bounded probe was observed, but it is insufficient to establish system performance improvement." if probe_observed else "No system performance improvement was established.",
            },
            "limitations": [
                "Logical bytes removed are estimates and are not exact reclaimed storage for sparse files, clones, hard links, compression, or concurrent filesystem activity.",
                "Items moved to Trash do not reclaim storage until Trash is emptied separately.",
                "Cleanup did not stop processes, change login items, disable services, install updates, reboot, quarantine, or change policy.",
            ],
        }
        with self._lock:
            job["state"] = result["state"]
            job["phase"] = "finished"
            job["completedCount"] = completed_count
            job["totalCount"] = len(job["entries"])
            job["result"] = result

    def rollback_trash_item(self, run_id, item_id, confirmation):
        self._require_supported()
        if confirmation != "RESTORE":
            raise CleanupError("confirmation-required", "Type RESTORE exactly to restore this Trash item.")
        key = (str(run_id), str(item_id))
        record = self._rollback.get(key)
        if record is None or not isinstance(record.get("receipt"), dict) or not isinstance(record.get("expected"), dict):
            raise CleanupError("restore-unavailable", "No identity-verified Trash receipt is available in this session.")
        lock_fd = None
        lock_context = None
        root = None
        parent_fd = None
        try:
            lock_fd, lock_context = self._acquire_cleanup_lock()
            if not self._trash_identity_available():
                raise CleanupError("restore-unavailable", "Identity-preserving Trash restoration is unavailable in this build.")
            root = self._open_root_context(record["root"])
            parts = Path(record["relativeToRoot"]).parts
            parent_fd = self._open_parent_chain(root["rootFd"], parts[:-1])
            try:
                os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                raise CleanupError("restore-target-unsafe", "The original location is no longer empty.")
            except FileNotFoundError:
                pass
            try:
                self._trash_adapter.restore_identity(
                    copy.deepcopy(record["receipt"]),
                    parent_fd,
                    parts[-1],
                    copy.deepcopy(record["expected"]),
                )
            except CleanupError:
                raise
            except Exception as error:
                raise CleanupError(
                    "restore-failed-unverified",
                    "The identity-preserving restore failed before a safe outcome could be established.",
                ) from error
            restored = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if not self._matches_expected(restored, record["expected"]):
                raise CleanupError("restore-target-unsafe", "The restored item identity could not be verified.")
            self._fsync_fd(parent_fd)
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
            self._close_context(root)
            self._release_cleanup_lock(lock_fd, lock_context)
        del self._rollback[key]
        return {"ok": True, "state": "restored", "runId": str(run_id), "itemId": str(item_id), "target": self._relative_label(record["originalPath"])}

    def empty_trash(self, confirmation):
        self._require_supported()
        if confirmation != "EMPTY TRASH":
            raise CleanupError("strong-confirmation-required", "Empty Trash requires the exact separate confirmation EMPTY TRASH.")
        raise CleanupError("empty-trash-unavailable", "Empty Trash is a separate macOS action and is not available in this build.")

    @staticmethod
    def _latest_journal(rows):
        latest = {}
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("entryId"), str):
                latest[row["entryId"]] = row
        return latest

    def journal_recovery_status(self):
        if not self._supported():
            return {"schemaVersion": SCHEMA_VERSION, "state": "unsupported", "pendingCount": None}
        rows, oversized, error = self._read_records("journal.jsonl")
        if error:
            return {"schemaVersion": SCHEMA_VERSION, "state": "unavailable", "pendingCount": None, "errorCode": error}
        pending_states = {"prepared", "staged", "trash-inflight", "deleting", "partial-irreversible", "recovery-required"}
        pending = [row for row in self._latest_journal(rows).values() if row.get("state") in pending_states]
        if pending:
            state = "recovery-available" if self._identity_mutations_available() else "manual-recovery-required"
        elif oversized:
            state = "journal-oversize-unverified"
        else:
            state = "clean"
        return {"schemaVersion": SCHEMA_VERSION, "state": state, "pendingCount": len(pending), "boundedTailOnly": oversized}

    def recover_journal(self, confirmation):
        self._require_supported()
        if confirmation != "RESTORE":
            raise CleanupError("confirmation-required", "Type RESTORE exactly to recover staged cleanup items.")
        lock_fd = None
        lock_context = None
        try:
            lock_fd, lock_context = self._acquire_cleanup_lock()
            self._require_identity_mutations()
            rows, oversized, error = self._read_records("journal.jsonl")
            if error:
                raise CleanupError(error, "Cleanup recovery journal is unavailable.")
            if oversized:
                raise CleanupError("journal-oversize-unverified", "The recovery journal is oversized; automatic recovery fails closed.")
            roots = {}
            for category_roots in self._category_roots.values():
                for root_path in category_roots:
                    label = self._relative_label(root_path)
                    if label:
                        roots[_digest(label)[:16]] = root_path
            pending_states = {"prepared", "staged", "trash-inflight", "deleting", "partial-irreversible", "recovery-required"}
            outcomes = []
            for record in self._latest_journal(rows).values():
                if record.get("state") not in pending_states:
                    continue
                root_path = roots.get(record.get("rootKey"))
                relative = record.get("originalRel")
                staging_name = record.get("stagingName")
                expected = {
                    "dev": record.get("dev"),
                    "ino": record.get("ino"),
                    "uid": record.get("uid"),
                    "mode": record.get("mode"),
                    "size": record.get("size"),
                    "mtimeNs": record.get("mtimeNs"),
                }
                if (
                    root_path is None
                    or not isinstance(relative, str)
                    or not isinstance(staging_name, str)
                    or any(not isinstance(expected[key], int) for key in expected)
                ):
                    outcomes.append({"entryId": record.get("entryId"), "outcome": "unavailable"})
                    continue
                root = self._open_root_context(root_path)
                parent_fd = None
                staging_fd = None
                try:
                    if (
                        root["stat"].st_dev != record.get("rootDev")
                        or root["stat"].st_ino != record.get("rootIno")
                        or root["stat"].st_uid != record.get("rootUid")
                    ):
                        outcomes.append({"entryId": record.get("entryId"), "outcome": "root-changed"})
                        continue
                    parts = Path(relative).parts
                    if not parts or any(part in {"", ".", ".."} for part in parts):
                        outcomes.append({"entryId": record.get("entryId"), "outcome": "unavailable"})
                        continue
                    parent_fd = self._open_parent_chain(root["rootFd"], parts[:-1])
                    try:
                        staging_fd = os.open(STAGING_NAME, self._nofollow_flags(directory=True), dir_fd=root["rootFd"])
                    except FileNotFoundError:
                        staging_fd = None
                    try:
                        original_metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        original_metadata = None
                    try:
                        staged_metadata = os.stat(staging_name, dir_fd=staging_fd, follow_symlinks=False) if staging_fd is not None else None
                    except FileNotFoundError:
                        staged_metadata = None
                    metadata_may_drift = record.get("state") in {"deleting", "partial-irreversible"}
                    original_matches = (
                        self._matches_identity_core(original_metadata, expected)
                        if original_metadata is not None and metadata_may_drift
                        else original_metadata is not None and self._matches_expected(original_metadata, expected)
                    )
                    staged_matches = (
                        self._matches_identity_core(staged_metadata, expected)
                        if staged_metadata is not None and metadata_may_drift
                        else staged_metadata is not None and self._matches_expected(staged_metadata, expected)
                    )
                    if original_metadata is not None and staged_metadata is None and original_matches:
                        terminal = dict(record)
                        terminal["state"] = "aborted-before-stage"
                        terminal["observedAt"] = _iso(self.clock())
                        self._journal(terminal)
                        outcomes.append({"entryId": record["entryId"], "outcome": "already-at-original"})
                    elif original_metadata is None and staged_metadata is not None and staged_matches:
                        try:
                            self._identity_move_noreplace(
                                staging_fd,
                                staging_name,
                                parent_fd,
                                parts[-1],
                                expected,
                                allow_metadata_drift=metadata_may_drift,
                            )
                        except CleanupError:
                            outcomes.append({"entryId": record["entryId"], "outcome": "conflict-unverified"})
                            continue
                        self._fsync_fd(staging_fd)
                        self._fsync_fd(parent_fd)
                        terminal = dict(record)
                        terminal["state"] = "partial-restored" if record.get("state") in {"deleting", "partial-irreversible"} else "restored"
                        terminal["observedAt"] = _iso(self.clock())
                        self._journal(terminal)
                        outcomes.append({"entryId": record["entryId"], "outcome": terminal["state"]})
                    elif original_metadata is None and staged_metadata is None and record.get("state") == "trash-inflight":
                        outcomes.append({"entryId": record["entryId"], "outcome": "manual-trash-review"})
                    else:
                        outcomes.append({"entryId": record["entryId"], "outcome": "conflict-unverified"})
                finally:
                    if staging_fd is not None:
                        os.close(staging_fd)
                    if parent_fd is not None:
                        os.close(parent_fd)
                    self._close_context(root)
            return {"schemaVersion": SCHEMA_VERSION, "state": "recovered", "outcomes": outcomes}
        finally:
            self._release_cleanup_lock(lock_fd, lock_context)

    def history(self):
        if not self._supported():
            return {
                "schemaVersion": SCHEMA_VERSION,
                "state": "unsupported",
                "rows": [],
                "privacy": self._privacy(),
            }
        rows, oversized, error = self._read_records("history.jsonl")
        if error:
            return {"schemaVersion": SCHEMA_VERSION, "state": "unavailable", "rows": [], "errorCode": error}
        allowed = {
            "runId", "itemId", "category", "outcome", "actionClass", "logicalBytesRemoved",
            "movedToTrashLogicalBytes", "swapPerformed", "observedAt", "reason",
        }
        sanitized = [{key: value for key, value in row.items() if key in allowed} for row in rows]
        state = "truncated-unverified" if oversized else "available" if sanitized else "empty"
        return {"schemaVersion": SCHEMA_VERSION, "state": state, "rows": sanitized, "boundedTailOnly": oversized, "privacy": self._privacy()}
