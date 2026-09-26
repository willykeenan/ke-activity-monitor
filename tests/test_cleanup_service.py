import json
import hashlib
import fcntl
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import cleanup_service
from cleanup_service import (
    CATEGORY_DEFINITIONS,
    CleanupError,
    CleanupService,
    IDENTITY_MUTATION_CONTRACT,
    MAX_JOURNAL_BYTES,
    STAGING_NAME,
)


class FixtureIdentityMutator:
    available = True
    contract_version = IDENTITY_MUTATION_CONTRACT
    fixture_only = True

    def __init__(self, move_hook=None, delete_hook=None):
        self.move_hook = move_hook
        self.delete_hook = delete_hook

    @staticmethod
    def _matches(metadata, expected):
        identity_matches = (
            not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_dev == expected["dev"]
            and metadata.st_ino == expected["ino"]
            and metadata.st_uid == expected["uid"]
            and stat.S_IFMT(metadata.st_mode) == expected["mode"]
        )
        return identity_matches and (
            expected.get("allowMetadataDrift") is True
            or (
                metadata.st_size == expected["size"]
                and metadata.st_mtime_ns == expected["mtimeNs"]
            )
        )

    def move_noreplace(self, source_fd, source_name, destination_fd, destination_name, expected):
        if self.move_hook is not None:
            self.move_hook(source_fd, source_name, destination_fd, destination_name, expected)
        source = os.stat(source_name, dir_fd=source_fd, follow_symlinks=False)
        if not self._matches(source, expected):
            raise CleanupError("path-swap", "fixture source identity changed")
        try:
            os.stat(destination_name, dir_fd=destination_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CleanupError("path-swap", "fixture no-replace destination exists")
        os.rename(source_name, destination_name, src_dir_fd=source_fd, dst_dir_fd=destination_fd)
        moved = os.stat(destination_name, dir_fd=destination_fd, follow_symlinks=False)
        if not self._matches(moved, expected):
            raise CleanupError("path-swap", "fixture move returned wrong identity")

    def _delete_tree(self, parent_fd, name, expected=None):
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if expected is not None and not self._matches(metadata, expected):
            raise CleanupError("path-swap", "fixture delete identity changed")
        if stat.S_ISDIR(metadata.st_mode):
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            try:
                entries = os.scandir(child_fd)
                try:
                    for child in entries:
                        child_metadata = os.stat(child.name, dir_fd=child_fd, follow_symlinks=False)
                        self._delete_tree(child_fd, child.name, {
                            "dev": child_metadata.st_dev,
                            "ino": child_metadata.st_ino,
                            "uid": child_metadata.st_uid,
                            "mode": stat.S_IFMT(child_metadata.st_mode),
                            "size": child_metadata.st_size,
                            "mtimeNs": child_metadata.st_mtime_ns,
                        })
                finally:
                    entries.close()
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=parent_fd)
        elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            os.unlink(name, dir_fd=parent_fd)
        else:
            raise CleanupError("unsupported-file-type", "fixture unsupported type")

    def delete_identity(self, parent_fd, name, expected):
        if self.delete_hook is not None:
            self.delete_hook(parent_fd, name, expected)
        self._delete_tree(parent_fd, name, expected)


class FakeTrash:
    available = True
    supports_identity_target = True
    contract_version = IDENTITY_MUTATION_CONTRACT
    fixture_only = True

    def __init__(self, root, fail=False, trash_hook=None, restore_hook=None):
        self.root = Path(root)
        self.fail = fail
        self.trash_hook = trash_hook
        self.restore_hook = restore_hook
        self.calls = []

    @staticmethod
    def _expected(metadata):
        return {
            "dev": metadata.st_dev,
            "ino": metadata.st_ino,
            "uid": metadata.st_uid,
            "mode": stat.S_IFMT(metadata.st_mode),
            "size": metadata.st_size,
            "mtimeNs": metadata.st_mtime_ns,
        }

    def trash_identity(self, staging_fd, staging_name, expected):
        if self.trash_hook is not None:
            self.trash_hook(staging_fd, staging_name, expected)
        self.calls.append(staging_name)
        if self.fail:
            raise CleanupError("trash-failed", "fixture failure")
        self.root.mkdir(parents=True, exist_ok=True)
        destination_name = staging_name + ".trashed"
        destination_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            FixtureIdentityMutator().move_noreplace(
                staging_fd,
                staging_name,
                destination_fd,
                destination_name,
                expected,
            )
            metadata = os.stat(destination_name, dir_fd=destination_fd, follow_symlinks=False)
        finally:
            os.close(destination_fd)
        destination = self.root / destination_name
        return {"resultingPath": str(destination), "resultingIdentity": self._expected(metadata)}

    def restore_identity(self, receipt, destination_fd, destination_name, expected):
        if self.restore_hook is not None:
            self.restore_hook(receipt, destination_fd, destination_name, expected)
        source = Path(receipt["resultingPath"])
        source_fd = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            FixtureIdentityMutator().move_noreplace(
                source_fd,
                source.name,
                destination_fd,
                destination_name,
                expected,
            )
        finally:
            os.close(source_fd)
        return True


class FakeMonotonic:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class CleanupServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name).resolve()
        self.cache = self.home / "Library" / "Caches"
        self.downloads = self.home / "Downloads"
        self.projects = self.home / "Projects" / "Example"
        self.cache.mkdir(parents=True)
        self.downloads.mkdir(parents=True)
        self.projects.mkdir(parents=True)
        self.now = time.time()

    def tearDown(self):
        self.temporary.cleanup()

    def _service(self, roots=None, **kwargs):
        return CleanupService(
            home=self.home,
            platform_name="Darwin",
            clock=lambda: self.now,
            category_roots=roots or {"app-caches": [self.cache]},
            state_root=self.home / ".test-cleanup-state",
            open_handle_checker=kwargs.pop("open_handle_checker", lambda _path: False),
            browser_running_checker=kwargs.pop("browser_running_checker", lambda: False),
            trash_adapter=kwargs.pop("trash_adapter", FakeTrash(self.home / ".fixture-trash")),
            identity_mutation_adapter=kwargs.pop("identity_mutation_adapter", FixtureIdentityMutator()),
            performance_probe=kwargs.pop("performance_probe", lambda: {"available": False, "latencyMs": None}),
            **kwargs,
        )

    @staticmethod
    def _wait_analysis(service, started):
        if started.get("state") != "running":
            return started
        deadline = time.time() + 5
        while time.time() < deadline:
            result = service.analysis_status(started["jobId"])
            if result["state"] != "running":
                return result
            time.sleep(0.005)
        raise AssertionError("analysis did not finish")

    @staticmethod
    def _wait_execution(service, started):
        deadline = time.time() + 5
        while time.time() < deadline:
            result = service.execution_status(started["runId"])
            if result["state"] not in {"running", "cancelling"}:
                return result
            time.sleep(0.005)
        raise AssertionError("execution did not finish")

    def _analyze(self, service, categories=None, **options):
        requested = {"categories": categories or list(CATEGORY_DEFINITIONS), **options}
        return self._wait_analysis(service, service.start_analysis(requested))

    def _plan_one(self, service, category):
        analysis = self._analyze(service, [category])
        self.assertEqual(analysis["state"], "complete")
        plan = service.create_plan(analysis["analysisId"], [category])
        self.assertTrue(plan["entries"])
        return analysis, plan, plan["entries"][0]

    def _prepare_pending(self, service, root, name="RecoverMe", staged_name="fixture-entry", body=b"APPROVED"):
        original = Path(root) / name
        original.write_bytes(body)
        staging = Path(root) / STAGING_NAME
        staging.mkdir(mode=0o700, exist_ok=True)
        staged = staging / staged_name
        original.replace(staged)
        metadata = staged.stat()
        label = service._relative_label(root)
        service._journal(
            {
                "entryId": staged_name,
                "runId": "fixture-run",
                "itemId": "fixture-item",
                "state": "prepared",
                "action": "rebuildable-delete",
                "rootKey": hashlib.sha256(label.encode()).hexdigest()[:16],
                "rootDev": Path(root).stat().st_dev,
                "rootIno": Path(root).stat().st_ino,
                "rootUid": Path(root).stat().st_uid,
                "originalRel": name,
                "stagingName": staged_name,
                "bytes": len(body),
                "dev": metadata.st_dev,
                "ino": metadata.st_ino,
                "uid": metadata.st_uid,
                "mode": stat.S_IFMT(metadata.st_mode),
                "size": metadata.st_size,
                "mtimeNs": metadata.st_mtime_ns,
                "observedAt": "2026-08-21T00:00:00Z",
            }
        )
        return original, staged

    def test_safe_recoverable_review_and_protected_classification(self):
        safe = self.cache / "Regenerates"
        safe.mkdir()
        (safe / "cache.bin").write_bytes(b"cache" * 200)
        brain = self.cache / "Brains"
        brain.mkdir()
        (brain / "memory.txt").write_text("never read", encoding="utf-8")
        current_app = self.cache / "Activity Monitor"
        current_app.mkdir()
        (current_app / "receipt").write_text("receipt", encoding="utf-8")
        installer = self.downloads / "old-installer.dmg"
        installer.write_bytes(b"installer")
        old = self.now - 40 * 86400
        os.utime(installer, (old, old))
        artifact = self.projects / "node_modules"
        artifact.mkdir()
        (artifact / "module.js").write_text("module", encoding="utf-8")
        service = self._service(
            {
                "app-caches": [self.cache],
                "old-installers": [self.downloads],
                "project-artifacts": [self.projects],
            },
            current_app_path=current_app,
        )
        result = self._analyze(service, ["app-caches", "old-installers", "project-artifacts"])
        by_category = {row["category"]: row for row in result["candidates"]}
        self.assertEqual(by_category["app-caches"]["riskClass"], "SAFE")
        self.assertEqual(by_category["app-caches"]["actionClass"], "rebuildable-delete")
        self.assertEqual(by_category["old-installers"]["riskClass"], "RECOVERABLE")
        self.assertEqual(by_category["old-installers"]["actionClass"], "trash")
        self.assertEqual(by_category["project-artifacts"]["riskClass"], "REVIEW REQUIRED")
        self.assertEqual(by_category["project-artifacts"]["actionClass"], "review-only")
        serialized = json.dumps(result)
        self.assertNotIn("memory.txt", serialized)
        self.assertNotIn("receipt", serialized)
        reasons = {row["reason"] for row in result["exclusions"]}
        self.assertIn("protected-data-class", reasons)
        self.assertIn("current-app", reasons)

    def test_root_execution_is_unsupported_before_analysis_or_execution(self):
        target = self.cache / "NeverScannedAsRoot"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        service = self._service(uid=0)
        self.assertFalse(service.capabilities()["supported"])
        result = service.start_analysis({"categories": ["app-caches"]})
        self.assertEqual(result["state"], "unsupported")
        self.assertIsNone(service._analysis_inflight)
        self.assertEqual(service.performance_assessment()["state"], "unsupported")
        self.assertEqual(service.journal_recovery_status()["state"], "unsupported")
        self.assertEqual(service.history()["state"], "unsupported")
        self.assertFalse(service.state_root.exists())
        with self.assertRaises(CleanupError) as error:
            service.start_execution("plan", "digest", ["item"], "CLEAN")
        self.assertEqual(error.exception.code, "unsupported")

    def test_documents_source_brain_memory_credentials_and_symlinks_are_never_targets(self):
        documents = self.home / "Documents"
        documents.mkdir()
        (documents / "source.py").write_text("source", encoding="utf-8")
        for name in ("Brain", "Memories", "Credentials", "Cookies", ".git"):
            folder = self.cache / name
            folder.mkdir()
            (folder / "private").write_text("PRIVATE_BODY", encoding="utf-8")
        outside = self.home / "outside"
        outside.write_text("OUTSIDE_SECRET", encoding="utf-8")
        (self.cache / "linked").symlink_to(outside)
        service = self._service({"app-caches": [self.cache], "logs-crash": [documents]})
        result = self._analyze(service, ["app-caches", "logs-crash"])
        self.assertEqual(result["candidates"], [])
        serialized = json.dumps(result)
        self.assertNotIn("PRIVATE_BODY", serialized)
        self.assertNotIn("OUTSIDE_SECRET", serialized)
        reasons = {row["reason"] for row in result["exclusions"]}
        self.assertIn("symbolic-link", reasons)
        self.assertIn("protected-root", reasons)

    def test_special_files_are_excluded_without_blocking_the_scan(self):
        fifo = self.cache / "blocked-reader.fifo"
        os.mkfifo(fifo, 0o600)
        socket_path = self.cache / "live.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(socket_path))
        try:
            started_at = time.monotonic()
            result = self._analyze(self._service(), ["app-caches"], reviewOnly=True)
            elapsed = time.monotonic() - started_at
        finally:
            listener.close()
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["candidates"], [])
        self.assertLess(elapsed, 1.0)
        excluded = {row["reason"]: row["count"] for row in result["exclusions"]}
        self.assertGreaterEqual(excluded.get("unsupported-file-type", 0), 2)

    def test_regular_file_swapped_to_fifo_fails_closed_without_hanging(self):
        target = self.cache / "swap-me"
        target.write_bytes(b"reviewed regular file")
        swapped = False

        def swap_before_open(phase, path):
            nonlocal swapped
            if phase == "before-candidate-open" and Path(path) == target and not swapped:
                target.unlink()
                os.mkfifo(target, 0o600)
                swapped = True

        service = self._service(analysis_swap_hook=swap_before_open)
        started_at = time.monotonic()
        result = self._analyze(service, ["app-caches"], reviewOnly=True)
        self.assertLess(time.monotonic() - started_at, 1.0)
        self.assertTrue(swapped)
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["candidates"], [])
        self.assertIn("analysis-path-swap", {row["reason"] for row in result["exclusions"]})

    def test_review_metadata_never_opens_regular_file_bodies(self):
        leaf = self.cache / "metadata-only.bin"
        leaf.write_bytes(b"body stays unopened")
        opened_leaf = []
        real_open = cleanup_service.os.open

        def record_open(path, *args, **kwargs):
            if os.fspath(path) == leaf.name:
                opened_leaf.append(os.fspath(path))
            return real_open(path, *args, **kwargs)

        with patch.object(cleanup_service.os, "open", side_effect=record_open):
            result = self._analyze(self._service(), ["app-caches"], reviewOnly=True)
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["reviewCandidateCount"], 1)
        self.assertEqual(result["reviewCandidateBytes"], len(b"body stays unopened"))
        self.assertEqual(opened_leaf, [])

    def test_dataless_objects_are_explicitly_excluded(self):
        fake = type("DatalessStat", (), {
            "st_mode": stat.S_IFREG | 0o600,
            "st_uid": os.getuid(),
            "st_flags": cleanup_service.SF_DATALESS,
        })()
        self.assertEqual(self._service()._protection_reason(self.cache / "cloud-placeholder", fake), "dataless-object")

    def test_active_writer_and_browser_process_exclude_targets(self):
        busy = self.cache / "Busy"
        busy.mkdir()
        (busy / "data").write_bytes(b"data")
        service = self._service(open_handle_checker=lambda path: Path(path).name == "Busy")
        result = self._analyze(service, ["app-caches"])
        self.assertEqual(result["candidates"], [])
        self.assertIn("active-writer-or-handle", {row["reason"] for row in result["exclusions"]})

        browser_root = self.home / "Library" / "Caches" / "Browser"
        browser_root.mkdir(parents=True)
        (browser_root / "CacheData").write_bytes(b"cache")
        browser = self._service(
            {"browser-cache": [browser_root]},
            browser_running_checker=lambda: True,
        )
        result = self._analyze(browser, ["browser-cache"])
        self.assertEqual(result["candidates"], [])
        self.assertIn("browser-active-or-unverified", {row["reason"] for row in result["exclusions"]})

    def test_browser_profile_fields_are_excluded_even_when_browser_is_inactive(self):
        root = self.home / "Library" / "Caches" / "Browser"
        root.mkdir(parents=True)
        for name in ("Cookies", "History", "Passwords", "Sessions", "Bookmarks", "Extensions"):
            (root / name).write_text("SECRET_PROFILE_BODY", encoding="utf-8")
        (root / "CacheData").write_bytes(b"cache")
        service = self._service({"browser-cache": [root]})
        result = self._analyze(service, ["browser-cache"])
        self.assertEqual([row["target"] for row in result["candidates"]], ["~/Library/Caches/Browser/CacheData"])
        self.assertNotIn("SECRET_PROFILE_BODY", json.dumps(result))

    def test_duplicate_bytes_are_read_only_after_explicit_choice_and_not_persisted(self):
        first = self.downloads / "first.bin"
        second = self.downloads / "second.bin"
        unique = self.downloads / "unique.bin"
        first.write_bytes(b"same-content")
        second.write_bytes(b"same-content")
        unique.write_bytes(b"different")
        service = self._service({"downloads-duplicates": [self.downloads]})
        without = self._analyze(service, ["downloads-duplicates"], duplicateAnalysis=False)
        self.assertEqual(without["candidates"], [])
        self.assertFalse(without["duplicateBytesHashed"])
        explicit = self._analyze(service, ["downloads-duplicates"], duplicateAnalysis=True)
        self.assertEqual(len(explicit["candidates"]), 2)
        self.assertTrue(explicit["duplicateBytesHashed"])
        serialized = json.dumps(explicit)
        self.assertNotIn("same-content", serialized)
        self.assertNotIn("sha256", serialized.casefold())

    def test_explicit_duplicate_hash_never_reads_credential_like_files(self):
        first = self.downloads / "credentials.json"
        second = self.downloads / "session-cookie.pem"
        first.write_bytes(b"SENSITIVE_DUPLICATE")
        second.write_bytes(b"SENSITIVE_DUPLICATE")
        service = self._service({"downloads-duplicates": [self.downloads]})
        hashed = []
        original_hash = service._hash_duplicate_candidate_at

        def record_hash(parent_fd, name, expected, cancel, deadline, scan_budget=None):
            hashed.append(name)
            return original_hash(parent_fd, name, expected, cancel, deadline, scan_budget)

        service._hash_duplicate_candidate_at = record_hash
        result = self._analyze(service, ["downloads-duplicates"], duplicateAnalysis=True)
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(hashed, [])
        self.assertIn("protected-data-class", {row["reason"] for row in result["exclusions"]})
        self.assertNotIn("SENSITIVE_DUPLICATE", json.dumps(result))

    def test_plan_is_immutable_expiring_and_gated_by_digest_selection_and_clean(self):
        target = self.cache / "PlanTarget"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        mono = FakeMonotonic()
        service = self._service(monotonic=mono, plan_ttl_seconds=10)
        _analysis, plan, item = self._plan_one(service, "app-caches")
        original_digest = plan["planDigest"]
        plan["entries"][0]["target"] = "~/tampered"
        internal, entries = service._validate_execution(
            plan["planId"], original_digest, [item["id"]], "CLEAN"
        )
        self.assertEqual(entries[0]["public"]["target"], "~/Library/Caches/PlanTarget")
        self.assertNotEqual(internal["public"]["entries"][0]["target"], "~/tampered")
        with self.assertRaisesRegex(CleanupError, "CLEAN"):
            service._validate_execution(plan["planId"], original_digest, [item["id"]], "clean")
        with self.assertRaises(CleanupError) as mismatch:
            service._validate_execution(plan["planId"], "0" * 64, [item["id"]], "CLEAN")
        self.assertEqual(mismatch.exception.code, "plan-digest-mismatch")
        with self.assertRaises(CleanupError) as selection:
            service._validate_execution(plan["planId"], original_digest, ["not-in-plan"], "CLEAN")
        self.assertEqual(selection.exception.code, "invalid-selection")
        mono.value += 11
        with self.assertRaises(CleanupError) as expired:
            service._validate_execution(plan["planId"], original_digest, [item["id"]], "CLEAN")
        self.assertEqual(expired.exception.code, "plan-expired")

    def test_completed_analysis_becomes_stale_and_non_actionable_at_cache_ttl(self):
        target = self.cache / "StaleAnalysis"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        mono = FakeMonotonic()
        service = self._service(monotonic=mono, cache_ttl_seconds=10)
        started = service.start_analysis({"categories": ["app-caches"]})
        complete = self._wait_analysis(service, started)
        self.assertEqual(complete["state"], "complete")
        mono.value += 11
        stale = service.analysis_status(started["jobId"])
        self.assertEqual(stale["state"], "stale")
        self.assertEqual(stale["sourceState"], "complete")
        self.assertFalse(stale["actionable"])
        with self.assertRaises(CleanupError) as expired:
            service.create_plan(complete["analysisId"], ["app-caches"])
        self.assertEqual(expired.exception.code, "analysis-expired")

    def test_plan_digest_is_reverified_before_every_item_action(self):
        targets = []
        for name in ("DigestOne", "DigestTwo"):
            target = self.cache / name
            target.mkdir()
            (target / "data").write_bytes(name.encode())
            targets.append(target)
        service = self._service()
        analysis = self._analyze(service, ["app-caches"])
        plan = service.create_plan(analysis["analysisId"], ["app-caches"])
        mutated = {"done": False}

        def mutate_after_first_reverify(_public, _path):
            if mutated["done"]:
                return
            mutated["done"] = True
            service._plans[plan["planId"]]["public"]["entries"][0]["target"] = "~/tampered"

        service._before_action_hook = mutate_after_first_reverify
        result = self._wait_execution(
            service,
            service.start_execution(
                plan["planId"],
                plan["planDigest"],
                [row["id"] for row in plan["entries"]],
                "CLEAN",
            ),
        )
        self.assertTrue(mutated["done"])
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["completedCount"], 1)
        self.assertEqual(result["outcomes"][-1]["reason"], "plan-digest-mismatch")
        self.assertEqual(sum(target.exists() for target in targets), 1)

    def test_rebuildable_delete_uses_fd_bound_staging_and_truthful_logical_byte_accounting(self):
        target = self.cache / "Rebuildable"
        target.mkdir()
        (target / "cache.bin").write_bytes(b"x" * 4096)
        service = self._service()
        _analysis, plan, item = self._plan_one(service, "app-caches")
        started = service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN")
        result = self._wait_execution(service, started)
        self.assertEqual(result["state"], "complete")
        self.assertFalse(target.exists())
        self.assertEqual(result["estimatedLogicalBytesRemoved"], item["bytes"])
        self.assertEqual(result["deletedRebuildableLogicalBytes"], item["bytes"])
        self.assertIsNone(result["attributedBytesReclaimed"])
        self.assertFalse(result["emptyTrashBundled"])
        self.assertEqual(result["outcomes"][0]["outcome"], "deleted-rebuildable")
        self.assertTrue((self.cache / STAGING_NAME).is_dir())
        self.assertEqual(list((self.cache / STAGING_NAME).iterdir()), [])
        history = service.history()
        serialized = json.dumps(history)
        self.assertNotIn(str(self.home), serialized)
        self.assertNotIn("cache.bin", serialized)

    def test_deterministic_path_swap_sets_swap_performed_true_and_deletes_nothing(self):
        target = self.cache / "SwapTarget"
        target.mkdir()
        (target / "data").write_bytes(b"approved")
        outside = self.home / "Documents"
        outside.mkdir()
        (outside / "protected").write_text("PROTECTED", encoding="utf-8")
        backup = self.cache / "SwapTarget.backup"

        def swap(_public, path):
            Path(path).replace(backup)
            Path(path).symlink_to(outside, target_is_directory=True)

        service = self._service(before_action_hook=swap)
        _analysis, plan, item = self._plan_one(service, "app-caches")
        started = service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN")
        result = self._wait_execution(service, started)
        self.assertEqual(result["state"], "partial")
        self.assertTrue(result["outcomes"][0]["swapPerformed"])
        self.assertEqual(result["outcomes"][0]["outcome"], "stopped")
        self.assertTrue(backup.exists())
        self.assertEqual((outside / "protected").read_text(encoding="utf-8"), "PROTECTED")

    def test_recoverable_uses_adapter_trash_then_explicit_rollback_and_never_counts_reclaimed(self):
        installer = self.downloads / "restore.dmg"
        installer.write_bytes(b"installer-bytes")
        old = self.now - 40 * 86400
        os.utime(installer, (old, old))
        adapter = FakeTrash(self.home / ".fixture-trash")
        service = self._service({"old-installers": [self.downloads]}, trash_adapter=adapter)
        _analysis, plan, item = self._plan_one(service, "old-installers")
        started = service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN")
        result = self._wait_execution(service, started)
        self.assertEqual(result["state"], "complete")
        self.assertFalse(installer.exists())
        self.assertEqual(result["movedToTrashLogicalBytes"], item["bytes"])
        self.assertEqual(result["estimatedLogicalBytesRemoved"], item["bytes"])
        self.assertIsNone(result["attributedBytesReclaimed"])
        self.assertFalse(result["trashSpaceReclaimed"])
        with self.assertRaises(CleanupError):
            service.rollback_trash_item(result["runId"], item["id"], "restore")
        restored = service.rollback_trash_item(result["runId"], item["id"], "RESTORE")
        self.assertTrue(restored["ok"])
        self.assertTrue(installer.exists())
        with self.assertRaises(CleanupError) as separate:
            service.empty_trash("CLEAN")
        self.assertEqual(separate.exception.code, "strong-confirmation-required")
        with self.assertRaises(CleanupError) as unavailable:
            service.empty_trash("EMPTY TRASH")
        self.assertEqual(unavailable.exception.code, "empty-trash-unavailable")

    def test_foundation_unavailable_fails_recoverable_action_without_raw_trash_fallback(self):
        installer = self.downloads / "unavailable.pkg"
        installer.write_bytes(b"pkg")
        old = self.now - 40 * 86400
        os.utime(installer, (old, old))

        class Unavailable:
            available = False
            supports_identity_target = False

        service = self._service({"old-installers": [self.downloads]}, trash_adapter=Unavailable())
        analysis, plan, item = self._plan_one(service, "old-installers")
        category = next(row for row in analysis["categories"] if row["id"] == "old-installers")
        self.assertEqual(category["state"], "review-only")
        self.assertEqual(category["executableCount"], 0)
        self.assertEqual(item["actionClass"], "review-only")
        with self.assertRaises(CleanupError) as unavailable:
            service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN")
        self.assertEqual(unavailable.exception.code, "review-only")
        self.assertTrue(installer.exists())
        source = Path(__file__).resolve().parents[1].joinpath("cleanup_service.py").read_text(encoding="utf-8")
        self.assertNotIn("shutil.rmtree", source)
        self.assertIn("trashItemAtURL", source)
        self.assertNotIn("trashItemAtURL_resultingItemURL_error_", source)
        self.assertNotIn("replace(self.home / \".Trash\"", source)

    def test_partial_failure_stops_and_leaves_unselected_remainder_untouched(self):
        for name in ("one.dmg", "two.dmg"):
            path = self.downloads / name
            path.write_bytes(name.encode())
            old = self.now - 40 * 86400
            os.utime(path, (old, old))
        adapter = FakeTrash(self.home / ".fixture-trash", fail=True)
        service = self._service({"old-installers": [self.downloads]}, trash_adapter=adapter)
        analysis = self._analyze(service, ["old-installers"])
        plan = service.create_plan(analysis["analysisId"], ["old-installers"])
        ids = [row["id"] for row in plan["entries"]]
        result = self._wait_execution(
            service,
            service.start_execution(plan["planId"], plan["planDigest"], ids, "CLEAN"),
        )
        self.assertEqual(result["state"], "partial")
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(result["untouchedCount"], 1)
        self.assertTrue((self.downloads / "one.dmg").exists())
        self.assertTrue((self.downloads / "two.dmg").exists())

    def test_cancel_stops_before_action_and_keeps_target(self):
        target = self.cache / "CancelTarget"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        entered = threading.Event()
        release = threading.Event()

        def pause(_public, _path):
            entered.set()
            release.wait(2)

        service = self._service(before_action_hook=pause)
        _analysis, plan, item = self._plan_one(service, "app-caches")
        started = service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN")
        self.assertTrue(entered.wait(2))
        self.assertTrue(service.cancel_execution(started["runId"])["ok"])
        release.set()
        result = self._wait_execution(service, started)
        self.assertEqual(result["state"], "cancelled")
        self.assertTrue(target.exists())

    def test_journal_recovery_restores_fd_bound_staged_item(self):
        original = self.cache / "RecoverMe"
        original.mkdir()
        (original / "data").write_bytes(b"data")
        service = self._service()
        staging = self.cache / STAGING_NAME
        staging.mkdir(mode=0o700)
        staged_name = "fixture-entry"
        original.replace(staging / staged_name)
        root_key = __import__("hashlib").sha256("~/Library/Caches".encode()).hexdigest()[:16]
        service._journal(
            {
                "entryId": "fixture-entry",
                "runId": "fixture-run",
                "itemId": "fixture-item",
                "state": "prepared",
                "rootKey": root_key,
                "rootDev": self.cache.stat().st_dev,
                "rootIno": self.cache.stat().st_ino,
                "rootUid": self.cache.stat().st_uid,
                "originalRel": "RecoverMe",
                "stagingName": staged_name,
                "bytes": 4,
                "dev": (staging / staged_name).stat().st_dev,
                "ino": (staging / staged_name).stat().st_ino,
                "uid": (staging / staged_name).stat().st_uid,
                "mode": stat.S_IFMT((staging / staged_name).stat().st_mode),
                "size": (staging / staged_name).stat().st_size,
                "mtimeNs": (staging / staged_name).stat().st_mtime_ns,
                "observedAt": "2026-08-20T00:00:00Z",
            }
        )
        self.assertEqual(service.journal_recovery_status()["state"], "recovery-available")
        with self.assertRaises(CleanupError):
            service.recover_journal("CLEAN")
        recovered = service.recover_journal("RESTORE")
        self.assertEqual(recovered["outcomes"][0]["outcome"], "restored")
        self.assertTrue(original.exists())
        self.assertFalse((staging / staged_name).exists())

    def test_no_speed_claim_without_material_measured_improvement(self):
        target = self.cache / "NoSpeedClaim"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        probes = iter(
            [
                {"available": True, "latencyMs": 10.0},
                {"available": True, "latencyMs": 9.6},
            ]
        )
        service = self._service(performance_probe=lambda: next(probes))
        _analysis, plan, item = self._plan_one(service, "app-caches")
        result = self._wait_execution(
            service,
            service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"),
        )
        self.assertEqual(result["speedOutcome"]["state"], "probe-only")
        self.assertNotIn("restored", result["speedOutcome"]["claim"].casefold())
        self.assertIn("insufficient", result["speedOutcome"]["claim"])

    def test_analysis_cache_is_monotonic_and_one_inflight_is_reused(self):
        target = self.cache / "CacheTarget"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        mono = FakeMonotonic()
        entered = threading.Event()
        release = threading.Event()

        def blocked(_path):
            entered.set()
            release.wait(2)
            return False

        service = self._service(monotonic=mono, cache_ttl_seconds=60, open_handle_checker=blocked)
        first = service.start_analysis({"categories": ["app-caches"]})
        self.assertTrue(entered.wait(2))
        second = service.start_analysis({"categories": ["app-caches"]})
        self.assertEqual(second["jobId"], first["jobId"])
        self.assertTrue(second["reusedInFlight"])
        release.set()
        complete = self._wait_analysis(service, first)
        cached = service.start_analysis({"categories": ["app-caches"]})
        self.assertEqual(cached["analysisId"], complete["analysisId"])
        self.assertTrue(cached["cached"])
        mono.value += 61
        refreshed = service.start_analysis({"categories": ["app-caches"]})
        self.assertEqual(refreshed["state"], "running")
        self.assertNotEqual(refreshed["jobId"], first["jobId"])
        self._wait_analysis(service, refreshed)

    def test_analysis_root_swap_is_descriptor_blocked_and_reports_swap_performed(self):
        target = self.cache / "Candidate"
        target.mkdir()
        (target / "data").write_bytes(b"approved")
        outside = self.home / "Documents"
        outside.mkdir()
        (outside / "protected").write_text("OUTSIDE", encoding="utf-8")
        backup = self.cache.with_name("Caches.approved")
        swapped = {"done": False}

        def swap(phase, path):
            if phase == "after-root-open" and Path(path) == self.cache and not swapped["done"]:
                swapped["done"] = True
                self.cache.replace(backup)
                self.cache.symlink_to(outside, target_is_directory=True)

        service = self._service(analysis_swap_hook=swap)
        result = self._analyze(service, ["app-caches"])
        self.assertTrue(swapped["done"])
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["candidates"], [])
        self.assertTrue(any(row["swapPerformed"] for row in result["securityEvents"]))
        with self.assertRaises(CleanupError) as error:
            service.create_plan(result["analysisId"], ["app-caches"])
        self.assertEqual(error.exception.code, "analysis-incomplete")
        self.assertEqual((outside / "protected").read_text(encoding="utf-8"), "OUTSIDE")

    def test_analysis_candidate_leaf_swap_is_descriptor_blocked(self):
        target = self.cache / "Leaf"
        target.mkdir()
        (target / "data").write_bytes(b"approved")
        outside = self.home / "Documents"
        outside.mkdir()
        (outside / "protected").write_text("OUTSIDE", encoding="utf-8")
        backup = self.cache / "Leaf.approved"
        swapped = {"done": False}

        def swap(phase, path):
            if phase == "before-candidate-open" and Path(path) == target and not swapped["done"]:
                swapped["done"] = True
                target.replace(backup)
                target.symlink_to(outside, target_is_directory=True)

        result = self._analyze(self._service(analysis_swap_hook=swap), ["app-caches"])
        self.assertTrue(swapped["done"])
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["candidates"], [])
        self.assertTrue(any(row["swapPerformed"] for row in result["securityEvents"]))
        self.assertEqual((outside / "protected").read_text(encoding="utf-8"), "OUTSIDE")

    def test_analysis_nested_component_swap_is_descriptor_blocked(self):
        target = self.cache / "Tree"
        nested = target / "Nested"
        nested.mkdir(parents=True)
        (nested / "data").write_bytes(b"approved")
        outside = self.home / "Documents"
        outside.mkdir()
        (outside / "protected").write_text("OUTSIDE", encoding="utf-8")
        backup = target / "Nested.approved"
        swapped = {"done": False}

        def swap(phase, path):
            if phase == "before-nested-open" and Path(path) == nested and not swapped["done"]:
                swapped["done"] = True
                nested.replace(backup)
                nested.symlink_to(outside, target_is_directory=True)

        result = self._analyze(self._service(analysis_swap_hook=swap), ["app-caches"])
        self.assertTrue(swapped["done"])
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["candidates"], [])
        self.assertTrue(any(row["swapPerformed"] for row in result["securityEvents"]))
        self.assertEqual((outside / "protected").read_text(encoding="utf-8"), "OUTSIDE")

    def test_pre_trash_swap_never_moves_outside_target(self):
        installer = self.downloads / "approved.dmg"
        installer.write_bytes(b"approved")
        old = self.now - 40 * 86400
        os.utime(installer, (old, old))
        outside = self.home / "Documents" / "protected.dmg"
        outside.parent.mkdir()
        outside.write_bytes(b"OUTSIDE")
        adapter = FakeTrash(self.home / ".fixture-trash")
        backup = {"path": None}

        def swap(stage_path, _public):
            stage_path = Path(stage_path)
            backup["path"] = stage_path.with_name(stage_path.name + ".approved")
            stage_path.replace(backup["path"])
            stage_path.symlink_to(outside)

        service = self._service(
            {"old-installers": [self.downloads]},
            trash_adapter=adapter,
            before_trash_hook=swap,
        )
        _analysis, plan, item = self._plan_one(service, "old-installers")
        result = self._wait_execution(
            service,
            service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"),
        )
        self.assertEqual(result["state"], "partial")
        self.assertTrue(result["outcomes"][0]["swapPerformed"])
        self.assertEqual(adapter.calls, [])
        self.assertEqual(outside.read_bytes(), b"OUTSIDE")
        self.assertTrue(backup["path"].exists())

    def test_journal_leaf_and_parent_swaps_fail_closed_without_outside_write(self):
        service = self._service()
        service._journal({"entryId": "one", "state": "completed"})
        outside_file = self.home / "outside-journal"
        outside_file.write_text("OUTSIDE", encoding="utf-8")
        backup_file = service.state_root / "journal.approved"
        swapped = {"leaf": False}

        def leaf_swap(phase, path):
            if phase == "after-journal.jsonl-open" and not swapped["leaf"]:
                swapped["leaf"] = True
                Path(path).replace(backup_file)
                Path(path).symlink_to(outside_file)

        leaf_service = self._service(journal_swap_hook=leaf_swap)
        with self.assertRaises(CleanupError) as leaf_error:
            leaf_service._journal({"entryId": "two", "state": "completed"})
        self.assertEqual(leaf_error.exception.code, "journal-path-swap")
        self.assertEqual(outside_file.read_text(encoding="utf-8"), "OUTSIDE")

        service.state_root.unlink(missing_ok=True) if service.state_root.is_symlink() else None
        if backup_file.exists():
            backup_file.replace(service.state_root / "journal.jsonl")
        outside_parent = self.home / "outside-state-parent"
        outside_parent.mkdir()
        backup_root = service.state_root.with_name("state.approved")
        swapped["parent"] = False

        def parent_swap(phase, _path):
            if phase == "after-state-root-open" and not swapped["parent"]:
                swapped["parent"] = True
                service.state_root.replace(backup_root)
                service.state_root.symlink_to(outside_parent, target_is_directory=True)

        parent_service = self._service(journal_swap_hook=parent_swap)
        with self.assertRaises(CleanupError) as parent_error:
            parent_service._journal({"entryId": "three", "state": "completed"})
        self.assertEqual(parent_error.exception.code, "journal-path-swap")
        self.assertFalse((outside_parent / "journal.jsonl").exists())

    def test_oversize_journal_is_bounded_and_never_reported_clean(self):
        service = self._service()
        service._journal({"entryId": "seed", "state": "completed"})
        pending = {
            "entryId": "pending",
            "state": "staged",
            "rootKey": "fixture",
            "originalRel": "item",
            "stagingName": "stage",
        }
        (service.state_root / "journal.jsonl").write_bytes(
            b"x" * (MAX_JOURNAL_BYTES + 32) + b"\n" + json.dumps(pending).encode() + b"\n"
        )
        status = service.journal_recovery_status()
        self.assertEqual(status["state"], "recovery-available")
        self.assertTrue(status["boundedTailOnly"])
        with self.assertRaises(CleanupError) as error:
            service._journal({"entryId": "new", "state": "completed"})
        self.assertEqual(error.exception.code, "journal-oversize-unverified")

    def test_journal_capacity_fails_closed_without_replacing_pending_file(self):
        service = self._service()
        service._journal({"entryId": "seed", "state": "completed"})
        journal = service.state_root / "journal.jsonl"
        rows = [{"entryId": "pending", "state": "staged"}]
        index = 0
        while len(b"".join((json.dumps(row) + "\n").encode() for row in rows)) < 930:
            rows.append({"entryId": f"done-{index}", "state": "completed", "observedAt": "x" * 24})
            index += 1
        journal.write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in rows))
        inode_before = journal.stat().st_ino
        with patch.object(cleanup_service, "MAX_JOURNAL_BYTES", 1024):
            with self.assertRaises(CleanupError) as error:
                service._journal({"entryId": "next", "state": "completed"})
            self.assertEqual(error.exception.code, "journal-capacity-reached")
            records, oversized, error = service._read_records("journal.jsonl")
        self.assertEqual(journal.stat().st_ino, inode_before)
        self.assertFalse(oversized)
        self.assertIsNone(error)
        latest = service._latest_journal(records)
        self.assertEqual(latest["pending"]["state"], "staged")
        self.assertNotIn("next", latest)

    def test_only_complete_analysis_can_create_a_plan(self):
        for name in ("one", "two"):
            target = self.cache / name
            target.mkdir()
            (target / "data").write_bytes(b"data")
        service = self._service(max_scan_items=1)
        result = self._analyze(service, ["app-caches"])
        self.assertEqual(result["state"], "partial")
        with self.assertRaises(CleanupError) as error:
            service.create_plan(result["analysisId"], ["app-caches"])
        self.assertEqual(error.exception.code, "analysis-incomplete")

    def test_analysis_cancellation_preserves_findings_as_non_actionable(self):
        target = self.cache / "CancelAnalysis"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        entered = threading.Event()
        release = threading.Event()

        def blocked(_path):
            entered.set()
            release.wait(2)
            return False

        service = self._service(open_handle_checker=blocked)
        started = service.start_analysis({"categories": ["app-caches"]})
        self.assertTrue(entered.wait(2))
        self.assertTrue(service.cancel_analysis(started["jobId"])["ok"])
        release.set()
        result = self._wait_analysis(service, started)
        self.assertEqual(result["state"], "cancelled")
        with self.assertRaises(CleanupError) as error:
            service.create_plan(result["analysisId"], ["app-caches"])
        self.assertEqual(error.exception.code, "analysis-incomplete")

    def test_analysis_item_and_byte_limits_are_global_even_for_excluded_entries(self):
        for index in range(4):
            (self.downloads / f"recent-{index}.txt").write_bytes(b"123456")
        item_service = self._service(
            {"old-installers": [self.downloads]},
            max_scan_items=2,
        )
        item_result = self._analyze(item_service, ["old-installers"])
        self.assertEqual(item_result["state"], "partial")
        self.assertEqual(item_result["errorCode"], "scan-limit")

        byte_service = self._service(
            {"old-installers": [self.downloads]},
            max_scan_bytes=10,
        )
        byte_result = self._analyze(byte_service, ["old-installers"])
        self.assertEqual(byte_result["state"], "partial")
        self.assertEqual(byte_result["errorCode"], "scan-limit")

        roots = {
            "app-caches": [self.home / f"missing-cache-{index}" for index in range(33)],
            "logs-crash": [self.home / f"missing-log-{index}" for index in range(33)],
        }
        root_service = self._service(roots)
        root_result = self._analyze(root_service, ["app-caches", "logs-crash"])
        self.assertEqual(root_result["state"], "partial")
        self.assertEqual(root_result["errorCode"], "scan-limit")

    def test_plan_is_consumed_atomically_and_cannot_be_replayed(self):
        target = self.cache / "ConsumeOnce"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        service = self._service()
        _analysis, plan, item = self._plan_one(service, "app-caches")
        self._wait_execution(
            service,
            service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"),
        )
        with self.assertRaises(CleanupError) as replay:
            service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN")
        self.assertEqual(replay.exception.code, "plan-consumed")

    def test_overlapping_download_classifications_deduplicate_to_one_review_target(self):
        installer = self.downloads / "large-old.dmg"
        installer.write_bytes(b"x")
        os.truncate(installer, 600 * 1024 * 1024)
        old = self.now - 40 * 86400
        os.utime(installer, (old, old))
        service = self._service(
            {"old-installers": [self.downloads], "downloads-large": [self.downloads]}
        )
        analysis = self._analyze(service, ["old-installers", "downloads-large"])
        self.assertEqual(len(analysis["candidates"]), 2)
        plan = service.create_plan(analysis["analysisId"], ["old-installers", "downloads-large"])
        self.assertEqual(len(plan["entries"]), 1)
        self.assertEqual(plan["entries"][0]["actionClass"], "review-only")
        self.assertIn("overlapping-or-duplicate-target", {row["reason"] for row in plan["exclusions"]})

    def test_overlapping_log_roots_are_scanned_once_and_recent_logs_are_excluded(self):
        logs = self.home / "Library" / "Logs"
        diagnostic = logs / "DiagnosticReports"
        diagnostic.mkdir(parents=True)
        old_file = diagnostic / "old.log"
        old_file.write_bytes(b"old")
        recent = logs / "recent.log"
        recent.write_bytes(b"recent")
        old = self.now - 10 * 86400
        os.utime(old_file, (old, old))
        os.utime(diagnostic, (old, old))
        service = self._service({"logs-crash": [logs, diagnostic]})
        result = self._analyze(service, ["logs-crash"])
        self.assertEqual([row["target"] for row in result["candidates"]], ["~/Library/Logs/DiagnosticReports"])
        reasons = {row["reason"] for row in result["exclusions"]}
        self.assertIn("log-too-recent", reasons)
        self.assertIn("overlapping-analysis-root", reasons)

    def test_partial_irreversible_failure_is_journaled_and_only_partially_restored(self):
        target = self.cache / "PartialDelete"
        target.mkdir()
        (target / "one").write_bytes(b"one")
        (target / "two").write_bytes(b"two")
        service = self._service()
        _analysis, plan, item = self._plan_one(service, "app-caches")

        def fail_after_one(parent_fd, name, expected=None):
            target_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            try:
                entries = os.scandir(target_fd)
                try:
                    first = next(entries)
                    os.unlink(first.name, dir_fd=target_fd)
                finally:
                    entries.close()
            finally:
                os.close(target_fd)
            raise CleanupError("fixture-partial-delete", "fixture")

        service._identity_mutation_adapter.delete_identity = fail_after_one
        result = self._wait_execution(
            service,
            service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"),
        )
        self.assertEqual(result["state"], "partial")
        self.assertNotIn("restored", json.dumps(result).casefold())
        self.assertEqual(service.journal_recovery_status()["state"], "recovery-available")
        recovered = service.recover_journal("RESTORE")
        self.assertEqual(recovered["outcomes"][0]["outcome"], "partial-restored")
        self.assertTrue(target.exists())
        self.assertEqual(len(list(target.iterdir())), 1)

    def test_journal_failure_after_stage_rename_restores_before_irreversible_work(self):
        target = self.cache / "JournalGap"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        service = self._service()
        _analysis, plan, item = self._plan_one(service, "app-caches")
        original_journal = service._journal
        calls = {"count": 0}

        def fail_second(row):
            calls["count"] += 1
            if calls["count"] == 2:
                raise CleanupError("fixture-journal-failure", "fixture")
            return original_journal(row)

        service._journal = fail_second
        result = self._wait_execution(
            service,
            service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"),
        )
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["outcomes"][0]["reason"], "fixture-journal-failure")
        self.assertTrue(target.exists())
        self.assertEqual((target / "data").read_bytes(), b"data")

    def test_cancellation_during_irreversible_delete_defers_to_action_boundary(self):
        target = self.cache / "DeferredCancel"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        service = self._service()
        _analysis, plan, item = self._plan_one(service, "app-caches")
        entered = threading.Event()
        release = threading.Event()
        original_delete = service._identity_mutation_adapter.delete_identity

        def blocked_delete(parent_fd, name, expected=None):
            entered.set()
            release.wait(2)
            return original_delete(parent_fd, name, expected)

        service._identity_mutation_adapter.delete_identity = blocked_delete
        started = service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN")
        self.assertTrue(entered.wait(2))
        self.assertTrue(service.cancel_execution(started["runId"])["ok"])
        release.set()
        result = self._wait_execution(service, started)
        self.assertEqual(result["state"], "partial")
        self.assertTrue(result["cancellationDeferredUntilActionBoundary"])
        self.assertEqual(result["completedCount"], 1)
        self.assertFalse(target.exists())
        self.assertNotIn("restored", json.dumps(result).casefold())

    def test_storage_delta_is_independent_and_no_exact_or_speed_claim_is_returned(self):
        target = self.cache / "Accounting"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        service = self._service()
        _analysis, plan, item = self._plan_one(service, "app-caches")
        snapshots = iter(
            [
                {"state": "attention", "freeBytes": 1000, "totalBytes": 10000},
                {"state": "observed", "freeBytes": 1400, "totalBytes": 10000},
            ]
        )
        service._storage_snapshot = lambda: next(snapshots)
        result = self._wait_execution(
            service,
            service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"),
        )
        self.assertEqual(result["estimatedLogicalBytesRemoved"], item["bytes"])
        self.assertEqual(result["observedFreeSpaceDeltaBytes"], 400)
        self.assertIsNone(result["attributedBytesReclaimed"])
        self.assertTrue(result["storagePressureChange"]["changed"])
        serialized = json.dumps(result)
        self.assertNotIn("exactBytesReclaimed", serialized)
        self.assertNotIn("measured-improvement", serialized)
        self.assertNotIn("speed restored", serialized.casefold())

    def test_worker_exceptions_always_terminalize_analysis_and_execution(self):
        service = self._service()
        service._run_analysis = lambda _job: (_ for _ in ()).throw(RuntimeError("SECRET"))
        analysis = self._wait_analysis(service, service.start_analysis({"categories": ["app-caches"]}))
        self.assertEqual(analysis["state"], "failed")
        self.assertNotIn("SECRET", json.dumps(analysis))

        target = self.cache / "TerminalExecution"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        execution_service = self._service()
        _analysis, plan, item = self._plan_one(execution_service, "app-caches")
        execution_service._run_execution = lambda _job: (_ for _ in ()).throw(RuntimeError("SECRET"))
        result = self._wait_execution(
            execution_service,
            execution_service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"),
        )
        self.assertEqual(result["state"], "failed")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertIsNone(result["untouchedCount"])
        self.assertIsNone(result["estimatedLogicalBytesRemoved"])

    def test_unexpected_item_failure_records_sanitized_terminal_outcome(self):
        target = self.cache / "UnexpectedActionFailure"
        target.mkdir()
        (target / "data").write_bytes(b"data")
        service = self._service()
        _analysis, plan, item = self._plan_one(service, "app-caches")
        service._stage_and_delete = lambda _job, _item: (_ for _ in ()).throw(RuntimeError("SECRET_PATH_BODY"))
        result = self._wait_execution(
            service,
            service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"),
        )
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["outcomes"][0]["outcome"], "failed-unverified")
        self.assertEqual(result["outcomes"][0]["reason"], "unexpected-action-failure")
        self.assertTrue(target.exists())
        self.assertNotIn("SECRET_PATH_BODY", json.dumps(result))

    def test_nested_open_descendant_is_detected_by_recursive_bounded_lsof(self):
        if not Path("/usr/sbin/lsof").exists():
            self.skipTest("macOS lsof is unavailable")
        target = self.cache / "OpenTree"
        target.mkdir()
        child = target / "nested.db"
        child.write_bytes(b"fixture")
        service = self._service()
        with child.open("rb"):
            self.assertIs(service._default_open_handle_checker(target), True)

    def test_stage_source_identity_swap_never_moves_unselected_object(self):
        target = self.cache / "StageSourceRace"
        target.mkdir()
        (target / "approved").write_bytes(b"APPROVED")
        raced = {"done": False}

        def swap_source(source_fd, source_name, _destination_fd, _destination_name, _expected):
            if raced["done"]:
                return
            raced["done"] = True
            os.rename(source_name, source_name + ".approved-backup", src_dir_fd=source_fd, dst_dir_fd=source_fd)
            os.mkdir(source_name, mode=0o700, dir_fd=source_fd)
            wrong_fd = os.open(source_name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=source_fd)
            try:
                sentinel = os.open("unselected", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=wrong_fd)
                os.write(sentinel, b"UNSELECTED")
                os.close(sentinel)
            finally:
                os.close(wrong_fd)

        service = self._service(identity_mutation_adapter=FixtureIdentityMutator(move_hook=swap_source))
        _analysis, plan, item = self._plan_one(service, "app-caches")
        result = self._wait_execution(service, service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"))
        self.assertTrue(raced["done"])
        self.assertTrue(result["outcomes"][0]["swapPerformed"])
        self.assertEqual((target / "unselected").read_bytes(), b"UNSELECTED")
        self.assertTrue((self.cache / "StageSourceRace.approved-backup" / "approved").exists())

    def test_stage_destination_no_replace_race_preserves_new_destination(self):
        target = self.cache / "StageDestinationRace"
        target.mkdir()
        (target / "approved").write_bytes(b"APPROVED")
        raced = {"done": False, "name": None}

        def create_destination(_source_fd, _source_name, destination_fd, destination_name, _expected):
            if raced["done"]:
                return
            raced["done"] = True
            raced["name"] = destination_name
            sentinel = os.open(destination_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=destination_fd)
            os.write(sentinel, b"UNSELECTED-DESTINATION")
            os.close(sentinel)

        service = self._service(identity_mutation_adapter=FixtureIdentityMutator(move_hook=create_destination))
        _analysis, plan, item = self._plan_one(service, "app-caches")
        result = self._wait_execution(service, service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"))
        destination = self.cache / STAGING_NAME / raced["name"]
        self.assertTrue(result["outcomes"][0]["swapPerformed"])
        self.assertEqual(destination.read_bytes(), b"UNSELECTED-DESTINATION")
        self.assertEqual((target / "approved").read_bytes(), b"APPROVED")

    def test_delete_identity_swap_never_unlinks_changed_staged_object(self):
        target = self.cache / "DeleteIdentityRace"
        target.mkdir()
        (target / "approved").write_bytes(b"APPROVED")
        raced = {"done": False, "name": None}

        def swap_before_delete(parent_fd, name, _expected):
            raced["done"] = True
            raced["name"] = name
            os.rename(name, name + ".approved-backup", src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            wrong_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd)
            try:
                sentinel = os.open("unselected", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=wrong_fd)
                os.write(sentinel, b"UNSELECTED")
                os.close(sentinel)
            finally:
                os.close(wrong_fd)

        service = self._service(identity_mutation_adapter=FixtureIdentityMutator(delete_hook=swap_before_delete))
        _analysis, plan, item = self._plan_one(service, "app-caches")
        result = self._wait_execution(service, service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"))
        staged = self.cache / STAGING_NAME
        self.assertTrue(raced["done"])
        self.assertTrue(result["outcomes"][0]["swapPerformed"])
        self.assertEqual((staged / raced["name"] / "unselected").read_bytes(), b"UNSELECTED")
        self.assertEqual((staged / (raced["name"] + ".approved-backup") / "approved").read_bytes(), b"APPROVED")

    def test_final_trash_identity_swap_never_moves_changed_object(self):
        installer = self.downloads / "TrashIdentityRace.dmg"
        installer.write_bytes(b"APPROVED")
        old = self.now - 40 * 86400
        os.utime(installer, (old, old))
        raced = {"done": False, "name": None}

        def swap_before_trash(staging_fd, staging_name, _expected):
            raced["done"] = True
            raced["name"] = staging_name
            os.rename(staging_name, staging_name + ".approved-backup", src_dir_fd=staging_fd, dst_dir_fd=staging_fd)
            wrong = os.open(staging_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=staging_fd)
            os.write(wrong, b"UNSELECTED")
            os.close(wrong)

        adapter = FakeTrash(self.home / ".fixture-trash", trash_hook=swap_before_trash)
        service = self._service({"old-installers": [self.downloads]}, trash_adapter=adapter)
        _analysis, plan, item = self._plan_one(service, "old-installers")
        result = self._wait_execution(service, service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"))
        staged = self.downloads / STAGING_NAME
        self.assertTrue(raced["done"])
        self.assertTrue(result["outcomes"][0]["swapPerformed"])
        self.assertEqual((staged / raced["name"]).read_bytes(), b"UNSELECTED")
        self.assertEqual((staged / (raced["name"] + ".approved-backup")).read_bytes(), b"APPROVED")
        self.assertFalse(any((self.home / ".fixture-trash").glob("*.trashed")))

    def test_rollback_source_identity_swap_never_restores_changed_object(self):
        installer = self.downloads / "RollbackIdentityRace.dmg"
        installer.write_bytes(b"APPROVED")
        old = self.now - 40 * 86400
        os.utime(installer, (old, old))
        adapter = FakeTrash(self.home / ".fixture-trash")
        service = self._service({"old-installers": [self.downloads]}, trash_adapter=adapter)
        _analysis, plan, item = self._plan_one(service, "old-installers")
        result = self._wait_execution(service, service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"))
        raced = {"done": False, "path": None}

        def swap_restore_source(receipt, _destination_fd, _destination_name, _expected):
            source = Path(receipt["resultingPath"])
            raced["done"] = True
            raced["path"] = source
            source.replace(source.with_name(source.name + ".approved-backup"))
            source.write_bytes(b"UNSELECTED")

        adapter.restore_hook = swap_restore_source
        with self.assertRaises(CleanupError) as error:
            service.rollback_trash_item(result["runId"], item["id"], "RESTORE")
        self.assertEqual(error.exception.code, "path-swap")
        self.assertTrue(raced["done"])
        self.assertFalse(installer.exists())
        self.assertEqual(raced["path"].read_bytes(), b"UNSELECTED")

    def test_recovery_source_identity_swap_never_restores_changed_object(self):
        raced = {"done": False}

        def swap_recovery_source(source_fd, source_name, _destination_fd, _destination_name, _expected):
            if raced["done"]:
                return
            raced["done"] = True
            os.rename(source_name, source_name + ".approved-backup", src_dir_fd=source_fd, dst_dir_fd=source_fd)
            wrong = os.open(source_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=source_fd)
            os.write(wrong, b"UNSELECTED")
            os.close(wrong)

        service = self._service(identity_mutation_adapter=FixtureIdentityMutator(move_hook=swap_recovery_source))
        original, staged = self._prepare_pending(service, self.cache)
        recovered = service.recover_journal("RESTORE")
        self.assertTrue(raced["done"])
        self.assertEqual(recovered["outcomes"][0]["outcome"], "conflict-unverified")
        self.assertFalse(original.exists())
        self.assertEqual(staged.read_bytes(), b"UNSELECTED")
        self.assertEqual(staged.with_name(staged.name + ".approved-backup").read_bytes(), b"APPROVED")

    def test_recovery_destination_no_replace_race_preserves_new_destination(self):
        raced = {"done": False}

        def create_recovery_destination(_source_fd, _source_name, destination_fd, destination_name, _expected):
            if raced["done"]:
                return
            raced["done"] = True
            sentinel = os.open(destination_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=destination_fd)
            os.write(sentinel, b"UNSELECTED-DESTINATION")
            os.close(sentinel)

        service = self._service(identity_mutation_adapter=FixtureIdentityMutator(move_hook=create_recovery_destination))
        original, staged = self._prepare_pending(service, self.cache)
        recovered = service.recover_journal("RESTORE")
        self.assertTrue(raced["done"])
        self.assertEqual(recovered["outcomes"][0]["outcome"], "conflict-unverified")
        self.assertEqual(original.read_bytes(), b"UNSELECTED-DESTINATION")
        self.assertEqual(staged.read_bytes(), b"APPROVED")

    def test_torn_newer_pending_journal_never_reports_clean(self):
        service = self._service()
        service._journal({"entryId": "same", "state": "completed"})
        journal = service.state_root / "journal.jsonl"
        with journal.open("ab") as handle:
            handle.write(b'{"entryId":"same","state":"staged"')
        status = service.journal_recovery_status()
        self.assertEqual(status["state"], "unavailable")
        self.assertEqual(status["errorCode"], "journal-corrupt-unverified")
        self.assertIsNone(status["pendingCount"])
        with self.assertRaises(CleanupError) as error:
            service.recover_journal("RESTORE")
        self.assertEqual(error.exception.code, "journal-corrupt-unverified")

    def test_pending_journal_entry_older_than_history_row_cap_is_not_lost(self):
        service = self._service()
        service._journal({"entryId": "pending", "state": "staged"})
        journal = service.state_root / "journal.jsonl"
        with journal.open("ab") as handle:
            for index in range(MAX_JOURNAL_BYTES // 1024 + 80):
                handle.write((json.dumps({"entryId": f"done-{index}", "state": "completed"}) + "\n").encode())
        self.assertLess(journal.stat().st_size, MAX_JOURNAL_BYTES)
        status = service.journal_recovery_status()
        self.assertEqual(status["state"], "recovery-available")
        self.assertEqual(status["pendingCount"], 1)

    def test_recovery_obeys_shared_cleanup_lock(self):
        service = self._service()
        original, staged = self._prepare_pending(service, self.cache)
        lock_fd, context = service._open_state_file("cleanup.lock", os.O_RDWR | os.O_CREAT, create_root=True)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with self.assertRaises(CleanupError) as error:
                service.recover_journal("RESTORE")
            self.assertEqual(error.exception.code, "cleanup-locked")
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
            service._close_context(context)
        self.assertFalse(original.exists())
        self.assertEqual(staged.read_bytes(), b"APPROVED")

    def test_rollback_obeys_shared_cleanup_lock(self):
        installer = self.downloads / "RollbackLock.dmg"
        installer.write_bytes(b"APPROVED")
        old = self.now - 40 * 86400
        os.utime(installer, (old, old))
        adapter = FakeTrash(self.home / ".fixture-trash")
        service = self._service({"old-installers": [self.downloads]}, trash_adapter=adapter)
        _analysis, plan, item = self._plan_one(service, "old-installers")
        result = self._wait_execution(service, service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"))
        receipt_path = Path(service._rollback[(result["runId"], item["id"])]["resultingPath"])
        lock_fd, context = service._open_state_file("cleanup.lock", os.O_RDWR | os.O_CREAT, create_root=True)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with self.assertRaises(CleanupError) as error:
                service.rollback_trash_item(result["runId"], item["id"], "RESTORE")
            self.assertEqual(error.exception.code, "cleanup-locked")
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
            service._close_context(context)
        self.assertFalse(installer.exists())
        self.assertEqual(receipt_path.read_bytes(), b"APPROVED")

    def test_packaged_default_disables_unsafe_automatic_mutation_before_clean(self):
        target = self.cache / "ReviewOnlyDefault"
        target.mkdir()
        (target / "data").write_bytes(b"APPROVED")
        service = CleanupService(
            home=self.home,
            platform_name="Darwin",
            clock=lambda: self.now,
            category_roots={"app-caches": [self.cache]},
            state_root=self.home / ".default-state",
            open_handle_checker=lambda _path: False,
            browser_running_checker=lambda: False,
            performance_probe=lambda: {"available": False, "latencyMs": None},
        )
        caps = service.capabilities()
        self.assertEqual(caps["automaticExecution"], "unavailable-fail-closed")
        self.assertEqual(caps["irreversibleDirectorySafety"], "unavailable-fail-closed")
        analysis = self._analyze(service, ["app-caches"])
        self.assertEqual(analysis["candidates"][0]["actionClass"], "review-only")
        self.assertEqual(analysis["candidates"][0]["executionState"], "identity-mutation-unavailable")
        plan = service.create_plan(analysis["analysisId"], ["app-caches"])
        with self.assertRaises(CleanupError) as error:
            service.start_execution(plan["planId"], plan["planDigest"], [plan["entries"][0]["id"]], "CLEAN")
        self.assertEqual(error.exception.code, "review-only")
        self.assertEqual((target / "data").read_bytes(), b"APPROVED")

    def test_capabilities_and_history_are_truthful_and_content_free(self):
        target = self.cache / "HistoryTarget"
        target.mkdir()
        (target / "private-cache.bin").write_text("SUPER_SECRET_CONTENT", encoding="utf-8")
        service = self._service()
        caps = service.capabilities()
        self.assertEqual(caps["irreversibleDirectorySafety"], IDENTITY_MUTATION_CONTRACT)
        self.assertEqual(caps["journalSafety"], "descriptor-bound-nofollow-bounded-append-fail-closed")
        self.assertFalse(caps["scanStartsAutomatically"])
        self.assertFalse(caps["privacy"]["fullDiskAccessExpandsProtectedScope"])
        _analysis, plan, item = self._plan_one(service, "app-caches")
        self._wait_execution(
            service,
            service.start_execution(plan["planId"], plan["planDigest"], [item["id"]], "CLEAN"),
        )
        serialized = json.dumps(service.history())
        self.assertNotIn("SUPER_SECRET_CONTENT", serialized)
        self.assertNotIn(str(self.home), serialized)
        self.assertNotIn("private-cache.bin", serialized)

    def test_review_only_analysis_skips_changed_candidate_and_keeps_stable_results(self):
        unstable = self.cache / "A-Unstable"
        unstable.mkdir()
        (unstable / "data").write_bytes(b"approved")
        stable = self.cache / "B-Stable"
        stable.mkdir()
        (stable / "data").write_bytes(b"stable")
        outside = self.home / "Documents"
        outside.mkdir()
        (outside / "protected").write_text("OUTSIDE", encoding="utf-8")
        backup = self.cache / "A-Unstable.approved"
        swapped = {"done": False}

        def swap(phase, path):
            if phase == "before-candidate-open" and Path(path) == unstable and not swapped["done"]:
                swapped["done"] = True
                unstable.replace(backup)
                unstable.symlink_to(outside, target_is_directory=True)

        result = self._analyze(
            self._service(analysis_swap_hook=swap),
            ["app-caches"],
            reviewOnly=True,
        )
        self.assertTrue(swapped["done"])
        self.assertEqual(result["state"], "complete")
        self.assertEqual([row["target"] for row in result["reviewCandidates"]], ["~/Library/Caches/B-Stable"])
        self.assertTrue(any(row["outcome"] == "skipped" for row in result["securityEvents"]))
        self.assertEqual((outside / "protected").read_text(encoding="utf-8"), "OUTSIDE")

    def test_review_candidates_deduplicate_same_identity_and_bytes(self):
        installer = self.downloads / "large-old.dmg"
        with installer.open("wb") as handle:
            handle.truncate(600 * 1024 * 1024)
        old = self.now - 40 * 86400
        os.utime(installer, (old, old))
        service = self._service(
            {"old-installers": [self.downloads], "downloads-large": [self.downloads]}
        )
        result = self._analyze(
            service,
            ["old-installers", "downloads-large"],
            reviewOnly=True,
        )
        self.assertEqual(result["state"], "complete")
        self.assertEqual(len(result["candidates"]), 2)
        self.assertEqual(result["reviewCandidateCount"], 1)
        self.assertEqual(result["reviewCandidateBytes"], 600 * 1024 * 1024)
        self.assertEqual(result["reviewExclusions"], [{"reason": "overlapping-or-duplicate-target", "count": 1}])

    def test_isolated_review_helpers_aggregate_path_free_candidates(self):
        target = self.cache / "IsolatedCandidate"
        target.mkdir()
        (target / "cache.bin").write_bytes(b"approved")
        bundles = []

        def helper(category, _timeout_seconds, _cancel):
            child = self._service({category: [self.cache]})
            result = self._analyze(child, [category], reviewOnly=True)
            bundle = child.review_helper_bundle(category, result)
            bundles.append(bundle)
            return bundle

        service = self._service(
            {"app-caches": [self.cache]},
            review_helper_runner=helper,
        )
        result = self._analyze(service, ["app-caches"], reviewOnly=True)
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["reviewCandidateCount"], 1)
        self.assertEqual(result["reviewCandidates"][0]["target"], "~/Library/Caches/IsolatedCandidate")
        serialized = json.dumps(bundles)
        self.assertNotIn(str(self.home), serialized)
        self.assertNotIn("cache.bin", serialized)

    def test_isolated_review_helper_failure_keeps_other_categories_useful(self):
        target = self.cache / "StableCandidate"
        target.mkdir()
        (target / "cache.bin").write_bytes(b"approved")

        def helper(category, _timeout_seconds, _cancel):
            if category == "logs-crash":
                raise CleanupError("helper-time-limit", "fixture time limit")
            child = self._service({category: [self.cache]})
            result = self._analyze(child, [category], reviewOnly=True)
            return child.review_helper_bundle(category, result)

        service = self._service(
            {"app-caches": [self.cache], "logs-crash": [self.cache]},
            review_helper_runner=helper,
        )
        result = self._analyze(service, ["app-caches", "logs-crash"], reviewOnly=True)
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["errorCode"], "helper-partial")
        self.assertEqual(result["reviewCandidateCount"], 1)
        self.assertEqual({row["id"] for row in result["categories"]}, {"app-caches", "logs-crash"})
        failed = next(row for row in result["categories"] if row["id"] == "logs-crash")
        self.assertEqual(failed["state"], "partial-review-only")
        self.assertIn({"reason": "helper-time-limit", "count": 1}, result["exclusions"])

    def test_isolated_review_helper_rejects_traversal_and_fails_category_closed(self):
        def helper(category, _timeout_seconds, _cancel):
            return {
                "schemaVersion": cleanup_service.REVIEW_HELPER_SCHEMA_VERSION,
                "category": category,
                "result": {
                    "state": "complete",
                    "categories": [{
                        "id": category,
                        "detail": "fixture",
                        "targetCount": 1,
                        "bytes": 1,
                        "excludedCount": 0,
                        "executableCount": 0,
                    }],
                    "exclusions": [],
                    "securityEvents": [],
                },
                "internalCandidates": [{
                    "public": {"id": "forged", "category": category, "target": "~/escape", "bytes": 1},
                    "rootIndex": 0,
                    "relativeToRoot": "../escape",
                    "rootStat": {"dev": 1, "ino": 1, "uid": os.geteuid()},
                    "stat": {
                        "dev": 1,
                        "ino": 1,
                        "uid": os.geteuid(),
                        "mode": stat.S_IFREG,
                        "size": 1,
                        "mtimeNs": 1,
                        "treeBytes": 1,
                        "treeItems": 1,
                        "treeNewestMtimeNs": 1,
                    },
                }],
            }

        service = self._service(
            {"app-caches": [self.cache]},
            review_helper_runner=helper,
        )
        result = self._analyze(service, ["app-caches"], reviewOnly=True)
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["reviewCandidateCount"], 0)
        self.assertIn({"reason": "helper-invalid", "count": 1}, result["exclusions"])

    def test_finder_reveal_uses_only_revalidated_analysis_identities(self):
        installer = self.downloads / "review-me.dmg"
        installer.write_bytes(b"approved")
        old = self.now - 40 * 86400
        os.utime(installer, (old, old))
        revealed = []
        service = self._service(
            {"old-installers": [self.downloads]},
            reveal_handler=lambda paths: revealed.extend(paths) or len(paths),
        )
        analysis = self._analyze(service, ["old-installers"], reviewOnly=True)
        item = analysis["reviewCandidates"][0]
        result = service.reveal_candidates(analysis["analysisId"], [item["id"]])
        self.assertTrue(result["ok"])
        self.assertEqual(result["revealedCount"], 1)
        self.assertEqual(revealed, [installer])
        self.assertNotIn(str(self.home), json.dumps(result))
        self.assertEqual(installer.read_bytes(), b"approved")

        installer.write_bytes(b"changed identity metadata")
        changed = service.reveal_candidates(analysis["analysisId"], [item["id"]])
        self.assertFalse(changed["ok"])
        self.assertEqual(changed["state"], "needs-rescan")
        self.assertEqual(changed["skipped"][0]["reason"], "reveal-target-changed")
        self.assertEqual(len(revealed), 1)

    def test_finder_reveal_and_review_destinations_are_strictly_bounded(self):
        opened = []
        service = self._service(destination_opener=lambda target: opened.append(target) or True)
        with self.assertRaises(CleanupError) as too_many:
            service.reveal_candidates("analysis", [f"id-{index}" for index in range(13)])
        self.assertEqual(too_many.exception.code, "invalid-reveal-selection")
        with self.assertRaises(CleanupError) as duplicate:
            service.reveal_candidates("analysis", ["same", "same"])
        self.assertEqual(duplicate.exception.code, "invalid-reveal-selection")
        for destination in ("storage-settings", "trash", "downloads"):
            result = service.open_review_destination(destination)
            self.assertTrue(result["ok"])
            self.assertEqual(result["destination"], destination)
        self.assertEqual(len(opened), 3)
        with self.assertRaises(CleanupError) as arbitrary:
            service.open_review_destination("file:///etc")
        self.assertEqual(arbitrary.exception.code, "invalid-review-destination")
        self.assertEqual(len(opened), 3)


if __name__ == "__main__":
    unittest.main()
