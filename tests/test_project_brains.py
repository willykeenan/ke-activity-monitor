import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from brain_discovery import BrainService
import project_brains
from project_brains import (
    LABEL_POLICY_VERSION,
    MAX_MANIFEST_BYTES,
    MANIFEST_FILENAME,
    MARKER_FILENAME,
    REGISTRY_FILENAME,
    REGISTRY_SCHEMA_VERSION,
    ProjectBrainRegistry,
)


PROJECT_A = "local-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PROJECT_B = "local-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CLAUDE_A = "claude-cccccccccccccccccccccccc"


class ProjectBrainRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.parent = self.home / ".grokcode" / "brain"
        (self.parent / ".obsidian").mkdir(parents=True, mode=0o700)
        self.projects = self.parent / "GrokCode" / "Projects"
        self.projects.mkdir(parents=True, mode=0o700)
        for path in (self.home, self.parent.parent, self.parent, self.parent / "GrokCode", self.projects):
            os.chmod(path, 0o700)
        self.registry = ProjectBrainRegistry(home=self.home)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def _project(provider, project_id, label):
        return {"provider": provider, "projectId": project_id, "label": label}

    def _assert_snapshot_persistence_untrusted(self, *, registry=None):
        before_fds = len(os.listdir("/dev/fd"))
        snapshot = (registry or ProjectBrainRegistry(home=self.home)).snapshot()
        after_fds = len(os.listdir("/dev/fd"))
        self.assertFalse(snapshot["ok"])
        self.assertEqual(snapshot["state"], "unavailable")
        self.assertEqual(snapshot["code"], "project_brain_persistence_untrusted")
        self.assertFalse(snapshot["privacy"]["persistedValuesValidated"])
        self.assertFalse(snapshot["privacy"]["labelsSanitized"])
        self.assertTrue(snapshot["privacy"]["credentialsStored"])
        self.assertEqual(after_fds, before_fds)
        return snapshot

    def test_provisions_real_private_obsidian_children_with_metadata_only_identity(self):
        result = self.registry.sync([
            self._project("codex", PROJECT_A, "Activity Monitor"),
            self._project("claude", CLAUDE_A, "Claude Research"),
        ])
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["counts"], {"total": 2, "active": 2, "dormant": 0, "blocked": 0})
        self.assertEqual(len(result["byProject"]), 2)
        self.assertFalse(result["privacy"]["repositoryPathsStored"])

        for child in result["children"]:
            path = Path(child["path"])
            self.assertTrue((path / ".obsidian").is_dir())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            for folder in (".obsidian", "Inbox", "Decisions", "Reference", "Sessions"):
                self.assertEqual(stat.S_IMODE((path / folder).stat().st_mode), 0o700)
            for filename in (MARKER_FILENAME, MANIFEST_FILENAME):
                self.assertEqual(stat.S_IMODE((path / filename).stat().st_mode), 0o600)
            manifest = (path / MANIFEST_FILENAME).read_text(encoding="utf-8")
            self.assertIn(child["brainId"], manifest)
            self.assertIn(child["parentBrainId"], manifest)
            self.assertNotIn("/Users/", manifest)
            self.assertNotIn("cwd", manifest.lower())
            self.assertNotIn("transcript", manifest.lower())

        registry_path = self.projects / REGISTRY_FILENAME
        self.assertEqual(stat.S_IMODE(registry_path.stat().st_mode), 0o600)
        raw = registry_path.read_text(encoding="utf-8")
        self.assertNotIn("/Users/", raw)
        self.assertNotIn("prompt", raw.lower())
        self.assertNotIn("transcript", raw.lower())

    def test_rename_retains_identity_and_disappearance_becomes_dormant_without_delete(self):
        first = self.registry.sync([self._project("codex", PROJECT_A, "Old Name")])
        original = first["children"][0]
        original_path = Path(original["path"])

        renamed = self.registry.sync([self._project("codex", PROJECT_A, "New Name")])
        current = renamed["children"][0]
        self.assertEqual(current["brainId"], original["brainId"])
        self.assertEqual(current["path"], original["path"])
        self.assertEqual(current["label"], "New Name")
        self.assertIn("New Name", (original_path / MANIFEST_FILENAME).read_text(encoding="utf-8"))

        dormant = self.registry.sync([])
        retained = dormant["children"][0]
        self.assertEqual(retained["lifecycleState"], "dormant")
        self.assertTrue(original_path.is_dir())

        replaced = self.registry.sync([self._project("codex", PROJECT_B, "New Identity")])
        self.assertEqual(replaced["counts"]["total"], 2)
        by_id = {item["projectId"]: item for item in replaced["children"]}
        self.assertEqual(by_id[PROJECT_A]["lifecycleState"], "dormant")
        self.assertEqual(by_id[PROJECT_B]["lifecycleState"], "active")
        self.assertNotEqual(by_id[PROJECT_A]["brainId"], by_id[PROJECT_B]["brainId"])

    def test_corrupt_registry_fails_closed_without_overwrite(self):
        self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        registry_path = self.projects / REGISTRY_FILENAME
        registry_path.write_text("{broken registry", encoding="utf-8")
        os.chmod(registry_path, 0o600)
        before = registry_path.read_bytes()

        failed = self.registry.sync([self._project("codex", PROJECT_B, "Other")])
        self.assertFalse(failed["ok"])
        self.assertEqual(failed["code"], "metadata_corrupt")
        self.assertEqual(registry_path.read_bytes(), before)
        self.assertFalse(any("other--" in path.name for path in self.projects.iterdir()))

    def test_symlink_replacement_is_blocked_and_never_followed(self):
        first = self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        child = first["children"][0]
        child_path = Path(child["path"])
        outside = self.home / "outside"
        outside.mkdir(mode=0o700)
        marker = outside / "do-not-touch.txt"
        marker.write_text("safe", encoding="utf-8")
        shutil.rmtree(child_path)
        child_path.symlink_to(outside, target_is_directory=True)

        retried = self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        self.assertTrue(retried["ok"])
        self.assertEqual(retried["state"], "degraded")
        self.assertEqual(retried["errors"][0]["code"], "child_untrusted")
        self.assertTrue(child_path.is_symlink())
        self.assertEqual(marker.read_text(encoding="utf-8"), "safe")
        self.assertFalse((outside / MANIFEST_FILENAME).exists())

    def test_concurrent_idempotent_sync_creates_one_child(self):
        project = self._project("codex", PROJECT_A, "Activity Monitor")
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _index: self.registry.sync([project]), range(16)))
        self.assertTrue(all(item["ok"] for item in results))
        snapshot = self.registry.snapshot()
        self.assertEqual(snapshot["counts"]["total"], 1)
        children = [path for path in self.projects.iterdir() if path.is_dir() and not path.name.startswith(".")]
        self.assertEqual(len(children), 1)

    def test_unchanged_sync_does_not_rewrite_registry_or_managed_manifest(self):
        project = self._project("codex", PROJECT_A, "Activity Monitor")
        first = self.registry.sync([project])
        child_path = Path(first["children"][0]["path"])
        registry_path = self.projects / REGISTRY_FILENAME
        observed = {
            "registry": registry_path.stat().st_mtime_ns,
            "marker": (child_path / MARKER_FILENAME).stat().st_mtime_ns,
            "manifest": (child_path / MANIFEST_FILENAME).stat().st_mtime_ns,
        }
        second = self.registry.sync([project])
        self.assertTrue(second["ok"])
        self.assertEqual(registry_path.stat().st_mtime_ns, observed["registry"])
        self.assertEqual((child_path / MARKER_FILENAME).stat().st_mtime_ns, observed["marker"])
        self.assertEqual((child_path / MANIFEST_FILENAME).stat().st_mtime_ns, observed["manifest"])

    def test_interrupted_first_commit_adopts_exact_orphan_without_duplicate(self):
        project = self._project("codex", PROJECT_A, "Activity Monitor")
        first = self.registry.sync([project])
        child = first["children"][0]
        child_path = Path(child["path"])
        created_at = json.loads((child_path / MARKER_FILENAME).read_text(encoding="utf-8"))["createdAt"]
        (self.projects / REGISTRY_FILENAME).unlink()

        recovered = self.registry.sync([project])

        self.assertTrue(recovered["ok"])
        self.assertEqual(recovered["counts"]["total"], 1)
        self.assertEqual(recovered["children"][0]["path"], str(child_path))
        self.assertEqual(
            json.loads((child_path / MARKER_FILENAME).read_text(encoding="utf-8"))["createdAt"],
            created_at,
        )
        children = [path.resolve() for path in self.projects.iterdir() if path.is_dir() and not path.name.startswith(".")]
        self.assertEqual(children, [child_path.resolve()])

    def test_registry_rejects_noncanonical_timestamp_without_child_mutation(self):
        first = self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        child_path = Path(first["children"][0]["path"])
        manifest_before = (child_path / MANIFEST_FILENAME).read_bytes()
        registry_path = self.projects / REGISTRY_FILENAME
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
        payload["projects"][f"codex:{PROJECT_A}"]["updatedAt"] = "/Users/private/secret-path"
        registry_path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(registry_path, 0o600)

        failed = self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])

        self.assertFalse(failed["ok"])
        self.assertEqual(failed["code"], "registry_corrupt")
        self.assertEqual((child_path / MANIFEST_FILENAME).read_bytes(), manifest_before)

    def test_parent_symlink_fails_closed_before_outside_mutation(self):
        shutil.rmtree(self.parent)
        outside = self.home / "outside-parent"
        (outside / ".obsidian").mkdir(parents=True, mode=0o700)
        (outside / "GrokCode" / "Projects").mkdir(parents=True, mode=0o700)
        self.parent.symlink_to(outside, target_is_directory=True)
        registry = ProjectBrainRegistry(home=self.home)
        failed = registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        self.assertFalse(failed["ok"])
        self.assertIn(failed["code"], {"parent_untrusted", "directory_untrusted"})
        self.assertEqual(list((outside / "GrokCode" / "Projects").iterdir()), [])

    def test_brain_inventory_renders_parent_child_and_child_is_browsable(self):
        service = BrainService(
            home=self.home,
            scan_roots=[self.home],
            settings_path=self.home / "support" / "brain-settings.json",
            scan_seconds=2.0,
            max_directories=2_000,
        )
        synced = service.sync_project_brains([
            self._project("codex", PROJECT_A, "Activity Monitor")
        ])
        child = synced["children"][0]
        inventory = service.scan(force=True)
        self.assertTrue(inventory["projectHierarchy"]["ok"])
        self.assertEqual(inventory["summary"]["projectChildren"], 1)
        row = next(item for item in inventory["brains"] if item["id"] == child["brainId"])
        self.assertTrue(row["managedProjectChild"])
        self.assertEqual(row["parentBrainId"], child["parentBrainId"])
        self.assertEqual(row["projectId"], PROJECT_A)
        self.assertEqual(row["status"], "connected")
        self.assertTrue(row["canBrowse"])
        listing = service.list_directory(row["id"], inventory["inventoryRevision"])
        self.assertIn(MANIFEST_FILENAME, [item["name"] for item in listing["items"]])
        with self.assertRaisesRegex(ValueError, "governed by the project menu"):
            service.set_connected(row["path"], False)
        with self.assertRaisesRegex(ValueError, "never ignored"):
            service.set_ignored(row["path"], True)

    def test_registry_rejects_traversal_record_without_touching_target(self):
        payload = {
            "schemaVersion": REGISTRY_SCHEMA_VERSION,
            "parentBrainId": "brain_invalid",
            "projects": {
                f"codex:{PROJECT_A}": {
                    "provider": "codex",
                    "projectId": PROJECT_A,
                    "label": "Escape",
                    "directoryName": "../../outside",
                    "brainId": "brain_invalid",
                    "parentBrainId": "brain_invalid",
                    "lifecycleState": "active",
                    "createdAt": "2026-08-20T00:00:00Z",
                    "updatedAt": "2026-08-20T00:00:00Z",
                }
            },
        }
        registry_path = self.projects / REGISTRY_FILENAME
        registry_path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(registry_path, 0o600)
        failed = self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        self.assertFalse(failed["ok"])
        self.assertIn(failed["code"], {"registry_parent_mismatch", "registry_corrupt"})
        self.assertFalse((self.home.parent / "outside").exists())

    def test_atomic_child_publish_preserves_competitor_inode_on_absence_race(self):
        real_publish = project_brains._rename_directory_noreplace
        observed = {}

        def racing_publish(parent_fd, temporary, final_name):
            competitor = self.projects / final_name
            competitor.mkdir(mode=0o700)
            sentinel = competitor / "competitor.txt"
            sentinel.write_text("competitor survives", encoding="utf-8")
            observed.update({
                "path": competitor,
                "inode": competitor.stat().st_ino,
                "sentinel": sentinel,
            })
            return real_publish(parent_fd, temporary, final_name)

        with patch("project_brains._rename_directory_noreplace", side_effect=racing_publish):
            result = self.registry.sync([
                self._project("codex", PROJECT_A, "Activity Monitor")
            ])

        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["errors"][0]["code"], "child_path_conflict")
        self.assertEqual(observed["path"].stat().st_ino, observed["inode"])
        self.assertEqual(observed["sentinel"].read_text(encoding="utf-8"), "competitor survives")

    def _metadata_swap_hook(self, target_name, sentinel):
        real_exchange = project_brains._rename_file_exchange
        observed = {}

        def racing_exchange(parent_fd, temporary, final_name):
            if final_name == target_name and not observed:
                backup = final_name + ".raced-original"
                os.rename(final_name, backup, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                descriptor = os.open(
                    final_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=parent_fd,
                )
                try:
                    os.write(descriptor, sentinel)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                metadata = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
                observed.update({"inode": metadata.st_ino, "performed": True})
            return real_exchange(parent_fd, temporary, final_name)

        return observed, racing_exchange

    def test_registry_commit_is_identity_conditional_and_preserves_swapped_inode(self):
        self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        sentinel = b'{"competitor":"registry-race"}\n'
        observed, hook = self._metadata_swap_hook(REGISTRY_FILENAME, sentinel)
        with patch("project_brains._rename_file_exchange", side_effect=hook):
            result = self.registry.sync([
                self._project("codex", PROJECT_A, "Renamed Activity Monitor")
            ])
        target = self.projects / REGISTRY_FILENAME
        self.assertTrue(observed["performed"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "metadata_identity_changed")
        self.assertEqual(target.stat().st_ino, observed["inode"])
        self.assertEqual(target.read_bytes(), sentinel)

    def test_marker_commit_is_identity_conditional_and_preserves_swapped_inode(self):
        first = self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        child = Path(first["children"][0]["path"])
        sentinel = b'{"competitor":"marker-race"}\n'
        observed, hook = self._metadata_swap_hook(MARKER_FILENAME, sentinel)
        with patch("project_brains._rename_file_exchange", side_effect=hook):
            result = self.registry.sync([
                self._project("codex", PROJECT_A, "Renamed Activity Monitor")
            ])
        target = child / MARKER_FILENAME
        self.assertTrue(observed["performed"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["errors"][0]["code"], "metadata_identity_changed")
        self.assertEqual(target.stat().st_ino, observed["inode"])
        self.assertEqual(target.read_bytes(), sentinel)

    def test_manifest_commit_is_identity_conditional_and_preserves_swapped_inode(self):
        first = self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        child = Path(first["children"][0]["path"])
        sentinel = b"competitor manifest race\n"
        observed, hook = self._metadata_swap_hook(MANIFEST_FILENAME, sentinel)
        with patch("project_brains._rename_file_exchange", side_effect=hook):
            result = self.registry.sync([
                self._project("codex", PROJECT_A, "Renamed Activity Monitor")
            ])
        target = child / MANIFEST_FILENAME
        self.assertTrue(observed["performed"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["errors"][0]["code"], "metadata_identity_changed")
        self.assertEqual(target.stat().st_ino, observed["inode"])
        self.assertEqual(target.read_bytes(), sentinel)

    def test_sensitive_labels_are_redacted_before_every_persisted_projection(self):
        path_canary = "/Users/customer/Private/repository"
        secret_canary = "api-key sk-fixture-credential"
        result = self.registry.sync([
            self._project("codex", PROJECT_A, path_canary),
            self._project("claude", CLAUDE_A, secret_canary),
        ])
        self.assertTrue(result["ok"])
        self.assertFalse(result["privacy"]["repositoryPathsStored"])
        self.assertTrue(result["privacy"]["labelsSanitized"])
        self.assertNotIn("path", result["privacy"]["persistedFields"])
        self.assertNotIn("credential", result["privacy"]["persistedFields"])

        persisted = [(self.projects / REGISTRY_FILENAME).read_bytes()]
        for child in result["children"]:
            child_path = Path(child["path"])
            persisted.extend([
                (child_path / MARKER_FILENAME).read_bytes(),
                (child_path / MANIFEST_FILENAME).read_bytes(),
            ])
            self.assertNotEqual(child["label"], path_canary)
            self.assertNotEqual(child["label"], secret_canary)
        raw = b"\n".join(persisted).decode("utf-8")
        self.assertNotIn(path_canary, raw)
        self.assertNotIn(secret_canary, raw)
        self.assertNotIn("sk-fixture-credential", raw)

    def test_credential_shapes_are_redacted_with_value_derived_privacy_truth(self):
        sensitive = [
            ("local-cccccccccccccccccccccccccccccccc", "Production AKIAIOSFODNN7EXAMPLE"),
            ("local-dddddddddddddddddddddddddddddddd", "release " + "gh" + "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # built at runtime: not a committed token literal),
            (
                "local-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "alerts " + "xo" + "xb-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
            ),
            ("local-ffffffffffffffffffffffffffffffff", "/Users/customer/Private/repository"),
            ("local-11111111111111111111111111111111", "production api-key fixture-value"),
            ("local-22222222222222222222222222222222", "client_secret fixture-only-value"),
        ]
        ordinary = [
            ("local-33333333333333333333333333333333", "Cybersecurity Operations"),
            ("local-44444444444444444444444444444444", "KE Guard"),
            ("local-55555555555555555555555555555555", "Cyber Defense"),
        ]
        projects = [self._project("codex", project_id, label) for project_id, label in sensitive + ordinary]
        result = self.registry.sync(projects)

        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["privacy"]["labelPolicyVersion"], LABEL_POLICY_VERSION)
        self.assertTrue(result["privacy"]["persistedValuesValidated"])
        self.assertTrue(result["privacy"]["labelsSanitized"])
        self.assertFalse(result["privacy"]["credentialsStored"])
        self.assertFalse(result["privacy"]["repositoryPathsStored"])
        self.assertEqual(result["privacy"]["persistedLabelCount"], len(projects))

        children = {child["projectId"]: child for child in result["children"]}
        directory_names = "\n".join(Path(child["path"]).name for child in result["children"]).casefold()
        surfaces = {"registry": (self.projects / REGISTRY_FILENAME).read_text(encoding="utf-8")}
        for child in result["children"]:
            child_path = Path(child["path"])
            surfaces[f"marker:{child['projectId']}"] = (child_path / MARKER_FILENAME).read_text(encoding="utf-8")
            surfaces[f"manifest:{child['projectId']}"] = (child_path / MANIFEST_FILENAME).read_text(encoding="utf-8")
        all_persisted = "\n".join(surfaces.values()).casefold()

        for project_id, raw_label in sensitive:
            key = f"codex:{project_id}"
            fallback = f"Codex project · {hashlib.sha256(key.encode('utf-8')).hexdigest()[:8]}"
            self.assertEqual(children[project_id]["label"], fallback)
            self.assertNotIn(raw_label.casefold(), all_persisted)
            self.assertNotIn(raw_label.casefold(), directory_names)
            slug = re.sub(r"[^a-z0-9]+", "-", raw_label.casefold()).strip("-")[:48]
            self.assertNotIn(slug, directory_names)
            self.assertNotIn(slug, all_persisted)

        for project_id, ordinary_label in ordinary:
            child = children[project_id]
            self.assertEqual(child["label"], ordinary_label)
            self.assertIn(ordinary_label.casefold(), all_persisted)
            expected_slug = re.sub(r"[^a-z0-9]+", "-", ordinary_label.casefold()).strip("-")
            self.assertTrue(Path(child["path"]).name.startswith(expected_slug + "--"))

        snapshot = self.registry.snapshot()
        self.assertTrue(snapshot["ok"])
        self.assertTrue(snapshot["privacy"]["persistedValuesValidated"])
        self.assertTrue(snapshot["privacy"]["labelsSanitized"])
        self.assertFalse(snapshot["privacy"]["credentialsStored"])

        # A credential-shaped value introduced outside the governed writer is
        # rejected on read, and the public projection becomes conservative
        # instead of repeating an unverified privacy claim.
        registry_path = self.projects / REGISTRY_FILENAME
        injected = json.loads(registry_path.read_text(encoding="utf-8"))
        injected["projects"]["codex:local-33333333333333333333333333333333"]["label"] = sensitive[0][1]
        registry_path.write_text(json.dumps(injected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(registry_path, 0o600)
        failed_closed = self.registry.snapshot()
        self.assertFalse(failed_closed["ok"])
        self.assertEqual(failed_closed["state"], "unavailable")
        self.assertFalse(failed_closed["privacy"]["persistedValuesValidated"])
        self.assertFalse(failed_closed["privacy"]["labelsSanitized"])
        self.assertTrue(failed_closed["privacy"]["credentialsStored"])

    def test_restart_snapshot_fails_closed_on_marker_credential_corruption(self):
        created = self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        marker_path = Path(created["children"][0]["path"]) / MARKER_FILENAME
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        marker["label"] = "Production AKIAIOSFODNN7EXAMPLE"
        marker_path.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(marker_path, 0o600)

        snapshot = self._assert_snapshot_persistence_untrusted()
        self.assertEqual(snapshot["children"][0]["errorCode"], "child_marker_mismatch")
        self.assertFalse(snapshot["children"][0]["accessible"])

    def test_restart_snapshot_fails_closed_on_manifest_credential_corruption(self):
        created = self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        manifest_path = Path(created["children"][0]["path"]) / MANIFEST_FILENAME
        manifest_path.write_bytes(
            manifest_path.read_bytes() + b"\ncredential-canary: AKIAIOSFODNN7EXAMPLE\n"
        )
        os.chmod(manifest_path, 0o600)

        snapshot = self._assert_snapshot_persistence_untrusted()
        self.assertEqual(snapshot["children"][0]["errorCode"], "child_manifest_mismatch")
        self.assertFalse(snapshot["children"][0]["accessible"])

    def test_snapshot_surface_trust_failures_are_nofollow_bounded_and_fd_clean(self):
        created = self.registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
        child = Path(created["children"][0]["path"])
        marker_path = child / MARKER_FILENAME
        manifest_path = child / MANIFEST_FILENAME
        marker_bytes = marker_path.read_bytes()
        manifest_bytes = manifest_path.read_bytes()

        def restore(path, payload):
            if path.is_symlink() or path.exists():
                path.unlink()
            path.write_bytes(payload)
            os.chmod(path, 0o600)

        marker_path.write_bytes(b"{malformed")
        os.chmod(marker_path, 0o600)
        malformed = self._assert_snapshot_persistence_untrusted()
        self.assertIn(malformed["children"][0]["errorCode"], {"child_marker_mismatch", "metadata_untrusted"})
        restore(marker_path, marker_bytes)

        manifest_path.write_bytes(b"X" * (MAX_MANIFEST_BYTES + 1))
        os.chmod(manifest_path, 0o600)
        oversized = self._assert_snapshot_persistence_untrusted()
        self.assertEqual(oversized["children"][0]["errorCode"], "metadata_untrusted")
        restore(manifest_path, manifest_bytes)

        identity_mismatch = json.loads(marker_bytes.decode("utf-8"))
        identity_mismatch["brainId"] = "brain_project_competitor"
        marker_path.write_text(json.dumps(identity_mismatch, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(marker_path, 0o600)
        mismatched = self._assert_snapshot_persistence_untrusted()
        self.assertEqual(mismatched["children"][0]["errorCode"], "child_marker_mismatch")
        restore(marker_path, marker_bytes)

        marker_path.chmod(0o644)
        insecure = self._assert_snapshot_persistence_untrusted()
        self.assertEqual(insecure["children"][0]["errorCode"], "metadata_untrusted")
        marker_path.chmod(0o600)

        outside = self.home / "outside-marker.json"
        outside_canary = "outside-private-AKIAIOSFODNN7EXAMPLE"
        outside.write_text(json.dumps({"label": outside_canary}), encoding="utf-8")
        os.chmod(outside, 0o600)
        marker_path.unlink()
        marker_path.symlink_to(outside)
        symlinked = self._assert_snapshot_persistence_untrusted()
        serialized = json.dumps(symlinked, sort_keys=True)
        self.assertNotIn(outside_canary, serialized)
        self.assertNotIn(str(outside), serialized)
        self.assertEqual(symlinked["children"][0]["errorCode"], "metadata_corrupt")

    def test_snapshot_detects_marker_and_manifest_inode_swaps_without_fd_leaks(self):
        for surface in (MARKER_FILENAME, MANIFEST_FILENAME):
            with self.subTest(surface=surface), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                parent = home / ".grokcode" / "brain"
                projects = parent / "GrokCode" / "Projects"
                (parent / ".obsidian").mkdir(parents=True, mode=0o700)
                projects.mkdir(parents=True, mode=0o700)
                for path in (home, parent.parent, parent, parent / "GrokCode", projects):
                    os.chmod(path, 0o700)
                registry = ProjectBrainRegistry(home=home)
                created = registry.sync([self._project("codex", PROJECT_A, "Activity Monitor")])
                child = Path(created["children"][0]["path"])
                target = child / surface
                original_bytes = target.read_bytes()
                real_read = ProjectBrainRegistry._read_regular_bytes_with_fingerprint
                observed = {}

                def swapping_read(parent_fd, name, *, max_bytes, required_mode=0o600):
                    payload, fingerprint = real_read(
                        parent_fd,
                        name,
                        max_bytes=max_bytes,
                        required_mode=required_mode,
                    )
                    if name == surface and not observed:
                        backup = surface + ".snapshot-original"
                        os.rename(surface, backup, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                        descriptor = os.open(
                            surface,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                            0o600,
                            dir_fd=parent_fd,
                        )
                        try:
                            os.write(descriptor, payload)
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                        metadata = os.stat(surface, dir_fd=parent_fd, follow_symlinks=False)
                        observed.update({"performed": True, "inode": metadata.st_ino})
                    return payload, fingerprint

                before_fds = len(os.listdir("/dev/fd"))
                with patch.object(
                    ProjectBrainRegistry,
                    "_read_regular_bytes_with_fingerprint",
                    side_effect=swapping_read,
                ):
                    snapshot = ProjectBrainRegistry(home=home).snapshot()
                after_fds = len(os.listdir("/dev/fd"))
                self.assertTrue(observed["performed"])
                self.assertFalse(snapshot["ok"])
                self.assertEqual(snapshot["state"], "unavailable")
                self.assertFalse(snapshot["privacy"]["persistedValuesValidated"])
                self.assertFalse(snapshot["privacy"]["labelsSanitized"])
                self.assertTrue(snapshot["privacy"]["credentialsStored"])
                self.assertEqual(target.stat().st_ino, observed["inode"])
                self.assertEqual(target.read_bytes(), original_bytes)
                self.assertEqual(after_fds, before_fds)


if __name__ == "__main__":
    unittest.main()
