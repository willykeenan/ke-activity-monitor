import json
from pathlib import Path
import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

import activity_monitor
from brain_discovery import BrainService, SCHEMA_VERSION


class BrainDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.settings = self.home / "settings" / "brain-settings.json"
        self.service = BrainService(
            home=self.home,
            settings_path=self.settings,
            scan_roots=[self.home],
            scan_seconds=2.0,
            max_directories=5000,
        )
        self.spotlight = patch.object(self.service, "_spotlight_paths", return_value=[])
        self.spotlight.start()

    def tearDown(self):
        self.spotlight.stop()
        self.temporary.cleanup()

    def _scan(self):
        return self.service.scan(force=True)

    def _connected_vault(self, name="Private Vault"):
        vault = self.home / "Documents" / name
        (vault / ".obsidian").mkdir(parents=True)
        inventory = self._scan()
        row = next(brain for brain in inventory["brains"] if brain["path"] == str(vault.resolve()))
        inventory = self.service.set_connected(row["path"], True)
        row = next(brain for brain in inventory["brains"] if brain["id"] == row["id"])
        return vault, row, inventory

    def test_repair_connection_requires_exact_root_and_rebinds_once(self):
        vault, row, _inventory = self._connected_vault("Repair Vault")
        disconnected = self.service.set_connected(row["path"], False)
        current = next(item for item in disconnected["brains"] if item["id"] == row["id"])
        self.assertFalse(current["canBrowse"])
        with self.assertRaisesRegex(ValueError, "exact Brain folder"):
            self.service.repair_connection(row["path"], str(vault.parent))
        repaired = self.service.repair_connection(row["path"], row["path"])
        rebound = next(item for item in repaired["brains"] if item["id"] == row["id"])
        self.assertEqual(rebound["status"], "connected")
        self.assertTrue(rebound["canBrowse"])
        self.assertFalse(repaired["privacy"]["noteBodiesRead"])

    def test_fingerprints_real_brains_and_excludes_name_only_dependencies(self):
        ke_brain = self.home / ".grokcode" / "brain"
        (ke_brain / ".obsidian").mkdir(parents=True)
        (ke_brain / "GrokCode").mkdir()
        (ke_brain / "GrokCode" / "Decision.md").write_text("private body")

        obsidian = self.home / "Documents" / "Research Vault"
        (obsidian / ".obsidian").mkdir(parents=True)
        (obsidian / "Notes").mkdir()
        (obsidian / "Notes" / "One.md").write_text("one")
        (obsidian / "Two.canvas").write_text("{}")

        codex = self.home / ".codex" / "memories"
        codex.mkdir(parents=True)
        (codex / "MEMORY.md").write_text("registry")

        claude = self.home / ".claude" / "projects" / "project-a" / "memory"
        claude.mkdir(parents=True)

        vector = self.home / "Nova" / "brain"
        vector.mkdir(parents=True)
        (vector / "chroma.sqlite3").write_bytes(b"not opened")

        false_memory = self.home / "App" / "node_modules" / "library" / "memory"
        false_memory.mkdir(parents=True)
        (false_memory / "index.js").write_text("module.exports = {}")

        payload = self._scan()
        by_type = {brain["type"]: brain for brain in payload["brains"]}
        self.assertEqual(payload["schemaVersion"], SCHEMA_VERSION)
        self.assertIn("KE Brain", by_type)
        self.assertEqual(by_type["KE Brain"]["status"], "connected")
        self.assertIn("Obsidian vault", by_type)
        self.assertEqual(by_type["Obsidian vault"]["noteCount"], 2)
        self.assertIn("Codex memory", by_type)
        self.assertFalse(by_type["Codex memory"]["canStructure"])
        self.assertIn("Claude memory", by_type)
        self.assertFalse(by_type["Claude memory"]["canStructure"])
        self.assertIn("Vector brain", by_type)
        self.assertNotIn(str(false_memory), {brain["path"] for brain in payload["brains"]})
        self.assertFalse(payload["privacy"]["noteBodiesRead"])
        self.assertFalse(payload["scan"]["contentRead"])

    def test_scan_never_opens_note_bodies(self):
        vault = self.home / "Documents" / "Private Vault"
        (vault / ".obsidian").mkdir(parents=True)
        note = vault / "Secret.md"
        note.write_text("must not be opened")
        original_open = Path.open

        def guarded_open(path, *args, **kwargs):
            if Path(path) == note:
                raise AssertionError("note body was opened")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", guarded_open):
            payload = self._scan()
        row = next(brain for brain in payload["brains"] if brain["path"] == str(vault.resolve()))
        self.assertEqual(row["noteCount"], 1)

    def test_external_spotlight_markers_are_surfaced_without_opening_volumes(self):
        external_vault = Path("/Volumes/Unavailable/Private Vault")
        external_name_only = Path("/Volumes/Unavailable/brain")
        hits = [
            {"path": external_vault, "marker": ".obsidian"},
            {"path": external_name_only, "marker": "name-only"},
        ]
        original_scandir = os.scandir

        def guarded_scandir(path):
            if str(path).startswith("/Volumes/"):
                raise AssertionError("external volume was opened")
            return original_scandir(path)

        with patch.object(self.service, "_spotlight_paths", return_value=hits), patch(
            "brain_discovery.os.scandir", side_effect=guarded_scandir
        ):
            started = time.monotonic()
            payload = self._scan()
        self.assertLess(time.monotonic() - started, 2.0)
        paths = {brain["path"]: brain for brain in payload["brains"]}
        self.assertIn(str(external_vault), paths)
        self.assertTrue(paths[str(external_vault)]["indexedOnly"])
        self.assertFalse(paths[str(external_vault)]["canStructure"])
        self.assertNotIn(str(external_name_only), paths)
        self.assertEqual(payload["scan"]["externalDirectoriesOpened"], 0)
        self.assertEqual(payload["scan"]["externalNameOnlyRejected"], 1)

    def test_default_direct_scan_scope_never_enumerates_volumes(self):
        service = BrainService(home=self.home, settings_path=self.settings, scan_seconds=0.5)
        with patch.object(Path, "iterdir", side_effect=AssertionError("/Volumes enumerated")):
            self.assertEqual(service._default_scan_roots(), [service.home])

    def test_connect_ignore_and_offline_states_are_truthful(self):
        vault = self.home / "Documents" / "Work Vault"
        (vault / ".obsidian").mkdir(parents=True)
        first = self._scan()
        row = next(brain for brain in first["brains"] if brain["path"] == str(vault.resolve()))
        self.assertEqual(row["status"], "discovered")

        connected = self.service.set_connected(str(vault), True)
        row = next(brain for brain in connected["brains"] if brain["path"] == str(vault.resolve()))
        self.assertEqual(row["status"], "connected")

        ignored = self.service.set_ignored(str(vault), True)
        row = next(brain for brain in ignored["brains"] if brain["path"] == str(vault.resolve()))
        self.assertEqual(row["status"], "ignored")

        self.service.set_ignored(str(vault), False)
        self.service.set_connected(str(vault), True)
        shutil.rmtree(vault)
        offline = self._scan()
        row = next(brain for brain in offline["brains"] if brain["path"] == str(vault.resolve()))
        self.assertEqual(row["status"], "offline")

    def test_create_brain_is_explicit_connected_and_obsidian_compatible(self):
        result = self.service.create_brain("Client Brain")
        target = Path(result["createdPath"])
        self.assertTrue((target / ".obsidian").is_dir())
        self.assertTrue((target / "Inbox").is_dir())
        self.assertTrue((target / "Archive").is_dir())
        self.assertTrue((target / "README.md").is_file())
        row = next(brain for brain in result["inventory"]["brains"] if brain["path"] == str(target))
        self.assertEqual(row["status"], "connected")

    def test_structure_requires_preview_confirmation_backup_and_rolls_back(self):
        vault = self.home / "Documents" / "Unstructured Vault"
        (vault / ".obsidian").mkdir(parents=True)
        (vault / "Existing.md").write_text("leave me in place")
        self._scan()
        preview = self.service.preview_structure(str(vault))
        self.assertEqual(preview["moveFiles"], [])
        self.assertEqual(preview["deleteFiles"], [])
        self.assertIn(str((vault / "Inbox").resolve()), preview["createDirectories"])
        with self.assertRaisesRegex(ValueError, "confirmation"):
            self.service.apply_structure(preview["previewId"], "NO")

        applied = self.service.apply_structure(preview["previewId"], "APPLY")
        self.assertTrue(Path(applied["backupManifest"]).is_file())
        self.assertTrue((vault / "Inbox").is_dir())
        self.assertTrue((vault / "Existing.md").is_file())
        with Path(applied["backupManifest"]).open(encoding="utf-8") as handle:
            manifest = json.load(handle)
        self.assertFalse(manifest["existingContentMoved"])
        self.assertFalse(manifest["noteBodiesRead"])

        rolled_back = self.service.rollback_structure(applied["operationId"])
        self.assertTrue(rolled_back["ok"])
        self.assertFalse((vault / "Inbox").exists())
        self.assertTrue((vault / "Existing.md").is_file())

    def test_rollback_preserves_any_user_content_added_after_structure(self):
        vault = self.home / "Documents" / "Safe Vault"
        (vault / ".obsidian").mkdir(parents=True)
        self._scan()
        preview = self.service.preview_structure(str(vault))
        applied = self.service.apply_structure(preview["previewId"], "APPLY")
        note = vault / "Inbox" / "New.md"
        note.write_text("user content")
        rollback = self.service.rollback_structure(applied["operationId"])
        self.assertFalse(rollback["ok"])
        self.assertIn(str((vault / "Inbox").resolve()), rollback["retainedDirectories"])
        self.assertEqual(note.read_text(), "user content")

    def test_browser_maps_exact_current_brain_id_and_rejects_stale_inventory(self):
        alpha, alpha_row, first = self._connected_vault("Alpha Vault")
        beta, beta_row, second = self._connected_vault("Beta Vault")
        (alpha / "Same.md").write_text("alpha exact body", encoding="utf-8")
        (beta / "Same.md").write_text("beta exact body", encoding="utf-8")
        current = self._scan()
        revision = current["inventoryRevision"]
        alpha_id = next(row["id"] for row in current["brains"] if row["path"] == str(alpha.resolve()))
        beta_id = next(row["id"] for row in current["brains"] if row["path"] == str(beta.resolve()))

        self.assertEqual(self.service.open_note(alpha_id, revision, "Same.md")["body"], "alpha exact body")
        self.assertEqual(self.service.open_note(beta_id, revision, "Same.md")["body"], "beta exact body")
        self.assertNotEqual(alpha_id, beta_id)

        changed = self.service.set_ignored(str(beta), True)
        self.assertNotEqual(changed["inventoryRevision"], revision)
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            self.service.list_directory(alpha_id, revision)
        self.assertEqual(
            self.service.list_directory(alpha_id, changed["inventoryRevision"])["brainId"],
            alpha_id,
        )

    def test_browser_requires_connected_local_access_and_fails_closed_for_other_states(self):
        vault = self.home / "Documents" / "Discovered Vault"
        (vault / ".obsidian").mkdir(parents=True)
        inventory = self._scan()
        row = next(brain for brain in inventory["brains"] if brain["path"] == str(vault.resolve()))
        with self.assertRaisesRegex(ValueError, "Connect this Brain"):
            self.service.list_directory(row["id"], inventory["inventoryRevision"])

        connected = self.service.set_connected(str(vault), True)
        row = next(brain for brain in connected["brains"] if brain["path"] == str(vault.resolve()))
        disconnected = self.service.set_connected(str(vault), False)
        disconnected_row = next(brain for brain in disconnected["brains"] if brain["id"] == row["id"])
        with self.assertRaisesRegex(ValueError, "Connect this Brain"):
            self.service.list_directory(disconnected_row["id"], disconnected["inventoryRevision"])
        self.service.set_connected(str(vault), True)
        ignored = self.service.set_ignored(str(vault), True)
        with self.assertRaisesRegex(ValueError, "ignored"):
            self.service.list_directory(row["id"], ignored["inventoryRevision"])

        self.service.set_ignored(str(vault), False)
        self.service.set_connected(str(vault), True)
        shutil.rmtree(vault)
        offline = self._scan()
        offline_row = next(brain for brain in offline["brains"] if brain["id"] == row["id"])
        with self.assertRaisesRegex(ValueError, "offline"):
            self.service.list_directory(offline_row["id"], offline["inventoryRevision"])

        external = Path("/Volumes/Unavailable/Indexed Vault")
        with patch.object(self.service, "_spotlight_paths", return_value=[{"path": external, "marker": ".obsidian"}]):
            indexed = self._scan()
        indexed_row = next(brain for brain in indexed["brains"] if brain["path"] == str(external))
        with self.assertRaisesRegex(ValueError, "Spotlight-indexed only"):
            self.service.list_directory(indexed_row["id"], indexed["inventoryRevision"])

        denied_root = self.home / "Locked" / "brain"
        denied_root.mkdir(parents=True)
        original_directory_names = self.service._directory_names

        def permission_boundary(path):
            if Path(path) == denied_root:
                raise PermissionError("denied")
            return original_directory_names(path)

        with patch.object(self.service, "_directory_names", side_effect=permission_boundary):
            denied = self._scan()
        denied_row = next(brain for brain in denied["brains"] if brain["path"] == str(denied_root.resolve()))
        with self.assertRaisesRegex(ValueError, "permission was denied"):
            self.service.list_directory(denied_row["id"], denied["inventoryRevision"])

    def test_directory_listing_is_metadata_only_and_note_body_requires_exact_open(self):
        vault, row, inventory = self._connected_vault()
        folder = vault / "Projects"
        folder.mkdir()
        note = folder / "Decision.md"
        note.write_text("selected only after click", encoding="utf-8")

        original_path_open = Path.open

        def guarded_path_open(path, *args, **kwargs):
            if Path(path) == note:
                raise AssertionError("note body opened during list")
            return original_path_open(path, *args, **kwargs)

        with patch.object(Path, "open", guarded_path_open):
            root_listing = self.service.list_directory(row["id"], inventory["inventoryRevision"])
            folder_listing = self.service.list_directory(row["id"], inventory["inventoryRevision"], "Projects")
        self.assertFalse(root_listing["privacy"]["noteBodiesRead"])
        self.assertEqual(root_listing["items"][0]["kind"], "folder")
        self.assertEqual(folder_listing["items"][0]["relativePath"], "Projects/Decision.md")
        self.assertNotIn("body", folder_listing["items"][0])

        opened = self.service.open_note(row["id"], inventory["inventoryRevision"], "Projects/Decision.md")
        self.assertEqual(opened["body"], "selected only after click")
        self.assertTrue(opened["privacy"]["selectedBodyRead"])
        self.assertEqual(opened["renderMode"], "plain-text")

    def test_directory_navigation_breadcrumbs_sorting_pagination_and_bounds(self):
        vault, row, inventory = self._connected_vault("Large Vault")
        (vault / "Zulu").mkdir()
        (vault / "Alpha").mkdir()
        for index in range(1002):
            (vault / f"Note-{index:04d}.md").touch()

        listing = self.service.list_directory(row["id"], inventory["inventoryRevision"], page_size=3)
        self.assertEqual([item["name"] for item in listing["items"]], [".obsidian", "Alpha", "Zulu"])
        self.assertEqual(listing["countState"], "bounded")
        self.assertIsNone(listing["itemCount"])
        self.assertEqual(listing["boundedItemCount"], 1000)
        self.assertTrue(listing["hasMore"])
        page_two = self.service.list_directory(row["id"], inventory["inventoryRevision"], page=1, page_size=3)
        self.assertTrue(all(item["kind"] == "file" for item in page_two["items"]))

        nested = vault / "Alpha" / "Nested"
        nested.mkdir()
        inside = self.service.list_directory(row["id"], inventory["inventoryRevision"], "Alpha/Nested")
        self.assertEqual(inside["parentPath"], "Alpha")
        self.assertEqual(
            [crumb["relativePath"] for crumb in inside["breadcrumbs"]],
            ["", "Alpha", "Alpha/Nested"],
        )

    def test_traversal_absolute_paths_and_symlinks_fail_closed(self):
        vault, row, inventory = self._connected_vault("Contained Vault")
        outside = self.home / "outside.md"
        outside.write_text("must stay outside", encoding="utf-8")
        (vault / "escape.md").symlink_to(outside)
        revision = inventory["inventoryRevision"]

        for unsafe in ("../outside.md", str(outside), "C:/outside.md"):
            with self.subTest(unsafe=unsafe), self.assertRaisesRegex(ValueError, "root-relative|escapes"):
                self.service.open_note(row["id"], revision, unsafe)
        with self.assertRaisesRegex(ValueError, "Symbolic links"):
            self.service.open_note(row["id"], revision, "escape.md")
        listing = self.service.list_directory(row["id"], revision)
        symlink = next(item for item in listing["items"] if item["name"] == "escape.md")
        self.assertFalse(symlink["openable"])
        self.assertIn("Symbolic", symlink["restriction"])

    def test_directory_listing_is_descriptor_bound_across_nested_symlink_swap(self):
        vault, row, inventory = self._connected_vault("Race Vault")
        folder = vault / "Folder"
        folder.mkdir()
        (folder / "inside.md").write_text("inside", encoding="utf-8")
        outside = self.home / "Outside"
        outside.mkdir()
        (outside / "outside-secret.md").write_text("outside", encoding="utf-8")
        original_folder = vault / "Folder-original"
        original_resolver = self.service._resolve_browser_target
        swapped = {"performed": False}

        def swapping_resolver(root, relative_path, *, expected):
            resolved = original_resolver(root, relative_path, expected=expected)
            folder.rename(original_folder)
            folder.symlink_to(outside, target_is_directory=True)
            swapped["performed"] = True
            return resolved

        with patch.object(self.service, "_resolve_browser_target", side_effect=swapping_resolver):
            with self.assertRaisesRegex(ValueError, "changed|securely") as raised:
                self.service.list_directory(
                    row["id"],
                    inventory["inventoryRevision"],
                    "Folder",
                )
        self.assertTrue(swapped["performed"])
        self.assertNotIn("outside-secret.md", str(raised.exception))

    def test_directory_listing_rejects_root_replacement_and_closes_descriptors(self):
        vault, row, inventory = self._connected_vault("Root Race Vault")
        (vault / "inside.md").write_text("inside", encoding="utf-8")
        outside = self.home / "Outside Root"
        outside.mkdir()
        (outside / "outside-secret.md").write_text("outside", encoding="utf-8")
        original_vault = vault.with_name("Root Race Vault-original")
        original_resolver = self.service._resolve_browser_target
        real_open = os.open
        real_close = os.close
        opened = []
        closed = []
        swapped = {"performed": False}

        def tracked_open(path, flags, mode=0o777, *, dir_fd=None):
            if dir_fd is None:
                descriptor = real_open(path, flags, mode)
            else:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            opened.append(descriptor)
            return descriptor

        def tracked_close(descriptor):
            closed.append(descriptor)
            return real_close(descriptor)

        def swapping_resolver(root, relative_path, *, expected):
            resolved = original_resolver(root, relative_path, expected=expected)
            vault.rename(original_vault)
            vault.symlink_to(outside, target_is_directory=True)
            swapped["performed"] = True
            return resolved

        with patch.object(self.service, "_resolve_browser_target", side_effect=swapping_resolver), patch(
            "brain_discovery.os.open", side_effect=tracked_open
        ), patch("brain_discovery.os.close", side_effect=tracked_close):
            with self.assertRaisesRegex(ValueError, "changed|securely") as raised:
                self.service.list_directory(row["id"], inventory["inventoryRevision"])
        self.assertTrue(swapped["performed"])
        self.assertNotIn("outside-secret.md", str(raised.exception))
        self.assertEqual(len(opened), len(closed))
        self.assertCountEqual(opened, closed)

    def test_directory_listing_fails_closed_without_secure_platform_support(self):
        vault, row, inventory = self._connected_vault("Portable Vault")
        (vault / "Note.md").write_text("body", encoding="utf-8")
        with patch("brain_discovery._OPENAT_DIRECTORY_SUPPORTED", False), patch(
            "brain_discovery.os.scandir",
            side_effect=AssertionError("pathname listing must not be used as an insecure fallback"),
        ):
            with self.assertRaisesRegex(ValueError, "unavailable on this platform"):
                self.service.list_directory(row["id"], inventory["inventoryRevision"])
        with patch("brain_discovery.os.open", side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(ValueError, "permission was denied"):
                self.service.list_directory(row["id"], inventory["inventoryRevision"])
        self.assertNotIn("rootIdentity", row)

    def test_sensitive_binary_oversized_invalid_and_unreadable_notes_fail_closed(self):
        vault, row, inventory = self._connected_vault("Restricted Vault")
        (vault / "credentials.md").write_text("token=secret", encoding="utf-8")
        (vault / "image.png").write_bytes(b"png")
        (vault / "too-large.md").write_bytes(b"x" * (1024 * 1024 + 1))
        (vault / "invalid.md").write_bytes(b"\xff\xfe")
        (vault / "binary.md").write_bytes(b"text\x00binary")
        (vault / "unreadable.md").write_text("permission", encoding="utf-8")
        (vault / "auth").mkdir()
        (vault / "auth" / "session.md").write_text("auth store", encoding="utf-8")
        revision = inventory["inventoryRevision"]

        failures = {
            "credentials.md": "Credential-like",
            "image.png": "file type",
            "too-large.md": "too large",
            "invalid.md": "valid UTF-8",
            "binary.md": "Binary files",
            "auth/session.md": "Credential-like",
        }
        for relative, message in failures.items():
            with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, message):
                self.service.open_note(row["id"], revision, relative)
        with patch("brain_discovery.os.open", side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(ValueError, "permission was denied"):
                self.service.open_note(row["id"], revision, "unreadable.md")

    def test_connected_brain_allows_cybersecurity_topics_without_retrust(self):
        vault, row, inventory = self._connected_vault("Cyber Brain")
        cyber_folder = vault / "Cybersecurity"
        cyber_folder.mkdir()
        note = cyber_folder / "Cyber Defense.md"
        note.write_text("Local defensive research notes.", encoding="utf-8")
        revision = inventory["inventoryRevision"]

        root = self.service.list_directory(row["id"], revision)
        self.assertIn("Cybersecurity", {item["name"] for item in root["items"]})
        folder = self.service.list_directory(row["id"], revision, "Cybersecurity")
        self.assertIn("Cyber Defense.md", {item["name"] for item in folder["items"]})

        opened = self.service.open_note(row["id"], revision, "Cybersecurity/Cyber Defense.md")
        self.assertEqual(opened["body"], "Local defensive research notes.")
        self.assertEqual(opened["relativePath"], "Cybersecurity/Cyber Defense.md")

    def test_selected_note_body_is_never_persisted_to_settings_logs_or_history(self):
        vault, row, inventory = self._connected_vault("Ephemeral Vault")
        note = vault / "Only.md"
        secret = "ephemeral-selected-body-93b62"
        note.write_text(secret, encoding="utf-8")
        dispatch_history = self.home / "settings" / "dispatch-history.json"
        runtime_log = self.home / "settings" / "activity-monitor.log"
        dispatch_history.write_text('{"history":[]}', encoding="utf-8")
        runtime_log.write_text("viewer ready", encoding="utf-8")
        settings_before = self.settings.read_bytes()

        opened = self.service.open_note(row["id"], inventory["inventoryRevision"], "Only.md")
        self.assertEqual(opened["body"], secret)
        self.assertEqual(self.settings.read_bytes(), settings_before)
        self.assertNotIn(secret, json.dumps(self.service._cache, sort_keys=True))
        self.assertNotIn(secret, dispatch_history.read_text(encoding="utf-8"))
        self.assertNotIn(secret, runtime_log.read_text(encoding="utf-8"))

    def test_api_and_ui_wire_id_bound_read_only_keyboard_browser(self):
        class FakeBrain:
            def list_directory(self, brain_id, revision, relative, page, page_size):
                return {"ok": True, "brainId": brain_id, "relativePath": relative, "page": int(page)}

            def open_note(self, brain_id, revision, relative):
                return {"ok": True, "brainId": brain_id, "relativePath": relative, "body": "chosen"}

        api = activity_monitor.Api(brain_service=FakeBrain(), dispatch_service=object(), guard_service=object())
        listed = json.loads(api.list_brain_directory("brain_exact", "inventory_exact", "Folder", 2, 40))
        opened = json.loads(api.open_brain_note("brain_exact", "inventory_exact", "Folder/Only.md"))
        self.assertEqual(listed["brainId"], "brain_exact")
        self.assertEqual(listed["page"], 2)
        self.assertEqual(opened["body"], "chosen")

        html = activity_monitor.HTML
        for marker in (
            'id="brain-browser"', 'id="brain-browser-back"', 'id="brain-breadcrumbs"',
            'id="brain-note-body"', "pywebview.api.list_brain_directory",
            "pywebview.api.open_brain_note", "card.tabIndex = 0",
            "card.addEventListener('keydown'", "brainCardActivationKey(event)",
            "brain-browser-back').addEventListener", "brainPrimaryAction", "Connect & open",
            "Repair access", "Restore & open", "performBrainPrimaryAction",
            "document.getElementById('brain-note-body').textContent", "result.body = ''",
            "pywebview.api.forget_brain", "'Forget'",
        ):
            self.assertIn(marker, html)
        self.assertNotIn("Why unavailable", html)
        self.assertNotIn("Read-only access unavailable", html)
        self.assertNotIn("showBrainUnavailable", html)
        self.assertNotIn("document.getElementById('brain-note-body').innerHTML", html)
        self.assertIn("Note text opens only when you select a file", html)
        self.assertIn('id="brain-files-welcome"', html)
        self.assertIn("brainAutoOpenAttempted", html)

    def test_api_repair_uses_one_native_exact_folder_selection(self):
        class FakeBrain:
            def __init__(self):
                self.repaired = None

            def repair_connection(self, expected, selected):
                self.repaired = (expected, selected)
                return {"ok": True, "brains": []}

        class FakeWindow:
            def __init__(self, selected):
                self.selected = selected
                self.calls = 0

            def create_file_dialog(self, kind, allow_multiple=False):
                self.calls += 1
                self.assert_single = not allow_multiple
                return [self.selected]

        expected = str(self.home / "Documents" / "Repair Vault")
        brain = FakeBrain()
        window = FakeWindow(expected)
        api = activity_monitor.Api(
            brain_service=brain, dispatch_service=object(), guard_service=object()
        )
        api.attach_window(window)
        result = json.loads(api.repair_brain_connection(expected))
        self.assertTrue(result["ok"])
        self.assertEqual(window.calls, 1)
        self.assertTrue(window.assert_single)
        self.assertEqual(brain.repaired, (expected, expected))

    def test_project_brain_hierarchy_visual_and_generation_bound_navigation_are_wired(self):
        html = activity_monitor.HTML
        for marker in (
            'id="brain-view-files"', 'id="brain-view-visual"', 'id="brain-visual"',
            'id="brain-graph"', 'id="brain-graph-world"', 'id="brain-visual-fit"',
            'id="brain-projects"', "function renderProjectBrainFamily", "function renderBrainVisual",
            "function applyBrainGraphTransform", "brainGraph.addEventListener('pointerdown'",
            "brainGraph.addEventListener('wheel'", "prefers-reduced-motion:reduce",
            "brainRequestGeneration", "generation !== brainRequestGeneration",
            "workspace-project-brain", "workspaceOpenProjectBrain(project)",
            "Main knowledge workspace",
            "function restoreBrainBrowserOrigin", "originView:'visual'",
            "originTransform:{...brainGraphTransform}", "placeBrainBrowser",
            "brain-visual-inspector", "group.dataset.brainId",
            "brainBrowserState.originView === 'visual'", "clearBrainNoteBody();",
            "function brainGraphLabelLines", "function brainGraphColumnPoints", "function brainGraphBackdrop",
            "brain-spatial-layer", "brain-region claude", "brain-region codex",
            "brain-fold claude", "brain-fold codex", "brain-bridge",
            "brain-node-signal", "brain-synapse", "group.dataset.spatialGroup",
            "edge.dataset.spatialGroup", " C ${controlOneX}", "Your Brain map",
            "function renderBrainDirectoryLoading", "brain-directory-loading-state",
        ):
            self.assertIn(marker, html)
        self.assertEqual(html.count("setBrainView('files')"), 1)
        directory_guard = html.index("generation !== brainRequestGeneration || brainBrowserState?.brainId !== requestedBrainId")
        directory_render = html.index("renderBrainDirectory(result)", directory_guard)
        self.assertLess(directory_guard, directory_render)
        load_start = html.index("async function loadBrainDirectory")
        loading_state = html.index("renderBrainDirectoryLoading();", load_start)
        loading_message = html.index("setBrainBrowserMessage('');", loading_state)
        self.assertLess(loading_state, loading_message)
        self.assertIn("document.getElementById('brain-pager').hidden = true", html[loading_state:loading_message])
        loading_helper = html[html.index("function renderBrainDirectoryLoading"):html.index("function renderBrainDirectory(payload)")]
        self.assertIn("emptyNode(directory)", loading_helper)
        self.assertIn("index < 5", loading_helper)
        self.assertNotIn("brainGraph.innerHTML", html)


if __name__ == "__main__":
    unittest.main()
