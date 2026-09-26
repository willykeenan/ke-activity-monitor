import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import tempfile
import unittest
from unittest.mock import patch

import activity_monitor
from brain_discovery import BrainService
from workspace_browser import (
    FLAGSHIP_PREFERENCES_SCHEMA_VERSION,
    PREFERENCES_SCHEMA_VERSION,
    WorkspaceError,
    WorkspacePreferences,
    WorkspaceService,
)


PROJECT_A = "local-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PROJECT_B = "local-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
PROJECT_UUID = "4935c9de-a2df-4143-a844-d9db93143003"
PROJECT_OMITTED = "local-cccccccccccccccccccccccccccccccc"
THREAD_A = "01a020e9-c953-70d0-b86b-eb2e49f45cf5"
THREAD_B = "01a020e9-16a8-7fb2-a6f5-8470ae30fcd2"
THREAD_CHILD = "01a020e5-d27c-7350-b81e-8ce24122c02d"
CLAUDE_A = "f91d84b7-a732-4e94-bd32-1c87ec9c273f"
THREAD_UNFILED = "01a020e6-08aa-7ebd-b810-d679c2671c35"


class WorkspaceBrowserTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.codex_state = self.home / ".codex" / ".codex-global-state.json"
        self.codex_state.parent.mkdir(mode=0o700)
        self.preferences = self.home / "support" / "workspace-preferences.json"
        self.claude_projects = self.home / ".claude" / "projects"
        self.claude_projects.mkdir(parents=True, mode=0o700)
        os.chmod(self.claude_projects, 0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def _write_codex_state(self):
        value = {
            "local-projects": {
                PROJECT_A: {"name": "Activity Monitor", "privateDraft": "never-expose"},
                PROJECT_B: {"name": "KE Swarm"},
                PROJECT_UUID: {"name": "Pixel Forge"},
                PROJECT_OMITTED: {"name": "Omitted but valid"},
            },
            "project-order": [PROJECT_UUID, PROJECT_B, PROJECT_A],
            "thread-project-assignments": {
                THREAD_A: {"projectKind": "local", "projectId": PROJECT_A},
                THREAD_B: {"projectKind": "local", "projectId": PROJECT_B},
                THREAD_CHILD: {"projectKind": "local", "projectId": PROJECT_A},
                THREAD_UNFILED: {"projectKind": "remote", "projectId": PROJECT_A},
            },
            "sidebar-project-thread-orders": {
                PROJECT_A: {"threadIds": [THREAD_CHILD, THREAD_A]},
                PROJECT_B: {"threadIds": [THREAD_B]},
            },
            "pinned-thread-ids": [THREAD_A],
            "pinned-project-ids": [PROJECT_UUID],
            "projectless-thread-ids": [THREAD_UNFILED],
            "composer-prompt-drafts": {THREAD_A: "private-prompt-marker-7104"},
        }
        self.codex_state.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(self.codex_state, 0o600)

    def _threads(self):
        return [
            {
                "id": THREAD_A,
                "name": "Rail implementation",
                "status": {"type": "active"},
                "projectId": PROJECT_B,
                "cwd": "/wrong/inferred/project",
                "preview": "private-preview-marker-9930",
                "updatedAt": 30,
            },
            {
                "id": THREAD_CHILD,
                "name": "Verifier child",
                "status": {"type": "completed"},
                "parentThreadId": THREAD_A,
                "updatedAt": 20,
            },
            {
                "id": THREAD_B,
                "name": "KE Swarm",
                "status": "notLoaded",
                "updatedAt": 10,
            },
            {
                "id": THREAD_UNFILED,
                "name": "Explicitly unfiled",
                "projectId": PROJECT_A,
                "status": "notLoaded",
                "updatedAt": 5,
            },
        ]

    def _service(self):
        return WorkspaceService(
            home=self.home,
            preferences_path=self.preferences,
            codex_state_path=self.codex_state,
            claude_projects_path=self.claude_projects,
            thread_loader=self._threads,
            command_finder=lambda _name: None,
            board_command=[],
            cache_seconds=0,
        )

    def test_codex_uses_only_whitelisted_assignments_order_and_titles(self):
        self._write_codex_state()
        real_loads = json.loads

        def guarded_loads(raw, *args, **kwargs):
            self.assertNotIn("private-prompt-marker-7104", str(raw))
            return real_loads(raw, *args, **kwargs)

        with patch("workspace_browser.json.loads", side_effect=guarded_loads):
            snapshot = self._service().snapshot(force=True)
        self.assertTrue(snapshot["ok"])
        projects = snapshot["projects"]
        self.assertEqual([item["id"] for item in projects[:3]], [PROJECT_UUID, PROJECT_B, PROJECT_A])
        self.assertTrue(projects[0]["pinned"])
        self.assertIn(PROJECT_OMITTED, [item["id"] for item in projects])
        activity = next(item for item in projects if item["id"] == PROJECT_A)
        self.assertEqual([row["id"] for row in activity["conversations"]], [THREAD_A, THREAD_CHILD])
        self.assertEqual(activity["conversations"][1]["depth"], 1)
        self.assertTrue(activity["conversations"][0]["pinned"])
        serialized = json.dumps(snapshot)
        self.assertNotIn("private-prompt-marker-7104", serialized)
        self.assertNotIn("private-preview-marker-9930", serialized)
        self.assertNotIn("never-expose", serialized)
        self.assertNotIn("/wrong/inferred/project", serialized)
        unfiled = next(item for item in projects if item["id"] == "codex-unfiled")
        self.assertEqual([item["id"] for item in unfiled["conversations"]], [THREAD_UNFILED])

    def test_claude_reads_bounded_metadata_but_never_transcript_body_or_title(self):
        self._write_codex_state()
        encoded = "-Users-test-Project-One"
        project = self.claude_projects / encoded
        project.mkdir(mode=0o700)
        transcript = project / f"{CLAUDE_A}.jsonl"
        transcript.write_text(
            json.dumps({
                "type": "user",
                "sessionId": CLAUDE_A,
                "cwd": str(self.home / "Project One"),
                "timestamp": "2026-08-20T20:00:00Z",
                "message": {"content": "secret transcript marker 4491"},
            }) + "\n",
            encoding="utf-8",
        )
        os.chmod(transcript, 0o600)
        service = self._service()
        original_read_text = Path.read_text

        def deny_transcript_reads(path, *args, **kwargs):
            if str(path).endswith(".jsonl"):
                raise AssertionError("Claude transcript body was opened during listing")
            return original_read_text(path, *args, **kwargs)

        with patch.object(Path, "read_text", deny_transcript_reads):
            initial = service.snapshot(force=True)
        project_id = "claude-" + hashlib.sha256(encoded.encode()).hexdigest()[:24]
        candidate = next(item for item in initial["availableClaudeProjects"] if item["id"] == project_id)
        self.assertFalse(candidate["saved"])
        self.assertNotIn(CLAUDE_A, json.dumps(initial["projects"]))

        with patch.object(Path, "read_text", deny_transcript_reads):
            saved = service.set_claude_project_saved(project_id, True)
        claude = next(item for item in saved["projects"] if item["id"] == project_id)
        self.assertEqual(claude["name"], encoded.lstrip("-"))
        self.assertEqual(claude["conversations"][0]["id"], CLAUDE_A)
        self.assertEqual(claude["conversations"][0]["title"], f"Claude session · {CLAUDE_A[:8]}")
        serialized = json.dumps(saved)
        self.assertNotIn("secret transcript marker 4491", serialized)
        self.assertNotIn("Project One", serialized)
        self.assertTrue(saved["privacy"]["metadataOnly"])
        self.assertFalse(saved["privacy"]["transcriptBodiesRead"])

    def test_preferences_are_bounded_mode_0600_and_body_free(self):
        store = WorkspacePreferences(self.preferences)
        self.assertIsNone(store.read()["expandedProjectIds"])
        updated = store.update({
            "railWidth": 99_999,
            "expandedProjectIds": [PROJECT_A, PROJECT_A, "../../escape"],
            "visibleCodexProjectIds": [PROJECT_UUID, PROJECT_A, "../../escape"],
            "savedClaudeProjectIds": ["claude-" + "c" * 24, "not-claude"],
            "providerFilters": {"codex": False, "claude": True},
            "lastSelected": {
                "provider": "codex",
                "projectId": PROJECT_A,
                "conversationId": THREAD_A,
            },
            "messageBody": "secret preference marker 1308",
        })
        self.assertEqual(updated["railWidth"], 380)
        self.assertEqual(updated["expandedProjectIds"], [PROJECT_A])
        self.assertEqual(updated["visibleCodexProjectIds"], [PROJECT_UUID, PROJECT_A])
        self.assertEqual(updated["savedClaudeProjectIds"], ["claude-" + "c" * 24])
        self.assertFalse(updated["providerFilters"]["codex"])
        metadata = self.preferences.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        raw = self.preferences.read_text(encoding="utf-8")
        self.assertNotIn("secret preference marker 1308", raw)
        self.assertEqual(json.loads(raw)["schemaVersion"], PREFERENCES_SCHEMA_VERSION)
        self.assertLess(len(raw.encode("utf-8")), 4_096)
        self.assertEqual(store.update({"expandedProjectIds": []})["expandedProjectIds"], [])

    def test_flagship_collapse_preference_persists_and_malformed_state_fails_expanded(self):
        first = self._service()
        result = first.set_flagship_fabric_collapsed("brain", True)
        self.assertEqual(result["schemaVersion"], FLAGSHIP_PREFERENCES_SCHEMA_VERSION)
        self.assertEqual(result["collapsedTabs"], ["brain"])
        self.assertEqual(stat.S_IMODE(self.preferences.stat().st_mode), 0o600)

        relaunched = self._service().flagship_ui_preferences()
        self.assertEqual(relaunched["collapsedTabs"], ["brain"])
        self.assertEqual(relaunched["storage"], "private-local-preferences")
        with self.assertRaises(WorkspaceError):
            first.set_flagship_fabric_collapsed("guard", True)

        self.preferences.write_text("{malformed", encoding="utf-8")
        os.chmod(self.preferences, 0o600)
        failed_safe = self._service().flagship_ui_preferences()
        self.assertEqual(failed_safe["collapsedTabs"], [])

    def test_preferences_reject_group_or_other_access_bits(self):
        self.preferences.parent.mkdir(parents=True)
        self.preferences.write_text(json.dumps({
            "schemaVersion": PREFERENCES_SCHEMA_VERSION,
            "railWidth": 379,
        }), encoding="utf-8")
        os.chmod(self.preferences, 0o644)
        loaded = WorkspacePreferences(self.preferences).read()
        self.assertEqual(loaded["railWidth"], 252)

    def test_preferences_file_swap_to_symlink_fails_closed_on_the_opened_inode(self):
        store = WorkspacePreferences(self.preferences)
        store.write({"railWidth": 310})
        original = self.preferences.with_name("workspace-original.json")
        outside = self.home / "outside-preferences.json"
        outside.write_text(json.dumps({
            "schemaVersion": PREFERENCES_SCHEMA_VERSION,
            "railWidth": 379,
            "messageBody": "outside private preference 7791",
        }), encoding="utf-8")
        os.chmod(outside, 0o600)
        real_open = os.open
        swapped = False

        def swap_then_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == self.preferences.name and dir_fd is not None and not swapped:
                self.preferences.rename(original)
                self.preferences.symlink_to(outside)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with patch("workspace_browser.os.open", side_effect=swap_then_open):
            loaded = store.read()
        self.assertTrue(swapped)
        self.assertEqual(loaded["railWidth"], 252)

    def test_preferences_write_stays_on_opened_parent_during_directory_swap(self):
        self.preferences.parent.mkdir(parents=True, mode=0o700)
        os.chmod(self.preferences.parent, 0o700)
        original_parent = self.preferences.parent.with_name("support-opened")
        outside_parent = self.home / "outside-support"
        outside_parent.mkdir(mode=0o700)
        real_open = os.open
        swapped = False

        def swap_parent_after_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if Path(path) == self.preferences.parent and dir_fd is None and not swapped:
                self.preferences.parent.rename(original_parent)
                self.preferences.parent.symlink_to(outside_parent, target_is_directory=True)
                swapped = True
            return descriptor

        with patch("workspace_browser.os.open", side_effect=swap_parent_after_open):
            WorkspacePreferences(self.preferences).write({"railWidth": 333})
        self.assertTrue(swapped)
        written = original_parent / self.preferences.name
        self.assertTrue(written.is_file())
        self.assertEqual(stat.S_IMODE(written.stat().st_mode), 0o600)
        self.assertFalse((outside_parent / self.preferences.name).exists())

    def test_codex_project_menu_defaults_all_and_can_select_uuid_projects(self):
        self._write_codex_state()
        service = self._service()
        initial = service.snapshot(force=True)
        self.assertTrue(all(item["selected"] for item in initial["availableCodexProjects"]))
        service.update_preferences({"visibleCodexProjectIds": [PROJECT_UUID]})
        filtered = service.snapshot(force=True)
        self.assertEqual([item["id"] for item in filtered["projects"]], [PROJECT_UUID])
        self.assertEqual(
            [item["id"] for item in filtered["availableCodexProjects"] if item["selected"]],
            [PROJECT_UUID],
        )

    def test_hidden_provider_or_project_is_not_openable_by_direct_api(self):
        self._write_codex_state()
        launched = []
        service = WorkspaceService(
            home=self.home,
            preferences_path=self.preferences,
            codex_state_path=self.codex_state,
            claude_projects_path=self.claude_projects,
            thread_loader=self._threads,
            command_finder=lambda _name: None,
            board_command=[],
            launcher=lambda args, cwd: launched.append((args, cwd)),
            cache_seconds=0,
        )
        service.update_preferences({"visibleCodexProjectIds": [PROJECT_UUID]})
        with self.assertRaises(WorkspaceError) as hidden_project:
            service.open_conversation("codex", THREAD_A)
        self.assertEqual(hidden_project.exception.code, "conversation_stale")
        service.update_preferences({
            "visibleCodexProjectIds": None,
            "providerFilters": {"codex": False, "claude": True},
        })
        with self.assertRaises(WorkspaceError) as hidden_provider:
            service.open_conversation("codex", THREAD_A)
        self.assertEqual(hidden_provider.exception.code, "conversation_stale")
        self.assertEqual(launched, [])

    def test_codex_exact_open_uses_registered_uuid_url_and_fixed_argv(self):
        self._write_codex_state()
        launched = []
        service = WorkspaceService(
            home=self.home,
            preferences_path=self.preferences,
            codex_state_path=self.codex_state,
            claude_projects_path=self.claude_projects,
            thread_loader=self._threads,
            command_finder=lambda _name: None,
            board_command=[],
            launcher=lambda args, cwd: launched.append((args, cwd)),
            cache_seconds=0,
        )
        result = service.open_conversation("codex", THREAD_A)
        self.assertEqual(result["launchMode"], "codex-url-scheme")
        self.assertFalse(result["nativeDestinationVerified"])
        self.assertEqual(launched, [(["/usr/bin/open", f"codex://threads/{THREAD_A}"], None)])

    def test_claude_project_swap_to_symlink_fails_closed_without_leaking_outside_metadata(self):
        self._write_codex_state()
        project_name = "-Users-test-swap"
        project = self.claude_projects / project_name
        project.mkdir(mode=0o700)
        (project / f"{CLAUDE_A}.jsonl").write_text("outside must not appear\n", encoding="utf-8")
        outside = self.home / "outside"
        outside.mkdir(mode=0o700)
        outside_session = "b474088c-4ab9-4105-8dae-0b80234c8624"
        (outside / f"{outside_session}.jsonl").write_text("secret outside metadata\n", encoding="utf-8")
        backup = self.home / "swapped-original"
        service = self._service()
        original_open = service._open_private_directory
        swapped = False

        def swap_then_open(path, *, dir_fd=None):
            nonlocal swapped
            if dir_fd is not None and str(path) == project_name and not swapped:
                project.rename(backup)
                project.symlink_to(outside, target_is_directory=True)
                swapped = True
            return original_open(path, dir_fd=dir_fd)

        with patch.object(service, "_open_private_directory", side_effect=swap_then_open):
            snapshot = service.snapshot(force=True)
        self.assertTrue(swapped)
        serialized = json.dumps(snapshot)
        self.assertNotIn(outside_session, serialized)
        self.assertNotIn("secret outside metadata", serialized)

    def test_claude_registry_file_swap_to_symlink_fails_closed(self):
        self._write_codex_state()
        sessions = self.home / ".claude" / "sessions"
        sessions.mkdir(parents=True, mode=0o700)
        registry = sessions / "123.json"
        registry.write_text("{}", encoding="utf-8")
        os.chmod(registry, 0o644)
        outside = self.home / "outside-registry.json"
        outside.write_text(json.dumps({
            "sessionId": CLAUDE_A,
            "kind": "interactive",
            "peerProtocol": 1,
            "pid": os.getpid(),
            "messagingSocketPath": str(self.home / "secret.sock"),
            "name": "secret registry title 4410",
        }), encoding="utf-8")
        os.chmod(outside, 0o600)
        backup = sessions / "original.json"
        service = self._service()
        real_open = os.open
        swapped = False

        def swap_then_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == "123.json" and dir_fd is not None and not swapped:
                registry.rename(backup)
                registry.symlink_to(outside)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with patch("workspace_browser.os.open", side_effect=swap_then_open):
            live = service._claude_live_registry()
        self.assertTrue(swapped)
        self.assertEqual(live, {})
        self.assertNotIn("secret registry title 4410", json.dumps(live))

    def test_live_claude_registry_requires_private_socket_and_keeps_generic_title(self):
        self._write_codex_state()
        encoded = "-Users-test-live"
        project = self.claude_projects / encoded
        project.mkdir(mode=0o700)
        transcript = project / f"{CLAUDE_A}.jsonl"
        transcript.write_text("must never be read\n", encoding="utf-8")
        os.chmod(transcript, 0o600)
        sessions = self.home / ".claude" / "sessions"
        sessions.mkdir(parents=True, mode=0o700)
        socket_path = self.home / "live.sock"
        live_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        live_socket.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        registry = sessions / f"{os.getpid()}.json"
        registry.write_text(json.dumps({
            "sessionId": CLAUDE_A,
            "kind": "interactive",
            "peerProtocol": 1,
            "pid": os.getpid(),
            "messagingSocketPath": str(socket_path),
            "cwd": str(self.home),
            "name": "private registry name 8902",
        }), encoding="utf-8")
        os.chmod(registry, 0o600)
        project_id = "claude-" + hashlib.sha256(encoded.encode()).hexdigest()[:24]
        WorkspacePreferences(self.preferences).update({"savedClaudeProjectIds": [project_id]})
        try:
            snapshot = self._service().snapshot(force=True)
        finally:
            live_socket.close()
        claude = next(item for item in snapshot["projects"] if item["id"] == project_id)
        conversation = claude["conversations"][0]
        self.assertEqual(conversation["state"], "active")
        self.assertTrue(conversation["canDispatch"])
        self.assertFalse(conversation["canOpen"])
        self.assertIn("existing Terminal", conversation["openLabel"])
        self.assertEqual(conversation["title"], f"Claude session · {CLAUDE_A[:8]}")
        self.assertNotIn("private registry name 8902", json.dumps(snapshot))
        with self.assertRaises(WorkspaceError) as duplicate_owner:
            self._service().open_conversation("claude", CLAUDE_A)
        self.assertEqual(duplicate_owner.exception.code, "conversation_stale")

    def test_claude_exact_resume_uses_visible_terminal_and_safely_quoted_fixed_argv(self):
        self._write_codex_state()
        project_directory = self.home / "Project One"
        project_directory.mkdir()
        encoded = re.sub(r"[^A-Za-z0-9]", "-", str(project_directory.resolve()))
        project = self.claude_projects / encoded
        project.mkdir(mode=0o700)
        transcript = project / f"{CLAUDE_A}.jsonl"
        transcript.write_text("not read\n", encoding="utf-8")
        os.chmod(transcript, 0o600)
        cli = self.home / "bin" / "claude"
        cli.parent.mkdir()
        cli.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"--version\" ]; then echo 2.1.100; exit 0; fi\n"
            "if [ \"$1\" = \"--help\" ]; then echo ' --resume [value] Resume a conversation by session ID'; exit 0; fi\n"
            "exit 2\n",
            encoding="utf-8",
        )
        os.chmod(cli, 0o755)
        launched = []
        service = WorkspaceService(
            home=self.home,
            preferences_path=self.preferences,
            codex_state_path=self.codex_state,
            claude_projects_path=self.claude_projects,
            thread_loader=self._threads,
            board_command=[],
            command_finder=lambda name: str(cli) if name == "claude" else None,
            launcher=lambda args, cwd: launched.append((args, cwd)),
            cache_seconds=0,
        )
        project_id = "claude-" + hashlib.sha256(encoded.encode()).hexdigest()[:24]
        service.set_claude_project_saved(project_id, True)
        service.set_claude_project_directory(project_id, str(project_directory))
        self.assertEqual(service._companion_version(str(cli)), "2.1.100")
        self.assertTrue(service._claude_resume_supported(str(cli)))
        result = service.open_conversation("claude", CLAUDE_A)
        self.assertEqual(result["launchMode"], "claude-visible-terminal-resume")
        self.assertFalse(result["nativeDestinationVerified"])
        args, cwd = launched[0]
        self.assertEqual(args[0], "/usr/bin/osascript")
        self.assertIsNone(cwd)
        self.assertEqual(args[-4], "--")
        self.assertEqual(args[-3:], [str(cli.resolve()), str(project_directory.resolve()), CLAUDE_A])
        script = "\n".join(args[1:-4])
        self.assertIn("quoted form of projectPath", script)
        self.assertIn("quoted form of cliPath", script)
        self.assertIn("quoted form of sessionId", script)
        self.assertNotIn(str(project_directory.resolve()), script)
        self.assertEqual(
            service.preferences.read()["lastSelected"],
            {"provider": "claude", "projectId": project_id, "conversationId": CLAUDE_A},
        )

    def test_claude_project_directory_must_encode_to_the_exact_detected_project(self):
        self._write_codex_state()
        correct = self.home / "Exact Project"
        wrong = self.home / "Wrong Project"
        correct.mkdir()
        wrong.mkdir()
        encoded = re.sub(r"[^A-Za-z0-9]", "-", str(correct.resolve()))
        project = self.claude_projects / encoded
        project.mkdir(mode=0o700)
        transcript = project / f"{CLAUDE_A}.jsonl"
        transcript.write_text("not read\n", encoding="utf-8")
        os.chmod(transcript, 0o600)
        project_id = "claude-" + hashlib.sha256(encoded.encode()).hexdigest()[:24]
        service = self._service()
        service.set_claude_project_saved(project_id, True)
        with self.assertRaisesRegex(WorkspaceError, "does not match"):
            service.set_claude_project_directory(project_id, str(wrong))
        result = service.set_claude_project_directory(project_id, str(correct))
        self.assertEqual(
            result["preferences"]["claudeProjectDirectories"][project_id],
            str(correct.resolve()),
        )
        mapped = next(item for item in result["projects"] if item["id"] == project_id)
        self.assertEqual(mapped["name"], "Exact Project")

    def test_saved_claude_project_key_survives_bounded_root_enumeration(self):
        self._write_codex_state()
        saved_key = "zzzz-saved-project"
        project_id = "claude-" + hashlib.sha256(saved_key.encode()).hexdigest()[:24]
        for name in ("aaaa", "bbbb", saved_key):
            directory = self.claude_projects / name
            directory.mkdir(mode=0o700)
        transcript = self.claude_projects / saved_key / f"{CLAUDE_A}.jsonl"
        transcript.write_text("not read\n", encoding="utf-8")
        os.chmod(transcript, 0o600)
        WorkspacePreferences(self.preferences).update({
            "savedClaudeProjectIds": [project_id],
            "savedClaudeProjectKeys": {project_id: saved_key},
        })
        with patch("workspace_browser.MAX_CLAUDE_PROJECT_SCAN_ENTRIES", 2):
            snapshot = self._service().snapshot(force=True)
        self.assertIn(project_id, [item["id"] for item in snapshot["availableClaudeProjects"]])
        self.assertIn(project_id, [item["id"] for item in snapshot["projects"]])

    def test_saved_claude_projects_share_the_global_session_catalog_fairly(self):
        self._write_codex_state()
        keys = ["aaaa-saved", "bbbb-saved"]
        project_ids = ["claude-" + hashlib.sha256(key.encode()).hexdigest()[:24] for key in keys]
        session_ids = [
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444",
            "55555555-5555-4555-8555-555555555555",
        ]
        for index, key in enumerate(keys):
            directory = self.claude_projects / key
            directory.mkdir(mode=0o700)
            selected = session_ids[:4] if index == 0 else session_ids[4:]
            for offset, session_id in enumerate(selected):
                transcript = directory / f"{session_id}.jsonl"
                transcript.write_text("not read\n", encoding="utf-8")
                os.chmod(transcript, 0o600)
                os.utime(transcript, (100 + offset, 100 + offset))
        WorkspacePreferences(self.preferences).update({
            "savedClaudeProjectIds": project_ids,
            "savedClaudeProjectKeys": dict(zip(project_ids, keys)),
        })
        with patch("workspace_browser.MAX_CLAUDE_SESSIONS", 4):
            snapshot = self._service().snapshot(force=True)
        counts = {item["id"]: item["conversationCount"] for item in snapshot["projects"] if item["provider"] == "claude"}
        self.assertEqual(counts[project_ids[0]], 2)
        self.assertEqual(counts[project_ids[1]], 1)

    def test_visible_projects_receive_stable_child_brains_and_conversations_inherit_brain_id(self):
        self._write_codex_state()
        parent = self.home / ".grokcode" / "brain"
        (parent / ".obsidian").mkdir(parents=True, mode=0o700)
        (parent / "GrokCode" / "Projects").mkdir(parents=True, mode=0o700)
        for path in (parent.parent, parent, parent / "GrokCode", parent / "GrokCode" / "Projects"):
            os.chmod(path, 0o700)
        brain_service = BrainService(
            home=self.home,
            settings_path=self.home / "support" / "brain-settings.json",
            scan_roots=[self.home],
            scan_seconds=1,
        )
        service = WorkspaceService(
            home=self.home,
            preferences_path=self.preferences,
            codex_state_path=self.codex_state,
            claude_projects_path=self.claude_projects,
            thread_loader=self._threads,
            command_finder=lambda _name: None,
            board_command=[],
            brain_service=brain_service,
            cache_seconds=0,
        )

        initial = service.snapshot(force=True)
        activity = next(item for item in initial["projects"] if item["id"] == PROJECT_A)
        self.assertTrue(activity["brainId"].startswith("brain_project_"))
        self.assertEqual(activity["brainStatus"], "ready")
        self.assertEqual(activity["brainLifecycleState"], "active")
        self.assertTrue(all(row["brainId"] == activity["brainId"] for row in activity["conversations"]))
        self.assertTrue(all(row["projectId"] == PROJECT_A for row in activity["conversations"]))
        self.assertGreaterEqual(initial["counts"]["projectBrains"], 4)
        self.assertFalse(initial["privacy"]["projectBrainsAutoDelete"])

        service.update_preferences({"visibleCodexProjectIds": [PROJECT_UUID]})
        hidden = service.snapshot(force=True)
        retained = next(item for item in hidden["availableCodexProjects"] if item["id"] == PROJECT_A)
        self.assertEqual(retained["brainId"], activity["brainId"])
        self.assertEqual(retained["brainLifecycleState"], "dormant")
        self.assertTrue(Path(
            brain_service.project_brain_snapshot()["byProject"][f"codex:{PROJECT_A}"]["path"]
        ).is_dir())

        service.update_preferences({"visibleCodexProjectIds": None})
        routing = service.routing_index(force=True)
        self.assertEqual(routing[THREAD_B]["projectId"], PROJECT_B)
        self.assertTrue(routing[THREAD_B]["brainId"].startswith("brain_project_"))

    def test_claude_project_brain_is_created_only_when_saved_and_is_retained_when_unsaved(self):
        self._write_codex_state()
        encoded = "-Users-test-Claude-Brain"
        directory = self.claude_projects / encoded
        directory.mkdir(mode=0o700)
        transcript = directory / f"{CLAUDE_A}.jsonl"
        transcript.write_text("private body never parsed\n", encoding="utf-8")
        os.chmod(transcript, 0o600)
        project_id = "claude-" + hashlib.sha256(encoded.encode()).hexdigest()[:24]
        parent = self.home / ".grokcode" / "brain"
        (parent / ".obsidian").mkdir(parents=True, mode=0o700)
        (parent / "GrokCode" / "Projects").mkdir(parents=True, mode=0o700)
        for path in (parent.parent, parent, parent / "GrokCode", parent / "GrokCode" / "Projects"):
            os.chmod(path, 0o700)
        brain_service = BrainService(
            home=self.home,
            settings_path=self.home / "support" / "brain-settings.json",
            scan_roots=[self.home],
            scan_seconds=1,
        )
        service = WorkspaceService(
            home=self.home,
            preferences_path=self.preferences,
            codex_state_path=self.codex_state,
            claude_projects_path=self.claude_projects,
            thread_loader=self._threads,
            command_finder=lambda _name: None,
            board_command=[],
            brain_service=brain_service,
            cache_seconds=0,
        )

        initial = service.snapshot(force=True)
        candidate = next(item for item in initial["availableClaudeProjects"] if item["id"] == project_id)
        self.assertFalse(candidate["saved"])
        self.assertIsNone(candidate["brainId"])
        self.assertNotIn(f"claude:{project_id}", brain_service.project_brain_snapshot()["byProject"])

        saved = service.set_claude_project_saved(project_id, True)
        active = next(item for item in saved["projects"] if item["id"] == project_id)
        self.assertTrue(active["brainId"].startswith("brain_project_"))
        self.assertEqual(active["brainLifecycleState"], "active")
        self.assertTrue(all(item["brainId"] == active["brainId"] for item in active["conversations"]))

        unsaved = service.set_claude_project_saved(project_id, False)
        retained = next(item for item in unsaved["availableClaudeProjects"] if item["id"] == project_id)
        self.assertEqual(retained["brainId"], active["brainId"])
        self.assertEqual(retained["brainLifecycleState"], "dormant")
        child = brain_service.project_brain_snapshot()["byProject"][f"claude:{project_id}"]
        self.assertTrue(Path(child["path"]).is_dir())

    def test_workspace_bridge_uses_explicit_native_folder_picker_and_ui_is_global(self):
        class FakeWorkspace:
            def __init__(self):
                self.directory = None

            def snapshot(self, force=False):
                return {"ok": True, "projects": [], "force": force}

            def set_claude_project_directory(self, project_id, directory):
                self.directory = (project_id, directory)
                return {"ok": True, "projectId": project_id}

        class FakeWindow:
            def __init__(self):
                self.calls = 0

            def create_file_dialog(self, kind, allow_multiple=False):
                self.calls += 1
                return [str(self.home)]

        fake_workspace = FakeWorkspace()
        fake_window = FakeWindow()
        fake_window.home = self.home
        api = activity_monitor.Api(
            brain_service=object(), dispatch_service=object(), guard_service=object(),
            workspace_service=fake_workspace,
        )
        self.assertTrue(json.loads(api.get_workspace_state(True))["ok"])
        self.assertEqual(fake_window.calls, 0)
        api.attach_window(fake_window)
        result = json.loads(api.choose_claude_project_directory("claude-" + "a" * 24))
        self.assertTrue(result["ok"])
        self.assertEqual(fake_window.calls, 1)
        self.assertEqual(fake_workspace.directory[1], str(self.home))

        html = activity_monitor.HTML
        for marker in (
            'id="workspace-shell"', 'id="workspace-rail"', 'id="workspace-resizer"',
            'id="workspace-search"', 'id="workspace-manage"', 'id="workspace-dialog"',
            "pywebview.api.get_workspace_state", "pywebview.api.update_workspace_preferences",
            "pywebview.api.open_workspace_conversation", "pywebview.api.choose_claude_project_directory",
            "pywebview.api.get_project_conversation_host", "pywebview.api.read_hosted_conversation",
            "pywebview.api.send_project_conductor", "pywebview.api.send_hosted_conversation",
            'id="workspace-host-native"', 'id="workspace-host-activity"',
            'id="conversation-host"', 'data-route-kind="powerswarm"',
            "workspaceResizer.addEventListener('pointerdown'", "event.key === 'ArrowDown'",
            "event.key === 'Escape'", "event.target.id === 'workspace-dialog'",
            "persistedExpansion === null", ".slice(0, 3)",
            "const matchingConversations = (expanded || workspaceQuery)",
            "if (visibleProjects === 0)",
        ):
            self.assertIn(marker, html)
        self.assertLess(html.index('id="workspace-rail"'), html.index('class="toolbar"'))
        self.assertGreater(html.index('</section>\n</div>'), html.index('class="status-bar"'))

    def test_packaging_and_source_parity_include_workspace_adapter(self):
        root = Path(__file__).resolve().parents[1]
        spec = (root / "activity_monitor.spec").read_text(encoding="utf-8")
        package = (root / "package_app.zsh").read_text(encoding="utf-8")
        self.assertIn('workspace_browser.py"), "source"', spec)
        compile_line = next(line for line in package.splitlines() if " -m py_compile " in line)
        self.assertIn("workspace_browser.py", compile_line)
        self.assertIn('project_brains.py"), "source"', spec)
        self.assertIn("project_brains.py", compile_line)
        self.assertIn('cmp project_brains.py "$bundle/Contents/Resources/source/project_brains.py"', package)
        self.assertIn('cmp workspace_browser.py "$bundle/Contents/Resources/source/workspace_browser.py"', package)
        self.assertIn('conversation_host.py"), "source"', spec)
        self.assertIn("conversation_host.py", compile_line)
        self.assertIn('cmp conversation_host.py "$bundle/Contents/Resources/source/conversation_host.py"', package)


if __name__ == "__main__":
    unittest.main()
