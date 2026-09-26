import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import activity_monitor
from dispatch_router import (
    DIAGNOSTIC_PREFACE,
    HISTORY_SCHEMA_VERSION,
    OPERATOR_PREFACE,
    DispatchError,
    DispatchService,
    attributed_message,
)


CODEX_A = "01a020e9-c953-70d0-b86b-eb2e49f45cf5"
CODEX_B = "01a020e9-16a8-7fb2-a6f5-8470ae30fcd2"
CLAUDE_A = "f91d84b7-a732-4e94-bd32-1c87ec9c273f"
OWNER_A = "debeac58-62fb-4b36-9d35-a82cf1776310"
TURN_A = "64abc69d-5c26-455c-92a2-8d06f16bc498"


def codex_target(task_id=CODEX_A, title="Activity Monitor Brain"):
    return {
        "provider": "codex",
        "providerLabel": "Codex",
        "id": task_id,
        "title": title,
        "state": "active",
        "busy": True,
        "modelProvider": "openai",
        "_routingText": title,
        "_board": True,
        "_cwd": "/tmp/activity-monitor",
        "_path": "",
    }


def claude_target(session_id=CLAUDE_A, title="Claude Brain session"):
    return {
        "provider": "claude",
        "providerLabel": "Claude",
        "id": session_id,
        "title": title,
        "state": "active",
        "busy": True,
        "livePid": 321,
        "_routingText": title,
        "_board": True,
    }


class FakeDesktopClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.closed = False

    def request(self, method, params, **kwargs):
        self.requests.append((method, params, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        self.closed = True


class DispatchRouterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.history = self.home / "dispatch-history.json"
        self.service = DispatchService(
            home=self.home,
            history_path=self.history,
            codex_command="/usr/bin/false",
            board_command=[],
            monitor_seconds=5,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _install_permission_audit_fixture(self):
        audit = (
            self.service.home
            / ".codex"
            / "skills"
            / "maintain-full-access-plus"
            / "scripts"
            / "audit.zsh"
        )
        audit.parent.mkdir(parents=True)
        audit.write_text("#!/bin/zsh\n", encoding="utf-8")
        return audit

    def _install_claude_sender_fixture(self):
        self.service.claude_sender.parent.mkdir(parents=True, exist_ok=True)
        self.service.claude_sender.write_text("// fixture", encoding="utf-8")

    @staticmethod
    def _claude_receipt(original):
        return {
            "state": "queued",
            "sessionId": CLAUDE_A,
            "sourceSha256": hashlib.sha256(original.encode()).hexdigest(),
            "msgId": "dispatch-test",
            "socketWritten": True,
            "transcriptObserved": True,
            "contract": "ke.dispatch.claude.v1",
        }

    def test_fixed_attribution_preserves_original_text_verbatim(self):
        original = "  Keep spacing.\nDo not reinterpret ${authority}.  "
        self.assertEqual(attributed_message(original), OPERATOR_PREFACE + original)
        self.assertEqual(attributed_message(original, True), DIAGNOSTIC_PREFACE + original)

    def test_exact_id_is_materially_strongest_and_provider_is_preserved(self):
        targets = [codex_target(), claude_target(title="Activity Monitor Brain")]
        message = f"Please route this to exact Codex task {CODEX_A}."
        with patch.object(self.service, "_collect_targets", return_value=(targets, {"brain"}, True)):
            result = self.service.resolve(message)
        self.assertTrue(result["ok"])
        self.assertEqual(result["target"]["id"], CODEX_A)
        self.assertEqual(result["target"]["providerLabel"], "Codex")
        self.assertIn("Brain", result["reason"])

    def test_project_brain_association_is_metadata_only_routing_evidence(self):
        class FakeWorkspace:
            def routing_index(self, force=False):
                return {
                    CODEX_A: {
                        "provider": "codex",
                        "projectId": "local-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "projectName": "Activity Monitor",
                        "brainId": "brain_project_1234567890abcdef1234",
                        "parentBrainId": "brain_parent1234567",
                        "brainStatus": "ready",
                    }
                }

        self.service.workspace_service = FakeWorkspace()
        with patch.object(self.service, "_board_agents", return_value=[]), \
            patch.object(self.service, "_list_codex_threads", return_value=[{
                "id": CODEX_A,
                "name": "Unrelated implementation task",
                "status": {"type": "idle"},
            }]), \
            patch.object(self.service, "_live_claude_sessions", return_value=[]), \
            patch.object(self.service, "_brain_metadata_terms", return_value=set()):
            original = "activity monitor project private marker 9137"
            result = self.service.resolve(original)
        self.assertTrue(result["ok"])
        self.assertEqual(result["target"]["projectName"], "Activity Monitor")
        self.assertEqual(result["target"]["brainId"], "brain_project_1234567890abcdef1234")
        self.assertIn("project Brain association", result["target"]["reason"])
        self.assertIn("project/Brain association", result["reason"])
        serialized = json.dumps(result)
        self.assertNotIn(original, serialized)
        self.assertFalse(result["privacy"]["brainNoteBodiesRead"])

    def test_genuine_ambiguity_requires_selection_and_never_fans_out(self):
        targets = [
            codex_target(CODEX_A, "Brain visual verifier"),
            codex_target(CODEX_B, "Brain visual proof"),
        ]
        with patch.object(self.service, "_collect_targets", return_value=(targets, set(), True)):
            result = self.service.resolve("brain visual")
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "ambiguous")
        self.assertEqual(len(result["choices"]), 2)
        self.assertIsNone(result["target"])
        with self.assertRaisesRegex(DispatchError, "Choose one destination"):
            self.service.send(result["resolutionId"], "not-a-choice", "brain visual")

    def test_no_owner_fails_closed_and_history_contains_only_digest(self):
        body = "private-body-marker-4810"
        with patch.object(self.service, "_collect_targets", return_value=([], set(), False)):
            result = self.service.resolve(body)
        self.assertEqual(result["state"], "no target")
        raw = self.history.read_text()
        self.assertNotIn(body, raw)
        entry = json.loads(raw)["entries"][0]
        self.assertEqual(entry["sha256"], hashlib.sha256(body.encode()).hexdigest())
        self.assertNotIn("message", entry)

    def test_history_preserves_0600_receipts_under_existing_0755_support_parent(self):
        self.history.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.history.parent, 0o755)
        receipt = {
            "schemaVersion": "ke.activity-monitor-dispatch-history.v1",
            "entries": [{"id": "dispatch_existing", "state": "accepted", "sha256": "a" * 64}],
        }
        self.history.write_text(json.dumps(receipt), encoding="utf-8")
        os.chmod(self.history, 0o600)
        loaded = self.service._read_history()
        self.assertEqual(loaded["entries"][0]["id"], "dispatch_existing")
        self.service._write_history(loaded)
        self.assertEqual(stat.S_IMODE(self.history.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.history.parent.stat().st_mode), 0o755)

    def test_history_rejects_symlink_swap_and_non_private_file_mode(self):
        self.history.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.history.parent, 0o755)
        payload = {"schemaVersion": "ke.activity-monitor-dispatch-history.v1", "entries": [{"id": "outside"}]}
        self.history.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(self.history, 0o644)
        self.assertEqual(self.service._read_history()["entries"], [])
        os.chmod(self.history, 0o600)
        original = self.history.with_name("history-original.json")
        outside = self.home / "outside-history.json"
        outside.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(outside, 0o600)
        real_open = os.open
        swapped = False

        def swap_then_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == self.history.name and dir_fd is not None and not swapped:
                self.history.rename(original)
                self.history.symlink_to(outside)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with patch("dispatch_router.os.open", side_effect=swap_then_open):
            loaded = self.service._read_history()
        self.assertTrue(swapped)
        self.assertEqual(loaded["entries"], [])

    def test_existing_bad_history_blocks_send_without_overwrite_or_transport(self):
        target = codex_target()
        outside = self.home / "outside-attempted-history.json"
        outside_payload = json.dumps({
            "schemaVersion": HISTORY_SCHEMA_VERSION,
            "entries": [{"id": "dispatch_prior", "state": "accepted", "sha256": "a" * 64}],
        }).encode()
        outside.write_bytes(outside_payload)
        os.chmod(outside, 0o600)

        variants = ("malformed", "wrong-mode", "symlink", "unreadable")
        for index, variant in enumerate(variants):
            with self.subTest(variant=variant):
                if os.path.lexists(self.history):
                    if not self.history.is_symlink():
                        os.chmod(self.history, 0o600)
                    self.history.unlink()
                if variant == "malformed":
                    original = b"{malformed receipt history"
                    self.history.write_bytes(original)
                    os.chmod(self.history, 0o600)
                elif variant == "wrong-mode":
                    original = outside_payload
                    self.history.write_bytes(original)
                    os.chmod(self.history, 0o644)
                elif variant == "symlink":
                    original = outside_payload
                    self.history.symlink_to(outside)
                else:
                    original = outside_payload
                    self.history.write_bytes(original)
                    os.chmod(self.history, 0o000)

                message = f"blocked by {variant} history {index} {CODEX_A}"
                with patch.object(self.service, "_collect_targets", return_value=([target], set(), True)):
                    resolution = self.service.resolve(message)
                with patch.object(self.service, "_start_codex") as deliver:
                    with self.assertRaises(DispatchError) as raised:
                        self.service.send(resolution["resolutionId"], CODEX_A, message)
                self.assertEqual(raised.exception.code, "dispatch_history_unavailable")
                self.assertFalse(raised.exception.delivery_attempted)
                self.assertFalse(raised.exception.receipt["retrySafe"])
                self.assertTrue(raised.exception.receipt["reconciliationRequired"])
                deliver.assert_not_called()
                state = self.service.state()
                self.assertFalse(state["readiness"]["historyAvailable"])
                self.assertFalse(state["readiness"]["dispatchSendAllowed"])
                self.assertTrue(state["warnings"])
                if self.history.is_symlink():
                    self.assertEqual(self.history.resolve(), outside.resolve())
                    self.assertEqual(outside.read_bytes(), original)
                else:
                    os.chmod(self.history, 0o600)
                    self.assertEqual(self.history.read_bytes(), original)

        if os.path.lexists(self.history):
            if not self.history.is_symlink():
                os.chmod(self.history, 0o600)
            self.history.unlink()

    def test_resolution_binds_message_sha_and_routes_once(self):
        target = codex_target()
        original = f"For {CODEX_A}: preserve this exact payload."
        with patch.object(self.service, "_collect_targets", return_value=([target], set(), True)):
            resolution = self.service.resolve(original)
        with self.assertRaisesRegex(DispatchError, "changed"):
            self.service.send(resolution["resolutionId"], CODEX_A, original + " changed")
        with patch.object(
            self.service,
            "_start_codex",
            return_value=(
                "queued",
                {"turnId": TURN_A, "clientUserMessageId": "e733b109-88d3-4877-b6ee-f356c2d85e96"},
                None,
            ),
        ) as deliver:
            sent = self.service.send(resolution["resolutionId"], CODEX_A, original)
        self.assertTrue(sent["ok"])
        self.assertEqual(sent["target"]["providerLabel"], "Codex")
        deliver.assert_called_once()
        self.assertEqual(deliver.call_args.args[1], original)
        persisted = self.history.read_text()
        self.assertNotIn(original, persisted)
        self.assertEqual(persisted.count(hashlib.sha256(original.encode()).hexdigest()), 1)

    def test_restart_history_blocks_recent_possible_duplicate_before_transport(self):
        target = codex_target()
        original = f"same exact message after restart {CODEX_A}"
        digest = hashlib.sha256(original.encode()).hexdigest()
        self.service._history_entry(
            target,
            digest,
            "prior exact target",
            "accepted",
            False,
            {"deliveryAttempted": True, "retrySafe": False, "turnId": TURN_A},
        )
        with patch.object(self.service, "_collect_targets", return_value=([target], set(), True)):
            resolution = self.service.resolve(original)
        with patch.object(self.service, "_start_codex") as deliver:
            with self.assertRaises(DispatchError) as raised:
                self.service.send(resolution["resolutionId"], CODEX_A, original)
        self.assertEqual(raised.exception.code, "dispatch_reconciliation_required")
        self.assertTrue(raised.exception.delivery_attempted)
        deliver.assert_not_called()

    def test_restart_history_blocks_legacy_attempting_state_before_transport(self):
        target = codex_target()
        original = f"legacy in-flight attempt {CODEX_A}"
        digest = hashlib.sha256(original.encode()).hexdigest()
        self.history.write_text(json.dumps({
            "schemaVersion": HISTORY_SCHEMA_VERSION,
            "entries": [{
                "id": "dispatch_legacy_attempt",
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "destinationId": CODEX_A,
                "sha256": digest,
                "state": "attempting",
                "receipt": {"deliveryAttempted": False, "retrySafe": False},
            }],
        }), encoding="utf-8")
        os.chmod(self.history, 0o600)
        with patch.object(self.service, "_collect_targets", return_value=([target], set(), True)):
            resolution = self.service.resolve(original)
        with patch.object(self.service, "_start_codex") as deliver:
            with self.assertRaises(DispatchError) as raised:
                self.service.send(resolution["resolutionId"], CODEX_A, original)
        self.assertEqual(raised.exception.code, "dispatch_reconciliation_required")
        deliver.assert_not_called()

    def test_codex_app_server_command_must_be_a_trusted_executable(self):
        untrusted = self.home / "codex-untrusted"
        untrusted.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        os.chmod(untrusted, 0o777)
        service = DispatchService(
            home=self.home,
            history_path=self.history,
            codex_command=str(untrusted),
            board_command=["/usr/bin/false"],
        )
        self.assertIsNone(service.codex_command)

    def test_restart_history_allows_genuine_failed_before_send_retry(self):
        target = codex_target()
        original = f"retry exact pre-send failure {CODEX_A}"
        digest = hashlib.sha256(original.encode()).hexdigest()
        self.service._history_entry(
            target,
            digest,
            "prior exact target",
            "failed before send",
            False,
            {"deliveryAttempted": False, "retrySafe": True, "code": "desktop_ipc_unavailable"},
        )
        with patch.object(self.service, "_collect_targets", return_value=([target], set(), True)):
            resolution = self.service.resolve(original)
        with patch.object(
            self.service,
            "_start_codex",
            return_value=(
                "queued",
                {"turnId": TURN_A, "clientUserMessageId": "e733b109-88d3-4877-b6ee-f356c2d85e96"},
                None,
            ),
        ) as deliver, patch("dispatch_router.threading.Thread"):
            result = self.service.send(resolution["resolutionId"], CODEX_A, original)
        self.assertTrue(result["ok"])
        deliver.assert_called_once()

    def test_claude_bridge_receipt_preserves_exact_session_and_original_stdin(self):
        original = "Claude exact-session payload\nwith line two"
        target = claude_target()
        receipt = self._claude_receipt(original)
        completed = subprocess.CompletedProcess([], 0, json.dumps(receipt), "")
        self._install_claude_sender_fixture()
        with patch("dispatch_router.shutil.which", return_value="/usr/local/bin/node"), patch.object(
            self.service, "_permission_bypass_verified", return_value=True
        ), patch("dispatch_router.subprocess.run", return_value=completed) as run:
            state, result = self.service._send_claude(target, original, True)
        self.assertEqual(state, "transcript observed")
        self.assertTrue(result["socketWritten"])
        self.assertEqual(run.call_args.kwargs["input"], original)
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--session-id") + 1], CLAUDE_A)
        self.assertIn("--diagnostic", args)

    def test_claude_accepted_phase_keeps_reconciliation_fields_and_observer(self):
        original = f"accepted Claude phase {CLAUDE_A}"
        message_id = "f447c3b2-2c76-477e-831f-ce27d97fd878"
        target = {**claude_target(), "_projectKey": "-Users-test-Claude-Project"}
        with patch.object(self.service, "_collect_targets", return_value=([target], set(), True)):
            resolution = self.service.resolve(original)
        receipt = {
            "msgId": message_id,
            "socketWritten": True,
            "transcriptObserved": False,
            "deliveryAttempted": True,
            "retrySafe": False,
            "reconciliationRequired": True,
        }
        with patch.object(self.service, "_send_claude", return_value=("queued", receipt)), patch(
            "dispatch_router.threading.Thread"
        ) as monitor:
            result = self.service.send(resolution["resolutionId"], CLAUDE_A, original)
        self.assertTrue(result["ok"])
        self.assertEqual(result["phase"], "accepted")
        self.assertTrue(result["deliveryAttempted"])
        self.assertFalse(result["retrySafe"])
        self.assertTrue(result["reconciliationRequired"])
        monitor.assert_called_once()
        self.assertEqual(monitor.call_args.kwargs["target"], self.service._monitor_uncertain_claude_transcript)
        self.assertEqual(monitor.call_args.kwargs["args"][2:], (CLAUDE_A, message_id))

    def test_claude_socket_written_failure_is_uncertain_and_not_retryable(self):
        original = "socket already crossed"
        receipt = {
            "state": "blocked",
            "code": "transcript_verification_failed",
            "message": "socket write succeeded but verification failed",
            "sessionId": CLAUDE_A,
            "sourceSha256": hashlib.sha256(original.encode()).hexdigest(),
            "msgId": "c1b66c94-e0fc-4200-a20e-eac80968563c",
            "socketWritten": True,
            "transcriptObserved": False,
            "contract": "ke.dispatch.claude-delivery.v1",
        }
        self._install_claude_sender_fixture()
        with patch("dispatch_router.shutil.which", return_value="/usr/local/bin/node"), patch.object(
            self.service, "_permission_bypass_verified", return_value=True
        ), patch(
            "dispatch_router.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, json.dumps(receipt), ""),
        ):
            with self.assertRaises(DispatchError) as raised:
                self.service._send_claude(claude_target(), original, False)
        self.assertTrue(raised.exception.delivery_attempted)
        self.assertFalse(raised.exception.receipt["retrySafe"])
        self.assertEqual(raised.exception.receipt["msgId"], receipt["msgId"])

    def test_claude_pre_socket_failure_remains_provably_retryable(self):
        original = "socket never opened"
        receipt = {
            "state": "blocked",
            "code": "missing_live_session",
            "message": "no live inbox",
            "socketWritten": False,
            "contract": "ke.dispatch.claude-delivery.v1",
        }
        self._install_claude_sender_fixture()
        with patch("dispatch_router.shutil.which", return_value="/usr/local/bin/node"), patch.object(
            self.service, "_permission_bypass_verified", return_value=True
        ), patch(
            "dispatch_router.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, json.dumps(receipt), ""),
        ):
            with self.assertRaises(DispatchError) as raised:
                self.service._send_claude(claude_target(), original, False)
        self.assertFalse(raised.exception.delivery_attempted)
        self.assertTrue(raised.exception.receipt["retrySafe"])

    def test_claude_queued_without_socket_confirmation_fails_closed_as_uncertain(self):
        original = "contradictory receipt"
        receipt = {
            "state": "queued",
            "sessionId": CLAUDE_A,
            "sourceSha256": hashlib.sha256(original.encode()).hexdigest(),
            "socketWritten": False,
            "contract": "ke.dispatch.claude-delivery.v1",
        }
        self._install_claude_sender_fixture()
        with patch("dispatch_router.shutil.which", return_value="/usr/local/bin/node"), patch.object(
            self.service, "_permission_bypass_verified", return_value=True
        ), patch(
            "dispatch_router.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps(receipt), ""),
        ):
            with self.assertRaises(DispatchError) as raised:
                self.service._send_claude(claude_target(), original, False)
        self.assertEqual(raised.exception.code, "claude_receipt_protocol_error")
        self.assertTrue(raised.exception.delivery_attempted)
        self.assertFalse(raised.exception.receipt["retrySafe"])

    def test_first_claude_send_on_cold_start_runs_permission_audit(self):
        original = "Cold-start permission audit"
        audit = self._install_permission_audit_fixture()
        self._install_claude_sender_fixture()
        audit_result = subprocess.CompletedProcess([], 0, "FULL_ACCESS_PLUS=healthy\n", "")
        delivery_result = subprocess.CompletedProcess(
            [], 0, json.dumps(self._claude_receipt(original)), ""
        )

        with patch("dispatch_router.shutil.which", return_value="/usr/local/bin/node"), patch(
            "dispatch_router.time.monotonic", return_value=0.012
        ), patch(
            "dispatch_router.subprocess.run", side_effect=[audit_result, delivery_result]
        ) as run:
            state, receipt = self.service._send_claude(claude_target(), original, False)

        self.assertEqual(state, "transcript observed")
        self.assertTrue(receipt["transcriptObserved"])
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0], [str(audit)])
        self.assertEqual(
            run.call_args_list[0].kwargs["env"]["CODEX_THREAD_ID"],
            self.service.source_task_id,
        )
        self.assertEqual(run.call_args_list[1].kwargs["input"], original)

    def test_permission_audit_cache_preserves_results_until_expiry(self):
        audit = self._install_permission_audit_fixture()

        self.service._permission_audit = (10.0, True)
        with patch("dispatch_router.time.monotonic", return_value=69.999), patch(
            "dispatch_router.subprocess.run"
        ) as run:
            self.assertTrue(self.service._permission_bypass_verified())
        run.assert_not_called()

        self.service._permission_audit = (10.0, False)
        with patch("dispatch_router.time.monotonic", return_value=69.999), patch(
            "dispatch_router.subprocess.run"
        ) as run:
            self.assertFalse(self.service._permission_bypass_verified())
        run.assert_not_called()

        refreshed = subprocess.CompletedProcess([], 0, "FULL_ACCESS_PLUS=healthy\n", "")
        self.service._permission_audit = (10.0, False)
        with patch("dispatch_router.time.monotonic", side_effect=[70.0, 70.25]), patch(
            "dispatch_router.subprocess.run", return_value=refreshed
        ) as run:
            self.assertTrue(self.service._permission_bypass_verified())
        run.assert_called_once_with(
            [str(audit)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15.0,
            check=False,
            env=run.call_args.kwargs["env"],
        )
        self.assertEqual(self.service._permission_audit, (70.25, True))

    def test_first_claude_send_fails_closed_when_permission_audit_fails(self):
        self._install_permission_audit_fixture()
        self._install_claude_sender_fixture()
        failed_audit = subprocess.CompletedProcess([], 1, "FULL_ACCESS_PLUS=unhealthy\n", "")

        with patch("dispatch_router.shutil.which", return_value="/usr/local/bin/node"), patch(
            "dispatch_router.time.monotonic", return_value=0.012
        ), patch("dispatch_router.subprocess.run", return_value=failed_audit) as run:
            with self.assertRaises(DispatchError) as raised:
                self.service._send_claude(claude_target(), "must not emit", False)

        self.assertEqual(raised.exception.code, "source_permission_mode_unverified")
        run.assert_called_once()

    def test_dispatch_claude_registry_swap_to_symlink_fails_closed(self):
        sessions = self.home / ".claude" / "sessions"
        sessions.mkdir(parents=True, mode=0o700)
        os.chmod(sessions, 0o700)
        registry = sessions / "123.json"
        registry.write_text("{}", encoding="utf-8")
        os.chmod(registry, 0o644)
        outside = self.home / "outside-registry.json"
        outside.write_text(json.dumps({
            "sessionId": CLAUDE_A,
            "kind": "interactive",
            "peerProtocol": 1,
            "pid": os.getpid(),
            "messagingSocketPath": str(self.home / "outside.sock"),
        }), encoding="utf-8")
        os.chmod(outside, 0o600)
        original = sessions / "registry-original.json"
        real_open = os.open
        swapped = False

        def swap_then_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if path == "123.json" and dir_fd is not None and not swapped:
                registry.rename(original)
                registry.symlink_to(outside)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with patch("dispatch_router.os.open", side_effect=swap_then_open):
            records = self.service._live_claude_sessions()
        self.assertTrue(swapped)
        self.assertEqual(records, [])

    def test_busy_codex_uses_exact_discovered_owner_and_valid_receipt_shape(self):
        original = "Busy owner diagnostic"
        fake = FakeDesktopClient([
            {
                "type": "response",
                "resultType": "success",
                "method": "thread-owner-discovery",
                "handledByClientId": OWNER_A,
                "result": {},
            },
            {
                "type": "response",
                "resultType": "success",
                "method": "thread-follower-steer-turn",
                "handledByClientId": OWNER_A,
                "result": {"result": {"turnId": TURN_A}},
            },
        ])
        self.service.desktop_ipc_factory = lambda path: fake
        state, receipt, client = self.service._try_desktop_codex(codex_target(), original, True)
        self.assertEqual(state, "queued")
        self.assertIsNone(client)
        self.assertEqual(receipt["ownerClientId"], OWNER_A)
        self.assertEqual(receipt["deliveryMode"], "steer")
        self.assertEqual([call[0] for call in fake.requests], [
            "thread-owner-discovery", "thread-follower-steer-turn"
        ])
        method, params, options = fake.requests[1]
        self.assertEqual(options["target_client_id"], OWNER_A)
        self.assertEqual(params["conversationId"], CODEX_A)
        self.assertEqual(params["input"][0]["text"], DIAGNOSTIC_PREFACE + original)
        self.assertEqual(params["restoreMessage"]["text"], DIAGNOSTIC_PREFACE + original)
        self.assertTrue(fake.closed)

    def test_inactive_steer_starts_once_with_the_same_client_message_id(self):
        fake = FakeDesktopClient([
            {
                "type": "response", "resultType": "success",
                "method": "thread-owner-discovery", "handledByClientId": OWNER_A, "result": {},
            },
            {
                "type": "response", "resultType": "error",
                "method": "thread-follower-steer-turn", "handledByClientId": OWNER_A,
                "error": {"name": "SteerTurnInactiveError", "message": f"Cannot steer conversation {CODEX_A} because its active turn already ended"},
            },
            {
                "type": "response", "resultType": "success",
                "method": "thread-follower-start-turn", "handledByClientId": OWNER_A,
                "result": {"result": {"turn": {"id": TURN_A}}},
            },
        ])
        self.service.desktop_ipc_factory = lambda path: fake
        _, receipt, _ = self.service._try_desktop_codex(codex_target(), "idle exact task", False)
        self.assertEqual(receipt["deliveryMode"], "start-after-inactive-steer")
        self.assertEqual([call[0] for call in fake.requests], [
            "thread-owner-discovery", "thread-follower-steer-turn", "thread-follower-start-turn"
        ])
        steer_id = fake.requests[1][1]["clientUserMessageId"]
        start_id = fake.requests[2][1]["turnStartParams"]["clientUserMessageId"]
        self.assertEqual(steer_id, start_id)

    def test_unexpected_owner_error_fails_closed_without_start_fallback(self):
        fake = FakeDesktopClient([
            {
                "type": "response", "resultType": "success",
                "method": "thread-owner-discovery", "handledByClientId": OWNER_A, "result": {},
            },
            {
                "type": "response", "resultType": "error",
                "method": "thread-follower-steer-turn", "handledByClientId": OWNER_A,
                "error": {"message": "permission mismatch"},
            },
        ])
        self.service.desktop_ipc_factory = lambda path: fake
        with self.assertRaisesRegex(DispatchError, "permission mismatch"):
            self.service._try_desktop_codex(codex_target(), "do not reroute", False)
        self.assertEqual([call[0] for call in fake.requests], [
            "thread-owner-discovery", "thread-follower-steer-turn"
        ])

    def test_stale_owner_discovery_timeout_falls_through_to_exact_app_server_once(self):
        desktop = FakeDesktopClient([
            DispatchError("desktop_ipc_read_failed", "timed out before owner discovery"),
        ])
        self.service.desktop_ipc_factory = lambda path: desktop

        class FakeAppServer:
            instances = []

            def __init__(inner_self, command):
                inner_self.calls = []
                inner_self.closed = False
                FakeAppServer.instances.append(inner_self)

            def start(inner_self):
                inner_self.calls.append(("start", None))

            def request(inner_self, method, params, timeout=None):
                inner_self.calls.append((method, params))
                if method == "thread/resume":
                    return {"thread": {"id": CODEX_A}, "modelProvider": "openai"}
                if method == "turn/start":
                    return {"turn": {"id": TURN_A}}
                raise AssertionError(method)

            def close(inner_self):
                inner_self.closed = True

        with patch("dispatch_router.CodexAppServerClient", FakeAppServer):
            state, receipt, client = self.service._start_codex(
                codex_target(), "stale exact owner", False
            )

        self.assertEqual(state, "queued")
        self.assertEqual(receipt["turnId"], TURN_A)
        self.assertIs(client, FakeAppServer.instances[0])
        self.assertEqual([call[0] for call in desktop.requests], ["thread-owner-discovery"])
        self.assertEqual(
            [call[0] for call in client.calls],
            ["start", "thread/resume", "turn/start"],
        )
        self.assertFalse(client.closed)

    def test_post_steer_read_timeout_never_falls_back_or_duplicates(self):
        desktop = FakeDesktopClient([
            {
                "type": "response", "resultType": "success",
                "method": "thread-owner-discovery", "handledByClientId": OWNER_A,
                "result": {},
            },
            DispatchError("desktop_ipc_read_failed", "timeout after message-bearing steer"),
        ])
        self.service.desktop_ipc_factory = lambda path: desktop
        with patch("dispatch_router.CodexAppServerClient") as app_server:
            with self.assertRaisesRegex(DispatchError, "message-bearing steer"):
                self.service._start_codex(codex_target(), "send once only", False)
        app_server.assert_not_called()
        self.assertEqual(
            [call[0] for call in desktop.requests],
            ["thread-owner-discovery", "thread-follower-steer-turn"],
        )

    def test_desktop_success_without_turn_id_is_uncertain_and_cannot_duplicate(self):
        original = f"desktop accepted with missing turn receipt {CODEX_A}"
        target = codex_target()
        with patch.object(self.service, "_collect_targets", return_value=([target], set(), True)):
            resolution = self.service.resolve(original)
        desktop = FakeDesktopClient([
            {
                "type": "response", "resultType": "success",
                "method": "thread-owner-discovery", "handledByClientId": OWNER_A, "result": {},
            },
            {
                "type": "response", "resultType": "success",
                "method": "thread-follower-steer-turn", "handledByClientId": OWNER_A,
                "result": {"result": {}},
            },
        ])
        self.service.desktop_ipc_factory = lambda path: desktop
        with patch("dispatch_router.threading.Thread"):
            result = self.service.send(resolution["resolutionId"], CODEX_A, original)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "uncertain after send")
        self.assertFalse(result["retrySafe"])
        self.assertTrue(result["reconciliationRequired"])
        self.assertRegex(result["receipt"]["clientUserMessageId"], r"^[0-9a-f-]{36}$")
        with self.assertRaisesRegex(DispatchError, "reconcile it"):
            self.service.send(resolution["resolutionId"], CODEX_A, original)

    def test_app_server_success_without_turn_id_is_uncertain_and_not_retryable(self):
        original = f"app server accepted with missing turn receipt {CODEX_A}"
        target = codex_target()
        with patch.object(self.service, "_collect_targets", return_value=([target], set(), True)):
            resolution = self.service.resolve(original)
        self.service.desktop_ipc_factory = lambda path: FakeDesktopClient([
            DispatchError("desktop_ipc_read_failed", "stale owner discovery"),
        ])

        class MissingTurnAppServer:
            def __init__(inner_self, command):
                inner_self.closed = False

            def start(inner_self):
                pass

            def request(inner_self, method, params, timeout=None):
                if method == "thread/resume":
                    return {"thread": {"id": CODEX_A}, "modelProvider": "openai"}
                if method == "turn/start":
                    return {"turn": {}}
                raise AssertionError(method)

            def close(inner_self):
                inner_self.closed = True

        with patch("dispatch_router.CodexAppServerClient", MissingTurnAppServer), patch(
            "dispatch_router.threading.Thread"
        ):
            result = self.service.send(resolution["resolutionId"], CODEX_A, original)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "uncertain after send")
        self.assertFalse(result["retrySafe"])
        self.assertEqual(result["receipt"]["deliveryMode"], "app-server-start-receipt-uncertain")

    def test_uncertain_claude_socket_delivery_reconciles_by_metadata_id_only(self):
        project_directory = self.home / "Claude Project"
        project_directory.mkdir(mode=0o700)
        project_key = re.sub(r"[^A-Za-z0-9]", "-", str(project_directory))
        metadata_project = self.home / ".claude" / "projects" / project_key
        metadata_project.mkdir(parents=True, mode=0o700)
        os.chmod(self.home / ".claude" / "projects", 0o700)
        os.chmod(metadata_project, 0o700)
        message_id = "c1b66c94-e0fc-4200-a20e-eac80968563c"
        private_body = "private claude transcript body 7712"
        transcript = metadata_project / f"{CLAUDE_A}.jsonl"
        transcript.write_text(
            json.dumps({"msg_id": message_id, "message": private_body}) + "\n",
            encoding="utf-8",
        )
        os.chmod(transcript, 0o600)
        target = {**claude_target(), "_projectKey": project_key}
        entry = self.service._history_entry(
            target,
            hashlib.sha256(b"digest only").hexdigest(),
            "exact target",
            "uncertain after send",
            False,
            {"msgId": message_id, "reconciliationRequired": True},
        )
        self.service._monitor_uncertain_claude_transcript(
            entry["id"], project_key, CLAUDE_A, message_id
        )
        history = json.loads(self.history.read_text(encoding="utf-8"))
        updated = next(item for item in history["entries"] if item["id"] == entry["id"])
        self.assertEqual(updated["state"], "transcript observed")
        self.assertTrue(updated["receipt"]["transcriptMetadataObserved"])
        self.assertFalse(updated["receipt"]["reconciliationRequired"])
        self.assertNotIn(private_body, self.history.read_text(encoding="utf-8"))

    def test_transcript_observation_searches_metadata_id_without_persisting_body(self):
        sessions = self.home / ".codex" / "sessions" / "2026" / "08" / "20"
        sessions.mkdir(parents=True)
        message_id = "19ddfd84-1927-4fe0-9bb9-d86c4ae86e61"
        body = "sensitive-transcript-body-9241"
        rollout = sessions / "rollout.jsonl"
        rollout.write_text(json.dumps({"clientUserMessageId": message_id, "text": body}) + "\n")
        self.assertTrue(self.service._rollout_contains_id(str(rollout), message_id))
        self.assertFalse(self.history.exists())

    def test_ui_and_bridge_expose_real_brain_and_dispatch_wiring(self):
        html = activity_monitor.HTML
        for marker in (
            'data-tab="brain"', 'id="brain-tab"', 'id="brain-rescan"',
            'id="brain-structure-apply"', 'id="brain-structure-rollback"',
            'data-tab="dispatch"', 'id="dispatch-tab"', 'id="dispatch-message"',
            'id="dispatch-resolve"', 'id="dispatch-send"', 'id="dispatch-history"',
            "pywebview.api.resolve_dispatch", "pywebview.api.send_dispatch",
        ):
            self.assertIn(marker, html)
        self.assertIn("Type APPLY", html)
        self.assertIn("SHA-256", html)
        self.assertIn("Note text opens only when you select a file", html)

        class FakeDispatch:
            def __init__(self):
                self.sent = None

            def state(self):
                return {"ok": True, "state": "ready"}

            def resolve(self, message):
                return {"ok": True, "state": "resolved", "echoLength": len(message)}

            def send(self, resolution_id, target_id, message, diagnostic):
                self.sent = (resolution_id, target_id, message, diagnostic)
                return {"ok": True, "state": "queued"}

        fake = FakeDispatch()
        api = activity_monitor.Api(brain_service=object(), dispatch_service=fake)
        self.assertTrue(json.loads(api.get_dispatch_state())["ok"])
        self.assertEqual(json.loads(api.resolve_dispatch("verbatim"))["echoLength"], 8)
        self.assertEqual(
            json.loads(api.send_dispatch("resolution", CODEX_A, " exact ", True))["state"],
            "queued",
        )
        self.assertEqual(fake.sent, ("resolution", CODEX_A, " exact ", True))

        class UncertainDispatch(FakeDispatch):
            def send(self, *args):
                raise DispatchError(
                    "dispatch_reconciliation_required",
                    "reconcile exact receipt",
                    phase="accepted",
                    delivery_attempted=True,
                    receipt={
                        "deliveryAttempted": True,
                        "retrySafe": False,
                        "reconciliationRequired": True,
                        "messageBody": "must not cross bridge",
                    },
                )

        uncertain_api = activity_monitor.Api(
            brain_service=object(), dispatch_service=UncertainDispatch()
        )
        uncertain = json.loads(
            uncertain_api.send_dispatch("resolution", CODEX_A, "draft stays visible", False)
        )
        self.assertEqual(uncertain["state"], "uncertain after send")
        self.assertTrue(uncertain["deliveryAttempted"])
        self.assertFalse(uncertain["retrySafe"])
        self.assertTrue(uncertain["reconciliationRequired"])
        self.assertEqual(uncertain["phase"], "accepted")
        self.assertNotIn("messageBody", json.dumps(uncertain))

        class InvalidatedDispatch(FakeDispatch):
            def send(self, *args):
                raise DispatchError(
                    "resolution_expired",
                    "resolve again",
                    phase="owner preflight",
                    delivery_attempted=False,
                )

        invalidated_api = activity_monitor.Api(
            brain_service=object(), dispatch_service=InvalidatedDispatch()
        )
        invalidated = json.loads(
            invalidated_api.send_dispatch("expired", CODEX_A, "draft stays visible", False)
        )
        self.assertEqual(invalidated["state"], "failed before send")
        self.assertFalse(invalidated["deliveryAttempted"])
        self.assertFalse(invalidated["retrySafe"])
        self.assertFalse(invalidated["reconciliationRequired"])
        self.assertIn("result.state === 'failed before send'", activity_monitor.HTML)
        self.assertIn("sendButton.textContent = 'Resolve again'", activity_monitor.HTML)
        self.assertIn("Delivery did not start. Keep this draft; re-resolve it", activity_monitor.HTML)
        self.assertIn("Delivery may have occurred. Retry is disabled", activity_monitor.HTML)
        self.assertNotIn("nothing was duplicated", activity_monitor.HTML.lower())

        class HistoryBlockedDispatch(FakeDispatch):
            def send(self, *args):
                raise DispatchError(
                    "dispatch_history_unavailable",
                    "repair receipt history",
                    phase="history reconciliation",
                    delivery_attempted=False,
                    receipt={
                        "deliveryAttempted": False,
                        "retrySafe": False,
                        "reconciliationRequired": True,
                    },
                )

        history_api = activity_monitor.Api(
            brain_service=object(), dispatch_service=HistoryBlockedDispatch()
        )
        blocked = json.loads(
            history_api.send_dispatch("resolution", CODEX_A, "draft stays visible", False)
        )
        self.assertEqual(blocked["state"], "failed before send")
        self.assertEqual(blocked["phase"], "history reconciliation")
        self.assertFalse(blocked["deliveryAttempted"])
        self.assertFalse(blocked["retrySafe"])
        self.assertTrue(blocked["reconciliationRequired"])
        self.assertIn("Receipt history needs repair", activity_monitor.HTML)
        self.assertIn("No new delivery started. Existing receipt history", activity_monitor.HTML)


if __name__ == "__main__":
    unittest.main()
