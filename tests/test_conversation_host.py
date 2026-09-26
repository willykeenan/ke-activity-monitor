import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from conversation_host import (
    ClaudeConversationTransport,
    CodexConversationTransport,
    ConversationHostError,
    ConversationHostService,
    ReceiptStore,
    SCHEMA_VERSION,
)
from dispatch_router import DispatchError


PROJECT_A = "f44ff049-3883-480b-a103-2c4a0c93835e"
PROJECT_B = "77e9fec0-b306-468f-af9b-fae531607563"
THREAD_A = "11111111-1111-4111-8111-111111111111"
THREAD_B = "22222222-2222-4222-8222-222222222222"
THREAD_C = "33333333-3333-4333-8333-333333333333"
CREATED = "44444444-4444-4444-8444-444444444444"
TURN_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


class FakeWorkspace:
    def __init__(self, root: Path, projects=None):
        self.calls = []
        self.projects = projects or [
            {
                "id": PROJECT_A,
                "provider": "codex",
                "name": "Activity Monitor",
                "rootPath": str(root),
                "brainId": "brain_project_activity",
                "conversationCount": 0,
                "conversations": [],
            }
        ]

    def __call__(self, force=False):
        self.calls.append(bool(force))
        return {"ok": True, "projects": json.loads(json.dumps(self.projects))}


class FakeCodex:
    def __init__(self, *, create_delay=0.0):
        self.created = []
        self.sent = []
        self.reads = []
        self.exists = set()
        self.create_delay = create_delay
        self._lock = threading.Lock()
        self.read_items = [{"id": "answer", "role": "assistant", "text": "current answer"}]

    def create_thread(self, *, cwd, title, developer_instructions):
        if self.create_delay:
            time.sleep(self.create_delay)
        with self._lock:
            self.created.append({
                "cwd": cwd,
                "title": title,
                "developerInstructions": developer_instructions,
            })
            self.exists.add(CREATED)
        return {
            "id": CREATED,
            "provider": "codex",
            "title": title,
            "state": "idle",
            "stateSource": "Activity Monitor Conductor",
            "cwd": cwd,
        }

    def thread_exists(self, thread_id):
        return thread_id in self.exists

    def send(self, target, message, request_id):
        with self._lock:
            self.sent.append((dict(target), message, request_id))
        return {
            "state": "accepted",
            "phase": "accepted",
            "deliveryAttempted": True,
            "retrySafe": False,
            "reconciliationRequired": False,
            "clientUserMessageId": request_id,
            "turnId": TURN_A,
        }

    def read(self, target):
        self.reads.append(dict(target))
        return {
            "ok": True,
            "provider": "codex",
            "conversationId": target["id"],
            "title": target["title"],
            "items": json.loads(json.dumps(self.read_items)),
            "nextCursor": None,
        }


class FakeClaude:
    def __init__(self):
        self.sent = []
        self.reads = []

    def send(self, target, message, request_id):
        self.sent.append((dict(target), message, request_id))
        return {
            "state": "accepted",
            "phase": "accepted",
            "deliveryAttempted": True,
            "retrySafe": False,
            "reconciliationRequired": False,
            "clientUserMessageId": request_id,
            "turnId": TURN_A,
        }

    def read(self, target):
        self.reads.append(dict(target))
        return {
            "ok": True,
            "provider": "claude",
            "conversationId": target["id"],
            "title": target["title"],
            "items": [{"role": "assistant", "text": "claude answer"}],
            "nextCursor": None,
        }


class PreSendFailCodex(FakeCodex):
    def __init__(self):
        super().__init__()
        self.failures = 1

    def send(self, target, message, request_id):
        self.sent.append((dict(target), message, request_id))
        if self.failures:
            self.failures -= 1
            raise ConversationHostError(
                "preflight_failed",
                "delivery did not start",
                phase="owner preflight",
                delivery_attempted=False,
            )
        return super().send(target, message, request_id)


class UncertainCodex(FakeCodex):
    def send(self, target, message, request_id):
        self.sent.append((dict(target), message, request_id))
        raise ConversationHostError(
            "receipt_timeout",
            "delivery may have occurred",
            phase="exact-task resume/steer",
            delivery_attempted=True,
            receipt={"clientUserMessageId": request_id},
        )


class UncertainCreateCodex(FakeCodex):
    def __init__(self):
        super().__init__()
        self.create_attempts = 0

    def create_thread(self, *, cwd, title, developer_instructions):
        self.create_attempts += 1
        raise ConversationHostError(
            "codex_thread_creation_uncertain",
            "the project task may have been created",
            phase="task creation",
            delivery_attempted=True,
        )


class UncertainClaude(FakeClaude):
    def send(self, target, message, request_id):
        self.sent.append((dict(target), message, request_id))
        raise ConversationHostError(
            "claude_receipt_timeout",
            "the private socket write may have completed",
            phase="exact-session delivery",
            delivery_attempted=True,
            receipt={"clientUserMessageId": request_id, "msgId": THREAD_B},
        )


class UncertainResultClaude(FakeClaude):
    def send(self, target, message, request_id):
        self.sent.append((dict(target), message, request_id))
        return {
            "state": "uncertain after send",
            "phase": "uncertain after send",
            "deliveryAttempted": True,
            "retrySafe": False,
            "reconciliationRequired": True,
            "clientUserMessageId": request_id,
            "providerMessageId": THREAD_B,
        }


class ConversationHostServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.project_root = self.home / "project"
        self.project_root.mkdir(mode=0o700)
        self.store_path = self.home / "support" / "conversation-host-receipts.json"
        self.codex = FakeCodex()
        self.claude = FakeClaude()
        self.workspace = FakeWorkspace(self.project_root)

    def tearDown(self):
        self.temp.cleanup()

    def service(self, *, workspace=None, codex=None, claude=None, full_access=True):
        return ConversationHostService(
            workspace or self.workspace,
            home=self.home,
            store_path=self.store_path,
            codex_transport=codex or self.codex,
            claude_transport=claude or self.claude,
            full_access_checker=lambda: full_access,
        )

    @staticmethod
    def request_id(index=1):
        return f"00000000-0000-4000-8000-{index:012d}"

    def test_project_state_is_scoped_to_final_visible_projects(self):
        service = self.service()
        state = service.project_state("codex", PROJECT_A)
        self.assertTrue(state["ok"])
        self.assertEqual(state["schemaVersion"], SCHEMA_VERSION)
        self.assertTrue(state["capabilities"]["conductor"])
        self.assertTrue(state["capabilities"]["powerSwarmExistingOrCreate"])
        self.assertFalse(state["privacy"]["transcriptBodyRead"])

        with self.assertRaises(ConversationHostError) as hidden:
            service.project_state("codex", PROJECT_B)
        self.assertEqual(hidden.exception.code, "project_not_visible")

    def test_verified_active_owner_is_routed_without_creation(self):
        self.workspace.projects[0]["conversations"] = [
            {
                "id": THREAD_A,
                "provider": "codex",
                "title": "Orchard dataset",
                "state": "active",
                "stateSource": "Agent Board",
                "updatedAtEpoch": 50,
            }
        ]
        result = self.service().submit(
            "codex",
            PROJECT_A,
            "Continue the Orchard dataset replay",
            self.request_id(),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["destination"]["id"], THREAD_A)
        self.assertEqual(result["receipt"]["routeKind"], "existing-owner")
        self.assertEqual(self.codex.created, [])
        self.assertEqual(self.codex.sent[0][0]["id"], THREAD_A)

    def test_ambiguous_active_owners_fall_back_to_one_conductor(self):
        self.workspace.projects[0]["conversations"] = [
            {
                "id": THREAD_A,
                "provider": "codex",
                "title": "Orchard replay A",
                "state": "active",
                "stateSource": "Agent Board",
            },
            {
                "id": THREAD_B,
                "provider": "codex",
                "title": "Orchard replay B",
                "state": "active",
                "stateSource": "Agent Board",
            },
        ]
        result = self.service().submit(
            "codex", PROJECT_A, "Continue the Orchard replay", self.request_id()
        )
        self.assertEqual(result["destination"]["id"], CREATED)
        self.assertEqual(result["receipt"]["routeKind"], "created-conductor")
        self.assertEqual(len(self.codex.created), 1)

    def test_powerswarm_existing_task_is_reused_even_when_inactive(self):
        self.workspace.projects[0]["conversations"] = [
            {
                "id": THREAD_B,
                "provider": "codex",
                "title": "KE PowerSwarm orchestration",
                "state": "not loaded",
                "stateSource": "provider metadata",
                "updatedAtEpoch": 60,
            }
        ]
        result = self.service().submit(
            "codex", PROJECT_A, "Run this through PowerSwarm", self.request_id()
        )
        self.assertEqual(result["destination"]["id"], THREAD_B)
        self.assertEqual(result["receipt"]["routeKind"], "existing-powerswarm")
        self.assertEqual(self.codex.created, [])

    def test_eight_rapid_powerswarm_requests_create_exactly_one_task(self):
        codex = FakeCodex(create_delay=0.03)
        service = self.service(codex=codex)

        def submit(index):
            return service.submit(
                "codex",
                PROJECT_A,
                f"PowerSwarm request number {index}",
                self.request_id(index + 1),
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(submit, range(8)))

        self.assertEqual(len(codex.created), 1)
        self.assertEqual(len(codex.sent), 8)
        self.assertTrue(all(item["destination"]["id"] == CREATED for item in results))
        self.assertEqual(
            {item["receipt"]["routeKind"] for item in results},
            {"created-powerswarm", "existing-powerswarm"},
        )

    def test_uncertain_task_creation_durably_blocks_a_duplicate_agent(self):
        codex = UncertainCreateCodex()
        service = self.service(codex=codex)
        with self.assertRaises(ConversationHostError) as first:
            service.submit("codex", PROJECT_A, "First project request", self.request_id())
        self.assertTrue(first.exception.delivery_attempted)
        self.assertTrue(first.exception.reconciliation_required)

        with self.assertRaises(ConversationHostError) as second:
            service.submit("codex", PROJECT_A, "Different rapid follow-up", self.request_id(2))
        self.assertEqual(second.exception.code, "task_creation_reconciliation_required")
        self.assertFalse(second.exception.delivery_attempted)
        self.assertFalse(second.exception.retry_safe)
        self.assertTrue(second.exception.reconciliation_required)
        self.assertEqual(codex.create_attempts, 1)
        stored = json.loads(self.store_path.read_text())
        guard = stored["creationGuards"][f"codex:{PROJECT_A}:conductor"]
        self.assertEqual(guard["state"], "uncertain")
        self.assertEqual(guard["requestId"], self.request_id())

    def test_created_conductor_has_full_access_and_no_native_child_policy(self):
        result = self.service().submit(
            "codex", PROJECT_A, "Please take care of the project backlog", self.request_id()
        )
        self.assertEqual(result["receipt"]["routeKind"], "created-conductor")
        created = self.codex.created[0]
        self.assertEqual(created["cwd"], str(self.project_root.resolve()))
        self.assertEqual(created["title"], "Conductor · Activity Monitor")
        self.assertIn("full local tools and Full Access", created["developerInstructions"])
        self.assertIn("create at most one", created["developerInstructions"])
        self.assertIn("Never use native Codex child agents", created["developerInstructions"])
        self.assertIn("PowerSwarm/Grok", created["developerInstructions"])

    def test_newly_created_conductor_can_be_read_before_workspace_refresh_lists_it(self):
        service = self.service()
        created = service.submit(
            "codex", PROJECT_A, "Create the project command center", self.request_id()
        )
        result = service.read_conversation("codex", created["destination"]["id"])
        self.assertEqual(result["conversationId"], CREATED)
        self.assertEqual(result["title"], "Conductor · Activity Monitor")
        self.assertEqual(result["items"][0]["text"], "current answer")

    def test_full_access_failure_is_provably_pre_send(self):
        message = "Keep this private request body out of receipts"
        service = self.service(full_access=False)
        with self.assertRaises(ConversationHostError) as failure:
            service.submit("codex", PROJECT_A, message, self.request_id())
        self.assertEqual(failure.exception.code, "full_access_unverified")
        self.assertFalse(failure.exception.delivery_attempted)
        stored = self.store_path.read_text()
        self.assertNotIn(message, stored)
        entry = json.loads(stored)["receipts"][0]
        self.assertEqual(entry["state"], "failed before send")
        self.assertTrue(entry["retrySafe"])
        self.assertFalse(entry["reconciliationRequired"])

    def test_same_request_id_is_idempotent_and_sends_once(self):
        message = "One durable request"
        request_id = self.request_id()
        service = self.service()
        first = service.submit("codex", PROJECT_A, message, request_id)
        second = service.submit("codex", PROJECT_A, message, request_id)
        self.assertTrue(first["ok"])
        self.assertTrue(second["idempotentReplay"])
        self.assertEqual(len(self.codex.sent), 1)

    def test_request_id_cannot_be_reused_for_different_text(self):
        request_id = self.request_id()
        service = self.service()
        service.submit("codex", PROJECT_A, "first", request_id)
        with self.assertRaises(ConversationHostError) as reused:
            service.submit("codex", PROJECT_A, "second", request_id)
        self.assertEqual(reused.exception.code, "client_request_id_reused")

    def test_uncertain_after_send_blocks_same_digest_and_retry(self):
        service = self.service(codex=UncertainCodex())
        message = "May have crossed the transport"
        with self.assertRaises(ConversationHostError) as uncertain:
            service.submit("codex", PROJECT_A, message, self.request_id())
        self.assertTrue(uncertain.exception.delivery_attempted)
        self.assertFalse(uncertain.exception.retry_safe)
        self.assertTrue(uncertain.exception.reconciliation_required)
        with self.assertRaises(ConversationHostError) as duplicate:
            service.submit("codex", PROJECT_A, message, self.request_id(2))
        self.assertEqual(duplicate.exception.code, "reconciliation_required")

    def test_uncertain_receipt_reconciles_only_on_exact_provider_message_id(self):
        codex = UncertainCodex()
        service = self.service(codex=codex)
        request_id = self.request_id()
        with self.assertRaises(ConversationHostError):
            service.submit("codex", PROJECT_A, "Observe me exactly", request_id)
        codex.read_items = [{"id": request_id, "role": "user", "text": "Observe me exactly"}]
        reconciled = service.reconcile_request(request_id)
        self.assertTrue(reconciled["ok"])
        self.assertEqual(reconciled["state"], "transcript observed")
        self.assertFalse(reconciled["receipt"]["reconciliationRequired"])

    def test_uncertain_receipt_without_exact_id_remains_uncertain(self):
        codex = UncertainCodex()
        service = self.service(codex=codex)
        request_id = self.request_id()
        with self.assertRaises(ConversationHostError):
            service.submit("codex", PROJECT_A, "Do not guess", request_id)
        codex.read_items = [{"id": THREAD_B, "role": "user", "text": "Do not guess"}]
        result = service.reconcile_request(request_id)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "uncertain after send")
        self.assertTrue(result["receipt"]["reconciliationRequired"])

    def test_failed_before_send_allows_new_fixed_id_retry(self):
        codex = PreSendFailCodex()
        service = self.service(codex=codex)
        message = "Safe retry after preflight"
        with self.assertRaises(ConversationHostError) as first:
            service.submit("codex", PROJECT_A, message, self.request_id())
        self.assertFalse(first.exception.delivery_attempted)
        result = service.submit("codex", PROJECT_A, message, self.request_id(2))
        self.assertTrue(result["ok"])

    def test_receipt_file_is_mode_0600_bounded_and_body_free(self):
        message = "secret-looking-but-not-a-secret body token 998877"
        self.service().submit("codex", PROJECT_A, message, self.request_id())
        metadata = self.store_path.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        raw = self.store_path.read_text()
        self.assertLess(len(raw.encode("utf-8")), 512 * 1024)
        self.assertNotIn(message, raw)
        self.assertNotIn("998877", raw)
        self.assertIn("sha256", raw)

    def test_mode_0755_parent_and_0600_receipt_is_accepted(self):
        parent = self.store_path.parent
        parent.mkdir(parents=True)
        os.chmod(parent, 0o755)
        payload = ReceiptStore.defaults()
        self.store_path.write_text(json.dumps(payload))
        os.chmod(self.store_path, 0o600)
        self.assertEqual(ReceiptStore(self.store_path).read()["schemaVersion"], payload["schemaVersion"])

    def test_existing_0644_receipt_is_rejected(self):
        self.store_path.parent.mkdir(parents=True)
        self.store_path.write_text(json.dumps(ReceiptStore.defaults()))
        os.chmod(self.store_path, 0o644)
        with self.assertRaises(ConversationHostError) as insecure:
            ReceiptStore(self.store_path).read()
        self.assertEqual(insecure.exception.code, "receipt_store_insecure")

    def test_receipt_symlink_is_rejected_without_following(self):
        self.store_path.parent.mkdir(parents=True)
        target = self.home / "outside.json"
        target.write_text(json.dumps(ReceiptStore.defaults()))
        os.chmod(target, 0o600)
        self.store_path.symlink_to(target)
        with self.assertRaises(ConversationHostError) as insecure:
            ReceiptStore(self.store_path).read()
        self.assertIn(insecure.exception.code, {"receipt_store_unreadable", "receipt_store_insecure"})

    def test_transcript_read_occurs_only_after_exact_explicit_call(self):
        self.workspace.projects[0]["conversations"] = [
            {
                "id": THREAD_A,
                "provider": "codex",
                "title": "Exact task",
                "state": "idle",
                "stateSource": "provider metadata",
            }
        ]
        service = self.service()
        service.project_state("codex", PROJECT_A)
        self.assertEqual(self.codex.reads, [])
        result = service.read_conversation("codex", THREAD_A)
        self.assertEqual(result["items"][0]["text"], "current answer")
        self.assertTrue(result["privacy"]["transcriptBodyRead"])
        self.assertFalse(result["privacy"]["transcriptBodiesPersistedByActivityMonitor"])
        self.assertEqual(len(self.codex.reads), 1)

        uppercase = service.read_conversation("Codex", THREAD_A)
        self.assertEqual(uppercase["provider"], "codex")
        self.assertEqual(len(self.codex.reads), 2)

    def test_hidden_provider_conversation_cannot_be_read_or_sent(self):
        service = self.service()
        with self.assertRaises(ConversationHostError) as hidden:
            service.read_conversation("codex", THREAD_A)
        self.assertEqual(hidden.exception.code, "conversation_not_visible")
        with self.assertRaises(ConversationHostError):
            service.send_conversation("codex", THREAD_A, "hello", self.request_id())

    def test_exact_conversation_uncertainty_preserves_provider_id_for_reconciliation(self):
        self.workspace.projects[0]["provider"] = "claude"
        self.workspace.projects[0]["conversations"] = [
            {
                "id": THREAD_A,
                "provider": "claude",
                "title": "Exact Claude session",
                "state": "active",
                "stateSource": "live private session registry",
            }
        ]
        service = self.service(claude=UncertainClaude())
        request_id = self.request_id()
        with self.assertRaises(ConversationHostError) as failure:
            service.send_conversation("claude", THREAD_A, "hello", request_id)
        self.assertEqual(failure.exception.phase, "exact-session delivery")
        self.assertTrue(failure.exception.delivery_attempted)
        self.assertFalse(failure.exception.retry_safe)
        receipt = failure.exception.receipt
        self.assertEqual(receipt["destinationId"], THREAD_A)
        self.assertEqual(receipt["clientUserMessageId"], request_id)
        self.assertEqual(receipt["providerMessageId"], THREAD_B)
        self.assertTrue(receipt["reconciliationRequired"])
        public = failure.exception.public()
        self.assertEqual(public["receipt"]["providerMessageId"], THREAD_B)
        self.assertFalse(public["retrySafe"])

    def test_unreconciled_claude_resume_blocks_a_second_writer(self):
        self.workspace.projects[0]["provider"] = "claude"
        self.workspace.projects[0]["conversations"] = [
            {
                "id": THREAD_A,
                "provider": "claude",
                "title": "Inactive Claude session",
                "state": "idle",
                "stateSource": "provider metadata",
            }
        ]
        claude = UncertainResultClaude()
        service = self.service(claude=claude)
        first = service.send_conversation("claude", THREAD_A, "first", self.request_id())
        self.assertFalse(first["ok"])
        self.assertTrue(first["receipt"]["reconciliationRequired"])
        with self.assertRaises(ConversationHostError) as blocked:
            service.send_conversation("claude", THREAD_A, "second", self.request_id(2))
        self.assertEqual(blocked.exception.code, "destination_reconciliation_required")
        self.assertFalse(blocked.exception.delivery_attempted)
        self.assertFalse(blocked.exception.retry_safe)
        self.assertTrue(blocked.exception.reconciliation_required)
        self.assertEqual(len(claude.sent), 1)

    def test_stale_process_accepted_receipt_blocks_post_crash_duplicate(self):
        self.workspace.projects[0]["conversations"] = [
            {
                "id": THREAD_A,
                "provider": "codex",
                "title": "Exact task",
                "state": "idle",
                "stateSource": "provider metadata",
            }
        ]
        previous = self.service()
        previous_id = self.request_id()
        project_key = f"codex:{PROJECT_A}"
        previous._claim(previous_id, project_key, "codex", "a" * 64)
        previous._update_receipt(
            previous_id,
            destinationId=THREAD_A,
            destinationProvider="codex",
            state="accepted",
            phase="accepted",
            deliveryAttempted=True,
            retrySafe=False,
        )

        restarted = self.service()
        with self.assertRaises(ConversationHostError) as blocked:
            restarted.send_conversation("codex", THREAD_A, "new request", self.request_id(2))
        self.assertEqual(blocked.exception.code, "destination_reconciliation_required")
        self.assertFalse(blocked.exception.delivery_attempted)
        self.assertFalse(blocked.exception.retry_safe)
        self.assertEqual(self.codex.sent, [])

    def test_error_public_receipt_drops_untrusted_body_fields(self):
        error = ConversationHostError(
            "receipt_timeout",
            "delivery may have occurred",
            phase="exact-session delivery",
            delivery_attempted=True,
            receipt={
                "providerMessageId": THREAD_B,
                "message": "private request body",
                "transcript": "private provider response",
            },
        )
        public = error.public()
        self.assertEqual(public["receipt"], {"providerMessageId": THREAD_B})
        self.assertNotIn("private", json.dumps(public))


class ReceiptStoreSwapTests(unittest.TestCase):
    def test_parent_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            parent = root / "support"
            parent.symlink_to(outside, target_is_directory=True)
            store = ReceiptStore(parent / "receipts.json")
            with self.assertRaises(ConversationHostError) as failure:
                store.write(ReceiptStore.defaults())
            self.assertIn(failure.exception.code, {"receipt_store_unavailable", "receipt_store_insecure"})


class ClaudeTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.project_root = self.home / "real-project"
        self.project_root.mkdir(mode=0o700)
        self.storage_key = "-Users-alex-real-project"
        self.session_id = THREAD_C
        projects = self.home / ".claude" / "projects"
        projects.mkdir(parents=True, mode=0o700)
        os.chmod(self.home / ".claude", 0o700)
        os.chmod(projects, 0o700)
        self.project_store = projects / self.storage_key
        self.project_store.mkdir(mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def target(self, **patch):
        value = {
            "id": self.session_id,
            "provider": "claude",
            "title": "Claude session",
            "state": "idle",
            "cwd": str(self.project_root),
            "projectKey": self.storage_key,
        }
        value.update(patch)
        return value

    def test_descriptor_bound_exact_transcript_read(self):
        transcript = self.project_store / f"{self.session_id}.jsonl"
        rows = [
            {
                "sessionId": self.session_id,
                "uuid": THREAD_A,
                "type": "user",
                "message": {"content": "hello Claude"},
            },
            {
                "sessionId": self.session_id,
                "uuid": THREAD_B,
                "type": "assistant",
                "message": {"content": [{"type": "text", "text": "hello Alex"}]},
            },
        ]
        transcript.write_text("\n".join(json.dumps(item) for item in rows) + "\n")
        os.chmod(transcript, 0o600)
        result = ClaudeConversationTransport(home=self.home, command="/usr/bin/true").read(self.target())
        self.assertEqual([item["role"] for item in result["items"]], ["user", "assistant"])
        self.assertEqual(result["items"][1]["text"], "hello Alex")

    def test_transcript_symlink_is_rejected(self):
        outside = self.home / "outside.jsonl"
        outside.write_text("{}\n")
        os.chmod(outside, 0o600)
        (self.project_store / f"{self.session_id}.jsonl").symlink_to(outside)
        with self.assertRaises(ConversationHostError) as failure:
            ClaudeConversationTransport(home=self.home, command="/usr/bin/true").read(self.target())
        self.assertEqual(failure.exception.code, "claude_transcript_unavailable")

    def test_non_private_transcript_is_rejected(self):
        transcript = self.project_store / f"{self.session_id}.jsonl"
        transcript.write_text("{}\n")
        os.chmod(transcript, 0o644)
        with self.assertRaises(ConversationHostError) as failure:
            ClaudeConversationTransport(home=self.home, command="/usr/bin/true").read(self.target())
        self.assertEqual(failure.exception.code, "claude_transcript_untrusted")

    def test_inactive_exact_resume_uses_fixed_argv_and_project_cwd(self):
        launches = []
        input_copies = []

        def launch(args, **kwargs):
            launches.append((list(args), dict(kwargs)))
            input_copies.append(os.dup(kwargs["stdin"]))
            return object()

        transport = ClaudeConversationTransport(
            home=self.home,
            command="/usr/bin/true",
            process_launcher=launch,
        )
        request_id = "99999999-9999-4999-8999-999999999999"
        result = transport.send(self.target(), "exact prompt", request_id)
        args, kwargs = launches[0]
        self.assertEqual(args[0], "/usr/bin/true")
        self.assertEqual(args[1], "-p")
        self.assertNotIn("exact prompt", args)
        self.assertEqual(args[args.index("--resume") + 1], self.session_id)
        self.assertEqual(args[args.index("--input-format") + 1], "text")
        self.assertEqual(args[args.index("--permission-mode") + 1], "bypassPermissions")
        self.assertEqual(kwargs["cwd"], str(self.project_root.resolve()))
        self.assertEqual(os.read(input_copies[0], 1024), b"exact prompt")
        os.close(input_copies[0])
        self.assertTrue(result["deliveryAttempted"])
        self.assertTrue(result["reconciliationRequired"])
        self.assertEqual(result["state"], "uncertain after send")

    def test_active_session_never_starts_second_cli_writer(self):
        launches = []
        transport = ClaudeConversationTransport(
            home=self.home,
            command="/usr/bin/true",
            process_launcher=lambda *args, **kwargs: launches.append((args, kwargs)),
        )
        with self.assertRaises(ConversationHostError) as failure:
            transport.send(
                self.target(state="active"),
                "do not duplicate",
                "99999999-9999-4999-8999-999999999999",
            )
        self.assertEqual(failure.exception.code, "claude_live_owner_required")
        self.assertFalse(failure.exception.delivery_attempted)
        self.assertEqual(launches, [])

    def test_live_receipt_without_socket_write_fails_closed_pre_send(self):
        transport = ClaudeConversationTransport(
            home=self.home,
            command="/usr/bin/true",
            live_sender=lambda target, message, request_id: {
                "state": "queued",
                "socketWritten": False,
                "msgId": THREAD_A,
            },
        )
        with self.assertRaises(ConversationHostError) as failure:
            transport.send(
                self.target(state="active"),
                "message",
                "99999999-9999-4999-8999-999999999999",
            )
        self.assertEqual(failure.exception.code, "claude_socket_not_confirmed")
        self.assertFalse(failure.exception.delivery_attempted)

    def test_socket_written_without_transcript_is_truthfully_uncertain(self):
        transport = ClaudeConversationTransport(
            home=self.home,
            command="/usr/bin/true",
            live_sender=lambda target, message, request_id: {
                "state": "queued",
                "socketWritten": True,
                "transcriptObserved": False,
                "msgId": THREAD_A,
            },
        )
        result = transport.send(
            self.target(state="active"),
            "message",
            "99999999-9999-4999-8999-999999999999",
        )
        self.assertEqual(result["state"], "uncertain after send")
        self.assertTrue(result["deliveryAttempted"])
        self.assertFalse(result["retrySafe"])
        self.assertTrue(result["reconciliationRequired"])


class FakeDesktopNoOwner:
    def __init__(self, path, *, error_code=None):
        self.path = path
        self.error_code = error_code
        self.calls = []

    def request(self, method, params, **kwargs):
        self.calls.append((method, params, kwargs))
        if self.error_code:
            raise DispatchError(self.error_code, "stale discovery")
        return {"resultType": "error", "error": "no-client-found"}

    def close(self):
        pass


class FakeAppServer:
    def __init__(self, command, *, missing_turn=False, fail_method=None):
        self.command = command
        self.missing_turn = missing_turn
        self.fail_method = fail_method
        self.calls = []
        self.closed = False
        self.notifications = []

    def start(self):
        self.calls.append(("_start", {}))

    def request(self, method, params, timeout=None):
        self.calls.append((method, dict(params), timeout))
        if method == self.fail_method:
            raise DispatchError("desktop_ipc_timeout", f"{method} timed out")
        if method == "thread/start":
            return {"thread": {"id": CREATED}}
        if method == "thread/name/set":
            return {"thread": {"id": CREATED, "name": params["name"]}}
        if method == "thread/read":
            return {"thread": {"id": params["threadId"]}}
        if method == "thread/resume":
            return {"thread": {"id": params["threadId"]}}
        if method == "turn/start":
            return {"turn": {} if self.missing_turn else {"id": TURN_A}}
        if method == "turn/steer":
            return {"turn": {"id": params["expectedTurnId"]}}
        if method == "thread/turns/list":
            return {
                "data": [
                    {
                        "id": TURN_A,
                        "items": [
                            {"id": "agent", "type": "agentMessage", "text": "answer"},
                            {"id": "user", "type": "userMessage", "content": [{"text": "question"}]},
                        ],
                    }
                ],
                "nextCursor": "older",
            }
        raise AssertionError(method)

    def next_notification(self, timeout=1.0):
        time.sleep(min(float(timeout), 0.01))
        return self.notifications.pop(0) if self.notifications else None

    def close(self):
        self.closed = True


class CodexTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "project"
        self.project.mkdir(mode=0o700)
        self.clients = []
        self.desktops = []

    def tearDown(self):
        self.temp.cleanup()

    def transport(
        self,
        *,
        missing_turn=False,
        discovery_error=None,
        fail_method=None,
        monitor_seconds=0.2,
    ):
        def client_factory(command):
            client = FakeAppServer(command, missing_turn=missing_turn, fail_method=fail_method)
            self.clients.append(client)
            return client

        def desktop_factory(path):
            desktop = FakeDesktopNoOwner(path, error_code=discovery_error)
            self.desktops.append(desktop)
            return desktop

        return CodexConversationTransport(
            "/usr/bin/true",
            desktop_ipc_factory=desktop_factory,
            client_factory=client_factory,
            monitor_seconds=monitor_seconds,
        )

    def target(self):
        return {
            "id": THREAD_A,
            "provider": "codex",
            "title": "Exact task",
            "cwd": str(self.project),
        }

    def test_create_thread_uses_full_access_persistent_exact_project_params(self):
        transport = self.transport()
        result = transport.create_thread(
            cwd=str(self.project),
            title="Conductor · Test",
            developer_instructions="bounded conductor",
        )
        self.assertEqual(result["id"], CREATED)
        calls = self.clients[0].calls
        params = next(item[1] for item in calls if item[0] == "thread/start")
        self.assertEqual(params["cwd"], str(self.project.resolve()))
        self.assertEqual(params["runtimeWorkspaceRoots"], [str(self.project.resolve())])
        self.assertEqual(params["approvalPolicy"], "never")
        self.assertEqual(params["sandbox"], "danger-full-access")
        self.assertFalse(params["ephemeral"])
        named = next(item[1] for item in calls if item[0] == "thread/name/set")
        self.assertEqual(named, {"threadId": CREATED, "name": "Conductor · Test"})

    def test_thread_creation_timeout_is_uncertain_and_not_retryable(self):
        transport = self.transport(fail_method="thread/start")
        with self.assertRaises(ConversationHostError) as failure:
            transport.create_thread(
                cwd=str(self.project),
                title="Conductor · Test",
                developer_instructions="bounded conductor",
            )
        self.assertEqual(failure.exception.phase, "task creation")
        self.assertTrue(failure.exception.delivery_attempted)
        self.assertFalse(failure.exception.retry_safe)

    def test_resume_timeout_is_provably_pre_send(self):
        transport = self.transport(fail_method="thread/resume")
        with self.assertRaises(ConversationHostError) as failure:
            transport.send(
                self.target(),
                "plain direct text",
                "99999999-9999-4999-8999-999999999999",
            )
        self.assertEqual(failure.exception.phase, "owner preflight")
        self.assertFalse(failure.exception.delivery_attempted)
        self.assertTrue(failure.exception.retry_safe)

    def test_stale_owner_discovery_falls_back_once_before_send(self):
        transport = self.transport(discovery_error="desktop_ipc_timeout")
        request_id = "99999999-9999-4999-8999-999999999999"
        result = transport.send(self.target(), "plain direct text", request_id)
        self.assertEqual(result["turnId"], TURN_A)
        self.assertEqual(len(self.clients), 1)
        turn_params = next(item[1] for item in self.clients[0].calls if item[0] == "turn/start")
        self.assertEqual(turn_params["clientUserMessageId"], request_id)
        self.assertEqual(turn_params["input"][0]["text"], "plain direct text")
        self.assertNotIn("Forwarded verbatim", turn_params["input"][0]["text"])

    def test_fallback_app_server_is_retained_and_rapid_followup_steers_same_turn(self):
        transport = self.transport(monitor_seconds=2.0)
        first_id = "99999999-9999-4999-8999-999999999999"
        second_id = "88888888-8888-4888-8888-888888888888"
        first = transport.send(self.target(), "first", first_id)
        self.assertEqual(first["turnId"], TURN_A)
        self.assertFalse(self.clients[0].closed)

        second = transport.send(self.target(), "second", second_id)
        self.assertEqual(len(self.clients), 1)
        steer = next(item for item in self.clients[0].calls if item[0] == "turn/steer")
        self.assertEqual(steer[1]["expectedTurnId"], TURN_A)
        self.assertEqual(steer[1]["clientUserMessageId"], second_id)
        self.assertEqual(steer[1]["input"][0]["text"], "second")
        self.assertEqual(second["deliveryMode"], "steer")

        transcript = transport.read(self.target())
        self.assertEqual(len(self.clients), 1)
        self.assertEqual(transcript["items"][0]["text"], "answer")

        self.clients[0].notifications.append({
            "method": "turn/completed",
            "params": {"turn": {"id": TURN_A, "status": "completed"}},
        })
        deadline = time.time() + 1.0
        while not self.clients[0].closed and time.time() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.clients[0].closed)

    def test_missing_post_send_turn_receipt_is_uncertain_and_not_retryable(self):
        transport = self.transport(missing_turn=True)
        with self.assertRaises(ConversationHostError) as uncertain:
            transport.send(
                self.target(),
                "already submitted",
                "99999999-9999-4999-8999-999999999999",
            )
        self.assertTrue(uncertain.exception.delivery_attempted)
        self.assertFalse(uncertain.exception.retry_safe)
        self.assertTrue(uncertain.exception.reconciliation_required)

    def test_read_uses_bounded_full_turn_page_and_normalizes_messages(self):
        transport = self.transport()
        result = transport.read(self.target())
        call = next(item for item in self.clients[0].calls if item[0] == "thread/turns/list")
        self.assertEqual(call[1]["limit"], 60)
        self.assertEqual(call[1]["itemsView"], "full")
        self.assertEqual([item["role"] for item in result["items"]], ["assistant", "user"])
        self.assertEqual(result["nextCursor"], "older")


if __name__ == "__main__":
    unittest.main()
