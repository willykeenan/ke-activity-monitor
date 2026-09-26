import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from flagship_capabilities import FlagshipCapabilityService  # noqa: E402
import flagship_local_sources as local_sources  # noqa: E402
from flagship_local_sources import CompanyDiscovery, OperationsBoardDiscovery  # noqa: E402
from flagship_sources import board_signals, company_signals, feature_signals, signal_from_payload  # noqa: E402


class CompanyDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.ethos = self.root / ".grokcode" / "ethos"
        self.ethos.mkdir(parents=True)

    def tearDown(self):
        self.temporary.cleanup()

    def write_json(self, name, payload):
        (self.ethos / name).write_text(json.dumps(payload), encoding="utf-8")

    def test_missing_roster_is_truthful_and_does_not_seed_files(self):
        result = CompanyDiscovery(home=self.root).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "not-configured")
        self.assertEqual(list(self.ethos.iterdir()), [])

    def test_roster_returns_identity_and_team_metadata_without_private_fields(self):
        self.write_json(
            "roster.json",
            {
                "agents": [
                    {
                        "id": "merz",
                        "name": "Merz",
                        "role": "Business Ops",
                        "team": "Operations",
                        "lead": True,
                        "enabled": True,
                        "hired": "2026-08-01T00:00:00Z",
                        "model": "gpt-test",
                        "email": "private@example.com",
                        "persona": "secret persona",
                        "charter": "private charter",
                        "brainDir": "/Users/private/brain",
                        "allowFrom": ["private@example.com"],
                    }
                ]
            },
        )
        self.write_json(
            "jobs.json",
            {
                "jobs": [
                    {
                        "agentId": "merz",
                        "status": "working",
                        "subject": "private customer subject",
                        "from": "private@example.com",
                    }
                ]
            },
        )
        result = CompanyDiscovery(home=self.root, now=lambda: "2026-08-21T02:00:00Z").snapshot()
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"]["agents"], 1)
        self.assertEqual(result["summary"]["jobs"], 1)
        self.assertFalse(result["teams"][0]["crewContract"])
        self.assertEqual(result["agents"][0]["jobs"]["working"], 1)
        encoded = json.dumps(result)
        self.assertNotIn("private@example.com", encoded)
        self.assertNotIn("secret persona", encoded)
        self.assertNotIn("private charter", encoded)
        self.assertNotIn("/Users/private/brain", encoded)

    def test_symlinked_roster_fails_closed(self):
        outside = self.root / "outside.json"
        outside.write_text('{"agents":[]}', encoding="utf-8")
        (self.ethos / "roster.json").symlink_to(outside)
        result = CompanyDiscovery(home=self.root).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")

    def test_default_roster_parent_cannot_escape_the_private_home(self):
        with tempfile.TemporaryDirectory() as outside:
            outside_root = Path(outside)
            (outside_root / "roster.json").write_text('{"agents": []}', encoding="utf-8")
            for child in list(self.ethos.iterdir()):
                child.unlink()
            self.ethos.rmdir()
            self.ethos.symlink_to(outside_root, target_is_directory=True)
            result = CompanyDiscovery(home=self.root).snapshot()
            self.assertFalse(result["ok"])
            self.assertEqual(result["state"], "unavailable")

    def test_performed_roster_parent_swap_fails_closed(self):
        self.write_json(
            "roster.json",
            {"agents": [{"id": "trusted-agent", "name": "Trusted", "role": "Dev"}]},
        )
        replacement = self.ethos.parent / "replacement-ethos"
        replacement.mkdir()
        (replacement / "roster.json").write_text(
            json.dumps(
                {"agents": [{"id": "attacker-agent", "name": "Attacker", "role": "Spy"}]}
            ),
            encoding="utf-8",
        )
        displaced = self.ethos.parent / "displaced-ethos"

        def perform_swap():
            self.ethos.rename(displaced)
            replacement.rename(self.ethos)

        result = CompanyDiscovery(
            home=self.root,
            _before_roster_open=perform_swap,
        ).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")
        self.assertNotIn("attacker-agent", json.dumps(result))

    def test_performed_roster_parent_swap_and_restore_fails_closed(self):
        self.write_json("roster.json", {"agents": [{"id": "trusted-agent"}]})
        replacement = self.ethos.parent / "replacement-ethos"
        replacement.mkdir()
        (replacement / "roster.json").write_text(
            '{"agents":[{"id":"attacker-agent"}]}',
            encoding="utf-8",
        )
        displaced = self.ethos.parent / "displaced-ethos"

        def perform_swap_and_restore():
            self.ethos.rename(displaced)
            replacement.rename(self.ethos)
            self.ethos.rename(replacement)
            displaced.rename(self.ethos)

        result = CompanyDiscovery(
            home=self.root,
            _before_roster_open=perform_swap_and_restore,
        ).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")
        self.assertNotIn("attacker-agent", json.dumps(result))

    def test_colliding_team_slugs_remain_unique(self):
        self.write_json(
            "roster.json",
            {
                "agents": [
                    {"id": "one", "name": "One", "role": "Role", "team": "A B", "enabled": True},
                    {"id": "two", "name": "Two", "role": "Role", "team": "A-B", "enabled": True},
                ]
            },
        )
        result = CompanyDiscovery(home=self.root).snapshot()
        team_ids = [team["id"] for team in result["teams"]]
        self.assertEqual(len(team_ids), len(set(team_ids)))

    def test_roster_writable_by_another_principal_fails_closed(self):
        self.write_json("roster.json", {"agents": []})
        (self.ethos / "roster.json").chmod(0o666)
        result = CompanyDiscovery(home=self.root).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")

    def test_roster_parent_writable_by_another_principal_fails_closed(self):
        self.write_json("roster.json", {"agents": []})
        self.ethos.chmod(0o777)
        result = CompanyDiscovery(home=self.root).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")

    def test_unsupported_descriptor_platform_fails_closed(self):
        self.write_json("roster.json", {"agents": []})
        with patch.object(local_sources.sys, "platform", "unsupported"):
            result = CompanyDiscovery(home=self.root).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")

    def test_duplicate_or_invalid_agent_identity_is_not_projected(self):
        self.write_json(
            "roster.json",
            {
                "agents": [
                    {"id": "agent-1", "name": "One", "role": "Dev", "enabled": True},
                    {"id": "agent-1", "name": "Duplicate", "role": "Dev", "enabled": True},
                    {"id": "../../escape", "name": "Invalid", "role": "Dev", "enabled": True},
                ]
            },
        )
        result = CompanyDiscovery(home=self.root).snapshot()
        self.assertEqual([item["id"] for item in result["agents"]], ["agent-1"])


class OperationsBoardDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "board.sqlite3"

    def tearDown(self):
        self.temporary.cleanup()

    def seed(self, database=None, *, agent_id="codex:task-1"):
        target = database or self.database
        with sqlite3.connect(target) as connection:
            connection.executescript(
                """
                CREATE TABLE agents(
                  agent_id TEXT, team TEXT, provider TEXT, endpoint TEXT,
                  display_name TEXT, capabilities_json TEXT,
                  writable_scopes_json TEXT, priority INTEGER, status TEXT,
                  last_seen_at TEXT
                );
                CREATE TABLE incidents(
                  incident_id TEXT, team TEXT, title TEXT, details TEXT,
                  severity TEXT, status TEXT, source TEXT, safe_action TEXT,
                  required_capability TEXT, william_needed INTEGER,
                  assigned_agent_id TEXT, acknowledged_at TEXT,
                  resolved_at TEXT, updated_at TEXT
                );
                """
            )
            connection.execute(
                "INSERT INTO agents VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    agent_id, "GENERAL", "codex", "task-1", "Flagship owner",
                    '["implementation","testing"]', '["/Users/private/repo"]', 10,
                    "ACTIVE", "2026-08-21T02:00:00Z",
                ),
            )
            connection.execute(
                "INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "inc-1", "GENERAL", "Needs one choice", "/Users/private/details",
                    "high", "BLOCKED_HUMAN", "private source", "delete everything",
                    "implementation", 1, agent_id, None, None,
                    "2026-08-21T02:00:00Z",
                ),
            )

    def test_missing_board_is_not_configured_and_not_created(self):
        result = OperationsBoardDiscovery(database_path=self.database).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "not-configured")
        self.assertFalse(self.database.exists())

    def test_read_only_projection_keeps_owner_and_incident_identity_without_bodies(self):
        self.seed()
        before = self.database.read_bytes()
        result = OperationsBoardDiscovery(
            database_path=self.database,
            now=lambda: "2026-08-21T02:00:00Z",
        ).snapshot()
        after = self.database.read_bytes()
        self.assertEqual(before, after)
        self.assertTrue(result["ok"])
        self.assertEqual(result["counts"]["activeOwners"], 1)
        self.assertEqual(result["counts"]["needsHuman"], 1)
        self.assertEqual(result["incidents"][0]["assignedAgentId"], "codex:task-1")
        encoded = json.dumps(result)
        self.assertNotIn("/Users/private/details", encoded)
        self.assertNotIn("delete everything", encoded)
        self.assertNotIn("writable_scopes", encoded)
        self.assertNotIn(str(self.database), encoded)

    def test_sqlite_is_opened_only_through_the_validated_descriptor_alias(self):
        self.seed()
        real_connect = sqlite3.connect
        opened = []

        def capture(database, *args, **kwargs):
            opened.append(str(database))
            return real_connect(database, *args, **kwargs)

        with patch.object(local_sources.sqlite3, "connect", side_effect=capture):
            result = OperationsBoardDiscovery(database_path=self.database).snapshot()

        self.assertTrue(result["ok"])
        self.assertEqual(len(opened), 1)
        self.assertTrue(opened[0].startswith("file:/dev/fd/"))
        self.assertIn("mode=ro", opened[0])
        self.assertIn("immutable=1", opened[0])
        self.assertNotIn(str(self.database), opened[0])

    def test_connect_boundary_database_swap_and_restore_fails_closed(self):
        self.seed(agent_id="codex:trusted-owner")
        attacker = self.root / "attacker.sqlite3"
        self.seed(attacker, agent_id="codex:attacker-owner")
        displaced = self.root / "displaced.sqlite3"
        real_connect = sqlite3.connect
        swaps = []

        def connect_during_swap(database, *args, **kwargs):
            self.database.rename(displaced)
            attacker.rename(self.database)
            swaps.append(str(database))
            try:
                return real_connect(database, *args, **kwargs)
            finally:
                self.database.rename(attacker)
                displaced.rename(self.database)

        with patch.object(local_sources.sqlite3, "connect", side_effect=connect_during_swap):
            result = OperationsBoardDiscovery(database_path=self.database).snapshot()

        self.assertEqual(len(swaps), 1)
        self.assertTrue(swaps[0].startswith("file:/dev/fd/"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")
        self.assertNotIn("codex:attacker-owner", json.dumps(result))

    def test_symlinked_board_fails_closed(self):
        self.seed()
        link = self.root / "board-link.sqlite3"
        link.symlink_to(self.database)
        result = OperationsBoardDiscovery(database_path=link).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")

    def test_performed_board_parent_swap_fails_closed(self):
        board_root = self.root / "board-root"
        board_root.mkdir()
        database = board_root / "board.sqlite3"
        self.seed(database, agent_id="codex:trusted-owner")

        replacement = self.root / "replacement-board-root"
        replacement.mkdir()
        self.seed(replacement / "board.sqlite3", agent_id="codex:attacker-owner")
        displaced = self.root / "displaced-board-root"

        def perform_swap():
            board_root.rename(displaced)
            replacement.rename(board_root)

        result = OperationsBoardDiscovery(
            database_path=database,
            _before_database_open=perform_swap,
        ).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")
        self.assertNotIn("codex:attacker-owner", json.dumps(result))

    def test_unsupported_descriptor_platform_fails_closed(self):
        self.seed()
        with patch.object(local_sources.sys, "platform", "unsupported"):
            result = OperationsBoardDiscovery(database_path=self.database).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")

    def test_unsupported_schema_fails_soft(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE unrelated(id INTEGER)")
        result = OperationsBoardDiscovery(database_path=self.database).snapshot()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unavailable")

    def test_malformed_capability_json_fails_soft_without_scope_projection(self):
        self.seed()
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE agents SET capabilities_json='{}', priority=NULL")
        result = OperationsBoardDiscovery(database_path=self.database).snapshot()
        self.assertTrue(result["ok"])
        self.assertEqual(result["agents"][0]["capabilities"], [])
        self.assertEqual(result["agents"][0]["priority"], 100)


class FlagshipSourceTranslationTests(unittest.TestCase):
    def test_catalog_source_is_always_verified_but_other_sources_are_not_invented(self):
        signals = feature_signals({})
        self.assertEqual([signal.source_id for signal in signals], ["capability-registry"])
        self.assertEqual(signals[0].evidence, "verified")

    def test_company_and_board_payloads_drive_exact_capabilities(self):
        company = {
            "ok": True,
            "state": "partial",
            "observedAt": "2026-08-21T02:00:00Z",
            "summary": {"agents": 2, "teams": 1, "crewContracts": 0},
        }
        board = {
            "ok": True,
            "state": "available",
            "observedAt": "2026-08-21T02:00:00Z",
            "counts": {"activeOwners": 1, "open": 2, "needsHuman": 1},
        }
        signals = feature_signals({"company": company, "operations-board": board})
        payload = FlagshipCapabilityService(now=lambda: "2026-08-21T02:00:00Z").snapshot(signals)
        rows = {row["id"]: row for row in payload["capabilities"]}
        self.assertEqual(rows["C17"]["state"], "degraded")
        self.assertEqual(rows["C19"]["state"], "not-connected")
        self.assertEqual(rows["C10"]["state"], "working")
        self.assertEqual(rows["C13"]["state"], "blocked")
        self.assertEqual(rows["C24"]["state"], "working")

    def test_stale_feature_payload_translates_to_stale_snapshot(self):
        signals = feature_signals(
            {
                "powerswarm": {
                    "ok": True,
                    "state": "available",
                    "stale": True,
                    "observedAt": "2026-08-21T01:00:00Z",
                }
            }
        )
        payload = FlagshipCapabilityService().snapshot(signals)
        row = next(item for item in payload["capabilities"] if item["id"] == "C33")
        self.assertEqual(row["state"], "stale")

    def test_feature_payload_requires_mapping(self):
        with self.assertRaisesRegex(TypeError, "mapping"):
            signal_from_payload("brain", [], owner="KE Brain")

    def test_malformed_or_hostile_counts_fail_soft(self):
        company = company_signals(
            {
                "ok": True,
                "state": "partial",
                "observedAt": "2026-08-20T00:00:00Z",
                "summary": {"agents": "not-a-number", "teams": -10, "crewContracts": object()},
            }
        )
        board = board_signals(
            {
                "ok": True,
                "state": "available",
                "observedAt": "2026-08-20T00:00:00Z",
                "counts": {"activeOwners": "x", "open": -1, "needsHuman": object()},
            }
        )
        self.assertIn("0 Agents", company[0].resource)
        self.assertEqual(company[1].state, "not-configured")
        self.assertIn("0 active", board[0].resource)
        self.assertEqual(board[2].state, "available")


if __name__ == "__main__":
    unittest.main()
