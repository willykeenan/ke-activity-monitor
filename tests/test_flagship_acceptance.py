import copy
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from flagship_acceptance import (  # noqa: E402
    acceptance_summary,
    verify_flagship_repair_result,
    verify_flagship_snapshot,
)
from flagship_capabilities import CAPABILITY_BY_ID, FlagshipCapabilityService  # noqa: E402
from flagship_sources import feature_signals  # noqa: E402


class FlagshipAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = FlagshipCapabilityService(
            now=lambda: "2026-08-21T02:00:00Z"
        ).snapshot(feature_signals({}))

    def test_contract_only_snapshot_passes_all_thirty_plus_powerswarm(self):
        self.assertEqual(verify_flagship_snapshot(self.snapshot), [])
        self.assertTrue(acceptance_summary(self.snapshot)["ok"])

    def test_changed_navigation_fails(self):
        payload = copy.deepcopy(self.snapshot)
        payload["topLevelOrder"] = ["agents", "cpu"]
        self.assertIn("top-level order changed", verify_flagship_snapshot(payload))

    def test_missing_capability_fails(self):
        payload = copy.deepcopy(self.snapshot)
        payload["capabilities"] = [row for row in payload["capabilities"] if row["id"] != "C19"]
        errors = verify_flagship_snapshot(payload)
        self.assertTrue(any("missing capabilities: C19" in error for error in errors))

    def test_working_with_missing_source_fails(self):
        payload = copy.deepcopy(self.snapshot)
        row = next(item for item in payload["capabilities"] if item["id"] == "C19")
        row["state"] = "working"
        errors = verify_flagship_snapshot(payload)
        self.assertIn("C19 appears working with missing owner sources", errors)

    def test_power_swarm_implicit_launch_fails(self):
        payload = copy.deepcopy(self.snapshot)
        row = next(item for item in payload["capabilities"] if item["id"] == "C33")
        row["actions"].append("launch")
        self.assertIn("PowerSwarm visibility contains implicit run controls", verify_flagship_snapshot(payload))

    def test_privacy_regression_fails(self):
        payload = copy.deepcopy(self.snapshot)
        payload["privacy"]["absolutePathsReturned"] = True
        self.assertIn(
            "privacy field absolutePathsReturned must be false",
            verify_flagship_snapshot(payload),
        )

    def test_generation_bound_no_io_recovery_contract_is_accepted(self):
        payload = copy.deepcopy(self.snapshot)
        row = next(item for item in payload["capabilities"] if item["id"] == "C26")
        row["state"] = "repairable"
        row["recovery"] = {
            "mode": "safe-local-binding",
            "canAttempt": True,
            "noSideEffects": True,
        }
        payload["counts"]["not-connected"] -= 1
        payload["counts"]["repairable"] = 1
        payload["counts"]["setup-required"] = 0
        payload["recovery"] = {
            "generationBound": True,
            "singleFlight": True,
            "noIORepair": True,
        }
        self.assertEqual(verify_flagship_snapshot(payload), [])

    def test_unbounded_or_side_effecting_recovery_fails(self):
        payload = copy.deepcopy(self.snapshot)
        row = next(item for item in payload["capabilities"] if item["id"] == "C26")
        row["recovery"] = {
            "mode": "provider-repair",
            "canAttempt": True,
            "noSideEffects": False,
        }
        payload["recovery"] = {
            "generationBound": False,
            "singleFlight": False,
            "noIORepair": False,
        }
        errors = verify_flagship_snapshot(payload)
        self.assertIn("C26 recovery has side effects", errors)
        self.assertIn("C26 exposes an unbounded recovery action", errors)
        self.assertIn("recovery must be generation-bound", errors)
        self.assertIn("recovery must be single-flight", errors)
        self.assertIn("recovery must remain no-I/O", errors)

    def test_bounded_repair_result_ledger_is_accepted(self):
        payload = {
            "ok": True,
            "code": "repaired",
            "repaired": 1,
            "outcomeSchemaVersion": (
                "ke.activity-monitor-flagship-repair-outcomes.v1"
            ),
            "outcomesBounded": True,
            "outcomeCounts": {
                "applied": 1,
                "already-healthy": 0,
                "manual": 0,
                "unavailable": 0,
                "failed": 0,
            },
            "outcomes": [
                {
                    "capabilityId": "C25",
                    "name": CAPABILITY_BY_ID["C25"].name,
                    "outcome": "applied",
                    "stateBefore": "repairable",
                    "stateAfter": "degraded",
                    "repairMode": "safe-local-binding",
                    "detail": "Safe local metadata binding rebuilt.",
                    "noSideEffects": True,
                }
            ],
        }
        self.assertEqual(verify_flagship_repair_result(payload), [])

    def test_repair_result_ledger_fails_on_count_or_side_effect_drift(self):
        payload = {
            "ok": True,
            "repaired": 1,
            "outcomeSchemaVersion": (
                "ke.activity-monitor-flagship-repair-outcomes.v1"
            ),
            "outcomesBounded": True,
            "outcomeCounts": {"applied": 0},
            "outcomes": [
                {
                    "capabilityId": "C25",
                    "name": CAPABILITY_BY_ID["C25"].name,
                    "outcome": "applied",
                    "stateBefore": "repairable",
                    "stateAfter": "degraded",
                    "detail": "Safe local metadata binding rebuilt.",
                    "noSideEffects": False,
                }
            ],
        }
        errors = verify_flagship_repair_result(payload)
        self.assertIn("C25 repair result has side effects", errors)
        self.assertIn("repair outcome counts do not match the ledger", errors)

    def test_cli_emits_one_exact_success_line(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_flagship_snapshot.py")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=8,
        )
        self.assertEqual(result.stdout.strip(), "FLAGSHIP_CAPABILITIES_OK 30+1 CURRENT_ORDER_PRESERVED")
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
