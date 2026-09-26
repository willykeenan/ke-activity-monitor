import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from flagship_capabilities import (  # noqa: E402
    CAPABILITIES,
    CAPABILITY_BY_ID,
    CURRENT_TOP_LEVEL_ORDER,
    FlagshipCapabilityService,
    NATIVE_CAPABILITY_IDS,
    SUPPLEMENTAL_CAPABILITY_IDS,
    SourceSignal,
    catalog,
    search_capabilities,
)


EXPECTED_NATIVE_IDS = {
    "C01", "C02", "C03", "C04", "C09", "C10", "C11", "C12", "C13",
    "C17", "C18", "C19", "C24", "C25", "C26", "C27", "C28", "C30",
    "C31", "C32", "C36", "C39", "C40", "C41", "C42", "C43", "C44",
    "C48", "C63", "C64",
}


class FlagshipCapabilityCatalogTests(unittest.TestCase):
    def test_exact_thirty_native_capabilities_are_present(self):
        native = {item.capability_id for item in CAPABILITIES if item.kind == "native"}
        self.assertEqual(native, EXPECTED_NATIVE_IDS)
        self.assertEqual(native, NATIVE_CAPABILITY_IDS)
        self.assertEqual(len(native), 30)

    def test_powerswarm_is_one_additional_governed_native_surface(self):
        self.assertEqual(SUPPLEMENTAL_CAPABILITY_IDS, {"C33"})
        descriptor = CAPABILITY_BY_ID["C33"]
        self.assertEqual(descriptor.kind, "native-governed-surface")
        self.assertEqual(descriptor.interaction, "observe")
        self.assertIn("separate-powerswarm-command", descriptor.authority_gates)
        self.assertNotIn("launch", descriptor.actions)
        self.assertNotIn("cancel", descriptor.actions)

    def test_existing_top_level_order_is_exact_and_has_no_replacement_tabs(self):
        self.assertEqual(
            CURRENT_TOP_LEVEL_ORDER,
            ("cpu", "memory", "energy", "disk", "network", "agents", "brain", "dispatch", "guard"),
        )
        payload = catalog()
        self.assertTrue(payload["preservesCurrentOrder"])
        self.assertEqual(payload["topLevelOrder"], list(CURRENT_TOP_LEVEL_ORDER))
        self.assertNotIn("today", payload["topLevelOrder"])
        self.assertNotIn("company", payload["topLevelOrder"])
        self.assertNotIn("evidence", payload["topLevelOrder"])

    def test_every_capability_is_placed_inside_the_current_order(self):
        valid = set(CURRENT_TOP_LEVEL_ORDER)
        self.assertTrue(CAPABILITIES)
        self.assertTrue(all(item.tab in valid for item in CAPABILITIES))
        self.assertEqual(len({item.capability_id for item in CAPABILITIES}), 31)
        self.assertEqual(len({item.slug for item in CAPABILITIES}), 31)

    def test_every_capability_publishes_owner_sources_actions_and_boundary(self):
        for item in CAPABILITIES:
            with self.subTest(item.capability_id):
                self.assertTrue(item.owner)
                self.assertTrue(item.summary)
                self.assertTrue(item.required_sources)
                self.assertTrue(item.actions)
                self.assertTrue(item.empty_state)

    def test_catalog_is_json_serializable_and_ordered_by_current_tabs(self):
        payload = catalog()
        encoded = json.dumps(payload, sort_keys=True)
        self.assertIn("ke.activity-monitor-flagship.v1", encoded)
        ranks = [row["placement"]["tabRank"] for row in payload["capabilities"]]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(payload["counts"], {"native": 30, "nativeGovernedSurface": 1, "total": 31})

    def test_capability_help_searches_owned_contracts_without_provider_calls(self):
        result = search_capabilities("PowerSwarm")
        self.assertEqual([row["id"] for row in result], ["C33"])
        brain = search_capabilities("brain")
        self.assertIn("C25", {row["id"] for row in brain})
        self.assertLessEqual(len(search_capabilities("", limit=3)), 3)


class FlagshipCapabilitySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.service = FlagshipCapabilityService(now=lambda: "2026-08-21T02:00:00.000Z")

    def row(self, payload, capability_id):
        return next(row for row in payload["capabilities"] if row["id"] == capability_id)

    def test_missing_owner_source_is_not_connected_not_fake_empty(self):
        payload = self.service.snapshot([])
        self.assertEqual(payload["counts"]["not-connected"], 31)
        self.assertEqual(self.row(payload, "C26")["state"], "not-connected")
        self.assertIn("no bounded conversation provider", self.row(payload, "C26")["detail"].lower())

    def test_required_verified_fresh_source_proves_working_surface(self):
        payload = self.service.snapshot(
            [
                SourceSignal(
                    "powerswarm",
                    "available",
                    evidence="verified",
                    freshness="fresh",
                    observed_at="2026-08-21T01:59:59Z",
                    detail="Durable run ledger and process probe agree.",
                    resource="3 live workers; signed cap 8",
                    receipt_ref="sha256:abc123",
                )
            ]
        )
        row = self.row(payload, "C33")
        self.assertEqual(row["state"], "working")
        self.assertEqual(row["evidence"]["level"], "verified")
        self.assertEqual(row["freshness"]["state"], "fresh")
        self.assertEqual(row["resource"]["state"], "published")
        self.assertFalse(row["authority"]["inheritedFromVisibility"])

    def test_stale_source_never_appears_working(self):
        payload = self.service.snapshot(
            [SourceSignal("cpu-workers", "available", evidence="observed", freshness="stale")]
        )
        row = self.row(payload, "C39")
        self.assertEqual(row["state"], "stale")
        self.assertEqual(row["evidence"]["level"], "observed")

    def test_degraded_and_blocked_sources_remain_distinct(self):
        degraded = self.service.snapshot(
            [SourceSignal("brain", "degraded", evidence="observed", freshness="fresh", detail="Index unavailable")]
        )
        self.assertEqual(self.row(degraded, "C25")["state"], "degraded")
        blocked = self.service.snapshot(
            [SourceSignal("human-gates", "blocked", evidence="recorded", freshness="fresh", detail="Human decision required")]
        )
        self.assertEqual(self.row(blocked, "C13")["state"], "blocked")

    def test_multi_source_capability_requires_every_declared_owner_source(self):
        only_dispatch = self.service.snapshot(
            [SourceSignal("dispatch", "available", evidence="verified", freshness="fresh")]
        )
        row = self.row(only_dispatch, "C02")
        self.assertEqual(row["state"], "not-connected")
        self.assertEqual(row["evidence"]["missingSources"], ["ownership"])
        complete = self.service.snapshot(
            [
                SourceSignal("dispatch", "available", evidence="verified", freshness="fresh"),
                SourceSignal("ownership", "available", evidence="observed", freshness="fresh"),
            ]
        )
        row = self.row(complete, "C02")
        self.assertEqual(row["state"], "working")
        self.assertEqual(row["evidence"]["level"], "observed")

    def test_private_source_text_is_redacted_before_ui_projection(self):
        payload = self.service.snapshot(
            [
                SourceSignal(
                    "evidence",
                    "available",
                    evidence="verified",
                    freshness="fresh",
                    detail="Read /Users/alex/private/receipt.json for person@example.com using sk-live-abcdefghijklmnop",
                    owner="person@example.com",
                    receipt_ref="/Users/alex/private/receipt.json",
                )
            ]
        )
        encoded = json.dumps(payload)
        self.assertNotIn("alex", encoded)
        self.assertNotIn("person@example.com", encoded)
        self.assertNotIn("sk-live-abcdefghijklmnop", encoded)
        self.assertIn("[local path]", encoded)
        self.assertIn("[private contact]", encoded)
        self.assertIn("[credential]", encoded)

        volume = self.service.snapshot(
            [SourceSignal("evidence", "available", detail="Read /Volumes/PrivateDrive/evidence.json")]
        )
        self.assertNotIn("/Volumes/PrivateDrive", json.dumps(volume))

    def test_duplicate_source_signals_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "duplicate source signal"):
            self.service.snapshot(
                [
                    SourceSignal("brain", "available"),
                    SourceSignal("brain", "degraded"),
                ]
            )

    def test_invalid_truth_vocabularies_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "source identifier"):
            SourceSignal("../../brain", "available")
        with self.assertRaisesRegex(ValueError, "unsupported source state"):
            SourceSignal("brain", "fine")
        with self.assertRaisesRegex(ValueError, "unsupported evidence level"):
            SourceSignal("brain", "available", evidence="probably")
        with self.assertRaisesRegex(ValueError, "unsupported freshness state"):
            SourceSignal("brain", "available", freshness="recent-ish")

    def test_snapshot_json_is_stable_for_one_input(self):
        signal = SourceSignal("capability-registry", "available", evidence="verified", freshness="fresh")
        first = self.service.snapshot_json([signal])
        second = self.service.snapshot_json([signal])
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)["generatedAt"], "2026-08-21T02:00:00.000Z")


if __name__ == "__main__":
    unittest.main()
