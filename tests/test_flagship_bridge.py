import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import activity_monitor  # noqa: E402
from flagship_bridge import FlagshipBridge, baseline_snapshot  # noqa: E402
from flagship_capabilities import CURRENT_TOP_LEVEL_ORDER  # noqa: E402


class _Service:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def scan(self, force=False):
        self.calls += 1
        return dict(self.payload)

    def state(self):
        self.calls += 1
        return dict(self.payload)

    def status(self):
        self.calls += 1
        return dict(self.payload)

    def snapshot(self):
        self.calls += 1
        return dict(self.payload)


def _row(snapshot, capability_id):
    return next(item for item in snapshot["capabilities"] if item["id"] == capability_id)


class FlagshipBridgeTests(unittest.TestCase):
    def _bridge(self, *, providers=None, agents_provider=None):
        brain = _Service({
            "ok": True,
            "state": "available",
            "generatedAt": "2026-08-20T22:00:00Z",
            "summary": {"connected": 1},
        })
        dispatch = _Service({"ok": True, "state": "available"})
        guard = _Service({
            "ok": True,
            "state": "armed",
            "observedAt": "2026-08-20T22:00:00Z",
        })
        company = _Service({
            "ok": True,
            "state": "partial",
            "observedAt": "2026-08-20T22:00:00Z",
            "summary": {"agents": 4, "teams": 2, "crewContracts": 0},
        })
        board = _Service({
            "ok": True,
            "state": "available",
            "observedAt": "2026-08-20T22:00:00Z",
            "counts": {"activeOwners": 2, "open": 1, "needsHuman": 0},
        })
        return (
            FlagshipBridge(
                brain_service=brain,
                dispatch_service=dispatch,
                guard_service=guard,
                company_discovery=company,
                board_discovery=board,
                agents_provider=agents_provider,
                providers=providers,
            ),
            brain,
        )

    def _recovery_bridge(self, *, auto_heal=True):
        brain = _Service({
            "ok": True,
            "state": "available",
            "generatedAt": "2026-08-24T14:00:00Z",
            "summary": {"connected": 22, "projectChildren": 14},
            "scan": {"settingsTrusted": True},
            "privacy": {
                "noteBodiesRead": False,
                "uploads": False,
                "credentialsUsed": False,
            },
        })
        dispatch = _Service({
            "ok": True,
            "state": "available",
            "readiness": {
                "codexExactTask": True,
                "codexDesktopOwnerIpc": True,
                "claudeExactSession": True,
                "historyAvailable": True,
                "dispatchSendAllowed": True,
            },
        })
        guard = _Service({
            "ok": True,
            "state": "armed",
            "observedAt": "2026-08-24T14:00:00Z",
            "ledgerAvailable": True,
            "recentEvidence": [{"event": "bounded"}],
        })
        company = _Service({
            "ok": True,
            "state": "partial",
            "observedAt": "2026-08-24T14:00:00Z",
            "summary": {"agents": 4, "teams": 2, "crewContracts": 0},
        })
        board = _Service({
            "ok": True,
            "state": "available",
            "observedAt": "2026-08-24T14:00:00Z",
            "counts": {"activeOwners": 20, "open": 11, "needsHuman": 5},
        })
        workspace = _Service({
            "ok": True,
            "state": "available",
            "observedAt": "2026-08-24T14:00:00Z",
            "counts": {"projectBrains": 14, "activeProjectBrains": 14},
            "companions": {
                "codex": {"cliInstalled": True, "appInstalled": True},
                "claude": {"installed": True},
            },
        })
        bridge = FlagshipBridge(
            brain_service=brain,
            dispatch_service=dispatch,
            guard_service=guard,
            company_discovery=company,
            board_discovery=board,
            agents_provider=lambda: {
                "ok": True,
                "state": "available",
                "observedAt": "2026-08-24T14:00:00Z",
                "cpu": {"ok": True, "state": "available"},
                "gpu": {"ok": True, "state": "available"},
            },
            providers={
                "workspace": workspace.snapshot,
                "powerswarm": lambda: {
                    "ok": True,
                    "state": "available",
                    "observedAt": "2026-08-24T14:00:00Z",
                    "selectedRun": {"providerId": "xai", "modelId": "grok-4.6"},
                },
            },
            auto_heal=auto_heal,
        )
        return bridge, (brain, dispatch, guard, company, board, workspace)

    def test_baseline_is_exact_read_only_30_plus_1(self):
        snapshot = baseline_snapshot()
        self.assertEqual(tuple(snapshot["topLevelOrder"]), CURRENT_TOP_LEVEL_ORDER)
        self.assertEqual(snapshot["counts"]["native"], 30)
        self.assertEqual(snapshot["counts"]["nativeGovernedSurface"], 1)
        self.assertEqual(snapshot["counts"]["total"], 31)
        self.assertTrue(snapshot["readOnly"])
        self.assertTrue(all(row["state"] == "not-connected" for row in snapshot["capabilities"] if row["id"] != "C24" and row["id"] != "C28"))

    def test_tab_collection_is_bounded_and_brain_is_explicit(self):
        calls = {"powerswarm": 0}

        def powerswarm():
            calls["powerswarm"] += 1
            return {"ok": True, "state": "available", "observedAt": "2026-08-20T22:00:00Z"}

        bridge, brain = self._bridge(providers={"powerswarm": powerswarm})
        cpu = bridge.snapshot("cpu")
        self.assertEqual(brain.calls, 0)
        self.assertEqual(calls["powerswarm"], 0)
        self.assertEqual(_row(cpu, "C33")["state"], "not-connected")
        brain_snapshot = bridge.snapshot("brain")
        self.assertEqual(brain.calls, 1)
        self.assertEqual(_row(brain_snapshot, "C25")["state"], "working")
        agents = bridge.snapshot("agents")
        self.assertEqual(calls["powerswarm"], 1)
        self.assertEqual(_row(agents, "C33")["state"], "working")

    def test_agents_projection_keeps_cpu_gpu_truth_separate(self):
        def agents():
            return json.dumps({
                "ok": True,
                "stale": False,
                "observedAt": "2026-08-20T22:00:00Z",
                "cpu": {"ok": True},
                "gpu": {"ok": False, "error": "plugin offline"},
            })

        bridge, _ = self._bridge(agents_provider=agents)
        snapshot = bridge.snapshot("agents")
        self.assertEqual(_row(snapshot, "C39")["state"], "working")
        self.assertEqual(_row(snapshot, "C40")["state"], "unavailable")

    def test_provider_failure_is_unavailable_without_raw_exception(self):
        def powerswarm():
            raise RuntimeError("secret /Users/example/private/run.json")

        bridge, _ = self._bridge(providers={"powerswarm": powerswarm})
        snapshot = bridge.snapshot("agents")
        row = _row(snapshot, "C33")
        self.assertEqual(row["state"], "unavailable")
        serialized = json.dumps(row)
        self.assertNotIn("/Users/", serialized)
        self.assertNotIn("secret", serialized)

    def test_raw_provider_fields_never_survive_into_an_unrelated_tab_snapshot(self):
        forbidden = {
            "provider-body-7df7b4",
            "provider-prompt-9e33c1",
            "provider-message-82d7a0",
            "provider-transcript-57f2c8",
            "sk-live-credential-4f795c75c60e",
            "/Users/provider/private/store.json",
            "unknown-nested-value-e739a5",
            "private-resource-label-9cc7a1",
        }

        def powerswarm():
            return {
                "ok": True,
                "state": "available",
                "observedAt": "2026-08-20T22:00:00Z",
                "detail": "provider-body-7df7b4",
                "body": "provider-body-7df7b4",
                "credential": {"token": "sk-live-credential-4f795c75c60e"},
                "prompt": "provider-prompt-9e33c1",
                "messages": ["provider-message-82d7a0"],
                "transcript": "provider-transcript-57f2c8",
                "path": "/Users/provider/private/store.json",
                "unknown": {"nested": "unknown-nested-value-e739a5"},
                "resource": "private-resource-label-9cc7a1",
            }

        bridge, _ = self._bridge(providers={"powerswarm": powerswarm})
        self.assertEqual(_row(bridge.snapshot("agents"), "C33")["state"], "working")
        unrelated = bridge.snapshot("cpu")

        self.assertFalse(hasattr(bridge, "_payloads"))
        retained = json.dumps(bridge._projections, sort_keys=True)
        serialized = json.dumps(unrelated, sort_keys=True)
        for value in forbidden:
            self.assertNotIn(value, retained)
            self.assertNotIn(value, serialized)
        self.assertEqual(_row(unrelated, "C33")["state"], "working")

    def test_powerswarm_cache_retains_only_the_allowlisted_runtime_identity(self):
        forbidden = {
            "provider-body-model-truth-sentinel",
            "sk-provider-model-truth-sentinel",
            "/Users/provider/private/model-truth.json",
        }

        def powerswarm():
            return {
                "ok": True,
                "state": "available",
                "observedAt": "2026-08-20T22:00:00Z",
                "selectedRun": {
                    "providerId": " XAI ",
                    "modelId": " GROK-4.6 ",
                    "body": "provider-body-model-truth-sentinel",
                    "credential": {"token": "sk-provider-model-truth-sentinel"},
                    "path": "/Users/provider/private/model-truth.json",
                },
            }

        bridge, _ = self._bridge(providers={"powerswarm": powerswarm})
        bridge.snapshot("agents")
        bridge.snapshot("cpu")

        self.assertEqual(
            bridge._projections["powerswarm"]["selectedRun"],
            {"providerId": "xai", "modelId": "grok-4.6"},
        )
        retained = json.dumps(bridge._projections, sort_keys=True)
        for value in forbidden:
            self.assertNotIn(value, retained)

    def test_powerswarm_cache_fails_closed_for_partial_stale_or_unrecognized_identity(self):
        cases = [
            ({"providerId": "xai"}, False),
            ({"modelId": "grok-4.6"}, False),
            ({"providerId": "openai", "modelId": "grok-4.6"}, False),
            ({"providerId": "/private/tmp/xai", "modelId": "grok-4.6"}, False),
            ({"providerId": "xai", "modelId": "token=secret"}, False),
            ({"providerId": "xai", "modelId": "grok-4.6"}, True),
        ]

        for selected_run, stale in cases:
            with self.subTest(selected_run=selected_run, stale=stale):
                def powerswarm(selected_run=selected_run, stale=stale):
                    return {
                        "ok": True,
                        "state": "stale" if stale else "available",
                        "stale": stale,
                        "selectedRun": selected_run,
                    }

                bridge, _ = self._bridge(providers={"powerswarm": powerswarm})
                bridge.snapshot("agents")
                self.assertEqual(
                    bridge._projections["powerswarm"]["selectedRun"],
                    {"providerId": None, "modelId": None},
                )

    def test_invalid_tab_fails_to_cpu_without_reordering(self):
        bridge, _ = self._bridge()
        snapshot = bridge.snapshot("today")
        self.assertEqual(tuple(snapshot["topLevelOrder"]), CURRENT_TOP_LEVEL_ORDER)
        self.assertTrue(snapshot["preservesCurrentOrder"])

    def test_brain_connections_auto_bind_from_bounded_current_owner_evidence(self):
        bridge, _ = self._recovery_bridge()
        snapshot = bridge.snapshot("brain")
        brain_rows = [
            row for row in snapshot["capabilities"]
            if row["placement"]["tab"] == "brain"
        ]
        self.assertEqual({row["id"] for row in brain_rows}, {"C25", "C26", "C27", "C30", "C31"})
        self.assertEqual(_row(snapshot, "C25")["state"], "working")
        for capability_id in ("C26", "C27", "C30", "C31"):
            row = _row(snapshot, capability_id)
            self.assertEqual(row["state"], "degraded")
            self.assertEqual(row["recovery"]["mode"], "auto-bound")
            self.assertFalse(row["recovery"]["canAttempt"])
            self.assertTrue(row["recovery"]["noSideEffects"])
        self.assertEqual(sum(row["state"] == "not-connected" for row in brain_rows), 0)
        self.assertGreaterEqual(snapshot["recovery"]["autoHeal"]["performed"], 4)
        serialized = json.dumps(snapshot)
        self.assertNotIn("/Users/", serialized)
        self.assertNotIn("noteBodies", serialized)

    def test_explicit_owner_source_always_wins_over_derived_compatibility_binding(self):
        bridge, _ = self._recovery_bridge()
        bridge._providers["evidence"] = lambda: {
            "ok": True,
            "state": "available",
            "observedAt": "2026-08-24T14:00:00Z",
            "evidenceLevel": "verified",
        }
        snapshot = bridge.snapshot("brain")
        row = _row(snapshot, "C30")
        self.assertEqual(row["state"], "working")
        self.assertEqual(row["evidence"]["level"], "verified")
        self.assertEqual(row["recovery"]["mode"], "inspect")
        self.assertNotIn("evidence", bridge._derived_active)

    def test_every_current_destination_eliminates_generic_disconnected_when_owners_answer(self):
        bridge, _ = self._recovery_bridge()
        snapshot = None
        for tab in CURRENT_TOP_LEVEL_ORDER:
            snapshot = bridge.snapshot(tab)
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot["counts"]["not-connected"], 0)
        self.assertEqual(snapshot["counts"]["setup-required"], 4)
        self.assertEqual(
            {
                row["id"]
                for row in snapshot["capabilities"]
                if row["state"] == "setup-required"
            },
            {"C12", "C19", "C32", "C64"},
        )

    def test_known_manual_publishers_are_setup_required_not_fake_repairable(self):
        bridge, _ = self._recovery_bridge()
        memory = bridge.snapshot("memory")
        agents = bridge.snapshot("agents")
        network = bridge.snapshot("network")
        for snapshot, capability_ids in (
            (memory, ("C12",)),
            (agents, ("C19",)),
            (network, ("C32", "C64")),
        ):
            for capability_id in capability_ids:
                row = _row(snapshot, capability_id)
                self.assertEqual(row["state"], "setup-required")
                self.assertEqual(row["recovery"]["mode"], "manual-setup")
                self.assertFalse(row["recovery"]["canAttempt"])
                self.assertTrue(row["recovery"]["noSideEffects"])

    def test_one_click_repair_is_no_io_idempotent_and_generation_bound(self):
        bridge, services = self._recovery_bridge(auto_heal=False)
        before = bridge.snapshot("brain")
        before_calls = tuple(service.calls for service in services)
        self.assertEqual(_row(before, "C26")["state"], "repairable")
        result = bridge.repair("brain", None, before["recovery"]["generation"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["code"], "repaired")
        self.assertEqual(result["repaired"], 4)
        self.assertTrue(result["outcomesBounded"])
        self.assertEqual(
            result["outcomeSchemaVersion"],
            "ke.activity-monitor-flagship-repair-outcomes.v1",
        )
        self.assertEqual(len(result["outcomes"]), 5)
        self.assertEqual(result["outcomeCounts"]["applied"], 4)
        self.assertEqual(result["outcomeCounts"]["already-healthy"], 1)
        self.assertTrue(all(item["noSideEffects"] for item in result["outcomes"]))
        self.assertEqual(tuple(service.calls for service in services), before_calls)
        self.assertEqual(_row(result["snapshot"], "C26")["state"], "degraded")

        generation = result["generation"]
        second = bridge.repair("brain", None, generation)
        self.assertTrue(second["ok"])
        self.assertEqual(second["code"], "already-healthy")
        self.assertEqual(second["generation"], generation)
        self.assertEqual(second["outcomeCounts"]["applied"], 0)
        self.assertEqual(second["outcomeCounts"]["already-healthy"], 5)
        self.assertEqual(tuple(service.calls for service in services), before_calls)

        stale = bridge.repair("brain", None, generation - 1)
        self.assertFalse(stale["ok"])
        self.assertEqual(stale["code"], "stale-generation")
        self.assertEqual(tuple(service.calls for service in services), before_calls)

    def test_capability_repair_is_scoped_and_never_fans_out(self):
        bridge, _ = self._recovery_bridge(auto_heal=False)
        before = bridge.snapshot("brain")
        result = bridge.repair(
            "brain",
            "C26",
            before["recovery"]["generation"],
        )
        self.assertEqual(result["repaired"], 1)
        self.assertEqual(len(result["outcomes"]), 1)
        self.assertEqual(result["outcomes"][0]["capabilityId"], "C26")
        self.assertEqual(result["outcomes"][0]["outcome"], "applied")
        self.assertEqual(_row(result["snapshot"], "C26")["state"], "degraded")
        self.assertEqual(_row(result["snapshot"], "C27")["state"], "repairable")
        outside = bridge.repair("brain", "C32", result["generation"])
        self.assertFalse(outside["ok"])
        self.assertEqual(outside["code"], "capability-out-of-scope")

    def test_repair_outcome_categories_are_bounded_and_truthful(self):
        cases = (
            (
                {"state": "repairable", "recovery": {"mode": "safe-local-binding"}},
                {"state": "degraded", "name": "Applied"},
                "applied",
            ),
            (
                {"state": "working", "recovery": {"mode": "auto-bound"}},
                {"state": "working", "name": "Current"},
                "already-healthy",
            ),
            (
                {"state": "setup-required", "recovery": {"mode": "manual-setup"}},
                {"state": "setup-required", "name": "Manual"},
                "manual",
            ),
            (
                {"state": "unavailable", "recovery": {"mode": "inspect"}},
                {"state": "unavailable", "name": "Unavailable"},
                "unavailable",
            ),
            (
                {"state": "repairable", "recovery": {"mode": "safe-local-binding"}},
                {"state": "repairable", "name": "Failed"},
                "failed",
            ),
        )
        for before, after, expected in cases:
            with self.subTest(expected=expected):
                result = FlagshipBridge._repair_outcome("C99", before, after)
                self.assertEqual(result["outcome"], expected)
                self.assertEqual(result["capabilityId"], "C99")
                self.assertTrue(result["noSideEffects"])

    def test_repair_single_flight_fails_closed(self):
        bridge, _ = self._recovery_bridge(auto_heal=False)
        snapshot = bridge.snapshot("brain")
        bridge._repair_lock.acquire()
        try:
            result = bridge.repair("brain", None, snapshot["recovery"]["generation"])
        finally:
            bridge._repair_lock.release()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "repair-busy")
        bridge._lock.acquire()
        try:
            refreshing = bridge.repair(
                "brain", None, snapshot["recovery"]["generation"]
            )
        finally:
            bridge._lock.release()
        self.assertFalse(refreshing["ok"])
        self.assertEqual(refreshing["code"], "repair-busy")

    def test_failure_snapshot_does_not_repaint_a_tab_as_disconnected(self):
        bridge, _ = self._recovery_bridge()
        snapshot = bridge.failure_snapshot("brain")
        brain_rows = [
            row for row in snapshot["capabilities"]
            if row["placement"]["tab"] == "brain"
        ]
        self.assertTrue(all(row["state"] != "not-connected" for row in brain_rows))
        self.assertTrue(snapshot["recovery"]["generationBound"])
        self.assertTrue(snapshot["recovery"]["noIORepair"])


class FlagshipActivityMonitorIntegrationTests(unittest.TestCase):
    def test_html_keeps_exact_top_level_order_and_mounts_eight_tabs(self):
        html = activity_monitor.HTML
        offsets = [html.index(f'data-tab="{tab}"') for tab in CURRENT_TOP_LEVEL_ORDER]
        self.assertEqual(offsets, sorted(offsets))
        for tab in CURRENT_TOP_LEVEL_ORDER:
            expected = 0 if tab == "energy" else 1
            self.assertEqual(html.count(f'data-flagship-tab="{tab}"'), expected)
        self.assertNotIn('data-tab="powerswarm"', html)
        self.assertEqual(html.count('id="powerswarm-tab"'), 1)
        self.assertIn("get_flagship_capabilities", html)
        self.assertIn("window.renderFlagshipCapabilities", html)
        self.assertIn("window.renderFlagshipRecoveryResults", html)
        self.assertIn("window.restoreFlagshipCapabilityFocus", html)
        self.assertIn("detail.restoreFocus === true", html)
        self.assertIn("event.detail?.capabilityId === 'C33'", html)
        self.assertIn("openPowerSwarmSubview()", html)
        self.assertIn('id="powerswarm-back"', html)
        self.assertNotIn("launchPowerSwarm", html)
        self.assertNotIn("cancelPowerSwarm", html)
        self.assertNotIn("resumePowerSwarm", html)
        self.assertNotIn('id="powerswarm-retry"', html)

    def test_combined_script_is_valid_javascript(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "activity-monitor.js"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run(
                ["node", "--check", str(path)],
                text=True,
                capture_output=True,
                timeout=8,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_api_returns_bridge_snapshot_and_forwards_tab(self):
        class FakeBridge:
            def __init__(self):
                self.tab = None

            def snapshot_json(self, tab):
                self.tab = tab
                return json.dumps(baseline_snapshot())

        fake = FakeBridge()
        api = activity_monitor.Api(flagship_bridge=fake)
        payload = json.loads(api.get_flagship_capabilities("agents"))
        self.assertEqual(fake.tab, "agents")
        self.assertEqual(payload["counts"]["native"], 30)
        self.assertEqual(payload["counts"]["nativeGovernedSurface"], 1)

    def test_api_wires_generation_bound_safe_repair(self):
        class FakeBridge:
            def __init__(self):
                self.args = None

            def repair_json(self, tab, capability_id, generation):
                self.args = (tab, capability_id, generation)
                return json.dumps({"ok": True, "code": "already-healthy"})

        fake = FakeBridge()
        api = activity_monitor.Api(flagship_bridge=fake)
        payload = json.loads(api.repair_flagship_capabilities("brain", "C26", "7"))
        self.assertTrue(payload["ok"])
        self.assertEqual(fake.args, ("brain", "C26", 7))

    def test_api_uses_failure_snapshot_instead_of_empty_disconnected_baseline(self):
        class FakeBridge:
            def snapshot_json(self, tab):
                raise RuntimeError("transient")

            def failure_snapshot_json(self, tab):
                return json.dumps({"mode": "owner-unavailable", "tab": tab})

        api = activity_monitor.Api(flagship_bridge=FakeBridge())
        payload = json.loads(api.get_flagship_capabilities("brain"))
        self.assertEqual(payload, {"mode": "owner-unavailable", "tab": "brain"})

    def test_api_binds_existing_workspace_and_powerswarm_as_read_only_owners(self):
        captured = {}

        class CaptureBridge:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            def snapshot_json(self, tab):
                return json.dumps(baseline_snapshot())

        class Workspace:
            def snapshot(self, force=False):
                return {"ok": True, "state": "available", "force": bool(force)}

        class PowerSwarm:
            def snapshot(self, run_id=None, force=False):
                return {
                    "ok": True,
                    "state": "available",
                    "observedAt": "2026-08-21T06:00:00Z",
                    "runId": run_id,
                    "force": bool(force),
                }

        service = _Service({"ok": True, "state": "available"})
        with patch.object(activity_monitor, "FlagshipBridge", CaptureBridge):
            activity_monitor.Api(
                brain_service=service,
                dispatch_service=service,
                guard_service=service,
                workspace_service=Workspace(),
                powerswarm_service=PowerSwarm(),
            )

        providers = captured["providers"]
        self.assertEqual(set(providers), {"workspace", "powerswarm"})
        self.assertEqual(providers["workspace"]()["state"], "available")
        self.assertEqual(providers["powerswarm"]()["state"], "available")
        self.assertFalse(providers["powerswarm"]()["force"])

    def test_html_wires_one_click_and_continuous_safe_recovery_only(self):
        html = activity_monitor.HTML
        self.assertIn("repair_flagship_capabilities", html)
        self.assertIn("ke:capability-repair", html)
        self.assertIn("flagshipAutoHealAt", html)
        self.assertIn("expectedGeneration", html)
        self.assertIn("safeAutoFixable", html)
        flagship_script = activity_monitor.FLAGSHIP_BRIDGE_JS
        for forbidden in (
            "start_network_discovery",
            "perform_network_action",
            "run_disk",
            "update_preferences",
            "send_dispatch",
            "apply_brain_structure",
        ):
            self.assertNotIn(forbidden, flagship_script)

    def test_package_contract_contains_every_flagship_source(self):
        spec = (ROOT / "activity_monitor.spec").read_text(encoding="utf-8")
        package = (ROOT / "package_app.zsh").read_text(encoding="utf-8")
        for name in (
            "flagship_acceptance.py",
            "flagship_bridge.py",
            "flagship_capabilities.py",
            "flagship_local_sources.py",
            "flagship_sources.py",
            "flagship_ui.py",
        ):
            self.assertIn(name, spec)
            self.assertIn(name, package)


if __name__ == "__main__":
    unittest.main()
