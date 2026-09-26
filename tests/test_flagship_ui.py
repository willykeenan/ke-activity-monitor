import pathlib
import re
import subprocess
import tempfile
import unittest

from flagship_capabilities import CURRENT_TOP_LEVEL_ORDER
from flagship_ui import (
    CAPABILITY_TABS,
    CAPABILITY_UI_CSS,
    CAPABILITY_UI_JS,
    capability_mount_html,
    capability_mounts,
    combined_mount_html,
)


class FlagshipUiContractTests(unittest.TestCase):
    def test_mounts_preserve_existing_order(self):
        mounts = capability_mounts()
        self.assertEqual(tuple(mounts), CAPABILITY_TABS)
        expected = tuple(tab for tab in CURRENT_TOP_LEVEL_ORDER if tab != "energy")
        self.assertEqual(CAPABILITY_TABS, expected)

    def test_energy_is_not_forced_to_host_an_unrelated_surface(self):
        self.assertEqual(capability_mount_html("energy"), "")

    def test_each_mount_is_inert_and_accessible(self):
        for tab, markup in capability_mounts().items():
            self.assertIn(f'data-flagship-tab="{tab}"', markup)
            self.assertIn('aria-label=', markup)
            self.assertIn('data-flagship-body', markup)
            self.assertIn('data-flagship-recovery-results', markup)
            if tab == "guard":
                self.assertNotIn('data-flagship-filter', markup)
                self.assertNotIn('<input', markup)
                self.assertNotIn('data-flagship-fix-all', markup)
                self.assertNotIn('data-flagship-collapse', markup)
                self.assertNotIn('<button', markup)
            else:
                self.assertIn('data-flagship-filter', markup)
                self.assertIn('data-flagship-fix-all', markup)
                self.assertIn('data-flagship-collapse', markup)
                self.assertIn('aria-expanded="true"', markup)
                self.assertIn('aria-controls=', markup)
            self.assertNotIn('<script', markup.lower())
            self.assertNotIn('onclick=', markup.lower())
            self.assertIn('role="status"', markup)
            self.assertIn('aria-live="polite"', markup)

    def test_combined_mount_order_is_exact(self):
        markup = combined_mount_html()
        offsets = [markup.index(f'data-flagship-tab="{tab}"') for tab in CAPABILITY_TABS]
        self.assertEqual(offsets, sorted(offsets))

    def test_renderer_uses_text_nodes_for_source_values(self):
        self.assertIn("node.textContent = text(value)", CAPABILITY_UI_JS)
        self.assertIn("cards.replaceChildren()", CAPABILITY_UI_JS)
        self.assertNotIn("innerHTML", CAPABILITY_UI_JS)
        self.assertNotIn("insertAdjacentHTML", CAPABILITY_UI_JS)

    def test_renderer_exposes_only_inspection_and_safe_local_binding_repair(self):
        self.assertIn("ke:capability-inspect", CAPABILITY_UI_JS)
        self.assertIn("ke:capability-repair", CAPABILITY_UI_JS)
        self.assertIn("recovery.canAttempt === true", CAPABILITY_UI_JS)
        self.assertIn("expectedGeneration", CAPABILITY_UI_JS)
        forbidden = (
            "launchPowerSwarm",
            "cancelPowerSwarm",
            "resumePowerSwarm",
            "kill_process",
            "send_dispatch",
            "apply_brain_structure",
            "start_network_discovery",
            "perform_network_action",
            "update_preferences",
        )
        for name in forbidden:
            self.assertNotIn(name, CAPABILITY_UI_JS)
        self.assertIn("placement.tab === 'guard'", CAPABILITY_UI_JS)

    def test_snapshot_boundary_is_fail_closed(self):
        self.assertIn("snapshot.readOnly !== true", CAPABILITY_UI_JS)
        self.assertIn("snapshot.preservesCurrentOrder !== true", CAPABILITY_UI_JS)
        self.assertIn("failed its read-only/order boundary", CAPABILITY_UI_JS)
        self.assertIn("EXPECTED_ORDER", CAPABILITY_UI_JS)
        self.assertIn("EXPECTED_IDS", CAPABILITY_UI_JS)
        self.assertIn("seen.has(row.id)", CAPABILITY_UI_JS)
        self.assertIn("snapshot.recovery.noIORepair !== true", CAPABILITY_UI_JS)
        self.assertIn("snapshot.recovery.generationBound !== true", CAPABILITY_UI_JS)
        self.assertIn("row.recovery.noSideEffects !== true", CAPABILITY_UI_JS)

    def test_truthful_recovery_states_are_visually_distinct(self):
        for state in ("repairable", "setup-required", "unavailable", "not-connected"):
            self.assertIn(state, CAPABILITY_UI_JS)
        self.assertIn("flagship-state-repairable", CAPABILITY_UI_CSS)
        self.assertIn("flagship-state-setup-required", CAPABILITY_UI_CSS)
        self.assertIn("Setup needed", CAPABILITY_UI_JS)
        self.assertIn("Auto Fix", CAPABILITY_UI_JS)

    def test_recovery_results_and_keyboard_focus_are_explicit(self):
        for outcome in (
            "applied",
            "already-healthy",
            "manual",
            "unavailable",
            "failed",
        ):
            self.assertIn(outcome, CAPABILITY_UI_JS)
        self.assertIn("renderFlagshipRecoveryResults", CAPABILITY_UI_JS)
        self.assertIn("restoreFlagshipCapabilityFocus", CAPABILITY_UI_JS)
        self.assertIn("restoreFocus:document.activeElement === fix", CAPABILITY_UI_JS)
        self.assertIn("flagship-recovery-results", CAPABILITY_UI_CSS)
        self.assertIn("flagship-result-failed", CAPABILITY_UI_CSS)
        self.assertIn("Rechecking current status", CAPABILITY_UI_JS)
        self.assertIn("finalState", CAPABILITY_UI_JS)
        self.assertNotIn("compact(item.capabilityId)+' · '", CAPABILITY_UI_JS)

    def test_internal_capability_taxonomy_is_only_rendered_after_inspect(self):
        primary_copy = CAPABILITY_UI_JS.split("const details = make('div','flagship-card-meta');", 1)[0]
        self.assertNotIn("flagship-card-id", primary_copy)
        self.assertNotIn("placement.section,'Capability'))", primary_copy)
        self.assertIn("meta('Reference',id)", CAPABILITY_UI_JS)
        self.assertIn("meta('Area'", CAPABILITY_UI_JS)
        self.assertIn("DISPLAY_NAMES", CAPABILITY_UI_JS)

    def test_fabric_collapse_is_local_persistent_and_fail_safe(self):
        self.assertIn("COLLAPSE_STORAGE_KEY", CAPABILITY_UI_JS)
        self.assertIn("window.localStorage.setItem", CAPABILITY_UI_JS)
        self.assertIn("get_flagship_ui_preferences", CAPABILITY_UI_JS)
        self.assertIn("set_flagship_fabric_collapsed", CAPABILITY_UI_JS)
        self.assertIn("ke.activity-monitor-flagship-preferences.v1", CAPABILITY_UI_JS)
        self.assertIn("hydrateFlagshipCollapsePreferences", CAPABILITY_UI_JS)
        self.assertIn("Native preference state is authoritative", CAPABILITY_UI_JS)
        self.assertIn("applyCollapsed(mount,false", CAPABILITY_UI_JS)
        self.assertIn("catch (_)", CAPABILITY_UI_JS)
        self.assertIn("applyCollapsed", CAPABILITY_UI_JS)
        self.assertIn("bindCollapse", CAPABILITY_UI_JS)
        self.assertIn("captureScroll", CAPABILITY_UI_JS)
        self.assertIn("restoreScroll", CAPABILITY_UI_JS)
        self.assertIn("data-flagship-collapse", combined_mount_html())
        self.assertIn(".flagship-fabric.is-collapsed", CAPABILITY_UI_CSS)
        self.assertIn(".flagship-fabric-body[hidden]", CAPABILITY_UI_CSS)
        self.assertNotIn("update_preferences", CAPABILITY_UI_JS)

    def test_powerswarm_is_labelled_as_agents_native(self):
        self.assertIn("Open in Agents", CAPABILITY_UI_JS)
        self.assertNotIn('data-flagship-tab="powerswarm"', combined_mount_html())

    def test_styles_are_responsive_and_do_not_redefine_navigation(self):
        self.assertIn("@media(max-width:820px)", CAPABILITY_UI_CSS)
        self.assertNotIn(".seg-btn", CAPABILITY_UI_CSS)
        self.assertNotIn(".toolbar", CAPABILITY_UI_CSS)

    def test_javascript_parses_when_node_is_available(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = pathlib.Path(temp_dir) / "flagship-ui.js"
            path.write_text(CAPABILITY_UI_JS + "\n", encoding="utf-8")
            result = subprocess.run(
                ["node", "--check", str(path)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_absolute_private_paths_or_contacts_are_embedded(self):
        payload = "\n".join((CAPABILITY_UI_CSS, CAPABILITY_UI_JS, combined_mount_html()))
        self.assertIsNone(re.search(r"/(?:Users|home|root|private|Volumes)/", payload))
        self.assertNotIn("@kestudios", payload.lower())


if __name__ == "__main__":
    unittest.main()
