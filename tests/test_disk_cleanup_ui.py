#!/usr/bin/env python3
import json
from html.parser import HTMLParser
import os
import unittest
from unittest.mock import patch

import activity_monitor
import cleanup_service


class FakeCleanupService:
    def __init__(self):
        self.calls = []

    def capabilities(self):
        self.calls.append(("capabilities",))
        return {
            "schemaVersion": cleanup_service.SCHEMA_VERSION,
            "supported": True,
            "automaticExecution": "unavailable-fail-closed",
            "finderReview": "available-exact-selection",
            "activityMonitorMutation": False,
        }

    def start_analysis(self, options):
        self.calls.append(("start", options))
        return {
            "schemaVersion": cleanup_service.SCHEMA_VERSION,
            "state": "running",
            "jobId": "job-1",
            "scanStartedAutomatically": False,
        }

    def analysis_status(self, job_id):
        self.calls.append(("status", job_id))
        return {
            "schemaVersion": cleanup_service.SCHEMA_VERSION,
            "state": "complete",
            "jobId": job_id,
            "analysisId": "analysis-1",
            "categories": [],
            "reviewCandidates": [],
            "reviewCandidateBytes": 0,
            "reviewCandidateCount": 0,
        }

    def cancel_analysis(self, job_id):
        self.calls.append(("cancel", job_id))
        return {"ok": True, "state": "cancelling"}

    def reveal_candidates(self, analysis_id, item_ids):
        self.calls.append(("reveal", analysis_id, item_ids))
        return {
            "ok": True,
            "state": "revealed",
            "revealedCount": len(item_ids),
            "skippedCount": 0,
            "detail": "Nothing was deleted.",
        }

    def open_review_destination(self, destination):
        self.calls.append(("destination", destination))
        return {"ok": True, "state": "opened", "destination": destination}


class IdParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []

    def handle_starttag(self, _tag, attrs):
        for key, value in attrs:
            if key == "id":
                self.ids.append(value)


class DiskCleanupBridgeTests(unittest.TestCase):
    @staticmethod
    def api(service):
        return activity_monitor.Api(
            brain_service=object(),
            dispatch_service=object(),
            guard_service=object(),
            workspace_service=object(),
            memory_diagnostics_service=object(),
            network_service=object(),
            powerswarm_service=object(),
            flagship_bridge=object(),
            cleanup_service=service,
        )

    def test_bridge_freezes_review_only_scope_and_exposes_no_mutation(self):
        service = FakeCleanupService()
        api = self.api(service)
        started = json.loads(api.start_disk_cleanup_scan())
        self.assertEqual(started["state"], "running")
        options = service.calls[-1][1]
        self.assertTrue(options["reviewOnly"])
        self.assertFalse(options["duplicateAnalysis"])
        self.assertEqual(tuple(options["categories"]), activity_monitor.DISK_CLEANUP_REVIEW_CATEGORIES)
        self.assertNotIn("downloads-duplicates", options["categories"])
        self.assertFalse(hasattr(api, "start_disk_cleanup_execution"))
        self.assertFalse(hasattr(api, "empty_disk_cleanup_trash"))

    def test_bridge_covers_status_cancel_reveal_and_fixed_destination(self):
        service = FakeCleanupService()
        api = self.api(service)
        self.assertTrue(json.loads(api.get_disk_cleanup_capabilities())["supported"])
        self.assertEqual(json.loads(api.get_disk_cleanup_scan("job-1"))["analysisId"], "analysis-1")
        self.assertEqual(json.loads(api.cancel_disk_cleanup_scan("job-1"))["state"], "cancelling")
        self.assertEqual(json.loads(api.reveal_disk_cleanup_candidates("analysis-1", ["one"]))["revealedCount"], 1)
        self.assertEqual(json.loads(api.open_disk_cleanup_destination("trash"))["destination"], "trash")
        self.assertEqual(
            [row[0] for row in service.calls],
            ["capabilities", "status", "cancel", "reveal", "destination"],
        )

    def test_bridge_errors_are_path_free_and_fail_soft(self):
        service = FakeCleanupService()

        def reject(_analysis_id, _ids):
            raise cleanup_service.CleanupError("analysis-expired", "The scan expired; scan again.")

        service.reveal_candidates = reject
        result = json.loads(self.api(service).reveal_disk_cleanup_candidates("analysis", ["one"]))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "analysis-expired")
        self.assertFalse(result["activityMonitorMutation"])
        self.assertNotIn("/Users/", json.dumps(result))

    def test_helper_command_reuses_exact_trusted_executable_without_a_shell(self):
        with patch.object(activity_monitor.sys, "executable", "/usr/bin/python3"):
            with patch.object(activity_monitor.sys, "frozen", False, create=True):
                command = activity_monitor._cleanup_helper_command()
        self.assertEqual(command[0], "/usr/bin/python3")
        self.assertEqual(command[-1], "--cleanup-scan-helper")
        self.assertEqual(len(command), 3)
        self.assertTrue(os.path.isabs(command[1]))

    def test_helper_protocol_accepts_only_one_fixed_category_and_writes_json(self):
        request = json.dumps({
            "schemaVersion": cleanup_service.REVIEW_HELPER_SCHEMA_VERSION,
            "category": "app-caches",
        }).encode("utf-8")
        writes = []

        class HelperService:
            def __init__(self, **_kwargs):
                pass

            def start_analysis(self, options):
                self.options = options
                return {"state": "complete", "analysisId": "analysis"}

            def review_helper_bundle(self, category, result):
                return {
                    "schemaVersion": cleanup_service.REVIEW_HELPER_SCHEMA_VERSION,
                    "category": category,
                    "result": result,
                    "internalCandidates": [],
                }

        with patch.object(activity_monitor.os, "read", side_effect=[request, b""]):
            with patch.object(activity_monitor.os, "write", side_effect=lambda _fd, body: writes.append(body) or len(body)):
                with patch.object(activity_monitor, "CleanupService", HelperService):
                    activity_monitor._run_cleanup_scan_helper()
        payload = json.loads(b"".join(writes).decode("utf-8"))
        self.assertEqual(payload["category"], "app-caches")
        self.assertEqual(payload["schemaVersion"], cleanup_service.REVIEW_HELPER_SCHEMA_VERSION)

    def test_helper_protocol_rejects_extra_fields_before_scanning(self):
        request = json.dumps({
            "schemaVersion": cleanup_service.REVIEW_HELPER_SCHEMA_VERSION,
            "category": "app-caches",
            "path": "/tmp/not-allowed",
        }).encode("utf-8")
        with patch.object(activity_monitor.os, "read", side_effect=[request, b""]):
            with patch.object(activity_monitor, "CleanupService") as service:
                with self.assertRaises(SystemExit) as error:
                    activity_monitor._run_cleanup_scan_helper()
        self.assertEqual(error.exception.code, 2)
        service.assert_not_called()


class DiskCleanupUiContractTests(unittest.TestCase):
    def test_surface_is_unique_accessible_and_stays_inside_disk(self):
        parser = IdParser()
        parser.feed(activity_monitor.HTML)
        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        for expected in (
            "disk-cleanup-open",
            "disk-cleanup-sheet",
            "disk-cleanup-scan",
            "disk-cleanup-cancel",
            "disk-cleanup-category-list",
            "disk-cleanup-candidate-list",
            "disk-cleanup-reveal",
            "disk-usage-meter",
        ):
            self.assertIn(expected, parser.ids)
        self.assertIn('role="dialog"', activity_monitor.HTML)
        self.assertIn('aria-modal="true"', activity_monitor.HTML)
        disk_markup = activity_monitor.HTML.split('<div id="disk-tab"', 1)[1].split('<div id="network-tab"', 1)[0]
        self.assertIn('id="disk-cleanup-sheet"', disk_markup)

    def test_disk_cleanup_entry_and_sheet_use_the_current_card_system(self):
        html = activity_monitor.HTML
        disk_markup = html.split('<div id="disk-tab"', 1)[1].split('<div id="network-tab"', 1)[0]
        for class_name in (
            "disk-overview",
            "disk-storage-card",
            "disk-io-card",
            "disk-cleanup-trigger-icon",
            "disk-cleanup-trigger-copy",
            "disk-cleanup-head-icon",
        ):
            self.assertIn(class_name, disk_markup)
        self.assertIn("Review cleanup", disk_markup)
        self.assertIn("Large files, caches, logs, and installers", disk_markup)
        self.assertIn('role="progressbar"', disk_markup)
        self.assertIn('aria-label="Open Cleanup Assistant to review cleanup candidates"', disk_markup)
        self.assertNotIn("✦", disk_markup)
        self.assertNotIn("linear-gradient(90deg,#34C759,#FF9F0A,#FF3B30)", disk_markup)
        self.assertIn("@media(max-width:760px)", html)
        self.assertIn("diskPercent.toFixed(1)", html)

    def test_scan_is_explicit_cancellable_and_leaving_disk_closes_it(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        open_region = "async function openDiskCleanup" + script.split("async function openDiskCleanup", 1)[1].split("async function closeDiskCleanup", 1)[0]
        self.assertNotIn("start_disk_cleanup_scan", open_region)
        self.assertIn("pywebview.api.start_disk_cleanup_scan()", script)
        self.assertIn("pywebview.api.cancel_disk_cleanup_scan", script)
        self.assertIn("if (currentTab === 'disk' && nextTab !== 'disk') closeDiskCleanup(false);", script)
        self.assertIn("event.key === 'Escape'", script)
        self.assertIn("No scan yet. Nothing runs in the background.", activity_monitor.HTML)

    def test_ui_keeps_truthful_no_delete_and_delta_boundaries(self):
        html = activity_monitor.HTML
        self.assertIn("Review cleanup candidates", html)
        self.assertIn("Nothing is deleted automatically.", html)
        self.assertNotIn("Find space. Keep control.", html)
        self.assertIn("Nothing is deleted here.", html)
        self.assertIn("Activity Monitor never deletes files.", html)
        self.assertIn("system-wide since first scan", html)
        self.assertIn("does not attribute this delta to a specific action", html)
        self.assertIn("Trash must be emptied separately", html)
        self.assertIn("DISK_CLEANUP_MAX_SELECTION = 12", html)
        self.assertNotIn("pywebview.api.start_execution", html)
        self.assertNotIn("pywebview.api.empty_trash", html)

    def test_untrusted_candidates_are_rendered_with_text_content(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        region = "function renderDiskCleanupCategories" + script.split("function renderDiskCleanupCategories", 1)[1].split("function sortProcs", 1)[0]
        self.assertIn("target.textContent = item.target", region)
        self.assertIn("reason.textContent =", region)
        self.assertIn("name.textContent =", region)
        self.assertNotIn("innerHTML", region)

    def test_review_handoffs_are_fixed_and_no_arbitrary_path_enters_bridge(self):
        html = activity_monitor.HTML
        self.assertIn('data-disk-cleanup-destination="storage-settings"', html)
        self.assertIn('data-disk-cleanup-destination="downloads"', html)
        self.assertIn('data-disk-cleanup-destination="trash"', html)
        self.assertIn("open_disk_cleanup_destination(destination)", html)
        self.assertIn("reveal_disk_cleanup_candidates(diskCleanupAnalysisId, Array.from(diskCleanupSelected))", html)
        self.assertIn("@media(prefers-reduced-motion:reduce)", html)


if __name__ == "__main__":
    unittest.main()
