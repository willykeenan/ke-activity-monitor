import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import activity_monitor
from guard_status import GuardService, SCHEMA_VERSION


class GuardStatusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.base = self.home / "ke-agent-rooms" / "resource" / "keguard"
        self.now = 1_800_000_000.0
        self.service = GuardService(
            home=self.home,
            platform_name="Darwin",
            clock=lambda: self.now,
        )

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def _stamp(epoch):
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")

    def _state(self, *, armed=True, age=30):
        return {
            "daemon": {"pid": 50703, "armed": armed, "tick": 60, "last": self.now - age},
            "ticks": [
                {"t": self.now - 120, "load1": 9.0, "free_gb": 21.5},
                {"t": self.now - 60, "load1": 7.0, "free_gb": 21.0},
                {"t": self.now - 30, "load1": 5.0, "free_gb": 20.5},
            ],
            "suspects": {
                "4321": {"streak": 3, "children": [4322, 4323, 4324]},
                "9999": {"streak": 0, "children": []},
            },
            "pending_kill": {
                "pid": 4321,
                "cmd": "SECRET_COMMAND --token do-not-return",
                "targets": [4321, 4322],
                "ts": self.now - 10,
                "flood": "/private/secret/flood.log",
                "evidence": "/private/secret/evidence.txt",
            },
            "kills": [self.now - 100],
        }

    def _write_state(self, state):
        self.base.mkdir(parents=True, exist_ok=True)
        self.service.state_path.write_text(json.dumps(state), encoding="utf-8")

    def _write_ledger(self, rows):
        self.base.mkdir(parents=True, exist_ok=True)
        self.service.ledger_path.write_text(
            "".join(json.dumps(row) + "\n" for row in rows),
            encoding="utf-8",
        )

    def test_live_armed_projection_is_complete_and_privacy_bounded(self):
        self._write_state(self._state())
        self._write_ledger([
            {
                "ts": self._stamp(self.now - 120),
                "event": "alert",
                "key": "bigfile-/Users/private/secret.log",
                "body": "RAW_ALERT_BODY_DO_NOT_RETURN",
            },
            {
                "ts": self._stamp(self.now - 90),
                "event": "kill_sigterm",
                "pid": 4321,
                "cmd": "RAW_COMMAND_DO_NOT_RETURN",
                "flood": "/Users/private/flood.log",
                "evidence": "/Users/private/evidence.txt",
            },
            {"ts": self._stamp(self.now - 30), "event": "kill_complete", "pid": 4321},
        ])

        payload = self.service.status()
        serialized = json.dumps(payload)
        self.assertEqual(payload["schemaVersion"], SCHEMA_VERSION)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["state"], "armed")
        self.assertEqual(payload["configuredMode"], "armed")
        self.assertEqual(payload["activeSuspects"]["count"], 1)
        self.assertEqual(payload["activeSuspects"]["items"][0]["childCount"], 3)
        self.assertEqual(payload["pendingRemediation"]["targetCount"], 2)
        self.assertEqual(payload["kills24h"], 1)
        self.assertEqual(payload["trends"]["load"]["direction"], "falling")
        self.assertEqual(payload["trends"]["diskFree"]["direction"], "falling")
        self.assertEqual(payload["recentEvidence"][0]["label"], "Process remediation completed")
        self.assertIn("Large growing file", [row["label"] for row in payload["recentEvidence"]])
        self.assertNotIn("RAW_ALERT_BODY_DO_NOT_RETURN", serialized)
        self.assertNotIn("RAW_COMMAND_DO_NOT_RETURN", serialized)
        self.assertNotIn("/Users/private", serialized)
        self.assertNotIn("/private/secret", serialized)
        self.assertFalse(payload["privacy"]["controlsExposed"])

    def test_live_unarmed_projection_is_dry_run(self):
        self._write_state(self._state(armed=False))
        self._write_ledger([])
        payload = self.service.status()
        self.assertEqual(payload["state"], "dry-run")
        self.assertEqual(payload["statusLabel"], "DRY-RUN")
        self.assertEqual(payload["configuredMode"], "dry-run")

    def test_old_observations_transition_from_stale_to_offline(self):
        self._write_state(self._state(age=181))
        self.assertEqual(self.service.status()["state"], "stale")
        self._write_state(self._state(age=901))
        payload = self.service.status()
        self.assertEqual(payload["state"], "offline")
        self.assertTrue(payload["available"])

    def test_malformed_state_retains_last_valid_snapshot_as_stale(self):
        self._write_state(self._state())
        self._write_ledger([])
        live = self.service.status()
        self.assertEqual(live["activeSuspects"]["count"], 1)

        self.service.state_path.write_text("{malformed", encoding="utf-8")
        retained = self.service.status()
        self.assertEqual(retained["state"], "stale")
        self.assertTrue(retained["retained"])
        self.assertEqual(retained["readErrorCode"], "state_malformed")
        self.assertEqual(retained["activeSuspects"]["count"], 1)

    def test_absent_install_and_absent_state_are_intentional(self):
        missing_install = self.service.status()
        self.assertEqual(missing_install["state"], "not-installed")
        self.assertFalse(missing_install["installed"])

        self.base.mkdir(parents=True)
        missing_state = self.service.status()
        self.assertEqual(missing_state["state"], "offline")
        self.assertTrue(missing_state["installed"])
        self.assertEqual(missing_state["readErrorCode"], "state_missing")

    def test_unsupported_operating_system_degrades_without_reading_install(self):
        service = GuardService(
            home=self.home,
            platform_name="Windows",
            clock=lambda: self.now,
        )
        payload = service.status()
        self.assertEqual(payload["state"], "unsupported")
        self.assertFalse(payload["supported"])
        self.assertFalse(payload["available"])

    @staticmethod
    def _api(service):
        brain = object()
        dispatch = object()
        api = activity_monitor.Api(
            brain_service=brain,
            dispatch_service=dispatch,
            guard_service=service,
        )
        return api, brain, dispatch

    def test_permission_denied_is_offline_then_retains_valid_state_without_api_failure(self):
        self.base.mkdir(parents=True)

        def denied():
            raise PermissionError("PRIVATE_PERMISSION_DETAIL")

        unavailable = GuardService(
            home=self.home,
            platform_name="Darwin",
            clock=lambda: self.now,
            state_reader=denied,
        )
        api, brain, dispatch = self._api(unavailable)
        payload = json.loads(api.get_guard_status())
        self.assertEqual(payload["state"], "offline")
        self.assertEqual(payload["readErrorCode"], "state_unreadable")
        self.assertNotIn("PRIVATE_PERMISSION_DETAIL", json.dumps(payload))
        self.assertIs(api._brain_service, brain)
        self.assertIs(api._dispatch_service, dispatch)

        sequence = [self._state(), PermissionError("PRIVATE_PERMISSION_DETAIL")]

        def valid_then_denied():
            value = sequence.pop(0)
            if isinstance(value, Exception):
                raise value
            return value

        retained_service = GuardService(
            home=self.home,
            platform_name="Darwin",
            clock=lambda: self.now,
            state_reader=valid_then_denied,
        )
        retained_api, _, _ = self._api(retained_service)
        self.assertEqual(json.loads(retained_api.get_guard_status())["state"], "armed")
        retained = json.loads(retained_api.get_guard_status())
        self.assertEqual(retained["state"], "stale")
        self.assertTrue(retained["retained"])
        self.assertEqual(retained["readErrorCode"], "state_unreadable")

    def test_bounded_state_timeout_is_offline_then_retains_valid_state(self):
        self.base.mkdir(parents=True)

        def slow():
            time.sleep(0.08)
            return self._state()

        unavailable = GuardService(
            home=self.home,
            platform_name="Darwin",
            clock=lambda: self.now,
            read_timeout_seconds=0.01,
            state_reader=slow,
        )
        payload = json.loads(self._api(unavailable)[0].get_guard_status())
        self.assertEqual(payload["state"], "offline")
        self.assertEqual(payload["readErrorCode"], "state_timeout")

        calls = {"count": 0}

        def valid_then_slow():
            calls["count"] += 1
            if calls["count"] == 1:
                return self._state()
            time.sleep(0.08)
            return self._state()

        retained_service = GuardService(
            home=self.home,
            platform_name="Darwin",
            clock=lambda: self.now,
            read_timeout_seconds=0.01,
            state_reader=valid_then_slow,
        )
        retained_api, _, _ = self._api(retained_service)
        self.assertEqual(json.loads(retained_api.get_guard_status())["state"], "armed")
        retained = json.loads(retained_api.get_guard_status())
        self.assertEqual(retained["state"], "stale")
        self.assertTrue(retained["retained"])
        self.assertEqual(retained["readErrorCode"], "state_timeout")

    def test_repeated_timeouts_reuse_one_inflight_reader_and_leave_other_api_surfaces_usable(self):
        self.base.mkdir(parents=True)
        release = threading.Event()
        starts = {"count": 0}

        def blocked_reader():
            starts["count"] += 1
            release.wait(1.0)
            return self._state()

        service = GuardService(
            home=self.home,
            platform_name="Darwin",
            clock=lambda: self.now,
            read_timeout_seconds=0.01,
            state_reader=blocked_reader,
        )

        class Brain:
            @staticmethod
            def scan(force=False):
                return {"ok": True, "force": bool(force), "surface": "brain"}

        api = activity_monitor.Api(
            brain_service=Brain(),
            dispatch_service=object(),
            guard_service=service,
        )
        for _ in range(3):
            payload = json.loads(api.get_guard_status())
            self.assertEqual(payload["state"], "offline")
            self.assertEqual(payload["readErrorCode"], "state_timeout")
        self.assertEqual(starts["count"], 1)
        self.assertEqual(json.loads(api.get_brain_inventory())["surface"], "brain")

        release.set()
        time.sleep(0.02)
        recovered = json.loads(api.get_guard_status())
        self.assertEqual(recovered["state"], "armed")
        self.assertEqual(starts["count"], 1)

    def test_install_probe_permission_error_is_fail_soft_before_and_after_valid_state(self):
        with patch.object(Path, "is_dir", side_effect=PermissionError("private")):
            initial = self.service.status()
        self.assertEqual(initial["state"], "offline")
        self.assertIsNone(initial["installed"])
        self.assertEqual(initial["readErrorCode"], "state_unreadable")

        self._write_state(self._state())
        self._write_ledger([])
        self.assertEqual(self.service.status()["state"], "armed")
        with patch.object(Path, "is_dir", side_effect=PermissionError("private")):
            retained = self.service.status()
        self.assertEqual(retained["state"], "stale")
        self.assertTrue(retained["retained"])
        self.assertEqual(retained["readErrorCode"], "state_unreadable")

    def test_malformed_ledger_rows_do_not_leak_or_break_live_state(self):
        self._write_state(self._state())
        self.base.mkdir(parents=True, exist_ok=True)
        self.service.ledger_path.write_text(
            "{malformed\n"
            + json.dumps({
                "ts": self._stamp(self.now - 5),
                "event": "alert",
                "key": "churn-4321",
                "body": "LEDGER_SECRET_DO_NOT_RETURN",
            })
            + "\n",
            encoding="utf-8",
        )
        payload = self.service.status()
        self.assertEqual(payload["state"], "armed")
        self.assertTrue(payload["ledgerAvailable"])
        self.assertEqual(payload["recentEvidence"][0]["label"], "Suspicious process churn")
        self.assertNotIn("LEDGER_SECRET_DO_NOT_RETURN", json.dumps(payload))

    def test_adversarial_ledger_timestamp_is_never_returned_verbatim(self):
        self._write_state(self._state())
        malicious_timestamp = "/Users/private/secret-path"
        self._write_ledger([
            {
                "ts": malicious_timestamp,
                "event": "alert",
                "key": "bigfile-/Users/private/other-secret",
                "body": "RAW_ALERT_BODY_DO_NOT_RETURN",
            }
        ])
        payload = self.service.status()
        self.assertEqual(payload["state"], "armed")
        self.assertEqual(payload["recentEvidence"][0]["label"], "Large growing file")
        self.assertIsNone(payload["recentEvidence"][0]["observedAt"])
        serialized = json.dumps(payload)
        self.assertNotIn(malicious_timestamp, serialized)
        self.assertNotIn("other-secret", serialized)
        self.assertNotIn("RAW_ALERT_BODY_DO_NOT_RETURN", serialized)

    def test_browser_bridge_fallback_ages_truthfully_and_preserves_terminal_states(self):
        html = activity_monitor.HTML
        start = html.index("function guardBridgeFallbackPayload")
        end = html.index("\n}\n\nfunction renderGuardSpark", start) + 2
        helper = html[start:end]
        script = helper + r"""
const now = Date.parse('2026-08-20T12:00:00Z');
const active = {
  ok:true,state:'armed',statusLabel:'ARMED',available:true,retained:false,
  observedAt:'2026-08-20T11:59:00Z',ageSeconds:1,offlineAfterSeconds:900,
  activeSuspects:{count:1,items:[]},recentEvidence:[]
};
const stale = guardBridgeFallbackPayload(active, now);
const expired = guardBridgeFallbackPayload(stale, now + 901000);
const priorOffline = guardBridgeFallbackPayload({...active,state:'offline',statusLabel:'OFFLINE'}, now);
const notInstalled = guardBridgeFallbackPayload({state:'not-installed',statusLabel:'NOT INSTALLED',observedAt:null,ageSeconds:null}, now);
const unsupported = guardBridgeFallbackPayload({state:'unsupported',statusLabel:'UNSUPPORTED',observedAt:null,ageSeconds:null}, now);
const currentStale = guardBridgeFallbackPayload({...active,state:'stale'}, now);
const customExpired = guardBridgeFallbackPayload({...active,offlineAfterSeconds:30}, now);
const invalidObserved = guardBridgeFallbackPayload({...active,observedAt:'/Users/private/secret-path'}, now);
const empty = guardBridgeFallbackPayload(null, now);
process.stdout.write(JSON.stringify({stale,expired,priorOffline,notInstalled,unsupported,currentStale,customExpired,invalidObserved,empty}));
"""
        completed = subprocess.run(
            ["node", "-e", script],
            text=True,
            capture_output=True,
            check=True,
            timeout=8,
        )
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["stale"]["state"], "stale")
        self.assertTrue(payload["stale"]["retained"])
        self.assertEqual(payload["stale"]["ageSeconds"], 60)
        self.assertEqual(payload["expired"]["state"], "offline")
        self.assertEqual(payload["expired"]["ageSeconds"], 961)
        self.assertEqual(payload["priorOffline"]["state"], "offline")
        self.assertEqual(payload["notInstalled"]["state"], "not-installed")
        self.assertEqual(payload["unsupported"]["state"], "unsupported")
        self.assertEqual(payload["currentStale"]["state"], "stale")
        self.assertEqual(payload["customExpired"]["state"], "offline")
        self.assertEqual(payload["invalidObserved"]["state"], "offline")
        self.assertEqual(payload["empty"]["state"], "offline")
        self.assertIsNone(payload["empty"]["installed"])
        self.assertIn(
            "renderGuardStatus(guardBridgeFallbackPayload(lastGuardStatus, Date.now()))",
            html,
        )

    def test_row_capped_recent_ledger_keeps_24_hour_kill_count_unknown(self):
        self._write_state(self._state())
        self._write_ledger([
            {
                "ts": self._stamp(self.now - 600 + index),
                "event": "kill_sigterm" if index == 0 else "heartbeat",
            }
            for index in range(401)
        ])
        payload = self.service.status()
        self.assertTrue(payload["ledgerAvailable"])
        self.assertFalse(payload["killsWindowComplete"])
        self.assertIsNone(payload["kills24h"])

    def test_rotated_recent_ledger_keeps_24_hour_kill_count_unknown(self):
        self._write_state(self._state())
        self._write_ledger([
            {"ts": self._stamp(self.now - 60), "event": "kill_sigterm"},
        ])
        self.service.ledger_path.with_name("ledger.jsonl.1").write_text(
            json.dumps({"ts": self._stamp(self.now - 90000), "event": "heartbeat"}) + "\n",
            encoding="utf-8",
        )
        payload = self.service.status()
        self.assertTrue(payload["ledgerAvailable"])
        self.assertFalse(payload["killsWindowComplete"])
        self.assertIsNone(payload["kills24h"])

    def test_unavailable_ledger_keeps_kill_count_unknown_in_parser_and_ui(self):
        self._write_state(self._state())
        payload = self.service.status()
        self.assertIsNone(payload["kills24h"])
        self.assertFalse(payload["ledgerAvailable"])

        script = (
            "function finite(value){return typeof value==='number'&&Number.isFinite(value);}\n"
            "function guardCount(value){return value!=null&&finite(Number(value))?String(Number(value)):'—';}\n"
            "process.stdout.write(JSON.stringify([guardCount(null),guardCount(undefined),guardCount(0),guardCount(2)]));"
        )
        completed = subprocess.run(
            ["node", "-e", script],
            text=True,
            capture_output=True,
            check=True,
            timeout=8,
        )
        self.assertEqual(json.loads(completed.stdout), ["—", "—", "0", "2"])
        self.assertIn("guardCount(payload?.kills24h)", activity_monitor.HTML)

    def test_paths_are_derived_from_the_supplied_current_user_home(self):
        self.assertEqual(
            self.service.state_path,
            self.home / "ke-agent-rooms" / "resource" / "keguard" / "state.json",
        )
        self.assertNotIn("alex", str(self.service.state_path))

    def test_guard_module_is_mirrored_and_byte_checked_in_every_mac_bundle(self):
        root = Path(__file__).resolve().parents[1]
        spec = (root / "activity_monitor.spec").read_text(encoding="utf-8")
        script = (root / "package_app.zsh").read_text(encoding="utf-8")
        self.assertIn('(os.path.join(ROOT, "guard_status.py"), "source")', spec)
        self.assertIn("py_compile activity_monitor.py brain_discovery.py dispatch_router.py guard_status.py", script)
        self.assertIn('/usr/bin/cmp guard_status.py "$bundle/Contents/Resources/source/guard_status.py"', script)
        self.assertIn('verify_source_parity "$built_app"', script)
        self.assertIn('verify_source_parity "$installed_app"', script)
        self.assertIn('verify_source_parity "$distributable_app"', script)
        self.assertIn('verify_source_parity "$archive_verify/Activity Monitor.app"', script)

    def test_guard_tab_has_no_interactive_or_mutating_controls(self):
        html = activity_monitor.HTML
        start = html.index('<div id="guard-tab"')
        end = html.index('<div class="status-bar">', start)
        guard_markup = html[start:end]
        self.assertNotIn("<button", guard_markup)
        self.assertNotIn("<input", guard_markup)
        self.assertNotIn("<textarea", guard_markup)
        self.assertIn("Strictly read-only", guard_markup)
        self.assertIn("get_guard_status", Path(activity_monitor.__file__).read_text(encoding="utf-8"))
        self.assertIn("@media(max-width:1000px)", html)


if __name__ == "__main__":
    unittest.main()
