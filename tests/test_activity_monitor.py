import hashlib
import json
import os
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import activity_monitor  # noqa: E402


class ActivityMonitorAgentsTests(unittest.TestCase):
    def setUp(self):
        self._observer = activity_monitor.AGENTS_OBSERVER
        activity_monitor.Api._agents_cache = {
            "t": 0.0, "body": None, "last_good": None, "cpu_pool_activity": {}
        }

    def tearDown(self):
        activity_monitor.AGENTS_OBSERVER = self._observer
        activity_monitor.Api._agents_cache = {
            "t": 0.0, "body": None, "last_good": None, "cpu_pool_activity": {}
        }

    def test_observer_schema_keeps_worker_plugins_optional(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment = os.environ.copy()
            environment["HOME"] = temporary
            for name in (
                "KE_ACTIVITY_CPU_LIB",
                "KE_ACTIVITY_GPU_LIB",
            ):
                environment.pop(name, None)
            result = subprocess.run(
                ["node", str(ROOT / "agents_snapshot.mjs")],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=True,
                timeout=8,
            )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schemaVersion"], "ke.activity-monitor-agents.v1")
        self.assertIsInstance(payload["cpu"]["ok"], bool)
        self.assertIsInstance(payload["gpu"]["ok"], bool)
        self.assertFalse(payload["cpu"]["ok"])
        self.assertFalse(payload["gpu"]["ok"])

    def test_gpu_only_observer_does_not_import_the_cpu_section(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cpu_lib = root / "cpu.mjs"
            gpu_lib = root / "gpu.mjs"
            cpu_lib.write_text(
                "throw new Error('CPU section must not load');\n"
                "export function buildSnapshot(){return {}; }\n"
            )
            gpu_lib.write_text(
                "export function buildSnapshot(){return "
                + json.dumps({
                    "kind": "gpu-workers-snapshot",
                    "schemaVersion": "gpu-workers.v1",
                    "generatedAt": "2026-08-20T21:00:00Z",
                    "host": {},
                    "devices": [],
                    "lane": {"state": "idle"},
                    "counts": {"registered": 0},
                    "jobs": [],
                    "hints": [],
                    "boundary": "fixture",
                })
                + ";}\n"
            )
            environment = os.environ.copy()
            environment.update({
                "KE_ACTIVITY_CPU_LIB": str(cpu_lib),
                "KE_ACTIVITY_GPU_LIB": str(gpu_lib),
            })
            result = subprocess.run(
                ["node", str(ROOT / "agents_snapshot.mjs"), "--section=gpu"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=True,
                timeout=8,
            )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["section"], "gpu")
        self.assertIsNone(payload["cpu"])
        self.assertTrue(payload["gpu"]["ok"])
        self.assertEqual(payload["gpu"]["snapshot"]["lane"]["state"], "idle")

    def _run_observer_fixture(self, state, pool, *, return_snapshot=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cpu_lib = root / "cpu.mjs"
            gpu_lib = root / "gpu.mjs"
            state_path = root / "state.json"
            cpu_lib.write_text(
                "export function buildSnapshot(){return "
                + json.dumps({
                    "kind": "cpu-workers-snapshot",
                    "schemaVersion": "cpu-workers.v1",
                    "generatedAt": "2026-08-20T21:00:00Z",
                    "host": {},
                    "discovery": {"state": "observed", "mode": "fixture"},
                    "counts": {},
                    "pools": [pool],
                    "boundary": "fixture",
                })
                + ";}\n"
            )
            gpu_lib.write_text(
                "export function buildSnapshot(){return "
                + json.dumps({
                    "kind": "gpu-workers-snapshot",
                    "schemaVersion": "gpu-workers.v1",
                    "generatedAt": "2026-08-20T21:00:00Z",
                    "host": {},
                    "devices": [],
                    "lane": {},
                    "counts": {},
                    "jobs": [],
                    "hints": [],
                    "boundary": "fixture",
                })
                + ";}\n"
            )
            state_path.write_text(json.dumps(state))
            environment = os.environ.copy()
            environment.update({
                "KE_ACTIVITY_CPU_LIB": str(cpu_lib),
                "KE_ACTIVITY_GPU_LIB": str(gpu_lib),
            })
            result = subprocess.run(
                ["node", str(ROOT / "agents_snapshot.mjs")],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=True,
                timeout=8,
            )
            snapshot = json.loads(result.stdout)["cpu"]["snapshot"]
            return snapshot if return_snapshot else snapshot["pools"][0]

    @staticmethod
    def _stamp(epoch):
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")

    def _cpu_pool(self, *, pool_id="cpu_pool_fixture", live=0, activity_epoch=None, workers=None):
        retention = None if activity_epoch is None else {
            "lastActivityAt": self._stamp(activity_epoch),
            "inactiveForMs": None,
            "retentionMs": 900_000,
            "expiresAt": self._stamp(activity_epoch + 900),
            "visibleByDefault": True,
        }
        workers = list(workers or [])
        return {
            "id": pool_id,
            "title": "Generic fixture pool",
            "source": "fixture",
            "registered": True,
            "runState": "stopped" if live == 0 else "active",
            "parent": {"pid": 5000, "processAlive": False, "state": "exited"},
            "totals": {"live": live, "busy": live, "cpuPercent": 0, "rssBytes": 0},
            "progress": {
                "available": activity_epoch is not None,
                "updatedAt": self._stamp(activity_epoch) if activity_epoch is not None else None,
            },
            "retention": retention,
            "workers": workers,
        }

    def _agents_payload(self, pool, generated_epoch, *, stale=False, cpu_ok=True):
        return {
            "schemaVersion": "ke.activity-monitor-agents.v1",
            "generatedAt": self._stamp(generated_epoch),
            "observedAt": self._stamp(generated_epoch),
            "stale": stale,
            "cpu": {
                "ok": cpu_ok,
                "stale": stale,
                "snapshot": {
                    "generatedAt": self._stamp(generated_epoch),
                    "counts": {"pools": 1, "workers": len(pool.get("workers") or []), "live": pool["totals"]["live"], "busy": pool["totals"]["busy"], "registered": 1},
                    "pools": [pool],
                    "host": {},
                },
            },
            "gpu": {
                "ok": True,
                "stale": False,
                "snapshot": {"jobs": [], "devices": [], "hints": [], "lane": {}},
            },
        }

    def _run_cpu_retention_js(self, payload, now_epoch, selection=None):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        start = script.index("const CPU_POOL_RETENTION_MS")
        end = script.index("function workerDetail", start)
        fixture = script[start:end]
        fixture += "\nconst fixturePayload=" + json.dumps(payload) + ";"
        fixture += "\nconst fixtureSelection=" + json.dumps(selection or {}) + ";"
        fixture += "\nconst pruned=pruneExpiredCpuPools(fixturePayload," + str(int(now_epoch * 1000)) + ");"
        fixture += "\ncleanupAgentWorkerSelection(pruned,fixtureSelection);"
        fixture += "\nprocess.stdout.write(JSON.stringify({payload:pruned,selection:fixtureSelection}));"
        completed = subprocess.run(
            ["node", "-e", fixture],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=8,
        )
        return json.loads(completed.stdout)

    def test_observer_preserves_cpu_parent_provenance(self):
        pool = self._cpu_pool(activity_epoch=1_800_000_000.0)
        observed = self._run_observer_fixture({"schema_version": "unrelated"}, pool)
        self.assertEqual(observed["parent"]["pid"], 5000)
        self.assertFalse(observed["parent"]["processAlive"])

    def test_observer_preserves_cpu_discovery_freshness_provenance(self):
        snapshot = self._run_observer_fixture(
            {"schema_version": "unrelated"},
            self._cpu_pool(activity_epoch=None),
            return_snapshot=True,
        )
        self.assertEqual(snapshot["discovery"]["state"], "observed")
        self.assertEqual(snapshot["discovery"]["mode"], "fixture")

    def test_stopped_cpu_pool_is_retained_at_899_seconds_and_evicted_at_901(self):
        now = 1_800_000_000.0
        visible = activity_monitor._prune_expired_cpu_pools(
            self._agents_payload(self._cpu_pool(activity_epoch=now - 899), now),
            now_epoch=now,
            activity_cache={},
            current_observation=True,
        )
        self.assertEqual(len(visible["cpu"]["snapshot"]["pools"]), 1)

        boundary = activity_monitor._prune_expired_cpu_pools(
            self._agents_payload(self._cpu_pool(activity_epoch=now - 900), now),
            now_epoch=now,
            activity_cache={},
            current_observation=True,
        )
        self.assertEqual(len(boundary["cpu"]["snapshot"]["pools"]), 1)

        expired = activity_monitor._prune_expired_cpu_pools(
            self._agents_payload(self._cpu_pool(activity_epoch=now - 901), now),
            now_epoch=now,
            activity_cache={},
            current_observation=True,
        )
        self.assertEqual(expired["cpu"]["snapshot"]["pools"], [])
        self.assertEqual(expired["cpu"]["snapshot"]["counts"]["pools"], 0)
        self.assertEqual(expired["cpu"]["snapshot"]["counts"]["live"], 0)

    def test_fresh_live_cpu_pool_is_retained_beyond_stopped_ttl(self):
        now = 1_800_000_000.0
        result = activity_monitor._prune_expired_cpu_pools(
            self._agents_payload(self._cpu_pool(live=1, activity_epoch=now - 10_000), now),
            now_epoch=now,
            activity_cache={},
            current_observation=True,
        )
        self.assertEqual(len(result["cpu"]["snapshot"]["pools"]), 1)
        self.assertFalse(result["cpu"]["snapshot"]["pools"][0]["livenessStale"])

    def test_ordinary_fresh_reads_without_activity_do_not_renew_stopped_pool(self):
        first_observation = 1_800_000_000.0
        cache = {}
        first = activity_monitor._prune_expired_cpu_pools(
            self._agents_payload(self._cpu_pool(activity_epoch=None), first_observation),
            now_epoch=first_observation,
            activity_cache=cache,
            current_observation=True,
        )
        self.assertEqual(len(first["cpu"]["snapshot"]["pools"]), 1)

        repeated_pool = self._cpu_pool(activity_epoch=None)
        repeated_pool["updatedAt"] = self._stamp(first_observation + 901)
        repeated_pool["progress"]["observedAt"] = self._stamp(first_observation + 901)
        repeated = activity_monitor._prune_expired_cpu_pools(
            self._agents_payload(repeated_pool, first_observation + 901),
            now_epoch=first_observation + 901,
            activity_cache=cache,
            current_observation=True,
        )
        self.assertEqual(repeated["cpu"]["snapshot"]["pools"], [])

    def test_registration_derived_retention_does_not_renew_stopped_pool(self):
        first_observation = 1_800_000_000.0
        pool = self._cpu_pool(activity_epoch=None)
        pool["retention"] = {
            "lastActivityAt": self._stamp(first_observation + 901),
            "inactiveForMs": 0,
            "retentionMs": 900_000,
            "expiresAt": self._stamp(first_observation + 1801),
            "visibleByDefault": True,
        }
        result = activity_monitor._prune_expired_cpu_pools(
            self._agents_payload(pool, first_observation + 901),
            now_epoch=first_observation + 901,
            activity_cache={pool["id"]: first_observation},
            current_observation=True,
        )
        self.assertEqual(result["cpu"]["snapshot"]["pools"], [])

    def test_backend_cache_hit_labels_live_count_as_last_observed(self):
        now = 1_800_000_000.0
        pool = self._cpu_pool(live=1, activity_epoch=now - 1)
        payload = self._agents_payload(pool, now - 1)
        activity_monitor.Api._agents_cache = {
            "t": now - 1,
            "body": json.dumps(payload),
            "last_good": payload,
            "cpu_pool_activity": {pool["id"]: now - 1},
        }
        with patch.object(activity_monitor.time, "time", return_value=now), patch.object(
            activity_monitor, "_run_agents_observer", side_effect=AssertionError("cache miss")
        ):
            result = json.loads(activity_monitor.Api().get_agent_activity())
        self.assertEqual(len(result["cpu"]["snapshot"]["pools"]), 1)
        self.assertTrue(result["cpu"]["snapshot"]["pools"][0]["livenessStale"])

    def test_backend_cache_hit_evicts_pool_that_crossed_ttl(self):
        now = 1_800_000_000.0
        pool = self._cpu_pool(activity_epoch=now - 901)
        payload = self._agents_payload(pool, now - 1)
        activity_monitor.Api._agents_cache = {
            "t": now - 1,
            "body": json.dumps(payload),
            "last_good": payload,
            "cpu_pool_activity": {pool["id"]: now - 901},
        }
        with patch.object(activity_monitor.time, "time", return_value=now), patch.object(
            activity_monitor, "_run_agents_observer", side_effect=AssertionError("cache miss")
        ):
            result = json.loads(activity_monitor.Api().get_agent_activity())
        self.assertEqual(result["cpu"]["snapshot"]["pools"], [])

    def test_last_good_exception_fallback_evicts_and_does_not_resurrect_pool(self):
        activity_epoch = 1_800_000_000.0
        api = activity_monitor.Api()
        good = self._agents_payload(self._cpu_pool(activity_epoch=activity_epoch), activity_epoch + 899)
        with patch.object(activity_monitor.time, "time", return_value=activity_epoch + 899), patch.object(
            activity_monitor, "_run_agents_observer", return_value=good
        ), patch.object(activity_monitor, "_collect_ai_processes", return_value=[]):
            first = json.loads(api.get_agent_activity())
        self.assertEqual(len(first["cpu"]["snapshot"]["pools"]), 1)

        for now in (activity_epoch + 901, activity_epoch + 902):
            activity_monitor.Api._agents_cache["t"] = 0.0
            activity_monitor.Api._agents_cache["body"] = None
            with patch.object(activity_monitor.time, "time", return_value=now), patch.object(
                activity_monitor, "_run_agents_observer", side_effect=RuntimeError("observer unavailable")
            ), patch.object(activity_monitor, "_collect_ai_processes", return_value=[]):
                fallback = json.loads(api.get_agent_activity())
            self.assertEqual(fallback["cpu"]["snapshot"]["pools"], [])
            self.assertTrue(fallback["cpu"]["stale"])

    def test_partial_cpu_fallback_evicts_expired_last_good_pool(self):
        activity_epoch = 1_800_000_000.0
        api = activity_monitor.Api()
        good = self._agents_payload(self._cpu_pool(activity_epoch=activity_epoch), activity_epoch + 899)
        with patch.object(activity_monitor.time, "time", return_value=activity_epoch + 899), patch.object(
            activity_monitor, "_run_agents_observer", return_value=good
        ), patch.object(activity_monitor, "_collect_ai_processes", return_value=[]):
            api.get_agent_activity()

        activity_monitor.Api._agents_cache["t"] = 0.0
        activity_monitor.Api._agents_cache["body"] = None
        partial = self._agents_payload(self._cpu_pool(activity_epoch=None), activity_epoch + 901, cpu_ok=False)
        partial["cpu"] = {"ok": False, "snapshot": None, "error": "CPU observer unavailable"}
        with patch.object(activity_monitor.time, "time", return_value=activity_epoch + 901), patch.object(
            activity_monitor, "_run_agents_observer", return_value=partial
        ), patch.object(activity_monitor, "_collect_ai_processes", return_value=[]):
            fallback = json.loads(api.get_agent_activity())
        self.assertEqual(fallback["cpu"]["snapshot"]["pools"], [])
        self.assertTrue(fallback["cpu"]["stale"])

    def test_degraded_observer_does_not_treat_cached_live_count_as_current(self):
        activity_epoch = 1_800_000_000.0
        api = activity_monitor.Api()
        good = self._agents_payload(
            self._cpu_pool(live=1, activity_epoch=activity_epoch), activity_epoch
        )
        good["cpu"]["snapshot"]["discovery"] = {"state": "observed", "mode": "process-list"}
        with patch.object(activity_monitor.time, "time", return_value=activity_epoch), patch.object(
            activity_monitor, "_run_agents_observer", return_value=good
        ), patch.object(activity_monitor, "_collect_ai_processes", return_value=[]):
            first = json.loads(api.get_agent_activity())
        self.assertEqual(len(first["cpu"]["snapshot"]["pools"]), 1)

        activity_monitor.Api._agents_cache["t"] = 0.0
        activity_monitor.Api._agents_cache["body"] = None
        degraded = self._agents_payload(
            self._cpu_pool(live=1, activity_epoch=activity_epoch), activity_epoch + 901
        )
        degraded["cpu"]["snapshot"]["discovery"] = {
            "state": "degraded", "mode": "registered-process-fallback"
        }
        with patch.object(activity_monitor.time, "time", return_value=activity_epoch + 901), patch.object(
            activity_monitor, "_run_agents_observer", return_value=degraded
        ), patch.object(activity_monitor, "_collect_ai_processes", return_value=[]):
            fallback = json.loads(api.get_agent_activity())
        self.assertEqual(fallback["cpu"]["snapshot"]["pools"], [])
        self.assertTrue(fallback["cpu"]["stale"])

    def test_frontend_last_snapshot_fallback_evicts_at_901_and_clears_selection(self):
        activity_epoch = 1_800_000_000.0
        pool = self._cpu_pool(
            activity_epoch=activity_epoch,
            workers=[{"id": "worker-1", "pid": 5001, "state": "exited"}],
        )
        payload = self._agents_payload(pool, activity_epoch)
        payload["cpu"]["snapshot"]["pools"][0]["retention"]["activityMonitorLastVerifiedAt"] = self._stamp(activity_epoch)
        at_899 = self._run_cpu_retention_js(
            payload, activity_epoch + 899, {pool["id"]: "worker-1"}
        )
        self.assertEqual(len(at_899["payload"]["cpu"]["snapshot"]["pools"]), 1)
        self.assertIn(pool["id"], at_899["selection"])

        last_snapshot = at_899["payload"]
        last_snapshot["stale"] = True
        last_snapshot["cpu"]["stale"] = True
        last_snapshot["cpu"]["snapshot"]["pools"][0]["retention"].update({
            "lastActivityAt": self._stamp(activity_epoch + 901),
            "inactiveForMs": 0,
            "expiresAt": self._stamp(activity_epoch + 1801),
        })
        at_901 = self._run_cpu_retention_js(
            last_snapshot, activity_epoch + 901, at_899["selection"]
        )
        self.assertEqual(at_901["payload"]["cpu"]["snapshot"]["pools"], [])
        self.assertEqual(at_901["payload"]["cpu"]["snapshot"]["counts"]["pools"], 0)
        self.assertNotIn(pool["id"], at_901["selection"])

    def test_cpu_sampler_uses_a_real_interval_on_every_bridge_thread(self):
        cpu_times = SimpleNamespace(user=22.0, system=11.0, idle=67.0)
        with patch.object(activity_monitor.psutil, "cpu_percent", return_value=[25.0, 50.0]) as cpu_percent:
            with patch.object(activity_monitor.psutil, "cpu_times_percent", return_value=cpu_times) as cpu_times_percent:
                sample = activity_monitor._sample_cpu_usage()
        cpu_percent.assert_called_once_with(interval=0.1, percpu=True)
        cpu_times_percent.assert_called_once_with(interval=0.1, percpu=False)
        self.assertEqual(sample["per_cpu"], [25.0, 50.0])
        self.assertEqual(sample["percent"], 37.5)
        self.assertEqual(sample["user"], 22.0)

    def test_memory_pressure_uses_macos_reclaimable_headroom(self):
        vm = SimpleNamespace(total=1000, available=250)
        result = SimpleNamespace(
            returncode=0,
            stdout="System-wide memory free percentage: 50%\n",
            stderr="",
        )
        with patch.object(activity_monitor.sys, "platform", "darwin"):
            with patch.object(activity_monitor.subprocess, "run", return_value=result) as run:
                pressure = activity_monitor._memory_pressure_snapshot(vm)
        run.assert_called_once_with(
            ["/usr/bin/memory_pressure", "-Q"],
            capture_output=True,
            text=True,
            timeout=0.75,
            check=False,
        )
        self.assertEqual(pressure["source"], "memory_pressure -Q")
        self.assertEqual(pressure["headroom_percent"], 50.0)
        self.assertEqual(pressure["pressure_percent"], 50.0)
        self.assertEqual(pressure["state"], "normal")

    def test_memory_pressure_falls_back_without_blank_state(self):
        vm = SimpleNamespace(total=1000, available=50)
        result = SimpleNamespace(returncode=1, stdout="", stderr="unavailable")
        with patch.object(activity_monitor.sys, "platform", "darwin"):
            with patch.object(activity_monitor.subprocess, "run", return_value=result):
                pressure = activity_monitor._memory_pressure_snapshot(vm)
        self.assertEqual(pressure["source"], "psutil.available")
        self.assertEqual(pressure["headroom_percent"], 5.0)
        self.assertEqual(pressure["state"], "critical")

    def test_system_identity_is_detected_from_the_current_mac(self):
        activity_monitor._system_identity.cache_clear()
        sysctl = {
            "machdep.cpu.brand_string": "Apple M2 Pro",
            "hw.model": "Mac14,5",
            "sysctl.proc_translated": "0",
            "hw.optional.arm64": "1",
        }
        with patch.object(activity_monitor, "_sysctl_value", side_effect=lambda name: sysctl.get(name)):
            with patch.object(activity_monitor.platform, "system", return_value="Darwin"):
                with patch.object(activity_monitor.platform, "mac_ver", return_value=("14.7", ("", "", ""), "")):
                    with patch.object(activity_monitor.platform, "machine", return_value="arm64"):
                        with patch.object(activity_monitor.psutil, "cpu_count", side_effect=[12, 12]):
                            identity = activity_monitor._system_identity()
        activity_monitor._system_identity.cache_clear()
        self.assertEqual(identity["cpu_model"], "Apple M2 Pro")
        self.assertEqual(identity["machine_model"], "Mac14,5")
        self.assertEqual(identity["logical_cpu_count"], 12)
        self.assertEqual(identity["architecture"], "arm64")
        self.assertEqual(identity["execution_architecture"], "arm64")

    def test_gpu_probe_uses_the_current_mac_model_and_core_count(self):
        fixture = '''+-o AGXAcceleratorG13X <class AGXAcceleratorG13X>
    "model" = "Apple M2 Pro"
    "gpu-core-count" = 19
    "PerformanceStatistics" = {"Device Utilization %"=37,"Renderer Utilization %"=21,"Tiler Utilization %"=4,"In use system memory"=123456789}
    "AGCInfo" = {"fLastSubmissionPID"=2468,"fSubmissionsSinceLastCheck"=3,"fBusyCount"=9}
'''
        probe = activity_monitor._local_gpu_probe(ioreg_text=fixture, profiler_text="{}", system_name="Darwin")
        device = probe["devices"][0]
        self.assertEqual(device["model"], "Apple M2 Pro")
        self.assertEqual(device["coreCount"], 19)
        self.assertEqual(device["utilization"]["percent"], 37.0)
        self.assertEqual(device["memory"]["kind"], "unified")
        self.assertNotIn("M4 Max", json.dumps(probe))

    def test_discrete_mac_gpu_inventory_does_not_pretend_to_be_apple_silicon(self):
        fixture = json.dumps({
            "SPDisplaysDataType": [{
                "_name": "AMD Radeon Pro 5500M",
                "sppci_model": "AMD Radeon Pro 5500M",
                "spdisplays_vendor": "sppci_vendor_AMD",
                "sppci_bus": "spdisplays_pcie_device",
                "spdisplays_vram": "8 GB",
            }]
        })
        probe = activity_monitor._local_gpu_probe(ioreg_text="", profiler_text=fixture, system_name="Darwin")
        device = probe["devices"][0]
        self.assertEqual(device["model"], "AMD Radeon Pro 5500M")
        self.assertIsNone(device["coreCount"])
        self.assertFalse(device["integrated"])
        self.assertEqual(device["memory"]["kind"], "dedicated")
        self.assertEqual(device["memory"]["capacityBytes"], 8 * 1024**3)

    def test_first_launch_without_node_or_worker_plugins_uses_built_in_telemetry(self):
        probe = {
            "available": True,
            "devices": [{
                "id": "gpu_device_0",
                "model": "Apple M3",
                "coreCount": 10,
                "backend": "Metal",
                "integrated": True,
                "utilization": {"scope": "host-wide", "percent": 12.0, "observedAt": "2026-01-01T00:00:00Z"},
                "memory": {"kind": "unified", "inUseBytes": 1},
            }],
            "source": "built-in:test",
            "observedAt": "2026-01-01T00:00:00Z",
            "error": None,
        }
        identity = {
            "os_name": "macOS", "os_version": "15.0", "architecture": "arm64",
            "machine_model": "Mac15,12", "cpu_model": "Apple M3",
            "logical_cpu_count": 8, "physical_cpu_count": 8, "hostname": "another-mac",
            "source": "runtime-detected",
        }
        activity_monitor.Api._agents_cache = {"t": 0.0, "body": None, "last_good": None}
        with patch.object(activity_monitor, "_run_agents_observer", side_effect=FileNotFoundError("node unavailable")):
            with patch.object(activity_monitor, "_local_gpu_probe", return_value=probe):
                with patch.object(activity_monitor, "_system_identity", return_value=identity):
                    payload = json.loads(activity_monitor.Api().get_agent_activity())
        self.assertTrue(payload["builtInFallback"])
        self.assertFalse(payload["stale"])
        self.assertTrue(payload["cpu"]["ok"])
        self.assertTrue(payload["gpu"]["ok"])
        self.assertEqual(payload["gpu"]["snapshot"]["devices"][0]["model"], "Apple M3")
        self.assertNotIn("M4 Max", json.dumps(payload))

    def test_combined_observer_timeout_recovers_fresh_registered_gpu_job(self):
        now = datetime.now(tz=timezone.utc).timestamp()
        prior = self._agents_payload(self._cpu_pool(activity_epoch=now), now)
        prior["builtInFallback"] = False
        activity_monitor.Api._agents_cache = {
            "t": 0.0,
            "body": None,
            "last_good": prior,
            "cpu_pool_activity": {},
        }
        job_pid = 48696
        fresh_gpu = {
            "ok": True,
            "observerVersion": "fixture",
            "snapshot": {
                "jobs": [{
                    "id": "gpu-job-fixture",
                    "pid": job_pid,
                    "childPids": [],
                    "title": "Apple GPU backend optimization",
                    "state": "running",
                    "processAlive": True,
                }],
                "devices": [],
                "hints": [],
                "lane": {"state": "running", "activeCount": 1},
            },
        }
        process = SimpleNamespace(info={
            "pid": job_pid,
            "ppid": 1,
            "name": "python3",
            "username": "alex",
            "cpu_percent": 0,
            "memory_info": SimpleNamespace(rss=4096),
            "memory_percent": 0,
            "num_threads": 2,
            "status": "running",
            "create_time": now - 5,
            "cmdline": ["python3", "benchmark_gpu.py"],
            "uids": None,
        })
        timeout = subprocess.TimeoutExpired(["node", "agents_snapshot.mjs"], 4.0)
        with patch.object(activity_monitor.time, "time", return_value=now), patch.object(
            activity_monitor, "_run_agents_observer", side_effect=timeout
        ), patch.object(
            activity_monitor, "_run_gpu_observer", return_value=fresh_gpu
        ), patch.object(activity_monitor.psutil, "process_iter", return_value=[process]):
            payload = json.loads(activity_monitor.Api().get_agent_activity())

        self.assertTrue(payload["stale"])
        self.assertTrue(payload["partialSnapshot"])
        self.assertTrue(payload["cpu"]["stale"])
        self.assertFalse(payload["gpu"]["stale"])
        self.assertTrue(payload["gpu"]["recoveredIndependently"])
        self.assertEqual(payload["gpu"]["snapshot"]["jobs"][0]["pid"], job_pid)
        by_pid = {row["pid"]: row for row in payload["aiProcesses"]}
        self.assertEqual(by_pid[job_pid]["category"], "GPU job")
        self.assertEqual(by_pid[job_pid]["confidence"], "owner-published")
        self.assertEqual(by_pid[job_pid]["provider"], "Apple GPU backend optimization")

    def test_every_observed_cpu_worker_is_in_ai_processes(self):
        payload = json.loads(activity_monitor.Api().get_agent_activity())
        live_worker_pids = {
            worker["pid"]
            for pool in payload["cpu"]["snapshot"]["pools"]
            for worker in pool.get("workers", [])
            if worker.get("pid") and worker.get("state") != "exited"
        }
        ai_pids = {row["pid"] for row in payload["aiProcesses"]}
        self.assertTrue(live_worker_pids.issubset(ai_pids))

    def test_worker_exit_between_observer_and_process_census_fails_closed(self):
        now_epoch = datetime.now(tz=timezone.utc).timestamp()
        pool = self._cpu_pool(
            live=2,
            activity_epoch=now_epoch,
            workers=[
                {"id": "worker-live", "pid": 41001, "state": "busy", "cpuPercent": 8.0, "rssBytes": 1000},
                {"id": "worker-exited", "pid": 41002, "state": "busy", "cpuPercent": 4.0, "rssBytes": 500},
            ],
        )
        pool["totals"].update({"cpuPercent": 12.0, "rssBytes": 1500})
        observed = self._agents_payload(pool, now_epoch)
        census = [{"pid": 41001, "category": "CPU worker"}]
        with patch.object(activity_monitor, "_run_agents_observer", return_value=observed):
            with patch.object(activity_monitor, "_collect_ai_processes", return_value=census):
                payload = json.loads(activity_monitor.Api().get_agent_activity())

        workers = payload["cpu"]["snapshot"]["pools"][0]["workers"]
        by_pid = {worker["pid"]: worker for worker in workers}
        totals = payload["cpu"]["snapshot"]["pools"][0]["totals"]
        self.assertEqual(by_pid[41001]["state"], "busy")
        self.assertEqual(by_pid[41002]["state"], "exited")
        self.assertEqual(
            by_pid[41002]["livenessReconciled"],
            "absent-from-same-response-process-census",
        )
        self.assertEqual(totals["live"], 1)
        self.assertEqual(totals["busy"], 1)
        self.assertEqual(totals["cpuPercent"], 8.0)
        self.assertEqual(totals["rssBytes"], 1000)
        self.assertEqual(payload["cpu"]["processCensusReconciledWorkers"], 1)
        live_worker_pids = {
            worker["pid"]
            for worker in workers
            if worker.get("pid") and worker.get("state") != "exited"
        }
        self.assertEqual(live_worker_pids, {41001})
        self.assertTrue(live_worker_pids.issubset({row["pid"] for row in payload["aiProcesses"]}))

    def test_core_inspector_uses_coactivity_without_claiming_placement(self):
        payload = json.loads(activity_monitor.Api().get_agent_activity())
        attribution = payload["cpuCoreAttribution"]
        self.assertEqual(attribution["scope"], "sampled-coactivity")
        self.assertFalse(attribution["exactPlacementAvailable"])
        self.assertIn("does not expose", attribution["boundary"])
        html = activity_monitor.HTML
        self.assertIn('id="agents-core-inspector"', html)
        self.assertIn("selectAgentCore", html)
        self.assertIn("recordCoreActivity", html)
        self.assertIn("coreCoactivity", html)
        self.assertIn("CORE_COACTIVITY_MIN_SAMPLES", html)
        self.assertIn("placement unclaimed", html)

    def test_transient_observer_failure_retains_last_good_snapshot(self):
        api = activity_monitor.Api()
        good = {
            "schemaVersion": "ke.activity-monitor-agents.v1",
            "generatedAt": "2026-01-01T00:00:00Z",
            "cpu": {"ok": True, "snapshot": {"pools": [], "host": {}}},
            "gpu": {"ok": True, "snapshot": {"jobs": [], "devices": [], "hints": [], "lane": {}}},
        }
        with patch.object(activity_monitor, "_run_agents_observer", return_value=good):
            first = json.loads(api.get_agent_activity())
        self.assertFalse(first["stale"])
        activity_monitor.Api._agents_cache["t"] = 0.0
        activity_monitor.Api._agents_cache["body"] = None
        with patch.object(activity_monitor, "_run_agents_observer", side_effect=RuntimeError("observer unavailable")):
            second = json.loads(api.get_agent_activity())
        self.assertTrue(second["stale"])
        self.assertIsNotNone(second["cpu"]["snapshot"])
        self.assertIsNotNone(second["gpu"]["snapshot"])
        self.assertIn("unavailable", second["error"].lower())

    def test_process_classification_keeps_evidence_levels_distinct(self):
        cpu = {123: {"label": "Worker 123", "pool": "Test pool", "registered": True, "state": "busy"}}
        worker = activity_monitor._classify_ai_process("Python", "python workload.py", 123, cpu, {})
        runtime = activity_monitor._classify_ai_process("Claude", "/Applications/Claude.app/Claude", 456, {}, {})
        ordinary = activity_monitor._classify_ai_process("Finder", "/System/Library/CoreServices/Finder.app", 789, {}, {})
        self.assertEqual(worker["confidence"], "observed-worker")
        self.assertEqual(runtime["confidence"], "runtime-match")
        self.assertIsNone(ordinary)

    def test_ai_process_collection_does_not_truncate_matches(self):
        processes = []
        for pid in range(1000, 1600):
            info = {
                "pid": pid,
                "ppid": 1,
                "name": "codex",
                "username": "alex",
                "cpu_percent": 0,
                "memory_info": SimpleNamespace(rss=1),
                "memory_percent": 0,
                "num_threads": 1,
                "status": "sleeping",
                "create_time": 1,
                "cmdline": ["codex"],
                "uids": None,
            }
            processes.append(SimpleNamespace(info=info))
        with patch.object(activity_monitor.psutil, "process_iter", return_value=processes):
            rows = activity_monitor._collect_ai_processes({})
        self.assertEqual(len(rows), 600)

    def test_ai_process_filter_matches_an_exact_pid(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        start = script.index("function aiProcessMatches")
        end = script.index("function renderAiProcesses", start)
        fixture = script[start:end]
        fixture += "\nconst row={pid:48696,name:'python3',provider:'GPU owner',category:'GPU job'};"
        fixture += "\nprocess.stdout.write(JSON.stringify({pid:aiProcessMatches(row,'48696'),missing:aiProcessMatches(row,'99999')}));"
        completed = subprocess.run(
            ["node", "-e", fixture],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=8,
        )
        matches = json.loads(completed.stdout)
        self.assertTrue(matches["pid"])
        self.assertFalse(matches["missing"])

    def test_fresh_gpu_is_not_labeled_as_a_wholly_stale_snapshot(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        start = script.index("function agentFreshnessState")
        end = script.index("function renderAgents", start)
        fixture = script[start:end]
        fixture += "\nconst state=agentFreshnessState({stale:true,observedAt:'2026-08-20T22:00:00Z',generatedAt:'2026-08-20T21:59:00Z',cpu:{stale:true},gpu:{stale:false}});"
        fixture += "\nprocess.stdout.write(JSON.stringify(state));"
        completed = subprocess.run(
            ["node", "-e", fixture],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=8,
        )
        state = json.loads(completed.stdout)
        self.assertEqual(state["label"], "Partial · GPU live · CPU retained")
        self.assertEqual(state["observedAt"], "2026-08-20T22:00:00Z")

    def test_html_uses_a_stable_agents_tab_not_an_auto_hiding_strip(self):
        html = activity_monitor.HTML
        self.assertIn('data-tab="agents"', html)
        self.assertIn('id="agents-tab"', html)
        self.assertIn("CPU by logical core", html)
        self.assertIn("AI processes", html)
        self.assertIn('id="agents-gpu-history"', html)
        self.assertIn('id="agents-gpu-now"', html)
        self.assertIn('id="agents-gpu-peak"', html)
        self.assertIn('id="agents-gpu-memory"', html)
        self.assertIn('id="agents-gpu-memory-label"', html)
        self.assertIn('id="agents-memory-dial"', html)
        self.assertIn('id="agents-memory-headroom"', html)
        self.assertIn('id="agents-memory-swap"', html)
        self.assertNotIn('id="agents-memory-history"', html)
        self.assertNotIn("memory-pressure-bar", html)
        self.assertIn("paintPressureGauge", html)
        self.assertIn("renderMemoryPressure", html)
        self.assertIn("lastValidAgentMemory", html)
        self.assertIn("'no registered jobs'", html)
        self.assertIn("Active registered jobs", html)
        self.assertNotIn("No GPU jobs are registered. Host-wide GPU activity", html)
        self.assertIn("refreshInFlight", html)
        self.assertIn("agentProcessRows", html)
        self.assertIn("patchMarkup", html)
        self.assertIn("const AGENT_PROCESS_MISS_GRACE = 10", html)
        self.assertIn("CORE_RECENT_ACTIVITY_SAMPLES", html)
        self.assertIn("CORE_CONTRIBUTOR_SESSION_RETENTION", html)
        self.assertIn("GPU_UTILIZATION_HISTORY_LENGTH = 20", html)
        self.assertIn("GPU_SMOOTHING_WINDOW = 5", html)
        self.assertIn("renderGpuHistory", html)
        self.assertIn("Whole-run progress", html)
        self.assertIn('role="progressbar"', html)
        self.assertIn("lastValidGpuDevice", html)
        self.assertIn("stabilizeAgentSystemData", html)
        self.assertNotIn("agent-process-grace{opacity:.68}", html)
        self.assertNotIn('id="agents-gpu-note"', html)
        self.assertNotIn('class="gpu-scope-note"', html)
        self.assertNotIn("Apple M4 Max", html)
        self.assertNotIn("Apple GPU / MPS lane", html)
        self.assertIn("systemData?.system?.cpu_model", html)
        self.assertIn("aria-pressed", html)
        self.assertNotIn("kw-panel", html)
        self.assertNotIn("renderKwPanel", html)
        self.assertNotIn("get_cpu_workers", html)
        self.assertNotIn("setInterval(refreshAll", html)
        self.assertNotIn("panel.style.display", html)
        self.assertNotIn("body.innerHTML = filtered.map", html)
        self.assertNotIn("agents-kicker", html)
        self.assertNotIn("agents-subtitle", html)
        self.assertNotIn("core-click-hint", html)
        self.assertNotIn("agent-section-copy", html)
        self.assertNotIn("agents-boundary", html)
        self.assertIn("grid-template-columns:max-content max-content", html)
        self.assertIn("memory-detail-section{flex:0 0 270px}", html)

    def test_energy_tab_is_never_born_as_an_empty_surface(self):
        html = activity_monitor.HTML
        self.assertIn('id="energy-tbody"><tr class="energy-state-row loading"', html)
        self.assertIn("Loading current energy activity…", html)
        self.assertIn("function renderEnergyUnavailable()", html)
        self.assertIn("if (currentTab === 'energy') showEnergyLoading();", html)
        self.assertIn("if (requestedTab === 'energy') renderEnergyUnavailable();", html)

    def test_energy_renderer_normalizes_bad_samples_and_retains_last_good_rows(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        start = script.index("function energyNumber")
        end = script.index("function renderDiskTable", start)
        fixture = """
const nodes = {
  'energy-tbody': {innerHTML:'', dataset:{}},
  'energy-total': {textContent:'--', title:''},
  'energy-bar-chart': {innerHTML:''},
};
const document = {getElementById: id => nodes[id]};
let energyHistory = [];
let lastEnergyProcesses = [];
let searchFilter = '';
const sortState = {energy:{key:'energy_impact',dir:'desc'}};
function sortProcs(procs,key,dir){return procs.sort((a,b)=>dir==='desc'?b[key]-a[key]:a[key]-b[key]);}
function filterProcs(procs){return procs;}
function esc(value){return String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
""" + script[start:end] + """
showEnergyLoading();
const loading = nodes['energy-tbody'].innerHTML;
const total = renderEnergyTable([
  {name:'<bad>',energy_impact:null,avg_energy_impact:'nope',app_nap:null,preventing_sleep:null,pid:'bad'},
  {name:'Worker',energy_impact:12.5,avg_energy_impact:10,app_nap:'Yes',preventing_sleep:'No',pid:42},
]);
const rendered = nodes['energy-tbody'].innerHTML;
renderEnergyUnavailable();
const retained = nodes['energy-tbody'].innerHTML;
const retainedTitle = nodes['energy-total'].title;
lastEnergyProcesses = [];
nodes['energy-tbody'].innerHTML = '';
renderEnergyUnavailable();
process.stdout.write(JSON.stringify({loading,total,rendered,retained,retainedTitle,unavailable:nodes['energy-tbody'].innerHTML,totalState:nodes['energy-total'].textContent}));
"""
        completed = subprocess.run(
            ["node", "-e", fixture],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=8,
        )
        result = json.loads(completed.stdout)
        self.assertIn("Loading current energy activity", result["loading"])
        self.assertEqual(result["total"], 12.5)
        self.assertIn("&lt;bad&gt;", result["rendered"])
        self.assertNotIn("NaN", result["rendered"])
        self.assertEqual(result["retained"], result["rendered"])
        self.assertIn("last complete sample", result["retainedTitle"])
        self.assertIn("temporarily unavailable", result["unavailable"])
        self.assertEqual(result["totalState"], "Unavailable")

    def test_one_unreadable_process_cannot_blank_the_energy_snapshot(self):
        base_info = {
            "username": "alex",
            "cpu_percent": 4.0,
            "memory_info": SimpleNamespace(rss=1024),
            "memory_percent": 0.1,
            "num_threads": 2,
            "status": "running",
            "create_time": 1,
        }

        class Process:
            def __init__(self, pid, name, unreadable=False):
                self.info = {**base_info, "pid": pid, "name": name}
                self.unreadable = unreadable

            def io_counters(self):
                return SimpleNamespace(read_bytes=1, write_bytes=2, read_count=3, write_count=4)

            def net_connections(self, kind):
                if self.unreadable:
                    raise OSError("process counters changed")
                return []

        processes = [Process(41, "Unreadable", True), Process(42, "Worker")]
        api = object.__new__(activity_monitor.Api)
        with patch.object(activity_monitor.psutil, "process_iter", return_value=processes):
            result = json.loads(api.get_processes("energy"))

        self.assertEqual([row["pid"] for row in result["processes"]], [42])
        self.assertEqual(result["processes"][0]["energy_impact"], 2.0)

    def test_packaging_uses_the_stethoscope_icon_master(self):
        script = (ROOT / "package_app.zsh").read_text()
        spec = (ROOT / "activity_monitor.spec").read_text()
        icon_path = ROOT / "assets" / "AppIcon-1024.png"
        icon = icon_path.read_bytes()
        self.assertTrue(icon_path.is_file())
        self.assertEqual(icon[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(icon[12:16], b"IHDR")
        self.assertEqual(struct.unpack(">II", icon[16:24]), (1024, 1024))
        self.assertEqual(icon[24], 8)
        self.assertEqual(icon[25], 6)
        self.assertEqual(
            hashlib.sha256(icon).hexdigest(),
            "987e3ce7982ca91ae9c996f04648d6b427419ee09453681ec2c6ee0d475abffc",
        )
        self.assertIn("assets/AppIcon-1024.png", script)
        self.assertIn("iconutil -c icns", script)
        self.assertIn("PyInstaller", script)
        self.assertIn("universal2", script)
        self.assertIn("self-test-x86_64.json", script)
        self.assertIn("Activity-Monitor-$release_version-mac-$target_arch.zip", script)
        self.assertNotIn("/usr/bin/arch -arm64 /usr/bin/python3", script)
        self.assertIn('bundle_identifier="com.kestudios.activity-monitor"', spec)
        self.assertIn('(os.path.join(ROOT, "activity_monitor.py"), "source")', spec)
        self.assertIn('(os.path.join(ROOT, "brain_discovery.py"), "source")', spec)
        self.assertIn('(os.path.join(ROOT, "dispatch_router.py"), "source")', spec)
        self.assertIn('(os.path.join(ROOT, "ke_wizard_launcher.py"), "source")', spec)
        self.assertIn('(os.path.join(ROOT, "project_brains.py"), "source")', spec)
        self.assertIn("ke_wizard_launcher.py", script)
        self.assertIn(
            'cmp ke_wizard_launcher.py "$bundle/Contents/Resources/source/ke_wizard_launcher.py"',
            script,
        )
        self.assertIn('(os.path.join(ROOT, "agents_snapshot.mjs"), ".")', spec)
        self.assertIn("setApplicationIconImage_", (ROOT / "activity_monitor.py").read_text())

    def test_conversation_host_bridge_preserves_generation_phase_and_body_privacy(self):
        class Host:
            def __init__(self):
                self.project_calls = []
                self.conversation_calls = []

            @staticmethod
            def project_state(provider, project_id):
                return {
                    "ok": True,
                    "project": {"provider": provider, "id": project_id, "name": "PowerSwarm"},
                    "agents": {},
                    "queue": [],
                    "privacy": {"receiptsDigestOnly": True},
                }

            @staticmethod
            def read_conversation(provider, conversation_id):
                return {
                    "ok": True,
                    "provider": provider,
                    "conversationId": conversation_id,
                    "items": [{"role": "assistant", "text": "Visible only after the explicit read."}],
                    "privacy": {"transcriptBodyRead": True},
                }

            def submit(self, provider, project_id, message, request_id):
                self.project_calls.append((provider, project_id, message, request_id))
                return {
                    "ok": True,
                    "destination": {
                        "provider": "codex",
                        "id": "01a020e9-c953-70d0-b86b-eb2e49f45cf5",
                        "title": "PowerSwarm · Activity Monitor",
                    },
                    "receipt": {
                        "requestId": request_id,
                        "state": "accepted",
                        "deliveryAttempted": True,
                        "retrySafe": False,
                        "reconciliationRequired": False,
                    },
                    "privacy": {"queuedMessageBodiesPersistedByActivityMonitor": False},
                }

            def send_conversation(self, provider, conversation_id, message, request_id):
                self.conversation_calls.append((provider, conversation_id, message, request_id))
                raise activity_monitor.ConversationHostError(
                    "receipt_pending",
                    "Delivery may have crossed the exact transport boundary",
                    phase="uncertain after send",
                    delivery_attempted=True,
                    retry_safe=False,
                    reconciliation_required=True,
                    receipt={"requestId": request_id, "state": "uncertain after send"},
                )

            @staticmethod
            def reconcile_request(request_id):
                return {
                    "ok": False,
                    "state": "uncertain after send",
                    "receipt": {"requestId": request_id, "reconciliationRequired": True},
                    "privacy": {"receiptsDigestOnly": True},
                }

        host = Host()
        api = activity_monitor.Api(
            brain_service=object(), dispatch_service=object(), guard_service=object(),
            workspace_service=object(), memory_diagnostics_service=object(), network_service=object(),
            internet_optimizer_service=object(), powerswarm_service=object(), flagship_bridge=object(),
            cleanup_service=object(), conversation_host_service=host,
        )
        request_id = "28a020e9-c953-40d0-886b-eb2e49f45cf5"
        body = "PRIVATE rapid PowerSwarm follow-up"
        raw = api.send_project_conductor(
            "codex", "local-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", body, request_id, 17, "powerswarm"
        )
        result = json.loads(raw)
        self.assertTrue(result["ok"])
        self.assertEqual(result["generation"], 17)
        self.assertEqual(len(host.project_calls), 1)
        self.assertEqual(host.project_calls[0][2], "PowerSwarm request:\n\n" + body)
        self.assertNotIn(body, raw)

        conflict = json.loads(api.send_project_conductor(
            "codex", "local-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", body, request_id, 18, "powerswarm"
        ))
        self.assertFalse(conflict["ok"])
        self.assertEqual(conflict["code"], "request_generation_conflict")
        self.assertTrue(conflict["reconciliationRequired"])
        self.assertFalse(conflict["retrySafe"])
        self.assertEqual(len(host.project_calls), 1)

        uncertain_id = "38a020e9-c953-40d0-886b-eb2e49f45cf5"
        uncertain_raw = api.send_hosted_conversation(
            "codex", "01a020e9-c953-70d0-b86b-eb2e49f45cf5", "another private body", uncertain_id, 19
        )
        uncertain = json.loads(uncertain_raw)
        self.assertFalse(uncertain["ok"])
        self.assertEqual(uncertain["phase"], "uncertain after send")
        self.assertTrue(uncertain["deliveryAttempted"])
        self.assertFalse(uncertain["retrySafe"])
        self.assertTrue(uncertain["reconciliationRequired"])
        self.assertNotIn("another private body", uncertain_raw)

        read = json.loads(api.read_hosted_conversation(
            "codex", "01a020e9-c953-70d0-b86b-eb2e49f45cf5", 20
        ))
        self.assertTrue(read["ok"])
        self.assertEqual(read["generation"], 20)
        self.assertTrue(read["privacy"]["transcriptBodyRead"])

    def test_conversation_host_reuses_dispatch_private_claude_bridge(self):
        class Dispatch:
            def __init__(self, error=None):
                self.error = error
                self.calls = []

            def _send_claude(self, target, message, diagnostic):
                self.calls.append((target, message, diagnostic))
                if self.error:
                    raise self.error
                return "queued", {
                    "socketWritten": True,
                    "transcriptObserved": False,
                    "msgId": "48a020e9-c953-40d0-886b-eb2e49f45cf5",
                    "deliveryAttempted": True,
                    "retrySafe": False,
                    "reconciliationRequired": True,
                }

        dispatch = Dispatch()
        api = object.__new__(activity_monitor.Api)
        api._dispatch_service = dispatch
        receipt = api._send_hosted_claude(
            {"id": "f91d84b7-a732-4e94-bd32-1c87ec9c273f"}, "hello", "58a020e9-c953-40d0-886b-eb2e49f45cf5"
        )
        self.assertTrue(receipt["socketWritten"])
        self.assertEqual(dispatch.calls[0][2], False)

        dispatch.error = activity_monitor.DispatchError(
            "claude_receipt_pending", "receipt pending", phase="exact-session delivery",
            delivery_attempted=True,
            receipt={"deliveryAttempted": True, "retrySafe": False, "reconciliationRequired": True},
        )
        with self.assertRaises(activity_monitor.ConversationHostError) as raised:
            api._send_hosted_claude({}, "hello", "68a020e9-c953-40d0-886b-eb2e49f45cf5")
        self.assertTrue(raised.exception.delivery_attempted)
        self.assertFalse(raised.exception.retry_safe)
        self.assertTrue(raised.exception.reconciliation_required)

    def test_conversation_host_ui_contract_and_source_parity_are_complete(self):
        html = activity_monitor.HTML
        for marker in (
            'id="workspace-host-native"', 'id="workspace-host-activity"',
            'id="conversation-host"', 'aria-modal="true"', 'id="conversation-host-input"',
            'data-route-kind="conductor"', 'data-route-kind="powerswarm"',
            "pywebview.api.get_project_conversation_host", "pywebview.api.read_hosted_conversation",
            "pywebview.api.send_project_conductor", "pywebview.api.send_hosted_conversation",
            "pywebview.api.reconcile_hosted_request", "conversationHostNewRequestId",
            "request.generation", "event.metaKey || event.ctrlKey", "conversationHostClose",
            "text.textContent = request.body", "Delivery may have occurred. Retry is disabled",
            "Delivery did not start", "workspace-project-toggle",
        ):
            self.assertIn(marker, html)
        self.assertNotIn("innerHTML = request.body", html)
        host_source = (ROOT / "activity_monitor.py").read_text(encoding="utf-8")
        host_start = host_source.index("function conversationHostNextGeneration")
        host_end = host_source.index("function workspaceApplyPreferences", host_start)
        self.assertNotIn("localStorage", host_source[host_start:host_end])
        spec = (ROOT / "activity_monitor.spec").read_text(encoding="utf-8")
        package = (ROOT / "package_app.zsh").read_text(encoding="utf-8")
        self.assertIn('(os.path.join(ROOT, "conversation_host.py"), "source")', spec)
        compile_line = next(line for line in package.splitlines() if " -m py_compile " in line)
        self.assertIn("conversation_host.py", compile_line)
        self.assertIn('cmp conversation_host.py "$bundle/Contents/Resources/source/conversation_host.py"', package)

    def test_conversation_host_renders_and_operates_at_960_by_680_headlessly(self):
        chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        if not chrome.is_file():
            self.skipTest("system Chrome is unavailable for the required headless render")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright is unavailable for the required headless render")

        project_id = "local-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        conversation_id = "01a020e9-c953-70d0-b86b-eb2e49f45cf5"
        payload = {
            "ok": True,
            "preferences": {
                "railCollapsed": False, "railWidth": 252, "expandedProjectIds": [],
                "providerFilters": {"codex": True, "claude": True}, "lastSelected": None,
            },
            "counts": {"projects": 1, "conversations": 1, "active": 1},
            "companions": {
                "codex": {"exactOpenAvailable": True, "version": "test"},
                "claude": {"exactOpenAvailable": False, "remediation": "Optional"},
            },
            "projects": [{
                "id": project_id, "provider": "codex", "name": "Activity Monitor",
                "conversationCount": 1, "activeCount": 1, "pinned": True,
                "brainId": "brain_project_test", "brainStatus": "ready", "brainLifecycleState": "active",
                "conversations": [{
                    "id": conversation_id, "provider": "codex", "title": "Project Conductor",
                    "state": "active", "stateSource": "Agent Operations Board", "canOpen": True,
                    "depth": 0, "pinned": True,
                }],
            }],
            "availableCodexProjects": [], "availableClaudeProjects": [], "warnings": [],
        }
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=str(chrome), headless=True)
            page = browser.new_page(viewport={"width": 960, "height": 680}, device_scale_factor=1)
            page.set_content(activity_monitor.HTML, wait_until="domcontentloaded")
            page.evaluate("""payload => {
                window.__hostCalls = {sends:[], reads:[], native:[]};
                window.__workspacePayload = payload;
                window.pywebview = {api:{
                    get_workspace_state: async () => JSON.stringify(window.__workspacePayload),
                    update_workspace_preferences: async patch => JSON.stringify({ok:true,preferences:{...payload.preferences,...patch}}),
                    get_project_conversation_host: async (provider, projectId) => JSON.stringify({
                        ok:true, project:{provider,id:projectId,name:'Activity Monitor'}, agents:{}, queue:[],
                        privacy:{receiptsDigestOnly:true}
                    }),
                    read_hosted_conversation: async (provider, conversationId, generation) => {
                        window.__hostCalls.reads.push([provider,conversationId,generation]);
                        return JSON.stringify({ok:true,provider,conversationId,generation,title:'Project Conductor',items:[
                            {id:'u1',role:'user',text:'Exact user message'},
                            {id:'a1',role:'assistant',text:'Exact assistant response'}
                        ],privacy:{transcriptBodyRead:true}});
                    },
                    send_project_conductor: async (provider, projectId, message, requestId, generation, routeKind) => {
                        window.__hostCalls.sends.push([provider,projectId,message,requestId,generation,routeKind]);
                        return JSON.stringify({ok:true,generation,destination:{provider:'codex',id:'01a020e9-c953-70d0-b86b-eb2e49f45cf5',title:'Conductor · Activity Monitor'},receipt:{requestId,state:'accepted',deliveryAttempted:true,retrySafe:false,reconciliationRequired:false}});
                    },
                    send_hosted_conversation: async (provider, conversationId, message, requestId, generation) => JSON.stringify({ok:true,generation,receipt:{requestId,state:'accepted',deliveryAttempted:true,retrySafe:false,reconciliationRequired:false}}),
                    reconcile_hosted_request: async (requestId,generation) => JSON.stringify({ok:true,generation,receipt:{requestId,state:'transcript observed'}}),
                    open_workspace_conversation: async (provider,conversationId) => {window.__hostCalls.native.push([provider,conversationId]); return JSON.stringify({ok:true});},
                }};
                apiReady = true;
                workspaceSnapshot = payload;
                workspaceExpanded = new Set();
                renderWorkspace(payload);
            }""", payload)

            project_button = page.locator(".workspace-project-button")
            project_button.focus()
            project_button.press("ArrowRight")
            page.wait_for_function("document.querySelector('.workspace-project').classList.contains('expanded')")
            project_button = page.locator(".workspace-project-button")
            project_button.click()
            page.wait_for_selector("#conversation-host:not([hidden])")
            page.wait_for_selector(".conversation-host-empty")
            self.assertEqual(page.locator("#workspace-host-activity").get_attribute("aria-pressed"), "true")
            self.assertEqual(page.locator(".workspace-project-brain").text_content(), "Brain")

            rail_box = page.locator("#workspace-rail").bounding_box()
            host_box = page.locator("#conversation-host").bounding_box()
            composer_box = page.locator(".conversation-host-composer").bounding_box()
            body_box = page.locator(".conversation-host-body").bounding_box()
            deck_box = page.locator(".conversation-host-empty").bounding_box()
            self.assertGreaterEqual(rail_box["width"], 220)
            self.assertGreaterEqual(host_box["x"], rail_box["width"] - 3)
            self.assertLessEqual(host_box["x"] + host_box["width"], 960.5)
            self.assertLessEqual(composer_box["y"] + composer_box["height"], 680.5)
            top_gap = deck_box["y"] - body_box["y"]
            bottom_gap = body_box["y"] + body_box["height"] - composer_box["y"] - composer_box["height"]
            self.assertLess(abs(top_gap - bottom_gap), 28)
            self.assertEqual(page.locator("#conversation-host").get_attribute("role"), "dialog")
            self.assertEqual(page.locator("#conversation-host").get_attribute("aria-modal"), "true")
            self.assertEqual(page.locator("#workspace-summary span").nth(1).text_content(), "1 project · 1 task")
            self.assertEqual(page.locator("#workspace-summary strong").text_content(), "1 active")
            self.assertEqual(page.locator(".workspace-conversation").locator(":scope > *").count(), 2)
            self.assertNotIn("Agent Operations Board", page.locator(".workspace-conversation").inner_text())
            self.assertGreaterEqual(float(page.locator("#workspace-codex-companion").evaluate("node => parseFloat(getComputedStyle(node).fontSize)")), 10)
            self.assertEqual(page.locator(".workspace-privacy").count(), 0)
            screenshot_path = os.environ.get("ACTIVITY_MONITOR_HEADLESS_SCREENSHOT")
            if screenshot_path:
                page.screenshot(path=screenshot_path, full_page=False)

            composer = page.locator("#conversation-host-input")
            composer.fill("first rapid request")
            composer.press("Meta+Enter")
            composer.fill("second rapid request")
            page.locator("#conversation-host-send").click()
            page.wait_for_function("window.__hostCalls.sends.length === 2")
            calls = page.evaluate("window.__hostCalls.sends")
            self.assertNotEqual(calls[0][3], calls[1][3])
            self.assertEqual(calls[0][4], calls[1][4])
            self.assertEqual([call[2] for call in calls], ["first rapid request", "second rapid request"])
            self.assertNotIn("project-home", page.locator("#conversation-host").get_attribute("class"))
            page.locator('[data-route-kind="powerswarm"]').click()
            composer.fill("parallelize this safely")
            page.locator("#conversation-host-send").click()
            page.wait_for_function("window.__hostCalls.sends.length === 3")
            self.assertEqual(page.evaluate("window.__hostCalls.sends[2][5]"), "powerswarm")

            page.keyboard.press("Escape")
            self.assertTrue(page.locator("#conversation-host").is_hidden())
            self.assertEqual(page.evaluate("document.activeElement?.dataset?.projectButton"), project_id)

            page.locator("#workspace-host-activity").click()
            page.locator(".workspace-project-button").press("ArrowRight")
            page.locator(".workspace-conversation").click()
            page.wait_for_selector("#conversation-host:not([hidden])")
            page.wait_for_selector("text=Exact assistant response")
            self.assertEqual(page.evaluate("window.__hostCalls.reads.length"), 1)
            page.keyboard.press("Escape")

            page.locator("#workspace-host-native").click()
            if not page.locator(".workspace-project").get_attribute("class").endswith("expanded"):
                page.locator(".workspace-project-button").press("ArrowRight")
            page.locator(".workspace-conversation").click()
            page.wait_for_function("window.__hostCalls.native.length === 1")
            self.assertTrue(page.locator("#conversation-host").is_hidden())

            page.locator("#workspace-manage").click()
            self.assertFalse(page.locator("#workspace-dialog").is_hidden())
            page.keyboard.press("Escape")
            self.assertTrue(page.locator("#workspace-dialog").is_hidden())
            browser.close()

    def test_embedded_javascript_parses(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            result = subprocess.run(
                ["node", "--check", path],
                text=True,
                capture_output=True,
                timeout=8,
            )
        finally:
            os.unlink(path)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
