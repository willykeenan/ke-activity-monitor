import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import activity_monitor  # noqa: E402
import powerswarm_discovery  # noqa: E402
from powerswarm_discovery import PowerSwarmService, SCHEMA_VERSION  # noqa: E402


RUN_A = "director_swarm_run_11111111111111111111"
RUN_B = "director_swarm_run_22222222222222222222"
RUN_C = "director_swarm_run_33333333333333333333"


def attempt(number, status, pid, *, check=None, ended=False, stage="speedDev"):
    payload = {
        "attempt": number,
        "status": status,
        "pid": pid,
        "startedAt": "2026-08-20T20:00:00Z",
        "endedAt": "2026-08-20T20:05:00Z" if ended else None,
        "exitCode": 0 if ended else None,
    }
    if check:
        payload["killCheck"] = {"status": check, "exitCode": 0 if check == "succeeded" else 1}
    return payload


def target(identifier, status="queued", attempts=None, *, aim=None):
    return {
        "targetId": identifier,
        "aim": aim or f"Own {identifier}",
        "status": status,
        "branch": f"powerswarm/test/{identifier}",
        "worktreePath": f"/tmp/{identifier}",
        "baseRevision": "a" * 40,
        "headRevision": "b" * 40,
        "stages": {
            "speedDev": {"status": status, "attempts": attempts or []},
            "bugSweep": {"status": "not-started", "attempts": []},
        },
    }


def run_record(run_id, status, updated_at, targets, coordinator_pid=None):
    return {
        "schemaVersion": "2.0.0",
        "runId": run_id,
        "status": status,
        "createdAt": "2026-08-20T19:59:00Z",
        "updatedAt": updated_at,
        "coordinator": {"pid": coordinator_pid, "startedAt": "2026-08-20T19:59:30Z"},
        "limits": {"runConcurrency": 4},
        "runtime": {"runtime": "grok-build"},
        "plan": {
            "planId": "director_swarm_plan_aaaaaaaaaaaaaaaaaaaa",
            "objective": f"Objective for {run_id}",
            "product": {"productId": "fixture-product"},
            "topology": {"maxDepth": 1},
        },
        "targets": targets,
    }


def nested_plan(record, subdirectors):
    return {
        "schemaVersion": "1.0.0",
        "planId": "director_swarm_central_plan_aaaaaaaaaaaaaaaaaaaa",
        "contract": "ke.director.powerswarm-central-recursion.v1",
        "topology": {
            "logicalDepth": 2,
            "processSpawnDepth": 1,
            "rootOnlyProcessSpawn": True,
        },
        "subdirectors": subdirectors,
        "executionPlan": {"planId": record["plan"]["planId"]},
    }


class PowerSwarmDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runs = self.root / "runs"
        self.bindings = self.root / "bindings"
        self.runs.mkdir()
        self.bindings.mkdir()
        self.live_pids = set()

    def tearDown(self):
        self.temporary.cleanup()

    def service(self):
        return PowerSwarmService(
            self.runs,
            self.bindings,
            process_probe=lambda pid, _started_at: pid in self.live_pids,
            cache_seconds=0,
        )

    def write_run(self, record):
        directory = self.runs / record["runId"]
        directory.mkdir()
        (directory / "run.json").write_text(json.dumps(record))
        return directory

    def test_no_history_is_a_calm_truthful_state(self):
        payload = self.service().snapshot()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["schemaVersion"], SCHEMA_VERSION)
        self.assertEqual(payload["state"], "no-runs")
        self.assertEqual(payload["counts"]["live"], 0)
        self.assertEqual(payload["processes"], [])
        self.assertFalse(payload["privacy"]["mutations"])

    def test_auto_selection_prefers_a_real_active_run_over_newer_history(self):
        historical = run_record(
            RUN_A,
            "review-ready",
            "2026-08-20T21:00:00Z",
            [target("done", "review-ready", [attempt(1, "succeeded", 501, check="succeeded", ended=True)])],
        )
        active = run_record(
            RUN_B,
            "speed-dev",
            "2026-08-20T20:30:00Z",
            [target("live-leaf", "speed-dev", [attempt(1, "running", 601)])],
            coordinator_pid=600,
        )
        self.write_run(historical)
        self.write_run(active)
        self.live_pids.update({600, 601})

        payload = self.service().snapshot()

        self.assertEqual(payload["selectedRun"]["id"], RUN_B)
        self.assertEqual(payload["counts"]["live"], 1)
        self.assertEqual({row["pid"] for row in payload["processes"]}, {600, 601})
        self.assertEqual({row["role"] for row in payload["processes"]}, {"coordinator", "worker"})
        self.assertEqual(payload["recentRuns"][0]["id"], RUN_A)

    def test_agents_projection_includes_processes_from_every_active_run(self):
        newest_active = run_record(
            RUN_A,
            "speed-dev",
            "2026-08-20T21:00:00Z",
            [target("newest-worker", "speed-dev", [attempt(1, "running", 611)])],
            coordinator_pid=610,
        )
        older_active = run_record(
            RUN_B,
            "bug-sweep",
            "2026-08-20T20:30:00Z",
            [target("older-worker", "bug-sweep", [attempt(1, "running", 621)])],
            coordinator_pid=620,
        )
        finished = run_record(
            RUN_C,
            "review-ready",
            "2026-08-20T21:30:00Z",
            [target("finished-worker", "review-ready", [attempt(1, "succeeded", 631, ended=True)])],
            coordinator_pid=630,
        )
        self.write_run(newest_active)
        self.write_run(older_active)
        self.write_run(finished)
        self.live_pids.update({610, 611, 620, 621, 630, 631})

        payload = self.service().snapshot()

        self.assertEqual(payload["selectedRun"]["id"], RUN_A)
        self.assertEqual({row["pid"] for row in payload["processes"]}, {610, 611, 620, 621})
        self.assertEqual({row["runId"] for row in payload["processes"]}, {RUN_A, RUN_B})

    def test_review_ready_workers_are_verified_but_never_live(self):
        record = run_record(
            RUN_A,
            "review-ready",
            "2026-08-20T21:00:00Z",
            [
                target("alpha", "review-ready", [attempt(1, "succeeded", 701, check="succeeded", ended=True)]),
                target("beta", "review-ready", [attempt(1, "succeeded", 702, check="succeeded", ended=True)]),
            ],
        )
        self.write_run(record)
        # Even a recycled PID must not resurrect an attempt with endedAt.
        self.live_pids.update({701, 702})

        payload = self.service().snapshot()

        self.assertEqual(payload["state"], "checkpoint")
        self.assertEqual(payload["counts"]["verified"], 2)
        self.assertEqual(payload["counts"]["live"], 0)
        self.assertEqual(payload["processes"], [])
        self.assertTrue(all(not worker["processAlive"] for worker in payload["workers"]))

    def test_runtime_identity_projects_only_the_registered_provider_model_pair(self):
        cases = [
            ({"providerId": "xai", "modelId": "grok-4.6"}, ("xai", "grok-4.6")),
            ({"providerId": " XAI ", "modelId": " GROK-4.6 "}, ("xai", "grok-4.6")),
            ({"providerId": "xai"}, (None, None)),
            ({"modelId": "grok-4.6"}, (None, None)),
            ({"providerId": "openai", "modelId": "grok-4.6"}, (None, None)),
            ({"providerId": "xai", "modelId": "grok-latest"}, (None, None)),
            ({"providerId": "/private/tmp/xai", "modelId": "grok-4.6"}, (None, None)),
            ({"providerId": "xai", "modelId": "/Users/private/grok-4.6"}, (None, None)),
            ({"providerId": "sk-live-provider-secret", "modelId": "grok-4.6"}, (None, None)),
            ({"providerId": "xai", "modelId": "token=credential-secret"}, (None, None)),
            ({"providerId": {"body": "raw-provider-body"}, "modelId": ["grok-4.6"]}, (None, None)),
        ]

        for runtime, expected in cases:
            with self.subTest(runtime=runtime):
                self.assertEqual(powerswarm_discovery._runtime_identity(runtime), expected)

    def test_snapshot_exports_normalized_runtime_identity_without_raw_provider_body(self):
        record = run_record(RUN_A, "review-ready", "2026-08-20T21:00:00Z", [])
        record["runtime"].update(
            {
                "providerId": " XAI ",
                "modelId": " GROK-4.6 ",
                "body": "raw-provider-body-sentinel",
                "credential": {"token": "sk-runtime-secret-sentinel"},
                "unknown": {"path": "/Users/private/runtime.json"},
            }
        )
        self.write_run(record)

        payload = self.service().snapshot()

        self.assertEqual(payload["selectedRun"]["providerId"], "xai")
        self.assertEqual(payload["selectedRun"]["modelId"], "grok-4.6")
        serialized = json.dumps(payload, sort_keys=True)
        for forbidden in (
            "raw-provider-body-sentinel",
            "sk-runtime-secret-sentinel",
            "/Users/private/runtime.json",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_valid_nested_plan_builds_logical_subdirector_tree(self):
        record = run_record(
            RUN_A,
            "speed-dev",
            "2026-08-20T21:00:00Z",
            [
                target("auth", "speed-dev", [attempt(1, "running", 801)]),
                target("secrets", "queued", []),
                target("retries", "queued", []),
            ],
            coordinator_pid=800,
        )
        directory = self.write_run(record)
        nested = {
            "schemaVersion": "1.0.0",
            "planId": "director_swarm_central_plan_aaaaaaaaaaaaaaaaaaaa",
            "contract": "ke.director.powerswarm-central-recursion.v1",
            "topology": {
                "logicalDepth": 2,
                "processSpawnDepth": 1,
                "rootOnlyProcessSpawn": True,
            },
            "subdirectors": [
                {"subdirectorId": "security", "aim": "Security surfaces", "targetIds": ["auth", "secrets"]},
                {"subdirectorId": "reliability", "aim": "Retry surface", "targetIds": ["retries"]},
            ],
            "executionPlan": {"planId": record["plan"]["planId"]},
        }
        (directory / "nested-plan.json").write_text(json.dumps(nested))
        self.live_pids.update({800, 801})

        payload = self.service().snapshot()

        self.assertEqual(payload["nested"]["state"], "observed")
        self.assertEqual(payload["nested"]["logicalDepth"], 2)
        self.assertEqual([node["id"] for node in payload["hierarchy"]["children"]], ["security", "reliability"])
        self.assertEqual(payload["hierarchy"]["children"][0]["state"], "running")
        self.assertEqual([leaf["id"] for leaf in payload["hierarchy"]["children"][0]["children"]], ["auth", "secrets"])

    def test_invalid_nested_plan_fails_closed_to_flat_worker_truth(self):
        record = run_record(RUN_A, "speed-dev", "2026-08-20T21:00:00Z", [target("auth")])
        directory = self.write_run(record)
        (directory / "nested-plan.json").write_text(json.dumps({"contract": "wrong"}))

        payload = self.service().snapshot()

        self.assertEqual(payload["nested"]["state"], "invalid")
        self.assertEqual(payload["hierarchy"]["children"][0]["kind"], "worker")
        self.assertEqual(payload["hierarchy"]["children"][0]["id"], "auth")

    def test_exact_parent_binding_is_projected_without_opening_codex_state(self):
        record = run_record(RUN_A, "review-ready", "2026-08-20T21:00:00Z", [])
        self.write_run(record)
        thread_id = "12345678-1234-1234-1234-123456789abc"
        (self.bindings / f"{RUN_A}.json").write_text(
            json.dumps(
                {
                    "runId": RUN_A,
                    "confidence": "exact",
                    "source": "launch-hook",
                    "parent": {
                        "host": "codex",
                        "threadId": thread_id,
                        "title": "Owning task",
                        "agentName": "Director",
                        "agentRole": "owner",
                    },
                }
            )
        )

        payload = self.service().snapshot()

        self.assertTrue(payload["selectedRun"]["parentExact"])
        self.assertEqual(payload["selectedRun"]["parent"]["threadId"], thread_id)
        self.assertEqual(payload["selectedRun"]["parent"]["codexUrl"], f"codex://threads/{thread_id}")

    def test_read_failure_retains_last_metadata_but_clears_liveness(self):
        record = run_record(
            RUN_A,
            "speed-dev",
            "2026-08-20T21:00:00Z",
            [target("live", "speed-dev", [attempt(1, "running", 901)])],
            coordinator_pid=900,
        )
        record["runtime"].update({"providerId": "xai", "modelId": "grok-4.6"})
        directory = self.write_run(record)
        self.live_pids.update({900, 901})
        service = self.service()
        first = service.snapshot(RUN_A)
        self.assertEqual(first["counts"]["live"], 1)
        (directory / "run.json").unlink()

        retained = service.snapshot(RUN_A, force=True)

        self.assertTrue(retained["stale"])
        self.assertEqual(retained["state"], "stale")
        self.assertEqual(retained["counts"]["live"], 0)
        self.assertEqual(retained["counts"]["stale"], 1)
        self.assertEqual(retained["processes"], [])
        self.assertTrue(all(not worker["processAlive"] for worker in retained["workers"]))
        self.assertTrue(all(worker["pid"] is None for worker in retained["workers"]))
        self.assertEqual(retained["workers"][0]["state"], "stale")
        self.assertEqual(retained["workers"][0]["recordedState"], "stale")
        self.assertFalse(retained["selectedRun"]["coordinatorAlive"])
        self.assertIsNone(retained["selectedRun"]["coordinatorPid"])
        self.assertEqual(retained["selectedRun"]["state"], "stale")
        self.assertIsNone(retained["selectedRun"]["providerId"])
        self.assertIsNone(retained["selectedRun"]["modelId"])
        self.assertFalse(retained["recentRuns"][0]["active"])
        self.assertFalse(retained["recentRuns"][0]["coordinatorAlive"])
        self.assertEqual(retained["recentRuns"][0]["state"], "stale")
        self.assertEqual(retained["hierarchy"]["children"][0]["state"], "stale")

    def test_worker_detail_keeps_exit_and_green_check_separate(self):
        record = run_record(
            RUN_A,
            "review-ready",
            "2026-08-20T21:00:00Z",
            [target("checked", "review-ready", [attempt(1, "succeeded", 1001, check="succeeded", ended=True)])],
        )
        self.write_run(record)

        detail = self.service().worker_detail(RUN_A, "checked")

        self.assertTrue(detail["ok"])
        self.assertEqual(detail["worker"]["state"], "verified")
        self.assertFalse(detail["attempts"][0]["processAlive"])
        self.assertEqual(detail["attempts"][0]["killCheck"]["status"], "succeeded")
        self.assertFalse(detail["privacy"]["outputsRead"])

    def test_pid_identity_rejects_older_and_newer_recycled_processes(self):
        service = PowerSwarmService(self.runs, self.bindings, cache_seconds=0)
        started_at = "2026-08-20T20:00:00Z"
        expected = powerswarm_discovery._epoch(started_at)

        def observed_process(created_at):
            return SimpleNamespace(
                is_running=lambda: True,
                status=lambda: "running",
                create_time=lambda: created_at,
            )

        with patch.object(powerswarm_discovery.psutil, "Process", return_value=observed_process(expected - 1.01)):
            self.assertFalse(service._probe(1201, started_at=started_at))
        with patch.object(powerswarm_discovery.psutil, "Process", return_value=observed_process(expected + 1.01)):
            self.assertFalse(service._probe(1201, started_at=started_at))
        with patch.object(powerswarm_discovery.psutil, "Process", return_value=observed_process(expected + 0.25)):
            self.assertTrue(service._probe(1201, started_at=started_at))
        with patch.object(powerswarm_discovery.psutil, "Process", return_value=observed_process(expected)):
            self.assertFalse(service._probe(1201, started_at=None))

    def test_record_cache_identity_includes_descriptor_device_and_inode(self):
        first = run_record(RUN_A, "review-ready", "2026-08-20T21:00:00Z", [])
        first["plan"]["objective"] = "Safe AAAA"
        directory = self.write_run(first)
        service = self.service()
        initial = service.snapshot(force=True)
        ledger = directory / "run.json"
        metadata = ledger.stat()

        second = run_record(RUN_A, "review-ready", "2026-08-20T21:00:00Z", [])
        second["plan"]["objective"] = "Safe BBBB"
        replacement = directory / "replacement.json"
        replacement.write_text(json.dumps(second))
        self.assertEqual(replacement.stat().st_size, metadata.st_size)
        os.utime(replacement, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        os.replace(replacement, ledger)

        refreshed = service.snapshot(force=True)

        self.assertEqual(initial["selectedRun"]["objective"], "Safe AAAA")
        self.assertEqual(refreshed["selectedRun"]["objective"], "Safe BBBB")

    def test_record_cache_evicts_five_disjoint_generations_at_declared_cap(self):
        service = self.service()
        first_generation_key = None
        for generation in range(5):
            for child in list(self.runs.iterdir()):
                shutil.rmtree(child)
            generation_keys = []
            for index in range(64):
                sequence = generation * 64 + index + 1
                run_id = f"director_swarm_run_{sequence:020x}"
                generation_keys.append(run_id)
                self.write_run(run_record(run_id, "review-ready", "2026-08-20T21:00:00Z", []))
            if first_generation_key is None:
                first_generation_key = generation_keys[0]
            service.snapshot(force=True)
            self.assertLessEqual(len(service._record_cache), powerswarm_discovery.MAX_RECORD_CACHE_ENTRIES)
            self.assertLessEqual(service._record_cache_bytes, powerswarm_discovery.MAX_RECORD_CACHE_BYTES)

        self.assertEqual(len(service._record_cache), powerswarm_discovery.MAX_RECORD_CACHE_ENTRIES)
        self.assertNotIn(first_generation_key, service._record_cache)
        self.assertTrue(set(service._record_cache).issubset(set(generation_keys)))

    def test_record_cache_byte_budget_evicts_disjoint_eight_mib_entries(self):
        service = self.service()
        keys = [f"director_swarm_run_{index:020x}" for index in range(1, 4)]
        for index, key in enumerate(keys, start=1):
            payload = {
                "runId": key,
                "blob": chr(96 + index) * (powerswarm_discovery.MAX_RUN_BYTES - 2048),
            }
            service._cache_record(
                key,
                (1, index, index, powerswarm_discovery.MAX_RUN_BYTES),
                payload,
            )

        self.assertEqual(service._record_cache_bytes, powerswarm_discovery.MAX_RECORD_CACHE_BYTES)
        self.assertEqual(len(service._record_cache), 2)
        self.assertNotIn(keys[0], service._record_cache)
        self.assertLessEqual(service._record_cache_bytes, powerswarm_discovery.MAX_RECORD_CACHE_BYTES)
        self.assertLessEqual(
            sum(len(entry[1]["blob"]) for entry in service._record_cache.values()),
            powerswarm_discovery.MAX_RECORD_CACHE_BYTES,
        )

    def test_snapshot_and_last_good_caches_have_entry_and_byte_eviction(self):
        service = self.service()
        first_key = "generation-000"
        for index in range(5 * 64):
            key = f"generation-{index:03d}"
            payload = {"ok": True, "selectedRun": {"id": key}, "counts": {"live": 0}}
            service._cache_snapshot(key, float(index), payload)
            service._cache_last_good(key, payload)

        self.assertLessEqual(len(service._snapshot_cache), powerswarm_discovery.MAX_SNAPSHOT_CACHE_ENTRIES)
        self.assertLessEqual(service._snapshot_cache_bytes, powerswarm_discovery.MAX_SNAPSHOT_CACHE_BYTES)
        self.assertLessEqual(len(service._last_good), powerswarm_discovery.MAX_LAST_GOOD_CACHE_ENTRIES)
        self.assertLessEqual(service._last_good_cache_bytes, powerswarm_discovery.MAX_LAST_GOOD_CACHE_BYTES)
        self.assertNotIn(first_key, service._snapshot_cache)
        self.assertNotIn(first_key, service._last_good)

        byte_service = self.service()
        with patch.multiple(
            powerswarm_discovery,
            MAX_SNAPSHOT_CACHE_BYTES=1024,
            MAX_LAST_GOOD_CACHE_BYTES=1024,
        ):
            for index in range(3):
                payload = {"ok": True, "blob": "x" * 700, "generation": index}
                byte_service._cache_snapshot(f"byte-{index}", float(index), payload)
                byte_service._cache_last_good(f"byte-{index}", payload)
            self.assertLessEqual(byte_service._snapshot_cache_bytes, 1024)
            self.assertLessEqual(byte_service._last_good_cache_bytes, 1024)
            self.assertNotIn("byte-0", byte_service._snapshot_cache)
            self.assertNotIn("byte-0", byte_service._last_good)

    def test_opened_runs_root_survives_path_swap_without_reading_outside_metadata(self):
        safe = run_record(RUN_A, "review-ready", "2026-08-20T21:00:00Z", [])
        safe["plan"]["objective"] = "Safe root metadata"
        self.write_run(safe)
        outside_root = self.root / "outside-runs"
        outside_directory = outside_root / RUN_A
        outside_directory.mkdir(parents=True)
        outside = run_record(RUN_A, "review-ready", "2026-08-20T22:00:00Z", [])
        outside["plan"]["objective"] = "OUTSIDE ROOT SECRET"
        (outside_directory / "run.json").write_text(json.dumps(outside))
        service = self.service()
        original = service._record_from_run_fd
        swapped = False

        def swap_then_read(run_id, run_fd):
            nonlocal swapped
            if not swapped:
                swapped = True
                self.runs.rename(self.root / "runs-original")
                outside_root.rename(self.runs)
            return original(run_id, run_fd)

        with patch.object(service, "_record_from_run_fd", side_effect=swap_then_read):
            payload = service.snapshot(force=True)

        encoded = json.dumps(payload)
        self.assertEqual(payload["selectedRun"]["objective"], "Safe root metadata")
        self.assertNotIn("OUTSIDE ROOT SECRET", encoded)

    def test_opened_nested_parent_survives_directory_swap_without_reading_outside_plan(self):
        safe = run_record(RUN_A, "review-ready", "2026-08-20T21:00:00Z", [target("leaf", "review-ready")])
        directory = self.write_run(safe)
        (directory / "nested-plan.json").write_text(
            json.dumps(nested_plan(safe, [{"subdirectorId": "safe-branch", "aim": "Safe", "targetIds": ["leaf"]}]))
        )
        outside_parent = self.root / "outside-run-parent"
        outside_parent.mkdir()
        (outside_parent / "nested-plan.json").write_text(
            json.dumps(nested_plan(safe, [{"subdirectorId": "outside-branch", "aim": "OUTSIDE PLAN SECRET", "targetIds": ["leaf"]}]))
        )
        service = self.service()
        original = service._read_nested_from_run_fd
        swapped = False

        def swap_then_read(run_fd):
            nonlocal swapped
            if not swapped:
                swapped = True
                directory.rename(self.runs / f"{RUN_A}-original")
                outside_parent.rename(directory)
            return original(run_fd)

        with patch.object(service, "_read_nested_from_run_fd", side_effect=swap_then_read):
            payload = service.snapshot(force=True)

        encoded = json.dumps(payload)
        self.assertEqual(payload["hierarchy"]["children"][0]["id"], "safe-branch")
        self.assertNotIn("outside-branch", encoded)
        self.assertNotIn("OUTSIDE PLAN SECRET", encoded)

    def test_opened_bindings_root_survives_path_swap_without_reading_outside_parent(self):
        record = run_record(RUN_A, "review-ready", "2026-08-20T21:00:00Z", [])
        self.write_run(record)
        thread_id = "12345678-1234-1234-1234-123456789abc"

        def binding(title):
            return {
                "runId": RUN_A,
                "confidence": "exact",
                "parent": {"host": "codex", "threadId": thread_id, "title": title},
            }

        (self.bindings / f"{RUN_A}.json").write_text(json.dumps(binding("Safe parent")))
        outside_root = self.root / "outside-bindings"
        outside_root.mkdir()
        (outside_root / f"{RUN_A}.json").write_text(json.dumps(binding("OUTSIDE PARENT SECRET")))
        service = self.service()
        original = service._binding_from_root_fd
        swapped = False

        def swap_then_read(root_fd, run_id):
            nonlocal swapped
            if not swapped:
                swapped = True
                self.bindings.rename(self.root / "bindings-original")
                outside_root.rename(self.bindings)
            return original(root_fd, run_id)

        with patch.object(service, "_binding_from_root_fd", side_effect=swap_then_read):
            payload = service.snapshot(force=True)

        encoded = json.dumps(payload)
        self.assertEqual(payload["selectedRun"]["parent"]["title"], "Safe parent")
        self.assertNotIn("OUTSIDE PARENT SECRET", encoded)

    def test_nofollow_and_current_user_ownership_fail_closed(self):
        outside_root = self.root / "outside-runs"
        outside_directory = outside_root / RUN_A
        outside_directory.mkdir(parents=True)
        outside = run_record(RUN_A, "review-ready", "2026-08-20T21:00:00Z", [])
        outside["plan"]["objective"] = "OUTSIDE SYMLINK SECRET"
        (outside_directory / "run.json").write_text(json.dumps(outside))

        self.runs.rmdir()
        self.runs.symlink_to(outside_root, target_is_directory=True)
        symlink_payload = self.service().snapshot(force=True)
        self.assertFalse(symlink_payload["ok"])
        self.assertEqual(symlink_payload["errorCode"], "observer-runs-root-untrusted")
        self.assertNotIn("OUTSIDE SYMLINK SECRET", json.dumps(symlink_payload))

        self.runs.unlink()
        self.runs.mkdir()
        with patch.object(powerswarm_discovery.os, "getuid", return_value=os.getuid() + 1):
            ownership_payload = self.service().snapshot(force=True)
        self.assertFalse(ownership_payload["ok"])
        self.assertEqual(ownership_payload["errorCode"], "observer-runs-root-untrusted")

    def test_symlinked_run_nested_plan_and_binding_never_project_outside_metadata(self):
        outside_run = self.root / "outside-run"
        outside_run.mkdir()
        outside_record = run_record(RUN_A, "review-ready", "2026-08-20T21:00:00Z", [])
        outside_record["plan"]["objective"] = "OUTSIDE RUN SECRET"
        (outside_run / "run.json").write_text(json.dumps(outside_record))
        (self.runs / RUN_A).symlink_to(outside_run, target_is_directory=True)
        run_payload = self.service().snapshot(force=True)
        self.assertEqual(run_payload["state"], "no-runs")
        self.assertEqual(run_payload["invalidRunCount"], 1)
        self.assertNotIn("OUTSIDE RUN SECRET", json.dumps(run_payload))

        (self.runs / RUN_A).unlink()
        safe = run_record(RUN_A, "review-ready", "2026-08-20T21:00:00Z", [target("leaf")])
        safe_directory = self.write_run(safe)
        outside_nested = self.root / "outside-nested.json"
        outside_nested.write_text(
            json.dumps(nested_plan(safe, [{"subdirectorId": "outside", "aim": "OUTSIDE NESTED SECRET", "targetIds": ["leaf"]}]))
        )
        (safe_directory / "nested-plan.json").symlink_to(outside_nested)

        outside_bindings = self.root / "outside-bindings"
        outside_bindings.mkdir()
        (outside_bindings / f"{RUN_A}.json").write_text(
            json.dumps(
                {
                    "runId": RUN_A,
                    "confidence": "exact",
                    "parent": {
                        "host": "codex",
                        "threadId": "12345678-1234-1234-1234-123456789abc",
                        "title": "OUTSIDE BINDING SECRET",
                    },
                }
            )
        )
        self.bindings.rmdir()
        self.bindings.symlink_to(outside_bindings, target_is_directory=True)

        payload = self.service().snapshot(force=True)
        encoded = json.dumps(payload)
        self.assertEqual(payload["nested"]["state"], "invalid")
        self.assertEqual(payload["nested"]["errorCode"], "observer-nested-plan")
        self.assertIsNone(payload["selectedRun"]["parent"])
        self.assertEqual(payload["selectedRun"]["parentObserverCode"], "observer-bindings-root-untrusted")
        self.assertNotIn("OUTSIDE NESTED SECRET", encoded)
        self.assertNotIn("OUTSIDE BINDING SECRET", encoded)

    def test_every_observer_collection_has_a_hard_cap_and_truncation_truth(self):
        for index in range(4):
            (self.runs / f"noise-{index}").write_text("x")
        with patch.object(powerswarm_discovery, "MAX_SCAN_ENTRIES", 2):
            scan_payload = self.service().snapshot(force=True)
        self.assertTrue(scan_payload["truncation"]["scannedEntries"])

        for index, run_id in enumerate((RUN_A, RUN_B, RUN_C)):
            self.write_run(run_record(run_id, "review-ready", f"2026-08-20T2{index}:00:00Z", []))
        with patch.object(powerswarm_discovery, "MAX_RECORDS", 1):
            records_payload = self.service().snapshot(force=True)
        self.assertEqual(len(records_payload["recentRuns"]), 1)
        self.assertTrue(records_payload["truncation"]["records"])

        with patch.object(powerswarm_discovery, "MAX_RECENT_RUNS", 1):
            returned_records_payload = self.service().snapshot(force=True)
        self.assertEqual(len(returned_records_payload["recentRuns"]), 1)
        self.assertTrue(returned_records_payload["truncation"]["records"])

        capped_record = run_record(
            RUN_A,
            "speed-dev",
            "2026-08-20T23:00:00Z",
            [
                target(f"worker-{index}", "speed-dev", [attempt(number, "running", 1400 + index * 10 + number) for number in range(1, 4)])
                for index in range(3)
            ],
            coordinator_pid=1399,
        )
        (self.runs / RUN_A / "run.json").write_text(json.dumps(capped_record))
        self.live_pids.update({1399, 1401, 1411, 1421})
        with patch.multiple(
            powerswarm_discovery,
            MAX_TARGETS_PER_RUN=2,
            MAX_ATTEMPTS_PER_STAGE=1,
            MAX_ATTEMPTS_PER_WORKER=1,
            MAX_RETURNED_PROCESSES=2,
        ):
            capped_payload = self.service().snapshot(RUN_A, force=True)
        self.assertEqual(len(capped_payload["workers"]), 2)
        self.assertEqual(len(capped_payload["processes"]), 2)
        self.assertTrue(capped_payload["truncation"]["targets"])
        self.assertTrue(capped_payload["truncation"]["attempts"])
        self.assertTrue(capped_payload["truncation"]["processes"])

    def test_nested_branch_and_leaf_caps_fail_closed_to_flat_truth(self):
        record = run_record(
            RUN_A,
            "review-ready",
            "2026-08-20T21:00:00Z",
            [target("one", "review-ready"), target("two", "review-ready")],
        )
        directory = self.write_run(record)
        branches = [
            {"subdirectorId": "first", "aim": "First", "targetIds": ["one"]},
            {"subdirectorId": "second", "aim": "Second", "targetIds": ["two"]},
        ]
        (directory / "nested-plan.json").write_text(json.dumps(nested_plan(record, branches)))
        with patch.object(powerswarm_discovery, "MAX_NESTED_BRANCHES", 1):
            branch_payload = self.service().snapshot(force=True)
        self.assertEqual(branch_payload["nested"]["state"], "truncated")
        self.assertTrue(branch_payload["truncation"]["nestedBranches"])
        self.assertTrue(all(child["kind"] == "worker" for child in branch_payload["hierarchy"]["children"]))

        with patch.object(powerswarm_discovery, "MAX_NESTED_LEAVES", 1):
            leaf_payload = self.service().snapshot(force=True)
        self.assertEqual(leaf_payload["nested"]["state"], "truncated")
        self.assertTrue(leaf_payload["truncation"]["nestedLeaves"])
        self.assertTrue(all(child["kind"] == "worker" for child in leaf_payload["hierarchy"]["children"]))

    def test_failed_and_cancelled_run_states_are_not_relabelled_checkpoint(self):
        for state in ("failed", "cancelled"):
            with self.subTest(state=state):
                directory = self.write_run(run_record(RUN_A, state, "2026-08-20T21:00:00Z", []))
                payload = self.service().snapshot(force=True)
                self.assertEqual(payload["state"], state)
                self.assertEqual(payload["selectedRun"]["state"], state)
                directory.rename(self.root / f"finished-{state}")

    def test_api_omits_absolute_paths_and_sanitizes_arbitrary_ledger_errors(self):
        failing_attempt = attempt(1, "failed", 1501, ended=True)
        failing_attempt["error"] = "SECRET /private/tmp/outside traceback"
        failing_attempt["killCheck"] = {"status": "failed", "error": "SECRET /private/tmp/check"}
        record = run_record(RUN_A, "failed", "2026-08-20T21:00:00Z", [target("failed", "failed", [failing_attempt])])
        directory = self.write_run(record)
        thread_id = "12345678-1234-1234-1234-123456789abc"
        (self.bindings / f"{RUN_A}.json").write_text(
            json.dumps(
                {
                    "runId": RUN_A,
                    "confidence": "exact",
                    "parent": {"host": "codex", "threadId": thread_id, "cwd": "/private/tmp/SECRET-CWD"},
                }
            )
        )
        payload = self.service().snapshot(force=True)
        detail = self.service().worker_detail(RUN_A, "failed")
        encoded = json.dumps({"payload": payload, "detail": detail})

        self.assertNotIn("worktreePath", encoded)
        self.assertNotIn('"cwd"', encoded)
        self.assertNotIn("SECRET", encoded)
        self.assertNotIn("/private/tmp", encoded)
        self.assertEqual(detail["attempts"][0]["errorCode"], "worker-attempt-failed")
        self.assertEqual(detail["attempts"][0]["killCheck"]["errorCode"], "kill-check-failed")

    def test_timestamp_and_enum_path_sentinels_never_reach_any_output_surface(self):
        sentinel = "/private/tmp/POWERSWARM-TIMESTAMP-SENTINEL"
        malformed_attempt = attempt(1, sentinel, 1551, ended=True)
        malformed_attempt.update(
            {
                "startedAt": sentinel,
                "endedAt": sentinel,
                "signal": sentinel,
                "killCheck": {
                    "status": sentinel,
                    "startedAt": sentinel,
                    "endedAt": sentinel,
                },
                "toolBurst": {"status": sentinel, "telemetry": {"status": sentinel}},
            }
        )
        malformed_target = target("sentinel-worker", sentinel, [malformed_attempt])
        record = run_record(RUN_A, sentinel, sentinel, [malformed_target], coordinator_pid=1550)
        record["createdAt"] = sentinel
        record["coordinator"]["startedAt"] = sentinel
        record["runtime"]["runtime"] = sentinel
        self.write_run(record)

        service = self.service()
        payload = service.snapshot(force=True)
        detail = service.worker_detail(RUN_A, "sentinel-worker")
        encoded = json.dumps({"payload": payload, "detail": detail})

        self.assertNotIn(sentinel, encoded)
        self.assertIsNone(payload["generatedAt"])
        self.assertIsNone(payload["selectedRun"]["createdAt"])
        self.assertIsNone(payload["selectedRun"]["updatedAt"])
        self.assertIsNone(payload["recentRuns"][0]["updatedAt"])
        self.assertIsNone(payload["workers"][0]["startedAt"])
        self.assertIsNone(payload["workers"][0]["endedAt"])
        self.assertEqual(payload["selectedRun"]["state"], "unknown")
        self.assertEqual(payload["selectedRun"]["runtime"], "grok-build")
        self.assertIsNone(payload["workers"][0]["recordedState"])
        self.assertIsNone(payload["workers"][0]["killCheck"])
        self.assertIsNone(payload["workers"][0]["toolState"])
        self.assertEqual(detail["run"]["state"], "unknown")
        self.assertIsNone(detail["attempts"][0]["status"])
        self.assertIsNone(detail["attempts"][0]["startedAt"])
        self.assertIsNone(detail["attempts"][0]["endedAt"])
        self.assertIsNone(detail["attempts"][0]["signal"])
        self.assertIsNone(detail["attempts"][0]["killCheck"]["status"])
        self.assertIsNone(detail["attempts"][0]["killCheck"]["startedAt"])
        self.assertIsNone(detail["attempts"][0]["killCheck"]["endedAt"])
        self.assertIsNone(detail["attempts"][0]["toolActivity"]["status"])
        self.assertIsNone(detail["attempts"][0]["toolActivity"]["telemetryStatus"])

    def test_all_valid_ledger_timestamps_are_canonicalized_to_utc(self):
        checked_attempt = attempt(1, "succeeded", 1561, check="succeeded", ended=True)
        checked_attempt["startedAt"] = "2026-08-20T20:00:00-04:00"
        checked_attempt["endedAt"] = "2026-08-20T20:05:00-04:00"
        checked_attempt["killCheck"].update(
            {
                "startedAt": "2026-08-20T20:05:01-04:00",
                "endedAt": "2026-08-20T20:05:02-04:00",
            }
        )
        record = run_record(
            RUN_A,
            "review-ready",
            "2026-08-20T21:00:00-04:00",
            [target("canonical", "review-ready", [checked_attempt])],
        )
        record["createdAt"] = "2026-08-20T19:59:00-04:00"
        self.write_run(record)

        service = self.service()
        payload = service.snapshot(force=True)
        detail = service.worker_detail(RUN_A, "canonical")

        self.assertEqual(payload["generatedAt"], "2026-08-21T01:00:00.000Z")
        self.assertEqual(payload["selectedRun"]["createdAt"], "2026-08-20T23:59:00.000Z")
        self.assertEqual(payload["selectedRun"]["updatedAt"], "2026-08-21T01:00:00.000Z")
        self.assertEqual(payload["recentRuns"][0]["updatedAt"], "2026-08-21T01:00:00.000Z")
        self.assertEqual(payload["workers"][0]["startedAt"], "2026-08-21T00:00:00.000Z")
        self.assertEqual(payload["workers"][0]["endedAt"], "2026-08-21T00:05:00.000Z")
        self.assertEqual(detail["attempts"][0]["startedAt"], "2026-08-21T00:00:00.000Z")
        self.assertEqual(detail["attempts"][0]["endedAt"], "2026-08-21T00:05:00.000Z")
        self.assertEqual(detail["attempts"][0]["killCheck"]["startedAt"], "2026-08-21T00:05:01.000Z")
        self.assertEqual(detail["attempts"][0]["killCheck"]["endedAt"], "2026-08-21T00:05:02.000Z")

    def test_raw_ledger_timestamp_parser_requires_known_zone_and_four_digit_utc_range(self):
        accepted = {
            "2026-08-21T12:00:00-04:00": "2026-08-21T16:00:00.000Z",
            "0001-01-01T00:01:00+00:01": "0001-01-01T00:00:00.000Z",
            "9999-12-31T23:58:59-00:01": "9999-12-31T23:59:59.000Z",
            0: "1970-01-01T00:00:00.000Z",
            -62_135_596_800_000: "0001-01-01T00:00:00.000Z",
            253_402_300_799_000: "9999-12-31T23:59:59.000Z",
        }
        rejected = [
            "2026-08-21T12:00:00-00:00",
            "0000-01-01T00:00:00Z",
            "0001-01-01T00:00:00+00:01",
            "9999-12-31T23:59:59-00:01",
            -62_135_596_800_001,
            253_402_300_800_000,
        ]

        for raw, canonical in accepted.items():
            with self.subTest(raw=raw):
                self.assertEqual(powerswarm_discovery._canonical_timestamp(raw), canonical)
        for raw in rejected:
            with self.subTest(raw=raw):
                self.assertIsNone(powerswarm_discovery._timestamp_datetime(raw))
                self.assertIsNone(powerswarm_discovery._canonical_timestamp(raw))

    def test_fresh_snapshot_never_fabricates_unknown_offset_or_extended_year(self):
        checked_attempt = attempt(1, "succeeded", 1562, check="succeeded", ended=True)
        checked_attempt.update(
            {
                "startedAt": 0,
                "endedAt": 253_402_300_799_000,
            }
        )
        checked_attempt["killCheck"].update(
            {
                "startedAt": "0001-01-01T00:00:00+00:01",
                "endedAt": "9999-12-31T23:58:59-00:01",
            }
        )
        record = run_record(
            RUN_A,
            "review-ready",
            "2026-08-21T12:00:00-00:00",
            [target("strict-time", "review-ready", [checked_attempt])],
        )
        record["createdAt"] = "0000-01-01T00:00:00Z"
        self.write_run(record)

        service = self.service()
        payload = service.snapshot(force=True)
        detail = service.worker_detail(RUN_A, "strict-time")

        self.assertTrue(payload["ok"])
        self.assertFalse(payload["stale"])
        self.assertIsNone(payload["generatedAt"])
        self.assertIsNone(payload["selectedRun"]["createdAt"])
        self.assertIsNone(payload["selectedRun"]["updatedAt"])
        self.assertIsNone(payload["recentRuns"][0]["updatedAt"])
        self.assertEqual(payload["workers"][0]["startedAt"], "1970-01-01T00:00:00.000Z")
        self.assertEqual(payload["workers"][0]["endedAt"], "9999-12-31T23:59:59.000Z")
        self.assertEqual(detail["attempts"][0]["startedAt"], "1970-01-01T00:00:00.000Z")
        self.assertEqual(detail["attempts"][0]["endedAt"], "9999-12-31T23:59:59.000Z")
        self.assertIsNone(detail["attempts"][0]["killCheck"]["startedAt"])
        self.assertEqual(
            detail["attempts"][0]["killCheck"]["endedAt"],
            "9999-12-31T23:59:59.000Z",
        )

    def test_public_failures_use_stable_codes_and_unsupported_platform_fails_closed(self):
        invalid = self.service().snapshot("../../secret", force=True)
        self.assertEqual(invalid["error"], "observer-run-id-invalid")
        self.assertEqual(invalid["errorCode"], "observer-run-id-invalid")
        self.assertNotIn("secret", json.dumps(invalid))
        worker = self.service().worker_detail("bad", "also/bad")
        self.assertEqual(worker["errorCode"], "observer-run-id-invalid")

        with patch.object(powerswarm_discovery, "_descriptor_security_supported", return_value=False):
            unsupported = self.service().snapshot(force=True)
        self.assertFalse(unsupported["ok"])
        self.assertEqual(unsupported["errorCode"], "observer-platform-unsupported")


class ActivityMonitorPowerSwarmWiringTests(unittest.TestCase):
    def setUp(self):
        activity_monitor.Api._agents_cache = {
            "t": 0.0,
            "body": None,
            "last_good": None,
            "cpu_pool_activity": {},
        }

    def tearDown(self):
        activity_monitor.Api._agents_cache = {
            "t": 0.0,
            "body": None,
            "last_good": None,
            "cpu_pool_activity": {},
        }

    @staticmethod
    def live_powerswarm_fixture():
        return {
            "ok": True,
            "schemaVersion": SCHEMA_VERSION,
            "state": "active",
            "installed": True,
            "stale": False,
            "observedAt": "2026-08-21T12:00:00Z",
            "generatedAt": "2026-08-21T11:59:59Z",
            "selectedRun": {
                "id": RUN_A,
                "objective": "Retained historical objective",
                "product": "fixture-product",
                "state": "running",
                "createdAt": "2026-08-21T11:50:00Z",
                "updatedAt": "2026-08-21T11:59:59Z",
                "coordinatorPid": 9100,
                "coordinatorAlive": True,
                "runtime": "grok-build",
                "providerId": "xai",
                "modelId": "grok-4.6",
            },
            "counts": {"total": 2, "live": 1, "queued": 0, "verified": 1, "failed": 0, "stale": 0},
            "workers": [
                {
                    "id": "live-worker",
                    "aim": "Retained historical worker aim",
                    "state": "running",
                    "recordedState": "worker-live",
                    "stage": "speed-dev",
                    "pid": 9101,
                    "processAlive": True,
                    "startedAt": "2026-08-21T11:55:00Z",
                },
                {
                    "id": "verified-worker",
                    "aim": "Retained verified result",
                    "state": "verified",
                    "recordedState": "review-ready",
                    "stage": "bug-sweep",
                    "pid": 9102,
                    "processAlive": False,
                    "endedAt": "2026-08-21T11:58:00Z",
                },
            ],
            "hierarchy": {
                "kind": "run",
                "id": RUN_A,
                "state": "active",
                "coordinatorPid": 9100,
                "children": [
                    {"kind": "worker", "id": "live-worker", "state": "running", "pid": 9101, "processAlive": True},
                    {"kind": "worker", "id": "verified-worker", "state": "verified", "pid": 9102, "processAlive": False},
                ],
            },
            "nested": {"state": "observed", "logicalDepth": 2, "processSpawnDepth": 1},
            "recentRuns": [
                {
                    "id": RUN_A,
                    "state": "active",
                    "updatedAt": "2026-08-21T11:59:59Z",
                    "coordinatorAlive": True,
                    "active": True,
                    "workerCount": 2,
                    "objective": "Retained historical objective",
                }
            ],
            "processes": [{"pid": 9100}, {"pid": 9101}],
            "truncation": {"any": False},
            "privacy": {"mode": "metadata-only", "outputsRead": False, "mutations": False},
        }

    @staticmethod
    def run_browser_projection(expression, fixture):
        html = activity_monitor.HTML
        start = html.index("function stalePowerSwarmProjection")
        end = html.index("function powerSwarmErrorText", start)
        functions = html[start:end]
        script = (
            functions
            + "\nconst fs=require('fs');const fixture=JSON.parse(fs.readFileSync(0,'utf8'));"
            + f"const projected={expression};process.stdout.write(JSON.stringify(projected));"
        )
        completed = subprocess.run(
            ["node", "-e", script],
            input=json.dumps(fixture),
            text=True,
            capture_output=True,
            timeout=8,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr)
        return json.loads(completed.stdout)

    def assert_powerswarm_projection_has_no_current_pid_or_live_state(self, payload):
        self.assertEqual(payload["counts"]["live"], 0)
        self.assertEqual(payload["processes"], [])
        self.assertFalse(payload["selectedRun"]["coordinatorAlive"])
        self.assertIsNone(payload["selectedRun"]["coordinatorPid"])
        self.assertIsNone(payload["selectedRun"]["providerId"])
        self.assertIsNone(payload["selectedRun"]["modelId"])
        self.assertNotIn(payload["selectedRun"]["state"], {"active", "running", "worker-live"})
        for worker in payload["workers"]:
            self.assertFalse(worker["processAlive"])
            self.assertIsNone(worker["pid"])
            self.assertNotIn(worker["state"], {"active", "running", "worker-live"})
            self.assertNotIn(worker["recordedState"], {"active", "running", "worker-live"})
        for run in payload["recentRuns"]:
            self.assertFalse(run["active"])
            self.assertFalse(run["coordinatorAlive"])
            self.assertNotIn(run["state"], {"active", "running", "worker-live"})

        def inspect(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in {"pid", "coordinatorPid"}:
                        self.assertIsNone(value)
                    inspect(value)
            elif isinstance(node, list):
                for value in node:
                    inspect(value)

        inspect(payload)

    def test_bridge_failure_uses_pure_stale_projection_with_zero_liveness(self):
        fixture = self.live_powerswarm_fixture()
        projected = self.run_browser_projection(
            "stalePowerSwarmProjection(fixture,'powerswarm-bridge-unavailable','2026-08-21T12:01:00Z')",
            fixture,
        )

        self.assertTrue(projected["stale"])
        self.assertEqual(projected["state"], "stale")
        self.assertEqual(projected["errorCode"], "powerswarm-bridge-unavailable")
        self.assertEqual(projected["selectedRun"]["objective"], "Retained historical objective")
        self.assertEqual(projected["workers"][1]["state"], "verified")
        self.assertEqual(projected["workers"][1]["aim"], "Retained verified result")
        self.assert_powerswarm_projection_has_no_current_pid_or_live_state(projected)
        self.assertIn(
            "stalePowerSwarmProjection(lastPowerSwarmSnapshot,'powerswarm-bridge-unavailable'",
            activity_monitor.HTML,
        )
        self.assertIn("if (stale) closePowerSwarmWorker();", activity_monitor.HTML)

    def test_agents_last_snapshot_failure_uses_same_projection_and_drops_powerswarm_rows(self):
        fixture = {
            "schemaVersion": "ke.activity-monitor-agents.v1",
            "powerSwarm": self.live_powerswarm_fixture(),
            "cpu": {"ok": True, "stale": False},
            "gpu": {"ok": True, "stale": False},
            "aiProcesses": [
                {"pid": 9101, "category": "PowerSwarm worker", "powerSwarmRun": RUN_A},
                {"pid": 9200, "category": "Codex", "name": "Retained non-PowerSwarm process"},
            ],
        }
        projected = self.run_browser_projection(
            "staleAgentSnapshotProjection(fixture,'2026-08-21T12:02:00Z')",
            fixture,
        )

        self.assertTrue(projected["stale"])
        self.assertTrue(projected["cpu"]["stale"])
        self.assertTrue(projected["gpu"]["stale"])
        self.assertEqual(projected["aiProcesses"], [fixture["aiProcesses"][1]])
        self.assert_powerswarm_projection_has_no_current_pid_or_live_state(projected["powerSwarm"])
        self.assertEqual(
            activity_monitor.HTML.count(
                "staleAgentSnapshotProjection(lastAgentSnapshot,new Date().toISOString())"
            ),
            2,
        )

    def test_browser_runtime_truth_is_exact_pair_only_and_never_returns_raw_values(self):
        cases = [
            ("xai", "grok-4.6", False, True, "xAI · Grok 4.6"),
            (" XAI ", " GROK-4.6 ", False, True, "xAI · Grok 4.6"),
            (None, "grok-4.6", False, False, "Provider/model unknown"),
            ("xai", None, False, False, "Provider/model unknown"),
            ("openai", "grok-4.6", False, False, "Provider/model unknown"),
            ("xai", "arbitrary-model-sentinel", False, False, "Provider/model unknown"),
            ("/private/tmp/provider-sentinel", "grok-4.6", False, False, "Provider/model unknown"),
            ("xai", "sk-live-credential-sentinel", False, False, "Provider/model unknown"),
            ("xai", "grok-4.6", True, False, "Provider/model unknown"),
        ]

        for provider_id, model_id, stale, known, label in cases:
            fixture = self.live_powerswarm_fixture()
            fixture["selectedRun"]["providerId"] = provider_id
            fixture["selectedRun"]["modelId"] = model_id
            fixture["stale"] = stale
            projected = self.run_browser_projection(
                "powerSwarmRuntimeTruth(fixture.selectedRun,Boolean(fixture.stale))",
                fixture,
            )
            with self.subTest(provider=provider_id, model=model_id, stale=stale):
                self.assertEqual(projected["known"], known)
                self.assertEqual(projected["label"], label)
                if known:
                    self.assertEqual(projected["providerId"], "xai")
                    self.assertEqual(projected["modelId"], "grok-4.6")
                else:
                    self.assertIsNone(projected["providerId"])
                    self.assertIsNone(projected["modelId"])
                    self.assertNotIn(str(provider_id), json.dumps(projected))
                    self.assertNotIn(str(model_id), json.dumps(projected))

        self.assertIn("const runtimeTruth = powerSwarmRuntimeTruth(run, stale);", activity_monitor.HTML)
        self.assertIn(
            "const runtimeTruth = powerSwarmRuntimeTruth(powerSwarm.selectedRun,Boolean(powerSwarm.stale));",
            activity_monitor.HTML,
        )
        self.assertIn('id="agents-powerswarm-runtime"', activity_monitor.HTML)

    def test_browser_fallback_timestamps_require_explicit_zones_in_both_paths(self):
        mutation = """(()=>{
            const target=fixture.powerSwarm || fixture;
            target.generatedAt='2026-08-21T12:01:02.456789-04:00';
            target.selectedRun.createdAt=0;
            target.selectedRun.updatedAt='2026-08-21T11:59:59';
            target.workers[0].startedAt='/private/tmp/POWERSWARM-TIME-SENTINEL';
            target.workers[0].endedAt='not-a-date';
            target.workers[1].startedAt='2026-08-21T11:55:00+02:30';
            target.workers[1].endedAt=Number.POSITIVE_INFINITY;
            target.recentRuns[0].updatedAt='2026-02-30T12:00:00Z';
            const result=fixture.powerSwarm
                ? staleAgentSnapshotProjection(fixture,'2026-08-21T12:02:03+05:30')
                : stalePowerSwarmProjection(target,'powerswarm-bridge-unavailable','2026-08-21T12:02:03+05:30');
            const projected=fixture.powerSwarm ? result.powerSwarm : result;
            if (projected.workers[1].endedAt !== null) throw new Error('nonfinite timestamp survived');
            return result;
        })()"""
        fixtures = [
            self.live_powerswarm_fixture(),
            {
                "schemaVersion": "ke.activity-monitor-agents.v1",
                "powerSwarm": self.live_powerswarm_fixture(),
                "cpu": {"ok": True},
                "gpu": {"ok": True},
                "aiProcesses": [],
            },
        ]

        for fixture in fixtures:
            with self.subTest(path="agents" if "powerSwarm" in fixture else "dedicated"):
                result = self.run_browser_projection(mutation, fixture)
                projected = result["powerSwarm"] if "powerSwarm" in result else result
                self.assertEqual(projected["observedAt"], "2026-08-21T06:32:03.000Z")
                self.assertEqual(projected["generatedAt"], "2026-08-21T16:01:02.456Z")
                self.assertEqual(projected["selectedRun"]["createdAt"], "1970-01-01T00:00:00.000Z")
                self.assertIsNone(projected["selectedRun"]["updatedAt"])
                self.assertIsNone(projected["workers"][0]["startedAt"])
                self.assertIsNone(projected["workers"][0]["endedAt"])
                self.assertEqual(projected["workers"][1]["startedAt"], "2026-08-21T09:25:00.000Z")
                self.assertIsNone(projected["workers"][1]["endedAt"])
                self.assertIsNone(projected["recentRuns"][0]["updatedAt"])
                self.assertNotIn("POWERSWARM-TIME-SENTINEL", json.dumps(projected))

    def test_browser_fallback_timestamp_range_matches_backend_in_both_paths(self):
        mutation = """(()=>{
            const target=fixture.powerSwarm || fixture;
            target.generatedAt='2026-08-21T12:00:00-00:00';
            target.selectedRun.createdAt='0000-01-01T00:00:00Z';
            target.selectedRun.updatedAt='0001-01-01T00:00:00+00:01';
            target.workers[0].startedAt=0;
            target.workers[0].endedAt=-62135596800000;
            target.workers[1].startedAt=-62135596800001;
            target.workers[1].endedAt=253402300799000;
            target.recentRuns[0].updatedAt=253402300800000;
            target.recentRuns.push({...target.recentRuns[0],id:'historical-overflow',updatedAt:'9999-12-31T23:59:59-00:01'});
            return fixture.powerSwarm
                ? staleAgentSnapshotProjection(fixture,'0001-01-01T00:01:00+00:01')
                : stalePowerSwarmProjection(target,'powerswarm-bridge-unavailable','0001-01-01T00:01:00+00:01');
        })()"""
        fixtures = [
            self.live_powerswarm_fixture(),
            {
                "schemaVersion": "ke.activity-monitor-agents.v1",
                "powerSwarm": self.live_powerswarm_fixture(),
                "cpu": {"ok": True},
                "gpu": {"ok": True},
                "aiProcesses": [],
            },
        ]

        for fixture in fixtures:
            with self.subTest(path="agents" if "powerSwarm" in fixture else "dedicated"):
                result = self.run_browser_projection(mutation, fixture)
                projected = result["powerSwarm"] if "powerSwarm" in result else result
                self.assertEqual(projected["observedAt"], "0001-01-01T00:00:00.000Z")
                self.assertIsNone(projected["generatedAt"])
                self.assertIsNone(projected["selectedRun"]["createdAt"])
                self.assertIsNone(projected["selectedRun"]["updatedAt"])
                self.assertEqual(projected["workers"][0]["startedAt"], "1970-01-01T00:00:00.000Z")
                self.assertEqual(projected["workers"][0]["endedAt"], "0001-01-01T00:00:00.000Z")
                self.assertIsNone(projected["workers"][1]["startedAt"])
                self.assertEqual(projected["workers"][1]["endedAt"], "9999-12-31T23:59:59.000Z")
                self.assertIsNone(projected["recentRuns"][0]["updatedAt"])
                self.assertIsNone(projected["recentRuns"][1]["updatedAt"])

    def test_browser_fallback_enums_are_field_allowlisted_in_both_paths(self):
        mutation = """(()=>{
            const target=fixture.powerSwarm || fixture;
            target.selectedRun.state='totally-invented-run';
            target.selectedRun.runtime='invented-runtime';
            target.selectedRun.parent={
                threadId:'00000000-0000-0000-0000-000000000001',
                agentRole:'invented-role',
                source:'invented-source'
            };
            target.selectedRun.parentObserverCode='invented-observer-code';
            target.workers[0].state='totally-invented-worker';
            target.workers[0].recordedState='totally-invented-recorded';
            target.workers[0].terminalReasonCode='invented-terminal-reason';
            target.workers[0].stage='invented-stage';
            target.workers[0].killCheck='invented-check';
            target.workers[0].toolState='invented-tool-state';
            target.workers[0].errorCode='invented-worker-error';
            target.recentRuns[0].state='invented-recent-state';
            target.nested.state='invented-nested';
            target.nested.errorCode='invented-nested-error';
            target.hierarchy.kind='invented-hierarchy-kind';
            target.hierarchy.state='invented-hierarchy-state';
            target.hierarchy.children[0].kind='invented-child-kind';
            target.hierarchy.children[0].state='invented-child-state';
            return fixture.powerSwarm
                ? staleAgentSnapshotProjection(fixture,'2026-08-21T12:02:00Z')
                : stalePowerSwarmProjection(target,'powerswarm-bridge-unavailable','2026-08-21T12:02:00Z');
        })()"""
        fixtures = [
            self.live_powerswarm_fixture(),
            {
                "schemaVersion": "ke.activity-monitor-agents.v1",
                "powerSwarm": self.live_powerswarm_fixture(),
                "cpu": {"ok": True},
                "gpu": {"ok": True},
                "aiProcesses": [],
            },
        ]

        for fixture in fixtures:
            with self.subTest(path="agents" if "powerSwarm" in fixture else "dedicated"):
                result = self.run_browser_projection(mutation, fixture)
                projected = result["powerSwarm"] if "powerSwarm" in result else result
                run = projected["selectedRun"]
                worker = projected["workers"][0]
                self.assertEqual(run["state"], "unknown")
                self.assertEqual(run["runtime"], "unknown")
                self.assertEqual(run["parent"]["agentRole"], "unknown")
                self.assertEqual(run["parent"]["source"], "unknown")
                self.assertIsNone(run["parentObserverCode"])
                self.assertEqual(worker["state"], "unknown")
                self.assertIsNone(worker["recordedState"])
                self.assertIsNone(worker["terminalReasonCode"])
                self.assertEqual(worker["stage"], "unknown")
                self.assertIsNone(worker["killCheck"])
                self.assertIsNone(worker["toolState"])
                self.assertIsNone(worker["errorCode"])
                self.assertEqual(projected["recentRuns"][0]["state"], "unknown")
                self.assertEqual(projected["nested"]["state"], "invalid")
                self.assertIsNone(projected["nested"]["errorCode"])
                self.assertIsNone(projected["hierarchy"]["kind"])
                self.assertEqual(projected["hierarchy"]["state"], "unknown")
                self.assertIsNone(projected["hierarchy"]["children"][0]["kind"])
                self.assertEqual(projected["hierarchy"]["children"][0]["state"], "unknown")
                self.assertEqual(projected["workers"][1]["state"], "verified")
                self.assertEqual(projected["workers"][1]["recordedState"], "review-ready")
                self.assertEqual(projected["workers"][1]["stage"], "bug-sweep")
                self.assertNotIn("invented-", json.dumps(projected))

        projection_source = activity_monitor.HTML[
            activity_monitor.HTML.index("function stalePowerSwarmProjection"):
            activity_monitor.HTML.index("function powerSwarmErrorText")
        ]
        self.assertNotIn("Date.parse", projection_source)
        self.assertNotIn("safeToken", projection_source)

    def test_live_ledger_pid_automatically_wins_over_runtime_regex(self):
        process = SimpleNamespace(
            info={
                "pid": 1101,
                "ppid": 1,
                "name": "node",
                "username": "alex",
                "cpu_percent": 4.2,
                "memory_info": SimpleNamespace(rss=1024),
                "memory_percent": 0.1,
                "num_threads": 3,
                "status": "running",
                "create_time": 1,
                "cmdline": ["node", "worker.js"],
                "uids": None,
            }
        )
        payload = {
            "powerSwarm": {
                "processes": [
                    {
                        "pid": 1101,
                        "role": "worker",
                        "runId": RUN_A,
                        "workerId": "exact-worker",
                        "label": "exact-worker",
                        "state": "running",
                        "stage": "speed-dev",
                    }
                ]
            }
        }
        with patch.object(activity_monitor.psutil, "process_iter", return_value=[process]):
            rows = activity_monitor._collect_ai_processes(payload)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["category"], "PowerSwarm worker")
        self.assertEqual(rows[0]["confidence"], "run-ledger")
        self.assertEqual(rows[0]["powerSwarmRun"], RUN_A)
        self.assertTrue(rows[0]["registered"])

    def test_api_exposes_read_only_tree_and_worker_bridges(self):
        class FakePowerSwarm:
            def snapshot(self, run_id=None, force=False):
                return {"ok": True, "schemaVersion": SCHEMA_VERSION, "selected": run_id, "force": force}

            def worker_detail(self, run_id, worker_id):
                return {"ok": True, "schemaVersion": SCHEMA_VERSION, "run": run_id, "worker": worker_id}

        api = activity_monitor.Api(
            brain_service=object(),
            dispatch_service=object(),
            guard_service=object(),
            powerswarm_service=FakePowerSwarm(),
        )
        tree = json.loads(api.get_powerswarm_activity(RUN_A, True))
        detail = json.loads(api.get_powerswarm_worker(RUN_A, "checked"))
        self.assertEqual(tree["selected"], RUN_A)
        self.assertTrue(tree["force"])
        self.assertEqual(detail["worker"], "checked")

    def test_html_has_compact_clickable_automatic_view_without_controls(self):
        html = activity_monitor.HTML
        toolbar = html[html.index('<div class="segmented-control">'):html.index('<div class="search-box">')]
        labels = re.findall(r'data-tab="[^"]+">([^<]+)</button>', toolbar)
        self.assertEqual(labels, ["CPU", "Memory", "Energy", "Disk", "Network", "Agents", "AI Brain", "Dispatch", "KE Guard"])
        self.assertNotIn('data-tab="powerswarm"', toolbar)
        self.assertIn('id="agents-powerswarm-open"', html)
        self.assertIn('id="powerswarm-back"', html)
        self.assertIn('id="powerswarm-tab"', html)
        self.assertIn("get_powerswarm_activity", html)
        self.assertIn("get_powerswarm_worker", html)
        self.assertIn("data-powerswarm-worker", html)
        self.assertIn("Logical subdirector", html)
        self.assertIn("No active recursion", html)
        self.assertIn("currentTab === 'agents' || currentTab === 'powerswarm' ? 3000", html)
        surface = html[html.index('<div id="powerswarm-tab"'):html.index('<div id="brain-tab"')]
        for forbidden in ("Start", "Launch", "Cancel", "Recover", "Retry", "Stop"):
            self.assertNotIn(forbidden, surface)
        script_surface = html[html.index("function powerSwarmErrorText"):html.index("async function loadBrain")]
        self.assertIn("payload?.truncation?.any", script_surface)
        self.assertIn("esc(run.objective)", script_surface)
        self.assertIn("esc(worker.aim ||", script_surface)
        self.assertNotIn("String(error)", script_surface)

    def test_packaging_preserves_the_powerswarm_observer_source(self):
        spec = (ROOT / "activity_monitor.spec").read_text()
        package = (ROOT / "package_app.zsh").read_text()
        self.assertIn('(os.path.join(ROOT, "powerswarm_discovery.py"), "source")', spec)
        self.assertRegex(
            package,
            r"py_compile activity_monitor\.py brain_discovery\.py dispatch_router\.py "
            r"guard_status\.py workspace_browser\.py powerswarm_discovery\.py",
        )
        self.assertIn('cmp powerswarm_discovery.py "$bundle/Contents/Resources/source/powerswarm_discovery.py"', package)

    def test_embedded_javascript_still_parses(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            completed = subprocess.run(["node", "--check", path], text=True, capture_output=True, timeout=8)
        finally:
            Path(path).unlink()
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
