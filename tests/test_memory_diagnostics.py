import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_diagnostics import (  # noqa: E402
    DEFAULT_SAMPLE_SECONDS,
    GIB,
    MIB,
    MemoryDiagnosticsService,
    MemorySourceError,
    READ_ONLY_BOUNDARY,
    SCHEMA_VERSION,
    SourceChainError,
    _parse_vm_stat,
)
import activity_monitor  # noqa: E402


class FakePsutil:
    def __init__(self, *, process_samples=None, swap_samples=None, disk_free=120 * GIB, headroom=40 * GIB):
        self.process_samples = list(process_samples or [{}, {}, {}])
        self.swap_samples = list(swap_samples or [(2 * GIB, 0, 0)] * 3)
        self.process_index = 0
        self.swap_index = 0
        self.disk_free = disk_free
        self.headroom = headroom

    def virtual_memory(self):
        return SimpleNamespace(
            total=100 * GIB,
            available=self.headroom,
            used=100 * GIB - self.headroom,
            wired=8 * GIB,
            inactive=12 * GIB,
            percent=60.0,
        )

    def swap_memory(self):
        used, sin, sout = self.swap_samples[min(self.swap_index, len(self.swap_samples) - 1)]
        self.swap_index += 1
        return SimpleNamespace(used=used, sin=sin, sout=sout)

    def disk_usage(self, _path):
        return SimpleNamespace(total=500 * GIB, free=self.disk_free)

    def process_iter(self, _attrs):
        sample = self.process_samples[min(self.process_index, len(self.process_samples) - 1)]
        self.process_index += 1
        return [
            SimpleNamespace(info={
                "pid": pid,
                "name": row[0],
                "create_time": row[1],
                "memory_info": SimpleNamespace(rss=row[2]),
            })
            for pid, row in sample.items()
        ]


def vm_stat(*, compressions=100, decompressions=50, occupied=1000, pageins=400, pageouts=25):
    return f"""Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free: 100000.
Pages active: 200000.
Pages inactive: 300000.
Pages speculative: 1000.
Pages wired down: 50000.
Pages occupied by compressor: {occupied}.
Pages stored in compressor: 2000.
Compressions: {compressions}.
Decompressions: {decompressions}.
Pageins: {pageins}.
Pageouts: {pageouts}.
"""


def top_summary(*, compressor="10G"):
    return f"""Processes: 100 total, 2 running, 98 sleeping
PhysMem: 80G used (8G wired, {compressor} compressor), 20G unused.
VM: 5T vsize, 400(0) swapins, 25(0) swapouts.
"""


def statvfs(_path=None, *, total=500 * GIB, free=120 * GIB):
    block = 4096
    return SimpleNamespace(f_frsize=block, f_bsize=block, f_blocks=total // block, f_bavail=free // block)


class MemoryDiagnosticsTests(unittest.TestCase):
    def _service(
        self,
        fake,
        *,
        pressure=45,
        vm_stats=None,
        sample_seconds=12,
        sleeper=lambda _seconds: None,
        faults=None,
        command_reader=None,
        statvfs_reader=statvfs,
        source_attempts=2,
        source_retry_seconds=0,
    ):
        stats = list(vm_stats or [vm_stat(), vm_stat(), vm_stat()])
        calls = {"vm": 0}

        def command(args, _timeout):
            if args[:2] == ["/usr/bin/memory_pressure", "-Q"]:
                return f"System-wide memory free percentage: {pressure}%\n"
            if args == ["/usr/bin/vm_stat"]:
                index = min(calls["vm"], len(stats) - 1)
                calls["vm"] += 1
                return stats[index]
            if args == ["/usr/sbin/sysctl", "-n", "hw.memsize"]:
                return str(100 * GIB)
            if args == ["/usr/sbin/sysctl", "vm.swapusage"]:
                return "vm.swapusage: total = 4096.00M  used = 2048.00M  free = 2048.00M  (encrypted)"
            if args[:3] == ["/usr/bin/top", "-l", "1"]:
                return top_summary()
            if args[:3] == ["/bin/ps", "-axo", "pid=,rss=,comm="]:
                return " 42 307200 /Applications/Example.app/Contents/MacOS/Example\n"
            raise AssertionError(f"unexpected command: {args}")

        return MemoryDiagnosticsService(
            psutil_module=fake,
            command_reader=command_reader or command,
            statvfs_reader=statvfs_reader,
            sleeper=sleeper,
            clock=lambda: 1_700_000_000.0,
            sample_seconds=sample_seconds,
            platform_name="darwin",
            disk_path="/private/var/vm",
            current_pid=99999,
            faults=faults,
            source_attempts=source_attempts,
            source_retry_seconds=source_retry_seconds,
        )

    def test_default_run_is_bounded_read_only_and_healthy(self):
        sleeps = []
        fake = FakePsutil(process_samples=[{10: ("Example", 1.0, 300 * MIB)}] * 3)
        service = self._service(fake, sleeper=sleeps.append)
        payload = service.run()

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["schemaVersion"], SCHEMA_VERSION)
        self.assertEqual(payload["verdict"], "healthy")
        self.assertEqual(payload["sampleCount"], 3)
        self.assertEqual(payload["sampleSeconds"], DEFAULT_SAMPLE_SECONDS)
        self.assertEqual(sleeps, [DEFAULT_SAMPLE_SECONDS / 2] * 2)
        self.assertEqual(payload["boundary"], READ_ONLY_BOUNDARY)
        self.assertFalse(payload["boundary"]["processSignals"])
        self.assertFalse(payload["boundary"]["automaticRepair"])
        self.assertIn("no processes or workloads were changed", payload["reportText"])
        self.assertTrue(all(finding["displayValue"] for finding in payload["findings"]))

    def test_critical_pressure_swap_and_disk_are_reported_without_action(self):
        fake = FakePsutil(
            swap_samples=[
                (8 * GIB, 0, 0),
                (8 * GIB, 0, 256 * MIB),
                (8 * GIB, 0, 768 * MIB),
            ],
            disk_free=4 * GIB,
            headroom=5 * GIB,
        )
        payload = self._service(fake, pressure=5).run()
        findings = {row["id"]: row for row in payload["findings"]}

        self.assertEqual(payload["verdict"], "critical")
        self.assertEqual(findings["pressure"]["status"], "critical")
        self.assertEqual(findings["swap"]["status"], "critical")
        self.assertEqual(findings["swap-disk"]["status"], "critical")
        self.assertFalse(payload["boundary"]["cleanup"])
        self.assertFalse(payload["boundary"]["processTermination"])

    def test_process_growth_is_cautious_evidence_not_a_leak_diagnosis(self):
        samples = [
            {42: ("Growing App", 10.0, 300 * MIB)},
            {42: ("Growing App", 10.0, 400 * MIB)},
            {42: ("Growing App", 10.0, 600 * MIB)},
        ]
        payload = self._service(FakePsutil(process_samples=samples)).run()
        finding = {row["id"]: row for row in payload["findings"]}["process-growth"]

        self.assertEqual(finding["status"], "attention")
        self.assertEqual(finding["evidence"]["items"][0]["growthBytes"], 300 * MIB)
        self.assertIn("repeat the test", finding["summary"])
        self.assertNotIn("leak detected", json.dumps(payload).lower())
        self.assertIn("not a leak diagnosis", finding["evidence"]["claimBoundary"])

    def test_process_spike_without_middle_sample_support_is_not_flagged(self):
        samples = [
            {42: ("Spiky App", 10.0, 300 * MIB)},
            {42: ("Spiky App", 10.0, 300 * MIB)},
            {42: ("Spiky App", 10.0, 700 * MIB)},
        ]
        payload = self._service(FakePsutil(process_samples=samples)).run()
        finding = {row["id"]: row for row in payload["findings"]}["process-growth"]
        self.assertEqual(finding["status"], "healthy")
        self.assertEqual(finding["evidence"]["items"], [])

    def test_pressure_primary_failure_recovers_through_measured_fallback(self):
        payload = self._service(
            FakePsutil(),
            sample_seconds=0,
            faults={"pressure.memory_pressure"},
        ).run()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["sources"]["pressure"]["selected"], "pressure.memory_snapshot")
        self.assertTrue(payload["sources"]["pressure"]["usedFallback"])
        self.assertIn("pressure", payload["fallbacksUsed"])

    def test_paging_primary_failure_recovers_and_zero_delta_is_healthy(self):
        payload = self._service(
            FakePsutil(),
            sample_seconds=0,
            faults={"paging.psutil"},
            vm_stats=[vm_stat(pageins=400, pageouts=25)] * 3,
        ).run()
        finding = {row["id"]: row for row in payload["findings"]}["swap"]
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["sources"]["swap"]["selected"], "paging.vm_stat_sysctl")
        self.assertEqual(finding["status"], "healthy")
        self.assertEqual(finding["evidence"]["swapOutBytesDelta"], 0)
        self.assertEqual(finding["displayValue"], "No swap-out growth")

    def test_compression_primary_failure_recovers_with_top_occupancy(self):
        payload = self._service(
            FakePsutil(),
            sample_seconds=0,
            faults={"compression.vm_stat"},
        ).run()
        finding = {row["id"]: row for row in payload["findings"]}["compressor"]
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["sources"]["compressor"]["selected"], "compression.top")
        self.assertEqual(finding["displayValue"], "10.0 GB occupied")
        self.assertFalse(finding["evidence"]["activityDeltasAvailable"])

    def test_process_primary_failure_recovers_with_bounded_ps_sample(self):
        payload = self._service(
            FakePsutil(),
            sample_seconds=0,
            faults={"process.psutil"},
        ).run()
        finding = {row["id"]: row for row in payload["findings"]}["process-growth"]
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["sources"]["process-growth"]["selected"], "process.ps")
        self.assertEqual(finding["status"], "healthy")

    def test_swap_storage_primary_failure_recovers_with_statvfs(self):
        payload = self._service(
            FakePsutil(),
            sample_seconds=0,
            faults={"swap-storage.psutil"},
        ).run()
        finding = {row["id"]: row for row in payload["findings"]}["swap-disk"]
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["sources"]["swap-disk"]["selected"], "swap-storage.statvfs")
        self.assertEqual(finding["displayValue"], "120.0 GB free")

    def test_prior_valid_finding_is_timestamped_and_retained_after_bounded_failure(self):
        service = self._service(FakePsutil(), sample_seconds=0)
        first = service.run()
        self.assertTrue(first["ok"])
        service._faults.update({"compression.vm_stat", "compression.top"})
        second = service.run()
        finding = {row["id"]: row for row in second["findings"]}["compressor"]
        self.assertTrue(second["ok"])
        self.assertEqual(second["retainedCount"], 1)
        self.assertTrue(finding["stale"])
        self.assertEqual(finding["freshness"], "retained-last-valid")
        self.assertIn(first["finishedAt"], finding["summary"])
        self.assertIn("retained", finding["displayValue"])

    def test_source_retry_is_strictly_bounded(self):
        service = self._service(
            FakePsutil(),
            sample_seconds=0,
            faults={"pressure.memory_pressure", "pressure.memory_snapshot"},
            source_attempts=2,
        )
        with self.assertRaises(SourceChainError) as caught:
            service._resolve_pressure({"totalBytes": 100, "availableBytes": 50})
        error = caught.exception.public(label="Pressure")
        self.assertEqual(error["attemptLimit"], 2)
        self.assertEqual(len(error["failedSources"]), 4)
        self.assertEqual({row["attempt"] for row in error["failedSources"]}, {1, 2})

    def test_total_source_failure_is_actionable_and_never_fabricates_cards(self):
        class BrokenPsutil:
            def __getattr__(self, _name):
                return lambda *args, **kwargs: (_ for _ in ()).throw(MemorySourceError("forced_primary_failure"))

        def broken_command(_args, _timeout):
            raise MemorySourceError("forced_command_failure")

        def broken_statvfs(_path):
            raise MemorySourceError("forced_statvfs_failure")

        service = MemoryDiagnosticsService(
            psutil_module=BrokenPsutil(),
            command_reader=broken_command,
            statvfs_reader=broken_statvfs,
            sleeper=lambda _seconds: None,
            clock=lambda: 1_700_000_000.0,
            sample_seconds=0,
            platform_name="darwin",
            disk_path="/private/var/vm",
            current_pid=99999,
            source_attempts=2,
            source_retry_seconds=0,
        )
        payload = service.run()
        encoded = json.dumps(payload)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "memory_source_chain_failed")
        self.assertEqual(payload["findings"], [])
        self.assertEqual(len(payload["errors"]), 5)
        self.assertTrue(payload["retryable"])
        self.assertEqual(payload["actionLabel"], "Retry")
        self.assertNotIn("unavailable", encoded.lower())
        self.assertTrue(all(error["failedSources"] for error in payload["errors"]))

    def test_base_memory_metrics_fall_back_as_one_complete_measured_snapshot(self):
        snapshot = self._service(
            FakePsutil(),
            sample_seconds=0,
            faults={"memory.psutil", "swap-used.psutil", "pressure.memory_pressure"},
        ).base_snapshot()
        self.assertTrue(snapshot["ok"])
        self.assertFalse(snapshot["stale"])
        self.assertEqual(snapshot["sources"]["memory"]["selected"], "memory.vm_stat_sysctl")
        self.assertEqual(snapshot["sources"]["swapUsed"]["selected"], "swap-used.sysctl")
        self.assertEqual(snapshot["sources"]["pressure"]["selected"], "pressure.memory_snapshot")
        for key in ("total_gb", "used_gb", "available_gb", "wired_gb", "swap_used_gb"):
            self.assertGreaterEqual(snapshot[key], 0)

    def test_base_memory_retains_last_valid_snapshot_instead_of_replacing_values(self):
        service = self._service(FakePsutil(), sample_seconds=0)
        first = service.base_snapshot()
        service._faults.update({
            "memory.psutil", "memory.vm_stat_sysctl",
            "swap-used.psutil", "swap-used.sysctl",
            "pressure.memory_pressure", "pressure.memory_snapshot",
        })
        retained = service.base_snapshot()
        self.assertTrue(retained["ok"])
        self.assertTrue(retained["stale"])
        self.assertEqual(retained["freshness"], "retained-last-valid")
        self.assertEqual(retained["total_gb"], first["total_gb"])
        self.assertEqual(retained["swap_used_gb"], first["swap_used_gb"])
        self.assertTrue(retained["sourceErrors"])

    def test_second_run_fails_fast_while_sampling(self):
        entered = threading.Event()
        release = threading.Event()

        def sleeper(_seconds):
            entered.set()
            release.wait(timeout=2)

        service = self._service(FakePsutil(), sleeper=sleeper)
        result = {}
        worker = threading.Thread(target=lambda: result.setdefault("first", service.run()))
        worker.start()
        self.assertTrue(entered.wait(timeout=1))
        second = service.run()
        release.set()
        worker.join(timeout=2)

        self.assertEqual(second["code"], "diagnostic_in_progress")
        self.assertFalse(second["ok"])
        self.assertTrue(result["first"]["ok"])

    def test_vm_stat_parser_uses_reported_page_size(self):
        parsed = _parse_vm_stat(vm_stat(compressions=123, decompressions=45, occupied=67))
        self.assertEqual(parsed["pageSizeBytes"], 16384)
        self.assertEqual(parsed["compressions"], 123)
        self.assertEqual(parsed["decompressions"], 45)
        self.assertEqual(parsed["pagesOccupied"], 67)
        self.assertEqual(parsed["pageIns"], 400)
        self.assertEqual(parsed["pageOuts"], 25)

    def test_installed_canary_fault_requires_explicit_double_environment_gate(self):
        with patch.dict(os.environ, {
            "KE_ACTIVITY_MONITOR_MEMORY_CANARY": "0",
            "KE_ACTIVITY_MONITOR_MEMORY_CANARY_FAULTS": "pressure-primary",
        }, clear=False):
            self.assertEqual(MemoryDiagnosticsService._environment_faults(), set())
        with patch.dict(os.environ, {
            "KE_ACTIVITY_MONITOR_MEMORY_CANARY": "1",
            "KE_ACTIVITY_MONITOR_MEMORY_CANARY_FAULTS": "pressure-primary,compression-primary",
        }, clear=False):
            self.assertEqual(
                MemoryDiagnosticsService._environment_faults(),
                {"pressure.memory_pressure", "compression.vm_stat"},
            )

    def test_api_exposes_service_result_without_changing_it(self):
        expected = {
            "ok": True,
            "schemaVersion": SCHEMA_VERSION,
            "verdict": "healthy",
            "findings": [],
            "boundary": READ_ONLY_BOUNDARY,
        }

        class StubService:
            def run(self):
                return expected

        payload = json.loads(activity_monitor.Api(memory_diagnostics_service=StubService()).run_memory_diagnostics())
        self.assertEqual(payload, expected)

    def test_memory_panel_requires_explicit_run_and_copy_actions(self):
        html = activity_monitor.HTML
        self.assertIn('id="memory-diagnostics-run"', html)
        self.assertIn('id="memory-diagnostics-copy" disabled', html)
        self.assertIn('id="memory-diagnostics-progress" hidden', html)
        self.assertIn("pywebview.api.run_memory_diagnostics", html)
        self.assertIn("if (!apiReady || memoryDiagnosticsRunning) return", html)
        self.assertIn("const MEMORY_DIAGNOSTIC_SAMPLE_SECONDS = 12", html)
        self.assertIn("navigator.clipboard?.writeText", html)
        self.assertIn("finding.displayValue || finding.summary", html)
        self.assertIn("No automatic actions", html)
        self.assertIn('id="memory-diagnostics-error"', html)
        self.assertIn('id="memory-diagnostics-retry"', html)
        self.assertIn("memorySourceFailureCopy", html)
        self.assertIn("renderMemoryBaseSnapshot(data.memory)", html)
        self.assertIn("Recovered ' + fallbackCount", html)
        self.assertNotIn("runMemoryDiagnostics();\nwindow.addEventListener('pywebviewready'", html)

    def test_memory_ui_has_zero_generic_unavailable_result_copy(self):
        html = activity_monitor.HTML
        markup = html[html.index('<div id="memory-tab"'):html.index('<div id="energy-tab"')]
        script = html[html.index("function memorySourceFailureCopy"):html.index("function fallbackCopyText")]
        self.assertNotIn("Unavailable", markup)
        self.assertNotIn("Unavailable", script)
        self.assertNotRegex(markup, r"(?i)>\s*unavailable\s*<")
        self.assertNotIn('finding.status || \'unavailable\'', script)
        self.assertNotIn("diagnostic_unavailable", script)

    def test_memory_ui_total_failure_renders_one_precise_error_and_retry(self):
        html = activity_monitor.HTML
        fixture = html[html.index("function memorySourceFailureCopy"):html.index("function fallbackCopyText")]
        harness = r"""
function classes(){return {values:new Set(),toggle(name,on){if(on)this.values.add(name);else this.values.delete(name)},add(name){this.values.add(name)},remove(name){this.values.delete(name)}}}
function node(){return {hidden:true,disabled:false,textContent:'',title:'',className:'',children:[],classList:classes(),setAttribute(){},append(...items){this.children.push(...items)},appendChild(item){this.children.push(item)},removeChild(){this.children.shift()},get firstChild(){return this.children[0]||null},get childElementCount(){return this.children.length}}}
const verdict=node(), summary=node(), result=node(), findings=node();
result.querySelector=(selector)=>selector.includes('verdict')?verdict:summary;
const nodes={
 'memory-diagnostics-result':result,
 'memory-diagnostics-findings':findings,
 'memory-diagnostics-status':node(),
 'memory-diagnostics-copy':node(),
 'memory-diagnostics-error':node(),
 'memory-diagnostics-error-copy':node(),
 'memory-diagnostics-retry':node(),
 'mem-details':node()
};
global.document={getElementById:(id)=>nodes[id],querySelector:()=>node(),createElement:()=>node()};
let lastMemoryDiagnostics=null, memoryRetryTarget=null, memoryDiagnosticsRunning=false;
function emptyNode(target){target.children=[]}
function observedClock(value){return value}
""" + fixture + r"""
renderMemoryDiagnostics({
 ok:false,code:'memory_source_chain_failed',verdict:'attention',statusLabel:'Retry needed',
 summary:'Pressure measurement stopped after bounded retry.',findings:[],retryable:true,actionLabel:'Retry',
 errors:[{label:'Pressure',failedSources:[{source:'pressure.memory_pressure',code:'exit_1'}]}]
});
process.stdout.write(JSON.stringify({
 errorHidden:nodes['memory-diagnostics-error'].hidden,
 errorCopy:nodes['memory-diagnostics-error-copy'].textContent,
 retry:nodes['memory-diagnostics-retry'].textContent,
 findingCount:findings.childElementCount,
 findingCopy:findings.children[0]?.textContent,
 verdict:verdict.textContent
}));
"""
        completed = subprocess.run(
            ["node", "-e", harness],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=8,
        )
        rendered = json.loads(completed.stdout)
        self.assertFalse(rendered["errorHidden"])
        self.assertIn("pressure.memory_pressure:exit_1", rendered["errorCopy"])
        self.assertEqual(rendered["retry"], "Retry")
        self.assertEqual(rendered["findingCount"], 1)
        self.assertIn("No measured diagnostic value", rendered["findingCopy"])
        self.assertNotIn("unavailable", json.dumps(rendered).lower())

    def test_api_system_info_uses_resilient_base_memory_service(self):
        source = (ROOT / "activity_monitor.py").read_text(encoding="utf-8")
        self.assertIn("memory_snapshot = self._memory_diagnostics_service.base_snapshot()", source)
        self.assertIn('"memory": memory_snapshot', source)

    def test_packaging_carries_diagnostic_source_and_parity_gate(self):
        spec = (ROOT / "activity_monitor.spec").read_text(encoding="utf-8")
        script = (ROOT / "package_app.zsh").read_text(encoding="utf-8")
        self.assertIn('(os.path.join(ROOT, "memory_diagnostics.py"), "source")', spec)
        compile_line = next(line for line in script.splitlines() if " -m py_compile " in line)
        self.assertIn("memory_diagnostics.py", compile_line)
        self.assertIn('/usr/bin/cmp memory_diagnostics.py "$bundle/Contents/Resources/source/memory_diagnostics.py"', script)


if __name__ == "__main__":
    unittest.main()
