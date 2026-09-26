#!/usr/bin/env python3
"""
Activity Monitor — Native macOS app using pywebview + psutil
No Flask, no web server. Direct JS↔Python bridge.
Built by Jarvis 🦈
"""

import json
import functools
from datetime import datetime, timezone
import math
import os
import platform
import re
import signal
import shutil
import socket
import subprocess
import sys
import time
import threading
import webview
import psutil

import process_io

_DATA_VOLUME = '/System/Volumes/Data' if os.path.isdir('/System/Volumes/Data') else '/'

from brain_discovery import BrainService, SCHEMA_VERSION as BRAIN_SCHEMA_VERSION
from cleanup_service import (
    CleanupError,
    CleanupService,
    REVIEW_HELPER_SCHEMA_VERSION,
    SCHEMA_VERSION as CLEANUP_SCHEMA_VERSION,
)
from conversation_host import (
    ClaudeConversationTransport,
    ConversationHostError,
    ConversationHostService,
    SCHEMA_VERSION as CONVERSATION_HOST_SCHEMA_VERSION,
)
from dispatch_router import DispatchError, DispatchService, SCHEMA_VERSION as DISPATCH_SCHEMA_VERSION
from flagship_bridge import FlagshipBridge, baseline_snapshot
from flagship_ui import CAPABILITY_UI_CSS, CAPABILITY_UI_JS, capability_mount_html
from guard_status import GuardService, SCHEMA_VERSION as GUARD_SCHEMA_VERSION
from ke_wizard_launcher import install_ke_wizard_launcher
from memory_diagnostics import (
    MemoryDiagnosticsService,
    READ_ONLY_BOUNDARY as MEMORY_DIAGNOSTICS_BOUNDARY,
    SCHEMA_VERSION as MEMORY_DIAGNOSTICS_SCHEMA_VERSION,
)
from network_fabric import (
    NetworkFabricError,
    NetworkFabricService,
    SCHEMA_VERSION as NETWORK_SCHEMA_VERSION,
    network_error_contract,
)
from network_optimizer import (
    InternetOptimizerError,
    InternetOptimizerService,
    SCHEMA_VERSION as INTERNET_OPTIMIZER_SCHEMA_VERSION,
)
from powerswarm_discovery import PowerSwarmService, SCHEMA_VERSION as POWERSWARM_SCHEMA_VERSION
from workspace_browser import WorkspaceError, WorkspaceService, SCHEMA_VERSION as WORKSPACE_SCHEMA_VERSION

# Track previous I/O for rate calculations
_prev_net = None
_prev_net_time = None
_prev_disk = None
_prev_disk_time = None

def _resource_path(name):
    """Resolve a bundled resource without depending on the developer checkout."""
    roots = [getattr(sys, "_MEIPASS", None), os.path.dirname(os.path.abspath(__file__))]
    for root in roots:
        if root:
            candidate = os.path.join(root, name)
            if os.path.exists(candidate):
                return candidate
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


AGENTS_OBSERVER = _resource_path("agents_snapshot.mjs")
MAX_AGENT_SNAPSHOT_BYTES = 4 * 1024 * 1024
AGENTS_OBSERVER_TIMEOUT_SECONDS = 4.0
GPU_RECOVERY_TIMEOUT_SECONDS = 3.0
STOPPED_CPU_POOL_TTL_SECONDS = 900.0
DISK_CLEANUP_REVIEW_CATEGORIES = (
    "app-caches",
    "logs-crash",
    "package-manager-caches",
    "developer-caches",
    "old-installers",
    "downloads-large",
    "trash",
    "device-backups",
    "local-models",
    "docker-vm",
)


def _current_app_bundle_path():
    """Return the active .app bundle when packaged, otherwise the source root."""
    current = os.path.abspath(sys.executable)
    while current and current != os.path.dirname(current):
        if current.casefold().endswith(".app"):
            return current
        current = os.path.dirname(current)
    return os.path.dirname(os.path.abspath(__file__))


def _cleanup_helper_command():
    """Return an argv-only command for the same trusted Activity Monitor build."""
    executable = os.path.abspath(sys.executable)
    if getattr(sys, "frozen", False):
        return (executable, "--cleanup-scan-helper")
    return (executable, os.path.abspath(__file__), "--cleanup-scan-helper")

_AI_SIGNATURES = (
    ("ChatGPT / Codex", "AI runtime", re.compile(r"(?:^|[^a-z0-9])(?:chatgpt|codex)(?:[^a-z0-9]|$)")),
    ("Claude", "AI runtime", re.compile(r"(?:^|[^a-z0-9])claude(?:[^a-z0-9]|$)|claudefordesktop")),
    ("Grok / GrokCode", "AI runtime", re.compile(r"(?:^|[^a-z0-9])grok(?:code)?(?:[^a-z0-9]|$)|(?:^|[^a-z0-9])xai(?:[^a-z0-9]|$)")),
    ("PowerSwarm / Director", "Agent runtime", re.compile(r"powerswarm|director[-_ ]swarm|director-powerswarm")),
    ("Ollama", "Local model runtime", re.compile(r"(?:^|[^a-z0-9])ollama(?:[^a-z0-9]|$)")),
    ("LM Studio", "Local model runtime", re.compile(r"lm[ _-]?studio|(?:^|[^a-z0-9])lms(?:[^a-z0-9]|$)")),
    ("Local model", "Local model runtime", re.compile(r"llama(?:\.cpp|[-_ ]server)?|vllm|localai|open[-_ ]webui|koboldcpp|text-generation-webui|mlx[_-]lm|comfyui|automatic1111|stable[-_ ]diffusion")),
    ("KE Agent operations", "Agent operations", re.compile(r"ke-agent-rooms|agent[-_ ]daemon|agent[-_ ]board|kea[-_ ]watch|keguard|cpu-workers-service")),
    ("ML workload", "AI workload", re.compile(r"pytorch|(?:^|[^a-z0-9])torch(?:[^a-z0-9]|$)|tensorflow|transformers|diffusers|(?:^|[^a-z0-9])mlx(?:[^a-z0-9]|$)|coreml|metalperformance|mps[_-]")),
)

_CPU_CORE_ATTRIBUTION = {
    "scope": "sampled-coactivity",
    "exactPlacementAvailable": False,
    "boundary": (
        "macOS schedules threads dynamically and ordinary unprivileged process telemetry "
        "does not expose a trustworthy process-to-logical-core placement. Core inspection "
        "therefore combines measured core load with measured process CPU activity and "
        "labels rolling relationships as co-activity, never fixed assignment."
    ),
}


def _sample_cpu_usage():
    """Take one real CPU interval, safe across pywebview bridge threads."""
    per_cpu = psutil.cpu_percent(interval=0.1, percpu=True)
    cpu_times = psutil.cpu_times_percent(interval=0.1, percpu=False)
    return {
        "percent": sum(per_cpu) / len(per_cpu) if per_cpu else 0.0,
        "user": float(getattr(cpu_times, "user", 0.0)),
        "system": float(getattr(cpu_times, "system", 0.0)),
        "idle": float(getattr(cpu_times, "idle", 0.0)),
        "per_cpu": [round(float(value), 1) for value in per_cpu],
    }


def _memory_pressure_snapshot(vm):
    """Read macOS reclaimable headroom without confusing RAM use with pressure."""
    fallback = (float(vm.available) / float(vm.total) * 100.0) if vm.total else 0.0
    headroom = fallback
    source = "psutil.available"
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/usr/bin/memory_pressure", "-Q"],
                capture_output=True,
                text=True,
                timeout=0.75,
                check=False,
            )
            match = re.search(
                r"System-wide memory free percentage:\s*([0-9]+(?:\.[0-9]+)?)%",
                result.stdout or "",
            )
            if result.returncode == 0 and match:
                headroom = float(match.group(1))
                source = "memory_pressure -Q"
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    headroom = max(0.0, min(100.0, headroom))
    state = "critical" if headroom < 8.0 else "pressure" if headroom < 18.0 else "normal"
    return {
        "state": state,
        "headroom_percent": round(headroom, 1),
        "pressure_percent": round(100.0 - headroom, 1),
        "scope": "system-wide",
        "source": source,
        "observed_at": time.time(),
        "detail": (
            "macOS reclaimable-memory headroom when available; psutil available memory is the fallback. "
            "RAM occupancy alone is not treated as memory pressure."
        ),
    }


def _command_text(args, timeout=1.5):
    """Run one bounded read-only hardware command and return clean stdout."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _sysctl_value(name):
    if sys.platform != "darwin":
        return None
    return _command_text(["/usr/sbin/sysctl", "-n", name], timeout=0.75)


@functools.lru_cache(maxsize=1)
def _system_identity():
    """Return only non-sensitive, runtime-derived hardware identity fields."""
    system_name = platform.system() or "Unknown OS"
    os_version = platform.mac_ver()[0] if system_name == "Darwin" else platform.release()
    execution_architecture = platform.machine() or "unknown"
    cpu_model = _sysctl_value("machdep.cpu.brand_string") or platform.processor() or execution_architecture
    machine_model = _sysctl_value("hw.model") or execution_architecture
    translated = _sysctl_value("sysctl.proc_translated") == "1"
    arm_capable = _sysctl_value("hw.optional.arm64") == "1"
    architecture = "arm64" if translated or arm_capable else execution_architecture
    logical = psutil.cpu_count(logical=True) or 0
    physical = psutil.cpu_count(logical=False) or 0
    return {
        "os_name": "macOS" if system_name == "Darwin" else system_name,
        "os_version": os_version or "unknown",
        "architecture": architecture,
        "execution_architecture": execution_architecture,
        "translated": translated,
        "machine_model": machine_model,
        "cpu_model": cpu_model,
        "logical_cpu_count": int(logical),
        "physical_cpu_count": int(physical),
        "hostname": socket.gethostname(),
        "source": "runtime-detected",
    }


def _ioreg_number(block, label):
    match = re.search(rf'"{re.escape(label)}"\s*=\s*(-?[0-9]+)', block)
    return int(match.group(1)) if match else None


def _ioreg_string(block, label):
    match = re.search(rf'"{re.escape(label)}"\s*=\s*"([^"\n]{{0,512}})"', block)
    return match.group(1).strip() if match else None


def _bounded_percent(value):
    if not isinstance(value, (int, float)):
        return None
    return max(0.0, min(100.0, float(value)))


def _parse_ioreg_gpu_devices(text, observed_at=None):
    """Parse Apple AGX telemetry; model and core count come from this Mac."""
    source = str(text or "")
    starts = [match.start() for match in re.finditer(r"^\+-o\s+AGXAccelerator[^\n]*", source, re.MULTILINE)]
    if starts:
        blocks = [source[start:starts[index + 1] if index + 1 < len(starts) else len(source)] for index, start in enumerate(starts)]
    else:
        blocks = [source] if "AGXAccelerator" in source else []
    observed_at = observed_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    devices = []
    for index, block in enumerate(blocks):
        performance_match = re.search(r'"PerformanceStatistics"\s*=\s*\{(.*?)\}', block, re.DOTALL)
        performance = performance_match.group(1) if performance_match else block
        agc_match = re.search(r'"AGCInfo"\s*=\s*\{(.*?)\}', block, re.DOTALL)
        agc = agc_match.group(1) if agc_match else block
        model = _ioreg_string(block, "model") or _ioreg_string(block, "MetalPluginName") or f"Apple GPU {index + 1}"
        devices.append({
            "id": f"gpu_device_{index}",
            "model": model,
            "coreCount": _ioreg_number(block, "gpu-core-count"),
            "backend": "Metal",
            "integrated": True,
            "utilization": {
                "scope": "host-wide",
                "percent": _bounded_percent(_ioreg_number(performance, "Device Utilization %")),
                "rendererPercent": _bounded_percent(_ioreg_number(performance, "Renderer Utilization %")),
                "tilerPercent": _bounded_percent(_ioreg_number(performance, "Tiler Utilization %")),
                "observedAt": observed_at,
                "source": "built-in:ioreg:AGXAccelerator.PerformanceStatistics",
            },
            "memory": {
                "scope": "host-wide",
                "kind": "unified",
                "inUseBytes": _ioreg_number(performance, "In use system memory"),
                "driverInUseBytes": _ioreg_number(performance, "In use system memory (driver)"),
                "allocatedBytes": _ioreg_number(performance, "Alloc system memory"),
                "capacityBytes": None,
                "observedAt": observed_at,
                "source": "built-in:ioreg:AGXAccelerator.PerformanceStatistics",
            },
            "activityHint": {
                "lastSubmissionPid": _ioreg_number(agc, "fLastSubmissionPID"),
                "submissionsSinceLastCheck": _ioreg_number(agc, "fSubmissionsSinceLastCheck"),
                "busyCount": _ioreg_number(agc, "fBusyCount"),
                "confidence": "low",
                "scope": "device-hint",
                "detail": "The driver last-submission PID is a hint, not proof of current GPU ownership or utilization.",
            },
            "provenance": {
                "state": "observed-host-aggregate",
                "source": "built-in:ioreg",
                "observedAt": observed_at,
            },
        })
    return devices


def _size_bytes(value):
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*(KB|MB|GB|TB)", str(value or ""), re.IGNORECASE)
    if not match:
        return None
    multiplier = {"KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}[match.group(2).upper()]
    return int(float(match.group(1)) * multiplier)


def _parse_system_profiler_gpu_devices(text, observed_at=None):
    """Detect integrated or discrete Mac GPUs when AGX counters are unavailable."""
    try:
        rows = json.loads(text or "{}").get("SPDisplaysDataType") or []
    except (AttributeError, json.JSONDecodeError, TypeError):
        return []
    observed_at = observed_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    devices = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        model = row.get("sppci_model") or row.get("spdisplays_chipset-model") or row.get("_name")
        if not model:
            continue
        core_match = re.search(r"[0-9]+", str(row.get("sppci_cores") or ""))
        core_count = int(core_match.group(0)) if core_match else None
        vendor = str(row.get("spdisplays_vendor") or "")
        bus = str(row.get("sppci_bus") or "")
        integrated = "Apple" in vendor or str(model).startswith("Apple ") or "builtin" in bus.lower()
        capacity = None
        for key in ("spdisplays_vram", "spdisplays_vram_shared", "spdisplays_vram_dynamic"):
            capacity = _size_bytes(row.get(key))
            if capacity is not None:
                break
        devices.append({
            "id": f"gpu_device_{len(devices)}",
            "model": str(model),
            "coreCount": core_count,
            "backend": "Metal",
            "integrated": integrated,
            "utilization": {
                "scope": "host-wide",
                "percent": None,
                "rendererPercent": None,
                "tilerPercent": None,
                "observedAt": observed_at,
                "source": "built-in:system_profiler:device-inventory",
            },
            "memory": {
                "scope": "device-inventory",
                "kind": "unified" if integrated else "dedicated",
                "inUseBytes": None,
                "driverInUseBytes": None,
                "allocatedBytes": None,
                "capacityBytes": capacity,
                "observedAt": observed_at,
                "source": "built-in:system_profiler:device-inventory",
            },
            "activityHint": None,
            "provenance": {
                "state": "observed-device-inventory",
                "source": "built-in:system_profiler",
                "observedAt": observed_at,
            },
        })
    return devices


@functools.lru_cache(maxsize=1)
def _profiled_gpu_devices():
    text = _command_text(["/usr/sbin/system_profiler", "SPDisplaysDataType", "-json"], timeout=4.0)
    return _parse_system_profiler_gpu_devices(text) if text else []


def _local_gpu_probe(ioreg_text=None, profiler_text=None, system_name=None):
    """Return fresh local GPU facts without Node or a separately installed plugin."""
    observed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    detected_system = system_name or platform.system()
    if detected_system != "Darwin" and ioreg_text is None and profiler_text is None:
        return {
            "available": False,
            "devices": [],
            "source": "built-in:unsupported-platform",
            "observedAt": observed_at,
            "error": f"GPU telemetry is unavailable for {detected_system or 'this platform'} in this macOS build.",
        }
    if ioreg_text is None:
        ioreg_text = _command_text(["/usr/sbin/ioreg", "-r", "-c", "AGXAccelerator", "-d", "1"], timeout=1.5)
    devices = _parse_ioreg_gpu_devices(ioreg_text, observed_at) if ioreg_text else []
    source = "built-in:ioreg"
    if not devices:
        devices = _parse_system_profiler_gpu_devices(profiler_text, observed_at) if profiler_text is not None else list(_profiled_gpu_devices())
        source = "built-in:system_profiler"
        for device in devices:
            device["utilization"]["observedAt"] = observed_at
            device["memory"]["observedAt"] = observed_at
            device["provenance"]["observedAt"] = observed_at
    return {
        "available": bool(devices),
        "devices": devices,
        "source": source,
        "observedAt": observed_at,
        "error": None if devices else "No supported GPU device was reported by macOS.",
    }


def _local_cpu_worker_section():
    logical = psutil.cpu_count(logical=True) or 0
    load = list(os.getloadavg()) if hasattr(os, "getloadavg") else [0.0, 0.0, 0.0]
    ratio = (load[0] / logical) if logical else 0.0
    vm = psutil.virtual_memory()
    headroom = _memory_pressure_snapshot(vm)
    queue = "critical" if ratio >= 1.5 else "pressure" if ratio >= 1.0 else "healthy"
    return {
        "ok": True,
        "observerVersion": "built-in",
        "fallback": True,
        "stale": False,
        "snapshot": {
            "kind": "cpu-worker-pools",
            "schemaVersion": "ke.activity-monitor-local-cpu.v1",
            "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "host": {
                "name": socket.gethostname(),
                "platform": f"{platform.system().lower()} {platform.release()}",
                "architecture": platform.machine(),
                "logicalCpuCount": int(logical),
                "loadAverage": [round(float(value), 2) for value in load],
                "loadRatio": round(ratio, 2),
                "cpuQueueHealth": queue,
                "totalMemoryBytes": int(vm.total),
                "availableMemoryBytes": int(vm.available),
                "availableMemoryPercent": headroom["headroom_percent"],
                "memoryHealth": headroom["state"],
                "memoryHealthSource": headroom["source"],
            },
            "counts": {"pools": 0, "workers": 0, "live": 0, "busy": 0, "registered": 0},
            "pools": [],
            "boundary": "Built-in host telemetry is active. Installing CPU Workers adds owner-published pool and progress metadata; this app does not invent it.",
        },
    }


def _local_gpu_worker_section():
    probe = _local_gpu_probe()
    vm = psutil.virtual_memory()
    identity = _system_identity()
    available_percent = (float(vm.available) / float(vm.total) * 100.0) if vm.total else None
    active_platform = identity["architecture"] in ("arm64", "aarch64")
    return {
        "ok": True,
        "observerVersion": "built-in",
        "fallback": True,
        "stale": False,
        "snapshot": {
            "kind": "gpu-job-lane",
            "schemaVersion": "ke.activity-monitor-local-gpu.v1",
            "generatedAt": probe["observedAt"],
            "host": {
                "hostname": socket.gethostname(),
                "platform": platform.system().lower(),
                "architecture": identity["architecture"],
                "memory": {
                    "unifiedTotalBytes": int(vm.total) if active_platform else None,
                    "systemTotalBytes": int(vm.total),
                    "osAvailableBytes": int(vm.available),
                    "osAvailablePercent": round(available_percent, 1) if available_percent is not None else None,
                    "scope": "host-wide",
                    "detail": "Apple silicon GPU allocations share system memory." if active_platform else "System memory is reported separately from dedicated GPU memory.",
                },
            },
            "devices": probe["devices"],
            "deviceProbe": {
                "available": probe["available"],
                "source": probe["source"],
                "observedAt": probe["observedAt"],
                "error": probe["error"],
                "attributionBoundary": "Device telemetry is host-wide and is never assigned to a process or job.",
            },
            "lane": {
                "state": "unregistered",
                "activeJobIds": [],
                "activeCount": 0,
                "queuedJobIds": [],
                "staleJobIds": [],
                "ownerJobId": None,
                "ownerTaskId": None,
                "ownerTitle": None,
                "ownerLeaseMode": None,
                "ownerLeaseState": None,
                "contention": False,
                "concurrencyBenchmarkEarned": False,
                "leaseIssues": [],
                "ownershipVerified": False,
                "policy": "One active owner per detected GPU by default; shared concurrency requires explicit owner-published evidence.",
            },
            "counts": {"registered": 0, "shown": 0, "running": 0, "claimed": 0, "queued": 0, "stale": 0, "failed": 0, "hints": 0},
            "jobs": [],
            "hints": [],
            "registry": {"available": False, "issues": [], "schemaVersion": "ke.gpu-job.v1", "note": "GPU job registration is optional and local to the current user."},
            "boundary": "Built-in GPU visibility is read-only. It never starts, stops, signals, schedules, queues, claims, releases, or mutates GPU work. Host utilization is aggregate; per-job values require owner-published telemetry.",
        },
    }


def _built_in_agents_snapshot(observer_error=None):
    observed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {
        "schemaVersion": "ke.activity-monitor-agents.v1",
        "generatedAt": observed_at,
        "observedAt": observed_at,
        "stale": False,
        "builtInFallback": True,
        "cpu": _local_cpu_worker_section(),
        "gpu": _local_gpu_worker_section(),
    }
    if observer_error:
        payload["observerWarning"] = str(observer_error)[:240]
    return payload


def _configure_macos_app_identity():
    """Apply the packaged name and icon to the Python-hosted Cocoa process."""
    if sys.platform != "darwin":
        return
    try:
        from AppKit import NSApplication, NSImage
        from Foundation import NSProcessInfo

        icon_path = _resource_path("AppIcon.icns")
        NSProcessInfo.processInfo().setProcessName_("Activity Monitor")
        icon = NSImage.alloc().initWithContentsOfFile_(icon_path)
        if icon:
            application = NSApplication.sharedApplication()
            application.setApplicationIconImage_(icon)
            application.dockTile().display()
            print("Activity Monitor Dock icon applied from AppIcon.icns", flush=True)
    except Exception:
        # Identity polish must never prevent the monitor itself from opening.
        pass


def _queue_macos_app_identity():
    """Apply Cocoa identity after pywebview has finished creating NSApplication."""
    if sys.platform != "darwin":
        return
    try:
        from PyObjCTools import AppHelper

        AppHelper.callAfter(_configure_macos_app_identity)
    except Exception:
        _configure_macos_app_identity()


def _queue_macos_app_extras(window):
    """Install the Activity Monitor identity and its native companion launcher."""
    _queue_macos_app_identity()
    install_ke_wizard_launcher(window)


def _runtime_text(created_at):
    try:
        elapsed = max(0, int(time.time() - float(created_at)))
    except (TypeError, ValueError):
        return ""
    days, rem = divmod(elapsed, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _registered_processes(payload):
    cpu = {}
    gpu = {}
    powerswarm = {}
    cpu_snapshot = ((payload.get("cpu") or {}).get("snapshot") or {})
    for pool in cpu_snapshot.get("pools") or []:
        for worker in pool.get("workers") or []:
            pid = worker.get("pid")
            if isinstance(pid, int) and pid > 0:
                cpu[pid] = {
                    "label": worker.get("label") or f"Worker {pid}",
                    "pool": pool.get("title") or "CPU worker pool",
                    "registered": bool(pool.get("registered")),
                    "state": worker.get("state"),
                }
    gpu_snapshot = ((payload.get("gpu") or {}).get("snapshot") or {})
    for job in gpu_snapshot.get("jobs") or []:
        for pid in [job.get("pid"), *(job.get("childPids") or [])]:
            if isinstance(pid, int) and pid > 0:
                gpu[pid] = {
                    "label": job.get("title") or f"GPU job {pid}",
                    "pool": "GPU / MPS lane",
                    "registered": True,
                    "state": job.get("state"),
                }
    powerswarm_snapshot = payload.get("powerSwarm") or {}
    for process in powerswarm_snapshot.get("processes") or []:
        if not isinstance(process, dict):
            continue
        pid = process.get("pid")
        if isinstance(pid, int) and pid > 0:
            powerswarm[pid] = {
                "label": process.get("label") or f"PowerSwarm process {pid}",
                "run": process.get("runId") or "PowerSwarm run",
                "role": process.get("role") or "worker",
                "state": process.get("state"),
                "stage": process.get("stage"),
                "worker": process.get("workerId"),
            }
    return cpu, gpu, powerswarm


def _classify_ai_process(name, command, pid, cpu_workers, gpu_jobs, powerswarm_processes=None):
    powerswarm_processes = powerswarm_processes or {}
    if pid in powerswarm_processes:
        meta = powerswarm_processes[pid]
        role = "coordinator" if meta.get("role") == "coordinator" else "worker"
        return {
            "category": f"PowerSwarm {role}",
            "provider": meta["label"],
            "confidence": "run-ledger",
            "reason": "Live PID from the durable PowerSwarm run ledger",
            "group": meta["run"],
            "registered": True,
            "workerState": meta.get("state"),
            "powerSwarmRun": meta.get("run"),
            "powerSwarmWorker": meta.get("worker"),
            "powerSwarmStage": meta.get("stage"),
        }
    if pid in gpu_jobs:
        meta = gpu_jobs[pid]
        return {
            "category": "GPU job",
            "provider": meta["label"],
            "confidence": "owner-published",
            "reason": "Registered GPU job process",
            "group": meta["pool"],
            "registered": True,
            "workerState": meta.get("state"),
        }
    if pid in cpu_workers:
        meta = cpu_workers[pid]
        return {
            "category": "CPU worker",
            "provider": meta["label"],
            "confidence": "observed-worker",
            "reason": "Observed in a CPU worker pool",
            "group": meta["pool"],
            "registered": meta["registered"],
            "workerState": meta.get("state"),
        }
    haystack = f"{name or ''} {command or ''}".lower()
    for provider, category, pattern in _AI_SIGNATURES:
        if pattern.search(haystack):
            return {
                "category": category,
                "provider": provider,
                "confidence": "runtime-match",
                "reason": "Known local AI/runtime signature",
                "group": provider,
                "registered": False,
                "workerState": None,
            }
    return None


def _collect_ai_processes(payload):
    cpu_workers, gpu_jobs, powerswarm_processes = _registered_processes(payload)
    rows = []
    current_uid = os.getuid() if hasattr(os, "getuid") else None
    attrs = [
        "pid", "ppid", "name", "username", "cpu_percent", "memory_info",
        "memory_percent", "num_threads", "status", "create_time", "cmdline", "uids",
    ]
    for process in psutil.process_iter(attrs):
        try:
            info = process.info
            uids = info.get("uids")
            if current_uid is not None and uids is not None and getattr(uids, "real", current_uid) != current_uid:
                continue
            command = " ".join(info.get("cmdline") or [])
            classification = _classify_ai_process(
                info.get("name") or "Unknown",
                command,
                int(info["pid"]),
                cpu_workers,
                gpu_jobs,
                powerswarm_processes,
            )
            if not classification:
                continue
            memory = info.get("memory_info")
            rows.append({
                "pid": int(info["pid"]),
                "ppid": int(info.get("ppid") or 0),
                "name": info.get("name") or "Unknown",
                "cpuPercent": round(float(info.get("cpu_percent") or 0), 1),
                "memoryBytes": int(memory.rss) if memory else 0,
                "memoryPercent": round(float(info.get("memory_percent") or 0), 2),
                "threads": int(info.get("num_threads") or 0),
                "state": info.get("status") or "unknown",
                "runtime": _runtime_text(info.get("create_time")),
                **classification,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError, TypeError, ValueError):
            continue
    rows.sort(key=lambda row: (-row["cpuPercent"], row["provider"].lower(), row["pid"]))
    return rows


def _reconcile_cpu_worker_census(payload, ai_processes):
    """Fail closed when a worker exits between observer and process census.

    The CPU observer and psutil census cannot be captured atomically. A short-
    lived worker can therefore be reported as live by the observer and exit
    before psutil reaches it. Keep the observer's provenance row, but mark that
    worker exited and remove its resource contribution from the same response.
    This makes one API payload internally consistent without inventing liveness
    or depending on any pool name or workload-specific behavior.
    """
    result = json.loads(json.dumps(payload))
    section = result.get("cpu") or {}
    snapshot = section.get("snapshot") or {}
    pools = snapshot.get("pools")
    if not isinstance(pools, list):
        return result

    census_pids = {
        row.get("pid")
        for row in (ai_processes or [])
        if isinstance(row, dict) and isinstance(row.get("pid"), int) and row.get("pid") > 0
    }
    reconciled_count = 0
    for pool in pools:
        if not isinstance(pool, dict):
            continue
        workers = pool.get("workers")
        if not isinstance(workers, list):
            continue
        missing_live = 0
        missing_busy = 0
        missing_cpu = 0.0
        missing_rss = 0
        reconciled_workers = []
        for worker in workers:
            if not isinstance(worker, dict):
                reconciled_workers.append(worker)
                continue
            state = str(worker.get("state") or "").strip().lower()
            pid = worker.get("pid")
            if state == "exited" or not isinstance(pid, int) or pid <= 0 or pid in census_pids:
                reconciled_workers.append(worker)
                continue

            reconciled = dict(worker)
            reconciled["state"] = "exited"
            reconciled["osState"] = None
            reconciled["cpuPercent"] = 0
            reconciled["rssBytes"] = 0
            reconciled["livenessReconciled"] = "absent-from-same-response-process-census"
            reconciled_workers.append(reconciled)
            missing_live += 1
            missing_busy += int(state == "busy")
            try:
                missing_cpu += max(0.0, float(worker.get("cpuPercent") or 0))
            except (TypeError, ValueError):
                pass
            try:
                missing_rss += max(0, int(worker.get("rssBytes") or 0))
            except (TypeError, ValueError):
                pass
            reconciled_count += 1

        if not missing_live:
            continue
        pool["workers"] = reconciled_workers
        totals = dict(pool.get("totals") or {})
        try:
            old_live = max(0, int(totals.get("live") or 0))
        except (TypeError, ValueError):
            old_live = 0
        try:
            old_busy = max(0, int(totals.get("busy") or 0))
        except (TypeError, ValueError):
            old_busy = 0
        try:
            old_cpu = max(0.0, float(totals.get("cpuPercent") or 0))
        except (TypeError, ValueError):
            old_cpu = 0.0
        try:
            old_rss = max(0, int(totals.get("rssBytes") or 0))
        except (TypeError, ValueError):
            old_rss = 0
        new_cpu = max(0.0, old_cpu - missing_cpu)
        totals["live"] = max(0, old_live - missing_live)
        totals["busy"] = max(0, old_busy - missing_busy)
        totals["cpuPercent"] = round(new_cpu, 1)
        totals["rssBytes"] = max(0, old_rss - missing_rss)
        if old_cpu > 0:
            ratio = new_cpu / old_cpu
            for field in ("cpuCoreEquivalents", "hostCpuCapacityPercent"):
                try:
                    totals[field] = round(max(0.0, float(totals.get(field) or 0)) * ratio, 2)
                except (TypeError, ValueError):
                    totals[field] = 0
        elif new_cpu == 0:
            for field in ("cpuCoreEquivalents", "hostCpuCapacityPercent"):
                if field in totals:
                    totals[field] = 0
        pool["totals"] = totals
        if totals["live"] == 0 and not ((pool.get("parent") or {}).get("processAlive") is True):
            pool["runState"] = "stopped"

    if reconciled_count:
        counts = dict(snapshot.get("counts") or {})
        counts.update({
            "pools": len([pool for pool in pools if isinstance(pool, dict)]),
            "workers": sum(len(pool.get("workers") or []) for pool in pools if isinstance(pool, dict)),
            "live": sum(max(0, int(((pool.get("totals") or {}).get("live")) or 0)) for pool in pools if isinstance(pool, dict)),
            "busy": sum(max(0, int(((pool.get("totals") or {}).get("busy")) or 0)) for pool in pools if isinstance(pool, dict)),
            "registered": sum(1 for pool in pools if isinstance(pool, dict) and pool.get("registered") is True),
        })
        snapshot["counts"] = counts
        section["processCensusReconciledWorkers"] = reconciled_count
    section["snapshot"] = snapshot
    result["cpu"] = section
    return result


def _execute_agents_observer(*arguments, timeout):
    node = shutil.which("node") or "/opt/homebrew/bin/node"
    if not os.path.isfile(AGENTS_OBSERVER):
        raise RuntimeError("The built-in Agents observer is unavailable")
    result = subprocess.run(
        [node, AGENTS_OBSERVER, *arguments],
        cwd=os.path.dirname(AGENTS_OBSERVER),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or "observer exited unsuccessfully").strip().splitlines()[-1]
        raise RuntimeError(detail[:240])
    if len(result.stdout.encode("utf-8")) > MAX_AGENT_SNAPSHOT_BYTES:
        raise RuntimeError("The Agents observer response exceeded its 4 MiB boundary")
    payload = json.loads(result.stdout)
    if payload.get("schemaVersion") != "ke.activity-monitor-agents.v1":
        raise RuntimeError("The Agents observer returned an unsupported schema")
    return payload


def _run_agents_observer():
    return _execute_agents_observer(timeout=AGENTS_OBSERVER_TIMEOUT_SECONDS)


def _run_gpu_observer():
    """Collect GPU owner metadata without waiting for the CPU observer."""
    payload = _execute_agents_observer(
        "--section=gpu",
        timeout=GPU_RECOVERY_TIMEOUT_SECONDS,
    )
    section = payload.get("gpu")
    if not isinstance(section, dict) or not section.get("ok"):
        detail = (section or {}).get("error") if isinstance(section, dict) else None
        raise RuntimeError(detail or "The GPU observer returned no current snapshot")
    return section


def _activity_epoch(value):
    """Parse an observer-published activity timestamp without inventing one."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if not math.isfinite(number) or number <= 0:
            return None
        if number > 100_000_000_000:
            number /= 1000.0
        return number
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (OverflowError, TypeError, ValueError):
        return None


def _activity_iso(epoch):
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _cpu_pool_explicit_activity(pool):
    progress = pool.get("progress") or {}
    # CPU Workers' progress.updatedAt is source-published progress evidence. Its
    # current retention timestamps are intentionally not accepted here: that
    # observer contract can derive them from registration or manifest mtime,
    # neither of which proves that work occurred.
    if progress.get("available") is not True:
        return None
    return _activity_epoch(progress.get("updatedAt"))


def _prune_expired_cpu_pools(
    payload,
    *,
    now_epoch=None,
    activity_cache=None,
    current_observation=False,
    retained=False,
):
    """Remove CPU pool cards once their last verifiable activity exceeds 15 minutes.

    Fresh liveness may advance the per-pool evidence clock. Retained or stale
    liveness never does, so observer failures cannot preserve a card forever.
    """
    result = json.loads(json.dumps(payload))
    section = result.get("cpu") or {}
    snapshot = section.get("snapshot") or {}
    pools = snapshot.get("pools")
    if not isinstance(pools, list):
        return result

    now_epoch = float(time.time() if now_epoch is None else now_epoch)
    activity_cache = activity_cache if isinstance(activity_cache, dict) else {}
    snapshot_epoch = _activity_epoch(snapshot.get("generatedAt"))
    if snapshot_epoch is None:
        snapshot_epoch = _activity_epoch(result.get("generatedAt"))
    if snapshot_epoch is not None and snapshot_epoch > now_epoch + 60.0:
        snapshot_epoch = None

    kept = []
    expired = 0
    for index, pool in enumerate(pools):
        if not isinstance(pool, dict):
            continue
        pool_id = str(pool.get("id") or f"observer-index-{index}")
        totals = pool.get("totals") or {}
        try:
            live = max(0, int(totals.get("live") or 0))
        except (TypeError, ValueError):
            live = 0
        parent_alive = (pool.get("parent") or {}).get("processAlive") is True
        explicit = _cpu_pool_explicit_activity(pool)
        if explicit is not None and explicit > now_epoch + 60.0:
            explicit = None
        stored = activity_cache.get(pool_id)
        if not isinstance(stored, (int, float)) or isinstance(stored, bool) or not math.isfinite(float(stored)):
            stored = None
        else:
            stored = float(stored)

        current_liveness = bool(current_observation and (live > 0 or parent_alive))
        if current_liveness:
            observed = snapshot_epoch if snapshot_epoch is not None else now_epoch
            observed = min(now_epoch, observed)
            stored = max(value for value in (stored, explicit, observed) if value is not None)
        elif explicit is not None and (stored is None or explicit > stored):
            stored = explicit
        elif stored is None:
            # The original snapshot time is an upper bound, not proof of new
            # work. Store it once so repeated ordinary reads cannot renew it.
            stored = min(now_epoch, snapshot_epoch if snapshot_epoch is not None else now_epoch)

        activity_cache[pool_id] = stored
        age = max(0.0, now_epoch - stored)
        visible = current_liveness or age <= STOPPED_CPU_POOL_TTL_SECONDS
        if not visible:
            expired += 1
            continue

        retention_info = dict(pool.get("retention") or {})
        retention_info.update({
            "activityMonitorLastVerifiedAt": _activity_iso(stored),
            "activityMonitorInactiveForSeconds": round(age, 3),
            "activityMonitorRetentionSeconds": STOPPED_CPU_POOL_TTL_SECONDS,
        })
        pool["retention"] = retention_info
        # A cache hit or retained fallback may preserve the last observed live
        # count, but only this observer invocation can call that liveness
        # current. Keep the card during its evidence window and label the count
        # as last-observed everywhere else.
        pool["livenessStale"] = bool(
            not current_observation and (live > 0 or parent_alive)
        )
        kept.append(pool)

    snapshot["pools"] = kept
    counts = dict(snapshot.get("counts") or {})

    def total(field):
        value = 0
        for pool in kept:
            try:
                value += max(0, int(((pool.get("totals") or {}).get(field)) or 0))
            except (TypeError, ValueError):
                continue
        return value

    counts.update({
        "pools": len(kept),
        "workers": sum(len(pool.get("workers") or []) for pool in kept),
        "live": total("live"),
        "busy": total("busy"),
        "registered": sum(1 for pool in kept if pool.get("registered") is True),
    })
    snapshot["counts"] = counts
    section["snapshot"] = snapshot
    if retained:
        section["stale"] = True
    section["expiredPoolCount"] = expired
    section["stoppedPoolRetentionSeconds"] = STOPPED_CPU_POOL_TTL_SECONDS
    result["cpu"] = section
    return result


def _cpu_observation_is_current(section):
    if not isinstance(section, dict) or section.get("ok") is not True:
        return False
    discovery = ((section.get("snapshot") or {}).get("discovery") or {})
    state = str(discovery.get("state") or "").strip().lower()
    return state not in {"degraded", "fallback", "stale", "unavailable", "unknown"}


class Api:
    """Exposed to JavaScript via window.pywebview.api"""

    def __init__(
        self,
        brain_service=None,
        dispatch_service=None,
        guard_service=None,
        workspace_service=None,
        memory_diagnostics_service=None,
        network_service=None,
        internet_optimizer_service=None,
        powerswarm_service=None,
        flagship_bridge=None,
        flagship_providers=None,
        cleanup_service=None,
        conversation_host_service=None,
    ):
        self._brain_service = brain_service or BrainService()
        self._workspace_service = workspace_service or WorkspaceService(brain_service=self._brain_service)
        self._dispatch_service = dispatch_service or DispatchService(
            brain_service=self._brain_service,
            workspace_service=self._workspace_service,
        )
        self._conversation_host_service = conversation_host_service or ConversationHostService(
            lambda force=False: self._workspace_service.snapshot(bool(force)),
            claude_transport=ClaudeConversationTransport(live_sender=self._send_hosted_claude),
        )
        self._conversation_host_generation_lock = threading.Lock()
        self._conversation_host_generations = {}
        self._guard_service = guard_service or GuardService()
        self._memory_diagnostics_service = memory_diagnostics_service or MemoryDiagnosticsService()
        self._network_service = network_service or NetworkFabricService()
        self._internet_optimizer_service = internet_optimizer_service or InternetOptimizerService()
        self._powerswarm_service = powerswarm_service or PowerSwarmService()
        self._cleanup_service = cleanup_service or CleanupService(
            current_app_path=_current_app_bundle_path(),
            max_scan_items=100000,
            review_helper_command=_cleanup_helper_command(),
        )
        owner_providers = {
            "workspace": lambda: self._workspace_service.snapshot(False),
            "powerswarm": lambda: self._powerswarm_snapshot(None, False),
        }
        owner_providers.update(dict(flagship_providers or {}))
        self._flagship_bridge = flagship_bridge or FlagshipBridge(
            brain_service=self._brain_service,
            dispatch_service=self._dispatch_service,
            guard_service=self._guard_service,
            agents_provider=self.get_agent_activity,
            providers=owner_providers,
        )
        self._window = None

    def attach_window(self, window):
        self._window = window

    def get_system_info(self):
        global _prev_net, _prev_net_time, _prev_disk, _prev_disk_time

        # CPU — pywebview may dispatch each bridge request on a fresh thread.
        # psutil's non-blocking cpu_percent() is thread-local and intentionally
        # returns a meaningless all-zero value on the first call in that thread.
        # Take one short blocking sample so every refresh is measured rather
        # than intermittently showing the first-call sentinel.
        cpu_sample = _sample_cpu_usage()
        load_avg = list(os.getloadavg())

        # Memory — every displayed row uses the resilient measured source chain.
        memory_snapshot = self._memory_diagnostics_service.base_snapshot()

        # Disk
        # On APFS, '/' is the sealed system snapshot (~15 GB used); the user's data volume is the real usage.
        disk = psutil.disk_usage(_DATA_VOLUME)
        dio_counters = psutil.disk_io_counters()
        now = time.time()
        dio_read_rate = dio_write_rate = 0
        if _prev_disk and _prev_disk_time:
            dt = now - _prev_disk_time
            if dt > 0:
                dio_read_rate = (dio_counters.read_bytes - _prev_disk.read_bytes) / dt
                dio_write_rate = (dio_counters.write_bytes - _prev_disk.write_bytes) / dt
        _prev_disk = dio_counters
        _prev_disk_time = now

        # Network
        net = psutil.net_io_counters()
        net_sent_rate = net_recv_rate = 0
        if _prev_net and _prev_net_time:
            dt = now - _prev_net_time
            if dt > 0:
                net_sent_rate = (net.bytes_sent - _prev_net.bytes_sent) / dt
                net_recv_rate = (net.bytes_recv - _prev_net.bytes_recv) / dt
        _prev_net = net
        _prev_net_time = now

        net_conns = 0
        try:
            net_conns = len(psutil.net_connections(kind='inet'))
        except (psutil.AccessDenied, PermissionError):
            pass

        # Uptime
        boot = psutil.boot_time()
        uptime_secs = int(now - boot)
        days, rem = divmod(uptime_secs, 86400)
        hrs, rem = divmod(rem, 3600)
        mins, _ = divmod(rem, 60)
        uptime_str = f"{days}d {hrs}h {mins}m" if days else f"{hrs}h {mins}m"

        # Totals
        total_procs = len(psutil.pids())
        total_threads = 0
        try:
            for p in psutil.process_iter(['num_threads']):
                total_threads += (p.info['num_threads'] or 0)
        except:
            pass

        return json.dumps({
            "system": _system_identity(),
            "cpu": {
                **cpu_sample,
                "load_avg": load_avg,
            },
            "memory": memory_snapshot,
            "disk": {
                "total_gb": disk.total / (1024**3),
                "used_gb": disk.used / (1024**3),
                "free_gb": disk.free / (1024**3),
                "percent": disk.percent,
                "io": {
                    "read_bytes": dio_counters.read_bytes,
                    "write_bytes": dio_counters.write_bytes,
                    "read_rate": dio_read_rate,
                    "write_rate": dio_write_rate,
                }
            },
            "network": {
                "bytes_sent": net.bytes_sent,
                "bytes_recv": net.bytes_recv,
                "packets_sent": net.packets_sent,
                "packets_recv": net.packets_recv,
                "sent_rate": net_sent_rate,
                "recv_rate": net_recv_rate,
                "connections": net_conns,
            },
            "total_processes": total_procs,
            "total_threads": total_threads,
            "uptime": {"formatted": uptime_str},
        })

    def get_processes(self, sort_by="cpu"):
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent',
                                       'memory_info', 'memory_percent',
                                       'num_threads', 'status', 'create_time']):
            try:
                info = p.info
                mem_mb = (info['memory_info'].rss / (1024*1024)) if info.get('memory_info') else 0
                mem_pct = info.get('memory_percent') or 0

                # Runtime
                rt = ""
                try:
                    elapsed = int(time.time() - info['create_time'])
                    if elapsed >= 3600:
                        rt = f"{elapsed//3600}h {(elapsed%3600)//60}m"
                    else:
                        rt = f"{elapsed//60}m"
                except:
                    pass

                # I/O (fetch separately, may fail)
                read_bytes = write_bytes = read_count = write_count = 0
                try:
                    io = p.io_counters()
                    if io:
                        read_bytes = io.read_bytes
                        write_bytes = io.write_bytes
                        read_count = io.read_count
                        write_count = io.write_count
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    # psutil has no io_counters on macOS; the kernel's rusage keeps the bytes.
                    rusage = process_io.disk_bytes(info['pid'])
                    if rusage is not None:
                        read_bytes, write_bytes = rusage
                    read_count = write_count = None  # macOS keeps bytes, not operation counts

                # Network connections (fetch separately)
                conns = 0
                sent_bytes = recv_bytes = 0
                try:
                    conns = len(p.net_connections(kind='inet'))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Energy impact (estimate from CPU)
                cpu_pct = info.get('cpu_percent') or 0
                energy = cpu_pct * 0.5  # rough estimate

                procs.append({
                    "pid": info['pid'],
                    "name": info['name'] or "Unknown",
                    "username": info.get('username') or "",
                    "cpu_percent": cpu_pct,
                    "memory_mb": mem_mb,
                    "memory_percent": mem_pct,
                    "threads": info.get('num_threads') or 0,
                    "status": info.get('status') or "",
                    "runtime": rt,
                    "read_bytes": read_bytes,
                    "write_bytes": write_bytes,
                    "read_count": read_count,
                    "write_count": write_count,
                    "connections": conns,
                    "sent_bytes": sent_bytes,
                    "recv_bytes": recv_bytes,
                    "energy_impact": energy,
                    "avg_energy_impact": energy * 0.8,
                    "app_nap": "No",
                    "preventing_sleep": "No",
                })
            # A single process can disappear or expose a temporarily unreadable
            # counter between process_iter() and the per-process probes. Keep
            # that race from blanking the entire Energy table.
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, TypeError, ValueError):
                continue

        return json.dumps({"processes": procs})

    def kill_process(self, pid, force=False):
        try:
            p = psutil.Process(pid)
            if force:
                p.kill()
            else:
                p.terminate()
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"success": False, "message": str(e)})

    _agents_cache = {"t": 0.0, "body": None, "last_good": None, "cpu_pool_activity": {}}
    _agents_lock = threading.Lock()

    def _powerswarm_snapshot(self, run_id=None, force=False):
        try:
            return self._powerswarm_service.snapshot(run_id, force=bool(force))
        except Exception as error:
            return PowerSwarmService.unavailable(error)

    def get_powerswarm_activity(self, run_id="", force=False):
        """Return durable run hierarchy and exact live PowerSwarm PIDs only."""
        selected = str(run_id or "").strip() or None
        payload = self._powerswarm_snapshot(selected, force)
        return json.dumps(payload, separators=(",", ":"))

    def get_powerswarm_worker(self, run_id, worker_id):
        """Return metadata-only attempt history for one exact worker target."""
        try:
            payload = self._powerswarm_service.worker_detail(str(run_id), str(worker_id))
        except Exception:
            payload = {
                "ok": False,
                "schemaVersion": POWERSWARM_SCHEMA_VERSION,
                "error": "observer-worker-detail-failed",
                "errorCode": "observer-worker-detail-failed",
            }
        return json.dumps(payload, separators=(",", ":"))

    def get_agent_activity(self):
        """Return one stable, read-only CPU/GPU/AI-process snapshot.

        A transient observer failure never hides the Agents surface. The last
        complete snapshot is retained and explicitly marked stale until a fresh
        observation succeeds.
        """
        now = time.time()
        with self._agents_lock:
            if now - self._agents_cache["t"] < 2.0 and self._agents_cache["body"]:
                cached = json.loads(self._agents_cache["body"])
                cached = _prune_expired_cpu_pools(
                    cached,
                    now_epoch=now,
                    activity_cache=self._agents_cache.setdefault("cpu_pool_activity", {}),
                    current_observation=False,
                    retained=bool((cached.get("cpu") or {}).get("stale")),
                )
                body = json.dumps(cached, separators=(",", ":"))
                self._agents_cache["body"] = body
                return body
            try:
                payload = _run_agents_observer()
                cpu_observer_fresh = _cpu_observation_is_current(payload.get("cpu") or {})
                prior = self._agents_cache.get("last_good") or {}
                degraded = False
                fallback = None
                fallback_active = False
                warnings = []
                for key in ("cpu", "gpu"):
                    section = payload.get(key) or {}
                    if section.get("ok"):
                        if key == "cpu" and not cpu_observer_fresh:
                            section["stale"] = True
                            degraded = True
                            continue
                        section["stale"] = False
                        continue
                    previous = prior.get(key) or {}
                    if previous.get("ok") and previous.get("snapshot") and not previous.get("fallback"):
                        payload[key] = {
                            **previous,
                            "stale": True,
                            "error": section.get("error") or f"{key.upper()} observer unavailable",
                        }
                        degraded = True
                        continue
                    if fallback is None:
                        fallback = _built_in_agents_snapshot()
                    replacement = json.loads(json.dumps(fallback[key]))
                    replacement["observerError"] = section.get("error") or f"{key.upper()} worker plugin unavailable"
                    payload[key] = replacement
                    warnings.append(replacement["observerError"])
                    fallback_active = True
                payload["powerSwarm"] = self._powerswarm_snapshot()
                payload["aiProcesses"] = _collect_ai_processes(payload)
                payload = _reconcile_cpu_worker_census(payload, payload["aiProcesses"])
                payload = _prune_expired_cpu_pools(
                    payload,
                    now_epoch=now,
                    activity_cache=self._agents_cache.setdefault("cpu_pool_activity", {}),
                    current_observation=cpu_observer_fresh,
                    retained=not cpu_observer_fresh,
                )
                payload["cpuCoreAttribution"] = dict(_CPU_CORE_ATTRIBUTION)
                payload["stale"] = degraded
                payload["builtInFallback"] = fallback_active
                if warnings:
                    payload["observerWarnings"] = warnings
                payload["observedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                if not degraded:
                    self._agents_cache["last_good"] = payload
            except Exception as error:
                recovered_gpu = None
                recovery_error = None
                if isinstance(error, subprocess.TimeoutExpired):
                    try:
                        recovered_gpu = _run_gpu_observer()
                    except Exception as gpu_error:
                        recovery_error = str(gpu_error)[:240]
                prior = self._agents_cache.get("last_good")
                if prior and not prior.get("builtInFallback"):
                    payload = json.loads(json.dumps(prior))
                    payload["stale"] = True
                    payload["error"] = str(error)[:240]
                    for key in ("cpu", "gpu"):
                        section = payload.get(key)
                        if isinstance(section, dict):
                            section["stale"] = True
                            section["error"] = payload["error"]
                    if recovered_gpu is not None:
                        payload["gpu"] = json.loads(json.dumps(recovered_gpu))
                        payload["gpu"]["stale"] = False
                        payload["gpu"]["recoveredIndependently"] = True
                        payload["partialSnapshot"] = True
                        payload["observerRecovery"] = "gpu-only-after-combined-timeout"
                    if recovery_error:
                        payload["observerRecoveryWarning"] = recovery_error
                    payload["observedAt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    payload["powerSwarm"] = self._powerswarm_snapshot()
                    payload["aiProcesses"] = _collect_ai_processes(payload)
                    payload = _reconcile_cpu_worker_census(payload, payload["aiProcesses"])
                    payload = _prune_expired_cpu_pools(
                        payload,
                        now_epoch=now,
                        activity_cache=self._agents_cache.setdefault("cpu_pool_activity", {}),
                        current_observation=False,
                        retained=True,
                    )
                    payload["cpuCoreAttribution"] = dict(_CPU_CORE_ATTRIBUTION)
                else:
                    payload = _built_in_agents_snapshot(error)
                    if recovered_gpu is not None:
                        payload["gpu"] = json.loads(json.dumps(recovered_gpu))
                        payload["gpu"]["stale"] = False
                        payload["gpu"]["recoveredIndependently"] = True
                        payload["observerRecovery"] = "gpu-only-after-combined-timeout"
                    if recovery_error:
                        payload["observerRecoveryWarning"] = recovery_error
                    payload["powerSwarm"] = self._powerswarm_snapshot()
                    payload["aiProcesses"] = _collect_ai_processes(payload)
                    payload = _reconcile_cpu_worker_census(payload, payload["aiProcesses"])
                    payload = _prune_expired_cpu_pools(
                        payload,
                        now_epoch=now,
                        activity_cache=self._agents_cache.setdefault("cpu_pool_activity", {}),
                        current_observation=False,
                        retained=True,
                    )
                    payload["cpuCoreAttribution"] = dict(_CPU_CORE_ATTRIBUTION)
                    self._agents_cache["last_good"] = payload
            body = json.dumps(payload, separators=(",", ":"))
            self._agents_cache["t"] = now
            self._agents_cache["body"] = body
            return body

    def _brain_call(self, method, *args):
        """Run one local Brain operation with a stable, fail-soft response."""
        try:
            payload = method(*args)
        except Exception as error:
            payload = {
                "ok": False,
                "schemaVersion": BRAIN_SCHEMA_VERSION,
                "error": str(error)[:300],
                "privacy": {
                    "mode": "metadata-only",
                    "noteBodiesRead": False,
                    "selectedBodyRead": False,
                    "uploads": False,
                    "credentialsUsed": False,
                    "mutationDuringDiscovery": False,
                },
            }
        return json.dumps(payload, separators=(",", ":"))

    def get_brain_inventory(self, force=False):
        return self._brain_call(self._brain_service.scan, bool(force))

    def list_brain_directory(self, brain_id, inventory_revision, relative_path="", page=0, page_size=60):
        return self._brain_call(
            self._brain_service.list_directory,
            str(brain_id),
            str(inventory_revision),
            str(relative_path or ""),
            page,
            page_size,
        )

    def open_brain_note(self, brain_id, inventory_revision, relative_path):
        return self._brain_call(
            self._brain_service.open_note,
            str(brain_id),
            str(inventory_revision),
            str(relative_path or ""),
        )

    def set_brain_connected(self, path, connected):
        return self._brain_call(self._brain_service.set_connected, str(path), bool(connected))

    def repair_brain_connection(self, path):
        if self._window is None:
            return self._brain_call(
                lambda: (_ for _ in ()).throw(
                    ValueError("The native Brain folder picker could not open")
                )
            )
        try:
            selected = self._window.create_file_dialog(webview.FileDialog.FOLDER, allow_multiple=False)
        except Exception:
            selected = None
        if not selected:
            return json.dumps({
                "ok": False,
                "schemaVersion": BRAIN_SCHEMA_VERSION,
                "code": "folder-picker-cancelled",
                "error": "Brain folder selection was cancelled",
                "privacy": {
                    "mode": "metadata-only",
                    "noteBodiesRead": False,
                    "selectedBodyRead": False,
                    "uploads": False,
                    "credentialsUsed": False,
                    "mutationDuringDiscovery": False,
                },
            }, separators=(",", ":"))
        directory = selected[0] if isinstance(selected, (list, tuple)) else selected
        return self._brain_call(
            self._brain_service.repair_connection,
            str(path),
            str(directory),
        )

    def set_brain_ignored(self, path, ignored):
        return self._brain_call(self._brain_service.set_ignored, str(path), bool(ignored))

    def forget_brain(self, path):
        return self._brain_call(self._brain_service.forget, str(path))

    def create_brain(self, name="My AI Brain"):
        return self._brain_call(self._brain_service.create_brain, str(name))

    def preview_brain_structure(self, path):
        return self._brain_call(self._brain_service.preview_structure, str(path))

    def apply_brain_structure(self, preview_id, confirmation):
        return self._brain_call(
            self._brain_service.apply_structure,
            str(preview_id),
            str(confirmation),
        )

    def rollback_brain_structure(self, operation_id):
        return self._brain_call(self._brain_service.rollback_structure, str(operation_id))

    def _dispatch_call(self, method, *args):
        """Expose private local Dispatch operations without leaking tracebacks."""
        is_send = getattr(method, "__name__", "") == "send"
        try:
            payload = method(*args)
        except DispatchError as error:
            receipt = DispatchService._receipt_metadata(error.receipt)
            attempted = bool(error.delivery_attempted or receipt.get("deliveryAttempted") is True)
            reconciliation_required = bool(
                attempted or receipt.get("reconciliationRequired") is True
            )
            explicit_retry = bool(
                is_send
                and not attempted
                and receipt.get("deliveryAttempted") is False
                and receipt.get("retrySafe") is True
                and not reconciliation_required
            )
            payload = {
                "ok": False,
                "schemaVersion": DISPATCH_SCHEMA_VERSION,
                "state": ("uncertain after send" if attempted else "failed before send") if is_send else "failed",
                "code": error.code,
                "error": str(error)[:300],
                "phase": error.phase or receipt.get("phase"),
                "deliveryAttempted": attempted,
                "retrySafe": explicit_retry,
                "reconciliationRequired": reconciliation_required,
                "receipt": receipt,
                "privacy": DispatchService._privacy(),
            }
        except Exception:
            payload = {
                "ok": False,
                "schemaVersion": DISPATCH_SCHEMA_VERSION,
                "state": "uncertain after send" if is_send else "failed",
                "code": "dispatch_internal_error",
                "error": (
                    "The Dispatch bridge was interrupted; reconcile before retrying"
                    if is_send else "Dispatch is temporarily unavailable"
                ),
                "phase": "reconciliation" if is_send else None,
                "deliveryAttempted": bool(is_send),
                "retrySafe": False,
                "reconciliationRequired": bool(is_send),
                "privacy": DispatchService._privacy(),
            }
        return json.dumps(payload, separators=(",", ":"))

    def get_dispatch_state(self):
        return self._dispatch_call(self._dispatch_service.state)

    def resolve_dispatch(self, message):
        return self._dispatch_call(self._dispatch_service.resolve, str(message))

    def send_dispatch(self, resolution_id, target_id, message, diagnostic=False):
        return self._dispatch_call(
            self._dispatch_service.send,
            str(resolution_id),
            str(target_id),
            str(message),
            bool(diagnostic),
        )

    def _workspace_call(self, method, *args):
        try:
            payload = method(*args)
        except WorkspaceError as error:
            payload = {
                "ok": False,
                "schemaVersion": WORKSPACE_SCHEMA_VERSION,
                "code": error.code,
                "error": str(error)[:300],
                "privacy": WorkspaceService._privacy(),
            }
        except Exception:
            payload = {
                "ok": False,
                "schemaVersion": WORKSPACE_SCHEMA_VERSION,
                "code": "workspace_internal_error",
                "error": "The local project browser is temporarily unavailable",
                "privacy": WorkspaceService._privacy(),
            }
        return json.dumps(payload, separators=(",", ":"))

    def get_workspace_state(self, force=False):
        return self._workspace_call(self._workspace_service.snapshot, bool(force))

    def update_workspace_preferences(self, patch):
        return self._workspace_call(self._workspace_service.update_preferences, patch)

    def set_claude_project_saved(self, project_id, saved):
        return self._workspace_call(
            self._workspace_service.set_claude_project_saved,
            str(project_id),
            bool(saved),
        )

    def choose_claude_project_directory(self, project_id):
        if self._window is None:
            return self._workspace_call(
                lambda: (_ for _ in ()).throw(
                    WorkspaceError("folder_picker_unavailable", "The native folder picker is unavailable")
                )
            )
        try:
            selected = self._window.create_file_dialog(webview.FileDialog.FOLDER, allow_multiple=False)
        except Exception:
            selected = None
        if not selected:
            return json.dumps({
                "ok": False,
                "schemaVersion": WORKSPACE_SCHEMA_VERSION,
                "code": "folder_picker_cancelled",
                "error": "No folder was selected",
                "privacy": WorkspaceService._privacy(),
            }, separators=(",", ":"))
        directory = selected[0] if isinstance(selected, (list, tuple)) else selected
        return self._workspace_call(
            self._workspace_service.set_claude_project_directory,
            str(project_id),
            str(directory),
        )

    def open_workspace_conversation(self, provider, conversation_id):
        return self._workspace_call(
            self._workspace_service.open_conversation,
            str(provider),
            str(conversation_id),
        )

    def _send_hosted_claude(self, target, message, request_id):
        """Reuse Dispatch's verified private-session bridge without a second Claude writer."""
        try:
            _, receipt = self._dispatch_service._send_claude(dict(target), str(message), False)
            return dict(receipt or {})
        except DispatchError as error:
            receipt = dict(getattr(error, "receipt", {}) or {})
            attempted = bool(getattr(error, "delivery_attempted", False) or receipt.get("deliveryAttempted"))
            raise ConversationHostError(
                str(getattr(error, "code", "claude_live_delivery_failed")),
                str(error),
                phase=str(getattr(error, "phase", None) or receipt.get("phase") or "exact-session delivery"),
                delivery_attempted=attempted,
                retry_safe=bool(receipt.get("retrySafe")) if "retrySafe" in receipt else not attempted,
                reconciliation_required=(
                    bool(receipt.get("reconciliationRequired"))
                    if "reconciliationRequired" in receipt
                    else attempted
                ),
                receipt=receipt,
            ) from error

    @staticmethod
    def _conversation_host_privacy(body_read=False):
        return ConversationHostService.privacy(body_read=bool(body_read))

    def _conversation_host_call(self, method, *args, generation=None, is_send=False, body_read=False):
        try:
            payload = method(*args)
        except ConversationHostError as error:
            payload = error.public()
            payload["privacy"] = self._conversation_host_privacy(body_read=body_read)
        except Exception:
            payload = {
                "ok": False,
                "schemaVersion": CONVERSATION_HOST_SCHEMA_VERSION,
                "code": "conversation_host_internal_error",
                "error": "The in-app conversation host is temporarily unavailable",
                "phase": "host bridge",
                "deliveryAttempted": bool(is_send),
                "retrySafe": False,
                "reconciliationRequired": bool(is_send),
                "privacy": self._conversation_host_privacy(body_read=body_read),
            }
        if generation is not None:
            payload["generation"] = generation
        return json.dumps(payload, separators=(",", ":"))

    def _bind_conversation_host_generation(self, request_id, generation):
        request_id = str(request_id or "").lower()
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", request_id):
            raise ConversationHostError(
                "client_request_id_invalid",
                "Create one exact request identifier before sending",
                phase="queue preflight",
            )
        if isinstance(generation, bool) or not isinstance(generation, int) or not 1 <= generation <= 2_147_483_647:
            raise ConversationHostError(
                "request_generation_invalid",
                "Refresh the selected conversation before sending",
                phase="queue preflight",
            )
        with self._conversation_host_generation_lock:
            prior = self._conversation_host_generations.get(request_id)
            if prior is not None and prior != generation:
                raise ConversationHostError(
                    "request_generation_conflict",
                    "This queued request belongs to a different conversation generation",
                    phase="queue reconciliation",
                    reconciliation_required=True,
                    retry_safe=False,
                    receipt={"requestId": request_id},
                )
            self._conversation_host_generations[request_id] = generation
            while len(self._conversation_host_generations) > 512:
                self._conversation_host_generations.pop(next(iter(self._conversation_host_generations)))
        return request_id, generation

    def get_project_conversation_host(self, provider, project_id):
        return self._conversation_host_call(
            self._conversation_host_service.project_state,
            str(provider),
            str(project_id),
        )

    def read_hosted_conversation(self, provider, conversation_id, generation):
        if isinstance(generation, bool) or not isinstance(generation, int) or not 1 <= generation <= 2_147_483_647:
            return self._conversation_host_call(
                lambda: (_ for _ in ()).throw(
                    ConversationHostError(
                        "request_generation_invalid",
                        "Refresh the selected conversation before reading it",
                        phase="transcript read",
                    )
                ),
                generation=generation,
                body_read=False,
            )
        return self._conversation_host_call(
            self._conversation_host_service.read_conversation,
            str(provider),
            str(conversation_id),
            generation=generation,
            body_read=True,
        )

    def send_hosted_conversation(self, provider, conversation_id, message, request_id, generation):
        try:
            request_id, generation = self._bind_conversation_host_generation(request_id, generation)
        except ConversationHostError as error:
            return self._conversation_host_call(
                lambda: (_ for _ in ()).throw(error),
                generation=generation,
                is_send=False,
            )
        return self._conversation_host_call(
            self._conversation_host_service.send_conversation,
            str(provider),
            str(conversation_id),
            str(message),
            request_id,
            generation=generation,
            is_send=True,
        )

    def send_project_conductor(self, provider, project_id, message, request_id, generation, route_kind="conductor"):
        try:
            request_id, generation = self._bind_conversation_host_generation(request_id, generation)
        except ConversationHostError as error:
            return self._conversation_host_call(
                lambda: (_ for _ in ()).throw(error),
                generation=generation,
                is_send=False,
            )
        route_kind = str(route_kind or "conductor").lower()
        if route_kind not in {"conductor", "powerswarm"}:
            return self._conversation_host_call(
                lambda: (_ for _ in ()).throw(
                    ConversationHostError(
                        "route_kind_invalid",
                        "Choose Conductor or PowerSwarm before sending",
                        phase="queue preflight",
                    )
                ),
                generation=generation,
                is_send=False,
            )
        routed_message = str(message)
        if route_kind == "powerswarm":
            routed_message = "PowerSwarm request:\n\n" + routed_message
        return self._conversation_host_call(
            self._conversation_host_service.submit,
            str(provider),
            str(project_id),
            routed_message,
            request_id,
            generation=generation,
            is_send=True,
        )

    def reconcile_hosted_request(self, request_id, generation):
        request_id = str(request_id or "").lower()
        if (
            not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", request_id)
            or isinstance(generation, bool)
            or not isinstance(generation, int)
            or not 1 <= generation <= 2_147_483_647
        ):
            return self._conversation_host_call(
                lambda: (_ for _ in ()).throw(
                    ConversationHostError(
                        "reconciliation_identity_invalid",
                        "Choose one exact queued request before reconciling",
                        phase="reconciliation",
                    )
                ),
                generation=generation,
                is_send=False,
            )
        return self._conversation_host_call(
            self._conversation_host_service.reconcile_request,
            request_id,
            generation=generation,
            body_read=True,
        )

    def get_guard_status(self):
        """Return a sanitized, read-only KE Guard projection."""
        try:
            payload = self._guard_service.status()
        except Exception:
            payload = {
                "ok": False,
                "schemaVersion": GUARD_SCHEMA_VERSION,
                "state": "offline",
                "statusLabel": "OFFLINE",
                "supported": True,
                "installed": True,
                "available": False,
                "retained": False,
                "detail": "KE Guard status is temporarily unavailable.",
                "configuredMode": None,
                "observedAt": None,
                "ageSeconds": None,
                "activeSuspects": {"count": 0, "items": []},
                "pendingRemediation": None,
                "kills24h": None,
                "trends": {"load": None, "diskFree": None},
                "recentEvidence": [],
                "ledgerAvailable": False,
                "killsWindowComplete": False,
                "privacy": GuardService._privacy(),
            }
        return json.dumps(payload, separators=(",", ":"))

    def run_memory_diagnostics(self):
        """Run one bounded local sample without gaining process-control authority."""
        try:
            payload = self._memory_diagnostics_service.run()
        except Exception as error:
            payload = {
                "ok": False,
                "schemaVersion": MEMORY_DIAGNOSTICS_SCHEMA_VERSION,
                "code": "diagnostic_bridge_error",
                "verdict": "attention",
                "statusLabel": "Retry needed",
                "summary": f"Memory diagnostic bridge failed with code {type(error).__name__}; measured values were not inferred.",
                "errors": [{
                    "metric": "diagnostic",
                    "label": "Memory diagnostics",
                    "code": type(error).__name__,
                    "attemptLimit": 1,
                    "failedSources": [{
                        "source": "pywebview.bridge",
                        "code": type(error).__name__,
                        "attempt": 1,
                    }],
                    "retryable": True,
                }],
                "findings": [],
                "retryable": True,
                "actionLabel": "Retry",
                "boundary": dict(MEMORY_DIAGNOSTICS_BOUNDARY),
            }
        return json.dumps(payload, separators=(",", ":"))

    def _cleanup_call(self, method, *args):
        """Expose review-only cleanup operations without leaking local paths."""
        try:
            payload = method(*args)
        except CleanupError as error:
            payload = {
                "ok": False,
                "schemaVersion": CLEANUP_SCHEMA_VERSION,
                "state": "failed",
                "code": error.code,
                "error": error.public_message,
                "activityMonitorMutation": False,
            }
        except Exception:
            payload = {
                "ok": False,
                "schemaVersion": CLEANUP_SCHEMA_VERSION,
                "state": "failed",
                "code": "cleanup_internal_error",
                "error": "The cleanup review is temporarily unavailable. Disk monitoring is still active.",
                "activityMonitorMutation": False,
            }
        return json.dumps(payload, separators=(",", ":"))

    def get_disk_cleanup_capabilities(self):
        return self._cleanup_call(self._cleanup_service.capabilities)

    def start_disk_cleanup_scan(self):
        return self._cleanup_call(
            self._cleanup_service.start_analysis,
            {
                "categories": list(DISK_CLEANUP_REVIEW_CATEGORIES),
                "duplicateAnalysis": False,
                "reviewOnly": True,
            },
        )

    def get_disk_cleanup_scan(self, job_id):
        return self._cleanup_call(self._cleanup_service.analysis_status, str(job_id))

    def cancel_disk_cleanup_scan(self, job_id):
        return self._cleanup_call(self._cleanup_service.cancel_analysis, str(job_id))

    def reveal_disk_cleanup_candidates(self, analysis_id, item_ids):
        return self._cleanup_call(
            self._cleanup_service.reveal_candidates,
            str(analysis_id),
            item_ids,
        )

    def open_disk_cleanup_destination(self, destination):
        return self._cleanup_call(
            self._cleanup_service.open_review_destination,
            str(destination),
        )

    def _network_call_from_source(self, source, method, *args):
        """Expose bounded local-network operations with stable error shapes."""
        try:
            payload = method(*args)
        except NetworkFabricError as error:
            safe_error = self._network_service.error_projection(error.code, source)
            payload = {
                "ok": False,
                "schemaVersion": NETWORK_SCHEMA_VERSION,
                "code": safe_error["code"],
                "error": safe_error["message"],
                "errorDetail": safe_error,
                "attempted": error.attempted,
                "state": "uncertain-after-send" if error.attempted else "failed-before-send",
            }
        except Exception:
            safe_error = self._network_service.error_projection("network_internal_error", source)
            payload = {
                "ok": False,
                "schemaVersion": NETWORK_SCHEMA_VERSION,
                "code": safe_error["code"],
                "error": safe_error["message"],
                "errorDetail": safe_error,
                "attempted": False,
                "state": "failed-before-send",
            }
        return json.dumps(payload, separators=(",", ":"))

    def _network_call(self, method, *args):
        return self._network_call_from_source("bridge", method, *args)

    def start_network_discovery(self):
        return self._network_call(self._network_service.start_discovery)

    def stop_network_discovery(self):
        return self._network_call(self._network_service.stop_discovery)

    def get_network_snapshot(self):
        return self._network_call(self._network_service.get_snapshot)

    def request_network_scan(self):
        return self._network_call(self._network_service.request_deep_scan)

    def recover_network_connection(self, code, source=None, device_id=None, after_settings=False, recovery_generation=None):
        if str(source or "") == "internet-optimizer":
            return self._network_call_from_source(
                "internet-optimizer",
                self._recover_internet_optimizer,
                str(code or "internet_optimizer_unavailable"),
                bool(after_settings),
                recovery_generation,
            )
        return self._network_call_from_source(
            str(source or "network"),
            self._network_service.recover_connection,
            str(code or "network_internal_error"),
            None if source is None else str(source),
            None if device_id is None else str(device_id),
            bool(after_settings),
            recovery_generation,
        )

    def _recover_internet_optimizer(self, code, after_settings, expected_generation):
        safe_error = self._network_service.error_projection(code, "internet-optimizer")
        plan = safe_error["recovery"]
        try:
            supplied_generation = int(expected_generation)
        except (TypeError, ValueError):
            supplied_generation = -1
        if supplied_generation != plan["generation"]:
            raise NetworkFabricError("recovery_stale")
        action = plan["action"]
        try:
            if action == "open-wifi-settings" and not after_settings:
                self._internet_optimizer_service.perform_action("open-wifi-settings")
                return {
                    "ok": True,
                    "state": "waiting-for-user",
                    "code": safe_error["code"],
                    "recovery": plan,
                    "autoRetryOnReturn": True,
                    "message": "Review the active Wi-Fi connection, then return; one local Wi-Fi recheck will run.",
                }
            if action in {"retry-internet-optimizer", "open-wifi-settings"}:
                snapshot = self._internet_optimizer_service.analyze()
                return {
                    "ok": True,
                    "state": "optimizer-rechecked",
                    "code": safe_error["code"],
                    "recovery": plan,
                    "optimizerSnapshot": snapshot,
                }
            if action == "retry-internet-test":
                measurement = self._internet_optimizer_service.measure()
                return {
                    "ok": True,
                    "state": "internet-measured",
                    "code": safe_error["code"],
                    "recovery": plan,
                    "internetQuality": measurement,
                }
            if action == "open-network-settings":
                result = self._internet_optimizer_service.perform_action("open-wifi-settings")
                return {
                    "ok": True,
                    "state": "settings-opened",
                    "code": safe_error["code"],
                    "recovery": plan,
                    "settingsResult": result,
                }
        except InternetOptimizerError as error:
            mapped = (
                "wifi_diagnostics_permission_denied"
                if error.code == "permission_denied" and action != "retry-internet-test"
                else "internet_quality_unavailable"
                if action == "retry-internet-test"
                else "internet_optimizer_unavailable"
            )
            raise NetworkFabricError(mapped) from error
        except Exception as error:
            mapped = (
                "internet_quality_unavailable"
                if action == "retry-internet-test"
                else "system_settings_unavailable"
                if action == "open-network-settings"
                else "internet_optimizer_unavailable"
            )
            raise NetworkFabricError(mapped) from error
        raise NetworkFabricError("network_internal_error")

    def set_ke_link_enabled(self, enabled):
        return self._network_call(self._network_service.set_link_enabled, bool(enabled))

    def begin_ke_link_pairing(self):
        return self._network_call(self._network_service.begin_pairing)

    def pair_network_device(self, device_id, code):
        return self._network_call(self._network_service.pair_device, str(device_id), str(code))

    def verify_network_peer(self, device_id):
        return self._network_call(self._network_service.verify_link_session, str(device_id))

    def revoke_network_peer(self, device_id):
        return self._network_call(self._network_service.revoke_peer, str(device_id))

    def revoke_network_trusted_peer(self, peer_id):
        return self._network_call(self._network_service.revoke_trusted_peer, str(peer_id))

    def send_network_message(self, device_id, message, client_message_id):
        return self._network_call(
            self._network_service.send_message,
            str(device_id),
            str(message),
            str(client_message_id),
        )

    def perform_network_action(self, device_id, action, service_id=None):
        return self._network_call(
            self._network_service.perform_action,
            str(device_id),
            str(action),
            None if service_id is None else str(service_id),
        )

    def _internet_optimizer_call(self, operation, method, *args):
        """Keep optimizer errors inside the existing one-click recovery contract."""
        try:
            payload = method(*args)
        except InternetOptimizerError as error:
            if operation == "analyze":
                code = "wifi_diagnostics_permission_denied" if error.code == "permission_denied" else "internet_optimizer_unavailable"
            elif operation == "measure":
                code = "internet_quality_unavailable"
            else:
                code = "system_settings_unavailable"
            safe_error = self._network_service.error_projection(code, "internet-optimizer")
            payload = {
                "ok": False,
                "schemaVersion": INTERNET_OPTIMIZER_SCHEMA_VERSION,
                "code": safe_error["code"],
                "error": safe_error["message"],
                "errorDetail": safe_error,
                "state": "failed-before-change",
                "settingsChanged": False,
            }
        except Exception:
            code = (
                "internet_optimizer_unavailable"
                if operation == "analyze"
                else "internet_quality_unavailable"
                if operation == "measure"
                else "system_settings_unavailable"
            )
            safe_error = self._network_service.error_projection(code, "internet-optimizer")
            payload = {
                "ok": False,
                "schemaVersion": INTERNET_OPTIMIZER_SCHEMA_VERSION,
                "code": safe_error["code"],
                "error": safe_error["message"],
                "errorDetail": safe_error,
                "state": "failed-before-change",
                "settingsChanged": False,
            }
        return json.dumps(payload, separators=(",", ":"))

    def analyze_internet_connection(self):
        return self._internet_optimizer_call("analyze", self._internet_optimizer_service.analyze)

    def measure_internet_quality(self):
        return self._internet_optimizer_call("measure", self._internet_optimizer_service.measure)

    def perform_internet_optimizer_action(self, action_id):
        return self._internet_optimizer_call(
            "action",
            self._internet_optimizer_service.perform_action,
            str(action_id),
        )

    def shutdown(self):
        try:
            self._internet_optimizer_service.shutdown()
        except Exception:
            pass
        return self._network_service.shutdown()

    def get_flagship_capabilities(self, requested_tab="cpu"):
        """Return all 30 native surfaces plus governed PowerSwarm read-only."""
        tab = "agents" if str(requested_tab or "").strip().lower() == "powerswarm" else str(requested_tab or "cpu")
        try:
            return self._flagship_bridge.snapshot_json(tab)
        except Exception:
            try:
                return self._flagship_bridge.failure_snapshot_json(tab)
            except Exception:
                return json.dumps(
                    baseline_snapshot(), separators=(",", ":"), sort_keys=True
                )

    def get_flagship_ui_preferences(self):
        return self._workspace_call(self._workspace_service.flagship_ui_preferences)

    def set_flagship_fabric_collapsed(self, tab, collapsed):
        return self._workspace_call(
            self._workspace_service.set_flagship_fabric_collapsed,
            str(tab),
            bool(collapsed),
        )

    def repair_flagship_capabilities(
        self,
        requested_tab="cpu",
        capability_id=None,
        expected_generation=None,
    ):
        """Rebuild only allowlisted no-I/O Capability Fabric bindings."""
        tab = "agents" if str(requested_tab or "").strip().lower() == "powerswarm" else str(requested_tab or "cpu")
        try:
            generation = int(expected_generation)
        except (TypeError, ValueError, OverflowError):
            generation = None
        try:
            return self._flagship_bridge.repair_json(
                tab,
                None if capability_id is None else str(capability_id),
                generation,
            )
        except Exception:
            return json.dumps(
                {
                    "ok": False,
                    "code": "repair-unavailable",
                    "detail": "The safe local connection check is temporarily unavailable.",
                },
                separators=(",", ":"),
                sort_keys=True,
            )



# The HTML with fetch() calls replaced by pywebview.api bridge calls
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Activity Monitor</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text','Helvetica Neue',sans-serif;background:#171719;color:#1d1d1f;height:100vh;overflow:hidden;font-size:13px;-webkit-font-smoothing:antialiased}
.toolbar{background:linear-gradient(180deg,#F6F6F6 0%,#E8E8E8 100%);border-bottom:1px solid #C0C0C0;padding:6px 12px;display:flex;align-items:center;gap:10px;min-width:0;overflow:hidden}
.search-box{margin-left:auto;position:relative}
.search-box input{width:200px;padding:4px 8px 4px 24px;border:1px solid #C0C0C0;border-radius:6px;font-size:12px;background:#fff url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23999' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cline x1='21' y1='21' x2='16.65' y2='16.65'/%3E%3C/svg%3E") 6px center no-repeat;outline:none}
.search-box input:focus{border-color:#007AFF;box-shadow:0 0 0 3px rgba(0,122,255,0.15)}
.segmented-control{display:inline-flex;background:#D4D4D4;border-radius:7px;padding:1px;border:1px solid #B8B8B8}
.seg-btn{background:none;border:none;padding:4px 18px;font-size:12px;font-weight:500;color:#333;cursor:pointer;border-radius:6px;transition:all 0.15s;position:relative}
.seg-btn.active{background:#fff;box-shadow:0 1px 3px rgba(0,0,0,0.15);color:#1d1d1f}
.seg-btn:hover:not(.active){color:#000}
.agents-scroll{flex:1;overflow:auto;padding:12px 14px;background:#ECECEC}
.agents-heading{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:8px}
.agents-heading h1{font-size:21px;line-height:1.1;font-weight:650;letter-spacing:-.02em}
.agents-heading-actions{display:flex;align-items:center;gap:7px}
.agents-powerswarm-open{display:flex;align-items:center;gap:6px;border:1px solid #C8C8C8;border-radius:999px;background:#fff;color:#333;padding:4px 8px 4px 10px;font:600 10px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.agents-powerswarm-runtime{color:#777;font-size:8px;font-style:normal;font-weight:550}.agents-powerswarm-runtime.known{color:#075FAE}
.agents-powerswarm-open:hover,.agents-powerswarm-open:focus-visible{border-color:#007AFF;background:#F1F7FF;outline:none}.agents-powerswarm-open strong{color:#666;font-size:9px;font-weight:550;font-variant-numeric:tabular-nums}.agents-powerswarm-open.live strong{color:#237A12}.agents-powerswarm-open .powerswarm-arrow{font-size:14px;line-height:10px}
.agents-freshness{flex:none;border:1px solid #C8C8C8;border-radius:999px;background:#fff;padding:4px 9px;font-size:10px;color:#555;font-variant-numeric:tabular-nums}
.agents-freshness.fresh{color:#237A12;border-color:#A7D89B;background:#F2FAEF}
.agents-freshness.stale{color:#A04A00;border-color:#E7BD8F;background:#FFF7EC}
.agents-heading-actions{display:flex;align-items:center;gap:7px}
.agents-powerswarm-open{display:flex;align-items:center;gap:6px;border:1px solid #C8C8C8;border-radius:999px;background:#fff;color:#333;padding:4px 8px 4px 10px;font:600 10px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}
.agents-powerswarm-open:hover,.agents-powerswarm-open:focus-visible{border-color:#007AFF;background:#F1F7FF;outline:none}.agents-powerswarm-open strong{color:#666;font-size:9px;font-weight:550;font-variant-numeric:tabular-nums}.agents-powerswarm-open.live strong{color:#237A12}.agents-powerswarm-open .powerswarm-arrow{font-size:14px;line-height:10px}
.agents-overview{display:grid;grid-template-columns:minmax(360px,1.25fr) minmax(300px,1fr) minmax(185px,.58fr);gap:10px;align-items:start;margin-bottom:10px}
.agent-card,.agent-section{background:#fff;border:1px solid #CBCBCB;border-radius:10px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.agent-card{padding:12px}
.agent-card-head,.agent-section-head,.agent-pool-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}
.agent-card-title,.agent-section-title{font-size:13px;font-weight:650;color:#222}
.agent-card-value{font-size:26px;font-weight:550;letter-spacing:-.025em;font-variant-numeric:tabular-nums;margin-top:7px}
.agent-card-meta{font-size:10px;color:#777;margin-top:1px}
.agent-badge{display:inline-flex;align-items:center;border-radius:999px;padding:2px 7px;font-size:9px;font-weight:650;line-height:1.4;white-space:nowrap;background:#E9E9E9;color:#555}
.agent-badge.ok{background:#E9F7E5;color:#267A17}.agent-badge.warn{background:#FFF2DD;color:#A34B00}.agent-badge.bad{background:#FDE7EA;color:#B42338}.agent-badge.info{background:#E8F2FF;color:#075FAE}
.agents-core-grid{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:5px;margin-top:10px}
.agents-core{min-width:0;border:1px solid transparent;border-radius:7px;background:transparent;padding:4px;cursor:pointer;text-align:initial;font:inherit;color:inherit;transition:border-color .15s ease,background .15s ease,box-shadow .15s ease}
.agents-core:hover{border-color:#B9CFE8;background:#F4F8FD}.agents-core:focus-visible{outline:none;border-color:#007AFF;box-shadow:0 0 0 3px rgba(0,122,255,.15)}.agents-core.selected{border-color:#007AFF;background:#EDF5FF}
.agents-core-top{display:flex;justify-content:space-between;gap:3px;color:#666;font-size:8px;font-variant-numeric:tabular-nums;margin-bottom:2px}
.agents-meter{height:7px;background:#E3E3E3;border-radius:999px;overflow:hidden}
.agents-meter>span{display:block;height:100%;border-radius:inherit;background:#34C759;transition:width .35s ease}
.agents-meter>span.warm{background:#FF9F0A}.agents-meter>span.hot{background:#FF3B30}.agents-meter>span.gpu{background:#AF52DE}
.gpu-primary{display:flex;align-items:baseline;gap:7px}.gpu-primary-label{font-size:8px;color:#777;text-transform:uppercase;letter-spacing:.06em;font-weight:650}
.gpu-history-shell{position:relative;height:58px;margin-top:7px;border:1px solid #DED5E5;border-radius:8px;background:#FBF9FC;overflow:hidden}
.gpu-history-grid{position:absolute;inset:0;background:linear-gradient(to bottom,transparent 32%,rgba(128,79,151,.08) 33%,transparent 34%,transparent 65%,rgba(128,79,151,.08) 66%,transparent 67%)}
.gpu-history{position:absolute;inset:7px 8px 6px;display:grid;grid-template-columns:repeat(20,minmax(2px,1fr));gap:3px;align-items:end}
.gpu-history-bar{min-height:2px;border-radius:2px 2px 1px 1px;background:linear-gradient(180deg,#C47BE4 0%,#9350B1 100%);opacity:.78;transition:height .35s ease,opacity .2s ease}.gpu-history-bar.empty{height:2px!important;background:#D8D0DC;opacity:.42}.gpu-history-bar.current{opacity:1;background:linear-gradient(180deg,#D28AEE 0%,#7D2EA0 100%)}
.gpu-metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:5px;margin-top:6px}.gpu-metric{display:flex;align-items:baseline;justify-content:space-between;gap:5px;border:1px solid #E3DEE6;border-radius:6px;background:#FCFBFD;padding:4px 6px;min-width:0}.gpu-metric-label{font-size:7px;color:#807685;text-transform:uppercase;letter-spacing:.055em;font-weight:650}.gpu-metric-value{font-size:10px;color:#3B3140;font-weight:650;font-variant-numeric:tabular-nums;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.memory-pressure-card{padding:10px 12px;min-height:0}.memory-pressure-body{display:flex;flex-direction:column;align-items:center;margin-top:2px}.memory-pressure-dial{display:block;width:118px;height:78px}.memory-pressure-headroom{font-size:9px;color:#667168;margin-top:-3px;font-variant-numeric:tabular-nums}.memory-pressure-metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px;width:100%;margin-top:8px}.memory-pressure-metric{display:flex;flex-direction:column;gap:1px;border-top:1px solid #E2E6E1;padding-top:5px;min-width:0}.memory-pressure-metric span{font-size:7px;color:#718073;text-transform:uppercase;letter-spacing:.05em;font-weight:650}.memory-pressure-metric strong{font-size:10px;color:#304233;font-weight:650;font-variant-numeric:tabular-nums;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.core-inspector[hidden]{display:none}.core-inspector{border-color:#AFC8E4}.core-inspector .agent-section-head{background:#F3F7FC}
.core-inspector-close{border:1px solid #C7C7C7;background:#fff;border-radius:6px;color:#555;padding:3px 8px;font-size:10px;cursor:pointer}.core-inspector-close:hover{border-color:#999;color:#222}.core-inspector-close:focus-visible{outline:none;border-color:#007AFF;box-shadow:0 0 0 3px rgba(0,122,255,.15)}
.core-inspector-summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;margin-bottom:8px}.core-stat{border:1px solid #D8DDE3;border-radius:7px;background:#FAFBFC;padding:7px}.core-stat-label{font-size:8px;text-transform:uppercase;letter-spacing:.06em;color:#777}.core-stat-value{font-size:16px;font-weight:600;font-variant-numeric:tabular-nums;margin-top:2px}
.core-truth-note{border-left:3px solid #6F9BC8;background:#F2F7FC;border-radius:0 6px 6px 0;padding:7px 9px;font-size:9px;color:#536476;line-height:1.45;margin-bottom:8px}
.core-contributor-head,.core-contributor-row{display:grid;grid-template-columns:minmax(180px,1.6fr) minmax(90px,.65fr) minmax(100px,.75fr) minmax(135px,1fr);gap:8px;align-items:center}.core-contributor-head{padding:0 7px 4px;color:#777;font-size:8px;text-transform:uppercase;letter-spacing:.04em}.core-contributor-list{max-height:220px;overflow:auto;border:1px solid #D8D8D8;border-radius:7px;background:#fff}.core-contributor-row{min-height:38px;padding:6px 7px;border-bottom:1px solid #ECECEC;font-size:9px;contain:layout paint}.core-contributor-row.core-contributor-grace{background:#FCFCFC}.core-contributor-row:last-child{border-bottom:0}.core-contributor-name{font-size:10px;font-weight:620;color:#222}.core-contributor-sub{color:#777;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.core-contributor-metric{font-variant-numeric:tabular-nums}.core-contributor-evidence{color:#666;line-height:1.35}.core-contributor-empty{padding:13px;color:#777;font-size:10px;line-height:1.4}
.agents-layout{display:grid;grid-template-columns:minmax(0,1.18fr) minmax(280px,.82fr);gap:10px;align-items:start}
.agent-section{min-width:0;overflow:hidden;margin-bottom:10px}
.agent-section-head{padding:10px 12px;border-bottom:1px solid #DADADA;background:#F8F8F8}
.agent-section-body{padding:10px 12px}
.ai-process-wrap{max-height:260px;overflow:auto}
.ai-process-table{width:100%;font-size:10px}
.ai-process-table th{top:0;font-size:9px;padding:4px 6px}
.ai-process-table td{padding:4px 6px}
.ai-process-table tbody tr{contain:layout paint}
.ai-process-table tbody tr.agent-process-grace{opacity:1}
.ai-process-name{font-weight:600;color:#222}.ai-process-sub{font-size:9px;color:#777;margin-top:1px;max-width:320px;overflow:hidden;text-overflow:ellipsis}
.agent-empty,.agent-error{border:1px dashed #C8C8C8;border-radius:7px;padding:12px;color:#777;font-size:11px;line-height:1.4;background:#FAFAFA}
.agent-error{border-color:#E1B176;color:#8B4500;background:#FFF9EF}
.agent-pool{border:1px solid #D6D6D6;border-radius:8px;padding:9px;margin-bottom:8px;background:#FCFCFC}
.agent-pool:last-child{margin-bottom:0}
.agent-pool-title{font-size:11px;font-weight:650;line-height:1.35}
.agent-pool-meta{font-size:9px;color:#777;margin-top:2px;line-height:1.35}
.agent-progress{height:5px;background:#E3E3E3;border-radius:999px;overflow:hidden;margin-top:7px}
.agent-progress>span{display:block;height:100%;background:#1D9E75;border-radius:inherit}
.agent-worker-grid{display:flex;flex-wrap:wrap;gap:4px;margin-top:7px}
.agent-worker{border:1px solid #D1D1D1;background:#fff;border-radius:6px;padding:4px 6px;font-size:9px;color:#333;cursor:pointer;font-variant-numeric:tabular-nums}
.agent-worker:hover,.agent-worker.selected{border-color:#007AFF;background:#EDF5FF}
.agent-detail{margin-top:6px;border-radius:6px;background:#F0F0F2;padding:7px;font-size:9px;color:#555;line-height:1.45}
.gpu-lane{border:1px solid #D7C3E5;background:#FBF7FE;border-radius:8px;padding:9px;margin-bottom:8px}
.gpu-lane-row{display:flex;justify-content:space-between;gap:10px;font-size:10px;margin-top:3px}
.hint-row{border-top:1px solid #E1E1E1;padding-top:7px;margin-top:7px;font-size:9px;color:#777;line-height:1.4}
.sr-only{position:absolute!important;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.network-scroll{flex:1;overflow:auto;padding:14px 16px 24px;scroll-padding:14px;background:linear-gradient(180deg,#F5F7FA 0%,#EEF2F5 100%);color:#172131}.network-scroll>.flagship-fabric{margin:14px 0 0;box-shadow:none}
.network-hero{position:relative;isolation:isolate;overflow:hidden;display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:20px;min-height:0;padding:16px 17px;border:1px solid #22536A;border-radius:14px;background:radial-gradient(circle at 88% 22%,rgba(61,199,218,.18),transparent 30%),linear-gradient(130deg,#0B1D2D 0%,#0D3044 58%,#124958 100%);box-shadow:0 8px 24px rgba(11,37,59,.14);color:#F4FBFF}
.network-hero:before{content:"";position:absolute;z-index:-1;inset:0;opacity:.22;background:radial-gradient(circle at 88% 50%,transparent 0 42px,rgba(109,224,239,.24) 43px,transparent 44px 84px,rgba(109,224,239,.16) 85px,transparent 86px)}.network-hero:after{content:"";position:absolute;z-index:-1;inset:0;background:linear-gradient(90deg,transparent 0 49.8%,rgba(146,230,255,.06) 50%,transparent 50.2%),linear-gradient(transparent 0 49.8%,rgba(146,230,255,.05) 50%,transparent 50.2%);background-size:52px 52px;mask-image:linear-gradient(90deg,transparent,black)}
.network-kicker{font-size:9px;font-weight:760;text-transform:uppercase;letter-spacing:.15em;color:#70DFF5}.network-hero h1{font-size:23px;line-height:1.08;letter-spacing:-.025em;margin-top:4px}.network-hero-copy{max-width:590px;margin-top:6px;color:#C4D4DE;font-size:11px;line-height:1.5}.network-live-line{display:flex;align-items:center;gap:7px;margin-top:10px;color:#D8F7FB;font-size:10px}.network-pulse{width:8px;height:8px;border-radius:50%;background:#3EF2A4;box-shadow:0 0 0 0 rgba(62,242,164,.6);animation:network-pulse 2s infinite}.network-pulse.paused{background:#9AA9B7;box-shadow:none;animation:none}@keyframes network-pulse{70%{box-shadow:0 0 0 7px rgba(62,242,164,0)}100%{box-shadow:0 0 0 0 rgba(62,242,164,0)}}
.network-hero-actions{display:flex;flex-direction:column;align-items:stretch;justify-content:center;gap:7px;min-width:158px}.network-hero-btn{min-height:32px;border:1px solid rgba(157,224,255,.44);border-radius:8px;background:rgba(255,255,255,.08);color:#F5FCFF;padding:7px 11px;font:660 10px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer;backdrop-filter:blur(8px)}.network-hero-btn:hover:not(:disabled){background:rgba(255,255,255,.16)}.network-hero-btn:focus-visible{outline:2px solid #BCEEFF;outline-offset:2px}.network-hero-btn.primary{border-color:#50D4F6;background:linear-gradient(135deg,#087EC6,#1AA7A8)}.network-hero-btn:disabled{opacity:.45;cursor:default}
.network-boundary{display:flex;align-items:flex-start;gap:8px;border:1px solid #C7D9E4;border-radius:9px;background:#F7FBFD;padding:9px 10px;margin:10px 0;color:#405666;font-size:10px;line-height:1.45}.network-boundary strong{color:#183A51}.network-boundary-icon{flex:none;color:#087BC1;font-size:13px}.network-boundary-copy{min-width:0;flex:1}.network-boundary-title{display:inline-flex;align-items:center;gap:6px}.network-error{display:flex;align-items:center;justify-content:space-between;gap:10px;border:1px solid #E4A8AF;border-radius:9px;background:#FFF4F5;color:#84232E;padding:9px 10px;margin-bottom:10px;font-size:10px;line-height:1.45}.network-error[data-tone="warning"]{border-color:#D9C38E;background:#FFF9EB;color:#684C12}.network-error[hidden],.network-error-action[hidden]{display:none}.network-error-copy{min-width:0}.network-error-action{flex:none;min-height:28px;border:1px solid #C05F6A;border-radius:7px;background:#fff;color:#84232E;padding:5px 9px;font:700 9px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.network-error[data-tone="warning"] .network-error-action{border-color:#B9974B;color:#684C12}.network-error-action:hover:not(:disabled){background:#FFE9EC}.network-error[data-tone="warning"] .network-error-action:hover:not(:disabled){background:#FFF2CE}.network-error-action:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(166,45,58,.16)}.network-error[data-tone="warning"] .network-error-action:focus-visible{box-shadow:0 0 0 3px rgba(169,124,26,.18)}.network-error-action:disabled{opacity:.55;cursor:default}
.network-stats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin-bottom:10px}.network-stat{min-width:0;border:1px solid #D5DCE2;border-radius:10px;background:#fff;padding:9px 10px;box-shadow:0 1px 2px rgba(21,42,62,.035)}.network-stat-label{display:flex;align-items:center;justify-content:space-between;gap:5px}.network-stat span{display:block;font-size:8px;color:#697781;text-transform:uppercase;letter-spacing:.075em;font-weight:700}.network-stat strong{display:block;font-size:21px;line-height:1.1;margin-top:4px;font-variant-numeric:tabular-nums}.network-stat small{display:block;color:#687782;font-size:9px;line-height:1.35;margin-top:3px;white-space:normal}
.network-info-trigger{display:inline-grid;place-items:center;flex:none;width:20px;height:20px;border:1px solid #9DB9CA;border-radius:50%;background:#fff;color:#0877B4;padding:0;font:700 11px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;line-height:1;cursor:pointer}.network-info-trigger:hover,.network-info-trigger[aria-expanded="true"]{border-color:#087FC0;background:#E8F6FE;color:#045F90}.network-info-trigger:focus-visible,.network-info-close:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(0,122,255,.17)}.network-info-panel{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:start;gap:10px;border:1px solid #9EC8DE;border-radius:10px;background:#F5FBFE;color:#344D5D;padding:10px 11px;margin:0 0 10px;box-shadow:0 4px 12px rgba(22,74,104,.07)}.network-info-panel[hidden]{display:none}.network-info-mark{display:grid;place-items:center;width:21px;height:21px;border-radius:50%;background:#087FC0;color:#fff;font:700 11px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif}.network-info-copy{min-width:0}.network-info-copy strong{display:block;color:#163D55;font-size:11px}.network-info-copy p{margin:3px 0 0;font-size:9px;line-height:1.5}.network-info-close{border:1px solid #B6C9D5;border-radius:7px;background:#fff;color:#31566D;padding:4px 8px;font:700 9px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.network-info-close:hover{border-color:#6FA9C8;background:#EFF8FD}
.network-layout{display:grid;grid-template-columns:minmax(0,1.18fr) minmax(285px,.82fr);gap:10px;align-items:start}.network-card{border:1px solid #D4DBE1;border-radius:11px;background:#fff;box-shadow:0 1px 3px rgba(25,45,64,.04);overflow:hidden;min-width:0}.network-card-head{display:flex;align-items:center;justify-content:space-between;gap:9px;padding:11px 12px;border-bottom:1px solid #E5E9EC;background:#FBFCFD}.network-card-title{font-size:13px;font-weight:710}.network-card-copy{font-size:9px;color:#6E7B85;line-height:1.4;margin-top:2px}.network-filters{display:flex;gap:5px;flex-wrap:wrap}.network-filter{min-height:25px;border:1px solid #CAD1D8;border-radius:999px;background:#fff;color:#53606C;padding:4px 8px;font:650 9px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.network-filter.active{border-color:#178FCD;background:#E9F7FF;color:#00689F}.network-filter:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(0,122,255,.14)}
.network-device-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;padding:9px;max-height:360px;overflow:auto}.network-device{position:relative;display:grid;grid-template-columns:auto minmax(0,1fr);gap:9px;width:100%;min-height:78px;border:1px solid #DDE2E6;border-radius:9px;background:#fff;color:#1D2935;padding:9px;text-align:left;cursor:pointer;font:inherit;contain:layout paint}.network-device:hover{border-color:#8BBBD6;background:#F7FBFE}.network-device:focus-visible{outline:none;border-color:#007AFF;box-shadow:0 0 0 3px rgba(0,122,255,.14)}.network-device.selected{border-color:#087FC0;background:#ECF8FF;box-shadow:inset 0 0 0 1px rgba(8,127,192,.2)}.network-device-icon{display:grid;place-items:center;width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#E7F4FC,#DDF8F3);color:#077FB7;font-size:15px}.network-device-name{font-size:11px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-right:42px}.network-device-meta{font:9px ui-monospace,SFMono-Regular,Menlo,monospace;color:#61707B;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.network-device-sources{font-size:9px;color:#74818A;margin-top:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.network-device-state{position:absolute;top:9px;right:9px;display:flex;align-items:center;gap:4px;font-size:8px;text-transform:uppercase;font-weight:750}.network-device-trust{position:absolute;right:9px;bottom:8px;border:1px solid #9DC9B2;border-radius:999px;background:#EEF9F2;color:#267247;padding:2px 6px;font-size:8px;font-weight:750;text-transform:uppercase;letter-spacing:.04em}.network-state-dot{width:7px;height:7px;border-radius:50%;background:#9CA7B0}.network-state-dot.online{background:#21B66B;box-shadow:0 0 6px rgba(33,182,107,.55)}.network-state-dot.recent{background:#F0A51B}.network-empty{grid-column:1/-1;border:1px dashed #C3CBD2;border-radius:8px;background:#FAFBFC;color:#66747F;padding:25px 14px;text-align:center;font-size:10px;line-height:1.5}
.network-device{min-height:86px;padding-bottom:20px}.network-device-name,.network-device-meta,.network-device-sources{display:block}.network-device-name{padding-right:56px}
.network-detail{min-height:270px}.network-detail-empty{padding:44px 20px;text-align:center;color:#687681;font-size:10px;line-height:1.5}.network-detail-empty strong{display:block;color:#263746;font-size:13px;margin-bottom:5px}.network-detail-content[hidden],.network-detail-empty[hidden]{display:none}.network-detail-content{padding:12px}.network-detail-top{display:flex;align-items:flex-start;justify-content:space-between;gap:9px}.network-detail-badges{display:flex;align-items:center;justify-content:flex-end;gap:5px;flex-wrap:wrap}.network-detail-name{font-size:16px;font-weight:720;letter-spacing:-.02em}.network-detail-sub{font:9px ui-monospace,SFMono-Regular,Menlo,monospace;color:#65747F;margin-top:3px;overflow-wrap:anywhere}.network-detail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin-top:10px}.network-detail-metric{border:1px solid #E2E6E9;border-radius:7px;background:#FAFBFC;padding:7px}.network-detail-metric span{display:block;color:#74818B;font-size:8px;text-transform:uppercase;letter-spacing:.06em}.network-detail-metric strong{display:block;font-size:10px;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.network-section-label{font-size:8px;text-transform:uppercase;letter-spacing:.08em;font-weight:750;color:#74818B;margin-top:11px}.network-chip-row{display:flex;gap:5px;flex-wrap:wrap;margin-top:6px}.network-chip{border:1px solid #D5DCE2;border-radius:999px;background:#F6F8FA;color:#53606C;padding:3px 7px;font-size:8px}.network-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:7px}.network-action{min-height:28px;border:1px solid #B8C6D1;border-radius:7px;background:#fff;color:#254053;padding:5px 8px;font:650 9px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.network-action:hover:not(:disabled){border-color:#238AC0;background:#F0F9FE}.network-action:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(0,122,255,.14)}.network-action:disabled{opacity:.42;cursor:default}.network-services{display:grid;gap:5px;margin-top:6px}.network-service{display:flex;align-items:center;justify-content:space-between;gap:7px;border:1px solid #E0E4E7;border-radius:7px;padding:6px 7px;background:#FCFCFD}.network-service-name{min-width:0;font-size:9px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.network-service-meta{font:8px ui-monospace,SFMono-Regular,Menlo,monospace;color:#71808B;margin-top:2px}
.ke-link-card{margin-top:10px}.ke-link-head{display:flex;align-items:flex-start;justify-content:space-between;gap:11px;padding:12px}.ke-link-brand{display:flex;align-items:center;gap:9px;min-width:0}.ke-link-mark{display:grid;place-items:center;flex:none;width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,#063866,#11A9AF);box-shadow:0 4px 10px rgba(12,105,132,.16);color:#fff;font-size:15px}.ke-link-title{font-size:13px;font-weight:720}.ke-link-copy{font-size:9px;color:#677680;line-height:1.4;margin-top:2px}.ke-link-controls{display:flex;gap:6px;align-items:center}.ke-pairing-code{border:1px solid #A6D8D0;border-radius:8px;background:#F0FFFC;color:#075C55;padding:7px 9px;margin:0 11px 10px;font:700 12px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em}.ke-pairing-code[hidden]{display:none}.ke-trusted-list{display:grid;gap:5px;padding:0 11px 10px}.ke-trusted-peer{display:flex;align-items:center;justify-content:space-between;gap:9px;border:1px solid #DDE4E8;border-radius:8px;background:#FCFDFD;padding:7px 8px}.ke-trusted-peer-copy{min-width:0}.ke-trusted-peer-copy strong{display:block;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.ke-trusted-peer-copy span{display:block;color:#71808A;font-size:8px;margin-top:2px}.ke-link-boundary{border-top:1px solid #E2E7EA;padding:9px 11px;background:#F8FAFB;color:#596B77;font-size:9px;line-height:1.5}.network-pair-row{display:flex;gap:6px;margin-top:7px}.network-pair-requirement{color:#71808A;font-size:8px;line-height:1.4;margin-top:5px}.network-pair-row input,.network-compose textarea{border:1px solid #BEC8D0;border-radius:7px;background:#fff;color:#1E2B36;padding:6px 7px;font:10px ui-monospace,SFMono-Regular,Menlo,monospace;outline:none}.network-pair-row input{min-width:0;flex:1}.network-pair-row input:focus,.network-compose textarea:focus{border-color:#0784C5;box-shadow:0 0 0 3px rgba(7,132,197,.12)}.network-messages{max-height:140px;overflow:auto;display:grid;gap:6px;margin-top:7px}.network-message{max-width:88%;border-radius:8px;background:#EFF3F6;color:#263643;padding:7px 8px;font-size:9px;line-height:1.45;overflow-wrap:anywhere}.network-message.outbound{justify-self:end;background:#DFF5FF}.network-message-meta{font-size:8px;color:#71808A;margin-bottom:3px}.network-compose{display:flex;gap:6px;align-items:flex-end;margin-top:7px}.network-compose textarea{flex:1;min-height:50px;resize:vertical;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif}.network-action-feedback{min-height:15px;color:#4D6C7D;font-size:9px;line-height:1.4;margin-top:7px}.network-action-feedback.error{color:#A42D38}
.internet-optimizer{margin:0 0 10px;border-color:#A7C9D8;background:#FBFDFE}.internet-optimizer[hidden]{display:none}.internet-optimizer:focus-visible{outline:3px solid rgba(0,122,255,.42);outline-offset:2px}.internet-optimizer-head{display:flex;align-items:flex-start;justify-content:space-between;gap:11px;padding:12px 13px;border-bottom:1px solid #DCE7EC;background:#F2FAFC}.internet-optimizer-head>div:last-child{display:flex;align-items:center;gap:7px}.internet-optimizer-brand{display:flex;align-items:center;gap:10px;min-width:0}.internet-optimizer-mark{display:grid;place-items:center;flex:none;width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,#087EC6,#1AA7A8);box-shadow:0 4px 10px rgba(4,105,142,.15);color:#fff;font-size:17px}.internet-optimizer-title-row{display:flex;align-items:center;gap:6px}.internet-optimizer-title{font-size:15px;font-weight:750;color:#12394F}.internet-optimizer-subtitle{max-width:590px;margin-top:2px;color:#526C7B;font-size:10px;line-height:1.45}.internet-optimizer-state{flex:none;white-space:nowrap;border:1px solid #9CC9D5;border-radius:999px;background:#fff;color:#22637B;padding:4px 8px;font-size:8px;font-weight:750;text-transform:uppercase;letter-spacing:.05em}.internet-optimizer-body{padding:12px}.internet-optimizer-loading{border:1px dashed #9DBECC;border-radius:8px;background:#F6FCFF;color:#416779;padding:14px;text-align:center;font-size:10px;line-height:1.45}.internet-optimizer-loading[hidden],.internet-optimizer-results[hidden]{display:none}.internet-optimizer-summary{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:7px}.internet-optimizer-metric{border:1px solid #DDE5E9;border-radius:8px;background:#fff;padding:8px;min-width:0}.internet-optimizer-metric span{display:block;color:#6D7C85;font-size:8px;text-transform:uppercase;letter-spacing:.055em}.internet-optimizer-metric strong{display:block;margin-top:3px;color:#173A4C;font-size:11px;line-height:1.3;overflow-wrap:anywhere}.internet-optimizer-grid{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr);gap:9px;margin-top:9px}.internet-optimizer-pane{border:1px solid #DDE5E9;border-radius:9px;background:#fff;padding:9px;min-width:0}.internet-optimizer-pane-title{display:flex;align-items:center;justify-content:space-between;gap:8px;color:#315464;font-size:8px;font-weight:750;text-transform:uppercase;letter-spacing:.055em}.internet-channel-list,.internet-finding-list{display:grid;gap:5px;margin-top:7px}.internet-channel{display:grid;grid-template-columns:58px minmax(0,1fr) 54px;align-items:center;gap:7px;font-size:9px}.internet-channel strong{color:#254858}.internet-channel-track{height:6px;border-radius:999px;background:#E6EEF1;overflow:hidden}.internet-channel-track span{display:block;height:100%;border-radius:inherit;background:linear-gradient(90deg,#19B998,#F0AB27,#DC5A5E)}.internet-channel small{text-align:right;color:#687983;font-size:8px}.internet-channel.current strong:after{content:' current';color:#0782B5;font-size:8px;font-weight:700}.internet-finding{display:grid;grid-template-columns:8px minmax(0,1fr);gap:8px;border:1px solid #E1E7EA;border-radius:8px;background:#FBFCFD;padding:7px}.internet-finding-dot{width:8px;height:8px;border-radius:50%;margin-top:2px;background:#31A66D}.internet-finding.high .internet-finding-dot{background:#D74D58}.internet-finding.medium .internet-finding-dot,.internet-finding.attention .internet-finding-dot{background:#E5A126}.internet-finding strong{display:block;color:#263E4C;font-size:9px}.internet-finding p{margin-top:2px;color:#61747F;font-size:8px;line-height:1.45}.internet-optimizer-recommendation{margin-top:8px;border-left:3px solid #10A58B;background:#F0FBF8;color:#355D5A;padding:7px 8px;font-size:9px;line-height:1.5}.internet-optimizer-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:10px}.internet-optimizer-actions .network-action.primary{border-color:#087CB9;background:#087CB9;color:#fff}.internet-optimizer-actions .network-action.primary:hover:not(:disabled){background:#05689C}.internet-optimizer-disclosure{margin-top:8px;color:#5F737F;font-size:9px;line-height:1.5}.internet-quality-result{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;margin-top:9px}.internet-quality-result[hidden]{display:none}.internet-quality-result div{border:1px solid #DDE5E9;border-radius:8px;background:#F9FCFD;padding:7px}.internet-quality-result span{display:block;color:#697B85;font-size:8px;text-transform:uppercase;letter-spacing:.04em}.internet-quality-result strong{display:block;margin-top:3px;color:#173A4C;font-size:10px;line-height:1.3;overflow-wrap:anywhere}.internet-optimizer-close{border:0;background:transparent;color:#476A7C;padding:4px;font:700 9px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.internet-optimizer-close:hover{text-decoration:underline}.internet-optimizer-close:focus-visible{outline:2px solid rgba(0,122,255,.35);outline-offset:1px;border-radius:4px}
.network-traffic{margin-top:9px}.network-traffic summary{display:flex;align-items:center;justify-content:space-between;gap:10px;list-style:none;cursor:pointer;padding:10px 11px;font-size:11px;font-weight:700}.network-traffic summary::-webkit-details-marker{display:none}.network-traffic summary:after{content:'Show';font-size:8px;color:#6F7B85;font-weight:600}.network-traffic[open] summary:after{content:'Hide'}.network-traffic .table-container{max-height:185px;border-top:1px solid #E0E5E8}.network-traffic .bottom-panel{border-top:1px solid #DCE2E7;background:#F8FAFC}.network-traffic .graph-area{height:105px;flex:none}.network-traffic #net-bar-chart{min-height:70px}.network-traffic .info-row{padding:5px 10px}
#network-tab :is(.network-kicker,.network-error-action,.network-stat span,.network-stat small,.network-info-copy p,.network-info-close,.network-card-copy,.network-filter,.network-device-meta,.network-device-sources,.network-device-state,.network-device-trust,.network-detail-sub,.network-detail-metric span,.network-section-label,.network-chip,.network-action,.network-service-name,.network-service-meta,.ke-link-copy,.ke-trusted-peer-copy strong,.ke-trusted-peer-copy span,.ke-link-boundary,.network-pair-requirement,.network-message,.network-message-meta,.network-action-feedback,.internet-optimizer-state,.internet-optimizer-metric span,.internet-optimizer-pane-title,.internet-channel,.internet-channel small,.internet-finding strong,.internet-finding p,.internet-optimizer-recommendation,.internet-optimizer-disclosure,.internet-quality-result span,.internet-optimizer-close,.status-pill,.flagship-kicker,.flagship-fabric-title-group p,.flagship-readonly,.flagship-fix-all,.flagship-collapse,.flagship-recovery-status,.flagship-filter-label input,.flagship-result-head strong,.flagship-result-head span,.flagship-result-badge,.flagship-result-copy strong,.flagship-result-copy span,.flagship-rail,.flagship-card-id,.flagship-card-detail,.flagship-card-owner,.flagship-state,.flagship-inspect,.flagship-fix-one,.flagship-meta span,.flagship-meta strong,.flagship-empty){font-size:10px}
#network-tab .network-traffic summary:after,#network-tab .internet-channel.current strong:after{font-size:10px}
.powerswarm-heading{align-items:center}.powerswarm-heading-title{display:flex;align-items:center;gap:9px}.powerswarm-heading .agents-freshness{margin-left:auto}.powerswarm-back{border:0;background:transparent;color:#0668C7;padding:3px 0;font:600 10px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.powerswarm-back:hover{text-decoration:underline}.powerswarm-back:focus-visible{outline:2px solid rgba(0,122,255,.35);outline-offset:2px;border-radius:3px}.powerswarm-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-bottom:9px}.powerswarm-summary .summary-tile{padding:6px 9px}.powerswarm-summary .summary-tile strong{font-size:17px}.powerswarm-layout{display:grid;grid-template-columns:minmax(0,1fr) 255px;gap:9px;align-items:start}.powerswarm-card{border:1px solid #CBCBCB;background:#fff;border-radius:9px;min-width:0;overflow:hidden}.powerswarm-card-head{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 10px;border-bottom:1px solid #E0E0E0;background:#F8F8F8}.powerswarm-card-title{font-size:12px;font-weight:650}.powerswarm-card-body{padding:10px}.powerswarm-checkpoint{display:flex;align-items:center;gap:7px;border:1px solid #D8DDE3;border-radius:7px;background:#F7F8FA;color:#59616B;padding:7px 9px;margin-bottom:8px;font-size:9px}.powerswarm-tree{display:grid;gap:6px}.powerswarm-edge{height:10px;margin:-6px 0 -6px 17px;border-left:1px solid #AFC3D9}.powerswarm-node{border:1px solid #D6D6D6;border-radius:8px;background:#FCFCFC;padding:8px 9px;min-width:0}.powerswarm-node.parent{background:#F7F7F8}.powerswarm-node.run{border-color:#AFC9E5;background:#F7FAFD}.powerswarm-node-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}.powerswarm-node-label{font-size:8px;color:#777;text-transform:uppercase;letter-spacing:.055em}.powerswarm-node-title{font-size:11px;font-weight:650;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-node-meta{font-size:8px;color:#777;margin-top:2px;line-height:1.35;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-objective{font-size:9px;color:#555;line-height:1.4;margin-top:7px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}.powerswarm-children{display:grid;gap:5px;margin-top:7px;padding-left:13px;border-left:1px solid #C9D6E3}.powerswarm-branch{border:1px solid #D9DFE6;background:#FAFBFC;border-radius:7px;padding:7px}.powerswarm-branch-head{display:flex;align-items:flex-start;justify-content:space-between;gap:7px}.powerswarm-worker{display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;border:1px solid #DEDEDE;border-radius:7px;background:#fff;color:#222;padding:7px 8px;text-align:left;cursor:pointer;font:inherit}.powerswarm-worker:hover,.powerswarm-worker:focus-visible{border-color:#007AFF;background:#F1F7FF;outline:none}.powerswarm-worker-main{min-width:0}.powerswarm-worker-name{display:block;font-size:10px;font-weight:630;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-worker-meta{display:block;font-size:8px;color:#777;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-arrow{font-size:17px;color:#8A8A8F;font-weight:300}.powerswarm-runs{display:grid}.powerswarm-run{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px;width:100%;border:0;border-top:1px solid #E8E8E8;background:transparent;color:#222;padding:8px 2px;text-align:left;cursor:pointer}.powerswarm-run:first-child{border-top:0}.powerswarm-run:hover,.powerswarm-run:focus-visible{background:#F4F8FC;outline:none}.powerswarm-run.selected{color:#005FB8}.powerswarm-run-title{font-size:9px;font-weight:620;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-run-meta{font-size:8px;color:#777;margin-top:2px;font-variant-numeric:tabular-nums}.powerswarm-latest{border:0;background:transparent;color:#0668C7;font-size:9px;font-weight:600;cursor:pointer}.powerswarm-latest:hover{text-decoration:underline}.powerswarm-worker-inspector{margin-top:9px}.powerswarm-worker-inspector[hidden]{display:none}.powerswarm-inspector-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;margin-bottom:8px}.powerswarm-inspector-stat{border:1px solid #DEDEDE;border-radius:7px;background:#FAFAFA;padding:7px;min-width:0}.powerswarm-inspector-stat span{display:block;font-size:7px;color:#777;text-transform:uppercase;letter-spacing:.055em}.powerswarm-inspector-stat strong{display:block;font-size:11px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-aim{font-size:9px;color:#555;line-height:1.4;margin-bottom:8px}.powerswarm-attempts{border:1px solid #DEDEDE;border-radius:7px;overflow:hidden}.powerswarm-attempt{display:grid;grid-template-columns:minmax(125px,1fr) 78px 95px 85px;gap:7px;align-items:center;padding:7px 8px;border-top:1px solid #E8E8E8;font-size:9px}.powerswarm-attempt:first-child{border-top:0}.powerswarm-attempt-title{font-weight:620}.powerswarm-attempt-meta{color:#777;font-size:8px;margin-top:1px}.powerswarm-empty{border:1px dashed #C8C8C8;border-radius:7px;background:#FAFAFA;color:#777;padding:16px;text-align:center;font-size:10px}.status-pill.running{background:#E8F6E4;color:#29731B}.status-pill.verified,.status-pill.review-ready,.status-pill.checkpoint{background:#E8F2FF;color:#075FAE}.status-pill.cancelled,.status-pill.invalid{background:#FDE7EA;color:#B42338}.status-pill.mixed{background:#F0ECF8;color:#604790}
@media(max-width:1000px){.seg-btn{padding-left:11px;padding-right:11px}.search-box input{width:150px}.agents-layout,.network-layout{grid-template-columns:1fr}.agents-overview{grid-template-columns:1fr 1fr}.agents-core-grid{grid-template-columns:repeat(7,minmax(28px,1fr))}.memory-pressure-card{max-width:240px}.core-contributor-head,.core-contributor-row{grid-template-columns:minmax(150px,1.4fr) 80px 95px minmax(120px,1fr)}.network-hero{grid-template-columns:1fr}.network-hero-actions{flex-direction:row;justify-content:flex-start;flex-wrap:wrap}.network-hero-btn{min-width:132px}}
@media(max-width:620px){.agents-overview{grid-template-columns:1fr}.memory-pressure-card{max-width:none}.network-scroll{padding:10px 10px 18px;scroll-padding:10px}.network-hero{padding:14px;border-radius:12px;gap:14px}.network-hero h1{font-size:21px}.network-hero-copy{font-size:10px}.network-hero-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));width:100%;gap:7px}.network-hero-btn{min-width:0}.network-hero-btn.primary{grid-column:1/-1}.network-boundary{font-size:10px}.network-device-list{grid-template-columns:1fr}.network-card-head{align-items:flex-start;flex-direction:column}.network-stats{grid-template-columns:repeat(2,minmax(0,1fr))}.network-stat:last-child{grid-column:1/-1}.network-info-panel{grid-template-columns:auto minmax(0,1fr)}.network-info-close{grid-column:2;justify-self:start}.network-error{align-items:flex-start;flex-direction:column}.network-error-action{align-self:flex-end}.internet-optimizer-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.internet-optimizer-metric:last-child{grid-column:1/-1}.internet-optimizer-grid{grid-template-columns:1fr}.internet-quality-result{grid-template-columns:repeat(2,minmax(0,1fr))}.internet-optimizer-head{display:grid;grid-template-columns:1fr;align-items:start}.internet-optimizer-head>div:last-child{justify-content:space-between}.internet-optimizer-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}.internet-optimizer-actions .network-action{white-space:normal}.ke-link-head{flex-direction:column}.ke-link-controls{width:100%}.network-compose{align-items:stretch;flex-direction:column}.network-compose .network-action{align-self:flex-end}.network-pair-row{align-items:stretch}.network-scroll>.flagship-fabric{margin-top:12px}}
@media(max-width:1000px){.powerswarm-layout{grid-template-columns:1fr}.powerswarm-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.powerswarm-inspector-summary{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:620px){.powerswarm-attempt{grid-template-columns:minmax(100px,1fr) 66px 76px 76px;gap:5px}}
@media(prefers-reduced-motion:reduce){.network-pulse{animation:none!important}}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.tab-content{display:none;flex:1;flex-direction:column;overflow:hidden}
.tab-content.active{display:flex}
.table-container{flex:1;overflow-y:auto;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:11px}
thead{position:sticky;top:0;z-index:2}
th{background:linear-gradient(180deg,#F6F6F6 0%,#E0E0E0 100%);border-bottom:1px solid #B8B8B8;border-right:1px solid #D0D0D0;padding:3px 8px;text-align:left;font-weight:500;color:#555;cursor:pointer;user-select:none;white-space:nowrap;font-size:11px}
th:hover{background:linear-gradient(180deg,#E8E8E8 0%,#D0D0D0 100%)}
th.sort-asc::after{content:" ▲";font-size:8px;color:#007AFF}
th.sort-desc::after{content:" ▼";font-size:8px;color:#007AFF}
th:last-child{border-right:none}
td{padding:2px 8px;border-bottom:1px solid #E5E5E5;white-space:nowrap;font-variant-numeric:tabular-nums}
tr:nth-child(even){background:#F5F5F7}
tr:nth-child(odd){background:#fff}
tr:hover{background:#D4E8FF !important}
tr.selected{background:#007AFF !important;color:#fff}
.num{text-align:right}
.bottom-panel{border-top:1px solid #B8B8B8;background:#F0F0F0;flex-shrink:0;display:flex;flex-direction:column}
.bottom-panel.has-graph{height:150px}
.bottom-panel.no-graph{height:auto}
.graph-area{flex:1;display:flex;padding:8px 12px;gap:14px;min-height:0}
.graph-section{flex:1;display:flex;flex-direction:column;min-height:0;position:relative}
.graph-title{font-size:10px;font-weight:600;color:#555;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.5px;flex-shrink:0}
.graph-canvas{flex:1;border-radius:4px;position:relative;min-height:80px}
.cpu-graph{background:#1a1a2e}
.memory-gauge-container{display:flex;align-items:center;gap:16px;flex:1}
.info-row{display:flex;gap:16px;padding:4px 12px;font-size:11px;color:#555;flex-wrap:wrap;border-top:1px solid #D5D5D5;align-items:center}
.info-item{display:flex;align-items:center;gap:4px}
.info-label{color:#888}
.info-value{font-weight:500;font-variant-numeric:tabular-nums}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.dot-green{background:#34C759}.dot-yellow{background:#FF9F0A}.dot-red{background:#FF3B30}
.dot-blue{background:#007AFF}.dot-user{background:#73BF44}.dot-system{background:#E33E38}
.memory-pressure-summary{flex:0 0 160px}
.memory-detail-section{flex:0 0 270px}
.mem-info-grid{display:grid;grid-template-columns:max-content max-content;gap:4px 14px;font-size:11px;align-items:baseline;justify-content:start}
.mem-info-grid .label{color:#888;white-space:nowrap}.mem-info-grid .val{font-weight:500;text-align:left;white-space:nowrap}
.memory-diagnostics-section{flex:1;min-width:300px;border-left:1px solid #D0D0D0;padding-left:14px}.memory-diagnostics-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:4px}.memory-diagnostics-head .graph-title{margin-bottom:0}.memory-diagnostic-actions{display:flex;gap:5px}.memory-diagnostic-btn{border:1px solid #AEB4BB;border-radius:5px;background:linear-gradient(#fff,#ECEFF2);color:#222;padding:3px 7px;font:600 9px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer;white-space:nowrap}.memory-diagnostic-btn:hover:not(:disabled){background:#fff;border-color:#858C94}.memory-diagnostic-btn:focus-visible{outline:none;border-color:#007AFF;box-shadow:0 0 0 3px rgba(0,122,255,.16)}.memory-diagnostic-btn:disabled{opacity:.45;cursor:default}.memory-diagnostic-btn.primary{color:#fff;border-color:#006BCB;background:linear-gradient(#1988F4,#0876D8)}.memory-diagnostic-status{font-size:9px;color:#666;line-height:1.25;min-height:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.memory-diagnostic-status.stale{color:#955000}.memory-diagnostic-progress{display:flex;align-items:center;gap:7px;margin:4px 0}.memory-diagnostic-progress[hidden]{display:none}.memory-diagnostic-progress progress{height:5px;flex:1;accent-color:#007AFF}.memory-diagnostic-progress span{font-size:8px;color:#68717B;white-space:nowrap}.memory-diagnostic-result{min-height:66px}.memory-diagnostic-summary{display:flex;align-items:center;gap:6px;margin:3px 0 4px}.memory-diagnostic-verdict{display:inline-flex;align-items:center;border-radius:999px;padding:2px 6px;font-size:8px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;background:#ECECEC;color:#555}.memory-diagnostic-verdict.healthy{background:#E7F5E3;color:#287219}.memory-diagnostic-verdict.attention{background:#FFF0D7;color:#955000}.memory-diagnostic-verdict.critical{background:#FDE4E7;color:#B21D32}.memory-diagnostic-summary-copy{font-size:8px;color:#5F6870;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.memory-diagnostic-findings{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:3px 10px}.memory-diagnostic-finding{display:grid;grid-template-columns:7px minmax(62px,max-content) minmax(0,1fr);align-items:center;gap:4px;min-width:0;font-size:8px}.memory-diagnostic-finding.stale{border-radius:4px;background:#FFF8EA;padding:1px 3px}.memory-diagnostic-dot{width:6px;height:6px;border-radius:50%;background:#A0A0A0}.memory-diagnostic-finding.healthy .memory-diagnostic-dot{background:#34C759}.memory-diagnostic-finding.attention .memory-diagnostic-dot{background:#FF9F0A}.memory-diagnostic-finding.critical .memory-diagnostic-dot{background:#FF3B30}.memory-diagnostic-finding.stale .memory-diagnostic-dot{background:#D48700}.memory-diagnostic-label{font-weight:650;color:#444;white-space:nowrap}.memory-diagnostic-copy{color:#747474;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.memory-diagnostic-empty{font-size:9px;color:#777;line-height:1.35;padding-top:5px}.memory-diagnostic-error{display:grid;grid-template-columns:12px minmax(0,1fr) auto;align-items:center;gap:6px;border:1px solid #E0A861;border-radius:6px;background:#FFF7E8;color:#71440C;padding:5px 6px;margin-top:4px;font-size:8px;line-height:1.3}.memory-diagnostic-error[hidden]{display:none}.memory-diagnostic-error-mark{font-weight:800;color:#B86200}.memory-diagnostic-error-copy{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.memory-diagnostic-error .memory-diagnostic-btn{padding:2px 6px;border-color:#C98B43;background:#fff;color:#7A4300}.mem-info-grid.stale .val{color:#955000}.memory-pressure-summary.stale{background:#FFF9EF;border-radius:5px}
@media(max-width:800px){.memory-bottom-panel{height:238px!important}.memory-bottom-panel .graph-area{flex-wrap:wrap}.memory-pressure-summary{flex-basis:150px}.memory-detail-section{flex:1}.memory-diagnostics-section{flex:1 0 100%;min-width:0;border-left:0;border-top:1px solid #D0D0D0;padding:7px 0 0}.memory-diagnostic-findings{grid-template-columns:repeat(2,minmax(0,1fr))}}
.status-bar{background:linear-gradient(180deg,#F0F0F0 0%,#DCDCDC 100%);border-top:1px solid #B8B8B8;padding:3px 12px;font-size:11px;color:#555;display:flex;gap:20px}
.status-bar .s-item{display:flex;gap:4px}
.usage-bar{height:14px;background:#E0E0E0;border-radius:3px;overflow:hidden;margin:4px 0}
.usage-bar-fill{height:100%;transition:width 0.5s}
.energy-bar{display:inline-block;height:10px;border-radius:2px;transition:width 0.3s}
.energy-state-row td{height:96px;text-align:center;color:#777;font-size:11px;white-space:normal}.energy-state-row.unavailable td{color:#8A5A18}.energy-state-dot{display:inline-block;width:7px;height:7px;margin-right:7px;border-radius:50%;background:#FF9F0A;vertical-align:1px;animation:energy-pulse 1.2s ease-in-out infinite}.energy-state-row.unavailable .energy-state-dot{animation:none;background:#C98A2E}.energy-graph-state{display:grid;place-items:center;width:100%;height:100%;color:rgba(255,255,255,.55);font-size:10px;letter-spacing:.01em}@keyframes energy-pulse{0%,100%{opacity:.35}50%{opacity:1}}@media(prefers-reduced-motion:reduce){.energy-state-dot{animation:none}}
#disk-tab{position:relative;background:#EEF2F6}#disk-tab>.table-container{background:#fff}#disk-tab>.bottom-panel{border-top:1px solid #D9E0E7;background:#EEF2F6;padding:10px 12px}.disk-overview{display:grid;grid-template-columns:minmax(0,1fr) minmax(235px,.34fr);gap:10px}.disk-storage-card,.disk-io-card{min-width:0;border:1px solid #D8E0E8;border-radius:13px;background:#fff;box-shadow:0 2px 7px rgba(31,52,73,.05)}.disk-storage-card{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:9px 16px;padding:11px 12px}.disk-overview-kicker{color:#667583;font-size:8px;font-weight:720;letter-spacing:.08em;text-transform:uppercase}.disk-capacity-line{display:flex;align-items:baseline;gap:6px;margin-top:3px}.disk-capacity-line strong{color:#182635;font-size:20px;line-height:1;font-weight:720;letter-spacing:-.025em;font-variant-numeric:tabular-nums}.disk-capacity-line span{color:#6A7783;font-size:9px}.disk-capacity-free{color:#506171;font-size:9px;margin-top:4px}.disk-capacity-track{grid-column:1;align-self:end;height:8px;border-radius:999px;background:#E5EAF0;overflow:hidden;box-shadow:inset 0 1px 2px rgba(33,51,69,.08)}.disk-capacity-track .usage-bar-fill{height:100%;border-radius:inherit;background:linear-gradient(90deg,#39B98A 0%,#5AA8F8 62%,#0A84FF 100%)!important;transition:width .45s ease}.disk-cleanup-trigger{grid-column:2;grid-row:1/3;align-self:stretch;display:grid;grid-template-columns:34px minmax(0,1fr) auto;align-items:center;gap:9px;min-width:225px;border:1px solid #0878E3;border-radius:11px;background:#0A84FF;color:#fff;padding:9px 10px;text-align:left;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer;box-shadow:0 4px 12px rgba(10,132,255,.18);transition:transform .15s ease,box-shadow .15s ease,background .15s ease}.disk-cleanup-trigger:hover{background:#0878E3;box-shadow:0 6px 15px rgba(10,132,255,.24);transform:translateY(-1px)}.disk-cleanup-trigger-icon{display:grid;place-items:center;width:34px;height:34px;border-radius:9px;background:rgba(255,255,255,.16)}.disk-cleanup-trigger-icon svg{width:19px;height:19px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.disk-cleanup-trigger-copy{min-width:0}.disk-cleanup-trigger-copy strong,.disk-cleanup-trigger-copy small{display:block}.disk-cleanup-trigger-copy strong{font-size:11px;line-height:1.2;font-weight:720}.disk-cleanup-trigger-copy small{margin-top:2px;color:rgba(255,255,255,.79);font-size:8px;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.disk-cleanup-trigger-arrow{font-size:18px;line-height:1;color:rgba(255,255,255,.82)}.disk-cleanup-trigger:focus-visible,.disk-cleanup-btn:focus-visible,.disk-cleanup-close:focus-visible,.disk-cleanup-filter:focus-visible,.disk-cleanup-category:focus-visible,.disk-cleanup-select-tools button:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(10,132,255,.2);border-color:#0A84FF}.disk-io-card{padding:11px 12px}.disk-io-head{display:flex;align-items:baseline;justify-content:space-between;gap:8px}.disk-io-head h2{font-size:12px;color:#1D2A37}.disk-io-head span{font-size:8px;color:#7A8792}.disk-io-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:8px}.disk-io-metric{min-width:0;border-radius:8px;background:#F4F7FA;padding:6px 7px}.disk-io-metric span{display:block;color:#76838E;font-size:7px;text-transform:uppercase;letter-spacing:.05em}.disk-io-metric strong{display:block;margin-top:2px;color:#263746;font-size:10px;font-weight:680;font-variant-numeric:tabular-nums;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.disk-cleanup-sheet[hidden]{display:none}.disk-cleanup-sheet{position:absolute;z-index:20;inset:0;display:flex;flex-direction:column;min-height:0;color:#172331;background:#F3F6F9}.disk-cleanup-head{display:flex;align-items:center;gap:11px;padding:12px 14px 10px;border-bottom:1px solid #DCE3EA;background:rgba(255,255,255,.96);box-shadow:0 1px 5px rgba(29,47,65,.04)}.disk-cleanup-head-icon{display:grid;place-items:center;flex:none;width:36px;height:36px;border-radius:10px;background:#EAF4FF;color:#0878E3}.disk-cleanup-head-icon svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.disk-cleanup-title{flex:1;min-width:0}.disk-cleanup-kicker{font-size:8px;font-weight:700;color:#647483}.disk-cleanup-title h1{font-size:18px;line-height:1.1;letter-spacing:-.02em;margin-top:2px}.disk-cleanup-title p{font-size:9px;color:#657481;line-height:1.4;margin-top:3px}.disk-cleanup-close{display:grid;place-items:center;width:29px;height:29px;flex:none;border:1px solid #CDD6DE;border-radius:50%;background:#F7F9FB;color:#536272;font-size:15px;cursor:pointer}.disk-cleanup-close:hover{background:#EDF1F5;color:#1F2D3A}.disk-cleanup-summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;padding:9px 14px 0}.disk-cleanup-metric{min-width:0;border:1px solid #D9E1E8;border-radius:11px;background:#fff;padding:8px 10px;box-shadow:0 1px 3px rgba(31,52,73,.035)}.disk-cleanup-metric span{display:block;color:#6D7A86;font-size:8px;font-weight:680}.disk-cleanup-metric strong{display:block;font-size:18px;line-height:1.1;margin-top:3px;font-variant-numeric:tabular-nums;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.disk-cleanup-metric small{display:block;color:#7B8791;font-size:8px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.disk-cleanup-boundary{display:flex;gap:8px;align-items:flex-start;margin:8px 14px 0;border:1px solid #BBD4EA;border-radius:10px;background:#F1F7FD;color:#40586E;padding:7px 9px;font-size:8px;line-height:1.42}.disk-cleanup-boundary strong{color:#193C5A}.disk-cleanup-boundary-mark{display:grid;place-items:center;flex:none;width:17px;height:17px;border-radius:50%;background:#DCEEFF;color:#0878E3;font-size:10px;line-height:1}.disk-cleanup-controls{display:flex;align-items:center;gap:7px;padding:8px 14px}.disk-cleanup-btn{min-height:29px;border:1px solid #C7D1DB;border-radius:8px;background:#fff;color:#2A3A48;padding:6px 10px;font:660 9px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer;white-space:nowrap}.disk-cleanup-btn:hover:not(:disabled){border-color:#8BA8C2;background:#F8FBFE}.disk-cleanup-btn.primary{border-color:#0A84FF;background:#0A84FF;color:#fff}.disk-cleanup-btn.primary:hover:not(:disabled){border-color:#0878E3;background:#0878E3}.disk-cleanup-btn:disabled{opacity:.42;cursor:default}.disk-cleanup-status{min-width:0;flex:1;color:#687782;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.disk-cleanup-status.error{color:#A2323C}.disk-cleanup-progress{height:3px;margin:0 14px;background:#D9E2EA;overflow:hidden;border-radius:999px}.disk-cleanup-progress[hidden]{display:none}.disk-cleanup-progress span{display:block;width:34%;height:100%;border-radius:inherit;background:#0A84FF;animation:disk-cleanup-scan 1.15s ease-in-out infinite}@keyframes disk-cleanup-scan{0%{transform:translateX(-105%)}100%{transform:translateX(300%)}}
.disk-cleanup-workbench{display:grid;grid-template-columns:minmax(150px,190px) minmax(0,1fr);gap:9px;min-height:0;flex:1;padding:7px 14px 9px}.disk-cleanup-categories,.disk-cleanup-results{min-width:0;min-height:0;border:1px solid #D6DFE7;border-radius:11px;background:#fff;overflow:hidden;box-shadow:0 1px 3px rgba(31,52,73,.035)}.disk-cleanup-section-head{display:flex;align-items:center;justify-content:space-between;gap:6px;min-height:34px;padding:8px 10px;border-bottom:1px solid #E4E9EE;background:#FAFBFC}.disk-cleanup-section-head h2{font-size:10px}.disk-cleanup-section-head span{font-size:8px;color:#77848F}.disk-cleanup-category-list{height:calc(100% - 34px);overflow:auto;padding:5px}.disk-cleanup-category{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:2px 6px;width:100%;border:1px solid transparent;border-radius:8px;background:transparent;color:#2A3947;padding:7px;text-align:left;font:inherit;cursor:pointer}.disk-cleanup-category:hover{background:#F2F7FC}.disk-cleanup-category.active{border-color:#B8D8F5;background:#EAF4FF;color:#075FAE}.disk-cleanup-category-name{min-width:0;font-size:9px;font-weight:670;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.disk-cleanup-category-bytes{font-size:9px;font-weight:700;font-variant-numeric:tabular-nums}.disk-cleanup-category-meta{grid-column:1/-1;font-size:8px;color:#7A8791}.disk-cleanup-results{display:flex;flex-direction:column}.disk-cleanup-result-tools{display:flex;align-items:center;gap:5px}.disk-cleanup-filter{border:1px solid #CBD5DE;border-radius:999px;background:#fff;color:#64727F;padding:4px 7px;font:650 8px -apple-system,sans-serif;cursor:pointer}.disk-cleanup-filter.active{border-color:#8BC6F7;background:#EAF4FF;color:#075FAE}.disk-cleanup-candidate-list{min-height:0;flex:1;overflow:auto;padding:4px 7px}.disk-cleanup-candidate{display:grid;grid-template-columns:18px minmax(0,1fr) auto;gap:8px;align-items:center;min-height:46px;border-top:1px solid #E9EDF1;padding:6px 4px}.disk-cleanup-candidate:first-child{border-top:0}.disk-cleanup-candidate input{accent-color:#0A84FF}.disk-cleanup-candidate-main{min-width:0}.disk-cleanup-candidate-target{font:650 9px ui-monospace,SFMono-Regular,Menlo,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.disk-cleanup-candidate-detail{display:flex;gap:5px;align-items:center;margin-top:2px;min-width:0;color:#74818C;font-size:8px}.disk-cleanup-candidate-reason{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.disk-cleanup-candidate-side{text-align:right}.disk-cleanup-candidate-bytes{font-size:10px;font-weight:700;font-variant-numeric:tabular-nums}.disk-cleanup-risk{display:inline-block;margin-top:2px;border-radius:999px;background:#EDF0F2;color:#67737D;padding:2px 6px;font-size:7px;font-weight:740;text-transform:uppercase}.disk-cleanup-risk.safe{background:#E7F5E8;color:#27741A}.disk-cleanup-risk.recoverable{background:#E7F3FB;color:#12638E}.disk-cleanup-risk.review-required{background:#FFF0D9;color:#925200}.disk-cleanup-empty{display:grid;place-items:center;min-height:120px;padding:18px;text-align:center;color:#71808C;font-size:9px;line-height:1.5}.disk-cleanup-select-tools{display:flex;align-items:center;gap:7px;border-top:1px solid #E3E8ED;padding:6px 9px;background:#FAFBFC}.disk-cleanup-select-tools span{margin-right:auto;color:#6C7984;font-size:8px}.disk-cleanup-select-tools button{border:0;background:transparent;color:#0878E3;font:650 8px -apple-system,sans-serif;cursor:pointer;padding:3px}.disk-cleanup-foot{display:flex;align-items:center;gap:7px;min-height:44px;padding:7px 14px;border-top:1px solid #D9E1E8;background:#fff}.disk-cleanup-foot-note{min-width:0;flex:1;color:#6B7883;font-size:8px;line-height:1.4}.disk-cleanup-foot-note strong{color:#344654}.disk-cleanup-delta.positive{color:#22723A}.disk-cleanup-delta.negative{color:#9A4D24}
@media(max-width:760px){#disk-tab>.bottom-panel{padding:8px}.disk-overview{grid-template-columns:1fr}.disk-storage-card{grid-template-columns:minmax(0,1fr) minmax(190px,.72fr)}.disk-io-card{display:none}.disk-cleanup-trigger{min-width:0}.disk-cleanup-workbench{grid-template-columns:125px minmax(0,1fr)}.disk-cleanup-title p,.disk-cleanup-foot-note{display:none}.disk-cleanup-summary{gap:5px}.disk-cleanup-metric{padding:7px}.disk-cleanup-foot{flex-wrap:wrap}.disk-cleanup-btn{padding-left:8px;padding-right:8px}}
@media(prefers-reduced-motion:reduce){.disk-cleanup-progress span{animation:none;width:100%}.disk-cleanup-trigger{transition:none}}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:#F0F0F0}
::-webkit-scrollbar-thumb{background:#C0C0C0;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#A0A0A0}
.act-btn{font-size:10px;padding:1px 6px;border:1px solid #C0C0C0;border-radius:4px;background:#fff;cursor:pointer;color:#333}
.act-btn:hover{background:#E8E8E8}
.act-btn.danger{color:#FF3B30;border-color:#FF3B30}
.act-btn.danger:hover{background:#FF3B30;color:#fff}
.feature-scroll{flex:1;overflow:auto;padding:12px 14px;background:#ECECEC}
.feature-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:9px}
.feature-heading h1{font-size:21px;line-height:1.1;font-weight:650;letter-spacing:-.02em}
.feature-subtitle{font-size:10px;color:#686868;margin-top:3px;line-height:1.35}
.feature-actions{display:flex;align-items:center;gap:6px;flex:none}
.feature-btn{border:1px solid #B9B9B9;border-radius:6px;background:linear-gradient(#fff,#F2F2F2);color:#222;padding:5px 9px;font:600 10px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}
.feature-btn:hover:not(:disabled){background:#fff;border-color:#949494}.feature-btn:disabled{opacity:.45;cursor:default}.feature-btn.primary{color:#fff;border-color:#006ADB;background:linear-gradient(#1688F8,#0877DF)}.feature-btn.danger{color:#B42338;border-color:#E2AAB2;background:#FFF7F8}
.privacy-strip{display:flex;align-items:center;gap:8px;border:1px solid #BFD8BE;border-radius:8px;background:#F3FAF1;color:#285E2E;padding:7px 9px;margin-bottom:9px;font-size:10px;line-height:1.35}.privacy-lock{font-size:14px}.privacy-strip strong{font-weight:700}
.feature-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-bottom:9px}#brain-tab .feature-summary{grid-template-columns:repeat(5,minmax(0,1fr))}.summary-tile{border:1px solid #D0D0D0;background:#fff;border-radius:8px;padding:7px 9px}.summary-tile span{display:block;color:#777;font-size:8px;text-transform:uppercase;letter-spacing:.06em}.summary-tile strong{display:block;font-size:18px;margin-top:2px;font-variant-numeric:tabular-nums}.summary-tile small{display:block;color:#777;font-size:8px;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.brain-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.brain-list[hidden]{display:none}.brain-card{border:1px solid #CFCFCF;background:#fff;border-radius:9px;padding:9px;min-width:0;cursor:pointer;outline:none}.brain-card:hover{border-color:#999}.brain-card:focus-visible{border-color:#007AFF;box-shadow:0 0 0 3px rgba(0,122,255,.16)}.brain-card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}.brain-label{font-size:12px;font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.brain-type{font-size:9px;color:#777;margin-top:1px}.brain-path{font:9px ui-monospace,SFMono-Regular,Menlo,monospace;color:#555;background:#F7F7F7;border-radius:4px;padding:4px 5px;margin:7px 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.brain-evidence{font-size:9px;color:#777;line-height:1.35;min-height:24px}.brain-card-hint{font-size:8px;color:#777;margin-top:5px}.brain-controls{display:flex;gap:5px;flex-wrap:wrap;margin-top:7px}.brain-empty{grid-column:1/-1;border:1px dashed #BFBFBF;border-radius:9px;background:#F8F8F8;padding:22px;text-align:center;color:#666}.status-pill{display:inline-flex;align-items:center;border-radius:999px;padding:2px 7px;font-size:8px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;background:#ECECEC;color:#555}.status-pill.connected,.status-pill.ready,.status-pill.trusted,.status-pill.completed,.status-pill.transcript-observed{background:#E8F6E4;color:#29731B}.status-pill.discovered,.status-pill.resolving,.status-pill.owner-preflight,.status-pill.exact-task-resume-steer,.status-pill.exact-session-delivery,.status-pill.accepted,.status-pill.queued,.status-pill.working{background:#E8F2FF;color:#075FAE}.status-pill.ignored,.status-pill.offline,.status-pill.no-target{background:#F1F1F1;color:#666}.status-pill.ambiguous,.status-pill.uncertain-after-send{background:#FFF2DD;color:#995000}.status-pill.failed,.status-pill.failed-before-send{background:#FDE7EA;color:#B42338}
.brain-view-switch{display:flex;border:1px solid #B9B9B9;border-radius:7px;background:#E8E8EA;padding:2px}.brain-view-button{border:0;border-radius:5px;background:transparent;color:#666;padding:4px 9px;font:650 9px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.brain-view-button[aria-selected="true"]{background:#fff;color:#151515;box-shadow:0 1px 3px rgba(0,0,0,.16)}.brain-files-view[hidden],.brain-visual[hidden]{display:none}.brain-family{grid-column:1/-1;border:1px solid #AFC5DA;border-radius:11px;background:linear-gradient(145deg,#F8FBFF,#F1F6FC);padding:10px;box-shadow:0 7px 24px rgba(52,89,128,.08)}.brain-family-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px}.brain-family-title{font-size:12px;font-weight:700;color:#23374C}.brain-family-copy{font-size:8px;color:#68798B;margin-top:2px}.brain-family-parent{display:flex;align-items:center;gap:8px;width:100%;border:1px solid #9DB9D5;border-radius:8px;background:#fff;padding:8px;text-align:left;cursor:pointer}.brain-family-parent:hover,.brain-family-parent:focus-visible{border-color:#277AD3;outline:none;box-shadow:0 0 0 3px rgba(0,122,255,.12)}.brain-orbit-mark{width:28px;height:28px;display:grid;place-items:center;flex:none;border-radius:50%;color:#fff;background:radial-gradient(circle at 35% 30%,#76B4FF,#1E5BA7 67%,#123B72);box-shadow:0 4px 13px rgba(30,91,167,.28);font-size:10px;font-weight:760}.brain-family-parent-copy{min-width:0;flex:1}.brain-family-parent-copy strong{display:block;font-size:11px}.brain-family-parent-copy span{display:block;color:#6E7D8B;font-size:8px;margin-top:1px}.brain-child-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:6px;margin-top:7px}.brain-child-card{display:grid;grid-template-columns:20px minmax(0,1fr) auto;align-items:center;gap:7px;min-height:46px;border:1px solid #D5DEE8;border-radius:8px;background:#fff;color:#252B31;padding:6px 7px;text-align:left;cursor:pointer}.brain-child-card:hover:not(:disabled),.brain-child-card:focus-visible{border-color:#4089D5;background:#F8FBFF;outline:none}.brain-child-card:disabled{cursor:not-allowed;opacity:.58}.brain-child-provider{width:20px;height:20px;display:grid;place-items:center;border-radius:6px;background:#28558B;color:#fff;font-size:7px;font-weight:760}.brain-child-provider.claude{background:#74452E}.brain-child-copy{min-width:0}.brain-child-copy strong{display:block;font-size:9px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.brain-child-copy span{display:block;color:#74808B;font-size:7px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.brain-child-state{font-size:7px;text-transform:uppercase;color:#4C708F}.brain-child-state.dormant{color:#8A6E3E}.brain-visual{position:relative;min-height:470px;border:1px solid #17263A;border-radius:12px;overflow:hidden;background:radial-gradient(circle at 50% 43%,#183A62 0,#0E223B 35%,#07131F 77%);box-shadow:inset 0 1px rgba(255,255,255,.09),0 10px 30px rgba(20,45,75,.18)}.brain-visual-toolbar{position:absolute;z-index:3;left:10px;right:10px;top:10px;display:flex;align-items:center;gap:5px;pointer-events:none}.brain-visual-toolbar>*{pointer-events:auto}.brain-visual-title{margin-right:auto;color:#DDEEFF;font-size:10px;font-weight:680;text-shadow:0 1px 2px #000}.brain-visual-btn{border:1px solid rgba(181,215,250,.27);border-radius:6px;background:rgba(12,28,47,.82);color:#D8EAFC;padding:4px 8px;font-size:8px;cursor:pointer}.brain-visual-btn:hover,.brain-visual-btn:focus-visible{background:#183F68;outline:none;border-color:#6EAAF0}.brain-graph{display:block;width:100%;height:470px;touch-action:none;cursor:grab}.brain-graph.dragging{cursor:grabbing}.brain-graph-edge{fill:none;stroke:#6FA9E8;stroke-width:1.2;opacity:.34}.brain-graph-edge.dormant{stroke:#C6A66C;opacity:.24}.brain-graph-node{cursor:pointer;outline:none}.brain-graph-node rect{fill:#F7FBFF;stroke:#82B4E9;stroke-width:1.4;filter:drop-shadow(0 5px 8px rgba(0,0,0,.25))}.brain-graph-node.parent rect{fill:#E9F4FF;stroke:#93C6FF;stroke-width:2}.brain-graph-node.claude rect{fill:#FFF4ED;stroke:#D99268}.brain-graph-node.dormant rect{fill:#F7F1E6;stroke:#B79B69;opacity:.88}.brain-graph-node.blocked rect{fill:#E9E9EB;stroke:#888;opacity:.7}.brain-graph-node:hover rect,.brain-graph-node:focus-visible rect{stroke:#fff;stroke-width:2.4}.brain-graph-label{font:650 11px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;fill:#17293C}.brain-graph-meta{font:8px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;fill:#5B7186}.brain-visual-legend{position:absolute;left:10px;bottom:9px;color:#AFC7DF;font-size:8px}.brain-visual-status{position:absolute;right:10px;bottom:9px;color:#89A8C6;font-size:8px}.brain-visual-status[hidden]{display:none}
#brain-tab.visual-mode .feature-summary{grid-template-columns:repeat(5,minmax(0,1fr));gap:5px;margin-bottom:7px}#brain-tab.visual-mode .summary-tile{padding:5px 7px}#brain-tab.visual-mode .summary-tile strong{font-size:14px}#brain-tab.visual-mode .summary-tile small{font-size:7px}#brain-tab.visual-mode .privacy-strip{padding:5px 8px;margin-bottom:7px;font-size:9px}#brain-tab.visual-mode .brain-visual,#brain-tab.visual-mode .brain-graph{height:calc(100vh - 244px);min-height:380px}
.brain-browser{border:1px solid #AFC5DA;background:#fff;border-radius:9px;margin-bottom:9px;min-height:250px;overflow:hidden}.brain-browser[hidden]{display:none}.brain-browser-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding:9px 10px;border-bottom:1px solid #E1E6EB;background:#F7FAFD}.brain-browser-title{font-size:12px;font-weight:650}.brain-browser-copy{font-size:8px;color:#68727D;margin-top:2px}.brain-browser-actions{display:flex;gap:5px;align-items:center}.brain-breadcrumbs{display:flex;align-items:center;gap:3px;flex-wrap:wrap;padding:7px 10px;border-bottom:1px solid #E8E8E8;background:#FBFBFB}.brain-crumb{border:0;background:transparent;color:#0668C7;padding:2px 3px;font:600 9px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.brain-crumb.current{color:#333;cursor:default}.brain-crumb-sep{color:#999;font-size:9px}.brain-browser-message{margin:8px 10px;border:1px solid #E1CF9F;background:#FFF9E9;color:#6C5310;border-radius:6px;padding:7px 8px;font-size:9px;line-height:1.4}.brain-browser-message[hidden]{display:none}.brain-directory{padding:4px 10px 7px}.brain-item{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;width:100%;border:0;border-top:1px solid #ECECEC;background:transparent;color:#222;padding:7px 3px;text-align:left;cursor:pointer}.brain-item:first-child{border-top:0}.brain-item:hover,.brain-item:focus-visible{background:#F4F8FC;outline:none}.brain-item.restricted{color:#777}.brain-item-name{display:block;font-size:10px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.brain-item-path{display:block;font:8px ui-monospace,SFMono-Regular,Menlo,monospace;color:#777;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:1px}.brain-item-meta{font-size:8px;color:#777;white-space:nowrap;text-align:right}.brain-pager{display:flex;align-items:center;justify-content:flex-end;gap:6px;border-top:1px solid #E8E8E8;padding:7px 10px;background:#FAFAFA}.brain-page-copy{font-size:8px;color:#777;margin-right:auto}.brain-note{padding:9px 10px}.brain-note[hidden],.brain-directory[hidden],.brain-pager[hidden]{display:none}.brain-note-meta{font:8px ui-monospace,SFMono-Regular,Menlo,monospace;color:#66717E;margin-bottom:7px;overflow-wrap:anywhere}.brain-note-body{margin:0;max-height:310px;overflow:auto;border:1px solid #D8D8D8;border-radius:7px;background:#FAFAFA;padding:9px;white-space:pre-wrap;overflow-wrap:anywhere;font:10px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;color:#202020}.brain-note-boundary{font-size:8px;color:#68727D;margin-top:6px}
.structure-panel{border:1px solid #9FC5ED;background:#F6FAFF;border-radius:9px;padding:10px;margin-bottom:9px}.structure-panel[hidden]{display:none}.structure-title{font-size:12px;font-weight:650}.structure-copy{font-size:9px;color:#586474;line-height:1.4;margin-top:3px}.structure-folders{display:flex;gap:4px;flex-wrap:wrap;margin-top:7px}.folder-chip{border:1px solid #CFDDED;background:#fff;border-radius:5px;padding:3px 6px;font:8px ui-monospace,SFMono-Regular,Menlo,monospace}.confirmation-row{display:flex;gap:6px;align-items:center;margin-top:8px}.confirmation-row input{width:92px;border:1px solid #B7B7B7;border-radius:5px;padding:5px 6px;font:10px ui-monospace,SFMono-Regular,Menlo,monospace}
.dispatch-layout{display:grid;grid-template-columns:minmax(0,1.32fr) minmax(280px,.85fr);gap:9px;align-items:start}.dispatch-card{border:1px solid #CBCBCB;background:#fff;border-radius:9px;padding:10px}.dispatch-card h2{font-size:12px;font-weight:650;margin-bottom:7px}.dispatch-composer textarea{display:block;width:100%;height:135px;resize:vertical;border:1px solid #BDBDBD;border-radius:7px;padding:8px;font:11px/1.45 -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;outline:none}.dispatch-composer textarea:focus{border-color:#007AFF;box-shadow:0 0 0 3px rgba(0,122,255,.12)}.dispatch-row{display:flex;align-items:center;gap:7px;margin-top:8px}.dispatch-row .spacer{flex:1}.diagnostic-toggle{font-size:9px;color:#666;display:flex;align-items:center;gap:4px}.dispatch-target{border:1px solid #D3DCE7;background:#F8FAFC;border-radius:7px;padding:8px;margin-top:8px;min-height:66px}.dispatch-target-title{font-size:11px;font-weight:650}.dispatch-target-meta{font-size:9px;color:#626B76;margin-top:2px}.dispatch-target-id{font:8px ui-monospace,SFMono-Regular,Menlo,monospace;color:#777;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.dispatch-reason{font-size:9px;line-height:1.35;color:#626262;margin-top:6px}.dispatch-choice{display:flex;gap:7px;align-items:flex-start;border-top:1px solid #E5E5E5;padding:6px 0}.dispatch-choice:first-child{border-top:0}.dispatch-choice label{min-width:0;cursor:pointer}.dispatch-phase{display:flex;align-items:center;gap:7px;margin-top:8px;border-top:1px solid #E5E5E5;padding-top:8px}.dispatch-phase-copy{font-size:9px;color:#666}.dispatch-history{max-height:390px;overflow:auto}.history-entry{padding:7px 0;border-top:1px solid #E7E7E7}.history-entry:first-child{border-top:0}.history-top{display:flex;justify-content:space-between;align-items:center;gap:7px}.history-destination{font-size:10px;font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.history-meta,.history-reason,.history-hash{font-size:8px;color:#777;margin-top:2px;line-height:1.3}.history-hash{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.dispatch-empty{color:#777;font-size:10px;line-height:1.4;padding:12px 2px}
.status-pill.armed{background:#E8F6E4;color:#29731B}.status-pill.dry-run{background:#E8F2FF;color:#075FAE}.status-pill.stale{background:#FFF2DD;color:#995000}.status-pill.not-installed,.status-pill.unsupported{background:#F1F1F1;color:#666}
.guard-layout{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(300px,.85fr);gap:9px;align-items:start}.guard-column{display:grid;gap:9px}.guard-card{border:1px solid #CBCBCB;background:#fff;border-radius:9px;padding:10px;min-width:0}.guard-card h2{font-size:12px;font-weight:650;margin-bottom:7px}.guard-card-copy{font-size:9px;line-height:1.4;color:#666}.guard-trends{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.guard-trend{border:1px solid #DEDEDE;border-radius:7px;background:#FAFAFA;padding:8px;min-width:0}.guard-trend-head{display:flex;align-items:baseline;justify-content:space-between;gap:7px}.guard-trend-title{font-size:9px;color:#666}.guard-trend-value{font-size:16px;font-weight:650;font-variant-numeric:tabular-nums}.guard-trend-meta{font-size:8px;color:#777;margin-top:2px}.guard-spark{height:42px;display:flex;align-items:flex-end;gap:3px;margin-top:7px}.guard-spark span{flex:1;min-width:3px;border-radius:2px 2px 0 0;background:#4D9B69;opacity:.72}.guard-spark.load span{background:#5C86B7}.guard-evidence{max-height:245px;overflow:auto}.guard-evidence-row{padding:7px 0;border-top:1px solid #E7E7E7}.guard-evidence-row:first-child{border-top:0}.guard-evidence-top{display:flex;align-items:center;justify-content:space-between;gap:7px}.guard-evidence-label{font-size:10px;font-weight:620;min-width:0}.guard-evidence-meta{font-size:8px;color:#777;margin-top:2px}.guard-empty{border:1px dashed #C8C8C8;border-radius:7px;background:#FAFAFA;color:#777;padding:12px;font-size:10px;line-height:1.4}.guard-pending{display:flex;align-items:flex-start;gap:8px;border:1px solid #D8D8D8;border-radius:7px;background:#FAFAFA;padding:8px}.guard-pending-copy{font-size:9px;line-height:1.4;color:#666}.guard-unavailable{border-color:#D8D8D8;background:#F6F6F6}.guard-unavailable[hidden]{display:none}
.workspace-shell{--rail-width:252px;display:flex;width:100vw;height:100vh;min-width:0;overflow:hidden;background:#171719}.workspace-rail{flex:0 0 min(var(--rail-width),40vw);width:min(var(--rail-width),40vw);min-width:220px;height:100vh;display:flex;flex-direction:column;color:#F5F5F7;background:radial-gradient(circle at 8% -5%,rgba(64,111,196,.22),transparent 30%),linear-gradient(180deg,#202024,#171719);border-right:1px solid #060607;overflow:hidden}.workspace-shell.rail-collapsed .workspace-rail{flex-basis:52px;width:52px;min-width:52px}.workspace-shell.rail-collapsed .workspace-resizer{display:none}
.workspace-rail-header{height:58px;flex:none;display:flex;align-items:center;gap:9px;padding:10px 10px 8px 12px;border-bottom:1px solid rgba(255,255,255,.07)}.workspace-mark{width:29px;height:29px;flex:none;border-radius:9px;display:grid;place-items:center;color:#fff;font-size:11px;font-weight:760;background:linear-gradient(145deg,#5D9BFF,#2758B7);box-shadow:0 7px 20px rgba(24,76,166,.35),inset 0 1px rgba(255,255,255,.28)}.workspace-brand{min-width:0;flex:1}.workspace-brand strong{display:block;font-size:12px}.workspace-brand span{display:block;margin-top:1px;color:#909098;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.workspace-icon-btn{width:28px;height:28px;flex:none;border:1px solid rgba(255,255,255,.1);border-radius:7px;color:#C8C8CD;background:rgba(255,255,255,.035);font:600 13px -apple-system,sans-serif;cursor:pointer}.workspace-icon-btn:hover,.workspace-icon-btn:focus-visible{color:#fff;background:rgba(255,255,255,.09);outline:none}.workspace-shell.rail-collapsed .workspace-brand,.workspace-shell.rail-collapsed .workspace-rail-body,.workspace-shell.rail-collapsed .workspace-rail-footer{display:none}.workspace-shell.rail-collapsed .workspace-rail-header{padding:10px 11px;height:auto;flex-direction:column}.workspace-shell.rail-collapsed .workspace-collapse{transform:rotate(180deg)}
.workspace-rail-body{display:flex;flex-direction:column;min-height:0;flex:1;padding:10px 8px 0}.workspace-search-wrap{position:relative;flex:none}.workspace-search-wrap:before{content:'⌕';position:absolute;left:9px;top:6px;color:#777780;font-size:14px}.workspace-search{width:100%;height:30px;border:1px solid rgba(255,255,255,.09);border-radius:8px;background:rgba(255,255,255,.055);color:#fff;padding:0 29px 0 27px;outline:none;font:11px -apple-system,sans-serif}.workspace-search::placeholder{color:#777780}.workspace-search:focus{border-color:#4C8BE9;box-shadow:0 0 0 3px rgba(55,125,231,.16)}.workspace-refresh{position:absolute;right:4px;top:3px;width:24px;height:24px;border:0;background:transparent;color:#8E8E95;border-radius:6px;cursor:pointer}.workspace-refresh:hover{color:#fff;background:rgba(255,255,255,.07)}.workspace-refresh.loading{animation:workspace-spin .9s linear infinite}@keyframes workspace-spin{to{transform:rotate(360deg)}}
.workspace-tools{display:flex;align-items:center;gap:5px;margin-top:8px;flex:none}.workspace-provider{height:25px;border:1px solid rgba(255,255,255,.08);border-radius:7px;background:transparent;color:#85858D;padding:0 8px;font:650 9px -apple-system,sans-serif;cursor:pointer}.workspace-provider.active{color:#E9F2FF;border-color:rgba(83,144,239,.45);background:rgba(51,112,205,.19)}.workspace-manage{margin-left:auto;width:26px;height:25px;border:1px solid rgba(255,255,255,.08);border-radius:7px;background:transparent;color:#A0A0A7;cursor:pointer}.workspace-provider:hover,.workspace-manage:hover{color:#fff;background:rgba(255,255,255,.07)}.workspace-host-switch{display:grid;grid-template-columns:1fr 1fr;gap:3px;margin-top:8px;padding:3px;border:1px solid rgba(255,255,255,.08);border-radius:9px;background:rgba(0,0,0,.18)}.workspace-host-mode{min-height:27px;border:0;border-radius:6px;background:transparent;color:#85858D;font:650 9px -apple-system,sans-serif;cursor:pointer}.workspace-host-mode.active{background:linear-gradient(180deg,rgba(65,133,235,.42),rgba(43,96,180,.34));color:#F4F8FF;box-shadow:inset 0 1px rgba(255,255,255,.12)}.workspace-host-mode:hover,.workspace-host-mode:focus-visible{color:#fff;outline:none}.workspace-summary{display:flex;gap:6px;align-items:center;padding:9px 4px 5px;color:#777780;font-size:9px}.workspace-summary strong{color:#B9B9BF}.workspace-live-dot{width:5px;height:5px;border-radius:50%;background:#4DA673}
.workspace-tree{min-height:0;flex:1;overflow:auto;padding:0 1px 14px;outline:none}.workspace-tree-message{margin:9px 3px;border:1px solid rgba(255,255,255,.08);border-radius:8px;background:rgba(255,255,255,.025);padding:10px;color:#8D8D95;font-size:9px;line-height:1.45}.workspace-project{margin-top:3px}.workspace-project-row{display:grid;grid-template-columns:23px minmax(0,1fr) 39px;align-items:center;gap:2px}.workspace-project-toggle{width:23px;height:27px;border:0;border-radius:6px;background:transparent;color:#74747C;cursor:pointer}.workspace-project-toggle:hover,.workspace-project-toggle:focus-visible{background:rgba(255,255,255,.065);color:#fff;outline:none}.workspace-project-button{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:6px;width:100%;min-height:29px;border:0;border-radius:7px;background:transparent;color:#D7D7DC;padding:3px 5px;text-align:left;cursor:pointer}.workspace-project-button:hover,.workspace-project-button:focus-visible{background:linear-gradient(90deg,rgba(48,116,221,.26),rgba(48,116,221,.08));outline:none}.workspace-project-brain{width:37px;height:25px;border:1px solid rgba(119,179,245,.2);border-radius:7px;background:rgba(54,113,180,.13);color:#82BBF8;font:650 8px -apple-system,sans-serif;cursor:pointer}.workspace-project-brain:hover:not(:disabled),.workspace-project-brain:focus-visible{background:rgba(61,132,215,.32);color:#fff;outline:none}.workspace-project-brain:disabled{opacity:.35;cursor:not-allowed}.workspace-chevron{display:inline-block;color:#6F6F77;font-size:9px;text-align:center;transition:transform .14s}.workspace-project.expanded .workspace-chevron{transform:rotate(90deg)}.workspace-project-title{min-width:0;display:flex;align-items:center;gap:6px}.workspace-provider-glyph{width:16px;height:16px;display:grid;place-items:center;flex:none;border-radius:5px;color:#D9E9FF;background:#264A79;font-size:7px;font-weight:760}.workspace-provider-glyph.claude{color:#FFE6D6;background:#70422D}.workspace-project-name{font-size:10px;font-weight:610;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.workspace-project-count{color:#717179;font-size:8px}.workspace-pin{color:#78B7FF;font-size:8px}
.workspace-conversations{display:none}.workspace-project.expanded .workspace-conversations{display:block}.workspace-conversation{display:grid;grid-template-columns:8px minmax(0,1fr) auto;align-items:center;gap:6px;width:100%;min-height:34px;border:0;border-radius:7px;background:transparent;color:#BEBEC4;padding:4px 5px 4px calc(13px + var(--thread-depth,0)*12px);text-align:left;cursor:pointer}.workspace-conversation:hover,.workspace-conversation:focus-visible{background:rgba(255,255,255,.06);color:#fff;outline:none}.workspace-conversation.selected{background:linear-gradient(90deg,rgba(48,116,221,.35),rgba(48,116,221,.15));color:#fff}.workspace-conversation:disabled{cursor:not-allowed;opacity:.48}.workspace-state-dot{width:6px;height:6px;border-radius:50%;background:#696970}.workspace-state-dot.active{background:#54A7FF}.workspace-state-dot.completed{background:#55A776}.workspace-state-dot.failed{background:#E35B65}.workspace-thread-copy{display:block;min-width:0}.workspace-thread-title{display:block;font-size:10px;line-height:1.2;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.workspace-thread-meta{display:block;font-size:8px;color:#85858D;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.workspace-thread-badge{color:#777780;font-size:8px;text-transform:uppercase}.workspace-thread-pin{color:#78B7FF}
.workspace-rail-footer{flex:none;border-top:1px solid rgba(255,255,255,.07);padding:8px 10px 9px}.workspace-companions{display:flex;gap:6px}.workspace-companion{display:flex;align-items:center;gap:5px;min-width:0;flex:1;color:#85858D;font-size:9px}.workspace-companion:before{content:'';width:6px;height:6px;border-radius:50%;background:#55555C}.workspace-companion.ready{color:#B7C0CB}.workspace-companion.ready:before{background:#4DA673}.workspace-privacy{margin-top:6px;color:#74747D;font-size:8px;line-height:1.4}.workspace-resizer{flex:0 0 4px;width:4px;margin-left:-2px;z-index:4;cursor:col-resize;background:transparent}.workspace-resizer:hover,.workspace-resizer.dragging{background:#3478D4}.monitor-surface{position:relative;min-width:0;flex:1;height:100vh;display:flex;flex-direction:column;overflow:hidden;background:#ECECEC;box-shadow:-10px 0 28px rgba(0,0,0,.16)}.segmented-control{min-width:0;overflow-x:auto;scrollbar-width:none}.segmented-control::-webkit-scrollbar{display:none}.seg-btn{flex:none}.monitor-surface>.main{min-height:0}
.workspace-toast{position:fixed;left:calc(min(var(--rail-width),40vw) + 18px);bottom:31px;z-index:50;max-width:min(440px,calc(100vw - 80px));border:1px solid rgba(255,255,255,.12);border-radius:10px;background:rgba(28,28,31,.96);color:#F5F5F7;box-shadow:0 12px 34px rgba(0,0,0,.28);padding:9px 12px;font-size:10px;line-height:1.4;opacity:0;transform:translateY(8px);pointer-events:none;transition:.18s}.workspace-toast.visible{opacity:1;transform:translateY(0)}.rail-collapsed .workspace-toast{left:70px}.workspace-dialog[hidden]{display:none}.workspace-dialog{position:fixed;z-index:90;inset:0;display:grid;place-items:center;background:rgba(8,8,10,.48);backdrop-filter:blur(8px);padding:20px}.workspace-dialog-panel{width:min(520px,calc(100vw - 40px));max-height:min(620px,calc(100vh - 40px));display:flex;flex-direction:column;overflow:hidden;border:1px solid rgba(255,255,255,.16);border-radius:14px;background:#F8F8FA;box-shadow:0 26px 70px rgba(0,0,0,.34)}.workspace-dialog-head{display:flex;align-items:flex-start;gap:12px;padding:14px 15px 11px;border-bottom:1px solid #DEDEE2}.workspace-dialog-title{flex:1}.workspace-dialog-title h2{font-size:15px}.workspace-dialog-title p{font-size:9px;color:#6D6D73;line-height:1.4;margin-top:3px}.workspace-dialog-close{border:1px solid #CECED3;border-radius:7px;background:#fff;padding:5px 9px;font-size:10px;cursor:pointer}.workspace-dialog-body{overflow:auto;padding:12px 15px 15px}.workspace-chooser-section+.workspace-chooser-section{margin-top:14px}.workspace-chooser-heading{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:6px}.workspace-chooser-heading strong{font-size:11px}.workspace-chooser-heading span{font-size:8px;color:#7A7A81}.workspace-choice{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:9px;min-height:38px;border-top:1px solid #E7E7EA}.workspace-choice:first-of-type{border-top:0}.workspace-choice input{accent-color:#2677DF}.workspace-choice-copy{min-width:0}.workspace-choice-name{font-size:10px;font-weight:620;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.workspace-choice-meta{font-size:8px;color:#7A7A81;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.workspace-folder-button{border:1px solid #C8C8CE;border-radius:6px;background:#fff;color:#333;padding:4px 7px;font-size:8px;cursor:pointer}.workspace-folder-button.mapped{color:#26703A;background:#F2FAF3;border-color:#B8D7BF}.workspace-choice-empty{border:1px dashed #CBCBD0;border-radius:8px;padding:11px;color:#777;font-size:9px}
@media(max-width:1100px){.brain-list,.dispatch-layout,.guard-layout{grid-template-columns:1fr}.brain-child-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.feature-summary,.guard-trends{grid-template-columns:repeat(2,minmax(0,1fr))}.search-box input{width:130px}.seg-btn{padding-left:9px;padding-right:9px}}
@media(max-width:780px){.workspace-rail{flex-basis:min(var(--rail-width),36vw);width:min(var(--rail-width),36vw);min-width:190px}.workspace-shell.rail-collapsed .workspace-rail{min-width:52px}.search-box{display:none}.agents-overview,.brain-list,.dispatch-layout,.guard-layout{grid-template-columns:1fr}.feature-summary,.guard-trends{grid-template-columns:repeat(2,minmax(0,1fr))}}
.conversation-host[hidden]{display:none}.conversation-host{position:absolute;z-index:72;inset:0;display:flex;min-width:0;min-height:0;flex-direction:column;background:linear-gradient(160deg,#F7F9FC 0,#EDF2F8 56%,#E7EDF5 100%);color:#172435}.conversation-host-head{display:flex;align-items:center;gap:11px;min-height:64px;flex:none;border-bottom:1px solid #CCD6E2;background:rgba(255,255,255,.9);padding:10px 13px;box-shadow:0 7px 24px rgba(34,56,80,.06)}.conversation-host-back,.conversation-host-action{min-height:32px;border:1px solid #C8D3DF;border-radius:9px;background:#fff;color:#34495E;padding:0 10px;font:650 10px -apple-system,sans-serif;cursor:pointer}.conversation-host-back{width:32px;padding:0;font-size:16px}.conversation-host-back:hover,.conversation-host-action:hover,.conversation-host-back:focus-visible,.conversation-host-action:focus-visible{border-color:#72A8DF;background:#F3F8FD;outline:3px solid rgba(44,126,209,.14)}.conversation-host-identity{display:flex;align-items:center;gap:10px;min-width:0;flex:1}.conversation-host-glyph{display:grid;place-items:center;width:35px;height:35px;flex:none;border-radius:11px;background:linear-gradient(145deg,#3E8BE7,#1D5DAE);color:#fff;font-size:10px;font-weight:780;box-shadow:0 7px 18px rgba(39,102,177,.23)}.conversation-host-glyph.claude{background:linear-gradient(145deg,#A86543,#70412D);box-shadow:0 7px 18px rgba(119,68,43,.22)}.conversation-host-titles{min-width:0}.conversation-host-titles h2{font-size:15px;line-height:1.2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.conversation-host-titles p{margin-top:3px;color:#68798A;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.conversation-host-actions{display:flex;align-items:center;gap:6px}.conversation-host-action.primary{border-color:#2F7CCB;background:linear-gradient(180deg,#3D8CE0,#2773C2);color:#fff}.conversation-host-body{display:flex;min-height:0;flex:1;flex-direction:column}.conversation-host-transcript{display:flex;min-height:0;flex:1;flex-direction:column;gap:10px;overflow:auto;padding:19px 20px 16px;scroll-behavior:smooth}.conversation-host-empty{align-self:center;width:min(520px,100%);margin:auto;border:1px solid #D4DEE8;border-radius:16px;background:rgba(255,255,255,.84);padding:22px;box-shadow:0 13px 34px rgba(35,59,84,.08)}.conversation-host-empty-mark{display:grid;place-items:center;width:42px;height:42px;border-radius:13px;background:linear-gradient(145deg,#4C98EB,#2868B1);color:#fff;font-size:12px;font-weight:780}.conversation-host-empty h3{margin-top:13px;font-size:17px;letter-spacing:-.02em}.conversation-host-empty p{margin-top:7px;color:#5F7284;font-size:11px;line-height:1.55}.conversation-host-proof{display:flex;gap:6px;flex-wrap:wrap;margin-top:13px}.conversation-host-proof span{border:1px solid #CCDAE8;border-radius:999px;background:#F4F8FC;color:#48637D;padding:5px 8px;font-size:9px}.conversation-host-message{max-width:min(560px,86%);border:1px solid #D4DEE8;border-radius:14px;background:#fff;padding:10px 12px;box-shadow:0 5px 18px rgba(35,58,82,.06)}.conversation-host-message.user{align-self:flex-end;border-color:#2F77C2;background:linear-gradient(160deg,#3A86D5,#2868AD);color:#fff}.conversation-host-message.assistant{align-self:flex-start}.conversation-host-message.activity{align-self:center;max-width:92%;border-style:dashed;background:rgba(255,255,255,.58);color:#5E7082}.conversation-host-message-role{display:block;margin-bottom:4px;color:#6C7F91;font-size:9px;font-weight:740;text-transform:uppercase;letter-spacing:.05em}.conversation-host-message.user .conversation-host-message-role{color:#D9EBFF}.conversation-host-message-text{font-size:11px;line-height:1.52;white-space:pre-wrap;overflow-wrap:anywhere}.conversation-host-request-state{display:flex;align-items:center;gap:7px;margin-top:8px;border-top:1px solid rgba(105,127,149,.2);padding-top:7px;font-size:9px}.conversation-host-request-state strong{font-weight:700}.conversation-host-request-state button{margin-left:auto;border:1px solid currentColor;border-radius:6px;background:transparent;color:inherit;padding:3px 7px;font:650 9px -apple-system,sans-serif;cursor:pointer}.conversation-host-receipt{align-self:center;display:flex;align-items:center;gap:7px;max-width:92%;border-radius:999px;background:rgba(50,76,103,.07);color:#5E7184;padding:6px 10px;font-size:9px}.conversation-host-receipt.uncertain{background:#FFF3D8;color:#825A12}.conversation-host-receipt.failed{background:#FDECEE;color:#8D2D39}.conversation-host-composer{flex:none;border-top:1px solid #CAD5E0;background:rgba(255,255,255,.92);padding:10px 13px 12px}.conversation-host-route{display:flex;align-items:center;gap:5px;margin-bottom:7px}.conversation-host-route[hidden]{display:none}.conversation-host-route-label{margin-right:3px;color:#687A8B;font-size:9px;font-weight:680}.conversation-host-route-btn{min-height:25px;border:1px solid #D1DAE4;border-radius:7px;background:#F6F8FA;color:#637689;padding:0 9px;font:650 9px -apple-system,sans-serif;cursor:pointer}.conversation-host-route-btn.active{border-color:#5E9AD7;background:#EAF4FF;color:#1D5F9D}.conversation-host-compose-row{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:end;gap:9px}.conversation-host-input{width:100%;min-height:68px;max-height:150px;resize:vertical;border:1px solid #BAC8D6;border-radius:11px;background:#fff;color:#1C2B39;padding:9px 10px;outline:none;font:11px/1.45 -apple-system,sans-serif}.conversation-host-input:focus{border-color:#397FC6;box-shadow:0 0 0 3px rgba(52,126,202,.14)}.conversation-host-send{min-width:78px;height:38px;border:1px solid #1762AB;border-radius:10px;background:linear-gradient(180deg,#3E8FE4,#2673C2);color:#fff;font:700 10px -apple-system,sans-serif;box-shadow:0 6px 16px rgba(37,111,187,.18);cursor:pointer}.conversation-host-send:hover,.conversation-host-send:focus-visible{background:#246DB7;outline:3px solid rgba(49,125,202,.17)}.conversation-host-status{min-height:15px;margin-top:6px;color:#627587;font-size:9px;line-height:1.4}.conversation-host-status.uncertain{color:#865B12}.conversation-host-status.failed{color:#922F3B}.conversation-host-loading{align-self:center;margin:auto;color:#607487;font-size:11px}.conversation-host-loading:before{content:'';display:inline-block;width:9px;height:9px;margin-right:8px;border:2px solid #B9D3EB;border-top-color:#2E7BC6;border-radius:50%;vertical-align:-2px;animation:workspace-spin .9s linear infinite}@media(max-width:780px){.conversation-host-head{padding:8px}.conversation-host-actions .conversation-host-action.optional{display:none}.conversation-host-transcript{padding:13px}.conversation-host-composer{padding:9px}.conversation-host-message{max-width:94%}}
.powerswarm-heading{align-items:center}.powerswarm-heading-title{display:flex;align-items:center;gap:9px}.powerswarm-heading .agents-freshness{margin-left:auto}.powerswarm-back{border:0;background:transparent;color:#0668C7;padding:3px 0;font:600 10px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.powerswarm-back:hover{text-decoration:underline}.powerswarm-back:focus-visible{outline:2px solid rgba(0,122,255,.35);outline-offset:2px;border-radius:3px}.powerswarm-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-bottom:9px}.powerswarm-summary .summary-tile{padding:6px 9px}.powerswarm-summary .summary-tile strong{font-size:17px}.powerswarm-layout{display:grid;grid-template-columns:minmax(0,1fr) 255px;gap:9px;align-items:start}.powerswarm-card{border:1px solid #CBCBCB;background:#fff;border-radius:9px;min-width:0;overflow:hidden}.powerswarm-card-head{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 10px;border-bottom:1px solid #E0E0E0;background:#F8F8F8}.powerswarm-card-title{font-size:12px;font-weight:650}.powerswarm-card-body{padding:10px}.powerswarm-checkpoint{display:flex;align-items:center;gap:7px;border:1px solid #D8DDE3;border-radius:7px;background:#F7F8FA;color:#59616B;padding:7px 9px;margin-bottom:8px;font-size:9px}.powerswarm-tree{display:grid;gap:6px}.powerswarm-edge{height:10px;margin:-6px 0 -6px 17px;border-left:1px solid #AFC3D9}.powerswarm-node{border:1px solid #D6D6D6;border-radius:8px;background:#FCFCFC;padding:8px 9px;min-width:0}.powerswarm-node.parent{background:#F7F7F8}.powerswarm-node.run{border-color:#AFC9E5;background:#F7FAFD}.powerswarm-node-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}.powerswarm-node-label{font-size:8px;color:#777;text-transform:uppercase;letter-spacing:.055em}.powerswarm-node-title{font-size:11px;font-weight:650;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-node-meta{font-size:8px;color:#777;margin-top:2px;line-height:1.35;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-objective{font-size:9px;color:#555;line-height:1.4;margin-top:7px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}.powerswarm-children{display:grid;gap:5px;margin-top:7px;padding-left:13px;border-left:1px solid #C9D6E3}.powerswarm-branch{border:1px solid #D9DFE6;background:#FAFBFC;border-radius:7px;padding:7px}.powerswarm-branch-head{display:flex;align-items:flex-start;justify-content:space-between;gap:7px}.powerswarm-worker{display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;border:1px solid #DEDEDE;border-radius:7px;background:#fff;color:#222;padding:7px 8px;text-align:left;cursor:pointer;font:inherit}.powerswarm-worker:hover,.powerswarm-worker:focus-visible{border-color:#007AFF;background:#F1F7FF;outline:none}.powerswarm-worker-main{min-width:0}.powerswarm-worker-name{display:block;font-size:10px;font-weight:630;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-worker-meta{display:block;font-size:8px;color:#777;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-arrow{font-size:17px;color:#8A8A8F;font-weight:300}.powerswarm-runs{display:grid}.powerswarm-run{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px;width:100%;border:0;border-top:1px solid #E8E8E8;background:transparent;color:#222;padding:8px 2px;text-align:left;cursor:pointer}.powerswarm-run:first-child{border-top:0}.powerswarm-run:hover,.powerswarm-run:focus-visible{background:#F4F8FC;outline:none}.powerswarm-run.selected{color:#005FB8}.powerswarm-run-title{font-size:9px;font-weight:620;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-run-meta{font-size:8px;color:#777;margin-top:2px;font-variant-numeric:tabular-nums}.powerswarm-latest{border:0;background:transparent;color:#0668C7;font-size:9px;font-weight:600;cursor:pointer}.powerswarm-latest:hover{text-decoration:underline}.powerswarm-worker-inspector{margin-top:9px}.powerswarm-worker-inspector[hidden]{display:none}.powerswarm-inspector-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;margin-bottom:8px}.powerswarm-inspector-stat{border:1px solid #DEDEDE;border-radius:7px;background:#FAFAFA;padding:7px;min-width:0}.powerswarm-inspector-stat span{display:block;font-size:7px;color:#777;text-transform:uppercase;letter-spacing:.055em}.powerswarm-inspector-stat strong{display:block;font-size:11px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.powerswarm-aim{font-size:9px;color:#555;line-height:1.4;margin-bottom:8px}.powerswarm-attempts{border:1px solid #DEDEDE;border-radius:7px;overflow:hidden}.powerswarm-attempt{display:grid;grid-template-columns:minmax(125px,1fr) 78px 95px 85px;gap:7px;align-items:center;padding:7px 8px;border-top:1px solid #E8E8E8;font-size:9px}.powerswarm-attempt:first-child{border-top:0}.powerswarm-attempt-title{font-weight:620}.powerswarm-attempt-meta{color:#777;font-size:8px;margin-top:1px}.powerswarm-empty{border:1px dashed #C8C8C8;border-radius:7px;background:#FAFAFA;color:#777;padding:16px;text-align:center;font-size:10px}.status-pill.running{background:#E8F6E4;color:#29731B}.status-pill.verified,.status-pill.review-ready,.status-pill.checkpoint{background:#E8F2FF;color:#075FAE}.status-pill.cancelled,.status-pill.invalid{background:#FDE7EA;color:#B42338}.status-pill.mixed{background:#F0ECF8;color:#604790}
@media(max-width:820px){.search-box{display:none}}
@media(max-width:780px){.seg-btn{padding-left:7px;padding-right:7px}.brain-list,.dispatch-layout,.guard-layout,.powerswarm-layout{grid-template-columns:1fr}.feature-summary,.guard-trends,.powerswarm-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.powerswarm-inspector-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.powerswarm-attempt{grid-template-columns:minmax(100px,1fr) 66px 76px 76px;gap:5px}}
.conversation-host-receipt button{border:1px solid currentColor;border-radius:999px;background:rgba(255,255,255,.55);color:inherit;padding:2px 7px;font:650 9px -apple-system,sans-serif;cursor:pointer}
.conversation-host.project-home .conversation-host-body{justify-content:center;overflow:auto;padding:24px 20px;background:linear-gradient(160deg,#F4F8FC,#EAF0F7)}.conversation-host.project-home .conversation-host-transcript{flex:0 0 auto;align-self:center;width:min(620px,100%);min-height:0;overflow:visible;padding:0;gap:7px}.conversation-host.project-home .conversation-host-empty{width:100%;margin:0;border-radius:16px 16px 0 0;border-bottom:0;padding:17px 18px 14px;box-shadow:0 14px 32px rgba(35,59,84,.09)}.conversation-host-empty-head{display:flex;align-items:center;gap:10px}.conversation-host-empty-head .conversation-host-empty-mark{width:34px;height:34px;border-radius:10px;font-size:10px}.conversation-host-empty-head h3{margin:0;font-size:17px}.conversation-host.project-home .conversation-host-empty p{margin-top:9px;font-size:12px;line-height:1.5}.conversation-host.project-home .conversation-host-proof{margin-top:11px}.conversation-host.project-home .conversation-host-proof span{font-size:10px;padding:5px 8px}.conversation-host.project-home .conversation-host-composer{align-self:center;width:min(620px,100%);border:1px solid #D4DEE8;border-top:1px solid #E5EBF1;border-radius:0 0 16px 16px;background:#fff;padding:11px 18px 14px;box-shadow:0 14px 32px rgba(35,59,84,.09)}.conversation-host-compose-row{gap:0;align-items:stretch;border:1px solid #AFC1D3;border-radius:12px;background:#fff;overflow:hidden;box-shadow:0 5px 16px rgba(36,70,103,.07)}.conversation-host-input{min-height:70px;border:0;border-radius:0;resize:vertical;padding:10px 11px;font-size:12px}.conversation-host-input:focus{border:0;box-shadow:inset 0 0 0 2px #397FC6}.conversation-host-send{height:auto;min-height:70px;min-width:92px;border:0;border-left:1px solid #1762AB;border-radius:0;background:linear-gradient(180deg,#3E8FE4,#2673C2);font-size:11px;box-shadow:none}.conversation-host-status{min-height:17px;margin-top:7px;font-size:10px}.workspace-privacy{font-size:9px;color:#888892}.workspace-thread-meta{font-size:9px;color:#92929A}.workspace-summary{font-size:9px}.workspace-companion{font-size:10px;min-height:18px}.workspace-conversation{grid-template-columns:8px minmax(0,1fr)}.conversation-host.project-home .conversation-host-receipt{align-self:flex-start;margin-top:9px;font-size:10px}@media(max-width:780px){.conversation-host.project-home .conversation-host-body{padding:14px 10px}.conversation-host.project-home .conversation-host-empty{padding:14px}.conversation-host.project-home .conversation-host-composer{padding:10px 14px 13px}}
.workspace-summary strong:before{content:'·';margin-right:6px;color:#686871}.conversation-host.project-home .conversation-host-route-label,.conversation-host.project-home .conversation-host-route-btn{font-size:10px}.conversation-host.project-home .conversation-host-route-btn{min-height:27px}
/* AI Brain product surface: direct actions, useful empty/error states, and an in-visual browser. */
#brain-tab .feature-scroll{background:linear-gradient(180deg,#f1f3f6 0,#e9edf2 100%)}
#brain-tab .feature-heading{margin-bottom:10px}
#brain-tab .brain-view-switch{border-color:#c4c9d0;background:#e4e8ed;padding:3px}
#brain-tab .brain-view-button{min-height:28px;padding:5px 12px;font-size:10px}
#brain-tab .brain-list{gap:10px}
#brain-tab .brain-card{border-color:#d8dde4;border-radius:12px;padding:12px;box-shadow:0 8px 24px rgba(28,44,64,.05);cursor:default}
#brain-tab .brain-card:hover{border-color:#aebdcc;box-shadow:0 10px 26px rgba(28,44,64,.08)}
#brain-tab .brain-card-top{align-items:center}
#brain-tab .brain-label{font-size:14px;letter-spacing:-.01em}
#brain-tab .brain-type,#brain-tab .brain-path,#brain-tab .brain-evidence,#brain-tab .brain-card-hint,#brain-tab .brain-card-error,#brain-tab .brain-family-copy,#brain-tab .brain-family-parent-copy span,#brain-tab .brain-child-copy strong,#brain-tab .brain-child-copy span,#brain-tab .brain-child-state,#brain-tab .brain-visual-title,#brain-tab .brain-visual-btn,#brain-tab .brain-graph-meta,#brain-tab .brain-visual-legend,#brain-tab .brain-visual-status,#brain-tab .brain-browser-copy,#brain-tab .brain-crumb,#brain-tab .brain-crumb-sep,#brain-tab .brain-browser-message,#brain-tab .brain-item-name,#brain-tab .brain-item-path,#brain-tab .brain-item-meta,#brain-tab .brain-page-copy,#brain-tab .brain-note-meta,#brain-tab .brain-note-boundary,#brain-tab .status-pill,#brain-tab .feature-btn,#brain-tab .privacy-strip,#brain-tab .summary-tile span,#brain-tab .summary-tile small{font-size:10px}
#brain-tab .brain-path{margin:9px 0 7px;padding:6px 7px;background:#f4f6f8;border:1px solid #e4e8ec}
#brain-tab .brain-card-hint{min-height:30px;color:#596674;line-height:1.45;margin-top:0}
#brain-tab .brain-card-error{margin-top:7px;border:1px solid #edb8be;border-radius:8px;background:#fff2f3;color:#922936;padding:7px 8px;line-height:1.4}
#brain-tab .brain-card-error[hidden]{display:none}
#brain-tab .brain-controls{margin-top:10px}
#brain-tab .brain-primary-action{min-height:32px;border-color:#0a6fd8;background:linear-gradient(180deg,#1684e9,#0868c5);color:#fff;border-radius:8px;padding:7px 14px;box-shadow:0 4px 12px rgba(10,111,216,.18)}
#brain-tab .brain-primary-action:hover{background:#0868c5}
#brain-tab .brain-card-more{margin-top:8px;border-top:1px solid #edf0f3;padding-top:7px}
#brain-tab .brain-card-more summary{width:max-content;color:#557086;font-size:10px;font-weight:650;cursor:pointer;list-style:none}
#brain-tab .brain-card-more summary::-webkit-details-marker{display:none}
#brain-tab .brain-card-more summary:after{content:'  +'}
#brain-tab .brain-card-more[open] summary:after{content:'  −'}
#brain-tab .brain-secondary-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:8px}
#brain-tab .brain-secondary-actions .brain-evidence{flex:1 1 100%;min-height:0;color:#697786}
#brain-tab .brain-inline-error{grid-column:1/-1;display:flex;align-items:center;justify-content:space-between;gap:12px;border:1px solid #efb7be;border-radius:10px;background:#fff3f4;color:#8f2633;padding:12px;font-size:11px;line-height:1.45}
#brain-tab .brain-family{border-color:#cbd8e5;background:linear-gradient(145deg,#fbfdff,#f3f7fb);padding:12px}
#brain-tab .brain-family-parent,#brain-tab .brain-child-card{min-height:52px;border-radius:10px}
#brain-tab .brain-child-provider{width:26px;height:26px;font-size:10px}
#brain-tab .brain-child-grid{gap:8px}
#brain-tab .brain-files-browser-host:empty{display:none}
#brain-tab .brain-browser{border-color:#b8c8d8;border-radius:12px;box-shadow:0 12px 34px rgba(14,34,55,.14)}
#brain-tab .brain-browser-head{padding:10px 11px;background:linear-gradient(180deg,#fbfdff,#f2f6fa)}
#brain-tab .brain-browser-title{font-size:14px}
#brain-tab .brain-browser-message{font-size:10px}
#brain-tab .brain-item{min-height:48px;padding:8px 5px}
#brain-tab .brain-note-body{font-size:11px;line-height:1.5}
#brain-tab .brain-visual{min-height:470px;border-radius:14px;background:radial-gradient(circle at 46% 42%,#214d7a 0,#102c49 36%,#071623 80%)}
#brain-tab .brain-graph{height:470px}
#brain-tab .brain-graph-label{font-size:12px}
#brain-tab .brain-visual-inspector[hidden],#brain-tab .brain-visual-error[hidden]{display:none}
#brain-tab .brain-visual-inspector{position:absolute;z-index:6;top:48px;right:11px;bottom:34px;width:min(430px,48%);display:flex;min-width:330px;filter:drop-shadow(0 18px 34px rgba(0,0,0,.28))}
#brain-tab .brain-visual-inspector .brain-browser{display:flex;flex:1;min-height:0;height:100%;margin:0;flex-direction:column;background:#fff}
#brain-tab .brain-visual-inspector .brain-directory,#brain-tab .brain-visual-inspector .brain-note{min-height:0;overflow:auto}
#brain-tab .brain-visual-inspector .brain-directory{flex:1}
#brain-tab .brain-visual-inspector .brain-note{flex:1}
#brain-tab .brain-visual-error{position:absolute;z-index:7;left:50%;top:58px;transform:translateX(-50%);display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 10px;width:min(520px,calc(100% - 30px));border:1px solid rgba(255,190,198,.72);border-radius:10px;background:rgba(75,20,31,.94);color:#fff;padding:10px 11px;box-shadow:0 14px 30px rgba(0,0,0,.25)}
#brain-tab .brain-visual-error strong{font-size:11px}.brain-visual-error span{grid-column:1;font-size:10px;line-height:1.4}.brain-visual-error button{grid-column:2;grid-row:1/3;align-self:center}
/* Brain Visual: a spatial knowledge map, not a diagnostic hub-and-spoke chart. */
#brain-tab .brain-visual{isolation:isolate;border-color:#1e3f5d;background:radial-gradient(circle at 50% 47%,rgba(35,101,151,.62) 0,rgba(11,43,70,.96) 28%,#061722 72%),linear-gradient(135deg,#0d2a40,#06131d);box-shadow:inset 0 1px rgba(255,255,255,.12),inset 0 -80px 120px rgba(0,0,0,.18),0 14px 34px rgba(15,42,65,.2)}
#brain-tab .brain-visual-toolbar{left:12px;right:12px;top:11px}#brain-tab .brain-visual-title{color:#f2f8fd;font-size:11px;font-weight:700;letter-spacing:-.01em;text-shadow:0 1px 4px rgba(0,0,0,.55)}
#brain-tab .brain-visual-btn{min-width:30px;min-height:30px;border-color:rgba(177,216,248,.3);border-radius:9px;background:rgba(8,28,43,.7);color:#e7f3fc;font-size:10px;backdrop-filter:blur(14px);box-shadow:inset 0 1px rgba(255,255,255,.08)}#brain-tab .brain-visual-btn:hover,#brain-tab .brain-visual-btn:focus-visible{border-color:#87c9f8;background:rgba(18,65,96,.9);box-shadow:0 0 0 3px rgba(91,183,246,.18)}
#brain-tab .brain-region{stroke:rgba(146,205,245,.16);stroke-width:1.2}.brain-region.claude{fill:rgba(173,98,65,.085)}.brain-region.codex{fill:rgba(44,132,198,.09)}
#brain-tab .brain-fold{fill:none;stroke-width:1.15;stroke-linecap:round;opacity:.3}.brain-fold.claude{stroke:#d38d68}.brain-fold.codex{stroke:#6eb5e7}.brain-bridge{fill:none;stroke:rgba(176,224,255,.3);stroke-width:2;stroke-linecap:round;stroke-dasharray:1 8}
#brain-tab .brain-orbit{fill:none;stroke:rgba(129,198,242,.2);stroke-width:1}.brain-orbit.inner{stroke-dasharray:5 8}.brain-orbit.outer{stroke-dasharray:2 11}.brain-center-glow{fill:rgba(63,159,222,.11);stroke:rgba(154,218,255,.19);stroke-width:1.5}
#brain-tab .brain-region-label{fill:#9fc9e5;font:650 10px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;letter-spacing:.02em}.brain-region-label.dormant{fill:#c3b083}
#brain-tab .brain-graph-edge{stroke-width:1.45;opacity:.55}.brain-graph-edge[data-spatial-group="codex"]{stroke:#65b5ed}.brain-graph-edge[data-spatial-group="claude"]{stroke:#d9916c}.brain-graph-edge[data-spatial-group="dormant"]{stroke:#bca56f;stroke-dasharray:4 6;opacity:.42}
#brain-tab .brain-graph-node rect{fill:rgba(12,35,53,.95);stroke:#72b5e2;stroke-width:1.35;filter:drop-shadow(0 8px 14px rgba(0,0,0,.34))}.brain-graph-node.claude rect{fill:rgba(66,38,28,.95);stroke:#dd9975}.brain-graph-node.parent rect{fill:rgba(17,72,109,.98);stroke:#a9dcff;stroke-width:2.15;filter:drop-shadow(0 0 18px rgba(91,188,249,.52))}.brain-graph-node.dormant rect,.brain-graph-node.blocked rect{fill:rgba(57,53,45,.95);stroke:#b3a078}
#brain-tab .brain-graph-node .brain-graph-label{fill:#f0f8fe;font-size:11px;font-weight:680}#brain-tab .brain-graph-node .brain-graph-meta{fill:#a8c4d8;font-size:10px}#brain-tab .brain-graph-node.claude .brain-graph-meta{fill:#e0b59f}#brain-tab .brain-graph-node.dormant .brain-graph-meta,#brain-tab .brain-graph-node.blocked .brain-graph-meta{fill:#ccbe98}
#brain-tab .brain-node-signal{fill:#67bdf4;stroke:#d4efff;stroke-width:1.15;filter:drop-shadow(0 0 5px rgba(96,194,255,.85));pointer-events:none}.brain-graph-node.claude .brain-node-signal{fill:#e3956d;stroke:#ffd5c0}.brain-graph-node.dormant .brain-node-signal,.brain-graph-node.blocked .brain-node-signal{fill:#aa9569;stroke:#e2d5b2}.brain-node-signal.parent{fill:#e2f6ff;stroke:#fff;filter:drop-shadow(0 0 8px rgba(163,224,255,.95))}
#brain-tab .brain-synapse{fill:#9fd9ff;opacity:.72;filter:drop-shadow(0 0 4px rgba(100,196,255,.8));pointer-events:none}.brain-synapse.claude{fill:#e8a47d}.brain-synapse.dormant{fill:#c2af7d;opacity:.52}
#brain-tab .brain-visual-legend,#brain-tab .brain-visual-status{bottom:10px;color:#a9c5d8;font-size:10px}#brain-tab .brain-visual-legend{left:12px}#brain-tab .brain-visual-status{right:12px}
#brain-tab .brain-directory.brain-directory-loading{display:block;padding:12px 14px}.brain-directory-loading-state{display:grid;gap:9px}.brain-directory-loading-copy{display:flex;align-items:center;gap:7px;color:#617182;font-size:10px;font-weight:650}.brain-directory-loading-copy:before{content:'';width:7px;height:7px;border:2px solid #a9cbe9;border-top-color:#2687dd;border-radius:50%;animation:brain-loading-spin .9s linear infinite}.brain-directory-loading-row{display:grid;grid-template-columns:26px minmax(0,1fr) 54px;align-items:center;gap:9px;min-height:44px;border-top:1px solid #edf0f3}.brain-directory-loading-row:first-of-type{border-top:0}.brain-directory-loading-icon{width:25px;height:25px;border-radius:7px;background:#e5edf4}.brain-directory-loading-lines{display:grid;gap:6px}.brain-directory-loading-lines:before,.brain-directory-loading-lines:after,.brain-directory-loading-meta{content:'';display:block;height:7px;border-radius:999px;background:linear-gradient(90deg,#e6ebf0,#f2f5f7,#e6ebf0)}.brain-directory-loading-lines:before{width:62%}.brain-directory-loading-lines:after{width:38%;height:6px}.brain-directory-loading-meta{width:48px;height:6px;justify-self:end}@keyframes brain-loading-spin{to{transform:rotate(360deg)}}
@media(prefers-contrast:more){#brain-tab .brain-region,#brain-tab .brain-orbit,#brain-tab .brain-fold{opacity:.68;stroke-width:1.7}#brain-tab .brain-graph-node rect{stroke-width:2}#brain-tab .brain-graph-edge{opacity:.8;stroke-width:2}}
#brain-tab .feature-heading{margin-bottom:8px}
#brain-tab .brain-context-bar{margin-bottom:9px;border:1px solid #d8e0e8;border-radius:12px;background:rgba(255,255,255,.92);box-shadow:0 3px 14px rgba(29,45,64,.04);overflow:hidden}
#brain-tab .brain-overview{display:flex;align-items:stretch;min-height:45px;padding:7px 10px}
#brain-tab .brain-overview-primary,#brain-tab .brain-overview-item,#brain-tab .brain-overview-scan{display:grid;grid-template-columns:auto 1fr;align-content:center;column-gap:5px;min-width:0;padding:0 11px;border-left:1px solid #e7ebef}
#brain-tab .brain-overview-primary{border-left:0;padding-left:0;min-width:78px}#brain-tab .brain-overview-primary strong{color:#0878e3;font-size:22px;line-height:1;font-weight:740;letter-spacing:-.03em}#brain-tab .brain-overview-primary span{align-self:center;color:#32485c;font-size:11px;font-weight:680}
#brain-tab .brain-overview-item{min-width:105px}#brain-tab .brain-overview-item strong{font-size:15px;line-height:1.1;color:#263746}#brain-tab .brain-overview-item span{align-self:center;color:#536577;font-size:10px;font-weight:620}#brain-tab .brain-overview-item small{grid-column:1/-1;margin-top:2px;color:#7a8792;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#brain-tab .brain-overview-scan{margin-left:auto;min-width:120px}#brain-tab .brain-overview-scan strong{font-size:13px;color:#34485a}#brain-tab .brain-overview-scan span{align-self:center;color:#647585;font-size:10px}#brain-tab .brain-overview-scan small{grid-column:1/-1;margin-top:2px;color:#7a8792;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#brain-tab .brain-privacy-line{display:flex;align-items:center;gap:6px;margin:0;border-top:1px solid #e8ecef;background:#f8fafb;color:#637382;padding:6px 10px;font-size:10px;line-height:1.3}#brain-tab .brain-privacy-line strong{color:#38566f}#brain-tab .brain-privacy-line>span:last-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#brain-tab .brain-files-view{display:grid;grid-template-columns:248px minmax(0,1fr);height:calc(100vh - 220px);min-height:410px;border:1px solid #cdd7e1;border-radius:13px;background:#fff;overflow:hidden;box-shadow:0 12px 30px rgba(29,45,64,.08)}
#brain-tab .brain-files-view[hidden]{display:none}
#brain-tab .brain-files-browser-host{grid-column:2;grid-row:1;position:relative;min-width:0;min-height:0;background:linear-gradient(180deg,#fff,#fbfcfd)}
#brain-tab .brain-files-welcome{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:30px;text-align:center;color:#687887}#brain-tab .brain-files-welcome[hidden]{display:none}#brain-tab .brain-files-welcome-mark{display:grid;place-items:center;width:58px;height:58px;border-radius:18px;background:linear-gradient(145deg,#78b8ff,#1769bd);box-shadow:0 12px 24px rgba(23,105,189,.24);color:#fff;font-size:17px;font-weight:760}#brain-tab .brain-files-welcome h2{margin-top:14px;color:#24384b;font-size:18px;letter-spacing:-.02em}#brain-tab .brain-files-welcome p{max-width:330px;margin-top:5px;font-size:11px;line-height:1.5}#brain-tab .brain-files-welcome>span{margin-top:11px;border-radius:999px;background:#eef5fb;color:#47657e;padding:5px 9px;font-size:10px}
#brain-tab .brain-list{grid-column:1;grid-row:1;display:block;min-width:0;min-height:0;overflow:auto;padding:9px;border-right:1px solid #dfe5eb;background:linear-gradient(180deg,#f7f9fb,#f1f4f7)}#brain-tab .brain-list[hidden]{display:none}
#brain-tab .brain-action-list{margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid #dfe5eb}#brain-tab .brain-action-list-title{margin:2px 5px 6px;color:#8a5a22;font-size:11px;font-weight:720;text-transform:uppercase;letter-spacing:.055em}
#brain-tab .brain-family{display:block;border:0;border-radius:0;background:transparent;padding:0;box-shadow:none}
#brain-tab .brain-family-head{align-items:center;margin:2px 3px 7px;padding:0 2px}#brain-tab .brain-family-title{color:#4d6174;font-size:11px;text-transform:uppercase;letter-spacing:.055em}#brain-tab .brain-family-copy{color:#7a8895;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}#brain-tab .brain-family-head>.status-pill{display:none}
#brain-tab .brain-family-parent{min-height:45px;border:1px solid #b9d4ee;border-radius:9px;background:#eaf4ff;padding:7px;margin-bottom:5px;box-shadow:none}#brain-tab .brain-family-parent:hover,#brain-tab .brain-family-parent:focus-visible{background:#e1f0ff;border-color:#75aee3}#brain-tab .brain-orbit-mark{width:28px;height:28px;border-radius:9px;box-shadow:0 4px 10px rgba(30,91,167,.2)}#brain-tab .brain-family-parent-copy strong{font-size:11px}#brain-tab .brain-family-parent-copy span{font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#brain-tab .brain-child-grid{display:block;margin:0}#brain-tab .brain-child-card{grid-template-columns:25px minmax(0,1fr);width:100%;min-height:42px;margin:2px 0;border:1px solid transparent;border-radius:8px;background:transparent;padding:6px}#brain-tab .brain-child-card:hover:not(:disabled),#brain-tab .brain-child-card:focus-visible{border-color:#c7d8e8;background:#fff}#brain-tab .brain-child-provider{width:25px;height:25px;border-radius:7px;font-size:10px}#brain-tab .brain-child-copy strong,#brain-tab .brain-child-copy span{font-size:10px}#brain-tab .brain-child-state{display:none}
#brain-tab .brain-card{margin-top:5px;border-color:#d8e0e7;border-radius:9px;padding:8px;box-shadow:none;background:rgba(255,255,255,.9)}#brain-tab .brain-card:hover{box-shadow:none}#brain-tab .brain-card-top{display:grid;grid-template-columns:minmax(0,1fr);gap:4px}#brain-tab .brain-card-top>.status-pill{justify-self:start}#brain-tab .brain-label{font-size:11px;white-space:normal;overflow:visible;text-overflow:clip}#brain-tab .brain-type{font-size:10px}#brain-tab .brain-path{margin:6px 0;padding:5px;font-size:10px}#brain-tab .brain-card-hint{min-height:0;font-size:10px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}#brain-tab .brain-controls{margin-top:7px}#brain-tab .brain-primary-action{width:100%;min-height:30px;padding:6px 9px}
#brain-tab .brain-browser{display:flex;height:100%;min-height:0;margin:0;border:0;border-radius:0;box-shadow:none;flex-direction:column}#brain-tab .brain-browser[hidden]{display:none}#brain-tab .brain-browser-head{padding:11px 12px;background:#f8fafc}#brain-tab .brain-browser-title{font-size:15px}#brain-tab .brain-browser-copy{font-size:10px}#brain-tab .brain-breadcrumbs{min-height:37px;padding:7px 12px;background:#fff}#brain-tab .brain-directory{min-height:0;flex:1;overflow:auto;padding:6px 12px 10px}#brain-tab .brain-item{grid-template-columns:28px minmax(0,1fr) auto;align-items:center;min-height:50px;padding:7px 5px}#brain-tab .brain-item-icon{position:relative;display:block;width:26px;height:26px;border-radius:7px;background:#e9f3fd}#brain-tab .brain-item-icon:before{content:'';position:absolute;left:5px;top:8px;width:16px;height:11px;border-radius:3px;background:#4a9ff0;box-shadow:inset 0 1px rgba(255,255,255,.25)}#brain-tab .brain-item-icon:after{content:'';position:absolute;left:6px;top:6px;width:8px;height:4px;border-radius:2px 2px 0 0;background:#73b9f7}#brain-tab .brain-item[data-kind="file"] .brain-item-icon{background:#f1f2f4}#brain-tab .brain-item[data-kind="file"] .brain-item-icon:before{left:7px;top:5px;width:12px;height:16px;border-radius:2px;background:#8e9aa6;box-shadow:inset 0 0 0 2px #fff}#brain-tab .brain-item[data-kind="file"] .brain-item-icon:after{left:10px;top:9px;width:6px;height:1px;border-radius:0;background:#fff;box-shadow:0 3px #fff,0 6px #fff}#brain-tab .brain-item-name{font-size:11px}#brain-tab .brain-item-path,#brain-tab .brain-item-meta{font-size:10px}#brain-tab .brain-note{min-height:0;flex:1;overflow:auto}#brain-tab .brain-pager{min-height:42px}
#brain-tab.visual-mode .brain-context-bar{margin-bottom:7px}#brain-tab.visual-mode .brain-overview{min-height:39px;padding-top:5px;padding-bottom:5px}#brain-tab.visual-mode .brain-privacy-line{display:none}#brain-tab.visual-mode .brain-visual,#brain-tab.visual-mode .brain-graph{height:calc(100vh - 190px);min-height:420px}
@media(max-width:820px){#brain-tab .brain-visual-inspector{left:10px;right:10px;width:auto;min-width:0}#brain-tab .brain-files-view{grid-template-columns:205px minmax(0,1fr)}#brain-tab .brain-overview-scan{display:none}#brain-tab .brain-overview-item{min-width:90px;padding-left:8px;padding-right:8px}}
@media(prefers-reduced-motion:reduce){.brain-graph-node,.brain-graph-edge,.workspace-chevron{transition:none!important}.brain-visual{scroll-behavior:auto}.brain-directory-loading-copy:before{animation:none}}
</style>
</head>
<body>
<div class="workspace-shell" id="workspace-shell">
<aside class="workspace-rail" id="workspace-rail" aria-label="Projects and conversations">
    <header class="workspace-rail-header">
        <div class="workspace-mark" aria-hidden="true">KE</div>
        <div class="workspace-brand"><strong>Workspace</strong><span>Projects & exact conversations</span></div>
        <button type="button" class="workspace-icon-btn workspace-collapse" id="workspace-collapse" aria-label="Collapse project rail" title="Collapse project rail">‹</button>
    </header>
    <div class="workspace-rail-body">
        <div class="workspace-search-wrap">
            <input class="workspace-search" id="workspace-search" type="search" autocomplete="off" spellcheck="false" placeholder="Search projects and tasks" aria-label="Search projects and conversations">
            <button type="button" class="workspace-refresh" id="workspace-refresh" aria-label="Refresh projects" title="Refresh projects">↻</button>
        </div>
        <div class="workspace-tools" aria-label="Provider filters">
            <button type="button" class="workspace-provider active" id="workspace-filter-codex" data-provider="codex">Codex</button>
            <button type="button" class="workspace-provider active" id="workspace-filter-claude" data-provider="claude">Claude</button>
            <button type="button" class="workspace-manage" id="workspace-manage" aria-label="Choose visible projects" title="Choose visible projects">＋</button>
        </div>
        <div class="workspace-host-switch" role="group" aria-label="Conversation host">
            <button type="button" class="workspace-host-mode active" id="workspace-host-native" data-host-mode="native" aria-pressed="true">Native apps</button>
            <button type="button" class="workspace-host-mode" id="workspace-host-activity" data-host-mode="activity" aria-pressed="false">Activity Monitor</button>
        </div>
        <div class="workspace-summary" id="workspace-summary"><span>Loading local metadata…</span></div>
        <div class="workspace-tree" id="workspace-tree" role="tree" tabindex="0" aria-label="Visible projects and conversations"><div class="workspace-tree-message">Loading project metadata…</div></div>
    </div>
    <footer class="workspace-rail-footer">
        <div class="workspace-companions"><span class="workspace-companion" id="workspace-codex-companion">Codex</span><span class="workspace-companion" id="workspace-claude-companion">Claude Code</span></div>
    </footer>
</aside>
<div class="workspace-resizer" id="workspace-resizer" role="separator" aria-orientation="vertical" aria-label="Resize project rail"></div>
<section class="monitor-surface" aria-label="Activity Monitor">
<section class="conversation-host" id="conversation-host" hidden role="dialog" aria-modal="true" aria-labelledby="conversation-host-title" aria-describedby="conversation-host-subtitle">
    <header class="conversation-host-head">
        <button type="button" class="conversation-host-back" id="conversation-host-close" aria-label="Close in-app conversation">‹</button>
        <div class="conversation-host-identity">
            <div class="conversation-host-glyph" id="conversation-host-glyph" aria-hidden="true">CX</div>
            <div class="conversation-host-titles">
                <h2 id="conversation-host-title">Project Conductor</h2>
                <p id="conversation-host-subtitle">Activity Monitor host · exact local destination</p>
            </div>
        </div>
        <div class="conversation-host-actions">
            <button type="button" class="conversation-host-action optional" id="conversation-host-native-open" hidden>Open in native app</button>
            <button type="button" class="conversation-host-action" id="conversation-host-refresh" aria-label="Refresh this conversation">Refresh</button>
            <button type="button" class="conversation-host-action primary" id="conversation-host-destination" hidden>Open exact task</button>
        </div>
    </header>
    <div class="conversation-host-body">
        <div class="conversation-host-transcript" id="conversation-host-transcript" role="log" aria-live="polite" aria-relevant="additions text" aria-label="Conversation messages"></div>
        <div class="conversation-host-composer">
            <div class="conversation-host-route" id="conversation-host-route" role="group" aria-label="Project routing">
                <span class="conversation-host-route-label">Route with</span>
                <button type="button" class="conversation-host-route-btn active" data-route-kind="conductor" aria-pressed="true">Conductor</button>
                <button type="button" class="conversation-host-route-btn" data-route-kind="powerswarm" aria-pressed="false">PowerSwarm</button>
            </div>
            <div class="conversation-host-compose-row">
                <textarea class="conversation-host-input" id="conversation-host-input" maxlength="200000" placeholder="Tell this project what you need. Send rapid follow-ups whenever they occur." aria-label="Message the selected project or conversation"></textarea>
                <button type="button" class="conversation-host-send" id="conversation-host-send">Send</button>
            </div>
            <div class="conversation-host-status" id="conversation-host-status" role="status" aria-live="polite">Nothing sends until you press Send.</div>
        </div>
    </div>
</section>
<div class="toolbar">
    <div class="segmented-control">
        <button class="seg-btn active" data-tab="cpu">CPU</button>
        <button class="seg-btn" data-tab="memory">Memory</button>
        <button class="seg-btn" data-tab="energy">Energy</button>
        <button class="seg-btn" data-tab="disk">Disk</button>
        <button class="seg-btn" data-tab="network">Network</button>
        <button class="seg-btn" data-tab="agents">Agents</button>
        <button class="seg-btn" data-tab="brain">AI Brain</button>
        <button class="seg-btn" data-tab="dispatch">Dispatch</button>
        <button class="seg-btn" data-tab="guard">KE Guard</button>
    </div>
    <div class="search-box"><input type="text" id="search" placeholder="Search"></div>
</div>
<div class="main">

<div id="cpu-tab" class="tab-content active">
    <div class="table-container">
        <table id="cpu-table"><thead><tr>
            <th data-key="name" style="min-width:180px">Process Name</th>
            <th data-key="cpu_percent" class="num sort-desc" style="width:70px">% CPU</th>
            <th data-key="threads" class="num" style="width:60px">Threads</th>
            <th data-key="pid" class="num" style="width:60px">PID</th>
            <th data-key="username" style="width:80px">User</th>
            <th style="width:60px"></th>
        </tr></thead><tbody id="cpu-tbody"></tbody></table>
    </div>
    <div class="bottom-panel has-graph">
        <div class="graph-area">
            <div class="graph-section">
                <div class="graph-title">CPU Usage</div>
                <div class="graph-canvas cpu-graph" id="cpu-bar-chart" style="display:flex;align-items:flex-end;gap:0;overflow:hidden"></div>
            </div>
            <div class="graph-section" style="max-width:240px">
                <div class="graph-title">CPU Load</div>
                <div id="cpu-cores-bars" style="flex:1;overflow-y:auto;font-size:10px"></div>
            </div>
        </div>
        <div class="info-row" id="cpu-info-row">
            <div class="info-item"><span class="dot dot-system"></span><span class="info-label">System:</span><span class="info-value" id="cpu-system">0%</span></div>
            <div class="info-item"><span class="dot dot-user"></span><span class="info-label">User:</span><span class="info-value" id="cpu-user">0%</span></div>
            <div class="info-item"><span class="info-label">Idle:</span><span class="info-value" id="cpu-idle">0%</span></div>
            <div class="info-item"><span class="info-label">Load Avg:</span><span class="info-value" id="cpu-load">0 0 0</span></div>
        </div>
    </div>
</div>

<div id="memory-tab" class="tab-content">
    <div class="table-container">
        <table id="mem-table"><thead><tr>
            <th data-key="name" style="min-width:180px">Process Name</th>
            <th data-key="memory_mb" class="num sort-desc" style="width:90px">Memory</th>
            <th data-key="memory_percent" class="num" style="width:70px">% Mem</th>
            <th data-key="threads" class="num" style="width:60px">Threads</th>
            <th data-key="pid" class="num" style="width:60px">PID</th>
            <th data-key="username" style="width:80px">User</th>
            <th style="width:60px"></th>
        </tr></thead><tbody id="mem-tbody"></tbody></table>
    </div>
    <div class="bottom-panel has-graph memory-bottom-panel">
        <div class="graph-area">
            <div class="graph-section memory-pressure-summary">
                <div class="graph-title">Memory Pressure</div>
                <div class="memory-gauge-container"><canvas id="pressure-canvas" width="140" height="100"></canvas></div>
            </div>
            <div class="graph-section memory-detail-section">
                <div class="graph-title">Memory</div>
                <div class="mem-info-grid" id="mem-details">
                    <span class="label">Physical Memory:</span><span class="val" id="mem-physical">--</span>
                    <span class="label">Memory Used:</span><span class="val" id="mem-used">--</span>
                    <span class="label">Cached Files:</span><span class="val" id="mem-cached">--</span>
                    <span class="label">Swap Used:</span><span class="val" id="mem-swap">--</span>
                    <span class="label">App Memory:</span><span class="val" id="mem-app">--</span>
                    <span class="label">Wired Memory:</span><span class="val" id="mem-wired">--</span>
                </div>
            </div>
            <section class="graph-section memory-diagnostics-section" aria-labelledby="memory-diagnostics-title">
                <div class="memory-diagnostics-head">
                    <div class="graph-title" id="memory-diagnostics-title">Memory Diagnostics</div>
                    <div class="memory-diagnostic-actions">
                        <button type="button" class="memory-diagnostic-btn" id="memory-diagnostics-copy" disabled>Copy Report</button>
                        <button type="button" class="memory-diagnostic-btn primary" id="memory-diagnostics-run" aria-describedby="memory-diagnostics-boundary">Run Diagnostics</button>
                    </div>
                </div>
                <div class="memory-diagnostic-status" id="memory-diagnostics-status" role="status" aria-live="polite">Ready · local read-only check</div>
                <div class="memory-diagnostic-progress" id="memory-diagnostics-progress" hidden>
                    <progress id="memory-diagnostics-progress-bar" value="0" max="12" aria-label="Memory diagnostic sampling progress"></progress>
                    <span id="memory-diagnostics-progress-copy">0 of 12 seconds</span>
                </div>
                <div class="memory-diagnostic-result" id="memory-diagnostics-result">
                    <div class="memory-diagnostic-summary">
                        <span class="memory-diagnostic-verdict">Ready</span>
                        <span class="memory-diagnostic-summary-copy" id="memory-diagnostics-boundary">Samples pressure, paging, compression, process growth, and swap storage. No automatic actions.</span>
                    </div>
                    <div class="memory-diagnostic-findings" id="memory-diagnostics-findings">
                        <div class="memory-diagnostic-empty">Run a bounded 12-second sample when you want a current verdict.</div>
                    </div>
                </div>
                <div class="memory-diagnostic-error" id="memory-diagnostics-error" role="alert" hidden>
                    <span class="memory-diagnostic-error-mark" aria-hidden="true">!</span>
                    <span class="memory-diagnostic-error-copy" id="memory-diagnostics-error-copy"></span>
                    <button type="button" class="memory-diagnostic-btn" id="memory-diagnostics-retry">Retry</button>
                </div>
            </section>
        </div>
        <div class="info-row">
            <div class="info-item"><span class="dot dot-green"></span><span class="info-label">Pressure:</span><span class="info-value" id="mem-pressure-text">Normal</span></div>
        </div>
    </div>
</div>

<div id="energy-tab" class="tab-content">
    <div class="table-container">
        <table id="energy-table"><thead><tr>
            <th data-key="name" style="min-width:180px">Process Name</th>
            <th data-key="energy_impact" class="num sort-desc" style="width:100px">Energy Impact</th>
            <th data-key="avg_energy_impact" class="num" style="width:110px">Avg Energy Impact</th>
            <th data-key="app_nap" style="width:70px">App Nap</th>
            <th data-key="preventing_sleep" style="width:100px">Preventing Sleep</th>
            <th data-key="pid" class="num" style="width:60px">PID</th>
        </tr></thead><tbody id="energy-tbody"><tr class="energy-state-row loading"><td colspan="6"><span class="energy-state-dot"></span>Loading current energy activity…</td></tr></tbody></table>
    </div>
    <div class="bottom-panel has-graph">
        <div class="graph-area">
            <div class="graph-section">
                <div class="graph-title">Energy Impact</div>
                <div class="graph-canvas" id="energy-bar-chart" style="background:#1a1a2e;display:flex;align-items:flex-end;gap:0;overflow:hidden"></div>
            </div>
        </div>
        <div class="info-row">
            <div class="info-item"><span class="info-label">Power Source:</span><span class="info-value" id="energy-source">--</span></div>
            <div class="info-item"><span class="info-label">Battery:</span><span class="info-value" id="energy-battery">--</span></div>
            <div class="info-item"><span class="info-label">Total Energy Impact:</span><span class="info-value" id="energy-total">--</span></div>
        </div>
    </div>
</div>

<div id="disk-tab" class="tab-content">
    <div class="table-container">
        <table id="disk-table"><thead><tr>
            <th data-key="name" style="min-width:180px">Process Name</th>
            <th data-key="read_bytes" class="num sort-desc" style="width:100px">Bytes Read</th>
            <th data-key="write_bytes" class="num" style="width:100px">Bytes Written</th>
            <th data-key="read_count" class="num" style="width:80px">Reads In</th>
            <th data-key="write_count" class="num" style="width:80px">Writes Out</th>
            <th data-key="pid" class="num" style="width:60px">PID</th>
        </tr></thead><tbody id="disk-tbody"></tbody></table>
    </div>
    <div class="bottom-panel no-graph">
        <div class="disk-overview">
            <section class="disk-storage-card" aria-labelledby="disk-storage-title">
                <div>
                    <div class="disk-overview-kicker" id="disk-storage-title">Mac storage</div>
                    <div class="disk-capacity-line"><strong><span id="disk-used-label">0</span> GB</strong><span>used of <span id="disk-total-label">0</span> GB</span></div>
                    <div class="disk-capacity-free"><span id="disk-free-label">0</span> GB available</div>
                </div>
                <button type="button" class="disk-cleanup-trigger" id="disk-cleanup-open" aria-label="Open Cleanup Assistant to review cleanup candidates" aria-haspopup="dialog" aria-controls="disk-cleanup-sheet">
                    <span class="disk-cleanup-trigger-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="5.5"></circle><path d="m15 15 4 4"></path><path d="M8 10.5h5M10.5 8v5"></path></svg></span>
                    <span class="disk-cleanup-trigger-copy"><strong>Review cleanup</strong><small>Large files, caches, logs, and installers</small></span>
                    <span class="disk-cleanup-trigger-arrow" aria-hidden="true">›</span>
                </button>
                <div class="disk-capacity-track" id="disk-usage-meter" role="progressbar" aria-label="Disk space used" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div class="usage-bar-fill" id="disk-usage-fill" style="width:0%"></div></div>
            </section>
            <section class="disk-io-card" aria-labelledby="disk-io-title">
                <div class="disk-io-head"><div><div class="disk-overview-kicker">Live activity</div><h2 id="disk-io-title">Disk I/O</h2></div><span>Current session</span></div>
                <div class="disk-io-grid">
                    <div class="disk-io-metric"><span>Read</span><strong id="dio-read">--</strong></div>
                    <div class="disk-io-metric"><span>Written</span><strong id="dio-write">--</strong></div>
                    <div class="disk-io-metric"><span>Read rate</span><strong id="dio-rrate">--</strong></div>
                    <div class="disk-io-metric"><span>Write rate</span><strong id="dio-wrate">--</strong></div>
                </div>
            </section>
        </div>
    </div>
    <section class="disk-cleanup-sheet" id="disk-cleanup-sheet" hidden role="dialog" aria-modal="true" aria-labelledby="disk-cleanup-title" aria-describedby="disk-cleanup-boundary" tabindex="-1">
        <header class="disk-cleanup-head">
            <span class="disk-cleanup-head-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="5.5"></circle><path d="m15 15 4 4"></path><path d="M8 10.5h5M10.5 8v5"></path></svg></span>
            <div class="disk-cleanup-title">
                <div class="disk-cleanup-kicker">Cleanup Assistant</div>
                <h1 id="disk-cleanup-title">Review cleanup candidates</h1>
                <p>Scan for large files, caches, logs, installers, and other items. Nothing is deleted automatically.</p>
            </div>
            <button type="button" class="disk-cleanup-close" id="disk-cleanup-close" aria-label="Close Cleanup Assistant">×</button>
        </header>
        <div class="disk-cleanup-summary" aria-label="Cleanup review summary">
            <div class="disk-cleanup-metric"><span>Potential space</span><strong id="disk-cleanup-potential">—</strong><small>deduplicated logical size</small></div>
            <div class="disk-cleanup-metric"><span>Free now</span><strong id="disk-cleanup-free">—</strong><small id="disk-cleanup-free-detail">measured when scanned</small></div>
            <div class="disk-cleanup-metric"><span>Review items</span><strong id="disk-cleanup-count">—</strong><small>ranked · metadata only</small></div>
        </div>
        <div class="disk-cleanup-boundary" id="disk-cleanup-boundary"><span class="disk-cleanup-boundary-mark" aria-hidden="true">◇</span><span><strong>Nothing is deleted here.</strong> Activity Monitor identifies and revalidates candidates; Finder handles your final Trash decision. Documents, Desktop, source repositories, Brains, credentials, mail, browser profiles, and agent state stay protected.</span></div>
        <div class="disk-cleanup-controls">
            <button type="button" class="disk-cleanup-btn primary" id="disk-cleanup-scan">Scan for space</button>
            <button type="button" class="disk-cleanup-btn" id="disk-cleanup-cancel" hidden>Cancel</button>
            <div class="disk-cleanup-status" id="disk-cleanup-status" role="status" aria-live="polite">Ready · scanning starts only when you ask</div>
        </div>
        <div class="disk-cleanup-progress" id="disk-cleanup-progress" hidden aria-hidden="true"><span></span></div>
        <div class="disk-cleanup-workbench">
            <aside class="disk-cleanup-categories" aria-labelledby="disk-cleanup-categories-title">
                <div class="disk-cleanup-section-head"><h2 id="disk-cleanup-categories-title">Categories</h2><span id="disk-cleanup-category-total">0 found</span></div>
                <div class="disk-cleanup-category-list" id="disk-cleanup-category-list"><div class="disk-cleanup-empty">Run a scan to map reclaimable space.</div></div>
            </aside>
            <section class="disk-cleanup-results" aria-labelledby="disk-cleanup-results-title">
                <div class="disk-cleanup-section-head">
                    <h2 id="disk-cleanup-results-title">Ranked review</h2>
                    <div class="disk-cleanup-result-tools" role="group" aria-label="Candidate filters">
                        <button type="button" class="disk-cleanup-filter active" data-disk-cleanup-filter="all">All</button>
                        <button type="button" class="disk-cleanup-filter" data-disk-cleanup-filter="quick">Quick wins</button>
                        <button type="button" class="disk-cleanup-filter" data-disk-cleanup-filter="review">Review</button>
                    </div>
                </div>
                <div class="disk-cleanup-candidate-list" id="disk-cleanup-candidate-list"><div class="disk-cleanup-empty">No scan yet. Nothing runs in the background.</div></div>
                <div class="disk-cleanup-select-tools">
                    <span id="disk-cleanup-selection">0 of 12 selected</span>
                    <button type="button" id="disk-cleanup-select-top" disabled>Select top quick wins</button>
                    <button type="button" id="disk-cleanup-clear" disabled>Clear</button>
                </div>
            </section>
        </div>
        <footer class="disk-cleanup-foot">
            <div class="disk-cleanup-foot-note"><strong>Review workflow:</strong> reveal exact matches, move what you choose to Trash in Finder, then rescan. Trash must be emptied separately before macOS reclaims space.</div>
            <button type="button" class="disk-cleanup-btn" data-disk-cleanup-destination="storage-settings">Storage Settings</button>
            <button type="button" class="disk-cleanup-btn" data-disk-cleanup-destination="downloads">Downloads</button>
            <button type="button" class="disk-cleanup-btn" data-disk-cleanup-destination="trash">Open Trash</button>
            <button type="button" class="disk-cleanup-btn primary" id="disk-cleanup-reveal" disabled>Reveal selected</button>
        </footer>
    </section>
</div>

<div id="network-tab" class="tab-content" aria-describedby="network-scope">
    <p class="sr-only" id="network-scope">Live observation of devices visible on directly connected network segments. Silent, sleeping, isolated, or firewalled devices may remain undiscoverable.</p>
    <div class="network-scroll">
        <section class="network-hero" aria-labelledby="network-title">
            <div>
                <div class="network-kicker">Network workspace</div>
                <h1 id="network-title">See what is connected. Fix what is not.</h1>
                <p class="network-hero-copy">Inventory stays on this Mac; discovery probes stay on eligible directly connected segments. Inspect Wi-Fi health and open trusted KE Link workflows. Discovery runs only while this tab is open; KE Link stays off until you enable it.</p>
                <div class="network-live-line"><span class="network-pulse paused" id="network-live-pulse"></span><span id="network-live-copy">Discovery starts when this tab opens</span></div>
            </div>
            <div class="network-hero-actions">
                <button class="network-hero-btn primary" id="internet-optimizer-btn" type="button">Speed Up My Internet</button>
                <button class="network-hero-btn" id="network-scan-btn" type="button">Scan devices</button>
                <button class="network-hero-btn" id="network-link-toggle" type="button">Enable KE Link</button>
            </div>
        </section>
        <div class="network-boundary"><span class="network-boundary-icon" aria-hidden="true">◉</span><div class="network-boundary-copy"><span class="network-boundary-title"><strong>Observable, not omniscient.</strong><button class="network-info-trigger" type="button" data-network-info="visibility" aria-label="Explain Network visibility" aria-expanded="false" aria-controls="network-info-panel">i</button></span> <span id="network-boundary-copy">Direct evidence only. Sleeping, isolated, or firewalled devices may not appear.</span></div></div>
        <div class="network-error" id="network-error" role="status" aria-live="polite" tabindex="-1" hidden><span class="network-error-copy" id="network-error-copy"></span><button class="network-error-action" id="network-recovery-btn" type="button" hidden>Fix connection</button></div>
        <section class="network-stats" aria-label="Network discovery summary">
            <div class="network-stat"><div class="network-stat-label"><span>Observed</span><button class="network-info-trigger" type="button" data-network-info="observed" aria-label="Explain Observed devices" aria-expanded="false" aria-controls="network-info-panel">i</button></div><strong id="network-count-observed">0</strong><small>deduplicated devices</small></div>
            <div class="network-stat"><div class="network-stat-label"><span>Online now</span><button class="network-info-trigger" type="button" data-network-info="online" aria-label="Explain Online now" aria-expanded="false" aria-controls="network-info-panel">i</button></div><strong id="network-count-online">0</strong><small>direct evidence</small></div>
            <div class="network-stat"><div class="network-stat-label"><span>Recently seen</span><button class="network-info-trigger" type="button" data-network-info="recent" aria-label="Explain Recently seen" aria-expanded="false" aria-controls="network-info-panel">i</button></div><strong id="network-count-recent">0</strong><small>neighbor memory</small></div>
            <div class="network-stat"><div class="network-stat-label"><span>Trusted</span><button class="network-info-trigger" type="button" data-network-info="trusted" aria-label="Explain Trusted peers" aria-expanded="false" aria-controls="network-info-panel">i</button></div><strong id="network-count-paired">0</strong><small>persistent KE Link peers</small></div>
            <div class="network-stat"><div class="network-stat-label"><span>Coverage</span><button class="network-info-trigger" type="button" data-network-info="coverage" aria-label="Explain Coverage" aria-expanded="false" aria-controls="network-info-panel">i</button></div><strong id="network-coverage-value">—</strong><small id="network-coverage-meta">waiting for interfaces</small></div>
        </section>
        <section class="network-info-panel" id="network-info-panel" role="region" aria-live="polite" aria-labelledby="network-info-title" hidden>
            <span class="network-info-mark" aria-hidden="true">i</span>
            <div class="network-info-copy"><strong id="network-info-title">Network help</strong><p id="network-info-body"></p></div>
            <button class="network-info-close" id="network-info-close" type="button" aria-label="Close Network explanation">Close</button>
        </section>
        <div class="network-layout">
            <section class="network-card" aria-labelledby="network-device-title">
                <div class="network-card-head">
                    <div><div class="network-card-title" id="network-device-title">Devices</div><div class="network-card-copy" id="network-scan-status">Waiting for the first observation</div></div>
                    <div class="network-filters" aria-label="Filter devices">
                        <button class="network-filter active" type="button" data-network-filter="all">All</button>
                        <button class="network-filter" type="button" data-network-filter="online">Online</button>
                        <button class="network-filter" type="button" data-network-filter="paired">Paired</button>
                    </div>
                </div>
                <div class="network-device-list" id="network-device-list" aria-live="polite"><div class="network-empty">Open the Network tab to begin live local discovery.</div></div>
            </section>
            <aside class="network-card network-detail" id="network-detail-card" tabindex="-1" aria-labelledby="network-detail-title">
                <div class="network-card-head"><div><div class="network-card-title" id="network-detail-title">Device details</div><div class="network-card-copy">Actions are limited to what this device advertises</div></div></div>
                <div class="network-detail-empty" id="network-detail-empty"><strong>Select a device</strong>Inspect its evidence, advertised services, and available local actions.</div>
                <div class="network-detail-content" id="network-detail-content" hidden>
                    <div class="network-detail-top"><div><div class="network-detail-name" id="network-detail-name">—</div><div class="network-detail-sub" id="network-detail-address">—</div></div><div class="network-detail-badges"><span class="status-pill" id="network-detail-state">unknown</span><span class="status-pill trusted" id="network-detail-trust" hidden>trusted</span><span class="status-pill ready" id="network-detail-ready" hidden>ready</span></div></div>
                    <div class="network-detail-grid">
                        <div class="network-detail-metric"><span>Kind</span><strong id="network-detail-kind">—</strong></div>
                        <div class="network-detail-metric"><span>Latency</span><strong id="network-detail-latency">—</strong></div>
                        <div class="network-detail-metric"><span>Interface</span><strong id="network-detail-interface">—</strong></div>
                        <div class="network-detail-metric"><span>Last seen</span><strong id="network-detail-age">—</strong></div>
                    </div>
                    <div class="network-section-label">Evidence</div><div class="network-chip-row" id="network-detail-sources"></div>
                    <div class="network-section-label">Safe actions</div><div class="network-actions" id="network-detail-actions"></div>
                    <div class="network-section-label">Advertised services</div><div class="network-services" id="network-detail-services"></div>
                    <div id="network-pair-panel" hidden><div class="network-section-label">Pair this KE Link peer</div><div class="network-pair-requirement" id="network-pair-requirement">Enable KE Link explicitly before pairing. Pair never enables the listener.</div><div class="network-pair-row"><input id="network-pair-input" type="text" maxlength="40" autocomplete="off" spellcheck="false" aria-label="Pairing code" placeholder="XXXX-XXXX-…"><button class="network-action" id="network-pair-btn" type="button">Pair</button></div></div>
                    <div id="network-message-panel" hidden><div class="network-section-label">Encrypted plain-text channel · fresh authenticated session required</div><div class="network-messages" id="network-message-list"></div><div class="network-compose"><textarea id="network-message-input" maxlength="4096" aria-label="Message" placeholder="Message this ready KE Monitor…"></textarea><button class="network-action" id="network-message-btn" type="button">Send</button></div></div>
                    <div class="network-action-feedback" id="network-action-feedback" role="status"></div>
                </div>
            </aside>
        </div>
        <section class="network-card internet-optimizer" id="internet-optimizer" tabindex="-1" aria-labelledby="internet-optimizer-title" hidden>
            <div class="internet-optimizer-head">
                <div class="internet-optimizer-brand">
                    <div class="internet-optimizer-mark" aria-hidden="true">↯</div>
                    <div>
                        <div class="internet-optimizer-title-row"><div class="internet-optimizer-title" id="internet-optimizer-title">Internet Optimizer</div><button class="network-info-trigger" type="button" data-network-info="optimizer" aria-label="Explain Internet Optimizer" aria-expanded="false" aria-controls="network-info-panel">i</button></div>
                        <div class="internet-optimizer-subtitle">Measures Wi-Fi signal, noise, channel pressure, security, and link rate before recommending a change.</div>
                    </div>
                </div>
                <div><span class="internet-optimizer-state" id="internet-optimizer-state">Ready</span><button class="internet-optimizer-close" id="internet-optimizer-close" type="button" aria-label="Close Internet Optimizer">Close</button></div>
            </div>
            <div class="internet-optimizer-body">
                <div class="internet-optimizer-loading" id="internet-optimizer-loading">Reading this Mac's active Wi-Fi path and nearby channel pressure…</div>
                <div class="internet-optimizer-results" id="internet-optimizer-results" hidden>
                    <div class="internet-optimizer-summary" aria-label="Measured Wi-Fi quality">
                        <div class="internet-optimizer-metric"><span>Radio health</span><strong id="internet-health">—</strong></div>
                        <div class="internet-optimizer-metric"><span>Signal</span><strong id="internet-signal">—</strong></div>
                        <div class="internet-optimizer-metric"><span>Noise / SNR</span><strong id="internet-noise">—</strong></div>
                        <div class="internet-optimizer-metric"><span>Channel</span><strong id="internet-channel">—</strong></div>
                        <div class="internet-optimizer-metric"><span>Link rate</span><strong id="internet-link-rate">—</strong></div>
                    </div>
                    <div class="internet-optimizer-grid">
                        <section class="internet-optimizer-pane" aria-labelledby="internet-channel-title">
                            <div class="internet-optimizer-pane-title"><span id="internet-channel-title">Channel pressure</span><span id="internet-nearby-count">—</span></div>
                            <div class="internet-channel-list" id="internet-channel-list"></div>
                            <div class="internet-optimizer-recommendation" id="internet-channel-recommendation"></div>
                        </section>
                        <section class="internet-optimizer-pane" aria-labelledby="internet-findings-title">
                            <div class="internet-optimizer-pane-title"><span id="internet-findings-title">Highest-impact next steps</span><span id="internet-confidence">—</span></div>
                            <div class="internet-finding-list" id="internet-finding-list"></div>
                        </section>
                    </div>
                    <div class="internet-quality-result" id="internet-quality-result" aria-label="Measured internet quality" hidden>
                        <div><span>Download</span><strong id="internet-download">—</strong></div>
                        <div><span>Upload</span><strong id="internet-upload">—</strong></div>
                        <div><span>Idle latency</span><strong id="internet-latency">—</strong></div>
                        <div><span>Responsiveness</span><strong id="internet-responsiveness">—</strong></div>
                    </div>
                    <div class="internet-optimizer-actions">
                        <button class="network-action primary" id="internet-router-btn" type="button">Open router settings</button>
                        <button class="network-action" id="internet-quality-btn" type="button">Measure internet (uses data)</button>
                        <button class="network-action" id="internet-diagnostics-btn" type="button">Wireless Diagnostics</button>
                        <button class="network-action" id="internet-wifi-settings-btn" type="button">Wi-Fi Settings</button>
                        <button class="network-action" id="internet-rerun-btn" type="button">Run again</button>
                    </div>
                    <p class="internet-optimizer-disclosure" id="internet-optimizer-disclosure">No settings changed. Nearby network names and identifiers are not read, displayed, or saved. Router channel changes require your router administrator or an explicitly authorized vendor adapter.</p>
                </div>
            </div>
        </section>
        <section class="network-card ke-link-card" id="ke-link-card" tabindex="-1" aria-labelledby="ke-link-title">
            <div class="ke-link-head">
                <div class="ke-link-brand"><div class="ke-link-mark" aria-hidden="true">↭</div><div><div class="ke-link-title" id="ke-link-title">KE Link</div><div class="ke-link-copy" id="ke-link-status">Off by default · opt in to become discoverable to other KE Monitors</div></div></div>
                <div class="ke-link-controls"><button class="network-action" id="network-pair-code-btn" type="button" disabled>Show one-time pairing code</button></div>
            </div>
            <div class="ke-pairing-code" id="network-pair-code" hidden></div>
            <div class="ke-trusted-list" id="network-trusted-peers" aria-label="Persistently trusted KE Link peers"></div>
            <div class="ke-link-boundary" id="ke-link-boundary">Plain-text messages only. A message cannot execute commands, open files, invoke an Agent, or grant authority. Message bodies stay in memory and disappear when the app quits.</div>
        </section>
        <details class="network-card network-traffic">
            <summary><span>Process traffic &amp; throughput</span><span class="network-card-copy">Existing per-process connection telemetry</span></summary>
            <div class="table-container">
                <table id="net-table"><thead><tr>
                    <th data-key="name" style="min-width:180px">Process Name</th>
                    <th data-key="connections" class="num sort-desc" style="width:100px">Connections</th>
                    <th data-key="sent_bytes" class="num" style="width:100px">Sent Bytes</th>
                    <th data-key="recv_bytes" class="num" style="width:100px">Rcvd Bytes</th>
                    <th data-key="pid" class="num" style="width:60px">PID</th>
                </tr></thead><tbody id="net-tbody"></tbody></table>
            </div>
            <div class="bottom-panel has-graph">
                <div class="graph-area"><div class="graph-section"><div class="graph-title">Network Activity</div><div id="net-bar-chart" style="flex:1;background:#1a1a2e;border-radius:4px;display:flex;align-items:flex-end;gap:0;overflow:hidden;min-height:80px"></div><canvas class="graph-canvas" id="net-canvas" style="display:none"></canvas></div></div>
                <div class="info-row" id="net-info-row">
                    <div class="info-item"><span class="dot dot-blue"></span><span class="info-label">Data Sent:</span><span class="info-value" id="net-sent">--</span></div>
                    <div class="info-item"><span class="dot dot-green"></span><span class="info-label">Data Received:</span><span class="info-value" id="net-recv">--</span></div>
                    <div class="info-item"><span class="info-label">Packets In:</span><span class="info-value" id="net-pin">--</span></div>
                    <div class="info-item"><span class="info-label">Packets Out:</span><span class="info-value" id="net-pout">--</span></div>
                    <div class="info-item"><span class="info-label">Send Rate:</span><span class="info-value" id="net-srate">--</span></div>
                    <div class="info-item"><span class="info-label">Recv Rate:</span><span class="info-value" id="net-rrate">--</span></div>
                    <div class="info-item"><span class="info-label">Connections:</span><span class="info-value" id="net-conns">--</span></div>
                </div>
            </div>
        </details>
    </div>
</div>

<div id="agents-tab" class="tab-content" aria-describedby="agents-scope">
    <p class="sr-only" id="agents-scope">Read-only local compute visibility. CPU core relationships are sampled co-activity, not fixed process placement.</p>
    <div class="agents-scroll">
        <div class="agents-heading">
            <h1>Agents</h1>
            <div class="agents-heading-actions">
                <button type="button" class="agents-powerswarm-open" id="agents-powerswarm-open" title="Open read-only PowerSwarm activity"><span>PowerSwarm</span><em class="agents-powerswarm-runtime" id="agents-powerswarm-runtime">Provider/model unknown</em><strong id="agents-powerswarm-count">—</strong><span class="powerswarm-arrow" aria-hidden="true">›</span></button>
                <div class="agents-freshness" id="agents-freshness">Waiting for telemetry</div>
            </div>
        </div>

        <div class="agents-overview">
            <section class="agent-card" aria-labelledby="agents-cpu-title">
                <div class="agent-card-head">
                    <div><div class="agent-card-title" id="agents-cpu-title">CPU by logical core</div><div class="agent-card-meta" id="agents-cpu-meta">Waiting for CPU data</div></div>
                    <span class="agent-badge info" id="agents-cpu-health">observing</span>
                </div>
                <div class="agent-card-value" id="agents-cpu-value">—</div>
                <div class="agents-core-grid" id="agents-cpu-cores"></div>
            </section>
            <section class="agent-card" aria-labelledby="agents-gpu-title">
                <div class="agent-card-head">
                    <div><div class="agent-card-title" id="agents-gpu-title">GPU compute</div><div class="agent-card-meta" id="agents-gpu-meta">Waiting for GPU data</div></div>
                    <span class="agent-badge info" id="agents-gpu-health" title="GPU telemetry is detected from the current Mac and measured host-wide when available.">host-wide</span>
                </div>
                <div class="gpu-primary"><div class="agent-card-value" id="agents-gpu-value">—</div><span class="gpu-primary-label">15s avg</span></div>
                <div class="gpu-history-shell" id="agents-gpu-history-frame" role="img" aria-label="Waiting for GPU utilization history">
                    <div class="gpu-history-grid" aria-hidden="true"></div>
                    <div class="gpu-history" id="agents-gpu-history" aria-hidden="true"></div>
                </div>
                <div class="gpu-metrics">
                    <div class="gpu-metric"><span class="gpu-metric-label" id="agents-gpu-now-label">Now</span><strong class="gpu-metric-value" id="agents-gpu-now">—</strong></div>
                    <div class="gpu-metric"><span class="gpu-metric-label">60s peak</span><strong class="gpu-metric-value" id="agents-gpu-peak">—</strong></div>
                    <div class="gpu-metric"><span class="gpu-metric-label" id="agents-gpu-memory-label">Memory</span><strong class="gpu-metric-value" id="agents-gpu-memory">—</strong></div>
                </div>
            </section>
            <section class="agent-card memory-pressure-card" aria-labelledby="agents-memory-title">
                <div class="agent-card-head">
                    <div><div class="agent-card-title" id="agents-memory-title">Memory pressure</div><div class="agent-card-meta" id="agents-memory-meta">Waiting for system memory data</div></div>
                    <span class="agent-badge info" id="agents-memory-health">observing</span>
                </div>
                <div class="memory-pressure-body">
                    <canvas class="memory-pressure-dial" id="agents-memory-dial" width="118" height="78" role="img" aria-label="Waiting for memory pressure"></canvas>
                    <div class="memory-pressure-headroom" id="agents-memory-headroom">Waiting</div>
                    <div class="memory-pressure-metrics">
                        <div class="memory-pressure-metric"><span>Available</span><strong id="agents-memory-available">—</strong></div>
                        <div class="memory-pressure-metric"><span>Swap</span><strong id="agents-memory-swap">—</strong></div>
                    </div>
                </div>
            </section>
        </div>

        <section class="agent-section core-inspector" id="agents-core-inspector" hidden aria-labelledby="agents-core-inspector-title">
            <div class="agent-section-head">
                <div class="agent-section-title" id="agents-core-inspector-title">Core inspector</div>
                <button type="button" class="core-inspector-close" id="agents-core-inspector-close" aria-label="Close core inspector">Close</button>
            </div>
            <div class="agent-section-body">
                <div class="core-inspector-summary">
                    <div class="core-stat"><div class="core-stat-label">Load</div><div class="core-stat-value" id="agents-core-current">—</div></div>
                    <div class="core-stat"><div class="core-stat-label">Average</div><div class="core-stat-value" id="agents-core-average">—</div></div>
                    <div class="core-stat"><div class="core-stat-label">Processes</div><div class="core-stat-value" id="agents-core-active-count">0</div></div>
                </div>
                <div class="core-truth-note" id="agents-core-truth">Co-activity only — fixed process placement is not exposed.</div>
                <div class="core-contributor-head" aria-hidden="true"><span>Agent / process</span><span>Total CPU</span><span>Co-activity</span><span>Evidence</span></div>
                <div class="core-contributor-list" id="agents-core-contributors"><div class="core-contributor-empty">Waiting for an active AI process sample.</div></div>
            </div>
        </section>

        <div class="agent-section">
            <div class="agent-section-head">
                <div class="agent-section-title">AI processes</div>
                <span class="agent-badge info" id="agents-process-count">0 observed</span>
            </div>
            <div class="ai-process-wrap">
                <table class="ai-process-table"><thead><tr>
                    <th>Process</th><th>Type</th><th class="num">% CPU</th><th class="num">Memory</th><th class="num">Threads</th><th class="num">PID</th><th>Runtime</th>
                </tr></thead><tbody id="agents-process-body"></tbody></table>
            </div>
        </div>

        <div class="agents-layout">
            <section class="agent-section">
                <div class="agent-section-head">
                    <div class="agent-section-title">CPU Workers</div>
                    <span class="agent-badge info" id="agents-cpu-count">0 live</span>
                </div>
                <div class="agent-section-body" id="agents-cpu-pools"><div class="agent-empty">Waiting for CPU Workers.</div></div>
            </section>
            <section class="agent-section">
                <div class="agent-section-head">
                    <div class="agent-section-title">GPU Jobs</div>
                    <span class="agent-badge info" id="agents-gpu-count">lane unknown</span>
                </div>
                <div class="agent-section-body" id="agents-gpu-jobs"><div class="agent-empty">Waiting for GPU Jobs.</div></div>
            </section>
        </div>
    </div>
</div>

<div id="powerswarm-tab" class="tab-content" aria-describedby="powerswarm-scope">
    <p class="sr-only" id="powerswarm-scope">Read-only PowerSwarm run-ledger visibility. Process liveness is observed separately from verified completion. Nested branches appear only when a valid central-recursion plan exists.</p>
    <div class="feature-scroll">
        <div class="feature-heading powerswarm-heading">
            <div class="powerswarm-heading-title"><button type="button" class="powerswarm-back" id="powerswarm-back">‹ Agents</button><h1>PowerSwarm</h1></div>
            <div class="agents-freshness" id="powerswarm-freshness" title="Automatic read-only refresh">Waiting for run ledger</div>
        </div>
        <div class="powerswarm-summary" aria-label="PowerSwarm worker counts">
            <div class="summary-tile"><span>Live</span><strong id="powerswarm-live">—</strong></div>
            <div class="summary-tile"><span>Queued</span><strong id="powerswarm-queued">—</strong></div>
            <div class="summary-tile"><span>Verified</span><strong id="powerswarm-verified">—</strong></div>
            <div class="summary-tile"><span>Failed</span><strong id="powerswarm-failed">—</strong></div>
        </div>
        <div class="powerswarm-layout">
            <section class="powerswarm-card" aria-labelledby="powerswarm-tree-title">
                <div class="powerswarm-card-head"><div class="powerswarm-card-title" id="powerswarm-tree-title">Recursion</div><span class="status-pill" id="powerswarm-state">checking</span></div>
                <div class="powerswarm-card-body" id="powerswarm-tree"><div class="powerswarm-empty">Waiting for PowerSwarm.</div></div>
            </section>
            <section class="powerswarm-card" aria-labelledby="powerswarm-runs-title">
                <div class="powerswarm-card-head"><div class="powerswarm-card-title" id="powerswarm-runs-title">Runs</div><button type="button" class="powerswarm-latest" id="powerswarm-latest">Latest</button></div>
                <div class="powerswarm-card-body"><div class="powerswarm-runs" id="powerswarm-runs"><div class="powerswarm-empty">No run history.</div></div></div>
            </section>
        </div>
        <section class="powerswarm-card powerswarm-worker-inspector" id="powerswarm-worker-inspector" hidden aria-live="polite" aria-labelledby="powerswarm-worker-title">
            <div class="powerswarm-card-head"><div class="powerswarm-card-title" id="powerswarm-worker-title">Worker</div><button type="button" class="core-inspector-close" id="powerswarm-worker-close">Close</button></div>
            <div class="powerswarm-card-body" id="powerswarm-worker-detail"></div>
        </section>
    </div>
</div>

<div id="brain-tab" class="tab-content" aria-describedby="brain-privacy-copy">
    <div class="feature-scroll">
        <div class="feature-heading">
            <div><h1>AI Brain</h1><div class="feature-subtitle">Your local knowledge systems, fingerprint-bound and under your control.</div></div>
            <div class="feature-actions">
                <div class="brain-view-switch" role="tablist" aria-label="AI Brain view">
                    <button type="button" class="brain-view-button" id="brain-view-files" role="tab" aria-selected="true">Files</button>
                    <button type="button" class="brain-view-button" id="brain-view-visual" role="tab" aria-selected="false">Visual</button>
                </div>
                <button type="button" class="feature-btn" id="brain-rescan">Scan all storage</button>
                <button type="button" class="feature-btn primary" id="brain-create">Create a brain</button>
            </div>
        </div>
        <div class="brain-context-bar">
            <div class="brain-overview" aria-label="AI Brain status">
                <div class="brain-overview-primary"><strong id="brain-connected">—</strong><span>ready</span></div>
                <div class="brain-overview-item"><strong id="brain-projects">—</strong><span>projects</span><small id="brain-project-state">Checking activity</small></div>
                <div class="brain-overview-item"><strong id="brain-discovered">—</strong><span>ready to connect</span></div>
                <div class="brain-overview-item"><strong id="brain-bodies">0 open</strong><span>selected note</span></div>
                <div class="brain-overview-scan"><strong id="brain-found">—</strong><span>local roots</span><small id="brain-coverage">Waiting for scan</small></div>
            </div>
            <p class="brain-privacy-line" id="brain-privacy-copy"><span aria-hidden="true">▣</span><strong>Local only</strong><span>Note text opens only when you select a file. Nothing is uploaded or routed.</span></p>
        </div>
        <div class="brain-files-view" id="brain-files-view">
        <div class="brain-files-browser-host" id="brain-files-browser-host">
        <section class="brain-files-welcome" id="brain-files-welcome" aria-label="Choose a Brain">
            <div class="brain-files-welcome-mark" aria-hidden="true">KE</div>
            <h2>Choose a Brain</h2>
            <p>Your connected folders appear on the left. Select one to browse its immediate files here.</p>
            <span>Read-only · local metadata first</span>
        </section>
        <section class="brain-browser" id="brain-browser" hidden aria-live="polite" aria-label="Read-only Brain browser">
            <div class="brain-browser-head">
                <div><div class="brain-browser-title" id="brain-browser-title">Brain browser</div><div class="brain-browser-copy" id="brain-browser-copy">Immediate items only · read-only</div></div>
                <div class="brain-browser-actions"><span class="status-pill connected" id="brain-browser-status">connected</span><button type="button" class="feature-btn" id="brain-browser-back">Back</button><button type="button" class="feature-btn" id="brain-browser-close">Close</button></div>
            </div>
            <nav class="brain-breadcrumbs" id="brain-breadcrumbs" aria-label="Brain path"></nav>
            <div class="brain-browser-message" id="brain-browser-message" hidden></div>
            <div class="brain-directory" id="brain-directory"></div>
            <article class="brain-note" id="brain-note" hidden aria-label="Selected note">
                <div class="brain-note-meta" id="brain-note-meta"></div>
                <pre class="brain-note-body" id="brain-note-body"></pre>
                <div class="brain-note-boundary">Plain text only · held in memory while this view is open · never stored or routed</div>
            </article>
            <div class="brain-pager" id="brain-pager" hidden><span class="brain-page-copy" id="brain-page-copy"></span><button type="button" class="feature-btn" id="brain-page-previous">Previous</button><button type="button" class="feature-btn" id="brain-page-next">Next</button></div>
        </section>
        </div>
        <section class="structure-panel" id="brain-structure-panel" hidden aria-live="polite">
            <div class="structure-title" id="brain-structure-title">Structure preview</div>
            <div class="structure-copy" id="brain-structure-copy"></div>
            <div class="structure-folders" id="brain-structure-folders"></div>
            <div class="confirmation-row">
                <label for="brain-structure-confirm" class="structure-copy">Type APPLY to confirm</label>
                <input id="brain-structure-confirm" autocomplete="off" spellcheck="false" placeholder="APPLY">
                <button type="button" class="feature-btn primary" id="brain-structure-apply" disabled>Apply with backup</button>
                <button type="button" class="feature-btn" id="brain-structure-cancel">Cancel</button>
                <button type="button" class="feature-btn danger" id="brain-structure-rollback" hidden>Rollback created folders</button>
            </div>
        </section>
        <div class="brain-list" id="brain-list" aria-label="Available Brains"><div class="brain-empty">Finding local Brains…</div></div>
        </div>
        <section class="brain-visual" id="brain-visual" hidden aria-label="Interactive project Brain hierarchy">
            <div class="brain-visual-toolbar">
                <div class="brain-visual-title">Your Brain map</div>
                <button type="button" class="brain-visual-btn" id="brain-visual-zoom-out" aria-label="Zoom out">−</button>
                <button type="button" class="brain-visual-btn" id="brain-visual-zoom-in" aria-label="Zoom in">＋</button>
                <button type="button" class="brain-visual-btn" id="brain-visual-fit">Fit</button>
            </div>
            <aside class="brain-visual-inspector" id="brain-visual-inspector" hidden aria-label="Selected Brain in Visual view"></aside>
            <div class="brain-visual-error" id="brain-visual-error" role="alert" hidden><strong>Brain scan could not finish.</strong><span id="brain-visual-error-copy"></span><button type="button" class="brain-visual-btn" id="brain-visual-retry">Retry</button></div>
            <svg class="brain-graph" id="brain-graph" viewBox="0 0 1000 620" role="img" aria-labelledby="brain-visual-label">
                <title id="brain-visual-label">Canonical KE Brain with its Codex and Claude project Brain children</title>
                <g id="brain-graph-world"></g>
            </svg>
            <div class="brain-visual-legend">Drag to pan · wheel or controls to zoom · select a node to browse</div>
            <div class="brain-visual-status" id="brain-visual-status" role="status" aria-live="polite"></div>
        </section>
    </div>
</div>

<div id="dispatch-tab" class="tab-content" aria-describedby="dispatch-privacy-copy">
    <div class="feature-scroll">
        <div class="feature-heading">
            <div><h1>Dispatch</h1><div class="feature-subtitle">Route one message to the exact existing Codex task or Claude session that already owns it.</div></div>
            <div class="feature-actions"><span class="status-pill" id="dispatch-readiness">Checking routes</span></div>
        </div>
        <div class="privacy-strip" id="dispatch-privacy-copy"><span class="privacy-lock" aria-hidden="true">▣</span><span><strong>Private local routing.</strong> The Brain viewer never routes selected note bodies or credentials. History keeps destination metadata and a SHA-256 fingerprint—not your message body.</span></div>
        <div class="dispatch-layout">
            <section class="dispatch-card dispatch-composer">
                <h2>Message</h2>
                <textarea id="dispatch-message" placeholder="Paste or type your message. Name a task, provider, or exact session ID when useful."></textarea>
                <div class="dispatch-row">
                    <label class="diagnostic-toggle"><input type="checkbox" id="dispatch-diagnostic"> Agent-generated diagnostic; not written by you</label>
                    <span class="spacer"></span>
                    <button type="button" class="feature-btn" id="dispatch-resolve">Resolve destination</button>
                    <button type="button" class="feature-btn primary" id="dispatch-send" disabled>Send once</button>
                </div>
                <div class="dispatch-target" id="dispatch-target" aria-live="polite">
                    <div class="dispatch-target-title">No destination resolved</div>
                    <div class="dispatch-target-meta">Dispatch will show the exact provider, title, task/session ID, state, and reason before send.</div>
                </div>
                <div id="dispatch-choices"></div>
                <div class="dispatch-phase"><span class="status-pill" id="dispatch-state">ready</span><span class="dispatch-phase-copy" id="dispatch-state-copy">Resolve before sending. Ambiguity and missing owners fail closed.</span></div>
            </section>
            <section class="dispatch-card">
                <h2>Recent metadata-only history</h2>
                <div class="dispatch-history" id="dispatch-history"><div class="dispatch-empty">No local dispatch receipts yet.</div></div>
            </section>
        </div>
    </div>
</div>

<div id="guard-tab" class="tab-content" aria-describedby="guard-privacy-copy">
    <div class="feature-scroll">
        <div class="feature-heading">
            <div><h1>KE Guard</h1><div class="feature-subtitle">Read-only machine protection status from the current user’s local guardian.</div></div>
            <div class="feature-actions"><span class="status-pill" id="guard-state">Checking</span></div>
        </div>
        <div class="privacy-strip" id="guard-privacy-copy"><span class="privacy-lock" aria-hidden="true">▣</span><span><strong>Strictly read-only.</strong> This tab cannot kill, delete, restart, arm, or change policy. Raw commands, alert bodies, file paths, and evidence paths never enter the page.</span></div>
        <div class="feature-summary">
            <div class="summary-tile"><span>Configured mode</span><strong id="guard-mode">—</strong><small id="guard-mode-detail">Waiting for state</small></div>
            <div class="summary-tile"><span>Observed</span><strong id="guard-observed">—</strong><small id="guard-observed-detail">No observation yet</small></div>
            <div class="summary-tile"><span>Active suspects</span><strong id="guard-suspects">—</strong><small id="guard-suspects-detail">No validated state</small></div>
            <div class="summary-tile"><span>Kills · 24h</span><strong id="guard-kills">—</strong><small id="guard-kills-detail">Actual SIGTERM remediations</small></div>
        </div>
        <section class="guard-card guard-unavailable" id="guard-unavailable" hidden aria-live="polite">
            <h2 id="guard-unavailable-title">KE Guard unavailable</h2>
            <div class="guard-card-copy" id="guard-unavailable-copy"></div>
        </section>
        <div class="guard-layout">
            <div class="guard-column">
                <section class="guard-card">
                    <h2>Resource trend</h2>
                    <div class="guard-trends">
                        <div class="guard-trend">
                            <div class="guard-trend-head"><span class="guard-trend-title">System load</span><strong class="guard-trend-value" id="guard-load-value">—</strong></div>
                            <div class="guard-trend-meta" id="guard-load-meta">Waiting for samples</div>
                            <div class="guard-spark load" id="guard-load-spark" aria-label="No load trend available"></div>
                        </div>
                        <div class="guard-trend">
                            <div class="guard-trend-head"><span class="guard-trend-title">Disk free</span><strong class="guard-trend-value" id="guard-disk-value">—</strong></div>
                            <div class="guard-trend-meta" id="guard-disk-meta">Waiting for samples</div>
                            <div class="guard-spark" id="guard-disk-spark" aria-label="No disk trend available"></div>
                        </div>
                    </div>
                </section>
                <section class="guard-card">
                    <h2>Pending remediation</h2>
                    <div id="guard-pending"><div class="guard-empty">No remediation is pending.</div></div>
                </section>
            </div>
            <section class="guard-card">
                <h2>Recent alert and remediation evidence</h2>
                <div class="guard-evidence" id="guard-evidence"><div class="guard-empty">No sanitized evidence is available yet.</div></div>
            </section>
        </div>
    </div>
</div>

</div>

<div class="status-bar">
    <div class="s-item"><span>Processes:</span><strong id="sb-procs">0</strong></div>
    <div class="s-item"><span>Threads:</span><strong id="sb-threads">0</strong></div>
    <div class="s-item"><span>CPU Usage:</span><strong id="sb-cpu">0%</strong></div>
    <div class="s-item" style="margin-left:auto;color:#888" id="sb-uptime"></div>
</div>
</section>
</div>

<div class="workspace-toast" id="workspace-toast" role="status" aria-live="polite"></div>
<div class="workspace-dialog" id="workspace-dialog" hidden role="dialog" aria-modal="true" aria-labelledby="workspace-dialog-title">
    <div class="workspace-dialog-panel">
        <header class="workspace-dialog-head">
            <div class="workspace-dialog-title"><h2 id="workspace-dialog-title">Choose projects</h2><p>Codex projects follow exact sidebar assignments. Claude projects are added explicitly and need their matching folder for inactive-session resume.</p></div>
            <button type="button" class="workspace-dialog-close" id="workspace-dialog-close">Done</button>
        </header>
        <div class="workspace-dialog-body" id="workspace-dialog-body"></div>
    </div>
</div>

<script>
let currentTab = 'cpu';
let searchFilter = '';
let sortState = {
    cpu: {key:'cpu_percent', dir:'desc'},
    memory: {key:'memory_mb', dir:'desc'},
    energy: {key:'energy_impact', dir:'desc'},
    disk: {key:'read_bytes', dir:'desc'},
    network: {key:'connections', dir:'desc'},
};
let cpuHistory = {user:[], system:[]};
const CPU_HIST_LEN = 120;
let netHistory = {sent:[], recv:[]};
const NET_HIST_LEN = 120;
let energyHistory = [];
const ENERGY_HIST_LEN = 120;
let lastEnergyProcesses = [];
let selectedPid = null;
let apiReady = false;
let refreshTimer = null;
let refreshInFlight = false;
let refreshQueued = false;
let selectedAgentCore = null;
let lastCoreActivitySample = null;
let lastValidAgentCpu = null;
let lastValidGpuDevice = null;
let lastValidAgentMemory = null;
let lastGpuUtilizationSample = null;
const gpuUtilizationHistory = [];
const GPU_UTILIZATION_HISTORY_LENGTH = 20;
const GPU_SMOOTHING_WINDOW = 5;
const coreActivityHistory = [];
const CORE_ACTIVITY_HISTORY_LENGTH = 20;
const CORE_COACTIVITY_MIN_SAMPLES = 8;
const CORE_RECENT_ACTIVITY_SAMPLES = 10;
const CORE_CONTRIBUTOR_SESSION_RETENTION = true;
const coreContributorRows = new Map();
let lastBrainInventory = null;
let brainBrowserState = null;
let brainPreview = null;
let brainOperationId = null;
let brainView = 'files';
let brainRequestGeneration = 0;
let brainActionGeneration = 0;
let brainAutoOpenAttempted = false;
const brainActionErrors = new Map();
let brainGraphTransform = {x:0, y:0, scale:1};
let brainGraphDrag = null;
let dispatchResolution = null;
let dispatchTargetId = null;
let lastGuardStatus = null;
let memoryDiagnosticsRunning = false;
let lastMemoryDiagnostics = null;
let memoryRetryTarget = null;
const MEMORY_DIAGNOSTIC_SAMPLE_SECONDS = 12;
let workspaceSnapshot = null;
let workspaceExpanded = null;
let workspaceQuery = '';
let workspaceTimer = null;
let workspaceToastTimer = null;
let workspaceHostMode = 'native';
let conversationHostGeneration = 0;
let conversationHostContext = null;
let conversationHostTrigger = null;
let conversationHostRouteKind = 'conductor';
const conversationHostRequests = new Map();
let lastNetworkSnapshot = null;
let selectedNetworkDeviceId = null;
let networkDeviceFilter = 'all';
let networkDiscoveryStarted = false;
let networkDiscoveryStopPromise = Promise.resolve();
let pendingNetworkMessage = null;
let networkRecoveryContext = null;
let networkRecoveryInFlight = false;
let networkRecoveryWatcher = null;
let networkRecoveryErrorGeneration = 0;
let networkRecoveryFingerprint = '';
let networkRecoveryRequestSequence = 0;
let networkLifecycleGeneration = 0;
let networkWindowTransitionSequence = 0;
let networkLastDepartureSequence = 0;
let networkLastReturnSequence = 0;
const NETWORK_RECOVERY_RETURN_TIMEOUT_MS = 120000;
let activeNetworkInfoTrigger = null;
let lastInternetOptimizerSnapshot = null;
let internetOptimizerErrorDetail = null;
let internetOptimizerGeneration = 0;
let internetOptimizerInFlight = false;
let internetQualityInFlight = false;
const NETWORK_INFO_COPY = Object.freeze({
    visibility: Object.freeze({
        title: 'What this view can see',
        body: 'Activity Monitor reports evidence from eligible directly connected segments. Sleeping, silent, firewalled, client-isolated, tunnel, or different-VLAN devices may not appear.'
    }),
    observed: Object.freeze({
        title: 'Observed devices',
        body: 'Deduplicated devices with current or retained local evidence. This is not a complete router inventory and does not guarantee every device is visible.'
    }),
    online: Object.freeze({
        title: 'Online now',
        body: 'Fresh direct evidence was seen inside the online window. A trusted peer is not online or ready unless fresh evidence and, for KE Link, an authenticated session exist.'
    }),
    recent: Object.freeze({
        title: 'Recently seen',
        body: 'Seen recently, but without evidence fresh enough for Online now. The device may be asleep, disconnected, or simply silent.'
    }),
    trusted: Object.freeze({
        title: 'Trusted peers',
        body: 'A KE Link peer you explicitly paired and retained. Trust persists across discovery; Connected or Ready still requires a fresh pinned and authenticated session.'
    }),
    coverage: Object.freeze({
        title: 'Coverage',
        body: 'Eligible directly connected segments included in this bounded cycle. An asterisk means the scan is partial or capped; excluded and tunnel interfaces are not counted.'
    }),
    optimizer: Object.freeze({
        title: 'What Internet Optimizer changes',
        body: 'The first click measures this Mac and nearby channel pressure but changes nothing. Router changes require your visible authorization. Measure internet is separate because it connects to the internet and uses plan data.'
    })
});
let lastPowerSwarmSnapshot = null;
let selectedPowerSwarmRunId = null;
let selectedPowerSwarmWorkerId = null;
let diskCleanupJobId = null;
let diskCleanupAnalysisId = null;
let diskCleanupResult = null;
let diskCleanupFilter = 'all';
let diskCleanupCategory = 'all';
let diskCleanupGeneration = 0;
let diskCleanupInitialFreeBytes = null;
let diskCleanupReturnFocus = null;
const diskCleanupSelected = new Set();
const DISK_CLEANUP_MAX_SELECTION = 12;

function workspaceShowToast(message) {
    const toast = document.getElementById('workspace-toast');
    toast.textContent = String(message || '');
    toast.classList.add('visible');
    if (workspaceToastTimer) clearTimeout(workspaceToastTimer);
    workspaceToastTimer = setTimeout(() => toast.classList.remove('visible'), 4200);
}

function conversationHostNextGeneration() {
    conversationHostGeneration = conversationHostGeneration >= 2147483646 ? 1 : conversationHostGeneration + 1;
    return conversationHostGeneration;
}

function conversationHostNewRequestId() {
    if (crypto?.randomUUID) return crypto.randomUUID().toLowerCase();
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    const hex = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

function conversationHostSetStatus(message, state = '') {
    const status = document.getElementById('conversation-host-status');
    status.textContent = String(message || '');
    status.className = 'conversation-host-status' + (state ? ' ' + state : '');
}

function setWorkspaceHostMode(mode, announce = true) {
    const nextMode = mode === 'activity' ? 'activity' : 'native';
    const changed = workspaceHostMode !== nextMode;
    workspaceHostMode = nextMode;
    document.querySelectorAll('.workspace-host-mode').forEach(button => {
        const active = button.dataset.hostMode === workspaceHostMode;
        button.classList.toggle('active', active);
        button.setAttribute('aria-pressed', String(active));
    });
    if (changed && workspaceSnapshot) renderWorkspace(workspaceSnapshot);
    if (announce) {
        workspaceShowToast(
            workspaceHostMode === 'activity'
                ? 'Conversation clicks now open inside Activity Monitor.'
                : 'Conversation clicks now open in their native companion.'
        );
    }
}

function workspaceFindProject(provider, projectId) {
    return (workspaceSnapshot?.projects || []).find(project =>
        project.provider === provider && project.id === projectId
    ) || null;
}

function workspaceFindConversation(provider, conversationId) {
    for (const project of workspaceSnapshot?.projects || []) {
        const conversation = (project.conversations || []).find(item =>
            item.provider === provider && item.id === conversationId
        );
        if (conversation) return {project, conversation};
    }
    return null;
}

function conversationHostSetHeader() {
    const context = conversationHostContext;
    if (!context) return;
    const projectMode = context.kind === 'project';
    document.getElementById('conversation-host').classList.toggle('project-home', projectMode);
    const title = projectMode ? `${context.projectName} Conductor` : context.title;
    document.getElementById('conversation-host-title').textContent = title || 'Conversation';
    document.getElementById('conversation-host-subtitle').textContent = projectMode
        ? `${context.provider === 'claude' ? 'Claude' : 'Codex'} project · routes to the right project task`
        : `${context.provider === 'claude' ? 'Claude' : 'Codex'} · exact conversation hosted in Activity Monitor`;
    const glyph = document.getElementById('conversation-host-glyph');
    glyph.textContent = context.provider === 'claude' ? 'CL' : 'CX';
    glyph.className = 'conversation-host-glyph' + (context.provider === 'claude' ? ' claude' : '');
    document.getElementById('conversation-host-route').hidden = !projectMode;
    document.getElementById('conversation-host-native-open').hidden = !context.conversationId;
    document.getElementById('conversation-host-destination').hidden = !context.destination?.id;
    document.getElementById('conversation-host-refresh').textContent = projectMode ? 'Refresh queue' : 'Refresh';
    document.getElementById('conversation-host-input').placeholder = projectMode
        ? 'Tell this project what you need. Send rapid follow-ups whenever they occur.'
        : 'Continue this exact conversation…';
}

function conversationHostReveal(context, trigger) {
    if (!trigger?.closest?.('#conversation-host')) conversationHostTrigger = trigger || document.activeElement;
    conversationHostContext = {...context, generation: conversationHostNextGeneration(), destination:null, projectState:null};
    conversationHostRequests.clear();
    const panel = document.getElementById('conversation-host');
    panel.hidden = false;
    conversationHostSetHeader();
    const transcript = document.getElementById('conversation-host-transcript');
    emptyNode(transcript);
    const loading = document.createElement('div');
    loading.className = 'conversation-host-loading';
    loading.textContent = context.kind === 'project' ? 'Preparing the project Conductor…' : 'Reading the exact local conversation…';
    transcript.appendChild(loading);
    document.getElementById('conversation-host-input').value = '';
    conversationHostSetStatus('Nothing sends until you press Send.');
}

function conversationHostReceiptState(receipt = {}) {
    const state = String(receipt.state || 'queued');
    if (receipt.reconciliationRequired || state.includes('uncertain') || state.includes('reconciliation')) return 'uncertain';
    if (state.includes('failed')) return 'failed';
    return '';
}

function conversationHostReceiptCopy(receipt = {}) {
    const state = String(receipt.state || 'queued');
    if (receipt.reconciliationRequired || state.includes('uncertain')) return 'Delivery may have occurred · reconciliation required';
    if (state.includes('reconciliation')) return 'Previous delivery needs reconciliation';
    if (state.includes('failed')) return 'Delivery did not start';
    if (state === 'transcript observed') return 'Delivered · observed in transcript';
    if (state === 'accepted' || state === 'working' || state === 'acknowledged') return 'Accepted by the exact task';
    return 'Queued for the exact task';
}

function conversationHostSetDestination(destination) {
    const provider = String(destination?.provider || '').toLowerCase();
    const id = String(destination?.id || '').toLowerCase();
    if (!['codex','claude'].includes(provider) || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) return;
    conversationHostContext.destination = {
        provider,
        id,
        title:String(destination.title || (conversationHostRouteKind === 'powerswarm' ? 'PowerSwarm' : 'Project Conductor')),
    };
    document.getElementById('conversation-host-destination').hidden = false;
    document.getElementById('conversation-host-native-open').hidden = false;
}

function conversationHostSyncMappedDestination() {
    const context = conversationHostContext;
    const id = context?.projectState?.agents?.[conversationHostRouteKind];
    if (id) {
        conversationHostSetDestination({
            provider:'codex',
            id,
            title:conversationHostRouteKind === 'powerswarm'
                ? `PowerSwarm · ${context.projectName}`
                : `Conductor · ${context.projectName}`,
        });
    } else if (context?.kind === 'project') {
        context.destination = null;
        document.getElementById('conversation-host-destination').hidden = true;
        document.getElementById('conversation-host-native-open').hidden = true;
    }
}

function conversationHostRenderProject(payload) {
    if (!conversationHostContext || conversationHostContext.kind !== 'project') return;
    document.getElementById('conversation-host').classList.add('project-home');
    conversationHostContext.projectState = payload;
    const transcript = document.getElementById('conversation-host-transcript');
    emptyNode(transcript);
    const card = document.createElement('section');
    card.className = 'conversation-host-empty';
    const head = document.createElement('div');
    head.className = 'conversation-host-empty-head';
    const mark = document.createElement('div');
    mark.className = 'conversation-host-empty-mark';
    mark.textContent = 'KE';
    const heading = document.createElement('h3');
    heading.textContent = 'What should this project handle next?';
    head.append(mark, heading);
    const copy = document.createElement('p');
    copy.textContent = 'Send one request or several follow-ups. The Conductor routes each one to the right task, or starts one project task when needed.';
    const proof = document.createElement('div');
    proof.className = 'conversation-host-proof';
    ['Routes to the current owner','Creates one task when needed','PowerSwarm ready'].forEach(label => {
        const chip = document.createElement('span'); chip.textContent = label; proof.appendChild(chip);
    });
    card.append(head, copy, proof);
    transcript.appendChild(card);
    (payload.queue || []).slice(0, 8).reverse().forEach(receipt => {
        const row = document.createElement('div');
        row.className = 'conversation-host-receipt ' + conversationHostReceiptState(receipt);
        const copy = document.createElement('span');
        copy.textContent = conversationHostReceiptCopy(receipt);
        row.appendChild(copy);
        row.title = `Request ${String(receipt.requestId || '').slice(0, 8)}`;
        if (receipt.reconciliationRequired === true && receipt.requestId) {
            const reconcile = document.createElement('button');
            reconcile.type = 'button';
            reconcile.textContent = 'Reconcile';
            reconcile.addEventListener('click', () => conversationHostReconcile({
                id:String(receipt.requestId), generation:conversationHostContext.generation,
            }));
            row.appendChild(reconcile);
        } else if (String(receipt.state || '').includes('failed')) {
            const writeAgain = document.createElement('button');
            writeAgain.type = 'button';
            writeAgain.textContent = 'Write again';
            writeAgain.addEventListener('click', () => document.getElementById('conversation-host-input').focus());
            row.appendChild(writeAgain);
        }
        card.appendChild(row);
    });
    conversationHostSyncMappedDestination();
    transcript.scrollTop = transcript.scrollHeight;
}

function conversationHostRenderTranscript(payload) {
    const transcript = document.getElementById('conversation-host-transcript');
    emptyNode(transcript);
    const items = Array.isArray(payload.items) ? payload.items : [];
    if (!items.length) {
        const card = document.createElement('section');
        card.className = 'conversation-host-empty';
        const heading = document.createElement('h3'); heading.textContent = 'This conversation is ready';
        const copy = document.createElement('p'); copy.textContent = 'No readable messages are in the bounded local page yet. Send below to continue the exact task.';
        card.append(heading, copy);
        transcript.appendChild(card);
    }
    items.forEach(item => {
        const role = ['user','assistant','activity'].includes(item.role) ? item.role : 'activity';
        const bubble = document.createElement('article');
        bubble.className = 'conversation-host-message ' + role;
        const label = document.createElement('span');
        label.className = 'conversation-host-message-role';
        label.textContent = role === 'user' ? 'You' : role === 'assistant' ? 'Agent' : 'Activity';
        const text = document.createElement('div');
        text.className = 'conversation-host-message-text';
        text.textContent = String(item.text || '');
        bubble.append(label, text);
        transcript.appendChild(bubble);
    });
    transcript.scrollTop = transcript.scrollHeight;
}

function conversationHostAppendRequest(request) {
    const transcript = document.getElementById('conversation-host-transcript');
    if (conversationHostContext?.kind === 'project') {
        document.getElementById('conversation-host').classList.remove('project-home');
    }
    transcript.querySelector('.conversation-host-empty')?.remove();
    const bubble = document.createElement('article');
    bubble.className = 'conversation-host-message user';
    bubble.dataset.requestId = request.id;
    const label = document.createElement('span'); label.className = 'conversation-host-message-role'; label.textContent = 'You';
    const text = document.createElement('div'); text.className = 'conversation-host-message-text'; text.textContent = request.body;
    const state = document.createElement('div');
    state.className = 'conversation-host-request-state';
    const strong = document.createElement('strong'); strong.textContent = 'Routing now…';
    const detail = document.createElement('span'); detail.textContent = request.routeKind === 'powerswarm' ? 'PowerSwarm' : 'Exact destination';
    state.append(strong, detail);
    bubble.append(label, text, state);
    transcript.appendChild(bubble);
    transcript.scrollTop = transcript.scrollHeight;
}

function conversationHostUpdateRequest(request, result) {
    const bubble = document.querySelector(`[data-request-id="${request.id}"]`);
    if (!bubble) return;
    const state = bubble.querySelector('.conversation-host-request-state');
    emptyNode(state);
    const strong = document.createElement('strong');
    const receipt = result.receipt || {};
    const deliveryAttempted = result.deliveryAttempted === true || receipt.deliveryAttempted === true;
    const reconciliationRequired = result.reconciliationRequired === true || receipt.reconciliationRequired === true;
    const retrySafe = result.retrySafe === true || receipt.retrySafe === true;
    const uncertain = deliveryAttempted || reconciliationRequired;
    if (result.ok) strong.textContent = conversationHostReceiptCopy(receipt);
    else if (uncertain) strong.textContent = 'Delivery may have occurred. Reconciliation is required.';
    else strong.textContent = 'Delivery did not start.';
    state.appendChild(strong);
    if (!result.ok && uncertain && request.id) {
        const reconcile = document.createElement('button');
        reconcile.type = 'button';
        reconcile.textContent = 'Reconcile';
        reconcile.addEventListener('click', () => conversationHostReconcile(request));
        state.appendChild(reconcile);
    } else if (!result.ok && retrySafe && !deliveryAttempted) {
        const retry = document.createElement('button');
        retry.type = 'button';
        retry.textContent = 'Try again';
        retry.addEventListener('click', () => conversationHostSendBody(request.body, request.routeKind));
        state.appendChild(retry);
    }
}

async function conversationHostReconcile(request) {
    conversationHostSetStatus('Checking the exact transcript for this request…');
    try {
        const result = bridgeJson(await pywebview.api.reconcile_hosted_request(request.id, request.generation));
        if (result.generation !== request.generation) return;
        conversationHostUpdateRequest(request, result);
        if (result.ok) conversationHostSetStatus('Delivery is now observed in the exact transcript.');
        else conversationHostSetStatus('Delivery is still uncertain. Retry remains disabled.', 'uncertain');
    } catch (_) {
        conversationHostSetStatus('Delivery is still uncertain. Retry remains disabled.', 'uncertain');
    }
}

async function conversationHostSendBody(body, routeKind = conversationHostRouteKind) {
    const context = conversationHostContext;
    if (!apiReady || !context || !String(body || '').trim()) return;
    const request = {
        id:conversationHostNewRequestId(),
        generation:context.generation,
        body:String(body),
        routeKind:routeKind === 'powerswarm' ? 'powerswarm' : 'conductor',
        context:{...context},
    };
    conversationHostRequests.set(request.id, request);
    conversationHostAppendRequest(request);
    conversationHostSetStatus('Routing this request now. You can send another follow-up immediately.');
    let result;
    try {
        if (context.kind === 'project') {
            result = bridgeJson(await pywebview.api.send_project_conductor(
                context.provider, context.projectId, request.body, request.id, request.generation, request.routeKind
            ));
        } else {
            result = bridgeJson(await pywebview.api.send_hosted_conversation(
                context.provider, context.conversationId, request.body, request.id, request.generation
            ));
        }
    } catch (_) {
        result = {
            ok:false,
            generation:request.generation,
            deliveryAttempted:true,
            retrySafe:false,
            reconciliationRequired:true,
            receipt:{requestId:request.id,state:'uncertain after send',reconciliationRequired:true},
        };
    }
    conversationHostUpdateRequest(request, result);
    if (result.generation !== request.generation) return;
    if (result.destination && conversationHostContext?.generation === request.generation) {
        conversationHostSetDestination(result.destination);
    }
    if (result.ok) {
        conversationHostSetStatus('Accepted by the exact destination. Send another follow-up whenever you need.');
    } else if (result.deliveryAttempted || result.reconciliationRequired) {
        conversationHostSetStatus('Delivery may have occurred. Retry is disabled until reconciliation completes.', 'uncertain');
    } else {
        conversationHostSetStatus('Delivery did not start. Your request remains above and can be tried again safely.', 'failed');
    }
}

function conversationHostSubmit() {
    const input = document.getElementById('conversation-host-input');
    const body = input.value;
    if (!body.trim()) {
        conversationHostSetStatus('Write a request before sending.', 'failed');
        input.focus();
        return;
    }
    input.value = '';
    conversationHostSendBody(body, conversationHostRouteKind);
    input.focus();
}

async function conversationHostOpenProject(project, trigger) {
    if (!apiReady || !project) return;
    setWorkspaceHostMode('activity', false);
    const liveTrigger = Array.from(document.querySelectorAll('.workspace-project-button')).find(
        button => button.dataset.projectButton === project.id
    ) || trigger;
    conversationHostReveal({
        kind:'project', provider:project.provider, projectId:project.id, projectName:project.name,
    }, liveTrigger);
    const generation = conversationHostContext.generation;
    try {
        const result = bridgeJson(await pywebview.api.get_project_conversation_host(project.provider, project.id));
        if (!conversationHostContext || conversationHostContext.generation !== generation) return;
        if (!result.ok) throw new Error(result.error || 'This project Conductor is unavailable');
        conversationHostRenderProject(result);
        document.getElementById('conversation-host-input').focus();
    } catch (error) {
        const transcript = document.getElementById('conversation-host-transcript');
        emptyNode(transcript);
        const card = document.createElement('section'); card.className = 'conversation-host-empty';
        const heading = document.createElement('h3'); heading.textContent = 'Conductor is not ready';
        const copy = document.createElement('p'); copy.textContent = String(error?.message || error);
        card.append(heading, copy); transcript.appendChild(card);
        conversationHostSetStatus('No message was sent. Resolve the companion issue and refresh.', 'failed');
    }
}

async function conversationHostOpenConversation(provider, conversationId, trigger) {
    if (!apiReady) return;
    const found = workspaceFindConversation(provider, conversationId);
    const conversation = found?.conversation || {};
    const project = found?.project || {};
    setWorkspaceHostMode('activity', false);
    conversationHostReveal({
        kind:'conversation', provider, conversationId,
        projectId:project.id || '', projectName:project.name || 'Project',
        title:conversation.title || 'Conversation',
    }, trigger);
    const generation = conversationHostContext.generation;
    try {
        const result = bridgeJson(await pywebview.api.read_hosted_conversation(provider, conversationId, generation));
        if (!conversationHostContext || result.generation !== generation || conversationHostContext.generation !== generation) return;
        if (!result.ok) throw new Error(result.error || 'The exact conversation could not be read');
        conversationHostRenderTranscript(result);
        conversationHostSetStatus('Exact local transcript loaded. Nothing was sent.');
        document.getElementById('conversation-host-input').focus();
    } catch (error) {
        const transcript = document.getElementById('conversation-host-transcript');
        emptyNode(transcript);
        const card = document.createElement('section'); card.className = 'conversation-host-empty';
        const heading = document.createElement('h3'); heading.textContent = 'Conversation could not be read';
        const copy = document.createElement('p'); copy.textContent = String(error?.message || error);
        card.append(heading, copy); transcript.appendChild(card);
        conversationHostSetStatus('Nothing was sent. You can open the exact task in its native app.', 'failed');
    }
}

async function conversationHostRefresh() {
    const context = conversationHostContext;
    if (!context) return;
    if (context.kind === 'project') {
        const result = bridgeJson(await pywebview.api.get_project_conversation_host(context.provider, context.projectId));
        if (result.ok && conversationHostContext?.generation === context.generation) conversationHostRenderProject(result);
    } else {
        const result = bridgeJson(await pywebview.api.read_hosted_conversation(context.provider, context.conversationId, context.generation));
        if (result.ok && result.generation === context.generation && conversationHostContext?.generation === context.generation) {
            conversationHostRenderTranscript(result);
            conversationHostSetStatus('Exact local transcript refreshed. Nothing was sent.');
        }
    }
}

function conversationHostClose() {
    const panel = document.getElementById('conversation-host');
    if (panel.hidden) return;
    panel.hidden = true;
    conversationHostNextGeneration();
    conversationHostContext = null;
    conversationHostRequests.clear();
    const trigger = conversationHostTrigger;
    conversationHostTrigger = null;
    if (trigger?.isConnected && typeof trigger.focus === 'function') trigger.focus();
}

async function conversationHostOpenNative(provider, conversationId) {
    if (!apiReady || !provider || !conversationId) return;
    const result = bridgeJson(await pywebview.api.open_workspace_conversation(provider, conversationId));
    if (!result.ok) throw new Error(result.error || 'The native companion could not open this exact conversation');
    workspaceShowToast(provider === 'codex'
        ? 'Open requested in Codex. Confirm the exact task in the native app.'
        : 'Resume requested in a visible Terminal. Confirm the exact Claude session there.');
}

function workspaceApplyPreferences(preferences = {}) {
    const shell = document.getElementById('workspace-shell');
    const collapsed = Boolean(preferences.railCollapsed);
    const width = Math.max(220, Math.min(380, Number(preferences.railWidth || 252)));
    shell.classList.toggle('rail-collapsed', collapsed);
    shell.style.setProperty('--rail-width', width + 'px');
    document.documentElement.style.setProperty('--rail-width', width + 'px');
    const collapse = document.getElementById('workspace-collapse');
    collapse.setAttribute('aria-expanded', String(!collapsed));
    collapse.setAttribute('aria-label', collapsed ? 'Expand project rail' : 'Collapse project rail');
}

async function workspaceUpdatePreferences(patch, reload = true) {
    if (!apiReady) return null;
    const result = bridgeJson(await pywebview.api.update_workspace_preferences(patch));
    if (!result.ok) throw new Error(result.error || 'Workspace preference update failed');
    workspaceApplyPreferences(result.preferences || {});
    if (reload) await loadWorkspace(true);
    return result;
}

function workspaceScheduleRefresh(delay = 15000) {
    if (workspaceTimer) clearTimeout(workspaceTimer);
    workspaceTimer = setTimeout(() => loadWorkspace(false), delay);
}

async function loadWorkspace(force = false) {
    if (!apiReady) return;
    const refresh = document.getElementById('workspace-refresh');
    refresh.classList.add('loading');
    try {
        const result = bridgeJson(await pywebview.api.get_workspace_state(Boolean(force)));
        if (!result.ok) throw new Error(result.error || 'Project metadata is unavailable');
        workspaceSnapshot = result;
        if (workspaceExpanded === null) {
            const persistedExpansion = result.preferences?.expandedProjectIds;
            workspaceExpanded = new Set(
                persistedExpansion === null
                    ? (result.projects || []).slice(0, 3).map(project => project.id)
                    : (persistedExpansion || [])
            );
        }
        workspaceApplyPreferences(result.preferences || {});
        renderWorkspace(result);
        if (!document.getElementById('workspace-dialog').hidden) renderWorkspaceChooser();
    } catch (error) {
        const tree = document.getElementById('workspace-tree');
        emptyNode(tree);
        const message = document.createElement('div');
        message.className = 'workspace-tree-message';
        message.textContent = 'Project rail unavailable: ' + String(error);
        tree.appendChild(message);
    } finally {
        refresh.classList.remove('loading');
        workspaceScheduleRefresh();
    }
}

function workspaceMatches(project, conversation = null) {
    if (!workspaceQuery) return true;
    const values = conversation
        ? [conversation.title, conversation.id, conversation.state]
        : [project.name, project.id, project.provider];
    return values.some(value => String(value || '').toLowerCase().includes(workspaceQuery));
}

function renderWorkspace(payload) {
    const preferences = payload.preferences || {};
    const filters = preferences.providerFilters || {};
    document.getElementById('workspace-filter-codex').classList.toggle('active', filters.codex !== false);
    document.getElementById('workspace-filter-claude').classList.toggle('active', filters.claude !== false);
    const counts = payload.counts || {};
    const summary = document.getElementById('workspace-summary');
    emptyNode(summary);
    const dot = document.createElement('span');
    dot.className = 'workspace-live-dot';
    const copy = document.createElement('span');
    const active = Number(counts.active || 0);
    const projectCount = Number(counts.projects || 0);
    const taskCount = Number(counts.conversations || 0);
    copy.textContent = `${projectCount} project${projectCount === 1 ? '' : 's'} · ${taskCount} task${taskCount === 1 ? '' : 's'}`;
    const strong = document.createElement('strong');
    strong.textContent = active ? `${active} active` : 'local metadata';
    summary.append(dot, copy, strong);
    const companions = payload.companions || {};
    const codex = document.getElementById('workspace-codex-companion');
    const claude = document.getElementById('workspace-claude-companion');
    codex.classList.toggle('ready', Boolean(companions.codex?.exactOpenAvailable));
    claude.classList.toggle('ready', Boolean(companions.claude?.exactOpenAvailable));
    codex.title = companions.codex?.remediation || companions.codex?.version || 'Codex companion';
    claude.title = companions.claude?.remediation || companions.claude?.version || 'Claude Code companion';

    const tree = document.getElementById('workspace-tree');
    emptyNode(tree);
    let visibleRows = 0;
    let visibleProjects = 0;
    const selected = preferences.lastSelected || {};
    (payload.projects || []).forEach(project => {
        const projectMatches = workspaceMatches(project);
        const expanded = workspaceQuery ? true : workspaceExpanded.has(project.id);
        const matchingConversations = (expanded || workspaceQuery)
            ? (projectMatches
                ? (project.conversations || [])
                : (project.conversations || []).filter(item => workspaceMatches(project, item)))
            : [];
        if (!projectMatches && matchingConversations.length === 0) return;
        visibleProjects += 1;
        const projectNode = document.createElement('section');
        projectNode.className = 'workspace-project';
        projectNode.dataset.projectId = project.id;
        projectNode.classList.toggle('expanded', expanded);
        const header = document.createElement('button');
        header.type = 'button';
        header.className = 'workspace-project-button';
        header.dataset.projectButton = project.id;
        header.setAttribute('role', 'treeitem');
        header.setAttribute('aria-level', '1');
        header.setAttribute('aria-expanded', String(expanded));
        header.setAttribute('aria-label', `Open ${project.name} project Conductor in Activity Monitor`);
        header.title = `${project.name} Conductor · ${project.conversationCount} conversations`;
        const toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'workspace-project-toggle';
        toggle.dataset.projectToggle = project.id;
        toggle.setAttribute('aria-label', `${expanded ? 'Collapse' : 'Expand'} ${project.name} conversations`);
        toggle.setAttribute('aria-expanded', String(expanded));
        const chevron = document.createElement('span');
        chevron.className = 'workspace-chevron';
        chevron.textContent = '▶';
        toggle.appendChild(chevron);
        const title = document.createElement('span');
        title.className = 'workspace-project-title';
        const glyph = document.createElement('span');
        glyph.className = 'workspace-provider-glyph ' + project.provider;
        glyph.textContent = project.provider === 'claude' ? 'CL' : 'CX';
        const name = document.createElement('span');
        name.className = 'workspace-project-name';
        name.textContent = project.name;
        title.append(glyph, name);
        if (project.pinned) {
            const pin = document.createElement('span');
            pin.className = 'workspace-pin';
            pin.textContent = '◆';
            title.appendChild(pin);
        }
        const count = document.createElement('span');
        count.className = 'workspace-project-count';
        count.textContent = String(project.conversationCount || 0);
        header.append(title, count);
        const toggleProject = async () => {
            if (workspaceExpanded.has(project.id)) workspaceExpanded.delete(project.id);
            else workspaceExpanded.add(project.id);
            renderWorkspace(workspaceSnapshot);
            try {
                await workspaceUpdatePreferences({expandedProjectIds: Array.from(workspaceExpanded)}, false);
            } catch (error) { workspaceShowToast(String(error)); }
        };
        toggle.addEventListener('click', toggleProject);
        header.addEventListener('click', () => conversationHostOpenProject(project, header));
        const projectRow = document.createElement('div');
        projectRow.className = 'workspace-project-row';
        const brainButton = document.createElement('button');
        brainButton.type = 'button';
        brainButton.className = 'workspace-project-brain';
        brainButton.dataset.brainId = project.brainId || '';
        brainButton.textContent = 'Brain';
        brainButton.disabled = !project.brainId || project.brainStatus !== 'ready';
        brainButton.setAttribute('aria-label', `Open ${project.name} project Brain`);
        brainButton.title = project.brainId
            ? `Open project Brain · ${project.brainLifecycleState || project.brainStatus || 'ready'}`
            : `Project Brain ${project.brainErrorCode || 'is not ready'}`;
        brainButton.addEventListener('click', event => {
            event.stopPropagation();
            workspaceOpenProjectBrain(project);
        });
        projectRow.append(toggle, header, brainButton);
        const conversations = document.createElement('div');
        conversations.className = 'workspace-conversations';
        matchingConversations.forEach(conversation => {
            visibleRows += 1;
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'workspace-conversation';
            button.dataset.conversationId = conversation.id;
            button.dataset.provider = conversation.provider;
            button.dataset.projectId = project.id;
            button.setAttribute('role', 'treeitem');
            button.setAttribute('aria-level', String(Math.max(2, Math.min(6, Number(conversation.depth || 0) + 2))));
            button.style.setProperty('--thread-depth', String(Math.max(0, Math.min(4, Number(conversation.depth || 0)))));
            button.disabled = workspaceHostMode === 'native' && conversation.canOpen === false;
            button.title = workspaceHostMode === 'activity'
                ? 'Read this exact conversation inside Activity Monitor'
                : conversation.openLabel || 'Open exact conversation';
            if (selected.provider === conversation.provider && selected.projectId === project.id && selected.conversationId === conversation.id) {
                button.classList.add('selected');
            }
            const stateDot = document.createElement('span');
            stateDot.className = 'workspace-state-dot ' + statusClass(conversation.state);
            const threadCopy = document.createElement('span');
            threadCopy.className = 'workspace-thread-copy';
            const threadTitle = document.createElement('span');
            threadTitle.className = 'workspace-thread-title';
            threadTitle.textContent = conversation.title;
            const threadMeta = document.createElement('span');
            threadMeta.className = 'workspace-thread-meta';
            const activeClaudeHint = workspaceHostMode === 'native' && conversation.provider === 'claude' && conversation.state === 'active' && conversation.canOpen === false
                ? ' · use existing Terminal'
                : '';
            const stateLabel = conversation.state === 'active'
                ? 'Active now'
                : conversation.state === 'completed'
                    ? 'Complete'
                    : conversation.state === 'failed'
                        ? 'Needs attention'
                        : 'Ready';
            threadMeta.textContent = `${stateLabel}${activeClaudeHint}`;
            threadCopy.append(threadTitle, threadMeta);
            button.append(stateDot, threadCopy);
            button.addEventListener('click', () => workspaceOpenConversation(conversation.provider, conversation.id, button));
            conversations.appendChild(button);
        });
        projectNode.append(projectRow, conversations);
        tree.appendChild(projectNode);
    });
    if (visibleProjects === 0) {
        const message = document.createElement('div');
        message.className = 'workspace-tree-message';
        const warnings = payload.warnings || [];
        message.textContent = workspaceQuery
            ? 'No project or conversation matches this search.'
            : warnings[0] || 'No visible conversations yet. Use ＋ to choose projects.';
        tree.appendChild(message);
    }
}

async function workspaceOpenConversation(provider, conversationId, button) {
    if (!apiReady || button.disabled) return;
    if (workspaceHostMode === 'activity') {
        await conversationHostOpenConversation(provider, conversationId, button);
        return;
    }
    button.disabled = true;
    try {
        const result = bridgeJson(await pywebview.api.open_workspace_conversation(provider, conversationId));
        if (!result.ok) throw new Error(result.error || 'The companion could not open this conversation');
        workspaceShowToast(
            provider === 'codex'
                ? 'Open requested in Codex. Confirm the exact task in the native app.'
                : 'Resume requested in a visible Terminal. Confirm the exact Claude session there.'
        );
        await loadWorkspace(true);
    } catch (error) {
        workspaceShowToast(String(error));
        button.disabled = false;
    }
}

async function workspaceOpenProjectBrain(project) {
    if (!apiReady || !project?.brainId) return;
    try {
        workspaceShowToast(`Opening ${project.name} Brain…`);
        const brainTab = document.querySelector('.seg-btn[data-tab="brain"]');
        if (currentTab !== 'brain') brainTab.click();
        let brain = (lastBrainInventory?.brains || []).find(item => item.id === project.brainId);
        if (!brain) {
            await loadBrain(false);
            brain = (lastBrainInventory?.brains || []).find(item => item.id === project.brainId);
        }
        if (!brain || brain.canBrowse === false || brain.status !== 'connected') {
            throw new Error('This project Brain is not ready. AI Brain now shows the exact next action.');
        }
        await performBrainPrimaryAction(brain, {originView:brainView});
    } catch (error) {
        workspaceShowToast(String(error?.message || error));
    }
}

function workspaceChoiceCopy(item, provider) {
    const copy = document.createElement('span');
    copy.className = 'workspace-choice-copy';
    const name = document.createElement('span');
    name.className = 'workspace-choice-name';
    name.textContent = item.name;
    const meta = document.createElement('span');
    meta.className = 'workspace-choice-meta';
    const brainState = item.brainId
        ? ` · Brain ${item.brainLifecycleState || item.brainStatus || 'ready'}`
        : ` · Brain ${item.brainErrorCode || 'pending'}`;
    meta.textContent = `${item.conversationCount || 0} conversations · ${item.activeCount || 0} active${brainState}${provider === 'claude' && !item.directoryMapped ? ' · folder needed for inactive resume' : ''}`;
    copy.append(name, meta);
    return copy;
}

function renderWorkspaceChooser() {
    if (!workspaceSnapshot) return;
    const body = document.getElementById('workspace-dialog-body');
    emptyNode(body);
    const makeSection = (title, note) => {
        const section = document.createElement('section');
        section.className = 'workspace-chooser-section';
        const heading = document.createElement('div');
        heading.className = 'workspace-chooser-heading';
        const strong = document.createElement('strong');
        strong.textContent = title;
        const span = document.createElement('span');
        span.textContent = note;
        heading.append(strong, span);
        section.appendChild(heading);
        body.appendChild(section);
        return section;
    };
    const codexSection = makeSection('Codex projects', 'Exact sidebar assignments and order');
    const codexItems = workspaceSnapshot.availableCodexProjects || [];
    if (!codexItems.length) {
        const empty = document.createElement('div'); empty.className = 'workspace-choice-empty'; empty.textContent = 'No validated Codex project metadata is available.'; codexSection.appendChild(empty);
    }
    codexItems.forEach(item => {
        const row = document.createElement('label'); row.className = 'workspace-choice';
        const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = Boolean(item.selected);
        checkbox.addEventListener('change', async () => {
            checkbox.disabled = true;
            try {
                const selected = new Set(codexItems.filter(project => project.selected).map(project => project.id));
                if (checkbox.checked) selected.add(item.id); else selected.delete(item.id);
                const value = selected.size === codexItems.length ? null : Array.from(selected);
                await workspaceUpdatePreferences({visibleCodexProjectIds: value});
            } catch (error) { workspaceShowToast(String(error)); checkbox.checked = !checkbox.checked; }
        });
        const spacer = document.createElement('span');
        row.append(checkbox, workspaceChoiceCopy(item, 'codex'), spacer);
        codexSection.appendChild(row);
    });
    const claudeSection = makeSection('Claude Code projects', 'Explicitly saved · metadata-only listing');
    const claudeItems = workspaceSnapshot.availableClaudeProjects || [];
    if (!claudeItems.length) {
        const empty = document.createElement('div'); empty.className = 'workspace-choice-empty'; empty.textContent = 'No private local Claude project metadata was detected.'; claudeSection.appendChild(empty);
    }
    claudeItems.forEach(item => {
        const row = document.createElement('div'); row.className = 'workspace-choice';
        const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = Boolean(item.saved); checkbox.setAttribute('aria-label', `Show ${item.name}`);
        checkbox.addEventListener('change', async () => {
            checkbox.disabled = true;
            try {
                const result = bridgeJson(await pywebview.api.set_claude_project_saved(item.id, checkbox.checked));
                if (!result.ok) throw new Error(result.error || 'Claude project update failed');
                await loadWorkspace(true);
            } catch (error) { workspaceShowToast(String(error)); checkbox.checked = !checkbox.checked; }
        });
        const folder = document.createElement('button'); folder.type = 'button'; folder.className = 'workspace-folder-button' + (item.directoryMapped ? ' mapped' : ''); folder.textContent = item.directoryMapped ? 'Folder linked' : 'Choose folder';
        folder.addEventListener('click', async () => {
            folder.disabled = true;
            try {
                const result = bridgeJson(await pywebview.api.choose_claude_project_directory(item.id));
                if (!result.ok) {
                    if (result.code !== 'folder_picker_cancelled') throw new Error(result.error || 'Folder did not match this Claude project');
                    return;
                }
                workspaceShowToast('Exact Claude project folder linked.');
                await loadWorkspace(true);
            } catch (error) { workspaceShowToast(String(error)); } finally { folder.disabled = false; }
        });
        row.append(checkbox, workspaceChoiceCopy(item, 'claude'), folder);
        claudeSection.appendChild(row);
    });
}

// Wait for pywebview API to be ready
window.addEventListener('pywebviewready', () => {
    apiReady = true;
    loadWorkspace(true);
    scheduleRefresh(0);
});

document.getElementById('workspace-collapse').addEventListener('click', async () => {
    const preferences = workspaceSnapshot?.preferences || {};
    try { await workspaceUpdatePreferences({railCollapsed: !preferences.railCollapsed}); }
    catch (error) { workspaceShowToast(String(error)); }
});

document.getElementById('workspace-refresh').addEventListener('click', () => loadWorkspace(true));
document.getElementById('workspace-search').addEventListener('input', event => {
    workspaceQuery = String(event.target.value || '').trim().toLowerCase();
    if (workspaceSnapshot) renderWorkspace(workspaceSnapshot);
});

document.querySelectorAll('.workspace-host-mode').forEach(button => {
    button.addEventListener('click', () => setWorkspaceHostMode(button.dataset.hostMode));
});

document.getElementById('conversation-host-close').addEventListener('click', conversationHostClose);
document.getElementById('conversation-host-send').addEventListener('click', conversationHostSubmit);
document.getElementById('conversation-host-refresh').addEventListener('click', async () => {
    try { await conversationHostRefresh(); }
    catch (error) { conversationHostSetStatus(String(error?.message || error), 'failed'); }
});
document.getElementById('conversation-host-native-open').addEventListener('click', async () => {
    const target = conversationHostContext?.conversationId
        ? {provider:conversationHostContext.provider, id:conversationHostContext.conversationId}
        : conversationHostContext?.destination;
    if (!target) return;
    try { await conversationHostOpenNative(target.provider, target.id); }
    catch (error) { conversationHostSetStatus(String(error?.message || error), 'failed'); }
});
document.getElementById('conversation-host-destination').addEventListener('click', () => {
    const target = conversationHostContext?.destination;
    if (target) conversationHostOpenConversation(target.provider, target.id, document.getElementById('conversation-host-destination'));
});
document.querySelectorAll('.conversation-host-route-btn').forEach(button => {
    button.addEventListener('click', () => {
        conversationHostRouteKind = button.dataset.routeKind === 'powerswarm' ? 'powerswarm' : 'conductor';
        document.querySelectorAll('.conversation-host-route-btn').forEach(item => {
            const active = item.dataset.routeKind === conversationHostRouteKind;
            item.classList.toggle('active', active);
            item.setAttribute('aria-pressed', String(active));
        });
        conversationHostSyncMappedDestination();
        conversationHostSetStatus(
            conversationHostRouteKind === 'powerswarm'
                ? 'PowerSwarm will reuse the verified owner or create exactly one governed project task.'
                : 'Conductor will route to the verified existing owner or create exactly one project task.'
        );
        document.getElementById('conversation-host-input').focus();
    });
});
document.getElementById('conversation-host-input').addEventListener('keydown', event => {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
        event.preventDefault();
        conversationHostSubmit();
    }
});

document.querySelectorAll('.workspace-provider').forEach(button => {
    button.addEventListener('click', async () => {
        const provider = button.dataset.provider;
        const filters = {...(workspaceSnapshot?.preferences?.providerFilters || {codex:true,claude:true})};
        filters[provider] = filters[provider] === false;
        try { await workspaceUpdatePreferences({providerFilters: filters}); }
        catch (error) { workspaceShowToast(String(error)); }
    });
});

function closeWorkspaceChooser() {
    document.getElementById('workspace-dialog').hidden = true;
    document.getElementById('workspace-manage').focus();
}
document.getElementById('workspace-manage').addEventListener('click', () => {
    document.getElementById('workspace-dialog').hidden = false;
    renderWorkspaceChooser();
    document.getElementById('workspace-dialog-close').focus();
});
document.getElementById('workspace-dialog-close').addEventListener('click', closeWorkspaceChooser);
document.getElementById('workspace-dialog').addEventListener('click', event => {
    if (event.target.id === 'workspace-dialog') closeWorkspaceChooser();
});

document.getElementById('workspace-tree').addEventListener('keydown', event => {
    const controls = Array.from(document.querySelectorAll(
        '.workspace-project-button, .workspace-conversation:not(:disabled)'
    )).filter(node => node.offsetParent !== null);
    if (!controls.length) return;
    const current = controls.indexOf(document.activeElement);
    let next = current;
    if (event.key === 'ArrowDown') next = Math.min(controls.length - 1, Math.max(0, current + 1));
    else if (event.key === 'ArrowUp') next = Math.max(0, current < 0 ? 0 : current - 1);
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = controls.length - 1;
    else if (event.key === 'ArrowRight' && document.activeElement?.dataset.projectButton) {
        const project = document.activeElement.closest('.workspace-project');
        if (!project.classList.contains('expanded')) project.querySelector('.workspace-project-toggle')?.click();
        event.preventDefault();
        return;
    } else if (event.key === 'ArrowLeft') {
        const project = document.activeElement?.closest('.workspace-project');
        if (document.activeElement?.dataset.projectButton && project?.classList.contains('expanded')) {
            project.querySelector('.workspace-project-toggle')?.click();
        } else if (project) {
            project.querySelector('.workspace-project-button')?.focus();
        }
        event.preventDefault();
        return;
    } else return;
    controls[next]?.focus();
    event.preventDefault();
});

let workspaceResizeStart = null;
const workspaceResizer = document.getElementById('workspace-resizer');
workspaceResizer.addEventListener('pointerdown', event => {
    if (document.getElementById('workspace-shell').classList.contains('rail-collapsed')) return;
    workspaceResizeStart = {x:event.clientX, width:Number(workspaceSnapshot?.preferences?.railWidth || 252)};
    workspaceResizer.classList.add('dragging');
    workspaceResizer.setPointerCapture(event.pointerId);
    event.preventDefault();
});
workspaceResizer.addEventListener('pointermove', event => {
    if (!workspaceResizeStart) return;
    const width = Math.max(220, Math.min(380, workspaceResizeStart.width + event.clientX - workspaceResizeStart.x));
    document.getElementById('workspace-shell').style.setProperty('--rail-width', width + 'px');
    document.documentElement.style.setProperty('--rail-width', width + 'px');
});
workspaceResizer.addEventListener('pointerup', async event => {
    if (!workspaceResizeStart) return;
    const width = Math.max(220, Math.min(380, workspaceResizeStart.width + event.clientX - workspaceResizeStart.x));
    workspaceResizeStart = null;
    workspaceResizer.classList.remove('dragging');
    try { await workspaceUpdatePreferences({railWidth: Math.round(width)}); }
    catch (error) { workspaceShowToast(String(error)); }
});

document.addEventListener('keydown', event => {
    const conversationPanel = document.getElementById('conversation-host');
    if (event.key === 'Escape' && conversationPanel && !conversationPanel.hidden) {
        event.preventDefault();
        conversationHostClose();
        return;
    }
    if (event.key === 'Escape' && !document.getElementById('disk-cleanup-sheet').hidden) {
        event.preventDefault();
        closeDiskCleanup();
        return;
    }
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        const shell = document.getElementById('workspace-shell');
        if (shell.classList.contains('rail-collapsed')) document.getElementById('workspace-collapse').click();
        setTimeout(() => document.getElementById('workspace-search').focus(), 0);
    }
    if (event.key === 'Escape' && !document.getElementById('network-info-panel').hidden) {
        event.preventDefault();
        closeNetworkInfo(true);
    } else if (event.key === 'Escape' && !document.getElementById('internet-optimizer').hidden) {
        event.preventDefault();
        closeInternetOptimizer(true);
    }
    if (event.key === 'Escape' && !document.getElementById('workspace-dialog').hidden) closeWorkspaceChooser();
});

document.querySelectorAll('.seg-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const nextTab = btn.dataset.tab;
        const leavingNetwork = currentTab === 'network' && nextTab !== 'network';
        const enteringNetwork = currentTab !== 'network' && nextTab === 'network';
        if (currentTab === 'brain' && nextTab !== 'brain') closeBrainBrowser({restoreFocus:false});
        if (leavingNetwork) {
            networkLifecycleGeneration += 1;
            networkRecoveryRequestSequence += 1;
            closeInternetOptimizer(false);
            closeNetworkInfo(false);
            cancelNetworkRecoveryWatcher();
            networkDiscoveryStopPromise = stopNetworkDiscovery();
        }
        if (currentTab === 'disk' && nextTab !== 'disk') closeDiskCleanup(false);
        if (currentTab === 'powerswarm') closePowerSwarmWorker();
        document.querySelectorAll('.seg-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        currentTab = nextTab;
        if (enteringNetwork) networkLifecycleGeneration += 1;
        document.getElementById(currentTab + '-tab').classList.add('active');
        if (currentTab === 'energy') showEnergyLoading();
        document.getElementById('search').placeholder = currentTab === 'agents' ? 'Search AI processes' : currentTab === 'powerswarm' ? 'Filter PowerSwarm' : currentTab === 'brain' ? 'Filter brains' : currentTab === 'network' ? 'Filter devices' : currentTab === 'guard' ? 'KE Guard is read-only' : 'Search';
        // Redraw graphs from history after tab becomes visible
        setTimeout(() => {
            if (currentTab === 'network' && netHistory.sent.length > 0) redrawNetGraph();
            if (currentTab === 'cpu' && cpuHistory.user.length > 0) renderCpuBars();
            if (currentTab === 'energy' && energyHistory.length > 0) renderEnergyBars();
            if (currentTab === 'powerswarm') loadPowerSwarm(false);
            if (currentTab === 'brain') loadBrain(false);
            if (currentTab === 'dispatch') loadDispatchState();
            if (currentTab === 'guard') loadGuardStatus();
            if (currentTab === 'network') {
                startNetworkDiscovery();
                resumeNetworkRecoveryAfterSettings();
            }
            scheduleRefresh(0);
        }, 50);
    });
});

document.getElementById('search').addEventListener('input', e => {
    searchFilter = e.target.value.toLowerCase();
    if (currentTab === 'agents' && lastAgentSnapshot) renderAiProcesses(lastAgentSnapshot);
    if (currentTab === 'powerswarm' && lastPowerSwarmSnapshot) renderPowerSwarm(lastPowerSwarmSnapshot);
    if (currentTab === 'brain' && lastBrainInventory) renderBrain(lastBrainInventory);
    if (currentTab === 'network' && lastNetworkSnapshot) renderNetworkSnapshot(lastNetworkSnapshot);
});

document.querySelectorAll('[data-network-filter]').forEach(button => {
    button.addEventListener('click', () => {
        networkDeviceFilter = button.dataset.networkFilter;
        document.querySelectorAll('[data-network-filter]').forEach(item => item.classList.toggle('active', item === button));
        if (lastNetworkSnapshot) renderNetworkDeviceList(lastNetworkSnapshot);
    });
});

document.getElementById('internet-optimizer-btn').addEventListener('click', openInternetOptimizer);
document.getElementById('internet-optimizer-close').addEventListener('click', () => closeInternetOptimizer(true));
document.getElementById('internet-rerun-btn').addEventListener('click', analyzeInternetConnection);
document.getElementById('internet-quality-btn').addEventListener('click', measureInternetQuality);
document.getElementById('internet-router-btn').addEventListener('click', () => performInternetOptimizerAction('open-router-settings'));
document.getElementById('internet-diagnostics-btn').addEventListener('click', () => performInternetOptimizerAction('wireless-diagnostics'));
document.getElementById('internet-wifi-settings-btn').addEventListener('click', () => performInternetOptimizerAction('open-wifi-settings'));
document.getElementById('network-scan-btn').addEventListener('click', requestNetworkScan);
document.getElementById('network-link-toggle').addEventListener('click', toggleKeLink);
document.getElementById('network-recovery-btn').addEventListener('click', () => repairNetworkConnection(false));
document.getElementById('network-pair-code-btn').addEventListener('click', beginKeLinkPairing);
document.getElementById('network-pair-btn').addEventListener('click', pairSelectedNetworkDevice);
document.getElementById('network-message-btn').addEventListener('click', sendSelectedNetworkMessage);
document.getElementById('network-message-input').addEventListener('input', event => {
    if (pendingNetworkMessage && event.target.value !== pendingNetworkMessage.body) pendingNetworkMessage = null;
});
document.querySelectorAll('[data-network-info]').forEach(button => {
    button.addEventListener('click', event => {
        event.stopPropagation();
        toggleNetworkInfo(button);
    });
});
document.getElementById('network-info-close').addEventListener('click', () => closeNetworkInfo(true));
document.addEventListener('click', event => {
    const panel = document.getElementById('network-info-panel');
    if (panel.hidden || panel.contains(event.target)) return;
    if ([...document.querySelectorAll('[data-network-info]')].some(button => button.contains(event.target))) return;
    closeNetworkInfo(false);
});
window.addEventListener('blur', noteNetworkRecoveryDeparture);
window.addEventListener('focus', noteNetworkRecoveryReturn);
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') noteNetworkRecoveryDeparture();
    else if (document.visibilityState === 'visible') noteNetworkRecoveryReturn();
});
window.addEventListener('beforeunload', () => {
    internetOptimizerGeneration += 1;
    cancelNetworkRecoveryWatcher();
});

document.getElementById('agents-powerswarm-open').addEventListener('click', () => openPowerSwarmSubview());
document.getElementById('powerswarm-back').addEventListener('click', () => closePowerSwarmSubview());
document.getElementById('powerswarm-worker-close').addEventListener('click', () => closePowerSwarmWorker());
document.getElementById('powerswarm-latest').addEventListener('click', async () => {
    selectedPowerSwarmRunId = null;
    closePowerSwarmWorker();
    await loadPowerSwarm(true);
});

document.getElementById('agents-core-inspector-close').addEventListener('click', () => closeAgentCoreInspector());
document.getElementById('memory-diagnostics-run').addEventListener('click', () => runMemoryDiagnostics());
document.getElementById('memory-diagnostics-copy').addEventListener('click', () => copyMemoryDiagnosticReport());
document.getElementById('memory-diagnostics-retry').addEventListener('click', () => {
    if (memoryRetryTarget === 'base') scheduleRefresh(0);
    else runMemoryDiagnostics();
});
document.getElementById('disk-cleanup-open').addEventListener('click', openDiskCleanup);
document.getElementById('disk-cleanup-close').addEventListener('click', () => closeDiskCleanup());
document.getElementById('disk-cleanup-scan').addEventListener('click', startDiskCleanupScan);
document.getElementById('disk-cleanup-cancel').addEventListener('click', cancelDiskCleanupScan);
document.getElementById('disk-cleanup-reveal').addEventListener('click', revealDiskCleanupSelection);
document.querySelectorAll('[data-disk-cleanup-destination]').forEach(button => {
    button.addEventListener('click', () => openDiskCleanupDestination(button.dataset.diskCleanupDestination));
});
document.querySelectorAll('[data-disk-cleanup-filter]').forEach(button => {
    button.addEventListener('click', () => {
        diskCleanupFilter = button.dataset.diskCleanupFilter;
        document.querySelectorAll('[data-disk-cleanup-filter]').forEach(item => item.classList.toggle('active', item === button));
        renderDiskCleanupCandidates();
    });
});
document.getElementById('disk-cleanup-select-top').addEventListener('click', () => {
    diskCleanupSelected.clear();
    (diskCleanupResult?.reviewCandidates || [])
        .filter(item => (diskCleanupCategory === 'all' || item.category === diskCleanupCategory) && String(item.riskClass || '').toUpperCase() === 'SAFE')
        .slice(0, DISK_CLEANUP_MAX_SELECTION)
        .forEach(item => diskCleanupSelected.add(item.id));
    renderDiskCleanupCandidates();
});
document.getElementById('disk-cleanup-clear').addEventListener('click', () => {
    diskCleanupSelected.clear();
    renderDiskCleanupCandidates();
});
document.getElementById('disk-cleanup-sheet').addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const controls = Array.from(event.currentTarget.querySelectorAll('button:not(:disabled), input:not(:disabled)')).filter(node => node.offsetParent !== null);
    if (!controls.length) return;
    const first = controls[0], last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
});

document.querySelectorAll('th[data-key]').forEach(th => {
    th.addEventListener('click', () => {
        const table = th.closest('table');
        const tabId = table.id.replace('-table','');
        const tabKey = tabId === 'mem' ? 'memory' : tabId === 'net' ? 'network' : tabId;
        const key = th.dataset.key;
        const st = sortState[tabKey];
        if (st.key === key) st.dir = st.dir === 'desc' ? 'asc' : 'desc';
        else { st.key = key; st.dir = 'desc'; }
        table.querySelectorAll('th').forEach(h => h.classList.remove('sort-asc','sort-desc'));
        th.classList.add('sort-' + st.dir);
    });
});

function bridgeJson(raw) {
    if (raw && typeof raw === 'object') return raw;
    return JSON.parse(String(raw || '{}'));
}

function emptyNode(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
}

function statusClass(value) {
    return String(value || 'unknown').toLowerCase().replaceAll(' ', '-');
}

function pill(value) {
    const element = document.createElement('span');
    element.className = 'status-pill ' + statusClass(value);
    element.textContent = String(value || 'unknown');
    return element;
}

function featureButton(label, handler, className = '') {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'feature-btn ' + className;
    button.textContent = label;
    button.addEventListener('click', async () => {
        button.disabled = true;
        try { await handler(); } finally { button.disabled = false; }
    });
    return button;
}

function clearSharedSearch(placeholder) {
    const search = document.getElementById('search');
    search.value = '';
    searchFilter = '';
    search.placeholder = placeholder;
}

function openPowerSwarmSubview() {
    document.querySelectorAll('.seg-btn').forEach(button => button.classList.toggle('active', button.dataset.tab === 'agents'));
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    currentTab = 'powerswarm';
    document.getElementById('powerswarm-tab').classList.add('active');
    clearSharedSearch('Filter PowerSwarm');
    loadPowerSwarm(false);
    scheduleRefresh(0);
}

function closePowerSwarmSubview() {
    closePowerSwarmWorker();
    selectedPowerSwarmRunId = null;
    document.querySelectorAll('.seg-btn').forEach(button => button.classList.toggle('active', button.dataset.tab === 'agents'));
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    currentTab = 'agents';
    document.getElementById('agents-tab').classList.add('active');
    clearSharedSearch('Search AI processes');
    scheduleRefresh(0);
}

function stalePowerSwarmProjection(snapshot, errorCode, observedAt) {
    const source = snapshot && typeof snapshot === 'object' ? snapshot : {};
    const boundedText = (value, limit) => typeof value === 'string' && value.trim() ? value.trim().slice(0,limit) : null;
    const safeIdentifier = (value, limit = 80) => {
        const token = boundedText(value,limit);
        return token && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(token) ? token : null;
    };
    const RUN_STATES = new Set([
        'planned','preflight','worktree-ready','coordinator-starting','admitted-waiting-for-worker',
        'worker-live','speed-dev','bug-sweep','review-ready','queued','running','active','checkpoint',
        'verified','succeeded','completed','failed','cancelled','stale','no-runs','unavailable','unknown',
    ]);
    const WORKER_STATES = new Set([...RUN_STATES,'not-started','starting','timed-out','skipped']);
    const HIERARCHY_STATES = new Set([...WORKER_STATES,'mixed','empty']);
    const STAGE_STATES = new Set(['speed-dev','bug-sweep','director','unknown']);
    const RUNTIME_STATES = new Set(['grok-build','grok-code','grokcode','grok','unknown']);
    const CHECK_STATES = new Set(['not-started','queued','running','succeeded','completed','failed','cancelled','timed-out','skipped']);
    const TOOL_STATES = new Set(['not-started','queued','starting','running','active','idle','succeeded','completed','failed','cancelled','unavailable']);
    const NESTED_STATES = new Set(['none','observed','invalid','truncated']);
    const HIERARCHY_KINDS = new Set(['run','subdirector','worker']);
    const PARENT_ROLES = new Set(['owner','director','coordinator','worker','reviewer','operator','unknown']);
    const PARENT_SOURCES = new Set(['binding-ledger','capture-parent','powerswarm-binding','unknown']);
    const TERMINAL_REASON_CODES = new Set([
        'run-failed-before-worker-admission','run-cancelled-before-worker-admission','worker-terminal-reason-recorded',
    ]);
    const WORKER_ERROR_CODES = new Set(['worker-attempt-failed']);
    const PARENT_OBSERVER_CODES = new Set([
        'observer-bindings-root-untrusted','observer-binding-invalid','observer-binding-not-found',
        'observer-binding-size','observer-binding-changed','observer-binding-json','observer-json-invalid',
        'observer-access-denied',
    ]);
    const NESTED_ERROR_CODES = new Set([
        'observer-nested-plan','observer-nested-plan-not-found','observer-nested-plan-size',
        'observer-nested-plan-changed','observer-nested-plan-json','observer-nested-contract-invalid',
        'observer-nested-topology-invalid','observer-nested-plan-mismatch','observer-nested-branches-invalid',
        'observer-nested-branch-invalid','observer-nested-leaves-invalid','observer-nested-ownership-invalid',
        'observer-nested-targets-truncated','observer-nested-branches-truncated',
        'observer-nested-leaves-truncated','observer-nested-invalid','observer-json-invalid',
        'observer-access-denied',
    ]);
    const enumValue = (value, allowed, fallback = null) => {
        if (typeof value !== 'string') return fallback;
        const candidate = value.trim().toLowerCase();
        return candidate.length <= 80 && allowed.has(candidate) ? candidate : fallback;
    };
    const timestamp = value => {
        // Numeric epochs intentionally mirror the observer: finite seconds,
        // or milliseconds at 1e11 and above. Strings must carry an explicit
        // RFC3339 zone; a host-local interpretation is never permitted.
        const canonical = milliseconds => {
            if (!Number.isFinite(milliseconds)) return null;
            try {
                const parsed = new Date(milliseconds);
                if (!Number.isFinite(parsed.getTime())) return null;
                const iso = parsed.toISOString();
                return /^(?!0000)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(iso) ? iso : null;
            } catch (_) { return null; }
        };
        if (typeof value === 'number') {
            if (!Number.isFinite(value)) return null;
            const milliseconds = Math.abs(value) >= 100000000000 ? value : value * 1000;
            return canonical(milliseconds);
        }
        if (typeof value !== 'string') return null;
        const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/i.exec(value.trim());
        if (!match) return null;
        const year = Number(match[1]);
        const month = Number(match[2]);
        const day = Number(match[3]);
        const hour = Number(match[4]);
        const minute = Number(match[5]);
        const second = Number(match[6]);
        const millisecond = Number((match[7] || '').slice(0,3).padEnd(3,'0'));
        const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
        const days = [31,leap ? 29 : 28,31,30,31,30,31,31,30,31,30,31];
        const offsetHour = match[8].toUpperCase() === 'Z' ? 0 : Number(match[10]);
        const offsetMinute = match[8].toUpperCase() === 'Z' ? 0 : Number(match[11]);
        if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 || day > days[month-1] || hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59) return null;
        // RFC3339 -00:00 means an unknown local offset, so it cannot prove an instant.
        if (match[9] === '-' && offsetHour === 0 && offsetMinute === 0) return null;
        const local = new Date(0);
        local.setUTCFullYear(year,month-1,day);
        local.setUTCHours(hour,minute,second,millisecond);
        const direction = match[8].toUpperCase() === 'Z' ? 0 : (match[9] === '-' ? -1 : 1);
        const milliseconds = local.getTime() - direction * (offsetHour * 60 + offsetMinute) * 60000;
        return canonical(milliseconds);
    };
    const integer = (value, maximum = 2147483647) => {
        const number = Number(value);
        return Number.isSafeInteger(number) && number >= 0 && number <= maximum ? number : 0;
    };
    const liveStates = new Set(['active','running','worker-live','coordinator-starting','admitted-waiting-for-worker','speed-dev','bug-sweep','starting']);
    const staleState = (value, allowed, fallback = 'unknown') => {
        const state = enumValue(value,allowed,fallback);
        return liveStates.has(state) ? 'stale' : state;
    };
    const staleRunState = value => staleState(value,RUN_STATES);
    const staleWorkerState = value => staleState(value,WORKER_STATES);
    const staleRecordedWorkerState = value => staleState(value,WORKER_STATES,null);
    const staleHierarchyState = value => staleState(value,HIERARCHY_STATES);
    const cloneHierarchy = (node, depth = 0) => {
        if (!node || typeof node !== 'object' || depth > 3) return null;
        const children = Array.isArray(node.children) ? node.children.slice(0,128).map(child => cloneHierarchy(child,depth+1)).filter(Boolean) : [];
        return {
            kind:enumValue(node.kind,HIERARCHY_KINDS),
            id:boundedText(node.id,128) || 'unknown-worker',
            aim:boundedText(node.aim,500),
            state:staleHierarchyState(node.state),
            processAlive:false,
            children,
        };
    };
    const workers = (Array.isArray(source.workers) ? source.workers : []).slice(0,128).filter(worker => worker && typeof worker === 'object').map(worker => ({
        id:boundedText(worker.id,128) || 'unknown-worker',
        aim:boundedText(worker.aim,500),
        state:staleWorkerState(worker.state),
        recordedState:staleRecordedWorkerState(worker.recordedState),
        terminalReasonCode:enumValue(worker.terminalReasonCode,TERMINAL_REASON_CODES),
        stage:enumValue(worker.stage,STAGE_STATES,'unknown'),
        attempt:integer(worker.attempt,1000000),
        attemptCount:integer(worker.attemptCount,64),
        attemptsTruncated:Boolean(worker.attemptsTruncated),
        pid:null,
        processAlive:false,
        startedAt:timestamp(worker.startedAt),
        endedAt:timestamp(worker.endedAt),
        branch:boundedText(worker.branch,300),
        baseRevision:safeIdentifier(worker.baseRevision),
        headRevision:safeIdentifier(worker.headRevision),
        killCheck:enumValue(worker.killCheck,CHECK_STATES),
        toolState:enumValue(worker.toolState,TOOL_STATES),
        errorCode:enumValue(worker.errorCode,WORKER_ERROR_CODES),
    }));
    const selectedSource = source.selectedRun && typeof source.selectedRun === 'object' ? source.selectedRun : null;
    const parentSource = selectedSource?.parent && typeof selectedSource.parent === 'object' ? selectedSource.parent : null;
    const threadId = boundedText(parentSource?.threadId,36);
    const parent = parentSource && /^[0-9a-f-]{36}$/i.test(threadId || '') ? {
        host:'codex',
        threadId,
        turnId:safeIdentifier(parentSource.turnId),
        title:boundedText(parentSource.title,160) || 'Codex parent task',
        agentName:boundedText(parentSource.agentName,100) || 'Codex parent',
        agentRole:enumValue(parentSource.agentRole,PARENT_ROLES,'unknown'),
        exact:Boolean(parentSource.exact),
        source:enumValue(parentSource.source,PARENT_SOURCES,'unknown'),
        codexUrl:'codex://threads/'+threadId,
    } : null;
    const selectedRun = selectedSource ? {
        id:boundedText(selectedSource.id,64),
        planId:safeIdentifier(selectedSource.planId,100),
        objective:boundedText(selectedSource.objective,1000) || 'PowerSwarm run',
        product:safeIdentifier(selectedSource.product,100),
        state:staleRunState(selectedSource.state),
        createdAt:timestamp(selectedSource.createdAt),
        updatedAt:timestamp(selectedSource.updatedAt),
        coordinatorPid:null,
        coordinatorAlive:false,
        requestedWidth:integer(selectedSource.requestedWidth,32768) || null,
        runtime:enumValue(selectedSource.runtime,RUNTIME_STATES,'unknown'),
        providerId:null,
        modelId:null,
        parent,
        parentExact:Boolean(parent?.exact),
        parentObserverCode:enumValue(selectedSource.parentObserverCode,PARENT_OBSERVER_CODES),
    } : null;
    const recentRuns = (Array.isArray(source.recentRuns) ? source.recentRuns : []).slice(0,12).filter(run => run && typeof run === 'object').map(run => ({
        id:boundedText(run.id,64),
        state:staleRunState(run.state),
        updatedAt:timestamp(run.updatedAt),
        coordinatorAlive:false,
        active:false,
        workerCount:integer(run.workerCount,128),
        workersTruncated:Boolean(run.workersTruncated),
        objective:boundedText(run.objective,160) || 'PowerSwarm run',
    }));
    const sourceCounts = source.counts && typeof source.counts === 'object' ? source.counts : {};
    const counts = {
        total:integer(sourceCounts.total,128),
        live:0,
        queued:integer(sourceCounts.queued,128),
        verified:integer(sourceCounts.verified,128),
        failed:integer(sourceCounts.failed,128),
        stale:workers.filter(worker => worker.state === 'stale').length,
    };
    const nestedSource = source.nested && typeof source.nested === 'object' ? source.nested : {};
    const nested = {
        state:nestedSource.state == null ? 'none' : enumValue(nestedSource.state,NESTED_STATES,'invalid'),
        logicalDepth:integer(nestedSource.logicalDepth,3) || 1,
        processSpawnDepth:integer(nestedSource.processSpawnDepth,1) || 1,
        rootOnlyProcessSpawn:Boolean(nestedSource.rootOnlyProcessSpawn),
        planId:safeIdentifier(nestedSource.planId,100),
        subdirectorCount:integer(nestedSource.subdirectorCount,64),
        errorCode:enumValue(nestedSource.errorCode,NESTED_ERROR_CODES),
        truncatedBranches:Boolean(nestedSource.truncatedBranches),
        truncatedLeaves:Boolean(nestedSource.truncatedLeaves),
    };
    const truncationSource = source.truncation && typeof source.truncation === 'object' ? source.truncation : {};
    const truncation = {
        any:Boolean(truncationSource.any),
        scannedEntries:Boolean(truncationSource.scannedEntries),
        records:Boolean(truncationSource.records),
        targets:Boolean(truncationSource.targets),
        attempts:Boolean(truncationSource.attempts),
        nestedBranches:Boolean(truncationSource.nestedBranches),
        nestedLeaves:Boolean(truncationSource.nestedLeaves),
        processes:Boolean(truncationSource.processes),
    };
    const code = ['powerswarm-bridge-unavailable','powerswarm-agents-snapshot-unavailable'].includes(errorCode) ? errorCode : 'powerswarm-bridge-unavailable';
    return {
        ok:Boolean(source.ok),
        schemaVersion:'ke.activity-monitor-powerswarm.v1',
        state:selectedRun ? 'stale' : 'unavailable',
        installed:Boolean(source.installed),
        stale:true,
        error:code,
        errorCode:code,
        observedAt:timestamp(observedAt) || timestamp(source.observedAt),
        generatedAt:timestamp(source.generatedAt),
        selectedRun,
        counts,
        workers,
        hierarchy:cloneHierarchy(source.hierarchy),
        nested,
        recentRuns,
        invalidRunCount:integer(source.invalidRunCount,512),
        processes:[],
        truncation,
        privacy:{mode:'metadata-only',outputsRead:false,mutations:false},
    };
}

function staleAgentSnapshotProjection(snapshot, observedAt) {
    const source = snapshot && typeof snapshot === 'object' ? snapshot : {};
    return {
        ...source,
        schemaVersion:source.schemaVersion || 'ke.activity-monitor-agents.v1',
        stale:true,
        error:'Agents observer unavailable',
        cpu:{...(source.cpu || {ok:false,snapshot:null,error:'CPU observer unavailable'}),stale:true},
        gpu:{...(source.gpu || {ok:false,snapshot:null,error:'GPU observer unavailable'}),stale:true},
        powerSwarm:stalePowerSwarmProjection(source.powerSwarm,'powerswarm-agents-snapshot-unavailable',observedAt),
        aiProcesses:(Array.isArray(source.aiProcesses) ? source.aiProcesses : []).filter(process => !process?.powerSwarmRun && !String(process?.category || '').startsWith('PowerSwarm')),
    };
}

function powerSwarmRuntimeTruth(run, stale = false) {
    if (stale || !run || typeof run !== 'object') {
        return {providerId:null,modelId:null,known:false,label:'Provider/model unknown'};
    }
    const providerId = typeof run.providerId === 'string' ? run.providerId.trim().toLowerCase() : null;
    const modelId = typeof run.modelId === 'string' ? run.modelId.trim().toLowerCase() : null;
    if (providerId === 'xai' && modelId === 'grok-4.6') {
        return {providerId:'xai',modelId:'grok-4.6',known:true,label:'xAI · Grok 4.6'};
    }
    return {providerId:null,modelId:null,known:false,label:'Provider/model unknown'};
}

function powerSwarmErrorText(code) {
    const messages = {
        'observer-platform-unsupported':'Secure local observation is unavailable.',
        'observer-runs-root-untrusted':'PowerSwarm history could not be verified.',
        'observer-runs-scan-failed':'PowerSwarm history could not be read.',
        'observer-run-id-invalid':'That PowerSwarm run is unavailable.',
        'observer-run-not-found':'That PowerSwarm run was not found.',
        'observer-run-outside-limit':'That run is outside this limited view.',
        'observer-worker-id-invalid':'That worker is unavailable.',
        'observer-worker-not-found':'That worker was not found.',
        'observer-worker-outside-limit':'That worker is outside this limited view.',
        'observer-worker-detail-failed':'Worker detail is unavailable.',
        'worker-attempt-failed':'Attempt failed.',
        'kill-check-failed':'Check failed.',
        'powerswarm-bridge-unavailable':'PowerSwarm is unavailable.',
        'powerswarm-agents-snapshot-unavailable':'PowerSwarm status is stale.'
    };
    return messages[String(code || '')] || 'PowerSwarm is unavailable.';
}

function powerSwarmTone(state, alive = false) {
    const value = String(state || 'unknown').toLowerCase();
    if (alive || value === 'running' || value === 'active') return 'running';
    if (['verified','review-ready','completed','succeeded','checkpoint'].includes(value)) return value === 'review-ready' ? 'review-ready' : 'verified';
    if (['failed','cancelled','invalid'].includes(value)) return value;
    if (['queued','not-started','worktree-ready'].includes(value)) return 'queued';
    if (value === 'stale') return 'stale';
    return value === 'mixed' ? 'mixed' : 'offline';
}

function powerSwarmWorkerButton(worker) {
    if (!worker) return '';
    const process = worker.processAlive ? 'PID '+worker.pid+' · live' : worker.pid ? 'PID '+worker.pid+' · exited' : 'not started';
    const meta = [worker.stage, process, worker.killCheck ? 'check '+worker.killCheck : null].filter(Boolean).join(' · ');
    return '<button type="button" class="powerswarm-worker" data-powerswarm-worker="'+esc(worker.id)+'" aria-label="Inspect PowerSwarm worker '+esc(worker.id)+'"><span class="powerswarm-worker-main"><span class="powerswarm-worker-name">'+esc(worker.id)+'</span><span class="powerswarm-worker-meta">'+esc(meta)+'</span></span><span class="status-pill '+powerSwarmTone(worker.state,worker.processAlive)+'">'+esc(worker.processAlive ? 'live' : worker.state)+'</span><span class="powerswarm-arrow" aria-hidden="true">›</span></button>';
}

function powerSwarmTreeChildren(snapshot, workerById) {
    const hierarchy = snapshot?.hierarchy;
    const branches = Array.isArray(hierarchy?.children) ? hierarchy.children : [];
    const matches = worker => !searchFilter || [worker?.id,worker?.aim,worker?.state,worker?.stage,snapshot?.selectedRun?.objective].some(value => String(value || '').toLowerCase().includes(searchFilter));
    const rendered = [];
    branches.forEach(branch => {
        if (branch?.kind === 'subdirector') {
            const workers = (branch.children || []).map(child => workerById.get(child.id)).filter(worker => worker && matches(worker));
            if (!workers.length) return;
            rendered.push('<div class="powerswarm-branch"><div class="powerswarm-branch-head"><div><div class="powerswarm-node-label">Logical subdirector</div><div class="powerswarm-node-title">'+esc(branch.id)+'</div><div class="powerswarm-node-meta">'+esc(branch.aim || workers.length+' leaves')+'</div></div><span class="status-pill '+powerSwarmTone(branch.state)+'">'+esc(branch.state)+'</span></div><div class="powerswarm-children">'+workers.map(powerSwarmWorkerButton).join('')+'</div></div>');
            return;
        }
        const worker = workerById.get(branch?.id);
        if (worker && matches(worker)) rendered.push(powerSwarmWorkerButton(worker));
    });
    return rendered.join('') || '<div class="powerswarm-empty">No matching worker targets.</div>';
}

function renderPowerSwarm(payload) {
    lastPowerSwarmSnapshot = payload;
    const counts = payload?.counts || {};
    document.getElementById('powerswarm-live').textContent = Number(counts.live || 0);
    document.getElementById('powerswarm-queued').textContent = Number(counts.queued || 0);
    document.getElementById('powerswarm-verified').textContent = Number(counts.verified || 0);
    document.getElementById('powerswarm-failed').textContent = Number(counts.failed || 0);
    const freshness = document.getElementById('powerswarm-freshness');
    const stale = Boolean(payload?.stale);
    if (stale) closePowerSwarmWorker();
    const limited = Boolean(payload?.truncation?.any);
    freshness.textContent = (stale ? 'Stale · ' : limited ? 'Limited · ' : 'Auto · ') + observedClock(payload?.observedAt);
    freshness.className = 'agents-freshness '+(stale || limited ? 'stale' : 'fresh');
    freshness.title = stale ? powerSwarmErrorText(payload?.errorCode || payload?.error) : limited ? 'Observer limits reached; some metadata is hidden.' : 'Automatic read-only refresh';
    const state = document.getElementById('powerswarm-state');
    const run = payload?.selectedRun;
    const runtimeTruth = powerSwarmRuntimeTruth(run, stale);
    const stateValue = run?.state || payload?.state || 'unavailable';
    state.className = 'status-pill '+powerSwarmTone(stateValue,Boolean(run?.coordinatorAlive));
    state.textContent = run?.coordinatorAlive ? 'live' : stateValue;

    const tree = document.getElementById('powerswarm-tree');
    if (!payload?.ok || !run) {
        patchMarkup(tree, '<div class="powerswarm-empty">'+esc(payload?.state === 'no-runs' ? 'No PowerSwarm run history.' : powerSwarmErrorText(payload?.errorCode || payload?.error))+'</div>');
    } else {
        const workerById = new Map((payload.workers || []).map(worker => [worker.id,worker]));
        const parent = run.parent;
        const parentTitle = parent?.title || 'External or unbound parent';
        const parentMeta = parent ? [parent.agentName,parent.agentRole,parent.exact ? 'exact launch edge' : 'unbound edge'].filter(Boolean).join(' · ') : 'No exact Codex launch edge recorded';
        const checkpoint = payload?.state === 'checkpoint';
        const nested = payload?.nested || {};
        const nestedBadge = nested.state === 'observed' ? '<span class="status-pill mixed">nested · '+Number(nested.logicalDepth || 2)+'</span>' : ['invalid','truncated'].includes(nested.state) ? '<span class="status-pill invalid" title="Nested plan unavailable">nested unavailable</span>' : '';
        const runMeta = [run.product,runtimeTruth.label,run.runtime,run.requestedWidth ? 'width '+run.requestedWidth : null,run.id].filter(Boolean).join(' · ');
        const checkpointRow = checkpoint ? '<div class="powerswarm-checkpoint"><span class="status-pill checkpoint">checkpoint</span><span>No active recursion · latest durable run shown</span></div>' : '';
        patchMarkup(tree, checkpointRow+'<div class="powerswarm-tree"><div class="powerswarm-node parent"><div class="powerswarm-node-label">Codex parent</div><div class="powerswarm-node-title">'+esc(parentTitle)+'</div><div class="powerswarm-node-meta">'+esc(parentMeta)+'</div></div><div class="powerswarm-edge" aria-hidden="true"></div><div class="powerswarm-node run"><div class="powerswarm-node-top"><div><div class="powerswarm-node-label">PowerSwarm run</div><div class="powerswarm-node-title">'+esc(run.product || 'PowerSwarm')+'</div><div class="powerswarm-node-meta" title="'+esc(run.id)+'">'+esc(runMeta)+'</div></div><div style="display:flex;gap:5px;align-items:center">'+nestedBadge+'<span class="status-pill '+powerSwarmTone(run.state,run.coordinatorAlive)+'">'+esc(run.coordinatorAlive ? 'live' : run.state)+'</span></div></div><div class="powerswarm-objective">'+esc(run.objective)+'</div><div class="powerswarm-children">'+powerSwarmTreeChildren(payload,workerById)+'</div></div></div>');
        tree.querySelectorAll('[data-powerswarm-worker]').forEach(button => button.addEventListener('click', () => openPowerSwarmWorker(button.dataset.powerswarmWorker)));
    }

    const recent = document.getElementById('powerswarm-runs');
    const runs = (payload?.recentRuns || []).filter(item => !searchFilter || [item.id,item.state,item.objective].some(value => String(value || '').toLowerCase().includes(searchFilter)));
    if (!runs.length) {
        patchMarkup(recent, '<div class="powerswarm-empty">No matching runs.</div>');
    } else {
        patchMarkup(recent, runs.map(item => '<button type="button" class="powerswarm-run '+(item.id === run?.id ? 'selected' : '')+'" data-powerswarm-run="'+esc(item.id)+'"><span><span class="powerswarm-run-title">'+esc(item.objective || item.id)+'</span><span class="powerswarm-run-meta">'+Number(item.workerCount || 0)+(item.workersTruncated ? '+' : '')+' workers · '+esc(observedClock(item.updatedAt))+'</span></span><span class="status-pill '+powerSwarmTone(item.state,item.coordinatorAlive)+'">'+esc(item.coordinatorAlive ? 'live' : item.state)+'</span></button>').join(''));
        recent.querySelectorAll('[data-powerswarm-run]').forEach(button => button.addEventListener('click', () => selectPowerSwarmRun(button.dataset.powerswarmRun)));
    }
}

function renderPowerSwarmWorker(detail) {
    const inspector = document.getElementById('powerswarm-worker-inspector');
    const container = document.getElementById('powerswarm-worker-detail');
    if (!detail?.ok || !detail?.worker) {
        inspector.hidden = false;
        patchMarkup(container, '<div class="powerswarm-empty">'+esc(powerSwarmErrorText(detail?.errorCode || detail?.error))+'</div>');
        return;
    }
    const worker = detail.worker;
    document.getElementById('powerswarm-worker-title').textContent = worker.id;
    const attempts = detail.attempts || [];
    const process = worker.processAlive ? 'PID '+worker.pid+' · live' : worker.pid ? 'PID '+worker.pid+' · exited' : 'not started';
    const rows = attempts.map(attempt => {
        const attemptProcess = attempt.processAlive ? 'PID '+attempt.pid+' · live' : attempt.pid ? 'PID '+attempt.pid+' · exited' : 'not started';
        const check = attempt.killCheck?.status || '—';
        const tool = attempt.toolActivity?.telemetryStatus || attempt.toolActivity?.status || '—';
        return '<div class="powerswarm-attempt"><div><div class="powerswarm-attempt-title">'+esc(attempt.stage)+' · attempt '+Number(attempt.attempt || 0)+'</div><div class="powerswarm-attempt-meta">'+esc(attempt.errorCode ? powerSwarmErrorText(attempt.errorCode) : observedClock(attempt.endedAt || attempt.startedAt))+'</div></div><span class="status-pill '+powerSwarmTone(attempt.status,attempt.processAlive)+'">'+esc(attempt.processAlive ? 'live' : attempt.status || 'unknown')+'</span><span>'+esc(attemptProcess)+'</span><span title="Tool telemetry: '+esc(tool)+'">check '+esc(check)+'</span></div>';
    }).join('') || '<div class="powerswarm-empty">No attempts recorded.</div>';
    patchMarkup(container, '<div class="powerswarm-aim">'+esc(worker.aim || 'No worker aim recorded.')+'</div><div class="powerswarm-inspector-summary"><div class="powerswarm-inspector-stat"><span>Process</span><strong>'+esc(process)+'</strong></div><div class="powerswarm-inspector-stat"><span>Stage</span><strong>'+esc(worker.stage || '—')+'</strong></div><div class="powerswarm-inspector-stat"><span>Attempts</span><strong>'+Number(worker.attemptCount || 0)+(worker.attemptsTruncated ? '+' : '')+'</strong></div><div class="powerswarm-inspector-stat"><span>Green check</span><strong>'+esc(worker.killCheck || '—')+'</strong></div></div><div class="powerswarm-attempts">'+rows+'</div>');
    inspector.hidden = false;
    inspector.scrollIntoView({behavior:'smooth',block:'nearest'});
}

async function openPowerSwarmWorker(workerId) {
    const runId = lastPowerSwarmSnapshot?.selectedRun?.id;
    if (!runId || !workerId) return;
    selectedPowerSwarmWorkerId = workerId;
    const inspector = document.getElementById('powerswarm-worker-inspector');
    inspector.hidden = false;
    document.getElementById('powerswarm-worker-title').textContent = workerId;
    patchMarkup(document.getElementById('powerswarm-worker-detail'), '<div class="powerswarm-empty">Loading worker…</div>');
    try {
        const detail = bridgeJson(await pywebview.api.get_powerswarm_worker(runId,workerId));
        if (selectedPowerSwarmWorkerId === workerId) renderPowerSwarmWorker(detail);
    } catch (error) {
        if (selectedPowerSwarmWorkerId === workerId) renderPowerSwarmWorker({ok:false,error:'powerswarm-bridge-unavailable',errorCode:'powerswarm-bridge-unavailable'});
    }
}

function closePowerSwarmWorker() {
    selectedPowerSwarmWorkerId = null;
    document.getElementById('powerswarm-worker-inspector').hidden = true;
}

async function selectPowerSwarmRun(runId) {
    selectedPowerSwarmRunId = runId || null;
    closePowerSwarmWorker();
    await loadPowerSwarm(true);
}

async function loadPowerSwarm(force = false) {
    try {
        const payload = bridgeJson(await pywebview.api.get_powerswarm_activity(selectedPowerSwarmRunId || '',Boolean(force)));
        renderPowerSwarm(payload);
    } catch (error) {
        const fallback = stalePowerSwarmProjection(lastPowerSwarmSnapshot,'powerswarm-bridge-unavailable',new Date().toISOString());
        renderPowerSwarm(fallback);
    }
}

async function loadBrain(force = false) {
    if (!apiReady) return;
    const button = document.getElementById('brain-rescan');
    button.disabled = true;
    button.textContent = force ? 'Scanning…' : 'Refreshing…';
    try {
        const payload = bridgeJson(await pywebview.api.get_brain_inventory(Boolean(force)));
        if (!payload.ok) throw new Error(payload.error || 'Brain scan failed');
        lastBrainInventory = payload;
        document.getElementById('brain-visual-error').hidden = true;
        renderBrain(payload);
        return payload;
    } catch (error) {
        const list = document.getElementById('brain-list');
        emptyNode(list);
        const row = document.createElement('div');
        row.className = 'brain-inline-error';
        const copy = document.createElement('span');
        copy.textContent = 'The local Brain scan did not finish: ' + String(error?.message || error);
        const retry = featureButton('Retry', () => loadBrain(true), 'primary');
        row.append(copy, retry);
        list.append(row);
        document.getElementById('brain-visual-error-copy').textContent = String(error?.message || error);
        document.getElementById('brain-visual-error').hidden = false;
        return null;
    } finally {
        button.disabled = false;
        button.textContent = 'Scan all storage';
    }
}

function placeBrainBrowser(view = brainView) {
    const browser = document.getElementById('brain-browser');
    const inspector = document.getElementById('brain-visual-inspector');
    const host = view === 'visual' ? inspector : document.getElementById('brain-files-browser-host');
    if (browser.parentElement !== host) host.appendChild(browser);
    inspector.hidden = view !== 'visual' || browser.hidden;
    const welcome = document.getElementById('brain-files-welcome');
    if (welcome) welcome.hidden = view !== 'files' || !browser.hidden;
}

function setBrainView(view) {
    brainView = view === 'visual' ? 'visual' : 'files';
    if (brainBrowserState) brainBrowserState.originView = brainView;
    document.getElementById('brain-tab').classList.toggle('visual-mode', brainView === 'visual');
    document.getElementById('brain-files-view').hidden = brainView !== 'files';
    document.getElementById('brain-visual').hidden = brainView !== 'visual';
    document.getElementById('brain-view-files').setAttribute('aria-selected', String(brainView === 'files'));
    document.getElementById('brain-view-visual').setAttribute('aria-selected', String(brainView === 'visual'));
    if (brainView === 'visual' && lastBrainInventory) renderBrainVisual(lastBrainInventory);
    placeBrainBrowser(brainView);
}

function renderProjectBrainFamily(payload, list) {
    const hierarchy = payload.projectHierarchy || {};
    const children = hierarchy.children || [];
    const parentMeta = hierarchy.parent || {};
    const grouped = new Set(children.map(item => item.brainId).filter(Boolean));
    if (parentMeta.brainId) grouped.add(parentMeta.brainId);
    if (!hierarchy.ok || !children.length) return grouped;
    const byId = new Map((payload.brains || []).map(item => [item.id, item]));
    const parentBrain = byId.get(parentMeta.brainId);
    const matches = value => !searchFilter || String(value || '').toLowerCase().includes(searchFilter);
    const visibleChildren = children.filter(child => {
        const brain = byId.get(child.brainId) || {};
        return !searchFilter || [child.label, child.provider, child.projectId, child.lifecycleState, brain.pathDisplay]
            .some(matches);
    });
    const parentMatches = !searchFilter || [parentMeta.label, parentMeta.pathDisplay, 'parent canonical ke studios brain']
        .some(matches);
    if (!parentMatches && !visibleChildren.length) return grouped;

    const family = document.createElement('section');
    family.className = 'brain-family';
    family.setAttribute('aria-label', 'KE Brain parent and project child Brains');
    const head = document.createElement('div');
    head.className = 'brain-family-head';
    const heading = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'brain-family-title';
    title.textContent = 'Brains';
    const copy = document.createElement('div');
    copy.className = 'brain-family-copy';
    const counts = hierarchy.counts || {};
    copy.textContent = `${Number(counts.active || 0)} active · ${Number(counts.dormant || 0)} paused`;
    heading.append(title, copy);
    head.append(heading, pill('connected'));
    family.appendChild(head);

    if (parentMatches) {
        const parent = document.createElement('button');
        parent.type = 'button';
        parent.className = 'brain-family-parent';
        parent.disabled = !parentBrain;
        parent.setAttribute('aria-label', `${brainPrimaryAction(parentBrain).label} canonical ${parentMeta.label || 'KE Studios Brain'}`);
        const mark = document.createElement('span');
        mark.className = 'brain-orbit-mark';
        mark.textContent = 'KE';
        const parentCopy = document.createElement('span');
        parentCopy.className = 'brain-family-parent-copy';
        const strong = document.createElement('strong');
        strong.textContent = parentMeta.label || 'KE Studios Brain';
        const small = document.createElement('span');
        small.textContent = 'Main knowledge workspace';
        parentCopy.append(strong, small);
        parent.append(mark, parentCopy, pill(brainProductState(parentBrain)));
        if (parentBrain) parent.addEventListener('click', () => performBrainPrimaryAction(parentBrain, {originView:brainView}));
        family.appendChild(parent);
    }

    const grid = document.createElement('div');
    grid.className = 'brain-child-grid';
    visibleChildren.forEach(child => {
        const brain = byId.get(child.brainId);
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'brain-child-card';
        button.dataset.brainId = child.brainId || '';
        button.disabled = !brain;
        button.setAttribute('aria-label', `${brainPrimaryAction(brain).label} ${child.label} ${child.provider} project Brain; ${brainProductState(brain)}`);
        const provider = document.createElement('span');
        provider.className = 'brain-child-provider ' + child.provider;
        provider.textContent = child.provider === 'claude' ? 'CL' : 'CX';
        const childCopy = document.createElement('span');
        childCopy.className = 'brain-child-copy';
        const strong = document.createElement('strong');
        strong.textContent = child.label || 'Project Brain';
        const meta = document.createElement('span');
        meta.textContent = child.provider === 'claude' ? 'Claude project' : 'Codex project';
        childCopy.append(strong, meta);
        const state = document.createElement('span');
        state.className = 'brain-child-state ' + (child.lifecycleState || child.status || '');
        state.textContent = brainProductState(brain);
        button.append(provider, childCopy, state);
        if (brain) button.addEventListener('click', () => performBrainPrimaryAction(brain, {originView:brainView}));
        grid.appendChild(button);
    });
    family.appendChild(grid);
    list.appendChild(family);
    return grouped;
}

function brainSvg(tag) {
    return document.createElementNS('http://www.w3.org/2000/svg', tag);
}

function brainGraphLabelLines(value, limit = 17) {
    const text = String(value || 'Project Brain').trim();
    if (text.length <= limit) return [text];
    const words = text.split(/\s+/).filter(Boolean);
    if (words.length < 2) return [text.slice(0, limit - 1) + '…'];
    let best = 1;
    let bestScore = Number.POSITIVE_INFINITY;
    for (let index = 1; index < words.length; index += 1) {
        const first = words.slice(0, index).join(' ');
        const second = words.slice(index).join(' ');
        const overflow = Math.max(0, first.length - limit) + Math.max(0, second.length - limit);
        const score = overflow * 100 + Math.abs(first.length - second.length);
        if (score < bestScore) {
            best = index;
            bestScore = score;
        }
    }
    const bounded = line => line.length > limit ? line.slice(0, limit - 1) + '…' : line;
    return [bounded(words.slice(0, best).join(' ')), bounded(words.slice(best).join(' '))];
}

function applyBrainGraphTransform() {
    const world = document.getElementById('brain-graph-world');
    const {x, y, scale} = brainGraphTransform;
    world.setAttribute('transform', `translate(${x} ${y}) scale(${scale})`);
}

function brainGraphColumnPoints(items, xs) {
    if (!items.length) return [];
    const columns = items.length > 4 ? Math.min(2, xs.length) : 1;
    const activeXs = columns === 1
        ? [xs.reduce((sum, value) => sum + value, 0) / xs.length]
        : xs.slice(0, columns);
    const rows = Math.ceil(items.length / columns);
    const startY = rows === 1 ? 320 : rows === 2 ? 218 : rows === 3 ? 150 : 112;
    const endY = rows === 1 ? 320 : rows === 2 ? 422 : rows === 3 ? 470 : 478;
    const step = rows <= 1 ? 0 : (endY - startY) / (rows - 1);
    return items.map((child, index) => ({
        child,
        x: activeXs[index % columns],
        y: startY + step * Math.floor(index / columns),
    }));
}

function brainGraphBackdrop(hasDormant) {
    const layer = brainSvg('g');
    layer.setAttribute('class', 'brain-spatial-layer');
    layer.setAttribute('aria-hidden', 'true');
    const shape = (tag, className, attributes = {}) => {
        const node = brainSvg(tag);
        node.setAttribute('class', className);
        Object.entries(attributes).forEach(([name, value]) => node.setAttribute(name, String(value)));
        return node;
    };
    layer.append(
        shape('path', 'brain-region claude', {d:'M34 72 Q196 18 374 88 L374 510 Q198 584 34 522 Z'}),
        shape('path', 'brain-region codex', {d:'M626 88 Q804 18 966 72 L966 522 Q802 584 626 510 Z'}),
        shape('path', 'brain-fold claude', {d:'M72 172 C156 112 246 144 340 202'}),
        shape('path', 'brain-fold claude', {d:'M62 286 C154 228 248 256 346 322'}),
        shape('path', 'brain-fold claude', {d:'M80 410 C178 354 264 388 350 456'}),
        shape('path', 'brain-fold codex', {d:'M928 172 C844 112 754 144 660 202'}),
        shape('path', 'brain-fold codex', {d:'M938 286 C846 228 752 256 654 322'}),
        shape('path', 'brain-fold codex', {d:'M920 410 C822 354 736 388 650 456'}),
        shape('ellipse', 'brain-orbit outer', {cx:500, cy:320, rx:326, ry:236}),
        shape('ellipse', 'brain-orbit inner', {cx:500, cy:320, rx:154, ry:112}),
        shape('circle', 'brain-center-glow', {cx:500, cy:320, r:126}),
        shape('path', 'brain-bridge', {d:'M500 142 C458 188 548 230 500 278 C452 326 548 370 500 418 C462 456 532 486 500 516'}),
    );
    const label = (text, className, x, y, anchor = 'start') => {
        const node = shape('text', className, {x, y, 'text-anchor':anchor});
        node.textContent = text;
        return node;
    };
    layer.append(
        label('Claude projects', 'brain-region-label', 52, 96),
        label('Codex projects', 'brain-region-label', 948, 96, 'end'),
    );
    if (hasDormant) layer.append(label('Dormant', 'brain-region-label dormant', 500, 610, 'middle'));
    return layer;
}

function brainGraphNode(item, brain, x, y, parent = false) {
    const group = brainSvg('g');
    const lifecycle = item.lifecycleState || '';
    group.setAttribute('class', `brain-graph-node ${parent ? 'parent' : item.provider || ''} ${item.accessible === false ? 'blocked' : lifecycle}`);
    group.setAttribute('transform', `translate(${x} ${y})`);
    group.dataset.brainId = brain?.id || '';
    group.dataset.spatialGroup = parent
        ? 'parent'
        : item.accessible === false || lifecycle === 'dormant' ? 'dormant' : item.provider === 'claude' ? 'claude' : 'codex';
    group.setAttribute('role', 'button');
    group.setAttribute('aria-label', parent
        ? `${brainPrimaryAction(brain).label} ${item.label || 'canonical KE Brain'}`
        : `${brainPrimaryAction(brain).label} ${item.label || 'project Brain'}, ${item.provider || 'project'}, ${brainProductState(brain)}`);
    group.setAttribute('tabindex', brain ? '0' : '-1');
    if (!brain) group.setAttribute('aria-disabled', 'true');
    const title = brainSvg('title');
    title.textContent = parent
        ? 'Canonical KE Studios Brain'
        : `${item.label} · ${item.provider} · ${lifecycle || item.status || 'ready'}`;
    const rect = brainSvg('rect');
    rect.setAttribute('x', parent ? '-100' : '-78');
    rect.setAttribute('y', parent ? '-34' : '-27');
    rect.setAttribute('width', parent ? '200' : '156');
    rect.setAttribute('height', parent ? '68' : '54');
    rect.setAttribute('rx', parent ? '34' : '27');
    const signal = brainSvg('circle');
    signal.setAttribute('class', `brain-node-signal${parent ? ' parent' : ''}`);
    signal.setAttribute('cx', parent ? '0' : '-56');
    signal.setAttribute('cy', parent ? '-34' : '0');
    signal.setAttribute('r', parent ? '6' : '5');
    const label = brainSvg('text');
    label.setAttribute('class', 'brain-graph-label');
    label.setAttribute('text-anchor', parent ? 'middle' : 'start');
    label.setAttribute('x', parent ? '0' : '-40');
    const labelLines = parent ? [String(item.label || 'KE Studios Brain')] : brainGraphLabelLines(item.label || 'Project Brain');
    label.setAttribute('y', parent ? '-2' : labelLines.length > 1 ? '-10' : '-3');
    labelLines.forEach((line, index) => {
        const span = brainSvg('tspan');
        span.setAttribute('x', parent ? '0' : '-40');
        if (index) span.setAttribute('dy', '12');
        span.textContent = line;
        label.appendChild(span);
    });
    const meta = brainSvg('text');
    meta.setAttribute('class', 'brain-graph-meta');
    meta.setAttribute('text-anchor', parent ? 'middle' : 'start');
    meta.setAttribute('x', parent ? '0' : '-40');
    meta.setAttribute('y', parent ? '16' : labelLines.length > 1 ? '18' : '14');
    const providerLabel = item.provider === 'claude' ? 'Claude' : item.provider === 'codex' ? 'Codex' : 'Project';
    const state = String(lifecycle || item.status || 'ready').toLowerCase();
    meta.textContent = parent ? 'Canonical parent' : `${providerLabel} · ${state.charAt(0).toUpperCase()}${state.slice(1)}`;
    group.append(title, rect, signal, label, meta);
    const activate = () => {
        if (!brain) return;
        performBrainPrimaryAction(brain, {
            originView:'visual',
            originBrainId:brain.id,
            originTransform:{...brainGraphTransform},
        });
    };
    group.addEventListener('click', activate);
    group.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            activate();
        }
    });
    return group;
}

function renderBrainVisual(payload) {
    const hierarchy = payload.projectHierarchy || {};
    const world = document.getElementById('brain-graph-world');
    emptyNode(world);
    const status = document.getElementById('brain-visual-status');
    const children = (hierarchy.children || []).slice(0, 64);
    if (!hierarchy.ok || !children.length) {
        const message = brainSvg('text');
        message.setAttribute('x', '500');
        message.setAttribute('y', '315');
        message.setAttribute('text-anchor', 'middle');
        message.setAttribute('fill', '#B9CCE0');
        message.setAttribute('font-size', '14');
        message.textContent = hierarchy.error || 'Project Brains will appear when the canonical KE Brain is available.';
        world.appendChild(message);
        status.textContent = 'No project constellation yet';
        applyBrainGraphTransform();
        return;
    }
    const byId = new Map((payload.brains || []).map(item => [item.id, item]));
    const parentMeta = hierarchy.parent || {label:'KE Studios Brain'};
    const parentBrain = byId.get(parentMeta.brainId);
    const center = {x:500, y:320};
    const active = children.filter(child => child.accessible !== false && child.lifecycleState !== 'dormant');
    const dormant = children.filter(child => !active.includes(child)).slice(0, 4);
    const claude = active.filter(child => child.provider === 'claude').slice(0, 8);
    const codex = active.filter(child => child.provider !== 'claude').slice(0, 16);
    const points = [
        ...brainGraphColumnPoints(claude, [112, 288]),
        ...brainGraphColumnPoints(codex, [712, 888]),
    ];
    dormant.forEach((child, index) => {
        const spacing = dormant.length === 1 ? 0 : 500 / Math.max(1, dormant.length - 1);
        points.push({child, x:dormant.length === 1 ? 500 : 250 + spacing * index, y:560});
    });
    world.appendChild(brainGraphBackdrop(Boolean(dormant.length)));
    points.forEach(point => {
        const edge = brainSvg('path');
        edge.setAttribute('class', `brain-graph-edge ${point.child.lifecycleState || ''}`);
        const group = point.child.accessible === false || point.child.lifecycleState === 'dormant'
            ? 'dormant' : point.child.provider === 'claude' ? 'claude' : 'codex';
        const direction = point.x < center.x ? -1 : point.x > center.x ? 1 : 0;
        const controlOneX = center.x + direction * 104;
        const controlTwoX = point.x - direction * Math.min(138, Math.abs(point.x - center.x) * .44);
        const controlOneY = center.y + (point.y - center.y) * .12;
        const controlTwoY = point.y - (point.y - center.y) * .12;
        edge.setAttribute('d', `M ${center.x} ${center.y} C ${controlOneX} ${controlOneY} ${controlTwoX} ${controlTwoY} ${point.x} ${point.y}`);
        edge.dataset.spatialGroup = group;
        world.appendChild(edge);
        const synapse = brainSvg('circle');
        synapse.setAttribute('class', `brain-synapse ${group}`);
        synapse.setAttribute('cx', String(center.x + (point.x - center.x) * .58));
        synapse.setAttribute('cy', String(center.y + (point.y - center.y) * .58));
        synapse.setAttribute('r', group === 'dormant' ? '2' : '2.5');
        world.appendChild(synapse);
    });
    points.forEach(point => world.appendChild(
        brainGraphNode(point.child, byId.get(point.child.brainId), point.x, point.y, false)
    ));
    world.appendChild(brainGraphNode(parentMeta, parentBrain, center.x, center.y, true));
    const omitted = Math.max(0, (hierarchy.children || []).length - points.length);
    status.textContent = `${points.length} project Brains${omitted ? ` · ${omitted} more` : ''}`;
    applyBrainGraphTransform();
}

function renderBrain(payload) {
    const summary = payload.summary || {};
    document.getElementById('brain-found').textContent = summary.found ?? 0;
    document.getElementById('brain-projects').textContent = summary.projectChildren ?? 0;
    document.getElementById('brain-project-state').textContent = `${summary.activeProjectChildren ?? 0} active · ${summary.dormantProjectChildren ?? 0} dormant`;
    document.getElementById('brain-connected').textContent = summary.connected ?? 0;
    document.getElementById('brain-discovered').textContent = summary.discovered ?? 0;
    setBrainBodyIndicator(brainBrowserState?.view === 'note');
    const scan = payload.scan || {};
    document.getElementById('brain-coverage').textContent = scan.truncated
        ? `${Number(scan.directoriesInspected || 0).toLocaleString()} folders · bounded pass`
        : `${Number(scan.directoriesInspected || 0).toLocaleString()} folders inspected`;

    const list = document.getElementById('brain-list');
    emptyNode(list);
    renderBrainVisual(payload);
    if (brainBrowserState) {
        const current = (payload.brains || []).find(brain => brain.id === brainBrowserState.brainId);
        if (current && current.status === 'connected' && current.canBrowse !== false && !current.indexedOnly) {
            brainBrowserState.inventoryRevision = payload.inventoryRevision;
        } else {
            const priorId = brainBrowserState.brainId;
            brainActionErrors.set(priorId, brainActionReason(current));
            closeBrainBrowser({restoreFocus:false});
        }
    }
    list.hidden = false;
    const groupedBrainIds = renderProjectBrainFamily(payload, list);
    const brains = (payload.brains || []).filter(brain => {
        if (groupedBrainIds.has(brain.id)) return false;
        if (!searchFilter) return true;
        return [brain.label, brain.type, brain.pathDisplay, ...(brain.evidence || [])]
            .join(' ').toLowerCase().includes(searchFilter);
    });
    const needsAction = brains.filter(brain => brainPrimaryAction(brain).kind !== 'open' || brainActionErrors.has(brain.id));
    let actionList = null;
    if (needsAction.length) {
        actionList = document.createElement('section');
        actionList.className = 'brain-action-list';
        const actionTitle = document.createElement('div');
        actionTitle.className = 'brain-action-list-title';
        actionTitle.textContent = 'Needs you';
        actionList.appendChild(actionTitle);
        list.insertBefore(actionList,list.firstChild);
    }
    if (!brains.length && list.childElementCount === 0) {
        const empty = document.createElement('div');
        empty.className = 'brain-empty';
        empty.textContent = summary.found ? 'No brains match this filter.' : 'No credible Brain structure was found. Create one when you are ready.';
        list.appendChild(empty);
        return;
    }
    brains.forEach(brain => {
        const card = document.createElement('section');
        card.className = 'brain-card';
        card.tabIndex = 0;
        card.setAttribute('role', 'group');
        card.setAttribute('aria-keyshortcuts', 'Enter Space');
        const primary = brainPrimaryAction(brain);
        const primaryLabel = brainActionErrors.has(brain.id) ? 'Retry' : primary.label;
        card.setAttribute('aria-label', `${brain.label || 'local Brain'}; ${brainProductState(brain)}; press Enter to ${primaryLabel.toLowerCase()}`);
        card.dataset.brainId = brain.id || '';
        card.addEventListener('click', event => {
            if (event.target.closest('button,summary,details')) return;
            performBrainPrimaryAction(brain, {originView:brainView});
        });
        card.addEventListener('keydown', event => {
            if (event.target !== card || !brainCardActivationKey(event)) return;
            event.preventDefault();
            performBrainPrimaryAction(brain, {originView:brainView});
        });
        const top = document.createElement('div');
        top.className = 'brain-card-top';
        const identity = document.createElement('div');
        identity.style.minWidth = '0';
        const label = document.createElement('div');
        label.className = 'brain-label';
        label.textContent = brain.label || 'Local Brain';
        const type = document.createElement('div');
        type.className = 'brain-type';
        type.textContent = brain.type || 'Brain';
        identity.append(label, type);
        top.append(identity, pill(brainProductState(brain)));
        const path = document.createElement('div');
        path.className = 'brain-path';
        path.textContent = brain.pathDisplay || brain.path;
        path.title = brain.path || '';
        const hint = document.createElement('div');
        hint.className = 'brain-card-hint';
        hint.textContent = brainActionReason(brain);
        const error = document.createElement('div');
        error.className = 'brain-card-error';
        error.hidden = !brainActionErrors.has(brain.id);
        error.textContent = brainActionErrors.get(brain.id) || '';
        const controls = document.createElement('div');
        controls.className = 'brain-controls';
        controls.appendChild(featureButton(primaryLabel, () => performBrainPrimaryAction(brain, {originView:brainView}), 'primary brain-primary-action'));

        const more = document.createElement('details');
        more.className = 'brain-card-more';
        const summary = document.createElement('summary');
        summary.textContent = 'More';
        const secondary = document.createElement('div');
        secondary.className = 'brain-secondary-actions';
        const evidence = document.createElement('div');
        evidence.className = 'brain-evidence';
        const evidenceText = (brain.evidence || []).join(' · ') || 'Verified local structure';
        const countText = brain.countState === 'complete' ? ` · ${brain.itemCount ?? brain.noteCount ?? 0} items` : brain.countState === 'bounded' ? ' · bounded count' : '';
        evidence.textContent = evidenceText + countText;
        secondary.appendChild(evidence);
        if (brain.status === 'connected' && brain.canConnect && !brain.managedProjectChild) {
            secondary.appendChild(featureButton('Disconnect', async () => {
                const result = bridgeJson(await pywebview.api.set_brain_connected(brain.path, false));
                if (!result.ok) throw new Error(result.error || 'Disconnect failed');
                lastBrainInventory = result;
                renderBrain(result);
            }));
        }
        if (!brain.managedProjectChild && brain.status !== 'ignored' && brain.status !== 'offline') {
            secondary.appendChild(featureButton('Pause', async () => {
                const result = bridgeJson(await pywebview.api.set_brain_ignored(brain.path, true));
                if (!result.ok) throw new Error(result.error || 'Pause failed');
                lastBrainInventory = result;
                renderBrain(result);
            }));
        }
        if (brain.canConnect && !brain.managedProjectChild) {
            secondary.appendChild(featureButton('Forget', async () => {
                const result = bridgeJson(await pywebview.api.forget_brain(brain.path));
                if (!result.ok) throw new Error(result.error || 'Forget failed');
                lastBrainInventory = result;
                renderBrain(result);
            }));
        }
        if (brain.canStructure && brain.status === 'connected' && !brain.indexedOnly) {
            secondary.appendChild(featureButton('Preview structure', () => previewBrain(brain.path)));
        }
        more.append(summary, secondary);
        card.append(top, path, hint, error, controls, more);
        if (actionList && needsAction.includes(brain)) actionList.appendChild(card);
        else list.appendChild(card);
    });
    if (!brainAutoOpenAttempted && !brainBrowserState && brainView === 'files') {
        const parentId = payload.projectHierarchy?.parent?.brainId;
        const preferred = (payload.brains || []).find(brain => brain.id === parentId && brainCanBrowse(brain))
            || (payload.brains || []).find(brain => brain.managedProjectChild && brainCanBrowse(brain))
            || (payload.brains || []).find(brainCanBrowse);
        if (preferred) {
            brainAutoOpenAttempted = true;
            void activateBrainCard(preferred,{originView:'files'});
        }
    }
}

function brainCardActivationKey(event) {
    return event?.key === 'Enter' || event?.key === ' ';
}

function brainCanBrowse(brain) {
    return Boolean(brain && brain.status === 'connected' && brain.canBrowse !== false && !brain.indexedOnly);
}

function brainProductState(brain) {
    if (!brain) return 'Check needed';
    if (brainCanBrowse(brain)) return 'Connected';
    if (brain.identityChanged) return 'Identity changed';
    if (brain.status === 'ignored') return 'Paused';
    if (brain.status === 'permission-denied' || brain.permissionDenied || brain.indexedOnly) return 'Access needed';
    if (brain.status === 'discovered') return 'Ready to connect';
    if (brain.status === 'offline') return 'Root missing';
    return 'Check needed';
}

function brainPrimaryAction(brain) {
    if (brainCanBrowse(brain)) return {kind:'open', label:'Open'};
    if (brain?.status === 'ignored') return {kind:'restore', label:'Restore & open'};
    if (brain?.identityChanged || brain?.status === 'permission-denied' || brain?.permissionDenied || brain?.indexedOnly) {
        return {kind:'repair', label:'Repair access'};
    }
    if (brain?.status === 'discovered' && brain?.canConnect) return {kind:'connect', label:'Connect & open'};
    return {kind:'retry', label:'Retry'};
}

function brainActionReason(brain) {
    if (!brain) return 'This Brain is no longer in the current local scan.';
    if (brainCanBrowse(brain)) return 'Verified and ready. Opening reads folder metadata only until you select one text file.';
    if (brain.identityChanged) return 'The saved root identity changed. Reselect the exact Brain folder to verify it.';
    if (brain.status === 'ignored') return 'You paused this Brain. Restore it to verify and open the same root.';
    if (brain.indexedOnly) return 'macOS can see this Brain in its index, but Activity Monitor still needs one folder grant.';
    if (brain.status === 'permission-denied' || brain.permissionDenied) return 'macOS denied this exact folder. Repair access with the native folder picker.';
    if (brain.status === 'discovered') return 'This verified local Brain is ready for a one-time connection.';
    if (brain.status === 'offline') return 'The saved Brain root is not present at its verified path.';
    return 'The current local scan could not verify this Brain. Retry the scan.';
}

async function performBrainPrimaryAction(brain, options = {}) {
    if (!brain) return;
    const action = brainPrimaryAction(brain);
    if (action.kind === 'open') {
        brainActionErrors.delete(brain.id);
        await activateBrainCard(brain, options);
        return;
    }
    const generation = ++brainActionGeneration;
    const visualError = document.getElementById('brain-visual-error');
    visualError.hidden = true;
    try {
        let result;
        if (action.kind === 'connect') {
            result = bridgeJson(await pywebview.api.set_brain_connected(brain.path, true));
        } else if (action.kind === 'restore') {
            result = bridgeJson(await pywebview.api.set_brain_ignored(brain.path, false));
            if (generation !== brainActionGeneration) return;
            let restored = (result?.brains || []).find(item => item.id === brain.id);
            if (result?.ok && restored && !brainCanBrowse(restored) && restored.canConnect) {
                result = bridgeJson(await pywebview.api.set_brain_connected(restored.path, true));
            }
        } else if (action.kind === 'repair') {
            result = bridgeJson(await pywebview.api.repair_brain_connection(brain.path));
        } else {
            result = bridgeJson(await pywebview.api.get_brain_inventory(true));
        }
        if (generation !== brainActionGeneration) return;
        if (!result?.ok) throw new Error(result?.error || 'The local Brain action did not finish');
        brainActionErrors.delete(brain.id);
        lastBrainInventory = result;
        renderBrain(result);
        const current = (result.brains || []).find(item => item.id === brain.id);
        if (brainCanBrowse(current)) await activateBrainCard(current, options);
        else if (current) {
            brainActionErrors.set(current.id, brainActionReason(current));
            renderBrain(result);
        }
    } catch (error) {
        if (generation !== brainActionGeneration) return;
        const reason = String(error?.message || error);
        brainActionErrors.set(brain.id, reason);
        if (lastBrainInventory) renderBrain(lastBrainInventory);
        if ((options.originView || brainView) === 'visual') {
            document.getElementById('brain-visual-error-copy').textContent = reason;
            visualError.hidden = false;
        }
    }
}

function setBrainBodyIndicator(open) {
    document.getElementById('brain-bodies').textContent = open ? '1 open' : '0 open';
}

function clearBrainNoteBody() {
    const body = document.getElementById('brain-note-body');
    body.textContent = '';
    document.getElementById('brain-note-meta').textContent = '';
    document.getElementById('brain-note').hidden = true;
    setBrainBodyIndicator(false);
}

function setBrainBrowserMessage(copy = '') {
    const message = document.getElementById('brain-browser-message');
    message.textContent = String(copy || '');
    message.hidden = !copy;
}

function showBrainBrowserShell(label, status, copy) {
    document.getElementById('brain-browser').hidden = false;
    document.getElementById('brain-list').hidden = false;
    const welcome = document.getElementById('brain-files-welcome');
    if (welcome) welcome.hidden = true;
    document.getElementById('brain-browser-title').textContent = label || 'Brain browser';
    document.getElementById('brain-browser-copy').textContent = copy || 'Immediate items only · read-only';
    const state = document.getElementById('brain-browser-status');
    state.className = 'status-pill ' + statusClass(status);
    state.textContent = status === 'connected' ? 'Connected' : String(status || 'Check needed');
    placeBrainBrowser(brainView);
}

function closeBrainBrowser(options = {}) {
    const prior = brainBrowserState ? {...brainBrowserState} : null;
    brainRequestGeneration += 1;
    clearBrainNoteBody();
    brainBrowserState = null;
    const browser = document.getElementById('brain-browser');
    browser.hidden = true;
    document.getElementById('brain-directory').hidden = false;
    document.getElementById('brain-pager').hidden = true;
    document.getElementById('brain-list').hidden = false;
    const welcome = document.getElementById('brain-files-welcome');
    if (welcome) welcome.hidden = false;
    emptyNode(document.getElementById('brain-breadcrumbs'));
    setBrainBrowserMessage('');
    const inspector = document.getElementById('brain-visual-inspector');
    inspector.hidden = true;
    document.getElementById('brain-files-browser-host').appendChild(browser);
    if (prior?.originView === 'visual') {
        brainView = 'visual';
        if (prior.originTransform) brainGraphTransform = {...prior.originTransform};
        applyBrainGraphTransform();
        if (options.restoreFocus !== false && prior.originBrainId) {
            window.requestAnimationFrame(() => {
                const node = Array.from(document.querySelectorAll('.brain-graph-node')).find(
                    item => item.dataset.brainId === prior.originBrainId
                );
                if (node && typeof node.focus === 'function') node.focus();
            });
        }
    }
}

function restoreBrainBrowserOrigin() {
    closeBrainBrowser();
}

async function activateBrainCard(brain, options = {}) {
    resetBrainStructure();
    const generation = ++brainRequestGeneration;
    const originView = options.originView === 'visual' || brainView === 'visual' ? 'visual' : 'files';
    if (!brainCanBrowse(brain)) {
        brainActionErrors.set(brain?.id || '', brainActionReason(brain));
        if (lastBrainInventory) renderBrain(lastBrainInventory);
        return;
    }
    brainBrowserState = {
        brainId: brain.id,
        inventoryRevision: lastBrainInventory?.inventoryRevision || '',
        brainLabel: brain.label || 'Brain',
        view: 'directory',
        relativePath: '',
        parentPath: null,
        page: 0,
        originView,
        originBrainId: options.originBrainId || brain.id,
        originTransform: options.originTransform ? {...options.originTransform} : {...brainGraphTransform},
    };
    showBrainBrowserShell(brainBrowserState.brainLabel, 'connected', 'Immediate items only · read-only');
    await loadBrainDirectory('', 0, generation);
}

function renderBrainBreadcrumbs(payload) {
    const container = document.getElementById('brain-breadcrumbs');
    emptyNode(container);
    const crumbs = payload.breadcrumbs || [];
    crumbs.forEach((crumb, index) => {
        if (index) {
            const separator = document.createElement('span');
            separator.className = 'brain-crumb-sep';
            separator.textContent = '›';
            container.appendChild(separator);
        }
        const current = index === crumbs.length - 1;
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'brain-crumb' + (current ? ' current' : '');
        button.textContent = crumb.label || 'Brain';
        button.disabled = current;
        if (!current) button.addEventListener('click', () => loadBrainDirectory(crumb.relativePath || '', 0));
        container.appendChild(button);
    });
}

function brainItemMeta(item) {
    const values = [item.kind === 'folder' ? 'Folder' : item.kind === 'file' ? 'Text note' : 'Restricted'];
    if (item.kind === 'file' && Number.isFinite(Number(item.sizeBytes))) values.push(fmtBytes(Number(item.sizeBytes)));
    if (item.modifiedAt) {
        const observed = new Date(item.modifiedAt);
        if (Number.isFinite(observed.getTime())) values.push(observed.toLocaleString());
    }
    return values.join(' · ');
}

function renderBrainDirectoryLoading() {
    const directory = document.getElementById('brain-directory');
    emptyNode(directory);
    directory.classList.add('brain-directory-loading');
    directory.hidden = false;
    const state = document.createElement('div');
    state.className = 'brain-directory-loading-state';
    state.setAttribute('role', 'status');
    state.setAttribute('aria-live', 'polite');
    const copy = document.createElement('div');
    copy.className = 'brain-directory-loading-copy';
    copy.textContent = 'Loading this folder…';
    state.appendChild(copy);
    for (let index = 0; index < 5; index += 1) {
        const row = document.createElement('div');
        row.className = 'brain-directory-loading-row';
        row.setAttribute('aria-hidden', 'true');
        const icon = document.createElement('span');
        icon.className = 'brain-directory-loading-icon';
        const lines = document.createElement('span');
        lines.className = 'brain-directory-loading-lines';
        const meta = document.createElement('span');
        meta.className = 'brain-directory-loading-meta';
        row.append(icon, lines, meta);
        state.appendChild(row);
    }
    directory.appendChild(state);
}

function renderBrainDirectory(payload) {
    clearBrainNoteBody();
    brainBrowserState = {
        ...brainBrowserState,
        brainId: payload.brainId,
        inventoryRevision: payload.inventoryRevision,
        brainLabel: payload.brainLabel,
        view: 'directory',
        relativePath: payload.relativePath || '',
        parentPath: payload.parentPath,
        page: Number(payload.page || 0),
    };
    showBrainBrowserShell(payload.brainLabel, 'connected', `${payload.relativePath || 'Root'} · immediate metadata only`);
    renderBrainBreadcrumbs(payload);
    const directory = document.getElementById('brain-directory');
    directory.classList.remove('brain-directory-loading');
    directory.hidden = false;
    emptyNode(directory);
    (payload.items || []).forEach(item => {
        const row = document.createElement('button');
        row.type = 'button';
        row.className = 'brain-item' + (item.openable ? '' : ' restricted');
        row.dataset.kind = item.kind || 'restricted';
        row.setAttribute('aria-label', `${item.kind || 'item'} ${item.name}${item.restriction ? ': ' + item.restriction : ''}`);
        const icon = document.createElement('span');
        icon.className = 'brain-item-icon';
        icon.setAttribute('aria-hidden','true');
        const identity = document.createElement('span');
        const name = document.createElement('span');
        name.className = 'brain-item-name';
        name.textContent = item.name;
        const path = document.createElement('span');
        path.className = 'brain-item-path';
        path.textContent = item.relativePath || item.name;
        identity.append(name, path);
        const meta = document.createElement('span');
        meta.className = 'brain-item-meta';
        meta.textContent = item.restriction || brainItemMeta(item);
        row.append(icon, identity, meta);
        row.addEventListener('click', () => {
            if (!item.openable) {
                setBrainBrowserMessage(item.restriction || 'This item cannot be opened safely.');
            } else if (item.kind === 'folder') {
                loadBrainDirectory(item.relativePath, 0);
            } else if (item.kind === 'file') {
                openBrainNote(item.relativePath);
            }
        });
        directory.appendChild(row);
    });
    if (!(payload.items || []).length) {
        const empty = document.createElement('div');
        empty.className = 'brain-empty';
        empty.textContent = 'This folder has no immediate files or folders.';
        directory.appendChild(empty);
    }
    const pager = document.getElementById('brain-pager');
    pager.hidden = !(payload.hasPrevious || payload.hasMore || payload.countState === 'bounded');
    document.getElementById('brain-page-copy').textContent = payload.countState === 'bounded'
        ? `Showing a bounded ${Number(payload.boundedItemCount || 0).toLocaleString()}-item window (limit ${Number(payload.directoryLimit || 0).toLocaleString()})`
        : `${Number(payload.itemCount || 0).toLocaleString()} immediate items · page ${Number(payload.page || 0) + 1}`;
    document.getElementById('brain-page-previous').disabled = !payload.hasPrevious;
    document.getElementById('brain-page-next').disabled = !payload.hasMore;
    document.getElementById('brain-browser-back').disabled = (
        payload.parentPath == null && brainBrowserState?.originView !== 'visual'
    );
    setBrainBrowserMessage(payload.countState === 'bounded' ? 'This large folder is capped so it cannot freeze Activity Monitor.' : '');
}

async function loadBrainDirectory(relativePath = '', page = 0, generation = brainRequestGeneration) {
    if (!brainBrowserState?.brainId) return;
    const requestedBrainId = brainBrowserState.brainId;
    const requestedRevision = brainBrowserState.inventoryRevision;
    clearBrainNoteBody();
    renderBrainDirectoryLoading();
    document.getElementById('brain-pager').hidden = true;
    setBrainBrowserMessage('');
    try {
        const result = bridgeJson(await pywebview.api.list_brain_directory(
            requestedBrainId,
            requestedRevision,
            relativePath || '',
            Number(page || 0),
            60,
        ));
        if (generation !== brainRequestGeneration || brainBrowserState?.brainId !== requestedBrainId) return;
        if (!result.ok) throw new Error(result.error || 'The Brain folder could not be opened');
        renderBrainDirectory(result);
    } catch (error) {
        if (generation !== brainRequestGeneration || brainBrowserState?.brainId !== requestedBrainId) return;
        document.getElementById('brain-directory').hidden = true;
        document.getElementById('brain-pager').hidden = true;
        setBrainBrowserMessage(String(error?.message || error));
    }
}

async function openBrainNote(relativePath, generation = brainRequestGeneration) {
    if (!brainBrowserState?.brainId) return;
    const requestedBrainId = brainBrowserState.brainId;
    const requestedRevision = brainBrowserState.inventoryRevision;
    clearBrainNoteBody();
    setBrainBrowserMessage('Opening only the selected local text note…');
    try {
        const result = bridgeJson(await pywebview.api.open_brain_note(
            requestedBrainId,
            requestedRevision,
            relativePath,
        ));
        if (generation !== brainRequestGeneration || brainBrowserState?.brainId !== requestedBrainId) {
            result.body = '';
            return;
        }
        if (!result.ok) throw new Error(result.error || 'The selected Brain note could not be opened');
        brainBrowserState = {
            ...brainBrowserState,
            brainId: result.brainId,
            inventoryRevision: result.inventoryRevision,
            brainLabel: result.brainLabel,
            view: 'note',
            relativePath: result.relativePath,
            parentPath: result.parentPath,
        };
        showBrainBrowserShell(result.brainLabel, 'connected', `${result.relativePath} · explicitly selected note`);
        renderBrainBreadcrumbs(result);
        document.getElementById('brain-directory').hidden = true;
        document.getElementById('brain-pager').hidden = true;
        const note = document.getElementById('brain-note');
        note.hidden = false;
        const modified = result.modifiedAt ? new Date(result.modifiedAt) : null;
        const modifiedCopy = modified && Number.isFinite(modified.getTime()) ? modified.toLocaleString() : 'modified time not recorded';
        document.getElementById('brain-note-meta').textContent = `${result.relativePath} · ${fmtBytes(Number(result.sizeBytes || 0))} · ${modifiedCopy}`;
        document.getElementById('brain-note-body').textContent = String(result.body || '');
        result.body = '';
        document.getElementById('brain-browser-back').disabled = false;
        setBrainBrowserMessage('');
        setBrainBodyIndicator(true);
    } catch (error) {
        if (generation !== brainRequestGeneration || brainBrowserState?.brainId !== requestedBrainId) return;
        document.getElementById('brain-directory').hidden = true;
        setBrainBrowserMessage(String(error?.message || error));
    }
}

function resetBrainStructure() {
    brainPreview = null;
    brainOperationId = null;
    document.getElementById('brain-structure-panel').hidden = true;
    document.getElementById('brain-structure-confirm').value = '';
    document.getElementById('brain-structure-apply').disabled = true;
    document.getElementById('brain-structure-apply').hidden = false;
    document.getElementById('brain-structure-confirm').hidden = false;
    document.getElementById('brain-structure-rollback').hidden = true;
}

async function previewBrain(path) {
    const result = bridgeJson(await pywebview.api.preview_brain_structure(path));
    if (!result.ok) throw new Error(result.error || 'Structure preview failed');
    brainPreview = result;
    brainOperationId = null;
    const panel = document.getElementById('brain-structure-panel');
    panel.hidden = false;
    document.getElementById('brain-structure-title').textContent = 'Structure preview · ' + (result.label || 'Local Brain');
    document.getElementById('brain-structure-copy').textContent = `${result.summary} ${result.analysis} ${result.backup}`;
    const folders = document.getElementById('brain-structure-folders');
    emptyNode(folders);
    (result.createDirectories || []).forEach(value => {
        const chip = document.createElement('span');
        chip.className = 'folder-chip';
        chip.textContent = String(value).split('/').pop();
        folders.appendChild(chip);
    });
    if (!(result.createDirectories || []).length) {
        const chip = document.createElement('span');
        chip.className = 'folder-chip';
        chip.textContent = 'No changes proposed';
        folders.appendChild(chip);
    }
    document.getElementById('brain-structure-confirm').hidden = false;
    document.getElementById('brain-structure-apply').hidden = false;
    document.getElementById('brain-structure-rollback').hidden = true;
    document.getElementById('brain-structure-confirm').value = '';
    document.getElementById('brain-structure-apply').disabled = true;
    panel.scrollIntoView({behavior:'smooth', block:'nearest'});
}

async function applyBrainStructure() {
    if (!brainPreview) return;
    const confirmation = document.getElementById('brain-structure-confirm').value;
    const result = bridgeJson(await pywebview.api.apply_brain_structure(brainPreview.previewId, confirmation));
    if (!result.ok) throw new Error(result.error || 'Structure operation failed');
    brainOperationId = result.operationId;
    document.getElementById('brain-structure-title').textContent = 'Structure applied with rollback available';
    document.getElementById('brain-structure-copy').textContent = `Created ${Number(result.createdDirectories?.length || 0)} navigation folders. A local manifest backup was saved before the change: ${result.backupManifest}`;
    document.getElementById('brain-structure-confirm').hidden = true;
    document.getElementById('brain-structure-apply').hidden = true;
    document.getElementById('brain-structure-rollback').hidden = false;
    await loadBrain(true);
}

async function rollbackBrainStructure() {
    if (!brainOperationId) return;
    const result = bridgeJson(await pywebview.api.rollback_brain_structure(brainOperationId));
    document.getElementById('brain-structure-title').textContent = result.ok ? 'Structure rolled back' : 'Rollback retained user content';
    document.getElementById('brain-structure-copy').textContent = result.ok
        ? 'Only the empty folders created by Activity Monitor were removed. Existing content was untouched.'
        : `Rollback stopped safely because ${Number(result.retainedDirectories?.length || 0)} created folders now contain user content.`;
    document.getElementById('brain-structure-rollback').hidden = true;
    brainOperationId = null;
    await loadBrain(true);
}

function setDispatchPhase(state, copy) {
    const element = document.getElementById('dispatch-state');
    element.className = 'status-pill ' + statusClass(state);
    element.textContent = state;
    document.getElementById('dispatch-state-copy').textContent = copy || '';
}

function renderDispatchTarget(target, reason) {
    const container = document.getElementById('dispatch-target');
    emptyNode(container);
    if (!target) {
        const title = document.createElement('div');
        title.className = 'dispatch-target-title';
        title.textContent = 'No destination resolved';
        const meta = document.createElement('div');
        meta.className = 'dispatch-target-meta';
        meta.textContent = reason || 'Dispatch did not find one trustworthy existing owner.';
        container.append(title, meta);
        return;
    }
    const title = document.createElement('div');
    title.className = 'dispatch-target-title';
    title.textContent = `${target.providerLabel} · ${target.title}`;
    const meta = document.createElement('div');
    meta.className = 'dispatch-target-meta';
    meta.textContent = `${target.busy ? 'Busy' : 'Available'} · ${target.state || 'state unknown'}${target.projectName ? ` · ${target.projectName} project Brain` : ''}`;
    const id = document.createElement('div');
    id.className = 'dispatch-target-id';
    id.textContent = target.brainId ? `${target.id} · ${target.brainId}` : target.id;
    const why = document.createElement('div');
    why.className = 'dispatch-reason';
    why.textContent = [target.reason, reason].filter(Boolean).join(' · ');
    container.append(title, meta, id, why);
}

function chooseDispatchTarget(target) {
    dispatchTargetId = target?.id || null;
    renderDispatchTarget(target, dispatchResolution?.reason);
    document.getElementById('dispatch-send').disabled = !dispatchTargetId;
}

function renderDispatchChoices(choices) {
    const container = document.getElementById('dispatch-choices');
    emptyNode(container);
    choices.forEach((target, index) => {
        const row = document.createElement('div');
        row.className = 'dispatch-choice';
        const radio = document.createElement('input');
        radio.type = 'radio';
        radio.name = 'dispatch-choice';
        radio.id = 'dispatch-choice-' + index;
        radio.addEventListener('change', () => chooseDispatchTarget(target));
        const label = document.createElement('label');
        label.htmlFor = radio.id;
        const title = document.createElement('div');
        title.className = 'dispatch-target-title';
        title.textContent = `${target.providerLabel} · ${target.title}`;
        const meta = document.createElement('div');
        meta.className = 'dispatch-target-meta';
        meta.textContent = `${target.state || 'state unknown'}${target.projectName ? ` · ${target.projectName} Brain` : ''} · ${target.reason || 'candidate evidence'}`;
        const id = document.createElement('div');
        id.className = 'dispatch-target-id';
        id.textContent = target.brainId ? `${target.id} · ${target.brainId}` : target.id;
        label.append(title, meta, id);
        row.append(radio, label);
        container.appendChild(row);
    });
}

async function resolveDispatch() {
    const message = document.getElementById('dispatch-message').value;
    dispatchResolution = null;
    dispatchTargetId = null;
    const sendButton = document.getElementById('dispatch-send');
    sendButton.disabled = true;
    sendButton.textContent = 'Send once';
    renderDispatchChoices([]);
    setDispatchPhase('resolving', 'Scanning exact task/session ownership plus project Brain associations; note bodies remain unread.');
    try {
        const result = bridgeJson(await pywebview.api.resolve_dispatch(message));
        dispatchResolution = result;
        if (result.state === 'resolved' && result.target) {
            chooseDispatchTarget(result.target);
            setDispatchPhase('resolved', 'One materially strongest existing destination. Review it, then send once.');
        } else if (result.state === 'ambiguous') {
            renderDispatchTarget(null, result.reason);
            renderDispatchChoices(result.choices || []);
            setDispatchPhase('ambiguous', 'Several plausible existing destinations remain. Choose exactly one; Dispatch will not fan out.');
        } else if (result.state === 'failed before send') {
            setDispatchPhase(
                'failed before send',
                result.error || 'Delivery did not start, but this resolution is no longer valid. Keep the draft and resolve again.'
            );
            dispatchResolution = null;
            dispatchTargetId = null;
            sendButton.textContent = 'Resolve again';
            sendButton.disabled = true;
        } else {
            renderDispatchTarget(null, result.error || result.reason);
            setDispatchPhase(result.state || 'no target', result.error || result.reason || 'No existing owner matched. Nothing was sent.');
        }
    } catch (error) {
        renderDispatchTarget(null, String(error));
        setDispatchPhase('failed', String(error));
    }
    await loadDispatchState();
}

async function sendDispatch() {
    if (!dispatchResolution || !dispatchTargetId) return;
    const message = document.getElementById('dispatch-message').value;
    const diagnostic = document.getElementById('dispatch-diagnostic').checked;
    const sendButton = document.getElementById('dispatch-send');
    sendButton.disabled = true;
    setDispatchPhase('owner preflight', 'Checking the exact existing owner before any message-bearing request.');
    try {
        const result = bridgeJson(await pywebview.api.send_dispatch(
            dispatchResolution.resolutionId,
            dispatchTargetId,
            message,
            diagnostic
        ));
        if (result.ok) {
            setDispatchPhase(
                result.state || 'accepted',
                'The exact destination accepted this delivery. Metadata-only transcript observation continues separately.'
            );
            dispatchResolution = null;
            dispatchTargetId = null;
            sendButton.textContent = 'Send once';
        } else if (result.retrySafe === true && result.state === 'failed before send') {
            const detail = result.error ? ` ${result.error}` : '';
            setDispatchPhase('failed before send', 'Delivery did not start. Keep this unchanged draft; retry this proven pre-send failure or re-resolve it.' + detail);
            sendButton.textContent = 'Retry pre-send';
            sendButton.disabled = false;
        } else if (result.state === 'failed before send' && result.reconciliationRequired === true) {
            const detail = result.error ? ` ${result.error}` : '';
            setDispatchPhase('failed before send', 'No new delivery started. Existing receipt history may conceal an earlier attempt, so retry is disabled until that metadata-only history is repaired or reconciled.' + detail);
            dispatchResolution = null;
            dispatchTargetId = null;
            sendButton.textContent = 'Reconcile history';
            sendButton.disabled = true;
        } else if (result.state === 'failed before send') {
            const detail = result.error ? ` ${result.error}` : '';
            setDispatchPhase('failed before send', 'Delivery did not start. Keep this draft; re-resolve it, then retry when ready.' + detail);
            dispatchResolution = null;
            dispatchTargetId = null;
            sendButton.textContent = 'Resolve again';
            sendButton.disabled = true;
        } else {
            const detail = result.error ? ` ${result.error}` : '';
            setDispatchPhase(
                'uncertain after send',
                'Delivery may have occurred. Retry is disabled, this draft is preserved, and metadata-only receipt reconciliation is required.' + detail
            );
            dispatchResolution = null;
            dispatchTargetId = null;
            sendButton.textContent = 'Reconcile first';
            sendButton.disabled = true;
        }
    } catch (error) {
        setDispatchPhase('uncertain after send', 'The bridge response was interrupted. Preserve this draft and reconcile history before any retry. ' + String(error));
        dispatchResolution = null;
        dispatchTargetId = null;
        sendButton.textContent = 'Reconcile first';
        sendButton.disabled = true;
    }
    await loadDispatchState();
}

function renderDispatchHistory(entries) {
    const container = document.getElementById('dispatch-history');
    emptyNode(container);
    if (!entries.length) {
        const empty = document.createElement('div');
        empty.className = 'dispatch-empty';
        empty.textContent = 'No local dispatch receipts yet.';
        container.appendChild(empty);
        return;
    }
    entries.slice(0, 20).forEach(entry => {
        const row = document.createElement('div');
        row.className = 'history-entry';
        const top = document.createElement('div');
        top.className = 'history-top';
        const destination = document.createElement('div');
        destination.className = 'history-destination';
        destination.textContent = entry.destinationTitle ? `${entry.provider} · ${entry.destinationTitle}` : 'No destination';
        top.append(destination, pill(entry.state));
        const meta = document.createElement('div');
        meta.className = 'history-meta';
        const observed = new Date(entry.timestamp);
        meta.textContent = `${Number.isNaN(observed.valueOf()) ? entry.timestamp : observed.toLocaleString()} · ${entry.destinationId || 'fail-closed resolution'}`;
        const reason = document.createElement('div');
        reason.className = 'history-reason';
        reason.textContent = entry.routingReason || '';
        const hash = document.createElement('div');
        hash.className = 'history-hash';
        hash.textContent = 'SHA-256 ' + entry.sha256;
        row.append(top, meta, reason, hash);
        container.appendChild(row);
    });
}

async function loadDispatchState() {
    if (!apiReady) return;
    try {
        const result = bridgeJson(await pywebview.api.get_dispatch_state());
        if (!result.ok) throw new Error(result.error || 'Dispatch state unavailable');
        renderDispatchHistory(result.history || []);
        const readiness = result.readiness || {};
        const historyReady = readiness.historyAvailable !== false;
        const ready = readiness.codexExactTask && readiness.claudeExactSession && historyReady;
        const element = document.getElementById('dispatch-readiness');
        element.className = 'status-pill ' + (ready ? 'connected' : historyReady ? 'ambiguous' : 'failed');
        element.textContent = ready ? 'Codex + Claude ready' : historyReady ? 'Route availability limited' : 'Receipt history needs repair';
        element.title = historyReady ? '' : (result.warnings || [])[0] || 'Sending is disabled until receipt history is reconciled.';
    } catch (error) {
        const element = document.getElementById('dispatch-readiness');
        element.className = 'status-pill failed';
        element.textContent = 'Routing unavailable';
    }
}

function guardCount(value) {
    return value != null && finite(Number(value)) ? String(Number(value)) : '—';
}

function guardAge(seconds) {
    if (!finite(Number(seconds))) return 'age unavailable';
    const value = Math.max(0, Number(seconds));
    if (value < 60) return Math.round(value) + 's ago';
    if (value < 3600) return Math.round(value / 60) + 'm ago';
    if (value < 86400) return (value / 3600).toFixed(value < 7200 ? 1 : 0) + 'h ago';
    return (value / 86400).toFixed(1) + 'd ago';
}

function guardBridgeFallbackPayload(last, nowMs = Date.now()) {
    if (!last || typeof last !== 'object') {
        return {
            ok:false,state:'offline',statusLabel:'OFFLINE',supported:true,installed:null,available:false,retained:false,
            detail:'KE Guard status is temporarily unavailable.',configuredMode:null,observedAt:null,ageSeconds:null,
            activeSuspects:{count:0,items:[]},pendingRemediation:null,kills24h:null,trends:{load:null,diskFree:null},
            recentEvidence:[],ledgerAvailable:false,killsWindowComplete:false,readErrorCode:'bridge_unavailable',
        };
    }
    const priorState = String(last.state || 'offline').toLowerCase();
    const terminalStates = new Set(['offline','not-installed','unsupported']);
    const observedMs = typeof last.observedAt === 'string' ? Date.parse(last.observedAt) : NaN;
    const rawAge = Number.isFinite(observedMs) && Number.isFinite(Number(nowMs))
        ? Math.max(0, (Number(nowMs) - observedMs) / 1000)
        : null;
    const ageSeconds = rawAge == null ? null : Math.round(rawAge * 10) / 10;
    const configuredOfflineAfter = last.offlineAfterSeconds;
    const offlineAfterSeconds = configuredOfflineAfter != null
        && Number.isFinite(Number(configuredOfflineAfter))
        && Number(configuredOfflineAfter) > 0
        ? Number(configuredOfflineAfter)
        : 900;
    const statusLabel = state => state === 'not-installed' ? 'NOT INSTALLED' : state.toUpperCase();

    if (terminalStates.has(priorState)) {
        const priorAge = last.ageSeconds != null && Number.isFinite(Number(last.ageSeconds))
            ? Number(last.ageSeconds)
            : null;
        return {
            ...last,
            ok:false,
            state:priorState,
            statusLabel:statusLabel(priorState),
            ageSeconds:ageSeconds == null ? priorAge : ageSeconds,
            readErrorCode:'bridge_unavailable',
        };
    }

    const retainable = ['armed','dry-run','stale'].includes(priorState);
    const state = retainable && ageSeconds != null && ageSeconds <= offlineAfterSeconds ? 'stale' : 'offline';
    return {
        ...last,
        ok:false,
        state,
        statusLabel:statusLabel(state),
        retained:true,
        ageSeconds,
        readErrorCode:'bridge_unavailable',
        detail:state === 'stale'
            ? 'Showing the last valid KE Guard snapshot after a bridge read failure.'
            : 'The last valid KE Guard snapshot expired while bridge reads were unavailable.',
    };
}

function renderGuardSpark(id, trend, suffix) {
    const container = document.getElementById(id);
    emptyNode(container);
    const points = Array.isArray(trend?.points) ? trend.points.filter(point => finite(Number(point?.value))) : [];
    if (!points.length) {
        container.setAttribute('aria-label', 'No trend samples available');
        return;
    }
    const values = points.map(point => Number(point.value));
    const minimum = Math.min(...values);
    const maximum = Math.max(...values);
    const span = Math.max(maximum - minimum, Math.max(Math.abs(maximum), 1) * 0.05);
    values.forEach(value => {
        const bar = document.createElement('span');
        bar.style.height = (18 + 82 * ((value - minimum) / span)).toFixed(1) + '%';
        bar.title = value.toFixed(suffix === ' GB' ? 1 : 2) + suffix;
        container.appendChild(bar);
    });
    container.setAttribute('aria-label', `${trend.direction || 'steady'} trend across ${points.length} samples`);
}

function renderGuardStatus(payload) {
    lastGuardStatus = payload;
    const state = payload?.state || 'offline';
    const stateElement = document.getElementById('guard-state');
    stateElement.className = 'status-pill ' + statusClass(state);
    stateElement.textContent = payload?.statusLabel || state;

    const mode = payload?.configuredMode ? String(payload.configuredMode).toUpperCase() : '—';
    document.getElementById('guard-mode').textContent = mode;
    document.getElementById('guard-mode-detail').textContent = payload?.retained ? 'Last valid local state' : payload?.installed ? 'Local guardian configuration' : 'Not available on this host';
    document.getElementById('guard-observed').textContent = payload?.observedAt ? observedClock(payload.observedAt) : '—';
    document.getElementById('guard-observed-detail').textContent = payload?.observedAt ? guardAge(payload.ageSeconds) : 'No valid observation';

    const suspects = payload?.activeSuspects || {count:0,items:[]};
    document.getElementById('guard-suspects').textContent = payload?.available ? String(Number(suspects.count || 0)) : '—';
    const suspectItems = Array.isArray(suspects.items) ? suspects.items : [];
    document.getElementById('guard-suspects-detail').textContent = suspectItems.length
        ? suspectItems.map(item => `PID ${item.pid || '—'} · streak ${item.streak} · ${item.childCount} children`).join(' | ')
        : payload?.available ? 'No active churn streaks' : 'No validated state';

    document.getElementById('guard-kills').textContent = guardCount(payload?.kills24h);
    document.getElementById('guard-kills-detail').textContent = payload?.kills24h != null ? 'Actual SIGTERM remediations' : payload?.ledgerAvailable ? '24-hour evidence window incomplete' : 'Evidence ledger unavailable';

    const unavailable = document.getElementById('guard-unavailable');
    const showAvailability = !['armed','dry-run'].includes(state) || payload?.retained;
    unavailable.hidden = !showAvailability;
    document.getElementById('guard-unavailable-title').textContent = state === 'not-installed' ? 'KE Guard is not installed' : state === 'unsupported' ? 'KE Guard is unavailable on this OS' : state === 'stale' ? 'KE Guard state is stale' : 'KE Guard is offline';
    document.getElementById('guard-unavailable-copy').textContent = payload?.detail || 'No current KE Guard state is available.';

    const load = payload?.trends?.load;
    document.getElementById('guard-load-value').textContent = finite(Number(load?.current)) ? Number(load.current).toFixed(1) : '—';
    document.getElementById('guard-load-meta').textContent = load ? `${load.direction} · ${load.delta >= 0 ? '+' : ''}${Number(load.delta).toFixed(1)} across ${load.samples} samples` : 'Waiting for samples';
    renderGuardSpark('guard-load-spark', load, ' load');

    const disk = payload?.trends?.diskFree;
    document.getElementById('guard-disk-value').textContent = finite(Number(disk?.current)) ? Number(disk.current).toFixed(1) + ' GB' : '—';
    document.getElementById('guard-disk-meta').textContent = disk ? `${disk.direction} · ${disk.delta >= 0 ? '+' : ''}${Number(disk.delta).toFixed(1)} GB across ${disk.samples} samples` : 'Waiting for samples';
    renderGuardSpark('guard-disk-spark', disk, ' GB');

    const pendingContainer = document.getElementById('guard-pending');
    emptyNode(pendingContainer);
    const pending = payload?.pendingRemediation;
    if (!pending) {
        const empty = document.createElement('div');
        empty.className = 'guard-empty';
        empty.textContent = payload?.available ? 'No remediation is pending.' : 'Pending remediation is unavailable without a valid state.';
        pendingContainer.appendChild(empty);
    } else {
        const card = document.createElement('div');
        card.className = 'guard-pending';
        card.appendChild(pill(pending.phase || 'pending'));
        const copy = document.createElement('div');
        copy.className = 'guard-pending-copy';
        copy.textContent = `PID ${pending.pid || '—'} · ${Number(pending.targetCount || 0)} verified target${Number(pending.targetCount || 0) === 1 ? '' : 's'} · ${pending.evidenceAvailable ? 'evidence retained' : 'no evidence receipt'}`;
        card.appendChild(copy);
        pendingContainer.appendChild(card);
    }

    const evidenceContainer = document.getElementById('guard-evidence');
    emptyNode(evidenceContainer);
    const evidence = Array.isArray(payload?.recentEvidence) ? payload.recentEvidence : [];
    if (!evidence.length) {
        const empty = document.createElement('div');
        empty.className = 'guard-empty';
        empty.textContent = payload?.ledgerAvailable ? 'No recent alert or remediation evidence.' : 'The sanitized evidence ledger is unavailable.';
        evidenceContainer.appendChild(empty);
    } else {
        evidence.slice(0, 12).forEach(item => {
            const row = document.createElement('div');
            row.className = 'guard-evidence-row';
            const top = document.createElement('div');
            top.className = 'guard-evidence-top';
            const label = document.createElement('div');
            label.className = 'guard-evidence-label';
            label.textContent = item.label || 'KE Guard evidence';
            top.append(label, pill(item.kind || 'evidence'));
            const meta = document.createElement('div');
            meta.className = 'guard-evidence-meta';
            const observed = item.observedAt ? new Date(item.observedAt) : null;
            const observedText = observed && Number.isFinite(observed.getTime()) ? observed.toLocaleString() : 'time unavailable';
            meta.textContent = [observedText, item.pid ? `PID ${item.pid}` : null, item.evidenceAvailable ? 'evidence retained' : null].filter(Boolean).join(' · ');
            row.append(top, meta);
            evidenceContainer.appendChild(row);
        });
    }
}

async function loadGuardStatus() {
    if (!apiReady) return;
    try {
        renderGuardStatus(bridgeJson(await pywebview.api.get_guard_status()));
    } catch (_) {
        renderGuardStatus(guardBridgeFallbackPayload(lastGuardStatus, Date.now()));
    }
}

document.getElementById('brain-rescan').addEventListener('click', () => loadBrain(true));
document.getElementById('brain-visual-retry').addEventListener('click', () => loadBrain(true));
document.getElementById('brain-view-files').addEventListener('click', () => setBrainView('files'));
document.getElementById('brain-view-visual').addEventListener('click', () => setBrainView('visual'));
document.getElementById('brain-visual-fit').addEventListener('click', () => {
    brainGraphTransform = {x:0, y:0, scale:1};
    applyBrainGraphTransform();
});
document.getElementById('brain-visual-zoom-in').addEventListener('click', () => {
    brainGraphTransform.scale = Math.min(2.4, brainGraphTransform.scale * 1.18);
    applyBrainGraphTransform();
});
document.getElementById('brain-visual-zoom-out').addEventListener('click', () => {
    brainGraphTransform.scale = Math.max(.6, brainGraphTransform.scale / 1.18);
    applyBrainGraphTransform();
});
const brainGraph = document.getElementById('brain-graph');
brainGraph.addEventListener('pointerdown', event => {
    if (event.target.closest?.('.brain-graph-node')) return;
    const rect = brainGraph.getBoundingClientRect();
    brainGraphDrag = {pointerId:event.pointerId, x:event.clientX, y:event.clientY, factor:1000 / Math.max(1, rect.width)};
    brainGraph.classList.add('dragging');
    brainGraph.setPointerCapture(event.pointerId);
});
brainGraph.addEventListener('pointermove', event => {
    if (!brainGraphDrag || brainGraphDrag.pointerId !== event.pointerId) return;
    brainGraphTransform.x += (event.clientX - brainGraphDrag.x) * brainGraphDrag.factor;
    brainGraphTransform.y += (event.clientY - brainGraphDrag.y) * brainGraphDrag.factor;
    brainGraphDrag.x = event.clientX;
    brainGraphDrag.y = event.clientY;
    applyBrainGraphTransform();
});
const endBrainGraphDrag = event => {
    if (!brainGraphDrag || brainGraphDrag.pointerId !== event.pointerId) return;
    brainGraphDrag = null;
    brainGraph.classList.remove('dragging');
};
brainGraph.addEventListener('pointerup', endBrainGraphDrag);
brainGraph.addEventListener('pointercancel', endBrainGraphDrag);
brainGraph.addEventListener('wheel', event => {
    event.preventDefault();
    const multiplier = event.deltaY < 0 ? 1.1 : 1 / 1.1;
    brainGraphTransform.scale = Math.max(.6, Math.min(2.4, brainGraphTransform.scale * multiplier));
    applyBrainGraphTransform();
}, {passive:false});
document.getElementById('brain-browser-close').addEventListener('click', closeBrainBrowser);
document.getElementById('brain-browser-back').addEventListener('click', () => {
    if (!brainBrowserState) return;
    if (brainBrowserState.view === 'note') {
        const parentPath = brainBrowserState.parentPath || '';
        clearBrainNoteBody();
        loadBrainDirectory(parentPath, 0);
    } else if (brainBrowserState.view === 'directory' && brainBrowserState.parentPath != null) {
        loadBrainDirectory(brainBrowserState.parentPath, 0);
    } else if (brainBrowserState.view === 'directory' && brainBrowserState.originView === 'visual') {
        restoreBrainBrowserOrigin();
    }
});
document.getElementById('brain-page-previous').addEventListener('click', () => {
    if (brainBrowserState?.view === 'directory') loadBrainDirectory(brainBrowserState.relativePath, Math.max(0, brainBrowserState.page - 1));
});
document.getElementById('brain-page-next').addEventListener('click', () => {
    if (brainBrowserState?.view === 'directory') loadBrainDirectory(brainBrowserState.relativePath, brainBrowserState.page + 1);
});
document.getElementById('brain-create').addEventListener('click', async () => {
    const name = window.prompt('Name this local Brain', 'My AI Brain');
    if (name == null || !name.trim()) return;
    const result = bridgeJson(await pywebview.api.create_brain(name));
    if (!result.ok) throw new Error(result.error || 'Brain creation failed');
    lastBrainInventory = result.inventory;
    renderBrain(result.inventory);
});
document.getElementById('brain-structure-confirm').addEventListener('input', event => {
    const changes = brainPreview?.createDirectories?.length || 0;
    document.getElementById('brain-structure-apply').disabled = event.target.value !== 'APPLY' || changes === 0;
});
document.getElementById('brain-structure-apply').addEventListener('click', applyBrainStructure);
document.getElementById('brain-structure-cancel').addEventListener('click', resetBrainStructure);
document.getElementById('brain-structure-rollback').addEventListener('click', rollbackBrainStructure);
document.getElementById('dispatch-resolve').addEventListener('click', resolveDispatch);
document.getElementById('dispatch-send').addEventListener('click', sendDispatch);
document.getElementById('dispatch-message').addEventListener('input', () => {
    if (!dispatchResolution) return;
    dispatchResolution = null;
    dispatchTargetId = null;
    document.getElementById('dispatch-send').disabled = true;
    document.getElementById('dispatch-send').textContent = 'Send once';
    renderDispatchChoices([]);
    renderDispatchTarget(null, 'Message changed. Resolve again before sending.');
    setDispatchPhase('ready', 'Message changed. Resolve again so the reviewed SHA-256 and destination stay bound.');
});

function fmtBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
    if (b < 1024*1024*1024) return (b/(1024*1024)).toFixed(1) + ' MB';
    return (b/(1024*1024*1024)).toFixed(2) + ' GB';
}
function fmtRate(b) { return fmtBytes(b) + '/s'; }

function diskCleanupSetStatus(message, error = false) {
    const node = document.getElementById('disk-cleanup-status');
    node.textContent = String(message || '');
    node.classList.toggle('error', Boolean(error));
}

function diskCleanupFinishBusy() {
    diskCleanupJobId = null;
    document.getElementById('disk-cleanup-progress').hidden = true;
    document.getElementById('disk-cleanup-cancel').hidden = true;
    const scan = document.getElementById('disk-cleanup-scan');
    scan.disabled = false;
    scan.textContent = diskCleanupResult ? 'Rescan' : 'Scan for space';
}

function diskCleanupRows() {
    const rows = Array.isArray(diskCleanupResult?.reviewCandidates)
        ? diskCleanupResult.reviewCandidates
        : Array.isArray(diskCleanupResult?.candidates) ? diskCleanupResult.candidates : [];
    return rows.filter(item => {
        if (!item || typeof item.id !== 'string' || typeof item.target !== 'string') return false;
        if (diskCleanupCategory !== 'all' && item.category !== diskCleanupCategory) return false;
        const safe = String(item.riskClass || '').toUpperCase() === 'SAFE';
        if (diskCleanupFilter === 'quick' && !safe) return false;
        if (diskCleanupFilter === 'review' && safe) return false;
        return true;
    }).slice(0, 150);
}

function diskCleanupSelectionState() {
    const validIds = new Set((diskCleanupResult?.reviewCandidates || []).map(item => item.id));
    Array.from(diskCleanupSelected).forEach(id => { if (!validIds.has(id)) diskCleanupSelected.delete(id); });
    const count = diskCleanupSelected.size;
    document.getElementById('disk-cleanup-selection').textContent = count + ' of ' + DISK_CLEANUP_MAX_SELECTION + ' selected';
    document.getElementById('disk-cleanup-reveal').disabled = count === 0 || !diskCleanupAnalysisId;
    document.getElementById('disk-cleanup-clear').disabled = count === 0;
    document.getElementById('disk-cleanup-select-top').disabled = !(diskCleanupResult?.reviewCandidates || []).some(item => String(item.riskClass || '').toUpperCase() === 'SAFE');
}

function renderDiskCleanupCategories() {
    const list = document.getElementById('disk-cleanup-category-list');
    emptyNode(list);
    const categories = Array.isArray(diskCleanupResult?.categories) ? diskCleanupResult.categories : [];
    if (!diskCleanupResult) {
        const empty = document.createElement('div');
        empty.className = 'disk-cleanup-empty';
        empty.textContent = 'Run a scan to map reclaimable space.';
        list.appendChild(empty);
        document.getElementById('disk-cleanup-category-total').textContent = '0 found';
        return;
    }
    const total = Number(diskCleanupResult.reviewCandidateCount || (diskCleanupResult.reviewCandidates || []).length || 0);
    document.getElementById('disk-cleanup-category-total').textContent = total + ' found';
    const choices = [{id:'all', label:'All ranked', bytes:Number(diskCleanupResult.reviewCandidateBytes || 0), targetCount:total, state:'deduplicated'}, ...categories];
    choices.forEach(category => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'disk-cleanup-category' + (diskCleanupCategory === category.id ? ' active' : '');
        button.setAttribute('aria-pressed', String(diskCleanupCategory === category.id));
        const name = document.createElement('span');
        name.className = 'disk-cleanup-category-name';
        name.textContent = String(category.label || category.id || 'Category');
        const bytes = document.createElement('span');
        bytes.className = 'disk-cleanup-category-bytes';
        bytes.textContent = fmtBytes(Math.max(0, Number(category.bytes || 0)));
        const meta = document.createElement('span');
        meta.className = 'disk-cleanup-category-meta';
        meta.textContent = Number(category.targetCount || 0) + ' found · ' + String(category.state || 'review');
        button.append(name, bytes, meta);
        button.addEventListener('click', () => {
            diskCleanupCategory = category.id;
            renderDiskCleanupCategories();
            renderDiskCleanupCandidates();
        });
        list.appendChild(button);
    });
}

function renderDiskCleanupCandidates() {
    const list = document.getElementById('disk-cleanup-candidate-list');
    emptyNode(list);
    const rows = diskCleanupRows();
    if (!rows.length) {
        const empty = document.createElement('div');
        empty.className = 'disk-cleanup-empty';
        empty.textContent = diskCleanupResult ? 'No candidates match this view. Protected and changing items stay excluded.' : 'No scan yet. Nothing runs in the background.';
        list.appendChild(empty);
        diskCleanupSelectionState();
        return;
    }
    const categoryLabels = new Map((diskCleanupResult?.categories || []).map(category => [category.id, category.label]));
    rows.forEach(item => {
        const row = document.createElement('label');
        row.className = 'disk-cleanup-candidate';
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = diskCleanupSelected.has(item.id);
        checkbox.setAttribute('aria-label', 'Select ' + item.target + ' for Finder reveal');
        checkbox.addEventListener('change', () => {
            if (checkbox.checked && diskCleanupSelected.size >= DISK_CLEANUP_MAX_SELECTION) {
                checkbox.checked = false;
                diskCleanupSetStatus('Selection is limited to 12 exact Finder reveals per review.', true);
                return;
            }
            if (checkbox.checked) diskCleanupSelected.add(item.id);
            else diskCleanupSelected.delete(item.id);
            diskCleanupSelectionState();
        });
        const main = document.createElement('span');
        main.className = 'disk-cleanup-candidate-main';
        const target = document.createElement('span');
        target.className = 'disk-cleanup-candidate-target';
        target.textContent = item.target;
        const detail = document.createElement('span');
        detail.className = 'disk-cleanup-candidate-detail';
        const age = Number(item.factors?.ageDays);
        const reason = document.createElement('span');
        reason.className = 'disk-cleanup-candidate-reason';
        reason.textContent = String(categoryLabels.get(item.category) || item.category || 'Local data') + (Number.isFinite(age) ? ' · ' + Math.round(age) + 'd old' : '') + ' · ' + String(item.reason || 'Review in Finder');
        reason.title = String(item.reason || 'Review in Finder');
        detail.appendChild(reason);
        main.append(target, detail);
        const side = document.createElement('span');
        side.className = 'disk-cleanup-candidate-side';
        const bytes = document.createElement('span');
        bytes.className = 'disk-cleanup-candidate-bytes';
        bytes.textContent = fmtBytes(Math.max(0, Number(item.bytes || 0)));
        const risk = document.createElement('span');
        risk.className = 'disk-cleanup-risk ' + String(item.riskClass || '').toLowerCase().replaceAll(' ', '-');
        risk.textContent = String(item.riskClass || 'Review');
        side.append(bytes, document.createElement('br'), risk);
        row.append(checkbox, main, side);
        list.appendChild(row);
    });
    diskCleanupSelectionState();
}

function renderDiskCleanupResult(result, hadPriorResult = false) {
    diskCleanupResult = result;
    diskCleanupAnalysisId = typeof result?.analysisId === 'string' ? result.analysisId : null;
    diskCleanupSelected.clear();
    diskCleanupCategory = 'all';
    const potential = Math.max(0, Number(result?.reviewCandidateBytes || 0));
    const freeBytes = Number(result?.performanceAssessment?.storage?.freeBytes);
    document.getElementById('disk-cleanup-potential').textContent = fmtBytes(potential);
    document.getElementById('disk-cleanup-count').textContent = String(Number(result?.reviewCandidateCount || (result?.reviewCandidates || []).length || 0));
    const free = document.getElementById('disk-cleanup-free');
    const detail = document.getElementById('disk-cleanup-free-detail');
    if (Number.isFinite(freeBytes) && freeBytes >= 0) {
        free.textContent = fmtBytes(freeBytes);
        if (diskCleanupInitialFreeBytes === null) diskCleanupInitialFreeBytes = freeBytes;
        const delta = freeBytes - diskCleanupInitialFreeBytes;
        detail.className = 'disk-cleanup-delta' + (delta > 0 ? ' positive' : delta < 0 ? ' negative' : '');
        detail.textContent = hadPriorResult ? (delta >= 0 ? '+' : '−') + fmtBytes(Math.abs(delta)) + ' system-wide since first scan' : 'measured when scanned';
        detail.title = hadPriorResult ? 'System-wide change only; Activity Monitor does not attribute this delta to a specific action.' : 'Current system-wide free space at scan time.';
    } else {
        free.textContent = 'Unavailable';
        detail.textContent = 'macOS measurement unavailable';
        detail.className = 'disk-cleanup-delta';
    }
    renderDiskCleanupCategories();
    renderDiskCleanupCandidates();
    const excluded = (result?.exclusions || []).reduce((sum, item) => sum + Math.max(0, Number(item?.count || 0)), 0);
    const count = Number(result?.reviewCandidateCount || (result?.reviewCandidates || []).length || 0);
    if (result?.state === 'partial') {
        diskCleanupSetStatus('Partial scan · ' + count + ' ranked · ' + excluded + ' changing, protected, or bounded items excluded. ' + String(result.detail || ''), true);
    } else {
        diskCleanupSetStatus('Scan complete · ' + count + ' ranked · ' + excluded + ' excluded by safety or scope.');
    }
}

async function pollDiskCleanup(jobId, generation) {
    if (!diskCleanupJobId || diskCleanupJobId !== jobId || generation !== diskCleanupGeneration) return;
    try {
        const payload = bridgeJson(await pywebview.api.get_disk_cleanup_scan(jobId));
        if (generation !== diskCleanupGeneration) return;
        if (payload.state === 'running' || payload.state === 'cancelling') {
            window.setTimeout(() => pollDiskCleanup(jobId, generation), 180);
            return;
        }
        const hadPrior = Boolean(diskCleanupResult);
        if (payload.state === 'complete' || payload.state === 'partial') renderDiskCleanupResult(payload, hadPrior);
        else if (payload.state === 'cancelled') diskCleanupSetStatus('Scan cancelled. Existing disk monitoring was unaffected.');
        else diskCleanupSetStatus(payload.error || payload.detail || 'The scan stopped safely. Disk monitoring is still active.', true);
    } catch (_) {
        if (generation === diskCleanupGeneration) diskCleanupSetStatus('The scan bridge was interrupted. Disk monitoring is still active.', true);
    }
    if (generation === diskCleanupGeneration) diskCleanupFinishBusy();
}

async function startDiskCleanupScan() {
    if (!apiReady || diskCleanupJobId) return;
    const generation = ++diskCleanupGeneration;
    document.getElementById('disk-cleanup-scan').disabled = true;
    document.getElementById('disk-cleanup-cancel').hidden = false;
    document.getElementById('disk-cleanup-progress').hidden = false;
    diskCleanupSetStatus('Scanning bounded local metadata · file contents and network stay untouched…');
    try {
        const payload = bridgeJson(await pywebview.api.start_disk_cleanup_scan());
        if (generation !== diskCleanupGeneration) return;
        if (payload.ok === false || payload.state === 'unsupported' || payload.state === 'failed') {
            diskCleanupSetStatus(payload.error || payload.detail || 'Cleanup review is unavailable on this Mac.', true);
            diskCleanupFinishBusy();
            return;
        }
        if (payload.state === 'running') {
            diskCleanupJobId = payload.jobId;
            pollDiskCleanup(payload.jobId, generation);
            return;
        }
        const hadPrior = Boolean(diskCleanupResult);
        if (payload.state === 'complete' || payload.state === 'partial') renderDiskCleanupResult(payload, hadPrior);
        else diskCleanupSetStatus(payload.detail || 'The scan stopped safely.', payload.state !== 'cancelled');
    } catch (_) {
        diskCleanupSetStatus('Cleanup review is temporarily unavailable. Disk monitoring is still active.', true);
    }
    diskCleanupFinishBusy();
}

async function cancelDiskCleanupScan() {
    if (!diskCleanupJobId) return;
    const jobId = diskCleanupJobId;
    diskCleanupSetStatus('Cancelling at the next bounded metadata boundary…');
    try { await pywebview.api.cancel_disk_cleanup_scan(jobId); }
    catch (_) { diskCleanupSetStatus('Cancellation could not be confirmed; this review holds no deletion authority.', true); }
}

async function openDiskCleanup() {
    const sheet = document.getElementById('disk-cleanup-sheet');
    diskCleanupReturnFocus = document.activeElement;
    sheet.hidden = false;
    document.getElementById('disk-cleanup-close').focus();
    if (!apiReady) {
        diskCleanupSetStatus('Waiting for the local bridge…');
        return;
    }
    try {
        const capabilities = bridgeJson(await pywebview.api.get_disk_cleanup_capabilities());
        if (capabilities.ok === false || capabilities.supported === false) {
            document.getElementById('disk-cleanup-scan').disabled = true;
            diskCleanupSetStatus(capabilities.error || 'Cleanup review requires current-user macOS execution.', true);
        } else if (!diskCleanupResult && !diskCleanupJobId) {
            diskCleanupSetStatus('Ready · scanning starts only when you ask · Activity Monitor never deletes files.');
        }
    } catch (_) {
        diskCleanupSetStatus('Cleanup capabilities are temporarily unavailable. Disk monitoring is still active.', true);
    }
}

async function closeDiskCleanup(restoreFocus = true) {
    const sheet = document.getElementById('disk-cleanup-sheet');
    if (sheet.hidden) return;
    const activeJob = diskCleanupJobId;
    diskCleanupGeneration += 1;
    diskCleanupJobId = null;
    sheet.hidden = true;
    diskCleanupFinishBusy();
    if (activeJob && apiReady) {
        try { await pywebview.api.cancel_disk_cleanup_scan(activeJob); } catch (_) {}
    }
    if (restoreFocus && diskCleanupReturnFocus && typeof diskCleanupReturnFocus.focus === 'function') diskCleanupReturnFocus.focus();
}

async function revealDiskCleanupSelection() {
    if (!diskCleanupAnalysisId || !diskCleanupSelected.size) return;
    const button = document.getElementById('disk-cleanup-reveal');
    button.disabled = true;
    diskCleanupSetStatus('Revalidating exact identities before Finder handoff…');
    try {
        const payload = bridgeJson(await pywebview.api.reveal_disk_cleanup_candidates(diskCleanupAnalysisId, Array.from(diskCleanupSelected)));
        if (payload.ok === false) {
            diskCleanupSetStatus(payload.error || payload.detail || 'Selected items changed. Rescan before review.', true);
        } else {
            diskCleanupSetStatus(payload.detail + (payload.skippedCount ? ' ' + payload.skippedCount + ' changed item(s) were skipped; rescan before retry.' : ''));
        }
    } catch (_) {
        diskCleanupSetStatus('Finder handoff was unavailable. Nothing was changed.', true);
    } finally {
        diskCleanupSelectionState();
    }
}

async function openDiskCleanupDestination(destination) {
    diskCleanupSetStatus('Opening the fixed macOS review destination…');
    try {
        const payload = bridgeJson(await pywebview.api.open_disk_cleanup_destination(destination));
        diskCleanupSetStatus(payload.ok === false ? (payload.error || payload.detail) : payload.detail, payload.ok === false);
    } catch (_) {
        diskCleanupSetStatus('macOS could not open that review destination. Nothing was changed.', true);
    }
}

function sortProcs(procs, key, dir) {
    return procs.sort((a,b) => {
        let va = a[key], vb = b[key];
        if (typeof va === 'string') { va = va.toLowerCase(); vb = (vb||'').toLowerCase(); }
        if (va < vb) return dir === 'asc' ? -1 : 1;
        if (va > vb) return dir === 'asc' ? 1 : -1;
        return 0;
    });
}
function filterProcs(procs) {
    if (!searchFilter) return procs;
    return procs.filter(p => (p.name||'').toLowerCase().includes(searchFilter));
}
function actionCell(pid) {
    return '<button class="act-btn danger" onclick="killProc('+pid+',true);event.stopPropagation()">✕</button>';
}

function renderCpuTable(procs) {
    const st = sortState.cpu;
    const sorted = sortProcs(filterProcs([...procs]), st.key, st.dir);
    document.getElementById('cpu-tbody').innerHTML = sorted.slice(0,200).map(p =>
        '<tr onclick="selectedPid='+Number(p.pid)+'" class="'+(p.pid===selectedPid?'selected':'')+'"><td>'+esc(p.name)+'</td><td class="num">'+Number(p.cpu_percent).toFixed(1)+'</td><td class="num">'+Number(p.threads)+'</td><td class="num">'+Number(p.pid)+'</td><td>'+esc(p.username)+'</td><td>'+actionCell(Number(p.pid))+'</td></tr>'
    ).join('');
}
function renderMemTable(procs) {
    const st = sortState.memory;
    const sorted = sortProcs(filterProcs([...procs]), st.key, st.dir);
    document.getElementById('mem-tbody').innerHTML = sorted.slice(0,200).map(p =>
        '<tr onclick="selectedPid='+Number(p.pid)+'" class="'+(p.pid===selectedPid?'selected':'')+'"><td>'+esc(p.name)+'</td><td class="num">'+Number(p.memory_mb).toFixed(1)+' MB</td><td class="num">'+Number(p.memory_percent).toFixed(1)+'</td><td class="num">'+Number(p.threads)+'</td><td class="num">'+Number(p.pid)+'</td><td>'+esc(p.username)+'</td><td>'+actionCell(Number(p.pid))+'</td></tr>'
    ).join('');
}
function energyNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 ? number : 0;
}
function energyStateRow(message, state = 'loading') {
    return '<tr class="energy-state-row '+state+'"><td colspan="6"><span class="energy-state-dot"></span>'+message+'</td></tr>';
}
function showEnergyLoading() {
    const body = document.getElementById('energy-tbody');
    if (!lastEnergyProcesses.length) body.innerHTML = energyStateRow('Loading current energy activity…');
    body.dataset.refreshState = 'loading';
    const total = document.getElementById('energy-total');
    if (!lastEnergyProcesses.length) total.textContent = 'Loading…';
    total.title = '';
    if (!energyHistory.length) document.getElementById('energy-bar-chart').innerHTML = '<div class="energy-graph-state">Loading current sample…</div>';
}
function renderEnergyUnavailable() {
    const body = document.getElementById('energy-tbody');
    body.dataset.refreshState = 'unavailable';
    const total = document.getElementById('energy-total');
    if (!lastEnergyProcesses.length) {
        body.innerHTML = energyStateRow('Energy activity is temporarily unavailable. Retrying…', 'unavailable');
        total.textContent = 'Unavailable';
        if (!energyHistory.length) document.getElementById('energy-bar-chart').innerHTML = '<div class="energy-graph-state">Sample unavailable · retrying</div>';
    } else {
        total.title = 'Live refresh unavailable; showing the last complete sample.';
    }
}
function normalizeEnergyProcess(process) {
    const source = process && typeof process === 'object' ? process : {};
    const pid = Number(source.pid);
    return {
        name: typeof source.name === 'string' && source.name ? source.name : 'Unknown',
        energy_impact: energyNumber(source.energy_impact),
        avg_energy_impact: energyNumber(source.avg_energy_impact),
        app_nap: source.app_nap === 'Yes' ? 'Yes' : 'No',
        preventing_sleep: source.preventing_sleep === 'Yes' ? 'Yes' : 'No',
        pid: Number.isInteger(pid) && pid > 0 ? pid : 0,
    };
}
function renderEnergyTable(procs) {
    const normalized = Array.isArray(procs) ? procs.map(normalizeEnergyProcess) : [];
    lastEnergyProcesses = normalized;
    const st = sortState.energy;
    const sorted = sortProcs(filterProcs([...normalized]), st.key, st.dir);
    const body = document.getElementById('energy-tbody');
    body.dataset.refreshState = 'ready';
    if (!sorted.length) {
        body.innerHTML = energyStateRow(normalized.length ? 'No processes match this search.' : 'No process energy samples are available.', 'empty');
        return normalized.reduce((sum, process) => sum + process.energy_impact, 0);
    }
    body.innerHTML = sorted.slice(0,200).map(p => {
        const ei = p.energy_impact;
        const barW = Math.min(ei * 3, 100);
        const barColor = ei > 20 ? '#FF3B30' : ei > 5 ? '#FF9F0A' : '#34C759';
        return '<tr><td>'+esc(p.name)+'</td><td class="num"><span class="energy-bar" style="width:'+barW+'px;background:'+barColor+'"></span> '+ei.toFixed(1)+'</td><td class="num">'+p.avg_energy_impact.toFixed(1)+'</td><td>'+p.app_nap+'</td><td>'+p.preventing_sleep+'</td><td class="num">'+(p.pid || '—')+'</td></tr>';
    }).join('');
    return normalized.reduce((sum, process) => sum + process.energy_impact, 0);
}
function renderDiskTable(procs) {
    const st = sortState.disk;
    const sorted = sortProcs(filterProcs([...procs]), st.key, st.dir);
    document.getElementById('disk-tbody').innerHTML = sorted.slice(0,200).map(p =>
        '<tr><td>'+esc(p.name)+'</td><td class="num">'+fmtBytes(p.read_bytes)+'</td><td class="num">'+fmtBytes(p.write_bytes)+'</td><td class="num">'+(p.read_count == null ? '—' : Number(p.read_count))+'</td><td class="num">'+(p.write_count == null ? '—' : Number(p.write_count))+'</td><td class="num">'+Number(p.pid)+'</td></tr>'
    ).join('');
}
function renderNetTable(procs) {
    const st = sortState.network;
    const sorted = sortProcs(filterProcs([...procs]), st.key, st.dir);
    document.getElementById('net-tbody').innerHTML = sorted.slice(0,200).map(p =>
        '<tr><td>'+esc(p.name)+'</td><td class="num">'+Number(p.connections)+'</td><td class="num">'+fmtBytes(p.sent_bytes)+'</td><td class="num">'+fmtBytes(p.recv_bytes)+'</td><td class="num">'+Number(p.pid)+'</td></tr>'
    ).join('');
}

function drawCpuGraph(userPct, sysPct) {
    cpuHistory.user.push(userPct);
    cpuHistory.system.push(sysPct);
    if (cpuHistory.user.length > CPU_HIST_LEN) { cpuHistory.user.shift(); cpuHistory.system.shift(); }
    renderCpuBars();
}
function renderCpuBars() {
    const el = document.getElementById('cpu-bar-chart');
    if (!el) return;
    const maxPts = 80;
    const users = cpuHistory.user.slice(-maxPts);
    const systems = cpuHistory.system.slice(-maxPts);
    let html = '';
    for (let i = 0; i < maxPts; i++) {
        const u = i < users.length ? users[i] : 0;
        const s = i < systems.length ? systems[i] : 0;
        html += '<div style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;height:100%">';
        html += '<div style="background:rgba(115,191,68,0.8);height:'+u+'%"></div>';
        html += '<div style="background:rgba(227,62,56,0.8);height:'+s+'%"></div>';
        html += '</div>';
    }
    el.innerHTML = html;
}

function drawCoreBars(perCpu) {
    document.getElementById('cpu-cores-bars').innerHTML = perCpu.map((v, i) =>
        '<div style="display:flex;align-items:center;gap:4px;margin-bottom:2px"><span style="width:16px;text-align:right;color:#888;font-size:9px">'+i+'</span><div style="flex:1;height:10px;background:#D0D0D0;border-radius:2px;overflow:hidden"><div style="height:100%;width:'+v+'%;background:'+(v>80?'#FF3B30':v>50?'#FF9F0A':'#34C759')+';transition:width 0.3s"></div></div><span style="width:28px;font-size:9px;color:#555">'+v.toFixed(0)+'%</span></div>'
    ).join('');
}

function paintPressureGauge(canvas, percent, state = null, label = 'Memory Pressure') {
    if (!canvas) return '#8E8E93';
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0,0,W,H);
    const cx = W/2, cy = H*0.76, r = Math.min(W*.36, H*.5);
    const stroke = Math.max(9, Math.round(r*.27));
    ctx.beginPath(); ctx.arc(cx, cy, r, Math.PI, 2*Math.PI); ctx.lineWidth = stroke; ctx.strokeStyle = '#E0E0E0'; ctx.lineCap = 'round'; ctx.stroke();
    const color = state === 'critical' ? '#FF3B30' : state === 'pressure' ? '#FF9F0A' : state === 'normal' ? '#34C759' : percent > 80 ? '#FF3B30' : percent > 50 ? '#FF9F0A' : '#34C759';
    ctx.beginPath(); ctx.arc(cx, cy, r, Math.PI, Math.PI + (clampPct(percent)/100)*Math.PI); ctx.lineWidth = stroke; ctx.strokeStyle = color; ctx.lineCap = 'round'; ctx.stroke();
    ctx.fillStyle = '#1d1d1f'; ctx.font = '600 '+Math.max(15,Math.round(W*.14))+'px -apple-system, sans-serif'; ctx.textAlign = 'center'; ctx.fillText(Number(percent).toFixed(0)+'%', cx, cy-5);
    ctx.fillStyle = '#888'; ctx.font = Math.max(8,Math.round(W*.065))+'px -apple-system, sans-serif'; ctx.fillText(label, cx, cy+11);
    return color;
}

function drawPressureGauge(percent, state = null) {
    return paintPressureGauge(document.getElementById('pressure-canvas'), percent, state, 'Memory Pressure');
}

function memorySourceFailureCopy(payload) {
    const failures = (payload?.errors || []).flatMap(error =>
        (error.failedSources || []).map(source => String(source.source || error.label || 'memory source') + ':' + String(source.code || error.code || 'source_error'))
    );
    const unique = [...new Set(failures)];
    const summary = payload?.summary || 'Measured memory sources did not complete after bounded retry.';
    return unique.length ? summary + ' Failed: ' + unique.join(', ') + '.' : summary;
}

function showMemorySourceError(payload, target = 'diagnostic') {
    const error = document.getElementById('memory-diagnostics-error');
    const copy = document.getElementById('memory-diagnostics-error-copy');
    const retry = document.getElementById('memory-diagnostics-retry');
    if (memoryRetryTarget === 'diagnostic' && target === 'base') return;
    memoryRetryTarget = target;
    copy.textContent = memorySourceFailureCopy(payload);
    copy.title = copy.textContent;
    retry.textContent = payload?.actionLabel || 'Retry';
    retry.disabled = payload?.retryable === false;
    error.hidden = false;
}

function renderMemoryBaseSnapshot(memory) {
    const details = document.getElementById('mem-details');
    const pressurePanel = document.querySelector('#memory-tab .memory-pressure-summary');
    const status = document.getElementById('memory-diagnostics-status');
    if (!memory?.ok) {
        details.classList.add('stale');
        pressurePanel?.classList.add('stale');
        if (!memoryDiagnosticsRunning && memoryRetryTarget !== 'diagnostic') {
            status.classList.add('stale');
            status.textContent = 'Base Memory sources stopped after bounded retry · Retry is safe and read-only';
        }
        showMemorySourceError(memory || {summary:'Base Memory source chain failed.',retryable:true,actionLabel:'Retry'}, 'base');
        return false;
    }
    const pressureState = memory.pressure?.state;
    const pressurePct = Number(memory.pressure?.pressure_percent);
    if (!finite(memory.total_gb) || !finite(memory.used_gb) || !finite(memory.swap_used_gb) || !finite(pressurePct)) {
        showMemorySourceError({
            summary:'Base Memory returned an incomplete measured payload.',
            errors:[{label:'Base Memory',failedSources:[{source:'memory.payload',code:'incomplete_payload'}]}],
            retryable:true,
            actionLabel:'Retry'
        }, 'base');
        return false;
    }
    const gaugeColor = drawPressureGauge(pressurePct, pressureState);
    const pressureText = pressureState === 'critical' ? 'Critical' : pressureState === 'pressure' ? 'Pressure' : 'Normal';
    document.getElementById('mem-pressure-text').textContent = pressureText;
    const dotEl = document.querySelector('#memory-tab .info-row .dot');
    if (dotEl) dotEl.style.background = gaugeColor;
    document.getElementById('mem-physical').textContent = Number(memory.total_gb).toFixed(1) + ' GB';
    document.getElementById('mem-used').textContent = Number(memory.used_gb).toFixed(2) + ' GB';
    document.getElementById('mem-cached').textContent = (Number(memory.inactive || 0) / (1024**3)).toFixed(2) + ' GB';
    document.getElementById('mem-swap').textContent = Number(memory.swap_used_gb).toFixed(2) + ' GB';
    document.getElementById('mem-app').textContent = (Math.max(0, Number(memory.used || 0) - Number(memory.wired || 0)) / (1024**3)).toFixed(2) + ' GB';
    document.getElementById('mem-wired').textContent = Number(memory.wired_gb).toFixed(2) + ' GB';
    details.classList.toggle('stale', Boolean(memory.stale));
    pressurePanel?.classList.toggle('stale', Boolean(memory.stale));
    if (memory.stale) {
        if (!memoryDiagnosticsRunning && memoryRetryTarget !== 'diagnostic') {
            status.classList.add('stale');
            status.textContent = 'Base Memory retained from ' + observedClock(memory.observedAt) + ' while sources retry automatically';
        }
        showMemorySourceError({...memory, errors:memory.sourceErrors || []}, 'base');
    } else {
        if (!memoryDiagnosticsRunning && memoryRetryTarget === 'base') {
            status.classList.remove('stale');
            status.textContent = 'Base Memory refreshed ' + observedClock(memory.observedAt) + ' · local read-only';
        }
        clearMemorySourceError('base');
    }
    return true;
}

function clearMemorySourceError(target = null) {
    if (target && memoryRetryTarget && memoryRetryTarget !== target) return;
    document.getElementById('memory-diagnostics-error').hidden = true;
    memoryRetryTarget = null;
}

function renderMemoryDiagnostics(payload) {
    const result = document.getElementById('memory-diagnostics-result');
    const findings = document.getElementById('memory-diagnostics-findings');
    const status = document.getElementById('memory-diagnostics-status');
    const copyButton = document.getElementById('memory-diagnostics-copy');
    if (payload?.code === 'diagnostic_in_progress') {
        status.textContent = payload.summary || 'Sampling local counters.';
        return;
    }
    const verdictValue = String(payload?.verdict || 'attention').toLowerCase();
    const verdict = result.querySelector('.memory-diagnostic-verdict');
    const summary = result.querySelector('.memory-diagnostic-summary-copy');
    verdict.className = 'memory-diagnostic-verdict ' + verdictValue;
    verdict.textContent = payload?.statusLabel || (verdictValue === 'critical' ? 'Critical' : verdictValue === 'healthy' ? 'Healthy' : 'Attention');
    summary.textContent = payload?.summary || 'No diagnostic claim was inferred.';
    summary.title = summary.textContent;
    emptyNode(findings);
    (payload?.findings || []).forEach(finding => {
        const row = document.createElement('div');
        row.className = 'memory-diagnostic-finding ' + String(finding.status || 'attention').toLowerCase() + (finding.stale ? ' stale' : '');
        row.title = finding.summary || '';
        const dot = document.createElement('span');
        dot.className = 'memory-diagnostic-dot';
        dot.setAttribute('aria-hidden', 'true');
        const label = document.createElement('span');
        label.className = 'memory-diagnostic-label';
        label.textContent = finding.label || 'Check';
        const copy = document.createElement('span');
        copy.className = 'memory-diagnostic-copy';
        copy.textContent = finding.displayValue || finding.summary || 'Retry required';
        row.append(dot, label, copy);
        findings.appendChild(row);
    });
    if (!findings.childElementCount) {
        const empty = document.createElement('div');
        empty.className = 'memory-diagnostic-empty';
        empty.textContent = 'No measured diagnostic value was inferred. Use Retry after reviewing the source code below.';
        findings.appendChild(empty);
    }
    lastMemoryDiagnostics = payload?.ok && payload?.reportText ? payload : null;
    copyButton.disabled = !lastMemoryDiagnostics?.reportText;
    const completed = payload?.finishedAt ? observedClock(payload.finishedAt) : 'now';
    const fallbackCount = (payload?.fallbacksUsed || []).length;
    const retainedCount = Number(payload?.retainedCount || 0);
    status.classList.toggle('stale', retainedCount > 0);
    if (!payload?.ok) {
        status.textContent = 'Source chain stopped after bounded retry · no value inferred for failed checks';
        showMemorySourceError(payload, 'diagnostic');
    } else if (retainedCount) {
        status.textContent = 'Showing ' + retainedCount + ' time-stamped retained measurement' + (retainedCount === 1 ? '' : 's') + ' · Retry refreshes them';
        showMemorySourceError({...payload, errors:Object.values(payload?.findings || {}).flatMap(finding => finding.retryFailures?.length ? [{label:finding.label,failedSources:finding.retryFailures}] : [])}, 'diagnostic');
    } else {
        status.textContent = (fallbackCount ? 'Recovered ' + fallbackCount + ' primary source' + (fallbackCount === 1 ? '' : 's') + ' through measured fallback · ' : '') + 'Completed ' + completed + ' · local read-only · no processes changed';
        clearMemorySourceError('diagnostic');
    }
}

async function runMemoryDiagnostics() {
    if (!apiReady || memoryDiagnosticsRunning) return;
    memoryDiagnosticsRunning = true;
    const runButton = document.getElementById('memory-diagnostics-run');
    const copyButton = document.getElementById('memory-diagnostics-copy');
    const progress = document.getElementById('memory-diagnostics-progress');
    const progressBar = document.getElementById('memory-diagnostics-progress-bar');
    const progressCopy = document.getElementById('memory-diagnostics-progress-copy');
    const status = document.getElementById('memory-diagnostics-status');
    runButton.disabled = true;
    runButton.textContent = 'Sampling…';
    copyButton.disabled = true;
    progress.hidden = false;
    progressBar.max = MEMORY_DIAGNOSTIC_SAMPLE_SECONDS;
    progressBar.value = 0;
    status.textContent = 'Sampling local counters · no processes or workloads will be changed';
    const started = Date.now();
    const updateProgress = () => {
        const elapsed = Math.min(MEMORY_DIAGNOSTIC_SAMPLE_SECONDS, Math.floor((Date.now() - started) / 1000));
        progressBar.value = elapsed;
        progressCopy.textContent = elapsed + ' of ' + MEMORY_DIAGNOSTIC_SAMPLE_SECONDS + ' seconds';
    };
    updateProgress();
    const progressTimer = setInterval(updateProgress, 1000);
    try {
        const payload = bridgeJson(await pywebview.api.run_memory_diagnostics());
        renderMemoryDiagnostics(payload);
    } catch (error) {
        renderMemoryDiagnostics({
            ok:false,
            code:'diagnostic_bridge_error',
            verdict:'attention',
            statusLabel:'Retry needed',
            summary:'The local diagnostic bridge failed; measured values were not inferred.',
            findings:[],
            errors:[{label:'Memory diagnostics',failedSources:[{source:'pywebview.bridge',code:'bridge_error'}]}],
            retryable:true,
            actionLabel:'Retry'
        });
    } finally {
        clearInterval(progressTimer);
        progressBar.value = progressBar.max;
        progressCopy.textContent = MEMORY_DIAGNOSTIC_SAMPLE_SECONDS + ' of ' + MEMORY_DIAGNOSTIC_SAMPLE_SECONDS + ' seconds';
        progress.hidden = true;
        runButton.disabled = false;
        runButton.textContent = 'Run Again';
        memoryDiagnosticsRunning = false;
    }
}

function fallbackCopyText(text) {
    const field = document.createElement('textarea');
    field.value = text;
    field.setAttribute('readonly', '');
    field.style.position = 'fixed';
    field.style.opacity = '0';
    document.body.appendChild(field);
    field.select();
    const copied = document.execCommand('copy');
    field.remove();
    if (!copied) throw new Error('Clipboard write failed');
}

async function copyMemoryDiagnosticReport() {
    const text = lastMemoryDiagnostics?.reportText;
    if (!text) return;
    try {
        if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text);
        else fallbackCopyText(text);
        document.getElementById('memory-diagnostics-status').textContent = 'Report copied by explicit request · nothing uploaded or saved';
    } catch (error) {
        document.getElementById('memory-diagnostics-status').textContent = 'Clipboard write failed · report remains only in memory';
    }
}

function drawNetGraph(sentRate, recvRate) {
    netHistory.sent.push(sentRate); netHistory.recv.push(recvRate);
    if (netHistory.sent.length > NET_HIST_LEN) { netHistory.sent.shift(); netHistory.recv.shift(); }
    const canvas = document.getElementById('net-canvas');
    if (!canvas || canvas.offsetWidth === 0 || canvas.offsetHeight === 0) return;
    const ctx = canvas.getContext('2d');
    const newW = canvas.offsetWidth * 2;
    const newH = canvas.offsetHeight * 2;
    if (canvas.width !== newW) canvas.width = newW;
    if (canvas.height !== newH) canvas.height = newH;
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0,0,W,H);
    // Auto-scale: use max of last 10 samples only, tight fit
    const last10 = [...netHistory.sent.slice(-10), ...netHistory.recv.slice(-10)];
    const visMax = Math.max(...last10, 1);
    const maxVal = visMax * 1.5;
    const len = netHistory.sent.length;
    const dx = W / (NET_HIST_LEN - 1);
    ctx.strokeStyle = 'rgba(255,255,255,0.08)';
    for (let i = 0; i <= 4; i++) { const y = H*i/4; ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke(); }
    // Draw filled area versions for visibility
    function drawArea(data, fillColor, lineColor) {
        ctx.beginPath(); ctx.moveTo(W, H);
        for (let i = len - 1; i >= 0; i--) {
            const x = W-(len-1-i)*dx;
            const val = Math.min(data[i], maxVal);
            const y = H - (val/maxVal)*H*0.85;
            ctx.lineTo(x, y);
        }
        ctx.lineTo(W-(len-1)*dx, H); ctx.closePath();
        ctx.fillStyle = fillColor; ctx.fill();
        // Line on top
        ctx.beginPath();
        for (let i = 0; i < len; i++) {
            const x = W-(len-1-i)*dx;
            const val = Math.min(data[i], maxVal);
            const y = H - (val/maxVal)*H*0.85;
            if (i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
        }
        ctx.strokeStyle = lineColor; ctx.lineWidth = 3; ctx.stroke();
    }
    drawArea(netHistory.recv, 'rgba(52,199,89,0.35)', '#34C759');
    drawArea(netHistory.sent, 'rgba(0,122,255,0.35)', '#007AFF');
    // Scale label
    ctx.fillStyle = 'rgba(255,255,255,0.3)'; ctx.font = '18px -apple-system,sans-serif'; ctx.textAlign = 'right';
    if (maxVal > 1024*1024) ctx.fillText((maxVal/(1024*1024)).toFixed(1)+' MB/s', W-10, 22);
    else if (maxVal > 1024) ctx.fillText((maxVal/1024).toFixed(1)+' KB/s', W-10, 22);
    else ctx.fillText(maxVal.toFixed(0)+' B/s', W-10, 22);
}

function drawEnergyGraph(totalEnergy) {
    energyHistory.push(totalEnergy);
    if (energyHistory.length > ENERGY_HIST_LEN) energyHistory.shift();
    renderEnergyBars();
}
function renderEnergyBars() {
    const el = document.getElementById('energy-bar-chart');
    if (!el) return;
    const maxPts = 80;
    const data = energyHistory.slice(-maxPts);
    if (!data.length) {
        el.innerHTML = '<div class="energy-graph-state">Loading current sample…</div>';
        return;
    }
    const maxVal = Math.max(...data.slice(-20), 10) * 1.3;
    let html = '';
    for (let i = 0; i < maxPts; i++) {
        const v = i < data.length ? data[i] : 0;
        const pct = Math.min((v / maxVal) * 100, 100);
        html += '<div style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;height:100%">';
        html += '<div style="background:rgba(255,159,10,0.8);height:'+pct+'%"></div>';
        html += '</div>';
    }
    el.innerHTML = html;
}

function redrawNetGraph() {
    const canvas = document.getElementById('net-canvas');
    if (!canvas || canvas.offsetWidth === 0) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width = canvas.offsetWidth * 2;
    const H = canvas.height = canvas.offsetHeight * 2;
    ctx.clearRect(0,0,W,H);
    const last10 = [...netHistory.sent.slice(-10), ...netHistory.recv.slice(-10)];
    const visMax = Math.max(...last10, 1);
    const maxVal = visMax * 1.5;
    const len = netHistory.sent.length;
    const dx = W / (NET_HIST_LEN - 1);
    ctx.strokeStyle = 'rgba(255,255,255,0.08)';
    for (let i = 0; i <= 4; i++) { const y = H*i/4; ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke(); }
    function drawArea(data, fillColor, lineColor) {
        ctx.beginPath(); ctx.moveTo(W, H);
        for (let i = len - 1; i >= 0; i--) { const x = W-(len-1-i)*dx; const val = Math.min(data[i], maxVal); ctx.lineTo(x, H-(val/maxVal)*H*0.85); }
        ctx.lineTo(W-(len-1)*dx, H); ctx.closePath(); ctx.fillStyle = fillColor; ctx.fill();
        ctx.beginPath();
        for (let i = 0; i < len; i++) { const x = W-(len-1-i)*dx; const val = Math.min(data[i], maxVal); const y = H-(val/maxVal)*H*0.85; if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y); }
        ctx.strokeStyle = lineColor; ctx.lineWidth = 3; ctx.stroke();
    }
    drawArea(netHistory.recv, 'rgba(52,199,89,0.35)', '#34C759');
    drawArea(netHistory.sent, 'rgba(0,122,255,0.35)', '#007AFF');
}
// CSS bar charts replace canvas-based redraw functions

function renderNetBars() {
    const el = document.getElementById('net-bar-chart');
    if (!el) return;
    const maxPts = 60;
    const sent = netHistory.sent.slice(-maxPts);
    const recv = netHistory.recv.slice(-maxPts);
    const maxVal = Math.max(...sent.slice(-15), ...recv.slice(-15), 1) * 1.5;
    const barW = 100 / maxPts;
    let html = '';
    for (let i = 0; i < maxPts; i++) {
        const s = i < sent.length ? sent[i] : 0;
        const r = i < recv.length ? recv[i] : 0;
        const sPct = Math.max((s / maxVal) * 100, 1);
        const rPct = Math.max((r / maxVal) * 100, 1);
        html += '<div style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:stretch;height:100%">';
        html += '<div style="background:rgba(0,122,255,0.6);height:'+sPct+'%;min-height:1px;border-radius:1px 1px 0 0"></div>';
        html += '<div style="background:rgba(52,199,89,0.6);height:'+rPct+'%;min-height:1px"></div>';
        html += '</div>';
    }
    el.innerHTML = html;
}

function killProc(pid, force) {
    if (!apiReady) return;
    pywebview.api.kill_process(pid, force).then(r => {
        const d = JSON.parse(r);
        if (!d.success) alert(d.message);
    });
}

let agentWorkerSelection = {};
let lastAgentSnapshot = null;
let lastAgentSystemData = null;
const agentProcessRows = new Map();
const AGENT_PROCESS_MISS_GRACE = 10;

function esc(value) {
    return String(value == null ? '' : value)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function finite(value) { return typeof value === 'number' && Number.isFinite(value); }
function clampPct(value) { return Math.max(0, Math.min(100, finite(value) ? value : 0)); }
function metricTone(value) { return value >= 80 ? 'hot' : value >= 50 ? 'warm' : ''; }
function setAgentBadge(id, text, tone) {
    const el = document.getElementById(id);
    el.textContent = text;
    el.className = 'agent-badge ' + (tone || 'info');
}
function observedClock(value) {
    const date = value ? new Date(value) : null;
    return date && Number.isFinite(date.getTime()) ? date.toLocaleTimeString([], {hour:'numeric',minute:'2-digit',second:'2-digit'}) : 'unknown time';
}

function patchText(element, value) {
    const text = String(value == null ? '' : value);
    if (element.textContent !== text) element.textContent = text;
}

function patchAttributes(current, incoming) {
    [...current.attributes].forEach(attribute => {
        if (!incoming.hasAttribute(attribute.name)) current.removeAttribute(attribute.name);
    });
    [...incoming.attributes].forEach(attribute => {
        if (current.getAttribute(attribute.name) !== attribute.value) current.setAttribute(attribute.name, attribute.value);
    });
}

function patchNode(current, incoming) {
    if (current.nodeType !== incoming.nodeType || (current.nodeType === Node.ELEMENT_NODE && current.tagName !== incoming.tagName)) {
        current.replaceWith(incoming.cloneNode(true));
        return;
    }
    if (current.nodeType === Node.TEXT_NODE) {
        if (current.nodeValue !== incoming.nodeValue) current.nodeValue = incoming.nodeValue;
        return;
    }
    if (current.nodeType !== Node.ELEMENT_NODE) return;
    patchAttributes(current, incoming);
    const currentChildren = [...current.childNodes];
    const incomingChildren = [...incoming.childNodes];
    const shared = Math.min(currentChildren.length, incomingChildren.length);
    for (let index = 0; index < shared; index++) patchNode(currentChildren[index], incomingChildren[index]);
    for (let index = shared; index < incomingChildren.length; index++) current.appendChild(incomingChildren[index].cloneNode(true));
    for (let index = currentChildren.length - 1; index >= incomingChildren.length; index--) currentChildren[index].remove();
}

function patchMarkup(container, markup) {
    const template = document.createElement('template');
    template.innerHTML = markup;
    const currentChildren = [...container.childNodes];
    const incomingChildren = [...template.content.childNodes];
    const shared = Math.min(currentChildren.length, incomingChildren.length);
    for (let index = 0; index < shared; index++) patchNode(currentChildren[index], incomingChildren[index]);
    for (let index = shared; index < incomingChildren.length; index++) container.appendChild(incomingChildren[index].cloneNode(true));
    for (let index = currentChildren.length - 1; index >= incomingChildren.length; index--) currentChildren[index].remove();
}

function resetCoreContributorRows() {
    coreContributorRows.clear();
    document.getElementById('agents-core-contributors').replaceChildren();
}

function selectAgentCore(index) {
    const coreCount = lastAgentSystemData?.cpu?.per_cpu?.length || 0;
    if (!Number.isInteger(index) || index < 0 || index >= coreCount) return;
    if (selectedAgentCore !== index) {
        selectedAgentCore = index;
        resetCoreContributorRows();
    }
    document.getElementById('agents-core-inspector').hidden = false;
    renderAgentCoreOverview(lastAgentSystemData, lastAgentSnapshot);
    renderAgentCoreInspector(lastAgentSystemData, lastAgentSnapshot);
}

function closeAgentCoreInspector() {
    selectedAgentCore = null;
    document.getElementById('agents-core-inspector').hidden = true;
    document.querySelectorAll('.agents-core').forEach(core => {
        core.classList.remove('selected');
        core.setAttribute('aria-pressed', 'false');
    });
    resetCoreContributorRows();
}

function recordCoreActivity(systemData, payload) {
    const coreLoads = systemData?.cpu?.per_cpu || [];
    const sampleId = payload?.observedAt;
    if (!sampleId || sampleId === lastCoreActivitySample || !coreLoads.length) return;
    const processCpu = {};
    (payload?.aiProcesses || []).forEach(row => {
        const pid = Number(row.pid);
        if (Number.isInteger(pid) && pid > 0) processCpu[pid] = Math.max(0, Number(row.cpuPercent || 0));
    });
    coreActivityHistory.push({sampleId, coreLoads:coreLoads.map(value => clampPct(Number(value))), processCpu});
    if (coreActivityHistory.length > CORE_ACTIVITY_HISTORY_LENGTH) coreActivityHistory.shift();
    lastCoreActivitySample = sampleId;
}

function coreCoactivity(pid, coreIndex) {
    const points = coreActivityHistory
        .filter(sample => coreIndex < sample.coreLoads.length)
        .map(sample => [sample.coreLoads[coreIndex], Number(sample.processCpu[pid] || 0)]);
    if (points.length < CORE_COACTIVITY_MIN_SAMPLES) return {value:null, samples:points.length};
    const coreMean = points.reduce((sum, point) => sum + point[0], 0) / points.length;
    const processMean = points.reduce((sum, point) => sum + point[1], 0) / points.length;
    let numerator = 0;
    let coreVariance = 0;
    let processVariance = 0;
    points.forEach(point => {
        const coreDelta = point[0] - coreMean;
        const processDelta = point[1] - processMean;
        numerator += coreDelta * processDelta;
        coreVariance += coreDelta * coreDelta;
        processVariance += processDelta * processDelta;
    });
    if (coreVariance < 0.0001 || processVariance < 0.0001) return {value:null, samples:points.length};
    return {value:Math.max(-1, Math.min(1, numerator / Math.sqrt(coreVariance * processVariance))), samples:points.length};
}

function coactivityCopy(result) {
    if (!finite(result.value)) return {value:'collecting', detail:result.samples+' / '+CORE_COACTIVITY_MIN_SAMPLES+' samples'};
    const magnitude = result.value >= .65 ? 'strong' : result.value >= .35 ? 'moderate' : result.value >= .10 ? 'light' : 'no clear pattern';
    const maturity = result.samples < 12 ? 'early ' : '';
    return {value:'r '+result.value.toFixed(2), detail:maturity+magnitude+' · '+result.samples+' samples'};
}

function recentProcessActivity(pid) {
    const window = coreActivityHistory.slice(-CORE_RECENT_ACTIVITY_SAMPLES);
    let lastActiveIndex = -1;
    let peakCpu = 0;
    let activeSamples = 0;
    window.forEach((sample,index) => {
        const cpu = Number(sample.processCpu[pid] || 0);
        if (cpu <= 0) return;
        lastActiveIndex = index;
        peakCpu = Math.max(peakCpu, cpu);
        activeSamples += 1;
    });
    return {
        seen: lastActiveIndex >= 0,
        samplesAgo: lastActiveIndex >= 0 ? window.length - 1 - lastActiveIndex : null,
        peakCpu,
        activeSamples,
    };
}

function renderAgentCoreInspector(systemData, payload) {
    const inspector = document.getElementById('agents-core-inspector');
    const perCore = systemData?.cpu?.per_cpu || [];
    if (selectedAgentCore == null || selectedAgentCore >= perCore.length) {
        inspector.hidden = true;
        return;
    }
    inspector.hidden = false;
    const coreIndex = selectedAgentCore;
    const historyValues = coreActivityHistory.filter(sample => coreIndex < sample.coreLoads.length).map(sample => sample.coreLoads[coreIndex]);
    const average = historyValues.length ? historyValues.reduce((sum, value) => sum + value, 0) / historyValues.length : null;
    const rows = (payload?.aiProcesses || []).map(row => ({
        ...row,
        coactivity:coreCoactivity(Number(row.pid), coreIndex),
        recentActivity:recentProcessActivity(Number(row.pid)),
    }));
    const recentRows = rows.filter(row => {
        const workerState = String(row.workerState || '').toLowerCase();
        return row.recentActivity.seen || ['active','busy','running','processing','working'].some(state => workerState.includes(state));
    }).sort((a,b) => {
        const aScore = finite(a.coactivity.value) ? a.coactivity.value : -2;
        const bScore = finite(b.coactivity.value) ? b.coactivity.value : -2;
        return bScore - aScore || Number(b.cpuPercent || 0) - Number(a.cpuPercent || 0) || Number(a.pid) - Number(b.pid);
    });

    patchText(document.getElementById('agents-core-inspector-title'), 'Logical core C'+coreIndex);
    inspector.setAttribute('aria-label', 'Logical core C'+coreIndex+', measured load with AI process co-activity across '+historyValues.length+' samples.');
    patchText(document.getElementById('agents-core-current'), Number(perCore[coreIndex] || 0).toFixed(1)+'%');
    patchText(document.getElementById('agents-core-average'), finite(average) ? average.toFixed(1)+'%' : '—');
    patchText(document.getElementById('agents-core-truth'), 'Co-activity only — fixed process placement is not exposed.');

    const container = document.getElementById('agents-core-contributors');
    const recentPids = new Set(recentRows.map(row => Number(row.pid)));
    recentRows.forEach(row => {
        const pid = Number(row.pid);
        let record = coreContributorRows.get(pid);
        if (!record) {
            const element = document.createElement('div');
            element.className = 'core-contributor-row';
            element.dataset.pid = String(pid);
            element.innerHTML = '<div><div class="core-contributor-name"></div><div class="core-contributor-sub"></div></div><div class="core-contributor-metric"><div></div><div class="core-contributor-sub"></div></div><div class="core-contributor-metric"><div></div><div class="core-contributor-sub"></div></div><div class="core-contributor-evidence"></div>';
            container.appendChild(element);
            record = {element, misses:0};
            coreContributorRows.set(pid, record);
        }
        record.misses = 0;
        record.element.hidden = false;
        record.element.classList.remove('core-contributor-grace');
        record.element.title = '';
        const columns = record.element.children;
        patchText(columns[0].querySelector('.core-contributor-name'), row.provider || row.name || 'AI process');
        patchText(columns[0].querySelector('.core-contributor-sub'), (row.name || 'Unknown')+' · PID '+pid+(row.group ? ' · '+row.group : ''));
        const cpu = Math.max(0, Number(row.cpuPercent || 0));
        patchText(columns[1].children[0], cpu.toFixed(1)+'%');
        const activityCopy = cpu > 0
            ? 'active in latest sample'
            : row.recentActivity.seen
                ? 'active '+(row.recentActivity.samplesAgo === 1 ? '1 sample' : row.recentActivity.samplesAgo+' samples')+' ago'
                : 'published '+(row.workerState || 'active');
        patchText(columns[1].children[1], (cpu / 100).toFixed(2)+' total core equiv. · '+activityCopy);
        const relation = coactivityCopy(row.coactivity);
        patchText(columns[2].children[0], relation.value);
        patchText(columns[2].children[1], relation.detail);
        const evidence = row.confidence === 'owner-published' ? 'owner-published GPU job' : row.confidence === 'observed-worker' ? 'observed CPU worker' : 'known runtime signature';
        patchText(columns[3], evidence+(row.workerState ? ' · '+row.workerState : '')+'; placement unclaimed');
    });
    for (const [pid, record] of coreContributorRows) {
        if (recentPids.has(pid)) continue;
        record.misses += 1;
        record.element.hidden = false;
        record.element.classList.add('core-contributor-grace');
        const columns = record.element.children;
        patchText(columns[1].children[1], 'last observed · retained in this view');
        patchText(columns[3], 'outside recent activity window; placement unclaimed');
        record.element.title = CORE_CONTRIBUTOR_SESSION_RETENTION
            ? 'No recent CPU sample; retained for this core-inspector session so the view stays stable.'
            : '';
    }
    patchText(document.getElementById('agents-core-active-count'), coreContributorRows.size);
    let empty = document.getElementById('agents-core-contributor-empty');
    if (!empty) {
        empty = document.createElement('div');
        empty.id = 'agents-core-contributor-empty';
        empty.className = 'core-contributor-empty';
        empty.textContent = 'No substantiated AI process has reported CPU activity in this observation window yet.';
        container.appendChild(empty);
    }
    empty.hidden = coreContributorRows.size > 0;
}

function renderGpuHistory(rawUtilization, inUseBytes, retained = false) {
    const history = document.getElementById('agents-gpu-history');
    if (history.children.length !== GPU_UTILIZATION_HISTORY_LENGTH) {
        history.replaceChildren(...Array.from({length:GPU_UTILIZATION_HISTORY_LENGTH}, () => {
            const bar = document.createElement('span');
            bar.className = 'gpu-history-bar empty';
            return bar;
        }));
    }
    const missing = Math.max(0, GPU_UTILIZATION_HISTORY_LENGTH - gpuUtilizationHistory.length);
    const values = Array(missing).fill(null).concat(gpuUtilizationHistory.slice(-GPU_UTILIZATION_HISTORY_LENGTH));
    values.forEach((value,index) => {
        const bar = history.children[index];
        const current = value != null && index === values.length - 1;
        bar.className = 'gpu-history-bar'+(value == null ? ' empty' : '')+(current ? ' current' : '');
        bar.style.height = value == null ? '2px' : Math.max(3, clampPct(value))+'%';
    });
    const smoothingValues = gpuUtilizationHistory.slice(-GPU_SMOOTHING_WINDOW);
    const average = smoothingValues.length
        ? smoothingValues.reduce((sum,value) => sum + value, 0) / smoothingValues.length
        : null;
    const peak = gpuUtilizationHistory.length ? Math.max(...gpuUtilizationHistory) : null;
    patchText(document.getElementById('agents-gpu-value'), finite(average) ? average.toFixed(1)+'%' : '—');
    patchText(document.getElementById('agents-gpu-now-label'), retained ? 'Last' : 'Now');
    patchText(document.getElementById('agents-gpu-now'), finite(rawUtilization) ? Number(rawUtilization).toFixed(1)+'%' : '—');
    patchText(document.getElementById('agents-gpu-peak'), finite(peak) ? peak.toFixed(1)+'%' : '—');
    patchText(document.getElementById('agents-gpu-memory'), finite(inUseBytes) ? fmtBytes(inUseBytes) : '—');
    const frame = document.getElementById('agents-gpu-history-frame');
    const summary = finite(rawUtilization)
        ? 'Recent host-wide GPU utilization. '+(retained ? 'Last observed ' : 'Now ')+Number(rawUtilization).toFixed(1)+' percent, 15 second average '+Number(average || 0).toFixed(1)+' percent, recent peak '+Number(peak || 0).toFixed(1)+' percent.'
        : 'Waiting for GPU utilization history.';
    frame.setAttribute('aria-label', summary);
    frame.title = summary;
    return average;
}

function renderMemoryPressure(memory) {
    const pressure = memory?.pressure || {};
    const fallbackHeadroom = finite(memory?.available_gb) && finite(memory?.total_gb) && Number(memory.total_gb) > 0
        ? Number(memory.available_gb) / Number(memory.total_gb) * 100
        : null;
    const headroom = finite(pressure.headroom_percent) ? clampPct(Number(pressure.headroom_percent)) : fallbackHeadroom;
    const score = finite(pressure.pressure_percent) ? clampPct(Number(pressure.pressure_percent)) : finite(headroom) ? 100 - headroom : null;
    const derivedState = finite(headroom) ? (headroom < 8 ? 'critical' : headroom < 18 ? 'pressure' : 'normal') : 'unknown';
    const state = ['normal','pressure','critical'].includes(pressure.state) ? pressure.state : derivedState;
    const stateLabel = state === 'normal' ? 'Normal' : state === 'pressure' ? 'Pressure' : state === 'critical' ? 'Critical' : 'Waiting';
    const tone = state === 'normal' ? 'ok' : state === 'pressure' ? 'warn' : state === 'critical' ? 'bad' : 'info';
    patchText(document.getElementById('agents-memory-headroom'), finite(headroom) ? Number(headroom).toFixed(0)+'% headroom' : 'Waiting');
    patchText(document.getElementById('agents-memory-available'), finite(memory?.available_gb) ? Number(memory.available_gb).toFixed(1)+' GB' : '—');
    patchText(document.getElementById('agents-memory-swap'), finite(memory?.swap_used_gb) ? Number(memory.swap_used_gb).toFixed(1)+' GB' : '—');
    patchText(document.getElementById('agents-memory-meta'), 'System-wide');
    setAgentBadge('agents-memory-health', stateLabel.toLowerCase(), tone);
    const dial = document.getElementById('agents-memory-dial');
    paintPressureGauge(dial, finite(score) ? Number(score) : 0, state, 'Pressure');
    const summary = finite(headroom)
        ? stateLabel+' memory pressure. '+Number(score || 0).toFixed(0)+' percent pressure, '+Number(headroom).toFixed(0)+' percent reclaimable headroom, '+Number(memory.available_gb || 0).toFixed(1)+' gigabytes available, '+Number(memory.swap_used_gb || 0).toFixed(1)+' gigabytes swap, '+Number(memory.used_gb || 0).toFixed(1)+' of '+Number(memory.total_gb || 0).toFixed(1)+' gigabytes used.'
        : 'Waiting for memory pressure.';
    dial.setAttribute('aria-label', summary);
    dial.title = summary;
}

function renderAgentCoreOverview(systemData, payload) {
    const perCore = systemData?.cpu?.per_cpu || [];
    const total = systemData?.cpu?.percent;
    document.getElementById('agents-cpu-value').textContent = finite(total) ? total.toFixed(1) + '%' : '—';
    const cpuModel = systemData?.system?.cpu_model || systemData?.system?.machine_model || 'Detected CPU';
    document.getElementById('agents-cpu-meta').textContent = cpuModel + ' · ' + perCore.length + ' cores';
    document.getElementById('agents-cpu-meta').title = 'Load average '+(systemData?.cpu?.load_avg || []).map(v=>Number(v).toFixed(1)).join(' / ');
    const queue = payload?.cpu?.snapshot?.host?.cpuQueueHealth || 'unknown';
    setAgentBadge('agents-cpu-health', queue, queue === 'healthy' ? 'ok' : queue === 'pressure' ? 'warn' : queue === 'critical' ? 'bad' : 'info');
    const coreContainer = document.getElementById('agents-cpu-cores');
    if (coreContainer.children.length !== perCore.length) {
        coreContainer.replaceChildren(...perCore.map((value,index) => {
            const core = document.createElement('button');
            core.type = 'button';
            core.className = 'agents-core';
            core.dataset.core = String(index);
            core.setAttribute('aria-pressed', 'false');
            core.addEventListener('click', () => selectAgentCore(index));
            core.innerHTML = '<div class="agents-core-top"><span></span><span></span></div><div class="agents-meter"><span></span></div>';
            return core;
        }));
    }
    perCore.forEach((value,index) => {
        const pct = clampPct(value);
        const core = coreContainer.children[index];
        core.title = 'Inspect logical CPU core '+index+' at '+Number(value).toFixed(1)+'% load';
        core.setAttribute('aria-label', 'Inspect logical CPU core '+index+', '+Number(value).toFixed(1)+' percent load');
        core.setAttribute('aria-pressed', selectedAgentCore === index ? 'true' : 'false');
        core.classList.toggle('selected', selectedAgentCore === index);
        const labels = core.querySelectorAll('.agents-core-top span');
        patchText(labels[0], 'C'+index);
        patchText(labels[1], Number(value).toFixed(0)+'%');
        const meter = core.querySelector('.agents-meter span');
        meter.className = metricTone(pct);
        meter.style.width = pct+'%';
    });

    const gpuSection = payload?.gpu || {};
    const observedDevice = gpuSection?.snapshot?.devices?.[0];
    if (observedDevice) lastValidGpuDevice = observedDevice;
    const device = observedDevice || lastValidGpuDevice;
    if (!device) {
        renderGpuHistory(null, null);
        patchText(document.getElementById('agents-gpu-meta'), gpuSection.error || gpuSection?.snapshot?.deviceProbe?.error || 'Waiting for local GPU detection');
        setAgentBadge('agents-gpu-health', 'waiting', 'warn');
        return;
    }
    const rawUtilization = device.utilization?.percent;
    const sampleKey = device.utilization?.observedAt || payload?.observedAt || payload?.generatedAt;
    if (finite(rawUtilization) && sampleKey !== lastGpuUtilizationSample) {
        gpuUtilizationHistory.push(clampPct(Number(rawUtilization)));
        if (gpuUtilizationHistory.length > GPU_UTILIZATION_HISTORY_LENGTH) gpuUtilizationHistory.shift();
        lastGpuUtilizationSample = sampleKey;
    }
    const coreCount = finite(device.coreCount) && Number(device.coreCount) > 0 ? Number(device.coreCount) : null;
    const inUse = finite(device.memory?.inUseBytes) ? Number(device.memory.inUseBytes) : finite(device.memory?.capacityBytes) ? Number(device.memory.capacityBytes) : null;
    const retained = !observedDevice || gpuSection.stale;
    renderGpuHistory(rawUtilization, inUse, retained);
    const coreLabel = coreCount ? coreCount + ' GPU cores' : 'core count not exposed';
    const inventoryOnly = !finite(rawUtilization);
    patchText(document.getElementById('agents-gpu-meta'), (device.model || 'Detected GPU') + ' · ' + coreLabel);
    patchText(document.getElementById('agents-gpu-memory-label'), device.memory?.kind === 'dedicated' ? 'VRAM' : device.memory?.kind === 'unified' ? 'Shared' : 'Memory');
    setAgentBadge('agents-gpu-health', retained ? 'retained' : inventoryOnly ? 'detected' : 'host-wide', retained ? 'warn' : 'info');
    const health = document.getElementById('agents-gpu-health');
    health.title = inventoryOnly ? 'This Mac reports the GPU identity, but not live utilization through the available telemetry.' : 'GPU utilization is detected from this Mac and measured host-wide.';
}

function aiProcessMatches(row, query) {
    const needle = String(query || '').toLowerCase();
    if (!needle) return true;
    return [row?.pid,row?.name,row?.provider,row?.category,row?.group,row?.reason]
        .some(value => String(value || '').toLowerCase().includes(needle));
}

function renderAiProcesses(payload) {
    const all = payload?.aiProcesses || [];
    const filtered = searchFilter ? all.filter(row => aiProcessMatches(row, searchFilter)) : all;
    const body = document.getElementById('agents-process-body');
    const observedPids = new Set();
    const filteredPids = new Set(filtered.map(row => Number(row.pid)));
    all.forEach(row => {
        const pid = Number(row.pid);
        observedPids.add(pid);
        let record = agentProcessRows.get(pid);
        if (!record) {
            const element = document.createElement('tr');
            element.dataset.pid = String(pid);
            element.innerHTML = '<td><div class="ai-process-name"></div><div class="ai-process-sub"></div></td><td><span class="ai-process-category"></span><br><span class="agent-badge ai-process-confidence"></span></td><td class="num"></td><td class="num"></td><td class="num"></td><td class="num"></td><td></td>';
            const emptyRow = document.getElementById('agents-process-empty');
            body.insertBefore(element, emptyRow || null);
            record = {element, misses:0, data:row};
            agentProcessRows.set(pid, record);
        }
        record.misses = 0;
        record.data = row;
        record.element.classList.remove('agent-process-grace');
        record.element.title = '';
        const confidenceTone = row.confidence === 'owner-published' ? 'ok' : row.confidence === 'observed-worker' ? 'info' : 'warn';
        const cells = record.element.cells;
        patchText(cells[0].querySelector('.ai-process-name'), row.name);
        patchText(cells[0].querySelector('.ai-process-sub'), row.provider+' · '+row.reason);
        patchText(cells[1].querySelector('.ai-process-category'), row.category);
        const confidence = cells[1].querySelector('.ai-process-confidence');
        patchText(confidence, row.confidence);
        confidence.className = 'agent-badge ai-process-confidence '+confidenceTone;
        patchText(cells[2], Number(row.cpuPercent || 0).toFixed(1)+'%');
        patchText(cells[3], fmtBytes(row.memoryBytes || 0));
        patchText(cells[4], Number(row.threads || 0));
        patchText(cells[5], pid);
        patchText(cells[6], row.runtime || '—');
        record.element.hidden = !filteredPids.has(pid);
    });
    for (const [pid, record] of agentProcessRows) {
        if (observedPids.has(pid)) continue;
        record.misses += 1;
        if (record.misses > AGENT_PROCESS_MISS_GRACE) {
            record.element.remove();
            agentProcessRows.delete(pid);
            continue;
        }
        const matches = aiProcessMatches(record.data, searchFilter);
        record.element.hidden = !matches;
        record.element.classList.add('agent-process-grace');
        record.element.title = 'Not seen in the latest sample; retained in the stable observation window.';
    }
    let empty = document.getElementById('agents-process-empty');
    if (!empty) {
        empty = document.createElement('tr');
        empty.id = 'agents-process-empty';
        empty.innerHTML = '<td colspan="7" style="padding:14px;color:#777;text-align:center">No substantiated AI processes match this view.</td>';
        body.appendChild(empty);
    }
    const visibleCount = [...agentProcessRows.values()].filter(record => !record.element.hidden).length;
    setAgentBadge(
        'agents-process-count',
        (searchFilter ? visibleCount+' / '+agentProcessRows.size : agentProcessRows.size)+' processes',
        agentProcessRows.size ? 'info' : 'warn'
    );
    empty.hidden = visibleCount > 0;
}

const CPU_POOL_RETENTION_MS = 900000;

function cpuPoolTimestampMs(value) {
    if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
        return value > 100000000000 ? value : value * 1000;
    }
    if (typeof value !== 'string' || !value.trim()) return null;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : null;
}

function cpuPoolLastActivityMs(pool, snapshot, payload, nowMs) {
    const retention = pool?.retention || {};
    const progress = pool?.progress || {};
    const candidates = [
        retention.activityMonitorLastVerifiedAt,
        progress.available === true ? progress.updatedAt : null,
    ].map(cpuPoolTimestampMs).filter(value => value != null && value <= nowMs + 60000);
    const snapshotMs = cpuPoolTimestampMs(snapshot?.generatedAt) || cpuPoolTimestampMs(payload?.generatedAt);
    if (candidates.length) return Math.max(...candidates);
    return snapshotMs != null && snapshotMs <= nowMs + 60000 ? snapshotMs : null;
}

function pruneExpiredCpuPools(payload, nowMs = Date.now()) {
    if (!payload || typeof payload !== 'object') return payload;
    const sanitized = JSON.parse(JSON.stringify(payload));
    const section = sanitized?.cpu;
    const snapshot = section?.snapshot;
    if (!snapshot || !Array.isArray(snapshot.pools)) return sanitized;
    const sectionStale = Boolean(section.stale);
    let expired = 0;
    snapshot.pools = snapshot.pools.filter(pool => {
        const live = Math.max(0, Number(pool?.totals?.live || 0));
        const parentAlive = pool?.parent?.processAlive === true;
        const staleLiveness = Boolean(sectionStale || pool?.livenessStale);
        const currentLiveness = !staleLiveness && (live > 0 || parentAlive);
        const lastActivityMs = cpuPoolLastActivityMs(pool, snapshot, sanitized, nowMs);
        const visible = currentLiveness || (
            lastActivityMs != null && Math.max(0, nowMs - lastActivityMs) <= CPU_POOL_RETENTION_MS
        );
        if (!visible) {
            expired += 1;
            return false;
        }
        pool.livenessStale = Boolean(staleLiveness && (live > 0 || parentAlive));
        pool.retention = {
            ...(pool.retention || {}),
            activityMonitorLastVerifiedAt: lastActivityMs == null ? null : new Date(lastActivityMs).toISOString(),
            activityMonitorInactiveForSeconds: lastActivityMs == null ? null : Math.max(0, nowMs - lastActivityMs) / 1000,
            activityMonitorRetentionSeconds: CPU_POOL_RETENTION_MS / 1000,
        };
        return true;
    });
    const totals = field => snapshot.pools.reduce((sum, pool) => sum + Math.max(0, Number(pool?.totals?.[field] || 0)), 0);
    snapshot.counts = {
        ...(snapshot.counts || {}),
        pools: snapshot.pools.length,
        workers: snapshot.pools.reduce((sum, pool) => sum + (pool?.workers || []).length, 0),
        live: totals('live'),
        busy: totals('busy'),
        registered: snapshot.pools.filter(pool => pool?.registered === true).length,
    };
    section.expiredPoolCount = Number(section.expiredPoolCount || 0) + expired;
    section.stoppedPoolRetentionSeconds = CPU_POOL_RETENTION_MS / 1000;
    return sanitized;
}

function cleanupAgentWorkerSelection(payload, selection = agentWorkerSelection) {
    const visible = new Set((payload?.cpu?.snapshot?.pools || []).map(pool => String(pool?.id || '')));
    for (const poolId of Object.keys(selection || {})) {
        if (!visible.has(poolId)) delete selection[poolId];
    }
    return selection;
}

function workerDetail(worker) {
    if (!worker) return '';
    const assignment = worker.assignment || {};
    const processBits = [
        worker.pid ? 'pid '+worker.pid : null,
        worker.ppid ? 'parent '+worker.ppid : null,
        worker.elapsed ? 'running '+worker.elapsed : null,
    ].filter(Boolean).join(' · ');
    const resourceBits = [finite(worker.cpuPercent) ? Number(worker.cpuPercent).toFixed(1)+'% CPU' : null, finite(worker.rssBytes) ? fmtBytes(worker.rssBytes)+' memory' : null].filter(Boolean).join(' · ');
    return '<div class="agent-detail"><b>'+esc(worker.label || worker.id || 'Worker')+'</b> · '+esc(worker.state || 'unknown')+(worker.osState ? ' / '+esc(worker.osState) : '')+
        (processBits ? '<br>'+esc(processBits) : '')+(resourceBits ? '<br>'+esc(resourceBits) : '')+
        (assignment.value || assignment.date ? '<br>Assignment: <b>'+esc(assignment.value || assignment.date)+'</b>' : '')+
        (assignment.detail ? '<br>'+esc(assignment.detail) : '')+'</div>';
}

function renderCpuPools(section) {
    const container = document.getElementById('agents-cpu-pools');
    const snapshot = section?.snapshot;
    if (!snapshot) {
        setAgentBadge('agents-cpu-count', section?.stale ? 'stale' : 'unavailable', section?.stale ? 'warn' : 'bad');
        patchMarkup(container, '<div class="agent-error">'+esc(section?.error || 'CPU Workers observer is unavailable.')+'</div>');
        return;
    }
    const pools = snapshot.pools || [];
    const live = pools.reduce((sum,pool)=>sum+Number(pool.totals?.live || 0),0);
    const liveLabel = section?.stale ? live+' last observed' : live+' live';
    setAgentBadge('agents-cpu-count', liveLabel+' · '+pools.length+' pool'+(pools.length===1?'':'s'), section?.stale ? 'warn' : live ? 'ok' : 'info');
    if (!pools.length) {
        patchMarkup(container, '<div class="agent-empty">No CPU worker pools are currently registered or observed.</div>');
        return;
    }
    patchMarkup(container, pools.map((pool,pi) => {
        const totals = pool.totals || {};
        const progress = pool.progress || {};
        const workers = pool.workers || [];
        const selectedId = agentWorkerSelection[pool.id];
        const selectedIndex = workers.findIndex(worker => worker.id === selectedId);
        const livenessStale = Boolean(section?.stale || pool.livenessStale);
        const state = Number(totals.live || 0) > 0 ? (livenessStale ? 'last observed live' : 'running') : (pool.runState || (progress.available ? 'stopped checkpoint' : 'idle'));
        const badgeTone = Number(totals.live || 0) > 0 && !livenessStale ? 'ok' : pool.registered ? 'info' : 'warn';
        const meta = [
            Number(totals.live || 0)+(livenessStale ? ' last observed live' : ' live'),
            Number(totals.busy || 0)+' busy',
            finite(totals.cpuCoreEquivalents) ? Number(totals.cpuCoreEquivalents).toFixed(2)+' CPU equivalents' : null,
            finite(totals.hostCpuCapacityPercent) ? Number(totals.hostCpuCapacityPercent).toFixed(1)+'% host capacity' : null,
            pool.failures != null ? pool.failures+' failures' : null,
        ].filter(Boolean).join(' · ');
        let progressHtml = '';
        if (progress.available) {
            const progressLabel = progress.scope === 'whole-pool' ? 'Whole-run progress' : 'Published progress';
            const progressText = [
                progress.processed != null && progress.total != null ? progress.processed+' / '+progress.total : null,
                progress.unit,
                finite(progress.percent) ? Number(progress.percent).toFixed(1)+'%' : null,
                progress.source ? 'source '+progress.source : null,
            ].filter(Boolean).join(' · ');
            progressHtml = '<div class="agent-pool-meta">'+esc(progressLabel)+': '+esc(progressText)+'</div>'+
                (finite(progress.percent) ? '<div class="agent-progress" role="progressbar" aria-label="'+esc(progressLabel)+'" aria-valuemin="0" aria-valuemax="100" aria-valuenow="'+clampPct(progress.percent)+'"><span style="width:'+clampPct(progress.percent)+'%"></span></div>' : '');
        }
        const workerHtml = workers.length ? '<div class="agent-worker-grid">'+workers.map((worker,wi) => {
            const selected = selectedIndex === wi ? ' selected' : '';
            return '<button class="agent-worker'+selected+'" onclick="selectAgentWorker('+pi+','+wi+')">'+esc(worker.label || worker.id || 'Worker')+' · '+Number(worker.cpuPercent || 0).toFixed(0)+'%</button>';
        }).join('')+'</div>' : '<div class="agent-pool-meta">No live worker process rows.</div>';
        return '<div class="agent-pool"><div class="agent-pool-head"><div><div class="agent-pool-title">'+esc(pool.title || pool.id)+'</div><div class="agent-pool-meta">'+esc(meta)+'</div></div>'+
            '<span class="agent-badge '+badgeTone+'">'+esc((pool.registered ? 'registered · ' : 'discovered · ')+state)+'</span></div>'+progressHtml+workerHtml+
            (selectedIndex >= 0 ? workerDetail(workers[selectedIndex]) : '')+'</div>';
    }).join(''));
}

function selectAgentWorker(poolIndex, workerIndex) {
    const pools = lastAgentSnapshot?.cpu?.snapshot?.pools || [];
    const pool = pools[poolIndex], worker = pool?.workers?.[workerIndex];
    if (!pool || !worker) return;
    agentWorkerSelection[pool.id] = agentWorkerSelection[pool.id] === worker.id ? null : worker.id;
    renderCpuPools(lastAgentSnapshot.cpu);
}

function renderGpuJobs(section) {
    const container = document.getElementById('agents-gpu-jobs');
    const snapshot = section?.snapshot;
    if (!snapshot) {
        setAgentBadge('agents-gpu-count', section?.stale ? 'stale' : 'unavailable', section?.stale ? 'warn' : 'bad');
        patchMarkup(container, '<div class="agent-error">'+esc(section?.error || 'GPU Jobs observer is unavailable.')+'</div>');
        return;
    }
    const lane = snapshot.lane || {};
    const jobs = snapshot.jobs || [];
    const hints = snapshot.hints || [];
    const active = Number(lane.activeCount || 0);
    const laneTone = lane.contention ? 'bad' : active ? 'ok' : section?.stale ? 'warn' : 'info';
    const hasRegisteredJobs = jobs.length > 0;
    const laneLabel = hasRegisteredJobs ? (lane.contention ? 'contention' : lane.state || 'unknown') : 'none registered';
    setAgentBadge('agents-gpu-count', hasRegisteredJobs ? (lane.state || 'unknown')+' · '+jobs.length+' registered' : 'no registered jobs', laneTone);
    const device = snapshot.devices?.[0];
    const laneTitle = (device?.model || 'Local GPU') + ' compute lane';
    let html = '<div class="gpu-lane"><div class="agent-pool-head"><div class="agent-pool-title">'+esc(laneTitle)+'</div><span class="agent-badge '+laneTone+'">'+esc(laneLabel)+'</span></div>'+
        '<div class="gpu-lane-row"><span>Active registered jobs</span><b>'+active+'</b></div><div class="gpu-lane-row"><span>Owner</span><b>'+esc(lane.ownerTitle || '—')+'</b></div>'+
        '<div class="gpu-lane-row"><span>Lease</span><b>'+esc([lane.ownerLeaseMode,lane.ownerLeaseState].filter(Boolean).join(' · ') || '—')+'</b></div>'+
        '</div>';
    if (hasRegisteredJobs) html += jobs.map(job => {
        const progress = job.progress || {};
        const metrics = job.metrics || {};
        const meta = [job.framework,job.backend,job.processAlive === true ? 'process observed' : job.processAlive === false ? 'process not observed' : null,job.owner].filter(Boolean).join(' · ');
        const stateTone = job.state === 'running' || job.state === 'claimed' ? 'ok' : job.state === 'queued' ? 'warn' : job.state === 'failed' || job.state === 'stale' ? 'bad' : 'info';
        const progressText = progress.available ? [progress.processed != null && progress.total != null ? progress.processed+' / '+progress.total : null,progress.unit,finite(progress.percent) ? Number(progress.percent).toFixed(1)+'%' : null,progress.source].filter(Boolean).join(' · ') : 'Progress not published';
        return '<div class="agent-pool"><div class="agent-pool-head"><div><div class="agent-pool-title">'+esc(job.title || job.id)+'</div><div class="agent-pool-meta">'+esc(meta)+'</div></div><span class="agent-badge '+stateTone+'">'+esc(job.state || 'unknown')+'</span></div>'+
            '<div class="agent-pool-meta">'+esc(progressText)+'</div>'+(finite(progress.percent) ? '<div class="agent-progress"><span style="width:'+clampPct(progress.percent)+'%"></span></div>' : '')+
            '<div class="agent-pool-meta">Lease: '+esc([job.lease?.mode,job.lease?.state].filter(Boolean).join(' · ') || 'not published')+(metrics.available && finite(metrics.utilizationPercent) ? ' · owner-published '+Number(metrics.utilizationPercent).toFixed(1)+'% utilization' : '')+'</div></div>';
    }).join('');
    if (hints.length) {
        html += '<div class="hint-row"><span class="agent-badge warn">not proof</span> '+hints.map(hint => esc((hint.reason || 'GPU process hint')+(hint.pid ? ' · pid '+hint.pid : ''))).join('<br>')+'</div>';
    }
    patchMarkup(container, html);
}

function stabilizeAgentSystemData(systemData) {
    const perCore = systemData?.cpu?.per_cpu;
    const validCpu = Array.isArray(perCore) && perCore.length > 0 && perCore.every(value => finite(Number(value)));
    let stable = systemData || {};
    if (validCpu) {
        lastValidAgentCpu = {...systemData.cpu, per_cpu:[...perCore]};
    } else if (lastValidAgentCpu) {
        stable = {...stable, cpu:{...(stable?.cpu || {}), ...lastValidAgentCpu, held:true}};
    }
    const memory = stable?.memory;
    const validMemory = finite(memory?.total_gb) && finite(memory?.available_gb) && finite(memory?.pressure?.headroom_percent);
    if (validMemory) {
        lastValidAgentMemory = {...memory, pressure:{...memory.pressure}};
    } else if (lastValidAgentMemory) {
        stable = {...stable, memory:{...(stable?.memory || {}), ...lastValidAgentMemory, pressure:{...lastValidAgentMemory.pressure}, held:true}};
    }
    return stable;
}

function agentFreshnessState(payload) {
    const cpuStale = payload?.cpu?.stale === true;
    const gpuStale = payload?.gpu?.stale === true;
    if (cpuStale !== gpuStale) {
        return {
            stale: true,
            label: cpuStale ? 'Partial · GPU live · CPU retained' : 'Partial · CPU live · GPU retained',
            observedAt: payload?.observedAt || payload?.generatedAt,
        };
    }
    const stale = Boolean(payload?.stale || cpuStale || gpuStale);
    return {
        stale,
        label: stale ? 'Stale snapshot' : 'Live',
        observedAt: stale ? payload?.generatedAt : payload?.observedAt,
    };
}

function renderAgents(systemData, payload) {
    systemData = stabilizeAgentSystemData(systemData);
    payload = pruneExpiredCpuPools(payload, Date.now());
    cleanupAgentWorkerSelection(payload);
    lastAgentSystemData = systemData;
    lastAgentSnapshot = payload;
    recordCoreActivity(systemData, payload);
    const freshnessState = agentFreshnessState(payload);
    const freshness = document.getElementById('agents-freshness');
    freshness.textContent = freshnessState.label + ' · ' + observedClock(freshnessState.observedAt);
    freshness.className = 'agents-freshness ' + (freshnessState.stale ? 'stale' : 'fresh');
    freshness.title = payload?.error || payload?.cpu?.error || payload?.gpu?.error || '';
    const powerSwarm = payload?.powerSwarm || {};
    const powerSwarmCounts = powerSwarm.counts || {};
    const powerSwarmLive = Number(powerSwarmCounts.live || 0);
    const powerSwarmQueued = Number(powerSwarmCounts.queued || 0);
    const powerSwarmVerified = Number(powerSwarmCounts.verified || 0);
    const powerSwarmButton = document.getElementById('agents-powerswarm-open');
    const powerSwarmRuntime = document.getElementById('agents-powerswarm-runtime');
    const powerSwarmCount = document.getElementById('agents-powerswarm-count');
    const runtimeTruth = powerSwarmRuntimeTruth(powerSwarm.selectedRun,Boolean(powerSwarm.stale));
    powerSwarmRuntime.textContent = runtimeTruth.label;
    powerSwarmRuntime.classList.toggle('known',runtimeTruth.known);
    powerSwarmCount.textContent = !powerSwarm.ok ? '—' : powerSwarmLive ? powerSwarmLive+' live' : powerSwarmQueued ? powerSwarmQueued+' queued' : powerSwarmVerified ? powerSwarmVerified+' verified' : Number(powerSwarmCounts.total || 0)+' workers';
    powerSwarmButton.classList.toggle('live', powerSwarmLive > 0);
    powerSwarmButton.setAttribute('aria-label', 'Open PowerSwarm activity, '+runtimeTruth.label+', '+powerSwarmCount.textContent);
    powerSwarmButton.title = !powerSwarm.ok ? powerSwarmErrorText(powerSwarm.errorCode || powerSwarm.error) : runtimeTruth.label+' · '+(powerSwarmLive ? 'Open live PowerSwarm recursion' : 'Open latest durable PowerSwarm run');
    renderAgentCoreOverview(systemData, payload);
    renderMemoryPressure(systemData?.memory || {});
    renderAgentCoreInspector(systemData, payload);
    renderAiProcesses(payload);
    renderCpuPools(payload?.cpu || {});
    renderGpuJobs(payload?.gpu || {});
}

const NETWORK_ERROR_COPY = Object.freeze(__NETWORK_ERROR_COPY_JSON__);
const NETWORK_RECOVERY_BY_CODE = Object.freeze(__NETWORK_RECOVERIES_JSON__);
const NETWORK_RECOVERY_KINDS = new Set(__NETWORK_RECOVERY_KINDS_JSON__);
const NETWORK_RECOVERY_ACTIONS = new Set(__NETWORK_RECOVERY_ACTIONS_JSON__);

function networkRecoveryDetail(code, rawRecovery) {
    const expected = NETWORK_RECOVERY_BY_CODE[code];
    if (!expected || !rawRecovery || typeof rawRecovery !== 'object') return null;
    const generation = rawRecovery.generation;
    const priority = rawRecovery.priority;
    if (
        typeof rawRecovery.kind !== 'string' ||
        typeof rawRecovery.action !== 'string' ||
        typeof rawRecovery.target !== 'string' ||
        typeof rawRecovery.label !== 'string' ||
        typeof rawRecovery.requiresUserAction !== 'boolean' ||
        !NETWORK_RECOVERY_KINDS.has(rawRecovery.kind) ||
        !NETWORK_RECOVERY_ACTIONS.has(rawRecovery.action) ||
        rawRecovery.kind !== expected.kind ||
        rawRecovery.action !== expected.action ||
        rawRecovery.target !== expected.target ||
        rawRecovery.requiresUserAction !== expected.requiresUserAction ||
        rawRecovery.label !== expected.label ||
        !Number.isInteger(priority) || priority !== Number(expected.priority) ||
        !Number.isInteger(generation) || generation < 0
    ) return null;
    return {...expected, generation};
}

function networkErrorDetail(value, _fallback = 'The local Network service could not complete this request.') {
    const envelope = value?.networkPayload || value;
    const candidate = envelope?.errorDetail || envelope;
    const rawCode = candidate && typeof candidate === 'object' ? String(candidate.code || '') : '';
    const codeKnown = Object.prototype.hasOwnProperty.call(NETWORK_ERROR_COPY, rawCode);
    const code = codeKnown ? rawCode : 'network_internal_error';
    const rawSource = candidate && typeof candidate === 'object' ? String(candidate.source || '') : '';
    const source = /^[a-z0-9-]{1,32}$/.test(rawSource) ? rawSource : 'network';
    const rawObservedAt = candidate && typeof candidate === 'object' ? String(candidate.observedAt || '') : '';
    const observedAt = /^\d{4}-\d{2}-\d{2}T[0-9:.+-]+Z$/.test(rawObservedAt) ? rawObservedAt.slice(0, 40) : null;
    const recovery = codeKnown ? networkRecoveryDetail(code, candidate?.recovery) : null;
    return {
        code,
        source,
        observedAt,
        message: NETWORK_ERROR_COPY[code],
        recovery,
        malformedRecovery: !recovery
    };
}

function networkErrorCopy(value, fallback = 'The local Network service could not complete this request.') {
    return networkErrorDetail(value, fallback).message;
}

function networkFailure(payload) {
    const error = new Error('network-safe-failure');
    error.networkPayload = payload;
    return error;
}

function showNetworkError(message = '', detail = null) {
    const banner = document.getElementById('network-error');
    const body = document.getElementById('network-error-copy');
    const button = document.getElementById('network-recovery-btn');
    const safeMessage = String(message || '').slice(0, 240);
    const recovery = detail?.recovery && NETWORK_RECOVERY_ACTIONS.has(String(detail.recovery.action || '')) ? detail.recovery : null;
    const lowPriority = Boolean(recovery && Number(recovery.priority) < 50);
    banner.setAttribute('data-tone', lowPriority ? 'warning' : 'error');
    const fingerprint = safeMessage ? [
        String(detail?.code || 'network_internal_error'),
        String(detail?.source || 'network'),
        String(detail?.observedAt || ''),
        String(recovery?.action || 'manual'),
        String(recovery?.generation ?? -1),
        String(detail?.deviceId || '')
    ].join('|') : '';
    if (fingerprint !== networkRecoveryFingerprint) {
        networkRecoveryFingerprint = fingerprint;
        networkRecoveryErrorGeneration += 1;
        cancelNetworkRecoveryWatcher();
    }
    body.textContent = safeMessage;
    networkRecoveryContext = safeMessage && recovery ? {
        code: String(detail?.code || 'network_internal_error').slice(0, 64),
        source: String(detail?.source || 'network').slice(0, 32),
        observedAt: detail?.observedAt || null,
        recovery,
        deviceId: detail?.deviceId ? String(detail.deviceId).slice(0, 128) : null,
        errorGeneration: networkRecoveryErrorGeneration,
        lifecycleGeneration: networkLifecycleGeneration
    } : null;
    button.hidden = !safeMessage;
    button.disabled = Boolean(networkRecoveryInFlight) || !networkRecoveryContext;
    button.textContent = networkRecoveryInFlight
        ? 'Fixing…'
        : networkRecoveryContext
            ? String(recovery.label).slice(0, 40)
            : 'Manual review required';
    button.setAttribute('aria-label', networkRecoveryContext
        ? String(recovery.label) + ': ' + safeMessage
        : 'Automatic recovery unavailable: ' + safeMessage);
    banner.hidden = !safeMessage;
}

function showNetworkFailure(value, fallback) {
    const detail = networkErrorDetail(value, fallback);
    showNetworkError(detail.message, detail);
}

function setNetworkFailureFeedback(value, fallback, deviceId = null) {
    const detail = networkErrorDetail(value, fallback);
    detail.deviceId = deviceId ? String(deviceId).slice(0, 128) : null;
    setNetworkFeedback(detail.message, true);
    showNetworkError(detail.message, detail);
}

function setInternetOptimizerFailure(value, fallback) {
    const detail = networkErrorDetail(value, fallback);
    internetOptimizerErrorDetail = detail;
    setNetworkFeedback(detail.message, true);
    if (lastNetworkSnapshot) renderNetworkSnapshot(lastNetworkSnapshot);
    else showNetworkError(detail.message, detail);
    return detail;
}

function clearInternetOptimizerFailure(codes = []) {
    if (!internetOptimizerErrorDetail) return;
    const allowed = new Set(codes.map(code => String(code)));
    if (!allowed.size || allowed.has(String(internetOptimizerErrorDetail.code || ''))) {
        internetOptimizerErrorDetail = null;
        if (lastNetworkSnapshot) renderNetworkSnapshot(lastNetworkSnapshot);
        else showNetworkError('', null);
    }
}

function focusNetworkRecoverySurface(action) {
    const target = action === 'retry-internet-test'
        ? document.getElementById('internet-quality-btn')
        : action === 'retry-internet-optimizer' || action === 'open-wifi-settings'
            ? document.getElementById('internet-optimizer')
        : action === 'enable-ke-link'
        ? document.getElementById('network-link-toggle')
        : action === 'retry-message'
            ? document.getElementById('network-message-btn')
            : action === 'review-message'
                ? document.getElementById('network-message-input')
                : action === 'review-pairing'
                    ? document.getElementById('network-pair-input')
                    : document.getElementById(['review-link', 'review-trust', 'repair-ke-link'].includes(action) ? 'ke-link-card' : 'network-detail-card');
    if (target?.scrollIntoView) target.scrollIntoView({block:'nearest', behavior:'smooth'});
    if (target?.focus) target.focus();
}

function cancelNetworkRecoveryWatcher() {
    if (networkRecoveryWatcher?.timeoutId) clearTimeout(networkRecoveryWatcher.timeoutId);
    networkRecoveryWatcher = null;
}

function noteNetworkRecoveryDeparture() {
    networkWindowTransitionSequence += 1;
    networkLastDepartureSequence = networkWindowTransitionSequence;
}

function noteNetworkRecoveryReturn() {
    networkWindowTransitionSequence += 1;
    networkLastReturnSequence = networkWindowTransitionSequence;
    resumeNetworkRecoveryAfterSettings();
}

function armNetworkRecoveryReturnWatcher(context, departureBaseline) {
    cancelNetworkRecoveryWatcher();
    const watcher = {
        context,
        departureBaseline,
        errorGeneration: context.errorGeneration,
        lifecycleGeneration: context.lifecycleGeneration,
        deadlineAt: Date.now() + NETWORK_RECOVERY_RETURN_TIMEOUT_MS,
        timeoutId: null
    };
    watcher.timeoutId = setTimeout(() => {
        if (networkRecoveryWatcher !== watcher) return;
        networkRecoveryWatcher = null;
        setNetworkFeedback('Automatic return check expired. Click Fix access to try again.', true);
    }, NETWORK_RECOVERY_RETURN_TIMEOUT_MS);
    networkRecoveryWatcher = watcher;
    if (networkLastDepartureSequence > departureBaseline && networkLastReturnSequence > networkLastDepartureSequence) {
        setTimeout(resumeNetworkRecoveryAfterSettings, 0);
    }
}

function restoreNetworkRecoveryFocus() {
    if (currentTab !== 'network') return;
    const button = document.getElementById('network-recovery-btn');
    const fallback = document.getElementById('network-scan-btn');
    setTimeout(() => {
        if (!button.hidden && !button.disabled) button.focus();
        else fallback?.focus();
    }, 0);
}

async function repairNetworkConnection(afterSettings = false, suppliedContext = null) {
    if (!apiReady || currentTab !== 'network' || networkRecoveryInFlight) return;
    const context = suppliedContext || networkRecoveryContext;
    if (
        !context?.recovery ||
        !NETWORK_RECOVERY_ACTIONS.has(String(context.recovery.action || '')) ||
        context.errorGeneration !== networkRecoveryErrorGeneration ||
        context.lifecycleGeneration !== networkLifecycleGeneration
    ) return;
    const action = context.recovery.action;
    const optimizerRecoveryMode = context.source === 'internet-optimizer'
        ? action === 'retry-internet-test'
            ? 'measure'
            : action === 'retry-internet-optimizer' || (action === 'open-wifi-settings' && afterSettings)
                ? 'analyze'
                : null
        : null;
    if (optimizerRecoveryMode && (internetOptimizerInFlight || internetQualityInFlight)) {
        setNetworkFeedback('The current Internet Optimizer operation is still finishing. Retry when its controls are ready.');
        return;
    }
    if (!afterSettings) cancelNetworkRecoveryWatcher();
    if (['enable-ke-link', 'retry-message', 'review-message', 'review-pairing', 'review-trust', 'review-link'].includes(action)) {
        focusNetworkRecoverySurface(action);
        setNetworkFeedback(
            action === 'retry-message'
                ? 'Review the original uncertain message, then use the separate Retry safely button. Fix Connection never sends.'
                : action === 'enable-ke-link'
                    ? 'Use the separate KE Link toggle if you want this Mac to listen. Fix Connection never enables it.'
                    : 'The exact safe review control is ready here. No trust, listener, message, or device action changed automatically.'
        );
        return;
    }
    const requestId = ++networkRecoveryRequestSequence;
    const lifecycleAtStart = networkLifecycleGeneration;
    const errorAtStart = networkRecoveryErrorGeneration;
    const departureBaseline = networkWindowTransitionSequence;
    networkRecoveryInFlight = true;
    if (optimizerRecoveryMode === 'analyze') internetOptimizerInFlight = true;
    if (optimizerRecoveryMode === 'measure') internetQualityInFlight = true;
    const optimizerHeroButton = optimizerRecoveryMode ? document.getElementById('internet-optimizer-btn') : null;
    const optimizerRerunButton = optimizerRecoveryMode ? document.getElementById('internet-rerun-btn') : null;
    const optimizerQualityButton = optimizerRecoveryMode ? document.getElementById('internet-quality-btn') : null;
    if (optimizerHeroButton) optimizerHeroButton.disabled = true;
    if (optimizerRerunButton) optimizerRerunButton.disabled = true;
    if (optimizerQualityButton) {
        optimizerQualityButton.disabled = true;
        if (optimizerRecoveryMode === 'measure') optimizerQualityButton.textContent = 'Measuring…';
    }
    const button = document.getElementById('network-recovery-btn');
    button.disabled = true;
    button.textContent = 'Fixing…';
    let settingsHandoffPending = false;
    try {
        const payload = bridgeJson(await pywebview.api.recover_network_connection(
            context.code,
            context.source,
            context.deviceId || null,
            Boolean(afterSettings),
            context.recovery.generation
        ));
        if (
            requestId !== networkRecoveryRequestSequence ||
            currentTab !== 'network' ||
            lifecycleAtStart !== networkLifecycleGeneration ||
            errorAtStart !== networkRecoveryErrorGeneration
        ) return;
        if (payload.ok === false) throw networkFailure(payload);
        if (payload.state === 'waiting-for-user') {
            settingsHandoffPending = true;
            armNetworkRecoveryReturnWatcher(context, departureBaseline);
            setNetworkFeedback(
                action === 'open-local-network-settings'
                    ? 'Turn on Activity Monitor in Local Network, then return here; one bounded recheck will run automatically.'
                    : action === 'open-wifi-settings'
                        ? 'Review the active Wi-Fi connection, then return here; one local Wi-Fi recheck will run automatically.'
                    : 'Restore a directly connected network interface, then return here; one bounded recheck will run automatically.'
            );
            return;
        }
        if (payload.state === 'action-required') {
            const detail = networkErrorDetail(payload);
            if (context.source === 'internet-optimizer') setInternetOptimizerFailure(payload, detail.message);
            else showNetworkError(detail.message, detail);
            focusNetworkRecoverySurface(detail.recovery?.action || 'review-link');
            return;
        }
        const recoveredInternetQuality = payload.internetQuality
            ? optimizerBoundMeasurement(lastInternetOptimizerSnapshot, payload.internetQuality)
            : null;
        if (payload.internetQuality && !recoveredInternetQuality) {
            throw networkFailure({
                ok: false,
                errorDetail: {
                    code: context.code,
                    source: context.source,
                    observedAt: context.observedAt,
                    recovery: context.recovery
                }
            });
        }
        if (context.source === 'internet-optimizer') clearInternetOptimizerFailure([context.code]);
        setNetworkFeedback(
            payload.state === 'peer-ready' ? 'Secure peer session restored.' :
            payload.state === 'link-rechecked' ? 'KE Link advertiser rechecked without changing listener consent.' :
            payload.state === 'optimizer-rechecked' ? 'Internet Optimizer rechecked the local Wi-Fi path. No settings changed.' :
            payload.state === 'internet-measured' ? 'Internet quality measured. The retry used internet data and changed no settings.' :
            payload.state === 'settings-opened' ? 'Wi-Fi Settings opened. No setting was changed automatically.' :
            'Connection recovery started one bounded current-source recheck.'
        );
        if (payload.optimizerSnapshot) renderInternetOptimizer(payload.optimizerSnapshot);
        if (recoveredInternetQuality) {
            if (lastInternetOptimizerSnapshot) lastInternetOptimizerSnapshot = {...lastInternetOptimizerSnapshot, activeTest:recoveredInternetQuality};
            renderInternetQuality(recoveredInternetQuality);
        }
        if (payload.snapshot) renderNetworkSnapshot(payload.snapshot);
        else await loadNetworkSnapshot();
        scheduleRefresh(650);
    } catch (error) {
        if (
            requestId !== networkRecoveryRequestSequence ||
            currentTab !== 'network' ||
            lifecycleAtStart !== networkLifecycleGeneration ||
            errorAtStart !== networkRecoveryErrorGeneration
        ) return;
        if (context.source === 'internet-optimizer') {
            setInternetOptimizerFailure(error, 'Connection recovery could not complete.');
        } else {
            setNetworkFailureFeedback(error, 'Connection recovery could not complete.', context.deviceId || null);
        }
    } finally {
        networkRecoveryInFlight = false;
        if (optimizerRecoveryMode === 'analyze') internetOptimizerInFlight = false;
        if (optimizerRecoveryMode === 'measure') internetQualityInFlight = false;
        if (optimizerHeroButton) optimizerHeroButton.disabled = internetOptimizerInFlight || internetQualityInFlight;
        if (optimizerRerunButton) optimizerRerunButton.disabled = internetOptimizerInFlight || internetQualityInFlight;
        if (optimizerQualityButton) {
            optimizerQualityButton.textContent = 'Measure internet (uses data)';
            optimizerQualityButton.disabled = internetOptimizerInFlight || internetQualityInFlight || !optimizerAction(lastInternetOptimizerSnapshot, 'measure-internet')?.available;
        }
        if (requestId === networkRecoveryRequestSequence) {
            button.disabled = !networkRecoveryContext;
            if (!button.hidden) button.textContent = networkRecoveryContext?.recovery?.label || 'Manual review required';
            if (!settingsHandoffPending) restoreNetworkRecoveryFocus();
        }
    }
}

function resumeNetworkRecoveryAfterSettings() {
    const watcher = networkRecoveryWatcher;
    if (!watcher) return;
    if (
        Date.now() > watcher.deadlineAt ||
        currentTab !== 'network' ||
        watcher.lifecycleGeneration !== networkLifecycleGeneration ||
        watcher.errorGeneration !== networkRecoveryErrorGeneration
    ) {
        cancelNetworkRecoveryWatcher();
        return;
    }
    if (
        networkLastDepartureSequence <= watcher.departureBaseline ||
        networkLastReturnSequence <= networkLastDepartureSequence
    ) return;
    const context = watcher.context;
    cancelNetworkRecoveryWatcher();
    repairNetworkConnection(true, context);
}

function setNetworkFeedback(message = '', isError = false) {
    const node = document.getElementById('network-action-feedback');
    node.textContent = String(message || '').slice(0, 240);
    node.classList.toggle('error', Boolean(isError));
}

function openNetworkInfo(trigger) {
    const entry = NETWORK_INFO_COPY[String(trigger?.dataset?.networkInfo || '')];
    if (!entry) return;
    const panel = document.getElementById('network-info-panel');
    document.querySelectorAll('[data-network-info]').forEach(button => {
        button.setAttribute('aria-expanded', button === trigger ? 'true' : 'false');
    });
    activeNetworkInfoTrigger = trigger;
    panel.hidden = false;
    document.getElementById('network-info-title').textContent = entry.title;
    document.getElementById('network-info-body').textContent = entry.body;
    panel.scrollIntoView({block:'nearest'});
}

function closeNetworkInfo(restoreFocus = false) {
    const panel = document.getElementById('network-info-panel');
    if (panel.hidden && !activeNetworkInfoTrigger) return;
    const previousTrigger = activeNetworkInfoTrigger;
    panel.hidden = true;
    document.querySelectorAll('[data-network-info]').forEach(button => button.setAttribute('aria-expanded', 'false'));
    activeNetworkInfoTrigger = null;
    if (restoreFocus && previousTrigger?.isConnected && currentTab === 'network') previousTrigger.focus();
}

function toggleNetworkInfo(trigger) {
    const panel = document.getElementById('network-info-panel');
    if (activeNetworkInfoTrigger === trigger && !panel.hidden) {
        closeNetworkInfo(true);
        return;
    }
    openNetworkInfo(trigger);
}

function optimizerAction(snapshot, actionId) {
    return (snapshot?.actions || []).find(action => action?.id === actionId) || null;
}

function optimizerBoundMeasurement(snapshot, measurement = snapshot?.activeTest) {
    const snapshotInterface = String(snapshot?.connection?.interface || '');
    const measurementInterface = String(measurement?.interface || '');
    return measurement && snapshotInterface && measurementInterface === snapshotInterface
        ? measurement
        : null;
}

function internetValue(value, suffix = '', digits = 0) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toFixed(digits) + suffix : '—';
}

function internetDelta(value, suffix = '') {
    const number = Number(value);
    if (!Number.isFinite(number) || Math.abs(number) < .005) return '';
    return ' · Δ ' + (number > 0 ? '+' : '') + number.toFixed(1) + suffix;
}

function renderInternetQuality(measurement) {
    const panel = document.getElementById('internet-quality-result');
    if (!measurement || measurement.ok === false) {
        panel.hidden = true;
        return;
    }
    const comparison = measurement.comparison || {};
    document.getElementById('internet-download').textContent = internetValue(measurement.downloadMbps, ' Mbps', 1) + internetDelta(comparison.downloadMbps, ' Mbps');
    document.getElementById('internet-upload').textContent = internetValue(measurement.uploadMbps, ' Mbps', 1) + internetDelta(comparison.uploadMbps, ' Mbps');
    document.getElementById('internet-latency').textContent = internetValue(measurement.idleLatencyMs, ' ms', 1) + internetDelta(comparison.idleLatencyMs, ' ms');
    document.getElementById('internet-responsiveness').textContent = internetValue(measurement.responsivenessRpm, ' RPM', 0) + internetDelta(comparison.responsivenessRpm, ' RPM');
    panel.hidden = false;
}

function renderInternetOptimizer(snapshot) {
    if (!snapshot || snapshot.ok === false) return;
    const connection = snapshot.connection || {};
    const activeTest = optimizerBoundMeasurement(snapshot);
    lastInternetOptimizerSnapshot = {...snapshot, activeTest};
    const quality = snapshot.quality || {};
    const interference = snapshot.interference || {};
    const state = document.getElementById('internet-optimizer-state');
    state.textContent = snapshot.state === 'complete' ? quality.label || 'Measured' : snapshot.state === 'busy' ? 'Working' : 'Needs attention';
    document.getElementById('internet-health').textContent = Number.isFinite(Number(quality.healthScore))
        ? String(quality.label || 'Measured') + ' · ' + String(Math.round(Number(quality.healthScore))) + '/100'
        : String(quality.label || '—');
    document.getElementById('internet-signal').textContent = internetValue(connection.signalDbm, ' dBm');
    document.getElementById('internet-noise').textContent = connection.noiseDbm == null && connection.snrDb == null
        ? '—'
        : internetValue(connection.noiseDbm, ' dBm') + ' · ' + internetValue(connection.snrDb, ' dB');
    document.getElementById('internet-channel').textContent = connection.channel == null
        ? String(connection.kind === 'ethernet' ? 'Wired' : '—')
        : String(connection.band || 'Wi-Fi') + ' · ch ' + String(connection.channel) + (connection.widthMHz ? ' / ' + String(connection.widthMHz) + ' MHz' : '');
    document.getElementById('internet-link-rate').textContent = internetValue(connection.transmitRateMbps, ' Mbps', 0);
    document.getElementById('internet-nearby-count').textContent = interference.measured
        ? String(Number(interference.nearbyObservationCount ?? interference.nearbyNetworkCount ?? 0)) + (interference.partial ? '+ observations · capped' : ' observations')
        : 'partial';
    document.getElementById('internet-confidence').textContent = String(quality.confidence || 'partial');

    const channels = document.getElementById('internet-channel-list');
    emptyNode(channels);
    const channelRows = Array.isArray(interference.channels) ? interference.channels.slice(0, 24) : [];
    if (!channelRows.length) {
        const empty = document.createElement('div');
        empty.className = 'network-service-meta';
        empty.textContent = 'No comparable channel-pressure rows were available.';
        channels.appendChild(empty);
    }
    channelRows.forEach(item => {
        const row = document.createElement('div');
        row.className = 'internet-channel' + (item.current ? ' current' : '');
        const label = document.createElement('strong');
        label.textContent = 'Ch ' + String(item.channel);
        const track = document.createElement('div');
        track.className = 'internet-channel-track';
        const fill = document.createElement('span');
        fill.style.width = Math.max(2, Math.min(100, Number(item.pressurePercent || 0))) + '%';
        track.appendChild(fill);
        const count = document.createElement('small');
        count.textContent = String(Number(item.nearbyCount || 0)) + ' seen';
        row.append(label, track, count);
        channels.appendChild(row);
    });
    const recommendation = interference.recommendation || {};
    document.getElementById('internet-channel-recommendation').textContent = String(recommendation.reason || 'Keep the router on Auto unless a measured result supports a change.').slice(0, 500);

    const findings = document.getElementById('internet-finding-list');
    emptyNode(findings);
    (Array.isArray(snapshot.findings) ? snapshot.findings.slice(0, 12) : []).forEach(item => {
        const row = document.createElement('div');
        const severity = ['high', 'medium', 'attention', 'good'].includes(item?.severity) ? item.severity : 'attention';
        row.className = 'internet-finding ' + severity;
        const dot = document.createElement('span');
        dot.className = 'internet-finding-dot';
        dot.setAttribute('aria-hidden', 'true');
        const copy = document.createElement('div');
        const title = document.createElement('strong');
        title.textContent = String(item?.title || 'Review connection').slice(0, 120);
        const detail = document.createElement('p');
        detail.textContent = String(item?.detail || '').slice(0, 500);
        copy.append(title, detail);
        row.append(dot, copy);
        findings.appendChild(row);
    });
    if (!findings.children.length) {
        const empty = document.createElement('div');
        empty.className = 'network-service-meta';
        empty.textContent = 'No safe recommendation was inferred from the available evidence.';
        findings.appendChild(empty);
    }

    const routerAction = optimizerAction(snapshot, 'open-router-settings');
    const qualityAction = optimizerAction(snapshot, 'measure-internet');
    const diagnosticAction = optimizerAction(snapshot, 'wireless-diagnostics');
    const wifiAction = optimizerAction(snapshot, 'open-wifi-settings');
    document.getElementById('internet-router-btn').disabled = !routerAction?.available;
    document.getElementById('internet-quality-btn').disabled = !qualityAction?.available || internetQualityInFlight || internetOptimizerInFlight;
    document.getElementById('internet-diagnostics-btn').disabled = !diagnosticAction?.available;
    document.getElementById('internet-wifi-settings-btn').disabled = !wifiAction?.available;
    document.getElementById('internet-optimizer-disclosure').textContent =
        'No settings changed. Nearby network names and identifiers were not read, displayed, or saved. ' +
        String(snapshot.router?.boundary || 'Router changes require your visible authorization.').slice(0, 260) +
        ' Before/after deltas are observational and do not prove that one change caused the result.';
    renderInternetQuality(activeTest);
    document.getElementById('internet-optimizer-loading').hidden = true;
    document.getElementById('internet-optimizer-results').hidden = false;
}

function scrollInternetOptimizerIntoView(panel, behavior = 'smooth') {
    const scroller = document.querySelector('#network-tab .network-scroll');
    if (!scroller || !panel) return;
    const scrollerBox = scroller.getBoundingClientRect();
    const panelBox = panel.getBoundingClientRect();
    const top = Math.max(0, scroller.scrollTop + panelBox.top - scrollerBox.top - 10);
    const reducedMotion = Boolean(window.matchMedia?.('(prefers-reduced-motion: reduce)').matches);
    if (typeof scroller.scrollTo === 'function') scroller.scrollTo({top, behavior: reducedMotion ? 'auto' : behavior});
    else scroller.scrollTop = top;
}

function openInternetOptimizer() {
    const panel = document.getElementById('internet-optimizer');
    panel.hidden = false;
    try { panel.focus({preventScroll: true}); }
    catch (_) { panel.focus(); }
    scrollInternetOptimizerIntoView(panel);
    analyzeInternetConnection();
}

function closeInternetOptimizer(restoreFocus = false) {
    const panel = document.getElementById('internet-optimizer');
    if (panel.hidden) return;
    internetOptimizerGeneration += 1;
    panel.hidden = true;
    if (restoreFocus && currentTab === 'network') document.getElementById('internet-optimizer-btn').focus();
}

async function analyzeInternetConnection() {
    if (!apiReady || currentTab !== 'network' || internetOptimizerInFlight || internetQualityInFlight) return;
    const panel = document.getElementById('internet-optimizer');
    const loading = document.getElementById('internet-optimizer-loading');
    const results = document.getElementById('internet-optimizer-results');
    const heroButton = document.getElementById('internet-optimizer-btn');
    const rerunButton = document.getElementById('internet-rerun-btn');
    const qualityButton = document.getElementById('internet-quality-btn');
    const requestGeneration = ++internetOptimizerGeneration;
    panel.hidden = false;
    panel.setAttribute('aria-busy', 'true');
    loading.hidden = false;
    loading.textContent = "Reading this Mac's active Wi-Fi path and nearby channel pressure…";
    results.hidden = true;
    document.getElementById('internet-optimizer-state').textContent = 'Measuring';
    internetOptimizerInFlight = true;
    heroButton.disabled = true;
    rerunButton.disabled = true;
    qualityButton.disabled = true;
    try {
        const payload = bridgeJson(await pywebview.api.analyze_internet_connection());
        if (requestGeneration !== internetOptimizerGeneration || currentTab !== 'network' || panel.hidden) return;
        if (payload.ok === false) throw networkFailure(payload);
        if (payload.state === 'busy') {
            loading.textContent = 'The current local Wi-Fi analysis is still finishing. Try again in a moment.';
            return;
        }
        clearInternetOptimizerFailure(['wifi_diagnostics_permission_denied', 'internet_optimizer_unavailable']);
        renderInternetOptimizer(payload);
        setNetworkFeedback('Internet Optimizer measured the local radio path. No settings changed.');
    } catch (error) {
        if (requestGeneration !== internetOptimizerGeneration || currentTab !== 'network' || panel.hidden) return;
        const detail = setInternetOptimizerFailure(error, 'Internet Optimizer could not complete the local Wi-Fi analysis.');
        loading.hidden = false;
        loading.textContent = detail.message + ' Use the one-click recovery above.';
        results.hidden = true;
        document.getElementById('internet-optimizer-state').textContent = 'Needs help';
    } finally {
        internetOptimizerInFlight = false;
        panel.removeAttribute('aria-busy');
        heroButton.disabled = internetQualityInFlight;
        rerunButton.disabled = internetQualityInFlight;
        qualityButton.disabled = internetQualityInFlight || !optimizerAction(lastInternetOptimizerSnapshot, 'measure-internet')?.available;
    }
}

async function measureInternetQuality() {
    if (!apiReady || currentTab !== 'network' || internetQualityInFlight || internetOptimizerInFlight) return;
    const button = document.getElementById('internet-quality-btn');
    const heroButton = document.getElementById('internet-optimizer-btn');
    const rerunButton = document.getElementById('internet-rerun-btn');
    const requestGeneration = internetOptimizerGeneration;
    internetQualityInFlight = true;
    button.disabled = true;
    heroButton.disabled = true;
    rerunButton.disabled = true;
    button.textContent = 'Measuring…';
    setNetworkFeedback('Running Apple networkQuality. This active test connects to the internet and uses plan data.');
    try {
        const payload = bridgeJson(await pywebview.api.measure_internet_quality());
        if (requestGeneration !== internetOptimizerGeneration || currentTab !== 'network' || document.getElementById('internet-optimizer').hidden) return;
        if (payload.ok === false) throw networkFailure(payload);
        const activeTest = optimizerBoundMeasurement(lastInternetOptimizerSnapshot, payload);
        if (!activeTest) {
            renderInternetQuality(null);
            setNetworkFeedback('The active connection changed during the data test. Run the data test again on the current connection.', true);
            return;
        }
        clearInternetOptimizerFailure(['internet_quality_unavailable']);
        if (lastInternetOptimizerSnapshot) lastInternetOptimizerSnapshot = {...lastInternetOptimizerSnapshot, activeTest};
        renderInternetQuality(activeTest);
        setNetworkFeedback('Internet quality measured. Re-run after an authorized change to see the before/after delta.');
    } catch (error) {
        if (requestGeneration !== internetOptimizerGeneration || currentTab !== 'network') return;
        setInternetOptimizerFailure(error, 'Internet quality measurement could not complete.');
    } finally {
        internetQualityInFlight = false;
        button.textContent = 'Measure internet (uses data)';
        button.disabled = internetOptimizerInFlight || !optimizerAction(lastInternetOptimizerSnapshot, 'measure-internet')?.available;
        heroButton.disabled = internetOptimizerInFlight;
        rerunButton.disabled = internetOptimizerInFlight;
    }
}

async function performInternetOptimizerAction(actionId) {
    if (!apiReady || currentTab !== 'network') return;
    const allowed = new Set(['open-router-settings', 'wireless-diagnostics', 'open-wifi-settings']);
    if (!allowed.has(actionId)) return;
    try {
        const payload = bridgeJson(await pywebview.api.perform_internet_optimizer_action(actionId));
        if (payload.ok === false) throw networkFailure(payload);
        clearInternetOptimizerFailure(['system_settings_unavailable']);
        const label = actionId === 'open-router-settings' ? 'Router settings opened. Review the measured recommendation before authorizing a change.' : actionId === 'wireless-diagnostics' ? 'Wireless Diagnostics opened. It does not change network settings.' : 'Wi-Fi Settings opened. No setting was changed automatically.';
        setNetworkFeedback(label);
    } catch (error) {
        setInternetOptimizerFailure(error, 'The requested settings handoff could not open.');
    }
}

function networkDeviceGlyph(type) {
    return ({gateway:'⌁',computer:'▣',phone:'▯',speaker:'◖',display:'▱',printer:'▤',storage:'▥',device:'◇'})[String(type || '').toLowerCase()] || '◇';
}

function networkAge(device) {
    const seconds = Number(device?.ageSeconds);
    if (!Number.isFinite(seconds)) return 'unknown';
    if (seconds < 2) return 'now';
    if (seconds < 60) return Math.round(seconds) + 's ago';
    return Math.round(seconds / 60) + 'm ago';
}

function networkSelectedDevice(snapshot = lastNetworkSnapshot) {
    return (snapshot?.devices || []).find(device => device.id === selectedNetworkDeviceId) || null;
}

function networkCurrentErrors(snapshot) {
    return [
        ...(snapshot?.errors || []),
        ...(snapshot?.link?.errors || []),
        ...(snapshot?.link?.error ? [snapshot.link.error] : []),
        ...(internetOptimizerErrorDetail ? [internetOptimizerErrorDetail] : [])
    ]
        .sort((a, b) => {
            const aDetail = networkErrorDetail(a);
            const bDetail = networkErrorDetail(b);
            const aPriority = aDetail.recovery ? Number(aDetail.recovery.priority) : 1000;
            const bPriority = bDetail.recovery ? Number(bDetail.recovery.priority) : 1000;
            return bPriority - aPriority || String(b?.observedAt || '').localeCompare(String(a?.observedAt || ''));
        })
        .filter((item, index, rows) => rows.findIndex(other => String(other?.source || '') === String(item?.source || '') && String(other?.code || '') === String(item?.code || '')) === index)
        .slice(0, 2);
}

function renderNetworkSnapshot(snapshot) {
    if (!snapshot || snapshot.ok === false) {
        showNetworkFailure(snapshot, 'Local network discovery is unavailable.');
        return;
    }
    lastNetworkSnapshot = snapshot;
    const currentErrors = networkCurrentErrors(snapshot);
    const primaryError = currentErrors[0] || null;
    showNetworkError(
        currentErrors.map(item => networkErrorCopy(item)).join(' · '),
        primaryError ? networkErrorDetail(primaryError) : null
    );
    const counts = snapshot.counts || {};
    document.getElementById('network-count-observed').textContent = String(counts.observed || 0);
    document.getElementById('network-count-online').textContent = String(counts.online || 0);
    document.getElementById('network-count-recent').textContent = String(counts.recent || 0);
    document.getElementById('network-count-paired').textContent = String(counts.paired || 0);
    const interfaces = snapshot.local?.interfaces || [];
    const eligibleSegmentCount = Number(snapshot.coverage?.eligibleSegmentCount || 0);
    const coverageLimited = Boolean(snapshot.coverage?.limited);
    const maxHosts = Number(snapshot.scan?.maxHostsPerScan || 0);
    document.getElementById('network-coverage-value').textContent = eligibleSegmentCount ? String(eligibleSegmentCount) + (coverageLimited ? '*' : '') : '—';
    const excludedCount = Number(snapshot.coverage?.excludedInterfaceCount || 0);
    const partialCopy = coverageLimited ? 'Partial scan · capped at ' + String(maxHosts || 254) + ' hosts per cycle · ' : '';
    const excludedCopy = excludedCount
        ? String(excludedCount) + ' interface' + (excludedCount === 1 ? '' : 's') + ' excluded'
        : '';
    document.getElementById('network-coverage-meta').textContent = interfaces.length
        ? partialCopy + interfaces.map(item => item.name).join(' · ') + (excludedCopy ? ' · ' + excludedCopy : '')
        : 'no eligible directly connected segment';
    document.getElementById('network-boundary-copy').textContent = (coverageLimited ? 'This cycle is partial because the bounded host cap was reached. ' : '') + (snapshot.coverage?.boundary || 'Coverage is limited to observable devices on directly connected segments.');
    const pulse = document.getElementById('network-live-pulse');
    pulse.classList.toggle('paused', !snapshot.active);
    document.getElementById('network-live-copy').textContent = snapshot.active
        ? (snapshot.scan?.inProgress ? 'Actively reconciling your local segments' : 'Live observation · scan ' + String(snapshot.scan?.sequence || 0))
        : 'Discovery paused outside this tab';
    document.getElementById('network-scan-status').textContent = snapshot.scan?.inProgress
        ? 'Scanning across bounded local evidence sources…'
        : snapshot.scan?.lastScanAt ? 'Last reconciled ' + new Date(snapshot.scan.lastScanAt).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'}) : 'Waiting for the first observation';
    renderNetworkLink(snapshot.link || {});
    const existing = networkSelectedDevice(snapshot);
    if (!existing) selectedNetworkDeviceId = (snapshot.devices || [])[0]?.id || null;
    renderNetworkDeviceList(snapshot);
    renderNetworkDeviceDetail(networkSelectedDevice(snapshot), snapshot);
}

function renderNetworkDeviceList(snapshot) {
    const list = document.getElementById('network-device-list');
    emptyNode(list);
    const query = searchFilter.trim();
    const devices = (snapshot?.devices || []).filter(device => {
        if (networkDeviceFilter === 'online' && device.state !== 'online') return false;
        if (networkDeviceFilter === 'paired' && !device.paired) return false;
        if (!query) return true;
        const haystack = [device.name, device.type, ...(device.addresses || []), ...(device.sources || [])].join(' ').toLowerCase();
        return haystack.includes(query);
    });
    if (!devices.length) {
        const empty = document.createElement('div');
        empty.className = 'network-empty';
        empty.textContent = snapshot?.scan?.inProgress ? 'Listening now — devices will appear as evidence arrives.' : 'No devices match this view. Silent or isolated devices may still exist.';
        list.appendChild(empty);
        return;
    }
    devices.forEach(device => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'network-device' + (device.id === selectedNetworkDeviceId ? ' selected' : '');
        button.setAttribute('aria-pressed', device.id === selectedNetworkDeviceId ? 'true' : 'false');
        const icon = document.createElement('span');
        icon.className = 'network-device-icon';
        icon.setAttribute('aria-hidden', 'true');
        icon.textContent = networkDeviceGlyph(device.type);
        const body = document.createElement('span');
        const name = document.createElement('span');
        name.className = 'network-device-name';
        name.textContent = device.name || 'Observed device';
        const meta = document.createElement('span');
        meta.className = 'network-device-meta';
        meta.textContent = (device.addresses || []).join(' · ') || 'address unavailable';
        const sources = document.createElement('span');
        sources.className = 'network-device-sources';
        sources.textContent = (device.sources || []).join(' + ') || 'historical observation';
        body.append(name, meta, sources);
        const state = document.createElement('span');
        state.className = 'network-device-state';
        const dot = document.createElement('span');
        dot.className = 'network-state-dot ' + statusClass(device.state);
        state.append(dot, document.createTextNode(String(device.state || 'unknown')));
        button.append(icon, body, state);
        if (device.paired) {
            const trust = document.createElement('span');
            trust.className = 'network-device-trust';
            trust.textContent = device.remoteReady ? 'trusted · ready' : 'trusted';
            button.appendChild(trust);
        }
        button.addEventListener('click', () => {
            if (selectedNetworkDeviceId !== device.id) {
                pendingNetworkMessage = null;
                document.getElementById('network-message-input').value = '';
            }
            selectedNetworkDeviceId = device.id;
            setNetworkFeedback('');
            renderNetworkDeviceList(lastNetworkSnapshot);
            renderNetworkDeviceDetail(device, lastNetworkSnapshot);
        });
        list.appendChild(button);
    });
}

function networkActionButton(label, action, serviceId = null) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'network-action';
    button.textContent = label;
    button.addEventListener('click', async () => {
        button.disabled = true;
        try { await performNetworkAction(action, serviceId); } finally { button.disabled = false; }
    });
    return button;
}

function networkControlButton(label, callback) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'network-action';
    button.textContent = label;
    button.addEventListener('click', async () => {
        button.disabled = true;
        try { await callback(); } finally { button.disabled = false; }
    });
    return button;
}

function renderNetworkDeviceDetail(device, snapshot) {
    const empty = document.getElementById('network-detail-empty');
    const content = document.getElementById('network-detail-content');
    empty.hidden = Boolean(device);
    content.hidden = !device;
    if (!device) return;
    document.getElementById('network-detail-name').textContent = device.name || 'Observed device';
    document.getElementById('network-detail-address').textContent = (device.addresses || []).join(' · ') || 'No current address';
    const state = document.getElementById('network-detail-state');
    state.textContent = String(device.state || 'unknown');
    state.className = 'status-pill ' + statusClass(device.state);
    const trust = document.getElementById('network-detail-trust');
    trust.hidden = !device.paired;
    const ready = document.getElementById('network-detail-ready');
    ready.hidden = !device.remoteReady;
    document.getElementById('network-detail-kind').textContent = device.type || 'device';
    document.getElementById('network-detail-latency').textContent = Number.isFinite(Number(device.latencyMs)) ? Number(device.latencyMs).toFixed(1) + ' ms' : 'not sampled';
    document.getElementById('network-detail-interface').textContent = device.interface || 'observed';
    document.getElementById('network-detail-age').textContent = networkAge(device);
    const sourceRow = document.getElementById('network-detail-sources');
    emptyNode(sourceRow);
    (device.sources || ['historical']).forEach(value => {
        const chip = document.createElement('span');
        chip.className = 'network-chip';
        chip.textContent = value;
        sourceRow.appendChild(chip);
    });
    const actions = document.getElementById('network-detail-actions');
    emptyNode(actions);
    if ((device.capabilities || []).includes('ping')) actions.appendChild(networkActionButton('Ping', 'ping'));
    if ((device.capabilities || []).includes('wake')) actions.appendChild(networkActionButton('Wake', 'wake'));
    if ((device.capabilities || []).includes('verify-link')) actions.appendChild(networkControlButton('Verify secure session', verifySelectedNetworkPeer));
    if ((device.capabilities || []).includes('revoke-peer')) actions.appendChild(networkControlButton('Revoke trust', revokeSelectedNetworkPeer));
    if (!actions.childElementCount) {
        const chip = document.createElement('span');
        chip.className = 'network-chip';
        chip.textContent = 'No safe generic action advertised';
        actions.appendChild(chip);
    }
    const services = document.getElementById('network-detail-services');
    emptyNode(services);
    (device.services || []).forEach(service => {
        const row = document.createElement('div');
        row.className = 'network-service';
        const copy = document.createElement('div');
        copy.style.minWidth = '0';
        const title = document.createElement('div');
        title.className = 'network-service-name';
        title.textContent = service.name || service.label || service.type || 'Advertised service';
        const meta = document.createElement('div');
        meta.className = 'network-service-meta';
        meta.textContent = [service.label, service.port ? 'port ' + service.port : ''].filter(Boolean).join(' · ');
        copy.append(title, meta);
        row.appendChild(copy);
        if (service.url && ['http','https','ssh','vnc','smb'].includes(service.scheme)) row.appendChild(networkActionButton('Open', 'open-service', service.id));
        services.appendChild(row);
    });
    if (!services.childElementCount) {
        const row = document.createElement('div');
        row.className = 'network-service';
        const copy = document.createElement('div');
        copy.className = 'network-service-meta';
        copy.textContent = 'No openable service advertised';
        row.appendChild(copy);
        services.appendChild(row);
    }
    document.getElementById('network-pair-panel').hidden = !(device.capabilities || []).includes('pair');
    const pairingEnabled = Boolean(snapshot?.link?.enabled);
    document.getElementById('network-pair-btn').disabled = !pairingEnabled;
    document.getElementById('network-pair-input').disabled = !pairingEnabled;
    document.getElementById('network-pair-requirement').textContent = pairingEnabled
        ? 'KE Link is enabled. Pairing records trust; it does not grant execution authority.'
        : 'Enable KE Link explicitly before pairing. Pair never enables the listener.';
    const messageReady = Boolean(device.remoteReady && (device.capabilities || []).includes('message'));
    document.getElementById('network-message-panel').hidden = !messageReady;
    document.getElementById('network-message-btn').disabled = !messageReady;
    renderNetworkMessages(device, snapshot?.link?.messages || []);
}

function renderNetworkMessages(device, messages) {
    const list = document.getElementById('network-message-list');
    emptyNode(list);
    if (!device || !device.paired) return;
    const selected = messages.filter(message => message.peerId === device.linkPeerId).slice(-40);
    if (pendingNetworkMessage && pendingNetworkMessage.deviceId === device.id) selected.push(pendingNetworkMessage);
    if (!selected.length) {
        const empty = document.createElement('div');
        empty.className = 'network-service-meta';
        empty.textContent = device.remoteReady ? 'Ready. No in-memory messages yet.' : 'Trusted. Verify a fresh secure session to message.';
        list.appendChild(empty);
        return;
    }
    selected.slice(-40).forEach(message => {
        const bubble = document.createElement('div');
        bubble.className = 'network-message ' + (message.direction === 'outbound' ? 'outbound' : 'inbound');
        const meta = document.createElement('div');
        meta.className = 'network-message-meta';
        const state = ['attempted','uncertain-after-send','delivered'].includes(message.state) ? message.state : 'delivered';
        const observed = message.observedAt ? new Date(message.observedAt).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : 'now';
        meta.textContent = (message.direction === 'outbound' ? 'You' : message.peerName || 'Peer') + ' · ' + state + ' · ' + observed;
        const body = document.createElement('div');
        body.textContent = message.body || '';
        bubble.append(meta, body);
        list.appendChild(bubble);
    });
    list.scrollTop = list.scrollHeight;
}

function renderNetworkLink(link) {
    const enabled = Boolean(link.enabled);
    const advertising = enabled && Boolean(link.advertising);
    document.getElementById('network-link-toggle').textContent = enabled ? 'Disable KE Link' : 'Enable KE Link';
    document.getElementById('network-pair-code-btn').disabled = !enabled;
    document.getElementById('ke-link-status').textContent = enabled
        ? (advertising ? 'Opt-in listener stays available until disabled' : 'Enabled, but local advertisement is unavailable') + ' · one direct IPv4 interface · ' + String(link.pairedPeerCount || 0) + ' trusted · ' + String(link.readyPeerCount || 0) + ' ready'
        : 'Off by default · opt in to become discoverable to other KE Monitors';
    document.getElementById('ke-link-boundary').textContent = link.boundary || 'Plain-text messages only. Messages never grant execution or authority.';
    const code = document.getElementById('network-pair-code');
    if (enabled && link.pairing?.code) {
        code.hidden = false;
        code.textContent = link.pairing.code + ' · expires ' + new Date(link.pairing.expiresAt).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    } else {
        code.hidden = true;
        code.textContent = '';
    }
    const trustedList = document.getElementById('network-trusted-peers');
    emptyNode(trustedList);
    const trustedPeers = Array.isArray(link.trustedPeers) ? link.trustedPeers.slice(0, 128) : [];
    if (!trustedPeers.length) {
        const empty = document.createElement('div');
        empty.className = 'network-service-meta';
        empty.textContent = 'No persistently trusted peers.';
        trustedList.appendChild(empty);
    }
    trustedPeers.forEach(peer => {
        const row = document.createElement('div');
        row.className = 'ke-trusted-peer';
        const copy = document.createElement('div');
        copy.className = 'ke-trusted-peer-copy';
        const name = document.createElement('strong');
        name.textContent = peer.name || 'KE Link peer';
        const state = document.createElement('span');
        state.textContent = peer.ready ? 'Trusted · authenticated session ready' : 'Trusted · offline or not verified';
        copy.append(name, state);
        const revoke = document.createElement('button');
        revoke.className = 'network-action';
        revoke.type = 'button';
        revoke.textContent = 'Revoke';
        revoke.addEventListener('click', () => revokeTrustedNetworkPeer(peer.id));
        row.append(copy, revoke);
        trustedList.appendChild(row);
    });
}

async function startNetworkDiscovery() {
    await networkDiscoveryStopPromise;
    if (!apiReady || currentTab !== 'network' || networkDiscoveryStarted) return;
    networkDiscoveryStarted = true;
    try {
        const payload = bridgeJson(await pywebview.api.start_network_discovery());
        if (payload.ok === false) throw networkFailure(payload);
        renderNetworkSnapshot(payload);
    } catch (error) {
        networkDiscoveryStarted = false;
        showNetworkFailure(error, 'Discovery could not start.');
    }
}

async function stopNetworkDiscovery() {
    networkDiscoveryStarted = false;
    if (!apiReady) return;
    try { await pywebview.api.stop_network_discovery(); } catch (_error) {}
}

async function loadNetworkSnapshot() {
    if (!apiReady || currentTab !== 'network') return;
    try {
        const payload = bridgeJson(await pywebview.api.get_network_snapshot());
        renderNetworkSnapshot(payload);
    } catch (error) { showNetworkFailure(error, 'The local Network snapshot is temporarily unavailable.'); }
}

async function requestNetworkScan() {
    const button = document.getElementById('network-scan-btn');
    button.disabled = true;
    try {
        const payload = bridgeJson(await pywebview.api.request_network_scan());
        if (payload.ok === false) throw networkFailure(payload);
        document.getElementById('network-scan-status').textContent = payload.rateLimited ? 'Deep scan available again in ' + String(payload.retryAfterSeconds) + 's' : 'Deep scan queued…';
        scheduleRefresh(350);
    } catch (error) { showNetworkFailure(error, 'Scan was rejected.'); }
    finally { button.disabled = false; }
}

async function toggleKeLink() {
    const button = document.getElementById('network-link-toggle');
    const enabled = Boolean(lastNetworkSnapshot?.link?.enabled);
    button.disabled = true;
    try {
        const payload = bridgeJson(await pywebview.api.set_ke_link_enabled(!enabled));
        if (payload.ok === false) throw networkFailure(payload);
        await loadNetworkSnapshot();
    } catch (error) { showNetworkFailure(error, 'KE Link could not change state.'); }
    finally { button.disabled = false; }
}

async function beginKeLinkPairing() {
    const button = document.getElementById('network-pair-code-btn');
    button.disabled = true;
    try {
        const payload = bridgeJson(await pywebview.api.begin_ke_link_pairing());
        if (payload.ok === false) throw networkFailure(payload);
        const code = document.getElementById('network-pair-code');
        code.hidden = false;
        code.textContent = String(payload.code || '') + ' · expires ' + new Date(payload.expiresAt).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
        await loadNetworkSnapshot();
    } catch (error) { showNetworkFailure(error, 'Pairing could not begin.'); }
    finally { button.disabled = false; }
}

async function pairSelectedNetworkDevice() {
    const device = networkSelectedDevice();
    const input = document.getElementById('network-pair-input');
    const button = document.getElementById('network-pair-btn');
    if (!device || !lastNetworkSnapshot?.link?.enabled) {
        setNetworkFailureFeedback({
            code:'ke_link_disabled', source:'pairing',
            observedAt:new Date().toISOString(),
            recovery:{
                ...NETWORK_RECOVERY_BY_CODE.ke_link_disabled,
                generation:Number(lastNetworkSnapshot?.link?.generation || 0)
            }
        }, 'Enable KE Link explicitly before pairing. Pair never enables the listener.', device?.id || null);
        return;
    }
    button.disabled = true;
    setNetworkFeedback('Authenticating one-time code and certificate…');
    try {
        const payload = bridgeJson(await pywebview.api.pair_network_device(device.id, input.value));
        if (payload.ok === false) throw networkFailure(payload);
        input.value = '';
        setNetworkFeedback('Trusted and ready after a fresh authenticated session.');
        await loadNetworkSnapshot();
    } catch (error) { setNetworkFailureFeedback(error, 'Pairing failed.', device.id); }
    finally { button.disabled = !lastNetworkSnapshot?.link?.enabled; }
}

async function verifySelectedNetworkPeer() {
    const device = networkSelectedDevice();
    if (!device || !device.paired) return;
    setNetworkFeedback('Verifying TLS pin and authenticated session health…');
    try {
        const payload = bridgeJson(await pywebview.api.verify_network_peer(device.id));
        if (payload.ok === false) throw networkFailure(payload);
        setNetworkFeedback('Ready for this bounded authenticated session.');
        await loadNetworkSnapshot();
    } catch (error) { setNetworkFailureFeedback(error, 'Secure session verification failed.', device.id); }
}

async function revokeSelectedNetworkPeer() {
    const device = networkSelectedDevice();
    if (!device || !device.paired) return;
    setNetworkFeedback('Revoking persistent trust and invalidating the old secret…');
    try {
        const payload = bridgeJson(await pywebview.api.revoke_network_peer(device.id));
        if (payload.ok === false) throw networkFailure(payload);
        pendingNetworkMessage = null;
        document.getElementById('network-message-input').value = '';
        setNetworkFeedback('Trust revoked. A new explicit pairing is required.');
        await loadNetworkSnapshot();
    } catch (error) { setNetworkFailureFeedback(error, 'Trust could not be revoked.', device.id); }
}

async function revokeTrustedNetworkPeer(peerId) {
    if (!/^[a-f0-9]{32}$/.test(String(peerId || ''))) return;
    setNetworkFeedback('Revoking persistent trust and invalidating the old secret…');
    try {
        const payload = bridgeJson(await pywebview.api.revoke_network_trusted_peer(peerId));
        if (payload.ok === false) throw networkFailure(payload);
        pendingNetworkMessage = null;
        document.getElementById('network-message-input').value = '';
        setNetworkFeedback('Trust revoked. A new explicit pairing is required.');
        await loadNetworkSnapshot();
    } catch (error) { setNetworkFailureFeedback(error, 'Trust could not be revoked.', null); }
}

function newNetworkClientMessageId() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
}

async function sendSelectedNetworkMessage() {
    const device = networkSelectedDevice();
    const input = document.getElementById('network-message-input');
    const button = document.getElementById('network-message-btn');
    const message = input.value;
    if (!device || !device.remoteReady || !message.trim()) return;
    if (!pendingNetworkMessage || pendingNetworkMessage.deviceId !== device.id || pendingNetworkMessage.body !== message) {
        pendingNetworkMessage = {
            deviceId: device.id,
            peerId: device.linkPeerId,
            clientMessageId: newNetworkClientMessageId(),
            body: message,
            direction: 'outbound',
            state: 'attempted',
            observedAt: new Date().toISOString()
        };
    } else {
        pendingNetworkMessage.state = 'attempted';
    }
    button.disabled = true;
    button.textContent = 'Sending…';
    setNetworkFeedback('Attempted over the fresh authenticated KE Link session…');
    renderNetworkMessages(device, lastNetworkSnapshot?.link?.messages || []);
    try {
        const payload = bridgeJson(await pywebview.api.send_network_message(device.id, message, pendingNetworkMessage.clientMessageId));
        if (payload.ok === false) {
            if (payload.attempted || payload.state === 'uncertain-after-send') {
                pendingNetworkMessage.state = 'uncertain-after-send';
                setNetworkFailureFeedback(payload, 'Delivery is uncertain. Retry uses the same message identifier.', device.id);
                renderNetworkMessages(device, lastNetworkSnapshot?.link?.messages || []);
                return;
            }
            pendingNetworkMessage = null;
            throw networkFailure(payload);
        }
        pendingNetworkMessage.state = 'delivered';
        renderNetworkMessages(device, lastNetworkSnapshot?.link?.messages || []);
        input.value = '';
        setNetworkFeedback('Delivered and authenticated.');
        pendingNetworkMessage = null;
        await loadNetworkSnapshot();
    } catch (error) {
        if (pendingNetworkMessage) {
            pendingNetworkMessage.state = 'uncertain-after-send';
            setNetworkFailureFeedback({
                code:'message_delivery_uncertain',
                source:'message',
                observedAt:new Date().toISOString(),
                recovery:{
                    ...NETWORK_RECOVERY_BY_CODE.message_delivery_uncertain,
                    generation:Number(lastNetworkSnapshot?.link?.generation || 0)
                }
            }, 'Delivery is uncertain. Retry uses the same message identifier.', device.id);
            renderNetworkMessages(device, lastNetworkSnapshot?.link?.messages || []);
        } else {
            setNetworkFailureFeedback(error, 'Message failed before send.', device.id);
        }
    } finally {
        button.disabled = !networkSelectedDevice()?.remoteReady;
        button.textContent = pendingNetworkMessage?.state === 'uncertain-after-send' ? 'Retry safely' : 'Send';
    }
}

async function performNetworkAction(action, serviceId = null) {
    const device = networkSelectedDevice();
    if (!device) return;
    setNetworkFeedback(action === 'open-service' ? 'Opening the exact advertised service…' : 'Running ' + action + '…');
    try {
        const payload = bridgeJson(await pywebview.api.perform_network_action(device.id, action, serviceId));
        if (payload.ok === false) throw networkFailure(payload);
        const message = action === 'ping' ? 'Reachable in ' + Number(payload.latencyMs).toFixed(1) + ' ms.' : action === 'wake' ? 'Wake-on-LAN packet sent.' : 'Opened the exact advertised service.';
        setNetworkFeedback(message);
        if (action === 'ping') await loadNetworkSnapshot();
    } catch (error) { setNetworkFailureFeedback(error, 'The local device action failed.', device.id); }
}
function scheduleRefresh(delay = 2000) {
    if (!apiReady) return;
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => {
        refreshTimer = null;
        refreshAll();
    }, delay);
}

async function refreshAll() {
    if (!apiReady) return;
    if (refreshInFlight) {
        refreshQueued = true;
        return;
    }
    refreshInFlight = true;
    const requestedTab = currentTab;
    try {
        if (requestedTab === 'powerswarm') {
            await loadPowerSwarm(false);
            return;
        }
        if (requestedTab === 'brain') {
            await loadBrain(false);
            return;
        }
        if (requestedTab === 'dispatch') {
            await loadDispatchState();
            return;
        }
        if (requestedTab === 'guard') {
            await loadGuardStatus();
            return;
        }
        if (requestedTab === 'powerswarm') {
            await loadPowerSwarm(false);
            return;
        }
        const systemPromise = pywebview.api.get_system_info();
        const processesPromise = requestedTab === 'agents' ? Promise.resolve(null) : pywebview.api.get_processes(requestedTab);
        const agentsPromise = requestedTab === 'agents' ? pywebview.api.get_agent_activity() : Promise.resolve(null);
        const networkPromise = requestedTab === 'network' ? pywebview.api.get_network_snapshot() : Promise.resolve(null);
        const [sysRaw, procRaw, agentsRaw, networkRaw] = await Promise.all([systemPromise, processesPromise, agentsPromise, networkPromise]);
        const data = JSON.parse(sysRaw);

        document.getElementById('sb-procs').textContent = data.total_processes;
        document.getElementById('sb-threads').textContent = data.total_threads;
        document.getElementById('sb-cpu').textContent = data.cpu.percent.toFixed(1) + '%';
        document.getElementById('sb-uptime').textContent = 'Uptime: ' + data.uptime.formatted;

        if (requestedTab !== currentTab) {
            refreshQueued = true;
            return;
        }

        if (requestedTab === 'agents') {
            try {
                renderAgents(data, JSON.parse(agentsRaw));
            } catch (observerError) {
                const fallback = staleAgentSnapshotProjection(lastAgentSnapshot,new Date().toISOString());
                renderAgents(data, fallback);
            }
            return;
        }

        if (requestedTab === 'network') renderNetworkSnapshot(bridgeJson(networkRaw));

        document.getElementById('cpu-system').textContent = data.cpu.system.toFixed(1) + '%';
        document.getElementById('cpu-user').textContent = data.cpu.user.toFixed(1) + '%';
        document.getElementById('cpu-idle').textContent = data.cpu.idle.toFixed(1) + '%';
        document.getElementById('cpu-load').textContent = data.cpu.load_avg.map(v=>v.toFixed(2)).join('  ');
        drawCpuGraph(data.cpu.user, data.cpu.system);
        drawCoreBars(data.cpu.per_cpu);

        renderMemoryBaseSnapshot(data.memory);

        document.getElementById('disk-used-label').textContent = data.disk.used_gb.toFixed(0);
        document.getElementById('disk-total-label').textContent = data.disk.total_gb.toFixed(0);
        document.getElementById('disk-free-label').textContent = data.disk.free_gb.toFixed(0);
        const diskPercent = Math.max(0, Math.min(100, Number(data.disk.percent) || 0));
        document.getElementById('disk-usage-fill').style.width = diskPercent.toFixed(1) + '%';
        document.getElementById('disk-usage-meter').setAttribute('aria-valuenow', diskPercent.toFixed(1));
        document.getElementById('dio-read').textContent = fmtBytes(data.disk.io.read_bytes);
        document.getElementById('dio-write').textContent = fmtBytes(data.disk.io.write_bytes);
        document.getElementById('dio-rrate').textContent = fmtRate(data.disk.io.read_rate);
        document.getElementById('dio-wrate').textContent = fmtRate(data.disk.io.write_rate);

        const net = data.network;
        document.getElementById('net-sent').textContent = fmtBytes(net.bytes_sent);
        document.getElementById('net-recv').textContent = fmtBytes(net.bytes_recv);
        document.getElementById('net-pin').textContent = net.packets_recv.toLocaleString();
        document.getElementById('net-pout').textContent = net.packets_sent.toLocaleString();
        document.getElementById('net-srate').textContent = fmtRate(net.sent_rate);
        document.getElementById('net-rrate').textContent = fmtRate(net.recv_rate);
        document.getElementById('net-conns').textContent = net.connections;
        try { drawNetGraph(net.sent_rate, net.recv_rate); } catch(e) {}
        renderNetBars();

        // Battery for energy tab
        document.getElementById('energy-source').textContent = 'AC Power';
        document.getElementById('energy-battery').textContent = 'N/A (Desktop)';

        const procData = JSON.parse(procRaw);
        const procs = procData.processes;

        if (requestedTab === 'cpu') renderCpuTable(procs);
        else if (requestedTab === 'memory') renderMemTable(procs);
        else if (requestedTab === 'energy') {
            const total = renderEnergyTable(procs);
            document.getElementById('energy-total').textContent = total.toFixed(1);
            document.getElementById('energy-total').title = '';
            drawEnergyGraph(total);
        }
        else if (requestedTab === 'disk') renderDiskTable(procs);
        else if (requestedTab === 'network') renderNetTable(procs);

    } catch(e) {
        console.error('refresh error:', e);
        if (requestedTab === 'energy') renderEnergyUnavailable();
        if (requestedTab === 'agents' && lastAgentSnapshot && lastAgentSystemData) {
            renderAgents(lastAgentSystemData, staleAgentSnapshotProjection(lastAgentSnapshot,new Date().toISOString()));
        }
    } finally {
        refreshInFlight = false;
        if (refreshQueued) {
            refreshQueued = false;
            scheduleRefresh(0);
        } else {
            scheduleRefresh(currentTab === 'agents' || currentTab === 'powerswarm' ? 3000 : (currentTab === 'brain' || currentTab === 'dispatch' || currentTab === 'guard') ? 10000 : 2000);
        }
    }
}
</script>
</body>
</html>"""


FLAGSHIP_BRIDGE_JS = r'''
let flagshipRefreshInFlight = false;
let flagshipRepairInFlight = false;
let flagshipAutoHealAt = 0;

function setFlagshipRecoveryStatus(tab, message, busy = false) {
    const mount = document.querySelector(`[data-flagship-tab="${String(tab || '')}"]`);
    if (!mount) return;
    const status = mount.querySelector('[data-flagship-recovery-status]');
    const button = mount.querySelector('[data-flagship-fix-all]');
    if (status) status.textContent = String(message || '');
    if (button) button.disabled = Boolean(busy);
}

async function repairFlagshipCapabilities(detail = {}, automatic = false) {
    if (!apiReady || flagshipRepairInFlight) return;
    const tab = detail.tab === 'powerswarm' ? 'agents' : String(detail.tab || currentTab || 'cpu');
    const generation = Number(detail.expectedGeneration);
    if (!Number.isInteger(generation) || generation < 1) {
        setFlagshipRecoveryStatus(tab,'Refresh capability evidence before checking connections.');
        return;
    }
    flagshipRepairInFlight = true;
    setFlagshipRecoveryStatus(tab,automatic ? 'Auto-fixing safe local connections…' : 'Checking safe local connections…',true);
    try {
        const result = bridgeJson(await pywebview.api.repair_flagship_capabilities(
            tab,
            detail.capabilityId || null,
            generation,
        ));
        if (result?.snapshot) window.renderFlagshipCapabilities(result.snapshot);
        const mount = document.querySelector(`[data-flagship-tab="${String(tab || '')}"]`);
        if (mount) mount.__flagshipPendingRepairResult = result;
        let presentation = null;
        if (typeof window.renderFlagshipRecoveryResults === 'function') {
            presentation = window.renderFlagshipRecoveryResults(tab,result,{rechecking:true});
        }
        setFlagshipRecoveryStatus(
            tab,
            presentation?.statusMessage || 'Updates recorded. Rechecking current status…',
            true,
        );
        try {
            const refreshed = bridgeJson(await pywebview.api.get_flagship_capabilities(tab));
            window.renderFlagshipCapabilities(refreshed);
            if (typeof window.renderFlagshipRecoveryResults === 'function') {
                presentation = window.renderFlagshipRecoveryResults(tab,result,{rechecking:false});
            }
            if (mount) delete mount.__flagshipPendingRepairResult;
            setFlagshipRecoveryStatus(
                tab,
                presentation?.statusMessage || 'Current connection status is available.',
                false,
            );
        } catch (_) {
            setFlagshipRecoveryStatus(tab,'Updates recorded. Current status is still rechecking…',false);
            setTimeout(() => loadFlagshipCapabilities(tab),250);
        }
        if (
            detail.restoreFocus === true &&
            detail.capabilityId &&
            typeof window.restoreFlagshipCapabilityFocus === 'function'
        ) {
            window.restoreFlagshipCapabilityFocus(tab,detail.capabilityId);
        }
        if (!result?.snapshot && result?.code === 'stale-generation') {
            setTimeout(() => loadFlagshipCapabilities(tab),0);
        }
    } catch (_) {
        setFlagshipRecoveryStatus(tab,'Safe connection check is temporarily unavailable.',false);
    } finally {
        flagshipRepairInFlight = false;
    }
}

async function loadFlagshipCapabilities(tab = currentTab) {
    if (!apiReady || flagshipRefreshInFlight) return;
    flagshipRefreshInFlight = true;
    const ownerTab = tab === 'powerswarm' ? 'agents' : tab;
    try {
        const snapshot = bridgeJson(await pywebview.api.get_flagship_capabilities(ownerTab));
        window.renderFlagshipCapabilities(snapshot);
        const mount = document.querySelector(`[data-flagship-tab="${String(ownerTab || '')}"]`);
        const pending = mount?.__flagshipPendingRepairResult;
        if (pending && typeof window.renderFlagshipRecoveryResults === 'function') {
            const presentation = window.renderFlagshipRecoveryResults(ownerTab,pending,{rechecking:false});
            delete mount.__flagshipPendingRepairResult;
            setFlagshipRecoveryStatus(
                ownerTab,
                presentation?.statusMessage || 'Current connection status is available.',
                false,
            );
        } else {
            setFlagshipRecoveryStatus(ownerTab,'',false);
        }
        if (
            snapshot?.recovery?.autoHeal?.enabled === true &&
            Number(snapshot?.recovery?.safeAutoFixable || 0) > 0 &&
            Date.now() - flagshipAutoHealAt > 30000
        ) {
            flagshipAutoHealAt = Date.now();
            setTimeout(() => repairFlagshipCapabilities({
                tab: ownerTab,
                capabilityId: null,
                expectedGeneration: snapshot.recovery.generation,
            },true),0);
        }
    } catch (_) {
        document.querySelectorAll('[data-flagship-summary]').forEach(node => {
            node.textContent = 'Capability evidence is temporarily unavailable; owner views remain unchanged.';
        });
    } finally {
        flagshipRefreshInFlight = false;
    }
}

window.addEventListener('pywebviewready', async () => {
    if (typeof window.hydrateFlagshipCollapsePreferences === 'function') {
        await window.hydrateFlagshipCollapsePreferences();
    }
    setTimeout(() => loadFlagshipCapabilities(currentTab), 0);
});

document.querySelectorAll('.seg-btn[data-tab]').forEach(button => {
    button.addEventListener('click', () => {
        setTimeout(() => loadFlagshipCapabilities(button.dataset.tab), 75);
    });
});

document.addEventListener('ke:capability-inspect', event => {
    if (event.detail?.capabilityId === 'C33' && typeof openPowerSwarmSubview === 'function') {
        openPowerSwarmSubview();
    }
});

document.addEventListener('ke:capability-repair', event => {
    repairFlagshipCapabilities(event.detail || {},false);
});

window.setInterval(() => {
    if (apiReady) loadFlagshipCapabilities(currentTab);
}, 15000);
'''.strip()


def _compose_network_error_contract(base_html):
    """Bind every rendered Network error and recovery kind to the backend catalog."""
    contract = network_error_contract()
    replacements = {
        "__NETWORK_ERROR_COPY_JSON__": json.dumps(
            contract["messages"],
            ensure_ascii=True,
            separators=(",", ":"),
        ),
        "__NETWORK_RECOVERIES_JSON__": json.dumps(
            contract["recoveries"],
            ensure_ascii=True,
            separators=(",", ":"),
        ),
        "__NETWORK_RECOVERY_KINDS_JSON__": json.dumps(
            contract["recoveryKinds"],
            ensure_ascii=True,
            separators=(",", ":"),
        ),
        "__NETWORK_RECOVERY_ACTIONS_JSON__": json.dumps(
            contract["recoveryActions"],
            ensure_ascii=True,
            separators=(",", ":"),
        ),
    }
    rendered = base_html
    for marker, replacement in replacements.items():
        if rendered.count(marker) != 1:
            raise RuntimeError("Activity Monitor Network error contract boundary changed")
        rendered = rendered.replace(marker, replacement, 1)
    return rendered


def _compose_flagship_html(base_html):
    """Mount the capability fabric without changing the existing tab strip."""

    def replace_once(value, marker, replacement):
        if value.count(marker) != 1:
            raise RuntimeError("Activity Monitor capability mount boundary changed")
        return value.replace(marker, replacement, 1)

    rendered = replace_once(
        base_html,
        "\n</style>",
        "\n" + CAPABILITY_UI_CSS + "\n</style>",
    )
    for tab, next_tab in (
        ("cpu", "memory"),
        ("memory", "energy"),
        ("disk", "network"),
    ):
        marker = f'\n</div>\n\n<div id="{next_tab}-tab"'
        rendered = replace_once(
            rendered,
            marker,
            "\n" + capability_mount_html(tab) + "\n" + marker,
        )
    network_marker = '        </details>\n    </div>\n</div>\n\n<div id="agents-tab"'
    rendered = replace_once(
        rendered,
        network_marker,
        '        </details>\n'
        + capability_mount_html("network")
        + '\n    </div>\n</div>\n\n<div id="agents-tab"',
    )
    for tab, next_tab in (
        ("agents", "powerswarm"),
        ("brain", "dispatch"),
        ("dispatch", "guard"),
    ):
        marker = f'    </div>\n</div>\n\n<div id="{next_tab}-tab"'
        rendered = replace_once(
            rendered,
            marker,
            capability_mount_html(tab) + "\n" + marker,
        )
    guard_marker = '    </div>\n</div>\n\n</div>\n\n<div class="status-bar">'
    rendered = replace_once(
        rendered,
        guard_marker,
        capability_mount_html("guard") + "\n" + guard_marker,
    )
    rendered = replace_once(
        rendered,
        "\n</script>",
        "\n" + CAPABILITY_UI_JS + "\n" + FLAGSHIP_BRIDGE_JS + "\n</script>",
    )
    return rendered


HTML = _compose_flagship_html(_compose_network_error_contract(HTML))


def _write_portable_self_test(path):
    """Exercise the frozen runtime without opening a window (build verification only)."""
    if not path or not os.path.isabs(path):
        raise ValueError("KE_ACTIVITY_SELF_TEST_PATH must be an absolute path")
    fallback = _built_in_agents_snapshot()
    flagship = baseline_snapshot()
    result = {
        "ok": True,
        "packaged": bool(getattr(sys, "frozen", False)),
        "system": _system_identity(),
        "cpu": fallback["cpu"]["snapshot"]["host"],
        "gpu": fallback["gpu"]["snapshot"],
        "observerBundled": os.path.isfile(AGENTS_OBSERVER),
        "flagship": {
            "topLevelOrder": flagship["topLevelOrder"],
            "counts": flagship["counts"],
            "readOnly": flagship["readOnly"],
        },
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")


def _run_cleanup_scan_helper():
    """Scan exactly one fixed category for the parent process, then exit."""
    request_bytes = bytearray()
    while True:
        chunk = os.read(0, 4096)
        if not chunk:
            break
        request_bytes.extend(chunk)
        if len(request_bytes) > 4096:
            raise SystemExit(2)
    try:
        request = json.loads(bytes(request_bytes).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit(2)
    if (
        not isinstance(request, dict)
        or request.get("schemaVersion") != REVIEW_HELPER_SCHEMA_VERSION
        or request.get("category") not in DISK_CLEANUP_REVIEW_CATEGORIES
        or set(request) != {"schemaVersion", "category"}
    ):
        raise SystemExit(2)
    category = request["category"]
    service = CleanupService(
        current_app_path=_current_app_bundle_path(),
        max_scan_items=100000,
    )
    result = service.start_analysis(
        {
            "categories": [category],
            "duplicateAnalysis": False,
            "reviewOnly": True,
        }
    )
    while result.get("state") == "running":
        time.sleep(0.02)
        result = service.analysis_status(result.get("jobId"))
    if result.get("state") not in {"complete", "partial"}:
        raise SystemExit(3)
    bundle = service.review_helper_bundle(category, result)
    encoded = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 2 * 1024 * 1024:
        raise SystemExit(4)
    offset = 0
    while offset < len(encoded):
        written = os.write(1, encoded[offset:])
        if written <= 0:
            raise SystemExit(5)
        offset += written


def main():
    if "--cleanup-scan-helper" in sys.argv:
        _run_cleanup_scan_helper()
        return
    self_test_path = os.environ.get("KE_ACTIVITY_SELF_TEST_PATH")
    if self_test_path:
        _write_portable_self_test(self_test_path)
        return
    api = Api()

    # Prime psutil CPU measurement
    psutil.cpu_percent(interval=0)
    psutil.cpu_times_percent(interval=0)
    psutil.cpu_percent(percpu=True)

    window = webview.create_window(
        'Activity Monitor',
        html=HTML,
        js_api=api,
        width=960,
        height=680,
        min_size=(700, 400),
    )
    api.attach_window(window)

    try:
        webview.start(_queue_macos_app_extras, args=(window,), debug=False)
    finally:
        api.shutdown()


if __name__ == '__main__':
    main()
