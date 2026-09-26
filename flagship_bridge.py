"""Read-only bridge from current Activity Monitor owners to the flagship rail.

The bridge deliberately collects only bounded metadata projections.  A source
provider can make its own capability visible, but cannot gain execution
authority through this bridge.  The bridge may rebuild a finite set of derived
local connection bindings; it never repairs permissions, credentials, provider
sessions, disks, networks, or an owning product.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import threading
from typing import Any, Callable, Dict, Mapping, MutableMapping, Optional, Union

from flagship_capabilities import (
    CAPABILITIES,
    CURRENT_TOP_LEVEL_ORDER,
    FlagshipCapabilityService,
)
from flagship_local_sources import CompanyDiscovery, OperationsBoardDiscovery
from flagship_sources import feature_signals


Provider = Callable[[], Union[Mapping[str, Any], str]]

BOARD_DATABASE_PATH = Path.home() / "ke-agent-rooms" / "board" / "board.sqlite3"
MAX_PROVIDER_JSON_BYTES = 1024 * 1024

_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)
_FRESHNESS = frozenset({"fresh", "aging", "stale", "unknown"})
_EVIDENCE = frozenset({"recorded", "claimed", "observed", "verified"})
_NOT_CONFIGURED = frozenset({"not-installed", "not-configured", "absent", "none", "no-runs"})
_BLOCKED = frozenset({"needs-user-action", "blocked", "blocked-human", "blocked_human"})
_UNAVAILABLE = frozenset({"offline", "unavailable", "unsupported", "error", "failed"})
_DEGRADED = frozenset({"stale", "degraded", "partial", "aging"})
_AVAILABLE = frozenset(
    {"available", "working", "active", "running", "connected", "armed", "dry-run"}
)
_POWERSWARM_PROVIDER_IDS = frozenset({"xai"})
_POWERSWARM_MODEL_IDS_BY_PROVIDER = {"xai": frozenset({"grok-4.6"})}

_DERIVED_SOURCE_IDS = frozenset(
    {
        "authority",
        "brain-conversation",
        "context-packs",
        "entitlements",
        "evidence",
        "kea-watch",
    }
)
_MANUAL_SOURCE_TARGETS = {
    "connectors": "network",
    "crews": "agents",
    "governor": "memory",
    "permissions": "network",
    "private-hosts": "network",
}
_PUBLIC_STATES = (
    "working",
    "degraded",
    "stale",
    "blocked",
    "unavailable",
    "repairable",
    "setup-required",
    "not-connected",
)
_RECOVERY_BOUNDARY = (
    "Safe recovery only rebuilds allowlisted in-memory metadata bindings. It performs "
    "no file, preference, permission, credential, provider-session, network, disk, "
    "process, message, or authority mutation."
)


def _mapping(value: Union[Mapping[str, Any], str]) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_PROVIDER_JSON_BYTES:
            raise ValueError("capability source exceeds the bridge input boundary")
        decoded = json.loads(value)
        if isinstance(decoded, Mapping):
            return decoded
    raise TypeError("capability source must publish one mapping")


def _unavailable(source_id: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "state": "unavailable",
        "detail": f"The {source_id} metadata source is temporarily unavailable.",
    }


def _canonical_state(payload: Mapping[str, Any]) -> str:
    raw_value = payload.get("state")
    if not isinstance(raw_value, str):
        raw_value = payload.get("status")
    raw = raw_value.strip().lower() if isinstance(raw_value, str) else ""
    if raw in _NOT_CONFIGURED:
        return "not-configured"
    if raw in _BLOCKED:
        return "blocked"
    if raw in _UNAVAILABLE:
        return "unavailable"
    if raw in _DEGRADED:
        return raw
    if raw in _AVAILABLE:
        return raw
    if payload.get("ok") is False:
        return "unavailable"
    if payload.get("stale") is True:
        return "stale"
    if payload.get("ok") is True:
        return "available"
    return "degraded"


def _timestamp(payload: Mapping[str, Any]) -> Optional[str]:
    for key in ("observedAt", "generatedAt", "updatedAt"):
        value = payload.get(key)
        if isinstance(value, str):
            value = value.strip()
            if len(value) <= 64 and _TIMESTAMP.fullmatch(value):
                return value
    return None


def _count(value: Any, maximum: int = 1_000_000) -> int:
    if type(value) is not int:
        return 0
    return max(0, min(value, maximum))


def _powerswarm_runtime_identity(payload: Mapping[str, Any]) -> Dict[str, Optional[str]]:
    """Project only the exact registered runtime pair; never cache provider bodies."""

    selected = payload.get("selectedRun")
    selected = selected if isinstance(selected, Mapping) else {}
    if payload.get("stale") is True or _canonical_state(payload) == "stale":
        return {"providerId": None, "modelId": None}
    provider = selected.get("providerId")
    provider_id = provider.strip().lower() if isinstance(provider, str) else None
    if provider_id not in _POWERSWARM_PROVIDER_IDS:
        return {"providerId": None, "modelId": None}
    model = selected.get("modelId")
    model_id = model.strip().lower() if isinstance(model, str) else None
    if model_id not in _POWERSWARM_MODEL_IDS_BY_PROVIDER.get(provider_id, frozenset()):
        return {"providerId": None, "modelId": None}
    return {"providerId": provider_id, "modelId": model_id}


def _common_projection(source_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Copy only the finite state fields the capability translator consumes."""

    state = _canonical_state(payload)
    projection: Dict[str, Any] = {
        "ok": payload.get("ok") if isinstance(payload.get("ok"), bool) else state not in {
            "not-configured",
            "unavailable",
        },
        "state": state,
        "detail": f"The {source_id} owner published a bounded read-only state projection.",
    }
    observed_at = _timestamp(payload)
    if observed_at is not None:
        projection["observedAt"] = observed_at
    if payload.get("stale") is True or state == "stale":
        projection["stale"] = True
    freshness = payload.get("freshness")
    if isinstance(freshness, str) and freshness.strip().lower() in _FRESHNESS:
        projection["freshness"] = freshness.strip().lower()
    evidence = payload.get("evidenceLevel")
    if isinstance(evidence, str) and evidence.strip().lower() in _EVIDENCE:
        projection["evidenceLevel"] = evidence.strip().lower()
    if payload.get("verified") is True:
        projection["verified"] = True
    return projection


def _project_source(source_id: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Apply a strict per-source allowlist before anything enters bridge state."""

    projection = _common_projection(source_id, payload)
    if source_id == "company":
        summary = payload.get("summary")
        summary = summary if isinstance(summary, Mapping) else {}
        projection["summary"] = {
            "agents": _count(summary.get("agents")),
            "teams": _count(summary.get("teams")),
            "crewContracts": _count(summary.get("crewContracts")),
        }
    elif source_id == "operations-board":
        counts = payload.get("counts")
        counts = counts if isinstance(counts, Mapping) else {}
        projection["counts"] = {
            "activeOwners": _count(counts.get("activeOwners")),
            "open": _count(counts.get("open")),
            "needsHuman": _count(counts.get("needsHuman")),
        }
    elif source_id == "brain":
        summary = payload.get("summary")
        summary = summary if isinstance(summary, Mapping) else {}
        scan = payload.get("scan")
        scan = scan if isinstance(scan, Mapping) else {}
        privacy = payload.get("privacy")
        privacy = privacy if isinstance(privacy, Mapping) else {}
        projection["summary"] = {
            "connected": _count(summary.get("connected")),
            "projectChildren": _count(summary.get("projectChildren")),
        }
        projection["settingsTrusted"] = scan.get("settingsTrusted") is True
        projection["privacyVerified"] = bool(
            privacy.get("noteBodiesRead") is False
            and privacy.get("uploads") is False
            and privacy.get("credentialsUsed") is False
        )
    elif source_id == "workspace":
        counts = payload.get("counts")
        counts = counts if isinstance(counts, Mapping) else {}
        companions = payload.get("companions")
        companions = companions if isinstance(companions, Mapping) else {}
        codex = companions.get("codex")
        codex = codex if isinstance(codex, Mapping) else {}
        claude = companions.get("claude")
        claude = claude if isinstance(claude, Mapping) else {}
        projection["counts"] = {
            "projectBrains": _count(counts.get("projectBrains")),
            "activeProjectBrains": _count(counts.get("activeProjectBrains")),
        }
        projection["companions"] = {
            "codexAvailable": bool(codex.get("cliInstalled") or codex.get("appInstalled")),
            "claudeAvailable": bool(claude.get("installed") or claude.get("cliInstalled")),
        }
    elif source_id == "dispatch":
        readiness = payload.get("readiness")
        readiness = readiness if isinstance(readiness, Mapping) else {}
        projection["readiness"] = {
            "codexExactTask": readiness.get("codexExactTask") is True,
            "codexDesktopOwnerIpc": readiness.get("codexDesktopOwnerIpc") is True,
            "claudeExactSession": readiness.get("claudeExactSession") is True,
            "historyAvailable": readiness.get("historyAvailable") is True,
            "dispatchSendAllowed": readiness.get("dispatchSendAllowed") is True,
        }
    elif source_id == "guard":
        evidence = payload.get("recentEvidence")
        projection["ledgerAvailable"] = payload.get("ledgerAvailable") is True
        projection["evidenceCount"] = min(len(evidence), 1000) if isinstance(evidence, list) else 0
    elif source_id == "powerswarm":
        projection["selectedRun"] = _powerswarm_runtime_identity(payload)
    return projection


def _projection_ready(payload: Any) -> bool:
    return bool(
        isinstance(payload, Mapping)
        and payload.get("ok") is not False
        and str(payload.get("state") or "").strip().lower()
        not in {"not-configured", "unavailable", "offline", "error", "failed"}
    )


def _derived_bindings(
    projections: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Build only truthful no-I/O compatibility bindings from safe projections."""

    bindings: Dict[str, Dict[str, Any]] = {}
    brain = projections.get("brain")
    dispatch = projections.get("dispatch")
    workspace = projections.get("workspace")
    board = projections.get("operations-board")
    guard = projections.get("guard")
    powerswarm = projections.get("powerswarm")

    brain_summary = brain.get("summary") if isinstance(brain, Mapping) else {}
    brain_summary = brain_summary if isinstance(brain_summary, Mapping) else {}
    connected_brains = _count(brain_summary.get("connected"))
    brain_private = bool(
        _projection_ready(brain)
        and brain.get("settingsTrusted") is True
        and brain.get("privacyVerified") is True
    ) if isinstance(brain, Mapping) else False

    readiness = dispatch.get("readiness") if isinstance(dispatch, Mapping) else {}
    readiness = readiness if isinstance(readiness, Mapping) else {}
    exact_providers = int(
        readiness.get("codexExactTask") is True
        and readiness.get("codexDesktopOwnerIpc") is True
    ) + int(readiness.get("claudeExactSession") is True)
    if connected_brains and _projection_ready(dispatch) and exact_providers:
        bindings["brain-conversation"] = {
            "ok": True,
            "state": "degraded",
            "detail": (
                "Connected Brain inventory is bound to exact local conversation providers; "
                "a dedicated expiring retrieval receipt is still required for each answer."
            ),
            "resource": f"{exact_providers} exact local conversation provider(s)",
            "observedAt": _timestamp(brain or {}),
            "evidenceLevel": "observed",
        }

    workspace_counts = workspace.get("counts") if isinstance(workspace, Mapping) else {}
    workspace_counts = workspace_counts if isinstance(workspace_counts, Mapping) else {}
    active_project_brains = _count(workspace_counts.get("activeProjectBrains"))
    if connected_brains and active_project_brains and _projection_ready(workspace):
        bindings["context-packs"] = {
            "ok": True,
            "state": "degraded",
            "detail": (
                "Active Project Brain associations provide a bounded context source; no "
                "expiring per-run Context Pack receipt is currently published."
            ),
            "resource": f"{active_project_brains} active Project Brain association(s)",
            "observedAt": _timestamp(workspace or {}),
            "evidenceLevel": "observed",
        }

    evidence_owners = int(_projection_ready(board)) + int(_projection_ready(guard))
    if evidence_owners:
        bindings["evidence"] = {
            "ok": True,
            "state": "degraded",
            "detail": (
                "Bounded board and defense evidence is connected; universal artifact-to-"
                "acceptance lineage remains owner-published and may be incomplete."
            ),
            "resource": f"{evidence_owners} bounded evidence owner(s)",
            "observedAt": _timestamp(board or {}) or _timestamp(guard or {}),
            "evidenceLevel": "observed",
        }

    if connected_brains and brain_private:
        bindings["entitlements"] = {
            "ok": True,
            "state": "degraded",
            "detail": (
                "Trusted Brain roots and metadata-only privacy enforcement are connected; "
                "full public, customer, third-party, and server-only classification remains "
                "owner-published."
            ),
            "resource": f"{connected_brains} privacy-bounded connected Brain(s)",
            "observedAt": _timestamp(brain or {}),
            "evidenceLevel": "verified",
        }

    board_counts = board.get("counts") if isinstance(board, Mapping) else {}
    board_counts = board_counts if isinstance(board_counts, Mapping) else {}
    observed_operations = _count(board_counts.get("activeOwners")) + _count(
        board_counts.get("open")
    )
    if _projection_ready(board) and (observed_operations or _projection_ready(powerswarm)):
        bindings["kea-watch"] = {
            "ok": True,
            "state": "degraded",
            "detail": (
                "Current owner and incident evidence is connected for operations visibility; "
                "this does not claim complete Movement, Cue, or Signal coverage."
            ),
            "resource": f"{observed_operations} current owner/incident record(s)",
            "observedAt": _timestamp(board or {}),
            "evidenceLevel": "observed",
        }

    if _projection_ready(dispatch):
        human_gates = _count(board_counts.get("needsHuman"))
        bindings["authority"] = {
            "ok": True,
            "state": "degraded",
            "detail": (
                "Exact Dispatch boundaries and current human gates are connected; visibility "
                "never grants send, spend, deploy, release, destructive, or account authority."
            ),
            "resource": f"{human_gates} current human authority gate(s)",
            "observedAt": _timestamp(board or {}),
            "evidenceLevel": "observed",
        }
    return bindings


def _agent_sections(payload: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Project combined Agents telemetry into explicit CPU/GPU owner sources."""

    base = _project_source("agents", payload)
    observed_at = base.get("observedAt")
    stale = base.get("stale") is True
    available = base.get("ok") is not False
    projected: Dict[str, Dict[str, Any]] = {"agents": base}
    for source_id, section_id in (("cpu-workers", "cpu"), ("gpu-workers", "gpu")):
        section = payload.get(section_id)
        if not isinstance(section, Mapping):
            if not available:
                projected[source_id] = _unavailable(source_id)
            continue
        item = _project_source(source_id, section)
        if "observedAt" not in item and observed_at is not None:
            item["observedAt"] = observed_at
        if stale or item.get("stale") is True:
            item["stale"] = True
        projected[source_id] = item
    return projected


def baseline_snapshot() -> Dict[str, Any]:
    """Return the executable 30+1 contract without claiming any owner source."""

    return FlagshipCapabilityService().snapshot(feature_signals({}))


class FlagshipBridge:
    """Collect current owner projections and publish one immutable snapshot."""

    def __init__(
        self,
        *,
        brain_service: Any,
        dispatch_service: Any,
        guard_service: Any,
        agents_provider: Optional[Provider] = None,
        company_discovery: Optional[Any] = None,
        board_discovery: Optional[Any] = None,
        providers: Optional[Mapping[str, Provider]] = None,
        capability_service: Optional[FlagshipCapabilityService] = None,
        auto_heal: bool = True,
    ) -> None:
        self._brain_service = brain_service
        self._dispatch_service = dispatch_service
        self._guard_service = guard_service
        self._agents_provider = agents_provider
        self._company = company_discovery or CompanyDiscovery()
        self._board = board_discovery or OperationsBoardDiscovery(
            database_path=BOARD_DATABASE_PATH
        )
        self._providers = dict(providers or {})
        self._service = capability_service or FlagshipCapabilityService()
        self._projections: MutableMapping[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._repair_lock = threading.Lock()
        self._auto_heal = bool(auto_heal)
        self._derived_active: set[str] = set()
        self._generation = 0
        self._last_snapshot: Optional[Dict[str, Any]] = None
        self._last_tab = "cpu"

    @staticmethod
    def _source_ids_for_tab(tab: str) -> set[str]:
        return {
            source_id
            for capability in CAPABILITIES
            if capability.tab == tab
            for source_id in capability.required_sources + capability.supporting_sources
        }

    @staticmethod
    def _call(source_id: str, provider: Provider) -> Dict[str, Any]:
        try:
            return _project_source(source_id, _mapping(provider()))
        except Exception:
            return _unavailable(source_id)

    @staticmethod
    def _call_agents(provider: Provider) -> Dict[str, Dict[str, Any]]:
        try:
            return _agent_sections(_mapping(provider()))
        except Exception:
            return _agent_sections(_unavailable("agents"))

    def _collect_base(self) -> None:
        self._projections["company"] = self._call("company", self._company.snapshot)
        self._projections["operations-board"] = self._call(
            "operations-board", self._board.snapshot
        )
        self._projections["dispatch"] = self._call("dispatch", self._dispatch_service.state)
        self._projections["guard"] = self._call("guard", self._guard_service.status)

    @staticmethod
    def _normalize_tab(requested_tab: str) -> str:
        tab = str(requested_tab or "cpu").strip().lower()
        return tab if tab in CURRENT_TOP_LEVEL_ORDER else "cpu"

    def _sync_derived(
        self,
        *,
        add_missing: bool,
        source_ids: Optional[set[str]] = None,
    ) -> int:
        desired = _derived_bindings(self._projections)
        changed = 0
        for source_id in _DERIVED_SOURCE_IDS:
            current = self._projections.get(source_id)
            candidate = desired.get(source_id)
            current_is_derived = source_id in self._derived_active
            if current_is_derived and candidate is None:
                del self._projections[source_id]
                self._derived_active.discard(source_id)
                changed += 1
                continue
            if not add_missing or candidate is None:
                continue
            if source_ids is not None and source_id not in source_ids:
                continue
            if current is not None and not current_is_derived:
                continue
            if current != candidate:
                self._projections[source_id] = candidate
                self._derived_active.add(source_id)
                changed += 1
        return changed

    @staticmethod
    def _required_source_ids(row: Mapping[str, Any]) -> set[str]:
        evidence = row.get("evidence")
        evidence = evidence if isinstance(evidence, Mapping) else {}
        required = evidence.get("requiredSources")
        required = required if isinstance(required, list) else []
        return {
            str(item.get("sourceId"))
            for item in required
            if isinstance(item, Mapping) and isinstance(item.get("sourceId"), str)
        }

    @staticmethod
    def _repair_outcome(
        capability_id: str,
        before: Optional[Mapping[str, Any]],
        after: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Return bounded capability-level repair truth without owner data."""

        before_row = before if isinstance(before, Mapping) else {}
        after_row = after if isinstance(after, Mapping) else {}
        before_state = str(before_row.get("state") or "unavailable")
        after_state = str(after_row.get("state") or "unavailable")
        recovery = before_row.get("recovery")
        recovery = recovery if isinstance(recovery, Mapping) else {}
        mode = str(recovery.get("mode") or "inspect")

        if not before or not after:
            outcome = "failed"
            detail = "Capability evidence changed before the safe result was recorded."
        elif before_state == "repairable":
            if after_state != "repairable":
                outcome = "applied"
                detail = "Safe local metadata binding rebuilt."
            else:
                outcome = "failed"
                detail = "Safe local metadata binding did not reach a current state."
        elif before_state == "setup-required" or mode == "manual-setup":
            outcome = "manual"
            detail = "Explicit setup, permission, or publisher evidence remains required."
        elif before_state in {"blocked", "unavailable", "not-connected"}:
            outcome = "unavailable"
            detail = "No safe local binding repair is available for this owner state."
        else:
            outcome = "already-healthy"
            detail = "No safe local binding change was needed."

        return {
            "capabilityId": str(capability_id),
            "name": str(after_row.get("name") or before_row.get("name") or "Capability"),
            "outcome": outcome,
            "stateBefore": before_state,
            "stateAfter": after_state,
            "repairMode": mode,
            "detail": detail,
            "noSideEffects": True,
        }

    def _decorate_snapshot(
        self,
        snapshot: Dict[str, Any],
        *,
        tab: str,
        auto_healed: int,
    ) -> Dict[str, Any]:
        desired = _derived_bindings(self._projections)
        repairable = 0
        setup_required = 0
        for row in snapshot.get("capabilities", []):
            evidence = row.get("evidence")
            evidence = evidence if isinstance(evidence, Mapping) else {}
            missing = {
                str(item)
                for item in evidence.get("missingSources", [])
                if isinstance(item, str)
            }
            present = self._required_source_ids(row)
            required_rows = evidence.get("requiredSources")
            required_rows = required_rows if isinstance(required_rows, list) else []
            not_configured = {
                str(item.get("sourceId"))
                for item in required_rows
                if isinstance(item, Mapping) and item.get("state") == "not-configured"
            }
            manual = (missing | not_configured) & set(_MANUAL_SOURCE_TARGETS)
            missing_derived = missing & _DERIVED_SOURCE_IDS
            derivable = {
                source_id for source_id in missing_derived if source_id in desired
            }
            if row.get("state") == "not-connected":
                if manual or not_configured:
                    row["state"] = "setup-required"
                elif missing_derived:
                    row["state"] = (
                        "repairable" if derivable == missing_derived else "unavailable"
                    )

            state = str(row.get("state") or "unavailable")
            can_attempt = state == "repairable" and bool(derivable)
            if state == "setup-required":
                setup_required += 1
            if can_attempt:
                repairable += 1
            target = next(
                (_MANUAL_SOURCE_TARGETS[source_id] for source_id in sorted(manual)),
                str((row.get("placement") or {}).get("tab") or tab),
            )
            auto_bound = bool(present & self._derived_active)
            if can_attempt:
                mode = "safe-local-binding"
                label = "Fix connection"
                reason = (
                    "An allowlisted metadata binding can be rebuilt without owner or "
                    "system mutation."
                )
            elif state == "setup-required":
                mode = "manual-setup"
                label = "Inspect setup"
                reason = (
                    "An owning publisher, permission, or trusted connection must be "
                    "configured explicitly."
                )
            elif auto_bound:
                mode = "auto-bound"
                label = "Connected"
                reason = (
                    "A bounded local metadata binding is continuously recomputed from "
                    "current owner evidence."
                )
            else:
                mode = "inspect"
                label = "Inspect"
                reason = "No safe local binding repair is available for this owner state."
            row["recovery"] = {
                "mode": mode,
                "canAttempt": can_attempt,
                "label": label,
                "reason": reason,
                "targetTab": target,
                "localBindingOnly": mode in {"safe-local-binding", "auto-bound"},
                "noSideEffects": True,
                "generation": self._generation,
            }

        counts = snapshot.get("counts")
        counts = counts if isinstance(counts, dict) else {}
        for state in _PUBLIC_STATES:
            counts[state] = sum(
                1 for row in snapshot.get("capabilities", []) if row.get("state") == state
            )
        snapshot["counts"] = counts
        snapshot["recovery"] = {
            "schemaVersion": "ke.activity-monitor-flagship-recovery.v1",
            "generation": self._generation,
            "scopeTab": tab,
            "autoHeal": {
                "enabled": self._auto_heal,
                "performed": auto_healed,
                "continuous": True,
            },
            "safeAutoFixable": repairable,
            "setupRequired": setup_required,
            "singleFlight": True,
            "generationBound": True,
            "noIORepair": True,
            "boundary": _RECOVERY_BOUNDARY,
        }
        snapshot["boundary"] = snapshot["boundary"] + " " + _RECOVERY_BOUNDARY
        return snapshot

    def _publish_locked(self, tab: str, *, auto_healed: int = 0) -> Dict[str, Any]:
        self._generation += 1
        snapshot = self._service.snapshot(feature_signals(dict(self._projections)))
        snapshot = self._decorate_snapshot(snapshot, tab=tab, auto_healed=auto_healed)
        self._last_snapshot = json.loads(json.dumps(snapshot))
        self._last_tab = tab
        return json.loads(json.dumps(snapshot))

    def snapshot(self, requested_tab: str = "cpu") -> Dict[str, Any]:
        tab = self._normalize_tab(requested_tab)
        with self._lock:
            self._collect_base()
            if tab == "brain":
                self._projections["brain"] = self._call(
                    "brain", lambda: self._brain_service.scan(False)
                )
            if tab in {"cpu", "agents"} and self._agents_provider is not None:
                self._projections.update(self._call_agents(self._agents_provider))
            relevant = self._source_ids_for_tab(tab)
            for source_id, provider in self._providers.items():
                if source_id in relevant:
                    self._projections[source_id] = self._call(source_id, provider)
                    self._derived_active.discard(source_id)
            auto_healed = self._sync_derived(add_missing=self._auto_heal)
            return self._publish_locked(tab, auto_healed=auto_healed)

    def repair(
        self,
        requested_tab: str,
        capability_id: Optional[str] = None,
        expected_generation: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Rebuild safe cached bindings once; never call an owner or mutate its state."""

        tab = self._normalize_tab(requested_tab)
        selected = str(capability_id or "").strip().upper() or None
        descriptors = [item for item in CAPABILITIES if item.tab == tab]
        if selected is not None:
            descriptors = [item for item in descriptors if item.capability_id == selected]
            if not descriptors:
                return {
                    "ok": False,
                    "code": "capability-out-of-scope",
                    "detail": "Choose a capability in the currently visible destination.",
                    "boundary": _RECOVERY_BOUNDARY,
                }
        if not self._repair_lock.acquire(blocking=False):
            return {
                "ok": False,
                "code": "repair-busy",
                "detail": "A safe connection check is already running.",
                "boundary": _RECOVERY_BOUNDARY,
            }
        state_lock_acquired = self._lock.acquire(blocking=False)
        if not state_lock_acquired:
            self._repair_lock.release()
            return {
                "ok": False,
                "code": "repair-busy",
                "detail": "Capability evidence is refreshing; retry against the next generation.",
                "boundary": _RECOVERY_BOUNDARY,
            }
        try:
            if (
                type(expected_generation) is not int
                or expected_generation != self._generation
            ):
                current = (
                    json.loads(json.dumps(self._last_snapshot))
                    if self._last_snapshot
                    else None
                )
                return {
                    "ok": False,
                    "code": "stale-generation",
                    "detail": (
                        "Capability evidence changed; review the current snapshot before "
                        "retrying."
                    ),
                    "generation": self._generation,
                    "snapshot": current,
                    "boundary": _RECOVERY_BOUNDARY,
                }
            source_ids = {
                source_id
                for descriptor in descriptors
                for source_id in descriptor.required_sources
                if source_id in _DERIVED_SOURCE_IDS
            }
            selected_ids = {item.capability_id for item in descriptors}
            before = self._last_snapshot
            before_rows = {
                row.get("id"): json.loads(json.dumps(row))
                for row in (before or {}).get("capabilities", [])
                if row.get("id") in selected_ids
            }
            changed = self._sync_derived(
                add_missing=True,
                source_ids=source_ids,
            )
            if changed:
                snapshot = self._publish_locked(tab)
            elif self._last_snapshot:
                snapshot = json.loads(json.dumps(self._last_snapshot))
            else:
                snapshot = self._publish_locked(tab)
            repaired = sum(
                (before_rows.get(row.get("id")) or {}).get("state") == "repairable"
                and row.get("state") != "repairable"
                for row in snapshot.get("capabilities", [])
                if row.get("id") in before_rows
            )
            after_rows = {
                row.get("id"): row
                for row in snapshot.get("capabilities", [])
                if row.get("id") in selected_ids
            }
            outcomes = [
                self._repair_outcome(
                    descriptor.capability_id,
                    before_rows.get(descriptor.capability_id),
                    after_rows.get(descriptor.capability_id),
                )
                for descriptor in descriptors
            ]
            outcome_counts = {
                outcome: sum(item["outcome"] == outcome for item in outcomes)
                for outcome in (
                    "applied",
                    "already-healthy",
                    "manual",
                    "unavailable",
                    "failed",
                )
            }
            failed = outcome_counts["failed"]
            return {
                "ok": failed == 0,
                "code": (
                    "repair-incomplete"
                    if failed
                    else "repaired" if repaired else "already-healthy"
                ),
                "detail": (
                    "One or more safe local bindings could not be reconciled."
                    if failed
                    else f"Rebuilt {repaired} safe local capability connection(s)."
                    if repaired
                    else "Safe local capability connections are already current."
                ),
                "attempted": len(source_ids),
                "repaired": repaired,
                "outcomeSchemaVersion": (
                    "ke.activity-monitor-flagship-repair-outcomes.v1"
                ),
                "outcomes": outcomes,
                "outcomeCounts": outcome_counts,
                "outcomesBounded": True,
                "generation": snapshot["recovery"]["generation"],
                "snapshot": snapshot,
                "boundary": _RECOVERY_BOUNDARY,
            }
        finally:
            self._lock.release()
            self._repair_lock.release()

    def failure_snapshot(self, requested_tab: str = "cpu") -> Dict[str, Any]:
        """Return a truthful owner-unavailable view instead of an empty baseline."""

        tab = self._normalize_tab(requested_tab)
        with self._lock:
            relevant = self._source_ids_for_tab(tab)
            for source_id in relevant:
                if (
                    source_id not in self._projections
                    and source_id not in _DERIVED_SOURCE_IDS
                    and source_id not in _MANUAL_SOURCE_TARGETS
                    and source_id != "capability-registry"
                ):
                    self._projections[source_id] = _unavailable(source_id)
            auto_healed = self._sync_derived(add_missing=self._auto_heal)
            return self._publish_locked(tab, auto_healed=auto_healed)

    def snapshot_json(self, requested_tab: str = "cpu") -> str:
        return json.dumps(
            self.snapshot(requested_tab), separators=(",", ":"), sort_keys=True
        )

    def repair_json(
        self,
        requested_tab: str,
        capability_id: Optional[str] = None,
        expected_generation: Optional[int] = None,
    ) -> str:
        return json.dumps(
            self.repair(requested_tab, capability_id, expected_generation),
            separators=(",", ":"),
            sort_keys=True,
        )

    def failure_snapshot_json(self, requested_tab: str = "cpu") -> str:
        return json.dumps(
            self.failure_snapshot(requested_tab), separators=(",", ":"), sort_keys=True
        )


__all__ = [
    "BOARD_DATABASE_PATH",
    "FlagshipBridge",
    "baseline_snapshot",
]
