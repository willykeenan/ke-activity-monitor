"""Native flagship capability catalog and truthful read-model aggregation.

This module is deliberately independent from the app's HTML bridge so the
active feature lanes can integrate it without sharing a writer.  It owns the
stable capability vocabulary, the existing top-level tab order, and the common
truth rail used by every capability surface.  It does not execute PowerSwarm,
send messages, alter Agents, write the Brain, or cross any authority gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA_VERSION = "ke.activity-monitor-flagship.v1"

# The owner's product-order decision is a product invariant, not a design hint.
CURRENT_TOP_LEVEL_ORDER: Tuple[str, ...] = (
    "cpu",
    "memory",
    "energy",
    "disk",
    "network",
    "agents",
    "brain",
    "dispatch",
    "guard",
)

NATIVE_CAPABILITY_IDS = frozenset(
    {
        "C01",
        "C02",
        "C03",
        "C04",
        "C09",
        "C10",
        "C11",
        "C12",
        "C13",
        "C17",
        "C18",
        "C19",
        "C24",
        "C25",
        "C26",
        "C27",
        "C28",
        "C30",
        "C31",
        "C32",
        "C36",
        "C39",
        "C40",
        "C41",
        "C42",
        "C43",
        "C44",
        "C48",
        "C63",
        "C64",
    }
)

SUPPLEMENTAL_CAPABILITY_IDS = frozenset({"C33"})

SOURCE_STATES = frozenset(
    {
        "available",
        "degraded",
        "blocked",
        "unavailable",
        "not-configured",
    }
)
FRESHNESS_STATES = frozenset({"fresh", "aging", "stale", "unknown"})
EVIDENCE_LEVELS = ("recorded", "claimed", "observed", "verified")
EVIDENCE_RANK = {level: index for index, level in enumerate(EVIDENCE_LEVELS)}

_ABSOLUTE_PATH = re.compile(
    r"(?:/(?:Users|home|root|private|var|etc|tmp|Volumes|Applications|opt|Library|System)/[^\s'\"`,;)]*|"
    r"\b[A-Za-z]:\\(?:Users|Windows|ProgramData|Temp)\\[^\s'\"`,;)]*)",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_TOKEN = re.compile(
    r"\b(?:Bearer\s+)?(?:(?:sk|rk|pk|kek|xai|gsk|gh[pousr]|whsec|sbp)[-_]"
    r"[A-Za-z0-9._~+/-]{12,}|AKIA[A-Z0-9]{16})\b",
    re.IGNORECASE,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_text(value: Any, limit: int = 320) -> str:
    """Return bounded human text without private paths, contacts, or tokens."""

    text = str(value or "").strip().replace("\x00", "")
    text = _ABSOLUTE_PATH.sub("[local path]", text)
    text = _EMAIL.sub("[private contact]", text)
    text = _TOKEN.sub("[credential]", text)
    return text[:limit]


@dataclass(frozen=True)
class CapabilityDescriptor:
    capability_id: str
    slug: str
    name: str
    tab: str
    section: str
    owner: str
    kind: str
    summary: str
    required_sources: Tuple[str, ...]
    supporting_sources: Tuple[str, ...]
    interaction: str
    actions: Tuple[str, ...]
    authority_gates: Tuple[str, ...]
    side_effects: Tuple[str, ...]
    empty_state: str

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "id": self.capability_id,
            "slug": self.slug,
            "name": self.name,
            "kind": self.kind,
            "placement": {
                "tab": self.tab,
                "tabRank": CURRENT_TOP_LEVEL_ORDER.index(self.tab),
                "section": self.section,
            },
            "owner": self.owner,
            "summary": self.summary,
            "sources": {
                "required": list(self.required_sources),
                "supporting": list(self.supporting_sources),
            },
            "interaction": self.interaction,
            "actions": list(self.actions),
            "authorityGates": list(self.authority_gates),
            "sideEffects": list(self.side_effects),
            "emptyState": self.empty_state,
        }


@dataclass(frozen=True)
class SourceSignal:
    source_id: str
    state: str
    evidence: str = "recorded"
    freshness: str = "unknown"
    observed_at: Optional[str] = None
    detail: str = ""
    owner: str = ""
    resource: str = ""
    receipt_ref: str = ""

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", self.source_id):
            raise ValueError("source identifier is invalid")
        if self.state not in SOURCE_STATES:
            raise ValueError(f"unsupported source state: {self.state}")
        if self.evidence not in EVIDENCE_RANK:
            raise ValueError(f"unsupported evidence level: {self.evidence}")
        if self.freshness not in FRESHNESS_STATES:
            raise ValueError(f"unsupported freshness state: {self.freshness}")

    def public_dict(self) -> Dict[str, Any]:
        return {
            "sourceId": _safe_text(self.source_id, 80),
            "state": self.state,
            "evidence": self.evidence,
            "freshness": self.freshness,
            "observedAt": _safe_text(self.observed_at, 80) or None,
            "detail": _safe_text(self.detail),
            "owner": _safe_text(self.owner, 120),
            "resource": _safe_text(self.resource, 160),
            "receiptRef": _safe_text(self.receipt_ref, 160),
        }


def _cap(
    capability_id: str,
    slug: str,
    name: str,
    tab: str,
    section: str,
    owner: str,
    summary: str,
    required_sources: Sequence[str],
    *,
    supporting_sources: Sequence[str] = (),
    interaction: str = "observe",
    actions: Sequence[str] = ("inspect",),
    authority_gates: Sequence[str] = (),
    side_effects: Sequence[str] = (),
    empty_state: str = "The owning source has not published current evidence.",
    kind: str = "native",
) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        capability_id=capability_id,
        slug=slug,
        name=name,
        tab=tab,
        section=section,
        owner=owner,
        kind=kind,
        summary=summary,
        required_sources=tuple(required_sources),
        supporting_sources=tuple(supporting_sources),
        interaction=interaction,
        actions=tuple(actions),
        authority_gates=tuple(authority_gates),
        side_effects=tuple(side_effects),
        empty_state=empty_state,
    )


CAPABILITIES: Tuple[CapabilityDescriptor, ...] = (
    _cap(
        "C39", "cpu-workers", "CPU Worker Visibility", "cpu", "Registered work",
        "CPU Workers", "Show registered CPU pools, owner-published progress, worker evidence, and staleness without inferring completion from process activity.",
        ("cpu-workers",), supporting_sources=("agents",),
    ),
    _cap(
        "C12", "budgets-guardrails", "Budgets and Guardrails", "memory", "Resource boundaries",
        "Execution Governor", "Show published time, concurrency, retry, provider, spend, and resource boundaries separately from host utilization.",
        ("governor",), supporting_sources=("memory", "agents", "powerswarm"),
        empty_state="No universal Governor envelope is published; host telemetry remains visible but is not a budget.",
    ),
    _cap(
        "C36", "worktree-visibility", "Isolated Worktree Execution Visibility", "disk", "Work custody",
        "Owning task and repository", "Show exact base, branch, writer, dirty state, bounded artifacts, and integration state for registered worktrees.",
        ("workspace",), supporting_sources=("disk", "evidence"),
    ),
    _cap(
        "C32", "connector-discovery", "Connector Discovery", "network", "Capabilities",
        "KE Connector", "Discover only versioned capabilities available to the current user without exposing connector secrets or granting invocation authority.",
        ("connectors",), supporting_sources=("network",), actions=("inspect", "open-settings"),
    ),
    _cap(
        "C64", "private-host-link", "Private Host Link and Remote Operation", "network", "Trusted hosts",
        "KE Remote Operator", "Show discovered, paired, trusted, reachable, service-verified, operating, recoverable, and revoked host states as distinct facts.",
        ("private-hosts",), supporting_sources=("network", "permissions"),
        interaction="human-gated", actions=("inspect", "open-handoff"),
        authority_gates=("authentication", "device-trust", "human-consent"),
    ),
    _cap(
        "C09", "exact-task-identity", "Exact Task Identity", "agents", "Ownership",
        "Workspace Registry", "Resolve immutable provider, task or session, project, and work-object identity instead of guessing from titles or recency.",
        ("workspace",),
    ),
    _cap(
        "C10", "one-writer", "One-Writer Ownership", "agents", "Ownership",
        "Agent Operations Board", "Show the sole writer for each mutable target and surface overlaps before another writer begins.",
        ("ownership",), supporting_sources=("workspace", "incidents"),
    ),
    _cap(
        "C17", "agent-identity", "Persistent Agent Identity", "agents", "Company",
        "Ethos", "Show durable Agent identity separately from the attached model, process, provider session, or task.",
        ("company",), supporting_sources=("workspace",),
    ),
    _cap(
        "C18", "capability-atlas", "Department and Capability Atlas", "agents", "Company",
        "Ethos and Capability Registry", "Organize departments, roster teams, Agents, and verified capabilities while distinguishing implemented contracts from aspirations.",
        ("company", "capability-registry"),
    ),
    _cap(
        "C19", "crew-registry", "Crew Registry", "agents", "Company",
        "Ethos", "Show durable Crew contracts when published; roster-team grouping remains visibly partial and never masquerades as a Crew.",
        ("crews",), supporting_sources=("company",),
        empty_state="No persistent Crew contract is published; roster teams may still appear as partial organizational evidence.",
    ),
    _cap(
        "C24", "capability-help", "Delegator Chat and Capability Help", "agents", "Capability help",
        "Flagship Capability Fabric", "Answer what KE can do, which system owns it, required inputs, effects, limits, current health, and what evidence it returns.",
        ("capability-registry",), supporting_sources=("connectors", "brain"), actions=("search", "inspect"),
    ),
    _cap(
        "C28", "capability-cards", "Capability Cards", "agents", "Capability help",
        "Ethos Context Fabric", "Show version, owner, inputs, artifacts, effects, approvals, cost, health, verification, and limitations for each exposed capability.",
        ("capability-registry",), supporting_sources=("connectors", "evidence"),
    ),
    _cap(
        "C40", "gpu-mps-jobs", "GPU and MPS Job Visibility", "agents", "Compute",
        "GPU Workers", "Show registered jobs, host GPU truth, memory scope, exact owner, lifecycle, freshness, and MPS lane state without process-to-job invention.",
        ("gpu-workers",), supporting_sources=("agents", "memory"),
    ),
    _cap(
        "C41", "kea-watch", "Kea Watch Operations Intelligence", "agents", "Operations intelligence",
        "Kea Watch", "Normalize Movements, Cues, Signals, delegations, runs, gates, receipts, and incidents while keeping observation separate from authority.",
        ("kea-watch",), supporting_sources=("workspace", "powerswarm", "incidents", "evidence"),
    ),
    _cap(
        "C42", "stale-terminal-monitoring", "Stale and Terminal Worker Monitoring", "agents", "Operations intelligence",
        "Kea Watch and registered worker products", "Distinguish fresh, aging, stale, exited, failed, cancelled, verified, and unknown states without inventing useful work.",
        ("kea-watch",), supporting_sources=("cpu-workers", "gpu-workers", "powerswarm"),
    ),
    _cap(
        "C25", "brain-retrieval", "KE Brain Retrieval", "brain", "Knowledge",
        "KE Brain", "Retrieve the minimum relevant entitled context with source, version, ownership, delivery, and freshness truth.",
        ("brain",), supporting_sources=("context-fabric",), actions=("search", "inspect"),
    ),
    _cap(
        "C26", "brain-conversation", "Brain Conversation", "brain", "Knowledge",
        "KE Brain", "Ask a connected Brain through bounded retrieval without copying the whole vault or treating model output as canonical memory.",
        ("brain-conversation",), supporting_sources=("brain", "context-fabric"),
        interaction="local-explicit", actions=("ask",), authority_gates=("entitlement",),
        empty_state="Brain browsing may be available, but no bounded conversation provider is connected.",
    ),
    _cap(
        "C27", "context-packs", "Context Packs", "brain", "Knowledge",
        "Ethos Context Fabric", "Show the exact bounded knowledge snapshot used by work, its version and expiry, and opaque exclusion reasons without leaking protected names.",
        ("context-packs",), supporting_sources=("brain", "evidence"),
        empty_state="No runtime Context Pack has been published for this work object.",
    ),
    _cap(
        "C30", "provenance-lineage", "Provenance and Lineage", "brain", "Evidence",
        "Kea and product evidence owners", "Trace source, context, owner, invocation, artifact, checks, gates, delivery state, and acceptance without collapsing them.",
        ("evidence",), supporting_sources=("brain", "workspace", "kea-watch"),
    ),
    _cap(
        "C31", "entitlement-ip", "Entitlement and IP Filtering", "brain", "Privacy boundary",
        "Ethos Context Fabric", "Enforce public, customer, KE-owned, third-party, derived-only, and server-only boundaries before retrieval or projection.",
        ("entitlements",), supporting_sources=("brain", "context-fabric"),
        interaction="observe", actions=("inspect-policy",), authority_gates=("identity", "entitlement"),
    ),
    _cap(
        "C01", "objective-intake", "Objective Intake", "dispatch", "Request",
        "Dispatch", "Preserve the exact user request and source, then resolve a proposal or owner without silently starting new work.",
        ("dispatch",), supporting_sources=("workspace", "brain"), actions=("draft", "resolve"),
    ),
    _cap(
        "C02", "live-priority-routing", "Live Priority Routing", "dispatch", "Routing",
        "Agent Operations Board and Dispatch", "Deduplicate and resolve one qualified existing owner using exact identity, capability, team, priority, and current ownership.",
        ("dispatch", "ownership"), supporting_sources=("workspace", "incidents"), actions=("resolve",),
    ),
    _cap(
        "C03", "dispatch-existing-work", "Dispatch to Existing Work", "dispatch", "Routing",
        "Dispatch", "Review and deliver once to the exact existing Codex task or Claude session; ambiguity fails closed and no companion work is created.",
        ("dispatch",), supporting_sources=("workspace",), interaction="local-explicit",
        actions=("resolve", "send-once"), authority_gates=("reviewed-destination",), side_effects=("inter-agent-message",),
    ),
    _cap(
        "C11", "authority-gates", "Authority Gates", "dispatch", "Authority",
        "Execution Governor and owning products", "Keep view, local write, send, spend, deploy, release, destructive action, account control, and acceptance as distinct gates.",
        ("authority",), supporting_sources=("permissions", "evidence"), actions=("inspect", "open-handoff"),
    ),
    _cap(
        "C13", "human-escalation", "Human Escalation", "dispatch", "Needs you",
        "Owning task", "Present one precise decision, consequence, available evidence, and resumable boundary; preserve the block until the human acts.",
        ("human-gates",), supporting_sources=("dispatch", "incidents", "evidence"),
        interaction="human-only", actions=("inspect", "respond"), authority_gates=("human-decision",),
    ),
    _cap(
        "C04", "machine-incident-intake", "Machine Incident Intake", "guard", "Incidents",
        "Agent Operations Board", "Turn one attributable terminal failure, stale source, contradiction, or blocked handoff into one durable incident without duplication.",
        ("incidents",), supporting_sources=("guard", "kea-watch"),
    ),
    _cap(
        "C43", "durable-incident-board", "Durable Incident Board", "guard", "Incidents",
        "Agent Operations Board", "Preserve incident identity, severity, owner, acknowledgment, progress, evidence, resolution, and restart-safe history.",
        ("incidents",), supporting_sources=("kea-watch", "guard"),
    ),
    _cap(
        "C44", "ack-repair-resolve", "Acknowledge, Repair, Resolve", "guard", "Incidents",
        "Incident owner and owning product", "Expose the complete loop while keeping repair action, destructive authority, and resolution evidence separately attributable.",
        ("incidents",), supporting_sources=("guard", "evidence"),
        interaction="governed-handoff", actions=("acknowledge", "open-repair", "resolve-with-evidence"),
        authority_gates=("exact-owner", "action-specific-authority"), side_effects=("incident-state",),
    ),
    _cap(
        "C48", "evidence-bound-completion", "Evidence-Bound Completion", "guard", "Evidence",
        "Release Truth and product owner", "Keep activity, implementation, clean candidate, package, installed runtime, live verification, external proof, and founder acceptance distinct.",
        ("evidence",), supporting_sources=("kea-watch", "incidents", "workspace"),
    ),
    _cap(
        "C63", "defense-observation", "Cyber Observation and KE Defense+", "guard", "Defense",
        "KE Defense+ and KE Guard", "Show authorized posture, sensors, suspects, coverage gaps, incidents, and recovery evidence without claiming universal protection.",
        ("guard",), supporting_sources=("permissions", "incidents"), actions=("inspect", "open-defense"),
    ),
    _cap(
        "C33", "powerswarm", "Governed PowerSwarm", "agents", "PowerSwarm",
        "PowerSwarm and Director", "Show exact Codex parent, signed run, target lanes, real worker attempts, liveness, kill checks, evidence, retries, nested-plan truth, and settlement.",
        ("powerswarm",), supporting_sources=("workspace", "evidence", "kea-watch"),
        interaction="observe", actions=("inspect", "open-owner"),
        authority_gates=("separate-powerswarm-command",),
        empty_state="No durable PowerSwarm run is recorded; the flagship does not launch one implicitly.",
        kind="native-governed-surface",
    ),
)


def _validate_catalog() -> None:
    ids = [item.capability_id for item in CAPABILITIES]
    slugs = [item.slug for item in CAPABILITIES]
    if len(ids) != len(set(ids)) or len(slugs) != len(set(slugs)):
        raise RuntimeError("flagship capability identifiers must be unique")
    native = {item.capability_id for item in CAPABILITIES if item.kind == "native"}
    supplement = {
        item.capability_id for item in CAPABILITIES if item.kind == "native-governed-surface"
    }
    if native != NATIVE_CAPABILITY_IDS:
        raise RuntimeError("flagship catalog does not contain the exact 30 native capabilities")
    if supplement != SUPPLEMENTAL_CAPABILITY_IDS:
        raise RuntimeError("flagship catalog does not contain the PowerSwarm governed surface")
    invalid_tabs = {item.tab for item in CAPABILITIES} - set(CURRENT_TOP_LEVEL_ORDER)
    if invalid_tabs:
        raise RuntimeError(f"capabilities target non-current tabs: {sorted(invalid_tabs)}")
    for item in CAPABILITIES:
        if not item.owner or not item.summary or not item.required_sources or not item.actions:
            raise RuntimeError(f"incomplete capability descriptor: {item.capability_id}")


_validate_catalog()

CAPABILITY_BY_ID = {item.capability_id: item for item in CAPABILITIES}
CAPABILITY_BY_SLUG = {item.slug: item for item in CAPABILITIES}


def catalog() -> Dict[str, Any]:
    """Return the immutable, serializable product catalog in current tab order."""

    ordered = sorted(
        CAPABILITIES,
        key=lambda item: (CURRENT_TOP_LEVEL_ORDER.index(item.tab), item.capability_id),
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "preservesCurrentOrder": True,
        "topLevelOrder": list(CURRENT_TOP_LEVEL_ORDER),
        "counts": {
            "native": len(NATIVE_CAPABILITY_IDS),
            "nativeGovernedSurface": len(SUPPLEMENTAL_CAPABILITY_IDS),
            "total": len(CAPABILITIES),
        },
        "capabilities": [item.to_public_dict() for item in ordered],
        "boundary": (
            "The flagship owns these native experiences and read models. "
            "Observation, connection, and visibility never inherit execution authority."
        ),
    }


def search_capabilities(query: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Search the Capability Atlas without provider calls or fuzzy invention."""

    terms = [term for term in re.split(r"\s+", str(query or "").strip().casefold()) if term]
    bounded_limit = max(1, min(int(limit), len(CAPABILITIES)))
    scored: List[Tuple[int, CapabilityDescriptor]] = []
    for item in CAPABILITIES:
        haystack = " ".join(
            (
                item.capability_id,
                item.slug,
                item.name,
                item.owner,
                item.summary,
                item.tab,
                item.section,
                " ".join(item.actions),
            )
        ).casefold()
        if not terms:
            score = 1
        elif all(term in haystack for term in terms):
            score = sum(5 if term in item.name.casefold() else 1 for term in terms)
        else:
            continue
        scored.append((score, item))
    scored.sort(
        key=lambda pair: (
            -pair[0],
            CURRENT_TOP_LEVEL_ORDER.index(pair[1].tab),
            pair[1].capability_id,
        )
    )
    return [item.to_public_dict() for _, item in scored[:bounded_limit]]


def _overall_state(required: Sequence[SourceSignal]) -> str:
    if not required:
        return "not-connected"
    states = {signal.state for signal in required}
    freshness = {signal.freshness for signal in required}
    if "blocked" in states:
        return "blocked"
    if "unavailable" in states:
        return "unavailable"
    if "not-configured" in states:
        return "not-connected"
    if "stale" in freshness:
        return "stale"
    if "degraded" in states or "aging" in freshness or "unknown" in freshness:
        return "degraded"
    return "working"


def _evidence_level(required: Sequence[SourceSignal]) -> str:
    if not required:
        return "recorded"
    return min(required, key=lambda signal: EVIDENCE_RANK[signal.evidence]).evidence


def _freshness(required: Sequence[SourceSignal]) -> str:
    if not required:
        return "unknown"
    values = {signal.freshness for signal in required}
    for value in ("stale", "unknown", "aging", "fresh"):
        if value in values:
            return value
    return "unknown"


class FlagshipCapabilityService:
    """Combine separately owned source signals into one truthful native surface."""

    def __init__(self, now=None) -> None:
        self._now = now or _utc_now

    @staticmethod
    def _signal_map(signals: Iterable[SourceSignal]) -> Dict[str, SourceSignal]:
        mapped: Dict[str, SourceSignal] = {}
        for signal in signals:
            if signal.source_id in mapped:
                raise ValueError(f"duplicate source signal: {signal.source_id}")
            mapped[signal.source_id] = signal
        return mapped

    def snapshot(self, signals: Iterable[SourceSignal] = ()) -> Dict[str, Any]:
        source_map = self._signal_map(signals)
        rows: List[Dict[str, Any]] = []
        for descriptor in sorted(
            CAPABILITIES,
            key=lambda item: (CURRENT_TOP_LEVEL_ORDER.index(item.tab), item.capability_id),
        ):
            required = [
                source_map[source_id]
                for source_id in descriptor.required_sources
                if source_id in source_map
            ]
            missing = [
                source_id
                for source_id in descriptor.required_sources
                if source_id not in source_map
            ]
            supporting = [
                source_map[source_id]
                for source_id in descriptor.supporting_sources
                if source_id in source_map
            ]
            state = "not-connected" if missing else _overall_state(required)
            detail = descriptor.empty_state if missing else next(
                (
                    _safe_text(signal.detail)
                    for signal in required
                    if signal.detail and signal.state != "available"
                ),
                "Current evidence is available from every required owner source.",
            )
            resources = [
                _safe_text(signal.resource, 160)
                for signal in required + supporting
                if signal.resource
            ]
            receipts = [
                _safe_text(signal.receipt_ref, 160)
                for signal in required + supporting
                if signal.receipt_ref
            ]
            row = descriptor.to_public_dict()
            row.update(
                {
                    "state": state,
                    "authority": {
                        "interaction": descriptor.interaction,
                        "gates": list(descriptor.authority_gates),
                        "sideEffects": list(descriptor.side_effects),
                        "inheritedFromVisibility": False,
                    },
                    "resource": {
                        "state": "published" if resources else "not-published",
                        "summaries": resources,
                    },
                    "evidence": {
                        "level": _evidence_level(required),
                        "requiredSources": [signal.public_dict() for signal in required],
                        "supportingSources": [signal.public_dict() for signal in supporting],
                        "missingSources": missing,
                        "receiptRefs": receipts,
                    },
                    "freshness": {
                        "state": _freshness(required),
                        "observedAt": [
                            _safe_text(signal.observed_at, 80)
                            for signal in required
                            if signal.observed_at
                        ],
                    },
                    "detail": detail,
                }
            )
            rows.append(row)

        counts: Dict[str, int] = {
            state: sum(1 for row in rows if row["state"] == state)
            for state in (
                "working",
                "degraded",
                "stale",
                "blocked",
                "unavailable",
                "not-connected",
            )
        }
        return {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": self._now(),
            "readOnly": True,
            "preservesCurrentOrder": True,
            "topLevelOrder": list(CURRENT_TOP_LEVEL_ORDER),
            "counts": {
                **counts,
                "native": len(NATIVE_CAPABILITY_IDS),
                "nativeGovernedSurface": len(SUPPLEMENTAL_CAPABILITY_IDS),
                "total": len(rows),
            },
            "stateRail": [
                "owner",
                "capability",
                "state",
                "authority",
                "resource",
                "evidence",
                "freshness",
            ],
            "capabilities": rows,
            "privacy": {
                "mode": "metadata-only",
                "absolutePathsReturned": False,
                "privateContactsReturned": False,
                "credentialsReturned": False,
                "sourceBodiesReturned": False,
            },
            "boundary": (
                "This snapshot observes and routes. It does not launch PowerSwarm, "
                "grant authority, mutate a Brain, control a process, or accept work."
            ),
        }

    def snapshot_json(self, signals: Iterable[SourceSignal] = ()) -> str:
        return json.dumps(self.snapshot(signals), separators=(",", ":"), sort_keys=True)


__all__ = [
    "CAPABILITIES",
    "CAPABILITY_BY_ID",
    "CURRENT_TOP_LEVEL_ORDER",
    "FlagshipCapabilityService",
    "NATIVE_CAPABILITY_IDS",
    "SCHEMA_VERSION",
    "SUPPLEMENTAL_CAPABILITY_IDS",
    "SourceSignal",
    "catalog",
    "search_capabilities",
]
