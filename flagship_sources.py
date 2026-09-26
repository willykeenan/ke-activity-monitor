"""Translate owner feature payloads into flagship capability source signals."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional

from flagship_capabilities import SourceSignal


def _safe_count(value: Any, maximum: int = 1_000_000) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, min(number, maximum))


def _detail(payload: Mapping[str, Any], fallback: str) -> str:
    for key in ("detail", "boundary", "error", "reason"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def _observed_at(payload: Mapping[str, Any]) -> Optional[str]:
    for key in ("observedAt", "generatedAt", "updatedAt"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _state(payload: Mapping[str, Any]) -> str:
    raw = str(payload.get("state") or payload.get("status") or "").strip().lower()
    if raw in {"not-installed", "not-configured", "absent", "none", "no-runs"}:
        return "not-configured"
    if raw in {"needs-user-action", "blocked", "blocked-human", "blocked_human"}:
        return "blocked"
    if raw in {"offline", "unavailable", "unsupported", "error", "failed"}:
        return "unavailable"
    if payload.get("ok") is False:
        return "unavailable"
    if payload.get("stale") is True or raw in {"stale", "degraded", "partial", "aging"}:
        return "degraded"
    if payload.get("ok") is True or raw in {
        "available", "working", "active", "running", "connected", "armed", "dry-run"
    }:
        return "available"
    return "degraded"


def _freshness(payload: Mapping[str, Any]) -> str:
    raw = str(payload.get("freshness") or "").strip().lower()
    if raw in {"fresh", "aging", "stale", "unknown"}:
        return raw
    if payload.get("stale") is True or str(payload.get("state") or "").lower() == "stale":
        return "stale"
    return "fresh" if _observed_at(payload) else "unknown"


def _evidence(payload: Mapping[str, Any], default: str = "observed") -> str:
    raw = str(payload.get("evidenceLevel") or "").strip().lower()
    if raw in {"recorded", "claimed", "observed", "verified"}:
        return raw
    if payload.get("verified") is True:
        return "verified"
    return default


def signal_from_payload(
    source_id: str,
    payload: Mapping[str, Any],
    *,
    owner: str,
    resource: str = "",
    receipt_ref: str = "",
    default_evidence: str = "observed",
) -> SourceSignal:
    """Create one explicit signal; callers choose the semantic source ID."""

    if not isinstance(payload, Mapping):
        raise TypeError("feature payload must be a mapping")
    return SourceSignal(
        source_id=source_id,
        state=_state(payload),
        evidence=_evidence(payload, default_evidence),
        freshness=_freshness(payload),
        observed_at=_observed_at(payload),
        detail=_detail(payload, f"{owner} published a bounded feature state."),
        owner=owner,
        resource=resource,
        receipt_ref=receipt_ref,
    )


def company_signals(payload: Mapping[str, Any]) -> List[SourceSignal]:
    signals = [
        signal_from_payload(
            "company",
            payload,
            owner="Ethos",
            resource=(
                f"{_safe_count((payload.get('summary') or {}).get('agents'))} Agents; "
                f"{_safe_count((payload.get('summary') or {}).get('teams'))} roster teams"
            ),
        )
    ]
    crew_count = _safe_count((payload.get("summary") or {}).get("crewContracts"))
    signals.append(
        SourceSignal(
            "crews",
            "available" if crew_count > 0 else "not-configured",
            evidence="observed",
            freshness="fresh" if payload.get("ok") else "unknown",
            observed_at=_observed_at(payload),
            detail=(
                f"{crew_count} durable Crew contracts observed."
                if crew_count > 0
                else "Roster teams are visible, but no durable Crew contract is published."
            ),
            owner="Ethos",
        )
    )
    return signals


def board_signals(payload: Mapping[str, Any]) -> List[SourceSignal]:
    counts = payload.get("counts") if isinstance(payload.get("counts"), Mapping) else {}
    base = signal_from_payload(
        "ownership",
        payload,
        owner="Agent Operations Board",
        resource=f"{_safe_count(counts.get('activeOwners'))} active registered owners",
    )
    incidents = signal_from_payload(
        "incidents",
        payload,
        owner="Agent Operations Board",
        resource=f"{_safe_count(counts.get('open'))} open incidents",
    )
    needs = _safe_count(counts.get("needsHuman"))
    human = SourceSignal(
        "human-gates",
        "blocked" if needs else ("available" if payload.get("ok") else "unavailable"),
        evidence="observed",
        freshness="fresh" if payload.get("ok") else "unknown",
        observed_at=_observed_at(payload),
        detail=(f"{needs} precise decisions currently need a human decision." if needs else "No open board incident currently needs a human decision."),
        owner="Agent Operations Board",
    )
    return [base, incidents, human]


def feature_signals(payloads: Mapping[str, Mapping[str, Any]]) -> List[SourceSignal]:
    """Translate only explicitly supplied owner payloads; never invent sources."""

    signals: List[SourceSignal] = [
        SourceSignal(
            "capability-registry",
            "available",
            evidence="verified",
            freshness="fresh",
            detail="The exact thirty-capability catalog and PowerSwarm supplement passed its executable contract.",
            owner="Flagship Capability Fabric",
        )
    ]
    owner_by_source = {
        "agents": "Activity Monitor",
        "dispatch": "Dispatch",
        "workspace": "Workspace Registry",
        "brain": "KE Brain",
        "brain-conversation": "KE Brain",
        "context-fabric": "Ethos Context Fabric",
        "context-packs": "Ethos Context Fabric",
        "entitlements": "Ethos Context Fabric",
        "connectors": "KE Connector",
        "cpu-workers": "CPU Workers",
        "gpu-workers": "GPU Workers",
        "kea-watch": "Kea Watch",
        "evidence": "Product evidence owners",
        "guard": "KE Defense+ and KE Guard",
        "authority": "Execution Governor and owning products",
        "governor": "Execution Governor",
        "permissions": "macOS and owning providers",
        "memory": "Activity Monitor",
        "disk": "Activity Monitor",
        "network": "Network observer",
        "private-hosts": "KE Remote Operator",
        "powerswarm": "PowerSwarm and Director",
    }
    for source_id, owner in owner_by_source.items():
        payload = payloads.get(source_id)
        if isinstance(payload, Mapping):
            signals.append(signal_from_payload(source_id, payload, owner=owner))
    company = payloads.get("company")
    if isinstance(company, Mapping):
        signals.extend(company_signals(company))
    board = payloads.get("operations-board")
    if isinstance(board, Mapping):
        signals.extend(board_signals(board))
    return signals


__all__ = [
    "board_signals",
    "company_signals",
    "feature_signals",
    "signal_from_payload",
]
