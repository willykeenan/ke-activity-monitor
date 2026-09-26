"""Executable combined acceptance for the flagship capability projection."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from flagship_capabilities import (
    CAPABILITY_BY_ID,
    CURRENT_TOP_LEVEL_ORDER,
    NATIVE_CAPABILITY_IDS,
    SCHEMA_VERSION,
    SUPPLEMENTAL_CAPABILITY_IDS,
)


ALLOWED_STATES = {
    "working",
    "degraded",
    "stale",
    "blocked",
    "unavailable",
    "repairable",
    "setup-required",
    "not-connected",
}
ALLOWED_REPAIR_OUTCOMES = {
    "applied",
    "already-healthy",
    "manual",
    "unavailable",
    "failed",
}
STATE_RAIL = [
    "owner",
    "capability",
    "state",
    "authority",
    "resource",
    "evidence",
    "freshness",
]


def verify_flagship_snapshot(payload: Mapping[str, Any]) -> List[str]:
    """Return every deterministic contract error without mutating the payload."""

    errors: List[str] = []
    if not isinstance(payload, Mapping):
        return ["snapshot root must be an object"]
    if payload.get("schemaVersion") != SCHEMA_VERSION:
        errors.append("schemaVersion mismatch")
    if payload.get("readOnly") is not True:
        errors.append("snapshot must be read-only")
    if payload.get("preservesCurrentOrder") is not True:
        errors.append("current-order invariant is missing")
    if payload.get("topLevelOrder") != list(CURRENT_TOP_LEVEL_ORDER):
        errors.append("top-level order changed")
    if payload.get("stateRail") != STATE_RAIL:
        errors.append("state rail changed")

    privacy = payload.get("privacy") if isinstance(payload.get("privacy"), Mapping) else {}
    for field in (
        "absolutePathsReturned",
        "privateContactsReturned",
        "credentialsReturned",
        "sourceBodiesReturned",
    ):
        if privacy.get(field) is not False:
            errors.append(f"privacy field {field} must be false")

    rows = payload.get("capabilities")
    if not isinstance(rows, list):
        return errors + ["capabilities must be an array"]
    by_id: Dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            errors.append(f"capability row {index} is not an object")
            continue
        capability_id = str(row.get("id") or "")
        if capability_id in by_id:
            errors.append(f"duplicate capability row {capability_id}")
            continue
        by_id[capability_id] = row

    expected = NATIVE_CAPABILITY_IDS | SUPPLEMENTAL_CAPABILITY_IDS
    missing = sorted(expected - set(by_id))
    unexpected = sorted(set(by_id) - expected)
    if missing:
        errors.append("missing capabilities: " + ",".join(missing))
    if unexpected:
        errors.append("unexpected capabilities: " + ",".join(unexpected))
    if len(rows) != 31:
        errors.append("snapshot must contain exactly 30 native capabilities plus PowerSwarm")

    for capability_id in sorted(expected & set(by_id)):
        row = by_id[capability_id]
        descriptor = CAPABILITY_BY_ID[capability_id]
        placement = row.get("placement") if isinstance(row.get("placement"), Mapping) else {}
        if placement.get("tab") != descriptor.tab:
            errors.append(f"{capability_id} moved from its declared current tab")
        if placement.get("tabRank") != CURRENT_TOP_LEVEL_ORDER.index(descriptor.tab):
            errors.append(f"{capability_id} has an invalid tab rank")
        if row.get("owner") != descriptor.owner:
            errors.append(f"{capability_id} owner changed")
        state = row.get("state")
        if state not in ALLOWED_STATES:
            errors.append(f"{capability_id} has an invalid state")
        authority = row.get("authority") if isinstance(row.get("authority"), Mapping) else {}
        if authority.get("inheritedFromVisibility") is not False:
            errors.append(f"{capability_id} inherits authority from visibility")
        recovery = row.get("recovery")
        if recovery is not None:
            recovery = recovery if isinstance(recovery, Mapping) else {}
            if recovery.get("noSideEffects") is not True:
                errors.append(f"{capability_id} recovery has side effects")
            if recovery.get("canAttempt") is True and recovery.get("mode") != "safe-local-binding":
                errors.append(f"{capability_id} exposes an unbounded recovery action")
        evidence = row.get("evidence") if isinstance(row.get("evidence"), Mapping) else {}
        missing_sources = evidence.get("missingSources")
        required_sources = evidence.get("requiredSources")
        if not isinstance(missing_sources, list) or not isinstance(required_sources, list):
            errors.append(f"{capability_id} evidence sources are malformed")
        else:
            expected_required = set(descriptor.required_sources)
            observed_required = {
                item.get("sourceId")
                for item in required_sources
                if isinstance(item, Mapping) and isinstance(item.get("sourceId"), str)
            }
            if set(missing_sources) | observed_required != expected_required:
                errors.append(f"{capability_id} required source accounting is incomplete")
            if set(missing_sources) & observed_required:
                errors.append(f"{capability_id} source appears both present and missing")
            if state == "working" and missing_sources:
                errors.append(f"{capability_id} appears working with missing owner sources")
            if state == "not-connected" and not missing_sources:
                errors.append(f"{capability_id} is not-connected without a missing source")

    powerswarm = by_id.get("C33")
    if isinstance(powerswarm, Mapping):
        if powerswarm.get("kind") != "native-governed-surface":
            errors.append("PowerSwarm surface kind changed")
        actions = powerswarm.get("actions")
        if not isinstance(actions, list) or any(action in actions for action in ("launch", "cancel", "resume")):
            errors.append("PowerSwarm visibility contains implicit run controls")
        authority = powerswarm.get("authority") if isinstance(powerswarm.get("authority"), Mapping) else {}
        if "separate-powerswarm-command" not in (authority.get("gates") or []):
            errors.append("PowerSwarm separate-command gate is missing")

    counts = payload.get("counts") if isinstance(payload.get("counts"), Mapping) else {}
    if counts.get("native") != 30 or counts.get("nativeGovernedSurface") != 1 or counts.get("total") != 31:
        errors.append("capability counts do not equal 30 plus PowerSwarm")
    projected_state_total = sum(int(counts.get(state) or 0) for state in ALLOWED_STATES)
    if projected_state_total != 31:
        errors.append("capability state counts do not sum to 31")
    recovery = payload.get("recovery")
    if recovery is not None:
        recovery = recovery if isinstance(recovery, Mapping) else {}
        if recovery.get("generationBound") is not True:
            errors.append("recovery must be generation-bound")
        if recovery.get("singleFlight") is not True:
            errors.append("recovery must be single-flight")
        if recovery.get("noIORepair") is not True:
            errors.append("recovery must remain no-I/O")
    return errors


def acceptance_summary(payload: Mapping[str, Any]) -> Dict[str, Any]:
    errors = verify_flagship_snapshot(payload)
    return {
        "ok": not errors,
        "contract": "ke.activity-monitor-flagship-acceptance.v1",
        "nativeCapabilities": 30,
        "powerSwarmGovernedSurface": 1,
        "currentOrderPreserved": payload.get("topLevelOrder") == list(CURRENT_TOP_LEVEL_ORDER),
        "errors": errors,
    }


def verify_flagship_repair_result(payload: Mapping[str, Any]) -> List[str]:
    """Validate one bounded, privacy-safe capability repair result ledger."""

    errors: List[str] = []
    if not isinstance(payload, Mapping):
        return ["repair result root must be an object"]
    if payload.get("outcomeSchemaVersion") != (
        "ke.activity-monitor-flagship-repair-outcomes.v1"
    ):
        errors.append("repair outcome schema mismatch")
    if payload.get("outcomesBounded") is not True:
        errors.append("repair outcomes must be bounded")
    outcomes = payload.get("outcomes")
    if not isinstance(outcomes, list) or not 1 <= len(outcomes) <= len(CAPABILITY_BY_ID):
        return errors + ["repair outcomes must contain 1 to 31 capability results"]

    seen = set()
    observed_counts = {outcome: 0 for outcome in ALLOWED_REPAIR_OUTCOMES}
    for index, item in enumerate(outcomes):
        if not isinstance(item, Mapping):
            errors.append(f"repair outcome {index} is not an object")
            continue
        capability_id = str(item.get("capabilityId") or "")
        if capability_id not in CAPABILITY_BY_ID:
            errors.append(f"repair outcome {index} has an unknown capability")
        elif capability_id in seen:
            errors.append(f"duplicate repair outcome {capability_id}")
        else:
            seen.add(capability_id)
            if item.get("name") != CAPABILITY_BY_ID[capability_id].name:
                errors.append(f"{capability_id} repair outcome name changed")
        outcome = str(item.get("outcome") or "")
        if outcome not in ALLOWED_REPAIR_OUTCOMES:
            errors.append(f"{capability_id or index} has an invalid repair outcome")
        else:
            observed_counts[outcome] += 1
        if item.get("noSideEffects") is not True:
            errors.append(f"{capability_id or index} repair result has side effects")
        if item.get("stateBefore") not in ALLOWED_STATES:
            errors.append(f"{capability_id or index} has an invalid prior state")
        if item.get("stateAfter") not in ALLOWED_STATES:
            errors.append(f"{capability_id or index} has an invalid resulting state")
        detail = item.get("detail")
        if not isinstance(detail, str) or not detail or len(detail) > 180:
            errors.append(f"{capability_id or index} repair detail is malformed")

    counts = payload.get("outcomeCounts")
    try:
        claimed_counts = (
            {
                outcome: int(counts.get(outcome) or 0)
                for outcome in ALLOWED_REPAIR_OUTCOMES
            }
            if isinstance(counts, Mapping)
            else {}
        )
    except (TypeError, ValueError):
        claimed_counts = {}
    if claimed_counts != observed_counts:
        errors.append("repair outcome counts do not match the ledger")
    try:
        repaired = int(payload.get("repaired") or 0)
    except (TypeError, ValueError):
        repaired = -1
    if repaired != observed_counts["applied"]:
        errors.append("repair applied count does not match repaired")
    if (payload.get("ok") is True) == bool(observed_counts["failed"]):
        errors.append("repair success does not match failed outcomes")
    return errors


__all__ = [
    "acceptance_summary",
    "verify_flagship_repair_result",
    "verify_flagship_snapshot",
]
