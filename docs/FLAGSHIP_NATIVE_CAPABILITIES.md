# Flagship native capability contract

Status: local integration foundation. This document does not rename the app,
change its navigation, launch PowerSwarm, or claim that unfinished owner
systems are working.

## Product-order constraint

The existing top-level order is binding until the product owner changes it:

1. CPU
2. Memory
3. Energy
4. Disk
5. Network
6. Agents
7. AI Brain
8. Dispatch
9. KE Guard

The flagship expands **inside this order**. It does not introduce a Today-first
shell, replace the tab strip, or silently position itself as a KE Desktop
successor. New surfaces may attach to the relevant existing tab without moving
the existing destinations.

## What “native” means

Native means the flagship owns the primary local experience, normalized read
model, truth state, navigation, and human handoff. It does not mean the
flagship steals execution or data ownership from PowerSwarm, Ethos, KE Brain,
Kea Watch, the Execution Governor, KE Defense+, or another product.

Every capability uses one common rail:

```text
OWNER · CAPABILITY · STATE · AUTHORITY · RESOURCE · EVIDENCE · FRESHNESS
```

The rail is functional rather than decorative:

- a safe missing local binding appears `repairable`, a known publisher or
  consent gap appears `setup-required`, and only an unknown absent owner remains
  `not-connected`;
- source failure appears `unavailable` or `degraded`, never as zero activity;
- stale data remains visibly stale;
- recorded, claimed, observed, and verified evidence remain distinct;
- visibility never grants execution authority;
- host utilization never becomes an invented budget or progress counter;
- product acceptance remains separate from implementation and runtime proof.

## Exact capability placement

| Current destination | Native capability surfaces |
|---|---|
| CPU | C39 CPU Worker Visibility |
| Memory | C12 Budgets and Guardrails, with host pressure shown only as supporting evidence |
| Energy | Existing energy experience remains in place; no unrelated capability is forced into it |
| Disk | C36 Isolated Worktree Execution Visibility |
| Network | C32 Connector Discovery; C64 Private Host Link and Remote Operation |
| Agents | C09 Exact Task Identity; C10 One-Writer Ownership; C17 Persistent Agent Identity; C18 Department and Capability Atlas; C19 Crew Registry; C24 Capability Help; C28 Capability Cards; C40 GPU/MPS Jobs; C41 Kea Watch; C42 stale/terminal monitoring |
| AI Brain | C25 Retrieval; C26 Conversation; C27 Context Packs; C30 Provenance and Lineage; C31 Entitlement and IP Filtering |
| Dispatch | C01 Objective Intake; C02 Live Priority Routing; C03 Dispatch to Existing Work; C11 Authority Gates; C13 Human Escalation |
| KE Guard | C04 Machine Incident Intake; C43 Durable Incident Board; C44 Acknowledge/Repair/Resolve; C48 Evidence-Bound Completion; C63 Cyber Observation and KE Defense+ |

That is exactly thirty native capabilities.

## PowerSwarm is additionally native as a governed surface

PowerSwarm is C33 and sits alongside the thirty because the product owner explicitly
included it in the flagship scope. The flagship surface shows:

- the exact Codex parent edge when recorded;
- the signed Director PowerSwarm run;
- objective, product, runtime profile, requested width, signed cap, and state;
- each target lane and its one-writer worktree;
- coordinator and worker PID liveness as observation, not completion;
- speed-dev and bug-sweep attempts;
- immutable kill-check status and verification receipts;
- retries, deadline state, settlement, failure, and cancellation truth;
- centrally governed nested-plan depth only when its contract validates;
- Kea/operations evidence without copying worker output or private prompts.

The flagship does **not** infer that queued workers are live, relabel generic
Grok sessions, expose raw worker prompts or outputs, launch on view, resume a
run, cancel work, or inherit PowerSwarm authority. Those actions remain
separate explicit PowerSwarm commands.

In the integrated flagship, C33 is not a dead detail card. **Open in Agents**
routes to the existing accepted, read-only PowerSwarm subview. That subview
stays nested under Agents, retains its **‹ Agents** Back control, and exposes
no launch, cancel, resume, or retry action. The bridge reads its bounded run
projection through the existing `PowerSwarmService`; it does not read provider
stores directly or create a worker.

## How the implementation composes

`flagship_capabilities.py` is the stable cross-feature contract. Existing and
in-flight adapters publish small `SourceSignal` records. The service projects
those records into the common rail and keeps each capability inside its current
destination.

`flagship_local_sources.py` adds two real, bounded local observers without
importing or starting the owning systems:

- the existing Ethos roster becomes privacy-safe Agent and roster-team
  metadata; it never returns email addresses, personas, charters, Brain paths,
  allowlists, job subjects, or message bodies, and it never seeds a missing
  roster. The trusted user root and every descendant are opened first as
  current-user, local-filesystem, no-follow descriptors; identity and directory
  change metadata are revalidated after bounded parsing, so performed swaps
  fail closed even when the original pathname is restored;
- the Agent Operations Board binds SQLite to the already validated file through
  its Darwin `/dev/fd` descriptor alias in read-only immutable mode. SQLite is
  never given the Board pathname, and fixed, length-bounded metadata queries
  return exact owner and incident identity without writable scopes, incident
  details, safe-action commands, event payloads, or the database path. Platforms
  that cannot prove that binding report the source unavailable.

`flagship_sources.py` is the adapter seam for the current feature lanes. It
translates only explicitly supplied, allowlisted payloads into source signals
and always publishes the executable capability catalog itself. A bounded
derived binding may summarize current owner evidence, but it cannot turn an
adjacent tab into an invented Connector, Crew, Governor, permission, or
authority.

`flagship_bridge.py` binds the current Workspace Registry and PowerSwarm owner
services as read-only providers, alongside the already bounded Brain,
Dispatch, Guard, Agents, Ethos, and Agent Operations Board projections. It
continuously recomputes six finite compatibility bindings—Brain conversation,
Context Packs, evidence, entitlements, Kea Watch, and authority—from those
already sanitized projections. These bindings remain degraded when the
dedicated owner receipt or complete coverage is absent. A Governor, Connector,
Crew, private-host trust, permission, credential, or provider session is never
auto-created. Provider results are immediately reduced to strict
source-specific allowlists containing only normalized state, bounded time and
evidence fields, and the exact Company or Board counts their translators use.
Only those projections are cached across tabs; raw objects, details, bodies,
credentials, prompts, messages, transcripts, tokens, paths, and unknown fields
never enter retained bridge state.

The one-click **Check & fix** path is single-flight, generation-bound, and
idempotent. It only rebuilds those allowlisted bindings from the current cache;
it performs no I/O and does not refresh or mutate an owner. Normal snapshot
refreshes perform the same safe binding reconciliation automatically. A stale
click fails closed, and a whole-bridge failure returns owner-unavailable truth
instead of repainting an empty baseline as disconnected. Network and Disk
recovery remain with their owning tabs and are never invoked here.
Every completed check returns one bounded result for each capability in scope:
`applied`, `already-healthy`, `manual`, `unavailable`, or `failed`. The UI
renders that ledger with text nodes and restores keyboard focus to the repaired
card's next meaningful control after its DOM is refreshed.

`flagship_ui.py` is the reusable native presentation layer. It supplies one
compact capability fabric mount for every relevant existing destination and
intentionally supplies no Energy mount because no unrelated capability should
be forced into that tab. Every source-provided value is rendered through DOM
text nodes and every card shows the common evidence rail. It emits inspection
and bounded local-repair requests only. PowerSwarm is labelled **Open in
Agents**; the component has no launch, cancel, resume, send, process-control,
Brain-write, Network/Disk-repair, preference, credential, or authority-grant
action. Each non-Guard Fabric header has an explicit accessible minimize/expand
control; Guard remains permanently expanded because its tab permits no controls.
The minimized view retains its title and aggregate truth while hiding the
filter, result detail, evidence rail, and cards. Its UI-only collapsed state is
stored locally, fails safely expanded when storage is missing or malformed, and
does not rerun repair or alter capability truth. In-memory filter, expanded-card,
scroll, and focus state survive minimize/expand and ordinary snapshot refreshes.

Examples:

- Dispatch plus the ownership registry jointly prove Live Priority Routing.
  Dispatch alone cannot call C02 working.
- A fresh PowerSwarm ledger plus independent process evidence may prove a live
  worker, but only a green kill check proves its target verified.
- Brain browsing can bind to exact local Codex/Claude conversation readiness,
  while remaining degraded until each answer has a bounded retrieval receipt.
- Ethos roster teams can support Company visibility while Crew Registry stays
  partial until a real persistent Crew contract is published.
- CPU activity can support a worker observation but cannot produce completion,
  budget, or accepted-output claims.

## Integration seams

The canonical integrator should instantiate one
`FlagshipCapabilityService`, translate existing feature payloads into
`SourceSignal` records, and expose a read-only bridge method. The integrator
injects `CAPABILITY_UI_CSS` once, mounts `capability_mount_html(tab)` inside
each assigned existing tab, injects `CAPABILITY_UI_JS` once, and calls
`renderFlagshipCapabilities(snapshot)` after the bridge returns. Each tab
renders only the capability sections assigned above. The catalog search
supplies C24 and C28 without a provider call.

The module is intentionally fail-soft and source-agnostic so active candidate
lanes can integrate in sequence:

1. project rail and Dispatch;
2. GPU correctness;
3. Memory diagnostics;
4. Network and KE Link;
5. PowerSwarm visibility;
6. Full Access posture;
7. Defense Center;
8. flagship capability fabric and combined installed verification.

The final installed proof must show the original top-level order unchanged,
all thirty native capability surfaces addressable, PowerSwarm truthful and
read-only, unavailable owner systems labelled honestly, keyboard access, no
private path/contact/token projection, and no mutation caused by observation.

`scripts/verify_flagship_snapshot.py` is the combined deterministic gate. It
rejects missing or extra capabilities, changed navigation, owner drift,
incomplete source accounting, a working state with missing owner evidence,
privacy regressions, and any implicit PowerSwarm launch/cancel/resume control.
Its exact green line is:

```text
FLAGSHIP_CAPABILITIES_OK 30+1 CURRENT_ORDER_PRESERVED
```
