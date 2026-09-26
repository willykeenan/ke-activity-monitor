"""Reusable native presentation layer for the flagship capability fabric.

The canonical app is intentionally owned by a separate integration lane.  This
module therefore supplies an add-only, deterministic UI component that can be
mounted inside the existing tabs without changing their order.  The browser
renderer uses DOM text nodes for every source-provided value, publishes only an
inspect event, and contains no execution control.
"""

from __future__ import annotations

from html import escape
from typing import Dict, Iterable, Tuple

from flagship_capabilities import CAPABILITIES, CURRENT_TOP_LEVEL_ORDER


SCHEMA_VERSION = "ke.activity-monitor-flagship-ui.v1"

CAPABILITY_TABS: Tuple[str, ...] = tuple(
    tab
    for tab in CURRENT_TOP_LEVEL_ORDER
    if any(capability.tab == tab for capability in CAPABILITIES)
)

_TAB_LABELS = {
    "cpu": "CPU",
    "memory": "Memory",
    "energy": "Energy",
    "disk": "Disk",
    "network": "Network",
    "agents": "Agents",
    "brain": "AI Brain",
    "dispatch": "Dispatch",
    "guard": "KE Guard",
}


def capability_mount_html(tab: str) -> str:
    """Return one inert, keyboard-accessible mount for an existing tab."""

    if tab not in CAPABILITY_TABS:
        return ""
    label = escape(_TAB_LABELS[tab])
    body_id = f"flagship-fabric-body-{tab}"
    filter_control = "" if tab == "guard" else (
        f'<label class="flagship-filter-label"><span class="flagship-sr-only">'
        f'Filter {label} capabilities</span><input type="search" data-flagship-filter '
        'placeholder="Filter capabilities" autocomplete="off"></label>'
    )
    fix_control = "" if tab == "guard" else (
        '<button type="button" class="flagship-fix-all" '
        'data-flagship-fix-all>Auto Fix</button>'
    )
    collapse_control = "" if tab == "guard" else (
        '<button type="button" class="flagship-collapse" data-flagship-collapse '
        f'aria-expanded="true" aria-controls="{body_id}" '
        f'aria-label="Minimize {label} capability fabric">Minimize</button>'
    )
    return f'''<section class="flagship-fabric" data-flagship-tab="{tab}" aria-label="{label} connections">
  <div class="flagship-fabric-head">
    <div class="flagship-fabric-title-group">
      <span class="flagship-kicker">Connections</span>
      <h2>{label}</h2>
      <p data-flagship-summary>Checking local connection health…</p>
    </div>
    <div class="flagship-fabric-tools">
      {fix_control}
      <span class="flagship-readonly">Read-only</span>
      {filter_control}
      {collapse_control}
      <span class="flagship-recovery-status" role="status" aria-live="polite" data-flagship-recovery-status></span>
    </div>
  </div>
  <div class="flagship-fabric-body" id="{body_id}" data-flagship-body>
    <section class="flagship-recovery-results" data-flagship-recovery-results
      aria-label="Capability connection results" hidden></section>
    <div class="flagship-rail" aria-label="Capability evidence rail">
      <span>Owner</span><span>Capability</span><span>State</span><span>Authority</span><span>Resource</span><span>Evidence</span><span>Freshness</span>
    </div>
    <div class="flagship-card-grid" data-flagship-cards aria-live="polite">
      <div class="flagship-empty">Waiting for the local capability snapshot.</div>
    </div>
  </div>
</section>'''


def capability_mounts() -> Dict[str, str]:
    """Return mounts keyed by their unchanged top-level destination."""

    return {tab: capability_mount_html(tab) for tab in CAPABILITY_TABS}


def combined_mount_html(tabs: Iterable[str] = CAPABILITY_TABS) -> str:
    """Return stable mounts in the founder-approved top-level order."""

    requested = set(tabs)
    return "\n".join(
        capability_mount_html(tab)
        for tab in CURRENT_TOP_LEVEL_ORDER
        if tab in requested and tab in CAPABILITY_TABS
    )


CAPABILITY_UI_CSS = r'''
.flagship-fabric{--fs-ink:#1d1d1f;--fs-muted:#6e6e73;--fs-line:#d5d5d7;--fs-blue:#0a6fd8;--fs-green:#287a3b;--fs-amber:#9a5a00;--fs-red:#b42338;flex:none;margin:10px 12px 12px;border:1px solid var(--fs-line);border-radius:12px;background:linear-gradient(180deg,#fff 0%,#fbfbfc 100%);box-shadow:0 1px 1px rgba(0,0,0,.03);color:var(--fs-ink);overflow:hidden}
.feature-scroll>.flagship-fabric{margin:12px 0 0}
.flagship-fabric-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;padding:12px 13px 10px}
.flagship-fabric-title-group{min-width:0}.flagship-kicker{display:block;color:#6d5ea8;font-size:8px;font-weight:750;letter-spacing:.085em;text-transform:uppercase}.flagship-fabric h2{margin:2px 0 0;font-size:14px;line-height:1.2;font-weight:680;letter-spacing:-.01em}.flagship-fabric-title-group p{margin:3px 0 0;color:var(--fs-muted);font-size:9px;line-height:1.35}
.flagship-fabric-tools{display:flex;align-items:center;gap:7px;flex:none;flex-wrap:wrap;justify-content:flex-end}.flagship-readonly{border:1px solid #bcd6be;border-radius:999px;background:#f0f8f0;color:#2c6936;padding:3px 7px;font-size:8px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}.flagship-fix-all,.flagship-collapse{border:1px solid #9fbfe0;border-radius:7px;background:linear-gradient(#f7fbff,#eaf4ff);padding:5px 8px;color:#075da9;font:700 8px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer;white-space:nowrap}.flagship-collapse{border-color:#c3c3c6;background:linear-gradient(#fff,#f3f3f4);color:#3d3d42}.flagship-fix-all:hover,.flagship-collapse:hover{background:#fff}.flagship-fix-all:disabled{cursor:default;opacity:.58}.flagship-fix-all:focus-visible,.flagship-collapse:focus-visible{outline:2px solid rgba(10,111,216,.38);outline-offset:1px}.flagship-recovery-status{flex-basis:100%;min-height:9px;color:#66666b;font-size:7px;line-height:1.25;text-align:right}.flagship-recovery-status:empty{display:none}.flagship-filter-label input{width:148px;border:1px solid #c7c7c9;border-radius:7px;background:#fff;padding:5px 7px;color:var(--fs-ink);font:9px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;outline:none}.flagship-filter-label input:focus{border-color:#1683e6;box-shadow:0 0 0 3px rgba(10,111,216,.12)}
.flagship-fabric-body[hidden]{display:none}.flagship-fabric.is-collapsed .flagship-fabric-head{align-items:center;padding-bottom:12px}.flagship-fabric.is-collapsed .flagship-fix-all,.flagship-fabric.is-collapsed .flagship-filter-label,.flagship-fabric.is-collapsed .flagship-recovery-status{display:none}
.flagship-recovery-results{border-top:1px solid #e3e3e6;background:#f8fbff;padding:7px 9px}.flagship-recovery-results[hidden]{display:none}.flagship-result-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:5px}.flagship-result-head strong{font-size:8px}.flagship-result-head span{color:#68717b;font-size:7px}.flagship-result-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px}.flagship-result{display:grid;grid-template-columns:auto minmax(0,1fr);align-items:start;gap:6px;border:1px solid #dde5ed;border-radius:6px;background:#fff;padding:5px 6px;min-width:0}.flagship-result-badge{border-radius:999px;padding:2px 5px;background:#eceef1;color:#50555b;font-size:6px;font-weight:780;letter-spacing:.025em;text-transform:uppercase;white-space:nowrap}.flagship-result-applied .flagship-result-badge,.flagship-result-already-healthy .flagship-result-badge{background:#e8f6e4;color:#287236}.flagship-result-manual .flagship-result-badge{background:#fff2dd;color:#8f5200}.flagship-result-unavailable .flagship-result-badge,.flagship-result-failed .flagship-result-badge{background:#fde7ea;color:#a52335}.flagship-result-copy{min-width:0}.flagship-result-copy strong,.flagship-result-copy span{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.flagship-result-copy strong{font-size:7px}.flagship-result-copy span{margin-top:1px;color:#69696e;font-size:6px}
.flagship-rail{display:grid;grid-template-columns:.85fr 1.2fr .72fr .9fr .8fr .8fr .72fr;gap:7px;border-top:1px solid #e8e8ea;border-bottom:1px solid #e2e2e4;background:#f5f5f7;padding:6px 13px;color:#737378;font-size:7px;font-weight:700;letter-spacing:.055em;text-transform:uppercase}
.flagship-card-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;padding:9px}.flagship-card{position:relative;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;border:1px solid #d9d9dc;border-radius:9px;background:#fff;padding:9px;min-width:0}.flagship-card:focus-within{border-color:#9ec8ef}.flagship-card-power{border-color:#c8bde6;background:linear-gradient(145deg,#fff 0%,#fbf9ff 100%)}
.flagship-card-copy{min-width:0}.flagship-card-id{color:#77717f;font:700 8px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.025em}.flagship-card-name{margin-top:2px;font-size:11px;font-weight:670;line-height:1.24}.flagship-card-detail{margin-top:4px;color:#66666b;font-size:8px;line-height:1.38;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}.flagship-card-owner{margin-top:5px;color:#777;font-size:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.flagship-card-side{display:flex;flex-direction:column;align-items:flex-end;gap:5px;min-width:78px}.flagship-state{display:inline-flex;align-items:center;border-radius:999px;padding:3px 7px;font-size:7px;font-weight:780;letter-spacing:.035em;text-transform:uppercase;white-space:nowrap}.flagship-state-working{background:#e8f6e4;color:#287236}.flagship-state-degraded,.flagship-state-stale,.flagship-state-setup-required{background:#fff2dd;color:#8f5200}.flagship-state-repairable{background:#e8f2ff;color:#075da9}.flagship-state-blocked,.flagship-state-unavailable{background:#fde7ea;color:#a52335}.flagship-state-not-connected{background:#eeeef0;color:#66666b}
.flagship-inspect,.flagship-fix-one{border:1px solid #c3c3c6;border-radius:6px;background:linear-gradient(#fff,#f3f3f4);padding:4px 7px;color:#333;font:650 8px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;cursor:pointer}.flagship-fix-one{border-color:#9fbfe0;background:#eef6ff;color:#075da9}.flagship-inspect:hover,.flagship-fix-one:hover{background:#fff;border-color:#9e9ea2}.flagship-inspect:focus-visible,.flagship-fix-one:focus-visible{outline:2px solid rgba(10,111,216,.38);outline-offset:1px}
.flagship-card-meta{grid-column:1/-1;display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:5px;border-top:1px solid #ececef;padding-top:6px}.flagship-meta{min-width:0}.flagship-meta span{display:block;color:#85858a;font-size:6px;font-weight:720;letter-spacing:.055em;text-transform:uppercase}.flagship-meta strong{display:block;margin-top:1px;color:#4a4a4f;font-size:7px;font-weight:620;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.flagship-card-expanded .flagship-card-detail{-webkit-line-clamp:unset}.flagship-card-expanded .flagship-card-meta{grid-template-columns:repeat(2,minmax(0,1fr))}
.flagship-empty{grid-column:1/-1;border:1px dashed #c7c7ca;border-radius:8px;background:#fafafa;padding:14px;color:#777;font-size:9px;text-align:center}.flagship-sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:820px){.flagship-fabric-head{flex-direction:column}.flagship-fabric-tools{width:100%;justify-content:space-between}.flagship-fabric.is-collapsed .flagship-fabric-head{flex-direction:row}.flagship-fabric.is-collapsed .flagship-fabric-tools{width:auto}.flagship-filter-label input{width:190px}.flagship-rail{display:none}.flagship-card-grid{grid-template-columns:1fr}.flagship-card-meta{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:560px){.flagship-result-grid{grid-template-columns:1fr}.flagship-fabric.is-collapsed .flagship-readonly{display:none}}
.flagship-fabric{border-color:#d8dde4;border-radius:13px;background:#fff;box-shadow:0 8px 25px rgba(29,45,64,.055)}
.flagship-fabric-head{align-items:center;padding:12px 14px}
.flagship-kicker{color:#557087;font-size:10px;letter-spacing:.07em}
.flagship-fabric h2{font-size:15px}.flagship-fabric-title-group p{font-size:10px}
.flagship-fabric-tools{gap:8px}.flagship-readonly,.flagship-fix-all,.flagship-collapse,.flagship-recovery-status,.flagship-filter-label input{font-size:10px}
.flagship-fix-all{min-height:30px;border-color:#0a6fd8;border-radius:8px;background:linear-gradient(180deg,#1684e9,#0868c5);color:#fff;padding:6px 11px;box-shadow:0 4px 12px rgba(10,111,216,.16)}
.flagship-fix-all:hover{background:#0868c5}.flagship-collapse{min-height:30px;border-radius:8px;padding:6px 10px}
.flagship-filter-label input{min-height:30px;width:170px}.flagship-readonly{padding:4px 8px}
.flagship-rail{display:none}
.flagship-card-grid{grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:9px;padding:10px;border-top:1px solid #e7eaee}
.flagship-card{border-color:#dde2e7;border-radius:10px;padding:10px;box-shadow:0 3px 12px rgba(28,44,64,.035)}
.flagship-card-id,.flagship-card-detail,.flagship-card-owner,.flagship-state,.flagship-inspect,.flagship-fix-one,.flagship-meta span,.flagship-meta strong,.flagship-empty{font-size:10px}
.flagship-card-name{font-size:12px}.flagship-card-detail{line-height:1.45}.flagship-card-owner{margin-top:6px}
.flagship-inspect,.flagship-fix-one{min-height:28px;border-radius:7px;padding:5px 8px}.flagship-fix-one{border-color:#8eb8e1;background:#edf6ff}
.flagship-card-meta{display:none}.flagship-card-expanded .flagship-card-meta{display:grid}
.flagship-result-head strong,.flagship-result-head span,.flagship-result-badge,.flagship-result-copy strong,.flagship-result-copy span{font-size:10px}
.flagship-recovery-results{padding:9px 10px}.flagship-result{padding:7px 8px}
.flagship-result-ledger{margin-top:2px}.flagship-result-ledger-summary{width:max-content;color:#0a67ba;font-size:10px;font-weight:680;cursor:pointer;list-style:none}.flagship-result-ledger-summary::-webkit-details-marker{display:none}.flagship-result-ledger-summary:after{content:'  ›'}.flagship-result-ledger[open] .flagship-result-ledger-summary:after{content:'  ⌄'}.flagship-result-ledger .flagship-result-grid{margin-top:7px}
.flagship-card-diagnostic{grid-column:1/-1;min-width:0;border-top:1px solid #eceff2;padding-top:7px}.flagship-card-diagnostic span{display:block;color:#85858a;font-size:10px;font-weight:720;letter-spacing:.055em;text-transform:uppercase}.flagship-card-diagnostic strong{display:block;margin-top:3px;color:#555b62;font-size:10px;font-weight:520;line-height:1.45;white-space:normal}
.flagship-result-copy strong,.flagship-result-copy span{white-space:normal}.flagship-result-state-working .flagship-result-badge{background:#e8f6e4;color:#287236}.flagship-result-state-degraded .flagship-result-badge,.flagship-result-state-stale .flagship-result-badge,.flagship-result-state-setup-required .flagship-result-badge{background:#fff2dd;color:#8f5200}.flagship-result-state-repairable .flagship-result-badge{background:#e8f2ff;color:#075da9}.flagship-result-state-blocked .flagship-result-badge,.flagship-result-state-unavailable .flagship-result-badge,.flagship-result-state-not-connected .flagship-result-badge{background:#fde7ea;color:#a52335}
.flagship-fabric.is-collapsed .flagship-fabric-title-group p{margin-top:2px}.flagship-fabric.is-collapsed{box-shadow:0 3px 12px rgba(29,45,64,.04)}
'''.strip()


CAPABILITY_UI_JS = r'''
(function(){
  'use strict';
  const EXPECTED_ORDER = ['cpu','memory','energy','disk','network','agents','brain','dispatch','guard'];
  const EXPECTED_IDS = new Set(['C01','C02','C03','C04','C09','C10','C11','C12','C13','C17','C18','C19','C24','C25','C26','C27','C28','C30','C31','C32','C33','C36','C39','C40','C41','C42','C43','C44','C48','C63','C64']);
  const ALLOWED_STATES = new Set(['working','degraded','stale','blocked','unavailable','repairable','setup-required','not-connected']);
  const ALLOWED_OUTCOMES = new Set(['applied','already-healthy','manual','unavailable','failed']);
  const DISPLAY_NAMES = new Map([
    ['C25','Brain access'],
    ['C26','Conversation context'],
    ['C27','Project context'],
    ['C30','Source history'],
    ['C31','Privacy checks'],
  ]);
  const COLLAPSE_STORAGE_KEY = 'ke.activity-monitor.flagship-fabric.collapsed.v1';
  const text = value => String(value == null ? '' : value);
  const compact = (value, fallback = 'Not published') => {
    const result = text(value).trim();
    return result || fallback;
  };
  const make = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value != null) node.textContent = text(value);
    return node;
  };
  const collapsedTabs = new Set();
  const writeCollapsedTabs = () => {
    try {
      const value = EXPECTED_ORDER.filter(tab => collapsedTabs.has(tab));
      window.localStorage.setItem(COLLAPSE_STORAGE_KEY,JSON.stringify(value));
    } catch (_) {
      // Preference storage is optional; expanded remains the safe default.
    }
  };
  const mountScroller = mount => mount.closest('.feature-scroll') || mount.parentElement;
  const applyCollapsed = (mount, collapsed, options = {}) => {
    const body = mount.querySelector('[data-flagship-body]');
    const control = mount.querySelector('[data-flagship-collapse]');
    if (!body || !control) return false;
    const next = collapsed === true;
    const scroller = mountScroller(mount);
    if (next && options.captureScroll === true && scroller) {
      mount.__flagshipScrollTop = Number(scroller.scrollTop || 0);
    }
    mount.classList.toggle('is-collapsed',next);
    body.hidden = next;
    control.setAttribute('aria-expanded',String(!next));
    const label = compact(mount.getAttribute('aria-label'),'Capability fabric');
    control.setAttribute('aria-label',(next ? 'Expand ' : 'Minimize ')+label);
    control.textContent = next ? 'Expand' : 'Minimize';
    if (options.persist === true) {
      if (next) collapsedTabs.add(mount.dataset.flagshipTab);
      else collapsedTabs.delete(mount.dataset.flagshipTab);
      writeCollapsedTabs();
    }
    if (!next && options.restoreScroll === true && scroller) {
      const scrollTop = Number(mount.__flagshipScrollTop || 0);
      window.requestAnimationFrame(() => { scroller.scrollTop = scrollTop; });
    }
    return true;
  };
  const bindCollapse = mount => {
    const control = mount.querySelector('[data-flagship-collapse]');
    if (!control || control.__flagshipBound) return;
    control.__flagshipBound = true;
    applyCollapsed(mount,collapsedTabs.has(mount.dataset.flagshipTab));
    control.addEventListener('click',async () => {
      if (control.__flagshipSaving) return;
      control.__flagshipSaving = true;
      const collapsed = !mount.classList.contains('is-collapsed');
      applyCollapsed(mount,collapsed,{
        persist:true,
        captureScroll:collapsed,
        restoreScroll:!collapsed
      });
      try {
        const raw = await pywebview.api.set_flagship_fabric_collapsed(mount.dataset.flagshipTab,collapsed);
        const result = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (!result?.ok || result.schemaVersion !== 'ke.activity-monitor-flagship-preferences.v1') {
          throw new Error('preference-write-failed');
        }
      } catch (_) {
        // Native preference state is authoritative. Failure is safe-expanded.
        applyCollapsed(mount,false,{persist:true,restoreScroll:true});
        try { control.focus({preventScroll:true}); } catch (_) { control.focus(); }
      } finally {
        control.__flagshipSaving = false;
      }
    });
  };
  window.hydrateFlagshipCollapsePreferences = async () => {
    collapsedTabs.clear();
    let result = null;
    try {
      const raw = await pywebview.api.get_flagship_ui_preferences();
      result = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (
        !result?.ok ||
        result.schemaVersion !== 'ke.activity-monitor-flagship-preferences.v1' ||
        !Array.isArray(result.collapsedTabs)
      ) throw new Error('preference-read-failed');
      result.collapsedTabs.filter(tab => EXPECTED_ORDER.includes(tab)).forEach(tab => collapsedTabs.add(tab));
    } catch (_) {
      collapsedTabs.clear();
    }
    writeCollapsedTabs();
    document.querySelectorAll('[data-flagship-tab]').forEach(mount => {
      applyCollapsed(mount,collapsedTabs.has(mount.dataset.flagshipTab));
    });
    return {ok:Boolean(result?.ok),collapsedTabs:Array.from(collapsedTabs)};
  };
  const meta = (label, value) => {
    const box = make('div','flagship-meta');
    box.append(make('span','',label), make('strong','',compact(value)));
    return box;
  };
  const stateLabel = value => text(value).replaceAll('-',' ');
  const publicName = row => DISPLAY_NAMES.get(row && row.id) || compact(row && row.name,'Connection');
  const publicStateLabel = state => ({
    working:'Ready',
    degraded:'Needs attention',
    stale:'Needs refresh',
    blocked:'Blocked',
    unavailable:'Unavailable',
    repairable:'Can fix',
    'setup-required':'Setup needed',
    'not-connected':'Not connected',
  }[state] || 'Check needed');
  const publicStateDetail = state => ({
    working:'Ready with current local evidence.',
    degraded:'Connected locally; some supporting evidence still needs attention.',
    stale:'Connected, but the latest evidence needs a refresh.',
    blocked:'A required local owner is currently blocked.',
    unavailable:'The current local source is unavailable.',
    repairable:'A safe local connection can be restored.',
    'setup-required':'Needs your setup before it can connect.',
    'not-connected':'No current local connection.',
  }[state] || 'Current status needs a fresh check.');
  const evidenceSummary = row => {
    const evidence = row && row.evidence || {};
    const missing = Array.isArray(evidence.missingSources) ? evidence.missingSources.length : 0;
    return missing ? compact(evidence.level,'recorded')+' · '+missing+' missing' : compact(evidence.level,'recorded');
  };
  const resourceSummary = row => {
    const resource = row && row.resource || {};
    const summaries = Array.isArray(resource.summaries) ? resource.summaries : [];
    return summaries.length ? summaries[0] : compact(resource.state,'not published');
  };
  const authoritySummary = row => {
    const authority = row && row.authority || {};
    const mode = compact(authority.interaction,'observe');
    return authority.inheritedFromVisibility ? 'invalid inherited authority' : mode;
  };
  const renderCard = (row, mount) => {
    const id = compact(row && row.id,'Unknown');
    const state = ALLOWED_STATES.has(row && row.state) ? row.state : 'unavailable';
    const staticReadOnly = row && row.placement && row.placement.tab === 'guard';
    const expandedIds = mount.__flagshipExpanded || (mount.__flagshipExpanded = new Set());
    const expanded = !staticReadOnly && expandedIds.has(id);
    const card = make('article','flagship-card'+(id === 'C33' ? ' flagship-card-power' : '')+(expanded ? ' flagship-card-expanded' : ''));
    card.dataset.capabilityId = id;
    card.dataset.state = state;
    const copy = make('div','flagship-card-copy');
    copy.append(
      make('div','flagship-card-name',publicName(row)),
      make('div','flagship-card-detail',publicStateDetail(state))
    );
    const side = make('div','flagship-card-side');
    side.append(make('span','flagship-state flagship-state-'+state,publicStateLabel(state)));
    const recovery = row && row.recovery || {};
    if (recovery.canAttempt === true && !staticReadOnly) {
      const fix = make('button','flagship-fix-one',compact(recovery.label,'Fix connection'));
      fix.type = 'button';
      fix.addEventListener('click', () => {
        document.dispatchEvent(new CustomEvent('ke:capability-repair',{detail:{
          capabilityId:id,
          tab:compact(row && row.placement && row.placement.tab),
          expectedGeneration:Number(recovery.generation),
          restoreFocus:document.activeElement === fix
        }}));
      });
      side.append(fix);
    } else if (!staticReadOnly) {
      const inspect = make('button','flagship-inspect',id === 'C33' ? 'Open in Agents' : 'Inspect');
      inspect.type = 'button';
      inspect.setAttribute('aria-expanded',String(expanded));
      inspect.addEventListener('click', () => {
        const next = !card.classList.contains('flagship-card-expanded');
        card.classList.toggle('flagship-card-expanded',next);
        if (next) expandedIds.add(id); else expandedIds.delete(id);
        inspect.setAttribute('aria-expanded',String(next));
        document.dispatchEvent(new CustomEvent('ke:capability-inspect',{detail:{capabilityId:id,tab:compact(row && row.placement && row.placement.tab)}}));
      });
      side.append(inspect);
    }
    const details = make('div','flagship-card-meta');
    details.append(
      meta('Reference',id),
      meta('Area',compact(row && row.placement && row.placement.section,'Capability')),
      meta('Capability',compact(row && row.name,'Connection')),
      meta('Owner',compact(row && row.owner,'Unassigned')),
      meta('Authority',authoritySummary(row)),
      meta('Resource',resourceSummary(row)),
      meta('Evidence',evidenceSummary(row)),
      meta('Freshness',compact(row && row.freshness && row.freshness.state,'unknown'))
    );
    const diagnostic = make('div','flagship-card-diagnostic');
    diagnostic.append(
      make('span','', 'Details'),
      make('strong','',compact(row && row.detail,row && row.emptyState || 'No current owner evidence.'))
    );
    details.append(diagnostic);
    card.append(copy,side);
    if (!staticReadOnly) card.append(details);
    return card;
  };
  const summarize = rows => {
    const working = rows.filter(row => row.state === 'working').length;
    const attention = rows.filter(row => ['degraded','stale','blocked','unavailable'].includes(row.state)).length;
    const repairable = rows.filter(row => row.state === 'repairable').length;
    const setup = rows.filter(row => row.state === 'setup-required').length;
    const disconnected = rows.filter(row => row.state === 'not-connected').length;
    const parts = [rows.length+' connection'+(rows.length === 1 ? '' : 's'),working+' ready'];
    if (repairable) parts.push(repairable+' can fix');
    if (setup) parts.push(setup+' need setup');
    if (attention) parts.push(attention+' need attention');
    if (disconnected) parts.push(disconnected+' not connected');
    return parts.join(' · ');
  };
  const paintMount = (mount, rows, recovery = {}) => {
    const cards = mount.querySelector('[data-flagship-cards]');
    const summary = mount.querySelector('[data-flagship-summary]');
    const query = text(mount.querySelector('[data-flagship-filter]')?.value).trim().toLowerCase();
    const filtered = rows.filter(row => !query || [row.id,row.name,row.owner,row.detail,row.placement && row.placement.section].some(value => text(value).toLowerCase().includes(query)));
    cards.replaceChildren();
    if (!filtered.length) cards.append(make('div','flagship-empty',rows.length ? 'No capability matches this filter.' : 'No capability is assigned to this destination.'));
    else filtered.forEach(row => cards.append(renderCard(row,mount)));
    summary.textContent = summarize(rows);
    const fixAll = mount.querySelector('[data-flagship-fix-all]');
    if (fixAll) {
      const count = rows.filter(row => row && row.recovery && row.recovery.canAttempt === true).length;
      fixAll.textContent = count ? 'Auto Fix '+count : 'Auto Fix';
      fixAll.dataset.generation = text(recovery.generation);
      fixAll.setAttribute('aria-label',count ? 'Auto Fix '+count+' safe local capability connections' : 'Auto Fix safe local capability connections');
      if (!fixAll.__flagshipBound) {
        fixAll.__flagshipBound = true;
        fixAll.addEventListener('click',() => {
          document.dispatchEvent(new CustomEvent('ke:capability-repair',{detail:{
            capabilityId:null,
            tab:mount.dataset.flagshipTab,
            expectedGeneration:Number(fixAll.dataset.generation)
          }}));
        });
      }
    }
  };
  window.restoreFlagshipCapabilityFocus = (tab, capabilityId) => {
    const mount = document.querySelector(`[data-flagship-tab="${text(tab)}"]`);
    if (!mount) return false;
    const card = Array.from(mount.querySelectorAll('.flagship-card[data-capability-id]')).find(
      node => node.dataset.capabilityId === text(capabilityId)
    );
    const target = card?.querySelector('.flagship-fix-one,.flagship-inspect') ||
      mount.querySelector('[data-flagship-collapse]');
    if (!target || typeof target.focus !== 'function') return false;
    try { target.focus({preventScroll:true}); } catch (_) { target.focus(); }
    return document.activeElement === target;
  };
  window.renderFlagshipRecoveryResults = (tab, result, options = {}) => {
    const mount = document.querySelector(`[data-flagship-tab="${text(tab)}"]`);
    const region = mount?.querySelector('[data-flagship-recovery-results]');
    if (!mount || !region) return {rendered:0};
    const allowedIds = new Set((mount.__flagshipRows || []).map(row => row && row.id));
    const validEnvelope = result?.outcomeSchemaVersion === 'ke.activity-monitor-flagship-repair-outcomes.v1' && result?.outcomesBounded === true;
    const outcomes = (validEnvelope && Array.isArray(result?.outcomes) ? result.outcomes : []).filter(item =>
      item && allowedIds.has(item.capabilityId) && ALLOWED_OUTCOMES.has(item.outcome) && item.noSideEffects === true
    );
    region.replaceChildren();
    if (!outcomes.length) {
      region.hidden = true;
      return {rendered:0};
    }
    const currentById = new Map((mount.__flagshipRows || []).map(row => [row && row.id,row]));
    const rechecking = options.rechecking === true;
    const finalStates = outcomes.map(item => currentById.get(item.capabilityId)?.state || 'unavailable');
    const finalCounts = {
      ready: finalStates.filter(state => state === 'working').length,
      attention: finalStates.filter(state => ['degraded','stale','blocked','unavailable'].includes(state)).length,
      fixable: finalStates.filter(state => state === 'repairable').length,
      setup: finalStates.filter(state => ['setup-required','not-connected'].includes(state)).length,
    };
    const head = make('div','flagship-result-head');
    head.append(
      make('strong','',rechecking ? 'Rechecking current status' : 'Connection check complete'),
      make('span','',rechecking ? 'Updates recorded · waiting for fresh evidence' : [
        finalCounts.ready ? finalCounts.ready+' ready' : '',
        finalCounts.attention ? finalCounts.attention+' need attention' : '',
        finalCounts.fixable ? finalCounts.fixable+' can retry' : '',
        finalCounts.setup ? finalCounts.setup+' need setup' : ''
      ].filter(Boolean).join(' · '))
    );
    const grid = make('div','flagship-result-grid');
    outcomes.forEach(item => {
      const current = currentById.get(item.capabilityId) || {};
      const currentState = current.state || 'unavailable';
      const badgeLabel = rechecking ? 'Rechecking' : publicStateLabel(currentState);
      const detail = rechecking
        ? 'The safe local update finished. Fresh evidence is being checked now.'
        : item.outcome === 'already-healthy'
          ? publicStateDetail(currentState)
          : item.outcome === 'applied' && currentState === 'working'
            ? 'The local connection is restored and ready.'
            : item.outcome === 'applied'
              ? publicStateDetail(currentState)
              : item.outcome === 'manual'
                ? 'This connection needs a manual setup step.'
                : 'The current local connection could not be restored.';
      const row = make('div','flagship-result flagship-result-'+item.outcome+' flagship-result-state-'+currentState);
      row.dataset.capabilityId = item.capabilityId;
      row.dataset.outcome = item.outcome;
      row.dataset.finalState = currentState;
      const badge = make('span','flagship-result-badge',badgeLabel);
      const copy = make('span','flagship-result-copy');
      copy.append(
        make('strong','',publicName({...current,id:item.capabilityId,name:item.name})),
        make('span','',detail)
      );
      row.append(badge,copy);
      grid.append(row);
    });
    const ledger = make('details','flagship-result-ledger');
    const ledgerSummary = make('summary','flagship-result-ledger-summary','View '+outcomes.length+' result'+(outcomes.length === 1 ? '' : 's'));
    ledger.append(ledgerSummary,grid);
    region.append(head,ledger);
    region.hidden = false;
    const statusMessage = rechecking
      ? 'Updates recorded. Rechecking current status…'
      : [
          finalCounts.ready ? finalCounts.ready+' ready' : '',
          finalCounts.attention ? finalCounts.attention+' need attention' : '',
          finalCounts.fixable ? finalCounts.fixable+' can retry' : '',
          finalCounts.setup ? finalCounts.setup+' need setup' : '',
        ].filter(Boolean).join(' · ') || 'Current connection status is available.';
    return {rendered:outcomes.length,finalCounts,statusMessage,rechecking};
  };
  const validSnapshot = snapshot => {
    if (!snapshot || snapshot.readOnly !== true || snapshot.preservesCurrentOrder !== true) return false;
    if (!snapshot.recovery || snapshot.recovery.noIORepair !== true || snapshot.recovery.generationBound !== true) return false;
    if (!Number.isInteger(snapshot.recovery.generation) || snapshot.recovery.generation < 1) return false;
    if (!Array.isArray(snapshot.topLevelOrder) || snapshot.topLevelOrder.length !== EXPECTED_ORDER.length) return false;
    if (!snapshot.topLevelOrder.every((value,index) => value === EXPECTED_ORDER[index])) return false;
    if (!Array.isArray(snapshot.capabilities) || snapshot.capabilities.length !== EXPECTED_IDS.size) return false;
    const seen = new Set();
    for (const row of snapshot.capabilities) {
      if (!row || !EXPECTED_IDS.has(row.id) || seen.has(row.id)) return false;
      if (!row.placement || !EXPECTED_ORDER.includes(row.placement.tab) || !ALLOWED_STATES.has(row.state)) return false;
      if (row.authority && row.authority.inheritedFromVisibility === true) return false;
      if (!row.recovery || row.recovery.noSideEffects !== true || row.recovery.generation !== snapshot.recovery.generation) return false;
      if (row.recovery.canAttempt === true && row.recovery.mode !== 'safe-local-binding') return false;
      seen.add(row.id);
    }
    return seen.size === EXPECTED_IDS.size;
  };
  window.renderFlagshipCapabilities = snapshot => {
    if (!validSnapshot(snapshot)) throw new Error('Flagship capability snapshot failed its read-only/order boundary');
    document.querySelectorAll('[data-flagship-tab]').forEach(mount => {
      bindCollapse(mount);
      const tab = mount.dataset.flagshipTab;
      const rows = snapshot.capabilities.filter(row => row && row.placement && row.placement.tab === tab);
      mount.__flagshipRows = rows;
      mount.__flagshipRecovery = snapshot.recovery;
      paintMount(mount,rows,snapshot.recovery);
      const filter = mount.querySelector('[data-flagship-filter]');
      if (filter && !filter.__flagshipBound) {
        filter.__flagshipBound = true;
        filter.addEventListener('input',() => paintMount(mount,mount.__flagshipRows || [],mount.__flagshipRecovery || {}));
      }
    });
    return {rendered:snapshot.capabilities.length,readOnly:true,preservesCurrentOrder:true};
  };
})();
'''.strip()


__all__ = [
    "CAPABILITY_TABS",
    "CAPABILITY_UI_CSS",
    "CAPABILITY_UI_JS",
    "SCHEMA_VERSION",
    "capability_mount_html",
    "capability_mounts",
    "combined_mount_html",
]
