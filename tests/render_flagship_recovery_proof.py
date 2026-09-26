"""Render deterministic 960x680 source proof for safe Capability Fabric recovery."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys

from playwright.async_api import async_playwright


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from activity_monitor import FLAGSHIP_BRIDGE_JS  # noqa: E402
from flagship_bridge import FlagshipBridge  # noqa: E402
from flagship_ui import CAPABILITY_UI_CSS, CAPABILITY_UI_JS, capability_mount_html  # noqa: E402


class _Service:
    def __init__(self, payload: dict):
        self.payload = payload

    def scan(self, force: bool = False) -> dict:
        return dict(self.payload)

    def state(self) -> dict:
        return dict(self.payload)

    def status(self) -> dict:
        return dict(self.payload)

    def snapshot(self) -> dict:
        return dict(self.payload)


def _fixture() -> tuple[dict, dict, dict]:
    brain = _Service({
        "ok": True,
        "state": "available",
        "generatedAt": "2026-08-24T14:00:00Z",
        "summary": {"connected": 22, "projectChildren": 14},
        "scan": {"settingsTrusted": True},
        "privacy": {
            "noteBodiesRead": False,
            "uploads": False,
            "credentialsUsed": False,
        },
    })
    dispatch = _Service({
        "ok": True,
        "state": "available",
        "readiness": {
            "codexExactTask": True,
            "codexDesktopOwnerIpc": True,
            "claudeExactSession": True,
            "historyAvailable": True,
            "dispatchSendAllowed": True,
        },
    })
    guard = _Service({
        "ok": True,
        "state": "armed",
        "observedAt": "2026-08-24T14:00:00Z",
        "ledgerAvailable": True,
        "recentEvidence": [{"event": "bounded"}],
    })
    company = _Service({
        "ok": True,
        "state": "partial",
        "observedAt": "2026-08-24T14:00:00Z",
        "summary": {"agents": 4, "teams": 2, "crewContracts": 0},
    })
    board = _Service({
        "ok": True,
        "state": "available",
        "observedAt": "2026-08-24T14:00:00Z",
        "counts": {"activeOwners": 20, "open": 11, "needsHuman": 5},
    })
    workspace = _Service({
        "ok": True,
        "state": "available",
        "observedAt": "2026-08-24T14:00:00Z",
        "counts": {"projectBrains": 14, "activeProjectBrains": 14},
        "companions": {
            "codex": {"cliInstalled": True, "appInstalled": True},
            "claude": {"installed": True},
        },
    })
    bridge = FlagshipBridge(
        brain_service=brain,
        dispatch_service=dispatch,
        guard_service=guard,
        company_discovery=company,
        board_discovery=board,
        providers={"workspace": workspace.snapshot},
        auto_heal=False,
    )
    before = bridge.snapshot("brain")
    per_capability = bridge.repair(
        "brain", "C26", before["recovery"]["generation"]
    )
    repaired = bridge.repair("brain", None, per_capability["generation"])
    if not per_capability.get("ok") or per_capability.get("repaired") != 1:
        raise RuntimeError("fixture per-capability recovery did not repair exactly one binding")
    if not repaired.get("ok") or repaired.get("repaired") != 3:
        raise RuntimeError("fixture Fix All recovery did not repair the remaining three bindings")
    return before, per_capability, repaired


async def _render(output_dir: Path) -> dict:
    before, per_capability, repaired = _fixture()
    output_dir.mkdir(parents=True, exist_ok=True)
    expanded_screenshot = output_dir / "capability-fabric-expanded-960x680.png"
    minimized_screenshot = output_dir / "capability-fabric-minimized-960x680.png"
    narrow_screenshot = output_dir / "capability-fabric-expanded-560x680.png"
    html_path = output_dir / "capability-fabric-proof.html"
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><style>
*{{box-sizing:border-box}}html,body{{width:100vw;height:100vh;margin:0;overflow:hidden;background:#ececef;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif}}
.proof-shell{{height:100vh;padding:18px 14px;overflow:auto;background:linear-gradient(#ececef,#e5e5e8)}}
{CAPABILITY_UI_CSS}
</style></head><body><main class="proof-shell">
{capability_mount_html('brain')}
</main><script>
const currentTab = 'brain';
const apiReady = true;
const bridgeJson = value => typeof value === 'string' ? JSON.parse(value) : value;
let fixtureSnapshot = {json.dumps(before)};
window.pywebview = {{api:{{
  get_flagship_capabilities: async () => JSON.stringify(fixtureSnapshot),
  get_flagship_ui_preferences: async () => {{
    let tabs = [];
    const raw = window.localStorage.getItem('fixture.native.flagship.collapsed');
    if (raw != null) tabs = JSON.parse(raw);
    return JSON.stringify({{ok:true,schemaVersion:'ke.activity-monitor-flagship-preferences.v1',collapsedTabs:tabs}});
  }},
  set_flagship_fabric_collapsed: async (tab, collapsed) => {{
    let tabs = [];
    try {{ tabs = JSON.parse(window.localStorage.getItem('fixture.native.flagship.collapsed') || '[]'); }} catch (_) {{ tabs = []; }}
    tabs = Array.isArray(tabs) ? tabs.filter(value => value !== tab) : [];
    if (collapsed) tabs.push(tab);
    window.localStorage.setItem('fixture.native.flagship.collapsed',JSON.stringify(tabs));
    return JSON.stringify({{ok:true,schemaVersion:'ke.activity-monitor-flagship-preferences.v1',collapsedTabs:tabs}});
  }},
  repair_flagship_capabilities: async (_tab, capabilityId) => {{
    const result = capabilityId ? {json.dumps(per_capability)} : {json.dumps(repaired)};
    fixtureSnapshot = result.snapshot;
    return JSON.stringify(result);
  }}
}}}};
{CAPABILITY_UI_JS}
{FLAGSHIP_BRIDGE_JS}
window.fixtureReady = window.hydrateFlagshipCollapsePreferences().then(() => window.renderFlagshipCapabilities({json.dumps(before)}));
</script></body></html>"""
    html_path.write_text(html, encoding="utf-8")

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            executable_path="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        )
        page = await browser.new_page(
            viewport={"width": 960, "height": 680},
            device_scale_factor=1,
        )
        await page.goto(html_path.as_uri(), wait_until="load")
        await page.evaluate("window.fixtureReady")
        region = page.get_by_role("region", name="AI Brain connections")
        if await region.count() != 1:
            raise RuntimeError("named AI Brain region is missing")

        per_card = page.locator('.flagship-card[data-capability-id="C26"] .flagship-fix-one')
        if await per_card.count() != 1:
            raise RuntimeError("per-capability safe recovery control is missing")
        await per_card.focus()
        await per_card.press("Enter")
        await page.get_by_role("status").filter(has_text="need attention").wait_for()
        per_card_focus_restored = await page.evaluate("""() => {
          const card = document.querySelector('.flagship-card[data-capability-id="C26"]');
          return Boolean(card && card.contains(document.activeElement) && document.activeElement.classList.contains('flagship-inspect'));
        }""")
        per_card_ledger = await page.evaluate("""() => Array.from(
          document.querySelectorAll('[data-flagship-recovery-results] .flagship-result')
        ).map(node => ({id:node.dataset.capabilityId,outcome:node.dataset.outcome}))""")

        button = page.get_by_role("button", name="Auto Fix 3 safe local capability connections")
        if await button.count() != 1:
            raise RuntimeError("one-click safe recovery control is missing")
        await button.focus()
        focused = await page.evaluate(
            "document.activeElement === document.querySelector('[data-flagship-fix-all]')"
        )
        await button.click()
        await page.get_by_role("status").filter(has_text="4 need attention").wait_for()
        cards = page.locator(".flagship-card")
        states = await cards.evaluate_all("nodes => nodes.map(node => node.dataset.state)")
        result_ledger = await page.evaluate("""() => Array.from(
          document.querySelectorAll('[data-flagship-recovery-results] .flagship-result')
        ).map(node => ({id:node.dataset.capabilityId,outcome:node.dataset.outcome,finalState:node.dataset.finalState}))""")
        product_copy = await page.locator('[data-flagship-tab="brain"]').evaluate("node => node.innerText")

        filter_control = page.locator('[data-flagship-filter]')
        await filter_control.fill("Brain")
        inspect = page.locator('.flagship-card[data-capability-id="C26"] .flagship-inspect')
        await inspect.click()
        expanded_card_before = await page.locator('.flagship-card[data-capability-id="C26"]').evaluate(
            "node => node.classList.contains('flagship-card-expanded')"
        )
        collapse = page.get_by_role("button", name="Minimize AI Brain connections")
        await collapse.focus()
        await collapse.click()
        collapsed_metrics = await page.evaluate("""() => {
          const mount = document.querySelector('[data-flagship-tab="brain"]');
          const body = mount.querySelector('[data-flagship-body]');
          const summary = mount.querySelector('[data-flagship-summary]');
          const filter = mount.querySelector('[data-flagship-filter]');
          return {
            collapsed: mount.classList.contains('is-collapsed'),
            bodyHidden: body.hidden,
            summaryVisible: summary.getBoundingClientRect().height > 0,
            filterVisible: filter.getBoundingClientRect().height > 0,
            ariaExpanded: mount.querySelector('[data-flagship-collapse]').getAttribute('aria-expanded'),
            height: mount.getBoundingClientRect().height
          };
        }""")
        await page.screenshot(path=str(minimized_screenshot))

        await page.evaluate(
            "snapshot => window.renderFlagshipCapabilities(snapshot)",
            repaired["snapshot"],
        )
        refresh_kept_collapsed = await page.evaluate("""() => {
          const mount = document.querySelector('[data-flagship-tab="brain"]');
          return mount.classList.contains('is-collapsed') && mount.querySelector('[data-flagship-body]').hidden;
        }""")
        expand = page.get_by_role("button", name="Expand AI Brain connections")
        await expand.focus()
        await expand.click()
        await page.wait_for_timeout(30)
        restored_metrics = await page.evaluate("""() => ({
          filter:document.querySelector('[data-flagship-filter]').value,
          expandedCard:document.querySelector('.flagship-card[data-capability-id="C26"]').classList.contains('flagship-card-expanded'),
          focusOnToggle:document.activeElement === document.querySelector('[data-flagship-collapse]'),
          collapsed:document.querySelector('[data-flagship-tab="brain"]').classList.contains('is-collapsed')
        })""")
        if restored_metrics["expandedCard"]:
            await inspect.click()
        metrics = await page.evaluate("""() => ({
          width: window.innerWidth,
          height: window.innerHeight,
          scrollWidth: document.documentElement.scrollWidth,
          scrollHeight: document.documentElement.scrollHeight,
          cardCount: document.querySelector('[data-flagship-tab="brain"]').__flagshipRows.length,
          fixButtonCount: document.querySelectorAll('[data-flagship-fix-all]').length,
          liveRegionCount: document.querySelectorAll('[role="status"][aria-live="polite"]').length,
          notConnectedCount: Array.from(document.querySelectorAll('.flagship-state')).filter(node => node.textContent.trim() === 'not connected').length,
          recoveryStatus: document.querySelector('[data-flagship-recovery-status]').textContent.trim()
        })""")
        visible_text_below_10px = await page.evaluate("""() => Array.from(
          document.querySelectorAll('[data-flagship-tab="brain"] *')
        ).filter(node => {
          const style=getComputedStyle(node); const rect=node.getBoundingClientRect();
          return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0 && node.childElementCount === 0 && node.textContent.trim() && parseFloat(style.fontSize) < 10;
        }).map(node => ({text:node.textContent.trim().slice(0,80),size:getComputedStyle(node).fontSize}))""")
        await page.screenshot(path=str(expanded_screenshot))

        await page.get_by_role("button", name="Minimize AI Brain connections").click()
        stored_preference = await page.evaluate("""() => JSON.parse(
          window.localStorage.getItem('fixture.native.flagship.collapsed') || '[]'
        )""")
        await page.reload(wait_until="load")
        await page.evaluate("window.fixtureReady")
        persisted_after_reload = await page.evaluate("""() => {
          const mount = document.querySelector('[data-flagship-tab="brain"]');
          return mount.classList.contains('is-collapsed') && mount.querySelector('[data-flagship-body]').hidden;
        }""")
        await page.get_by_role("button", name="Expand AI Brain connections").click()
        await page.set_viewport_size({"width": 560, "height": 680})
        await page.screenshot(path=str(narrow_screenshot))
        narrow_metrics = await page.evaluate("""() => ({
          width:window.innerWidth,
          scrollWidth:document.documentElement.scrollWidth,
          mountWidth:document.querySelector('[data-flagship-tab="brain"]').getBoundingClientRect().width
        })""")

        await page.evaluate("""() => window.localStorage.setItem(
          'fixture.native.flagship.collapsed','{"invalid":true}'
        )""")
        await page.reload(wait_until="load")
        await page.evaluate("window.fixtureReady")
        malformed_storage_fails_expanded = await page.evaluate("""() => {
          const mount = document.querySelector('[data-flagship-tab="brain"]');
          return !mount.classList.contains('is-collapsed') && !mount.querySelector('[data-flagship-body]').hidden;
        }""")
        await browser.close()

    if not focused:
        raise RuntimeError("one-click recovery control is not keyboard focusable")
    if not per_card_focus_restored:
        raise RuntimeError("per-capability repair did not restore keyboard focus")
    if per_card_ledger != [{"id": "C26", "outcome": "applied"}]:
        raise RuntimeError("per-capability repair result ledger is not exact")
    if len(result_ledger) != 5:
        raise RuntimeError("Fix All did not render one bounded result per Brain capability")
    if [item["outcome"] for item in result_ledger].count("applied") != 3:
        raise RuntimeError("Fix All applied-result count is not truthful")
    if [item["outcome"] for item in result_ledger].count("already-healthy") != 2:
        raise RuntimeError("Fix All already-current result count is not truthful")
    if any(token in product_copy for token in ("C25", "C26", "C27", "C30", "C31", "Knowledge", "Privacy boundary", "APPLIED", "Rebuilt 3")):
        raise RuntimeError(f"Capability Fabric exposes internal or contradictory primary copy: {product_copy}")
    if [item["finalState"] for item in result_ledger].count("degraded") != 4:
        raise RuntimeError("Fix All result ledger did not reconcile refreshed degraded truth")
    if metrics["width"] != 960 or metrics["height"] != 680:
        raise RuntimeError("proof viewport drifted from 960x680")
    if metrics["scrollWidth"] > 960 or metrics["scrollHeight"] > 680:
        raise RuntimeError("Capability Fabric overflows the 960x680 proof viewport")
    if metrics["cardCount"] != 5 or metrics["fixButtonCount"] != 1:
        raise RuntimeError("Brain capability or recovery-control count is incorrect")
    if metrics["liveRegionCount"] != 1 or metrics["notConnectedCount"] != 0:
        raise RuntimeError("accessibility or truthful connection state failed")
    if visible_text_below_10px:
        raise RuntimeError(f"Capability Fabric has visible text below 10px: {visible_text_below_10px[:4]}")
    if states.count("working") != 1 or states.count("degraded") != 4:
        raise RuntimeError("repaired Brain state mix is incorrect")
    if not expanded_card_before or not restored_metrics["expandedCard"]:
        raise RuntimeError("expanded card state was not restored after Fabric minimization")
    if restored_metrics["filter"] != "Brain" or restored_metrics["collapsed"]:
        raise RuntimeError("Fabric expansion did not restore the exact filter and expanded state")
    if not restored_metrics["focusOnToggle"]:
        raise RuntimeError("Fabric collapse toggle lost keyboard focus")
    if not all((
        collapsed_metrics["collapsed"],
        collapsed_metrics["bodyHidden"],
        collapsed_metrics["summaryVisible"],
        not collapsed_metrics["filterVisible"],
        collapsed_metrics["ariaExpanded"] == "false",
        refresh_kept_collapsed,
        "brain" in stored_preference,
        persisted_after_reload,
        malformed_storage_fails_expanded,
    )):
        raise RuntimeError("Fabric minimized-state or local persistence contract failed")
    if narrow_metrics["width"] != 560 or narrow_metrics["scrollWidth"] > 560:
        raise RuntimeError("Capability Fabric overflows the narrow proof viewport")

    screenshots = {
        "expanded960": expanded_screenshot,
        "minimized960": minimized_screenshot,
        "expanded560": narrow_screenshot,
    }
    report = {
        "ok": True,
        "contract": "ke.activity-monitor-flagship-recovery-source-proof.v2",
        "viewports": ["960x680", "560x680"],
        "sourceOnly": True,
        "installedAppMutated": False,
        "cards": metrics["cardCount"],
        "states": {"working": 1, "degraded": 4, "notConnected": 0},
        "oneClick": {
            "keyboardFocusable": focused,
            "perCapabilityFocusRestored": per_card_focus_restored,
            "singleControl": metrics["fixButtonCount"] == 1,
            "status": metrics["recoveryStatus"],
            "results": result_ledger,
        },
        "collapse": {
            "minimizedHeight": collapsed_metrics["height"],
            "summaryRetained": collapsed_metrics["summaryVisible"],
            "filterRestored": restored_metrics["filter"],
            "cardStateRestored": restored_metrics["expandedCard"],
            "focusRetained": restored_metrics["focusOnToggle"],
            "refreshKeptCollapsed": refresh_kept_collapsed,
            "persistedAcrossReload": persisted_after_reload,
            "malformedStorageFailsExpanded": malformed_storage_fails_expanded,
        },
        "accessibility": {
            "namedRegion": True,
            "politeLiveRegion": metrics["liveRegionCount"] == 1,
            "visibleTextBelow10px": visible_text_below_10px,
        },
        "overflow": {
            "horizontal": metrics["scrollWidth"] > 960,
            "vertical": metrics["scrollHeight"] > 680,
            "narrowHorizontal": narrow_metrics["scrollWidth"] > 560,
        },
        "screenshots": {
            name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for name, path in screenshots.items()
        },
    }
    report_path = output_dir / "capability-autofix-source-proof.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report["report"] = str(report_path)
    report["reportSha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
    return report


def main() -> int:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/activity-monitor-capability-autofix-proof")
    print(json.dumps(asyncio.run(_render(output)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
