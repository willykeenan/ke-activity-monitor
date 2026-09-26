#!/usr/bin/env python3
"""Render deterministic, offline visual proof for the Network workspace."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys

from playwright.async_api import async_playwright


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import activity_monitor  # noqa: E402
import network_fabric  # noqa: E402


NETWORK_FIXTURE = {
    "ok": True,
    "schemaVersion": 1,
    "active": True,
    "counts": {"observed": 6, "online": 4, "recent": 1, "offline": 1, "paired": 1},
    "local": {"interfaces": [{"name": "en0"}, {"name": "en7"}]},
    "coverage": {
        "eligibleSegmentCount": 2,
        "excludedInterfaceCount": 3,
        "limited": False,
        "boundary": "Two directly connected segments are observable. Sleeping, isolated, or firewalled devices may not appear.",
    },
    "scan": {
        "sequence": 8,
        "inProgress": False,
        "lastScanAt": "2026-08-24T20:40:00Z",
        "maxHostsPerScan": 254,
    },
    "errors": [],
    "devices": [
        {
            "id": "fixture-studio-mac",
            "name": "Studio Mac",
            "type": "computer",
            "state": "online",
            "ageSeconds": 1,
            "addresses": ["192.168.1.24"],
            "interface": "en0",
            "latencyMs": 1.8,
            "sources": ["Bonjour", "neighbor", "reachability"],
            "capabilities": ["ping"],
            "services": [{"id": "fixture-https", "name": "Local dashboard", "label": "HTTPS", "scheme": "https", "url": "https://192.168.1.24", "port": 443}],
            "paired": False,
            "remoteReady": False,
        },
        {
            "id": "fixture-router",
            "name": "Gateway",
            "type": "gateway",
            "state": "online",
            "ageSeconds": 2,
            "addresses": ["192.168.1.1"],
            "interface": "en0",
            "latencyMs": 1.2,
            "sources": ["route", "neighbor", "reachability"],
            "capabilities": ["ping"],
            "services": [],
            "paired": False,
            "remoteReady": False,
        },
        {
            "id": "fixture-trusted-mac",
            "name": "Trusted MacBook",
            "type": "computer",
            "state": "recent",
            "ageSeconds": 73,
            "addresses": ["192.168.1.38"],
            "interface": "en0",
            "latencyMs": None,
            "sources": ["neighbor", "KE Link"],
            "capabilities": ["ping", "verify-link", "revoke-peer"],
            "services": [],
            "paired": True,
            "remoteReady": False,
            "linkPeerId": "fixture-peer",
        },
        {
            "id": "fixture-phone",
            "name": "Phone",
            "type": "phone",
            "state": "online",
            "ageSeconds": 4,
            "addresses": ["192.168.1.51"],
            "interface": "en0",
            "latencyMs": None,
            "sources": ["Bonjour", "neighbor"],
            "capabilities": [],
            "services": [],
            "paired": False,
            "remoteReady": False,
        },
        {
            "id": "fixture-printer",
            "name": "Office Printer",
            "type": "printer",
            "state": "online",
            "ageSeconds": 7,
            "addresses": ["192.168.1.70"],
            "interface": "en0",
            "latencyMs": None,
            "sources": ["Bonjour", "SSDP"],
            "capabilities": [],
            "services": [],
            "paired": False,
            "remoteReady": False,
        },
        {
            "id": "fixture-storage",
            "name": "Backup Storage",
            "type": "storage",
            "state": "offline",
            "ageSeconds": 540,
            "addresses": ["192.168.1.81"],
            "interface": "en0",
            "latencyMs": None,
            "sources": ["neighbor memory"],
            "capabilities": [],
            "services": [],
            "paired": False,
            "remoteReady": False,
        },
    ],
    "link": {
        "enabled": False,
        "advertising": False,
        "pairedPeerCount": 1,
        "readyPeerCount": 0,
        "generation": 4,
        "messages": [],
        "errors": [],
        "trustedPeers": [{"id": "fixture-peer", "name": "Trusted MacBook", "ready": False}],
        "boundary": "Plain-text messages only. A message cannot execute commands, open files, invoke an Agent, or grant authority.",
    },
}


OPTIMIZER_FIXTURE = {
    "ok": True,
    "schemaVersion": 1,
    "state": "complete",
    "observedAt": "2026-08-24T20:41:00Z",
    "connection": {
        "kind": "wifi",
        "interface": "en0",
        "connected": True,
        "band": "2.4 GHz",
        "channel": 1,
        "widthMHz": 40,
        "signalDbm": -72,
        "noiseDbm": -90,
        "snrDb": 18,
        "transmitRateMbps": 144,
        "security": "WPA2 Personal",
    },
    "quality": {"label": "Needs attention", "healthScore": 30, "confidence": "measured"},
    "interference": {
        "measured": True,
        "partial": False,
        "nearbyObservationCount": 7,
        "band": "2.4 GHz",
        "currentChannel": 1,
        "channels": [
            {"channel": 1, "pressurePercent": 100, "nearbyCount": 5, "current": True},
            {"channel": 6, "pressurePercent": 36, "nearbyCount": 2, "current": False},
            {"channel": 11, "pressurePercent": 0, "nearbyCount": 0, "current": False},
        ],
        "recommendation": {
            "canApply": False,
            "reason": "Auto is preferred; if Auto is unavailable, channel 11 was the quietest non-overlapping 2.4 GHz choice in this scan.",
        },
    },
    "findings": [
        {"severity": "high", "title": "Signal is weak", "detail": "Move closer to the router, reduce obstructions, or add a wired access point before changing software settings."},
        {"severity": "high", "title": "Interference is crowding the signal", "detail": "Prefer router Auto channel and review access-point placement."},
        {"severity": "high", "title": "A quieter 2.4 GHz channel was observed", "detail": "Auto is preferred; channel 11 is the measured manual fallback."},
    ],
    "router": {"canApplyChannel": False, "adminAvailable": True, "boundary": "Router settings require the router administrator or an explicitly authorized vendor adapter."},
    "actions": [
        {"id": "open-router-settings", "available": True},
        {"id": "measure-internet", "available": True},
        {"id": "wireless-diagnostics", "available": True},
        {"id": "open-wifi-settings", "available": True},
    ],
    "activeTest": {
        "ok": True,
        "state": "measured",
        "interface": "en0",
        "downloadMbps": 312.4,
        "uploadMbps": 41.8,
        "idleLatencyMs": 18.2,
        "responsivenessRpm": 612,
        "comparison": {"downloadMbps": 28.7, "uploadMbps": 4.1, "idleLatencyMs": -5.4, "responsivenessRpm": 74},
        "usesInternetData": True,
        "settingsChanged": False,
    },
    "privacy": {"nearbyNetworkNamesCollected": False, "nearbyNetworkIdentifiersCollected": False, "settingsChanged": False, "persisted": False},
}


PERMISSION_ERROR = {
    "source": "bonjour",
    "code": "permission_denied",
    "message": "Local Network access is unavailable. Check macOS privacy settings and try again.",
    "recovery": {
        "kind": "settings",
        "action": "open-local-network-settings",
        "target": "local-network-permission",
        "label": "Fix access",
        "requiresUserAction": True,
        "priority": 95,
        "generation": 4,
    },
    "observedAt": "2026-08-24T20:42:00Z",
}


CONNECTIONS_ERROR = network_fabric.public_error(
    "connections_unavailable",
    "connections",
    1787604120,
    recovery_generation=4,
)


OPTIMIZER_ERROR_DETAIL = {
    "source": "internet-optimizer",
    "code": "internet_optimizer_unavailable",
    "message": "Internet optimization could not complete its local Wi-Fi analysis.",
    "recovery": {
        "kind": "retry",
        "action": "retry-internet-optimizer",
        "target": "internet-optimizer",
        "label": "Retry optimizer",
        "requiresUserAction": False,
        "priority": 55,
        "generation": 4,
    },
    "observedAt": "2026-08-24T20:42:00Z",
}


async def render_state(browser, output: Path, width: int, state: str) -> dict:
    context = await browser.new_context(
        offline=True,
        viewport={"width": width, "height": 680},
        device_scale_factor=1,
        reduced_motion="reduce",
    )
    page = await context.new_page()
    console_errors: list[str] = []
    network_requests: list[str] = []
    page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
    page.on("pageerror", lambda error: console_errors.append(str(error)))
    page.on("request", lambda request: network_requests.append(request.url) if request.url.startswith(("http://", "https://")) else None)
    await page.set_content(activity_monitor.HTML, wait_until="domcontentloaded")
    await page.evaluate(
        """fixtures => {
          document.querySelectorAll('.tab-content').forEach(node => node.classList.remove('active'));
          document.querySelectorAll('.seg-btn').forEach(node => node.classList.remove('active'));
          document.getElementById('network-tab').classList.add('active');
          document.querySelector('[data-tab="network"]').classList.add('active');
          currentTab = 'network';
          apiReady = true;
          window.pywebview = {api:{analyze_internet_connection: async () => JSON.stringify(fixtures.optimizer)}};
          const errors = fixtures.state === 'recovery'
            ? [fixtures.permissionError]
            : fixtures.state === 'connections-warning'
              ? [fixtures.connectionsError]
              : [];
          renderNetworkSnapshot({...fixtures.network, errors});
          document.querySelector('.network-scroll').scrollTop = 0;
        }""",
        {
            "network": NETWORK_FIXTURE,
            "optimizer": OPTIMIZER_FIXTURE,
            "permissionError": PERMISSION_ERROR,
            "connectionsError": CONNECTIONS_ERROR,
            "state": state,
        },
    )
    optimizer_focus = {
        "optimizerFocusAfterFailure": None,
        "optimizerFocusRestoredAfterClose": None,
        "optimizerFocusAfterSuccess": None,
    }
    if state == "optimizer":
        trigger = page.locator("#internet-optimizer-btn")
        await trigger.focus()
        await page.evaluate(
            """detail => {
              window.pywebview.api.analyze_internet_connection = async () => JSON.stringify({
                ok:false,
                errorDetail:detail
              });
            }""",
            OPTIMIZER_ERROR_DETAIL,
        )
        await page.keyboard.press("Enter")
        await page.wait_for_function(
            "document.getElementById('internet-optimizer-state').textContent === 'Needs help' && !document.getElementById('internet-optimizer-btn').disabled"
        )
        optimizer_focus["optimizerFocusAfterFailure"] = await page.evaluate(
            "document.activeElement === document.getElementById('internet-optimizer')"
        )
        await page.keyboard.press("Escape")
        optimizer_focus["optimizerFocusRestoredAfterClose"] = await page.evaluate(
            "document.activeElement === document.getElementById('internet-optimizer-btn')"
        )
        await page.evaluate(
            """fixture => {
              window.pywebview.api.analyze_internet_connection = async () => JSON.stringify(fixture);
            }""",
            OPTIMIZER_FIXTURE,
        )
        await page.keyboard.press("Enter")
        await page.wait_for_function(
            "document.getElementById('internet-optimizer-state').textContent === 'Needs attention' && !document.getElementById('internet-optimizer-btn').disabled"
        )
        optimizer_focus["optimizerFocusAfterSuccess"] = await page.evaluate(
            "document.activeElement === document.getElementById('internet-optimizer')"
        )
    elif state in ("recovery", "connections-warning"):
        await page.locator("#network-recovery-btn").focus()
    else:
        await page.locator("#internet-optimizer-btn").focus()
    await page.wait_for_timeout(100)
    proof = await page.evaluate(
        """state => {
          const scroll = document.querySelector('.network-scroll');
          const optimizer = document.getElementById('internet-optimizer');
          const fabric = document.querySelector('[data-flagship-tab="network"]');
          const focused = document.activeElement;
          const recovery = document.getElementById('network-error');
          const box = state === 'optimizer' ? optimizer.getBoundingClientRect() : ['recovery','connections-warning'].includes(state) ? recovery.getBoundingClientRect() : document.querySelector('.network-hero').getBoundingClientRect();
          const deviceSource = document.querySelector('.network-device-sources');
          const recoveryCopy = document.getElementById('network-error-copy').textContent.trim();
          const renderedTextBelow10 = [...document.querySelectorAll('#network-tab *')].flatMap(element => {
            const style = getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            if (
              style.display === 'none' ||
              style.visibility === 'hidden' ||
              Number(style.opacity) === 0 ||
              rect.width === 0 ||
              rect.height === 0
            ) return [];
            const directText = [...element.childNodes]
              .filter(node => node.nodeType === Node.TEXT_NODE)
              .map(node => node.textContent.trim())
              .filter(Boolean)
              .join(' ');
            const formText = element.matches('input,textarea,select')
              ? (element.value || element.getAttribute('placeholder') || element.getAttribute('aria-label') || '')
              : '';
            const before = getComputedStyle(element, '::before').content;
            const after = getComputedStyle(element, '::after').content;
            const pseudoText = [before, after]
              .filter(value => value && value !== 'none' && value !== 'normal' && value !== '""')
              .join(' ');
            const text = [directText, formText, pseudoText].filter(Boolean).join(' ').trim();
            if (!text) return [];
            const fontPx = parseFloat(style.fontSize);
            if (!Number.isFinite(fontPx) || fontPx >= 10) return [];
            return [{
              selector: element.id ? `#${element.id}` : `${element.tagName.toLowerCase()}.${[...element.classList].join('.')}`,
              text: text.slice(0, 80),
              fontPx,
              inViewport: rect.bottom > 0 && rect.right > 0 && rect.top < innerHeight && rect.left < innerWidth,
            }];
          });
          return {
            state,
            currentTab,
            optimizerHidden: optimizer.hidden,
            observed: document.getElementById('network-count-observed').textContent,
            deviceRows: document.querySelectorAll('.network-device').length,
            fabricInsideScroll: fabric.parentElement === scroll,
            rootHorizontalOverflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
            networkHorizontalOverflow: scroll.scrollWidth > scroll.clientWidth,
            primaryHorizontalInViewport: box.left >= 0 && box.right <= innerWidth,
            primaryFocusVisible:
              (state === 'overview' && focused === document.getElementById('internet-optimizer-btn')) ||
              (['recovery','connections-warning'].includes(state) && focused === document.getElementById('network-recovery-btn')),
            recoveryHidden: recovery.hidden,
            recoveryCopy,
            recoveryLabel: document.getElementById('network-recovery-btn').textContent,
            recoveryRegionCount: document.querySelectorAll('#network-error').length,
            deviceSourcesFontPx: deviceSource ? parseFloat(getComputedStyle(deviceSource).fontSize) : 0,
            renderedTextBelow10,
            optimizerState: document.getElementById('internet-optimizer-state').textContent,
          };
        }""",
        state,
    )
    path = output / f"network-{state}-{width}x680.png"
    await page.screenshot(path=str(path), full_page=False)
    proof.update(
        {
            "viewport": f"{width}x680",
            "screenshot": str(path),
            "screenshotSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "consoleErrors": console_errors,
            "networkRequests": network_requests,
        }
    )
    proof.update(optimizer_focus)
    await context.close()
    return proof


async def main(output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            executable_path="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        )
        proofs = []
        for width in (960, 560):
            for state in ("overview", "recovery", "connections-warning", "optimizer"):
                proofs.append(await render_state(browser, output, width, state))
        await browser.close()
    ok = all(
        item["currentTab"] == "network"
        and item["observed"] == "6"
        and item["deviceRows"] == 6
        and item["fabricInsideScroll"]
        and not item["rootHorizontalOverflow"]
        and not item["networkHorizontalOverflow"]
        and item["primaryHorizontalInViewport"]
        and not item["consoleErrors"]
        and not item["networkRequests"]
        and not item["renderedTextBelow10"]
        and (
            (item["state"] == "overview" and item["optimizerHidden"] and item["recoveryHidden"] and item["primaryFocusVisible"])
            or (item["state"] == "recovery" and item["optimizerHidden"] and not item["recoveryHidden"] and item["recoveryLabel"] == "Fix access" and item["primaryFocusVisible"])
            or (
                item["state"] == "connections-warning"
                and item["optimizerHidden"]
                and not item["recoveryHidden"]
                and item["recoveryLabel"] == "Retry connections"
                and item["recoveryCopy"] == CONNECTIONS_ERROR["message"]
                and not any(label in item["recoveryCopy"] for label in ("ARP", "NDP", "ICMP", "Bonjour", "SSDP"))
                and item["recoveryRegionCount"] == 1
                and item["deviceSourcesFontPx"] >= 10
                and item["primaryFocusVisible"]
            )
            or (
                item["state"] == "optimizer"
                and not item["optimizerHidden"]
                and item["recoveryHidden"]
                and item["optimizerState"] == "Needs attention"
                and item["optimizerFocusAfterFailure"]
                and item["optimizerFocusRestoredAfterClose"]
                and item["optimizerFocusAfterSuccess"]
            )
        )
        for item in proofs
    )
    compact_warning = next(
        item for item in proofs
        if item["viewport"] == "960x680" and item["state"] == "connections-warning"
    )
    receipt = {
        "ok": ok,
        "sourceOnly": True,
        "offlineBrowser": True,
        "syntheticFixture": True,
        "installedAppOpened": False,
        "networkTraffic": any(item["networkRequests"] for item in proofs),
        "liveWifiScanRun": False,
        "networkQualityRun": False,
        "routerSettingsOpened": False,
        "composedHtmlSha256": hashlib.sha256(activity_monitor.HTML.encode("utf-8")).hexdigest(),
        "firstLookGate960x680": {
            "internalDiagnosticLabelsAreNotPrimaryCopy": not any(
                label in compact_warning["recoveryCopy"]
                for label in ("ARP", "NDP", "ICMP", "Bonjour", "SSDP")
            ),
            "stateAndActionAgree": compact_warning["recoveryLabel"] == "Retry connections",
            "mainViewIsUseful": compact_warning["deviceRows"] > 0,
            "resolutionIsDirect": not compact_warning["recoveryHidden"],
            "noDuplicateWarningSection": compact_warning["recoveryRegionCount"] == 1,
            "allRenderedNetworkTextIsAtLeast10px": not compact_warning["renderedTextBelow10"],
            "deviceEvidenceTextIsReadable": compact_warning["deviceSourcesFontPx"] >= 10,
            "mainActionIsImmediatelyIdentifiable": compact_warning["primaryFocusVisible"],
            "screenshot": compact_warning["screenshot"],
        },
        "proofs": proofs,
    }
    receipt_path = output / "network-ui-visual-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if ok else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.output.resolve())))
