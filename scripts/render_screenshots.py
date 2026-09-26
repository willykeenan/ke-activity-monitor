"""Render every Activity Monitor tab from the app's real HTML with public-safe fixtures.

usage: python3 scripts/render_screenshots.py [. docs/screenshots/fixtures.json docs/images/full]

The fixtures are public-safe: captured from a real Mac, then every project, task,
brain, path and host name was replaced with invented values (see docs/screenshots/README.md).
"""
import argparse, asyncio, json, sys
from pathlib import Path
from playwright.async_api import async_playwright

ap = argparse.ArgumentParser()
ap.add_argument("repo", nargs="?", default="."); ap.add_argument("fixtures", nargs="?", default="docs/screenshots/fixtures.json")
ap.add_argument("out", nargs="?", default="docs/images/full")
ap.add_argument("--scale", type=float, default=2); ap.add_argument("--dark", action="store_true")
ap.add_argument("--width", type=int, default=1440); ap.add_argument("--height", type=int, default=900)
args = ap.parse_args()
sys.path.insert(0, args.repo); sys.path.insert(0, str(Path(args.repo) / "tests"))
import activity_monitor  # noqa: E402
import render_network_ui_proof as netproof  # noqa: E402

fx = json.load(open(args.fixtures))
fx["get_network_snapshot"] = netproof.NETWORK_FIXTURE
TABS = ["cpu", "memory", "energy", "disk", "network", "agents", "brain", "dispatch", "guard"]

BRIDGE = r"""
(() => {
  const FX = __FX__;
  // Shift captured ISO timestamps so the fixture reads as a live session at render time.
  const anchor = Date.parse((FX.get_agent_activity || {}).generatedAt || '');
  const shift = Number.isFinite(anchor) ? Date.now() - anchor : 0;
  const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
  const shiftAll = v => {
    if (Array.isArray(v)) return v.map(shiftAll);
    if (v && typeof v === 'object') { for (const k of Object.keys(v)) v[k] = shiftAll(v[k]); return v; }
    if (typeof v === 'string' && ISO.test(v)) { const t = Date.parse(v); return Number.isFinite(t) ? new Date(t + shift).toISOString() : v; }
    return v;
  };
  shiftAll(FX);
  const ok = v => Promise.resolve(JSON.stringify(v));
  const denied = () => ok({ok:false, error:'Disabled in the screenshot fixture.'});
  const api = new Proxy({}, {get: (_, name) => {
    if (name === 'get_flagship_capabilities') return (tab) => ok(FX['get_flagship_capabilities:' + (tab || 'cpu')] || FX['get_flagship_capabilities:cpu']);
    if (name === 'get_processes') return () => ok(FX.get_processes);
    if (name === 'get_system_info') return () => {
      const v = JSON.parse(JSON.stringify(FX.get_system_info));
      const t = (window.__tick = (window.__tick || 0) + 1);
      if (v.cpu && Array.isArray(v.cpu.per_cpu)) {
        v.cpu.per_cpu = v.cpu.per_cpu.map((x, i) => Math.max(1, Math.min(99, x + 14 * Math.sin(t / 2.3 + i))));
        const avg = v.cpu.per_cpu.reduce((a, b) => a + b, 0) / v.cpu.per_cpu.length;
        v.cpu.percent = avg; v.cpu.user = avg * 0.62; v.cpu.system = avg * 0.38; v.cpu.idle = 100 - avg;
      }
      return ok(v);
    };
    if (name in FX) return () => ok(FX[name]);
    if (name === 'start_network_discovery' || name === 'request_network_scan') return () => ok(FX.get_network_snapshot);
    if (name === 'stop_network_discovery') return () => ok({ok:true});
    if (name === 'list_brain_directory') return () => ok({ok:true, entries:[], items:[], page:0, total:0});
    return denied;
  }});
  window.pywebview = {api};
})();
"""

async def main():
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    report = {}
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        ctx = await browser.new_context(offline=True, viewport={"width": args.width, "height": args.height},
                                        device_scale_factor=args.scale, reduced_motion="reduce",
                                        color_scheme="dark" if args.dark else "light")
        page = await ctx.new_page()
        errors, requests = [], []
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("request", lambda r: requests.append(r.url) if r.url.startswith(("http://", "https://")) else None)
        await page.add_init_script(BRIDGE.replace("__FX__", json.dumps(fx)))
        await page.set_content(activity_monitor.HTML, wait_until="domcontentloaded")
        await page.evaluate(BRIDGE.replace("__FX__", json.dumps(fx)))
        await page.evaluate("typeof pywebview !== 'undefined' && window.dispatchEvent(new Event('pywebviewready'))")
        await page.wait_for_timeout(2500)
        for _ in range(90):
            await page.evaluate("typeof refreshAll === 'function' ? refreshAll() : null")
            await page.wait_for_timeout(120)
        for tab in TABS:
            before = len(errors)
            await page.click(f'.seg-btn[data-tab="{tab}"]')
            await page.wait_for_timeout(2200)
            path = out / f"{tab}{'-dark' if args.dark else ''}.png"
            await page.screenshot(path=str(path))
            report[tab] = {"screenshot": str(path), "newErrors": errors[before:]}
        await browser.close()
    report["_network_requests"] = requests
    json.dump(report, open(out / f"render-report{'-dark' if args.dark else ''}.json", "w"), indent=1)
    for tab in TABS:
        print(f"{tab:9} errors={len(report[tab]['newErrors'])} {report[tab]['newErrors'][:1]}")
    print("network requests:", len(requests))

asyncio.run(main())
