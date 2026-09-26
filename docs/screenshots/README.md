# How the screenshots were made

The images in `docs/images/` are the real app. `scripts/render_screenshots.py` loads the exact HTML the app ships (`activity_monitor.HTML`) into headless Chromium and answers its bridge calls from `fixtures.json`, the same way pywebview answers them in the app. It then opens each tab and saves a screenshot. The render makes no network requests and runs no product actions.

`fixtures.json` started as the answers the app's own read-only API gave on a working Mac: processes, per-core CPU, memory pressure and diagnostics, GPU state, AI processes, capability status. Before it was saved:

- every project, task, brain and path name was replaced with an invented one (Lighthouse App, Orchard API and so on);
- the host name became `Studio` and the user account became `demo`;
- the Workspace rail, brain inventory and Dispatch history were rebuilt from the real record shapes with invented content;
- the two CPU worker pools and the GPU job names are illustrative;
- the Network tab uses the invented devices from `tests/render_network_ui_proof.py`;
- a final check refused to write the file if any original name, title or path, or any private term, was still present.

The numbers (CPU, memory, disk bytes, threads and the rest) are the real ones from that sample.

Regenerate with:

```bash
python3 scripts/render_screenshots.py            # writes docs/images/full/*.png
```
