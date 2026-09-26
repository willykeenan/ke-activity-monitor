#!/usr/bin/env python3
"""Render the real embedded UI with deterministic Memory Diagnostics evidence.

This helper never calls the pywebview bridge and cannot run a live diagnostic.
Its output is explicitly labelled as a fixture so candidate layout proof cannot
be mistaken for installed-runtime evidence.
"""

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import activity_monitor  # noqa: E402


FIXTURE = {
    "ok": True,
    "schemaVersion": "ke.activity-monitor-memory-diagnostics.v1",
    "verdict": "attention",
    "statusLabel": "Attention",
    "summary": "One check deserves attention; no automatic action was taken.",
    "finishedAt": "2026-08-21T02:45:00Z",
    "durationSeconds": 12.0,
    "sampleSeconds": 12.0,
    "sampleCount": 3,
    "findings": [
        {"id": "pressure", "label": "Pressure", "status": "healthy", "summary": "48% reclaimable headroom; pressure is normal.", "displayValue": "48% headroom"},
        {"id": "swap", "label": "Swap activity", "status": "healthy", "summary": "No swap-out growth; 4.5 GB remains allocated.", "displayValue": "No swap-out growth"},
        {"id": "compressor", "label": "Compression", "status": "healthy", "summary": "No new compression observed; 1.8 GB is occupied.", "displayValue": "No new compression"},
        {"id": "process-growth", "label": "Process growth", "status": "healthy", "summary": "No process crossed the material growth threshold.", "displayValue": "No unusual growth"},
        {"id": "swap-disk", "label": "Swap storage", "status": "attention", "summary": "12.0 GB free on the volume used by swap.", "displayValue": "12.0 GB free"},
    ],
    "recommendations": ["Free local storage before memory demand increases."],
    "reportText": "Deterministic fixture report",
    "boundary": {
        "mode": "local-read-only",
        "uploads": False,
        "savedReport": False,
        "processSignals": False,
        "automaticRepair": False,
    },
}


def render(output_path):
    fixture_json = json.dumps(FIXTURE, separators=(",", ":")).replace("</", "<\\/")
    script = f"""
<script>
(() => {{
    document.querySelectorAll('.seg-btn').forEach(button => button.classList.toggle('active', button.dataset.tab === 'memory'));
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.toggle('active', tab.id === 'memory-tab'));
    currentTab = 'memory';
    drawPressureGauge(52, 'normal');
    document.getElementById('mem-physical').textContent = '36.0 GB';
    document.getElementById('mem-used').textContent = '14.16 GB';
    document.getElementById('mem-cached').textContent = '9.00 GB';
    document.getElementById('mem-swap').textContent = '4.50 GB';
    document.getElementById('mem-app').textContent = '9.18 GB';
    document.getElementById('mem-wired').textContent = '4.98 GB';
    document.getElementById('mem-pressure-text').textContent = 'Normal';
    renderMemTable([
        {{name:'Codex Renderer',memory_mb:1472.0,memory_percent:4.0,threads:25,pid:53755,username:'local user'}},
        {{name:'Codex',memory_mb:1231.0,memory_percent:3.3,threads:44,pid:32624,username:'local user'}},
        {{name:'Python',memory_mb:332.0,memory_percent:0.9,threads:1,pid:39129,username:'local user'}},
        {{name:'ChatGPT',memory_mb:323.7,memory_percent:0.9,threads:69,pid:53589,username:'local user'}},
        {{name:'Claude',memory_mb:314.7,memory_percent:0.9,threads:76,pid:13402,username:'local user'}},
        {{name:'Chrome',memory_mb:168.5,memory_percent:0.5,threads:45,pid:723,username:'local user'}}
    ]);
    renderMemoryDiagnostics({fixture_json});
    document.getElementById('memory-diagnostics-status').textContent = 'Fixture · deterministic candidate proof · no live diagnostic run';
    document.documentElement.dataset.fixtureReady = 'true';
}})();
</script>
"""
    html = activity_monitor.HTML.replace("</body>", script + "</body>")
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(render(args.output))


if __name__ == "__main__":
    main()
