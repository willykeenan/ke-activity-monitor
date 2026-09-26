"""Process names and usernames are attacker-controlled text: every table renders them inert."""
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import activity_monitor  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

HOSTILE = '<img src=x onerror="window.__owned=1">'


class StaticChecks(unittest.TestCase):
    def test_no_table_inserts_raw_process_fields(self):
        html = activity_monitor.HTML
        for renderer in ("renderCpuTable", "renderMemTable", "renderDiskTable", "renderNetTable", "renderEnergyTable"):
            start = html.index("function " + renderer)
            body = html[start:html.index("\nfunction ", start + 10)]
            self.assertNotRegex(body, r"\+p\.(name|username)\+", renderer)

    def test_storage_uses_the_apfs_data_volume_when_present(self):
        expected = "/System/Volumes/Data" if Path("/System/Volumes/Data").is_dir() else "/"
        self.assertEqual(activity_monitor._DATA_VOLUME, expected)


@unittest.skipIf(sync_playwright is None, "playwright is not installed")
class RenderedChecks(unittest.TestCase):
    def test_hostile_process_name_renders_as_text_in_every_table(self):
        proc = {"pid": 4242, "name": HOSTILE, "username": HOSTILE, "cpu_percent": 50.0, "memory_mb": 64.0,
                "memory_percent": 1.0, "threads": 3, "status": "running", "runtime": "1m", "read_bytes": 1024,
                "write_bytes": 2048, "read_count": None, "write_count": None, "connections": 1, "sent_bytes": 0,
                "recv_bytes": 0, "energy_impact": 5.0, "avg_energy_impact": 4.0, "app_nap": "No", "preventing_sleep": "No"}
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.set_content(activity_monitor.HTML, wait_until="domcontentloaded")
            page.evaluate("""proc => {
                renderCpuTable([proc]); renderMemTable([proc]); renderDiskTable([proc]); renderNetTable([proc]);
            }""", proc)
            page.wait_for_timeout(200)
            owned = page.evaluate("window.__owned === 1")
            texts = page.evaluate("""() => ['cpu-tbody','mem-tbody','disk-tbody','net-tbody']
                .map(id => document.getElementById(id).querySelector('td').textContent)""")
            disk_counts = page.evaluate("document.getElementById('disk-tbody').querySelectorAll('td')[3].textContent")
            browser.close()
        self.assertFalse(owned, "a process name executed script")
        self.assertEqual(texts, [HOSTILE] * 4)
        self.assertEqual(disk_counts, "—")


if __name__ == "__main__":
    unittest.main()
