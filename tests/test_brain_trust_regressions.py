import json
import os
from pathlib import Path
import tempfile
import unittest

from brain_discovery import (
    BrainService,
    ROOT_FINGERPRINT_SCHEMA_VERSION,
    SETTINGS_SCHEMA_VERSION,
)


class BrainTrustRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        self.settings = self.home / "support" / "brain-settings.json"

    def tearDown(self):
        self.temporary.cleanup()

    def _service(self) -> BrainService:
        service = BrainService(
            home=self.home,
            settings_path=self.settings,
            scan_roots=[self.home],
            scan_seconds=2.0,
            max_directories=5_000,
        )
        service._spotlight_paths = lambda _timeout: []
        return service

    @staticmethod
    def _row(payload: dict, path: Path) -> dict:
        exact = str(path.resolve())
        return next(item for item in payload["brains"] if item["path"] == exact)

    def test_replacement_inode_at_consented_path_never_inherits_connection(self):
        vault = self.home / "Documents" / "Identity Vault"
        (vault / ".obsidian").mkdir(parents=True)
        service = self._service()
        discovered = service.scan(force=True)
        connected = service.set_connected(self._row(discovered, vault)["path"], True)
        self.assertEqual(self._row(connected, vault)["status"], "connected")
        before = json.loads(self.settings.read_text(encoding="utf-8"))
        old_fingerprint = before["connections"][str(vault.resolve())]["fingerprint"]
        self.assertEqual(old_fingerprint["schemaVersion"], ROOT_FINGERPRINT_SCHEMA_VERSION)

        original = vault.with_name("Identity Vault original")
        vault.rename(original)
        (vault / ".obsidian").mkdir(parents=True)
        (vault / "replacement-canary.md").write_text("replacement", encoding="utf-8")

        restarted = self._service()
        replaced = restarted.scan(force=True)
        row = self._row(replaced, vault)
        self.assertEqual(row["status"], "discovered")
        self.assertTrue(row["identityChanged"])
        self.assertFalse(row["canBrowse"])
        after = json.loads(self.settings.read_text(encoding="utf-8"))
        self.assertEqual(after["connections"][str(vault.resolve())]["fingerprint"], old_fingerprint)
        with self.assertRaisesRegex(ValueError, "Connect this Brain|identity"):
            restarted.list_directory(row["id"], replaced["inventoryRevision"])

    def test_untrusted_settings_and_configured_symlink_fail_closed_without_outside_metadata(self):
        codex = self.home / ".codex" / "memories"
        codex.mkdir(parents=True)
        (codex / "MEMORY.md").write_text("fixture registry", encoding="utf-8")
        self.settings.parent.mkdir(mode=0o700)
        canary = "outside-settings-canary-7f9d2"
        injected = "/outside/provider/private-brain"
        self.settings.write_text(json.dumps({"path": injected, "label": canary}), encoding="utf-8")
        os.chmod(self.settings, 0o644)

        mode_rejected = self._service().scan(force=True)
        serialized = json.dumps(mode_rejected, sort_keys=True)
        self.assertFalse(mode_rejected["scan"]["settingsTrusted"])
        self.assertNotIn(canary, serialized)
        self.assertNotIn(injected, serialized)
        self.assertEqual(self._row(mode_rejected, codex)["status"], "discovered")

        self.settings.unlink()
        with tempfile.TemporaryDirectory() as outside_raw:
            outside = Path(outside_raw)
            outside_settings = outside / "brain-settings.json"
            outside_settings.write_text(json.dumps({"path": injected, "label": canary}), encoding="utf-8")
            os.chmod(outside_settings, 0o600)
            self.settings.symlink_to(outside_settings)
            symlink_rejected = self._service().scan(force=True)
            serialized = json.dumps(symlink_rejected, sort_keys=True)
            self.assertFalse(symlink_rejected["scan"]["settingsTrusted"])
            self.assertNotIn(canary, serialized)
            self.assertNotIn(injected, serialized)

            self.settings.unlink()
            grok = self.home / ".grokcode"
            grok.mkdir(mode=0o700)
            outside_brain = outside / "outside-brain"
            (outside_brain / ".obsidian").mkdir(parents=True)
            (outside_brain / "GrokCode").mkdir()
            (outside_brain / canary).write_text("must not enumerate", encoding="utf-8")
            (grok / "brain").symlink_to(outside_brain, target_is_directory=True)
            configured_rejected = self._service().scan(force=True)
            serialized = json.dumps(configured_rejected, sort_keys=True)
            self.assertNotIn(str(outside_brain), serialized)
            self.assertNotIn(canary, serialized)
            self.assertNotIn("KE Brain", {row["type"] for row in configured_rejected["brains"]})

    def test_codex_and_claude_memory_auto_connect_and_opt_outs_survive_restart(self):
        codex = self.home / ".codex" / "memories"
        codex.mkdir(parents=True)
        (codex / "MEMORY.md").write_text("fixture registry", encoding="utf-8")
        claude = self.home / ".claude" / "memory"
        claude.mkdir(parents=True)

        first_service = self._service()
        first = first_service.scan(force=True)
        self.assertEqual(self._row(first, codex)["status"], "connected")
        self.assertEqual(self._row(first, claude)["status"], "connected")
        saved = json.loads(self.settings.read_text(encoding="utf-8"))
        self.assertEqual(saved["schemaVersion"], SETTINGS_SCHEMA_VERSION)
        for path in (codex, claude):
            record = saved["connections"][str(path.resolve())]
            self.assertEqual(record["source"], "managed-memory")
            self.assertEqual(record["fingerprint"]["schemaVersion"], ROOT_FINGERPRINT_SCHEMA_VERSION)

        restarted = self._service()
        after_restart = restarted.scan(force=True)
        self.assertEqual(self._row(after_restart, codex)["status"], "connected")
        self.assertEqual(self._row(after_restart, claude)["status"], "connected")

        disconnected = restarted.set_connected(str(codex.resolve()), False)
        self.assertEqual(self._row(disconnected, codex)["optOutState"], "disconnected")
        ignored = restarted.set_ignored(str(claude.resolve()), True)
        self.assertEqual(self._row(ignored, claude)["status"], "ignored")

        opted_out = self._service()
        persisted = opted_out.scan(force=True)
        self.assertEqual(self._row(persisted, codex)["optOutState"], "disconnected")
        self.assertEqual(self._row(persisted, codex)["status"], "discovered")
        self.assertEqual(self._row(persisted, claude)["optOutState"], "ignored")
        self.assertEqual(self._row(persisted, claude)["status"], "ignored")

        forgotten = opted_out.forget(str(codex.resolve()))
        self.assertEqual(self._row(forgotten, codex)["optOutState"], "forgotten")
        final = self._service().scan(force=True)
        self.assertEqual(self._row(final, codex)["optOutState"], "forgotten")
        self.assertEqual(self._row(final, codex)["status"], "discovered")
        final_settings = json.loads(self.settings.read_text(encoding="utf-8"))
        self.assertNotIn(str(codex.resolve()), final_settings["connections"])
        self.assertEqual(final_settings["optOuts"][str(codex.resolve())]["state"], "forgotten")

        restored = opted_out.set_ignored(str(claude.resolve()), False)
        self.assertEqual(self._row(restored, claude)["status"], "connected")
        self.assertEqual(self._row(self._service().scan(force=True), claude)["status"], "connected")


if __name__ == "__main__":
    unittest.main()
