from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

import ke_wizard_launcher as launcher


class KEWizardLauncherTests(unittest.TestCase):
    def make_app(self, root: Path, bundle_id: str = launcher.KE_WIZARD_BUNDLE_ID) -> Path:
        app = root / "KE Wizard.app"
        macos = app / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        (macos / "KE Wizard").write_text("candidate", encoding="utf-8")
        with (app / "Contents" / "Info.plist").open("wb") as handle:
            plistlib.dump(
                {"CFBundleIdentifier": bundle_id, "CFBundleExecutable": "KE Wizard"},
                handle,
            )
        return app

    def test_titlebar_frame_exactly_mirrors_red_close_button(self):
        close = launcher.Frame(x=18, y=7, width=14, height=14)
        result = launcher.mirrored_titlebar_frame(960, close)
        self.assertEqual(result, launcher.Frame(x=928, y=7, width=14, height=14))
        self.assertEqual(result.y, close.y)
        self.assertEqual(result.width, close.width)
        self.assertEqual(960 - (result.x + result.width), close.x)

    def test_resolves_only_exact_bundle_identity_and_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = self.make_app(root)
            self.assertEqual(launcher.resolve_ke_wizard_app([valid]), valid.resolve())
            wrong = root / "Wrong"
            wrong.mkdir()
            invalid = self.make_app(wrong, "com.example.not-wizard")
            with self.assertRaises(FileNotFoundError):
                launcher.resolve_ke_wizard_app([invalid])

    def test_rejects_symlink_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = self.make_app(root / "real")
            link = root / "KE Wizard Link.app"
            link.symlink_to(real)
            with self.assertRaises(ValueError):
                launcher.validate_ke_wizard_app(link)

    def test_launch_uses_fixed_open_argv_without_shell(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = self.make_app(Path(temporary))
            calls = []

            def fake_popen(argv, **kwargs):
                calls.append((argv, kwargs))
                return object()

            launched = launcher.launch_ke_wizard(candidates=[app], popen=fake_popen)
            self.assertEqual(launched, app.resolve())
            self.assertEqual(
                calls,
                [(["/usr/bin/open", str(app.resolve())], {"start_new_session": True})],
            )

    def test_non_macos_install_is_a_noop(self):
        with mock.patch.object(launcher.sys, "platform", "linux"):
            self.assertIsNone(launcher.install_ke_wizard_launcher(object()))

    def test_no_button_when_ke_wizard_is_not_installed(self):
        calls = []
        with mock.patch.object(launcher.sys, "platform", "darwin"), \
                mock.patch.object(launcher, "resolve_ke_wizard_app", side_effect=FileNotFoundError("absent")), \
                mock.patch.object(launcher, "_install_native_launcher", side_effect=lambda w: calls.append(w)):
            self.assertIsNone(launcher.install_ke_wizard_launcher(object()))
        self.assertEqual(calls, [])

    def test_main_wiring_is_native_and_does_not_add_a_tab(self):
        source = (Path(__file__).resolve().parents[1] / "activity_monitor.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("install_ke_wizard_launcher(window)", source)
        self.assertIn("webview.start(_queue_macos_app_extras, args=(window,)", source)
        self.assertNotIn("ke-wizard-tab", source)


if __name__ == "__main__":
    unittest.main()
