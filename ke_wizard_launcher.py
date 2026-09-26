"""Native upper-right launcher for the KE Wizard companion app.

This module owns only the titlebar control and its exact, validated local app
launch. It does not change Activity Monitor's HTML, tabs, settings, telemetry,
credentials, packaging, or installed bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import plistlib
import subprocess
import sys
from typing import Any, Callable, Iterable


KE_WIZARD_BUNDLE_ID = "com.kestudios.ke-wizard"
KE_WIZARD_APP_CANDIDATES = (Path("/Applications/KE Wizard.app"),)
LAUNCHER_ACCESSIBILITY_LABEL = "Open KE Wizard"


@dataclass(frozen=True)
class Frame:
    x: float
    y: float
    width: float
    height: float


def mirrored_titlebar_frame(container_width: float, close_frame: Frame) -> Frame:
    """Mirror the red close button's frame across the titlebar centerline."""
    if container_width <= 0 or close_frame.width <= 0 or close_frame.height <= 0:
        raise ValueError("Titlebar and close-button geometry must be positive")
    right_x = float(container_width) - float(close_frame.x) - float(close_frame.width)
    if right_x < 0:
        raise ValueError("Close-button geometry is outside the titlebar")
    return Frame(right_x, float(close_frame.y), float(close_frame.width), float(close_frame.height))


def _bundle_identity(path: Path) -> tuple[str | None, str | None]:
    info_path = path / "Contents" / "Info.plist"
    try:
        with info_path.open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        return None, None
    return info.get("CFBundleIdentifier"), info.get("CFBundleExecutable")


def validate_ke_wizard_app(path: Path) -> Path:
    """Return one exact KE Wizard bundle path or fail closed."""
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("KE Wizard app path may not be a symlink")
    try:
        resolved = expanded.resolve(strict=True)
    except OSError as error:
        raise FileNotFoundError("KE Wizard is not installed") from error
    if not resolved.is_dir() or resolved.suffix != ".app":
        raise ValueError("KE Wizard candidate is not an app bundle")
    bundle_id, executable = _bundle_identity(resolved)
    if bundle_id != KE_WIZARD_BUNDLE_ID:
        raise ValueError("KE Wizard bundle identity does not match")
    executable_path = resolved / "Contents" / "MacOS" / str(executable or "")
    if not executable or not executable_path.is_file():
        raise ValueError("KE Wizard bundle executable is missing")
    return resolved


def resolve_ke_wizard_app(candidates: Iterable[Path] = KE_WIZARD_APP_CANDIDATES) -> Path:
    errors = []
    for candidate in candidates:
        try:
            return validate_ke_wizard_app(candidate)
        except (OSError, ValueError) as error:
            errors.append(str(error))
    raise FileNotFoundError("A valid KE Wizard app is not installed in /Applications")


def launch_ke_wizard(
    *,
    candidates: Iterable[Path] = KE_WIZARD_APP_CANDIDATES,
    popen: Callable[..., Any] = subprocess.Popen,
) -> Path:
    """Open the validated local bundle with a fixed argv and no shell."""
    app_path = resolve_ke_wizard_app(candidates)
    popen(["/usr/bin/open", str(app_path)], start_new_session=True)
    return app_path


_INSTALLATIONS: dict[int, tuple[Any, Any]] = {}


def _native_frame(rect: Any) -> Frame:
    return Frame(
        float(rect.origin.x),
        float(rect.origin.y),
        float(rect.size.width),
        float(rect.size.height),
    )


def _show_launch_error(message: str) -> None:
    try:
        from AppKit import NSAlert, NSAlertStyleWarning

        alert = NSAlert.alloc().init()
        alert.setAlertStyle_(NSAlertStyleWarning)
        alert.setMessageText_("KE Wizard is unavailable")
        alert.setInformativeText_(message)
        alert.addButtonWithTitle_("OK")
        alert.runModal()
    except Exception:
        print(f"KE Wizard launcher: {message}", file=sys.stderr, flush=True)


def _make_target() -> Any:
    from Foundation import NSObject

    class LauncherTarget(NSObject):
        def openWizard_(self, _sender):
            try:
                launch_ke_wizard()
            except (OSError, ValueError) as error:
                _show_launch_error(str(error))

    return LauncherTarget.alloc().init()


def _install_native_launcher(pywebview_window: Any) -> bool:
    if sys.platform != "darwin":
        return False
    from AppKit import (
        NSButton,
        NSColor,
        NSFont,
        NSFontWeightSemibold,
        NSMakeRect,
        NSViewMinXMargin,
        NSWindowCloseButton,
    )

    native_window = getattr(pywebview_window, "native", None)
    if native_window is None:
        return False
    key = id(native_window)
    if key in _INSTALLATIONS:
        return True
    close_button = native_window.standardWindowButton_(NSWindowCloseButton)
    if close_button is None or close_button.superview() is None:
        return False
    container = close_button.superview()
    mirrored = mirrored_titlebar_frame(float(container.bounds().size.width), _native_frame(close_button.frame()))
    button = NSButton.alloc().initWithFrame_(
        NSMakeRect(mirrored.x, mirrored.y, mirrored.width, mirrored.height)
    )
    button.setTitle_("✦")
    button.setBordered_(False)
    button.setFont_(
        NSFont.systemFontOfSize_weight_(
            max(9.0, mirrored.height * 0.72), NSFontWeightSemibold
        )
    )
    button.setToolTip_(LAUNCHER_ACCESSIBILITY_LABEL)
    button.setAccessibilityLabel_(LAUNCHER_ACCESSIBILITY_LABEL)
    button.setAutoresizingMask_(NSViewMinXMargin)
    button.setWantsLayer_(True)
    layer = button.layer()
    if layer is not None:
        layer.setCornerRadius_(mirrored.height / 2.0)
        layer.setBackgroundColor_(
            NSColor.colorWithSRGBRed_green_blue_alpha_(0.46, 0.34, 0.94, 0.92).CGColor()
        )
        layer.setBorderWidth_(1.0)
        layer.setBorderColor_(
            NSColor.colorWithSRGBRed_green_blue_alpha_(0.82, 0.94, 1.0, 0.82).CGColor()
        )
    button.setContentTintColor_(NSColor.whiteColor())
    target = _make_target()
    button.setTarget_(target)
    button.setAction_("openWizard:")
    container.addSubview_(button)
    _INSTALLATIONS[key] = (button, target)
    return True


def install_ke_wizard_launcher(pywebview_window: Any) -> None:
    """Queue one native launcher after pywebview has created its NSWindow."""
    if sys.platform != "darwin":
        return
    try:
        resolve_ke_wizard_app()
    except FileNotFoundError:
        return  # KE Wizard is an optional companion: no titlebar button when it is not installed
    try:
        from PyObjCTools import AppHelper

        AppHelper.callAfter(_install_native_launcher, pywebview_window)
    except Exception:
        _install_native_launcher(pywebview_window)
