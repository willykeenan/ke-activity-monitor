# -*- mode: python ; coding: utf-8 -*-

import os
import sys


ROOT = os.path.abspath(SPECPATH)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from network_fabric import BONJOUR_SERVICE_ALLOWLIST, LOCAL_NETWORK_USAGE_DESCRIPTION

VERSION = os.environ.get("ACTIVITY_MONITOR_VERSION", "2.7")
TARGET_ARCH = os.environ.get("ACTIVITY_MONITOR_TARGET_ARCH", "universal2")
ICON = os.path.join(ROOT, ".build", "AppIcon.icns")


a = Analysis(
    [os.path.join(ROOT, "activity_monitor.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[
        (os.path.join(ROOT, "agents_snapshot.mjs"), "."),
        (ICON, "."),
        (os.path.join(ROOT, "activity_monitor.py"), "source"),
        (os.path.join(ROOT, "brain_discovery.py"), "source"),
        (os.path.join(ROOT, "cleanup_service.py"), "source"),
        (os.path.join(ROOT, "conversation_host.py"), "source"),
        (os.path.join(ROOT, "dispatch_router.py"), "source"),
        (os.path.join(ROOT, "flagship_acceptance.py"), "source"),
        (os.path.join(ROOT, "flagship_bridge.py"), "source"),
        (os.path.join(ROOT, "flagship_capabilities.py"), "source"),
        (os.path.join(ROOT, "flagship_local_sources.py"), "source"),
        (os.path.join(ROOT, "flagship_sources.py"), "source"),
        (os.path.join(ROOT, "flagship_ui.py"), "source"),
        (os.path.join(ROOT, "guard_status.py"), "source"),
        (os.path.join(ROOT, "ke_wizard_launcher.py"), "source"),
        (os.path.join(ROOT, "memory_diagnostics.py"), "source"),
        (os.path.join(ROOT, "network_fabric.py"), "source"),
        (os.path.join(ROOT, "network_optimizer.py"), "source"),
        (os.path.join(ROOT, "project_brains.py"), "source"),
        (os.path.join(ROOT, "workspace_browser.py"), "source"),
        (os.path.join(ROOT, "powerswarm_discovery.py"), "source"),
        (os.path.join(ROOT, "process_io.py"), "source"),
        (os.path.join(ROOT, "docs", "FLAGSHIP_NATIVE_CAPABILITIES.md"), "source/docs"),
        (os.path.join(ROOT, "README.md"), "source"),
        (os.path.join(ROOT, "docs", "DESIGN.md"), "source/docs"),
    ],
    hiddenimports=[
        "webview.platforms.cocoa",
        "AppKit",
        "Foundation",
        "Quartz",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Activity Monitor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    target_arch=TARGET_ARCH,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="Activity Monitor",
)

app = BUNDLE(
    coll,
    name="Activity Monitor.app",
    icon=ICON,
    bundle_identifier="com.kestudios.activity-monitor",
    version=VERSION,
    info_plist={
        "CFBundleDisplayName": "Activity Monitor",
        "CFBundleName": "Activity Monitor",
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "LSMinimumSystemVersion": "12.0",
        "LSApplicationCategoryType": "public.app-category.utilities",
        "NSHighResolutionCapable": True,
        "NSLocalNetworkUsageDescription": LOCAL_NETWORK_USAGE_DESCRIPTION,
        "NSBonjourServices": list(BONJOUR_SERVICE_ALLOWLIST),
    },
)
