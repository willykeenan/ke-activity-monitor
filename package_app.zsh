#!/bin/zsh
set -euo pipefail

activity_root=${0:A:h}
release_version=${1:-2.7}
target_arch=${ACTIVITY_MONITOR_TARGET_ARCH:-universal2}
build_root="$activity_root/.build"
dist_root="$activity_root/dist"
builder_venv="$build_root/portable-venv"
builder_python="$builder_venv/bin/python"
requirements="$activity_root/portable-build-requirements.txt"
spec_file="$activity_root/activity_monitor.spec"
icon_master="$activity_root/assets/AppIcon-1024.png"
icon_path="$build_root/AppIcon.icns"
pyinstaller_dist="$build_root/pyinstaller-dist"
pyinstaller_work="$build_root/pyinstaller-work"
built_app="$pyinstaller_dist/Activity Monitor.app"
installed_app="$activity_root/Activity Monitor.app"
distributable_app="$activity_root/Activity Monitor Distributable.app"
archive="$dist_root/Activity-Monitor-$release_version-mac-$target_arch.zip"
base_python=${ACTIVITY_MONITOR_BUILD_PYTHON:-/usr/bin/python3}

if [[ "$release_version" != <->.<-> && "$release_version" != <->.<->.<-> ]]; then
  print -u2 "Invalid Activity Monitor version: $release_version"
  exit 1
fi
if [[ "$target_arch" != "universal2" && "$target_arch" != "arm64" && "$target_arch" != "x86_64" ]]; then
  print -u2 "Unsupported target architecture: $target_arch"
  exit 1
fi
if [[ ! -x "$base_python" ]]; then
  base_python=$(command -v python3 || true)
fi
if [[ -z "$base_python" || ! -x "$base_python" ]]; then
  print -u2 "A Python 3 build interpreter is required."
  exit 1
fi
if [[ ! -f "$icon_master" || ! -f "$requirements" || ! -f "$spec_file" ]]; then
  print -u2 "Portable build inputs are incomplete in $activity_root"
  exit 1
fi

select_signing_identity() {
  local requested=${ACTIVITY_MONITOR_SIGN_IDENTITY:-"KE Studios Local Code Signing"}
  local identities matches match_count
  identities=$(/usr/bin/security find-identity -v -p codesigning 2>/dev/null || true)
  matches=$(print -r -- "$identities" | "$builder_python" -c '
import re
import sys

label = sys.argv[1]
for line in sys.stdin:
    match = re.fullmatch(r"\s*\d+\) ([0-9A-F]{40}) \"([^\"]+)\"\s*", line)
    if match and match.group(2) == label:
        print(match.group(1))
' "$requested")
  match_count=$(print -r -- "$matches" | /usr/bin/awk 'NF { count += 1 } END { print count + 0 }')
  if (( match_count > 1 )); then
    print -u2 "Ambiguous code-signing identity: $requested"
    return 1
  fi
  if (( match_count == 1 )); then
    signing_identity=$(print -r -- "$matches" | /usr/bin/awk 'NF { print; exit }')
    signing_label=$requested
    signing_mode=identity
  elif [[ -n ${ACTIVITY_MONITOR_SIGN_IDENTITY:-} ]]; then
    print -u2 "Requested code-signing identity is unavailable: $requested"
    return 1
  else
    signing_identity="-"
    signing_label="ad hoc"
    signing_mode=adhoc
  fi
}

verify_network_plist() {
  local bundle=$1
  "$builder_python" - "$bundle/Contents/Info.plist" <<'PY'
import plistlib
import sys

from network_fabric import BONJOUR_SERVICE_ALLOWLIST, LOCAL_NETWORK_USAGE_DESCRIPTION

with open(sys.argv[1], "rb") as handle:
    info = plistlib.load(handle)
assert info.get("NSLocalNetworkUsageDescription") == LOCAL_NETWORK_USAGE_DESCRIPTION
assert tuple(info.get("NSBonjourServices") or ()) == BONJOUR_SERVICE_ALLOWLIST
PY
}

verify_signer() {
  local bundle=$1
  local details requirement
  details=$(/usr/bin/codesign -d --verbose=4 "$bundle" 2>&1)
  requirement=$(/usr/bin/codesign -d -r- "$bundle" 2>&1)
  [[ "$requirement" == *'identifier "com.kestudios.activity-monitor"'* ]] || {
    print -u2 "Signed bundle has an unexpected designated requirement."
    return 1
  }
  if [[ "$signing_mode" == identity ]]; then
    [[ "$details" == *"Authority=$signing_label"* ]] || {
      print -u2 "Signed bundle does not carry the selected identity: $signing_label"
      return 1
    }
  else
    [[ "$details" == *"Signature=adhoc"* ]] || {
      print -u2 "Fallback package was not truthfully signed ad hoc."
      return 1
    }
  fi
}

/bin/mkdir -p "$build_root" "$dist_root"

safe_remove() {
  local target=$1
  case "$target" in
    "$build_root"/*|"$dist_root"/*)
      [[ -e "$target" || -L "$target" ]] && /bin/rm -R "$target"
      ;;
    *)
      print -u2 "Refusing to remove path outside the build roots: $target"
      return 1
      ;;
  esac
}

builder_ready() {
  [[ -x "$builder_python" ]] || return 1
  "$builder_python" -c 'import PyInstaller, psutil, webview; assert PyInstaller.__version__ == "6.22.2"; assert psutil.__version__ == "7.2.2"' >/dev/null 2>&1 || return 1
  local psutil_binary binary_info
  psutil_binary=$("$builder_python" -c 'import psutil; print(psutil._psutil_osx.__file__)') || return 1
  binary_info=$(/usr/bin/file "$psutil_binary") || return 1
  if [[ "$target_arch" == "universal2" ]]; then
    [[ "$binary_info" == *"x86_64"* && "$binary_info" == *"arm64"* ]] || return 1
  fi
}

if ! builder_ready; then
  if [[ "$target_arch" == "universal2" ]]; then
    base_info=$(/usr/bin/file "$base_python")
    if [[ "$base_info" != *"x86_64"* || "$base_info" != *"arm64"* ]]; then
      print -u2 "Universal2 packaging requires a universal2 Python build interpreter."
      exit 1
    fi
  fi
  safe_remove "$builder_venv"
  "$base_python" -m venv "$builder_venv"
  "$builder_python" -m pip install --disable-pip-version-check --upgrade pip setuptools wheel
  MACOSX_DEPLOYMENT_TARGET=12.0 \
    ARCHFLAGS='-arch arm64 -arch x86_64' \
    _PYTHON_HOST_PLATFORM=macosx-12.0-universal2 \
    "$builder_python" -m pip install --disable-pip-version-check --no-binary=psutil -r "$requirements"
fi

cd "$activity_root"
"$builder_python" -m unittest discover -s tests -v
"$builder_python" -m py_compile activity_monitor.py brain_discovery.py dispatch_router.py guard_status.py workspace_browser.py powerswarm_discovery.py memory_diagnostics.py network_fabric.py network_optimizer.py project_brains.py cleanup_service.py conversation_host.py ke_wizard_launcher.py process_io.py
"$builder_python" -m py_compile \
  flagship_acceptance.py \
  flagship_bridge.py \
  flagship_capabilities.py \
  flagship_local_sources.py \
  flagship_sources.py \
  flagship_ui.py
if node_path=$(command -v node 2>/dev/null); then
  "$node_path" --check agents_snapshot.mjs
  combined_js="$build_root/activity-monitor-combined.js"
  "$builder_python" - "$combined_js" <<'PY'
from pathlib import Path
import sys

import activity_monitor

script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
Path(sys.argv[1]).write_text(script, encoding="utf-8")
PY
  "$node_path" --check "$combined_js"
fi
/usr/bin/git diff --check

icon_work="$build_root/AppIcon.iconset"
safe_remove "$icon_work"
/bin/mkdir "$icon_work"
/usr/bin/sips -z 16 16 "$icon_master" --out "$icon_work/icon_16x16.png" >/dev/null
/usr/bin/sips -z 32 32 "$icon_master" --out "$icon_work/icon_16x16@2x.png" >/dev/null
/usr/bin/sips -z 32 32 "$icon_master" --out "$icon_work/icon_32x32.png" >/dev/null
/usr/bin/sips -z 64 64 "$icon_master" --out "$icon_work/icon_32x32@2x.png" >/dev/null
/usr/bin/sips -z 128 128 "$icon_master" --out "$icon_work/icon_128x128.png" >/dev/null
/usr/bin/sips -z 256 256 "$icon_master" --out "$icon_work/icon_128x128@2x.png" >/dev/null
/usr/bin/sips -z 256 256 "$icon_master" --out "$icon_work/icon_256x256.png" >/dev/null
/usr/bin/sips -z 512 512 "$icon_master" --out "$icon_work/icon_256x256@2x.png" >/dev/null
/usr/bin/sips -z 512 512 "$icon_master" --out "$icon_work/icon_512x512.png" >/dev/null
/usr/bin/sips -z 1024 1024 "$icon_master" --out "$icon_work/icon_512x512@2x.png" >/dev/null
/usr/bin/iconutil -c icns "$icon_work" -o "$icon_path"

safe_remove "$pyinstaller_dist"
safe_remove "$pyinstaller_work"
ACTIVITY_MONITOR_VERSION="$release_version" \
  ACTIVITY_MONITOR_TARGET_ARCH="$target_arch" \
  "$builder_python" -m PyInstaller \
    --noconfirm \
    --clean \
    --distpath "$pyinstaller_dist" \
    --workpath "$pyinstaller_work" \
    "$spec_file"

if [[ ! -d "$built_app" ]]; then
  print -u2 "PyInstaller did not produce $built_app"
  exit 1
fi

select_signing_identity
/usr/bin/codesign --force --deep --sign "$signing_identity" "$built_app"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$built_app"
verify_signer "$built_app"
verify_network_plist "$built_app"

verify_source_parity() {
  local bundle=$1
  /usr/bin/cmp activity_monitor.py "$bundle/Contents/Resources/source/activity_monitor.py"
  /usr/bin/cmp brain_discovery.py "$bundle/Contents/Resources/source/brain_discovery.py"
  /usr/bin/cmp cleanup_service.py "$bundle/Contents/Resources/source/cleanup_service.py"
  /usr/bin/cmp conversation_host.py "$bundle/Contents/Resources/source/conversation_host.py"
  /usr/bin/cmp dispatch_router.py "$bundle/Contents/Resources/source/dispatch_router.py"
  /usr/bin/cmp flagship_acceptance.py "$bundle/Contents/Resources/source/flagship_acceptance.py"
  /usr/bin/cmp flagship_bridge.py "$bundle/Contents/Resources/source/flagship_bridge.py"
  /usr/bin/cmp flagship_capabilities.py "$bundle/Contents/Resources/source/flagship_capabilities.py"
  /usr/bin/cmp flagship_local_sources.py "$bundle/Contents/Resources/source/flagship_local_sources.py"
  /usr/bin/cmp flagship_sources.py "$bundle/Contents/Resources/source/flagship_sources.py"
  /usr/bin/cmp flagship_ui.py "$bundle/Contents/Resources/source/flagship_ui.py"
  /usr/bin/cmp guard_status.py "$bundle/Contents/Resources/source/guard_status.py"
  /usr/bin/cmp ke_wizard_launcher.py "$bundle/Contents/Resources/source/ke_wizard_launcher.py"
  /usr/bin/cmp memory_diagnostics.py "$bundle/Contents/Resources/source/memory_diagnostics.py"
  /usr/bin/cmp network_fabric.py "$bundle/Contents/Resources/source/network_fabric.py"
  /usr/bin/cmp network_optimizer.py "$bundle/Contents/Resources/source/network_optimizer.py"
  /usr/bin/cmp project_brains.py "$bundle/Contents/Resources/source/project_brains.py"
  /usr/bin/cmp workspace_browser.py "$bundle/Contents/Resources/source/workspace_browser.py"
  /usr/bin/cmp powerswarm_discovery.py "$bundle/Contents/Resources/source/powerswarm_discovery.py"
  /usr/bin/cmp process_io.py "$bundle/Contents/Resources/source/process_io.py"
  /usr/bin/cmp docs/FLAGSHIP_NATIVE_CAPABILITIES.md "$bundle/Contents/Resources/source/docs/FLAGSHIP_NATIVE_CAPABILITIES.md"
  /usr/bin/cmp agents_snapshot.mjs "$bundle/Contents/Resources/agents_snapshot.mjs"
}

verify_source_parity "$built_app"

binary="$built_app/Contents/MacOS/Activity Monitor"
binary_info=$(/usr/bin/file "$binary")
if [[ "$target_arch" == "universal2" && ( "$binary_info" != *"x86_64"* || "$binary_info" != *"arm64"* ) ]]; then
  print -u2 "The built executable is not universal2: $binary_info"
  exit 1
fi

native_self_test="$build_root/self-test-native.json"
safe_remove "$native_self_test"
KE_ACTIVITY_SELF_TEST_PATH="$native_self_test" "$binary"
self_tests=("$native_self_test")
if [[ "$target_arch" == "universal2" && "$(/usr/bin/arch)" == "arm64" ]]; then
  x86_self_test="$build_root/self-test-x86_64.json"
  safe_remove "$x86_self_test"
  KE_ACTIVITY_SELF_TEST_PATH="$x86_self_test" /usr/bin/arch -x86_64 "$binary"
  self_tests+=("$x86_self_test")
fi

"$builder_python" - "${self_tests[@]}" <<'PY'
import json
import sys

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as handle:
        result = json.load(handle)
    assert result["ok"] is True
    assert result["packaged"] is True
    assert result["observerBundled"] is True
    assert result["system"]["source"] == "runtime-detected"
    assert result["system"]["cpu_model"]
    assert result["system"]["logical_cpu_count"] > 0
    assert result["gpu"]["deviceProbe"]["source"].startswith("built-in:")
    assert result["flagship"]["readOnly"] is True
    assert result["flagship"]["counts"]["native"] == 30
    assert result["flagship"]["counts"]["nativeGovernedSurface"] == 1
    assert result["flagship"]["topLevelOrder"] == [
        "cpu", "memory", "energy", "disk", "network",
        "agents", "brain", "dispatch", "guard",
    ]
PY

install_bundle() {
  local destination=$1
  local label=${destination:t}
  local staged="$build_root/$label.staged"
  local backup="$build_root/previous/$label"
  /bin/mkdir -p "$build_root/previous"
  safe_remove "$staged"
  safe_remove "$backup"
  /usr/bin/ditto "$built_app" "$staged"
  if [[ -d "$destination" ]]; then
    /bin/mv "$destination" "$backup"
  fi
  if ! /bin/mv "$staged" "$destination"; then
    [[ -d "$backup" ]] && /bin/mv "$backup" "$destination"
    return 1
  fi
  /usr/bin/codesign --verify --deep --strict --verbose=2 "$destination"
}

install_bundle "$installed_app"
install_bundle "$distributable_app"
verify_source_parity "$installed_app"
verify_source_parity "$distributable_app"
verify_network_plist "$installed_app"
verify_network_plist "$distributable_app"
verify_signer "$installed_app"
verify_signer "$distributable_app"

safe_remove "$archive"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$built_app" "$archive"
archive_verify="$build_root/archive-verify"
safe_remove "$archive_verify"
/bin/mkdir "$archive_verify"
/usr/bin/ditto -x -k "$archive" "$archive_verify"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$archive_verify/Activity Monitor.app"
verify_source_parity "$archive_verify/Activity Monitor.app"
verify_network_plist "$archive_verify/Activity Monitor.app"
verify_signer "$archive_verify/Activity Monitor.app"

print "Activity Monitor $release_version packaged as a self-contained $target_arch app."
print "Signing: $signing_label ($signing_mode)"
print "Installed: $installed_app"
print "Download archive: $archive"
