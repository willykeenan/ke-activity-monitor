#!/usr/bin/env python3
"""User-initiated, privacy-bounded internet quality diagnostics.

The optimizer measures the Mac and its local radio environment.  It never
pretends that changing the client interface changes an associated Wi-Fi
router: CoreWLAN explicitly forbids setting the client channel while the
interface is associated.  Router changes therefore remain an authenticated,
user-visible handoff until a vendor-specific router adapter is explicitly
authorized.
"""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from collections import deque
import ipaddress
import json
import math
import re
import subprocess
import threading


SCHEMA_VERSION = 1
WIFI_SCAN_TIMEOUT_SECONDS = 15.0
NETWORK_QUALITY_TIMEOUT_SECONDS = 60.0
MAX_NEARBY_NETWORKS = 512
MAX_NETWORK_QUALITY_BYTES = 512 * 1024
CORE_WLAN_FRAMEWORK = "/System/Library/Frameworks/CoreWLAN.framework"
NETWORK_QUALITY_PATH = "/usr/bin/networkQuality"
ROUTE_PATH = "/sbin/route"
OPEN_PATH = "/usr/bin/open"
WIRELESS_DIAGNOSTICS_PATH = "/System/Library/CoreServices/Applications/Wireless Diagnostics.app"
WIFI_SETTINGS_URL = "x-apple.systempreferences:com.apple.wifi-settings-extension"
NETWORK_SETTINGS_URL = "x-apple.systempreferences:com.apple.preference.network"

_INTERFACE_RE = re.compile(r"^[a-z][a-z0-9]{0,15}$")
_PERMISSION_MARKERS = (
    "not permitted",
    "not authorized",
    "permission denied",
    "policy denied",
    "authorization denied",
)
_CHANNEL_BANDS = {1: "2.4 GHz", 2: "5 GHz", 3: "6 GHz"}
_CHANNEL_WIDTHS = {1: 20, 2: 40, 3: 80, 4: 160}
_SECURITY_LABELS = {
    0: "Open",
    1: "WEP",
    2: "WPA Personal",
    3: "WPA/WPA2 mixed",
    4: "WPA2 Personal",
    5: "Personal",
    6: "Dynamic WEP",
    7: "WPA Enterprise",
    8: "WPA/WPA2 Enterprise mixed",
    9: "WPA2 Enterprise",
    10: "Enterprise",
    11: "WPA3 Personal",
    12: "WPA3 Enterprise",
    13: "WPA2/WPA3 Transitional",
    14: "Enhanced Open",
    15: "Enhanced Open Transitional",
}
_WEAK_SECURITY = {0, 1, 2, 3, 6}


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class InternetOptimizerError(RuntimeError):
    """A stable, safe error code with no raw local detail."""

    def __init__(self, code):
        self.code = str(code or "network_internal_error")
        super().__init__(self.code)


def _is_permission_error(error):
    if isinstance(error, PermissionError):
        return True
    code = getattr(error, "code", None)
    try:
        if callable(code):
            code = code()
    except Exception:
        code = None
    if code in {-65570, -65571, -3930, 1, 13}:
        return True
    text = str(error or "").lower()
    return any(marker in text for marker in _PERMISSION_MARKERS)


def _safe_int(value, minimum=None, maximum=None):
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if minimum is not None and result < minimum:
        return None
    if maximum is not None and result > maximum:
        return None
    return result


def _safe_float(value, minimum=None, maximum=None):
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(result):
        return None
    if minimum is not None and result < minimum:
        return None
    if maximum is not None and result > maximum:
        return None
    return result


def _call(obj, name, default=None):
    try:
        method = getattr(obj, name)
        return method() if callable(method) else method
    except Exception as error:
        if _is_permission_error(error):
            raise InternetOptimizerError("permission_denied") from error
        return default


def _channel_projection(channel):
    if channel is None:
        return {"number": None, "band": "Unknown", "widthMHz": None}
    band_value = _safe_int(_call(channel, "channelBand"), 0, 10)
    width_value = _safe_int(_call(channel, "channelWidth"), 0, 10)
    return {
        "number": _safe_int(_call(channel, "channelNumber"), 1, 4096),
        "band": _CHANNEL_BANDS.get(band_value, "Unknown"),
        "widthMHz": _CHANNEL_WIDTHS.get(width_value),
    }


def _interface_name(interface):
    name = str(_call(interface, "interfaceName", "") or "")
    return name if _INTERFACE_RE.fullmatch(name) else None


class CoreWLANProbe:
    """Collect only aggregate radio facts; never return SSID or BSSID values."""

    def __call__(self):
        try:
            import objc

            objc.loadBundle("CoreWLAN", {}, bundle_path=CORE_WLAN_FRAMEWORK)
            client_class = objc.lookUpClass("CWWiFiClient")
            client = client_class.sharedWiFiClient()
            interfaces = list(client.interfaces() or ())
        except Exception as error:
            if _is_permission_error(error):
                raise InternetOptimizerError("permission_denied") from error
            raise InternetOptimizerError("discovery_unavailable") from error

        rows = []
        for interface in interfaces[:16]:
            name = _interface_name(interface)
            if not name:
                continue
            channel = _channel_projection(_call(interface, "wlanChannel"))
            rssi = _safe_int(_call(interface, "rssiValue"), -150, 0)
            noise = _safe_int(_call(interface, "noiseMeasurement"), -150, 0)
            rows.append(
                {
                    "object": interface,
                    "name": name,
                    "powerOn": bool(_call(interface, "powerOn", False)),
                    "serviceActive": bool(_call(interface, "serviceActive", False)),
                    "channel": channel,
                    "rssiDbm": rssi if rssi != 0 else None,
                    "noiseDbm": noise if noise != 0 else None,
                    "transmitRateMbps": _safe_float(_call(interface, "transmitRate"), 0, 100000),
                    "securityCode": _safe_int(_call(interface, "security"), 0, 1000),
                }
            )
        rows.sort(
            key=lambda row: (
                not row["serviceActive"],
                not row["powerOn"],
                not bool(row["channel"]["number"]),
                row["name"],
            )
        )
        selected = rows[0] if rows else None
        if not selected:
            return {"kind": "none", "interfaces": [], "nearby": [], "supportedChannels": []}

        interface = selected.pop("object")
        supported = []
        for channel in list(_call(interface, "supportedWLANChannels", ()) or ())[:512]:
            projected = _channel_projection(channel)
            if projected["number"]:
                supported.append(projected)
        supported.sort(key=lambda row: (row["band"], row["number"], row["widthMHz"] or 0))

        nearby = []
        nearby_capped = False
        if selected["powerOn"] and selected["serviceActive"]:
            try:
                raw = interface.scanForNetworksWithSSID_error_(None, None)
                networks, error = (raw + (None,))[:2] if isinstance(raw, tuple) else (raw, None)
                if error is not None:
                    if _is_permission_error(error):
                        raise InternetOptimizerError("permission_denied")
                    raise InternetOptimizerError("discovery_unavailable")
                network_rows = list(networks or ())
                nearby_capped = len(network_rows) > MAX_NEARBY_NETWORKS
                for network in network_rows[:MAX_NEARBY_NETWORKS]:
                    channel = _channel_projection(_call(network, "wlanChannel"))
                    if not channel["number"]:
                        continue
                    nearby.append(
                        {
                            "channel": channel,
                            "rssiDbm": _safe_int(_call(network, "rssiValue"), -150, 0),
                            "noiseDbm": _safe_int(_call(network, "noiseMeasurement"), -150, 0),
                        }
                    )
            except InternetOptimizerError:
                raise
            except Exception as error:
                if _is_permission_error(error):
                    raise InternetOptimizerError("permission_denied") from error
                raise InternetOptimizerError("discovery_unavailable") from error

        selected["connected"] = bool(selected["channel"]["number"] and selected["rssiDbm"] is not None)
        selected["security"] = _SECURITY_LABELS.get(selected.pop("securityCode"), "Unknown")
        selected["snrDb"] = _snr(selected.get("rssiDbm"), selected.get("noiseDbm"))
        return {
            "kind": "wifi",
            "current": selected,
            "interfaces": [
                {key: value for key, value in row.items() if key != "object"}
                for row in rows
            ],
            "nearby": nearby,
            "nearbyMeasured": bool(selected["powerOn"] and selected["serviceActive"]),
            "nearbyCapped": nearby_capped,
            "supportedChannels": supported,
        }


def _snr(rssi, noise):
    if rssi is None or noise is None:
        return None
    value = rssi - noise
    return value if -20 <= value <= 100 else None


def default_route_probe():
    """Read the local route table without sending traffic."""
    try:
        result = subprocess.run(
            [ROUTE_PATH, "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return {"interface": None, "gateway": None, "adminUrl": None}
    if result.returncode != 0:
        return {"interface": None, "gateway": None, "adminUrl": None}
    gateway_match = re.search(r"^\s*gateway:\s*(\S+)\s*$", result.stdout or "", re.MULTILINE)
    interface_match = re.search(r"^\s*interface:\s*(\S+)\s*$", result.stdout or "", re.MULTILINE)
    gateway = gateway_match.group(1) if gateway_match else None
    interface = interface_match.group(1) if interface_match else None
    if not interface or not _INTERFACE_RE.fullmatch(interface):
        interface = None
    admin_url = _private_router_url(gateway)
    return {"interface": interface, "gateway": gateway if admin_url else None, "adminUrl": admin_url}


def _private_router_url(value):
    try:
        address = ipaddress.ip_address(str(value or ""))
    except ValueError:
        return None
    if address.version != 4:
        return None
    allowed = any(
        address in ipaddress.ip_network(block)
        for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )
    return f"http://{address.compressed}/" if allowed else None


def _signal_weight(rssi):
    value = _safe_int(rssi, -150, 0)
    if value is None:
        return 1.0
    return round(max(0.5, min(8.0, (value + 100) / 8.0)), 3)


def _channel_pressure(nearby, band, target):
    pressure = 0.0
    count = 0
    for row in nearby:
        channel = row.get("channel") or {}
        if channel.get("band") != band:
            continue
        number = _safe_int(channel.get("number"), 1, 4096)
        if number is None:
            continue
        overlap = 1.0
        if band == "2.4 GHz":
            overlap = max(0.0, 1.0 - abs(number - target) / 5.0)
        elif number != target:
            overlap = 0.0
        if overlap:
            pressure += _signal_weight(row.get("rssiDbm")) * overlap
            count += 1
    return round(pressure, 2), count


def _channel_plan(probe):
    current = probe.get("current") or {}
    band = (current.get("channel") or {}).get("band") or "Unknown"
    current_number = _safe_int((current.get("channel") or {}).get("number"), 1, 4096)
    nearby = list(probe.get("nearby") or ())[:MAX_NEARBY_NETWORKS]
    if band == "2.4 GHz":
        supported = {
            row.get("number")
            for row in (probe.get("supportedChannels") or ())
            if row.get("band") == band
        }
        candidates = [number for number in (1, 6, 11) if not supported or number in supported]
    else:
        candidates = sorted(
            {
                row.get("channel", {}).get("number")
                for row in nearby
                if row.get("channel", {}).get("band") == band
            }
            | ({current_number} if current_number else set())
        )[:24]
    rows = []
    for number in candidates:
        if not isinstance(number, int):
            continue
        pressure, count = _channel_pressure(nearby, band, number)
        rows.append(
            {
                "channel": number,
                "band": band,
                "pressure": pressure,
                "nearbyCount": count,
                "current": number == current_number,
            }
        )
    maximum = max([row["pressure"] for row in rows] or [0.0])
    for row in rows:
        row["pressurePercent"] = round((row["pressure"] / maximum) * 100) if maximum else 0
    rows.sort(key=lambda row: (row["pressure"], row["channel"]))
    best = rows[0] if rows else None
    current_row = next((row for row in rows if row["current"]), None)
    suggested = None
    if band == "2.4 GHz" and best and current_row and best["channel"] != current_number:
        if current_row["pressure"] >= best["pressure"] + 2.0:
            suggested = best["channel"]
    display_rows = sorted(rows, key=lambda row: row["channel"])
    measured = bool(probe.get("nearbyMeasured")) if "nearbyMeasured" in probe else bool(nearby)
    return {
        "measured": measured,
        "partial": bool(probe.get("nearbyCapped")),
        "nearbyObservationCount": len(nearby),
        "band": band,
        "currentChannel": current_number,
        "channels": display_rows,
        "recommendation": {
            "mode": "router-auto",
            "label": "Use Auto channel on the router",
            "suggestedChannel": suggested,
            "canApply": False,
            "status": "router-authorization-required",
            "reason": _channel_reason(band, suggested, measured),
        },
    }


def _channel_reason(band, suggested, measured):
    if not measured:
        return "Nearby channel pressure was unavailable. Keep the router on Auto and use Wireless Diagnostics for deeper analysis."
    if suggested:
        return f"Auto is preferred; if Auto is unavailable, channel {suggested} was the quietest non-overlapping 2.4 GHz choice in this scan."
    if band == "2.4 GHz":
        return "Auto is preferred. If you configure 2.4 GHz manually, use 20 MHz width and the quietest non-overlapping channel."
    if band in {"5 GHz", "6 GHz"}:
        return f"Auto channel and all supported widths are preferred on {band}; the router can account for DFS and changing conditions."
    return "Keep the router on Auto unless a measured scan and the router administrator support a specific change."


def _finding(identifier, severity, title, detail, action_id=None, action_label=None):
    return {
        "id": identifier,
        "severity": severity,
        "title": title,
        "detail": detail,
        "actionId": action_id,
        "actionLabel": action_label,
    }


def _findings(probe, interference):
    current = probe.get("current") or {}
    findings = []
    if not current.get("connected"):
        return [
            _finding(
                "wifi-not-connected",
                "attention",
                "Wi-Fi is not connected",
                "Connect to the network you want to optimize, then run the analysis again.",
                "open-wifi-settings",
                "Open Wi-Fi Settings",
            )
        ]
    rssi = current.get("rssiDbm")
    snr = current.get("snrDb")
    if rssi is not None and rssi <= -70:
        findings.append(
            _finding(
                "weak-signal",
                "high",
                "Signal is weak",
                "Move closer to the router, reduce obstructions, or add a wired access point before changing software settings.",
                "wireless-diagnostics",
                "Open Wireless Diagnostics",
            )
        )
    elif rssi is not None and rssi <= -62:
        findings.append(
            _finding(
                "signal-headroom",
                "medium",
                "Signal has limited headroom",
                "Placement or a nearer access point may improve stability under load.",
            )
        )
    if snr is not None and snr < 20:
        findings.append(
            _finding(
                "low-snr",
                "high",
                "Interference is crowding the signal",
                "The measured signal-to-noise ratio is low. Prefer router Auto channel and review access-point placement.",
                "open-router-settings",
                "Open router settings",
            )
        )
    elif snr is not None and snr < 30:
        findings.append(
            _finding(
                "snr-headroom",
                "medium",
                "Signal-to-noise headroom is moderate",
                "Router Auto channel and better placement can reduce retries during busy periods.",
            )
        )
    channel = current.get("channel") or {}
    if channel.get("band") == "2.4 GHz" and channel.get("widthMHz") not in {None, 20}:
        findings.append(
            _finding(
                "wide-24ghz",
                "high",
                "2.4 GHz channel is wider than 20 MHz",
                "Apple recommends 20 MHz on 2.4 GHz to reduce interference and reliability problems.",
                "open-router-settings",
                "Open router settings",
            )
        )
    recommendation = interference.get("recommendation") or {}
    if recommendation.get("suggestedChannel"):
        findings.append(
            _finding(
                "crowded-channel",
                "high",
                "A quieter 2.4 GHz channel was observed",
                recommendation.get("reason"),
                "open-router-settings",
                "Open router settings",
            )
        )
    security = current.get("security")
    security_code = next((code for code, label in _SECURITY_LABELS.items() if label == security), None)
    if security_code in _WEAK_SECURITY:
        findings.append(
            _finding(
                "weak-security",
                "high",
                "Wi-Fi security is outdated",
                "Use WPA3 Personal or WPA2/WPA3 Transitional. Weak security can also reduce reliability and performance.",
                "open-router-settings",
                "Open router settings",
            )
        )
    if not findings:
        findings.append(
            _finding(
                "radio-healthy",
                "good",
                "The measured Wi-Fi radio path looks healthy",
                "No high-confidence client-side radio fix was found. Measure internet quality to separate ISP, router, and load-related limits.",
                "measure-internet",
                "Measure internet",
            )
        )
    return findings[:12]


def _quality(probe, interference, findings):
    current = probe.get("current") or {}
    if not current.get("connected"):
        return {
            "label": "Not connected",
            "healthScore": None,
            "confidence": "unavailable",
            "headline": "Connect to Wi-Fi before measuring radio quality.",
        }
    score = 100.0
    rssi = current.get("rssiDbm")
    snr = current.get("snrDb")
    if rssi is None:
        score -= 15
    elif rssi <= -75:
        score -= 35
    elif rssi <= -68:
        score -= 22
    elif rssi <= -60:
        score -= 10
    if snr is None:
        score -= 10
    elif snr < 15:
        score -= 30
    elif snr < 25:
        score -= 18
    elif snr < 35:
        score -= 7
    if any(item["id"] == "crowded-channel" for item in findings):
        score -= 18
    if any(item["id"] == "wide-24ghz" for item in findings):
        score -= 12
    if any(item["id"] == "weak-security" for item in findings):
        score -= 12
    score = int(max(0, min(100, round(score))))
    label = "Strong" if score >= 82 else "Good" if score >= 68 else "Fair" if score >= 48 else "Needs attention"
    confidence = "measured" if rssi is not None and snr is not None and interference.get("measured") and not interference.get("partial") else "partial"
    return {
        "label": label,
        "healthScore": score,
        "confidence": confidence,
        "headline": "Radio health is measured separately from internet speed and ISP capacity.",
    }


def _actions(route):
    return [
        {
            "id": "open-router-settings",
            "label": "Open router settings",
            "kind": "guided",
            "available": bool(route.get("adminUrl")),
            "changesSettings": False,
            "disclosure": "Opens the private default-gateway page. You review and authorize every router change.",
        },
        {
            "id": "wireless-diagnostics",
            "label": "Wireless Diagnostics",
            "kind": "diagnostic",
            "available": True,
            "changesSettings": False,
            "disclosure": "Opens Apple's diagnostic tool; it does not change network settings.",
        },
        {
            "id": "open-wifi-settings",
            "label": "Wi-Fi Settings",
            "kind": "settings",
            "available": True,
            "changesSettings": False,
            "disclosure": "Opens System Settings without changing Wi-Fi.",
        },
        {
            "id": "measure-internet",
            "label": "Measure internet (uses data)",
            "kind": "active-test",
            "available": True,
            "changesSettings": False,
            "disclosure": "Runs Apple's networkQuality test. It connects to the internet and uses plan data.",
        },
    ]


def analyze_probe(probe, route=None, observed_at=None):
    """Pure projection used by production and no-I/O regression fixtures."""
    probe = dict(probe or {})
    route = dict(route or {})
    kind = probe.get("kind") if probe.get("kind") in {"wifi", "ethernet", "none"} else "none"
    if kind != "wifi":
        interface = str(probe.get("interface") or "")
        interface = interface if _INTERFACE_RE.fullmatch(interface) else None
        safe_route = route if interface and route.get("interface") == interface else {}
        return {
            "ok": True,
            "schemaVersion": SCHEMA_VERSION,
            "state": "attention",
            "observedAt": observed_at or _utc_now(),
            "connection": {"kind": kind, "connected": kind == "ethernet", "interface": interface},
            "quality": {
                "label": "Wired connection" if kind == "ethernet" else "Not connected",
                "healthScore": None,
                "confidence": "partial" if kind == "ethernet" else "unavailable",
                "headline": "Wi-Fi interference analysis applies only to an active Wi-Fi connection.",
            },
            "interference": {
                "measured": False,
                "partial": False,
                "nearbyObservationCount": 0,
                "band": "Unknown",
                "currentChannel": None,
                "channels": [],
                "recommendation": {
                    "mode": "not-applicable",
                    "label": "No Wi-Fi channel change",
                    "suggestedChannel": None,
                    "canApply": False,
                    "status": "not-applicable",
                    "reason": "No active Wi-Fi radio path was measured.",
                },
            },
            "findings": [
                _finding(
                    "wifi-not-active",
                    "attention",
                    "No active Wi-Fi path to optimize",
                    "Connect to Wi-Fi and run again, or use Measure internet for the active wired connection.",
                    "open-wifi-settings",
                    "Open Wi-Fi Settings",
                )
            ],
            "router": _router_projection(safe_route),
            "actions": _actions(safe_route),
            "activeTest": None,
            "privacy": _privacy_projection(),
        }
    current = dict(probe.get("current") or {})
    current["interface"] = current.pop("name", current.get("interface"))
    probe["current"] = current
    route = route if route.get("interface") == current.get("interface") else {}
    interference = _channel_plan(probe)
    findings = _findings(probe, interference)
    return {
        "ok": True,
        "schemaVersion": SCHEMA_VERSION,
        "state": "complete" if current.get("connected") else "attention",
        "observedAt": observed_at or _utc_now(),
        "connection": {
            "kind": "wifi",
            "interface": current.get("interface"),
            "connected": bool(current.get("connected")),
            "band": (current.get("channel") or {}).get("band"),
            "channel": (current.get("channel") or {}).get("number"),
            "widthMHz": (current.get("channel") or {}).get("widthMHz"),
            "signalDbm": current.get("rssiDbm"),
            "noiseDbm": current.get("noiseDbm"),
            "snrDb": current.get("snrDb"),
            "transmitRateMbps": current.get("transmitRateMbps"),
            "security": current.get("security"),
        },
        "quality": _quality(probe, interference, findings),
        "interference": interference,
        "findings": findings,
        "router": _router_projection(route),
        "actions": _actions(route),
        "activeTest": None,
        "privacy": _privacy_projection(),
    }


def _router_projection(route):
    return {
        "control": "guided",
        "canApplyChannel": False,
        "adminAvailable": bool(route.get("adminUrl")),
        "interface": route.get("interface") if _INTERFACE_RE.fullmatch(str(route.get("interface") or "")) else None,
        "boundary": "Router settings require the router administrator or an explicitly authorized vendor adapter.",
    }


def _privacy_projection():
    return {
        "userInitiated": True,
        "runsOnlyOnRequest": True,
        "internetTrafficUsed": False,
        "nearbyNetworkNamesRead": False,
        "nearbyNetworkIdentifiersRead": False,
        "routerCredentialsAccessed": False,
        "settingsChanged": False,
        "persisted": False,
    }


class NetworkQualityRunner:
    def __call__(self, interface=None):
        command = [NETWORK_QUALITY_PATH]
        if interface and _INTERFACE_RE.fullmatch(str(interface)):
            command.extend(["-I", str(interface)])
        command.append("-c")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=NETWORK_QUALITY_TIMEOUT_SECONDS,
                check=False,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"},
            )
        except subprocess.TimeoutExpired as error:
            raise InternetOptimizerError("request_timeout") from error
        except (OSError, subprocess.SubprocessError) as error:
            if _is_permission_error(error):
                raise InternetOptimizerError("permission_denied") from error
            raise InternetOptimizerError("discovery_unavailable") from error
        stdout = result.stdout or ""
        if result.returncode != 0 or len(stdout.encode("utf-8", "replace")) > MAX_NETWORK_QUALITY_BYTES:
            if _is_permission_error(result.stderr):
                raise InternetOptimizerError("permission_denied")
            raise InternetOptimizerError("discovery_unavailable")
        try:
            payload = json.loads(stdout)
        except (TypeError, ValueError) as error:
            raise InternetOptimizerError("discovery_unavailable") from error
        if not isinstance(payload, dict) or payload.get("error_code") not in (None, 0, "0"):
            raise InternetOptimizerError("discovery_unavailable")
        projected = project_network_quality(payload, interface=interface)
        if all(
            projected.get(key) is None
            for key in ("downloadMbps", "uploadMbps", "idleLatencyMs", "responsivenessRpm")
        ):
            raise InternetOptimizerError("discovery_unavailable")
        if interface and projected.get("interface") != interface:
            raise InternetOptimizerError("discovery_unavailable")
        return projected


def _first_number(payload, *keys):
    for key in keys:
        if key in payload:
            value = _safe_float(payload.get(key), 0, 10**15)
            if value is not None:
                return value
    return None


def project_network_quality(payload, interface=None, observed_at=None):
    """Pure, bounded projection of Apple's computer-readable output."""
    payload = payload if isinstance(payload, dict) else {}
    download_bytes = _first_number(payload, "dl_throughput", "download_throughput")
    upload_bytes = _first_number(payload, "ul_throughput", "upload_throughput")
    base_rtt = _first_number(payload, "base_rtt", "idle_latency")
    responsiveness = _first_number(payload, "responsiveness")
    reported_interface = str(payload.get("interface_name") or interface or "")
    if not _INTERFACE_RE.fullmatch(reported_interface):
        reported_interface = None
    return {
        "ok": True,
        "schemaVersion": SCHEMA_VERSION,
        "state": "measured",
        "observedAt": observed_at or _utc_now(),
        "interface": reported_interface,
        "downloadMbps": round(download_bytes * 8 / 1_000_000, 2) if download_bytes is not None else None,
        "uploadMbps": round(upload_bytes * 8 / 1_000_000, 2) if upload_bytes is not None else None,
        "idleLatencyMs": round(base_rtt, 2) if base_rtt is not None else None,
        "responsivenessRpm": round(responsiveness) if responsiveness is not None else None,
        "usesInternetData": True,
        "serverIdentityVerificationDisabled": False,
        "settingsChanged": False,
    }


def _measurement_delta(before, after):
    before_interface = str((before or {}).get("interface") or "")
    after_interface = str((after or {}).get("interface") or "")
    if (
        not before
        or not after
        or not _INTERFACE_RE.fullmatch(before_interface)
        or before_interface != after_interface
    ):
        return None
    fields = {
        "downloadMbps": "downloadMbps",
        "uploadMbps": "uploadMbps",
        "idleLatencyMs": "idleLatencyMs",
        "responsivenessRpm": "responsivenessRpm",
    }
    result = {}
    for output, key in fields.items():
        old = _safe_float(before.get(key))
        new = _safe_float(after.get(key))
        result[output] = round(new - old, 2) if old is not None and new is not None else None
    return result


def default_opener(target):
    if target not in {WIRELESS_DIAGNOSTICS_PATH, WIFI_SETTINGS_URL, NETWORK_SETTINGS_URL} and not _private_router_url(
        str(target or "").removeprefix("http://").rstrip("/")
    ):
        raise InternetOptimizerError("system_settings_unavailable")
    try:
        result = subprocess.run(
            [OPEN_PATH, target],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise InternetOptimizerError("system_settings_unavailable") from error
    if result.returncode != 0:
        raise InternetOptimizerError("system_settings_unavailable")


class InternetOptimizerService:
    """One-at-a-time, in-memory optimizer with explicit active-test consent."""

    def __init__(
        self,
        wifi_probe=None,
        route_probe=None,
        quality_runner=None,
        opener=None,
        clock=None,
        scan_timeout=WIFI_SCAN_TIMEOUT_SECONDS,
    ):
        self.wifi_probe = wifi_probe or CoreWLANProbe()
        self.route_probe = route_probe or default_route_probe
        self.quality_runner = quality_runner or NetworkQualityRunner()
        self.opener = opener or default_opener
        self.clock = clock or _utc_now
        self.scan_timeout = float(scan_timeout)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ke-internet-optimizer")
        self._lock = threading.RLock()
        self._analysis_future = None
        self._snapshot = None
        self._route = {}
        self._measurements = deque(maxlen=2)
        self._measurement_in_flight = False
        self._analysis_generation = 0
        self._analysis_request_sequence = 0
        self._stopped = False

    def _collect(self):
        return self.wifi_probe(), self.route_probe()

    def analyze(self):
        with self._lock:
            if self._stopped:
                raise InternetOptimizerError("discovery_unavailable")
            if self._analysis_future and not self._analysis_future.done():
                return {
                    "ok": True,
                    "schemaVersion": SCHEMA_VERSION,
                    "state": "busy",
                    "observedAt": self.clock(),
                    "settingsChanged": False,
                }
            future = self._executor.submit(self._collect)
            self._analysis_future = future
            self._analysis_request_sequence += 1
            request_sequence = self._analysis_request_sequence
        try:
            probe, route = future.result(timeout=self.scan_timeout)
        except FutureTimeout as error:
            raise InternetOptimizerError("request_timeout") from error
        except InternetOptimizerError:
            raise
        except Exception as error:
            if _is_permission_error(error):
                raise InternetOptimizerError("permission_denied") from error
            raise InternetOptimizerError("discovery_unavailable") from error
        finally:
            with self._lock:
                if future.done() and self._analysis_future is future:
                    self._analysis_future = None
        snapshot = analyze_probe(probe, route=route, observed_at=self.clock())
        with self._lock:
            if self._stopped:
                raise InternetOptimizerError("discovery_unavailable")
            if request_sequence != self._analysis_request_sequence:
                raise InternetOptimizerError("request_superseded")
            previous_interface = ((self._snapshot or {}).get("connection") or {}).get("interface")
            current_interface = (snapshot.get("connection") or {}).get("interface")
            same_known_interface = (
                isinstance(previous_interface, str)
                and _INTERFACE_RE.fullmatch(previous_interface)
                and previous_interface == current_interface
            )
            if self._snapshot is not None and not same_known_interface:
                self._measurements.clear()
            self._route = dict(route or {})
            if self._measurements:
                latest = self._measurements[-1]
                if latest.get("interface") == current_interface:
                    snapshot["activeTest"] = dict(latest)
            self._analysis_generation += 1
            self._snapshot = snapshot
        return snapshot

    def measure(self):
        with self._lock:
            if self._stopped:
                raise InternetOptimizerError("discovery_unavailable")
            if self._measurement_in_flight:
                raise InternetOptimizerError("discovery_unavailable")
            self._measurement_in_flight = True
            snapshot = self._snapshot
            generation = self._analysis_generation
            interface = ((snapshot or {}).get("connection") or {}).get("interface")
        try:
            result = dict(self.quality_runner(interface) or {})
            with self._lock:
                current_interface = ((self._snapshot or {}).get("connection") or {}).get("interface")
                if (
                    self._snapshot is not snapshot
                    or self._analysis_generation != generation
                    or current_interface != interface
                    or (
                        isinstance(interface, str)
                        and _INTERFACE_RE.fullmatch(interface)
                        and result.get("interface") != interface
                    )
                ):
                    raise InternetOptimizerError("request_superseded")
                previous = self._measurements[-1] if self._measurements else None
                result["comparison"] = _measurement_delta(previous, result)
                self._measurements.append(dict(result))
                if self._snapshot is not None:
                    self._snapshot["activeTest"] = dict(result)
            return result
        finally:
            with self._lock:
                self._measurement_in_flight = False

    def perform_action(self, action_id):
        action = str(action_id or "")
        with self._lock:
            if self._stopped:
                raise InternetOptimizerError("discovery_unavailable")
            route = dict(self._route)
            interface = ((self._snapshot or {}).get("connection") or {}).get("interface")
        if action == "open-router-settings":
            try:
                route = dict(self.route_probe() or {})
            except Exception:
                route = {}
            if route.get("interface") != interface:
                route = {}
            with self._lock:
                self._route = dict(route)
        targets = {
            "wireless-diagnostics": WIRELESS_DIAGNOSTICS_PATH,
            "open-wifi-settings": WIFI_SETTINGS_URL,
            "open-network-settings": NETWORK_SETTINGS_URL,
            "open-router-settings": route.get("adminUrl"),
        }
        target = targets.get(action)
        if not target:
            raise InternetOptimizerError("system_settings_unavailable")
        self.opener(target)
        return {
            "ok": True,
            "schemaVersion": SCHEMA_VERSION,
            "state": "opened",
            "actionId": action,
            "settingsChanged": False,
        }

    def shutdown(self):
        with self._lock:
            self._stopped = True
            future = self._analysis_future
        if future and not future.done():
            future.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)
        return {"ok": True, "schemaVersion": SCHEMA_VERSION, "state": "stopped"}
