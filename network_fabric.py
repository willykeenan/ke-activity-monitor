#!/usr/bin/env python3
"""Truthful local-network discovery and consent-bound KE Link messaging.

The service observes only directly connected network segments. It never claims
that a VLAN-isolated, sleeping, firewalled, or otherwise silent device does not
exist. Discovery is active only while the Network tab asks for it; the KE Link
listener is a separate explicit opt-in.
"""

from __future__ import annotations

import base64
import collections
import concurrent.futures
import ctypes
from datetime import datetime, timezone
import errno
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import select
import secrets
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlparse

import psutil


SCHEMA_VERSION = "ke.activity-monitor-network.v1"
LINK_PROTOCOL = "ke-link.v1"
ACK_LEDGER_SCHEMA = "ke-link-acks.v1"
DIRECT_TTL_SECONDS = 45.0
RECENT_TTL_SECONDS = 120.0
SERVICE_TTL_SECONDS = 120.0
DIRECT_OBSERVATION_SOURCES = frozenset({"bonjour", "connection", "icmp", "ssdp"})
DEVICE_RETENTION_SECONDS = 900.0
DEEP_SCAN_CADENCE_SECONDS = 60.0
MAX_SCAN_HOSTS = 254
MAX_DEVICES = 1024
MAX_SERVICES = 128
MAX_BONJOUR_INSTANCE_BYTES = 63
MAX_DNS_SD_TXT_BYTES = 4096
MAX_MESSAGE_CHARS = 4096
MAX_MESSAGE_BYTES = 16 * 1024
PAIRING_TTL_SECONDS = 300.0
MESSAGE_CLOCK_SKEW_SECONDS = 120.0
AUTH_SESSION_TTL_SECONDS = 45.0
MAX_PEERS = 128
MAX_PEER_STORE_BYTES = 256 * 1024
MAX_IDENTITY_BYTES = 4096
MAX_TLS_MATERIAL_BYTES = 128 * 1024
MAX_NONCES_PER_PEER = 256
MAX_NONCES_GLOBAL = 2048
MAX_RECEIVED_MESSAGE_IDS = 512
RECEIVED_ACK_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_ACK_STORE_BYTES = 256 * 1024
MAX_LISTENER_CONNECTIONS = 12
LISTENER_READ_TIMEOUT_SECONDS = 3.0
TLS_HANDSHAKE_TIMEOUT_SECONDS = 3.0
DISCOVERY_STOP_TIMEOUT_SECONDS = 3.0
ADVERTISER_RETRY_SECONDS = 5.0
GLOBAL_REQUESTS_PER_MINUTE = 240
CLIENT_REQUESTS_PER_MINUTE = 60
PEER_REQUESTS_PER_MINUTE = 120
MAX_CLIENT_RATE_BUCKETS = 512
DNS_SD_PATH = "/usr/bin/dns-sd"
DNS_SERVICE_FLAGS_ADD = 0x2
DNS_SERVICE_ERR_NO_ERROR = 0
DNS_SERVICE_ERR_POLICY_DENIED = -65570
DNS_SERVICE_ERR_NOT_PERMITTED = -65571
OPENSSL_PATH = "/usr/bin/openssl"
PING_PATH = "/sbin/ping"
ARP_PATH = "/usr/sbin/arp"
NDP_PATH = "/usr/sbin/ndp"
ROUTE_PATH = "/sbin/route"
OPEN_PATH = "/usr/bin/open"
LOCAL_NETWORK_SETTINGS_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork"
NETWORK_SETTINGS_URL = "x-apple.systempreferences:com.apple.preference.network"
KE_LINK_TYPE = "_ke-link._tcp.local."
LOCAL_NETWORK_USAGE_DESCRIPTION = (
    "Activity Monitor discovers devices on directly connected local networks "
    "while the Network tab is open. If you explicitly enable KE Link, paired "
    "KE Monitors can remain available for authenticated pairing and plain-text "
    "messages until you disable KE Link."
)
BONJOUR_SERVICE_ALLOWLIST = (
    "_ke-link._tcp",
    "_http._tcp",
    "_https._tcp",
    "_ssh._tcp",
    "_rfb._tcp",
    "_smb._tcp",
    "_ipp._tcp",
    "_printer._tcp",
    "_airplay._tcp",
    "_raop._tcp",
    "_googlecast._tcp",
)
DARWIN_IP_BOUND_IF = getattr(socket, "IP_BOUND_IF", 25)
DARWIN_IPV6_BOUND_IF = getattr(socket, "IPV6_BOUND_IF", 125)

_ERROR_COPY = {
    "action_not_supported": "This device action is not supported.",
    "body_too_large": "The request was larger than KE Link permits.",
    "bonjour_advertisement_unavailable": "KE Link could not advertise on the local network.",
    "connections_unavailable": "Connection activity details are unavailable. Device discovery is still working with other available local signals.",
    "device_not_found": "The selected device is no longer in the live Network snapshot.",
    "discovery_inactive": "Open the Network tab before requesting a scan.",
    "discovery_unavailable": "Local network discovery is temporarily unavailable.",
    "endpoint_invalid": "The KE Link endpoint is invalid or outside the directly connected scope.",
    "identity_store_invalid": "KE Link identity storage failed its privacy checks.",
    "internet_optimizer_unavailable": "Internet optimization could not complete its local Wi-Fi analysis.",
    "internet_quality_unavailable": "The internet quality measurement could not complete.",
    "invalid_json": "The KE Link request body was invalid.",
    "ke_link_invalid": "The KE Link advertisement is incomplete.",
    "ke_link_disabled": "Enable KE Link before pairing a trusted peer.",
    "ke_link_unavailable": "This device is not currently advertising KE Link.",
    "listener_busy": "KE Link is temporarily busy. Try again after the current request finishes.",
    "listener_scope_unavailable": "No directly connected private IPv4 interface is available for KE Link.",
    "message_ack_invalid": "The KE Link acknowledgement failed authentication.",
    "message_delivery_uncertain": "Delivery is uncertain. Retry only with the same message identifier.",
    "message_id_conflict": "The message identifier was already used for different content.",
    "message_invalid": "The message envelope is invalid.",
    "message_rate_limited": "KE Link request limits were reached. Try again later.",
    "message_replay": "The message was already accepted.",
    "message_unauthorized": "The sender is not trusted by this KE Link.",
    "network_internal_error": "The local Network service could not complete this request.",
    "not_found": "The KE Link endpoint does not exist.",
    "pairing_acceptance_invalid": "The peer pairing acceptance was invalid.",
    "pairing_code_invalid": "Enter the complete KE Link pairing code.",
    "pairing_invalid": "Pairing is closed or the request is invalid.",
    "pairing_proof_invalid": "The peer did not prove the displayed pairing code.",
    "permission_denied": "Local Network access is unavailable. Check macOS privacy settings and try again.",
    "ping_unavailable": "No unambiguous local route is available for this device.",
    "recovery_busy": "Connection recovery is already running.",
    "recovery_stale": "Network state changed before recovery could run.",
    "peer_fingerprint_mismatch": "The KE Link certificate fingerprint changed.",
    "peer_not_paired": "Pair this KE Link device before messaging.",
    "peer_response_invalid": "The KE Link peer returned an invalid response.",
    "peer_response_too_large": "The KE Link peer response was too large.",
    "peer_session_required": "Verify a fresh secure session before messaging.",
    "peer_store_insecure": "KE Link peer storage failed its privacy checks.",
    "peer_unavailable": "The trusted KE Link peer has no authenticated local endpoint.",
    "peer_unreachable": "The KE Link peer is unavailable.",
    "request_timeout": "The KE Link request timed out.",
    "service_host_mismatch": "The service host does not match the selected device.",
    "service_not_found": "The advertised service is no longer available.",
    "service_scheme_denied": "This advertised service cannot be opened safely.",
    "store_identity_changed": "KE Link storage changed during validation.",
    "store_not_local": "KE Link storage must be on a local filesystem.",
    "system_settings_unavailable": "System Settings could not be opened. Open Privacy & Security manually.",
    "tls_identity_failed": "KE Link could not create its private TLS identity.",
    "tls_unavailable": "macOS TLS identity tooling is unavailable.",
    "wake_unavailable": "Wake-on-LAN requires one verified local route and a known unicast MAC address.",
    "wifi_diagnostics_permission_denied": "Wi-Fi diagnostics access is unavailable. Review Wi-Fi access in System Settings and try again.",
}

_RECOVERY_PLANS = {
    "restart-discovery": {"kind": "retry", "action": "restart-discovery", "target": "discovery", "label": "Retry discovery", "requiresUserAction": False, "priority": 50},
    "retry-connections": {"kind": "retry", "action": "retry-connections", "target": "active-connections", "label": "Retry connections", "requiresUserAction": False, "priority": 20},
    "open-local-network-settings": {"kind": "settings", "action": "open-local-network-settings", "target": "local-network-permission", "label": "Fix access", "requiresUserAction": True, "priority": 95},
    "open-network-settings": {"kind": "settings", "action": "open-network-settings", "target": "network-interface", "label": "Fix network", "requiresUserAction": True, "priority": 90},
    "open-wifi-settings": {"kind": "settings", "action": "open-wifi-settings", "target": "wifi-interface", "label": "Open Wi-Fi Settings", "requiresUserAction": True, "priority": 95},
    "retry-internet-optimizer": {"kind": "retry", "action": "retry-internet-optimizer", "target": "internet-optimizer", "label": "Retry optimizer", "requiresUserAction": False, "priority": 55},
    "retry-internet-test": {"kind": "retry", "action": "retry-internet-test", "target": "internet-quality", "label": "Retry data test", "requiresUserAction": True, "priority": 55},
    "repair-ke-link": {"kind": "retry", "action": "repair-ke-link", "target": "ke-link-advertiser", "label": "Repair KE Link", "requiresUserAction": False, "priority": 80},
    "enable-ke-link": {"kind": "guided", "action": "enable-ke-link", "target": "ke-link-control", "label": "Show enable control", "requiresUserAction": True, "priority": 75},
    "verify-peer": {"kind": "verify", "action": "verify-peer", "target": "selected-peer", "label": "Reconnect peer", "requiresUserAction": False, "priority": 70},
    "refresh-device": {"kind": "retry", "action": "refresh-device", "target": "selected-device", "label": "Refresh device", "requiresUserAction": False, "priority": 55},
    "retry-message": {"kind": "guided", "action": "retry-message", "target": "pending-message", "label": "Review retry", "requiresUserAction": True, "priority": 65},
    "review-trust": {"kind": "guided", "action": "review-trust", "target": "trust", "label": "Review trust", "requiresUserAction": True, "priority": 100},
    "review-pairing": {"kind": "guided", "action": "review-pairing", "target": "pairing", "label": "Review pairing", "requiresUserAction": True, "priority": 85},
    "review-message": {"kind": "guided", "action": "review-message", "target": "message", "label": "Edit message", "requiresUserAction": True, "priority": 65},
    "review-link": {"kind": "guided", "action": "review-link", "target": "ke-link", "label": "Review Network", "requiresUserAction": True, "priority": 100},
}

_RECOVERY_KIND_BY_CODE = {
    "action_not_supported": "refresh-device",
    "body_too_large": "review-message",
    "bonjour_advertisement_unavailable": "repair-ke-link",
    "connections_unavailable": "retry-connections",
    "device_not_found": "refresh-device",
    "discovery_inactive": "restart-discovery",
    "discovery_unavailable": "restart-discovery",
    "endpoint_invalid": "refresh-device",
    "identity_store_invalid": "review-link",
    "internet_optimizer_unavailable": "retry-internet-optimizer",
    "internet_quality_unavailable": "retry-internet-test",
    "invalid_json": "verify-peer",
    "ke_link_invalid": "refresh-device",
    "ke_link_disabled": "enable-ke-link",
    "ke_link_unavailable": "refresh-device",
    "listener_busy": "repair-ke-link",
    "listener_scope_unavailable": "open-network-settings",
    "message_ack_invalid": "verify-peer",
    "message_delivery_uncertain": "retry-message",
    "message_id_conflict": "review-message",
    "message_invalid": "review-message",
    "message_rate_limited": "retry-message",
    "message_replay": "refresh-device",
    "message_unauthorized": "review-trust",
    "network_internal_error": "review-link",
    "not_found": "refresh-device",
    "pairing_acceptance_invalid": "review-pairing",
    "pairing_code_invalid": "review-pairing",
    "pairing_invalid": "review-pairing",
    "pairing_proof_invalid": "review-pairing",
    "permission_denied": "open-local-network-settings",
    "ping_unavailable": "refresh-device",
    "recovery_busy": "restart-discovery",
    "recovery_stale": "refresh-device",
    "peer_fingerprint_mismatch": "review-trust",
    "peer_not_paired": "review-pairing",
    "peer_response_invalid": "verify-peer",
    "peer_response_too_large": "verify-peer",
    "peer_session_required": "verify-peer",
    "peer_store_insecure": "review-link",
    "peer_unavailable": "verify-peer",
    "peer_unreachable": "verify-peer",
    "request_timeout": "verify-peer",
    "service_host_mismatch": "refresh-device",
    "service_not_found": "refresh-device",
    "service_scheme_denied": "refresh-device",
    "store_identity_changed": "review-link",
    "store_not_local": "review-link",
    "system_settings_unavailable": "open-network-settings",
    "tls_identity_failed": "enable-ke-link",
    "tls_unavailable": "enable-ke-link",
    "wake_unavailable": "refresh-device",
    "wifi_diagnostics_permission_denied": "open-wifi-settings",
}

if set(_RECOVERY_KIND_BY_CODE) != set(_ERROR_COPY):
    raise RuntimeError("Every public Network error must declare one safe recovery path")


def recovery_plan(code, generation=0):
    """Return the bounded user-initiated recovery action for a public error."""
    safe_code = str(code or "network_internal_error")
    if safe_code not in _ERROR_COPY:
        safe_code = "network_internal_error"
    try:
        safe_generation = max(0, int(generation))
    except (TypeError, ValueError):
        safe_generation = 0
    result = dict(_RECOVERY_PLANS[_RECOVERY_KIND_BY_CODE[safe_code]])
    result["generation"] = safe_generation
    return result


def network_error_contract():
    """Expose one immutable-by-copy catalog for the Python bridge and composed UI."""
    return {
        "messages": dict(_ERROR_COPY),
        "recoveries": {code: recovery_plan(code) for code in _ERROR_COPY},
        "recoveryActions": sorted(_RECOVERY_PLANS),
        "recoveryKinds": sorted({plan["kind"] for plan in _RECOVERY_PLANS.values()}),
    }


class NetworkFabricError(RuntimeError):
    def __init__(self, code, message=None, *, attempted=False):
        public_message = _ERROR_COPY.get(str(code), _ERROR_COPY["network_internal_error"])
        super().__init__(public_message if message is None else str(message)[:240])
        self.code = str(code)
        self.public_message = public_message
        self.attempted = bool(attempted)


def public_error(code, source="network", observed_at=None, recovery_generation=0):
    """Return a bounded display-safe error projection with no exception detail."""
    safe_code = str(code or "network_internal_error")
    if safe_code not in _ERROR_COPY:
        safe_code = "network_internal_error"
    safe_source = re.sub(r"[^a-z0-9-]", "-", str(source or "network").lower())[:32].strip("-") or "network"
    result = {
        "source": safe_source,
        "code": safe_code,
        "message": _ERROR_COPY[safe_code],
        "recovery": recovery_plan(safe_code, recovery_generation),
        "observedAt": _utc_iso(time.time() if observed_at is None else observed_at),
    }
    return result


def _utc_iso(epoch=None):
    value = time.time() if epoch is None else float(epoch)
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _same_identity(left, right):
    return (
        int(left.st_dev), int(left.st_ino), stat.S_IFMT(left.st_mode)
    ) == (
        int(right.st_dev), int(right.st_ino), stat.S_IFMT(right.st_mode)
    )


def _close_all(*descriptors):
    """Attempt every close before surfacing the first close failure."""
    first_error = None
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None:
        raise first_error


def _fd_is_local(fd):
    """Fail closed unless Darwin identifies the mounted filesystem as local."""
    if sys.platform != "darwin":
        return False

    class _Fsid(ctypes.Structure):
        _fields_ = [("values", ctypes.c_int32 * 2)]

    class _Statfs(ctypes.Structure):
        _fields_ = [
            ("f_bsize", ctypes.c_uint32),
            ("f_iosize", ctypes.c_int32),
            ("f_blocks", ctypes.c_uint64),
            ("f_bfree", ctypes.c_uint64),
            ("f_bavail", ctypes.c_uint64),
            ("f_files", ctypes.c_uint64),
            ("f_ffree", ctypes.c_uint64),
            ("f_fsid", _Fsid),
            ("f_owner", ctypes.c_uint32),
            ("f_type", ctypes.c_uint32),
            ("f_flags", ctypes.c_uint32),
            ("f_fssubtype", ctypes.c_uint32),
            ("f_fstypename", ctypes.c_char * 16),
            ("f_mntonname", ctypes.c_char * 1024),
            ("f_mntfromname", ctypes.c_char * 1024),
            ("f_reserved", ctypes.c_uint32 * 8),
        ]

    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "fstatfs", None)
    if function is None:
        return False
    function.argtypes = [ctypes.c_int, ctypes.POINTER(_Statfs)]
    function.restype = ctypes.c_int
    details = _Statfs()
    if function(int(fd), ctypes.byref(details)) != 0:
        return False
    # Darwin MNT_LOCAL from sys/mount.h.
    return bool(int(details.f_flags) & 0x00001000)


def _safe_display_label(value, fallback, limit=80):
    text = re.sub(r"\s+", " ", str(value or "").strip())
    if not text or len(text) > int(limit) or any(ord(character) < 32 for character in text):
        return fallback
    if "/" in text or "\\" in text or "://" in text or re.search(r"(?:^|\s)~(?:/|$)", text):
        return fallback
    if re.search(r"(?i)(?:\b(?:bearer|password|secret|token|api[-_ ]?key)\b|\b(?:sk|ghp|github_pat)[-_]?[A-Za-z0-9_-]{12,})", text):
        return fallback
    return text


def _bonjour_instance_record(value):
    """Return exact private bytes/text/key for one native DNS-SD instance."""
    if isinstance(value, bytes):
        encoded = bytes(value)
        try:
            text = encoded.decode("utf-8", errors="strict")
        except UnicodeError:
            return None
    elif isinstance(value, str):
        text = value
        try:
            encoded = text.encode("utf-8", errors="strict")
        except UnicodeError:
            return None
    else:
        return None
    # DNSServiceBrowse returns an unescaped UTF-8 C string. Preserve every
    # legal byte, including CR/LF and edge whitespace, without normalization.
    # NUL cannot be represented inside that C-string boundary.
    if not encoded or len(encoded) > MAX_BONJOUR_INSTANCE_BYTES or b"\x00" in encoded:
        return None
    return {
        "bytes": encoded,
        "text": text,
        "key": f"bonjour-instance:{_sha(encoded)}",
    }


def _bonjour_instance_key(value):
    """Return a bounded opaque identity for exact native instance bytes."""
    record = _bonjour_instance_record(value)
    return record["key"] if record else None


def _validated_bonjour_instance_key(value):
    text = str(value or "")
    return text if re.fullmatch(r"bonjour-instance:[a-f0-9]{64}", text) else None


def _safe_peer_name(value):
    return _safe_display_label(value, "KE Link peer", 80)


def _decode_secret(value):
    text = str(value or "")
    if len(text) != 44 or not re.fullmatch(r"[A-Za-z0-9_-]{43}=", text):
        return None
    try:
        decoded = base64.b64decode(text.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError):
        return None
    return decoded if len(decoded) == 32 else None


def _clean_interface(value):
    interface = str(value or "").strip()
    if not interface or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", interface):
        return None
    return interface


def _interface_scope(value):
    """Classify interfaces once so discovery, listeners, and UI agree."""
    name = (_clean_interface(value) or "").lower()
    if not name:
        return "excluded"
    if name.startswith("lo"):
        return "loopback"
    if name.startswith(("awdl", "llw", "p2p")):
        return "peer-to-peer"
    if name.startswith((
        "utun", "ppp", "ipsec", "tun", "tap", "wg", "wireguard",
        "tailscale", "gif", "stf",
    )):
        return "tunnel"
    return "local"


def _split_ip_scope(value):
    raw = str(value or "").strip().replace("%25", "%")
    if raw.count("%") > 1:
        return None, None
    if "%" in raw:
        raw, scope = raw.rsplit("%", 1)
        scope = _clean_interface(scope)
        if not scope:
            return None, None
    else:
        scope = None
    try:
        return ipaddress.ip_address(raw), scope
    except ValueError:
        return None, None


def _clean_endpoint_host(value, *, allow_loopback=False, interface=None):
    raw = str(value or "").strip().rstrip(".")
    address, supplied_scope = _split_ip_scope(raw)
    if address is not None:
        expected_scope = _clean_interface(interface)
        if supplied_scope and (address.version != 6 or not address.is_link_local):
            return None
        if supplied_scope and expected_scope and supplied_scope != expected_scope:
            return None
        scope = supplied_scope or (expected_scope if address.version == 6 and address.is_link_local else None)
        if address.is_unspecified or address.is_multicast:
            return None
        if address.is_loopback:
            return str(address) if allow_loopback else None
        return f"{address}%{scope}" if scope else str(address)
    if "%" in raw:
        return None
    hostname = _clean_hostname(raw)
    if hostname and hostname.lower().endswith(".local"):
        return hostname.lower()
    return None


class _SecureDirectory:
    """Descriptor-bound private storage rooted at a validated local directory."""

    def __init__(self, path, local_checker=None):
        self.path = Path(os.path.abspath(os.path.expanduser(str(path))))
        self.local_checker = local_checker or _fd_is_local

    @staticmethod
    def _flags(directory=False, nonblock=False):
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        if directory:
            flags |= getattr(os, "O_DIRECTORY", 0)
        if nonblock:
            flags |= getattr(os, "O_NONBLOCK", 0)
        return flags

    def _open_root(self, create=False):
        if not self.path.is_absolute() or self.path == Path("/"):
            raise NetworkFabricError("peer_store_insecure")
        descriptor = os.open("/", self._flags(directory=True))
        try:
            components = self.path.parts[1:]
            for index, component in enumerate(components):
                if component in {"", ".", ".."} or "/" in component:
                    raise NetworkFabricError("peer_store_insecure")
                last = index == len(components) - 1
                try:
                    child = os.open(component, self._flags(directory=True), dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    child = os.open(component, self._flags(directory=True), dir_fd=descriptor)
                metadata = os.fstat(child)
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(child)
                    raise NetworkFabricError("peer_store_insecure")
                if metadata.st_uid not in ({os.getuid()} if last else {0, os.getuid()}):
                    os.close(child)
                    raise NetworkFabricError("peer_store_insecure")
                if last and metadata.st_mode & 0o077:
                    os.close(child)
                    raise NetworkFabricError("peer_store_insecure")
                os.close(descriptor)
                descriptor = child
            metadata = os.fstat(descriptor)
            if not self.local_checker(descriptor):
                raise NetworkFabricError("store_not_local")
            current = os.stat(self.path, follow_symlinks=False)
            if not _same_identity(metadata, current):
                raise NetworkFabricError("store_identity_changed")
            return descriptor, metadata
        except Exception:
            os.close(descriptor)
            raise

    def _root_unchanged(self, metadata):
        try:
            current = os.stat(self.path, follow_symlinks=False)
        except OSError as error:
            raise NetworkFabricError("store_identity_changed") from error
        if not _same_identity(metadata, current):
            raise NetworkFabricError("store_identity_changed")

    @staticmethod
    def _validate_file(metadata, cap):
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
            or metadata.st_size < 0
            or metadata.st_size > int(cap)
        ):
            raise NetworkFabricError("peer_store_insecure")

    @staticmethod
    def _safe_name(name):
        value = str(name or "")
        if not value or value in {".", ".."} or "/" in value or "\\" in value:
            raise NetworkFabricError("peer_store_insecure")
        return value

    def read_bytes(self, name, cap):
        name = self._safe_name(name)
        root_fd, root_metadata = self._open_root(create=False)
        file_fd = None
        try:
            file_fd = os.open(name, self._flags(nonblock=True), dir_fd=root_fd)
            before = os.fstat(file_fd)
            self._validate_file(before, cap)
            chunks = []
            remaining = int(cap) + 1
            while remaining > 0:
                chunk = os.read(file_fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > int(cap):
                raise NetworkFabricError("peer_store_insecure")
            after = os.fstat(file_fd)
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if not _same_identity(before, after) or not _same_identity(before, current):
                raise NetworkFabricError("store_identity_changed")
            self._root_unchanged(root_metadata)
            return data
        finally:
            _close_all(file_fd, root_fd)

    def open_descriptor(self, name, cap):
        name = self._safe_name(name)
        root_fd, root_metadata = self._open_root(create=False)
        file_fd = None
        try:
            file_fd = os.open(name, self._flags(nonblock=True), dir_fd=root_fd)
            metadata = os.fstat(file_fd)
            self._validate_file(metadata, cap)
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if not _same_identity(metadata, current):
                raise NetworkFabricError("store_identity_changed")
            self._root_unchanged(root_metadata)
            result, file_fd = file_fd, None
            return result
        finally:
            _close_all(file_fd, root_fd)

    def write_bytes(self, name, data, cap):
        name = self._safe_name(name)
        payload = bytes(data)
        if len(payload) > int(cap):
            raise NetworkFabricError("peer_store_insecure")
        root_fd, root_metadata = self._open_root(create=True)
        temporary = None
        file_fd = None
        existing_fd = None
        try:
            try:
                existing_fd = os.open(name, self._flags(nonblock=True), dir_fd=root_fd)
            except FileNotFoundError:
                existing_metadata = None
            else:
                existing_metadata = os.fstat(existing_fd)
                self._validate_file(existing_metadata, cap)
                current_existing = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if not _same_identity(existing_metadata, current_existing):
                    raise NetworkFabricError("store_identity_changed")
            for _attempt in range(8):
                temporary = f".{name}.{secrets.token_hex(12)}.tmp"
                try:
                    file_fd = os.open(
                        temporary,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=root_fd,
                    )
                    break
                except FileExistsError:
                    temporary = None
            if file_fd is None or temporary is None:
                raise NetworkFabricError("peer_store_insecure")
            offset = 0
            while offset < len(payload):
                offset += os.write(file_fd, payload[offset:])
            os.fchmod(file_fd, 0o600)
            os.fsync(file_fd)
            written = os.fstat(file_fd)
            self._validate_file(written, cap)
            self._root_unchanged(root_metadata)
            try:
                destination = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                destination = None
            if existing_metadata is None:
                if destination is not None:
                    raise NetworkFabricError("store_identity_changed")
            elif (
                destination is None
                or not _same_identity(existing_metadata, destination)
                or not _same_identity(existing_metadata, os.fstat(existing_fd))
            ):
                raise NetworkFabricError("store_identity_changed")
            os.replace(temporary, name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            temporary = None
            os.fsync(root_fd)
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            self._validate_file(current, cap)
            if not _same_identity(written, current):
                raise NetworkFabricError("store_identity_changed")
            self._root_unchanged(root_metadata)
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=root_fd)
                except FileNotFoundError:
                    pass
            _close_all(file_fd, existing_fd, root_fd)


def _normalize_mac(value):
    raw = str(value or "").strip().lower().replace("-", ":")
    pieces = raw.split(":")
    if len(pieces) != 6:
        return None
    try:
        octets = [int(piece, 16) for piece in pieces]
    except ValueError:
        return None
    if any(item < 0 or item > 255 for item in octets):
        return None
    if all(item == 0 for item in octets) or all(item == 255 for item in octets):
        return None
    return ":".join(f"{item:02x}" for item in octets)


def _unicast_mac(value):
    normalized = _normalize_mac(value)
    if not normalized:
        return None
    first = int(normalized.split(":", 1)[0], 16)
    return normalized if not (first & 1) else None


def _clean_hostname(value):
    host = str(value or "").strip().rstrip(".")
    if not host or len(host) > 253 or any(ord(char) < 32 or ord(char) > 126 for char in host):
        return None
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        return None
    return host.lower()


def _clean_ip(value, interface=None):
    address, supplied_scope = _split_ip_scope(value)
    if address is None:
        return None
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        return None
    expected_scope = _clean_interface(interface)
    if supplied_scope and (address.version != 6 or not address.is_link_local):
        return None
    if supplied_scope and expected_scope and supplied_scope != expected_scope:
        return None
    scope = supplied_scope or (expected_scope if address.version == 6 and address.is_link_local else None)
    return f"{address}%{scope}" if scope else str(address)


def _ip_address(value):
    address, _scope = _split_ip_scope(value)
    return address


def _ip_scope(value):
    address, scope = _split_ip_scope(value)
    return scope if address is not None else None


def _address_key(value, interface=None):
    clean = _clean_ip(value, interface)
    if not clean:
        return None
    scope = _clean_interface(interface) or _ip_scope(clean)
    return f"{clean}|{scope or '-'}"


def _own_address_key(value, interface=None):
    clean = _clean_ip(value, interface)
    address = _ip_address(clean) if clean else None
    if address is None:
        return None
    return _address_key(clean, interface) if address.is_link_local else _address_key(str(address))


def _ip_sort_key(value):
    address = _ip_address(value)
    return (address.version if address else 99, int(address) if address else 0, _ip_scope(value) or "")


def _permission_denied_error(error):
    if isinstance(error, NetworkFabricError):
        return error.code == "permission_denied"
    if isinstance(error, PermissionError):
        return True
    if isinstance(error, psutil.AccessDenied):
        return True
    return isinstance(error, OSError) and getattr(error, "errno", None) in {errno.EACCES, errno.EPERM}


def _permission_denied_output(value):
    text = str(value or "")[:4096].lower()
    return bool(re.search(r"(?:operation not permitted|permission denied|not authorized|local network.*denied|policy.*denied)", text))


def _run_command(args, timeout=1.5):
    try:
        return subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=float(timeout),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return subprocess.CompletedProcess(list(args), 127, "", str(error))


def _capture_process(args, duration, stop_event=None):
    if stop_event is not None and stop_event.is_set():
        return ""
    process = None
    terminated = False
    try:
        if stop_event is not None and stop_event.is_set():
            return ""
        process = subprocess.Popen(
            list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        deadline = time.monotonic() + max(0.1, float(duration))
        while time.monotonic() < deadline:
            if stop_event is not None and stop_event.is_set():
                break
            if process.poll() is not None:
                break
            time.sleep(0.05)
        if process.poll() is None:
            terminated = True
            process.terminate()
        try:
            output, _ = process.communicate(timeout=0.75)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=0.75)
        output = output or ""
        if _permission_denied_output(output):
            raise NetworkFabricError("permission_denied")
        if not terminated and process.returncode not in {0, None}:
            raise NetworkFabricError("discovery_unavailable")
        return output
    except (OSError, subprocess.SubprocessError) as error:
        if process is not None and process.poll() is None:
            process.kill()
        if _permission_denied_error(error):
            raise NetworkFabricError("permission_denied") from error
        raise NetworkFabricError("discovery_unavailable") from error


def parse_arp(text):
    rows = []
    pattern = re.compile(
        r"\(([^)]+)\)\s+at\s+([0-9a-fA-F:-]+|\(incomplete\))\s+on\s+(\S+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(str(text or "")):
        mac = _normalize_mac(match.group(2))
        interface = _clean_interface(match.group(3))
        address = _clean_ip(match.group(1), interface)
        if mac and address:
            rows.append({"ip": address, "mac": mac, "interface": interface})
    return rows


def parse_ndp(text):
    rows = []
    for line in str(text or "").splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        interface = _clean_interface(fields[2])
        address = _clean_ip(fields[0], interface)
        mac = _normalize_mac(fields[1])
        if address and mac and interface:
            rows.append({"ip": address, "mac": mac, "interface": interface})
    return rows


def parse_default_route(text):
    raw_gateway = interface = None
    for line in str(text or "").splitlines():
        match = re.match(r"\s*(gateway|interface):\s*(\S+)", line)
        if not match:
            continue
        if match.group(1) == "gateway":
            raw_gateway = match.group(2)
        else:
            interface = _clean_interface(match.group(2))
    gateway = _clean_ip(raw_gateway, interface)
    return {"gateway": gateway, "interface": interface}


def parse_dns_sd_browse(text):
    """Reject dns-sd browse text: it cannot preserve arbitrary name bytes.

    The command prints the unescaped service name as a line-final ``%s``.
    CR/LF are legal service-name bytes, so neither universal-newline text nor
    raw line splitting can distinguish records from instance content. Runtime
    browse identity therefore comes only from ``DNSServiceBrowse`` callbacks.
    """
    del text
    return []


_DNS_SERVICE_BROWSE_REPLY = ctypes.CFUNCTYPE(
    None,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_int32,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_void_p,
)
_DNS_SERVICE_RESOLVE_REPLY = ctypes.CFUNCTYPE(
    None,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_int32,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_uint16,
    ctypes.c_uint16,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_void_p,
)
_DNS_SD_NATIVE_LIBRARY = None
_DNS_SD_NATIVE_LOCK = threading.Lock()


def _dns_sd_native_library():
    """Load the process-exported Darwin DNS-SD API once, without a CLI."""
    global _DNS_SD_NATIVE_LIBRARY
    if sys.platform != "darwin":
        return None
    with _DNS_SD_NATIVE_LOCK:
        if _DNS_SD_NATIVE_LIBRARY is False:
            return None
        if _DNS_SD_NATIVE_LIBRARY is not None:
            return _DNS_SD_NATIVE_LIBRARY
        try:
            library = ctypes.CDLL(None)
            library.DNSServiceBrowse.argtypes = [
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_char_p,
                ctypes.c_char_p,
                _DNS_SERVICE_BROWSE_REPLY,
                ctypes.c_void_p,
            ]
            library.DNSServiceBrowse.restype = ctypes.c_int32
            library.DNSServiceResolve.argtypes = [
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_char_p,
                _DNS_SERVICE_RESOLVE_REPLY,
                ctypes.c_void_p,
            ]
            library.DNSServiceResolve.restype = ctypes.c_int32
            library.DNSServiceRefSockFD.argtypes = [ctypes.c_void_p]
            library.DNSServiceRefSockFD.restype = ctypes.c_int
            library.DNSServiceProcessResult.argtypes = [ctypes.c_void_p]
            library.DNSServiceProcessResult.restype = ctypes.c_int32
            library.DNSServiceRefDeallocate.argtypes = [ctypes.c_void_p]
            library.DNSServiceRefDeallocate.restype = None
        except (AttributeError, OSError, TypeError):
            _DNS_SD_NATIVE_LIBRARY = False
            return None
        _DNS_SD_NATIVE_LIBRARY = library
        return library


def _dns_sd_native_browse_row(flags, interface_index, service_name, regtype, domain):
    """Project one byte-exact callback into a private, bounded browse row."""
    record = _bonjour_instance_record(service_name)
    if not record:
        return None
    try:
        type_name = bytes(regtype).decode("utf-8", errors="strict")
        domain_name = bytes(domain).decode("utf-8", errors="strict")
        index = int(interface_index)
        event_flags = int(flags)
    except (TypeError, ValueError, UnicodeError):
        return None
    if (
        index <= 0
        or index > 0xFFFFFFFF
        or type_name.lower().rstrip(".") not in BONJOUR_SERVICE_ALLOWLIST
        or domain_name.lower() != "local."
        or len(type_name.encode("utf-8")) > 255
        or len(domain_name.encode("utf-8")) > 1008
        or "\x00" in type_name
        or "\x00" in domain_name
    ):
        return None
    return {
        "event": "add" if event_flags & DNS_SERVICE_FLAGS_ADD else "remove",
        "interfaceIndex": index,
        "domain": domain_name,
        "type": type_name,
        "name": record["text"],
        "instanceKey": record["key"],
    }


def _dns_sd_error(code):
    if int(code) in {
        DNS_SERVICE_ERR_POLICY_DENIED,
        DNS_SERVICE_ERR_NOT_PERMITTED,
    }:
        return NetworkFabricError("permission_denied")
    return NetworkFabricError("discovery_unavailable")


def _native_dns_sd_browse(type_name, interface_index, duration, stop_event=None):
    """Browse one allowlisted type via the exact native callback boundary."""
    if stop_event is not None and stop_event.is_set():
        return []
    short = str(type_name or "").rstrip(".")
    if short not in BONJOUR_SERVICE_ALLOWLIST:
        return []
    try:
        index = int(interface_index)
    except (TypeError, ValueError):
        return []
    if index <= 0 or index > 0xFFFFFFFF:
        return []
    library = _dns_sd_native_library()
    if library is None:
        raise NetworkFabricError("discovery_unavailable")

    events = []
    callback_errors = []

    def receive(_reference, flags, callback_index, error_code,
                service_name, regtype, reply_domain, _context):
        if int(error_code) != DNS_SERVICE_ERR_NO_ERROR:
            callback_errors.append(int(error_code))
            return
        row = _dns_sd_native_browse_row(
            flags, callback_index, service_name, regtype, reply_domain,
        )
        if row is not None and len(events) < MAX_SERVICES:
            events.append(row)

    callback = _DNS_SERVICE_BROWSE_REPLY(receive)
    reference = ctypes.c_void_p()
    try:
        error_code = library.DNSServiceBrowse(
            ctypes.byref(reference),
            0,
            index,
            short.encode("ascii"),
            b"local.",
            callback,
            None,
        )
        if int(error_code) != DNS_SERVICE_ERR_NO_ERROR or not reference.value:
            raise _dns_sd_error(error_code)
        descriptor = int(library.DNSServiceRefSockFD(reference))
        if descriptor < 0:
            raise NetworkFabricError("discovery_unavailable")
        deadline = time.monotonic() + max(0.05, float(duration))
        while time.monotonic() < deadline and len(events) < MAX_SERVICES:
            if stop_event is not None and stop_event.is_set():
                break
            remaining = max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select([descriptor], [], [], min(0.05, remaining))
            if not readable:
                continue
            error_code = library.DNSServiceProcessResult(reference)
            if int(error_code) != DNS_SERVICE_ERR_NO_ERROR:
                raise _dns_sd_error(error_code)
            if callback_errors:
                raise _dns_sd_error(callback_errors[0])
        if callback_errors:
            raise _dns_sd_error(callback_errors[0])
        return events
    except (OSError, ValueError, TypeError, ctypes.ArgumentError) as error:
        if _permission_denied_error(error):
            raise NetworkFabricError("permission_denied") from error
        raise NetworkFabricError("discovery_unavailable") from error
    finally:
        if reference.value:
            library.DNSServiceRefDeallocate(reference)


def _dns_sd_txt_properties(value):
    """Decode bounded binary DNS-SD TXT data without a textual record layer."""
    if not isinstance(value, bytes) or len(value) > MAX_DNS_SD_TXT_BYTES:
        return None
    properties = {}
    offset = 0
    while offset < len(value):
        size = value[offset]
        offset += 1
        if offset + size > len(value):
            return None
        token = value[offset:offset + size]
        offset += size
        if b"=" not in token:
            continue
        raw_key, raw_value = token.split(b"=", 1)
        try:
            key = raw_key.decode("ascii", errors="strict").lower()
        except UnicodeError:
            return None
        if key not in {"id", "fp", "proto"}:
            continue
        try:
            decoded = raw_value.decode("ascii", errors="strict")
        except UnicodeError:
            continue
        if (
            key in properties
            or not decoded
            or len(raw_value) > 256
        ):
            return None
        valid = (
            re.fullmatch(r"[a-f0-9]{32}", decoded) if key == "id"
            else re.fullmatch(r"[a-f0-9]{64}", decoded) if key == "fp"
            else re.fullmatch(r"1", decoded)
        )
        if not valid:
            continue
        properties[key] = decoded
    return properties


def _dns_sd_native_resolve_row(interface_index, hosttarget, port_network, txt_record):
    """Project one native resolve callback into a bounded service endpoint."""
    try:
        index = int(interface_index)
        host_text = bytes(hosttarget).decode("utf-8", errors="strict")
        port = socket.ntohs(int(port_network))
    except (TypeError, ValueError, UnicodeError, OverflowError):
        return None
    host = _clean_hostname(host_text)
    properties = _dns_sd_txt_properties(txt_record)
    if index <= 0 or index > 0xFFFFFFFF or not host or not (1 <= port <= 65535) or properties is None:
        return None
    return {
        "host": host,
        "port": port,
        "interfaceIndex": index,
        "properties": properties,
    }


def _native_dns_sd_resolve(instance, type_name, interface_index, duration, stop_event=None):
    """Resolve an exact native instance without parsing its textual echo."""
    if stop_event is not None and stop_event.is_set():
        return None
    record = _bonjour_instance_record(instance)
    short = str(type_name or "").rstrip(".")
    try:
        index = int(interface_index)
    except (TypeError, ValueError):
        return None
    if not record or short not in BONJOUR_SERVICE_ALLOWLIST or index <= 0 or index > 0xFFFFFFFF:
        return None
    library = _dns_sd_native_library()
    if library is None:
        raise NetworkFabricError("discovery_unavailable")

    results = []
    callback_errors = []
    callback_complete = []

    def receive(_reference, _flags, callback_index, error_code, _full_name,
                hosttarget, port_network, txt_len, txt_pointer, _context):
        if int(error_code) != DNS_SERVICE_ERR_NO_ERROR:
            callback_errors.append(int(error_code))
            callback_complete.append(True)
            return
        try:
            size = int(txt_len)
            if size < 0 or size > MAX_DNS_SD_TXT_BYTES:
                txt_data = None
            elif size == 0:
                txt_data = b""
            elif not txt_pointer:
                txt_data = None
            else:
                txt_data = ctypes.string_at(txt_pointer, size)
        except (TypeError, ValueError):
            txt_data = None
        if txt_data is not None:
            row = _dns_sd_native_resolve_row(
                callback_index, hosttarget, port_network, txt_data,
            )
            if row is not None:
                results.append(row)
        callback_complete.append(True)

    callback = _DNS_SERVICE_RESOLVE_REPLY(receive)
    reference = ctypes.c_void_p()
    try:
        error_code = library.DNSServiceResolve(
            ctypes.byref(reference),
            0,
            index,
            record["bytes"],
            short.encode("ascii"),
            b"local.",
            callback,
            None,
        )
        if int(error_code) != DNS_SERVICE_ERR_NO_ERROR or not reference.value:
            raise _dns_sd_error(error_code)
        descriptor = int(library.DNSServiceRefSockFD(reference))
        if descriptor < 0:
            raise NetworkFabricError("discovery_unavailable")
        deadline = time.monotonic() + max(0.05, float(duration))
        while time.monotonic() < deadline and not callback_complete:
            if stop_event is not None and stop_event.is_set():
                break
            remaining = max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select([descriptor], [], [], min(0.05, remaining))
            if not readable:
                continue
            error_code = library.DNSServiceProcessResult(reference)
            if int(error_code) != DNS_SERVICE_ERR_NO_ERROR:
                raise _dns_sd_error(error_code)
        if callback_errors:
            raise _dns_sd_error(callback_errors[0])
        return results[0] if results else None
    except (OSError, ValueError, TypeError, ctypes.ArgumentError) as error:
        if _permission_denied_error(error):
            raise NetworkFabricError("permission_denied") from error
        raise NetworkFabricError("discovery_unavailable") from error
    finally:
        if reference.value:
            library.DNSServiceRefDeallocate(reference)


def parse_dns_sd_resolve(text):
    """Reject legacy resolve text; runtime uses native binary callbacks."""
    del text
    return None


def parse_dns_sd_addresses(text, interface=None):
    return [row["address"] for row in parse_dns_sd_address_rows(text, interface)]


def parse_dns_sd_address_events(text, interface=None):
    events = {}
    for line in str(text or "").splitlines():
        fields = line.split()
        try:
            event_index = next(index for index, token in enumerate(fields) if token in {"Add", "Rmv"})
            event = "add" if fields[event_index] == "Add" else "remove"
            interface_index = int(fields[event_index + 2])
        except (StopIteration, IndexError, TypeError, ValueError):
            continue
        for token in reversed(fields):
            address = _clean_ip(token, interface)
            if address:
                key = (interface_index, address)
                events[key] = {
                    "event": event,
                    "interfaceIndex": interface_index,
                    "address": address,
                }
                break
    return list(events.values())


def parse_dns_sd_address_rows(text, interface=None):
    return [
        {"interfaceIndex": row["interfaceIndex"], "address": row["address"]}
        for row in parse_dns_sd_address_events(text, interface)
        if row["event"] == "add"
    ]


def parse_ssdp_response(data, sender_ip=None, interface=None):
    if isinstance(data, bytes):
        text = data.decode("iso-8859-1", errors="replace")
    else:
        text = str(data or "")
    headers = {}
    for line in text.split("\r\n")[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key in {"location", "server", "st", "usn"}:
            headers[key] = value.strip()[:1024]
    address = _clean_ip(sender_ip, interface)
    if not address or not headers:
        return None
    return {"ip": address, **headers}


def _interface_prefix(family, netmask):
    raw = str(netmask or "").split("%", 1)[0]
    if not raw:
        return None
    try:
        if raw.isdigit():
            prefix = int(raw)
        else:
            mask = ipaddress.ip_address(raw)
            if (family == socket.AF_INET and mask.version != 4) or (family == socket.AF_INET6 and mask.version != 6):
                return None
            bits = f"{int(mask):0{mask.max_prefixlen}b}"
            if "01" in bits:
                return None
            prefix = bits.count("1")
    except (ValueError, TypeError):
        return None
    maximum = 32 if family == socket.AF_INET else 128
    return prefix if 0 <= prefix <= maximum else None


def _interface_snapshot():
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    af_link = getattr(psutil, "AF_LINK", object())
    rows = []
    for name in sorted(addresses):
        status = stats.get(name)
        if status is not None and not status.isup:
            continue
        scope = _interface_scope(name)
        row = {
            "name": name,
            "mac": None,
            "addresses": [],
            "networks": [],
            "scanEligible": False,
            "scope": scope,
        }
        for item in addresses[name]:
            if item.family == af_link:
                row["mac"] = _normalize_mac(item.address)
                continue
            if item.family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            raw = str(item.address or "")
            clean = _clean_ip(raw, name)
            if not clean:
                continue
            prefix = _interface_prefix(item.family, item.netmask)
            if prefix is None:
                continue
            try:
                address = _ip_address(clean)
                interface = ipaddress.ip_interface(f"{address}/{prefix}")
            except (ValueError, TypeError):
                continue
            row["addresses"].append(clean)
            row["networks"].append(str(interface.network))
            if (
                item.family == socket.AF_INET
                and interface.ip.is_private
                and scope == "local"
            ):
                row["scanEligible"] = True
        if row["addresses"] or row["mac"]:
            rows.append(row)
    return rows


def _discovery_interface_allowed(interface):
    if not isinstance(interface, dict):
        return False
    name = _clean_interface(interface.get("name"))
    if (
        not name
        or _interface_scope(name) != "local"
        or interface.get("scope") not in {None, "local"}
    ):
        return False
    for value in interface.get("networks") or []:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if not (
            network.is_loopback
            or network.is_multicast
            or network.network_address.is_unspecified
        ):
            return True
    return False


def _network_objects(interfaces):
    result = []
    for interface in interfaces:
        interface_name = _clean_interface(interface.get("name")) if isinstance(interface, dict) else None
        if not interface_name or not _discovery_interface_allowed(interface):
            continue
        for value in interface.get("networks") or []:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            result.append({"interface": interface_name, "network": network})
    return result


def _route_binding(value, interfaces, interface=None, *, allow_loopback=False):
    """Return one exact local route binding or fail closed on ambiguity."""
    requested_interface = _clean_interface(interface)
    clean = _clean_endpoint_host(
        value,
        allow_loopback=allow_loopback,
        interface=requested_interface,
    )
    address = _ip_address(clean) if clean else None
    if address is None:
        return None
    supplied_scope = _ip_scope(clean)
    if supplied_scope:
        requested_interface = supplied_scope
    if address.is_loopback:
        if not allow_loopback:
            return None
        return {
            "address": str(address),
            "interface": requested_interface or "lo0",
            "sourceAddress": str(address),
            "network": str(ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False)),
            "broadcastAddress": str(address),
        }
    matches = []
    for row in interfaces or []:
        if not _discovery_interface_allowed(row):
            continue
        row_interface = _clean_interface(row.get("name"))
        if not row_interface or (requested_interface and row_interface != requested_interface):
            continue
        for network_value in row.get("networks") or []:
            try:
                network = ipaddress.ip_network(network_value, strict=False)
            except ValueError:
                continue
            if network.version != address.version or address not in network:
                continue
            source_addresses = []
            for source_value in row.get("addresses") or []:
                source_clean = _clean_ip(source_value, row_interface)
                source = _ip_address(source_clean) if source_clean else None
                if source is not None and source.version == address.version and source in network:
                    source_addresses.append(source_clean if source.is_link_local else str(source))
            for source_address in sorted(set(source_addresses)):
                matches.append({
                    "address": clean,
                    "interface": row_interface,
                    "sourceAddress": source_address,
                    "network": str(network),
                    "broadcastAddress": str(network.broadcast_address),
                })
    unique = {
        (item["interface"], item["sourceAddress"], item["network"]): item
        for item in matches
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _address_on_segments(value, networks, interface=None):
    clean_interface = _clean_interface(interface)
    clean = _clean_ip(value, clean_interface)
    if not clean:
        return False
    address = _ip_address(clean)
    scope = _ip_scope(clean)
    return any(
        address.version == row["network"].version
        and address in row["network"]
        and (not clean_interface or row["interface"] == clean_interface)
        and (not scope or row["interface"] == scope)
        for row in networks
    )


def _unique_segment_interface(value, networks):
    clean = _clean_ip(value)
    address = _ip_address(clean) if clean else None
    if address is None:
        return None
    matches = {
        row["interface"]
        for row in networks
        if address.version == row["network"].version and address in row["network"]
    }
    return next(iter(matches)) if len(matches) == 1 else None


def _scan_targets(interfaces, own_interfaces=None):
    targets = []
    coverage_limited = False
    global_own = {
        str(address)
        for interface in (own_interfaces if own_interfaces is not None else interfaces)
        for value in interface.get("addresses") or []
        for address in [_ip_address(_clean_ip(value, interface.get("name")))]
        if address is not None and not address.is_link_local
    }
    for interface in interfaces:
        if not interface.get("scanEligible"):
            continue
        interface_name = _clean_interface(interface.get("name"))
        own = {_clean_ip(value, interface_name) for value in interface.get("addresses") or []}
        for network_value in interface.get("networks") or []:
            try:
                network = ipaddress.ip_network(network_value, strict=False)
            except ValueError:
                continue
            if network.version != 4 or not network.network_address.is_private:
                continue
            source_v4 = next((
                str(address)
                for item in own
                for address in [_ip_address(item)]
                if address is not None and address.version == 4 and address in network
            ), None)
            if source_v4 is None:
                continue
            if network.num_addresses > 256:
                own_v4 = ipaddress.ip_address(source_v4)
                if own_v4 is None:
                    continue
                network = ipaddress.ip_network(f"{own_v4}/24", strict=False)
                coverage_limited = True
            for address in network.hosts():
                value = str(address)
                if value not in global_own:
                    targets.append((value, interface_name, str(network), source_v4))
    unique = []
    seen = set()
    for item in targets:
        identity = (item[0], item[1], item[3])
        if identity not in seen:
            seen.add(identity)
            unique.append(item)
        if len(unique) >= MAX_SCAN_HOSTS:
            coverage_limited = coverage_limited or len(targets) > MAX_SCAN_HOSTS
            break
    return unique, coverage_limited


def _default_ping(ip, interface=None, source_address=None, timeout=0.45):
    clean_interface = _clean_interface(interface)
    clean_ip = _clean_ip(ip, clean_interface)
    clean_source = _clean_ip(source_address, clean_interface)
    target = _ip_address(clean_ip)
    source = _ip_address(clean_source)
    if (
        not clean_interface
        or target is None
        or source is None
        or target.version != 4
        or source.version != 4
    ):
        raise NetworkFabricError("endpoint_invalid")
    started = time.monotonic()
    result = _run_command([
        PING_PATH, "-n", "-c", "1", "-W", "250",
        "-b", clean_interface, "-S", str(source), str(target),
    ], timeout=timeout)
    evidence = f"{getattr(result, 'stdout', '')}\n{getattr(result, 'stderr', '')}"
    if _permission_denied_output(evidence):
        raise NetworkFabricError("permission_denied")
    if result.returncode != 0:
        return None
    match = re.search(r"time[=<]([0-9.]+)\s*ms", result.stdout or "")
    return round(float(match.group(1)), 2) if match else round((time.monotonic() - started) * 1000, 2)


def _eligible_interface_rows(interfaces=None):
    source = _interface_snapshot() if interfaces is None else interfaces
    return [item for item in source if _discovery_interface_allowed(item)][:8]


def _default_ssdp(stop_event=None, duration=1.0, interfaces=None):
    if stop_event is not None and stop_event.is_set():
        return []
    observations = []
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    rows = _eligible_interface_rows(interfaces)
    for interface in rows:
        if stop_event is not None and stop_event.is_set():
            break
        interface_name = _clean_interface(interface.get("name"))
        address = next((
            _clean_ip(value, interface_name)
            for value in interface.get("addresses") or []
            if _ip_address(_clean_ip(value, interface_name))
            and _ip_address(_clean_ip(value, interface_name)).version == 4
        ), None)
        if not address:
            continue
        sock = None
        try:
            if stop_event is not None and stop_event.is_set():
                break
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            if stop_event is not None and stop_event.is_set():
                continue
            sock.bind((address, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(address))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.settimeout(0.15)
            if stop_event is not None and stop_event.is_set():
                continue
            sock.sendto(message, ("239.255.255.250", 1900))
            deadline = time.monotonic() + max(0.1, float(duration))
            while time.monotonic() < deadline and len(observations) < 64:
                if stop_event is not None and stop_event.is_set():
                    break
                try:
                    data, sender = sock.recvfrom(64 * 1024)
                except socket.timeout:
                    continue
                row = parse_ssdp_response(data, sender[0], interface_name)
                if row:
                    row["interface"] = interface_name
                    observations.append(row)
        except OSError as error:
            if _permission_denied_error(error):
                raise NetworkFabricError("permission_denied") from error
            raise NetworkFabricError("discovery_unavailable") from error
        finally:
            if sock is not None:
                sock.close()
    return observations


def _dns_type_name(row):
    if row.get("type") in {"_tcp.local.", "_udp.local."}:
        return f"{row.get('name')}.{row.get('type')}"
    return row.get("type")


def _default_mdns(stop_event=None, interfaces=None):
    if stop_event is not None and stop_event.is_set():
        return []
    if sys.platform != "darwin":
        return []
    # Runtime browsing and Info.plist privacy declarations share this exact
    # closed allowlist. Never widen it from unauthenticated enumeration.
    types = BONJOUR_SERVICE_ALLOWLIST
    interface_names = [
        _clean_interface(item.get("name")) for item in _eligible_interface_rows(interfaces)
    ]
    interface_names = [item for item in interface_names if item]
    if not interface_names:
        return []

    def browse(type_name, interface_name):
        if stop_event is not None and stop_event.is_set():
            return None
        short = type_name[:-7] if type_name.endswith(".local.") else type_name.rstrip(".")
        try:
            interface_index = int(socket.if_nametoindex(interface_name))
        except (OSError, TypeError, ValueError):
            return short, interface_name, []
        rows = _native_dns_sd_browse(short, interface_index, 0.7, stop_event)
        if stop_event is not None and stop_event.is_set():
            return None
        final_events = {}
        for row in rows:
            key = (
                row["interfaceIndex"],
                row["domain"],
                row["type"],
                row["instanceKey"],
            )
            final_events[key] = row
        return short, interface_name, list(final_events.values())

    services = []
    withdrawals = []
    browse_errors = []
    browse_items = [(item, interface_name) for interface_name in interface_names for item in types]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        pending = set()
        iterator = iter(browse_items)
        for _index in range(8):
            if stop_event is not None and stop_event.is_set():
                break
            try:
                item, interface_name = next(iterator)
            except StopIteration:
                break
            pending.add(pool.submit(browse, item, interface_name))
        while pending:
            completed, pending = concurrent.futures.wait(
                pending,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if stop_event is not None and stop_event.is_set():
                for future in pending:
                    future.cancel()
                break
            for future in completed:
                try:
                    value = future.result()
                    if value is None:
                        continue
                    short, interface_name, rows = value
                except Exception as error:
                    browse_errors.append(error)
                    continue
                for row in rows:
                    if (
                        str(row.get("domain") or "").lower() != "local."
                        or str(row.get("type") or "").lower().rstrip(".") != short
                    ):
                        continue
                    try:
                        event_interface = _clean_interface(
                            socket.if_indextoname(int(row["interfaceIndex"]))
                        )
                    except (OSError, TypeError, ValueError):
                        continue
                    if event_interface != interface_name:
                        continue
                    instance_key = _validated_bonjour_instance_key(row.get("instanceKey"))
                    if not instance_key:
                        continue
                    if row.get("event") == "remove":
                        withdrawals.append({
                            "withdrawn": True,
                            "withdrawalKind": "service",
                            "type": f"{short}.local.",
                            "name": _safe_display_label(row.get("name"), "Observed service", 160),
                            "instanceKey": instance_key,
                            "interfaceIndex": int(row["interfaceIndex"]),
                            "interface": interface_name,
                            "addresses": [],
                        })
                    else:
                        services.append((
                            short,
                            row["name"],
                            instance_key,
                            row["interfaceIndex"],
                            interface_name,
                        ))
                    if len(services) + len(withdrawals) >= MAX_SERVICES:
                        break
                if len(services) + len(withdrawals) >= MAX_SERVICES:
                    continue
                try:
                    item, interface_name = next(iterator)
                except StopIteration:
                    continue
                if stop_event is None or not stop_event.is_set():
                    pending.add(pool.submit(browse, item, interface_name))

    if any(_permission_denied_error(error) for error in browse_errors):
        raise NetworkFabricError("permission_denied")
    if browse_errors and not services and not withdrawals:
        raise NetworkFabricError("discovery_unavailable")

    def resolve(item):
        if stop_event is not None and stop_event.is_set():
            return None
        type_name, instance, instance_key, interface_index, expected_interface = item
        try:
            interface_name = _clean_interface(socket.if_indextoname(int(interface_index)))
        except (OSError, ValueError):
            return None
        if interface_name != expected_interface:
            return None
        resolved = _native_dns_sd_resolve(
            instance, type_name, interface_index, 0.8, stop_event,
        )
        if stop_event is not None and stop_event.is_set():
            return None
        if not resolved or int(resolved.get("interfaceIndex") or 0) != int(interface_index):
            return None
        try:
            resolved_interface = _clean_interface(
                socket.if_indextoname(int(resolved["interfaceIndex"]))
            )
        except (OSError, ValueError):
            return None
        if resolved_interface != expected_interface:
            return None
        host = resolved.get("host")
        address_output = _capture_process([DNS_SD_PATH, "-i", interface_name, "-G", "v4v6", f"{host}."], 0.65, stop_event) if host else ""
        if stop_event is not None and stop_event.is_set():
            return None
        address_rows = parse_dns_sd_address_events(address_output, interface_name)
        addresses = []
        withdrawn_addresses = []
        for row in address_rows:
            if int(row.get("interfaceIndex") or 0) != int(interface_index):
                return None
            try:
                address_interface = _clean_interface(
                    socket.if_indextoname(int(row["interfaceIndex"]))
                )
            except (OSError, ValueError):
                return None
            if address_interface != expected_interface:
                return None
            if row.get("event") == "remove":
                withdrawn_addresses.append(row["address"])
            else:
                addresses.append(row["address"])
        if not addresses and not withdrawn_addresses:
            return None
        result = {
            "type": f"{type_name}.local." if not type_name.endswith(".local.") else type_name,
            "name": _safe_display_label(instance, "Observed service", 160),
            "instanceKey": instance_key,
            "interfaceIndex": interface_index,
            "interface": interface_name,
            "host": host,
            "port": resolved["port"],
            "properties": resolved["properties"],
            "addresses": addresses,
        }
        if withdrawn_addresses:
            result["withdrawnAddresses"] = withdrawn_addresses
        if not addresses:
            result["withdrawn"] = True
            result["withdrawalKind"] = "address"
        return result

    results = []
    resolve_errors = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        pending = set()
        iterator = iter(services[:MAX_SERVICES])
        for _index in range(8):
            if stop_event is not None and stop_event.is_set():
                break
            try:
                item = next(iterator)
            except StopIteration:
                break
            pending.add(pool.submit(resolve, item))
        while pending:
            completed, pending = concurrent.futures.wait(
                pending,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if stop_event is not None and stop_event.is_set():
                for future in pending:
                    future.cancel()
                break
            for future in completed:
                try:
                    value = future.result()
                except Exception as error:
                    resolve_errors.append(error)
                    value = None
                if value:
                    results.append(value)
                try:
                    item = next(iterator)
                except StopIteration:
                    continue
                if stop_event is None or not stop_event.is_set():
                    pending.add(pool.submit(resolve, item))
    if any(_permission_denied_error(error) for error in resolve_errors):
        raise NetworkFabricError("permission_denied")
    if resolve_errors and services and not results and not withdrawals:
        raise NetworkFabricError("discovery_unavailable")
    return (withdrawals + results)[:MAX_SERVICES]


def _service_kind(type_name):
    lowered = str(type_name or "").lower()
    mapping = {
        "_http._tcp": ("Web", "http"),
        "_https._tcp": ("Secure web", "https"),
        "_ssh._tcp": ("Secure Shell", "ssh"),
        "_rfb._tcp": ("Screen Sharing", "vnc"),
        "_smb._tcp": ("File Sharing", "smb"),
        "_ipp._tcp": ("Printer", None),
        "_printer._tcp": ("Printer", None),
        "_airplay._tcp": ("AirPlay", None),
        "_raop._tcp": ("AirPlay audio", None),
        "_googlecast._tcp": ("Google Cast", None),
        "_ke-link._tcp": ("KE Link", None),
    }
    for marker, value in mapping.items():
        if marker in lowered:
            return value
    return (str(type_name or "Service").split(".", 1)[0].lstrip("_") or "Service", None)


def _service_url(scheme, host, port):
    if not scheme or not host or not port:
        return None
    rendered_host = str(host).replace("%", "%25")
    rendered = f"[{rendered_host}]" if ":" in rendered_host else rendered_host
    return f"{scheme}://{rendered}:{int(port)}"


def _interface_index(interface):
    clean = _clean_interface(interface)
    if not clean:
        raise NetworkFabricError("endpoint_invalid")
    try:
        index = int(socket.if_nametoindex(clean))
    except (OSError, ValueError) as error:
        raise NetworkFabricError("endpoint_invalid") from error
    if index <= 0:
        raise NetworkFabricError("endpoint_invalid")
    return index


def _bind_socket_interface(sock, interface, family):
    """Bind a Darwin socket to one validated interface before any I/O."""
    index = _interface_index(interface)
    if family == socket.AF_INET:
        sock.setsockopt(socket.IPPROTO_IP, DARWIN_IP_BOUND_IF, index)
    elif family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, DARWIN_IPV6_BOUND_IF, index)
    else:
        raise NetworkFabricError("endpoint_invalid")
    return index


def _bound_stream_socket(host, port, interface, source_address, timeout):
    clean_interface = _clean_interface(interface)
    clean_host = _clean_endpoint_host(host, allow_loopback=True, interface=clean_interface)
    clean_source = _clean_endpoint_host(
        source_address,
        allow_loopback=True,
        interface=clean_interface,
    )
    target = _ip_address(clean_host) if clean_host else None
    source = _ip_address(clean_source) if clean_source else None
    if (
        not clean_interface
        or target is None
        or source is None
        or target.version != source.version
    ):
        raise NetworkFabricError("endpoint_invalid")
    family = socket.AF_INET if target.version == 4 else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        index = _bind_socket_interface(sock, clean_interface, family)
        sock.settimeout(float(timeout))
        if family == socket.AF_INET:
            sock.bind((str(source), 0))
            destination = (str(target), int(port))
        else:
            sock.bind((str(source), 0, 0, index if source.is_link_local else 0))
            destination = (str(target), int(port), 0, index if target.is_link_local else 0)
        sock.connect(destination)
        return sock
    except Exception:
        sock.close()
        raise


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = MAX_LISTENER_CONNECTIONS

    def __init__(
        self,
        server_address,
        handler,
        manager,
        allowed_networks,
        allow_loopback=False,
        ssl_context=None,
        listener_generation=0,
    ):
        if ":" in str(server_address[0]):
            raise NetworkFabricError("listener_scope_unavailable")
        self.manager = manager
        self.allowed_networks = tuple(allowed_networks)
        self.allow_loopback = bool(allow_loopback)
        self.ssl_context = ssl_context
        self.listener_generation = int(listener_generation)
        self.request_slots = threading.BoundedSemaphore(MAX_LISTENER_CONNECTIONS)
        super().__init__(server_address, handler)

    def verify_request(self, request, client_address):
        try:
            address = ipaddress.ip_address(str(client_address[0]).split("%", 1)[0])
        except ValueError:
            return False
        if address.is_loopback:
            return self.allow_loopback
        return any(address.version == network.version and address in network for network in self.allowed_networks)

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        wrapped = None
        handed_off = False
        try:
            if self.ssl_context is not None:
                request.settimeout(TLS_HANDSHAKE_TIMEOUT_SECONDS)
                wrapped = self.ssl_context.wrap_socket(
                    request,
                    server_side=True,
                    do_handshake_on_connect=False,
                )
                wrapped.settimeout(TLS_HANDSHAKE_TIMEOUT_SECONDS)
                wrapped.do_handshake()
                request = wrapped
            handed_off = True
            super().process_request_thread(request, client_address)
        except Exception:
            if not handed_off:
                self.shutdown_request(wrapped or request)
        finally:
            self.request_slots.release()


class _LinkRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "KE-Link/1"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(LISTENER_READ_TIMEOUT_SECONDS)

    def log_message(self, *_args):
        return

    def do_GET(self):
        client_ip = str(self.client_address[0]).split("%", 1)[0]
        if not self.server.manager.allow_request(client_ip):
            self._reply(429, {"ok": False, "code": "message_rate_limited"})
            return
        self._reply(405, {"ok": False, "code": "not_found"})

    def do_POST(self):
        client_ip = str(self.client_address[0]).split("%", 1)[0]
        if not self.server.manager.allow_request(client_ip):
            self._reply(429, {"ok": False, "code": "message_rate_limited"})
            return
        length = self.headers.get("Content-Length")
        try:
            size = int(length or "0")
        except ValueError:
            size = -1
        if size <= 0 or size > MAX_MESSAGE_BYTES:
            self._reply(413, {"ok": False, "code": "body_too_large"})
            return
        try:
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("incomplete body")
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("object required")
        except (socket.timeout, TimeoutError):
            self._reply(408, {"ok": False, "code": "request_timeout"})
            return
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._reply(400, {"ok": False, "code": "invalid_json"})
            return
        status, body = self.server.manager.handle_request(
            self.path,
            payload,
            client_ip=client_ip,
            listener_generation=self.server.listener_generation,
        )
        self._reply(status, body)

    def _reply(self, status, payload):
        encoded = _canonical_json(payload)
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            return


class KELinkManager:
    def __init__(
        self,
        data_root=None,
        clock=None,
        name=None,
        advertise=True,
        interface_provider=None,
        listener_addresses=None,
        allowed_networks=None,
        allow_loopback=False,
        local_filesystem_checker=None,
    ):
        root = data_root or Path.home() / "Library" / "Application Support" / "KE Studios" / "Activity Monitor" / "Network"
        self.root = Path(os.path.abspath(os.path.expanduser(str(root))))
        self.store = _SecureDirectory(self.root, local_checker=local_filesystem_checker)
        self.clock = clock or time.time
        self.name = _safe_peer_name(name or socket.gethostname() or "KE Monitor")[:63]
        self.advertise = bool(advertise)
        self.interface_provider = interface_provider or _interface_snapshot
        self.listener_addresses = tuple(listener_addresses or ())
        self.allowed_networks = tuple(allowed_networks or ())
        self.allow_loopback = bool(allow_loopback)
        self.lock = threading.RLock()
        self.identity = None
        self.peers = {}
        self.revoked = {}
        self.sessions = {}
        self.messages = collections.deque(maxlen=200)
        self.seen_nonces = {}
        self.received_acks = collections.OrderedDict()
        self.request_times = collections.deque()
        self.client_request_times = {}
        self.peer_request_times = {}
        self.pairing = None
        self.server = None
        self.server_thread = None
        self.listener_generation = 0
        self.advertiser = None
        self.advertiser_args = None
        self.advertiser_retry_at = 0.0
        self.listener_interface = None
        self.error = None
        self.runtime_errors = {}
        self.storage_valid = True
        self._load_peers()
        if self.storage_valid:
            self._load_received_acks()

    @staticmethod
    def _timestamp_valid(value):
        text = str(value or "")
        if len(text) > 40 or not text.endswith("Z"):
            return False
        try:
            datetime.fromisoformat(text[:-1] + "+00:00")
        except ValueError:
            return False
        return True

    def _validated_peer(self, peer_id, value):
        if not isinstance(value, dict) or len(value) > 8:
            raise NetworkFabricError("peer_store_insecure")
        expected = {"id", "name", "fingerprint", "secret", "pairedAt"}
        optional = {"host", "port", "interface"}
        if not expected.issubset(value) or not set(value).issubset(expected | optional):
            raise NetworkFabricError("peer_store_insecure")
        record_id = str(value.get("id") or "")
        fingerprint = str(value.get("fingerprint") or "")
        safe_name = _safe_peer_name(value.get("name"))
        if (
            record_id != str(peer_id)
            or not re.fullmatch(r"[a-f0-9]{32}", record_id)
            or not re.fullmatch(r"[a-f0-9]{64}", fingerprint)
            or _decode_secret(value.get("secret")) is None
            or not self._timestamp_valid(value.get("pairedAt"))
            or str(value.get("name") or "") != safe_name
        ):
            raise NetworkFabricError("peer_store_insecure")
        result = {
            "id": record_id,
            "name": safe_name,
            "fingerprint": fingerprint,
            "secret": str(value["secret"]),
            "pairedAt": str(value["pairedAt"]),
        }
        endpoint_fields = set(value).intersection(optional)
        if endpoint_fields == {"host", "port", "interface"}:
            interface = _clean_interface(value.get("interface"))
            host = _clean_endpoint_host(
                value.get("host"),
                allow_loopback=self.allow_loopback,
                interface=interface,
            )
            try:
                port = int(value.get("port"))
            except (TypeError, ValueError):
                port = 0
            if not interface or not host or not (1 <= port <= 65535):
                raise NetworkFabricError("peer_store_insecure")
            result.update({"host": host, "port": port, "interface": interface})
        elif endpoint_fields not in (set(), {"host", "port"}):
            raise NetworkFabricError("peer_store_insecure")
        return result

    def _validated_revocation(self, peer_id, value):
        if (
            not re.fullmatch(r"[a-f0-9]{32}", str(peer_id))
            or not isinstance(value, dict)
            or set(value) != {"secretHash", "revokedAt"}
            or not re.fullmatch(r"[a-f0-9]{64}", str(value.get("secretHash") or ""))
            or not self._timestamp_valid(value.get("revokedAt"))
        ):
            raise NetworkFabricError("peer_store_insecure")
        return {"secretHash": str(value["secretHash"]), "revokedAt": str(value["revokedAt"])}

    def _load_peers(self):
        try:
            payload = json.loads(self.store.read_bytes("peers.json", MAX_PEER_STORE_BYTES).decode("utf-8"))
            if not isinstance(payload, dict) or set(payload) != {"schemaVersion", "peers", "revoked"}:
                raise NetworkFabricError("peer_store_insecure")
            if payload.get("schemaVersion") != LINK_PROTOCOL or not isinstance(payload.get("peers"), dict) or not isinstance(payload.get("revoked"), dict):
                raise NetworkFabricError("peer_store_insecure")
            if len(payload["peers"]) > MAX_PEERS or len(payload["revoked"]) > MAX_PEERS * 2:
                raise NetworkFabricError("peer_store_insecure")
            if set(payload["peers"]).intersection(payload["revoked"]):
                raise NetworkFabricError("peer_store_insecure")
            self.peers = {peer_id: self._validated_peer(peer_id, value) for peer_id, value in payload["peers"].items()}
            self.revoked = {peer_id: self._validated_revocation(peer_id, value) for peer_id, value in payload["revoked"].items()}
        except FileNotFoundError:
            return
        except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError, NetworkFabricError) as error:
            code = error.code if isinstance(error, NetworkFabricError) else "peer_store_insecure"
            self.peers = {}
            self.revoked = {}
            self.storage_valid = False
            self.error = public_error(code, "ke-link-storage", self.clock())

    def _save_peers(self, proposed_peers=None, proposed_revoked=None):
        with self.lock:
            if not self.storage_valid:
                raise NetworkFabricError("peer_store_insecure")
            source_peers = self.peers if proposed_peers is None else proposed_peers
            source_revoked = self.revoked if proposed_revoked is None else proposed_revoked
            try:
                if len(source_peers) > MAX_PEERS or len(source_revoked) > MAX_PEERS * 2:
                    raise NetworkFabricError("peer_store_insecure")
                if set(source_peers).intersection(source_revoked):
                    raise NetworkFabricError("peer_store_insecure")
                peers = {peer_id: self._validated_peer(peer_id, value) for peer_id, value in source_peers.items()}
                revoked = {peer_id: self._validated_revocation(peer_id, value) for peer_id, value in source_revoked.items()}
                payload = {"schemaVersion": LINK_PROTOCOL, "peers": peers, "revoked": revoked}
                self.store.write_bytes("peers.json", _canonical_json(payload) + b"\n", MAX_PEER_STORE_BYTES)
            except (OSError, NetworkFabricError) as error:
                self.storage_valid = False
                self.peers = {}
                self.revoked = {}
                self.sessions.clear()
                code = error.code if isinstance(error, NetworkFabricError) else "peer_store_insecure"
                self.error = public_error(code, "ke-link-storage", self.clock())
                raise
            self.peers = peers
            self.revoked = revoked

    def _validated_received_ack(self, key, value, *, require_record_mac=False):
        match = re.fullmatch(r"([a-f0-9]{32}):([a-f0-9]{32})", str(key or ""))
        if (
            not match
            or not isinstance(value, dict)
            or set(value) not in ({"bodyDigest", "observedAt", "response"}, {"bodyDigest", "observedAt", "response", "recordMac"})
            or (require_record_mac and "recordMac" not in value)
        ):
            raise NetworkFabricError("peer_store_insecure")
        response = value.get("response")
        if not isinstance(response, dict) or set(response) != {
            "ok", "state", "clientMessageId", "messageId", "ack"
        }:
            raise NetworkFabricError("peer_store_insecure")
        try:
            observed_at = float(value.get("observedAt"))
        except (TypeError, ValueError):
            observed_at = math.nan
        if (
            response.get("ok") is not True
            or response.get("state") != "delivered"
            or response.get("clientMessageId") != match.group(2)
            or not re.fullmatch(r"[a-f0-9]{24}", str(response.get("messageId") or ""))
            or not re.fullmatch(r"[a-f0-9]{64}", str(response.get("ack") or ""))
            or not re.fullmatch(r"[a-f0-9]{64}", str(value.get("bodyDigest") or ""))
            or not math.isfinite(observed_at)
            or observed_at < 0
        ):
            raise NetworkFabricError("peer_store_insecure")
        result = {
            "bodyDigest": str(value["bodyDigest"]),
            "observedAt": observed_at,
            "response": dict(response),
        }
        if "recordMac" in value:
            peer = self.peers.get(match.group(1))
            secret = _decode_secret(peer.get("secret")) if peer else None
            expected = hmac.new(
                secret or b"",
                b"dedupe-ledger|" + _canonical_json({"key": str(key), **result}),
                hashlib.sha256,
            ).hexdigest()
            if not secret or not hmac.compare_digest(expected, str(value.get("recordMac") or "")):
                raise NetworkFabricError("peer_store_insecure")
        return result

    def _purge_received_acks(self, now=None):
        cutoff = (self.clock() if now is None else float(now)) - RECEIVED_ACK_TTL_SECONDS
        self.received_acks = collections.OrderedDict(
            (key, value)
            for key, value in self.received_acks.items()
            if float(value.get("observedAt") or 0) >= cutoff
        )
        while len(self.received_acks) > MAX_RECEIVED_MESSAGE_IDS:
            self.received_acks.popitem(last=False)

    def _load_received_acks(self):
        try:
            payload = json.loads(self.store.read_bytes("message-acks.json", MAX_ACK_STORE_BYTES).decode("utf-8"))
            if (
                not isinstance(payload, dict)
                or set(payload) != {"schemaVersion", "entries"}
                or payload.get("schemaVersion") != ACK_LEDGER_SCHEMA
                or not isinstance(payload.get("entries"), dict)
                or len(payload["entries"]) > MAX_RECEIVED_MESSAGE_IDS
            ):
                raise NetworkFabricError("peer_store_insecure")
            self.received_acks = collections.OrderedDict(
                (key, self._validated_received_ack(key, value, require_record_mac=True))
                for key, value in sorted(
                    payload["entries"].items(),
                    key=lambda item: float(item[1].get("observedAt") or 0) if isinstance(item[1], dict) else -1,
                )
            )
            self._purge_received_acks(self.clock())
        except FileNotFoundError:
            return
        except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError, NetworkFabricError) as error:
            self.received_acks.clear()
            self.storage_valid = False
            code = error.code if isinstance(error, NetworkFabricError) else "peer_store_insecure"
            self.error = public_error(code, "ke-link-storage", self.clock())

    def _save_received_acks(self, proposed=None):
        if not self.storage_valid:
            raise NetworkFabricError("peer_store_insecure")
        source = collections.OrderedDict(self.received_acks if proposed is None else proposed)
        try:
            entries = collections.OrderedDict(
                (key, self._validated_received_ack(key, value)) for key, value in source.items()
            )
            while len(entries) > MAX_RECEIVED_MESSAGE_IDS:
                entries.popitem(last=False)
            disk_entries = {}
            for key, value in entries.items():
                peer_id = key.split(":", 1)[0]
                peer = self.peers.get(peer_id)
                secret = _decode_secret(peer.get("secret")) if peer else None
                if not secret:
                    raise NetworkFabricError("peer_store_insecure")
                record_mac = hmac.new(
                    secret,
                    b"dedupe-ledger|" + _canonical_json({"key": key, **value}),
                    hashlib.sha256,
                ).hexdigest()
                disk_entries[key] = {**value, "recordMac": record_mac}
            payload = {"schemaVersion": ACK_LEDGER_SCHEMA, "entries": disk_entries}
            self.store.write_bytes("message-acks.json", _canonical_json(payload) + b"\n", MAX_ACK_STORE_BYTES)
        except (OSError, NetworkFabricError) as error:
            self.storage_valid = False
            self.received_acks.clear()
            code = error.code if isinstance(error, NetworkFabricError) else "peer_store_insecure"
            self.error = public_error(code, "ke-link-storage", self.clock())
            raise
        self.received_acks = entries

    def _clear_peer_runtime(self, peer_id):
        peer_id = str(peer_id)
        prefix = f"{peer_id}:"
        self.sessions.pop(peer_id, None)
        self.seen_nonces = {key: value for key, value in self.seen_nonces.items() if not key.startswith(prefix)}
        self.received_acks = collections.OrderedDict(
            (key, value) for key, value in self.received_acks.items() if not key.startswith(prefix)
        )
        self._save_received_acks()
        self.peer_request_times.pop(peer_id, None)
        self.messages = collections.deque(
            (item for item in self.messages if item.get("peerId") != peer_id),
            maxlen=200,
        )

    def _endpoint_route(self, host, interface=None):
        return _route_binding(
            host,
            self.interface_provider(),
            interface,
            allow_loopback=self.allow_loopback,
        )

    def _endpoint_allowed(self, host, interface=None):
        return self._endpoint_route(host, interface) is not None

    def _generate_identity_material(self, identity_id):
        openssl = OPENSSL_PATH if os.path.isfile(OPENSSL_PATH) else shutil.which("openssl")
        if not openssl or sys.platform != "darwin":
            raise NetworkFabricError("tls_unavailable")
        with tempfile.TemporaryFile() as key_handle, tempfile.TemporaryFile() as cert_handle:
            try:
                result = subprocess.run(
                    [
                        openssl, "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
                        "-days", "3650", "-subj", f"/CN=KE-Link-{identity_id[:12]}",
                        "-keyout", f"/dev/fd/{key_handle.fileno()}",
                        "-out", f"/dev/fd/{cert_handle.fileno()}",
                    ],
                    pass_fds=(key_handle.fileno(), cert_handle.fileno()),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise NetworkFabricError("tls_identity_failed") from error
            if result.returncode != 0:
                raise NetworkFabricError("tls_identity_failed")
            key_handle.seek(0)
            cert_handle.seek(0)
            key_data = key_handle.read(MAX_TLS_MATERIAL_BYTES + 1)
            cert_data = cert_handle.read(MAX_TLS_MATERIAL_BYTES + 1)
        if (
            not key_data.startswith(b"-----BEGIN PRIVATE KEY-----")
            or not cert_data.startswith(b"-----BEGIN CERTIFICATE-----")
            or len(key_data) > MAX_TLS_MATERIAL_BYTES
            or len(cert_data) > MAX_TLS_MATERIAL_BYTES
        ):
            raise NetworkFabricError("tls_identity_failed")
        return key_data, cert_data

    def _ensure_identity(self):
        if not self.storage_valid:
            raise NetworkFabricError("peer_store_insecure")
        if self.identity:
            return self.identity
        try:
            raw = self.store.read_bytes("identity.json", MAX_IDENTITY_BYTES)
        except FileNotFoundError:
            raw = None
        if raw is None:
            identity_id = secrets.token_hex(16)
            key_data, cert_data = self._generate_identity_material(identity_id)
            self.store.write_bytes("identity-key.pem", key_data, MAX_TLS_MATERIAL_BYTES)
            self.store.write_bytes("identity-cert.pem", cert_data, MAX_TLS_MATERIAL_BYTES)
            self.store.write_bytes("identity.json", _canonical_json({"id": identity_id}) + b"\n", MAX_IDENTITY_BYTES)
        else:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
                raise NetworkFabricError("identity_store_invalid") from error
            if not isinstance(payload, dict) or set(payload) != {"id"} or not re.fullmatch(r"[a-f0-9]{32}", str(payload.get("id") or "")):
                raise NetworkFabricError("identity_store_invalid")
            identity_id = str(payload["id"])
        try:
            cert_data = self.store.read_bytes("identity-cert.pem", MAX_TLS_MATERIAL_BYTES)
            self.store.read_bytes("identity-key.pem", MAX_TLS_MATERIAL_BYTES)
            pem = cert_data.decode("ascii")
            der = ssl.PEM_cert_to_DER_cert(pem)
        except (OSError, UnicodeDecodeError, ValueError, ssl.SSLError, NetworkFabricError) as error:
            raise NetworkFabricError("identity_store_invalid") from error
        self.identity = {"id": identity_id, "fingerprint": hashlib.sha256(der).hexdigest()}
        return self.identity

    def _server_context(self):
        key_fd = cert_fd = None
        try:
            key_fd = self.store.open_descriptor("identity-key.pem", MAX_TLS_MATERIAL_BYTES)
            cert_fd = self.store.open_descriptor("identity-cert.pem", MAX_TLS_MATERIAL_BYTES)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(f"/dev/fd/{cert_fd}", f"/dev/fd/{key_fd}")
            return context
        except (OSError, ssl.SSLError) as error:
            raise NetworkFabricError("identity_store_invalid") from error
        finally:
            _close_all(key_fd, cert_fd)

    def _listener_scope(self):
        if self.listener_addresses:
            host = _clean_endpoint_host(self.listener_addresses[0], allow_loopback=self.allow_loopback)
            if not host:
                raise NetworkFabricError("listener_scope_unavailable")
            address = ipaddress.ip_address(host)
            if address.is_loopback and not self.allow_loopback:
                raise NetworkFabricError("listener_scope_unavailable")
            if not address.is_loopback and not address.is_private:
                raise NetworkFabricError("listener_scope_unavailable")
            networks = []
            for value in self.allowed_networks:
                try:
                    networks.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    raise NetworkFabricError("listener_scope_unavailable")
            if address.is_loopback and self.allow_loopback and not networks:
                networks = [ipaddress.ip_network("127.0.0.0/8")]
            if address.version != 4 or not networks or not any(address in network for network in networks if network.version == 4):
                raise NetworkFabricError("listener_scope_unavailable")
            if address.is_loopback:
                return host, networks, "lo0"
            binding = _route_binding(host, self.interface_provider())
            if not binding:
                raise NetworkFabricError("listener_scope_unavailable")
            return host, networks, binding["interface"]
        for interface in self.interface_provider():
            if not interface.get("scanEligible") or not _discovery_interface_allowed(interface):
                continue
            networks = []
            for value in interface.get("networks") or []:
                try:
                    network = ipaddress.ip_network(value, strict=False)
                except ValueError:
                    continue
                if network.version == 4 and network.network_address.is_private:
                    networks.append(network)
            for value in interface.get("addresses") or []:
                host = _clean_ip(value)
                if not host or ":" in host:
                    continue
                address = ipaddress.ip_address(host)
                if address.is_private and any(address in network for network in networks):
                    return host, networks, _clean_interface(interface.get("name"))
        raise NetworkFabricError("listener_scope_unavailable")

    def _set_runtime_error(self, source, code):
        safe_source = public_error("discovery_unavailable", source)["source"]
        self.runtime_errors[safe_source] = public_error(code, safe_source, self.clock())

    def _clear_runtime_error(self, source):
        safe_source = public_error("discovery_unavailable", source)["source"]
        self.runtime_errors.pop(safe_source, None)

    def _poll_advertiser(self):
        if self.advertiser is not None and self.advertiser.poll() is not None:
            self.advertiser = None
            self.advertiser_retry_at = max(
                self.advertiser_retry_at,
                self.clock() + ADVERTISER_RETRY_SECONDS,
            )
            self._set_runtime_error("bonjour", "bonjour_advertisement_unavailable")

    def _start_advertiser(self, identity, interface, port, *, force=False):
        self._poll_advertiser()
        if not self.advertise:
            self._clear_runtime_error("bonjour")
            return
        if not force and self.clock() < self.advertiser_retry_at:
            return
        interface = _clean_interface(interface)
        if not interface or not os.path.isfile(DNS_SD_PATH):
            self._set_runtime_error("bonjour", "bonjour_advertisement_unavailable")
            return
        args = [
            DNS_SD_PATH, "-i", interface, "-R", self.name, "_ke-link._tcp", "local.", str(port),
            f"id={identity['id']}", f"fp={identity['fingerprint']}", "proto=1",
        ]
        self.advertiser_args = tuple(args)
        try:
            self.advertiser = subprocess.Popen(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            self.advertiser = None
            self.advertiser_retry_at = self.clock() + ADVERTISER_RETRY_SECONDS
            self._set_runtime_error("bonjour", "bonjour_advertisement_unavailable")
            return
        if self.advertiser.poll() is not None:
            self.advertiser = None
            self.advertiser_retry_at = self.clock() + ADVERTISER_RETRY_SECONDS
            self._set_runtime_error("bonjour", "bonjour_advertisement_unavailable")
            return
        self.advertiser_retry_at = 0.0
        self._clear_runtime_error("bonjour")

    def enable(self):
        with self.lock:
            if self.server:
                self._poll_advertiser()
                if self.advertise and self.advertiser is None:
                    identity = self._ensure_identity()
                    self._start_advertiser(
                        identity,
                        self.listener_interface,
                        self.server.server_port,
                        force=True,
                    )
                return self.status()
            identity = self._ensure_identity()
            host, networks, interface = self._listener_scope()
            context = self._server_context()
            listener_generation = self.listener_generation + 1
            server = _BoundedThreadingHTTPServer(
                (host, 0),
                _LinkRequestHandler,
                self,
                networks,
                self.allow_loopback,
                ssl_context=context,
                listener_generation=listener_generation,
            )
            try:
                server.socket.settimeout(0.5)
            except OSError:
                server.server_close()
                raise
            self.listener_generation = listener_generation
            self.server = server
            self.listener_interface = interface
            self.server_thread = threading.Thread(target=server.serve_forever, name="ke-link-server", daemon=True)
            self.server_thread.start()
            self._start_advertiser(identity, interface, server.server_port, force=True)
            return self.status()

    def repair_advertiser_if_enabled(self, expected_generation=None):
        """Recheck advertising under one lock without ever enabling a listener."""
        with self.lock:
            if expected_generation is not None:
                try:
                    generation = int(expected_generation)
                except (TypeError, ValueError):
                    generation = -1
                if generation != self.listener_generation:
                    raise NetworkFabricError("recovery_stale")
            return self.status()

    def disable(self):
        with self.lock:
            self.listener_generation += 1
            advertiser, self.advertiser = self.advertiser, None
            server, self.server = self.server, None
            thread, self.server_thread = self.server_thread, None
            self.listener_interface = None
            self.advertiser_args = None
            self.advertiser_retry_at = 0.0
            self.pairing = None
            self.sessions.clear()
        if advertiser is not None and advertiser.poll() is None:
            advertiser.terminate()
            try:
                advertiser.wait(timeout=1)
            except subprocess.TimeoutExpired:
                advertiser.kill()
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)
        with self.lock:
            self._clear_runtime_error("bonjour")
        return self.status()

    def status(self):
        with self.lock:
            self._poll_advertiser()
            if self.server is not None and self.advertise and self.advertiser is None:
                try:
                    identity = self._ensure_identity()
                    self._start_advertiser(identity, self.listener_interface, self.server.server_port)
                except NetworkFabricError:
                    self._set_runtime_error("bonjour", "bonjour_advertisement_unavailable")
            identity = self.identity or {}
            pairing = self.pairing
            now = self.clock()
            self._purge_sessions(now)
            if pairing and pairing["expiresAt"] <= now:
                pairing = self.pairing = None
            trusted_peers = []
            for peer_id, peer in sorted(self.peers.items(), key=lambda item: (item[1]["name"].lower(), item[0])):
                session = self.session_status(peer_id)
                trusted_peers.append({
                    "id": peer_id,
                    "name": _safe_peer_name(peer.get("name")),
                    "pairedAt": peer.get("pairedAt"),
                    "hasAuthenticatedEndpoint": bool(peer.get("host") and peer.get("port") and peer.get("interface")),
                    "ready": bool(session.get("ready")),
                })
            return {
                "enabled": self.server is not None,
                "advertising": self.advertiser is not None,
                "generation": self.listener_generation,
                "id": identity.get("id"),
                "fingerprint": identity.get("fingerprint"),
                "port": self.server.server_port if self.server else None,
                "listener": {
                    "family": "IPv4",
                    "scope": "direct-private-interface",
                    "interface": self.listener_interface,
                    "maxConcurrentRequests": MAX_LISTENER_CONNECTIONS,
                    "readTimeoutSeconds": LISTENER_READ_TIMEOUT_SECONDS,
                    "tlsHandshakeTimeoutSeconds": TLS_HANDSHAKE_TIMEOUT_SECONDS,
                },
                "pairedPeerCount": len(self.peers),
                "readyPeerCount": len(self.sessions),
                "trustedPeers": trusted_peers[:MAX_PEERS],
                "pairing": None if not pairing or pairing.get("reserved") else {
                    "code": pairing["display"],
                    "expiresAt": _utc_iso(pairing["expiresAt"]),
                },
                "messages": list(self.messages),
                "error": self.error,
                "errors": sorted(
                    ([self.error] if self.error else []) + list(self.runtime_errors.values()),
                    key=lambda item: str(item.get("observedAt") or ""),
                    reverse=True,
                ),
                "boundary": "Trust is persistent; connectivity is not. Plain-text messages never grant command, file, Agent, account, or authority execution.",
            }

    def begin_pairing(self):
        token = base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
        display = "-".join(token[index:index + 4] for index in range(0, len(token), 4))
        with self.lock:
            if self.server is None:
                raise NetworkFabricError("ke_link_disabled")
            self.pairing = {
                "token": token,
                "display": display,
                "codeId": _sha(token)[:12],
                "expiresAt": self.clock() + PAIRING_TTL_SECONDS,
                "reserved": False,
            }
            return {
                "code": self.pairing["display"],
                "expiresAt": _utc_iso(self.pairing["expiresAt"]),
            }

    @staticmethod
    def _normalize_pair_code(value):
        token = re.sub(r"[^A-Z2-7]", "", str(value or "").upper())
        return token if len(token) == 26 else None

    def _pairing_token(self, code_id=None):
        with self.lock:
            pairing = self.pairing
            if not pairing or pairing["expiresAt"] <= self.clock():
                self.pairing = None
                return None
            if pairing.get("reserved"):
                return None
            if code_id and not hmac.compare_digest(pairing["codeId"], str(code_id)):
                return None
            return pairing["token"]

    def _reserve_pairing(self, code_id):
        with self.lock:
            pairing = self.pairing
            if (
                self.server is None
                or not pairing
                or pairing["expiresAt"] <= self.clock()
                or pairing.get("reserved")
                or not hmac.compare_digest(pairing["codeId"], str(code_id or ""))
            ):
                if pairing and pairing["expiresAt"] <= self.clock():
                    self.pairing = None
                raise NetworkFabricError("pairing_invalid")
            pairing["reserved"] = True
            return pairing

    def _consume_reserved_pairing(self, pairing):
        with self.lock:
            if self.pairing is pairing:
                self.pairing = None

    def _rate_bucket(self, mapping, key, now, cap, max_keys):
        for stale_key, stale_bucket in list(mapping.items()):
            while stale_bucket and stale_bucket[0] < now - 60.0:
                stale_bucket.popleft()
            if not stale_bucket:
                del mapping[stale_key]
        if key not in mapping and len(mapping) >= max_keys:
            return False
        bucket = mapping.setdefault(key, collections.deque())
        cutoff = now - 60.0
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= cap:
            return False
        bucket.append(now)
        return True

    def allow_request(self, client_ip, peer_id=None):
        with self.lock:
            now = self.clock()
            if peer_id is None:
                cutoff = now - 60.0
                while self.request_times and self.request_times[0] < cutoff:
                    self.request_times.popleft()
                if len(self.request_times) >= GLOBAL_REQUESTS_PER_MINUTE:
                    return False
                if not self._rate_bucket(
                    self.client_request_times,
                    str(client_ip),
                    now,
                    CLIENT_REQUESTS_PER_MINUTE,
                    MAX_CLIENT_RATE_BUCKETS,
                ):
                    return False
                self.request_times.append(now)
                return True
            return self._rate_bucket(
                self.peer_request_times,
                str(peer_id),
                now,
                PEER_REQUESTS_PER_MINUTE,
                MAX_PEERS,
            )

    def handle_request(self, path, payload, client_ip=None, listener_generation=None):
        # Serialize request validation and every authenticated side-effect with
        # listener disable. A handler accepted by an older listener generation
        # cannot commit after the user disables or re-enables KE Link.
        with self.lock:
            try:
                server = self.server
                active_generation = self.listener_generation
                request_generation = (
                    active_generation
                    if listener_generation is None
                    else int(listener_generation)
                )
                server_generation = int(
                    getattr(server, "listener_generation", active_generation)
                ) if server is not None else None
                if (
                    server is None
                    or request_generation != active_generation
                    or server_generation != active_generation
                ):
                    raise NetworkFabricError("ke_link_disabled")
                if path == "/v1/pair/challenge":
                    return 200, self._handle_challenge(payload)
                if path == "/v1/pair":
                    return 200, self._handle_pair(payload)
                if path == "/v1/health":
                    return 200, self._handle_health(payload, client_ip=client_ip)
                if path == "/v1/message":
                    return 200, self._handle_message(payload, client_ip=client_ip)
                return 404, {"ok": False, "code": "not_found", "error": _ERROR_COPY["not_found"]}
            except (TypeError, ValueError):
                error = NetworkFabricError("ke_link_disabled")
                return 409, {"ok": False, "code": error.code, "error": error.public_message}
            except NetworkFabricError as error:
                status = 401 if error.code in {"pairing_invalid", "message_unauthorized"} else 429 if error.code == "message_rate_limited" else 409
                return status, {"ok": False, "code": error.code, "error": error.public_message}

    def _handle_challenge(self, payload):
        if set(payload) != {"version", "codeId", "nonce"} or payload.get("version") != 1:
            raise NetworkFabricError("pairing_invalid")
        nonce = str(payload.get("nonce") or "")
        if not re.fullmatch(r"[a-f0-9]{32}", nonce):
            raise NetworkFabricError("pairing_invalid")
        token = self._pairing_token(payload.get("codeId"))
        if not token:
            raise NetworkFabricError("pairing_invalid")
        identity = self._ensure_identity()
        message = f"challenge|{identity['fingerprint']}|{nonce}".encode("utf-8")
        proof = hmac.new(token.encode("ascii"), message, hashlib.sha256).hexdigest()
        return {"ok": True, "fingerprint": identity["fingerprint"], "proof": proof}

    def _handle_pair(self, payload):
        expected = {"version", "codeId", "nonce", "senderId", "senderName", "senderFingerprint", "proof"}
        if set(payload) != expected or payload.get("version") != 1:
            raise NetworkFabricError("pairing_invalid")
        sender_id = str(payload.get("senderId") or "")
        sender_fp = str(payload.get("senderFingerprint") or "")
        nonce = str(payload.get("nonce") or "")
        if not re.fullmatch(r"[a-f0-9]{32}", sender_id) or not re.fullmatch(r"[a-f0-9]{64}", sender_fp) or not re.fullmatch(r"[a-f0-9]{32}", nonce):
            raise NetworkFabricError("pairing_invalid")
        pairing = self._reserve_pairing(payload.get("codeId"))
        token = pairing["token"]
        try:
            identity = self._ensure_identity()
            signed = f"pair|{identity['fingerprint']}|{sender_fp}|{sender_id}|{nonce}".encode("utf-8")
            expected_proof = hmac.new(token.encode("ascii"), signed, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_proof, str(payload.get("proof") or "")):
                raise NetworkFabricError("pairing_invalid")
            secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
            record = {
                "id": sender_id,
                "name": _safe_peer_name(payload.get("senderName")),
                "fingerprint": sender_fp,
                "secret": secret,
                "pairedAt": _utc_iso(self.clock()),
            }
            with self.lock:
                if self.server is None or self.pairing is not pairing:
                    raise NetworkFabricError("pairing_invalid")
                if sender_id not in self.peers and len(self.peers) >= MAX_PEERS:
                    raise NetworkFabricError("peer_store_insecure")
                peers = dict(self.peers)
                peers[sender_id] = record
                revoked = dict(self.revoked)
                revoked.pop(sender_id, None)
                self._save_peers(peers, revoked)
                self._clear_peer_runtime(sender_id)
                self.pairing = None
            accepted = f"accepted|{identity['id']}|{sender_id}|{nonce}|{secret}".encode("utf-8")
            proof = hmac.new(token.encode("ascii"), accepted, hashlib.sha256).hexdigest()
            return {
                "ok": True,
                "peerId": identity["id"],
                "peerName": self.name,
                "fingerprint": identity["fingerprint"],
                "secret": secret,
                "proof": proof,
            }
        finally:
            self._consume_reserved_pairing(pairing)

    def _purge_nonces(self, now):
        cutoff = now - MESSAGE_CLOCK_SKEW_SECONDS * 2
        self.seen_nonces = {key: value for key, value in self.seen_nonces.items() if value >= cutoff}

    def _record_nonce(self, sender_id, nonce, now):
        self._purge_nonces(now)
        key = f"{sender_id}:{nonce}"
        if key in self.seen_nonces:
            raise NetworkFabricError("message_replay")
        peer_count = sum(1 for item in self.seen_nonces if item.startswith(f"{sender_id}:"))
        if peer_count >= MAX_NONCES_PER_PEER or len(self.seen_nonces) >= MAX_NONCES_GLOBAL:
            raise NetworkFabricError("message_rate_limited")
        self.seen_nonces[key] = now

    def _authenticated_envelope(self, payload, fields, client_ip=None):
        if not self.storage_valid:
            raise NetworkFabricError("peer_store_insecure")
        if set(payload) != set(fields) | {"mac"} or payload.get("version") != 1:
            raise NetworkFabricError("message_invalid")
        sender_id = str(payload.get("senderId") or "")
        peer = self.peers.get(sender_id)
        if not peer or _decode_secret(peer.get("secret")) is None:
            raise NetworkFabricError("message_unauthorized")
        if not self.allow_request(client_ip or "unknown", peer_id=sender_id):
            raise NetworkFabricError("message_rate_limited")
        nonce = str(payload.get("nonce") or "")
        try:
            timestamp = float(payload.get("timestamp"))
        except (TypeError, ValueError):
            timestamp = 0.0
        if not math.isfinite(timestamp) or not re.fullmatch(r"[a-f0-9]{32}", nonce) or abs(self.clock() - timestamp) > MESSAGE_CLOCK_SKEW_SECONDS:
            raise NetworkFabricError("message_invalid")
        signed = {key: payload[key] for key in fields}
        secret = _decode_secret(peer["secret"])
        expected_mac = hmac.new(secret, _canonical_json(signed), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac, str(payload.get("mac") or "")):
            raise NetworkFabricError("message_unauthorized")
        return sender_id, peer, secret, signed, nonce

    def _handle_health(self, payload, client_ip=None):
        fields = ("version", "senderId", "timestamp", "nonce")
        sender_id, peer, secret, signed, nonce = self._authenticated_envelope(payload, fields, client_ip)
        with self.lock:
            self._record_nonce(sender_id, nonce, self.clock())
        identity = self._ensure_identity()
        ack = hmac.new(secret, b"health-ack|" + _canonical_json(signed), hashlib.sha256).hexdigest()
        return {
            "ok": True,
            "protocol": LINK_PROTOCOL,
            "peerId": identity["id"],
            "peerName": self.name,
            "fingerprint": identity["fingerprint"],
            "ack": ack,
        }

    def _handle_message(self, payload, client_ip=None):
        fields = ("version", "senderId", "timestamp", "nonce", "clientMessageId", "body")
        sender_id, peer, secret, signed, nonce = self._authenticated_envelope(payload, fields, client_ip)
        body = payload.get("body")
        client_message_id = str(payload.get("clientMessageId") or "")
        if (
            not isinstance(body, str)
            or not body.strip()
            or len(body) > MAX_MESSAGE_CHARS
            or len(body.encode("utf-8")) > MAX_MESSAGE_BYTES
            or not re.fullmatch(r"[a-f0-9]{32}", client_message_id)
        ):
            raise NetworkFabricError("message_invalid")
        dedupe_key = f"{sender_id}:{client_message_id}"
        body_digest = _sha(body)
        with self.lock:
            self._purge_received_acks(self.clock())
            prior = self.received_acks.get(dedupe_key)
            if prior:
                if not hmac.compare_digest(str(prior.get("bodyDigest") or ""), body_digest):
                    raise NetworkFabricError("message_id_conflict")
                self.received_acks.move_to_end(dedupe_key)
                return dict(prior["response"])
            self._record_nonce(sender_id, nonce, self.clock())
            message_id = _sha(dedupe_key)[:24]
            ack = hmac.new(secret, f"ack|{client_message_id}|{message_id}".encode("utf-8"), hashlib.sha256).hexdigest()
            response = {
                "ok": True,
                "state": "delivered",
                "clientMessageId": client_message_id,
                "messageId": message_id,
                "ack": ack,
            }
            self.received_acks[dedupe_key] = {
                "response": response,
                "bodyDigest": body_digest,
                "observedAt": self.clock(),
            }
            while len(self.received_acks) > MAX_RECEIVED_MESSAGE_IDS:
                self.received_acks.popitem(last=False)
            self._save_received_acks()
            self.messages.append({
                "id": message_id,
                "clientMessageId": client_message_id,
                "state": "delivered",
                "direction": "inbound",
                "peerId": sender_id,
                "peerName": peer.get("name") or "KE Link peer",
                "body": body,
                "observedAt": _utc_iso(self.clock()),
            })
        return response

    @staticmethod
    def _request(
        host,
        port,
        path,
        payload,
        expected_fingerprint,
        timeout=4.0,
        *,
        interface=None,
        source_address=None,
    ):
        clean_interface = _clean_interface(interface)
        clean_host = _clean_endpoint_host(host, allow_loopback=True, interface=clean_interface)
        clean_source = _clean_endpoint_host(
            source_address,
            allow_loopback=True,
            interface=clean_interface,
        )
        try:
            clean_port = int(port)
        except (TypeError, ValueError):
            clean_port = 0
        if (
            not clean_interface
            or not clean_host
            or not clean_source
            or (_ip_address(clean_host) or ipaddress.ip_address("::")).version
            != (_ip_address(clean_source) or ipaddress.ip_address("0.0.0.0")).version
            or not (1 <= clean_port <= 65535)
            or not re.fullmatch(r"[a-f0-9]{64}", str(expected_fingerprint or ""))
        ):
            raise NetworkFabricError("endpoint_invalid")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(
            str(_ip_address(clean_host)),
            clean_port,
            timeout=timeout,
            context=context,
        )
        raw_socket = None
        try:
            raw_socket = _bound_stream_socket(
                clean_host,
                clean_port,
                clean_interface,
                clean_source,
                timeout,
            )
            connection.sock = context.wrap_socket(
                raw_socket,
                server_hostname=str(_ip_address(clean_host)),
            )
            raw_socket = None
            certificate = connection.sock.getpeercert(binary_form=True)
            observed = hashlib.sha256(certificate).hexdigest()
            if not hmac.compare_digest(observed, str(expected_fingerprint)):
                raise NetworkFabricError("peer_fingerprint_mismatch")
            encoded = _canonical_json(payload)
            connection.request("POST", path, body=encoded, headers={"Content-Type": "application/json", "Content-Length": str(len(encoded))})
            response = connection.getresponse()
            body = response.read(MAX_MESSAGE_BYTES + 1)
            if len(body) > MAX_MESSAGE_BYTES:
                raise NetworkFabricError("peer_response_too_large")
            parsed = json.loads(body.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise NetworkFabricError("peer_response_invalid")
            if response.status >= 400 or parsed.get("ok") is not True:
                code = str(parsed.get("code") or "peer_response_invalid")
                raise NetworkFabricError(code if code in _ERROR_COPY else "peer_response_invalid")
            return parsed
        except NetworkFabricError:
            raise
        except (OSError, ssl.SSLError, json.JSONDecodeError, UnicodeDecodeError, http.client.HTTPException) as error:
            raise NetworkFabricError("peer_unreachable") from error
        finally:
            if raw_socket is not None:
                raw_socket.close()
            connection.close()

    def _record_session(self, peer_id, host, port, fingerprint, interface=None, persist_endpoint=False):
        try:
            clean_port = int(port)
        except (TypeError, ValueError):
            clean_port = 0
        route = self._endpoint_route(host, interface)
        clean_host = route["address"] if route else None
        clean_interface = route["interface"] if route else None
        with self.lock:
            peer = self.peers.get(str(peer_id))
            if (
                not peer
                or not clean_host
                or not clean_interface
                or not (1 <= clean_port <= 65535)
                or not hmac.compare_digest(str(peer.get("fingerprint") or ""), str(fingerprint or ""))
            ):
                raise NetworkFabricError("endpoint_invalid")
            now = self.clock()
            if persist_endpoint and (
                peer.get("host") != clean_host
                or peer.get("port") != clean_port
                or peer.get("interface") != clean_interface
            ):
                peers = dict(self.peers)
                peers[str(peer_id)] = {
                    **peer,
                    "host": clean_host,
                    "port": clean_port,
                    "interface": clean_interface,
                }
                self._save_peers(peers, self.revoked)
            session = {
                "verifiedAt": now,
                "expiresAt": now + AUTH_SESSION_TTL_SECONDS,
                "host": clean_host,
                "port": clean_port,
                "interface": clean_interface,
                "sourceAddress": route["sourceAddress"],
                "fingerprint": str(fingerprint),
            }
            self.sessions[str(peer_id)] = session
            return dict(session)

    def _purge_sessions(self, now=None):
        current = self.clock() if now is None else float(now)
        self.sessions = {peer_id: value for peer_id, value in self.sessions.items() if float(value.get("expiresAt") or 0) > current}

    def session_status(self, peer_id, *, host=None, port=None, fingerprint=None, interface=None):
        with self.lock:
            self._purge_sessions(self.clock())
            session = self.sessions.get(str(peer_id))
            if not session:
                return {"state": "not-ready", "ready": False, "ttlSeconds": AUTH_SESSION_TTL_SECONDS}
            if host is not None:
                clean_host = _clean_endpoint_host(host, allow_loopback=self.allow_loopback)
                if not clean_host or clean_host != session.get("host"):
                    return {"state": "not-ready", "ready": False, "ttlSeconds": AUTH_SESSION_TTL_SECONDS}
            if port is not None:
                try:
                    port_matches = int(port) == int(session.get("port") or 0)
                except (TypeError, ValueError):
                    port_matches = False
                if not port_matches:
                    return {"state": "not-ready", "ready": False, "ttlSeconds": AUTH_SESSION_TTL_SECONDS}
            if interface is not None and _clean_interface(interface) != session.get("interface"):
                return {"state": "not-ready", "ready": False, "ttlSeconds": AUTH_SESSION_TTL_SECONDS}
            if fingerprint and not hmac.compare_digest(str(fingerprint), str(session.get("fingerprint") or "")):
                return {"state": "not-ready", "ready": False, "ttlSeconds": AUTH_SESSION_TTL_SECONDS}
            return {
                "state": "ready",
                "ready": True,
                "verifiedAt": _utc_iso(session["verifiedAt"]),
                "expiresAt": _utc_iso(session["expiresAt"]),
                "ttlSeconds": AUTH_SESSION_TTL_SECONDS,
            }

    def pair(
        self,
        host,
        port,
        expected_fingerprint,
        code,
        interface=None,
        expected_peer_id=None,
    ):
        if self.server is None:
            raise NetworkFabricError("ke_link_disabled")
        route = self._endpoint_route(host, interface)
        clean_host = route["address"] if route else None
        clean_interface = route["interface"] if route else None
        try:
            clean_port = int(port)
        except (TypeError, ValueError):
            clean_port = 0
        if (
            not clean_host
            or not clean_interface
            or not (1 <= clean_port <= 65535)
            or not re.fullmatch(r"[a-f0-9]{64}", str(expected_fingerprint or ""))
            or (
                expected_peer_id is not None
                and not re.fullmatch(r"[a-f0-9]{32}", str(expected_peer_id or ""))
            )
        ):
            raise NetworkFabricError("endpoint_invalid")
        token = self._normalize_pair_code(code)
        if not token:
            raise NetworkFabricError("pairing_code_invalid")
        code_id = _sha(token)[:12]
        nonce = secrets.token_hex(16)
        challenge = self._request(
            clean_host,
            clean_port,
            "/v1/pair/challenge",
            {"version": 1, "codeId": code_id, "nonce": nonce},
            expected_fingerprint,
            interface=clean_interface,
            source_address=route["sourceAddress"],
        )
        expected = hmac.new(token.encode("ascii"), f"challenge|{expected_fingerprint}|{nonce}".encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(challenge.get("proof") or "")):
            raise NetworkFabricError("pairing_proof_invalid")
        identity = self._ensure_identity()
        proof = hmac.new(
            token.encode("ascii"),
            f"pair|{expected_fingerprint}|{identity['fingerprint']}|{identity['id']}|{nonce}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        accepted = self._request(clean_host, clean_port, "/v1/pair", {
            "version": 1,
            "codeId": code_id,
            "nonce": nonce,
            "senderId": identity["id"],
            "senderName": self.name,
            "senderFingerprint": identity["fingerprint"],
            "proof": proof,
        }, expected_fingerprint, interface=clean_interface, source_address=route["sourceAddress"])
        remote_id = str(accepted.get("peerId") or "")
        secret = str(accepted.get("secret") or "")
        accepted_proof = hmac.new(token.encode("ascii"), f"accepted|{remote_id}|{identity['id']}|{nonce}|{secret}".encode("utf-8"), hashlib.sha256).hexdigest()
        if (
            not re.fullmatch(r"[a-f0-9]{32}", remote_id)
            or (
                expected_peer_id is not None
                and not hmac.compare_digest(remote_id, str(expected_peer_id))
            )
            or _decode_secret(secret) is None
            or not hmac.compare_digest(accepted_proof, str(accepted.get("proof") or ""))
        ):
            raise NetworkFabricError("pairing_acceptance_invalid")
        with self.lock:
            if remote_id not in self.peers and len(self.peers) >= MAX_PEERS:
                raise NetworkFabricError("peer_store_insecure")
            peers = dict(self.peers)
            peers[remote_id] = {
                "id": remote_id,
                "name": _safe_peer_name(accepted.get("peerName")),
                "fingerprint": str(expected_fingerprint),
                "secret": secret,
                "host": clean_host,
                "port": clean_port,
                "interface": clean_interface,
                "pairedAt": _utc_iso(self.clock()),
            }
            revoked = dict(self.revoked)
            revoked.pop(remote_id, None)
            self._save_peers(peers, revoked)
            self._clear_peer_runtime(remote_id)
        session = self._record_session(
            remote_id,
            clean_host,
            clean_port,
            expected_fingerprint,
            clean_interface,
        )
        return {
            "ok": True,
            "state": "ready",
            "peerId": remote_id,
            "peerName": self.peers[remote_id]["name"],
            "sessionExpiresAt": _utc_iso(session["expiresAt"]),
        }

    def verify_peer(self, peer_id, host=None, port=None, fingerprint=None, interface=None):
        with self.lock:
            peer = self.peers.get(str(peer_id))
            if not peer:
                raise NetworkFabricError("peer_not_paired")
            # A user-requested verification must earn readiness again. If the
            # health exchange fails, an older session cannot remain "ready".
            self.sessions.pop(str(peer_id), None)
            route = self._endpoint_route(host or peer.get("host"), interface or peer.get("interface"))
            clean_host = route["address"] if route else None
            clean_interface = route["interface"] if route else None
            try:
                clean_port = int(port if port is not None else peer.get("port"))
            except (TypeError, ValueError):
                clean_port = 0
            expected_fingerprint = str(fingerprint or peer.get("fingerprint") or "")
            secret = _decode_secret(peer.get("secret"))
        if (
            not clean_host
            or not clean_interface
            or not (1 <= clean_port <= 65535)
            or not secret
            or not re.fullmatch(r"[a-f0-9]{64}", expected_fingerprint)
        ):
            raise NetworkFabricError("endpoint_invalid")
        identity = self._ensure_identity()
        signed = {
            "version": 1,
            "senderId": identity["id"],
            "timestamp": round(self.clock(), 3),
            "nonce": secrets.token_hex(16),
        }
        envelope = dict(signed)
        envelope["mac"] = hmac.new(secret, _canonical_json(signed), hashlib.sha256).hexdigest()
        result = self._request(
            clean_host,
            clean_port,
            "/v1/health",
            envelope,
            expected_fingerprint,
            interface=clean_interface,
            source_address=route["sourceAddress"],
        )
        expected_ack = hmac.new(secret, b"health-ack|" + _canonical_json(signed), hashlib.sha256).hexdigest()
        if (
            result.get("peerId") != str(peer_id)
            or result.get("fingerprint") != expected_fingerprint
            or not hmac.compare_digest(expected_ack, str(result.get("ack") or ""))
        ):
            raise NetworkFabricError("message_ack_invalid")
        session = self._record_session(
            peer_id,
            clean_host,
            clean_port,
            expected_fingerprint,
            clean_interface,
            persist_endpoint=True,
        )
        return {"ok": True, "state": "ready", "peerId": str(peer_id), "expiresAt": _utc_iso(session["expiresAt"])}

    def verify_peer_if_generation(self, peer_id, host, port, fingerprint, interface, expected_generation):
        """Bind a recovery health proof to one unchanged listener generation."""
        with self.lock:
            try:
                generation = int(expected_generation)
            except (TypeError, ValueError):
                generation = -1
            if generation != self.listener_generation:
                raise NetworkFabricError("recovery_stale")
        result = self.verify_peer(peer_id, host, port, fingerprint, interface)
        with self.lock:
            if generation != self.listener_generation:
                self.sessions.pop(str(peer_id), None)
                raise NetworkFabricError("recovery_stale")
        return result

    def revoke_peer(self, peer_id):
        peer_id = str(peer_id or "")
        with self.lock:
            peer = self.peers.get(peer_id)
            if not peer:
                return {"ok": True, "state": "revoked", "peerId": peer_id, "changed": False}
            peers = dict(self.peers)
            del peers[peer_id]
            revoked = dict(self.revoked)
            revoked[peer_id] = {
                "secretHash": _sha(str(peer.get("secret") or "")),
                "revokedAt": _utc_iso(self.clock()),
            }
            if len(revoked) > MAX_PEERS * 2:
                oldest = sorted(revoked, key=lambda item: revoked[item]["revokedAt"])[0]
                del revoked[oldest]
            self._save_peers(peers, revoked)
            self._clear_peer_runtime(peer_id)
            return {"ok": True, "state": "revoked", "peerId": peer_id, "changed": True}

    def send(self, peer_id, body, client_message_id):
        text = str(body or "")
        message_key = str(client_message_id or "").lower()
        if (
            not text.strip()
            or len(text) > MAX_MESSAGE_CHARS
            or len(text.encode("utf-8")) > MAX_MESSAGE_BYTES
            or not re.fullmatch(r"[a-f0-9]{32}", message_key)
        ):
            raise NetworkFabricError("message_invalid")
        with self.lock:
            peer = self.peers.get(str(peer_id))
            self._purge_sessions(self.clock())
            session = self.sessions.get(str(peer_id))
            if not peer or not peer.get("host") or not peer.get("port"):
                raise NetworkFabricError("peer_unavailable")
            if not session:
                raise NetworkFabricError("peer_session_required")
            secret = _decode_secret(peer.get("secret"))
            host, port, fingerprint = peer["host"], peer["port"], peer["fingerprint"]
            interface = peer.get("interface") or session.get("interface")
            route = self._endpoint_route(host, interface)
            if (
                not secret
                or not route
                or session.get("host") != host
                or int(session.get("port") or 0) != int(port)
                or session.get("interface") != route.get("interface")
                or not hmac.compare_digest(str(session.get("fingerprint") or ""), str(fingerprint))
            ):
                raise NetworkFabricError("peer_session_required")
        identity = self._ensure_identity()
        envelope = {
            "version": 1,
            "senderId": identity["id"],
            "timestamp": round(self.clock(), 3),
            "nonce": secrets.token_hex(16),
            "clientMessageId": message_key,
            "body": text,
        }
        envelope["mac"] = hmac.new(secret, _canonical_json(envelope), hashlib.sha256).hexdigest()
        try:
            result = self._request(
                host,
                port,
                "/v1/message",
                envelope,
                fingerprint,
                interface=route["interface"],
                source_address=route["sourceAddress"],
            )
        except NetworkFabricError as error:
            if error.code in {"peer_unreachable", "request_timeout", "peer_response_invalid", "peer_response_too_large"}:
                raise NetworkFabricError("message_delivery_uncertain", attempted=True) from error
            raise
        expected_ack = hmac.new(secret, f"ack|{message_key}|{result.get('messageId')}".encode("utf-8"), hashlib.sha256).hexdigest()
        if result.get("clientMessageId") != message_key or not hmac.compare_digest(expected_ack, str(result.get("ack") or "")):
            raise NetworkFabricError("message_delivery_uncertain", attempted=True)
        with self.lock:
            if not any(item.get("clientMessageId") == message_key and item.get("direction") == "outbound" for item in self.messages):
                self.messages.append({
                    "id": result["messageId"],
                    "clientMessageId": message_key,
                    "state": "delivered",
                    "direction": "outbound",
                    "peerId": str(peer_id),
                    "peerName": peer.get("name") or "KE Link peer",
                    "body": text,
                    "observedAt": _utc_iso(self.clock()),
                })
        return {"ok": True, "state": "delivered", "clientMessageId": message_key, "messageId": result["messageId"]}


class NetworkFabricService:
    def __init__(
        self,
        data_root=None,
        clock=None,
        interface_provider=None,
        command_runner=None,
        ping_probe=None,
        mdns_probe=None,
        ssdp_probe=None,
        connection_provider=None,
        opener=None,
        wol_sender=None,
        link_manager=None,
        settings_opener=None,
    ):
        self.clock = clock or time.time
        self.interface_provider = interface_provider or _interface_snapshot
        self.command_runner = command_runner or _run_command
        self.ping_probe = ping_probe or _default_ping
        self.mdns_probe = mdns_probe or _default_mdns
        self.ssdp_probe = ssdp_probe or _default_ssdp
        self.connection_provider = connection_provider or self._connections
        self.opener = opener or self._open_url
        self.wol_sender = wol_sender or self._send_wol
        self.settings_opener = settings_opener or self._open_system_settings
        self.link = link_manager or KELinkManager(
            data_root=data_root,
            clock=self.clock,
            interface_provider=self.interface_provider,
        )
        self.lock = threading.RLock()
        self.lifecycle_lock = threading.Lock()
        self.recovery_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.scan_event = threading.Event()
        self.thread = None
        self.worker_generation = 0
        self.stop_request_generation = 0
        self.active = False
        self.scanning = False
        self.scan_sequence = 0
        self.last_scan_at = None
        self.last_deep_scan_at = None
        self.devices = {}
        self.identity_map = {}
        self.interfaces = []
        self.excluded_interfaces = []
        self.coverage_limited = False
        self.errors = []

    def start_discovery(self):
        with self.lifecycle_lock:
            return self._start_discovery_locked()

    def _start_discovery_locked(self, expected_stop_generation=None):
        """Start while lifecycle_lock is held so recovery and tab-close serialize."""
        with self.lock:
            if (
                expected_stop_generation is not None
                and int(expected_stop_generation) != self.stop_request_generation
            ):
                raise NetworkFabricError("discovery_inactive")
            if self.active:
                return self.get_snapshot()
            if self.thread is not None and self.thread.is_alive():
                raise NetworkFabricError("discovery_unavailable")
            self.thread = None
            self.worker_generation += 1
            generation = self.worker_generation
            self.active = True
            self.stop_event = threading.Event()
            self.scan_event = threading.Event()
            self.scan_event.set()
            self.thread = threading.Thread(
                target=self._loop,
                args=(self.stop_event, self.scan_event, generation),
                name="network-fabric-discovery",
                daemon=True,
            )
            self.thread.start()
        return self.get_snapshot()

    def stop_discovery(self):
        # Publish tab-close intent before waiting on a recovery-held lifecycle
        # lock, so an in-flight stop->start cannot launch behind the close.
        with self.lock:
            self.stop_request_generation += 1
            self.active = False
            self.stop_event.set()
            self.scan_event.set()
        with self.lifecycle_lock:
            return self._stop_discovery_locked()

    def _stop_discovery_locked(self):
        """Stop while lifecycle_lock is held so no recovery can restart behind it."""
        with self.lock:
            had_generation = self.active or self.thread is not None
            self.active = False
            self.stop_event.set()
            self.scan_event.set()
            thread = self.thread
            if had_generation:
                self.worker_generation += 1
        if thread is not None and thread.is_alive():
            thread.join(timeout=DISCOVERY_STOP_TIMEOUT_SECONDS)
        with self.lock:
            if thread is self.thread and (thread is None or not thread.is_alive()):
                self.thread = None
                self.scanning = False
        return self.get_snapshot()

    def _restart_discovery(self, expected_worker_generation=None, expected_stop_generation=None):
        """Atomically stop then start; a concurrent tab close always runs last."""
        with self.lock:
            worker_generation = self.worker_generation if expected_worker_generation is None else int(expected_worker_generation)
            stop_generation = self.stop_request_generation if expected_stop_generation is None else int(expected_stop_generation)
        with self.lifecycle_lock:
            with self.lock:
                if worker_generation != self.worker_generation or stop_generation != self.stop_request_generation:
                    raise NetworkFabricError("recovery_stale")
            self._stop_discovery_locked()
            with self.lock:
                if self.thread is not None and self.thread.is_alive():
                    raise NetworkFabricError("discovery_unavailable")
                if stop_generation != self.stop_request_generation:
                    raise NetworkFabricError("recovery_stale")
            return self._start_discovery_locked(stop_generation)

    def shutdown(self):
        self.stop_discovery()
        self.link.disable()
        return {"ok": True}

    def request_deep_scan(self):
        with self.lock:
            if not self.active:
                raise NetworkFabricError("discovery_inactive", "Open the Network tab before requesting a scan")
            now = self.clock()
            if self.last_deep_scan_at and now - self.last_deep_scan_at < DEEP_SCAN_CADENCE_SECONDS:
                remaining = int(DEEP_SCAN_CADENCE_SECONDS - (now - self.last_deep_scan_at))
                return {"ok": True, "queued": False, "rateLimited": True, "retryAfterSeconds": max(1, remaining)}
            self.scan_event.set()
        return {"ok": True, "queued": True, "rateLimited": False}

    def _recovery_generation_for_code(self, code):
        target = recovery_plan(code).get("target")
        if target in {"ke-link-advertiser", "ke-link-control", "selected-peer", "pending-message", "trust", "pairing", "message", "ke-link"}:
            return max(0, int(getattr(self.link, "listener_generation", 0)))
        with self.lock:
            return max(0, int(self.worker_generation))

    def error_projection(self, code, source="network", observed_at=None):
        return public_error(
            code,
            source,
            self.clock() if observed_at is None else observed_at,
            recovery_generation=self._recovery_generation_for_code(code),
        )

    @staticmethod
    def _bind_error_generation(item, generation):
        if not isinstance(item, dict):
            return public_error("network_internal_error", recovery_generation=generation)
        result = public_error(
            item.get("code"),
            item.get("source"),
            recovery_generation=generation,
        )
        observed_at = item.get("observedAt")
        if isinstance(observed_at, str) and len(observed_at) <= 40:
            result["observedAt"] = observed_at
        return result

    def set_link_enabled(self, enabled):
        return self.link.enable() if bool(enabled) else self.link.disable()

    def recover_connection(self, code, source=None, device_id=None, after_settings=False, expected_generation=None):
        """Run exactly one allowlisted recovery after an explicit UI click."""
        safe_error = self.error_projection(code, source or "network")
        plan = safe_error["recovery"]
        action = plan["action"]
        device_key = str(device_id or "")[:128]
        try:
            supplied_generation = int(expected_generation)
        except (TypeError, ValueError):
            supplied_generation = -1
        if supplied_generation != plan["generation"]:
            raise NetworkFabricError("recovery_stale")
        if not self.recovery_lock.acquire(blocking=False):
            raise NetworkFabricError("recovery_busy")
        try:
            if action in {"open-local-network-settings", "open-network-settings", "open-wifi-settings"} and not bool(after_settings):
                target = LOCAL_NETWORK_SETTINGS_URL if action == "open-local-network-settings" else NETWORK_SETTINGS_URL
                try:
                    self.settings_opener(target)
                except Exception as error:
                    raise NetworkFabricError("system_settings_unavailable") from error
                return {
                    "ok": True,
                    "state": "waiting-for-user",
                    "code": safe_error["code"],
                    "recovery": plan,
                    "autoRetryOnReturn": True,
                    "message": (
                        "Turn on Activity Monitor in Local Network, then return here; recovery will retry automatically."
                        if action == "open-local-network-settings"
                        else "Review the active Wi-Fi or network interface, then return here; recovery will retry automatically."
                    ),
                }
            if action in {"restart-discovery", "refresh-device", "open-local-network-settings", "open-network-settings", "open-wifi-settings"}:
                with self.lock:
                    if supplied_generation != self.worker_generation:
                        raise NetworkFabricError("recovery_stale")
                    recovery_stop_generation = self.stop_request_generation
                snapshot = self._restart_discovery(
                    expected_worker_generation=supplied_generation,
                    expected_stop_generation=recovery_stop_generation,
                )
                return {
                    "ok": True,
                    "state": "rechecking",
                    "code": safe_error["code"],
                    "recovery": plan,
                    "snapshot": snapshot,
                }
            if action == "retry-connections":
                with self.lock:
                    if supplied_generation != self.worker_generation or not self.active:
                        raise NetworkFabricError("recovery_stale")
                try:
                    rows = self.connection_provider()
                except Exception as error:
                    with self.lock:
                        if supplied_generation != self.worker_generation or not self.active:
                            raise NetworkFabricError("recovery_stale") from error
                    self._set_source_error("connections", "connections_unavailable")
                    raise NetworkFabricError("connections_unavailable") from error
                with self.lock:
                    if supplied_generation != self.worker_generation or not self.active:
                        raise NetworkFabricError("recovery_stale")
                    interfaces = list(self.interfaces)
                    own_ips = {
                        _own_address_key(value, item.get("name"))
                        for item in interfaces
                        for value in item.get("addresses") or []
                        if _own_address_key(value, item.get("name"))
                    }
                    own_macs = {
                        mac
                        for item in interfaces
                        for mac in [_normalize_mac(item.get("mac"))]
                        if mac
                    }
                    self._apply_observations(
                        self._connection_observations(rows, interfaces),
                        self.clock(),
                        own_ips,
                        own_macs,
                        {socket.gethostname().lower(), f"{socket.gethostname().lower()}.local"},
                    )
                    self._clear_source_error("connections")
                return {
                    "ok": True,
                    "state": "source-rechecked",
                    "code": safe_error["code"],
                    "recovery": plan,
                    "snapshot": self.get_snapshot(),
                }
            if action == "enable-ke-link":
                return {
                    "ok": True,
                    "state": "action-required",
                    "code": safe_error["code"],
                    "recovery": plan,
                    "errorDetail": safe_error,
                    "message": "Use the separate KE Link toggle to enable the listener. Fix Connection never enables it.",
                }
            if action == "repair-ke-link":
                status = self.link.repair_advertiser_if_enabled(supplied_generation)
                if not status.get("enabled"):
                    guided = self.error_projection("ke_link_disabled", "ke-link")
                    return {
                        "ok": True,
                        "state": "action-required",
                        "code": guided["code"],
                        "recovery": guided["recovery"],
                        "errorDetail": guided,
                        "message": guided["message"],
                    }
                return {"ok": True, "state": "link-rechecked", "code": safe_error["code"], "recovery": plan, "link": status}
            if action == "verify-peer":
                if not device_key:
                    raise NetworkFabricError("device_not_found")
                result = self.verify_link_session(
                    device_key,
                    expected_link_generation=supplied_generation,
                )
                return {"ok": True, "state": "peer-ready", "code": safe_error["code"], "recovery": plan, "peer": result}
            return {
                "ok": True,
                "state": "action-required",
                "code": safe_error["code"],
                "recovery": plan,
                "errorDetail": safe_error,
                "message": safe_error["message"],
            }
        finally:
            self.recovery_lock.release()

    def begin_pairing(self):
        return self.link.begin_pairing()

    def _loop(self, stop_event, scan_event, generation):
        first = True
        try:
            while not stop_event.is_set():
                now = self.clock()
                deep = first or scan_event.is_set()
                if self.last_deep_scan_at and now - self.last_deep_scan_at < DEEP_SCAN_CADENCE_SECONDS:
                    deep = first
                scan_event.clear()
                try:
                    self._scan_once(deep=deep, stop_event=stop_event)
                except Exception as error:
                    with self.lock:
                        self.scanning = False
                    self._set_source_error(
                        "discovery",
                        "permission_denied" if _permission_denied_error(error) else "discovery_unavailable",
                    )
                first = False
                stop_event.wait(8.0)
        finally:
            with self.lock:
                if generation == self.worker_generation and self.thread is threading.current_thread():
                    self.thread = None
                    self.scanning = False
                    if not stop_event.is_set():
                        self.active = False

    def _clear_source_error(self, label):
        source = public_error("discovery_unavailable", label)["source"]
        with self.lock:
            self.errors = [item for item in self.errors if item.get("source") != source]

    def _set_source_error(self, label, code):
        source = public_error("discovery_unavailable", label)["source"]
        with self.lock:
            self.errors = [item for item in self.errors if item.get("source") != source]
            self.errors.append(public_error(code, source, self.clock()))
            self.errors = self.errors[-12:]

    def _safe_call(self, label, callback, fallback, failure_code=None):
        try:
            result = callback()
        except Exception as error:
            code = (
                failure_code
                if failure_code in _ERROR_COPY
                else "permission_denied"
                if _permission_denied_error(error)
                else "discovery_unavailable"
            )
            self._set_source_error(
                label,
                code,
            )
            return fallback
        self._clear_source_error(label)
        return result

    def _command_rows(self, label, path, parser):
        result = self.command_runner([path, "-an"], timeout=1.25)
        if int(getattr(result, "returncode", 0) or 0) != 0:
            evidence = f"{getattr(result, 'stdout', '')}\n{getattr(result, 'stderr', '')}"
            raise NetworkFabricError(
                "permission_denied" if _permission_denied_output(evidence) else "discovery_unavailable"
            )
        return parser(getattr(result, "stdout", ""))

    def _scan_once(self, deep=False, stop_event=None):
        stop_event = self.stop_event if stop_event is None else stop_event
        with self.lock:
            if not self.active:
                return
            self.scanning = True
            self.scan_sequence += 1
        try:
            if stop_event.is_set():
                return
            observed_at = self.clock()
            all_interfaces = self._safe_call("interfaces", self.interface_provider, [])
            if stop_event.is_set():
                return
            interfaces = [item for item in all_interfaces if _discovery_interface_allowed(item)]
            excluded_interfaces = [
                {
                    "name": _clean_interface(item.get("name")) or "unknown",
                    "scope": str(item.get("scope") or "excluded")[:24],
                }
                for item in all_interfaces
                if isinstance(item, dict) and not _discovery_interface_allowed(item)
            ][:64]
            networks = _network_objects(interfaces)
            own_ips = {
                _own_address_key(value, item.get("name"))
                for item in all_interfaces
                for value in item.get("addresses") or []
                if _own_address_key(value, item.get("name"))
            }
            own_macs = {
                mac
                for item in all_interfaces
                for mac in [_normalize_mac(item.get("mac"))]
                if mac
            }
            own_names = {socket.gethostname().lower(), f"{socket.gethostname().lower()}.local"}

            def route_probe():
                result = self.command_runner([ROUTE_PATH, "-n", "get", "default"], timeout=1.0)
                if int(getattr(result, "returncode", 0) or 0) != 0:
                    evidence = f"{getattr(result, 'stdout', '')}\n{getattr(result, 'stderr', '')}"
                    raise NetworkFabricError(
                        "permission_denied" if _permission_denied_output(evidence) else "discovery_unavailable"
                    )
                return parse_default_route(getattr(result, "stdout", ""))

            route = self._safe_call("route", route_probe, {})
            if stop_event.is_set():
                return
            observations = []
            gateway = route.get("gateway")
            if gateway and _address_on_segments(gateway, networks, route.get("interface")):
                observations.append({"source": "route", "ip": gateway, "interface": route.get("interface"), "hostname": "Network gateway", "direct": False})
            for source, path, parser in (("arp", ARP_PATH, parse_arp), ("ndp", NDP_PATH, parse_ndp)):
                if stop_event.is_set():
                    return
                for row in self._safe_call(source, lambda s=source, p=path, f=parser: self._command_rows(s, p, f), []):
                    if _address_on_segments(row["ip"], networks, row.get("interface")):
                        observations.append({"source": source, "direct": False, **row})
            if stop_event.is_set():
                return
            observations.extend(self._connection_observations(
                self._safe_call(
                    "connections",
                    self.connection_provider,
                    [],
                    failure_code="connections_unavailable",
                ),
                interfaces,
            ))
            if stop_event.is_set():
                return
            mdns = self._safe_call(
                "bonjour",
                lambda: self.mdns_probe(stop_event, interfaces)
                if self.mdns_probe is _default_mdns
                else self.mdns_probe(stop_event),
                [],
            )
            for service in mdns:
                if not isinstance(service, dict):
                    continue
                service_interface = _clean_interface(service.get("interface"))
                if service.get("withdrawn"):
                    withdrawn_addresses = service.get("withdrawnAddresses") or []
                    if service.get("withdrawalKind") == "address" and withdrawn_addresses:
                        for address in withdrawn_addresses:
                            clean = _clean_ip(address, service_interface)
                            if clean and service_interface and _address_on_segments(clean, networks, service_interface):
                                observations.append({
                                    "source": "bonjour",
                                    "withdrawn": True,
                                    "withdrawalKind": "address",
                                    "ip": clean,
                                    "interface": service_interface,
                                    "service": service,
                                })
                    else:
                        observations.append({
                            "source": "bonjour",
                            "withdrawn": True,
                            "withdrawalKind": service.get("withdrawalKind") or "service",
                            "interface": service_interface,
                            "service": service,
                        })
                    continue
                for address in service.get("withdrawnAddresses") or []:
                    clean = _clean_ip(address, service_interface)
                    if clean and service_interface and _address_on_segments(clean, networks, service_interface):
                        observations.append({
                            "source": "bonjour",
                            "withdrawn": True,
                            "withdrawalKind": "address",
                            "ip": clean,
                            "interface": service_interface,
                            "service": service,
                        })
                addresses = []
                for item in service.get("addresses") or []:
                    interface = service_interface or _unique_segment_interface(item, networks)
                    if interface and _address_on_segments(item, networks, interface):
                        addresses.append((_clean_ip(item, interface), interface))
                for address, interface in addresses:
                    observations.append({
                        "source": "bonjour",
                        "direct": True,
                        "ip": address,
                        "hostname": service.get("host"),
                        "service": service,
                        "interface": interface,
                    })
            if stop_event.is_set():
                return
            ssdp_rows = self._safe_call(
                "ssdp",
                lambda: self.ssdp_probe(stop_event, 1.0, interfaces)
                if self.ssdp_probe is _default_ssdp
                else self.ssdp_probe(stop_event),
                [],
            )
            for row in ssdp_rows:
                try:
                    if not isinstance(row, dict):
                        continue
                    interface = _clean_interface(row.get("interface")) or _unique_segment_interface(row.get("ip"), networks)
                    if not interface or not _address_on_segments(row.get("ip"), networks, interface):
                        continue
                    service = self._ssdp_service(row)
                except (AttributeError, TypeError, ValueError):
                    continue
                observations.append({"source": "ssdp", "direct": True, **row, "interface": interface, "service": service})
            if stop_event.is_set():
                return
            self._apply_observations(observations, observed_at, own_ips, own_macs, own_names)

            targets, coverage_limited = _scan_targets(interfaces, all_interfaces)
            if deep and targets and not stop_event.is_set():
                ping_observations = []
                ping_errors = []

                def probe(item):
                    if stop_event.is_set():
                        return None
                    return self.ping_probe(item[0], item[1], item[3])

                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    for offset in range(0, len(targets), 8):
                        if stop_event.is_set():
                            break
                        futures = {pool.submit(probe, item): item for item in targets[offset:offset + 8]}
                        for future in concurrent.futures.as_completed(futures):
                            ip, interface, _network, _source = futures[future]
                            try:
                                latency = future.result()
                            except Exception as error:
                                ping_errors.append(error)
                                latency = None
                            if latency is not None:
                                ping_observations.append({"source": "icmp", "direct": True, "ip": ip, "interface": interface, "latencyMs": latency})
                        if stop_event.is_set():
                            for future in futures:
                                future.cancel()
                            break
                if not stop_event.is_set():
                    self._apply_observations(ping_observations, self.clock(), own_ips, own_macs, own_names)
                    if ping_errors:
                        self._set_source_error(
                            "icmp",
                            "permission_denied" if any(_permission_denied_error(error) for error in ping_errors) else "discovery_unavailable",
                        )
                    else:
                        self._clear_source_error("icmp")
                    self.last_deep_scan_at = self.clock()
            if stop_event.is_set():
                return
            with self.lock:
                self.interfaces = interfaces
                self.excluded_interfaces = excluded_interfaces
                self.coverage_limited = coverage_limited
                self.last_scan_at = self.clock()
                self._expire_devices(self.clock())
            self._clear_source_error("discovery")
        finally:
            with self.lock:
                self.scanning = False

    @staticmethod
    def _connections():
        rows = []
        try:
            for connection in psutil.net_connections(kind="inet"):
                remote = connection.raddr
                if not remote:
                    continue
                ip = getattr(remote, "ip", remote[0] if remote else None)
                if _clean_ip(ip):
                    rows.append({"ip": _clean_ip(ip)})
        except (psutil.AccessDenied, PermissionError) as error:
            # macOS commonly denies process-wide socket inventory to ordinary
            # users.  That optional signal is unrelated to Local Network TCC;
            # the remaining ARP/NDP/ICMP/Bonjour/SSDP sources stay valid.
            raise NetworkFabricError("connections_unavailable") from error
        except OSError as error:
            if getattr(error, "errno", None) in {errno.EACCES, errno.EPERM}:
                raise NetworkFabricError("connections_unavailable") from error
            raise NetworkFabricError("discovery_unavailable") from error
        return rows

    @staticmethod
    def _connection_observations(rows, interfaces):
        networks = _network_objects(interfaces)
        observations = []
        for row in rows if isinstance(rows, (list, tuple)) else []:
            if not isinstance(row, dict):
                continue
            interface = _clean_interface(row.get("interface")) or _unique_segment_interface(row.get("ip"), networks)
            if interface and _address_on_segments(row.get("ip"), networks, interface):
                observations.append({"source": "connection", "direct": True, **row, "interface": interface})
        return observations

    @staticmethod
    def _ssdp_service(row):
        location = row.get("location")
        try:
            parsed = urlparse(location) if location else None
            host = _clean_hostname(parsed.hostname) if parsed else None
            parsed_port = parsed.port if parsed else None
        except (TypeError, ValueError):
            parsed = None
            host = None
            parsed_port = None
        scheme = parsed.scheme if parsed and parsed.scheme in {"http", "https"} else None
        port = parsed_port if parsed_port is not None else 443 if scheme == "https" else 80 if scheme == "http" else None
        safe_url = (
            str(location)[:1024]
            if scheme and host and port and parsed.username is None and parsed.password is None
            else None
        )
        return {
            "type": "ssdp",
            "name": _safe_display_label(row.get("st"), "UPnP device", 160),
            "host": host or row.get("ip"),
            "port": port,
            "url": safe_url,
            "properties": {"usn": str(row.get("usn") or "")[:256]},
        }

    @staticmethod
    def _observation_keys(observation):
        keys = []
        mac = _normalize_mac(observation.get("mac"))
        interface = _clean_interface(observation.get("interface"))
        ip = _clean_ip(observation.get("ip"), interface)
        host = _clean_hostname(observation.get("hostname"))
        service = observation.get("service") or {}
        remote_id = (service.get("properties") or {}).get("id") if isinstance(service, dict) else None
        if mac:
            keys.append(f"mac:{mac}")
        if remote_id and re.fullmatch(r"[a-f0-9]{32}", str(remote_id)):
            keys.append(f"ke:{remote_id}")
        if host:
            keys.append(f"host:{host.lower()}|if:{interface or '-'}")
        if ip:
            keys.append(f"ip:{ip}|if:{interface or _ip_scope(ip) or '-'}")
        return keys

    @staticmethod
    def _stable_identity(observation):
        service = observation.get("service") if isinstance(observation, dict) else None
        properties = service.get("properties") if isinstance(service, dict) and isinstance(service.get("properties"), dict) else {}
        remote_id = str(properties.get("id") or "")
        return {
            "mac": _normalize_mac(observation.get("mac")),
            "ke": remote_id if re.fullmatch(r"[a-f0-9]{32}", remote_id) else None,
        }

    @staticmethod
    def _device_stable_identity(device):
        peer_id = str(device.get("linkPeerId") or "")
        return {
            "mac": _normalize_mac(device.get("mac")),
            "ke": peer_id if re.fullmatch(r"[a-f0-9]{32}", peer_id) else None,
        }

    @classmethod
    def _stable_identity_conflicts(cls, observation, device):
        incoming = cls._stable_identity(observation)
        existing = cls._device_stable_identity(device)
        return any(
            incoming[kind] and existing[kind] and incoming[kind] != existing[kind]
            for kind in ("mac", "ke")
        )

    @staticmethod
    def _bonjour_type(value):
        raw_type = str(value or "").lower().strip()
        short_type = raw_type[:-7] if raw_type.endswith(".local.") else raw_type.rstrip(".")
        return f"{short_type}.local." if short_type in BONJOUR_SERVICE_ALLOWLIST else None

    @classmethod
    def _bonjour_service_matches(cls, retained, selector):
        if not isinstance(retained, dict) or not isinstance(selector, dict):
            return False
        type_name = cls._bonjour_type(selector.get("type"))
        interface = _clean_interface(selector.get("interface"))
        selector_key = _validated_bonjour_instance_key(selector.get("instanceKey"))
        retained_key = _validated_bonjour_instance_key(retained.get("instanceKey"))
        return bool(
            type_name
            and interface
            and selector_key
            and retained_key
            and retained.get("type") == type_name
            and _clean_interface(retained.get("interface")) == interface
            and hmac.compare_digest(retained_key, selector_key)
        )

    @staticmethod
    def _service_endpoint_values(service):
        interface = _clean_interface(service.get("interface")) if isinstance(service, dict) else None
        values = []
        for value in (service.get("endpoints") or []) if isinstance(service, dict) else []:
            clean = _clean_ip(value, interface)
            if clean:
                values.append(clean)
        observed = _clean_ip(service.get("observedAddress"), interface) if isinstance(service, dict) else None
        if observed:
            values.append(observed)
        return sorted(set(values), key=_ip_sort_key)

    def _refresh_device_evidence(self, device):
        source_times = {source: [] for source in DIRECT_OBSERVATION_SOURCES}
        for record in (device.get("addresses") or {}).values():
            if not isinstance(record, dict):
                continue
            record_sources = record.get("sources") if isinstance(record.get("sources"), dict) else {}
            for source in DIRECT_OBSERVATION_SOURCES:
                if source in record_sources:
                    source_times[source].append(float(record_sources[source] or 0))
        services = device.get("services") or {}
        for service in services.values():
            if self._bonjour_type(service.get("type")):
                source_times["bonjour"].append(float(service.get("lastSeen") or 0))
        for source, times in source_times.items():
            clean_times = [value for value in times if value > 0]
            if clean_times:
                device.setdefault("sources", {})[source] = max(clean_times)
            else:
                device.setdefault("sources", {}).pop(source, None)
        device["lastDirect"] = max(
            (value for values in source_times.values() for value in values if value > 0),
            default=0.0,
        )

    def _refresh_device_link_identity(self, device):
        identities = set()
        for service in (device.get("services") or {}).values():
            if service.get("type") != KE_LINK_TYPE:
                continue
            properties = service.get("properties") if isinstance(service.get("properties"), dict) else {}
            peer_id = str(properties.get("id") or "")
            fingerprint = str(properties.get("fp") or "")
            if re.fullmatch(r"[a-f0-9]{32}", peer_id) and re.fullmatch(r"[a-f0-9]{64}", fingerprint):
                identities.add((peer_id, fingerprint))
        if len(identities) == 1:
            device["linkPeerId"], device["linkFingerprint"] = next(iter(identities))
        elif len(identities) > 1:
            device.pop("linkPeerId", None)
            device.pop("linkFingerprint", None)

    def _discard_device_address(self, device, address, interface, source=None, force=False):
        clean = _clean_ip(address, interface)
        clean_interface = _clean_interface(interface) or _ip_scope(clean)
        record_key = _address_key(clean, clean_interface) if clean else None
        if not record_key:
            return False
        record = (device.get("addresses") or {}).get(record_key)
        if record is None:
            return False
        remove_record = bool(force)
        if isinstance(record, dict) and not remove_record:
            record_sources = dict(record.get("sources") or {})
            if source:
                record_sources.pop(str(source), None)
            if record_sources:
                record["sources"] = record_sources
                record["lastSeen"] = max(float(value or 0) for value in record_sources.values())
            else:
                remove_record = True
        else:
            remove_record = True
        if remove_record:
            del device["addresses"][record_key]
            identity_key = f"ip:{clean}|if:{clean_interface or '-'}"
            if self.identity_map.get(identity_key) == device.get("id"):
                del self.identity_map[identity_key]
        return remove_record

    def _apply_bonjour_withdrawal(self, observation):
        selector = observation.get("service") if isinstance(observation.get("service"), dict) else {}
        interface = _clean_interface(observation.get("interface")) or _clean_interface(selector.get("interface"))
        type_name = self._bonjour_type(selector.get("type"))
        instance_key = (
            _validated_bonjour_instance_key(selector.get("instanceKey"))
        )
        if not interface or not type_name or not instance_key:
            return
        address = _clean_ip(observation.get("ip"), interface)
        address_only = observation.get("withdrawalKind") == "address" or bool(address)
        for device in self.devices.values():
            removed_addresses = set()
            matched = False
            for service_id, retained in list((device.get("services") or {}).items()):
                if not self._bonjour_service_matches(retained, {
                    "type": type_name,
                    "instanceKey": instance_key,
                    "interface": interface,
                }):
                    continue
                endpoints = self._service_endpoint_values(retained)
                if address_only:
                    if not address or address not in endpoints:
                        continue
                    remaining = [value for value in endpoints if value != address]
                    removed_addresses.add(address)
                    if remaining:
                        retained["endpoints"] = remaining
                        retained["observedAddress"] = remaining[0]
                    else:
                        del device["services"][service_id]
                else:
                    removed_addresses.update(endpoints)
                    del device["services"][service_id]
                matched = True
            if not matched:
                continue
            remaining_endpoints = {
                value
                for retained in (device.get("services") or {}).values()
                for value in self._service_endpoint_values(retained)
            }
            for removed in removed_addresses - remaining_endpoints:
                self._discard_device_address(device, removed, interface, source="bonjour")
            self._refresh_device_link_identity(device)
            self._refresh_device_evidence(device)

    def _invalidate_conflicting_address_owner(self, device, address, interface):
        clean = _clean_ip(address, interface)
        clean_interface = _clean_interface(interface) or _ip_scope(clean)
        if not clean or not clean_interface:
            return
        for service_id, retained in list((device.get("services") or {}).items()):
            if _clean_interface(retained.get("interface")) != clean_interface:
                continue
            endpoints = self._service_endpoint_values(retained)
            if clean not in endpoints:
                continue
            remaining = [value for value in endpoints if value != clean]
            if remaining:
                retained["endpoints"] = remaining
                retained["observedAddress"] = remaining[0]
            else:
                del device["services"][service_id]
        self._discard_device_address(device, clean, clean_interface, force=True)
        self._refresh_device_link_identity(device)
        self._refresh_device_evidence(device)

    def _apply_observations(self, observations, observed_at, own_ips, own_macs, own_names):
        with self.lock:
            for observation in observations:
                if not isinstance(observation, dict):
                    continue
                if observation.get("withdrawn") and observation.get("source") == "bonjour":
                    self._apply_bonjour_withdrawal(observation)
                    continue
                interface = _clean_interface(observation.get("interface"))
                ip = _clean_ip(observation.get("ip"), interface)
                mac = _normalize_mac(observation.get("mac"))
                host = _clean_hostname(observation.get("hostname"))
                own_key = _own_address_key(ip, interface)
                if own_key in own_ips or (mac is not None and mac in own_macs):
                    continue
                keys = self._observation_keys(observation)
                if not keys:
                    continue
                stable_keys = [key for key in keys if key.startswith(("mac:", "ke:"))]
                ephemeral_keys = [key for key in keys if key not in stable_keys]
                stable_matches = {
                    self.identity_map[key]
                    for key in stable_keys
                    if key in self.identity_map
                }
                if len(stable_matches) > 1:
                    continue
                if stable_matches:
                    device_id = next(iter(stable_matches))
                    existing = self.devices.get(device_id)
                    if not existing or self._stable_identity_conflicts(observation, existing):
                        continue
                else:
                    ephemeral_matches = {
                        self.identity_map[key]
                        for key in ephemeral_keys
                        if key in self.identity_map
                    }
                    eligible_matches = {
                        device_id
                        for device_id in ephemeral_matches
                        if device_id in self.devices
                        and not self._stable_identity_conflicts(observation, self.devices[device_id])
                    }
                    if len(eligible_matches) > 1:
                        continue
                    device_id = (
                        next(iter(eligible_matches))
                        if eligible_matches
                        else f"device-{_sha(stable_keys[0] if stable_keys else keys[0])[:16]}"
                    )
                device = self.devices.setdefault(device_id, {
                    "id": device_id,
                    "firstSeen": observed_at,
                    "lastSeen": 0.0,
                    "lastDirect": 0.0,
                    "addresses": {},
                    "names": {},
                    "sources": {},
                    "services": {},
                    "mac": None,
                    "interface": None,
                    "latencyMs": None,
                })
                if stable_keys and ip:
                    ip_key = f"ip:{ip}|if:{interface or _ip_scope(ip) or '-'}"
                    previous_id = self.identity_map.get(ip_key)
                    previous = self.devices.get(previous_id) if previous_id != device_id else None
                    if previous and self._stable_identity_conflicts(observation, previous):
                        self._invalidate_conflicting_address_owner(previous, ip, interface)
                for key in keys:
                    mapped = self.identity_map.get(key)
                    if mapped in (None, device_id):
                        self.identity_map[key] = device_id
                device["lastSeen"] = max(float(device.get("lastSeen") or 0), observed_at)
                if observation.get("direct"):
                    device["lastDirect"] = max(float(device.get("lastDirect") or 0), observed_at)
                source = str(observation.get("source") or "observed")
                device["sources"][source] = observed_at
                if ip:
                    record_key = _address_key(ip, interface)
                    previous_record = device["addresses"].get(record_key)
                    record_sources = (
                        dict(previous_record.get("sources") or {})
                        if isinstance(previous_record, dict)
                        else {}
                    )
                    record_sources[source] = observed_at
                    device["addresses"][record_key] = {
                        "address": ip,
                        "interface": interface or _ip_scope(ip),
                        "lastSeen": observed_at,
                        "sources": record_sources,
                    }
                if mac:
                    device["mac"] = mac
                if host:
                    device["names"][host] = observed_at
                if interface:
                    device["interface"] = interface
                if observation.get("latencyMs") is not None:
                    device["latencyMs"] = float(observation["latencyMs"])
                service = observation.get("service")
                if isinstance(service, dict):
                    self._record_service(device, service, observed_at, ip, interface)
            self._expire_devices(observed_at)

    def _merge_devices(self, target_id, duplicate_id):
        target = self.devices.get(target_id)
        duplicate = self.devices.pop(duplicate_id, None)
        if not target or not duplicate:
            return
        target["firstSeen"] = min(target["firstSeen"], duplicate["firstSeen"])
        target["lastSeen"] = max(target["lastSeen"], duplicate["lastSeen"])
        target["lastDirect"] = max(target["lastDirect"], duplicate["lastDirect"])
        for field in ("addresses", "names", "sources", "services"):
            target[field].update(duplicate.get(field) or {})
        target["mac"] = target.get("mac") or duplicate.get("mac")
        target["interface"] = target.get("interface") or duplicate.get("interface")
        target["latencyMs"] = target.get("latencyMs") if target.get("latencyMs") is not None else duplicate.get("latencyMs")
        target["linkPeerId"] = target.get("linkPeerId") or duplicate.get("linkPeerId")
        target["linkFingerprint"] = target.get("linkFingerprint") or duplicate.get("linkFingerprint")
        for key, value in list(self.identity_map.items()):
            if value == duplicate_id:
                self.identity_map[key] = target_id

    def _drop_device(self, device_id):
        self.devices.pop(device_id, None)
        for key, value in list(self.identity_map.items()):
            if value == device_id:
                del self.identity_map[key]

    def _record_service(self, device, service, observed_at, fallback_ip, interface=None):
        raw_type = str(service.get("type") or "").lower().strip()
        short_type = raw_type[:-7] if raw_type.endswith(".local.") else raw_type.rstrip(".")
        type_name = (
            "ssdp"
            if raw_type == "ssdp"
            else f"{short_type}.local."
            if short_type in BONJOUR_SERVICE_ALLOWLIST
            else "service"
        )
        name = _safe_display_label(service.get("name") or type_name, "Observed service", 160)
        instance_key = (
            _validated_bonjour_instance_key(service.get("instanceKey"))
            or _bonjour_instance_key(service.get("name"))
        ) if type_name.endswith(".local.") else None
        if type_name.endswith(".local.") and not instance_key:
            # Synthetic/internal observations without an instance name remain
            # non-withdrawable by display label, but keep their prior identity
            # behavior for stable-peer conflict handling.
            instance_key = _bonjour_instance_key(type_name)
        service_interface = _clean_interface(service.get("interface")) or _clean_interface(interface)
        observed_address = _clean_ip(fallback_ip, service_interface)
        host = _clean_hostname(service.get("host")) or _clean_endpoint_host(
            service.get("host"),
            interface=service_interface,
        ) or fallback_ip
        try:
            port = int(service.get("port")) if service.get("port") is not None else None
        except (TypeError, ValueError):
            port = None
        if port is not None and not (1 <= port <= 65535):
            port = None
        label, scheme = _service_kind(type_name)
        properties = service.get("properties") if isinstance(service.get("properties"), dict) else {}
        safe_properties = {key: str(value)[:256] for key, value in properties.items() if key in {"id", "fp", "proto"}}
        is_ke_link = type_name == KE_LINK_TYPE or "_ke-link._tcp" in type_name
        identity_material = (
            f"{type_name}|{instance_key}|{safe_properties.get('id')}|{safe_properties.get('fp')}|{port}|{service_interface}"
            if is_ke_link
            else f"{type_name}|{instance_key or name}|{host}|{port}|{service_interface}|{observed_address}"
        )
        service_id = f"service-{_sha(identity_material)[:16]}"
        url = service.get("url") or _service_url(scheme, host, port)
        if url and scheme is None:
            advertised_scheme = urlparse(str(url)).scheme.lower()
            if advertised_scheme in {"http", "https"}:
                scheme = advertised_scheme
        if service_id not in device["services"] and len(device["services"]) >= MAX_SERVICES:
            oldest_id = min(device["services"], key=lambda key: float(device["services"][key].get("lastSeen") or 0))
            del device["services"][oldest_id]
        previous = device["services"].get(service_id) if is_ke_link else None
        endpoints = []
        if previous and float(previous.get("lastSeen") or 0) == float(observed_at):
            endpoints.extend(previous.get("endpoints") or [])
            if previous.get("observedAddress"):
                endpoints.append(previous["observedAddress"])
        if observed_address:
            endpoints.append(observed_address)
        endpoints = sorted(set(endpoints), key=_ip_sort_key)[:8]
        selected_observed = next(
            (value for value in endpoints if (_ip_address(value) or ipaddress.ip_address("::")).version == 4),
            endpoints[0] if endpoints else None,
        )
        device["services"][service_id] = {
            "id": service_id,
            "type": type_name,
            "name": name,
            "instanceKey": instance_key,
            "label": label,
            "host": host,
            "port": port,
            "url": url,
            "scheme": scheme,
            "properties": safe_properties,
            "interface": service_interface,
            "observedAddress": selected_observed,
            "endpoints": endpoints if is_ke_link else ([observed_address] if observed_address else []),
            "lastSeen": observed_at,
        }
        if is_ke_link:
            peer_id = safe_properties.get("id")
            fingerprint = safe_properties.get("fp")
            if re.fullmatch(r"[a-f0-9]{32}", str(peer_id or "")) and re.fullmatch(r"[a-f0-9]{64}", str(fingerprint or "")):
                device["linkPeerId"] = peer_id
                device["linkFingerprint"] = fingerprint

    def _expire_devices(self, now):
        for item in self.devices.values():
            addresses = item.get("addresses") or {}
            for address_key, record in list(addresses.items()):
                last_seen = float(record.get("lastSeen") or 0) if isinstance(record, dict) else float(record or 0)
                if now - last_seen <= SERVICE_TTL_SECONDS:
                    continue
                address = record.get("address") if isinstance(record, dict) else address_key
                interface = record.get("interface") if isinstance(record, dict) else item.get("interface")
                clean = _clean_ip(address, interface)
                identity_key = f"ip:{clean}|if:{_clean_interface(interface) or _ip_scope(clean) or '-'}" if clean else None
                del addresses[address_key]
                if identity_key and self.identity_map.get(identity_key) == item.get("id"):
                    del self.identity_map[identity_key]
            services = item.get("services") or {}
            for service_id, service in list(services.items()):
                if now - float(service.get("lastSeen") or 0) > SERVICE_TTL_SECONDS:
                    del services[service_id]
        expired = [device_id for device_id, item in self.devices.items() if now - item.get("lastSeen", 0) > DEVICE_RETENTION_SECONDS]
        for device_id in expired:
            self._drop_device(device_id)
        if len(self.devices) > MAX_DEVICES:
            ordered = sorted(self.devices.values(), key=lambda item: item.get("lastSeen", 0), reverse=True)
            keep = {item["id"] for item in ordered[:MAX_DEVICES]}
            for device_id in list(self.devices):
                if device_id not in keep:
                    self._drop_device(device_id)

    @staticmethod
    def _address_records(item):
        records = []
        for key, value in (item.get("addresses") or {}).items():
            if isinstance(value, dict):
                address = _clean_ip(value.get("address"), value.get("interface")) or _clean_endpoint_host(
                    value.get("address"), allow_loopback=True, interface=value.get("interface")
                )
                interface = _clean_interface(value.get("interface")) or _ip_scope(address)
                last_seen = float(value.get("lastSeen") or 0)
            else:
                address = _clean_ip(key, item.get("interface")) or _clean_endpoint_host(
                    key, allow_loopback=True, interface=item.get("interface")
                )
                interface = _clean_interface(item.get("interface")) or _ip_scope(address)
                last_seen = float(value or 0)
            if address:
                records.append({"address": address, "interface": interface, "lastSeen": last_seen})
        records.sort(key=lambda row: (_ip_sort_key(row["address"]), row.get("interface") or ""))
        return records

    @classmethod
    def _select_device_address(cls, item, interface=None, ipv4_only=False):
        clean_interface = _clean_interface(interface)
        matches = [
            row for row in cls._address_records(item)
            if (not clean_interface or row.get("interface") == clean_interface)
            and (not ipv4_only or (_ip_address(row["address"]) or ipaddress.ip_address("::")).version == 4)
        ]
        return matches[0]["address"] if matches else None

    def _device_route_bindings(self, item, *, ipv4_only=False):
        bindings = []
        for row in self._address_records(item):
            address = _ip_address(row["address"])
            if address is None or (ipv4_only and address.version != 4):
                continue
            binding = _route_binding(row["address"], self.interfaces, row.get("interface"))
            if binding:
                bindings.append(binding)
        unique = {
            (item["address"], item["interface"], item["sourceAddress"]): item
            for item in bindings
        }
        return list(unique.values())

    @classmethod
    def _service_endpoint(cls, item, service):
        if not isinstance(service, dict):
            return None
        interface = _clean_interface(service.get("interface"))
        endpoint_values = list(service.get("endpoints") or [])
        if service.get("observedAddress"):
            endpoint_values.append(service.get("observedAddress"))
        observed_endpoints = {
            clean
            for value in endpoint_values
            for clean in [_clean_ip(value, interface)]
            if clean
        }
        matches = [
            row["address"]
            for row in cls._address_records(item)
            if row.get("interface") == interface
            and (not observed_endpoints or row["address"] in observed_endpoints)
        ]
        unique = sorted(set(matches), key=_ip_sort_key)
        if "_ke-link._tcp" in str(service.get("type") or ""):
            ipv4 = [
                value for value in unique
                if (_ip_address(value) or ipaddress.ip_address("::")).version == 4
            ]
            return ipv4[0] if len(ipv4) == 1 else None
        return unique[0] if len(unique) == 1 else None

    def _public_service(self, item, service):
        result = dict(service)
        result.pop("endpoints", None)
        result.pop("instanceKey", None)
        if result.get("url") and result.get("scheme") in {"http", "https", "ssh", "vnc", "smb"}:
            try:
                host = urlparse(str(result["url"])).hostname
            except ValueError:
                host = None
            binding = _route_binding(host, self.interfaces) if host else None
            if not binding or (
                result.get("interface")
                and binding.get("interface") != _clean_interface(result.get("interface"))
            ):
                result["url"] = None
                result["actionUnavailable"] = "ambiguous-route"
        return result

    @staticmethod
    def _device_type(item, gateway=None):
        addresses = [row["address"] for row in NetworkFabricService._address_records(item)]
        if gateway and gateway in addresses:
            return "gateway"
        services = " ".join(service.get("type", "").lower() for service in (item.get("services") or {}).values())
        if "_ipp" in services or "_printer" in services:
            return "printer"
        if "_airplay" in services or "_raop" in services or "_googlecast" in services:
            return "media"
        if "_rfb" in services or "_ssh" in services or "_smb" in services or "_workstation" in services:
            return "computer"
        if "_ke-link" in services:
            return "ke-peer"
        return "device"

    def _public_device(self, item, now, gateway=None):
        direct_age = now - float(item.get("lastDirect") or 0)
        seen_age = now - float(item.get("lastSeen") or 0)
        state = "online" if item.get("lastDirect") and direct_age <= DIRECT_TTL_SECONDS else "recent" if seen_age <= RECENT_TTL_SECONDS else "offline"
        names = sorted(item.get("names") or {}, key=(item.get("names") or {}).get, reverse=True)
        address_details = self._address_records(item)
        addresses = [row["address"] for row in address_details]
        internal_services = sorted((item.get("services") or {}).values(), key=lambda value: (value.get("label") or "", value.get("name") or ""))
        services = [self._public_service(item, service) for service in internal_services]
        sources = sorted(item.get("sources") or {})
        peer_id = item.get("linkPeerId")
        stored_peer = self.link.peers.get(peer_id) if peer_id else None
        paired = bool(
            stored_peer
            and hmac.compare_digest(
                str(stored_peer.get("fingerprint") or ""),
                str(item.get("linkFingerprint") or ""),
            )
        )
        ke_services = [
            service for service in internal_services
            if "_ke-link._tcp" in service.get("type", "")
            and now - float(service.get("lastSeen") or 0) <= SERVICE_TTL_SECONDS
            and self._service_endpoint(item, service)
        ]
        ke_service = ke_services[0] if len(ke_services) == 1 else None
        ke_properties = (ke_service.get("properties") or {}) if ke_service else {}
        ke_service_valid = bool(
            ke_service
            and isinstance(ke_service.get("port"), int)
            and 1 <= ke_service["port"] <= 65535
            and str(ke_properties.get("id") or "") == str(peer_id or "")
            and re.fullmatch(r"[a-f0-9]{64}", str(ke_properties.get("fp") or ""))
            and str(ke_properties.get("proto") or "") == "1"
        )
        ke_host = self._service_endpoint(item, ke_service)
        session = self.link.session_status(
            peer_id,
            host=ke_host,
            port=ke_service.get("port") if ke_service else None,
            fingerprint=ke_properties.get("fp") if ke_service else None,
            interface=ke_service.get("interface") if ke_service else None,
        ) if paired else {"state": "not-ready", "ready": False, "ttlSeconds": AUTH_SESSION_TTL_SECONDS}
        ke_route = _route_binding(
            ke_host,
            self.interfaces,
            ke_service.get("interface") if ke_service else None,
            allow_loopback=self.link.allow_loopback,
        ) if ke_host else None
        remote_ready = bool(ke_service_valid and ke_route and session.get("ready"))
        capabilities = []
        route_bindings = self._device_route_bindings(item, ipv4_only=True)
        if len(route_bindings) == 1:
            capabilities.append("ping")
        if _unicast_mac(item.get("mac")) and len(route_bindings) == 1:
            capabilities.append("wake")
        if any(service.get("url") and service.get("scheme") in {"http", "https", "ssh", "vnc", "smb"} for service in services):
            capabilities.append("open-service")
        if ke_service and ke_route:
            if not paired:
                capabilities.append("pair")
            elif remote_ready:
                capabilities.append("message")
            else:
                capabilities.append("verify-link")
        if paired:
            capabilities.append("revoke-peer")
        name = (
            _safe_display_label(names[0], "Observed device", 160)
            if names
            else "Network gateway"
            if gateway and gateway in addresses
            else addresses[0]
            if addresses
            else "Observed device"
        )
        confidence = "direct" if state == "online" else "recent-neighbor" if state == "recent" else "historical"
        return {
            "id": item["id"],
            "name": name,
            "type": self._device_type(item, gateway),
            "state": state,
            "confidence": confidence,
            "firstSeenAt": _utc_iso(item["firstSeen"]),
            "lastSeenAt": _utc_iso(item["lastSeen"]),
            "ageSeconds": max(0, round(seen_age, 1)),
            "latencyMs": item.get("latencyMs"),
            "addresses": addresses,
            "addressDetails": [
                {"address": row["address"], "interface": row.get("interface")}
                for row in address_details
            ],
            "mac": item.get("mac"),
            "interface": item.get("interface"),
            "interfaces": sorted({row["interface"] for row in address_details if row.get("interface")}),
            "sources": sources,
            "services": services,
            "capabilities": capabilities,
            "linkPeerId": peer_id,
            "paired": paired,
            "trustState": "trusted" if paired else "untrusted",
            "remoteReady": remote_ready,
            "authenticatedSession": session,
        }

    def get_snapshot(self):
        with self.lock:
            now = self.clock()
            self._expire_devices(now)
            route_result = self.command_runner([ROUTE_PATH, "-n", "get", "default"], timeout=0.5)
            gateway = parse_default_route(getattr(route_result, "stdout", "")).get("gateway")
            devices = [self._public_device(item, now, gateway) for item in self.devices.values()]
            rank = {"online": 0, "recent": 1, "offline": 2}
            devices.sort(key=lambda item: (rank[item["state"]], item["name"].lower(), item["id"]))
            counts = {state: sum(1 for item in devices if item["state"] == state) for state in ("online", "recent", "offline")}
            local_addresses = [value for item in self.interfaces for value in item.get("addresses") or []]
            link_status = dict(self.link.status())
            link_generation = max(0, int(link_status.get("generation") or 0))
            link_status["error"] = (
                self._bind_error_generation(link_status.get("error"), link_generation)
                if link_status.get("error")
                else None
            )
            link_status["errors"] = [
                self._bind_error_generation(item, link_generation)
                for item in (link_status.get("errors") or [])
            ]
            discovery_errors = [
                self._bind_error_generation(item, self.worker_generation)
                for item in self.errors
            ]
            eligible_segment_count = len(_network_objects(self.interfaces))
            return {
                "schemaVersion": SCHEMA_VERSION,
                "generatedAt": _utc_iso(now),
                "active": self.active,
                "scan": {
                    "inProgress": self.scanning,
                    "sequence": self.scan_sequence,
                    "lastScanAt": _utc_iso(self.last_scan_at) if self.last_scan_at else None,
                    "lastDeepScanAt": _utc_iso(self.last_deep_scan_at) if self.last_deep_scan_at else None,
                    "deepScanCadenceSeconds": DEEP_SCAN_CADENCE_SECONDS,
                    "maxHostsPerScan": MAX_SCAN_HOSTS,
                },
                "local": {
                    "name": _safe_display_label(socket.gethostname(), "This Mac", 160),
                    "addresses": local_addresses,
                    "interfaces": self.interfaces,
                    "excludedInterfaces": list(self.excluded_interfaces),
                },
                "counts": {
                    **counts,
                    "observed": len(devices),
                    "paired": int(link_status.get("pairedPeerCount") or 0),
                    "pairedObserved": sum(1 for item in devices if item["paired"]),
                },
                "devices": devices,
                "link": link_status,
                "coverage": {
                    "mode": "directly-connected-segments",
                    "limited": self.coverage_limited,
                    "sources": ["ARP", "NDP", "ICMP", "Bonjour / DNS-SD", "SSDP", "active connections when permitted"],
                    "eligibleSegmentCount": eligible_segment_count,
                    "excludedInterfaceCount": len(self.excluded_interfaces),
                    "boundary": "Silent, sleeping, firewalled, client-isolated, or different-VLAN devices can remain undiscoverable without router inventory or an installed companion.",
                },
                "errors": sorted(discovery_errors, key=lambda item: str(item.get("observedAt") or ""), reverse=True),
                "privacy": {
                    "cloudInventory": False,
                    "messageBodiesPersisted": False,
                    "commandsAccepted": False,
                    "discoveryActiveOnlyWhileOpen": True,
                    "keLinkPersistsUntilDisabled": True,
                },
            }

    def _device(self, device_id):
        with self.lock:
            item = self.devices.get(str(device_id))
            if not item:
                raise NetworkFabricError("device_not_found", "The selected device is no longer in the live Network snapshot")
            return item

    def _ke_service(self, item):
        now = self.clock()
        services = [
            service
            for service in (item.get("services") or {}).values()
            if (
                "_ke-link._tcp" in service.get("type", "")
                and now - float(service.get("lastSeen") or 0) <= SERVICE_TTL_SECONDS
                and self._service_endpoint(item, service)
            )
        ]
        return services[0] if len(services) == 1 else None

    @staticmethod
    def _ke_service_identity(service):
        if not isinstance(service, dict):
            return None
        properties = service.get("properties") if isinstance(service.get("properties"), dict) else {}
        peer_id = str(properties.get("id") or "")
        fingerprint = str(properties.get("fp") or "")
        try:
            port = int(service.get("port"))
        except (TypeError, ValueError):
            port = 0
        if (
            not re.fullmatch(r"[a-f0-9]{32}", peer_id)
            or not re.fullmatch(r"[a-f0-9]{64}", fingerprint)
            or str(properties.get("proto") or "") != "1"
            or not (1 <= port <= 65535)
        ):
            return None
        return peer_id, fingerprint, port

    def pair_device(self, device_id, code):
        item = self._device(device_id)
        service = self._ke_service(item)
        identity = self._ke_service_identity(service)
        if not service or not identity:
            raise NetworkFabricError("ke_link_unavailable", "This device is not advertising KE Link")
        advertised_peer_id, fingerprint, port = identity
        interface = _clean_interface(service.get("interface"))
        host = self._service_endpoint(item, service)
        if not host or not interface or not _route_binding(
            host,
            self.interfaces,
            interface,
            allow_loopback=self.link.allow_loopback,
        ):
            raise NetworkFabricError("ke_link_invalid", "The KE Link advertisement is incomplete")
        result = self.link.pair(
            host,
            port,
            fingerprint,
            code,
            interface,
            expected_peer_id=advertised_peer_id,
        )
        with self.lock:
            item["linkPeerId"] = result["peerId"]
        return result

    def verify_link_session(self, device_id, expected_link_generation=None):
        item = self._device(device_id)
        peer_id = item.get("linkPeerId")
        service = self._ke_service(item)
        identity = self._ke_service_identity(service)
        if not peer_id or peer_id not in self.link.peers:
            raise NetworkFabricError("peer_not_paired")
        if not service or not identity or identity[0] != peer_id:
            raise NetworkFabricError("ke_link_unavailable")
        _advertised_peer_id, fingerprint, port = identity
        interface = _clean_interface(service.get("interface"))
        host = self._service_endpoint(item, service)
        if not host or not interface or not _route_binding(
            host,
            self.interfaces,
            interface,
            allow_loopback=self.link.allow_loopback,
        ):
            raise NetworkFabricError("ke_link_invalid")
        if expected_link_generation is None:
            return self.link.verify_peer(peer_id, host, port, fingerprint, interface)
        return self.link.verify_peer_if_generation(
            peer_id,
            host,
            port,
            fingerprint,
            interface,
            expected_link_generation,
        )

    def revoke_peer(self, device_id):
        item = self._device(device_id)
        peer_id = item.get("linkPeerId")
        service = self._ke_service(item)
        if not peer_id and service:
            peer_id = (service.get("properties") or {}).get("id")
        if not peer_id:
            raise NetworkFabricError("peer_not_paired")
        return self.link.revoke_peer(peer_id)

    def revoke_trusted_peer(self, peer_id):
        peer_id = str(peer_id or "")
        if not re.fullmatch(r"[a-f0-9]{32}", peer_id):
            raise NetworkFabricError("peer_not_paired")
        return self.link.revoke_peer(peer_id)

    def send_message(self, device_id, message, client_message_id):
        item = self._device(device_id)
        peer_id = item.get("linkPeerId")
        service = self._ke_service(item)
        identity = self._ke_service_identity(service)
        if not peer_id and service:
            peer_id = (service.get("properties") or {}).get("id")
        if not peer_id or peer_id not in self.link.peers:
            raise NetworkFabricError("peer_not_paired")
        interface = _clean_interface(service.get("interface")) if service else None
        host = self._service_endpoint(item, service)
        if not service or not interface or not _route_binding(
            host,
            self.interfaces,
            interface,
            allow_loopback=self.link.allow_loopback,
        ) or not identity or identity[0] != peer_id or not self.link.session_status(
            peer_id,
            host=host,
            port=identity[2],
            fingerprint=identity[1],
            interface=interface,
        ).get("ready"):
            raise NetworkFabricError("peer_session_required")
        return self.link.send(peer_id, message, client_message_id)

    def perform_action(self, device_id, action, service_id=None):
        item = self._device(device_id)
        action = str(action or "")
        address_records = self._address_records(item)
        addresses = [row["address"] for row in address_records]
        if action == "ping":
            bindings = self._device_route_bindings(item, ipv4_only=True)
            if len(bindings) != 1:
                raise NetworkFabricError("ping_unavailable", "No local IPv4 address is available for this device")
            binding = bindings[0]
            ip = binding["address"]
            latency = self.ping_probe(ip, binding["interface"], binding["sourceAddress"])
            if latency is None:
                return {"ok": False, "state": "unreachable", "address": ip, "interface": binding["interface"]}
            return {"ok": True, "state": "reachable", "address": ip, "interface": binding["interface"], "latencyMs": latency}
        if action == "wake":
            mac = _unicast_mac(item.get("mac"))
            bindings = self._device_route_bindings(item, ipv4_only=True)
            if not mac or len(bindings) != 1:
                raise NetworkFabricError("wake_unavailable", "Wake-on-LAN requires a known unicast MAC address")
            binding = bindings[0]
            self.wol_sender(
                mac,
                binding["interface"],
                binding["sourceAddress"],
                binding["broadcastAddress"],
            )
            return {"ok": True, "state": "sent", "mac": mac, "interface": binding["interface"]}
        if action == "open-service":
            service = (item.get("services") or {}).get(str(service_id))
            if not service:
                raise NetworkFabricError("service_not_found", "The advertised service is no longer available")
            parsed = urlparse(str(service.get("url") or ""))
            if parsed.scheme not in {"http", "https", "ssh", "vnc", "smb"}:
                raise NetworkFabricError("service_scheme_denied", "This advertised service cannot be opened safely")
            service_interface = _clean_interface(service.get("interface"))
            host = _clean_endpoint_host(parsed.hostname, interface=service_interface) or _clean_hostname(parsed.hostname)
            permitted = {
                row["address"]
                for row in address_records
                if not service_interface or row.get("interface") == service_interface
            }
            permitted.update(_clean_hostname(value) for value in item.get("names") or {})
            binding = _route_binding(host, self.interfaces)
            if (
                host not in permitted
                or not binding
                or not service_interface
                or binding.get("interface") != service_interface
            ):
                raise NetworkFabricError("service_host_mismatch", "The service host does not match the selected device")
            self.opener(service["url"], binding["interface"], binding["sourceAddress"])
            return {"ok": True, "state": "opened", "serviceId": service_id, "interface": binding["interface"]}
        raise NetworkFabricError("action_not_supported", "This device action is not supported")

    @staticmethod
    def _open_url(url, _interface=None, _source_address=None):
        subprocess.Popen([OPEN_PATH, str(url)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    @staticmethod
    def _open_system_settings(url):
        target = str(url or "")
        if target not in {LOCAL_NETWORK_SETTINGS_URL, NETWORK_SETTINGS_URL} or sys.platform != "darwin":
            raise NetworkFabricError("system_settings_unavailable")
        subprocess.Popen(
            [OPEN_PATH, target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    @staticmethod
    def _send_wol(mac, interface, source_address, broadcast_address):
        if not _clean_interface(interface):
            raise NetworkFabricError("endpoint_invalid")
        source = _ip_address(_clean_ip(source_address, interface))
        broadcast = _ip_address(_clean_ip(broadcast_address, interface))
        if source is None or broadcast is None or source.version != 4 or broadcast.version != 4:
            raise NetworkFabricError("endpoint_invalid")
        payload = bytes.fromhex("FF" * 6 + mac.replace(":", "") * 16)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            _bind_socket_interface(sock, interface, socket.AF_INET)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(1)
            sock.bind((str(source), 0))
            sock.sendto(payload, (str(broadcast), 9))
        finally:
            sock.close()
