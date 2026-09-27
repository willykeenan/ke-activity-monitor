import ast
import base64
import collections
import ctypes
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import network_fabric


class FakeClock:
    def __init__(self, value=1_800_000_000.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += float(seconds)


class FakeRunner:
    def __init__(self, arp="", ndp="", route=""):
        self.arp = arp
        self.ndp = ndp
        self.route = route
        self.calls = []

    def __call__(self, args, timeout=1.0):
        self.calls.append((tuple(args), timeout))
        if args[0] == network_fabric.ARP_PATH:
            output = self.arp
        elif args[0] == network_fabric.NDP_PATH:
            output = self.ndp
        elif args[0] == network_fabric.ROUTE_PATH:
            output = self.route
        else:
            output = ""
        return subprocess.CompletedProcess(args, 0, output, "")


def fixture_interfaces():
    return [{
        "name": "en1",
        "mac": "12:f5:6f:a8:59:db",
        "addresses": ["192.168.1.10", "fe80::10%en1"],
        "networks": ["192.168.1.0/24", "fe80::/64"],
        "scanEligible": True,
        "scope": "local",
    }]


class NetworkParserTests(unittest.TestCase):
    def test_process_connection_access_denial_is_not_local_network_permission_denial(self):
        failures = (
            network_fabric.psutil.AccessDenied(pid=81642),
            PermissionError("process socket inventory denied"),
            OSError(network_fabric.errno.EPERM, "operation not permitted"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(network_fabric.psutil, "net_connections", side_effect=failure):
                    with self.assertRaises(network_fabric.NetworkFabricError) as caught:
                        network_fabric.NetworkFabricService._connections()
                self.assertEqual(caught.exception.code, "connections_unavailable")
                self.assertNotEqual(caught.exception.code, "permission_denied")

    def test_arp_parser_excludes_incomplete_and_multicast_addresses(self):
        text = """? (192.168.1.1) at 2e:67:be:fa:a4:57 on en1 ifscope [ethernet]
? (192.168.1.22) at (incomplete) on en1 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en1 ifscope permanent [ethernet]
"""
        self.assertEqual(network_fabric.parse_arp(text), [{
            "ip": "192.168.1.1",
            "mac": "2e:67:be:fa:a4:57",
            "interface": "en1",
        }])

    def test_ndp_parser_keeps_ipv6_and_normalizes_mac(self):
        text = """Neighbor Linklayer Address Netif Expire St Flgs Prbs
fe80::2%en1 2E:67:BE:FA:A4:57 en1 20s R R
fe80::3%en1 (incomplete) en1 expired N
"""
        self.assertEqual(network_fabric.parse_ndp(text), [{
            "ip": "fe80::2%en1",
            "mac": "2e:67:be:fa:a4:57",
            "interface": "en1",
        }])

    def test_native_dns_sd_rows_preserve_exact_identity_and_safe_properties(self):
        rows = [
            network_fabric._dns_sd_native_browse_row(
                network_fabric.DNS_SERVICE_FLAGS_ADD,
                17,
                b"Living Room Mac",
                b"_ke-link._tcp.",
                b"local.",
            ),
            network_fabric._dns_sd_native_browse_row(
                0, 17, b"Old Mac", b"_rfb._tcp.", b"local.",
            ),
        ]
        self.assertEqual(rows[0]["event"], "add")
        self.assertEqual(rows[0]["name"], "Living Room Mac")
        self.assertEqual(
            rows[0]["instanceKey"],
            network_fabric._bonjour_instance_key("Living Room Mac"),
        )
        txt_items = [
            b"id=0123456789abcdef0123456789abcdef",
            b"fp=" + (b"a" * 64),
            b"proto=1",
            b"secret=never",
        ]
        txt_data = b"".join(bytes([len(item)]) + item for item in txt_items)
        result = network_fabric._dns_sd_native_resolve_row(
            17, b"living-room.local.", socket.htons(4455), txt_data,
        )
        self.assertEqual(result["host"], "living-room.local")
        self.assertEqual(result["port"], 4455)
        self.assertNotIn("secret", result["properties"])
        self.assertEqual(result["properties"]["proto"], "1")

    def test_native_dns_sd_browse_preserves_edge_space_and_control_bytes(self):
        names = ["Peer", " Peer ", "Peer ", " Pëer\u2028 ", "Peer\r", "Peer\nInjected"]
        rows = [
            network_fabric._dns_sd_native_browse_row(
                network_fabric.DNS_SERVICE_FLAGS_ADD,
                7,
                name.encode("utf-8"),
                b"_ke-link._tcp.",
                b"local.",
            )
            for name in names
        ]
        self.assertEqual([row["name"] for row in rows], names)
        self.assertEqual(len({row["instanceKey"] for row in rows}), len(names))
        self.assertEqual(
            [row["instanceKey"] for row in rows],
            [network_fabric._bonjour_instance_key(name) for name in names],
        )
        removed = network_fabric._dns_sd_native_browse_row(
            0, 7, b"Peer\r", b"_ke-link._tcp.", b"local.",
        )
        self.assertEqual(removed["event"], "remove")
        self.assertEqual(removed["name"], "Peer\r")
        self.assertEqual(removed["instanceKey"], rows[4]["instanceKey"])
        self.assertIsNotNone(network_fabric._bonjour_instance_key(("é" * 31) + "x"))
        self.assertIsNone(network_fabric._bonjour_instance_key("é" * 32))
        self.assertIsNone(network_fabric._bonjour_instance_key(b"\xff"))
        self.assertIsNone(network_fabric._bonjour_instance_key(b"x" * 64))
        injected = (
            "12:00:00 Add 2 7 local. _ke-link._tcp. A\n"
            "0 Rmv 0 7 local. _ke-link._tcp. Victim\n"
        )
        self.assertLessEqual(len("A\n0 Rmv 0 7 local. _ke-link._tcp. Victim".encode("utf-8")), 63)
        for cli_text in (
            "12:00:00 Add 2 7 local. _ke-link._tcp. Peer\r\n",
            "12:00:00 Add 2 7 local. _ke-link._tcp. Peer\nInjected\n",
            injected,
        ):
            self.assertEqual(network_fabric.parse_dns_sd_browse(cli_text), [])

    def test_native_dns_sd_callback_keeps_control_bytes_and_deallocates(self):
        calls = []

        class FakeLibrary:
            @staticmethod
            def DNSServiceBrowse(reference, _flags, interface_index, regtype,
                                 domain, callback, _context):
                reference._obj.value = 123
                calls.append(("browse", interface_index, regtype, domain))
                callback(
                    reference._obj,
                    network_fabric.DNS_SERVICE_FLAGS_ADD,
                    interface_index,
                    network_fabric.DNS_SERVICE_ERR_NO_ERROR,
                    b"Peer\r\nInjected",
                    b"_ke-link._tcp.",
                    b"local.",
                    None,
                )
                return network_fabric.DNS_SERVICE_ERR_NO_ERROR

            @staticmethod
            def DNSServiceRefSockFD(_reference):
                return 9

            @staticmethod
            def DNSServiceProcessResult(_reference):
                calls.append(("process",))
                return network_fabric.DNS_SERVICE_ERR_NO_ERROR

            @staticmethod
            def DNSServiceRefDeallocate(reference):
                calls.append(("deallocate", reference.value))

        with mock.patch.object(network_fabric, "_dns_sd_native_library", return_value=FakeLibrary()):
            with mock.patch.object(network_fabric.select, "select", return_value=([9], [], [])):
                with mock.patch.object(network_fabric.time, "monotonic", side_effect=[0.0, 0.0, 0.0, 0.1]):
                    rows = network_fabric._native_dns_sd_browse(
                        "_ke-link._tcp", 7, 0.05,
                    )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "Peer\r\nInjected")
        self.assertEqual(
            rows[0]["instanceKey"],
            network_fabric._bonjour_instance_key(b"Peer\r\nInjected"),
        )
        self.assertIn(("deallocate", 123), calls)

    def test_native_dns_sd_permission_denials_are_explicit_on_immediate_return(self):
        for error_code in (
            network_fabric.DNS_SERVICE_ERR_POLICY_DENIED,
            network_fabric.DNS_SERVICE_ERR_NOT_PERMITTED,
        ):
            with self.subTest(error_code=error_code):
                class DeniedLibrary:
                    @staticmethod
                    def DNSServiceBrowse(*_args):
                        return error_code

                    @staticmethod
                    def DNSServiceRefDeallocate(_reference):
                        raise AssertionError("an absent reference must not be deallocated")

                with mock.patch.object(
                    network_fabric,
                    "_dns_sd_native_library",
                    return_value=DeniedLibrary(),
                ):
                    with self.assertRaises(network_fabric.NetworkFabricError) as caught:
                        network_fabric._native_dns_sd_browse("_ke-link._tcp", 7, 0.05)
                self.assertEqual(caught.exception.code, "permission_denied")
                self.assertEqual(
                    caught.exception.public_message,
                    "Local Network access is unavailable. Check macOS privacy settings and try again.",
                )

    def test_native_dns_sd_permission_denials_are_explicit_from_callback(self):
        for error_code in (
            network_fabric.DNS_SERVICE_ERR_POLICY_DENIED,
            network_fabric.DNS_SERVICE_ERR_NOT_PERMITTED,
        ):
            with self.subTest(error_code=error_code):
                calls = []

                class DeniedLibrary:
                    @staticmethod
                    def DNSServiceBrowse(reference, _flags, interface_index, _regtype,
                                         _domain, callback, _context):
                        reference._obj.value = 321
                        callback(
                            reference._obj,
                            0,
                            interface_index,
                            error_code,
                            b"Denied",
                            b"_ke-link._tcp.",
                            b"local.",
                            None,
                        )
                        return network_fabric.DNS_SERVICE_ERR_NO_ERROR

                    @staticmethod
                    def DNSServiceRefSockFD(_reference):
                        return 9

                    @staticmethod
                    def DNSServiceProcessResult(_reference):
                        return network_fabric.DNS_SERVICE_ERR_NO_ERROR

                    @staticmethod
                    def DNSServiceRefDeallocate(reference):
                        calls.append(("deallocate", reference.value))

                with mock.patch.object(
                    network_fabric,
                    "_dns_sd_native_library",
                    return_value=DeniedLibrary(),
                ):
                    with mock.patch.object(
                        network_fabric.select,
                        "select",
                        return_value=([9], [], []),
                    ):
                        with mock.patch.object(network_fabric.time, "monotonic", return_value=0.0):
                            with self.assertRaises(network_fabric.NetworkFabricError) as caught:
                                network_fabric._native_dns_sd_browse("_ke-link._tcp", 7, 0.05)
                self.assertEqual(caught.exception.code, "permission_denied")
                self.assertEqual(calls, [("deallocate", 321)])

    def test_native_dns_sd_non_permission_error_stays_unavailable(self):
        class FailedLibrary:
            @staticmethod
            def DNSServiceBrowse(*_args):
                return -65537

            @staticmethod
            def DNSServiceRefDeallocate(_reference):
                raise AssertionError("an absent reference must not be deallocated")

        with mock.patch.object(
            network_fabric,
            "_dns_sd_native_library",
            return_value=FailedLibrary(),
        ):
            with self.assertRaises(network_fabric.NetworkFabricError) as caught:
                network_fabric._native_dns_sd_browse("_ke-link._tcp", 7, 0.05)
        self.assertEqual(caught.exception.code, "discovery_unavailable")
        self.assertEqual(
            caught.exception.public_message,
            "Local network discovery is temporarily unavailable.",
        )

    def test_native_dns_sd_resolve_passes_exact_control_name_and_binary_txt(self):
        peer_id = "a" * 32
        fingerprint = "b" * 64
        txt_items = [f"id={peer_id}".encode(), f"fp={fingerprint}".encode(), b"proto=1"]
        txt_data = b"".join(bytes([len(item)]) + item for item in txt_items)
        calls = []

        class FakeLibrary:
            @staticmethod
            def DNSServiceResolve(reference, _flags, interface_index, service_name,
                                  regtype, domain, callback, _context):
                reference._obj.value = 456
                calls.append(("resolve", service_name, regtype, domain))
                txt_buffer = (ctypes.c_ubyte * len(txt_data)).from_buffer_copy(txt_data)
                callback(
                    reference._obj,
                    0,
                    interface_index,
                    network_fabric.DNS_SERVICE_ERR_NO_ERROR,
                    b"ignored-full-name",
                    b"peer.local.",
                    socket.htons(4555),
                    len(txt_data),
                    txt_buffer,
                    None,
                )
                return network_fabric.DNS_SERVICE_ERR_NO_ERROR

            @staticmethod
            def DNSServiceRefSockFD(_reference):
                return 10

            @staticmethod
            def DNSServiceProcessResult(_reference):
                raise AssertionError("synchronous fake resolve already completed")

            @staticmethod
            def DNSServiceRefDeallocate(reference):
                calls.append(("deallocate", reference.value))

        with mock.patch.object(network_fabric, "_dns_sd_native_library", return_value=FakeLibrary()):
            with mock.patch.object(network_fabric.time, "monotonic", return_value=0.0):
                resolved = network_fabric._native_dns_sd_resolve(
                    "Peer\r\nInjected", "_ke-link._tcp", 7, 0.05,
                )
        self.assertEqual(calls[0][1], b"Peer\r\nInjected")
        self.assertEqual(resolved, {
            "host": "peer.local",
            "port": 4555,
            "interfaceIndex": 7,
            "properties": {"id": peer_id, "fp": fingerprint, "proto": "1"},
        })
        self.assertIn(("deallocate", 456), calls)

    def test_dns_sd_address_rows_keep_only_the_final_active_event(self):
        withdrawn = """12:00:00.000 Add 2 7 peer.local. 192.168.1.44 120
12:00:00.100 Rmv 2 7 peer.local. 192.168.1.44 0
"""
        restored = withdrawn + "12:00:00.200 Add 2 7 peer.local. 192.168.1.44 120\n"
        self.assertEqual(network_fabric.parse_dns_sd_address_rows(withdrawn, "en0"), [])
        self.assertEqual(network_fabric.parse_dns_sd_address_rows(
            "12:00:00.000 Rmv 2 7 peer.local. 192.168.1.44 0\n", "en0"
        ), [])
        self.assertEqual(network_fabric.parse_dns_sd_address_events(withdrawn, "en0"), [{
            "event": "remove",
            "interfaceIndex": 7,
            "address": "192.168.1.44",
        }])
        self.assertEqual(network_fabric.parse_dns_sd_address_rows(restored, "en0"), [{
            "interfaceIndex": 7,
            "address": "192.168.1.44",
        }])

    def test_ipv6_netmask_preserves_direct_segment_prefix(self):
        self.assertEqual(
            network_fabric._interface_prefix(socket.AF_INET6, "ffff:ffff:ffff:ffff::"),
            64,
        )
        self.assertIsNone(network_fabric._interface_prefix(socket.AF_INET6, "ffff:0:ffff::"))

    def test_ssdp_parser_retains_only_bounded_discovery_headers(self):
        packet = (
            "HTTP/1.1 200 OK\r\n"
            "LOCATION: http://192.168.1.4:8000/device.xml\r\n"
            "ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
            "USN: uuid:test::upnp:rootdevice\r\n"
            "X-SECRET: do-not-return\r\n\r\n"
        )
        parsed = network_fabric.parse_ssdp_response(packet, "192.168.1.4")
        self.assertEqual(parsed["ip"], "192.168.1.4")
        self.assertNotIn("x-secret", parsed)
        self.assertIn("MediaRenderer", parsed["st"])

    def test_malformed_ssdp_locations_are_per_row_fail_soft(self):
        for location in (
            "http://192.168.1.4:99999/device.xml",
            "http://bad host/device.xml",
            "file:///Users/alex/private",
            "http://[::1",
        ):
            service = network_fabric.NetworkFabricService._ssdp_service({
                "ip": "192.168.1.4",
                "location": location,
                "st": "fixture",
                "usn": "fixture",
            })
            self.assertIsNone(service["url"])
            self.assertNotIn("/Users/", json.dumps(service))
        credentialed = network_fabric.NetworkFabricService._ssdp_service({
            "ip": "192.168.1.4",
            "location": "http://user:secret@192.168.1.4:8000/device.xml",
            "st": "fixture",
            "usn": "fixture",
        })
        self.assertIsNone(credentialed["url"])

    def test_runtime_bonjour_scope_is_the_exact_declared_closed_allowlist(self):
        self.assertEqual(network_fabric.BONJOUR_SERVICE_ALLOWLIST, (
            "_ke-link._tcp", "_http._tcp", "_https._tcp", "_ssh._tcp", "_rfb._tcp",
            "_smb._tcp", "_ipp._tcp", "_printer._tcp", "_airplay._tcp", "_raop._tcp",
            "_googlecast._tcp",
        ))
        source = __import__("inspect").getsource(network_fabric._default_mdns)
        self.assertIn("types = BONJOUR_SERVICE_ALLOWLIST", source)
        self.assertIn("_native_dns_sd_browse", source)
        self.assertIn("_native_dns_sd_resolve", source)
        self.assertNotIn('"-B"', source)
        self.assertNotIn('"-L"', source)
        self.assertNotIn("parse_dns_sd_browse", source)
        self.assertNotIn("parse_dns_sd_resolve", source)
        self.assertNotIn("_services._dns-sd._udp", source)

    def test_scan_targets_are_capped_to_local_24_and_exclude_self(self):
        interfaces = fixture_interfaces()
        interfaces[0]["networks"] = ["192.168.0.0/16"]
        targets, limited = network_fabric._scan_targets(interfaces)
        self.assertTrue(limited)
        self.assertEqual(len(targets), 253)
        self.assertNotIn("192.168.1.10", {row[0] for row in targets})
        self.assertEqual({row[2] for row in targets}, {"192.168.1.0/24"})


class NetworkFabricLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.runner = FakeRunner(
            arp="? (192.168.1.20) at aa:bb:cc:dd:ee:02 on en1 ifscope [ethernet]\n",
            route="gateway: 192.168.1.1\ninterface: en1\n",
        )
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def _service(self, **overrides):
        mdns = {
            "type": "_ssh._tcp.local.",
            "name": "Studio Mac",
            "host": "studio-mac.local",
            "port": 22,
            "properties": {},
            "addresses": ["192.168.1.20"],
        }
        mdns.update(overrides)
        link = network_fabric.KELinkManager(os.path.realpath(self.temp.name), clock=self.clock, advertise=False)
        return network_fabric.NetworkFabricService(
            data_root=self.temp.name,
            clock=self.clock,
            interface_provider=fixture_interfaces,
            command_runner=self.runner,
            ping_probe=lambda ip, _interface, _source: 3.25 if ip == "192.168.1.20" else None,
            mdns_probe=lambda _stop: [mdns],
            ssdp_probe=lambda _stop: [{
                "ip": "192.168.1.20",
                "location": "http://192.168.1.20:8000/device.xml",
                "st": "urn:schemas-upnp-org:device:MediaRenderer:1",
                "usn": "uuid:fixture",
            }],
            connection_provider=lambda: [{"ip": "192.168.1.20"}],
            link_manager=link,
        )

    def test_multisource_discovery_deduplicates_and_exposes_truthful_sources(self):
        service = self._service()
        service.active = True
        service._scan_once(deep=True)
        snapshot = service.get_snapshot()
        device = next(item for item in snapshot["devices"] if item["name"] == "studio-mac.local")
        self.assertEqual(device["state"], "online")
        self.assertEqual(device["type"], "computer")
        self.assertEqual(device["addresses"], ["192.168.1.20"])
        self.assertEqual(device["mac"], "aa:bb:cc:dd:ee:02")
        self.assertEqual(device["latencyMs"], 3.25)
        self.assertTrue({"arp", "bonjour", "connection", "icmp", "ssdp"}.issubset(device["sources"]))
        self.assertIn("open-service", device["capabilities"])
        self.assertEqual(snapshot["counts"]["online"], 1)
        self.assertFalse(snapshot["privacy"]["cloudInventory"])
        self.assertFalse(snapshot["privacy"]["messageBodiesPersisted"])
        self.assertTrue(snapshot["privacy"]["discoveryActiveOnlyWhileOpen"])
        self.assertTrue(snapshot["privacy"]["keLinkPersistsUntilDisabled"])

    def test_connection_inventory_denial_degrades_only_that_optional_source(self):
        service = self._service()
        service.connection_provider = mock.Mock(
            side_effect=network_fabric.psutil.AccessDenied(pid=81642)
        )
        service.active = True
        service._scan_once(deep=True)
        snapshot = service.get_snapshot()
        device = next(item for item in snapshot["devices"] if item["name"] == "studio-mac.local")
        self.assertEqual(device["state"], "online")
        self.assertTrue({"arp", "bonjour", "icmp", "ssdp"}.issubset(device["sources"]))
        self.assertNotIn("connection", device["sources"])
        self.assertEqual(snapshot["counts"]["online"], 1)
        self.assertFalse(snapshot["scan"]["inProgress"])
        self.assertIsNotNone(snapshot["scan"]["lastScanAt"])
        self.assertEqual(
            [(row["source"], row["code"]) for row in snapshot["errors"]],
            [("connections", "connections_unavailable")],
        )
        self.assertNotIn("permission_denied", {row["code"] for row in snapshot["errors"]})

    def test_self_addresses_macs_and_hostname_never_become_devices(self):
        service = self._service(
            name="Self",
            host="%s.local" % __import__("socket").gethostname(),
            addresses=["192.168.1.10"],
        )
        service.active = True
        self.runner.arp = "? (192.168.1.10) at 12:f5:6f:a8:59:db on en1 ifscope [ethernet]\n"
        service.connection_provider = lambda: []
        service.ssdp_probe = lambda _stop: []
        service._scan_once(deep=False)
        devices = service.get_snapshot()["devices"]
        self.assertEqual([item["name"] for item in devices], ["Network gateway"])
        self.assertNotIn("192.168.1.10", {address for item in devices for address in item["addresses"]})

    def test_online_recent_offline_and_expired_are_distinct(self):
        service = self._service()
        service.active = True
        service._scan_once(deep=False)
        device_id = service.get_snapshot()["devices"][0]["id"]
        self.clock.advance(network_fabric.DIRECT_TTL_SECONDS + 1)
        self.assertEqual(service._public_device(service.devices[device_id], self.clock())["state"], "recent")
        self.clock.advance(network_fabric.RECENT_TTL_SECONDS)
        self.assertEqual(service._public_device(service.devices[device_id], self.clock())["state"], "offline")
        self.clock.advance(network_fabric.DEVICE_RETENTION_SECONDS)
        service._expire_devices(self.clock())
        self.assertNotIn(device_id, service.devices)

    def test_deep_scan_requires_active_tab_and_is_rate_limited(self):
        service = self._service()
        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "Open the Network tab"):
            service.request_deep_scan()
        service.active = True
        service.last_deep_scan_at = self.clock()
        response = service.request_deep_scan()
        self.assertTrue(response["rateLimited"])
        self.assertFalse(response["queued"])

    def test_probe_failures_degrade_without_hiding_snapshot_contract(self):
        def explode(_stop):
            raise PermissionError("Local Network denied")

        service = self._service()
        service.mdns_probe = explode
        service.ssdp_probe = explode
        service.active = True
        service._scan_once(deep=False)
        snapshot = service.get_snapshot()
        self.assertEqual(snapshot["schemaVersion"], network_fabric.SCHEMA_VERSION)
        self.assertGreaterEqual(len(snapshot["errors"]), 2)
        self.assertIn("client-isolated", snapshot["coverage"]["boundary"])

    def test_malformed_ssdp_rows_cannot_abort_the_scan_or_leak_location_text(self):
        service = self._service()
        service.ssdp_probe = lambda _stop: [
            None,
            "not-an-object",
            {
                "ip": "192.168.1.20",
                "location": "http://192.168.1.20:99999/Users/alex/private",
                "st": "fixture",
                "usn": "fixture",
            },
        ]
        service.active = True
        service._scan_once(deep=False)
        snapshot = service.get_snapshot()
        self.assertFalse(snapshot["scan"]["inProgress"])
        self.assertTrue(snapshot["devices"])
        self.assertNotIn("/Users/", json.dumps(snapshot))

    def test_start_stop_has_one_bounded_discovery_thread(self):
        service = self._service()
        service.mdns_probe = lambda _stop: []
        service.ssdp_probe = lambda _stop: []
        service.connection_provider = lambda: []
        service.start_discovery()
        deadline = time.time() + 2
        while not service.scanning and time.time() < deadline:
            time.sleep(0.01)
        thread = service.thread
        service.stop_discovery()
        self.assertIsNotNone(thread)
        self.assertFalse(thread.is_alive())
        self.assertFalse(service.get_snapshot()["active"])

    def test_advertised_service_open_and_wake_are_exactly_scoped(self):
        opened = []
        woken = []
        service = self._service()
        service.opener = lambda url, interface, source: opened.append((url, interface, source))
        service.wol_sender = lambda mac, interface, source, broadcast: woken.append((mac, interface, source, broadcast))
        service.active = True
        service._scan_once(deep=False)
        device = service.get_snapshot()["devices"][0]
        web = next(item for item in device["services"] if item["scheme"] == "http")
        result = service.perform_action(device["id"], "open-service", web["id"])
        self.assertTrue(result["ok"])
        self.assertEqual(opened, [("http://192.168.1.20:8000/device.xml", "en1", "192.168.1.10")])
        service.perform_action(device["id"], "wake")
        self.assertEqual(woken, [("aa:bb:cc:dd:ee:02", "en1", "192.168.1.10", "192.168.1.255")])
        internal = service.devices[device["id"]]
        bad_id = "service-bad"
        internal["services"][bad_id] = {
            "id": bad_id,
            "url": "https://example.com:443",
            "host": "192.168.1.20",
            "scheme": "https",
        }
        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "does not match"):
            service.perform_action(device["id"], "open-service", bad_id)
        malicious_id = "service-external"
        internal["services"][malicious_id] = {
            "id": malicious_id,
            "url": "https://example.com:443",
            "host": "example.com",
            "scheme": "https",
        }
        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "does not match"):
            service.perform_action(device["id"], "open-service", malicious_id)


def _fd_count():
    return len(os.listdir("/dev/fd"))


class NetworkRecoveryTests(unittest.TestCase):
    class FakeLink:
        def __init__(self, enabled=False):
            self.enabled = bool(enabled)
            self.calls = []
            self.listener_generation = 0

        def status(self):
            self.calls.append("status")
            return {"enabled": self.enabled, "generation": self.listener_generation, "errors": [], "pairedPeerCount": 0}

        def enable(self):
            self.calls.append("enable")
            self.enabled = True
            return {"enabled": True, "generation": self.listener_generation, "errors": [], "pairedPeerCount": 0}

        def disable(self):
            self.calls.append("disable")
            self.enabled = False
            return {"enabled": False, "generation": self.listener_generation, "errors": [], "pairedPeerCount": 0}

        def repair_advertiser_if_enabled(self, expected_generation=None):
            self.calls.append(("repair-advertiser", expected_generation))
            if expected_generation != self.listener_generation:
                raise network_fabric.NetworkFabricError("recovery_stale")
            return {"enabled": self.enabled, "generation": self.listener_generation, "errors": [], "pairedPeerCount": 0}

    def _service(self, *, link=None, opened=None):
        return network_fabric.NetworkFabricService(
            clock=FakeClock(),
            interface_provider=lambda: [],
            command_runner=FakeRunner(),
            ping_probe=lambda _ip, _interface, _source: None,
            mdns_probe=lambda _stop: [],
            ssdp_probe=lambda _stop: [],
            connection_provider=lambda: [],
            link_manager=link or self.FakeLink(),
            settings_opener=(lambda url: opened.append(url)) if opened is not None else (lambda _url: None),
        )

    def _recover(self, service, code, source=None, device_id=None, after_settings=False):
        generation = service.error_projection(code, source or "network")["recovery"]["generation"]
        return service.recover_connection(
            code,
            source,
            device_id,
            after_settings,
            generation,
        )

    def test_every_public_and_literal_network_error_has_one_bounded_recovery(self):
        self.assertEqual(set(network_fabric._RECOVERY_KIND_BY_CODE), set(network_fabric._ERROR_COPY))
        contract = network_fabric.network_error_contract()
        self.assertEqual(contract["messages"], network_fabric._ERROR_COPY)
        self.assertEqual(set(contract["recoveries"]), set(network_fabric._ERROR_COPY))
        self.assertEqual(contract["recoveryActions"], sorted(network_fabric._RECOVERY_PLANS))
        self.assertEqual(contract["recoveryKinds"], sorted({item["kind"] for item in network_fabric._RECOVERY_PLANS.values()}))
        for code in network_fabric._ERROR_COPY:
            plan = network_fabric.recovery_plan(code)
            self.assertIn(plan["action"], network_fabric._RECOVERY_PLANS)
            self.assertIn(plan["kind"], contract["recoveryKinds"])
            self.assertTrue(plan["target"])
            self.assertEqual(plan["generation"], 0)
            self.assertTrue(plan["label"])
            self.assertLessEqual(len(plan["label"]), 40)
            projected = network_fabric.public_error(code, "contract", 1.0, recovery_generation=7)
            self.assertEqual(projected["recovery"]["generation"], 7)
            self.assertTrue(projected["observedAt"].endswith("Z"))
        tree = ast.parse(Path(network_fabric.__file__).read_text(encoding="utf-8"))
        literal_codes = {
            node.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "NetworkFabricError"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        }
        self.assertTrue(literal_codes.issubset(network_fabric._ERROR_COPY))

    def test_permission_fix_opens_exact_settings_and_retries_only_after_return(self):
        opened = []
        service = self._service(opened=opened)
        first = self._recover(service, "permission_denied", "bonjour")
        self.assertEqual(opened, [network_fabric.LOCAL_NETWORK_SETTINGS_URL])
        self.assertEqual(first["state"], "waiting-for-user")
        self.assertTrue(first["autoRetryOnReturn"])
        self.assertEqual(first["recovery"]["action"], "open-local-network-settings")
        self.assertFalse(service.active)

        with mock.patch.object(service, "_restart_discovery", return_value={"active": True}) as restart:
            second = self._recover(service, "permission_denied", "bonjour", after_settings=True)
        restart.assert_called_once_with(expected_worker_generation=0, expected_stop_generation=0)
        self.assertEqual(opened, [network_fabric.LOCAL_NETWORK_SETTINGS_URL])
        self.assertEqual(second["state"], "rechecking")

    def test_connection_inventory_retry_is_source_only_low_priority_and_truthful(self):
        service = self._service()
        provider = mock.Mock(return_value=[])
        service.connection_provider = provider
        service.interface_provider = mock.Mock(side_effect=AssertionError("unrelated source reran"))
        service.mdns_probe = mock.Mock(side_effect=AssertionError("unrelated source reran"))
        service.ssdp_probe = mock.Mock(side_effect=AssertionError("unrelated source reran"))
        service.ping_probe = mock.Mock(side_effect=AssertionError("unrelated source reran"))
        service.active = True
        service._set_source_error("connections", "connections_unavailable")

        projection = service.error_projection("connections_unavailable", "connections")
        self.assertEqual(projection["recovery"]["action"], "retry-connections")
        self.assertEqual(projection["recovery"]["target"], "active-connections")
        self.assertLess(projection["recovery"]["priority"], 50)
        result = self._recover(service, "connections_unavailable", "connections")

        provider.assert_called_once_with()
        self.assertEqual(result["state"], "source-rechecked")
        self.assertEqual(result["snapshot"]["errors"], [])
        self.assertTrue(service.active)
        service.interface_provider.assert_not_called()
        service.mdns_probe.assert_not_called()
        service.ssdp_probe.assert_not_called()
        service.ping_probe.assert_not_called()

        service._set_source_error("connections", "connections_unavailable")
        service.connection_provider = mock.Mock(
            side_effect=network_fabric.psutil.AccessDenied(pid=81642)
        )
        with self.assertRaises(network_fabric.NetworkFabricError) as caught:
            self._recover(service, "connections_unavailable", "connections")
        self.assertEqual(caught.exception.code, "connections_unavailable")
        self.assertEqual(service.errors[-1]["code"], "connections_unavailable")

    def test_snapshot_and_error_projection_never_open_settings_without_a_fix_click(self):
        opened = []
        service = self._service(opened=opened)
        projection = service.error_projection("permission_denied", "bonjour")
        self.assertEqual(projection["recovery"]["action"], "open-local-network-settings")
        service.get_snapshot()
        self.assertEqual(opened, [])

    def test_system_settings_opener_is_exact_allowlisted_and_platform_bounded(self):
        with mock.patch.object(network_fabric.sys, "platform", "darwin"):
            with mock.patch.object(network_fabric.subprocess, "Popen") as launch:
                network_fabric.NetworkFabricService._open_system_settings(
                    network_fabric.LOCAL_NETWORK_SETTINGS_URL
                )
        launch.assert_called_once_with(
            [network_fabric.OPEN_PATH, network_fabric.LOCAL_NETWORK_SETTINGS_URL],
            stdout=network_fabric.subprocess.DEVNULL,
            stderr=network_fabric.subprocess.DEVNULL,
            start_new_session=True,
        )
        with mock.patch.object(network_fabric.subprocess, "Popen") as launch:
            with self.assertRaises(network_fabric.NetworkFabricError):
                network_fabric.NetworkFabricService._open_system_settings("file:///private/forbidden")
        launch.assert_not_called()
        with mock.patch.object(network_fabric.sys, "platform", "linux"):
            with self.assertRaises(network_fabric.NetworkFabricError):
                network_fabric.NetworkFabricService._open_system_settings(
                    network_fabric.LOCAL_NETWORK_SETTINGS_URL
                )

    def test_network_scope_fix_opens_network_settings_without_probe(self):
        opened = []
        service = self._service(opened=opened)
        result = self._recover(service, "listener_scope_unavailable", "link")
        self.assertEqual(opened, [network_fabric.NETWORK_SETTINGS_URL])
        self.assertEqual(result["state"], "waiting-for-user")
        self.assertFalse(service.active)

    def test_wifi_diagnostic_permission_fix_opens_settings_then_rechecks(self):
        opened = []
        service = self._service(opened=opened)
        first = self._recover(service, "wifi_diagnostics_permission_denied", "internet-optimizer")
        self.assertEqual(first["state"], "waiting-for-user")
        self.assertEqual(first["recovery"]["action"], "open-wifi-settings")
        self.assertEqual(opened, [network_fabric.NETWORK_SETTINGS_URL])
        with mock.patch.object(service, "_restart_discovery", return_value={"active": True}) as restart:
            second = self._recover(
                service,
                "wifi_diagnostics_permission_denied",
                "internet-optimizer",
                after_settings=True,
            )
        restart.assert_called_once_with(expected_worker_generation=0, expected_stop_generation=0)
        self.assertEqual(second["state"], "rechecking")

    def test_link_repair_never_hidden_enables_a_disabled_listener(self):
        disabled = self.FakeLink(enabled=False)
        service = self._service(link=disabled)
        result = self._recover(service, "bonjour_advertisement_unavailable", "bonjour")
        self.assertEqual(result["state"], "action-required")
        self.assertEqual(result["recovery"]["action"], "enable-ke-link")
        self.assertEqual(disabled.calls, [("repair-advertiser", 0)])

        enabled = self.FakeLink(enabled=True)
        service = self._service(link=enabled)
        result = self._recover(service, "bonjour_advertisement_unavailable", "bonjour")
        self.assertEqual(result["state"], "link-rechecked")
        self.assertEqual(enabled.calls, [("repair-advertiser", 0)])
        self.assertNotIn("disable", enabled.calls)

    def test_fix_never_enables_ke_link_and_routes_to_the_explicit_toggle(self):
        link = self.FakeLink(enabled=False)
        service = self._service(link=link)
        plan = network_fabric.recovery_plan("tls_identity_failed")
        self.assertEqual(plan["kind"], "guided")
        self.assertEqual(plan["action"], "enable-ke-link")
        self.assertEqual(plan["target"], "ke-link-control")
        result = self._recover(service, "tls_identity_failed", "tls")
        self.assertEqual(result["state"], "action-required")
        self.assertEqual(result["errorDetail"]["observedAt"], network_fabric._utc_iso(service.clock()))
        self.assertEqual(link.calls, [])

    def test_peer_reconnect_uses_only_selected_device_and_fresh_verify(self):
        service = self._service()
        with mock.patch.object(service, "verify_link_session", return_value={"ok": True, "state": "ready"}) as verify:
            result = self._recover(service, "peer_unreachable", "message", "device-123")
        verify.assert_called_once_with("device-123", expected_link_generation=0)
        self.assertEqual(result["state"], "peer-ready")

    def test_unknown_error_is_guided_manual_and_settings_failure_stays_safe(self):
        service = self._service()
        with mock.patch.object(service, "_restart_discovery", return_value={"active": True}) as restart:
            result = self._recover(service, "future-connection-error", "future")
        restart.assert_not_called()
        self.assertEqual(result["code"], "network_internal_error")
        self.assertEqual(result["state"], "action-required")
        self.assertEqual(result["recovery"]["action"], "review-link")
        self.assertEqual(result["errorDetail"]["code"], "network_internal_error")
        self.assertEqual(result["errorDetail"]["observedAt"], network_fabric._utc_iso(service.clock()))

        failing = network_fabric.NetworkFabricService(
            clock=FakeClock(),
            interface_provider=lambda: [],
            command_runner=FakeRunner(),
            ping_probe=lambda _ip, _interface, _source: None,
            mdns_probe=lambda _stop: [],
            ssdp_probe=lambda _stop: [],
            connection_provider=lambda: [],
            link_manager=self.FakeLink(),
            settings_opener=lambda _url: (_ for _ in ()).throw(OSError("private path must not escape")),
        )
        with self.assertRaises(network_fabric.NetworkFabricError) as raised:
            self._recover(failing, "permission_denied")
        self.assertEqual(raised.exception.code, "system_settings_unavailable")
        self.assertNotIn("private path", str(raised.exception))

    def test_review_only_recovery_does_not_mutate_link_or_discovery(self):
        link = self.FakeLink(enabled=True)
        service = self._service(link=link)
        with mock.patch.object(service, "_restart_discovery") as restart:
            result = self._recover(service, "peer_fingerprint_mismatch", "trust", "device-123")
        self.assertEqual(result["state"], "action-required")
        self.assertEqual(result["recovery"]["action"], "review-trust")
        self.assertEqual(link.calls, [])
        restart.assert_not_called()

    def test_recovery_generation_is_required_and_two_peers_remain_independent(self):
        opened = []
        service = self._service(opened=opened)
        projection = service.error_projection("permission_denied", "bonjour")
        recovery = projection["recovery"]
        self.assertEqual(recovery["generation"], service.worker_generation)
        self.assertEqual(recovery["target"], "local-network-permission")
        with self.assertRaises(network_fabric.NetworkFabricError) as stale:
            service.recover_connection(
                "permission_denied",
                "bonjour",
                None,
                False,
                recovery["generation"] + 1,
            )
        self.assertEqual(stale.exception.code, "recovery_stale")
        self.assertEqual(opened, [])

        calls = []
        with mock.patch.object(
            service,
            "verify_link_session",
            side_effect=lambda device_id, expected_link_generation=None: calls.append((device_id, expected_link_generation)) or {"ok": True, "state": "ready"},
        ):
            self._recover(service, "peer_unreachable", "peer-a", "device-a")
            self._recover(service, "peer_unreachable", "peer-b", "device-b")
        self.assertEqual(calls, [("device-a", 0), ("device-b", 0)])
        with self.assertRaises(network_fabric.NetworkFabricError) as missing:
            self._recover(service, "peer_unreachable", "peer-a")
        self.assertEqual(missing.exception.code, "device_not_found")

    def test_snapshot_rebinds_discovery_and_link_errors_to_current_generations(self):
        link = self.FakeLink(enabled=True)
        link.listener_generation = 9
        service = self._service(link=link)
        service.worker_generation = 6
        service.errors = [network_fabric.public_error("permission_denied", "bonjour", service.clock())]
        link.status = lambda: {
            "enabled": True,
            "generation": 9,
            "pairedPeerCount": 0,
            "errors": [network_fabric.public_error("peer_unreachable", "message", service.clock())],
            "error": None,
        }
        snapshot = service.get_snapshot()
        self.assertEqual(snapshot["errors"][0]["recovery"]["generation"], 6)
        self.assertEqual(snapshot["errors"][0]["recovery"]["target"], "local-network-permission")
        self.assertEqual(snapshot["link"]["errors"][0]["recovery"]["generation"], 9)
        self.assertEqual(snapshot["link"]["errors"][0]["recovery"]["target"], "selected-peer")

    def test_recovery_is_single_flight_and_tab_stop_serializes_after_restart(self):
        service = self._service()
        entered = threading.Event()
        release = threading.Event()
        outcomes = []

        def blocked_restart(**_expected):
            entered.set()
            release.wait(timeout=1)
            return {"active": True}

        with mock.patch.object(service, "_restart_discovery", side_effect=blocked_restart):
            worker = threading.Thread(
                target=lambda: outcomes.append(self._recover(service, "discovery_unavailable")),
                name="recovery-worker",
            )
            worker.start()
            self.assertTrue(entered.wait(timeout=1))
            with self.assertRaisesRegex(network_fabric.NetworkFabricError, "already running"):
                self._recover(service, "discovery_unavailable")
            release.set()
            worker.join(timeout=1)
        self.assertEqual(outcomes[0]["state"], "rechecking")

        order = []
        restart_entered = threading.Event()
        restart_release = threading.Event()

        def fake_stop_locked():
            order.append(("stop", threading.current_thread().name))
            return {"active": False}

        def fake_start_locked(*_args):
            order.append(("start-enter", threading.current_thread().name))
            restart_entered.set()
            restart_release.wait(timeout=1)
            order.append(("start-exit", threading.current_thread().name))
            return {"active": True}

        with mock.patch.object(service, "_stop_discovery_locked", side_effect=fake_stop_locked):
            with mock.patch.object(service, "_start_discovery_locked", side_effect=fake_start_locked):
                recovery = threading.Thread(target=service._restart_discovery, name="recovery")
                closing = threading.Thread(target=service.stop_discovery, name="tab-close")
                recovery.start()
                self.assertTrue(restart_entered.wait(timeout=1))
                closing.start()
                time.sleep(0.02)
                self.assertNotIn(("stop", "tab-close"), order)
                restart_release.set()
                recovery.join(timeout=1)
                closing.join(timeout=1)
        self.assertEqual(order[-1], ("stop", "tab-close"))

    def test_tab_close_intent_prevents_recovery_from_starting_a_new_worker(self):
        service = self._service()
        stop_entered = threading.Event()
        stop_release = threading.Event()
        outcomes = []
        stop_calls = 0

        def blocked_stop():
            nonlocal stop_calls
            stop_calls += 1
            if stop_calls == 1:
                stop_entered.set()
                stop_release.wait(timeout=1)
            return {"active": False}

        def run_recovery():
            try:
                service._restart_discovery()
            except network_fabric.NetworkFabricError as error:
                outcomes.append(error.code)

        with mock.patch.object(service, "_stop_discovery_locked", side_effect=blocked_stop):
            with mock.patch.object(service, "_start_discovery_locked") as start:
                recovery = threading.Thread(target=run_recovery, name="recovery")
                closing = threading.Thread(target=service.stop_discovery, name="tab-close")
                recovery.start()
                self.assertTrue(stop_entered.wait(timeout=1))
                closing.start()
                deadline = time.time() + 1
                while service.stop_request_generation == 0 and time.time() < deadline:
                    time.sleep(0.005)
                self.assertEqual(service.stop_request_generation, 1)
                stop_release.set()
                recovery.join(timeout=1)
                closing.join(timeout=1)
        self.assertEqual(outcomes, ["recovery_stale"])
        start.assert_not_called()

    def test_completed_tab_close_makes_a_not_yet_started_recovery_stale(self):
        service = self._service()
        service.worker_generation = 4
        service.stop_discovery()
        with mock.patch.object(service, "_start_discovery_locked") as start:
            with self.assertRaises(network_fabric.NetworkFabricError) as raised:
                service._restart_discovery(
                    expected_worker_generation=4,
                    expected_stop_generation=0,
                )
        self.assertEqual(raised.exception.code, "recovery_stale")
        start.assert_not_called()

    def test_link_recovery_helpers_reject_a_superseded_listener_generation(self):
        manager = object.__new__(network_fabric.KELinkManager)
        manager.lock = threading.RLock()
        manager.listener_generation = 6
        manager.sessions = {}
        manager.verify_peer = mock.Mock(return_value={"ok": True, "state": "ready"})
        with self.assertRaises(network_fabric.NetworkFabricError) as raised:
            manager.verify_peer_if_generation("peer", "host", 1, "f" * 64, "en0", 5)
        self.assertEqual(raised.exception.code, "recovery_stale")
        manager.verify_peer.assert_not_called()
        result = manager.verify_peer_if_generation("peer", "host", 1, "f" * 64, "en0", 6)
        self.assertEqual(result["state"], "ready")
        manager.verify_peer.assert_called_once_with("peer", "host", 1, "f" * 64, "en0")

        def superseded(*_args):
            manager.sessions["peer"] = {"ready": True}
            manager.listener_generation += 1
            return {"ok": True, "state": "ready"}

        manager.verify_peer = mock.Mock(side_effect=superseded)
        with self.assertRaises(network_fabric.NetworkFabricError) as changed:
            manager.verify_peer_if_generation("peer", "host", 1, "f" * 64, "en0", 6)
        self.assertEqual(changed.exception.code, "recovery_stale")
        self.assertNotIn("peer", manager.sessions)


class SecureNetworkStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(os.path.realpath(self.temp.name))
        self.root.chmod(0o700)
        self.store = network_fabric._SecureDirectory(self.root, local_checker=lambda _fd: True)
        self.store.write_bytes("peers.json", b'{"safe":true}\n', 4096)

    def test_root_symlink_fifo_oversize_and_nonlocal_filesystem_fail_closed_without_fd_leaks(self):
        baseline = _fd_count()
        target = self.root.parent / f"network-target-{os.getpid()}-{time.time_ns()}"
        link = self.root.parent / f"network-link-{os.getpid()}-{time.time_ns()}"
        target.mkdir(mode=0o700)
        self.addCleanup(lambda: target.rmdir() if target.exists() else None)
        link.symlink_to(target, target_is_directory=True)
        self.addCleanup(lambda: link.unlink() if link.is_symlink() else None)
        with self.assertRaises((OSError, network_fabric.NetworkFabricError)):
            network_fabric._SecureDirectory(link, local_checker=lambda _fd: True).read_bytes("peers.json", 4096)

        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(network_fabric.NetworkFabricError):
            self.store.read_bytes("fifo", 4096)
        with self.assertRaises(network_fabric.NetworkFabricError):
            self.store._validate_file(os.stat("/dev/null"), 4096)

        oversize = self.root / "oversize"
        oversize.write_bytes(b"x" * 65)
        oversize.chmod(0o600)
        with self.assertRaises(network_fabric.NetworkFabricError):
            self.store.read_bytes("oversize", 64)

        insecure = self.root / "insecure"
        insecure.write_bytes(b"{}")
        insecure.chmod(0o644)
        with self.assertRaises(network_fabric.NetworkFabricError):
            self.store.read_bytes("insecure", 4096)

        outside_file = target / "outside.json"
        outside_file.write_text("outside", encoding="utf-8")
        outside_file.chmod(0o600)
        file_link = self.root / "file-link"
        file_link.symlink_to(outside_file)
        with self.assertRaises((OSError, network_fabric.NetworkFabricError)):
            self.store.read_bytes("file-link", 4096)
        file_link.unlink()
        outside_file.unlink()

        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "local filesystem"):
            network_fabric._SecureDirectory(self.root, local_checker=lambda _fd: False).read_bytes("peers.json", 4096)
        self.assertEqual(_fd_count(), baseline)

    def test_parent_and_same_byte_file_swaps_fail_closed_without_outside_reads(self):
        baseline = _fd_count()
        outside = self.root.parent / f"network-outside-{os.getpid()}-{time.time_ns()}"
        parked = self.root.parent / f"network-parked-{os.getpid()}-{time.time_ns()}"
        outside.mkdir(mode=0o700)
        outside_file = outside / "peers.json"
        outside_file.write_text("OUTSIDE-METADATA", encoding="utf-8")
        outside_file.chmod(0o600)
        real_stat = os.stat
        root_stat_count = 0

        def swap_parent(path, *args, **kwargs):
            nonlocal root_stat_count
            if str(path) == str(self.root) and kwargs.get("follow_symlinks") is False:
                root_stat_count += 1
                if root_stat_count == 2:
                    os.rename(self.root, parked)
                    os.symlink(outside, self.root, target_is_directory=True)
            return real_stat(path, *args, **kwargs)

        try:
            with mock.patch.object(network_fabric.os, "stat", side_effect=swap_parent):
                with self.assertRaises(network_fabric.NetworkFabricError):
                    self.store.read_bytes("peers.json", 4096)
        finally:
            if self.root.is_symlink():
                self.root.unlink()
            if parked.exists():
                os.rename(parked, self.root)
            outside_file.unlink(missing_ok=True)
            outside.rmdir()
        self.assertNotIn(b"OUTSIDE", self.store.read_bytes("peers.json", 4096))

        replacement = self.root / "replacement"
        replacement.write_bytes(self.store.read_bytes("peers.json", 4096))
        replacement.chmod(0o600)
        original = self.root / "original"
        real_stat = os.stat
        swapped = False

        def swap_file(path, *args, **kwargs):
            nonlocal swapped
            if path == "peers.json" and kwargs.get("dir_fd") is not None and not swapped:
                swapped = True
                os.replace(self.root / "peers.json", original)
                os.replace(replacement, self.root / "peers.json")
            return real_stat(path, *args, **kwargs)

        try:
            with mock.patch.object(network_fabric.os, "stat", side_effect=swap_file):
                with self.assertRaises(network_fabric.NetworkFabricError):
                    self.store.read_bytes("peers.json", 4096)
        finally:
            if original.exists():
                os.replace(original, self.root / "peers.json")
            replacement.unlink(missing_ok=True)
        self.assertTrue(swapped)
        self.assertEqual(_fd_count(), baseline)

    def test_close_error_still_closes_every_descriptor(self):
        baseline = _fd_count()
        real_close = os.close
        injected = False

        def close_then_fail(descriptor):
            nonlocal injected
            try:
                regular = stat.S_ISREG(os.fstat(descriptor).st_mode)
            except OSError:
                regular = False
            real_close(descriptor)
            if regular and not injected:
                injected = True
                raise OSError("injected close failure")

        with mock.patch.object(network_fabric.os, "close", side_effect=close_then_fail):
            with self.assertRaises(OSError):
                self.store.read_bytes("peers.json", 4096)
        self.assertTrue(injected)
        self.assertEqual(_fd_count(), baseline)

    def test_write_detects_a_same_byte_destination_swap_before_atomic_replace(self):
        baseline = _fd_count()
        replacement = self.root / "replacement"
        parked = self.root / "parked"
        replacement.write_bytes(self.store.read_bytes("peers.json", 4096))
        replacement.chmod(0o600)
        real_stat = os.stat
        checks = 0
        swapped = False

        def swap_destination(path, *args, **kwargs):
            nonlocal checks, swapped
            if path == "peers.json" and kwargs.get("dir_fd") is not None:
                checks += 1
                if checks == 2:
                    os.replace(self.root / "peers.json", parked)
                    os.replace(replacement, self.root / "peers.json")
                    swapped = True
            return real_stat(path, *args, **kwargs)

        try:
            with mock.patch.object(network_fabric.os, "stat", side_effect=swap_destination):
                with self.assertRaises(network_fabric.NetworkFabricError):
                    self.store.write_bytes("peers.json", b'{"updated":true}\n', 4096)
        finally:
            if parked.exists():
                os.replace(parked, self.root / "peers.json")
            replacement.unlink(missing_ok=True)
        self.assertTrue(swapped)
        self.assertEqual(self.store.read_bytes("peers.json", 4096), b'{"safe":true}\n')
        self.assertEqual(_fd_count(), baseline)


class KELinkTruthTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = os.path.realpath(self.temp.name)
        self.peer_id = "a" * 32
        self.fingerprint = "b" * 64
        self.secret = base64.urlsafe_b64encode(b"s" * 32).decode("ascii")
        self.manager = network_fabric.KELinkManager(
            self.root,
            clock=self.clock,
            advertise=False,
            listener_addresses=["127.0.0.1"],
            allowed_networks=["127.0.0.0/8"],
            allow_loopback=True,
        )
        self.manager.peers[self.peer_id] = {
            "id": self.peer_id,
            "name": "Trusted peer",
            "fingerprint": self.fingerprint,
            "secret": self.secret,
            "pairedAt": network_fabric._utc_iso(self.clock()),
        }
        self.manager._save_peers()

    def _item(self, *, observed_age=0.0, service_age=0.0):
        now = self.clock()
        return {
            "id": "device-peer",
            "firstSeen": now - 300,
            "lastSeen": now - observed_age,
            "lastDirect": now - observed_age,
            "addresses": {"127.0.0.1": now - observed_age},
            "names": {"peer.local": now - observed_age},
            "sources": {"bonjour": now - observed_age},
            "services": {
                "service-link": {
                    "id": "service-link",
                    "type": network_fabric.KE_LINK_TYPE,
                    "name": "KE Link",
                    "label": "KE Link",
                    "host": "peer.local",
                    "port": 4555,
                    "interface": "lo0",
                    "observedAddress": "127.0.0.1",
                    "url": None,
                    "scheme": None,
                    "properties": {"id": self.peer_id, "fp": self.fingerprint, "proto": "1"},
                    "lastSeen": now - service_age,
                }
            },
            "mac": None,
            "interface": "lo0",
            "latencyMs": None,
            "linkPeerId": self.peer_id,
            "linkFingerprint": self.fingerprint,
        }

    def _service(self):
        return network_fabric.NetworkFabricService(
            clock=self.clock,
            interface_provider=lambda: [],
            command_runner=FakeRunner(),
            ping_probe=lambda _ip, _interface, _source: None,
            mdns_probe=lambda _stop: [],
            ssdp_probe=lambda _stop: [],
            connection_provider=lambda: [],
            link_manager=self.manager,
        )

    def test_persistent_trust_never_overwrites_liveness_or_grants_send(self):
        service = self._service()
        item = self._item(observed_age=network_fabric.RECENT_TTL_SECONDS + 1, service_age=network_fabric.SERVICE_TTL_SECONDS + 1)
        public = service._public_device(item, self.clock())
        self.assertEqual(public["state"], "offline")
        self.assertTrue(public["paired"])
        self.assertEqual(public["trustState"], "trusted")
        self.assertFalse(public["remoteReady"])
        self.assertNotIn("message", public["capabilities"])

    def test_only_fresh_authenticated_session_is_ready_and_it_expires(self):
        service = self._service()
        item = self._item()
        before = service._public_device(item, self.clock())
        self.assertFalse(before["remoteReady"])
        self.assertIn("verify-link", before["capabilities"])
        self.manager._record_session(self.peer_id, "127.0.0.1", 4555, self.fingerprint)
        ready = service._public_device(item, self.clock())
        self.assertTrue(ready["remoteReady"])
        self.assertIn("message", ready["capabilities"])
        self.clock.advance(network_fabric.AUTH_SESSION_TTL_SECONDS + 0.1)
        expired = service._public_device(item, self.clock())
        self.assertFalse(expired["remoteReady"])
        self.assertNotIn("message", expired["capabilities"])

    def test_failed_fresh_verify_clears_prior_ready_session(self):
        self.manager._record_session(self.peer_id, "127.0.0.1", 4555, self.fingerprint, "lo0")
        route = {"address": "127.0.0.1", "interface": "lo0", "sourceAddress": "127.0.0.1"}
        with mock.patch.object(self.manager, "_endpoint_route", return_value=route):
            with mock.patch.object(self.manager, "_ensure_identity", return_value={"id": "c" * 32}):
                with mock.patch.object(
                    self.manager,
                    "_request",
                    side_effect=network_fabric.NetworkFabricError("peer_unreachable"),
                ):
                    with self.assertRaises(network_fabric.NetworkFabricError):
                        self.manager.verify_peer(
                            self.peer_id,
                            "127.0.0.1",
                            4555,
                            self.fingerprint,
                            "lo0",
                        )
        self.assertFalse(self.manager.session_status(self.peer_id)["ready"])

    def test_trust_badge_requires_the_stored_fingerprint_and_ready_binds_exact_endpoint(self):
        service = self._service()
        item = self._item()
        item["linkFingerprint"] = "c" * 64
        spoofed = service._public_device(item, self.clock())
        self.assertFalse(spoofed["paired"])
        self.assertNotIn("message", spoofed["capabilities"])

        item["linkFingerprint"] = self.fingerprint
        self.manager._record_session(self.peer_id, "127.0.0.1", 4555, self.fingerprint)
        item["addresses"] = {"127.0.0.2": self.clock()}
        moved = service._public_device(item, self.clock())
        self.assertTrue(moved["paired"])
        self.assertFalse(moved["remoteReady"])
        self.assertNotIn("message", moved["capabilities"])

    def test_service_expiry_removes_advertised_endpoint_and_capabilities(self):
        service = self._service()
        item = self._item(service_age=network_fabric.SERVICE_TTL_SECONDS + 1)
        service.devices[item["id"]] = item
        service._expire_devices(self.clock())
        self.assertFalse(service.devices[item["id"]]["services"])
        public = service._public_device(item, self.clock())
        self.assertNotIn("message", public["capabilities"])
        self.assertNotIn("verify-link", public["capabilities"])

    def test_advertisement_does_not_persist_endpoint_before_authenticated_health(self):
        service = self._service()
        item = self._item()
        service._record_service(
            item,
            {
                "type": network_fabric.KE_LINK_TYPE,
                "name": "redirect",
                "host": "redirect.local",
                "port": 5999,
                "properties": {"id": self.peer_id, "fp": self.fingerprint},
            },
            self.clock(),
            "192.168.1.9",
        )
        self.assertNotIn("host", self.manager.peers[self.peer_id])
        self.assertNotIn("port", self.manager.peers[self.peer_id])

    def test_authenticated_health_is_the_only_path_that_persists_a_changed_endpoint(self):
        self.manager.identity = {"id": "e" * 32, "fingerprint": "f" * 64}
        secret = base64.urlsafe_b64decode(self.secret)

        def authenticated_health(_host, _port, path, payload, expected_fingerprint, timeout=4.0, **_binding):
            self.assertEqual(path, "/v1/health")
            self.assertEqual(expected_fingerprint, self.fingerprint)
            signed = {key: payload[key] for key in ("version", "senderId", "timestamp", "nonce")}
            return {
                "ok": True,
                "peerId": self.peer_id,
                "fingerprint": self.fingerprint,
                "ack": __import__("hmac").new(secret, b"health-ack|" + network_fabric._canonical_json(signed), __import__("hashlib").sha256).hexdigest(),
            }

        with mock.patch.object(self.manager, "_request", side_effect=authenticated_health):
            receipt = self.manager.verify_peer(self.peer_id, "127.0.0.1", 4555, self.fingerprint)
        self.assertEqual(receipt["state"], "ready")
        self.assertEqual(self.manager.peers[self.peer_id]["host"], "127.0.0.1")
        self.assertEqual(self.manager.peers[self.peer_id]["interface"], "lo0")
        restarted = network_fabric.KELinkManager(
            self.root,
            clock=self.clock,
            advertise=False,
            listener_addresses=["127.0.0.1"],
            allowed_networks=["127.0.0.0/8"],
            allow_loopback=True,
        )
        self.assertEqual(restarted.peers[self.peer_id]["port"], 4555)

    def test_revoke_persists_and_restarted_manager_rejects_old_secret(self):
        self.manager.seen_nonces[f"{self.peer_id}:{'1' * 32}"] = self.clock()
        self.manager.received_acks[f"{self.peer_id}:{'2' * 32}"] = {"response": {}, "bodyDigest": "3" * 64}
        self.assertTrue(self.manager.revoke_peer(self.peer_id)["changed"])
        self.assertFalse(self.manager.seen_nonces)
        self.assertFalse(self.manager.received_acks)
        restarted = network_fabric.KELinkManager(
            self.root,
            clock=self.clock,
            advertise=False,
            listener_addresses=["127.0.0.1"],
            allowed_networks=["127.0.0.0/8"],
            allow_loopback=True,
        )
        self.assertNotIn(self.peer_id, restarted.peers)
        self.assertIn(self.peer_id, restarted.revoked)
        envelope = {
            "version": 1,
            "senderId": self.peer_id,
            "timestamp": self.clock(),
            "nonce": "c" * 32,
            "clientMessageId": "d" * 32,
            "body": "old secret must not work",
        }
        secret = base64.urlsafe_b64decode(self.secret)
        envelope["mac"] = __import__("hmac").new(secret, network_fabric._canonical_json(envelope), __import__("hashlib").sha256).hexdigest()
        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "not trusted"):
            restarted._handle_message(envelope)

    def test_malformed_or_secret_shaped_persistent_peer_fails_closed_without_overwrite(self):
        payload = {
            "schemaVersion": network_fabric.LINK_PROTOCOL,
            "peers": {
                self.peer_id: {
                    **self.manager.peers[self.peer_id],
                    "name": "token sk-secretsecretsecret",
                    "host": "/Users/alex/private",
                    "port": 70000,
                }
            },
            "revoked": {},
        }
        peers_path = Path(self.root, "peers.json")
        peers_path.write_bytes(network_fabric._canonical_json(payload) + b"\n")
        peers_path.chmod(0o600)
        before = peers_path.read_bytes()
        restarted = network_fabric.KELinkManager(
            self.root,
            clock=self.clock,
            advertise=False,
            listener_addresses=["127.0.0.1"],
            allowed_networks=["127.0.0.0/8"],
            allow_loopback=True,
        )
        self.assertFalse(restarted.storage_valid)
        self.assertFalse(restarted.peers)
        self.assertEqual(restarted.error["code"], "peer_store_insecure")
        with self.assertRaises(network_fabric.NetworkFabricError):
            restarted._save_peers()
        self.assertEqual(peers_path.read_bytes(), before)

    def test_uncertain_send_is_attempted_and_reuses_caller_message_identity(self):
        self.manager.identity = {"id": "e" * 32, "fingerprint": "f" * 64}
        self.manager.peers[self.peer_id].update({"host": "127.0.0.1", "port": 4555})
        self.manager._record_session(self.peer_id, "127.0.0.1", 4555, self.fingerprint)
        client_id = "1" * 32
        with mock.patch.object(self.manager, "_request", side_effect=network_fabric.NetworkFabricError("peer_unreachable")) as request:
            with self.assertRaises(network_fabric.NetworkFabricError) as raised:
                self.manager.send(self.peer_id, "one logical message", client_id)
        self.assertEqual(raised.exception.code, "message_delivery_uncertain")
        self.assertTrue(raised.exception.attempted)
        self.assertEqual(request.call_args.args[3]["clientMessageId"], client_id)
        self.assertEqual(request.call_args.kwargs["interface"], "lo0")
        self.assertEqual(request.call_args.kwargs["source_address"], "127.0.0.1")

    def test_nonce_and_request_rate_caps_are_hard_bounds(self):
        now = self.clock()
        for index in range(network_fabric.MAX_NONCES_PER_PEER):
            self.manager._record_nonce(self.peer_id, f"{index:032x}", now)
        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "limits"):
            self.manager._record_nonce(self.peer_id, "f" * 32, now)
        for _index in range(network_fabric.CLIENT_REQUESTS_PER_MINUTE):
            self.assertTrue(self.manager.allow_request("192.168.1.20"))
        self.assertFalse(self.manager.allow_request("192.168.1.20"))

    def test_listener_scope_is_ipv4_direct_private_and_loopback_is_fixture_only(self):
        private = network_fabric.KELinkManager(
            self.root,
            advertise=False,
            listener_addresses=["192.168.1.10"],
            allowed_networks=["192.168.1.0/24"],
            interface_provider=fixture_interfaces,  # never the host's real network (CI runners have no 192.168.1.x)
        )
        self.assertEqual(private._listener_scope()[0], "192.168.1.10")
        for address, network in (("0.0.0.0", "0.0.0.0/0"), ("8.8.8.8", "8.8.8.0/24"), ("::1", "::1/128")):
            manager = network_fabric.KELinkManager(
                self.root,
                advertise=False,
                listener_addresses=[address],
                allowed_networks=[network],
            )
            with self.assertRaises(network_fabric.NetworkFabricError):
                manager._listener_scope()
        server = object.__new__(network_fabric._BoundedThreadingHTTPServer)
        server.allowed_networks = (network_fabric.ipaddress.ip_network("192.168.1.0/24"),)
        server.allow_loopback = False
        self.assertTrue(server.verify_request(None, ("192.168.1.44", 5000)))
        self.assertFalse(server.verify_request(None, ("192.168.2.44", 5000)))
        self.assertFalse(server.verify_request(None, ("127.0.0.1", 5000)))
        self.assertEqual(network_fabric._BoundedThreadingHTTPServer.request_queue_size, network_fabric.MAX_LISTENER_CONNECTIONS)
        self.assertLessEqual(network_fabric.LISTENER_READ_TIMEOUT_SECONDS, 3.0)

    def test_authenticated_endpoint_must_be_on_a_current_direct_segment(self):
        manager = network_fabric.KELinkManager(
            self.root,
            clock=self.clock,
            advertise=False,
            interface_provider=lambda: [{
                "name": "en1",
                "scope": "local",
                "networks": ["192.168.1.0/24"],
                "addresses": ["192.168.1.10"],
                "scanEligible": True,
            }],
        )
        manager.peers[self.peer_id] = dict(self.manager.peers[self.peer_id])
        self.assertTrue(manager._endpoint_allowed("192.168.1.44"))
        self.assertFalse(manager._endpoint_allowed("192.168.2.44"))
        self.assertFalse(manager._endpoint_allowed("peer.local"))
        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "endpoint"):
            manager._record_session(self.peer_id, "192.168.2.44", 4555, self.fingerprint)

    def test_listener_saturation_and_slow_body_fail_bounded_without_network_io(self):
        server = object.__new__(network_fabric._BoundedThreadingHTTPServer)
        server.request_slots = threading.BoundedSemaphore(1)
        server.request_slots.acquire()
        closed = []
        server.shutdown_request = closed.append
        server.process_request(object(), ("192.168.1.2", 5000))
        self.assertEqual(len(closed), 1)
        server.request_slots.release()

        handler = object.__new__(network_fabric._LinkRequestHandler)
        timeouts = []
        handler.connection = SimpleNamespace(settimeout=timeouts.append)
        with mock.patch.object(network_fabric.BaseHTTPRequestHandler, "setup", return_value=None):
            handler.setup()
        self.assertEqual(timeouts, [network_fabric.LISTENER_READ_TIMEOUT_SECONDS])

        replies = []
        handler.client_address = ("192.168.1.2", 5000)
        handler.server = SimpleNamespace(manager=SimpleNamespace(allow_request=lambda _ip: True))
        handler.headers = {"Content-Length": "32"}
        handler.rfile = SimpleNamespace(read=lambda _size: (_ for _ in ()).throw(socket.timeout()))
        handler._reply = lambda status, body: replies.append((status, body))
        handler.do_POST()
        self.assertEqual(replies[-1][0], 408)
        self.assertEqual(replies[-1][1]["code"], "request_timeout")

        handler.rfile = io.BytesIO(b"{}")
        handler.do_POST()
        self.assertEqual(replies[-1][0], 400)
        self.assertEqual(replies[-1][1]["code"], "invalid_json")


class KELinkSecurityTests(unittest.TestCase):
    def setUp(self):
        if not Path(network_fabric.OPENSSL_PATH).is_file():
            self.skipTest("macOS openssl is required for the controlled TLS peer")
        self.left_temp = tempfile.TemporaryDirectory()
        self.right_temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.left_temp.cleanup)
        self.addCleanup(self.right_temp.cleanup)
        fixture_scope = {
            "listener_addresses": ["127.0.0.1"],
            "allowed_networks": ["127.0.0.0/8"],
            "allow_loopback": True,
        }
        self.left = network_fabric.KELinkManager(
            os.path.realpath(self.left_temp.name), name="Left Mac", advertise=False, **fixture_scope
        )
        self.right = network_fabric.KELinkManager(
            os.path.realpath(self.right_temp.name), name="Right Mac", advertise=False, **fixture_scope
        )
        self.addCleanup(self.left.disable)
        self.addCleanup(self.right.disable)

    def _pair(self):
        self.left.enable()
        self.right.enable()
        pairing = self.left.begin_pairing()
        fingerprint = self.left.identity["fingerprint"]
        result = self.right.pair("127.0.0.1", self.left.server.server_port, fingerprint, pairing["code"])
        self.assertTrue(result["ok"])
        return result

    def test_tls_pairing_and_authenticated_plain_text_message_are_real(self):
        result = self._pair()
        receipt = self.right.send(result["peerId"], "Hello over a controlled TLS peer", "1" * 32)
        replay = self.right.send(result["peerId"], "Hello over a controlled TLS peer", "1" * 32)
        self.assertTrue(receipt["ok"])
        self.assertEqual(replay["messageId"], receipt["messageId"])
        self.assertEqual(len(self.left.status()["messages"]), 1)
        self.assertEqual(len(self.right.status()["messages"]), 1)
        inbound = self.left.status()["messages"][-1]
        self.assertEqual(inbound["body"], "Hello over a controlled TLS peer")
        self.assertEqual(inbound["direction"], "inbound")
        left_store = Path(self.left_temp.name, "peers.json").read_text(encoding="utf-8")
        right_store = Path(self.right_temp.name, "peers.json").read_text(encoding="utf-8")
        self.assertNotIn("Hello over", left_store + right_store)
        for root in (Path(self.left_temp.name), Path(self.right_temp.name)):
            for path in root.iterdir():
                self.assertEqual(path.stat().st_mode & 0o077, 0, path)

    def test_wrong_code_and_fingerprint_fail_closed(self):
        self.left.enable()
        pairing = self.left.begin_pairing()
        with self.assertRaises(network_fabric.NetworkFabricError):
            self.right.pair("127.0.0.1", self.left.server.server_port, "0" * 64, pairing["code"])
        wrong = "A" * 26
        with self.assertRaises(network_fabric.NetworkFabricError):
            self.right.pair("127.0.0.1", self.left.server.server_port, self.left.identity["fingerprint"], wrong)

    def test_message_id_replays_return_same_ack_and_tampering_is_rejected(self):
        result = self._pair()
        sender_id = self.right.identity["id"]
        peer = self.left.peers[sender_id]
        envelope = {
            "version": 1,
            "senderId": sender_id,
            "timestamp": self.left.clock(),
            "nonce": "a" * 32,
            "clientMessageId": "2" * 32,
            "body": "one authenticated message",
        }
        secret = base64.urlsafe_b64decode(peer["secret"])
        envelope["mac"] = __import__("hmac").new(secret, network_fabric._canonical_json(envelope), __import__("hashlib").sha256).hexdigest()
        first = self.left._handle_message(dict(envelope))
        self.assertTrue(first["ok"])
        replay = self.left._handle_message(dict(envelope))
        self.assertEqual(replay, first)
        self.assertEqual(len(self.left.status()["messages"]), 1)
        tampered = dict(envelope, nonce="b" * 32, body="changed")
        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "not trusted"):
            self.left._handle_message(tampered)

    def test_message_limits_and_no_command_endpoint(self):
        result = self._pair()
        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "envelope is invalid"):
            self.right.send(result["peerId"], "x" * (network_fabric.MAX_MESSAGE_CHARS + 1), "3" * 32)
        status, body = self.left.handle_request("/v1/command", {"command": "whoami"})
        self.assertEqual(status, 404)
        self.assertEqual(body["code"], "not_found")
        self.assertIn("never grant command", self.left.status()["boundary"])

    def test_disable_cleans_server_and_advertiser_state(self):
        self.left.enable()
        thread = self.left.server_thread
        self.left.disable()
        self.assertFalse(thread.is_alive())
        self.assertFalse(self.left.status()["enabled"])
        self.assertIsNone(self.left.server)

    def test_stalled_client_hello_cannot_block_accept_loop_or_leak_slots(self):
        with mock.patch.object(network_fabric, "TLS_HANDSHAKE_TIMEOUT_SECONDS", 0.25):
            self.left.enable()
            baseline = _fd_count()
            stalled = socket.create_connection(self.left.server.server_address, timeout=1)
            stalled.sendall(b"\x16\x03\x01")
            context = __import__("ssl")._create_unverified_context()
            valid = context.wrap_socket(socket.socket(), server_hostname="localhost")
            valid.settimeout(1)
            valid.connect(self.left.server.server_address)
            valid.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            self.assertIn(b"405", valid.recv(1024))
            valid.close()
            time.sleep(0.4)
            stalled.close()
            acquired = 0
            while self.left.server.request_slots.acquire(blocking=False):
                acquired += 1
            for _index in range(acquired):
                self.left.server.request_slots.release()
            self.assertEqual(acquired, network_fabric.MAX_LISTENER_CONNECTIONS)
            self.assertLessEqual(_fd_count(), baseline + 1)


class NetworkFabricStopLifecyclePureTests(unittest.TestCase):
    def _service(self):
        link = SimpleNamespace(
            disable=mock.Mock(return_value={"ok": True}),
            status=lambda: {
                "enabled": False,
                "pairedPeerCount": 0,
                "trustedPeers": [],
                "errors": [],
            },
        )
        service = network_fabric.NetworkFabricService(
            clock=FakeClock(),
            interface_provider=lambda: [],
            command_runner=FakeRunner(),
            ping_probe=lambda _ip, _interface, _source: None,
            mdns_probe=lambda _stop: [],
            ssdp_probe=lambda _stop: [],
            connection_provider=lambda: [],
            link_manager=link,
        )
        return service, link

    def test_stop_before_start_is_idempotent_and_clears_lifecycle_state(self):
        service, _link = self._service()
        service.scanning = True

        stopped = service.stop_discovery()

        self.assertFalse(stopped["active"])
        self.assertFalse(stopped["scan"]["inProgress"])
        self.assertIsNone(service.thread)
        self.assertTrue(service.stop_event.is_set())
        self.assertTrue(service.scan_event.is_set())

    def test_repeated_stop_with_no_thread_remains_safe_and_stopped(self):
        service, _link = self._service()

        first = service.stop_discovery()
        second = service.stop_discovery()

        self.assertFalse(first["active"])
        self.assertFalse(second["active"])
        self.assertFalse(second["scan"]["inProgress"])
        self.assertIsNone(service.thread)

    def test_shutdown_without_discovery_thread_still_disables_ke_link(self):
        service, link = self._service()

        result = service.shutdown()

        self.assertEqual(result, {"ok": True})
        link.disable.assert_called_once_with()
        self.assertIsNone(service.thread)
        self.assertFalse(service.active)


class NetworkFrozenLeafPureTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    @staticmethod
    def _passive_link():
        return SimpleNamespace(
            peers={},
            allow_loopback=False,
            session_status=lambda *_args, **_kwargs: {
                "state": "not-ready",
                "ready": False,
                "ttlSeconds": network_fabric.AUTH_SESSION_TTL_SECONDS,
            },
        )

    def _service(self):
        return network_fabric.NetworkFabricService(
            clock=self.clock,
            interface_provider=lambda: [],
            command_runner=FakeRunner(),
            ping_probe=lambda _ip, _interface, _source: None,
            mdns_probe=lambda _stop: [],
            ssdp_probe=lambda _stop: [],
            connection_provider=lambda: [],
            link_manager=self._passive_link(),
        )

    def _pure_link_manager(self):
        manager = network_fabric.KELinkManager.__new__(network_fabric.KELinkManager)
        secret = b"s" * 32
        peer_id = "a" * 32
        manager.lock = threading.RLock()
        manager.clock = self.clock
        manager.name = "Pure peer"
        manager.advertise = False
        manager.allow_loopback = False
        manager.identity = None
        manager.peers = {
            peer_id: {
                "id": peer_id,
                "name": "Pure sender",
                "fingerprint": "b" * 64,
                "secret": base64.urlsafe_b64encode(secret).decode("ascii"),
            },
        }
        manager.revoked = {}
        manager.sessions = {}
        manager.messages = collections.deque(maxlen=200)
        manager.seen_nonces = {}
        manager.received_acks = collections.OrderedDict()
        manager.request_times = collections.deque()
        manager.client_request_times = {}
        manager.peer_request_times = {}
        manager.pairing = None
        manager.listener_generation = 7
        manager.server = SimpleNamespace(
            listener_generation=7,
            shutdown=mock.Mock(),
            server_close=mock.Mock(),
        )
        manager.server_thread = None
        manager.advertiser = None
        manager.advertiser_args = None
        manager.advertiser_retry_at = 0.0
        manager.listener_interface = None
        manager.error = None
        manager.runtime_errors = {}
        manager.storage_valid = True
        manager._save_received_acks = mock.Mock()
        manager.status = mock.Mock(return_value={"ok": True, "enabled": False})
        return manager, peer_id, secret

    def _message_envelope(self, peer_id, secret, nonce="c" * 32):
        envelope = {
            "version": 1,
            "senderId": peer_id,
            "timestamp": self.clock(),
            "nonce": nonce,
            "clientMessageId": "d" * 32,
            "body": "one pure authenticated message",
        }
        envelope["mac"] = hmac.new(
            secret,
            network_fabric._canonical_json(envelope),
            hashlib.sha256,
        ).hexdigest()
        return envelope

    def test_bonjour_withdrawals_do_not_resolve_or_refresh_actionable_service(self):
        peer_id = "e" * 32
        fingerprint = "f" * 64
        native_rows = [
            network_fabric._dns_sd_native_browse_row(
                network_fabric.DNS_SERVICE_FLAGS_ADD,
                7, b"Withdrawn peer", b"_ke-link._tcp.", b"local.",
            ),
            network_fabric._dns_sd_native_browse_row(
                0, 7, b"Withdrawn peer", b"_ke-link._tcp.", b"local.",
            ),
        ]

        def native_browse(type_name, _index, _duration, _stop=None):
            return native_rows if type_name == "_ke-link._tcp" else []

        interface = {
            "name": "en0",
            "scope": "local",
            "scanEligible": True,
            "addresses": ["192.168.1.10"],
            "networks": ["192.168.1.0/24"],
        }
        with mock.patch.object(network_fabric.socket, "if_nametoindex", return_value=7):
            with mock.patch.object(network_fabric.socket, "if_indextoname", return_value="en0"):
                with mock.patch.object(network_fabric, "_native_dns_sd_browse", side_effect=native_browse):
                    with mock.patch.object(network_fabric, "_capture_process") as process:
                        rows = network_fabric._default_mdns(interfaces=[interface])
        self.assertEqual(rows, [{
            "withdrawn": True,
            "withdrawalKind": "service",
            "type": network_fabric.KE_LINK_TYPE,
            "name": "Withdrawn peer",
            "instanceKey": network_fabric._bonjour_instance_key("Withdrawn peer"),
            "interfaceIndex": 7,
            "interface": "en0",
            "addresses": [],
        }])
        process.assert_not_called()

        service = self._service()
        service.interfaces = [interface]
        advertised = {
            "type": network_fabric.KE_LINK_TYPE,
            "name": "Withdrawn peer",
            "host": "withdrawn.local",
            "port": 4555,
            "interface": "en0",
            "properties": {"id": peer_id, "fp": fingerprint, "proto": "1"},
        }
        service._apply_observations([{
            "source": "bonjour",
            "direct": True,
            "ip": "192.168.1.44",
            "interface": "en0",
            "service": advertised,
        }], self.clock(), set(), set(), set())
        device = next(iter(service.devices.values()))
        self.clock.advance(8)
        service._apply_observations([], self.clock(), set(), set(), set())
        before = service._public_device(device, self.clock())
        self.assertEqual(before["state"], "online")
        self.assertIn("pair", before["capabilities"])

        service.interface_provider = lambda: [interface]
        service.mdns_probe = lambda _stop: rows
        service.active = True
        service._scan_once(deep=False)
        self.assertIsNone(service._ke_service(device))
        after = service._public_device(device, self.clock())
        self.assertNotEqual(after["state"], "online")
        self.assertEqual(after["services"], [])
        self.assertFalse({"ping", "pair", "verify-link", "message"}.intersection(after["capabilities"]))

    def test_bonjour_withdrawal_uses_opaque_identity_when_safe_labels_collide(self):
        interface = {
            "name": "en0",
            "scope": "local",
            "scanEligible": True,
            "addresses": ["192.168.1.10"],
            "networks": ["192.168.1.0/24"],
        }
        service = self._service()
        service.interfaces = [interface]

        def observation(name, address, identity):
            return {
                "source": "bonjour",
                "direct": True,
                "ip": address,
                "interface": "en0",
                "service": {
                    "type": network_fabric.KE_LINK_TYPE,
                    "name": name,
                    "host": f"peer-{identity[0]}.local",
                    "port": 4555,
                    "interface": "en0",
                    "properties": {
                        "id": identity,
                        "fp": identity[0] * 64,
                        "proto": "1",
                    },
                },
            }

        first_peer = "1" * 32
        second_peer = "2" * 32
        first_key = network_fabric._bonjour_instance_key("Peer/One")
        second_key = network_fabric._bonjour_instance_key("Peer/Two")
        self.assertNotEqual(first_key, second_key)
        self.assertRegex(first_key, r"^bonjour-instance:[a-f0-9]{64}$")
        self.assertIsNone(network_fabric._bonjour_instance_key(""))
        self.assertIsNone(network_fabric._bonjour_instance_key("x" * 64))
        self.assertIsNotNone(network_fabric._bonjour_instance_key("unsafe\ninstance"))
        self.assertIsNone(network_fabric._validated_bonjour_instance_key("bonjour-instance:not-a-digest"))
        service._apply_observations([
            observation("Peer/One", "192.168.1.44", first_peer),
            observation("Peer/Two", "192.168.1.45", second_peer),
        ], self.clock(), set(), set(), set())

        by_peer = {item.get("linkPeerId"): item for item in service.devices.values()}
        self.assertEqual(
            next(iter(by_peer[first_peer]["services"].values()))["instanceKey"],
            first_key,
        )
        self.assertEqual(
            next(iter(by_peer[second_peer]["services"].values()))["instanceKey"],
            second_key,
        )
        public_payload = json.dumps([
            service._public_device(by_peer[first_peer], self.clock()),
            service._public_device(by_peer[second_peer], self.clock()),
        ], sort_keys=True)
        self.assertNotIn("Peer/One", public_payload)
        self.assertNotIn("Peer/Two", public_payload)
        self.assertNotIn("instanceKey", public_payload)
        self.assertNotIn(first_key, public_payload)
        self.assertNotIn(second_key, public_payload)
        self.assertEqual(public_payload.count("Observed service"), 2)

        service._apply_observations([{
            "source": "bonjour",
            "withdrawn": True,
            "withdrawalKind": "service",
            "interface": "en0",
            "service": {
                "withdrawn": True,
                "withdrawalKind": "service",
                "type": network_fabric.KE_LINK_TYPE,
                "name": "Observed service",
                "instanceKey": first_key,
                "interface": "en0",
                "addresses": [],
            },
        }], self.clock(), set(), set(), set())

        self.assertEqual(by_peer[first_peer]["services"], {})
        self.assertEqual(len(by_peer[second_peer]["services"]), 1)
        first_public = service._public_device(by_peer[first_peer], self.clock())
        second_public = service._public_device(by_peer[second_peer], self.clock())
        self.assertFalse({"ping", "pair", "verify-link", "message"}.intersection(first_public["capabilities"]))
        self.assertIn("pair", second_public["capabilities"])

    def test_bonjour_native_control_instances_withdraw_only_exact_identity(self):
        interface = {
            "name": "en0",
            "scope": "local",
            "scanEligible": True,
            "addresses": ["192.168.1.10"],
            "networks": ["192.168.1.0/24"],
        }
        service = self._service()
        service.interfaces = [interface]

        def observation(row, address, digit):
            return {
                "source": "bonjour",
                "direct": True,
                "ip": address,
                "interface": "en0",
                "service": {
                    "type": network_fabric.KE_LINK_TYPE,
                    "name": row["name"],
                    "instanceKey": row["instanceKey"],
                    "host": f"peer-{digit}.local",
                    "port": 4555,
                    "interface": "en0",
                    "properties": {
                        "id": digit * 32,
                        "fp": digit * 64,
                        "proto": "1",
                    },
                },
            }

        names = ["Peer", " Peer ", "Peer ", "Peer\r", "Peer\nInjected"]
        parsed_rows = [
            network_fabric._dns_sd_native_browse_row(
                network_fabric.DNS_SERVICE_FLAGS_ADD,
                7,
                name.encode("utf-8"),
                b"_ke-link._tcp.",
                b"local.",
            )
            for name in names
        ]
        self.assertEqual([row["name"] for row in parsed_rows], names)
        service._apply_observations([
            observation(row, f"192.168.1.{44 + index}", str(index + 1))
            for index, row in enumerate(parsed_rows)
        ], self.clock(), set(), set(), set())
        by_peer = {item.get("linkPeerId"): item for item in service.devices.values()}
        retained_keys = {
            peer_id: next(iter(device["services"].values()))["instanceKey"]
            for peer_id, device in by_peer.items()
        }
        self.assertEqual(len(set(retained_keys.values())), len(names))

        removed_row = network_fabric._dns_sd_native_browse_row(
            0, 7, b"Peer\r", b"_ke-link._tcp.", b"local.",
        )
        service._apply_observations([{
            "source": "bonjour",
            "withdrawn": True,
            "withdrawalKind": "service",
            "interface": "en0",
            "service": {
                "withdrawn": True,
                "withdrawalKind": "service",
                "type": network_fabric.KE_LINK_TYPE,
                "name": removed_row["name"],
                "instanceKey": removed_row["instanceKey"],
                "interface": "en0",
                "addresses": [],
            },
        }], self.clock(), set(), set(), set())

        self.assertEqual(len(by_peer["1" * 32]["services"]), 1)
        self.assertEqual(len(by_peer["2" * 32]["services"]), 1)
        self.assertEqual(len(by_peer["3" * 32]["services"]), 1)
        self.assertEqual(by_peer["4" * 32]["services"], {})
        self.assertEqual(len(by_peer["5" * 32]["services"]), 1)
        public_devices = [
            service._public_device(device, self.clock())
            for device in by_peer.values()
        ]
        public_payload = json.dumps(public_devices, sort_keys=True)
        self.assertNotIn("instanceKey", public_payload)
        self.assertNotIn("bonjour-instance:", public_payload)
        self.assertNotIn("\\r", public_payload)
        self.assertNotIn("\\n", public_payload)

    def test_bonjour_address_remove_invalidates_only_withdrawn_endpoint_immediately(self):
        interface = {
            "name": "en0", "scope": "local", "scanEligible": True,
            "addresses": ["192.168.1.10"], "networks": ["192.168.1.0/24"],
        }
        advertised = {
            "type": network_fabric.KE_LINK_TYPE,
            "name": "Address withdrawal peer",
            "host": "address-withdrawal.local",
            "port": 4555,
            "interface": "en0",
            "properties": {"id": "7" * 32, "fp": "8" * 64, "proto": "1"},
        }
        native_row = network_fabric._dns_sd_native_browse_row(
            network_fabric.DNS_SERVICE_FLAGS_ADD,
            7,
            b"Address withdrawal peer",
            b"_ke-link._tcp.",
            b"local.",
        )

        def native_browse(type_name, _index, _duration, _stop=None):
            return [native_row] if type_name == "_ke-link._tcp" else []

        def native_resolve(_instance, type_name, _index, _duration, _stop=None):
            if type_name != "_ke-link._tcp":
                return None
            return {
                "host": "address-withdrawal.local",
                "port": 4555,
                "interfaceIndex": 7,
                "properties": {"id": "7" * 32, "fp": "8" * 64, "proto": "1"},
            }

        def capture(args, _duration, _stop=None):
            if "-G" in args:
                return "12:00:00.000 Rmv 2 7 address-withdrawal.local. 192.168.1.44 0\n"
            return ""

        with mock.patch.object(network_fabric.os.path, "isfile", return_value=True):
            with mock.patch.object(network_fabric.socket, "if_nametoindex", return_value=7):
                with mock.patch.object(network_fabric.socket, "if_indextoname", return_value="en0"):
                    with mock.patch.object(network_fabric, "_native_dns_sd_browse", side_effect=native_browse):
                        with mock.patch.object(network_fabric, "_native_dns_sd_resolve", side_effect=native_resolve):
                            with mock.patch.object(network_fabric, "_capture_process", side_effect=capture):
                                rows = network_fabric._default_mdns(interfaces=[interface])
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["instanceKey"],
            network_fabric._bonjour_instance_key("Address withdrawal peer"),
        )
        self.assertTrue(rows[0]["withdrawn"])
        self.assertEqual(rows[0]["withdrawalKind"], "address")
        self.assertEqual(rows[0]["withdrawnAddresses"], ["192.168.1.44"])

        service = self._service()
        service.interfaces = [interface]
        service._apply_observations([{
            "source": "bonjour", "direct": True, "ip": "192.168.1.44",
            "interface": "en0", "service": advertised,
        }], self.clock(), set(), set(), set())
        device = next(iter(service.devices.values()))
        self.clock.advance(8)
        service.interface_provider = lambda: [interface]
        service.mdns_probe = lambda _stop: rows
        service.active = True
        service._scan_once(deep=False)
        public = service._public_device(device, self.clock())
        self.assertNotEqual(public["state"], "online")
        self.assertEqual(public["addresses"], [])
        self.assertEqual(public["services"], [])
        self.assertFalse({"ping", "pair", "verify-link", "message"}.intersection(public["capabilities"]))

    def test_new_stable_mac_rebinds_address_and_anonymous_icmp_to_new_owner(self):
        interface = {
            "name": "en0", "scope": "local", "scanEligible": True,
            "addresses": ["192.168.1.10"], "networks": ["192.168.1.0/24"],
        }
        service = self._service()
        service.interfaces = [interface]
        old_mac = "02:00:00:00:00:01"
        new_mac = "02:00:00:00:00:02"
        advertised = {
            "type": network_fabric.KE_LINK_TYPE,
            "name": "Former address owner",
            "host": "former-owner.local",
            "port": 4555,
            "interface": "en0",
            "properties": {"id": "9" * 32, "fp": "a" * 64, "proto": "1"},
        }
        service._apply_observations([{
            "source": "bonjour", "direct": True, "ip": "192.168.1.44",
            "interface": "en0", "mac": old_mac, "service": advertised,
        }], self.clock(), set(), set(), set())
        old_device = next(iter(service.devices.values()))
        self.clock.advance(8)
        service._apply_observations([{
            "source": "arp", "direct": False, "ip": "192.168.1.44",
            "interface": "en0", "mac": new_mac,
        }], self.clock(), set(), set(), set())
        new_device = next(item for item in service.devices.values() if item.get("mac") == new_mac)
        self.assertEqual(
            service.identity_map["ip:192.168.1.44|if:en0"],
            new_device["id"],
        )
        self.assertEqual(service._address_records(old_device), [])
        self.assertEqual(old_device["services"], {})

        self.clock.advance(1)
        service._apply_observations([{
            "source": "icmp", "direct": True, "ip": "192.168.1.44",
            "interface": "en0", "latencyMs": 1.25,
        }], self.clock(), set(), set(), set())
        old_public = service._public_device(old_device, self.clock())
        new_public = service._public_device(new_device, self.clock())
        self.assertNotEqual(old_public["state"], "online")
        self.assertFalse({"ping", "wake", "pair", "verify-link", "message"}.intersection(old_public["capabilities"]))
        self.assertEqual(new_public["state"], "online")
        self.assertEqual(new_public["addresses"], ["192.168.1.44"])
        self.assertIn("ping", new_public["capabilities"])

    def test_ke_service_endpoint_freshness_recovers_and_same_scan_ambiguity_fails_closed(self):
        interface = {
            "name": "en0",
            "scope": "local",
            "scanEligible": True,
            "addresses": ["192.168.1.10"],
            "networks": ["192.168.1.0/24"],
        }
        advertised = {
            "type": network_fabric.KE_LINK_TYPE,
            "name": "Moving peer",
            "host": "moving.local",
            "port": 4555,
            "interface": "en0",
            "properties": {"id": "1" * 32, "fp": "2" * 64, "proto": "1"},
        }
        service = self._service()
        service.interfaces = [interface]
        service._apply_observations([{
            "source": "bonjour", "direct": True, "ip": "192.168.1.44",
            "interface": "en0", "service": advertised,
        }], self.clock(), set(), set(), set())
        device = next(iter(service.devices.values()))
        self.clock.advance(60)
        service._apply_observations([{
            "source": "bonjour", "direct": True, "ip": "192.168.1.45",
            "interface": "en0", "service": advertised,
        }], self.clock(), set(), set(), set())
        current = service._ke_service(device)
        self.assertEqual(current["endpoints"], ["192.168.1.45"])
        self.assertEqual(service._service_endpoint(device, current), "192.168.1.45")
        self.clock.advance(61)
        service._expire_devices(self.clock())
        self.assertEqual(
            [row["address"] for row in service._address_records(device)],
            ["192.168.1.45"],
        )

        simultaneous = self._service()
        simultaneous.interfaces = [interface]
        observed_at = self.clock()
        simultaneous._apply_observations([
            {
                "source": "bonjour", "direct": True, "ip": "192.168.1.60",
                "interface": "en0", "service": advertised,
            },
            {
                "source": "bonjour", "direct": True, "ip": "192.168.1.61",
                "interface": "en0", "service": advertised,
            },
        ], observed_at, set(), set(), set())
        simultaneous_device = next(iter(simultaneous.devices.values()))
        ambiguous = next(iter(simultaneous_device["services"].values()))
        self.assertEqual(ambiguous["endpoints"], ["192.168.1.60", "192.168.1.61"])
        self.assertIsNone(simultaneous._service_endpoint(simultaneous_device, ambiguous))
        self.assertIsNone(simultaneous._ke_service(simultaneous_device))

    def test_disabled_listener_rejects_all_request_surfaces_without_side_effects(self):
        manager, peer_id, secret = self._pure_link_manager()
        envelope = self._message_envelope(peer_id, secret)
        old_generation = manager.listener_generation
        manager.disable()

        for path, payload in (
            ("/v1/pair/challenge", {}),
            ("/v1/pair", {}),
            ("/v1/health", {}),
            ("/v1/message", envelope),
        ):
            status, body = manager.handle_request(
                path,
                payload,
                client_ip="192.168.1.44",
                listener_generation=old_generation,
            )
            self.assertEqual(status, 409)
            self.assertEqual(body["code"], "ke_link_disabled")
        self.assertFalse(manager.sessions)
        self.assertFalse(manager.seen_nonces)
        self.assertFalse(manager.received_acks)
        self.assertFalse(manager.messages)
        manager._save_received_acks.assert_not_called()

    def test_enabled_message_replay_is_idempotent_with_listener_generation(self):
        manager, peer_id, secret = self._pure_link_manager()
        envelope = self._message_envelope(peer_id, secret)
        first = manager.handle_request(
            "/v1/message", envelope, client_ip="192.168.1.44", listener_generation=7,
        )
        replay = manager.handle_request(
            "/v1/message", envelope, client_ip="192.168.1.44", listener_generation=7,
        )
        self.assertEqual(first, replay)
        self.assertEqual(first[0], 200)
        self.assertEqual(len(manager.received_acks), 1)
        self.assertEqual(len(manager.messages), 1)

    def test_request_commit_serializes_before_disable_and_disable_first_rejects(self):
        manager, peer_id, secret = self._pure_link_manager()
        envelope = self._message_envelope(peer_id, secret)
        save_entered = threading.Event()
        release_save = threading.Event()
        disable_started = threading.Event()
        disable_done = threading.Event()
        request_result = []

        def block_save():
            save_entered.set()
            self.assertTrue(release_save.wait(1))

        manager._save_received_acks = mock.Mock(side_effect=block_save)

        def request_worker():
            request_result.append(manager.handle_request(
                "/v1/message", envelope, client_ip="192.168.1.44", listener_generation=7,
            ))

        def disable_worker():
            disable_started.set()
            manager.disable()
            disable_done.set()

        request_thread = threading.Thread(target=request_worker)
        disable_thread = threading.Thread(target=disable_worker)
        request_thread.start()
        self.assertTrue(save_entered.wait(1))
        disable_thread.start()
        self.assertTrue(disable_started.wait(1))
        self.assertFalse(disable_done.wait(0.05))
        release_save.set()
        request_thread.join(1)
        disable_thread.join(1)
        self.assertFalse(request_thread.is_alive())
        self.assertFalse(disable_thread.is_alive())
        self.assertTrue(disable_done.is_set())
        self.assertEqual(request_result[0][0], 200)
        self.assertEqual(len(manager.received_acks), 1)
        self.assertEqual(len(manager.messages), 1)
        self.assertIsNone(manager.server)

        rejected, body = manager.handle_request(
            "/v1/message", envelope, client_ip="192.168.1.44", listener_generation=7,
        )
        self.assertEqual(rejected, 409)
        self.assertEqual(body["code"], "ke_link_disabled")
        self.assertEqual(len(manager.received_acks), 1)
        self.assertEqual(len(manager.messages), 1)


class NetworkSuccessorRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = FakeClock()
        self.link = network_fabric.KELinkManager(
            os.path.realpath(self.temp.name),
            clock=self.clock,
            advertise=False,
            listener_addresses=["127.0.0.1"],
            allowed_networks=["127.0.0.0/8"],
            allow_loopback=True,
        )

    def _service(self, interfaces=fixture_interfaces):
        return network_fabric.NetworkFabricService(
            clock=self.clock,
            interface_provider=interfaces,
            command_runner=FakeRunner(),
            ping_probe=lambda _ip, _interface, _source: None,
            mdns_probe=lambda _stop: [],
            ssdp_probe=lambda _stop: [],
            connection_provider=lambda: [],
            link_manager=self.link,
        )

    def test_interface_provenance_prevents_link_local_and_overlapping_ipv4_collisions(self):
        service = self._service()
        observations = [
            {"source": "ndp", "ip": "fe80::1234%en0", "interface": "en0", "mac": "02:00:00:00:00:01"},
            {"source": "ndp", "ip": "fe80::1234%en5", "interface": "en5", "mac": "02:00:00:00:00:02"},
            {"source": "arp", "ip": "192.168.1.44", "interface": "en0", "mac": "02:00:00:00:00:03"},
            {"source": "arp", "ip": "192.168.1.44", "interface": "en5", "mac": "02:00:00:00:00:04"},
        ]
        service._apply_observations(observations, self.clock(), set(), set(), set())
        self.assertEqual(len(service.devices), 4)
        addresses = [
            sorted(row["address"] for row in service._address_records(device))
            for device in service.devices.values()
        ]
        self.assertIn(["fe80::1234%en0"], addresses)
        self.assertIn(["fe80::1234%en5"], addresses)
        self.assertEqual(sum(values == ["192.168.1.44"] for values in addresses), 2)
        scoped_route = network_fabric._route_binding(
            "fe80::1234%en0",
            [
                {"name": "en0", "scope": "local", "networks": ["fe80::/64"], "addresses": ["fe80::1%en0"]},
                {"name": "en5", "scope": "local", "networks": ["fe80::/64"], "addresses": ["fe80::1%en5"]},
            ],
        )
        self.assertEqual(scoped_route["interface"], "en0")
        self.assertEqual(scoped_route["sourceAddress"], "fe80::1%en0")

    def test_stable_mac_dedupes_global_and_ula_ipv6_across_interfaces(self):
        service = self._service()
        for address in ("fd00::44", "2001:db8::44"):
            service.devices.clear()
            service.identity_map.clear()
            service._apply_observations([
                {"source": "bonjour", "ip": address, "interface": "en0", "mac": "02:00:00:00:00:aa"},
                {"source": "connection", "ip": address, "interface": "en5", "mac": "02:00:00:00:00:aa"},
            ], self.clock(), set(), set(), set())
            self.assertEqual(len(service.devices), 1)

    def test_scan_targets_keep_same_ipv4_on_distinct_interfaces(self):
        interfaces = [
            {"name": "en0", "scope": "local", "scanEligible": True, "addresses": ["192.168.1.10"], "networks": ["192.168.1.8/30"]},
            {"name": "en5", "scope": "local", "scanEligible": True, "addresses": ["192.168.1.9"], "networks": ["192.168.1.8/30"]},
        ]
        targets, _limited = network_fabric._scan_targets(interfaces)
        self.assertEqual(targets, [])

    def test_tunnel_and_peer_to_peer_interfaces_are_excluded_and_reported(self):
        interfaces = lambda: [
            {"name": "en1", "scope": "local", "scanEligible": True, "addresses": ["192.168.1.10"], "networks": ["192.168.1.0/24"]},
            {"name": "utun4", "scope": "tunnel", "scanEligible": False, "addresses": ["10.9.0.2"], "networks": ["10.9.0.0/24"]},
            {"name": "awdl0", "scope": "peer-to-peer", "scanEligible": False, "addresses": ["169.254.4.2"], "networks": ["169.254.0.0/16"]},
        ]
        service = self._service(interfaces)
        service.mdns_probe = lambda _stop: [{
            "type": "_http._tcp.local.", "name": "AWDL only", "host": "awdl.local",
            "port": 80, "properties": {}, "addresses": ["169.254.4.8"], "interface": "awdl0",
        }]
        service.active = True
        service._scan_once(deep=False)
        snapshot = service.get_snapshot()
        self.assertEqual([row["name"] for row in snapshot["local"]["interfaces"]], ["en1"])
        self.assertEqual({row["name"] for row in snapshot["local"]["excludedInterfaces"]}, {"utun4", "awdl0"})
        self.assertEqual(snapshot["coverage"]["eligibleSegmentCount"], 1)
        self.assertEqual(snapshot["coverage"]["excludedInterfaceCount"], 2)
        self.assertFalse(any("169.254.4.8" in row["addresses"] for row in snapshot["devices"]))

    def test_permission_errors_are_source_keyed_and_success_clears_only_that_source(self):
        service = self._service()
        self.assertEqual(service._safe_call("bonjour", lambda: (_ for _ in ()).throw(PermissionError()), []), [])
        self.assertEqual(service.errors[0]["code"], "permission_denied")
        service._set_source_error("ssdp", "discovery_unavailable")
        self.assertEqual(service._safe_call("bonjour", lambda: ["restored"], []), ["restored"])
        self.assertEqual([(row["source"], row["code"]) for row in service.errors], [("ssdp", "discovery_unavailable")])

    def test_production_probe_adapters_propagate_permission_denial(self):
        denied_socket = mock.Mock()
        denied_socket.sendto.side_effect = PermissionError(1, "denied")
        with mock.patch.object(network_fabric.socket, "socket", return_value=denied_socket):
            with self.assertRaisesRegex(network_fabric.NetworkFabricError, "Local Network access"):
                network_fabric._default_ssdp(duration=0.1, interfaces=fixture_interfaces())
        with mock.patch.object(network_fabric.subprocess, "Popen", side_effect=PermissionError(1, "denied")):
            with self.assertRaisesRegex(network_fabric.NetworkFabricError, "Local Network access"):
                network_fabric._capture_process([network_fabric.DNS_SD_PATH], 0.1)

        class DeniedAfterTermination:
            returncode = -15

            def poll(self):
                return None

            def terminate(self):
                return None

            def communicate(self, timeout=None):
                return "dns-sd: Local Network policy denied", None

            def kill(self):
                return None

        with mock.patch.object(network_fabric.subprocess, "Popen", return_value=DeniedAfterTermination()):
            with mock.patch.object(network_fabric.time, "monotonic", side_effect=[0.0, 1.0]):
                with self.assertRaisesRegex(network_fabric.NetworkFabricError, "Local Network access"):
                    network_fabric._capture_process([network_fabric.DNS_SD_PATH], 0.1)

    def test_durable_trust_inventory_survives_no_discovery_and_revokes_by_peer_id(self):
        peer_id = "a" * 32
        secret = base64.urlsafe_b64encode(b"s" * 32).decode("ascii")
        self.link.peers[peer_id] = {
            "id": peer_id, "name": "Offline Studio", "fingerprint": "b" * 64,
            "secret": secret, "pairedAt": network_fabric._utc_iso(self.clock()),
        }
        self.link._save_peers()
        service = self._service()
        snapshot = service.get_snapshot()
        self.assertEqual(snapshot["devices"], [])
        self.assertEqual(snapshot["counts"]["paired"], 1)
        self.assertEqual(snapshot["link"]["trustedPeers"], [{
            "id": peer_id, "name": "Offline Studio", "pairedAt": network_fabric._utc_iso(self.clock()),
            "hasAuthenticatedEndpoint": False, "ready": False,
        }])
        self.assertTrue(service.revoke_trusted_peer(peer_id)["changed"])
        restarted = network_fabric.KELinkManager(
            os.path.realpath(self.temp.name), clock=self.clock, advertise=False,
            listener_addresses=["127.0.0.1"], allowed_networks=["127.0.0.0/8"], allow_loopback=True,
        )
        self.assertNotIn(peer_id, restarted.peers)
        self.assertIn(peer_id, restarted.revoked)

    def test_pair_requires_prior_explicit_listener_enablement(self):
        with mock.patch.object(self.link, "_request") as request:
            with self.assertRaisesRegex(network_fabric.NetworkFabricError, "Enable KE Link"):
                self.link.pair("127.0.0.1", 4555, "b" * 64, "AAAA-BBBB-CCCC-DDDD")
        request.assert_not_called()
        self.assertFalse(self.link.status()["enabled"])
        with mock.patch.object(self.link, "enable") as enable:
            with self.assertRaisesRegex(network_fabric.NetworkFabricError, "Enable KE Link"):
                self.link.begin_pairing()
        enable.assert_not_called()

    def test_received_ack_ledger_is_authenticated_body_free_and_restart_idempotent(self):
        peer_id = "c" * 32
        secret_text = base64.urlsafe_b64encode(b"q" * 32).decode("ascii")
        self.link.peers[peer_id] = {
            "id": peer_id, "name": "Restart peer", "fingerprint": "d" * 64,
            "secret": secret_text, "pairedAt": network_fabric._utc_iso(self.clock()),
        }
        self.link._save_peers()
        envelope = {
            "version": 1, "senderId": peer_id, "timestamp": self.clock(), "nonce": "e" * 32,
            "clientMessageId": "f" * 32, "body": "committed once only",
        }
        secret = base64.urlsafe_b64decode(secret_text)
        envelope["mac"] = __import__("hmac").new(secret, network_fabric._canonical_json(envelope), __import__("hashlib").sha256).hexdigest()
        first = self.link._handle_message(dict(envelope), client_ip="127.0.0.1")
        ledger = Path(self.temp.name, "message-acks.json").read_text(encoding="utf-8")
        self.assertNotIn("committed once only", ledger)
        self.assertIn("recordMac", ledger)
        restarted = network_fabric.KELinkManager(
            os.path.realpath(self.temp.name), clock=self.clock, advertise=False,
            listener_addresses=["127.0.0.1"], allowed_networks=["127.0.0.0/8"], allow_loopback=True,
        )
        replay = restarted._handle_message(dict(envelope), client_ip="127.0.0.1")
        self.assertEqual(replay, first)
        self.assertEqual(list(restarted.messages), [])
        changed = dict(envelope, nonce="1" * 32, body="different body")
        changed.pop("mac", None)
        changed["mac"] = __import__("hmac").new(secret, network_fabric._canonical_json(changed), __import__("hashlib").sha256).hexdigest()
        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "different content"):
            restarted._handle_message(changed, client_ip="127.0.0.1")

    def test_scan_binds_each_probe_and_excludes_every_local_ipv4_address(self):
        interfaces = [
            {
                "name": "en0", "scope": "local", "scanEligible": True,
                "mac": None, "addresses": ["192.168.1.1"],
                "networks": ["192.168.1.0/29"],
            },
            {
                "name": "en5", "scope": "local", "scanEligible": True,
                "mac": "02:00:00:00:00:05", "addresses": ["192.168.1.2"],
                "networks": ["192.168.1.0/29"],
            },
        ]
        targets, limited = network_fabric._scan_targets(interfaces)
        self.assertFalse(limited)
        self.assertFalse({"192.168.1.1", "192.168.1.2"}.intersection(row[0] for row in targets))
        self.assertEqual(
            {(row[0], row[1], row[3]) for row in targets if row[0] == "192.168.1.3"},
            {
                ("192.168.1.3", "en0", "192.168.1.1"),
                ("192.168.1.3", "en5", "192.168.1.2"),
            },
        )

        calls = []

        def ping(ip, interface, source):
            calls.append((ip, interface, source))
            return 1.0 if ip == "192.168.1.3" else None

        service = self._service(lambda: interfaces)
        service.ping_probe = ping
        service.active = True
        service._scan_once(deep=True)
        self.assertFalse({"192.168.1.1", "192.168.1.2"}.intersection(row[0] for row in calls))
        matching = [
            device for device in service.devices.values()
            if any(row["address"] == "192.168.1.3" for row in service._address_records(device))
        ]
        self.assertEqual(len(matching), 2)
        self.assertEqual({device["interface"] for device in matching}, {"en0", "en5"})

    def test_ping_permission_truth_and_recovery_are_source_specific(self):
        interfaces = lambda: [{
            "name": "en1", "scope": "local", "scanEligible": True,
            "mac": "02:00:00:00:00:01", "addresses": ["192.168.4.1"],
            "networks": ["192.168.4.0/30"],
        }]
        service = self._service(interfaces)
        service.active = True
        service._set_source_error("retained-fixture", "discovery_unavailable")
        service.ping_probe = lambda _ip, _interface, _source: (_ for _ in ()).throw(PermissionError())
        service._scan_once(deep=True)
        self.assertIn(("icmp", "permission_denied"), {(row["source"], row["code"]) for row in service.errors})

        service._set_source_error("discovery", "discovery_unavailable")
        service.ping_probe = lambda _ip, _interface, _source: None
        service._scan_once(deep=True)
        errors = {(row["source"], row["code"]) for row in service.errors}
        self.assertNotIn(("icmp", "permission_denied"), errors)
        self.assertNotIn(("discovery", "discovery_unavailable"), errors)
        self.assertIn(("retained-fixture", "discovery_unavailable"), errors)

        denied = subprocess.CompletedProcess(
            [network_fabric.PING_PATH], 2, "", "ping: sendto: Operation not permitted"
        )
        with mock.patch.object(network_fabric, "_run_command", return_value=denied):
            with self.assertRaisesRegex(network_fabric.NetworkFabricError, "Local Network access"):
                network_fabric._default_ping("192.168.4.2", "en1", "192.168.4.1")

    def test_preset_stop_starts_no_socket_process_or_probe(self):
        stopped = threading.Event()
        stopped.set()
        with mock.patch.object(network_fabric.socket, "socket") as socket_factory:
            self.assertEqual(
                network_fabric._default_ssdp(stopped, interfaces=fixture_interfaces()),
                [],
            )
        socket_factory.assert_not_called()

        with mock.patch.object(network_fabric, "_native_dns_sd_browse") as browse:
            with mock.patch.object(network_fabric, "_capture_process") as capture:
                self.assertEqual(
                    network_fabric._default_mdns(stopped, interfaces=fixture_interfaces()),
                    [],
                )
        browse.assert_not_called()
        capture.assert_not_called()

        providers = {
            "interfaces": mock.Mock(return_value=fixture_interfaces()),
            "mdns": mock.Mock(return_value=[]),
            "ssdp": mock.Mock(return_value=[]),
            "connections": mock.Mock(return_value=[]),
            "ping": mock.Mock(return_value=None),
        }
        service = network_fabric.NetworkFabricService(
            clock=self.clock,
            interface_provider=providers["interfaces"],
            command_runner=FakeRunner(),
            ping_probe=providers["ping"],
            mdns_probe=providers["mdns"],
            ssdp_probe=providers["ssdp"],
            connection_provider=providers["connections"],
            link_manager=self.link,
        )
        service.active = True
        service.stop_event.set()
        service._scan_once(deep=True)
        for provider in providers.values():
            provider.assert_not_called()

        stop_between_sources = threading.Event()

        def interfaces_then_stop():
            stop_between_sources.set()
            return fixture_interfaces()

        later_runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        later_mdns = mock.Mock(return_value=[])
        later_ssdp = mock.Mock(return_value=[])
        later_connections = mock.Mock(return_value=[])
        service = network_fabric.NetworkFabricService(
            clock=self.clock,
            interface_provider=interfaces_then_stop,
            command_runner=later_runner,
            ping_probe=mock.Mock(return_value=None),
            mdns_probe=later_mdns,
            ssdp_probe=later_ssdp,
            connection_provider=later_connections,
            link_manager=self.link,
        )
        service.active = True
        service.stop_event = stop_between_sources
        service._scan_once(deep=True)
        later_runner.assert_not_called()
        later_mdns.assert_not_called()
        later_ssdp.assert_not_called()
        later_connections.assert_not_called()
        self.assertIn("socket.IP_MULTICAST_TTL, 1", __import__("inspect").getsource(network_fabric._default_ssdp))

    def test_conflicting_stable_ids_never_merge_and_missing_mac_never_filters(self):
        service = self._service()
        own_names = {"shared-host.local"}
        service._apply_observations([{
            "source": "bonjour", "ip": "192.168.1.44", "interface": "en1",
            "hostname": "shared-host.local", "mac": None,
        }], self.clock(), set(), {None}, own_names)
        self.assertEqual(len(service.devices), 1)
        self.assertTrue(any("shared-host.local" in device["names"] for device in service.devices.values()))

        service._apply_observations([
            {
                "source": "arp", "ip": "192.168.1.44", "interface": "en1",
                "mac": "02:00:00:00:00:01",
            },
            {
                "source": "arp", "ip": "192.168.1.44", "interface": "en1",
                "mac": "02:00:00:00:00:02",
            },
        ], self.clock(), set(), {None}, own_names)
        self.assertEqual(len(service.devices), 2)
        self.assertTrue(any("shared-host.local" in device["names"] for device in service.devices.values()))

        peer_a, peer_b = "a" * 32, "b" * 32
        service.devices.clear()
        service.identity_map.clear()
        service._apply_observations([
            {
                "source": "bonjour", "ip": "192.168.1.55", "interface": "en1",
                "mac": "02:00:00:00:00:03",
                "service": {
                    "type": network_fabric.KE_LINK_TYPE,
                    "properties": {"id": peer_a, "fp": "c" * 64, "proto": "1"},
                },
            },
            {
                "source": "bonjour", "ip": "192.168.1.55", "interface": "en1",
                "mac": "02:00:00:00:00:04",
                "service": {
                    "type": network_fabric.KE_LINK_TYPE,
                    "properties": {"id": peer_b, "fp": "d" * 64, "proto": "1"},
                },
            },
        ], self.clock(), set(), set(), set())
        self.assertEqual(len(service.devices), 2)
        self.assertEqual(
            {device.get("linkPeerId") for device in service.devices.values()},
            {peer_a, peer_b},
        )

    def test_actions_and_ke_transports_bind_interface_or_fail_closed(self):
        interfaces = [
            {
                "name": "en0", "scope": "local", "scanEligible": True,
                "addresses": ["192.168.8.1"], "networks": ["192.168.8.0/24"],
            },
            {
                "name": "en5", "scope": "local", "scanEligible": True,
                "addresses": ["192.168.8.2"], "networks": ["192.168.8.0/24"],
            },
        ]
        service = self._service(lambda: interfaces)
        service.interfaces = interfaces
        peer_id, fingerprint = "a" * 32, "b" * 64
        now = self.clock()
        item = {
            "id": "device-ambiguous", "firstSeen": now, "lastSeen": now, "lastDirect": now,
            "addresses": {
                "192.168.8.44|en0": {"address": "192.168.8.44", "interface": "en0", "lastSeen": now},
                "192.168.8.44|en5": {"address": "192.168.8.44", "interface": "en5", "lastSeen": now},
            },
            "names": {}, "sources": {"bonjour": now}, "mac": "02:00:00:00:00:44",
            "interface": "en0", "latencyMs": None, "linkPeerId": peer_id,
            "linkFingerprint": fingerprint,
            "services": {
                "service-link": {
                    "id": "service-link", "type": network_fabric.KE_LINK_TYPE,
                    "host": "192.168.8.44", "port": 4555, "interface": "en0",
                    "properties": {"id": peer_id, "fp": fingerprint, "proto": "1"},
                    "lastSeen": now, "url": None, "scheme": None, "label": "KE Link", "name": "peer",
                },
                "service-http": {
                    "id": "service-http", "type": "_http._tcp.local.",
                    "host": "192.168.8.44", "port": 80, "interface": "en0",
                    "properties": {}, "lastSeen": now,
                    "url": "http://192.168.8.44/", "scheme": "http", "label": "Web", "name": "web",
                },
            },
        }
        service.devices[item["id"]] = item
        service.link.peers[peer_id] = {
            "id": peer_id, "name": "peer", "fingerprint": fingerprint,
            "secret": base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
            "pairedAt": network_fabric._utc_iso(now),
        }
        for action, service_id in (("ping", None), ("wake", None), ("open-service", "service-http")):
            with self.assertRaises(network_fabric.NetworkFabricError):
                service.perform_action(item["id"], action, service_id)

        with mock.patch.object(service.link, "pair", return_value={"ok": True, "peerId": peer_id}) as pair:
            service.pair_device(item["id"], "AAAA-BBBB-CCCC-DDDD")
        self.assertEqual(pair.call_args.args[-1], "en0")
        self.assertEqual(pair.call_args.kwargs["expected_peer_id"], peer_id)

        with mock.patch.object(service.link, "verify_peer", return_value={"ok": True, "state": "ready"}) as verify:
            service.verify_link_session(item["id"])
        self.assertEqual(verify.call_args.args[-1], "en0")

        with mock.patch.object(service.link, "session_status", return_value={"ready": True}):
            with mock.patch.object(service.link, "send", return_value={"ok": True, "state": "delivered"}) as send:
                service.send_message(item["id"], "bounded text", "c" * 32)
        send.assert_called_once_with(peer_id, "bounded text", "c" * 32)

        item["addresses"]["192.168.8.45|en0"] = {
            "address": "192.168.8.45", "interface": "en0", "lastSeen": now,
        }
        item["services"]["service-link"]["observedAddress"] = "192.168.8.44"
        item["services"]["service-link-2"] = {
            **item["services"]["service-link"],
            "id": "service-link-2",
            "observedAddress": "192.168.8.45",
        }
        with mock.patch.object(service.link, "pair") as pair:
            with self.assertRaisesRegex(network_fabric.NetworkFabricError, "not advertising"):
                service.pair_device(item["id"], "AAAA-BBBB-CCCC-DDDD")
        pair.assert_not_called()

    def test_unsigned_tampered_and_wrong_secret_ack_ledgers_fail_closed(self):
        peer_id = "d" * 32
        client_id = "e" * 32
        response = {
            "ok": True, "state": "delivered", "clientMessageId": client_id,
            "messageId": "f" * 24, "ack": "1" * 64,
        }
        base_entry = {"bodyDigest": "2" * 64, "observedAt": self.clock(), "response": response}

        for variant in ("unsigned", "tampered", "wrong-secret"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(dir=self.temp.name) as root:
                root = os.path.realpath(root)
                manager = network_fabric.KELinkManager(
                    root, clock=self.clock, advertise=False,
                    listener_addresses=["127.0.0.1"], allowed_networks=["127.0.0.0/8"],
                    allow_loopback=True,
                )
                secret_text = base64.urlsafe_b64encode(b"s" * 32).decode("ascii")
                manager.peers[peer_id] = {
                    "id": peer_id, "name": "peer", "fingerprint": "3" * 64,
                    "secret": secret_text, "pairedAt": network_fabric._utc_iso(self.clock()),
                }
                manager._save_peers()
                key = f"{peer_id}:{client_id}"
                entry = dict(base_entry)
                if variant != "unsigned":
                    signing_secret = b"x" * 32 if variant == "wrong-secret" else b"s" * 32
                    entry["recordMac"] = __import__("hmac").new(
                        signing_secret,
                        b"dedupe-ledger|" + network_fabric._canonical_json({"key": key, **base_entry}),
                        __import__("hashlib").sha256,
                    ).hexdigest()
                    if variant == "tampered":
                        entry["bodyDigest"] = "4" * 64
                path = Path(root, "message-acks.json")
                path.write_bytes(network_fabric._canonical_json({
                    "schemaVersion": network_fabric.ACK_LEDGER_SCHEMA,
                    "entries": {key: entry},
                }) + b"\n")
                path.chmod(0o600)
                restarted = network_fabric.KELinkManager(
                    root, clock=self.clock, advertise=False,
                    listener_addresses=["127.0.0.1"], allowed_networks=["127.0.0.0/8"],
                    allow_loopback=True,
                )
                self.assertFalse(restarted.storage_valid)
                self.assertFalse(restarted.received_acks)
                self.assertEqual(restarted.error["code"], "peer_store_insecure")

    def test_advertiser_death_is_truthful_and_reenable_recovers_on_exact_interface(self):
        self.link.advertise = True
        self.link.identity = {"id": "5" * 32, "fingerprint": "6" * 64}
        self.link.listener_interface = "lo0"
        self.link.server = SimpleNamespace(server_port=4555)
        self.link.advertiser = SimpleNamespace(poll=lambda: 1)
        with mock.patch.object(network_fabric.os.path, "isfile", return_value=False):
            dead = self.link.status()
        self.assertFalse(dead["advertising"])
        self.assertEqual(dead["errors"][0]["code"], "bonjour_advertisement_unavailable")

        live = SimpleNamespace(poll=lambda: None)
        with mock.patch.object(network_fabric.os.path, "isfile", return_value=True):
            with mock.patch.object(network_fabric.subprocess, "Popen", return_value=live) as start:
                recovered = self.link.enable()
        self.assertTrue(recovered["advertising"])
        self.assertFalse(recovered["errors"])
        args = start.call_args.args[0]
        self.assertEqual(args[args.index("-i") + 1], "lo0")
        self.assertEqual(args[args.index("-R") + 1], self.link.name)

    def test_blocked_discovery_generation_cannot_overlap_a_restart(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def blocked_interfaces():
            calls.append(threading.current_thread().name)
            if len(calls) == 1:
                entered.set()
                release.wait(timeout=2)
            return []

        service = self._service(blocked_interfaces)
        service.start_discovery()
        self.assertTrue(entered.wait(timeout=1))
        original = service.thread
        with mock.patch.object(network_fabric, "DISCOVERY_STOP_TIMEOUT_SECONDS", 0.01):
            stopped = service.stop_discovery()
        self.assertFalse(stopped["active"])
        self.assertIs(service.thread, original)
        self.assertTrue(original.is_alive())
        with self.assertRaisesRegex(network_fabric.NetworkFabricError, "temporarily unavailable"):
            service.start_discovery()
        self.assertEqual(len(calls), 1)
        release.set()
        original.join(timeout=1)
        self.assertFalse(original.is_alive())
        service.start_discovery()
        replacement = service.thread
        self.assertIsNot(replacement, original)
        service.stop_discovery()
        self.assertFalse(replacement.is_alive())

    def test_pairing_code_is_single_acceptance_and_disable_race_returns_no_code(self):
        self.link.server = SimpleNamespace(server_port=4555)
        self.link.identity = {"id": "1" * 32, "fingerprint": "2" * 64}
        self.link.begin_pairing()
        pairing = dict(self.link.pairing)
        barrier = threading.Barrier(3)
        outcomes = []

        def attempt(sender_digit):
            sender_id = sender_digit * 32
            nonce = ("a" if sender_digit == "3" else "b") * 32
            signed = (
                f"pair|{self.link.identity['fingerprint']}|{'4' * 64}|{sender_id}|{nonce}"
            ).encode("utf-8")
            payload = {
                "version": 1,
                "codeId": pairing["codeId"],
                "nonce": nonce,
                "senderId": sender_id,
                "senderName": f"Peer {sender_digit}",
                "senderFingerprint": "4" * 64,
                "proof": hmac.new(pairing["token"].encode("ascii"), signed, hashlib.sha256).hexdigest(),
            }
            barrier.wait()
            try:
                outcomes.append(("ok", self.link._handle_pair(payload)["ok"]))
            except network_fabric.NetworkFabricError as error:
                outcomes.append(("error", error.code))

        workers = [threading.Thread(target=attempt, args=(digit,)) for digit in ("3", "5")]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(timeout=1)
        self.assertEqual(sorted(outcomes), [("error", "pairing_invalid"), ("ok", True)])
        self.assertEqual(len(self.link.peers), 1)
        self.assertIsNone(self.link.pairing)

        started = threading.Event()
        unblock = threading.Event()
        result = []

        def delayed_bytes(size):
            started.set()
            unblock.wait(timeout=1)
            return b"z" * size

        def begin():
            try:
                result.append(self.link.begin_pairing())
            except network_fabric.NetworkFabricError as error:
                result.append(error.code)

        with mock.patch.object(network_fabric.secrets, "token_bytes", side_effect=delayed_bytes):
            worker = threading.Thread(target=begin)
            worker.start()
            self.assertTrue(started.wait(timeout=1))
            with self.link.lock:
                self.link.server = None
                self.link.pairing = None
            unblock.set()
            worker.join(timeout=1)
        self.assertEqual(result, ["ke_link_disabled"])
        self.assertIsNone(self.link.pairing)

    def test_advertised_peer_identity_substitution_fails_before_persistence(self):
        expected_peer = "6" * 32
        substituted_peer = "7" * 32
        fingerprint = "8" * 64
        token = "A" * 26
        secret = base64.urlsafe_b64encode(b"s" * 32).decode("ascii")
        self.link.server = SimpleNamespace(server_port=4555)
        self.link.identity = {"id": "9" * 32, "fingerprint": "a" * 64}

        def response(_host, _port, path, payload, _fingerprint, **_binding):
            nonce = payload["nonce"]
            if path.endswith("challenge"):
                proof = hmac.new(
                    token.encode("ascii"),
                    f"challenge|{fingerprint}|{nonce}".encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                return {"ok": True, "proof": proof}
            proof = hmac.new(
                token.encode("ascii"),
                f"accepted|{substituted_peer}|{self.link.identity['id']}|{nonce}|{secret}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            return {
                "ok": True,
                "peerId": substituted_peer,
                "peerName": "Substituted peer",
                "secret": secret,
                "proof": proof,
            }

        with mock.patch.object(self.link, "_request", side_effect=response):
            with self.assertRaisesRegex(network_fabric.NetworkFabricError, "acceptance"):
                self.link.pair(
                    "127.0.0.1",
                    4555,
                    fingerprint,
                    token,
                    "lo0",
                    expected_peer_id=expected_peer,
                )
        self.assertFalse(self.link.peers)
        self.assertFalse(Path(self.temp.name, "peers.json").exists())

    def test_transport_and_wake_bind_exact_interface_without_socket_io(self):
        traces = []

        class FakeSocket:
            family = None

            def __init__(self, family):
                self.family = family

            def setsockopt(self, level, option, value):
                traces.append(("setsockopt", level, option, value))

            def settimeout(self, value):
                traces.append(("timeout", value))

            def bind(self, value):
                traces.append(("bind", value))

            def connect(self, value):
                traces.append(("connect", value))

            def sendto(self, _payload, value):
                traces.append(("sendto", value))

            def close(self):
                traces.append(("close",))

        sockets = []

        def factory(family, _kind, *_args):
            sock = FakeSocket(family)
            sockets.append(sock)
            return sock

        with mock.patch.object(network_fabric.socket, "if_nametoindex", return_value=7):
            with mock.patch.object(network_fabric.socket, "socket", side_effect=factory):
                stream = network_fabric._bound_stream_socket(
                    "fe80::2%en0", 4555, "en0", "fe80::1%en0", 1.0,
                )
                stream.close()
                network_fabric.NetworkFabricService._send_wol(
                    "02:00:00:00:00:11", "en0", "192.168.1.10", "192.168.1.255",
                )
        self.assertIn(
            ("setsockopt", socket.IPPROTO_IPV6, network_fabric.DARWIN_IPV6_BOUND_IF, 7),
            traces,
        )
        self.assertIn(("bind", ("fe80::1", 0, 0, 7)), traces)
        self.assertIn(("connect", ("fe80::2", 4555, 0, 7)), traces)
        self.assertIn(
            ("setsockopt", socket.IPPROTO_IP, network_fabric.DARWIN_IP_BOUND_IF, 7),
            traces,
        )
        self.assertIn(("sendto", ("192.168.1.255", 9)), traces)

        certificate = b"fixture-certificate"
        raw = SimpleNamespace(
            getpeercert=lambda binary_form=False: certificate if binary_form else {},
            close=lambda: None,
        )
        context = SimpleNamespace(
            check_hostname=True,
            verify_mode=None,
            wrap_socket=lambda sock, server_hostname=None: sock,
        )

        class FakeResponse:
            status = 200

            @staticmethod
            def read(_limit):
                return b'{"ok":true}'

        class FakeConnection:
            def __init__(self):
                self.sock = None

            def request(self, *_args, **_kwargs):
                return None

            def getresponse(self):
                return FakeResponse()

            def close(self):
                return None

        with mock.patch.object(network_fabric.ssl, "create_default_context", return_value=context):
            with mock.patch.object(network_fabric.http.client, "HTTPSConnection", return_value=FakeConnection()):
                with mock.patch.object(network_fabric, "_bound_stream_socket", return_value=raw) as bound:
                    result = self.link._request(
                        "fe80::2%en0",
                        4555,
                        "/v1/health",
                        {"version": 1},
                        hashlib.sha256(certificate).hexdigest(),
                        interface="en0",
                        source_address="fe80::1%en0",
                    )
        self.assertTrue(result["ok"])
        self.assertEqual(
            bound.call_args.args[:4],
            ("fe80::2%en0", 4555, "en0", "fe80::1%en0"),
        )

    def test_dual_stack_ke_advertisement_is_one_pairable_service(self):
        interfaces = [{
            "name": "en0",
            "scope": "local",
            "scanEligible": True,
            "addresses": ["192.168.1.10", "fd00::10"],
            "networks": ["192.168.1.0/24", "fd00::/64"],
        }]
        service = self._service(lambda: interfaces)
        service.interfaces = interfaces
        peer_id = "b" * 32
        advertised = {
            "type": network_fabric.KE_LINK_TYPE,
            "name": "Dual-stack peer",
            "host": "dual-peer.local",
            "port": 4555,
            "interface": "en0",
            "properties": {"id": peer_id, "fp": "c" * 64, "proto": "1"},
        }
        service._apply_observations([
            {"source": "bonjour", "direct": True, "ip": "192.168.1.44", "interface": "en0", "service": advertised},
            {"source": "bonjour", "direct": True, "ip": "fd00::44", "interface": "en0", "service": advertised},
        ], self.clock(), set(), set(), set())
        self.assertEqual(len(service.devices), 1)
        device = next(iter(service.devices.values()))
        self.assertEqual(len(device["services"]), 1)
        link_service = service._ke_service(device)
        self.assertIsNotNone(link_service)
        self.assertEqual(link_service["endpoints"], ["192.168.1.44", "fd00::44"])
        self.assertEqual(service._service_endpoint(device, link_service), "192.168.1.44")
        self.assertIn("pair", service._public_device(device, self.clock())["capabilities"])

    def test_all_interface_self_identity_and_tunnel_classifier_fail_closed(self):
        interfaces = lambda: [
            {
                "name": "en0", "scope": "local", "scanEligible": True,
                "mac": "02:00:00:00:00:01", "addresses": ["10.22.0.1"],
                "networks": ["10.22.0.0/24"],
            },
            {
                "name": "utun4", "scope": "tunnel", "scanEligible": False,
                "mac": None, "addresses": ["10.22.0.2"], "networks": ["10.22.0.0/24"],
            },
        ]
        service = self._service(interfaces)
        service.connection_provider = lambda: [{"ip": "10.22.0.2"}]
        service.active = True
        service._scan_once(deep=False)
        self.assertFalse(service.devices)
        self.assertEqual(service.excluded_interfaces, [{"name": "utun4", "scope": "tunnel"}])

        af_link = getattr(network_fabric.psutil, "AF_LINK")
        rows = {
            "ppp0": [
                SimpleNamespace(family=socket.AF_INET, address="10.9.0.2", netmask="255.255.255.0"),
            ],
            "en0": [
                SimpleNamespace(family=socket.AF_INET, address="192.168.1.10", netmask="255.255.255.0"),
                SimpleNamespace(family=af_link, address="02:00:00:00:00:02", netmask=None),
            ],
        }
        stats = {name: SimpleNamespace(isup=True) for name in rows}
        with mock.patch.object(network_fabric.psutil, "net_if_addrs", return_value=rows):
            with mock.patch.object(network_fabric.psutil, "net_if_stats", return_value=stats):
                snapshot = {row["name"]: row for row in network_fabric._interface_snapshot()}
        self.assertEqual(snapshot["ppp0"]["scope"], "tunnel")
        self.assertFalse(snapshot["ppp0"]["scanEligible"])
        self.assertFalse(network_fabric._discovery_interface_allowed(snapshot["ppp0"]))
        self.assertTrue(network_fabric._discovery_interface_allowed(snapshot["en0"]))
        for name in (
            "utun0", "ppp0", "ipsec0", "tun0", "tap0", "wg0",
            "wireguard0", "tailscale0", "gif0", "stf0",
        ):
            self.assertEqual(network_fabric._interface_scope(name), "tunnel", name)
        for name in ("awdl0", "llw0", "p2p0"):
            self.assertEqual(network_fabric._interface_scope(name), "peer-to-peer", name)

    def test_bonjour_browse_resolve_and_address_indexes_must_match(self):
        peer_id = "d" * 32
        fingerprint = "e" * 64
        native_row = network_fabric._dns_sd_native_browse_row(
            network_fabric.DNS_SERVICE_FLAGS_ADD,
            7,
            b"Exact Peer",
            b"_ke-link._tcp.",
            b"local.",
        )

        def native_browse(type_name, _index, _duration, _stop=None):
            return [native_row] if type_name == "_ke-link._tcp" else []

        def native_resolve(_instance, type_name, _index, _duration, _stop=None):
            if type_name != "_ke-link._tcp":
                return None
            return {
                "host": "peer.local",
                "port": 4555,
                "interfaceIndex": 7,
                "properties": {"id": peer_id, "fp": fingerprint, "proto": "1"},
            }

        def capture(args, _duration, _stop=None):
            if "-G" in args:
                return "12:00:00.000 Add 2 7 peer.local. 192.168.1.44 120\n"
            return ""

        with mock.patch.object(network_fabric.os.path, "isfile", return_value=True):
            with mock.patch.object(network_fabric, "_native_dns_sd_browse", side_effect=native_browse):
                with mock.patch.object(network_fabric, "_native_dns_sd_resolve", side_effect=native_resolve):
                    with mock.patch.object(network_fabric.socket, "if_nametoindex", return_value=7):
                        with mock.patch.object(network_fabric, "_capture_process", side_effect=capture):
                            with mock.patch.object(network_fabric.socket, "if_indextoname", side_effect=lambda index: "en0" if index == 7 else "en5"):
                                rows = network_fabric._default_mdns(interfaces=[{
                                    "name": "en0", "scope": "local", "scanEligible": True,
                                    "addresses": ["192.168.1.10"], "networks": ["192.168.1.0/24"],
                                }])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["interface"], "en0")
        self.assertEqual(rows[0]["addresses"], ["192.168.1.44"])

        def mismatch(args, duration, stop=None):
            value = capture(args, duration, stop)
            return value.replace("Add 2 7 peer.local.", "Add 2 8 peer.local.") if "-G" in args else value

        with mock.patch.object(network_fabric.os.path, "isfile", return_value=True):
            with mock.patch.object(network_fabric, "_native_dns_sd_browse", side_effect=native_browse):
                with mock.patch.object(network_fabric, "_native_dns_sd_resolve", side_effect=native_resolve):
                    with mock.patch.object(network_fabric.socket, "if_nametoindex", return_value=7):
                        with mock.patch.object(network_fabric, "_capture_process", side_effect=mismatch):
                            with mock.patch.object(network_fabric.socket, "if_indextoname", side_effect=lambda index: "en0" if index == 7 else "en5"):
                                rejected = network_fabric._default_mdns(interfaces=[{
                                    "name": "en0", "scope": "local", "scanEligible": True,
                                    "addresses": ["192.168.1.10"], "networks": ["192.168.1.0/24"],
                                }])
        self.assertEqual(rejected, [])

    def test_immediate_advertiser_death_is_degraded_and_backed_off(self):
        self.link.advertise = True
        self.link.identity = {"id": "f" * 32, "fingerprint": "1" * 64}
        self.link.listener_interface = "lo0"
        self.link.server = SimpleNamespace(server_port=4555)
        dead = SimpleNamespace(poll=lambda: 1)
        with mock.patch.object(network_fabric.os.path, "isfile", return_value=True):
            with mock.patch.object(network_fabric.subprocess, "Popen", return_value=dead) as start:
                self.link._start_advertiser(
                    self.link.identity, "lo0", 4555, force=True,
                )
                first = self.link.status()
        self.assertEqual(start.call_count, 1)
        self.assertTrue(first["enabled"])
        self.assertFalse(first["advertising"])
        self.assertEqual(first["errors"][0]["code"], "bonjour_advertisement_unavailable")

        live = SimpleNamespace(poll=lambda: None)
        self.clock.advance(network_fabric.ADVERTISER_RETRY_SECONDS + 0.1)
        with mock.patch.object(network_fabric.os.path, "isfile", return_value=True):
            with mock.patch.object(network_fabric.subprocess, "Popen", return_value=live) as restart:
                recovered = self.link.status()
        self.assertEqual(restart.call_count, 1)
        self.assertTrue(recovered["advertising"])
        self.assertFalse(recovered["errors"])


if __name__ == "__main__":
    unittest.main()
