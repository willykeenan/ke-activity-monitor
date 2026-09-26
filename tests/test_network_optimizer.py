#!/usr/bin/env python3
import sys
import threading
import types
import unittest
from unittest import mock

import network_optimizer


def wifi_probe(
    *,
    interface="en0",
    channel=1,
    band="2.4 GHz",
    width=20,
    rssi=-55,
    noise=-92,
    security="WPA3 Personal",
    nearby=None,
    nearby_measured=True,
):
    return {
        "kind": "wifi",
        "current": {
            "name": interface,
            "connected": True,
            "channel": {"number": channel, "band": band, "widthMHz": width},
            "rssiDbm": rssi,
            "noiseDbm": noise,
            "snrDb": rssi - noise,
            "transmitRateMbps": 866.7,
            "security": security,
        },
        "nearby": list(nearby or []),
        "nearbyMeasured": nearby_measured,
        "supportedChannels": [
            {"number": 1, "band": "2.4 GHz", "widthMHz": 20},
            {"number": 6, "band": "2.4 GHz", "widthMHz": 20},
            {"number": 11, "band": "2.4 GHz", "widthMHz": 20},
            {"number": 36, "band": "5 GHz", "widthMHz": 80},
            {"number": 44, "band": "5 GHz", "widthMHz": 80},
        ],
    }


def nearby(channel, rssi, band="2.4 GHz"):
    return {
        "channel": {"number": channel, "band": band, "widthMHz": 20},
        "rssiDbm": rssi,
        "noiseDbm": -95,
    }


class InternetOptimizerProjectionTests(unittest.TestCase):
    def test_crowded_24ghz_prefers_auto_and_truthfully_names_manual_fallback(self):
        result = network_optimizer.analyze_probe(
            wifi_probe(
                channel=1,
                width=40,
                rssi=-72,
                noise=-90,
                nearby=[nearby(1, -40), nearby(1, -52), nearby(6, -82)],
            ),
            {"interface": "en0", "adminUrl": "http://192.168.1.1/"},
            "2026-08-24T18:00:00Z",
        )
        recommendation = result["interference"]["recommendation"]
        self.assertEqual(recommendation["mode"], "router-auto")
        self.assertEqual(recommendation["suggestedChannel"], 11)
        self.assertFalse(recommendation["canApply"])
        self.assertEqual(recommendation["status"], "router-authorization-required")
        self.assertIn("Auto is preferred", recommendation["reason"])
        self.assertTrue(result["router"]["adminAvailable"])
        self.assertFalse(result["router"]["canApplyChannel"])
        self.assertIn("wide-24ghz", {item["id"] for item in result["findings"]})
        self.assertIn("crowded-channel", {item["id"] for item in result["findings"]})

    def test_strong_5ghz_path_does_not_invent_a_channel_change(self):
        result = network_optimizer.analyze_probe(
            wifi_probe(
                channel=36,
                band="5 GHz",
                width=80,
                nearby=[nearby(36, -75, "5 GHz"), nearby(44, -80, "5 GHz")],
            ),
            {},
        )
        self.assertEqual(result["quality"]["label"], "Strong")
        self.assertIsNone(result["interference"]["recommendation"]["suggestedChannel"])
        self.assertIn("Auto channel", result["interference"]["recommendation"]["reason"])
        self.assertEqual(result["findings"][0]["id"], "radio-healthy")

    def test_weak_signal_and_low_snr_are_separate_evidence(self):
        result = network_optimizer.analyze_probe(
            wifi_probe(rssi=-78, noise=-88, nearby=[nearby(1, -60)]),
            {},
        )
        ids = {item["id"] for item in result["findings"]}
        self.assertIn("weak-signal", ids)
        self.assertIn("low-snr", ids)
        self.assertLess(result["quality"]["healthScore"], 50)

    def test_weak_security_is_not_described_as_a_speed_setting(self):
        result = network_optimizer.analyze_probe(wifi_probe(security="WEP"), {})
        finding = next(item for item in result["findings"] if item["id"] == "weak-security")
        self.assertIn("outdated", finding["title"].lower())
        self.assertIn("reliability", finding["detail"].lower())

    def test_no_wifi_returns_attention_without_fabricated_measurements(self):
        result = network_optimizer.analyze_probe(
            {"kind": "none"},
            {"interface": "en0", "adminUrl": "http://192.168.1.1/"},
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "attention")
        self.assertIsNone(result["quality"]["healthScore"])
        self.assertFalse(result["interference"]["measured"])
        self.assertEqual(result["findings"][0]["id"], "wifi-not-active")
        self.assertFalse(result["router"]["adminAvailable"])
        router_action = next(item for item in result["actions"] if item["id"] == "open-router-settings")
        self.assertFalse(router_action["available"])

    def test_successful_empty_scan_is_measured_as_zero_observations(self):
        result = network_optimizer.analyze_probe(wifi_probe(nearby=[], nearby_measured=True), {})
        self.assertTrue(result["interference"]["measured"])
        self.assertEqual(result["interference"]["nearbyObservationCount"], 0)
        self.assertNotIn("unavailable", result["interference"]["recommendation"]["reason"].lower())

    def test_privacy_projection_proves_no_identifiers_persistence_or_change(self):
        result = network_optimizer.analyze_probe(wifi_probe(), {})
        self.assertFalse(result["privacy"]["nearbyNetworkNamesRead"])
        self.assertFalse(result["privacy"]["nearbyNetworkIdentifiersRead"])
        self.assertFalse(result["privacy"]["routerCredentialsAccessed"])
        self.assertFalse(result["privacy"]["settingsChanged"])
        self.assertFalse(result["privacy"]["persisted"])
        serialized = str(result).lower()
        self.assertNotIn("ssid", serialized)
        self.assertNotIn("bssid", serialized)

    def test_only_private_rfc1918_gateways_become_admin_urls(self):
        self.assertEqual(network_optimizer._private_router_url("192.168.50.1"), "http://192.168.50.1/")
        self.assertEqual(network_optimizer._private_router_url("10.0.0.1"), "http://10.0.0.1/")
        self.assertIsNone(network_optimizer._private_router_url("8.8.8.8"))
        self.assertIsNone(network_optimizer._private_router_url("169.254.1.1"))
        self.assertIsNone(network_optimizer._private_router_url("router.example"))
        self.assertIsNone(network_optimizer._private_router_url("192.168.1.1@evil.example"))


class NetworkQualityProjectionTests(unittest.TestCase):
    def test_computer_output_converts_bytes_per_second_to_megabits(self):
        result = network_optimizer.project_network_quality(
            {
                "dl_throughput": 12_500_000,
                "ul_throughput": 2_500_000,
                "base_rtt": 14.25,
                "responsiveness": 520,
                "interface_name": "en0",
                "server_secret": "must-not-project",
            },
            observed_at="2026-08-24T18:00:00Z",
        )
        self.assertEqual(result["downloadMbps"], 100.0)
        self.assertEqual(result["uploadMbps"], 20.0)
        self.assertEqual(result["idleLatencyMs"], 14.25)
        self.assertEqual(result["responsivenessRpm"], 520)
        self.assertTrue(result["usesInternetData"])
        self.assertFalse(result["serverIdentityVerificationDisabled"])
        self.assertNotIn("server_secret", result)

    def test_malformed_numbers_remain_unavailable(self):
        result = network_optimizer.project_network_quality(
            {"dl_throughput": "nan", "base_rtt": -1, "interface_name": "../../bad"}
        )
        self.assertIsNone(result["downloadMbps"])
        self.assertIsNone(result["idleLatencyMs"])
        self.assertIsNone(result["interface"])

    def test_runner_binds_interface_and_never_disables_tls_verification(self):
        completed = types.SimpleNamespace(
            returncode=0,
            stdout='{"dl_throughput":125000,"interface_name":"en0"}',
            stderr="",
        )
        with mock.patch.object(network_optimizer.subprocess, "run", return_value=completed) as run:
            result = network_optimizer.NetworkQualityRunner()("en0")
        command = run.call_args.args[0]
        self.assertEqual(command, [network_optimizer.NETWORK_QUALITY_PATH, "-I", "en0", "-c"])
        self.assertNotIn("-k", command)
        self.assertEqual(result["downloadMbps"], 1.0)

    def test_runner_rejects_a_result_reported_on_another_interface(self):
        completed = types.SimpleNamespace(
            returncode=0,
            stdout='{"dl_throughput":125000,"interface_name":"en7"}',
            stderr="",
        )
        with mock.patch.object(network_optimizer.subprocess, "run", return_value=completed):
            with self.assertRaises(network_optimizer.InternetOptimizerError) as raised:
                network_optimizer.NetworkQualityRunner()("en0")
        self.assertEqual(raised.exception.code, "discovery_unavailable")

    def test_runner_projects_nonzero_and_oversize_failures_safely(self):
        failed = types.SimpleNamespace(returncode=1, stdout="", stderr="connection failed /private/path")
        with mock.patch.object(network_optimizer.subprocess, "run", return_value=failed):
            with self.assertRaises(network_optimizer.InternetOptimizerError) as raised:
                network_optimizer.NetworkQualityRunner()()
        self.assertEqual(raised.exception.code, "discovery_unavailable")
        oversized = types.SimpleNamespace(
            returncode=0,
            stdout="x" * (network_optimizer.MAX_NETWORK_QUALITY_BYTES + 1),
            stderr="",
        )
        with mock.patch.object(network_optimizer.subprocess, "run", return_value=oversized):
            with self.assertRaises(network_optimizer.InternetOptimizerError):
                network_optimizer.NetworkQualityRunner()()

    def test_runner_rejects_embedded_error_and_empty_success_payloads(self):
        for stdout in ('{"error_code":42,"error_domain":"private"}', '{}'):
            completed = types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")
            with self.subTest(stdout=stdout), mock.patch.object(network_optimizer.subprocess, "run", return_value=completed):
                with self.assertRaises(network_optimizer.InternetOptimizerError) as raised:
                    network_optimizer.NetworkQualityRunner()()
            self.assertEqual(raised.exception.code, "discovery_unavailable")


class InternetOptimizerServiceTests(unittest.TestCase):
    def service(self, **overrides):
        defaults = {
            "wifi_probe": lambda: wifi_probe(),
            "route_probe": lambda: {"interface": "en0", "adminUrl": "http://192.168.1.1/"},
            "quality_runner": lambda interface: network_optimizer.project_network_quality(
                {
                    "dl_throughput": 1_000_000,
                    "ul_throughput": 500_000,
                    "base_rtt": 20,
                    "responsiveness": 400,
                    "interface_name": interface,
                },
                observed_at="2026-08-24T18:00:00Z",
            ),
            "opener": lambda _target: None,
            "clock": lambda: "2026-08-24T18:00:00Z",
        }
        defaults.update(overrides)
        return network_optimizer.InternetOptimizerService(**defaults)

    def test_analysis_and_actions_are_explicit_and_in_memory(self):
        opened = []
        service = self.service(opener=opened.append)
        try:
            result = service.analyze()
            self.assertEqual(result["state"], "complete")
            action = service.perform_action("open-router-settings")
            self.assertEqual(opened, ["http://192.168.1.1/"])
            self.assertFalse(action["settingsChanged"])
        finally:
            service.shutdown()

    def test_router_handoff_is_disabled_when_default_route_uses_another_interface(self):
        result = network_optimizer.analyze_probe(
            wifi_probe(),
            {"interface": "utun4", "adminUrl": "http://192.168.1.1/"},
        )
        self.assertFalse(result["router"]["adminAvailable"])
        action = next(item for item in result["actions"] if item["id"] == "open-router-settings")
        self.assertFalse(action["available"])

    def test_two_measurements_produce_a_same_interface_before_after_delta(self):
        samples = iter(
            [
                {"dl_throughput": 1_000_000, "ul_throughput": 500_000, "base_rtt": 30, "responsiveness": 300, "interface_name": "en0"},
                {"dl_throughput": 2_000_000, "ul_throughput": 750_000, "base_rtt": 20, "responsiveness": 420, "interface_name": "en0"},
            ]
        )
        service = self.service(
            quality_runner=lambda interface: network_optimizer.project_network_quality(
                next(samples), interface=interface, observed_at="2026-08-24T18:00:00Z"
            )
        )
        try:
            service.analyze()
            first = service.measure()
            second = service.measure()
            self.assertIsNone(first["comparison"])
            self.assertEqual(second["comparison"]["downloadMbps"], 8.0)
            self.assertEqual(second["comparison"]["idleLatencyMs"], -10.0)
            self.assertEqual(second["comparison"]["responsivenessRpm"], 120.0)
        finally:
            service.shutdown()

    def test_measurement_is_discarded_if_analysis_switches_interfaces(self):
        probes = iter([wifi_probe(interface="en0"), wifi_probe(interface="en7")])
        routes = iter(
            [
                {"interface": "en0", "adminUrl": "http://192.168.1.1/"},
                {"interface": "en7", "adminUrl": "http://192.168.50.1/"},
            ]
        )
        started = threading.Event()
        release = threading.Event()
        outcome = {}

        def blocked_quality(interface):
            started.set()
            release.wait(1.0)
            return network_optimizer.project_network_quality(
                {
                    "dl_throughput": 1_000_000,
                    "ul_throughput": 500_000,
                    "base_rtt": 30,
                    "responsiveness": 300,
                    "interface_name": interface,
                },
                observed_at="2026-08-24T18:00:00Z",
            )

        service = self.service(
            wifi_probe=lambda: next(probes),
            route_probe=lambda: next(routes),
            quality_runner=blocked_quality,
        )
        try:
            first = service.analyze()

            def run_measurement():
                try:
                    outcome["result"] = service.measure()
                except Exception as error:
                    outcome["error"] = error

            worker = threading.Thread(target=run_measurement)
            worker.start()
            self.assertTrue(started.wait(1.0))
            second = service.analyze()
            release.set()
            worker.join(1.0)

            self.assertFalse(worker.is_alive())
            self.assertEqual(first["connection"]["interface"], "en0")
            self.assertEqual(second["connection"]["interface"], "en7")
            self.assertNotIn("result", outcome)
            self.assertIsInstance(outcome.get("error"), network_optimizer.InternetOptimizerError)
            self.assertEqual(outcome["error"].code, "request_superseded")
            self.assertIsNone(service._snapshot["activeTest"])
            self.assertEqual(list(service._measurements), [])

            service.quality_runner = lambda interface: network_optimizer.project_network_quality(
                {
                    "dl_throughput": 2_000_000,
                    "ul_throughput": 750_000,
                    "base_rtt": 20,
                    "responsiveness": 420,
                    "interface_name": interface,
                },
                observed_at="2026-08-24T18:01:00Z",
            )
            retry = service.measure()
            self.assertEqual(retry["interface"], "en7")
            self.assertIsNone(retry["comparison"])
            self.assertEqual(service._snapshot["activeTest"]["interface"], "en7")
        finally:
            release.set()
            service.shutdown()

    def test_older_analysis_cannot_commit_after_newer_analysis(self):
        probes = iter([wifi_probe(interface="en0"), wifi_probe(interface="en7")])
        routes = iter(
            [
                {"interface": "en0", "adminUrl": "http://192.168.1.1/"},
                {"interface": "en7", "adminUrl": "http://192.168.50.1/"},
            ]
        )
        observed_times = iter(["2026-08-24T18:00:00Z", "2026-08-24T18:01:00Z"])
        older_projected = threading.Event()
        release_older = threading.Event()
        outcome = {}
        original_analyze_probe = network_optimizer.analyze_probe

        def controlled_projection(probe, route=None, observed_at=None):
            result = original_analyze_probe(probe, route=route, observed_at=observed_at)
            if (probe.get("current") or {}).get("name") == "en0":
                older_projected.set()
                release_older.wait(1.0)
            return result

        service = self.service(
            wifi_probe=lambda: next(probes),
            route_probe=lambda: next(routes),
            clock=lambda: next(observed_times),
        )
        try:
            def run_older_analysis():
                try:
                    outcome["result"] = service.analyze()
                except Exception as error:
                    outcome["error"] = error

            with mock.patch.object(network_optimizer, "analyze_probe", side_effect=controlled_projection):
                older = threading.Thread(target=run_older_analysis)
                older.start()
                self.assertTrue(older_projected.wait(1.0))
                newer = service.analyze()
                release_older.set()
                older.join(1.0)

            self.assertFalse(older.is_alive())
            self.assertNotIn("result", outcome)
            self.assertIsInstance(outcome.get("error"), network_optimizer.InternetOptimizerError)
            self.assertEqual(outcome["error"].code, "request_superseded")
            self.assertEqual(newer["connection"]["interface"], "en7")
            self.assertEqual(service._snapshot["connection"]["interface"], "en7")
            self.assertEqual(service._snapshot["observedAt"], "2026-08-24T18:01:00Z")
            self.assertEqual(service._route["interface"], "en7")
            self.assertEqual(service._analysis_generation, 1)
        finally:
            release_older.set()
            service.shutdown()

    def test_unbound_measurements_never_claim_a_before_after_delta(self):
        before = network_optimizer.project_network_quality({"dl_throughput": 1_000_000})
        after = network_optimizer.project_network_quality({"dl_throughput": 2_000_000})
        self.assertIsNone(network_optimizer._measurement_delta(before, after))

    def test_router_action_rechecks_interface_and_rejects_a_stale_gateway(self):
        routes = iter(
            [
                {"interface": "en0", "adminUrl": "http://192.168.1.1/"},
                {"interface": "en7", "adminUrl": "http://192.168.50.1/"},
            ]
        )
        opened = []
        service = self.service(route_probe=lambda: next(routes), opener=opened.append)
        try:
            service.analyze()
            with self.assertRaises(network_optimizer.InternetOptimizerError) as raised:
                service.perform_action("open-router-settings")
            self.assertEqual(raised.exception.code, "system_settings_unavailable")
            self.assertEqual(opened, [])
        finally:
            service.shutdown()

    def test_shutdown_before_analysis_starts_zero_probes(self):
        calls = []
        service = self.service(wifi_probe=lambda: calls.append("probe"))
        service.shutdown()
        with self.assertRaises(network_optimizer.InternetOptimizerError):
            service.analyze()
        self.assertEqual(calls, [])

    def test_stalled_probe_times_out_without_starting_a_second_probe(self):
        started = threading.Event()
        release = threading.Event()
        calls = []

        def slow_probe():
            calls.append("probe")
            started.set()
            release.wait(1.0)
            return wifi_probe()

        service = self.service(wifi_probe=slow_probe, scan_timeout=0.01)
        try:
            with self.assertRaises(network_optimizer.InternetOptimizerError) as raised:
                service.analyze()
            self.assertTrue(started.is_set())
            self.assertEqual(raised.exception.code, "request_timeout")
            busy = service.analyze()
            self.assertEqual(busy["state"], "busy")
            self.assertEqual(calls, ["probe"])
        finally:
            release.set()
            service.shutdown()

    def test_unallowlisted_action_fails_before_open(self):
        opened = []
        service = self.service(opener=opened.append)
        try:
            service.analyze()
            with self.assertRaises(network_optimizer.InternetOptimizerError) as raised:
                service.perform_action("change-router-channel")
            self.assertEqual(raised.exception.code, "system_settings_unavailable")
            self.assertEqual(opened, [])
        finally:
            service.shutdown()


class CoreWLANProbeContractTests(unittest.TestCase):
    class Channel:
        def __init__(self, number, band=1, width=1):
            self.number = number
            self.band = band
            self.width = width

        def channelNumber(self):
            return self.number

        def channelBand(self):
            return self.band

        def channelWidth(self):
            return self.width

    class Network:
        def wlanChannel(self):
            return CoreWLANProbeContractTests.Channel(6)

        def rssiValue(self):
            return -65

        def noiseMeasurement(self):
            return -92

        def ssid(self):
            raise AssertionError("SSID must not be read")

        def bssid(self):
            raise AssertionError("BSSID must not be read")

    class Interface:
        def interfaceName(self):
            return "en0"

        def wlanChannel(self):
            return CoreWLANProbeContractTests.Channel(1)

        def rssiValue(self):
            return -55

        def noiseMeasurement(self):
            return -92

        def transmitRate(self):
            return 866.7

        def security(self):
            return 11

        def powerOn(self):
            return True

        def serviceActive(self):
            return True

        def supportedWLANChannels(self):
            return [CoreWLANProbeContractTests.Channel(1), CoreWLANProbeContractTests.Channel(6)]

        def scanForNetworksWithSSID_error_(self, _ssid, _error):
            return ({CoreWLANProbeContractTests.Network()}, None)

        def ssid(self):
            raise AssertionError("SSID must not be read")

        def bssid(self):
            raise AssertionError("BSSID must not be read")

    def fake_objc(self, interface):
        client = types.SimpleNamespace(interfaces=lambda: {interface})
        client_class = types.SimpleNamespace(sharedWiFiClient=lambda: client)
        module = types.ModuleType("objc")
        module.loadBundle = lambda *_args, **_kwargs: None
        module.lookUpClass = lambda name: client_class if name == "CWWiFiClient" else None
        return module

    def test_probe_never_reads_or_returns_ssid_or_bssid(self):
        with mock.patch.dict(sys.modules, {"objc": self.fake_objc(self.Interface())}):
            result = network_optimizer.CoreWLANProbe()()
        self.assertEqual(result["current"]["name"], "en0")
        self.assertEqual(result["current"]["security"], "WPA3 Personal")
        self.assertEqual(result["nearby"][0]["channel"]["number"], 6)
        keys = []

        def collect(value):
            if isinstance(value, dict):
                keys.extend(str(key).lower() for key in value)
                for item in value.values():
                    collect(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    collect(item)

        collect(result)
        self.assertNotIn("ssid", keys)
        self.assertNotIn("bssid", keys)

    def test_probe_maps_permission_failure_without_raw_detail(self):
        interface = self.Interface()
        interface.scanForNetworksWithSSID_error_ = lambda *_args: (_ for _ in ()).throw(PermissionError("/private/path"))
        with mock.patch.dict(sys.modules, {"objc": self.fake_objc(interface)}):
            with self.assertRaises(network_optimizer.InternetOptimizerError) as raised:
                network_optimizer.CoreWLANProbe()()
        self.assertEqual(raised.exception.code, "permission_denied")
        self.assertEqual(str(raised.exception), "permission_denied")

    def test_corewlan_operation_not_permitted_code_maps_to_permission(self):
        class CoreWLANPermissionError(Exception):
            def code(self):
                return -3930

        interface = self.Interface()
        interface.scanForNetworksWithSSID_error_ = lambda *_args: (_ for _ in ()).throw(CoreWLANPermissionError("private"))
        with mock.patch.dict(sys.modules, {"objc": self.fake_objc(interface)}):
            with self.assertRaises(network_optimizer.InternetOptimizerError) as raised:
                network_optimizer.CoreWLANProbe()()
        self.assertEqual(raised.exception.code, "permission_denied")

    def test_returned_corewlan_permission_object_maps_without_raising_raw_object(self):
        class ReturnedCoreWLANPermission:
            def code(self):
                return -3930

        interface = self.Interface()
        interface.scanForNetworksWithSSID_error_ = lambda *_args: (None, ReturnedCoreWLANPermission())
        with mock.patch.dict(sys.modules, {"objc": self.fake_objc(interface)}):
            with self.assertRaises(network_optimizer.InternetOptimizerError) as raised:
                network_optimizer.CoreWLANProbe()()
        self.assertEqual(raised.exception.code, "permission_denied")


if __name__ == "__main__":
    unittest.main()
