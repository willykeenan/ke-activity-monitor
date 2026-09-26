#!/usr/bin/env python3
import json
from html.parser import HTMLParser
from pathlib import Path
import subprocess
import tempfile
import unittest

import activity_monitor
import network_fabric
import network_optimizer


class FakeNetworkService:
    def __init__(self):
        self.calls = []

    def snapshot(self):
        return {
            "schemaVersion": network_fabric.SCHEMA_VERSION,
            "active": True,
            "devices": [],
            "counts": {"observed": 0, "online": 0, "recent": 0, "offline": 0, "paired": 0},
            "link": {"enabled": False, "generation": 0, "messages": []},
            "coverage": {"boundary": "direct segments only"},
            "local": {"interfaces": []},
            "scan": {},
            "errors": [],
        }

    def start_discovery(self):
        self.calls.append(("start",))
        return self.snapshot()

    def stop_discovery(self):
        self.calls.append(("stop",))
        result = self.snapshot()
        result["active"] = False
        return result

    def get_snapshot(self):
        self.calls.append(("snapshot",))
        return self.snapshot()

    def request_deep_scan(self):
        self.calls.append(("scan",))
        return {"ok": True, "queued": True, "rateLimited": False}

    def recover_connection(self, code, source=None, device_id=None, after_settings=False, recovery_generation=None):
        self.calls.append(("recover", code, source, device_id, after_settings, recovery_generation))
        return {"ok": True, "state": "rechecking", "recovery": network_fabric.recovery_plan(code, recovery_generation), "snapshot": self.snapshot()}

    def error_projection(self, code, source="network", observed_at=None):
        return network_fabric.public_error(code, source, observed_at, recovery_generation=0)

    def set_link_enabled(self, enabled):
        self.calls.append(("link", enabled))
        return {"enabled": enabled}

    def begin_pairing(self):
        self.calls.append(("begin",))
        return {"code": "ABCD-EFGH", "expiresAt": "2027-01-01T00:00:00Z"}

    def pair_device(self, device_id, code):
        self.calls.append(("pair", device_id, code))
        return {"ok": True, "peerId": "peer", "peerName": "Studio"}

    def verify_link_session(self, device_id):
        self.calls.append(("verify", device_id))
        return {"ok": True, "state": "ready"}

    def revoke_peer(self, device_id):
        self.calls.append(("revoke", device_id))
        return {"ok": True, "state": "revoked"}

    def revoke_trusted_peer(self, peer_id):
        self.calls.append(("revoke-trusted", peer_id))
        return {"ok": True, "state": "revoked", "peerId": peer_id}

    def send_message(self, device_id, message, client_message_id):
        self.calls.append(("send", device_id, message, client_message_id))
        return {"ok": True, "state": "delivered", "clientMessageId": client_message_id, "messageId": "message"}

    def perform_action(self, device_id, action, service_id=None):
        self.calls.append(("action", device_id, action, service_id))
        return {"ok": True, "state": "reachable", "latencyMs": 1.2}

    def shutdown(self):
        self.calls.append(("shutdown",))
        return {"ok": True}


class FakeInternetOptimizerService:
    def __init__(self):
        self.calls = []
        self.error = None

    def snapshot(self):
        return {
            "ok": True,
            "schemaVersion": network_optimizer.SCHEMA_VERSION,
            "state": "complete",
            "connection": {
                "kind": "wifi",
                "interface": "en0",
                "connected": True,
                "band": "5 GHz",
                "channel": 36,
                "widthMHz": 80,
                "signalDbm": -55,
                "noiseDbm": -92,
                "snrDb": 37,
                "transmitRateMbps": 866.7,
            },
            "quality": {"label": "Strong", "healthScore": 92, "confidence": "measured"},
            "interference": {
                "measured": True,
                "nearbyObservationCount": 3,
                "channels": [],
                "recommendation": {"canApply": False, "reason": "Keep the router on Auto."},
            },
            "findings": [],
            "router": {"canApplyChannel": False, "adminAvailable": True, "boundary": "Router authorization required."},
            "actions": [
                {"id": "open-router-settings", "available": True},
                {"id": "measure-internet", "available": True},
                {"id": "wireless-diagnostics", "available": True},
                {"id": "open-wifi-settings", "available": True},
            ],
            "activeTest": None,
            "privacy": {"settingsChanged": False},
        }

    def analyze(self):
        self.calls.append(("analyze",))
        if self.error:
            raise self.error
        return self.snapshot()

    def measure(self):
        self.calls.append(("measure",))
        if self.error:
            raise self.error
        return {
            "ok": True,
            "schemaVersion": network_optimizer.SCHEMA_VERSION,
            "state": "measured",
            "interface": "en0",
            "downloadMbps": 100.0,
            "uploadMbps": 20.0,
            "idleLatencyMs": 15.0,
            "responsivenessRpm": 500,
            "usesInternetData": True,
            "settingsChanged": False,
            "comparison": None,
        }

    def perform_action(self, action_id):
        self.calls.append(("action", action_id))
        if self.error:
            raise self.error
        return {"ok": True, "state": "opened", "actionId": action_id, "settingsChanged": False}

    def shutdown(self):
        self.calls.append(("shutdown",))
        return {"ok": True}


class IdParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []

    def handle_starttag(self, _tag, attrs):
        for key, value in attrs:
            if key == "id":
                self.ids.append(value)


class NetworkBridgeTests(unittest.TestCase):
    def api(self, service, optimizer=None):
        return activity_monitor.Api(
            brain_service=object(),
            dispatch_service=object(),
            guard_service=object(),
            network_service=service,
            internet_optimizer_service=optimizer or FakeInternetOptimizerService(),
        )

    def test_bridge_covers_discovery_pair_message_action_and_shutdown(self):
        service = FakeNetworkService()
        api = self.api(service)
        self.assertTrue(json.loads(api.start_network_discovery())["active"])
        self.assertTrue(json.loads(api.request_network_scan())["queued"])
        self.assertEqual(
            json.loads(api.recover_network_connection("permission_denied", "bonjour", "device", True))["state"],
            "rechecking",
        )
        self.assertTrue(json.loads(api.set_ke_link_enabled(True))["enabled"])
        self.assertEqual(json.loads(api.begin_ke_link_pairing())["code"], "ABCD-EFGH")
        self.assertTrue(json.loads(api.pair_network_device("device", "code"))["ok"])
        self.assertTrue(json.loads(api.verify_network_peer("device"))["ok"])
        self.assertTrue(json.loads(api.send_network_message("device", "hello", "a" * 32))["ok"])
        self.assertTrue(json.loads(api.revoke_network_peer("device"))["ok"])
        self.assertTrue(json.loads(api.revoke_network_trusted_peer("a" * 32))["ok"])
        self.assertEqual(json.loads(api.perform_network_action("device", "ping"))["state"], "reachable")
        self.assertFalse(json.loads(api.stop_network_discovery())["active"])
        api.shutdown()
        self.assertEqual(
            [row[0] for row in service.calls],
            ["start", "scan", "recover", "link", "begin", "pair", "verify", "send", "revoke", "revoke-trusted", "action", "stop", "shutdown"],
        )

    def test_bridge_fails_closed_with_stable_network_error(self):
        service = FakeNetworkService()

        def reject():
            raise network_fabric.NetworkFabricError("permission_denied", "Local Network access is unavailable")

        service.start_discovery = reject
        result = json.loads(self.api(service).start_network_discovery())
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "permission_denied")
        self.assertEqual(result["schemaVersion"], network_fabric.SCHEMA_VERSION)
        self.assertTrue(result["errorDetail"]["observedAt"].endswith("Z"))
        self.assertEqual(result["errorDetail"]["recovery"]["kind"], "settings")
        self.assertEqual(result["errorDetail"]["recovery"]["action"], "open-local-network-settings")

    def test_failed_connection_inventory_retry_keeps_the_exact_source(self):
        service = FakeNetworkService()

        def reject(*_args):
            raise network_fabric.NetworkFabricError("connections_unavailable")

        service.recover_connection = reject
        result = json.loads(self.api(service).recover_network_connection(
            "connections_unavailable",
            "connections",
            None,
            False,
            0,
        ))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "connections_unavailable")
        self.assertEqual(result["errorDetail"]["source"], "connections")
        self.assertEqual(result["errorDetail"]["recovery"]["action"], "retry-connections")

    def test_bridge_covers_optimizer_analysis_measurement_and_guided_action(self):
        network = FakeNetworkService()
        optimizer = FakeInternetOptimizerService()
        api = self.api(network, optimizer)
        self.assertEqual(json.loads(api.analyze_internet_connection())["quality"]["label"], "Strong")
        measurement = json.loads(api.measure_internet_quality())
        self.assertTrue(measurement["usesInternetData"])
        action = json.loads(api.perform_internet_optimizer_action("open-router-settings"))
        self.assertFalse(action["settingsChanged"])
        api.shutdown()
        self.assertEqual(
            optimizer.calls,
            [("analyze",), ("measure",), ("action", "open-router-settings"), ("shutdown",)],
        )

    def test_optimizer_permission_error_gets_exact_one_click_settings_recovery(self):
        network = FakeNetworkService()
        optimizer = FakeInternetOptimizerService()
        optimizer.error = network_optimizer.InternetOptimizerError("permission_denied")
        api = self.api(network, optimizer)
        failure = json.loads(api.analyze_internet_connection())
        self.assertEqual(failure["code"], "wifi_diagnostics_permission_denied")
        self.assertEqual(failure["errorDetail"]["source"], "internet-optimizer")
        self.assertEqual(failure["errorDetail"]["recovery"]["action"], "open-wifi-settings")
        generation = failure["errorDetail"]["recovery"]["generation"]
        optimizer.error = None
        handoff = json.loads(
            api.recover_network_connection(
                failure["code"], "internet-optimizer", None, False, generation
            )
        )
        self.assertEqual(handoff["state"], "waiting-for-user")
        self.assertIn(("action", "open-wifi-settings"), optimizer.calls)
        rechecked = json.loads(
            api.recover_network_connection(
                failure["code"], "internet-optimizer", None, True, generation
            )
        )
        self.assertEqual(rechecked["state"], "optimizer-rechecked")
        self.assertEqual(rechecked["optimizerSnapshot"]["quality"]["label"], "Strong")

    def test_internet_measurement_failure_retry_is_labelled_as_data_using(self):
        network = FakeNetworkService()
        optimizer = FakeInternetOptimizerService()
        optimizer.error = network_optimizer.InternetOptimizerError("request_timeout")
        api = self.api(network, optimizer)
        failure = json.loads(api.measure_internet_quality())
        self.assertEqual(failure["code"], "internet_quality_unavailable")
        self.assertEqual(failure["errorDetail"]["recovery"]["action"], "retry-internet-test")
        self.assertEqual(failure["errorDetail"]["recovery"]["label"], "Retry data test")
        generation = failure["errorDetail"]["recovery"]["generation"]
        optimizer.error = None
        retried = json.loads(
            api.recover_network_connection(
                failure["code"], "internet-optimizer", None, False, generation
            )
        )
        self.assertEqual(retried["state"], "internet-measured")
        self.assertTrue(retried["internetQuality"]["usesInternetData"])

    def test_superseded_measurement_returns_truthful_one_click_retry(self):
        network = FakeNetworkService()
        optimizer = FakeInternetOptimizerService()
        optimizer.error = network_optimizer.InternetOptimizerError("request_superseded")
        failure = json.loads(self.api(network, optimizer).measure_internet_quality())
        self.assertFalse(failure["ok"])
        self.assertEqual(failure["state"], "failed-before-change")
        self.assertEqual(failure["code"], "internet_quality_unavailable")
        self.assertEqual(failure["errorDetail"]["source"], "internet-optimizer")
        self.assertEqual(failure["errorDetail"]["recovery"]["action"], "retry-internet-test")
        self.assertEqual(failure["errorDetail"]["recovery"]["label"], "Retry data test")

    def test_superseded_analysis_returns_truthful_one_click_retry(self):
        network = FakeNetworkService()
        optimizer = FakeInternetOptimizerService()
        optimizer.error = network_optimizer.InternetOptimizerError("request_superseded")
        failure = json.loads(self.api(network, optimizer).analyze_internet_connection())
        self.assertFalse(failure["ok"])
        self.assertEqual(failure["state"], "failed-before-change")
        self.assertEqual(failure["code"], "internet_optimizer_unavailable")
        self.assertEqual(failure["errorDetail"]["source"], "internet-optimizer")
        self.assertEqual(failure["errorDetail"]["recovery"]["action"], "retry-internet-optimizer")
        self.assertEqual(failure["errorDetail"]["recovery"]["label"], "Retry optimizer")

    def test_failed_optimizer_retry_retains_exact_recoverable_source(self):
        network = FakeNetworkService()
        optimizer = FakeInternetOptimizerService()
        optimizer.error = network_optimizer.InternetOptimizerError("request_timeout")
        api = self.api(network, optimizer)
        failure = json.loads(api.measure_internet_quality())
        retried = json.loads(
            api.recover_network_connection(
                failure["code"],
                "internet-optimizer",
                None,
                False,
                failure["errorDetail"]["recovery"]["generation"],
            )
        )
        self.assertFalse(retried["ok"])
        self.assertEqual(retried["code"], "internet_quality_unavailable")
        self.assertEqual(retried["errorDetail"]["source"], "internet-optimizer")
        self.assertEqual(retried["errorDetail"]["recovery"]["action"], "retry-internet-test")

    def test_unexpected_optimizer_errors_remain_safe_and_one_click_recoverable(self):
        network = FakeNetworkService()
        optimizer = FakeInternetOptimizerService()
        optimizer.error = RuntimeError("private local path must never escape")
        api = self.api(network, optimizer)
        analysis = json.loads(api.analyze_internet_connection())
        self.assertEqual(analysis["code"], "internet_optimizer_unavailable")
        self.assertEqual(analysis["errorDetail"]["recovery"]["action"], "retry-internet-optimizer")
        self.assertNotIn("private local path", json.dumps(analysis))

        settings = json.loads(api.perform_internet_optimizer_action("open-router-settings"))
        self.assertEqual(settings["code"], "system_settings_unavailable")
        self.assertEqual(settings["errorDetail"]["recovery"]["action"], "open-network-settings")
        optimizer.error = None
        retried = json.loads(
            api.recover_network_connection(
                settings["code"],
                "internet-optimizer",
                None,
                False,
                settings["errorDetail"]["recovery"]["generation"],
            )
        )
        self.assertEqual(retried["state"], "settings-opened")
        self.assertIn(("action", "open-wifi-settings"), optimizer.calls)


class NetworkUiContractTests(unittest.TestCase):
    def test_live_surface_has_unique_ids_and_accessible_scope(self):
        parser = IdParser()
        parser.feed(activity_monitor.HTML)
        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        for expected in (
            "network-scope",
            "network-error-copy",
            "network-recovery-btn",
            "network-device-list",
            "network-detail-card",
            "network-detail-content",
            "network-link-toggle",
            "network-pair-input",
            "network-message-input",
            "network-trusted-peers",
            "ke-link-card",
            "network-pair-requirement",
            "internet-optimizer-btn",
            "internet-optimizer",
            "internet-health",
            "internet-channel-list",
            "internet-finding-list",
            "internet-quality-btn",
            "internet-router-btn",
            "net-table",
            "net-bar-chart",
        ):
            self.assertIn(expected, parser.ids)
        self.assertIn('aria-describedby="network-scope"', activity_monitor.HTML)
        self.assertIn("@media(prefers-reduced-motion:reduce)", activity_monitor.HTML)

    def test_speed_up_internet_is_measured_truthful_and_accessible(self):
        html = activity_monitor.HTML
        script = html.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        self.assertEqual(html.count('id="internet-optimizer-btn"'), 1)
        self.assertEqual(html.count('id="internet-optimizer"'), 1)
        self.assertIn(">Speed Up My Internet</button>", html)
        self.assertIn('aria-labelledby="internet-optimizer-title"', html)
        self.assertIn('data-network-info="optimizer"', html)
        self.assertIn("Measure internet (uses data)", html)
        self.assertIn("Nearby network names and identifiers are not read, displayed, or saved", html)
        self.assertIn("Router channel changes require your router administrator", html)
        self.assertIn("pywebview.api.analyze_internet_connection()", script)
        self.assertIn("pywebview.api.measure_internet_quality()", script)
        self.assertIn("pywebview.api.perform_internet_optimizer_action(actionId)", script)
        self.assertIn("function renderInternetOptimizer", script)
        self.assertIn("function renderInternetQuality", script)

    def test_first_optimizer_click_never_runs_data_test_or_claims_router_change(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        analyze = "async function analyzeInternetConnection" + script.split("async function analyzeInternetConnection", 1)[1].split("async function measureInternetQuality", 1)[0]
        render = "function renderInternetOptimizer" + script.split("function renderInternetOptimizer", 1)[1].split("function openInternetOptimizer", 1)[0]
        self.assertIn("pywebview.api.analyze_internet_connection()", analyze)
        self.assertNotIn("measure_internet_quality", analyze)
        self.assertNotIn("perform_internet_optimizer_action", analyze)
        self.assertIn("recommendation.reason", render)
        self.assertIn("router?.boundary", render)
        self.assertNotIn("innerHTML", render)

    def test_optimizer_lifecycle_ignores_late_results_after_tab_exit(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        self.assertIn("closeInternetOptimizer(false);\n            closeNetworkInfo(false);", script)
        self.assertIn("const requestGeneration = ++internetOptimizerGeneration;", script)
        self.assertIn("requestGeneration !== internetOptimizerGeneration || currentTab !== 'network' || panel.hidden", script)
        self.assertIn("internetOptimizerGeneration += 1;\n    panel.hidden = true;", script)

    def test_optimizer_prevents_analysis_measurement_overlap_and_hides_cross_interface_results(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        render_region = "function optimizerAction" + script.split("function optimizerAction", 1)[1].split("function openInternetOptimizer", 1)[0]
        async_region = "async function analyzeInternetConnection" + script.split("async function analyzeInternetConnection", 1)[1].split("async function performInternetOptimizerAction", 1)[0]
        analyze_region = async_region.split("async function measureInternetQuality", 1)[0]
        measure_region = "async function measureInternetQuality" + async_region.split("async function measureInternetQuality", 1)[1]
        self.assertIn("internetOptimizerInFlight || internetQualityInFlight", analyze_region)
        self.assertIn("internetQualityInFlight || internetOptimizerInFlight", measure_region)
        self.assertIn("rerunButton.disabled = true;", measure_region)
        self.assertIn("qualityButton.disabled = true;", analyze_region)
        self.assertIn("measurementInterface === snapshotInterface", render_region)
        repair_region = "async function repairNetworkConnection" + script.split("async function repairNetworkConnection", 1)[1].split("function resumeNetworkRecoveryAfterSettings", 1)[0]
        self.assertIn("optimizerBoundMeasurement(lastInternetOptimizerSnapshot, payload.internetQuality)", repair_region)
        self.assertIn("payload.internetQuality && !recoveredInternetQuality", repair_region)
        self.assertIn("optimizerRecoveryMode && (internetOptimizerInFlight || internetQualityInFlight)", repair_region)
        self.assertIn("if (optimizerRecoveryMode === 'analyze') internetOptimizerInFlight = true;", repair_region)

        harness = r'''
class FakeNode {
  constructor(){this.children=[];this.hidden=false;this.disabled=false;this.textContent='';this.className='';this.style={};}
  get firstChild(){return this.children[0] || null;}
  appendChild(child){this.children.push(child);return child;}
  append(...children){this.children.push(...children);}
  removeChild(child){this.children=this.children.filter(item => item !== child);}
  setAttribute(){}
  removeAttribute(){}
}
const nodes={};
const document={
  getElementById:id => (nodes[id] ||= new FakeNode()),
  createElement:() => new FakeNode()
};
function emptyNode(node){while(node.firstChild) node.removeChild(node.firstChild);}
let lastInternetOptimizerSnapshot=null;
let internetOptimizerInFlight=false;
let internetQualityInFlight=true;
let internetOptimizerGeneration=4;
let apiReady=true;
let currentTab='network';
let analyzeCalls=0;
let measureCalls=0;
let recoveryCalls=0;
let networkRecoveryInFlight=false;
let networkRecoveryContext=null;
let networkRecoveryErrorGeneration=3;
let networkLifecycleGeneration=7;
let networkRecoveryRequestSequence=0;
let networkWindowTransitionSequence=0;
const NETWORK_RECOVERY_ACTIONS=new Set(['retry-internet-optimizer','retry-internet-test']);
const pywebview={api:{
  analyze_internet_connection:async()=>{analyzeCalls += 1;return '{}';},
  measure_internet_quality:async()=>{measureCalls += 1;return '{}';},
  recover_network_connection:async()=>{recoveryCalls += 1;return new Promise(()=>{});}
}};
function bridgeJson(raw){return raw && typeof raw === 'object' ? raw : JSON.parse(String(raw || '{}'));}
function networkFailure(payload){const error=new Error('network-safe-failure');error.networkPayload=payload;return error;}
function clearInternetOptimizerFailure(){}
let feedback='';
function setNetworkFeedback(message){feedback=String(message || '');}
function setInternetOptimizerFailure(){}
function cancelNetworkRecoveryWatcher(){}
'''
        exercise = r'''
(async()=>{
  await analyzeInternetConnection();
  const blockedAnalyzeCalls=analyzeCalls;
  internetQualityInFlight=false;
  internetOptimizerInFlight=true;
  await measureInternetQuality();
  const blockedMeasureCalls=measureCalls;

  const recoveryContext={
    code:'internet_optimizer_unavailable',source:'internet-optimizer',deviceId:null,
    errorGeneration:3,lifecycleGeneration:7,
    recovery:{action:'retry-internet-optimizer',generation:2}
  };
  await repairNetworkConnection(false,recoveryContext);
  const recoveryBlockedByOrdinary={calls:recoveryCalls,feedback};
  internetOptimizerInFlight=false;
  repairNetworkConnection(false,recoveryContext);
  const recoveryStarted={calls:recoveryCalls,analysisBusy:internetOptimizerInFlight};
  await analyzeInternetConnection();
  const ordinaryBlockedByRecovery=analyzeCalls;
  internetOptimizerInFlight=false;
  networkRecoveryInFlight=false;

  const base={
    ok:true,state:'complete',connection:{kind:'wifi',interface:'en7'},
    quality:{label:'Strong',healthScore:90,confidence:'measured'},
    interference:{measured:true,nearbyObservationCount:0,channels:[],recommendation:{}},
    findings:[],router:{},actions:[
      {id:'measure-internet',available:true},
      {id:'open-router-settings',available:false},
      {id:'wireless-diagnostics',available:true},
      {id:'open-wifi-settings',available:true}
    ]
  };
  renderInternetOptimizer({...base,activeTest:{ok:true,interface:'en0',downloadMbps:999,comparison:{downloadMbps:900}}});
  const stale={
    stored:lastInternetOptimizerSnapshot.activeTest,
    hidden:nodes['internet-quality-result'].hidden,
    download:document.getElementById('internet-download').textContent
  };
  renderInternetOptimizer({...base,activeTest:{ok:true,interface:'en7',downloadMbps:50,uploadMbps:10,idleLatencyMs:20,responsivenessRpm:400,comparison:null}});
  const current={
    storedInterface:lastInternetOptimizerSnapshot.activeTest?.interface,
    hidden:nodes['internet-quality-result'].hidden,
    download:nodes['internet-download'].textContent
  };
  console.log(JSON.stringify({blockedAnalyzeCalls,blockedMeasureCalls,recoveryBlockedByOrdinary,recoveryStarted,ordinaryBlockedByRecovery,stale,current}));
})().catch(error=>{console.error(error);process.exit(1);});
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, render_region, async_region, repair_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=False, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["blockedAnalyzeCalls"], 0)
        self.assertEqual(result["blockedMeasureCalls"], 0)
        self.assertEqual(result["recoveryBlockedByOrdinary"]["calls"], 0)
        self.assertIn("still finishing", result["recoveryBlockedByOrdinary"]["feedback"])
        self.assertEqual(result["recoveryStarted"]["calls"], 1)
        self.assertTrue(result["recoveryStarted"]["analysisBusy"])
        self.assertEqual(result["ordinaryBlockedByRecovery"], 0)
        self.assertIsNone(result["stale"]["stored"])
        self.assertTrue(result["stale"]["hidden"])
        self.assertEqual(result["stale"]["download"], "")
        self.assertEqual(result["current"]["storedInterface"], "en7")
        self.assertFalse(result["current"]["hidden"])
        self.assertEqual(result["current"]["download"], "50.0 Mbps")

    def test_optimizer_permission_and_active_test_errors_use_one_click_contract(self):
        contract = network_fabric.network_error_contract()
        location = contract["recoveries"]["wifi_diagnostics_permission_denied"]
        quality = contract["recoveries"]["internet_quality_unavailable"]
        optimizer = contract["recoveries"]["internet_optimizer_unavailable"]
        self.assertEqual(location["action"], "open-wifi-settings")
        self.assertEqual(location["label"], "Open Wi-Fi Settings")
        self.assertEqual(quality["action"], "retry-internet-test")
        self.assertEqual(quality["label"], "Retry data test")
        self.assertEqual(optimizer["action"], "retry-internet-optimizer")
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        repair = "async function repairNetworkConnection" + script.split("async function repairNetworkConnection", 1)[1].split("function resumeNetworkRecoveryAfterSettings", 1)[0]
        self.assertIn("payload.optimizerSnapshot", repair)
        self.assertIn("payload.internetQuality", repair)
        self.assertIn("action === 'open-wifi-settings'", repair)

    def test_optimizer_error_survives_refresh_until_that_operation_succeeds(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        constants = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function networkRecoveryDetail", 1)[0]
        detail_region = "function networkRecoveryDetail" + script.split("function networkRecoveryDetail", 1)[1].split("function networkErrorCopy", 1)[0]
        clear_region = "function clearInternetOptimizerFailure" + script.split("function clearInternetOptimizerFailure", 1)[1].split("function focusNetworkRecoverySurface", 1)[0]
        current_region = "function networkCurrentErrors" + script.split("function networkCurrentErrors", 1)[1].split("function renderNetworkSnapshot", 1)[0]
        remembered = network_fabric.public_error(
            "internet_quality_unavailable",
            "internet-optimizer",
        )
        remembered["observedAt"] = "2026-08-24T20:00:00Z"
        permission = network_fabric.public_error("permission_denied", "bonjour")
        permission["observedAt"] = "2026-08-24T20:00:01Z"
        harness = f"""
let internetOptimizerErrorDetail={json.dumps(remembered, separators=(',', ':'))};
let lastNetworkSnapshot={{errors:[],link:{{}}}};
let renderCount=0;
function renderNetworkSnapshot(_snapshot){{renderCount += 1;}}
function showNetworkError(){{}}
{constants}
{detail_region}
{clear_region}
{current_region}
const before=networkCurrentErrors(lastNetworkSnapshot).map(item => item.code);
const prioritized=networkCurrentErrors({{errors:[{json.dumps(permission, separators=(',', ':'))}],link:{{}}}}).map(item => item.code);
clearInternetOptimizerFailure(['internet_optimizer_unavailable']);
const afterUnrelatedSuccess=networkCurrentErrors(lastNetworkSnapshot).map(item => item.code);
clearInternetOptimizerFailure(['internet_quality_unavailable']);
const afterExactSuccess=networkCurrentErrors(lastNetworkSnapshot).map(item => item.code);
console.log(JSON.stringify({{before,prioritized,afterUnrelatedSuccess,afterExactSuccess,renderCount}}));
"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write(harness)
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        self.assertEqual(result["before"], ["internet_quality_unavailable"])
        self.assertEqual(result["prioritized"], ["permission_denied", "internet_quality_unavailable"])
        self.assertEqual(result["afterUnrelatedSuccess"], ["internet_quality_unavailable"])
        self.assertEqual(result["afterExactSuccess"], [])
        self.assertEqual(result["renderCount"], 1)

    def test_optimizer_has_compact_and_narrow_layouts(self):
        html = activity_monitor.HTML
        self.assertIn(".internet-optimizer-summary{display:grid;grid-template-columns:repeat(5,minmax(0,1fr))", html)
        self.assertIn(".internet-optimizer-grid{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr)", html)
        self.assertIn(".internet-optimizer-summary{grid-template-columns:repeat(2,minmax(0,1fr))}", html)
        self.assertIn(".internet-optimizer-grid{grid-template-columns:1fr}", html)

    def test_network_visual_hierarchy_keeps_inventory_ahead_of_secondary_tools(self):
        html = activity_monitor.HTML
        region = html.split('<div id="network-tab"', 1)[1].split('<div id="agents-tab"', 1)[0]
        ordered = (
            'class="network-stats"',
            'class="network-layout"',
            'class="network-card internet-optimizer" id="internet-optimizer"',
            'class="network-card ke-link-card"',
            'class="network-card network-traffic"',
            'data-flagship-tab="network"',
        )
        positions = [region.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("See what is connected. Fix what is not.", region)
        self.assertIn("Device details", region)
        self.assertNotIn("Device constellation", region)

    def test_network_capability_fabric_scrolls_below_primary_workspace(self):
        html = activity_monitor.HTML
        region = html.split('<div id="network-tab"', 1)[1].split('<div id="agents-tab"', 1)[0]
        self.assertIn(
            '</details>\n<section class="flagship-fabric" data-flagship-tab="network"',
            region,
        )
        self.assertNotIn(
            '</details>\n    </div>\n<section class="flagship-fabric" data-flagship-tab="network"',
            region,
        )
        self.assertIn(".network-scroll>.flagship-fabric{margin:14px 0 0;box-shadow:none}", html)

    def test_network_polish_keeps_small_copy_readable_and_actions_responsive(self):
        source = Path(activity_monitor.__file__).read_text(encoding="utf-8")
        network_css = source.split(".network-scroll", 1)[1].split(".powerswarm-heading", 1)[0]
        for size in range(5, 8):
            self.assertNotIn(f"font-size:{size}px", network_css)
        self.assertIn("#network-tab :is(.network-kicker,.network-error-action", network_css)
        self.assertIn(".network-device-meta,.network-device-sources,.network-device-state,.network-device-trust", network_css)
        self.assertIn(".flagship-meta span,.flagship-meta strong,.flagship-empty){font-size:10px}", network_css)
        self.assertIn("#network-tab .network-traffic summary:after", network_css)
        self.assertIn(".network-boundary{font-size:10px}", source)
        self.assertIn(".network-stat:last-child{grid-column:1/-1}", source)
        self.assertIn(".network-hero-btn.primary{grid-column:1/-1}", source)
        self.assertIn(".internet-optimizer-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}", source)
        self.assertIn("@media(prefers-reduced-motion:reduce){.network-pulse{animation:none!important}}", source)
        self.assertIn("function scrollInternetOptimizerIntoView(panel, behavior = 'smooth')", source)
        self.assertIn("scroller.scrollTo({top, behavior: reducedMotion ? 'auto' : behavior})", source)
        optimizer_open = source.split("function openInternetOptimizer()", 1)[1].split("function closeInternetOptimizer", 1)[0]
        self.assertIn("scrollInternetOptimizerIntoView(panel);", optimizer_open)
        self.assertNotIn("scrollIntoView", optimizer_open)

    def test_optimizer_keyboard_focus_enters_panel_and_close_restores_trigger(self):
        source = Path(activity_monitor.__file__).read_text(encoding="utf-8")
        self.assertIn(
            'id="internet-optimizer" tabindex="-1" aria-labelledby="internet-optimizer-title"',
            source,
        )
        self.assertIn(".internet-optimizer:focus-visible{outline:3px solid", source)
        optimizer_open = source.split("function openInternetOptimizer()", 1)[1].split(
            "function closeInternetOptimizer", 1
        )[0]
        self.assertIn("panel.focus({preventScroll: true})", optimizer_open)
        self.assertLess(
            optimizer_open.index("panel.focus({preventScroll: true})"),
            optimizer_open.index("analyzeInternetConnection();"),
        )
        optimizer_close = source.split("function closeInternetOptimizer", 1)[1].split(
            "async function analyzeInternetConnection", 1
        )[0]
        self.assertIn(
            "if (restoreFocus && currentTab === 'network') document.getElementById('internet-optimizer-btn').focus();",
            optimizer_close,
        )

    def test_tab_lifecycle_starts_and_stops_discovery(self):
        html = activity_monitor.HTML
        self.assertIn("const leavingNetwork = currentTab === 'network' && nextTab !== 'network';", html)
        self.assertIn("networkDiscoveryStopPromise = stopNetworkDiscovery();", html)
        self.assertIn("if (currentTab === 'network') {\n                startNetworkDiscovery();\n                resumeNetworkRecoveryAfterSettings();", html)
        self.assertIn("await networkDiscoveryStopPromise;", html)
        self.assertIn("pywebview.api.start_network_discovery()", html)
        self.assertIn("pywebview.api.stop_network_discovery()", html)
        self.assertIn("api.shutdown()", Path(activity_monitor.__file__).read_text(encoding="utf-8"))

    def test_untrusted_network_values_use_text_content_not_html_injection(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        network_region = script.split("function showNetworkError", 1)[1].split("function scheduleRefresh", 1)[0]
        self.assertIn("body.textContent = message.body", network_region)
        self.assertIn("name.textContent = device.name", network_region)
        self.assertNotIn("innerHTML", network_region)

    def test_ui_states_truthful_coverage_and_no_execution_boundary(self):
        html = activity_monitor.HTML
        self.assertIn("Observable, not omniscient", html)
        self.assertIn("Silent, sleeping, isolated, or firewalled devices", html)
        self.assertIn("A message cannot execute commands", html)
        self.assertIn("Message bodies stay in memory", html)
        self.assertIn("Actions are limited to what this device advertises", html)
        self.assertIn("Inventory stays on this Mac; discovery probes stay on eligible directly connected segments.", html)
        self.assertNotIn("Nothing leaves this Mac", html)

    def test_contextual_info_controls_explain_network_truth_accessibly(self):
        html = activity_monitor.HTML
        script = html.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        info_region = "function openNetworkInfo" + script.split("function openNetworkInfo", 1)[1].split("function optimizerAction", 1)[0]
        self.assertEqual(html.count('class="network-info-trigger"'), 7)
        for key, label in (
            ("visibility", "Explain Network visibility"),
            ("observed", "Explain Observed devices"),
            ("online", "Explain Online now"),
            ("recent", "Explain Recently seen"),
            ("trusted", "Explain Trusted peers"),
            ("coverage", "Explain Coverage"),
            ("optimizer", "Explain Internet Optimizer"),
        ):
            self.assertIn(f'data-network-info="{key}" aria-label="{label}"', html)
        self.assertEqual(html.count('aria-controls="network-info-panel"'), 7)
        self.assertIn('id="network-info-panel" role="region" aria-live="polite"', html)
        self.assertIn('id="network-info-close" type="button" aria-label="Close Network explanation"', html)
        self.assertIn("Sleeping, silent, firewalled, client-isolated, tunnel, or different-VLAN devices may not appear.", script)
        self.assertIn("A trusted peer is not online or ready unless fresh evidence", script)
        self.assertIn("Connected or Ready still requires a fresh pinned and authenticated session.", script)
        self.assertIn("An asterisk means the scan is partial or capped", script)
        self.assertIn("Measure internet is separate because it connects to the internet and uses plan data.", script)
        self.assertIn("document.getElementById('network-info-title').textContent = entry.title;", info_region)
        self.assertIn("document.getElementById('network-info-body').textContent = entry.body;", info_region)
        self.assertIn("panel.scrollIntoView({block:'nearest'});", info_region)
        self.assertNotIn("innerHTML", info_region)
        self.assertNotIn("pywebview", info_region)
        self.assertIn("closeNetworkInfo(false);\n            cancelNetworkRecoveryWatcher();", script)
        self.assertIn(".network-info-trigger:focus-visible", html)
        self.assertIn(".network-info-panel[hidden]{display:none}", html)
        self.assertIn(".network-info-close{grid-column:2;justify-self:start}", html)

    def test_contextual_info_controls_open_replace_escape_and_dismiss(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        state_region = "let activeNetworkInfoTrigger" + script.split("let activeNetworkInfoTrigger", 1)[1].split("let lastPowerSwarmSnapshot", 1)[0]
        listener_region = "document.querySelectorAll('[data-network-info]')" + script.split("document.querySelectorAll('[data-network-info]')", 1)[1].split("window.addEventListener('blur'", 1)[0]
        keydown_region = "document.addEventListener('keydown'" + script.split("document.addEventListener('keydown'", 1)[1].split("document.querySelectorAll('.seg-btn')", 1)[0]
        function_region = "function openNetworkInfo" + script.split("function openNetworkInfo", 1)[1].split("function networkDeviceGlyph", 1)[0]
        harness = r'''
class FakeNode {
  constructor(id,key=null){
    this.id=id;this.dataset=key?{networkInfo:key}:{};this.hidden=true;this.isConnected=true;
    this.textContent='';this.attributes={};this.listeners={};this.children=[];this.focusCount=0;
  }
  addEventListener(type,handler){(this.listeners[type] ||= []).push(handler);}
  emit(type,event={}){for(const handler of this.listeners[type] || []) handler(event);}
  setAttribute(name,value){this.attributes[name]=String(value);}
  getAttribute(name){return this.attributes[name] ?? null;}
  contains(target){return target === this || this.children.includes(target);}
  scrollIntoView(options){this.scrollOptions=options;}
  focus(){this.focusCount += 1;}
}
const keys=['visibility','observed','online','recent','trusted','coverage'];
const buttons=keys.map(key => new FakeNode('button-'+key,key));
buttons.forEach(button => button.setAttribute('aria-expanded','false'));
const nodes={
  'network-info-panel':new FakeNode('network-info-panel'),
  'network-info-title':new FakeNode('network-info-title'),
  'network-info-body':new FakeNode('network-info-body'),
  'network-info-close':new FakeNode('network-info-close'),
  'workspace-dialog':new FakeNode('workspace-dialog'),
  'workspace-shell':new FakeNode('workspace-shell'),
  'workspace-collapse':new FakeNode('workspace-collapse'),
  'workspace-search':new FakeNode('workspace-search'),
  'disk-cleanup-sheet':new FakeNode('disk-cleanup-sheet')
};
nodes['network-info-panel'].hidden=true;
nodes['workspace-dialog'].hidden=true;
const documentListeners={};
const document={
  getElementById:id => nodes[id],
  querySelectorAll:selector => selector === '[data-network-info]' ? buttons : [],
  addEventListener(type,handler){(documentListeners[type] ||= []).push(handler);},
  dispatch(type,event){for(const handler of documentListeners[type] || []) handler(event);}
};
const window={addEventListener(){}};
let currentTab='network';
'''
        exercise = r'''
let stopped=0;
buttons[1].emit('click',{target:buttons[1],stopPropagation(){stopped += 1;}});
const first={
  hidden:nodes['network-info-panel'].hidden,
  title:nodes['network-info-title'].textContent,
  body:nodes['network-info-body'].textContent,
  expanded:buttons[1].getAttribute('aria-expanded')
};
buttons[4].emit('click',{target:buttons[4],stopPropagation(){stopped += 1;}});
const replaced={
  title:nodes['network-info-title'].textContent,
  body:nodes['network-info-body'].textContent,
  oldExpanded:buttons[1].getAttribute('aria-expanded'),
  expanded:buttons[4].getAttribute('aria-expanded')
};
document.dispatch('keydown',{key:'Escape',preventDefault(){}});
const escaped={hidden:nodes['network-info-panel'].hidden,focus:buttons[4].focusCount,expanded:buttons[4].getAttribute('aria-expanded')};
buttons[0].emit('click',{target:buttons[0],stopPropagation(){}});
document.dispatch('click',{target:new FakeNode('outside')});
const outside={hidden:nodes['network-info-panel'].hidden,focus:buttons[0].focusCount};
buttons[5].emit('click',{target:buttons[5],stopPropagation(){}});
nodes['network-info-close'].emit('click',{target:nodes['network-info-close']});
const close={hidden:nodes['network-info-panel'].hidden,focus:buttons[5].focusCount};
console.log(JSON.stringify({first,replaced,escaped,outside,close,stopped}));
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, state_region, function_region, listener_region, keydown_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        self.assertFalse(result["first"]["hidden"])
        self.assertEqual(result["first"]["title"], "Observed devices")
        self.assertIn("not a complete router inventory", result["first"]["body"])
        self.assertEqual(result["first"]["expanded"], "true")
        self.assertEqual(result["replaced"]["title"], "Trusted peers")
        self.assertIn("fresh pinned and authenticated session", result["replaced"]["body"])
        self.assertEqual(result["replaced"]["oldExpanded"], "false")
        self.assertEqual(result["replaced"]["expanded"], "true")
        self.assertTrue(result["escaped"]["hidden"])
        self.assertEqual(result["escaped"]["focus"], 1)
        self.assertEqual(result["escaped"]["expanded"], "false")
        self.assertTrue(result["outside"]["hidden"])
        self.assertEqual(result["outside"]["focus"], 0)
        self.assertTrue(result["close"]["hidden"])
        self.assertEqual(result["close"]["focus"], 1)
        self.assertEqual(result["stopped"], 2)

    def test_persistent_trust_and_pairing_consent_are_explicit_in_final_html(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        link_region = "function renderNetworkLink" + script.split("function renderNetworkLink", 1)[1].split("async function startNetworkDiscovery", 1)[0]
        pair_region = "async function pairSelectedNetworkDevice" + script.split("async function pairSelectedNetworkDevice", 1)[1].split("async function verifySelectedNetworkPeer", 1)[0]
        self.assertIn("link.trustedPeers", link_region)
        self.assertIn("revokeTrustedNetworkPeer(peer.id)", link_region)
        self.assertIn("pywebview.api.revoke_network_trusted_peer(peerId)", script)
        self.assertIn("!lastNetworkSnapshot?.link?.enabled", pair_region)
        self.assertLess(pair_region.index("!lastNetworkSnapshot?.link?.enabled"), pair_region.index("pywebview.api.pair_network_device"))
        self.assertIn("Pair never enables the listener", pair_region)
        self.assertIn("stays available until disabled", link_region)

    def test_permission_errors_render_newest_current_sources(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        region = "function renderNetworkSnapshot" + script.split("function renderNetworkSnapshot", 1)[1].split("function renderNetworkDeviceList", 1)[0]
        error_merge_region = "function networkCurrentErrors" + script.split("function networkCurrentErrors", 1)[1].split("function renderNetworkSnapshot", 1)[0]
        link_region = "function renderNetworkLink" + script.split("function renderNetworkLink", 1)[1].split("async function startNetworkDiscovery", 1)[0]
        self.assertIn("snapshot?.link?.errors", error_merge_region)
        self.assertIn("internetOptimizerErrorDetail", error_merge_region)
        self.assertIn("localeCompare", error_merge_region)
        self.assertIn("bPriority - aPriority", error_merge_region)
        self.assertIn("const primaryError = currentErrors[0]", region)
        self.assertIn(".slice(0, 2)", error_merge_region)
        self.assertIn("excludedInterfaceCount", region)
        self.assertNotIn("showNetworkError", link_region)
        self.assertIn("Partial scan · capped at", region)
        self.assertIn("This cycle is partial because the bounded host cap was reached.", region)
        local_scope_fixture = {
            "local": {"excludedInterfaces": [{"name": "en9", "scope": "local"}]},
            "coverage": {"excludedInterfaceCount": 1},
        }
        self.assertEqual(local_scope_fixture["local"]["excludedInterfaces"][0]["scope"], "local")
        self.assertIn("' interface'", region)
        self.assertIn("excludedCopy", region)
        self.assertNotIn("tunnel/peer interface", region)

    def test_every_rendered_connection_error_has_one_safe_recovery_control(self):
        html = activity_monitor.HTML
        self.assertEqual(html.count('id="network-recovery-btn"'), 1)
        self.assertIn('id="network-error" role="status" aria-live="polite" tabindex="-1"', html)
        self.assertIn('id="network-recovery-btn" type="button"', html)
        self.assertIn("document.getElementById('network-recovery-btn').addEventListener('click'", html)
        self.assertIn(".network-error{align-items:flex-start;flex-direction:column}", html)
        self.assertEqual(html.count("function repairNetworkConnection"), 1)
        self.assertEqual(html.count("pywebview.api.recover_network_connection("), 1)
        script = html.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        error_region = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function networkDeviceGlyph", 1)[0]
        contract = network_fabric.network_error_contract()
        catalog_json = json.dumps(contract["messages"], ensure_ascii=True, separators=(",", ":"))
        recoveries_json = json.dumps(contract["recoveries"], ensure_ascii=True, separators=(",", ":"))
        kinds_json = json.dumps(contract["recoveryKinds"], ensure_ascii=True, separators=(",", ":"))
        actions_json = json.dumps(contract["recoveryActions"], ensure_ascii=True, separators=(",", ":"))
        self.assertIn("Object.freeze(" + catalog_json + ")", error_region)
        self.assertIn("Object.freeze(" + recoveries_json + ")", error_region)
        self.assertIn("new Set(" + kinds_json + ")", error_region)
        self.assertIn("new Set(" + actions_json + ")", error_region)
        self.assertIn("body.textContent = safeMessage", error_region)
        self.assertIn("NETWORK_RECOVERY_KINDS.has", error_region)
        self.assertIn("NETWORK_RECOVERY_ACTIONS.has", error_region)
        self.assertIn("networkRecoveryInFlight", error_region)
        self.assertIn("afterSettings", error_region)
        self.assertIn("networkRecoveryWatcher", error_region)
        self.assertIn("networkLastDepartureSequence", error_region)
        self.assertIn("networkLastReturnSequence", error_region)
        self.assertIn("NETWORK_RECOVERY_RETURN_TIMEOUT_MS", error_region)
        self.assertIn("const detail = networkErrorDetail(payload);", error_region)
        self.assertIn("Fix Connection never sends", error_region)
        self.assertIn("Fix Connection never enables it", error_region)
        self.assertNotIn("innerHTML", error_region)
        self.assertNotIn("set_ke_link_enabled", error_region)
        repair_region = "async function repairNetworkConnection" + error_region.split("async function repairNetworkConnection", 1)[1].split("function resumeNetworkRecoveryAfterSettings", 1)[0]
        self.assertNotIn("sendSelectedNetworkMessage", repair_region)
        self.assertIn("window.addEventListener('blur', noteNetworkRecoveryDeparture)", script)
        self.assertIn("window.addEventListener('focus', noteNetworkRecoveryReturn)", script)
        self.assertIn("document.visibilityState === 'hidden'", script)
        self.assertIn("document.visibilityState === 'visible'", script)
        self.assertIn("cancelNetworkRecoveryWatcher();\n            networkDiscoveryStopPromise", script)

        harness = r'''
class FakeNode {
  constructor(){this.textContent='';this.hidden=true;this.disabled=false;this.children=[];}
  addEventListener(){}
  setAttribute(){}
  scrollIntoView(){}
  focus(){}
}
const nodes={};
const document={getElementById:id => (nodes[id] ||= new FakeNode())};
let networkRecoveryContext=null;
let networkRecoveryInFlight=false;
let networkRecoveryWatcher=null;
let networkRecoveryErrorGeneration=0;
let networkRecoveryFingerprint='';
let networkRecoveryRequestSequence=0;
let networkLifecycleGeneration=0;
let networkWindowTransitionSequence=0;
let networkLastDepartureSequence=0;
let networkLastReturnSequence=0;
const NETWORK_RECOVERY_RETURN_TIMEOUT_MS=120000;
let apiReady=true;
let currentTab='network';
let pendingNetworkMessage=null;
function networkSelectedDevice(){return null;}
'''
        exercise = r'''
showNetworkFailure({
  code:'permission_denied', source:'bonjour',
  recovery:{...NETWORK_RECOVERY_BY_CODE.permission_denied,generation:3}
}, 'fallback');
const permission={
  bannerHidden:nodes['network-error'].hidden,
  body:nodes['network-error-copy'].textContent,
  buttonHidden:nodes['network-recovery-btn'].hidden,
  button:nodes['network-recovery-btn'].textContent,
  code:networkRecoveryContext.code,
  kind:networkRecoveryContext.recovery.kind,
  action:networkRecoveryContext.recovery.action,
  target:networkRecoveryContext.recovery.target,
  generation:networkRecoveryContext.recovery.generation
};
showNetworkFailure({code:'future_connection_error',source:'future'}, 'A future connection failed.');
const future={
  bannerHidden:nodes['network-error'].hidden,
  body:nodes['network-error-copy'].textContent,
  buttonHidden:nodes['network-recovery-btn'].hidden,
  button:nodes['network-recovery-btn'].textContent,
  buttonDisabled:nodes['network-recovery-btn'].disabled,
  hasContext:Boolean(networkRecoveryContext)
};
showNetworkFailure({
  code:'permission_denied',source:'bonjour',
  recovery:{...NETWORK_RECOVERY_BY_CODE.permission_denied,generation:'3'}
});
console.log(JSON.stringify({
  permission,
  future,
  malformed:{
    bannerHidden:nodes['network-error'].hidden,
    body:nodes['network-error-copy'].textContent,
    buttonHidden:nodes['network-recovery-btn'].hidden,
    button:nodes['network-recovery-btn'].textContent,
    buttonDisabled:nodes['network-recovery-btn'].disabled,
    hasContext:Boolean(networkRecoveryContext)
  }
}));
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, error_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        permission = result["permission"]
        self.assertFalse(permission["bannerHidden"])
        self.assertEqual(permission["body"], "Local Network access is unavailable. Check macOS privacy settings and try again.")
        self.assertFalse(permission["buttonHidden"])
        self.assertEqual(permission["button"], "Fix access")
        self.assertEqual(permission["code"], "permission_denied")
        self.assertEqual(permission["kind"], "settings")
        self.assertEqual(permission["action"], "open-local-network-settings")
        self.assertEqual(permission["target"], "local-network-permission")
        self.assertEqual(permission["generation"], 3)
        self.assertFalse(result["future"]["bannerHidden"])
        self.assertFalse(result["future"]["buttonHidden"])
        self.assertTrue(result["future"]["buttonDisabled"])
        self.assertEqual(result["future"]["button"], "Manual review required")
        self.assertFalse(result["future"]["hasContext"])
        self.assertFalse(result["malformed"]["bannerHidden"])
        self.assertFalse(result["malformed"]["buttonHidden"])
        self.assertTrue(result["malformed"]["buttonDisabled"])
        self.assertEqual(result["malformed"]["button"], "Manual review required")
        self.assertFalse(result["malformed"]["hasContext"])

    def test_connection_inventory_warning_is_non_tcc_low_priority_and_retryable_in_composed_ui(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        error_region = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function networkDeviceGlyph", 1)[0]
        harness = r'''
class FakeNode {
  constructor(){this.textContent='';this.hidden=true;this.disabled=false;this.attributes={};}
  addEventListener(){}
  setAttribute(name,value){this.attributes[name]=String(value);}
  scrollIntoView(){}
  focus(){}
}
const nodes={};
const document={getElementById:id => (nodes[id] ||= new FakeNode())};
let networkRecoveryContext=null;
let networkRecoveryInFlight=false;
let networkRecoveryWatcher=null;
let networkRecoveryErrorGeneration=0;
let networkRecoveryFingerprint='';
let networkRecoveryRequestSequence=0;
let networkLifecycleGeneration=0;
let networkWindowTransitionSequence=0;
let networkLastDepartureSequence=0;
let networkLastReturnSequence=0;
const NETWORK_RECOVERY_RETURN_TIMEOUT_MS=120000;
let apiReady=true;
let currentTab='network';
let pendingNetworkMessage=null;
function networkSelectedDevice(){return null;}
'''
        exercise = r'''
showNetworkFailure({
  code:'connections_unavailable',source:'connections',
  recovery:{...NETWORK_RECOVERY_BY_CODE.connections_unavailable,generation:5}
});
console.log(JSON.stringify({
  body:nodes['network-error-copy'].textContent,
  button:nodes['network-recovery-btn'].textContent,
  tone:nodes['network-error'].attributes['data-tone'],
  context:networkRecoveryContext
}));
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, error_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        self.assertEqual(result["tone"], "warning")
        self.assertEqual(result["button"], "Retry connections")
        self.assertEqual(result["context"]["code"], "connections_unavailable")
        self.assertEqual(result["context"]["source"], "connections")
        self.assertEqual(result["context"]["recovery"]["action"], "retry-connections")
        self.assertEqual(result["context"]["recovery"]["target"], "active-connections")
        self.assertLess(result["context"]["recovery"]["priority"], 50)
        self.assertEqual(
            result["body"],
            "Connection activity details are unavailable. Device discovery is still working with other available local signals.",
        )
        for internal_label in ("ARP", "NDP", "ICMP", "Bonjour", "SSDP"):
            self.assertNotIn(internal_label, result["body"])
        self.assertNotIn("privacy", result["body"].lower())
        self.assertNotIn("settings", result["body"].lower())

    def test_backend_error_envelope_preserves_valid_recovery_metadata(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        error_region = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function networkDeviceGlyph", 1)[0]
        harness = r'''
class FakeNode {
  constructor(){this.textContent='';this.hidden=true;this.disabled=false;this.classList={toggle(){}};}
  setAttribute(){}
  scrollIntoView(){}
  focus(){}
}
const nodes={};
const document={getElementById:id => (nodes[id] ||= new FakeNode())};
let networkRecoveryContext=null;
let networkRecoveryInFlight=false;
let networkRecoveryWatcher=null;
let networkRecoveryErrorGeneration=0;
let networkRecoveryFingerprint='';
let networkRecoveryRequestSequence=0;
let networkLifecycleGeneration=3;
let networkWindowTransitionSequence=0;
let networkLastDepartureSequence=0;
let networkLastReturnSequence=0;
const NETWORK_RECOVERY_RETURN_TIMEOUT_MS=120000;
let apiReady=true;
let currentTab='network';
let pendingNetworkMessage=null;
function networkSelectedDevice(){return null;}
'''
        exercise = r'''
const detail={
  code:'permission_denied',source:'bonjour',observedAt:'2026-08-24T12:00:00Z',
  recovery:{...NETWORK_RECOVERY_BY_CODE.permission_denied,generation:7}
};
showNetworkFailure(networkFailure({ok:false,code:'permission_denied',error:'safe',errorDetail:detail}));
console.log(JSON.stringify({
  code:networkRecoveryContext?.code,
  source:networkRecoveryContext?.source,
  action:networkRecoveryContext?.recovery?.action,
  generation:networkRecoveryContext?.recovery?.generation,
  button:nodes['network-recovery-btn'].textContent,
  disabled:nodes['network-recovery-btn'].disabled
}));
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, error_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        self.assertEqual(result["code"], "permission_denied")
        self.assertEqual(result["source"], "bonjour")
        self.assertEqual(result["action"], "open-local-network-settings")
        self.assertEqual(result["generation"], 7)
        self.assertEqual(result["button"], "Fix access")
        self.assertFalse(result["disabled"])

    def test_permission_return_watcher_requires_departure_is_single_use_and_cancels(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        error_region = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function networkDeviceGlyph", 1)[0]
        harness = r'''
class FakeNode {
  constructor(){
    this.textContent='';this.hidden=false;this.disabled=false;
    this.classList={toggle(){}};
  }
  setAttribute(){}
  scrollIntoView(){}
  focus(){}
}
const nodes={};
const document={getElementById:id => (nodes[id] ||= new FakeNode())};
let timerId=0;
const timers=new Map();
function setTimeout(fn,delay){const id=++timerId;timers.set(id,{fn,delay});return id;}
function clearTimeout(id){timers.delete(id);}
let networkRecoveryContext=null;
let networkRecoveryInFlight=false;
let networkRecoveryWatcher=null;
let networkRecoveryErrorGeneration=4;
let networkRecoveryFingerprint='';
let networkRecoveryRequestSequence=0;
let networkLifecycleGeneration=7;
let networkWindowTransitionSequence=0;
let networkLastDepartureSequence=0;
let networkLastReturnSequence=0;
const NETWORK_RECOVERY_RETURN_TIMEOUT_MS=120000;
let apiReady=true;
let currentTab='network';
let pendingNetworkMessage=null;
function networkSelectedDevice(){return null;}
'''
        exercise = r'''
const context={
  code:'permission_denied',source:'bonjour',deviceId:null,
  recovery:{...NETWORK_RECOVERY_BY_CODE.permission_denied,generation:2},
  errorGeneration:4,lifecycleGeneration:7
};
const calls=[];
repairNetworkConnection=(afterSettings,suppliedContext) => calls.push({afterSettings,suppliedContext});
armNetworkRecoveryReturnWatcher(context,networkWindowTransitionSequence);
noteNetworkRecoveryReturn();
const beforeDeparture=calls.length;
noteNetworkRecoveryDeparture();
noteNetworkRecoveryReturn();
noteNetworkRecoveryReturn();
const afterReturn={calls:calls.length,afterSettings:calls[0]?.afterSettings,watcher:networkRecoveryWatcher};

armNetworkRecoveryReturnWatcher(context,networkWindowTransitionSequence);
const timeoutEntry=[...timers.entries()].find(([_id,item]) => item.delay === NETWORK_RECOVERY_RETURN_TIMEOUT_MS);
timers.delete(timeoutEntry[0]);
const timeout=timeoutEntry[1];
timeout.fn();
const afterTimeout={watcher:networkRecoveryWatcher,feedback:nodes['network-action-feedback'].textContent};

armNetworkRecoveryReturnWatcher(context,networkWindowTransitionSequence);
cancelNetworkRecoveryWatcher();
const afterCancel={watcher:networkRecoveryWatcher,timers:timers.size};
console.log(JSON.stringify({beforeDeparture,afterReturn,afterTimeout,afterCancel}));
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, error_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        self.assertEqual(result["beforeDeparture"], 0)
        self.assertEqual(result["afterReturn"]["calls"], 1)
        self.assertTrue(result["afterReturn"]["afterSettings"])
        self.assertIsNone(result["afterReturn"]["watcher"])
        self.assertIsNone(result["afterTimeout"]["watcher"])
        self.assertIn("expired", result["afterTimeout"]["feedback"])
        self.assertIsNone(result["afterCancel"]["watcher"])
        self.assertEqual(result["afterCancel"]["timers"], 0)

    def test_permission_handoff_keeps_return_watcher_armed_and_runs_one_recheck(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        error_region = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function networkDeviceGlyph", 1)[0]
        harness = r'''
class FakeNode {
  constructor(){this.textContent='';this.hidden=false;this.disabled=false;this.classList={toggle(){}};}
  setAttribute(){}
  scrollIntoView(){}
  focus(){}
}
const nodes={};
const document={getElementById:id => (nodes[id] ||= new FakeNode())};
let timerId=0;
const timers=new Map();
function setTimeout(fn,delay){const id=++timerId;timers.set(id,{fn,delay});return id;}
function clearTimeout(id){timers.delete(id);}
let networkRecoveryContext=null;
let networkRecoveryInFlight=false;
let networkRecoveryWatcher=null;
let networkRecoveryErrorGeneration=0;
let networkRecoveryFingerprint='';
let networkRecoveryRequestSequence=0;
let networkLifecycleGeneration=5;
let networkWindowTransitionSequence=0;
let networkLastDepartureSequence=0;
let networkLastReturnSequence=0;
const NETWORK_RECOVERY_RETURN_TIMEOUT_MS=120000;
let apiReady=true;
let currentTab='network';
let pendingNetworkMessage=null;
let lastNetworkSnapshot=null;
function networkSelectedDevice(){return null;}
function bridgeJson(value){return value;}
function scheduleRefresh(){}
function renderNetworkSnapshot(){}
async function loadNetworkSnapshot(){}
const bridgeCalls=[];
const pywebview={api:{recover_network_connection:async (...args) => {
  bridgeCalls.push(args);
  return bridgeCalls.length === 1
    ? {ok:true,state:'waiting-for-user'}
    : {ok:true,state:'rechecking',snapshot:{ok:true}};
}}};
'''
        exercise = r'''
(async () => {
  showNetworkFailure({
    code:'permission_denied',source:'bonjour',observedAt:'2026-08-24T12:00:00Z',
    recovery:{...NETWORK_RECOVERY_BY_CODE.permission_denied,generation:3}
  });
  const originalGeneration=networkRecoveryErrorGeneration;
  const originalBody=nodes['network-error-copy'].textContent;
  await repairNetworkConnection(false);
  const armed={
    watcher:Boolean(networkRecoveryWatcher),
    generation:networkRecoveryErrorGeneration,
    body:nodes['network-error-copy'].textContent,
    feedback:nodes['network-action-feedback'].textContent,
    calls:bridgeCalls.length
  };
  noteNetworkRecoveryDeparture();
  noteNetworkRecoveryReturn();
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  console.log(JSON.stringify({
    originalGeneration,originalBody,armed,
    returned:{watcher:Boolean(networkRecoveryWatcher),calls:bridgeCalls.length,afterSettings:bridgeCalls[1]?.[3]}
  }));
})().catch(error => { console.error(error); process.exit(1); });
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, error_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        self.assertTrue(result["armed"]["watcher"])
        self.assertEqual(result["armed"]["generation"], result["originalGeneration"])
        self.assertEqual(result["armed"]["body"], result["originalBody"])
        self.assertIn("return here", result["armed"]["feedback"])
        self.assertEqual(result["armed"]["calls"], 1)
        self.assertFalse(result["returned"]["watcher"])
        self.assertEqual(result["returned"]["calls"], 2)
        self.assertTrue(result["returned"]["afterSettings"])

    def test_current_highest_priority_error_advances_to_the_next_recovery(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        error_region = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function networkDeviceGlyph", 1)[0]
        current_region = "function networkCurrentErrors" + script.split("function networkCurrentErrors", 1)[1].split("function renderNetworkSnapshot", 1)[0]
        render_region = "function renderNetworkSnapshot" + script.split("function renderNetworkSnapshot", 1)[1].split("function renderNetworkDeviceList", 1)[0]
        harness = r'''
class FakeNode {
  constructor(){this.textContent='';this.hidden=false;this.disabled=false;this.classList={toggle(){}};}
  setAttribute(){}
  focus(){}
}
const nodes={};
const document={getElementById:id => (nodes[id] ||= new FakeNode())};
let networkRecoveryContext=null;
let networkRecoveryInFlight=false;
let networkRecoveryWatcher=null;
let networkRecoveryErrorGeneration=0;
let networkRecoveryFingerprint='';
let networkRecoveryRequestSequence=0;
let networkLifecycleGeneration=2;
let networkWindowTransitionSequence=0;
let networkLastDepartureSequence=0;
let networkLastReturnSequence=0;
const NETWORK_RECOVERY_RETURN_TIMEOUT_MS=120000;
let apiReady=true;
let currentTab='network';
let pendingNetworkMessage=null;
let lastNetworkSnapshot=null;
let selectedNetworkDeviceId=null;
let internetOptimizerErrorDetail=null;
function networkSelectedDevice(){return null;}
function renderNetworkLink(){}
function renderNetworkDeviceList(){}
function renderNetworkDeviceDetail(){}
'''
        exercise = r'''
const permission={code:'permission_denied',source:'bonjour',observedAt:'2026-08-24T12:00:02Z',recovery:{...NETWORK_RECOVERY_BY_CODE.permission_denied,generation:4}};
const discovery={code:'discovery_unavailable',source:'discovery',observedAt:'2026-08-24T12:00:01Z',recovery:{...NETWORK_RECOVERY_BY_CODE.discovery_unavailable,generation:4}};
const newerDiscovery={...discovery,observedAt:'2026-08-24T12:00:03Z'};
const base={ok:true,active:true,counts:{},local:{interfaces:[]},coverage:{},scan:{},devices:[],link:{errors:[]}};
renderNetworkSnapshot({...base,errors:[discovery,permission]});
const first={body:nodes['network-error-copy'].textContent,button:nodes['network-recovery-btn'].textContent,code:networkRecoveryContext?.code};
renderNetworkSnapshot({...base,errors:[discovery,newerDiscovery]});
const second={body:nodes['network-error-copy'].textContent,button:nodes['network-recovery-btn'].textContent,code:networkRecoveryContext?.code,observedAt:networkRecoveryContext?.observedAt};
console.log(JSON.stringify({first,second}));
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, error_region, current_region, render_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        self.assertEqual(result["first"]["code"], "permission_denied")
        self.assertEqual(result["first"]["button"], "Fix access")
        self.assertIn("Local Network access", result["first"]["body"])
        self.assertIn("temporarily unavailable", result["first"]["body"])
        self.assertEqual(result["second"]["code"], "discovery_unavailable")
        self.assertEqual(result["second"]["button"], "Retry discovery")
        self.assertEqual(result["second"]["observedAt"], "2026-08-24T12:00:03Z")
        self.assertNotIn("Local Network access", result["second"]["body"])

    def test_uncertain_message_recovery_only_focuses_safe_retry_and_preserves_id(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        error_region = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function networkDeviceGlyph", 1)[0]
        harness = r'''
class FakeNode {
  constructor(){this.textContent='';this.hidden=false;this.disabled=false;this.focused=false;this.classList={toggle(){}};}
  setAttribute(){}
  scrollIntoView(){}
  focus(){this.focused=true;}
}
const nodes={};
const document={getElementById:id => (nodes[id] ||= new FakeNode())};
let networkRecoveryContext=null;
let networkRecoveryInFlight=false;
let networkRecoveryWatcher=null;
let networkRecoveryErrorGeneration=0;
let networkRecoveryFingerprint='';
let networkRecoveryRequestSequence=0;
let networkLifecycleGeneration=8;
let networkWindowTransitionSequence=0;
let networkLastDepartureSequence=0;
let networkLastReturnSequence=0;
const NETWORK_RECOVERY_RETURN_TIMEOUT_MS=120000;
let apiReady=true;
let currentTab='network';
let pendingNetworkMessage={deviceId:'device-7',body:'same body',clientMessageId:'fixed-message-id',state:'uncertain-after-send'};
function networkSelectedDevice(){return {id:'device-7'};}
let bridgeCalls=0;
const pywebview={api:{recover_network_connection:async () => {bridgeCalls += 1; return {ok:true};}}};
'''
        exercise = r'''
(async () => {
  showNetworkFailure({
    code:'message_delivery_uncertain',source:'message',observedAt:'2026-08-24T12:00:00Z',
    recovery:{...NETWORK_RECOVERY_BY_CODE.message_delivery_uncertain,generation:6}
  });
  const before=JSON.stringify(pendingNetworkMessage);
  await repairNetworkConnection(false);
  console.log(JSON.stringify({
    unchanged:before === JSON.stringify(pendingNetworkMessage),
    bridgeCalls,
    focused:nodes['network-message-btn'].focused,
    feedback:nodes['network-action-feedback'].textContent
  }));
})().catch(error => { console.error(error); process.exit(1); });
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, error_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        self.assertTrue(result["unchanged"])
        self.assertEqual(result["bridgeCalls"], 0)
        self.assertTrue(result["focused"])
        self.assertIn("never sends", result["feedback"])

    def test_async_peer_failure_and_recovery_stay_bound_to_origin_device(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        error_region = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function networkDeviceGlyph", 1)[0]
        verify_region = "async function verifySelectedNetworkPeer" + script.split("async function verifySelectedNetworkPeer", 1)[1].split("async function revokeSelectedNetworkPeer", 1)[0]
        harness = r'''
class FakeNode {
  constructor(){this.textContent='';this.hidden=false;this.disabled=false;this.classList={toggle(){}};}
  setAttribute(){}
  scrollIntoView(){}
  focus(){}
}
const nodes={};
const document={getElementById:id => (nodes[id] ||= new FakeNode())};
let networkRecoveryContext=null;
let networkRecoveryInFlight=false;
let networkRecoveryWatcher=null;
let networkRecoveryErrorGeneration=0;
let networkRecoveryFingerprint='';
let networkRecoveryRequestSequence=0;
let networkLifecycleGeneration=9;
let networkWindowTransitionSequence=0;
let networkLastDepartureSequence=0;
let networkLastReturnSequence=0;
const NETWORK_RECOVERY_RETURN_TIMEOUT_MS=120000;
let apiReady=true;
let currentTab='network';
let pendingNetworkMessage=null;
let selectedNetworkDeviceId='device-a';
const devices=[{id:'device-a',paired:true},{id:'device-b',paired:true}];
function networkSelectedDevice(){return devices.find(item => item.id === selectedNetworkDeviceId) || null;}
function bridgeJson(value){return value;}
async function loadNetworkSnapshot(){}
function scheduleRefresh(){}
let settleVerify;
let missingOrigin=false;
let repeatFailure=false;
const recoveryCalls=[];
const pywebview={api:{
  verify_network_peer:() => new Promise(resolve => {settleVerify=resolve;}),
  recover_network_connection:async (...args) => {
    recoveryCalls.push(args);
    if (missingOrigin) return {
      ok:false,code:'device_not_found',
      errorDetail:{
        code:'device_not_found',source:'recovery',observedAt:'2026-08-24T12:00:01Z',
        recovery:{...NETWORK_RECOVERY_BY_CODE.device_not_found,generation:6}
      }
    };
    if (repeatFailure) return {
      ok:false,code:'peer_unreachable',
      errorDetail:{
        code:'peer_unreachable',source:'message',observedAt:'2026-08-24T12:00:03Z',
        recovery:{...NETWORK_RECOVERY_BY_CODE.peer_unreachable,generation:6}
      }
    };
    return {ok:true,state:'peer-ready'};
  }
}};
'''
        exercise = r'''
(async () => {
  const operation=verifySelectedNetworkPeer();
  selectedNetworkDeviceId='device-b';
  settleVerify({
    ok:false,code:'peer_unreachable',
    errorDetail:{
      code:'peer_unreachable',source:'message',observedAt:'2026-08-24T12:00:00Z',
      recovery:{...NETWORK_RECOVERY_BY_CODE.peer_unreachable,generation:6}
    }
  });
  await operation;
  const afterFailure={selected:selectedNetworkDeviceId,contextDevice:networkRecoveryContext?.deviceId};
  await repairNetworkConnection(false);
  setNetworkFailureFeedback({
    code:'peer_unreachable',source:'message',observedAt:'2026-08-24T12:00:02Z',
    recovery:{...NETWORK_RECOVERY_BY_CODE.peer_unreachable,generation:6}
  }, 'Secure session verification failed.', 'device-a');
  repeatFailure=true;
  await repairNetworkConnection(false);
  const repeatedFailureContextDevice=networkRecoveryContext?.deviceId;
  const repeatedFailureCode=networkRecoveryContext?.code;
  const repeatedFailureButton=nodes['network-recovery-btn'].textContent;
  await repairNetworkConnection(false);
  setNetworkFailureFeedback({
    code:'peer_unreachable',source:'message',observedAt:'2026-08-24T12:00:04Z',
    recovery:{...NETWORK_RECOVERY_BY_CODE.peer_unreachable,generation:6}
  }, 'Secure session verification failed.', 'device-a');
  devices.splice(0,1);
  repeatFailure=false;
  missingOrigin=true;
  await repairNetworkConnection(false);
  console.log(JSON.stringify({
    afterFailure,
    recoveryDevice:recoveryCalls[0]?.[2],
    recoveryGeneration:recoveryCalls[0]?.[4],
    repeatedFailureRecoveryDevice:recoveryCalls[1]?.[2],
    repeatedFailureContextDevice,
    repeatedFailureCode,
    repeatedFailureButton,
    nextRepeatedRecoveryDevice:recoveryCalls[2]?.[2],
    removedOriginRecoveryDevice:recoveryCalls[3]?.[2],
    removedOriginDidNotSubstituteB:networkRecoveryContext?.deviceId !== 'device-b',
    removedOriginCode:networkRecoveryContext?.code
  }));
})().catch(error => { console.error(error); process.exit(1); });
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, error_region, verify_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=False, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["afterFailure"]["selected"], "device-b")
        self.assertEqual(result["afterFailure"]["contextDevice"], "device-a")
        self.assertEqual(result["recoveryDevice"], "device-a")
        self.assertEqual(result["recoveryGeneration"], 6)
        self.assertEqual(result["repeatedFailureRecoveryDevice"], "device-a")
        self.assertEqual(result["repeatedFailureContextDevice"], "device-a")
        self.assertEqual(result["repeatedFailureCode"], "peer_unreachable")
        self.assertEqual(result["repeatedFailureButton"], "Reconnect peer")
        self.assertEqual(result["nextRepeatedRecoveryDevice"], "device-a")
        self.assertEqual(result["removedOriginRecoveryDevice"], "device-a")
        self.assertTrue(result["removedOriginDidNotSubstituteB"])
        self.assertEqual(result["removedOriginCode"], "device_not_found")

    def test_rejected_recovery_cannot_overwrite_newer_error_or_exited_tab(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        error_region = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function networkDeviceGlyph", 1)[0]
        harness = r'''
class FakeNode {
  constructor(){this.textContent='';this.hidden=false;this.disabled=false;this.focused=false;this.classList={toggle(){}};}
  setAttribute(){}
  scrollIntoView(){}
  focus(){this.focused=true;}
}
const nodes={};
const document={getElementById:id => (nodes[id] ||= new FakeNode())};
let networkRecoveryContext=null;
let networkRecoveryInFlight=false;
let networkRecoveryWatcher=null;
let networkRecoveryErrorGeneration=0;
let networkRecoveryFingerprint='';
let networkRecoveryRequestSequence=0;
let networkLifecycleGeneration=4;
let networkWindowTransitionSequence=0;
let networkLastDepartureSequence=0;
let networkLastReturnSequence=0;
const NETWORK_RECOVERY_RETURN_TIMEOUT_MS=120000;
let apiReady=true;
let currentTab='network';
let pendingNetworkMessage=null;
function networkSelectedDevice(){return {id:'device-a'};}
function bridgeJson(value){return value;}
async function loadNetworkSnapshot(){}
function scheduleRefresh(){}
let rejectRecovery;
const pywebview={api:{
  recover_network_connection:() => new Promise((_resolve,reject) => {rejectRecovery=reject;})
}};
'''
        exercise = r'''
(async () => {
  setNetworkFailureFeedback({
    code:'peer_unreachable',source:'message',observedAt:'2026-08-24T12:00:00Z',
    recovery:{...NETWORK_RECOVERY_BY_CODE.peer_unreachable,generation:6}
  }, 'Secure session verification failed.', 'device-a');
  const superseded=repairNetworkConnection(false);
  setNetworkFailureFeedback({
    code:'permission_denied',source:'bonjour',observedAt:'2026-08-24T12:00:01Z',
    recovery:{...NETWORK_RECOVERY_BY_CODE.permission_denied,generation:7}
  }, 'Local Network access is unavailable.', null);
  rejectRecovery(networkFailure({
    ok:false,code:'peer_unreachable',
    errorDetail:{
      code:'peer_unreachable',source:'message',observedAt:'2026-08-24T12:00:02Z',
      recovery:{...NETWORK_RECOVERY_BY_CODE.peer_unreachable,generation:6}
    }
  }));
  await superseded;
  const newerError={
    code:networkRecoveryContext?.code,
    deviceId:networkRecoveryContext?.deviceId || null,
    button:nodes['network-recovery-btn'].textContent,
    body:nodes['network-error-copy'].textContent
  };

  setNetworkFailureFeedback({
    code:'peer_unreachable',source:'message',observedAt:'2026-08-24T12:00:03Z',
    recovery:{...NETWORK_RECOVERY_BY_CODE.peer_unreachable,generation:6}
  }, 'Secure session verification failed.', 'device-a');
  const beforeExit={
    code:networkRecoveryContext?.code,
    deviceId:networkRecoveryContext?.deviceId,
    body:nodes['network-error-copy'].textContent,
    fingerprint:networkRecoveryFingerprint
  };
  const exited=repairNetworkConnection(false);
  currentTab='cpu';
  networkLifecycleGeneration += 1;
  networkRecoveryRequestSequence += 1;
  rejectRecovery(networkFailure({
    ok:false,code:'permission_denied',
    errorDetail:{
      code:'permission_denied',source:'bonjour',observedAt:'2026-08-24T12:00:04Z',
      recovery:{...NETWORK_RECOVERY_BY_CODE.permission_denied,generation:7}
    }
  }));
  await exited;
  console.log(JSON.stringify({
    newerError,
    beforeExit,
    afterExit:{
      code:networkRecoveryContext?.code,
      deviceId:networkRecoveryContext?.deviceId,
      body:nodes['network-error-copy'].textContent,
      fingerprint:networkRecoveryFingerprint
    },
    inFlight:networkRecoveryInFlight
  }));
})().catch(error => { console.error(error); process.exit(1); });
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, error_region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=False, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["newerError"]["code"], "permission_denied")
        self.assertIsNone(result["newerError"]["deviceId"])
        self.assertEqual(result["newerError"]["button"], "Fix access")
        self.assertIn("Local Network access", result["newerError"]["body"])
        self.assertEqual(result["afterExit"], result["beforeExit"])
        self.assertFalse(result["inFlight"])

    def test_final_composed_link_degrades_advertiser_and_hides_disabled_code(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        region = "function renderNetworkLink" + script.split("function renderNetworkLink", 1)[1].split("async function startNetworkDiscovery", 1)[0]
        harness = r'''
class FakeNode {
  constructor(){this.textContent='';this.hidden=false;this.disabled=false;this.children=[];this.className='';}
  append(...items){this.children.push(...items);}
  appendChild(item){this.children.push(item);return item;}
  addEventListener(){}
}
const nodes={};
const document={
  getElementById:id => (nodes[id] ||= new FakeNode()),
  createElement:_tag => new FakeNode()
};
function emptyNode(node){node.children=[];node.textContent='';}
function revokeTrustedNetworkPeer(){}
'''
        exercise = r'''
renderNetworkLink({enabled:false,advertising:false,pairing:{code:'SHOULD-NOT-RENDER'},trustedPeers:[]});
const disabled={hidden:nodes['network-pair-code'].hidden,text:nodes['network-pair-code'].textContent};
renderNetworkLink({enabled:true,advertising:false,pairing:null,pairedPeerCount:1,readyPeerCount:0,trustedPeers:[],boundary:'safe'});
console.log(JSON.stringify({disabled,status:nodes['ke-link-status'].textContent}));
'''
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write("\n".join((harness, region, exercise)))
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        self.assertTrue(result["disabled"]["hidden"])
        self.assertEqual(result["disabled"]["text"], "")
        self.assertIn("advertisement is unavailable", result["status"])
        for code in (
            "bonjour_advertisement_unavailable",
            "tls_identity_failed",
            "tls_unavailable",
        ):
            self.assertIn(code, script)

    def test_final_composed_html_separates_trust_liveness_and_ready_state(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        error_region = "const NETWORK_ERROR_COPY" + script.split("const NETWORK_ERROR_COPY", 1)[1].split("function showNetworkError", 1)[0]
        list_region = "function renderNetworkDeviceList" + script.split("function renderNetworkDeviceList", 1)[1].split("function networkActionButton", 1)[0]
        detail_region = "function renderNetworkDeviceDetail" + script.split("function renderNetworkDeviceDetail", 1)[1].split("function renderNetworkMessages", 1)[0]
        harness = r'''
class FakeNode {
  constructor(tag='div') { this.tag=tag; this.children=[]; this.className=''; this.hidden=false; this.disabled=false; this.style={}; this.dataset={}; this.textContent=''; this.classList={toggle:()=>{}}; }
  append(...items) { this.children.push(...items); }
  appendChild(item) { this.children.push(item); return item; }
  addEventListener() {}
  setAttribute(name,value) { this[name]=value; }
  get childElementCount() { return this.children.filter(item => item instanceof FakeNode).length; }
}
const nodes = {};
const document = {
  createElement: tag => new FakeNode(tag),
  createTextNode: text => ({textContent:String(text)}),
  getElementById: id => (nodes[id] ||= new FakeNode())
};
function emptyNode(node) { node.children=[]; node.textContent=''; }
function statusClass(value) { return String(value || 'unknown'); }
function networkDeviceGlyph() { return '◇'; }
function networkAge() { return 'now'; }
function networkActionButton(label) { const node=new FakeNode('button'); node.textContent=label; return node; }
function networkControlButton(label) { const node=new FakeNode('button'); node.textContent=label; return node; }
function verifySelectedNetworkPeer() {}
function revokeSelectedNetworkPeer() {}
function renderNetworkMessages() {}
let searchFilter='';
let networkDeviceFilter='all';
let selectedNetworkDeviceId='device-1';
let pendingNetworkMessage=null;
let lastNetworkSnapshot=null;
function findClass(node,name) {
  if (node && node.className === name) return node;
  for (const child of (node?.children || [])) { const found=findClass(child,name); if (found) return found; }
  return null;
}
function nodeText(node) { return [node?.textContent || '', ...(node?.children || []).map(nodeText)].join(''); }
'''
        exercise = r'''
const offline = {
  id:'device-1', name:'Trusted offline peer', type:'ke-peer', state:'offline', paired:true,
  remoteReady:false, linkPeerId:'peer-1', addresses:['192.168.1.9'], sources:['bonjour'],
  capabilities:['verify-link','revoke-peer'], services:[], ageSeconds:180
};
renderNetworkDeviceList({devices:[offline],scan:{}});
const listButton=nodes['network-device-list'].children[0];
const listState=nodeText(findClass(listButton,'network-device-state'));
const listTrust=nodeText(findClass(listButton,'network-device-trust'));
renderNetworkDeviceDetail(offline,{link:{messages:[]}});
const offlineResult={
  listState, listTrust,
  detailState:nodes['network-detail-state'].textContent,
  trustHidden:nodes['network-detail-trust'].hidden,
  readyHidden:nodes['network-detail-ready'].hidden,
  messageHidden:nodes['network-message-panel'].hidden,
  sendDisabled:nodes['network-message-btn'].disabled,
  actions:nodes['network-detail-actions'].children.map(node => node.textContent)
};
const ready={...offline,state:'online',remoteReady:true,capabilities:['message','revoke-peer']};
renderNetworkDeviceDetail(ready,{link:{messages:[]}});
const readyResult={
  detailState:nodes['network-detail-state'].textContent,
  trustHidden:nodes['network-detail-trust'].hidden,
  readyHidden:nodes['network-detail-ready'].hidden,
  messageHidden:nodes['network-message-panel'].hidden,
  sendDisabled:nodes['network-message-btn'].disabled
};
const safeError=networkErrorCopy({code:'network_internal_error',message:'/Users/alex/secret'});
const unknownError=networkErrorCopy({code:'not-a-real-code',message:'/Users/alex/secret'});
console.log(JSON.stringify({offlineResult,readyResult,safeError,unknownError}));
'''
        source = "\n".join((harness, error_region, list_region, detail_region, exercise))
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write(source)
            handle.flush()
            completed = subprocess.run(["node", handle.name], capture_output=True, text=True, check=True, timeout=5)
        result = json.loads(completed.stdout)
        offline = result["offlineResult"]
        self.assertEqual(offline["listState"], "offline")
        self.assertEqual(offline["listTrust"], "trusted")
        self.assertEqual(offline["detailState"], "offline")
        self.assertFalse(offline["trustHidden"])
        self.assertTrue(offline["readyHidden"])
        self.assertTrue(offline["messageHidden"])
        self.assertTrue(offline["sendDisabled"])
        self.assertEqual(offline["actions"], ["Verify secure session", "Revoke trust"])
        ready = result["readyResult"]
        self.assertEqual(ready["detailState"], "online")
        self.assertFalse(ready["trustHidden"])
        self.assertFalse(ready["readyHidden"])
        self.assertFalse(ready["messageHidden"])
        self.assertFalse(ready["sendDisabled"])
        self.assertNotIn("/Users/", result["safeError"] + result["unknownError"])

    def test_final_composed_html_has_stable_message_retry_and_safe_errors(self):
        script = activity_monitor.HTML.rsplit("<script>", 1)[1].split("</script>", 1)[0]
        network_region = script.split("const NETWORK_ERROR_COPY", 1)[1].split("function scheduleRefresh", 1)[0]
        self.assertIn("pendingNetworkMessage.clientMessageId", network_region)
        self.assertIn("uncertain-after-send", network_region)
        self.assertIn("Retry safely", network_region)
        self.assertIn("pywebview.api.verify_network_peer(device.id)", network_region)
        self.assertIn("pywebview.api.revoke_network_peer(device.id)", network_region)
        self.assertNotIn("String(error)", network_region)
        self.assertNotIn("device.paired ? 'paired'", network_region)
        self.assertNotIn("statusClass(device.paired", network_region)

    def test_package_declares_local_network_privacy_and_source_parity(self):
        root = Path(activity_monitor.__file__).resolve().parent
        spec = (root / "activity_monitor.spec").read_text(encoding="utf-8")
        package = (root / "package_app.zsh").read_text(encoding="utf-8")
        readme = (root / "docs" / "DESIGN.md").read_text(encoding="utf-8")
        self.assertIn("NSLocalNetworkUsageDescription", spec)
        self.assertIn("BONJOUR_SERVICE_ALLOWLIST", spec)
        self.assertNotIn('"_services._dns-sd._udp"', spec)
        self.assertIn("verify_network_plist", package)
        self.assertIn("verify_signer", package)
        self.assertIn('signing_label="ad hoc"', package)
        self.assertIn("KE Studios Local Code Signing", package)
        self.assertIn("prefers the exact `KE Studios Local Code Signing` identity", readme)
        self.assertIn("otherwise labels and applies an ad-hoc local signature", readme)
        self.assertIn("while the Network tab is open", network_fabric.LOCAL_NETWORK_USAGE_DESCRIPTION)
        self.assertIn("until you disable KE Link", network_fabric.LOCAL_NETWORK_USAGE_DESCRIPTION)
        self.assertIn('(os.path.join(ROOT, "network_fabric.py"), "source")', spec)
        self.assertIn('(os.path.join(ROOT, "network_optimizer.py"), "source")', spec)
        compile_line = next(line for line in package.splitlines() if " -m py_compile " in line)
        self.assertIn("network_fabric.py", compile_line)
        self.assertIn("network_optimizer.py", compile_line)
        self.assertIn('cmp network_fabric.py "$bundle/Contents/Resources/source/network_fabric.py"', package)
        self.assertIn('cmp network_optimizer.py "$bundle/Contents/Resources/source/network_optimizer.py"', package)
        self.assertIn("Speed Up My Internet", readme)
        self.assertIn("never reads, projects, displays, or persists nearby SSID or BSSID values", readme)


if __name__ == "__main__":
    unittest.main()
