"""Dashboard fix tests for task 3.4 (consensus-liveness-security-fix).

Covers settings validation before any I/O, revive sending only /fault, the operator token
header on /fault and /reputation, 403 handling on stop/revive, the token source, the runtime
trust helper, and a property over random online/quarantine assignments for the cluster
quorum_health signal. No live cluster ports are used; node I/O is replaced by a recording opener.
"""
import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import gc
import io
import json
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from hypothesis import HealthCheck, given, settings, strategies as st

import dashboard.control as control
from dashboard.control import Operator, load_operator_token
from dashboard.runtime import NODE_SCRIPT, ROOT
from dashboard.server import ClusterMonitor, configured_nodes

TOKEN = "dashboard-fix-operator-token-0123456789abcdef"
TOKEN_ENV = "FEDCONSENSUS_OPERATOR_TOKEN"
NODE_IDS = [f"fednode-{i}" for i in range(5)]
DASHBOARD_NODES = ",".join(f"http://fednode-{i}.invalid:{59080 + i}" for i in range(5))
OK_BODY = b'{"status": "OK", "node_id": "fednode-1", "byzantine_mode": "NONE"}'


class StubRuntime:
    """Non-runtime dashboard mode that records any fallback call."""
    kind = "docker"
    namespace = "default"

    def __init__(self):
        self.calls = []

    def capabilities(self):
        return {"kind": "docker", "available": False, "message": "No runtime in this test"}

    def fault(self, node_id, mode):
        self.calls.append(("fault", node_id, mode))
        return "runtime fault"

    def node_call(self, node_id, request):
        self.calls.append(("node_call", node_id, request))
        return {"score": request.get("score"), "quarantined": request.get("score", 100) < 30}

    def lifecycle(self, node_id, action):
        self.calls.append(("lifecycle", node_id, action))
        return "lifecycle"

    def ensure_forward(self, index):
        pass

    def close(self):
        pass


def recording_open(log, error_code=None):
    def fake_open(request, timeout=None):
        log.append({"url": request.full_url, "body": json.loads(request.data) if request.data else None,
                    "token": request.get_header("X-operator-token")})
        if error_code is not None:
            raise HTTPError(request.full_url, error_code, "error", {}, io.BytesIO(b"{}"))
        return io.BytesIO(OK_BODY)
    return fake_open


class OperatorFixTests(unittest.TestCase):
    def make_operator(self, token=TOKEN):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.monitor = ClusterMonitor(configured_nodes(DASHBOARD_NODES))
        self.addCleanup(self.monitor.close)
        self.runtime = StubRuntime()
        missing_env_file = Path(self.temp.name) / "missing.env"
        with patch.dict(os.environ), patch.object(control, "ENV_FILE", missing_env_file):
            os.environ.pop(TOKEN_ENV, None)
            if token:
                os.environ[TOKEN_ENV] = token
            self.operator = Operator(self.monitor, runtime=self.runtime,
                                     state_path=os.path.join(self.temp.name, "state.json"))
        self.operator.connected = True
        self.monitor._data["nodes"] = [{"node_id": n, "online": True, "reputations": []} for n in NODE_IDS]
        self.address = {n["node_id"]: n["address"] for n in self.monitor.nodes}

    def run_action(self, body, error_code=None):
        log = []
        with patch.object(self.monitor, "refresh"), \
                patch.object(self.operator.opener, "open", side_effect=recording_open(log, error_code)):
            result = self.operator.handle(body)
        return result, log

    def test_settings_rejects_unsupported_modes_before_any_io(self):
        self.make_operator()
        for fault in ("BOGUS", "HONEST", "CENSOR", "EQUIVOCATOR", "", 1, None, ["LIAR"], True):
            with self.subTest(fault=fault):
                with self.assertRaises(ValueError):
                    self.run_action({"action": "settings", "node": "fednode-1", "fault": fault})
        log = []
        with patch.object(self.monitor, "refresh"), \
                patch.object(self.operator.opener, "open", side_effect=recording_open(log)):
            with self.assertRaises(ValueError):
                self.operator.handle({"action": "settings", "node": "fednode-1", "fault": "BOGUS"})
        self.assertEqual(log, [])
        self.assertEqual(self.runtime.calls, [])

    def test_settings_sends_and_reports_normalised_mode(self):
        self.make_operator()
        result, log = self.run_action({"action": "settings", "node": "fednode-1", "fault": "  liar "})
        self.assertEqual([(e["url"], e["body"]) for e in log],
                         [(self.address["fednode-1"] + "/fault", {"mode": "LIAR"})])
        self.assertEqual(result["message"], "[fednode-1] Byzantine mode switched to: LIAR")

    def test_settings_runtime_fallback_gets_normalised_mode(self):
        self.make_operator()
        result, _ = self.run_action({"action": "settings", "node": "fednode-1", "fault": "forger"},
                                    error_code=503)
        self.assertEqual(self.runtime.calls, [("fault", "fednode-1", "FORGER")])

    def test_revive_sends_only_fault(self):
        self.make_operator()
        _, log = self.run_action({"action": "revive", "node": "fednode-2"})
        self.assertEqual([(e["url"], e["body"]) for e in log],
                         [(self.address["fednode-2"] + "/fault", {"mode": "NONE", "offline": False})])

    def test_token_header_on_fault_and_reputation(self):
        self.make_operator()
        logs = []
        for body in ({"action": "stop", "node": "fednode-1"},
                     {"action": "revive", "node": "fednode-1"},
                     {"action": "settings", "node": "fednode-1", "fault": "SILENT"},
                     {"action": "trust", "node": "fednode-1", "peer": "fednode-2", "score": 40, "scope": "all"}):
            logs += self.run_action(body)[1]
        self.assertEqual({e["url"].rsplit("/", 1)[1] for e in logs}, {"fault", "reputation"})
        self.assertTrue(logs)
        self.assertTrue(all(e["token"] == TOKEN for e in logs))

    def test_no_token_header_when_credential_missing(self):
        self.make_operator(token="")
        _, log = self.run_action({"action": "settings", "node": "fednode-1", "fault": "NONE"})
        self.assertIsNone(log[0]["token"])
        self.assertEqual(self.operator.state()["operator_credential"], "missing")

    def test_state_reports_credential_without_exposing_it(self):
        self.make_operator()
        state = self.operator.state()
        self.assertEqual(state["operator_credential"], "configured")
        self.assertNotIn(TOKEN, json.dumps(state))

    def test_stop_and_revive_map_403_to_runtime_error(self):
        self.make_operator()
        for action in ("stop", "revive"):
            with self.subTest(action):
                with self.assertRaises(RuntimeError) as caught:
                    self.run_action({"action": action, "node": "fednode-1"}, error_code=403)
                self.assertIn("operator credential", str(caught.exception))
                self.assertIn(TOKEN_ENV, str(caught.exception))
                self.assertNotIn(TOKEN, str(caught.exception))
        self.assertEqual(self.runtime.calls, [])

    def test_trust_falls_back_to_runtime_on_403(self):
        self.make_operator()
        result, _ = self.run_action({"action": "trust", "node": "fednode-1", "peer": "fednode-2",
                                     "score": 20}, error_code=403)
        self.assertEqual(self.runtime.calls,
                         [("node_call", "fednode-1", {"operation": "trust", "peer": "fednode-2", "score": 20})])
        self.assertEqual(result["outcomes"][0]["node_id"], "fednode-1")


class TokenSourceTests(unittest.TestCase):
    def test_env_var_wins_then_env_file(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            env_file = Path(temp) / ".env"
            env_file.write_text("OTHER=1\n# comment\nFEDCONSENSUS_OPERATOR_TOKEN=from-file-token\n",
                                encoding="utf-8")
            with patch.dict(os.environ):
                os.environ.pop(TOKEN_ENV, None)
                self.assertEqual(load_operator_token(env_file), "from-file-token")
                self.assertEqual(load_operator_token(Path(temp) / "absent.env"), "")
                os.environ[TOKEN_ENV] = "from-env-token"
                self.assertEqual(load_operator_token(env_file), "from-env-token")


class RuntimeTrustHelperTests(unittest.TestCase):
    def test_trust_operation_sets_absolute_score_and_anchor(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            env = {**os.environ, "DATA_DIR": temp}
            for score in (20, 55):
                completed = subprocess.run(
                    [sys.executable, "-B", "-c", NODE_SCRIPT], cwd=ROOT, env=env, check=True,
                    input=json.dumps({"operation": "trust", "peer": "fednode-3", "score": score}),
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(json.loads(completed.stdout), {"score": score, "quarantined": score < 30})
            conn = sqlite3.connect(os.path.join(temp, "wal.db"))
            try:
                row = conn.execute("SELECT trust_score, is_active, recovery_anchor_at FROM peer_reputation "
                                   "WHERE peer_id = 'fednode-3'").fetchone()
            finally:
                conn.close()
            gc.collect()
        self.assertEqual(row[0], 55)
        self.assertEqual(row[1], 1)
        self.assertGreater(row[2], 0)


def telemetry(node_id, reputations=(), proposals=()):
    return {"node_id": node_id, "state": "FOLLOWER", "epoch": 1, "quorum": 4, "last_sequence": 0,
            "operational_mode": "AUTOMATIC", "events": [], "proposals": list(proposals),
            "blocked_domains": [], "reputations": list(reputations)}


def rep(peer_id, score):
    return {"peer_id": peer_id, "trust_score": score, "violations_count": 0,
            "is_active": 0 if score < 30 else 1, "last_updated": 0}


def pending_proposal(domain):
    return {"proposal_id": "prop-1-9-" + domain, "domain": domain, "proposer": "fednode-0", "reason": 1,
            "epoch": 1, "sequence": 9, "created_at": int(time.time() * 1000), "committed": False,
            "latency_ms": 0, "threat_score": 0.9, "approvals": [], "quorum": 4, "observer": "fednode-0"}


def refresh_with(monitor, views, offline):
    addresses = {n["node_id"]: n["address"] for n in monitor.nodes}

    def fake_json(address):
        for node_id, base in addresses.items():
            if address.startswith(base):
                if node_id in offline:
                    raise URLError("node unreachable")
                return json.loads(json.dumps(views[node_id]))
        raise URLError("unknown address")
    with patch.object(monitor, "_json", side_effect=fake_json):
        monitor.refresh()
    return monitor.snapshot()


class ClusterQuorumHealthTests(unittest.TestCase):
    @settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(offline=st.sets(st.sampled_from(NODE_IDS)), flagged=st.sets(st.sampled_from(NODE_IDS)))
    def test_quorum_health_matches_online_and_quarantine_assignment(self, offline, flagged):
        """**Validates: Requirements 2.1, 2.2, 2.7**"""
        monitor = ClusterMonitor(configured_nodes(DASHBOARD_NODES))
        try:
            domain = "pending.lab.example"
            # Every node reports every flagged node (including itself) at trust 20.
            views = {n: telemetry(n, [rep(q, 20) for q in sorted(flagged)],
                                  [pending_proposal(domain)]) for n in NODE_IDS}
            data = refresh_with(monitor, views, offline)
        finally:
            monitor.close()
        online = set(NODE_IDS) - offline
        # A node is quarantined only when some *other* online observer reports it.
        quarantined = {q for q in flagged if online - {q}}
        eligible = set(NODE_IDS) - offline - quarantined
        health = data["quorum_health"]
        self.assertEqual(health["offline"], sorted(offline))
        self.assertEqual(health["quarantined"], sorted(quarantined))
        self.assertEqual(health["eligible_voters"], len(eligible))
        self.assertEqual(health["eligible"], sorted(eligible))
        self.assertEqual(health["quorum"], 4)  # reported by online nodes, else N - (N-1)//3
        self.assertIs(health["quorum_reachable"], len(eligible) >= 4)
        expected_pending = [domain] if online and len(eligible) < 4 else []
        self.assertEqual(health["pending_unreachable"], expected_pending)
        for node in data["nodes"]:
            self.assertNotIn(node["node_id"], node["quarantined_by"])
            self.assertEqual(node["quarantined"], node["node_id"] in quarantined)

    def test_tolerates_legacy_and_malformed_nodes(self):
        monitor = ClusterMonitor(configured_nodes(DASHBOARD_NODES))
        self.addCleanup(monitor.close)
        addresses = {n["node_id"]: n["address"] for n in monitor.nodes}

        def fake_json(address):
            node_id = next(n for n, base in addresses.items() if address.startswith(base))
            if node_id == "fednode-1":  # legacy node: no /telemetry, only /health
                if address.endswith("/telemetry"):
                    raise HTTPError(address, 404, "not found", {}, io.BytesIO(b"{}"))
                return {"node_id": "fednode-1", "status": "ok"}
            if node_id == "fednode-2":  # malformed telemetry
                return {"node_id": "fednode-2", "state": "FOLLOWER", "proposals": "nope"}
            return telemetry(node_id)
        with patch.object(monitor, "_json", side_effect=fake_json):
            monitor.refresh()
        health = monitor.snapshot()["quorum_health"]
        self.assertEqual(health["offline"], ["fednode-2"])
        self.assertEqual(health["quarantined"], [])
        self.assertEqual(health["eligible_voters"], 4)
        self.assertEqual(health["quorum"], 4)
        self.assertIs(health["quorum_reachable"], True)
        self.assertEqual(health["pending_unreachable"], [])


class StaticAssetTests(unittest.TestCase):
    def test_threat_label_id_and_no_inline_script(self):
        static = Path(ROOT) / "dashboard" / "static"
        html = (static / "index.html").read_text(encoding="utf-8")
        self.assertIn('<span id="threat-label">awaiting a decision</span>', html)
        self.assertNotIn("<script>", html)
        app = (static / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("innerHTML", app)
        self.assertIn("QUORUM UNREACHABLE (", app)
        self.assertIn("CONSENSUS CANNOT PROGRESS", app)
        self.assertIn(".quorum-unreachable", (static / "style.css").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
