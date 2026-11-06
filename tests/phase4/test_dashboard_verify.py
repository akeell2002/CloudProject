"""Dashboard checks use only stdlib: python -m unittest discover -s tests/phase4 -p test_dashboard_verify.py"""
import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

from dashboard.server import ClusterMonitor, configured_nodes, make_handler
from node.telemetry import EventLog, node_snapshot


def sample_node():
    return {
        "node_id": "fednode-0", "state": "LEADER", "epoch": 1,
        "quorum": 4, "last_sequence": 2, "reputations": [],
        "proposals": [], "blocked_domains": ["blocked.example"],
        "events": [{"id": "event-1", "timestamp": 100, "kind": "threat",
                    "source": "bad.example", "target": "fednode-0",
                    "message": "<script>alert(1)</script>"}],
    }


class DashboardTests(unittest.TestCase):
    def test_node_configuration_rejects_invalid_addresses(self):
        for raw in ("", "file:///data", "http://user:secret@localhost", "http://localhost/api",
                    "http://localhost?target=other", ",".join(["http://localhost"] * 33)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                configured_nodes(raw)
        self.assertEqual(len(configured_nodes()), 5)
        self.assertEqual(configured_nodes("http://localhost:8080/")[0]["address"], "http://localhost:8080")

    def test_events_are_bounded_and_restart_ids_do_not_collide(self):
        first = EventLog("fednode-0", limit=2)
        for i in range(3):
            first.record("vote", "a", "b", str(i), decision="APPROVE")
        events = first.snapshot()
        self.assertEqual([event["message"] for event in events], ["1", "2"])
        events[0]["message"] = "changed"
        self.assertEqual(first.snapshot()[0]["message"], "1")
        second = EventLog("fednode-0")
        second.record("vote", "a", "b", "new boot")
        self.assertNotEqual(first.snapshot()[0]["id"], second.snapshot()[0]["id"])

    def test_snapshot_excludes_keys_signatures_and_evidence(self):
        proposal = SimpleNamespace(
            proposal_id="p", target_domain="bad.example", reason=4, epoch=1,
            sequence_number=1, created_at=1, is_committed=False,
            approved_votes={"fednode-0": "SECRET_SIGNATURE"}, evidence_payload="SECRET_EVIDENCE",
        )
        engine = SimpleNamespace(telemetry=EventLog("fednode-0"),
                                 _lock=threading.Lock(), active_proposals={"p": proposal})
        service = SimpleNamespace(
            consensus=engine, config=SimpleNamespace(node_id="fednode-0", quorum_size=4,
                operational_mode="AUTOMATIC", private_key_hex="SECRET_PRIVATE_KEY"),
            leader=SimpleNamespace(is_current_leader=lambda: True, current_epoch=1),
            byzantine_mode="NONE", db=SimpleNamespace(get_latest_sequence_number=lambda: 0),
            reputation=SimpleNamespace(get_ledger=lambda: []),
            firewall=SimpleNamespace(get_blocked_domains=lambda: {"bad.example"}),
        )
        snapshot = node_snapshot(service)
        encoded = json.dumps(snapshot)
        self.assertNotIn("SECRET", encoded)
        self.assertEqual(snapshot["proposals"][0]["approvals"], ["fednode-0"])
        self.assertEqual(snapshot["blocked_domains"], ["bad.example"])

    def test_polling_offline_transition_and_last_known_bans(self):
        monitor = ClusterMonitor(configured_nodes("http://127.0.0.1:1"), timeout=.05)
        self.addCleanup(monitor.close)
        with patch.object(monitor, "_json", return_value=sample_node()):
            monitor.refresh()
            monitor.refresh()
        snapshot = monitor.snapshot()
        self.assertTrue(snapshot["nodes"][0]["online"])
        self.assertEqual(len(snapshot["events"]), 1)
        self.assertEqual(snapshot["bans"][0]["applied_on"], ["fednode-0"])
        with patch.object(monitor, "_json", side_effect=OSError("offline")):
            monitor.refresh()
        snapshot = monitor.snapshot()
        self.assertFalse(snapshot["nodes"][0]["online"])
        self.assertIn("last_seen", snapshot["nodes"][0])
        self.assertEqual(snapshot["bans"][0]["applied_on"], [])
        self.assertEqual(snapshot["bans"][0]["last_known_on"], ["fednode-0"])
        self.assertNotIn("proposals", snapshot["nodes"][0])

    def test_legacy_health_is_online_without_inventing_votes(self):
        monitor = ClusterMonitor(configured_nodes("http://127.0.0.1:1"))
        self.addCleanup(monitor.close)
        not_found = HTTPError("http://localhost/telemetry", 404, "old node", {}, None)
        with patch.object(monitor, "_json", side_effect=[not_found, {"node_id": "fednode-legacy"}]):
            monitor.refresh()
        not_found.close()
        node = monitor.snapshot()["nodes"][0]
        self.assertTrue(node["online"])
        self.assertFalse(node["telemetry_available"])
        self.assertEqual(node["state"], "UNKNOWN")
        self.assertEqual(monitor.snapshot()["bans"], [])

    def test_malformed_telemetry_does_not_crash_polling(self):
        monitor = ClusterMonitor(configured_nodes("http://127.0.0.1:1"))
        self.addCleanup(monitor.close)
        for response in ({}, {**sample_node(), "proposals": None},
                         {**sample_node(), "events": [{"timestamp": "invalid"}]},
                         {**sample_node(), "quorum": 0},
                         {**sample_node(), "blocked_domains": [None]}):
            with patch.object(monitor, "_json", return_value=response):
                monitor.refresh()
            self.assertFalse(monitor.snapshot()["nodes"][0]["online"])

    def test_real_http_collection_api_and_static_allowlist(self):
        class NodeHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(sample_node()).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        fake = ThreadingHTTPServer(("127.0.0.1", 0), NodeHandler)
        thread = threading.Thread(target=fake.serve_forever, daemon=True)
        thread.start()
        monitor = ClusterMonitor(configured_nodes(f"http://127.0.0.1:{fake.server_port}"))
        dashboard = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(monitor))
        dashboard_thread = threading.Thread(target=dashboard.serve_forever, daemon=True)
        dashboard_thread.start()
        try:
            monitor.refresh()
            base = f"http://127.0.0.1:{dashboard.server_port}"
            with urlopen(base + "/api/cluster") as response:
                data = json.load(response)
                self.assertEqual(data["nodes"][0]["node_id"], "fednode-0")
                self.assertEqual(data["events"][0]["source"], "bad.example")
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            for path in ("/", "/app.js", "/style.css"):
                with urlopen(base + path) as response:
                    self.assertEqual(response.status, 200)
                    self.assertTrue(response.read())
            for path in ("/server.py", "/../node/config.py", "/api/unknown", "/demo.js"):
                with self.assertRaises(HTTPError) as error:
                    urlopen(base + path)
                self.assertEqual(error.exception.code, 404)
                error.exception.close()
        finally:
            dashboard.shutdown()
            dashboard.server_close()
            fake.shutdown()
            fake.server_close()
            monitor.close()
            thread.join()
            dashboard_thread.join()


if __name__ == "__main__":
    unittest.main()
