"""Operator adapters exercise existing APIs; they do not patch backend source."""
import io
import json
import tempfile
import threading
import unittest
import importlib.util
import os
import socket
import subprocess
import sys
import gc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from dashboard.control import Operator
from dashboard.runtime import Runtime, NODE_SCRIPT
from dashboard.server import ClusterMonitor, configured_nodes, make_handler


class LabRuntime:
    kind = "docker"
    namespace = "default"

    def __init__(self):
        self.calls = []

    def capabilities(self):
        return {"kind": "docker", "available": True, "message": "Test runtime"}

    def node_call(self, node_id, request):
        self.calls.append((node_id, request))
        if request["operation"] == "trust":
            return {"score": request["score"], "quarantined": request["score"] < 30}
        if request["operation"] == "post":
            return {"http_status": 202, "status": "ACCEPTED"}
        raise RuntimeError("Signing not supplied in this fixture")

    def scale(self, count):
        if type(count) is not int or not 1 <= count <= 9:
            raise ValueError("Invalid count")
        self.calls.append(("scale", count))

    def lifecycle(self, node_id, action):
        self.calls.append((action, node_id))
        return "Runtime action completed"

    def ensure_forward(self, index):
        pass

    def close(self):
        pass


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runtime = LabRuntime()
        self.monitor = ClusterMonitor(configured_nodes())
        self.operator = Operator(self.monitor, runtime=self.runtime,
                                 state_path=Path(self.temp.name) / "state.json")
        self.operator.connected = True
        self.monitor._data["nodes"] = [
            {"node_id": f"fednode-{i}", "online": True, "reputations": []} for i in range(5)]
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.monitor.close)

    def test_trust_calls_only_existing_helper_and_rejects_invalid_input(self):
        with patch.object(self.monitor, "refresh"):
            result = self.operator.handle({"action": "trust", "node": "fednode-0",
                "peer": "fednode-2", "score": 20, "scope": "all"})
        self.assertEqual(len(result["outcomes"]), 5)
        self.assertTrue(all(call[1]["operation"] == "trust" for call in self.runtime.calls))
        self.assertTrue(all(call[1]["peer"] == "fednode-2" for call in self.runtime.calls))
        for score in (-1, 101, 1.5, True, "20"):
            with self.assertRaises(ValueError):
                self.operator.handle({"action": "trust", "node": "fednode-0",
                                      "peer": "fednode-2", "score": score})

    def test_runtime_scale_updates_observed_addresses_not_backend_membership(self):
        with patch.object(self.monitor, "refresh"):
            response = self.operator.handle({"action": "scale", "replicas": 7})
        self.assertEqual(len(self.monitor.nodes), 7)
        self.assertEqual(self.monitor.nodes[-1]["address"], "http://127.0.0.1:8086")
        self.assertEqual(self.runtime.calls, [("scale", 7)])
        self.assertIn("not been rewritten", response["message"])
        self.assertTrue(self.operator.state_path.exists())

    def test_missing_backend_apis_are_explicit(self):
        for action in ("leader", "sync"):
            with self.assertRaisesRegex(RuntimeError, "backend API"):
                self.operator.handle({"action": action})
        with self.assertRaisesRegex(RuntimeError, "origin-signature"):
            self.operator.handle({"action": "inject", "node": "fednode-0", "scenario": "false_flag"})
        self.assertEqual(self.runtime.calls, [])

    def test_internal_traffic_really_requests_a_post_from_the_selected_runtime(self):
        result = self.operator.handle({"action": "inject", "node": "fednode-1",
            "source": "internal", "source_node": "fednode-3", "scenario": "malware"})
        self.assertEqual(self.runtime.calls[0][0], "fednode-3")
        request = self.runtime.calls[0][1]
        self.assertEqual(request["receiver"], "fednode-1")
        self.assertIn("fednode-3.lab.example", request["payload"]["actor"])
        self.assertEqual(result["inbox_results"][0]["http_status"], 202)

    def test_external_403_is_observed_not_invented_as_a_ban(self):
        body = json.dumps({"status": "FLAGGED_FOR_CONSENSUS", "domain": "attack.example"}).encode()
        error = HTTPError("http://node/inbox", 403, "flagged", {}, io.BytesIO(body))
        with patch.object(self.operator.opener, "open", side_effect=error):
            result = self.operator.handle({"action": "inject", "node": "fednode-0",
                                          "scenario": "malware", "domain": "attack.example"})
        self.assertEqual(result["inbox_results"][0]["http_status"], 403)
        self.assertNotIn("banned", result)

    def test_csrf_origin_checks_and_disabled_demo_asset(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.monitor, self.operator))
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        opener = build_opener(ProxyHandler({}))
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            for headers in (
                {"Content-Type": "application/json"},
                {"Content-Type": "application/json", "X-CSRF-Token": self.operator.csrf,
                 "Origin": "https://untrusted.example"},
            ):
                with self.assertRaises(HTTPError) as caught:
                    opener.open(Request(base + "/api/actions", b'{"action":"connect"}', headers))
                self.assertEqual(caught.exception.code, 403)
                caught.exception.close()
            with opener.open(base + "/api/controls") as response:
                state = json.load(response)
            self.assertFalse(state["capabilities"]["leader"])
            with patch.object(self.operator, "handle", return_value={"message": "Observed"}):
                with opener.open(Request(base + "/api/actions", b'{"action":"connect"}',
                    {"Content-Type": "application/json", "X-CSRF-Token": self.operator.csrf})) as response:
                    self.assertEqual(json.load(response)["message"], "Observed")
            with self.assertRaises(HTTPError) as caught:
                opener.open(base + "/demo.js")
            self.assertEqual(caught.exception.code, 404)
            caught.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_runtime_uses_fixed_argument_lists_and_retains_env_file_during_create(self):
        runtime = Runtime("docker")
        seed = {"Image": "sha256:test", "Config": {
            "Env": ["NODE_ID=fednode-0", "PEER_ADDRESSES=unchanged", "DATA_DIR=/data"],
            "Labels": {"com.docker.compose.project": "cloudproject"}},
            "NetworkSettings": {"Networks": {"cloudproject_fedconsensus-net": {}}},
            "State": {"Running": True}}
        commands = []
        def inspect(node_id="fednode-0"):
            if node_id == "fednode-5":
                raise RuntimeError("Missing node")
            return seed
        def run(arguments, timeout=45):
            commands.append(arguments)
            if arguments[:2] == ["docker", "run"]:
                env_path = arguments[arguments.index("--env-file") + 1]
                self.assertTrue(Path(env_path).exists())
                self.assertIn("PEER_ADDRESSES=unchanged", Path(env_path).read_text())
                self.assertIn("NODE_ID=fednode-5", Path(env_path).read_text())
            return ""
        with patch.object(runtime, "inspect", side_effect=inspect), patch.object(runtime, "run", side_effect=run):
            runtime.scale(6)
        self.assertTrue(any(command[:2] == ["docker", "run"] for command in commands))
        self.assertTrue(all("-v" not in command and "rm" not in command for command in commands))
        with self.assertRaises(ValueError):
            runtime.lifecycle("fednode-0;evil", "stop")
        compile(NODE_SCRIPT, "<existing-helper-adapter>", "exec")


@unittest.skipUnless(importlib.util.find_spec("grpc"), "Node dependencies are required")
class ExistingBackendTests(unittest.TestCase):
    def test_controls_use_real_inbox_and_rpc_without_changing_backend(self):
        from node.main import FedNodeRunner
        root = Path(__file__).resolve().parents[2]
        paths = list((root / "node").rglob("*.py")) + list((root / "proto").glob("*.py"))
        baseline = {str(path): path.read_bytes() for path in paths}
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            port_socket = socket.socket()
            port_socket.bind(("127.0.0.1", 0))
            grpc_port = port_socket.getsockname()[1]
            port_socket.close()
            with patch.dict(os.environ, {"DATA_DIR": temp, "NODE_ID": "fednode-0",
                    "HTTP_PORT": "0", "GRPC_PORT": str(grpc_port),
                    "PEER_ADDRESSES": ",".join([f"localhost:{grpc_port}"] * 5),
                    "QUORUM_MODE": "STRICT", "BYZANTINE_MODE": "NONE"}):
                runner = FedNodeRunner()
                runner.start()
                monitor = ClusterMonitor(configured_nodes(f"http://127.0.0.1:{runner.http_server.server_port}"))
                runtime = LabRuntime()
                def existing_helper(node_id, request):
                    completed = subprocess.run([sys.executable, "-B", "-c", NODE_SCRIPT],
                        input=json.dumps(request), capture_output=True, text=True, cwd=root, check=True)
                    return json.loads(completed.stdout)
                runtime.node_call = existing_helper
                operator = Operator(monitor, runtime=runtime, state_path=Path(temp) / "dashboard-state.json")
                try:
                    operator.connect()
                    benign = operator.handle({"action": "inject", "node": "fednode-0", "scenario": "benign"})
                    self.assertEqual(benign["inbox_results"][0]["http_status"], 202)
                    attack = operator.handle({"action": "inject", "node": "fednode-0", "scenario": "malware"})
                    self.assertEqual(attack["inbox_results"][0]["status"], "FLAGGED_FOR_CONSENSUS")
                    proposal = operator.handle({"action": "propose", "node": "fednode-0",
                        "domain": "custom.lab.example", "justification": "Operator review"})
                    self.assertTrue(proposal["accepted"])
                    self.assertIn(proposal["proposal_id"], runner.consensus.active_proposals)
                    operator.handle({"action": "vote", "node": "fednode-0", "receiver": "fednode-0",
                        "proposal_id": proposal["proposal_id"], "decision": "APPROVE"})
                    self.assertEqual(len(runner.consensus.active_proposals[proposal["proposal_id"]].approved_votes), 1)
                    self.assertFalse(runner.firewall.is_blocked("custom.lab.example"))
                    operator.handle({"action": "trust", "node": "fednode-0", "peer": "fednode-0",
                                     "score": 20, "scope": "selected"})
                    self.assertFalse(runner.reputation.is_peer_eligible_to_vote("fednode-0"))
                finally:
                    runner.stop()
                    runner.http_server.server_close()
                    monitor.close()
                    gc.collect()
        self.assertEqual(baseline, {str(path): path.read_bytes() for path in paths})


if __name__ == "__main__":
    unittest.main()
