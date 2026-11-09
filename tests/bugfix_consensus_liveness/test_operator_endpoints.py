"""Operator endpoint authentication and validation tests (task 3.3).

Covers node POST /fault, /reputation and /peers:
- 403 without the exact X-Operator-Token (missing, wrong, or no token configured),
  checked before the body is parsed; the client IP is ignored.
- 400 for a body outside the schema; 200 with the existing body for valid input.
- No state change on 403 or 400.

**Validates: Requirements 2.9, 2.10, 2.11, 2.12, 2.13, 2.14, 3.8**

Isolation: nodes are built in process with HTTP_PORT=0, GRPC_PORT=0 and a temp
DATA_DIR. Only the HTTP handler is served, on an ephemeral 127.0.0.1 port. Peers are
fednode-N.invalid:5905N and catch-up is stubbed, so nothing dials the live cluster.

Run: python tests/bugfix_consensus_liveness/test_operator_endpoints.py
"""
import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import gc
import http.client
import json
import logging
import re
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, given, settings, strategies as st

from node.main import ActivityPubHTTPHandler, FedNodeRunner

ROOT = Path(__file__).resolve().parents[2]
SECRET = "bugfix-consensus-liveness-secret"
TOKEN = "bugfix-operator-token-0123456789abcdef0123456789"
PEER_LIST = [f"fednode-{i}.invalid:{59050 + i}" for i in range(5)]
OPERATOR_MODES = {"NONE", "SILENT", "LIAR", "FORGER"}
ROUTES = ("/fault", "/reputation", "/peers")
PBT = settings(max_examples=60, deadline=None,
               suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])


def node_env(data_dir, token):
    return {
        "DATA_DIR": data_dir, "NODE_ID": "fednode-0", "HTTP_PORT": "0", "GRPC_PORT": "0",
        "PEER_ADDRESSES": ",".join(PEER_LIST), "CONSORTIUM_SECRET": SECRET,
        "USE_RANDOM_NODE_KEYS": "false", "BYZANTINE_MODE": "NONE", "QUORUM_MODE": "STRICT",
        "OPERATIONAL_MODE": "AUTOMATIC", "FEDCONSENSUS_OPERATOR_TOKEN": token,
    }


class NodeHarness:
    """A FedNodeRunner that is never started; only its HTTP handler is served on 127.0.0.1:0."""

    def __init__(self, token=TOKEN):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.env = patch.dict(os.environ, node_env(self.temp.name, token))
        self.env.start()
        self.runner = FedNodeRunner()
        self.catchup_patch = patch.object(self.runner.service.catchup, "sync_with_consortium")
        self.catchup_patch.start()
        ActivityPubHTTPHandler.inbox = self.runner.inbox
        ActivityPubHTTPHandler.service = self.runner.service
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ActivityPubHTTPHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_port

    def reset(self):
        service = self.runner.service
        service.byzantine_mode = "FORGER"
        service.simulated_offline = False
        self.runner.config.peers = list(PEER_LIST)

    def state(self):
        service = self.runner.service
        ledger = sorted((r["peer_id"], r["trust_score"], r["is_active"], r["violations_count"])
                        for r in self.runner.db.get_all_reputations())
        return (service.byzantine_mode, service.simulated_offline, ledger, list(self.runner.config.peers))

    def post(self, path, raw, token=None, headers=None):
        """Raw POST via http.client. Returns (status, parsed JSON or None)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.putrequest("POST", path, skip_accept_encoding=True)
            conn.putheader("Content-Type", "application/json")
            if token is not None:
                conn.putheader("X-Operator-Token", token)
            extra = dict(headers or {})
            if "Content-Length" not in extra:
                extra["Content-Length"] = str(len(raw))
            for name, value in extra.items():
                conn.putheader(name, value)
            conn.endheaders(raw if raw else None)
            response = conn.getresponse()
            payload = response.read()
            try:
                return response.status, (json.loads(payload) if payload else None)
            except ValueError:
                return response.status, None
        finally:
            conn.close()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.catchup_patch.stop()
        self.runner._rpc_executor.shutdown(wait=False)
        self.runner.service._rpc_executor.shutdown(wait=False)
        self.env.stop()
        gc.collect()
        self.temp.cleanup()


def encode(body):
    return json.dumps(body).encode("utf-8")


# ---------------------------------------------------------------------------
# Schema oracle (mirrors the spec, not the implementation)
# ---------------------------------------------------------------------------
def valid_body(path, body):
    if not isinstance(body, dict):
        return False
    if path == "/fault":
        mode = body.get("mode", "NONE")
        if not isinstance(mode, str) or mode.strip().upper() not in OPERATOR_MODES:
            return False
        return "offline" not in body or isinstance(body["offline"], bool)
    if path == "/reputation":
        peer_id, score = body.get("peer_id"), body.get("score")
        return (isinstance(peer_id, str) and re.fullmatch(r"fednode-[0-9]{1,3}", peer_id) is not None
                and type(score) is int and 0 <= score <= 100)
    address = body.get("peer_address")
    match = re.fullmatch(r"[A-Za-z0-9.-]{1,253}:([0-9]{1,5})", address) if isinstance(address, str) else None
    return match is not None and 1 <= int(match.group(1)) <= 65535


VALID = {
    "/fault": {"mode": "LIAR"},
    "/reputation": {"peer_id": "fednode-1", "score": 5},
    "/peers": {"peer_address": "fednode-9.invalid:59059"},
}
INVALID = {
    "/fault": [{"mode": "BOGUS"}, {"mode": 3}, {"mode": None}, {"mode": "LIAR", "offline": None},
               {"mode": "LIAR", "offline": 1}, ["LIAR"]],
    "/reputation": [{"peer_id": "fednode-1", "score": "abc"}, {"peer_id": "fednode-1", "score": 1.5},
                    {"peer_id": "fednode-1", "score": True}, {"peer_id": "fednode-1", "score": 101},
                    {"peer_id": "fednode-1"}, {"peer_id": "fednode-1\n", "score": 5},
                    {"peer_id": "fednode-1234", "score": 5}, {"score": 5}],
    "/peers": [{}, {"peer_address": "host:0"}, {"peer_address": "host:65536"},
               {"peer_address": "host"}, {"peer_address": "ho st:80"}, {"peer_address": 80},
               {"peer_address": "host:80\n"}],
}


class OperatorMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = NodeHarness(TOKEN)

    @classmethod
    def tearDownClass(cls):
        cls.node.close()

    def setUp(self):
        self.node.reset()

    def test_403_without_exact_token_before_body_is_parsed(self):
        for path in ROUTES:
            for label, token in (("missing", None), ("wrong", "wrong-" + TOKEN), ("prefix", TOKEN[:-1]),
                                 ("empty", ""), ("non-ascii", "t\u00f6ken-\u00e9")):
                for raw in (encode(VALID[path]), b"not json"):
                    with self.subTest(path=path, credential=label, raw=raw[:8]):
                        before = self.node.state()
                        status, body = self.node.post(path, raw, token=token)
                        self.assertEqual(status, 403)
                        self.assertEqual(body, {"error": "Operator credential required"})
                        self.assertEqual(self.node.state(), before)

    def test_400_for_invalid_bodies_with_valid_token(self):
        for path in ROUTES:
            raws = [encode(b) for b in INVALID[path]] + [b"not json", b"\xff\xfe", b"[]", b"null", b"\"x\""]
            for raw in raws:
                with self.subTest(path=path, raw=raw):
                    before = self.node.state()
                    status, _ = self.node.post(path, raw, token=TOKEN)
                    self.assertEqual(status, 400)
                    self.assertEqual(self.node.state(), before)

    def test_400_for_bad_content_length(self):
        for path in ROUTES:
            for length in ("0", "-5", "abc"):
                with self.subTest(path=path, length=length):
                    before = self.node.state()
                    status, body = self.node.post(path, b"", token=TOKEN, headers={"Content-Length": length})
                    self.assertEqual(status, 400)
                    self.assertEqual(body, {"error": "Expected a JSON object"})
                    self.assertEqual(self.node.state(), before)

    def test_200_bodies_for_valid_requests(self):
        status, body = self.node.post("/fault", encode({"mode": " liar "}), token=TOKEN)
        self.assertEqual((status, body), (200, {"status": "OK", "node_id": "fednode-0", "byzantine_mode": "LIAR"}))
        self.assertEqual(self.node.runner.service.byzantine_mode, "LIAR")

        status, body = self.node.post("/reputation", encode({"peer_id": "fednode-1", "score": 0}), token=TOKEN)
        self.assertEqual((status, body), (200, {"status": "OK", "peer_id": "fednode-1", "score": 0}))
        self.assertFalse(self.node.runner.reputation.is_peer_eligible_to_vote("fednode-1"))

        status, body = self.node.post("/peers", encode({"peer_address": "fednode-7.invalid:1"}), token=TOKEN)
        self.assertEqual((status, body), (200, {"status": "OK", "total_nodes": 6, "quorum": 5}))
        self.assertIn("fednode-7.invalid:1", self.node.runner.config.peers)

    def test_public_routes_still_need_no_token(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.node.port, timeout=5)
        try:
            conn.request("GET", "/health")
            self.assertEqual(conn.getresponse().status, 200)
        finally:
            conn.close()


class UnconfiguredTokenTests(unittest.TestCase):
    def test_empty_configured_token_always_403(self):
        node = NodeHarness(token="")
        self.addCleanup(node.close)
        node.reset()
        for path in ROUTES:
            for token in (None, "", TOKEN, " "):
                with self.subTest(path=path, token=token):
                    before = node.state()
                    status, _ = node.post(path, encode(VALID[path]), token=token)
                    self.assertEqual(status, 403)
                    self.assertEqual(node.state(), before)

    def test_non_ascii_configured_token_does_not_raise(self):
        node = NodeHarness(token="j\u00e9ton-\u4e2d\u6587-0123456789abcdef0123456789")
        self.addCleanup(node.close)
        node.reset()
        for token in (None, TOKEN, "j\u00e9ton"):
            with self.subTest(token=token):
                status, _ = node.post("/fault", encode({"mode": "LIAR"}), token=token)
                self.assertEqual(status, 403)
                self.assertEqual(node.runner.service.byzantine_mode, "FORGER")


class StartupAndConfigTests(unittest.TestCase):
    def build(self, token):
        temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        self.addCleanup(gc.collect)
        with patch.dict(os.environ, node_env(temp.name, token)):
            with self.assertLogs("fedconsensus.main", level="WARNING") as logs:
                runner = FedNodeRunner()
                logging.getLogger("fedconsensus.main").warning("sentinel")
        runner._rpc_executor.shutdown(wait=False)
        runner.service._rpc_executor.shutdown(wait=False)
        identity = Path(temp.name, "node_identity.json").read_text()
        return [r for r in logs.output if "sentinel" not in r], identity

    def test_warns_when_token_missing(self):
        output, _ = self.build("")
        self.assertTrue(any("operator endpoints will return 403" in line for line in output))

    def test_warns_on_short_token_without_logging_it(self):
        short = "short-secret-xyz"
        output, identity = self.build(short)
        self.assertTrue(any("shorter than 32" in line for line in output))
        self.assertFalse(any(short in line for line in output))
        self.assertNotIn(short, identity)

    def test_long_token_no_warning_and_not_persisted(self):
        output, identity = self.build(TOKEN)
        self.assertEqual(output, [])
        self.assertNotIn(TOKEN, identity)


class DeploymentWiringTests(unittest.TestCase):
    def test_compose_passes_token_to_nodes_and_dashboard(self):
        text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertEqual(text.count("FEDCONSENSUS_OPERATOR_TOKEN: ${FEDCONSENSUS_OPERATOR_TOKEN:-}"), 2)

    def test_statefulset_secret_is_optional_and_no_new_manifest(self):
        text = (ROOT / "k8s" / "statefulset.yaml").read_text(encoding="utf-8")
        self.assertIn("name: FEDCONSENSUS_OPERATOR_TOKEN", text)
        self.assertIn("name: fedconsensus-operator", text)
        self.assertIn("optional: true", text)
        self.assertEqual(len(list((ROOT / "k8s").glob("*.yaml"))), 4)

    def test_env_file_is_gitignored(self):
        lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn(".env", [line.strip() for line in lines])


# ---------------------------------------------------------------------------
# Property: arbitrary bodies and headers
# ---------------------------------------------------------------------------
json_values = st.recursive(
    st.none() | st.booleans() | st.integers(-10**6, 10**6) | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=12),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=10,
)
mode_values = st.sampled_from(["NONE", "silent", " Liar ", "FORGER", "CENSOR", "EQUIVOCATOR", "BOGUS", ""]) | json_values
near_schema = st.one_of(
    st.fixed_dictionaries({}, optional={"mode": mode_values, "offline": json_values | st.booleans()}),
    st.fixed_dictionaries({}, optional={
        "peer_id": st.sampled_from(["fednode-0", "fednode-12", "fednode-1234", "node-1", ""]) | json_values,
        "score": st.integers(-5, 105) | json_values}),
    st.fixed_dictionaries({}, optional={
        "peer_address": st.sampled_from(["fednode-8.invalid:59058", "a:1", "a:65535", "a:0", "a:70000",
                                         "a", "a b:1"]) | json_values}),
)
header_tokens = st.one_of(
    st.none(), st.just(TOKEN),
    st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E), max_size=60),
).filter(lambda t: t is None or t == TOKEN or t.strip() != TOKEN)


class OperatorEndpointProperty(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = NodeHarness(TOKEN)

    @classmethod
    def tearDownClass(cls):
        cls.node.close()

    @PBT
    @given(path=st.sampled_from(ROUTES), token=header_tokens,
           body=st.one_of(json_values, near_schema), raw=st.one_of(st.none(), st.binary(max_size=40)))
    def test_403_400_200_and_no_state_change(self, path, token, body, raw):
        """**Validates: Requirements 2.9, 2.10, 2.11, 2.12, 2.13, 2.14**"""
        node = self.node
        node.reset()
        payload = raw if raw is not None else encode(body)
        if raw is not None:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                parsed = None
        else:
            parsed = body
        before = node.state()
        status, _ = node.post(path, payload, token=token)
        if token != TOKEN:
            self.assertEqual(status, 403)
            self.assertEqual(node.state(), before)
        elif not valid_body(path, parsed):
            self.assertEqual(status, 400)
            self.assertEqual(node.state(), before)
        else:
            self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
