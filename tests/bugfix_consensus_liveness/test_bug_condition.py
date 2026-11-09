"""Bug condition exploration tests (Property 1) for consensus-liveness-security-fix.

These tests encode the expected behaviour from the design's ``expectedBehavior``.
They are written to FAIL on the unfixed code, which confirms that each defect group
(C1 liveness visibility, C2 reputation/quarantine, C3 fault-mode validation,
C4 operator auth/validation) exists. They should pass once the fix is in place.

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12, 1.13**

Isolation: no test dials the live cluster. Nodes are built in process with
HTTP_PORT=0, GRPC_PORT=0 and a temp DATA_DIR; only the HTTP handler is served,
on an ephemeral 127.0.0.1 port. Peers are fednode-N.invalid:5905N, gRPC is stubbed,
and no heartbeat loop is started.

Run: python tests/bugfix_consensus_liveness/test_bug_condition.py

Counterexamples observed on the UNFIXED code (all 15 tests failed, 43 failures
counting subtests):

C2 reputation and quarantine
- Retry equivocation: REJECT then two APPROVE retries from fednode-1 on one
  proposal gives trust 0 (expected 50). Hypothesis shrinks to
  first='APPROVE', repeats=['REJECT', 'REJECT'] -> trust 0, quarantined.
- Self-penalty: fednode-1 processing its own REJECT then APPROVE ballots lowers
  its own ledger entry to 0 (expected 100).
- Sync: a peer's GetStatus entry {fednode-2: 0} is copied onto fednode-2's own
  entry (0, expected 100); a local 10 is overwritten by a remote 25.
- No recovery: ReputationManager has no apply_recovery; a peer at 10 stays at 10.
- Revive (non-runtime): POSTs score=100 to /reputation on every node.
- quarantined_by: fednode-2 is listed in its own quarantined_by (['fednode-2']).

C3 fault-mode validation
- Dashboard settings with fault 'BOGUS': no ValueError; the node is contacted.
- Node /fault: {"mode":"BOGUS"} -> 200; body 'not json' -> 200 and mode NONE
  applied; JSON array -> handler raises AttributeError ('list' has no 'get') and
  no HTTP response is sent; {"offline":"yes"} -> 200 and mode changed.

C4 operator auth and validation
- /fault, /reputation, /peers from 127.0.0.1 with no token, a wrong token, or on a
  node with no token configured -> 200 (expected 403) and state changes.
- /reputation: score "abc" -> int() ValueError, no HTTP response; 1.5, true, 101,
  -1, missing score, missing/malformed/non-string peer_id -> 200 (expected 400).
- /peers: {}, "host:99999", and an address with no port -> 200 (expected 400).

C1 liveness visibility
- node_snapshot has no quorum_health and no per-proposal quorum_state with
  fednode-3 unreachable and fednode-2 quarantined (3 eligible < Q=4).
- ClusterMonitor snapshot has no quorum_health in the same situation.
"""
import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import gc
import http.client
import io
import itertools
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from hypothesis import HealthCheck, given, settings, strategies as st

from proto import fedconsensus_pb2 as pb2
from node.config import NodeConfig
from node.crypto.ed25519 import generate_deterministic_keypair, sign_message
from node.engine.consensus import ConsensusEngine, ProposalState
from node.ingress.firewall import FirewallFilter
from node.main import ActivityPubHTTPHandler, FedNodeRunner
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.telemetry import node_snapshot
from dashboard.control import Operator
from dashboard.server import ClusterMonitor, configured_nodes

SECRET = "bugfix-consensus-liveness-secret"
TOKEN = "bugfix-operator-token-0123456789abcdef0123456789"
PEERS = ",".join(f"fednode-{i}.invalid:{59050 + i}" for i in range(5))
DASHBOARD_NODES = ",".join(f"http://fednode-{i}.invalid:{59080 + i}" for i in range(5))
OPENER = build_opener(ProxyHandler({}))


def node_env(data_dir, node_id="fednode-0", token=TOKEN):
    return {
        "DATA_DIR": data_dir, "NODE_ID": node_id, "HTTP_PORT": "0", "GRPC_PORT": "0",
        "PEER_ADDRESSES": PEERS, "CONSORTIUM_SECRET": SECRET, "USE_RANDOM_NODE_KEYS": "false",
        "BYZANTINE_MODE": "NONE", "QUORUM_MODE": "STRICT", "OPERATIONAL_MODE": "AUTOMATIC",
        "FEDCONSENSUS_OPERATOR_TOKEN": token,
    }


def private_key(node_id):
    return generate_deterministic_keypair(f"{SECRET}-{node_id}")[0]


def ballot(voter_id, proposal, decision):
    meta = {"proposal_id": proposal.proposal_id, "sequence_number": proposal.sequence_number,
            "epoch": proposal.epoch, "target_domain": proposal.target_domain, "decision": decision}
    return pb2.VoteRequest(
        proposal_id=proposal.proposal_id, sequence_number=proposal.sequence_number,
        epoch=proposal.epoch, target_domain=proposal.target_domain, voter_id=voter_id,
        decision=pb2.VOTE_APPROVE if decision == "APPROVE" else pb2.VOTE_REJECT,
        voter_signature=sign_message(private_key(voter_id), meta),
        timestamp=int(time.time() * 1000),
    )


def trust_of(reputation, peer_id):
    row = next((r for r in reputation.get_ledger() if r["peer_id"] == peer_id), None)
    return 100 if row is None else row["trust_score"]


def ledger_view(db):
    return sorted((r["peer_id"], r["trust_score"], r["is_active"], r["violations_count"])
                  for r in db.get_all_reputations())


def post(port, path, body=None, token=None, raw=None):
    """POST to the in-process node. Returns the HTTP status, or None if no valid response."""
    data = raw if raw is not None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Operator-Token"] = token
    request = Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method="POST")
    try:
        with OPENER.open(request, timeout=5) as response:
            response.read()
            return response.status
    except HTTPError as error:
        code = error.code
        error.close()
        return code
    except (URLError, http.client.HTTPException, ConnectionError, OSError):
        return None


class NodeHarness:
    """A FedNodeRunner that is never started; only its HTTP handler is served on 127.0.0.1:0."""

    def __init__(self, node_id="fednode-0", token=TOKEN):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.env = patch.dict(os.environ, node_env(self.temp.name, node_id, token))
        self.env.start()
        self.runner = FedNodeRunner()
        self.server = None

    def serve(self):
        ActivityPubHTTPHandler.inbox = self.runner.inbox
        ActivityPubHTTPHandler.service = self.runner.service
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ActivityPubHTTPHandler)
        self.runner.http_server = self.server
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self.server.server_port

    def close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.runner._rpc_executor.shutdown(wait=False)
        self.runner.service._rpc_executor.shutdown(wait=False)
        self.env.stop()
        gc.collect()
        self.temp.cleanup()


class StubRuntime:
    """Non-runtime dashboard mode: capabilities unavailable, records any fallback call."""
    kind = "docker"
    namespace = "default"

    def __init__(self):
        self.calls = []

    def capabilities(self):
        return {"kind": "docker", "available": False, "message": "No runtime in this test"}

    def fault(self, node_id, mode):
        self.calls.append(("fault", node_id, mode))
        return "Node restarted using its existing BYZANTINE_MODE=" + str(mode)

    def node_call(self, node_id, request):
        self.calls.append(("node_call", node_id, request))
        return {}

    def lifecycle(self, node_id, action):
        self.calls.append(("lifecycle", node_id, action))
        return "lifecycle"

    def ensure_forward(self, index):
        pass

    def close(self):
        pass


def telemetry(node_id, reputations=(), proposals=()):
    return {"node_id": node_id, "state": "FOLLOWER", "epoch": 1, "quorum": 4, "last_sequence": 0,
            "operational_mode": "AUTOMATIC", "events": [], "proposals": list(proposals),
            "blocked_domains": [], "reputations": list(reputations)}


def rep(peer_id, score):
    return {"peer_id": peer_id, "trust_score": score, "violations_count": 0,
            "is_active": 0 if score < 30 else 1, "last_updated": 0}


# ---------------------------------------------------------------------------
# C2: reputation and quarantine faults
# ---------------------------------------------------------------------------
class RetryEquivocationTests(unittest.TestCase):
    """C2 retry equivocation: one proposal must not drive a voter from 100 into quarantine."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.env = patch.dict(os.environ, node_env(cls.temp.name, "fednode-0"))
        cls.env.start()
        cls.config = NodeConfig()
        cls.counter = itertools.count()

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        gc.collect()
        cls.temp.cleanup()

    def fresh_engine(self):
        db = Database(os.path.join(self.temp.name, f"engine-{next(self.counter)}.db"))
        reputation = ReputationManager(db)
        engine = ConsensusEngine(self.config, db, FirewallFilter(db), reputation)
        request = engine.create_proposal("phishing-retry.lab.example", 1, "{}", "", 0.9)
        return engine, reputation, engine.active_proposals[request.proposal_id]

    def test_reject_then_two_approve_retries_costs_one_penalty(self):
        engine, reputation, proposal = self.fresh_engine()
        engine.handle_vote(ballot("fednode-1", proposal, "REJECT"))   # LIAR mode
        engine.handle_vote(ballot("fednode-1", proposal, "APPROVE"))  # retry after switch to NONE
        engine.handle_vote(ballot("fednode-1", proposal, "APPROVE"))  # next retry 2 s later
        self.assertEqual(trust_of(reputation, "fednode-1"), 50)
        self.assertTrue(reputation.is_peer_eligible_to_vote("fednode-1"))

    @settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(first=st.sampled_from(["APPROVE", "REJECT"]),
           repeats=st.lists(st.sampled_from(["APPROVE", "REJECT"]), min_size=1, max_size=20))
    def test_conflicting_repeats_cost_at_most_one_equivocation(self, first, repeats):
        """**Validates: Requirements 1.3, 2.3**"""
        engine, reputation, proposal = self.fresh_engine()
        engine.handle_vote(ballot("fednode-1", proposal, first))
        for decision in repeats:
            engine.handle_vote(ballot("fednode-1", proposal, decision))
        self.assertGreaterEqual(trust_of(reputation, "fednode-1"), 50)
        self.assertTrue(reputation.is_peer_eligible_to_vote("fednode-1"))


class SelfPenaltyTests(unittest.TestCase):
    def setUp(self):
        self.node = NodeHarness("fednode-1")
        self.addCleanup(self.node.close)

    def test_own_ballot_change_does_not_penalise_own_entry(self):
        runner = self.node.runner
        proposal = ProposalState("prop-1-21-self.lab.example", 21, 1, "self.lab.example", 1, 0.9)
        runner.consensus.active_proposals[proposal.proposal_id] = proposal
        runner.consensus.handle_vote(ballot("fednode-1", proposal, "REJECT"))
        runner.consensus.handle_vote(ballot("fednode-1", proposal, "APPROVE"))
        runner.consensus.handle_vote(ballot("fednode-1", proposal, "APPROVE"))
        self.assertEqual(trust_of(runner.reputation, "fednode-1"), 100)


class ReputationSyncTests(unittest.TestCase):
    def setUp(self):
        self.node = NodeHarness("fednode-2")
        self.addCleanup(self.node.close)

    def test_sync_skips_own_entry_and_never_raises_a_score(self):
        runner = self.node.runner
        runner.db.set_reputation("fednode-3", 10)
        before_self = trust_of(runner.reputation, "fednode-2")
        status = pb2.StatusResponse(node_id="fednode-0", reputations=[
            pb2.PeerReputationEntry(peer_id="fednode-1", trust_score=0, is_active=False, violations_count=2),
            pb2.PeerReputationEntry(peer_id="fednode-2", trust_score=0, is_active=False, violations_count=2),
            pb2.PeerReputationEntry(peer_id="fednode-3", trust_score=25, is_active=False, violations_count=0),
        ])
        stub = MagicMock()
        stub.CatchupSync.return_value = pb2.CatchupResponse(node_id="fednode-0", records=[])
        stub.GetStatus.return_value = status
        with patch("grpc.insecure_channel", return_value=MagicMock()), \
                patch("proto.fedconsensus_pb2_grpc.FedConsensusServiceStub", return_value=stub):
            runner.catchup.sync_with_consortium(runner.consensus)
        self.assertTrue(stub.GetStatus.called, "stubbed GetStatus was not reached")
        with self.subTest("own entry"):
            self.assertEqual(trust_of(runner.reputation, "fednode-2"), before_self,
                             "sync copied a peer's low score onto the node's own entry")
        with self.subTest("lower-only"):
            self.assertEqual(trust_of(runner.reputation, "fednode-3"), 10,
                             "sync raised a local 10 to the remote 25")


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(gc.collect)

    def test_quarantined_peer_recovers_without_new_violations(self):
        db = Database(os.path.join(self.temp.name, "recovery.db"))
        reputation = ReputationManager(db)
        reputation.penalize_equivocation("fednode-1")  # 100 -> 50
        reputation.penalize_forgery("fednode-1")       # 50 -> 10, quarantined
        self.assertEqual(trust_of(reputation, "fednode-1"), 10)
        self.assertTrue(hasattr(reputation, "apply_recovery"),
                        "ReputationManager has no recovery path (apply_recovery missing)")
        base = time.time()
        for elapsed in range(0, 202, 2):  # heartbeat ticks every 2 s for 200 s
            reputation.apply_recovery(now=base + elapsed)
        self.assertGreaterEqual(trust_of(reputation, "fednode-1"), 30)
        self.assertLessEqual(trust_of(reputation, "fednode-1"), 100)
        self.assertTrue(reputation.is_peer_eligible_to_vote("fednode-1"))


def recording_open(urls, bodies=None):
    def fake_open(request, timeout=None):
        urls.append(request.full_url)
        if bodies is not None:
            bodies.append(request.data)
        return io.BytesIO(b'{"status": "OK", "node_id": "fednode-1", "byzantine_mode": "NONE"}')
    return fake_open


class DashboardOperatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.monitor = ClusterMonitor(configured_nodes(DASHBOARD_NODES))
        self.addCleanup(self.monitor.close)
        self.runtime = StubRuntime()
        self.operator = Operator(self.monitor, runtime=self.runtime,
                                 state_path=os.path.join(self.temp.name, "state.json"))
        self.operator.connected = True
        self.monitor._data["nodes"] = [
            {"node_id": f"fednode-{i}", "online": True, "reputations": []} for i in range(5)]

    def test_revive_without_runtime_sends_no_reputation_reset(self):
        urls = []
        with patch.object(self.monitor, "refresh"), \
                patch.object(self.operator.opener, "open", side_effect=recording_open(urls)):
            self.operator.handle({"action": "revive", "node": "fednode-1"})
        self.assertTrue(any(url.endswith("/fault") for url in urls))
        self.assertEqual([url for url in urls if url.endswith("/reputation")], [],
                         "revive POSTed score=100 to /reputation")

    def test_settings_rejects_unsupported_mode_before_any_io(self):
        urls = []
        with patch.object(self.monitor, "refresh"), \
                patch.object(self.operator.opener, "open", side_effect=recording_open(urls)):
            with self.assertRaises(ValueError):
                self.operator.handle({"action": "settings", "node": "fednode-1", "fault": "BOGUS"})
        self.assertEqual(urls, [], "the node was contacted with an unsupported mode")
        self.assertEqual(self.runtime.calls, [], "runtime fallback was used for an unsupported mode")


class DashboardMonitorTests(unittest.TestCase):
    def setUp(self):
        self.monitor = ClusterMonitor(configured_nodes(DASHBOARD_NODES))
        self.addCleanup(self.monitor.close)
        self.addresses = {n["node_id"]: n["address"] for n in self.monitor.nodes}

    def fake_json(self, views, offline=()):
        def _json(address):
            for node_id, base in self.addresses.items():
                if address.startswith(base):
                    if node_id in offline:
                        raise URLError("node unreachable")
                    return json.loads(json.dumps(views[node_id]))
            raise URLError("unknown address")
        return _json

    def test_quarantined_by_excludes_the_node_itself(self):
        views = {f"fednode-{i}": telemetry(f"fednode-{i}") for i in range(5)}
        views["fednode-2"] = telemetry("fednode-2", reputations=[rep("fednode-2", 20)])
        with patch.object(self.monitor, "_json", side_effect=self.fake_json(views)):
            self.monitor.refresh()
        node2 = next(n for n in self.monitor.snapshot()["nodes"] if n["node_id"] == "fednode-2")
        self.assertNotIn("fednode-2", node2["quarantined_by"])

    def test_cluster_quorum_health_reports_unreachable_quorum(self):
        now_ms = int(time.time() * 1000)
        pending = {"proposal_id": "prop-1-21-pending.lab.example", "domain": "pending.lab.example",
                   "proposer": "fednode-0", "reason": 1, "epoch": 1, "sequence": 21,
                   "created_at": now_ms, "committed": False, "latency_ms": 0, "threat_score": 0.9,
                   "approvals": ["fednode-0", "fednode-4"], "quorum": 4, "observer": "fednode-0"}
        low = [rep("fednode-2", 20)]
        views = {
            "fednode-0": telemetry("fednode-0", reputations=low, proposals=[pending]),
            "fednode-1": telemetry("fednode-1", reputations=low),
            "fednode-2": telemetry("fednode-2"),
            "fednode-3": telemetry("fednode-3"),
            "fednode-4": telemetry("fednode-4", reputations=low),
        }
        with patch.object(self.monitor, "_json", side_effect=self.fake_json(views, offline={"fednode-3"})):
            self.monitor.refresh()
        data = self.monitor.snapshot()
        self.assertIn("quorum_health", data, "dashboard has no quorum_health signal")
        health = data["quorum_health"]
        self.assertIs(health["quorum_reachable"], False)
        self.assertEqual(health["eligible_voters"], 3)
        self.assertEqual(health["quorum"], 4)
        self.assertEqual(sorted(health["offline"]), ["fednode-3"])
        self.assertEqual(sorted(health["quarantined"]), ["fednode-2"])
        self.assertIn("pending.lab.example", health["pending_unreachable"])


# ---------------------------------------------------------------------------
# C3 and C4: node operator endpoints
# ---------------------------------------------------------------------------
class NodeFaultValidationTests(unittest.TestCase):
    def setUp(self):
        self.node = NodeHarness("fednode-0")
        self.addCleanup(self.node.close)
        self.port = self.node.serve()
        self.service = self.node.runner.service

    def test_invalid_fault_requests_return_400_and_change_nothing(self):
        cases = [
            ("unsupported mode", {"raw": json.dumps({"mode": "BOGUS"}).encode()}),
            ("not json", {"raw": b"not json"}),
            ("json array", {"raw": b"[1, 2]"}),
            ("non-bool offline", {"raw": json.dumps({"mode": "LIAR", "offline": "yes"}).encode()}),
        ]
        for label, kwargs in cases:
            with self.subTest(label):
                self.service.byzantine_mode = "FORGER"
                self.service.simulated_offline = False
                status = post(self.port, "/fault", token=TOKEN, **kwargs)
                self.assertEqual(status, 400)
                self.assertEqual(self.service.byzantine_mode, "FORGER")
                self.assertFalse(self.service.simulated_offline)


class NodeOperatorAuthTests(unittest.TestCase):
    VALID = {
        "/fault": {"mode": "LIAR"},
        "/reputation": {"peer_id": "fednode-1", "score": 5},
        "/peers": {"peer_address": "fednode-9.invalid:59059"},
    }

    def check_matrix(self, node, credentials):
        port = node.serve()
        service = node.runner.service
        for path, body in self.VALID.items():
            for label, token in credentials:
                with self.subTest(path=path, credential=label):
                    service.byzantine_mode = "NONE"
                    ledger_before = ledger_view(node.runner.db)
                    peers_before = list(node.runner.config.peers)
                    status = post(port, path, body, token=token)
                    self.assertEqual(status, 403)
                    self.assertEqual(service.byzantine_mode, "NONE")
                    self.assertEqual(ledger_view(node.runner.db), ledger_before)
                    self.assertEqual(node.runner.config.peers, peers_before)

    def test_missing_or_wrong_token_from_loopback_is_403(self):
        node = NodeHarness("fednode-0", token=TOKEN)
        self.addCleanup(node.close)
        self.check_matrix(node, [("missing", None), ("wrong", "wrong-" + TOKEN)])

    def test_node_without_configured_token_always_403(self):
        node = NodeHarness("fednode-0", token="")
        self.addCleanup(node.close)
        self.check_matrix(node, [("missing", None), ("any token", TOKEN), ("empty", "")])


class NodeReputationValidationTests(unittest.TestCase):
    def setUp(self):
        self.node = NodeHarness("fednode-0")
        self.addCleanup(self.node.close)
        self.port = self.node.serve()

    def test_invalid_reputation_input_returns_400_and_ledger_unchanged(self):
        cases = [
            ("score string", {"peer_id": "fednode-1", "score": "abc"}),
            ("score float", {"peer_id": "fednode-1", "score": 1.5}),
            ("score bool", {"peer_id": "fednode-1", "score": True}),
            ("score 101", {"peer_id": "fednode-1", "score": 101}),
            ("score -1", {"peer_id": "fednode-1", "score": -1}),
            ("score missing", {"peer_id": "fednode-1"}),
            ("peer_id missing", {"score": 50}),
            ("peer_id bad format", {"peer_id": "node-1", "score": 50}),
            ("peer_id injection", {"peer_id": "fednode-1; drop", "score": 50}),
            ("peer_id not str", {"peer_id": 5, "score": 50}),
        ]
        for label, body in cases:
            with self.subTest(label):
                before = ledger_view(self.node.runner.db)
                status = post(self.port, "/reputation", body, token=TOKEN)
                self.assertEqual(status, 400)
                self.assertEqual(ledger_view(self.node.runner.db), before)


class NodePeersValidationTests(unittest.TestCase):
    def setUp(self):
        self.node = NodeHarness("fednode-0")
        self.addCleanup(self.node.close)
        self.port = self.node.serve()

    def test_missing_or_malformed_peer_address_returns_400(self):
        for label, body in [("empty body", {}), ("port out of range", {"peer_address": "host:99999"}),
                            ("no port", {"peer_address": "fednode-9.invalid"})]:
            with self.subTest(label):
                before = list(self.node.runner.config.peers)
                status = post(self.port, "/peers", body, token=TOKEN)
                self.assertEqual(status, 400)
                self.assertEqual(self.node.runner.config.peers, before)


# ---------------------------------------------------------------------------
# C1: node telemetry liveness signal
# ---------------------------------------------------------------------------
class NodeQuorumHealthTests(unittest.TestCase):
    def setUp(self):
        self.node = NodeHarness("fednode-0")
        self.addCleanup(self.node.close)

    def test_snapshot_reports_quorum_unreachable(self):
        runner = self.node.runner
        runner.db.set_reputation("fednode-2", 20)
        runner.catchup.peer_reachability = {
            "fednode-3": {"reachable": False, "checked_at": int(time.time() * 1000)}}
        request = runner.consensus.create_proposal("pending.lab.example", 1, "{}", "", 0.9)
        snap = node_snapshot(runner.service)
        self.assertIn("quorum_health", snap, "node telemetry has no quorum_health signal")
        health = snap["quorum_health"]
        self.assertIs(health["quorum_reachable"], False)
        self.assertEqual(health["eligible_voters"], 3)
        self.assertEqual(health["quorum"], 4)
        self.assertEqual(health["offline"], ["fednode-3"])
        self.assertEqual(health["quarantined"], ["fednode-2"])
        proposal = next(p for p in snap["proposals"] if p["proposal_id"] == request.proposal_id)
        self.assertEqual(proposal.get("quorum_state"), "quorum_unreachable")


if __name__ == "__main__":
    unittest.main()
