"""Preservation property tests (Property 2) for consensus-liveness-security-fix.

Property 2: Preservation - consensus, scoring, operator and telemetry behaviour
outside the bug condition. Every case here has isBugCondition(input) = false, so the
fixed code must give the same result as the unfixed code.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.11**

Observation-first: the expected values below were recorded by running the UNFIXED
code. These tests pass on the unfixed code and must keep passing after the fix.

Notes on fix-compatibility:
- Operator requests always carry X-Operator-Token with the node's configured
  FEDCONSENSUS_OPERATOR_TOKEN (set via patch.dict). Unfixed code accepts them because
  they come from loopback; fixed code accepts them because the token matches.
- Telemetry comparisons ignore only the additive `quorum_health` and per-proposal
  `quorum_state` keys. When present, they must report a reachable quorum.
- Revive only asserts what the fix keeps: /fault gets {"mode":"NONE","offline":false}
  and the node runs catch-up. The unfixed /reputation score=100 reset is not asserted.
- Settings use already-normalised upper-case modes, because the fix reports the
  normalised mode.

Isolation: no test dials the live cluster. Nodes are built in process with
HTTP_PORT=0, GRPC_PORT=0 and a temp DATA_DIR; only the HTTP handler is served on an
ephemeral 127.0.0.1 port. Peers are fednode-N.invalid:5905N, catch-up is stubbed,
and no heartbeat loop is started.

Run: python tests/bugfix_consensus_liveness/test_preservation.py
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
from node.engine.consensus import ConsensusEngine
from node.ingress.firewall import FirewallFilter
from node.main import ActivityPubHTTPHandler, FedNodeRunner
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.telemetry import node_snapshot
from dashboard.control import Operator
from dashboard.server import ClusterMonitor, configured_nodes, make_handler

SECRET = "bugfix-consensus-liveness-secret"
TOKEN = "bugfix-operator-token-0123456789abcdef0123456789"
PEER_LIST = [f"fednode-{i}.invalid:{59050 + i}" for i in range(5)]
PEERS = ",".join(PEER_LIST)
DASHBOARD_NODES = ",".join(f"http://fednode-{i}.invalid:{59080 + i}" for i in range(5))
OPENER = build_opener(ProxyHandler({}))
OPERATOR_MODES = ["NONE", "SILENT", "LIAR", "FORGER"]
VOTERS = ["fednode-1", "fednode-2", "fednode-3", "fednode-4"]
PBT = settings(max_examples=30, deadline=None,
               suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])


def node_env(data_dir, node_id="fednode-0", token=TOKEN, **extra):
    env = {
        "DATA_DIR": data_dir, "NODE_ID": node_id, "HTTP_PORT": "0", "GRPC_PORT": "0",
        "PEER_ADDRESSES": PEERS, "CONSORTIUM_SECRET": SECRET, "USE_RANDOM_NODE_KEYS": "false",
        "BYZANTINE_MODE": "NONE", "QUORUM_MODE": "STRICT", "OPERATIONAL_MODE": "AUTOMATIC",
        "FEDCONSENSUS_OPERATOR_TOKEN": token,
    }
    env.update(extra)
    return env


def private_key(node_id):
    return generate_deterministic_keypair(f"{SECRET}-{node_id}")[0]


def ballot(voter_id, proposal, decision, forged=False):
    meta = {"proposal_id": proposal.proposal_id, "sequence_number": proposal.sequence_number,
            "epoch": proposal.epoch, "target_domain": proposal.target_domain, "decision": decision}
    signature = ("bad_signature_000000000000000000000000000000000000000000000000" if forged
                 else sign_message(private_key(voter_id), meta))
    return pb2.VoteRequest(
        proposal_id=proposal.proposal_id, sequence_number=proposal.sequence_number,
        epoch=proposal.epoch, target_domain=proposal.target_domain, voter_id=voter_id,
        decision=pb2.VOTE_APPROVE if decision == "APPROVE" else pb2.VOTE_REJECT,
        voter_signature=signature, timestamp=int(time.time() * 1000),
    )


def row_of(reputation, peer_id):
    return next((r for r in reputation.get_ledger() if r["peer_id"] == peer_id), None)


def trust_of(reputation, peer_id):
    row = row_of(reputation, peer_id)
    return 100 if row is None else row["trust_score"]


def request(port, method, path, body=None, token=TOKEN, raw=None):
    """Call the in-process node. Returns (status, parsed JSON body or None)."""
    data = None
    if method == "POST":
        data = raw if raw is not None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Operator-Token"] = token
    req = Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method)
    try:
        with OPENER.open(req, timeout=5) as response:
            payload = response.read()
            return response.status, (json.loads(payload) if payload else None)
    except HTTPError as error:
        payload = error.read()
        code = error.code
        error.close()
        try:
            return code, (json.loads(payload) if payload else None)
        except ValueError:
            return code, None
    except (URLError, http.client.HTTPException, ConnectionError, OSError):
        return None, None


class NodeHarness:
    """A FedNodeRunner that is never started; only its HTTP handler is served on 127.0.0.1:0."""

    def __init__(self, node_id="fednode-0", token=TOKEN, **extra_env):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.env = patch.dict(os.environ, node_env(self.temp.name, node_id, token, **extra_env))
        self.env.start()
        self.runner = FedNodeRunner()
        self.server = None
        # Catch-up is stubbed: it must never dial the .invalid peers.
        self.catchup_called = threading.Event()
        self.catchup_patch = patch.object(self.runner.service.catchup, "sync_with_consortium",
                                          side_effect=lambda *a, **k: self.catchup_called.set())
        self.catchup_mock = self.catchup_patch.start()

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
        self.catchup_patch.stop()
        self.runner._rpc_executor.shutdown(wait=False)
        self.runner.service._rpc_executor.shutdown(wait=False)
        self.env.stop()
        gc.collect()
        self.temp.cleanup()


# ---------------------------------------------------------------------------
# 3.4, 3.5: un-keyed penalties and the +2 reward
# ---------------------------------------------------------------------------
PENALTY_DELTAS = {"forgery": -40, "equivocation": -50, "bogus": -25, "censorship": -30, "reward": 2}


class UnkeyedPenaltyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(gc.collect)
        self.counter = itertools.count()

    def fresh(self):
        db = Database(os.path.join(self.temp.name, f"rep-{next(self.counter)}.db"))
        return ReputationManager(db)

    @staticmethod
    def apply(reputation, op, peer):
        return {
            "forgery": reputation.penalize_forgery,
            "equivocation": reputation.penalize_equivocation,
            "bogus": reputation.penalize_bogus_evidence,
            "censorship": reputation.penalize_censorship,
            "reward": reputation.reward_honest_participation,
        }[op](peer)

    def test_observed_sequence_100_50_10_quarantined(self):
        reputation = self.fresh()
        self.assertTrue(reputation.is_peer_eligible_to_vote("fednode-1"))
        reputation.penalize_equivocation("fednode-1")
        self.assertEqual(trust_of(reputation, "fednode-1"), 50)
        self.assertTrue(reputation.is_peer_eligible_to_vote("fednode-1"))
        reputation.penalize_forgery("fednode-1")
        row = row_of(reputation, "fednode-1")
        self.assertEqual((row["trust_score"], row["violations_count"], row["is_active"]), (10, 2, 0))
        self.assertFalse(reputation.is_peer_eligible_to_vote("fednode-1"))

    @PBT
    @given(ops=st.lists(st.tuples(st.sampled_from(sorted(PENALTY_DELTAS)),
                                  st.sampled_from(["fednode-1", "fednode-2", "fednode-3"])),
                        min_size=1, max_size=25))
    def test_unkeyed_sequences_match_original_arithmetic(self, ops):
        """**Validates: Requirements 3.4, 3.5**"""
        reputation = self.fresh()
        oracle = {}
        for op, peer in ops:
            self.apply(reputation, op, peer)
            score, violations = oracle.get(peer, (100, 0))
            score = max(0, min(100, score + PENALTY_DELTAS[op]))
            violations += 0 if op == "reward" else 1
            oracle[peer] = (score, violations)
        for peer, (score, violations) in oracle.items():
            row = row_of(reputation, peer)
            self.assertIsNotNone(row)
            self.assertEqual(row["trust_score"], score)
            self.assertEqual(row["violations_count"], violations)
            self.assertEqual(row["is_active"], 0 if score < 30 else 1)
            self.assertEqual(reputation.is_peer_eligible_to_vote(peer), score >= 30)


# ---------------------------------------------------------------------------
# 3.1, 3.2: conflict-free ballots, QC at Q=4, quarantine exclusion, quorum math
# ---------------------------------------------------------------------------
class EngineFixture:
    def __init__(self, test):
        test.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        test.env = patch.dict(os.environ, node_env(test.temp.name, "fednode-0"))
        test.env.start()
        test.config = NodeConfig()
        test.counter = itertools.count()


class ConflictFreeBallotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        EngineFixture(cls)

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        gc.collect()
        cls.temp.cleanup()

    def fresh_engine(self, domain="preserve-ballots.lab.example"):
        db = Database(os.path.join(self.temp.name, f"engine-{next(self.counter)}.db"))
        reputation = ReputationManager(db)
        engine = ConsensusEngine(self.config, db, FirewallFilter(db), reputation)
        req = engine.create_proposal(domain, 1, "{}", "", 0.9)
        return engine, reputation, db, engine.active_proposals[req.proposal_id]

    def test_honest_flow_commits_at_q4(self):
        engine, reputation, _, proposal = self.fresh_engine("honest-commit.lab.example")
        self.assertEqual(self.config.quorum_size, 4)
        self.assertIsNone(engine.handle_vote(ballot("fednode-1", proposal, "APPROVE")))
        self.assertIsNone(engine.handle_vote(ballot("fednode-2", proposal, "APPROVE")))
        proof = engine.handle_vote(ballot("fednode-3", proposal, "APPROVE"))
        self.assertIsNotNone(proof)
        self.assertEqual(sorted(s.voter_id for s in proof.signatures),
                         ["fednode-0", "fednode-1", "fednode-2", "fednode-3"])
        self.assertTrue(engine.commit_defederation(proof))
        self.assertTrue(engine.firewall.is_blocked("honest-commit.lab.example"))
        self.assertTrue(proposal.is_committed)
        self.assertIsNone(engine.handle_vote(ballot("fednode-4", proposal, "APPROVE")))

    def test_commit_excludes_quarantined_voters_from_qc(self):
        engine, reputation, db, proposal = self.fresh_engine("quarantine-qc.lab.example")
        for voter in VOTERS:
            engine.handle_vote(ballot(voter, proposal, "APPROVE"))
        signatures = list(proposal.approved_votes.values())
        self.assertEqual(len(signatures), 5)
        db.set_reputation("fednode-4", 20)

        def proof_of(sigs):
            return pb2.QuorumProof(proposal_id=proposal.proposal_id,
                                   sequence_number=proposal.sequence_number, epoch=proposal.epoch,
                                   target_domain=proposal.target_domain, reason=proposal.reason,
                                   signatures=sigs, finalized_at=int(time.time() * 1000))
        four_with_quarantined = [s for s in signatures if s.voter_id != "fednode-3"]
        self.assertFalse(engine.commit_defederation(proof_of(four_with_quarantined)))
        self.assertFalse(engine.firewall.is_blocked("quarantine-qc.lab.example"))
        tampered = [pb2.VoterSignature(voter_id=s.voter_id, signature="00" * 64, timestamp=s.timestamp)
                    if s.voter_id == "fednode-1" else s for s in signatures]
        self.assertFalse(engine.commit_defederation(proof_of(tampered)))
        self.assertTrue(engine.commit_defederation(proof_of(signatures)))
        self.assertTrue(engine.firewall.is_blocked("quarantine-qc.lab.example"))

    @PBT
    @given(decisions=st.fixed_dictionaries({v: st.sampled_from(["APPROVE", "REJECT"]) for v in VOTERS}),
           order=st.lists(st.sampled_from(VOTERS), min_size=1, max_size=16),
           quarantined=st.one_of(st.none(), st.sampled_from(VOTERS)),
           forged=st.one_of(st.none(), st.tuples(st.sampled_from(VOTERS), st.integers(0, 16))))
    def test_conflict_free_sequences_match_observed_behaviour(self, decisions, order, quarantined, forged):
        """**Validates: Requirements 3.1, 3.2, 3.5**"""
        engine, reputation, db, proposal = self.fresh_engine()
        trust = {v: 100 for v in VOTERS}
        if quarantined:
            db.set_reputation(quarantined, 20)
            trust[quarantined] = 20
        approvals = {"fednode-0"}
        events = [(v, False) for v in order]
        if forged:
            events.insert(min(forged[1], len(events)), (forged[0], True))
        for voter, is_forged in events:
            result = engine.handle_vote(ballot(voter, proposal, decisions[voter], forged=is_forged))
            expected_qc = False
            if trust[voter] < 30:
                pass  # quarantined: excluded, nothing changes
            elif is_forged:
                trust[voter] = max(0, trust[voter] - 40)
            elif decisions[voter] == "APPROVE":
                approvals.add(voter)
                trust[voter] = min(100, trust[voter] + 2)
                expected_qc = len(approvals) >= 4
            if expected_qc:
                self.assertIsNotNone(result)
                self.assertEqual(sorted(s.voter_id for s in result.signatures), sorted(approvals))
            else:
                self.assertIsNone(result)
            self.assertEqual(sorted(proposal.approved_votes), sorted(approvals))
        for voter in VOTERS:
            self.assertEqual(trust_of(reputation, voter), trust[voter], voter)
        if quarantined:
            self.assertNotIn(quarantined, proposal.approved_votes)


class QuorumMathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        EngineFixture(cls)

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        gc.collect()
        cls.temp.cleanup()

    def test_five_nodes_strict_and_majority(self):
        self.assertEqual(self.config.total_nodes, 5)
        self.assertEqual(self.config.max_byzantine_faults, 1)
        self.assertEqual(self.config.quorum_size, 4)
        with patch.dict(os.environ, {"QUORUM_MODE": "MAJORITY"}):
            self.assertEqual(self.config.quorum_size, 3)

    @PBT
    @given(n=st.integers(1, 32), mode=st.sampled_from(["STRICT", "MAJORITY"]))
    def test_quorum_formula(self, n, mode):
        """**Validates: Requirements 3.2**"""
        original = list(self.config.peers)
        try:
            self.config.peers = [f"fednode-{i}.invalid:{59050 + i}" for i in range(n)]
            f = (n - 1) // 3
            with patch.dict(os.environ, {"QUORUM_MODE": mode}):
                self.assertEqual(self.config.max_byzantine_faults, f)
                self.assertEqual(self.config.quorum_size, 2 * f + 1 if mode == "MAJORITY" else n - f)
        finally:
            self.config.peers = original


# ---------------------------------------------------------------------------
# 3.8: valid, authenticated operator requests
# ---------------------------------------------------------------------------
@st.composite
def mixed_case_mode(draw):
    mode = draw(st.sampled_from(OPERATOR_MODES))
    flags = draw(st.lists(st.booleans(), min_size=len(mode), max_size=len(mode)))
    return mode, "".join(c.upper() if up else c.lower() for c, up in zip(mode, flags))


class ValidOperatorRequestTests(unittest.TestCase):
    def setUp(self):
        self.node = NodeHarness("fednode-0")
        self.addCleanup(self.node.close)
        self.port = self.node.serve()
        self.service = self.node.runner.service

    @PBT
    @given(mode=mixed_case_mode(), offline=st.sampled_from([True, False, "absent"]),
           start_offline=st.booleans())
    def test_fault_switches_mode_and_honours_offline(self, mode, offline, start_offline):
        """**Validates: Requirements 3.7, 3.8**"""
        canonical, sent = mode
        self.service.byzantine_mode = "FORGER"
        self.service.simulated_offline = start_offline
        self.node.catchup_called.clear()
        self.node.catchup_mock.reset_mock()
        body = {"mode": sent}
        if offline != "absent":
            body["offline"] = offline
        status, response = request(self.port, "POST", "/fault", body)
        if offline is True:
            expected_mode, expected_offline = "SILENT", True
        elif offline is False:
            expected_mode, expected_offline = canonical, False
        else:
            expected_mode, expected_offline = canonical, start_offline
        self.assertEqual(status, 200)
        self.assertEqual(response, {"status": "OK", "node_id": "fednode-0", "byzantine_mode": expected_mode})
        self.assertEqual(self.service.byzantine_mode, expected_mode)
        self.assertEqual(self.service.simulated_offline, expected_offline)
        if offline is False:
            self.assertTrue(self.node.catchup_called.wait(3), "revive did not run catch-up sync")
        else:
            self.assertEqual(self.node.catchup_mock.call_count, 0)

    def test_fault_without_mode_defaults_to_none(self):
        self.service.byzantine_mode = "LIAR"
        status, response = request(self.port, "POST", "/fault", {})
        self.assertEqual(status, 200)
        self.assertEqual(response["byzantine_mode"], "NONE")
        self.assertEqual(self.service.byzantine_mode, "NONE")

    @PBT
    @given(peer=st.sampled_from([f"fednode-{i}" for i in range(5)]), score=st.integers(0, 100))
    def test_reputation_sets_absolute_score(self, peer, score):
        """**Validates: Requirements 3.6, 3.8**"""
        status, response = request(self.port, "POST", "/reputation", {"peer_id": peer, "score": score})
        self.assertEqual(status, 200)
        self.assertEqual(response, {"status": "OK", "peer_id": peer, "score": score})
        row = row_of(self.node.runner.reputation, peer)
        self.assertEqual(row["trust_score"], score)
        self.assertEqual(row["is_active"], 0 if score < 30 else 1)
        self.assertEqual(self.node.runner.reputation.is_peer_eligible_to_vote(peer), score >= 30)

    @PBT
    @given(index=st.integers(5, 99), port=st.integers(1, 65535))
    def test_peers_adds_new_peer(self, index, port):
        """**Validates: Requirements 3.8**"""
        config = self.node.runner.config
        config.peers = list(PEER_LIST)
        address = f"fednode-{index}.invalid:{port}"
        status, response = request(self.port, "POST", "/peers", {"peer_address": address})
        self.assertEqual(status, 200)
        self.assertEqual(response, {"status": "OK", "total_nodes": 6, "quorum": 5})
        self.assertEqual(config.peers, PEER_LIST + [address])
        self.assertIn(f"fednode-{index}", self.node.runner.consensus.peer_public_keys)

    def test_peers_existing_address_is_not_duplicated(self):
        config = self.node.runner.config
        config.peers = list(PEER_LIST)
        status, response = request(self.port, "POST", "/peers", {"peer_address": PEER_LIST[3]})
        self.assertEqual(status, 200)
        self.assertEqual(response, {"status": "OK", "total_nodes": 5, "quorum": 4})
        self.assertEqual(config.peers, PEER_LIST)


# ---------------------------------------------------------------------------
# 3.3, 3.10: telemetry and public routes
# ---------------------------------------------------------------------------
TOP_LEVEL_KEYS = {"node_id", "org", "state", "epoch", "last_sequence", "quorum", "operational_mode",
                  "reputations", "blocked_domains", "proposals", "events"}
PROPOSAL_KEYS = {"proposal_id", "domain", "proposer", "reason", "epoch", "sequence", "created_at",
                 "committed", "latency_ms", "threat_score", "approvals", "quorum", "observer"}
REPUTATION_KEYS = {"peer_id", "trust_score", "violations_count", "is_active", "last_updated"}


def strip_additive(snapshot):
    """Remove only the additive quorum-health fields the fix introduces."""
    data = dict(snapshot)
    health = data.pop("quorum_health", None)
    states = []
    proposals = []
    for proposal in data["proposals"]:
        proposal = dict(proposal)
        states.append((proposal["committed"], proposal.pop("quorum_state", None)))
        proposals.append(proposal)
    data["proposals"] = proposals
    return data, health, states


class TelemetryPreservationTests(unittest.TestCase):
    def setUp(self):
        self.node = NodeHarness("fednode-0")
        self.addCleanup(self.node.close)
        self.runner = self.node.runner

    def check_existing_fields(self, snapshot, request_id):
        data, health, states = strip_additive(snapshot)
        self.assertEqual(set(data), TOP_LEVEL_KEYS)
        self.assertEqual(data["node_id"], "fednode-0")
        self.assertEqual(data["org"], "glasgow.social")
        self.assertEqual(data["state"], "LEADER")
        self.assertEqual(data["epoch"], 1)
        self.assertEqual(data["last_sequence"], 0)
        self.assertEqual(data["quorum"], 4)
        self.assertEqual(data["operational_mode"], "AUTOMATIC")
        self.assertEqual(data["blocked_domains"], [])
        self.assertEqual(len(data["reputations"]), 1)
        reputation = data["reputations"][0]
        self.assertEqual(set(reputation), REPUTATION_KEYS)
        self.assertEqual((reputation["peer_id"], reputation["trust_score"],
                          reputation["violations_count"], reputation["is_active"]),
                         ("fednode-2", 20, 0, 0))
        self.assertEqual(len(data["proposals"]), 1)
        proposal = data["proposals"][0]
        self.assertEqual(set(proposal), PROPOSAL_KEYS)
        expected = {"proposal_id": request_id, "domain": "pending-ok.lab.example",
                    "proposer": "fednode-0", "reason": 1, "epoch": 1, "sequence": 1,
                    "committed": False, "latency_ms": 0, "threat_score": 0.9,
                    "approvals": ["fednode-0"], "quorum": 4, "observer": "fednode-0"}
        self.assertEqual({k: v for k, v in proposal.items() if k != "created_at"}, expected)
        self.assertIsInstance(proposal["created_at"], int)
        proposal_events = [e for e in data["events"] if e.get("proposal_id") == request_id]
        self.assertEqual([(e["kind"], e["message"]) for e in proposal_events],
                         [("proposal", "Proposed a domain block")])
        # Additive fields, when present, must say the quorum is reachable (eligible 4 >= Q 4).
        if health is not None:
            self.assertIs(health["quorum_reachable"], True)
        for committed, state in states:
            if state is not None:
                self.assertEqual(state, "committed" if committed else "awaiting")
        for forbidden in ("private_key", "signature", "evidence_payload", "voter_signature"):
            self.assertNotIn(forbidden, json.dumps(data))

    def test_snapshot_fields_unchanged_when_quorum_reachable(self):
        self.runner.db.set_reputation("fednode-2", 20)
        req = self.runner.consensus.create_proposal("pending-ok.lab.example", 1, "{}", "", 0.9)
        self.check_existing_fields(node_snapshot(self.runner.service), req.proposal_id)

    def test_public_routes_need_no_credential(self):
        self.runner.db.set_reputation("fednode-2", 20)
        req = self.runner.consensus.create_proposal("pending-ok.lab.example", 1, "{}", "", 0.9)
        port = self.node.serve()
        status, telemetry = request(port, "GET", "/telemetry", token=None)
        self.assertEqual(status, 200)
        self.check_existing_fields(telemetry, req.proposal_id)
        for path in ("/health", "/status"):
            status, body = request(port, "GET", path, token=None)
            self.assertEqual(status, 200)
            self.assertEqual(body, {"status": "HEALTHY", "node_id": "fednode-0", "blocked_domains": 0})
        status, _ = request(port, "GET", "/unknown", token=None)
        self.assertEqual(status, 404)
        benign = {"actor": "https://glasgow.social/users/lab-sender",
                  "object": {"type": "Note", "content": "Hello from the federation security lab."}}
        status, body = request(port, "POST", "/inbox", benign, token=None)
        self.assertEqual(status, 202)
        self.assertEqual(body["status"], "ACCEPTED")
        self.assertEqual(body["domain"], "glasgow.social")
        status, body = request(port, "POST", "/inbox", token=None, raw=b"not json")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "Invalid ActivityStreams JSON payload"})

    def test_public_routes_return_503_while_soft_offline(self):
        port = self.node.serve()
        self.runner.service.simulated_offline = True
        for path in ("/health", "/status", "/telemetry"):
            self.assertEqual(request(port, "GET", path, token=None)[0], 503, path)
        benign = {"actor": "https://glasgow.social/users/lab-sender",
                  "object": {"type": "Note", "content": "Hello"}}
        self.assertEqual(request(port, "POST", "/inbox", benign, token=None)[0], 503)


# ---------------------------------------------------------------------------
# 3.9: BYZANTINE_MODE env and in-process set_byzantine_mode()
# ---------------------------------------------------------------------------
class InProcessModeTests(unittest.TestCase):
    def test_set_byzantine_mode_accepts_censor_and_equivocator(self):
        node = NodeHarness("fednode-0")
        self.addCleanup(node.close)
        service = node.runner.service
        for sent, expected in (("CENSOR", "CENSOR"), ("EQUIVOCATOR", "EQUIVOCATOR"),
                               ("censor", "CENSOR"), (" equivocator ", "EQUIVOCATOR")):
            with self.subTest(sent):
                service.set_byzantine_mode(sent)
                self.assertEqual(service.byzantine_mode, expected)
                self.assertEqual(node_snapshot(service)["state"], "BYZANTINE_" + expected)

    def test_env_equivocator_mode(self):
        node = NodeHarness("fednode-1", BYZANTINE_MODE="EQUIVOCATOR")
        self.addCleanup(node.close)
        self.assertEqual(node.runner.service.byzantine_mode, "EQUIVOCATOR")
        self.assertEqual(node_snapshot(node.runner.service)["state"], "BYZANTINE_EQUIVOCATOR")

    def test_env_censor_mode(self):
        node = NodeHarness("fednode-1", BYZANTINE_MODE="censor")
        self.addCleanup(node.close)
        self.assertEqual(node.runner.service.byzantine_mode, "CENSOR")
        self.assertEqual(node_snapshot(node.runner.service)["state"], "BYZANTINE_CENSOR")


# ---------------------------------------------------------------------------
# 3.6, 3.7, 3.8, 3.11: dashboard operator actions and POST API checks
# ---------------------------------------------------------------------------
class RecordingRuntime:
    kind = "docker"
    namespace = "default"

    def __init__(self, available=False):
        self.available = available
        self.calls = []

    def capabilities(self):
        return {"kind": "docker", "available": self.available,
                "message": "Runtime in this test" if self.available else "No runtime in this test"}

    def fault(self, node_id, mode):
        self.calls.append(("fault", node_id, mode))
        return f"Runtime restarted {node_id} with BYZANTINE_MODE={mode}"

    def node_call(self, node_id, req):
        self.calls.append(("node_call", node_id, req))
        if req.get("operation") == "trust":
            return {"score": req["score"], "quarantined": req["score"] < 30}
        return {}

    def lifecycle(self, node_id, action):
        self.calls.append(("lifecycle", node_id, action))
        return f"Runtime {action} completed"

    def ensure_forward(self, index):
        pass

    def close(self):
        pass


def recording_open(log, fail=False):
    def fake_open(req, timeout=None):
        log.append((req.full_url, json.loads(req.data) if req.data else None))
        if fail:
            raise URLError("node unreachable")
        return io.BytesIO(b'{"status": "OK", "node_id": "fednode-1", "byzantine_mode": "NONE"}')
    return fake_open


class DashboardActionTests(unittest.TestCase):
    def make_operator(self, available=False):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.monitor = ClusterMonitor(configured_nodes(DASHBOARD_NODES))
        self.addCleanup(self.monitor.close)
        self.runtime = RecordingRuntime(available)
        self.operator = Operator(self.monitor, runtime=self.runtime,
                                 state_path=os.path.join(self.temp.name, "state.json"))
        self.operator.connected = True
        self.monitor._data["nodes"] = [
            {"node_id": f"fednode-{i}", "online": True, "reputations": []} for i in range(5)]
        self.address = {n["node_id"]: n["address"] for n in self.monitor.nodes}

    def run_action(self, body, fail=False):
        log = []
        with patch.object(self.monitor, "refresh"), \
                patch.object(self.operator.opener, "open", side_effect=recording_open(log, fail)):
            result = self.operator.handle(body)
        return result, log

    def test_stop_puts_node_soft_offline(self):
        self.make_operator()
        result, log = self.run_action({"action": "stop", "node": "fednode-1"})
        self.assertEqual(log, [(self.address["fednode-1"] + "/fault", {"mode": "SILENT", "offline": True})])
        self.assertEqual(result["message"], "[fednode-1] Node killed (offline)")
        self.assertEqual(self.runtime.calls, [])

    def test_revive_sends_none_offline_false(self):
        self.make_operator()
        result, log = self.run_action({"action": "revive", "node": "fednode-1"})
        fault_calls = [entry for entry in log if entry[0].endswith("/fault")]
        self.assertEqual(fault_calls, [(self.address["fednode-1"] + "/fault", {"mode": "NONE", "offline": False})])
        self.assertEqual(log[0], fault_calls[0])
        self.assertEqual(result["message"], "[fednode-1] Node revived and syncing missed bans")
        self.assertEqual(self.runtime.calls, [])

    def test_stop_and_revive_with_runtime_use_lifecycle(self):
        self.make_operator(available=True)
        for action in ("stop", "revive"):
            with self.subTest(action):
                self.runtime.calls.clear()
                result, log = self.run_action({"action": action, "node": "fednode-2"})
                self.assertEqual(log, [])
                self.assertEqual(self.runtime.calls, [("lifecycle", "fednode-2", action)])
                self.assertEqual(result["message"], f"Runtime {action} completed. "
                                 "Existing node persistence/recovery behavior is unchanged.")

    def test_valid_settings_switch_mode(self):
        self.make_operator()
        for mode in OPERATOR_MODES:
            with self.subTest(mode):
                result, log = self.run_action({"action": "settings", "node": "fednode-3", "fault": mode})
                self.assertEqual(log, [(self.address["fednode-3"] + "/fault", {"mode": mode})])
                self.assertEqual(result["message"], f"[fednode-3] Byzantine mode switched to: {mode}")
        self.assertEqual(self.runtime.calls, [])

    def test_valid_settings_fall_back_to_runtime_on_http_failure(self):
        self.make_operator()
        result, log = self.run_action({"action": "settings", "node": "fednode-3", "fault": "LIAR"}, fail=True)
        self.assertEqual(len(log), 1)
        self.assertEqual(self.runtime.calls, [("fault", "fednode-3", "LIAR")])
        self.assertEqual(result["message"], "Runtime restarted fednode-3 with BYZANTINE_MODE=LIAR")

    @PBT
    @given(node=st.sampled_from([f"fednode-{i}" for i in range(5)]),
           peer=st.sampled_from([f"fednode-{i}" for i in range(5)]),
           score=st.integers(0, 100), scope=st.sampled_from(["selected", "all", None]))
    def test_trust_sets_score_on_targeted_ledgers(self, node, peer, score, scope):
        """**Validates: Requirements 3.6**"""
        if not hasattr(self, "operator"):
            self.make_operator()
        body = {"action": "trust", "node": node, "peer": peer, "score": score}
        if scope:
            body["scope"] = scope
        result, log = self.run_action(body)
        targets = [f"fednode-{i}" for i in range(5)] if scope == "all" else [node]
        self.assertEqual(log, [(self.address[t] + "/reputation", {"peer_id": peer, "score": score})
                               for t in targets])
        self.assertEqual(result["outcomes"], [{"node_id": t, "score": score, "quarantined": score < 30}
                                              for t in targets])
        self.assertEqual(result["message"], "Existing reputation helper applied the requested score")

    def test_trust_includes_self_entry_and_falls_back_to_runtime(self):
        self.make_operator()
        result, log = self.run_action({"action": "trust", "node": "fednode-2", "peer": "fednode-2",
                                       "score": 20, "scope": "all"}, fail=True)
        self.assertEqual(len(log), 1)
        self.assertEqual(self.runtime.calls, [
            ("node_call", f"fednode-{i}", {"operation": "trust", "peer": "fednode-2", "score": 20})
            for i in range(5)])
        self.assertEqual(result["outcomes"], [{"node_id": f"fednode-{i}", "score": 20, "quarantined": True}
                                              for i in range(5)])

    def test_trust_rejects_invalid_scores(self):
        self.make_operator()
        for score in (-1, 101, 1.5, True, "20", None):
            with self.subTest(score=score):
                with self.assertRaises(ValueError):
                    self.run_action({"action": "trust", "node": "fednode-0", "peer": "fednode-2", "score": score})


class DashboardToNodeTests(unittest.TestCase):
    """Dashboard actions against an in-process node; the token comes from the shared env var."""

    def setUp(self):
        self.node = NodeHarness("fednode-0")
        self.addCleanup(self.node.close)
        self.port = self.node.serve()
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        # Five configured dashboard nodes, all served by the single in-process node, so that
        # fednode-0..4 are valid selections; only fednode-0 is used as the target.
        self.monitor = ClusterMonitor(configured_nodes(",".join([f"http://127.0.0.1:{self.port}"] * 5)))
        self.addCleanup(self.monitor.close)
        self.runtime = RecordingRuntime(False)
        self.operator = Operator(self.monitor, runtime=self.runtime,
                                 state_path=os.path.join(self.temp.name, "state.json"))
        self.operator.connected = True
        self.monitor._data["nodes"] = [
            {"node_id": f"fednode-{i}", "online": True, "reputations": []} for i in range(5)]

    def test_trust_stop_revive_settings_reach_the_node(self):
        service = self.node.runner.service
        with patch.object(self.monitor, "refresh"):
            result = self.operator.handle({"action": "trust", "node": "fednode-0",
                                           "peer": "fednode-3", "score": 20})
            self.assertEqual(result["outcomes"], [{"node_id": "fednode-0", "score": 20, "quarantined": True}])
            self.assertEqual(trust_of(self.node.runner.reputation, "fednode-3"), 20)
            self.assertFalse(self.node.runner.reputation.is_peer_eligible_to_vote("fednode-3"))

            self.operator.handle({"action": "settings", "node": "fednode-0", "fault": "LIAR"})
            self.assertEqual(service.byzantine_mode, "LIAR")

            self.operator.handle({"action": "stop", "node": "fednode-0"})
            self.assertTrue(service.simulated_offline)
            self.assertEqual(service.byzantine_mode, "SILENT")
            self.assertEqual(request(self.port, "GET", "/health", token=None)[0], 503)

            self.node.catchup_called.clear()
            self.operator.handle({"action": "revive", "node": "fednode-0"})
            self.assertFalse(service.simulated_offline)
            self.assertEqual(service.byzantine_mode, "NONE")
            self.assertTrue(self.node.catchup_called.wait(3), "revive did not run catch-up sync")
            self.assertEqual(request(self.port, "GET", "/health", token=None)[0], 200)
        self.assertEqual(self.runtime.calls, [], "the HTTP path failed and the runtime fallback was used")


def telemetry(node_id, reputations=()):
    return {"node_id": node_id, "state": "FOLLOWER", "epoch": 1, "quorum": 4, "last_sequence": 0,
            "operational_mode": "AUTOMATIC", "events": [], "proposals": [],
            "blocked_domains": [], "reputations": list(reputations)}


def rep(peer_id, score):
    return {"peer_id": peer_id, "trust_score": score, "violations_count": 0,
            "is_active": 0 if score < 30 else 1, "last_updated": 0}


class DashboardMonitorPreservationTests(unittest.TestCase):
    def test_quarantined_by_lists_other_online_observers(self):
        monitor = ClusterMonitor(configured_nodes(DASHBOARD_NODES))
        self.addCleanup(monitor.close)
        addresses = {n["node_id"]: n["address"] for n in monitor.nodes}
        views = {f"fednode-{i}": telemetry(f"fednode-{i}") for i in range(5)}
        views["fednode-0"] = telemetry("fednode-0", [rep("fednode-2", 20)])
        views["fednode-1"] = telemetry("fednode-1", [rep("fednode-2", 10), rep("fednode-3", 90)])

        def fake_json(address):
            for node_id, base in addresses.items():
                if address.startswith(base):
                    return json.loads(json.dumps(views[node_id]))
            raise URLError("unknown address")
        with patch.object(monitor, "_json", side_effect=fake_json):
            monitor.refresh()
        data = monitor.snapshot()
        self.assertTrue({"nodes", "events", "bans", "updated_at"} <= set(data))
        by_id = {n["node_id"]: n for n in data["nodes"]}
        self.assertEqual(by_id["fednode-2"]["quarantined_by"], ["fednode-0", "fednode-1"])
        self.assertTrue(by_id["fednode-2"]["quarantined"])
        for other in ("fednode-0", "fednode-1", "fednode-3", "fednode-4"):
            self.assertEqual(by_id[other]["quarantined_by"], [])
            self.assertFalse(by_id[other]["quarantined"])
        if "quorum_health" in data:  # additive; 4 eligible >= Q=4
            self.assertIs(data["quorum_health"]["quorum_reachable"], True)


class DashboardPostApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.monitor = ClusterMonitor(configured_nodes(DASHBOARD_NODES))
        self.addCleanup(self.monitor.close)
        self.operator = Operator(self.monitor, runtime=RecordingRuntime(False),
                                 state_path=os.path.join(self.temp.name, "state.json"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.monitor, self.operator))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def post(self, headers, data=b'{"action":"connect"}'):
        try:
            with OPENER.open(Request(self.base + "/api/actions", data, headers, method="POST"),
                             timeout=5) as response:
                return response.status
        except HTTPError as error:
            error.close()
            return error.code

    def test_loopback_origin_csrf_and_content_type_checks(self):
        csrf = self.operator.csrf
        same_origin = f"127.0.0.1:{self.server.server_port}"
        cases = [
            ("non-loopback host", {"Content-Type": "application/json", "X-CSRF-Token": csrf,
                                   "Host": "evil.example"}, 403),
            ("cross origin", {"Content-Type": "application/json", "X-CSRF-Token": csrf,
                              "Origin": "https://untrusted.example"}, 403),
            ("missing csrf", {"Content-Type": "application/json"}, 403),
            ("wrong csrf", {"Content-Type": "application/json", "X-CSRF-Token": "wrong-" + csrf}, 403),
            ("wrong content type", {"Content-Type": "text/plain", "X-CSRF-Token": csrf}, 415),
            ("valid", {"Content-Type": "application/json", "X-CSRF-Token": csrf}, 200),
            ("valid same origin", {"Content-Type": "application/json", "X-CSRF-Token": csrf,
                                   "Origin": "http://" + same_origin}, 200),
        ]
        with patch.object(self.operator, "handle", return_value={"message": "Observed"}) as handle:
            for label, headers, expected in cases:
                with self.subTest(label):
                    handle.reset_mock()
                    self.assertEqual(self.post(headers), expected)
                    self.assertEqual(handle.called, expected == 200)


if __name__ == "__main__":
    unittest.main()
