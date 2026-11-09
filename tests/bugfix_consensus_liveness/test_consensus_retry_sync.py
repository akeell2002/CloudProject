"""Unit and property tests for task 3.2: keyed consensus penalties, the pending-proposal
retry filter, peer reachability and lower-only reputation sync.

Isolation: no test dials a real peer. Nodes are built in process (never started) with
HTTP_PORT=0, GRPC_PORT=0 and a temp DATA_DIR. Peers are fednode-N.invalid:5905N.
``FedNodeRunner._get_stub`` and the gRPC channel/stub used by catch-up are replaced
with in-memory stubs.

Run: python tests/bugfix_consensus_liveness/test_consensus_retry_sync.py
"""
import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import gc
import itertools
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from hypothesis import HealthCheck, given, settings, strategies as st

from proto import fedconsensus_pb2 as pb2
from node.config import NodeConfig, peer_id_from_addr
from node.crypto.ed25519 import generate_deterministic_keypair, sign_message
from node.engine.catchup import CatchupEngine
from node.engine.consensus import ConsensusEngine
from node.ingress.firewall import FirewallFilter
from node.main import FedNodeRunner
from node.storage.database import Database
from node.storage.reputation import ReputationManager

SECRET = "bugfix-consensus-liveness-secret"
PEER_ADDRS = [f"fednode-{i}.invalid:{59050 + i}" for i in range(5)]
NODE_IDS = [f"fednode-{i}" for i in range(5)]

FIRST_EQUIVOCATION = "Equivocation detected: peer sent conflicting signed ballots (-50 trust)"
REPEATED_EQUIVOCATION = "Conflicting ballot ignored (equivocation already penalised for this proposal)"


def node_env(data_dir, node_id):
    return {
        "DATA_DIR": data_dir, "NODE_ID": node_id, "HTTP_PORT": "0", "GRPC_PORT": "0",
        "PEER_ADDRESSES": ",".join(PEER_ADDRS), "CONSORTIUM_SECRET": SECRET,
        "USE_RANDOM_NODE_KEYS": "false", "BYZANTINE_MODE": "NONE", "QUORUM_MODE": "STRICT",
        "OPERATIONAL_MODE": "AUTOMATIC",
    }


def ballot(voter_id, proposal, decision):
    meta = {"proposal_id": proposal.proposal_id, "sequence_number": proposal.sequence_number,
            "epoch": proposal.epoch, "target_domain": proposal.target_domain, "decision": decision}
    key = generate_deterministic_keypair(f"{SECRET}-{voter_id}")[0]
    return pb2.VoteRequest(
        proposal_id=proposal.proposal_id, sequence_number=proposal.sequence_number,
        epoch=proposal.epoch, target_domain=proposal.target_domain, voter_id=voter_id,
        decision=pb2.VOTE_APPROVE if decision == "APPROVE" else pb2.VOTE_REJECT,
        voter_signature=sign_message(key, meta), timestamp=int(time.time() * 1000),
    )


def ledger(db):
    return {r["peer_id"]: r for r in db.get_all_reputations()}


class TempEnv:
    """Temp DATA_DIR plus patched environment for one node id."""

    def __init__(self, node_id):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.env = patch.dict(os.environ, node_env(self.temp.name, node_id))
        self.env.start()

    def close(self):
        self.env.stop()
        gc.collect()
        self.temp.cleanup()


class RunnerHarness(TempEnv):
    """A FedNodeRunner that is never started (no servers, no heartbeat thread)."""

    def __init__(self, node_id):
        super().__init__(node_id)
        self.runner = FedNodeRunner()

    def close(self):
        self.runner._rpc_executor.shutdown(wait=False)
        self.runner.service._rpc_executor.shutdown(wait=False)
        super().close()


# ---------------------------------------------------------------------------
# handle_vote: equivocation telemetry on first and repeated detection
# ---------------------------------------------------------------------------
class EquivocationTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv("fednode-0")
        self.addCleanup(self.env.close)
        config = NodeConfig()
        self.db = Database(os.path.join(self.env.temp.name, "engine.db"))
        self.reputation = ReputationManager(self.db, self_id="fednode-0")
        self.engine = ConsensusEngine(config, self.db, FirewallFilter(self.db), self.reputation)
        request = self.engine.create_proposal("equivocate.lab.example", 1, "{}", "", 0.9)
        self.proposal = self.engine.active_proposals[request.proposal_id]

    def invalid_messages(self):
        return [e["message"] for e in self.engine.telemetry.snapshot()
                if e.get("kind") == "invalid" and e.get("source") == "fednode-1"]

    def test_first_and_repeated_equivocation_messages_differ(self):
        self.engine.handle_vote(ballot("fednode-1", self.proposal, "REJECT"))
        self.engine.handle_vote(ballot("fednode-1", self.proposal, "APPROVE"))
        self.engine.handle_vote(ballot("fednode-1", self.proposal, "APPROVE"))

        self.assertEqual(self.invalid_messages(), [FIRST_EQUIVOCATION, REPEATED_EQUIVOCATION])
        self.assertEqual(ledger(self.db)["fednode-1"]["trust_score"], 50)
        self.assertEqual(ledger(self.db)["fednode-1"]["violations_count"], 1)
        self.assertNotIn("fednode-1", self.proposal.approved_votes)
        self.assertEqual(self.proposal.recorded_decisions["fednode-1"], pb2.VOTE_REJECT,
                         "recorded_decisions must keep the first decision")

    def test_equivocator_is_dropped_from_approved_votes(self):
        self.engine.handle_vote(ballot("fednode-1", self.proposal, "APPROVE"))
        self.assertIn("fednode-1", self.proposal.approved_votes)
        self.engine.handle_vote(ballot("fednode-1", self.proposal, "REJECT"))
        self.assertNotIn("fednode-1", self.proposal.approved_votes)
        self.assertEqual(self.invalid_messages(), [FIRST_EQUIVOCATION])

    def test_equivocation_is_penalised_again_on_a_different_proposal(self):
        self.engine.handle_vote(ballot("fednode-1", self.proposal, "REJECT"))
        self.engine.handle_vote(ballot("fednode-1", self.proposal, "APPROVE"))
        request = self.engine.create_proposal("second.lab.example", 1, "{}", "", 0.9)
        other = self.engine.active_proposals[request.proposal_id]
        self.engine.handle_vote(ballot("fednode-1", other, "REJECT"))
        self.engine.handle_vote(ballot("fednode-1", other, "APPROVE"))
        self.assertEqual(ledger(self.db)["fednode-1"]["trust_score"], 0)
        self.assertEqual(self.invalid_messages(), [FIRST_EQUIVOCATION, FIRST_EQUIVOCATION])


# ---------------------------------------------------------------------------
# _heartbeat_loop retry filter (driven directly via _retry_pending_proposals)
# ---------------------------------------------------------------------------
class RetrySkipSetTests(unittest.TestCase):
    def setUp(self):
        self.node = RunnerHarness("fednode-0")
        self.addCleanup(self.node.close)
        self.runner = self.node.runner
        self.dialed = []
        self.stub = MagicMock()
        self.stub.ProposeDefederation.return_value = pb2.ProposeResponse(accepted=True)

        def fake_get_stub(peer_addr):
            self.dialed.append(peer_addr)
            return self.stub

        patcher = patch.object(self.runner, "_get_stub", side_effect=fake_get_stub)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_retry_skips_recorded_and_approved_peers_but_retries_silent_ones(self):
        consensus = self.runner.consensus
        request = consensus.create_proposal("retry.lab.example", 1, "{}", "", 0.9)
        proposal = consensus.active_proposals[request.proposal_id]
        consensus.handle_vote(ballot("fednode-1", proposal, "REJECT"))   # REJECT recorded
        consensus.handle_vote(ballot("fednode-2", proposal, "APPROVE"))  # approved
        # fednode-3 and fednode-4 never answered (crashed or SILENT)

        self.runner._retry_pending_proposals()

        self.assertEqual(sorted(self.dialed), ["fednode-3.invalid:59053", "fednode-4.invalid:59054"])
        self.assertEqual(self.stub.ProposeDefederation.call_count, 2)
        for call in self.stub.ProposeDefederation.call_args_list:
            self.assertEqual(call.args[0].proposal_id, request.proposal_id)

    def test_quarantined_voter_is_still_retried(self):
        consensus = self.runner.consensus
        self.runner.db.set_reputation("fednode-4", 10)  # quarantined: its ballot is never recorded
        request = consensus.create_proposal("quarantine-retry.lab.example", 1, "{}", "", 0.9)
        proposal = consensus.active_proposals[request.proposal_id]
        consensus.handle_vote(ballot("fednode-4", proposal, "APPROVE"))
        self.assertNotIn("fednode-4", proposal.recorded_decisions)

        self.runner._retry_pending_proposals()

        self.assertIn("fednode-4.invalid:59054", self.dialed)
        self.assertNotIn("fednode-0.invalid:59050", self.dialed, "the node must not retry itself")

    def test_expired_and_committed_proposals_are_not_retried(self):
        consensus = self.runner.consensus
        request = consensus.create_proposal("expired.lab.example", 1, "{}", "", 0.9)
        consensus.active_proposals[request.proposal_id].created_at -= 25.0
        request2 = consensus.create_proposal("committed.lab.example", 1, "{}", "", 0.9)
        consensus.active_proposals[request2.proposal_id].is_committed = True

        self.runner._retry_pending_proposals()

        self.assertEqual(self.dialed, [])


class RunnerWiringTests(unittest.TestCase):
    def setUp(self):
        self.node = RunnerHarness("fednode-1")
        self.addCleanup(self.node.close)

    def test_runner_reputation_knows_its_own_id(self):
        self.assertEqual(self.node.runner.reputation.self_id, "fednode-1")

    def test_runner_peer_id_helper_delegates_to_module_helper(self):
        # String-only parsing inputs (never dialed); ports kept outside the live cluster range.
        for addr in PEER_ADDRS + ["localhost:50058", "127.0.0.1:50056", "other-host:1234"]:
            self.assertEqual(self.node.runner._peer_id_from_addr(addr), peer_id_from_addr(addr))
        self.assertEqual(peer_id_from_addr("fednode-3.invalid:59053"), "fednode-3")
        self.assertEqual(peer_id_from_addr("localhost:50058"), "fednode-7")
        self.assertEqual(peer_id_from_addr("other-host:1234"), "other-host")


# ---------------------------------------------------------------------------
# CatchupEngine.sync_with_consortium: own entry, lower-only adoption, reachability
# ---------------------------------------------------------------------------
def fake_grpc(stub_for_addr):
    """Patches the gRPC channel and stub constructors used inside sync_with_consortium."""

    def make_channel(addr, *args, **kwargs):
        channel = MagicMock()
        channel.addr = addr
        channel.__enter__.return_value = channel
        channel.__exit__.return_value = False
        return channel

    return (patch("grpc.insecure_channel", side_effect=make_channel),
            patch("proto.fedconsensus_pb2_grpc.FedConsensusServiceStub",
                  side_effect=lambda channel: stub_for_addr(channel.addr)))


def status_stub(entries):
    stub = MagicMock()
    stub.CatchupSync.return_value = pb2.CatchupResponse(node_id="peer", records=[])
    stub.GetStatus.return_value = pb2.StatusResponse(node_id="peer", reputations=[
        pb2.PeerReputationEntry(peer_id=p, trust_score=s, is_active=a, violations_count=0)
        for p, s, a in entries
    ])
    return stub


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.node = RunnerHarness("fednode-2")
        self.addCleanup(self.node.close)
        self.runner = self.node.runner

    def sync(self, stub_for_addr):
        channel_patch, stub_patch = fake_grpc(stub_for_addr)
        with channel_patch, stub_patch:
            self.runner.catchup.sync_with_consortium(self.runner.consensus)

    def test_sync_never_touches_own_entry_and_only_lowers(self):
        db = self.runner.db
        db.set_reputation("fednode-3", 10)
        db.update_reputation("fednode-4", -40, is_violation=True)  # 60, violations 1
        stub = status_stub([
            ("fednode-2", 0, False),   # peer's view of us: must be ignored
            ("fednode-3", 25, False),  # higher than local 10: must not raise
            ("fednode-4", 20, False),  # lower than local 60: adopt
            ("fednode-1", 0, False),   # no local row: adopt
            ("fednode-0", 80, True),   # healthy: filtered out
        ])
        self.sync(lambda addr: stub)

        rows = ledger(db)
        self.assertNotIn("fednode-2", rows, "sync created or changed the node's own entry")
        self.assertEqual(rows["fednode-3"]["trust_score"], 10)
        self.assertEqual(rows["fednode-4"]["trust_score"], 20)
        self.assertEqual(rows["fednode-4"]["violations_count"], 1, "sync must keep violations_count")
        self.assertEqual(rows["fednode-4"]["is_active"], 0)
        self.assertEqual(rows["fednode-1"]["trust_score"], 0)
        self.assertNotIn("fednode-0", rows)

    def test_own_entry_unchanged_when_it_already_exists(self):
        self.runner.db.set_reputation("fednode-2", 70)
        self.sync(lambda addr: status_stub([("fednode-2", 0, False)]))
        self.assertEqual(ledger(self.runner.db)["fednode-2"]["trust_score"], 70)

    def test_peer_reachability_tracks_successful_and_failed_syncs(self):
        good = status_stub([])
        bad = MagicMock()
        bad.CatchupSync.side_effect = RuntimeError("unreachable")
        before = int(time.time() * 1000)
        self.sync(lambda addr: bad if addr.startswith("fednode-3.") else good)

        reach = self.runner.catchup.peer_reachability
        self.assertEqual(sorted(reach), ["fednode-0", "fednode-1", "fednode-3", "fednode-4"])
        self.assertNotIn("fednode-2", reach, "the local node is never probed")
        self.assertFalse(reach["fednode-3"]["reachable"])
        for peer in ("fednode-0", "fednode-1", "fednode-4"):
            self.assertTrue(reach[peer]["reachable"])
        for entry in reach.values():
            self.assertGreaterEqual(entry["checked_at"], before)

        # A later successful sync flips the peer back to reachable
        self.sync(lambda addr: good)
        self.assertTrue(reach["fednode-3"]["reachable"])


class SyncLowerOnlyPropertyTests(unittest.TestCase):
    """Property 1 (C2, ReputationSync): ledger[localNode] is unchanged and
    newLocal = min(oldLocal, remote) for every synced low entry."""

    @classmethod
    def setUpClass(cls):
        cls.env = TempEnv("fednode-2")
        cls.config = NodeConfig()
        cls.counter = itertools.count()

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    @settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(local=st.fixed_dictionaries({p: st.one_of(st.none(), st.integers(0, 100)) for p in NODE_IDS}),
           remote=st.fixed_dictionaries({p: st.tuples(st.integers(0, 100), st.booleans()) for p in NODE_IDS}))
    def test_sync_only_lowers_and_skips_self(self, local, remote):
        """**Validates: Requirements 2.4, 2.5**"""
        db = Database(os.path.join(self.env.temp.name, f"sync-{next(self.counter)}.db"))
        for peer, score in local.items():
            if score is not None:
                db.set_reputation(peer, score)
        reputation = ReputationManager(db, self_id="fednode-2")
        engine = CatchupEngine(self.config, db, FirewallFilter(db), reputation=reputation)
        stub = status_stub([(p, s, a) for p, (s, a) in remote.items()])
        channel_patch, stub_patch = fake_grpc(lambda addr: stub)
        with channel_patch, stub_patch:
            engine.sync_with_consortium()

        rows = ledger(db)
        for peer in NODE_IDS:
            old = local[peer]
            remote_score, remote_active = remote[peer]
            new = rows[peer]["trust_score"] if peer in rows else None
            if peer == "fednode-2" or not (remote_score < 30 or not remote_active):
                self.assertEqual(new, old, f"{peer} changed although it must not")
            elif old is None:
                self.assertEqual(new, remote_score)
            else:
                self.assertEqual(new, min(old, remote_score))


if __name__ == "__main__":
    unittest.main()
