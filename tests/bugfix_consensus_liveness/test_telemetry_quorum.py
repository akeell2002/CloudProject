"""Task 3.6: node telemetry quorum-health signal.

Runs in process only. The runner is never started, peers use non-resolving
`fednode-N.invalid:5905N` addresses, and no network port is opened.
"""
import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import gc
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from hypothesis import HealthCheck, given, settings, strategies as st

from node.main import FedNodeRunner
from node.telemetry import EventLog, node_snapshot, quorum_health

SECRET = "bugfix-consensus-liveness-secret"
NODES = [f"fednode-{i}" for i in range(5)]
PEERS = ",".join(f"fednode-{i}.invalid:{59050 + i}" for i in range(5))
SELF_ID = "fednode-0"
HEALTH_KEYS = {"total_nodes", "quorum", "eligible_voters", "eligible", "offline",
               "quarantined", "quorum_reachable"}

# Reachability states a member can be in on the local catch-up view.
NO_ENTRY, REACHABLE, UNREACHABLE_FRESH, UNREACHABLE_STALE = range(4)


def make_runner(data_dir):
    env = {
        "DATA_DIR": data_dir, "NODE_ID": SELF_ID, "HTTP_PORT": "0", "GRPC_PORT": "0",
        "PEER_ADDRESSES": PEERS, "CONSORTIUM_SECRET": SECRET, "USE_RANDOM_NODE_KEYS": "false",
        "BYZANTINE_MODE": "NONE", "QUORUM_MODE": "STRICT", "OPERATIONAL_MODE": "AUTOMATIC",
        "FEDCONSENSUS_OPERATOR_TOKEN": "",
    }
    patcher = patch.dict(os.environ, env)
    patcher.start()
    return FedNodeRunner(), patcher


class RunnerQuorumHealthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.runner, cls.patcher = make_runner(cls.temp.name)
        cls.request = cls.runner.consensus.create_proposal("pending.lab.example", 1, "{}", "", 0.9)

    @classmethod
    def tearDownClass(cls):
        cls.runner._rpc_executor.shutdown(wait=False)
        cls.runner.service._rpc_executor.shutdown(wait=False)
        cls.patcher.stop()
        gc.collect()
        cls.temp.cleanup()

    def apply(self, reach_states, quarantined):
        now_ms = int(time.time() * 1000)
        reachability = {}
        for node, state in zip(NODES, reach_states):
            if state == REACHABLE:
                reachability[node] = {"reachable": True, "checked_at": now_ms}
            elif state == UNREACHABLE_FRESH:
                reachability[node] = {"reachable": False, "checked_at": now_ms}
            elif state == UNREACHABLE_STALE:
                reachability[node] = {"reachable": False, "checked_at": now_ms - 60_000}
        self.runner.catchup.peer_reachability = reachability
        for node, is_quarantined in zip(NODES, quarantined):
            self.runner.db.set_reputation(node, 20 if is_quarantined else 100)

    # **Validates: Requirements 2.1, 2.2**
    @settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(reach_states=st.lists(st.sampled_from([NO_ENTRY, REACHABLE, UNREACHABLE_FRESH,
                                                  UNREACHABLE_STALE]), min_size=5, max_size=5),
           quarantined=st.lists(st.booleans(), min_size=5, max_size=5))
    def test_quorum_reachable_matches_eligible_count(self, reach_states, quarantined):
        self.apply(reach_states, quarantined)
        expected_offline = sorted(n for n, s in zip(NODES, reach_states)
                                  if s == UNREACHABLE_FRESH and n != SELF_ID)
        expected_quarantined = sorted(n for n, q in zip(NODES, quarantined) if q)
        expected_eligible = sorted(set(NODES) - set(expected_offline) - set(expected_quarantined))

        snap = node_snapshot(self.runner.service)
        health = snap["quorum_health"]
        self.assertEqual(set(health), HEALTH_KEYS)
        self.assertEqual(health["total_nodes"], 5)
        self.assertEqual(health["quorum"], 4)
        self.assertEqual(health["offline"], expected_offline)
        self.assertEqual(health["quarantined"], expected_quarantined)
        self.assertEqual(health["eligible"], expected_eligible)
        self.assertEqual(health["eligible_voters"], len(expected_eligible))
        self.assertIs(health["quorum_reachable"], len(expected_eligible) >= 4)
        proposal = next(p for p in snap["proposals"] if p["proposal_id"] == self.request.proposal_id)
        self.assertEqual(proposal["quorum_state"],
                         "awaiting" if health["quorum_reachable"] else "quorum_unreachable")

    def test_stale_or_missing_reachability_counts_as_online_and_self_is_online(self):
        self.apply([UNREACHABLE_FRESH, UNREACHABLE_STALE, NO_ENTRY, REACHABLE, UNREACHABLE_STALE],
                   [False] * 5)
        health = quorum_health(self.runner.service)
        self.assertEqual(health["offline"], [])
        self.assertEqual(health["eligible_voters"], 5)
        self.assertIs(health["quorum_reachable"], True)

    def test_committed_proposal_reports_committed(self):
        self.apply([NO_ENTRY] * 5, [False, False, True, True, False])
        with self.runner.consensus._lock:
            state = self.runner.consensus.active_proposals[self.request.proposal_id]
            state.is_committed = True
        try:
            snap = node_snapshot(self.runner.service)
        finally:
            with self.runner.consensus._lock:
                state.is_committed = False
        self.assertIs(snap["quorum_health"]["quorum_reachable"], False)
        proposal = next(p for p in snap["proposals"] if p["proposal_id"] == self.request.proposal_id)
        self.assertEqual(proposal["quorum_state"], "committed")


class StubServiceTests(unittest.TestCase):
    def stub_service(self):
        proposal = SimpleNamespace(
            proposal_id="p", target_domain="bad.example", reason=4, epoch=1,
            sequence_number=1, created_at=1, is_committed=False, approved_votes={})
        engine = SimpleNamespace(telemetry=EventLog("fednode-0"), _lock=threading.Lock(),
                                 active_proposals={"p": proposal})
        return SimpleNamespace(
            consensus=engine,
            config=SimpleNamespace(node_id="fednode-0", quorum_size=4, operational_mode="AUTOMATIC"),
            leader=SimpleNamespace(is_current_leader=lambda: True, current_epoch=1),
            byzantine_mode="NONE", db=SimpleNamespace(get_latest_sequence_number=lambda: 0),
            reputation=SimpleNamespace(get_ledger=lambda: []),
            firewall=SimpleNamespace(get_blocked_domains=lambda: set()),
        )

    def test_service_without_peers_or_catchup_has_no_quorum_health(self):
        service = self.stub_service()
        self.assertIsNone(quorum_health(service))
        snap = node_snapshot(service)
        self.assertIsNone(snap["quorum_health"])
        self.assertEqual(snap["proposals"][0]["quorum_state"], "awaiting")


if __name__ == "__main__":
    unittest.main()
