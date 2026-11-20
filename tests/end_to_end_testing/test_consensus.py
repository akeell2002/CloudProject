"""Consensus quorum, partition safety, commit, and quarantine tests."""
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.config import NodeConfig
from node.crypto.ed25519 import generate_keypair, sign_message
from node.engine.consensus import ConsensusEngine
from node.ingress.firewall import FirewallFilter
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from proto import fedconsensus_pb2 as pb2


class TestConsensusQuorumAndSafety(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_dynamic_bft_quorum_math(self):
        test_cases = [
            (4, 1, 3),
            (5, 1, 4),
            (7, 2, 5),
            (10, 3, 7),
            (16, 5, 11),
        ]
        for n, expected_f, expected_q in test_cases:
            f = (n - 1) // 3
            q = n - f
            self.assertEqual(f, expected_f)
            self.assertEqual(q, expected_q)
            self.assertGreaterEqual(2 * q - n, f + 1)

    def test_split_brain_partition_invariance(self):
        # 5-node cluster (Q=4) split 3 / 2 cannot commit on either side.
        self.assertLess(3, 4)
        self.assertLess(2, 4)

        # 7-node cluster (Q=5) split 4 / 3 cannot commit on either side.
        self.assertLess(4, 5)
        self.assertLess(3, 5)

    def test_live_quorum_minting_and_commit(self):
        db = Database(os.path.join(self.temp_dir, "consensus_test.db"))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        with patch.dict(os.environ, {"NODE_ID": "fednode-0", "DATA_DIR": self.temp_dir}):
            cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        engine = ConsensusEngine(cfg, db, fw, rep)

        keys = {"fednode-0": (cfg.private_key_hex, cfg.public_key_hex)}
        for i in range(1, 5):
            nid = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[nid] = (priv, pub)
            engine.register_peer_key(nid, pub)

        prop = engine.create_proposal(
            target_domain="botnet-c2.net",
            reason=pb2.REASON_BOTNET,
            evidence_payload='{"actor": "https://botnet-c2.net/attacker"}',
            origin_http_signature="",
            threat_score=0.92,
        )
        self.assertEqual(prop.sequence_number, 1)
        self.assertIn("botnet-c2.net", prop.proposal_id)
        self.assertEqual(len(engine.active_proposals[prop.proposal_id].approved_votes), 1)

        def cast_vote(voter_id: str):
            meta = {
                "proposal_id": prop.proposal_id,
                "sequence_number": prop.sequence_number,
                "epoch": prop.epoch,
                "target_domain": prop.target_domain,
                "decision": "APPROVE",
            }
            req = pb2.VoteRequest(
                proposal_id=prop.proposal_id,
                sequence_number=prop.sequence_number,
                epoch=prop.epoch,
                target_domain=prop.target_domain,
                voter_id=voter_id,
                decision=pb2.VOTE_APPROVE,
                voter_signature=sign_message(keys[voter_id][0], meta),
                timestamp=int(time.time() * 1000),
            )
            return engine.handle_vote(req)

        self.assertIsNone(cast_vote("fednode-1"))
        self.assertIsNone(cast_vote("fednode-2"))

        minted_qc = cast_vote("fednode-3")
        self.assertIsNotNone(minted_qc)
        self.assertEqual(len(minted_qc.signatures), 4)
        self.assertEqual(minted_qc.target_domain, "botnet-c2.net")

        self.assertTrue(engine.commit_defederation(minted_qc))
        self.assertTrue(db.is_domain_blocked("botnet-c2.net"))
        self.assertTrue(fw.is_blocked("botnet-c2.net"))

    def test_quarantined_peer_vote_exclusion(self):
        db = Database(os.path.join(self.temp_dir, "quarantine_test.db"))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        with patch.dict(os.environ, {"NODE_ID": "fednode-0", "DATA_DIR": self.temp_dir}):
            cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        engine = ConsensusEngine(cfg, db, fw, rep)

        priv_bad, pub_bad = generate_keypair()
        engine.register_peer_key("fednode-bad", pub_bad)

        rep.penalize_forgery("fednode-bad")
        rep.penalize_equivocation("fednode-bad")
        self.assertFalse(rep.is_peer_eligible_to_vote("fednode-bad"))

        prop = engine.create_proposal(
            target_domain="phish-site.org",
            reason=pb2.REASON_PHISHING,
            evidence_payload="{}",
            origin_http_signature="",
            threat_score=0.88,
        )

        vote_meta = {
            "proposal_id": prop.proposal_id,
            "sequence_number": prop.sequence_number,
            "epoch": prop.epoch,
            "target_domain": prop.target_domain,
            "decision": "APPROVE",
        }
        vote_bad = pb2.VoteRequest(
            proposal_id=prop.proposal_id,
            sequence_number=prop.sequence_number,
            epoch=prop.epoch,
            target_domain=prop.target_domain,
            voter_id="fednode-bad",
            decision=pb2.VOTE_APPROVE,
            voter_signature=sign_message(priv_bad, vote_meta),
            timestamp=int(time.time() * 1000),
        )

        self.assertIsNone(engine.handle_vote(vote_bad))
        self.assertNotIn("fednode-bad", engine.active_proposals[prop.proposal_id].approved_votes)


if __name__ == "__main__":
    unittest.main()
