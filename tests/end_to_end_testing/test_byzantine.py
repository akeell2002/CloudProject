"""Byzantine fault resilience tests for the consensus engine."""
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


class TestByzantineFaultResilience(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_engine(self, db_name: str):
        db = Database(os.path.join(self.temp_dir, db_name))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        with patch.dict(os.environ, {"NODE_ID": "fednode-0", "DATA_DIR": self.temp_dir}):
            cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        return ConsensusEngine(cfg, db, fw, rep), cfg, db, fw, rep

    def test_byzantine_liar_fault_masking(self):
        engine, cfg, _, fw, rep = self._make_engine("byzantine_liar.db")

        keys = {"fednode-0": (cfg.private_key_hex, cfg.public_key_hex)}
        for i in range(1, 5):
            nid = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[nid] = (priv, pub)
            engine.register_peer_key(nid, pub)

        prop = engine.create_proposal(
            target_domain="stealer-trojan.com",
            reason=pb2.REASON_MALICIOUS_FILES,
            evidence_payload='{"actor": "https://stealer-trojan.com/bot"}',
            origin_http_signature="",
            threat_score=0.95,
        )

        liar_meta = {
            "proposal_id": prop.proposal_id,
            "sequence_number": prop.sequence_number,
            "epoch": prop.epoch,
            "target_domain": prop.target_domain,
            "decision": "REJECT",
        }
        liar_vote = pb2.VoteRequest(
            proposal_id=prop.proposal_id,
            sequence_number=prop.sequence_number,
            epoch=prop.epoch,
            target_domain=prop.target_domain,
            voter_id="fednode-1",
            decision=pb2.VOTE_REJECT,
            voter_signature=sign_message(keys["fednode-1"][0], liar_meta),
            timestamp=int(time.time() * 1000),
        )
        self.assertIsNone(engine.handle_vote(liar_vote))

        qc = None
        for i in [2, 3, 4]:
            nid = f"fednode-{i}"
            meta = {
                "proposal_id": prop.proposal_id,
                "sequence_number": prop.sequence_number,
                "epoch": prop.epoch,
                "target_domain": prop.target_domain,
                "decision": "APPROVE",
            }
            vote = pb2.VoteRequest(
                proposal_id=prop.proposal_id,
                sequence_number=prop.sequence_number,
                epoch=prop.epoch,
                target_domain=prop.target_domain,
                voter_id=nid,
                decision=pb2.VOTE_APPROVE,
                voter_signature=sign_message(keys[nid][0], meta),
                timestamp=int(time.time() * 1000),
            )
            qc = engine.handle_vote(vote)

        self.assertIsNotNone(qc)
        self.assertEqual(len(qc.signatures), 4)
        voter_ids = [s.voter_id for s in qc.signatures]
        self.assertNotIn("fednode-1", voter_ids)
        self.assertEqual(set(voter_ids), {"fednode-0", "fednode-2", "fednode-3", "fednode-4"})
        liar_score = next(r["trust_score"] for r in rep.get_ledger() if r["peer_id"] == "fednode-1")
        self.assertEqual(liar_score, 85)

        engine.commit_defederation(qc)
        self.assertTrue(fw.is_blocked("stealer-trojan.com"))

    def test_byzantine_forger_reputation_penalty(self):
        engine, _, _, _, rep = self._make_engine("byzantine_forger.db")

        _, pub_2 = generate_keypair()
        engine.register_peer_key("fednode-2", pub_2)

        initial_score = next((r["trust_score"] for r in rep.get_ledger() if r["peer_id"] == "fednode-2"), 100)
        self.assertEqual(initial_score, 100)

        prop = engine.create_proposal(
            target_domain="phish-bank.com",
            reason=pb2.REASON_PHISHING,
            evidence_payload="{}",
            origin_http_signature="",
            threat_score=0.89,
        )

        forged_vote = pb2.VoteRequest(
            proposal_id=prop.proposal_id,
            sequence_number=prop.sequence_number,
            epoch=prop.epoch,
            target_domain=prop.target_domain,
            voter_id="fednode-2",
            decision=pb2.VOTE_APPROVE,
            voter_signature="bad_signature_000000000000000000000000000000000000000000000000",
            timestamp=int(time.time() * 1000),
        )

        self.assertIsNone(engine.handle_vote(forged_vote))
        p_state = engine.active_proposals[prop.proposal_id]
        self.assertNotIn("fednode-2", p_state.approved_votes)

        penalized_score = next(r["trust_score"] for r in rep.get_ledger() if r["peer_id"] == "fednode-2")
        self.assertEqual(penalized_score, 60)

    def test_safety_under_excessive_faults(self):
        engine, cfg, _, fw, _ = self._make_engine("excessive_faults.db")

        keys = {"fednode-0": (cfg.private_key_hex, cfg.public_key_hex)}
        for i in range(1, 5):
            nid = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[nid] = (priv, pub)
            engine.register_peer_key(nid, pub)

        prop = engine.create_proposal(
            target_domain="suspicious-domain.net",
            reason=pb2.REASON_SPAM,
            evidence_payload="{}",
            origin_http_signature="",
            threat_score=0.75,
        )

        qc = None
        for i in [1, 2]:
            nid = f"fednode-{i}"
            meta = {
                "proposal_id": prop.proposal_id,
                "sequence_number": prop.sequence_number,
                "epoch": prop.epoch,
                "target_domain": prop.target_domain,
                "decision": "APPROVE",
            }
            vote = pb2.VoteRequest(
                proposal_id=prop.proposal_id,
                sequence_number=prop.sequence_number,
                epoch=prop.epoch,
                target_domain=prop.target_domain,
                voter_id=nid,
                decision=pb2.VOTE_APPROVE,
                voter_signature=sign_message(keys[nid][0], meta),
                timestamp=int(time.time() * 1000),
            )
            qc = engine.handle_vote(vote)

        self.assertIsNone(qc)
        self.assertFalse(fw.is_blocked("suspicious-domain.net"))


if __name__ == "__main__":
    unittest.main()
