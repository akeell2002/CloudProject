import os
import shutil
import sys
import tempfile
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


class TestConsensusEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_propose_vote_and_commit_flow(self):
        db_path = os.path.join(self.temp_dir, "consensus_engine_test.db")
        with patch.dict(os.environ, {"NODE_ID": "fednode-0", "DATA_DIR": self.temp_dir}):
            cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        db = Database(db_path)
        fw = FirewallFilter(db)
        rep = ReputationManager(db)
        engine = ConsensusEngine(cfg, db, fw, rep)

        target = "botnet-distributor.cc"
        prop = engine.create_proposal(
            target_domain=target,
            reason=pb2.REASON_BOTNET,
            evidence_payload='{"actor": "botnet"}',
            origin_http_signature="",
            threat_score=0.91,
        )
        self.assertEqual(prop.sequence_number, 1)
        self.assertEqual(prop.proposer_id, "fednode-0")

        followers = []
        for i in range(1, 4):
            peer_id = f"fednode-{i}"
            priv, pub = generate_keypair()
            engine.register_peer_key(peer_id, pub)
            followers.append((peer_id, priv))

        qc = None
        for peer_id, priv in followers:
            vote_meta = {
                "proposal_id": prop.proposal_id,
                "sequence_number": prop.sequence_number,
                "epoch": prop.epoch,
                "target_domain": target,
                "decision": "APPROVE",
            }
            ballot = pb2.VoteRequest(
                proposal_id=prop.proposal_id,
                sequence_number=prop.sequence_number,
                epoch=prop.epoch,
                target_domain=target,
                voter_id=peer_id,
                decision=pb2.VOTE_APPROVE,
                voter_signature=sign_message(priv, vote_meta),
                timestamp=1000,
            )
            res = engine.handle_vote(ballot)
            if res is not None:
                qc = res

        self.assertIsNotNone(qc)
        self.assertEqual(len(qc.signatures), 4)

        self.assertTrue(engine.commit_defederation(qc))
        self.assertTrue(db.is_domain_blocked(target))
        self.assertTrue(fw.is_blocked(target))


if __name__ == "__main__":
    unittest.main()
