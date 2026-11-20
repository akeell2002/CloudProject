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
from node.engine.leader import LeaderManager
from node.ingress.activitypub import ActivityPubInbox
from node.ingress.classifier import ThreatClassifier
from node.ingress.firewall import FirewallFilter
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from proto import fedconsensus_pb2 as pb2


class TestIngressAndConsensusPipeline(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_pipeline_from_ingress_to_firewall_block(self):
        db_path = os.path.join(self.temp_dir, "pipeline_verify.db")
        with patch.dict(os.environ, {"NODE_ID": "fednode-0", "DATA_DIR": self.temp_dir}):
            cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        db = Database(db_path)
        fw = FirewallFilter(db)
        rep = ReputationManager(db)
        tc = ThreatClassifier()
        inbox = ActivityPubInbox(fw, tc)
        engine = ConsensusEngine(cfg, db, fw, rep)
        leader = LeaderManager(cfg, rep)

        malicious_post = {
            "actor": "https://malware-distributor.net/users/bot1",
            "object": {
                "type": "Note",
                "content": "Download this urgent security patch: update.exe now!",
            },
        }
        status_code, res = inbox.process_inbox_post(malicious_post)
        self.assertEqual(status_code, 403)
        self.assertEqual(res["status"], "FLAGGED_FOR_CONSENSUS")
        self.assertGreaterEqual(res["threat_score"], 0.60)

        target_domain = "malware-distributor.net"
        prop = engine.create_proposal(
            target_domain=target_domain,
            reason=res["dominant_reason_code"],
            evidence_payload="{}",
            origin_http_signature="",
            threat_score=res["threat_score"],
        )
        self.assertTrue(prop.proposal_id.startswith("prop-"))
        self.assertEqual(prop.target_domain, target_domain)
        self.assertEqual(prop.proposer_id, "fednode-0")

        followers = []
        for i in range(1, 4):
            node_id = f"fednode-{i}"
            priv, pub = generate_keypair()
            engine.register_peer_key(node_id, pub)
            followers.append((node_id, priv))

        proof = None
        for node_id, priv in followers:
            vote_meta = {
                "proposal_id": prop.proposal_id,
                "sequence_number": prop.sequence_number,
                "epoch": prop.epoch,
                "target_domain": target_domain,
                "decision": "APPROVE",
            }
            ballot = pb2.VoteRequest(
                proposal_id=prop.proposal_id,
                sequence_number=prop.sequence_number,
                epoch=prop.epoch,
                target_domain=target_domain,
                voter_id=node_id,
                decision=pb2.VOTE_APPROVE,
                voter_signature=sign_message(priv, vote_meta),
                timestamp=12345,
            )
            result_proof = engine.handle_vote(ballot)
            if result_proof is not None:
                proof = result_proof

        self.assertIsNotNone(proof)
        self.assertEqual(len(proof.signatures), 4)

        self.assertTrue(engine.commit_defederation(proof))
        self.assertTrue(db.is_domain_blocked(target_domain))
        self.assertTrue(fw.is_blocked(target_domain))

        retry_code, retry_res = inbox.process_inbox_post(malicious_post)
        self.assertEqual(retry_code, 403)
        self.assertEqual(retry_res["status"], "BLOCKED")

        self.assertEqual(leader.get_leader_for_epoch(1), "fednode-0")
        imp_req = leader.create_impeachment_request("Leader unresponsive")
        self.assertEqual(imp_req.leader_id, "fednode-0")


if __name__ == "__main__":
    unittest.main()
