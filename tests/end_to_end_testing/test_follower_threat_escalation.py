import os
import sys
import json
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from proto import fedconsensus_pb2 as pb2
from proto import fedconsensus_pb2_grpc as pb2_grpc
from node.config import NodeConfig
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.ingress.firewall import FirewallFilter
from node.ingress.classifier import ThreatClassifier
from node.engine.consensus import ConsensusEngine
from node.engine.leader import LeaderManager
from node.engine.catchup import CatchupEngine
from node.service import FedConsensusService
from node.crypto.ed25519 import generate_keypair, sign_message, verify_signature


class TestFollowerThreatEscalation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.temp_dir, "test.db"))
        self.rep = ReputationManager(self.db)
        self.fw = FirewallFilter(self.db)
        self.cfg = NodeConfig()
        self.cfg.node_id = "fednode-0"  # Leader for Epoch 1
        self.cfg.peers = []             # Isolated test: do not contact live docker cluster
        self.consensus = ConsensusEngine(self.cfg, self.db, self.fw, self.rep)
        self.leader = LeaderManager(self.cfg, self.rep)
        self.catchup = CatchupEngine(self.cfg, self.db, self.fw, self.consensus.peer_public_keys, self.rep)

        self.service = FedConsensusService(
            config=self.cfg,
            database=self.db,
            reputation=self.rep,
            firewall=self.fw,
            consensus=self.consensus,
            leader=self.leader,
            catchup=self.catchup
        )

        # Register peer fednode-1
        self.priv1, self.pub1 = generate_keypair()
        self.consensus.register_peer_key("fednode-1", self.pub1)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_leader_adopts_follower_threat_report(self):
        """Verify leader accepts valid threat forwarded from follower fednode-1 and creates leader proposal."""
        domain = "malware-attack.example.org"
        vote_meta = {
            "proposal_id": f"forward-1-fednode-1-{domain}",
            "sequence_number": 1,
            "epoch": 1,
            "target_domain": domain,
            "decision": "APPROVE"
        }
        sig1 = sign_message(self.priv1, vote_meta)

        req = pb2.ProposeRequest(
            proposal_id=vote_meta["proposal_id"],
            sequence_number=1,
            epoch=1,
            target_domain=domain,
            reason=pb2.REASON_MALICIOUS_FILES,
            evidence_payload=json.dumps({"actor": "bad", "object": {"attachment": [{"url": "http://evil.org/x.exe"}]}}),
            origin_http_signature="",
            threat_score=0.85,
            proposer_id="fednode-1",
            proposer_signature=sig1,
            timestamp=1000
        )

        resp = self.service.ProposeDefederation(req, None)
        self.assertTrue(resp.accepted)
        self.assertEqual(resp.node_id, "fednode-0")

        # Verify proposal was created on leader with leader as proposer
        leader_props = [p for p in self.consensus.active_proposals.values() if p.target_domain == domain]
        self.assertEqual(len(leader_props), 1)
        self.assertEqual(leader_props[0].request.proposer_id, "fednode-0")
        self.assertIn("fednode-0", leader_props[0].approved_votes)

    def test_leader_rejects_unauthorized_reporter(self):
        """Verify leader rejects forwarded threats from unknown / unauthorized peers."""
        domain = "fake-threat.org"
        priv_fake, pub_fake = generate_keypair()
        vote_meta = {
            "proposal_id": f"forward-1-rogue-node-{domain}",
            "sequence_number": 1,
            "epoch": 1,
            "target_domain": domain,
            "decision": "APPROVE"
        }
        sig = sign_message(priv_fake, vote_meta)
        req = pb2.ProposeRequest(
            proposal_id=vote_meta["proposal_id"],
            sequence_number=1,
            epoch=1,
            target_domain=domain,
            reason=pb2.REASON_SPAM,
            threat_score=0.85,
            proposer_id="rogue-node",
            proposer_signature=sig,
            timestamp=1000
        )
        resp = self.service.ProposeDefederation(req, None)
        self.assertFalse(resp.accepted)
        self.assertIn("not an authorized consortium peer", resp.reason)


if __name__ == "__main__":
    unittest.main()
