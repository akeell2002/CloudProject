import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.config import NodeConfig
from node.crypto.ed25519 import (
    canonical_json_hash,
    generate_keypair,
    sign_message,
    verify_signature,
)
from node.crypto.http_sig import (
    create_origin_http_signature,
    verify_origin_http_signature,
)
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from proto import fedconsensus_pb2 as pb2


class TestFoundationComponents(unittest.TestCase):
    def test_grpc_proto_messages(self):
        req = pb2.ProposeRequest(
            proposal_id="prop-001",
            sequence_number=1,
            epoch=1,
            target_domain="spam-botnet.net",
            reason=pb2.REASON_BOTNET,
            evidence_payload='{"actor": "botnet.net"}',
            threat_score=0.92,
            proposer_id="fednode-0",
        )
        self.assertEqual(req.proposal_id, "prop-001")
        self.assertEqual(req.reason, pb2.REASON_BOTNET)
        self.assertEqual(round(req.threat_score, 2), 0.92)

    def test_ed25519_signatures(self):
        priv, pub = generate_keypair()

        dict_a = {"domain": "evil.xyz", "seq": 10}
        dict_b = {"seq": 10, "domain": "evil.xyz"}
        self.assertEqual(canonical_json_hash(dict_a), canonical_json_hash(dict_b))

        sig = sign_message(priv, dict_a)
        self.assertTrue(verify_signature(pub, dict_a, sig))
        self.assertFalse(verify_signature(pub, {"domain": "innocent.edu", "seq": 10}, sig))

        _, other_pub = generate_keypair()
        self.assertFalse(verify_signature(other_pub, dict_a, sig))

    def test_origin_http_signature(self):
        evil_priv, evil_pub = generate_keypair()
        accused_domain = "evil-spammer.com"
        known_keys = {accused_domain: evil_pub}

        payload = {"content": "Malicious phishing payload"}
        valid_sig = create_origin_http_signature(accused_domain, payload, evil_priv)

        self.assertTrue(verify_origin_http_signature(accused_domain, payload, valid_sig, known_keys))
        self.assertFalse(verify_origin_http_signature("innocent-university.edu", payload, valid_sig, known_keys))

    def test_sqlite_wal_storage(self):
        temp_dir = tempfile.mkdtemp()
        try:
            db = Database(os.path.join(temp_dir, "wal_verify.db"))
            self.assertEqual(db.get_latest_sequence_number(), 0)

            proof = {
                "proposal_id": "prop-100",
                "target_domain": "malware.net",
                "signatures": ["sig_node0", "sig_node1", "sig_node2", "sig_node3"],
            }
            success = db.save_commit_record(
                sequence_number=1,
                epoch=1,
                target_domain="malware.net",
                reason=pb2.REASON_MALICIOUS_FILES,
                quorum_proof=proof,
            )
            self.assertTrue(success)
            self.assertEqual(db.get_latest_sequence_number(), 1)
            self.assertTrue(db.is_domain_blocked("malware.net"))
            self.assertFalse(db.is_domain_blocked("safe-site.org"))

            records = db.get_commit_records(from_sequence_number=1)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["target_domain"], "malware.net")
            self.assertEqual(len(records[0]["quorum_proof"]["signatures"]), 4)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_peer_reputation(self):
        temp_dir = tempfile.mkdtemp()
        try:
            db = Database(os.path.join(temp_dir, "rep_verify.db"))
            rep = ReputationManager(db)

            peer = "fednode-4"
            self.assertTrue(rep.is_peer_eligible_to_vote(peer))

            rep.penalize_equivocation(peer)
            self.assertTrue(rep.is_peer_eligible_to_vote(peer))

            rep.penalize_forgery(peer)
            self.assertFalse(rep.is_peer_eligible_to_vote(peer))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_node_configuration(self):
        cfg = NodeConfig()
        self.assertEqual(cfg.total_nodes, 5)
        self.assertEqual(cfg.max_byzantine_faults, 1)
        self.assertEqual(cfg.quorum_size, 4)
        self.assertEqual(len(cfg.public_key_hex), 64)
        self.assertEqual(len(cfg.private_key_hex), 64)


if __name__ == "__main__":
    unittest.main()
