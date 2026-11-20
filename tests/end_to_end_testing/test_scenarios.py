"""End-to-end moderation lifecycle, catch-up recovery, and origin signature tests."""
import json
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
from node.crypto.http_sig import create_origin_http_signature, verify_origin_http_signature
from node.engine.catchup import CatchupEngine
from node.engine.consensus import ConsensusEngine
from node.ingress.activitypub import ActivityPubInbox
from node.ingress.classifier import ThreatClassifier
from node.ingress.firewall import FirewallFilter
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from proto import fedconsensus_pb2 as pb2


class TestEndToEndScenarios(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_moderation_lifecycle(self):
        db = Database(os.path.join(self.temp_dir, "scenario_lifecycle.db"))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        with patch.dict(os.environ, {"NODE_ID": "fednode-0", "DATA_DIR": self.temp_dir}):
            cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        classifier = ThreatClassifier()
        consensus = ConsensusEngine(cfg, db, fw, rep)

        keys = {"fednode-0": (cfg.private_key_hex, cfg.public_key_hex)}
        for i in range(1, 5):
            nid = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[nid] = (priv, pub)
            consensus.register_peer_key(nid, pub)

        proposals_triggered = []

        def on_threat(domain, payload, assessment):
            prop = consensus.create_proposal(
                target_domain=domain,
                reason=assessment.dominant_reason_code,
                evidence_payload=json.dumps(payload),
                origin_http_signature="",
                threat_score=assessment.score,
            )
            proposals_triggered.append(prop)

        inbox = ActivityPubInbox(firewall=fw, classifier=classifier, on_threat_detected=on_threat)

        benign_json = json.dumps(
            {
                "actor": "https://happy-community.org/users/alice",
                "object": {"content": "Hello friends! Beautiful sunny day today in Glasgow."},
            }
        )
        status, resp = inbox.process_inbox_post(benign_json)
        self.assertEqual(status, 202)
        self.assertEqual(resp["status"], "ACCEPTED")
        self.assertEqual(len(proposals_triggered), 0)

        attack_json = json.dumps(
            {
                "actor": "https://evil-phish.net/users/scammer",
                "object": {
                    "content": "urgent security update: verify your account immediately at http://evil-phish.net",
                    "attachment": [{"url": "https://evil-phish.net/malware.exe"}],
                },
            }
        )
        status, resp = inbox.process_inbox_post(attack_json)
        self.assertEqual(status, 403)
        self.assertEqual(resp["status"], "FLAGGED_FOR_CONSENSUS")
        self.assertEqual(len(proposals_triggered), 1)

        prop = proposals_triggered[0]
        qc = None
        for i in range(1, 4):
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
            qc = consensus.handle_vote(vote)

        self.assertIsNotNone(qc)
        consensus.commit_defederation(qc)

        status_subsequent, resp_subsequent = inbox.process_inbox_post(attack_json)
        self.assertEqual(status_subsequent, 403)
        self.assertEqual(resp_subsequent["status"], "BLOCKED")

    def test_crash_and_catchup_replay(self):
        cluster_dir = os.path.join(self.temp_dir, "cluster")
        crashed_dir = os.path.join(self.temp_dir, "crashed")
        os.makedirs(cluster_dir, exist_ok=True)
        os.makedirs(crashed_dir, exist_ok=True)

        db_cluster = Database(os.path.join(cluster_dir, "cluster.db"))
        fw_cluster = FirewallFilter(db_cluster)
        with patch.dict(os.environ, {"NODE_ID": "fednode-0", "DATA_DIR": cluster_dir}):
            cfg_cluster = NodeConfig()
        cfg_cluster.node_id = "fednode-0"
        engine_cluster = CatchupEngine(cfg_cluster, db_cluster, fw_cluster)

        keys = {}
        for i in range(5):
            nid = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[nid] = (priv, pub)
            engine_cluster.register_peer_key(nid, pub)

        for seq, domain in [(1, "spam-1.net"), (2, "malware-2.org")]:
            sigs = []
            for nid, (priv, _) in list(keys.items())[:4]:
                meta = {
                    "proposal_id": f"prop-1-{seq}-{domain}",
                    "sequence_number": seq,
                    "epoch": 1,
                    "target_domain": domain,
                    "decision": "APPROVE",
                }
                sigs.append({"voter_id": nid, "signature": sign_message(priv, meta), "timestamp": 1000})

            db_cluster.save_commit_record(
                sequence_number=seq,
                epoch=1,
                target_domain=domain,
                reason=pb2.REASON_BOTNET,
                quorum_proof={"proposal_id": f"prop-1-{seq}-{domain}", "signatures": sigs, "finalized_at": 1000},
            )

        db_crashed = Database(os.path.join(crashed_dir, "crashed.db"))
        fw_crashed = FirewallFilter(db_crashed)
        with patch.dict(os.environ, {"NODE_ID": "fednode-4", "DATA_DIR": crashed_dir}):
            cfg_crashed = NodeConfig()
        cfg_crashed.node_id = "fednode-4"
        engine_crashed = CatchupEngine(cfg_crashed, db_crashed, fw_crashed)

        for nid, (_, pub) in keys.items():
            engine_crashed.register_peer_key(nid, pub)

        self.assertEqual(db_crashed.get_latest_sequence_number(), 0)
        self.assertFalse(fw_crashed.is_blocked("malware-2.org"))

        req = pb2.CatchupRequest(node_id="fednode-4", from_sequence_number=1)
        res = engine_cluster.handle_catchup_request(req)
        self.assertEqual(len(res.records), 2)

        replayed = engine_crashed.replay_records(list(res.records))
        self.assertEqual(replayed, 2)
        self.assertEqual(db_crashed.get_latest_sequence_number(), 2)
        self.assertTrue(fw_crashed.is_blocked("spam-1.net"))
        self.assertTrue(fw_crashed.is_blocked("malware-2.org"))

    def test_origin_signature_rejects_fabricated_evidence(self):
        innocent_priv, innocent_pub = generate_keypair()
        known_pubkeys = {"innocent-community.org": innocent_pub}

        genuine_payload = {"actor": "https://innocent-community.org/users/bob", "content": "Good morning everyone!"}
        genuine_sig = create_origin_http_signature("innocent-community.org", genuine_payload, innocent_priv)

        self.assertTrue(
            verify_origin_http_signature(
                accused_domain="innocent-community.org",
                evidence_payload_json=json.dumps(genuine_payload),
                origin_signature_info=genuine_sig,
                known_domain_public_keys=known_pubkeys,
            )
        )

        rogue_priv, _ = generate_keypair()
        fake_abusive_payload = {
            "actor": "https://innocent-community.org/users/bob",
            "content": "CLICK HERE FOR FREE BITCOIN SCAM LINK",
        }
        fake_sig = create_origin_http_signature("innocent-community.org", fake_abusive_payload, rogue_priv)

        self.assertFalse(
            verify_origin_http_signature(
                accused_domain="innocent-community.org",
                evidence_payload_json=json.dumps(fake_abusive_payload),
                origin_signature_info=fake_sig,
                known_domain_public_keys=known_pubkeys,
            )
        )


if __name__ == "__main__":
    unittest.main()
