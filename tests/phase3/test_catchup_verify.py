import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.config import NodeConfig
from node.crypto.ed25519 import generate_keypair, sign_message
from node.engine.catchup import CatchupEngine
from node.ingress.firewall import FirewallFilter
from node.storage.database import Database
from proto import fedconsensus_pb2 as pb2


class TestCatchupEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir_healthy = tempfile.mkdtemp()
        self.temp_dir_crashed = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir_healthy, ignore_errors=True)
        shutil.rmtree(self.temp_dir_crashed, ignore_errors=True)

    def test_catchup_replay(self):
        db_healthy = Database(os.path.join(self.temp_dir_healthy, "healthy.db"))
        fw_healthy = FirewallFilter(db_healthy)
        with patch.dict(os.environ, {"DATA_DIR": self.temp_dir_healthy}):
            cfg_healthy = NodeConfig()
        engine_healthy = CatchupEngine(cfg_healthy, db_healthy, fw_healthy)

        keys = {}
        for i in range(4):
            node_id = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[node_id] = (priv, pub)
            engine_healthy.register_peer_key(node_id, pub)

        proof_sigs = []
        for node_id, (priv, _) in keys.items():
            meta = {
                "proposal_id": "prop-1-1-botnet-attack.org",
                "sequence_number": 1,
                "epoch": 1,
                "target_domain": "botnet-attack.org",
                "decision": "APPROVE",
            }
            proof_sigs.append(
                {
                    "voter_id": node_id,
                    "signature": sign_message(priv, meta),
                    "timestamp": 1000,
                }
            )

        db_healthy.save_commit_record(
            sequence_number=1,
            epoch=1,
            target_domain="botnet-attack.org",
            reason=pb2.REASON_BOTNET,
            quorum_proof={
                "proposal_id": "prop-1-1-botnet-attack.org",
                "signatures": proof_sigs,
                "finalized_at": 1000,
            },
        )

        db_crashed = Database(os.path.join(self.temp_dir_crashed, "crashed.db"))
        fw_crashed = FirewallFilter(db_crashed)
        with patch.dict(os.environ, {"DATA_DIR": self.temp_dir_crashed}):
            cfg_crashed = NodeConfig()
        engine_crashed = CatchupEngine(cfg_crashed, db_crashed, fw_crashed)
        for node_id, (_, pub) in keys.items():
            engine_crashed.register_peer_key(node_id, pub)

        self.assertEqual(db_crashed.get_latest_sequence_number(), 0)
        self.assertFalse(fw_crashed.is_blocked("botnet-attack.org"))

        req = pb2.CatchupRequest(node_id="fednode-4", from_sequence_number=1)
        res = engine_healthy.handle_catchup_request(req)
        self.assertEqual(len(res.records), 1)
        self.assertEqual(res.records[0].target_domain, "botnet-attack.org")

        replayed = engine_crashed.replay_records(list(res.records))
        self.assertEqual(replayed, 1)
        self.assertEqual(db_crashed.get_latest_sequence_number(), 1)
        self.assertTrue(fw_crashed.is_blocked("botnet-attack.org"))


if __name__ == "__main__":
    unittest.main()
