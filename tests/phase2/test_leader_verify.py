import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.config import NodeConfig
from node.engine.leader import LeaderManager
from node.storage.database import Database
from node.storage.reputation import ReputationManager


class TestLeaderManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_leases_heartbeats_and_impeachment(self):
        db_path = os.path.join(self.temp_dir, "leader_test.db")
        with patch.dict(os.environ, {"NODE_ID": "fednode-0", "DATA_DIR": self.temp_dir}):
            cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        db = Database(db_path)
        rep = ReputationManager(db)
        leader = LeaderManager(cfg, rep)

        self.assertEqual(leader.get_leader_for_epoch(1), "fednode-0")
        self.assertEqual(leader.get_leader_for_epoch(2), "fednode-1")
        self.assertEqual(leader.get_leader_for_epoch(3), "fednode-2")

        self.assertTrue(leader.is_current_leader())

        hb = leader.generate_heartbeat()
        self.assertEqual(hb.leader_id, "fednode-0")
        self.assertEqual(hb.epoch, 1)
        self.assertGreater(len(hb.signature), 0)

        imp_req = leader.create_impeachment_request(justification="Leader unresponsive to reported attack")
        self.assertEqual(imp_req.leader_id, "fednode-0")
        self.assertEqual(imp_req.target_epoch, 1)
        self.assertEqual(imp_req.accuser_id, "fednode-0")


if __name__ == "__main__":
    unittest.main()
