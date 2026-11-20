import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.config import NodeConfig
from node.engine.catchup import CatchupEngine
from node.engine.consensus import ConsensusEngine
from node.engine.leader import LeaderManager
from node.ingress.firewall import FirewallFilter
from node.service import FedConsensusService
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from proto import fedconsensus_pb2 as pb2


class TestFedConsensusService(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_status_and_byzantine_modes(self):
        db = Database(os.path.join(self.temp_dir, "service_test.db"))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        with patch.dict(os.environ, {"NODE_ID": "fednode-0", "DATA_DIR": self.temp_dir}):
            cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        consensus = ConsensusEngine(cfg, db, fw, rep)
        leader = LeaderManager(cfg, rep)
        catchup = CatchupEngine(cfg, db, fw)
        service = FedConsensusService(cfg, db, rep, fw, consensus, leader, catchup)

        status = service.GetStatus(pb2.StatusRequest(caller_id="test_client"), None)
        self.assertEqual(status.node_id, "fednode-0")
        self.assertEqual(status.blocked_domains_count, 0)
        self.assertEqual(status.last_committed_seq, 0)

        service.set_byzantine_mode("LIAR")
        self.assertEqual(service.byzantine_mode, "LIAR")
        self.assertEqual(service.GetStatus(pb2.StatusRequest(caller_id="test_client"), None).state, "BYZANTINE_LIAR")

        service.set_byzantine_mode("FORGER")
        self.assertEqual(service.byzantine_mode, "FORGER")
        self.assertEqual(service.GetStatus(pb2.StatusRequest(caller_id="test_client"), None).state, "BYZANTINE_FORGER")

        service.set_byzantine_mode("NONE")
        self.assertEqual(service.byzantine_mode, "NONE")


if __name__ == "__main__":
    unittest.main()
