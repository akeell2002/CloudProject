"""Integration tests for the fedctl operator CLI."""
import os
import shutil
import sys
import tempfile
import time
import unittest
from concurrent import futures
from unittest.mock import MagicMock, patch

import grpc

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from cli.fedctl import cmd_peers, cmd_propose, cmd_status
from node.config import NodeConfig
from node.engine.catchup import CatchupEngine
from node.engine.consensus import ConsensusEngine
from node.engine.leader import LeaderManager
from node.ingress.firewall import FirewallFilter
from node.service import FedConsensusService
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from proto import fedconsensus_pb2 as pb2
from proto import fedconsensus_pb2_grpc as pb2_grpc


class TestFedctlCli(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cli_status_peers_and_propose(self):
        db = Database(os.path.join(self.temp_dir, "cli_test.db"))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        with patch.dict(os.environ, {"DATA_DIR": self.temp_dir}):
            cfg = NodeConfig()
        cfg.node_id = "fednode-cli-test"

        db.save_commit_record(
            sequence_number=1,
            epoch=1,
            target_domain="evil-phishing.org",
            reason=pb2.REASON_PHISHING,
            quorum_proof={"proposal_id": "p-1", "signatures": []},
        )
        fw.block_domain("evil-phishing.org")

        rep.penalize_forgery("fednode-bad-actor")
        rep.penalize_equivocation("fednode-bad-actor")

        consensus = ConsensusEngine(cfg, db, fw, rep)
        leader = LeaderManager(cfg, rep)
        catchup = CatchupEngine(cfg, db, fw)

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        service = FedConsensusService(cfg, db, rep, fw, consensus, leader, catchup)
        pb2_grpc.add_FedConsensusServiceServicer_to_server(service, server)
        port = server.add_insecure_port("127.0.0.1:0")
        target_addr = f"127.0.0.1:{port}"
        server.start()
        time.sleep(0.2)

        try:
            args_status = MagicMock(target=target_addr, timeout=2.0)
            self.assertEqual(cmd_status(args_status), 0)

            args_peers = MagicMock(target=target_addr, timeout=2.0)
            self.assertEqual(cmd_peers(args_peers), 0)

            args_prop = MagicMock(
                target=target_addr,
                domain="malicious-crypto-bot.net",
                reason="BOTNET",
                timeout=2.0,
            )
            # Unknown operator key should be rejected by signature verification.
            self.assertEqual(cmd_propose(args_prop), 1)
        finally:
            server.stop(grace=None)


if __name__ == "__main__":
    unittest.main()
