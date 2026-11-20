import json
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
import urllib.request
from unittest.mock import patch

import grpc

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.config import NodeConfig
from node.crypto.ed25519 import generate_keypair, sign_message
from node.engine.catchup import CatchupEngine
from node.engine.consensus import ConsensusEngine
from node.engine.leader import LeaderManager
from node.ingress.firewall import FirewallFilter
from node.main import FedNodeRunner
from node.service import FedConsensusService
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from proto import fedconsensus_pb2 as pb2
from proto import fedconsensus_pb2_grpc as pb2_grpc


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestNodeIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_dir_healthy = os.path.join(self.temp_dir, "healthy")
        self.temp_dir_crashed = os.path.join(self.temp_dir, "crashed")
        os.makedirs(self.temp_dir_healthy, exist_ok=True)
        os.makedirs(self.temp_dir_crashed, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_catchup_service_and_dual_server(self):
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

        catchup_res = engine_healthy.handle_catchup_request(
            pb2.CatchupRequest(node_id="fednode-4", from_sequence_number=1)
        )
        replayed = engine_crashed.replay_records(list(catchup_res.records))
        self.assertEqual(replayed, 1)
        self.assertTrue(fw_crashed.is_blocked("botnet-attack.org"))

        rep = ReputationManager(db_healthy)
        consensus = ConsensusEngine(cfg_healthy, db_healthy, fw_healthy, rep)
        leader = LeaderManager(cfg_healthy, rep)
        service = FedConsensusService(
            cfg_healthy, db_healthy, rep, fw_healthy, consensus, leader, engine_healthy
        )

        status = service.GetStatus(pb2.StatusRequest(caller_id="tester"), None)
        self.assertEqual(status.node_id, cfg_healthy.node_id)

        service.set_byzantine_mode("LIAR")
        self.assertEqual(service.GetStatus(pb2.StatusRequest(caller_id="tester"), None).state, "BYZANTINE_LIAR")

        service.set_byzantine_mode("FORGER")
        self.assertEqual(service.GetStatus(pb2.StatusRequest(caller_id="tester"), None).state, "BYZANTINE_FORGER")

        service.set_byzantine_mode("NONE")

        grpc_port = _free_port()
        http_port = _free_port()
        env = {
            "DATA_DIR": self.temp_dir,
            "GRPC_PORT": str(grpc_port),
            "HTTP_PORT": str(http_port),
            "NODE_ID": "fednode-runner-test",
        }
        with patch.dict(os.environ, env):
            runner = FedNodeRunner()
            runner.start()
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{http_port}/health", timeout=2.0) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(json.loads(resp.read().decode())["status"], "HEALTHY")

                benign_payload = json.dumps(
                    {
                        "actor": "https://normal-server.org/users/alice",
                        "object": {"content": "Hello fediverse!"},
                    }
                ).encode("utf-8")
                post_req = urllib.request.Request(
                    f"http://127.0.0.1:{http_port}/inbox",
                    data=benign_payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(post_req, timeout=2.0) as resp:
                    self.assertEqual(resp.status, 202)

                with grpc.insecure_channel(f"127.0.0.1:{grpc_port}") as channel:
                    stub = pb2_grpc.FedConsensusServiceStub(channel)
                    res = stub.GetStatus(pb2.StatusRequest(caller_id="tester"), timeout=2.0)
                    self.assertEqual(res.node_id, "fednode-runner-test")
            finally:
                runner.stop()
                if runner.http_server:
                    runner.http_server.server_close()


if __name__ == "__main__":
    unittest.main()
