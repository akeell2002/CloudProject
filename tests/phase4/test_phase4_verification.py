"""Tests for the fedctl operator CLI and Kubernetes manifests."""
import glob
import os
import shutil
import sys
import tempfile
import time
import unittest
from concurrent import futures
from unittest.mock import MagicMock, patch

import grpc
import yaml

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


class TestCliAndKubernetesInfrastructure(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_operator_cli(self):
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
            self.assertEqual(cmd_status(MagicMock(target=target_addr, timeout=2.0)), 0)
            self.assertEqual(cmd_peers(MagicMock(target=target_addr, timeout=2.0)), 0)
            args_prop = MagicMock(
                target=target_addr,
                domain="malicious-crypto-bot.net",
                reason="BOTNET",
                timeout=2.0,
            )
            self.assertEqual(cmd_propose(args_prop), 1)
        finally:
            server.stop(grace=None)

    def test_kubernetes_manifests(self):
        k8s_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "k8s"))
        files = glob.glob(os.path.join(k8s_dir, "*.yaml"))
        self.assertEqual(len(files), 4)

        manifests = {}
        for path in files:
            with open(path, "r", encoding="utf-8") as stream:
                data = yaml.safe_load(stream)
                self.assertIsNotNone(data)
                manifests[os.path.basename(path)] = data

        cm = manifests["configmap.yaml"]
        self.assertEqual(cm["kind"], "ConfigMap")
        self.assertEqual(cm["data"]["GRPC_PORT"], "50051")
        self.assertIn("fednode-0.fedconsensus-mesh:50051", cm["data"]["PEER_ADDRESSES"])

        svc = manifests["service-headless.yaml"]
        self.assertEqual(svc["kind"], "Service")
        self.assertEqual(svc["spec"]["clusterIP"], "None")

        ss = manifests["statefulset.yaml"]
        self.assertEqual(ss["kind"], "StatefulSet")
        self.assertEqual(ss["spec"]["replicas"], 5)
        self.assertEqual(ss["spec"]["serviceName"], "fedconsensus-mesh")

        container = ss["spec"]["template"]["spec"]["containers"][0]
        node_id_env = next(e for e in container["env"] if e["name"] == "NODE_ID")
        self.assertEqual(node_id_env["valueFrom"]["fieldRef"]["fieldPath"], "metadata.name")

        vct = ss["spec"]["volumeClaimTemplates"][0]
        self.assertEqual(vct["metadata"]["name"], "data")


if __name__ == "__main__":
    unittest.main()
