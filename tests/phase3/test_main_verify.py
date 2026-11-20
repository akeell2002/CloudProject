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

from node.main import FedNodeRunner
from proto import fedconsensus_pb2 as pb2
from proto import fedconsensus_pb2_grpc as pb2_grpc


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestDualServerRunner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_dual_server_startup(self):
        grpc_port = _free_port()
        http_port = _free_port()
        env = {
            "DATA_DIR": self.temp_dir,
            "GRPC_PORT": str(grpc_port),
            "HTTP_PORT": str(http_port),
            "NODE_ID": "fednode-test",
        }
        with patch.dict(os.environ, env):
            runner = FedNodeRunner()
            runner.start()
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{http_port}/health", timeout=2.0) as resp:
                    self.assertEqual(resp.status, 200)
                    data = json.loads(resp.read().decode())
                    self.assertEqual(data["status"], "HEALTHY")
                    self.assertEqual(data["node_id"], "fednode-test")

                benign_payload = json.dumps(
                    {
                        "actor": "https://normal-server.org/users/alice",
                        "object": {"content": "Hello world from decentralized social media!"},
                    }
                ).encode("utf-8")
                post_req = urllib.request.Request(
                    f"http://127.0.0.1:{http_port}/inbox",
                    data=benign_payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(post_req, timeout=2.0) as resp:
                    self.assertEqual(resp.status, 202)
                    res = json.loads(resp.read().decode())
                    self.assertEqual(res["status"], "ACCEPTED")

                with grpc.insecure_channel(f"127.0.0.1:{grpc_port}") as channel:
                    stub = pb2_grpc.FedConsensusServiceStub(channel)
                    status_res = stub.GetStatus(pb2.StatusRequest(caller_id="tester"), timeout=2.0)
                    self.assertEqual(status_res.node_id, "fednode-test")
            finally:
                runner.stop()
                if runner.http_server:
                    runner.http_server.server_close()


if __name__ == "__main__":
    unittest.main()
