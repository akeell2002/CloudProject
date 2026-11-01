import os
import sys
import time
import json
import urllib.request
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from node.main import FedNodeRunner
import grpc
from proto import fedconsensus_pb2 as pb2
from proto import fedconsensus_pb2_grpc as pb2_grpc


def test_dual_server_startup():
    temp_dir = tempfile.mkdtemp()
    os.environ["DATA_DIR"] = temp_dir
    os.environ["GRPC_PORT"] = "59051"
    os.environ["HTTP_PORT"] = "58080"
    os.environ["NODE_ID"] = "fednode-test"

    runner = FedNodeRunner()
    runner.start()
    time.sleep(1.0)  # Allow servers to bind sockets

    try:
        # 1. Test HTTP /health endpoint
        health_url = "http://127.0.0.1:58080/health"
        req = urllib.request.Request(health_url)
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["status"] == "HEALTHY"
            assert data["node_id"] == "fednode-test"
        print("  [PASS] 1. HTTP /health responding cleanly")

        # 2. Test HTTP /inbox accepting benign ActivityPub post
        inbox_url = "http://127.0.0.1:58080/inbox"
        benign_payload = json.dumps({
            "actor": "https://normal-server.org/users/alice",
            "object": {"content": "Hello world from decentralized social media!"}
        }).encode("utf-8")

        post_req = urllib.request.Request(
            inbox_url,
            data=benign_payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(post_req, timeout=2.0) as resp:
            assert resp.status == 202
            res = json.loads(resp.read().decode())
            assert res["status"] == "ACCEPTED"
        print("  [PASS] 2. HTTP POST /inbox accepted benign post (HTTP 202)")

        # 3. Test gRPC Mesh GetStatus
        channel = grpc.insecure_channel("127.0.0.1:59051")
        stub = pb2_grpc.FedConsensusServiceStub(channel)
        status_res = stub.GetStatus(pb2.StatusRequest(caller_id="tester"), timeout=2.0)
        assert status_res.node_id == "fednode-test"
        print("  [PASS] 3. gRPC Mesh GetStatus answered on internal port 59051")

        print("\n=======================================================")
        print("   MILESTONE 3.3: DUAL-SERVER RUNNER VERIFIED 100%!    ")
        print("=======================================================\n")

    finally:
        runner.stop()
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    test_dual_server_startup()