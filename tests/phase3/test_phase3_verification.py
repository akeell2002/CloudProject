import os
import sys
import time
import json
import shutil
import tempfile
import urllib.request
import grpc

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from proto import fedconsensus_pb2 as pb2
from proto import fedconsensus_pb2_grpc as pb2_grpc
from node.config import NodeConfig
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.ingress.firewall import FirewallFilter
from node.engine.consensus import ConsensusEngine
from node.engine.leader import LeaderManager
from node.engine.catchup import CatchupEngine
from node.service import FedConsensusService
from node.main import FedNodeRunner
from node.crypto.ed25519 import generate_keypair, sign_message


def run_phase3_comprehensive_verification():
    print("\n=======================================================")
    print("   FEDCONSENSUS: PHASE 3 COMPREHENSIVE VERIFICATION   ")
    print("=======================================================")

    temp_dir = tempfile.mkdtemp()
    temp_dir_healthy = os.path.join(temp_dir, "healthy")
    temp_dir_crashed = os.path.join(temp_dir, "crashed")
    os.makedirs(temp_dir_healthy, exist_ok=True)
    os.makedirs(temp_dir_crashed, exist_ok=True)

    try:
        # =========================================================
        # 1. TEST CATCH-UP & CRYPTOGRAPHIC LOG REPLAY (Milestone 3.1)
        # =========================================================
        db_healthy = Database(os.path.join(temp_dir_healthy, "healthy.db"))
        fw_healthy = FirewallFilter(db_healthy)
        cfg_healthy = NodeConfig()
        engine_healthy = CatchupEngine(cfg_healthy, db_healthy, fw_healthy)

        # Generate 4 honest validator keys
        keys = {}
        for i in range(4):
            node_id = f"fednode-{i}"
            priv, pub = generate_keypair()
            keys[node_id] = (priv, pub)
            engine_healthy.register_peer_key(node_id, pub)

        # Healthy node has committed sequence 1: "botnet-attack.org"
        proof_sigs = []
        for node_id, (priv, _) in keys.items():
            meta = {
                "proposal_id": "prop-1-1-botnet-attack.org",
                "sequence_number": 1,
                "epoch": 1,
                "target_domain": "botnet-attack.org",
                "decision": "APPROVE"
            }
            proof_sigs.append({
                "voter_id": node_id,
                "signature": sign_message(priv, meta),
                "timestamp": 1000
            })

        db_healthy.save_commit_record(
            sequence_number=1,
            epoch=1,
            target_domain="botnet-attack.org",
            reason=pb2.REASON_BOTNET,
            quorum_proof={
                "proposal_id": "prop-1-1-botnet-attack.org",
                "signatures": proof_sigs,
                "finalized_at": 1000
            }
        )

        # Crashed node wakes up empty
        db_crashed = Database(os.path.join(temp_dir_crashed, "crashed.db"))
        fw_crashed = FirewallFilter(db_crashed)
        cfg_crashed = NodeConfig()
        engine_crashed = CatchupEngine(cfg_crashed, db_crashed, fw_crashed)
        for node_id, (_, pub) in keys.items():
            engine_crashed.register_peer_key(node_id, pub)

        # Fetch missing records and replay
        catchup_res = engine_healthy.handle_catchup_request(
            pb2.CatchupRequest(node_id="fednode-4", from_sequence_number=1)
        )
        replayed = engine_crashed.replay_records(list(catchup_res.records))
        assert replayed == 1
        assert fw_crashed.is_blocked("botnet-attack.org") is True
        print("  [PASS] 1. Catchup Engine & QC Replay Verified (Self-Healing Active)")

        # =========================================================
        # 2. TEST gRPC SERVICE & BYZANTINE FAULT INJECTION (Milestone 3.2)
        # =========================================================
        rep = ReputationManager(db_healthy)
        consensus = ConsensusEngine(cfg_healthy, db_healthy, fw_healthy, rep)
        leader = LeaderManager(cfg_healthy, rep)
        service = FedConsensusService(
            cfg_healthy, db_healthy, rep, fw_healthy, consensus, leader, engine_healthy
        )

        # Test Telemetry Status
        status = service.GetStatus(pb2.StatusRequest(caller_id="tester"), None)
        assert status.node_id == cfg_healthy.node_id

        # Test Fault Injection: LIAR mode
        service.set_byzantine_mode("LIAR")
        assert service.GetStatus(pb2.StatusRequest(caller_id="tester"), None).state == "BYZANTINE_LIAR"

        # Test Fault Injection: FORGER mode
        service.set_byzantine_mode("FORGER")
        assert service.GetStatus(pb2.StatusRequest(caller_id="tester"), None).state == "BYZANTINE_FORGER"

        # Reset Honest mode
        service.set_byzantine_mode("NONE")
        print("  [PASS] 2. gRPC Service & Byzantine Fault Injection Verified (Chaos Modes Ready)")

        # =========================================================
        # 3. TEST DUAL-SERVER NODE RUNNER (Milestone 3.3)
        # =========================================================
        os.environ["DATA_DIR"] = temp_dir
        os.environ["GRPC_PORT"] = "19051"
        os.environ["HTTP_PORT"] = "18080"
        os.environ["NODE_ID"] = "fednode-runner-test"

        runner = FedNodeRunner()
        runner.start()
        time.sleep(1.0)

        try:
            # Check HTTP /health
            with urllib.request.urlopen("http://127.0.0.1:18080/health", timeout=2.0) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "HEALTHY"

            # Check HTTP /inbox
            benign_payload = json.dumps({
                "actor": "https://normal-server.org/users/alice",
                "object": {"content": "Hello fediverse!"}
            }).encode("utf-8")
            post_req = urllib.request.Request(
                "http://127.0.0.1:18080/inbox",
                data=benign_payload,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(post_req, timeout=2.0) as resp:
                assert resp.status == 202

            # Check gRPC mesh port
            channel = grpc.insecure_channel("127.0.0.1:19051")
            stub = pb2_grpc.FedConsensusServiceStub(channel)
            res = stub.GetStatus(pb2.StatusRequest(caller_id="tester"), timeout=2.0)
            assert res.node_id == "fednode-runner-test"
            print("  [PASS] 3. Dual-Server Mesh Verified (HTTP Port 18080 & gRPC Port 19051)")
        finally:
            runner.stop()

        print("=======================================================")
        print("   ALL PHASE 3 MODULES VERIFIED & INTEGRATED 100%!     ")
        print("=======================================================\n")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_phase3_comprehensive_verification()
