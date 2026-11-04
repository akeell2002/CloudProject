import os
import sys
import shutil
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from proto import fedconsensus_pb2 as pb2
from node.config import NodeConfig
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.ingress.firewall import FirewallFilter
from node.engine.consensus import ConsensusEngine
from node.engine.leader import LeaderManager
from node.engine.catchup import CatchupEngine
from node.service import FedConsensusService


def test_service_and_byzantine_modes():
    temp_dir = tempfile.mkdtemp()
    try:
        # 1. Initialize complete component stack
        db = Database(os.path.join(temp_dir, "service_test.db"))
        rep = ReputationManager(db)
        fw = FirewallFilter(db)
        cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        consensus = ConsensusEngine(cfg, db, fw, rep)
        leader = LeaderManager(cfg, rep)
        catchup = CatchupEngine(cfg, db, fw)

        service = FedConsensusService(cfg, db, rep, fw, consensus, leader, catchup)

        # 2. Test GetStatus RPC
        status = service.GetStatus(pb2.StatusRequest(caller_id="test_client"), None)
        assert status.node_id == "fednode-0"
        assert status.blocked_domains_count == 0
        assert status.last_committed_seq == 0
        print("  [PASS] 1. GetStatus telemetry returned cleanly (state: " + status.state + ")")

        # 3. Test Byzantine LIAR Mode injection
        service.set_byzantine_mode("LIAR")
        assert service.byzantine_mode == "LIAR"
        status_liar = service.GetStatus(pb2.StatusRequest(caller_id="test_client"), None)
        assert status_liar.state == "BYZANTINE_LIAR"
        print("  [PASS] 2. Byzantine LIAR mode active and visible in telemetry")

        # 4. Test Byzantine FORGER Mode injection
        service.set_byzantine_mode("FORGER")
        assert service.byzantine_mode == "FORGER"
        status_forger = service.GetStatus(pb2.StatusRequest(caller_id="test_client"), None)
        assert status_forger.state == "BYZANTINE_FORGER"
        print("  [PASS] 3. Byzantine FORGER mode active and visible in telemetry")

        # 5. Restore Honest Mode
        service.set_byzantine_mode("NONE")
        assert service.byzantine_mode == "NONE"
        print("  [PASS] 4. Honest mode restored")

        print("\n=======================================================")
        print("   MILESTONE 3.2: gRPC SERVICE & CHAOS MODES 100%!     ")
        print("=======================================================\n")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    test_service_and_byzantine_modes()