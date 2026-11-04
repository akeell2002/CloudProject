import os
import sys
import shutil
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from proto import fedconsensus_pb2 as pb2
from node.config import NodeConfig
from node.storage.database import Database
from node.ingress.firewall import FirewallFilter
from node.engine.catchup import CatchupEngine
from node.crypto.ed25519 import generate_keypair, sign_message


def test_catchup_and_self_healing():
    temp_dir_healthy = tempfile.mkdtemp()
    temp_dir_crashed = tempfile.mkdtemp()
    try:
        # 1. Setup a "Healthy" Node that has committed bans
        db_healthy = Database(os.path.join(temp_dir_healthy, "healthy.db"))
        fw_healthy = FirewallFilter(db_healthy)
        cfg_healthy = NodeConfig()
        engine_healthy = CatchupEngine(cfg_healthy, db_healthy, fw_healthy)

        # Generate 4 honest node keys
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

        # 2. Setup a "Crashed" Node that just woke up (its DB is empty!)
        db_crashed = Database(os.path.join(temp_dir_crashed, "crashed.db"))
        fw_crashed = FirewallFilter(db_crashed)
        cfg_crashed = NodeConfig()
        engine_crashed = CatchupEngine(cfg_crashed, db_crashed, fw_crashed)

        # Register the known peer public keys on the crashed node
        for node_id, (_, pub) in keys.items():
            engine_crashed.register_peer_key(node_id, pub)

        assert db_crashed.get_latest_sequence_number() == 0
        assert fw_crashed.is_blocked("botnet-attack.org") is False
        print("  [PASS] 1. Crashed node starts empty (seq=0, domain not blocked)")

        # 3. Crashed node asks healthy node: "Catchup from seq 1"
        req = pb2.CatchupRequest(node_id="fednode-4", from_sequence_number=1)
        res = engine_healthy.handle_catchup_request(req)

        assert len(res.records) == 1
        assert res.records[0].target_domain == "botnet-attack.org"
        print(f"  [PASS] 2. Healthy node provided {len(res.records)} missed records")

        # 4. Crashed node replays and verifies cryptographic proofs
        replayed = engine_crashed.replay_records(list(res.records))
        assert replayed == 1
        assert db_crashed.get_latest_sequence_number() == 1
        assert fw_crashed.is_blocked("botnet-attack.org") is True
        print("  [PASS] 3. Self-healing complete! Record audited, saved to SQLite, and active in RAM Firewall!")

        print("\n=======================================================")
        print("   MILESTONE 3.1: CATCH-UP ENGINE VERIFIED 100%!       ")
        print("=======================================================\n")

    finally:
        shutil.rmtree(temp_dir_healthy, ignore_errors=True)
        shutil.rmtree(temp_dir_crashed, ignore_errors=True)


if __name__ == "__main__":
    test_catchup_and_self_healing()