import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.config import NodeConfig
from proto import fedconsensus_pb2 as pb2


def test_protobuf_and_config():
    """Verify Protobuf schemas, NodeConfig parsing, and BFT mathematical limits."""
    # 1. Protobuf Contract
    req = pb2.ProposeRequest(
        proposal_id="prop-proto-1",
        sequence_number=10,
        epoch=2,
        target_domain="phishing-bank.com",
        reason=pb2.REASON_PHISHING,
        evidence_payload='{"url": "http://phishing-bank.com"}',
        threat_score=0.95,
        proposer_id="fednode-0"
    )
    assert req.proposal_id == "prop-proto-1"
    assert req.reason == pb2.REASON_PHISHING
    assert req.proposer_id == "fednode-0"
    print("  [PASS] 1. Protobuf message instantiation & field mapping verified")

    # 2. NodeConfig Invariants
    cfg = NodeConfig()
    assert cfg.total_nodes == 5
    assert cfg.max_byzantine_faults == 1
    # Strict BFT quorum Q = N - f
    assert cfg.quorum_size == 4
    print(f"  [PASS] 2. BFT Quorum Math verified: N={cfg.total_nodes}, f={cfg.max_byzantine_faults}, Q={cfg.quorum_size}")

    # 3. Keypair generation and encoding
    assert len(cfg.public_key_hex) == 64
    assert len(cfg.private_key_hex) == 64
    print("  [PASS] 3. Node Ed25519 keypair loaded & hex-encoded (64 hex characters)")


if __name__ == "__main__":
    print("\n=======================================================")
    print("   PHASE 1 FACTOR: PROTOBUF CONTRACTS & NODE CONFIG    ")
    print("=======================================================")
    test_protobuf_and_config()
    print("=======================================================")
    print("   ALL CONFIGURATION MODULES PASS 100%!                ")
    print("=======================================================\n")
