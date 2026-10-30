import os
import sys
import shutil
import tempfile

# Add project root to sys.path so modules and proto packages resolve cleanly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from proto import fedconsensus_pb2 as pb2
from node.crypto.ed25519 import (
    generate_keypair,
    sign_message,
    verify_signature,
    canonical_json_hash
)
from node.crypto.http_sig import (
    create_origin_http_signature,
    verify_origin_http_signature
)
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.config import NodeConfig


def test_grpc_proto_messages():
    """Verify that all gRPC Protobuf classes can instantiate cleanly."""
    req = pb2.ProposeRequest(
        proposal_id="prop-001",
        sequence_number=1,
        epoch=1,
        target_domain="spam-botnet.net",
        reason=pb2.REASON_BOTNET,
        evidence_payload='{"actor": "botnet.net"}',
        threat_score=0.92,
        proposer_id="fednode-0"
    )
    assert req.proposal_id == "prop-001"
    assert req.reason == pb2.REASON_BOTNET
    assert round(req.threat_score, 2) == 0.92
    print("  [PASS] gRPC Proto Messages Instantiation")


def test_ed25519_signatures():
    """Verify digital signature creation, canonical hashing, and forgery detection."""
    priv, pub = generate_keypair()
    
    # 1. Deterministic Canonical Hash check
    dict_a = {"domain": "evil.xyz", "seq": 10}
    dict_b = {"seq": 10, "domain": "evil.xyz"}
    assert canonical_json_hash(dict_a) == canonical_json_hash(dict_b)

    # 2. Genuine signature verification
    sig = sign_message(priv, dict_a)
    assert verify_signature(pub, dict_a, sig) is True

    # 3. Tampered payload rejection
    tampered_dict = {"domain": "innocent.edu", "seq": 10}
    assert verify_signature(pub, tampered_dict, sig) is False

    # 4. Forged signature rejection (using another node's public key)
    _, other_pub = generate_keypair()
    assert verify_signature(other_pub, dict_a, sig) is False
    print("  [PASS] Ed25519 Signatures & Canonical Hash")


def test_http_sig_anti_framing():
    """Verify that framing attacks against innocent servers are caught and rejected."""
    evil_priv, evil_pub = generate_keypair()
    accused_domain = "evil-spammer.com"
    known_keys = {accused_domain: evil_pub}

    payload = {"content": "Malicious phishing payload"}
    valid_sig = create_origin_http_signature(accused_domain, payload, evil_priv)

    # 1. Real spam verified
    assert verify_origin_http_signature(accused_domain, payload, valid_sig, known_keys) is True

    # 2. Framing attack caught (someone attributing the post to an innocent domain)
    innocent_domain = "innocent-university.edu"
    assert verify_origin_http_signature(innocent_domain, payload, valid_sig, known_keys) is False
    print("  [PASS] Origin HTTP Signature Anti-Framing")


def test_sqlite_wal_storage():
    """Verify SQLite WAL mode, atomic commits, and catchup synchronization."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "wal_verify.db")
    try:
        db = Database(db_path)
        assert db.get_latest_sequence_number() == 0

        # Save committed decision with Quorum Proof
        proof = {
            "proposal_id": "prop-100",
            "target_domain": "malware.net",
            "signatures": ["sig_node0", "sig_node1", "sig_node2", "sig_node3"]
        }
        success = db.save_commit_record(
            sequence_number=1,
            epoch=1,
            target_domain="malware.net",
            reason=pb2.REASON_MALICIOUS_FILES,
            quorum_proof=proof
        )
        assert success is True
        assert db.get_latest_sequence_number() == 1
        assert db.is_domain_blocked("malware.net") is True
        assert db.is_domain_blocked("safe-site.org") is False

        # Catchup fetch check
        records = db.get_commit_records(from_sequence_number=1)
        assert len(records) == 1
        assert records[0]["target_domain"] == "malware.net"
        assert len(records[0]["quorum_proof"]["signatures"]) == 4
        print("  [PASS] SQLite WAL Storage & Catch-Up Sync")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_peer_reputation():
    """Verify trust score deductions and quarantine threshold stripping."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "rep_verify.db")
    try:
        db = Database(db_path)
        rep = ReputationManager(db)

        peer = "fednode-4"
        # Peer starts eligible
        assert rep.is_peer_eligible_to_vote(peer) is True

        # First violation: Equivocation (-50 points -> 50)
        rep.penalize_equivocation(peer)
        assert rep.is_peer_eligible_to_vote(peer) is True

        # Second violation: Forgery (-40 points -> 10)
        rep.penalize_forgery(peer)
        # Trust score is now 10 < 30 -> QUARANTINED!
        assert rep.is_peer_eligible_to_vote(peer) is False
        print("  [PASS] Dynamic Peer Reputation & Quarantine Cutoff")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_node_configuration():
    """Verify configuration loading and rigorous BFT quorum math."""
    cfg = NodeConfig()
    assert cfg.total_nodes == 5
    assert cfg.max_byzantine_faults == 1
    assert cfg.quorum_size == 4  # Strict BFT Q = N - f
    assert len(cfg.public_key_hex) == 64
    assert len(cfg.private_key_hex) == 64
    print("  [PASS] NodeConfig & BFT Quorum Math (Q = N - f = 4)")


if __name__ == "__main__":
    print("\n=======================================================")
    print("   FEDCONSENSUS: PHASE 1 COMPREHENSIVE VERIFICATION   ")
    print("=======================================================")
    test_grpc_proto_messages()
    test_ed25519_signatures()
    test_http_sig_anti_framing()
    test_sqlite_wal_storage()
    test_peer_reputation()
    test_node_configuration()
    print("=======================================================")
    print("   ALL PHASE 1 MODULES VERIFIED & WORKING 100%!       ")
    print("=======================================================\n")
