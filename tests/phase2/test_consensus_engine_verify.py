import os
import sys
import shutil
import tempfile

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.config import NodeConfig
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.ingress.firewall import FirewallFilter
from node.engine.consensus import ConsensusEngine
from node.crypto.ed25519 import generate_keypair, sign_message
from proto import fedconsensus_pb2 as pb2


def test_consensus_engine_state_machine():
    """Verify 3-phase consensus: PROPOSE -> PREPARE -> QC Minting -> COMMIT."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "consensus_engine_test.db")
    try:
        os.environ["NODE_ID"] = "fednode-0"
        cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        db = Database(db_path)
        fw = FirewallFilter(db)
        rep = ReputationManager(db)
        engine = ConsensusEngine(cfg, db, fw, rep)

        # 1. Phase 1: Create Proposal (PROPOSE)
        target = "botnet-distributor.cc"
        prop = engine.create_proposal(
            target_domain=target,
            reason=pb2.REASON_BOTNET,
            evidence_payload='{"actor": "botnet"}',
            origin_http_signature="",
            threat_score=0.91
        )
        assert prop.sequence_number == 1
        assert prop.proposer_id == "fednode-0"
        print(f"  [PASS] 1. Proposal minted by leader (Seq: {prop.sequence_number}, ID: {prop.proposal_id})")

        # 2. Phase 2: Voting & Quorum Accumulation (PREPARE)
        # Register 3 follower public keys
        followers = []
        for i in range(1, 4):
            peer_id = f"fednode-{i}"
            priv, pub = generate_keypair()
            engine.register_peer_key(peer_id, pub)
            followers.append((peer_id, priv, pub))

        qc = None
        for peer_id, priv, _ in followers:
            vote_meta = {
                "proposal_id": prop.proposal_id,
                "sequence_number": prop.sequence_number,
                "epoch": prop.epoch,
                "target_domain": target,
                "decision": "APPROVE"
            }
            sig = sign_message(priv, vote_meta)
            ballot = pb2.VoteRequest(
                proposal_id=prop.proposal_id,
                sequence_number=prop.sequence_number,
                epoch=prop.epoch,
                target_domain=target,
                voter_id=peer_id,
                decision=pb2.VOTE_APPROVE,
                voter_signature=sig,
                timestamp=1000
            )
            res = engine.handle_vote(ballot)
            if res is not None:
                qc = res

        # 3. Quorum Certificate (QC) check: 1 leader + 3 followers = 4 signatures
        assert qc is not None
        assert len(qc.signatures) == 4
        print(f"  [PASS] 2. Quorum reached (Q=4/5) -> Quorum Certificate minted with {len(qc.signatures)} signatures")

        # 4. Phase 3: COMMIT to WAL & activate perimeter blocklist
        committed = engine.commit_defederation(qc)
        assert committed is True
        assert db.is_domain_blocked(target) is True
        assert fw.is_blocked(target) is True
        print("  [PASS] 3. Decision committed to SQLite WAL & Firewall blocklist active in RAM")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    print("\n=======================================================")
    print("   PHASE 2 FACTOR: 3-PHASE BFT CONSENSUS ENGINE        ")
    print("=======================================================")
    test_consensus_engine_state_machine()
    print("=======================================================")
    print("   ALL CONSENSUS ENGINE MODULES PASS 100%!             ")
    print("=======================================================\n")
