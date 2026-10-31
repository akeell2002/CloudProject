import os
import sys
import shutil
import tempfile

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from proto import fedconsensus_pb2 as pb2
from node.config import NodeConfig
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.ingress.firewall import FirewallFilter
from node.ingress.classifier import ThreatClassifier
from node.ingress.activitypub import ActivityPubInbox
from node.engine.consensus import ConsensusEngine
from node.engine.leader import LeaderManager
from node.crypto.ed25519 import generate_keypair, sign_message


def test_phase2_full_pipeline():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "phase2_verify.db")
    try:
        # 1. Initialize Core Services (Leader is fednode-0)
        os.environ["NODE_ID"] = "fednode-0"
        db = Database(db_path)
        fw = FirewallFilter(db)
        rep = ReputationManager(db)
        cfg = NodeConfig()
        cfg.node_id = "fednode-0"
        tc = ThreatClassifier()
        inbox = ActivityPubInbox(fw, tc)
        engine = ConsensusEngine(cfg, db, fw, rep)
        leader = LeaderManager(cfg, rep)

        print("\n=======================================================")
        print("   FEDCONSENSUS: PHASE 2 PIPELINE VERIFICATION         ")
        print("=======================================================")

        # ---------------------------------------------------------
        # TEST 1: ActivityPub Ingress & Threat Classification
        # ---------------------------------------------------------
        malicious_post = {
            "actor": "https://malware-distributor.net/users/bot1",
            "object": {
                "type": "Note",
                "content": "Download this urgent security patch: update.exe now!"
            }
        }
        status_code, res = inbox.process_inbox_post(malicious_post)
        assert status_code == 403
        assert res["status"] == "FLAGGED_FOR_CONSENSUS"
        assert res["threat_score"] >= 0.60
        print(f"  [PASS] 1. Ingress Caught Malware Attack (Score: {res['threat_score']})")

        # ---------------------------------------------------------
        # TEST 2: Phase 1 Proposal Creation
        # ---------------------------------------------------------
        target_domain = "malware-distributor.net"
        prop = engine.create_proposal(
            target_domain=target_domain,
            reason=res["dominant_reason_code"],
            evidence_payload="{}",
            origin_http_signature="",
            threat_score=res["threat_score"]
        )
        assert prop.proposal_id.startswith("prop-")
        assert prop.target_domain == target_domain
        assert prop.proposer_id == "fednode-0"
        print(f"  [PASS] 2. Leader Generated Proposal: {prop.proposal_id}")

        # ---------------------------------------------------------
        # TEST 3: Generate 3 Follower Peers with REAL Keypairs
        # ---------------------------------------------------------
        followers = []
        for i in range(1, 4):
            node_id = f"fednode-{i}"
            priv, pub = generate_keypair()
            engine.register_peer_key(node_id, pub)
            followers.append((node_id, priv, pub))

        # ---------------------------------------------------------
        # TEST 4: Phase 2 Voting with Real Cryptographic Signatures
        # ---------------------------------------------------------
        proof = None
        for node_id, priv, pub in followers:
            vote_meta = {
                "proposal_id": prop.proposal_id,
                "sequence_number": prop.sequence_number,
                "epoch": prop.epoch,
                "target_domain": target_domain,
                "decision": "APPROVE"
            }
            # Followers legitimately sign their ballots
            valid_sig = sign_message(priv, vote_meta)

            ballot = pb2.VoteRequest(
                proposal_id=prop.proposal_id,
                sequence_number=prop.sequence_number,
                epoch=prop.epoch,
                target_domain=target_domain,
                voter_id=node_id,
                decision=pb2.VOTE_APPROVE,
                voter_signature=valid_sig,
                timestamp=12345
            )
            # handle_vote checks real cryptography!
            result_proof = engine.handle_vote(ballot)
            if result_proof is not None:
                proof = result_proof

        # Quorum Q = 4 (1 leader fednode-0 + 3 followers fednode-1,2,3 = 4 valid signatures!)
        assert proof is not None
        assert len(proof.signatures) == 4
        print("  [PASS] 3. Quorum Reached (Q=4/5) -> Quorum Certificate (QC) Minted!")

        # ---------------------------------------------------------
        # TEST 5: Phase 3 Commit & Perimeter Firewall Enforcement
        # ---------------------------------------------------------
        committed = engine.commit_defederation(proof)
        assert committed is True
        assert db.is_domain_blocked(target_domain) is True
        assert fw.is_blocked(target_domain) is True
        print("  [PASS] 4. Decision Committed to SQLite WAL & Firewall Blocklist Active!")

        # ---------------------------------------------------------
        # TEST 6: Verify Ingress Now Drops Attacker at Perimeter
        # ---------------------------------------------------------
        retry_code, retry_res = inbox.process_inbox_post(malicious_post)
        assert retry_code == 403
        assert retry_res["status"] == "BLOCKED"
        print("  [PASS] 5. Perimeter Firewall Instantly Drops Subsequent Traffic (HTTP 403)!")

        # ---------------------------------------------------------
        # TEST 7: Leader Leases & Follower Impeachment
        # ---------------------------------------------------------
        assert leader.get_leader_for_epoch(1) == "fednode-0"
        imp_req = leader.create_impeachment_request("Leader unresponsive")
        assert imp_req.leader_id == "fednode-0"
        print("  [PASS] 6. Leader Lease & Impeachment Engine Active!")

        print("=======================================================")
        print("   ALL PHASE 2 ENGINES VERIFIED & INTEGRATED 100%!    ")
        print("=======================================================\n")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    test_phase2_full_pipeline()
