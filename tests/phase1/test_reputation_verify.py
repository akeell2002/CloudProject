import os
import sys
import shutil
import tempfile

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.storage.database import Database
from node.storage.reputation import ReputationManager


def test_peer_reputation_and_quarantine():
    """Verify dynamic trust score scoring, penalties, and quarantine threshold."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "rep_factor_test.db")
    try:
        db = Database(db_path)
        rep = ReputationManager(db)

        peer = "fednode-rogue"

        # 1. Baseline status
        assert rep.is_peer_eligible_to_vote(peer) is True
        print("  [PASS] 1. New peer initialized with 100 trust points (Eligible)")

        # 2. Equivocation penalty (-50 points -> 50)
        rep.penalize_equivocation(peer)
        ledger = rep.get_ledger()
        peer_entry = next(r for r in ledger if r["peer_id"] == peer)
        assert peer_entry["trust_score"] == 50
        assert peer_entry["violations_count"] == 1
        assert rep.is_peer_eligible_to_vote(peer) is True
        print(f"  [PASS] 2. Equivocation penalty deducted 50 points (Score: {peer_entry['trust_score']})")

        # 3. Forgery penalty (-40 points -> 10)
        rep.penalize_forgery(peer)
        ledger = rep.get_ledger()
        peer_entry = next(r for r in ledger if r["peer_id"] == peer)
        assert peer_entry["trust_score"] == 10
        assert peer_entry["violations_count"] == 2
        print(f"  [PASS] 3. Forgery penalty deducted 40 points (Score: {peer_entry['trust_score']})")

        # 4. Quarantine cutoff enforcement (score < 30)
        assert rep.is_peer_eligible_to_vote(peer) is False
        print("  [PASS] 4. Quarantine enforcement: peer with score < 30 stripped of voting rights")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    print("\n=======================================================")
    print("   PHASE 1 FACTOR: DYNAMIC PEER REPUTATION LEDGER      ")
    print("=======================================================")
    test_peer_reputation_and_quarantine()
    print("=======================================================")
    print("   ALL PEER REPUTATION MODULES PASS 100%!              ")
    print("=======================================================\n")
