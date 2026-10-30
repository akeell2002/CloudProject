from typing import List, Dict, Any
from node.storage.database import Database


class ReputationManager:
    """
    Dynamic Peer Reputation Ledger (Section 3 of Specification):
    Nodes maintain trust scores (100 -> 0) for every peer in the consortium.
    Liars, censors, and forgers are penalized and stripped of voting rights.
    """
    PENALTY_FORGED_SIGNATURE = -40
    PENALTY_EQUIVOCATION = -50
    PENALTY_CENSORSHIP = -30
    PENALTY_BOGUS_EVIDENCE = -25
    BONUS_HONEST_VOTE = +2

    def __init__(self, db: Database):
        self.db = db

    def penalize_forgery(self, peer_id: str):
        """Called when a node submits a forged signature."""
        self.db.update_reputation(peer_id, self.PENALTY_FORGED_SIGNATURE, is_violation=True)

    def penalize_equivocation(self, peer_id: str):
        """Called when a node sends conflicting votes to different peers (lying)."""
        self.db.update_reputation(peer_id, self.PENALTY_EQUIVOCATION, is_violation=True)

    def penalize_censorship(self, peer_id: str):
        """Called when a leader ignores or censors incoming attack reports."""
        self.db.update_reputation(peer_id, self.PENALTY_CENSORSHIP, is_violation=True)

    def penalize_bogus_evidence(self, peer_id: str):
        """Called when a node submits invalid or fabricated evidence."""
        self.db.update_reputation(peer_id, self.PENALTY_BOGUS_EVIDENCE, is_violation=True)

    def reward_honest_participation(self, peer_id: str):
        """Rewards honest nodes who vote validly."""
        self.db.update_reputation(peer_id, self.BONUS_HONEST_VOTE, is_violation=False)

    def is_peer_eligible_to_vote(self, peer_id: str) -> bool:
        """
        Quarantine Rule:
        Peers with trust scores falling below 30 lose consensus voting rights.
        """
        reps = {r["peer_id"]: r for r in self.db.get_all_reputations()}
        if peer_id not in reps:
            return True  # Default trust for new registered peers
        return reps[peer_id]["trust_score"] >= 30 and bool(reps[peer_id]["is_active"])

    def get_ledger(self) -> List[Dict[str, Any]]:
        """Returns the full reputation table for dashboard monitoring."""
        return self.db.get_all_reputations()
