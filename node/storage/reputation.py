import threading
import time
from collections import OrderedDict
from typing import List, Dict, Any, Optional, Tuple
from node.storage.database import Database


class ReputationManager:
    """
    Dynamic Peer Reputation Ledger:
    Nodes maintain trust scores (100 -> 0) for every peer in the consortium.
    Liars, censors, and forgers are penalized and stripped of voting rights.

    Automatic penalties never apply to the local node (``self_id``). Penalties
    given a ``proposal_id`` are applied at most once per
    (violation type, peer, proposal). Trust recovers over time: after
    RECOVERY_GRACE_SECONDS without a new violation, a score below 100 rises by
    RECOVERY_STEP every RECOVERY_INTERVAL_SECONDS, capped at 100.
    """
    PENALTY_FORGED_SIGNATURE = -40
    PENALTY_EQUIVOCATION = -50
    PENALTY_CENSORSHIP = -30
    PENALTY_BOGUS_EVIDENCE = -25
    PENALTY_DISSENT_ON_THREAT = -15
    BONUS_HONEST_VOTE = +5

    RECOVERY_GRACE_SECONDS = 60
    RECOVERY_INTERVAL_SECONDS = 30
    RECOVERY_STEP = +5

    MAX_PENALTY_KEYS = 10_000

    def __init__(self, db: Database, self_id: Optional[str] = None):
        self.db = db
        self.self_id = self_id
        self._penalty_keys: "OrderedDict[Tuple[str, str, str], None]" = OrderedDict()
        self._penalty_lock = threading.Lock()
        self._reset_until: Dict[str, float] = {}

    def _claim_penalty(self, violation_type: str, peer_id: str, proposal_id: Optional[str]) -> bool:
        """Returns True if the penalty should be applied (first time for this key)."""
        if self.self_id is not None and peer_id == self.self_id:
            return False
        if proposal_id is None:
            return True
        key = (violation_type, peer_id, proposal_id)
        with self._penalty_lock:
            if key in self._penalty_keys:
                return False
            self._penalty_keys[key] = None
            while len(self._penalty_keys) > self.MAX_PENALTY_KEYS:
                self._penalty_keys.popitem(last=False)
        return True

    def _penalize(self, violation_type: str, peer_id: str, delta: int,
                  proposal_id: Optional[str] = None) -> bool:
        if not self._claim_penalty(violation_type, peer_id, proposal_id):
            return False
        self.db.update_reputation(peer_id, delta, is_violation=True)
        return True

    def penalize_forgery(self, peer_id: str, proposal_id: Optional[str] = None) -> bool:
        """Called when a node submits a forged signature."""
        return self._penalize("forgery", peer_id, self.PENALTY_FORGED_SIGNATURE, proposal_id)

    def penalize_equivocation(self, peer_id: str, proposal_id: Optional[str] = None) -> bool:
        """Called when a node sends conflicting votes to different peers (lying)."""
        if self.self_id is not None and peer_id == self.self_id:
            return False
        prior_dissent = False
        if proposal_id is not None:
            with self._penalty_lock:
                if ("equivocation", peer_id, proposal_id) in self._penalty_keys:
                    return False
                prior_dissent = ("liar_dissent", peer_id, proposal_id) in self._penalty_keys
                self._penalty_keys[("equivocation", peer_id, proposal_id)] = None
                while len(self._penalty_keys) > self.MAX_PENALTY_KEYS:
                    self._penalty_keys.popitem(last=False)
        if prior_dissent:
            self.db.update_reputation(
                peer_id,
                self.PENALTY_EQUIVOCATION - self.PENALTY_DISSENT_ON_THREAT,
                is_violation=False,
            )
            return True
        self.db.update_reputation(peer_id, self.PENALTY_EQUIVOCATION, is_violation=True)
        return True

    def penalize_censorship(self, peer_id: str) -> bool:
        """Called when a leader ignores or censors incoming attack reports."""
        return self._penalize("censorship", peer_id, self.PENALTY_CENSORSHIP)

    def penalize_bogus_evidence(self, peer_id: str, proposal_id: Optional[str] = None) -> bool:
        """Called when a node submits invalid or fabricated evidence."""
        return self._penalize("bogus_evidence", peer_id, self.PENALTY_BOGUS_EVIDENCE, proposal_id)

    def penalize_dissent_on_valid_threat(self, peer_id: str, proposal_id: Optional[str] = None) -> bool:
        """Called when a Byzantine LIAR votes REJECT against a verified threat."""
        return self._penalize("liar_dissent", peer_id, self.PENALTY_DISSENT_ON_THREAT, proposal_id)

    def reward_honest_participation(self, peer_id: str, proposal_id: Optional[str] = None) -> bool:
        """Rewards eligible honest peers who cast a valid APPROVE ballot (+5 trust, capped at 100)."""
        if not self.is_peer_eligible_to_vote(peer_id):
            return False
        if not self._claim_penalty("honest_vote", peer_id, proposal_id):
            return False
        self.db.update_reputation(peer_id, self.BONUS_HONEST_VOTE, is_violation=False, mark_recovered=True)
        return True

    def apply_recovery(self, now: Optional[float] = None) -> int:
        """Raises every score below 100 by RECOVERY_STEP once the grace period and
        interval have elapsed. ``now`` is in seconds. Returns the rows raised."""
        now_s = time.time() if now is None else now
        return self.db.recover_reputations(
            step=self.RECOVERY_STEP,
            grace_ms=self.RECOVERY_GRACE_SECONDS * 1000,
            interval_ms=self.RECOVERY_INTERVAL_SECONDS * 1000,
            now_ms=int(round(now_s * 1000)),
        )

    def mark_reset(self, peer_id: str, ttl: float = 12.0):
        """Suppresses stale peer gossip overwriting an explicit operator score reset."""
        with self._penalty_lock:
            self._reset_until[peer_id] = time.time() + ttl
            stale_keys = [k for k in self._penalty_keys if k[1] == peer_id]
            for k in stale_keys:
                self._penalty_keys.pop(k, None)

    def set_operator_reputation(self, peer_id: str, score: int, ttl: float = 12.0):
        """Applies an operator score change under the lock so sync gossip cannot race it."""
        with self._penalty_lock:
            if score >= 100:
                self._reset_until[peer_id] = time.time() + ttl
                stale_keys = [k for k in self._penalty_keys if k[1] == peer_id]
                for k in stale_keys:
                    self._penalty_keys.pop(k, None)
            else:
                self._reset_until.pop(peer_id, None)
            self.db.set_reputation(peer_id, score)

    def adopt_peer_view(self, peer_id: str, remote_score: int, remote_violations: Optional[int] = None) -> bool:
        """Adopts a peer's lower score for ``peer_id``; never touches the own entry."""
        if self.self_id is not None and peer_id == self.self_id:
            return False
        with self._penalty_lock:
            if time.time() < self._reset_until.get(peer_id, 0.0):
                return False
            self.db.adopt_lower_reputation(peer_id, remote_score, violations_count=remote_violations)
            return True

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
