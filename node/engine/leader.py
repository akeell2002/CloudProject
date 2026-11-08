import time
import threading
from typing import Dict, Optional, Tuple, Set, Any
from proto import fedconsensus_pb2 as pb2
from node.config import NodeConfig
from node.storage.reputation import ReputationManager
from node.crypto.ed25519 import sign_message, verify_signature


class LeaderManager:
    """
    Dynamic Leader Lease & Anti-Censorship Impeachment Engine (Section 1).
    Manages epoch terms, heartbeat lease renewals, and follower emergency elections.
    """
    LEASE_DURATION_SECONDS = 5.0
    PROPOSAL_CENSOR_TIMEOUT_SECONDS = 3.0

    def __init__(self, config: NodeConfig, reputation: ReputationManager):
        self.config = config
        self.reputation = reputation
        self._lock = threading.Lock()

        self.current_epoch = 1
        self.lease_expires_at = time.time() + self.LEASE_DURATION_SECONDS
        # Track impeachment votes: epoch -> set of accuser node_ids
        self.impeachment_votes: Dict[int, Set[str]] = {}
        self.censorship_watches: Dict[str, Dict[str, Any]] = {}
        self.penalized_epochs: Set[int] = set()

    def get_leader_for_epoch(self, epoch: int) -> str:
        """Deterministic round-robin leader selection skipping quarantined peers."""
        n = max(len(self.config.peers), 1)
        base_idx = (epoch - 1) % n
        for offset in range(n):
            candidate = f"fednode-{(base_idx + offset) % n}"
            if self.reputation.is_peer_eligible_to_vote(candidate):
                return candidate
        return f"fednode-{base_idx}"

    def watch_censorship(self, domain: str, payload: dict, assessment):
        """Follower starts a 3.0s timer waiting for the Leader to propose/commit this domain."""
        with self._lock:
            if domain not in self.censorship_watches:
                self.censorship_watches[domain] = {
                    "reported_at": time.time(),
                    "payload": payload,
                    "assessment": assessment,
                    "epoch": self.current_epoch
                }

    def clear_censorship_watch(self, domain: str):
        with self._lock:
            self.censorship_watches.pop(domain, None)

    def get_expired_censorship_watches(self) -> list:
        now = time.time()
        expired = []
        with self._lock:
            for domain, info in list(self.censorship_watches.items()):
                if now - info["reported_at"] >= self.PROPOSAL_CENSOR_TIMEOUT_SECONDS:
                    expired.append((domain, info))
                    del self.censorship_watches[domain]
        return expired

    def is_current_leader(self) -> bool:
        """Returns True if this node is the active leader for the current epoch."""
        with self._lock:
            expected_leader = self.get_leader_for_epoch(self.current_epoch)
            is_match = (self.config.node_id == expected_leader)
            return is_match and time.time() < self.lease_expires_at

    # -------------------------------------------------------------
    # HEARTBEATS & LEASE RENEWAL
    # -------------------------------------------------------------
    def generate_heartbeat(self) -> pb2.HeartbeatRequest:
        """Leader generates signed heartbeat to renew lease across followers."""
        with self._lock:
            now = time.time()
            self.lease_expires_at = now + self.LEASE_DURATION_SECONDS
            lease_exp_ms = int(self.lease_expires_at * 1000)

            sign_meta = {
                "leader_id": self.config.node_id,
                "epoch": self.current_epoch,
                "lease_expires_at": lease_exp_ms
            }
            sig = sign_message(self.config.private_key_hex, sign_meta)

            return pb2.HeartbeatRequest(
                leader_id=self.config.node_id,
                epoch=self.current_epoch,
                lease_expires_at=lease_exp_ms,
                signature=sig
            )

    def handle_heartbeat(self, req: pb2.HeartbeatRequest, leader_pubkey: str) -> Tuple[bool, int]:
        """Follower audits and acknowledges leader heartbeat."""
        with self._lock:
            # 1. Verify epoch
            if req.epoch < self.current_epoch:
                return False, self.current_epoch  # Stale leader

            # 2. Verify signature
            sign_meta = {
                "leader_id": req.leader_id,
                "epoch": req.epoch,
                "lease_expires_at": req.lease_expires_at
            }
            if not verify_signature(leader_pubkey, sign_meta, req.signature):
                self.reputation.penalize_forgery(req.leader_id)
                return False, self.current_epoch

            # 3. If advancing epoch after impeachment votes, penalize deposed leader once
            if req.epoch > self.current_epoch:
                for e in range(self.current_epoch, req.epoch):
                    if e in self.impeachment_votes and e not in self.penalized_epochs:
                        old_leader = self.get_leader_for_epoch(e)
                        self.penalized_epochs.add(e)
                        self.reputation.penalize_censorship(old_leader)

            # 4. Renew follower's local lease timer for this leader
            self.current_epoch = req.epoch
            self.lease_expires_at = req.lease_expires_at / 1000.0
            return True, self.current_epoch

    # -------------------------------------------------------------
    # FOLLOWER IMPEACHMENT (ANTI-CENSORSHIP)
    # -------------------------------------------------------------
    def create_impeachment_request(self, justification: str) -> pb2.ImpeachRequest:
        """Follower triggers emergency election if leader censors attacks or dies."""
        with self._lock:
            target_leader = self.get_leader_for_epoch(self.current_epoch)
            sign_meta = {
                "accuser_id": self.config.node_id,
                "target_epoch": self.current_epoch,
                "leader_id": target_leader,
                "justification": justification
            }
            sig = sign_message(self.config.private_key_hex, sign_meta)

            return pb2.ImpeachRequest(
                accuser_id=self.config.node_id,
                target_epoch=self.current_epoch,
                leader_id=target_leader,
                justification=justification,
                signature=sig
            )

    def handle_impeachment(self, req: pb2.ImpeachRequest, accuser_pubkey: str) -> bool:
        """
        Processes impeachment vote.
        If Q = N - f nodes vote to impeach, leader is deposed and epoch increments!
        """
        with self._lock:
            # Verify accuser signature
            sign_meta = {
                "accuser_id": req.accuser_id,
                "target_epoch": req.target_epoch,
                "leader_id": req.leader_id,
                "justification": req.justification
            }
            if not verify_signature(accuser_pubkey, sign_meta, req.signature):
                self.reputation.penalize_forgery(req.accuser_id)
                return False

            if req.target_epoch not in self.impeachment_votes:
                self.impeachment_votes[req.target_epoch] = set()

            self.impeachment_votes[req.target_epoch].add(req.accuser_id)
            if self.config.node_id != req.leader_id and self.current_epoch <= req.target_epoch:
                self.impeachment_votes[req.target_epoch].add(self.config.node_id)

            # Check if Quorum threshold reached to depose leader
            required_quorum = self.config.quorum_size
            if len(self.impeachment_votes[req.target_epoch]) >= required_quorum:
                if req.target_epoch not in self.penalized_epochs:
                    self.penalized_epochs.add(req.target_epoch)
                    self.reputation.penalize_censorship(req.leader_id)
                if self.current_epoch <= req.target_epoch:
                    # Advance epoch (failover to next leader!)
                    self.current_epoch = req.target_epoch + 1
                    self.lease_expires_at = time.time() + self.LEASE_DURATION_SECONDS
                return True

            # Return True if this node seconded the impeachment vote so the caller can tally it!
            return self.config.node_id in self.impeachment_votes[req.target_epoch]

    def record_impeachment_vote(self, target_epoch: int, leader_id: str, voter_id: str) -> bool:
        """Records an affirmative ImpeachResponse from a peer and advances epoch once Q votes are collected."""
        with self._lock:
            if target_epoch not in self.impeachment_votes:
                self.impeachment_votes[target_epoch] = set()
            self.impeachment_votes[target_epoch].add(voter_id)
            if len(self.impeachment_votes[target_epoch]) >= self.config.quorum_size:
                if target_epoch not in self.penalized_epochs:
                    self.penalized_epochs.add(target_epoch)
                    self.reputation.penalize_censorship(leader_id)
                if self.current_epoch <= target_epoch:
                    self.current_epoch = target_epoch + 1
                    self.lease_expires_at = time.time() + self.LEASE_DURATION_SECONDS
                return True
            return False
