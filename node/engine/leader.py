import time
import threading
from typing import Dict, Optional, Tuple, Set
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

    def get_leader_for_epoch(self, epoch: int) -> str:
        """Deterministic round-robin leader selection: leader = peers[epoch % N]."""
        sorted_peers = sorted(self.config.peers)
        if not sorted_peers:
            return self.config.node_id
        # Use modulo to pick deterministic leader for this term
        idx = (epoch - 1) % len(sorted_peers)
        # Handle 'host:port' by mapping to node identifier
        return f"fednode-{idx}"

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

            # 3. Renew follower's local lease timer for this leader
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

            # Check if Quorum threshold reached to depose leader
            required_quorum = self.config.quorum_size
            if len(self.impeachment_votes[req.target_epoch]) >= required_quorum:
                # Penalize censoring leader
                self.reputation.penalize_censorship(req.leader_id)
                # Advance epoch (failover to next leader!)
                self.current_epoch = req.target_epoch + 1
                self.lease_expires_at = time.time() + self.LEASE_DURATION_SECONDS
                return True

            return False
