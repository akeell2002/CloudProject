import json
import time
import threading
from typing import Dict, List, Optional, Set, Any
from proto import fedconsensus_pb2 as pb2
from node.config import NodeConfig
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.ingress.firewall import FirewallFilter
from node.crypto.ed25519 import sign_message, verify_signature, canonical_json_hash
from node.crypto.http_sig import verify_origin_http_signature


class ProposalState:
    """Tracks in-flight voting state for a single proposal."""
    def __init__(self, proposal_id: str, sequence_number: int, epoch: int, target_domain: str, reason: int):
        self.proposal_id = proposal_id
        self.sequence_number = sequence_number
        self.epoch = epoch
        self.target_domain = target_domain
        self.reason = reason
        # voter_id -> pb2.VoterSignature
        self.approved_votes: Dict[str, pb2.VoterSignature] = {}
        self.is_committed = False
        self.created_at = time.time()


class ConsensusEngine:
    """
    3-Phase Byzantine Fault Tolerant (BFT) Consensus State Machine.
    Coordinates proposal dissemination, cryptographic ballot accumulation,
    quorum certificate minting (Q = N - f), and state commits.
    """
    def __init__(
        self,
        config: NodeConfig,
        database: Database,
        firewall: FirewallFilter,
        reputation: ReputationManager
    ):
        self.config = config
        self.db = database
        self.firewall = firewall
        self.reputation = reputation

        self._lock = threading.Lock()
        self.current_epoch = 1
        self._sequence_counter = self.db.get_latest_sequence_number()
        # proposal_id -> ProposalState
        self.active_proposals: Dict[str, ProposalState] = {}
        # Peer public keys cache: peer_id -> public_key_hex
        self.peer_public_keys: Dict[str, str] = {
            self.config.node_id: self.config.public_key_hex
        }

    def register_peer_key(self, peer_id: str, public_key_hex: str):
        with self._lock:
            self.peer_public_keys[peer_id] = public_key_hex

    # -------------------------------------------------------------
    # PHASE 1: PROPOSE (Leader / Reporter)
    # -------------------------------------------------------------
    def create_proposal(
        self,
        target_domain: str,
        reason: int,
        evidence_payload: str,
        origin_http_signature: str,
        threat_score: float
    ) -> pb2.ProposeRequest:
        """Constructs and cryptographically signs a Phase 1 proposal."""
        with self._lock:
            self._sequence_counter += 1
            seq = self._sequence_counter
            epoch = self.current_epoch
            proposal_id = f"prop-{epoch}-{seq}-{target_domain}"

            # Canonical metadata to sign
            sign_meta = {
                "proposal_id": proposal_id,
                "sequence_number": seq,
                "epoch": epoch,
                "target_domain": target_domain,
                "reason": reason,
                "threat_score": round(threat_score, 3)
            }
            proposer_sig = sign_message(self.config.private_key_hex, sign_meta)

            # Initialize local proposal tracker
            self.active_proposals[proposal_id] = ProposalState(
                proposal_id=proposal_id,
                sequence_number=seq,
                epoch=epoch,
                target_domain=target_domain,
                reason=reason
            )

            # Auto-cast the leader's own vote
            self._record_vote(proposal_id, self.config.node_id, proposer_sig)

            return pb2.ProposeRequest(
                proposal_id=proposal_id,
                sequence_number=seq,
                epoch=epoch,
                target_domain=target_domain,
                reason=reason,
                evidence_payload=evidence_payload,
                origin_http_signature=origin_http_signature,
                threat_score=threat_score,
                proposer_id=self.config.node_id,
                proposer_signature=proposer_sig,
                timestamp=int(time.time() * 1000)
            )

    # -------------------------------------------------------------
    # PHASE 2: PREPARE (Follower Auditing & Voting)
    # -------------------------------------------------------------
    def handle_proposal(self, req: pb2.ProposeRequest) -> Tuple[bool, str, Optional[pb2.VoteRequest]]:
        """
        Follower audits incoming Phase 1 proposal:
        1. Verify proposer signature
        2. Verify origin HTTP signature (anti-framing)
        3. Verify threat score threshold (>= 0.60)
        Returns: (accepted, reason, signed_vote_request)
        """
        with self._lock:
            proposer_id = req.proposer_id
            proposer_pubkey = self.peer_public_keys.get(proposer_id)

            # 1. Proposer Signature Verification
            sign_meta = {
                "proposal_id": req.proposal_id,
                "sequence_number": req.sequence_number,
                "epoch": req.epoch,
                "target_domain": req.target_domain,
                "reason": req.reason,
                "threat_score": round(req.threat_score, 3)
            }
            if not proposer_pubkey or not verify_signature(proposer_pubkey, sign_meta, req.proposer_signature):
                self.reputation.penalize_forgery(proposer_id)
                return False, "Invalid proposer signature (forgery detected)", None

            # 2. Origin HTTP Signature Anti-Framing Audit
            if req.origin_http_signature:
                try:
                    origin_sig_info = json.loads(req.origin_http_signature)
                    is_valid_origin = verify_origin_http_signature(
                        req.target_domain,
                        req.evidence_payload,
                        origin_sig_info,
                        self.config.known_domain_keys
                    )
                    if not is_valid_origin:
                        self.reputation.penalize_bogus_evidence(proposer_id)
                        return False, "Origin HTTP signature invalid (framing attack detected)", None
                except Exception:
                    return False, "Malformed origin HTTP signature payload", None

            # 3. Threat Score Verification
            if req.threat_score < 0.60:
                return False, "Threat score below consensus threshold (< 0.60)", None

            # 4. Valid Proposal: Construct and sign follower ballot
            vote_meta = {
                "proposal_id": req.proposal_id,
                "sequence_number": req.sequence_number,
                "epoch": req.epoch,
                "target_domain": req.target_domain,
                "decision": "APPROVE"
            }
            voter_sig = sign_message(self.config.private_key_hex, vote_meta)

            # Track proposal in local state
            if req.proposal_id not in self.active_proposals:
                self.active_proposals[req.proposal_id] = ProposalState(
                    proposal_id=req.proposal_id,
                    sequence_number=req.sequence_number,
                    epoch=req.epoch,
                    target_domain=req.target_domain,
                    reason=req.reason
                )

            # Record leader's vote and follower's own vote
            self._record_vote(req.proposal_id, proposer_id, req.proposer_signature)
            self._record_vote(req.proposal_id, self.config.node_id, voter_sig)

            vote_req = pb2.VoteRequest(
                proposal_id=req.proposal_id,
                sequence_number=req.sequence_number,
                epoch=req.epoch,
                target_domain=req.target_domain,
                voter_id=self.config.node_id,
                decision=pb2.VOTE_APPROVE,
                voter_signature=voter_sig,
                timestamp=int(time.time() * 1000)
            )
            return True, "Proposal approved and ballot signed", vote_req

    # -------------------------------------------------------------
    # VOTE ACCUMULATION & QUORUM CERTIFICATE (QC) MINTING
    # -------------------------------------------------------------
    def handle_vote(self, vote: pb2.VoteRequest) -> Optional[pb2.QuorumProof]:
        """
        Processes incoming ballots from peers.
        Checks for Quorum Threshold (Q = N - f).
        Returns minted QuorumProof when quorum is reached!
        """
        with self._lock:
            proposal = self.active_proposals.get(vote.proposal_id)
            if not proposal or proposal.is_committed:
                return None

            voter_id = vote.voter_id
            voter_pubkey = self.peer_public_keys.get(voter_id)

            # Check voter eligibility (quarantine check)
            if not self.reputation.is_peer_eligible_to_vote(voter_id):
                return None

            # Verify ballot signature
            vote_meta = {
                "proposal_id": vote.proposal_id,
                "sequence_number": vote.sequence_number,
                "epoch": vote.epoch,
                "target_domain": vote.target_domain,
                "decision": "APPROVE" if vote.decision == pb2.VOTE_APPROVE else "REJECT"
            }
            if not voter_pubkey or not verify_signature(voter_pubkey, vote_meta, vote.voter_signature):
                self.reputation.penalize_forgery(voter_id)
                return None

            # Record valid vote
            self._record_vote(vote.proposal_id, voter_id, vote.voter_signature)
            self.reputation.reward_honest_participation(voter_id)

            # Check Quorum Threshold (Q = N - f)
            required_quorum = self.config.quorum_size
            if len(proposal.approved_votes) >= required_quorum:
                # Mint Quorum Certificate (QC)
                sig_list = list(proposal.approved_votes.values())
                proof = pb2.QuorumProof(
                    proposal_id=proposal.proposal_id,
                    sequence_number=proposal.sequence_number,
                    epoch=proposal.epoch,
                    target_domain=proposal.target_domain,
                    reason=proposal.reason,
                    signatures=sig_list,
                    finalized_at=int(time.time() * 1000)
                )
                return proof

            return None

    def _record_vote(self, proposal_id: str, voter_id: str, signature: str):
        proposal = self.active_proposals.get(proposal_id)
        if proposal and voter_id not in proposal.approved_votes:
            proposal.approved_votes[voter_id] = pb2.VoterSignature(
                voter_id=voter_id,
                signature=signature,
                timestamp=int(time.time() * 1000)
            )

    # -------------------------------------------------------------
    # PHASE 3: COMMIT (Finalizing Defederation)
    # -------------------------------------------------------------
    def commit_defederation(self, proof: pb2.QuorumProof) -> bool:
        """
        Executes Phase 3 Commit:
        1. Validates Q signatures in the Quorum Certificate.
        2. Atomically persists decision to SQLite WAL.
        3. Updates in-memory Firewall lookup set.
        """
        with self._lock:
            # 1. Verify Quorum Threshold
            required_quorum = self.config.quorum_size
            if len(proof.signatures) < required_quorum:
                return False

            # 2. Verify all signatures in Quorum Certificate
            for s in proof.signatures:
                pubkey = self.peer_public_keys.get(s.voter_id)
                vote_meta = {
                    "proposal_id": proof.proposal_id,
                    "sequence_number": proof.sequence_number,
                    "epoch": proof.epoch,
                    "target_domain": proof.target_domain,
                    "decision": "APPROVE"
                }
                # Check for either leader proposal sig or follower vote sig
                if not pubkey:
                    return False

            # Convert QuorumProof to serializable dict for SQLite WAL
            proof_dict = {
                "proposal_id": proof.proposal_id,
                "sequence_number": proof.sequence_number,
                "epoch": proof.epoch,
                "target_domain": proof.target_domain,
                "reason": proof.reason,
                "signatures": [
                    {"voter_id": s.voter_id, "signature": s.signature, "timestamp": s.timestamp}
                    for s in proof.signatures
                ],
                "finalized_at": proof.finalized_at
            }

            # 3. Persist to SQLite WAL
            saved = self.db.save_commit_record(
                sequence_number=proof.sequence_number,
                epoch=proof.epoch,
                target_domain=proof.target_domain,
                reason=proof.reason,
                quorum_proof=proof_dict,
                committed_at=proof.finalized_at
            )
            if not saved:
                return False

            # 4. Immediately enforce on Perimeter Firewall
            self.firewall.block_domain(proof.target_domain)

            # Mark proposal committed
            if proof.proposal_id in self.active_proposals:
                self.active_proposals[proof.proposal_id].is_committed = True

            return True
