import time
import threading
import logging
from typing import Dict, Any, Optional

import grpc
from proto import fedconsensus_pb2 as pb2
from proto import fedconsensus_pb2_grpc as pb2_grpc

from node.config import NodeConfig
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.ingress.firewall import FirewallFilter
from node.engine.consensus import ConsensusEngine
from node.engine.leader import LeaderManager
from node.engine.catchup import CatchupEngine
from node.crypto.ed25519 import sign_message

logger = logging.getLogger("fedconsensus.service")


class FedConsensusService(pb2_grpc.FedConsensusServiceServicer):
    """
    gRPC Server Implementation for FedConsensus (Milestone 3.2).
    Binds the 7 cluster RPC operations and supports runtime Byzantine fault injection
    (NONE, SILENT, LIAR, FORGER).
    """
    def __init__(
        self,
        config: NodeConfig,
        database: Database,
        reputation: ReputationManager,
        firewall: FirewallFilter,
        consensus: ConsensusEngine,
        leader: LeaderManager,
        catchup: CatchupEngine
    ):
        self.config = config
        self.db = database
        self.reputation = reputation
        self.firewall = firewall
        self.consensus = consensus
        self.leader = leader
        self.catchup = catchup

        # Configurable fault mode: NONE, SILENT, LIAR, FORGER
        self.byzantine_mode = self.config.byzantine_mode

    def set_byzantine_mode(self, mode: str):
        """Allows dynamic fault injection from CLI or Dashboard (Phase 4)."""
        clean_mode = mode.upper().strip()
        logger.warning(f"[{self.config.node_id}] Switching Byzantine mode to: {clean_mode}")
        self.byzantine_mode = clean_mode

    # -------------------------------------------------------------
    # 1. ProposeDefederation (Phase 1 of BFT)
    # -------------------------------------------------------------
    def ProposeDefederation(self, request: pb2.ProposeRequest, context) -> pb2.ProposeResponse:
        # Byzantine SILENT: simulate dead/dropping node
        if self.byzantine_mode == "SILENT":
            context.abort(grpc.StatusCode.UNAVAILABLE, "Node is in SILENT Byzantine fault mode")

        logger.info(f"[{self.config.node_id}] Received proposal for: {request.target_domain}")

        # Follower audits the proposal
        accepted, reason, vote_req = self.consensus.handle_proposal(request)

        # Byzantine LIAR: refuse to vote for legitimate threats
        if self.byzantine_mode == "LIAR" and vote_req:
            logger.warning(f"[{self.config.node_id}] Byzantine LIAR injecting REJECT ballot!")
            vote_req.decision = pb2.VOTE_REJECT
            reject_meta = {
                "proposal_id": request.proposal_id,
                "sequence_number": request.sequence_number,
                "epoch": request.epoch,
                "target_domain": request.target_domain,
                "decision": "REJECT"
            }
            vote_req.voter_signature = sign_message(self.config.private_key_hex, reject_meta)
            with self.consensus._lock:
                prop_state = self.consensus.active_proposals.get(request.proposal_id)
                if prop_state:
                    prop_state.approved_votes.pop(self.config.node_id, None)
            self.consensus.telemetry.record(
                "vote", self.config.node_id, request.proposer_id,
                "Cast a dissenting REJECT ballot (Byzantine LIAR)",
                proposal_id=request.proposal_id, domain=request.target_domain,
                decision="REJECT",
            )

        # Byzantine FORGER: tamper with digital signature
        if self.byzantine_mode == "FORGER" and vote_req:
            logger.warning(f"[{self.config.node_id}] Byzantine FORGER corrupting ballot signature!")
            vote_req.voter_signature = "bad_signature_000000000000000000000000000000000000000000000000"
            with self.consensus._lock:
                prop_state = self.consensus.active_proposals.get(request.proposal_id)
                if prop_state:
                    prop_state.approved_votes.pop(self.config.node_id, None)
            self.consensus.telemetry.record(
                "invalid", self.config.node_id, request.proposer_id,
                "Injected forged ballot signature (Byzantine FORGER)",
                proposal_id=request.proposal_id, domain=request.target_domain,
                decision="INVALID",
            )

        # If proposal accepted and vote created, process locally
        if accepted and vote_req:
            proof = self.consensus.handle_vote(vote_req)
            if proof and self.consensus.commit_defederation(proof):
                self.consensus.telemetry.record(
                    "commit", self.config.node_id, "firewall",
                    f"Quorum certificate reached (Q={self.config.quorum_size}); committed ban",
                    domain=proof.target_domain,
                )
                commit_req = pb2.CommitRequest(
                    proposal_id=proof.proposal_id,
                    sequence_number=proof.sequence_number,
                    quorum_proof=proof
                )
                threading.Thread(
                    target=self._broadcast_commit,
                    args=(commit_req,),
                    daemon=True
                ).start()

            if request.proposer_id != self.config.node_id:
                threading.Thread(
                    target=self._send_vote_to_proposer,
                    args=(request.proposer_id, vote_req),
                    daemon=True
                ).start()

        return pb2.ProposeResponse(
            accepted=accepted,
            reason=reason,
            node_id=self.config.node_id
        )

    # -------------------------------------------------------------
    # 2. CastVote (Phase 2 of BFT)
    # -------------------------------------------------------------
    def CastVote(self, request: pb2.VoteRequest, context) -> pb2.VoteResponse:
        if self.byzantine_mode == "SILENT":
            context.abort(grpc.StatusCode.UNAVAILABLE, "Node is in SILENT Byzantine fault mode")

        proof = self.consensus.handle_vote(request)
        if proof:
            logger.info(f"[{self.config.node_id}] Quorum Certificate minted for {proof.target_domain}!")
            if self.consensus.commit_defederation(proof):
                self.consensus.telemetry.record(
                    "commit", self.config.node_id, "firewall",
                    f"Quorum certificate reached (Q={self.config.quorum_size}); committed ban",
                    domain=proof.target_domain,
                )
                commit_req = pb2.CommitRequest(
                    proposal_id=proof.proposal_id,
                    sequence_number=proof.sequence_number,
                    quorum_proof=proof
                )
                threading.Thread(
                    target=self._broadcast_commit,
                    args=(commit_req,),
                    daemon=True
                ).start()

        return pb2.VoteResponse(
            acknowledged=True,
            message="Vote registered successfully"
        )

    # -------------------------------------------------------------
    # 3. CommitDefederation (Phase 3 of BFT)
    # -------------------------------------------------------------
    def CommitDefederation(self, request: pb2.CommitRequest, context) -> pb2.CommitResponse:
        if self.byzantine_mode == "SILENT":
            context.abort(grpc.StatusCode.UNAVAILABLE, "Node is in SILENT Byzantine fault mode")

        success = self.consensus.commit_defederation(request.quorum_proof)
        return pb2.CommitResponse(
            committed=success,
            message="Committed to SQLite and Firewall" if success else "Commit rejected"
        )

    # -------------------------------------------------------------
    # 4. Heartbeat (Leader Lease Renewal)
    # -------------------------------------------------------------
    def Heartbeat(self, request: pb2.HeartbeatRequest, context) -> pb2.HeartbeatResponse:
        if self.byzantine_mode == "SILENT":
            context.abort(grpc.StatusCode.UNAVAILABLE, "Node is in SILENT Byzantine fault mode")

        leader_pubkey = self.consensus.peer_public_keys.get(request.leader_id, "")
        acknowledged, current_epoch = self.leader.handle_heartbeat(request, leader_pubkey)
        self.consensus.current_epoch = self.leader.current_epoch

        return pb2.HeartbeatResponse(
            acknowledged=acknowledged,
            current_epoch=current_epoch
        )

    # -------------------------------------------------------------
    # 5. ImpeachLeader (Anti-Censorship Emergency Election)
    # -------------------------------------------------------------
    def ImpeachLeader(self, request: pb2.ImpeachRequest, context) -> pb2.ImpeachResponse:
        if self.byzantine_mode == "SILENT":
            context.abort(grpc.StatusCode.UNAVAILABLE, "Node is in SILENT Byzantine fault mode")

        prev_epoch = self.leader.current_epoch
        accuser_pubkey = self.consensus.peer_public_keys.get(request.accuser_id, "")
        impeached = self.leader.handle_impeachment(request, accuser_pubkey)
        self.consensus.current_epoch = self.leader.current_epoch
        if impeached and self.leader.current_epoch > prev_epoch:
            new_leader = self.leader.get_leader_for_epoch(self.leader.current_epoch)
            self.consensus.telemetry.record(
                "message", self.config.node_id, new_leader,
                f"Leader {request.leader_id} impeached; elected {new_leader} for Epoch {self.leader.current_epoch}",
            )

        return pb2.ImpeachResponse(
            vote_impeach=impeached,
            voter_id=self.config.node_id
        )

    # -------------------------------------------------------------
    # 6. CatchupSync (State Recovery & Self-Healing)
    # -------------------------------------------------------------
    def CatchupSync(self, request: pb2.CatchupRequest, context) -> pb2.CatchupResponse:
        if self.byzantine_mode == "SILENT":
            context.abort(grpc.StatusCode.UNAVAILABLE, "Node is in SILENT Byzantine fault mode")

        return self.catchup.handle_catchup_request(request)

    # -------------------------------------------------------------
    # 7. GetStatus (Telemetry for Dashboard & CLI)
    # -------------------------------------------------------------
    def GetStatus(self, request: pb2.StatusRequest, context) -> pb2.StatusResponse:
        # Determine current node state
        if self.byzantine_mode != "NONE":
            state_str = f"BYZANTINE_{self.byzantine_mode}"
        elif self.leader.is_current_leader():
            state_str = "LEADER"
        else:
            state_str = "FOLLOWER"

        # Build reputation list
        rep_entries = []
        for r in self.reputation.get_ledger():
            rep_entries.append(
                pb2.PeerReputationEntry(
                    peer_id=r["peer_id"],
                    trust_score=r["trust_score"],
                    is_active=bool(r["is_active"]),
                    violations_count=r["violations_count"]
                )
            )

        return pb2.StatusResponse(
            node_id=self.config.node_id,
            state=state_str,
            current_epoch=self.leader.current_epoch,
            last_committed_seq=self.db.get_latest_sequence_number(),
            blocked_domains_count=self.firewall.count(),
            reputations=rep_entries,
            operational_mode=self.config.operational_mode
        )

    # -------------------------------------------------------------
    # Helper Network Methods for Consensus Automation
    # -------------------------------------------------------------
    def _is_self_peer(self, peer_addr: str) -> bool:
        host = peer_addr.split(":")[0]
        if host == self.config.node_id:
            return True
        if host in ("localhost", "127.0.0.1") and f":{self.config.grpc_port}" in peer_addr:
            return True
        return False

    def _find_peer_address(self, peer_id: str) -> Optional[str]:
        for addr in self.config.peers:
            host = addr.split(":")[0]
            if host == peer_id:
                return addr
        if peer_id.startswith("fednode-"):
            try:
                idx = int(peer_id.split("-")[1])
                target_port = 50051 + idx
                for addr in self.config.peers:
                    if f":{target_port}" in addr:
                        return addr
            except Exception:
                pass
        return None

    def _send_vote_to_proposer(self, proposer_id: str, vote_req: pb2.VoteRequest):
        addr = self._find_peer_address(proposer_id)
        if not addr:
            logger.warning(f"[{self.config.node_id}] Could not find address for proposer {proposer_id}")
            return
        try:
            with grpc.insecure_channel(addr) as channel:
                stub = pb2_grpc.FedConsensusServiceStub(channel)
                self.consensus.telemetry.record(
                    "vote", self.config.node_id, addr, "Transmitting vote to proposer",
                    proposal_id=vote_req.proposal_id, decision="APPROVE" if vote_req.decision == pb2.VOTE_APPROVE else "REJECT"
                )
                stub.CastVote(vote_req, timeout=2.0)
                logger.info(f"[{self.config.node_id}] Successfully sent vote to proposer {proposer_id} at {addr}")
        except Exception as e:
            logger.warning(f"[{self.config.node_id}] Failed to send vote to proposer {proposer_id} at {addr}: {e}")

    def _broadcast_commit(self, commit_req: pb2.CommitRequest):
        for peer_addr in self.config.peers:
            if self._is_self_peer(peer_addr):
                continue
            try:
                with grpc.insecure_channel(peer_addr) as channel:
                    stub = pb2_grpc.FedConsensusServiceStub(channel)
                    stub.CommitDefederation(commit_req, timeout=2.0)
                    logger.info(f"[{self.config.node_id}] Broadcasted commit to {peer_addr}")
            except Exception as e:
                logger.debug(f"[{self.config.node_id}] Failed to broadcast commit to {peer_addr}: {e}")
