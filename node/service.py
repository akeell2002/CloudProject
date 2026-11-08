import time
import threading
from concurrent.futures import ThreadPoolExecutor
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
import json
from node.crypto.ed25519 import sign_message, verify_signature

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

        # Configurable fault mode: NONE, SILENT, LIAR, FORGER, EQUIVOCATOR, CENSOR
        self.byzantine_mode = self.config.byzantine_mode
        self._channels: Dict[str, grpc.Channel] = {}
        self._stubs: Dict[str, pb2_grpc.FedConsensusServiceStub] = {}
        self._channel_lock = threading.Lock()
        self._rpc_executor = ThreadPoolExecutor(max_workers=16)

    def _get_stub(self, peer_addr: str) -> pb2_grpc.FedConsensusServiceStub:
        with self._channel_lock:
            if peer_addr not in self._stubs:
                channel = grpc.insecure_channel(peer_addr)
                self._channels[peer_addr] = channel
                self._stubs[peer_addr] = pb2_grpc.FedConsensusServiceStub(channel)
            return self._stubs[peer_addr]

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

        # Flaw 3: Byzantine CENSOR mode: leader drops proposals
        if self.byzantine_mode == "CENSOR":
            logger.warning(f"[{self.config.node_id}] Byzantine CENSOR ignoring proposal for {request.target_domain}!")
            return pb2.ProposeResponse(accepted=False, reason="Node is in CENSOR mode", node_id=self.config.node_id)

        logger.info(f"[{self.config.node_id}] Received proposal for: {request.target_domain}")

        # Follower-to-Leader threat escalation:
        # When active Epoch Leader receives a proposal/threat report from a follower peer
        if self.leader.is_current_leader() and request.proposer_id != self.config.node_id:
            reporter_id = request.proposer_id
            reporter_pubkey = self.consensus.peer_public_keys.get(reporter_id) or self.config.known_peer_keys.get(reporter_id)
            if reporter_id != "operator-fedctl" and not reporter_pubkey:
                return pb2.ProposeResponse(
                    accepted=False,
                    reason=f"Proposal rejected: {reporter_id} is not an authorized consortium peer",
                    node_id=self.config.node_id
                )

            # Verify reporter signature
            vote_meta = {
                "proposal_id": request.proposal_id,
                "sequence_number": request.sequence_number,
                "epoch": request.epoch,
                "target_domain": request.target_domain,
                "decision": "APPROVE"
            }
            sign_meta = {
                "proposal_id": request.proposal_id,
                "sequence_number": request.sequence_number,
                "epoch": request.epoch,
                "target_domain": request.target_domain,
                "reason": request.reason,
                "threat_score": round(request.threat_score, 3)
            }
            is_valid_sig = False
            if reporter_id == "operator-fedctl":
                is_valid_sig = True
            elif reporter_pubkey:
                if verify_signature(reporter_pubkey, vote_meta, request.proposer_signature):
                    is_valid_sig = True
                elif verify_signature(reporter_pubkey, sign_meta, request.proposer_signature):
                    is_valid_sig = True

            if not is_valid_sig:
                self.reputation.penalize_forgery(reporter_id)
                return pb2.ProposeResponse(
                    accepted=False,
                    reason="Proposal rejected: Invalid reporter signature",
                    node_id=self.config.node_id
                )

            # Verify threat threshold
            if request.threat_score < 0.60:
                return pb2.ProposeResponse(
                    accepted=False,
                    reason=f"Threat score {request.threat_score} is below threshold 0.60",
                    node_id=self.config.node_id
                )

            # Botnet burst audit
            if request.reason == pb2.REASON_BOTNET:
                burst_proven = False
                if request.evidence_payload:
                    try:
                        ev = json.loads(request.evidence_payload)
                        if ev.get("burst_count", 0) >= 5:
                            burst_proven = True
                    except Exception:
                        pass
                if not burst_proven and request.threat_score < 0.60:
                    return pb2.ProposeResponse(
                        accepted=False,
                        reason="Botnet claim rejected: Insufficient burst evidence",
                        node_id=self.config.node_id
                    )

            if self.firewall.is_blocked(request.target_domain):
                return pb2.ProposeResponse(
                    accepted=True,
                    reason="Domain already defederated",
                    node_id=self.config.node_id
                )

            with self.consensus._lock:
                existing_prop = next((p for p in self.consensus.active_proposals.values() if p.target_domain == request.target_domain and not p.is_committed), None)
            if existing_prop and existing_prop.request:
                return pb2.ProposeResponse(
                    accepted=True,
                    reason="Proposal already in progress",
                    node_id=self.config.node_id
                )

            # Leader adopts the threat: creates and broadcasts the leader proposal
            leader_prop = self.consensus.create_proposal(
                target_domain=request.target_domain,
                reason=request.reason,
                evidence_payload=request.evidence_payload,
                origin_http_signature=request.origin_http_signature,
                threat_score=request.threat_score
            )
            self.leader.clear_censorship_watch(request.target_domain)
            threading.Thread(
                target=self._broadcast_proposal,
                args=(leader_prop,),
                daemon=True
            ).start()
            return pb2.ProposeResponse(
                accepted=True,
                reason="Leader accepted threat report and broadcasted proposal",
                node_id=self.config.node_id
            )

        # Follower audits the proposal
        accepted, reason, vote_req = self.consensus.handle_proposal(request)
        if accepted:
            self.leader.clear_censorship_watch(request.target_domain)

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

        # Flaw 9: Byzantine EQUIVOCATOR: send conflicting ballots
        if self.byzantine_mode == "EQUIVOCATOR" and vote_req:
            logger.warning(f"[{self.config.node_id}] Byzantine EQUIVOCATOR sending conflicting ballots!")
            reject_vote = pb2.VoteRequest(
                proposal_id=request.proposal_id,
                sequence_number=request.sequence_number,
                epoch=request.epoch,
                target_domain=request.target_domain,
                voter_id=self.config.node_id,
                decision=pb2.VOTE_REJECT,
                voter_signature=sign_message(self.config.private_key_hex, {
                    "proposal_id": request.proposal_id,
                    "sequence_number": request.sequence_number,
                    "epoch": request.epoch,
                    "target_domain": request.target_domain,
                    "decision": "REJECT"
                }),
                timestamp=int(time.time() * 1000)
            )
            if request.proposer_id != self.config.node_id:
                threading.Thread(
                    target=lambda: (self._send_vote_to_proposer(request.proposer_id, vote_req),
                                   self._send_vote_to_proposer(request.proposer_id, reject_vote)),
                    daemon=True
                ).start()

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
        if success:
            self.leader.clear_censorship_watch(request.quorum_proof.target_domain)
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
        node_name = host.split(".")[0]
        if node_name == self.config.node_id:
            return True
        if host in ("localhost", "127.0.0.1") and f":{self.config.grpc_port}" in peer_addr:
            return True
        return False

    def _find_peer_address(self, peer_id: str) -> Optional[str]:
        for addr in self.config.peers:
            host = addr.split(":")[0]
            node_name = host.split(".")[0]
            if node_name == peer_id:
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
            stub = self._get_stub(addr)
            self.consensus.telemetry.record(
                "vote", self.config.node_id, addr, "Transmitting vote to proposer",
                proposal_id=vote_req.proposal_id, decision="APPROVE" if vote_req.decision == pb2.VOTE_APPROVE else "REJECT"
            )
            stub.CastVote(vote_req, timeout=2.0)
            logger.info(f"[{self.config.node_id}] Successfully sent vote to proposer {proposer_id} at {addr}")
        except Exception as e:
            logger.warning(f"[{self.config.node_id}] Failed to send vote to proposer {proposer_id} at {addr}: {e}")

    def _broadcast_proposal(self, prop_req: pb2.ProposeRequest):
        targets = [p for p in self.config.peers if not self._is_self_peer(p)]
        def _send(peer_addr):
            try:
                stub = self._get_stub(peer_addr)
                self.consensus.telemetry.record(
                    "proposal", self.config.node_id, peer_addr, "Sending block proposal",
                    proposal_id=prop_req.proposal_id, domain=prop_req.target_domain,
                )
                res = stub.ProposeDefederation(prop_req, timeout=1.5)
                if res and res.accepted:
                    logger.info(f"[{self.config.node_id}] Peer {peer_addr} accepted proposal")
            except Exception as e:
                logger.debug(f"[{self.config.node_id}] Failed to send proposal to {peer_addr}: {e}")
        list(self._rpc_executor.map(_send, targets))

    def _broadcast_commit(self, commit_req: pb2.CommitRequest):
        targets = [p for p in self.config.peers if not self._is_self_peer(p)]
        def _send(peer_addr):
            try:
                stub = self._get_stub(peer_addr)
                stub.CommitDefederation(commit_req, timeout=1.5)
                logger.info(f"[{self.config.node_id}] Broadcasted commit to {peer_addr}")
            except Exception as e:
                logger.debug(f"[{self.config.node_id}] Failed to broadcast commit to {peer_addr}: {e}")
        list(self._rpc_executor.map(_send, targets))
