import json
import logging
import time
from typing import Dict, List, Optional
from proto import fedconsensus_pb2 as pb2
from node.config import NodeConfig, peer_id_from_addr
from node.storage.database import Database
from node.ingress.firewall import FirewallFilter
from node.storage.reputation import ReputationManager
from node.crypto.ed25519 import verify_signature

logger = logging.getLogger("fedconsensus.catchup")


class CatchupEngine:
    """
    Self-Healing Catch-up and State Replay Engine (Phase 3).
    Allows crashed or newly joined nodes to query active peers for missed defederation 
    records and replay them locally after cryptographically verifying Quorum Certificates.
    """
    def __init__(
        self,
        config: NodeConfig,
        database: Database,
        firewall: FirewallFilter,
        peer_public_keys: Optional[Dict[str, str]] = None,
        reputation: Optional[ReputationManager] = None
    ):
        self.config = config
        self.db = database
        self.firewall = firewall
        self.reputation = reputation or ReputationManager(database)
        # peer_id -> {"reachable": bool, "checked_at": ms}, from the latest CatchupSync attempt
        self.peer_reachability: Dict[str, Dict] = {}
        self.peer_public_keys: Dict[str, str] = peer_public_keys or {
            **getattr(self.config, "known_peer_keys", {}),
            self.config.node_id: self.config.public_key_hex
        }

    def register_peer_key(self, peer_id: str, public_key_hex: str):
        """Registers or updates a known peer's public key for signature audit."""
        self.peer_public_keys[peer_id] = public_key_hex

    # -------------------------------------------------------------
    # 1. SERVING CATCH-UP (When an out-of-date peer asks US for history)
    # -------------------------------------------------------------
    def handle_catchup_request(self, req: pb2.CatchupRequest) -> pb2.CatchupResponse:
        """
        Queries local SQLite database for all committed bans starting from
        from_sequence_number and packs them into gRPC CommitRecord protobufs.
        """
        raw_records = self.db.get_commit_records(req.from_sequence_number)
        proto_records: List[pb2.CommitRecord] = []

        for r in raw_records:
            proof_dict = r["quorum_proof"]

            # Convert JSON signature list back to protobuf VoterSignature objects
            signatures = [
                pb2.VoterSignature(
                    voter_id=s["voter_id"],
                    signature=s["signature"],
                    timestamp=s.get("timestamp", 0)
                )
                for s in proof_dict.get("signatures", [])
            ]

            proto_proof = pb2.QuorumProof(
                proposal_id=proof_dict.get("proposal_id", ""),
                sequence_number=r["sequence_number"],
                epoch=r["epoch"],
                target_domain=r["target_domain"],
                reason=r["reason"],
                signatures=signatures,
                finalized_at=proof_dict.get("finalized_at", r["committed_at"])
            )

            proto_records.append(
                pb2.CommitRecord(
                    sequence_number=r["sequence_number"],
                    epoch=r["epoch"],
                    target_domain=r["target_domain"],
                    reason=r["reason"],
                    quorum_proof=proto_proof,
                    committed_at=r["committed_at"]
                )
            )

        return pb2.CatchupResponse(
            node_id=self.config.node_id,
            records=proto_records,
            latest_sequence_number=self.db.get_latest_sequence_number()
        )

    # -------------------------------------------------------------
    # 2. REPLAYING HISTORY (When WE wake up and receive records from a peer)
    # -------------------------------------------------------------
    def replay_records(self, records: List[pb2.CommitRecord]) -> int:
        """
        Audits incoming commit records from a peer:
        1. Checks that sequence numbers are new.
        2. Validates each signature in the Quorum Certificate against known public keys.
        3. Persists valid records to SQLite and loads them into RAM Firewall.
        Returns the number of successfully replayed records.
        """
        local_latest = self.db.get_latest_sequence_number()
        replayed_count = 0

        for rec in records:
            # Skip records we already have if domain is already blocked
            if rec.sequence_number <= local_latest and self.firewall.is_blocked(rec.target_domain):
                continue

            proof = rec.quorum_proof

            # Verify Quorum size threshold (Must have at least Q matching signatures)
            if len(proof.signatures) < self.config.quorum_size:
                logger.warning(
                    f"[Catchup] Insufficient signatures on seq {rec.sequence_number} "
                    f"({len(proof.signatures)} < {self.config.quorum_size}). Skipping."
                )
                continue

            # Cryptographically audit each signature in the proof
            valid_voters = set()
            for sig in proof.signatures:
                # Flaw 16: Check signer eligibility (quarantine check)
                if self.reputation and not self.reputation.is_peer_eligible_to_vote(sig.voter_id):
                    continue
                pubkey = self.peer_public_keys.get(sig.voter_id)
                if not pubkey:
                    continue

                # Expected metadata that was signed
                vote_meta = {
                    "proposal_id": proof.proposal_id,
                    "sequence_number": proof.sequence_number,
                    "epoch": proof.epoch,
                    "target_domain": proof.target_domain,
                    "decision": "APPROVE"
                }

                # Try verifying vote format or leader proposal format
                if verify_signature(pubkey, vote_meta, sig.signature):
                    valid_voters.add(sig.voter_id)
                else:
                    # Candidate threat score matching (including 1.0, Item 3)
                    for candidate_score in (1.0, 0.95, 0.92, 0.91, 0.90, 0.89, 0.88, 0.85, 0.80, 0.75, 0.70, 0.65, 0.60):
                        prop_meta = {
                            "proposal_id": proof.proposal_id,
                            "sequence_number": proof.sequence_number,
                            "epoch": proof.epoch,
                            "target_domain": proof.target_domain,
                            "reason": proof.reason,
                            "threat_score": round(candidate_score, 3)
                        }
                        if verify_signature(pubkey, prop_meta, sig.signature):
                            valid_voters.add(sig.voter_id)
                            break

            if len(valid_voters) < self.config.quorum_size:
                logger.warning(
                    f"[Catchup] Signature verification failed on seq {rec.sequence_number}. Rejecting."
                )
                continue

            # Proof is valid! Convert to dict for SQLite WAL persistence
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

            saved = self.db.save_commit_record(
                sequence_number=rec.sequence_number,
                epoch=rec.epoch,
                target_domain=rec.target_domain,
                reason=rec.reason,
                quorum_proof=proof_dict,
                committed_at=rec.committed_at
            )

            if saved:
                # Instantly enforce in RAM firewall
                self.firewall.block_domain(rec.target_domain)
                replayed_count += 1
                local_latest = max(local_latest, rec.sequence_number)
                logger.info(
                    f"[Catchup] Replayed seq {rec.sequence_number}: banned {rec.target_domain}"
                )

        return replayed_count

    def sync_with_consortium(self, consensus=None) -> int:
        """Queries online consortium peers via gRPC CatchupSync and replays any missed bans."""
        import grpc
        from proto import fedconsensus_pb2_grpc as pb2_grpc

        total_replayed = 0
        for peer_addr in self.config.peers:
            host = peer_addr.split(":")[0]
            node_name = host.split(".")[0]
            if node_name == self.config.node_id or (host in ("localhost", "127.0.0.1") and f":{self.config.grpc_port}" in peer_addr):
                continue
            peer_id = peer_id_from_addr(peer_addr)
            try:
                start_seq = self.db.get_latest_sequence_number() + 1
                with grpc.insecure_channel(peer_addr) as channel:
                    stub = pb2_grpc.FedConsensusServiceStub(channel)
                    req = pb2.CatchupRequest(
                        node_id=self.config.node_id,
                        from_sequence_number=start_seq
                    )
                    res = stub.CatchupSync(req, timeout=1.5)
                    self._mark_reachability(peer_id, True)
                    if res and res.records:
                        new_domains = [r.target_domain for r in res.records if not self.firewall.is_blocked(r.target_domain)]
                        count = self.replay_records(list(res.records))
                        if count > 0 and consensus is not None:
                            for rec in res.records:
                                if rec.target_domain in new_domains:
                                    consensus.commit_defederation(rec.quorum_proof)
                                    consensus.telemetry.record(
                                        "commit", self.config.node_id, "firewall",
                                        f"Self-healed missed ban via CatchupSync from {res.node_id}",
                                        proposal_id=rec.quorum_proof.proposal_id,
                                        domain=rec.target_domain,
                                    )
                        total_replayed += count

                    # Item 7: Sync peer reputation/quarantine status to eliminate epoch split-brain.
                    # Never copy a peer's view of this node, and only ever lower a local score.
                    try:
                        status_res = stub.GetStatus(pb2.StatusRequest(caller_id=self.config.node_id), timeout=1.0)
                        if status_res and status_res.reputations:
                            for rep_entry in status_res.reputations:
                                if rep_entry.peer_id == self.config.node_id:
                                    continue
                                if rep_entry.trust_score < 30 or not rep_entry.is_active:
                                    self.reputation.adopt_peer_view(rep_entry.peer_id, rep_entry.trust_score)
                    except Exception:
                        pass
            except Exception:
                self._mark_reachability(peer_id, False)
                continue
        return total_replayed

    def _mark_reachability(self, peer_id: str, reachable: bool):
        self.peer_reachability[peer_id] = {
            "reachable": reachable,
            "checked_at": int(time.time() * 1000),
        }