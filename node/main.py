import os
import sys
import time
import json
import logging
import signal
import threading
from concurrent import futures
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import List, Optional

import grpc
from proto import fedconsensus_pb2 as pb2
from proto import fedconsensus_pb2_grpc as pb2_grpc

from node.config import NodeConfig
from node.storage.database import Database
from node.storage.reputation import ReputationManager
from node.ingress.firewall import FirewallFilter
from node.ingress.classifier import ThreatClassifier, ThreatAssessment
from node.ingress.activitypub import ActivityPubInbox
from node.engine.consensus import ConsensusEngine
from node.engine.leader import LeaderManager
from node.engine.catchup import CatchupEngine
from node.service import FedConsensusService
from node.telemetry import node_snapshot

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("fedconsensus.main")


class ActivityPubHTTPHandler(BaseHTTPRequestHandler):
    """Handles external ActivityPub POST /inbox and GET /health requests."""
    inbox: Optional[ActivityPubInbox] = None
    service: Optional[FedConsensusService] = None

    def _is_internal_operator(self) -> bool:
        client_ip = str(self.client_address[0]) if self.client_address else ""
        return (
            client_ip in ("127.0.0.1", "::1", "localhost")
            or client_ip.startswith(("10.", "172.", "192.168."))
        )

    def do_GET(self):
        if self.service and getattr(self.service, "simulated_offline", False):
            self.send_response(503)
            self.end_headers()
            return
        if self.path == "/telemetry":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(json.dumps(node_snapshot(self.service)).encode("utf-8"))
        elif self.path in ("/health", "/status"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            status_data = {
                "status": "HEALTHY",
                "node_id": self.service.config.node_id if self.service else "unknown",
                "blocked_domains": self.service.firewall.count() if self.service else 0
            }
            self.wfile.write(json.dumps(status_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/inbox":
            if self.service and getattr(self.service, "simulated_offline", False):
                self.send_response(503)
                self.end_headers()
                return
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")

            status_code, response_json = self.inbox.process_inbox_post(post_data)
            if self.service:
                kind = {
                    "FLAGGED_FOR_CONSENSUS": "threat", "BLOCKED": "blocked",
                }.get(response_json.get("status"), "message")
                self.service.consensus.telemetry.record(
                    kind, response_json.get("domain", "unknown"),
                    self.service.config.node_id,
                    "; ".join(response_json.get("reasons", []))
                    or response_json.get("message", response_json.get("error", "Post received")),
                    domain=response_json.get("domain", ""),
                    score=response_json.get("threat_score"),
                    status=response_json.get("status", "INVALID"),
                )

            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_json).encode("utf-8"))
        elif self.path == "/fault":
            if not self._is_internal_operator():
                self.send_response(403)
                self.end_headers()
                return
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            try:
                req_json = json.loads(post_data) if post_data else {}
            except Exception:
                req_json = {}
            mode = req_json.get("mode", "NONE").upper().strip()
            offline = req_json.get("offline")
            if self.service:
                if offline is True:
                    self.service.simulated_offline = True
                    self.service.set_byzantine_mode("SILENT")
                elif offline is False:
                    self.service.simulated_offline = False
                    self.service.set_byzantine_mode(mode)
                    if self.service.catchup:
                        threading.Thread(
                            target=self.service.catchup.sync_with_consortium,
                            args=(self.service.consensus,),
                            daemon=True
                        ).start()
                else:
                    self.service.set_byzantine_mode(mode)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "OK",
                "node_id": self.service.config.node_id if self.service else "unknown",
                "byzantine_mode": self.service.byzantine_mode if self.service else mode
            }).encode("utf-8"))
        elif self.path == "/reputation":
            if not self._is_internal_operator():
                self.send_response(403)
                self.end_headers()
                return
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            try:
                req_json = json.loads(post_data) if post_data else {}
            except Exception:
                req_json = {}
            peer_id = req_json.get("peer_id", "")
            score = int(req_json.get("score", 100))
            if self.service and peer_id:
                self.service.db.set_reputation(peer_id, score)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "OK",
                "peer_id": peer_id,
                "score": score
            }).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress normal HTTP logging to keep console clean
        return


class FedNodeRunner:
    """Manages the lifecycle of gRPC mesh, HTTP ingress, and background consensus routines."""
    def __init__(self):
        self.config = NodeConfig()
        logger.info(f"Initializing FedNode: {self.config.node_id} (Data dir: {self.config.data_dir})")

        # Storage & Ingress
        self.db = Database(self.config.db_path)
        self.reputation = ReputationManager(self.db)
        self.firewall = FirewallFilter(self.db)
        self.classifier = ThreatClassifier()

        # Engines
        self.consensus = ConsensusEngine(self.config, self.db, self.firewall, self.reputation)
        self.leader = LeaderManager(self.config, self.reputation)
        self.catchup = CatchupEngine(self.config, self.db, self.firewall, self.consensus.peer_public_keys, self.reputation)

        # Wire ActivityPub Ingress to automated consensus proposal
        self.inbox = ActivityPubInbox(
            firewall=self.firewall,
            classifier=self.classifier,
            on_threat_detected=self.on_threat_detected
        )

        # gRPC Service binding
        self.service = FedConsensusService(
            config=self.config,
            database=self.db,
            reputation=self.reputation,
            firewall=self.firewall,
            consensus=self.consensus,
            leader=self.leader,
            catchup=self.catchup
        )

        self.grpc_server: Optional[grpc.Server] = None
        self.http_server: Optional[HTTPServer] = None
        self.running = False
        self._channels: dict = {}
        self._stubs: dict = {}
        self._channel_lock = threading.Lock()
        self._rpc_executor = futures.ThreadPoolExecutor(max_workers=16)

    def _get_stub(self, peer_addr: str) -> pb2_grpc.FedConsensusServiceStub:
        with self._channel_lock:
            if peer_addr not in self._stubs:
                channel = grpc.insecure_channel(peer_addr)
                self._channels[peer_addr] = channel
                self._stubs[peer_addr] = pb2_grpc.FedConsensusServiceStub(channel)
            return self._stubs[peer_addr]

    def on_threat_detected(self, domain: str, payload: dict, assessment: ThreatAssessment):
        """Callback: Automatically escalated when incoming post crosses threat score >= 0.60."""
        logger.warning(
            f"[{self.config.node_id}] Escalating attack to consensus! Target: {domain} "
            f"(Score: {assessment.score}, Reasons: {assessment.reasons})"
        )
        # Flaw 3: Byzantine CENSOR check
        if getattr(self.service, "byzantine_mode", "") == "CENSOR":
            logger.warning(f"[{self.config.node_id}] Leader is in CENSOR Byzantine mode; dropping proposal for {domain}!")
            return

        # Flaw 5: Extract or generate authentic origin_http_signature
        origin_sig = payload.get("origin_http_signature", "")
        if isinstance(origin_sig, dict):
            origin_sig_str = json.dumps(origin_sig)
        elif isinstance(origin_sig, str) and origin_sig:
            origin_sig_str = origin_sig
        else:
            from node.crypto.ed25519 import generate_deterministic_keypair
            from node.crypto.http_sig import create_origin_http_signature
            domain_privkey, _ = generate_deterministic_keypair(f"origin-domain-{domain}")
            sig_dict = create_origin_http_signature(domain, payload, domain_privkey)
            origin_sig_str = json.dumps(sig_dict)

        # Flaw 2 & Patch A1: Check if this node is current Epoch Leader
        if self.leader.is_current_leader():
            prop_req = self.consensus.create_proposal(
                target_domain=domain,
                reason=assessment.dominant_reason_code,
                evidence_payload=json.dumps(payload),
                origin_http_signature=origin_sig_str,
                threat_score=assessment.score
            )
            threading.Thread(target=self._broadcast_proposal, args=(prop_req,), daemon=True).start()
        else:
            # Follower starts 3.0s censorship watch AND forwards threat to Leader
            self.leader.watch_censorship(domain, payload, assessment)
            if domain in self.leader.censorship_watches:
                self.leader.censorship_watches[domain]["origin_sig_str"] = origin_sig_str
            threading.Thread(
                target=self._forward_threat_to_leader,
                args=(domain, payload, origin_sig_str, assessment),
                daemon=True
            ).start()

    def _forward_threat_to_leader(self, domain: str, payload: dict, origin_sig_str: str, assessment: ThreatAssessment):
        """Forwards a follower-detected threat to the current Epoch Leader, or proposes to peers while watching for censorship."""
        expected_leader = self.leader.get_leader_for_epoch(self.leader.current_epoch)
        leader_addr = self.service._find_peer_address(expected_leader)
        prop_req = self.consensus.create_proposal(
            target_domain=domain,
            reason=assessment.dominant_reason_code,
            evidence_payload=json.dumps(payload),
            origin_http_signature=origin_sig_str,
            threat_score=assessment.score
        )
        if leader_addr and not self._is_self_peer(leader_addr):
            try:
                self.consensus.telemetry.record(
                    "proposal", self.config.node_id, leader_addr, "Forwarding block proposal to leader",
                    proposal_id=prop_req.proposal_id, domain=prop_req.target_domain,
                )
                res = self._get_stub(leader_addr).ProposeDefederation(prop_req, timeout=1.0)
                if res.accepted:
                    self.leader.clear_censorship_watch(domain)
                    self._broadcast_proposal(prop_req, exclude_addr=leader_addr)
                    return
            except Exception:
                pass
        # If Leader is in CENSOR mode (accepted=False) or SILENT/unreachable, watch_censorship will impeach in 3s
        # while still broadcasting proposal to remaining honest peers so quorum can form:
        self._broadcast_proposal(prop_req, exclude_addr=leader_addr)

    def _is_self_peer(self, peer_addr: str) -> bool:
        host = peer_addr.split(":")[0]
        node_name = host.split(".")[0]
        if node_name == self.config.node_id:
            return True
        if host in ("localhost", "127.0.0.1") and f":{self.config.grpc_port}" in peer_addr:
            return True
        return False

    def _broadcast_proposal(self, prop_req: pb2.ProposeRequest, exclude_addr: Optional[str] = None):
        """Broadcasts proposal to all consortium peers via gRPC in parallel."""
        targets = [p for p in self.config.peers if not self._is_self_peer(p) and p != exclude_addr]
        def _send(peer_addr):
            try:
                stub = self._get_stub(peer_addr)
                self.consensus.telemetry.record(
                    "proposal", self.config.node_id, peer_addr, "Sending block proposal",
                    proposal_id=prop_req.proposal_id, domain=prop_req.target_domain,
                )
                res = stub.ProposeDefederation(prop_req, timeout=1.5)
                if res.accepted:
                    logger.info(f"[{self.config.node_id}] Peer {peer_addr} accepted proposal")
            except Exception:
                pass
        list(self._rpc_executor.map(_send, targets))

    def _heartbeat_loop(self):
        """Background thread: Leader heartbeats, lease failover election, pending proposal retry, and catchup sync."""
        tick = 0
        while self.running:
            time.sleep(2.0)
            tick += 1
            if getattr(self.service, "simulated_offline", False) or self.service.byzantine_mode == "SILENT":
                continue

            expected_leader = self.leader.get_leader_for_epoch(self.leader.current_epoch)
            if expected_leader == self.config.node_id:
                hb = self.leader.generate_heartbeat()
                self.consensus.current_epoch = self.leader.current_epoch
                targets = [p for p in self.config.peers if not self._is_self_peer(p)]
                def _send_hb(p_addr):
                    try:
                        self._get_stub(p_addr).Heartbeat(hb, timeout=0.8)
                    except Exception:
                        pass
                list(self._rpc_executor.map(_send_hb, targets))
            elif time.time() > self.leader.lease_expires_at:
                # Leader lease expired -> trigger emergency impeachment & failover election
                imp_req = self.leader.create_impeachment_request(
                    justification=f"Leader {expected_leader} heartbeat lease expired"
                )
                prev_epoch = self.leader.current_epoch
                self.leader.handle_impeachment(imp_req, self.config.public_key_hex)
                self.consensus.current_epoch = self.leader.current_epoch
                targets = [p for p in self.config.peers if not self._is_self_peer(p)]
                def _send_imp(p_addr):
                    try:
                        res = self._get_stub(p_addr).ImpeachLeader(imp_req, timeout=0.8)
                        if res and res.vote_impeach and res.voter_id:
                            if self.leader.record_impeachment_vote(imp_req.target_epoch, imp_req.leader_id, res.voter_id):
                                self.consensus.current_epoch = self.leader.current_epoch
                    except Exception:
                        pass
                list(self._rpc_executor.map(_send_imp, targets))
                if self.leader.current_epoch > prev_epoch:
                    new_leader = self.leader.get_leader_for_epoch(self.leader.current_epoch)
                    self.consensus.telemetry.record(
                        "message", self.config.node_id, new_leader,
                        f"Leader {expected_leader} impeached; elected {new_leader} for Epoch {self.leader.current_epoch}",
                    )

            # Flaw 3 & Flaw 14: Check expired censorship watches
            expired_watches = self.leader.get_expired_censorship_watches()
            for censored_domain, info in expired_watches:
                logger.warning(f"[{self.config.node_id}] Leader censored attack on {censored_domain} > 3s! Impeaching.")
                imp_req = self.leader.create_impeachment_request(
                    justification=f"Leader {expected_leader} censored attack on {censored_domain}"
                )
                prev_epoch = self.leader.current_epoch
                self.leader.handle_impeachment(imp_req, self.config.public_key_hex)
                self.consensus.current_epoch = self.leader.current_epoch
                targets = [p for p in self.config.peers if not self._is_self_peer(p)]
                def _send_censor_imp(p_addr):
                    try:
                        res = self._get_stub(p_addr).ImpeachLeader(imp_req, timeout=0.8)
                        if res and res.vote_impeach and res.voter_id:
                            if self.leader.record_impeachment_vote(imp_req.target_epoch, imp_req.leader_id, res.voter_id):
                                self.consensus.current_epoch = self.leader.current_epoch
                    except Exception:
                        pass
                list(self._rpc_executor.map(_send_censor_imp, targets))
                if self.leader.current_epoch > prev_epoch:
                    new_leader = self.leader.get_leader_for_epoch(self.leader.current_epoch)
                    self.consensus.telemetry.record(
                        "message", self.config.node_id, new_leader,
                        f"Leader {expected_leader} impeached for censorship; elected {new_leader} for Epoch {self.leader.current_epoch}",
                    )
                if self.leader.is_current_leader() and not self.firewall.is_blocked(censored_domain):
                    censor_origin_sig = info.get("origin_sig_str", "") or info["payload"].get("origin_http_signature", "")
                    if isinstance(censor_origin_sig, dict):
                        censor_origin_sig = json.dumps(censor_origin_sig)
                    prop_req = self.consensus.create_proposal(
                        target_domain=censored_domain,
                        reason=info["assessment"].dominant_reason_code,
                        evidence_payload=json.dumps(info["payload"]),
                        origin_http_signature=str(censor_origin_sig),
                        threat_score=info["assessment"].score
                    )
                    threading.Thread(target=self._broadcast_proposal, args=(prop_req,), daemon=True).start()

            # Retry pending uncommitted proposals (heals 2-nodes-down partitions once a peer revives)
            with self.consensus._lock:
                pending = [
                    p for p in self.consensus.active_proposals.values()
                    if not p.is_committed and p.request is not None and p.request.proposer_id == self.config.node_id
                ]
            for prop in pending:
                for peer_addr in self.config.peers:
                    if self._is_self_peer(peer_addr):
                        continue
                    peer_host = peer_addr.split(":")[0]
                    if peer_host in prop.approved_votes:
                        continue
                    try:
                        self._get_stub(peer_addr).ProposeDefederation(prop.request, timeout=0.8)
                    except Exception:
                        pass

            # Periodic self-healing catchup sync every 2 ticks (~4s)
            if tick % 2 == 0 and self.catchup:
                try:
                    self.catchup.sync_with_consortium(self.consensus)
                except Exception:
                    pass

    def start(self):
        """Starts both gRPC and HTTP servers concurrently."""
        self.running = True

        # 1. Start gRPC Internal Mesh Server
        self.grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        pb2_grpc.add_FedConsensusServiceServicer_to_server(self.service, self.grpc_server)
        grpc_addr = f"0.0.0.0:{self.config.grpc_port}"
        self.grpc_server.add_insecure_port(grpc_addr)
        self.grpc_server.start()
        logger.info(f"Consortium gRPC mesh listening on {grpc_addr}")

        # 2. Start HTTP External Ingress Server (multi-threaded so /inbox never blocks /health)
        ActivityPubHTTPHandler.inbox = self.inbox
        ActivityPubHTTPHandler.service = self.service
        self.http_server = ThreadingHTTPServer(("0.0.0.0", self.config.http_port), ActivityPubHTTPHandler)
        http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
        http_thread.start()
        logger.info(f"ActivityPub HTTP /inbox listening on http://0.0.0.0:{self.config.http_port}")

        # 3. Start Leader Heartbeat & Self-Healing loop
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

    def stop(self):
        """Graceful shutdown handler."""
        self.running = False
        if self.http_server:
            self.http_server.shutdown()
        if self.grpc_server:
            self.grpc_server.stop(grace=1.0)
        for ch in self._channels.values():
            try:
                ch.close()
            except Exception:
                pass
        self._rpc_executor.shutdown(wait=False)
        logger.info("FedNode servers stopped cleanly.")


def main():
    runner = FedNodeRunner()
    runner.start()

    def handle_signal(sig, frame):
        logger.info("Received termination signal. Shutting down...")
        runner.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    logger.info("FedNode operational. Press Ctrl+C to exit.")
    while runner.running:
        time.sleep(1.0)


if __name__ == "__main__":
    main()
