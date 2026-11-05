import os
import sys
import time
import json
import logging
import signal
import threading
from concurrent import futures
from http.server import HTTPServer, BaseHTTPRequestHandler
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

    def do_GET(self):
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
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            try:
                req_json = json.loads(post_data) if post_data else {}
            except Exception:
                req_json = {}
            mode = req_json.get("mode", "NONE").upper().strip()
            if self.service:
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
        self.catchup = CatchupEngine(self.config, self.db, self.firewall)

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

    def on_threat_detected(self, domain: str, payload: dict, assessment: ThreatAssessment):
        """Callback: Automatically escalated when incoming post crosses threat score >= 0.60."""
        logger.warning(
            f"[{self.config.node_id}] Escalating attack to consensus! Target: {domain} "
            f"(Score: {assessment.score}, Reasons: {assessment.reasons})"
        )
        # Create Phase 1 Proposal
        prop_req = self.consensus.create_proposal(
            target_domain=domain,
            reason=assessment.dominant_reason_code,
            evidence_payload=json.dumps(payload),
            origin_http_signature="",
            threat_score=assessment.score
        )
        # Broadcast proposal in background thread to avoid blocking HTTP worker
        threading.Thread(target=self._broadcast_proposal, args=(prop_req,), daemon=True).start()

    def _is_self_peer(self, peer_addr: str) -> bool:
        host = peer_addr.split(":")[0]
        if host == self.config.node_id:
            return True
        if host in ("localhost", "127.0.0.1") and f":{self.config.grpc_port}" in peer_addr:
            return True
        return False

    def _broadcast_proposal(self, prop_req: pb2.ProposeRequest):
        """Broadcasts proposal to all consortium peers via gRPC."""
        for peer_addr in self.config.peers:
            if self._is_self_peer(peer_addr):
                continue  # Skip self
            try:
                channel = grpc.insecure_channel(peer_addr)
                stub = pb2_grpc.FedConsensusServiceStub(channel)
                self.consensus.telemetry.record(
                    "proposal", self.config.node_id, peer_addr, "Sending block proposal",
                    proposal_id=prop_req.proposal_id, domain=prop_req.target_domain,
                )
                res = stub.ProposeDefederation(prop_req, timeout=1.0)
                if res.accepted:
                    logger.info(f"[{self.config.node_id}] Peer {peer_addr} accepted proposal")
            except Exception:
                pass  # Peer might be down or not started yet

    def _heartbeat_loop(self):
        """Background thread: Leader sends heartbeat every 2 seconds to renew lease."""
        while self.running:
            time.sleep(2.0)
            if self.leader.is_current_leader():
                hb = self.leader.generate_heartbeat()
                for peer_addr in self.config.peers:
                    if self._is_self_peer(peer_addr):
                        continue
                    try:
                        channel = grpc.insecure_channel(peer_addr)
                        stub = pb2_grpc.FedConsensusServiceStub(channel)
                        stub.Heartbeat(hb, timeout=0.8)
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

        # 2. Start HTTP External Ingress Server
        ActivityPubHTTPHandler.inbox = self.inbox
        ActivityPubHTTPHandler.service = self.service
        self.http_server = HTTPServer(("0.0.0.0", self.config.http_port), ActivityPubHTTPHandler)
        http_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
        http_thread.start()
        logger.info(f"ActivityPub HTTP /inbox listening on http://0.0.0.0:{self.config.http_port}")

        # 3. Start Leader Heartbeat loop
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

    def stop(self):
        """Graceful shutdown handler."""
        self.running = False
        if self.http_server:
            self.http_server.shutdown()
        if self.grpc_server:
            self.grpc_server.stop(grace=1.0)
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
