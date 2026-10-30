import os
import json
from typing import List, Dict
from node.crypto.ed25519 import generate_keypair


class NodeConfig:
    """
    Central Configuration for a FedConsensus node.
    Manages persistent cryptographic identity, networking topology,
    and BFT quorum thresholds.
    """
    def __init__(self):
        self.node_id = os.getenv("NODE_ID", "fednode-1")
        self.grpc_port = int(os.getenv("GRPC_PORT", "50051"))
        self.http_port = int(os.getenv("HTTP_PORT", "8080"))
        self.data_dir = os.getenv("DATA_DIR", os.path.join(".", "data", self.node_id))
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "wal.db")

        # 1. Persistent Cryptographic Identity
        key_file = os.path.join(self.data_dir, "node_identity.json")
        if os.path.exists(key_file):
            with open(key_file, "r") as f:
                data = json.load(f)
                self.private_key_hex = data["private_key"]
                self.public_key_hex = data["public_key"]
        else:
            self.private_key_hex, self.public_key_hex = generate_keypair()
            with open(key_file, "w") as f:
                json.dump({
                    "node_id": self.node_id,
                    "private_key": self.private_key_hex,
                    "public_key": self.public_key_hex
                }, f, indent=2)

        # 2. Peer Cluster Topology
        peers_str = os.getenv("PEER_ADDRESSES", "")
        if peers_str:
            self.peers: List[str] = [p.strip() for p in peers_str.split(",") if p.strip()]
        else:
            # Default 5-node cluster for local testing
            self.peers = [f"localhost:{50051 + i}" for i in range(5)]

        # 3. Operational Mode: AUTOMATIC (instant drop) or ADVISORY (manual review)
        self.operational_mode = os.getenv("OPERATIONAL_MODE", "AUTOMATIC").upper()

        # 4. Byzantine Fault Injection Mode: NONE, LIAR, FORGER, SILENT, EQUIVOCATOR
        self.byzantine_mode = os.getenv("BYZANTINE_MODE", "NONE").upper()

        # 5. Known domain public keys for Origin HTTP Signature verification
        self.known_domain_keys: Dict[str, str] = {}
        domain_keys_raw = os.getenv("KNOWN_DOMAIN_KEYS", "")
        if domain_keys_raw:
            try:
                self.known_domain_keys = json.loads(domain_keys_raw)
            except Exception:
                pass

    @property
    def total_nodes(self) -> int:
        return max(len(self.peers), 1)

    @property
    def max_byzantine_faults(self) -> int:
        """Standard BFT safety bound: f = (N - 1) // 3"""
        return (self.total_nodes - 1) // 3

    @property
    def quorum_size(self) -> int:
        """
        Quorum threshold:
        - Strict BFT (Default Option B): Q = N - f (4 out of 5 for N=5, f=1) to prevent split-brain.
        - Majority Mode (Option A): Q = 2f + 1 (3 out of 5 for N=5, f=1).
        """
        f = self.max_byzantine_faults
        mode = os.getenv("QUORUM_MODE", "STRICT").upper()
        if mode == "MAJORITY":
            return 2 * f + 1  # 3 out of 5
        return self.total_nodes - f  # 4 out of 5 (Default Option B)
