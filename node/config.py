import os
import json
from typing import List, Dict
from node.crypto.ed25519 import generate_keypair, generate_deterministic_keypair


DEFAULT_ORG_DOMAINS = {
    "fednode-0": "glasgow.social",
    "fednode-1": "edinburgh.social",
    "fednode-2": "oxford.social",
    "fednode-3": "cambridge.social",
    "fednode-4": "imperial.social",
    "fednode-5": "manchester.social",
    "fednode-6": "bristol.social",
    "fednode-7": "warwick.social",
    "fednode-8": "st-andrews.social",
}


class NodeConfig:
    """
    Central Configuration for a FedConsensus node.
    Manages persistent cryptographic identity, networking topology,
    and BFT quorum thresholds.
    """
    def __init__(self):
        self.node_id = os.getenv("NODE_ID", "fednode-1")
        self.org_domain = os.getenv("ORG_DOMAIN", DEFAULT_ORG_DOMAINS.get(self.node_id, f"{self.node_id}.social"))
        self.grpc_port = int(os.getenv("GRPC_PORT", "50051"))
        self.http_port = int(os.getenv("HTTP_PORT", "8080"))
        self.data_dir = os.getenv("DATA_DIR", os.path.join(".", "data", self.node_id))
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "wal.db")

        # 1. Persistent Cryptographic Identity
        key_file = os.path.join(self.data_dir, "node_identity.json")
        consortium_secret = os.getenv("CONSORTIUM_SECRET", "fedconsensus-consortium")
        use_random_keys = os.getenv("USE_RANDOM_NODE_KEYS", "false").lower() == "true"

        if use_random_keys and os.path.exists(key_file):
            with open(key_file, "r") as f:
                saved = json.load(f)
                self.private_key_hex = saved["private_key"]
                self.public_key_hex = saved["public_key"]
        elif use_random_keys:
            self.private_key_hex, self.public_key_hex = generate_keypair()
        else:
            self.private_key_hex, self.public_key_hex = generate_deterministic_keypair(f"{consortium_secret}-{self.node_id}")

        with open(key_file, "w") as f:
            json.dump({
                "node_id": self.node_id,
                "org_domain": self.org_domain,
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

        # Derive known consortium public keys for BFT verification
        self.known_peer_keys: Dict[str, str] = {}
        custom_pubkeys_raw = os.getenv("CONSORTIUM_PUBLIC_KEYS", "")
        if custom_pubkeys_raw:
            try:
                self.known_peer_keys = json.loads(custom_pubkeys_raw)
            except Exception:
                pass
        for p in self.peers:
            peer_host = p.split(":")[0]
            if "fednode" in peer_host:
                node_name = peer_host.split(".")[0]
                if node_name not in self.known_peer_keys:
                    _, pub = generate_deterministic_keypair(f"{consortium_secret}-{node_name}")
                    self.known_peer_keys[node_name] = pub
            elif peer_host in ("localhost", "127.0.0.1"):
                try:
                    port = int(p.split(":")[1])
                    idx = port - 50051 if port >= 50051 else 0
                    node_name = f"fednode-{idx}"
                    if node_name not in self.known_peer_keys:
                        _, pub = generate_deterministic_keypair(f"{consortium_secret}-{node_name}")
                        self.known_peer_keys[node_name] = pub
                except Exception:
                    pass

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
        return self.total_nodes - f  # 4 out of 5 
