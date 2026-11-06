# FedConsensus: Byzantine-Resilient Consensus for Federated Social Moderation

**Operator dashboard:** from this project directory, run
`docker compose up --build -d` and open http://127.0.0.1:8090 (or run `python -m dashboard.server --port 8091`).
See [dashboard/README.md](dashboard/README.md) for live UI controls and setup.
The live Operator Console provides end-to-end observability and interactive testing for external & internal ActivityPub threat injection, automated 3-phase BFT voting (`Q = N - f`), O(1) RAM firewall inspection, Byzantine fault injection (`Silent`, `Liar`, `Forger`), crash/revive `CatchupSync` self-healing, and unlimited Kubernetes StatefulSet scaling.

[![Course](https://img.shields.io/badge/Course-CSC3104%20Cloud%20%26%20Distributed%20Computing-blue.svg)](https://www.gla.ac.uk/)
[![Institution](https://img.shields.io/badge/Institution-University%20of%20Glasgow%20%2F%20SIT-red.svg)](https://www.singaporetech.edu.sg/)
[![Architecture](https://img.shields.io/badge/Architecture-3--Phase%20BFT%20Quorum%20%2B%20gRPC-green.svg)](#2-system-architecture--how-it-works)
[![Cloud Native](https://img.shields.io/badge/Cloud%20Native-Kubernetes%20StatefulSets-orange.svg)](#6-phase-4-modules-operator-diagnostics-cli--kubernetes-infrastructure)

FedConsensus is a cloud-native, Byzantine-resilient consensus engine designed for decentralized social networks (Mastodon / ActivityPub). It automates domain-level defederation across independent instances in **sub-second latency (< 300 ms)** using a 3-phase BFT quorum protocol, Ed25519 digital signatures, and cryptographic origin verification.

---

## Table of Contents
1. [The Real-World Problem](#1-the-real-world-problem)
2. [System Architecture & How It Works](#2-system-architecture--how-it-works)
3. [Phase 1 Modules: Cryptography & Storage Engine](#3-phase-1-modules-cryptography--storage-engine)
4. [Phase 2 Modules: Ingress, Threat Detection & Consensus](#4-phase-2-modules-ingress-threat-detection--consensus)
5. [Phase 3 Modules: Catch-Up Sync, gRPC Service & Cluster Fleet](#5-phase-3-modules-catch-up-sync-grpc-service--cluster-fleet)
6. [Phase 4 Modules: Operator Diagnostics CLI & Kubernetes Infrastructure](#6-phase-4-modules-operator-diagnostics-cli--kubernetes-infrastructure)
7. [Repository File Tree at a Glance](#7-repository-file-tree-at-a-glance)
8. [Verification & Testing](#8-verification--testing)

---

## 1. The Real-World Problem

In decentralized social networks powered by the W3C **ActivityPub** protocol (such as **Mastodon**, Lemmy, and Threads), there is no central authority to ban malicious servers. When an aggressive actor launches an automated botnet, phishing campaign, or malware distribution, server administrators currently coordinate defenses manually:

* **The Current Workflow:** Admins share `.csv` blocklists over Discord, Matrix chats, and GitHub repositories using hashtags like `#fediblock`.
* **The Latency Bottleneck:** Disseminating manual blocklists takes **6 to 48 hours**, during which millions of users receive malicious links.
* **The Byzantine & Framing Vulnerability:** A rogue or compromised admin can fabricate false reports against an innocent instance (`innocent-server.org`) due to personal disputes (false-flag defederation). Conversely, a colluding admin can refuse to report malicious attacks (censorship).

**FedConsensus replaces this fragile manual process with automated, cryptographic Byzantine Fault Tolerant consensus.**

---

## 2. System Architecture & How It Works

FedConsensus uses a **Two-Tier Network Architecture**:
1. **Edge Border (Public Internet):** Ingests incoming posts from external servers via standard **W3C ActivityPub (HTTP/REST)**.
2. **Consortium Mesh (Internal Cluster):** Autonomous nodes coordinate consensus votes at high speed via **Google gRPC (HTTP/2 binary)**.

```text
       EXTERNAL INTERNET                                INTERNAL CONSORTIUM MESH
 (External Attackers & Users)                          (5 Autonomous Node Pods)

┌────────────────────────────┐
│ External Malicious Server  │
│ (e.g., spam-botnet.net)    │
└──────────────┬─────────────┘
               │
               │ W3C ActivityPub (HTTP POST /inbox)
               ▼
      ┌─────────────────┐
      │    fednode-0    │ <================== Google gRPC ==================> ┌─────────────────┐
      │ (Ingress Door)  │                 (3-Phase BFT Voting)                │    fednode-1    │
      └────────┬────────┘                                                     └────────┬────────┘
               │                                                                       │
               │ <=========================== Google gRPC ===========================> │
               ▼                                                                       ▼
      ┌─────────────────┐                                                     ┌─────────────────┐
      │    fednode-2    │ <================== Google gRPC ==================> │    fednode-3    │
      └─────────────────┘                                                     └─────────────────┘
```

### The 4-Stage Moderation Lifecycle:
```text
1. Ingress & Firewall ──► 2. Threat Classifier ──► 3. BFT Consensus ──► 4. SQLite WAL Commit
   • In-Memory set         • Velocity (Bots)       • Phase 1: Propose      • Quorum Proof saved
   • Sub-µs O(1) drop      • Executables (.exe)    • Phase 2: Vote         • In-Memory firewall
   • Returns HTTP 403      • Phishing keywords     • Phase 3: Commit         updated instantly
                           • Score ≥ 0.60 trigger  • Q = N - f = 4/5
```

---

## 3. Phase 1 Modules: Cryptography & Storage Engine

These foundational modules provide the cryptographic identity, message contracts, and persistent crash resilience for every node.

### 1. `proto/fedconsensus.proto` (gRPC Network Contract)
* **What it does:** Defines the strict, single source of truth for all binary network communication between Kubernetes pods.
* **Problem it solves:** In distributed systems, nodes cannot talk using unstructured text. This file defines the exact binary schemas for the 6 core cluster operations:
  1. `ProposeDefederation`: Leader broadcasts target domain, evidence, and Ed25519 signature.
  2. `CastVote`: Followers return cryptographically signed `APPROVE` / `REJECT` ballots.
  3. `CommitDefederation`: Broadcaster attaches the **Quorum Proof** ($Q = 4$ signatures) to finalize the ban.
  4. `Heartbeat`: Leader lease renewal to prevent split-brain dual leaders.
  5. `ImpeachLeader`: Emergency vote to remove a censoring or offline leader.
  6. `CatchupSync`: Recovering nodes query missing bans and replay state.

### 2. `node/crypto/ed25519.py` (Digital Signatures & Deterministic Hashing)
* **What it does:** Provides asymmetric Ed25519 keypair generation, deterministic SHA-256 canonical hashing, and digital signature signing and verification.
* **Problem it solves (Byzantine Forgery):** In a Byzantine environment, nodes cannot trust plain text. If Node 3 says *"Node 1 voted YES"*, other nodes verify Node 1's public key. If the digital signature doesn't match, the vote is instantly rejected.
* **Why SHA-256?** ActivityPub posts can be large (2 MB). Elliptic-curve cryptography requires a fixed 32-byte input. SHA-256 condenses the payload into a 32-byte fingerprint with an "avalanche effect" (changing 1 character alters the entire hash).

### 3. `node/crypto/http_sig.py` (Origin Anti-Framing Defense)
* **What it does:** Verifies that abusive post evidence was genuinely signed by the private key of the *accused server*.
* **Problem it solves (False-Flag / Framing Attacks):** If a rogue leader hates an innocent server (`friendly-community.org`), the leader could make up a fake spam post and propose a ban. This module checks: *"Was this post authentically signed by `friendly-community.org`'s private key?"* If not, the proposal is rejected as a framing attempt, and the leader is penalized.

### 4. `node/storage/database.py` (Crash-Resilient SQLite in WAL Mode)
* **What it does:** Embedded relational storage using SQLite configured with Write-Ahead Logging (`PRAGMA journal_mode = WAL;`).
* **Problem it solves (Crash Resilience & High Concurrency):**
  - **No Table Locks:** In WAL mode, readers never block writers, and writers never block readers.
  - **Zero Corruption on Crash:** If Kubernetes kills a pod mid-write (`kill -9` or OOM crash), SQLite recovers atomically from the WAL log file upon reboot.
  - **Storage:** Persists `committed_defederations` with their tamper-proof Quorum Proofs, the `active_blocklist`, and the `peer_reputation` ledger.

### 5. `node/storage/reputation.py` (Dynamic Peer Reputation Ledger)
* **What it does:** Tracks peer trust scores bounded between $100 \rightarrow 0$.
* **Problem it solves (Byzantine Accountability):**
  - Forged Signature: `-40 points`
  - Equivocation (Double-Voting / Lying): `-50 points`
  - Censorship (Ignoring Attacks): `-30 points`
  - Fake Evidence: `-25 points`
  - Honest Vote: `+2 points`
  - **Quarantine Rule:** If a peer's trust drops below **30**, it is quarantined: its voting rights are stripped, preventing persistent sabotage.

### 6. `node/config.py` (Identity Persistence & Quorum Math)
* **What it does:** Central configuration loader for environment variables, persistent key storage, and BFT mathematical limits.
* **Problem it solves:**
  - **Persistent Keypairs:** When a pod restarts after a crash, it reloads its private/public keypair from `node_identity.json` so peers still recognize its identity.
  - **BFT Quorum Math:** Computes `f = (N - 1) // 3` and enforces strict supermajority quorum:
    `Q = N - f`
    (e.g., for `N = 5`, `f = (5 - 1) // 3 = 1`, and `Q = 5 - 1 = 4` out of 5 votes to mathematically eliminate split-brain risk).

---

## 4. Phase 2 Modules: Ingress, Threat Detection & Consensus

These modules handle real-time social network traffic, automated threat scanning, and the live 3-phase consensus voting rounds.

### 1. `node/ingress/firewall.py` (Perimeter Firewall Filter)
* **What it does:** In-memory hash set lookup table loaded from SQLite on startup and updated dynamically on each commit.
* **Problem it solves (Sub-Microsecond Rejection):** If a botnet attacks with 50,000 requests per second, querying a disk database 50,000 times will exhaust disk I/O and freeze the node. Checking an in-memory set in RAM takes **under 1 microsecond (O(1) complexity)** and drops banned traffic with `HTTP 403 Forbidden` instantly before consuming CPU or RAM.
* **Thread-Safety:** Protected with a `threading.Lock()` so concurrent HTTP worker threads can read and update the blocklist safely without race conditions.

### 2. `node/ingress/classifier.py` (Multi-Feature Threat Classifier)
* **What it does:** An intelligent heuristic inspector analyzing incoming ActivityPub post content and traffic behavior across 3 dimensions:
  1. **Burst Velocity:** Request count in a sliding 10-second window (bot flood detection -> `REASON_BOTNET`).
  2. **Malicious File Links:** Scans content and attachments for executable binaries (`.exe`, `.apk`, `.scr`, `.zip`, `.bat` -> `REASON_MALICIOUS_FILES`).
  3. **Phishing Language:** Detects credential theft phrases like *"verify password"*, *"urgent security update"* (-> `REASON_PHISHING`).
* **Problem it solves (Automated Threat Detection):** A firewall only blocks *known* bad actors. The classifier catches *new* attackers in real-time. If the weighted threat score is **>= 0.60**, it automatically triggers the BFT consensus alarm. Safe posts (< 0.60) are accepted with `HTTP 202`.

### 3. `node/ingress/activitypub.py` (W3C `/inbox` Middleware)
* **What it does:** The public HTTP front door of the node handling inbound `POST /inbox` ActivityStreams JSON-LD traffic.
* **Problem it solves (Decentralized Ingress & Pipeline Coordination):**
  - **No Single Point of Failure:** External traffic does *not* funnel through the leader. Every node has its own independent `/inbox` endpoint.
  - **Complete Ingress Pipeline:** Extracts the sender's origin domain -> checks Perimeter Firewall (drops if banned) -> runs Threat Classifier -> delivers safe traffic (`HTTP 202`) or triggers automated consensus escalation (`HTTP 403`).

### 4. `node/engine/consensus.py` (3-Phase BFT Consensus State Machine)
* **What it does:** The core BFT consensus engine running inside every node to coordinate live voting rounds:
  - **Phase 1 (PROPOSE):** The leader signs a canonical proposal hash and broadcasts it to peers.
  - **Phase 2 (PREPARE):** Follower nodes independently audit the leader's signature, verify the origin HTTP signature (anti-framing), sign an `APPROVE` ballot with their own private key, and return the vote.
  - **Quorum Accumulation (Q = N - f = 4):** Gathers ballots into an in-memory accumulator. Once 4 valid, distinct signatures are reached, an immutable **Quorum Certificate (QC)** is minted.
  - **Phase 3 (COMMIT):** Broadcasts the QC, atomically persists the defederation to SQLite WAL, and activates the in-memory firewall rule.
* **Problem it solves:** Eliminates the 6–48 hour delay of manual CSV blocklists, replacing it with sub-second, mathematically binding Byzantine consensus.

### 5. `node/engine/leader.py` (Dynamic Leader Leases & Follower Impeachment)
* **What it does:** Manages leader leases (5s duration), heartbeat renewals, term-based leader failover, and follower emergency impeachment.
* **Problem it solves (Split-Brain Prevention & Anti-Censorship):**
  - **Lease Renewal:** Leaders must broadcast signed heartbeats to renew their lease, preventing dual-leader split-brain scenarios.
  - **Follower Impeachment (The Police Chief Defense):** If a corrupt leader colludes with an attacker and refuses to propose a ban (censorship), followers start a 3-second censorship timer. When the timer expires, followers broadcast an `ImpeachRequest`, fire the corrupt leader, advance the epoch, and elect a new honest leader to ban the attacker!

---

## 5. Phase 3 Modules: Catch-Up Sync, gRPC Service & Cluster Fleet

These modules connect individual node components across the network, provide crash recovery self-healing, enable Byzantine chaos fault injection, and containerize the cluster.

### 1. `node/engine/catchup.py` (Self-Healing Catch-Up Sync & QC Replay)
* **What it does:** Allows crashed or partitioned nodes to query peers for missed defederation records (`handle_catchup_request`) and replay them locally (`replay_records`).
* **Problem it solves (State Gap on Crash Recovery):** When a Kubernetes pod crashes or is restarted, its in-memory firewall and local database may be out of date. Without catch-up, the restarted node would permit malicious traffic that the rest of the cluster has already banned.
* **Cryptographic QC Verification:** When catching up, the node does *not* blindly trust the peer. It mathematically verifies that every replayed record contains a valid **Quorum Certificate (QC)** with at least $Q = 4$ signatures from authenticated peer public keys before writing to SQLite WAL and loading the ban into the RAM firewall.

### 2. `node/service.py` (Consortium gRPC Server & Byzantine Fault Injection)
* **What it does:** Implements the 7 core gRPC remote procedure calls (`ProposeDefederation`, `CastVote`, `CommitDefederation`, `Heartbeat`, `ImpeachLeader`, `CatchupSync`, `GetStatus`) connecting the consortium mesh.
* **Problem it solves (Inter-Node Coordination & Chaos Testing):** Binds the consensus engine to live network ports, enabling sub-millisecond binary message exchange across pods.
* **Runtime Byzantine Fault Injection (`set_byzantine_mode`):** Enables dynamic testing of malicious behavior for academic benchmark evaluations:
  - `NONE`: Normal honest validation.
  - `SILENT`: Simulates node crash or packet drop (rejects RPCs / times out).
  - `LIAR`: Maliciously casts `VOTE_REJECT` on verified threats to protect colluding attackers.
  - `FORGER`: Corrupts ballot digital signatures to attempt signature forgery attacks.

### 3. `node/main.py` (Dual-Server Node Bootstrap & Escalation Loop)
* **What it does:** Unified daemon entrypoint that concurrently initializes and runs the two distinct server layers of the node.
* **Problem it solves (Decoupling Public Web from Consortium Mesh):**
  - **Port 8080 (External HTTP / REST):** Public-facing ActivityPub receiver handling `POST /inbox` posts from the global Fediverse and `GET /health` liveness probes.
  - **Port 50051 (Internal gRPC / Binary):** Private consortium mesh handling BFT consensus proposals, ballots, and heartbeats.
  - **Automated Escalation Loop:** Automatically wires the Threat Classifier to consensus: if an incoming post on Port 8080 scores $\ge 0.60$, `main.py` launches a background thread to broadcast a BFT proposal to the internal gRPC cluster on Port 50051 without blocking HTTP response delivery.
  - **Leader Heartbeat Daemon:** Automatically broadcasts periodic heartbeat pulses (every 2 seconds) to preserve the leader lease.

### 4. `node/Dockerfile` & `docker-compose.yml` (Local 5-Node Cluster Fleet)
* **What it does:** Container specification and multi-node orchestration engine to spin up a complete 5-node FedConsensus network (`fednode-0` to `fednode-4`) on an isolated virtual bridge network (`fedconsensus-net`).
* **Problem it solves (Realistic Distributed Testing):** Allows developers and evaluators to run, test, and benchmark the entire distributed system locally on a single machine before Kubernetes deployment. Each container mounts its own persistent SQLite volume (`fednode-X-data`), preserving blocklists and cryptographic identities across container restarts (`docker-compose stop/start`).
* **One-Click Startup (`start-cluster.bat`):** Automates container teardown, rebuild, and background deployment with container health status output.

---

## 6. Phase 4 Modules: Operator Diagnostics CLI & Kubernetes Infrastructure

Phase 4 transitions FedConsensus from local Docker testing into enterprise cloud-native Kubernetes orchestration and provides terminal diagnostic tooling and end-to-end chaos verification.

### 1. `cli/fedctl.py` (Local Node Operator Diagnostics CLI)
* **What it does:** A lightweight terminal management client connecting over gRPC to any target node (`localhost:50051` to `50055`) to query status, inspect peer reputation, and dispatch manual proposals.
* **Commands Implemented:**
  - `status`: Queries `GetStatus` telemetry to display role (`LEADER` / `FOLLOWER`), current epoch, sequence number, and blocked domain count.
  - `peers`: Formats the peer reputation ledger into an aligned terminal table and flags nodes with trust $< 30$ as `QUARANTINED`.
  - `propose <domain> [--reason]`: Allows a local node administrator to submit an emergency signed proposal over gRPC if an attack was missed by automated filters.
* **Problem it solves:** In headless cloud deployments (AWS EC2 / remote Kubernetes nodes without a web browser), sysadmins need a fast, scriptable CLI to inspect node health and reputation without digging through raw SQLite files.

### 2. `k8s/configmap.yaml` (Consortium Cluster Topology)
* **What it does:** Centralizes cluster-wide environment variables (`GRPC_PORT: 50051`, `HTTP_PORT: 8080`, `DATA_DIR: /data`, `BYZANTINE_MODE: NONE`) and the peer DNS address phonebook (`PEER_ADDRESSES`).
* **Problem it solves:** Decouples networking configuration from container images, allowing operators to reconfigure cluster topology without rebuilding Docker containers.

### 3. `k8s/service-headless.yaml` (Point-to-Point Headless DNS Service)
* **What it does:** Defines a Headless Service (`clusterIP: None`) named `fedconsensus-mesh`.
* **Problem it solves (The Middleman Load Balancer Problem):** Standard Kubernetes Services randomly distribute traffic across pods using round-robin proxies. In BFT consensus, a leader must send ballots to *specific* individual peers. A Headless Service creates direct internal DNS A-records for each pod (`fednode-0.fedconsensus-mesh:50051`, `fednode-1.fedconsensus-mesh:50051`), enabling direct point-to-point gRPC mesh communication.

### 4. `k8s/statefulset.yaml` & `k8s/pvc.yaml` (Persistent Cloud Orchestration)
* **What it does:** Deploys the 5-node cluster as a Kubernetes `StatefulSet` with dedicated persistent storage (`volumeClaimTemplates`).
* **Problem it solves (Container Ephemerality & Amnesia):** Standard Kubernetes Deployments assign random pod hostnames and wipe disk files upon container restarts. The StatefulSet guarantees:
  1. **Deterministic Identities:** Fixed, permanent pod names (`fednode-0` through `fednode-4`).
  2. **Kubernetes Downward API:** Pods automatically discover their own identity (`NODE_ID = metadata.name`) dynamically at boot.
  3. **Dedicated PVC Binding:** Automatically mounts dedicated 1Gi storage claims (`data-fednode-X`) so SQLite WAL databases and Ed25519 node identities survive pod crashes.
  4. **Health Probes:** Automates self-healing via `livenessProbe` and `readinessProbe` checking `GET /health` on port 8080.

### 5. `Cloud-Native Kubernetes Infrastructure`

FedConsensus is containerized and deployed using **Kubernetes StatefulSets**:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ StatefulSet: fedconsensus-cluster (Replicas: 5)                        │
│                                                                        │
│  ┌────────────────────┐  ┌────────────────────┐  ┌───────────────────┐ │
│  │ Pod: fednode-0     │  │ Pod: fednode-1     │  │ Pod: fednode-2    │ │
│  │ (Leader / Honest)  │  │ (Follower / Honest)│  │ (Follower / Honest│ │
│  │ PVC: /data/wal.db  │  │ PVC: /data/wal.db  │  │ PVC: /data/wal.db │ │
│  └─────────┬──────────┘  └─────────┬──────────┘  └─────────┬─────────┘ │
│            │                       │                       │           │
│            ▼                       ▼                       ▼           │
│  Headless Service: fedconsensus-mesh (Direct Peer-to-Peer gRPC DNS)    │
│  (fednode-0.fedconsensus-mesh.default.svc.cluster.local:50051)         │
└────────────────────────────────────────────────────────────────────────┘
```

* **Deterministic Identities:** StatefulSets assign fixed hostnames (`fednode-0`, `fednode-1`, etc.).
* **Headless DNS Service:** Enables direct peer-to-peer gRPC addressing without load-balancer proxy overhead.
* **PersistentVolumeClaims (PVC):** Ensures SQLite WAL files and node keypairs survive pod crashes and restarts.
* **Automated Elastic Self-Healing:** If 2 nodes are compromised, the cluster detects the quorum stall (3/4 votes) and automatically patches the Kubernetes API to scale to 7 replicas, restoring quorum ($5/7$) autonomously!

---

## 7. Repository File Tree at a Glance

```text
CloudProject/
├── proto/                          # gRPC Protocol Buffer contracts
│   ├── fedconsensus.proto          # Protocol Buffer schema
│   ├── fedconsensus_pb2.py         # Generated message classes
│   └── fedconsensus_pb2_grpc.py    # Generated client/server stubs
│
├── node/                           # Core Autonomous FedNode Microservice
│   ├── engine/                     # Consensus and leader coordination
│   │   ├── consensus.py            # 3-Phase BFT State Machine (Q = N - f)
│   │   ├── leader.py               # Leases, heartbeats, and follower impeachment
│   │   └── catchup.py              # CatchupSync RPC handler & log replay
│   ├── crypto/                     # Cryptographic primitives & verification
│   │   ├── ed25519.py              # Keypair generation, signing, and canonical hash
│   │   └── http_sig.py             # Origin HTTP signature anti-framing check
│   ├── storage/                    # Persistent storage & peer accounting
│   │   ├── database.py             # SQLite WAL engine (persisting blocklist & QCs)
│   │   └── reputation.py           # Dynamic Peer Reputation Ledger (100 -> 0)
│   ├── ingress/                    # Social traffic ingestion & firewall
│   │   ├── activitypub.py          # W3C ActivityPub /inbox HTTP receiver
│   │   ├── classifier.py           # Multi-feature threat classifier
│   │   └── firewall.py             # Sub-microsecond perimeter blocklist filter
│   ├── telemetry.py                # In-memory bounded event logging & node telemetry snapshot
│   ├── service.py                  # gRPC server binding node components
│   ├── config.py                   # Node identity, port, and peer topology
│   ├── main.py                     # FedNode service bootstrap entrypoint
│   ├── requirements.txt            # Python dependencies for FedNode
│   └── Dockerfile                  # Container specification for FedNode
│
├── dashboard/                      # Observability & Chaos Testing Studio
│   ├── README.md                   # Operator dashboard guide & live controls reference
│   ├── server.py                   # Cluster telemetry monitor & HTTP API server
│   ├── control.py                  # Live operator actions, internal/external traffic & K8s scaling
│   ├── runtime.py                  # Docker Compose & Kubernetes StatefulSet runtime adapter
│   ├── static/                     # Real-time web UI frontend
│   │   ├── index.html              # Operator web UI layout & live controls
│   │   ├── app.js                  # Real-time network mesh, live BFT vote animation & RAM inspector
│   │   └── style.css               # Modern dark-mode dashboard styling
│   ├── requirements.txt            # Python dependencies for dashboard
│   └── Dockerfile                  # Container specification for dashboard
│
├── cli/                            # Administrative terminal tooling
│   └── fedctl.py                   # CLI for manual proposals and inspection
│
├── k8s/                            # Cloud-Native Kubernetes Manifests (Dell Award)
│   ├── statefulset.yaml            # StatefulSet definition for fednode cluster
│   ├── service-headless.yaml       # Headless Service for peer discovery
│   ├── configmap.yaml              # Cluster topology and peer configuration
│   └── pvc.yaml                    # PersistentVolumeClaims for SQLite WAL persistence
│
├── tests/                          # Automated verification test suites organized by phase
│   ├── phase1/                     # Phase 1: Cryptography & Storage Engine
│   │   ├── test_crypto_verify.py       # Ed25519 signatures, canonical hash & anti-framing
│   │   ├── test_database_verify.py     # SQLite WAL mode, commits & catch-up queries
│   │   ├── test_reputation_verify.py   # Peer trust scores, violations & quarantine
│   │   ├── test_config_verify.py       # Protobuf contracts & BFT quorum math (Q = N - f)
│   │   └── test_phase1_verification.py # Phase 1 comprehensive verification suite
│   ├── phase2/                     # Phase 2: Ingress Firewall, Classifier & Consensus
│   │   ├── test_firewall_verify.py     # Sub-microsecond O(1) in-memory perimeter drops
│   │   ├── test_classifier_verify.py   # Heuristic threat analysis & scoring (>= 0.60)
│   │   ├── test_inbox_verify.py        # ActivityPub /inbox receiver & escalation
│   │   ├── test_consensus_engine_verify.py # 3-Phase BFT State Machine & QC minting
│   │   ├── test_leader_verify.py       # Leases, heartbeats & follower impeachment
│   │   └── test_phase2_verification.py # Phase 2 comprehensive pipeline suite
│   ├── phase3/                     # Phase 3: Catch-up Sync, gRPC Service & Dual Servers
│   │   ├── test_catchup_verify.py      # Self-healing catch-up replay & QC verification
│   │   ├── test_service_verify.py      # Consortium gRPC servicer & Byzantine chaos modes
│   │   ├── test_main_verify.py         # Dual-server daemon (Port 8080 & 50051)
│   │   └── test_phase3_verification.py # Phase 3 comprehensive cluster suite
│   ├── phase4/                     # Phase 4: Operator CLI, K8s & Dashboard Verification
│   │   ├── test_cli_verify.py          # fedctl terminal diagnostic management CLI
│   │   ├── test_k8s_verify.py          # Kubernetes StatefulSet, headless svc & PVC manifests
│   │   ├── test_dashboard_verify.py    # Telemetry bounding, polling resilience & security checks
│   │   ├── test_dashboard_controls.py  # Operator console actions, CSRF & runtime controls test
│   │   ├── test_dashboard_node_verify.py # Node /telemetry endpoint integration test
│   │   ├── test_dashboard_routes.cjs   # Network routes & persistent sender labels (Node.js)
│   │   └── test_phase4_verification.py # Phase 4 comprehensive cloud infrastructure suite
│   └── end_to_end_testing/         # End-to-End BFT Quorum, Byzantine Masking & Chaos Lifecycles
│       ├── test_consensus.py           # Quorum math, split-brain invariance & live QC minting
│       ├── test_byzantine.py           # Byzantine LIAR masking & FORGER signature audit
│       └── test_scenarios.py           # End-to-end moderation, crash catch-up & anti-framing
│
├── benchmarks/                     # Quantitative Evaluation Framework (25% Paper)
│   ├── benchmark_runner.py         # Automated latency and throughput benchmarking
│   ├── generate_graphs.py          # Generates the 4 IEEE paper figures
│   └── results/                    # Directory for benchmark CSVs and output PNG charts
│
├── docker-compose.yml              # Local multi-node testbed with bridge networking
├── start-cluster.bat               # 1-click startup batch script
└── README.md                       # Master architecture documentation
```

---

## 8. Verification & Testing

To independently verify the implemented phases, execute the automated verification test suites:

```powershell
# Phase 1: Comprehensive Verification Suite
python tests/phase1/test_phase1_verification.py

# Phase 1: Individual Factor Tests
python tests/phase1/test_crypto_verify.py
python tests/phase1/test_database_verify.py
python tests/phase1/test_reputation_verify.py
python tests/phase1/test_config_verify.py

# Phase 2: Comprehensive Pipeline Verification Suite
python tests/phase2/test_phase2_verification.py

# Phase 2: Individual Factor Tests
python tests/phase2/test_firewall_verify.py
python tests/phase2/test_classifier_verify.py
python tests/phase2/test_inbox_verify.py
python tests/phase2/test_consensus_engine_verify.py
python tests/phase2/test_leader_verify.py

# Phase 3: Comprehensive Cluster Integration Suite
python tests/phase3/test_phase3_verification.py

# Phase 3: Individual Factor Tests
python tests/phase3/test_catchup_verify.py
python tests/phase3/test_service_verify.py
python tests/phase3/test_main_verify.py

# Phase 4: Comprehensive Cloud Infrastructure Suite
python tests/phase4/test_phase4_verification.py

# Phase 4: Individual Factor Tests
python tests/phase4/test_cli_verify.py
python tests/phase4/test_k8s_verify.py

# Phase 4: Operator Dashboard Test Suite
python tests/phase4/test_dashboard_verify.py
python tests/phase4/test_dashboard_controls.py
python tests/phase4/test_dashboard_node_verify.py
node tests/phase4/test_dashboard_routes.cjs

# End-to-End Chaos Verification Suites
python tests/end_to_end_testing/test_consensus.py
python tests/end_to_end_testing/test_byzantine.py
python tests/end_to_end_testing/test_scenarios.py
```
