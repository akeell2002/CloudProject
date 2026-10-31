# FedConsensus: Byzantine-Resilient Consensus for Federated Social Moderation

[![Course](https://img.shields.io/badge/Course-CSC3104%20Cloud%20%26%20Distributed%20Computing-blue.svg)](https://www.gla.ac.uk/)
[![Institution](https://img.shields.io/badge/Institution-University%20of%20Glasgow%20%2F%20SIT-red.svg)](https://www.singaporetech.edu.sg/)
[![Architecture](https://img.shields.io/badge/Architecture-3--Phase%20BFT%20Quorum%20%2B%20gRPC-green.svg)](#2-system-architecture--how-it-works)
[![Cloud Native](https://img.shields.io/badge/Cloud%20Native-Kubernetes%20StatefulSets-orange.svg)](#5-cloud-native-kubernetes-infrastructure)

FedConsensus is a cloud-native, Byzantine-resilient consensus engine designed for decentralized social networks (Mastodon / ActivityPub). It automates domain-level defederation across independent instances in **sub-second latency (< 300 ms)** using a 3-phase BFT quorum protocol, Ed25519 digital signatures, and cryptographic origin verification.

---

## Table of Contents
1. [The Real-World Problem](#1-the-real-world-problem)
2. [System Architecture & How It Works](#2-system-architecture--how-it-works)
3. [Phase 1 Modules: Cryptography & Storage Engine](#3-phase-1-modules-cryptography--storage-engine)
4. [Phase 2 Modules: Ingress, Threat Detection & Consensus](#4-phase-2-modules-ingress-threat-detection--consensus)
5. [Cloud-Native Kubernetes Infrastructure](#5-cloud-native-kubernetes-infrastructure)
6. [Repository File Tree](#6-repository-file-tree)
7. [Verification & Testing](#7-verification--testing)

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

## 5. Cloud-Native Kubernetes Infrastructure

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

## 6. Repository File Tree

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
│   ├── service.py                  # gRPC server binding node components
│   ├── config.py                   # Node identity, port, and peer topology
│   ├── main.py                     # FedNode service bootstrap entrypoint
│   ├── requirements.txt            # Python dependencies for FedNode
│   └── Dockerfile                  # Container specification for FedNode
│
├── dashboard/                      # Observability & Chaos Testing Studio
│   ├── server.py                   # Backend service aggregating cluster telemetry
│   ├── static/                     # Real-time web UI frontend
│   │   ├── index.html              # Browser UI layout
│   │   ├── app.js                  # 1-click chaos triggers (kill, revive, Byzantine)
│   │   └── style.css               # Dashboard styling
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
├── tests/                          # Automated verification test suites
│   ├── test_phase1_verification.py # Phase 1 unit test suite
│   ├── test_phase2_verification.py # Phase 2 pipeline integration suite
│   ├── test_consensus.py           # BFT voting & quorum math tests
│   ├── test_byzantine.py           # Byzantine fault masking tests
│   └── test_scenarios.py           # End-to-end chaos verification
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

## 7. Verification & Testing

To independently verify the implemented phases, run the automated test suites:

```powershell
# Verify Phase 1 (gRPC, Ed25519 Signatures, SQLite WAL, Reputation, Config)
python tests/test_phase1_verification.py

# Verify Phase 2 (Ingress, Firewall, Threat Classifier, 3-Phase BFT, Impeachment)
python tests/test_phase2_verification.py
```
