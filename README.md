# FedConsensus: Byzantine-Resilient Consensus for Federated Social Moderation

[![Course](https://img.shields.io/badge/Course-CSC3104%20Cloud%20%26%20Distributed%20Computing-blue.svg)](https://www.gla.ac.uk/)
[![Institution](https://img.shields.io/badge/Institution-University%20of%20Glasgow%20%2F%20SIT-red.svg)](https://www.singaporetech.edu.sg/)
[![Architecture](https://img.shields.io/badge/Architecture-3--Phase%20BFT%20Quorum%20%2B%20gRPC-green.svg)](#system-architecture)
[![Cloud Native](https://img.shields.io/badge/Cloud%20Native-Kubernetes%20StatefulSets%20%2B%20Docker-orange.svg)](#cloud-native-infrastructure)

---

## 1. Executive Summary & Problem Statement

In decentralized social networks powered by the W3C **ActivityPub** protocol (such as **Mastodon**, Lemmy, and Pleroma), there is no centralized authority or corporate headquarters to ban malicious servers. When an aggressive actor launches an automated botnet, phishing campaign, or malware distribution, server administrators currently coordinate defenses manually:

* **The Current Status Quo:** Admins share `.csv` blocklists over Discord, Matrix chats, and GitHub repositories using hashtags like `#fediblock`.
* **The Fatal Latency Bottleneck:** Disseminating manual blocklists takes **6 to 48 hours**. By the time neighboring admins import the list, millions of users have already received spam, phishing payloads, or malicious links.
* **The Byzantine & Framing Vulnerability:** A rogue or compromised admin can fabricate false reports against an innocent instance (`innocent-server.org`) due to personal disputes (false-flag defederation). Conversely, a colluding admin can refuse to report malicious attacks (censorship).

### The Solution: FedConsensus
**FedConsensus** is a high-performance, cloud-native consensus engine deployed as a Kubernetes StatefulSet across independent federated instances. It automates domain-level defederation in **sub-second latency (< 300 ms)** using:
1. **A 3-Phase Byzantine Fault Tolerant (BFT) Quorum Protocol** enforcing a strict $Q = N - f$ quorum threshold.
2. **Ed25519 Cryptographic Signatures** for tamper-proof non-repudiation on all ballots and quorum certificates.
3. **Origin HTTP Signature Verification (Anti-Framing)** that cryptographically validates abusive content against the accused domain's private key, making false-flag attacks mathematically impossible.
4. **Dynamic Leader Leases & Follower Impeachment** to prevent censorship and split-brain failures.
5. **Self-Healing State Synchronization** via Write-Ahead Log (WAL) replay and Quorum Certificate verification upon crash recovery.

---

## 2. End-to-End System Architecture

```text
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │                             FEDCONSENSUS SYSTEM TOPOLOGY                               │
 └────────────────────────────────────────────────────────────────────────────────────────┘

    [External ActivityPub Traffic / Attacks]
                      │
                      ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ 1. EDGE INGRESS & FIREWALL                                                             │
 │                                                                                        │
 │  Inbound HTTP POST /inbox (ActivityStreams JSON-LD)                                    │
 │       │                                                                                │
 │       ▼                                                                                │
 │  ┌───────────────────────┐                                                             │
 │  │ Perimeter Firewall    │ ─── Is Domain in Active Blocklist? ──► YES ──► HTTP 403     │
 │  │ In-Memory (Sub-µs)    │                                                (Dropped)    │
 │  └──────────┬────────────┘                                                             │
 │             │ NO (Domain not blocked)                                                  │
 │             ▼                                                                          │
 │  ┌───────────────────────┐                                                             │
 │  │ Multi-Feature Threat  │ ──► [Velocity / Burst Rate]                                 │
 │  │ Classifier            │ ──► [Malicious Extensions: .exe, .apk, .zip]                │
 │  │                       │ ──► [Phishing & Credential Theft Language]                  │
 │  └──────────┬────────────┘                                                             │
 │             │                                                                          │
 │             ├─ Threat Score < 0.60 ──► HTTP 202 Accepted (Delivered to Social Feed)    │
 │             │                                                                          │
 │             └─ Threat Score ≥ 0.60 ──► AUTOMATED ESCALATION TRIGGER                    │
 └─────────────┼──────────────────────────────────────────────────────────────────────────┘
               │
               ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ 2. CRYPTOGRAPHIC ANTI-FRAMING AUDIT                                                    │
 │                                                                                        │
 │  Origin HTTP Signature Verification:                                                   │
 │  • Fetches accused domain's public key (https://accused.net/actor#main-key)            │
 │  • Verifies that abusive payload was authentically signed by accused server            │
 │  • IF INVALID: Accusation rejected (prevents rogue leaders framing innocent servers)   │
 └─────────────┼──────────────────────────────────────────────────────────────────────────┘
               │
               ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ 3. DISTRIBUTED BFT CONSENSUS ENGINE (Google gRPC)                                      │
 │                                                                                        │
 │      Phase 1: PROPOSE (Leader broadcasts signed DefederationProposal)                  │
 │                      │                                                                 │
 │                      ▼                                                                 │
 │      Phase 2: PREPARE (Followers independently audit evidence & broadcast Vote)        │
 │                      │                                                                 │
 │                      ▼                                                                 │
 │      [Quorum Threshold Reached: Q = N - f Valid Ed25519 Signatures Accumulated]        │
 │      [Quorum Certificate (QC) Minted]                                                  │
 │                      │                                                                 │
 │                      ▼                                                                 │
 │      Phase 3: COMMIT (Nodes broadcast QC and execute atomic blocklist state commit)    │
 └─────────────┬──────────────────────────────────────────────────────────────────────────┘
               │
               ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │ 4. STORAGE & PERIMETER ENFORCEMENT                                                     │
 │                                                                                        │
 │  • Atomic commit to Embedded SQLite with Write-Ahead Logging (WAL)                     │
 │  • Domain instantly pushed to in-memory Firewall lookup set                            │
 │  • Peer Reputation Ledger updated (rewards honest voters, penalizes Byzantine liars)   │
 └────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. How the System Works: Step-by-Step

### Step 1: Ingress Traffic & Multi-Feature Threat Detection
Every FedNode exposes a W3C-compliant ActivityPub `/inbox` endpoint. When remote instances push posts:
1. **Perimeter Filter:** The domain is checked against an in-memory hash set in sub-microsecond time. Banned domains are rejected immediately with `HTTP 403 Forbidden`.
2. **Threat Classification:** Safe traffic passes into a feature classifier evaluating:
   * **Burst Velocity:** Request count in a sliding 10-second window (bot detection).
   * **Malicious File Links:** Regex scanner for executables and archives (`.exe`, `.scr`, `.apk`, `.zip`, `.bat`).
   * **Phishing Language:** Pattern matching for credential theft keywords ("verify account immediately", "login here to avoid ban").
3. **Escalation:** If the weighted threat score is $\ge 0.60$, the node packages the signed post as cryptographic evidence and initiates consensus.

---

### Step 2: Cryptographic Anti-Framing (Origin HTTP Signatures)
In decentralized networks, a malicious node might attempt to defederate an innocent rival by submitting fake spam posts. 
* FedConsensus mandates that all defederation proposals include the **Origin HTTP Signature** generated by the accused server.
* Followers verify the signature against the accused domain's public key. If the post cannot be mathematically proven to originate from the accused server, followers reject the proposal and penalize the proposer.

---

### Step 3: 3-Phase BFT Quorum Consensus Protocol

FedConsensus guarantees linearizable consensus across $N$ nodes tolerating up to $f$ Byzantine faults, where $N \ge 3f + 1$:

```text
 Leader / Reporter (Node 0)         Follower (Node 1)            Follower (Node 2)         Byzantine (Node 3)
          │                                 │                            │                          │
          ├───── 1. ProposeDefederation ───>│                            │                          │
          ├─────────────────────────────────┼───────────────────────────>│                          │
          │                                 │                            │                          │
          │                                 │ [Audit Origin Sig & Evid]  │ [Audit Origin Sig]       │
          │<──── 2. CastVote (Approved) ────┤                            │                          │
          │<────────────────────────────────┼── 2. CastVote (Approved) ──┤                          │
          │                                 │                            │    (Casts Bogus Vote)    │
          │                                 │                            │<── 2. Bogus Vote ────────┤ [REJECTED]
          │                                 │                            │                          │
   [Count Votes: 3/4 ≥ Q]                   │                            │                          │
   [Mint Quorum Certificate QC]             │                            │                          │
          │                                 │                            │                          │
          ├───── 3. CommitDefederation ────>│                            │                          │
          ├─────────────────────────────────┼───────────────────────────>│                          │
          │                                 │                            │                          │
   [Commit to SQLite WAL]            [Commit to SQLite WAL]       [Commit to SQLite WAL]            │
   [Update In-Memory Firewall]       [Update In-Memory Firewall]  [Update In-Memory Firewall]       │
```

1. **Phase 1: PROPOSE:** The active leader broadcasts a `ProposeRequest` containing the target domain, evidence, origin HTTP signature, epoch, and strictly monotonic sequence number, signed with the leader's Ed25519 private key.
2. **Phase 2: PREPARE (Voting):** Follower nodes independently verify the signature, audit the evidence, and verify the threat classification. If valid, they broadcast a signed `VoteRequest`.
3. **Quorum Certificate (QC):** Once $Q = N - f$ matching, valid signed votes are collected from distinct nodes, an immutable **Quorum Proof** is minted.
4. **Phase 3: COMMIT:** Nodes broadcast a `CommitRequest` containing the QC. Each node verifies the $Q$ voter signatures in the QC and atomically commits the defederation to SQLite and updates the in-memory firewall.

---

### Step 4: Leader Leases, Heartbeats & Follower Impeachment
* **Dynamic Leader Lease:** Leaders hold a time-bounded lease refreshed via periodic `Heartbeat` RPCs to prevent dual-leader split-brain scenarios.
* **Follower Impeachment (Anti-Censorship):** If a leader is compromised and ignores known attacks or censors valid reports, followers detect the proposal timeout, broadcast an `ImpeachRequest`, increment the epoch, and elect a new leader.

---

### Step 5: Self-Healing & Crash Recovery (CatchupSync)
If a node crashes (e.g. killed by Kubernetes OOM or host reboot) and restarts:
1. It reads its local SQLite database and identifies its last committed sequence number $K$.
2. It calls `rpc CatchupSync(from_sequence_number=K+1)` on active peers.
3. The peer responds with the missing committed records and their attached **Quorum Certificates**.
4. The recovering node independently validates the $Q$ signatures on each QC before replaying commits into its local database, restoring consistency without trusting any single peer.

---

## 4. Cloud-Native Kubernetes Infrastructure

FedConsensus is built from the ground up for containerized orchestration:

```text
                     KUBERNETES DEPLOYMENT TOPOLOGY
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

* **Kubernetes StatefulSet:** Provides deterministic, ordered pod identities (`fednode-0`, `fednode-1`, etc.).
* **Headless Service:** Enables direct peer-to-peer gRPC addressing without load-balancer proxy overhead.
* **PersistentVolumeClaims (PVC):** Ensures SQLite write-ahead logs and cryptographic identities persist across pod restarts.

---

## 5. Observability, Chaos Testing Studio & CLI

* **Live Web Dashboard:** A real-time browser dashboard visualizing:
  - Cluster status and active leader identity.
  - Live 3-phase consensus voting rounds.
  - Incoming social feed activity and classification scores.
  - Active perimeter firewall rules.
  - Dynamic peer reputation scores ($100 \rightarrow 0$).
* **Interactive Chaos Controls:** One-click controls to test system resilience:
  - Kill node (`docker stop`) and revive with automatic catch-up.
  - Inject Byzantine faults (liar node, forged signatures, silent dropper).
* **Administrative CLI (`fedctl`):** Terminal utility for operators to inspect cluster health, propose manual defederation, and audit firewall states.

---

## 6. Repository File Architecture

```text
CloudProject/
├── proto/                          # Google gRPC Interface Definition Language
│   └── fedconsensus.proto          # Protocol Buffer schema (Propose, Vote, Commit, Catchup, Impeach)
│
├── node/                           # Core Autonomous FedNode Microservice
│   ├── engine/                     # Consensus and leader coordination
│   │   ├── consensus.py            # 3-Phase BFT Quorum State Machine (Q = N - f)
│   │   ├── leader.py               # Leases, heartbeats, and follower impeachment
│   │   └── catchup.py              # CatchupSync RPC handler & WAL log replay
│   ├── crypto/                     # Cryptographic primitives & verification
│   │   ├── ed25519.py              # Ed25519 keypair generation, signing, and verification
│   │   └── http_sig.py             # Origin HTTP signature verification (anti-framing)
│   ├── storage/                    # Persistent storage & peer accounting
│   │   ├── database.py             # SQLite WAL engine (persisting blocklist & QCs)
│   │   └── reputation.py           # Dynamic Peer Reputation Ledger (100 -> 0)
│   ├── ingress/                    # Social traffic ingestion & firewall
│   │   ├── activitypub.py          # W3C ActivityPub /inbox HTTP receiver
│   │   ├── classifier.py           # Multi-feature threat classifier (burst, files, phishing)
│   │   └── firewall.py             # Sub-microsecond perimeter blocklist filter (HTTP 403)
│   ├── service.py                  # gRPC server implementation binding node components
│   ├── config.py                   # Node identity, port, and peer topology configuration
│   ├── main.py                     # FedNode service bootstrap entrypoint
│   ├── requirements.txt            # Python dependencies for FedNode service
│   └── Dockerfile                  # Container specification for FedNode
│
├── dashboard/                      # Observability & Chaos Testing Studio
│   ├── server.py                   # Backend service aggregating cluster telemetry
│   ├── static/                     # Real-time web UI frontend
│   │   ├── index.html              # Browser UI layout
│   │   ├── app.js                  # Real-time event polling and 1-click chaos triggers
│   │   └── style.css               # Dashboard styling
│   ├── requirements.txt            # Python dependencies for dashboard
│   └── Dockerfile                  # Container specification for dashboard
│
├── cli/                            # Administrative terminal tooling
│   └── fedctl.py                   # Terminal utility for manual proposals and inspection
│
├── k8s/                            # Cloud-Native Kubernetes Manifests (Dell Award)
│   ├── statefulset.yaml            # StatefulSet definition for fednode cluster
│   ├── service-headless.yaml       # Headless Service for peer discovery
│   ├── configmap.yaml              # Cluster topology and peer configuration
│   └── pvc.yaml                    # PersistentVolumeClaims for SQLite WAL persistence
│
├── tests/                          # Automated verification test suite
│   ├── test_consensus.py           # Unit tests for 3-phase BFT voting & quorum math
│   ├── test_byzantine.py           # Tests for Byzantine fault masking (liar, forger, silent)
│   └── test_scenarios.py           # End-to-end automated verification scenarios
│
├── benchmarks/                     # Quantitative Evaluation Framework (25% Paper)
│   ├── benchmark_runner.py         # Automated latency and throughput benchmarking
│   ├── generate_graphs.py          # Script generating the 4 IEEE paper figures
│   └── results/                    # Directory for benchmark CSVs and output PNG charts
│
├── docker-compose.yml              # Local multi-node testbed with bridge networking
├── start-cluster.bat               # 1-click startup batch script
└── README.md                       # Comprehensive architecture and reference guide
```
