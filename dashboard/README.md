# FedConsensus Live Operator Dashboard

The FedConsensus Operator Dashboard (`http://127.0.0.1:8090`) provides real-time telemetry, live 3-phase Byzantine Fault Tolerant (BFT) voting visualization, per-node O(1) RAM Firewall inspection, chaos fault injection, and elastic Kubernetes StatefulSet scaling.

## Quick Start

Start the 5-node cluster and dashboard container:

```powershell
docker compose up --build -d
```

Then open **http://127.0.0.1:8090** in your browser.

**Operator token.** Stop, revive, settings and trust call node operator routes that require `X-Operator-Token`. Nodes and the dashboard read the same `FEDCONSENSUS_OPERATOR_TOKEN`. `start-cluster.bat` writes a random one to the gitignored `.env` and docker compose passes it through; a host-run dashboard (`python -m dashboard.server`) reads it from the environment or from `.env`. On Kubernetes: `kubectl create secret generic fedconsensus-operator --from-literal=token=<random>`, then export the same value for the dashboard. Without a token the nodes answer 403.

**Trust recovery.** After 60 s with no new violation, any score below 100 (including one set with the trust control) rises by +5 every 30 s. A node at 0 can vote again (≥ 30) after about 210 s; one at 20 after about 90 s.

---

## Operator Console Features

### 1. Attack & Traffic Simulator (`POST /inbox`)
- **Target / Receiving Node:** Choose any node in the consortium (`fednode-0`..`N`) to receive the ActivityPub post. Whichever node receives a malicious post (`score >= 0.60`) automatically becomes the **Active Proposer (`★`)** for that consensus round and broadcasts a signed `BlockProposal` over gRPC.
- **Traffic Origin (`External Server` vs. `Internal Nodes`):**
  - **External Server (Internet):** Simulates an external Fediverse server sending benign notes, phishing bursts, malware-link text (`.exe`), or custom post text.
  - **Internal Nodes:** Choose any consortium peer (e.g., `fednode-1`, `fednode-2`, etc.) to act as a compromised internal server sending malicious traffic to the Target Node. Internal attacks animate node-to-node across the mesh ring, trigger a BFT vote on the sender's domain, and **automatically quarantine the internal attacker** (slashing its trust score to `20`).

### 2. Chaos Lab (Faults & Self-Healing)
- **Simulate Voting Behavior (`Honest` / `Silent` / `Liar` / `Forger`):**
  - `Honest (NONE)`: Verifies Ed25519 signatures and threat scores (`>= 0.60`) and votes `APPROVE`.
  - `Silent`: Drops gRPC requests to simulate packet loss or network partition.
  - `Liar`: Intentionally votes `REJECT` on verified threats to test Byzantine masking.
  - `Forger`: Corrupts its Ed25519 ballot signature; the consensus engine detects the invalid signature, rejects the ballot as `Forged`, and **automatically penalizes the node's reputation score (`-50`)**.
- **Crash & Self-Healing (`Kill node` / `Revive`):**
  - Killing a node takes it offline. If a domain is banned while the node is offline, clicking that node in the mesh and opening its **`Banned Domains · RAM`** tab highlights the missed ban as `× Missing (Offline)`.
  - Clicking **`Revive (Self-heal)`** brings the node back online, triggers `gRPC CatchupSync` with verification of the Ed25519 Quorum Certificate, and updates its local O(1) RAM Firewall to `✓ Active in RAM`.

### 3. K8s Autoscaling & Organisations
- **`+ Add organisation node`:** Onboards a new federated organisation server (e.g., `ntu.social`, `oxford.social`) into the consortium ring and syncs historical bans into its O(1) RAM Firewall via `CatchupSync`.
- **`⚡ Auto-scale (+2)`:** Elastically scales the Kubernetes StatefulSet by `+2` replicas with no upper limit and dynamically recalculates fault tolerance `f = (N - 1) // 3` and required quorum `Q = N - f`.
- **`Reset to 5 nodes`:** Scales the cluster back to the base 5 consortium nodes (`N=5, f=1, Q=4`).

---

## Verification Commands

```powershell
python tests/phase4/test_dashboard_verify.py
python tests/phase4/test_dashboard_controls.py
python tests/phase4/test_dashboard_node_verify.py
node tests/phase4/test_dashboard_routes.cjs
node --check dashboard/static/app.js
```
