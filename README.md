# FedConsensus

FedConsensus is a Byzantine-fault-tolerant (BFT) consensus engine for automated domain-level moderation across federated ActivityPub instances. Instead of sharing manual blocklists over chat or spreadsheets, consortium nodes verify incoming abuse evidence and vote over gRPC using Ed25519 signatures to commit domain bans across the cluster.

## Quick Start

Start the 5-node cluster and operator dashboard with Docker:

```powershell
.\start-cluster.bat
```

On first run, `start-cluster.bat` generates a random `FEDCONSENSUS_OPERATOR_TOKEN` in `.env` (gitignored) and launches the containers. Once `.env` exists, `docker compose up --build -d` works directly. To wipe volumes and start fresh, run `.\clean-cluster.bat`.

Open the dashboard at `http://127.0.0.1:8090`. To run the dashboard on the host instead of in Docker:

```powershell
python -m dashboard.server --port 8091
```

See [dashboard/README.md](dashboard/README.md) for dashboard controls and setup details.

### Operator Token

Node operator endpoints (`POST /fault`, `POST /reputation`, `POST /peers`) require an `X-Operator-Token` header matching `FEDCONSENSUS_OPERATOR_TOKEN`. Requests without a valid token return HTTP 403.

On Kubernetes, create the secret before deploying:

```bash
kubectl create secret generic fedconsensus-operator --from-literal=token=<random-hex>
```

## Architecture

Each node runs two servers (`node/main.py`):

- **External HTTP (port 8080):** Receives ActivityPub `POST /inbox` traffic, health checks (`GET /health`), telemetry (`GET /telemetry`), and token-gated operator routes.
- **Internal gRPC mesh (port 50051):** Handles peer-to-peer consensus RPCs (`ProposeDefederation`, `CastVote`, `CommitDefederation`, `Heartbeat`, `ImpeachLeader`, `CatchupSync`, `GetStatus`).

### Moderation Flow

1. **Perimeter Firewall (`node/ingress/firewall.py`):** Checks the sender domain against an in-memory blocklist set. Already-banned domains are dropped with HTTP 403 before further processing.
2. **Threat Classifier (`node/ingress/classifier.py`):** Scores posts based on request burst velocity, executable/archive file links, and phishing keywords. Posts scoring `>= 0.60` escalate to consensus; benign posts return HTTP 202.
3. **3-Phase BFT Consensus (`node/engine/consensus.py`):**
   - **Propose:** The current epoch leader builds and signs a proposal (followers forward detected threats to the leader).
   - **Prepare / Vote:** Peers verify the proposer's Ed25519 signature, audit the origin HTTP signature (`node/crypto/http_sig.py`) to block false-flag framing, re-check the evidence payload, and return signed ballots.
   - **Commit:** Once `Q = N - f` valid votes are collected (where `f = (N - 1) // 3`, so `Q = 4` for `N = 5`), a Quorum Certificate is written to SQLite WAL (`node/storage/database.py`) and enforced in the firewall.
4. **Fault Handling & Recovery:**
   - **Reputation (`node/storage/reputation.py`):** Peer trust scores start at 100 and drop on equivocation (-50), signature forgery (-40), censorship (-30), bogus evidence (-25), or dissenting votes on valid threats (-15). Peers below 30 are quarantined from voting. After 60 s without new violations, scores below 100 recover by +5 every 30 s.
   - **Leader Failover (`node/engine/leader.py`):** Leaders renew a 5 s lease via signed heartbeats. If a leader crashes or ignores forwarded threats for 3 s, followers impeach it and advance the epoch.
   - **Catch-up Sync (`node/engine/catchup.py`):** Restarted or newly joined nodes pull missed records via `CatchupSync`, verify each Quorum Certificate, and replay them locally.

## Project Layout

```text
cli/
  fedctl.py              Operator CLI (status, peers, propose)
dashboard/
  server.py              Dashboard HTTP server and telemetry poller
  control.py             Lab traffic, fault injection, and scaling adapters
  runtime.py             Docker and Kubernetes runtime helpers
  static/                Frontend UI (HTML, CSS, JS)
node/
  main.py                Dual HTTP + gRPC node entrypoint and background loops
  service.py             gRPC servicer and Byzantine fault modes
  config.py              Node configuration, key persistence, quorum math
  telemetry.py           Read-only state snapshots for the dashboard
  crypto/                Ed25519 signing/hashing and origin HTTP signature audit
  ingress/               In-memory firewall, heuristic classifier, /inbox handler
  engine/                BFT consensus state machine, leader leases, catch-up sync
  storage/               SQLite WAL persistence and peer reputation ledger
proto/
  fedconsensus.proto     gRPC service and message definitions
k8s/
  configmap.yaml         Cluster ports and peer mesh addresses
  service-headless.yaml  Headless Service (clusterIP: None) for direct pod DNS
  statefulset.yaml       5-replica StatefulSet with Downward API and probes
  pvc.yaml               PersistentVolumeClaim template for SQLite storage
benchmarks/
  benchmark_runner.py    Standalone latency, fault, and recovery benchmarks
  generate_graphs.py     Matplotlib chart generator for benchmark runs
tests/
  phase1/ - phase4/      Unit and component tests
  end_to_end_testing/    Consensus, Byzantine fault, and scenario tests
```

## Operator CLI & Kubernetes

Install Python dependencies for local CLI, testing, or host-run dashboard:

```powershell
pip install -r requirements.txt
```

Inspect a running node or submit a manual proposal:

```powershell
python cli/fedctl.py --target localhost:50051 status
python cli/fedctl.py --target localhost:50051 peers
python cli/fedctl.py --target localhost:50051 propose spam-botnet.net --reason BOTNET
```

Deploy to Kubernetes:

```bash
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/service-headless.yaml
kubectl apply -f k8s/statefulset.yaml
```

## Benchmarks & Tests

See [benchmarks/README.md](benchmarks/README.md) for running standalone performance benchmarks and generating charts.

Run the verification suites from the repo root:

```powershell
# Component suites
python tests/phase1/test_phase1_verification.py
python tests/phase2/test_phase2_verification.py
python tests/phase3/test_phase3_verification.py
python tests/phase4/test_phase4_verification.py

# Dashboard tests
python tests/phase4/test_dashboard_verify.py
python tests/phase4/test_dashboard_controls.py
python tests/phase4/test_dashboard_node_verify.py
node tests/phase4/test_dashboard_routes.cjs

# End-to-end BFT and chaos scenarios
python tests/end_to_end_testing/test_consensus.py
python tests/end_to_end_testing/test_byzantine.py
python tests/end_to_end_testing/test_scenarios.py
python tests/end_to_end_testing/test_follower_threat_escalation.py
```
