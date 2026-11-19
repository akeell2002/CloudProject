# FedConsensus Operator Dashboard

The operator dashboard (`http://127.0.0.1:8090`) displays live cluster telemetry, 3-phase BFT voting activity, per-node firewall state, and interactive controls for traffic simulation, fault injection, and cluster scaling.

## Setup

Start the 5-node Docker cluster and dashboard:

```powershell
.\start-cluster.bat
```

Once `.env` contains `FEDCONSENSUS_OPERATOR_TOKEN`, `docker compose up --build -d` works directly. To run the dashboard on the host:

```powershell
python -m dashboard.server --port 8091
```

### Operator Token

Node operator endpoints (`/fault`, `/reputation`, `/peers`) require `X-Operator-Token` matching `FEDCONSENSUS_OPERATOR_TOKEN`. Both the nodes and dashboard read the same token from the environment or `.env`. On Kubernetes, create the secret with `kubectl create secret generic fedconsensus-operator --from-literal=token=<random>` and export the same value for a host-run dashboard. Nodes return HTTP 403 if the token is missing or wrong.

### Trust Recovery

After 60 s with no new violation, any peer score below 100 rises by +5 every 30 s. A peer at 0 reaches the voting threshold (`>= 30`) after about 210 s; one at 20 recovers after about 90 s.

## Features

- **Traffic Attack Simulator (`POST /inbox`):** Send benign posts, phishing bursts, malware links, false-flag framing tests, or custom payloads to any target node from either an external domain or an internal consortium node.
- **Chaos & Faults:** Switch any node between `Honest (NONE)`, `Censor`, `Equivocator`, `Liar`, and `Forger` modes, kill or revive nodes to test `CatchupSync` state replay, and reset peer trust scores.
- **Scale Cluster:** Onboard additional platform nodes or auto-scale up to 8 nodes and reset back to 5 nodes, syncing historical bans via `CatchupSync` and recalculating quorum thresholds.

## Tests

```powershell
python tests/phase4/test_dashboard_verify.py
python tests/phase4/test_dashboard_controls.py
python tests/phase4/test_dashboard_node_verify.py
node tests/phase4/test_dashboard_routes.cjs
node --check dashboard/static/app.js
```
