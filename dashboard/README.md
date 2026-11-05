# FedConsensus live operator dashboard

The dashboard is an adapter to the team's existing backend. It does not modify
node source, protobuf contracts, quorum rules, leader logic, or consensus state
machines. Scripted demo mode has been removed.

## Start

Run start-cluster.bat from the project folder. It starts the Compose services and runs the host dashboard on
http://127.0.0.1:8091. Keep that terminal open.

For manual startup:

    docker compose up --build -d
    python -m dashboard.server --port 8091

Compose also serves a dashboard at localhost:8090. Use the host version on 8091
for runtime controls: the dashboard container deliberately has no Docker socket
or privileged host access.

Click **Connect backend**, then choose **Act as node**. This changes the identity
used by supported operator actions; it does not make that node the leader.

## Working actions and their backend connections

| UI action | Actual operation |
|---|---|
| Benign / phishing / malware-link / custom text | HTTP POST to the existing /inbox route. Payloads are inert text. |
| External source | The operator sends the post with the requested actor domain. The existing backend decides whether/how to verify that claim. |
| Internal source | Docker/Kubernetes exec sends the HTTP request from the selected node using Python's HTTP client. |
| Custom domain proposal | The selected node signs the existing proposal metadata using its existing signing helper, then the dashboard calls ProposeDefederation on configured nodes. |
| Approve / reject | The selected node signs the existing ballot format, then CastVote is called on the proposal's selected observer. |
| Trust adjustment | The selected/all reachable nodes execute the existing Database.update_reputation helper against their existing SQLite database. No new trust rules are introduced. |
| Fault mode | For the original five Docker services, a temporary Compose override restarts the selected service with its existing BYZANTINE_MODE environment setting. |
| Kill / revive | Stops/starts the named managed Docker container. Kubernetes deletes the named fednode pod; the StatefulSet recreates it. |
| Scale replicas | Changes real runtime replicas and the dashboard's observed endpoint list. Existing data volumes are retained. |

Signing and gRPC clients run inside the existing node runtime. Private keys and
signatures are not returned to the browser. Runtime commands use fixed argument lists and fixed node IDs,
not user-supplied shell commands. Traffic links are never opened or executed.

## Backend capabilities that are not exposed

Leader assignment, a manual/automatic voting switch, an origin-signature
injection API, and a live catch-up trigger are not exposed by the current
backend. Those controls are visibly unavailable. Their implementation belongs
to the backend team.

The existing backend's peer-key registration and vote/commit transport gaps
remain. A proposal can be accepted locally without reaching quorum. A ballot
can be acknowledged but excluded by signature or trust checks. The dashboard
reports these observations instead of manufacturing votes or bans.

Scaling containers/pods does not update the backend's configured voting
membership, peer addresses, or quorum. Additional nodes are shown as real
runtime instances, but the backend team must implement membership changes
before claiming that they are integrated voting members.

## Runtime selection

Docker is the default. The UI can select Kubernetes when kubectl can reach the
fednode StatefulSet in the chosen context. Set DASHBOARD_NAMESPACE before
startup if the namespace is not default.

Local Kubernetes port-forwards use HTTP ports 18080–18088 and gRPC ports
51051–51059, separate from Docker's ports. Only dashboard-owned port-forward
processes are stopped on dashboard shutdown.

The runtime must already contain the team's node image and configuration.
Unavailable runtime permissions are shown as unavailable controls.

## What the screen means

- Active means reachable, not trustworthy. Inactive means unreachable.
- The permanent external-server card retains the last external sender in this
  dashboard session, including while nodes exchange votes.
- Votes belong to the selected observer; separate nodes' partial vote totals
  are not added together.
- Quarantine is reported with the names of the observing ledgers. It is not
  presented as a globally agreed trust percentage.
- The banned list shows per-node reported coverage. Offline coverage is
  explicitly last-known.

Recent observations are bounded in memory. Existing node data remains in the
team's SQLite volumes. The local .operator-state.json file remembers which
runtime endpoints the dashboard should observe; it contains no signing keys.

## Local access and checks

Operator actions require localhost access, a matching Origin, and the
dashboard session's CSRF token. Keep this lab console on localhost. Access to
the Docker/Kubernetes runtime grants powerful control over the named lab
nodes; no arbitrary shell-command endpoint is exposed.

    python -B -m unittest discover -s tests/phase4 -p test_dashboard_controls.py -v
    python -B -m unittest discover -s tests/phase4 -p test_dashboard_verify.py -v
    node tests/phase4/test_dashboard_routes.cjs
    node --check dashboard/static/app.js
