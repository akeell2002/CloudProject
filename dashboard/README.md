# Federation dashboard

A read-only operator view inspired by Raft's network visualization and the existing
fedctl status/peer commands. No frontend framework or Python packages are needed
to run the dashboard itself.

## Start locally

Run the start-cluster.bat file, then an IP address will be shown copy it onto a new tab in
you google chrome, firefox wtv, then you will be able to see the website. {Make sure docker application is correct}

## Reading the screen

- **Live cluster** is the default. It never invents votes or bans.
- **Guided demo** is an explicitly labelled, browser-local illustration. It sends
  nothing to your nodes. Watch a suspicious attachment trigger a proposal, four
  approvals, a reported block, and a blocked repeat message. Replay restarts it.
- **Active** means the node's HTTP endpoint is reachable. It does not prove the
  node is honest or eligible to vote. **Inactive** means unreachable, not proof
  that an administrator deliberately deactivated it.
- Click a node to inspect its role, committed sequence, and its own reputation
  ledger. Trust is not presented as a global percentage.
- The threat panel shows one named observer's proposal state at a time. Counts
  are not added across observers. Invalid ballots, rejection, offline nodes,
  and waiting are shown separately.
- Banned-domain coverage lists nodes currently reporting the block. Data kept
  from unreachable nodes is explicitly last-known.
- Activity lists claimed sender domains, receiving nodes, proposals, and votes.
  The network diagram labels external senders and non-node destinations, with
  directional arrows. Flagged traffic is red. The latest route stays visible
  after its animation ends, so its source remains clear.
  The external-server card stays visible while nodes vote or commit. It retains
  the last sender within the current live/demo session; before traffic it shows
  "Waiting for traffic". Switching modes resets that remembered sender.
  No links or attachments are executed. Raw post bodies, signing keys, and
  signatures are not included in telemetry.

## Limits

This is a dashboard, not a replacement consensus implementation. Existing
peer registration, voting transport, leader failover, and proof-validation
limitations remain. Missing votes remain waiting; telemetry cannot establish
the security of a reported commit.

Recent activity is in memory (200 events per node, 300 in the dashboard) and
resets when its process restarts. Node proposal snapshots show the latest 50
tracked proposals. Persistent blocklists remain in the existing SQLite database.

The /telemetry route is read-only operational metadata on each node's existing
HTTP port. Keep node HTTP endpoints on a trusted demonstration/operator network;
this change does not add Internet-facing authentication. The dashboard listens
on loopback by default and serves only its fixed static files and JSON API.

## Checks

    python -B -m unittest discover -s tests/phase4 -p test_dashboard_verify.py -v
    node tests/phase4/test_dashboard_demo.cjs
    node tests/phase4/test_dashboard_routes.cjs
    node --check dashboard/static/app.js
