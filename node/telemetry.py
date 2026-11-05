"""Bounded, read-only observations for the local operator dashboard."""
import threading
import time
import uuid
from collections import deque


class EventLog:
    def __init__(self, node_id, limit=200):
        self.node_id = node_id
        self.boot_id = uuid.uuid4().hex
        self._events = deque(maxlen=limit)
        self._sequence = 0
        self._lock = threading.Lock()

    def record(self, kind, source, target, message, **fields):
        with self._lock:
            self._sequence += 1
            event = {
                "id": f"{self.node_id}:{self.boot_id}:{self._sequence}",
                "timestamp": int(time.time() * 1000),
                "kind": kind,
                "source": str(source)[:200],
                "target": str(target)[:200],
                "message": str(message)[:400],
                "observer": self.node_id,
                **fields,
            }
            self._events.append(event)

    def snapshot(self):
        with self._lock:
            return [dict(event) for event in self._events]


def node_snapshot(service):
    """Expose state without signatures, private keys, or raw evidence payloads."""
    engine = service.consensus
    events = engine.telemetry.snapshot()
    with engine._lock:
        # shortcut: show the latest 50 proposals; use paginated history for larger deployments.
        proposals = [
            {
                "proposal_id": p.proposal_id,
                "domain": p.target_domain,
                "reason": p.reason,
                "epoch": p.epoch,
                "sequence": p.sequence_number,
                "created_at": int(p.created_at * 1000),
                "committed": p.is_committed,
                "approvals": sorted(p.approved_votes),
                "quorum": service.config.quorum_size,
                "observer": service.config.node_id,
            }
            for p in list(engine.active_proposals.values())[-50:]
        ]
    state = "LEADER" if service.leader.is_current_leader() else "FOLLOWER"
    if service.byzantine_mode != "NONE":
        state = "BYZANTINE_" + service.byzantine_mode
    return {
        "node_id": service.config.node_id,
        "state": state,
        "epoch": service.leader.current_epoch,
        "last_sequence": service.db.get_latest_sequence_number(),
        "quorum": service.config.quorum_size,
        "operational_mode": service.config.operational_mode,
        "reputations": service.reputation.get_ledger(),
        "blocked_domains": sorted(service.firewall.get_blocked_domains()),
        "proposals": proposals,
        "events": events,
    }
