"""Bounded, read-only observations for the local operator dashboard."""
import os
import threading
import time
import uuid
from collections import deque

from node.config import peer_id_from_addr


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


REACHABILITY_FRESH_MS = 15_000


def _is_quarantined(row):
    try:
        return row.get("trust_score", 100) < 30 or row.get("is_active", 1) == 0
    except TypeError:
        return False


def quorum_health(service, ledger=None):
    """Local view of how many consortium members can vote right now.

    Returns None when the service has no peer list (e.g. lightweight stubs).
    A member counts as offline only when the latest catch-up attempt failed
    within REACHABILITY_FRESH_MS; missing or stale data counts as online.
    """
    config = getattr(service, "config", None)
    peers = getattr(config, "peers", None)
    if not isinstance(peers, list):
        return None
    self_id = getattr(config, "node_id", None)
    members = {peer_id_from_addr(str(addr)) for addr in peers}
    if self_id:
        members.add(self_id)

    now_ms = int(time.time() * 1000)
    catchup = getattr(service, "catchup", None)
    try:
        reachability = dict(getattr(catchup, "peer_reachability", None) or {})
    except (TypeError, ValueError, RuntimeError):
        reachability = {}
    offline = set()
    for member in members:
        if member == self_id:
            continue
        entry = reachability.get(member)
        if not isinstance(entry, dict) or entry.get("reachable") is not False:
            continue
        checked_at = entry.get("checked_at")
        if isinstance(checked_at, (int, float)) and now_ms - checked_at <= REACHABILITY_FRESH_MS:
            offline.add(member)

    if ledger is None:
        reputation = getattr(service, "reputation", None)
        get_ledger = getattr(reputation, "get_ledger", None)
        ledger = get_ledger() if callable(get_ledger) else []
    quarantined = {
        row.get("peer_id") for row in (ledger or [])
        if isinstance(row, dict) and row.get("peer_id") in members and _is_quarantined(row)
    }
    if self_id and getattr(getattr(service, "leader", None), "self_quarantined_by_peers", False):
        quarantined.add(self_id)

    total_nodes = getattr(config, "total_nodes", None) or max(len(peers), 1)
    active_voting_nodes = max(1, total_nodes - len(quarantined))
    max_faults = (active_voting_nodes - 1) // 3
    mode = os.getenv("QUORUM_MODE", "STRICT").upper()
    quorum = max(1, (2 * max_faults + 1) if mode == "MAJORITY" else (active_voting_nodes - max_faults))
    eligible = members - offline - quarantined
    return {
        "total_nodes": total_nodes,
        "active_voting_nodes": active_voting_nodes,
        "max_faults": max_faults,
        "quorum": quorum,
        "eligible_voters": len(eligible),
        "eligible": sorted(eligible),
        "offline": sorted(offline),
        "quarantined": sorted(quarantined),
        "quorum_reachable": len(eligible) >= quorum,
    }


def _quorum_state(committed, health):
    if committed:
        return "committed"
    if health is not None and not health["quorum_reachable"]:
        return "quorum_unreachable"
    return "awaiting"


def node_snapshot(service):
    """Expose state without signatures, private keys, or raw evidence payloads."""
    engine = service.consensus
    events = engine.telemetry.snapshot()
    ledger = service.reputation.get_ledger()
    health = quorum_health(service, ledger)
    with engine._lock:
        # Keep the snapshot bounded to the latest 50 proposals.
        proposals = [
            {
                "proposal_id": p.proposal_id,
                "domain": p.target_domain,
                "proposer": getattr(p.request, "proposer_id", "") if getattr(p, "request", None) else service.config.node_id,
                "reason": p.reason,
                "epoch": p.epoch,
                "sequence": p.sequence_number,
                "created_at": int(p.created_at * 1000),
                "committed": p.is_committed,
                "latency_ms": getattr(p, "latency_ms", None) or 0,
                "threat_score": getattr(p, "threat_score", 0.85),
                "approvals": sorted(p.approved_votes),
                "rejections": sorted(
                    k for k, v in getattr(p, "recorded_decisions", {}).items()
                    if v == 2 and k not in getattr(p, "invalid_voters", set())
                ),
                "invalids": sorted(getattr(p, "invalid_voters", set())),
                "equivocators": sorted(getattr(p, "equivocator_voters", set())),
                "quarantined": sorted(getattr(p, "quarantined_voters", set())),
                "quorum": getattr(p, "quorum_threshold", None) or service.config.quorum_size,
                "observer": service.config.node_id,
                "quorum_state": _quorum_state(p.is_committed, health),
            }
            for p in list(engine.active_proposals.values())[-50:]
        ]
    is_leader = bool(service.leader.is_current_leader())
    state = "LEADER" if is_leader else "FOLLOWER"
    if service.byzantine_mode != "NONE":
        state = "BYZANTINE_" + service.byzantine_mode
    return {
        "node_id": service.config.node_id,
        "org": getattr(service.config, "org_domain", f"{service.config.node_id}.social"),
        "state": state,
        "is_leader": is_leader,
        "epoch": service.leader.current_epoch,
        "last_sequence": service.db.get_latest_sequence_number(),
        "quorum": health["quorum"] if health else service.config.quorum_size,
        "operational_mode": service.config.operational_mode,
        "reputations": ledger,
        "blocked_domains": sorted(service.firewall.get_blocked_domains()),
        "proposals": proposals,
        "events": events,
        "quorum_health": health,
    }
