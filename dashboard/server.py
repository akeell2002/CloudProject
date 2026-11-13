"""Local live operator dashboard. Start with: python -m dashboard.server"""
import argparse
import json
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener
from dashboard.control import Operator

STATIC = Path(__file__).parent / "static"


def validate_telemetry(data):
    """Fail one bad node's observation instead of breaking the whole dashboard."""
    def text(value):
        return isinstance(value, str) and len(value) <= 1000

    for key in ("node_id", "state"):
        if not text(data.get(key)):
            raise ValueError("Invalid node identity or state")
    for key in ("epoch", "quorum", "last_sequence"):
        if type(data.get(key)) is not int or data[key] < 0:
            raise ValueError("Invalid numeric node state")
    if not 1 <= data["quorum"] <= 32:
        raise ValueError("Invalid quorum")
    for key in ("events", "proposals", "blocked_domains", "reputations"):
        if not isinstance(data.get(key), list):
            raise ValueError("Invalid telemetry collection")
    if not all(text(domain) for domain in data["blocked_domains"]):
        raise ValueError("Invalid blocked domain")
    for event in data["events"]:
        if not isinstance(event, dict) or any(
            not text(event.get(key)) for key in ("id", "kind", "source", "target", "message")
        ) or type(event.get("timestamp")) is not int:
            raise ValueError("Invalid event")
        if "decision" in event and event["decision"] not in ("APPROVE", "REJECT", "INVALID", "QUARANTINED"):
            raise ValueError("Invalid vote decision")
    for proposal in data["proposals"]:
        if not isinstance(proposal, dict) or any(
            not text(proposal.get(key)) for key in ("proposal_id", "domain", "observer")
        ):
            raise ValueError("Invalid proposal")
        if not isinstance(proposal.get("approvals"), list) or not all(text(v) for v in proposal["approvals"]):
            raise ValueError("Invalid approval list")
        if len(proposal["approvals"]) != len(set(proposal["approvals"])):
            raise ValueError("Duplicate approval identity")
        if type(proposal.get("quorum")) is not int or not 1 <= proposal["quorum"] <= 32:
            raise ValueError("Invalid proposal quorum")
        if type(proposal.get("created_at")) is not int or type(proposal.get("committed")) is not bool:
            raise ValueError("Invalid proposal state")
    for rep in data["reputations"]:
        if not isinstance(rep, dict) or not text(rep.get("peer_id")) or type(rep.get("trust_score")) is not int:
            raise ValueError("Invalid peer reputation")
        if not 0 <= rep["trust_score"] <= 100 or rep.get("is_active") not in (0, 1):
            raise ValueError("Invalid peer eligibility")


def configured_nodes(raw=None):
    addresses = raw if raw is not None else os.getenv(
        "DASHBOARD_NODES", ",".join(f"http://127.0.0.1:{8080 + i}" for i in range(5))
    )
    nodes = []
    for index, address in enumerate(addresses.split(",")):
        address = address.strip().rstrip("/")
        parsed = urlsplit(address)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username:
            raise ValueError("DASHBOARD_NODES must be comma-separated HTTP(S) node addresses")
        if parsed.path or parsed.query or parsed.fragment:
            raise ValueError("Node addresses must not contain a path, query, or fragment")
        nodes.append({"node_id": f"fednode-{index}", "address": address})
    if not nodes or len(nodes) > 32:
        raise ValueError("Configure between 1 and 32 nodes")
    return nodes


class ClusterMonitor:
    def __init__(self, nodes, timeout=1.2):
        self.nodes = nodes
        self.timeout = timeout
        self._lock = threading.Lock()
        self._data = {"nodes": [], "events": [], "bans": [], "updated_at": None, "quorum_health": None}
        self._last_known = {}
        self._events = {}
        self._executor = ThreadPoolExecutor(max_workers=len(nodes))
        self._opener = build_opener(ProxyHandler({}))

    def _json(self, address):
        with self._opener.open(Request(address, headers={"Accept": "application/json"}),
                               timeout=self.timeout) as response:
            body = response.read(2_000_001)
            if len(body) > 2_000_000:
                raise ValueError("Telemetry response exceeds size limit")
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object")
            return data

    def _poll(self, node):
        now = int(time.time() * 1000)
        base = {**node, "online": False, "telemetry_available": False, "checked_at": now}
        try:
            try:
                data = self._json(node["address"] + "/telemetry")
            except HTTPError as error:
                if error.code != 404:
                    raise
                health = self._json(node["address"] + "/health")
                return {**base, "node_id": health.get("node_id", node["node_id"]),
                        "online": True, "state": "UNKNOWN", "error": "Restart node to enable telemetry"}
            validate_telemetry(data)
            return {**data, **base, "node_id": data["node_id"], "online": True,
                    "telemetry_available": True, "last_seen": now}
        except (OSError, URLError, ValueError, TypeError):
            return {**base, "state": "OFFLINE", "error": "Node unreachable or telemetry unavailable"}

    def refresh(self):
        observations = list(self._executor.map(self._poll, self.nodes))
        bans = {}
        for node in observations:
            address = node["address"]
            if node["online"] and node["telemetry_available"]:
                self._last_known[address] = node.copy()
                for event in node["events"]:
                    if isinstance(event, dict) and isinstance(event.get("id"), str):
                        self._events[event["id"]] = {**event, "observer": node["node_id"]}
            elif address in self._last_known:
                previous = self._last_known[address]
                node["node_id"] = previous["node_id"]
                node["last_seen"] = previous["last_seen"]
                node["last_known_state"] = previous["state"]
                node["last_sequence"] = previous["last_sequence"]
                node["blocked_domains"] = previous["blocked_domains"]
                node["reputations"] = previous["reputations"]
            for domain in node.get("blocked_domains", []):
                if not isinstance(domain, str):
                    continue
                entry = bans.setdefault(domain, {"domain": domain, "applied_on": [], "last_known_on": []})
                entry["applied_on" if node["online"] and node["telemetry_available"]
                      else "last_known_on"].append(node["node_id"])
        cluster_reps = {}
        for observer in observations:
            if not observer.get("online"):
                continue
            for rep in observer.get("reputations", []):
                pid = rep["peer_id"]
                if pid not in cluster_reps or rep["trust_score"] < cluster_reps[pid]["trust_score"]:
                    cluster_reps[pid] = dict(rep)
        if cluster_reps:
            for node in observations:
                if node.get("online") and node.get("telemetry_available"):
                    merged = {r["peer_id"]: dict(r) for r in node.get("reputations", [])}
                    for pid, crep in cluster_reps.items():
                        if pid not in merged or crep["trust_score"] < merged[pid]["trust_score"]:
                            merged[pid] = dict(crep)
                    node["reputations"] = list(merged.values())
        for node in observations:
            observers = [
                observer["node_id"] for observer in observations if observer["online"]
                and observer["node_id"] != node["node_id"]
                for rep in observer.get("reputations", [])
                if rep["peer_id"] == node["node_id"] and
                    (rep["trust_score"] < 30 or not rep["is_active"])
            ]
            node["quarantined_by"] = observers
            node["quarantined"] = bool(observers)
        quorum_health = self._quorum_health(observations)
        # shortcut: retain the latest 300 observations in memory; add durable history if required.
        events = sorted(self._events.values(), key=lambda e: e.get("timestamp", 0))[-300:]
        self._events = {event["id"]: event for event in events}
        with self._lock:
            self._data = {
                "nodes": observations, "events": events,
                "bans": sorted(bans.values(), key=lambda b: b["domain"]),
                "updated_at": int(time.time() * 1000),
                "quorum_health": quorum_health,
            }

    @staticmethod
    def _quorum_health(observations):
        """Cluster-wide liveness view from the dashboard's own observations of every node."""
        members = [node["node_id"] for node in observations]
        offline = sorted({node["node_id"] for node in observations if not node.get("online")})
        quarantined = sorted({node["node_id"] for node in observations if node.get("quarantined")})
        total = len(members)
        reported = [node.get("quorum") for node in observations
                    if node.get("online") and node.get("telemetry_available")
                    and type(node.get("quorum")) is int and node.get("quorum") > 0]
        quorum = max(reported) if reported else total - (total - 1) // 3
        eligible = sorted(set(members) - set(offline) - set(quarantined))
        reachable = len(eligible) >= quorum
        pending, committed = set(), set()
        if not reachable:
            for node in observations:
                if not (node.get("online") and node.get("telemetry_available")):
                    continue
                proposals = node.get("proposals")
                for proposal in proposals if isinstance(proposals, list) else []:
                    if not isinstance(proposal, dict) or not isinstance(proposal.get("domain"), str):
                        continue
                    (committed if proposal.get("committed") is True else pending).add(proposal["domain"])
        return {
            "total_nodes": total, "quorum": quorum,
            "eligible_voters": len(eligible), "eligible": eligible,
            "offline": offline, "quarantined": quarantined,
            "quorum_reachable": reachable,
            "pending_unreachable": sorted(pending - committed),
        }

    def snapshot(self):
        with self._lock:
            return self._data

    def close(self):
        self._executor.shutdown(wait=True, cancel_futures=True)


def make_handler(monitor, operator=None):
    class DashboardHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(STATIC), **kwargs)

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; style-src 'self'; "
                             "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                             "base-uri 'none'; frame-ancestors 'none'")
            super().end_headers()

        def do_GET(self):
            route = urlsplit(self.path).path
            if route in ("/api/cluster", "/api/controls"):
                if urlsplit("http://" + self.headers.get("Host", "")).hostname not in ("127.0.0.1", "localhost", "::1"):
                    return self.send_error(403, "Operator UI requires a localhost address")
                data = monitor.snapshot() if route == "/api/cluster" else (
                    operator.state() if operator else {"enabled": False, "message": "Controls unavailable"})
                body = json.dumps(data).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif route in ("/", "/index.html", "/style.css", "/app.js"):
                self.path = "/index.html" if route == "/" else route
                super().do_GET()
            else:
                self.send_error(404)

        def do_POST(self):
            def respond(status, data):
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            if self.path != "/api/actions" or not operator:
                return respond(404, {"error": "Unknown action route"})
            host = self.headers.get("Host", "")
            origin = self.headers.get("Origin")
            if (urlsplit("http://" + host).hostname not in ("localhost", "127.0.0.1", "::1")
                or (origin and urlsplit(origin).netloc != host)
                or not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), operator.csrf)):
                return respond(403, {"error": "Use this dashboard's local controls"})
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return respond(415, {"error": "Expected application/json"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 0 < length <= 16384:
                    return respond(413, {"error": "Action request is too large"})
                request = json.loads(self.rfile.read(length))
                if not isinstance(request, dict):
                    raise ValueError("Expected a JSON object")
                result = operator.handle(request)
                return respond(200, result)
            except (ValueError, KeyError, TypeError) as error:
                return respond(400, {"error": str(error)})
            except RuntimeError as error:
                return respond(409, {"error": str(error)})
            except OSError:
                return respond(503, {"error": "Local runtime or state storage is unavailable"})

        def log_message(self, *_):
            pass
    return DashboardHandler


def main():
    parser = argparse.ArgumentParser(description="FedConsensus read-only operator dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    monitor = ClusterMonitor(configured_nodes())
    operator = Operator(monitor)
    monitor.refresh()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(monitor, operator))
    stop = threading.Event()

    def poll():
        while not stop.wait(2):
            monitor.refresh()

    worker = threading.Thread(target=poll, daemon=True)
    worker.start()
    print(f"FedConsensus dashboard: http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        worker.join()
        server.server_close()
        monitor.close()
        operator.close()


if __name__ == "__main__":
    main()
