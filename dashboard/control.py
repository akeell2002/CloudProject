"""UI adapters for existing backend APIs and operator-authorized lab operations."""
import json
import re
import secrets
import threading
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from dashboard.runtime import Runtime, ROOT

DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class Operator:
    def __init__(self, monitor, runtime=None, state_path=None):
        self.monitor = monitor
        self.csrf = secrets.token_urlsafe(32)
        self.runtime = runtime or Runtime()
        self.runtime_status = self.runtime.capabilities()
        self.connected = False
        self._lock = threading.Lock()
        self.opener = build_opener(ProxyHandler({}))
        self.state_path = Path(state_path or Path(ROOT) / ".operator-state.json")
        if self.state_path.exists():
            saved = json.loads(self.state_path.read_text(encoding="utf-8"))
            if saved.get("runtime") == self.runtime.kind:
                self.monitor.nodes = saved["nodes"]

    def state(self):
        runtime_ready = self.runtime_status["available"]
        return {
            "enabled": True, "csrf": self.csrf, "connected": self.connected,
            "runtime": self.runtime_status, "replicas": len(self.monitor.nodes),
            "capabilities": {"traffic": True, "proposal": runtime_ready,
                "vote": runtime_ready, "trust": runtime_ready,
                "fault": runtime_ready and self.runtime.kind == "docker",
                "leader": False, "voting_mode": False, "sync": False},
            "message": "Connect to inspect the running backend. No backend logic is modified.",
            "limitations": "Leader assignment, voting-mode changes, and live catch-up need an API from the backend team.",
        }

    def node(self, node_id):
        if not isinstance(node_id, str) or not re.fullmatch(r"fednode-[0-8]", node_id):
            raise ValueError("Select a configured node")
        node = next((node for node in self.monitor.nodes if node["node_id"] == node_id), None)
        if not node:
            raise ValueError("Node is outside this cluster")
        return node

    def connect(self):
        if self.runtime.kind == "kubernetes":
            for index in range(len(self.monitor.nodes)):
                self.runtime.ensure_forward(index)
        self.monitor.refresh()
        self.runtime_status = self.runtime.capabilities()
        self.connected = any(node["online"] for node in self.monitor.snapshot()["nodes"])
        if not self.connected:
            raise RuntimeError("No backend node is reachable; start your cluster first")
        return {"message": "Connected to the existing backend. Its voting and membership rules are unchanged."}

    def addresses(self, count):
        template = self.monitor.nodes[0]["address"]
        nodes = []
        for index in range(count):
            if self.runtime.kind == "kubernetes" and urlsplit(template).hostname in ("127.0.0.1", "localhost"):
                address = f"http://127.0.0.1:{18080+index}"
                self.runtime.ensure_forward(index)
            elif "fednode-0" in template:
                address = template.replace("fednode-0", f"fednode-{index}")
            else:
                parsed = urlsplit(template)
                address = f"{parsed.scheme}://{parsed.hostname}:{8080+index}"
                self.runtime.ensure_forward(index)
            nodes.append({"node_id": f"fednode-{index}", "address": address})
        return nodes

    def inject(self, body):
        node = self.node(body.get("node"))
        scenario = body.get("scenario")
        templates = {
            "benign": "Hello from the federation security lab.",
            "phishing": "urgent security update: verify your account and confirm password",
            "malware": "Download the lab attachment: lab-update.exe",
            "custom": body.get("content", ""),
        }
        if scenario == "false_flag":
            raise RuntimeError("The backend inbox does not expose an origin-signature injection API")
        if scenario not in templates:
            raise ValueError("Unknown traffic scenario")
        content = templates[scenario]
        if not isinstance(content, str) or not 1 <= len(content) <= 2000:
            raise ValueError("Supply 1–2000 text characters")
        source = body.get("source", "external")
        if source not in ("external", "internal"):
            raise ValueError("Choose an external or internal lab source")
        source_node = body.get("source_node")
        if source == "internal":
            self.node(source_node)
        domain = str(body.get("domain", "")).strip().lower() or (
            f"{source_node}.lab.example" if source == "internal" else
            "glasgow.social" if scenario == "benign" else scenario + "-" + secrets.token_hex(3) + ".lab.example"
        )
        if not DOMAIN.fullmatch(domain):
            raise ValueError("Supply a valid sender domain")
        payload = {"actor": f"https://{domain}/users/lab-sender",
                   "object": {"type": "Note", "content": content}}
        count = 6 if scenario == "phishing" else 1
        results = []
        for _ in range(count):
            if source == "internal":
                results.append(self.runtime.node_call(source_node, {
                    "operation": "post", "receiver": node["node_id"], "payload": payload}))
                continue
            request = Request(node["address"] + "/inbox", data=json.dumps(payload).encode(),
                              headers={"Content-Type": "application/json"})
            try:
                with self.opener.open(request, timeout=8) as response:
                    results.append({"http_status": response.status, **json.load(response)})
            except HTTPError as error:
                if error.code not in (400, 403):
                    error.close()
                    raise RuntimeError("The backend inbox rejected the request") from None
                results.append({"http_status": error.code, **json.load(error)})
                error.close()
            except (OSError, URLError, ValueError):
                raise RuntimeError("The backend inbox could not be reached") from None
        return {"message": f"Sent {count} lab post(s) claiming source {domain} to {node['node_id']}",
                "domain": domain, "inbox_results": results}

    def signed_rpc(self, body):
        node_id = body.get("node")
        self.node(node_id)
        self.monitor.refresh()
        if body["action"] == "propose":
            domain = str(body.get("domain", "")).strip().lower()
            justification = str(body.get("justification", "")).strip()
            if not DOMAIN.fullmatch(domain) or not 1 <= len(justification) <= 1000:
                raise ValueError("Supply a valid target domain and 1–1000 justification characters")
            observations = self.monitor.snapshot()["nodes"]
            node = next(n for n in observations if n["node_id"] == node_id)
            sequences = [n.get("last_sequence", 0) for n in observations]
            sequences += [p["sequence"] for n in observations for p in n.get("proposals", [])]
            sequence = max(sequences, default=0) + 1
            epoch = node.get("epoch", 1)
            proposal_id = f"prop-ui-{epoch}-{sequence}-{secrets.token_hex(4)}"
            meta = {"proposal_id": proposal_id, "sequence_number": sequence, "epoch": epoch,
                    "target_domain": domain, "reason": 1, "threat_score": .95}
            result = self.runtime.node_call(node_id, {"operation": "propose", "meta": meta,
                "justification": justification, "targets": [node["node_id"] for node in self.monitor.nodes]})
            if result["node_id"] != node_id:
                raise RuntimeError("Runtime signing identity does not match the selected node")
            outcomes = result["outcomes"]
            accepted = sum(item["accepted"] for item in outcomes)
            self.monitor.refresh()
            return {"message": f"Existing RPC accepted the proposal on {accepted}/{len(outcomes)} nodes. This is not a committed ban.",
                    "proposal_id": proposal_id, "outcomes": outcomes, "accepted": accepted > 0}
        proposal_id = body.get("proposal_id")
        decision = body.get("decision")
        if decision not in ("APPROVE", "REJECT"):
            raise ValueError("Choose APPROVE or REJECT")
        receiver = body.get("receiver")
        self.node(receiver)
        node = next(n for n in self.monitor.snapshot()["nodes"] if n["node_id"] == receiver)
        proposal = next((p for p in node.get("proposals", []) if p["proposal_id"] == proposal_id), None)
        if not proposal or proposal["committed"]:
            raise ValueError("Select a pending proposal and its observing node")
        meta = {"proposal_id": proposal_id, "sequence_number": proposal["sequence"],
                "epoch": proposal["epoch"], "target_domain": proposal["domain"], "decision": decision}
        result = self.runtime.node_call(node_id, {"operation": "vote", "meta": meta, "receiver": receiver})
        if result["node_id"] != node_id:
            raise RuntimeError("Runtime signing identity mismatch")
        if not result.get("acknowledged"):
            raise RuntimeError("The backend did not acknowledge the ballot")
        self.monitor.refresh()
        receiver_state = next(n for n in self.monitor.snapshot()["nodes"] if n["node_id"] == receiver)
        events = [e for e in receiver_state.get("events", []) if
                  e.get("proposal_id") == proposal_id and e.get("source") == node_id and e.get("decision")]
        rejected = bool(events and events[-1]["decision"] in ("INVALID", "QUARANTINED"))
        return {"message": "Backend rejected/excluded this ballot; inspect its key/trust checks" if rejected
                else "Ballot delivered to the existing RPC. Inspect actual recorded votes for the result.",
                "accepted": not rejected}

    def handle(self, body):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("Another action is running; wait for its result")
        try:
            action = body.get("action")
            if action == "connect":
                return self.connect()
            if action == "runtime":
                candidate = Runtime(body.get("runtime"))
                status = candidate.capabilities()
                if not status["available"]:
                    raise RuntimeError(status["message"])
                self.runtime.close()
                self.runtime, self.runtime_status = candidate, status
                self.monitor.nodes = self.addresses(len(self.monitor.nodes))
                self.connected = False
                self.monitor.refresh()
                return {"message": "Runtime selected. Connect to the backend after its endpoints are ready."}
            if not self.connected:
                raise RuntimeError("Connect to the running backend first")
            if action in ("leader", "sync"):
                raise RuntimeError("This action needs a backend API from your team; backend logic has not been changed")
            if action == "scale":
                count = body.get("replicas")
                self.runtime.scale(count)
                self.monitor.nodes = self.addresses(count)
                self.state_path.write_text(json.dumps({"runtime": self.runtime.kind, "nodes": self.monitor.nodes}), encoding="utf-8")
                self.monitor.refresh()
                return {"message": f"Runtime set to {count} replicas. Backend membership/quorum configuration has not been rewritten."}
            node_id = body.get("node")
            self.node(node_id)
            if action in ("stop", "revive"):
                message = self.runtime.lifecycle(node_id, action)
                if self.runtime.kind == "kubernetes" and action == "revive":
                    self.runtime.ensure_forward(int(node_id.rsplit("-", 1)[1]))
                self.monitor.refresh()
                return {"message": message + ". Existing node persistence/recovery behavior is unchanged."}
            if action == "settings":
                if "automatic_voting" in body:
                    raise RuntimeError("Voting-mode changes require a backend API from your team")
                message = self.runtime.fault(node_id, body.get("fault"))
                return {"message": message}
            if action == "inject":
                return self.inject(body)
            if action in ("propose", "vote"):
                return self.signed_rpc(body)
            if action == "trust":
                peer, score = body.get("peer"), body.get("score")
                self.node(peer)
                if type(score) is not int or not 0 <= score <= 100:
                    raise ValueError("Trust must be an integer from 0 to 100")
                if body.get("scope", "selected") not in ("all", "selected"):
                    raise ValueError("Choose the selected ledger or all reachable ledgers")
                targets = [node_id] if body.get("scope", "selected") == "selected" else [
                    n["node_id"] for n in self.monitor.snapshot()["nodes"] if n["online"]]
                outcomes = [{"node_id": target, **self.runtime.node_call(target, {
                    "operation": "trust", "peer": peer, "score": score})} for target in targets]
                self.monitor.refresh()
                return {"message": "Existing reputation helper applied the requested score", "outcomes": outcomes}
            raise ValueError("Unknown dashboard action")
        finally:
            self._lock.release()

    def close(self):
        self.runtime.close()
