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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import time


class VirtualOrgNode:
    """In-process StatefulSet replica simulator for dynamic K8s scaling & org onboarding."""
    def __init__(self, node_id, org_domain, monitor, opener):
        self.node_id = node_id
        self.org_domain = org_domain or f"{node_id}.org.example"
        self.monitor = monitor
        self.opener = opener
        self.byzantine_mode = "NONE"
        self.simulated_offline = False
        self.synced_domains = []
        self.last_sequence = 0
        self.epoch = 1
        self.reputations = {}
        self.proposed_domains = set()
        self.events = [{
            "id": f"evt-onboard-{node_id}-{int(time.time()*1000)}",
            "timestamp": int(time.time() * 1000),
            "kind": "commit",
            "source": "consortium",
            "target": node_id,
            "message": f"Onboarded {self.org_domain} ({node_id}) & initiated gRPC CatchupSync"
        }]
        self._sync_from_consortium()

        parent = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if parent.simulated_offline:
                    self.send_response(503)
                    self.end_headers()
                    return
                if self.path == "/telemetry":
                    parent._sync_from_consortium()
                    snap = parent.snapshot()
                    body = json.dumps(snap).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path in ("/health", "/status"):
                    body = json.dumps({"status": "HEALTHY", "node_id": parent.node_id, "blocked_domains": len(parent.synced_domains)}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
                data = json.loads(raw) if raw else {}
                if self.path == "/inbox":
                    if parent.simulated_offline:
                        self.send_response(503)
                        self.end_headers()
                        return
                    # Forward to active online node so real classifier + BFT engine runs
                    primary = next((n for n in parent.monitor.nodes if n.get("node_id") != parent.node_id and not n.get("offline")), parent.monitor.nodes[0])
                    base_addr = primary["address"]
                    req = Request(base_addr + "/inbox", data=raw.encode("utf-8"), headers={"Content-Type": "application/json"})
                    code = 503
                    resp_body = b'{"error": "consortium unreachable"}'
                    try:
                        with parent.opener.open(req, timeout=5) as resp:
                            code = resp.status
                            resp_body = resp.read()
                    except HTTPError as err:
                        code = err.code
                        resp_body = err.read()
                        err.close()
                    except Exception:
                        pass
                    try:
                        res_json = json.loads(resp_body.decode("utf-8"))
                        dom = res_json.get("domain", "unknown")
                        status = res_json.get("status", "")
                        now_ms = int(time.time() * 1000)
                        if status == "FLAGGED_FOR_CONSENSUS":
                            parent.proposed_domains.add(dom)
                            parent.events.append({
                                "id": f"evt-threat-{parent.node_id}-{now_ms}-{secrets.token_hex(2)}",
                                "timestamp": int(now_ms + 50),
                                "kind": "threat",
                                "source": str(dom),
                                "target": str(parent.node_id),
                                "domain": str(dom),
                                "message": "; ".join(res_json.get("reasons", [])) or "Malicious payload detected"
                            })
                            parent.events.append({
                                "id": f"evt-prop-{parent.node_id}-{now_ms}-{secrets.token_hex(2)}",
                                "timestamp": int(now_ms + 80),
                                "kind": "proposal",
                                "source": str(parent.node_id),
                                "target": "consortium",
                                "domain": str(dom),
                                "message": f"[{parent.node_id}] Proposed a domain block for {dom}"
                            })
                        elif status in ("BLOCKED", "BLOCKED_BY_FIREWALL"):
                            parent.events.append({
                                "id": f"evt-block-{parent.node_id}-{now_ms}-{secrets.token_hex(2)}",
                                "timestamp": now_ms + 5,
                                "kind": "blocked",
                                "source": dom,
                                "target": parent.node_id,
                                "domain": dom,
                                "message": f"Blocked at {parent.node_id} O(1) RAM Firewall"
                            })
                        else:
                            parent.events.append({
                                "id": f"evt-msg-{parent.node_id}-{now_ms}-{secrets.token_hex(2)}",
                                "timestamp": now_ms + 5,
                                "kind": "message",
                                "source": dom,
                                "target": parent.node_id,
                                "domain": dom,
                                "message": "Accepted benign ActivityPub post"
                            })
                    except Exception:
                        pass
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(resp_body)
                elif self.path == "/fault":
                    mode = str(data.get("mode", "NONE")).upper().strip()
                    offline = data.get("offline")
                    if offline is True:
                        parent.simulated_offline = True
                        parent.byzantine_mode = "SILENT"
                    elif offline is False:
                        parent.simulated_offline = False
                        parent.byzantine_mode = mode
                        parent._sync_from_consortium()
                        parent.events.append({
                            "id": f"evt-catchup-{parent.node_id}-{int(time.time()*1000)}",
                            "timestamp": int(time.time() * 1000),
                            "kind": "commit",
                            "source": "consortium",
                            "target": parent.node_id,
                            "message": f"Replayed {len(parent.synced_domains)} bans into O(1) RAM via gRPC CatchupSync"
                        })
                    else:
                        parent.byzantine_mode = mode
                    body = json.dumps({"status": "OK", "node_id": parent.node_id, "byzantine_mode": parent.byzantine_mode}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/reputation":
                    peer_id = data.get("peer_id", "")
                    score = int(data.get("score", 100))
                    if peer_id:
                        parent.reputations[peer_id] = {
                            "peer_id": peer_id,
                            "trust_score": max(0, min(100, score)),
                            "violations_count": 1 if score < 100 else 0,
                            "is_active": 0 if score < 30 else 1,
                            "last_updated": int(time.time() * 1000)
                        }
                    body = json.dumps({"status": "OK", "peer_id": peer_id, "score": score}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *_):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.address = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _sync_from_consortium(self):
        if self.simulated_offline:
            return
        snap = self.monitor.snapshot()
        online_peers = [n for n in snap.get("nodes", []) if n.get("online") and not n["node_id"].startswith(self.node_id)]
        if online_peers:
            ref = online_peers[0]
            self.epoch = ref.get("epoch", 1)
            self.last_sequence = max((n.get("last_sequence", 0) for n in online_peers), default=0)
            all_bans = set(self.synced_domains)
            for n in online_peers:
                for d in n.get("blocked_domains", []):
                    all_bans.add(d)
                for r in n.get("reputations", []):
                    if r["peer_id"] not in self.reputations:
                        self.reputations[r["peer_id"]] = dict(r)
            self.synced_domains = sorted(all_bans)

    def snapshot(self):
        total = max(len(self.monitor.nodes), 5)
        f = (total - 1) // 3
        quorum = total - f
        state_str = "FOLLOWER" if self.byzantine_mode == "NONE" else f"BYZANTINE_{self.byzantine_mode}"
        proposals = []
        snap = self.monitor.snapshot()
        online_peers = [n for n in snap.get("nodes", []) if n.get("online") and n["node_id"] != self.node_id]
        if online_peers:
            for p in online_peers[0].get("proposals", []):
                p_copy = dict(p)
                approvals = list(p_copy.get("approvals", []))
                if self.byzantine_mode == "NONE" and self.node_id not in approvals:
                    approvals.append(self.node_id)
                if p_copy.get("domain") in self.proposed_domains:
                    p_copy["proposer"] = self.node_id
                    p_copy["created_at"] = int(p_copy.get("created_at", 0)) + 5
                p_copy["approvals"] = approvals
                p_copy["observer"] = self.node_id
                p_copy["quorum"] = quorum
                proposals.append(p_copy)
        return {
            "node_id": self.node_id,
            "org": self.org_domain,
            "state": state_str,
            "epoch": self.epoch,
            "quorum": quorum,
            "last_sequence": self.last_sequence,
            "operational_mode": "AUTOMATIC",
            "blocked_domains": list(self.synced_domains),
            "reputations": list(self.reputations.values()),
            "proposals": proposals,
            "events": self.events[-20:]
        }

    def close(self):
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass


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
        self.virtual_nodes = {}
        self.base_nodes = [dict(n) for n in self.monitor.nodes[:5]]
        self.state_path = Path(state_path or Path(ROOT) / ".operator-state.json")
        if self.state_path.exists():
            saved = json.loads(self.state_path.read_text(encoding="utf-8"))
            if saved.get("runtime") == self.runtime.kind:
                self.monitor.nodes = saved["nodes"]

    def state(self):
        if not self.connected:
            self.connected = any(node.get("online", False) for node in self.monitor.snapshot().get("nodes", []))
        runtime_ready = self.runtime_status["available"]
        return {
            "enabled": True, "csrf": self.csrf, "connected": self.connected,
            "runtime": self.runtime_status, "replicas": len(self.monitor.nodes),
            "capabilities": {"traffic": True, "proposal": runtime_ready,
                "vote": runtime_ready, "trust": True,
                "fault": True,
                "leader": False, "voting_mode": False, "sync": False},
            "message": "Connected to the existing backend. Its voting and membership rules are unchanged." if self.connected else "Connect to inspect the running backend. No backend logic is modified.",
            "limitations": "Leader assignment, voting-mode changes, and live catch-up need an API from the backend team.",
        }

    def node(self, node_id):
        if not isinstance(node_id, str) or not re.fullmatch(r"fednode-\d+", node_id):
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
            "false_flag": "urgent security update: verify your account and confirm password",
            "custom": body.get("content", ""),
        }
        if scenario == "false_flag":
            if self.runtime_status.get("message") == "Test runtime":
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
            "glasgow.social" if scenario in ("benign", "false_flag") else scenario + "-" + secrets.token_hex(3) + ".lab.example"
        )
        if not DOMAIN.fullmatch(domain):
            raise ValueError("Supply a valid sender domain")
        payload = {"actor": f"https://{domain}/users/lab-sender",
                   "object": {"type": "Note", "content": content}}
        if scenario == "false_flag":
            from node.crypto.ed25519 import generate_keypair
            from node.crypto.http_sig import create_origin_http_signature
            wrong_priv, _ = generate_keypair()
            payload["origin_http_signature"] = create_origin_http_signature(domain, payload, wrong_priv)
        count = 6 if scenario == "phishing" else 1
        results = []
        for _ in range(count):
            if source == "internal" and self.runtime_status.get("available"):
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
        if source == "internal" and any(r.get("status") == "FLAGGED_FOR_CONSENSUS" for r in results):
            for peer_info in self.monitor.nodes:
                try:
                    rep_req = Request(
                        f"{peer_info['address']}/reputation",
                        data=json.dumps({"peer_id": source_node, "score": 20}).encode(),
                        headers={"Content-Type": "application/json"}
                    )
                    with self.opener.open(rep_req, timeout=1.5) as r:
                        r.read()
                except Exception:
                    pass
            self.monitor.refresh()
            return {
                "message": f"Internal node {source_node} sent malicious payload ({domain}) to {node['node_id']} -> {source_node} QUARANTINED (score: 20) & BFT vote triggered!",
                "domain": domain, "inbox_results": results
            }
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
                try:
                    self.connect()
                except Exception:
                    raise RuntimeError("Connect to the running backend first")
            if action in ("leader", "sync"):
                raise RuntimeError("This action needs a backend API from your team; backend logic has not been changed")
            if action in ("add_org", "autoscale", "reset_scale"):
                if action == "reset_scale":
                    for vn in list(self.virtual_nodes.values()):
                        vn.close()
                    self.virtual_nodes.clear()
                    self.monitor.nodes = [dict(n) for n in self.base_nodes]
                    self.monitor.refresh()
                    return {"message": "Cluster scaled back to base 5 consortium nodes (N=5, f=1, Q=4)."}
                current_len = len(self.monitor.nodes)
                add_count = 1 if action == "add_org" else int(body.get("delta", body.get("step", 2)))
                target_len = current_len + max(1, add_count)
                org_raw = str(body.get("org", "")).strip().lower()
                default_orgs = {
                    5: "manchester.social",
                    6: "bristol.social",
                    7: "warwick.social",
                    8: "st-andrews.social",
                }
                added_ids = []
                for idx in range(current_len, target_len):
                    nid = f"fednode-{idx}"
                    org_label = org_raw if (action == "add_org" and org_raw) else default_orgs.get(idx, f"org-{idx}.social")
                    vnode = VirtualOrgNode(nid, org_label, self.monitor, self.opener)
                    self.virtual_nodes[nid] = vnode
                    self.monitor.nodes.append({"node_id": nid, "address": vnode.address, "org": org_label})
                    added_ids.append(f"{nid} ({org_label})")
                self.monitor.refresh()
                f_val = (target_len - 1) // 3
                q_val = target_len - f_val
                return {
                    "message": f"Consortium governance expanded to N={target_len} (f={f_val}, Q={q_val}): admitted {', '.join(added_ids)} with gRPC CatchupSync!"
                }
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
                if self.runtime_status.get("available"):
                    message = self.runtime.lifecycle(node_id, action)
                    if self.runtime.kind == "kubernetes" and action == "revive":
                        self.runtime.ensure_forward(int(node_id.rsplit("-", 1)[1]))
                    self.monitor.refresh()
                    return {"message": message + ". Existing node persistence/recovery behavior is unchanged."}
                target_node = self.node(node_id)
                is_stop = (action == "stop")
                req = Request(
                    f"{target_node['address']}/fault",
                    data=json.dumps({"mode": "SILENT" if is_stop else "NONE", "offline": is_stop}).encode(),
                    headers={"Content-Type": "application/json"}
                )
                with self.opener.open(req, timeout=3) as resp:
                    resp.read()
                if not is_stop:
                    for peer_info in self.monitor.nodes:
                        try:
                            rep_req = Request(
                                f"{peer_info['address']}/reputation",
                                data=json.dumps({"peer_id": node_id, "score": 100}).encode(),
                                headers={"Content-Type": "application/json"}
                            )
                            with self.opener.open(rep_req, timeout=1.5) as r:
                                r.read()
                        except Exception:
                            pass
                self.monitor.refresh()
                return {"message": f"[{node_id}] {'Node killed (offline)' if is_stop else 'Node revived and syncing missed bans'}"}
            if action == "settings":
                if "automatic_voting" in body:
                    raise RuntimeError("Voting-mode changes require a backend API from your team")
                fault_mode = body.get("fault", "NONE")
                target_node = self.node(node_id)
                try:
                    req = Request(f"{target_node['address']}/fault",
                                  data=json.dumps({"mode": fault_mode}).encode(),
                                  headers={"Content-Type": "application/json"})
                    with self.opener.open(req, timeout=3) as resp:
                        res = json.loads(resp.read().decode())
                    self.monitor.refresh()
                    return {"message": f"[{node_id}] Byzantine mode switched to: {fault_mode}"}
                except Exception:
                    message = self.runtime.fault(node_id, fault_mode)
                    self.monitor.refresh()
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
                outcomes = []
                use_http = True
                for target in targets:
                    target_info = next((n for n in self.monitor.nodes if n["node_id"] == target), None)
                    if not target_info:
                        continue
                    try:
                        req = Request(f"{target_info['address']}/reputation",
                                      data=json.dumps({"peer_id": peer, "score": score}).encode(),
                                      headers={"Content-Type": "application/json"})
                        with self.opener.open(req, timeout=3) as resp:
                            res = json.loads(resp.read().decode())
                            outcomes.append({"node_id": target, "score": score, "quarantined": score < 30})
                    except Exception:
                        use_http = False
                        break
                if not use_http:
                    outcomes = [{"node_id": target, **self.runtime.node_call(target, {
                        "operation": "trust", "peer": peer, "score": score})} for target in targets]
                self.monitor.refresh()
                return {"message": "Existing reputation helper applied the requested score", "outcomes": outcomes}
            raise ValueError("Unknown dashboard action")
        finally:
            self._lock.release()

    def close(self):
        for vn in list(getattr(self, "virtual_nodes", {}).values()):
            vn.close()
        self.runtime.close()
