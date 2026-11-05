"""Fixed-target Docker/Kubernetes lab operations, never a shell command endpoint."""
import json
import os
import re
import subprocess
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NODE_SCRIPT = """
import json, os, sys
from node.crypto.ed25519 import sign_message
from node.storage.database import Database
request = json.load(sys.stdin)
data_dir = os.getenv("DATA_DIR", "/data")
if request["operation"] in ("propose", "vote"):
    import grpc
    from proto import fedconsensus_pb2 as pb2
    from proto import fedconsensus_pb2_grpc as rpc
    with open(os.path.join(data_dir, "node_identity.json")) as file:
        identity = json.load(file)
    peers = [p.strip() for p in os.getenv("PEER_ADDRESSES", "").split(",") if p.strip()]
    def address(node_id):
        index = int(node_id.rsplit("-", 1)[1])
        if index < len(peers):
            return peers[index]
        if peers and "fednode-0" in peers[0]:
            return peers[0].replace("fednode-0", node_id)
        return node_id + ":50051"
    meta = request["meta"]
    signature = sign_message(identity["private_key"], meta)
    if request["operation"] == "propose":
        proposal = pb2.ProposeRequest(**meta,
            evidence_payload=json.dumps({"operator_justification": request["justification"]}),
            proposer_id=identity["node_id"], proposer_signature=signature)
        outcomes = []
        for target in request["targets"]:
            try:
                with grpc.insecure_channel(address(target)) as channel:
                    result = rpc.FedConsensusServiceStub(channel).ProposeDefederation(proposal, timeout=3)
                outcomes.append({"node_id": target, "accepted": result.accepted, "reason": result.reason})
            except grpc.RpcError:
                outcomes.append({"node_id": target, "accepted": False, "reason": "Unreachable"})
        print(json.dumps({"outcomes": outcomes, "node_id": identity["node_id"]}))
    else:
        fields = {key: value for key, value in meta.items() if key != "decision"}
        ballot = pb2.VoteRequest(**fields, voter_id=identity["node_id"], voter_signature=signature,
            decision=pb2.VOTE_APPROVE if meta["decision"] == "APPROVE" else pb2.VOTE_REJECT)
        with grpc.insecure_channel(address(request["receiver"])) as channel:
            result = rpc.FedConsensusServiceStub(channel).CastVote(ballot, timeout=3)
        print(json.dumps({"acknowledged": result.acknowledged, "node_id": identity["node_id"]}))
elif request["operation"] == "trust":
    db = Database(os.path.join(data_dir, "wal.db"))
    ledger = {r["peer_id"]: r for r in db.get_all_reputations()}
    old = ledger.get(request["peer"], {}).get("trust_score", 100)
    db.update_reputation(request["peer"], request["score"] - old)
    print(json.dumps({"score": request["score"], "quarantined": request["score"] < 30}))
elif request["operation"] == "post":
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError
    index = int(request["receiver"].rsplit("-", 1)[1])
    peers = [p.strip() for p in os.getenv("PEER_ADDRESSES", "").split(",") if p.strip()]
    host = peers[index].rsplit(":", 1)[0] if index < len(peers) else request["receiver"]
    port = 8080 + index if host in ("localhost", "127.0.0.1") else 8080
    req = Request("http://" + host + ":" + str(port) + "/inbox",
                  data=json.dumps(request["payload"]).encode(),
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=8) as response:
            print(json.dumps({"http_status": response.status, **json.load(response)}))
    except HTTPError as error:
        if error.code not in (400, 403):
            raise
        print(json.dumps({"http_status": error.code, **json.load(error)}))
        error.close()
else:
    raise ValueError("Unsupported operation")
"""


class Runtime:
    def __init__(self, kind=None):
        self.kind = kind or os.getenv("DASHBOARD_RUNTIME", "docker")
        if self.kind not in ("docker", "kubernetes"):
            raise ValueError("Runtime must be docker or kubernetes")
        self.namespace = os.getenv("DASHBOARD_NAMESPACE", "default")
        if not re.fullmatch(r"[a-z0-9-]+", self.namespace):
            raise ValueError("Invalid Kubernetes namespace")
        self.forwarders = {}

    def run(self, arguments, timeout=45):
        try:
            result = subprocess.run(arguments, cwd=ROOT, capture_output=True,
                                    text=True, timeout=timeout,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("Runtime command unavailable or timed out") from error
        if result.returncode:
            # Runtime output can contain inherited credentials; do not echo it into the UI.
            raise RuntimeError("Runtime rejected the operation; check Docker Desktop or the selected Kubernetes context")
        return result.stdout

    def kubectl(self, *args):
        return self.run(["kubectl", "--namespace", self.namespace, *args])

    def inspect(self, node_id="fednode-0"):
        value = json.loads(self.run(["docker", "inspect", node_id]))[0]
        labels = value.get("Config", {}).get("Labels") or {}
        if value.get("Name", "").lstrip("/") != node_id:
            raise RuntimeError("Container identity mismatch")
        if not labels.get("com.docker.compose.project") and labels.get("fedconsensus.operator-managed") != "true":
            raise RuntimeError("Container is not a managed FedConsensus node")
        if labels.get("com.docker.compose.service") not in (None, node_id):
            raise RuntimeError("Container service does not match the requested node")
        return value

    def capabilities(self):
        try:
            if self.kind == "docker":
                self.inspect()
            else:
                state = json.loads(self.kubectl("get", "statefulset", "fednode", "-o", "json"))
                if state["spec"]["template"]["metadata"]["labels"].get("app") != "fednode":
                    raise RuntimeError("StatefulSet is not the FedConsensus workload")
            return {"kind": self.kind, "available": True, "message": "Runtime controls ready"}
        except (RuntimeError, ValueError, KeyError):
            return {"kind": self.kind, "available": False,
                    "message": "Run the dashboard on the host with Docker access, or configure the FedConsensus Kubernetes context"}

    def lifecycle(self, node_id, operation):
        if not re.fullmatch(r"fednode-[0-8]", node_id) or operation not in ("stop", "revive"):
            raise ValueError("Invalid node lifecycle operation")
        if self.kind == "docker":
            self.inspect(node_id)
            self.run(["docker", "stop" if operation == "stop" else "start", node_id])
            return "Container stopped" if operation == "stop" else "Container started"
        pod = json.loads(self.kubectl("get", "pod", node_id, "-o", "json"))
        if pod.get("metadata", {}).get("labels", {}).get("app") != "fednode":
            raise RuntimeError("Pod is not a FedConsensus node")
        if operation == "stop":
            self.kubectl("delete", "pod", node_id, "--wait=false")
            return "Pod deleted; its StatefulSet will recreate it"
        return "StatefulSet manages revival; reconnect and catch up when the pod is ready"

    def scale(self, count):
        if type(count) is not int or not 1 <= count <= 9:
            raise ValueError("Choose 1–9 replicas")
        if not self.capabilities()["available"]:
            raise RuntimeError("Runtime controls are unavailable")
        if self.kind == "kubernetes":
            self.kubectl("scale", "statefulset/fednode", "--replicas=" + str(count))
            return
        seed = self.inspect()
        networks = seed["NetworkSettings"]["Networks"]
        network = next((name for name in networks if name.endswith("fedconsensus-net")), None)
        if not network:
            raise RuntimeError("FedConsensus Docker network was not found")
        inherited = seed["Config"].get("Env", [])
        project = seed["Config"]["Labels"]["com.docker.compose.project"]
        for index in range(9):
            node_id = f"fednode-{index}"
            try:
                node = self.inspect(node_id)
            except RuntimeError:
                if index >= count:
                    continue
                if index < 5:
                    self.run(["docker", "compose", "up", "-d", node_id])
                    continue
                # Keep the shared credential out of process-list arguments.
                environment = [entry for entry in inherited if not entry.startswith("NODE_ID=")]
                if any("\n" in entry or "\r" in entry for entry in environment):
                    raise RuntimeError("Multiline environment values cannot be copied safely")
                with tempfile.TemporaryDirectory() as directory:
                    env_path = os.path.join(directory, "node.env")
                    with open(env_path, "w", encoding="utf-8") as file:
                        file.write("\n".join(environment) + "\nNODE_ID=" + node_id + "\n")
                    self.run(["docker", "run", "-d", "--name", node_id, "--network", network,
                        "--label", "fedconsensus.operator-managed=true",
                        "--label", "com.docker.compose.project=" + project,
                        "--env-file", env_path,
                        "-p", f"127.0.0.1:{8080+index}:8080",
                        "-p", f"127.0.0.1:{50051+index}:50051",
                        "--mount", f"type=volume,source={project}-{node_id}-data,target=/data", seed["Image"]])
                continue
            if index < count and not node["State"]["Running"]:
                self.run(["docker", "start", node_id])
            elif index >= count and node["State"]["Running"]:
                self.run(["docker", "stop", node_id])

    def ensure_forward(self, index):
        if self.kind != "kubernetes":
            return
        previous = self.forwarders.get(index)
        if previous and previous.poll() is None:
            return
        self.forwarders[index] = subprocess.Popen(
            ["kubectl", "--namespace", self.namespace, "port-forward",
             f"pod/fednode-{index}", f"{18080+index}:8080", f"{51051+index}:50051",
             "--address=127.0.0.1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def node_call(self, node_id, request):
        if not re.fullmatch(r"fednode-[0-8]", node_id):
            raise ValueError("Invalid node")
        if self.kind == "docker":
            self.inspect(node_id)
            command = ["docker", "exec", "-i", node_id, "python", "-c", NODE_SCRIPT]
        else:
            pod = json.loads(self.kubectl("get", "pod", node_id, "-o", "json"))
            if pod.get("metadata", {}).get("labels", {}).get("app") != "fednode":
                raise RuntimeError("Pod is not a FedConsensus node")
            command = ["kubectl", "--namespace", self.namespace, "exec", "-i", node_id,
                       "--", "python", "-c", NODE_SCRIPT]
        try:
            result = subprocess.run(command, input=json.dumps(request), capture_output=True, text=True,
                timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode:
                raise RuntimeError("The node's existing helper rejected this operation")
            return json.loads(result.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            raise RuntimeError("Cannot call the node's existing helper") from None

    def fault(self, node_id, mode):
        if self.kind != "docker" or not re.fullmatch(r"fednode-[0-4]", node_id):
            raise RuntimeError("Per-node fault environment changes are available for the original five Docker services")
        if mode not in ("NONE", "SILENT", "LIAR", "FORGER"):
            raise ValueError("Unknown backend fault mode")
        container = self.inspect(node_id)
        project = container["Config"]["Labels"]["com.docker.compose.project"]
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "fault.json")
            with open(path, "w", encoding="utf-8") as file:
                json.dump({"services": {node_id: {"environment": {"BYZANTINE_MODE": mode}}}}, file)
            self.run(["docker", "compose", "--project-name", project, "-f",
                      os.path.join(ROOT, "docker-compose.yml"), "-f", path,
                      "up", "-d", "--no-deps", "--force-recreate", node_id])
        return "Node restarted using its existing BYZANTINE_MODE=" + mode

    def close(self):
        for process in self.forwarders.values():
            process.terminate()
