"""Run from any directory with: python -B benchmarks/benchmark_runner.py"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import csv
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import platform
import secrets
import socket
import statistics
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from node.config import NodeConfig
from node.crypto.ed25519 import generate_deterministic_keypair, sign_message
from node.engine.catchup import CatchupEngine
from node.ingress.classifier import ThreatClassifier
from node.ingress.firewall import FirewallFilter
from node.storage.database import Database
from proto import fedconsensus_pb2 as pb

NS = 1_000_000_000
HTTP = build_opener(ProxyHandler({}))
NODE_BOOT = """
import json, os, time
from pathlib import Path
from unittest.mock import patch

import grpc
from node import main as node_main

# Keep the real node handlers and restrict the test listeners to loopback.
http_server = node_main.ThreadingHTTPServer
grpc_server = grpc.server
insecure_channel = grpc.insecure_channel
peer_endpoints = {peer: "127.0.0.1:" + peer.rsplit(":", 1)[1]
                  for peer in os.environ["PEER_ADDRESSES"].split(",")}


def loopback_channel(target, *args, **kwargs):
    return insecure_channel(peer_endpoints[target], *args, **kwargs)


grpc.insecure_channel = loopback_channel

def loopback_grpc(executor):
    server = grpc_server(executor, options=[("grpc.so_reuseport", 0)])
    bind = server.add_insecure_port
    server.add_insecure_port = lambda addr: bind(addr.replace("0.0.0.0:", "127.0.0.1:"))
    return server

runner = node_main.FedNodeRunner()
with patch.object(grpc, "server", loopback_grpc), patch.object(
    node_main, "ThreadingHTTPServer", lambda addr, handler: http_server(("127.0.0.1", addr[1]), handler)
):
    runner.start()
ready = Path(os.environ["DATA_DIR"], "ready.json")
ready.with_suffix(".tmp").write_text(json.dumps(runner.http_server.server_port), encoding="utf-8")
ready.with_suffix(".tmp").replace(ready)
while runner.running:
    time.sleep(1)
"""
CONFIG = ("NODE_ID", "ORG_DOMAIN", "GRPC_PORT", "HTTP_PORT", "DATA_DIR",
          "PEER_ADDRESSES", "CONSORTIUM_SECRET", "USE_RANDOM_NODE_KEYS",
          "CONSORTIUM_PUBLIC_KEYS", "KNOWN_DOMAIN_KEYS", "OPERATIONAL_MODE",
          "BYZANTINE_MODE", "QUORUM_MODE", "FEDCONSENSUS_OPERATOR_TOKEN")


def payload(domain, content="hello", attachment=False):
    obj = {"content": content}
    if attachment:
        obj["attachment"] = [{"url": f"https://{domain}/sample.exe"}]
    return {"type": "Create", "actor": f"https://{domain}/users/bench", "object": obj}


def elapsed(start):
    return time.perf_counter_ns() - start


def micro(run, repetitions):
    fw = FirewallFilter(Database(str(run / "micro.db")))
    fw.block_domain("blocked.example")
    assert fw.is_blocked("blocked.example") and not fw.is_blocked("other.example")
    samples = [(f"sender{i}.example", payload(f"sender{i}.example",
                 "verify your account" if i % 3 == 1 else "hello", i % 3 == 2))
               for i in range(5000)]
    for trial in range(1, repetitions + 1):
        classifier = ThreatClassifier()
        start = time.perf_counter_ns()
        for _ in range(50_000):
            fw.is_blocked("blocked.example")
            fw.is_blocked("other.example")
        yield {"suite": "micro", "case": "firewall", "trial": trial,
               "operations": 100_000, "elapsed_ns": elapsed(start), "outcome": "ok"}
        start = time.perf_counter_ns()
        for domain, activity in samples:
            classifier.analyze(domain, activity)
        yield {"suite": "micro", "case": "classifier", "trial": trial,
               "operations": len(samples), "elapsed_ns": elapsed(start), "outcome": "ok"}


def get(port, path, body=None, timeout=3):
    req = Request(f"http://127.0.0.1:{port}{path}", data=body,
                  headers={"Content-Type": "application/json"})
    try:
        response = HTTP.open(req, timeout=timeout)
    except HTTPError as exc:
        response = exc
    with response:
        return response.status, json.load(response)


def free_loopback_ports(count):
    with ExitStack() as stack:
        ports = []
        for _ in range(count):
            probe = stack.enter_context(socket.socket())
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            probe.bind(("127.0.0.1", 0))
            ports.append(probe.getsockname()[1])
        return ports


@contextmanager
def cluster(path, n, mode):
    grpc_ports = free_loopback_ports(n)
    peers = ",".join(f"fednode-{i}:{port}" for i, port in enumerate(grpc_ports))
    secret = secrets.token_hex(32)
    processes, markers = [], []
    try:
        for i, grpc_port in enumerate(grpc_ports):
            data = path / f"fednode-{i}"
            data.mkdir(parents=True)
            markers.append(data / "ready.json")
            env = {k: v for k, v in os.environ.items() if k not in CONFIG}
            env.update(NODE_ID=f"fednode-{i}", DATA_DIR=str(data), GRPC_PORT=str(grpc_port),
                       HTTP_PORT="0", PEER_ADDRESSES=peers, QUORUM_MODE="STRICT",
                       CONSORTIUM_SECRET=secret, BYZANTINE_MODE=mode if i == 1 else "NONE",
                       PYTHONNOUSERSITE="1", PYTHONPATH=os.pathsep.join(
                           [str(ROOT), os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep))
            with (data / "node.log").open("wb") as log:
                processes.append(subprocess.Popen([sys.executable, "-B", "-c", NODE_BOOT],
                                                  cwd=path, env=env, stdout=log, stderr=log))
        deadline = time.monotonic() + 20
        while not all(m.exists() and m.stat().st_size for m in markers):
            if any(p.poll() is not None for p in processes) or time.monotonic() >= deadline:
                raise RuntimeError(f"Cluster did not start. Check logs in {path}")
            time.sleep(0.02)
        ports = [int(m.read_text(encoding="utf-8")) for m in markers]
        quorum = n - (n - 1) // 3
        for i, port in enumerate(ports):
            status, snap = get(port, "/telemetry")
            if status != 200 or snap["node_id"] != f"fednode-{i}" or snap["quorum"] != quorum:
                raise RuntimeError(f"Unexpected node or quorum on benchmark port {port}")
        yield ports
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def observe(port):
    try:
        return get(port, "/telemetry", timeout=0.5)[1]
    except OSError:
        return None


def measure_cluster(run, suite, n, mode, trials, timeout):
    case = str(n) if suite == "consensus" else {"NONE": "HONEST"}.get(mode, mode)
    print(f"Running {suite} {case} ({trials} trials)...", flush=True)
    with cluster(run / f"{suite}-{case}", n, mode) as ports, ThreadPoolExecutor(n) as pool:
        # Observe honest peers; the injected fault is on fednode-1.
        observers = [p for i, p in enumerate(ports) if i != 1 or mode == "NONE"]
        prior_trust = 100
        for trial in range(0 if suite == "consensus" else 1, trials + 1):
            domain = f"bench-{trial}.example"
            body = json.dumps(payload(domain, attachment=True)).encode()
            start = time.perf_counter_ns()
            if trial == 1:
                window_start = start
            code, response = get(ports[0], "/inbox", body)
            if code != 403 or response.get("status") != "FLAGGED_FOR_CONSENSUS":
                raise RuntimeError(f"Unexpected benchmark ingress response: {code}, {response}")
            snapshots, enforced, errors = {}, set(), 0
            while True:
                pending = [port for port in observers if port not in enforced]
                for port, snapshot in zip(pending, pool.map(observe, pending)):
                    if snapshot is None:
                        errors += 1
                        continue
                    snapshots[port] = snapshot
                    if domain in snapshot["blocked_domains"]:
                        enforced.add(port)
                duration = elapsed(start)
                if len(enforced) == len(observers) or duration >= timeout * NS:
                    break
                time.sleep(0.002)
            success = len(enforced) == len(observers) and duration < timeout * NS
            slots = {(p["epoch"], p["sequence"]) for snap in snapshots.values()
                     for p in snap["proposals"] if p["committed"] and p["domain"] == domain}
            conflict = any(
                p["committed"] and (p["epoch"], p["sequence"]) in slots and p["domain"] != domain
                for snap in snapshots.values() for p in snap["proposals"]
            )
            ledger = snapshots.get(ports[0], {}).get("reputations", [])
            entry = next((r for r in ledger if r["peer_id"] == "fednode-1"), {})
            trust = entry.get("trust_score", 100 if ports[0] in snapshots else "")
            yield {"suite": suite, "case": case, "trial": trial, "nodes": n,
                   "quorum": n - (n - 1) // 3, "operations": 1,
                   "elapsed_ns": duration, "outcome": "ok" if success else "timeout",
                   "enforced_peers": len(enforced), "required_peers": len(observers), "observation_errors": errors,
                   "conflict_observed": int(conflict), "node0_view_node1_trust_before": prior_trust,
                   "node0_view_node1_trust_after": trust,
                   "node0_view_node1_quarantined": int(not entry.get("is_active", True)) if ports[0] in snapshots else "",
                   "window_elapsed_ns": start + duration - window_start if trial else ""}
            prior_trust = trust
            if trial and (trial % 5 == 0 or trial == trials):
                print(f"  {trial}/{trials} trials finished", flush=True)


def recovery(run, repetitions):
    cfg = NodeConfig()
    keys = {}
    for i in range(cfg.quorum_size):
        keys[f"fednode-{i}"] = generate_deterministic_keypair(f"benchmark-recovery-{i}")
    public = {node: key[1] for node, key in keys.items()}
    records = []
    for i in range(1, 501):
        meta = dict(proposal_id=f"replay-{i}", epoch=1, sequence_number=i,
                    target_domain=f"replay-{i}.example", decision="APPROVE")
        signatures = [pb.VoterSignature(voter_id=node, signature=sign_message(key[0], meta))
                      for node, key in keys.items()]
        fields = {k: v for k, v in meta.items() if k != "decision"}
        proof = pb.QuorumProof(**fields, signatures=signatures, reason=pb.REASON_MALICIOUS_FILES)
        records.append(pb.CommitRecord(sequence_number=i, epoch=1, target_domain=meta["target_domain"],
                                      reason=proof.reason, quorum_proof=proof))
    for count in (10, 50, 100, 250, 500):
        for trial in range(1, repetitions + 1):
            db = Database(str(run / "recovery" / f"{count}-{trial}.db"))
            fw = FirewallFilter(db)
            engine = CatchupEngine(cfg, db, fw, public)
            start = time.perf_counter_ns()
            replayed = engine.replay_records(records[:count])
            duration = elapsed(start)
            assert replayed == count and db.get_latest_sequence_number() == count
            assert fw.get_blocked_domains() == {r.target_domain for r in records[:count]}
            yield {"suite": "recovery", "case": str(count), "trial": trial,
                   "operations": replayed, "elapsed_ns": duration, "outcome": "ok"}


FIELDS = ("suite", "case", "trial", "nodes", "quorum", "operations", "elapsed_ns", "outcome",
          "enforced_peers", "required_peers", "observation_errors", "conflict_observed", "node0_view_node1_trust_before",
          "node0_view_node1_trust_after", "node0_view_node1_quarantined", "window_elapsed_ns")


def summarize(rows):
    groups = {}
    for row in rows:
        if row["trial"]:
            groups.setdefault((row["suite"], row["case"]), []).append(row)
    for (suite, case), group in groups.items():
        good = [r for r in group if r["outcome"] == "ok"]
        durations = [r["elapsed_ns"] for r in good] if suite != "micro" else []
        operations = sum(r["operations"] for r in good) if durations else 0
        total = sum(durations)
        p95 = statistics.quantiles(durations, n=100, method="inclusive")[94] if len(durations) > 1 else None
        window = group[-1].get("window_elapsed_ns", 0)
        yield {"suite": suite, "case": case, "trials": len(group), "successes": len(good),
               "mean_ms": statistics.mean(durations) / 1e6 if durations else None,
               "p95_ms": p95 / 1e6 if p95 is not None else None,
               "mean_us_per_op": total / operations / 1e3 if operations else None,
               "ops_per_sec": operations * NS / total if total and suite == "recovery" else None,
               "serial_commits_per_sec": len(good) * NS / window if window else None,
               "observed_conflicts": sum(r.get("conflict_observed", 0) for r in group)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--sizes", nargs="+", type=int, default=[4, 5, 7, 10, 16])
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=5)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--local-only", action="store_true", help="Run microbenchmarks and local recovery only")
    selection.add_argument("--micro-only", action="store_true", help="Run only the blocklist and threat screening benchmarks")
    args = parser.parse_args()
    if min(args.trials, args.repeats, args.timeout) <= 0 or any(not 4 <= n <= 16 for n in args.sizes):
        parser.error("Use positive trial/repeat/timeout values and cluster sizes 4–16.")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    run = HERE / "results" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    run.mkdir(parents=True)
    print(run, flush=True)
    (run / "metadata.json").write_text(json.dumps(
        {"commit": commit, "python": sys.version, "platform": platform.platform(),
         "cpu_count": os.cpu_count(), "quorum_mode": "STRICT", "timer": "perf_counter_ns",
         "consensus_endpoint": "local HTTP /inbox until all honest peers report block via /telemetry",
         "warmup": "trial 0 excluded for consensus; no warmup for fault cases; clean cluster per case",
         "recovery_scope": "local QC verification, SQLite persistence, firewall update",
         **vars(args)}, indent=2), encoding="utf-8")
    for name in CONFIG:
        os.environ.pop(name, None)
    os.environ.update(DATA_DIR=str(run / "recovery-identity"), QUORUM_MODE="STRICT")
    logging.disable(logging.WARNING)
    rows = []
    with (run / "raw.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()

        def collect(records):
            for row in records:
                writer.writerow(row)
                rows.append(row)
                stream.flush()

        collect(micro(run, args.repeats))
        if not (args.local_only or args.micro_only):
            for size in dict.fromkeys(args.sizes):
                collect(measure_cluster(run, "consensus", size, "NONE", args.trials, args.timeout))
            for mode in ("NONE", "LIAR", "FORGER"):
                collect(measure_cluster(run, "fault", 5, mode, args.trials, args.timeout))
        if not args.micro_only:
            print("Running local certificate replay...", flush=True)
            collect(recovery(run, args.repeats))
    summary = list(summarize(rows))
    with (run / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=summary[0].keys())
        writer.writeheader()
        writer.writerows(summary)
    print(f"Saved {len(rows)} trial/batch rows.", flush=True)


if __name__ == "__main__":
    main()
