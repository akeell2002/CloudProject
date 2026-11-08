import urllib.request
import urllib.error
import json
import time
import sys

BASE_URL = "http://127.0.0.1:8090"
CSRF_TOKEN = None

def get_csrf():
    global CSRF_TOKEN
    if not CSRF_TOKEN:
        controls = get("/api/controls")
        CSRF_TOKEN = controls.get("csrf")
    return CSRF_TOKEN

def post(endpoint, data):
    url = f"{BASE_URL}{endpoint}"
    headers = {
        "Content-Type": "application/json",
        "X-CSRF-Token": get_csrf(),
        "Origin": BASE_URL
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers,
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}
    except Exception as e:
        return 0, {"error": str(e)}

def get(endpoint):
    url = f"{BASE_URL}{endpoint}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))

def get_aggregated_proposals(cluster):
    by_domain = {}
    for node in cluster.get("nodes", []):
        if not node.get("online"):
            continue
        for p in node.get("proposals", []):
            domain = p.get("domain") or p.get("proposal_id")
            if domain not in by_domain:
                by_domain[domain] = dict(p)
            else:
                existing = by_domain[domain]
                # merge approvals
                existing_apps = set(existing.get("approvals", []))
                existing_apps.update(p.get("approvals", []))
                existing["approvals"] = list(existing_apps)
                if p.get("committed"):
                    existing["committed"] = True
    return list(by_domain.values())

def main():
    print("=== STEP 0: Initial Cluster State ===")
    cluster = get("/api/cluster")
    nodes = cluster.get("nodes", [])
    print(f"Monitored nodes count: {len(nodes)}")
    for n in nodes:
        print(f"  {n['node_id']} ({n.get('org')}): state={n.get('state')}, epoch={n.get('epoch')}, blocked={len(n.get('blocked_domains', []))}, online={n.get('online')}")
    
    # 1. Benign note injection to follower
    print("\n=== TEST 1: Inject Benign Note to fednode-1 ===")
    initial_props = len(get_aggregated_proposals(cluster))
    status, res = post("/api/actions", {"action": "inject", "node": "fednode-1", "scenario": "benign"})
    print(f"Status: {status}, Response: {res}")
    time.sleep(1)
    cluster = get("/api/cluster")
    proposals = get_aggregated_proposals(cluster)
    print(f"Proposals count: {len(proposals)}")
    assert len(proposals) == initial_props, f"Expected {initial_props} proposals, found {len(proposals)}"
    print("PASS: Benign note accepted without consensus proposal.")

    # 2. Malware attack on follower fednode-1
    print("\n=== TEST 2: Inject Malware Attack to Follower fednode-1 ===")
    status, res = post("/api/actions", {"action": "inject", "node": "fednode-1", "scenario": "malware"})
    print(f"Status: {status}, Response: {res}")
    # Wait for leader proposal forwarding and BFT voting rounds (max ~4-5s)
    print("Waiting 4 seconds for consensus rounds...")
    time.sleep(4)
    cluster = get("/api/cluster")
    proposals = get_aggregated_proposals(cluster)
    bans = cluster.get("bans", [])
    print(f"Proposals count: {len(proposals)}")
    target_domain = res.get("domain")
    print(f"Target domain: {target_domain}")
    matching_props = [p for p in proposals if p.get("domain") == target_domain]
    assert len(matching_props) > 0, f"Expected proposal for {target_domain}"
    prop = matching_props[0]
    print(f"  Proposal {prop.get('domain')}: committed={prop.get('committed')}, approvals={prop.get('approvals')}")
    assert prop.get("committed") is True, f"Proposal not committed: {prop}"
    assert len(prop.get("approvals", [])) >= 4, f"Approvals < 4: {prop.get('approvals')}"

    # Verify ban in bans list
    matching_bans = [b for b in bans if b.get("domain") == target_domain]
    assert len(matching_bans) > 0, f"Expected ban entry for {target_domain}"
    print(f"  Bans entry: {matching_bans[0]}")
    assert len(matching_bans[0].get("applied_on", [])) == 5, f"Not applied across all 5 nodes: {matching_bans[0]}"
    print("PASS: Malware attack on follower was forwarded to leader and committed by 5/5 nodes!")

    # 3. Phishing burst on leader fednode-0
    print("\n=== TEST 3: Inject Phishing Burst to Leader fednode-0 ===")
    status, res = post("/api/actions", {"action": "inject", "node": "fednode-0", "scenario": "phishing"})
    print(f"Status: {status}, Response: {res}")
    print("Waiting 4 seconds for consensus rounds...")
    time.sleep(4)
    cluster = get("/api/cluster")
    proposals = get_aggregated_proposals(cluster)
    target_domain = res.get("domain")
    matching_props = [p for p in proposals if p.get("domain") == target_domain]
    assert len(matching_props) > 0, f"Expected proposal for {target_domain}"
    prop = matching_props[0]
    print(f"  Proposal {prop.get('domain')}: committed={prop.get('committed')}, approvals={prop.get('approvals')}")
    assert prop.get("committed") is True, "Phishing proposal not committed"
    print("PASS: Phishing attack on leader committed by BFT quorum!")

    # 4. Byzantine Fault: Set fednode-2 to LIAR, inject malware to fednode-3
    print("\n=== TEST 4: Byzantine Fault Injection (fednode-2 -> LIAR) ===")
    status, res = post("/api/actions", {"action": "settings", "node": "fednode-2", "fault": "LIAR"})
    print(f"Fault injection status: {status}, Response: {res}")
    time.sleep(1)

    print("Injecting malware to fednode-3 while fednode-2 is LIAR...")
    status, res = post("/api/actions", {"action": "inject", "node": "fednode-3", "scenario": "malware"})
    print(f"Status: {status}, Response: {res}")
    print("Waiting 4 seconds for consensus rounds...")
    time.sleep(4)

    cluster = get("/api/cluster")
    proposals = get_aggregated_proposals(cluster)
    target_domain = res.get("domain")
    matching_props = [p for p in proposals if p.get("domain") == target_domain]
    assert len(matching_props) > 0, f"Expected proposal for {target_domain}"
    latest_prop = matching_props[0]
    print(f"Latest proposal {latest_prop.get('domain')}: committed={latest_prop.get('committed')}, approvals={latest_prop.get('approvals')}")
    assert latest_prop.get("committed") is True, "Consensus failed despite 4 honest nodes (N=5, f=1, Q=4)"
    assert "fednode-2" not in latest_prop.get("approvals", []), "Liar node approved when it should have rejected/lied!"
    print("PASS: BFT Consensus committed with Q=4 honest nodes despite fednode-2 being LIAR!")

    # Reset fednode-2 to HONEST
    post("/api/actions", {"action": "settings", "node": "fednode-2", "fault": "HONEST"})

    # 5. Node stop and revive (Catch-up sync test)
    print("\n=== TEST 5: Node Kill and Catchup Recovery (fednode-4) ===")
    status, res = post("/api/actions", {"action": "stop", "node": "fednode-4"})
    print(f"Stop fednode-4 status: {status}, Response: {res}")
    time.sleep(2)
    cluster = get("/api/cluster")
    fn4 = next(n for n in cluster["nodes"] if n["node_id"] == "fednode-4")
    print(f"fednode-4 status: online={fn4.get('online')}")

    # Inject another threat while fednode-4 is down
    print("Injecting threat to fednode-1 while fednode-4 is down...")
    status, res = post("/api/actions", {"action": "inject", "node": "fednode-1", "scenario": "malware"})
    time.sleep(4)

    # Revive fednode-4
    print("Reviving fednode-4...")
    status, res = post("/api/actions", {"action": "revive", "node": "fednode-4"})
    print(f"Revive fednode-4 status: {status}, Response: {res}")
    time.sleep(4) # allow health checks & catchup loop

    cluster = get("/api/cluster")
    fn4 = next(n for n in cluster["nodes"] if n["node_id"] == "fednode-4")
    fn0 = next(n for n in cluster["nodes"] if n["node_id"] == "fednode-0")
    print(f"fednode-4 after revive: online={fn4.get('online')}, blocked={len(fn4.get('blocked_domains', []))}")
    print(f"fednode-0: blocked={len(fn0.get('blocked_domains', []))}")
    assert len(fn4.get("blocked_domains", [])) == len(fn0.get("blocked_domains", [])), f"Catchup divergence: fn4={len(fn4.get('blocked_domains', []))} vs fn0={len(fn0.get('blocked_domains', []))}"
    print("PASS: fednode-4 caught up and synced all blocks!")

    print("\nALL 5 INTERACTIVE DASHBOARD TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    main()
