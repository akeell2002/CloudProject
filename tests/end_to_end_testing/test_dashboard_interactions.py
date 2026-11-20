"""Live Docker cluster interaction tests against the operator dashboard."""
import json
import time
import unittest
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8090"


def _get(endpoint, timeout=10):
    with urllib.request.urlopen(f"{BASE_URL}{endpoint}", timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_aggregated_proposals(cluster):
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
                existing_apps = set(existing.get("approvals", []))
                existing_apps.update(p.get("approvals", []))
                existing["approvals"] = list(existing_apps)
                if p.get("committed"):
                    existing["committed"] = True
    return list(by_domain.values())


class TestLiveDashboardInteractions(unittest.TestCase):
    csrf_token = None

    @classmethod
    def setUpClass(cls):
        try:
            controls = _get("/api/controls", timeout=1.5)
            cls.csrf_token = controls.get("csrf")
        except Exception as exc:
            raise unittest.SkipTest(f"Live dashboard cluster not reachable at {BASE_URL}: {exc}")

    def _post(self, endpoint, data):
        req = urllib.request.Request(
            f"{BASE_URL}{endpoint}",
            data=json.dumps(data).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": self.csrf_token or "",
                "Origin": BASE_URL,
            },
            method="POST",
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

    def test_1_benign_note_accepted_without_proposal(self):
        initial_props = len(_get_aggregated_proposals(_get("/api/cluster")))
        self._post("/api/actions", {"action": "inject", "node": "fednode-1", "scenario": "benign"})
        time.sleep(1)
        proposals = _get_aggregated_proposals(_get("/api/cluster"))
        self.assertEqual(len(proposals), initial_props)

    def test_2_malware_on_follower_escalates_and_commits(self):
        _, res = self._post("/api/actions", {"action": "inject", "node": "fednode-1", "scenario": "malware"})
        time.sleep(4)
        cluster = _get("/api/cluster")
        target_domain = res.get("domain")
        matching_props = [p for p in _get_aggregated_proposals(cluster) if p.get("domain") == target_domain]
        self.assertGreater(len(matching_props), 0)
        self.assertTrue(matching_props[0].get("committed"))
        self.assertGreaterEqual(len(matching_props[0].get("approvals", [])), 4)

        matching_bans = [b for b in cluster.get("bans", []) if b.get("domain") == target_domain]
        self.assertGreater(len(matching_bans), 0)
        self.assertEqual(len(matching_bans[0].get("applied_on", [])), 5)

    def test_3_phishing_burst_on_leader_commits(self):
        _, res = self._post("/api/actions", {"action": "inject", "node": "fednode-0", "scenario": "phishing"})
        time.sleep(4)
        cluster = _get("/api/cluster")
        target_domain = res.get("domain")
        matching_props = [p for p in _get_aggregated_proposals(cluster) if p.get("domain") == target_domain]
        self.assertGreater(len(matching_props), 0)
        self.assertTrue(matching_props[0].get("committed"))

    def test_4_byzantine_liar_masked_by_quorum(self):
        self._post("/api/actions", {"action": "settings", "node": "fednode-2", "fault": "LIAR"})
        try:
            time.sleep(1)
            _, res = self._post("/api/actions", {"action": "inject", "node": "fednode-3", "scenario": "malware"})
            time.sleep(4)
            cluster = _get("/api/cluster")
            target_domain = res.get("domain")
            matching_props = [p for p in _get_aggregated_proposals(cluster) if p.get("domain") == target_domain]
            self.assertGreater(len(matching_props), 0)
            self.assertTrue(matching_props[0].get("committed"))
            self.assertNotIn("fednode-2", matching_props[0].get("approvals", []))
        finally:
            self._post("/api/actions", {"action": "settings", "node": "fednode-2", "fault": "NONE"})

    def test_5_node_stop_and_catchup_recovery(self):
        self._post("/api/actions", {"action": "stop", "node": "fednode-4"})
        try:
            time.sleep(2)
            self._post("/api/actions", {"action": "inject", "node": "fednode-1", "scenario": "malware"})
            time.sleep(4)
        finally:
            self._post("/api/actions", {"action": "revive", "node": "fednode-4"})
        time.sleep(4)
        cluster = _get("/api/cluster")
        fn4 = next(n for n in cluster["nodes"] if n["node_id"] == "fednode-4")
        fn0 = next(n for n in cluster["nodes"] if n["node_id"] == "fednode-0")
        self.assertEqual(len(fn4.get("blocked_domains", [])), len(fn0.get("blocked_domains", [])))


if __name__ == "__main__":
    unittest.main()
