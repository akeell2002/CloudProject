import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.storage.database import Database
from node.storage.reputation import ReputationManager


class TestReputationManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.temp_dir, "reputation_test.db"))
        self.rep = ReputationManager(self.db)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_penalties_and_quarantine_threshold(self):
        peer = "fednode-rogue"
        self.assertTrue(self.rep.is_peer_eligible_to_vote(peer))

        self.rep.penalize_equivocation(peer)
        peer_entry = next(r for r in self.rep.get_ledger() if r["peer_id"] == peer)
        self.assertEqual(peer_entry["trust_score"], 50)
        self.assertEqual(peer_entry["violations_count"], 1)
        self.assertTrue(self.rep.is_peer_eligible_to_vote(peer))

        self.rep.penalize_forgery(peer)
        peer_entry = next(r for r in self.rep.get_ledger() if r["peer_id"] == peer)
        self.assertEqual(peer_entry["trust_score"], 10)
        self.assertEqual(peer_entry["violations_count"], 2)
        self.assertFalse(self.rep.is_peer_eligible_to_vote(peer))

    def test_recovery_and_reset_behavior(self):
        peer = "fednode-recover"
        self.db.update_reputation(peer, -80, is_violation=True)  # score=20, violations=1
        with self.db._get_connection() as conn:
            anchor = conn.execute(
                "SELECT recovery_anchor_at FROM peer_reputation WHERE peer_id = ?",
                (peer,),
            ).fetchone()["recovery_anchor_at"]

        raised = self.db.recover_reputations(step=5, grace_ms=60_000, interval_ms=30_000, now_ms=anchor + 60_000)
        self.assertGreaterEqual(raised, 1)
        row = next(r for r in self.db.get_all_reputations() if r["peer_id"] == peer)
        self.assertEqual(row["trust_score"], 25)

        # Stale peer reports with the same violation count do not roll back recovery.
        self.db.adopt_lower_reputation(peer, 20, violations_count=1)
        row = next(r for r in self.db.get_all_reputations() if r["peer_id"] == peer)
        self.assertEqual(row["trust_score"], 25)

        # Newer violations are adopted.
        self.db.adopt_lower_reputation(peer, 15, violations_count=2)
        row = next(r for r in self.db.get_all_reputations() if r["peer_id"] == peer)
        self.assertEqual(row["trust_score"], 15)
        self.assertEqual(row["violations_count"], 2)

        self.db.set_reputation(peer, 100)
        row = next(r for r in self.db.get_all_reputations() if r["peer_id"] == peer)
        self.assertEqual(row["trust_score"], 100)
        self.assertEqual(row["violations_count"], 0)


if __name__ == "__main__":
    unittest.main()
