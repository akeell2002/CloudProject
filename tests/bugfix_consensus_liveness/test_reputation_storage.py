"""Unit and property tests for task 3.1 (reputation and storage).

Covers keyed penalty idempotency, the self-exemption, lower-only peer adoption,
the recovery-column migration on a pre-fix database, and the recovery timing
(60 s grace, then +5 every 30 s, capped at 100).

Time is injected: the database module's clock is replaced with a fixed integer
base so millisecond arithmetic is exact, and apply_recovery receives ``now``.

Run: python tests/bugfix_consensus_liveness/test_reputation_storage.py
"""
import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import gc
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch

from hypothesis import HealthCheck, given, settings, strategies as st

import node.storage.database as database_module
from node.storage.database import Database
from node.storage.reputation import ReputationManager

BASE = 1_700_000_000  # fixed integer epoch seconds


def fixed_clock(seconds):
    return types.SimpleNamespace(time=lambda: seconds)


def row_of(db, peer_id):
    return next((r for r in db.get_all_reputations() if r["peer_id"] == peer_id), None)


def trust_of(db, peer_id):
    row = row_of(db, peer_id)
    return 100 if row is None else row["trust_score"]


def expected_recovered(start, t):
    if t < ReputationManager.RECOVERY_GRACE_SECONDS:
        return start
    steps = (t - 60) // 30 + 1
    return min(100, start + 5 * steps)


class TempDbCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(gc.collect)
        self._counter = 0

    def new_db(self):
        self._counter += 1
        return Database(os.path.join(self.temp.name, f"rep-{self._counter}.db"))


class KeyedPenaltyTests(TempDbCase):
    def test_keyed_penalty_applies_once_per_type_peer_proposal(self):
        db = self.new_db()
        rep = ReputationManager(db)
        self.assertTrue(rep.penalize_equivocation("fednode-1", proposal_id="prop-1"))
        for _ in range(5):
            self.assertFalse(rep.penalize_equivocation("fednode-1", proposal_id="prop-1"))
        self.assertEqual(trust_of(db, "fednode-1"), 50)
        self.assertEqual(row_of(db, "fednode-1")["violations_count"], 1)
        self.assertTrue(rep.is_peer_eligible_to_vote("fednode-1"))

        # A different type, proposal or peer is a different key.
        self.assertTrue(rep.penalize_forgery("fednode-1", proposal_id="prop-1"))
        self.assertTrue(rep.penalize_bogus_evidence("fednode-2", proposal_id="prop-1"))
        self.assertTrue(rep.penalize_equivocation("fednode-2", proposal_id="prop-2"))
        self.assertEqual(trust_of(db, "fednode-1"), 10)
        self.assertEqual(trust_of(db, "fednode-2"), 25)

    def test_unkeyed_penalty_always_applies(self):
        db = self.new_db()
        rep = ReputationManager(db)
        self.assertTrue(rep.penalize_equivocation("fednode-1"))
        self.assertTrue(rep.penalize_equivocation("fednode-1"))
        self.assertEqual(trust_of(db, "fednode-1"), 0)
        self.assertEqual(row_of(db, "fednode-1")["violations_count"], 2)

    def test_key_store_is_capped_oldest_first(self):
        rep = ReputationManager(self.new_db())
        rep.MAX_PENALTY_KEYS = 3
        for i in range(4):
            self.assertTrue(rep.penalize_bogus_evidence("fednode-1", proposal_id=f"prop-{i}"))
        self.assertEqual(len(rep._penalty_keys), 3)
        self.assertNotIn(("bogus_evidence", "fednode-1", "prop-0"), rep._penalty_keys)
        self.assertFalse(rep.penalize_bogus_evidence("fednode-1", proposal_id="prop-3"))


class SelfExemptionTests(TempDbCase):
    def test_automatic_penalties_on_self_are_noops(self):
        db = self.new_db()
        rep = ReputationManager(db, self_id="fednode-1")
        self.assertFalse(rep.penalize_forgery("fednode-1", proposal_id="p"))
        self.assertFalse(rep.penalize_equivocation("fednode-1", proposal_id="p"))
        self.assertFalse(rep.penalize_bogus_evidence("fednode-1"))
        self.assertFalse(rep.penalize_censorship("fednode-1"))
        self.assertIsNone(row_of(db, "fednode-1"))
        self.assertTrue(rep.penalize_censorship("fednode-2"))
        self.assertEqual(trust_of(db, "fednode-2"), 70)

    def test_adopt_peer_view_only_lowers_and_skips_self(self):
        db = self.new_db()
        rep = ReputationManager(db, self_id="fednode-0")
        self.assertFalse(rep.adopt_peer_view("fednode-0", 0))
        self.assertIsNone(row_of(db, "fednode-0"))

        db.set_reputation("fednode-3", 10)
        anchor = self._anchor(db, "fednode-3")
        self.assertTrue(rep.adopt_peer_view("fednode-3", 25))
        self.assertEqual(trust_of(db, "fednode-3"), 10)
        rep.penalize_bogus_evidence("fednode-4")  # 75, one violation
        anchor4 = self._anchor(db, "fednode-4")
        rep.adopt_peer_view("fednode-4", 20)
        row = row_of(db, "fednode-4")
        self.assertEqual((row["trust_score"], row["is_active"], row["violations_count"]), (20, 0, 1))
        self.assertEqual(self._anchor(db, "fednode-4"), anchor4)
        self.assertEqual(self._anchor(db, "fednode-3"), anchor)

        rep.adopt_peer_view("fednode-2", 0)  # missing row is inserted
        row = row_of(db, "fednode-2")
        self.assertEqual((row["trust_score"], row["is_active"], row["violations_count"]), (0, 0, 0))
        self.assertGreater(self._anchor(db, "fednode-2"), 0)

    @staticmethod
    def _anchor(db, peer_id):
        with db._get_connection() as conn:
            return conn.execute("SELECT recovery_anchor_at FROM peer_reputation WHERE peer_id = ?",
                                (peer_id,)).fetchone()[0]


class MigrationTests(TempDbCase):
    def test_pre_fix_database_is_migrated_once_with_backfill(self):
        path = os.path.join(self.temp.name, "legacy.db")
        conn = sqlite3.connect(path)
        conn.execute("""CREATE TABLE peer_reputation (
            peer_id TEXT PRIMARY KEY, trust_score INTEGER DEFAULT 100,
            violations_count INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1,
            last_updated INTEGER NOT NULL);""")
        conn.execute("INSERT INTO peer_reputation VALUES ('fednode-1', 0, 2, 0, 1234)")
        conn.execute("INSERT INTO peer_reputation VALUES ('fednode-2', 100, 0, 1, 5678)")
        conn.commit()
        conn.close()

        db = Database(path)

        def snapshot():
            with db._get_connection() as c:
                return {r["peer_id"]: (r["recovery_anchor_at"], r["last_recovery_at"])
                        for r in c.execute("SELECT * FROM peer_reputation")}

        self.assertEqual(snapshot(), {"fednode-1": (1234, 0), "fednode-2": (0, 0)})
        self.assertEqual(set(db.get_all_reputations()[0]),
                         {"peer_id", "trust_score", "violations_count", "is_active", "last_updated"})

        with db._get_connection() as c:
            c.execute("UPDATE peer_reputation SET recovery_anchor_at = 9999 WHERE peer_id = 'fednode-1'")
        db.init_db()  # re-running is a no-op: no error, no second backfill
        self.assertEqual(snapshot(), {"fednode-1": (9999, 0), "fednode-2": (0, 0)})

        rep = ReputationManager(db)
        self.assertEqual(rep.apply_recovery(now=1234 / 1000 + 10_000), 1)
        self.assertEqual(trust_of(db, "fednode-1"), 5)


class RecoveryTimingTests(TempDbCase):
    def run_ticks(self, rep, db, peer, start, until, check=None):
        for t in range(0, until + 1, 2):
            rep.apply_recovery(now=BASE + t)
            if check is not None:
                check(t, trust_of(db, peer))

    @settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(start=st.integers(min_value=0, max_value=100))
    def test_recovery_follows_grace_then_step_schedule(self, start):
        """**Validates: Requirements 2.5**"""
        db = self.new_db()
        rep = ReputationManager(db)
        with patch.object(database_module, "time", fixed_clock(BASE)):
            db.set_reputation("fednode-1", start)  # operator-set score also recovers

        def check(t, trust):
            self.assertEqual(trust, expected_recovered(start, t), f"start={start} t={t}")
            self.assertLessEqual(trust, 100)
            self.assertEqual(rep.is_peer_eligible_to_vote("fednode-1"), trust >= 30)

        self.run_ticks(rep, db, "fednode-1", start, 400, check)

    def test_zero_reaches_quarantine_threshold_by_210_seconds(self):
        db = self.new_db()
        rep = ReputationManager(db)
        with patch.object(database_module, "time", fixed_clock(BASE)):
            rep.penalize_equivocation("fednode-1")
            rep.penalize_equivocation("fednode-1")
        self.assertEqual(trust_of(db, "fednode-1"), 0)
        self.run_ticks(rep, db, "fednode-1", 0, 208)
        self.assertLess(trust_of(db, "fednode-1"), 30)
        rep.apply_recovery(now=BASE + 210)
        self.assertEqual(trust_of(db, "fednode-1"), 30)
        self.assertTrue(rep.is_peer_eligible_to_vote("fednode-1"))

    def test_new_violation_restarts_grace_period(self):
        db = self.new_db()
        rep = ReputationManager(db)
        with patch.object(database_module, "time", fixed_clock(BASE)):
            db.set_reputation("fednode-1", 60)
        self.run_ticks(rep, db, "fednode-1", 60, 90)
        self.assertEqual(trust_of(db, "fednode-1"), 70)
        with patch.object(database_module, "time", fixed_clock(BASE + 100)):
            rep.penalize_bogus_evidence("fednode-1")  # 70 -> 45, anchor = t 100
        for t in range(100, 160, 2):
            rep.apply_recovery(now=BASE + t)
        self.assertEqual(trust_of(db, "fednode-1"), 45)
        rep.apply_recovery(now=BASE + 160)
        self.assertEqual(trust_of(db, "fednode-1"), 50)

    def test_reward_does_not_reset_anchor(self):
        db = self.new_db()
        rep = ReputationManager(db)
        with patch.object(database_module, "time", fixed_clock(BASE)):
            db.set_reputation("fednode-1", 40)
        with patch.object(database_module, "time", fixed_clock(BASE + 50)):
            rep.reward_honest_participation("fednode-1")  # 42
        rep.apply_recovery(now=BASE + 60)
        self.assertEqual(trust_of(db, "fednode-1"), 47)


if __name__ == "__main__":
    unittest.main()
