import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.storage.database import Database
from proto import fedconsensus_pb2 as pb2


class TestDatabaseStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "wal_test.db")
        self.db = Database(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_wal_mode_commits_and_catchup_queries(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            self.assertEqual(cursor.fetchone()[0].lower(), "wal")

        self.assertEqual(self.db.get_latest_sequence_number(), 0)

        proof = {
            "proposal_id": "prop-wal-1",
            "target_domain": "malicious-domain.org",
            "signatures": ["sig1", "sig2", "sig3", "sig4"],
        }
        success = self.db.save_commit_record(
            sequence_number=1,
            epoch=1,
            target_domain="malicious-domain.org",
            reason=pb2.REASON_BOTNET,
            quorum_proof=proof,
        )
        self.assertTrue(success)
        self.assertEqual(self.db.get_latest_sequence_number(), 1)

        self.assertTrue(self.db.is_domain_blocked("malicious-domain.org"))
        self.assertFalse(self.db.is_domain_blocked("safe-site.com"))
        self.assertIn("malicious-domain.org", self.db.get_all_blocked_domains())

        records = self.db.get_commit_records(from_sequence_number=1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["target_domain"], "malicious-domain.org")
        self.assertEqual(len(records[0]["quorum_proof"]["signatures"]), 4)


if __name__ == "__main__":
    unittest.main()
