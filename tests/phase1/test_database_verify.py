import os
import sys
import shutil
import tempfile
import sqlite3

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from node.storage.database import Database
from proto import fedconsensus_pb2 as pb2


def test_sqlite_wal_and_operations():
    """Verify SQLite WAL mode, atomic commits, blocklist queries, and log catchup."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "wal_factor_test.db")
    try:
        db = Database(db_path)

        # 1. Verify WAL Journal Mode
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            journal_mode = cursor.fetchone()[0].lower()
            assert journal_mode == "wal", f"Expected WAL mode, got {journal_mode}"
        print("  [PASS] 1. SQLite WAL (Write-Ahead Logging) journal mode confirmed")

        # 2. Sequence Number starts at 0
        assert db.get_latest_sequence_number() == 0
        print("  [PASS] 2. Sequence number initialized to 0")

        # 3. Save commit record with Quorum Certificate proof
        proof = {
            "proposal_id": "prop-wal-1",
            "target_domain": "malicious-domain.org",
            "signatures": ["sig1", "sig2", "sig3", "sig4"]
        }
        success = db.save_commit_record(
            sequence_number=1,
            epoch=1,
            target_domain="malicious-domain.org",
            reason=pb2.REASON_BOTNET,
            quorum_proof=proof
        )
        assert success is True
        assert db.get_latest_sequence_number() == 1
        print("  [PASS] 3. Atomic commit record and QC proof persisted")

        # 4. Domain Blocklist query
        assert db.is_domain_blocked("malicious-domain.org") is True
        assert db.is_domain_blocked("safe-site.com") is False
        blocked_all = db.get_all_blocked_domains()
        assert "malicious-domain.org" in blocked_all
        print("  [PASS] 4. In-database blocklist queries verified")

        # 5. Catchup log query
        records = db.get_commit_records(from_sequence_number=1)
        assert len(records) == 1
        assert records[0]["target_domain"] == "malicious-domain.org"
        assert len(records[0]["quorum_proof"]["signatures"]) == 4
        print("  [PASS] 5. Catch-up log range query verified")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    print("\n=======================================================")
    print("   PHASE 1 FACTOR: SQLITE WAL STORAGE ENGINE           ")
    print("=======================================================")
    test_sqlite_wal_and_operations()
    print("=======================================================")
    print("   ALL STORAGE ENGINE MODULES PASS 100%!               ")
    print("=======================================================\n")
