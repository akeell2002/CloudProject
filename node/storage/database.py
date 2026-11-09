import os
import json
import sqlite3
import time
from typing import List, Dict, Set, Optional, Any


class Database:
    """
    ACID Relational Storage Engine with Write-Ahead Logging (WAL).
    Persists consensus decisions, quorum proofs, and peer reputations across container reboots.
    """
    def __init__(self, db_path: str = "wal.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initializes SQLite database with Write-Ahead Logging (WAL) mode."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Enable WAL mode for high concurrency and crash resilience
            cursor.execute("PRAGMA journal_mode = WAL;")
            cursor.execute("PRAGMA synchronous = NORMAL;")

            # 1. Committed defederation ledger with Quorum Proofs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS committed_defederations (
                    sequence_number INTEGER PRIMARY KEY,
                    epoch INTEGER NOT NULL,
                    target_domain TEXT NOT NULL,
                    reason INTEGER NOT NULL,
                    quorum_proof_json TEXT NOT NULL,
                    committed_at INTEGER NOT NULL
                );
            """)

            # 2. Active defederation blocklist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS active_blocklist (
                    target_domain TEXT PRIMARY KEY,
                    sequence_number INTEGER NOT NULL,
                    reason INTEGER NOT NULL,
                    committed_at INTEGER NOT NULL
                );
            """)

            # 3. Dynamic Peer Reputation Ledger
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS peer_reputation (
                    peer_id TEXT PRIMARY KEY,
                    trust_score INTEGER DEFAULT 100,
                    violations_count INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    last_updated INTEGER NOT NULL
                );
            """)

            # Recovery columns (idempotent migration for pre-existing ledgers)
            columns = {row["name"] for row in cursor.execute("PRAGMA table_info(peer_reputation);")}
            if "recovery_anchor_at" not in columns:
                cursor.execute(
                    "ALTER TABLE peer_reputation ADD COLUMN recovery_anchor_at INTEGER NOT NULL DEFAULT 0;"
                )
                # Existing low scores recover once the grace period after their last update ends.
                cursor.execute(
                    "UPDATE peer_reputation SET recovery_anchor_at = last_updated WHERE trust_score < 100;"
                )
            if "last_recovery_at" not in columns:
                cursor.execute(
                    "ALTER TABLE peer_reputation ADD COLUMN last_recovery_at INTEGER NOT NULL DEFAULT 0;"
                )
            conn.commit()

    def save_commit_record(
        self,
        sequence_number: int,
        epoch: int,
        target_domain: str,
        reason: int,
        quorum_proof: Dict[str, Any],
        committed_at: Optional[int] = None
    ) -> bool:
        """Persists a finalized consensus decision atomically."""
        if committed_at is None:
            committed_at = int(time.time() * 1000)

        proof_json = json.dumps(quorum_proof)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO committed_defederations 
                    (sequence_number, epoch, target_domain, reason, quorum_proof_json, committed_at)
                    VALUES (?, ?, ?, ?, ?, ?);
                """, (sequence_number, epoch, target_domain, reason, proof_json, committed_at))

                cursor.execute("""
                    INSERT OR REPLACE INTO active_blocklist
                    (target_domain, sequence_number, reason, committed_at)
                    VALUES (?, ?, ?, ?);
                """, (target_domain, sequence_number, reason, committed_at))

                conn.commit()
                return True
            except sqlite3.Error:
                conn.rollback()
                return False

    def get_commit_records(self, from_sequence_number: int) -> List[Dict[str, Any]]:
        """
        Retrieves committed records starting from sequence_number.
        Used by the CatchupSync RPC when a recovered node asks for missing history.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT sequence_number, epoch, target_domain, reason, quorum_proof_json, committed_at
                FROM committed_defederations
                WHERE sequence_number >= ?
                ORDER BY sequence_number ASC;
            """, (from_sequence_number,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "sequence_number": r["sequence_number"],
                    "epoch": r["epoch"],
                    "target_domain": r["target_domain"],
                    "reason": r["reason"],
                    "quorum_proof": json.loads(r["quorum_proof_json"]),
                    "committed_at": r["committed_at"]
                })
            return results

    def get_latest_sequence_number(self) -> int:
        """Returns the highest committed sequence number, or 0 if empty."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(sequence_number) as max_seq FROM committed_defederations;")
            row = cursor.fetchone()
            if row and row["max_seq"] is not None:
                return int(row["max_seq"])
            return 0

    def get_all_blocked_domains(self) -> Set[str]:
        """Returns the set of all actively blocked domains."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT target_domain FROM active_blocklist;")
            rows = cursor.fetchall()
            return {r["target_domain"] for r in rows}

    def is_domain_blocked(self, domain: str) -> bool:
        """Checks if a domain is currently on the active blocklist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM active_blocklist WHERE target_domain = ? LIMIT 1;", (domain,))
            return cursor.fetchone() is not None

    def set_reputation(self, peer_id: str, target_score: int):
        """Sets absolute peer trust score (bounded between 0 and 100)."""
        now = int(time.time() * 1000)
        bounded = max(0, min(100, int(target_score)))
        is_active = 0 if bounded < 30 else 1
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO peer_reputation
                    (peer_id, trust_score, violations_count, is_active, last_updated, recovery_anchor_at)
                VALUES (?, ?, 0, ?, ?, ?)
                ON CONFLICT(peer_id) DO UPDATE SET
                    trust_score = ?,
                    is_active = ?,
                    last_updated = ?,
                    recovery_anchor_at = ?;
            """, (peer_id, bounded, is_active, now, now, bounded, is_active, now, now))
            conn.commit()

    def update_reputation(self, peer_id: str, score_delta: int, is_violation: bool = False):
        """Adjusts peer trust score (bounded between 0 and 100)."""
        now = int(time.time() * 1000)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO peer_reputation (peer_id, trust_score, violations_count, is_active, last_updated)
                VALUES (?, 100, 0, 1, ?)
                ON CONFLICT(peer_id) DO NOTHING;
            """, (peer_id, now))

            violation_add = 1 if is_violation else 0
            cursor.execute("""
                UPDATE peer_reputation
                SET trust_score = MAX(0, MIN(100, trust_score + ?)),
                    violations_count = violations_count + ?,
                    is_active = CASE WHEN MAX(0, MIN(100, trust_score + ?)) < 30 THEN 0 ELSE 1 END,
                    last_updated = ?,
                    recovery_anchor_at = CASE WHEN ? THEN ? ELSE recovery_anchor_at END
                WHERE peer_id = ?;
            """, (score_delta, violation_add, score_delta, now, violation_add, now, peer_id))
            conn.commit()

    def recover_reputations(self, step: int, grace_ms: int, interval_ms: int, now_ms: int) -> int:
        """Raises scores below 100 by ``step`` for rows whose last violation (or operator
        write) is at least ``grace_ms`` old and whose last recovery is at least
        ``interval_ms`` old. Returns the number of rows raised."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE peer_reputation
                SET trust_score = MIN(100, trust_score + ?),
                    is_active = CASE WHEN MIN(100, trust_score + ?) < 30 THEN 0 ELSE 1 END,
                    last_recovery_at = ?,
                    last_updated = ?
                WHERE trust_score < 100
                  AND ? - recovery_anchor_at >= ?
                  AND ? - last_recovery_at >= ?;
            """, (step, step, now_ms, now_ms, now_ms, grace_ms, now_ms, interval_ms))
            raised = cursor.rowcount
            conn.commit()
            return raised

    def adopt_lower_reputation(self, peer_id: str, score: int):
        """Adopts a peer-reported score only if it is lower than the local one.
        Keeps the recovery anchor and violations_count of an existing row."""
        now = int(time.time() * 1000)
        bounded = max(0, min(100, int(score)))
        is_active = 0 if bounded < 30 else 1
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO peer_reputation
                    (peer_id, trust_score, violations_count, is_active, last_updated, recovery_anchor_at)
                VALUES (?, ?, 0, ?, ?, ?)
                ON CONFLICT(peer_id) DO UPDATE SET
                    trust_score = MIN(trust_score, ?),
                    is_active = CASE WHEN MIN(trust_score, ?) < 30 THEN 0 ELSE 1 END,
                    last_updated = ?;
            """, (peer_id, bounded, is_active, now, now, bounded, bounded, now))
            conn.commit()

    def get_all_reputations(self) -> List[Dict[str, Any]]:
        """Retrieves reputation stats for all registered peers."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT peer_id, trust_score, violations_count, is_active, last_updated
                FROM peer_reputation;
            """)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]