"""
Quarantine and dead-letter store.
Isolates anomalous, corrupted, or tampered records from downstream data processing
while recording full provenance for audit and forensic investigation.
"""

from datetime import datetime
import json
import sqlite3
from typing import Any, Dict, List, Optional, Union
from integrity_framework.models import Finding, Severity


class QuarantineStore:
    """
    Manages quarantine isolation for bad records.
    Can operate against a SQLite database table or an in-memory/file store.
    """

    TABLE_SCHEMA = """
    CREATE TABLE IF NOT EXISTS _quarantine_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        quarantine_id TEXT UNIQUE NOT NULL,
        source_table TEXT NOT NULL,
        record_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        violated_rules TEXT NOT NULL,
        raw_record_json TEXT NOT NULL,
        reason TEXT NOT NULL,
        status TEXT DEFAULT 'OPEN', -- OPEN, INVESTIGATING, RESOLVED, REJECTED
        quarantined_at TEXT DEFAULT CURRENT_TIMESTAMP,
        resolved_at TEXT,
        resolved_by TEXT,
        resolution_notes TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_quarantine_table ON _quarantine_records(source_table);
    CREATE INDEX IF NOT EXISTS idx_quarantine_status ON _quarantine_records(status);
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(self.TABLE_SCHEMA)

    def quarantine_record(
        self,
        source_table: str,
        record_id: Union[str, int],
        raw_record: Dict[str, Any],
        findings: List[Finding],
    ) -> str:
        """
        Quarantine a record associated with one or more findings.
        Returns unique quarantine ID.
        """
        import uuid
        quarantine_id = f"Q-{uuid.uuid4().hex[:10].upper()}"
        highest_severity = "WARNING"
        if any(f.severity in (Severity.CRITICAL, "CRITICAL") for f in findings):
            highest_severity = "CRITICAL"
        elif any(f.severity in (Severity.ERROR, "ERROR") for f in findings):
            highest_severity = "ERROR"

        rules = sorted(list({f.rule_name for f in findings}))
        reasons = "; ".join(f.message for f in findings if f.message)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO _quarantine_records (
                    quarantine_id, source_table, record_id, severity,
                    violated_rules, raw_record_json, reason, quarantined_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    quarantine_id,
                    source_table,
                    str(record_id),
                    highest_severity,
                    json.dumps(rules),
                    json.dumps(raw_record, default=str),
                    reasons,
                    datetime.utcnow().isoformat() + "Z",
                ),
            )
        return quarantine_id

    def list_quarantined(
        self,
        status: Optional[str] = None,
        source_table: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List quarantined records with optional filtering."""
        query = "SELECT * FROM _quarantine_records WHERE 1=1"
        params: List[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status.upper())
        if source_table:
            query += " AND source_table = ?"
            params.append(source_table)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["violated_rules"] = json.loads(item["violated_rules"])
                except Exception:
                    pass
                try:
                    item["raw_record"] = json.loads(item["raw_record_json"])
                except Exception:
                    pass
                results.append(item)
            return results

    def get_count(self, status: Optional[str] = "OPEN") -> int:
        """Get count of quarantined records."""
        query = "SELECT COUNT(*) as cnt FROM _quarantine_records"
        params: List[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status.upper())
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()["cnt"]

    def resolve_record(
        self,
        quarantine_id: str,
        resolution_status: str = "RESOLVED",
        resolved_by: str = "analyst",
        notes: str = "",
    ) -> bool:
        """Mark a quarantined record as resolved or rejected."""
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                UPDATE _quarantine_records
                SET status = ?, resolved_at = ?, resolved_by = ?, resolution_notes = ?
                WHERE quarantine_id = ?;
                """,
                (
                    resolution_status.upper(),
                    datetime.utcnow().isoformat() + "Z",
                    resolved_by,
                    notes,
                    quarantine_id,
                ),
            )
            return cur.rowcount > 0
