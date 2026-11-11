"""
SQLite database engine with Write-Ahead Logging (WAL), foreign key enforcement,
and pragma integrity diagnostics.
"""

from contextlib import contextmanager
import os
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Sequence, Tuple, Union
from integrity_framework.models import Finding, Severity, CheckType


class DatabaseEngine:
    """
    Manages SQLite database operations, transactions, and structural integrity checks.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON;")
        self._ensure_parent_dir()
        self._init_pragmas()

    def _ensure_parent_dir(self) -> None:
        if self.db_path != ":memory:":
            parent = os.path.dirname(os.path.abspath(self.db_path))
            if parent:
                os.makedirs(parent, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Create and configure a SQLite connection."""
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _init_pragmas(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA foreign_keys = ON;")

    @contextmanager
    def connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager yielding a transactional SQLite connection."""
        if self._mem_conn is not None:
            try:
                yield self._mem_conn
                self._mem_conn.commit()
            except Exception:
                self._mem_conn.rollback()
                raise
        else:
            conn = self.get_connection()
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def execute_query(
        self, query: str, params: Union[Sequence[Any], Dict[str, Any]] = ()
    ) -> List[Dict[str, Any]]:
        """Execute a SELECT query and return rows as dictionaries."""
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def execute_non_query(
        self, query: str, params: Union[Sequence[Any], Dict[str, Any]] = ()
    ) -> int:
        """Execute an INSERT/UPDATE/DELETE query and return affected rows count."""
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.rowcount

    def execute_script(self, script: str) -> None:
        """Execute multiple SQL statements sequentially."""
        with self.connect() as conn:
            conn.executescript(script)

    def get_table_names(self) -> List[str]:
        """Return list of user tables in the database."""
        query = (
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name;"
        )
        rows = self.execute_query(query)
        return [r["name"] for r in rows]

    def get_table_columns(self, table_name: str) -> List[Dict[str, Any]]:
        """Return schema columns for a given table."""
        # Clean table name to prevent injection
        safe_table = table_name.replace('"', '""')
        rows = self.execute_query(f'PRAGMA table_info("{safe_table}");')
        return [
            {
                "cid": r["cid"],
                "name": r["name"],
                "type": r["type"],
                "notnull": bool(r["notnull"]),
                "default_value": r["dflt_value"],
                "pk": bool(r["pk"]),
            }
            for r in rows
        ]

    def get_row_count(self, table_name: str) -> int:
        """Return total row count of a table."""
        safe_table = table_name.replace('"', '""')
        rows = self.execute_query(f'SELECT COUNT(*) as cnt FROM "{safe_table}";')
        return rows[0]["cnt"] if rows else 0

    def run_pragma_integrity_check(self) -> List[Finding]:
        """
        Run low-level SQLite database integrity and foreign key checks.
        """
        findings: List[Finding] = []

        with self.connect() as conn:
            # 1. PRAGMA integrity_check
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check;")
            rows = cursor.fetchall()
            for r in rows:
                val = r[0]
                if val.lower() != "ok":
                    findings.append(
                        Finding(
                            rule_name="SQLITE_PRAGMA_INTEGRITY",
                            check_type=CheckType.SQL_INVARIANT,
                            severity=Severity.CRITICAL,
                            table_name="SYSTEM_DATABASE",
                            message=f"Database page corruption detected: {val}",
                        )
                    )

            # 2. PRAGMA foreign_key_check
            cursor.execute("PRAGMA foreign_key_check;")
            fk_rows = cursor.fetchall()
            for r in fk_rows:
                # r: table, rowid, parent_table, fkid
                table_name = r[0]
                rowid = r[1]
                parent_table = r[2]
                fkid = r[3]
                findings.append(
                    Finding(
                        rule_name="FOREIGN_KEY_VIOLATION",
                        check_type=CheckType.SQL_INVARIANT,
                        severity=Severity.ERROR,
                        table_name=table_name,
                        record_id=rowid,
                        expected_value=f"Existing parent record in '{parent_table}'",
                        actual_value="Orphan foreign key reference",
                        message=(
                            f"Foreign key constraint broken in table '{table_name}' rowid '{rowid}' "
                            f"referencing missing parent in '{parent_table}'"
                        ),
                        details={"parent_table": parent_table, "fk_index": fkid},
                    )
                )

        return findings
