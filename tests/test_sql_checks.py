"""Tests for SQL engine, assertions, and dataset reconciliation."""

import unittest
from integrity_framework.models import Severity
from integrity_framework.sql.checks import SQLAssertion, AggregateAssertion, SQLCheckSuite
from integrity_framework.sql.engine import DatabaseEngine
from integrity_framework.sql.reconciler import SQLReconciler


class TestSQLEngineAndChecks(unittest.TestCase):
    def setUp(self):
        self.db = DatabaseEngine(":memory:")
        self.db.execute_script("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                age INTEGER,
                balance REAL DEFAULT 0.0
            );
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                total REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            INSERT INTO users (id, username, age, balance) VALUES (1, 'alice', 30, 100.0);
            INSERT INTO users (id, username, age, balance) VALUES (2, 'bob', 16, -50.0);
            INSERT INTO orders (id, user_id, total) VALUES (101, 1, 45.0);
        """)

    def test_pragma_integrity_pass(self):
        findings = self.db.run_pragma_integrity_check()
        self.assertEqual(len(findings), 0)

    def test_foreign_key_violation(self):
        # Insert orphan order referencing non-existent user 999
        # Need to temporarily bypass FK pragma to simulate corrupt orphan
        with self.db.connect() as conn:
            conn.execute("PRAGMA foreign_keys = OFF;")
            conn.execute("INSERT INTO orders (id, user_id, total) VALUES (999, 9999, 20.0);")
            conn.execute("PRAGMA foreign_keys = ON;")

        findings = self.db.run_pragma_integrity_check()
        self.assertTrue(any(f.rule_name == "FOREIGN_KEY_VIOLATION" for f in findings))

    def test_sql_row_assertion(self):
        suite = SQLCheckSuite(self.db)
        suite.add_row_assertion(
            SQLAssertion(
                name="USER_NON_NEGATIVE_BALANCE",
                table="users",
                condition="balance >= 0",
                severity=Severity.ERROR,
            )
        )
        findings = suite.run_row_assertions()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].record_id, 2)  # Bob has -50.0

    def test_sql_aggregate_assertion(self):
        suite = SQLCheckSuite(self.db)
        suite.add_aggregate_assertion(
            AggregateAssertion(
                name="USER_MINIMUM_TOTAL_BALANCE",
                table="users",
                query="SELECT SUM(balance) as total FROM users;",
                expected_value=100.0,
                operator=">=",
            )
        )
        # Sum is 100 - 50 = 50.0, which is < 100.0 -> violation!
        findings = suite.run_aggregate_assertions()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].actual_value, 50.0)

    def test_sql_uniqueness_check(self):
        # Insert non-duplicate to verify no findings first
        suite = SQLCheckSuite(self.db)
        findings = suite.check_uniqueness("users", ["age"])
        self.assertEqual(len(findings), 0)

        # Insert record with duplicate age to trigger uniqueness violation
        with self.db.connect() as conn:
            conn.execute("INSERT INTO users (id, username, age, balance) VALUES (4, 'carol', 30, 10.0);")
        findings = suite.check_uniqueness("users", ["age"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].actual_value, 2)


class TestSQLReconciler(unittest.TestCase):
    def setUp(self):
        self.db = DatabaseEngine(":memory:")
        self.db.execute_script("""
            CREATE TABLE src_txns (
                id INTEGER PRIMARY KEY,
                uuid TEXT,
                amount REAL,
                status TEXT
            );
            CREATE TABLE tgt_txns (
                id INTEGER PRIMARY KEY,
                uuid TEXT,
                amount REAL,
                status TEXT
            );

            -- Matching row
            INSERT INTO src_txns VALUES (1, 'UUID-1', 100.0, 'SETTLED');
            INSERT INTO tgt_txns VALUES (1, 'UUID-1', 100.0, 'SETTLED');

            -- Row missing in target
            INSERT INTO src_txns VALUES (2, 'UUID-2', 200.0, 'SETTLED');

            -- Row phantom in target
            INSERT INTO tgt_txns VALUES (3, 'UUID-3', 300.0, 'SETTLED');

            -- Row with attribute divergence
            INSERT INTO src_txns VALUES (4, 'UUID-4', 400.0, 'SETTLED');
            INSERT INTO tgt_txns VALUES (4, 'UUID-4', 999.0, 'SETTLED');
        """)
        self.reconciler = SQLReconciler(self.db)

    def test_full_reconciliation(self):
        res = self.reconciler.reconcile_tables(
            source_table="src_txns",
            target_table="tgt_txns",
            primary_key="id",
            metric_columns=["amount"],
        )

        self.assertFalse(res.passed)
        rule_names = [f.rule_name for f in res.findings]

        self.assertIn("RECONCILIATION_MISSING_RECORD", rule_names)
        self.assertIn("RECONCILIATION_UNEXPECTED_RECORD", rule_names)
        self.assertIn("RECONCILIATION_ATTRIBUTE_DIVERGENCE", rule_names)
        self.assertIn("RECONCILIATION_METRIC_DELTA", rule_names)


if __name__ == "__main__":
    unittest.main()
