"""End-to-end integration tests for ValidationPipeline and reporting."""

import os
import shutil
import tempfile
import unittest

from integrity_framework.crypto.hasher import RecordHasher
from integrity_framework.models import Severity
from integrity_framework.pipeline.orchestrator import ValidationPipeline
from integrity_framework.pipeline.quarantine import QuarantineStore
from integrity_framework.pipeline.reporter import ReportGenerator
from integrity_framework.rules.engine import RuleEngine
from integrity_framework.rules.value_rules import RangeRule
from integrity_framework.sql.checks import SQLAssertion
from integrity_framework.sql.engine import DatabaseEngine


class TestPipelineEndToEnd(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test.db")
        self.db = DatabaseEngine(self.db_path)
        self.hasher = RecordHasher("sha256")

        # Initialize schema and data
        self.db.execute_script("""
            CREATE TABLE invoices (
                id INTEGER PRIMARY KEY,
                vendor TEXT NOT NULL,
                amount REAL NOT NULL,
                record_hash TEXT
            );
        """)

        # Insert 1 clean record with hash
        rec1 = {"id": 1, "vendor": "Acme Corp", "amount": 100.0}
        h1 = self.hasher.hash_record(rec1)
        self.db.execute_non_query(
            "INSERT INTO invoices (id, vendor, amount, record_hash) VALUES (1, 'Acme Corp', 100.0, ?);",
            [h1],
        )

        # Insert 1 tampered record (hash doesn't match amount)
        self.db.execute_non_query(
            "INSERT INTO invoices (id, vendor, amount, record_hash) VALUES (2, 'Beta Ltd', -50.0, 'tampered_fake_hash');"
        )

        self.quarantine = QuarantineStore(self.db_path)
        self.rule_engine = RuleEngine()
        self.rule_engine.register_rule(
            RangeRule("NON_NEGATIVE_AMOUNT", "invoices", "amount", min_value=0.01)
        )

        self.pipeline = ValidationPipeline(
            db_engine=self.db,
            quarantine_store=self.quarantine,
            rule_engine=self.rule_engine,
            hasher=self.hasher,
            quarantine_on_error=True,
        )

        self.pipeline.sql_checks.add_row_assertion(
            SQLAssertion(
                name="SQL_INVOICE_AMOUNT_POS",
                table="invoices",
                condition="amount > 0",
                severity=Severity.ERROR,
            )
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_pipeline_execution_and_quarantine(self):
        summary = self.pipeline.run(target_name="Test Invoices DB")

        self.assertEqual(summary.total_records, 2)
        self.assertEqual(summary.passed_records, 1)
        self.assertEqual(summary.flagged_records, 1)
        self.assertEqual(summary.quarantined_records, 1)
        self.assertLess(summary.integrity_score, 100.0)

        # Verify record 2 is quarantined
        q_records = self.quarantine.list_quarantined()
        self.assertEqual(len(q_records), 1)
        self.assertEqual(q_records[0]["record_id"], "2")

    def test_multi_format_reporting(self):
        summary = self.pipeline.run(target_name="Test Invoices DB")
        reporter = ReportGenerator(summary)

        # 1. JSON
        json_str = reporter.to_json()
        self.assertIn("Test Invoices DB", json_str)
        self.assertIn("findings_by_severity", json_str)

        # 2. CSV
        csv_str = reporter.to_csv()
        self.assertIn("finding_id,timestamp,severity", csv_str)
        self.assertIn("invoices", csv_str)

        # 3. Markdown
        md_str = reporter.to_markdown()
        self.assertIn("# 🛡️ Data Integrity Audit Report", md_str)
        self.assertIn("Executive Metric Summary", md_str)

        # 4. HTML
        html_str = reporter.to_html()
        self.assertIn("<!DOCTYPE html>", html_str)
        self.assertIn("Data Integrity Audit", html_str)

        # 5. File saving
        reports_dir = os.path.join(self.temp_dir, "out_reports")
        saved = reporter.save_reports(reports_dir)
        for fmt, p in saved.items():
            self.assertTrue(os.path.exists(p), f"Report file for {fmt} was not created: {p}")


if __name__ == "__main__":
    unittest.main()
