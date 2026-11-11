#!/usr/bin/env python3
"""
Dashboard server launcher for Data Integrity & Anomaly Detection Framework.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data.seed_data import seed_database
from integrity_framework.crypto.hasher import RecordHasher
from integrity_framework.models import Severity
from integrity_framework.pipeline.orchestrator import ValidationPipeline
from integrity_framework.pipeline.quarantine import QuarantineStore
from integrity_framework.rules.engine import RuleEngine
from integrity_framework.sql.checks import SQLAssertion
from integrity_framework.sql.engine import DatabaseEngine
from integrity_framework.web.server import start_server


def setup_demo_pipeline() -> ValidationPipeline:
    db_path = os.path.join(os.path.dirname(__file__), "data", "demo_ledger.db")
    rules_path = os.path.join(os.path.dirname(__file__), "data", "sample_rules.json")

    if not os.path.exists(db_path):
        print("🌱 Seeding initial demo database...")
        seed_database(db_path, record_count=120)

    db_engine = DatabaseEngine(db_path)
    quarantine = QuarantineStore(db_path)
    rule_engine = RuleEngine()

    if os.path.exists(rules_path):
        rule_engine.load_rules_from_file(rules_path)

    pipeline = ValidationPipeline(
        db_engine=db_engine,
        quarantine_store=quarantine,
        rule_engine=rule_engine,
        hasher=RecordHasher("sha256"),
        quarantine_on_error=True,
    )

    pipeline.sql_checks.add_row_assertion(
        SQLAssertion(
            name="SQL_NON_NEGATIVE_TXN_AMOUNT",
            table="transactions",
            condition="amount > 0",
            severity=Severity.ERROR,
            description="Transaction amounts must be positive",
        )
    )

    return pipeline


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8088))
    pipeline = setup_demo_pipeline()
    start_server(pipeline=pipeline, host="127.0.0.1", port=port)
