#!/usr/bin/env python3
"""
End-to-End Demonstration Script for Data Integrity & Anomaly Detection Framework.
Executes complete automated validation pipeline, SQL reconciliation,
cryptographic tampering detection, rule-based discrepancy flagging,
and dead-letter quarantine isolation.
"""

import os
import sys
from datetime import datetime

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data.seed_data import seed_database
from integrity_framework.crypto.hasher import RecordHasher
from integrity_framework.crypto.merkle import MerkleTree
from integrity_framework.models import Severity
from integrity_framework.pipeline.orchestrator import ValidationPipeline
from integrity_framework.pipeline.quarantine import QuarantineStore
from integrity_framework.pipeline.reporter import ReportGenerator
from integrity_framework.rules.engine import RuleEngine
from integrity_framework.sql.checks import SQLAssertion, AggregateAssertion
from integrity_framework.sql.engine import DatabaseEngine
from integrity_framework.sql.reconciler import SQLReconciler


def print_banner(text: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def main():
    print_banner("🛡️  DATA INTEGRITY & ANOMALY DETECTION FRAMEWORK  🛡️")
    print("Automated validation pipeline using SQL-based checks, cryptographic hashing,")
    print("declarative data-quality rules, and dead-letter quarantine isolation.\n")

    db_path = os.path.join(os.path.dirname(__file__), "data", "demo_ledger.db")
    rules_path = os.path.join(os.path.dirname(__file__), "data", "sample_rules.json")
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")

    # Step 1: Database Generation & Cryptographic Seeding
    print("🔹 Step 1: Seeding Relational Database with Cryptographic Hash Baseline...")
    db_engine = seed_database(db_path, record_count=100)

    # Step 2: Initialize Framework Components
    print("\n🔹 Step 2: Configuring Validation Pipeline & Invariant Rules...")
    quarantine = QuarantineStore(db_path)
    rule_engine = RuleEngine()
    rule_engine.load_rules_from_file(rules_path)

    # Register Cross-Field Rule: settled_at must be >= created_at
    from integrity_framework.rules.value_rules import CrossFieldRule
    rule_engine.register_rule(
        CrossFieldRule(
            name="TXN_CHRONOLOGY_CONSISTENCY",
            table_name="transactions",
            predicate=lambda r: (
                not r.get("settled_at") or not r.get("created_at") or r.get("settled_at") >= r.get("created_at")
            ),
            involved_columns=["created_at", "settled_at"],
            expected_description="settled_at timestamp must be greater than or equal to created_at",
            severity=Severity.ERROR,
        )
    )

    pipeline = ValidationPipeline(
        db_engine=db_engine,
        quarantine_store=quarantine,
        rule_engine=rule_engine,
        hasher=RecordHasher("sha256"),
        quarantine_on_error=True,
    )

    # Add SQL Invariants: Positive balances, non-negative amounts
    pipeline.sql_checks.add_row_assertion(
        SQLAssertion(
            name="SQL_NON_NEGATIVE_TXN_AMOUNT",
            table="transactions",
            condition="amount > 0",
            severity=Severity.ERROR,
            description="Transaction amounts must be strictly positive (> 0.00)",
        )
    )
    pipeline.sql_checks.add_row_assertion(
        SQLAssertion(
            name="SQL_POSITIVE_ACCOUNT_BALANCE",
            table="accounts",
            condition="balance >= 0",
            severity=Severity.CRITICAL,
            description="Account balance cannot be overdrawn below zero",
        )
    )

    # Step 3: Run Full Validation Pipeline
    print("\n🔹 Step 3: Executing Automated Validation Pipeline...")
    summary = pipeline.run(
        target_name="Financial Ledger System",
        tables=["accounts", "transactions"],
    )

    # Step 4: Run SQL Set Reconciliation (Staging vs Prod)
    print("\n🔹 Step 4: Running SQL Relational Reconciliation (Staging vs Production)...")
    reconciler = SQLReconciler(db_engine)
    recon_result = reconciler.reconcile_tables(
        source_table="staging_transactions",
        target_table="prod_transactions",
        primary_key="id",
        metric_columns=["amount"],
    )
    summary.check_results.append(recon_result)

    # Step 5: Merkle Tree Dataset Integrity Fingerprint
    print("\n🔹 Step 5: Computing Dataset Merkle Tree Cryptographic Fingerprint...")
    txn_hashes = [
        r["record_hash"]
        for r in db_engine.execute_query("SELECT record_hash FROM transactions WHERE record_hash IS NOT NULL;")
    ]
    merkle = MerkleTree(txn_hashes, hash_algo="sha256")
    print(f"   • Merkle Root Hash: {merkle.root_hash}")
    print(f"   • Total Leaves Indexed: {len(txn_hashes)}")

    # Audit proof verification on first record
    proof = merkle.get_audit_proof(0)
    is_valid_proof = MerkleTree.verify_proof(txn_hashes[0], proof, merkle.root_hash)
    print(f"   • Cryptographic Inclusion Proof (Leaf 0): {'VALID ✅' if is_valid_proof else 'INVALID ❌'}")

    # Step 6: Generate Multi-Format Reports
    print("\n🔹 Step 6: Generating Multi-Format Forensic Audit Reports...")
    reporter = ReportGenerator(summary)
    saved_reports = reporter.save_reports(reports_dir, base_filename="demo_audit_report")

    # Step 7: Display Findings Summary
    print_banner("📊 VALIDATION PIPELINE EXECUTION SUMMARY")
    print(f"• Run ID:             {summary.run_id}")
    print(f"• Integrity Score:    {summary.integrity_score:.1f}%")
    print(f"• Records Checked:    {summary.total_records:,}")
    print(f"• Flagged Anomalies:  {summary.flagged_records:,}")
    print(f"• Quarantined:        {summary.quarantined_records:,}")
    print(f"• Critical Findings:  {summary.findings_by_severity.get('CRITICAL', 0)}")
    print(f"• Error Findings:     {summary.findings_by_severity.get('ERROR', 0)}")
    print(f"• Warning Findings:   {summary.findings_by_severity.get('WARNING', 0)}")
    print(f"• Elapsed Duration:   {summary.duration_seconds:.3f} seconds\n")

    print("🚨 Highlighted Discrepancies Detected:")
    all_findings = []
    for c in summary.check_results:
        all_findings.extend(c.findings)

    for i, f in enumerate(all_findings[:8], 1):
        sev_color = "🔴" if f.severity in (Severity.CRITICAL, "CRITICAL") else ("🟠" if f.severity in (Severity.ERROR, "ERROR") else "🟡")
        print(f"   {i}. {sev_color} [{f.severity}] {f.rule_name} on {f.table_name} (Record {f.record_id}):")
        print(f"      {f.message}")

    print("\n📁 Generated Artifacts:")
    for fmt, path in saved_reports.items():
        print(f"   • {fmt.upper()}: {path}")

    print("\n💡 Next Steps:")
    print("   1. Open HTML Report in browser: file://" + os.path.abspath(saved_reports['html']))
    print("   2. Start Web Dashboard:        python3 run_dashboard.py")
    print("   3. Run Automated Tests:         python3 run_tests.py\n")


if __name__ == "__main__":
    main()
