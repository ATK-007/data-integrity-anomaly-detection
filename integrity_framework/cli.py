"""
Command Line Interface (CLI) for Data Integrity & Anomaly Detection Framework.
"""

import argparse
import json
import os
import sys
from typing import List, Optional

from integrity_framework import __version__
from integrity_framework.crypto.hasher import RecordHasher
from integrity_framework.models import Severity
from integrity_framework.pipeline.orchestrator import ValidationPipeline
from integrity_framework.pipeline.quarantine import QuarantineStore
from integrity_framework.pipeline.reporter import ReportGenerator
from integrity_framework.rules.engine import RuleEngine
from integrity_framework.sql.engine import DatabaseEngine
from integrity_framework.sql.reconciler import SQLReconciler


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="integrity",
        description="Data Integrity & Anomaly Detection Framework | Python, SQL",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. Validate Command
    val_parser = subparsers.add_parser("validate", help="Execute validation pipeline on a SQLite database")
    val_parser.add_argument("--db", required=True, help="Path to SQLite database file")
    val_parser.add_argument("--rules", help="Path to rules JSON config file")
    val_parser.add_argument("--tables", nargs="*", help="Specific tables to validate")
    val_parser.add_argument("--out-dir", default="./reports", help="Directory to save generated audit reports")
    val_parser.add_argument("--quarantine-db", help="Path to quarantine database (defaults to target DB)")

    # 2. Reconcile Command
    rec_parser = subparsers.add_parser("reconcile", help="Reconcile source and target tables")
    rec_parser.add_argument("--db", required=True, help="Path to SQLite database file")
    rec_parser.add_argument("--source", required=True, help="Source table name")
    rec_parser.add_argument("--target", required=True, help="Target table name")
    rec_parser.add_argument("--pk", default="id", help="Primary key column name")
    rec_parser.add_argument("--metrics", nargs="*", help="Metric columns to reconcile totals for")

    # 3. Quarantine Command
    q_parser = subparsers.add_parser("quarantine", help="Inspect quarantined records")
    q_parser.add_argument("--db", required=True, help="Path to SQLite database")
    q_parser.add_argument("--status", choices=["OPEN", "RESOLVED", "REJECTED"], default="OPEN")
    q_parser.add_argument("--limit", type=int, default=20)

    # 4. Hash Stamp Command
    hash_parser = subparsers.add_parser("stamp-hashes", help="Calculate and update cryptographic hashes on records")
    hash_parser.add_argument("--db", required=True, help="Path to SQLite database")
    hash_parser.add_argument("--table", required=True, help="Table name to stamp hashes for")
    hash_parser.add_argument("--hash-col", default="record_hash", help="Target hash column name")
    hash_parser.add_argument("--algo", default="sha256", choices=["sha256", "blake2b"])

    return parser


def handle_validate(args: argparse.Namespace) -> int:
    print(f"\n🚀 Starting Data Integrity & Anomaly Detection Pipeline...")
    print(f"📦 Target Database: {args.db}")

    db = DatabaseEngine(args.db)
    q_db = args.quarantine_db or args.db
    quarantine = QuarantineStore(q_db)

    rule_engine = RuleEngine()
    if args.rules and os.path.exists(args.rules):
        print(f"📋 Loading declarative rules from: {args.rules}")
        rule_engine.load_rules_from_file(args.rules)

    pipeline = ValidationPipeline(
        db_engine=db,
        quarantine_store=quarantine,
        rule_engine=rule_engine,
    )

    summary = pipeline.run(
        target_name=os.path.basename(args.db),
        tables=args.tables,
    )

    reporter = ReportGenerator(summary)
    saved_files = reporter.save_reports(args.out_dir)

    print("\n" + "=" * 60)
    print(f"🏁 Validation Run Completed: {summary.run_id}")
    print(f"⏱️  Duration: {summary.duration_seconds:.3f} seconds")
    print(f"📊 Integrity Score: {summary.integrity_score:.1f}%")
    print(f"🔍 Total Records: {summary.total_records:,}")
    print(f"✅ Clean Records: {summary.passed_records:,}")
    print(f"🚨 Flagged Records: {summary.flagged_records:,}")
    print(f"🛑 Quarantined Records: {summary.quarantined_records:,}")
    print(f"📁 Reports Generated:")
    for fmt, p in saved_files.items():
        print(f"   • {fmt.upper()}: {p}")
    print("=" * 60 + "\n")

    return 0 if summary.flagged_records == 0 else 1


def handle_reconcile(args: argparse.Namespace) -> int:
    print(f"\n⚖️  Reconciling '{args.source}' against '{args.target}'...")
    db = DatabaseEngine(args.db)
    reconciler = SQLReconciler(db)
    result = reconciler.reconcile_tables(
        source_table=args.source,
        target_table=args.target,
        primary_key=args.pk,
        metric_columns=args.metrics,
    )

    print(f"⏱️  Latency: {result.execution_time_ms:.1f}ms")
    print(f"🔍 Findings: {len(result.findings)}")
    for f in result.findings:
        sev_label = f"[{f.severity}]" if isinstance(f.severity, str) else f"[{f.severity.value}]"
        print(f"   • {sev_label} {f.rule_name}: {f.message}")

    return 0 if result.passed else 1


def handle_quarantine(args: argparse.Namespace) -> int:
    print(f"\n🛑 Inspecting Quarantine Store ({args.status})...")
    q_store = QuarantineStore(args.db)
    records = q_store.list_quarantined(status=args.status, limit=args.limit)
    print(f"Found {len(records)} quarantined records (Limit: {args.limit}):\n")

    for r in records:
        print(f"• ID: {r['quarantine_id']} | Table: {r['source_table']} | Record: {r['record_id']} | Severity: {r['severity']}")
        print(f"  Rules: {r['violated_rules']}")
        print(f"  Reason: {r['reason']}")
        print(f"  Raw: {json.dumps(r.get('raw_record', {}))[:120]}...\n")

    return 0


def handle_stamp_hashes(args: argparse.Namespace) -> int:
    print(f"\n🔐 Stamping cryptographic {args.algo.upper()} hashes on '{args.table}'...")
    db = DatabaseEngine(args.db)
    hasher = RecordHasher(args.algo)

    # Ensure hash column exists
    existing_cols = {c["name"] for c in db.get_table_columns(args.table)}
    if args.hash_col not in existing_cols:
        db.execute_non_query(f'ALTER TABLE "{args.table}" ADD COLUMN "{args.hash_col}" TEXT;')

    records = db.execute_query(f'SELECT * FROM "{args.table}";')
    count = 0
    with db.connect() as conn:
        for r in records:
            clean = {k: v for k, v in r.items() if k != args.hash_col}
            h = hasher.hash_record(clean)
            conn.execute(
                f'UPDATE "{args.table}" SET "{args.hash_col}" = ? WHERE id = ?;',
                [h, r["id"]],
            )
            count += 1

    print(f"✅ Successfully stamped {count} records with cryptographic hashes.\n")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "validate":
        return handle_validate(args)
    elif args.command == "reconcile":
        return handle_reconcile(args)
    elif args.command == "quarantine":
        return handle_quarantine(args)
    elif args.command == "stamp-hashes":
        return handle_stamp_hashes(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
