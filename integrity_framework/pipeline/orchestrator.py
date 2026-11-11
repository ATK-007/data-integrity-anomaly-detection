"""
Validation pipeline orchestrator.
Automates repeatable validation workflows, coordinates cryptographic, SQL,
and rule-based checks, manages quarantine isolation, and produces audit findings.
"""

from collections import Counter, defaultdict
from datetime import datetime
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import uuid

from integrity_framework.crypto.hasher import RecordHasher
from integrity_framework.crypto.merkle import MerkleTree
from integrity_framework.models import (
    CheckResult,
    CheckType,
    Finding,
    PipelineSummary,
    Severity,
)
from integrity_framework.pipeline.quarantine import QuarantineStore
from integrity_framework.pipeline.reporter import ReportGenerator
from integrity_framework.rules.engine import RuleEngine
from integrity_framework.sql.checks import SQLCheckSuite
from integrity_framework.sql.engine import DatabaseEngine
from integrity_framework.sql.reconciler import SQLReconciler


class ValidationPipeline:
    """
    Automated end-to-end data integrity validation pipeline.
    """

    def __init__(
        self,
        db_engine: Optional[DatabaseEngine] = None,
        quarantine_store: Optional[QuarantineStore] = None,
        rule_engine: Optional[RuleEngine] = None,
        hasher: Optional[RecordHasher] = None,
        quarantine_on_error: bool = True,
    ):
        self.db = db_engine or DatabaseEngine(":memory:")
        self.quarantine = quarantine_store or QuarantineStore(":memory:")
        self.rules = rule_engine or RuleEngine()
        self.hasher = hasher or RecordHasher("sha256")
        self.quarantine_on_error = quarantine_on_error
        self.sql_checks = SQLCheckSuite(self.db)
        self.sql_reconciler = SQLReconciler(self.db)

    def run(
        self,
        target_name: str = "Production Database",
        tables: Optional[Sequence[str]] = None,
        verify_crypto_hash: bool = True,
        hash_column: str = "record_hash",
        id_column: str = "id",
    ) -> PipelineSummary:
        """
        Execute full automated validation pipeline across specified or all discovered tables.
        """
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        start_time_iso = datetime.utcnow().isoformat() + "Z"
        start_clock = time.perf_counter()

        active_tables = tables if tables is not None else self.db.get_table_names()
        # Filter out system and quarantine tables
        active_tables = [
            t for t in active_tables
            if not t.startswith("_quarantine") and not t.startswith("sqlite_")
        ]

        check_results: List[CheckResult] = []
        table_summaries: Dict[str, Dict[str, Any]] = {}
        total_records = 0
        quarantined_record_ids: set = set()
        flagged_record_ids: set = set()
        severity_counter: Counter = Counter()

        # Step 1: Low-level SQL Pragma & Structural Checks
        sql_invariants_result = self.sql_checks.run_all(total_records=0)
        check_results.append(sql_invariants_result)
        for f in sql_invariants_result.findings:
            severity_counter[f.severity if isinstance(f.severity, str) else f.severity.value] += 1
            if f.record_id:
                flagged_record_ids.add((f.table_name, str(f.record_id)))

        # Step 2: Per-Table Validations
        for tbl in active_tables:
            tbl_count = self.db.get_row_count(tbl)
            total_records += tbl_count
            records = self.db.execute_query(f'SELECT * FROM "{tbl}";')

            # 2a: Cryptographic Hash Verification
            if verify_crypto_hash and records:
                cols = {c["name"] for c in self.db.get_table_columns(tbl)}
                if hash_column in cols:
                    hash_result = self.hasher.verify_dataset(
                        records=records,
                        hash_column=hash_column,
                        id_column=id_column,
                        table_name=tbl,
                    )
                    check_results.append(hash_result)
                    for f in hash_result.findings:
                        severity_counter[f.severity if isinstance(f.severity, str) else f.severity.value] += 1
                        if f.record_id:
                            flagged_record_ids.add((tbl, str(f.record_id)))

            # 2b: Declarative Rule-based Validation
            rule_result = self.rules.evaluate_table_records(
                table_name=tbl,
                records=records,
                id_column=id_column,
            )
            check_results.append(rule_result)
            for f in rule_result.findings:
                severity_counter[f.severity if isinstance(f.severity, str) else f.severity.value] += 1
                if f.record_id:
                    flagged_record_ids.add((tbl, str(f.record_id)))

            # Track table metrics
            tbl_flagged = len({rid for t, rid in flagged_record_ids if t == tbl})
            table_summaries[tbl] = {
                "total_rows": tbl_count,
                "flagged_rows": tbl_flagged,
                "clean_rows": max(0, tbl_count - tbl_flagged),
            }

        # Step 3: Quarantine Isolation
        # Group findings by (table, record_id)
        if self.quarantine_on_error:
            record_findings: Dict[Tuple[str, str], List[Finding]] = defaultdict(list)
            for cr in check_results:
                for f in cr.findings:
                    if f.record_id and f.severity in (
                        Severity.CRITICAL,
                        Severity.ERROR,
                        "CRITICAL",
                        "ERROR",
                    ):
                        record_findings[(f.table_name, str(f.record_id))].append(f)

            # Quarantine flagged records
            for (tbl, rec_id), f_list in record_findings.items():
                # Fetch raw record from DB
                row_matches = self.db.execute_query(
                    f'SELECT * FROM "{tbl}" WHERE "{id_column}" = ? LIMIT 1;',
                    [rec_id],
                )
                raw_data = row_matches[0] if row_matches else {}
                self.quarantine.quarantine_record(
                    source_table=tbl,
                    record_id=rec_id,
                    raw_record=raw_data,
                    findings=f_list,
                )
                quarantined_record_ids.add((tbl, rec_id))

        duration = time.perf_counter() - start_clock
        end_time_iso = datetime.utcnow().isoformat() + "Z"

        # Step 4: Calculate Data Integrity Health Score
        # Weighting: Critical= -10, Error= -5, Warning= -1
        total_flagged_count = len(flagged_record_ids)
        passed_records = max(0, total_records - total_flagged_count)

        if total_records == 0:
            integrity_score = 100.0
        else:
            base_score = (passed_records / float(total_records)) * 100.0
            crit_penalty = severity_counter.get("CRITICAL", 0) * 1.5
            err_penalty = severity_counter.get("ERROR", 0) * 0.75
            warn_penalty = severity_counter.get("WARNING", 0) * 0.2
            integrity_score = max(0.0, min(100.0, base_score - (crit_penalty + err_penalty + warn_penalty)))

        return PipelineSummary(
            run_id=run_id,
            target_name=target_name,
            start_time=start_time_iso,
            end_time=end_time_iso,
            duration_seconds=duration,
            total_records=total_records,
            passed_records=passed_records,
            flagged_records=total_flagged_count,
            quarantined_records=len(quarantined_record_ids),
            integrity_score=integrity_score,
            findings_by_severity=dict(severity_counter),
            table_summaries=table_summaries,
            check_results=check_results,
        )
