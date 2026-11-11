"""
Relational dataset reconciler.
Compares staging/source records against production/target records using SQL set operations
to detect missing records, unexpected phantoms, and column-level mutations.
"""

import time
from typing import Any, Dict, List, Optional, Sequence
from integrity_framework.models import CheckResult, CheckType, Finding, Severity
from integrity_framework.sql.engine import DatabaseEngine


class SQLReconciler:
    """
    Performs high-speed SQL reconciliation between two tables.
    """

    def __init__(self, db: DatabaseEngine):
        self.db = db

    def reconcile_tables(
        self,
        source_table: str,
        target_table: str,
        primary_key: str = "id",
        compare_columns: Optional[Sequence[str]] = None,
        metric_columns: Optional[Sequence[str]] = None,
    ) -> CheckResult:
        """
        Reconcile source and target tables.
        """
        start = time.perf_counter()
        findings: List[Finding] = []

        # If compare_columns not specified, intersect schema columns
        source_cols = {c["name"] for c in self.db.get_table_columns(source_table)}
        target_cols = {c["name"] for c in self.db.get_table_columns(target_table)}
        common_cols = sorted(list(source_cols.intersection(target_cols)))

        if compare_columns:
            active_cols = [c for c in compare_columns if c in common_cols]
        else:
            # Exclude metadata like updated_at or record_hash if desired
            active_cols = [
                c for c in common_cols if c.lower() not in ("updated_at", "record_hash")
            ]

        # 1. Total row count comparison
        src_count = self.db.get_row_count(source_table)
        tgt_count = self.db.get_row_count(target_table)

        if src_count != tgt_count:
            findings.append(
                Finding(
                    rule_name="RECONCILIATION_ROW_COUNT_MISMATCH",
                    check_type=CheckType.SQL_RECONCILIATION,
                    severity=Severity.ERROR,
                    table_name=target_table,
                    expected_value=src_count,
                    actual_value=tgt_count,
                    message=(
                        f"Row count disparity between source '{source_table}' ({src_count} rows) "
                        f"and target '{target_table}' ({tgt_count} rows). Delta: {tgt_count - src_count}."
                    ),
                )
            )

        # 2. Identify Missing Records in Target (Source EXCEPT Target on primary_key)
        missing_query = f"""
            SELECT s."{primary_key}" as missing_id
            FROM "{source_table}" s
            LEFT JOIN "{target_table}" t ON s."{primary_key}" = t."{primary_key}"
            WHERE t."{primary_key}" IS NULL;
        """
        missing_rows = self.db.execute_query(missing_query)
        for r in missing_rows:
            missing_id = r["missing_id"]
            findings.append(
                Finding(
                    rule_name="RECONCILIATION_MISSING_RECORD",
                    check_type=CheckType.SQL_RECONCILIATION,
                    severity=Severity.CRITICAL,
                    table_name=target_table,
                    record_id=missing_id,
                    expected_value="Record present in target table",
                    actual_value="Record absent in target table",
                    message=f"Source record '{missing_id}' from '{source_table}' was not found in target '{target_table}'.",
                )
            )

        # 3. Identify Unexpected / Phantom Records in Target
        phantom_query = f"""
            SELECT t."{primary_key}" as phantom_id
            FROM "{target_table}" t
            LEFT JOIN "{source_table}" s ON t."{primary_key}" = s."{primary_key}"
            WHERE s."{primary_key}" IS NULL;
        """
        phantom_rows = self.db.execute_query(phantom_query)
        for r in phantom_rows:
            phantom_id = r["phantom_id"]
            findings.append(
                Finding(
                    rule_name="RECONCILIATION_UNEXPECTED_RECORD",
                    check_type=CheckType.SQL_RECONCILIATION,
                    severity=Severity.ERROR,
                    table_name=target_table,
                    record_id=phantom_id,
                    expected_value="No unverified record",
                    actual_value="Phantom record exists in target",
                    message=f"Target table '{target_table}' contains unexpected record '{phantom_id}' absent from source '{source_table}'.",
                )
            )

        # 4. Column-level attribute divergence on shared keys
        for col in active_cols:
            if col == primary_key:
                continue
            divergence_query = f"""
                SELECT 
                    s."{primary_key}" as rec_id,
                    s."{col}" as source_val,
                    t."{col}" as target_val
                FROM "{source_table}" s
                JOIN "{target_table}" t ON s."{primary_key}" = t."{primary_key}"
                WHERE (s."{col}" != t."{col}")
                   OR (s."{col}" IS NULL AND t."{col}" IS NOT NULL)
                   OR (s."{col}" IS NOT NULL AND t."{col}" IS NULL);
            """
            divergent_rows = self.db.execute_query(divergence_query)
            for r in divergent_rows:
                findings.append(
                    Finding(
                        rule_name="RECONCILIATION_ATTRIBUTE_DIVERGENCE",
                        check_type=CheckType.SQL_RECONCILIATION,
                        severity=Severity.ERROR,
                        table_name=target_table,
                        record_id=r["rec_id"],
                        column_name=col,
                        expected_value=r["source_val"],
                        actual_value=r["target_val"],
                        message=(
                            f"Attribute divergence on record '{r['rec_id']}' column '{col}'. "
                            f"Source has '{r['source_val']}' while target has '{r['target_val']}'."
                        ),
                    )
                )

        # 5. Metric aggregation reconciliation (e.g. sums)
        if metric_columns:
            for metric in metric_columns:
                if metric in common_cols:
                    sum_query = f"""
                        SELECT 
                            (SELECT COALESCE(SUM("{metric}"), 0) FROM "{source_table}") as src_sum,
                            (SELECT COALESCE(SUM("{metric}"), 0) FROM "{target_table}") as tgt_sum;
                    """
                    sum_res = self.db.execute_query(sum_query)
                    if sum_res:
                        src_sum = float(sum_res[0]["src_sum"])
                        tgt_sum = float(sum_res[0]["tgt_sum"])
                        if abs(src_sum - tgt_sum) > 1e-4:
                            findings.append(
                                Finding(
                                    rule_name="RECONCILIATION_METRIC_DELTA",
                                    check_type=CheckType.SQL_RECONCILIATION,
                                    severity=Severity.CRITICAL,
                                    table_name=target_table,
                                    column_name=metric,
                                    expected_value=src_sum,
                                    actual_value=tgt_sum,
                                    message=(
                                        f"Aggregate balance disparity on column '{metric}'. "
                                        f"Source sum={src_sum:.2f}, Target sum={tgt_sum:.2f}, Delta={tgt_sum - src_sum:.2f}"
                                    ),
                                )
                            )

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return CheckResult(
            check_name=f"Reconciliation: {source_table} -> {target_table}",
            check_type=CheckType.SQL_RECONCILIATION,
            records_inspected=max(src_count, tgt_count),
            findings=findings,
            execution_time_ms=elapsed_ms,
            metadata={
                "source_count": src_count,
                "target_count": tgt_count,
                "columns_compared": active_cols,
            },
        )
