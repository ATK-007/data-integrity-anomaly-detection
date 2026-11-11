"""
SQL-based invariant checks, assertions, and constraint verifications.
Executes relational checks at high speed directly in the database engine.
"""

from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional, Union
from integrity_framework.models import CheckResult, CheckType, Finding, Severity
from integrity_framework.sql.engine import DatabaseEngine


@dataclass
class SQLAssertion:
    """
    Relational row-level assertion.
    condition defines what MUST hold true. Records where condition evaluates to FALSE or NULL are flagged.
    """
    name: str
    table: str
    condition: str
    severity: Severity = Severity.ERROR
    description: str = ""
    id_column: str = "id"


@dataclass
class AggregateAssertion:
    """
    Dataset-level aggregate assertion (e.g., debits == credits, non-negative balances).
    """
    name: str
    table: str
    query: str
    expected_value: Any
    severity: Severity = Severity.CRITICAL
    description: str = ""
    operator: str = "=="  # '==', '!=', '>', '>=', '<', '<='


class SQLCheckSuite:
    """
    Executes a comprehensive collection of SQL-based integrity checks.
    """

    def __init__(self, db: DatabaseEngine):
        self.db = db
        self.row_assertions: List[SQLAssertion] = []
        self.aggregate_assertions: List[AggregateAssertion] = []

    def add_row_assertion(self, assertion: SQLAssertion) -> None:
        self.row_assertions.append(assertion)

    def add_aggregate_assertion(self, assertion: AggregateAssertion) -> None:
        self.aggregate_assertions.append(assertion)

    def check_uniqueness(
        self,
        table: str,
        columns: List[str],
        severity: Severity = Severity.ERROR,
    ) -> List[Finding]:
        """
        Detect duplicate records on composite unique columns.
        """
        cols_str = ", ".join(f'"{c}"' for c in columns)
        query = f"""
            SELECT {cols_str}, COUNT(*) as dup_count, GROUP_CONCAT(id) as record_ids
            FROM "{table}"
            GROUP BY {cols_str}
            HAVING COUNT(*) > 1;
        """
        findings: List[Finding] = []
        try:
            rows = self.db.execute_query(query)
            for r in rows:
                dup_count = r["dup_count"]
                ids = str(r.get("record_ids", "")).split(",")
                findings.append(
                    Finding(
                        rule_name="SQL_UNIQUE_VIOLATION",
                        check_type=CheckType.SQL_INVARIANT,
                        severity=severity,
                        table_name=table,
                        record_id=ids[0] if ids else None,
                        column_name=",".join(columns),
                        expected_value=1,
                        actual_value=dup_count,
                        message=(
                            f"Duplicate constraint violation in table '{table}' on columns ({', '.join(columns)}). "
                            f"Found {dup_count} duplicate instances (Record IDs: {', '.join(ids[:5])})."
                        ),
                        details={"columns": columns, "duplicate_ids": ids},
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    rule_name="SQL_CHECK_EXECUTION_ERROR",
                    check_type=CheckType.SQL_INVARIANT,
                    severity=Severity.ERROR,
                    table_name=table,
                    message=f"Failed to execute uniqueness check on '{table}': {str(e)}",
                )
            )
        return findings

    def check_null_invariants(
        self,
        table: str,
        column: str,
        id_column: str = "id",
        severity: Severity = Severity.ERROR,
    ) -> List[Finding]:
        """
        Identify records containing forbidden NULL or empty string values.
        """
        query = f"""
            SELECT "{id_column}" as rec_id
            FROM "{table}"
            WHERE "{column}" IS NULL OR TRIM(CAST("{column}" AS TEXT)) = '';
        """
        findings: List[Finding] = []
        try:
            rows = self.db.execute_query(query)
            for r in rows:
                rec_id = r["rec_id"]
                findings.append(
                    Finding(
                        rule_name="SQL_NOT_NULL_INVARIANT",
                        check_type=CheckType.SQL_INVARIANT,
                        severity=severity,
                        table_name=table,
                        record_id=rec_id,
                        column_name=column,
                        expected_value="NOT NULL / NON-EMPTY",
                        actual_value="NULL or empty string",
                        message=(
                            f"Null constraint breach in table '{table}' column '{column}' "
                            f"for record '{rec_id}'"
                        ),
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    rule_name="SQL_CHECK_EXECUTION_ERROR",
                    check_type=CheckType.SQL_INVARIANT,
                    severity=Severity.ERROR,
                    table_name=table,
                    message=f"Failed to check null invariant for '{table}.{column}': {str(e)}",
                )
            )
        return findings

    def run_row_assertions(self) -> List[Finding]:
        """
        Execute all registered row assertions.
        Flag records where NOT (condition).
        """
        findings: List[Finding] = []
        for assertion in self.row_assertions:
            query = f"""
                SELECT "{assertion.id_column}" as rec_id, *
                FROM "{assertion.table}"
                WHERE NOT ({assertion.condition}) OR ({assertion.condition}) IS NULL;
            """
            try:
                rows = self.db.execute_query(query)
                for r in rows:
                    rec_id = r.get("rec_id")
                    findings.append(
                        Finding(
                            rule_name=assertion.name,
                            check_type=CheckType.SQL_INVARIANT,
                            severity=assertion.severity,
                            table_name=assertion.table,
                            record_id=rec_id,
                            expected_value=f"Satisfy ({assertion.condition})",
                            actual_value="Condition failed or evaluated to NULL",
                            message=(
                                f"SQL row assertion '{assertion.name}' failed on table '{assertion.table}' "
                                f"for record '{rec_id}'. {assertion.description}"
                            ),
                            details={"row_data": r},
                        )
                    )
            except Exception as e:
                findings.append(
                    Finding(
                        rule_name=assertion.name,
                        check_type=CheckType.SQL_INVARIANT,
                        severity=Severity.ERROR,
                        table_name=assertion.table,
                        message=f"Error evaluating assertion '{assertion.name}': {str(e)}",
                    )
                )
        return findings

    def run_aggregate_assertions(self) -> List[Finding]:
        """
        Evaluate dataset-level aggregate equations and invariants.
        """
        findings: List[Finding] = []
        for agg in self.aggregate_assertions:
            try:
                rows = self.db.execute_query(agg.query)
                if not rows:
                    continue
                actual = list(rows[0].values())[0]

                passed = False
                op = agg.operator
                if op == "==":
                    passed = (actual == agg.expected_value)
                elif op == "!=":
                    passed = (actual != agg.expected_value)
                elif op == ">":
                    passed = (actual > agg.expected_value)
                elif op == ">=":
                    passed = (actual >= agg.expected_value)
                elif op == "<":
                    passed = (actual < agg.expected_value)
                elif op == "<=":
                    passed = (actual <= agg.expected_value)

                if not passed:
                    findings.append(
                        Finding(
                            rule_name=agg.name,
                            check_type=CheckType.SQL_INVARIANT,
                            severity=agg.severity,
                            table_name=agg.table,
                            expected_value=f"{agg.operator} {agg.expected_value}",
                            actual_value=actual,
                            message=(
                                f"Aggregate balance check '{agg.name}' failed on table '{agg.table}'. "
                                f"Expected {agg.operator} {agg.expected_value}, observed {actual}. {agg.description}"
                            ),
                            details={"query": agg.query},
                        )
                    )
            except Exception as e:
                findings.append(
                    Finding(
                        rule_name=agg.name,
                        check_type=CheckType.SQL_INVARIANT,
                        severity=Severity.ERROR,
                        table_name=agg.table,
                        message=f"Error running aggregate query '{agg.name}': {str(e)}",
                    )
                )
        return findings

    def run_all(self, total_records: int = 0) -> CheckResult:
        """
        Run low-level pragma, row assertions, and aggregate assertions.
        """
        start = time.perf_counter()
        findings: List[Finding] = []

        # 1. Low-level PRAGMA integrity
        findings.extend(self.db.run_pragma_integrity_check())

        # 2. Row assertions
        findings.extend(self.run_row_assertions())

        # 3. Aggregate assertions
        findings.extend(self.run_aggregate_assertions())

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return CheckResult(
            check_name="SQL Database Invariants Suite",
            check_type=CheckType.SQL_INVARIANT,
            records_inspected=total_records,
            findings=findings,
            execution_time_ms=elapsed_ms,
        )
