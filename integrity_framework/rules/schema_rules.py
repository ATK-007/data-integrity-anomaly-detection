"""Schema and structure validation rules."""

from typing import Any, Dict, List, Optional, Set
from integrity_framework.models import CheckType, Finding, Severity
from integrity_framework.rules.base import BaseRule


class NotNullRule(BaseRule):
    """Flags records where a required column is None, NULL, or empty whitespace."""

    def __init__(
        self,
        name: str,
        table_name: str,
        column_name: str,
        allow_empty_string: bool = False,
        severity: Severity = Severity.ERROR,
        description: str = "",
    ):
        super().__init__(
            name=name,
            table_name=table_name,
            column_name=column_name,
            severity=severity,
            check_type=CheckType.RULE_VALIDATION,
            description=description or f"Column '{column_name}' must not be null or empty",
        )
        self.allow_empty_string = allow_empty_string

    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        val = record.get(self.column_name)
        is_missing = False
        if val is None:
            is_missing = True
        elif not self.allow_empty_string and isinstance(val, str) and not val.strip():
            is_missing = True

        if is_missing:
            return Finding(
                rule_name=self.name,
                check_type=self.check_type,
                severity=self.severity,
                table_name=self.table_name,
                record_id=record_id,
                column_name=self.column_name,
                expected_value="NOT NULL / NON-EMPTY",
                actual_value=val,
                message=(
                    f"Null constraint breach in table '{self.table_name}' column '{self.column_name}' "
                    f"for record '{record_id}'."
                ),
                details={"description": self.description},
            )
        return None


class NullRatioThresholdRule(BaseRule):
    """Flags an error if the proportion of nulls in a column exceeds a maximum threshold."""

    def __init__(
        self,
        name: str,
        table_name: str,
        column_name: str,
        max_ratio: float = 0.05,
        severity: Severity = Severity.WARNING,
        description: str = "",
    ):
        super().__init__(
            name=name,
            table_name=table_name,
            column_name=column_name,
            severity=severity,
            check_type=CheckType.RULE_VALIDATION,
            description=description or f"Null ratio in '{column_name}' must not exceed {max_ratio:.1%}",
        )
        self.max_ratio = max_ratio

    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        return None

    def evaluate_dataset(
        self, records: List[Dict[str, Any]], id_column: str = "id"
    ) -> List[Finding]:
        if not records:
            return []
        total = len(records)
        null_count = sum(
            1 for r in records if r.get(self.column_name) is None or str(r.get(self.column_name)).strip() == ""
        )
        ratio = null_count / float(total)

        if ratio > self.max_ratio:
            return [
                Finding(
                    rule_name=self.name,
                    check_type=self.check_type,
                    severity=self.severity,
                    table_name=self.table_name,
                    column_name=self.column_name,
                    expected_value=f"<= {self.max_ratio:.1%}",
                    actual_value=f"{ratio:.1%} ({null_count}/{total} rows)",
                    message=(
                        f"Excessive null ratio in table '{self.table_name}' column '{self.column_name}'. "
                        f"Observed {ratio:.1%}, allowed threshold is {self.max_ratio:.1%}."
                    ),
                    details={"null_count": null_count, "total_rows": total, "ratio": ratio},
                )
            ]
        return []


class TypeRule(BaseRule):
    """Validates that a field matches its expected primitive data type."""

    TYPE_MAP = {
        "int": int,
        "integer": int,
        "float": (float, int),
        "number": (float, int),
        "str": str,
        "string": str,
        "bool": bool,
        "boolean": bool,
    }

    def __init__(
        self,
        name: str,
        table_name: str,
        column_name: str,
        expected_type: str,
        severity: Severity = Severity.ERROR,
        description: str = "",
    ):
        super().__init__(
            name=name,
            table_name=table_name,
            column_name=column_name,
            severity=severity,
            check_type=CheckType.RULE_VALIDATION,
            description=description or f"Column '{column_name}' must be of type {expected_type}",
        )
        self.expected_type = expected_type.lower()
        if self.expected_type not in self.TYPE_MAP:
            raise ValueError(f"Unsupported expected type: {expected_type}")

    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        val = record.get(self.column_name)
        if val is None:
            return None  # Let NotNullRule handle nulls

        valid_types = self.TYPE_MAP[self.expected_type]
        if not isinstance(val, valid_types):
            # Attempt soft coercion if it's a numeric string
            coerced = False
            if self.expected_type in ("int", "integer"):
                try:
                    int(str(val))
                    coerced = True
                except ValueError:
                    coerced = False
            elif self.expected_type in ("float", "number"):
                try:
                    float(str(val))
                    coerced = True
                except ValueError:
                    coerced = False

            if not coerced:
                return Finding(
                    rule_name=self.name,
                    check_type=self.check_type,
                    severity=self.severity,
                    table_name=self.table_name,
                    record_id=record_id,
                    column_name=self.column_name,
                    expected_value=self.expected_type,
                    actual_value=type(val).__name__,
                    message=(
                        f"Data type discrepancy in table '{self.table_name}' column '{self.column_name}' "
                        f"for record '{record_id}'. Expected {self.expected_type}, received {type(val).__name__} ('{val}')."
                    ),
                )
        return None


class SchemaDriftRule(BaseRule):
    """Detects missing required columns or unexpected extra columns against expected schema."""

    def __init__(
        self,
        name: str,
        table_name: str,
        required_columns: Set[str],
        allowed_columns: Optional[Set[str]] = None,
        severity: Severity = Severity.ERROR,
        description: str = "",
    ):
        super().__init__(
            name=name,
            table_name=table_name,
            severity=severity,
            check_type=CheckType.SCHEMA_INTEGRITY,
            description=description or f"Schema conformity check for table '{table_name}'",
        )
        self.required_columns = set(required_columns)
        self.allowed_columns = set(allowed_columns) if allowed_columns else None

    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        return None

    def evaluate_dataset(
        self, records: List[Dict[str, Any]], id_column: str = "id"
    ) -> List[Finding]:
        if not records:
            return []
        findings = []
        observed_cols = set(records[0].keys())

        missing = self.required_columns - observed_cols
        if missing:
            findings.append(
                Finding(
                    rule_name=self.name,
                    check_type=self.check_type,
                    severity=self.severity,
                    table_name=self.table_name,
                    expected_value=f"Include required columns: {sorted(list(self.required_columns))}",
                    actual_value=f"Missing columns: {sorted(list(missing))}",
                    message=f"Schema drift: Table '{self.table_name}' is missing mandatory columns: {', '.join(sorted(missing))}.",
                )
            )

        if self.allowed_columns:
            extra = observed_cols - self.allowed_columns
            if extra:
                findings.append(
                    Finding(
                        rule_name=self.name + "_UNEXPECTED_COLUMNS",
                        check_type=self.check_type,
                        severity=Severity.WARNING,
                        table_name=self.table_name,
                        expected_value=f"Allowed columns: {sorted(list(self.allowed_columns))}",
                        actual_value=f"Unexpected extra columns: {sorted(list(extra))}",
                        message=f"Schema drift: Table '{self.table_name}' contains undeclared columns: {', '.join(sorted(extra))}.",
                    )
                )

        return findings
