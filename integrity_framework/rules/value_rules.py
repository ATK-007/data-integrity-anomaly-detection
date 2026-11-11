"""
Value-level validation rules: numeric bounds, regex formats, enum constraints, and cross-field predicates.
"""

from decimal import Decimal
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Union
from integrity_framework.models import CheckType, Finding, Severity
from integrity_framework.rules.base import BaseRule


class RangeRule(BaseRule):
    """Verifies that a numeric or comparable value lies strictly within [min_val, max_val]."""

    def __init__(
        self,
        name: str,
        table_name: str,
        column_name: str,
        min_value: Optional[float] = None,
        max_value: Optional[float] = None,
        inclusive: bool = True,
        severity: Severity = Severity.ERROR,
        description: str = "",
    ):
        super().__init__(
            name=name,
            table_name=table_name,
            column_name=column_name,
            severity=severity,
            check_type=CheckType.RULE_VALIDATION,
            description=description or f"Value of '{column_name}' must be within bounds [{min_value}, {max_value}]",
        )
        self.min_value = min_value
        self.max_value = max_value
        self.inclusive = inclusive

    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        val = record.get(self.column_name)
        if val is None:
            return None  # Let NotNullRule handle nulls

        try:
            num = float(val)
        except (ValueError, TypeError):
            return Finding(
                rule_name=self.name,
                check_type=self.check_type,
                severity=self.severity,
                table_name=self.table_name,
                record_id=record_id,
                column_name=self.column_name,
                expected_value=f"Numeric between {self.min_value} and {self.max_value}",
                actual_value=val,
                message=f"Non-numeric value '{val}' encountered in column '{self.column_name}'.",
            )

        violation = False
        if self.min_value is not None:
            if self.inclusive and num < self.min_value:
                violation = True
            elif not self.inclusive and num <= self.min_value:
                violation = True

        if self.max_value is not None:
            if self.inclusive and num > self.max_value:
                violation = True
            elif not self.inclusive and num >= self.max_value:
                violation = True

        if violation:
            bounds_str = f"[{self.min_value}, {self.max_value}]" if self.inclusive else f"({self.min_value}, {self.max_value})"
            return Finding(
                rule_name=self.name,
                check_type=self.check_type,
                severity=self.severity,
                table_name=self.table_name,
                record_id=record_id,
                column_name=self.column_name,
                expected_value=bounds_str,
                actual_value=num,
                message=(
                    f"Out-of-range value '{num}' in table '{self.table_name}' column '{self.column_name}' "
                    f"for record '{record_id}'. Allowed range: {bounds_str}."
                ),
            )
        return None


class RegexRule(BaseRule):
    """Enforces string conformance against regular expressions."""

    PRESETS = {
        "UUID": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        "EMAIL": r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
        "ISO_DATE": r"^\d{4}-\d{2}-\d{2}$",
        "ISO_TIMESTAMP": r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$",
        "CURRENCY_CODE": r"^[A-Z]{3}$",
        "ALPHANUMERIC": r"^[a-zA-Z0-9_-]+$",
    }

    def __init__(
        self,
        name: str,
        table_name: str,
        column_name: str,
        pattern: str,
        severity: Severity = Severity.ERROR,
        description: str = "",
    ):
        resolved_pattern = self.PRESETS.get(pattern.upper(), pattern)
        super().__init__(
            name=name,
            table_name=table_name,
            column_name=column_name,
            severity=severity,
            check_type=CheckType.RULE_VALIDATION,
            description=description or f"Column '{column_name}' must match pattern: {pattern}",
        )
        self.pattern_str = pattern
        self.regex = re.compile(resolved_pattern)

    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        val = record.get(self.column_name)
        if val is None:
            return None

        val_str = str(val).strip()
        if not self.regex.match(val_str):
            return Finding(
                rule_name=self.name,
                check_type=self.check_type,
                severity=self.severity,
                table_name=self.table_name,
                record_id=record_id,
                column_name=self.column_name,
                expected_value=f"Regex: {self.pattern_str}",
                actual_value=val_str,
                message=(
                    f"Pattern mismatch in table '{self.table_name}' column '{self.column_name}' "
                    f"for record '{record_id}'. Value '{val_str}' does not conform to pattern '{self.pattern_str}'."
                ),
            )
        return None


class AllowedValuesRule(BaseRule):
    """Ensures a field is restricted to an approved discrete set of allowed values (Enum)."""

    def __init__(
        self,
        name: str,
        table_name: str,
        column_name: str,
        allowed_values: Sequence[Any],
        case_sensitive: bool = False,
        severity: Severity = Severity.ERROR,
        description: str = "",
    ):
        super().__init__(
            name=name,
            table_name=table_name,
            column_name=column_name,
            severity=severity,
            check_type=CheckType.RULE_VALIDATION,
            description=description or f"Column '{column_name}' must be one of {allowed_values}",
        )
        self.case_sensitive = case_sensitive
        if case_sensitive:
            self.allowed_set = set(allowed_values)
        else:
            self.allowed_set = {str(v).lower() for v in allowed_values}

    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        val = record.get(self.column_name)
        if val is None:
            return None

        check_val = val if self.case_sensitive else str(val).lower()
        if check_val not in self.allowed_set:
            return Finding(
                rule_name=self.name,
                check_type=self.check_type,
                severity=self.severity,
                table_name=self.table_name,
                record_id=record_id,
                column_name=self.column_name,
                expected_value=sorted([str(x) for x in self.allowed_set]),
                actual_value=val,
                message=(
                    f"Invalid enum value '{val}' in table '{self.table_name}' column '{self.column_name}' "
                    f"for record '{record_id}'. Allowed values: {sorted([str(x) for x in self.allowed_set])}."
                ),
            )
        return None


class CrossFieldRule(BaseRule):
    """
    Evaluates cross-column business logic and assertions across multiple fields in the same record.
    Predicate receives the entire record dictionary and returns bool (True=valid, False=violation).
    """

    def __init__(
        self,
        name: str,
        table_name: str,
        predicate: Callable[[Dict[str, Any]], bool],
        involved_columns: Sequence[str],
        expected_description: str,
        severity: Severity = Severity.ERROR,
        description: str = "",
    ):
        super().__init__(
            name=name,
            table_name=table_name,
            column_name=",".join(involved_columns),
            severity=severity,
            check_type=CheckType.RULE_VALIDATION,
            description=description or expected_description,
        )
        self.predicate = predicate
        self.involved_columns = list(involved_columns)
        self.expected_description = expected_description

    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        try:
            is_valid = self.predicate(record)
        except Exception as e:
            return Finding(
                rule_name=self.name,
                check_type=self.check_type,
                severity=self.severity,
                table_name=self.table_name,
                record_id=record_id,
                column_name=",".join(self.involved_columns),
                expected_value=self.expected_description,
                actual_value=f"Evaluation Error: {str(e)}",
                message=f"Cross-field check '{self.name}' threw an error for record '{record_id}': {str(e)}",
            )

        if not is_valid:
            actual_values = {col: record.get(col) for col in self.involved_columns}
            return Finding(
                rule_name=self.name,
                check_type=self.check_type,
                severity=self.severity,
                table_name=self.table_name,
                record_id=record_id,
                column_name=",".join(self.involved_columns),
                expected_value=self.expected_description,
                actual_value=actual_values,
                message=(
                    f"Cross-field rule '{self.name}' violated for record '{record_id}' on table '{self.table_name}'. "
                    f"Expected: {self.expected_description}. Observed: {actual_values}."
                ),
                details={"involved_columns": self.involved_columns, "values": actual_values},
            )
        return None
