"""
Declarative rule execution engine.
Orchestrates schema, value, pattern, cross-field, and statistical rules across tables.
"""

from collections import defaultdict
import json
import time
from typing import Any, Dict, List, Optional, Sequence
from integrity_framework.models import CheckResult, CheckType, Finding, Severity
from integrity_framework.rules.base import BaseRule
from integrity_framework.rules.schema_rules import (
    NotNullRule,
    NullRatioThresholdRule,
    TypeRule,
    SchemaDriftRule,
)
from integrity_framework.rules.value_rules import (
    RangeRule,
    RegexRule,
    AllowedValuesRule,
    CrossFieldRule,
)
from integrity_framework.rules.statistical import (
    ZScoreAnomalyDetector,
    IQRAnomalyDetector,
)


class RuleEngine:
    """
    Validation engine that executes rules and aggregates findings.
    """

    def __init__(self):
        self.rules_by_table: Dict[str, List[BaseRule]] = defaultdict(list)
        self.global_rules: List[BaseRule] = []

    def register_rule(self, rule: BaseRule) -> None:
        """Register a single rule."""
        if rule.table_name == "*" or not rule.table_name:
            self.global_rules.append(rule)
        else:
            self.rules_by_table[rule.table_name].append(rule)

    def load_rules_from_dict(self, config: Dict[str, Any]) -> None:
        """
        Load declarative rules from dictionary/JSON configuration.
        """
        tables = config.get("tables", {})
        for tbl_name, rules_list in tables.items():
            for r_cfg in rules_list:
                rule = self._instantiate_rule(tbl_name, r_cfg)
                if rule:
                    self.register_rule(rule)

    def load_rules_from_file(self, file_path: str) -> None:
        """Load declarative rules from a JSON config file."""
        with open(file_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            self.load_rules_from_dict(cfg)

    def _instantiate_rule(
        self, table_name: str, cfg: Dict[str, Any]
    ) -> Optional[BaseRule]:
        rule_type = cfg.get("type", "").lower()
        name = cfg.get("name", f"{table_name}_{rule_type}")
        column = cfg.get("column")
        severity_str = cfg.get("severity", "ERROR").upper()
        severity = getattr(Severity, severity_str, Severity.ERROR)
        desc = cfg.get("description", "")

        if rule_type == "not_null":
            return NotNullRule(
                name=name,
                table_name=table_name,
                column_name=column,
                allow_empty_string=cfg.get("allow_empty_string", False),
                severity=severity,
                description=desc,
            )
        elif rule_type == "null_ratio":
            return NullRatioThresholdRule(
                name=name,
                table_name=table_name,
                column_name=column,
                max_ratio=float(cfg.get("max_ratio", 0.05)),
                severity=severity,
                description=desc,
            )
        elif rule_type == "type":
            return TypeRule(
                name=name,
                table_name=table_name,
                column_name=column,
                expected_type=cfg.get("expected_type", "str"),
                severity=severity,
                description=desc,
            )
        elif rule_type == "range":
            return RangeRule(
                name=name,
                table_name=table_name,
                column_name=column,
                min_value=cfg.get("min_value"),
                max_value=cfg.get("max_value"),
                inclusive=cfg.get("inclusive", True),
                severity=severity,
                description=desc,
            )
        elif rule_type == "regex":
            return RegexRule(
                name=name,
                table_name=table_name,
                column_name=column,
                pattern=cfg.get("pattern", ".*"),
                severity=severity,
                description=desc,
            )
        elif rule_type == "allowed_values":
            return AllowedValuesRule(
                name=name,
                table_name=table_name,
                column_name=column,
                allowed_values=cfg.get("values", []),
                case_sensitive=cfg.get("case_sensitive", False),
                severity=severity,
                description=desc,
            )
        elif rule_type == "z_score":
            return ZScoreAnomalyDetector(
                name=name,
                table_name=table_name,
                column_name=column,
                threshold=float(cfg.get("threshold", 3.0)),
                severity=severity,
                description=desc,
            )
        elif rule_type == "iqr":
            return IQRAnomalyDetector(
                name=name,
                table_name=table_name,
                column_name=column,
                multiplier=float(cfg.get("multiplier", 1.5)),
                severity=severity,
                description=desc,
            )
        elif rule_type == "schema_drift":
            return SchemaDriftRule(
                name=name,
                table_name=table_name,
                required_columns=set(cfg.get("required_columns", [])),
                allowed_columns=set(cfg.get("allowed_columns", []))
                if "allowed_columns" in cfg
                else None,
                severity=severity,
                description=desc,
            )
        return None

    def evaluate_table_records(
        self,
        table_name: str,
        records: List[Dict[str, Any]],
        id_column: str = "id",
    ) -> CheckResult:
        """
        Evaluate all applicable rules for a given table.
        """
        start = time.perf_counter()
        rules = self.rules_by_table.get(table_name, []) + self.global_rules
        findings: List[Finding] = []

        for rule in rules:
            rule_findings = rule.evaluate_dataset(records, id_column=id_column)
            findings.extend(rule_findings)

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return CheckResult(
            check_name=f"Rule Engine: {table_name}",
            check_type=CheckType.RULE_VALIDATION,
            records_inspected=len(records),
            findings=findings,
            execution_time_ms=elapsed_ms,
            metadata={"rules_evaluated": len(rules), "table": table_name},
        )
