"""Abstract base rule class."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from integrity_framework.models import CheckType, Finding, Severity


class BaseRule(ABC):
    """
    Base class for declarative data validation rules.
    """

    def __init__(
        self,
        name: str,
        table_name: str,
        column_name: Optional[str] = None,
        severity: Severity = Severity.ERROR,
        check_type: CheckType = CheckType.RULE_VALIDATION,
        description: str = "",
    ):
        self.name = name
        self.table_name = table_name
        self.column_name = column_name
        self.severity = severity
        self.check_type = check_type
        self.description = description

    @abstractmethod
    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        """
        Evaluate rule against a single record.
        Returns a Finding if validation fails, or None if passed.
        """
        pass

    def evaluate_dataset(
        self, records: List[Dict[str, Any]], id_column: str = "id"
    ) -> List[Finding]:
        """
        Evaluate rule across an entire list of records.
        Override in subclasses if the rule requires dataset-level aggregation.
        """
        findings: List[Finding] = []
        for r in records:
            rec_id = r.get(id_column)
            finding = self.evaluate_record(r, record_id=rec_id)
            if finding:
                findings.append(finding)
        return findings
