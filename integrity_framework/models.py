"""Data models and data structures for integrity checks, findings, and summaries."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import json
import uuid


class Severity(str, Enum):
    """Severity classification for data discrepancies and integrity issues."""
    CRITICAL = "CRITICAL"  # Data corruption, cryptographic mismatch, unauthorized mutation
    ERROR = "ERROR"        # Hard rule failure, foreign key break, schema invalidation
    WARNING = "WARNING"    # Statistical outlier, soft threshold breach, null ratio spike
    INFO = "INFO"          # Informational finding, cosmetic formatting drift


class CheckType(str, Enum):
    """Category of data integrity check executed."""
    CRYPTOGRAPHIC_HASH = "CRYPTOGRAPHIC_HASH"
    SQL_INVARIANT = "SQL_INVARIANT"
    SQL_RECONCILIATION = "SQL_RECONCILIATION"
    RULE_VALIDATION = "RULE_VALIDATION"
    STATISTICAL_ANOMALY = "STATISTICAL_ANOMALY"
    SCHEMA_INTEGRITY = "SCHEMA_INTEGRITY"


@dataclass
class Finding:
    """Represents a flagged discrepancy or anomaly discovered during validation."""
    rule_name: str
    check_type: Union[CheckType, str]
    severity: Union[Severity, str]
    table_name: str
    record_id: Optional[Union[str, int]] = None
    column_name: Optional[str] = None
    expected_value: Optional[Any] = None
    actual_value: Optional[Any] = None
    message: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary representation."""
        res = asdict(self)
        if isinstance(self.severity, Severity):
            res["severity"] = self.severity.value
        if isinstance(self.check_type, CheckType):
            res["check_type"] = self.check_type.value
        return res


@dataclass
class CheckResult:
    """Outcome of an individual validation check or rule suite execution."""
    check_name: str
    check_type: Union[CheckType, str]
    records_inspected: int
    findings: List[Finding] = field(default_factory=list)
    execution_time_ms: float = 0.0
    passed: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.findings:
            # Check is marked failed if any finding is CRITICAL or ERROR
            has_error = any(
                f.severity in (Severity.CRITICAL, Severity.ERROR, "CRITICAL", "ERROR")
                for f in self.findings
            )
            self.passed = not has_error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_name": self.check_name,
            "check_type": self.check_type.value if isinstance(self.check_type, CheckType) else self.check_type,
            "records_inspected": self.records_inspected,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "execution_time_ms": round(self.execution_time_ms, 2),
            "passed": self.passed,
            "metadata": self.metadata,
        }


@dataclass
class DataRecord:
    """Generic representation of a validated relational record."""
    table_name: str
    record_id: Union[str, int]
    data: Dict[str, Any]
    expected_hash: Optional[str] = None
    computed_hash: Optional[str] = None

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


@dataclass
class PipelineSummary:
    """Comprehensive summary of a pipeline validation execution."""
    run_id: str
    target_name: str
    start_time: str
    end_time: str
    duration_seconds: float
    total_records: int
    passed_records: int
    flagged_records: int
    quarantined_records: int
    integrity_score: float  # Percentage: 0.0 to 100.0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    table_summaries: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    check_results: List[CheckResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target_name": self.target_name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.duration_seconds, 3),
            "total_records": self.total_records,
            "passed_records": self.passed_records,
            "flagged_records": self.flagged_records,
            "quarantined_records": self.quarantined_records,
            "integrity_score": round(self.integrity_score, 2),
            "findings_by_severity": self.findings_by_severity,
            "table_summaries": self.table_summaries,
            "check_results": [c.to_dict() for c in self.check_results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
