"""
Data Integrity & Anomaly Detection Framework
Automated validation pipeline using SQL-based checks, cryptographic hashing,
and rule-based discrepancy flagging.
"""

__version__ = "1.0.0"
__author__ = "Aditya Atmakuri"

from integrity_framework.models import (
    Severity,
    Finding,
    CheckResult,
    PipelineSummary,
    DataRecord,
)
from integrity_framework.crypto.hasher import RecordHasher
from integrity_framework.crypto.merkle import MerkleTree
from integrity_framework.sql.engine import DatabaseEngine
from integrity_framework.sql.reconciler import SQLReconciler
from integrity_framework.rules.engine import RuleEngine
from integrity_framework.pipeline.orchestrator import ValidationPipeline
from integrity_framework.pipeline.quarantine import QuarantineStore
from integrity_framework.pipeline.reporter import ReportGenerator

__all__ = [
    "Severity",
    "Finding",
    "CheckResult",
    "PipelineSummary",
    "DataRecord",
    "RecordHasher",
    "MerkleTree",
    "DatabaseEngine",
    "SQLReconciler",
    "RuleEngine",
    "ValidationPipeline",
    "QuarantineStore",
    "ReportGenerator",
]
