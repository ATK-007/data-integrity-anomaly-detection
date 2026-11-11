"""
Statistical anomaly and outlier detection rules using pure Python standard library.
Implements Z-Score and Interquartile Range (IQR) detection on numeric series.
"""

import math
from typing import Any, Dict, List, Optional, Tuple, Union
from integrity_framework.models import CheckType, Finding, Severity
from integrity_framework.rules.base import BaseRule


class ZScoreAnomalyDetector(BaseRule):
    """
    Detects statistical outliers in a numeric column where |z| > threshold.
    Z = (x - mean) / std_dev.
    """

    def __init__(
        self,
        name: str,
        table_name: str,
        column_name: str,
        threshold: float = 3.0,
        severity: Severity = Severity.WARNING,
        description: str = "",
    ):
        super().__init__(
            name=name,
            table_name=table_name,
            column_name=column_name,
            severity=severity,
            check_type=CheckType.STATISTICAL_ANOMALY,
            description=description or f"Z-Score outlier detection on '{column_name}' (|z| > {threshold})",
        )
        self.threshold = threshold

    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        # Z-Score requires dataset context
        return None

    def evaluate_dataset(
        self, records: List[Dict[str, Any]], id_column: str = "id"
    ) -> List[Finding]:
        if not records:
            return []

        # Extract numeric values
        values: List[float] = []
        valid_records: List[Tuple[Any, float]] = []

        for r in records:
            v = r.get(self.column_name)
            if v is not None:
                try:
                    num = float(v)
                    values.append(num)
                    valid_records.append((r.get(id_column), num))
                except (ValueError, TypeError):
                    continue

        n = len(values)
        if n < 3:
            return []  # Need sufficient sample size

        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        std_dev = math.sqrt(variance)

        if std_dev == 0.0:
            return []  # All values identical, no outliers

        findings: List[Finding] = []
        for rec_id, num in valid_records:
            z_score = (num - mean) / std_dev
            if abs(z_score) > self.threshold:
                findings.append(
                    Finding(
                        rule_name=self.name,
                        check_type=self.check_type,
                        severity=self.severity,
                        table_name=self.table_name,
                        record_id=rec_id,
                        column_name=self.column_name,
                        expected_value=f"|z| <= {self.threshold} (Mean: {mean:.2f}, StdDev: {std_dev:.2f})",
                        actual_value=f"{num} (z-score: {z_score:+.2f})",
                        message=(
                            f"Statistical outlier detected in table '{self.table_name}' column '{self.column_name}' "
                            f"for record '{rec_id}'. Value {num} has z-score of {z_score:+.2f} (|z| > {self.threshold})."
                        ),
                        details={
                            "z_score": round(z_score, 3),
                            "mean": round(mean, 3),
                            "std_dev": round(std_dev, 3),
                            "threshold": self.threshold,
                        },
                    )
                )

        return findings


class IQRAnomalyDetector(BaseRule):
    """
    Non-parametric outlier detection using Interquartile Range (IQR).
    Fences: [Q1 - multiplier * IQR, Q3 + multiplier * IQR].
    """

    def __init__(
        self,
        name: str,
        table_name: str,
        column_name: str,
        multiplier: float = 1.5,
        severity: Severity = Severity.WARNING,
        description: str = "",
    ):
        super().__init__(
            name=name,
            table_name=table_name,
            column_name=column_name,
            severity=severity,
            check_type=CheckType.STATISTICAL_ANOMALY,
            description=description or f"IQR outlier detection on '{column_name}' (k={multiplier})",
        )
        self.multiplier = multiplier

    def evaluate_record(
        self, record: Dict[str, Any], record_id: Optional[Any] = None
    ) -> Optional[Finding]:
        return None

    def _percentile(self, sorted_vals: List[float], percent: float) -> float:
        k = (len(sorted_vals) - 1) * percent
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_vals[int(k)]
        d0 = sorted_vals[int(f)] * (c - k)
        d1 = sorted_vals[int(c)] * (k - f)
        return d0 + d1

    def evaluate_dataset(
        self, records: List[Dict[str, Any]], id_column: str = "id"
    ) -> List[Finding]:
        if not records:
            return []

        indexed_vals: List[Tuple[Any, float]] = []
        for r in records:
            v = r.get(self.column_name)
            if v is not None:
                try:
                    indexed_vals.append((r.get(id_column), float(v)))
                except (ValueError, TypeError):
                    continue

        if len(indexed_vals) < 4:
            return []

        sorted_vals = sorted(v for _, v in indexed_vals)
        q1 = self._percentile(sorted_vals, 0.25)
        q3 = self._percentile(sorted_vals, 0.75)
        iqr = q3 - q1

        lower_fence = q1 - (self.multiplier * iqr)
        upper_fence = q3 + (self.multiplier * iqr)

        findings: List[Finding] = []
        for rec_id, val in indexed_vals:
            if val < lower_fence or val > upper_fence:
                direction = "Low outlier" if val < lower_fence else "High outlier"
                findings.append(
                    Finding(
                        rule_name=self.name,
                        check_type=self.check_type,
                        severity=self.severity,
                        table_name=self.table_name,
                        record_id=rec_id,
                        column_name=self.column_name,
                        expected_value=f"Within IQR bounds [{lower_fence:.2f}, {upper_fence:.2f}]",
                        actual_value=val,
                        message=(
                            f"IQR {direction} in table '{self.table_name}' column '{self.column_name}' "
                            f"for record '{rec_id}'. Value {val} falls outside [{lower_fence:.2f}, {upper_fence:.2f}]."
                        ),
                        details={
                            "q1": round(q1, 3),
                            "q3": round(q3, 3),
                            "iqr": round(iqr, 3),
                            "lower_fence": round(lower_fence, 3),
                            "upper_fence": round(upper_fence, 3),
                        },
                    )
                )

        return findings
