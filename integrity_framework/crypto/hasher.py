"""
Cryptographic record hashing engine.
Provides deterministic canonical serialization and cryptographic verification
to compare records against expected hashes and identify tampering or silent corruption.
"""

from decimal import Decimal
import hashlib
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union
from integrity_framework.models import CheckResult, CheckType, Finding, Severity


class RecordHasher:
    """
    Deterministic hasher for relational data records.
    Normalizes types, handles null values predictably, and generates
    reproducible SHA-256 / BLAKE2b cryptographic digests.
    """

    def __init__(
        self,
        algorithm: str = "sha256",
        salt: str = "",
        excluded_columns: Optional[Sequence[str]] = None,
    ):
        """
        Initialize hasher.
        :param algorithm: 'sha256' or 'blake2b'
        :param salt: optional salt prefix for domain separation
        :param excluded_columns: columns to omit from hash calculation (e.g. updated_at)
        """
        self.algorithm = algorithm.lower()
        if self.algorithm not in ("sha256", "blake2b", "sha3_256"):
            raise ValueError(f"Unsupported cryptographic algorithm: {algorithm}")
        self.salt = salt
        self.excluded_columns = set(c.lower() for c in (excluded_columns or []))

    def _normalize_value(self, val: Any) -> str:
        """
        Canonically normalize data values for deterministic cross-platform hashing.
        """
        if val is None:
            return "__NULL__"
        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, (int, )):
            return str(val)
        if isinstance(val, (float, Decimal)):
            # Normalize floating point to fixed-precision string to avoid representation drift
            return f"{float(val):.8f}".rstrip("0").rstrip(".")
        if isinstance(val, (bytes, bytearray)):
            return val.hex()
        # Fallback string representation with trimmed whitespace
        return str(val).strip()

    def canonicalize(self, record: Dict[str, Any], columns: Optional[Sequence[str]] = None) -> str:
        """
        Convert a record dictionary into a canonical, sorted key-value string.
        """
        if columns is not None:
            active_keys = [k for k in columns if k.lower() not in self.excluded_columns]
        else:
            active_keys = sorted(
                k for k in record.keys() if k.lower() not in self.excluded_columns
            )

        pairs = []
        for key in active_keys:
            norm_key = str(key).strip().lower()
            norm_val = self._normalize_value(record.get(key))
            pairs.append(f"{norm_key}={norm_val}")

        return (f"{self.salt}|" if self.salt else "") + ";".join(pairs)

    def hash_record(self, record: Dict[str, Any], columns: Optional[Sequence[str]] = None) -> str:
        """
        Compute cryptographic digest of a single record dictionary.
        """
        canonical_str = self.canonicalize(record, columns)
        encoded = canonical_str.encode("utf-8")

        if self.algorithm == "sha256":
            return hashlib.sha256(encoded).hexdigest()
        elif self.algorithm == "blake2b":
            return hashlib.blake2b(encoded).hexdigest()
        elif self.algorithm == "sha3_256":
            return hashlib.sha3_256(encoded).hexdigest()
        else:
            return hashlib.sha256(encoded).hexdigest()

    def verify_record(
        self,
        record: Dict[str, Any],
        expected_hash: str,
        record_id: Optional[Union[str, int]] = None,
        table_name: str = "dataset",
        columns: Optional[Sequence[str]] = None,
    ) -> Optional[Finding]:
        """
        Verify that a record matches its expected cryptographic digest.
        Returns a Finding if mismatched, or None if valid.
        """
        computed = self.hash_record(record, columns)
        expected = expected_hash.strip().lower()

        if computed.lower() != expected:
            return Finding(
                rule_name="CRYPTOGRAPHIC_HASH_INTEGRITY",
                check_type=CheckType.CRYPTOGRAPHIC_HASH,
                severity=Severity.CRITICAL,
                table_name=table_name,
                record_id=record_id or record.get("id"),
                column_name="_record_hash",
                expected_value=expected,
                actual_value=computed,
                message=(
                    f"Cryptographic hash mismatch on table '{table_name}' record '{record_id}'. "
                    f"Expected {expected[:12]}... but computed {computed[:12]}... (potential tampering or unauthorized mutation)"
                ),
                details={
                    "algorithm": self.algorithm,
                    "canonical_representation": self.canonicalize(record, columns),
                },
            )
        return None

    def verify_dataset(
        self,
        records: Iterable[Dict[str, Any]],
        hash_column: str = "record_hash",
        id_column: str = "id",
        table_name: str = "dataset",
        columns: Optional[Sequence[str]] = None,
    ) -> CheckResult:
        """
        Verify an entire iterable of records containing an expected hash column.
        """
        import time
        start_time = time.perf_counter()
        findings: List[Finding] = []
        count = 0

        for r in records:
            count += 1
            rec_id = r.get(id_column, f"row_{count}")
            expected = r.get(hash_column)
            if not expected:
                findings.append(
                    Finding(
                        rule_name="MISSING_CRYPTOGRAPHIC_HASH",
                        check_type=CheckType.CRYPTOGRAPHIC_HASH,
                        severity=Severity.ERROR,
                        table_name=table_name,
                        record_id=rec_id,
                        column_name=hash_column,
                        expected_value="valid_hash_string",
                        actual_value=None,
                        message=f"Missing cryptographic checksum column '{hash_column}' for record '{rec_id}'",
                    )
                )
                continue

            # Record excluding the hash column itself
            clean_rec = {k: v for k, v in r.items() if k != hash_column}
            finding = self.verify_record(
                record=clean_rec,
                expected_hash=str(expected),
                record_id=rec_id,
                table_name=table_name,
                columns=columns,
            )
            if finding:
                findings.append(finding)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return CheckResult(
            check_name=f"Cryptographic Hash Verification: {table_name}",
            check_type=CheckType.CRYPTOGRAPHIC_HASH,
            records_inspected=count,
            findings=findings,
            execution_time_ms=elapsed_ms,
            metadata={"algorithm": self.algorithm, "table": table_name},
        )
