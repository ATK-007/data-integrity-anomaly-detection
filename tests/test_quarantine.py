"""Tests for quarantine and dead-letter store."""

import unittest
from integrity_framework.models import Finding, Severity, CheckType
from integrity_framework.pipeline.quarantine import QuarantineStore


class TestQuarantineStore(unittest.TestCase):
    def setUp(self):
        self.store = QuarantineStore(":memory:")

    def test_quarantine_record(self):
        finding = Finding(
            rule_name="CORRUPT_PAYLOAD",
            check_type=CheckType.CRYPTOGRAPHIC_HASH,
            severity=Severity.CRITICAL,
            table_name="orders",
            record_id=105,
            message="Cryptographic mismatch on hash signature",
        )

        qid = self.store.quarantine_record(
            source_table="orders",
            record_id=105,
            raw_record={"id": 105, "amount": 999.0, "status": "UNKNOWN"},
            findings=[finding],
        )

        self.assertTrue(qid.startswith("Q-"))
        self.assertEqual(self.store.get_count("OPEN"), 1)

        records = self.store.list_quarantined(status="OPEN")
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r["source_table"], "orders")
        self.assertEqual(r["record_id"], "105")
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertEqual(r["status"], "OPEN")

    def test_quarantine_resolution(self):
        finding = Finding(
            rule_name="RANGE_FAIL",
            check_type=CheckType.RULE_VALIDATION,
            severity=Severity.ERROR,
            table_name="users",
            record_id=20,
            message="Age out of bounds",
        )
        qid = self.store.quarantine_record("users", 20, {"id": 20, "age": -5}, [finding])

        # Resolve record
        ok = self.store.resolve_record(qid, resolution_status="RESOLVED", resolved_by="auditor_jane", notes="Corrected by customer service")
        self.assertTrue(ok)
        self.assertEqual(self.store.get_count("OPEN"), 0)
        self.assertEqual(self.store.get_count("RESOLVED"), 1)


if __name__ == "__main__":
    unittest.main()
