"""Tests for rule engine and statistical anomaly detection."""

import unittest
from integrity_framework.models import Severity
from integrity_framework.rules.engine import RuleEngine
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


class TestValidationRules(unittest.TestCase):
    def test_not_null_rule(self):
        rule = NotNullRule("CHECK_EMAIL", "users", "email")
        self.assertIsNone(rule.evaluate_record({"id": 1, "email": "a@b.com"}))
        self.assertIsNotNone(rule.evaluate_record({"id": 2, "email": None}))
        self.assertIsNotNone(rule.evaluate_record({"id": 3, "email": "   "}))

    def test_null_ratio_rule(self):
        rule = NullRatioThresholdRule("NULL_CAP", "users", "phone", max_ratio=0.20)
        # 1 out of 5 null = 20% (<= 20% -> passes)
        data_pass = [{"phone": "123"} for _ in range(4)] + [{"phone": None}]
        self.assertEqual(len(rule.evaluate_dataset(data_pass)), 0)

        # 2 out of 5 null = 40% (> 20% -> fails)
        data_fail = [{"phone": "123"} for _ in range(3)] + [{"phone": None}, {"phone": None}]
        findings = rule.evaluate_dataset(data_fail)
        self.assertEqual(len(findings), 1)

    def test_range_rule(self):
        rule = RangeRule("AGE_BOUNDS", "users", "age", min_value=18, max_value=65)
        self.assertIsNone(rule.evaluate_record({"age": 25}))
        self.assertIsNotNone(rule.evaluate_record({"age": 12}))
        self.assertIsNotNone(rule.evaluate_record({"age": 70}))

    def test_regex_rule(self):
        uuid_rule = RegexRule("VALID_UUID", "events", "uuid", pattern="UUID")
        self.assertIsNone(uuid_rule.evaluate_record({"uuid": "123e4567-e89b-12d3-a456-426614174000"}))
        self.assertIsNotNone(uuid_rule.evaluate_record({"uuid": "not-a-valid-uuid"}))

        currency_rule = RegexRule("ISO_CURRENCY", "txns", "ccy", pattern="CURRENCY_CODE")
        self.assertIsNone(currency_rule.evaluate_record({"ccy": "USD"}))
        self.assertIsNotNone(currency_rule.evaluate_record({"ccy": "DOLLARS"}))

    def test_allowed_values_rule(self):
        rule = AllowedValuesRule("STATUS_ENUM", "orders", "status", ["PENDING", "PAID", "CANCELLED"])
        self.assertIsNone(rule.evaluate_record({"status": "paid"}))  # case-insensitive default
        self.assertIsNotNone(rule.evaluate_record({"status": "SHIPPED"}))

    def test_cross_field_rule(self):
        rule = CrossFieldRule(
            name="CHECK_START_END_DATE",
            table_name="events",
            predicate=lambda r: r.get("end_date") >= r.get("start_date"),
            involved_columns=["start_date", "end_date"],
            expected_description="end_date must be >= start_date",
        )
        self.assertIsNone(rule.evaluate_record({"start_date": "2025-01-01", "end_date": "2025-01-05"}))
        self.assertIsNotNone(rule.evaluate_record({"start_date": "2025-01-05", "end_date": "2025-01-01"}))

    def test_schema_drift_rule(self):
        rule = SchemaDriftRule(
            name="CORE_COLUMNS",
            table_name="products",
            required_columns={"id", "sku", "price"},
            allowed_columns={"id", "sku", "price", "description"},
        )
        # Clean record
        clean = [{"id": 1, "sku": "A", "price": 10.0}]
        self.assertEqual(len(rule.evaluate_dataset(clean)), 0)

        # Missing required price column
        missing = [{"id": 1, "sku": "A"}]
        findings = rule.evaluate_dataset(missing)
        self.assertEqual(len(findings), 1)
        self.assertIn("missing", findings[0].message.lower())


class TestStatisticalAnomalies(unittest.TestCase):
    def test_z_score_detector(self):
        detector = ZScoreAnomalyDetector("PRICE_ZSCORE", "items", "price", threshold=3.0)
        # Normal records around 100
        records = [{"id": i, "price": 100.0 + (i % 5)} for i in range(1, 50)]
        # Add massive outlier
        records.append({"id": 999, "price": 10000.0})

        findings = detector.evaluate_dataset(records)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].record_id, 999)
        self.assertGreater(findings[0].details["z_score"], 3.0)

    def test_iqr_anomaly_detector(self):
        detector = IQRAnomalyDetector("SALARY_IQR", "employees", "salary", multiplier=1.5)
        records = [{"id": i, "salary": 50000.0 + (i * 500)} for i in range(1, 30)]
        # Low outlier
        records.append({"id": 101, "salary": 100.0})
        # High outlier
        records.append({"id": 102, "salary": 500000.0})

        findings = detector.evaluate_dataset(records)
        self.assertEqual(len(findings), 2)
        flagged_ids = {f.record_id for f in findings}
        self.assertIn(101, flagged_ids)
        self.assertIn(102, flagged_ids)


class TestRuleEngineIntegration(unittest.TestCase):
    def test_rule_engine_config_load(self):
        engine = RuleEngine()
        config = {
            "tables": {
                "payments": [
                    {"type": "not_null", "name": "MANDATORY_PAYER", "column": "payer_id"},
                    {"type": "range", "name": "PAYMENT_CAP", "column": "amount", "min_value": 1.0, "max_value": 500.0},
                ]
            }
        }
        engine.load_rules_from_dict(config)
        self.assertEqual(len(engine.rules_by_table["payments"]), 2)

        data = [
            {"id": 1, "payer_id": "P1", "amount": 50.0},
            {"id": 2, "payer_id": None, "amount": 600.0},
        ]
        result = engine.evaluate_table_records("payments", data)
        self.assertFalse(result.passed)
        self.assertEqual(len(result.findings), 2)  # Missing payer + out of bounds amount


if __name__ == "__main__":
    unittest.main()
