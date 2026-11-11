# 🛡️ Data Integrity & Anomaly Detection Framework (Python, SQL)

> Automated validation pipeline using SQL-based checks, cryptographic hashing, and rule-based discrepancy flagging — built to support repeatable data-quality analysis and issue investigation.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![Database](https://img.shields.io/badge/database-SQLite%20WAL-green.svg)](https://www.sqlite.org/)
[![Tests](https://img.shields.io/badge/tests-29%20passing-brightgreen.svg)](#testing)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20external-brightgreen.svg)](#zero-external-dependencies)

---

## ✨ What This Does

This framework provides an **end-to-end, fully automated data validation pipeline** that runs three classes of integrity checks in sequence:

| Layer | Mechanism | Detects |
|---|---|---|
| **Cryptographic** | SHA-256 / BLAKE2b record hashing | Silent data tampering, unauthorized mutations |
| **SQL-Based** | Invariant assertions, aggregate balance checks, FK validation | Schema violations, orphan keys, broken constraints |
| **Rule-Based** | Declarative JSON-driven rules | Null drift, regex mismatches, enum violations, outliers |

After each run, flagged records are automatically isolated into a **dead-letter quarantine store** and exported as a structured **forensic audit report** (JSON / CSV / Markdown / HTML).

---

## 🏗️ Architecture

```
data-integrity-framework/
│
├── integrity_framework/
│   ├── crypto/
│   │   ├── hasher.py          # SHA-256/BLAKE2b record hashing & tamper detection
│   │   └── merkle.py          # Merkle tree dataset fingerprinting & audit proofs
│   │
│   ├── sql/
│   │   ├── engine.py          # SQLite WAL engine with PRAGMA integrity checks
│   │   ├── checks.py          # Row assertions, aggregate balance checks
│   │   └── reconciler.py      # Source vs target table reconciliation
│   │
│   ├── rules/
│   │   ├── base.py            # Abstract rule interface
│   │   ├── schema_rules.py    # NotNull, NullRatio, TypeCheck, SchemaDrift
│   │   ├── value_rules.py     # Range, Regex, AllowedValues, CrossField
│   │   ├── statistical.py     # Z-Score & IQR anomaly detectors
│   │   └── engine.py          # Declarative rule loading & evaluation engine
│   │
│   ├── pipeline/
│   │   ├── orchestrator.py    # Automated end-to-end pipeline coordinator
│   │   ├── quarantine.py      # Dead-letter isolation & resolution store
│   │   └── reporter.py        # JSON / CSV / Markdown / HTML report generator
│   │
│   ├── web/
│   │   ├── server.py          # Pure stdlib HTTP dashboard server
│   │   └── static/            # HTML5 / CSS3 / JavaScript dark dashboard
│   │
│   ├── cli.py                 # CLI: validate, reconcile, quarantine, stamp-hashes
│   └── models.py              # Severity, Finding, CheckResult, PipelineSummary
│
├── data/
│   ├── seed_data.py           # Demo ledger generator with injected anomalies
│   └── sample_rules.json      # Declarative rule configuration example
│
├── tests/                     # 29 unit + integration tests (100% pass rate)
│   ├── test_crypto.py
│   ├── test_sql_checks.py
│   ├── test_rules.py
│   ├── test_quarantine.py
│   └── test_pipeline.py
│
├── run_demo.py                # End-to-end pipeline demonstration
├── run_dashboard.py           # Interactive web dashboard launcher
└── run_tests.py               # Test suite runner
```

---

## 🚀 Quick Start

**Zero external dependencies — runs on Python 3.9+ standard library only.**

```bash
git clone https://github.com/ATK-007/data-integrity-anomaly-detection.git
cd data-integrity-anomaly-detection

# 1. Run full demo (seeds DB, validates, generates reports)
python3 run_demo.py

# 2. Launch interactive web dashboard at http://127.0.0.1:8088
python3 run_dashboard.py

# 3. Run test suite (29 tests)
python3 run_tests.py
```

---

## 🔍 Validation Pipeline — 6 Sequential Stages

### Stage 1 — Database Structural Integrity
Runs SQLite `PRAGMA integrity_check` and `PRAGMA foreign_key_check` to detect page-level corruption and orphaned foreign key references before any data is read.

### Stage 2 — Cryptographic Hash Verification
Each record is **deterministically serialized** (sorted keys, canonical null handling, type normalization) and hashed with SHA-256. The computed hash is compared against the stored baseline to flag unauthorized mutations:

```python
from integrity_framework.crypto.hasher import RecordHasher

hasher = RecordHasher("sha256", excluded_columns=["updated_at"])
record_hash = hasher.hash_record({"id": 42, "amount": 250.00, "status": "SETTLED"})

# Tamper detection
finding = hasher.verify_record(tampered_record, expected_hash=record_hash, table_name="transactions")
# → CRITICAL Finding: "Cryptographic hash mismatch ... (potential tampering)"
```

### Stage 3 — Merkle Tree Dataset Fingerprinting
A **binary Merkle tree** is constructed from all record hashes. The root hash provides an O(1) check for dataset divergence. Individual records can be inclusion-proven without re-scanning the full table:

```python
from integrity_framework.crypto.merkle import MerkleTree

tree = MerkleTree(all_record_hashes)
print(f"Dataset fingerprint: {tree.root_hash}")

proof = tree.get_audit_proof(leaf_index=5)
is_authentic = MerkleTree.verify_proof(leaf_hash, proof, tree.root_hash)
```

### Stage 4 — SQL Row Assertions & Aggregate Invariants
Declarative SQL conditions are evaluated directly against the database engine:

```python
from integrity_framework.sql.checks import SQLAssertion, AggregateAssertion

# Row-level assertion: every transaction must be positive
pipeline.sql_checks.add_row_assertion(SQLAssertion(
    name="NON_NEGATIVE_AMOUNT",
    table="transactions",
    condition="amount > 0",
    severity=Severity.ERROR,
))

# Aggregate balance assertion
pipeline.sql_checks.add_aggregate_assertion(AggregateAssertion(
    name="DEBIT_CREDIT_BALANCE",
    table="ledger_entries",
    query="SELECT SUM(amount) FROM ledger_entries WHERE type='debit'",
    expected_value=100000.0,
    operator="==",
))
```

### Stage 5 — Declarative Rule Engine
Rules are loaded from JSON config or registered programmatically:

```json
{
  "tables": {
    "transactions": [
      { "type": "not_null",       "column": "account_id" },
      { "type": "range",          "column": "amount",    "min_value": 0.01, "max_value": 250000.0 },
      { "type": "regex",          "column": "currency",  "pattern": "CURRENCY_CODE" },
      { "type": "allowed_values", "column": "status",    "values": ["PENDING", "SETTLED", "FAILED"] },
      { "type": "z_score",        "column": "amount",    "threshold": 3.0,  "severity": "WARNING" },
      { "type": "iqr",            "column": "amount",    "multiplier": 1.5, "severity": "WARNING" }
    ]
  }
}
```

**Available rule types:**

| Type | Description |
|---|---|
| `not_null` | Column must not be NULL or empty string |
| `null_ratio` | Dataset-level null proportion cap |
| `type` | Primitive type validation (int, float, str, bool) |
| `range` | Numeric bounds `[min, max]` with inclusive/exclusive mode |
| `regex` | Pattern matching with named presets (`UUID`, `EMAIL`, `ISO_DATE`, `CURRENCY_CODE`) |
| `allowed_values` | Enum constraint (case-insensitive by default) |
| `schema_drift` | Required/allowed column presence validation |
| `z_score` | Statistical outlier via Z-Score threshold (default |z| > 3.0) |
| `iqr` | Non-parametric outlier via Interquartile Range fences |
| `cross_field` | Multi-column predicate business logic |

### Stage 6 — SQL Set Reconciliation
Source vs. target tables are reconciled using SQL join logic to detect:
- **Missing records** — in source but not target
- **Phantom records** — in target but not source
- **Attribute divergence** — column value differences on shared keys
- **Metric delta** — aggregate sum discrepancies on financial columns

```python
from integrity_framework.sql.reconciler import SQLReconciler

result = SQLReconciler(db).reconcile_tables(
    source_table="staging_transactions",
    target_table="prod_transactions",
    primary_key="id",
    metric_columns=["amount"],
)
```

---

## 📊 Sample Pipeline Output

```
Run ID:            RUN-C3459F02
Integrity Score:   86.5%
Records Checked:   105
Flagged Anomalies: 7
Quarantined:       6

🔴 CRITICAL  CRYPTOGRAPHIC_HASH_INTEGRITY  transactions  Record 3
   Hash mismatch — expected b96bb9e7... computed 3ec552b1... (unauthorized mutation)

🟠 ERROR     SQL_NON_NEGATIVE_TXN_AMOUNT   transactions  Record 6
   Amount -149.99 fails row assertion: amount > 0

🟠 ERROR     TXN_UUID_FORMAT               transactions  Record 13
   Value 'INVALID-UUID-999' does not conform to pattern 'UUID'

🟡 WARNING   TXN_AMOUNT_ZSCORE_ANOMALY     transactions  Record 33
   Value 84500.00 has z-score of +4.82 (|z| > 3.0 threshold)
```

---

## 🌐 Interactive Web Dashboard

Start the pure-Python dark-mode dashboard (no npm, no frameworks):

```bash
python3 run_dashboard.py
# → http://127.0.0.1:8088
```

Features:
- **KPI Cards**: Integrity score, total records, flagged count, quarantine count
- **Severity Distribution**: CRITICAL / ERROR / WARNING / INFO breakdown
- **Table Health**: Per-table clean vs. flagged row ratios
- **Forensic Ledger**: Searchable, filterable discrepancy table
- **Quarantine Store**: Dead-letter records with rule violations and provenance
- **Live Rerun**: Trigger a new pipeline execution from the browser
- **Export**: One-click JSON / CSV download

---

## 🛑 Quarantine Store

Records with CRITICAL or ERROR findings are automatically isolated with full provenance:

```python
from integrity_framework.pipeline.quarantine import QuarantineStore

store = QuarantineStore("ledger.db")
records = store.list_quarantined(status="OPEN")
# → [{"quarantine_id": "Q-A3F7E2B1", "source_table": "transactions",
#     "record_id": "3", "severity": "CRITICAL", "violated_rules": [...]}]

# Resolve after investigation
store.resolve_record("Q-A3F7E2B1", resolved_by="analyst_jane", notes="Corrected by customer service")
```

---

## 🖥️ CLI Reference

```bash
# Run full validation pipeline on a SQLite database
python3 -m integrity_framework.cli validate \
    --db ledger.db \
    --rules data/sample_rules.json \
    --out-dir ./reports

# Reconcile staging against production
python3 -m integrity_framework.cli reconcile \
    --db ledger.db \
    --source staging_transactions \
    --target prod_transactions \
    --metrics amount

# Inspect quarantine store
python3 -m integrity_framework.cli quarantine --db ledger.db --status OPEN

# Stamp cryptographic hashes on a table
python3 -m integrity_framework.cli stamp-hashes --db ledger.db --table transactions
```

---

## 🧪 Testing

29 unit and integration tests with full coverage of all framework layers:

```bash
python3 run_tests.py
```

```
test_audit_proof_verification ............ ok
test_deterministic_hashing ............... ok
test_tamper_detection .................... ok
test_pipeline_execution_and_quarantine ... ok
test_multi_format_reporting .............. ok
test_full_reconciliation ................. ok
test_z_score_detector .................... ok
test_iqr_anomaly_detector ................ ok
...

Ran 29 tests in 0.080s — OK
```

---

## 📋 Resume Summary

> **Data Integrity & Anomaly Detection Framework | Python, SQL**
> - Built an automated validation pipeline using SQL-based checks and cryptographic hashing (SHA-256 / BLAKE2b / Merkle trees) to compare records against expected values and detect silent tampering.
> - Applied rule-based validation (NotNull, Range, Regex, Enum, Z-Score, IQR, CrossField) to flag discrepancies and document findings across structured relational datasets.
> - Automated repeatable validation workflows with dead-letter quarantine isolation, multi-format forensic reporting (JSON/CSV/Markdown/HTML), and an interactive dark-mode web dashboard.

---

## 📄 License

MIT © 2026 Aditya Atmakuri
