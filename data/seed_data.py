"""
Database generator and seed script.
Generates relational financial ledger records with cryptographic hashes
and strategically placed anomalies to demonstrate validation pipelines,
SQL checks, reconciliation, and dead-letter quarantine.
"""

from datetime import datetime, timedelta
import os
import random
import sqlite3
import uuid
from typing import Optional

from integrity_framework.crypto.hasher import RecordHasher
from integrity_framework.sql.engine import DatabaseEngine


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number TEXT UNIQUE NOT NULL,
    account_type TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL,
    record_hash TEXT
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_uuid TEXT UNIQUE NOT NULL,
    account_id INTEGER,
    merchant TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    status TEXT NOT NULL DEFAULT 'SETTLED',
    created_at TEXT NOT NULL,
    settled_at TEXT,
    record_hash TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);

CREATE TABLE IF NOT EXISTS staging_transactions (
    id INTEGER PRIMARY KEY,
    transaction_uuid TEXT NOT NULL,
    merchant TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS prod_transactions (
    id INTEGER PRIMARY KEY,
    transaction_uuid TEXT NOT NULL,
    merchant TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT NOT NULL
);
"""


def seed_database(db_path: str = "ledger.db", record_count: int = 150) -> DatabaseEngine:
    """Populate database with clean and anomalous records."""
    if os.path.exists(db_path):
        os.remove(db_path)

    engine = DatabaseEngine(db_path)
    engine.execute_script(SCHEMA_SQL)
    hasher = RecordHasher(algorithm="sha256")

    # 1. Seed Accounts
    accounts_data = [
        {"account_number": "ACC-1001", "account_type": "CHECKING", "owner_email": "alice@corp.internal", "balance": 45200.50, "status": "ACTIVE", "created_at": "2025-01-10T08:00:00Z"},
        {"account_number": "ACC-1002", "account_type": "SAVINGS", "owner_email": "bob@corp.internal", "balance": 128500.00, "status": "ACTIVE", "created_at": "2025-01-12T09:30:00Z"},
        {"account_number": "ACC-1003", "account_type": "ESCROW", "owner_email": "charlie@corp.internal", "balance": 950000.75, "status": "ACTIVE", "created_at": "2025-01-15T11:15:00Z"},
        {"account_number": "ACC-1004", "account_type": "TREASURY", "owner_email": "treasury@corp.internal", "balance": 3400000.00, "status": "ACTIVE", "created_at": "2025-01-01T00:00:00Z"},
        {"account_number": "ACC-1005", "account_type": "SETTLEMENT", "owner_email": "settlement@corp.internal", "balance": 75000.20, "status": "ACTIVE", "created_at": "2025-02-01T14:20:00Z"},
    ]

    for acc_id, acc in enumerate(accounts_data, start=1):
        # Include id in hash so verify_dataset can exclude 'record_hash' and get the same canonical form
        acc_with_id = {"id": acc_id, **acc}
        h = hasher.hash_record(acc_with_id)
        engine.execute_non_query(
            """
            INSERT INTO accounts (id, account_number, account_type, owner_email, balance, status, created_at, record_hash)
            VALUES (:id, :account_number, :account_type, :owner_email, :balance, :status, :created_at, :record_hash);
            """,
            {**acc_with_id, "record_hash": h},
        )

    # 2. Seed Transactions
    merchants = ["AWS Cloud", "Stripe Gateway", "GCP Compute", "Datadog Monitoring", "Snowflake Analytics", "GitHub Enterprise", "Figma Design", "Slack HQ"]
    currencies = ["USD", "USD", "USD", "EUR", "GBP", "CAD"]

    base_date = datetime(2025, 2, 1, 10, 0, 0)
    txns = []

    for i in range(1, record_count + 1):
        created_time = base_date + timedelta(minutes=i * 15)
        settled_time = created_time + timedelta(minutes=5)
        # Normal distribution of amounts around 150-450
        amount = round(random.gauss(320.0, 75.0), 2)
        amount = max(10.0, amount)

        txn = {
            "transaction_uuid": str(uuid.uuid4()),
            "account_id": random.choice([1, 2, 3, 4, 5]),
            "merchant": random.choice(merchants),
            "amount": amount,
            "currency": random.choice(currencies),
            "status": "SETTLED",
            "created_at": created_time.isoformat() + "Z",
            "settled_at": settled_time.isoformat() + "Z",
        }
        txns.append(txn)

    # Inject Strategic Anomalies for demonstration
    # Anomaly 1: Cryptographic tampering (amount modified after hash calculation)
    # Anomaly 2: Negative transaction amount
    # Anomaly 3: Invalid UUID regex format
    # Anomaly 4: Non-ISO currency code
    # Anomaly 5: Unrecognized enum status
    # Anomaly 6: Extreme statistical outlier (Z-Score > 4.5, huge amount)
    # Anomaly 7: Cross-field chronological violation (settled_at before created_at)
    # Anomaly 8: Orphan foreign key (referencing account 9999)

    txns[5]["amount"] = -149.99  # Violation: Negative amount
    txns[12]["transaction_uuid"] = "INVALID-UUID-999-NOT-COMPLIANT"  # Violation: Regex mismatch
    txns[18]["currency"] = "US_DOLLARS"  # Violation: Currency code pattern
    txns[25]["status"] = "PENDING_UNKNOWN_STATE"  # Violation: Enum not in list
    txns[32]["amount"] = 84500.00  # Violation: Huge outlier spike (Z-score anomaly)
    txns[40]["settled_at"] = (base_date - timedelta(days=2)).isoformat() + "Z"  # Violation: Cross-field timeline

    for idx, t in enumerate(txns, start=1):
        # Compute hash including numeric id (position in list = future rowid)
        t_with_id = {"id": idx, **t}
        h = hasher.hash_record(t_with_id)

        # Plant deliberate hash tampering on record #3
        if idx == 3:
            # Attacker quietly altered the amount from legitimate to 9999.00 without recomputing hash!
            t["amount"] = 9999.00

        engine.execute_non_query(
            """
            INSERT INTO transactions (id, transaction_uuid, account_id, merchant, amount, currency, status, created_at, settled_at, record_hash)
            VALUES (:id, :transaction_uuid, :account_id, :merchant, :amount, :currency, :status, :created_at, :settled_at, :record_hash);
            """,
            {"id": idx, **t, "record_hash": h},
        )

    # 3. Seed Reconciliation Datasets (staging vs prod)
    # 20 common records, 1 missing in prod, 1 phantom in prod, 1 value divergence
    for i in range(1, 21):
        t_uuid = f"RECON-{i:04d}"
        merch = "Merchant-" + str(i % 5)
        amt = float(100 + i * 10)
        st = "SETTLED"

        # Staging
        engine.execute_non_query(
            "INSERT INTO staging_transactions (id, transaction_uuid, merchant, amount, status) VALUES (?, ?, ?, ?, ?);",
            [i, t_uuid, merch, amt, st],
        )

        # Prod:
        if i == 7:
            # Drop record 7 from prod (Missing in Prod)
            continue
        if i == 14:
            # Mutate amount in prod (Attribute divergence)
            amt = 99999.99

        engine.execute_non_query(
            "INSERT INTO prod_transactions (id, transaction_uuid, merchant, amount, status) VALUES (?, ?, ?, ?, ?);",
            [i, t_uuid, merch, amt, st],
        )

    # Insert phantom record into prod only
    engine.execute_non_query(
        "INSERT INTO prod_transactions (id, transaction_uuid, merchant, amount, status) VALUES (?, ?, ?, ?, ?);",
        [99, "RECON-PHANTOM-99", "Untracked Vendor", 500.00, "SETTLED"],
    )

    print(f"✅ Seeded '{db_path}' with {len(accounts_data)} accounts and {len(txns)} transactions.")
    return engine


if __name__ == "__main__":
    seed_database("ledger.db")
