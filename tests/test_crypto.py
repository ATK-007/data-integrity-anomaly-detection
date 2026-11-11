"""Tests for cryptographic hashing and Merkle tree modules."""

import unittest
from integrity_framework.crypto.hasher import RecordHasher
from integrity_framework.crypto.merkle import MerkleTree
from integrity_framework.models import Severity, CheckType


class TestRecordHasher(unittest.TestCase):
    def setUp(self):
        self.hasher = RecordHasher("sha256")

    def test_deterministic_hashing(self):
        rec1 = {"id": 1, "amount": 100.5, "currency": "USD"}
        rec2 = {"currency": "USD", "amount": 100.5, "id": 1}
        # Order of dictionary keys must not affect output hash
        h1 = self.hasher.hash_record(rec1)
        h2 = self.hasher.hash_record(rec2)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_canonical_null_handling(self):
        rec1 = {"id": 1, "note": None}
        rec2 = {"id": 1, "note": "__NULL__"}
        self.assertEqual(self.hasher.canonicalize(rec1), "id=1;note=__NULL__")

    def test_tamper_detection(self):
        legitimate = {"id": 42, "amount": 250.00, "status": "SETTLED"}
        golden_hash = self.hasher.hash_record(legitimate)

        # Altered record
        tampered = {"id": 42, "amount": 9999.00, "status": "SETTLED"}
        finding = self.hasher.verify_record(
            record=tampered,
            expected_hash=golden_hash,
            record_id=42,
            table_name="transactions",
        )

        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.check_type, CheckType.CRYPTOGRAPHIC_HASH)
        self.assertIn("mismatch", finding.message.lower())

    def test_dataset_verification(self):
        records = [
            {"id": 1, "name": "Item A", "price": 10.0},
            {"id": 2, "name": "Item B", "price": 20.0},
        ]
        # Stamp hashes
        for r in records:
            r["record_hash"] = self.hasher.hash_record({k: v for k, v in r.items() if k != "record_hash"})

        # Corrupt second record
        records[1]["price"] = 25.0

        res = self.hasher.verify_dataset(records, table_name="items")
        self.assertFalse(res.passed)
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].record_id, 2)


class TestMerkleTree(unittest.TestCase):
    def test_empty_tree(self):
        tree = MerkleTree([])
        self.assertTrue(len(tree.root_hash) > 0)

    def test_single_leaf(self):
        h = "a" * 64
        tree = MerkleTree([h])
        self.assertEqual(tree.root_hash, h)

    def test_multi_leaf_merkle_root(self):
        hasher = RecordHasher("sha256")
        hashes = [hasher.hash_record({"i": i}) for i in range(8)]
        tree1 = MerkleTree(hashes)
        tree2 = MerkleTree(hashes)
        self.assertEqual(tree1.root_hash, tree2.root_hash)

        # Perturb one hash
        perturbed = list(hashes)
        perturbed[3] = hasher.hash_record({"i": 999})
        tree_tampered = MerkleTree(perturbed)
        self.assertNotEqual(tree1.root_hash, tree_tampered.root_hash)

    def test_audit_proof_verification(self):
        hasher = RecordHasher("sha256")
        hashes = [hasher.hash_record({"idx": i}) for i in range(16)]
        tree = MerkleTree(hashes)

        for target_idx in [0, 5, 15]:
            leaf = hashes[target_idx]
            proof = tree.get_audit_proof(target_idx)
            is_valid = MerkleTree.verify_proof(leaf, proof, tree.root_hash)
            self.assertTrue(is_valid, f"Proof failed for leaf {target_idx}")

            # Tampered leaf must fail verification
            tampered_leaf = hasher.hash_record({"idx": "fake"})
            self.assertFalse(MerkleTree.verify_proof(tampered_leaf, proof, tree.root_hash))

    def test_diff_leaf_hashes(self):
        src = ["h1", "h2", "h3"]
        tgt = ["h1", "h2_modified", "h3"]
        diffs = MerkleTree.diff_leaf_hashes(src, tgt)
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0]["index"], 1)
        self.assertEqual(diffs[0]["type"], "MUTATION")


if __name__ == "__main__":
    unittest.main()
