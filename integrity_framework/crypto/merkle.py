"""
Merkle Tree implementation for dataset-level cryptographic integrity verification.
Enables rapid O(1) detection of dataset divergence and hierarchical leaf localization.
"""

from dataclasses import dataclass
import hashlib
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class MerkleNode:
    hash_value: str
    left: Optional["MerkleNode"] = None
    right: Optional["MerkleNode"] = None
    leaf_index: Optional[int] = None


class MerkleTree:
    """
    Binary Merkle Tree constructed from an ordered list of record digests.
    """

    def __init__(self, leaf_hashes: List[str], hash_algo: str = "sha256"):
        self.leaf_hashes = [h.strip().lower() for h in leaf_hashes]
        self.hash_algo = hash_algo
        self.root: Optional[MerkleNode] = None
        self._build_tree()

    def _hash(self, data: str) -> str:
        encoded = data.encode("utf-8")
        if self.hash_algo == "blake2b":
            return hashlib.blake2b(encoded).hexdigest()
        return hashlib.sha256(encoded).hexdigest()

    def _combine_hashes(self, left_hash: str, right_hash: str) -> str:
        # Sort hashes canonically before combining to ensure consistency
        combined = f"{left_hash}:{right_hash}"
        return self._hash(combined)

    def _build_tree(self) -> None:
        if not self.leaf_hashes:
            self.root = MerkleNode(hash_value=self._hash("__EMPTY_TREE__"))
            return

        current_level: List[MerkleNode] = [
            MerkleNode(hash_value=h, leaf_index=i)
            for i, h in enumerate(self.leaf_hashes)
        ]

        while len(current_level) > 1:
            next_level: List[MerkleNode] = []
            for i in range(0, len(current_level), 2):
                left_node = current_level[i]
                if i + 1 < len(current_level):
                    right_node = current_level[i + 1]
                else:
                    # Duplicate last node if odd count
                    right_node = MerkleNode(hash_value=left_node.hash_value)

                parent_hash = self._combine_hashes(
                    left_node.hash_value, right_node.hash_value
                )
                parent_node = MerkleNode(
                    hash_value=parent_hash,
                    left=left_node,
                    right=right_node,
                )
                next_level.append(parent_node)
            current_level = next_level

        self.root = current_level[0]

    @property
    def root_hash(self) -> str:
        """Get the root Merkle hash representing the entire dataset."""
        return self.root.hash_value if self.root else ""

    def get_audit_proof(self, leaf_index: int) -> List[Tuple[str, str]]:
        """
        Generate cryptographic audit proof path for a leaf index.
        Returns list of (sibling_hash, direction) where direction is 'left' or 'right'.
        """
        if leaf_index < 0 or leaf_index >= len(self.leaf_hashes):
            raise IndexError("Leaf index out of bounds")

        proof: List[Tuple[str, str]] = []
        leaves = [h for h in self.leaf_hashes]

        target_idx = leaf_index
        current_hashes = list(leaves)

        while len(current_hashes) > 1:
            next_hashes: List[str] = []
            for i in range(0, len(current_hashes), 2):
                left = current_hashes[i]
                right = current_hashes[i + 1] if i + 1 < len(current_hashes) else left
                if i == target_idx or i + 1 == target_idx:
                    if target_idx % 2 == 0:
                        proof.append((right, "right"))
                    else:
                        proof.append((left, "left"))
                next_hashes.append(self._combine_hashes(left, right))
            target_idx //= 2
            current_hashes = next_hashes

        return proof

    @staticmethod
    def verify_proof(
        leaf_hash: str,
        proof: List[Tuple[str, str]],
        expected_root: str,
        hash_algo: str = "sha256",
    ) -> bool:
        """Verify that a leaf hash belongs to a tree with the given root."""
        current = leaf_hash.strip().lower()
        for sibling, direction in proof:
            sibling = sibling.strip().lower()
            if direction == "right":
                combined = f"{current}:{sibling}"
            else:
                combined = f"{sibling}:{current}"

            encoded = combined.encode("utf-8")
            if hash_algo == "blake2b":
                current = hashlib.blake2b(encoded).hexdigest()
            else:
                current = hashlib.sha256(encoded).hexdigest()

        return current.lower() == expected_root.strip().lower()

    @staticmethod
    def diff_leaf_hashes(
        source_hashes: List[str], target_hashes: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Compare two sets of leaf hashes to find divergent or missing indices.
        """
        divergences = []
        max_len = max(len(source_hashes), len(target_hashes))
        for idx in range(max_len):
            src = source_hashes[idx] if idx < len(source_hashes) else None
            tgt = target_hashes[idx] if idx < len(target_hashes) else None
            if src != tgt:
                divergences.append(
                    {
                        "index": idx,
                        "source_hash": src,
                        "target_hash": tgt,
                        "type": "MUTATION"
                        if src and tgt
                        else ("MISSING_TARGET" if src else "EXTRA_TARGET"),
                    }
                )
        return divergences
