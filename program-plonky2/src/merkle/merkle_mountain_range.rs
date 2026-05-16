//! Merkle mountain range, Poseidon-Goldilocks variant.
//!
//! Mirrors the SHA256 MMR in `program/src/merkle/merkle_mountain_range.rs`
//! algorithmically; only the hash function and the digest type change.
//!
//! Structurally this is a fixed-shape padded Merkle tree (not a classical
//! MMR). The name is historical from the SP1 codebase. Capacity is a power
//! of two starting at 2 and doubling on demand; missing leaves are padded
//! with `ZERO_HASH`. Internal nodes are `hash_concat(left, right)`; missing
//! right siblings (at the boundary of an odd-leaf level) use `ZERO_HASH`.
//!
//! Persistence helpers (file save/load) are intentionally absent for now —
//! the host-side wiring will pick a serialisation when needed.

use crate::hash::{hash_concat, HashDigest, ZERO_HASH};

pub type MerklePath = Vec<HashDigest>;

/// Inclusion proof for a leaf in an MMR.
///
/// `index` is the leaf's position in the bottom level (the order it was
/// appended). `path` is the sibling hash at each level walking up from the
/// leaf to the level just below the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MMRProof {
    pub index: u32,
    pub path: MerklePath,
}

impl MMRProof {
    pub fn new(path: MerklePath, index: u32) -> Self {
        MMRProof { index, path }
    }

    /// Returns true if `leaf` hashes up through `self.path` to `expected_root`.
    pub fn verify(&self, leaf: HashDigest, expected_root: HashDigest) -> bool {
        let mut computed = leaf;
        let mut idx = self.index;
        for sibling in &self.path {
            computed = if idx % 2 == 0 {
                hash_concat(&computed, sibling)
            } else {
                hash_concat(sibling, &computed)
            };
            idx /= 2;
        }
        computed == expected_root
    }
}

/// Append-only fixed-shape padded Merkle tree.
#[derive(Debug)]
pub struct MerkleMountainRange {
    count: usize,
    capacity: usize,
    levels: Vec<Vec<HashDigest>>,
}

impl Default for MerkleMountainRange {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleMountainRange {
    /// Create an empty tree. Initial capacity is 2 (so a single leaf is paired
    /// with `ZERO_HASH` rather than being treated specially).
    pub fn new() -> Self {
        let capacity = 2;
        let mut levels = Vec::new();
        levels.push(vec![ZERO_HASH; capacity]);
        let depth = (capacity as f64).log2() as usize + 1;
        for level in 1..depth {
            levels.push(vec![ZERO_HASH; capacity >> level]);
        }
        Self {
            count: 0,
            capacity,
            levels,
        }
    }

    fn tree_depth(&self) -> usize {
        self.levels.len()
    }

    /// Append a leaf. Updates only the branch from the new leaf up to the root.
    /// Doubles capacity if the tree is full.
    pub fn append(&mut self, leaf: HashDigest) {
        if self.count == self.capacity {
            self.expand();
        }
        self.levels[0][self.count] = leaf;
        let mut index = self.count;
        for level in 1..self.tree_depth() {
            index /= 2;
            let left = self.levels[level - 1][2 * index];
            let right = if 2 * index + 1 < self.levels[level - 1].len() {
                self.levels[level - 1][2 * index + 1]
            } else {
                ZERO_HASH
            };
            self.levels[level][index] = hash_concat(&left, &right);
        }
        self.count += 1;
    }

    fn expand(&mut self) {
        let old_capacity = self.capacity;
        let new_capacity = old_capacity * 2;
        let new_depth = (new_capacity as f64).log2() as usize + 1;

        self.levels[0].resize(new_capacity, ZERO_HASH);

        for level in 1..self.tree_depth() {
            self.levels[level].resize(new_capacity >> level, ZERO_HASH);
        }

        for level in self.tree_depth()..new_depth {
            self.levels.push(vec![ZERO_HASH; new_capacity >> level]);
        }

        self.capacity = new_capacity;
    }

    /// Current root. `ZERO_HASH` for an empty tree.
    pub fn root(&self) -> HashDigest {
        if self.count == 0 {
            ZERO_HASH
        } else {
            self.levels[self.tree_depth() - 1][0]
        }
    }

    /// Inclusion proof for the leaf at `index`. Returns `Err` if out of range.
    pub fn get_proof(&self, index: usize) -> Result<MMRProof, &'static str> {
        if index >= self.count {
            return Err("index out of range");
        }
        let mut proof = Vec::with_capacity(self.tree_depth() - 1);
        let mut idx = index;
        for level in 0..(self.tree_depth() - 1) {
            let sibling_index = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = if sibling_index < self.levels[level].len() {
                self.levels[level][sibling_index]
            } else {
                ZERO_HASH
            };
            proof.push(sibling);
            idx /= 2;
        }
        Ok(MMRProof {
            index: index as u32,
            path: proof,
        })
    }

    pub fn leaf_count(&self) -> usize {
        self.count
    }

    pub fn get_leaf(&self, index: usize) -> Option<&HashDigest> {
        if index >= self.count {
            None
        } else {
            Some(&self.levels[0][index])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_bytes;

    fn leaf_of(s: &str) -> HashDigest {
        hash_bytes(s.as_bytes())
    }

    #[test]
    fn empty_tree_root_is_zero() {
        let tree = MerkleMountainRange::new();
        assert_eq!(tree.root(), ZERO_HASH);
    }

    #[test]
    fn single_leaf_pairs_with_zero() {
        let mut tree = MerkleMountainRange::new();
        let leaf = leaf_of("leaf1");
        tree.append(leaf);
        let expected_root = hash_concat(&leaf, &ZERO_HASH);
        assert_eq!(tree.root(), expected_root);

        let proof = tree.get_proof(0).expect("proof should exist");
        assert_eq!(proof.path.len(), 1);
        assert_eq!(proof.path[0], ZERO_HASH);
        assert!(proof.verify(leaf, tree.root()));
    }

    #[test]
    fn two_leaves_hash_directly() {
        let mut tree = MerkleMountainRange::new();
        let leaf1 = leaf_of("leaf1");
        let leaf2 = leaf_of("leaf2");
        tree.append(leaf1);
        tree.append(leaf2);
        let expected_root = hash_concat(&leaf1, &leaf2);
        assert_eq!(tree.root(), expected_root);

        let proof1 = tree.get_proof(0).expect("proof should exist");
        let proof2 = tree.get_proof(1).expect("proof should exist");
        assert!(proof1.verify(leaf1, tree.root()));
        assert!(proof2.verify(leaf2, tree.root()));
    }

    #[test]
    fn multiple_leaves_round_trip() {
        let mut tree = MerkleMountainRange::new();
        let leaves: Vec<HashDigest> = (1..=5).map(|i| leaf_of(&format!("leaf{i}"))).collect();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.get_proof(i).expect("proof should exist");
            assert!(proof.verify(*leaf, root));
        }
    }

    #[test]
    fn proofs_stay_consistent_as_tree_grows() {
        let mut tree = MerkleMountainRange::new();
        let inputs = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        let mut leaves = Vec::new();
        for (i, s) in inputs.iter().enumerate() {
            let leaf = leaf_of(s);
            tree.append(leaf);
            leaves.push(leaf);
            let current_root = tree.root();
            for (j, &leaf_val) in leaves.iter().enumerate() {
                let proof = tree.get_proof(j).expect("proof should exist");
                assert!(
                    proof.verify(leaf_val, current_root),
                    "proof for leaf index {j} failed at iteration {i}"
                );
            }
        }
    }

    #[test]
    fn get_proof_out_of_bounds() {
        let mut tree = MerkleMountainRange::new();
        tree.append(leaf_of("leaf1"));
        assert!(tree.get_proof(1).is_err());
    }

    #[test]
    fn tampered_proof_fails_verification() {
        let mut tree = MerkleMountainRange::new();
        let leaf = leaf_of("leaf1");
        tree.append(leaf);
        let mut proof = tree.get_proof(0).expect("proof should exist");
        // Flip a field element in the sibling to invalidate the path.
        proof.path[0] = hash_concat(&proof.path[0], &proof.path[0]);
        assert!(!proof.verify(leaf, tree.root()));
    }

    #[test]
    fn capacity_doubles_on_demand() {
        let mut tree = MerkleMountainRange::new();
        tree.append(leaf_of("leaf1"));
        tree.append(leaf_of("leaf2"));
        tree.append(leaf_of("leaf3"));
        assert_eq!(tree.count, 3);
        assert_eq!(tree.capacity, 4);

        let root = tree.root();
        for i in 0..tree.count {
            let proof = tree.get_proof(i).expect("proof should exist");
            let leaf = tree.levels[0][i];
            assert!(proof.verify(leaf, root));
        }
    }
}
