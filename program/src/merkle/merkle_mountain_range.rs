use serde::{Deserialize, Serialize};
use std::io;

use super::{hash_concat, HashDigest, ZERO_HASH};

pub type MerklePath = Vec<HashDigest>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct MMRProof {
    pub index: u32,
    pub path: MerklePath,
}

impl MMRProof {
    pub fn new(path: MerklePath, index: u32) -> Self {
        MMRProof { index, path }
    }

    // TODO use this in the client?
    /// Verify an inclusion proof.
    ///
    /// Given a leaf and an expected root, this function returns true if the proof is valid.
    pub fn verify(&self, leaf: HashDigest, expected_root: HashDigest) -> bool {
        let mut computed = leaf;
        let mut idx = self.index;
        for sibling in &self.path {
            if idx % 2 == 0 {
                computed = hash_concat(&computed, sibling);
            } else {
                computed = hash_concat(sibling, &computed);
            }
            idx /= 2;
        }
        computed == expected_root
    }
}

/// An append-only Merkle tree that updates incrementally.
///
/// The tree is represented as a complete binary tree with a fixed capacity (a power of two)
/// and padded with 32-byte zeros for missing leaves. When appending a new leaf, only the branch
/// from that leaf to the root is updated. If the number of leaves reaches the current capacity,
/// the capacity is doubled (recomputing the new portions of the tree).
#[derive(Debug, Serialize, Deserialize)]
pub struct MerkleMountainRange {
    /// Number of leaves appended so far.
    count: usize,
    /// Current capacity (number of leaves available in the bottom level).
    capacity: usize,
    /// The tree stored as levels, where level 0 is the leaves (length == capacity) and each higher
    /// level has half as many nodes as the level below. The root is at the highest level.
    levels: Vec<Vec<HashDigest>>,
}

impl Default for MerkleMountainRange {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleMountainRange {
    /// Create a new, empty Merkle tree.
    ///
    /// We set an initial capacity of 2 so that even a single leaf is paired with a zero.
    pub fn new() -> Self {
        let capacity = 2;
        let mut levels = Vec::new();
        // Level 0 (leaves): capacity elements (all zeros initially).
        levels.push(vec![ZERO_HASH; capacity]);
        // Number of levels is log2(capacity) + 1.
        let depth = (capacity as f64).log2() as usize + 1;
        // Create the remaining levels, each initialized to zeros.
        for level in 1..depth {
            levels.push(vec![ZERO_HASH; capacity >> level]);
        }
        Self {
            count: 0,
            capacity,
            levels,
        }
    }

    /// Return the depth (number of levels) in the tree.
    fn tree_depth(&self) -> usize {
        self.levels.len()
    }

    /// Append a new leaf to the Merkle tree.
    ///
    /// This function updates only the branch from the new leaf to the root.
    pub fn append(&mut self, leaf: HashDigest) {
        // Expand capacity if needed.
        if self.count == self.capacity {
            self.expand();
        }
        // Place the new leaf into the bottom level.
        self.levels[0][self.count] = leaf;
        // Update parent nodes along the branch.
        let mut index = self.count;
        for level in 1..self.tree_depth() {
            index /= 2;
            let left = self.levels[level - 1][2 * index];
            // The right child is either the next element or, if not available, 32 zeros.
            let right = if 2 * index + 1 < self.levels[level - 1].len() {
                self.levels[level - 1][2 * index + 1]
            } else {
                ZERO_HASH
            };
            self.levels[level][index] = hash_concat(&left, &right);
        }
        self.count += 1;
    }

    /// Expand the tree by doubling its capacity.
    ///
    /// This only expands the storage structure without recomputing nodes,
    /// as node updates are already handled by the append method.
    fn expand(&mut self) {
        let old_capacity = self.capacity;
        let new_capacity = old_capacity * 2;
        let new_depth = (new_capacity as f64).log2() as usize + 1;

        // Resize level 0 (leaves)
        self.levels[0].resize(new_capacity, ZERO_HASH);

        // For each existing higher level, resize appropriately
        for level in 1..self.tree_depth() {
            self.levels[level].resize(new_capacity >> level, ZERO_HASH);
        }

        // Add any new levels that are needed
        for level in self.tree_depth()..new_depth {
            self.levels.push(vec![ZERO_HASH; new_capacity >> level]);
        }

        self.capacity = new_capacity;
    }

    /// Return the current Merkle root.
    ///
    /// For an empty tree, the root is defined as 32 bytes of zero.
    pub fn root(&self) -> HashDigest {
        if self.count == 0 {
            ZERO_HASH
        } else {
            // The root is stored in the highest level at index 0.
            self.levels[self.tree_depth() - 1][0]
        }
    }

    /// Generate an inclusion proof for the leaf at the given index.
    ///
    /// The proof is a vector of sibling hashes at each level along the branch from the leaf
    /// up to (but not including) the root.
    ///
    /// Returns None if the index is out-of-bounds.
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

    /// Save the Merkle tree to a file.
    ///
    /// This serializes the tree structure using bincode and writes it to the specified path.
    /// Returns Ok(()) on success, or an IO error on failure.
    pub fn save_to_file(&self, path: &str) -> io::Result<()> {
        let encoded =
            bincode::serialize(self).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        std::fs::write(path, encoded)
    }

    /// Load a Merkle tree from a file.
    ///
    /// This reads and deserializes a tree from the specified path.
    /// Returns the loaded tree on success, or an IO error on failure.
    pub fn load_from_file(path: &str) -> io::Result<Self> {
        let data = std::fs::read(path)?;
        bincode::deserialize(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Return the current number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.count
    }

    /// Return a reference to the leaf at the given index.
    /// Returns None if the index is out of bounds.
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
    use sha2::{Digest, Sha256};

    use super::*;

    /// Helper to convert a string into a 32-byte hash using SHA256.
    fn hash_str(s: &str) -> HashDigest {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    #[test]
    fn test_empty_tree_root() {
        let tree = MerkleMountainRange::new();
        // For an empty tree, the root is defined as 32 bytes of zero.
        assert_eq!(tree.root(), ZERO_HASH);
    }

    #[test]
    fn test_single_leaf() {
        let mut tree = MerkleMountainRange::new();
        let leaf = hash_str("leaf1");
        tree.append(leaf);
        // With one leaf, the bottom level is [leaf, 0],
        // so the expected root is hash(leaf || 0).
        let expected_root = hash_concat(&leaf, &ZERO_HASH);
        assert_eq!(tree.root(), expected_root);

        // The inclusion proof for the only leaf should contain a single sibling ([0;32]).
        let proof = tree.get_proof(0).expect("proof should exist");
        assert_eq!(proof.path.len(), 1);
        assert_eq!(proof.path[0], ZERO_HASH);
        assert!(proof.verify(leaf, tree.root()));
    }

    #[test]
    fn test_two_leaves() {
        let mut tree = MerkleMountainRange::new();
        let leaf1 = hash_str("leaf1");
        let leaf2 = hash_str("leaf2");
        tree.append(leaf1);
        tree.append(leaf2);
        // For two leaves the expected root is hash(leaf1 || leaf2).
        let expected_root = hash_concat(&leaf1, &leaf2);
        assert_eq!(tree.root(), expected_root);

        // Verify inclusion proofs for both leaves.
        let proof1 = tree.get_proof(0).expect("proof should exist");
        let proof2 = tree.get_proof(1).expect("proof should exist");
        assert!(proof1.verify(leaf1, tree.root()));
        assert!(proof2.verify(leaf2, tree.root()));
    }

    #[test]
    fn test_multiple_leaves() {
        let mut tree = MerkleMountainRange::new();
        let leaves: Vec<HashDigest> = vec![
            hash_str("leaf1"),
            hash_str("leaf2"),
            hash_str("leaf3"),
            hash_str("leaf4"),
            hash_str("leaf5"),
        ];

        for leaf in &leaves {
            tree.append(*leaf);
        }
        let root = tree.root();
        // Check that inclusion proofs verify for all leaves.
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.get_proof(i).expect("proof should exist");
            assert!(proof.verify(*leaf, root));
        }
    }

    #[test]
    fn test_append_and_proof_consistency() {
        let mut tree = MerkleMountainRange::new();
        // Append leaves one by one and check that proofs verify for all leaves so far.
        let inputs = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        let mut leaves = Vec::new();
        for (i, s) in inputs.iter().enumerate() {
            let leaf = hash_str(s);
            tree.append(leaf);
            leaves.push(leaf);
            let current_root = tree.root();
            for (j, &leaf_val) in leaves.iter().enumerate() {
                let proof = tree.get_proof(j).expect("proof should exist");
                assert!(
                    proof.verify(leaf_val, current_root),
                    "Proof for leaf index {} failed at iteration {}",
                    j,
                    i
                );
            }
        }
    }

    #[test]
    fn test_get_proof_out_of_bounds() {
        let mut tree = MerkleMountainRange::new();
        let leaf = hash_str("leaf1");
        tree.append(leaf);
        // Requesting a proof for an index outside the current count should return None.
        assert!(tree.get_proof(1).is_err());
    }

    #[test]
    fn test_invalid_proof() {
        let mut tree = MerkleMountainRange::new();
        let leaf = hash_str("leaf1");
        tree.append(leaf);
        let mut proof = tree.get_proof(0).expect("proof should exist");
        // Tamper with the proof: flip one bit in the first byte.
        proof.path[0][0] ^= 0xff;
        // The verification should now fail.
        assert!(!proof.verify(leaf, tree.root()));
    }

    #[test]
    fn test_capacity_expansion() {
        let mut tree = MerkleMountainRange::new();
        // Initially, the capacity is 2.
        let leaf1 = hash_str("leaf1");
        let leaf2 = hash_str("leaf2");
        tree.append(leaf1);
        tree.append(leaf2);
        // Append one more leaf to force expansion.
        let leaf3 = hash_str("leaf3");
        tree.append(leaf3);
        // After expansion, the count should be 3 and the capacity should have doubled to 4.
        assert_eq!(tree.count, 3);
        assert_eq!(tree.capacity, 4);

        // Verify that inclusion proofs for all leaves are still valid.
        let root = tree.root();
        for i in 0..tree.count {
            let proof = tree.get_proof(i).expect("proof should exist");
            let leaf = tree.levels[0][i];
            assert!(proof.verify(leaf, root));
        }
    }

    #[test]
    fn test_serialization() {
        let mut tree = MerkleMountainRange::new();
        let leaves = vec![hash_str("one"), hash_str("two"), hash_str("three")];

        for leaf in &leaves {
            tree.append(*leaf);
        }

        // Serialize to bytes using bincode
        let encoded = bincode::serialize(&tree).expect("Failed to serialize");

        // Deserialize from bytes
        let loaded_tree: MerkleMountainRange =
            bincode::deserialize(&encoded).expect("Failed to deserialize");

        // Verify trees are identical
        assert_eq!(tree.count, loaded_tree.count);
        assert_eq!(tree.capacity, loaded_tree.capacity);
        assert_eq!(tree.root(), loaded_tree.root());

        // Verify all leaves
        for i in 0..tree.count {
            assert_eq!(tree.levels[0][i], loaded_tree.levels[0][i]);
            let proof = tree.get_proof(i).unwrap();
            let loaded_proof = loaded_tree.get_proof(i).unwrap();
            assert_eq!(proof, loaded_proof);
        }
    }

    #[test]
    fn test_file_saving_loading() {
        let mut tree = MerkleMountainRange::new();
        let leaves = vec![
            hash_str("file1"),
            hash_str("file2"),
            hash_str("file3"),
            hash_str("file4"),
        ];

        for leaf in &leaves {
            tree.append(*leaf);
        }

        // Create a temporary file path
        let temp_path = "test_merkle_tree.bin";

        // Save to file
        tree.save_to_file(temp_path)
            .expect("Failed to save to file");

        // Load from file
        let loaded_tree =
            MerkleMountainRange::load_from_file(temp_path).expect("Failed to load from file");

        // Clean up
        std::fs::remove_file(temp_path).ok();

        // Verify trees are identical
        assert_eq!(tree.count, loaded_tree.count);
        assert_eq!(tree.capacity, loaded_tree.capacity);
        assert_eq!(tree.root(), loaded_tree.root());

        // Verify all leaves
        for i in 0..tree.count {
            assert_eq!(tree.levels[0][i], loaded_tree.levels[0][i]);
        }
    }
}
