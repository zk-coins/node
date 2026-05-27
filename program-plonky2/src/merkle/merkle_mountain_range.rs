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

/// Maximum MMR depth used for fixed-shape in-circuit verification. Supports
/// up to 2^(MMR_MAX_DEPTH - 1) leaves. Variable-depth proofs and roots
/// produced by the off-circuit MMR are padded / extended to this depth via
/// [`MerkleMountainRange::root_extended`] and [`MMRProof::extend_to`]
/// before being consumed in-circuit.
///
/// Picked so a single zkCoins node can run for many years of state
/// transitions without exhausting the MMR; the closed test env makes
/// this a free parameter (no on-chain commitment to a specific depth).
pub const MMR_MAX_DEPTH: usize = 32;

/// Inclusion proof for a leaf in an MMR.
///
/// `index` is the leaf's position in the bottom level (the order it was
/// appended). `path` is the sibling hash at each level walking up from the
/// leaf to the level just below the root.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
            computed = if idx.is_multiple_of(2) {
                hash_concat(&computed, sibling)
            } else {
                hash_concat(sibling, &computed)
            };
            idx /= 2;
        }
        computed == expected_root
    }

    /// Pad `self.path` with `ZERO_HASH` siblings to length `target_path_len`.
    /// Used to bring a variable-depth proof from the off-circuit MMR (depth =
    /// `log2(capacity)`) up to the fixed depth that the in-circuit gadget
    /// expects. The padded proof verifies against
    /// [`MerkleMountainRange::root_extended`] at the same target depth.
    pub fn extend_to(mut self, target_path_len: usize) -> Self {
        while self.path.len() < target_path_len {
            self.path.push(ZERO_HASH);
        }
        self
    }
}

/// Append-only fixed-shape padded Merkle tree.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
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
            // Right child index is always in bounds: capacity is a power of two
            // and levels[level-1] has `capacity >> (level-1)` entries — an even
            // number for any level ≥ 1. `2*index+1` is therefore ≤ `len-1`.
            // `.get()` + `.copied().unwrap_or(ZERO_HASH)` collapses the safety
            // fallback into a single uncovered region the host never hits,
            // keeping the algorithm robust against future capacity tweaks.
            let right = self.levels[level - 1]
                .get(2 * index + 1)
                .copied()
                .unwrap_or(ZERO_HASH);
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

    /// Root extended to a fixed `target_path_len`. Computed by walking the
    /// natural [`Self::root`] up through additional levels of
    /// `hash_concat(current, ZERO_HASH)`. Used at the protocol boundary
    /// when handing the history root to a fixed-shape in-circuit verifier:
    /// the verifier needs the root and the proof to agree on a fixed
    /// number of levels, achieved by both extending the root and the proof
    /// path (via [`MMRProof::extend_to`]) to the same target.
    pub fn root_extended(&self, target_path_len: usize) -> HashDigest {
        let mut current = self.root();
        let natural_path_len = self.tree_depth() - 1;
        for _ in natural_path_len..target_path_len {
            current = hash_concat(&current, &ZERO_HASH);
        }
        current
    }

    /// Inclusion proof for the leaf at `index`. Returns `Err` if out of range.
    pub fn get_proof(&self, index: usize) -> Result<MMRProof, &'static str> {
        if index >= self.count {
            return Err("index out of range");
        }
        let mut proof = Vec::with_capacity(self.tree_depth() - 1);
        let mut idx = index;
        for level in 0..(self.tree_depth() - 1) {
            let sibling_index = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            // Same reasoning as in `append`: levels[level].len() is a power of
            // two and `sibling_index` is in `[0, len-1]` for any valid idx.
            // Collapsed into `.get()` so the unreachable bound check shares one
            // region with the success path.
            let sibling = self.levels[level]
                .get(sibling_index)
                .copied()
                .unwrap_or(ZERO_HASH);
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

/// Persist a `MerkleMountainRange` to `path` via bincode. Matches
/// the SP1-era `zkcoins_program::merkle::merkle_mountain_range`
/// helper shape — used by the node's `State::save_to_files` cutover.
pub fn save_mmr(mmr: &MerkleMountainRange, path: &str) -> std::io::Result<()> {
    use std::io::Write;
    let file = std::fs::File::create(path)?;
    let serialized = bincode::serialize(mmr).map_err(std::io::Error::other)?;
    let mut writer = std::io::BufWriter::new(file);
    writer.write_all(&serialized)?;
    Ok(())
}

/// Load a `MerkleMountainRange` from `path` previously written by
/// [`save_mmr`].
pub fn load_mmr(path: &str) -> std::io::Result<MerkleMountainRange> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    bincode::deserialize(&buffer).map_err(std::io::Error::other)
}

#[cfg_attr(coverage_nightly, coverage(off))]
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
    fn default_is_empty_tree() {
        let tree = MerkleMountainRange::default();
        assert_eq!(tree.root(), ZERO_HASH);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn leaf_count_and_get_leaf() {
        let mut tree = MerkleMountainRange::new();
        assert_eq!(tree.leaf_count(), 0);
        assert!(tree.get_leaf(0).is_none());

        let leaf = leaf_of("leaf1");
        tree.append(leaf);
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.get_leaf(0), Some(&leaf));
        assert!(tree.get_leaf(1).is_none());
    }

    #[test]
    fn proof_with_odd_leaf_count_uses_zero_sibling() {
        // 3 leaves → bottom level has 4 slots, last is ZERO_HASH.
        // Proof for index 2 should have a ZERO_HASH sibling at the bottom level.
        let mut tree = MerkleMountainRange::new();
        tree.append(leaf_of("a"));
        tree.append(leaf_of("b"));
        tree.append(leaf_of("c"));
        let proof = tree.get_proof(2).unwrap();
        assert_eq!(proof.path[0], ZERO_HASH);
        assert!(proof.verify(leaf_of("c"), tree.root()));
    }

    #[test]
    fn extend_to_and_root_extended_round_trip() {
        // A 2-leaf MMR has natural path length 1 (one sibling).
        let mut tree = MerkleMountainRange::new();
        tree.append(leaf_of("a"));
        tree.append(leaf_of("b"));
        let proof = tree.get_proof(0).unwrap();
        assert_eq!(proof.path.len(), 1);

        // Extend to MMR_MAX_DEPTH and verify against the extended root.
        let target_len = MMR_MAX_DEPTH - 1;
        let extended_proof = proof.extend_to(target_len);
        let extended_root = tree.root_extended(target_len);
        assert_eq!(extended_proof.path.len(), target_len);
        assert!(extended_proof.verify(leaf_of("a"), extended_root));
    }

    #[test]
    fn root_extended_at_natural_depth_equals_natural_root() {
        let mut tree = MerkleMountainRange::new();
        tree.append(leaf_of("a"));
        tree.append(leaf_of("b"));
        let natural_path_len = tree.tree_depth() - 1;
        assert_eq!(tree.root_extended(natural_path_len), tree.root());
    }

    #[test]
    fn extend_to_idempotent_at_target() {
        let mut tree = MerkleMountainRange::new();
        tree.append(leaf_of("a"));
        let proof = tree.get_proof(0).unwrap();
        let extended = proof.clone().extend_to(MMR_MAX_DEPTH - 1);
        // Already at target — extending again is a no-op.
        let extended_again = extended.clone().extend_to(MMR_MAX_DEPTH - 1);
        assert_eq!(extended, extended_again);
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

    /// `save_mmr` + `load_mmr` round-trip preserves the MMR's leaf
    /// set + root + inclusion proofs.
    #[test]
    fn save_load_round_trip() {
        let mut mmr = MerkleMountainRange::new();
        for i in 0..6 {
            mmr.append(leaf_of(&format!("leaf_{i}")));
        }
        let original_root = mmr.root();

        let path = std::env::temp_dir().join("zkcoins-plonky2-mmr-roundtrip.bin");
        let path_str = path.to_str().unwrap();
        save_mmr(&mmr, path_str).expect("save");
        let loaded = load_mmr(path_str).expect("load");
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded.root(), original_root);
        let proof = loaded.get_proof(0).expect("proof");
        assert!(proof.verify(loaded.get_leaf(0).copied().unwrap(), original_root));
    }

    /// Build-time assertion: `load_mmr` propagates I/O errors when
    /// the path doesn't exist.
    #[test]
    fn load_mmr_missing_path_errors() {
        let path = std::env::temp_dir().join("zkcoins-plonky2-mmr-does-not-exist.bin");
        std::fs::remove_file(&path).ok();
        let result = load_mmr(path.to_str().unwrap());
        assert!(result.is_err());
    }
}
