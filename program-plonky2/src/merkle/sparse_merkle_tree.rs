//! Sparse Merkle tree, Poseidon-Goldilocks variant.
//!
//! Mirrors the SHA256 SMT in `program/src/merkle/sparse_merkle_tree.rs`
//! algorithmically. Compared to the legacy compressed-path SP1 SMT, this
//! port uses **uncompressed paths**: every inclusion / non-inclusion
//! proof always carries exactly [`TREE_DEPTH`] sibling hashes, regardless
//! of how sparsely the tree is populated. Empty subtrees contribute
//! `DEFAULT_HASHES[level + 1]` siblings.
//!
//! ## Why uncompressed
//!
//! The compressed-path variant short-circuits a single-leaf subtree at
//! level *K* by treating its level-*K* root as the leaf hash itself,
//! producing a proof of length *K* ≤ 256. Plonky2 cyclic recursion
//! requires the verifier circuit to have a **fixed shape** — the
//! `circuit_digest` must be stable across builds — so a verifier that
//! consumes variable-length proofs would produce a different
//! `circuit_digest` per proof length and the recursion chain breaks.
//!
//! Storing always-`TREE_DEPTH` siblings makes the proof a constant-size
//! object and lets the in-circuit gadget hash up exactly 256 levels
//! every time. The trade-off is on-the-wire proof size: 256 × 32 B =
//! 8 KiB per proof, vs. typically tens of bytes for compressed proofs
//! in a sparsely-populated tree. For zkCoins' state-transition
//! workflow that is dwarfed by the recursive ZK proof itself.
//!
//! ## Layout
//!
//! - Keys: `[u8; 32]`, MSB-first bit indexing (unchanged).
//! - Values / node hashes: [`HashDigest`] (`HashOut<F>`, 4 Goldilocks elts).
//! - `hash_concat(left, right)` is Poseidon two-to-one.
//! - `DEFAULT_HASHES[depth] = empty-leaf` (domain-separated seed at
//!   depth = `TREE_DEPTH`); higher levels derived by self-concatenation,
//!   computed once via `LazyLock`.
//! - Internal `SparseMerkleTree::nodes` stores **uncompressed** parent
//!   hashes at every level: `(level, parent_key) → hash`. Levels with
//!   no real children are absent and the lookup falls back to
//!   `DEFAULT_HASHES[level]`.
//!
//! Persistence helpers (file save/load) are intentionally absent for now —
//! the host-side wiring will pick a serialisation when needed.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::hash::{digest_from_bytes, hash_bytes, hash_concat, HashDigest};

/// Tree depth. For a 256-bit key space, depth is 256.
pub const TREE_DEPTH: usize = 256;

/// Domain-separator for the empty-leaf seed at `DEFAULT_HASHES[TREE_DEPTH]`.
///
/// Picking the all-zero `HashDigest` here would collide structurally with
/// Poseidon's behaviour on zero input: `hash_no_pad([F::ZERO; n])` and
/// `two_to_one(ZERO, ZERO)` both permute the all-zero state and produce the
/// same digest. Any protocol-level hash of a zero-derived value (e.g. a key
/// derived from the input `0u32`) would then accidentally equal
/// `DEFAULT_HASHES[TREE_DEPTH - 1]`, silently corrupting the non-inclusion
/// proof chase loop. The domain-separator below breaks that collision.
const EMPTY_LEAF_TAG: &[u8] = b"zkcoins:smt:empty-leaf:v1";

/// Per-level default hashes of an empty subtree. `DEFAULT_HASHES[depth]` is
/// the bottom (empty-leaf) seed (a fixed, non-zero, domain-separated value);
/// each level above is `hash_concat` of two copies of the level below.
/// Computed exactly once on first access.
pub static DEFAULT_HASHES: LazyLock<Vec<HashDigest>> = LazyLock::new(|| {
    let depth = TREE_DEPTH;
    let empty_leaf = hash_bytes(EMPTY_LEAF_TAG);
    let mut default_hashes = vec![empty_leaf; depth + 1];
    for level in (0..depth).rev() {
        default_hashes[level] = hash_concat(&default_hashes[level + 1], &default_hashes[level + 1]);
    }
    default_hashes
});

/// Returns the bit at index `i` (0 = most-significant) in a 256-bit key.
pub fn get_bit(key: &[u8; 32], i: usize) -> bool {
    let byte_index = i / 8;
    let bit_index = 7 - (i % 8);
    ((key[byte_index] >> bit_index) & 1) == 1
}

/// Returns a new key where only the first `bits` are kept; the rest are zeroed.
fn trim_key(key: &[u8; 32], bits: usize) -> [u8; 32] {
    if bits == 0 {
        return [0; 32];
    }
    let mut new_key = *key;
    let full_bytes = bits / 8;
    let remaining_bits = bits % 8;
    if full_bytes < 32 {
        if remaining_bits != 0 {
            new_key[full_bytes] &= 0xFF << (8 - remaining_bits);
            new_key[(full_bytes + 1)..].fill(0);
        } else {
            new_key[full_bytes..].fill(0);
        }
    }
    new_key
}

/// Computes the key for the child node given its parent's key, the branch
/// (false for left, true for right), and the parent's level.
fn child_key(parent_key: &[u8; 32], branch: bool, level: usize) -> [u8; 32] {
    let mut child = *parent_key;
    if branch {
        let byte_index = level / 8;
        let bit_index = 7 - (level % 8);
        child[byte_index] |= 1 << bit_index;
    }
    trim_key(&child, level + 1)
}

/// Leaf hash = `Poseidon(value, key_as_digest)`. Used wherever a `(key, value)`
/// pair needs to be folded into a single 4-element digest before being hashed
/// up the path.
fn leaf_hash(value: &HashDigest, key: &[u8; 32]) -> HashDigest {
    hash_concat(value, &digest_from_bytes(key))
}

/// Hash up `start` through `siblings` (indexed by tree level, `siblings[level]`
/// is the sibling at that level's parent node) using `key`'s MSB-first bits
/// for swap direction. Walks from the deepest level (level `TREE_DEPTH - 1`,
/// where the leaf's parent lives) up to the root.
///
/// Returns the root produced by this walk. Used by every proof verify path
/// and by [`SparseMerkleTree::insert`]'s root computation.
fn hash_up_full_path(start: HashDigest, key: &[u8; 32], siblings: &[HashDigest]) -> HashDigest {
    debug_assert_eq!(siblings.len(), TREE_DEPTH);
    let mut current = start;
    for level in (0..TREE_DEPTH).rev() {
        let branch = get_bit(key, level);
        let sibling = siblings[level];
        current = if branch {
            hash_concat(&sibling, &current)
        } else {
            hash_concat(&current, &sibling)
        };
    }
    current
}

/// Inclusion proof: the key, plus exactly [`TREE_DEPTH`] sibling hashes from
/// the leaf's parent down to the root.
///
/// `siblings[level]` is the sibling at that level's parent node (i.e. the
/// other child of the node at `(level, trim_key(key, level))`). Siblings at
/// levels where the subtree is empty equal `DEFAULT_HASHES[level + 1]`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InclusionProof {
    pub key: [u8; 32],
    pub siblings: Vec<HashDigest>,
}

impl InclusionProof {
    /// Returns true if the proof reconstructs to `expected_root` from `leaf`.
    pub fn verify(&self, leaf: HashDigest, expected_root: HashDigest) -> bool {
        if self.siblings.len() != TREE_DEPTH {
            return false;
        }
        let start = leaf_hash(&leaf, &self.key);
        hash_up_full_path(start, &self.key, &self.siblings) == expected_root
    }
}

/// Non-inclusion proof: witnesses that `key` is absent from the tree.
///
/// The proof walks from `DEFAULT_HASHES[TREE_DEPTH]` (the empty-leaf seed) up
/// through `siblings` and verifies that the resulting root equals `root`. If
/// the slot at `key`'s depth-`TREE_DEPTH` position were occupied, the walk
/// would produce a different root.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NonInclusionProof {
    pub key: [u8; 32],
    pub root: HashDigest,
    pub siblings: Vec<HashDigest>,
}

impl NonInclusionProof {
    pub fn verify(&self) -> bool {
        if self.siblings.len() != TREE_DEPTH {
            return false;
        }
        let start = DEFAULT_HASHES[TREE_DEPTH];
        hash_up_full_path(start, &self.key, &self.siblings) == self.root
    }

    /// Returns the new root after inserting `leaf` at `self.key`. Does not
    /// verify the proof itself; pair with [`Self::verify_and_insert`] when
    /// validation is required.
    pub fn insert(&self, leaf: HashDigest) -> HashDigest {
        let start = leaf_hash(&leaf, &self.key);
        hash_up_full_path(start, &self.key, &self.siblings)
    }

    pub fn verify_and_insert(&self, leaf: HashDigest) -> Result<HashDigest, &'static str> {
        if !self.verify() {
            return Err("Invalid non-inclusion proof");
        }
        Ok(self.insert(leaf))
    }
}

/// Sparse Merkle tree: stores all internal nodes that differ from
/// the level-default. Insert/proof code hashes through every level.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SparseMerkleTree {
    nodes: HashMap<(usize, [u8; 32]), HashDigest>,
    leaf_values: HashMap<[u8; 32], HashDigest>,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        SparseMerkleTree {
            nodes: HashMap::new(),
            leaf_values: HashMap::new(),
        }
    }

    /// Sibling hash at level `parent_level + 1` of the node opposite the
    /// branch taken by `key`'s bit at `parent_level`. Falls back to
    /// `DEFAULT_HASHES[level + 1]` for empty subtrees.
    fn sibling_at(&self, key: &[u8; 32], parent_level: usize) -> HashDigest {
        let branch = get_bit(key, parent_level);
        let parent_key = trim_key(key, parent_level);
        let sibling_key = child_key(&parent_key, !branch, parent_level);
        self.nodes
            .get(&(parent_level + 1, sibling_key))
            .cloned()
            .unwrap_or(DEFAULT_HASHES[parent_level + 1])
    }

    /// Inserts `value` at `key`. Idempotent for identical re-insertions;
    /// errors on conflicting re-insertion.
    ///
    /// Updates exactly one branch from `key`'s leaf at depth `TREE_DEPTH`
    /// up to the root, recomputing each parent's hash unconditionally —
    /// the uncompressed scheme means a singleton subtree's level-K root
    /// is NOT `leaf_hash` itself but the result of hashing the leaf with
    /// `TREE_DEPTH - K` levels of default siblings.
    pub fn insert(&mut self, key: [u8; 32], value: HashDigest) -> Result<(), &'static str> {
        if self.leaf_values.contains_key(&key) {
            return if self.leaf_values.get(&key) == Some(&value) {
                Ok(())
            } else {
                Err("Key already exists in the tree with different value")
            };
        }
        self.leaf_values.insert(key, value);

        let leaf_h = leaf_hash(&value, &key);
        self.nodes.insert((TREE_DEPTH, key), leaf_h);

        let mut current_hash = leaf_h;
        for level in (0..TREE_DEPTH).rev() {
            let branch = get_bit(&key, level);
            let parent_key = trim_key(&key, level);
            let sibling = self.sibling_at(&key, level);
            current_hash = if branch {
                hash_concat(&sibling, &current_hash)
            } else {
                hash_concat(&current_hash, &sibling)
            };
            self.nodes.insert((level, parent_key), current_hash);
        }
        Ok(())
    }

    pub fn root(&self) -> HashDigest {
        self.nodes
            .get(&(0, [0; 32]))
            .cloned()
            .unwrap_or(DEFAULT_HASHES[0])
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<HashDigest> {
        self.leaf_values.get(key).cloned()
    }

    /// 256 siblings along `key`'s branch, in `siblings[level]` order
    /// (`level` is the parent's level, sibling lives at `level + 1`).
    fn collect_path_siblings(&self, key: &[u8; 32]) -> Vec<HashDigest> {
        (0..TREE_DEPTH).map(|l| self.sibling_at(key, l)).collect()
    }

    pub fn generate_inclusion_proof(
        &self,
        key: &[u8; 32],
    ) -> Result<(InclusionProof, HashDigest), &'static str> {
        if !self.nodes.contains_key(&(TREE_DEPTH, *key)) {
            return Err("Key does not exist in the tree");
        }
        let value = self.get(key).unwrap();
        let siblings = self.collect_path_siblings(key);
        Ok((
            InclusionProof {
                key: *key,
                siblings,
            },
            value,
        ))
    }

    pub fn generate_non_inclusion_proof(
        &self,
        key: [u8; 32],
    ) -> Result<NonInclusionProof, &'static str> {
        if self.nodes.contains_key(&(TREE_DEPTH, key)) {
            return Err("Leaf exists in the tree");
        }
        let siblings = self.collect_path_siblings(&key);
        Ok(NonInclusionProof {
            key,
            root: self.root(),
            siblings,
        })
    }
}

/// Persist a `SparseMerkleTree` to `path` via bincode. Matches the
/// SP1-era `zkcoins_program::merkle::sparse_merkle_tree::save_merkle_tree`
/// shape — used by the node's `State::save_to_files` cutover.
pub fn save_merkle_tree(tree: &SparseMerkleTree, path: &str) -> std::io::Result<()> {
    use std::io::Write;
    let file = std::fs::File::create(path)?;
    let serialized = bincode::serialize(tree).map_err(std::io::Error::other)?;
    let mut writer = std::io::BufWriter::new(file);
    writer.write_all(&serialized)?;
    Ok(())
}

/// Load a `SparseMerkleTree` from `path` previously written by
/// [`save_merkle_tree`].
pub fn load_merkle_tree(path: &str) -> std::io::Result<SparseMerkleTree> {
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

    /// 50 random-ish 256-bit keys for soak testing the tree.
    /// Generated deterministically from indices so the test corpus is
    /// reproducible without copy-pasting 50 array literals.
    fn sample_keys() -> Vec<[u8; 32]> {
        (0..50_u32)
            .map(|i| {
                let h = hash_bytes(&i.to_le_bytes());
                let mut out = [0u8; 32];
                for (j, e) in h.elements.iter().enumerate() {
                    out[j * 8..(j + 1) * 8].copy_from_slice(&e.0.to_be_bytes());
                }
                out
            })
            .collect()
    }

    fn sample_value(seed: u64) -> HashDigest {
        hash_bytes(&seed.to_le_bytes())
    }

    #[test]
    fn test_verify_and_insert() {
        let mut tree = SparseMerkleTree::new();
        let value = sample_value(42);
        for key in sample_keys() {
            let non_inclusion = tree.generate_non_inclusion_proof(key).unwrap();
            assert!(tree.insert(key, value).is_ok());
            assert_eq!(
                tree.root(),
                non_inclusion.verify_and_insert(value).unwrap(),
                "Roots deviate"
            );
        }
    }

    #[test]
    fn test_verify_and_insert_sibling() {
        let mut tree = SparseMerkleTree::new();
        let value = sample_value(42);
        for key in sample_keys() {
            let mut sibling_key = key;
            sibling_key[31] ^= 1;

            assert!(tree.insert(sibling_key, value).is_ok());

            let non_inclusion = tree.generate_non_inclusion_proof(key).unwrap();
            assert!(tree.insert(key, value).is_ok());

            assert_eq!(
                tree.root(),
                non_inclusion.verify_and_insert(value).unwrap(),
                "Roots deviate"
            );
        }
    }

    #[test]
    fn test_insert_new_key() {
        let mut tree = SparseMerkleTree::new();
        let value = sample_value(42);
        for key in sample_keys() {
            assert!(tree.insert(key, value).is_ok());
            assert!(tree.nodes.contains_key(&(TREE_DEPTH, key)));
        }
    }

    #[test]
    fn test_insert_existing_key() {
        let mut tree = SparseMerkleTree::new();
        let value = sample_value(42);
        let other = sample_value(99);
        for key in sample_keys() {
            assert!(tree.insert(key, value).is_ok());
            assert!(tree.insert(key, other).is_err());
            let leaf_h = leaf_hash(&value, &key);
            assert_eq!(tree.nodes.get(&(TREE_DEPTH, key)), Some(&leaf_h));
        }
    }

    #[test]
    fn test_root_changes_after_insert() {
        let mut tree = SparseMerkleTree::new();
        let value = sample_value(42);
        for key in sample_keys() {
            let initial_root = tree.root();
            assert!(tree.insert(key, value).is_ok());
            assert_ne!(tree.root(), initial_root);
        }
    }

    #[test]
    fn test_multiple_inserts() {
        let mut tree = SparseMerkleTree::new();

        for (i, key) in sample_keys().into_iter().enumerate() {
            assert!(tree.insert(key, sample_value(i as u64)).is_ok());
        }

        for key in sample_keys() {
            let leaf_key = trim_key(&key, TREE_DEPTH);
            assert!(tree.nodes.contains_key(&(TREE_DEPTH, leaf_key)));
        }

        let conflict = sample_value(99);
        for existing_key in sample_keys() {
            assert!(tree.insert(existing_key, conflict).is_err());
        }
    }

    #[test]
    fn test_get_value() {
        let mut tree = SparseMerkleTree::new();
        let value = sample_value(45);
        for key in sample_keys() {
            assert!(tree.insert(key, value).is_ok());
            assert_eq!(tree.get(&key).unwrap(), value);
            let non_existent_key = [10; 32];
            assert!(tree.get(&non_existent_key).is_none());
        }
    }

    #[test]
    fn test_multiple_values() {
        let mut tree = SparseMerkleTree::new();
        for (i, key) in sample_keys().into_iter().enumerate() {
            assert!(tree.insert(key, sample_value(i as u64)).is_ok());
        }
        for (i, key) in sample_keys().into_iter().enumerate() {
            assert_eq!(tree.get(&key).unwrap(), sample_value(i as u64));
        }
    }

    #[test]
    fn test_verify_inclusion_proofs() {
        let mut tree = SparseMerkleTree::new();
        for (i, key) in sample_keys().into_iter().enumerate() {
            assert!(
                tree.generate_inclusion_proof(&key).is_err(),
                "Proof for non-existent key should fail"
            );
            tree.insert(key, sample_value(i as u64)).unwrap();
            let (proof, commitment) = tree.generate_inclusion_proof(&key).unwrap();
            assert_eq!(proof.siblings.len(), TREE_DEPTH);
            assert!(proof.verify(commitment, tree.root()));
        }
    }

    #[test]
    fn test_verify_non_inclusion_proofs() {
        let mut tree = SparseMerkleTree::new();
        for (i, key) in sample_keys().into_iter().enumerate() {
            let proof = tree.generate_non_inclusion_proof(key).unwrap();
            assert_eq!(proof.siblings.len(), TREE_DEPTH);
            assert_eq!(proof.root, tree.root());
            assert!(proof.verify());
            tree.insert(key, sample_value(i as u64)).unwrap();
        }
    }

    #[test]
    fn default_is_empty_tree() {
        let tree = SparseMerkleTree::default();
        assert_eq!(tree.root(), DEFAULT_HASHES[0]);
    }

    #[test]
    fn insert_same_key_same_value_is_idempotent() {
        let mut tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        let value = sample_value(0);
        assert!(tree.insert(key, value).is_ok());
        // Re-inserting the same (key, value) is a no-op success.
        assert!(tree.insert(key, value).is_ok());
        assert_eq!(tree.get(&key), Some(value));
    }

    #[test]
    fn insert_same_key_different_value_errors() {
        let mut tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        tree.insert(key, sample_value(0)).unwrap();
        let err = tree.insert(key, sample_value(99));
        assert!(err.is_err());
    }

    #[test]
    fn generate_non_inclusion_proof_errors_when_key_exists() {
        let mut tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        tree.insert(key, sample_value(0)).unwrap();
        let err = tree.generate_non_inclusion_proof(key);
        assert!(err.is_err());
    }

    /// A non-inclusion proof with the wrong sibling count is rejected by
    /// the length guard in `verify()` — the in-circuit gadget is built
    /// against a fixed `TREE_DEPTH` shape and an off-circuit short proof
    /// would silently underspecify the chain.
    #[test]
    fn non_inclusion_verify_rejects_short_proof() {
        let tree = SparseMerkleTree::new();
        let mut proof = tree.generate_non_inclusion_proof([1u8; 32]).unwrap();
        proof.siblings.truncate(TREE_DEPTH - 1);
        assert!(!proof.verify());
    }

    #[test]
    fn inclusion_verify_rejects_short_proof() {
        let mut tree = SparseMerkleTree::new();
        tree.insert([1u8; 32], sample_value(1)).unwrap();
        let (mut proof, value) = tree.generate_inclusion_proof(&[1u8; 32]).unwrap();
        proof.siblings.truncate(TREE_DEPTH - 1);
        assert!(!proof.verify(value, tree.root()));
    }

    #[test]
    fn verify_and_insert_rejects_invalid_proof() {
        let tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        let mut proof = tree.generate_non_inclusion_proof(key).unwrap();
        // Tamper with a sibling: the verify() will reconstruct a different
        // root than `proof.root`, so verify_and_insert refuses to insert.
        proof.siblings[0] = sample_value(0xDEAD);
        let err = proof.verify_and_insert(sample_value(7));
        assert!(err.is_err());
    }

    #[test]
    fn non_inclusion_after_insert_changes_root_field_fails() {
        let tree = SparseMerkleTree::new();
        let key = [1u8; 32];
        let mut proof = tree.generate_non_inclusion_proof(key).unwrap();
        // Pretend the root is something else; verify must catch.
        proof.root = sample_value(0xBEEF);
        assert!(!proof.verify());
    }

    /// Regression guard against the zero-state Poseidon collision: if
    /// `DEFAULT_HASHES[TREE_DEPTH]` were `ZERO_HASH`, every level's default
    /// would equal `Poseidon(all-zeros)` — and any leaf whose value+key both
    /// permute through the zero state (e.g. derived from a `0u32` input)
    /// would collide with `DEFAULT_HASHES[TREE_DEPTH - 1]`, breaking the
    /// chase loop in non-inclusion proof generation. The domain-separated
    /// empty-leaf seed prevents this.
    #[test]
    fn leaf_hash_never_collides_with_defaults() {
        for (i, key) in sample_keys().into_iter().enumerate() {
            let v = sample_value(i as u64);
            let lh = leaf_hash(&v, &key);
            for (l, default) in DEFAULT_HASHES.iter().enumerate() {
                assert_ne!(lh, *default, "leaf {i} hash equals DEFAULT_HASHES[{l}]");
            }
        }
    }

    /// `save_merkle_tree` + `load_merkle_tree` round-trip preserves
    /// the tree's leaf set + root + inclusion proofs.
    #[test]
    fn save_load_round_trip() {
        let mut tree = SparseMerkleTree::new();
        for (i, key) in sample_keys().into_iter().enumerate().take(5) {
            tree.insert(key, sample_value(i as u64)).unwrap();
        }
        let original_root = tree.root();

        // Write to a temp file via `tempfile` isn't available without
        // a dep — use a deterministic per-test path under
        // `std::env::temp_dir()` instead.
        let path = std::env::temp_dir().join("zkcoins-plonky2-smt-roundtrip.bin");
        let path_str = path.to_str().unwrap();
        save_merkle_tree(&tree, path_str).expect("save");
        let loaded = load_merkle_tree(path_str).expect("load");
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded.root(), original_root);
        // Re-derive an inclusion proof from the loaded tree and
        // verify against the original root.
        let (proof, value) = loaded
            .generate_inclusion_proof(&sample_keys()[0])
            .expect("inclusion proof");
        assert_eq!(value, sample_value(0));
        assert!(proof.verify(value, original_root));
    }

    /// Build-time assertion: `load_merkle_tree` propagates I/O
    /// errors when the path doesn't exist.
    #[test]
    fn load_merkle_tree_missing_path_errors() {
        let path = std::env::temp_dir().join("zkcoins-plonky2-smt-does-not-exist.bin");
        std::fs::remove_file(&path).ok();
        let result = load_merkle_tree(path.to_str().unwrap());
        assert!(result.is_err());
    }
}
