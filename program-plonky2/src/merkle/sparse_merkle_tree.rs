//! Sparse Merkle tree, Poseidon-Goldilocks variant.
//!
//! Mirrors the SHA256 SMT in `program/src/merkle/sparse_merkle_tree.rs`
//! algorithmically; only the hash function and value type change.
//!
//! - Keys: `[u8; 32]`, MSB-first bit indexing (unchanged).
//! - Values / node hashes: [`HashDigest`] (`HashOut<F>`, 4 Goldilocks elts).
//! - `hash_concat(left, right)` is Poseidon two-to-one.
//! - `DEFAULT_HASHES[depth] = ZERO_HASH`; higher levels derived by
//!   self-concatenation, computed once via `LazyLock`.
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

/// Inclusion proof: the key, plus sibling hashes along the path from the
/// (single) leaf back up to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub key: [u8; 32],
    pub siblings: Vec<HashDigest>,
}

impl InclusionProof {
    /// Returns true if the proof reconstructs to `expected_root` from `leaf`.
    pub fn verify(&self, leaf: HashDigest, expected_root: HashDigest) -> bool {
        let mut current_hash = leaf_hash(&leaf, &self.key);
        let mut siblings = self.siblings.clone();
        while let Some(sibling) = siblings.pop() {
            let branch = get_bit(&self.key, siblings.len());
            current_hash = if branch {
                hash_concat(&sibling, &current_hash)
            } else {
                hash_concat(&current_hash, &sibling)
            };
        }
        current_hash == expected_root
    }
}

/// Non-inclusion proof: witnesses that `key` is *not* in the tree, by giving
/// either the occupying-sibling (different key, real value) or empty-subtree
/// (same key, default value) along the relevant path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonInclusionProof {
    pub key: [u8; 32],
    pub root: HashDigest,
    pub siblings: Vec<HashDigest>,
    pub leaf: ([u8; 32], HashDigest),
}

impl NonInclusionProof {
    pub fn verify(&self) -> bool {
        let mut siblings = self.siblings.clone();
        let mut current_hash = if self.key == self.leaf.0 {
            if self.leaf.1 != DEFAULT_HASHES[siblings.len()] {
                return false;
            }
            self.leaf.1
        } else {
            debug_assert_ne!(self.leaf.0, self.key);
            leaf_hash(&self.leaf.1, &self.leaf.0)
        };
        while let Some(sibling) = siblings.pop() {
            current_hash = if get_bit(&self.leaf.0, siblings.len()) {
                hash_concat(&sibling, &current_hash)
            } else {
                hash_concat(&current_hash, &sibling)
            };
        }
        current_hash == self.root
    }

    /// Returns the new root after inserting `leaf` at `self.key`. Does not
    /// verify the proof itself; pair with [`Self::verify_and_insert`] when
    /// validation is required.
    pub fn insert(&self, leaf: HashDigest) -> Result<HashDigest, &'static str> {
        let mut siblings = self.siblings.clone();
        let mut current_hash = if self.key == self.leaf.0 {
            if self.leaf.1 != DEFAULT_HASHES[siblings.len()] {
                return Err("Invalid non-inclusion proof");
            }
            leaf_hash(&leaf, &self.key)
        } else {
            debug_assert_ne!(self.leaf.0, self.key);
            while get_bit(&self.key, siblings.len()) == get_bit(&self.leaf.0, siblings.len()) {
                siblings.push(DEFAULT_HASHES[siblings.len() + 1])
            }
            let sibling = leaf_hash(&self.leaf.1, &self.leaf.0);
            let leaf = leaf_hash(&leaf, &self.key);
            if get_bit(&self.key, siblings.len()) {
                hash_concat(&sibling, &leaf)
            } else {
                hash_concat(&leaf, &sibling)
            }
        };
        while let Some(sibling) = siblings.pop() {
            current_hash = if get_bit(&self.key, siblings.len()) {
                hash_concat(&sibling, &current_hash)
            } else {
                hash_concat(&current_hash, &sibling)
            };
        }
        Ok(current_hash)
    }

    pub fn verify_and_insert(&self, leaf: HashDigest) -> Result<HashDigest, &'static str> {
        if !self.verify() {
            return Err("Invalid non-inclusion proof");
        }
        self.insert(leaf)
    }
}

/// Sparse Merkle tree: only stores nodes that differ from the level-default.
#[derive(Debug)]
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

    /// Inserts `leaf` at `key`. Idempotent for identical re-insertions;
    /// errors on conflicting re-insertion.
    pub fn insert(&mut self, key: [u8; 32], leaf: HashDigest) -> Result<(), &'static str> {
        if self.leaf_values.contains_key(&key) {
            return if self.leaf_values.get(&key) == Some(&leaf) {
                Ok(())
            } else {
                Err("Key already exists in the tree with different value")
            };
        }

        let prev_leaf = self.leaf_values.insert(key, leaf);
        debug_assert_eq!(prev_leaf, None);

        let leaf_h = leaf_hash(&leaf, &key);
        let mut current_hash = leaf_h;
        for level in (0..TREE_DEPTH).rev() {
            let branch = get_bit(&key, level);
            let parent_key = trim_key(&key, level);
            let sibling_key = child_key(&parent_key, !branch, level);
            let sibling = self
                .nodes
                .get(&(level + 1, sibling_key))
                .cloned()
                .unwrap_or(DEFAULT_HASHES[level + 1]);
            self.nodes.insert(
                (level + 1, child_key(&parent_key, branch, level)),
                current_hash,
            );
            if current_hash != leaf_h || sibling != DEFAULT_HASHES[level + 1] {
                current_hash = if branch {
                    hash_concat(&sibling, &current_hash)
                } else {
                    hash_concat(&current_hash, &sibling)
                };
            }
        }
        let prev_root = self.nodes.insert((0, [0; 32]), current_hash);
        debug_assert_ne!(prev_root, Some(current_hash));

        Ok(())
    }

    pub fn root(&self) -> HashDigest {
        self.nodes
            .get(&(0, [0; 32]))
            .cloned()
            .unwrap_or(DEFAULT_HASHES[0])
    }

    pub fn generate_non_inclusion_proof(
        &self,
        key: [u8; 32],
    ) -> Result<NonInclusionProof, &'static str> {
        let mut siblings = Vec::with_capacity(TREE_DEPTH);

        if self.nodes.contains_key(&(TREE_DEPTH, key)) {
            return Err("Leaf exists in the tree");
        }

        let mut sibling_leaf = (key, DEFAULT_HASHES[TREE_DEPTH]);

        if !self.nodes.contains_key(&(0, [0; 32])) {
            return Ok(NonInclusionProof {
                key,
                root: DEFAULT_HASHES[0],
                siblings,
                leaf: (key, DEFAULT_HASHES[0]),
            });
        }

        for level in 0..TREE_DEPTH {
            let branch = get_bit(&key, level);
            let parent_key = trim_key(&key, level);
            if let Some(parent) = self.nodes.get(&(level, parent_key)) {
                let sibling_key = child_key(&parent_key, !branch, level);
                let sibling = self
                    .nodes
                    .get(&(level + 1, sibling_key))
                    .cloned()
                    .unwrap_or(DEFAULT_HASHES[level + 1]);
                let key = child_key(&parent_key, branch, level);
                let child = self
                    .nodes
                    .get(&(level + 1, key))
                    .cloned()
                    .unwrap_or(DEFAULT_HASHES[level + 1]);
                if sibling == *parent || child == *parent {
                    let mut parent_key = if child == *parent { key } else { sibling_key };
                    for layer in level + 1..TREE_DEPTH {
                        let key_1 = child_key(&parent_key, true, layer);
                        let key_0 = child_key(&parent_key, false, layer);
                        let node_1 = self
                            .nodes
                            .get(&(layer + 1, key_1))
                            .cloned()
                            .unwrap_or(DEFAULT_HASHES[layer + 1]);
                        let node_0 = self
                            .nodes
                            .get(&(layer + 1, key_0))
                            .cloned()
                            .unwrap_or(DEFAULT_HASHES[layer + 1]);
                        debug_assert!(node_1 == *parent || node_0 == *parent);
                        parent_key = if node_1 == *parent { key_1 } else { key_0 };
                    }
                    sibling_leaf.0 = parent_key;
                    sibling_leaf.1 = *self.leaf_values.get(&parent_key).unwrap();
                    break;
                }
                siblings.push(sibling);
            } else {
                sibling_leaf.0 = key;
                sibling_leaf.1 = DEFAULT_HASHES[level];
                break;
            }
        }

        Ok(NonInclusionProof {
            key,
            root: self.root(),
            siblings,
            leaf: sibling_leaf,
        })
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<HashDigest> {
        self.leaf_values.get(key).cloned()
    }

    pub fn generate_inclusion_proof(
        &self,
        key: &[u8; 32],
    ) -> Result<(InclusionProof, HashDigest), &'static str> {
        if !self.nodes.contains_key(&(TREE_DEPTH, *key)) {
            return Err("Key does not exist in the tree");
        }

        let commitment = self.get(key).unwrap();

        let mut siblings = Vec::new();
        let mut parent = self
            .nodes
            .get(&(0, [0; 32]))
            .cloned()
            .unwrap_or(DEFAULT_HASHES[0]);

        for level in 0..TREE_DEPTH {
            let branch = get_bit(key, level);
            let parent_key = trim_key(key, level);
            let sibling_key = child_key(&parent_key, !branch, level);
            let sibling = self
                .nodes
                .get(&(level + 1, sibling_key))
                .cloned()
                .unwrap_or(DEFAULT_HASHES[level + 1]);
            let ck = child_key(&parent_key, branch, level);
            let child = self
                .nodes
                .get(&(level + 1, ck))
                .cloned()
                .unwrap_or(DEFAULT_HASHES[level + 1]);
            if child == parent || sibling == parent {
                break;
            }
            siblings.push(sibling);
            parent = child;
        }

        Ok((
            InclusionProof {
                key: *key,
                siblings,
            },
            commitment,
        ))
    }
}

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
            assert!(proof.verify(commitment, tree.root()));
        }
    }

    #[test]
    fn test_verify_non_inclusion_proofs() {
        let mut tree = SparseMerkleTree::new();
        for (i, key) in sample_keys().into_iter().enumerate() {
            let proof = tree.generate_non_inclusion_proof(key).unwrap();
            assert_eq!(proof.root, tree.root());
            assert!(proof.verify());
            tree.insert(key, sample_value(i as u64)).unwrap();
        }
    }

    /// Regression guard against the zero-state Poseidon collision: if
    /// `DEFAULT_HASHES[TREE_DEPTH]` were `ZERO_HASH`, every level's default
    /// would equal `Poseidon(all-zeros)` — and any leaf whose value+key both
    /// permute through the zero state (e.g. derived from a `0u32` input)
    /// would collide with `DEFAULT_HASHES[TREE_DEPTH - 1]`, breaking the
    /// chase loop in `generate_non_inclusion_proof`. The domain-separated
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
}
