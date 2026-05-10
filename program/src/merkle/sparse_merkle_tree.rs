use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};

use super::{hash_concat, HashDigest, ZERO_HASH};

/// The tree depth. For a 256-bit key space, depth is 256.
pub const TREE_DEPTH: usize = 256;

lazy_static! {
    /// Global default hash values for each level.
    pub static ref DEFAULT_HASHES: Vec<HashDigest> = {
        let depth = TREE_DEPTH;
        let mut default_hashes = vec![ZERO_HASH; depth + 1];
        // The default leaf hash can be computed arbitrarily; here using `hash_leaf(&[])`
        default_hashes[depth] = hash_leaf(&[]);
        for level in (0..depth).rev() {
            default_hashes[level] =
                hash_concat(&default_hashes[level + 1], &default_hashes[level + 1]);
        }
        default_hashes
    };
}

/// Represents an inclusion proof for a key in the Sparse Merkle Tree.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InclusionProof {
    /// The key (public key) that is proven to exist in the tree
    pub key: [u8; 32],
    /// The sibling hashes along the path from the root to the leaf
    pub siblings: Vec<HashDigest>,
}

/// Returns the bit at index `i` (0 = most-significant) in a 256‑bit key.
pub fn get_bit(key: &[u8; 32], i: usize) -> bool {
    let byte_index = i / 8;
    let bit_index = 7 - (i % 8);
    ((key[byte_index] >> bit_index) & 1) == 1
}

impl InclusionProof {
    /// Verifies an inclusion proof.
    /// Returns true if the proof is valid, false otherwise.
    pub fn verify(&self, leaf: HashDigest, expected_root: HashDigest) -> bool {
        // Hash leaf with key
        let mut current_hash = hash_concat(&leaf, &self.key);
        let mut siblings = self.siblings.clone();
        // Start with the leaf hash and work our way up to the root
        while let Some(sibling) = siblings.pop() {
            // Get the bit at this level (from most significant to least)
            let branch = get_bit(&self.key, siblings.len());

            // Combine the current hash with its sibling in the correct order
            if branch {
                // If bit is 1, we're on the right branch, so sibling is on the left
                current_hash = hash_concat(&sibling, &current_hash);
            } else {
                // If bit is 0, we're on the left branch, so sibling is on the right
                current_hash = hash_concat(&current_hash, &sibling);
            }
        }

        // The computed root should match the provided root
        current_hash == expected_root
    }
}

/// Represents a non-inclusion proof for a key in the Sparse Merkle Tree.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NonInclusionProof {
    /// The key that is proven to not exist in the tree
    pub key: [u8; 32],
    /// The root hash of the tree
    pub root: HashDigest,
    /// The sibling hashes along the path from the root to the leaf
    pub siblings: Vec<HashDigest>,
    /// The sibling hint (key, leaf)
    pub leaf: ([u8; 32], HashDigest),
}

impl NonInclusionProof {
    /// Verifies a non-inclusion proof without updating the tree.
    /// Returns true if the proof is valid, false otherwise.
    pub fn verify(&self) -> bool {
        let mut siblings = self.siblings.clone();
        // Compute the leaf hash for the sibling key
        let mut current_hash = if self.key == self.leaf.0 {
            // inclusion proof: expecting default leaf
            if self.leaf.1 != DEFAULT_HASHES[siblings.len()] {
                return false;
            }
            self.leaf.1
        } else {
            // non-inclusion proof: expecting keys not equal
            debug_assert_ne!(self.leaf.0, self.key);
            // Hash sibling leaf with key
            hash_concat(&self.leaf.1, &self.leaf.0)
        };
        // Reconstruct the root by combining the siblings
        while let Some(sibling) = siblings.pop() {
            // Combine the current hash with its sibling in the correct order
            current_hash = if get_bit(&self.leaf.0, siblings.len()) {
                hash_concat(&sibling, &current_hash)
            } else {
                hash_concat(&current_hash, &sibling)
            };
        }

        let result = current_hash == self.root;
        if !result {
            println!(
                "Root mismatch: computed {:?}, expected {:?}",
                current_hash, self.root
            );
        }

        result
    }

    /// Updates the tree with the new value.
    /// Returns the updated root.
    pub fn insert(&self, leaf: HashDigest) -> Result<HashDigest, &'static str> {
        let mut siblings = self.siblings.clone();
        let mut current_hash = if self.key == self.leaf.0 {
            // inclusion proof: expecting default leaf
            if self.leaf.1 != DEFAULT_HASHES[siblings.len()] {
                return Err("Invalid non-inclusion proof");
            }
            // Hash leaf with key
            hash_concat(&leaf, &self.key)
        } else {
            // non-inclusion proof: expecting keys not equal
            debug_assert_ne!(self.leaf.0, self.key);
            // Padding with default hashes
            while get_bit(&self.key, siblings.len()) == get_bit(&self.leaf.0, siblings.len()) {
                siblings.push(DEFAULT_HASHES[siblings.len() + 1])
            }
            let sibling = hash_concat(&self.leaf.1, &self.leaf.0);
            let leaf = hash_concat(&leaf, &self.key);
            // Combine children in the correct order.
            if get_bit(&self.key, siblings.len()) {
                hash_concat(&sibling, &leaf)
            } else {
                hash_concat(&leaf, &sibling)
            }
        };
        // Hash through previous siblings
        while let Some(sibling) = siblings.pop() {
            // Combine children in the correct order.
            current_hash = if get_bit(&self.key, siblings.len()) {
                hash_concat(&sibling, &current_hash)
            } else {
                hash_concat(&current_hash, &sibling)
            };
        }
        Ok(current_hash)
    }

    /// Verifies a non-inclusion proof and updates the tree with a new value if the proof is valid.
    /// Returns the new root hash if successful, or an error if the proof is invalid.
    pub fn verify_and_insert(&self, leaf: HashDigest) -> Result<HashDigest, &'static str> {
        // First, verify the proof using the global DEFAULT_HASHES.
        if !self.verify() {
            return Err("Invalid non-inclusion proof");
        }
        self.insert(leaf)
    }
}

/// Computes the hash for a leaf node with a domain‐separating prefix.
pub fn hash_leaf(data: &[u8]) -> HashDigest {
    let mut hasher = Sha256::new();
    // Domain separation: prefix with 0x00 for leaves.
    hasher.update([0x00]);
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = ZERO_HASH;
    hash.copy_from_slice(&result);
    hash
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
            // When bits is a multiple of 8, clear from index `full_bytes` onward.
            new_key[full_bytes..].fill(0);
        }
    }
    new_key
}

/// Computes the key for the child node given its parent's key, the branch (false for left, true for right),
/// and the parent's level.
fn child_key(parent_key: &[u8; 32], branch: bool, level: usize) -> [u8; 32] {
    let mut child = *parent_key;
    if branch {
        let byte_index = level / 8;
        let bit_index = 7 - (level % 8);
        child[byte_index] |= 1 << bit_index;
    }
    trim_key(&child, level + 1)
}

// A : 0b00
// B : 0b01
//      /\
//     /  \
//    /\  ∅
//   /  \
//  A    B

/// A simple sparse Merkle tree structure.
///
/// It only stores nodes that differ from the default (empty) values.
#[derive(Serialize, Deserialize, Debug)]
pub struct SparseMerkleTree {
    /// Map key: (level, node index). For a node at a given level, the index is represented as a 256‑bit array
    /// where only the first `level` bits are significant.
    nodes: HashMap<(usize, [u8; 32]), HashDigest>,
    /// Store the leaf values to support retrieval
    leaf_values: HashMap<[u8; 32], HashDigest>,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// Creates a new sparse Merkle tree with the specified depth.
    pub fn new() -> Self {
        SparseMerkleTree {
            nodes: HashMap::new(),
            leaf_values: HashMap::new(),
        }
    }

    /// Inserts a new leaf at `key` with the given `value`.
    ///
    /// Returns an error if the key already exists in the tree.
    /// The key is assumed to be a 256‑bit value (as a `[u8; 32]` array).
    pub fn insert(&mut self, key: [u8; 32], leaf: HashDigest) -> Result<(), &'static str> {
        // Check if the key already exists in the tree
        if self.leaf_values.contains_key(&key) {
            // Allow to insert the exact same leaf
            return if self.leaf_values.get(&key) == Some(&leaf) {
                Ok(eprintln!(
                    "\u{1B}[33mWARNING: Leaf already exists in the tree\u{1B}[0m"
                ))
            } else {
                Err("Key already exists in the tree with different value")
            };
        }

        // Store the leaf to get it with the key.
        // Bind the insert result first: debug_assert! is a no-op in release
        // and would otherwise drop the side effect entirely.
        let prev_leaf = self.leaf_values.insert(key, leaf);
        debug_assert_eq!(prev_leaf, None);

        // Hash leaf with key
        let leaf_hash = hash_concat(&leaf, &key);

        // Propagate the update upward.
        let mut current_hash = leaf_hash;
        for level in (0..TREE_DEPTH).rev() {
            // Determine whether the current node is a left or right child.
            let branch = get_bit(&key, level);
            let parent_key = trim_key(&key, level);
            // Sibling key is computed by taking the opposite branch.
            let sibling_key = child_key(&parent_key, !branch, level);
            let sibling = self
                .nodes
                .get(&(level + 1, sibling_key))
                .cloned()
                .unwrap_or(DEFAULT_HASHES[level + 1]);
            // Update sibling node
            self.nodes.insert(
                (level + 1, child_key(&parent_key, branch, level)),
                current_hash,
            );
            if current_hash != leaf_hash || sibling != DEFAULT_HASHES[level + 1] {
                current_hash = if branch {
                    // Combine children in the correct order.
                    hash_concat(&sibling, &current_hash)
                } else {
                    hash_concat(&current_hash, &sibling)
                };
            }
        }
        // Update the merkle root. Same caveat as above: bind first, assert second.
        let prev_root = self.nodes.insert((0, [0; 32]), current_hash);
        debug_assert_ne!(prev_root, Some(current_hash));

        Ok(())
    }

    /// Returns the current root hash of the tree.
    pub fn root(&self) -> HashDigest {
        // The root is at level 0 with an index of all zeros.
        self.nodes
            .get(&(0, [0; 32]))
            .cloned()
            .unwrap_or(DEFAULT_HASHES[0])
    }

    /// Generates a non-inclusion proof for a key.
    pub fn generate_non_inclusion_proof(
        &self,
        key: [u8; 32],
    ) -> Result<NonInclusionProof, &'static str> {
        let mut siblings = Vec::with_capacity(TREE_DEPTH);

        // Check if the key exists in the tree
        if self.nodes.contains_key(&(TREE_DEPTH, key)) {
            // If the key exists, we can't generate a valid non-inclusion proof
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

        // Collect sibling hashes along the path from root to leaf
        for level in 0..TREE_DEPTH {
            let branch = get_bit(&key, level);
            let parent_key = trim_key(&key, level);
            if let Some(parent) = self.nodes.get(&(level, parent_key)) {
                // Compute the sibling key (the key for the other branch)
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
                    // Restore full sibling key and fetch its leaf
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

    /// Gets the value associated with a key, if it exists in the tree.
    pub fn get(&self, key: &[u8; 32]) -> Option<HashDigest> {
        // Simply return the stored value from leaf_values
        self.leaf_values.get(key).cloned()
    }

    /// Generates an inclusion proof for a key in the tree.
    /// The proof includes the sibling hashes along the path from the root to the leaf,
    /// the key, and the value.
    pub fn generate_inclusion_proof(
        &self,
        key: &[u8; 32],
    ) -> Result<(InclusionProof, HashDigest), &'static str> {
        // Check if this key exists in the nodes map at the leaf level
        if !self.nodes.contains_key(&(TREE_DEPTH, *key)) {
            // The key doesn't exist in the tree
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
            let child_key = child_key(&parent_key, branch, level);
            let child = self
                .nodes
                .get(&(level + 1, child_key))
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

/// Saves a Sparse Merkle Tree to a file at the specified path.
pub fn save_merkle_tree(tree: &SparseMerkleTree, path: &str) -> io::Result<()> {
    let file = File::create(path)?;
    let serialized =
        bincode::serialize(tree).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut writer = io::BufWriter::new(file);
    writer.write_all(&serialized)?;
    Ok(())
}

/// Loads a Sparse Merkle Tree from a file at the specified path.
pub fn load_merkle_tree(path: &str) -> io::Result<SparseMerkleTree> {
    let file = File::open(path)?;
    let mut reader = io::BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;

    bincode::deserialize(&buffer).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

#[cfg(test)]
mod tests {
    use super::super::HASH_SIZE;

    use super::*;

    const SAMPLES: [[u8; 32]; 50] = [
        [
            0xFF, 0x86, 0x1D, 0xB2, 0xA9, 0xA1, 0x5A, 0x20, 0x0A, 0x6E, 0xED, 0x82, 0xF8, 0x3F,
            0xFA, 0x04, 0xD0, 0x3B, 0xB4, 0xDB, 0xF1, 0x23, 0xAC, 0x2F, 0x19, 0x74, 0xE2, 0xB2,
            0xC8, 0x86, 0xD4, 0x37,
        ],
        [
            0x2D, 0x54, 0x24, 0xE6, 0x8B, 0xA1, 0x19, 0xFA, 0x0B, 0x20, 0x82, 0xD2, 0x74, 0x02,
            0x3E, 0xAA, 0xA3, 0x81, 0xCA, 0x0E, 0xB7, 0x8E, 0xB1, 0x86, 0x9E, 0xBF, 0xB8, 0x95,
            0x9B, 0xA2, 0x59, 0xE8,
        ],
        [
            0xF8, 0x1C, 0xA1, 0xF1, 0xF4, 0x93, 0x7A, 0x62, 0x14, 0x05, 0x32, 0xA1, 0xF4, 0x43,
            0xD7, 0xAB, 0xCA, 0x9A, 0x15, 0xC2, 0xA3, 0xCF, 0x3F, 0x42, 0x5D, 0x90, 0x7D, 0xEC,
            0x29, 0xE7, 0x5D, 0x71,
        ],
        [
            0xA2, 0xFC, 0xAD, 0x39, 0xBC, 0x3B, 0x65, 0x30, 0x78, 0x31, 0x34, 0x46, 0x89, 0x05,
            0x49, 0xE9, 0xF6, 0xF1, 0x06, 0x9B, 0x13, 0xDB, 0x75, 0xD4, 0x45, 0xC1, 0x97, 0x43,
            0x2A, 0xD6, 0x1C, 0x64,
        ],
        [
            0xC7, 0x79, 0x0C, 0x63, 0xE2, 0xA5, 0x01, 0x6F, 0xA6, 0xC4, 0xA1, 0x6E, 0xB5, 0x3C,
            0x0D, 0x7A, 0xF9, 0xF4, 0xFD, 0x58, 0x02, 0xF0, 0xF1, 0x8C, 0x7F, 0xC0, 0x4E, 0x3D,
            0x58, 0x3A, 0x60, 0xF2,
        ],
        [
            0xD4, 0xE9, 0x69, 0xD7, 0x52, 0xAD, 0xBD, 0xF2, 0x41, 0x08, 0x96, 0xB2, 0xD7, 0xBD,
            0xF6, 0x6D, 0x4B, 0x43, 0x81, 0xC9, 0x1B, 0xD3, 0xC9, 0x96, 0x27, 0x2F, 0xAB, 0xE7,
            0xC2, 0xF7, 0x60, 0xC4,
        ],
        [
            0x00, 0x5E, 0x18, 0x2F, 0x55, 0x0A, 0xFA, 0x74, 0x8E, 0x8E, 0xE2, 0x12, 0xAF, 0xF4,
            0xBD, 0xE6, 0xF2, 0x04, 0xEE, 0x7F, 0xE1, 0xD7, 0x05, 0x0C, 0x1B, 0x16, 0x4B, 0x48,
            0xC3, 0x49, 0x70, 0x0F,
        ],
        [
            0x95, 0x4A, 0x8A, 0x33, 0x34, 0x99, 0x42, 0xA0, 0x95, 0x98, 0x1F, 0x83, 0x03, 0x58,
            0x92, 0xAC, 0xEE, 0xA6, 0x70, 0xE4, 0x3C, 0x00, 0x55, 0xEE, 0xB4, 0x71, 0xD1, 0xAC,
            0xDC, 0xB6, 0xDB, 0x21,
        ],
        [
            0xB3, 0x7B, 0xF4, 0xB3, 0x6E, 0x4F, 0x41, 0x47, 0xD7, 0x39, 0xB8, 0x4F, 0x5E, 0xC4,
            0x68, 0x18, 0x4F, 0xAD, 0x9C, 0xE7, 0x76, 0x65, 0x70, 0x6B, 0xC6, 0x88, 0x77, 0x9E,
            0x29, 0x1D, 0x0B, 0xC8,
        ],
        [
            0x01, 0xBA, 0xF8, 0x76, 0xBF, 0x30, 0xFF, 0x03, 0xDF, 0x84, 0x61, 0x4F, 0xC1, 0x06,
            0xCB, 0x37, 0x00, 0x78, 0x13, 0xC6, 0x0B, 0xAE, 0x30, 0x69, 0xD4, 0xB0, 0x25, 0x0C,
            0x29, 0x0F, 0x2F, 0x80,
        ],
        [
            0x6D, 0xB8, 0xE4, 0xA7, 0xE4, 0xA6, 0x37, 0x00, 0x2F, 0x47, 0xBD, 0x50, 0x67, 0x3D,
            0x7A, 0x89, 0x2D, 0x3F, 0xFE, 0xE3, 0xBA, 0x58, 0x15, 0xBE, 0x9A, 0xDA, 0xA7, 0xE2,
            0x8A, 0xDE, 0xD4, 0xB7,
        ],
        [
            0x78, 0xDE, 0x51, 0x6F, 0x01, 0xF2, 0x28, 0xFE, 0x23, 0xEE, 0xFA, 0xA3, 0x7C, 0x91,
            0xF0, 0x07, 0x41, 0x7A, 0x59, 0x36, 0xF8, 0x87, 0x57, 0x91, 0x8A, 0x9E, 0x39, 0xF3,
            0x84, 0x98, 0xF0, 0xF6,
        ],
        [
            0xCB, 0x08, 0x00, 0xD0, 0xB5, 0x17, 0xF0, 0x2F, 0x80, 0x8A, 0xC8, 0x40, 0xAC, 0x52,
            0xAF, 0x27, 0x2D, 0x10, 0x22, 0xE4, 0x30, 0xB3, 0x72, 0x34, 0x3F, 0xBD, 0x0C, 0x23,
            0x44, 0x87, 0x14, 0xCC,
        ],
        [
            0x7F, 0x87, 0xAD, 0x4E, 0x0F, 0x83, 0x18, 0x12, 0x2D, 0x73, 0x4C, 0xB3, 0xF5, 0x42,
            0x69, 0x5E, 0xC3, 0xAC, 0x03, 0x00, 0xB1, 0x27, 0xCB, 0xFE, 0x07, 0x9C, 0xED, 0xC3,
            0x4A, 0xFC, 0x09, 0xB4,
        ],
        [
            0x1A, 0x73, 0x9F, 0x3E, 0xE9, 0x1F, 0xE5, 0x6B, 0x3C, 0xE0, 0x81, 0x75, 0x78, 0xC8,
            0x7E, 0x8D, 0x65, 0x1A, 0x33, 0xE4, 0x57, 0x2F, 0x4C, 0x2D, 0x0F, 0x02, 0x3F, 0x76,
            0x57, 0xB1, 0x51, 0x82,
        ],
        [
            0x76, 0x9D, 0x74, 0x79, 0xBC, 0x89, 0xBF, 0xA2, 0x67, 0x54, 0x27, 0x67, 0xC7, 0xE9,
            0xFD, 0x81, 0x3F, 0xBC, 0x2F, 0x85, 0xBB, 0x09, 0x82, 0xFC, 0x70, 0x29, 0x93, 0x8B,
            0x44, 0x8B, 0xB0, 0x5D,
        ],
        [
            0xB5, 0x07, 0x83, 0xBF, 0x44, 0x92, 0xE3, 0xCB, 0x65, 0x85, 0x01, 0xFF, 0x8D, 0xDB,
            0xF5, 0xEC, 0x90, 0x04, 0x1C, 0x81, 0xA1, 0x08, 0x70, 0x11, 0xD4, 0x80, 0x4C, 0xA4,
            0x7B, 0xA0, 0x59, 0x11,
        ],
        [
            0x92, 0x2F, 0x9C, 0xA9, 0x27, 0xE4, 0xEA, 0xB5, 0x4F, 0x85, 0x45, 0xC3, 0xFB, 0x17,
            0xAD, 0x68, 0x54, 0x0F, 0x4E, 0x96, 0x3E, 0xF8, 0x22, 0x61, 0x8F, 0x4E, 0x5A, 0x8E,
            0x75, 0x97, 0x47, 0x3F,
        ],
        [
            0xC5, 0xC2, 0xBC, 0x32, 0x2C, 0xE9, 0xC4, 0x0E, 0x36, 0x10, 0xF0, 0x02, 0x67, 0xBF,
            0xF5, 0x2A, 0x24, 0xF7, 0x31, 0x7F, 0x0F, 0xBE, 0x18, 0x0C, 0x2A, 0x18, 0x71, 0x15,
            0xE4, 0x21, 0x35, 0xA9,
        ],
        [
            0xCF, 0x06, 0x69, 0x7D, 0x61, 0xD1, 0x18, 0xC5, 0xF2, 0xE2, 0x78, 0x82, 0xDC, 0x0D,
            0xF3, 0x06, 0xAA, 0xA5, 0x21, 0x12, 0xAA, 0xCA, 0x48, 0x1D, 0x6C, 0xA7, 0x66, 0x3D,
            0xDF, 0xA5, 0x2A, 0x00,
        ],
        [
            0xA7, 0x3D, 0xF6, 0x26, 0xE0, 0x12, 0xAB, 0x45, 0xE7, 0x7E, 0xB3, 0x90, 0x99, 0x11,
            0x73, 0x72, 0x21, 0x18, 0x85, 0x57, 0xF2, 0xCF, 0x1E, 0xBE, 0xC2, 0x78, 0x66, 0x3D,
            0x67, 0xD6, 0xDE, 0x0F,
        ],
        [
            0xF7, 0xFC, 0x3C, 0xAA, 0xAC, 0xF4, 0x70, 0x84, 0x62, 0x79, 0xBC, 0x6B, 0x78, 0x92,
            0x85, 0x25, 0x2C, 0xCB, 0x10, 0x9E, 0x57, 0x3A, 0x77, 0xA9, 0x12, 0x57, 0xE9, 0x6B,
            0x87, 0x70, 0x69, 0xAE,
        ],
        [
            0x65, 0x43, 0x0E, 0x20, 0x0A, 0x8B, 0x3E, 0x38, 0xD0, 0x7F, 0x75, 0x52, 0x4C, 0xC3,
            0x51, 0x29, 0x56, 0x69, 0x1E, 0xB8, 0xEB, 0x80, 0x15, 0x95, 0x0C, 0xD7, 0x52, 0xF7,
            0x53, 0x16, 0x00, 0x4B,
        ],
        [
            0xB8, 0xC5, 0xEF, 0xF1, 0x16, 0xDA, 0x0D, 0x16, 0xE4, 0xF1, 0xB1, 0x0B, 0x91, 0x39,
            0x1E, 0xC1, 0x3F, 0x3C, 0xD3, 0x9D, 0xAD, 0x7D, 0x2A, 0x85, 0xCA, 0x5E, 0xCE, 0xEC,
            0xFC, 0x30, 0xEE, 0x73,
        ],
        [
            0x2D, 0x48, 0xB4, 0x51, 0xC1, 0x5F, 0x56, 0x7A, 0x96, 0x78, 0x4D, 0xB7, 0x5D, 0xFB,
            0xF7, 0xE7, 0xA1, 0xA8, 0xDA, 0xAF, 0x1B, 0x42, 0xFB, 0x12, 0xE0, 0xC2, 0x3B, 0xFC,
            0x28, 0x34, 0x6C, 0x7A,
        ],
        [
            0xB1, 0x21, 0x6A, 0x05, 0xEF, 0xF1, 0xFC, 0x1C, 0x41, 0x1D, 0xF8, 0xC5, 0xF8, 0x72,
            0x83, 0xA0, 0xEA, 0x2F, 0x19, 0x22, 0x29, 0x11, 0x42, 0x19, 0x42, 0x31, 0xD3, 0xEB,
            0xE2, 0xFC, 0xF2, 0xFA,
        ],
        [
            0xE2, 0xA9, 0xAD, 0x90, 0x5F, 0xDE, 0xE0, 0x97, 0xB9, 0x83, 0x6C, 0xF9, 0x04, 0x07,
            0x01, 0x54, 0x68, 0x15, 0x67, 0x9A, 0x4F, 0x88, 0x64, 0x8E, 0x4F, 0xAD, 0xA0, 0xA7,
            0x0F, 0xF7, 0xFA, 0xBB,
        ],
        [
            0xDB, 0xDD, 0xB1, 0x47, 0x1D, 0x8B, 0x12, 0x3F, 0xF9, 0x3F, 0x9E, 0x3D, 0xDE, 0x91,
            0xBC, 0x36, 0x5E, 0x53, 0x2E, 0x32, 0x55, 0xB4, 0x2D, 0x35, 0x12, 0x29, 0x5A, 0x6E,
            0xE5, 0xEB, 0xBF, 0x48,
        ],
        [
            0xAB, 0x9A, 0x8C, 0x63, 0x8A, 0x8B, 0xDE, 0xBE, 0x24, 0x93, 0xC4, 0x23, 0x1E, 0xF3,
            0x55, 0x27, 0x54, 0x2E, 0xC2, 0x59, 0xC6, 0x7B, 0xC7, 0x00, 0x6D, 0x44, 0x1A, 0x5A,
            0x63, 0x99, 0x51, 0x14,
        ],
        [
            0x46, 0xAD, 0xA6, 0x5D, 0x94, 0x68, 0xE7, 0x74, 0x70, 0x51, 0x60, 0x64, 0x19, 0x0A,
            0x22, 0x10, 0xEF, 0xFE, 0x34, 0x24, 0x8F, 0x25, 0xAA, 0xE8, 0xEE, 0x53, 0xCD, 0xFD,
            0xE9, 0xD0, 0x7E, 0x36,
        ],
        [
            0x31, 0xAC, 0x1C, 0xA2, 0xC2, 0xD0, 0xF4, 0x0F, 0x9C, 0xD4, 0x47, 0x9A, 0xE7, 0x3E,
            0xA8, 0xD0, 0x17, 0xB0, 0x7E, 0xF1, 0xCF, 0x1F, 0x22, 0xC1, 0xB4, 0x81, 0x7E, 0x2C,
            0xD2, 0xAB, 0x0A, 0xC5,
        ],
        [
            0xAA, 0xCE, 0x93, 0x26, 0x30, 0x36, 0x81, 0xE5, 0xCE, 0xAF, 0x72, 0x45, 0xB4, 0xCB,
            0x54, 0x9F, 0xB0, 0x5F, 0x29, 0xAE, 0x5A, 0xE2, 0x05, 0xFC, 0xFF, 0x34, 0x9A, 0x9B,
            0xF9, 0x01, 0x88, 0x0E,
        ],
        [
            0x8C, 0x2C, 0x47, 0xEB, 0xF1, 0x33, 0x7D, 0x64, 0xE4, 0xAB, 0x71, 0xFE, 0x61, 0xBB,
            0x8A, 0xB2, 0xEE, 0x02, 0xA1, 0x4C, 0x56, 0xA5, 0x5C, 0x79, 0xAC, 0x75, 0x7D, 0x3D,
            0x02, 0xD0, 0x29, 0xEA,
        ],
        [
            0x24, 0xF2, 0xA4, 0x7D, 0x59, 0x72, 0x2F, 0xD4, 0x02, 0xE8, 0x5E, 0xEF, 0x01, 0xDD,
            0x67, 0x50, 0xAD, 0xDE, 0xE1, 0x1A, 0xF4, 0x73, 0x88, 0x14, 0x71, 0x04, 0xF2, 0x9E,
            0x55, 0xC4, 0xCC, 0x3A,
        ],
        [
            0xB0, 0xBD, 0x22, 0x70, 0x36, 0xDF, 0x04, 0x92, 0x2D, 0x73, 0x1B, 0xAD, 0x63, 0xAF,
            0x29, 0x51, 0x1C, 0x59, 0x36, 0x82, 0xD6, 0xE7, 0xC9, 0x4A, 0x22, 0xEE, 0xA6, 0x46,
            0x2E, 0x65, 0xA8, 0x0C,
        ],
        [
            0x66, 0xAC, 0x15, 0xAF, 0x80, 0x88, 0x69, 0x05, 0x81, 0x63, 0x2B, 0x19, 0x57, 0xB3,
            0x20, 0xC5, 0x81, 0xAF, 0xD9, 0x89, 0xC3, 0x60, 0x4D, 0xB3, 0x6C, 0xCF, 0x6F, 0xFB,
            0x87, 0x5D, 0x94, 0xC2,
        ],
        [
            0xEF, 0x9F, 0x14, 0xBA, 0x96, 0x6D, 0x52, 0xB6, 0x9F, 0xEE, 0xAF, 0x6C, 0xAE, 0x68,
            0x51, 0xD6, 0x3A, 0x60, 0xBF, 0x4E, 0x97, 0x36, 0xA0, 0x29, 0x8E, 0x58, 0x04, 0xD4,
            0x7E, 0xA7, 0xD2, 0x52,
        ],
        [
            0x9E, 0x23, 0x7A, 0xB7, 0xF5, 0xEB, 0xA7, 0xDE, 0x94, 0x75, 0x25, 0xF0, 0xCF, 0x0A,
            0x8B, 0x5D, 0x2C, 0x7A, 0xC5, 0x21, 0x4D, 0xB3, 0x5A, 0x2D, 0xBA, 0xCA, 0x8C, 0x6E,
            0xCA, 0x24, 0x33, 0xC6,
        ],
        [
            0x92, 0x5C, 0x2C, 0x6A, 0x89, 0x02, 0x04, 0xA0, 0xB3, 0x08, 0xDB, 0x0C, 0x55, 0x54,
            0xF7, 0xDC, 0x6C, 0xF9, 0x6F, 0x06, 0xC6, 0x6D, 0x56, 0xD8, 0xA2, 0xEB, 0x17, 0xF8,
            0xBD, 0xCD, 0x26, 0x0C,
        ],
        [
            0xD3, 0xB0, 0x44, 0x3D, 0x9A, 0xDB, 0x10, 0xD4, 0x70, 0xEE, 0x72, 0x15, 0x0E, 0x8B,
            0x34, 0x3F, 0xF2, 0x84, 0x40, 0x2F, 0x31, 0xF5, 0x37, 0x0A, 0x88, 0x7D, 0xDF, 0x28,
            0xF3, 0x13, 0xD3, 0xEC,
        ],
        [
            0xB3, 0xB3, 0xBD, 0x3A, 0x71, 0x6C, 0x66, 0x55, 0x36, 0x73, 0x17, 0x65, 0x39, 0x82,
            0x85, 0x3B, 0xA2, 0x2C, 0xB5, 0xF9, 0x8A, 0x65, 0x9E, 0xF3, 0x8E, 0x77, 0x02, 0x6E,
            0x13, 0xA4, 0xB2, 0x73,
        ],
        [
            0x3C, 0x11, 0xAE, 0x67, 0xF5, 0x80, 0xC0, 0x4E, 0x6F, 0xC0, 0x03, 0x9B, 0x2A, 0xD0,
            0xEC, 0x4E, 0x4A, 0x38, 0x3F, 0xC3, 0x62, 0x3B, 0x9A, 0xAE, 0x54, 0x08, 0x63, 0xE0,
            0xBE, 0x4D, 0x5C, 0x21,
        ],
        [
            0x0A, 0x60, 0x74, 0x8E, 0xE2, 0x37, 0x24, 0x81, 0x2C, 0xBC, 0x13, 0xA0, 0xBA, 0xF1,
            0x33, 0x4B, 0xFD, 0xE1, 0x1B, 0x23, 0x07, 0x6D, 0x5B, 0x1A, 0x38, 0xD6, 0x09, 0x98,
            0xDB, 0x65, 0x0C, 0x75,
        ],
        [
            0xFC, 0xB5, 0x46, 0x72, 0xE3, 0xBC, 0x2B, 0xAD, 0xA1, 0xAF, 0x1F, 0x36, 0x1C, 0x6E,
            0x62, 0x06, 0x41, 0x62, 0x8C, 0x1C, 0x7A, 0x1F, 0x5B, 0x8B, 0x8F, 0x85, 0xA2, 0x00,
            0x99, 0x32, 0xBD, 0x41,
        ],
        [
            0x19, 0xEE, 0x3D, 0x28, 0x51, 0x27, 0xAE, 0xFA, 0xF7, 0x60, 0xBC, 0x10, 0x42, 0x14,
            0x7C, 0x67, 0x4E, 0x6A, 0x47, 0x47, 0xA7, 0x9F, 0x4E, 0xC3, 0xB2, 0x1C, 0xE4, 0x6C,
            0x02, 0x5E, 0x89, 0x9C,
        ],
        [
            0xB8, 0xD9, 0x6C, 0xDE, 0xA1, 0x88, 0x53, 0xC2, 0xD5, 0xFA, 0x01, 0x9F, 0x12, 0xD6,
            0xFD, 0xF5, 0x48, 0xAA, 0x0B, 0xF4, 0x8D, 0xBC, 0x0F, 0x5B, 0x13, 0x24, 0x52, 0x24,
            0x10, 0x72, 0xE6, 0x0C,
        ],
        [
            0x94, 0x40, 0x9B, 0x3C, 0x0F, 0x21, 0xDF, 0x96, 0x91, 0x59, 0x29, 0xE6, 0xC8, 0xFC,
            0xC2, 0x07, 0xC9, 0x58, 0x44, 0xA7, 0xED, 0xF5, 0x20, 0x22, 0xE6, 0x5E, 0x8F, 0x93,
            0xC9, 0xC9, 0x51, 0xBF,
        ],
        [
            0x7A, 0x85, 0x40, 0x71, 0xD6, 0x4A, 0x4B, 0x58, 0x8D, 0xD6, 0x20, 0xDF, 0x7F, 0xB1,
            0x34, 0x58, 0xD8, 0x8C, 0x5A, 0x6B, 0x55, 0xB0, 0x75, 0xCD, 0x6A, 0x52, 0x8F, 0x9D,
            0xB0, 0x08, 0xED, 0xC6,
        ],
        [
            0x4E, 0xC4, 0x9B, 0x94, 0xC3, 0x5A, 0x63, 0xC6, 0xD9, 0xDC, 0x45, 0x41, 0xF6, 0x30,
            0x55, 0x10, 0x9E, 0x91, 0x00, 0x05, 0x2C, 0xDA, 0x94, 0x6D, 0xB3, 0x76, 0xD1, 0x44,
            0xFA, 0x44, 0xD7, 0xD3,
        ],
        [
            0x00, 0x74, 0xC8, 0x8F, 0x71, 0x48, 0x6A, 0x2C, 0xEC, 0x90, 0x97, 0x05, 0x77, 0x9A,
            0x26, 0x9E, 0x42, 0xBB, 0x08, 0x97, 0x89, 0xAE, 0xE2, 0xB6, 0x6C, 0x58, 0x4F, 0x4E,
            0xE3, 0x51, 0x39, 0xA5,
        ],
    ];

    #[test]
    fn test_verify_and_insert() {
        let mut tree = SparseMerkleTree::new();
        let value = [42; HASH_SIZE];
        for key in SAMPLES {
            let non_inclusion = tree.generate_non_inclusion_proof(key).unwrap();

            // Insert should succeed for a new key
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
        let value = [42; HASH_SIZE];
        for key in SAMPLES {
            let mut sibling_key = key;
            // Flip least significant bit
            sibling_key[31] ^= 1;

            // Insert should succeed for a new key
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
        let value = [42; HASH_SIZE];
        for key in SAMPLES {
            // Insert should succeed for a new key
            assert!(tree.insert(key, value).is_ok());

            // The key should now exist in the tree
            assert!(tree.nodes.contains_key(&(TREE_DEPTH, key)));
        }
    }

    #[test]
    fn test_insert_existing_key() {
        let mut tree = SparseMerkleTree::new();
        let value = [42; HASH_SIZE];
        for key in SAMPLES {
            // First insertion should succeed
            assert!(tree.insert(key, value).is_ok());

            // Second insertion with the same key should fail
            assert!(tree.insert(key, [99; HASH_SIZE]).is_err());

            // The original value should still be in the tree

            // Hash leaf with key
            let leaf_hash = hash_concat(&value, &key);
            assert_eq!(tree.nodes.get(&(TREE_DEPTH, key)), Some(&leaf_hash));
        }
    }

    #[test]
    fn test_root_changes_after_insert() {
        let mut tree = SparseMerkleTree::new();
        let value = [42; HASH_SIZE];
        for key in SAMPLES {
            // Get the initial root
            let initial_root = tree.root();

            // Insert a key
            assert!(tree.insert(key, value).is_ok());

            // Root should have changed
            assert_ne!(tree.root(), initial_root);
        }
    }

    #[test]
    fn test_multiple_inserts() {
        let mut tree = SparseMerkleTree::new();

        // Insert multiple keys
        for (value, key) in SAMPLES.into_iter().enumerate() {
            assert!(tree.insert(key, [value as u8; HASH_SIZE]).is_ok());
        }

        // Verify all keys exist
        for key in SAMPLES {
            let leaf_key = trim_key(&key, TREE_DEPTH);
            assert!(tree.nodes.contains_key(&(TREE_DEPTH, leaf_key)));
        }

        // Try to insert an existing key
        for existing_key in SAMPLES {
            assert!(tree.insert(existing_key, [99; HASH_SIZE]).is_err());
        }
    }

    #[test]
    fn test_get_value() {
        let mut tree = SparseMerkleTree::new();
        let value = [45; HASH_SIZE];
        for key in SAMPLES {
            // Insert the key-value pair
            assert!(tree.insert(key, value).is_ok());

            // Get the value back
            assert_eq!(tree.get(&key).unwrap(), value);

            // Try to get a non-existent key
            let non_existent_key = [10; 32];
            assert!(tree.get(&non_existent_key).is_none());
        }
    }

    #[test]
    fn test_multiple_values() {
        let mut tree = SparseMerkleTree::new();

        // Insert multiple key-value pairs
        for (value, key) in SAMPLES.into_iter().enumerate() {
            assert!(tree.insert(key, [value as u8; HASH_SIZE]).is_ok());
        }

        // Retrieve each value
        for (value, key) in SAMPLES.into_iter().enumerate() {
            let expected = [value as u8; HASH_SIZE];
            assert_eq!(tree.get(&key).unwrap(), expected);
        }
    }

    #[test]
    fn test_verify_inclusion_proofs() {
        // Create a new tree
        let mut tree = SparseMerkleTree::new();

        for (value, key) in SAMPLES.into_iter().enumerate() {
            // Test non-existent key
            assert!(
                tree.generate_inclusion_proof(&key).is_err(),
                "Proof for non-existent key should fail"
            );
            // Insert key and test proof
            match tree.insert(key, [value as u8; HASH_SIZE]) {
                Ok(_) => {
                    let (proof, commitment) = tree.generate_inclusion_proof(&key).unwrap();
                    assert!(proof.verify(commitment, tree.root()));
                }
                Err(e) => panic!("Failed to insert key {:02X?}: {}", key, e),
            }
        }
    }

    #[test]
    fn test_verify_non_inclusion_proofs() {
        // Create a new tree
        let mut tree = SparseMerkleTree::new();

        for (value, key) in SAMPLES.into_iter().enumerate() {
            // Test non-inclusion proof
            let proof = tree.generate_non_inclusion_proof(key).unwrap();
            assert_eq!(proof.root, tree.root());
            assert!(proof.verify());

            // Insert key for next iteration
            tree.insert(key, [value as u8; HASH_SIZE]).unwrap();
        }
    }
}
