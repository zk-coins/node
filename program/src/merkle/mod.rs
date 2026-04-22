use sha2::{Digest, Sha256};

pub mod merkle_mountain_range;
pub mod sparse_merkle_tree;

pub const HASH_SIZE: usize = 32;
// TODO: This needs a better name
pub type HashDigest = [u8; HASH_SIZE];
pub const ZERO_HASH: HashDigest = [0u8; HASH_SIZE];

/// Compute the SHA256 hash of the concatenation of two 32-byte arrays.
pub fn hash_concat(left: &HashDigest, right: &HashDigest) -> HashDigest {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
