use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::commitment::Commitment;
use std::collections::HashMap;
use std::io;
use zkcoins_program::merkle::merkle_mountain_range::{MMRProof, MerkleMountainRange};
use zkcoins_program::merkle::sparse_merkle_tree::{
    load_merkle_tree, save_merkle_tree, InclusionProof, SparseMerkleTree,
};
use zkcoins_program::merkle::{HashDigest, ZERO_HASH};

/// State stores both a Sparse Merkle Tree (for individual commitments)
/// and a Merkle Mountain Range (for accumulating SMT roots).
#[derive(Serialize, Deserialize)]
pub struct State {
    /// The Sparse Merkle Tree to store individual commitments
    pub smt: SparseMerkleTree,
    /// The Merkle Mountain Range to accumulate SMT roots
    pub mmr: MerkleMountainRange,
    /// Maps previous MMR roots to (SMT root, leaf index) pairs
    pub root_indices: HashMap<HashDigest, (HashDigest, usize)>,
    /// The previous MMR root
    pub prev_mmr_root: HashDigest,
}

impl State {
    /// Creates a new state with an empty SMT of the default depth and an empty MMR.
    pub fn new() -> Self {
        State {
            smt: SparseMerkleTree::new(),
            mmr: MerkleMountainRange::new(),
            root_indices: HashMap::new(),
            prev_mmr_root: ZERO_HASH,
        }
    }

    /// Updates the state by inserting a set of commitments into the SMT,
    /// then appending a new leaf to the MMR that combines the new SMT root
    /// and the previous MMR root.
    ///
    /// Returns the new MMR root.
    pub fn update(&mut self, commitments: &[Commitment]) -> Result<HashDigest, &'static str> {
        // 1. Insert all commitments into the SMT
        for commitment in commitments {
            // Use the public key as the key for the tree (hashed)
            let key_bytes = commitment.public_key.serialize();
            let key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&key_bytes).to_byte_array();

            // Store only the message instead of the entire commitment
            let message_data = commitment.get_account_state_hash();

            // Update the SMT with just the message
            self.smt.insert(key, message_data)?;
        }

        // 2. Get the current SMT root
        let smt_root = self.smt.root();

        // 3. Create a new leaf that combines the SMT root and previous MMR root
        let prev_mmr_root = self.mmr.root();
        self.prev_mmr_root = prev_mmr_root;

        // Combine the SMT root and previous MMR root into a single hash
        let mut hasher = Sha256::new();
        hasher.update(smt_root);
        hasher.update(prev_mmr_root);
        let combined_hash = hasher.finalize();
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&combined_hash);

        // Store the mapping of previous MMR root to (SMT root, leaf index)
        let leaf_index = self.mmr.leaf_count();
        self.root_indices
            .insert(prev_mmr_root, (smt_root, leaf_index));

        // 4. Append the new leaf to the MMR
        self.mmr.append(leaf);

        // 5. Return the new MMR root
        Ok(self.mmr.root())
    }

    /// Gets an inclusion proof for a leaf in the MMR that was created with the given previous MMR root.
    ///
    /// Returns:
    /// - The SMT root that was combined with this previous MMR root
    /// - The inclusion proof for the leaf in the MMR
    /// - None if the previous MMR root is not found
    pub fn get_mmr_inclusion_proof(
        &self,
        prev_mmr_root: HashDigest,
    ) -> Result<(HashDigest, MMRProof), &'static str> {
        // Look up the index and SMT root for this previous MMR root
        match self.root_indices.get(&prev_mmr_root) {
            // Get the inclusion proof for this index from the MMR
            Some(&(smt_root, index)) => self.mmr.get_proof(index).map(|proof| (smt_root, proof)),
            None => Err("Couldn't find MMR inclusion proof"),
        }
    }

    /// Gets an inclusion proof for a specific commitment in the SMT,
    /// along with an inclusion proof of the current SMT root in the MMR.
    ///
    /// Args:
    ///   commitment: The commitment to get the proof for (only the public key is used)
    ///
    /// Returns:
    ///   - Some((commitment, smt_proof, smt_root, mmr_proof)) if the commitment exists in the SMT
    ///   - None if the commitment doesn't exist or if there's no leaf in the MMR
    pub fn get_commitment_proof(
        &self,
        public_key: &PublicKey,
    ) -> Result<(HashDigest, InclusionProof, HashDigest, MMRProof), &'static str> {
        // Hash the public key to get the key in the SMT
        let key_bytes = public_key.serialize();
        let key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&key_bytes).to_byte_array();

        // Get the inclusion proof from the SMT
        // Convert Result to Option - if there's an error, return None
        let (smt_proof, commitment) = self.smt.generate_inclusion_proof(&key)?;

        // Get the current SMT root
        let smt_root = self.smt.root();

        // Get the latest leaf index in the MMR
        let leaf_count = self.mmr.leaf_count();
        if leaf_count == 0 {
            return Err("MMR leaf count = 0");
        }
        let latest_leaf_index = leaf_count - 1;

        // Get the MMR inclusion proof for the latest leaf
        let mmr_proof = self.mmr.get_proof(latest_leaf_index)?;

        Ok((commitment, smt_proof, smt_root, mmr_proof))
    }

    /// Saves the state to two files: one for the SMT and one for the MMR.
    pub fn save_to_files(&self, smt_path: &str, mmr_path: &str) -> io::Result<()> {
        // Save SMT
        save_merkle_tree(&self.smt, smt_path)?;

        // Save MMR
        self.mmr.save_to_file(mmr_path)?;

        // Save prev_mmr_root to a separate file
        let prev_root_path = format!("{}.prev_root", mmr_path);
        crate::atomic_write(&prev_root_path, &self.prev_mmr_root)?;

        Ok(())
    }

    /// Loads the state from two files: one for the SMT and one for the MMR.
    pub fn load_from_files(smt_path: &str, mmr_path: &str) -> io::Result<Self> {
        // Load SMT
        let smt = load_merkle_tree(smt_path)?;

        // Load MMR
        let mmr = MerkleMountainRange::load_from_file(mmr_path)?;

        // Load prev_mmr_root from its file
        let prev_root_path = format!("{}.prev_root", mmr_path);
        let prev_mmr_root = match std::fs::read(prev_root_path) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut root = [0u8; 32];
                root.copy_from_slice(&bytes);
                root
            }
            // If file doesn't exist or has wrong size, use zeros
            _ => [0u8; 32],
        };

        // Initialize an empty root_indices map
        let root_indices = HashMap::new();

        Ok(State {
            smt,
            mmr,
            root_indices,
            prev_mmr_root,
        })
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
