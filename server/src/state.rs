use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use shared::commitment::Commitment;
use std::collections::HashMap;
use std::io;
use zkcoins_program::hash::{
    digest_from_bytes, digest_to_bytes, hash_concat, HashDigest, ZERO_HASH,
};
use zkcoins_program::merkle::merkle_mountain_range::{
    load_mmr, save_mmr, MMRProof, MerkleMountainRange,
};
use zkcoins_program::merkle::sparse_merkle_tree::{
    load_merkle_tree, save_merkle_tree, InclusionProof, SparseMerkleTree,
};

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

            // Store the BIP-340 message digest (32 raw bytes) reinterpreted
            // as a Poseidon `HashOut<F>` — `digest_from_bytes` is the
            // canonical inverse of `digest_to_bytes` (round-trip safe).
            let message_bytes = commitment.get_account_state_hash();
            let message_data = digest_from_bytes(&message_bytes);

            // Update the SMT with just the message
            self.smt.insert(key, message_data)?;
        }

        // 2. Get the current SMT root
        let smt_root = self.smt.root();

        // 3. Create a new leaf that combines the SMT root and previous MMR root.
        // Uses Poseidon `hash_concat` (architectural invariant: Poseidon
        // everywhere in Merkle structures). Replaces the SP1-era SHA256.
        let prev_mmr_root = self.mmr.root();
        self.prev_mmr_root = prev_mmr_root;

        let leaf = hash_concat(&smt_root, &prev_mmr_root);

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
    pub fn get_mmr_inclusion_proof(
        &self,
        prev_mmr_root: HashDigest,
    ) -> Result<(HashDigest, MMRProof), &'static str> {
        match self.root_indices.get(&prev_mmr_root) {
            Some(&(smt_root, index)) => self.mmr.get_proof(index).map(|proof| (smt_root, proof)),
            None => Err("Couldn't find MMR inclusion proof"),
        }
    }

    /// Gets an inclusion proof for a specific commitment in the SMT,
    /// along with an inclusion proof of the current SMT root in the MMR.
    pub fn get_commitment_proof(
        &self,
        public_key: &PublicKey,
    ) -> Result<(HashDigest, InclusionProof, HashDigest, MMRProof), &'static str> {
        let key_bytes = public_key.serialize();
        let key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&key_bytes).to_byte_array();

        let (smt_proof, commitment) = self.smt.generate_inclusion_proof(&key)?;

        let smt_root = self.smt.root();

        let leaf_count = self.mmr.leaf_count();
        if leaf_count == 0 {
            return Err("MMR leaf count = 0");
        }
        let latest_leaf_index = leaf_count - 1;

        let mmr_proof = self.mmr.get_proof(latest_leaf_index)?;

        Ok((commitment, smt_proof, smt_root, mmr_proof))
    }

    /// Saves the state to two files: one for the SMT and one for the MMR.
    pub fn save_to_files(&self, smt_path: &str, mmr_path: &str) -> io::Result<()> {
        save_merkle_tree(&self.smt, smt_path)?;
        save_mmr(&self.mmr, mmr_path)?;

        // Save prev_mmr_root to a separate file as 32 raw bytes.
        let prev_root_path = format!("{}.prev_root", mmr_path);
        crate::atomic_write(&prev_root_path, &digest_to_bytes(&self.prev_mmr_root))?;

        Ok(())
    }

    /// Loads the state from two files: one for the SMT and one for the MMR.
    pub fn load_from_files(smt_path: &str, mmr_path: &str) -> io::Result<Self> {
        let smt = load_merkle_tree(smt_path)?;
        let mmr = load_mmr(mmr_path)?;

        // Load prev_mmr_root from its file
        let prev_root_path = format!("{}.prev_root", mmr_path);
        let prev_mmr_root = match std::fs::read(prev_root_path) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut root_bytes = [0u8; 32];
                root_bytes.copy_from_slice(&bytes);
                digest_from_bytes(&root_bytes)
            }
            // If file doesn't exist or has wrong size, use zeros
            _ => ZERO_HASH,
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
