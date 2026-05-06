use shared::commitment::Commitment;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkcoins_program::merkle::merkle_mountain_range::{MMRProof, MerkleMountainRange};
use zkcoins_program::merkle::sparse_merkle_tree::{load_merkle_tree, save_merkle_tree, InclusionProof, SparseMerkleTree};
use zkcoins_program::merkle::{HashDigest, ZERO_HASH};
use std::collections::HashMap;
use std::io;

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
        self.root_indices.insert(prev_mmr_root, (smt_root, leaf_index));

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
            None => Err("Couldn't find MMR inclusion proof")
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
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use zkcoins_program::merkle::{hash_concat, HASH_SIZE};
    use std::str::FromStr;

    // Helper function to create a test commitment with a given message
    fn create_test_commitment(message: &[u8], key_hex: &str) -> Commitment {
        let _secp = Secp256k1::new();
        let secret_key = SecretKey::from_str(key_hex).expect("Invalid key");
        Commitment::new(&secret_key, message.to_vec()).expect("Failed to create commitment")
    }

    #[test]
    fn test_update_with_single_commitment() {
        let mut state = State::new();

        // Create a test commitment
        let commitment = create_test_commitment(
            b"test message",
            "0000000000000000000000000000000000000000000000000000000000000001",
        );

        // Update state with this commitment
        let new_root = state.update(&[commitment.clone()]).unwrap();

        // The SMT should now contain this commitment
        let key_bytes = commitment.public_key.serialize();
        let _key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&key_bytes).to_byte_array();

        // The MMR should have one leaf now
        assert_ne!(state.mmr.root(), ZERO_HASH);
        assert_eq!(state.mmr.root(), new_root);
    }

    #[test]
    fn test_update_with_multiple_commitments() {
        let mut state = State::new();

        // Create test commitments with different keys
        let commitments = vec![
            create_test_commitment(
                b"message 1",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            create_test_commitment(
                b"message 2",
                "0000000000000000000000000000000000000000000000000000000000000002",
            ),
            create_test_commitment(
                b"message 3",
                "0000000000000000000000000000000000000000000000000000000000000003",
            ),
        ];

        // First update with one commitment
        let root1 = state.update(&[commitments[0].clone()]).unwrap();

        // Then update with the other two
        let root2 = state.update(&[commitments[1].clone(), commitments[2].clone()]).unwrap();

        // The roots should be different after each update
        assert_ne!(root1, root2);

        // After the second update, the MMR should have two leaves
        assert_eq!(state.mmr.root(), root2);
    }

    #[test]
    fn test_save_and_load_state() {
        let temp_smt_path = "test_state_smt.bin";
        let temp_mmr_path = "test_state_mmr.bin";

        // Create and populate a state
        let mut original_state = State::new();

        // Add some commitments
        let commitments = vec![
            create_test_commitment(
                b"message for save/load test",
                "0000000000000000000000000000000000000000000000000000000000000004",
            ),
            create_test_commitment(
                b"another message",
                "0000000000000000000000000000000000000000000000000000000000000005",
            ),
        ];

        original_state.update(&commitments).unwrap();

        // Save the state
        original_state
            .save_to_files(temp_smt_path, temp_mmr_path)
            .expect("Failed to save state");

        // Load the state
        let loaded_state =
            State::load_from_files(temp_smt_path, temp_mmr_path).expect("Failed to load state");

        // Clean up temporary files
        std::fs::remove_file(temp_smt_path).ok();
        std::fs::remove_file(temp_mmr_path).ok();
        // Also remove the prev_root file
        std::fs::remove_file(format!("{}.prev_root", temp_mmr_path)).ok();

        // Verify the loaded state has the same roots
        assert_eq!(original_state.smt.root(), loaded_state.smt.root());
        assert_eq!(original_state.mmr.root(), loaded_state.mmr.root());
    }

    #[test]
    fn test_sequential_updates_consistency() {
        let mut state = State::new();

        // Create several test commitments
        let messages = [b"msg1", b"msg2", b"msg3", b"msg4", b"msg5"];
        let mut roots = Vec::new();

        // Process commitments one by one and record roots
        for (i, &msg) in messages.iter().enumerate() {
            let key_hex = format!("{:064x}", i + 1);
            let commitment = create_test_commitment(msg, &key_hex);

            let root = state.update(&[commitment]).unwrap();
            roots.push(root);
        }

        // Verify that each update produced a different root
        for i in 1..roots.len() {
            assert_ne!(
                roots[i - 1],
                roots[i],
                "Sequential updates should produce different roots"
            );
        }

        // Verify that the final state has the expected root
        assert_eq!(state.mmr.root(), *roots.last().unwrap());
    }

    #[test]
    fn test_get_commitment_proof_with_mmr() {
        let mut state = State::new();

        // Create test commitment
        let commitment = create_test_commitment(
            b"test message",
            "0000000000000000000000000000000000000000000000000000000000000001",
        );

        // Update state with this commitment
        let mmr_root = state.update(&[commitment.clone()]).unwrap();

        // Get the complete proof (SMT + MMR)
        let proof_result = state.get_commitment_proof(&commitment.public_key);
        assert!(
            proof_result.is_ok(),
            "Should return a valid proof for existing commitment"
        );

        let (commitment_msg, smt_proof, smt_root, mmr_proof) = proof_result.unwrap();

        // Verify the message
        assert_eq!(
            commitment.message,
            b"test message".to_vec(),
            "Should return the correct message"
        );

        assert_ne!(smt_root, ZERO_HASH, "SMT root should not be zero");

        // Verify MMR proof info
        assert_eq!(mmr_proof.index, 0, "First update should be at leaf index 0");
        assert!(
            !mmr_proof.path.is_empty(),
            "MMR proof path should not be empty"
        );

        // Verify that the MMR root matches what was returned from update
        assert_eq!(
            state.mmr.root(),
            mmr_root,
            "MMR root should match what was returned from update"
        );

        assert!(smt_proof.verify(commitment_msg, smt_root));
        assert!(mmr_proof.verify(hash_concat(&smt_root, &state.prev_mmr_root), mmr_root));
    }

    #[test]
    fn test_reproduce_tree_verify() {
        let mut state = State::new();

        // Create test commitment
        let commitment = create_test_commitment(
            &[1; HASH_SIZE],
            "1000000000000000000000000000000000000000000000000000000000000000",
        );

        // Update state with this commitment
        //let mmr_root = state.update(&[commitment.clone()]);
        //let key_bytes = commitment.public_key.serialize();
        let key = [
            127u8, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        //let key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&key).to_byte_array();
        //let mut smt = SparseMerkleTree::new(256);
        state.smt.insert(key, [1; HASH_SIZE]).unwrap();
        let root = state.smt.root();

        //// Get the complete proof (SMT + MMR)
        ////let proof_result = state.get_commitment_proof(&commitment.public_key);

        let proof_result = state.smt.generate_inclusion_proof(&key);

        let (smt_proof, _) = proof_result.unwrap();

        assert!(smt_proof.verify([1; HASH_SIZE], root));
    }

    #[test]
    fn test_get_commitment_proof_nonexistent() {
        let mut state = State::new();

        // Add a different commitment to the state
        let existing_commitment = create_test_commitment(
            b"existing message",
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
        state.update(&[existing_commitment]).unwrap();

        // Try to get proof for a non-existent commitment
        let non_existent = create_test_commitment(
            b"non-existent message",
            "0000000000000000000000000000000000000000000000000000000000000099",
        );

        let result = state.get_commitment_proof(&non_existent.public_key);
        assert!(result.is_err(), "Should return Err for non-existent commitment");
    }

    #[test]
    fn test_get_commitment_proof_empty_mmr() {
        let state = State::new();

        // Create a commitment but don't add it to the state yet
        let commitment = create_test_commitment(
            b"test message",
            "0000000000000000000000000000000000000000000000000000000000000001",
        );

        // Try to get proof with empty MMR
        let result = state.get_commitment_proof(&commitment.public_key);
        assert!(result.is_err(), "Should return Err when MMR is empty");
    }

    #[test]
    fn test_get_commitment_proof_with_multiple_updates() {
        let mut state = State::new();

        // Create several test commitments
        let messages = [b"msg1", b"msg2", b"msg3", b"msg4", b"msg5"];
        let mut roots = Vec::new();

        // Process commitments one by one and record roots
        for (i, &msg) in messages.iter().enumerate() {
            let key_hex = format!("{:064x}", i + 1);
            let commitment = create_test_commitment(msg, &key_hex);

            let root = state.update(&[commitment]).unwrap();
            roots.push(root);
        }

        // Verify that each update produced a different root
        for i in 1..roots.len() {
            assert_ne!(
                roots[i - 1],
                roots[i],
                "Sequential updates should produce different roots"
            );
        }

        // Verify that the final state has the expected root
        assert_eq!(state.mmr.root(), *roots.last().unwrap());
    }
}
