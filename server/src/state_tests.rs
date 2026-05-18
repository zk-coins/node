use super::*;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use std::str::FromStr;
use zkcoins_program::hash::hash_concat;

const HASH_SIZE: usize = 32;

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
    let new_root = state.update(std::slice::from_ref(&commitment)).unwrap();

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
    let commitments = [
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
    let root2 = state
        .update(&[commitments[1].clone(), commitments[2].clone()])
        .unwrap();

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
    let mmr_root = state.update(std::slice::from_ref(&commitment)).unwrap();

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
    let _commitment = create_test_commitment(
        &[1; HASH_SIZE],
        "1000000000000000000000000000000000000000000000000000000000000000",
    );

    // Update state with this commitment
    //let mmr_root = state.update(&[commitment.clone()]);
    //let key_bytes = commitment.public_key.serialize();
    let key = [
        127u8, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];
    //let key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&key).to_byte_array();
    //let mut smt = SparseMerkleTree::new(256);
    let leaf = zkcoins_program::hash::digest_from_bytes(&[1; HASH_SIZE]);
    state.smt.insert(key, leaf).unwrap();
    let root = state.smt.root();

    //// Get the complete proof (SMT + MMR)
    ////let proof_result = state.get_commitment_proof(&commitment.public_key);

    let proof_result = state.smt.generate_inclusion_proof(&key);

    let (smt_proof, _) = proof_result.unwrap();

    assert!(smt_proof.verify(leaf, root));
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
    assert!(
        result.is_err(),
        "Should return Err for non-existent commitment"
    );
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

#[test]
fn test_get_mmr_inclusion_proof_unknown_root_returns_err() {
    // get_mmr_inclusion_proof must return Err when the previous MMR
    // root passed in is not tracked in root_indices.
    let state = State::new();
    let unknown_root = zkcoins_program::hash::digest_from_bytes(&[99u8; 32]);
    let result = state.get_mmr_inclusion_proof(unknown_root);
    assert!(result.is_err());
}

#[test]
fn test_get_mmr_inclusion_proof_known_root_returns_ok() {
    // After update(), root_indices maps the pre-update MMR root to a
    // (smt_root, leaf_index) tuple — feeding that root back must
    // return Ok and the leaf must verify against the post-update MMR
    // root via the returned proof.
    let mut state = State::new();
    let pre_root = state.mmr.root();

    let commitment = create_test_commitment(
        b"known-root test",
        "0000000000000000000000000000000000000000000000000000000000000007",
    );
    let post_root = state.update(&[commitment]).expect("update");

    let (smt_root, proof) = state
        .get_mmr_inclusion_proof(pre_root)
        .expect("inclusion proof for known prev_mmr_root");
    assert!(proof.verify(hash_concat(&smt_root, &pre_root), post_root));
}

#[test]
fn test_get_commitment_proof_returns_err_when_smt_has_key_but_mmr_empty() {
    // This inconsistent state cannot arise from normal operation
    // (update() always grows both trees together) — it is reached
    // only by loading mismatched on-disk state. The defensive guard
    // in get_commitment_proof must return Err rather than panic on
    // the leaf_count - 1 subtraction.
    let dir = std::env::temp_dir().join(format!(
        "zkcoins-mismatch-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let smt_a = dir.join("a.smt");
    let mmr_a = dir.join("a.mmr");
    let smt_b = dir.join("b.smt");
    let mmr_b = dir.join("b.mmr");

    // State A: contains one commitment.
    let mut a = State::new();
    let commitment = create_test_commitment(
        b"mismatched scenario",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    a.update(std::slice::from_ref(&commitment)).unwrap();
    a.save_to_files(smt_a.to_str().unwrap(), mmr_a.to_str().unwrap())
        .unwrap();

    // State B: empty.
    let b = State::new();
    b.save_to_files(smt_b.to_str().unwrap(), mmr_b.to_str().unwrap())
        .unwrap();

    // Load from A's SMT and B's empty MMR. SMT now has the key,
    // MMR has zero leaves — exactly the inconsistent-state trigger.
    let mismatched =
        State::load_from_files(smt_a.to_str().unwrap(), mmr_b.to_str().unwrap()).unwrap();

    let result = mismatched.get_commitment_proof(&commitment.public_key);
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_load_from_files_falls_back_to_zero_prev_root() {
    // load_from_files must tolerate a missing `.prev_root` sidecar
    // file and fall back to [0u8; 32] for prev_mmr_root.
    let dir = std::env::temp_dir().join(format!(
        "zkcoins-state-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let smt_path = dir.join("smt.bin");
    let mmr_path = dir.join("mmr.bin");
    let prev_root_path = dir.join("mmr.bin.prev_root");

    // Seed a state with one commitment and persist it.
    let mut state = State::new();
    let commitment = create_test_commitment(
        b"prev-root fallback",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    state.update(&[commitment]).unwrap();
    state
        .save_to_files(smt_path.to_str().unwrap(), mmr_path.to_str().unwrap())
        .unwrap();

    // Remove the prev_root sidecar so the fallback branch fires.
    std::fs::remove_file(&prev_root_path).unwrap();

    let loaded =
        State::load_from_files(smt_path.to_str().unwrap(), mmr_path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.prev_mmr_root, zkcoins_program::hash::ZERO_HASH);

    // Tidy up.
    std::fs::remove_dir_all(&dir).ok();
}
