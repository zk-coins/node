use super::*;
use crate::db::{connect_and_migrate, persist_state_tx};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use sqlx::PgPool;
use std::str::FromStr;
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use zkcoins_program::circuit::main::MMR_PROOF_PATH_LEN;
use zkcoins_program::hash::hash_concat;

const HASH_SIZE: usize = 32;

// Helper function to create a test commitment with a given message
fn create_test_commitment(message: &[u8], key_hex: &str) -> Commitment {
    let _secp = Secp256k1::new();
    let secret_key = SecretKey::from_str(key_hex).expect("Invalid key");
    Commitment::new(&secret_key, message.to_vec()).expect("Failed to create commitment")
}

/// Start a fresh `postgres:17` container and connect a migrated pool
/// to it. The container handle is returned alongside the pool so the
/// caller can keep it alive for the duration of the test — dropping
/// it tears the container down.
///
/// This mirrors `db_tests::setup_pool` deliberately rather than
/// sharing a helper module; both files keep their setups inline so
/// each is independently runnable / readable. PR-A3 may dedupe into a
/// `test_db` helper once the PR-A2/A3 churn settles.
async fn setup_pool() -> (PgPool, ContainerAsync<Postgres>) {
    let container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = container
        .get_host()
        .await
        .expect("failed to get container host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to get container port");
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = connect_and_migrate(&url)
        .await
        .expect("connect_and_migrate failed");
    (pool, container)
}

#[tokio::test]
async fn test_update_with_single_commitment() {
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

#[tokio::test]
async fn test_update_with_multiple_commitments() {
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

#[tokio::test]
async fn test_persist_and_load_state_roundtrip() {
    // Migration of the old `test_save_and_load_state`: persist via
    // `db::persist_state_tx` and reload via `State::load_from_pg`.
    // Roots must round-trip — that is the structural guarantee the
    // file-based pair used to provide, now backed by an atomic
    // BEGIN/COMMIT in Postgres (issue #11 fix).
    let (pool, _container) = setup_pool().await;

    // Create and populate a state
    let mut original_state = State::new();
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

    // Serialize + persist atomically.
    let (smt_bytes, mmr_bytes) = original_state.serialize_for_persist().unwrap();
    let block_hash = [0xABu8; 32];
    persist_state_tx(&pool, &smt_bytes, &mmr_bytes, &block_hash)
        .await
        .expect("persist_state_tx failed");

    // Reload from Postgres.
    let loaded_state = State::load_from_pg(&pool).await.expect("load_from_pg");

    // Verify the loaded state has the same roots
    assert_eq!(original_state.smt.root(), loaded_state.smt.root());
    assert_eq!(original_state.mmr.root(), loaded_state.mmr.root());
}

#[tokio::test]
async fn test_load_from_pg_empty_returns_fresh_state() {
    // No rows in smt_state / mmr_state means a fresh server: both
    // trees must come back empty — equivalent to State::new().
    let (pool, _container) = setup_pool().await;
    let loaded = State::load_from_pg(&pool).await.expect("load_from_pg");
    let fresh = State::new();
    assert_eq!(loaded.smt.root(), fresh.smt.root());
    assert_eq!(loaded.mmr.root(), fresh.mmr.root());
    assert_eq!(loaded.prev_mmr_root, ZERO_HASH);
    assert!(loaded.root_indices.is_empty());
}

#[tokio::test]
async fn test_load_from_pg_returns_err_on_corrupted_smt_blob() {
    // The `Deserialize` branch of `LoadStateError`: insert a row whose
    // bytes can never be decoded as a `SparseMerkleTree` and assert
    // the loader surfaces that as `LoadStateError::Deserialize` rather
    // than panicking or silently falling back to `State::new()`.
    let (pool, _container) = setup_pool().await;
    sqlx::query("INSERT INTO smt_state (id, data) VALUES (1, $1)")
        .bind(vec![0xFFu8; 8])
        .execute(&pool)
        .await
        .unwrap();
    let err = State::load_from_pg(&pool)
        .await
        .expect_err("expected deserialize error");
    assert!(
        matches!(err, crate::state::LoadStateError::Deserialize(_)),
        "unexpected: {:?}",
        err
    );
    // Display + source: exercise the Error / Display impls so the
    // 100% coverage gate stays green on the trait surface.
    let msg = format!("{}", err);
    assert!(msg.contains("state blob deserialize"));
    assert!(std::error::Error::source(&err).is_some());
}

#[tokio::test]
async fn test_load_from_pg_returns_err_on_corrupted_mmr_blob() {
    // Same as the SMT corruption test, but for the MMR row.
    // Persist a valid SMT first so we exercise the second
    // deserialize branch.
    let (pool, _container) = setup_pool().await;
    let empty_smt = bincode::serialize(&SparseMerkleTree::new()).unwrap();
    sqlx::query("INSERT INTO smt_state (id, data) VALUES (1, $1)")
        .bind(empty_smt)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mmr_state (id, data) VALUES (1, $1)")
        .bind(vec![0xFFu8; 8])
        .execute(&pool)
        .await
        .unwrap();
    let err = State::load_from_pg(&pool)
        .await
        .expect_err("expected deserialize error");
    assert!(
        matches!(err, crate::state::LoadStateError::Deserialize(_)),
        "unexpected: {:?}",
        err
    );
}

#[tokio::test]
async fn test_load_from_pg_propagates_db_error() {
    // Build a pool that connects to nothing, then call load_from_pg.
    // The pool's first query attempt times out → `sqlx::Error` → our
    // `LoadStateError::Db` variant. Covers the `From<sqlx::Error>`
    // and the `LoadStateError::Db` Display branch.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(100))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/postgres")
        .expect("connect_lazy never fails");
    let err = State::load_from_pg(&pool)
        .await
        .expect_err("expected db error");
    assert!(
        matches!(err, crate::state::LoadStateError::Db(_)),
        "unexpected: {:?}",
        err
    );
    let msg = format!("{}", err);
    assert!(msg.contains("database error"));
    assert!(std::error::Error::source(&err).is_some());
}

#[tokio::test]
async fn test_serialize_for_persist_roundtrip() {
    // The serialize helper must produce blobs that load_from_pg
    // accepts back. Belt-and-braces against any silent format drift
    // between the two halves of the persistence layer.
    let mut state = State::new();
    state
        .update(&[create_test_commitment(
            b"roundtrip",
            "0000000000000000000000000000000000000000000000000000000000000006",
        )])
        .unwrap();

    let (pool, _container) = setup_pool().await;
    let (smt_bytes, mmr_bytes) = state.serialize_for_persist().unwrap();
    persist_state_tx(&pool, &smt_bytes, &mmr_bytes, &[0u8; 32])
        .await
        .unwrap();
    let loaded = State::load_from_pg(&pool).await.unwrap();
    assert_eq!(loaded.smt.root(), state.smt.root());
    assert_eq!(loaded.mmr.root(), state.mmr.root());
}

#[tokio::test]
async fn test_sequential_updates_consistency() {
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

#[tokio::test]
async fn test_get_commitment_proof_with_mmr() {
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

#[tokio::test]
async fn test_reproduce_tree_verify() {
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

#[tokio::test]
async fn test_get_commitment_proof_nonexistent() {
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

#[tokio::test]
async fn test_get_commitment_proof_empty_mmr() {
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

#[tokio::test]
async fn test_get_commitment_proof_with_multiple_updates() {
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

#[tokio::test]
async fn test_get_mmr_inclusion_proof_unknown_root_returns_err() {
    // get_mmr_inclusion_proof must return Err when the previous MMR
    // root passed in is not tracked in root_indices.
    let state = State::new();
    let unknown_root = zkcoins_program::hash::digest_from_bytes(&[99u8; 32]);
    let result = state.get_mmr_inclusion_proof(unknown_root);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_mmr_inclusion_proof_known_root_returns_ok() {
    // After update(), root_indices maps the pre-update MMR root to a
    // (smt_root, leaf_index) tuple — feeding that root back must
    // return Ok and the leaf must verify against the post-update MMR
    // root via the returned proof. The recorded root is the *extended*
    // form (`root_extended(MMR_PROOF_PATH_LEN)`) so it matches what a
    // Plonky2 proof commits as `commitment_history_root`.
    let mut state = State::new();
    let pre_root = state.mmr.root_extended(MMR_PROOF_PATH_LEN);

    let commitment = create_test_commitment(
        b"known-root test",
        "0000000000000000000000000000000000000000000000000000000000000007",
    );
    let _post_root = state.update(&[commitment]).expect("update");
    let post_root_extended = state.mmr.root_extended(MMR_PROOF_PATH_LEN);

    let (smt_root, proof) = state
        .get_mmr_inclusion_proof(pre_root)
        .expect("inclusion proof for known prev_mmr_root");
    let leaf = hash_concat(&smt_root, &pre_root);
    let proof_extended = proof.extend_to(MMR_PROOF_PATH_LEN);
    assert!(proof_extended.verify(leaf, post_root_extended));
}

#[tokio::test]
async fn test_get_commitment_proof_returns_err_when_smt_has_key_but_mmr_empty() {
    // This inconsistent state cannot arise from normal operation
    // (update() always grows both trees together) — it is reached
    // only by loading mismatched on-disk state. The defensive guard
    // in get_commitment_proof must return Err rather than panic on
    // the leaf_count - 1 subtraction.
    //
    // In the Postgres world the equivalent inconsistent state is
    // synthesized by persisting a non-empty SMT alongside an empty
    // MMR directly, then reloading.
    let (pool, _container) = setup_pool().await;

    let mut populated = State::new();
    let commitment = create_test_commitment(
        b"mismatched scenario",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    populated.update(std::slice::from_ref(&commitment)).unwrap();

    // Persist the populated SMT but an EMPTY MMR (overwrite the MMR
    // row with the freshly-constructed empty tree).
    let smt_bytes = bincode::serialize(&populated.smt).unwrap();
    let empty_mmr_bytes = bincode::serialize(&MerkleMountainRange::new()).unwrap();
    persist_state_tx(&pool, &smt_bytes, &empty_mmr_bytes, &[0u8; 32])
        .await
        .unwrap();

    let mismatched = State::load_from_pg(&pool).await.unwrap();
    let result = mismatched.get_commitment_proof(&commitment.public_key);
    assert!(result.is_err());
}
