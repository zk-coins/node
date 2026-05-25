use super::*;
use crate::db::{connect_and_migrate, insert_root_index, load_root_indices, persist_state_tx};
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Network;
use shared::SECP256K1;
use sqlx::PgPool;
use std::str::FromStr;
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use zkcoins_program::circuit::main::MMR_PROOF_PATH_LEN;
use zkcoins_program::hash::{digest_from_bytes, hash_concat};

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
    persist_state_tx(&pool, &smt_bytes, &mmr_bytes, &block_hash, None)
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
    persist_state_tx(&pool, &smt_bytes, &mmr_bytes, &[0u8; 32], None)
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

    // Get the complete proof (SMT + MMR). `.expect` itself asserts
    // the Ok arm — a redundant `assert!(.is_ok())` before unwrap would
    // double-emit on the same failure mode.
    let (commitment_msg, smt_proof, smt_root, mmr_proof) = state
        .get_commitment_proof(&commitment.public_key)
        .expect("Should return a valid proof for existing commitment");

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
    persist_state_tx(&pool, &smt_bytes, &empty_mmr_bytes, &[0u8; 32], None)
        .await
        .unwrap();

    let mismatched = State::load_from_pg(&pool).await.unwrap();
    let result = mismatched.get_commitment_proof(&commitment.public_key);
    assert!(result.is_err());
}

// ---- Phase C: mmr_root_index persistence ----------------------------------

/// Drive `State::update` N times and persist each step atomically via
/// the extended [`persist_state_tx`] (SMT/MMR/latest_block +
/// `mmr_root_index` in one transaction). Mirrors the production
/// scanner-callback shape after the Phase-C atomicity fix.
async fn populate_state_with_persistence(pool: &PgPool, count: usize) -> State {
    let mut state = State::new();
    for i in 0..count {
        let key_hex = format!("{:064x}", i + 1);
        let commitment = create_test_commitment(format!("phase-c-{}", i).as_bytes(), &key_hex);
        state.update(&[commitment]).expect("update");
        let (smt_root, leaf_index) = *state
            .root_indices
            .get(&state.prev_mmr_root)
            .expect("update inserted root_indices entry keyed by prev_mmr_root");
        let (smt_bytes, mmr_bytes) = state.serialize_for_persist().unwrap();
        persist_state_tx(
            pool,
            &smt_bytes,
            &mmr_bytes,
            &[0u8; 32],
            Some((&state.prev_mmr_root, &smt_root, leaf_index as u64)),
        )
        .await
        .expect("persist_state_tx");
    }
    state
}

#[tokio::test]
async fn test_root_indices_persist_and_load_roundtrip() {
    // Drive a handful of updates with per-update persistence, drop the
    // in-memory state, reload via `State::load_from_pg`, and assert
    // that the HashMap content + `prev_mmr_root` round-trip.
    let (pool, _container) = setup_pool().await;
    let original = populate_state_with_persistence(&pool, 3).await;

    // Sanity: the in-memory map has exactly the number of updates we
    // ran (each update inserts a fresh `prev_mmr_root` key because the
    // MMR grows monotonically).
    assert_eq!(original.root_indices.len(), 3);
    let original_prev = original.prev_mmr_root;
    let original_entries: Vec<(HashDigest, (HashDigest, usize))> = original
        .root_indices
        .iter()
        .map(|(k, v)| (*k, *v))
        .collect();
    drop(original);

    let loaded = State::load_from_pg(&pool).await.expect("load_from_pg");
    assert_eq!(loaded.root_indices.len(), 3);
    for (key, value) in &original_entries {
        assert_eq!(
            loaded.root_indices.get(key).copied(),
            Some(*value),
            "root_indices entry must round-trip"
        );
    }
    assert_eq!(
        loaded.prev_mmr_root, original_prev,
        "prev_mmr_root must be restored from the highest-leaf_index entry"
    );
}

#[tokio::test]
async fn test_load_from_pg_with_empty_root_index_table_yields_empty_map() {
    // Fresh DB: the table exists but has no rows. `load_from_pg` must
    // succeed and leave `root_indices` empty + `prev_mmr_root` at
    // `ZERO_HASH` (matches `State::new`).
    let (pool, _container) = setup_pool().await;
    let loaded = State::load_from_pg(&pool).await.expect("load_from_pg");
    assert!(loaded.root_indices.is_empty());
    assert_eq!(loaded.prev_mmr_root, ZERO_HASH);
}

#[tokio::test]
async fn test_get_mmr_inclusion_proof_after_restart_succeeds() {
    // The original bug: a container restart cleared `root_indices`, so
    // any account whose latest proof referenced a `commitment_history_
    // root` from BEFORE the restart hit
    // `get_mmr_inclusion_proof -> Err`, and `/api/mint` surfaced 422
    // `Unable to get mmr inclusion proof for the previous root`.
    //
    // After Phase C, every entry persisted by `insert_root_index` is
    // rebuilt by `load_from_pg`, so each historical
    // `prev_mmr_root` must resolve to a valid `(smt_root, MMRProof)`
    // tuple on the reloaded state. Belt-and-braces: also verify the
    // returned proof against the post-update MMR root in extended form
    // (matches what a Plonky2 proof commits as `commitment_history_root`).
    let (pool, _container) = setup_pool().await;

    // Capture each pre-update `prev_mmr_root` during the populate run.
    let mut prev_roots: Vec<HashDigest> = Vec::new();
    let mut state = State::new();
    let n = 4;
    for i in 0..n {
        let pre_root = state.mmr.root_extended(MMR_PROOF_PATH_LEN);
        prev_roots.push(pre_root);

        let key_hex = format!("{:064x}", i + 10);
        let commitment = create_test_commitment(format!("restart-test-{}", i).as_bytes(), &key_hex);
        state.update(&[commitment]).expect("update");
        let (smt_root, leaf_index) = *state
            .root_indices
            .get(&state.prev_mmr_root)
            .expect("update inserted root_indices entry");
        let (smt_bytes, mmr_bytes) = state.serialize_for_persist().unwrap();
        persist_state_tx(
            &pool,
            &smt_bytes,
            &mmr_bytes,
            &[0u8; 32],
            Some((&state.prev_mmr_root, &smt_root, leaf_index as u64)),
        )
        .await
        .expect("persist_state_tx");
    }
    let final_mmr_root_extended = state.mmr.root_extended(MMR_PROOF_PATH_LEN);
    drop(state);

    // "Restart" — load a fresh State from the same pool.
    let restarted = State::load_from_pg(&pool).await.expect("load_from_pg");
    assert_eq!(restarted.root_indices.len(), n);

    for (i, prev_root) in prev_roots.iter().enumerate() {
        let (smt_root, proof) = restarted
            .get_mmr_inclusion_proof(*prev_root)
            .unwrap_or_else(|e| {
                panic!(
                    "historical prev_mmr_root {} must resolve after restart, got Err({})",
                    i, e
                )
            });
        let leaf = hash_concat(&smt_root, prev_root);
        let proof_extended = proof.extend_to(MMR_PROOF_PATH_LEN);
        assert!(
            proof_extended.verify(leaf, final_mmr_root_extended),
            "restored proof must verify against the loaded MMR root (entry {})",
            i
        );
    }
}

#[tokio::test]
async fn test_load_root_indices_rejects_short_prev_root_blob() {
    // Defensive decode branch in `load_root_indices`: a manually-
    // inserted row whose `prev_mmr_root` BYTEA is not 32 bytes must
    // surface as `sqlx::Error::Decode` rather than panicking on the
    // `try_into::<[u8; 32]>()`.
    let (pool, _container) = setup_pool().await;
    sqlx::query(
        "INSERT INTO mmr_root_index (prev_mmr_root, smt_root, leaf_index) \
         VALUES ($1, $2, $3)",
    )
    .bind(&vec![0xAAu8; 8][..])
    .bind(&vec![0xBBu8; 32][..])
    .bind(0_i64)
    .execute(&pool)
    .await
    .unwrap();
    let err = load_root_indices(&pool)
        .await
        .expect_err("expected decode error on short prev_mmr_root");
    let msg = format!("{}", err);
    assert!(msg.contains("prev_mmr_root"), "unexpected: {}", msg);
}

#[tokio::test]
async fn test_load_root_indices_rejects_short_smt_root_blob() {
    // Same defensive branch, for the `smt_root` column.
    let (pool, _container) = setup_pool().await;
    sqlx::query(
        "INSERT INTO mmr_root_index (prev_mmr_root, smt_root, leaf_index) \
         VALUES ($1, $2, $3)",
    )
    .bind(&vec![0xAAu8; 32][..])
    .bind(&vec![0xBBu8; 8][..])
    .bind(0_i64)
    .execute(&pool)
    .await
    .unwrap();
    let err = load_root_indices(&pool)
        .await
        .expect_err("expected decode error on short smt_root");
    let msg = format!("{}", err);
    assert!(msg.contains("smt_root"), "unexpected: {}", msg);
}

#[tokio::test]
async fn test_load_root_indices_rejects_negative_leaf_index() {
    // Defensive branch in `load_root_indices`: BIGINT is signed and the
    // column has no CHECK constraint, so a manual operator INSERT could
    // plant a negative value. Surface as decode error.
    //
    // ALSO covers the matching `load_from_pg` -> `LoadStateError::Db`
    // path: the error is wrapped in `LoadStateError::Db` because
    // `load_root_indices` returns `sqlx::Error` and the `From` impl on
    // `LoadStateError` re-wraps it.
    let (pool, _container) = setup_pool().await;
    sqlx::query(
        "INSERT INTO mmr_root_index (prev_mmr_root, smt_root, leaf_index) \
         VALUES ($1, $2, $3)",
    )
    .bind(&vec![0xAAu8; 32][..])
    .bind(&vec![0xBBu8; 32][..])
    .bind(-1_i64)
    .execute(&pool)
    .await
    .unwrap();
    let err = load_root_indices(&pool)
        .await
        .expect_err("expected decode error on negative leaf_index");
    let msg = format!("{}", err);
    assert!(msg.contains("leaf_index"), "unexpected: {}", msg);

    // And the matching `State::load_from_pg` surface — must arrive as
    // `LoadStateError::Db` (the `From<sqlx::Error>` branch).
    let err = State::load_from_pg(&pool)
        .await
        .expect_err("expected db error from load_from_pg");
    assert!(
        matches!(err, crate::state::LoadStateError::Db(_)),
        "unexpected: {:?}",
        err
    );
}

#[tokio::test]
async fn test_insert_root_index_is_idempotent_on_conflict() {
    // Single-row insert is `ON CONFLICT DO NOTHING` — re-issuing the
    // same `prev_mmr_root` must not error and must not duplicate.
    let (pool, _container) = setup_pool().await;
    let prev = digest_from_bytes(&[1u8; 32]);
    let smt = digest_from_bytes(&[2u8; 32]);
    insert_root_index(&pool, &prev, &smt, 0)
        .await
        .expect("first insert");
    insert_root_index(&pool, &prev, &smt, 0)
        .await
        .expect("second insert (idempotent)");
    let loaded = load_root_indices(&pool).await.unwrap();
    assert_eq!(loaded.len(), 1);
}

// ---- derive_num_pubkeys_from_smt (Phase D) --------------------------------

/// Derive the BIP-32 child pubkey at `index` from `xpriv` using the same
/// derivation path the production [`derive_num_pubkeys_from_smt`] walks.
/// Test-only helper so each membership setup builds the exact same key
/// bytes the production code will subsequently look up.
fn derive_pk(xpriv: &Xpriv, index: u32) -> bitcoin::secp256k1::PublicKey {
    Xpub::from_priv(&SECP256K1, xpriv)
        .derive_pub(&SECP256K1, &[ChildNumber::Normal { index }])
        .expect("derive_pub")
        .public_key
}

/// SMT key for a pubkey, matching [`State::update`]'s
/// `sha256(public_key.serialize())` convention.
fn smt_key_for_pk(pk: &bitcoin::secp256k1::PublicKey) -> [u8; 32] {
    bitcoin::hashes::sha256::Hash::hash(&pk.serialize()).to_byte_array()
}

/// Empty SMT → no minting pubkey has been issued yet.
#[test]
fn derive_num_pubkeys_from_smt_empty_returns_zero() {
    let xpriv = Xpriv::new_master(Network::Signet, &[7u8; 32]).expect("xpriv");
    let smt = SparseMerkleTree::new();
    assert_eq!(derive_num_pubkeys_from_smt(&xpriv, &smt), 0);
}

/// SMT contains `pk_0, pk_1, …, pk_{N-1}` → derive returns N.
///
/// Covers the "found at index N" branch of the algorithm: every loop
/// iteration up to `n = N - 1` finds the key in the SMT and `continue`s,
/// the `n = N` iteration misses and returns. Drives a small N (3) so the
/// test stays fast — the branch under test is invariant in N.
#[test]
fn derive_num_pubkeys_from_smt_returns_first_missing_index() {
    let xpriv = Xpriv::new_master(Network::Signet, &[11u8; 32]).expect("xpriv");
    let mut smt = SparseMerkleTree::new();
    // Stuff in pk_0, pk_1, pk_2. Value bytes are arbitrary — the
    // derive function only checks key presence, not leaf value.
    for n in 0..3u32 {
        let pk = derive_pk(&xpriv, n);
        let key = smt_key_for_pk(&pk);
        let dummy_value = digest_from_bytes(&[(n + 1) as u8; 32]);
        smt.insert(key, dummy_value).expect("smt insert");
    }
    assert_eq!(derive_num_pubkeys_from_smt(&xpriv, &smt), 3);
}

/// Two distinct minting wallets writing into the same SMT don't
/// contaminate each other's derived counts: each `xpriv` walks its own
/// branch and stops at its own first miss.
#[test]
fn derive_num_pubkeys_from_smt_is_xpriv_scoped() {
    let xpriv_a = Xpriv::new_master(Network::Signet, &[1u8; 32]).expect("xpriv a");
    let xpriv_b = Xpriv::new_master(Network::Signet, &[2u8; 32]).expect("xpriv b");
    let mut smt = SparseMerkleTree::new();
    // Insert pk_0 from xpriv_a only.
    let pk_a0 = derive_pk(&xpriv_a, 0);
    smt.insert(smt_key_for_pk(&pk_a0), digest_from_bytes(&[9u8; 32]))
        .expect("smt insert");
    assert_eq!(derive_num_pubkeys_from_smt(&xpriv_a, &smt), 1);
    assert_eq!(derive_num_pubkeys_from_smt(&xpriv_b, &smt), 0);
}

/// Loop-bound panic: every index up to and including `bound` is in the
/// SMT → the next iteration hits `n >= bound` and panics. Exercises the
/// safety-net branch of the algorithm; uses the
/// `derive_num_pubkeys_from_smt_with_bound` inner with a tiny bound so
/// the SMT setup is fast (a million real BIP-32 derivations would take
/// minutes).
#[test]
#[should_panic(expected = "loop bound is a safety net")]
fn derive_num_pubkeys_from_smt_panics_on_loop_bound_exceeded() {
    let xpriv = Xpriv::new_master(Network::Signet, &[33u8; 32]).expect("xpriv");
    let mut smt = SparseMerkleTree::new();
    // Fill the SMT with pk_0..=pk_BOUND so the loop never finds a miss.
    const BOUND: u32 = 3;
    for n in 0..=BOUND + 1 {
        let pk = derive_pk(&xpriv, n);
        let key = smt_key_for_pk(&pk);
        smt.insert(key, digest_from_bytes(&[(n as u8).wrapping_add(1); 32]))
            .expect("smt insert");
    }
    let _ = derive_num_pubkeys_from_smt_with_bound(&xpriv, &smt, BOUND);
}
