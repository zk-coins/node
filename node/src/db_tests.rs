// Postgres state-layer tests for `db.rs`.
//
// Strategy: every test gets its own Postgres 17 container via
// `testcontainers_modules::postgres::Postgres`. Per-test isolation is
// the simplest model — no shared state, no `truncate_all` ordering,
// no risk of cross-test contamination. The container boot is ~3-5 s
// each and the suite runs single-threaded under
// `--test-threads=1` (mirrors the rest of the node test gate), so
// the total wall time stays comfortably below a minute even with the
// per-test container.
//
// Migrations are applied via `db::connect_and_migrate`, the same code
// path the production bootstrap will exercise in PR-A2.

use super::*;
use sqlx::Row;
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;

/// Start a fresh `postgres:17` container and connect a migrated pool
/// to it. The container handle is returned alongside the pool so the
/// caller can keep it alive for the duration of the test — dropping
/// it tears the container down.
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
async fn connect_and_migrate_creates_all_tables() {
    let (pool, _container) = setup_pool().await;
    // Introspect via `information_schema.tables` — works on any
    // Postgres 9+ and avoids hard-coding pg_catalog quirks.
    let rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' \
         ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .expect("introspection query failed");
    let names: Vec<String> = rows.into_iter().map(|r| r.get::<String, _>(0)).collect();
    // Full expected schema after all migrations 0001-0010 (alphabetic
    // by `ORDER BY table_name`). `_sqlx_migrations` is created
    // implicitly by `sqlx::migrate!`. `minting_meta` (0002) is
    // dropped by 0005 (Phase D), absent from the final schema.
    //
    // Counts:
    //   * Pre-#113 schema (0001-0005):   8 tables
    //   * After 0006 (kind):             8 tables (ALTER only)
    //   * After 0007 (request_log):      9 tables
    //   * After 0008 (full DB trail):   19 tables + 1 trigger
    //   * After 0009 / 0010:            19 tables (polish only)
    assert_eq!(
        names,
        vec![
            "_sqlx_migrations".to_string(),
            "account_history".to_string(),
            "accounts".to_string(),
            "block_log".to_string(),
            "boot_log".to_string(),
            "coin_proof_store".to_string(),
            "error_log".to_string(),
            "esplora_log".to_string(),
            "latest_block".to_string(),
            "mmr_root_index".to_string(),
            "mmr_state".to_string(),
            "observed_inscriptions".to_string(),
            "pending_inscriptions".to_string(),
            "request_log".to_string(),
            "smt_state".to_string(),
            "state_update_log".to_string(),
            "tx_mining_log".to_string(),
            "username_claim_log".to_string(),
            "usernames".to_string(),
        ]
    );
}

#[tokio::test]
async fn load_smt_returns_none_initially() {
    let (pool, _container) = setup_pool().await;
    assert!(load_smt(&pool).await.expect("load_smt failed").is_none());
}

#[tokio::test]
async fn load_mmr_returns_none_initially() {
    let (pool, _container) = setup_pool().await;
    assert!(load_mmr(&pool).await.expect("load_mmr failed").is_none());
}

#[tokio::test]
async fn load_latest_block_returns_none_initially() {
    let (pool, _container) = setup_pool().await;
    assert!(load_latest_block(&pool)
        .await
        .expect("load_latest_block failed")
        .is_none());
}

#[tokio::test]
async fn persist_state_tx_writes_smt_mmr_block_atomically() {
    let (pool, _container) = setup_pool().await;
    let smt = vec![0xAAu8; 64];
    let mmr = vec![0xBBu8; 128];
    let block = [0xCCu8; 32];
    persist_state_tx(&pool, &smt, &mmr, &block, None)
        .await
        .expect("persist_state_tx failed");

    assert_eq!(load_smt(&pool).await.unwrap(), Some(smt));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(mmr));
    assert_eq!(load_latest_block(&pool).await.unwrap(), Some(block));
}

#[tokio::test]
async fn persist_state_tx_is_idempotent_on_conflict() {
    let (pool, _container) = setup_pool().await;
    let smt1 = vec![1u8; 16];
    let mmr1 = vec![2u8; 16];
    let block1 = [3u8; 32];
    persist_state_tx(&pool, &smt1, &mmr1, &block1, None)
        .await
        .unwrap();

    let smt2 = vec![4u8; 32];
    let mmr2 = vec![5u8; 32];
    let block2 = [6u8; 32];
    persist_state_tx(&pool, &smt2, &mmr2, &block2, None)
        .await
        .unwrap();

    assert_eq!(load_smt(&pool).await.unwrap(), Some(smt2));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(mmr2));
    assert_eq!(load_latest_block(&pool).await.unwrap(), Some(block2));
}

#[tokio::test]
async fn persist_state_tx_writes_root_index_in_same_transaction() {
    // Phase-C atomicity guarantee: the `mmr_root_index` row rides
    // along inside the same Postgres transaction as SMT/MMR/
    // latest_block. Closing the crash window between the snapshot
    // and the standalone INSERT is the whole point — see the
    // doc-comment on `persist_state_tx` for the heal-on-restart
    // story. This test asserts all four landed from one call.
    let (pool, _container) = setup_pool().await;
    let smt = vec![0xAAu8; 64];
    let mmr = vec![0xBBu8; 128];
    let block = [0xCCu8; 32];
    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0x10u8; 32]);
    let smt_root = zkcoins_program::hash::digest_from_bytes(&[0x20u8; 32]);
    persist_state_tx(&pool, &smt, &mmr, &block, Some((&prev_root, &smt_root, 7)))
        .await
        .expect("persist_state_tx failed");

    assert_eq!(load_smt(&pool).await.unwrap(), Some(smt));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(mmr));
    assert_eq!(load_latest_block(&pool).await.unwrap(), Some(block));
    let entries = load_root_indices(&pool).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], (prev_root, smt_root, 7));
}

#[tokio::test]
async fn persist_state_tx_root_index_on_conflict_does_nothing() {
    // Re-scanning the same commit tx after a crash MUST be a no-op on
    // the root_index row — `update()` is replayed against the same
    // unchanged MMR and the (prev_mmr_root, smt_root, leaf_index)
    // tuple is identical, so `ON CONFLICT (prev_mmr_root) DO NOTHING`
    // keeps the original row authoritative. Belt-and-braces: the
    // second call's `smt_root` differs to prove that the conflict
    // branch genuinely takes the DO NOTHING path (otherwise the row
    // would be silently mutated).
    let (pool, _container) = setup_pool().await;
    let smt = vec![1u8; 16];
    let mmr = vec![2u8; 16];
    let block = [3u8; 32];
    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0x10u8; 32]);
    let original_smt_root = zkcoins_program::hash::digest_from_bytes(&[0x20u8; 32]);
    let different_smt_root = zkcoins_program::hash::digest_from_bytes(&[0x99u8; 32]);

    persist_state_tx(
        &pool,
        &smt,
        &mmr,
        &block,
        Some((&prev_root, &original_smt_root, 0)),
    )
    .await
    .unwrap();
    persist_state_tx(
        &pool,
        &smt,
        &mmr,
        &block,
        Some((&prev_root, &different_smt_root, 0)),
    )
    .await
    .unwrap();

    let entries = load_root_indices(&pool).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].1, original_smt_root,
        "second call must DO NOTHING, original row stays authoritative"
    );
}

#[tokio::test]
async fn load_latest_block_rejects_wrong_length() {
    // Defensive branch in `load_latest_block`: the application only
    // writes 32-byte values via `persist_state_tx`, but BYTEA accepts
    // any length. Insert a deliberately wrong-length row directly
    // and assert the loader returns an `sqlx::Error::Decode` rather
    // than panicking or silently truncating.
    let (pool, _container) = setup_pool().await;
    // Drop the 0010 length CHECK so the corrupt-row plant succeeds;
    // the subject of this test is the Rust-side defense in
    // `load_latest_block`, not the DB-level CHECK.
    sqlx::query("ALTER TABLE latest_block DROP CONSTRAINT latest_block_hash_length")
        .execute(&pool)
        .await
        .expect("drop latest_block_hash_length");
    sqlx::query("INSERT INTO latest_block (id, block_hash) VALUES (1, $1)")
        .bind(vec![0u8; 7])
        .execute(&pool)
        .await
        .unwrap();
    let err = load_latest_block(&pool)
        .await
        .expect_err("expected decode error");
    assert!(
        matches!(err, sqlx::Error::Decode(_)),
        "unexpected: {:?}",
        err
    );
}

#[tokio::test]
async fn load_all_accounts_returns_empty_initially() {
    let (pool, _container) = setup_pool().await;
    let rows = load_all_accounts(&pool).await.unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn upsert_account_inserts_then_updates() {
    let (pool, _container) = setup_pool().await;
    let addr = vec![0xAAu8; 32];
    upsert_account(&pool, &addr, b"first").await.unwrap();
    let rows = load_all_accounts(&pool).await.unwrap();
    assert_eq!(rows, vec![(addr.clone(), b"first".to_vec())]);

    upsert_account(&pool, &addr, b"second").await.unwrap();
    let rows = load_all_accounts(&pool).await.unwrap();
    assert_eq!(rows, vec![(addr, b"second".to_vec())]);
}

#[tokio::test]
async fn load_all_accounts_returns_all_inserted() {
    let (pool, _container) = setup_pool().await;
    let a1 = vec![0x01u8; 32];
    let a2 = vec![0x02u8; 32];
    let a3 = vec![0x03u8; 32];
    upsert_account(&pool, &a1, b"d1").await.unwrap();
    upsert_account(&pool, &a2, b"d2").await.unwrap();
    upsert_account(&pool, &a3, b"d3").await.unwrap();
    let mut rows = load_all_accounts(&pool).await.unwrap();
    rows.sort();
    assert_eq!(
        rows,
        vec![
            (a1, b"d1".to_vec()),
            (a2, b"d2".to_vec()),
            (a3, b"d3".to_vec()),
        ]
    );
}

#[tokio::test]
async fn load_all_usernames_returns_empty_initially() {
    let (pool, _container) = setup_pool().await;
    let rows = load_all_usernames(&pool).await.unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn claim_username_returns_true_on_new() {
    let (pool, _container) = setup_pool().await;
    let addr = vec![0xAAu8; 32];
    let ok = claim_username(&pool, "alice", &addr).await.unwrap();
    assert!(ok);
    let rows = load_all_usernames(&pool).await.unwrap();
    assert_eq!(rows, vec![("alice".to_string(), addr)]);
}

#[tokio::test]
async fn claim_username_returns_false_on_conflict() {
    let (pool, _container) = setup_pool().await;
    let addr1 = vec![0xAAu8; 32];
    let addr2 = vec![0xBBu8; 32];
    assert!(claim_username(&pool, "alice", &addr1).await.unwrap());
    // Second claim with a different address must NOT overwrite.
    assert!(!claim_username(&pool, "alice", &addr2).await.unwrap());
    // The original binding must survive.
    let rows = load_all_usernames(&pool).await.unwrap();
    assert_eq!(rows, vec![("alice".to_string(), addr1)]);
}

#[tokio::test]
async fn resolve_username_returns_address_for_claimed_name() {
    let (pool, _container) = setup_pool().await;
    let addr = vec![0xABu8; 32];
    claim_username(&pool, "bob", &addr).await.unwrap();
    let resolved = resolve_username(&pool, "bob").await.unwrap();
    assert_eq!(resolved, Some(addr));
}

#[tokio::test]
async fn resolve_username_returns_none_for_unknown() {
    let (pool, _container) = setup_pool().await;
    let resolved = resolve_username(&pool, "nobody").await.unwrap();
    assert!(resolved.is_none());
}

#[tokio::test]
async fn connect_and_migrate_propagates_connect_failure() {
    // Bogus port → connect() fails fast (no Postgres listening) and
    // the error propagates via `?`. Exercises the otherwise-unreached
    // error branch in `connect_and_migrate`.
    let err = connect_and_migrate("postgres://postgres:postgres@127.0.0.1:1/postgres")
        .await
        .expect_err("expected connect failure");
    assert!(
        matches!(err, sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut),
        "unexpected: {:?}",
        err
    );
}

/// Happy-path: `commit_mint_tx` upserts every account in the bundle in
/// a single transaction. Phase D collapsed the optimistic counter bump
/// out of this helper (the minting account's `num_pubkeys` is now
/// derived from SMT membership at runtime), so the only assertion left
/// is "every row in the input slice round-trips through `accounts`".
/// Multi-row exercises the loop body that the old single-account
/// fixture never visited.
#[tokio::test]
async fn commit_mint_tx_upserts_every_account_atomically() {
    let (pool, _container) = setup_pool().await;
    let addr_a = [0xAAu8; 32];
    let data_a = vec![0xA1u8; 8];
    let addr_b = [0xBBu8; 32];
    let data_b = vec![0xB1u8; 12];
    let accounts: Vec<(&[u8], &[u8])> = vec![(&addr_a[..], &data_a), (&addr_b[..], &data_b)];
    commit_mint_tx(&pool, &accounts)
        .await
        .expect("commit_mint_tx must succeed");

    let rows = load_all_accounts(&pool).await.unwrap();
    let mut got: Vec<(Vec<u8>, Vec<u8>)> = rows.into_iter().collect();
    got.sort();
    let mut want = vec![
        (addr_a.to_vec(), data_a.clone()),
        (addr_b.to_vec(), data_b.clone()),
    ];
    want.sort();
    assert_eq!(got, want, "all accounts in the bundle must round-trip");
}

/// Second call with the same address overwrites the prior payload via
/// the `ON CONFLICT (address) DO UPDATE` branch. Exercises the
/// idempotent-replay shape the post-Phase-D mint flow relies on (a
/// concurrent receive between the snapshot and the commit will retry
/// with the latest serialized Account on the next mint).
#[tokio::test]
async fn commit_mint_tx_is_idempotent_on_conflict() {
    let (pool, _container) = setup_pool().await;
    let addr = [0xCCu8; 32];
    let first = vec![0x01u8; 16];
    let second = vec![0x02u8; 24];

    commit_mint_tx(&pool, &[(&addr[..], &first)])
        .await
        .expect("first commit");
    commit_mint_tx(&pool, &[(&addr[..], &second)])
        .await
        .expect("second commit");

    let rows = load_all_accounts(&pool).await.unwrap();
    assert_eq!(rows, vec![(addr.to_vec(), second.clone())]);
}

/// Empty input slice → empty transaction, no UPSERTs, no error. Pins
/// the no-op shape so a future refactor that turns the empty case into
/// a panic or error surfaces here rather than at a live caller.
#[tokio::test]
async fn commit_mint_tx_with_empty_accounts_is_noop() {
    let (pool, _container) = setup_pool().await;
    commit_mint_tx(&pool, &[])
        .await
        .expect("empty commit must succeed");
    let rows = load_all_accounts(&pool).await.unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn connect_and_migrate_propagates_migration_failure() {
    // Apply our migrations, then poison the `_sqlx_migrations` table
    // so the next `connect_and_migrate` re-run sees a checksum
    // mismatch and bails out via the `sqlx::Error::Migrate` branch.
    // This is the only sqlx-native way to force a deterministic
    // migration error without writing a second `.sql` file solely
    // for the test (which would itself drift from the real schema).
    let (pool, container) = setup_pool().await;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1")
        .bind(vec![0u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let err = connect_and_migrate(&url)
        .await
        .expect_err("expected migration failure");
    assert!(
        matches!(err, sqlx::Error::Migrate(_)),
        "unexpected: {:?}",
        err
    );
}

// ---- Phase E: pending_inscription_status_by_commit_txid ------------------

#[tokio::test]
async fn pending_inscription_status_by_commit_txid_returns_none_for_unknown_txid() {
    // Scanner's pre-state.update lookup: an external / out-of-band
    // inscription (not produced by this node's mint flow) has no
    // `pending_inscriptions` row. The helper must return `None` so the
    // scanner falls through to its normal state.update path instead of
    // short-circuiting.
    let (pool, _container) = setup_pool().await;
    let status = pending_inscription_status_by_commit_txid(&pool, &[0xABu8; 32])
        .await
        .expect("lookup must not error on missing row");
    assert!(status.is_none());
}

#[tokio::test]
async fn pending_inscription_status_by_commit_txid_returns_current_status() {
    let (pool, _container) = setup_pool().await;
    let commit_txid = [0xCDu8; 32];
    let reveal_txid = [0xCEu8; 32];
    let commitment = b"test-commitment";
    let commit_tx = b"test-commit-tx";
    let reveal_tx = b"test-reveal-tx";
    insert_pending_inscription(
        &pool,
        &commit_txid,
        &reveal_txid,
        InscriptionKind::Mint,
        commitment,
        commit_tx,
        reveal_tx,
        12_345,
    )
    .await
    .expect("insert must succeed");
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_CONSTRUCTED.to_string())
    );

    update_pending_status(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST)
        .await
        .unwrap();
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_REVEAL_BROADCAST.to_string())
    );

    update_pending_status(&pool, &commit_txid, PENDING_STATUS_COMPLETE)
        .await
        .unwrap();
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_COMPLETE.to_string())
    );
}

// ---- Phase E: persist_state_and_mark_complete_tx -------------------------

/// Helper: insert a `pending_inscriptions` row in the given starting
/// status so the atomic-tx tests can exercise the mark-complete step.
async fn seed_pending_row(pool: &PgPool, commit_txid: &[u8], status: &str) {
    // Synthetic reveal txid for tests — not derived from the seed
    // bytes since this helper is only used to drive the status state
    // machine, not the reveal-txid lookup.
    let reveal_txid: [u8; 32] = [0xAB; 32];
    insert_pending_inscription(
        pool,
        commit_txid,
        &reveal_txid,
        InscriptionKind::Mint,
        b"test-commitment",
        b"test-commit-tx",
        b"test-reveal-tx",
        12_345,
    )
    .await
    .expect("insert pending row");
    update_pending_status(pool, commit_txid, status)
        .await
        .expect("seed status");
}

#[tokio::test]
async fn persist_state_and_mark_complete_tx_writes_state_and_advances_row() {
    // The atomic Phase-E helper writes SMT/MMR/root_index AND marks the
    // pending row `complete` in one transaction. `latest_block` is left
    // untouched (the scanner is the only legitimate writer).
    let (pool, _container) = setup_pool().await;
    let commit_txid = [0x55u8; 32];
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    let smt = vec![0x11u8; 64];
    let mmr = vec![0x22u8; 128];
    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0x40u8; 32]);
    let smt_root = zkcoins_program::hash::digest_from_bytes(&[0x50u8; 32]);

    persist_state_and_mark_complete_tx(
        &pool,
        &smt,
        &mmr,
        Some((&prev_root, &smt_root, 3)),
        &commit_txid,
    )
    .await
    .expect("persist_state_and_mark_complete_tx must succeed");

    assert_eq!(load_smt(&pool).await.unwrap(), Some(smt));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(mmr));
    assert_eq!(load_latest_block(&pool).await.unwrap(), None);
    let entries = load_root_indices(&pool).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], (prev_root, smt_root, 3));
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_COMPLETE.to_string())
    );
}

#[tokio::test]
async fn persist_state_and_mark_complete_tx_preserves_existing_latest_block() {
    // A scanner sweep landed a `latest_block` before the mint flow ever
    // ran. The mint flow's atomic persist call must NOT rewind that
    // pointer back to the genesis fallback — the helper is responsible
    // for SMT/MMR/root_index/pending_inscriptions only.
    let (pool, _container) = setup_pool().await;
    let scanner_block = [0x77u8; 32];
    persist_state_tx(&pool, b"old-smt", b"old-mmr", &scanner_block, None)
        .await
        .unwrap();

    let commit_txid = [0x66u8; 32];
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    persist_state_and_mark_complete_tx(&pool, b"new-smt", b"new-mmr", None, &commit_txid)
        .await
        .unwrap();

    assert_eq!(load_smt(&pool).await.unwrap(), Some(b"new-smt".to_vec()));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(b"new-mmr".to_vec()));
    assert_eq!(
        load_latest_block(&pool).await.unwrap(),
        Some(scanner_block),
        "latest_block must remain untouched"
    );
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_COMPLETE.to_string())
    );
}

#[tokio::test]
async fn persist_state_and_mark_complete_tx_accepts_no_root_index() {
    // Mirror the `persist_state_tx` no-root-index branch: a call with
    // `None` writes SMT + MMR + the row advance only. The
    // mmr_root_index table stays empty, no error, latest_block untouched.
    let (pool, _container) = setup_pool().await;
    let commit_txid = [0x88u8; 32];
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    persist_state_and_mark_complete_tx(&pool, b"smt-only", b"mmr-only", None, &commit_txid)
        .await
        .expect("no-root-index path must succeed");

    assert_eq!(load_smt(&pool).await.unwrap(), Some(b"smt-only".to_vec()));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(b"mmr-only".to_vec()));
    assert!(load_root_indices(&pool).await.unwrap().is_empty());
    assert_eq!(load_latest_block(&pool).await.unwrap(), None);
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_COMPLETE.to_string())
    );
}

#[tokio::test]
async fn persist_state_and_mark_complete_tx_rollback_on_failure_leaves_state_untouched() {
    // The BLOCKER fix's load-bearing invariant: when the atomic tx
    // fails, NOTHING lands on disk — not the SMT, not the MMR, not the
    // root_index row, and crucially the pending row stays at its prior
    // status (so scanner-replay will integrate the inscription and
    // mark complete itself, never doubling up).
    //
    // We synthesize a tx failure by passing a `commit_txid` that
    // violates the BYTEA length expectation: the `pending_inscriptions.commit_txid`
    // column is `BYTEA NOT NULL` with no length check at the SQL
    // level, so we instead force a constraint violation by writing the
    // mmr_root_index row twice with conflicting payloads — wait, the
    // helper uses ON CONFLICT DO NOTHING. The cleanest way to force a
    // mid-tx failure is a leaf_index value that does not fit i64; the
    // helper's `i64::try_from(u64)` returns `sqlx::Error::Encode`
    // BEFORE the BEGIN, so that wouldn't actually exercise the
    // rollback path. Instead, drop the pending_inscriptions table
    // between the seed and the call so the UPDATE inside the tx
    // surfaces a sqlx::Error and the BEGIN/COMMIT envelope rolls
    // SMT/MMR back.
    let (pool, _container) = setup_pool().await;
    let commit_txid = [0x99u8; 32];
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    // Pre-call snapshot: nothing in the state tables yet.
    assert_eq!(load_smt(&pool).await.unwrap(), None);
    assert_eq!(load_mmr(&pool).await.unwrap(), None);

    // Force a mid-tx failure by dropping `pending_inscriptions`. The
    // UPDATE inside the helper will fail with "relation does not
    // exist", the transaction rolls back, and the smt/mmr UPSERTs
    // performed earlier in the same tx are undone.
    //
    // CASCADE is required after migration 0010 added FK constraints
    // from `tx_mining_log.commit_txid` and
    // `coin_proof_store.consumed_by_commit_txid` to
    // `pending_inscriptions(commit_txid)`. Without CASCADE the DROP
    // is rejected by Postgres with "cannot drop table … because
    // other objects depend on it". The dependent tables and their FK
    // constraints get dropped along with the parent — fine for this
    // test, which is exercising a synthetic mid-tx failure, not a
    // real schema change.
    sqlx::query("DROP TABLE pending_inscriptions CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0xA0u8; 32]);
    let smt_root = zkcoins_program::hash::digest_from_bytes(&[0xB0u8; 32]);
    let res = persist_state_and_mark_complete_tx(
        &pool,
        b"would-be-smt",
        b"would-be-mmr",
        Some((&prev_root, &smt_root, 7)),
        &commit_txid,
    )
    .await;
    assert!(
        res.is_err(),
        "atomic helper must surface the UPDATE failure"
    );

    // Post-call invariant: SMT/MMR did NOT advance. The
    // BEGIN/COMMIT envelope rolled the earlier UPSERTs back.
    assert_eq!(
        load_smt(&pool).await.unwrap(),
        None,
        "atomic-tx rollback must leave smt_state untouched"
    );
    assert_eq!(
        load_mmr(&pool).await.unwrap(),
        None,
        "atomic-tx rollback must leave mmr_state untouched"
    );
    assert!(
        load_root_indices(&pool).await.unwrap().is_empty(),
        "atomic-tx rollback must leave mmr_root_index untouched"
    );
}

#[tokio::test]
async fn persist_state_and_mark_complete_tx_idempotent_on_already_complete_row() {
    // The UPDATE guard `status <> 'complete'` keeps the helper
    // idempotent: a retry against a row that is already `complete`
    // re-runs the SMT/MMR/root_index UPSERTs (identical bytes, no-op
    // semantically) but does NOT bump `updated_at` on the pending
    // row. This matters for the audit log on scanner-replay edge
    // cases where the mint flow's tx committed but a transient client
    // error caused the caller to retry.
    let (pool, _container) = setup_pool().await;
    let commit_txid = [0xAAu8; 32];
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0x10u8; 32]);
    let smt_root = zkcoins_program::hash::digest_from_bytes(&[0x20u8; 32]);
    persist_state_and_mark_complete_tx(
        &pool,
        b"smt-1",
        b"mmr-1",
        Some((&prev_root, &smt_root, 1)),
        &commit_txid,
    )
    .await
    .expect("first call must succeed");

    // Record the row's updated_at after the first complete advance.
    // We compare as text to avoid pulling chrono into the test build —
    // TIMESTAMPTZ::text round-trips losslessly.
    let (first_updated_at,): (String,) =
        sqlx::query_as("SELECT updated_at::text FROM pending_inscriptions WHERE commit_txid = $1")
            .bind(&commit_txid[..])
            .fetch_one(&pool)
            .await
            .unwrap();

    // A second invocation against the same (already-complete) row
    // must succeed and leave the row's updated_at untouched.
    persist_state_and_mark_complete_tx(
        &pool,
        b"smt-1",
        b"mmr-1",
        Some((&prev_root, &smt_root, 1)),
        &commit_txid,
    )
    .await
    .expect("retry against already-complete row must succeed");

    let (second_updated_at,): (String,) =
        sqlx::query_as("SELECT updated_at::text FROM pending_inscriptions WHERE commit_txid = $1")
            .bind(&commit_txid[..])
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(
        first_updated_at, second_updated_at,
        "guarded UPDATE must NOT bump updated_at on already-complete row"
    );
}
