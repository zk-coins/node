// Postgres state-layer tests for `db.rs`.
//
// Strategy: every test gets its own Postgres 17 container via
// `testcontainers_modules::postgres::Postgres`. Per-test isolation is
// the simplest model — no shared state, no `truncate_all` ordering,
// no risk of cross-test contamination. The container boot is ~3-5 s
// each and the suite runs single-threaded under
// `--test-threads=1` (mirrors the rest of the server test gate), so
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
    // _sqlx_migrations is created implicitly by sqlx::migrate!.
    // `pending_inscriptions` lands via 0003_pending_inscriptions.sql
    // (Phase B). `mmr_root_index` lands via 0004_mmr_root_index.sql
    // (Phase C). `minting_meta` is created by 0002 then dropped by
    // 0005 (Phase D), so it is absent from the final schema.
    assert_eq!(
        names,
        vec![
            "_sqlx_migrations".to_string(),
            "accounts".to_string(),
            "latest_block".to_string(),
            "mmr_root_index".to_string(),
            "mmr_state".to_string(),
            "pending_inscriptions".to_string(),
            "smt_state".to_string(),
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
