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
    // `minting_meta` lands via 0002_minting_meta.sql (PR-A3).
    assert_eq!(
        names,
        vec![
            "_sqlx_migrations".to_string(),
            "accounts".to_string(),
            "latest_block".to_string(),
            "minting_meta".to_string(),
            "mmr_state".to_string(),
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
    persist_state_tx(&pool, &smt, &mmr, &block)
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
    persist_state_tx(&pool, &smt1, &mmr1, &block1)
        .await
        .unwrap();

    let smt2 = vec![4u8; 32];
    let mmr2 = vec![5u8; 32];
    let block2 = [6u8; 32];
    persist_state_tx(&pool, &smt2, &mmr2, &block2)
        .await
        .unwrap();

    assert_eq!(load_smt(&pool).await.unwrap(), Some(smt2));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(mmr2));
    assert_eq!(load_latest_block(&pool).await.unwrap(), Some(block2));
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
async fn load_minting_num_pubkeys_returns_none_initially() {
    let (pool, _container) = setup_pool().await;
    assert!(load_minting_num_pubkeys(&pool).await.unwrap().is_none());
}

#[tokio::test]
async fn upsert_minting_num_pubkeys_inserts_then_updates() {
    let (pool, _container) = setup_pool().await;
    upsert_minting_num_pubkeys(&pool, 7).await.unwrap();
    assert_eq!(load_minting_num_pubkeys(&pool).await.unwrap(), Some(7));

    upsert_minting_num_pubkeys(&pool, 42).await.unwrap();
    assert_eq!(load_minting_num_pubkeys(&pool).await.unwrap(), Some(42));
}

#[tokio::test]
async fn upsert_minting_num_pubkeys_round_trips_full_u32_range() {
    let (pool, _container) = setup_pool().await;
    upsert_minting_num_pubkeys(&pool, u32::MAX).await.unwrap();
    assert_eq!(
        load_minting_num_pubkeys(&pool).await.unwrap(),
        Some(u32::MAX)
    );
}

#[tokio::test]
async fn load_minting_num_pubkeys_rejects_negative_value() {
    // Plant a negative BIGINT directly via SQL and assert the loader
    // surfaces the out-of-range value as an sqlx::Error::Decode rather
    // than silently casting through `as u32`.
    let (pool, _container) = setup_pool().await;
    sqlx::query("INSERT INTO minting_meta (id, num_pubkeys) VALUES (1, $1)")
        .bind(-1_i64)
        .execute(&pool)
        .await
        .unwrap();
    let err = load_minting_num_pubkeys(&pool)
        .await
        .expect_err("expected decode error");
    assert!(
        matches!(err, sqlx::Error::Decode(_)),
        "unexpected: {:?}",
        err
    );
}

#[tokio::test]
async fn load_minting_num_pubkeys_rejects_value_above_u32_max() {
    // Same as above, but for the upper-bound branch.
    let (pool, _container) = setup_pool().await;
    sqlx::query("INSERT INTO minting_meta (id, num_pubkeys) VALUES (1, $1)")
        .bind(i64::from(u32::MAX) + 1)
        .execute(&pool)
        .await
        .unwrap();
    let err = load_minting_num_pubkeys(&pool)
        .await
        .expect_err("expected decode error");
    assert!(
        matches!(err, sqlx::Error::Decode(_)),
        "unexpected: {:?}",
        err
    );
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
