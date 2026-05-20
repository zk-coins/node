// UsernameStore tests for the Postgres-backed `claim` / `load_from_pg`
// implementation (PR-A3). Mirrors the testcontainer + per-test fresh
// schema pattern used in `db_tests.rs` and `state_tests.rs` — each
// test gets its own `postgres:17` container so there is no shared
// state to clean up between tests.

use super::*;
use sqlx::PgPool;
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use zkcoins_program::hash::digest_from_bytes;

use crate::db::connect_and_migrate;

/// Test helper: byte literal → Poseidon `HashDigest = HashOut<F>`.
fn addr(seed: u8) -> Address {
    digest_from_bytes(&[seed; 32])
}

/// Mirror of `db_tests::setup_pool`: per-test container, isolated
/// schema, dropped when the container handle drops. The duplication
/// is intentional — see the comment in `state_tests.rs::setup_pool`
/// for the rationale (each test module stays independently runnable
/// and readable).
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
async fn claim_and_resolve_persists_via_pg() {
    let (pool, _container) = setup_pool().await;
    let mut store = UsernameStore::new();
    let address = addr(1);

    store
        .claim(&pool, "Alice", address)
        .await
        .expect("claim ok");
    assert_eq!(store.resolve("alice"), Some(address));
    assert_eq!(store.resolve("Alice"), Some(address));
    assert_eq!(store.get_username(&address), Some("alice"));

    // The row must round-trip via load_from_pg.
    let reloaded = UsernameStore::load_from_pg(&pool)
        .await
        .expect("load_from_pg");
    assert_eq!(reloaded.resolve("alice"), Some(address));
    assert_eq!(reloaded.get_username(&address), Some("alice"));
}

#[tokio::test]
async fn duplicate_username_rejected_with_validation() {
    let (pool, _container) = setup_pool().await;
    let mut store = UsernameStore::new();
    store.claim(&pool, "alice", addr(1)).await.unwrap();
    let err = store
        .claim(&pool, "alice", addr(2))
        .await
        .expect_err("expected duplicate rejection");
    assert!(matches!(err, ClaimUsernameError::Validation(_)));
    assert!(format!("{}", err).contains("Username already taken"));
}

#[tokio::test]
async fn duplicate_address_rejected_with_validation() {
    let (pool, _container) = setup_pool().await;
    let mut store = UsernameStore::new();
    let address = addr(1);
    store.claim(&pool, "alice", address).await.unwrap();
    let err = store
        .claim(&pool, "bob", address)
        .await
        .expect_err("expected duplicate rejection");
    assert!(matches!(err, ClaimUsernameError::Validation(_)));
    assert!(format!("{}", err).contains("Address already has a username"));
}

#[tokio::test]
async fn invalid_username_rejected() {
    let (pool, _container) = setup_pool().await;
    let mut store = UsernameStore::new();
    assert!(store.claim(&pool, "", addr(1)).await.is_err());
    assert!(store.claim(&pool, "hello world", addr(2)).await.is_err());
    assert!(store.claim(&pool, "hello@world", addr(3)).await.is_err());
    assert!(store.claim(&pool, &"a".repeat(65), addr(4)).await.is_err());
}

#[tokio::test]
async fn valid_usernames_accepted() {
    let (pool, _container) = setup_pool().await;
    let mut store = UsernameStore::new();
    store.claim(&pool, "alice", addr(1)).await.unwrap();
    store.claim(&pool, "bob-99", addr(2)).await.unwrap();
    store.claim(&pool, "carol_x", addr(3)).await.unwrap();
    store.claim(&pool, "dave.btc", addr(4)).await.unwrap();
}

#[tokio::test]
async fn resolve_is_case_insensitive() {
    let (pool, _container) = setup_pool().await;
    let mut store = UsernameStore::new();
    let address = addr(5);
    store.claim(&pool, "Alice", address).await.unwrap();

    assert_eq!(store.resolve("alice"), Some(address));
    assert_eq!(store.resolve("ALICE"), Some(address));
    assert_eq!(store.resolve("Alice"), Some(address));
    assert_eq!(store.resolve("aLiCe"), Some(address));
}

#[tokio::test]
async fn get_username_returns_none_for_unknown() {
    let store = UsernameStore::new();
    let unknown_address = addr(99);
    assert_eq!(store.get_username(&unknown_address), None);
}

#[tokio::test]
async fn load_from_pg_returns_empty_initially() {
    let (pool, _container) = setup_pool().await;
    let store = UsernameStore::load_from_pg(&pool).await.expect("load ok");
    assert_eq!(store.resolve("alice"), None);
    assert_eq!(store.get_username(&addr(1)), None);
}

#[tokio::test]
async fn claim_propagates_db_error_when_pool_is_dead() {
    // Lazy pool that never connects → claim returns Db error.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(100))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/postgres")
        .expect("connect_lazy never fails");
    let mut store = UsernameStore::new();
    let err = store
        .claim(&pool, "alice", addr(1))
        .await
        .expect_err("expected db error");
    assert!(
        matches!(err, ClaimUsernameError::Db(_)),
        "unexpected: {:?}",
        err
    );
    let msg = format!("{}", err);
    assert!(msg.contains("database error"));
    assert!(std::error::Error::source(&err).is_some());
    // After a DB-side failure the in-memory mirror must NOT be updated;
    // a later retry should be able to claim the same name once the DB
    // is reachable again.
    assert_eq!(store.resolve("alice"), None);
}

#[tokio::test]
async fn load_from_pg_propagates_db_error() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(100))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/postgres")
        .expect("connect_lazy never fails");
    let err = UsernameStore::load_from_pg(&pool)
        .await
        .expect_err("expected db error");
    assert!(
        matches!(err, LoadUsernameStoreError::Db(_)),
        "unexpected: {:?}",
        err
    );
    let msg = format!("{}", err);
    assert!(msg.contains("database error"));
    assert!(std::error::Error::source(&err).is_some());
}

#[tokio::test]
async fn load_from_pg_rejects_wrong_address_length() {
    // Plant a row with an out-of-spec 7-byte address directly via SQL.
    // The schema (`BYTEA NOT NULL`) is intentionally permissive; the
    // application layer is the authoritative check, so the loader must
    // surface the mismatch as a typed error rather than panic on the
    // try_into.
    let (pool, _container) = setup_pool().await;
    sqlx::query("INSERT INTO usernames (name, address) VALUES ($1, $2)")
        .bind("alice")
        .bind(vec![0u8; 7])
        .execute(&pool)
        .await
        .unwrap();
    let err = UsernameStore::load_from_pg(&pool)
        .await
        .expect_err("expected bad-address length");
    assert!(
        matches!(err, LoadUsernameStoreError::BadAddressLength(7)),
        "unexpected: {:?}",
        err
    );
    // Exercise the Display + Error::source paths on both variants.
    let msg = format!("{}", err);
    assert!(msg.contains("expected 32"));
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn validation_error_display_passes_through_message() {
    let err = ClaimUsernameError::Validation("Username must be 1-64 characters");
    assert_eq!(format!("{}", err), "Username must be 1-64 characters");
    assert!(std::error::Error::source(&err).is_none());
}
