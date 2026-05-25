// Bootstrap-level tests for `main.rs`.
//
// Today the only thing here is regression coverage for the
// `block_in_place(block_on(...))` bridge used inside the scanner's
// synchronous `InscriptionCallback`. Without `block_in_place`, the
// naive `Handle::current().block_on(persist_state_tx(…))` form panics
// at runtime on the multi_thread tokio runtime (the default for
// `#[tokio::main]`) — and "runtime" here means "the first time the
// scanner sees a real inscription on Mutinynet". CI did not catch the
// original form because no integration test ever drove the sync
// callback through a real multi_thread worker; this test does.

use super::*;
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;

/// Spin up a fresh `postgres:17` container, run all migrations, and
/// return the live pool. Mirrors `db_tests::setup_pool` but lives in
/// this file so the `main.rs` test module stays self-contained.
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
    let pool = db::connect_and_migrate(&url)
        .await
        .expect("connect_and_migrate failed");
    (pool, container)
}

/// Regression test for the scanner-callback panic.
///
/// The production scanner calls `persist_state_from_sync_context`
/// from a *synchronous* closure that runs *inline* on a multi_thread
/// tokio worker — the callback is invoked from inside an `async fn`,
/// so it executes on whichever worker thread is currently driving
/// the scanner task. The earlier form — `Handle::current().block_on(...)`
/// without `block_in_place` — panicked the first time a real
/// inscription was processed (see Tokio docs on `Handle::block_on`:
/// "may panic when called from a thread that is part of the current
/// Tokio runtime"). This test reproduces that exact shape:
///
///   1. Stand up a Postgres testcontainer + migrated pool.
///   2. From an `async fn` body running on a multi_thread worker,
///      invoke a synchronous closure that calls
///      `persist_state_from_sync_context` — the same call shape as
///      `scanner_runtime` → `InscriptionCallback`.
///   3. Re-read on the async side and assert the row landed.
///
/// If somebody ever "simplifies" the helper back to a bare
/// `Handle::current().block_on(...)`, this test panics with
/// "Cannot start a runtime from within a runtime" / "may panic" and
/// CI catches it before it ships.
///
/// `flavor = "multi_thread"` is *load-bearing*: `block_in_place`
/// itself panics on the current-thread flavor (`"can call blocking
/// only when running on the multi-threaded runtime"`). The
/// production bootstrap is multi_thread, so this test mirrors it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persist_state_from_sync_context_works_from_sync_closure_on_multi_thread() {
    let (pool, _container) = setup_pool().await;

    let smt = vec![0x11u8; 64];
    let mmr = vec![0x22u8; 128];
    let block = [0x33u8; 32];

    // The scanner's `InscriptionCallback` is a sync `Fn(...)` that
    // gets called from inside an `async fn`. We mimic that here: the
    // outer `async fn` (this test body) is on a multi_thread worker;
    // the closure below is a plain `FnOnce()` invoked inline, so it
    // runs on that same worker thread — exactly the topology where
    // bare `Handle::current().block_on(...)` panics.
    let persist_from_sync_closure = || -> Result<(), sqlx::Error> {
        persist_state_from_sync_context(&pool, &smt, &mmr, &block, None)
    };
    persist_from_sync_closure()
        .expect("persist_state_from_sync_context returned Err (regression: did block_in_place get removed?)");

    // Round-trip verification: the helper actually wrote what we
    // gave it. Without this assertion, a no-op stub would still pass
    // the "no panic" half of the test.
    assert_eq!(db::load_smt(&pool).await.unwrap(), Some(smt));
    assert_eq!(db::load_mmr(&pool).await.unwrap(), Some(mmr));
    assert_eq!(db::load_latest_block(&pool).await.unwrap(), Some(block));
}
