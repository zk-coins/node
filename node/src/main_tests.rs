// Bootstrap-level tests for `main.rs` and the lib-root helpers it
// invokes (`build_network_config_from_env`, the
// `persist_state_from_sync_context` bridge).

use super::*;
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;

// --- build_network_config_from_env -------------------------------
//
// These tests cover the panic-on-missing rules for the Mainnet path.
// They use a fake `env` closure rather than `std::env::set_var` so
// the panic side-effect cannot poison the `NETWORK_CONFIG`
// lazy_static cell (shared across tests in this binary) and so the
// tests do not race other test threads via the process-wide
// environment.

/// Build a closure-shaped env from a slice so the tests read like a
/// table. Returns the first matching value or `None`.
fn fake_env(entries: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |k| {
        entries.iter().find_map(|(name, value)| {
            if *name == k {
                Some((*value).to_string())
            } else {
                None
            }
        })
    }
}

#[test]
fn build_network_config_defaults_to_mutinynet_when_is_mainnet_unset() {
    let cfg = build_network_config_from_env(fake_env(&[]));
    assert!(!cfg.is_mainnet);
    assert_eq!(cfg.url, "https://mutinynet.com/api");
    assert_eq!(cfg.network_name, "Mutinynet");
    assert!(cfg.ws_url.is_none());
}

#[test]
fn build_network_config_defaults_to_mutinynet_when_is_mainnet_is_not_true() {
    // Any value other than the literal string "true" is treated as
    // "not mainnet" — same semantics as the legacy `.map(|v| v == "true")`
    // pattern. Guards against accidental "TRUE" / "1" / "yes" thinking
    // it switches the network.
    let cfg = build_network_config_from_env(fake_env(&[("IS_MAINNET", "1")]));
    assert!(!cfg.is_mainnet);
    assert_eq!(cfg.url, "https://mutinynet.com/api");
    assert!(cfg.ws_url.is_none());
}

#[test]
fn build_network_config_respects_explicit_urls_on_mutinynet() {
    let cfg = build_network_config_from_env(fake_env(&[
        ("ESPLORA_URL", "http://electrs-mutinynet:3000"),
        ("ESPLORA_WS_URL", "wss://example.test/ws"),
        ("NETWORK_NAME", "Custom"),
    ]));
    assert!(!cfg.is_mainnet);
    assert_eq!(cfg.url, "http://electrs-mutinynet:3000");
    assert_eq!(cfg.ws_url.as_deref(), Some("wss://example.test/ws"));
    assert_eq!(cfg.network_name, "Custom");
}

#[test]
fn build_network_config_full_mainnet() {
    let cfg = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_URL", "http://electrs-mainnet:3000"),
        ("ESPLORA_WS_URL", "wss://mempool.space/api/v1/ws"),
    ]));
    assert!(cfg.is_mainnet);
    assert_eq!(cfg.url, "http://electrs-mainnet:3000");
    assert_eq!(cfg.ws_url.as_deref(), Some("wss://mempool.space/api/v1/ws"));
    assert_eq!(cfg.network_name, "Mainnet");
}

#[test]
fn build_network_config_mainnet_with_explicit_network_name() {
    // Mainnet path with `NETWORK_NAME` set: the override must win
    // over the `if is_mainnet { "Mainnet" } else { "Mutinynet" }`
    // default branch. Documents that operators can rename the chain
    // label (e.g. "Mainnet-Canary") without changing IS_MAINNET.
    let cfg = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_URL", "http://electrs-mainnet:3000"),
        ("ESPLORA_WS_URL", "wss://mempool.space/api/v1/ws"),
        ("NETWORK_NAME", "Mainnet-Canary"),
    ]));
    assert!(cfg.is_mainnet);
    assert_eq!(cfg.network_name, "Mainnet-Canary");
}

#[test]
#[should_panic(expected = "IS_MAINNET=true requires ESPLORA_URL")]
fn build_network_config_panics_on_mainnet_missing_esplora_url() {
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_WS_URL", "wss://mempool.space/api/v1/ws"),
    ]));
}

#[test]
#[should_panic(expected = "IS_MAINNET=true requires ESPLORA_URL")]
fn build_network_config_panics_on_mainnet_empty_esplora_url() {
    // `ESPLORA_URL=` in a compose file resolves to `Some("")`. Without
    // the empty-string filter in `env_or_unset`, the `expect` would
    // be bypassed and `EsploraConfig.url` would be left as `""` —
    // exactly the silent-misconfiguration class the panic is meant
    // to catch.
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_URL", ""),
        ("ESPLORA_WS_URL", "wss://mempool.space/api/v1/ws"),
    ]));
}

#[test]
#[should_panic(expected = "IS_MAINNET=true requires ESPLORA_WS_URL")]
fn build_network_config_panics_on_mainnet_missing_esplora_ws_url() {
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_URL", "http://electrs-mainnet:3000"),
    ]));
}

#[test]
#[should_panic(expected = "IS_MAINNET=true requires ESPLORA_WS_URL")]
fn build_network_config_panics_on_mainnet_whitespace_esplora_ws_url() {
    // Whitespace-only values are also rejected — same misconfiguration
    // class as the empty string, just easier to miss in a diff.
    let _ = build_network_config_from_env(fake_env(&[
        ("IS_MAINNET", "true"),
        ("ESPLORA_URL", "http://electrs-mainnet:3000"),
        ("ESPLORA_WS_URL", "   "),
    ]));
}

// --- persist_state_from_sync_context -----------------------------
//
// Regression coverage for the `block_in_place(block_on(...))` bridge
// used inside the scanner's synchronous `InscriptionCallback`.
// Without `block_in_place`, the naive
// `Handle::current().block_on(persist_state_tx(…))` form panics at
// runtime on the multi_thread tokio runtime (the default for
// `#[tokio::main]`) — and "runtime" here means "the first time the
// scanner sees a real inscription on Mutinynet". CI did not catch
// the original form because no integration test ever drove the sync
// callback through a real multi_thread worker; this test does.

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
