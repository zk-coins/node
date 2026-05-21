//! Smoke tests that exercise the runtime bootstrap end-to-end.
//!
//! `server_runtime.rs` itself is excluded from the coverage scope (it
//! binds a real socket and owns the process lifecycle), but its
//! bootstrap path carries regressions that the 100% MVP-scope gate
//! cannot catch. Each test here covers a specific failure mode that
//! production has hit (or would hit on the next migration in the same
//! class):
//!
//! - `start_rest_server_binds_and_serves_health` — the Plonky2-migration
//!   outage. An `assert_eq!` against `MINTING_ADDRESS` panicked the
//!   tokio worker that owned the HTTP listener while the scanner worker
//!   kept running. Container stayed `Up`, Cloudflare served 502s for
//!   hours. The test probes `/health`; a bootstrap panic manifests as
//!   a TCP connect timeout and fails the test with a clear diagnostic.
//!
//! - `bootstrap_initial_minting_account_balance_is_goldilocks_safe` —
//!   guards the `1u64 << 48` constant for the seeded minting balance.
//!   `u64::MAX` (the pre-Plonky2 value) reduces mod the Goldilocks
//!   prime inside the state-transition circuit and trips a
//!   "wire set twice" panic on every mint. The test probes
//!   `/api/balance?address=<MINTING_ADDRESS hex>` and asserts the
//!   returned balance stays in the Goldilocks-safe range.
//!
//! Both tests share the same probe-port / spawn / wait / cleanup
//! shape; once a third bootstrap test lands the duplicated setup is
//! worth extracting into a helper.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sqlx::PgPool;
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;

use crate::account_server::AccountServer;
use crate::db::connect_and_migrate;
use crate::server_runtime::start_rest_server;
use crate::state::State;
use crate::username::UsernameStore;
use zkcoins_program::hash::digest_to_bytes;
use zkcoins_program::types::MINTING_ADDRESS;

/// Boot a fresh `postgres:17` container, run the server migrations
/// against it, and return the live pool plus the container handle.
/// Dropping the container handle tears the container down, so the
/// caller keeps it alive for the duration of the test.
///
/// Each test gets its own container — the same isolation model as
/// `db_tests::setup_pool`. The shape is duplicated here rather than
/// re-exported across modules to keep `db_tests` and
/// `server_runtime_tests` independently runnable (a shared helper
/// would have to live in a `pub(crate)` module guarded with `#[cfg
/// (test)]` and pulled in by both test files via `#[path = ...]`,
/// which is heavier than the few lines below). The PR-A3 cleanup may
/// dedupe both into a `test_db` helper module.
async fn setup_pool() -> (Arc<PgPool>, ContainerAsync<Postgres>) {
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
    (Arc::new(pool), container)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_rest_server_binds_and_serves_health() {
    // Pick a free ephemeral port by binding/dropping a probe listener.
    // The race window between drop and rebind is irrelevant in CI and
    // pre-push (no other process listens on this port); a collision
    // would surface as a deterministic bind error below, not silent
    // corruption.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    let addr = format!("127.0.0.1:{}", port);

    // The lazy_static reads of `NETWORK_CONFIG` and `USERNAME_DOMAIN`
    // happen on first access in this test binary. The pre-push hook
    // exports both of these already; setting them here defensively
    // makes the test runnable in any environment.
    std::env::set_var("USERNAME_DOMAIN", "test.zkcoins.local");
    std::env::set_var("ESPLORA_URL", "http://127.0.0.1:1/api");

    // PR-A3 moved all sibling-file state (accounts.bin, usernames.bin,
    // minting_num_pubkeys.bin) into Postgres; the bootstrap only needs
    // a proofs directory now, which is configured via the `PROOFS_DIR`
    // env var read inside `start_rest_server`. PID + port keeps the
    // tempdir unique across parallel runs even though pre-push uses
    // --test-threads=1.
    let tmp = std::env::temp_dir().join(format!(
        "zkcoins-startup-test-{}-{}",
        std::process::id(),
        port
    ));
    std::fs::create_dir_all(&tmp).expect("create tempdir");
    std::env::set_var("PROOFS_DIR", tmp.to_string_lossy().into_owned());

    // Mimic main.rs wiring: fresh State and empty AccountServer /
    // UsernameStore, so the bootstrap exercises the "no saved state"
    // branch that was the production failure mode.
    let state = Arc::new(Mutex::new(State::new()));
    let account_server = AccountServer::new(Arc::clone(&state));
    let username_store = UsernameStore::new();

    let (pool, _pg_container) = setup_pool().await;

    let handle = tokio::spawn(async move {
        start_rest_server(account_server, username_store, &addr, pool).await
    });

    // Wait for the listener to come up. axum binds within ~hundreds of
    // ms on a warm cargo cache; cap the wait at 5 s so a regression
    // fails fast instead of hanging the whole suite.
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(mut stream) => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                stream
                    .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    .await
                    .expect("write probe");
                let mut buf = vec![0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]).into_owned();
                handle.abort();
                std::fs::remove_dir_all(&tmp).ok();
                assert!(
                    resp.starts_with("HTTP/1.1 200"),
                    "expected 200 on /health, got: {}",
                    &resp[..resp.len().min(300)]
                );
                return;
            }
            Err(e) => last_err = Some(e),
        }
    }
    handle.abort();
    std::fs::remove_dir_all(&tmp).ok();
    panic!(
        "start_rest_server never bound on 127.0.0.1:{} within 5 s; last connect error: {:?}",
        port, last_err
    );
}

/// Regression guard: the bootstrap-seeded minting account balance must
/// stay Goldilocks-safe (strictly less than `2^48`).
///
/// The Plonky2 state-transition circuit packs `u64` balances as
/// `balance_hi * 2^32 + balance_lo`. Values at or above the Goldilocks
/// modulus `p ≈ 2^64 - 2^32 + 1` reduce mod `p` inside the circuit but
/// stay full-width in the witness setter — that mismatch trips a
/// "wire set twice" partition error and panics every mint operation.
/// Before the Plonky2 migration the initial balance was `u64::MAX`,
/// which is exactly the value that triggers the panic.
///
/// This test exercises the bootstrap end-to-end, queries the public
/// `/api/balance?address=<MINTING_ADDRESS hex>` endpoint, and asserts
/// the returned balance is non-zero *and* well below `2^49` (one bit of
/// head-room above the documented `< 2^48` cap so a deliberate bump
/// within the safe range does not require updating the test, while a
/// regression to `u64::MAX` or any other unsafe value fails loudly).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bootstrap_initial_minting_account_balance_is_goldilocks_safe() {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    let addr = format!("127.0.0.1:{}", port);

    std::env::set_var("USERNAME_DOMAIN", "test.zkcoins.local");
    std::env::set_var("ESPLORA_URL", "http://127.0.0.1:1/api");

    let tmp = std::env::temp_dir().join(format!(
        "zkcoins-balance-test-{}-{}",
        std::process::id(),
        port
    ));
    std::fs::create_dir_all(&tmp).expect("create tempdir");
    std::env::set_var("PROOFS_DIR", tmp.to_string_lossy().into_owned());

    let state = Arc::new(Mutex::new(State::new()));
    let account_server = AccountServer::new(Arc::clone(&state));
    let username_store = UsernameStore::new();

    let (pool, _pg_container) = setup_pool().await;

    let handle = tokio::spawn(async move {
        start_rest_server(account_server, username_store, &addr, pool).await
    });

    let minting_hex = hex::encode(digest_to_bytes(&MINTING_ADDRESS));
    let request = format!(
        "GET /api/balance?address={} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        minting_hex
    );

    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(mut stream) => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                stream
                    .write_all(request.as_bytes())
                    .await
                    .expect("write probe");
                let mut buf = Vec::with_capacity(2048);
                stream.read_to_end(&mut buf).await.expect("read response");
                handle.abort();
                std::fs::remove_dir_all(&tmp).ok();
                let resp = String::from_utf8_lossy(&buf).into_owned();
                assert!(
                    resp.starts_with("HTTP/1.1 200"),
                    "expected 200 on /api/balance, got: {}",
                    &resp[..resp.len().min(300)]
                );
                // Body is the JSON payload after the blank line separating
                // headers and body. Find it and parse the `balance` field.
                let body = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&resp);
                let parsed: serde_json::Value =
                    serde_json::from_str(body.trim()).unwrap_or_else(|e| {
                        panic!("failed to parse balance JSON body {:?}: {}", body, e)
                    });
                let balance = parsed
                    .get("balance")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_else(|| panic!("balance field missing or not u64: {}", body));
                assert!(
                    balance > 0,
                    "bootstrap must seed a non-zero minting balance, got 0 \
                     (regression: bootstrap path skipped or import_account broken)"
                );
                assert!(
                    balance < (1u64 << 49),
                    "bootstrap minting balance {} is NOT Goldilocks-safe \
                     (must stay below 2^48; 2^49 ceiling here gives 1 bit of \
                     head-room). u64::MAX or any value >= p would panic the \
                     Plonky2 circuit with `wire set twice` on the next mint.",
                    balance
                );
                return;
            }
            Err(e) => last_err = Some(e),
        }
    }
    handle.abort();
    std::fs::remove_dir_all(&tmp).ok();
    panic!(
        "start_rest_server never bound on 127.0.0.1:{} within 5 s; last connect error: {:?}",
        port, last_err
    );
}
