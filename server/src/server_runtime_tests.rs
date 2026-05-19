//! Smoke test that exercises the runtime bootstrap end-to-end.
//!
//! `server_runtime.rs` itself is excluded from the coverage scope (it
//! binds a real socket and owns the process lifecycle), but its bootstrap
//! path WAS the failure mode in the Plonky2 migration: an `assert_eq!`
//! against `MINTING_ADDRESS` panicked the tokio worker that owned the
//! HTTP listener while the scanner worker kept running. The container
//! stayed `Up` for hours, Cloudflare served 502s, and no unit test
//! caught it because no test ever ran the bootstrap path.
//!
//! This test spawns `start_rest_server` against an ephemeral port, waits
//! for the listener to come up, and probes `/health`. A bootstrap panic
//! (or any other early failure) manifests as a TCP connect timeout and
//! the test fails with a clear diagnostic.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::account_server::AccountServer;
use crate::server_runtime::start_rest_server;
use crate::state::State;
use crate::username::UsernameStore;

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

    // Per-invocation tempdir for the persistent files the bootstrap
    // writes (initial accounts seed). PID + port keeps it unique across
    // parallel runs even though pre-push uses --test-threads=1.
    let tmp = std::env::temp_dir().join(format!(
        "zkcoins-startup-test-{}-{}",
        std::process::id(),
        port
    ));
    std::fs::create_dir_all(&tmp).expect("create tempdir");
    let accounts_path = tmp.join("accounts.bin").to_string_lossy().into_owned();
    let usernames_path = tmp.join("usernames.bin").to_string_lossy().into_owned();

    // Mimic main.rs wiring: fresh State and empty AccountServer /
    // UsernameStore, so the bootstrap exercises the "no saved state"
    // branch that was the production failure mode.
    let state = Arc::new(Mutex::new(State::new()));
    let account_server = AccountServer::new(Arc::clone(&state));
    let username_store = UsernameStore::new();

    let handle = tokio::spawn(async move {
        start_rest_server(
            account_server,
            username_store,
            &addr,
            accounts_path,
            usernames_path,
        )
        .await
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
