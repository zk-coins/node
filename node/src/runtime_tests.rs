//! Smoke tests that exercise the runtime bootstrap end-to-end.
//!
//! `runtime.rs` itself is excluded from the coverage scope (it
//! binds a real socket and owns the process lifecycle), but its
//! bootstrap path carries regressions that the 100% MVP-scope gate
//! cannot catch. Each test here covers a specific failure mode that
//! production has hit (or would hit on the next migration in the same
//! class):
//!
//! - `start_rest_node_binds_and_serves_health` — the Plonky2-migration
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

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::account_node::AccountNode;
use crate::runtime::start_rest_node;
use crate::state::State;
use crate::test_db::setup_pool;
use crate::username::UsernameStore;
use zkcoins_program::hash::digest_to_bytes;
use zkcoins_program::types::MINTING_ADDRESS;

// Shared-Postgres test infra (issue #181 Optimisation B): see
// `crate::test_db`. The previous file-local `setup_pool` is gone
// in favour of the shared helper; callers now keep the
// `SchemaScope` alive for the test's lifetime so its `Drop` can
// clean up the per-test schema after teardown.

/// Initialise the process-wide env vars the bootstrap reads through
/// `lazy_static` cells (`NETWORK_CONFIG`, `USERNAME_DOMAIN`) and the
/// `ZKCOINS_SKIP_BOOTSTRAP_WARMUP` opt-out exactly once per test
/// binary. The lazy_static cells freeze the values they observe on
/// first touch, so racing two `set_var` callers from different tests
/// is a use-after-free in spirit — issue #181 Opt A flips
/// `--test-threads=8`, which makes that race deterministic.
///
/// `OnceLock` gives a single "happens-before" barrier: the first
/// caller through here runs the `set_var` block, every subsequent
/// caller observes the initialised cell and returns immediately
/// without touching env. The `set_var` calls themselves are
/// idempotent — they only set if currently unset — so a host that
/// exports these via the pre-push hook keeps its own values.
///
/// `PROOFS_DIR` is intentionally NOT set here. Each test passes its
/// own `tempfile::tempdir()` path into `start_rest_node` as a
/// parameter so parallel tests cannot trample each other's proof
/// store. The env-read used to live inside `runtime::start_rest_node`;
/// it now lives at the binary edge in `main.rs` only.
fn ensure_test_env() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // Set each var only if currently unset — preserves whatever
        // the pre-push hook / CI workflow exported.
        let defaults: &[(&str, &str)] = &[
            ("USERNAME_DOMAIN", "test.zkcoins.local"),
            ("IS_MAINNET", "false"),
            ("ESPLORA_URL", "http://127.0.0.1:1/api"),
            ("ESPLORA_WS_URL", "ws://127.0.0.1:1/api/v1/ws"),
            // Smoke tests only need the listener to bind and serve
            // `/health` / `/api/balance`; they MUST NOT pay the
            // ~7 s background warmup tax (would double pre-push
            // wall and add nothing to the bootstrap failure-mode
            // coverage this file owns). With this flag set,
            // `prover_warm` is flipped to `true` immediately at
            // bootstrap and no `spawn_blocking` task is started.
            ("ZKCOINS_SKIP_BOOTSTRAP_WARMUP", "1"),
        ];
        for (k, v) in defaults {
            if std::env::var_os(k).is_none() {
                std::env::set_var(k, v);
            }
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_rest_node_binds_and_serves_health() {
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

    // Process-wide env init (idempotent + once-only). Replaces the
    // earlier per-test `std::env::set_var` block — under
    // `--test-threads=8` (issue #181 Opt A) two concurrent tests
    // would race on the lazy_static-frozen NETWORK_CONFIG values.
    ensure_test_env();

    // Per-test proofs dir — passed as a parameter to `start_rest_node`
    // so it does NOT touch process-wide env. `tempfile::tempdir`
    // removes the directory on Drop even when the test panics, so no
    // /tmp/zkcoins-* tree leaks on failure.
    let tmp = tempfile::tempdir().expect("create proofs tempdir");
    let proofs_dir = tmp.path().to_string_lossy().into_owned();

    // Mimic main.rs wiring: fresh State and empty AccountNode /
    // UsernameStore, so the bootstrap exercises the "no saved state"
    // branch that was the production failure mode.
    let state = Arc::new(Mutex::new(State::new()));
    let account_node = AccountNode::new(Arc::clone(&state));
    let username_store = UsernameStore::new();

    let scope = setup_pool().await;
    let pool = Arc::new(scope.pool.clone());

    let handle = tokio::spawn(async move {
        start_rest_node(account_node, username_store, &addr, pool, &proofs_dir).await
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
                // `tmp` (a `TempDir`) cleans itself up on Drop at
                // function return — no explicit `remove_dir_all`.
                assert!(
                    resp.starts_with("HTTP/1.1 200"),
                    "expected 200 on /health, got: {}",
                    &resp[..resp.len().min(300)]
                );
                // `/health` is the documented liveness probe whose
                // body is the literal string "ok" (see the route
                // registration in `router::create_router`). A 200
                // status with a different body would still satisfy
                // the old assertion but signal a regression in the
                // contract Kuma watches.
                let body = resp
                    .split("\r\n\r\n")
                    .nth(1)
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .trim();
                assert!(
                    body.starts_with("ok"),
                    "expected /health body to start with `ok`, got: {:?}",
                    body
                );
                return;
            }
            Err(e) => last_err = Some(e),
        }
    }
    handle.abort();
    panic!(
        "start_rest_node never bound on 127.0.0.1:{} within 5 s; last connect error: {:?}",
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

    // Process-wide env init — see the sibling smoke test for the
    // rationale (idempotent + once-only to keep `--test-threads=8`
    // parallel-safe).
    ensure_test_env();

    let tmp = tempfile::tempdir().expect("create proofs tempdir");
    let proofs_dir = tmp.path().to_string_lossy().into_owned();

    let state = Arc::new(Mutex::new(State::new()));
    let account_node = AccountNode::new(Arc::clone(&state));
    let username_store = UsernameStore::new();

    let scope = setup_pool().await;
    let pool = Arc::new(scope.pool.clone());

    let handle = tokio::spawn(async move {
        start_rest_node(account_node, username_store, &addr, pool, &proofs_dir).await
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
                // `tmp` (a `TempDir`) cleans itself up on Drop.
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
    panic!(
        "start_rest_node never bound on 127.0.0.1:{} within 5 s; last connect error: {:?}",
        port, last_err
    );
}

// Phase D removed the startup `check_minting_state_invariant` check.
// `num_pubkeys` is now derived from SMT membership at runtime
// (`state::derive_num_pubkeys_from_smt`), which is the same source the
// pre-Phase-D check measured the counter *against*. With the counter
// and the SMT collapsed into one value the desync mode the check
// guarded against can no longer arise, so the test that exercised the
// `CRITICAL: minting state desync` Err arm is gone too.
