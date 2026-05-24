//! Runtime bootstrap: binds a TCP listener and runs the Axum app.
//!
//! This file is intentionally excluded from the coverage scope. The
//! function below cannot be exercised by unit tests — it owns the
//! process lifecycle (port binding, signal-driven shutdown via axum)
//! and exists purely to wire the dependency graph defined in
//! `router.rs` to a real network socket.
//!
//! Anything that is testable in isolation (handlers, helpers, the
//! router construction in `create_router`) stays in `router.rs` and
//! is measured normally.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::Json;
use shared::commitment::Commitment;
use sqlx::PgPool;
use tokio::net::TcpListener;

use crate::account_node::{persist_account, CoinProof};
use crate::db;
use crate::publisher::create_and_broadcast_inscription;
use crate::router::{lock_or_recover, SendCoinResponse};
use crate::NETWORK_CONFIG;

use bitcoin::bip32::Xpriv;
use shared::ClientAccount;

use crate::account_node::AccountNode;
use crate::router::{create_router, AppState, ProofStore};
use crate::username::UsernameStore;

/// Default cap on how long the startup invariant check waits for the
/// scanner to ingest at least one block before evaluating the SMT
/// membership predicate. See [`check_minting_state_invariant`] for the
/// trade-off this knob bounds. Overridable via the
/// `SCANNER_INITIAL_SETTLE_TIMEOUT_MS` env var (set to `0` in unit tests
/// that drive the invariant check without a running scanner).
const SCANNER_INITIAL_SETTLE_TIMEOUT_MS_DEFAULT: u64 = 90_000;

/// Poll cadence for the scanner-progress wait inside
/// [`check_minting_state_invariant`]. Small enough that a settled
/// scanner unblocks the bootstrap within ~50 ms, large enough to keep
/// the busy-wait cost negligible.
const SCANNER_PROGRESS_POLL_INTERVAL: Duration = Duration::from_millis(50);

fn scanner_initial_settle_timeout() -> Duration {
    let ms = std::env::var("SCANNER_INITIAL_SETTLE_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(SCANNER_INITIAL_SETTLE_TIMEOUT_MS_DEFAULT);
    Duration::from_millis(ms)
}

pub async fn start_rest_node(
    account_node: AccountNode,
    username_store: UsernameStore,
    addr: &str,
    pool: Arc<PgPool>,
    scanner_progress: Option<Arc<AtomicU64>>,
) -> anyhow::Result<()> {
    let socket_addr = addr
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("Failed to parse address: {}", e))?;

    let shared_account_node = Arc::new(Mutex::new(account_node));

    // Proof files keep using a local directory — the proof store is
    // append-only and the proofs themselves are large (bincode-
    // serialized Plonky2 proofs) so a `BYTEA` column would balloon the
    // Postgres image. `PROOFS_DIR` defaults to `./proofs` for parity
    // with the pre-PR-A3 layout; the deployment overrides it to the
    // mounted data volume.
    let proofs_dir = std::env::var("PROOFS_DIR").unwrap_or_else(|_| "./proofs".to_string());
    let proof_store = Arc::new(ProofStore::new(&proofs_dir));

    let minting_account = {
        let secret = include_bytes!("../minting_secret.bin");
        let private_key = Xpriv::new_master(NETWORK_CONFIG.network(), secret)
            .expect("Failed to create private key.");
        println!(
            "Set MINTING_ADDRESS to {:?}",
            *zkcoins_program::types::MINTING_ADDRESS
        );
        let mut minting_client = ClientAccount::new(private_key);
        // ClientAccount::new starts with num_pubkeys=0, but each successful
        // mint increments it. The counter MUST survive process restarts;
        // otherwise we lose alignment with the server-side
        // minting_account.proof (which IS persisted), the next mint sends
        // the wrong prev_commitment_pubkey, and send_coins fails with
        // "prev_commitment_pubkey required for account update".
        //
        // PR-A3 moved the counter from the `minting_num_pubkeys.bin`
        // sibling file into the `minting_meta` Postgres table. A read
        // failure here is non-fatal — we log it and start from 0,
        // exactly like the legacy file-missing fallback used to do.
        match db::load_minting_num_pubkeys(&pool).await {
            Ok(Some(n)) => {
                println!("Loaded minting num_pubkeys={} from Postgres", n);
                minting_client.num_pubkeys = n;
            }
            Ok(None) => {
                println!("No minting_meta row found, starting num_pubkeys=0");
            }
            Err(e) => {
                eprintln!(
                    "Failed to load minting num_pubkeys from Postgres ({}); starting at 0",
                    e
                );
            }
        }
        // Plonky2 migration (D11 in MIGRATION_RESEARCH.md): MINTING_ADDRESS
        // is now a well-known constant derived from `hash_bytes(b"zkcoins:
        // minting-address:placeholder:v1")`, NOT from minting_secret.bin.
        // ClientAccount::new derives `address` from the privkey's first
        // child pubkey for ordinary wallets; for the minting wallet that
        // derivation is meaningless — only the wallet's commitment-signing
        // side is used. Force the address to the canonical constant so
        // the rest of the server (which reads minting_account.address as
        // the on-chain identity of the minting wallet) is internally
        // consistent. The test harness already constructs the minting
        // account this way (see
        // router_tests.rs::TestAccountData::new_minting_account).
        minting_client.address = *zkcoins_program::types::MINTING_ADDRESS;
        Arc::new(Mutex::new(minting_client))
    };

    let shared_username_store = Arc::new(Mutex::new(username_store));

    let state = AppState {
        account_node: shared_account_node,
        proof_store,
        minting_account,
        username_store: shared_username_store,
        pool: Arc::clone(&pool),
        // The readiness probe uses this to ping Esplora; in production
        // it points at the same `ESPLORA_URL` as the scanner / publisher.
        esplora_config: Arc::new(NETWORK_CONFIG.clone()),
        #[cfg(test)]
        phase2_reached: Arc::new(tokio::sync::Notify::new()),
    };

    // Bootstrap the minting account if it isn't already in the DB.
    // The snapshot pattern mirrors the handler sites: take the
    // mutation under the sync guard, then drop the guard before the
    // async upsert.
    let bootstrap_snapshot: Option<(zkcoins_program::hash::HashDigest, Vec<u8>)> = {
        let mut account_node_guard = state.account_node.lock().unwrap();
        if account_node_guard.get_minting_account_address().is_err() {
            let mut minting_server_account = crate::account_node::Account::new();
            // The Plonky2 state-transition circuit packs the running
            // balance as a Goldilocks field element via
            // `balance_hi * 2^32 + balance_lo`. Values >= p (the
            // Goldilocks prime ≈ 2^64 - 2^32 + 1) reduce mod p inside
            // the circuit but stay full-width in the witness setter,
            // which trips a "wire set twice" partition error. Stay
            // safely below 2^48 so the circuit-vs-witness sides agree
            // even after many mint operations.
            minting_server_account.balance = 1u64 << 48;
            account_node_guard.import_account(
                *zkcoins_program::types::MINTING_ADDRESS,
                minting_server_account,
            );
            account_node_guard
                .get_account(&zkcoins_program::types::MINTING_ADDRESS)
                .map(AccountNode::serialize_account)
                .map(|bytes| (*zkcoins_program::types::MINTING_ADDRESS, bytes))
        } else {
            None
        }
    };
    if let Some((address, _bytes)) = bootstrap_snapshot.as_ref() {
        // Look the account up once more through `persist_account` so
        // the helper's error variants are wired in the same way as the
        // handler sites. The address + (re-fetched) account go through
        // the lock again only briefly; the second snapshot reads the
        // same row we just inserted so it is guaranteed to be present.
        let acct_clone = {
            let guard = state.account_node.lock().unwrap();
            guard.get_account(address).and_then(|a| {
                let b = AccountNode::serialize_account(a);
                bincode::deserialize::<crate::account_node::Account>(&b).ok()
            })
        };
        if let Some(account) = acct_clone {
            if let Err(e) = persist_account(&pool, address, &account).await {
                eprintln!("Failed to upsert bootstrap minting account: {}", e);
            }
        }
    }

    // Startup invariant check (zk-coins/node#89): every persisted
    // minting-account pubkey index in `0..num_pubkeys` MUST have a
    // commitment in the SMT. A mismatch means the legacy
    // write-ahead-of-broadcast mint flow advanced the counter past a
    // failed inscription — every subsequent `/api/mint` and `/api/send`
    // for the minting account would 422 on the missing merkle proof.
    // The fix lives in `mint_handler` itself; this check is the second
    // line of defence — it refuses to start the listener until the
    // operator runs the `reset_state` workflow to restore the
    // invariant.
    //
    // NO break-glass flag. Strict by default. Operator override is a
    // code patch, not an env var.
    {
        let starting_num_pubkeys = {
            let guard = lock_or_recover(&state.minting_account);
            guard.num_pubkeys
        };
        check_minting_state_invariant(&state, starting_num_pubkeys, scanner_progress.as_deref())
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
    }

    let app = create_router(state);

    println!("REST server started at {}", socket_addr);
    let listener = TcpListener::bind(socket_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Verify every persisted minting-account pubkey index `0..num_pubkeys`
/// is anchored by a commitment in the SMT.
///
/// Returns `Ok(())` on a fresh state (`num_pubkeys == 0`) or after every
/// index has been verified. Returns `Err(CRITICAL log message)` on the
/// first miss — the caller propagates the error up so the bootstrap
/// fails with a non-zero exit code, matching the project's no-degraded-
/// mode startup policy.
///
/// **Scanner-settle wait (zk-coins/node#89 round-2 MAJOR 2).** Before
/// declaring a desync the function waits up to
/// [`scanner_initial_settle_timeout`] (default 90 s, overridable via
/// `SCANNER_INITIAL_SETTLE_TIMEOUT_MS`) for the scanner to ingest at
/// least one block. The signal is the `scanner_progress` `AtomicU64`
/// fed by `main.rs`'s scanner callback (incremented on every
/// `state.update` call). Without this wait, a fresh-state restart whose
/// scanner has not yet caught the latest mint inscription would
/// false-positive — the minting_meta counter is already at `N` from the
/// pre-restart `commit_mint_tx`, but the SMT has not yet seen the
/// inscription for pubkey index `N-1`. The trade-off: a real desync now
/// takes up to 90 s to surface, but transient restart desyncs no longer
/// crash-loop the container indefinitely waiting for an operator to
/// notice. If the timeout expires the invariant check still runs — a
/// genuine desync where the scanner is healthy but the inscription was
/// never persisted will fail loudly, just 90 s later than before.
///
/// When `scanner_progress` is `None` (unit tests, fresh-state
/// `num_pubkeys = 0` bootstraps) the wait is skipped.
///
/// **No break-glass flag.** Strict by default. If an operator needs
/// to start the server with a known state desync (e.g. to inspect the
/// damage), they must patch this function out. The lack of an env
/// override is intentional — the previous `DEV_SKIP_BROADCAST_FAILURE`
/// pattern is exactly the kind of silent-soft-fail that this check
/// is here to prevent (see zk-coins/node#89).
pub(crate) async fn check_minting_state_invariant(
    state: &AppState,
    num_pubkeys: u32,
    scanner_progress: Option<&AtomicU64>,
) -> Result<(), String> {
    if num_pubkeys == 0 {
        println!("Startup invariant: minting num_pubkeys=0, no SMT membership to verify");
        return Ok(());
    }

    // Wait for the scanner to ingest at least one inscription before
    // declaring a desync. See doc-comment above for the trade-off.
    if let Some(progress) = scanner_progress {
        let timeout = scanner_initial_settle_timeout();
        if timeout.is_zero() {
            println!(
                "Startup invariant: scanner-settle wait skipped (SCANNER_INITIAL_SETTLE_TIMEOUT_MS=0)"
            );
        } else {
            let deadline = Instant::now() + timeout;
            let mut settled = false;
            loop {
                if progress.load(Ordering::Relaxed) > 0 {
                    println!("Startup invariant: scanner reported progress within settle window");
                    settled = true;
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(SCANNER_PROGRESS_POLL_INTERVAL).await;
            }
            if !settled {
                println!(
                    "Startup invariant: scanner settle timeout ({} ms) elapsed without progress, \
                     evaluating SMT membership against current state",
                    timeout.as_millis()
                );
            }
        }
    }

    let minting_pubkeys: Vec<bitcoin::secp256k1::PublicKey> = {
        let guard = lock_or_recover(&state.minting_account);
        (0..num_pubkeys)
            .map(|i| guard.generate_public_key(i))
            .collect()
    };
    let account_node_guard = lock_or_recover(&state.account_node);
    let state_arc = account_node_guard.state().clone();
    drop(account_node_guard);
    let state_guard = lock_or_recover(&state_arc);
    for (i, pk) in minting_pubkeys.iter().enumerate() {
        if state_guard.get_commitment_proof(pk).is_err() {
            let msg = format!(
                "CRITICAL: minting state desync at pubkey_idx={}: commitment not in SMT. \
                 Operator action: dispatch reset_state workflow or repair manually. \
                 See zk-coins/node#89.",
                i
            );
            eprintln!("{}", msg);
            return Err(msg);
        }
    }
    println!(
        "Startup invariant: all {} minting pubkeys have commitments in SMT",
        num_pubkeys
    );
    Ok(())
}

/// Broadcast the commit inscription and, on success, deliver the coin
/// to the recipient and persist the account state. This contains the
/// network call (Bitcoin broadcast) and the post-broadcast bookkeeping,
/// plus the success/failure response dispatch — all of which cannot be
/// exercised by unit tests, so the whole function lives in the runtime
/// module that is excluded from the coverage scope.
///
/// **Invariant (zk-coins/node#89).** The broadcast `if let Err(...)
/// { return 503 }` MUST stay above every `receive_coin`/`upsert_account`
/// line. The mint flow had to be refactored to prepare-then-commit
/// because its old shape advanced state ahead of broadcast; this
/// function does not have that bug because its broadcast is already
/// the first effect. Any future refactor that moves a state mutation
/// above the broadcast re-introduces the state-desync class — do not.
pub(crate) async fn broadcast_commit_and_deliver(
    state: &AppState,
    commitment: Commitment,
    coin_proof: CoinProof,
    proof_id: u64,
) -> (StatusCode, Json<SendCoinResponse>) {
    let commitment_data = bincode::serialize(&commitment).expect("Failed to serialize commitment");
    println!(
        "Broadcasting user commitment ({} bytes)",
        commitment_data.len()
    );
    if let Err(err) = create_and_broadcast_inscription(&commitment_data, &NETWORK_CONFIG).await {
        eprintln!("Error broadcasting commit inscription: {}", err);
        return crate::router::handler_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Failed to broadcast commitment inscription on-chain",
        );
    }

    let mut updated_proof = coin_proof;
    updated_proof.commitment = Some(commitment);
    let recipient = updated_proof.coin.recipient;
    let snapshot: Option<Vec<u8>> = {
        let mut account_node_guard = lock_or_recover(&state.account_node);
        if let Err(e) = account_node_guard.receive_coin(updated_proof) {
            eprintln!("Failed to receive coin after commit: {}", e);
        }
        account_node_guard
            .get_account(&recipient)
            .map(AccountNode::serialize_account)
    };
    if let Some(bytes) = snapshot {
        let addr_bytes = zkcoins_program::hash::digest_to_bytes(&recipient);
        if let Err(e) = db::upsert_account(&state.pool, &addr_bytes, &bytes).await {
            eprintln!("Failed to upsert account after commit: {}", e);
        }
    }

    (
        StatusCode::OK,
        Json(SendCoinResponse {
            success: true,
            error: None,
            proof_id: Some(proof_id),
            account_state_hash: None,
            output_coins_root: None,
        }),
    )
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
