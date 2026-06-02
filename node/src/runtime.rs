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

use dashmap::DashMap;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use crate::account_node::persist_account;
use crate::job_dispatcher::{self, DEFAULT_AWAITING_SIGNATURE_TIMEOUT};
use crate::job_store::{JobStatus, JobStore};
use crate::publisher::resume_pending_inscriptions;
use crate::NETWORK_CONFIG;

use bitcoin::bip32::Xpriv;
use shared::ClientAccount;

use crate::account_node::AccountNode;
use crate::router::{create_router, AppState, ProofStore};
use crate::username::UsernameStore;

pub async fn start_rest_node(
    account_node: AccountNode,
    username_store: UsernameStore,
    addr: &str,
    pool: Arc<PgPool>,
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
        // Phase D: `num_pubkeys` is no longer carried in the shared
        // ClientAccount as boot state. Each `/api/mint` derives the
        // count fresh from the SMT via
        // `state::derive_num_pubkeys_from_smt`, which is the canonical
        // source of truth (the SMT is loaded from Postgres at boot and
        // mutated by the scanner on every inscription). The in-memory
        // field stays at 0 here; mint_handler reads N off the SMT
        // before deriving pubkeys and signs with a transient clone at
        // `num_pubkeys = N + 1` exactly as before.
        //
        // Plonky2 migration (D11 in MIGRATION_RESEARCH.md): MINTING_ADDRESS
        // is a well-known constant derived from `hash_bytes(b"zkcoins:
        // minting-address:placeholder:v1")`, NOT from minting_secret.bin.
        // ClientAccount::new derives `address` from the privkey's first
        // child pubkey for ordinary wallets; for the minting wallet that
        // derivation is meaningless — only the wallet's commitment-signing
        // side is used. Force the address to the canonical constant so
        // the rest of the node (which reads minting_account.address as
        // the on-chain identity of the minting wallet) is internally
        // consistent. The test harness already constructs the minting
        // account this way (see
        // router_tests.rs::TestAccountData::new_minting_account).
        minting_client.address = *zkcoins_program::types::MINTING_ADDRESS;
        Arc::new(Mutex::new(minting_client))
    };

    let shared_username_store = Arc::new(Mutex::new(username_store));

    // Background-warmup readiness flag. Default `false`; flipped to
    // `true` by either the background `spawn_blocking` task below (once
    // `AccountNode::warmup_prover` returns Ok) or immediately if the
    // operator set `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1`. Consumed by
    // `/health/ready`; see the field doc on `AppState::prover_warm`.
    let prover_warm = Arc::new(AtomicBool::new(false));

    // Job-API state-layer. The dispatcher is spawned below once
    // the AppState is fully populated; the mpsc channel is owned
    // by `start_rest_node` so the sender clone can be threaded
    // into the AppState before the dispatcher takes ownership of
    // the receiver half.
    let job_store = Arc::new(JobStore::new((*pool).clone()));
    let job_notify_map = Arc::new(DashMap::new());
    let (job_tx, job_rx) = tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(32);

    let state = AppState {
        account_node: Arc::clone(&shared_account_node),
        proof_store,
        minting_account,
        username_store: shared_username_store,
        pool: Arc::clone(&pool),
        // The readiness probe uses this to ping Esplora; in production
        // it points at the same `ESPLORA_URL` as the scanner / publisher.
        esplora_config: Arc::new(NETWORK_CONFIG.clone()),
        prover_warm: Arc::clone(&prover_warm),
        job_store: Arc::clone(&job_store),
        job_tx: job_tx.clone(),
        job_notify_map: Arc::clone(&job_notify_map),
    };

    // Bootstrap the minting account if it isn't already in the DB.
    // The snapshot pattern mirrors the handler sites: take the
    // mutation under the sync guard, then drop the guard before the
    // async upsert.
    let bootstrap_snapshot: Option<(zkcoins_program::hash::HashDigest, Vec<u8>)> = {
        let mut account_node_guard = state.account_node.lock().unwrap();
        if account_node_guard.get_minting_account_address().is_err() {
            let mut minting_node_account = crate::account_node::Account::new();
            // The Plonky2 state-transition circuit packs the running
            // balance as a Goldilocks field element via
            // `balance_hi * 2^32 + balance_lo`. Values >= p (the
            // Goldilocks prime ≈ 2^64 - 2^32 + 1) reduce mod p inside
            // the circuit but stay full-width in the witness setter,
            // which trips a "wire set twice" partition error. Stay
            // safely below 2^48 so the circuit-vs-witness sides agree
            // even after many mint operations.
            minting_node_account.balance = 1u64 << 48;
            account_node_guard.import_account(
                *zkcoins_program::types::MINTING_ADDRESS,
                minting_node_account,
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

    // Phase D removed the startup `check_minting_state_invariant`:
    // `num_pubkeys` is now derived from SMT membership at runtime
    // (`state::derive_num_pubkeys_from_smt`), so the predicate the
    // check measured ("every pubkey_idx ∈ 0..num_pubkeys has a
    // commitment in the SMT") is a tautology by construction. The
    // pre-Phase-D check existed only because the counter and the SMT
    // could disagree — collapsing them into one removes the disagree
    // mode and the check that measured it.

    // Phase B: re-broadcast any pending inscriptions left over from
    // a previous boot. A crash between commit-broadcast and
    // reveal-broadcast (or between construction and either broadcast)
    // leaves a row in `pending_inscriptions` with status != complete;
    // walk each one to completion before opening the listener so
    // operators do not see a stuck UTXO until the next mint triggers
    // the resumer.
    //
    // Failures here are LOGGED and SWALLOWED — the operator's escape
    // hatch is the PR #106 CLI recovery tool, and a transient
    // Esplora outage on boot must not crash-loop the container.
    if let Err(e) = resume_pending_inscriptions(&pool, &NETWORK_CONFIG).await {
        eprintln!(
            "Failed to resume pending inscriptions on bootstrap (continuing anyway): {}",
            e
        );
    }

    // Job-API boot-time resumer. The dispatcher walks each job
    // through the state machine; if the process restarts mid-way
    // through a `proving` / `broadcasting` row, the in-process
    // Plonky2 prover state is lost and the signed wallet payload's
    // timestamp window has expired by the time anyone notices. The
    // safest action is to mark every interrupted row `failed`
    // before serving so the wallet observes a terminal status on
    // its next poll and can re-submit (with a fresh timestamp +
    // fresh idempotency key). Jobs already at `awaiting_signature`
    // are different — the wallet may still come back with a valid
    // signature, so we re-arm the per-job `Notify` channel and
    // hand the public_id back to the dispatcher to park on. See
    // the `list_interrupted_for_resume` doc-comment for the
    // partitioning rationale.
    if let Err(e) = boot_resume_jobs(&job_store, &job_notify_map, &job_tx).await {
        eprintln!("Job-API boot-time resume failed (continuing anyway): {}", e);
    }

    // Spawn the dispatcher. Owns the `mpsc::Receiver` half of the
    // channel created above; the matching senders are held by
    // every cloned `AppState`. Closes cleanly when the last sender
    // is dropped (process shutdown).
    job_dispatcher::spawn(
        Arc::clone(&job_store),
        state.clone(),
        Arc::clone(&job_notify_map),
        DEFAULT_AWAITING_SIGNATURE_TIMEOUT,
        job_rx,
    );

    let app = create_router(state);

    // boot_log: announce the startup event with the connected network,
    // node version, listen address, and process pid. Best-effort —
    // a failed boot_log insert must NOT prevent the node from
    // starting (the operator would lose access to a real recovery
    // path on a transient DB blip).
    {
        let boot_entry = crate::db::BootLogEntry {
            event_type: "startup".to_string(),
            message: format!(
                "zkcoins-node {} starting on {} (network={})",
                env!("CARGO_PKG_VERSION"),
                socket_addr,
                NETWORK_CONFIG.network_name,
            ),
            metadata: Some(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "network": NETWORK_CONFIG.network_name,
                "socket_addr": socket_addr.to_string(),
                "pid": std::process::id(),
                "is_mainnet": NETWORK_CONFIG.is_mainnet,
            })),
        };
        if let Err(e) = crate::db::insert_boot_log(&pool, &boot_entry).await {
            eprintln!("Failed to persist boot_log startup event: {}", e);
        }
    }

    println!("REST API started at {}", socket_addr);
    let listener = TcpListener::bind(socket_addr).await?;
    tracing::info!("Listener bound on {socket_addr}; API is reachable");

    // Background-warmup. A fresh `Prover` carries a cold Rayon worker
    // pool and uninitialised AOT-compiled Plonky2 evaluator caches;
    // empirically (dfxdev R2 probe, 2026-05-31) the first
    // `prove_initial` after `Prover::new()` takes ~7012 ms vs the
    // steady-state p50 of ~4777 ms for every subsequent call.
    //
    // The previous shape (PR #147, closed) paid that tax synchronously
    // before binding the listener and pushed API offline time per
    // deploy from ~14 s to ~21 s. This shape instead binds the
    // listener FIRST (the API is reachable at ~0.1 s), then spawns
    // `AccountNode::warmup_prover` in a `spawn_blocking` task so the
    // tokio worker that runs `axum::serve` is not starved by the
    // CPU-bound Plonky2 prove. While the task is running a user
    // request still serves correctly — it just pays the ~7 s cold tax
    // — and `/health/ready` returns 503 with `prover: warming` so an
    // LB / Kuma can hold traffic on the previous-gen pod during a
    // rolling deploy.
    //
    // Opt-out via `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1`: the smoke tests
    // in `runtime_tests.rs` set this so each `start_rest_node_*` test
    // does not pay the ~7 s prove tax twice over. When set,
    // `prover_warm` is flipped to `true` immediately so the readiness
    // probe matches the production-ready shape.
    let skip_warmup = std::env::var("ZKCOINS_SKIP_BOOTSTRAP_WARMUP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let warmup_handle = if skip_warmup {
        tracing::info!(
            "Bootstrap warmup skipped via ZKCOINS_SKIP_BOOTSTRAP_WARMUP; \
             prover_warm = true (first user request will pay the ~7 s cold tax)"
        );
        prover_warm.store(true, Ordering::SeqCst);
        None
    } else {
        let account_node_for_warmup = Arc::clone(&shared_account_node);
        let prover_warm_flag = Arc::clone(&prover_warm);
        let handle = tokio::task::spawn_blocking(move || {
            let warmup_t = std::time::Instant::now();
            // Hold the sync `Mutex` only for the duration of the
            // prove call. The scanner — spawned in parallel by
            // `main.rs` — locks `state`, not `account_node`, so it
            // does not contend with this guard. The only realistic
            // contender is a user request that lands during the
            // ~7 s warmup window; that request blocks on
            // `account_node.lock()` for the remainder of the warmup
            // (then runs warm), which is the accepted trade-off
            // documented in the function comment. The block is
            // shorter (and aborts cleanly on shutdown) than the
            // previous synchronous-bootstrap shape.
            let result = {
                let guard = account_node_for_warmup
                    .lock()
                    .expect("AccountNode mutex poisoned before bootstrap warmup");
                guard.warmup_prover()
            };
            match result {
                Ok(()) => {
                    tracing::info!(
                        elapsed_ms = warmup_t.elapsed().as_millis() as u64,
                        "Background warmup complete; prover ready"
                    );
                    prover_warm_flag.store(true, Ordering::SeqCst);
                }
                Err(e) => {
                    // Same severity as the previous synchronous
                    // `expect()` — the same Prover serves every
                    // subsequent user request, so a warmup failure
                    // means production requests would also fail.
                    // Crash-loop the container rather than running
                    // a node that serves 5xx for the prove path.
                    tracing::error!(error = %e, "Background warmup failed — exiting");
                    std::process::exit(1);
                }
            }
        });
        tracing::info!("Bootstrap warmup spawned in background; listener serving now");
        Some(handle)
    };
    // `warmup_handle` is intentionally not awaited: `axum::serve`
    // owns the foreground future and the warmup runs to completion
    // on its own. On graceful shutdown `axum::serve` returns first;
    // the warmup task either completes naturally or is dropped when
    // the tokio runtime shuts down. The binding keeps the JoinHandle
    // alive (vs. `let _ =`) so a future shutdown signal can call
    // `.abort()` once a signal handler is wired in.
    let _warmup_handle = warmup_handle;

    // `into_make_service_with_connect_info::<SocketAddr>()` exposes the
    // peer's TCP socket to extractors — the audit middleware reads it
    // through `ConnectInfo<SocketAddr>` and writes it to
    // `request_log.remote_addr`. Without this the audit row's
    // `remote_addr` column is always NULL (the default `into_make_service`
    // never inserts a `ConnectInfo` extension).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Job-API boot-time resumer. Walks every non-terminal row in the
/// `jobs` table and applies the partition described in
/// `JobStore::list_interrupted_for_resume` /
/// `list_non_terminal_for_resume`:
///
/// * `proving` / `broadcasting` — interrupted in flight; the
///   in-process prover / publisher state is gone. Mark `failed`
///   with a wallet-facing message so the next poll observes a
///   terminal status.
/// * `queued` — the signed payload's timestamp window has expired
///   (the wallet's timestamp gate is 5 minutes, the server may
///   have been down longer). Mark `failed` for the same reason.
/// * `awaiting_signature` — the wallet may still come back with
///   the signature. Re-arm a fresh `Notify` entry and hand the
///   public_id back to the dispatcher so it parks on the channel
///   the same way it did pre-restart.
async fn boot_resume_jobs(
    job_store: &Arc<JobStore>,
    job_notify_map: &Arc<DashMap<uuid::Uuid, Arc<tokio::sync::Notify>>>,
    job_tx: &tokio::sync::mpsc::Sender<crate::job_dispatcher::JobEnvelope>,
) -> anyhow::Result<()> {
    // Interrupted in-flight rows: mark each failed so the wallet
    // observes a terminal status.
    let interrupted = job_store.list_interrupted_for_resume().await?;
    for job in interrupted {
        if let Err(e) = job_store
            .fail(
                job.public_id,
                "server restarted before processing — please retry",
            )
            .await
        {
            eprintln!(
                "boot_resume_jobs: fail({}) failed: {} (continuing)",
                job.public_id, e
            );
        } else {
            tracing::info!(
                "boot_resume_jobs: marked {} ({:?}) failed",
                job.public_id,
                job.status
            );
        }
    }

    // Non-terminal rows still in admit-side states.
    let pending = job_store.list_non_terminal_for_resume().await?;
    for job in pending {
        match job.status {
            JobStatus::Queued => {
                if let Err(e) = job_store
                    .fail(
                        job.public_id,
                        "server restarted before processing — please retry",
                    )
                    .await
                {
                    eprintln!(
                        "boot_resume_jobs: fail({}) failed: {} (continuing)",
                        job.public_id, e
                    );
                }
            }
            JobStatus::AwaitingSignature => {
                let notify = Arc::new(tokio::sync::Notify::new());
                job_notify_map.insert(job.public_id, notify);
                if let Err(e) = job_tx
                    .send(crate::job_dispatcher::JobEnvelope {
                        public_id: job.public_id,
                    })
                    .await
                {
                    eprintln!(
                        "boot_resume_jobs: enqueue({}) failed: {} (continuing)",
                        job.public_id, e
                    );
                } else {
                    tracing::info!(
                        "boot_resume_jobs: re-armed awaiting_signature job {}",
                        job.public_id
                    );
                }
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
