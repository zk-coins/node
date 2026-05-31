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
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use axum::Json;
use shared::commitment::Commitment;
use sqlx::PgPool;
use tokio::net::TcpListener;

use crate::account_node::{persist_account, CoinProof};
use crate::db;
use crate::publisher::{create_and_broadcast_inscription, resume_pending_inscriptions};
use crate::router::{
    apply_commit_and_persist_phase_e, handler_error_response, lock_or_recover, PhaseEFailure,
    SendCoinResponse,
};
use crate::NETWORK_CONFIG;
use shared::ProofData;
use zkcoins_program::hash::digest_to_bytes;

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
        #[cfg(test)]
        phase3_release_lock: Arc::new(tokio::sync::Mutex::new(())),
        #[cfg(test)]
        state_advance_release_lock: Arc::new(tokio::sync::Mutex::new(())),
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

/// Broadcast the commit inscription and, on success, run the shared
/// Phase E (SMT/MMR advance + atomic persist + `pending_inscriptions`
/// row marked `complete`), then deliver the coin to the recipient and
/// persist the account state. This contains the network call (Bitcoin
/// broadcast) and the post-broadcast bookkeeping, plus the
/// success/failure response dispatch.
///
/// **Invariant (zk-coins/node#89).** The broadcast `if let Err(...)
/// { return 503 }` MUST stay above every `receive_coin`/`upsert_account`
/// line. The mint flow had to be refactored to prepare-then-commit
/// because its old shape advanced state ahead of broadcast; this
/// function does not have that bug because its broadcast is already
/// the first effect. Any future refactor that moves a state mutation
/// above the broadcast re-introduces the state-desync class — do not.
///
/// **Phase E symmetry.** Between the broadcast and the recipient
/// `receive_coin` mutation, we invoke
/// [`apply_commit_and_persist_phase_e`] synchronously — identical
/// shape to `mint_handler`. Prior to this, the send-commit SMT
/// integration ran only via the async scanner, which surfaced as a
/// race for back-to-back `/api/send` + `/api/commit` + `/api/send`
/// flows: the second send walked the SMT for the first commit's
/// pubkey and found no entry, returning 422 `"Unable to get merkle
/// proofs for provided public key"`. Running Phase E inline closes
/// that window. The scanner remains the recovery path for external
/// inscriptions and re-scans of our own commits hit
/// `should_skip_scanner_state_update` because the `complete` row
/// advance lands atomically here.
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
    // Use `state.esplora_config` (instead of the process-wide
    // `NETWORK_CONFIG` lazy_static) so tests can redirect Esplora calls
    // at a `wiremock::MockServer`, matching the testability shape
    // already in place for `mint_handler`. In production
    // `start_rest_node` clones `NETWORK_CONFIG` into this slot so the
    // runtime behaviour is unchanged.
    let broadcast_outcome = create_and_broadcast_inscription(
        &commitment_data,
        crate::db::InscriptionKind::Send,
        &state.esplora_config,
        Some(&state.pool),
    )
    .await;
    let commit_txid_bytes: [u8; 32] = match broadcast_outcome {
        Ok((commit_txid, _reveal_txid)) => {
            use bitcoin::hashes::Hash as _;
            commit_txid.to_byte_array()
        }
        Err(err) => {
            eprintln!("Error broadcasting commit inscription: {}", err);
            return handler_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Failed to broadcast commitment inscription on-chain",
            );
        }
    };

    // ---- Phase E (broadcast OK) -----------------------------------------
    // Run the shared SMT/MMR advance + atomic persist + mark-complete
    // BEFORE the recipient `receive_coin` mutation. Locked-step with
    // `mint_handler::Phase E`; see [`apply_commit_and_persist_phase_e`]
    // for the full rationale, lock topology, and crash-recovery
    // contract. On failure the broadcast already landed on chain — we
    // surface 503 (no fallback, no retry) and the scanner-replay path
    // is the single source of repair.
    if let Err(failure) = apply_commit_and_persist_phase_e(
        state,
        &commitment,
        &commit_txid_bytes,
        "broadcast_commit_and_deliver",
    )
    .await
    {
        let msg: &'static str = match failure {
            PhaseEFailure::StateUpdate => {
                "commit broadcast landed on chain but in-process state advance failed; scanner will reconcile"
            }
            PhaseEFailure::DurablePersist => {
                "commit broadcast landed on chain but durable state advance failed; scanner will reconcile"
            }
        };
        return handler_error_response(StatusCode::SERVICE_UNAVAILABLE, msg);
    }

    let mut updated_proof = coin_proof;
    updated_proof.commitment = Some(commitment);
    // Extract the prover's post-state hash pair from the stored
    // CoinProof's public_inputs so the response carries the same
    // (account_state_hash, output_coins_root) the wallet client used
    // to build the commitment in the first place. Lets the client
    // confirm the server's post-commit snapshot matches what it just
    // signed without a second `/api/proof/:id` round-trip. Derivation
    // is identical to the one in `mint_handler` and `send_coin_handler`.
    let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
        updated_proof.proof.public_inputs
            [..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .expect("Plonky2 Proof emits N_PROOF_DATA_PUBLIC_INPUTS field elements");
    let proof_data = ProofData::from_field_elements(&pis);
    let ash_hex = Some(hex::encode(digest_to_bytes(&proof_data.account_state_hash)));
    let ocr_hex = Some(hex::encode(digest_to_bytes(&proof_data.output_coins_root)));

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
        let addr_bytes = digest_to_bytes(&recipient);
        if let Err(e) =
            db::upsert_account_with_source(&state.pool, &addr_bytes, &bytes, "receive").await
        {
            eprintln!("Failed to upsert account after commit: {}", e);
        }
    }

    (
        StatusCode::OK,
        Json(SendCoinResponse {
            success: true,
            error: None,
            proof_id: Some(proof_id),
            account_state_hash: ash_hex,
            output_coins_root: ocr_hex,
        }),
    )
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
