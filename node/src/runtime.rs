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
use crate::router::{lock_or_recover, SendCoinResponse};
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

    println!("REST server started at {}", socket_addr);
    let listener = TcpListener::bind(socket_addr).await?;
    axum::serve(listener, app).await?;

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
    if let Err(err) = create_and_broadcast_inscription(
        &commitment_data,
        crate::db::InscriptionKind::Send,
        &NETWORK_CONFIG,
        Some(&state.pool),
    )
    .await
    {
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
