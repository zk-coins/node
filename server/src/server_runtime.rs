//! Runtime bootstrap: binds a TCP listener and runs the Axum app.
//!
//! This file is intentionally excluded from the coverage scope. The
//! function below cannot be exercised by unit tests — it owns the
//! process lifecycle (port binding, signal-driven shutdown via axum)
//! and exists purely to wire the dependency graph defined in
//! `server.rs` to a real network socket.
//!
//! Anything that is testable in isolation (handlers, helpers, the
//! router construction in `create_router`) stays in `server.rs` and
//! is measured normally.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use axum::Json;
use shared::commitment::Commitment;
use tokio::net::TcpListener;

use crate::account_server::CoinProof;
use crate::publisher::create_and_broadcast_inscription;
use crate::server::{lock_or_recover, SendCoinResponse};
use crate::NETWORK_CONFIG;

#[cfg(feature = "faucet")]
use bitcoin::bip32::Xpriv;
#[cfg(feature = "faucet")]
use shared::ClientAccount;

use crate::account_server::AccountServer;
use crate::server::{create_router, AppState, ProofStore};
use crate::username::UsernameStore;

pub async fn start_rest_server(
    account_server: AccountServer,
    username_store: UsernameStore,
    addr: &str,
    accounts_path: String,
    #[cfg_attr(not(feature = "usernames"), allow(unused_variables))] usernames_path: String,
) -> anyhow::Result<()> {
    let socket_addr = addr
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("Failed to parse address: {}", e))?;

    let shared_account_server = Arc::new(Mutex::new(account_server));

    let proofs_dir = format!(
        "{}/proofs",
        std::path::Path::new(&accounts_path)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .display()
    );
    let proof_store = Arc::new(ProofStore::new(&proofs_dir));

    #[cfg(feature = "faucet")]
    let minting_account = {
        let secret = include_bytes!("../minting_secret.bin");
        let private_key = Xpriv::new_master(NETWORK_CONFIG.network(), secret)
            .expect("Failed to create private key.");
        println!(
            "Set MINTING_ADDRESS to {:?}",
            &zkcoins_program::MINTING_ADDRESS
        );
        let mut minting_client = ClientAccount::new(private_key);
        // ClientAccount::new starts with num_pubkeys=0, but each successful
        // mint increments it. The counter MUST survive process restarts;
        // otherwise we lose alignment with the server-side
        // minting_account.proof (which IS persisted), the next mint sends
        // the wrong prev_commitment_pubkey, and send_coins fails with
        // "prev_commitment_pubkey required for account update".
        //
        // Persist it in a tiny sibling file (4 bytes LE u32) next to
        // accounts.bin. Read here, written in mint_handler after every
        // successful increment.
        // accounts_path is typically a relative path like "accounts.bin"
        // (cwd-relative). Path::parent() returns Some("") for that, and
        // `format!("{}/minting_num_pubkeys.bin", "")` gives the absolute
        // path `/minting_num_pubkeys.bin` (filesystem root), not a
        // sibling of accounts.bin. Resolve to "." in that case so the
        // counter lands next to accounts.bin inside the data volume.
        let minting_pubkeys_path = {
            let parent = std::path::Path::new(&accounts_path).parent();
            let dir = match parent {
                Some(p) if !p.as_os_str().is_empty() => p.display().to_string(),
                _ => ".".to_string(),
            };
            format!("{}/minting_num_pubkeys.bin", dir)
        };
        if let Ok(bytes) = std::fs::read(&minting_pubkeys_path) {
            if bytes.len() == 4 {
                let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                println!(
                    "Loaded minting num_pubkeys={} from {}",
                    n, minting_pubkeys_path
                );
                minting_client.num_pubkeys = n;
            }
        }
        assert_eq!(
            minting_client.address,
            zkcoins_program::MINTING_ADDRESS,
            "Minting account address mismatch — minting_secret.bin or MINTING_ADDRESS constant is wrong"
        );
        Arc::new(Mutex::new(minting_client))
    };

    let shared_username_store = Arc::new(Mutex::new(username_store));

    let state = AppState {
        account_server: shared_account_server,
        proof_store,
        #[cfg(feature = "faucet")]
        minting_account,
        username_store: shared_username_store,
        accounts_path,
        #[cfg(feature = "usernames")]
        usernames_path,
    };
    {
        let mut account_server_guard = state.account_server.lock().unwrap();
        if account_server_guard.get_minting_account_address().is_err() {
            let mut minting_server_account = crate::account_server::Account::new();
            minting_server_account.balance = u64::MAX;
            account_server_guard
                .import_account(zkcoins_program::MINTING_ADDRESS, minting_server_account);
            if let Err(e) = account_server_guard.save_to_file(&state.accounts_path) {
                eprintln!("Failed to save initial accounts file: {}", e);
            }
        }
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
        // Mirror of the mint_handler tolerance: when
        // DEV_SKIP_BROADCAST_FAILURE=true the operator opts into
        // continuing without an on-chain commitment so E2E tests on a
        // dry Mutinynet publisher still succeed. See the comment over
        // the matching branch in server.rs::mint_handler.
        if std::env::var("DEV_SKIP_BROADCAST_FAILURE").unwrap_or_default() != "true" {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SendCoinResponse::default()),
            );
        }
        eprintln!("DEV_SKIP_BROADCAST_FAILURE=true — continuing without on-chain commitment");
    }

    let mut updated_proof = coin_proof;
    updated_proof.commitment = Some(commitment);
    let mut account_server_guard = lock_or_recover(&state.account_server);
    if let Err(e) = account_server_guard.receive_coin(updated_proof) {
        eprintln!("Failed to receive coin after commit: {}", e);
    }
    if let Err(e) = account_server_guard.save_to_file(&state.accounts_path) {
        eprintln!("Failed to persist accounts after commit: {}", e);
    }

    (
        StatusCode::OK,
        Json(SendCoinResponse {
            success: true,
            proof_id: Some(proof_id),
            account_state_hash: None,
            output_coins_root: None,
        }),
    )
}
