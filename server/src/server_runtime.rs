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

use tokio::net::TcpListener;

#[cfg(feature = "faucet")]
use bitcoin::bip32::Xpriv;
#[cfg(feature = "faucet")]
use shared::ClientAccount;

use crate::account_server::AccountServer;
use crate::server::{create_router, AppState, ProofStore};
use crate::username::UsernameStore;
#[cfg(feature = "faucet")]
use crate::NETWORK_CONFIG;

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
        let minting_client = ClientAccount::new(private_key);
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
