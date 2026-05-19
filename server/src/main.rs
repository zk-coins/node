mod account_server;
mod publisher;
mod scanner;
mod scanner_runtime;
mod server;
mod server_runtime;
mod state;
mod username;

use crate::publisher::EsploraConfig;
use crate::scanner_runtime::scan_for_inscriptions;
use crate::server_runtime::start_rest_server;
use crate::state::State;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use shared::commitment::Commitment;
use std::error::Error as StdError;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

const SMT_PATH: &str = "smt.bin";
const MMR_PATH: &str = "mmr.bin";
const LATEST_BLOCK_PATH: &str = "latest_block.bin";
const ACCOUNTS_PATH: &str = "accounts.bin";
const USERNAMES_PATH: &str = "usernames.bin";
const ACCOUNT_SERVER_ADDR: &str = "0.0.0.0:4242";
//const START_BLOCK_HASH: &str = "000000f43ca5c99c54c4738878fe1c5cca07691dc614a2734b73aa78ca868fb8";

use esplora_client::{
    r#async::DefaultSleeper, AsyncClient as EsploraAsyncClient, Builder as EsploraBuilder,
};

const DEFAULT_PUBLISHER_KEY: &str =
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

lazy_static::lazy_static! {
    pub static ref NETWORK_CONFIG: EsploraConfig = {
        let url = std::env::var("ESPLORA_URL")
            .unwrap_or_else(|_| "https://mutinynet.com/api".to_string());
        let is_mainnet = std::env::var("IS_MAINNET")
            .map(|v| v == "true")
            .unwrap_or(false);
        let network_name = std::env::var("NETWORK_NAME")
            .unwrap_or_else(|_| if is_mainnet { "Mainnet".to_string() } else { "Mutinynet".to_string() });
        println!("Network config: {} ({})", network_name, url);
        EsploraConfig { url, is_mainnet, network_name }
    };

    // Domain used by the client to render `<hex|username>@<domain>`. Distinct
    // from `network_name` because the same Bitcoin network (e.g. Mutinynet)
    // is served from two isolated test worlds (`dev.zkcoins.app`,
    // `zkcoins.app`) — the client needs the stage's external hostname, not
    // the chain identifier.
    //
    // Required (no default). A silent fallback would let a misconfigured
    // DEV image report the PRD domain and reproduce the cross-network
    // routing bug this whole envelope exists to fix (see issue #95). PRD
    // must set `USERNAME_DOMAIN=zkcoins.app` explicitly; DEV sets
    // `USERNAME_DOMAIN=dev.zkcoins.app`.
    pub static ref USERNAME_DOMAIN: String = {
        let domain = std::env::var("USERNAME_DOMAIN").expect(
            "USERNAME_DOMAIN env var must be set (e.g. `zkcoins.app` on PRD, \
             `dev.zkcoins.app` on DEV) — see #95 for the cross-network rationale",
        );
        println!("Username domain: {}", domain);
        domain
    };

    pub static ref PUBLISHER_KEY: String = {
        let key = std::env::var("PUBLISHER_KEY")
            .unwrap_or_else(|_| DEFAULT_PUBLISHER_KEY.to_string());
        if NETWORK_CONFIG.is_mainnet && key == DEFAULT_PUBLISHER_KEY {
            panic!("PUBLISHER_KEY env var must be set for mainnet");
        }
        key
    };
}

/// Atomic write: write to a temp file, then rename.
/// This prevents data corruption if the process crashes mid-write.
pub fn atomic_write(path: &str, data: &[u8]) -> std::io::Result<()> {
    let tmp_path = format!("{}.tmp", path);
    let mut file = File::create(&tmp_path)?;
    file.write_all(data)?;
    file.sync_all()?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

// Helper function to save the latest block hash
fn save_latest_block(block_hash: &BlockHash, path: &str) -> Result<(), Box<dyn StdError>> {
    atomic_write(path, &block_hash.to_byte_array())?;
    Ok(())
}

// Helper function to load the latest block hash
fn load_latest_block(path: &str) -> Result<BlockHash, Box<dyn StdError>> {
    let mut file = File::open(path)?;
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)?;
    Ok(BlockHash::from_byte_array(bytes))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    // A panic in any tokio worker — for example the bootstrap task that
    // owns the HTTP listener — by default only kills that task. The rest
    // of the process (notably the chain scanner) keeps running, the
    // container stays `Up`, but the REST port is never bound. Cloudflare
    // sees the upstream as alive-but-unresponsive and serves 502s for
    // hours. Override the panic hook so any panic anywhere aborts the
    // whole process; `restart: unless-stopped` in compose then crash-
    // loops the container until the underlying cause is fixed, which is
    // far easier to spot than a silent zombie.
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_panic_hook(info);
        std::process::exit(1);
    }));

    // Create a new State wrapped in Arc<Mutex>
    // Try to load existing state or create a new one
    let state = Arc::new(Mutex::new(
        match State::load_from_files(SMT_PATH, MMR_PATH) {
            Ok(state) => {
                println!("Loaded existing State from {} and {}", SMT_PATH, MMR_PATH);
                state
            }
            Err(_) => {
                println!("Creating new State");
                State::new()
            }
        },
    ));

    // Create a new AccountServer instance with a reference to the state.
    // Try to restore persisted accounts; otherwise start with an empty server
    // and let start_rest_server seed the minting account.
    let account_server =
        match account_server::AccountServer::load_from_file(Arc::clone(&state), ACCOUNTS_PATH) {
            Ok(server) => {
                println!("Loaded existing accounts from {}", ACCOUNTS_PATH);
                server
            }
            Err(_) => {
                println!("No accounts file found, creating new AccountServer");
                account_server::AccountServer::new(Arc::clone(&state))
            }
        };

    // Load or create UsernameStore
    let username_store = match username::UsernameStore::load_from_file(USERNAMES_PATH) {
        Ok(store) => {
            println!("Loaded existing usernames from {}", USERNAMES_PATH);
            store
        }
        Err(_) => {
            println!("No usernames file found, creating new UsernameStore");
            username::UsernameStore::new()
        }
    };

    // Spawn the account_server as a separate task
    tokio::spawn(async move {
        if let Err(e) = start_rest_server(
            account_server,
            username_store,
            ACCOUNT_SERVER_ADDR,
            ACCOUNTS_PATH.to_string(),
            USERNAMES_PATH.to_string(),
        )
        .await
        {
            eprintln!("Account server error: {}", e);
        }
    });

    // Try to load the latest block hash or use the default starting point
    let start_block_hash = match load_latest_block(LATEST_BLOCK_PATH) {
        Ok(hash) => {
            println!("Resuming from previously saved block: {}", hash);
            hash
        }
        Err(_) => {
            println!("No saved block hash found, fetching latest from Esplora...");
            let client = EsploraAsyncClient::<DefaultSleeper>::from_builder(EsploraBuilder::new(
                &NETWORK_CONFIG.url,
            ))?;

            let tip_hash = client.get_tip_hash().await?;
            println!("Fetched latest tip hash from Esplora: {}", tip_hash);
            tip_hash
        }
    };

    // Clone the State's Arc for the closure
    let state_clone = Arc::clone(&state);

    scan_for_inscriptions(&NETWORK_CONFIG, start_block_hash, &move |content_bytes: Vec<u8>, current_block_hash| {
        println!("Received content size: {} bytes", content_bytes.len());

        // Try to deserialize the content as a Commitment
        match bincode::deserialize::<Commitment>(&content_bytes) {
            Ok(commitment) => {
                println!("Successfully deserialized as commitment");
                println!("Public key: {}", commitment.public_key);

                // Verify the commitment
                if commitment.verify() {
                    println!("Commitment signature verified successfully");

                    // Capture the public_key before moving `commitment` into
                    // `state.update` so we can reference it in the Err arm.
                    let pubkey_for_log = commitment.public_key;

                    // Lock the mutex to modify the state
                    let mut state = state_clone.lock().unwrap();
                    // Update the state with this commitment.
                    //
                    // Errors are logged but do NOT panic — the scanner is
                    // best-effort and we never want a single bad commitment
                    // (replay, client bug, or a re-scan after crash where
                    // the SMT already has this public_key with a different
                    // leaf value) to take the whole REST server down. The
                    // scanner advances to the next block regardless.
                    match state.update(&[commitment]) {
                        Ok(new_root) => {
                            println!(
                                "Added to State. New MMR root: {}",
                                hex::encode(zkcoins_program::hash::digest_to_bytes(&new_root))
                            );

                            // Save the state after each update
                            if let Err(e) = state.save_to_files(SMT_PATH, MMR_PATH) {
                                eprintln!("Failed to save state after update: {}", e);
                            }

                            // Save the latest block hash after each update
                            if let Err(e) =
                                save_latest_block(&current_block_hash, LATEST_BLOCK_PATH)
                            {
                                eprintln!("Failed to save latest block hash: {}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "Skipping commitment for public_key {}: state.update failed: {}",
                                pubkey_for_log, e
                            );
                        }
                    }
                } else {
                    println!("Commitment verification failed, not adding to state");
                }
            },
            Err(e) => {
                // Print more detailed debug information
                println!("Found inscription with our message but failed to deserialize as commitment\nError: {}", e);
            }
        }
    })
    .await?;

    Ok(())
}
