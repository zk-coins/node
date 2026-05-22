//! Binary entrypoint for `server`.
//!
//! Modules live in `lib.rs`; this file only wires the bootstrap
//! (panic hook, Postgres pool, scanner task, REST listener) together.
//! Splitting the modules out of the binary lets out-of-tree
//! integration tests (`server/tests/api_remote.rs`) import the
//! handler response types and the `CoinProof` struct without
//! duplicating definitions or making the binary itself reachable
//! from a `cargo test --test ...` target.

use server::account_server;
use server::db;
use server::publisher::EsploraConfig;
use server::scanner_runtime::scan_for_inscriptions;
use server::server_runtime::start_rest_server;
use server::state::State;
use server::username;
use server::{persist_state_from_sync_context, DATABASE_URL, NETWORK_CONFIG};
use shared::commitment::Commitment;
use std::error::Error as StdError;
use std::sync::{Arc, Mutex};

// Postgres state-layer carries every persistent slice of server state
// after PR-A3: SMT / MMR / latest_block (PR-A2), accounts + usernames
// (PR-A3), and the faucet's `minting_meta.num_pubkeys` counter
// (PR-A3). The `accounts.bin`, `usernames.bin`, and
// `minting_num_pubkeys.bin` sibling files no longer exist, and the
// `atomic_write` helper that supported them is removed — the only
// remaining on-disk writes are the per-proof files under
// `${PROOFS_DIR:-./proofs}/{id}.bin`, owned by `ProofStore` in
// `server.rs`.
const ACCOUNT_SERVER_ADDR: &str = "0.0.0.0:4242";

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use esplora_client::{
    r#async::DefaultSleeper, AsyncClient as EsploraAsyncClient, Builder as EsploraBuilder,
};

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

    // Open the Postgres pool and run pending migrations BEFORE any
    // state load — `connect_and_migrate` is idempotent (sqlx tracks
    // applied migrations in `_sqlx_migrations`) and so safe to call on
    // every boot. A connect failure here aborts the whole bootstrap;
    // there is no useful "degraded" mode without persistent state.
    let pool = Arc::new(
        db::connect_and_migrate(&DATABASE_URL)
            .await
            .expect("connect and migrate database"),
    );
    println!("Connected to Postgres state-layer");

    // Load existing state from Postgres (PR-A2). When SMT/MMR rows are
    // absent (fresh DB), `load_from_pg` returns an empty State —
    // equivalent to the previous file-based `State::new()` fallback.
    let state = Arc::new(Mutex::new(
        State::load_from_pg(&pool)
            .await
            .expect("load state from Postgres"),
    ));
    println!("Loaded State from Postgres");

    // Reload AccountServer + UsernameStore from Postgres. The matching
    // file-based loaders from PR-A1/A2 are gone — these two calls are
    // the single source of truth after PR-A3. A DB error here aborts
    // the bootstrap (same reasoning as the State load above).
    let account_server = account_server::AccountServer::load_from_pg(Arc::clone(&state), &pool)
        .await
        .expect("load account server from Postgres");
    println!("Loaded AccountServer from Postgres");
    let username_store = username::UsernameStore::load_from_pg(&pool)
        .await
        .expect("load username store from Postgres");
    println!("Loaded UsernameStore from Postgres");

    // Spawn the account_server as a separate task.
    let pool_for_rest = Arc::clone(&pool);
    tokio::spawn(async move {
        if let Err(e) = start_rest_server(
            account_server,
            username_store,
            ACCOUNT_SERVER_ADDR,
            pool_for_rest,
        )
        .await
        {
            eprintln!("Account server error: {}", e);
        }
    });

    // Try to load the latest block hash from Postgres or fall back to
    // Esplora's current tip. The Postgres row is written atomically
    // alongside the SMT/MMR snapshot in the scanner callback, which is
    // the structural fix for issue #11.
    let network_config: &EsploraConfig = &NETWORK_CONFIG;
    let start_block_hash = match db::load_latest_block(&pool).await? {
        Some(hash_bytes) => {
            let hash = BlockHash::from_byte_array(hash_bytes);
            println!("Resuming from previously saved block: {}", hash);
            hash
        }
        None => {
            println!("No saved block hash found, fetching latest from Esplora...");
            let client = EsploraAsyncClient::<DefaultSleeper>::from_builder(EsploraBuilder::new(
                &network_config.url,
            ))?;
            let tip_hash = client.get_tip_hash().await?;
            println!("Fetched latest tip hash from Esplora: {}", tip_hash);
            tip_hash
        }
    };

    // Clones for the scanner callback closure.
    let pool_for_callback = Arc::clone(&pool);
    let state_for_callback = Arc::clone(&state);

    scan_for_inscriptions(network_config, start_block_hash, &move |content_bytes: Vec<u8>, current_block_hash| {
        println!("Received content size: {} bytes", content_bytes.len());

        // Try to deserialize the content as a Commitment
        match bincode::deserialize::<Commitment>(&content_bytes) {
            Ok(commitment) => {
                println!("Successfully deserialized as commitment");
                println!("Public key: {}", commitment.public_key);

                // Verify the commitment
                if !commitment.verify() {
                    println!("Commitment verification failed, not adding to state");
                    return;
                }
                println!("Commitment signature verified successfully");

                // Capture the public_key before moving `commitment` into
                // `state.update` so we can reference it in the Err arm.
                let pubkey_for_log = commitment.public_key;

                // Lock-scope: do the state mutation, capture the bytes
                // needed for persistence, then DROP THE LOCK before the
                // async DB call. Holding `std::sync::Mutex` across an
                // .await is unsound; also we want subsequent commitments
                // to make progress while the previous tx commits.
                let snapshot = {
                    let mut state_guard = state_for_callback.lock().unwrap();
                    match state_guard.update(&[commitment]) {
                        Ok(new_root) => match state_guard.serialize_for_persist() {
                            Ok((smt_bytes, mmr_bytes)) => Some((new_root, smt_bytes, mmr_bytes)),
                            Err(e) => {
                                eprintln!(
                                    "Failed to serialize state after update: {} (skipping persist)",
                                    e
                                );
                                None
                            }
                        },
                        Err(e) => {
                            // Errors are logged but do NOT panic — the scanner is
                            // best-effort and we never want a single bad commitment
                            // (replay, client bug, or a re-scan after crash where
                            // the SMT already has this public_key with a different
                            // leaf value) to take the whole REST server down. The
                            // scanner advances to the next block regardless.
                            eprintln!(
                                "Skipping commitment for public_key {}: state.update failed: {}",
                                pubkey_for_log, e
                            );
                            None
                        }
                    }
                }; // mutex dropped here, BEFORE the async tx below

                if let Some((new_root, smt_bytes, mmr_bytes)) = snapshot {
                    let block_hash_bytes = current_block_hash.to_byte_array();

                    // The callback runs INSIDE the async
                    // `scan_for_inscriptions` task on a multi_thread
                    // tokio runtime, so we cannot just
                    // `Handle::current().block_on(...)` — the docs say
                    // "may panic when called from a thread that is part
                    // of the current Tokio runtime" and on
                    // `#[tokio::main]` (multi_thread by default) it
                    // does panic the first time a real inscription is
                    // scanned. The fix is the documented
                    // `block_in_place(|| Handle::current().block_on(…))`
                    // pattern, encapsulated in
                    // `persist_state_from_sync_context`.
                    let persist_result = persist_state_from_sync_context(
                        &pool_for_callback,
                        &smt_bytes,
                        &mmr_bytes,
                        &block_hash_bytes,
                    );
                    match persist_result {
                        Ok(()) => println!(
                            "Persisted state. New MMR root: {}",
                            hex::encode(zkcoins_program::hash::digest_to_bytes(&new_root))
                        ),
                        Err(e) => eprintln!("persist_state_tx failed: {}", e),
                    }
                }
            }
            Err(e) => {
                // Print more detailed debug information
                println!("Found inscription with our message but failed to deserialize as commitment\nError: {}", e);
            }
        }
    })
    .await?;

    Ok(())
}
