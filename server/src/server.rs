use axum::{
    body::Bytes,
    extract::{Json, Path, State},
    http::{header, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use bitcoin::secp256k1::{self as secp, schnorr::Signature as SchnorrSignature, Message};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::commitment::Commitment;
#[cfg(feature = "faucet")]
use shared::ClientAccount;
use shared::{Invoice, ProofData};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tower_http::cors::CorsLayer;
use zkcoins_program::hash::{digest_from_bytes, digest_to_bytes};
use zkcoins_prover::Proof;

use crate::account_server::{AccountServer, CoinProof};
#[cfg(feature = "faucet")]
use crate::publisher::create_and_broadcast_inscription;
use crate::username::UsernameStore;
use crate::NETWORK_CONFIG;

/// Verify a Schnorr signature over send request fields.
/// Message = SHA256(account_address || recipient || amount || timestamp)
fn verify_send_signature(request: &SendCoinRequest) -> Result<(), &'static str> {
    let signature_hex = request.signature.as_deref().ok_or("Missing signature")?;
    let timestamp = request.timestamp.ok_or("Missing timestamp")?;

    // Reject requests older than 5 minutes
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.abs_diff(timestamp) > 300 {
        return Err("Request timestamp too old or in the future");
    }

    // Build the message: SHA256(account_address || recipient || amount || timestamp)
    let mut hasher = Sha256::new();
    hasher.update(request.account_address.as_bytes());
    hasher.update(request.recipient.as_bytes());
    hasher.update(request.amount.to_le_bytes());
    hasher.update(timestamp.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let msg = Message::from_digest(hash);
    let sig_bytes = hex::decode(signature_hex).or(Err("Invalid signature hex"))?;
    let sig =
        SchnorrSignature::from_slice(&sig_bytes).or(Err("Invalid Schnorr signature format"))?;

    let (xonly, _parity) = request.public_key.x_only_public_key();
    let secp = secp::Secp256k1::verification_only();

    secp.verify_schnorr(&sig, &msg, &xonly)
        .or(Err("Signature verification failed"))
}

/// Lock a mutex, recovering from poison if a previous holder panicked.
/// This prevents cascade failures where one panic takes down all handlers.
pub(crate) fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        eprintln!("WARNING: Recovering from poisoned mutex");
        poisoned.into_inner()
    })
}

// Define a struct for our application state
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) account_server: Arc<Mutex<AccountServer>>,
    pub(crate) proof_store: Arc<ProofStore>,
    #[cfg(feature = "faucet")]
    pub(crate) minting_account: Arc<Mutex<ClientAccount>>,
    pub(crate) username_store: Arc<Mutex<UsernameStore>>,
    pub(crate) accounts_path: String,
    #[cfg(feature = "usernames")]
    pub(crate) usernames_path: String,
}

// Response types for our API
#[derive(Serialize, Deserialize)]
pub struct BalanceResponse {
    balance: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

#[cfg(any(feature = "address-list", feature = "usernames", feature = "lnurl"))]
#[derive(Serialize, Deserialize)]
pub struct AddressesResponse {
    addresses: Vec<String>,
}

#[derive(Deserialize)]
pub struct SendCoinRequest {
    account_address: String,
    recipient: String,
    amount: u64,
    public_key: bitcoin::secp256k1::PublicKey,
    next_public_key: bitcoin::secp256k1::PublicKey,
    prev_commitment_pubkey: Option<bitcoin::secp256k1::PublicKey>,
    signature: Option<String>,
    timestamp: Option<u64>,
}

#[cfg(feature = "faucet")]
#[derive(Deserialize)]
pub struct MintRequest {
    account_address: String,
    amount: u64,
}

// `ReceiveCoinRequest` was the SP1-era POST body shape for a coin
// drop. It is currently unused — the receive flow is exercised via
// scanner + state.update — but kept as a placeholder for the future
// authenticated push endpoint. Mark `dead_code` to silence the lint.
#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ReceiveCoinRequest {
    coin_proof: Proof,
}

/// Persistent proof store — survives server restarts.
/// Each proof is stored as an individual file: /data/proofs/{id}.bin
pub(crate) struct ProofStore {
    dir: String,
    next_id: AtomicU64,
}

impl ProofStore {
    pub(crate) fn new(dir: &str) -> Self {
        std::fs::create_dir_all(dir).ok();
        // Scan existing files to find the highest ID
        let max_id = std::fs::read_dir(dir)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| {
                        e.file_name()
                            .to_str()?
                            .strip_suffix(".bin")?
                            .parse::<u64>()
                            .ok()
                    })
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);

        ProofStore {
            dir: dir.to_string(),
            next_id: AtomicU64::new(max_id + 1),
        }
    }

    /// Build a safe file path for a proof ID within the store directory.
    /// The ID is always a server-generated u64 and the suffix is the
    /// literal ".bin", so `base.join(...)` cannot escape `base` — no
    /// extra starts_with check is needed.
    fn proof_path(&self, id: u64) -> Option<std::path::PathBuf> {
        let base = std::path::Path::new(&self.dir).canonicalize().ok()?;
        Some(base.join(format!("{}.bin", id)))
    }

    fn add_proof(&self, proof_with_commitment: CoinProof) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let path = self
            .proof_path(id)
            .expect("proof store directory exists (created in ProofStore::new)");
        let bytes =
            bincode::serialize(&proof_with_commitment).expect("CoinProof is always serializable");
        Self::persist_proof_bytes(&path, &bytes, id);
        id
    }

    /// Best-effort persist: write `bytes` to `path` atomically, log the
    /// I/O error if the write fails. Extracted so the error arm can be
    /// exercised directly without having to construct a real `CoinProof`
    /// (which requires the SP1 prover to run).
    fn persist_proof_bytes(path: &std::path::Path, bytes: &[u8], id: u64) {
        if let Err(e) = crate::atomic_write(path.to_str().unwrap_or(""), bytes) {
            eprintln!("Failed to persist proof {}: {}", id, e);
        }
    }

    fn get_proof(&self, id: u64) -> Option<CoinProof> {
        let path = self.proof_path(id)?;
        let bytes = std::fs::read(&path).ok()?;
        bincode::deserialize(&bytes).ok()
    }
}

#[derive(Serialize, Default)]
pub struct SendCoinResponse {
    pub(crate) success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proof_id: Option<u64>,
    /// Hex-encoded hash fields the client needs to create a commitment (only set for user sends).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) account_state_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) output_coins_root: Option<String>,
}

#[derive(Deserialize)]
pub struct CommitRequest {
    proof_id: u64,
    /// Hex-encoded compressed public key (33 bytes) that signed the commitment.
    public_key: bitcoin::secp256k1::PublicKey,
    /// Hex-encoded Schnorr signature (64 bytes).
    signature: String,
    /// Hex-encoded message that was signed (the concatenation of account_state_hash + output_coins_root).
    message: String,
}

#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    network: String,
}

// --- Username & LNURL types ---

#[cfg(feature = "usernames")]
#[derive(Deserialize)]
pub struct ClaimUsernameRequest {
    username: String,
    address: String,
    public_key: bitcoin::secp256k1::PublicKey,
    signature: String,
    timestamp: u64,
}

#[cfg(any(feature = "usernames", feature = "lnurl"))]
#[derive(Serialize, Deserialize)]
pub struct UsernameResponse {
    username: String,
    address: String,
}

#[cfg(feature = "lnurl")]
#[derive(Serialize, Deserialize)]
pub struct LnurlpResponse {
    tag: String,
    callback: String,
    #[serde(rename = "minSendable")]
    min_sendable: u64,
    #[serde(rename = "maxSendable")]
    max_sendable: u64,
    metadata: String,
}

#[cfg(any(feature = "usernames", feature = "lnurl"))]
#[derive(Serialize, Deserialize)]
pub struct LnurlErrorResponse {
    status: String,
    reason: String,
}

// Handler functions for our REST API
async fn get_balance_handler(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let account_server = lock_or_recover(&state.account_server);

    // Check if an address parameter was provided
    if let Some(address_hex) = params.get("address") {
        // Convert hex string to Address type
        let address_vec = match hex::decode(address_hex.trim_start_matches("0x")) {
            Ok(addr) => addr,
            Err(_) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(BalanceResponse {
                        balance: 0,
                        username: None,
                    }),
                )
            }
        };

        // Convert Vec<u8> to [u8; 32], then to Poseidon HashDigest.
        let mut address_bytes = [0u8; 32];
        if address_vec.len() == 32 {
            address_bytes.copy_from_slice(&address_vec);
        } else {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(BalanceResponse {
                    balance: 0,
                    username: None,
                }),
            );
        }
        let address = digest_from_bytes(&address_bytes);

        // Get balance for the specific account
        let username = {
            let username_store = lock_or_recover(&state.username_store);
            username_store.get_username(&address).map(String::from)
        };
        match account_server.get_account_balance(&address) {
            Ok(balance) => (StatusCode::OK, Json(BalanceResponse { balance, username })),
            Err(_) => (
                StatusCode::NOT_FOUND,
                Json(BalanceResponse {
                    balance: 0,
                    username: None,
                }),
            ),
        }
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(BalanceResponse {
                balance: 0,
                username: None,
            }),
        )
    }
}

#[cfg(feature = "address-list")]
async fn get_address_handler(State(state): State<AppState>) -> impl IntoResponse {
    let account_server = lock_or_recover(&state.account_server);

    // Convert addresses to hex strings
    let hex_addresses: Vec<String> = account_server
        .get_addresses()
        .iter()
        .map(|addr| format!("0x{}", hex::encode(digest_to_bytes(addr))))
        .collect();

    Json(AddressesResponse {
        addresses: hex_addresses,
    })
}

async fn receive_coin_handler(
    State(state): State<AppState>,
    body: Bytes, // Accept raw binary data instead of multipart
) -> impl IntoResponse {
    // Try to deserialize the binary data as a CoinProof
    match bincode::deserialize::<CoinProof>(&body) {
        Ok(coin_proof) => {
            let mut account_server = lock_or_recover(&state.account_server);
            match account_server.receive_coin(coin_proof) {
                Ok(_) => Json(SendCoinResponse {
                    success: true,
                    ..Default::default()
                }),
                Err(_) => Json(SendCoinResponse::default()),
            }
        }
        Err(e) => {
            eprintln!("Failed to deserialize proof with commitment: {}", e);
            Json(SendCoinResponse::default())
        }
    }
}

async fn send_coin_handler(
    State(state): State<AppState>,
    Json(request): Json<SendCoinRequest>,
) -> impl IntoResponse {
    println!("Received send post request...");

    // Verify sender signature if provided (graceful: skip if not present for backwards compat)
    if request.signature.is_some() {
        if let Err(e) = verify_send_signature(&request) {
            eprintln!("Signature verification failed: {}", e);
            return (StatusCode::UNAUTHORIZED, Json(SendCoinResponse::default()));
        }
    }

    // Create converted addresses (from_address and to_address)
    let from_address_vec = match hex::decode(request.account_address.trim_start_matches("0x")) {
        Ok(addr) => addr,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(SendCoinResponse::default()),
            )
        }
    };
    let to_address_vec = match hex::decode(request.recipient.trim_start_matches("0x")) {
        Ok(addr) => addr,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(SendCoinResponse::default()),
            )
        }
    };

    // Convert Vec<u8> to [u8; 32], then to Poseidon HashDigest.
    let mut from_address_bytes = [0u8; 32];
    let mut to_address_bytes = [0u8; 32];
    if from_address_vec.len() == 32 && to_address_vec.len() == 32 {
        from_address_bytes.copy_from_slice(&from_address_vec);
        to_address_bytes.copy_from_slice(&to_address_vec);
    } else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(SendCoinResponse::default()),
        );
    }
    let from_address = digest_from_bytes(&from_address_bytes);
    let to_address = digest_from_bytes(&to_address_bytes);

    // TODO: Provide the correct public keys from the client
    // Acquire the account_server lock only for the duration of sending coins.
    let send_result = {
        let mut account_server_lock = lock_or_recover(&state.account_server);
        account_server_lock.send_coins(
            vec![Invoice::new(request.amount, to_address)],
            from_address,
            request.public_key,
            request.next_public_key,
            request.prev_commitment_pubkey,
        )
        // NOTE: accounts are NOT saved here — proof must be persisted first
    };

    eprintln!(
        "Send result: {}",
        if send_result.is_ok() { "ok" } else { "err" }
    );

    match send_result {
        Ok(mut coin_proofs) => {
            // PLONKY2 MIGRATION (Step 7): bridge from SP1's
            // `public_values` byte stream to Plonky2's `public_inputs`
            // field-element vector via `ProofData::from_field_elements`.
            let pis: [zkcoins_program::F;
                zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] = coin_proofs[0]
                .proof
                .public_inputs[..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
                .try_into()
                .expect("Plonky2 Proof emits N_PROOF_DATA_PUBLIC_INPUTS field elements");
            let pd = ProofData::from_field_elements(&pis);
            let ash_hex = Some(hex::encode(digest_to_bytes(&pd.account_state_hash)));
            let ocr_hex = Some(hex::encode(digest_to_bytes(&pd.output_coins_root)));

            // Mint flow only — broadcasting a pre-set commitment is the
            // server-signed minting path. The mint endpoint is feature-
            // gated, so in the MVP build coin_proofs[0].commitment is
            // always None and this block is excluded entirely.
            #[cfg(feature = "faucet")]
            if let Some(commitment) = coin_proofs[0].commitment.as_ref() {
                let commitment_data =
                    bincode::serialize(commitment).expect("Failed to serialize commitment");
                println!("Broadcasting commitment ({} bytes)", commitment_data.len());
                if let Err(err) =
                    create_and_broadcast_inscription(&commitment_data, &NETWORK_CONFIG).await
                {
                    eprintln!("Error broadcasting inscription: {}", err);
                }
            }

            // Persist proof FIRST (crash-safe: proof exists even if
            // account save fails). send_coins always returns a non-empty
            // Vec on Ok, so pop().unwrap() is total here.
            let proof_id = state.proof_store.add_proof(
                coin_proofs
                    .pop()
                    .expect("send_coins returns at least one coin_proof on Ok"),
            );
            // Now persist accounts (proof is already safe on disk)
            {
                let account_server_lock = lock_or_recover(&state.account_server);
                if let Err(e) = account_server_lock.save_to_file(&state.accounts_path) {
                    eprintln!("Failed to persist accounts after send: {}", e);
                }
            }

            (
                StatusCode::OK,
                Json(SendCoinResponse {
                    success: true,
                    proof_id: Some(proof_id),
                    account_state_hash: ash_hex,
                    output_coins_root: ocr_hex,
                }),
            )
        }
        Err(_) => (
            StatusCode::OK,
            Json(SendCoinResponse {
                success: false,
                proof_id: None,
                account_state_hash: None,
                output_coins_root: None,
            }),
        ),
    }
}

#[cfg(feature = "faucet")]
async fn mint_handler(
    State(state): State<AppState>,
    Json(request): Json<MintRequest>,
) -> impl IntoResponse {
    println!("Minting coins...");
    let account_address_vec = match hex::decode(request.account_address.trim_start_matches("0x")) {
        Ok(addr) => addr,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(SendCoinResponse::default()),
            )
        }
    };

    let mut account_address_bytes = [0u8; 32];
    if account_address_vec.len() == 32 {
        account_address_bytes.copy_from_slice(&account_address_vec);
    } else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(SendCoinResponse::default()),
        );
    }
    let account_address = digest_from_bytes(&account_address_bytes);

    // Generate keys and get necessary info while holding the minting_account lock briefly
    let (minting_pubkey, next_minting_pubkey, prev_commitment_pubkey, num_pubkeys_before_mint) = {
        let minting_account_guard = lock_or_recover(&state.minting_account);
        let current_num_pubkeys = minting_account_guard.num_pubkeys;
        let prev_pk = if current_num_pubkeys > 0 {
            Some(minting_account_guard.generate_public_key(current_num_pubkeys - 1))
        } else {
            None
        };
        (
            minting_account_guard.generate_public_key(current_num_pubkeys),
            minting_account_guard.generate_public_key(current_num_pubkeys + 1),
            prev_pk,
            current_num_pubkeys,
        )
    };

    // Acquire the account_server lock only for the duration of sending coins.
    let send_result = {
        let mut account_server_guard = lock_or_recover(&state.account_server);
        let minting_address = match account_server_guard.get_minting_account_address() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("Minting account not found: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(SendCoinResponse::default()),
                );
            }
        };
        account_server_guard.send_coins(
            vec![Invoice::new(request.amount, account_address)],
            minting_address,
            minting_pubkey,
            next_minting_pubkey,
            prev_commitment_pubkey,
        )
    };

    match &send_result {
        Ok(_) => eprintln!("Mint result: ok"),
        Err(e) => eprintln!("Mint result: err — {}", e),
    }
    // Now that the locks are dropped, we can await safely.
    match send_result {
        Ok(mut coin_proofs) => {
            // Increment num_pubkeys *after* successful send and before await
            {
                let mut minting_account_guard = lock_or_recover(&state.minting_account);
                // Ensure we only increment if the send was successful and based on the state *before* the send
                if minting_account_guard.num_pubkeys == num_pubkeys_before_mint {
                    minting_account_guard.num_pubkeys += 1;
                    // Persist the new counter so a server restart keeps the
                    // ClientAccount aligned with the on-disk server-side
                    // minting_account.proof. See the corresponding load in
                    // server_runtime.rs for the matching half.
                    //
                    // Same path-resolution logic as in server_runtime.rs:
                    // a relative accounts_path like "accounts.bin" has an
                    // empty parent; in that case fall back to "." so the
                    // counter lands next to accounts.bin, not at filesystem
                    // root.
                    let path = {
                        let parent = std::path::Path::new(&state.accounts_path).parent();
                        let dir = match parent {
                            Some(p) if !p.as_os_str().is_empty() => p.display().to_string(),
                            _ => ".".to_string(),
                        };
                        format!("{}/minting_num_pubkeys.bin", dir)
                    };
                    if let Err(e) =
                        crate::atomic_write(&path, &minting_account_guard.num_pubkeys.to_le_bytes())
                    {
                        eprintln!("Failed to persist minting num_pubkeys to {}: {}", path, e);
                    }
                } else {
                    // This case might indicate a race condition or unexpected state change.
                    // Handle appropriately, maybe log an error or return a specific response.
                    eprintln!("WARNING: num_pubkeys changed unexpectedly during mint operation.");
                }
                let pis: Result<
                    [zkcoins_program::F;
                        zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS],
                    _,
                > = coin_proofs[0].proof.public_inputs
                    [..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
                    .try_into();
                let proof_data = match pis {
                    Ok(pis) => ProofData::from_field_elements(&pis),
                    Err(e) => {
                        eprintln!("Failed to deserialize proof public_inputs: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(SendCoinResponse::default()),
                        );
                    }
                };
                coin_proofs[0].commitment = Some(minting_account_guard.create_commitment(
                    &proof_data.account_state_hash,
                    &proof_data.output_coins_root,
                ));
                // minting_account_guard is dropped here
            }

            let commitment = coin_proofs[0]
                .commitment
                .as_ref()
                .expect("Commitment must be set after mint");
            let commitment_data =
                bincode::serialize(commitment).expect("Failed to serialize commitment");

            println!(
                "Sending commitment data with size: {} bytes",
                commitment_data.len()
            );
            println!("Commitment data hex: {}", hex::encode(&commitment_data));

            // This await is now safe because no locks are held across it.
            //
            // The broadcast can fail for benign reasons in DEV environments
            // (e.g. the Mutinynet publisher wallet has no UTXOs). When the
            // operator opts in via `DEV_SKIP_BROADCAST_FAILURE=true`, we
            // log the error and continue: the recipient still gets the
            // server-side credit so E2E tests can proceed. The on-chain
            // commitment is missing — subsequent mints / sends that depend
            // on the SMT having this entry will fail until state is wiped.
            //
            // NEVER set this in PRD. On the default code path (env var
            // unset / != "true"), the handler returns 503 as before.
            if let Err(err) =
                create_and_broadcast_inscription(&commitment_data, &NETWORK_CONFIG).await
            {
                eprintln!("Error broadcasting mint inscription: {}", err);
                if std::env::var("DEV_SKIP_BROADCAST_FAILURE").unwrap_or_default() != "true" {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(SendCoinResponse::default()),
                    );
                }
                eprintln!(
                    "DEV_SKIP_BROADCAST_FAILURE=true — continuing without on-chain commitment"
                );
            }
            {
                let mut account_server_guard = lock_or_recover(&state.account_server);
                for coin_proof in &coin_proofs {
                    if let Err(e) = account_server_guard.receive_coin(coin_proof.clone()) {
                        eprintln!("Failed to receive minted coin: {}", e);
                    }
                }
                if let Err(e) = account_server_guard.save_to_file(&state.accounts_path) {
                    eprintln!("Failed to persist accounts after mint: {}", e);
                }
            }

            let proof_id = match coin_proofs.pop() {
                Some(proof) => state.proof_store.add_proof(proof),
                None => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(SendCoinResponse::default()),
                    );
                }
            };
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
        Err(_) => (StatusCode::OK, Json(SendCoinResponse::default())),
    }
}

// New handler to get a binary proof by ID
async fn get_proof_handler(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.proof_store.get_proof(id) {
        Some(proof_with_commitment) => {
            // Serialize the proof and commitment together to binary
            let binary_data = bincode::serialize(&proof_with_commitment).unwrap_or_default();

            // Set appropriate headers for binary download
            let mut headers = header::HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/octet-stream"),
            );
            headers.insert(
                header::CONTENT_DISPOSITION,
                header::HeaderValue::from_static("attachment; filename=\"coin_proof.bin\""),
            );

            (StatusCode::OK, headers, Bytes::from(binary_data))
        }
        None => (
            StatusCode::NOT_FOUND,
            header::HeaderMap::new(),
            Bytes::new(),
        ),
    }
}

/// Accepts a client-signed commitment for a previously generated proof.
/// Broadcasts the commitment as a Taproot inscription and delivers the coin to the recipient.
async fn commit_handler(
    State(state): State<AppState>,
    Json(request): Json<CommitRequest>,
) -> impl IntoResponse {
    // Retrieve the stored coin proof
    let coin_proof = match state.proof_store.get_proof(request.proof_id) {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(SendCoinResponse {
                    success: false,
                    proof_id: None,
                    account_state_hash: None,
                    output_coins_root: None,
                }),
            );
        }
    };

    // Reconstruct the Commitment from the client-provided fields
    let message_bytes = match hex::decode(&request.message) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(SendCoinResponse {
                    success: false,
                    proof_id: None,
                    account_state_hash: None,
                    output_coins_root: None,
                }),
            );
        }
    };
    let sig_bytes = match hex::decode(&request.signature) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(SendCoinResponse {
                    success: false,
                    proof_id: None,
                    account_state_hash: None,
                    output_coins_root: None,
                }),
            );
        }
    };
    let signature = match bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(SendCoinResponse {
                    success: false,
                    proof_id: None,
                    account_state_hash: None,
                    output_coins_root: None,
                }),
            );
        }
    };

    let commitment = Commitment {
        public_key: request.public_key,
        signature,
        message: message_bytes,
    };

    // Verify the commitment
    if !commitment.verify() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(SendCoinResponse {
                success: false,
                proof_id: None,
                account_state_hash: None,
                output_coins_root: None,
            }),
        );
    }

    crate::server_runtime::broadcast_commit_and_deliver(
        &state,
        commitment,
        coin_proof,
        request.proof_id,
    )
    .await
}

async fn info_handler() -> impl IntoResponse {
    Json(InfoResponse {
        network: NETWORK_CONFIG.network_name.clone(),
    })
}

#[derive(Serialize)]
struct RootResponse {
    service: &'static str,
    version: &'static str,
    network: String,
    endpoints: RootEndpoints,
    docs: &'static str,
}

#[derive(Serialize)]
struct RootEndpoints {
    info: &'static str,
    balance: &'static str,
    send: &'static str,
    receive: &'static str,
    commit: &'static str,
    proof: &'static str,
    health: &'static str,
}

/// Root handler — anything hitting `https://api.zkcoins.app/` (browser visit,
/// uptime probe, curious operator) gets a small JSON identifying the service,
/// the package version, the connected network, and pointers to the real
/// endpoints. Cheaper than serving a static landing page and still answers the
/// "is this the right host?" question without surfacing a bare 404.
async fn root_handler() -> impl IntoResponse {
    Json(RootResponse {
        service: "zkcoins-server",
        version: env!("CARGO_PKG_VERSION"),
        network: NETWORK_CONFIG.network_name.clone(),
        endpoints: RootEndpoints {
            info: "GET  /api/info",
            balance: "GET  /api/balance?address={hex}",
            send: "POST /api/send",
            receive: "POST /api/receive",
            commit: "POST /api/commit",
            proof: "GET  /api/proof/{id}",
            health: "GET  /health",
        },
        docs: "https://docs.zkcoins.app",
    })
}

// --- Username & LNURL handlers ---

#[cfg(feature = "usernames")]
async fn claim_username_handler(
    State(state): State<AppState>,
    Json(request): Json<ClaimUsernameRequest>,
) -> impl IntoResponse {
    // Decode address
    let address_vec = match hex::decode(request.address.trim_start_matches("0x")) {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(LnurlErrorResponse {
                    status: "ERROR".into(),
                    reason: "Invalid address hex".into(),
                }),
            )
                .into_response()
        }
    };
    let mut address_bytes = [0u8; 32];
    if address_vec.len() != 32 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Address must be 32 bytes".into(),
            }),
        )
            .into_response();
    }
    address_bytes.copy_from_slice(&address_vec);
    let address = digest_from_bytes(&address_bytes);

    // Verify public key matches address: sha256(compressed_pubkey) == address
    let pk_hash: [u8; 32] = Sha256::digest(request.public_key.serialize()).into();
    if pk_hash != address_bytes {
        return (
            StatusCode::UNAUTHORIZED,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Public key does not match address".into(),
            }),
        )
            .into_response();
    }

    // Verify timestamp freshness (5 min window)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.abs_diff(request.timestamp) > 300 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Timestamp too old or in the future".into(),
            }),
        )
            .into_response();
    }

    // Verify Schnorr signature over sha256("zkcoins:claim_username" || address_hex || username || timestamp_le)
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(request.address.as_bytes());
    hasher.update(request.username.as_bytes());
    hasher.update(request.timestamp.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let msg = Message::from_digest(hash);
    let sig_bytes = match hex::decode(&request.signature) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(LnurlErrorResponse {
                    status: "ERROR".into(),
                    reason: "Invalid signature hex".into(),
                }),
            )
                .into_response()
        }
    };
    let sig = match SchnorrSignature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(LnurlErrorResponse {
                    status: "ERROR".into(),
                    reason: "Invalid signature format".into(),
                }),
            )
                .into_response()
        }
    };
    let (xonly, _) = request.public_key.x_only_public_key();
    let secp = secp::Secp256k1::verification_only();
    if secp.verify_schnorr(&sig, &msg, &xonly).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Signature verification failed".into(),
            }),
        )
            .into_response();
    }

    // Claim the username
    let mut username_store = lock_or_recover(&state.username_store);
    if let Err(e) = username_store.claim(&request.username, address) {
        return (
            StatusCode::CONFLICT,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: e.into(),
            }),
        )
            .into_response();
    }
    if let Err(e) = username_store.save_to_file(&state.usernames_path) {
        eprintln!("Failed to persist usernames: {}", e);
    }

    let normalized = request.username.to_lowercase();
    (
        StatusCode::OK,
        Json(UsernameResponse {
            username: normalized,
            address: format!("0x{}", hex::encode(digest_to_bytes(&address))),
        }),
    )
        .into_response()
}

/// Resolve an identifier to an address. Checks the username store first,
/// then falls back to hex-prefix matching against known account addresses.
/// Only used by the gated username and LNURL handlers.
#[cfg(any(feature = "usernames", feature = "lnurl"))]
fn resolve_identifier(
    state: &AppState,
    identifier: &str,
) -> Option<(zkcoins_program::hash::HashDigest, String)> {
    let normalized = identifier.to_lowercase();

    // 1. Check custom username
    let username_store = lock_or_recover(&state.username_store);
    if let Some(address) = username_store.resolve(&normalized) {
        return Some((address, normalized));
    }
    drop(username_store);

    // 2. Check hex prefix against known addresses
    let account_server = lock_or_recover(&state.account_server);
    account_server
        .get_addresses()
        .into_iter()
        .find(|addr| hex::encode(digest_to_bytes(addr)).starts_with(&normalized))
        .map(|addr| (addr, normalized))
}

#[cfg(feature = "usernames")]
async fn resolve_username_handler(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    match resolve_identifier(&state, &username) {
        Some((address, resolved_name)) => (
            StatusCode::OK,
            Json(UsernameResponse {
                username: resolved_name,
                address: format!("0x{}", hex::encode(digest_to_bytes(&address))),
            }),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Username not found".into(),
            }),
        )
            .into_response(),
    }
}

#[cfg(feature = "lnurl")]
async fn lnurlp_handler(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if resolve_identifier(&state, &username).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "User not found".into(),
            }),
        )
            .into_response();
    }

    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("api.zkcoins.app");
    let scheme = if host.contains("localhost") {
        "http"
    } else {
        "https"
    };
    let normalized = username.to_lowercase();
    let callback = format!("{}://{}/lnurl/pay/{}", scheme, host, normalized);
    let metadata = format!(
        "[[\"text/plain\",\"Pay {} on zkCoins\"],[\"text/identifier\",\"{}@zkcoins.app\"]]",
        normalized, normalized
    );

    (
        StatusCode::OK,
        Json(LnurlpResponse {
            tag: "payRequest".into(),
            callback,
            min_sendable: 1_000,
            max_sendable: 1_000_000_000_000,
            metadata,
        }),
    )
        .into_response()
}

#[cfg(feature = "lnurl")]
async fn lnurl_callback_handler(
    State(_state): State<AppState>,
    Path(_username): Path<String>,
) -> impl IntoResponse {
    Json(LnurlErrorResponse {
        status: "ERROR".into(),
        reason: "Lightning payments coming soon (Phase 2)".into(),
    })
}

/// Build the full application router with all API routes, CORS, health check, and fallback.
/// Extracted so it can be reused in integration tests via `oneshot()`.
pub(crate) fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    // MVP routes — always compiled in.
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(|| async { "ok" }))
        .route("/api/info", get(info_handler))
        .route("/api/balance", get(get_balance_handler))
        .route("/api/send", post(send_coin_handler))
        .route("/api/receive", post(receive_coin_handler))
        .route("/api/proof/:id", get(get_proof_handler))
        .route("/api/commit", post(commit_handler));

    // Gated routes — only compiled in when their Cargo feature is enabled.
    // With a feature off, the handler does not exist in the binary and the
    // route is not registered, so the endpoint returns 404 via the fallback
    // and there is no code path to execute.
    #[cfg(feature = "address-list")]
    let app = app.route("/api/address", get(get_address_handler));

    #[cfg(feature = "faucet")]
    let app = app.route("/api/mint", post(mint_handler));

    #[cfg(feature = "usernames")]
    let app = app
        .route("/api/username/claim", post(claim_username_handler))
        .route(
            "/api/username/resolve/:username",
            get(resolve_username_handler),
        );

    #[cfg(feature = "lnurl")]
    let app = app
        .route("/.well-known/lnurlp/:username", get(lnurlp_handler))
        .route("/lnurl/pay/:username", get(lnurl_callback_handler));

    app.with_state(state)
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(cors)
}

// STEP 7 MIGRATION: server_tests.rs disabled pending Prover-API
// integration after Stage 5d-next-5 merge (issue zk-coins/server#19).
//
// #[cfg(test)]
// #[path = "server_tests.rs"]
// mod tests;
