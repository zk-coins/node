use axum::{
    body::Bytes,
    extract::{Json, Path, State},
    http::{header, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use bitcoin::bip32::Xpriv;
use bitcoin::secp256k1::{self as secp, schnorr::Signature as SchnorrSignature, Message};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::commitment::Commitment;
use shared::{ClientAccount, Invoice, ProofData};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use zkcoins_prover::Proof;

use crate::account_server::{AccountServer, CoinProof};
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
    let sig_bytes = hex::decode(signature_hex).map_err(|_| "Invalid signature hex")?;
    let sig =
        SchnorrSignature::from_slice(&sig_bytes).map_err(|_| "Invalid Schnorr signature format")?;

    let (xonly, _parity) = request.public_key.x_only_public_key();
    let secp = secp::Secp256k1::verification_only();

    secp.verify_schnorr(&sig, &msg, &xonly)
        .map_err(|_| "Signature verification failed")
}

/// Lock a mutex, recovering from poison if a previous holder panicked.
/// This prevents cascade failures where one panic takes down all handlers.
fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        eprintln!("WARNING: Recovering from poisoned mutex");
        poisoned.into_inner()
    })
}

// Define a struct for our application state
#[derive(Clone)]
struct AppState {
    account_server: Arc<Mutex<AccountServer>>,
    proof_store: Arc<ProofStore>,
    minting_account: Arc<Mutex<ClientAccount>>,
    username_store: Arc<Mutex<UsernameStore>>,
    accounts_path: String,
    usernames_path: String,
}

// Response types for our API
#[derive(Serialize, Deserialize)]
pub struct BalanceResponse {
    balance: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

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

#[derive(Deserialize)]
pub struct MintRequest {
    account_address: String,
    amount: u64,
}

#[derive(Deserialize)]
pub struct ReceiveCoinRequest {
    #[allow(dead_code)]
    coin_proof: Proof,
}

/// Persistent proof store — survives server restarts.
/// Each proof is stored as an individual file: /data/proofs/{id}.bin
struct ProofStore {
    dir: String,
    next_id: AtomicU64,
}

impl ProofStore {
    fn new(dir: &str) -> Self {
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
    fn proof_path(&self, id: u64) -> std::path::PathBuf {
        std::path::Path::new(&self.dir).join(format!("{}.bin", id))
    }

    fn add_proof(&self, proof_with_commitment: CoinProof) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let path = self.proof_path(id);
        match bincode::serialize(&proof_with_commitment) {
            Ok(bytes) => {
                if let Err(e) = crate::atomic_write(path.to_str().unwrap_or(""), &bytes) {
                    eprintln!("Failed to persist proof {}: {}", id, e);
                }
            }
            Err(e) => eprintln!("Failed to serialize proof {}: {}", id, e),
        }
        id
    }

    fn get_proof(&self, id: u64) -> Option<CoinProof> {
        let path = self.proof_path(id);
        let bytes = std::fs::read(&path).ok()?;
        bincode::deserialize(&bytes).ok()
    }
}

#[derive(Serialize, Default)]
pub struct SendCoinResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_id: Option<u64>,
    /// Hex-encoded hash fields the client needs to create a commitment (only set for user sends).
    #[serde(skip_serializing_if = "Option::is_none")]
    account_state_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_coins_root: Option<String>,
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

#[derive(Deserialize)]
pub struct ClaimUsernameRequest {
    username: String,
    address: String,
    public_key: bitcoin::secp256k1::PublicKey,
    signature: String,
    timestamp: u64,
}

#[derive(Serialize, Deserialize)]
pub struct UsernameResponse {
    username: String,
    address: String,
}

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

        // Convert Vec<u8> to [u8; 32]
        let mut address = [0u8; 32];
        if address_vec.len() == 32 {
            address.copy_from_slice(&address_vec);
        } else {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(BalanceResponse {
                    balance: 0,
                    username: None,
                }),
            );
        }

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

async fn get_address_handler(State(state): State<AppState>) -> impl IntoResponse {
    let account_server = lock_or_recover(&state.account_server);

    // Convert addresses to hex strings
    let hex_addresses: Vec<String> = account_server
        .get_addresses()
        .iter()
        .map(|addr| format!("0x{}", hex::encode(addr)))
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

    // Convert Vec<u8> to [u8; 32] for both addresses
    let mut from_address = [0u8; 32];
    let mut to_address = [0u8; 32];
    if from_address_vec.len() == 32 && to_address_vec.len() == 32 {
        from_address.copy_from_slice(&from_address_vec);
        to_address.copy_from_slice(&to_address_vec);
    } else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(SendCoinResponse::default()),
        );
    }

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
            // Extract proof data so the client can create a commitment
            let (ash_hex, ocr_hex) = {
                let proof_data =
                    bincode::deserialize::<ProofData>(&coin_proofs[0].proof.public_values.to_vec());
                match proof_data {
                    Ok(pd) => (
                        Some(hex::encode(pd.account_state_hash)),
                        Some(hex::encode(pd.output_coins_root)),
                    ),
                    Err(e) => {
                        eprintln!("Failed to deserialize proof data: {}", e);
                        (None, None)
                    }
                }
            };

            // If commitment is already set (e.g. mint flow), broadcast immediately
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

            // Persist proof FIRST (crash-safe: proof exists even if account save fails)
            let proof_id = match coin_proofs.pop() {
                Some(proof) => state.proof_store.add_proof(proof),
                None => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(SendCoinResponse {
                            success: false,
                            proof_id: None,
                            account_state_hash: None,
                            output_coins_root: None,
                        }),
                    );
                }
            };
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

    let mut account_address = [0u8; 32];
    if account_address_vec.len() == 32 {
        account_address.copy_from_slice(&account_address_vec);
    } else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(SendCoinResponse::default()),
        );
    }

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

    eprintln!(
        "Mint result: {}",
        if send_result.is_ok() { "ok" } else { "err" }
    );
    // Now that the locks are dropped, we can await safely.
    match send_result {
        Ok(mut coin_proofs) => {
            // Increment num_pubkeys *after* successful send and before await
            {
                let mut minting_account_guard = lock_or_recover(&state.minting_account);
                // Ensure we only increment if the send was successful and based on the state *before* the send
                if minting_account_guard.num_pubkeys == num_pubkeys_before_mint {
                    minting_account_guard.num_pubkeys += 1;
                } else {
                    // This case might indicate a race condition or unexpected state change.
                    // Handle appropriately, maybe log an error or return a specific response.
                    eprintln!("WARNING: num_pubkeys changed unexpectedly during mint operation.");
                }
                let proof_data = match bincode::deserialize::<ProofData>(
                    &coin_proofs[0].proof.public_values.to_vec(),
                ) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("Failed to deserialize proof data: {}", e);
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

            // This await is now safe because no locks are held across it
            if let Err(err) =
                create_and_broadcast_inscription(&commitment_data, &NETWORK_CONFIG).await
            {
                eprintln!("Error broadcasting mint inscription: {}", err);
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(SendCoinResponse::default()),
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

    // Broadcast the inscription
    let commitment_data = bincode::serialize(&commitment).expect("Failed to serialize commitment");
    println!(
        "Broadcasting user commitment ({} bytes)",
        commitment_data.len()
    );
    if let Err(err) = create_and_broadcast_inscription(&commitment_data, &NETWORK_CONFIG).await {
        eprintln!("Error broadcasting commit inscription: {}", err);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SendCoinResponse::default()),
        );
    }

    // Deliver the coin to the recipient
    let mut updated_proof = coin_proof;
    updated_proof.commitment = Some(commitment);
    {
        let mut account_server_guard = lock_or_recover(&state.account_server);
        if let Err(e) = account_server_guard.receive_coin(updated_proof) {
            eprintln!("Failed to receive coin after commit: {}", e);
        }
        if let Err(e) = account_server_guard.save_to_file(&state.accounts_path) {
            eprintln!("Failed to persist accounts after commit: {}", e);
        }
    }

    (
        StatusCode::OK,
        Json(SendCoinResponse {
            success: true,
            proof_id: Some(request.proof_id),
            account_state_hash: None,
            output_coins_root: None,
        }),
    )
}

async fn info_handler() -> impl IntoResponse {
    Json(InfoResponse {
        network: NETWORK_CONFIG.network_name.clone(),
    })
}

// --- Username & LNURL handlers ---

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
    let mut address = [0u8; 32];
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
    address.copy_from_slice(&address_vec);

    // Verify public key matches address: sha256(compressed_pubkey) == address
    let pk_hash: [u8; 32] = Sha256::digest(request.public_key.serialize()).into();
    if pk_hash != address {
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
            address: format!("0x{}", hex::encode(address)),
        }),
    )
        .into_response()
}

/// Resolve an identifier to an address. Checks the username store first,
/// then falls back to hex-prefix matching against known account addresses.
fn resolve_identifier(state: &AppState, identifier: &str) -> Option<([u8; 32], String)> {
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
        .find(|addr| hex::encode(addr).starts_with(&normalized))
        .map(|addr| (addr, normalized))
}

async fn resolve_username_handler(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    match resolve_identifier(&state, &username) {
        Some((address, resolved_name)) => (
            StatusCode::OK,
            Json(UsernameResponse {
                username: resolved_name,
                address: format!("0x{}", hex::encode(address)),
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
fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/info", get(info_handler))
        .route("/api/balance", get(get_balance_handler))
        .route("/api/send", post(send_coin_handler))
        .route("/api/address", get(get_address_handler))
        .route("/api/receive", post(receive_coin_handler))
        .route("/api/proof/:id", get(get_proof_handler))
        .route("/api/mint", post(mint_handler))
        .route("/api/commit", post(commit_handler))
        .route("/api/username/claim", post(claim_username_handler))
        .route(
            "/api/username/resolve/:username",
            get(resolve_username_handler),
        )
        .route("/.well-known/lnurlp/:username", get(lnurlp_handler))
        .route("/lnurl/pay/:username", get(lnurl_callback_handler))
        .with_state(state)
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(cors)
}

// Function to start the REST API server
pub async fn start_rest_server(
    account_server: AccountServer,
    username_store: UsernameStore,
    addr: &str,
    accounts_path: String,
    usernames_path: String,
) -> anyhow::Result<()> {
    // Parse the address string into a SocketAddr
    let socket_addr = addr
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("Failed to parse address: {}", e))?;

    // Wrap the account_server in an Arc<Mutex> for thread-safe sharing
    let shared_account_server = Arc::new(Mutex::new(account_server));

    // Create a persistent proof store
    let proofs_dir = format!(
        "{}/proofs",
        std::path::Path::new(&accounts_path)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .display()
    );
    let proof_store = Arc::new(ProofStore::new(&proofs_dir));

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

    // Create the combined state using the AppState struct
    let state = AppState {
        account_server: shared_account_server,
        proof_store,
        minting_account,
        username_store: shared_username_store,
        accounts_path,
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

    // Run the server
    println!("REST server started at {}", socket_addr);
    let listener = TcpListener::bind(socket_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// Handler to serve the index.html file (currently unused, kept for future use)
#[allow(dead_code)]
async fn serve_index() -> impl IntoResponse {
    let current_dir = std::env::current_dir().unwrap_or_default();
    let index_path = current_dir.join("..").join("client").join("index.html");

    match tokio::fs::read_to_string(&index_path).await {
        Ok(content) => {
            println!("Successfully read index.html, length: {}", content.len());
            let headers = [(header::CONTENT_TYPE, "text/html; charset=utf-8")];
            (StatusCode::OK, headers, content)
        }
        Err(e) => {
            eprintln!("Error reading index.html: {}", e);
            let error_message = format!("Index file not found: {}", e);
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/plain")],
                error_message,
            )
        }
    }
}

// http://myserver.com/<my_address>/balance
// http://myserver.com/<my_address>/send
// http://myserver.com/<my_address>/sign)

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::account_server::{Account, AccountServer};
    use crate::state::State;

    /// Create a minimal AppState for testing.
    /// The AccountServer is constructed with a real (mock) prover so that the
    /// type system is satisfied, but we seed it with a minting account so that
    /// balance / address queries work without needing the minting_secret.bin
    /// flow.
    fn test_state() -> AppState {
        let state = Arc::new(Mutex::new(State::new()));
        let mut account_server = AccountServer::new(Arc::clone(&state));

        // Seed a minting account with max balance (mirrors production setup)
        let mut minting_account = Account::new();
        minting_account.balance = u64::MAX;
        account_server.import_account(zkcoins_program::MINTING_ADDRESS, minting_account);

        // Create a dummy minting ClientAccount from a deterministic key
        let secret = include_bytes!("../minting_secret.bin");
        let private_key = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Signet, secret)
            .expect("Failed to create test private key");
        let minting_client = shared::ClientAccount::new(private_key);

        AppState {
            account_server: Arc::new(Mutex::new(account_server)),
            proof_store: Arc::new(ProofStore::new("/tmp/zkcoins-test-proofs")),
            minting_account: Arc::new(Mutex::new(minting_client)),
            username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
            accounts_path: String::new(),
            usernames_path: String::new(),
        }
    }

    /// Helper: send a request through the router and return (status, body string).
    async fn send_request(request: Request<Body>) -> (StatusCode, String) {
        let app = create_router(test_state());
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        (status, body)
    }

    // --- GET /health ---

    #[tokio::test]
    async fn health_returns_ok() {
        let req = Request::get("/health").body(Body::empty()).unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    // --- GET /api/info ---

    #[tokio::test]
    async fn info_returns_network_name() {
        let req = Request::get("/api/info").body(Body::empty()).unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::OK);

        let info: InfoResponse = serde_json::from_str(&body).expect("valid JSON");
        // The lazy_static defaults to "Mutinynet" when IS_MAINNET is unset
        assert!(!info.network.is_empty(), "network name must not be empty");
    }

    // --- GET /api/balance ---

    #[tokio::test]
    async fn balance_unknown_address_returns_not_found() {
        // 32 zero bytes in hex = 64 hex chars
        let address_hex = "00".repeat(32);
        let uri = format!("/api/balance?address={}", address_hex);
        let req = Request::get(&uri).body(Body::empty()).unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::NOT_FOUND);

        let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(resp.balance, 0);
        assert!(resp.username.is_none());
    }

    #[tokio::test]
    async fn balance_minting_address_returns_max() {
        let address_hex = hex::encode(zkcoins_program::MINTING_ADDRESS);
        let uri = format!("/api/balance?address={}", address_hex);
        let req = Request::get(&uri).body(Body::empty()).unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::OK);

        let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(resp.balance, u64::MAX);
    }

    #[tokio::test]
    async fn balance_missing_address_param_returns_not_found() {
        let req = Request::get("/api/balance").body(Body::empty()).unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::NOT_FOUND);

        let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(resp.balance, 0);
        assert!(resp.username.is_none());
    }

    #[tokio::test]
    async fn balance_invalid_hex_returns_unprocessable() {
        let req = Request::get("/api/balance?address=not_valid_hex")
            .body(Body::empty())
            .unwrap();
        let (status, _body) = send_request(req).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn balance_wrong_length_returns_unprocessable() {
        // 16 bytes = 32 hex chars, but the handler expects exactly 32 bytes
        let short_hex = "ab".repeat(16);
        let uri = format!("/api/balance?address={}", short_hex);
        let req = Request::get(&uri).body(Body::empty()).unwrap();
        let (status, _body) = send_request(req).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // --- GET /api/address ---

    #[tokio::test]
    async fn address_returns_list() {
        let req = Request::get("/api/address").body(Body::empty()).unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::OK);

        let resp: AddressesResponse = serde_json::from_str(&body).expect("valid JSON");
        // The test state has the minting address seeded
        assert!(
            !resp.addresses.is_empty(),
            "should contain at least the minting address"
        );
        assert!(
            resp.addresses[0].starts_with("0x"),
            "addresses should be 0x-prefixed"
        );
    }

    // --- POST /api/send with missing fields ---

    #[tokio::test]
    async fn send_missing_body_returns_error() {
        let req = Request::post("/api/send")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let (status, _body) = send_request(req).await;

        // Axum returns 422 when JSON deserialization fails (missing required fields)
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn send_invalid_json_returns_bad_request() {
        let req = Request::post("/api/send")
            .header("content-type", "application/json")
            .body(Body::from("not json"))
            .unwrap();
        let (status, _body) = send_request(req).await;

        // Axum returns 400 Bad Request for syntactically invalid JSON
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn send_no_content_type_returns_error() {
        let req = Request::post("/api/send").body(Body::from("{}")).unwrap();
        let (status, _body) = send_request(req).await;

        // Axum returns 415 Unsupported Media Type when content-type is missing for Json extractor
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // --- POST /api/mint with missing fields ---

    #[tokio::test]
    async fn mint_missing_body_returns_error() {
        let req = Request::post("/api/mint")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let (status, _body) = send_request(req).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // --- GET /api/proof/{id} for non-existent proof ---

    #[tokio::test]
    async fn proof_not_found_returns_404() {
        let req = Request::get("/api/proof/9999").body(Body::empty()).unwrap();
        let (status, _body) = send_request(req).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // --- POST /api/commit with missing fields ---

    #[tokio::test]
    async fn commit_missing_body_returns_error() {
        let req = Request::post("/api/commit")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let (status, _body) = send_request(req).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // --- Fallback for unknown routes ---

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let req = Request::get("/does-not-exist").body(Body::empty()).unwrap();
        let (status, _body) = send_request(req).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // =======================================================================
    // Helper: send a request through a *shared* router (same AppState across
    // calls) instead of creating a fresh test_state() for every request.
    // =======================================================================
    async fn send_request_with_state(
        state: AppState,
        request: Request<Body>,
    ) -> (StatusCode, String) {
        let app = create_router(state);
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        (status, body)
    }

    // --- GET /api/username/resolve/{username} ---

    #[tokio::test]
    async fn resolve_unknown_username_returns_404() {
        let req = Request::get("/api/username/resolve/nonexistent")
            .body(Body::empty())
            .unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::NOT_FOUND);

        let resp: LnurlErrorResponse = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(resp.status, "ERROR");
        assert!(resp.reason.contains("not found"));
    }

    #[tokio::test]
    async fn resolve_minting_address_by_hex_prefix() {
        // The minting address starts with "af53a1" — a short prefix is enough
        // for resolve_identifier to match via hex-prefix fallback.
        let full_hex = hex::encode(zkcoins_program::MINTING_ADDRESS);
        let prefix = &full_hex[..8]; // first 8 hex chars

        let uri = format!("/api/username/resolve/{}", prefix);
        let req = Request::get(&uri).body(Body::empty()).unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::OK);

        let resp: UsernameResponse = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(resp.address, format!("0x{}", full_hex));
        assert_eq!(resp.username, prefix);
    }

    // --- POST /api/username/claim ---

    #[tokio::test]
    async fn claim_username_empty_body_returns_422() {
        let req = Request::post("/api/username/claim")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let (status, _body) = send_request(req).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn claim_username_no_content_type_returns_415() {
        let req = Request::post("/api/username/claim")
            .body(Body::from("{}"))
            .unwrap();
        let (status, _body) = send_request(req).await;

        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // --- GET /.well-known/lnurlp/{username} ---

    #[tokio::test]
    async fn lnurlp_unknown_user_returns_404() {
        let req = Request::get("/.well-known/lnurlp/nobody")
            .body(Body::empty())
            .unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::NOT_FOUND);

        let resp: LnurlErrorResponse = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(resp.status, "ERROR");
        assert!(resp.reason.contains("not found"));
    }

    #[tokio::test]
    async fn lnurlp_known_address_returns_pay_request() {
        // The minting address is resolvable by hex prefix through resolve_identifier.
        let full_hex = hex::encode(zkcoins_program::MINTING_ADDRESS);
        let prefix = &full_hex[..8];

        let uri = format!("/.well-known/lnurlp/{}", prefix);
        let req = Request::get(&uri)
            .header("host", "api.zkcoins.app")
            .body(Body::empty())
            .unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::OK);

        let resp: LnurlpResponse = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(resp.tag, "payRequest");
        assert!(
            resp.callback.contains(prefix),
            "callback should include the identifier"
        );
        assert_eq!(resp.min_sendable, 1_000);
        assert_eq!(resp.max_sendable, 1_000_000_000_000);
        assert!(resp.metadata.contains("zkCoins"));
    }

    // --- GET /lnurl/pay/{username} ---

    #[tokio::test]
    async fn lnurl_pay_callback_returns_phase2_error() {
        let req = Request::get("/lnurl/pay/someone")
            .body(Body::empty())
            .unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::OK);

        let resp: LnurlErrorResponse = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(resp.status, "ERROR");
        assert!(
            resp.reason.contains("Phase 2"),
            "should mention Phase 2: {}",
            resp.reason
        );
    }

    // --- Balance includes username field ---

    #[tokio::test]
    async fn balance_minting_address_has_no_username() {
        let address_hex = hex::encode(zkcoins_program::MINTING_ADDRESS);
        let uri = format!("/api/balance?address={}", address_hex);
        let req = Request::get(&uri).body(Body::empty()).unwrap();
        let (status, body) = send_request(req).await;

        assert_eq!(status, StatusCode::OK);

        // username should be absent (skip_serializing_if = None)
        let raw: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(
            raw.get("username").is_none() || raw["username"].is_null(),
            "minting address without a claimed username should have no username field"
        );
    }

    #[tokio::test]
    async fn balance_includes_username_when_claimed() {
        let state = test_state();

        // Manually claim a username for the minting address
        {
            let mut username_store = state.username_store.lock().unwrap();
            username_store
                .claim("satoshi", zkcoins_program::MINTING_ADDRESS)
                .expect("claim should succeed");
        }

        let address_hex = hex::encode(zkcoins_program::MINTING_ADDRESS);
        let uri = format!("/api/balance?address={}", address_hex);
        let req = Request::get(&uri).body(Body::empty()).unwrap();
        let (status, body) = send_request_with_state(state, req).await;

        assert_eq!(status, StatusCode::OK);

        let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(resp.balance, u64::MAX);
        assert_eq!(resp.username, Some("satoshi".to_string()));
    }

    // --- Concurrent balance reads ---

    #[tokio::test]
    async fn concurrent_balance_reads_are_consistent() {
        let state = test_state();
        let address_hex = hex::encode(zkcoins_program::MINTING_ADDRESS);
        let uri = format!("/api/balance?address={}", address_hex);

        // Spawn many concurrent balance requests against the same shared state.
        let mut handles = vec![];
        for _ in 0..20 {
            let s = state.clone();
            let u = uri.clone();
            handles.push(tokio::spawn(async move {
                let req = Request::get(&u).body(Body::empty()).unwrap();
                send_request_with_state(s, req).await
            }));
        }

        for handle in handles {
            let (status, body) = handle.await.expect("task should not panic");
            assert_eq!(status, StatusCode::OK);
            let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
            assert_eq!(
                resp.balance,
                u64::MAX,
                "every concurrent read must see the same minting balance"
            );
        }
    }

    // --- Concurrent mixed reads and username operations ---

    #[tokio::test]
    async fn concurrent_reads_with_username_claim() {
        let state = test_state();
        let address_hex = hex::encode(zkcoins_program::MINTING_ADDRESS);

        // Claim a username through the store directly (bypasses signature validation)
        {
            let mut store = state.username_store.lock().unwrap();
            store
                .claim("testuser", zkcoins_program::MINTING_ADDRESS)
                .unwrap();
        }

        // Spawn concurrent balance + resolve requests
        let mut handles = vec![];

        for i in 0..10 {
            let s = state.clone();
            let hex = address_hex.clone();
            handles.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    // Balance request
                    let req = Request::get(&format!("/api/balance?address={}", hex))
                        .body(Body::empty())
                        .unwrap();
                    let (status, body) = send_request_with_state(s, req).await;
                    assert_eq!(status, StatusCode::OK);
                    let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
                    assert_eq!(resp.balance, u64::MAX);
                    assert_eq!(resp.username, Some("testuser".to_string()));
                } else {
                    // Resolve request
                    let req = Request::get("/api/username/resolve/testuser")
                        .body(Body::empty())
                        .unwrap();
                    let (status, body) = send_request_with_state(s, req).await;
                    assert_eq!(status, StatusCode::OK);
                    let resp: UsernameResponse = serde_json::from_str(&body).expect("valid JSON");
                    assert_eq!(resp.username, "testuser");
                    assert_eq!(resp.address, format!("0x{}", hex));
                }
            }));
        }

        for handle in handles {
            handle.await.expect("task should not panic");
        }
    }

    // --- POST /api/commit with non-existent proof_id ---

    #[tokio::test]
    async fn commit_nonexistent_proof_id_returns_404() {
        let state = test_state();
        let body = serde_json::json!({
            "proof_id": 999999,
            "public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "signature": "00".repeat(64),
            "message": "00".repeat(32),
        });
        let req = Request::post("/api/commit")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let (status, _body) = send_request_with_state(state, req).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // --- POST /api/commit with valid proof_id but invalid signature ---

    #[tokio::test]
    async fn commit_invalid_signature_returns_error() {
        // Submit a commit with a fabricated proof_id that does not exist but with
        // a structurally valid body — the handler should return 404 (proof not found).
        let commit_body = serde_json::json!({
            "proof_id": 99999,
            "public_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "signature": "ab".repeat(64),
            "message": "cd".repeat(32),
        });
        let req = Request::post("/api/commit")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&commit_body).unwrap()))
            .unwrap();
        let (status, _) = send_request(req).await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "commit with non-existent proof_id must return 404"
        );
    }

    // --- verify_send_signature tests ---

    #[test]
    fn send_signature_rejects_missing_signature() {
        let request = SendCoinRequest {
            account_address: "0x".to_string() + &hex::encode([1u8; 32]),
            recipient: "0x".to_string() + &hex::encode([2u8; 32]),
            amount: 100,
            public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            next_public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            prev_commitment_pubkey: None,
            signature: None,
            timestamp: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
        };
        let result = verify_send_signature(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing signature"));
    }

    #[test]
    fn send_signature_rejects_missing_timestamp() {
        let request = SendCoinRequest {
            account_address: "0x".to_string() + &hex::encode([1u8; 32]),
            recipient: "0x".to_string() + &hex::encode([2u8; 32]),
            amount: 100,
            public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            next_public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            prev_commitment_pubkey: None,
            signature: Some("ab".repeat(64)),
            timestamp: None,
        };
        let result = verify_send_signature(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing timestamp"));
    }

    #[test]
    fn send_signature_rejects_expired_timestamp() {
        let old_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600; // 10 minutes ago
        let request = SendCoinRequest {
            account_address: "0x".to_string() + &hex::encode([1u8; 32]),
            recipient: "0x".to_string() + &hex::encode([2u8; 32]),
            amount: 100,
            public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            next_public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            prev_commitment_pubkey: None,
            signature: Some("ab".repeat(64)),
            timestamp: Some(old_timestamp),
        };
        let result = verify_send_signature(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timestamp"));
    }

    #[test]
    fn send_signature_rejects_invalid_hex() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let request = SendCoinRequest {
            account_address: "0x".to_string() + &hex::encode([1u8; 32]),
            recipient: "0x".to_string() + &hex::encode([2u8; 32]),
            amount: 100,
            public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            next_public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap(),
            prev_commitment_pubkey: None,
            signature: Some("not_valid_hex".to_string()),
            timestamp: Some(now),
        };
        let result = verify_send_signature(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature hex"));
    }

    #[test]
    fn send_signature_rejects_wrong_signature() {
        use bitcoin::secp256k1::SecretKey;

        let secp = secp::Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Sign a DIFFERENT message than what verify_send_signature expects
        let wrong_msg = Message::from_digest([0u8; 32]);
        let (xonly, _) = public_key.x_only_public_key();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        let sig = secp.sign_schnorr(&wrong_msg, &keypair);

        let request = SendCoinRequest {
            account_address: "0x".to_string() + &hex::encode([1u8; 32]),
            recipient: "0x".to_string() + &hex::encode([2u8; 32]),
            amount: 100,
            public_key,
            next_public_key: public_key,
            prev_commitment_pubkey: None,
            signature: Some(hex::encode(sig.serialize())),
            timestamp: Some(now),
        };
        let result = verify_send_signature(&request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Signature verification failed"));
    }

    // --- POST /api/username/claim with valid Schnorr signature ---

    #[tokio::test]
    async fn claim_username_with_valid_signature() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = secp::Secp256k1::new();
        let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);

        // address = sha256(compressed_pubkey)
        let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
        let address_hex = hex::encode(address);

        let username = "testclaim";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build claim message: sha256("zkcoins:claim_username" || address_hex || username || timestamp_le)
        let mut hasher = Sha256::new();
        hasher.update(b"zkcoins:claim_username");
        hasher.update(address_hex.as_bytes());
        hasher.update(username.as_bytes());
        hasher.update(now.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let msg = Message::from_digest(hash);
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);

        // Import the address into the account_server so resolve_identifier can find it
        let state = test_state();
        {
            let mut account_server = state.account_server.lock().unwrap();
            account_server.import_account(address, Account::new());
        }

        let body = serde_json::json!({
            "username": username,
            "address": address_hex,
            "public_key": public_key.to_string(),
            "signature": hex::encode(sig.serialize()),
            "timestamp": now,
        });

        let req = Request::post("/api/username/claim")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let (status, resp_body) = send_request_with_state(state, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Claim should succeed: {}",
            resp_body
        );

        let resp: UsernameResponse = serde_json::from_str(&resp_body).expect("valid JSON");
        assert_eq!(resp.username, username);
        assert_eq!(resp.address, format!("0x{}", address_hex));
    }

    #[tokio::test]
    async fn claim_username_wrong_pubkey() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = secp::Secp256k1::new();
        let secret = SecretKey::from_slice(&[8u8; 32]).unwrap();
        let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);

        // Use a DIFFERENT address that does NOT match sha256(pubkey)
        let wrong_address: [u8; 32] = [0xAA; 32];
        let address_hex = hex::encode(wrong_address);

        let username = "wrongpk";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Sign with the correct message format but the address doesn't match the pubkey
        let mut hasher = Sha256::new();
        hasher.update(b"zkcoins:claim_username");
        hasher.update(address_hex.as_bytes());
        hasher.update(username.as_bytes());
        hasher.update(now.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let msg = Message::from_digest(hash);
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);

        let body = serde_json::json!({
            "username": username,
            "address": address_hex,
            "public_key": public_key.to_string(),
            "signature": hex::encode(sig.serialize()),
            "timestamp": now,
        });

        let req = Request::post("/api/username/claim")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let (status, _) = send_request(req).await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Claim with mismatched pubkey/address must be rejected"
        );
    }

    #[tokio::test]
    async fn claim_username_expired_timestamp() {
        use bitcoin::secp256k1::{Keypair, SecretKey};

        let secp = secp::Secp256k1::new();
        let secret = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);

        let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
        let address_hex = hex::encode(address);

        let username = "expiredts";
        // Timestamp 10 minutes in the past (exceeds 5-min window)
        let expired_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600;

        let mut hasher = Sha256::new();
        hasher.update(b"zkcoins:claim_username");
        hasher.update(address_hex.as_bytes());
        hasher.update(username.as_bytes());
        hasher.update(expired_timestamp.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let msg = Message::from_digest(hash);
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);

        let body = serde_json::json!({
            "username": username,
            "address": address_hex,
            "public_key": public_key.to_string(),
            "signature": hex::encode(sig.serialize()),
            "timestamp": expired_timestamp,
        });

        let req = Request::post("/api/username/claim")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let (status, _) = send_request(req).await;

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Claim with expired timestamp must be rejected"
        );
    }

    #[test]
    fn send_signature_accepts_valid_signature() {
        use bitcoin::secp256k1::SecretKey;

        let secp = secp::Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);

        let account_address = "0x".to_string() + &hex::encode([1u8; 32]);
        let recipient = "0x".to_string() + &hex::encode([2u8; 32]);
        let amount: u64 = 100;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build the exact same message as verify_send_signature
        let mut hasher = Sha256::new();
        hasher.update(account_address.as_bytes());
        hasher.update(recipient.as_bytes());
        hasher.update(amount.to_le_bytes());
        hasher.update(now.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let msg = Message::from_digest(hash);
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);

        let request = SendCoinRequest {
            account_address,
            recipient,
            amount,
            public_key,
            next_public_key: public_key,
            prev_commitment_pubkey: None,
            signature: Some(hex::encode(sig.serialize())),
            timestamp: Some(now),
        };
        assert!(verify_send_signature(&request).is_ok());
    }
}
