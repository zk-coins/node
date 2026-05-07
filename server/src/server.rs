use axum::{
    body::Bytes,
    extract::{Json, Path, State},
    http::{header, HeaderValue, Method, StatusCode},
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
    accounts_path: String,
}

// Response types for our API
#[derive(Serialize)]
pub struct BalanceResponse {
    balance: u64,
}

#[derive(Serialize)]
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

// Add a struct to store proofs temporarily
struct ProofStore {
    proofs: Mutex<HashMap<u64, CoinProof>>,
    next_id: AtomicU64,
}

impl ProofStore {
    fn new() -> Self {
        ProofStore {
            proofs: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn add_proof(&self, proof_with_commitment: CoinProof) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let mut proofs = lock_or_recover(&self.proofs);
        proofs.insert(id, proof_with_commitment);
        id
    }

    fn get_proof(&self, id: u64) -> Option<CoinProof> {
        let proofs = lock_or_recover(&self.proofs);
        proofs.get(&id).cloned()
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

#[derive(Serialize)]
pub struct InfoResponse {
    network: String,
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
                    Json(BalanceResponse { balance: 0 }),
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
                Json(BalanceResponse { balance: 0 }),
            );
        }

        // Get balance for the specific account
        match account_server.get_account_balance(&address) {
            Ok(balance) => (StatusCode::OK, Json(BalanceResponse { balance })),
            Err(_) => (StatusCode::NOT_FOUND, Json(BalanceResponse { balance: 0 })),
        }
    } else {
        (StatusCode::NOT_FOUND, Json(BalanceResponse { balance: 0 }))
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
        let result = account_server_lock.send_coins(
            vec![Invoice::new(request.amount, to_address)],
            from_address,
            request.public_key,
            request.next_public_key,
            request.prev_commitment_pubkey,
        );
        if result.is_ok() {
            if let Err(e) = account_server_lock.save_to_file(&state.accounts_path) {
                eprintln!("Failed to persist accounts after send: {}", e);
            }
        }
        result
    };

    println!("Generated send_result: {:?}", send_result);

    // Now that the account_server lock is dropped, we can await safely.
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

    println!("Minting result: {:?}", send_result);
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
                eprintln!("Error broadcasting inscription: {}", err);
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
        eprintln!("Error broadcasting inscription: {}", err);
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

// Function to start the REST API server
pub async fn start_rest_server(
    account_server: AccountServer,
    addr: &str,
    accounts_path: String,
) -> anyhow::Result<()> {
    // Parse the address string into a SocketAddr
    let socket_addr = addr
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("Failed to parse address: {}", e))?;

    // Wrap the account_server in an Arc<Mutex> for thread-safe sharing
    let shared_account_server = Arc::new(Mutex::new(account_server));

    // Create a proof store
    let proof_store = Arc::new(ProofStore::new());

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

    // Create the combined state using the AppState struct
    let state = AppState {
        account_server: shared_account_server,
        proof_store,
        minting_account,
        accounts_path,
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

    // Create a router for API endpoints
    let api_routes = Router::new()
        .route("/info", get(info_handler))
        .route("/balance", get(get_balance_handler))
        .route("/send", post(send_coin_handler))
        .route("/address", get(get_address_handler))
        .route("/receive", post(receive_coin_handler))
        .route("/proof/{id}", get(get_proof_handler))
        .route("/mint", post(mint_handler))
        .route("/commit", post(commit_handler))
        .with_state(state);

    // CORS: allow frontend origins
    let cors = CorsLayer::new()
        .allow_origin([
            "https://zkcoins.app"
                .parse::<HeaderValue>()
                .expect("valid origin"),
            "https://dev.zkcoins.app"
                .parse::<HeaderValue>()
                .expect("valid origin"),
            "http://localhost:3090"
                .parse::<HeaderValue>()
                .expect("valid origin"),
        ])
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    // Build our application with routes
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .nest("/api", api_routes)
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(cors);

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
