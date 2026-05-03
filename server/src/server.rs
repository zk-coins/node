use axum::{
    body::Bytes,
    extract::{Json, Path, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use bitcoin::{bip32::Xpriv, Network};
use serde::{Deserialize, Serialize};
use shared::{ClientAccount, Invoice, ProofData};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use zkcoins_program::hash;
use zkcoins_prover::Proof;

use crate::account_server::{AccountServer, CoinProof};
use crate::publisher::create_and_broadcast_inscription;
use crate::NETWORK_CONFIG;

// Define a struct for our application state
#[derive(Clone)]
struct AppState {
    account_server: Arc<Mutex<AccountServer>>,
    proof_store: Arc<ProofStore>,
    minting_account: Arc<Mutex<ClientAccount>>,
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

// TODO: Send multiple coins at once.
#[derive(Deserialize)]
pub struct SendCoinRequest {
    account_address: String,
    recipient: String,
    amount: u64,
    public_key: bitcoin::secp256k1::PublicKey,
    next_public_key: bitcoin::secp256k1::PublicKey,
}

#[derive(Deserialize)]
pub struct MintRequest {
    account_address: String,
    amount: u64,
}

#[derive(Deserialize)]
pub struct ReceiveCoinRequest {
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
        let mut proofs = self.proofs.lock().unwrap();
        proofs.insert(id, proof_with_commitment);
        id
    }

    fn get_proof(&self, id: u64) -> Option<CoinProof> {
        let proofs = self.proofs.lock().unwrap();
        proofs.get(&id).cloned()
    }
}

#[derive(Serialize)]
pub struct SendCoinResponse {
    success: bool,
    proof_id: Option<u64>, // Store a reference ID instead of the proof itself
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
    let account_server = state.account_server.lock().unwrap();

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
    let account_server = state.account_server.lock().unwrap();

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
            let mut account_server = state.account_server.lock().unwrap();
            match account_server.receive_coin(coin_proof) {
                Ok(_) => Json(SendCoinResponse {
                    success: true,
                    proof_id: None,
                }),
                Err(_) => Json(SendCoinResponse {
                    success: false,
                    proof_id: None,
                }),
            }
        }
        Err(e) => {
            eprintln!("Failed to deserialize proof with commitment: {}", e);
            Json(SendCoinResponse {
                success: false,
                proof_id: None,
            })
        }
    }
}

async fn send_coin_handler(
    State(state): State<AppState>,
    Json(request): Json<SendCoinRequest>,
) -> impl IntoResponse {
    println!("Received send post request...");
    // Create converted addresses (from_address and to_address)
    let from_address_vec = match hex::decode(request.account_address.trim_start_matches("0x")) {
        Ok(addr) => addr,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(SendCoinResponse {
                    success: false,
                    proof_id: None,
                }),
            )
        }
    };
    let to_address_vec = match hex::decode(request.recipient.trim_start_matches("0x")) {
        Ok(addr) => addr,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(SendCoinResponse {
                    success: false,
                    proof_id: None,
                }),
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
            Json(SendCoinResponse {
                success: false,
                proof_id: None,
            }),
        );
    }

    // TODO: Provide the correct public keys from the client
    // Acquire the account_server lock only for the duration of sending coins.
    let send_result = {
        let mut account_server_lock = state.account_server.lock().unwrap();
        account_server_lock.send_coins(
            vec![Invoice::new(request.amount, to_address)],
            from_address,
            request.public_key,
            request.next_public_key,
        )
    };

    println!("Generated send_result: {:?}", send_result);

    // Now that the account_server lock is dropped, we can await safely.
    match send_result {
        Ok(mut coin_proofs) => {
            let commitment_data = bincode::serialize(&coin_proofs[0].commitment)
                .expect("Failed to serialize commitment");

            println!(
                "Sending commitment data with size: {} bytes",
                commitment_data.len()
            );
            println!("Commitment data hex: {}", hex::encode(&commitment_data));

            if let Err(err) =
                create_and_broadcast_inscription(&commitment_data, &NETWORK_CONFIG).await
            {
                eprintln!("Error broadcasting inscription: {}", err);
            }

            // TODO: Handle all the coins_proofs
            let proof_id = state.proof_store.add_proof(coin_proofs.pop().unwrap());
            (
                StatusCode::OK,
                Json(SendCoinResponse {
                    success: true,
                    proof_id: Some(proof_id),
                }),
            )
        }
        Err(_) => (
            StatusCode::OK,
            Json(SendCoinResponse {
                success: false,
                proof_id: None,
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
                Json(SendCoinResponse {
                    success: false,
                    proof_id: None,
                }),
            )
        }
    };

    let mut account_address = [0u8; 32];
    if account_address_vec.len() == 32 {
        account_address.copy_from_slice(&account_address_vec);
    } else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(SendCoinResponse {
                success: false,
                proof_id: None,
            }),
        );
    }

    // Generate keys and get necessary info while holding the minting_account lock briefly
    let (minting_pubkey, next_minting_pubkey, num_pubkeys_before_mint) = {
        let minting_account_guard = state.minting_account.lock().unwrap();
        let current_num_pubkeys = minting_account_guard.num_pubkeys;
        (
            minting_account_guard.generate_public_key(current_num_pubkeys),
            minting_account_guard.generate_public_key(current_num_pubkeys + 1),
            current_num_pubkeys,
        )
        // minting_account_guard is dropped here, releasing the lock before any .await
    };

    // Acquire the account_server lock only for the duration of sending coins.
    let send_result = {
        let mut account_server_guard = state.account_server.lock().unwrap();
        let minting_address = account_server_guard.get_minting_account_address().unwrap();
        account_server_guard.send_coins(
            vec![Invoice::new(request.amount, account_address)],
            minting_address,
            minting_pubkey,      // Use the generated keys
            next_minting_pubkey, // Use the generated keys
        )
        // account_server_guard is dropped here
    };

    println!("Minting result: {:?}", send_result);
    // Now that the locks are dropped, we can await safely.
    match send_result {
        Ok(mut coin_proofs) => {
            // Increment num_pubkeys *after* successful send and before await
            {
                let mut minting_account_guard = state.minting_account.lock().unwrap();
                // Ensure we only increment if the send was successful and based on the state *before* the send
                if minting_account_guard.num_pubkeys == num_pubkeys_before_mint {
                    minting_account_guard.num_pubkeys += 1;
                } else {
                    // This case might indicate a race condition or unexpected state change.
                    // Handle appropriately, maybe log an error or return a specific response.
                    eprintln!("WARNING: num_pubkeys changed unexpectedly during mint operation.");
                }
                let proof_data =
                    bincode::deserialize::<ProofData>(&coin_proofs[0].proof.public_values.to_vec())
                        .unwrap();
                coin_proofs[0].commitment = Some(minting_account_guard.create_commitment(
                    &proof_data.account_state_hash,
                    &proof_data.output_coins_root,
                ));
                // minting_account_guard is dropped here
            }

            let commitment_data = bincode::serialize(&coin_proofs[0].commitment)
                .expect("Failed to serialize commitment");

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
                let mut account_server_guard = state.account_server.lock().unwrap();
                for coin_proof in &coin_proofs {
                    account_server_guard.receive_coin(coin_proof.clone());
                }
            }

            let proof_id = state.proof_store.add_proof(coin_proofs.pop().unwrap());
            (
                StatusCode::OK,
                Json(SendCoinResponse {
                    success: true,
                    proof_id: Some(proof_id),
                }),
            )
        }
        Err(_) => (
            StatusCode::OK,
            Json(SendCoinResponse {
                success: false,
                proof_id: None,
            }),
        ),
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

async fn info_handler() -> impl IntoResponse {
    Json(InfoResponse {
        network: NETWORK_CONFIG.network_name.clone(),
    })
}

// Function to start the REST API server
pub async fn start_rest_server(account_server: AccountServer, addr: &str) -> anyhow::Result<()> {
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
        let private_key =
            Xpriv::new_master(Network::Bitcoin, secret).expect("Failed to create private key.");
        println!(
            "Set MINTING_ADDRESS to {:?}",
            &zkcoins_program::MINTING_ADDRESS
        );
        Arc::new(Mutex::new(ClientAccount {
            address: hash(private_key.to_string().as_bytes()),
            num_pubkeys: 0,
            private_key,
        }))
    };

    // Create the combined state using the AppState struct
    let state = AppState {
        account_server: shared_account_server,
        proof_store,
        minting_account,
    };
    {
        let mut minting_server_account = crate::account_server::Account::new();
        minting_server_account.balance = u64::MAX;
        state.account_server.lock().unwrap().import_account(
            state.minting_account.lock().unwrap().address,
            minting_server_account,
        );
    }

    // Create a router for API endpoints
    let api_routes = Router::new()
        .route("/info", get(info_handler))
        .route("/balance", get(get_balance_handler))
        .route("/send", post(send_coin_handler))
        // .route("/address", get(get_address_handler))
        // .route("/receive", post(receive_coin_handler))
        // .route("/proof/:id", get(get_proof_handler))
        .route("/mint", post(mint_handler))
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

// Handler to serve the index.html file
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
