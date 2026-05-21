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
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tower_http::cors::CorsLayer;
use zkcoins_program::hash::{digest_from_bytes, digest_to_bytes};
use zkcoins_prover::Proof;

use crate::account_server::{AccountServer, CoinProof};
use crate::db;
#[cfg(feature = "faucet")]
use crate::publisher::create_and_broadcast_inscription;
use crate::username::UsernameStore;
use crate::{NETWORK_CONFIG, USERNAME_DOMAIN};

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
    /// Postgres pool for per-account upserts (accounts table) and the
    /// faucet's `minting_meta.num_pubkeys` counter. Cloned cheaply via
    /// `Arc`; the underlying connections are pooled.
    pub(crate) pool: Arc<PgPool>,
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
    /// (which requires the Plonky2 prover to run).
    ///
    /// "Atomic" here means write-to-temp + rename. `File::create` +
    /// `sync_all` flushes the data file before the rename, and the
    /// final rename is a single inode swap from the OS's perspective,
    /// so a crash between the two never leaves a half-written
    /// `{id}.bin` for `get_proof` to find. Inlined (rather than calling
    /// a shared `atomic_write` helper) because the only remaining
    /// user after PR-A3 is this proof store — `accounts.bin`,
    /// `usernames.bin`, and `minting_num_pubkeys.bin` all moved to
    /// Postgres.
    fn persist_proof_bytes(path: &std::path::Path, bytes: &[u8], id: u64) {
        let path_str = path.to_str().unwrap_or("");
        let tmp_path = format!("{}.tmp", path_str);
        let result: std::io::Result<()> = (|| {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&tmp_path, path_str)?;
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("Failed to persist proof {}: {}", id, e);
        }
    }

    fn get_proof(&self, id: u64) -> Option<CoinProof> {
        let path = self.proof_path(id)?;
        let bytes = std::fs::read(&path).ok()?;
        bincode::deserialize(&bytes).ok()
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct SendCoinResponse {
    pub(crate) success: bool,
    /// Structured error message on failure. `None` on success. Mirrors
    /// the body string returned alongside a 4xx/5xx status code, so
    /// clients deserialising a non-2xx response can branch on it without
    /// re-reading the body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proof_id: Option<u64>,
    /// Hex-encoded hash fields the client needs to create a commitment (only set for user sends).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) account_state_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) output_coins_root: Option<String>,
}

/// Map a `send_coins` error string to an HTTP status code plus a
/// client-safe body message.
///
/// Threat model (memory `feedback_threat_model_over_checklist`):
///
/// - **422 UNPROCESSABLE_ENTITY** — the request is well-formed but the
///   witness is invalid (insufficient balance, in-coin not in source's
///   output_coins_root, source commitment not in history MMR, etc.).
///   The defense-in-depth shim added in PR #26 (Stage 5d-next-5
///   Phase 2b) produces two of these strings in microseconds before
///   the minute-scale prove cost is paid; surfacing the specific
///   string lets clients distinguish "fix your inclusion proof" from
///   "fix your account selection".
/// - **404 NOT_FOUND** — sender address is not known to the server.
/// - **400 BAD_REQUEST** — request structure violates the API contract
///   (e.g. AccountUpdate transition without `prev_commitment_pubkey`).
/// - **500 INTERNAL_SERVER_ERROR** — the prover failed. Body collapses
///   to a generic `"prove failed"` to avoid leaking prover-internal
///   state to the caller. The full error string is logged via
///   `eprintln!` in the handler.
pub(crate) fn map_send_coins_error(err: &str) -> (StatusCode, &'static str) {
    match err {
        "Unknown account address" => (StatusCode::NOT_FOUND, "Unknown account address"),
        "prev_commitment_pubkey required for account update" => (
            StatusCode::BAD_REQUEST,
            "prev_commitment_pubkey required for account update",
        ),
        "Insufficient funds" => (StatusCode::UNPROCESSABLE_ENTITY, "Insufficient funds"),
        // `get_merkle_proofs` failures — reachable from `send_coins`
        // via the `prev_commitment_pubkey` path. The client supplied
        // the wrong public key, or the previous proof references a
        // history root the server hasn't seen yet (stale snapshot).
        // Both are caller-fixable, hence 422 rather than 500.
        "Unable to get merkle proofs for provided public key" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unable to get merkle proofs for provided public key",
        ),
        "Unable to get mmr inclusion proof for the previous root" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unable to get mmr inclusion proof for the previous root",
        ),
        // Truncated proof public-inputs vector — the proof stored on
        // the account is corrupt or was produced by an incompatible
        // build of the prover. Not caller-fixable; surfaces as 500.
        "Proof public_inputs too short" => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Proof public_inputs too short",
        ),
        "In-coin not present in source's output_coins_root" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "In-coin not present in source's output_coins_root",
        ),
        "Source commitment not present in history MMR" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Source commitment not present in history MMR",
        ),
        "Coin is missing commitment" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Coin is missing commitment",
        ),
        "Should provide an inclusion proof" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Should provide an inclusion proof",
        ),
        "Coin should not exist in coin history tree" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Coin should not exist in coin history tree",
        ),
        "Coin should not exist in tree yet" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Coin should not exist in tree yet",
        ),
        "Too many in-coins for one transition" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Too many in-coins for one transition",
        ),
        "Too many out-coins for one transition" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Too many out-coins for one transition",
        ),
        s if s.ends_with("failed") => (StatusCode::INTERNAL_SERVER_ERROR, "prove failed"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

/// Build a `SendCoinResponse` for a failed `send_coins` call, paired
/// with the appropriate HTTP status code.
pub(crate) fn send_coins_error_response(err: &str) -> (StatusCode, Json<SendCoinResponse>) {
    let (status, body) = map_send_coins_error(err);
    (
        status,
        Json(SendCoinResponse {
            success: false,
            error: Some(body.to_string()),
            ..SendCoinResponse::default()
        }),
    )
}

/// Build a `SendCoinResponse` for a request-level failure (signature
/// verification, hex decode, address length mismatch, broadcast
/// failure, etc.). Lets every handler failure carry a body.error
/// string instead of an opaque empty body.
pub(crate) fn handler_error_response(
    status: StatusCode,
    msg: &'static str,
) -> (StatusCode, Json<SendCoinResponse>) {
    (
        status,
        Json(SendCoinResponse {
            success: false,
            error: Some(msg.to_string()),
            ..SendCoinResponse::default()
        }),
    )
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
    capabilities: Capabilities,
    /// External hostname this server serves, used by the client to render
    /// `<hex|username>@<domain>`. DEV and PRD share the chain identifier
    /// but live behind different external hostnames, so the client cannot
    /// derive this from `network` alone — the server reports it directly.
    username_domain: String,
}

/// Server-side feature gates exposed to clients so the app can render
/// capability-driven UI without a parallel build-time env-flag set.
/// Each bool reflects a compile-time Cargo feature on the server binary.
#[derive(Serialize, Deserialize)]
pub struct Capabilities {
    pub address_list: bool,
    pub faucet: bool,
    pub usernames: bool,
    pub lnurl: bool,
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
            // Unobserved address: canonical zero-balance state, not a not-found condition.
            Err(_) => (
                StatusCode::OK,
                Json(BalanceResponse {
                    balance: 0,
                    username,
                }),
            ),
        }
    } else {
        // Missing required `address` query parameter — malformed request,
        // not a routing miss. Matches the 422 returned by the invalid-hex
        // and wrong-length branches above.
        (
            StatusCode::UNPROCESSABLE_ENTITY,
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
    let coin_proof = match bincode::deserialize::<CoinProof>(&body) {
        Ok(cp) => cp,
        Err(e) => {
            eprintln!("Failed to deserialize proof with commitment: {}", e);
            return Json(SendCoinResponse::default());
        }
    };
    let recipient = coin_proof.coin.recipient;
    // Snapshot the recipient's mutated account inside the (sync) lock
    // scope so the post-receive Postgres upsert runs without holding
    // the guard across an `.await` point.
    let snapshot: Option<Vec<u8>> = {
        let mut account_server = lock_or_recover(&state.account_server);
        match account_server.receive_coin(coin_proof) {
            Ok(_) => account_server
                .get_account(&recipient)
                .map(AccountServer::serialize_account),
            Err(_) => None,
        }
    };
    match snapshot {
        Some(bytes) => {
            let addr_bytes = digest_to_bytes(&recipient);
            if let Err(e) = db::upsert_account(&state.pool, &addr_bytes, &bytes).await {
                eprintln!("Failed to upsert recipient account after receive: {}", e);
            }
            Json(SendCoinResponse {
                success: true,
                ..Default::default()
            })
        }
        None => Json(SendCoinResponse::default()),
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
            return handler_error_response(
                StatusCode::UNAUTHORIZED,
                "Signature verification failed",
            );
        }
    }

    // Create converted addresses (from_address and to_address)
    let from_address_vec = match hex::decode(request.account_address.trim_start_matches("0x")) {
        Ok(addr) => addr,
        Err(_) => {
            return handler_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "account_address is not valid hex",
            )
        }
    };
    let to_address_vec = match hex::decode(request.recipient.trim_start_matches("0x")) {
        Ok(addr) => addr,
        Err(_) => {
            return handler_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "recipient is not valid hex",
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
        return handler_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "address must be 32 bytes (64 hex chars)",
        );
    }
    let from_address = digest_from_bytes(&from_address_bytes);
    let to_address = digest_from_bytes(&to_address_bytes);

    // TODO: Provide the correct public keys from the client
    // Acquire the account_server lock only for the duration of sending
    // coins, and snapshot the resulting account bincode bytes *inside*
    // the lock scope so the post-send Postgres upsert runs without
    // holding the (sync) `std::sync::Mutex` guard across the `.await`.
    // The guard cannot be held across an await point: `std::sync::
    // MutexGuard` is not `Send`, and even if it were, parking the
    // future would block other handlers behind the same lock for the
    // duration of the DB round-trip.
    // `updated_account_bytes` is only meaningful on the Ok branch
    // below — `send_coins` Ok implies the sender account exists in
    // memory (it was just mutated). On the Err branch the snapshot is
    // unused; we initialize it to an empty `Vec` to avoid an
    // `Option`-shaped sentinel whose `None`-arm at the upsert site
    // would never be reached at runtime (and thus could not be
    // covered by tests).
    let send_result: Result<Vec<CoinProof>, &str>;
    let updated_account_bytes: Vec<u8>;
    {
        let mut account_server_lock = lock_or_recover(&state.account_server);
        let res = account_server_lock.send_coins(
            vec![Invoice::new(request.amount, to_address)],
            from_address,
            request.public_key,
            request.next_public_key,
            request.prev_commitment_pubkey,
        );
        updated_account_bytes = match &res {
            Ok(_) => AccountServer::serialize_account(
                account_server_lock
                    .get_account(&from_address)
                    .expect("send_coins Ok implies the sender account is in memory"),
            ),
            Err(_) => Vec::new(),
        };
        send_result = res;
    }

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
            // Now persist the mutated sender account (proof is already
            // safe on disk). Best-effort: a database hiccup here leaves
            // the proof + in-memory state correct but the persistent
            // account row stale; the next mutation will overwrite it.
            // We log and continue rather than failing the request,
            // which mirrors the pre-Postgres `save_to_file` semantics.
            let addr_bytes = digest_to_bytes(&from_address);
            if let Err(e) =
                db::upsert_account(&state.pool, &addr_bytes, &updated_account_bytes).await
            {
                eprintln!("Failed to upsert sender account after send: {}", e);
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
        Err(e) => {
            eprintln!("send_coins error: {}", e);
            send_coins_error_response(e)
        }
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
            return handler_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "account_address is not valid hex",
            )
        }
    };

    let mut account_address_bytes = [0u8; 32];
    if account_address_vec.len() == 32 {
        account_address_bytes.copy_from_slice(&account_address_vec);
    } else {
        return handler_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "account_address must be 32 bytes (64 hex chars)",
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
                return handler_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Minting account not configured",
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
            // Increment num_pubkeys *after* successful send and snapshot
            // the new counter value so the Postgres upsert can run after
            // the lock is released (sync mutex must not be held across
            // `.await`).
            let num_pubkeys_to_persist: Option<u32>;
            {
                let mut minting_account_guard = lock_or_recover(&state.minting_account);
                // Ensure we only increment if the send was successful and based on the state *before* the send
                if minting_account_guard.num_pubkeys == num_pubkeys_before_mint {
                    minting_account_guard.num_pubkeys += 1;
                    num_pubkeys_to_persist = Some(minting_account_guard.num_pubkeys);
                } else {
                    // This case might indicate a race condition or unexpected state change.
                    // Handle appropriately, maybe log an error or return a specific response.
                    eprintln!("WARNING: num_pubkeys changed unexpectedly during mint operation.");
                    num_pubkeys_to_persist = None;
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
                        return handler_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "prove failed",
                        );
                    }
                };
                coin_proofs[0].commitment = Some(minting_account_guard.create_commitment(
                    &proof_data.account_state_hash,
                    &proof_data.output_coins_root,
                ));
                // minting_account_guard is dropped here
            }

            // Persist the new counter so a server restart keeps the
            // ClientAccount aligned with the server-side
            // minting_account.proof. Replaces the legacy
            // `minting_num_pubkeys.bin` sibling file; the matching
            // load lives in `server_runtime.rs`. Best-effort: a DB
            // hiccup leaves the in-memory counter ahead of the
            // persistent row, which the next successful mint will
            // re-sync.
            if let Some(n) = num_pubkeys_to_persist {
                if let Err(e) = db::upsert_minting_num_pubkeys(&state.pool, n).await {
                    eprintln!("Failed to upsert minting num_pubkeys to Postgres: {}", e);
                }
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
                    return handler_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Failed to broadcast mint inscription on-chain",
                    );
                }
                eprintln!(
                    "DEV_SKIP_BROADCAST_FAILURE=true — continuing without on-chain commitment"
                );
            }
            // Snapshot the mutated accounts (the minting account and
            // every recipient) so the post-mint upserts run lock-free.
            // The set of affected addresses is the recipient(s) plus
            // the faucet's MINTING_ADDRESS (the source side of the
            // transition).
            let accounts_to_persist: Vec<(zkcoins_program::hash::HashDigest, Vec<u8>)> = {
                let mut account_server_guard = lock_or_recover(&state.account_server);
                for coin_proof in &coin_proofs {
                    if let Err(e) = account_server_guard.receive_coin(coin_proof.clone()) {
                        eprintln!("Failed to receive minted coin: {}", e);
                    }
                }
                let mut affected: Vec<zkcoins_program::hash::HashDigest> =
                    Vec::with_capacity(1 + coin_proofs.len());
                affected.push(*zkcoins_program::types::MINTING_ADDRESS);
                for cp in &coin_proofs {
                    affected.push(cp.coin.recipient);
                }
                let mut out: Vec<(zkcoins_program::hash::HashDigest, Vec<u8>)> =
                    Vec::with_capacity(affected.len());
                for addr in affected {
                    if let Some(acct) = account_server_guard.get_account(&addr) {
                        out.push((addr, AccountServer::serialize_account(acct)));
                    }
                }
                out
            };
            for (addr, bytes) in accounts_to_persist {
                let addr_bytes = digest_to_bytes(&addr);
                if let Err(e) = db::upsert_account(&state.pool, &addr_bytes, &bytes).await {
                    eprintln!("Failed to upsert account after mint: {}", e);
                }
            }

            let proof_id = match coin_proofs.pop() {
                Some(proof) => state.proof_store.add_proof(proof),
                None => {
                    return handler_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "prove failed",
                    );
                }
            };
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
        Err(e) => {
            eprintln!("mint send_coins error: {}", e);
            send_coins_error_response(e)
        }
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
            return handler_error_response(StatusCode::NOT_FOUND, "Unknown proof_id");
        }
    };

    // Reconstruct the Commitment from the client-provided fields
    let message_bytes = match hex::decode(&request.message) {
        Ok(b) => b,
        Err(_) => {
            return handler_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "message is not valid hex",
            );
        }
    };
    let sig_bytes = match hex::decode(&request.signature) {
        Ok(b) => b,
        Err(_) => {
            return handler_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "signature is not valid hex",
            );
        }
    };
    let signature = match bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            return handler_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "signature is not a valid Schnorr signature",
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
        return handler_error_response(StatusCode::UNAUTHORIZED, "Commitment signature invalid");
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
        capabilities: Capabilities {
            address_list: cfg!(feature = "address-list"),
            faucet: cfg!(feature = "faucet"),
            usernames: cfg!(feature = "usernames"),
            lnurl: cfg!(feature = "lnurl"),
        },
        username_domain: USERNAME_DOMAIN.clone(),
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

    // Claim the username. `UsernameStore::claim` is async (it persists
    // through `db::claim_username` before mutating the in-memory map),
    // so the lock-acquire / drop ordering matters: we must hold the
    // store guard only synchronously, but the persistence call lives
    // inside it. We solve this by using `tokio::sync::Mutex` would
    // ripple through every other handler; instead we serialize the
    // claim path application-side: take the (sync) `std::sync::Mutex`,
    // do the in-memory pre-check + DB call + in-memory commit inside
    // the same `claim` method, and rely on the SQL `ON CONFLICT DO
    // NOTHING` to catch any race that slips past the in-memory
    // pre-check. Because `claim` is `async`, we have to drop the sync
    // guard before the `.await`, which means we cannot hold it across
    // the persistence call. The compromise: short critical section
    // around `std::mem::take` of the in-memory map, run the claim
    // against a temporary, then swap it back. Simpler and equivalent
    // for the MVP: leave the sync guard NOT held across the await by
    // routing the claim through a clone-out / merge-back pattern.
    //
    // For the MVP, the username-claim endpoint is feature-gated and
    // expected to see < 1 req/s in production. We just acquire the
    // guard, take ownership of the store, drop the guard, run the
    // async claim, then re-acquire and merge the result back. The
    // brief window where the guard is dropped is bounded by the DB
    // round-trip; concurrent claimers serialize at the SQL `ON
    // CONFLICT DO NOTHING` boundary regardless.
    let mut snapshot = {
        let mut guard = lock_or_recover(&state.username_store);
        std::mem::take(&mut *guard)
    };
    let claim_outcome = snapshot
        .claim(&state.pool, &request.username, address)
        .await;
    {
        let mut guard = lock_or_recover(&state.username_store);
        *guard = snapshot;
    }
    if let Err(e) = claim_outcome {
        let (status, reason): (StatusCode, String) = match e {
            crate::username::ClaimUsernameError::Validation(s) => {
                (StatusCode::CONFLICT, s.to_string())
            }
            crate::username::ClaimUsernameError::Db(db_err) => {
                eprintln!("Failed to persist username claim: {}", db_err);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Failed to persist username claim".to_string(),
                )
            }
        };
        return (
            status,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason,
            }),
        )
            .into_response();
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

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
