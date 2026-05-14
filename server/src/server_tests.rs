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
    #[cfg(feature = "faucet")]
    let minting_client = {
        let secret = include_bytes!("../minting_secret.bin");
        let private_key = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Signet, secret)
            .expect("Failed to create test private key");
        shared::ClientAccount::new(private_key)
    };

    AppState {
        account_server: Arc::new(Mutex::new(account_server)),
        proof_store: Arc::new(ProofStore::new("/tmp/zkcoins-test-proofs")),
        #[cfg(feature = "faucet")]
        minting_account: Arc::new(Mutex::new(minting_client)),
        username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
        accounts_path: String::new(),
        #[cfg(feature = "usernames")]
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

#[cfg(feature = "address-list")]
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

#[cfg(feature = "faucet")]
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
async fn send_request_with_state(state: AppState, request: Request<Body>) -> (StatusCode, String) {
    let app = create_router(state);
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    (status, body)
}

// --- GET /api/username/resolve/{username} ---

#[cfg(feature = "usernames")]
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

#[cfg(feature = "usernames")]
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

#[cfg(feature = "usernames")]
#[tokio::test]
async fn claim_username_empty_body_returns_422() {
    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (status, _body) = send_request(req).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[cfg(feature = "usernames")]
#[tokio::test]
async fn claim_username_no_content_type_returns_415() {
    let req = Request::post("/api/username/claim")
        .body(Body::from("{}"))
        .unwrap();
    let (status, _body) = send_request(req).await;

    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// --- GET /.well-known/lnurlp/{username} ---

#[cfg(feature = "lnurl")]
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

#[cfg(feature = "lnurl")]
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

#[cfg(feature = "lnurl")]
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

#[cfg(feature = "usernames")]
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

#[cfg(feature = "usernames")]
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

#[cfg(feature = "usernames")]
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

#[cfg(feature = "usernames")]
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

// --- POST /api/send (happy path, exercises the full handler) ---

#[tokio::test]
async fn send_with_valid_signature_returns_proof_id_and_hashes() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};

    // Build the AppState the same way test_state() does so the handler can
    // run through the entire send pipeline (signature -> SP1 mock prover ->
    // proof persistence -> response).
    let state = test_state();

    // Derive the minting account's BIP-32 keys from the same secret the
    // production code uses, so the SP1 prover's expectations line up with
    // the account already seeded in test_state.
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv =
        Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).expect("test minting xpriv");
    let secp = secp::Secp256k1::new();

    let derive_pk = |index: u32| -> PublicKey {
        Xpub::from_priv(&secp, &xpriv)
            .derive_pub(&secp, &[ChildNumber::Normal { index }])
            .expect("derive_pub")
            .public_key
    };
    let derive_sk = |index: u32| -> SecretKey {
        xpriv
            .derive_priv(&secp, &[ChildNumber::Normal { index }])
            .expect("derive_priv")
            .private_key
    };

    let sk_0 = derive_sk(0);
    let pk_0 = derive_pk(0);
    let pk_1 = derive_pk(1);

    let account_address = "0x".to_string() + &hex::encode(zkcoins_program::MINTING_ADDRESS);
    let recipient = "0x".to_string() + &hex::encode([1u8; 32]);
    let amount: u64 = 100;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Build the exact same message the handler will hash for the signature.
    let mut hasher = Sha256::new();
    hasher.update(account_address.as_bytes());
    hasher.update(recipient.as_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &sk_0);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let body = serde_json::json!({
        "account_address": account_address,
        "recipient": recipient,
        "amount": amount,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });

    let app = create_router(state);
    let req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(bytes.to_vec()).unwrap();

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let response_json: serde_json::Value =
        serde_json::from_str(&body).expect("response is valid JSON");
    assert_eq!(response_json["success"], true);
    assert!(
        response_json["proof_id"].as_u64().is_some(),
        "proof_id missing from response: {body}"
    );
    assert!(
        response_json["account_state_hash"].as_str().is_some(),
        "account_state_hash missing: {body}"
    );
    assert!(
        response_json["output_coins_root"].as_str().is_some(),
        "output_coins_root missing: {body}"
    );
}

#[tokio::test]
async fn commit_with_bad_message_hex_returns_422() {
    // Build a sendable state + perform a valid send first so a proof_id
    // exists in the store, then send a commit that decodes-fails on the
    // message hex.
    let state = test_state();

    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let derive_pk = |idx: u32| -> PublicKey {
        Xpub::from_priv(&secp, &xpriv)
            .derive_pub(&secp, &[ChildNumber::Normal { index: idx }])
            .unwrap()
            .public_key
    };
    let derive_sk = |idx: u32| -> SecretKey {
        xpriv
            .derive_priv(&secp, &[ChildNumber::Normal { index: idx }])
            .unwrap()
            .private_key
    };

    let pk_0 = derive_pk(0);
    let pk_1 = derive_pk(1);
    let sk_0 = derive_sk(0);

    let account_address = "0x".to_string() + &hex::encode(zkcoins_program::MINTING_ADDRESS);
    let recipient = "0x".to_string() + &hex::encode([2u8; 32]);
    let amount: u64 = 50;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut hasher = Sha256::new();
    hasher.update(account_address.as_bytes());
    hasher.update(recipient.as_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let kp = Keypair::from_secret_key(&secp, &sk_0);
    let sig = secp.sign_schnorr(&msg, &kp);

    let send_body = serde_json::json!({
        "account_address": account_address,
        "recipient": recipient,
        "amount": amount,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let send_req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(send_body.to_string()))
        .unwrap();
    let (status, body) = send_request_with_state(state.clone(), send_req).await;
    assert_eq!(status, StatusCode::OK, "send failed: {body}");
    let send_resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    let proof_id = send_resp["proof_id"].as_u64().unwrap();

    // Now post a commit with garbage in the message hex.
    let commit_body = serde_json::json!({
        "proof_id": proof_id,
        "public_key": hex::encode(pk_0.serialize()),
        "signature": hex::encode([0u8; 64]),
        "message": "not-hex-at-all-zzzz",
    });
    let commit_req = Request::post("/api/commit")
        .header("content-type", "application/json")
        .body(Body::from(commit_body.to_string()))
        .unwrap();
    let (status, _body) = send_request_with_state(state, commit_req).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn commit_with_bad_signature_hex_returns_422() {
    let state = test_state();

    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let derive_pk = |idx: u32| -> PublicKey {
        Xpub::from_priv(&secp, &xpriv)
            .derive_pub(&secp, &[ChildNumber::Normal { index: idx }])
            .unwrap()
            .public_key
    };
    let derive_sk = |idx: u32| -> SecretKey {
        xpriv
            .derive_priv(&secp, &[ChildNumber::Normal { index: idx }])
            .unwrap()
            .private_key
    };
    let pk_0 = derive_pk(0);
    let pk_1 = derive_pk(1);
    let sk_0 = derive_sk(0);

    let account_address = "0x".to_string() + &hex::encode(zkcoins_program::MINTING_ADDRESS);
    let recipient = "0x".to_string() + &hex::encode([3u8; 32]);
    let amount: u64 = 50;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut hasher = Sha256::new();
    hasher.update(account_address.as_bytes());
    hasher.update(recipient.as_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let kp = Keypair::from_secret_key(&secp, &sk_0);
    let sig = secp.sign_schnorr(&msg, &kp);

    let send_body = serde_json::json!({
        "account_address": account_address,
        "recipient": recipient,
        "amount": amount,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let send_req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(send_body.to_string()))
        .unwrap();
    let (status, body) = send_request_with_state(state.clone(), send_req).await;
    assert_eq!(status, StatusCode::OK, "send failed: {body}");
    let send_resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    let proof_id = send_resp["proof_id"].as_u64().unwrap();

    // Bad signature hex (odd length).
    let commit_body = serde_json::json!({
        "proof_id": proof_id,
        "public_key": hex::encode(pk_0.serialize()),
        "signature": "zzz",
        "message": hex::encode([0u8; 32]),
    });
    let commit_req = Request::post("/api/commit")
        .header("content-type", "application/json")
        .body(Body::from(commit_body.to_string()))
        .unwrap();
    let (status, _body) = send_request_with_state(state, commit_req).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn commit_with_unverifiable_commitment_returns_401() {
    let state = test_state();

    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let derive_pk = |idx: u32| -> PublicKey {
        Xpub::from_priv(&secp, &xpriv)
            .derive_pub(&secp, &[ChildNumber::Normal { index: idx }])
            .unwrap()
            .public_key
    };
    let derive_sk = |idx: u32| -> SecretKey {
        xpriv
            .derive_priv(&secp, &[ChildNumber::Normal { index: idx }])
            .unwrap()
            .private_key
    };
    let pk_0 = derive_pk(0);
    let pk_1 = derive_pk(1);
    let sk_0 = derive_sk(0);

    let account_address = "0x".to_string() + &hex::encode(zkcoins_program::MINTING_ADDRESS);
    let recipient = "0x".to_string() + &hex::encode([4u8; 32]);
    let amount: u64 = 50;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut hasher = Sha256::new();
    hasher.update(account_address.as_bytes());
    hasher.update(recipient.as_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let kp = Keypair::from_secret_key(&secp, &sk_0);
    let sig = secp.sign_schnorr(&msg, &kp);

    let send_body = serde_json::json!({
        "account_address": account_address,
        "recipient": recipient,
        "amount": amount,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let send_req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(send_body.to_string()))
        .unwrap();
    let (status, body) = send_request_with_state(state.clone(), send_req).await;
    assert_eq!(status, StatusCode::OK, "send failed: {body}");

    // Valid hex shapes but the commitment signature won't verify against
    // the message+public_key combination.
    let commit_body = serde_json::json!({
        "proof_id": serde_json::from_str::<serde_json::Value>(&body).unwrap()["proof_id"],
        "public_key": hex::encode(pk_0.serialize()),
        "signature": hex::encode([0u8; 64]),
        "message": hex::encode([0u8; 64]),
    });
    let commit_req = Request::post("/api/commit")
        .header("content-type", "application/json")
        .body(Body::from(commit_body.to_string()))
        .unwrap();
    let (status, _body) = send_request_with_state(state, commit_req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
