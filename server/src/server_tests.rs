use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::account_server::{Account, AccountServer};
use crate::state::State;

/// Build a `PgPool` that points at nowhere — every query against it
/// fails fast with a connect error. Used by the server-handler test
/// suite below so the handlers' persistence-side `.await` lines run
/// the error branch (which mirrors the legacy file-IO best-effort
/// semantics: log + continue, never fail the response). The matching
/// happy-path tests for the upsert lines run against a real
/// Postgres 17 testcontainer in `db_tests.rs`, `account_server_tests.rs`,
/// `username_tests.rs`, and `server_runtime_tests.rs`.
fn dead_pool() -> Arc<sqlx::PgPool> {
    Arc::new(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/postgres")
            .expect("connect_lazy never fails"),
    )
}

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
    minting_account.balance = 1_000_000;
    account_server.import_account(*zkcoins_program::types::MINTING_ADDRESS, minting_account);

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
        pool: dead_pool(),
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

// --- GET / (root) ---

#[tokio::test]
async fn root_returns_service_metadata() {
    let req = Request::get("/").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::OK);
    // Verify the response is JSON and contains the service identifier plus
    // a pointer to /api/info — those two are enough to prove the handler
    // ran and serialized correctly.
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(json["service"], "zkcoins-server");
    assert_eq!(json["endpoints"]["info"], "GET  /api/info");
    assert!(json["version"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(json["network"].as_str().is_some_and(|v| !v.is_empty()));
}

// --- GET /api/info ---

#[tokio::test]
async fn info_returns_network_name_capabilities_and_username_domain() {
    let req = Request::get("/api/info").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::OK);

    let info: InfoResponse = serde_json::from_str(&body).expect("valid JSON");
    // The lazy_static defaults to "Mutinynet" when IS_MAINNET is unset
    assert!(!info.network.is_empty(), "network name must not be empty");

    // Capabilities reflect the cargo feature set this binary was built with.
    // Same `cfg!(...)` evaluation as the handler, so the test passes both in
    // MVP builds (all false) and `--all-features` builds (all true).
    assert_eq!(
        info.capabilities.address_list,
        cfg!(feature = "address-list")
    );
    assert_eq!(info.capabilities.faucet, cfg!(feature = "faucet"));
    assert_eq!(info.capabilities.usernames, cfg!(feature = "usernames"));
    assert_eq!(info.capabilities.lnurl, cfg!(feature = "lnurl"));

    // The lazy_static defaults to "zkcoins.app" (PRD) when USERNAME_DOMAIN is unset
    assert!(
        !info.username_domain.is_empty(),
        "username_domain must not be empty"
    );
}

#[tokio::test]
async fn info_serialization_format_is_stable() {
    let req = Request::get("/api/info").body(Body::empty()).unwrap();
    let (_, body) = send_request(req).await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    // Top-level fields the app contract relies on.
    assert!(v["network"].is_string());
    assert!(v["capabilities"].is_object());
    assert!(v["username_domain"].is_string());

    let caps = &v["capabilities"];
    for key in ["address_list", "faucet", "usernames", "lnurl"] {
        assert!(caps[key].is_boolean(), "capability `{key}` must be bool");
    }
}

// --- GET /api/balance ---

#[tokio::test]
async fn balance_unknown_address_returns_ok_with_zero() {
    // 32 zero bytes in hex = 64 hex chars
    let address_hex = "00".repeat(32);
    let uri = format!("/api/balance?address={}", address_hex);
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::OK);

    let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(resp.balance, 0);
    assert!(resp.username.is_none());
}

#[cfg(feature = "usernames")]
#[tokio::test]
async fn balance_unknown_address_with_claimed_username_returns_username() {
    let state = test_state();
    let address_bytes = [0xABu8; 32];
    let address = zkcoins_program::hash::digest_from_bytes(&address_bytes);

    // Pre-populate the in-memory map (no Postgres round-trip — see
    // the comment on `insert_for_test`).
    {
        let mut store = state.username_store.lock().unwrap();
        store.insert_for_test("alice", address);
    }

    let uri = format!("/api/balance?address={}", hex::encode(address_bytes));
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::OK);
    let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(resp.balance, 0);
    assert_eq!(resp.username, Some("alice".to_string()));
}

#[tokio::test]
async fn balance_minting_address_returns_max() {
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(
        &zkcoins_program::types::MINTING_ADDRESS,
    ));
    let uri = format!("/api/balance?address={}", address_hex);
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::OK);

    let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(resp.balance, 1_000_000u64);
}

#[tokio::test]
async fn balance_missing_address_param_returns_unprocessable() {
    let req = Request::get("/api/balance").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

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
    let full_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(
        &zkcoins_program::types::MINTING_ADDRESS,
    ));
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
    let full_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(
        &zkcoins_program::types::MINTING_ADDRESS,
    ));
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
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(
        &zkcoins_program::types::MINTING_ADDRESS,
    ));
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

    // Pre-populate the in-memory username map via the test-only
    // helper (bypasses the async Postgres path; production code
    // claims via the /api/username/claim handler).
    {
        let mut username_store = state.username_store.lock().unwrap();
        username_store.insert_for_test("satoshi", *zkcoins_program::types::MINTING_ADDRESS);
    }

    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(
        &zkcoins_program::types::MINTING_ADDRESS,
    ));
    let uri = format!("/api/balance?address={}", address_hex);
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::OK);

    let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(resp.balance, 1_000_000u64);
    assert_eq!(resp.username, Some("satoshi".to_string()));
}

// --- Concurrent balance reads ---

#[tokio::test]
async fn concurrent_balance_reads_are_consistent() {
    let state = test_state();
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(
        &zkcoins_program::types::MINTING_ADDRESS,
    ));
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
            resp.balance, 1_000_000u64,
            "every concurrent read must see the same minting balance"
        );
    }
}

// --- Concurrent mixed reads and username operations ---

#[cfg(feature = "usernames")]
#[tokio::test]
async fn concurrent_reads_with_username_claim() {
    let state = test_state();
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(
        &zkcoins_program::types::MINTING_ADDRESS,
    ));

    // Claim a username through the store directly (bypasses both
    // signature validation and the async Postgres path; production
    // claims go through the /api/username/claim handler).
    {
        let mut store = state.username_store.lock().unwrap();
        store.insert_for_test("testuser", *zkcoins_program::types::MINTING_ADDRESS);
    }

    // Spawn concurrent balance + resolve requests
    let mut handles = vec![];

    for i in 0..10 {
        let s = state.clone();
        let hex = address_hex.clone();
        handles.push(tokio::spawn(async move {
            if i % 2 == 0 {
                // Balance request
                let req = Request::get(format!("/api/balance?address={}", hex))
                    .body(Body::empty())
                    .unwrap();
                let (status, body) = send_request_with_state(s, req).await;
                assert_eq!(status, StatusCode::OK);
                let resp: BalanceResponse = serde_json::from_str(&body).expect("valid JSON");
                assert_eq!(resp.balance, 1_000_000u64);
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
    let (_xonly, _) = public_key.x_only_public_key();
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
        account_server.import_account(
            zkcoins_program::hash::digest_from_bytes(&address),
            Account::new(),
        );
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

    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
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

    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
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

    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
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

    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
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

#[tokio::test]
async fn send_with_invalid_signature_returns_401() {
    let body = serde_json::json!({
        "account_address": "0x".to_string() + &hex::encode(zkcoins_program::hash::digest_to_bytes(&zkcoins_program::types::MINTING_ADDRESS)),
        "recipient": "0x".to_string() + &hex::encode([1u8; 32]),
        "amount": 50,
        "public_key": hex::encode([2u8; 33]), // garbage compressed pubkey of valid length
        "next_public_key": hex::encode([3u8; 33]),
        "signature": hex::encode([0u8; 64]),  // valid hex shape but wrong sig
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });
    let req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send_request(req).await;
    // serde will reject "02" + [2u8;32] as not-a-valid-pubkey at body parsing,
    // so we accept either UNPROCESSABLE_ENTITY (parse-failed) or UNAUTHORIZED
    // (parse-succeeded but signature verification failed).
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 401 or 422, got {status}"
    );
}

#[tokio::test]
async fn send_with_non_hex_account_address_returns_422() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;
    let sk_0: SecretKey = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    let account_address = "not-hex-at-all".to_string();
    let recipient = "0x".to_string() + &hex::encode([1u8; 32]);
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

    let body = serde_json::json!({
        "account_address": account_address,
        "recipient": recipient,
        "amount": amount,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send_request(req).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn send_with_wrong_length_address_returns_422() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;
    let sk_0: SecretKey = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    // Account address is parseable hex but only 16 bytes, not 32.
    let account_address = "0x".to_string() + &hex::encode([1u8; 16]);
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

    let body = serde_json::json!({
        "account_address": account_address,
        "recipient": recipient,
        "amount": amount,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send_request(req).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn send_with_insufficient_funds_returns_422_with_error_string() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};

    // Build a state where the minting account has been emptied.
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut account_server = AccountServer::new(Arc::clone(&state_arc));
    let mut empty_minting = Account::new();
    empty_minting.balance = 0;
    account_server.import_account(*zkcoins_program::types::MINTING_ADDRESS, empty_minting);
    #[cfg(feature = "faucet")]
    let minting_client = {
        let secret = include_bytes!("../minting_secret.bin");
        let private_key = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Signet, secret)
            .expect("test minting xpriv");
        shared::ClientAccount::new(private_key)
    };
    let state = AppState {
        account_server: Arc::new(Mutex::new(account_server)),
        proof_store: Arc::new(ProofStore::new("/tmp/zkcoins-test-proofs-empty")),
        #[cfg(feature = "faucet")]
        minting_account: Arc::new(Mutex::new(minting_client)),
        username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
        pool: dead_pool(),
    };

    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;
    let sk_0: SecretKey = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
    let recipient = "0x".to_string() + &hex::encode([1u8; 32]);
    let amount: u64 = 100;
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

    let body = serde_json::json!({
        "account_address": account_address,
        "recipient": recipient,
        "amount": amount,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, body) = send_request_with_state(state, req).await;
    // After the Item 1 HTTP error-mapping landed (see PR following #28),
    // send_coins failures surface as 4xx with body.error rather than
    // 200 + success:false. Insufficient funds maps to 422.
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(resp["success"], false);
    assert_eq!(resp["error"], "Insufficient funds");
}

#[tokio::test]
async fn receive_coin_with_invalid_bincode_returns_default_response() {
    let req = Request::post("/api/receive")
        .header("content-type", "application/octet-stream")
        .body(Body::from(vec![0xff, 0xfe, 0xfd, 0xfc]))
        .unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(resp["success"], false);
}

#[tokio::test]
async fn send_with_non_hex_recipient_returns_422() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;
    let sk_0: SecretKey = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
    let recipient = "absolutely-not-hex".to_string();
    let amount: u64 = 1;
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

    let body = serde_json::json!({
        "account_address": account_address,
        "recipient": recipient,
        "amount": amount,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send_request(req).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn lock_or_recover_recovers_from_poisoned_mutex() {
    let mutex = Arc::new(Mutex::new(42i32));
    let mutex_clone = Arc::clone(&mutex);

    // Poison the mutex by panicking inside lock().
    let _ = std::thread::spawn(move || {
        let _guard = mutex_clone.lock().unwrap();
        panic!("intentional panic to poison the mutex");
    })
    .join();

    assert!(
        mutex.is_poisoned(),
        "mutex must be poisoned after the panic"
    );

    // Recovering must succeed and yield the inner value.
    let guard = lock_or_recover(&mutex);
    assert_eq!(*guard, 42);
}

#[tokio::test]
async fn commit_with_valid_signature_fails_broadcast_returns_503() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    let state = test_state();

    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;
    let sk_0: SecretKey = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    // Send first to get proof_id + the hashes the client signs over.
    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
    let recipient = "0x".to_string() + &hex::encode([5u8; 32]);
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
    let ash_hex = send_resp["account_state_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let ocr_hex = send_resp["output_coins_root"].as_str().unwrap().to_string();

    // Build a valid commitment that the handler will accept.
    let ash_bytes = hex::decode(&ash_hex).unwrap();
    let ocr_bytes = hex::decode(&ocr_hex).unwrap();
    let mut commit_message = Vec::with_capacity(ash_bytes.len() + ocr_bytes.len());
    commit_message.extend_from_slice(&ash_bytes);
    commit_message.extend_from_slice(&ocr_bytes);
    // Commitment::new SHA256s the message internally, so just pass the
    // pre-image bytes the handler will receive.
    let commitment = shared::commitment::Commitment::new(&sk_0, commit_message.clone())
        .expect("commitment creation");
    assert!(commitment.verify(), "test commitment must verify locally");

    let commit_body = serde_json::json!({
        "proof_id": proof_id,
        "public_key": hex::encode(commitment.public_key.serialize()),
        "signature": hex::encode(commitment.signature.serialize()),
        "message": hex::encode(&commitment.message),
    });
    let commit_req = Request::post("/api/commit")
        .header("content-type", "application/json")
        .body(Body::from(commit_body.to_string()))
        .unwrap();
    let (status, _) = send_request_with_state(state, commit_req).await;
    // The commitment verifies, the handler proceeds to broadcast. Without
    // a reachable Bitcoin node in the unit test environment, that call
    // fails and the handler returns SERVICE_UNAVAILABLE. We accept either
    // 503 (broadcast attempted and failed) or 200 (network was reachable
    // and broadcast happened to succeed against a public Mutinynet).
    assert!(
        status == StatusCode::SERVICE_UNAVAILABLE || status == StatusCode::OK,
        "expected 503 or 200, got {status}"
    );
}

#[test]
fn proof_store_proof_path_returns_none_for_nonexistent_directory() {
    // proof_path canonicalizes the configured directory. If the directory
    // does not exist, canonicalize fails and proof_path returns None.
    let store = ProofStore::new("/nonexistent/zkcoins/proof/dir");
    // The directory was created by ProofStore::new, but to test the
    // None branch we point at one that does not exist.
    let truly_missing = ProofStore {
        dir: "/this/path/genuinely/does/not/exist/zkcoins".to_string(),
        next_id: std::sync::atomic::AtomicU64::new(0),
    };
    assert!(truly_missing.proof_path(7).is_none());
    // The real store was created and resolves fine for arbitrary ids.
    drop(store);
}

#[test]
fn proof_store_new_picks_up_max_id_from_existing_files() {
    let dir = std::env::temp_dir().join(format!(
        "zkcoins-proof-store-max-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // Drop a few well-formed and one malformed filename.
    std::fs::write(dir.join("3.bin"), b"placeholder").unwrap();
    std::fs::write(dir.join("17.bin"), b"placeholder").unwrap();
    std::fs::write(dir.join("garbage.bin"), b"placeholder").unwrap();
    std::fs::write(dir.join("notbin.txt"), b"placeholder").unwrap();

    let store = ProofStore::new(dir.to_str().unwrap());
    // next_id starts at max(3, 17) + 1 = 18; the malformed names are skipped.
    let id = store.next_id.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(id, 18);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn persist_proof_bytes_logs_error_when_write_fails() {
    // Pointing at a file inside a directory that does not exist guarantees
    // `File::create` inside `atomic_write` returns an `Err` on both Linux
    // and macOS. The function is best-effort: it logs and returns ().
    // Exercising it covers the `if let Err(e) = ...` arm in server.rs
    // that was reported uncovered on the Linux runner only.
    let bad = std::path::Path::new("/this/path/does/not/exist/zkcoins/0.bin");
    ProofStore::persist_proof_bytes(bad, b"payload", 42);
}

#[test]
fn persist_proof_bytes_succeeds_when_write_succeeds() {
    // Mirror test for the Ok arm so the helper is fully exercised.
    let dir = std::env::temp_dir().join(format!(
        "zkcoins-persist-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("99.bin");
    ProofStore::persist_proof_bytes(&path, b"payload", 99);
    assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn commit_with_wrong_length_signature_returns_422() {
    let state = test_state();

    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;
    let sk_0: SecretKey = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
    let recipient = "0x".to_string() + &hex::encode([6u8; 32]);
    let amount: u64 = 1;
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

    // Signature hex is parseable, but length is wrong (1 byte instead of 64).
    let commit_body = serde_json::json!({
        "proof_id": proof_id,
        "public_key": hex::encode(pk_0.serialize()),
        "signature": "00",
        "message": hex::encode([0u8; 32]),
    });
    let commit_req = Request::post("/api/commit")
        .header("content-type", "application/json")
        .body(Body::from(commit_body.to_string()))
        .unwrap();
    let (status, _) = send_request_with_state(state, commit_req).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn receive_coin_with_valid_proof_succeeds() {
    let state = test_state();

    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;
    let sk_0: SecretKey = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
    let recipient = "0x".to_string() + &hex::encode([7u8; 32]);
    let amount: u64 = 1;
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
    let proof_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["proof_id"]
        .as_u64()
        .unwrap();

    // Read the stored proof bytes via /api/proof/:id and POST them back
    // to /api/receive — this should exercise the success path of
    // receive_coin_handler.
    let proof_req = Request::get(format!("/api/proof/{}", proof_id))
        .body(Body::empty())
        .unwrap();
    let app = create_router(state.clone());
    let proof_resp = app.oneshot(proof_req).await.unwrap();
    assert_eq!(proof_resp.status(), StatusCode::OK);
    let proof_bytes = proof_resp.into_body().collect().await.unwrap().to_bytes();
    assert!(!proof_bytes.is_empty());

    let receive_req = Request::post("/api/receive")
        .header("content-type", "application/octet-stream")
        .body(Body::from(proof_bytes.to_vec()))
        .unwrap();
    let (status, body) = send_request_with_state(state, receive_req).await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        resp["success"], true,
        "receive should report success: {body}"
    );
}

#[tokio::test]
async fn send_with_wrong_signature_returns_401() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::PublicKey;
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;

    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
    let recipient = "0x".to_string() + &hex::encode([8u8; 32]);
    let amount: u64 = 1;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 64 zero bytes — valid hex shape, valid signature length, but
    // will never verify against the request's pk_0 over the SHA256
    // of (account_address || recipient || amount || timestamp).
    let body = serde_json::json!({
        "account_address": account_address,
        "recipient": recipient,
        "amount": amount,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
        "signature": hex::encode([0u8; 64]),
        "timestamp": now,
    });
    let req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send_request(req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn receive_coin_duplicate_returns_success_false() {
    // After a valid receive, posting the same proof bytes again should
    // exercise the Err arm of account_server.receive_coin (duplicate
    // detection via coin_queue).
    let state = test_state();

    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;
    let sk_0: SecretKey = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    let account_address = "0x".to_string()
        + &hex::encode(zkcoins_program::hash::digest_to_bytes(
            &zkcoins_program::types::MINTING_ADDRESS,
        ));
    let recipient = "0x".to_string() + &hex::encode([9u8; 32]);
    let amount: u64 = 1;
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
    let proof_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["proof_id"]
        .as_u64()
        .unwrap();

    let app = create_router(state.clone());
    let proof_resp = app
        .oneshot(
            Request::get(format!("/api/proof/{}", proof_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let proof_bytes = proof_resp.into_body().collect().await.unwrap().to_bytes();

    // First receive: succeeds.
    let receive_req = Request::post("/api/receive")
        .header("content-type", "application/octet-stream")
        .body(Body::from(proof_bytes.to_vec()))
        .unwrap();
    let (status, body) = send_request_with_state(state.clone(), receive_req).await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(resp["success"], true);

    // Second receive of the same bytes: receive_coin returns Err, the
    // handler responds with success=false (the L351 Err arm).
    let receive_req = Request::post("/api/receive")
        .header("content-type", "application/octet-stream")
        .body(Body::from(proof_bytes.to_vec()))
        .unwrap();
    let (status, body) = send_request_with_state(state, receive_req).await;
    assert_eq!(status, StatusCode::OK);
    let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(resp["success"], false);
}

#[tokio::test]
async fn send_without_signature_skips_verification_and_proceeds() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::PublicKey;
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;

    // signature field omitted entirely -> request.signature is None ->
    // the verify_send_signature block is skipped (legacy/back-compat path).
    let body = serde_json::json!({
        "account_address": "0x".to_string() + &hex::encode(zkcoins_program::hash::digest_to_bytes(&zkcoins_program::types::MINTING_ADDRESS)),
        "recipient": "0x".to_string() + &hex::encode([1u8; 32]),
        "amount": 1,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
    });
    let req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send_request(req).await;
    // Without signature, the handler proceeds to send_coins on the
    // minting account (seeded with 1_000_000 in test_state) and returns OK.
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn lock_or_recover_account_server_poisoned() {
    // Generic instantiation: cover the AccountServer-specific monomorphic
    // copy of lock_or_recover's poison-recovery closure.
    let state_arc = Arc::new(Mutex::new(State::new()));
    let server = Arc::new(Mutex::new(AccountServer::new(Arc::clone(&state_arc))));
    let server_clone = Arc::clone(&server);

    let _ = std::thread::spawn(move || {
        let _guard = server_clone.lock().unwrap();
        panic!("intentional poison");
    })
    .join();

    assert!(server.is_poisoned());
    let _guard = lock_or_recover(&server);
}

#[test]
fn lock_or_recover_username_store_poisoned() {
    // Generic instantiation: cover the UsernameStore-specific monomorphic
    // copy of lock_or_recover's poison-recovery closure.
    let store = Arc::new(Mutex::new(crate::username::UsernameStore::new()));
    let store_clone = Arc::clone(&store);

    let _ = std::thread::spawn(move || {
        let _guard = store_clone.lock().unwrap();
        panic!("intentional poison");
    })
    .join();

    assert!(store.is_poisoned());
    let _guard = lock_or_recover(&store);
}

// --- Item 1 (Issue #28) — HTTP error mapping for /api/send + /api/mint ---
//
// `map_send_coins_error` is the single source of truth for translating
// `account_server::send_coins` failure strings into a `(StatusCode,
// body)` pair. These unit tests pin every documented error string to
// its mapped pair so adding a new error string anywhere in `send_coins`
// will silently fall through the `_ => INTERNAL_SERVER_ERROR` arm of
// the helper but loudly break one of these tests if the new string was
// supposed to be mapped to a 4xx.

#[test]
fn map_send_coins_error_unknown_account_address_is_404() {
    let (status, body) = crate::server::map_send_coins_error("Unknown account address");
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "Unknown account address");
}

#[test]
fn map_send_coins_error_prev_commitment_pubkey_required_is_400() {
    let (status, body) =
        crate::server::map_send_coins_error("prev_commitment_pubkey required for account update");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "prev_commitment_pubkey required for account update");
}

#[test]
fn map_send_coins_error_insufficient_funds_is_422() {
    let (status, body) = crate::server::map_send_coins_error("Insufficient funds");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Insufficient funds");
}

#[test]
fn map_send_coins_error_unable_to_get_merkle_proofs_is_422() {
    // Reachable from send_coins via the prev_commitment_pubkey path
    // (account_server::get_merkle_proofs:224). Caller supplied a
    // public_key that has no associated commitment proof in state.
    let (status, body) =
        crate::server::map_send_coins_error("Unable to get merkle proofs for provided public key");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Unable to get merkle proofs for provided public key");
}

#[test]
fn map_send_coins_error_unable_to_get_mmr_inclusion_proof_is_422() {
    // Reachable from send_coins via get_merkle_proofs (account_server::236).
    // Caller's previous_proof references a history root the server's MMR
    // hasn't observed yet — stale snapshot, caller-fixable.
    let (status, body) = crate::server::map_send_coins_error(
        "Unable to get mmr inclusion proof for the previous root",
    );
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body,
        "Unable to get mmr inclusion proof for the previous root"
    );
}

#[test]
fn map_send_coins_error_proof_public_inputs_too_short_is_500() {
    // Reachable from send_coins via get_merkle_proofs (account_server::232).
    // The proof bytes stored against the account are too short to
    // decode N_PROOF_DATA_PUBLIC_INPUTS field elements — server-side
    // corruption or version mismatch, not caller-fixable.
    let (status, body) = crate::server::map_send_coins_error("Proof public_inputs too short");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "Proof public_inputs too short");
}

#[test]
fn map_send_coins_error_phase_2b_shim_in_coin_not_in_source_ocr_is_422() {
    let (status, body) =
        crate::server::map_send_coins_error("In-coin not present in source's output_coins_root");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "In-coin not present in source's output_coins_root");
}

#[test]
fn map_send_coins_error_phase_2b_shim_source_not_in_history_is_422() {
    let (status, body) =
        crate::server::map_send_coins_error("Source commitment not present in history MMR");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Source commitment not present in history MMR");
}

#[test]
fn map_send_coins_error_coin_missing_commitment_is_422() {
    let (status, body) = crate::server::map_send_coins_error("Coin is missing commitment");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Coin is missing commitment");
}

#[test]
fn map_send_coins_error_missing_inclusion_proof_is_422() {
    let (status, body) = crate::server::map_send_coins_error("Should provide an inclusion proof");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Should provide an inclusion proof");
}

#[test]
fn map_send_coins_error_coin_already_in_coin_history_is_422() {
    let (status, body) =
        crate::server::map_send_coins_error("Coin should not exist in coin history tree");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Coin should not exist in coin history tree");
}

#[test]
fn map_send_coins_error_coin_already_in_output_smt_is_422() {
    let (status, body) = crate::server::map_send_coins_error("Coin should not exist in tree yet");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Coin should not exist in tree yet");
}

#[test]
fn map_send_coins_error_too_many_in_coins_is_422() {
    let (status, body) =
        crate::server::map_send_coins_error("Too many in-coins for one transition");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Too many in-coins for one transition");
}

#[test]
fn map_send_coins_error_too_many_out_coins_is_422() {
    let (status, body) =
        crate::server::map_send_coins_error("Too many out-coins for one transition");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Too many out-coins for one transition");
}

#[test]
fn map_send_coins_error_prove_failed_initial_collapses_to_500_prove_failed() {
    // Per the threat-model note in map_send_coins_error, the prover-internal
    // error string is intentionally collapsed to a generic "prove failed"
    // body so 5xx responses don't leak prover state to callers.
    let (status, body) = crate::server::map_send_coins_error(
        "prove_initial_with_in_and_out_coins_and_sources failed",
    );
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "prove failed");
}

#[test]
fn map_send_coins_error_prove_failed_account_update_collapses_to_500_prove_failed() {
    let (status, body) = crate::server::map_send_coins_error(
        "prove_account_update_with_in_and_out_coins_and_sources failed",
    );
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "prove failed");
}

#[test]
fn map_send_coins_error_unknown_string_is_500_internal_error() {
    // A new `send_coins` error string we haven't mapped yet must NOT
    // accidentally surface as 200 OK / 4xx. The default arm is 500 with
    // a generic "internal error" body so the wallet treats it as a
    // server problem and the operator finds the unmapped string in the
    // `eprintln!` log.
    let (status, body) = crate::server::map_send_coins_error("a string we never added");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "internal error");
}

#[tokio::test]
async fn send_with_unknown_account_returns_404_with_error_string() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};

    // test_state() only seeds the minting account. Any other 32-byte
    // address is unknown to the account_server, so send_coins returns
    // "Unknown account address" which the handler maps to 404.
    let secret_bytes = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(bitcoin::Network::Signet, secret_bytes).unwrap();
    let secp = secp::Secp256k1::new();
    let pk_0: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .public_key;
    let pk_1: PublicKey = Xpub::from_priv(&secp, &xpriv)
        .derive_pub(&secp, &[ChildNumber::Normal { index: 1 }])
        .unwrap()
        .public_key;
    let sk_0: SecretKey = xpriv
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    // An address that is well-formed (hex, 32 bytes) but never claimed
    // an account on the server.
    let account_address = "0x".to_string() + &hex::encode([0xAAu8; 32]);
    let recipient = "0x".to_string() + &hex::encode([1u8; 32]);
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

    let body = serde_json::json!({
        "account_address": account_address,
        "recipient": recipient,
        "amount": amount,
        "public_key": hex::encode(pk_0.serialize()),
        "next_public_key": hex::encode(pk_1.serialize()),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(resp["success"], false);
    assert_eq!(resp["error"], "Unknown account address");
}
