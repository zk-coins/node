use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::account_node::{Account, AccountNode};
use crate::state::State;

/// Build a `PgPool` that points at nowhere — every query against it
/// fails fast with a connect error. Used by the server-handler test
/// suite below so the handlers' persistence-side `.await` lines run
/// the error branch (which mirrors the legacy file-IO best-effort
/// semantics: log + continue, never fail the response). The matching
/// happy-path tests for the upsert lines run against a real
/// Postgres 17 testcontainer in `db_tests.rs`, `account_node_tests.rs`,
/// `username_tests.rs`, and `runtime_tests.rs`.
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
/// The AccountNode is constructed with a real (mock) prover so that the
/// type system is satisfied, but we seed it with a minting account so that
/// balance / address queries work without needing the minting_secret.bin
/// flow.
fn test_state() -> AppState {
    let state = Arc::new(Mutex::new(State::new()));
    let mut account_node = AccountNode::new(Arc::clone(&state));

    // Seed a minting account with max balance (mirrors production setup)
    let mut minting_account = Account::new();
    minting_account.balance = 1_000_000;
    account_node.import_account(*zkcoins_program::types::MINTING_ADDRESS, minting_account);

    // Create a dummy minting ClientAccount from a deterministic key
    let minting_client = {
        let secret = include_bytes!("../minting_secret.bin");
        let private_key = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Signet, secret)
            .expect("Failed to create test private key");
        shared::ClientAccount::new(private_key)
    };

    AppState {
        account_node: Arc::new(Mutex::new(account_node)),
        proof_store: Arc::new(ProofStore::new("/tmp/zkcoins-test-proofs")),
        minting_account: Arc::new(Mutex::new(minting_client)),
        username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
        pool: dead_pool(),
        // Most tests don't exercise the readiness probe and so don't
        // care about Esplora — point at a guaranteed-unreachable URL
        // so an accidental call fails fast instead of hitting the real
        // mutinynet.com from CI. The three `/health/ready` tests below
        // override this slot with a `wiremock::MockServer` URL.
        esplora_config: Arc::new(crate::publisher::EsploraConfig {
            url: "http://127.0.0.1:1/api".to_string(),
            is_mainnet: false,
            network_name: "Mutinynet".to_string(),
            ws_url: None,
            track_tx_timeout: None,
        }),
    }
}

/// Variant of [`test_state`] that swaps the lazy `dead_pool` for a real
/// migrated Postgres pool. Used by the handful of happy-path tests
/// whose handler actually has to persist (e.g. `claim_username` —
/// hard-fails with 503 on DB error, unlike `send`/`mint`/`receive`
/// whose `db::upsert_account` calls are best-effort log-and-continue).
fn live_test_state(pool: Arc<sqlx::PgPool>) -> AppState {
    let mut state = test_state();
    state.pool = pool;
    state
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
    assert_eq!(json["service"], "zkcoins-node");
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
    // Mint is permanent MVP — `faucet` is hardcoded `true`, not cfg-derived.
    assert!(info.capabilities.faucet);
    // Usernames are permanent MVP — `usernames` is hardcoded `true`.
    assert!(info.capabilities.usernames);
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

#[tokio::test]
async fn claim_username_with_valid_signature() {
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    // The `claim_username_handler` hard-fails with 503 if persistence
    // fails — unlike the other handlers whose DB upserts are
    // log-and-continue. So this happy-path test cannot use the lazy
    // `dead_pool`; it boots a real Postgres 17 container, mirroring
    // the per-test isolation pattern from `db_tests::setup_pool` /
    // `username_tests::setup_pool` / `runtime_tests::setup_pool`.
    let pg_container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = pg_container
        .get_host()
        .await
        .expect("failed to get container host");
    let port = pg_container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to get container port");
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = Arc::new(
        crate::db::connect_and_migrate(&url)
            .await
            .expect("connect_and_migrate failed"),
    );

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

    // Import the address into the account_node so resolve_identifier can find it
    let state = live_test_state(pool);
    {
        let mut account_node = state.account_node.lock().unwrap();
        account_node.import_account(
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

/// Mixed-case input is normalised to lowercase **before** the
/// signature is hashed, so a wallet that signs over the normalised
/// form (`"alice"`) and sends the user-typed form (`"Alice"`) is
/// accepted and persisted under `"alice"`. Guards the case-mismatch
/// squat fix from PR #76's prod-readiness review.
#[tokio::test]
async fn claim_username_mixed_case_input_normalised_before_hashing() {
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    let pg_container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = pg_container
        .get_host()
        .await
        .expect("failed to get container host");
    let port = pg_container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to get container port");
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = Arc::new(
        crate::db::connect_and_migrate(&url)
            .await
            .expect("connect_and_migrate failed"),
    );

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[9u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let user_input = "Alice";
    let normalised = "alice";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign over the NORMALISED form — that is the contract the server
    // enforces by canonicalising before hashing.
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(normalised.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let state = live_test_state(pool);
    {
        let mut account_node = state.account_node.lock().unwrap();
        account_node.import_account(
            zkcoins_program::hash::digest_from_bytes(&address),
            Account::new(),
        );
    }

    // Send the mixed-case form. The server normalises, hashes over
    // the lowercase form, and the signature verifies.
    let body = serde_json::json!({
        "username": user_input,
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
        "claim should succeed: {}",
        resp_body
    );
    let resp: UsernameResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    // Response echoes the canonical lowercase name, NOT the raw input.
    assert_eq!(resp.username, normalised);
}

/// Counterpart to the test above: a wallet that signs over the RAW
/// mixed-case input (legacy/buggy behaviour) must be rejected by the
/// server, because the server hashes the normalised form. Without
/// this, the case-mismatch squat is reachable: attacker signs `"Bob"`,
/// server persists `"bob"`, the legitimate `bob` owner is locked out.
#[tokio::test]
async fn claim_username_raw_case_signature_rejected() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[10u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let user_input = "Bob";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign over the RAW form — the bug we are fixing.
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(user_input.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let state = test_state();
    {
        let mut account_node = state.account_node.lock().unwrap();
        account_node.import_account(
            zkcoins_program::hash::digest_from_bytes(&address),
            Account::new(),
        );
    }

    let body = serde_json::json!({
        "username": user_input,
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, _resp_body) = send_request_with_state(state, req).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "raw-case signature must fail; server hashes normalised form"
    );
}

/// In-memory `precheck` collision must surface as `409 CONFLICT` with
/// the verbatim collision string the wallet shows the user. Drives the
/// claim handler's precheck `Err` branch without any DB round-trip:
/// the in-memory mirror is pre-seeded via `insert_for_test`, the
/// signature is valid, and the handler short-circuits before the
/// `db::claim_username` call.
#[tokio::test]
async fn claim_username_precheck_conflict_returns_409() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[11u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let username = "claimed";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let state = test_state();
    {
        let mut account_node = state.account_node.lock().unwrap();
        account_node.import_account(
            zkcoins_program::hash::digest_from_bytes(&address),
            Account::new(),
        );
    }
    // Pre-seed the name → arbitrary OTHER address so the precheck's
    // `usernames.contains_key(normalized)` branch fires (rather than
    // the address-already-has-a-username branch).
    {
        let mut store = state.username_store.lock().unwrap();
        store.insert_for_test(
            username,
            zkcoins_program::hash::digest_from_bytes(&[99u8; 32]),
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

    assert_eq!(status, StatusCode::CONFLICT, "body: {}", resp_body);
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert!(
        resp.reason.contains("Username already taken"),
        "unexpected reason: {}",
        resp.reason
    );
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

/// `UsernameStore::validate` rejects names outside `[a-z0-9._-]{1,64}`.
/// Drives the handler's first early-return arm (the `validate` `Err`
/// branch), so no DB round-trip and no signature work is needed.
#[tokio::test]
async fn claim_username_invalid_format_returns_422() {
    let body = serde_json::json!({
        "username": "alice@evil",
        "address": hex::encode([0u8; 32]),
        "public_key": bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp::Secp256k1::new(),
            &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        )
        .to_string(),
        "signature": hex::encode([0u8; 64]),
        "timestamp": 0u64,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {resp_body}"
    );
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Username may only contain a-z, 0-9, -, _, .");
}

/// Non-hex address payload triggers the `hex::decode` early-return arm.
#[tokio::test]
async fn claim_username_invalid_address_hex_returns_422() {
    let body = serde_json::json!({
        "username": "alice",
        "address": "z".repeat(64),
        "public_key": bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp::Secp256k1::new(),
            &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        )
        .to_string(),
        "signature": hex::encode([0u8; 64]),
        "timestamp": 0u64,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {resp_body}"
    );
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Invalid address hex");
}

/// Valid hex address but not 32 bytes triggers the length-check arm.
#[tokio::test]
async fn claim_username_wrong_address_length_returns_422() {
    let body = serde_json::json!({
        "username": "alice",
        "address": hex::encode([0u8; 30]),
        "public_key": bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp::Secp256k1::new(),
            &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        )
        .to_string(),
        "signature": hex::encode([0u8; 64]),
        "timestamp": 0u64,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {resp_body}"
    );
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Address must be 32 bytes");
}

/// Address matches `sha256(pubkey)` and the timestamp is fresh, so the
/// handler reaches the signature-hex decode step before bailing on the
/// non-hex `signature` field.
#[tokio::test]
async fn claim_username_invalid_signature_hex_returns_422() {
    use bitcoin::secp256k1::SecretKey;

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[12u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let body = serde_json::json!({
        "username": "sighex",
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": "zz",
        "timestamp": now,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {resp_body}"
    );
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Invalid signature hex");
}

/// Signature is valid hex but the wrong length for a BIP-340 Schnorr
/// signature (64 bytes), so `SchnorrSignature::from_slice` rejects it.
#[tokio::test]
async fn claim_username_invalid_signature_format_returns_422() {
    use bitcoin::secp256k1::SecretKey;

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[13u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 63 bytes of zeros — valid hex, wrong Schnorr length.
    let body = serde_json::json!({
        "username": "sigfmt",
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode([0u8; 63]),
        "timestamp": now,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {resp_body}"
    );
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Invalid signature format");
}

/// Pool with no reachable server: `db::claim_username` returns an error
/// after the in-memory `precheck` passes. The handler must map that
/// onto a 503. Mirrors `claim_propagates_db_error_when_pool_is_dead`
/// from `username_tests.rs`, but exercises the handler's error arm.
#[tokio::test]
async fn claim_username_db_error_returns_503() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[14u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let username = "dberr";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    // `test_state()` already plugs in `dead_pool` — a lazy PgPool
    // pointing at 127.0.0.1:1 that fails fast with a connect error.
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
    let (status, resp_body) = send_request(req).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {resp_body}");
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Failed to persist username claim");
}

/// Concurrent-claim SQL race: plant the row directly via SQL so the
/// in-memory `precheck` mirror stays empty (passes) but the
/// `INSERT ... ON CONFLICT DO NOTHING` reports `rows_affected == 0`.
/// The handler must map that onto a 409 with the SQL-race reason
/// string. Mirrors `claim_falls_back_to_validation_when_sql_layer_catches_race`
/// from `username_tests.rs`, but exercises the handler's `!inserted`
/// arm rather than the `UsernameStore::claim` wrapper.
#[tokio::test]
async fn claim_username_sql_race_returns_409() {
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    let pg_container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = pg_container
        .get_host()
        .await
        .expect("failed to get container host");
    let port = pg_container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to get container port");
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = Arc::new(
        crate::db::connect_and_migrate(&url)
            .await
            .expect("connect_and_migrate failed"),
    );

    // Plant the username row bound to a different address, without
    // touching the in-memory mirror — so `precheck` passes and
    // `db::claim_username` returns `Ok(false)`.
    sqlx::query("INSERT INTO usernames (name, address) VALUES ($1, $2)")
        .bind("racename")
        .bind(vec![0xAAu8; 32])
        .execute(pool.as_ref())
        .await
        .expect("failed to plant username row");

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[15u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let username = "racename";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let state = live_test_state(pool);

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

    assert_eq!(status, StatusCode::CONFLICT, "body: {resp_body}");
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Username already taken");
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

/// Companion to `send_with_valid_signature_returns_proof_id_and_hashes`
/// that drives the post-send `db::upsert_account` path against a real
/// Postgres 17 testcontainer instead of `dead_pool`. The default
/// `test_state` exercises the upsert *error* arm (log-and-continue);
/// this test exercises the upsert *success* arm so the if-let-Some
/// block falls through without entering the `if let Err` branch —
/// the only path that touches the line after the inner Err handler.
///
/// The persist itself is best-effort, so the assertions are scoped
/// to (a) the handler still returning 200 with a usable proof_id and
/// (b) the `accounts` row being readable from Postgres after the
/// call. Together they pin both observable side-effects of the
/// happy-path upsert.
#[tokio::test]
async fn send_with_valid_signature_persists_sender_account_to_postgres() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    let pg_container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = pg_container
        .get_host()
        .await
        .expect("failed to get container host");
    let port = pg_container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to get container port");
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = Arc::new(
        crate::db::connect_and_migrate(&url)
            .await
            .expect("connect_and_migrate failed"),
    );

    let state = live_test_state(Arc::clone(&pool));

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

    let req = Request::post("/api/send")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;
    assert_eq!(status, StatusCode::OK, "body: {resp_body}");
    let response_json: serde_json::Value =
        serde_json::from_str(&resp_body).expect("response is valid JSON");
    assert_eq!(response_json["success"], true);
    assert!(response_json["proof_id"].as_u64().is_some());

    // The post-send upsert must have written the sender (minting)
    // account row. Confirm it via a direct SELECT so the assertion
    // doesn't depend on the handler's own read path.
    let from_address_bytes =
        zkcoins_program::hash::digest_to_bytes(&zkcoins_program::types::MINTING_ADDRESS);
    let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT data FROM accounts WHERE address = $1")
        .bind(&from_address_bytes[..])
        .fetch_optional(&*pool)
        .await
        .expect("select accounts row");
    let (data,) = row.expect("upsert wrote the sender account row");
    assert!(!data.is_empty(), "account blob must be non-empty");
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
    let mut account_node = AccountNode::new(Arc::clone(&state_arc));
    let mut empty_minting = Account::new();
    empty_minting.balance = 0;
    account_node.import_account(*zkcoins_program::types::MINTING_ADDRESS, empty_minting);
    let minting_client = {
        let secret = include_bytes!("../minting_secret.bin");
        let private_key = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Signet, secret)
            .expect("test minting xpriv");
        shared::ClientAccount::new(private_key)
    };
    let state = AppState {
        account_node: Arc::new(Mutex::new(account_node)),
        proof_store: Arc::new(ProofStore::new("/tmp/zkcoins-test-proofs-empty")),
        minting_account: Arc::new(Mutex::new(minting_client)),
        username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
        pool: dead_pool(),
        esplora_config: Arc::new(crate::publisher::EsploraConfig {
            url: "http://127.0.0.1:1/api".to_string(),
            is_mainnet: false,
            network_name: "Mutinynet".to_string(),
            ws_url: None,
            track_tx_timeout: None,
        }),
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
    // Exercising it covers the `if let Err(e) = ...` arm in router.rs
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
    // exercise the Err arm of account_node.receive_coin (duplicate
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
fn lock_or_recover_account_node_poisoned() {
    // Generic instantiation: cover the AccountNode-specific monomorphic
    // copy of lock_or_recover's poison-recovery closure.
    let state_arc = Arc::new(Mutex::new(State::new()));
    let server = Arc::new(Mutex::new(AccountNode::new(Arc::clone(&state_arc))));
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
// `account_node::send_coins` failure strings into a `(StatusCode,
// body)` pair. These unit tests pin every documented error string to
// its mapped pair so adding a new error string anywhere in `send_coins`
// will silently fall through the `_ => INTERNAL_SERVER_ERROR` arm of
// the helper but loudly break one of these tests if the new string was
// supposed to be mapped to a 4xx.

#[test]
fn map_send_coins_error_unknown_account_address_is_404() {
    let (status, body) = crate::router::map_send_coins_error("Unknown account address");
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "Unknown account address");
}

#[test]
fn map_send_coins_error_prev_commitment_pubkey_required_is_400() {
    let (status, body) =
        crate::router::map_send_coins_error("prev_commitment_pubkey required for account update");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "prev_commitment_pubkey required for account update");
}

#[test]
fn map_send_coins_error_insufficient_funds_is_422() {
    let (status, body) = crate::router::map_send_coins_error("Insufficient funds");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Insufficient funds");
}

#[test]
fn map_send_coins_error_unable_to_get_merkle_proofs_is_422() {
    // Reachable from send_coins via the prev_commitment_pubkey path
    // (account_node::get_merkle_proofs:224). Caller supplied a
    // public_key that has no associated commitment proof in state.
    let (status, body) =
        crate::router::map_send_coins_error("Unable to get merkle proofs for provided public key");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Unable to get merkle proofs for provided public key");
}

#[test]
fn map_send_coins_error_unable_to_get_mmr_inclusion_proof_is_422() {
    // Reachable from send_coins via get_merkle_proofs (account_node::236).
    // Caller's previous_proof references a history root the server's MMR
    // hasn't observed yet — stale snapshot, caller-fixable.
    let (status, body) = crate::router::map_send_coins_error(
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
    // Reachable from send_coins via get_merkle_proofs (account_node::232).
    // The proof bytes stored against the account are too short to
    // decode N_PROOF_DATA_PUBLIC_INPUTS field elements — server-side
    // corruption or version mismatch, not caller-fixable.
    let (status, body) = crate::router::map_send_coins_error("Proof public_inputs too short");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "Proof public_inputs too short");
}

#[test]
fn map_send_coins_error_phase_2b_shim_in_coin_not_in_source_ocr_is_422() {
    let (status, body) =
        crate::router::map_send_coins_error("In-coin not present in source's output_coins_root");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "In-coin not present in source's output_coins_root");
}

#[test]
fn map_send_coins_error_phase_2b_shim_source_not_in_history_is_422() {
    let (status, body) =
        crate::router::map_send_coins_error("Source commitment not present in history MMR");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Source commitment not present in history MMR");
}

#[test]
fn map_send_coins_error_coin_missing_commitment_is_422() {
    let (status, body) = crate::router::map_send_coins_error("Coin is missing commitment");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Coin is missing commitment");
}

#[test]
fn map_send_coins_error_missing_inclusion_proof_is_422() {
    let (status, body) = crate::router::map_send_coins_error("Should provide an inclusion proof");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Should provide an inclusion proof");
}

#[test]
fn map_send_coins_error_coin_already_in_coin_history_is_422() {
    let (status, body) =
        crate::router::map_send_coins_error("Coin should not exist in coin history tree");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Coin should not exist in coin history tree");
}

#[test]
fn map_send_coins_error_coin_already_in_output_smt_is_422() {
    let (status, body) = crate::router::map_send_coins_error("Coin should not exist in tree yet");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Coin should not exist in tree yet");
}

#[test]
fn map_send_coins_error_too_many_in_coins_is_422() {
    let (status, body) =
        crate::router::map_send_coins_error("Too many in-coins for one transition");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Too many in-coins for one transition");
}

#[test]
fn map_send_coins_error_too_many_out_coins_is_422() {
    let (status, body) =
        crate::router::map_send_coins_error("Too many out-coins for one transition");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, "Too many out-coins for one transition");
}

#[test]
fn map_send_coins_error_prove_failed_initial_collapses_to_500_prove_failed() {
    // Per the threat-model note in map_send_coins_error, the prover-internal
    // error string is intentionally collapsed to a generic "prove failed"
    // body so 5xx responses don't leak prover state to callers.
    let (status, body) = crate::router::map_send_coins_error(
        "prove_initial_with_in_and_out_coins_and_sources failed",
    );
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "prove failed");
}

#[test]
fn map_send_coins_error_prove_failed_account_update_collapses_to_500_prove_failed() {
    let (status, body) = crate::router::map_send_coins_error(
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
    let (status, body) = crate::router::map_send_coins_error("a string we never added");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, "internal error");
}

#[tokio::test]
async fn send_with_unknown_account_returns_404_with_error_string() {
    use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
    use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};

    // test_state() only seeds the minting account. Any other 32-byte
    // address is unknown to the account_node, so send_coins returns
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

// =======================================================================
// GET /health/ready — readiness probe
// =======================================================================
//
// The readiness probe combines a Postgres `SELECT 1` with an Esplora
// `/blocks/tip/height` ping. Each test below exercises one of the three
// reachable code paths (db ok + esplora ok / db fail + esplora ok / db
// ok + esplora fail) so the new `ready_handler` and `check_esplora`
// functions reach 100% line + region coverage. The DB side uses the
// existing `dead_pool` / live-testcontainer helpers; the Esplora side
// uses a per-test `wiremock::MockServer` so no real network is hit.

/// Spin up a Postgres 17 testcontainer and return a migrated pool —
/// the live half of the readiness happy path (and the db-ok side of
/// the esplora-fails test).
async fn ready_live_pool() -> (
    Arc<sqlx::PgPool>,
    testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>,
) {
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    let pg_container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = pg_container
        .get_host()
        .await
        .expect("failed to get container host");
    let port = pg_container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to get container port");
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = Arc::new(
        crate::db::connect_and_migrate(&url)
            .await
            .expect("connect_and_migrate failed"),
    );
    // The container handle MUST outlive the pool: `testcontainers`
    // tears the container down on `Drop`, which would close the
    // backing Postgres before the test finishes querying.
    (pool, pg_container)
}

/// Build an `AppState` whose `esplora_config` points at the supplied
/// `wiremock` URL. The DB pool is supplied separately so tests can
/// mix-and-match dead vs. live Postgres.
fn ready_state(pool: Arc<sqlx::PgPool>, esplora_url: String) -> AppState {
    let mut state = test_state();
    state.pool = pool;
    state.esplora_config = Arc::new(crate::publisher::EsploraConfig {
        url: esplora_url,
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
        track_tx_timeout: None,
    });
    state
}

#[tokio::test]
async fn ready_returns_200_when_db_and_esplora_reachable() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let (pool, _pg) = ready_live_pool().await;
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("123456"))
        .mount(&mock_server)
        .await;

    let state = ready_state(pool, mock_server.uri());
    let req = Request::get("/health/ready").body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::OK, "body={}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["ready"], true);
    assert_eq!(v["failures"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn ready_returns_503_when_db_unreachable() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Esplora is healthy …
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("123456"))
        .mount(&mock_server)
        .await;

    // … but Postgres is the lazy-connect dead pool, which fails on first
    // query with a connect error. `ready_handler` must surface that as
    // 503 + `failures: ["db"]`.
    let state = ready_state(dead_pool(), mock_server.uri());
    let req = Request::get("/health/ready").body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["ready"], false);
    let failures: Vec<String> = v["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert_eq!(failures, vec!["db".to_string()]);
}

#[tokio::test]
async fn ready_returns_503_when_esplora_unreachable() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let (pool, _pg) = ready_live_pool().await;

    // Live Postgres + Esplora returning 500 → only `esplora` fails.
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream down"))
        .mount(&mock_server)
        .await;

    let state = ready_state(pool, mock_server.uri());
    let req = Request::get("/health/ready").body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["ready"], false);
    let failures: Vec<String> = v["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert_eq!(failures, vec!["esplora".to_string()]);
}

// =======================================================================
// POST /api/mint — handler coverage
// =======================================================================
//
// Before #480300b the mint endpoint was gated behind the `faucet` Cargo
// feature, so `mint_handler` was excluded from the MVP-scope coverage
// gate. After the gate removal (mint is now permanent MVP) every line
// of the handler counts toward `--fail-under-lines 100 --fail-under-
// functions 100`. The tests below cover each reachable arm:
//
// - request validation (422 invalid hex / 422 wrong length)
// - bootstrap failure (500 missing minting account)
// - `send_coins` failure mapping (422 via the slot-count guard, which
//   fires before the prover so the test is cheap)
// - the post-`send_coins` Ok arm: num_pubkeys increment, ProofData
//   reconstruction, commitment build, `db::upsert_minting_num_pubkeys`,
//   and the inscription broadcast.
//
// The happy-path tests run the real prover; one mint takes ~seconds on
// the M3-Ultra runner but compiles cheaply, so they stay in the unit-
// test suite rather than moving to `tests/`.

/// Build an `AppState` configured for mint tests: minting account
/// seeded with `1u64 << 48` (Goldilocks-safe — see `runtime
/// ::start_rest_node`'s bootstrap comment), real prover wired
/// through the default `AccountNode`, dead Postgres pool by default
/// (callers swap it for a live pool via the second return value).
fn mint_test_state() -> AppState {
    let state_inner = Arc::new(Mutex::new(State::new()));
    let mut account_node = AccountNode::new(Arc::clone(&state_inner));

    // The Plonky2 state-transition circuit packs the running balance
    // as `balance_hi * 2^32 + balance_lo`; keeping the seed below 2^48
    // matches the production bootstrap in `start_rest_node`.
    let mut minting_account = Account::new();
    minting_account.balance = 1u64 << 48;
    account_node.import_account(*zkcoins_program::types::MINTING_ADDRESS, minting_account);

    // Mirror the production bootstrap: the wallet's address is forced
    // to the canonical `MINTING_ADDRESS` constant, regardless of what
    // `ClientAccount::new` would otherwise derive from the secret.
    let minting_client = {
        let secret = include_bytes!("../minting_secret.bin");
        let private_key = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Signet, secret)
            .expect("Failed to create test private key");
        let mut c = shared::ClientAccount::new(private_key);
        c.address = *zkcoins_program::types::MINTING_ADDRESS;
        c
    };

    AppState {
        account_node: Arc::new(Mutex::new(account_node)),
        proof_store: Arc::new(ProofStore::new("/tmp/zkcoins-mint-test-proofs")),
        minting_account: Arc::new(Mutex::new(minting_client)),
        username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
        pool: dead_pool(),
        esplora_config: Arc::new(crate::publisher::EsploraConfig {
            url: "http://127.0.0.1:1/api".to_string(),
            is_mainnet: false,
            network_name: "Mutinynet".to_string(),
            ws_url: None,
            track_tx_timeout: None,
        }),
    }
}

/// Variant of [`mint_test_state`] that DROPS the minting account so
/// `get_minting_account_address` returns Err — drives the 500
/// "Minting account not configured" arm in `mint_handler`.
fn mint_test_state_without_minting_account() -> AppState {
    let state = mint_test_state();
    {
        let mut server = state.account_node.lock().unwrap();
        // Reset to a brand-new server with no accounts at all. The
        // `Arc<Mutex<State>>` inside `server` is replaced too, but the
        // shared `state_inner` is dropped on overwrite which is fine
        // — nothing else holds it after `mint_test_state` returns.
        *server = AccountNode::new(Arc::new(Mutex::new(State::new())));
    }
    state
}

#[tokio::test]
async fn mint_invalid_hex_address_returns_422() {
    let body = serde_json::json!({
        "account_address": "not_hex",
        "amount": 100u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(mint_test_state(), req).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let v: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(v["success"], false);
    assert_eq!(v["error"], "account_address is not valid hex");
}

#[tokio::test]
async fn mint_wrong_address_length_returns_422() {
    // 16 bytes of hex (32 chars) — well-formed hex but not 32 bytes,
    // so the length check fires.
    let body = serde_json::json!({
        "account_address": "0x".to_string() + &"ab".repeat(16),
        "amount": 100u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(mint_test_state(), req).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let v: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(v["success"], false);
    assert_eq!(
        v["error"],
        "account_address must be 32 bytes (64 hex chars)"
    );
}

#[tokio::test]
async fn mint_without_minting_account_returns_500() {
    let body = serde_json::json!({
        "account_address": "0x".to_string() + &hex::encode([1u8; 32]),
        "amount": 100u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) =
        send_request_with_state(mint_test_state_without_minting_account(), req).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let v: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(v["success"], false);
    assert_eq!(v["error"], "Minting account not configured");
}

#[tokio::test]
async fn mint_insufficient_funds_returns_422() {
    // Replace the minting account's balance with zero so `send_coins`
    // bails out on the balance check (Err arm of `mint_handler`'s
    // outer match) before paying the prover cost. Maps to 422 via
    // `send_coins_error_response`.
    let state = mint_test_state();
    {
        let mut server = state.account_node.lock().unwrap();
        // Re-import the minting account with balance=0. The previous
        // import is overwritten by HashMap semantics inside
        // `import_account`.
        let mut empty = Account::new();
        empty.balance = 0;
        server.import_account(*zkcoins_program::types::MINTING_ADDRESS, empty);
    }

    let body = serde_json::json!({
        "account_address": "0x".to_string() + &hex::encode([1u8; 32]),
        "amount": 100u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let v: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(v["success"], false);
    assert_eq!(v["error"], "Insufficient funds");
}

/// Drives `mint_handler` through the prepare-then-broadcast phases:
/// `prepare_mint` runs the full prover, builds the commitment, then
/// the inscription broadcast fails against the default unreachable
/// `esplora_config` (127.0.0.1:1) and the handler returns 503.
///
/// **zk-coins/node#89 regression guard.** The asserts below pin the
/// no-state-advance contract that the prepare-then-commit refactor
/// introduced: after a broadcast failure the in-memory
/// `minting_account.num_pubkeys` MUST still be 0, the minting
/// `Account` in the server's map MUST still have an empty
/// `coin_queue`, `proof = None`, and the unchanged seed balance, and
/// the recipient account MUST NOT exist yet. Before this PR the
/// handler had already bumped the counter + mutated the minting
/// `Account` + (in the soft-fail DEV flavour) returned 200 — see the
/// issue text for the production manifestation.
#[tokio::test]
async fn mint_broadcast_failure_returns_503() {
    let state = mint_test_state();
    let recipient_bytes = [7u8; 32];
    let recipient_addr = zkcoins_program::hash::digest_from_bytes(&recipient_bytes);

    // Snapshot the pre-mint minting Account so we can prove the
    // failed-broadcast path leaves it byte-identical.
    let minting_balance_before: u64;
    let minting_coin_queue_len_before: usize;
    let minting_proof_some_before: bool;
    {
        let server_guard = state.account_node.lock().unwrap();
        let acct = server_guard
            .get_account(&zkcoins_program::types::MINTING_ADDRESS)
            .expect("minting account seeded by mint_test_state");
        minting_balance_before = acct.balance;
        minting_coin_queue_len_before = acct.coin_queue.len();
        minting_proof_some_before = acct.proof.is_some();
    }
    let num_pubkeys_before = state.minting_account.lock().unwrap().num_pubkeys;
    assert_eq!(
        num_pubkeys_before, 0,
        "fresh mint_test_state starts with num_pubkeys=0"
    );

    let recipient = "0x".to_string() + &hex::encode(recipient_bytes);
    let body = serde_json::json!({
        "account_address": recipient,
        "amount": 1u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state.clone(), req).await;

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "body: {}",
        resp_body
    );
    let v: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(v["success"], false);
    assert_eq!(v["error"], "Failed to broadcast mint inscription on-chain");

    // No-state-advance asserts: every persistent + in-memory side of
    // the mint flow must look exactly as it did before the request.
    let num_pubkeys_after = state.minting_account.lock().unwrap().num_pubkeys;
    assert_eq!(
        num_pubkeys_after, 0,
        "in-memory minting_account.num_pubkeys must NOT advance on broadcast failure (zk-coins/node#89)"
    );
    {
        let server_guard = state.account_node.lock().unwrap();
        let acct_after = server_guard
            .get_account(&zkcoins_program::types::MINTING_ADDRESS)
            .expect("minting account still present after failed mint");
        assert_eq!(
            acct_after.balance, minting_balance_before,
            "minting Account balance must NOT change on broadcast failure"
        );
        assert_eq!(
            acct_after.coin_queue.len(),
            minting_coin_queue_len_before,
            "minting Account coin_queue must NOT change on broadcast failure"
        );
        assert_eq!(
            acct_after.proof.is_some(),
            minting_proof_some_before,
            "minting Account proof must NOT be set by a failed-broadcast mint"
        );
        assert!(
            server_guard.get_account(&recipient_addr).is_none(),
            "recipient account must NOT be created when broadcast fails"
        );
    }
}

/// Companion to `mint_broadcast_failure_returns_503` that drives the
/// inscription broadcast through a wiremock Esplora that ACCEPTS the
/// commit + reveal POSTs, so `mint_handler` falls through into the
/// post-broadcast section: `receive_coin` loop, account-snapshot
/// builder, per-account `db::upsert_account` log-and-continue loop,
/// and the `coin_proofs.pop().expect(...)` value-extraction returning
/// 200 with a usable `proof_id`.
///
/// Uses a live Postgres testcontainer so the `upsert_minting_num_pubkeys`
/// + `upsert_account` calls hit the Ok arm of the persistence helpers
/// (rather than the dead-pool Err arm, which the broadcast-failure test
/// above covers). Together the two tests pin every line of the
/// mint_handler Ok branch.
#[tokio::test]
async fn mint_happy_path_broadcasts_and_returns_proof_id() {
    use bitcoin::Network;
    use bitcoin::{
        key::Secp256k1,
        secp256k1::{Keypair, SecretKey},
        XOnlyPublicKey,
    };
    use std::str::FromStr;
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // 1. Spin up a real Postgres so the upsert helpers run their Ok
    //    arms (the dead-pool test above already covers the Err arms).
    let pg_container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = pg_container.get_host().await.unwrap();
    let port = pg_container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = Arc::new(
        crate::db::connect_and_migrate(&url)
            .await
            .expect("connect_and_migrate failed"),
    );

    // 2. Spin up wiremock and answer the publisher's UTXO + broadcast
    //    requests. The publisher key in unit tests is the default
    //    `DEFAULT_PUBLISHER_KEY` from lib.rs (PUBLISHER_KEY env var
    //    unset in CI) — derive the matching Taproot address so the
    //    `/address/<addr>/utxo` mock matches.
    let mock_server = MockServer::start().await;
    let secp = Secp256k1::new();
    let sk =
        SecretKey::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            .expect("default publisher key parses");
    let key_pair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&key_pair);
    let publisher_address = bitcoin::Address::p2tr(&secp, xonly, None, Network::Signet);

    // 100_000 sats covers the commit + reveal fees (mirrors the
    // publisher_tests::create_and_broadcast_inscription_succeeds_end_to_end
    // setup).
    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "txid": "3333333333333333333333333333333333333333333333333333333333333333",
                "vout": 0,
                "value": 100_000,
                "status": {
                    "confirmed": true,
                    "block_height": 100,
                    "block_hash": "0000000000000000000000000000000000000000000000000000000000000001",
                    "block_time": 1_700_000_000
                }
            }
        ])))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock_server)
        .await;

    // 3. Wire the AppState to the live pool + wiremock URL.
    let ws_url = mint_broadcast_mock_ws().await;
    let mut state = mint_test_state();
    state.pool = Arc::clone(&pool);
    state.esplora_config = Arc::new(crate::publisher::EsploraConfig {
        url: mock_server.uri(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: Some(ws_url),
        track_tx_timeout: None,
    });

    let recipient_bytes = [9u8; 32];
    let recipient_hex = "0x".to_string() + &hex::encode(recipient_bytes);
    let body = serde_json::json!({
        "account_address": recipient_hex,
        "amount": 1u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::OK, "body: {}", resp_body);
    let v: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(v["success"], true);
    assert!(
        v["proof_id"].as_u64().is_some(),
        "proof_id missing from response: {}",
        resp_body
    );
    // Per the mint_handler contract, the mint response intentionally
    // omits `account_state_hash` and `output_coins_root` (those are
    // returned by /api/send instead).
    assert!(v["account_state_hash"].is_null());
    assert!(v["output_coins_root"].is_null());

    // 4. Verify the persistence side-effects of the Ok arm: the
    //    accounts row for the MINTING address was upserted, and the
    //    minting_meta.num_pubkeys counter was bumped from 0 to 1.
    let minting_addr_bytes =
        zkcoins_program::hash::digest_to_bytes(&zkcoins_program::types::MINTING_ADDRESS);
    let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT data FROM accounts WHERE address = $1")
        .bind(&minting_addr_bytes[..])
        .fetch_optional(&*pool)
        .await
        .expect("select minting accounts row");
    let (data,) = row.expect("upsert wrote the minting account row");
    assert!(!data.is_empty(), "minting account blob must be non-empty");

    let minting_num: Option<u32> = crate::db::load_minting_num_pubkeys(&pool)
        .await
        .expect("load_minting_num_pubkeys ok");
    assert_eq!(
        minting_num,
        Some(1),
        "num_pubkeys must be bumped to 1 after a successful mint"
    );
}

/// Covers the `current_num_pubkeys > 0` arm of the
/// `prev_commitment_pubkey` derivation at the top of `mint_handler`.
/// The default mint state has `num_pubkeys = 0`, so the
/// `mint_broadcast_failure_returns_503` / happy-path tests above hit
/// the `None` arm of that `if`. Pre-bumping `num_pubkeys` to `1` here
/// drives the `Some(prev_pk)` arm — `account.proof` is still `None`
/// (no prior mint has actually run on this AppState), so the
/// downstream `send_coins` stays on the initial-prove path and the
/// handler reaches the broadcast call. The broadcast then fails
/// against the default unreachable Esplora URL and the handler
/// returns 503, but the key-generation arm we wanted is already
/// covered by that point.
#[tokio::test]
async fn mint_with_nonzero_num_pubkeys_covers_prev_pubkey_arm() {
    let state = mint_test_state();
    {
        let mut mc = state.minting_account.lock().unwrap();
        mc.num_pubkeys = 1;
    }

    let recipient = "0x".to_string() + &hex::encode([5u8; 32]);
    let body = serde_json::json!({
        "account_address": recipient,
        "amount": 1u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "body: {}",
        resp_body
    );
}

/// Spin up the wiremock Esplora + matching publisher Taproot UTXO mock
/// used by the mint happy-path test. Returned `MockServer` is kept
/// alive by the caller; dropping it tears down the HTTP listener.
/// Spin up an in-process WS server that emulates the mempool.space
/// `track-tx` flow used by `publisher::broadcast_inscription_txs`
/// (issue #84): accept the subscribe frame and echo a documented
/// `txPosition` event for the txid the client subscribed to, so
/// the publisher's `wait_for_tx_in_mempool` resolves immediately.
/// Returns the `ws://` URL.
async fn mint_broadcast_mock_ws() -> String {
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut ws = match tokio_tungstenite::accept_async(stream).await {
                Ok(w) => w,
                Err(_) => continue,
            };
            let first = match ws.next().await {
                Some(Ok(WsMessage::Text(t))) => t,
                _ => continue,
            };
            let value: serde_json::Value = match serde_json::from_str(&first) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if value.get("action") == Some(&serde_json::json!("track-tx")) {
                if let Some(txid_str) = value.get("data").and_then(|v| v.as_str()) {
                    // Documented mempool.space `txPosition` shape;
                    // see `scanner_ws::frame_signals_tx_seen`.
                    let frame = format!(
                        r#"{{"txPosition":{{"txid":"{}","position":{{"block":1,"vsize":120}}}}}}"#,
                        txid_str
                    );
                    let _ = ws.send(WsMessage::Text(frame)).await;
                }
            }
            let _ = tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
    url
}

async fn mint_broadcast_mock_server() -> wiremock::MockServer {
    use bitcoin::Network;
    use bitcoin::{
        key::Secp256k1,
        secp256k1::{Keypair, SecretKey},
        XOnlyPublicKey,
    };
    use std::str::FromStr;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let secp = Secp256k1::new();
    let sk =
        SecretKey::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            .expect("default publisher key parses");
    let key_pair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&key_pair);
    let publisher_address = bitcoin::Address::p2tr(&secp, xonly, None, Network::Signet);

    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "txid": "3333333333333333333333333333333333333333333333333333333333333333",
                "vout": 0,
                "value": 100_000,
                "status": {
                    "confirmed": true,
                    "block_height": 100,
                    "block_hash": "0000000000000000000000000000000000000000000000000000000000000001",
                    "block_time": 1_700_000_000
                }
            }
        ])))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock_server)
        .await;

    mock_server
}

/// Drives the Err arm of the post-broadcast `db::commit_mint_tx` call
/// at the tail of `mint_handler`. The broadcast goes through (wiremock
/// answers the UTXO + tx POSTs), the handler walks past the early
/// 503 broadcast-failure branch into the commit-tx phase. The pool is
/// the lazy `dead_pool` that connect-errors on first use, so the
/// transaction fails to begin and the handler returns
/// `503 SERVICE_UNAVAILABLE` "Failed to persist mint commit
/// transaction". The in-memory state was guarded by the same commit
/// path, so per zk-coins/node#89 `num_pubkeys` MUST still be 0
/// after the failed commit.
#[tokio::test]
async fn mint_commit_tx_failure_returns_503() {
    let mock_server = mint_broadcast_mock_server().await;
    let ws_url = mint_broadcast_mock_ws().await;

    let mut state = mint_test_state();
    // dead_pool stays in place from mint_test_state; only swap the
    // Esplora URL so the broadcast succeeds.
    state.esplora_config = Arc::new(crate::publisher::EsploraConfig {
        url: mock_server.uri(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: Some(ws_url),
        track_tx_timeout: None,
    });
    let minting_account = Arc::clone(&state.minting_account);
    let account_node = Arc::clone(&state.account_node);

    let recipient = "0x".to_string() + &hex::encode([4u8; 32]);
    let body = serde_json::json!({
        "account_address": recipient,
        "amount": 1u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "body: {}",
        resp_body
    );
    let v: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(v["success"], false);
    assert_eq!(v["error"], "Failed to persist mint commit transaction");

    // No in-memory advance — the commit fence held.
    assert_eq!(minting_account.lock().unwrap().num_pubkeys, 0);
    {
        let server_guard = account_node.lock().unwrap();
        let acct = server_guard
            .get_account(&zkcoins_program::types::MINTING_ADDRESS)
            .expect("minting account still present");
        assert!(
            acct.coin_queue.is_empty() && acct.proof.is_none(),
            "in-memory minting Account must NOT mutate when commit_mint_tx fails"
        );
    }
}

/// Drives the Err arm of `AccountNode::receive_coin_into` inside
/// the commit phase of `mint_handler`. Pre-populates the recipient
/// account's `coin_history` SMT with the identifier that
/// `prepare_mint` is about to produce, so `receive_coin_into` returns
/// `Err("Coin already spent (replay)")` on the cloned recipient.
/// Identifier prediction mirrors `Account::create_coins` off-circuit
/// (canonical AccountState layout + Poseidon hash + index 0).
///
/// Per the prepare-then-commit refactor (zk-coins/node#89) the
/// receive error is logged and the unchanged recipient clone still
/// participates in `commit_mint_tx`. With a live Postgres the
/// transaction commits, the handler returns 200 OK, and
/// `minting_meta.num_pubkeys` advances to 1.
#[tokio::test]
async fn mint_receive_coin_failure_logs_and_returns_ok() {
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    let pg_container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = pg_container.get_host().await.unwrap();
    let port = pg_container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = Arc::new(
        crate::db::connect_and_migrate(&url)
            .await
            .expect("connect_and_migrate failed"),
    );

    let mock_server = mint_broadcast_mock_server().await;
    let ws_url = mint_broadcast_mock_ws().await;

    let recipient_bytes = [6u8; 32];
    let recipient = zkcoins_program::hash::digest_from_bytes(&recipient_bytes);

    let mut state = mint_test_state();
    state.pool = Arc::clone(&pool);
    state.esplora_config = Arc::new(crate::publisher::EsploraConfig {
        url: mock_server.uri(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: Some(ws_url),
        track_tx_timeout: None,
    });

    // Predict the coin identifier that `prepare_mint` will assign to
    // the freshly-minted output coin. `Account::create_coins` builds
    // `next_account_state` with `owner = MINTING_ADDRESS`,
    // `balance = minting_balance - amount`, and
    // `public_key = current minting pubkey`, then hashes it and feeds
    // the digest into `calculate_coin_identifier(_, 0)`.
    let amount: u64 = 1;
    let minting_balance: u64 = 1u64 << 48;
    let minting_pubkey_bytes = {
        let mc = state.minting_account.lock().unwrap();
        mc.generate_public_key(0).serialize()
    };
    let next_account_state = zkcoins_program::types::AccountState {
        owner: *zkcoins_program::types::MINTING_ADDRESS,
        balance: minting_balance - amount,
        public_key: minting_pubkey_bytes,
    };
    let predicted_coin_id =
        zkcoins_program::types::calculate_coin_identifier(next_account_state.hash(), 0);
    let predicted_coin_id_bytes = zkcoins_program::hash::digest_to_bytes(&predicted_coin_id);

    // Pre-insert the predicted identifier into the recipient's
    // coin_history SMT so `receive_coin_into` sees the coin as
    // already spent.
    let mut recipient_account = Account::new();
    recipient_account
        .coin_history
        .insert(predicted_coin_id_bytes, predicted_coin_id)
        .expect("insert into fresh SMT must succeed");
    {
        let mut server = state.account_node.lock().unwrap();
        server.import_account(recipient, recipient_account);
    }

    let recipient_hex = "0x".to_string() + &hex::encode(recipient_bytes);
    let body = serde_json::json!({
        "account_address": recipient_hex,
        "amount": amount,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::OK, "body: {}", resp_body);
    let v: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(v["success"], true);
    assert!(
        v["proof_id"].as_u64().is_some(),
        "proof_id missing from response: {}",
        resp_body
    );
}

/// Retry-after-broadcast-failure (zk-coins/node#89).
///
/// First mint runs against an unreachable Esplora (the default
/// `mint_test_state` config points at 127.0.0.1:1) — the handler
/// fails the broadcast and returns 503. The in-memory and persisted
/// state must be untouched: `num_pubkeys` still 0, no
/// `minting_meta` row, the minting Account still has `proof = None`
/// and `coin_queue` empty. Second mint reuses the same `AppState`
/// but swaps in a working wiremock Esplora; the broadcast succeeds,
/// `commit_mint_tx` writes the bundle in one transaction, and the
/// handler returns 200. After the second call `num_pubkeys = 1`,
/// the recipient account exists, and the proofs Vec was popped once.
///
/// **Idempotent-retry caveat (documented in `mint_handler`).** On a
/// real broadcast failure where the first commit + reveal pair
/// actually landed on chain but the response was lost, a retry
/// produces an identical inscription txid and Bitcoin returns
/// `txn-already-known`. The handler returns 503 again; reconciliation
/// happens on the next scanner sweep. This test does NOT cover that
/// branch — it only proves the "broadcast genuinely failed, no chain
/// effect, retry succeeds" flow.
#[tokio::test]
async fn mint_retry_after_broadcast_failure_succeeds() {
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    let pg_container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = pg_container.get_host().await.unwrap();
    let port = pg_container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = Arc::new(
        crate::db::connect_and_migrate(&url)
            .await
            .expect("connect_and_migrate failed"),
    );

    // ---- First mint: dead Esplora → 503 ---------------------------------
    let mut state = mint_test_state();
    state.pool = Arc::clone(&pool);
    // Keep the default unreachable URL so the broadcast fails.
    let cloned_state_first = state.clone();

    let recipient_bytes = [9u8; 32];
    let recipient = "0x".to_string() + &hex::encode(recipient_bytes);
    let body = serde_json::json!({
        "account_address": recipient,
        "amount": 1u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status1, _body1) = send_request_with_state(cloned_state_first, req).await;
    assert_eq!(status1, StatusCode::SERVICE_UNAVAILABLE);

    // Confirm no DB row + no in-memory advance.
    let minting_num_first: Option<u32> = crate::db::load_minting_num_pubkeys(&pool)
        .await
        .expect("load minting_meta after first mint");
    assert!(
        minting_num_first.is_none() || minting_num_first == Some(0),
        "minting_meta row must not show advance after broadcast failure, got {:?}",
        minting_num_first
    );
    assert_eq!(state.minting_account.lock().unwrap().num_pubkeys, 0);

    // ---- Second mint: working Esplora → 200 -----------------------------
    let mock_server = mint_broadcast_mock_server().await;
    let ws_url = mint_broadcast_mock_ws().await;
    state.esplora_config = Arc::new(crate::publisher::EsploraConfig {
        url: mock_server.uri(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: Some(ws_url),
        track_tx_timeout: None,
    });
    let cloned_state_second = state.clone();
    let body2 = serde_json::json!({
        "account_address": recipient,
        "amount": 1u64,
    });
    let req2 = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body2.to_string()))
        .unwrap();
    let (status2, resp_body2) = send_request_with_state(cloned_state_second, req2).await;
    assert_eq!(status2, StatusCode::OK, "body: {}", resp_body2);

    // Final state: counter at 1, recipient account exists.
    let minting_num_after: Option<u32> = crate::db::load_minting_num_pubkeys(&pool)
        .await
        .expect("load minting_meta after second mint");
    assert_eq!(
        minting_num_after,
        Some(1),
        "num_pubkeys must be 1 after successful retry"
    );
    assert_eq!(state.minting_account.lock().unwrap().num_pubkeys, 1);
    let recipient_digest = zkcoins_program::hash::digest_from_bytes(&recipient_bytes);
    {
        let server_guard = state.account_node.lock().unwrap();
        assert!(
            server_guard.get_account(&recipient_digest).is_some(),
            "recipient account must be created on successful mint"
        );
    }
}

/// Concurrent-mint serialization (zk-coins/node#89).
///
/// Pins the optimistic-UPDATE loser branch of `commit_mint_tx`
/// deterministically by pre-seeding a stale `minting_meta.num_pubkeys
/// = 1` row while the in-memory `minting_account.num_pubkeys` is
/// still 0. A truly-parallel two-mint race would land
/// probabilistically (the proof phase serializes on the shared
/// `Arc<Mutex<AccountNode>>`, the broadcast races against the DB
/// tx) and would be flaky in CI; the deterministic shape here
/// exercises the same exit branch — `expected_prev = 0`, stored = 1,
/// `INSERT ... ON CONFLICT DO UPDATE ... WHERE minting_meta.num_pubkeys
/// = 0` rejects on the WHERE predicate, `rows_affected == 0`, tx
/// rolls back, handler returns `503 "Concurrent mint detected"`.
///
/// In production this is exactly what the loser observes when two
/// requests both snapshotted `num_pubkeys = N` and the winner won the
/// race to UPDATE the counter to N+1: the loser's `expected_prev = N`
/// no longer matches the stored value, the WHERE clause filters out
/// the UPDATE, and the loser surfaces 503 with no state advance.
/// The optimistic lock guarantees that the in-memory `num_pubkeys`
/// cannot diverge from the persisted counter even on the loser.
#[tokio::test]
async fn concurrent_mints_only_one_commits() {
    use testcontainers::{runners::AsyncRunner, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    let pg_container = Postgres::default()
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres container");
    let host = pg_container.get_host().await.unwrap();
    let port = pg_container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let pool = Arc::new(
        crate::db::connect_and_migrate(&url)
            .await
            .expect("connect_and_migrate failed"),
    );

    let mock_server = mint_broadcast_mock_server().await;
    let ws_url = mint_broadcast_mock_ws().await;

    let mut state = mint_test_state();
    state.pool = Arc::clone(&pool);
    state.esplora_config = Arc::new(crate::publisher::EsploraConfig {
        url: mock_server.uri(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: Some(ws_url),
        track_tx_timeout: None,
    });

    // Force the optimistic UPDATE to race even when the in-memory
    // proof phase has already serialized: pre-insert a stale
    // `minting_meta` row with `num_pubkeys = 1` while the in-memory
    // `minting_account.num_pubkeys` is still 0. The first concurrent
    // mint will observe the in-memory `0`, derive pubkey index 0,
    // broadcast successfully, then try
    // `UPDATE minting_meta SET num_pubkeys = 1 WHERE num_pubkeys = 0`
    // — but the row is already at 1, so `rows_affected == 0` and the
    // commit_mint_tx returns Ok(false). The handler maps that to 503
    // "Concurrent mint detected". This pins the race-loser branch
    // deterministically (a real concurrent-mint race would land
    // probabilistically, which is not portable to CI).
    crate::db::upsert_minting_num_pubkeys(&pool, 1)
        .await
        .expect("seed stale minting_meta row");

    let recipient = "0x".to_string() + &hex::encode([3u8; 32]);
    let body = serde_json::json!({
        "account_address": recipient,
        "amount": 1u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "concurrent_mint must surface 503, got body: {}",
        resp_body
    );
    let v: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(v["success"], false);
    assert_eq!(v["error"], "Concurrent mint detected");

    // The stale row survives untouched.
    let minting_num: Option<u32> = crate::db::load_minting_num_pubkeys(&pool)
        .await
        .expect("load minting_meta after concurrent-mint");
    assert_eq!(
        minting_num,
        Some(1),
        "loser must not bump the counter; stale row stays at 1"
    );
}

/// Drives the post-proof "concurrent mint detected during proof phase"
/// branch of `mint_handler` (router.rs:854-858 / zk-coins/node#90)
/// against the pure helper.
///
/// Pairs with `mint_handler_concurrent_mint_during_proof_returns_503`
/// below, which drives the SAME branch end-to-end through
/// `mint_handler` so the call site itself (the
/// `return concurrent_mint_during_proof_response(...)` invocation)
/// is covered, not just the helper.
#[tokio::test]
async fn concurrent_mint_during_proof_response_returns_503() {
    let (status, Json(body)) = crate::router::concurrent_mint_during_proof_response(0, 1);
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "concurrent-mint-during-proof must surface 503"
    );
    assert!(!body.success);
    assert_eq!(body.error.as_deref(), Some("Concurrent mint detected"));
}

/// End-to-end race that drives the post-proof "concurrent mint
/// detected during proof phase" branch of `mint_handler` through the
/// HTTP layer so the `return concurrent_mint_during_proof_response(...)`
/// call site (router.rs ~L891) is covered, not just the helper.
///
/// Synchronisation strategy (deterministic, not time-based): the test
/// pre-acquires the `state.account_node` mutex BEFORE issuing the
/// `/api/mint` request. The handler completes phase 1 (lock
/// `minting_account`, snapshot `expected_num_pubkeys = 0`, release)
/// and then blocks at phase 2 trying to lock `account_node`. While
/// the handler is parked on that lock, the test acquires
/// `state.minting_account` and bumps `num_pubkeys` to a non-matching
/// value, then drops the `account_node` guard. The handler proceeds
/// through phase 2 (prover work), reaches phase 3, re-locks
/// `minting_account`, observes the bumped counter, and returns 503
/// before ever touching the broadcast / Esplora / Postgres paths —
/// so the bare `mint_test_state()` (dead pool, unreachable Esplora)
/// is sufficient.
///
/// Requires the multi-thread runtime: phase 2's `prepare_mint` is
/// blocking CPU work that would otherwise stall the single-threaded
/// executor and prevent the test thread from running the bump step.
///
/// `clippy::await_holding_lock` is silenced because holding the
/// `account_node` `MutexGuard` across the `sleep().await` IS the
/// synchronisation primitive — releasing it earlier would defeat the
/// test by letting phase 2 finish before the bump.
#[allow(clippy::await_holding_lock)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mint_handler_concurrent_mint_during_proof_returns_503() {
    let state = mint_test_state();

    // Pre-acquire the account_node lock so phase 2 of mint_handler
    // parks until we release it. Phase 1 only touches
    // `state.minting_account`, so the handler can still complete its
    // snapshot (capturing expected_num_pubkeys = 0) before parking.
    let account_node_guard = state.account_node.lock().unwrap();

    let recipient = "0x".to_string() + &hex::encode([7u8; 32]);
    let body = serde_json::json!({
        "account_address": recipient,
        "amount": 1u64,
    });
    let req = Request::post("/api/mint")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    // Drive the request on a worker so we can manipulate state from
    // this task while the handler is parked on the account_node
    // mutex inside phase 2.
    let state_for_request = state.clone();
    let request_task =
        tokio::spawn(async move { send_request_with_state(state_for_request, req).await });

    // Give the handler a generous window to enter phase 2 and park on
    // the account_node lock. Phase 1 is microseconds of work; 200ms
    // is overkill but cheap. Note: we cannot rely on `lock().is_locked`
    // because std::sync::Mutex offers no such API — but holding the
    // guard here is enough, because phase 2 will block until we drop
    // it regardless of when the handler arrives.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Now bump num_pubkeys on the minting_account. Phase 1 already
    // captured expected_num_pubkeys = 0, so any non-zero value here
    // trips the phase-3 inequality check.
    {
        let mut minting = state.minting_account.lock().unwrap();
        minting.num_pubkeys = 1;
    }

    // Release the account_node lock so phase 2 can proceed. The
    // handler now runs the prover, re-locks minting_account, observes
    // num_pubkeys = 1 != expected 0, and returns 503 via
    // `concurrent_mint_during_proof_response`.
    drop(account_node_guard);

    let (status, resp_body) = request_task.await.expect("request task panicked");

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "concurrent-mint-during-proof must surface 503, body: {}",
        resp_body
    );
    let v: serde_json::Value = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(v["success"], false);
    assert_eq!(v["error"], "Concurrent mint detected");
}

/// Drives the Err arm of `upsert_mint_recipient_or_log`
/// (router.rs:1025-1028 / zk-coins/node#90). The recipient upsert
/// loop in `mint_handler` is best-effort log-and-continue: the
/// minting_meta + minting-account bump already committed inside
/// `commit_mint_tx`, so a recipient-row upsert failure only delays the
/// row until the next receive on the same address. The Err branch is
/// otherwise only reachable on a pool-dead failure timed exactly
/// between `commit_mint_tx` returning Ok and the loop iterating —
/// which is intractable to orchestrate against a single shared
/// `PgPool`. Factoring the upsert-or-log into a helper lets us pin
/// the branch with a deterministic `dead_pool` call (the same pattern
/// the rest of the suite uses for the parallel send/receive
/// best-effort upserts).
#[tokio::test]
async fn upsert_mint_recipient_or_log_swallows_pool_dead_error() {
    // dead_pool's lazy connect fails fast on first use; the helper
    // logs the error and returns without panicking.
    let pool = dead_pool();
    let addr = [0u8; 32];
    let bytes = [0u8; 16];
    crate::router::upsert_mint_recipient_or_log(&pool, &addr, &bytes).await;
}
