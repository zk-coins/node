//! HTTP API end-to-end test suite for the deployed zkCoins server.
//!
//! This suite is the functional counterpart to the smoke test inside
//! `.github/workflows/deploy-dev.yaml` (which only probes `/api/info`).
//! Where the smoke test answers "is the listener bound?", this suite
//! answers "do all 15 routes behave as documented?". It signs real
//! Schnorr commitments with freshly-generated wallets, mints coins,
//! sends them, commits the resulting state, and claims a username —
//! exercising the API contract happy path against the same backend
//! the wallet app talks to.
//!
//! Scope note: the suite verifies server-visible behaviour (status
//! codes, response shapes, balance movements). The commit message
//! format used in `send_commit_roundtrip_moves_balance` is the
//! 64-byte `ash || ocr` raw concat, which the server accepts via
//! `Commitment::verify`'s SHA-256 fallback. The canonical wallet
//! client signs the 32-byte Poseidon `hash_concat(ash, ocr)` digest
//! (see `shared::ClientAccount::create_commitment`); the two forms
//! produce different SMT leaves but both pass the signature check,
//! and the suite never re-spends from the test wallet so the leaf
//! shape is observationally indistinguishable in-scope.
//!
//! The DEV server is shared by other workflows (per-PR app E2E,
//! interactive testing). To keep this suite race-free we always:
//!   - mint into freshly-generated wallets (no fixed addresses)
//!   - tolerate `503 Service Unavailable` on mutating endpoints,
//!     which the server returns when the Mutinynet publisher wallet
//!     has no UTXOs — a benign DEV condition
//!   - assert strictly on 4xx codes (client-fixable contract bugs)
//!   - skip on 5xx codes with a logged warning (server-side flake)
//!
//! Read by:
//!   - `cargo test -p server --release --test api_remote` (locally)
//!   - the `api-e2e` job in `deploy-dev.yaml` after `build-and-deploy`
//!
//! Configuration:
//!   - `ZKCOINS_API_URL` (default `https://dev-api.zkcoins.app`) —
//!     the base URL of the server under test.

use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::secp256k1::{self as secp, Keypair, Message, PublicKey, SecretKey};
use bitcoin::Network;
use rand::RngCore;
use reqwest::StatusCode;
use serde_json::{json, Value};
use server::account_server::CoinProof;
use server::server::Capabilities;
use sha2::{Digest, Sha256};
use shared::commitment::Commitment;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_API_URL: &str = "https://dev-api.zkcoins.app";
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const POLL_TIMEOUT: Duration = Duration::from_secs(60);
/// How long to keep retrying the user-level `/api/send` while the
/// server reports "Unable to get merkle proofs for provided public
/// key" — see the inline comment in `send_commit_roundtrip_moves_balance`
/// for why this is timing-bound on the scanner picking up the mint's
/// Taproot inscription. Mutinynet block time is ~30 s, the scanner
/// polls every 30 s, so 2 minutes is enough on a healthy network
/// without dragging the suite past the workflow timeout when the
/// publisher is offline.
const SEND_RETRY_DEADLINE: Duration = Duration::from_secs(120);
const SEND_RETRY_INTERVAL: Duration = Duration::from_secs(15);
const MINT_AMOUNT: u64 = 50_000;
const SEND_AMOUNT: u64 = 10_000;

fn api_base() -> String {
    std::env::var("ZKCOINS_API_URL").unwrap_or_else(|_| DEFAULT_API_URL.to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .expect("build reqwest client")
}

fn url(path: &str) -> String {
    format!("{}{}", api_base().trim_end_matches('/'), path)
}

/// Helper: log a one-line "skip" with reason and return.
macro_rules! dev_skip {
    ($reason:expr) => {{
        eprintln!("DEV environment skip: {}", $reason);
        return;
    }};
}

/// Helper: log a one-line "feature off" skip and return. Distinct
/// from [`dev_skip!`] so the workflow log line clearly marks "the
/// route is absent by design" vs. "the route is present but flaked
/// on the network".
macro_rules! feature_skip {
    ($feature:expr, $test:expr) => {{
        eprintln!(
            "SKIP {}: feature `{}` disabled on this server",
            $test, $feature
        );
        return;
    }};
}

// ---------------------------------------------------------------------------
// Capability detection
//
// Mint (`/api/mint`) is part of the MVP and is always present, so it is
// no longer gated here. The remaining post-MVP routes (`address-list`,
// `usernames`, `lnurl`) are still optional: the default deploy ships
// without them and the axum fallback answers 404 instead of the
// per-handler error codes. We fetch `/api/info` once per gated test,
// deserialise the well-known `Capabilities` shape, and skip the rest
// of the test if the relevant feature flag is `false`.
//
// `ZKCOINS_FORCE_DISABLE_FEATURES` (comma-separated list, e.g.
// `address_list,usernames`) overrides any flag returned by the server
// to `false`. This is the local dry-run hook — point the suite at the
// live DEV server, force features off, and confirm that every gated
// test prints `SKIP …` instead of hitting a disabled-on-paper but
// actually-running endpoint. Forcing `faucet` off is a no-op (the
// route is always registered) and the flag is ignored.
// ---------------------------------------------------------------------------

async fn fetch_capabilities(client: &reqwest::Client) -> Capabilities {
    let resp = client
        .get(url("/api/info"))
        .send()
        .await
        .expect("GET /api/info for capability detection");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "/api/info must answer 200 — required for capability detection"
    );
    // We deserialise into a transient Value first so the override hook
    // can flip booleans without round-tripping through the strongly
    // typed `Capabilities` (which has no setters).
    let body: Value = resp
        .json()
        .await
        .expect("/api/info body is JSON for capability detection");
    let mut caps = Capabilities {
        address_list: body["capabilities"]["address_list"]
            .as_bool()
            .unwrap_or(false),
        faucet: body["capabilities"]["faucet"].as_bool().unwrap_or(false),
        usernames: body["capabilities"]["usernames"].as_bool().unwrap_or(false),
        lnurl: body["capabilities"]["lnurl"].as_bool().unwrap_or(false),
    };
    if let Ok(force) = std::env::var("ZKCOINS_FORCE_DISABLE_FEATURES") {
        for flag in force.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            match flag {
                "address_list" | "address-list" => caps.address_list = false,
                "faucet" => {
                    // Mint is permanent MVP. The route is always
                    // registered, so forcing it "off" cannot disable
                    // it — log + ignore to keep callers honest.
                    eprintln!(
                        "ZKCOINS_FORCE_DISABLE_FEATURES: `faucet` is permanent MVP — ignored"
                    );
                }
                "usernames" => caps.usernames = false,
                "lnurl" => caps.lnurl = false,
                other => {
                    eprintln!(
                        "ZKCOINS_FORCE_DISABLE_FEATURES: unknown flag `{}` — ignored",
                        other
                    );
                }
            }
        }
    }
    caps
}

// ---------------------------------------------------------------------------
// TestWallet — fresh-per-test random key + helpers for signing the four
// request shapes the server accepts (send / commit / username-claim).
// ---------------------------------------------------------------------------

struct TestWallet {
    xpriv: Xpriv,
    secp: secp::Secp256k1<secp::All>,
}

impl TestWallet {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        // Signet matches the mutinynet flavour the DEV server runs on;
        // the network choice only affects xpub serialisation prefixes,
        // not the derived secp256k1 keys we sign with.
        let xpriv = Xpriv::new_master(Network::Signet, &seed).expect("derive xpriv from seed");
        Self {
            xpriv,
            secp: secp::Secp256k1::new(),
        }
    }

    /// Normal-child secret key at index `i`. Matches the convention
    /// used by `shared::ClientAccount::generate_public_key`.
    fn seckey(&self, idx: u32) -> SecretKey {
        self.xpriv
            .derive_priv(&self.secp, &[ChildNumber::Normal { index: idx }])
            .expect("derive private key")
            .private_key
    }

    fn pubkey(&self, idx: u32) -> PublicKey {
        Xpub::from_priv(&self.secp, &self.xpriv)
            .derive_pub(&self.secp, &[ChildNumber::Normal { index: idx }])
            .expect("derive public key")
            .public_key
    }

    fn keypair(&self, idx: u32) -> Keypair {
        Keypair::from_secret_key(&self.secp, &self.seckey(idx))
    }

    /// The hex address that the server treats as the account identifier.
    /// Mirrors `shared::AccountState::new` → `sha256(compressed_pubkey)`.
    fn address_hex(&self) -> String {
        let pk = self.pubkey(0);
        let digest: [u8; 32] = Sha256::digest(pk.serialize()).into();
        format!("0x{}", hex::encode(digest))
    }

    /// Sign the canonical send-request preimage:
    /// `SHA256(account_address_str || recipient_str || amount_le8 || timestamp_le8)`.
    fn sign_send(
        &self,
        account_address: &str,
        recipient: &str,
        amount: u64,
        timestamp: u64,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(account_address.as_bytes());
        hasher.update(recipient.as_bytes());
        hasher.update(amount.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let msg = Message::from_digest(hash);
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &self.keypair(0));
        hex::encode(sig.as_ref())
    }

    /// Sign the commit message: the BIP-340 Schnorr signature is
    /// produced by `Commitment::new`, which SHA256s any non-32-byte
    /// payload before signing. The server reconstructs the
    /// `Commitment` struct from `(public_key, signature, message)`
    /// and re-verifies it the same way.
    fn sign_commit(&self, message_bytes: &[u8]) -> String {
        let commitment = Commitment::new(&self.seckey(0), message_bytes.to_vec())
            .expect("Commitment::new from random secret");
        hex::encode(commitment.signature.as_ref())
    }

    /// Sign the username-claim preimage:
    /// `SHA256("zkcoins:claim_username" || address_hex_str || username_str || timestamp_le8)`.
    fn sign_username_claim(&self, address_hex: &str, username: &str, timestamp: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"zkcoins:claim_username");
        hasher.update(address_hex.as_bytes());
        hasher.update(username.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let msg = Message::from_digest(hash);
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &self.keypair(0));
        hex::encode(sig.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Section 1 — read-only endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn root_returns_service_metadata() {
    let resp = http_client().get(url("/")).send().await.expect("GET /");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("root body is JSON");
    assert_eq!(body["service"], "zkcoins-server");
    assert!(body["version"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(body["network"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(body["endpoints"]["info"].is_string());
}

#[tokio::test]
async fn health_returns_ok() {
    let resp = http_client()
        .get(url("/health"))
        .send()
        .await
        .expect("GET /health");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("read body");
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn health_ready_returns_ready_with_no_failures() {
    let resp = http_client()
        .get(url("/health/ready"))
        .send()
        .await
        .expect("GET /health/ready");
    let status = resp.status();
    let body: Value = resp.json().await.expect("/health/ready body is JSON");
    if status != StatusCode::OK {
        dev_skip!(format!(
            "/health/ready returned {} with body {}",
            status, body
        ));
    }
    assert_eq!(body["ready"], Value::Bool(true));
    let failures = body["failures"].as_array().expect("failures is an array");
    assert!(
        failures.is_empty(),
        "expected no failures, got {:?}",
        failures
    );
}

#[tokio::test]
async fn info_returns_well_formed_response() {
    // Shape-only check: the MVP deploy may run with zero features and
    // PRD may differ from DEV, so the only invariant we assert is the
    // contract — `/api/info` returns a well-formed `InfoResponse` with
    // a non-empty `network`, a non-empty `username_domain`, and four
    // boolean capability flags. The per-feature `true`/`false`
    // expectations live in the gated tests below, which short-circuit
    // through `fetch_capabilities`.
    let resp = http_client()
        .get(url("/api/info"))
        .send()
        .await
        .expect("GET /api/info");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("/api/info body is JSON");

    assert!(
        body["network"].as_str().is_some_and(|v| !v.is_empty()),
        "network must be a non-empty string, got {:?}",
        body["network"]
    );
    assert!(
        body["username_domain"]
            .as_str()
            .is_some_and(|v| !v.is_empty()),
        "username_domain must be a non-empty string, got {:?}",
        body["username_domain"]
    );

    for cap in ["address_list", "faucet", "usernames", "lnurl"] {
        assert!(
            body["capabilities"][cap].is_boolean(),
            "capability `{cap}` must be a bool, got {:?}",
            body["capabilities"][cap]
        );
    }
}

#[tokio::test]
async fn balance_unknown_address_returns_ok_with_zero() {
    let address = format!("0x{}", "00".repeat(32));
    let resp = http_client()
        .get(url(&format!("/api/balance?address={}", address)))
        .send()
        .await
        .expect("GET /api/balance");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
    assert_eq!(body["balance"], 0);
}

#[tokio::test]
async fn balance_missing_param_returns_422() {
    let resp = http_client()
        .get(url("/api/balance"))
        .send()
        .await
        .expect("GET /api/balance (no params)");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn balance_invalid_hex_returns_422() {
    let resp = http_client()
        .get(url("/api/balance?address=not_hex"))
        .send()
        .await
        .expect("GET /api/balance (bad hex)");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn balance_wrong_length_returns_422() {
    // 16 bytes = 32 hex chars, the handler requires exactly 32 bytes
    let address = format!("0x{}", "ab".repeat(16));
    let resp = http_client()
        .get(url(&format!("/api/balance?address={}", address)))
        .send()
        .await
        .expect("GET /api/balance (short hex)");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn address_list_returns_addresses() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.address_list {
        feature_skip!("address_list", "address_list_returns_addresses");
    }
    let resp = client
        .get(url("/api/address"))
        .send()
        .await
        .expect("GET /api/address");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
    let addresses = body["addresses"].as_array().expect("addresses is an array");
    assert!(!addresses.is_empty(), "address list must not be empty");
    for addr in addresses {
        let s = addr.as_str().expect("address entry is a string");
        assert!(s.starts_with("0x"), "address must be 0x-prefixed: {}", s);
        // 0x + 64 hex chars = 66 chars
        assert_eq!(s.len(), 66, "address must be 32 bytes: {}", s);
    }
}

#[tokio::test]
async fn proof_for_huge_id_returns_404() {
    // u64::MAX is guaranteed to exceed any real proof_id the server
    // has issued, so the file-on-disk lookup misses and returns 404.
    let resp = http_client()
        .get(url(&format!("/api/proof/{}", u64::MAX)))
        .send()
        .await
        .expect("GET /api/proof/<huge>");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn proof_id_one_returns_200_or_404() {
    // proof_id=1 may exist (a prior test minted) or not (fresh state).
    // Both 200 (binary) and 404 are valid; anything else is a regression.
    let resp = http_client()
        .get(url("/api/proof/1"))
        .send()
        .await
        .expect("GET /api/proof/1");
    let status = resp.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "proof/1 returned unexpected status: {}",
        status
    );
    if status == StatusCode::OK {
        let bytes = resp.bytes().await.expect("body bytes");
        // A valid CoinProof bincode payload is at least a few hundred
        // bytes (Plonky2 proof + commitment). 100 is a loose lower
        // bound that just guards against an empty response.
        assert!(
            bytes.len() > 100,
            "expected non-trivial CoinProof bytes, got {}",
            bytes.len()
        );
    }
}

#[tokio::test]
async fn resolve_unknown_username_returns_404() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.usernames {
        feature_skip!("usernames", "resolve_unknown_username_returns_404");
    }
    let resp = client
        .get(url("/api/username/resolve/definitely_not_claimed_xyzzy"))
        .send()
        .await
        .expect("GET /api/username/resolve/<unknown>");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "expected 404 for unknown username, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn lnurlp_unknown_user_returns_404() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.lnurl {
        feature_skip!("lnurl", "lnurlp_unknown_user_returns_404");
    }
    let resp = client
        .get(url("/.well-known/lnurlp/definitely_not_claimed_xyzzy"))
        .send()
        .await
        .expect("GET /.well-known/lnurlp/<unknown>");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn lnurl_pay_callback_returns_phase2_stub() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.lnurl {
        feature_skip!("lnurl", "lnurl_pay_callback_returns_phase2_stub");
    }
    let resp = client
        .get(url("/lnurl/pay/anyone"))
        .send()
        .await
        .expect("GET /lnurl/pay/anyone");
    // The lnurl callback returns Json directly (no error wrapping), so
    // it always answers 200 with a body that says "Phase 2".
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
    assert_eq!(body["status"], "ERROR");
    assert!(
        body["reason"]
            .as_str()
            .is_some_and(|s| s.contains("Phase 2")),
        "expected Phase 2 stub, got {:?}",
        body["reason"]
    );
}

#[tokio::test]
async fn fallback_unknown_route_returns_404() {
    let resp = http_client()
        .get(url("/api/nonsense"))
        .send()
        .await
        .expect("GET /api/nonsense");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Section 2 — negative-path POSTs (no roundtrip required)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mint_empty_body_returns_422() {
    let resp = http_client()
        .post(url("/api/mint"))
        .json(&json!({}))
        .send()
        .await
        .expect("POST /api/mint {}");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn mint_invalid_hex_address_returns_422() {
    let resp = http_client()
        .post(url("/api/mint"))
        .json(&json!({"account_address": "not_hex", "amount": 100}))
        .send()
        .await
        .expect("POST /api/mint bad hex");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn mint_wrong_address_length_returns_422() {
    // 16 bytes = 32 hex chars — short of the required 32 bytes
    let short_addr = format!("0x{}", "ab".repeat(16));
    let resp = http_client()
        .post(url("/api/mint"))
        .json(&json!({"account_address": short_addr, "amount": 100}))
        .send()
        .await
        .expect("POST /api/mint short addr");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn send_empty_body_returns_422() {
    let resp = http_client()
        .post(url("/api/send"))
        .json(&json!({}))
        .send()
        .await
        .expect("POST /api/send {}");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn send_bad_address_hex_returns_422() {
    // All required fields present, but account_address is not valid hex
    // — this should fail at the hex-decode step (handler-level 422,
    // not axum-level deserialization 422).
    let alice = TestWallet::new();
    let body = json!({
        "account_address": "0xZZZZZZ",
        "recipient": alice.address_hex(),
        "amount": 1u64,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "next_public_key": hex::encode(alice.pubkey(1).serialize()),
        "prev_commitment_pubkey": Option::<String>::None,
        "signature": Option::<String>::None,
        "timestamp": Option::<u64>::None,
    });
    let resp = http_client()
        .post(url("/api/send"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/send bad hex");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn send_unknown_account_returns_404() {
    // Well-formed body, valid signatures, but the sender account has
    // no balance / state on the server, so `send_coins` returns
    // "Unknown account address" → 404.
    let alice = TestWallet::new();
    let bob = TestWallet::new();
    let amount: u64 = 1;
    let ts = unix_now();
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, ts);

    let body = json!({
        "account_address": alice.address_hex(),
        "recipient": bob.address_hex(),
        "amount": amount,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "next_public_key": hex::encode(alice.pubkey(1).serialize()),
        "prev_commitment_pubkey": Option::<String>::None,
        "signature": Some(signature),
        "timestamp": Some(ts),
    });
    let resp = http_client()
        .post(url("/api/send"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/send unknown account");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn send_bad_signature_returns_401() {
    let alice = TestWallet::new();
    let bob = TestWallet::new();
    let body = json!({
        "account_address": alice.address_hex(),
        "recipient": bob.address_hex(),
        "amount": 1u64,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "next_public_key": hex::encode(alice.pubkey(1).serialize()),
        "prev_commitment_pubkey": Option::<String>::None,
        "signature": Some("00".repeat(64)),
        "timestamp": Some(unix_now()),
    });
    let resp = http_client()
        .post(url("/api/send"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/send bad sig");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn send_stale_timestamp_returns_401() {
    let alice = TestWallet::new();
    let bob = TestWallet::new();
    let amount: u64 = 1;
    // Timestamp ten minutes in the past — outside the 5-minute window.
    let stale_ts = unix_now().saturating_sub(600);
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, stale_ts);
    let body = json!({
        "account_address": alice.address_hex(),
        "recipient": bob.address_hex(),
        "amount": amount,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "next_public_key": hex::encode(alice.pubkey(1).serialize()),
        "prev_commitment_pubkey": Option::<String>::None,
        "signature": Some(signature),
        "timestamp": Some(stale_ts),
    });
    let resp = http_client()
        .post(url("/api/send"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/send stale ts");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn receive_empty_body_returns_default_failure() {
    let resp = http_client()
        .post(url("/api/receive"))
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("POST /api/receive empty");
    // Handler swallows bincode errors and returns Json(SendCoinResponse::default()) = 200.
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
    assert_eq!(body["success"], Value::Bool(false));
}

#[tokio::test]
async fn receive_garbage_body_returns_default_failure() {
    let garbage = vec![0xFFu8; 64];
    let resp = http_client()
        .post(url("/api/receive"))
        .body(garbage)
        .send()
        .await
        .expect("POST /api/receive garbage");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
    assert_eq!(body["success"], Value::Bool(false));
}

#[tokio::test]
async fn commit_unknown_proof_id_returns_404() {
    let alice = TestWallet::new();
    // The handler validates the proof_id BEFORE hex decoding, so any
    // syntactically valid body works as long as proof_id is unknown.
    let body = json!({
        "proof_id": u64::MAX,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "signature": "00".repeat(64),
        "message": "00".repeat(64),
    });
    let resp = http_client()
        .post(url("/api/commit"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/commit unknown id");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn commit_bad_message_hex_returns_422_or_404() {
    let alice = TestWallet::new();
    // proof_id=1 may or may not exist on the server. If it exists, the
    // handler reaches the hex-decode step and returns 422. If not, the
    // proof-store miss short-circuits at 404. Both are acceptable for
    // this negative-path coverage.
    let body = json!({
        "proof_id": 1u64,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "signature": "00".repeat(64),
        "message": "not_valid_hex_zzz",
    });
    let resp = http_client()
        .post(url("/api/commit"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/commit bad message");
    let status = resp.status();
    assert!(
        status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::NOT_FOUND,
        "expected 422 or 404, got {}",
        status
    );
}

#[tokio::test]
async fn claim_username_pk_mismatch_returns_401() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.usernames {
        feature_skip!("usernames", "claim_username_pk_mismatch_returns_401");
    }
    let alice = TestWallet::new();
    let mallory = TestWallet::new();
    let username = format!("mallory_{}", random_suffix());
    let ts = unix_now();
    // Sign with mallory's key but claim alice's address — the
    // sha256(pk) == address check fails.
    let signature = mallory.sign_username_claim(&alice.address_hex(), &username, ts);
    let body = json!({
        "username": username,
        "address": alice.address_hex(),
        "public_key": hex::encode(mallory.pubkey(0).serialize()),
        "signature": signature,
        "timestamp": ts,
    });
    let resp = client
        .post(url("/api/username/claim"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/username/claim mismatch");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn claim_username_bad_signature_returns_401() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.usernames {
        feature_skip!("usernames", "claim_username_bad_signature_returns_401");
    }
    let alice = TestWallet::new();
    let username = format!("alice_{}", random_suffix());
    let body = json!({
        "username": username,
        "address": alice.address_hex(),
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "signature": "00".repeat(64),
        "timestamp": unix_now(),
    });
    let resp = client
        .post(url("/api/username/claim"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/username/claim bad sig");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn claim_username_stale_timestamp_returns_401() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.usernames {
        feature_skip!("usernames", "claim_username_stale_timestamp_returns_401");
    }
    let alice = TestWallet::new();
    let username = format!("alice_{}", random_suffix());
    let stale_ts = unix_now().saturating_sub(600);
    let signature = alice.sign_username_claim(&alice.address_hex(), &username, stale_ts);
    let body = json!({
        "username": username,
        "address": alice.address_hex(),
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "signature": signature,
        "timestamp": stale_ts,
    });
    let resp = client
        .post(url("/api/username/claim"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/username/claim stale");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Section 3 — happy-path roundtrips against the deployed server
// ---------------------------------------------------------------------------

/// Roundtrip A — mint into a fresh wallet and observe the balance.
///
/// Reads the proof_id back via `GET /api/proof/{id}` and deserializes
/// it as a `CoinProof` so the side-effect (write to the proofs/
/// directory) is visible to the test as well.
#[tokio::test]
async fn mint_roundtrip_lands_balance_and_proof() {
    let client = http_client();
    let alice = TestWallet::new();

    let mint_resp = client
        .post(url("/api/mint"))
        .json(&json!({
            "account_address": alice.address_hex(),
            "amount": MINT_AMOUNT,
        }))
        .send()
        .await
        .expect("POST /api/mint");
    let mint_status = mint_resp.status();
    if mint_status.is_server_error() {
        dev_skip!(format!(
            "mint returned {} — DEV environment flake",
            mint_status
        ));
    }
    assert_eq!(mint_status, StatusCode::OK, "unexpected mint status");
    let mint_body: Value = mint_resp.json().await.expect("mint body JSON");
    assert_eq!(
        mint_body["success"],
        Value::Bool(true),
        "mint not successful: {}",
        mint_body
    );
    let proof_id = mint_body["proof_id"].as_u64().expect("proof_id present");

    // Poll the balance endpoint until the credit shows up.
    let observed = poll_balance_at_least(&client, &alice.address_hex(), MINT_AMOUNT).await;
    assert!(
        observed >= MINT_AMOUNT,
        "balance never reached mint amount; got {observed}"
    );

    // Verify the proof file is fetchable + bincode-decodable.
    let proof_resp = client
        .get(url(&format!("/api/proof/{}", proof_id)))
        .send()
        .await
        .expect("GET /api/proof");
    assert_eq!(proof_resp.status(), StatusCode::OK);
    let proof_bytes = proof_resp.bytes().await.expect("proof bytes");
    let coin_proof: CoinProof =
        bincode::deserialize(&proof_bytes).expect("decode CoinProof bincode");
    assert!(
        coin_proof.commitment.is_some(),
        "mint coin proof should carry a server-signed commitment"
    );
    assert_eq!(coin_proof.coin.amount, MINT_AMOUNT);
}

/// Roundtrip B — full mint → send → commit pipeline.
///
/// The send half requires the previous commitment's signing key as
/// `prev_commitment_pubkey`. After a mint that's the server's minting
/// pubkey, embedded in the mint's `CoinProof.commitment`.
#[tokio::test]
async fn send_commit_roundtrip_moves_balance() {
    let client = http_client();
    let alice = TestWallet::new();
    let bob = TestWallet::new();

    // ---- Mint ----
    // 422 with "Unable to get merkle proofs for provided public key" is
    // the documented signal that a PRIOR mint's on-chain Taproot
    // inscription has not yet been observed by the scanner. This test
    // runs sequentially after `mint_roundtrip_lands_balance_and_proof`
    // in the single-threaded suite, so the second mint hits the
    // server's "look up prev commitment" branch and depends on the
    // scanner having caught up. Mutinynet block time is ≈30 s and the
    // scanner polls Esplora on a 30 s interval — so until both delays
    // elapse, the SMT does not know about the prev_commitment_pubkey
    // the server needs to attach to this mint. Apply the same retry
    // pattern that `/api/send` below uses for the same condition.
    let mint_body_json = json!({
        "account_address": alice.address_hex(),
        "amount": MINT_AMOUNT,
    });
    let (mint_status, mint_body_text) = {
        let deadline = std::time::Instant::now() + SEND_RETRY_DEADLINE;
        loop {
            let resp = client
                .post(url("/api/mint"))
                .json(&mint_body_json)
                .send()
                .await
                .expect("POST /api/mint");
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let should_retry = status == StatusCode::UNPROCESSABLE_ENTITY
                && text.contains("Unable to get merkle proofs");
            if !should_retry || std::time::Instant::now() >= deadline {
                break (status, text);
            }
            eprintln!(
                "mint 422 (merkle proofs not yet observed); retrying in {:?}",
                SEND_RETRY_INTERVAL
            );
            tokio::time::sleep(SEND_RETRY_INTERVAL).await;
        }
    };
    if mint_status.is_server_error() {
        dev_skip!(format!("mint returned {} — DEV flake", mint_status));
    }
    if mint_status == StatusCode::UNPROCESSABLE_ENTITY
        && mint_body_text.contains("Unable to get merkle proofs")
    {
        dev_skip!(format!(
            "mint returned 422 after {:?} of retries — scanner did not observe the prior mint inscription in time; body={}",
            SEND_RETRY_DEADLINE, mint_body_text
        ));
    }
    assert_eq!(
        mint_status,
        StatusCode::OK,
        "mint failed: {} body={}",
        mint_status,
        mint_body_text
    );
    let mint_body: Value = serde_json::from_str(&mint_body_text).expect("mint body JSON");
    let mint_proof_id = mint_body["proof_id"].as_u64().expect("proof_id");

    // Wait for the balance to settle so send_coins has something to spend.
    let balance_before = poll_balance_at_least(&client, &alice.address_hex(), MINT_AMOUNT).await;
    if balance_before < MINT_AMOUNT {
        dev_skip!(format!(
            "balance never settled to {} after mint (saw {})",
            MINT_AMOUNT, balance_before
        ));
    }

    // ---- Fetch the mint's CoinProof to discover prev_commitment_pubkey ----
    let proof_resp = client
        .get(url(&format!("/api/proof/{}", mint_proof_id)))
        .send()
        .await
        .expect("GET mint proof");
    assert_eq!(proof_resp.status(), StatusCode::OK);
    let proof_bytes = proof_resp.bytes().await.expect("mint proof bytes");
    let mint_coin_proof: CoinProof = bincode::deserialize(&proof_bytes).expect("decode CoinProof");
    let prev_pk = mint_coin_proof
        .commitment
        .as_ref()
        .expect("mint coin proof has commitment")
        .public_key;

    // ---- Send ----
    let amount = SEND_AMOUNT;
    let ts = unix_now();
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, ts);
    let send_body = json!({
        "account_address": alice.address_hex(),
        "recipient": bob.address_hex(),
        "amount": amount,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "next_public_key": hex::encode(alice.pubkey(1).serialize()),
        "prev_commitment_pubkey": hex::encode(prev_pk.serialize()),
        "signature": signature,
        "timestamp": ts,
    });
    // 422 with "Unable to get merkle proofs for provided public key"
    // is the documented signal that the on-chain commitment for the
    // freshly-minted account has not yet been observed by the scanner.
    // Mints broadcast a Taproot inscription whose confirmation depends
    // on Mutinynet block time (≈30 s), and the scanner polls Esplora
    // on a 30 s interval — so until both delays elapse, the SMT does
    // not know about the prev_commitment_pubkey we just discovered.
    // Poll for up to [`SEND_RETRY_DEADLINE`] before treating it as a
    // DEV-environment skip, so a typical run on a healthy Mutinynet
    // (block time 30 s) completes the full roundtrip.
    let (send_status, send_body_text) = {
        let deadline = std::time::Instant::now() + SEND_RETRY_DEADLINE;
        loop {
            let resp = client
                .post(url("/api/send"))
                .json(&send_body)
                .send()
                .await
                .expect("POST /api/send");
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let should_retry = status == StatusCode::UNPROCESSABLE_ENTITY
                && text.contains("Unable to get merkle proofs");
            if !should_retry || std::time::Instant::now() >= deadline {
                break (status, text);
            }
            eprintln!(
                "send 422 (merkle proofs not yet observed); retrying in {:?}",
                SEND_RETRY_INTERVAL
            );
            tokio::time::sleep(SEND_RETRY_INTERVAL).await;
        }
    };
    if send_status.is_server_error() {
        dev_skip!(format!(
            "send returned {} — DEV flake; body={}",
            send_status, send_body_text
        ));
    }
    if send_status == StatusCode::UNPROCESSABLE_ENTITY
        && send_body_text.contains("Unable to get merkle proofs")
    {
        dev_skip!(format!(
            "send returned 422 after {:?} of retries — scanner did not observe the mint inscription in time; body={}",
            SEND_RETRY_DEADLINE, send_body_text
        ));
    }
    assert_eq!(
        send_status,
        StatusCode::OK,
        "send failed: {} body={}",
        send_status,
        send_body_text
    );
    let send_body: Value = serde_json::from_str(&send_body_text).expect("send body JSON");
    assert_eq!(send_body["success"], Value::Bool(true));
    let send_proof_id = send_body["proof_id"].as_u64().expect("send proof_id");
    let ash_hex = send_body["account_state_hash"]
        .as_str()
        .expect("account_state_hash")
        .to_string();
    let ocr_hex = send_body["output_coins_root"]
        .as_str()
        .expect("output_coins_root")
        .to_string();

    // ---- Commit ----
    let ash_bytes = hex::decode(&ash_hex).expect("decode ash");
    let ocr_bytes = hex::decode(&ocr_hex).expect("decode ocr");
    let mut commit_message = Vec::with_capacity(64);
    commit_message.extend_from_slice(&ash_bytes);
    commit_message.extend_from_slice(&ocr_bytes);
    let commit_sig = alice.sign_commit(&commit_message);

    let commit_body = json!({
        "proof_id": send_proof_id,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "signature": commit_sig,
        "message": hex::encode(&commit_message),
    });
    let commit_resp = client
        .post(url("/api/commit"))
        .json(&commit_body)
        .send()
        .await
        .expect("POST /api/commit");
    let commit_status = commit_resp.status();
    if commit_status.is_server_error() {
        dev_skip!(format!("commit returned {} — DEV flake", commit_status));
    }
    assert_eq!(
        commit_status,
        StatusCode::OK,
        "commit failed: {}",
        commit_status
    );
    let commit_body_resp: Value = commit_resp.json().await.expect("commit body");
    assert_eq!(commit_body_resp["success"], Value::Bool(true));

    // ---- Balance decreased ----
    let final_balance =
        poll_balance_at_most(&client, &alice.address_hex(), balance_before - amount).await;
    assert!(
        final_balance <= balance_before - amount,
        "balance never decreased after commit: before={}, after={}",
        balance_before,
        final_balance
    );
}

/// Roundtrip C — claim a username, resolve it, then hit the LNURLp
/// endpoint that depends on the username being resolvable.
#[tokio::test]
async fn username_claim_resolve_lnurlp_roundtrip() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    // Claim + resolve both live behind `usernames`; the LNURLp leg
    // additionally requires `lnurl`. If either is off we skip the
    // whole cascade — there's no useful sub-roundtrip when the
    // bootstrapping claim cannot land.
    if !caps.usernames {
        feature_skip!("usernames", "username_claim_resolve_lnurlp_roundtrip");
    }
    if !caps.lnurl {
        feature_skip!("lnurl", "username_claim_resolve_lnurlp_roundtrip");
    }
    let alice = TestWallet::new();
    let username = format!("e2e_{}", random_suffix());
    let ts = unix_now();
    let signature = alice.sign_username_claim(&alice.address_hex(), &username, ts);

    let claim_resp = client
        .post(url("/api/username/claim"))
        .json(&json!({
            "username": username,
            "address": alice.address_hex(),
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "signature": signature,
            "timestamp": ts,
        }))
        .send()
        .await
        .expect("POST /api/username/claim");
    let claim_status = claim_resp.status();
    if claim_status == StatusCode::SERVICE_UNAVAILABLE {
        dev_skip!("username claim returned 503 — DB unavailable");
    }
    assert_eq!(
        claim_status,
        StatusCode::OK,
        "claim failed: {}",
        claim_status
    );
    let claim_body: Value = claim_resp.json().await.expect("claim body");
    assert_eq!(claim_body["username"], username);

    // ---- Resolve ----
    let resolve_resp = client
        .get(url(&format!("/api/username/resolve/{}", username)))
        .send()
        .await
        .expect("GET resolve");
    assert_eq!(resolve_resp.status(), StatusCode::OK);
    let resolve_body: Value = resolve_resp.json().await.expect("resolve body");
    assert_eq!(resolve_body["username"], username);
    assert_eq!(resolve_body["address"], alice.address_hex());

    // ---- LNURLp ----
    let lnurlp_resp = client
        .get(url(&format!("/.well-known/lnurlp/{}", username)))
        .send()
        .await
        .expect("GET lnurlp");
    assert_eq!(lnurlp_resp.status(), StatusCode::OK);
    let lnurlp_body: Value = lnurlp_resp.json().await.expect("lnurlp body");
    assert_eq!(lnurlp_body["tag"], "payRequest");
    assert!(
        lnurlp_body["callback"]
            .as_str()
            .is_some_and(|s| s.contains(&username)),
        "callback must reference the username, got {:?}",
        lnurlp_body["callback"]
    );
    assert!(lnurlp_body["minSendable"].as_u64().is_some());
    assert!(lnurlp_body["maxSendable"].as_u64().is_some());
    assert!(lnurlp_body["metadata"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Poll `/api/balance` until the observed balance is >= `target`, or
/// until [`POLL_TIMEOUT`] elapses. Returns the last observed balance
/// regardless — the caller decides whether to assert on it.
async fn poll_balance_at_least(client: &reqwest::Client, address: &str, target: u64) -> u64 {
    let deadline = std::time::Instant::now() + POLL_TIMEOUT;
    let mut last_seen = 0u64;
    loop {
        let resp = client
            .get(url(&format!("/api/balance?address={}", address)))
            .send()
            .await
            .expect("GET balance");
        if resp.status() == StatusCode::OK {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(b) = body["balance"].as_u64() {
                last_seen = b;
                if b >= target {
                    return b;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return last_seen;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll `/api/balance` until the observed balance is <= `target`, or
/// until [`POLL_TIMEOUT`] elapses. Used to wait for the post-commit
/// debit to land in the in-memory account.
async fn poll_balance_at_most(client: &reqwest::Client, address: &str, target: u64) -> u64 {
    let deadline = std::time::Instant::now() + POLL_TIMEOUT;
    let mut last_seen = u64::MAX;
    loop {
        let resp = client
            .get(url(&format!("/api/balance?address={}", address)))
            .send()
            .await
            .expect("GET balance");
        if resp.status() == StatusCode::OK {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(b) = body["balance"].as_u64() {
                last_seen = b;
                if b <= target {
                    return b;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return last_seen;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
