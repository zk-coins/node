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
//!   - assert strictly on 4xx codes (client-fixable contract bugs)
//!   - assert strictly on 5xx codes as well (server-side regressions
//!     are real bugs, not flakes — the deploy-dev preflight verifies
//!     publisher wallet + /health/ready BEFORE this suite runs, so a
//!     503 here is unambiguous: it means something regressed)
//!
//! Read by:
//!   - `cargo test -p node --release --test api_remote` (locally)
//!   - the `api-e2e` job in `deploy-dev.yaml` after `build-and-deploy`
//!
//! Configuration:
//!   - `ZKCOINS_API_URL` (default `https://dev-api.zkcoins.app`) —
//!     the base URL of the server under test.

use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::secp256k1::{self as secp, Keypair, Message, PublicKey, SecretKey};
use bitcoin::Network;
use node::account_node::CoinProof;
use node::router::Capabilities;
use rand::RngCore;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use shared::commitment::Commitment;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zkcoins_program::hash::digest_to_bytes;
use zkcoins_program::types::MINTING_ADDRESS;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_API_URL: &str = "https://dev-api.zkcoins.app";
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const POLL_TIMEOUT: Duration = Duration::from_secs(60);
const MINT_AMOUNT: u64 = 50_000;
const SEND_AMOUNT: u64 = 10_000;
/// Bootstrap balance seeded into the `MINTING_ADDRESS` account at
/// startup by `start_rest_node` (see `node::runtime`).
/// Must stay strictly less than `2^48` for Plonky2 Goldilocks safety
/// — see the matching constant guard in `runtime_tests`. The
/// happy-path roundtrips probe `/api/balance` on `MINTING_ADDRESS`
/// before their first mint and use this as an upper bound —
/// `0 < balance <= BOOTSTRAP_MINTING_BALANCE`. The exact value is
/// not asserted because the deploy-dev push trigger does not run
/// `reset_state`, so prior test residue legitimately reduces the
/// minting balance; the bound still catches a fully empty / negative
/// state.
const BOOTSTRAP_MINTING_BALANCE: u64 = 1u64 << 48;

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

/// Helper: log a one-line "feature off" skip and return.
///
/// When running in CI (env `CI=true`) this is a hard panic instead of
/// a silent skip: CI is supposed to build with `--all-features`, so a
/// `feature_skip!` firing in CI is the canary for an accidentally
/// dropped `--all-features` flag in a workflow (e.g. someone copied
/// the local `cargo test` invocation into the workflow). Outside CI
/// the macro is still a skip — the suite is also runnable against a
/// feature-trimmed PRD deploy, where an absent route is expected.
///
/// Escape hatch: setting `ZKCOINS_E2E_ALLOW_FEATURE_TRIMMED_SERVER`
/// (any value, even empty) downgrades the CI panic back to a silent
/// skip. The dev-api / prd-api Docker images intentionally ship the
/// MVP-only feature set (`Dockerfile` `ARG FEATURES=`), so when the
/// suite runs `--all-features` against a feature-trimmed *server*
/// the gated `address_list` / `lnurl` tests must skip cleanly instead
/// of panicking the CI canary. The env var documents this as an
/// opt-in: workflows that point the suite at a trimmed server set it,
/// workflows that point it at a fully-featured server leave it unset
/// so the canary stays armed.
macro_rules! feature_skip {
    ($feature:expr, $test:expr) => {{
        let allow_trimmed_server =
            std::env::var("ZKCOINS_E2E_ALLOW_FEATURE_TRIMMED_SERVER").is_ok();
        if std::env::var("CI").is_ok() && !allow_trimmed_server {
            panic!(
                "feature `{}` disabled but running in CI — all-features build is required \
                 (set ZKCOINS_E2E_ALLOW_FEATURE_TRIMMED_SERVER=1 if the target server is \
                 intentionally feature-trimmed, e.g. the MVP-only DEV image)",
                $feature
            );
        }
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
// Mint (`/api/mint`) and the username routes (`/api/username/claim`,
// `/api/username/resolve/:u`) are part of the MVP and are always
// present, so they are no longer gated here. The remaining post-MVP
// routes (`address-list`, `lnurl`) are still optional: the default
// deploy ships without them and the axum fallback answers 404 instead
// of the per-handler error codes. We fetch `/api/info` once per gated
// test, deserialise the well-known `Capabilities` shape, and skip the
// rest of the test if the relevant feature flag is `false`.
//
// `ZKCOINS_FORCE_DISABLE_FEATURES` (comma-separated list, e.g.
// `address_list,lnurl`) overrides any flag returned by the server
// to `false`. This is the local dry-run hook — point the suite at the
// live DEV server, force features off, and confirm that every gated
// test prints `SKIP …` instead of hitting a disabled-on-paper but
// actually-running endpoint. Forcing `faucet` or `usernames` off is a
// no-op (the routes are always registered) and the flags are ignored.
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
    // Each capability field MUST be a bool — a missing field or a
    // non-bool value is a contract regression in `/api/info` and a
    // `.unwrap_or(false)` would silently mask it as "feature off".
    let mut caps = Capabilities {
        address_list: body["capabilities"]["address_list"].as_bool().expect(
            "/api/info capabilities.address_list must be a bool — missing field is a contract regression",
        ),
        faucet: body["capabilities"]["faucet"].as_bool().expect(
            "/api/info capabilities.faucet must be a bool — missing field is a contract regression",
        ),
        usernames: body["capabilities"]["usernames"].as_bool().expect(
            "/api/info capabilities.usernames must be a bool — missing field is a contract regression",
        ),
        lnurl: body["capabilities"]["lnurl"].as_bool().expect(
            "/api/info capabilities.lnurl must be a bool — missing field is a contract regression",
        ),
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
                "usernames" => {
                    // Usernames are permanent MVP — same shape as `faucet`.
                    eprintln!(
                        "ZKCOINS_FORCE_DISABLE_FEATURES: `usernames` is permanent MVP — ignored"
                    );
                }
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
    /// `SHA256("zkcoins:claim_username" || address_hex_str || normalised_username_str || timestamp_le8)`.
    ///
    /// The server canonicalises the username with `to_lowercase()`
    /// before hashing; wallets must sign over the same lowercase form
    /// or verification fails. The helper mirrors that to keep the
    /// signature path honest end-to-end.
    fn sign_username_claim(&self, address_hex: &str, username: &str, timestamp: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"zkcoins:claim_username");
        hasher.update(address_hex.as_bytes());
        hasher.update(username.to_lowercase().as_bytes());
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
    assert_eq!(body["service"], "zkcoins-node");
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
    assert_eq!(
        status,
        StatusCode::OK,
        "/health/ready must return 200 — failures: {:?}",
        body["failures"]
    );
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

/// Shape-only probe of `/health/publisher` — the JSON contract is
/// asserted here so the suite breaks if the field set changes, even
/// when the publisher wallet itself is empty (the deploy-dev
/// preflight separately enforces a non-zero UTXO count). 200 is
/// required: an Esplora-side error surfaces as 503 and we want that
/// to fail the suite, not be silently tolerated.
#[tokio::test]
async fn health_publisher_returns_well_formed_response() {
    let resp = http_client()
        .get(url("/health/publisher"))
        .send()
        .await
        .expect("GET /health/publisher");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "/health/publisher must return 200 — anything else means Esplora is unreachable or the publisher route regressed"
    );
    let body: Value = resp.json().await.expect("/health/publisher body is JSON");
    assert!(
        body["address"].as_str().is_some_and(|v| !v.is_empty()),
        "publisher address must be a non-empty string, got {:?}",
        body["address"]
    );
    assert!(
        body["utxo_count"].as_u64().is_some(),
        "utxo_count must be a u64, got {:?}",
        body["utxo_count"]
    );
    assert!(
        body["total_sats"].as_u64().is_some(),
        "total_sats must be a u64, got {:?}",
        body["total_sats"]
    );
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
    // The balance handler returns a `BalanceResponse` (not a
    // `SendCoinResponse`) on the 422 branches — so the body has
    // `balance: 0` and no `error` field. This anchors the contract:
    // any future refactor that swaps the body for a `handler_error_response`
    // envelope (with an `error: "Invalid hex"` string, matching the
    // app's `KNOWN_SERVER_ERRORS`) must update this assertion.
    let body: Value = resp.json().await.expect("balance body JSON");
    assert_eq!(body["balance"], 0, "422 balance body must report balance 0");
    assert!(
        body.get("error").is_none(),
        "balance 422 body must not carry an `error` field today (got {:?})",
        body.get("error")
    );
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
    // Same envelope shape as the invalid-hex branch above.
    let body: Value = resp.json().await.expect("balance body JSON");
    assert_eq!(body["balance"], 0, "422 balance body must report balance 0");
    assert!(
        body.get("error").is_none(),
        "balance 422 body must not carry an `error` field today (got {:?})",
        body.get("error")
    );
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
async fn resolve_unknown_username_returns_404() {
    let client = http_client();
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

    // Minting-account sanity guard: the deploy-dev workflow's
    // `push: branches: [develop]` trigger does NOT run
    // `reset-zkcoins-node`, so the minting balance is allowed to be
    // anywhere in (0, BOOTSTRAP_MINTING_BALANCE]. We only fail hard
    // on the genuinely impossible states (balance > bootstrap = code
    // regression or unauthorized re-seed; balance == 0 = unexpected
    // DB wipe). See `assert_minting_balance_in_bounds` for details.
    assert_minting_balance_in_bounds(&client).await;

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

    // Minting-account sanity guard — mirror of the one in
    // `mint_roundtrip_lands_balance_and_proof`. The deploy-dev
    // workflow's `push: branches: [develop]` trigger does NOT run
    // `reset-zkcoins-node`, so we cannot pin the minting balance to
    // an exact value (or even a small accept-set keyed off
    // `MINT_AMOUNT`): the balance accumulates `bootstrap - N*MINT_AMOUNT`
    // across every prior develop push that ran this suite. The
    // bounds-check still catches the impossible / catastrophic states
    // (balance > bootstrap = code regression or unauthorized re-seed;
    // balance == 0 = unexpected DB wipe).
    assert_minting_balance_in_bounds(&client).await;

    // ---- Mint ----
    // Post-#87 the scanner is event-driven (Esplora WS subscription),
    // so by the time `mint_roundtrip_lands_balance_and_proof` returns
    // 200 and writes alice-1's balance, the prior commitment is
    // already at-most-one-block away from being indexed in the SMT.
    // A `422 Unable to get merkle proofs` here is therefore a real
    // scanner-side regression, not a benign timing flake — the
    // previous PR-83-era retry loop is gone. Asserting `== 200`
    // surfaces it.
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
    let mint_body_text = mint_resp.text().await.unwrap_or_default();
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
    assert!(
        balance_before >= MINT_AMOUNT,
        "scanner never observed mint after MINT_AMOUNT={} (saw {})",
        MINT_AMOUNT,
        balance_before
    );

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

    // (No second poll needed — `poll_balance_at_least` above already
    // observed alice.balance >= MINT_AMOUNT; the inscription is therefore
    // on-chain and the scanner has ingested it. Removing the redundant
    // 15-s wait shaves test runtime without losing signal — if the
    // scanner regresses, the FIRST wait will fail.)

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
    let send_resp = client
        .post(url("/api/send"))
        .json(&send_body)
        .send()
        .await
        .expect("POST /api/send");
    let send_status = send_resp.status();
    let send_body_text = send_resp.text().await.unwrap_or_default();
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

    // Value-bearing assertions on the response payload: each hash
    // field must decode to exactly 32 bytes and be non-zero. A
    // shape-only `.is_some()` check was masking server bugs that
    // returned a placeholder zero-hash or a truncated hex string.
    let ash_hex = send_body["account_state_hash"]
        .as_str()
        .expect("account_state_hash present")
        .to_string();
    let ash_bytes = hex::decode(&ash_hex).expect("ash is hex");
    assert_eq!(ash_bytes.len(), 32, "account_state_hash must be 32 bytes");
    assert!(
        ash_bytes.iter().any(|&b| b != 0),
        "account_state_hash must be non-zero"
    );
    let ocr_hex = send_body["output_coins_root"]
        .as_str()
        .expect("output_coins_root present")
        .to_string();
    let ocr_bytes = hex::decode(&ocr_hex).expect("ocr is hex");
    assert_eq!(ocr_bytes.len(), 32, "output_coins_root must be 32 bytes");
    assert!(
        ocr_bytes.iter().any(|&b| b != 0),
        "output_coins_root must be non-zero"
    );
    assert!(send_proof_id > 0, "proof_id must be a positive u64");

    // ---- Commit ----
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
    // Claim + resolve are permanent MVP. The LNURLp leg still depends
    // on the `lnurl` Cargo feature — if it's off we skip the whole
    // cascade because the trailing well-known probe cannot succeed.
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
    // DB availability is covered separately by `/health/ready`'s `db`
    // failure tag; a 503 here means the username claim path itself
    // regressed and is treated as a hard failure (no `dev_skip!`).
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
    let min_sendable = lnurlp_body["minSendable"]
        .as_u64()
        .expect("minSendable must be a u64");
    let max_sendable = lnurlp_body["maxSendable"]
        .as_u64()
        .expect("maxSendable must be a u64");
    assert!(
        min_sendable >= 1,
        "minSendable must be >= 1 msat, got {}",
        min_sendable
    );
    assert!(
        max_sendable >= min_sendable,
        "maxSendable ({}) must be >= minSendable ({})",
        max_sendable,
        min_sendable
    );
    assert!(lnurlp_body["metadata"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

// ---------------------------------------------------------------------------
// Section 4 — value-bearing field coverage on wallet-app-facing routes
//
// The roundtrip tests above prove the happy path executes end-to-end;
// the tests in this section assert the EXACT shape and content of
// every response field the wallet app reads. A field that ships as
// `null` / `""` / `"0x00...0"` instead of a real value passes
// `.is_some()` but breaks the wallet — the assertions here catch that
// class of regression at the API layer instead of in the wallet's
// integration test loop.
// ---------------------------------------------------------------------------

/// Field coverage #1 — mint response carries the post-mint
/// commitment fields (`account_state_hash`, `output_coins_root`).
///
/// **Contract expectation.** The wallet app needs the same SMT-root
/// pair from the mint response that the send response already carries,
/// so its local account snapshot can advance without a second round
/// trip. Mirror of the strong-assertion block in
/// `send_commit_roundtrip_moves_balance:1090-1109`: each hash field
/// MUST be present, decode to exactly 32 bytes of hex, and be non-zero.
/// A shape-only `.is_some()` check would mask a server bug that
/// returned a placeholder zero-hash or a truncated hex string.
///
/// **Today the mint handler ships these fields as `None`** (see
/// `router::mint_handler`'s tail and the matching `None`s in
/// `runtime::broadcast_commit_and_deliver`), and the response struct
/// serialises them with `skip_serializing_if = Option::is_none`. The
/// test therefore fails against the current server — it is written
/// against the expected contract, not the current implementation, so
/// CI surfaces the gap until the server is updated to populate the
/// fields. See the task brief for the lockstep rationale.
#[tokio::test]
async fn mint_response_carries_state_hash_and_coins_root() {
    let client = http_client();
    let alice = TestWallet::new();

    assert_minting_balance_in_bounds(&client).await;

    let mint_resp = client
        .post(url("/api/mint"))
        .json(&json!({
            "account_address": alice.address_hex(),
            "amount": MINT_AMOUNT,
        }))
        .send()
        .await
        .expect("POST /api/mint");
    assert_eq!(mint_resp.status(), StatusCode::OK, "mint must succeed");
    let body: Value = mint_resp.json().await.expect("mint body JSON");

    assert_eq!(
        body["success"],
        Value::Bool(true),
        "mint success must be true"
    );
    let proof_id = body["proof_id"]
        .as_u64()
        .expect("proof_id present and a u64");
    assert!(
        proof_id > 0,
        "proof_id must be a positive u64, got {}",
        proof_id
    );

    // Value-bearing assertions on the two post-mint hash fields.
    // Mirrors the send-response block in
    // `send_commit_roundtrip_moves_balance:1090-1109` verbatim — the
    // mint client consumes the same pair to advance its local
    // account snapshot, so the same shape guarantees apply.
    let ash_hex = body["account_state_hash"]
        .as_str()
        .expect("account_state_hash present on mint response")
        .to_string();
    let ash_bytes = hex::decode(&ash_hex).expect("account_state_hash is hex");
    assert_eq!(
        ash_bytes.len(),
        32,
        "account_state_hash must be 32 bytes (got {})",
        ash_bytes.len()
    );
    assert!(
        ash_bytes.iter().any(|&b| b != 0),
        "account_state_hash must be non-zero on a real mint"
    );

    let ocr_hex = body["output_coins_root"]
        .as_str()
        .expect("output_coins_root present on mint response")
        .to_string();
    let ocr_bytes = hex::decode(&ocr_hex).expect("output_coins_root is hex");
    assert_eq!(
        ocr_bytes.len(),
        32,
        "output_coins_root must be 32 bytes (got {})",
        ocr_bytes.len()
    );
    assert!(
        ocr_bytes.iter().any(|&b| b != 0),
        "output_coins_root must be non-zero on a real mint"
    );

    // Balance must land — the proof is fetchable AND the balance is
    // credited. Value-bearing check on the side effect.
    let observed = poll_balance_at_least(&client, &alice.address_hex(), MINT_AMOUNT).await;
    assert!(
        observed >= MINT_AMOUNT,
        "balance never reached mint amount; got {observed}"
    );
}

/// Field coverage #2 — commit response carries the post-commit
/// commitment fields (`account_state_hash`, `output_coins_root`).
///
/// **Contract expectation.** Same as the mint test above — the wallet
/// app needs the SMT-root pair from the commit response so its local
/// account snapshot advances atomically with the broadcast. Each hash
/// field MUST be present, decode to exactly 32 bytes of hex, and be
/// non-zero. The full mint → send → commit pipeline is exercised
/// because the commit step is otherwise unreachable.
///
/// **Today the commit handler ships these fields as `None`** (see
/// `runtime::broadcast_commit_and_deliver`'s tail). The test is
/// written against the expected contract and fails against the
/// current server until the runtime is updated to populate the
/// fields.
#[tokio::test]
async fn commit_response_carries_state_hash_and_coins_root() {
    let client = http_client();
    let alice = TestWallet::new();
    let bob = TestWallet::new();

    assert_minting_balance_in_bounds(&client).await;

    // ---- Mint ----
    let mint_resp = client
        .post(url("/api/mint"))
        .json(&json!({
            "account_address": alice.address_hex(),
            "amount": MINT_AMOUNT,
        }))
        .send()
        .await
        .expect("POST /api/mint");
    assert_eq!(mint_resp.status(), StatusCode::OK, "mint must succeed");
    let mint_body: Value = mint_resp.json().await.expect("mint body JSON");
    let mint_proof_id = mint_body["proof_id"].as_u64().expect("mint proof_id");

    let _ = poll_balance_at_least(&client, &alice.address_hex(), MINT_AMOUNT).await;

    // ---- Fetch the mint proof for prev_commitment_pubkey ----
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
    let send_resp = client
        .post(url("/api/send"))
        .json(&json!({
            "account_address": alice.address_hex(),
            "recipient": bob.address_hex(),
            "amount": amount,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "next_public_key": hex::encode(alice.pubkey(1).serialize()),
            "prev_commitment_pubkey": hex::encode(prev_pk.serialize()),
            "signature": signature,
            "timestamp": ts,
        }))
        .send()
        .await
        .expect("POST /api/send");
    assert_eq!(send_resp.status(), StatusCode::OK, "send must succeed");
    let send_body: Value = send_resp.json().await.expect("send body JSON");
    let send_proof_id = send_body["proof_id"].as_u64().expect("send proof_id");
    let ash_hex = send_body["account_state_hash"]
        .as_str()
        .expect("send body carries account_state_hash")
        .to_string();
    let ocr_hex = send_body["output_coins_root"]
        .as_str()
        .expect("send body carries output_coins_root")
        .to_string();
    let ash_bytes = hex::decode(&ash_hex).expect("ash hex");
    let ocr_bytes = hex::decode(&ocr_hex).expect("ocr hex");

    // ---- Commit ----
    let mut commit_message = Vec::with_capacity(64);
    commit_message.extend_from_slice(&ash_bytes);
    commit_message.extend_from_slice(&ocr_bytes);
    let commit_sig = alice.sign_commit(&commit_message);
    let commit_resp = client
        .post(url("/api/commit"))
        .json(&json!({
            "proof_id": send_proof_id,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "signature": commit_sig,
            "message": hex::encode(&commit_message),
        }))
        .send()
        .await
        .expect("POST /api/commit");
    assert_eq!(commit_resp.status(), StatusCode::OK, "commit must succeed");
    let commit_body: Value = commit_resp.json().await.expect("commit body JSON");

    assert_eq!(
        commit_body["success"],
        Value::Bool(true),
        "commit success must be true"
    );
    let echoed_proof_id = commit_body["proof_id"]
        .as_u64()
        .expect("commit proof_id present and a u64");
    assert_eq!(
        echoed_proof_id, send_proof_id,
        "commit must echo the send proof_id (got {}, sent {})",
        echoed_proof_id, send_proof_id
    );

    // Value-bearing assertions on the post-commit hash fields. Same
    // contract as the send response (see
    // `send_commit_roundtrip_moves_balance:1090-1109`).
    let commit_ash_hex = commit_body["account_state_hash"]
        .as_str()
        .expect("account_state_hash present on commit response")
        .to_string();
    let commit_ash_bytes = hex::decode(&commit_ash_hex).expect("commit ash is hex");
    assert_eq!(
        commit_ash_bytes.len(),
        32,
        "commit account_state_hash must be 32 bytes (got {})",
        commit_ash_bytes.len()
    );
    assert!(
        commit_ash_bytes.iter().any(|&b| b != 0),
        "commit account_state_hash must be non-zero"
    );

    let commit_ocr_hex = commit_body["output_coins_root"]
        .as_str()
        .expect("output_coins_root present on commit response")
        .to_string();
    let commit_ocr_bytes = hex::decode(&commit_ocr_hex).expect("commit ocr is hex");
    assert_eq!(
        commit_ocr_bytes.len(),
        32,
        "commit output_coins_root must be 32 bytes (got {})",
        commit_ocr_bytes.len()
    );
    assert!(
        commit_ocr_bytes.iter().any(|&b| b != 0),
        "commit output_coins_root must be non-zero"
    );
}

/// Field coverage #3 — `/api/balance` carries the claimed username.
///
/// `BalanceResponse.username` is `Option<String>` with
/// `skip_serializing_if = Option::is_none`. After a successful
/// `/api/username/claim`, querying balance for the claimed address
/// MUST surface the exact (lowercased) username in the response body.
/// The wallet app reads this to render the "@<username>" badge next
/// to a balance figure without making a second round-trip.
#[tokio::test]
async fn balance_response_carries_username_after_claim() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    // `usernames` is permanent MVP per `fetch_capabilities`, so the
    // skip path is unreachable in practice — keep the gate honest in
    // case a future feature trim disables it.
    if !caps.usernames {
        feature_skip!("usernames", "balance_response_carries_username_after_claim");
    }

    let alice = TestWallet::new();
    let username = format!("u_{}", random_suffix());
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
    assert_eq!(claim_resp.status(), StatusCode::OK, "claim must succeed");

    // GET /api/balance and assert the username surfaces.
    let bal_resp = client
        .get(url(&format!(
            "/api/balance?address={}",
            alice.address_hex()
        )))
        .send()
        .await
        .expect("GET /api/balance after claim");
    assert_eq!(bal_resp.status(), StatusCode::OK);
    let body: Value = bal_resp.json().await.expect("balance body JSON");
    // Server canonicalises usernames to lowercase before persisting,
    // so the round-trip must compare against the lowercased form.
    let want = username.to_lowercase();
    assert_eq!(
        body["username"].as_str(),
        Some(want.as_str()),
        "balance body must carry the just-claimed username, got {:?}",
        body["username"]
    );
}

/// Field coverage #4 — `/api/username/claim` echoes the claimed
/// address. The roundtrip test asserts `username` only; the wallet
/// app reads BOTH fields (username + address) and uses the echoed
/// address to verify the claim landed on the wallet's own address
/// before persisting locally — a value-bearing assertion on `address`
/// is therefore required.
#[tokio::test]
async fn claim_response_carries_address() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.usernames {
        feature_skip!("usernames", "claim_response_carries_address");
    }
    let alice = TestWallet::new();
    let username = format!("u_{}", random_suffix());
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
    assert_eq!(claim_resp.status(), StatusCode::OK, "claim must succeed");
    let body: Value = claim_resp.json().await.expect("claim body JSON");
    assert_eq!(
        body["username"].as_str(),
        Some(username.to_lowercase().as_str()),
        "claim response must echo the lowercased username, got {:?}",
        body["username"]
    );
    assert_eq!(
        body["address"].as_str(),
        Some(alice.address_hex().as_str()),
        "claim response must echo the claimed address verbatim, got {:?}",
        body["address"]
    );
}

/// Field coverage #5 — `/api/balance` omits `username` for an unclaimed
/// wallet. `BalanceResponse.username` is `Option<String>` with
/// `skip_serializing_if = Option::is_none`, so an unclaimed account
/// MUST produce a JSON body that either omits the field entirely
/// (preferred) or sets it to `null`. The wallet app's response schema
/// permits both shapes; the assertion fails if the server returns
/// e.g. `""` (empty string) instead, which would render as a phantom
/// empty username in the UI.
#[tokio::test]
async fn balance_response_has_no_username_for_unclaimed_wallet() {
    let client = http_client();
    let wallet = TestWallet::new();
    // No claim happens — the wallet is fresh.
    let resp = client
        .get(url(&format!(
            "/api/balance?address={}",
            wallet.address_hex()
        )))
        .send()
        .await
        .expect("GET /api/balance for unclaimed wallet");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("balance body JSON");
    assert_eq!(
        body["balance"], 0,
        "fresh wallet must have zero balance, got {:?}",
        body["balance"]
    );
    match body.get("username") {
        // Preferred: field omitted entirely (`skip_serializing_if` path).
        None => {}
        // Permitted: explicit `null`.
        Some(Value::Null) => {}
        // Anything else (empty string, real string) is a contract
        // violation — the wallet app would mis-render it.
        Some(other) => panic!(
            "unclaimed wallet must produce no `username` (or null), got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// Section 5 — error-envelope contract
//
// Every non-2xx response the wallet app cares about MUST deserialise
// as `{ success: false, error: <non-empty string> }`. The error string
// is the lockstep anchor against `app/src/lib/api/errorMessages.ts ::
// KNOWN_SERVER_ERRORS` — if the server renames a string without
// updating the app's mapping, the user-facing message degrades to
// `Serverfehler <status>: <raw>`.
// ---------------------------------------------------------------------------

/// Error contract #6 — every 4xx send body is a structured envelope.
///
/// Asserts only the SHAPE of the body (`success: false`, `error`
/// non-empty string). The exact string is covered per-error by the
/// extended negative-path tests above and by the lockstep inventory
/// test below.
#[tokio::test]
async fn send_returns_structured_error_envelope() {
    // Use the "unknown account" path: a well-formed body with a
    // freshly-generated wallet that has never minted. Picked because
    // it is the cheapest provocation that exercises the
    // `send_coins_error_response` branch (the 422 invalid-hex paths
    // go through `handler_error_response`, which has its own envelope
    // shape — both are checked by the per-string assertions).
    let alice = TestWallet::new();
    let bob = TestWallet::new();
    let amount: u64 = 1;
    let ts = unix_now();
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, ts);
    let resp = http_client()
        .post(url("/api/send"))
        .json(&json!({
            "account_address": alice.address_hex(),
            "recipient": bob.address_hex(),
            "amount": amount,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "next_public_key": hex::encode(alice.pubkey(1).serialize()),
            "prev_commitment_pubkey": Option::<String>::None,
            "signature": Some(signature),
            "timestamp": Some(ts),
        }))
        .send()
        .await
        .expect("POST /api/send envelope check");
    let status = resp.status();
    assert!(status.is_client_error(), "expected 4xx, got {}", status);
    let body: Value = resp.json().await.expect("envelope body must be JSON");
    assert_eq!(
        body["success"],
        Value::Bool(false),
        "envelope must carry success=false, got {:?}",
        body["success"]
    );
    let error = body["error"]
        .as_str()
        .expect("envelope must carry an `error` string");
    assert!(!error.is_empty(), "envelope `error` must be non-empty");
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

/// Fetch the current balance of the well-known `MINTING_ADDRESS`.
/// Used by the fresh-state guard at the top of the happy-path
/// roundtrips to detect a dirty DEV state (prior mint residue or a
/// missed `reset_state` run).
async fn fetch_minting_balance(client: &reqwest::Client) -> u64 {
    let minting_hex = format!("0x{}", hex::encode(digest_to_bytes(&MINTING_ADDRESS)));
    let resp = client
        .get(url(&format!("/api/balance?address={}", minting_hex)))
        .send()
        .await
        .expect("GET /api/balance for MINTING_ADDRESS");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "/api/balance must return 200 for MINTING_ADDRESS"
    );
    let body: Value = resp.json().await.expect("balance body is JSON");
    body["balance"].as_u64().expect("balance must be a u64")
}

/// Assert that the minting account exists and its balance has not
/// somehow exceeded the bootstrap value. Allows for arbitrary prior
/// mints in the same DB lifetime (each mint reduces the balance, never
/// increases it).
///
/// Hard-fails if:
/// - balance > BOOTSTRAP_MINTING_BALANCE (impossible without a code bug
///   or unauthorized re-seed), OR
/// - balance == 0 with no inflight mints (suggests an unwanted reset
///   or DB wipe between deploys)
///
/// The deploy-dev workflow's `push: branches: [develop]` trigger does
/// NOT run `reset-zkcoins-node`; that command requires explicit
/// `workflow_dispatch` with `reset_state: true`. Strict equality with
/// BOOTSTRAP_MINTING_BALANCE would therefore tripwire CI on the second
/// push after any reset. Use this upper-bound assertion instead.
async fn assert_minting_balance_in_bounds(client: &reqwest::Client) {
    let balance = fetch_minting_balance(client).await;
    assert!(
        balance <= BOOTSTRAP_MINTING_BALANCE,
        "minting balance {} > bootstrap {} — code regression or unauthorized re-seed",
        balance,
        BOOTSTRAP_MINTING_BALANCE,
    );
    assert!(
        balance > 0,
        "minting balance is 0 — likely an unexpected reset_state run or DB wipe; \
         check the deploy-dev workflow's recent runs"
    );
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
