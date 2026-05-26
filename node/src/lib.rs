//! Library crate root for `node`.
//!
//! The server is primarily a binary (`main.rs`), but a few pieces of
//! it must be reachable from out-of-tree integration tests
//! (`node/tests/api_remote.rs` in particular). Exposing those
//! modules through a `lib` target keeps the binary side of the crate
//! untouched while letting the integration suite import the
//! `Capabilities` struct (for feature-gate detection on `/api/info`)
//! and the `CoinProof` struct used to decode the binary blobs
//! returned by `GET /api/proof/:id`. Other response types remain
//! reachable through their owning modules but are not currently
//! consumed by the suite.
//!
//! Everything declared here is also `use`d from `main.rs` so the
//! production binary keeps working with no change in behaviour.

// `Account::new()` and `State::new()` are visible from the lib root
// after the binary → bin+lib split. Clippy's `new_without_default`
// lint did not fire while these types lived in a `bin` target — the
// lint is library-target sensitive. Adding `Default` impls would
// change the public API of the crate (downstream callers could pick
// `Default::default()` over `::new()`), which is out of scope for
// this refactor. Suppress at the crate root so the lint stays off
// for the new lib target while the existing call sites stay
// untouched.
#![allow(clippy::new_without_default)]

pub mod account_node;
pub mod db;
pub mod publisher;
pub mod router;
pub mod runtime;
pub mod scanner;
pub mod scanner_runtime;
pub mod scanner_ws;
pub mod scanner_ws_parse;
pub mod state;
pub mod username;

use crate::publisher::EsploraConfig;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use lazy_static::lazy_static;
use sqlx::PgPool;
use std::str::FromStr;
use zkcoins_program::hash::HashDigest;

/// Pure builder for `NETWORK_CONFIG`. Extracted so the env-resolution
/// logic — in particular the panic-on-missing rules below — is
/// unit-testable without touching the process-wide environment or the
/// `lazy_static` cell (whose state would leak across tests in the same
/// binary).
///
/// ## Mainnet vs Mutinynet defaults
///
/// `ESPLORA_URL` and `ESPLORA_WS_URL` have Mutinynet defaults
/// (`https://mutinynet.com/api`, `wss://mutinynet.com/api/v1/ws`)
/// throughout the codebase. They are convenient for DEV (Mutinynet
/// the chain) and harmless for unit/integration tests. But on Mainnet
/// they are silent footguns: an `IS_MAINNET=true` deployment that
/// forgets to set either env publishes Mutinynet block events into
/// the scanner and / or fetches the wrong chain over REST. The
/// failure mode is asymmetric — an HTTP-only mismatch panics quickly
/// on the first publisher round-trip, but the event-driven scanner
/// (#84) sits in a 5 s HTTP-retry loop with no forward progress and
/// a green `/health/ready`.
///
/// To remove the footgun, both URLs are **required env vars when
/// `IS_MAINNET=true`** — the panic mirrors the existing pattern for
/// `PUBLISHER_KEY`, `USERNAME_DOMAIN`, and `DATABASE_URL`. Empty-
/// string values are treated as unset on the Mainnet path so a
/// misconfigured compose file (`ESPLORA_URL=`) panics with the same
/// diagnostic instead of silently producing `EsploraConfig.url = ""`.
/// When `IS_MAINNET` is unset or `false`, the Mutinynet defaults
/// continue to apply — DEV, the pre-push hook, and the M3 Ultra
/// coverage gate are all unaffected.
///
/// ## Scope of the guard
///
/// Only the `NETWORK_CONFIG` access path is hardened here.
/// `scanner_ws::ScannerWsConfig::from_env` and `publisher.rs` still
/// call `std::env::var("ESPLORA_WS_URL")` independently with a
/// Mutinynet fallback. In the production binary the panic in this
/// builder fires before any of those reads — `main.rs` dereferences
/// `NETWORK_CONFIG` during bootstrap — so the structural bypass is
/// unreachable today. A follow-up that has those sites consume
/// `NETWORK_CONFIG.ws_url` (or an explicit `&EsploraConfig`) directly
/// would close the bypass for future entry points and is tracked as
/// a separate refactor.
pub fn build_network_config_from_env<F>(env: F) -> EsploraConfig
where
    F: Fn(&str) -> Option<String>,
{
    // Treat empty strings as "unset" on the Mainnet path. Without
    // this, `ESPLORA_URL=` in a compose file bypasses the `expect`
    // below and leaves `EsploraConfig.url = ""` — the same class of
    // silent misconfiguration the panic is designed to surface.
    let env_or_unset = |k: &str| env(k).filter(|v| !v.trim().is_empty());
    let is_mainnet = env_or_unset("IS_MAINNET").as_deref() == Some("true");
    let url = if is_mainnet {
        env_or_unset("ESPLORA_URL").expect(
            "IS_MAINNET=true requires ESPLORA_URL to be set to a non-empty value — \
             the Mutinynet default is unsafe on Mainnet. Set ESPLORA_URL \
             to a Mainnet HTTP Esplora endpoint (e.g. http://electrs-mainnet:3000 \
             on the DFX Mainnet stack, or https://mempool.space/api)",
        )
    } else {
        env_or_unset("ESPLORA_URL").unwrap_or_else(|| "https://mutinynet.com/api".to_string())
    };
    let ws_url = if is_mainnet {
        Some(env_or_unset("ESPLORA_WS_URL").expect(
            "IS_MAINNET=true requires ESPLORA_WS_URL to be set to a non-empty value — \
             the Mutinynet default (wss://mutinynet.com/api/v1/ws) is unsafe on \
             Mainnet: the event-driven scanner subscribes to Mutinynet block \
             events and 404s against the Mainnet HTTP Esplora in a 5 s retry \
             loop with no forward progress (zk-coins/node #84). Set \
             ESPLORA_WS_URL to a Mainnet mempool.space-compatible WebSocket \
             (e.g. wss://mempool.space/api/v1/ws)",
        ))
    } else {
        env_or_unset("ESPLORA_WS_URL")
    };
    let network_name = env_or_unset("NETWORK_NAME").unwrap_or_else(|| {
        if is_mainnet {
            "Mainnet".to_string()
        } else {
            "Mutinynet".to_string()
        }
    });
    println!(
        "Network config: {} ({}) ws={}",
        network_name,
        url,
        ws_url
            .as_deref()
            .unwrap_or(crate::scanner_ws::DEFAULT_ESPLORA_WS_URL)
    );
    EsploraConfig {
        url,
        is_mainnet,
        network_name,
        ws_url,
        track_tx_timeout: None,
    }
}

lazy_static! {
    pub static ref NETWORK_CONFIG: EsploraConfig =
        build_network_config_from_env(|k| std::env::var(k).ok());

    /// Domain used by the client to render `<hex|username>@<domain>`.
    /// Distinct from `network_name` because the same Bitcoin network
    /// (e.g. Mutinynet) is served from two isolated test worlds
    /// (`dev.zkcoins.app`, `zkcoins.app`) — the client needs the
    /// stage's external hostname, not the chain identifier.
    pub static ref USERNAME_DOMAIN: String = {
        let domain = std::env::var("USERNAME_DOMAIN").expect(
            "USERNAME_DOMAIN env var must be set (e.g. `zkcoins.app` on PRD, \
             `dev.zkcoins.app` on DEV) — see #95 for the cross-network rationale",
        );
        println!("Username domain: {}", domain);
        domain
    };

    /// Publisher Bitcoin private key (32-byte hex). REQUIRED env var.
    /// No fallback default exists: the previous `1234567890abcdef…`
    /// placeholder was a publicly-known test key that drainer bots
    /// swept within minutes of any on-chain top-up. The matching
    /// public address is exposed by `GET /health/publisher`.
    pub static ref PUBLISHER_KEY: String = std::env::var("PUBLISHER_KEY")
        .expect("PUBLISHER_KEY env var must be set — no default exists. \
                 Generate a 32-byte hex secret via `openssl rand -hex 32`.");

    /// Taproot publisher address derived once at startup from
    /// `PUBLISHER_KEY` against the configured `NETWORK_CONFIG`. Folding
    /// the secp256k1 work into `lazy_static` keeps the request path of
    /// `publisher_health_handler` pure I/O (no per-request `SecretKey
    /// ::from_str` / `Address::p2tr`) and removes a structurally
    /// unreachable `Err` arm — `PUBLISHER_KEY` is validated here, so
    /// an invalid key panics at startup, not on the first health
    /// probe. Log-only, NOT a secret (the matching key lives in
    /// `PUBLISHER_KEY`).
    pub static ref PUBLISHER_ADDRESS: bitcoin::Address = {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_str(&PUBLISHER_KEY)
            .expect("PUBLISHER_KEY must be a valid 32-byte hex secp256k1 secret");
        let key_pair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
        bitcoin::Address::p2tr(&secp, xonly, None, NETWORK_CONFIG.network())
    };

    /// Postgres connection string for the state-layer. Required; the
    /// bootstrap refuses to start without it because there is no
    /// sensible default for a database URL.
    pub static ref DATABASE_URL: String = {
        std::env::var("DATABASE_URL").expect(
            "DATABASE_URL env var must be set (e.g. \
             postgresql://zkcoins:<pw>@postgres:5432/zkcoins)",
        )
    };
}

/// Run `db::persist_state_tx` from a *synchronous* context that already
/// lives on a tokio worker thread.
///
/// The scanner's `InscriptionCallback` is a sync `Fn`, but
/// `persist_state_tx` is async. The naive bridge —
/// `Handle::current().block_on(future)` — panics on the multi_thread
/// flavor. `block_in_place` is the documented sync-in-async escape
/// hatch for multi_thread runtimes.
///
/// `root_index_entry` carries the freshly-inserted `mmr_root_index`
/// row so the Phase-C write lands in the SAME Postgres transaction as
/// the SMT/MMR/latest_block snapshot — see the doc-comment on
/// `db::persist_state_tx` for the heal-on-restart rationale.
pub fn persist_state_from_sync_context(
    pool: &PgPool,
    smt: &[u8],
    mmr: &[u8],
    latest_block: &[u8; 32],
    root_index_entry: Option<(&HashDigest, &HashDigest, u64)>,
) -> Result<(), sqlx::Error> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(db::persist_state_tx(
            pool,
            smt,
            mmr,
            latest_block,
            root_index_entry,
        ))
    })
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
