//! Library crate root for `server`.
//!
//! The server is primarily a binary (`main.rs`), but a few pieces of
//! it must be reachable from out-of-tree integration tests
//! (`server/tests/api_remote.rs` in particular). Exposing those
//! modules through a `lib` target keeps the binary side of the crate
//! untouched while letting the integration suite import handler
//! response types (`SendCoinResponse`, `InfoResponse`, `Capabilities`,
//! `BalanceResponse`) and the `CoinProof` struct used to decode the
//! binary blobs returned by `GET /api/proof/:id`.
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

pub mod account_server;
pub mod db;
pub mod publisher;
pub mod scanner;
pub mod scanner_runtime;
pub mod server;
pub mod server_runtime;
pub mod state;
pub mod username;

use crate::publisher::EsploraConfig;
use lazy_static::lazy_static;
use sqlx::PgPool;

const DEFAULT_PUBLISHER_KEY: &str =
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

lazy_static! {
    pub static ref NETWORK_CONFIG: EsploraConfig = {
        let url = std::env::var("ESPLORA_URL")
            .unwrap_or_else(|_| "https://mutinynet.com/api".to_string());
        let is_mainnet = std::env::var("IS_MAINNET")
            .map(|v| v == "true")
            .unwrap_or(false);
        let network_name = std::env::var("NETWORK_NAME")
            .unwrap_or_else(|_| if is_mainnet { "Mainnet".to_string() } else { "Mutinynet".to_string() });
        println!("Network config: {} ({})", network_name, url);
        EsploraConfig { url, is_mainnet, network_name }
    };

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

    pub static ref PUBLISHER_KEY: String = {
        let key = std::env::var("PUBLISHER_KEY")
            .unwrap_or_else(|_| DEFAULT_PUBLISHER_KEY.to_string());
        if NETWORK_CONFIG.is_mainnet && key == DEFAULT_PUBLISHER_KEY {
            panic!("PUBLISHER_KEY env var must be set for mainnet");
        }
        key
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
pub fn persist_state_from_sync_context(
    pool: &PgPool,
    smt: &[u8],
    mmr: &[u8],
    latest_block: &[u8; 32],
) -> Result<(), sqlx::Error> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(db::persist_state_tx(
            pool,
            smt,
            mmr,
            latest_block,
        ))
    })
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
