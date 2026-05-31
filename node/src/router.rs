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
use shared::ClientAccount;
use shared::{Invoice, ProofData};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tower_http::cors::CorsLayer;
use utoipa::ToSchema;
use zkcoins_program::hash::{digest_from_bytes, digest_to_bytes};
use zkcoins_prover::Proof;

use crate::account_node::{AccountNode, CoinProof};
use crate::db;
use crate::db::InscriptionSummary;
use crate::publisher::create_and_broadcast_inscription;
use crate::publisher::EsploraConfig;
use crate::username::UsernameStore;
use crate::{NETWORK_CONFIG, USERNAME_DOMAIN};

/// Maximum allowed clock skew between the wallet's signed timestamp
/// and the server's wall clock. Matches the legacy in-helper window
/// extracted into [`check_timestamp_window`] so the existing app
/// behaviour is unchanged.
pub(crate) const MAX_TIMESTAMP_SKEW_SECS: u64 = 300;

/// Validate that `timestamp` is within [`MAX_TIMESTAMP_SKEW_SECS`] of
/// the server's wall clock. Extracted so signed handlers can run the
/// timestamp gate explicitly BEFORE `verify_send_signature` — emitting
/// the distinct `"Request timestamp too old or in the future"` string
/// the app's `KNOWN_SERVER_ERRORS` table maps. Folding it back into the
/// signature path would collapse both branches to
/// `"Signature verification failed"`, hiding a clock-skew misconfiguration
/// behind a generic crypto failure.
pub(crate) fn check_timestamp_window(timestamp: u64) -> Result<(), &'static str> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.abs_diff(timestamp) > MAX_TIMESTAMP_SKEW_SECS {
        return Err("Request timestamp too old or in the future");
    }
    Ok(())
}

/// Verify a Schnorr signature over send request fields.
/// Message = SHA256(account_address || recipient || amount || timestamp)
///
/// Callers MUST run [`check_timestamp_window`] first — this helper no
/// longer enforces the freshness window so the handler can surface
/// `"Request timestamp too old or in the future"` as its own status,
/// rather than collapsing it into `"Signature verification failed"`.
/// `request.signature` and `request.timestamp` are also required by the
/// time this helper runs (the handler returns 401 with
/// `"Missing signature"` / `"Missing timestamp"` upstream); the
/// `Option`-shaped `?` arms below stay as defence-in-depth.
fn verify_send_signature(request: &SendCoinRequest) -> Result<(), &'static str> {
    let signature_hex = request.signature.as_deref().ok_or("Missing signature")?;
    let timestamp = request.timestamp.ok_or("Missing timestamp")?;

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

/// Phase E failure modes returned by [`apply_commit_and_persist_phase_e`].
///
/// Each variant maps 1:1 to the two distinct error arms in the shared
/// helper: an in-process `state.update` rejection (typically an SMT
/// key-collision-with-different-value, observed-but-rare), or a
/// post-update durable-write rollback. The caller (mint or send) maps
/// the variant onto its own flow-tagged response string so the public
/// error message stays exactly as the wallet-side
/// `KNOWN_SERVER_ERRORS` table expects per endpoint.
#[derive(Debug)]
pub(crate) enum PhaseEFailure {
    /// `update_and_snapshot_for_persist` returned an `Err` — the
    /// in-process SMT/MMR could not be advanced (typical cause: SMT
    /// key collision with different value). The broadcast already
    /// landed on chain; the scanner-replay path will reconcile.
    StateUpdate,
    /// `persist_state_and_mark_complete_tx` failed — the atomic tx
    /// rolled back so SMT/MMR/root_index AND the
    /// `pending_inscriptions.status -> 'complete'` advance all stayed
    /// at their pre-call values on disk. The in-memory SMT/MMR HAVE
    /// already mutated; on restart `State::load_from_pg` returns the
    /// pre-update on-disk state and the scanner-replay path heals.
    DurablePersist,
}

/// Apply a freshly-broadcast commitment to the in-memory SMT + MMR
/// and persist the resulting snapshot **atomically** with the matching
/// `pending_inscriptions.status -> 'complete'` advance.
///
/// This is the shared Phase E body invoked by both flows that originate
/// inscriptions on this node:
/// * [`mint_handler`] — for mint commits, immediately after
///   `create_and_broadcast_inscription` returns Ok.
/// * [`crate::runtime::broadcast_commit_and_deliver`] — for send
///   commits, immediately after the user-signed commitment is
///   broadcast.
///
/// The symmetry matters: before this helper existed, the send path
/// relied exclusively on the async scanner to observe the commit on
/// chain and run `state.update` itself. That left a race window in
/// which a wallet could chain `/api/send` + `/api/commit` and then
/// issue a second `/api/send` whose proof-build walks the SMT for the
/// first send's commitment — and finds it missing because the scanner
/// hadn't yet observed the new inscription (especially on Mutinynet
/// where reveal-broadcast → scanner-observe sits at tens of seconds).
/// Running Phase E synchronously here closes that window: by the time
/// the handler responds 200, the SMT entry for the just-broadcast
/// commitment is committed in memory AND on disk, and the scanner
/// will skip its redundant integration via
/// `should_skip_scanner_state_update`. The scanner remains the
/// authoritative path for external / recovery inscriptions.
///
/// ## Lock topology (preserved across both callers)
/// The function acquires `state.account_node` only to clone its
/// `Arc<Mutex<State>>` reference, then drops the account-node guard
/// **before** acquiring the state guard. `std::sync::Mutex` is held
/// only across the synchronous `update_and_snapshot_for_persist` call
/// and is released before the async `persist_state_and_mark_complete_tx`
/// — keeping a `std::sync::Mutex` off any `.await` boundary.
///
/// ## Error handling (no fallbacks)
/// On Err the caller logs and converts to 503. There is **no in-process
/// retry, no spawn-async-retry, no half-state cleanup attempt** — the
/// scanner-replay path is the single source of repair, identical for
/// mint and send. See the memory rule on no-fallbacks for why this is
/// not a robustness gap.
pub(crate) async fn apply_commit_and_persist_phase_e(
    state: &AppState,
    commitment: &Commitment,
    commit_txid_bytes: &[u8; 32],
    flow_label: &'static str,
) -> Result<zkcoins_program::hash::HashDigest, PhaseEFailure> {
    // Test-only deterministic hold between the broadcast result and
    // the phase-3b state advance. Pre-unlocked in all `test_state`
    // constructors so production-shaped tests acquire + drop in one
    // step. Holding the guard across a colliding SMT injection lets
    // the in-process state.update Err test observe the collision when
    // the handler's `state.update` finally runs. Production builds
    // compile this out entirely (the field does not exist).
    #[cfg(test)]
    drop(state.state_advance_release_lock.lock().await);

    let state_advance_outcome = {
        let state_arc_for_advance = {
            let account_node_guard = lock_or_recover(&state.account_node);
            account_node_guard.state().clone()
        };
        let mut state_guard = lock_or_recover(&state_arc_for_advance);
        state_guard.update_and_snapshot_for_persist(std::slice::from_ref(commitment))
    };
    let (new_root, smt_bytes, mmr_bytes, root_index_entry) = match state_advance_outcome {
        Ok(snapshot) => snapshot,
        Err(e) => {
            // The in-process SMT/MMR could not be advanced — typically
            // an SMT key-collision-with-different-value. The broadcast
            // already landed on chain; the publisher already advanced
            // the row to `reveal_broadcast` BEFORE the broadcast call,
            // so the scanner-replay path will pick the inscription up
            // from chain and run state.update against the un-mutated
            // SMT.
            eprintln!(
                "{}: in-process state.update failed: {} (broadcast already landed; scanner-replay will reconcile)",
                flow_label, e
            );
            return Err(PhaseEFailure::StateUpdate);
        }
    };
    let root_index_ref = root_index_entry.as_ref().map(|(p, s, i)| (p, s, *i as u64));
    match db::persist_state_and_mark_complete_tx(
        &state.pool,
        &smt_bytes,
        &mmr_bytes,
        root_index_ref,
        &commit_txid_bytes[..],
    )
    .await
    {
        Ok(()) => {
            println!(
                "{}: state.update persisted + row marked complete. New MMR root: {}",
                flow_label,
                hex::encode(zkcoins_program::hash::digest_to_bytes(&new_root))
            );
            Ok(new_root)
        }
        Err(e) => {
            // The atomic tx rolled back: SMT/MMR/root_index AND the
            // row advance all stayed at their pre-call values on disk.
            // The in-memory SMT/MMR HAVE already been mutated (that
            // happened above before the await), so they are now ahead
            // of disk by exactly one leaf. On restart,
            // `State::load_from_pg` returns the pre-update on-disk
            // state and the scanner-replay path walks the block,
            // observes the row at `reveal_broadcast`, and integrates
            // the inscription itself — a clean heal.
            eprintln!(
                "{}: atomic persist + mark-complete failed: {} (scanner-replay will heal)",
                flow_label, e
            );
            Err(PhaseEFailure::DurablePersist)
        }
    }
}

// Define a struct for our application state
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) account_node: Arc<Mutex<AccountNode>>,
    pub(crate) proof_store: Arc<ProofStore>,
    pub(crate) minting_account: Arc<Mutex<ClientAccount>>,
    pub(crate) username_store: Arc<Mutex<UsernameStore>>,
    /// Postgres pool for per-account upserts (accounts table); the
    /// minting account's `num_pubkeys` is derived from SMT membership
    /// at runtime (Phase D), no separately-stored counter. Cloned
    /// cheaply via `Arc`; the underlying connections are pooled.
    pub(crate) pool: Arc<PgPool>,
    /// Esplora endpoint configuration consumed by the `/health/ready`
    /// readiness probe and by the mint-flow inscription broadcast in
    /// `mint_handler`. Injecting the config through `AppState` lets
    /// tests redirect Esplora calls at a `wiremock::MockServer`
    /// without having to mutate the process-wide `NETWORK_CONFIG`
    /// lazy_static (which is frozen on first access and shared across
    /// every test in the binary). In production `start_rest_node`
    /// clones `NETWORK_CONFIG` into this slot so the runtime
    /// behaviour is unchanged.
    pub(crate) esplora_config: Arc<EsploraConfig>,
    /// Background-warmup readiness flag. Default `false` at bootstrap
    /// start; flipped to `true` either (a) once the background
    /// `spawn_blocking` task in `runtime::start_rest_node` reports that
    /// `AccountNode::warmup_prover` returned Ok — at which point the
    /// Rayon worker pool is warm and every subsequent `/api/mint` /
    /// `/api/send` proof matches the steady-state ~5 s p50 — or (b)
    /// immediately at bootstrap when `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1`
    /// is set (no background task is spawned in that case).
    ///
    /// Consumed by `/health/ready`: while `prover_warm == false` the
    /// handler returns 503 with a `prover: warming` tag so a rolling
    /// deploy can keep the previous-generation pod taking traffic
    /// until the new pod's prover is warm. The liveness probe
    /// `/health` is unaffected — it returns 200 the moment the
    /// listener binds, so container restart loops keyed on liveness
    /// are not triggered during the ~21 s warmup window.
    pub(crate) prover_warm: Arc<AtomicBool>,
    /// Test-only synchronisation primitive used by
    /// `mint_handler_concurrent_mint_during_proof_returns_503`. The
    /// production code path notifies via `notify_one()` after entering
    /// phase 2 of `mint_handler` (after the `account_node` guard is
    /// acquired) so the test can `.notified().await` deterministically
    /// instead of `tokio::time::sleep(200ms)`. Hidden behind
    /// `cfg(test)` so the field does not exist in release builds.
    #[cfg(test)]
    pub(crate) phase2_reached: Arc<tokio::sync::Notify>,
    /// Test-only deterministic hold between `prepare_mint` (phase 2)
    /// and the phase-3 re-derive. The handler acquires + immediately
    /// drops this mutex AFTER `prepare_mint` returns and BEFORE the
    /// re-derive reads SMT membership. Constructed unlocked so all
    /// production-shaped tests proceed immediately (acquire is a
    /// non-blocking no-op). The concurrent-mint race test grabs the
    /// guard BEFORE spawning the request, holds it across the pk_N
    /// injection, then drops it — a hard happens-before edge that
    /// works for any number of sequential mints (unlike a `Notify`
    /// where one consumed permit would block subsequent waiters).
    /// Hidden behind `cfg(test)` so the field does not exist in
    /// release builds.
    #[cfg(test)]
    pub(crate) phase3_release_lock: Arc<tokio::sync::Mutex<()>>,
    /// Test-only deterministic hold between the broadcast result and
    /// the phase-3b state advance (`update_and_snapshot_for_persist`).
    /// Mirrors `phase3_release_lock`: the handler acquires + immediately
    /// drops this mutex AFTER `create_and_broadcast_inscription` returns
    /// and BEFORE acquiring the state lock to apply the new commitment.
    /// Constructed unlocked so production-shaped tests proceed
    /// immediately. The in-process state.update Err test grabs the
    /// guard before spawning the request, lets the handler run through
    /// broadcast, injects the colliding SMT entry, then drops the
    /// guard — at which point the handler's `state.update` observes
    /// the collision and returns 503. Hidden behind `cfg(test)` so the
    /// field does not exist in release builds.
    #[cfg(test)]
    pub(crate) state_advance_release_lock: Arc<tokio::sync::Mutex<()>>,
}

// Response types for our API
#[derive(Serialize, Deserialize, ToSchema)]
pub struct BalanceResponse {
    /// Total spendable balance of the account, in atomic zkCoin units.
    /// `u64::MAX` for the minting account.
    balance: u64,
    /// Username bound to this address, if any has been claimed.
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    /// Authoritative BIP-32 child-index counter for the queried account.
    ///
    /// Equals the number of times this account has executed a
    /// `/api/send` (`account.num_sends`). The wallet uses this value
    /// as `numPubkeys` for the next signing/derivation: the pubkey
    /// for the next send is at index `num_sends`.
    ///
    /// The wallet does NOT use it to derive `prev_commitment_pubkey`
    /// anymore — the server reads that one from its own state
    /// (`Account::commitment_public_key`) and the legacy
    /// `prev_commitment_pubkey` field on `SendCoinRequest` is
    /// ignored. See the field doc on `Account::commitment_public_key`
    /// for the bug class this eliminated (seed restore +
    /// stale-deploy + TOCTOU drift between local counter and server
    /// state, all surfacing as 400
    /// `"prev_commitment_pubkey required for account update"` in
    /// `07-send.spec.ts::send-success`).
    ///
    /// Always emitted (no `skip_serializing_if`) so the wallet can
    /// rely on its presence — `0` is the canonical value for an
    /// account that has never sent (matches `Account::new()`).
    #[serde(default)]
    num_sends: u32,
}

#[cfg(any(feature = "address-list", feature = "lnurl"))]
#[derive(Serialize, Deserialize, ToSchema)]
pub struct AddressesResponse {
    /// Known account addresses as `0x`-prefixed 32-byte hex strings.
    addresses: Vec<String>,
}

// ----- /api/history (issue #153) ------------------------------------------

/// Default page size when `/api/history?limit` is omitted.
pub(crate) const HISTORY_DEFAULT_LIMIT: i64 = 50;
/// Hard cap on `/api/history?limit`. Anything outside `[1, MAX]` is a
/// 400 — clamping silently was rejected as a footgun (callers that pass
/// `limit=1000` should learn about the cap, not get an unexplained 200
/// with 200 rows).
pub(crate) const HISTORY_MAX_LIMIT: i64 = 200;

/// `?address=&limit=&offset=` query for `GET /api/history`. All three
/// are parsed via the typed `Query` extractor so axum surfaces a 400 on
/// a non-integer `limit` / `offset` without the handler having to
/// re-parse.
#[derive(Deserialize)]
pub(crate) struct HistoryQuery {
    pub address: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// One entry in the `/api/history` response. Field names match the
/// issue #153 contract verbatim; `null`-able fields use `Option<T>`
/// with `serialize_with = Some` so the wire shape stays
/// `"field": null` rather than the field being elided.
///
/// Memo / counterparty / block_height stay `null` today: the current
/// schema does not store the recipient address per-mutation
/// (`account_history` is keyed on the address that changed, not the
/// counterparty), no memo column exists, and `triggering_commit_txid`
/// is unset by every Rust caller — see [`db::AccountHistoryRow::commit_txid`]
/// for the GUC-plumbing story.
#[derive(Serialize)]
pub struct HistoryItem {
    /// Server-internal monotonic id. Always set — sourced from
    /// `account_history.id`.
    pub id: i64,
    /// Bitcoin txid (lower-case hex, 64 chars) of the commit inscription
    /// for this state change, once the publisher has broadcast it.
    /// `null` while no commit_txid is linked to the row.
    pub txid: Option<String>,
    /// Unix epoch in seconds of the state change.
    pub timestamp: i64,
    /// `"send"`, `"receive"`, or `"mint"`. `scanner` / `recovery`
    /// `account_history` rows are filtered out before the handler maps
    /// to this enum.
    pub direction: &'static str,
    /// Absolute balance delta in sats (`|new_balance − prev_balance|`).
    /// For a `receive` / `mint` this is the amount credited; for a
    /// `send` this is the amount debited.
    pub amount: u64,
    /// Counterparty address (lower-case hex, 64 chars). Always `null`
    /// in the current schema — see the type-level doc-comment.
    pub counterparty: Option<String>,
    /// `"pending"`, `"confirmed"`, or `"failed"`. Every persisted
    /// `account_history` row reflects a state mutation that committed
    /// in Postgres, so the default is `"confirmed"`; the alternative
    /// values surface once the `pending_inscriptions` join lights up.
    pub status: &'static str,
    /// Bitcoin block height that contains the commit inscription, or
    /// `null` while the scanner has not integrated it (and while the
    /// `commit_txid` link is missing).
    pub block_height: Option<i64>,
    /// Free-text memo attached to the operation. Always `null` — no
    /// memo column exists in the current schema.
    pub memo: Option<String>,
}

/// Paginated wrapper around [`HistoryItem`]. `total` is the unfiltered
/// count for the queried address (not the count of returned `items`)
/// so the caller can drive pagination without a separate query.
#[derive(Serialize)]
pub struct HistoryResponse {
    pub items: Vec<HistoryItem>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// JSON envelope returned by the validation-failure branches of
/// `get_history_handler`. Distinct from the existing `SendCoinResponse`
/// shape because `/api/history` is a read endpoint with no `success` /
/// `proof_id` machinery — a flat `{ "error": "..." }` is the contract
/// the issue documents.
#[derive(Serialize)]
pub struct HistoryErrorResponse {
    pub error: &'static str,
}

/// Decode the 64-char (or 64 char + 0x prefix) hex `address` argument
/// into the raw 32-byte form `account_history.address` is keyed on.
/// Reuses the exact decode + length rules `get_balance_handler` applies
/// — `Err` on non-hex characters or a length that does not unpack to
/// 32 bytes.
pub(crate) fn decode_history_address(raw: &str) -> Result<[u8; 32], &'static str> {
    let bytes = hex::decode(raw.trim_start_matches("0x")).map_err(|_| "Invalid address hex")?;
    if bytes.len() != 32 {
        return Err("Address must be 32 bytes (64 hex chars)");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Map an `account_history.source` string into the user-facing
/// `direction` enum. Returns `None` for the `scanner` and `recovery`
/// sources, which are internal mutations the user did not initiate and
/// the handler filters out before serialising.
pub(crate) fn map_history_direction(source: &str) -> Option<&'static str> {
    match source {
        "mint" => Some("mint"),
        "send" => Some("send"),
        "receive" => Some("receive"),
        // `scanner` and `recovery` are internal replays / operator-only
        // mutations. Surface a `None` so the handler skips them.
        _ => None,
    }
}

/// Recover the usable balance out of a bincode-serialised
/// [`crate::account_node::Account`] blob. Returns `None` if the bytes
/// fail to round-trip — defensive, the handler treats a decode failure
/// as a missing prior balance (so the delta collapses to the absolute
/// new balance instead of producing a fabricated number).
///
/// Mirrors [`crate::account_node::Account::get_balance`]: the settled
/// `balance` field plus pending receives sitting in `coin_queue`.
/// Mints and receives push the credited coin into `coin_queue` without
/// touching `balance` until a subsequent send drains the queue into
/// `coin_history`; reading only `a.balance` here would report `0` for
/// the very transactions the history endpoint is meant to surface (the
/// E2E suite catches this as `amount = 0` on first mint).
///
/// `saturating_add` is used because the two summands come out of an
/// untrusted on-disk blob; in practice overflow is impossible (per-coin
/// amounts and `Account.balance` are both bounded by the minting
/// account's supply), but capping at `u64::MAX` is preferable to a
/// panic on a corrupted row.
pub(crate) fn balance_from_account_blob(blob: &[u8]) -> Option<u64> {
    let a = bincode::deserialize::<crate::account_node::Account>(blob).ok()?;
    let queued: u64 = a
        .coin_queue
        .iter()
        .fold(0u64, |acc, cp| acc.saturating_add(cp.coin.amount));
    Some(a.balance.saturating_add(queued))
}

/// Typed mirror of the `pending_inscriptions.status` CHECK constraint
/// (migration 0003: `constructed`, `commit_broadcast`, `reveal_broadcast`,
/// `complete`, `failed`). Parsed via [`PendingInscriptionStatus::from_db_str`]
/// so the `match` in [`history_row_to_item`] can be exhaustive and a
/// future schema state addition forces compile-time attention — a plain
/// `match row.pending_status.as_deref()` on a `String` can't enforce
/// that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingInscriptionStatus {
    Constructed,
    CommitBroadcast,
    RevealBroadcast,
    Complete,
    Failed,
}

impl PendingInscriptionStatus {
    /// Map a raw `pending_inscriptions.status` string to the enum.
    /// Returns `None` for an unrecognised value — Postgres's CHECK
    /// constraint prevents that in practice, but if it ever leaks the
    /// handler degrades to `pending` rather than crash.
    pub(crate) fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "constructed" => Some(Self::Constructed),
            "commit_broadcast" => Some(Self::CommitBroadcast),
            "reveal_broadcast" => Some(Self::RevealBroadcast),
            "complete" => Some(Self::Complete),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Convert one [`db::AccountHistoryRow`] into a wire [`HistoryItem`].
/// Returns `None` if the row's source is internal (`scanner` /
/// `recovery`), if the `new_data` blob fails to decode, or if a
/// non-null `prev_data` blob fails to decode (treating that as zero
/// would fabricate a full-balance delta — see the inner `match` for
/// the warn log).
pub(crate) fn history_row_to_item(row: &crate::db::AccountHistoryRow) -> Option<HistoryItem> {
    let direction = map_history_direction(&row.source)?;
    let new_balance = balance_from_account_blob(&row.new_data)?;
    // `prev_data` is `None` on the first INSERT for an address — treat
    // that as a from-zero delta so the very first mint / receive
    // surfaces the full credit instead of disappearing. A `Some(blob)`
    // that fails to decode is *not* the same as `None`: silently
    // collapsing to zero would fabricate the full new balance as the
    // delta. Drop the row instead and log a warn so an operator can
    // notice the schema drift.
    let prev_balance = match row.prev_data.as_deref() {
        None => 0,
        Some(blob) => match balance_from_account_blob(blob) {
            Some(b) => b,
            None => {
                let blob_len = blob.len();
                tracing::warn!(
                    "history_row_to_item: row id={} address has un-decodable prev_data blob (len={}); dropping row to avoid fabricating a full-balance delta",
                    row.id,
                    blob_len,
                );
                return None;
            }
        },
    };
    // Absolute delta — sends are debits (prev > new), mints / receives
    // are credits (new > prev). The `direction` field already encodes
    // the sign for the caller.
    let amount = new_balance.max(prev_balance) - new_balance.min(prev_balance);

    // Wire status derived from `pending_inscriptions.status` (the
    // authoritative state machine) joined to `observed_inscriptions`
    // for the post-broadcast on-chain confirmation. A DB-committed
    // `account_history` row only proves a server-side state change —
    // *not* an on-chain confirmation — so the default before any
    // matching inscription row exists is `pending`, not `confirmed`.
    //
    // The inner `match pending` is exhaustive over the
    // [`PendingInscriptionStatus`] enum (which mirrors migration 0003's
    // CHECK constraint). A future state added to the enum will fail to
    // compile here — no silent `_ => "pending"` catch-all.
    //
    // The unknown-string case is handled separately via
    // `from_db_str` returning `None`: Postgres's CHECK constraint
    // already prevents that, but if it ever leaks we warn and degrade
    // to `pending` rather than crash.
    let pending_enum = row
        .pending_status
        .as_deref()
        .map(|s| (s, PendingInscriptionStatus::from_db_str(s)));
    let status = match pending_enum {
        Some((_, Some(p))) => match p {
            PendingInscriptionStatus::Complete => "confirmed",
            PendingInscriptionStatus::Failed => "failed",
            PendingInscriptionStatus::Constructed
            | PendingInscriptionStatus::CommitBroadcast
            | PendingInscriptionStatus::RevealBroadcast => "pending",
        },
        Some((raw, None)) => {
            tracing::warn!(
                "history_row_to_item: unknown pending_inscriptions.status={:?} (id={}); defaulting to pending",
                raw,
                row.id,
            );
            "pending"
        }
        // No pending_inscriptions row but the scanner has observed the
        // inscription on-chain — it's confirmed even though we lost the
        // pending row (the resumer prunes `complete` rows after a
        // safe-depth threshold).
        None if row.block_height.is_some() => "confirmed",
        // Neither pending nor observed — the on-chain side is not yet
        // known to us; the DB write alone does not warrant `confirmed`.
        None => "pending",
    };

    Some(HistoryItem {
        id: row.id,
        txid: row.commit_txid.as_deref().map(hex::encode),
        timestamp: row.timestamp_secs,
        direction,
        amount,
        // TODO(zk-coins/node#160): capture `counterparty_address` per
        // `account_history` row (schema change) so this stops being
        // unconditionally null.
        counterparty: None,
        status,
        block_height: row.block_height,
        memo: None,
    })
}

#[derive(Deserialize, ToSchema)]
pub struct SendCoinRequest {
    /// Sender account address (`0x`-prefixed 32-byte hex, sha256 over the
    /// sender's BIP-32 root public key).
    account_address: String,
    /// Recipient identifier — either a `0x`-prefixed 32-byte hex address
    /// or a known username this node can resolve.
    recipient: String,
    /// Amount to send, in atomic zkCoin units.
    amount: u64,
    /// Compressed secp256k1 public key (33 bytes) at the sender's current
    /// `num_pubkeys` BIP-32 child index. Serialised as a hex string.
    #[schema(value_type = String, example = "02a34b6d…")]
    public_key: bitcoin::secp256k1::PublicKey,
    /// Compressed secp256k1 public key (33 bytes) at the sender's next
    /// BIP-32 child index (`num_pubkeys + 1`). Serialised as a hex string.
    #[schema(value_type = String, example = "03f128e2…")]
    next_public_key: bitcoin::secp256k1::PublicKey,
    /// Legacy field — IGNORED by `send_coin_handler` as of the
    /// [`crate::account_node::Account::commitment_public_key`]
    /// refactor. The server reads the previous commitment pubkey
    /// from its own state instead. Kept on the wire so deployed
    /// wallets (and the in-tree `app` PR #125) that still emit it
    /// continue to parse against the post-refactor server with no
    /// 4xx for an unknown field. Drop entirely once every published
    /// wallet has cycled off this contract.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    prev_commitment_pubkey: Option<bitcoin::secp256k1::PublicKey>,
    /// Hex-encoded Schnorr signature (64 bytes) over
    /// `SHA256(account_address || recipient || amount || timestamp)`.
    signature: Option<String>,
    /// Unix epoch seconds the signature was produced at. Must be within
    /// 5 minutes of the server's wall clock.
    timestamp: Option<u64>,
}

#[derive(Deserialize, ToSchema)]
pub struct MintRequest {
    /// Recipient account address (`0x`-prefixed 32-byte hex). The node
    /// signs the inscription using its own minting key.
    account_address: String,
    /// Amount to mint, in atomic zkCoin units.
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

/// Persistent proof store — survives node restarts.
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
    /// The ID is always a node-generated u64 and the suffix is the
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

#[derive(Serialize, Deserialize, Default, ToSchema)]
pub struct SendCoinResponse {
    /// `true` on success, `false` on every error path. Errors also
    /// populate [`SendCoinResponse::error`] and surface the appropriate
    /// HTTP status code.
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
/// - **404 NOT_FOUND** — sender address is not known to the node.
/// - **500 INTERNAL_SERVER_ERROR** — the prover failed. Body collapses
///   to a generic `"prove failed"` to avoid leaking prover-internal
///   state to the caller. The full error string is logged via
///   `eprintln!` in the handler.
///
/// The historical 400 `"prev_commitment_pubkey required for account
/// update"` is unreachable as of the
/// [`Account::commitment_public_key`] refactor: the server reads the
/// previous commitment pubkey from its own state instead of trusting
/// the caller. The match arm is therefore gone.
pub(crate) fn map_send_coins_error(err: &str) -> (StatusCode, &'static str) {
    match err {
        "Unknown account address" => (StatusCode::NOT_FOUND, "Unknown account address"),
        "Insufficient funds" => (StatusCode::UNPROCESSABLE_ENTITY, "Insufficient funds"),
        // `get_merkle_proofs` failures — reachable from `send_coins`
        // via the `prev_commitment_pubkey` path. The client supplied
        // the wrong public key, or the previous proof references a
        // history root the node hasn't seen yet (stale snapshot).
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

/// Build a `SendCoinResponse` for a failed `send_coins` call from a
/// pre-mapped `(status, body)` tuple. Callers that need the status
/// code separately (e.g. to route the log level off `is_server_error`)
/// call `map_send_coins_error` once and thread the result through
/// here, avoiding a redundant second mapping call.
pub(crate) fn send_coins_error_response(
    mapped: (StatusCode, &'static str),
) -> (StatusCode, Json<SendCoinResponse>) {
    let (status, body) = mapped;
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

/// Build the 503 response returned by `mint_handler` when the
/// post-proof re-derivation of `num_pubkeys` (from SMT membership)
/// reveals that another mint already landed on-chain since the SNAPSHOT
/// phase. Extracted from `mint_handler` so the (otherwise hard-to-race)
/// branch can be covered by a deterministic unit test in
/// `router_tests.rs` without having to orchestrate a real concurrent-
/// mint race against the live prover.
pub(crate) fn concurrent_mint_during_proof_response(
    expected_num_pubkeys: u32,
    observed_num_pubkeys: u32,
) -> (StatusCode, Json<SendCoinResponse>) {
    eprintln!(
        "Concurrent mint detected during proof phase: expected num_pubkeys={}, observed={}",
        expected_num_pubkeys, observed_num_pubkeys
    );
    handler_error_response(StatusCode::SERVICE_UNAVAILABLE, "Concurrent mint detected")
}

#[derive(Deserialize, ToSchema)]
pub struct CommitRequest {
    /// `proof_id` returned by a previous `POST /api/send` call.
    proof_id: u64,
    /// Hex-encoded compressed public key (33 bytes) that signed the commitment.
    #[schema(value_type = String)]
    public_key: bitcoin::secp256k1::PublicKey,
    /// Hex-encoded Schnorr signature (64 bytes).
    signature: String,
    /// Hex-encoded message that was signed (the concatenation of account_state_hash + output_coins_root).
    message: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct InfoResponse {
    /// Network the node is connected to (`Mainnet`, `Mutinynet`, …).
    network: String,
    /// Per-build capability flags for clients to gate UI on a single
    /// node-side source of truth.
    capabilities: Capabilities,
    /// External hostname this node serves, used by the client to render
    /// `<hex|username>@<domain>`. DEV and PRD share the chain identifier
    /// but live behind different external hostnames, so the client cannot
    /// derive this from `network` alone — the node reports it directly.
    username_domain: String,
}

/// Node-side feature gates exposed to clients so the app can render
/// capability-driven UI without a parallel build-time env-flag set.
/// Each bool reflects a compile-time Cargo feature on the node binary.
///
/// Only opt-in features appear here. Permanent MVP endpoints (mint,
/// username resolve) are always available and intentionally have no
/// capability bit — clients must not gate their UI on flags that
/// would always be `true`.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct Capabilities {
    /// `true` when the `address-list` Cargo feature is compiled in.
    pub address_list: bool,
    /// Username *claim* (write path). Gated by the `username-claim`
    /// Cargo feature; off in hosted DEV + PRD images. Wallet clients
    /// hide the claim input when this is `false`. Always present in
    /// the response so the app does not have to sniff build flags.
    pub username_claim: bool,
    /// `true` when the `lnurl` Cargo feature is compiled in.
    pub lnurl: bool,
}

// --- Username & LNURL types ---

#[cfg(feature = "username-claim")]
#[derive(Deserialize, ToSchema)]
pub struct ClaimUsernameRequest {
    /// Username to claim. Normalised to lowercase before persistence.
    username: String,
    /// `0x`-prefixed 32-byte hex address.
    address: String,
    /// Compressed secp256k1 public key (33 bytes), hex-encoded.
    #[schema(value_type = String)]
    public_key: bitcoin::secp256k1::PublicKey,
    /// Hex-encoded Schnorr signature (64 bytes).
    signature: String,
    /// Unix epoch seconds.
    timestamp: u64,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UsernameResponse {
    /// Resolved (lowercase) username.
    username: String,
    /// `0x`-prefixed 32-byte hex address the username binds to.
    address: String,
}

#[cfg(feature = "lnurl")]
#[derive(Serialize, Deserialize, ToSchema)]
pub struct LnurlpResponse {
    /// Always `payRequest` per LUD-06.
    tag: String,
    /// LNURL-pay callback URL the wallet should call.
    callback: String,
    /// Minimum sendable amount (millisats).
    #[serde(rename = "minSendable")]
    #[schema(rename = "minSendable")]
    min_sendable: u64,
    /// Maximum sendable amount (millisats).
    #[serde(rename = "maxSendable")]
    #[schema(rename = "maxSendable")]
    max_sendable: u64,
    /// JSON-encoded metadata array per LUD-06.
    metadata: String,
}

/// Error envelope used by username and LNURL endpoints (LUD-style).
/// Other endpoints return [`SendCoinResponse`] with `success: false`.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct LnurlErrorResponse {
    /// Always `ERROR` on failure.
    status: String,
    /// Human-readable failure reason.
    reason: String,
}

// Handler functions for our REST API
#[utoipa::path(
    get,
    path = "/api/balance",
    tag = "Accounts",
    params(
        ("address" = String, Query, description = "Account address as `0x`-prefixed 32-byte hex"),
    ),
    responses(
        (status = 200, description = "Balance lookup result. A well-formed address with no \
            on-chain activity returns `balance: 0` (canonical zero), not 404.",
            body = BalanceResponse),
        (status = 422, description = "Malformed address (bad hex, wrong length) or missing query parameter.",
            body = BalanceResponse),
    ),
)]
pub(crate) async fn get_balance_handler(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let account_node = lock_or_recover(&state.account_node);

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
                        num_sends: 0,
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
                    num_sends: 0,
                }),
            );
        }
        let address = digest_from_bytes(&address_bytes);

        // Get balance for the specific account
        let username = {
            let username_store = lock_or_recover(&state.username_store);
            username_store.get_username(&address).map(String::from)
        };
        // Read the per-account send counter so the wallet can hydrate
        // its `numPubkeys` from the server (the authoritative source —
        // see `BalanceResponse::num_sends` doc). Defaults to `0` for
        // an unobserved address, matching `Account::new()`.
        let num_sends = account_node
            .get_account(&address)
            .map(|a| a.num_sends)
            .unwrap_or(0);
        match account_node.get_account_balance(&address) {
            Ok(balance) => (
                StatusCode::OK,
                Json(BalanceResponse {
                    balance,
                    username,
                    num_sends,
                }),
            ),
            // Unobserved address: canonical zero-balance state, not a not-found condition.
            Err(_) => (
                StatusCode::OK,
                Json(BalanceResponse {
                    balance: 0,
                    username,
                    num_sends,
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
                num_sends: 0,
            }),
        )
    }
}

/// `GET /api/history?address=<hex>&limit=<n>&offset=<n>` — paginated
/// per-address transaction history. Implements issue #153.
///
/// Sort order is fixed `ORDER BY changed_at DESC` (newest first); the
/// matching test in `router_tests.rs` pins this so a future caller
/// cannot silently flip the order.
///
/// Validation contract (all return HTTP 422 with a
/// [`HistoryErrorResponse`] — mirrors the `/api/balance` shape so the
/// whole read surface uses the same status for malformed input):
///   * `address` missing.
///   * `address` not valid 32-byte hex.
///   * `limit` outside `[1, 200]` (the issue's max=200 rule). `limit=0`
///     is rejected because a successful response with zero items would
///     be indistinguishable from "no rows", masking the misuse.
///   * `offset` negative.
///
/// A successful response with `offset >= total` returns
/// `items: [], total: N` so the caller can detect end-of-list without
/// a second round-trip.
///
/// Persistence: pure read from `account_history` (joined with
/// `observed_inscriptions` + `pending_inscriptions` for the future
/// txid/block_height/status link — see [`db::AccountHistoryRow`] for
/// the today-vs-tomorrow story). No new schema work.
async fn get_history_handler(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<HistoryQuery>,
) -> impl IntoResponse {
    // Resolve defaults first so the rest of the validation block can
    // assume concrete values. `Option::get().copied().unwrap_or(...)`
    // would also work but the field is already an `Option<i64>` from
    // the typed extractor — `unwrap_or` is the same shape.
    let limit = query.limit.unwrap_or(HISTORY_DEFAULT_LIMIT);
    let offset = query.offset.unwrap_or(0);

    // --- validation ---
    let address_hex = match query.address.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(HistoryErrorResponse {
                    error: "Missing required `address` query parameter",
                }),
            )
                .into_response();
        }
    };
    let address_bytes = match decode_history_address(address_hex) {
        Ok(b) => b,
        Err(msg) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(HistoryErrorResponse { error: msg }),
            )
                .into_response();
        }
    };
    if !(1..=HISTORY_MAX_LIMIT).contains(&limit) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(HistoryErrorResponse {
                error: "limit must be in [1, 200]",
            }),
        )
            .into_response();
    }
    if offset < 0 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(HistoryErrorResponse {
                error: "offset must be non-negative",
            }),
        )
            .into_response();
    }

    // --- DB read ---
    // Single round-trip: page rows + filtered total in one query so the
    // handler carries a single DB error branch.
    let (rows, total) =
        match db::list_account_history(&state.pool, &address_bytes, limit, offset).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("get_history_handler: list query failed: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(HistoryErrorResponse {
                        error: "Database error while reading history",
                    }),
                )
                    .into_response();
            }
        };

    // Defense-in-depth safety net: the SQL already filters to
    // mint/send/receive, so `filter_map` should never actually drop a
    // row in normal operation. If it does, that's a schema drift bug —
    // the post-fetch filter prevents a junk row from reaching the wire
    // until someone fixes the SQL.
    let items: Vec<HistoryItem> = rows.iter().filter_map(history_row_to_item).collect();

    (
        StatusCode::OK,
        Json(HistoryResponse {
            items,
            total,
            limit,
            offset,
        }),
    )
        .into_response()
}

#[cfg(feature = "address-list")]
#[utoipa::path(
    get,
    path = "/api/address",
    tag = "Accounts",
    responses(
        (status = 200, description = "List of all known account addresses (`0x`-prefixed hex). \
            Only compiled in when the `address-list` Cargo feature is enabled.",
            body = AddressesResponse),
    ),
)]
pub(crate) async fn get_address_handler(State(state): State<AppState>) -> impl IntoResponse {
    let account_node = lock_or_recover(&state.account_node);

    // Convert addresses to hex strings
    let hex_addresses: Vec<String> = account_node
        .get_addresses()
        .iter()
        .map(|addr| format!("0x{}", hex::encode(digest_to_bytes(addr))))
        .collect();

    Json(AddressesResponse {
        addresses: hex_addresses,
    })
}

#[utoipa::path(
    post,
    path = "/api/receive",
    tag = "Coins",
    request_body(
        description = "Bincode-serialised `CoinProof` blob produced by the sender's \
            `POST /api/send` round. The body is binary — NOT JSON.",
        content_type = "application/octet-stream",
        content = Vec<u8>,
    ),
    responses(
        (status = 200, description = "On success, returns `{ \"success\": true }`. \
            A malformed binary body returns `{ \"success\": false }` with HTTP 200 \
            for back-compat with deployed wallets.",
            body = SendCoinResponse),
    ),
)]
pub(crate) async fn receive_coin_handler(
    State(state): State<AppState>,
    body: Bytes, // Accept raw binary data instead of multipart
) -> impl IntoResponse {
    // Try to deserialize the binary data as a CoinProof
    let coin_proof = match bincode::deserialize::<CoinProof>(&body) {
        Ok(cp) => cp,
        Err(e) => {
            // Caller submitted a malformed binary body. The handler
            // returns a default `SendCoinResponse { success: false }`
            // (currently a 200 with `success=false`, behaviourally a
            // client-input rejection); log at `info` so the CI E2E
            // negative-path tests hitting `/api/receive` with bad
            // bytes do not surface as `detected_level=error` lines.
            tracing::info!("Failed to deserialize proof with commitment: {}", e);
            return Json(SendCoinResponse::default());
        }
    };
    let recipient = coin_proof.coin.recipient;
    // Snapshot the recipient's mutated account inside the (sync) lock
    // scope so the post-receive Postgres upsert runs without holding
    // the guard across an `.await` point.
    let snapshot: Option<Vec<u8>> = {
        let mut account_node = lock_or_recover(&state.account_node);
        match account_node.receive_coin(coin_proof) {
            Ok(_) => account_node
                .get_account(&recipient)
                .map(AccountNode::serialize_account),
            Err(_) => None,
        }
    };
    match snapshot {
        Some(bytes) => {
            let addr_bytes = digest_to_bytes(&recipient);
            if let Err(e) =
                db::upsert_account_with_source(&state.pool, &addr_bytes, &bytes, "receive").await
            {
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

#[utoipa::path(
    post,
    path = "/api/send",
    tag = "Coins",
    request_body = SendCoinRequest,
    responses(
        (status = 200, description = "Proof generated and persisted. Returns `proof_id`, \
            `account_state_hash`, and `output_coins_root` for the client to sign as the \
            commitment input to `POST /api/commit`.",
            body = SendCoinResponse),
        (status = 401, description = "Missing signature or stale timestamp.",
            body = SendCoinResponse),
        (status = 404, description = "Unknown sender address.",
            body = SendCoinResponse),
        (status = 422, description = "Malformed request, invalid signature, insufficient \
            funds, or Merkle witness validation failure.",
            body = SendCoinResponse),
        (status = 500, description = "Internal prover failure (proof generation crashed).",
            body = SendCoinResponse),
    ),
)]
pub(crate) async fn send_coin_handler(
    State(state): State<AppState>,
    Json(request): Json<SendCoinRequest>,
) -> impl IntoResponse {
    println!("Received send post request...");

    // The pre-PR back-compat shape silently skipped signature
    // verification when `request.signature` was absent. That left
    // `/api/send` reachable by an unsigned attacker as long as the
    // sender address was known to the server — a hard-to-spot
    // security regression. Make signature + timestamp mandatory and
    // surface the distinct app-known strings so the client's error
    // mapping ladders correctly (`"Missing signature"` →
    // `"Anfrage ist nicht signiert."`, etc.).
    //
    // Run the timestamp gate BEFORE the signature crypto so a stale
    // request reports `"Request timestamp too old or in the future"`
    // rather than collapsing to a generic
    // `"Signature verification failed"`.
    // signature + timestamp are both load-bearing — the signature is
    // computed over the timestamp. Absent timestamp is a malformed
    // signed-payload; surface the same `"Missing signature"` string
    // since neither half is independently useful and the app only
    // maps one error code for this branch.
    if request.signature.is_none() || request.timestamp.is_none() {
        return handler_error_response(StatusCode::UNAUTHORIZED, "Missing signature");
    }
    let timestamp = request
        .timestamp
        .expect("timestamp presence checked immediately above");
    if let Err(e) = check_timestamp_window(timestamp) {
        // 401 — caller's signed timestamp is outside the freshness
        // window. Client-input class, logged at `info` so the post-deploy
        // API E2E negative-path tests (`send_stale_timestamp_returns_401`
        // and friends) do not surface as `detected_level=error` lines
        // in Loki on every CI run.
        tracing::info!("Timestamp window check failed: {}", e);
        return handler_error_response(StatusCode::UNAUTHORIZED, e);
    }
    if let Err(e) = verify_send_signature(&request) {
        // 401 — client-supplied signature does not validate. Same
        // log-level rationale as the timestamp window check above.
        tracing::info!("Signature verification failed: {}", e);
        return handler_error_response(StatusCode::UNAUTHORIZED, "Signature verification failed");
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
    // Acquire the account_node lock only for the duration of sending
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
        let mut account_node_lock = lock_or_recover(&state.account_node);
        let res = account_node_lock.send_coins(
            vec![Invoice::new(request.amount, to_address)],
            from_address,
            request.public_key,
            request.next_public_key,
            request.prev_commitment_pubkey,
        );
        updated_account_bytes = match &res {
            Ok(_) => AccountNode::serialize_account(
                account_node_lock
                    .get_account(&from_address)
                    .expect("send_coins Ok implies the sender account is in memory"),
            ),
            Err(_) => Vec::new(),
        };
        send_result = res;
    }

    // Outcome breadcrumb intentionally omitted: both arms below
    // already emit a specific log line (success state-hash on Ok,
    // mapped status + detail string on Err), so a generic
    // "Send result: ok|err" marker between them is pure duplication.

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

            // Note: User-initiated sends never pre-set
            // `coin_proofs[0].commitment` (see
            // `account_node::send_coins`, which always emits
            // `commitment: None`). The mint flow constructs and
            // broadcasts its own commitment inside `mint_handler`. The
            // pre-MVP `if let Some(commitment) = coin_proofs[0]
            // .commitment.as_ref() { … broadcast … }` block that used
            // to live here was dead under both flows and has been
            // removed; clients commit explicitly via `/api/commit`.

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
            if let Err(e) = db::upsert_account_with_source(
                &state.pool,
                &addr_bytes,
                &updated_account_bytes,
                "send",
            )
            .await
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
            // Single `warn` covers every error path. Rationale: a
            // 5xx-class mapping (prover failure, unmapped string)
            // originates from a deeper layer that already emits its
            // own `tracing::error!` / `eprintln!` at the source, so
            // this outer line is a request-level summary — `warn` is
            // the correct level (request failed, no new service-side
            // signal). A 4xx-class mapping is caller-fixable input
            // and `warn` is also correct there. Loki's
            // `FieldDetector.extractLogLevel` classifies `warn` as
            // non-error, which matches what we want for both arms.
            // Map once and thread the tuple into the response
            // builder — `map_send_coins_error` is pure but the
            // duplicate call was needless work.
            let mapped = map_send_coins_error(e);
            tracing::warn!("send_coins rejected: {} (status={})", e, mapped.0);
            send_coins_error_response(mapped)
        }
    }
}

/// Mint a fresh coin into `account_address`, advancing the minting
/// account's BIP-32 child index by 1 — but only if the on-chain
/// inscription broadcast succeeds AND no concurrent mint beat us to
/// the Postgres commit.
///
/// **Four phases, load-bearing ordering** (zk-coins/node#89):
///
/// 1. **SNAPSHOT.** Take the account_node guard briefly to clone the
///    `Arc<Mutex<State>>`, then derive `N = derive_num_pubkeys_from_smt
///    (xpriv, &smt)` under the state lock — N is the first BIP-32
///    child index whose `sha256(pk_n.serialize())` is absent from the
///    SMT. Generate the three pubkeys the prover witness needs
///    (`pk_N`, `pk_{N+1}`, optional `pk_{N-1}`). No mutation.
/// 2. **PROOF.** Briefly take the `account_node` guard, call
///    [`AccountNode::prepare_mint`] (clone-based, pure). Release
///    the guard. Build the signed `Commitment` over the prover's
///    output_coins_root + account_state_hash using a transient
///    ClientAccount clone with `num_pubkeys = N + 1` (so
///    `current_private_key` derives at index N) — the shared
///    ClientAccount is NOT mutated yet. Re-derive N from the SMT
///    immediately before signing and abort with 503 if it has
///    advanced — the scanner may have ingested a concurrent mint's
///    inscription while we were proving, which would invalidate the
///    pubkeys baked into the prover witness.
/// 3. **BROADCAST.** Inscribe the serialized `Commitment` onto Bitcoin.
///    On any error → 503 SERVICE_UNAVAILABLE. No DB write, no in-
///    memory mutation, no recipient update. The next mint retries
///    from `N` cleanly.
/// 4. **COMMIT.** Apply receives to the LIVE recipients under the
///    account_node lock (additive `receive_coin`, never overwriting),
///    then UPSERT the mutated minting account and every touched
///    recipient via [`db::commit_mint_tx`]. No counter step — N is
///    re-derived from SMT membership at the next mint.
///
/// **Concurrency gate (Phase D).** The pre-Phase-D shape carried an
/// optimistic `UPDATE minting_meta SET num_pubkeys = N+1 WHERE
/// num_pubkeys = N` inside `commit_mint_tx` that serialised concurrent
/// mints at the DB layer: the loser observed `rows_affected == 0` and
/// the handler mapped that to a 503. Phase D dropped the counter
/// outright (it lived only in `minting_meta`, which migration 0005
/// drops), so the in-process gate is the phase-2 re-derivation
/// described above. The on-chain gate is the scanner's `state.update`:
/// `SparseMerkleTree::insert` errors on a duplicate key with a
/// different value, so a true double-mint at pubkey index N (two
/// handlers that both broadcast before either inscription was
/// scanned) surfaces as a "Key already exists in the tree with
/// different value" error inside the scanner callback — the second
/// inscription is logged and dropped, the first remains
/// authoritative. The on-chain blobs are operationally cheap (the
/// publisher pays the fee, not the user). Clients that see a 503
/// retry; the next mint observes the new N and proceeds.
///
/// **Retry semantics.** Because the inscription is deterministically
/// derived from `(commitment, publisher_key)`, a 503 from broadcast
/// failure followed by a retry produces the *same* inscription txid.
/// Bitcoin's mempool will respond with `txn-already-known` if the
/// first broadcast actually landed but the response was lost — the
/// caller observes a second 503 here even though the chain has the
/// commitment. The scanner-on-next-boot reconciliation path closes
/// this window: the inscription is ingested into the SMT on the next
/// scanner sweep, the next mint's `derive_num_pubkeys_from_smt` walks
/// past it cleanly, and the wallet's retry semantics drive progress.
/// Document-only — no in-handler retry.
#[utoipa::path(
    post,
    path = "/api/mint",
    tag = "Coins",
    request_body = MintRequest,
    responses(
        (status = 200, description = "Mint succeeded. The on-chain inscription has been \
            broadcast and the recipient account credited.",
            body = SendCoinResponse),
        (status = 422, description = "Malformed `account_address`.",
            body = SendCoinResponse),
        (status = 500, description = "Internal error (minting account not configured, \
            prover failure).",
            body = SendCoinResponse),
        (status = 503, description = "Concurrent mint detected or inscription broadcast \
            failed (publisher wallet underfunded, Esplora unreachable).",
            body = SendCoinResponse),
    ),
)]
pub(crate) async fn mint_handler(
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

    // ---- 1. SNAPSHOT phase (no mutation) ---------------------------------
    // Derive `N = num_pubkeys` from SMT membership: the SMT is loaded
    // from Postgres at boot and mutated by the scanner on every
    // inscription, so it is authoritative. We avoid holding the
    // `account_node` guard across the SMT walk by cloning the inner
    // `Arc<Mutex<State>>` first.
    let state_arc = {
        let account_node_guard = lock_or_recover(&state.account_node);
        account_node_guard.state().clone()
    };
    let (expected_num_pubkeys, minting_pubkey, next_minting_pubkey, prev_commitment_pubkey) = {
        let minting_account_guard = lock_or_recover(&state.minting_account);
        let n = {
            let state_guard = lock_or_recover(&state_arc);
            crate::state::derive_num_pubkeys_from_smt(
                &minting_account_guard.private_key,
                &state_guard.smt,
            )
        };
        let prev_pk = if n > 0 {
            Some(minting_account_guard.generate_public_key(n - 1))
        } else {
            None
        };
        (
            n,
            minting_account_guard.generate_public_key(n),
            minting_account_guard.generate_public_key(n + 1),
            prev_pk,
        )
    };

    // ---- 2. PROOF phase (no mutation, clone-based) -----------------------
    let prepared = {
        let account_node_guard = lock_or_recover(&state.account_node);
        // Test-only barrier: notify any test waiting on
        // `state.phase2_reached` that the handler has acquired the
        // account_node guard and is about to invoke `prepare_mint`.
        // Production builds compile this out entirely (the field does
        // not exist in release).
        #[cfg(test)]
        state.phase2_reached.notify_one();
        // get_minting_account_address borrows immutably below, fine.
        if account_node_guard
            .get_account(&zkcoins_program::types::MINTING_ADDRESS)
            .is_none()
        {
            return handler_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Minting account not configured",
            );
        }
        account_node_guard.prepare_mint(
            vec![Invoice::new(request.amount, account_address)],
            minting_pubkey,
            next_minting_pubkey,
            prev_commitment_pubkey,
        )
    };
    let mut prepared = match prepared {
        Ok(p) => {
            // Success-path breadcrumb. `info` rather than `eprintln!`
            // (which used to land on stderr → Loki classified as
            // `detected_level=error`) — there is no failure to log
            // here.
            tracing::info!("Mint prepare: ok");
            p
        }
        Err(e) => {
            // Single `warn` for the same reason as the send_coins
            // error arm: 5xx-class mappings (prover failure,
            // unmapped string) are already logged at `error` by the
            // deeper layer, and 4xx-class mappings (insufficient
            // funds, malformed proofs, …) are caller-fixable input.
            // `warn` is the correct request-level summary level for
            // both. Map once and thread the tuple into the response
            // builder.
            let mapped = map_send_coins_error(e);
            tracing::warn!("Mint prepare rejected — {} (status={})", e, mapped.0);
            return send_coins_error_response(mapped);
        }
    };

    // Test-only deterministic hold between `prepare_mint` and the
    // phase-3 re-derive. Pre-unlocked in all `test_state`
    // constructors so production-shaped tests acquire + drop in one
    // step. The concurrent-mint race test holds the guard from the
    // outside across the pk_N injection, forcing the handler to
    // block here until the injection is visible. Production builds
    // compile this out entirely (the field does not exist).
    #[cfg(test)]
    drop(state.phase3_release_lock.lock().await);

    // Build the BIP-340 commitment over the prover's outputs. Sign with
    // the index-N private key — this is the same key the wallet would
    // sign with once `num_pubkeys` advances past N. We do NOT mutate
    // the shared ClientAccount's `num_pubkeys`; build a transient clone
    // where `num_pubkeys = N + 1` so its `current_private_key()`
    // derives at index N.
    //
    // Re-derive N from SMT membership immediately before signing — if
    // the scanner ingested a concurrent mint's inscription while we
    // were proving, the pubkeys baked into the witness are stale and
    // every downstream consumer will reject the resulting commitment.
    // Abort with 503; the wallet retries and the next attempt observes
    // the new N. This is the in-process leg of the Phase-D concurrency
    // gate documented on `mint_handler`'s doc-comment.
    let commitment = {
        let minting_account_guard = lock_or_recover(&state.minting_account);
        let current_num_pubkeys = {
            let state_guard = lock_or_recover(&state_arc);
            crate::state::derive_num_pubkeys_from_smt(
                &minting_account_guard.private_key,
                &state_guard.smt,
            )
        };
        if current_num_pubkeys != expected_num_pubkeys {
            return concurrent_mint_during_proof_response(
                expected_num_pubkeys,
                current_num_pubkeys,
            );
        }
        let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
            prepared.coin_proofs[0].proof.public_inputs
                [..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
                .try_into()
                .expect("prover always emits N_PROOF_DATA_PUBLIC_INPUTS field elements");
        let proof_data = ProofData::from_field_elements(&pis);
        let signing_clone = shared::ClientAccount {
            address: minting_account_guard.address,
            num_pubkeys: expected_num_pubkeys + 1,
            private_key: minting_account_guard.private_key,
        };
        signing_clone.create_commitment(
            &proof_data.account_state_hash,
            &proof_data.output_coins_root,
        )
    };
    prepared.coin_proofs[0].commitment = Some(commitment.clone());

    // ---- 3. BROADCAST phase ---------------------------------------------
    let commitment_data = bincode::serialize(&commitment).expect("Failed to serialize commitment");
    println!(
        "Sending commitment data with size: {} bytes",
        commitment_data.len()
    );
    println!("Commitment data hex: {}", hex::encode(&commitment_data));
    // NOTE (idempotent retry, zk-coins/node#89): on a retry after a
    // transient broadcast failure the publisher wallet's UTXO set has
    // changed (`get_publisher_utxo` selects fresh inputs every call),
    // so the new `commit_tx` has different inputs → different
    // commit_txid. Bitcoin does NOT short-circuit with
    // `txn-already-known` — both attempts land on chain as distinct
    // transactions. Idempotency is enforced one layer up: the
    // inscription payload encodes the same `(public_key, commitment)`
    // for both broadcasts, the scanner's `SparseMerkleTree::insert` is
    // idempotent on same key + same value (the second insert is a
    // no-op), and `State::update` deduplicates accordingly. The MMR
    // rebuild from scanner replay therefore produces a stable state
    // regardless of how many transient broadcast attempts landed on
    // chain. The handler still observes an Err here on a genuine
    // broadcast failure and returns 503; reconciliation happens on the
    // next scanner sweep. No in-handler retry.
    let broadcast_outcome = create_and_broadcast_inscription(
        &commitment_data,
        crate::db::InscriptionKind::Mint,
        &state.esplora_config,
        Some(&state.pool),
    )
    .await;
    let commit_txid_bytes: [u8; 32] = match broadcast_outcome {
        Ok((commit_txid, _reveal_txid)) => {
            use bitcoin::hashes::Hash as _;
            commit_txid.to_byte_array()
        }
        Err(err) => {
            eprintln!("Error broadcasting mint inscription: {}", err);
            return handler_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Failed to broadcast mint inscription on-chain",
            );
        }
    };

    // ---- 3b. STATE_ADVANCE phase (Phase E, broadcast OK) ----------------
    // Apply the freshly-broadcast commitment to the in-memory SMT + MMR
    // and persist the resulting snapshot — together with the
    // `pending_inscriptions.status = 'complete'` row advance — in ONE
    // atomic Postgres transaction. The shared implementation lives in
    // [`apply_commit_and_persist_phase_e`], which is also invoked from
    // the send path in [`crate::runtime::broadcast_commit_and_deliver`]
    // so the two flows that originate inscriptions on this node both
    // integrate them synchronously and the scanner becomes a redundant
    // observer for our own commits. See the helper's docstring for the
    // full rationale (race window, lock topology, crash-recovery
    // contract).
    if let Err(failure) =
        apply_commit_and_persist_phase_e(&state, &commitment, &commit_txid_bytes, "mint_handler")
            .await
    {
        let msg: &'static str = match failure {
            PhaseEFailure::StateUpdate => {
                "mint broadcast landed on chain but in-process state advance failed; scanner will reconcile"
            }
            PhaseEFailure::DurablePersist => {
                "mint broadcast landed on chain but durable state advance failed; scanner will reconcile"
            }
        };
        return handler_error_response(StatusCode::SERVICE_UNAVAILABLE, msg);
    }

    // ---- 4. COMMIT phase (broadcast OK) ---------------------------------
    // Apply receives to the LIVE in-memory recipient under the
    // account_node lock (additive `receive_coin`, never overwriting),
    // then UPSERT every touched account (minting + recipients) in a
    // single sqlx transaction via [`db::commit_mint_tx`].
    //
    // Rationale (zk-coins/node#89 round-2 MAJOR 1): a previous shape
    // snapshot-cloned each recipient under the lock, mutated the
    // clone, then `import_account`'d the clone back after the tx
    // commit. Between the snapshot read and the post-tx overwrite the
    // lock was released across the `await` on `commit_mint_tx`. A
    // concurrent `/api/send` flow that landed in
    // `broadcast_commit_and_deliver` could mutate the live recipient
    // in that window — and the post-tx `import_account` would clobber
    // it with our stale clone, losing the concurrent update both in
    // memory and (eventually) in the DB. The fix is to take the
    // account_node guard, do the `receive_coin` mutations, snapshot
    // the LIVE account state inside the same critical section, then
    // hand the bundle (already-fresh bytes) to the async DB upsert.
    let minting_addr_bytes =
        zkcoins_program::hash::digest_to_bytes(&zkcoins_program::types::MINTING_ADDRESS);
    let minting_snapshot_bytes = AccountNode::serialize_account(&prepared.mutated_minting);

    let recipient_snapshots: Vec<(zkcoins_program::hash::HashDigest, Vec<u8>)> = {
        let mut account_node_guard = lock_or_recover(&state.account_node);
        account_node_guard.commit_mint(prepared.mutated_minting);
        let mut snaps = Vec::with_capacity(prepared.coin_proofs.len());
        for coin_proof in &prepared.coin_proofs {
            let recipient = coin_proof.coin.recipient;
            if let Err(e) = account_node_guard.receive_coin(coin_proof.clone()) {
                // Best-effort: a duplicate / replay error here means
                // the recipient already has this coin (e.g. scanner-
                // replay after restart). Log and still snapshot
                // whatever the live recipient looks like so the DB
                // row stays current.
                eprintln!("Failed to receive minted coin into live recipient: {}", e);
            }
            if let Some(acct) = account_node_guard.get_account(&recipient) {
                snaps.push((recipient, AccountNode::serialize_account(acct)));
            }
        }
        snaps
    };

    // Build the per-account UPSERT bundle. `commit_mint_tx` writes
    // every entry in one transaction so a partial-failure leaves the
    // accounts table consistent.
    let mut commit_rows: Vec<(&[u8], &[u8])> = Vec::with_capacity(1 + recipient_snapshots.len());
    commit_rows.push((&minting_addr_bytes[..], &minting_snapshot_bytes[..]));
    let recipient_addr_bytes: Vec<[u8; 32]> = recipient_snapshots
        .iter()
        .map(|(addr, _)| zkcoins_program::hash::digest_to_bytes(addr))
        .collect();
    for ((_, bytes), addr_bytes) in recipient_snapshots.iter().zip(recipient_addr_bytes.iter()) {
        commit_rows.push((&addr_bytes[..], &bytes[..]));
    }
    if let Err(e) = db::commit_mint_tx(&state.pool, &commit_rows).await {
        eprintln!("Failed to commit mint transaction to Postgres: {}", e);
        // The on-chain commitment landed and the in-memory state is
        // already updated, but the DB persistence failed. Return 503
        // so the client knows nothing is durable on our side; the
        // scanner-replay path on next boot will rehydrate the SMT
        // from chain and the next mint observes the correct N via
        // `derive_num_pubkeys_from_smt`.
        return handler_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Failed to persist mint commit transaction",
        );
    }

    let mut coin_proofs = prepared.coin_proofs;
    // `mint_handler` passes a single-element `vec![Invoice::new(...)]`
    // to `prepare_mint`; `send_coins_inner` builds `coin_proofs` with
    // `out_coins.len() == coin_templates.len() == invoices.len() == 1`,
    // so the Ok-arm Vec has length exactly 1.
    //
    // Surface the prover's post-mint hash pair on the response. Today
    // the wallet client needs `prev_commitment_pubkey` for the next
    // send, which it derives from the proof file fetched via
    // `GET /api/proof/:id` — but the matching account_state_hash and
    // output_coins_root are the same pair the send response carries
    // for an ordinary user transition, so emitting them here lets the
    // client advance its local snapshot atomically with the mint
    // response (one round-trip instead of two). Source: the prover's
    // public inputs on the freshly-built coin proof — identical
    // derivation to the one `send_coin_handler` performs.
    let final_coin_proof = coin_proofs
        .pop()
        .expect("send_coins returns exactly one coin_proof for single-invoice mint");
    let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
        final_coin_proof.proof.public_inputs
            [..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .expect("Plonky2 Proof emits N_PROOF_DATA_PUBLIC_INPUTS field elements");
    let proof_data = ProofData::from_field_elements(&pis);
    let ash_hex = Some(hex::encode(digest_to_bytes(&proof_data.account_state_hash)));
    let ocr_hex = Some(hex::encode(digest_to_bytes(&proof_data.output_coins_root)));
    let proof_id = state.proof_store.add_proof(final_coin_proof);
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

// New handler to get a binary proof by ID
#[utoipa::path(
    get,
    path = "/api/proof/{id}",
    tag = "Coins",
    params(
        ("id" = u64, Path, description = "`proof_id` returned by a previous `POST /api/send`"),
    ),
    responses(
        (status = 200, description = "Binary `CoinProof` blob (bincode-serialised).",
            content_type = "application/octet-stream",
            body = Vec<u8>),
        (status = 404, description = "No proof exists for this `id`."),
    ),
)]
pub(crate) async fn get_proof_handler(
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
///
/// **Broadcast-then-deliver invariant (zk-coins/node#89).** The
/// `/api/commit` endpoint receives a *proof_id* the node already
/// generated (in an earlier `/api/send` call), looks up the persisted
/// `CoinProof`, broadcasts its commitment, advances the SMT/MMR via
/// the shared Phase E helper synchronously, and only then hands the
/// proof to `receive_coin` for the recipient mutation. The in-memory
/// mutation + persistence lives in [`broadcast_commit_and_deliver`] in
/// `runtime.rs`; the broadcast call sits at the very top of that
/// function and returns 503 on failure with NO subsequent state
/// mutation. DO NOT reorder the broadcast and the `receive_coin` call.
///
/// **Phase E symmetry (this branch).** The send-commit path now runs
/// [`apply_commit_and_persist_phase_e`] synchronously between the
/// broadcast and `receive_coin`, matching `mint_handler`. Before this
/// change the send-commit SMT integration relied exclusively on the
/// async scanner, which left a race window where a wallet that
/// followed `/api/send` + `/api/commit` with a second `/api/send`
/// would walk the SMT for the first commit's pubkey and find it
/// missing — surfacing as 422 `"Unable to get merkle proofs for
/// provided public key"`. The synchronous Phase E call closes that
/// window; the scanner remains the authoritative path for external
/// recovery inscriptions but is now a redundant observer for our own
/// send commits, exactly as for mint commits.
#[utoipa::path(
    post,
    path = "/api/commit",
    tag = "Coins",
    request_body = CommitRequest,
    responses(
        (status = 200, description = "Commitment verified, inscription broadcast on-chain, \
            recipient credited.",
            body = SendCoinResponse),
        (status = 401, description = "Commitment signature invalid.",
            body = SendCoinResponse),
        (status = 404, description = "Unknown `proof_id`.",
            body = SendCoinResponse),
        (status = 422, description = "Malformed signature, message, or signature format.",
            body = SendCoinResponse),
        (status = 503, description = "Inscription broadcast failed (Esplora down, publisher \
            wallet underfunded).",
            body = SendCoinResponse),
    ),
)]
pub(crate) async fn commit_handler(
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

    crate::runtime::broadcast_commit_and_deliver(&state, commitment, coin_proof, request.proof_id)
        .await
}

/// `GET /api/inscriptions/:txid` — operator/forensics lookup of a single
/// inscription by its commit txid. Surfaces the columns that answer
/// "what kind of operation was this, and where is it in the publish
/// pipeline" without exposing the raw commit/reveal/commitment blobs
/// (those are crash-recovery state, not user-facing).
///
/// Returns 404 when no row exists — the inscription either never went
/// through this node (e.g. external recovery via `recover_inscription`
/// CLI) or the txid is unknown.
#[utoipa::path(
    get,
    path = "/api/inscriptions/{txid}",
    tag = "Inscriptions",
    params(
        ("txid" = String, Path, description = "Commit transaction id (64 hex characters, \
            big-endian display order — matches what block explorers show)"),
    ),
    responses(
        (status = 200, description = "Inscription metadata.", body = InscriptionSummary),
        (status = 404, description = "No inscription matches this `txid`.",
            body = SendCoinResponse),
        (status = 422, description = "Malformed `txid` (not 32-byte hex).",
            body = SendCoinResponse),
        (status = 500, description = "Database error.", body = SendCoinResponse),
    ),
)]
pub(crate) async fn get_inscription_handler(
    State(state): State<AppState>,
    Path(txid_hex): Path<String>,
) -> axum::response::Response {
    // Bitcoin convention: display txids are big-endian, but the
    // `pending_inscriptions.commit_txid` column stores raw little-endian
    // bytes (matching `bitcoin::Txid::as_byte_array()` semantics — see
    // `publisher.rs` write site). Reverse on parse so a caller can pass
    // the same hex an explorer shows.
    let mut bytes = match hex::decode(txid_hex.trim()) {
        Ok(b) if b.len() == 32 => b,
        Ok(_) => {
            return handler_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "txid must be 32 bytes (64 hex chars)",
            )
            .into_response();
        }
        Err(_) => {
            return handler_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "txid is not valid hex",
            )
            .into_response();
        }
    };
    bytes.reverse();

    match crate::db::get_inscription_summary_by_commit_txid(&state.pool, &bytes).await {
        Ok(Some(summary)) => (StatusCode::OK, Json(summary)).into_response(),
        Ok(None) => {
            handler_error_response(StatusCode::NOT_FOUND, "No inscription found for this txid")
                .into_response()
        }
        Err(e) => {
            eprintln!("get_inscription_handler: db error: {}", e);
            handler_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error while looking up inscription",
            )
            .into_response()
        }
    }
}

// ---- Admin: R2 probe history --------------------------------------------
//
// The `probe_r2` binary persists its results into `r2_probe_runs` (see
// `r2_probe.rs` + migration 0013). This endpoint surfaces the most
// recent `limit` rows of the convenience view so the operator can ask
// "did the last few probe runs hit budget?" against a deployed node
// without shelling into the database.
//
// Closed test env (`feedback_zkcoins_closed_test_env`): the endpoint
// is unauthenticated like every other route. The path lives under an
// `/api/admin/` prefix so it is visibly separate from the user-facing
// surface and never accidentally documented as a public contract.
// Read-only — the handler never writes.

/// `?limit=` query for `GET /api/admin/r2-probe/history`. Capped at
/// 200 to bound the response size and the underlying DB scan.
#[derive(Deserialize)]
pub(crate) struct R2ProbeHistoryQuery {
    pub limit: Option<i64>,
}

/// Default page size when `?limit` is omitted.
pub(crate) const R2_PROBE_HISTORY_DEFAULT_LIMIT: i64 = 50;
/// Hard cap on the `?limit` parameter — clamps oversized requests
/// down to a sane scan budget.
pub(crate) const R2_PROBE_HISTORY_MAX_LIMIT: i64 = 200;

/// Normalise a caller-supplied `?limit` into the
/// `[1, R2_PROBE_HISTORY_MAX_LIMIT]` window. Negative / zero /
/// missing inputs collapse to the default; anything above the cap
/// is clamped down. Extracted so the clamp logic is unit-testable
/// without spinning up a Postgres container.
pub(crate) fn clamp_r2_probe_history_limit(raw: Option<i64>) -> i64 {
    match raw {
        Some(n) if n <= 0 => R2_PROBE_HISTORY_DEFAULT_LIMIT,
        Some(n) if n > R2_PROBE_HISTORY_MAX_LIMIT => R2_PROBE_HISTORY_MAX_LIMIT,
        Some(n) => n,
        None => R2_PROBE_HISTORY_DEFAULT_LIMIT,
    }
}

/// `GET /api/admin/r2-probe/history?limit=<int>` — operator-facing
/// trend view over the `r2_probe_runs_summary` view. Returns the
/// `limit` most recent runs newest first as a JSON array. Read-only:
/// no write path exists for this resource through HTTP.
///
/// The endpoint is intentionally unauthenticated — the node sits in
/// a closed test environment where the entire request surface is
/// fair game for the operator. Per
/// `feedback_zkcoins_no_privacy_promise` the server makes no
/// privacy claim; the probe rows are operational telemetry and any
/// future hardening goes alongside the wider auth story.
async fn r2_probe_history_handler(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<R2ProbeHistoryQuery>,
) -> axum::response::Response {
    let limit = clamp_r2_probe_history_limit(query.limit);
    match crate::r2_probe::fetch_recent_summary(&state.pool, limit).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            tracing::warn!("r2_probe_history_handler: db error: {}", e);
            handler_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error while reading R2 probe history",
            )
            .into_response()
        }
    }
}

/// JSON body returned by `GET /health/ready`. `failures` is empty on a
/// fully ready node; each failing dependency contributes one stable
/// short tag (`"db"`, `"esplora"`, `"prover"`) so a Kuma monitor parses
/// the cause without having to scrape the status code in isolation.
///
/// `prover` is the background-warmup tag (see `AppState::prover_warm`):
/// while the bootstrap warmup task is still running, the readiness
/// probe reports `failures: ["prover"]` with `status: starting` and a
/// 503 so a load balancer keeps holding traffic on the previous-gen
/// pod. `/health` (liveness) is unaffected.
#[derive(Serialize)]
struct ReadyResponse {
    ready: bool,
    failures: Vec<&'static str>,
    /// Lifecycle tag. `"starting"` while any failure is present,
    /// `"ready"` once every dependency probe passes. Distinct from
    /// `ready: bool` so a parsing consumer can branch on a short
    /// string without re-deriving it from the bool + failures shape.
    status: &'static str,
    /// Background-warmup tag. `"warming"` while
    /// `AppState::prover_warm == false`, `"ready"` afterwards.
    /// Emitted on every response (regardless of overall readiness) so
    /// a deploy dashboard can show the warmup progress separately
    /// from the DB/Esplora probes.
    prover: &'static str,
}

/// Readiness probe (`GET /health/ready`).
///
/// **Liveness vs readiness.** The pre-existing `/health` endpoint is
/// the Kubernetes-style liveness probe: it returns `"ok"` with 200 as
/// long as the HTTP listener is bound and the tokio runtime is alive.
/// It deliberately does NOT touch the database or Esplora, so an
/// upstream blip never restarts the process — losing the in-memory
/// `account_node` and `state` to a restart would lose every mint /
/// send the scanner has not yet checkpointed.
///
/// `/health/ready` is the complementary readiness probe: it actively
/// pings Postgres (`SELECT 1`) and Esplora (`GET /blocks/tip/height`,
/// re-using the configured `ESPLORA_URL`) and returns 503 if either
/// fails. A load balancer / uptime monitor uses this to decide
/// "should traffic flow?" without using it to decide "should this
/// process die?". The Kuma monitor at
/// <https://kuma.dfxserve.com> watches `api.zkcoins.app/health/ready`
/// on a 60 s interval — separate alert from the liveness check.
///
/// No caching: each call issues a fresh DB round-trip plus an Esplora
/// HEAD-equivalent. Both are sub-100 ms in steady state, and a cached
/// stale "ready" is worse than a slightly slow honest answer.
async fn ready_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut failures: Vec<&'static str> = Vec::new();

    if sqlx::query("SELECT 1").execute(&*state.pool).await.is_err() {
        failures.push("db");
    }

    if check_esplora(&state.esplora_config).await.is_err() {
        failures.push("esplora");
    }

    // Background-warmup gate. `prover_warm` is flipped to true by the
    // `spawn_blocking` task that `runtime::start_rest_node` launches
    // immediately after binding the TCP listener (or directly at boot
    // when `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1`). Until then a user
    // request still succeeds but pays the ~7 s cold-prove tax — for
    // the rolling-deploy use case the load balancer holds traffic on
    // the previous-gen pod by treating this readiness probe as the
    // gate, not the liveness probe.
    let prover_warm = state.prover_warm.load(Ordering::SeqCst);
    if !prover_warm {
        failures.push("prover");
    }

    let ready = failures.is_empty();
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let lifecycle_status = if ready { "ready" } else { "starting" };
    let prover_status = if prover_warm { "ready" } else { "warming" };
    (
        status,
        Json(ReadyResponse {
            ready,
            failures,
            status: lifecycle_status,
            prover: prover_status,
        }),
    )
}

/// Ping the configured Esplora endpoint. A successful tip-height fetch
/// proves the upstream is reachable AND serving the public REST API
/// (a TCP-only liveness check would miss a broken nginx upstream).
async fn check_esplora(
    config: &EsploraConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use esplora_client::{r#async::DefaultSleeper, AsyncClient, Builder};
    let client = AsyncClient::<DefaultSleeper>::from_builder(Builder::new(&config.url))?;
    client.get_height().await?;
    Ok(())
}

/// JSON body returned by `GET /health/publisher`. Surface enough state
/// for the deploy-dev preflight (and a curious operator) to make the
/// "should I top up the publisher wallet?" decision without scraping
/// Esplora directly. `address` is the publisher's Taproot bech32 — log-
/// only, NOT a secret (the matching key lives in `PUBLISHER_KEY`).
#[derive(Serialize)]
struct PublisherHealthResponse {
    address: String,
    utxo_count: u64,
    total_sats: u64,
}

/// Operational preflight (`GET /health/publisher`).
///
/// Reads the publisher Taproot wallet's UTXO set via the configured
/// Esplora endpoint and reports `(address, utxo_count, total_sats)`.
/// The deploy-dev workflow probes this BEFORE running the API E2E
/// suite — an empty wallet would otherwise cause every mint to 503
/// and historically masked as a "green" run because the E2E suite
/// itself silently treated 5xx as a skip. Returning 503 on an
/// Esplora-side error is intentional: the operator should see the
/// failure mode, not a fabricated empty response.
async fn publisher_health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let publisher_address = crate::PUBLISHER_ADDRESS.clone();

    match crate::publisher::get_publisher_utxo(&publisher_address, &state.esplora_config, None)
        .await
    {
        Ok(utxos) => {
            let utxo_count = utxos.len() as u64;
            let total_sats: u64 = utxos.iter().map(|(_, sats)| sats).sum();
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(PublisherHealthResponse {
                        address: publisher_address.to_string(),
                        utxo_count,
                        total_sats,
                    })
                    .expect("publisher health response serializes"),
                ),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Esplora-side error fetching publisher UTXOs",
                "detail": e.to_string(),
                "address": publisher_address.to_string(),
            })),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/info",
    tag = "Node",
    responses(
        (status = 200, description = "Node metadata: connected network, per-build \
            capability flags, and external username domain.",
            body = InfoResponse),
    ),
)]
pub(crate) async fn info_handler() -> impl IntoResponse {
    Json(InfoResponse {
        network: NETWORK_CONFIG.network_name.clone(),
        capabilities: Capabilities {
            address_list: cfg!(feature = "address-list"),
            username_claim: cfg!(feature = "username-claim"),
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
    history: &'static str,
    send: &'static str,
    receive: &'static str,
    commit: &'static str,
    proof: &'static str,
    inscription: &'static str,
    health: &'static str,
}

/// Root handler — anything hitting `https://api.zkcoins.app/` (browser visit,
/// uptime probe, curious operator) gets a small JSON identifying the service,
/// the package version, the connected network, and pointers to the real
/// endpoints. Cheaper than serving a static landing page and still answers the
/// "is this the right host?" question without surfacing a bare 404.
async fn root_handler() -> impl IntoResponse {
    Json(RootResponse {
        service: "zkcoins-node",
        version: env!("CARGO_PKG_VERSION"),
        network: NETWORK_CONFIG.network_name.clone(),
        endpoints: RootEndpoints {
            info: "GET  /api/info",
            balance: "GET  /api/balance?address={hex}",
            history: "GET  /api/history?address={hex}&limit={n}&offset={n}",
            send: "POST /api/send",
            receive: "POST /api/receive",
            commit: "POST /api/commit",
            proof: "GET  /api/proof/{id}",
            inscription: "GET  /api/inscriptions/{txid}",
            health: "GET  /health",
        },
        docs: "https://docs.zkcoins.app",
    })
}

// --- Username & LNURL handlers ---

#[cfg(feature = "username-claim")]
#[utoipa::path(
    post,
    path = "/api/username/claim",
    tag = "Usernames",
    request_body = ClaimUsernameRequest,
    responses(
        (status = 200, description = "Username claimed and bound to the address.",
            body = UsernameResponse),
        (status = 401, description = "Public key does not match address, signature \
            verification failed, or timestamp out of window.",
            body = LnurlErrorResponse),
        (status = 409, description = "Username already taken.",
            body = LnurlErrorResponse),
        (status = 422, description = "Malformed username, address, signature, or public key.",
            body = LnurlErrorResponse),
        (status = 503, description = "Database error while persisting the claim.",
            body = LnurlErrorResponse),
    ),
)]
pub(crate) async fn claim_username_handler(
    State(state): State<AppState>,
    Json(request): Json<ClaimUsernameRequest>,
) -> impl IntoResponse {
    // Normalise the username up-front so the Schnorr signature, the
    // in-memory mirror, and the Postgres row all agree on the exact
    // byte string. Hashing the raw `request.username` while persisting
    // `to_lowercase()` lets a wallet that signs over `"Alice"` end up
    // squatting `"alice"` — see PR #76's prod-readiness review.
    let normalized_username = match crate::username::UsernameStore::validate(&request.username) {
        Ok(n) => n,
        Err(err) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(LnurlErrorResponse {
                    status: "ERROR".into(),
                    reason: err.into(),
                }),
            )
                .into_response();
        }
    };

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

    // Verify timestamp freshness (shared 5 min window with
    // `send_coin_handler`). Uses the same string the send path emits so
    // the app's `KNOWN_SERVER_ERRORS` mapping ladders identically.
    if let Err(e) = check_timestamp_window(request.timestamp) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: e.into(),
            }),
        )
            .into_response();
    }

    // Verify Schnorr signature over sha256("zkcoins:claim_username" || address_hex || normalised_username || timestamp_le).
    // The wallet MUST sign over the lowercase form (same normalisation
    // as `UsernameStore::validate`) — otherwise the same input that the
    // node persists is not what the signature commits to, opening
    // the case-mismatch squat described above.
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(request.address.as_bytes());
    hasher.update(normalized_username.as_bytes());
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

    // Claim path, three steps. The previous `mem::take` approach left
    // the in-memory `UsernameStore` observable as empty for the full
    // duration of the DB round-trip — every `resolve` / `get_username`
    // request in that window saw a blank mirror, including
    // `get_balance_handler`'s `username` lookup.
    //
    // Split design:
    //   1. short sync lock → `precheck` (read-only)
    //   2. drop lock → async `db::claim_username` (`ON CONFLICT DO NOTHING`)
    //   3. short sync lock → `commit_after_db` (in-memory insert)
    //
    // Reads concurrent with a claim now always see the full mirror.
    // Concurrent writers race at the SQL `ON CONFLICT` boundary as
    // before; the second writer hits `rows_affected == 0` and the
    // handler maps that to a 409. The post-commit insert is idempotent
    // — re-inserting the same `(normalized, address)` is a no-op.
    // Decode signature bytes once so the claim-log row carries the
    // exact signature bytes the caller submitted, regardless of the
    // outcome below.
    let signature_bytes = hex::decode(&request.signature).unwrap_or_default();

    // username_claim_log helper: fire-and-forget, captures every
    // outcome that reaches the in-memory / SQL layer (precheck reject,
    // SQL race-loser, success). Pure-validation rejects above are
    // already captured via request_log on the audit path.
    let log_claim = |success: bool, reject_reason: Option<&str>| {
        let entry = crate::db::UsernameClaimLogEntry {
            requested_username: request.username.clone(),
            normalized_username: normalized_username.clone(),
            address: address_bytes.to_vec(),
            signature: signature_bytes.clone(),
            success,
            reject_reason: reject_reason.map(|s| s.to_string()),
            request_log_id: None,
        };
        let pool = state.pool.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::db::insert_username_claim_log(&pool, &entry).await {
                eprintln!("Failed to persist username_claim_log: {}", e);
            }
        });
    };

    if let Err(reason) =
        lock_or_recover(&state.username_store).precheck(&normalized_username, &address)
    {
        log_claim(false, Some(reason));
        // `precheck` returns the static collision strings the wallet
        // surfaces verbatim. The status is `409 CONFLICT` for either
        // collision variant — same shape as the SQL-layer race below.
        return (
            StatusCode::CONFLICT,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: reason.into(),
            }),
        )
            .into_response();
    }

    let addr_bytes = digest_to_bytes(&address);
    let inserted =
        match crate::db::claim_username(&state.pool, &normalized_username, &addr_bytes).await {
            Ok(b) => b,
            Err(db_err) => {
                eprintln!("Failed to persist username claim: {}", db_err);
                log_claim(false, Some(&format!("db error: {}", db_err)));
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(LnurlErrorResponse {
                        status: "ERROR".into(),
                        reason: "Failed to persist username claim".into(),
                    }),
                )
                    .into_response();
            }
        };
    if !inserted {
        log_claim(false, Some("race lost on ON CONFLICT"));
        // Concurrent claimer won the `ON CONFLICT` race for the same
        // name. Surface as the same 409 a precheck collision would.
        return (
            StatusCode::CONFLICT,
            Json(LnurlErrorResponse {
                status: "ERROR".into(),
                reason: "Username already taken".into(),
            }),
        )
            .into_response();
    }

    lock_or_recover(&state.username_store).commit_after_db(normalized_username.clone(), address);

    log_claim(true, None);

    (
        StatusCode::OK,
        Json(UsernameResponse {
            username: normalized_username,
            address: format!("0x{}", hex::encode(digest_to_bytes(&address))),
        }),
    )
        .into_response()
}

/// Resolve an identifier to an address. Checks the username store first,
/// then falls back to hex-prefix matching against known account addresses.
/// Used by the always-on username handlers and the gated LNURL handlers.
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
    let account_node = lock_or_recover(&state.account_node);
    account_node
        .get_addresses()
        .into_iter()
        .find(|addr| hex::encode(digest_to_bytes(addr)).starts_with(&normalized))
        .map(|addr| (addr, normalized))
}

#[utoipa::path(
    get,
    path = "/api/username/resolve/{username}",
    tag = "Usernames",
    params(
        ("username" = String, Path, description = "Username or hex address prefix to resolve"),
    ),
    responses(
        (status = 200, description = "Resolved address for the identifier.",
            body = UsernameResponse),
        (status = 404, description = "Identifier did not match any known username or address.",
            body = LnurlErrorResponse),
    ),
)]
pub(crate) async fn resolve_username_handler(
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
#[utoipa::path(
    get,
    path = "/.well-known/lnurlp/{username}",
    tag = "LNURL",
    params(
        ("username" = String, Path, description = "Username or hex address prefix"),
    ),
    responses(
        (status = 200, description = "LNURL-pay metadata per LUD-06.", body = LnurlpResponse),
        (status = 404, description = "Username not found.", body = LnurlErrorResponse),
    ),
)]
pub(crate) async fn lnurlp_handler(
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
#[utoipa::path(
    get,
    path = "/lnurl/pay/{username}",
    tag = "LNURL",
    params(
        ("username" = String, Path, description = "Username or hex address prefix"),
    ),
    responses(
        (status = 200, description = "LNURL-pay callback response. The current implementation \
            is a stub that always returns a phase-2 error.",
            body = LnurlErrorResponse),
    ),
)]
pub(crate) async fn lnurl_callback_handler(
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
        .route("/health/ready", get(ready_handler))
        .route("/health/publisher", get(publisher_health_handler))
        .route("/openapi.json", get(crate::openapi::openapi_json_handler))
        .route("/docs", get(crate::openapi::docs_handler))
        .route("/api/info", get(info_handler))
        .route("/api/balance", get(get_balance_handler))
        .route("/api/history", get(get_history_handler))
        .route("/api/send", post(send_coin_handler))
        .route("/api/receive", post(receive_coin_handler))
        .route("/api/proof/:id", get(get_proof_handler))
        .route("/api/commit", post(commit_handler))
        .route("/api/mint", post(mint_handler))
        .route("/api/inscriptions/:txid", get(get_inscription_handler))
        .route(
            "/api/username/resolve/:username",
            get(resolve_username_handler),
        )
        // Operator-facing R2 probe trend (see `r2_probe_history_handler`
        // doc-comment). Grouped under `/api/admin/` so it is visibly
        // separate from the user-facing surface.
        .route("/api/admin/r2-probe/history", get(r2_probe_history_handler));

    // Gated routes — only compiled in when their Cargo feature is enabled.
    // With a feature off, the handler does not exist in the binary and the
    // route is not registered, so the endpoint returns 404 via the fallback
    // and there is no code path to execute.
    #[cfg(feature = "address-list")]
    let app = app.route("/api/address", get(get_address_handler));

    #[cfg(feature = "username-claim")]
    let app = app.route("/api/username/claim", post(claim_username_handler));

    #[cfg(feature = "lnurl")]
    let app = app
        .route("/.well-known/lnurlp/:username", get(lnurlp_handler))
        .route("/lnurl/pay/:username", get(lnurl_callback_handler));

    // Audit middleware sits OUTSIDE `with_state` because it carries its
    // own `State<AppState>` extractor. Layered after CORS so the audit
    // log records the final, CORS-decorated response — `Access-Control-*`
    // headers and all. The `from_fn_with_state` adapter clones the
    // state for every request (state itself is `Arc`-backed, so the
    // clone is cheap).
    app.with_state(state.clone())
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(cors)
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::audit::audit_log_middleware,
        ))
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;
