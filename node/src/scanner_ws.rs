//! Event-driven chain ingestion via the Esplora WebSocket stream.
//!
//! Subscribes to the mempool.space-compatible WebSocket endpoint
//! (`ESPLORA_WS_URL`, default `wss://mutinynet.com/api/v1/ws`) and
//! publishes each new tip `BlockHash` into an `mpsc::Sender` that the
//! existing `scanner_runtime` drains. Replaces the 30-s tip polling
//! loop that previously gated `/api/mint` and `/api/send` visibility
//! by up to a full block-time + poll-interval (issue #84).
//!
//! TODO(structured-logging): this module still uses `println!` /
//! `eprintln!` for runtime logs, consistent with the rest of the
//! `server` crate's current conventions. Once the crate-wide
//! migration to `tracing` lands (out of scope for issue #84), the
//! reconnect / liveness lines below are the first candidates for
//! structured fields (peer URL, attempt count, backoff value) since
//! they sit on a hot path that operators need to grep cleanly.
//!
//! ### Design points
//!
//! - Reconnect-with-backoff is encapsulated here. The outer
//!   `scanner_runtime` never sees a disconnect — it only sees
//!   `BlockHash`es arriving on the channel.
//! - Backpressure-aware `Sender::send().await` (no `try_send`): if
//!   the downstream scanner is busy processing a block, the WS
//!   reader pauses rather than dropping tip notifications.
//! - 90 s liveness watchdog (`liveness_timeout`) wraps every
//!   `ws.next()` in `tokio::time::timeout`. A silent half-open WS
//!   triggers a forced reconnect, which is the only behaviour worth
//!   the `tokio::time::` reference in event-driven code (documented
//!   in CONTRIBUTING.md, enforced by the CI lint added in the same
//!   PR).
//! - On reconnect, fetch the current tip via the existing
//!   `EsploraClient::get_tip_hash` and push that hash into the
//!   channel too. This plugs the gap that opened while we were
//!   disconnected — `scanner_runtime` already deduplicates against
//!   `processed_blocks`, so re-publishing an already-processed hash
//!   is a no-op.
//! - Every `connect_async` is wrapped in a 15 s `CONNECT_TIMEOUT`
//!   (issue #84 round-4 MAJOR 1). A half-broken middlebox can stall
//!   the TCP handshake for the kernel SYN-retransmit budget
//!   (60-180 s on Linux/Darwin); bounding it explicitly lets the
//!   reconnect-backoff loop drive recovery instead of stalling on a
//!   single attempt.
//!
//! ### Wire format
//!
//! On subscribe (`{"action":"want","data":["blocks"]}`) the server
//! immediately seeds the new client with the last few blocks in a
//! `{"blocks": [<b1>, <b2>, ...]}` message. Each subsequent tip is
//! pushed as `{"block": <b>}`. Both shapes are handled; unknown
//! frames are logged and ignored.

use std::time::Duration;

use bitcoin::BlockHash;
use esplora_client::{
    r#async::DefaultSleeper, AsyncClient as EsploraAsyncClient, Builder as EsploraBuilder,
};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

pub use crate::scanner_ws_parse::{frame_signals_tx_seen, parse_ws_frame};

/// Default endpoint for Mutinynet's mempool.space-compatible WebSocket
/// API. Overridable via `ESPLORA_WS_URL` for self-host operators and
/// for DEV failover (the URL is not officially documented for
/// Mutinynet, but it follows the upstream mempool.space convention
/// and was smoke-tested against `wss://mutinynet.com/api/v1/ws` and
/// `wss://mempool.space/signet/api/v1/ws` before this PR landed).
pub const DEFAULT_ESPLORA_WS_URL: &str = "wss://mutinynet.com/api/v1/ws";

/// Default for the liveness watchdog. A real new block arrives at
/// least every ~10 min on any live signet/mainnet, so 90 s with no
/// frame at all (including `pong` / keep-alives) is a strong "the
/// socket is half-open" signal.
pub const DEFAULT_LIVENESS_TIMEOUT: Duration = Duration::from_secs(90);

/// Default initial reconnect delay. Doubled on each consecutive
/// failure up to `DEFAULT_RECONNECT_MAX`.
pub const DEFAULT_RECONNECT_MIN: Duration = Duration::from_millis(500);

/// Default cap on the exponential reconnect backoff. 30 s matches
/// the previous polling cadence — if the upstream is genuinely
/// down for that long, we are no worse off than before.
pub const DEFAULT_RECONNECT_MAX: Duration = Duration::from_secs(30);

/// Default fallback when no `ESPLORA_URL` is in the environment.
/// Kept in sync with `lib.rs::NETWORK_CONFIG`.
pub const DEFAULT_ESPLORA_HTTP_URL: &str = "https://mutinynet.com/api";

/// Wall-clock budget for completing a single WS connect handshake.
/// A half-broken middlebox can stall the TCP handshake for the
/// kernel SYN-retransmit budget (60-180 s on Linux/Darwin); bound it
/// explicitly so the reconnect-backoff loop drives recovery instead.
/// Issue #84 review (round 4) MAJOR 1.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Initial backoff between failed `track-tx` reconnect attempts inside
/// `wait_for_tx_inner_resilient`. Doubles up to `TRACK_TX_RECONNECT_BACKOFF_MAX`.
/// Issue #84 review (round 4) MAJOR 2: prevents a tight handshake-spin
/// loop against an immediate-close peer; the outer 30 s `track-tx`
/// timeout still bounds total work.
const TRACK_TX_RECONNECT_BACKOFF_MIN: Duration = Duration::from_millis(50);

/// Cap on the inner `track-tx` reconnect backoff.
const TRACK_TX_RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Errors surfaced by the per-broadcast `subscribe_track_tx` +
/// `TrackTxStream::wait` two-phase helper used by
/// `publisher::broadcast_inscription_txs`.
#[derive(Debug)]
pub enum WsError {
    /// `tokio_tungstenite::connect_async` returned an error.
    Connect(String),
    /// The subscribe frame failed to send.
    Subscribe(String),
    /// The peer closed the socket or surfaced an error mid-stream
    /// before the expected event arrived.
    Stream(String),
    /// The safety-net deadline elapsed without the expected event.
    Timeout,
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::Connect(e) => write!(f, "WS connect failed: {}", e),
            WsError::Subscribe(e) => write!(f, "WS subscribe failed: {}", e),
            WsError::Stream(e) => write!(f, "WS stream error: {}", e),
            WsError::Timeout => write!(f, "WS timeout (no expected event in window)"),
        }
    }
}

impl std::error::Error for WsError {}

/// Wrap `connect_async` in a hard wall-clock deadline so a stalled
/// TCP/TLS handshake cannot wedge the surrounding reconnect loop for
/// the kernel SYN-retransmit budget. On timeout the returned error
/// maps to the same `WsError::Connect` shape an actual connect
/// failure would yield, so the caller's reconnect logic is uniform.
async fn connect_with_timeout(
    url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    WsError,
> {
    match tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(url)).await {
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(e)) => Err(WsError::Connect(e.to_string())),
        Err(_) => Err(WsError::Connect(format!(
            "connect_async timed out after {:?}",
            CONNECT_TIMEOUT
        ))),
    }
}

/// Runtime knobs for the scanner WS task. Sensible defaults are
/// exposed via `from_env`; tests construct it directly with shorter
/// timeouts.
#[derive(Clone, Debug)]
pub struct ScannerWsConfig {
    /// Esplora WebSocket URL. Default: `DEFAULT_ESPLORA_WS_URL`.
    pub url: String,
    /// HTTP Esplora URL used to fetch the current tip after each
    /// reconnect (plugs gaps that opened while disconnected).
    pub http_url: String,
    /// Initial reconnect delay. Doubles up to `reconnect_max`.
    pub reconnect_min: Duration,
    /// Cap on the exponential reconnect backoff.
    pub reconnect_max: Duration,
    /// Force-reconnect deadline for `ws.next()`. A silent half-open
    /// socket would otherwise wedge the scanner indefinitely.
    pub liveness_timeout: Duration,
}

impl ScannerWsConfig {
    /// Read the config from the environment, falling back to the
    /// defaults documented above. Logged once at startup by the
    /// caller in `main.rs`.
    pub fn from_env() -> Self {
        let url =
            std::env::var("ESPLORA_WS_URL").unwrap_or_else(|_| DEFAULT_ESPLORA_WS_URL.to_string());
        let http_url =
            std::env::var("ESPLORA_URL").unwrap_or_else(|_| DEFAULT_ESPLORA_HTTP_URL.to_string());
        Self {
            url,
            http_url,
            reconnect_min: DEFAULT_RECONNECT_MIN,
            reconnect_max: DEFAULT_RECONNECT_MAX,
            liveness_timeout: DEFAULT_LIVENESS_TIMEOUT,
        }
    }
}

/// Run the WS scanner forever. Connects, subscribes, drains frames,
/// reconnects on any error. Never returns under normal operation —
/// the receiver side decides when to stop draining.
///
/// `tip_tx.send(...).await` is the documented backpressure point: if
/// `scanner_runtime` is busy processing a block, the reader stalls
/// rather than dropping tips.
pub async fn run_scanner_ws(config: ScannerWsConfig, tip_tx: mpsc::Sender<BlockHash>) -> ! {
    // Build the HTTP Esplora client ONCE outside the reconnect loop
    // so a tight reconnect storm does not rebuild it per attempt.
    // Construction is cheap, but rebuilding it on every iteration is
    // wasted work and obscures the fact that the same client is the
    // shared dependency of every anchor-on-reconnect call.
    //
    // Issue #84 review (round 4) MAJOR 4: collapsed the previous
    // duplicated fallback loop into a single state machine by making
    // `http_client` an `Option`. If construction failed the inner
    // anchor call logs a warning and skips the re-anchor; the next
    // session's first WS-pushed block re-establishes the tip.
    let http_client: Option<EsploraAsyncClient<DefaultSleeper>> =
        match EsploraAsyncClient::<DefaultSleeper>::from_builder(EsploraBuilder::new(
            &config.http_url,
        )) {
            Ok(c) => Some(c),
            Err(e) => {
                // If the HTTP client cannot even be constructed (e.g.
                // an unparseable URL) we have no useful fallback.
                // Stay loud: every reconnect from here on logs that
                // the re-anchor is skipped.
                eprintln!(
                    "scanner_ws: failed to build Esplora HTTP client for {}: {}. \
                     Re-anchor on reconnect will be skipped.",
                    config.http_url, e
                );
                None
            }
        };

    let mut backoff = config.reconnect_min;
    loop {
        match connect_and_drain(&config, &tip_tx).await {
            Ok(()) => {
                // `connect_and_drain` only returns Ok when the peer
                // closed the socket cleanly — still a reconnect
                // condition, but reset the backoff so we don't punish
                // a graceful close.
                backoff = config.reconnect_min;
                eprintln!("scanner_ws: peer closed cleanly, reconnecting");
            }
            Err(e) => {
                eprintln!(
                    "scanner_ws: session ended ({}). Reconnecting in {:?}",
                    e, backoff
                );
            }
        }

        // After every reconnect — clean or not — re-anchor on the
        // current tip via HTTP. This catches blocks that landed
        // while we were disconnected. `scanner_runtime` deduplicates
        // against `processed_blocks`, so a no-op re-publish is safe.
        if let Some(client) = &http_client {
            if let Err(e) = anchor_on_current_tip(client, &tip_tx).await {
                eprintln!(
                    "scanner_ws: failed to fetch current tip after reconnect: {}",
                    e
                );
            }
        } else {
            eprintln!("scanner_ws: no HTTP client, skipping anchor on reconnect");
        }

        tokio::time::sleep(backoff).await; // scanner-polling-ok: reconnect-with-backoff between failed WS sessions, not a chain-tip poll
        backoff = (backoff * 2).min(config.reconnect_max);
    }
}

/// Single connect → subscribe → drain cycle. Returns Ok on a clean
/// close, Err on any failure. Caller schedules the reconnect.
async fn connect_and_drain(
    config: &ScannerWsConfig,
    tip_tx: &mpsc::Sender<BlockHash>,
) -> Result<(), WsError> {
    let mut ws = connect_with_timeout(&config.url).await?;
    println!("scanner_ws: connected to {}", config.url);

    let subscribe = serde_json::json!({ "action": "want", "data": ["blocks"] }).to_string();
    ws.send(WsMessage::Text(subscribe))
        .await
        .map_err(|e| WsError::Subscribe(e.to_string()))?;

    loop {
        let next = tokio::time::timeout(config.liveness_timeout, ws.next()).await;
        let frame = match next {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => return Err(WsError::Stream(e.to_string())),
            Ok(None) => return Ok(()), // clean close
            Err(_) => {
                return Err(WsError::Stream(format!(
                    "no frame in {:?} (liveness watchdog)",
                    config.liveness_timeout
                )));
            }
        };

        match frame {
            WsMessage::Text(text) => {
                for hash in parse_ws_frame(&text) {
                    if tip_tx.send(hash).await.is_err() {
                        // Receiver dropped → scanner_runtime is
                        // shutting down; drop any remaining hashes in
                        // this frame (anchor_on_current_tip on the
                        // next session would replay the latest tip
                        // anyway). Issue #84 review (round 4) MAJOR 3.
                        return Err(WsError::Stream("receiver dropped".into()));
                    }
                }
            }
            WsMessage::Binary(_) => {
                // Esplora WS does not send binary frames for the
                // `blocks` subscription, but tungstenite delivers
                // protocol frames here too. Ignore quietly.
            }
            WsMessage::Ping(_) | WsMessage::Pong(_) => {
                // tungstenite handles ping/pong internally; nothing
                // to do.
            }
            WsMessage::Close(_) => return Ok(()),
            // The `Frame` variant of `tungstenite::Message` only
            // surfaces under the `frame` cargo feature, which we do
            // not enable. Keep the arm here as a defensive catch-all
            // so a future tungstenite upgrade that flips the feature
            // default does not break the build via a non-exhaustive
            // match warning.
            #[allow(unreachable_patterns)]
            WsMessage::Frame(_) => {}
        }
    }
}

/// On reconnect, fetch the current tip via HTTP and push it into
/// the channel so `scanner_runtime` can re-anchor. Bounded by a
/// short timeout — the channel must not stall on a slow tip lookup.
/// The Esplora client is owned by `run_scanner_ws` and passed in by
/// reference so we do not rebuild it on every reconnect.
async fn anchor_on_current_tip(
    client: &EsploraAsyncClient<DefaultSleeper>,
    tip_tx: &mpsc::Sender<BlockHash>,
) -> Result<(), String> {
    let lookup = tokio::time::timeout(Duration::from_secs(10), client.get_tip_hash());
    let hash = match lookup.await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("get_tip_hash timed out".into()),
    };

    if tip_tx.send(hash).await.is_err() {
        return Err("receiver dropped".into());
    }
    Ok(())
}

/// Per-frame watchdog used by the inner `track-tx` wait loop. The
/// outer 30 s `TRACK_TX_TIMEOUT_SECS` budget is owned by the publisher;
/// this inner watchdog detects a half-open peer that swallows frames
/// without delivering any event, so we can reconnect-and-re-subscribe
/// within the outer envelope rather than sitting for the full 30 s on
/// a wedged socket.
const TRACK_TX_FRAME_WATCHDOG: Duration = Duration::from_secs(10);

/// A live `track-tx` subscription against the Esplora WS. Returned by
/// [`subscribe_track_tx`]. Calling [`TrackTxStream::wait`] drains the
/// subscription until the peer reports the tracked txid as seen, or
/// until `timeout` elapses (whichever comes first).
///
/// The split between `subscribe_track_tx` and `wait` is load-bearing
/// (issue #84): the publisher MUST establish the subscription BEFORE
/// broadcasting the commit transaction, otherwise the upstream may
/// propagate the tx between the broadcast and the subscribe and the
/// "tx in mempool" event would fire before we are listening. With the
/// split, the subscribe handshake is complete before the broadcast
/// races against it.
pub struct TrackTxStream {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    url: String,
    txid: bitcoin::Txid,
    txid_str: String,
}

impl std::fmt::Debug for TrackTxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackTxStream")
            .field("url", &self.url)
            .field("txid", &self.txid)
            .finish_non_exhaustive()
    }
}

impl TrackTxStream {
    /// Drain the subscription until the peer reports the tracked
    /// txid, or the outer `timeout` elapses. The implementation also
    /// runs a per-frame watchdog ([`TRACK_TX_FRAME_WATCHDOG`]) so a
    /// silent half-open peer triggers a forced reconnect within the
    /// outer budget rather than wedging the full window.
    ///
    /// On reconnect we re-open the WS and re-send the `track-tx`
    /// subscribe frame, then continue waiting against the remaining
    /// outer budget. This keeps the publisher's contract simple: a
    /// missing event surfaces as `WsError::Timeout` exactly when the
    /// caller's deadline elapses, regardless of how many half-open
    /// reconnects happened in between.
    pub async fn wait(self, timeout: Duration) -> Result<(), WsError> {
        tokio::time::timeout(timeout, wait_for_tx_inner_resilient(self))
            .await
            .map_err(|_| WsError::Timeout)?
    }
}

/// Open a short-lived WS to `url`, subscribe to `track-tx` for
/// `txid`, and return the live stream WITHOUT yet waiting for an
/// event. The caller is expected to drive the actual wait via
/// [`TrackTxStream::wait`] after performing whatever side-effect the
/// subscription is gating (in our case: broadcasting the commit
/// transaction on the Esplora REST endpoint).
///
/// Splitting the two-phase API away from the old all-in-one
/// `wait_for_tx_in_mempool` plugs the issue #84 race: with the
/// single-call helper, the publisher used to broadcast the commit
/// BEFORE the subscribe completed, so the "tx in mempool" event
/// could fire before any listener was attached.
pub async fn subscribe_track_tx(url: &str, txid: bitcoin::Txid) -> Result<TrackTxStream, WsError> {
    let mut ws = connect_with_timeout(url).await?;

    let txid_str = txid.to_string();
    let subscribe = serde_json::json!({
        "action": "track-tx",
        "data": txid_str,
    })
    .to_string();
    ws.send(WsMessage::Text(subscribe))
        .await
        .map_err(|e| WsError::Subscribe(e.to_string()))?;

    Ok(TrackTxStream {
        ws,
        url: url.to_string(),
        txid,
        txid_str,
    })
}

/// Inner loop with per-frame watchdog + transparent reconnect. On a
/// per-frame timeout (`TRACK_TX_FRAME_WATCHDOG`), tear the current WS
/// down and re-subscribe; continue draining until the outer caller's
/// deadline elapses (which it does via `tokio::time::timeout` wrapping
/// this future in `TrackTxStream::wait`).
///
/// Issue #84 review (round 4) MAJOR 2: a peer that accepts and
/// immediately closes (or drops every frame) used to make this loop
/// tight-spin a fresh TCP+TLS handshake per iteration. We now apply
/// an exponential backoff between failed reconnects (50 ms → 1 s)
/// and reset it to 50 ms on the next successful connect+subscribe so
/// a single transient drop does not penalise subsequent good runs.
/// The outer 30 s `tokio::time::timeout` continues to bound total
/// work, so the backoff can never starve the publisher.
async fn wait_for_tx_inner_resilient(stream: TrackTxStream) -> Result<(), WsError> {
    let TrackTxStream {
        mut ws,
        url,
        txid,
        txid_str,
    } = stream;

    // Per-reconnect backoff. Doubles per consecutive failure, capped
    // at `TRACK_TX_RECONNECT_BACKOFF_MAX`. Reset to MIN whenever the
    // current session yields any frame from the peer ("good run").
    let mut reconnect_backoff = TRACK_TX_RECONNECT_BACKOFF_MIN;

    loop {
        let next = tokio::time::timeout(TRACK_TX_FRAME_WATCHDOG, ws.next()).await;
        match next {
            Ok(Some(Ok(WsMessage::Text(text)))) => {
                if frame_signals_tx_seen(&text, &txid_str) {
                    return Ok(());
                }
                // Non-matching text frame (heartbeat, position update
                // for some other tx, mempool stats). Keep draining.
                // The peer is delivering frames → this is a "good
                // run", so reset the reconnect backoff.
                reconnect_backoff = TRACK_TX_RECONNECT_BACKOFF_MIN;
            }
            Ok(Some(Ok(WsMessage::Close(_)))) | Ok(None) => {
                // Peer closed the socket before delivering the event.
                // Reconnect and re-subscribe; the outer timeout caps
                // how long we keep trying.
                eprintln!(
                    "scanner_ws: track-tx peer closed before event for {}; reconnecting after {:?}",
                    txid, reconnect_backoff
                );
                tokio::time::sleep(reconnect_backoff).await; // scanner-polling-ok: reconnect-backoff between failed track-tx sessions (issue #84 round-4 MAJOR 2)
                ws = reconnect_track_tx(&url, &txid_str).await?;
                reconnect_backoff = (reconnect_backoff * 2).min(TRACK_TX_RECONNECT_BACKOFF_MAX);
            }
            Ok(Some(Ok(_))) => {
                // Binary / ping / pong / raw frame — tungstenite
                // handles ping/pong internally and the others are not
                // emitted by Esplora for this subscription. Ignore,
                // but treat as evidence of a live peer.
                reconnect_backoff = TRACK_TX_RECONNECT_BACKOFF_MIN;
            }
            Ok(Some(Err(e))) => {
                return Err(WsError::Stream(e.to_string()));
            }
            Err(_) => {
                // Per-frame watchdog elapsed. Treat as half-open and
                // reconnect within the outer caller's budget.
                eprintln!(
                    "scanner_ws: track-tx frame watchdog ({:?}) elapsed for {}; reconnecting after {:?}",
                    TRACK_TX_FRAME_WATCHDOG, txid, reconnect_backoff
                );
                tokio::time::sleep(reconnect_backoff).await; // scanner-polling-ok: reconnect-backoff between failed track-tx sessions (issue #84 round-4 MAJOR 2)
                ws = reconnect_track_tx(&url, &txid_str).await?;
                reconnect_backoff = (reconnect_backoff * 2).min(TRACK_TX_RECONNECT_BACKOFF_MAX);
            }
        }
    }
}

/// Helper used by the inner wait loop: tear down the current ws (the
/// drop happens by reassignment in the caller) and open a fresh
/// connection with the same `track-tx` subscription frame.
async fn reconnect_track_tx(
    url: &str,
    txid_str: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    WsError,
> {
    let mut ws = connect_with_timeout(url).await?;
    let subscribe = serde_json::json!({
        "action": "track-tx",
        "data": txid_str,
    })
    .to_string();
    ws.send(WsMessage::Text(subscribe))
        .await
        .map_err(|e| WsError::Subscribe(e.to_string()))?;
    Ok(ws)
}

#[cfg(test)]
#[path = "scanner_ws_tests.rs"]
mod tests;
