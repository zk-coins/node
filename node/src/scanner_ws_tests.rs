//! Tests for `scanner_ws.rs`.
//!
//! The connect-subscribe-drain loop and the `wait_for_tx_in_mempool`
//! helper are exercised against an in-process WebSocket server
//! constructed with `tokio_tungstenite::accept_async` — no real
//! network hop, no upstream dependency, no flakiness from public
//! Mutinynet outages.
//!
//! Pure parsers (`parse_ws_frame`, `frame_signals_tx_seen`) live in
//! `scanner_ws_parse.rs` and are unit-tested in
//! `scanner_ws_parse_tests.rs` so they stay inside the 100% coverage
//! gate (issue #84 round-4 MINOR 6).

use super::*;
use bitcoin::{BlockHash, Txid};
use futures_util::{SinkExt, StreamExt};
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Sample block hash used in fixtures. Real Mutinynet block from the
/// smoke test before the patch landed; the exact value is irrelevant
/// — only the hex shape and the `BlockHash::from_str` round-trip
/// matter to the parser.
const SAMPLE_BLOCK_HASH_HEX: &str =
    "0000001188cdecb3bfe1cd91cf2209071e272e1b87efe33773717b05270fdf0c";

const SAMPLE_BLOCK_HASH_HEX_2: &str =
    "000002b1da7c7e2e2092ae5e4caf0828d1bc301490ddc714d8a3b80f84e333c0";

fn sample_hash() -> BlockHash {
    BlockHash::from_str(SAMPLE_BLOCK_HASH_HEX).unwrap()
}

fn sample_hash_2() -> BlockHash {
    BlockHash::from_str(SAMPLE_BLOCK_HASH_HEX_2).unwrap()
}

// -----------------------------------------------------------------------------
// In-process WS server fixtures
// -----------------------------------------------------------------------------

/// Spawn a single-shot WS server on `127.0.0.1:0`. The handler
/// receives the accepted stream and is responsible for performing
/// the subscribe handshake and any test-specific scripting. Returns
/// the `ws://` URL bound by the OS.
async fn spawn_ws_server<F, Fut>(handler: F) -> String
where
    F: FnOnce(tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        handler(ws).await;
    });
    url
}

/// Helper: read the `want`/`blocks` subscribe frame and assert its
/// shape. Returns the parsed JSON so handlers can layer additional
/// assertions on top.
async fn expect_subscribe_blocks(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) {
    let first = ws.next().await.unwrap().unwrap();
    let text = match first {
        WsMessage::Text(t) => t,
        other => panic!("expected text subscribe frame, got {:?}", other),
    };
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value.get("action"), Some(&serde_json::json!("want")));
    assert_eq!(value.get("data"), Some(&serde_json::json!(["blocks"])));
}

// -----------------------------------------------------------------------------
// run_scanner_ws — happy path + reconnect + liveness watchdog
// -----------------------------------------------------------------------------

#[tokio::test]
async fn run_scanner_ws_publishes_blocks_from_server() {
    let url = spawn_ws_server(|mut ws| async move {
        expect_subscribe_blocks(&mut ws).await;
        // Send initial seed (`blocks` array) + one fresh tip.
        let initial = format!(
            r#"{{"blocks":[{{"id":"{}","height":1}}]}}"#,
            SAMPLE_BLOCK_HASH_HEX
        );
        let tip = format!(
            r#"{{"block":{{"id":"{}","height":2}}}}"#,
            SAMPLE_BLOCK_HASH_HEX_2
        );
        ws.send(WsMessage::Text(initial)).await.unwrap();
        ws.send(WsMessage::Text(tip)).await.unwrap();
        // Hold the socket open until the test aborts the task. A
        // bounded `sleep(60s)` would silently expire on a slow CI
        // runner and let the scanner observe a clean close, masking
        // any race the test is trying to pin. `pending` has the
        // identical "hold forever" semantic without the bound.
        std::future::pending::<()>().await;
    })
    .await;

    let (tx, mut rx) = mpsc::channel::<BlockHash>(8);
    let config = ScannerWsConfig {
        url,
        http_url: "http://127.0.0.1:1/api".to_string(), // unused on happy path
        reconnect_min: Duration::from_millis(10),
        reconnect_max: Duration::from_millis(50),
        liveness_timeout: Duration::from_secs(5),
    };
    let handle = tokio::spawn(run_scanner_ws(config, tx));

    let h1 = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("first hash should arrive within 5s")
        .expect("channel open");
    let h2 = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("second hash should arrive within 5s")
        .expect("channel open");
    assert_eq!(h1, sample_hash());
    assert_eq!(h2, sample_hash_2());

    handle.abort();
}

#[tokio::test]
async fn run_scanner_ws_reconnects_after_server_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        // First connection: send one block then close.
        let (s1, _) = listener.accept().await.unwrap();
        let mut ws1 = tokio_tungstenite::accept_async(s1).await.unwrap();
        expect_subscribe_blocks(&mut ws1).await;
        let m1 = format!(
            r#"{{"block":{{"id":"{}","height":1}}}}"#,
            SAMPLE_BLOCK_HASH_HEX
        );
        ws1.send(WsMessage::Text(m1)).await.unwrap();
        ws1.close(None).await.unwrap();
        drop(ws1);

        // Second connection: send the second block.
        let (s2, _) = listener.accept().await.unwrap();
        let mut ws2 = tokio_tungstenite::accept_async(s2).await.unwrap();
        expect_subscribe_blocks(&mut ws2).await;
        let m2 = format!(
            r#"{{"block":{{"id":"{}","height":2}}}}"#,
            SAMPLE_BLOCK_HASH_HEX_2
        );
        ws2.send(WsMessage::Text(m2)).await.unwrap();
        // Hold forever until the test aborts (see the matching note
        // on the first sleep replacement above).
        std::future::pending::<()>().await;
    });

    let (tx, mut rx) = mpsc::channel::<BlockHash>(8);
    let config = ScannerWsConfig {
        url,
        http_url: "http://127.0.0.1:1/api".to_string(),
        reconnect_min: Duration::from_millis(10),
        reconnect_max: Duration::from_millis(50),
        liveness_timeout: Duration::from_secs(5),
    };
    let handle = tokio::spawn(run_scanner_ws(config, tx));

    let h1 = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("first hash within 5s")
        .expect("channel open");
    assert_eq!(h1, sample_hash());

    // Drain anything the http-anchor path pushed in between (it
    // points at a closed port, so it errors out and pushes nothing
    // — but be tolerant of an empty/extra value).
    let h2 = loop {
        let next = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("second hash within 5s")
            .expect("channel open");
        if next != sample_hash() {
            break next;
        }
    };
    assert_eq!(h2, sample_hash_2());

    handle.abort();
}

#[tokio::test]
async fn run_scanner_ws_force_reconnects_on_liveness_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    tokio::spawn(async move {
        // First connection: send one block, then park BRIEFLY without
        // sending anything else — the scanner's liveness watchdog
        // (300 ms below) must fire while the handler is parked, then
        // the handler reaches the second `accept_async` in time for
        // the scanner's reconnect attempt to complete inside the
        // outer 10 s budget. Issue #84 review (round 4) BLOCKER: the
        // previous version parked for 120 s, blocking the second
        // accept and starving the scanner's reconnect handshake.
        let (s1, _) = listener.accept().await.unwrap();
        let mut ws1 = tokio_tungstenite::accept_async(s1).await.unwrap();
        expect_subscribe_blocks(&mut ws1).await;
        let m1 = format!(
            r#"{{"block":{{"id":"{}","height":1}}}}"#,
            SAMPLE_BLOCK_HASH_HEX
        );
        ws1.send(WsMessage::Text(m1)).await.unwrap();
        // Short controlled park: ≫ liveness_timeout (300 ms) so the
        // watchdog fires before we drop ws1, but ≪ outer test budget
        // (10 s) so the reconnect handshake completes in-window.
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(ws1);

        let (s2, _) = listener.accept().await.unwrap();
        let mut ws2 = tokio_tungstenite::accept_async(s2).await.unwrap();
        expect_subscribe_blocks(&mut ws2).await;
        let m2 = format!(
            r#"{{"block":{{"id":"{}","height":2}}}}"#,
            SAMPLE_BLOCK_HASH_HEX_2
        );
        ws2.send(WsMessage::Text(m2)).await.unwrap();
        // Hold forever until the test aborts (see the matching note
        // on the first sleep replacement above).
        std::future::pending::<()>().await;
    });

    let (tx, mut rx) = mpsc::channel::<BlockHash>(8);
    let config = ScannerWsConfig {
        url,
        http_url: "http://127.0.0.1:1/api".to_string(),
        reconnect_min: Duration::from_millis(10),
        reconnect_max: Duration::from_millis(50),
        // Aggressive watchdog so the test stays fast.
        liveness_timeout: Duration::from_millis(300),
    };
    let handle = tokio::spawn(run_scanner_ws(config, tx));

    let h1 = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("first hash within 5s")
        .expect("channel open");
    assert_eq!(h1, sample_hash());

    // After watchdog fires we expect the second connection to land
    // the second block. Drain any anchor-on-reconnect leftovers.
    let h2 = loop {
        let next = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("second hash within 10s")
            .expect("channel open");
        if next != sample_hash() {
            break next;
        }
    };
    assert_eq!(h2, sample_hash_2());

    handle.abort();
}

// -----------------------------------------------------------------------------
// subscribe_track_tx / TrackTxStream::wait (two-phase API, issue #84
// round-2 MAJOR 1: subscribe MUST precede the commit broadcast)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn subscribe_track_tx_then_wait_returns_when_peer_emits_txid() {
    let txid =
        Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
    let txid_str = txid.to_string();

    let url = {
        let txid_for_handler = txid_str.clone();
        spawn_ws_server(move |mut ws| async move {
            // Expect the `track-tx` subscribe frame.
            let first = ws.next().await.unwrap().unwrap();
            let text = match first {
                WsMessage::Text(t) => t,
                other => panic!("expected text frame, got {:?}", other),
            };
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(value.get("action"), Some(&serde_json::json!("track-tx")));
            assert_eq!(
                value.get("data"),
                Some(&serde_json::json!(txid_for_handler))
            );

            // Send the documented mempool.space `txPosition` shape.
            let frame = format!(
                r#"{{"txPosition":{{"txid":"{}","position":{{"block":1,"vsize":120}}}}}}"#,
                txid_for_handler
            );
            ws.send(WsMessage::Text(frame)).await.unwrap();
            // Hold forever until the test aborts.
            std::future::pending::<()>().await;
        })
        .await
    };

    let stream = subscribe_track_tx(&url, txid)
        .await
        .expect("subscribe should succeed");
    stream
        .wait(Duration::from_secs(5))
        .await
        .expect("track-tx event should resolve the wait");
}

#[tokio::test]
async fn track_tx_wait_returns_timeout_when_event_never_arrives() {
    let txid =
        Txid::from_str("2222222222222222222222222222222222222222222222222222222222222222").unwrap();
    let url = spawn_ws_server(|mut ws| async move {
        // Consume the subscribe frame but never echo the event.
        let _ = ws.next().await;
        // Hold forever until the test aborts.
        std::future::pending::<()>().await;
    })
    .await;

    let stream = subscribe_track_tx(&url, txid)
        .await
        .expect("subscribe should succeed");
    let err = stream
        .wait(Duration::from_millis(300))
        .await
        .expect_err("must surface Timeout when no event arrives");
    assert!(
        matches!(err, WsError::Timeout),
        "unexpected error: {:?}",
        err
    );
}

#[tokio::test]
async fn subscribe_track_tx_returns_connect_error_on_bad_url() {
    let txid =
        Txid::from_str("3333333333333333333333333333333333333333333333333333333333333333").unwrap();
    // 127.0.0.1:1 is reserved (tcpmux) and refused on macOS / Linux
    // CI runners — produces an immediate connect error.
    let err = subscribe_track_tx("ws://127.0.0.1:1", txid)
        .await
        .expect_err("connect to closed port must fail");
    assert!(
        matches!(err, WsError::Connect(_)),
        "expected Connect, got: {:?}",
        err
    );
}

// -----------------------------------------------------------------------------
// Smoke — `from_env`
// -----------------------------------------------------------------------------

#[test]
fn scanner_ws_config_from_env_uses_defaults_when_unset() {
    // Don't touch the process-wide env; just verify the defaults
    // are exposed via `DEFAULT_*` constants and that the struct
    // assembles. The full `from_env` round-trip is exercised by the
    // bootstrap in `main.rs`.
    assert_eq!(DEFAULT_ESPLORA_WS_URL, "wss://mutinynet.com/api/v1/ws");
    assert_eq!(DEFAULT_LIVENESS_TIMEOUT, Duration::from_secs(90));
    assert!(DEFAULT_RECONNECT_MIN < DEFAULT_RECONNECT_MAX);
}
