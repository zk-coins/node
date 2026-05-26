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
        // Pin the ping cadence well above the test budget — the
        // happy-path coverage here is about block delivery, not the
        // keepalive (separate test below).
        ping_interval: Duration::from_secs(60),
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
        // Same rationale as the previous test — keepalive is not
        // under examination here.
        ping_interval: Duration::from_secs(60),
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
        // For this test the handler explicitly STOPS reading on
        // server side after the first block — so an outbound ping
        // gets no auto-Pong reply. Pin ping_interval well above the
        // 300 ms watchdog so the watchdog fires for the documented
        // "no inbound frame in window" reason rather than racing the
        // ping-pong round-trip. The keepalive-specific behaviour is
        // covered by the dedicated tests further down.
        ping_interval: Duration::from_secs(60),
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

// -----------------------------------------------------------------------------
// Ping keepalive — RFC 6455 §5.5 Pong-driven liveness
// -----------------------------------------------------------------------------

/// Sanity: the default ping cadence leaves room for at least one
/// full ping + pong round-trip inside the watchdog window with
/// margin. A drifted constant (e.g. someone bumping
/// `DEFAULT_PING_INTERVAL` to 60s without raising the watchdog)
/// would silently reintroduce the spurious-reconnect class this
/// keepalive is here to fix; the assertion turns that into a
/// build-time test failure.
#[test]
fn ping_interval_is_strictly_below_half_liveness_timeout() {
    assert!(
        DEFAULT_PING_INTERVAL * 2 < DEFAULT_LIVENESS_TIMEOUT,
        "DEFAULT_PING_INTERVAL ({:?}) must be < DEFAULT_LIVENESS_TIMEOUT/2 ({:?})",
        DEFAULT_PING_INTERVAL,
        DEFAULT_LIVENESS_TIMEOUT,
    );
    // And it should be non-trivially smaller than the watchdog
    // itself; a value within one tick of the watchdog would race
    // the watchdog under any timer jitter.
    assert!(DEFAULT_PING_INTERVAL < DEFAULT_LIVENESS_TIMEOUT);
}

/// Quiet-server test: the server completes the subscribe handshake,
/// sends no further block frames, but DOES keep draining its read
/// half. Tungstenite auto-pongs every inbound Ping, so each of our
/// keepalive pings produces an inbound Pong on the scanner's reader
/// and resets the liveness deadline. With keepalive working the
/// scanner stays connected through several watchdog windows back-to-
/// back; without keepalive (the pre-fix shape) the watchdog would
/// fire after one window and the test handler would see a second
/// `accept()`.
#[tokio::test]
async fn run_scanner_ws_pongs_keep_connection_alive_past_liveness_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    // Track how many connections the scanner opens. If the keepalive
    // works, this stays at 1 for the entire test window. If the
    // keepalive is broken, the watchdog fires and the scanner
    // reconnects (count goes ≥ 2 well inside our budget).
    let connection_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc_for_server = std::sync::Arc::clone(&connection_count);

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            cc_for_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            // Consume the subscribe frame and then keep draining the
            // socket forever. tungstenite auto-queues a Pong reply
            // for every inbound Ping while the stream is being polled,
            // so the scanner sees a Pong on every keepalive tick.
            // Crucially we send NO block frames — the only thing
            // reaching the scanner's reader is the pong stream.
            while let Some(msg) = ws.next().await {
                if msg.is_err() {
                    break;
                }
                // Drop the message and continue. We never send any
                // application-level frame.
            }
        }
    });

    let (tx, mut rx) = mpsc::channel::<BlockHash>(8);
    // Watchdog short enough that the test stays fast; ping interval
    // strictly < watchdog/2 (matching the production invariant) so a
    // pong fits comfortably inside every watchdog window.
    let config = ScannerWsConfig {
        url,
        http_url: "http://127.0.0.1:1/api".to_string(),
        reconnect_min: Duration::from_millis(10),
        reconnect_max: Duration::from_millis(50),
        liveness_timeout: Duration::from_millis(400),
        ping_interval: Duration::from_millis(100),
    };
    let handle = tokio::spawn(run_scanner_ws(config, tx));

    // Wait for >> liveness_timeout. Without keepalive the scanner
    // would fire the watchdog after ~400 ms and reconnect; with
    // keepalive the connection_count stays at 1.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Block channel must be empty (server sent no block frames at
    // all) — keepalive must not introduce phantom tip events.
    assert!(
        rx.try_recv().is_err(),
        "scanner must not publish any BlockHash when the server only echoes pings"
    );

    let observed = connection_count.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        observed, 1,
        "expected exactly 1 connection (keepalive should prevent the watchdog reconnect); \
         saw {} connections, which means the watchdog fired",
        observed,
    );

    handle.abort();
}

/// Failure-mode test: the server completes the subscribe handshake
/// and then stops reading entirely. Outbound pings pile up in the
/// server's TCP receive buffer; no Pong ever comes back; nothing
/// resets the deadline. The watchdog MUST fire after
/// `liveness_timeout` and the scanner MUST reconnect. Asserts the
/// brief's "no pong + no event in 90 s = connection genuinely dead"
/// semantic.
#[tokio::test]
async fn run_scanner_ws_watchdog_fires_when_pongs_are_dropped() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    let connection_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc_for_server = std::sync::Arc::clone(&connection_count);

    tokio::spawn(async move {
        // Accept connections in a loop and hand each off to a
        // dedicated task that parks forever — that way subsequent
        // accepts can run while earlier connections are still being
        // held open. The scanner reconnects after the watchdog, so
        // the listener must keep accepting beyond the first
        // connection for the test to observe count ≥ 2.
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            cc_for_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                // Read exactly the subscribe frame so the handshake
                // completes, then stop touching the socket. The pings
                // the scanner sends from now on are never observed
                // and never auto-ponged; the scanner's deadline must
                // elapse.
                let _ = ws.next().await;
                // Hold the socket open so the scanner's only path
                // out is the watchdog.
                std::future::pending::<()>().await;
            });
        }
    });

    let (tx, mut rx) = mpsc::channel::<BlockHash>(8);
    let config = ScannerWsConfig {
        url,
        http_url: "http://127.0.0.1:1/api".to_string(),
        reconnect_min: Duration::from_millis(10),
        reconnect_max: Duration::from_millis(50),
        liveness_timeout: Duration::from_millis(300),
        // Ping cadence is well inside the watchdog window — but
        // since the server never auto-pongs, the watchdog still
        // fires.
        ping_interval: Duration::from_millis(100),
    };
    let handle = tokio::spawn(run_scanner_ws(config, tx));

    // Allow the watchdog to fire at least once and the scanner to
    // open a fresh connection. 1.5 s is enough for several watchdog
    // windows back to back.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let observed = connection_count.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        observed >= 2,
        "expected ≥ 2 connections (watchdog must fire when pongs are dropped); \
         saw {} connections",
        observed,
    );

    // No block frames ever flowed, so the scanner channel must be
    // empty — keepalive doesn't conjure tips out of dropped pongs.
    assert!(
        rx.try_recv().is_err(),
        "scanner must not publish any BlockHash when no block frames are sent",
    );

    handle.abort();
}

/// Send-error reconnect: the server completes the subscribe handshake
/// and then drops the TCP socket abruptly (no clean WS close frame,
/// no graceful FIN handshake — just `drop(ws)` which closes the
/// underlying TcpStream). The scanner's next ping-ticker tick attempts
/// to write a Ping frame to the now-closed socket; the writer task's
/// `sink.feed`/`flush` returns `Err` (broken pipe / connection reset)
/// and the main loop surfaces that as `WsError::Stream("ping send
/// failed: ...")`, driving a reconnect via the normal backoff loop.
///
/// Race-note: in practice the reader arm may also observe the close
/// (as `Some(Err(_))` or `None`) on roughly the same scheduling tick
/// as the ping arm. Both paths produce the SAME observable behaviour
/// — fast reconnect well inside `liveness_timeout` — and both go
/// through the cancel-safe writer-task plumbing introduced for the
/// ping-send branch, so either winning the race exercises the
/// cancel-safety guarantee. The assertion below pins the observable
/// invariant: reconnect happens MUCH faster than the watchdog window,
/// which is only achievable if a non-watchdog reconnect path fired.
#[tokio::test]
async fn run_scanner_ws_reconnects_when_ping_send_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    let connection_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc_for_server = std::sync::Arc::clone(&connection_count);

    tokio::spawn(async move {
        // Accept connections in a loop; per-connection handler drops
        // the WS as soon as the subscribe frame arrives. Subsequent
        // accepts continue to fire so the scanner's reconnect attempt
        // can land cleanly.
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            cc_for_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                // Wait for the subscribe frame so the handshake is
                // observably complete (the scanner has transitioned
                // out of connect/subscribe and into the steady-state
                // select loop) before we tear the socket down.
                let _ = ws.next().await;
                // Drop the WS — this drops the underlying TcpStream,
                // which closes the connection from the server side.
                // The scanner's next outbound write (ping-tick) sees
                // a broken pipe; the reader sees an EOF/error around
                // the same time. Either way the scanner exits the
                // current session via a non-watchdog path and the
                // outer reconnect loop opens a fresh TCP connection
                // (which lands here, incrementing the counter).
                drop(ws);
            });
        }
    });

    let (tx, mut rx) = mpsc::channel::<BlockHash>(8);
    // Liveness watchdog is set to a value LARGER than the test budget
    // below so that a count ≥ 2 within the budget cannot possibly be
    // attributed to a watchdog firing — the reconnect MUST have come
    // from the close-detection path (ping-send error or read error).
    // Ping cadence is tight so the first ping tick fires within a few
    // ms of the subscribe completing, giving the send-error path the
    // best chance to be the path that actually drives the reconnect.
    let config = ScannerWsConfig {
        url,
        http_url: "http://127.0.0.1:1/api".to_string(),
        reconnect_min: Duration::from_millis(10),
        reconnect_max: Duration::from_millis(50),
        liveness_timeout: Duration::from_secs(30),
        ping_interval: Duration::from_millis(50),
    };
    let handle = tokio::spawn(run_scanner_ws(config, tx));

    // Budget for observing the reconnect. Must be ≫ ping_interval +
    // reconnect_max but ≪ liveness_timeout, so any observed
    // reconnect MUST be driven by the close-detection path, not the
    // watchdog. 2 s comfortably satisfies both.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let observed = connection_count.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        observed >= 2,
        "scanner must reconnect via the close-detection path \
         (ping-send-error OR read-error) — observed only {} connections \
         in the budget window, well inside the 30 s liveness watchdog",
        observed,
    );

    // The server never sent any block frames, only the implicit
    // subscribe-then-drop. The channel must therefore be empty —
    // failure-path reconnects must not inject phantom tips.
    assert!(
        rx.try_recv().is_err(),
        "scanner must not publish any BlockHash when no block frames are sent",
    );

    handle.abort();
}

/// Writer-send-timeout reconnect: exercises the
/// `tokio::time::timeout(liveness_timeout, out_tx.send(...))` guard
/// added around the ping arm's `out_tx.send` to defuse the
/// backpressure-deadlock window. The deadlock shape it defuses:
///
/// 1. The peer accepts the TCP socket and completes the WS upgrade,
///    but then never reads from the socket again. The OS-level TCP
///    send window on the scanner side fills up.
/// 2. The dedicated writer task wedges inside `sink.flush().await`
///    waiting for the kernel to drain that buffer.
/// 3. The 1-slot `out_tx` channel fills with the first un-flushed
///    ping (writer holds it, can't progress).
/// 4. The next `ping_ticker.tick()` fires; its body calls
///    `out_tx.send(...).await`, which now blocks because the queue
///    is full and the writer can't drain it.
/// 5. WITHOUT the timeout wrap, this `.await` sits forever — the
///    enclosing `select!` has already exited (the ping arm won),
///    so the watchdog arm can't fire to break the deadlock.
/// 6. WITH the timeout wrap, the wedge surfaces as a stream error
///    inside `liveness_timeout`, the outer reconnect loop kicks in,
///    and a fresh TCP connection lands at the server.
///
/// Setup: we shrink the server-side `SO_RCVBUF` on the listener to
/// the OS-minimum BEFORE `accept()`, so each accepted socket inherits
/// a tiny receive buffer (a few KB). Combined with a server that
/// reads exactly one frame (the subscribe) and then parks on
/// `pending()`, the client's kernel send buffer + the server's
/// receive buffer fill up after a handful of pings, and `flush()`
/// wedges inside the test budget.
///
/// `liveness_timeout = 300 ms` + `ping_interval = 50 ms` match the
/// reviewer's spec: the wedge bites well before either the watchdog
/// or the test-budget timeout, so observing ≥ 2 server-side accepts
/// inside ~3 s is positive evidence that a non-deadlock reconnect
/// path drove the reconnect.
#[cfg(unix)]
#[tokio::test]
async fn run_scanner_ws_reconnects_when_writer_send_times_out() {
    use std::os::unix::io::AsRawFd;

    // Bind a std listener first so we can `setsockopt(SO_RCVBUF)`
    // BEFORE handing it to tokio. Accepted sockets inherit the small
    // receive buffer, which is what fills the client's send window
    // and wedges `sink.flush()`. The exact size is platform-clamped:
    // Linux rounds up to its minimum (typically ~2 KB); macOS honors
    // it closer to the literal value. Either way the result is small
    // enough that a handful of WS Ping frames + WS framing overhead
    // saturate it inside the test budget.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    {
        let fd = std_listener.as_raw_fd();
        let bufsize: libc::c_int = 1024;
        // SAFETY: `fd` is a live socket file descriptor owned by
        // `std_listener` for the duration of this call; the option
        // name and value pointer are well-formed per setsockopt(2);
        // the return value is checked below.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &bufsize as *const _ as *const libc::c_void,
                std::mem::size_of_val(&bufsize) as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt SO_RCVBUF must succeed");
    }
    let listener = TcpListener::from_std(std_listener).unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    let connection_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cc_for_server = std::sync::Arc::clone(&connection_count);

    tokio::spawn(async move {
        // Per-connection handler: complete the WS handshake, read the
        // subscribe frame so the scanner observably transitions into
        // its steady-state select loop, then PARK without reading
        // anything else. The server-side socket's receive buffer
        // (shrunk via SO_RCVBUF on the listener above) fills up after
        // a handful of pings; the client's `sink.flush()` then wedges
        // on TCP backpressure, the 1-slot `out_tx` fills, and the
        // next `out_tx.send(...).await` in the ping arm hits the new
        // `liveness_timeout` wrap.
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            cc_for_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut ws = match tokio_tungstenite::accept_async(stream).await {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                // Read the subscribe frame so the handshake is fully
                // observable as complete; subsequent reads are
                // intentionally omitted so the receive buffer fills.
                let _ = ws.next().await;
                // Hold the socket open forever — do NOT read anything
                // else. The scanner's pings will pile up in the
                // (small) kernel buffer and wedge the writer.
                std::future::pending::<()>().await;
            });
        }
    });

    let (tx, mut rx) = mpsc::channel::<BlockHash>(8);
    // `liveness_timeout = 300 ms`: short enough that the timeout-wrap
    // around `out_tx.send` fires inside the test budget, long enough
    // that we don't race a slow CI scheduler.
    // `ping_interval = 50 ms`: fast enough to fill the 1-slot writer
    // queue + saturate the small receive buffer well before the
    // first watchdog window elapses.
    let config = ScannerWsConfig {
        url,
        http_url: "http://127.0.0.1:1/api".to_string(),
        reconnect_min: Duration::from_millis(10),
        reconnect_max: Duration::from_millis(50),
        liveness_timeout: Duration::from_millis(300),
        ping_interval: Duration::from_millis(50),
    };
    let handle = tokio::spawn(run_scanner_ws(config, tx));

    // Budget: ≫ liveness_timeout + reconnect_max so at least one
    // reconnect cycle is observable, ≪ any realistic CI flake budget.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let observed = connection_count.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        observed >= 2,
        "scanner must reconnect when the writer wedges — observed only \
         {} connections in the budget window (timeout-wrap path OR \
         watchdog path, both valid reconnect drivers)",
        observed,
    );

    // No block frames were ever sent, so the channel must be empty.
    assert!(
        rx.try_recv().is_err(),
        "scanner must not publish any BlockHash when no block frames are sent",
    );

    handle.abort();
}
