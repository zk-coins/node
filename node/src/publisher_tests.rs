//! Tests for `publisher.rs`.
//!
//! The pure inscription building / Schnorr signing / witness mining logic
//! in `inscription_txs` is exercised end-to-end with deterministic inputs.
//! The Esplora-touching helpers (`get_publisher_utxo`,
//! `broadcast_inscription_txs`, `create_and_broadcast_inscription`) are
//! exercised against a `wiremock` mock server so no real network is hit.

use super::*;
use bitcoin::blockdata::opcodes;
use bitcoin::hashes::Hash;
use bitcoin::script::Instruction;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Address, Network, OutPoint, Txid, XOnlyPublicKey};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test publisher key used to produce deterministic Taproot addresses
/// and signatures. The production `PUBLISHER_KEY` is now a required env
/// var with no default (see `lib.rs`); this constant is a local
/// test-only placeholder passed directly into `inscription_txs` and
/// never reaches the global `crate::PUBLISHER_KEY` resolution. Matches
/// the CI test value in `.github/workflows/ci.yaml`.
const TEST_PUBLISHER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

fn test_publisher_address(network: Network) -> Address {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_str(TEST_PUBLISHER_KEY).unwrap();
    let key_pair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&key_pair);
    Address::p2tr(&secp, xonly, None, network)
}

/// Build an arbitrary deterministic outpoint with all-zero txid and the
/// given vout. Good enough for tests — nothing on chain is verified.
fn fake_outpoint(vout: u32) -> OutPoint {
    OutPoint::new(Txid::all_zeros(), vout)
}

/// Spin up a wiremock server and produce an `EsploraConfig` that points
/// the publisher code at it. The WS endpoint is left unset because most
/// HTTP-only tests never reach the broadcast path.
async fn setup_mock_esplora() -> (MockServer, EsploraConfig) {
    let mock_server = MockServer::start().await;
    let config = EsploraConfig {
        url: mock_server.uri(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
        track_tx_timeout: None,
    };
    (mock_server, config)
}

/// Spin up an in-process WS server that emulates the Esplora
/// `track-tx` flow used by `broadcast_inscription_txs` (issue #84):
/// accept the subscribe frame and, depending on `mode`, either echo
/// back a `mempool: true` event for the txid the client subscribed
/// to (mode = "echo") or stay silent (mode = "silent") so the
/// publisher's 30-s safety-net fires. Returns the `ws://` URL.
async fn spawn_track_tx_ws(mode: &'static str) -> String {
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
            // Read the subscribe frame.
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
                    if mode == "echo" {
                        // Documented mempool.space `txPosition` shape;
                        // see `scanner_ws::frame_signals_tx_seen`.
                        let frame = format!(
                            r#"{{"txPosition":{{"txid":"{}","position":{{"block":1,"vsize":120}}}}}}"#,
                            txid_str
                        );
                        let _ = ws.send(WsMessage::Text(frame)).await;
                    }
                }
            }
            // Hold the connection open until the test aborts the
            // task. `std::future::pending` keeps the socket alive
            // indefinitely so a slow CI runner can never let the
            // helper observe a clean close before the event arrives;
            // a bounded `sleep(60s)` could expire and mask a race.
            std::future::pending::<()>().await;
        }
    });
    url
}

// -----------------------------------------------------------------------------
// Pure logic: inscription_txs
// -----------------------------------------------------------------------------

/// The reveal transaction's txid must start with the `INSCRIPTION_MARKER_PREFIX`
/// (the scanner relies on this prefix to find inscriptions in the chain).
#[test]
fn inscription_txs_produces_taproot_commit_and_reveal_with_marker_prefix() {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
        track_tx_timeout: None,
    };
    let publisher_address = test_publisher_address(config.network());
    let outpoints = vec![(fake_outpoint(0), 100_000u64)];

    let (commit_tx, reveal_tx) = inscription_txs(
        b"Hello, zkCoins!",
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );

    // commit_tx must spend the supplied outpoint.
    assert_eq!(commit_tx.input.len(), 1);
    assert_eq!(commit_tx.input[0].previous_output, fake_outpoint(0));

    // reveal_tx txid starts with the marker prefix (so the scanner picks
    // it up). `hex::decode` is the canonical inverse of the publisher's
    // own check.
    let target = hex::decode(INSCRIPTION_MARKER_PREFIX).unwrap();
    let txid_bytes = reveal_tx.compute_txid().as_byte_array().to_vec();
    assert!(
        txid_bytes.starts_with(&target),
        "reveal txid {} does not start with {}",
        reveal_tx.compute_txid(),
        INSCRIPTION_MARKER_PREFIX
    );
}

/// Reveal-script witness must embed the commitment payload bytes verbatim.
/// In a Taproot script-spend the witness layout is `[sig, script, control]`,
/// so the script is the second-to-last witness item.
#[test]
fn inscription_txs_embeds_commitment_data_in_reveal_script() {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
        track_tx_timeout: None,
    };
    let publisher_address = test_publisher_address(config.network());
    let payload = b"Hello, zkCoins!".to_vec();
    let outpoints = vec![(fake_outpoint(0), 100_000u64)];

    let (_commit_tx, reveal_tx) = inscription_txs(
        &payload,
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );

    let witness_items: Vec<Vec<u8>> = reveal_tx.input[0]
        .witness
        .iter()
        .map(|w| w.to_vec())
        .collect();
    assert_eq!(
        witness_items.len(),
        3,
        "reveal witness must be [sig, script, control_block]"
    );

    // The script lives at index `len - 2`. Walk its push-data chunks and
    // collect them to reconstruct the embedded payload.
    let script_bytes = &witness_items[witness_items.len() - 2];
    let script = bitcoin::ScriptBuf::from_bytes(script_bytes.clone());

    let mut collected = Vec::new();
    let mut prev_was_op_false = false;
    let mut inside = false;
    for ins in script.instructions().flatten() {
        if inside {
            match ins {
                Instruction::PushBytes(b) => collected.extend_from_slice(b.as_bytes()),
                Instruction::Op(op) if op == opcodes::all::OP_ENDIF => break,
                _ => {}
            }
        } else {
            match ins {
                Instruction::PushBytes(b) if b.is_empty() => prev_was_op_false = true,
                Instruction::Op(op) if op == opcodes::all::OP_IF && prev_was_op_false => {
                    inside = true;
                }
                _ => prev_was_op_false = false,
            }
        }
    }

    assert_eq!(
        collected, payload,
        "reveal script must embed the exact commitment data"
    );
}

/// Commitment payloads larger than `MAX_CHUNK_SIZE` (520 bytes) must be
/// split into multiple push-data chunks inside the reveal script.
#[test]
fn inscription_txs_chunks_large_commitment_data() {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
        track_tx_timeout: None,
    };
    let publisher_address = test_publisher_address(config.network());
    // 600 bytes of repeating non-zero pattern (zero bytes would collide
    // with the OP_FALSE delimiter inside the loop below).
    let payload: Vec<u8> = (0..600).map(|i| (i % 255 + 1) as u8).collect();
    let outpoints = vec![(fake_outpoint(0), 200_000u64)];

    let (_commit_tx, reveal_tx) = inscription_txs(
        &payload,
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );

    let witness_items: Vec<Vec<u8>> = reveal_tx.input[0]
        .witness
        .iter()
        .map(|w| w.to_vec())
        .collect();
    let script_bytes = &witness_items[witness_items.len() - 2];
    let script = bitcoin::ScriptBuf::from_bytes(script_bytes.clone());

    // Count push-data chunks inside the OP_FALSE / OP_IF envelope.
    let mut prev_was_op_false = false;
    let mut inside = false;
    let mut chunk_count = 0usize;
    for ins in script.instructions().flatten() {
        if inside {
            match ins {
                Instruction::PushBytes(_) => chunk_count += 1,
                Instruction::Op(op) if op == opcodes::all::OP_ENDIF => break,
                _ => {}
            }
        } else {
            match ins {
                Instruction::PushBytes(b) if b.is_empty() => prev_was_op_false = true,
                Instruction::Op(op) if op == opcodes::all::OP_IF && prev_was_op_false => {
                    inside = true;
                }
                _ => prev_was_op_false = false,
            }
        }
    }

    // 600 bytes / 520 per chunk = 2 chunks (520 + 80).
    assert_eq!(
        chunk_count, 2,
        "600-byte payload must be split into exactly 2 push_slice chunks"
    );
}

/// The commit transaction's input witness must carry a 64-byte BIP-340
/// Schnorr signature (key-spend, default sighash → no sighash flag byte).
#[test]
fn inscription_txs_signs_commit_input_with_taproot_keyspend() {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
        track_tx_timeout: None,
    };
    let publisher_address = test_publisher_address(config.network());
    let outpoints = vec![(fake_outpoint(0), 100_000u64)];

    let (commit_tx, _reveal_tx) = inscription_txs(
        b"Hello, zkCoins!",
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );

    let witness_items: Vec<Vec<u8>> = commit_tx.input[0]
        .witness
        .iter()
        .map(|w| w.to_vec())
        .collect();
    assert_eq!(
        witness_items.len(),
        1,
        "key-spend witness must be exactly [signature]"
    );
    assert_eq!(
        witness_items[0].len(),
        64,
        "BIP-340 Schnorr signature with default sighash is 64 bytes (no sighash flag)"
    );
}

/// `EsploraConfig::network()` must map `is_mainnet=false` to `Signet`.
/// The publisher derives the commit/publisher address from this network,
/// so an off-by-one here would silently broadcast to the wrong chain.
#[test]
fn inscription_txs_uses_signet_when_is_mainnet_false() {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
        track_tx_timeout: None,
    };
    assert_eq!(config.network(), Network::Signet);

    // And the mainnet branch — guards the bool-flip too.
    let mainnet_config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: true,
        network_name: "Mainnet".to_string(),
        ws_url: None,
        track_tx_timeout: None,
    };
    assert_eq!(mainnet_config.network(), Network::Bitcoin);
}

// -----------------------------------------------------------------------------
// Esplora HTTP, mocked via wiremock
// -----------------------------------------------------------------------------

#[tokio::test]
async fn get_publisher_utxo_returns_empty_when_address_has_no_utxos() {
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let result = get_publisher_utxo(&publisher_address, &config, None)
        .await
        .expect("call should succeed");
    assert!(result.is_empty(), "empty Esplora response → empty Vec");
}

#[tokio::test]
async fn get_publisher_utxo_returns_utxos_with_value() {
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    let txid_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "txid": txid_hex,
                "vout": 3,
                "value": 1000,
                "status": { "confirmed": true, "block_height": 100, "block_hash": "0000000000000000000000000000000000000000000000000000000000000001", "block_time": 1700000000 }
            }
        ])))
        .mount(&server)
        .await;

    let result = get_publisher_utxo(&publisher_address, &config, None)
        .await
        .expect("call should succeed");

    assert_eq!(result.len(), 1, "exactly one UTXO is mapped through");
    let (outpoint, sats) = result[0];
    assert_eq!(sats, 1000);
    assert_eq!(outpoint.vout, 3);
    assert_eq!(outpoint.txid, Txid::from_str(txid_hex).unwrap());
}

#[tokio::test]
async fn get_publisher_utxo_returns_empty_when_total_below_minimum() {
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    let txid_hex = "2222222222222222222222222222222222222222222222222222222222222222";
    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "txid": txid_hex,
                "vout": 0,
                "value": 500,
                "status": { "confirmed": true, "block_height": 100, "block_hash": "0000000000000000000000000000000000000000000000000000000000000001", "block_time": 1700000000 }
            }
        ])))
        .mount(&server)
        .await;

    // 500 sats present, but caller demands at least 1000 → wallet is
    // declared empty (publisher will refuse to broadcast).
    let result = get_publisher_utxo(&publisher_address, &config, Some(1000))
        .await
        .expect("call should succeed");
    assert!(
        result.is_empty(),
        "total below minimum must collapse to an empty vec"
    );
}

#[tokio::test]
async fn broadcast_inscription_txs_returns_both_txids_on_success() {
    let (server, mut config) = setup_mock_esplora().await;
    // Plug a mock WS server in so the publisher's track-tx wait
    // resolves immediately instead of hitting its 30-s safety-net.
    config.ws_url = Some(spawn_track_tx_ws("echo").await);
    let publisher_address = test_publisher_address(config.network());
    let outpoints = vec![(fake_outpoint(0), 100_000u64)];

    // Build a real (commit, reveal) pair — broadcast just serialises and
    // POSTs them, so the txids the function returns are the ones we
    // computed locally.
    let (commit_tx, reveal_tx) = inscription_txs(
        b"Hello, zkCoins!",
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );
    let expected_commit_txid = commit_tx.compute_txid();
    let expected_reveal_txid = reveal_tx.compute_txid();

    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string(expected_commit_txid.to_string()))
        .mount(&server)
        .await;

    let (got_commit, got_reveal) = broadcast_inscription_txs(&config, &commit_tx, &reveal_tx)
        .await
        .expect("broadcast should succeed when Esplora accepts both txs");

    assert_eq!(got_commit, expected_commit_txid);
    assert_eq!(got_reveal, expected_reveal_txid);
}

#[tokio::test]
async fn broadcast_inscription_txs_errors_when_track_tx_event_never_arrives() {
    // Silent WS mock — the publisher must hit its 30-s safety-net
    // and surface a hard error, NOT silently fall back to broadcasting
    // the reveal (issue #84 design).
    let (server, mut config) = setup_mock_esplora().await;
    config.ws_url = Some(spawn_track_tx_ws("silent").await);
    // Override the production 30-s deadline so the test fails fast
    // rather than blocking the suite for half a minute.
    config.track_tx_timeout = Some(Duration::from_millis(300));
    let publisher_address = test_publisher_address(config.network());
    let outpoints = vec![(fake_outpoint(0), 100_000u64)];

    let (commit_tx, reveal_tx) = inscription_txs(
        b"Hello, zkCoins!",
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );

    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(commit_tx.compute_txid().to_string()),
        )
        .mount(&server)
        .await;

    let err = broadcast_inscription_txs(&config, &commit_tx, &reveal_tx)
        .await
        .expect_err("silent WS must surface a hard error, not silent fallback");
    assert!(
        err.to_string().to_lowercase().contains("timeout")
            || err.to_string().to_lowercase().contains("ws"),
        "error should mention the WS timeout, got: {}",
        err
    );
}

#[tokio::test]
async fn broadcast_inscription_txs_propagates_esplora_error() {
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());
    let outpoints = vec![(fake_outpoint(0), 100_000u64)];

    let (commit_tx, reveal_tx) = inscription_txs(
        b"Hello, zkCoins!",
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );

    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(400).set_body_string("sendrawtransaction RPC error"))
        .mount(&server)
        .await;

    let err = broadcast_inscription_txs(&config, &commit_tx, &reveal_tx)
        .await
        .expect_err("400 from Esplora must bubble up as Err");

    // We don't pin the exact message, but it must be non-empty.
    assert!(
        !err.to_string().is_empty(),
        "error should carry a non-empty message"
    );
}

// -----------------------------------------------------------------------------
// create_and_broadcast_inscription — integration over the mocked HTTP layer
// -----------------------------------------------------------------------------

#[tokio::test]
async fn create_and_broadcast_inscription_fails_when_no_utxos() {
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let err = create_and_broadcast_inscription(b"Hello, zkCoins!", &config)
        .await
        .expect_err("empty wallet must produce an Err, not Ok(None)");

    assert!(
        err.to_string().contains("No UTXOs available"),
        "error should describe the empty-wallet condition, got: {}",
        err
    );
}

#[tokio::test]
async fn create_and_broadcast_inscription_succeeds_end_to_end_with_mocked_esplora() {
    let (server, mut config) = setup_mock_esplora().await;
    config.ws_url = Some(spawn_track_tx_ws("echo").await);
    let publisher_address = test_publisher_address(config.network());

    // 1) Address-UTXO lookup — return one UTXO with enough sats to cover
    //    both commit + reveal fees.
    let funding_txid = "3333333333333333333333333333333333333333333333333333333333333333";
    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "txid": funding_txid,
                "vout": 0,
                "value": 100_000,
                "status": { "confirmed": true, "block_height": 100, "block_hash": "0000000000000000000000000000000000000000000000000000000000000001", "block_time": 1700000000 }
            }
        ])))
        .mount(&server)
        .await;

    // 2) Broadcast — accept both commit and reveal POSTs.
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let result = create_and_broadcast_inscription(b"Hello, zkCoins!", &config)
        .await
        .expect("end-to-end inscription should succeed against mocked Esplora");

    let (commit_txid, reveal_txid) =
        result.expect("on success the function returns Some((commit, reveal))");
    assert_ne!(
        commit_txid, reveal_txid,
        "commit and reveal must be distinct transactions"
    );

    // Reveal txid must carry the inscription marker prefix.
    let target = hex::decode(INSCRIPTION_MARKER_PREFIX).unwrap();
    assert!(
        reveal_txid.as_byte_array().starts_with(&target),
        "reveal txid {} must start with marker {}",
        reveal_txid,
        INSCRIPTION_MARKER_PREFIX
    );
}
