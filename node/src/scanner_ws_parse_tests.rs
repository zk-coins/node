//! Unit tests for the pure WS-frame parsers.
//!
//! Split out from `scanner_ws_tests.rs` so the pure helper coverage
//! lives next to the pure helpers and stays inside the 100% line +
//! function coverage gate. Issue #84 review (round 4) MINOR 6.

use super::*;
use bitcoin::BlockHash;
use std::str::FromStr;

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

#[test]
fn parse_ws_frame_extracts_single_block_hash() {
    let frame = format!(
        r#"{{"block":{{"id":"{}","height":3123724}}}}"#,
        SAMPLE_BLOCK_HASH_HEX
    );
    let parsed = parse_ws_frame(&frame);
    assert_eq!(parsed, vec![sample_hash()]);
}

#[test]
fn parse_ws_frame_extracts_blocks_array_initial_seed() {
    let frame = format!(
        r#"{{"blocks":[{{"id":"{}","height":1}},{{"id":"{}","height":2}}]}}"#,
        SAMPLE_BLOCK_HASH_HEX, SAMPLE_BLOCK_HASH_HEX_2
    );
    let parsed = parse_ws_frame(&frame);
    assert_eq!(parsed, vec![sample_hash(), sample_hash_2()]);
}

#[test]
fn parse_ws_frame_ignores_unknown_shapes() {
    // mempool-blocks updates the scanner does not subscribe to.
    assert!(parse_ws_frame(r#"{"mempool-blocks":[]}"#).is_empty());
    // Empty object.
    assert!(parse_ws_frame("{}").is_empty());
    // Malformed JSON.
    assert!(parse_ws_frame("not json").is_empty());
    // Block field present but the id is not a valid hash.
    assert!(parse_ws_frame(r#"{"block":{"id":"zzzz"}}"#).is_empty());
}

#[test]
fn parse_ws_frame_returns_empty_when_block_id_is_invalid_hex() {
    // `block.id` is a string but not a valid BlockHash hex — must
    // not panic, must return empty Vec. Covers the
    // `BlockHash::from_str(hash).is_err()` fallthrough branch in
    // `parse_ws_frame`.
    let frame = r#"{"block":{"id":"not-a-real-hash"}}"#;
    assert!(parse_ws_frame(frame).is_empty());
}

#[test]
fn frame_signals_tx_seen_matches_documented_mempool_shapes() {
    let txid_hex = "1111111111111111111111111111111111111111111111111111111111111111";

    // `{"txConfirmed": "<hex>"}` — value is the txid string directly.
    assert!(frame_signals_tx_seen(
        &format!(r#"{{"txConfirmed":"{}"}}"#, txid_hex),
        txid_hex
    ));
    // `{"txPosition": {"txid": "<hex>", "position": {...}}}`
    assert!(frame_signals_tx_seen(
        &format!(
            r#"{{"txPosition":{{"txid":"{}","position":{{"block":1,"vsize":120}}}}}}"#,
            txid_hex
        ),
        txid_hex
    ));
    // `{"tx": {"txid": "<hex>", ...}}` — full tx detection event.
    assert!(frame_signals_tx_seen(
        &format!(
            r#"{{"tx":{{"txid":"{}","fee":100,"vsize":200}}}}"#,
            txid_hex
        ),
        txid_hex
    ));

    // Different txid — must not match.
    let other = "2222222222222222222222222222222222222222222222222222222222222222";
    assert!(!frame_signals_tx_seen(
        &format!(r#"{{"txConfirmed":"{}"}}"#, other),
        txid_hex
    ));
    assert!(!frame_signals_tx_seen(
        &format!(r#"{{"txPosition":{{"txid":"{}"}}}}"#, other),
        txid_hex
    ));

    // Malformed JSON
    assert!(!frame_signals_tx_seen("garbage", txid_hex));
}

/// Regression for issue #84 review (round 2, MINOR 5): an upstream
/// that echoed the subscribe frame back to the client used to satisfy
/// the wildcard `json_contains_string` matcher, which would have
/// resolved the wait before the tx had actually propagated. The
/// matcher now restricts itself to the documented response shapes
/// (`txConfirmed`, `txPosition`, `tx`) and explicitly does NOT match
/// the subscribe-echo frame.
#[test]
fn frame_signals_tx_seen_does_not_match_subscribe_echo() {
    let txid_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    let echo = format!(r#"{{"action":"track-tx","data":"{}"}}"#, txid_hex);
    assert!(
        !frame_signals_tx_seen(&echo, txid_hex),
        "subscribe-echo frame must NOT trigger the matcher"
    );

    // Also: an unrelated frame that just happens to mention the txid
    // in a non-documented field must not match.
    let unrelated = format!(r#"{{"someOtherKey":{{"txid":"{}"}}}}"#, txid_hex);
    assert!(
        !frame_signals_tx_seen(&unrelated, txid_hex),
        "non-documented shape mentioning the txid must not match"
    );
}
