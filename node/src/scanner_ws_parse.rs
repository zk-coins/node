//! Pure parsers for the Esplora WebSocket frame shapes.
//!
//! Split out from `scanner_ws.rs` so the pure logic stays inside the
//! 100% coverage gate while the runtime/network code (which cannot be
//! exercised without spinning up a fake WS server) remains excluded
//! from coverage via `--ignore-filename-regex`. Issue #84 review
//! (round 4) MINOR 6.

use std::str::FromStr;

use bitcoin::BlockHash;

/// Parse a `BlockHash` out of the `block.id` (or first
/// `blocks[].id`) field of an Esplora WS frame. Returns
/// `Some(hash)` only for the two documented shapes:
///
///   - `{"block": {"id": "<hex>", ...}}`
///   - `{"blocks": [{"id": "<hex>", ...}, ...]}` (initial seed)
///
/// Anything else (heartbeats, mempool-block updates the scanner
/// does not subscribe to, malformed frames) is silently dropped.
/// The reason this returns `Vec<BlockHash>` rather than a single
/// hash is the `blocks` shape — the initial subscribe response
/// carries several entries, and we publish each so
/// `scanner_runtime`'s dedupe handles the rest.
pub fn parse_ws_frame(text: &str) -> Vec<BlockHash> {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    if let Some(block) = value.get("block") {
        return block
            .get("id")
            .and_then(|v| v.as_str())
            .and_then(|s| BlockHash::from_str(s).ok())
            .map(|h| vec![h])
            .unwrap_or_default();
    }

    if let Some(blocks) = value.get("blocks").and_then(|v| v.as_array()) {
        return blocks
            .iter()
            .filter_map(|b| b.get("id").and_then(|v| v.as_str()))
            .filter_map(|s| BlockHash::from_str(s).ok())
            .collect();
    }

    Vec::new()
}

#[cfg(test)]
#[path = "scanner_ws_parse_tests.rs"]
mod tests;
