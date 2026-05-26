//! Pure inscription-parsing logic for the block scanner.
//!
//! The network-driven scan loop and the Esplora client wiring live in
//! `scanner_runtime.rs` and are excluded from the coverage scope.
//! Everything here is testable in isolation without a Bitcoin node.

use bitcoin::blockdata::opcodes;
use bitcoin::script::Instruction;
use bitcoin::script::ScriptBuf;
use bitcoin::{BlockHash, Transaction, Txid};

/// Pure-logic decision: given the current
/// `pending_inscriptions.status` value for a commit txid (or `None`
/// when the row does not exist), should the scanner skip its
/// `state.update` call for this inscription?
///
/// Returns `true` only when the row exists AND its status is
/// `db::PENDING_STATUS_COMPLETE` — Phase E's contract that the mint
/// flow integrated the inscription in-process. Every other state (no
/// row, an in-progress row, an unknown future status) falls through
/// to the scanner's normal `state.update` path:
///
/// * `None` — external / out-of-band inscription, never went through
///   the mint flow on this node.
/// * `constructed` / `commit_broadcast` / `reveal_broadcast` — the
///   mint flow broadcast but never reached the post-state.update
///   `complete` advance, so the SMT/MMR are still missing this entry
///   and the scanner is the recovery path.
/// * any other string — forward-compatible no-op (mirrors
///   `resume_single_row`'s "unknown status" branch).
pub fn should_skip_scanner_state_update(pending_status: Option<&str>) -> bool {
    matches!(pending_status, Some(s) if s == crate::db::PENDING_STATUS_COMPLETE)
}

/// Type alias for the inscription callback function.
///
/// Arguments are `(content_bytes, commit_txid, block_hash)`:
/// * `content_bytes` — the raw inscription payload extracted from the
///   reveal-side script.
/// * `commit_txid` — the txid of the inscription's commit transaction,
///   equivalently `reveal_tx.input[0].previous_output.txid`. The mint
///   flow keys the `pending_inscriptions` table by this value (see
///   `db::pending_inscription_status_by_commit_txid`), so a callback
///   that wants to skip its own `state.update` when the mint flow has
///   already applied the inscription needs the commit_txid here.
/// * `block_hash` — the Bitcoin block in which the reveal landed; the
///   scanner uses it as the new `latest_block` after persisting state.
pub(crate) type InscriptionCallback = dyn Fn(Vec<u8>, Txid, BlockHash) + Send + Sync + 'static;

/// Pure logic: filter a list of txids down to those starting with the
/// marker prefix. Extracted from the scan loop so it can be unit-tested
/// without an Esplora client.
pub(crate) fn filter_marker_txids(txids: Vec<Txid>, marker_bytes: &[u8]) -> Vec<Txid> {
    use bitcoin::hashes::Hash;
    txids
        .into_iter()
        .filter(|txid| txid.as_byte_array().starts_with(marker_bytes))
        .collect()
}

/// Pure logic: walk every input of the transaction, look for a Taproot
/// script-spend witness whose script encodes an inscription envelope,
/// extract the content bytes, and invoke the callback with them.
/// In a Taproot script-spend the witness is `[signature, script, control_block]`
/// so the script is always the second-to-last witness item.
///
/// Each match invokes `callback` with `(content_bytes, commit_txid,
/// current_block_hash)`. `commit_txid` is the previous-output txid of
/// the input whose witness carried the matching envelope — by
/// construction the txid of the inscription's commit transaction. Mint
/// inscriptions broadcast by `publisher::create_and_broadcast_inscription`
/// pin their reveal's `input[0]` to the commit's vout 0, so the
/// commit_txid surfaced here matches the `commit_txid` column in
/// `pending_inscriptions` for every inscription this node originated.
pub(crate) fn process_transaction_inscriptions(
    tx: &Transaction,
    current_block_hash: BlockHash,
    callback: &InscriptionCallback,
) {
    for input in tx.input.iter() {
        let witness_items: Vec<&[u8]> = input.witness.iter().collect();
        if witness_items.len() >= 3 {
            let script_bytes = witness_items[witness_items.len() - 2];
            if let Some(content_bytes) = extract_inscription_content(script_bytes) {
                callback(
                    content_bytes,
                    input.previous_output.txid,
                    current_block_hash,
                );
            }
        }
    }
}

/// Extract inscription content from a Taproot reveal script.
///
/// The script structure is:
///   <pubkey> OP_CHECKSIG OP_FALSE OP_IF <push data>... OP_ENDIF
///
/// We parse the script opcodes properly (not raw bytes) to find the
/// OP_FALSE OP_IF boundary, then concatenate all push data chunks
/// until OP_ENDIF.
pub fn extract_inscription_content(script_bytes: &[u8]) -> Option<Vec<u8>> {
    let script = ScriptBuf::from_bytes(script_bytes.to_vec());
    let mut instructions = script.instructions();

    // Walk opcodes until we find OP_FALSE followed by OP_IF
    let mut prev_was_op_false = false;
    let mut inside_envelope = false;
    let mut content = Vec::new();

    while let Some(Ok(instruction)) = instructions.next() {
        if inside_envelope {
            match instruction {
                Instruction::PushBytes(bytes) => {
                    content.extend_from_slice(bytes.as_bytes());
                }
                Instruction::Op(op) if op == opcodes::all::OP_ENDIF => {
                    break;
                }
                _ => {}
            }
        } else {
            match instruction {
                // OP_FALSE (0x00) is parsed as PushBytes of empty data by the bitcoin crate
                Instruction::PushBytes(bytes) if bytes.is_empty() => {
                    prev_was_op_false = true;
                }
                Instruction::Op(op) if op == opcodes::all::OP_IF && prev_was_op_false => {
                    inside_envelope = true;
                }
                _ => {
                    prev_was_op_false = false;
                }
            }
        }
    }

    if content.is_empty() {
        None
    } else {
        Some(content)
    }
}

#[cfg(test)]
#[path = "scanner_tests.rs"]
mod tests;
