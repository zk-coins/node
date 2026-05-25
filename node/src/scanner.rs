//! Pure inscription-parsing logic for the block scanner.
//!
//! The network-driven scan loop and the Esplora client wiring live in
//! `scanner_runtime.rs` and are excluded from the coverage scope.
//! Everything here is testable in isolation without a Bitcoin node.

use bitcoin::blockdata::opcodes;
use bitcoin::script::Instruction;
use bitcoin::script::ScriptBuf;
use bitcoin::{BlockHash, Transaction, Txid};

/// Type alias for the inscription callback function
pub(crate) type InscriptionCallback = dyn Fn(Vec<u8>, BlockHash) + Send + Sync + 'static;

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
                callback(content_bytes, current_block_hash);
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
