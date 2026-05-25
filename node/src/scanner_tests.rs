use super::*;
use bitcoin::blockdata::{opcodes, script};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::XOnlyPublicKey;
use shared::commitment::Commitment;
use std::str::FromStr;

/// Build a reveal script in the same format as the publisher:
///   <pubkey> OP_CHECKSIG OP_FALSE OP_IF <push data chunks...> OP_ENDIF
fn build_inscription_script(pubkey: XOnlyPublicKey, data: &[u8]) -> ScriptBuf {
    let mut builder = script::Builder::new()
        .push_slice(pubkey.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF);

    for chunk in data.chunks(520) {
        let buffer = PushBytesBuf::try_from(chunk.to_vec()).unwrap();
        builder = builder.push_slice(buffer);
    }

    builder.push_opcode(opcodes::all::OP_ENDIF).into_script()
}

/// Helper: create a deterministic x-only public key for tests.
fn test_xonly_pubkey() -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let sk =
        SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    XOnlyPublicKey::from_keypair(&kp).0
}

// --- extract_inscription_content ---

#[test]
fn parse_valid_inscription_into_commitment() {
    let sk =
        SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let message = b"test commitment data".to_vec();
    let commitment = Commitment::new(&sk, message.clone()).expect("should create commitment");
    let commitment_bytes = bincode::serialize(&commitment).expect("should serialize commitment");

    let pubkey = test_xonly_pubkey();
    let script = build_inscription_script(pubkey, &commitment_bytes);

    let extracted = extract_inscription_content(script.as_bytes());
    assert!(
        extracted.is_some(),
        "should extract content from valid script"
    );

    let extracted_bytes = extracted.unwrap();
    assert_eq!(
        extracted_bytes, commitment_bytes,
        "extracted bytes must match the serialized commitment"
    );

    // Deserialize back into a Commitment and verify fields
    let deserialized: Commitment =
        bincode::deserialize(&extracted_bytes).expect("should deserialize commitment");
    assert_eq!(deserialized.message, message);
    assert_eq!(deserialized.public_key, commitment.public_key);
}

#[test]
fn reject_invalid_inscription_data() {
    // Empty script has no envelope
    assert_eq!(extract_inscription_content(&[]), None);

    // Random bytes without OP_FALSE OP_IF envelope
    assert_eq!(extract_inscription_content(&[0xab, 0xcd, 0xef]), None);

    // Script with OP_IF but missing OP_FALSE before it (just OP_1 OP_IF OP_ENDIF)
    let script = script::Builder::new()
        .push_opcode(opcodes::all::OP_PUSHNUM_1)
        .push_opcode(opcodes::all::OP_IF)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script();
    assert_eq!(
        extract_inscription_content(script.as_bytes()),
        None,
        "OP_IF without OP_FALSE should not open an envelope"
    );

    // Script with OP_FALSE OP_IF but no push data (only OP_ENDIF)
    let script = script::Builder::new()
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script();
    assert_eq!(
        extract_inscription_content(script.as_bytes()),
        None,
        "envelope with no push data should return None"
    );
}

#[test]
fn verify_commitment_signature_after_deserialization() {
    let sk =
        SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();
    let message = vec![42u8; 32]; // 32-byte message (treated as raw digest)
    let commitment = Commitment::new(&sk, message.clone()).expect("should create commitment");
    let commitment_bytes = bincode::serialize(&commitment).unwrap();

    let pubkey = test_xonly_pubkey();
    let script = build_inscription_script(pubkey, &commitment_bytes);
    let extracted = extract_inscription_content(script.as_bytes()).unwrap();

    let deserialized: Commitment = bincode::deserialize(&extracted).unwrap();
    assert!(
        deserialized.verify(),
        "commitment signature must be valid after round-trip through inscription script"
    );

    // Tamper with the message and verify that verification fails
    let mut tampered = deserialized.clone();
    tampered.message = vec![0u8; 32];
    assert!(
        !tampered.verify(),
        "tampered commitment must fail signature verification"
    );
}

#[test]
fn parse_multi_chunk_inscription() {
    let sk =
        SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap();
    // Create a large message that will be split into multiple chunks (>520 bytes)
    let large_message = vec![0xAB; 1200];
    let commitment = Commitment::new(&sk, large_message).expect("should create commitment");
    let commitment_bytes = bincode::serialize(&commitment).unwrap();
    assert!(
        commitment_bytes.len() > 520,
        "test data should span multiple chunks"
    );

    let pubkey = test_xonly_pubkey();
    let script = build_inscription_script(pubkey, &commitment_bytes);
    let extracted = extract_inscription_content(script.as_bytes()).unwrap();

    assert_eq!(
        extracted, commitment_bytes,
        "multi-chunk inscription must reassemble correctly"
    );

    let deserialized: Commitment = bincode::deserialize(&extracted).unwrap();
    assert!(deserialized.verify(), "multi-chunk commitment must verify");
}

// --- filter_marker_txids ---

#[test]
fn filter_marker_txids_keeps_only_prefix_matches() {
    let marker = hex::decode("4242").unwrap();
    let matching = Txid::from_byte_array([
        0x42, 0x42, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99,
    ]);
    let non_matching = Txid::from_byte_array([0xab; 32]);

    let filtered = filter_marker_txids(vec![matching, non_matching], &marker);
    assert_eq!(filtered, vec![matching]);
}

#[test]
fn filter_marker_txids_returns_empty_when_no_matches() {
    let marker = hex::decode("4242").unwrap();
    let txid = Txid::from_byte_array([0xab; 32]);
    assert!(filter_marker_txids(vec![txid], &marker).is_empty());
}

#[test]
fn filter_marker_txids_accepts_empty_marker() {
    // An empty prefix matches everything — useful as a degenerate case
    // when the marker constant is empty/missing.
    let txid = Txid::from_byte_array([0xab; 32]);
    let filtered = filter_marker_txids(vec![txid], &[]);
    assert_eq!(filtered, vec![txid]);
}

// --- process_transaction_inscriptions ---

fn make_block_hash() -> BlockHash {
    BlockHash::from_byte_array([0xfe; 32])
}

fn make_inscription_witness(pubkey: XOnlyPublicKey, payload: &[u8]) -> bitcoin::Witness {
    use bitcoin::Witness;
    let script = build_inscription_script(pubkey, payload);
    let mut w = Witness::new();
    // [signature, script, control_block] — only the script body is parsed.
    w.push([0u8; 64]); // dummy signature
    w.push(script.as_bytes()); // the script with inscription envelope
    w.push([0u8; 33]); // dummy control block
    w
}

fn make_tx_with_witness(witness: bitcoin::Witness) -> Transaction {
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, OutPoint, Sequence, TxIn};
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![],
    }
}

#[test]
fn process_transaction_inscriptions_invokes_callback_with_payload() {
    let pubkey = test_xonly_pubkey();
    let payload = b"hello inscription".to_vec();
    let tx = make_tx_with_witness(make_inscription_witness(pubkey, &payload));

    let hash = make_block_hash();
    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let received_clone = received.clone();
    let callback: Box<dyn Fn(Vec<u8>, Txid, BlockHash) + Send + Sync> =
        Box::new(move |bytes, ctxid, h| {
            received_clone.lock().unwrap().push((bytes, ctxid, h));
        });

    process_transaction_inscriptions(&tx, hash, callback.as_ref());

    let calls = received.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, payload);
    // commit_txid is the previous_output txid of the reveal input —
    // `make_tx_with_witness` uses `OutPoint::null()` which carries an
    // all-zeros txid.
    assert_eq!(calls[0].1, Txid::all_zeros());
    assert_eq!(calls[0].2, hash);
}

#[test]
fn process_transaction_inscriptions_ignores_inputs_without_witness() {
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, OutPoint, Sequence, TxIn, Witness};
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![],
    };

    let hash = make_block_hash();
    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let received_clone = received.clone();
    let callback: Box<dyn Fn(Vec<u8>, Txid, BlockHash) + Send + Sync> =
        Box::new(move |bytes, ctxid, h| {
            received_clone.lock().unwrap().push((bytes, ctxid, h));
        });

    process_transaction_inscriptions(&tx, hash, callback.as_ref());
    assert!(received.lock().unwrap().is_empty());
}

#[test]
fn process_transaction_inscriptions_ignores_witness_without_envelope() {
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, OutPoint, Sequence, TxIn, Witness};
    let mut w = Witness::new();
    w.push([0u8; 64]);
    w.push([0u8; 32]); // bogus script — no inscription envelope
    w.push([0u8; 33]);

    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: w,
        }],
        output: vec![],
    };

    let hash = make_block_hash();
    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let received_clone = received.clone();
    let callback: Box<dyn Fn(Vec<u8>, Txid, BlockHash) + Send + Sync> =
        Box::new(move |bytes, ctxid, h| {
            received_clone.lock().unwrap().push((bytes, ctxid, h));
        });

    process_transaction_inscriptions(&tx, hash, callback.as_ref());
    assert!(received.lock().unwrap().is_empty());
}

// ---- Phase E: should_skip_scanner_state_update -----------------------------

#[test]
fn should_skip_scanner_state_update_returns_true_only_for_complete() {
    // Mint flow integrated the inscription in-process and marked the
    // pending row `complete`. Scanner must skip its own `state.update`.
    assert!(should_skip_scanner_state_update(Some(
        crate::db::PENDING_STATUS_COMPLETE
    )));
}

#[test]
fn should_skip_scanner_state_update_false_for_missing_row() {
    // Out-of-band / recovery inscription that never went through this
    // server's mint flow: no `pending_inscriptions` row, scanner is the
    // authoritative integration path.
    assert!(!should_skip_scanner_state_update(None));
}

#[test]
fn should_skip_scanner_state_update_false_for_in_progress_states() {
    // Every non-complete pending status means the mint flow did not
    // finish the in-process state.update step. The scanner must fall
    // through and integrate the inscription itself (recovery path).
    assert!(!should_skip_scanner_state_update(Some(
        crate::db::PENDING_STATUS_CONSTRUCTED
    )));
    assert!(!should_skip_scanner_state_update(Some(
        crate::db::PENDING_STATUS_COMMIT_BROADCAST
    )));
    assert!(!should_skip_scanner_state_update(Some(
        crate::db::PENDING_STATUS_REVEAL_BROADCAST
    )));
}

#[test]
fn should_skip_scanner_state_update_false_for_unknown_status() {
    // Forward-compatibility: a future status string (e.g. `failed`)
    // must NOT cause the scanner to short-circuit. Mirrors the unknown-
    // status branch in `resume_single_row`.
    assert!(!should_skip_scanner_state_update(Some(
        "some-future-status"
    )));
    assert!(!should_skip_scanner_state_update(Some("")));
}

#[test]
fn extract_inscription_skips_non_push_opcodes_inside_envelope() {
    // Inside the OP_FALSE OP_IF envelope, anything that is not a push or
    // OP_ENDIF should be silently ignored — exercise the wildcard arm.
    let script = script::Builder::new()
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF)
        .push_opcode(opcodes::all::OP_PUSHNUM_1) // non-push, non-endif
        .push_slice([1u8, 2u8, 3u8])
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script();
    let extracted = extract_inscription_content(script.as_bytes()).unwrap();
    assert_eq!(extracted, vec![1u8, 2u8, 3u8]);
}
