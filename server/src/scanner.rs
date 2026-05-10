use crate::publisher::{EsploraConfig, INSCRIPTION_MARKER_PREFIX};
use bitcoin::blockdata::opcodes;
use bitcoin::hashes::Hash;
use bitcoin::script::Instruction;
use bitcoin::script::ScriptBuf;
use bitcoin::{BlockHash, Transaction, Txid};
use esplora_client::r#async::DefaultSleeper;
use esplora_client::{AsyncClient, Builder, Error as EsploraError, Sleeper};
use std::collections::HashSet;
use std::error::Error as StdError;
use std::time::Duration;

/// Type alias for the inscription callback function
type InscriptionCallback = dyn Fn(Vec<u8>, BlockHash) + Send + Sync + 'static;

struct InscriptionScanner<S = DefaultSleeper> {
    client: AsyncClient<S>,
    processed_blocks: HashSet<BlockHash>,
    current_block_hash: Option<BlockHash>,
}

impl<S: Sleeper> InscriptionScanner<S> {
    pub fn new(client: AsyncClient<S>) -> Self {
        Self {
            client,
            processed_blocks: HashSet::new(),
            current_block_hash: None,
        }
    }

    /// Scans the blockchain starting from the given block hash
    pub async fn scan_from_block(
        &mut self,
        start_block_hash: BlockHash,
        callback: &InscriptionCallback,
    ) -> Result<(), EsploraError> {
        let mut current_hash = start_block_hash;
        let poll_interval = Duration::from_secs(30);

        loop {
            // Update the current block hash
            self.current_block_hash = Some(current_hash);

            // Skip if we've already processed this block
            if self.processed_blocks.contains(&current_hash) {
                // We've reached a block we've already processed
                // Wait for poll_interval before checking for new blocks
                println!(
                    "Reached previously processed block or chain tip. Waiting for new blocks..."
                );
                tokio::time::sleep(poll_interval).await;

                // Get the latest block hash
                let tip_hash = match self.client.get_tip_hash().await {
                    Ok(hash) => hash,
                    Err(e) => {
                        println!("Error getting tip hash: {}", e);
                        tokio::time::sleep(poll_interval).await;
                        continue;
                    }
                };

                // If we've already processed the tip, wait and try again
                if self.processed_blocks.contains(&tip_hash) {
                    continue;
                }

                // Otherwise, continue from the tip
                current_hash = tip_hash;
                continue;
            }

            println!("Processing block: {}", current_hash);

            // Get the transaction IDs in the block
            let txids = match self.client.get_block_txids(current_hash).await {
                Ok(txids) => txids,
                Err(e) => {
                    println!("Error fetching block txids {}: {}", current_hash, e);
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
            };

            // Filter txids that match our marker prefix
            let marker_bytes = hex::decode(INSCRIPTION_MARKER_PREFIX).unwrap_or_default();
            let matching_txids: Vec<Txid> = txids
                .into_iter()
                .filter(|txid| {
                    let txid_bytes = txid.as_byte_array();
                    txid_bytes.starts_with(&marker_bytes)
                })
                .collect();

            // Process only the matching transactions
            for txid in matching_txids {
                println!("Found transaction with marker prefix: {}", txid);
                match self.client.get_tx(&txid).await {
                    Ok(Some(tx)) => {
                        self.process_transaction(&tx, callback).await?;
                    }
                    Ok(None) => {
                        println!("Transaction {} not found", txid);
                    }
                    Err(e) => {
                        println!("Error fetching transaction {}: {}", txid, e);
                    }
                }
            }

            // Mark this block as processed
            self.processed_blocks.insert(current_hash);

            // Get the next block
            let block_status = self.client.get_block_status(&current_hash).await?;
            match block_status.next_best {
                Some(next_hash) => current_hash = next_hash,
                None => {
                    // No more blocks in the chain, wait and check for new ones
                    println!("Reached chain tip. Waiting for new blocks...");
                    tokio::time::sleep(poll_interval).await;

                    // Get the latest block hash
                    match self.client.get_tip_hash().await {
                        Ok(tip_hash) => {
                            // If we've already processed the tip, wait and try again
                            if self.processed_blocks.contains(&tip_hash) {
                                continue;
                            }
                            current_hash = tip_hash;
                        }
                        Err(e) => {
                            println!("Error getting tip hash: {}", e);
                            tokio::time::sleep(poll_interval).await;
                            continue;
                        }
                    }
                }
            }
        }
    }

    /// Process a single transaction, checking if it's an inscription transaction
    async fn process_transaction(
        &self,
        tx: &Transaction,
        callback: &InscriptionCallback,
    ) -> Result<(), EsploraError> {
        // We already know it's an inscription tx based on the txid prefix
        // In a Taproot script-spend, the witness is: [signature, script, control_block]
        // The script is the second-to-last witness item.
        for input in tx.input.iter() {
            let witness_items: Vec<&[u8]> = input.witness.iter().collect();
            if witness_items.len() >= 3 {
                let script_bytes = witness_items[witness_items.len() - 2];
                if let Some(content_bytes) = extract_inscription_content(script_bytes) {
                    if let Some(current_hash) = self.current_block_hash {
                        callback(content_bytes, current_hash);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Scans for inscriptions transactions in the blockchain
pub async fn scan_for_inscriptions(
    config: &EsploraConfig,
    start_block_hash: BlockHash,
    callback: &InscriptionCallback,
) -> Result<(), Box<dyn StdError>> {
    let builder = Builder::new(&config.url);
    let client = AsyncClient::<DefaultSleeper>::from_builder(builder)?;
    let mut scanner = InscriptionScanner::new(client);

    scanner.scan_from_block(start_block_hash, callback).await?;

    Ok(())
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
mod tests {
    use super::*;
    use bitcoin::blockdata::{opcodes, script};
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
        let commitment_bytes =
            bincode::serialize(&commitment).expect("should serialize commitment");

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
}
