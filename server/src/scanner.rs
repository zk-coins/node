use crate::publisher::{EsploraConfig, INSCRIPTION_MARKER_PREFIX};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Transaction, Txid};
use esplora_client::r#async::DefaultSleeper;
use esplora_client::{AsyncClient, Builder, Error as EsploraError, Sleeper};
use std::collections::HashSet;
use std::time::Duration;
use bitcoin::blockdata::opcodes;
use bitcoin::script::Instruction;
use bitcoin::script::ScriptBuf;
use std::error::Error as StdError;

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

    if content.is_empty() { None } else { Some(content) }
}
