use crate::publisher::{EsploraConfig, INSCRIPTION_MARKER_PREFIX};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Transaction, Txid};
use esplora_client::r#async::DefaultSleeper;
use esplora_client::{AsyncClient, Builder, Error as EsploraError, Sleeper};
use std::collections::HashSet;
use std::time::Duration;
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
        // Extract inscription content from inputs
        for input in tx.input.iter() {
            // Look for the witness item that contains the inscription
            if let Some(witness_item) = input.witness.iter().find(|item| {
                let hex_str = hex::encode(item);
                hex_str.contains("0063") // Look for the inscription marker
            }) {
                // Extract the inscription content
                if let Some(content_bytes) = extract_inscription_content(witness_item) {
                    // Call the handler with the content
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

/// Helper function to extract inscription content from witness data
pub fn extract_inscription_content(witness_data: &[u8]) -> Option<Vec<u8>> {
    // Look for the inscription marker in the witness data
    // The marker is "0063" (OP_FALSE OP_IF)
    let marker = [0x00, 0x63];

    if let Some(pos) = find_subsequence(witness_data, &marker) {
        // Skip the marker bytes
        let start_pos = pos + marker.len();
        
        // Create a script from the remaining data
        let script = ScriptBuf::from_bytes(witness_data[start_pos..].to_vec());
        
        // Parse the script instructions
        let instructions = script.instructions();
        
        // The first instruction after the marker should contain our data
        for instruction in instructions {
            if let Ok(Instruction::PushBytes(bytes)) = instruction {
                return Some(bytes.as_bytes().to_vec());
            }
        }
    }

    None
}

/// Helper function to find a subsequence in a byte array
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
