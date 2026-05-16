//! Runtime bootstrap for the inscription scanner.
//!
//! This file is intentionally excluded from the coverage scope. The
//! functions below own the network I/O (HTTP polling against the
//! Esplora REST API), the infinite scan loop, and a Bitcoin-mainnet-
//! style sleep cadence — none of which can be exercised by unit tests
//! without spinning up a fake Esplora server.
//!
//! The pure logic that can be tested without a Bitcoin node lives in
//! `scanner.rs` (filter_marker_txids, process_transaction_inscriptions,
//! extract_inscription_content) and is measured normally.

use bitcoin::{BlockHash, Transaction, Txid};
use esplora_client::r#async::DefaultSleeper;
use esplora_client::{AsyncClient, Builder, Error as EsploraError, Sleeper};
use std::collections::HashSet;
use std::error::Error as StdError;
use std::time::Duration;

use crate::publisher::{EsploraConfig, INSCRIPTION_MARKER_PREFIX};
use crate::scanner::{filter_marker_txids, process_transaction_inscriptions, InscriptionCallback};

struct InscriptionScanner<S = DefaultSleeper> {
    client: AsyncClient<S>,
    processed_blocks: HashSet<BlockHash>,
    current_block_hash: Option<BlockHash>,
}

impl<S: Sleeper> InscriptionScanner<S> {
    fn new(client: AsyncClient<S>) -> Self {
        Self {
            client,
            processed_blocks: HashSet::new(),
            current_block_hash: None,
        }
    }

    /// Scans the blockchain starting from the given block hash
    async fn scan_from_block(
        &mut self,
        start_block_hash: BlockHash,
        callback: &InscriptionCallback,
    ) -> Result<(), EsploraError> {
        let mut current_hash = start_block_hash;
        let poll_interval = Duration::from_secs(30);

        loop {
            self.current_block_hash = Some(current_hash);

            if self.processed_blocks.contains(&current_hash) {
                println!(
                    "Reached previously processed block or chain tip. Waiting for new blocks..."
                );
                tokio::time::sleep(poll_interval).await;

                let tip_hash = match self.client.get_tip_hash().await {
                    Ok(hash) => hash,
                    Err(e) => {
                        println!("Error getting tip hash: {}", e);
                        tokio::time::sleep(poll_interval).await;
                        continue;
                    }
                };

                if self.processed_blocks.contains(&tip_hash) {
                    continue;
                }

                current_hash = tip_hash;
                continue;
            }

            println!("Processing block: {}", current_hash);

            let txids = match self.client.get_block_txids(current_hash).await {
                Ok(txids) => txids,
                Err(e) => {
                    println!("Error fetching block txids {}: {}", current_hash, e);
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
            };

            let marker_bytes = hex::decode(INSCRIPTION_MARKER_PREFIX).unwrap_or_default();
            let matching_txids: Vec<Txid> = filter_marker_txids(txids, &marker_bytes);

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

            self.processed_blocks.insert(current_hash);

            let block_status = self.client.get_block_status(&current_hash).await?;
            match block_status.next_best {
                Some(next_hash) => current_hash = next_hash,
                None => {
                    println!("Reached chain tip. Waiting for new blocks...");
                    tokio::time::sleep(poll_interval).await;

                    match self.client.get_tip_hash().await {
                        Ok(tip_hash) => {
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

    async fn process_transaction(
        &self,
        tx: &Transaction,
        callback: &InscriptionCallback,
    ) -> Result<(), EsploraError> {
        if let Some(current_hash) = self.current_block_hash {
            process_transaction_inscriptions(tx, current_hash, callback);
        }
        Ok(())
    }
}

/// Scans for inscription transactions in the blockchain.
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
