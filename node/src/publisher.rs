use bitcoin::{
    absolute::LockTime,
    blockdata::{opcodes, script},
    hashes::Hash,
    key::TapTweak,
    locktime::absolute::Height,
    script::PushBytesBuf,
    secp256k1::{self, Secp256k1, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootBuilder},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Txid, Weight, Witness,
};

use std::str::FromStr;
// Import specific Esplora client types
use esplora_client::{
    r#async::DefaultSleeper, AsyncClient as EsploraAsyncClient, Builder as EsploraBuilder,
};

// Define a configuration struct for Esplora
#[derive(Clone, Debug)]
pub struct EsploraConfig {
    pub url: String,
    pub is_mainnet: bool,
    pub network_name: String,
    /// Esplora WebSocket endpoint used by the publisher's per-broadcast
    /// `track-tx` wait (issue #84). `None` falls back to
    /// `ESPLORA_WS_URL` (defaulting to `wss://mutinynet.com/api/v1/ws`);
    /// tests inject an in-process URL to avoid hitting the real
    /// upstream.
    pub ws_url: Option<String>,
    /// Override for the per-broadcast `track-tx` safety-net (issue
    /// #84). `None` uses the production default
    /// `TRACK_TX_TIMEOUT_SECS = 30`; tests pass a short Duration so
    /// the silent-fallback assertion does not stall the suite.
    ///
    /// Test-injection backdoor: production callers always leave this
    /// `None` and inherit the 30 s safety-net. Hidden from the
    /// rustdoc index (issue #84 review round 4 MINOR 5).
    #[doc(hidden)]
    pub track_tx_timeout: Option<std::time::Duration>,
}

impl EsploraConfig {
    pub fn network(&self) -> Network {
        if self.is_mainnet {
            Network::Bitcoin
        } else {
            Network::Signet
        }
    }
}

// Define constants for transaction identification
pub const INSCRIPTION_MARKER_PREFIX: &str = "4242";

const MAX_CHUNK_SIZE: usize = 520;
const MAX_MINING_ATTEMPTS: u32 = 400000;
const MIN_INSCRIPTION_AMOUNT: u64 = 800;

/// Safety-net deadline for the per-broadcast `track-tx` WS wait
/// (issue #84). The publisher subscribes to the Esplora WS for the
/// commit txid before broadcasting the reveal, and proceeds the
/// moment the peer reports the commit as seen. If 30 s pass without
/// any track-tx event, that is a hard error, NOT a silent fallback
/// to "broadcast the reveal anyway" — a missing event in that window
/// is a real upstream / network problem worth surfacing.
const TRACK_TX_TIMEOUT_SECS: u64 = 30;

use crate::scanner_ws::DEFAULT_ESPLORA_WS_URL;

const COMMIT_TX_WITNESS_WEIGHT: Weight = Weight::from_wu(68);
const REVEAL_TX_WITNESS_WEIGHT: Weight = Weight::from_wu(295);

fn min_fee(tx: &Transaction, witness_weight: Option<Weight>) -> u64 {
    let mut weight = tx.weight().to_wu();
    if tx.input.iter().any(|utxo| utxo.witness.is_empty()) {
        weight += witness_weight.unwrap().to_wu()
            * tx.input
                .iter()
                .map(|utxo| utxo.witness.is_empty() as u64)
                .sum::<u64>()
    }
    weight.div_ceil(4)
}

pub fn inscription_txs(
    commitment_data: &[u8],
    publisher_address: &Address,
    outpoints_with_sats: Vec<(OutPoint, u64)>,
    publisher_key: &str,
    config: &EsploraConfig,
) -> (Transaction, Transaction) {
    // Create secp context and keys
    let secp256k1 = Secp256k1::new();
    let sk = SecretKey::from_str(publisher_key).unwrap();
    let key_pair = secp256k1::Keypair::from_secret_key(&secp256k1, &sk);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let network = config.network();

    println!("Publisher address: {}", publisher_address);

    let amount: u64 = outpoints_with_sats.iter().map(|(_, sats)| sats).sum();

    // Build a taproot script committing to the data
    let mut script_builder = script::Builder::new()
        .push_slice(public_key.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(opcodes::all::OP_IF);

    // Add the commitment data in chunks
    for chunk in commitment_data.chunks(MAX_CHUNK_SIZE) {
        let buffer = PushBytesBuf::try_from(chunk.to_vec()).unwrap();
        script_builder = script_builder.push_slice(buffer);
    }

    let reveal_script = script_builder
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .unwrap()
        .finalize(&secp256k1, public_key)
        .unwrap();

    // The commit address commits to our data
    let commit_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

    // Create commit transaction
    let mut commit_tx = Transaction {
        version: Version(1),
        lock_time: LockTime::Blocks(Height::ZERO),
        input: outpoints_with_sats
            .iter()
            .map(|(outpoint, _)| TxIn {
                previous_output: *outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: commit_address.script_pubkey(),
        }],
    };

    let commit_fee = min_fee(&commit_tx, Some(COMMIT_TX_WITNESS_WEIGHT));
    commit_tx.output.first_mut().unwrap().value = Amount::from_sat(amount - commit_fee);

    // Create input TxOuts for signing
    let input_txout = outpoints_with_sats
        .iter()
        .map(|(_, sats)| TxOut {
            value: Amount::from_sat(*sats),
            script_pubkey: publisher_address.script_pubkey(),
        })
        .collect::<Vec<TxOut>>();

    // Sign each input of the commit transaction
    for idx in 0..outpoints_with_sats.len() {
        let mut sighash_cache = SighashCache::new(&mut commit_tx);
        let signature_hash = sighash_cache
            .taproot_key_spend_signature_hash(
                idx,
                &Prevouts::All(&input_txout),
                TapSighashType::Default,
            )
            .unwrap();

        // Sign with the tweaked keypair
        let message = secp256k1::Message::from_digest_slice(&signature_hash[..]).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp256k1, &sk);
        let tweaked_keypair = keypair.tap_tweak(&secp256k1, None).to_keypair();
        let signature = secp256k1.sign_schnorr(&message, &tweaked_keypair);

        // Add the signature to the witness
        let witness = sighash_cache.witness_mut(idx).unwrap();
        witness.clear();
        witness.push(signature.as_ref());
    }

    // Create reveal transaction
    let mut reveal_tx = Transaction {
        version: Version(1),
        lock_time: LockTime::from_consensus(0),
        input: vec![TxIn {
            previous_output: OutPoint::new(commit_tx.compute_txid(), 0),
            script_sig: script::Builder::new().into_script(),
            witness: Witness::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: publisher_address.script_pubkey(),
        }],
    };

    let reveal_fee = min_fee(&reveal_tx, Some(REVEAL_TX_WITNESS_WEIGHT));
    reveal_tx.output.first_mut().unwrap().value =
        Amount::from_sat(amount - reveal_fee - commit_fee);

    // Mine the reveal transaction to have a txid starting with our marker
    println!(
        "Mining reveal transaction to start with {}...",
        INSCRIPTION_MARKER_PREFIX
    );
    let target_prefix = hex::decode(INSCRIPTION_MARKER_PREFIX).unwrap();

    let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .unwrap();

    for nonce in 0..MAX_MINING_ATTEMPTS {
        // Update the nSequence for mining
        reveal_tx.input[0].sequence = Sequence(nonce);

        // Sign the transaction with the new sequence
        let mut sighash_cache = SighashCache::new(&mut reveal_tx);
        let signature_hash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&commit_tx.output[0]]),
                TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap();

        let message = secp256k1::Message::from_digest_slice(&signature_hash[..]).unwrap();
        let signature = secp256k1.sign_schnorr(&message, &key_pair);

        let witness = sighash_cache.witness_mut(0).unwrap();
        witness.clear();
        witness.push(signature.as_ref());
        witness.push(reveal_script.clone());
        witness.push(control_block.serialize());

        // Check if the txid starts with our target prefix
        let txid = reveal_tx.compute_txid();
        let txid_bytes = txid.as_byte_array();

        if txid_bytes.starts_with(&target_prefix) {
            println!("Found matching txid: {} with nSequence: {}", txid, nonce);
            break;
        }

        if nonce % 10000 == 0 {
            println!("Tried {} nonces...", nonce);
        }

        if nonce == MAX_MINING_ATTEMPTS - 1 {
            println!("WARNING: Reached maximum attempts without finding a match");
        }
    }

    (commit_tx, reveal_tx)
}

/// Broadcasts the commit and reveal transactions to the Bitcoin
/// network via the Esplora REST API and waits for the commit
/// transaction to appear in the mempool before sending the reveal.
///
/// The propagation gap used to be papered over by a fixed 5 s
/// `PROPAGATION_WAIT_SECS` async sleep; issue #84 replaces
/// that polling wait with a short-lived WebSocket subscription to
/// `{"action":"track-tx","data":"<commit_txid>"}` against the
/// Esplora WS endpoint, returning the moment the peer reports the
/// commit txid as seen. A 30 s safety-net (`TRACK_TX_TIMEOUT_SECS`)
/// caps the WS wait; if it elapses we issue ONE REST
/// `GET /tx/{commit_txid}` against the Esplora endpoint and treat a
/// 200 as success (the tx is in mempool / a block and the WS just
/// missed the frame, a regularly-observed Mutinynet failure mode).
/// A 404 propagates the original WS timeout — the broadcast genuinely
/// did not land. This is a single REST GET, NOT a poll loop; the
/// no-polling invariant from the `CONTRIBUTING.md` "No polling —
/// events only" section is preserved.
///
/// Order of operations is load-bearing: the `track-tx` subscription
/// MUST be established BEFORE the commit broadcast. Otherwise the
/// upstream may finish propagating the tx between
/// `client.broadcast(commit_tx)` and `subscribe_track_tx(...)`, and
/// the "tx in mempool" event would fire before any subscriber is
/// listening — wedging the wait for the full 30 s safety-net even
/// on the happy path.
pub async fn broadcast_inscription_txs(
    config: &EsploraConfig,
    commit_tx: &Transaction,
    reveal_tx: &Transaction,
) -> Result<(Txid, Txid), Box<dyn std::error::Error + Send + Sync>> {
    // Create an Esplora client
    let builder = EsploraBuilder::new(&config.url);
    let client = EsploraAsyncClient::<DefaultSleeper>::from_builder(builder)?;

    let commit_txid = commit_tx.compute_txid();
    let ws_url = config.ws_url.clone().unwrap_or_else(|| {
        std::env::var("ESPLORA_WS_URL").unwrap_or_else(|_| DEFAULT_ESPLORA_WS_URL.to_string())
    });
    let track_tx_timeout = config
        .track_tx_timeout
        .unwrap_or_else(|| std::time::Duration::from_secs(TRACK_TX_TIMEOUT_SECS));

    // Subscribe to the `track-tx` WS BEFORE broadcasting the commit
    // (issue #84). The previous ordering opened a race window between
    // the REST broadcast and the WS subscribe: if the peer finished
    // propagating the tx in that window, the event fired before any
    // listener was attached.
    println!(
        "Subscribing to commit tx {} via WS ({}) before broadcast...",
        commit_txid, ws_url
    );
    let stream = crate::scanner_ws::subscribe_track_tx(&ws_url, commit_txid).await?;

    println!("Broadcasting commit transaction...");
    client.broadcast(commit_tx).await?;
    println!("Commit transaction broadcast successfully: {}", commit_txid);

    // Wait for the commit txid to surface in the upstream mempool
    // before broadcasting the reveal. Event-driven (issue #84),
    // not a fixed sleep — see the function docstring for the design.
    println!(
        "Waiting for commit tx {} to appear in mempool via WS (deadline {:?})...",
        commit_txid, track_tx_timeout
    );
    match stream.wait(track_tx_timeout).await {
        Ok(()) => {}
        Err(crate::scanner_ws::WsError::Timeout) => {
            // Mutinynet's public WS endpoint regularly goes 30-90 s
            // between frames; a 30 s WS timeout therefore does NOT
            // prove the tx is not on-chain. Issue ONE REST GET to
            // distinguish "WS missed the frame" (tx is in
            // mempool / a block → success) from "broadcast genuinely
            // failed" (404 → propagate the original timeout).
            //
            // Single GET, NOT a poll loop — see the
            // "No polling — events only" section in CONTRIBUTING.md.
            println!(
                "WS timeout for {}; falling back to esplora-REST GET /tx/{}",
                commit_txid, commit_txid
            );
            match client.get_tx(&commit_txid).await {
                Ok(Some(_)) => {
                    println!(
                        "esplora-REST fallback confirmed commit tx {} is on-chain / in mempool",
                        commit_txid
                    );
                }
                Ok(None) => {
                    eprintln!(
                        "esplora-REST fallback: commit tx {} not found (404); broadcast genuinely failed",
                        commit_txid
                    );
                    return Err(Box::new(crate::scanner_ws::WsError::Timeout));
                }
                Err(e) => {
                    eprintln!(
                        "esplora-REST fallback failed for {}: {}; propagating original WS timeout",
                        commit_txid, e
                    );
                    return Err(Box::new(crate::scanner_ws::WsError::Timeout));
                }
            }
        }
        Err(other) => return Err(other.into()),
    }

    println!("Broadcasting reveal transaction...");
    client.broadcast(reveal_tx).await?;
    let reveal_txid = reveal_tx.compute_txid();
    println!("Reveal transaction broadcast successfully: {}", reveal_txid);

    Ok((commit_txid, reveal_txid))
}

/// Fetches available UTXOs for the publisher address
pub async fn get_publisher_utxo(
    publisher_address: &Address,
    config: &EsploraConfig,
    min_amount: Option<u64>,
) -> Result<Vec<(OutPoint, u64)>, Box<dyn std::error::Error + Send + Sync>> {
    let builder = EsploraBuilder::new(&config.url);
    let client = EsploraAsyncClient::<DefaultSleeper>::from_builder(builder)?;

    // Get all UTXOs for the address
    let utxos = client.get_address_utxo(publisher_address.clone()).await?;

    // Find UTXOs with sufficient value
    let required_amount = min_amount.unwrap_or(0);
    let mut outpoints_with_sats = Vec::<(OutPoint, u64)>::new();
    let mut sats_amount_sum = 0;

    for utxo in utxos {
        let sats = utxo.value.to_sat();
        outpoints_with_sats.push((OutPoint::new(utxo.txid, utxo.vout), sats));
        sats_amount_sum += sats;
    }

    // Discard UTXOs if total amount is insufficient
    if sats_amount_sum < required_amount {
        outpoints_with_sats.clear();
    }

    Ok(outpoints_with_sats)
}

/// Creates and broadcasts inscription transactions with the given commitment data
pub async fn create_and_broadcast_inscription(
    commitment_data: &[u8],
    config: &EsploraConfig,
) -> Result<Option<(Txid, Txid)>, Box<dyn std::error::Error + Send + Sync>> {
    // Generate publisher address
    let publisher_key = &*crate::PUBLISHER_KEY;
    let secp256k1 = Secp256k1::new();
    let sk = SecretKey::from_str(publisher_key)?;
    let key_pair = secp256k1::Keypair::from_secret_key(&secp256k1, &sk);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
    let network = config.network();
    let publisher_address = Address::p2tr(&secp256k1, public_key, None, network);
    println!("Publisher address: {}", publisher_address);

    // Fetch UTXOs
    println!("Fetching UTXOs...");
    let outpoints_with_sats =
        get_publisher_utxo(&publisher_address, config, Some(MIN_INSCRIPTION_AMOUNT)).await?;

    if outpoints_with_sats.is_empty() {
        eprintln!(
            "ERROR: No UTXOs found for publisher address {}. Fund it to continue.",
            publisher_address
        );
        return Err(
            "No UTXOs available for inscription broadcast — publisher wallet is empty".into(),
        );
    }

    // Log found UTXOs
    for (outpoint, sats) in &outpoints_with_sats {
        println!(
            "Found UTXO: {}:{} with value {} sats",
            outpoint.txid, outpoint.vout, sats
        );
    }

    // Create the inscription transactions
    let (commit_tx, reveal_tx) = inscription_txs(
        commitment_data,
        &publisher_address,
        outpoints_with_sats,
        publisher_key,
        config,
    );

    // Print transaction IDs
    println!("\nCommit TX ID: {}", commit_tx.compute_txid());
    println!("Reveal TX ID: {}", reveal_tx.compute_txid());

    // Broadcast the transactions
    match broadcast_inscription_txs(config, &commit_tx, &reveal_tx).await {
        Ok((commit_txid, reveal_txid)) => {
            println!("Successfully broadcast transactions:");
            println!("Commit TXID: {}", commit_txid);
            println!("Reveal TXID: {}", reveal_txid);
            Ok(Some((commit_txid, reveal_txid)))
        }
        Err(e) => {
            println!("Failed to broadcast transactions: {}", e);
            Err(e)
        }
    }
}

#[cfg(test)]
#[path = "publisher_tests.rs"]
mod tests;
