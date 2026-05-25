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
use sqlx::PgPool;

use crate::db;

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
    /// the "broadcast genuinely failed" path (short WS timeout +
    /// wiremock default 404 on `GET /tx/{txid}` ⇒ REST fallback returns
    /// `None` ⇒ hard `WsError::Timeout`) does not stall the suite for
    /// the full 30 s.
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
/// any track-tx event, the publisher issues a SINGLE REST
/// `GET /tx/{commit_txid}` fallback against the Esplora endpoint:
/// a 200 means the tx is in mempool / a block (the WS just missed
/// the frame, a regularly-observed Mutinynet failure mode) and the
/// publisher proceeds with the reveal; a 404 or any other error
/// propagates `WsError::Timeout`. The underlying rationale is
/// unchanged: a missing event without REST corroboration is still
/// a real upstream / network problem worth surfacing — never a
/// silent fallback to "broadcast the reveal anyway".
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

    // Build the script-path Taproot anchor that commits to the data.
    // The same builder is used by `build_reveal_only`, ensuring the
    // commit address (and therefore the reveal-spend script) matches
    // exactly between the in-process happy path and out-of-band
    // recovery callers.
    let TaprootAnchor {
        commit_address,
        reveal_script,
        taproot_spend_info,
    } = build_taproot_anchor(commitment_data, public_key, network);

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

    let commit_txid = commit_tx.compute_txid();
    let commit_output_value = commit_tx.output[0].value.to_sat();

    let reveal_tx = build_reveal_only_inner(
        commit_txid,
        commit_output_value,
        publisher_address,
        &key_pair,
        &reveal_script,
        &taproot_spend_info,
        &secp256k1,
    );

    (commit_tx, reveal_tx)
}

/// Internal helper carrying the script-path anchor artefacts that both
/// `inscription_txs` and the recovery CLI need to reconstruct.
struct TaprootAnchor {
    commit_address: Address,
    reveal_script: ScriptBuf,
    taproot_spend_info: bitcoin::taproot::TaprootSpendInfo,
}

/// Builds the script-path Taproot anchor (commit address + reveal
/// script + spend info) from a commitment payload, the publisher's
/// x-only pubkey, and the target network. Pure / deterministic — the
/// same `(commitment_data, public_key, network)` triple always produces
/// the same anchor.
fn build_taproot_anchor(
    commitment_data: &[u8],
    public_key: XOnlyPublicKey,
    network: Network,
) -> TaprootAnchor {
    let secp256k1 = Secp256k1::new();

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

    let commit_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

    TaprootAnchor {
        commit_address,
        reveal_script,
        taproot_spend_info,
    }
}

/// Reveal-only constructor used by both the in-process publisher path
/// (`inscription_txs`) and the out-of-band recovery CLI
/// (`bin/recover_inscription.rs`).
///
/// Re-derives the script-path Taproot anchor from `commitment_data`
/// and the publisher key, then assembles + nonce-mines the reveal
/// transaction that spends the commit anchor's output[0] back to the
/// publisher address. The caller supplies the already-broadcast
/// `commit_txid` and the anchor output's value in sats — there is no
/// commit broadcast or commit signing on this path.
///
/// Returns the mined reveal transaction together with the derived
/// commit address so the caller can sanity-check it against the
/// observed on-chain anchor.
pub fn build_reveal_only(
    commit_txid: Txid,
    commit_output_value: u64,
    commitment_data: &[u8],
    publisher_key: &str,
    publisher_address: &Address,
    network: Network,
) -> (Transaction, Address) {
    let secp256k1 = Secp256k1::new();
    let sk = SecretKey::from_str(publisher_key).unwrap();
    let key_pair = secp256k1::Keypair::from_secret_key(&secp256k1, &sk);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let TaprootAnchor {
        commit_address,
        reveal_script,
        taproot_spend_info,
    } = build_taproot_anchor(commitment_data, public_key, network);

    let reveal_tx = build_reveal_only_inner(
        commit_txid,
        commit_output_value,
        publisher_address,
        &key_pair,
        &reveal_script,
        &taproot_spend_info,
        &secp256k1,
    );

    (reveal_tx, commit_address)
}

/// Inner reveal-construction loop shared by `inscription_txs` and
/// `build_reveal_only`. Takes the pre-derived anchor artefacts so we
/// only re-derive once per call site, matching the legacy code path.
#[allow(clippy::too_many_arguments)]
fn build_reveal_only_inner(
    commit_txid: Txid,
    commit_output_value: u64,
    publisher_address: &Address,
    key_pair: &secp256k1::Keypair,
    reveal_script: &ScriptBuf,
    taproot_spend_info: &bitcoin::taproot::TaprootSpendInfo,
    secp256k1: &Secp256k1<secp256k1::All>,
) -> Transaction {
    // The reveal spends the commit anchor; mirror the prevout `TxOut`
    // used for signing so the legacy and recovery paths produce a
    // byte-identical witness for the same inputs. The scriptPubKey is
    // derived directly from the tweaked output key (network-agnostic —
    // P2TR scriptPubKey is `OP_1 <32-byte-output-key>` on every chain).
    let commit_prevout = TxOut {
        value: Amount::from_sat(commit_output_value),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(taproot_spend_info.output_key()),
    };

    // Create reveal transaction
    let mut reveal_tx = Transaction {
        version: Version(1),
        lock_time: LockTime::from_consensus(0),
        input: vec![TxIn {
            previous_output: OutPoint::new(commit_txid, 0),
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
        Amount::from_sat(commit_output_value - reveal_fee);

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
                &Prevouts::All(&[&commit_prevout]),
                TapLeafHash::from_script(reveal_script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap();

        let message = secp256k1::Message::from_digest_slice(&signature_hash[..]).unwrap();
        let signature = secp256k1.sign_schnorr(&message, key_pair);

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

    reveal_tx
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
/// The fallback fires on the OUTER `TRACK_TX_TIMEOUT_SECS` budget
/// (exposed via `TrackTxStream::wait` in `scanner_ws.rs`) — the
/// inner per-frame `TRACK_TX_FRAME_WATCHDOG` reconnect loop in
/// `scanner_ws.rs` is untouched.
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
                    println!(
                        "esplora-REST fallback: commit tx {} not found (404); broadcast genuinely failed",
                        commit_txid
                    );
                    return Err(Box::new(crate::scanner_ws::WsError::Timeout));
                }
                Err(e) => {
                    println!(
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

/// Creates and broadcasts inscription transactions with the given commitment data.
///
/// **Persistence contract (Phase B).** When `pool` is `Some`, the
/// constructed `(commit_tx, reveal_tx)` pair is persisted to the
/// `pending_inscriptions` table BEFORE the first broadcast attempt
/// and the row is walked through the `constructed → commit_broadcast
/// → reveal_broadcast → complete` state machine as each broadcast
/// lands. A crash anywhere in this sequence leaves a recoverable row
/// for [`resume_pending_inscriptions`] to re-drive on the next boot.
///
/// When `pool` is `None` (out-of-band callers / unit tests that don't
/// need persistence), the function behaves exactly like the
/// pre-Phase-B version — no DB writes, no resume hooks.
pub async fn create_and_broadcast_inscription(
    commitment_data: &[u8],
    kind: db::InscriptionKind,
    config: &EsploraConfig,
    pool: Option<&PgPool>,
) -> Result<(Txid, Txid), Box<dyn std::error::Error + Send + Sync>> {
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
    let commit_txid = commit_tx.compute_txid();
    let reveal_txid = reveal_tx.compute_txid();
    println!("\nCommit TX ID: {}", commit_txid);
    println!("Reveal TX ID: {}", reveal_txid);

    // Persist the (commit, reveal) pair BEFORE attempting any
    // broadcast. Crash-recovery (Phase B) hinges on the row being on
    // disk at every state-machine boundary — if we crash between
    // construct and commit-broadcast we want the resumer to find the
    // row and re-broadcast both; if we crash between commit and
    // reveal we want the resumer to find the row and re-broadcast
    // just the reveal. Both behaviours require the row already
    // exists by the time the first network call returns.
    if let Some(pool) = pool {
        let commit_tx_bytes = bitcoin::consensus::serialize(&commit_tx);
        let reveal_tx_bytes = bitcoin::consensus::serialize(&reveal_tx);
        let commit_output_value = commit_tx.output[0].value.to_sat() as i64;
        match db::insert_pending_inscription(
            pool,
            commit_txid.as_byte_array(),
            kind,
            commitment_data,
            &commit_tx_bytes,
            &reveal_tx_bytes,
            commit_output_value,
        )
        .await
        {
            Ok(true) => {
                println!(
                    "Persisted pending_inscriptions row (constructed) for commit={}",
                    commit_txid
                );
            }
            Ok(false) => {
                // UNIQUE-conflict: the same commit_txid is already on
                // disk (a previous attempt persisted, then crashed
                // before completing). The resumer will pick it up on
                // the next boot; in the meantime we still want to try
                // broadcasting now in case the operator hasn't
                // restarted yet.
                println!(
                    "pending_inscriptions row for commit={} already exists; proceeding with broadcast",
                    commit_txid
                );
            }
            Err(e) => {
                eprintln!(
                    "Failed to persist pending_inscriptions row for {}: {}",
                    commit_txid, e
                );
                return Err(format!("persist pending inscription: {}", e).into());
            }
        }
    }

    // Broadcast the transactions
    match broadcast_inscription_txs_with_persistence(config, &commit_tx, &reveal_tx, pool).await {
        Ok((commit_txid, reveal_txid)) => {
            println!("Successfully broadcast transactions:");
            println!("Commit TXID: {}", commit_txid);
            println!("Reveal TXID: {}", reveal_txid);
            Ok((commit_txid, reveal_txid))
        }
        Err(e) => {
            println!("Failed to broadcast transactions: {}", e);
            Err(e)
        }
    }
}

/// Esplora returns this substring inside an `HttpResponse { status:
/// 400, message }` payload when the commit's input UTXO was already
/// spent — typically because a previous attempt's commit broadcast
/// landed even though our process crashed before recording the
/// success. The resume path treats this as "commit already on chain;
/// advance and proceed to reveal" instead of a hard failure.
fn is_inputs_missingorspent_error(err: &dyn std::error::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("bad-txns-inputs-missingorspent")
        || msg.contains("missing-inputs")
        || msg.contains("txn-already-known")
}

/// Same as [`broadcast_inscription_txs`] but, when `pool` is
/// `Some`, advances the matching `pending_inscriptions` row through
/// `commit_broadcast → reveal_broadcast → complete` as each broadcast
/// step succeeds.
///
/// Status updates are best-effort: a DB-write failure after a
/// successful chain broadcast is logged but does NOT bubble back to
/// the caller — the chain is the source of truth, the row is
/// bookkeeping. If a status update fails, the next boot's resumer
/// will simply re-broadcast the next step (Esplora replies
/// `txn-already-known`) and advance the row then.
///
/// The body is a transcription of [`broadcast_inscription_txs`] with
/// status-update hooks woven in at the three points where the chain
/// confirms a step. Keeping the two functions separate (rather than
/// having one take `Option<&PgPool>`) avoids changing the existing
/// public surface and keeps the pure-broadcast code path readable.
pub async fn broadcast_inscription_txs_with_persistence(
    config: &EsploraConfig,
    commit_tx: &Transaction,
    reveal_tx: &Transaction,
    pool: Option<&PgPool>,
) -> Result<(Txid, Txid), Box<dyn std::error::Error + Send + Sync>> {
    let builder = EsploraBuilder::new(&config.url);
    let client = EsploraAsyncClient::<DefaultSleeper>::from_builder(builder)?;

    let commit_txid = commit_tx.compute_txid();
    let commit_txid_bytes = *commit_txid.as_byte_array();
    let ws_url = config.ws_url.clone().unwrap_or_else(|| {
        std::env::var("ESPLORA_WS_URL").unwrap_or_else(|_| DEFAULT_ESPLORA_WS_URL.to_string())
    });
    let track_tx_timeout = config
        .track_tx_timeout
        .unwrap_or_else(|| std::time::Duration::from_secs(TRACK_TX_TIMEOUT_SECS));

    println!(
        "Subscribing to commit tx {} via WS ({}) before broadcast...",
        commit_txid, ws_url
    );
    let stream = crate::scanner_ws::subscribe_track_tx(&ws_url, commit_txid).await?;

    println!("Broadcasting commit transaction...");
    client.broadcast(commit_tx).await?;
    println!("Commit transaction broadcast successfully: {}", commit_txid);
    advance_pending_status(
        pool,
        &commit_txid_bytes,
        db::PENDING_STATUS_COMMIT_BROADCAST,
    )
    .await;

    println!(
        "Waiting for commit tx {} to appear in mempool via WS (deadline {:?})...",
        commit_txid, track_tx_timeout
    );
    match stream.wait(track_tx_timeout).await {
        Ok(()) => {}
        Err(crate::scanner_ws::WsError::Timeout) => {
            // Mutinynet's public WS endpoint regularly goes 30-90 s
            // between frames; the REST fallback distinguishes "WS
            // missed the frame" from a genuine broadcast failure.
            // Same shape as `broadcast_inscription_txs` — see that
            // function's docstring for the full rationale.
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
                    println!(
                        "esplora-REST fallback: commit tx {} not found (404); broadcast genuinely failed",
                        commit_txid
                    );
                    return Err(Box::new(crate::scanner_ws::WsError::Timeout));
                }
                Err(e) => {
                    println!(
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
    advance_pending_status(
        pool,
        &commit_txid_bytes,
        db::PENDING_STATUS_REVEAL_BROADCAST,
    )
    .await;
    // Phase E: the row stays at `reveal_broadcast` here. The caller
    // (`mint_handler`) advances to `complete` only AFTER it has applied
    // `state.update` to the in-memory SMT/MMR and persisted the snapshot.
    // The scanner's pre-`state.update` lookup uses the
    // `complete` marker to decide whether the inscription has already
    // been integrated by the mint flow — advancing here would set the
    // marker before the integration actually happened and let a
    // mid-flight crash leave a `complete` row whose SMT/MMR were never
    // updated, which the scanner would then skip on replay.

    Ok((commit_txid, reveal_txid))
}

/// Helper: when `pool` is `Some`, set the row's status and log any
/// error rather than propagating it. The chain has already accepted
/// the step by the time this is called, so a DB-side failure is
/// recoverable on the next boot via the resumer.
async fn advance_pending_status(pool: Option<&PgPool>, commit_txid_bytes: &[u8], status: &str) {
    let Some(pool) = pool else {
        return;
    };
    if let Err(e) = db::update_pending_status(pool, commit_txid_bytes, status).await {
        eprintln!(
            "Failed to advance pending_inscriptions row {} to {}: {}",
            hex::encode(commit_txid_bytes),
            status,
            e
        );
    }
}

/// Re-broadcast every pending inscription left in the
/// `pending_inscriptions` table by a previous boot.
///
/// Strategy: load every row whose status is not `complete`, then
/// dispatch by status:
///
/// * `constructed` — re-broadcast both commit and reveal. If the
///   commit broadcast returns `bad-txns-inputs-missingorspent` the
///   commit's input was already spent by a previous attempt that
///   landed before we crashed; advance to `commit_broadcast` and
///   continue to the reveal.
/// * `commit_broadcast` — re-broadcast just the reveal. The commit
///   is already on chain.
/// * `reveal_broadcast` — re-broadcast the reveal anyway (idempotent;
///   Esplora returns `txn-already-known`) and advance to `complete`.
///
/// **Non-fatal on errors.** A failure here MUST NOT crash the
/// bootstrap — the publisher's CLI recovery tool (PR #106) remains
/// the operator's escape hatch. Errors are logged loudly so they
/// surface in the container's stdout / log aggregator.
pub async fn resume_pending_inscriptions(
    pool: &PgPool,
    config: &EsploraConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let rows = db::load_pending_in_progress(pool).await?;
    if rows.is_empty() {
        println!("resume_pending_inscriptions: no pending rows");
        return Ok(());
    }
    println!(
        "resume_pending_inscriptions: resuming {} pending row(s)",
        rows.len()
    );

    for row in rows {
        if let Err(e) = resume_single_row(pool, config, &row).await {
            eprintln!(
                "resume_pending_inscriptions: row id={} commit_txid={} status={} failed: {}",
                row.id,
                hex::encode(&row.commit_txid),
                row.status,
                e
            );
        }
    }
    Ok(())
}

/// Drives one [`db::PendingInscriptionRow`] to `complete`. Split out
/// of [`resume_pending_inscriptions`] so a per-row failure short-
/// circuits with `?` cleanly without abandoning the rest of the
/// queue.
async fn resume_single_row(
    pool: &PgPool,
    config: &EsploraConfig,
    row: &db::PendingInscriptionRow,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let commit_tx: Transaction = bitcoin::consensus::deserialize(&row.commit_tx)
        .map_err(|e| format!("deserialize commit_tx: {}", e))?;
    let reveal_tx: Transaction = bitcoin::consensus::deserialize(&row.reveal_tx)
        .map_err(|e| format!("deserialize reveal_tx: {}", e))?;

    let builder = EsploraBuilder::new(&config.url);
    let client = EsploraAsyncClient::<DefaultSleeper>::from_builder(builder)?;

    let commit_txid = commit_tx.compute_txid();

    match row.status.as_str() {
        db::PENDING_STATUS_CONSTRUCTED => {
            println!(
                "resume: row id={} status=constructed → re-broadcasting commit {}",
                row.id, commit_txid
            );
            match client.broadcast(&commit_tx).await {
                Ok(()) => {
                    db::update_pending_status(
                        pool,
                        &row.commit_txid,
                        db::PENDING_STATUS_COMMIT_BROADCAST,
                    )
                    .await?;
                }
                Err(e) if is_inputs_missingorspent_error(&e) => {
                    // The commit already landed on a previous attempt.
                    // Advance and fall through to the reveal step.
                    println!(
                        "resume: commit {} already on chain (bad-txns-inputs-missingorspent), advancing",
                        commit_txid
                    );
                    db::update_pending_status(
                        pool,
                        &row.commit_txid,
                        db::PENDING_STATUS_COMMIT_BROADCAST,
                    )
                    .await?;
                }
                Err(e) => return Err(e.into()),
            }
            broadcast_reveal_and_complete(pool, &client, &row.commit_txid, &reveal_tx).await?;
        }
        db::PENDING_STATUS_COMMIT_BROADCAST => {
            println!(
                "resume: row id={} status=commit_broadcast → broadcasting reveal for {}",
                row.id, commit_txid
            );
            broadcast_reveal_and_complete(pool, &client, &row.commit_txid, &reveal_tx).await?;
        }
        db::PENDING_STATUS_REVEAL_BROADCAST => {
            println!(
                "resume: row id={} status=reveal_broadcast → re-broadcasting reveal for {} (idempotent)",
                row.id, commit_txid
            );
            // Re-broadcast is idempotent: Esplora returns
            // `txn-already-known` if the reveal landed on a previous
            // attempt. Treat that as success.
            match client.broadcast(&reveal_tx).await {
                Ok(()) => {}
                Err(e) if is_inputs_missingorspent_error(&e) => {
                    println!(
                        "resume: reveal for {} already on chain (txn-already-known)",
                        commit_txid
                    );
                }
                Err(e) => return Err(e.into()),
            }
            // Phase E: leave the row at `reveal_broadcast`. The scanner
            // will observe the commit on chain, see the non-`complete`
            // status, run `state.update` itself, and only then mark the
            // row `complete` — the `complete` marker now means "SMT/MMR
            // contain this inscription's entry", which the resumer
            // cannot truthfully assert from outside the state lock.
        }
        other => {
            // Forward-compatible: an unknown status (e.g. a future
            // `failed` value) is skipped instead of crashing the
            // bootstrap.
            println!(
                "resume: row id={} commit_txid={} has unknown status {:?}; skipping",
                row.id,
                hex::encode(&row.commit_txid),
                other
            );
        }
    }
    Ok(())
}

/// Broadcast `reveal_tx` and advance the matching row to
/// `reveal_broadcast`. Used by both the `constructed` and
/// `commit_broadcast` resume branches.
///
/// Phase E: this no longer flips the row to `complete`. The `complete`
/// marker now means "SMT/MMR contain this inscription's entry", which
/// only the in-process mint flow (or the scanner-replay path after
/// re-running `state.update`) can truthfully assert. The resumer is
/// outside both code paths, so it stops at `reveal_broadcast` and
/// lets the scanner finish the integration.
async fn broadcast_reveal_and_complete(
    pool: &PgPool,
    client: &EsploraAsyncClient<DefaultSleeper>,
    commit_txid_bytes: &[u8],
    reveal_tx: &Transaction,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match client.broadcast(reveal_tx).await {
        Ok(()) => {}
        Err(e) if is_inputs_missingorspent_error(&e) => {
            // Reveal already on chain — proceed to advance the row.
            println!(
                "resume: reveal {} already on chain (txn-already-known)",
                reveal_tx.compute_txid()
            );
        }
        Err(e) => return Err(e.into()),
    }
    db::update_pending_status(pool, commit_txid_bytes, db::PENDING_STATUS_REVEAL_BROADCAST).await?;
    // Phase E: do not advance to `complete` here either. See the
    // `PENDING_STATUS_REVEAL_BROADCAST` branch in `resume_single_row`
    // for the rationale — `complete` is now reserved for "SMT/MMR
    // hold this entry", which the scanner sets after running
    // `state.update`.
    Ok(())
}

#[cfg(test)]
#[path = "publisher_tests.rs"]
mod tests;
