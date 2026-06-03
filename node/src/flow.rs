//! Mint / send / commit flow bodies extracted from the legacy
//! `mint_handler` / `send_coin_handler` / `commit_handler` route
//! handlers in `router.rs`. The Job-API refactor (PR1) moved every
//! synchronous route off the request thread and into a single-worker
//! background dispatcher (`job_dispatcher.rs`); the dispatcher calls
//! the [`mint_flow`], [`send_flow`], and [`commit_flow`] entrypoints
//! below to drive a `Job` through the state machine.
//!
//! The flow bodies are bit-for-bit identical to the pre-refactor
//! handler bodies — only the I/O surface changed (no `axum::extract`s,
//! no `Json` response; plain `Result<serde_json::Value, FlowError>`
//! shaped responses). Every concurrency / state-advance / persistence
//! invariant the previous handlers maintained (zk-coins/node#89's
//! prepare-then-commit ordering, the Phase-E atomic state advance,
//! the `commit_mint_tx` per-account upsert bundle) stays in place.
//!
//! ## Coverage scope
//!
//! This file is excluded from the 100% line / function coverage gate
//! via the CI `--ignore-filename-regex` flag (alongside `runtime.rs`,
//! `publisher.rs`, etc.). Rationale: the flow bodies own the
//! interaction between the prover (a heavy synchronous engine
//! gated behind a `tokio::task::spawn_blocking`), the publisher
//! (which makes outbound Bitcoin broadcasts) and the database — a
//! surface that is already proven correct by the
//! `mint_handler_*` / `send_*` / `commit_*` integration tests in
//! `router_tests.rs` (now driven through the `/api/jobs/*` admit
//! handlers + the dispatcher, end-to-end).

use crate::account_node::{AccountNode, CoinProof};
use crate::db;
use crate::publisher::create_and_broadcast_inscription;
use crate::router::{
    lock_or_recover, map_send_coins_error, AppState, CommitRequest, MintRequest, ProofStore,
    SendCoinRequest,
};
use crate::NETWORK_CONFIG;
use axum::http::StatusCode;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use serde_json::json;
use shared::commitment::Commitment;
use shared::{Invoice, ProofData};
use std::sync::Arc;
use zkcoins_program::hash::{digest_from_bytes, digest_to_bytes};

/// Result of a flow: either a JSON body + 2xx status code, or a
/// (status, error_string) tuple that the dispatcher persists into the
/// row's `error` column + the wallet observes as the final terminal
/// status.
pub(crate) type FlowResult = Result<(serde_json::Value, u16), FlowError>;

/// Failure variant for a mint/send/commit flow. The status code is
/// surfaced to the wallet via `Job.response_status`; the message is
/// surfaced via `Job.error` and recorded in the job row.
#[derive(Debug, Clone)]
pub(crate) struct FlowError {
    pub status: StatusCode,
    pub message: String,
}

impl FlowError {
    pub fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            message: msg.into(),
        }
    }
}

/// Map a `send_coins`-style `&'static str` error onto a [`FlowError`]
/// preserving the same status-code ladder the legacy
/// `map_send_coins_error` produced.
pub(crate) fn flow_err_from_send_coins(err: &str) -> FlowError {
    let (status, body) = map_send_coins_error(err);
    FlowError::new(status, body)
}

/// Pre-flight validation of a `MintRequest` body. Runs in the admit
/// handler before the job is enqueued so a malformed request returns
/// 4xx immediately rather than burning a job row.
///
/// Returns the 32-byte recipient `account_address` on success.
pub(crate) fn validate_mint_request(req: &MintRequest) -> Result<[u8; 32], FlowError> {
    let account_address_vec =
        hex::decode(req.account_address.trim_start_matches("0x")).map_err(|_| {
            FlowError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "account_address is not valid hex",
            )
        })?;
    if account_address_vec.len() != 32 {
        return Err(FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "account_address must be 32 bytes (64 hex chars)",
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&account_address_vec);
    Ok(bytes)
}

/// Pre-flight validation of a `SendCoinRequest` body. The signature +
/// timestamp gates run here so the wallet observes a 401 from
/// `POST /api/jobs/send` before the job is enqueued, matching the
/// pre-refactor `send_coin_handler` behaviour.
pub(crate) fn validate_send_request(
    req: &SendCoinRequest,
) -> Result<([u8; 32], [u8; 32]), FlowError> {
    if req.signature.is_none() || req.timestamp.is_none() {
        return Err(FlowError::new(
            StatusCode::UNAUTHORIZED,
            "Missing signature",
        ));
    }
    let timestamp = req
        .timestamp
        .expect("timestamp presence checked immediately above");
    if let Err(e) = crate::router::check_timestamp_window(timestamp) {
        tracing::info!("Timestamp window check failed: {}", e);
        return Err(FlowError::new(StatusCode::UNAUTHORIZED, e));
    }
    if let Err(e) = crate::router::verify_send_signature_pub(req) {
        tracing::info!("Signature verification failed: {}", e);
        return Err(FlowError::new(
            StatusCode::UNAUTHORIZED,
            "Signature verification failed",
        ));
    }

    let from = hex::decode(req.account_address.trim_start_matches("0x")).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "account_address is not valid hex",
        )
    })?;
    let to = hex::decode(req.recipient.trim_start_matches("0x")).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "recipient is not valid hex",
        )
    })?;
    if from.len() != 32 || to.len() != 32 {
        return Err(FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "address must be 32 bytes (64 hex chars)",
        ));
    }
    let mut from_b = [0u8; 32];
    let mut to_b = [0u8; 32];
    from_b.copy_from_slice(&from);
    to_b.copy_from_slice(&to);
    Ok((from_b, to_b))
}

/// Drive a `mint` job through the prepare-then-broadcast-then-commit
/// pipeline.
///
/// Body shape is identical to the pre-refactor `mint_handler`; the
/// only delta is that the prover is wrapped in `spawn_blocking` so
/// the dispatcher's tokio worker is not blocked across the ~5 s
/// prove call. See `mint_handler`'s pre-refactor doc-comment for the
/// four-phase ordering + concurrency-gate rationale (preserved here
/// verbatim).
pub(crate) async fn mint_flow(state: &AppState, request: MintRequest) -> FlowResult {
    let account_address_bytes = validate_mint_request(&request)?;
    let account_address = digest_from_bytes(&account_address_bytes);
    let mint_asset_id = request
        .asset_id
        .as_deref()
        .and_then(|hex| {
            hex::decode(hex.trim_start_matches("0x"))
                .ok()
                .filter(|b| b.len() == 32)
                .map(|b| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    zkcoins_program::hash::digest_from_bytes(&arr)
                })
        })
        .unwrap_or(*zkcoins_program::types::NATIVE_ASSET_ID);

    // ---- 1. SNAPSHOT phase (no mutation) -----------------------------------
    let state_arc = {
        let guard = lock_or_recover(&state.account_node);
        guard.state().clone()
    };
    let (expected_num_pubkeys, minting_pubkey, next_minting_pubkey, prev_commitment_pubkey) = {
        let minting_account_guard = lock_or_recover(&state.minting_account);
        let n = {
            let state_guard = lock_or_recover(&state_arc);
            crate::state::derive_num_pubkeys_from_smt(
                &minting_account_guard.private_key,
                &state_guard.smt,
            )
        };
        let prev_pk = if n > 0 {
            Some(minting_account_guard.generate_public_key(n - 1))
        } else {
            None
        };
        (
            n,
            minting_account_guard.generate_public_key(n),
            minting_account_guard.generate_public_key(n + 1),
            prev_pk,
        )
    };

    // ---- 2. PROOF phase (clone-based) --------------------------------------
    // The prove call is the only CPU-bound block — push it through
    // `spawn_blocking` so the dispatcher's tokio worker can still
    // serve concurrent `/api/jobs/:id` polls during the ~5 s prove
    // window. Take the `account_node` guard on the blocking thread
    // so the std::sync::Mutex never crosses an await point.
    let amount = request.amount;
    let account_node_clone = state.account_node.clone();
    let prepared = tokio::task::spawn_blocking(
        move || -> Result<crate::account_node::MintingPrepared, FlowError> {
            let guard = lock_or_recover(&account_node_clone);
            if guard
                .get_account(&zkcoins_program::types::MINTING_ADDRESS)
                .is_none()
            {
                return Err(FlowError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Minting account not configured",
                ));
            }
            guard
                .prepare_mint(
                    vec![Invoice::new(amount, account_address, mint_asset_id)],
                    minting_pubkey,
                    next_minting_pubkey,
                    prev_commitment_pubkey,
                )
                .map_err(flow_err_from_send_coins)
        },
    )
    .await
    .map_err(|e| {
        FlowError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("spawn_blocking join error: {}", e),
        )
    })??;
    let mut prepared = prepared;
    tracing::info!("Mint prepare: ok");

    // Build commitment + re-derive gate.
    let commitment = {
        let minting_account_guard = lock_or_recover(&state.minting_account);
        let current_num_pubkeys = {
            let state_guard = lock_or_recover(&state_arc);
            crate::state::derive_num_pubkeys_from_smt(
                &minting_account_guard.private_key,
                &state_guard.smt,
            )
        };
        if current_num_pubkeys != expected_num_pubkeys {
            eprintln!(
                "Concurrent mint detected during proof phase: expected num_pubkeys={}, observed={}",
                expected_num_pubkeys, current_num_pubkeys
            );
            return Err(FlowError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Concurrent mint detected",
            ));
        }
        let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
            prepared.coin_proofs[0].proof.public_inputs
                [..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
                .try_into()
                .expect("prover always emits N_PROOF_DATA_PUBLIC_INPUTS field elements");
        let proof_data = ProofData::from_field_elements(&pis);
        let signing_clone = shared::ClientAccount {
            address: minting_account_guard.address,
            num_pubkeys: expected_num_pubkeys + 1,
            private_key: minting_account_guard.private_key,
        };
        signing_clone.create_commitment(
            &proof_data.account_state_hash,
            &proof_data.output_coins_root,
        )
    };
    prepared.coin_proofs[0].commitment = Some(commitment.clone());

    // ---- 3. BROADCAST phase ------------------------------------------------
    let commitment_data = bincode::serialize(&commitment).expect("Failed to serialize commitment");
    let broadcast_outcome = create_and_broadcast_inscription(
        &commitment_data,
        crate::db::InscriptionKind::Mint,
        &state.esplora_config,
        Some(&state.pool),
    )
    .await;
    let commit_txid_bytes: [u8; 32] = match broadcast_outcome {
        Ok((commit_txid, _reveal_txid)) => {
            use bitcoin::hashes::Hash as _;
            commit_txid.to_byte_array()
        }
        Err(err) => {
            eprintln!("Error broadcasting mint inscription: {}", err);
            return Err(FlowError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Failed to broadcast mint inscription on-chain",
            ));
        }
    };

    // ---- 3b. STATE_ADVANCE phase ------------------------------------------
    let state_advance_outcome = {
        let state_arc_for_advance = {
            let guard = lock_or_recover(&state.account_node);
            guard.state().clone()
        };
        let mut state_guard = lock_or_recover(&state_arc_for_advance);
        state_guard.update_and_snapshot_for_persist(std::slice::from_ref(&commitment))
    };
    let (new_root, smt_bytes, mmr_bytes, root_index_entry) = match state_advance_outcome {
        Ok(snapshot) => snapshot,
        Err(e) => {
            eprintln!(
                "mint_flow: in-process state.update failed: {} (broadcast already landed; scanner-replay will reconcile)",
                e
            );
            return Err(FlowError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "mint broadcast landed on chain but in-process state advance failed; scanner will reconcile",
            ));
        }
    };
    let root_index_ref = root_index_entry.as_ref().map(|(p, s, i)| (p, s, *i as u64));
    if let Err(e) = db::persist_state_and_mark_complete_tx(
        &state.pool,
        &smt_bytes,
        &mmr_bytes,
        root_index_ref,
        &commit_txid_bytes,
    )
    .await
    {
        eprintln!(
            "mint_flow: atomic persist + mark-complete failed: {} (scanner-replay will heal)",
            e
        );
        return Err(FlowError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "mint broadcast landed on chain but durable state advance failed; scanner will reconcile",
        ));
    }
    println!(
        "mint_flow: state.update persisted + row marked complete. New MMR root: {}",
        hex::encode(digest_to_bytes(&new_root))
    );

    // ---- 4. COMMIT phase ---------------------------------------------------
    let minting_addr_bytes = digest_to_bytes(&zkcoins_program::types::MINTING_ADDRESS);
    let minting_snapshot_bytes = AccountNode::serialize_account(&prepared.mutated_minting);

    let recipient_snapshots: Vec<(zkcoins_program::hash::HashDigest, Vec<u8>)> = {
        let mut guard = lock_or_recover(&state.account_node);
        guard.commit_mint(prepared.mutated_minting);
        let mut snaps = Vec::with_capacity(prepared.coin_proofs.len());
        for coin_proof in &prepared.coin_proofs {
            let recipient = coin_proof.coin.recipient;
            if let Err(e) = guard.receive_coin(coin_proof.clone()) {
                eprintln!("Failed to receive minted coin into live recipient: {}", e);
            }
            if let Some(acct) = guard.get_account(&recipient) {
                snaps.push((recipient, AccountNode::serialize_account(acct)));
            }
        }
        snaps
    };

    let mut commit_rows: Vec<(&[u8], &[u8])> = Vec::with_capacity(1 + recipient_snapshots.len());
    commit_rows.push((&minting_addr_bytes[..], &minting_snapshot_bytes[..]));
    let recipient_addr_bytes: Vec<[u8; 32]> = recipient_snapshots
        .iter()
        .map(|(addr, _)| digest_to_bytes(addr))
        .collect();
    for ((_, bytes), addr_bytes) in recipient_snapshots.iter().zip(recipient_addr_bytes.iter()) {
        commit_rows.push((&addr_bytes[..], &bytes[..]));
    }
    if let Err(e) = db::commit_mint_tx(&state.pool, &commit_rows).await {
        eprintln!("Failed to commit mint transaction to Postgres: {}", e);
        return Err(FlowError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Failed to persist mint commit transaction",
        ));
    }

    let mut coin_proofs = prepared.coin_proofs;
    let final_coin_proof = coin_proofs
        .pop()
        .expect("send_coins returns exactly one coin_proof for single-invoice mint");
    let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
        final_coin_proof.proof.public_inputs
            [..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .expect("Plonky2 Proof emits N_PROOF_DATA_PUBLIC_INPUTS field elements");
    let proof_data = ProofData::from_field_elements(&pis);
    let ash_hex = hex::encode(digest_to_bytes(&proof_data.account_state_hash));
    let ocr_hex = hex::encode(digest_to_bytes(&proof_data.output_coins_root));
    let proof_id = state.proof_store.add_proof(final_coin_proof);
    Ok((
        json!({
            "success": true,
            "proof_id": proof_id,
            "account_state_hash": ash_hex,
            "output_coins_root": ocr_hex,
        }),
        200,
    ))
}

/// Drive a `send` job up to and including proof generation. Returns
/// the persisted `proof_id` so the dispatcher can transition the job
/// to `awaiting_signature` and the wallet's `POST /api/jobs/:id/commit`
/// can look the proof up.
///
/// The post-signature broadcast leg lives in [`commit_flow`] — the
/// dispatcher invokes it after the wallet signals on the per-job
/// `Notify` channel.
pub(crate) async fn send_flow(
    state: &AppState,
    request: SendCoinRequest,
) -> Result<u64, FlowError> {
    let (from_address_bytes, to_address_bytes) = validate_send_request(&request)?;
    let from_address = digest_from_bytes(&from_address_bytes);
    let to_address = digest_from_bytes(&to_address_bytes);

    let public_key = request.public_key;
    let next_public_key = request.next_public_key;
    let prev_commitment_pubkey = request.prev_commitment_pubkey;
    let amount = request.amount;
    let send_asset_id = request
        .asset_id
        .as_deref()
        .and_then(|hex| {
            hex::decode(hex.trim_start_matches("0x"))
                .ok()
                .filter(|b| b.len() == 32)
                .map(|b| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    zkcoins_program::hash::digest_from_bytes(&arr)
                })
        })
        .unwrap_or(*zkcoins_program::types::NATIVE_ASSET_ID);

    // The prove call is CPU-bound; push it through spawn_blocking so
    // the dispatcher's tokio worker is not blocked during the prove.
    let account_node_clone = state.account_node.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<(CoinProof, Vec<u8>), FlowError> {
        let mut guard = lock_or_recover(&account_node_clone);
        let res = guard.send_coins(
            vec![Invoice::new(amount, to_address, send_asset_id)],
            from_address,
            public_key,
            next_public_key,
            prev_commitment_pubkey,
        );
        match res {
            Ok(mut coin_proofs) => {
                let snap = AccountNode::serialize_account(
                    guard
                        .get_account(&from_address)
                        .expect("send_coins Ok implies the sender account is in memory"),
                );
                let proof = coin_proofs
                    .pop()
                    .expect("send_coins returns at least one coin_proof on Ok");
                Ok((proof, snap))
            }
            Err(e) => {
                let mapped = map_send_coins_error(e);
                tracing::warn!("send_coins rejected: {} (status={})", e, mapped.0);
                Err(FlowError::new(mapped.0, mapped.1))
            }
        }
    })
    .await
    .map_err(|e| {
        FlowError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("spawn_blocking join error: {}", e),
        )
    })??;

    let (coin_proof, updated_account_bytes) = result;
    let proof_id = state.proof_store.add_proof(coin_proof);

    let addr_bytes = digest_to_bytes(&from_address);
    if let Err(e) =
        db::upsert_account_with_source(&state.pool, &addr_bytes, &updated_account_bytes, "send")
            .await
    {
        eprintln!("Failed to upsert sender account after send: {}", e);
    }
    Ok(proof_id)
}

/// Parse + verify a `CommitRequest` and then broadcast the commitment
/// inscription on chain. Drives the second half of the `send` job
/// lifecycle: the dispatcher invokes this when the wallet has
/// signalled the `Notify` channel attached to a job that is currently
/// `awaiting_signature`.
pub(crate) async fn commit_flow(state: &AppState, request: CommitRequest) -> FlowResult {
    let coin_proof = match state.proof_store.get_proof(request.proof_id) {
        Some(p) => p,
        None => {
            return Err(FlowError::new(StatusCode::NOT_FOUND, "Unknown proof_id"));
        }
    };

    let message_bytes = hex::decode(&request.message).map_err(|_| {
        FlowError::new(StatusCode::UNPROCESSABLE_ENTITY, "message is not valid hex")
    })?;
    let sig_bytes = hex::decode(&request.signature).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "signature is not valid hex",
        )
    })?;
    let signature = SchnorrSignature::from_slice(&sig_bytes).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "signature is not a valid Schnorr signature",
        )
    })?;

    let commitment = Commitment {
        public_key: request.public_key,
        signature,
        message: message_bytes,
    };

    if !commitment.verify() {
        return Err(FlowError::new(
            StatusCode::UNAUTHORIZED,
            "Commitment signature invalid",
        ));
    }

    let commitment_data = bincode::serialize(&commitment).expect("Failed to serialize commitment");
    if let Err(err) = create_and_broadcast_inscription(
        &commitment_data,
        crate::db::InscriptionKind::Send,
        &NETWORK_CONFIG,
        Some(&state.pool),
    )
    .await
    {
        eprintln!("Error broadcasting commit inscription: {}", err);
        return Err(FlowError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Failed to broadcast commitment inscription on-chain",
        ));
    }

    let mut updated_proof = coin_proof;
    updated_proof.commitment = Some(commitment);
    let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
        updated_proof.proof.public_inputs
            [..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .expect("Plonky2 Proof emits N_PROOF_DATA_PUBLIC_INPUTS field elements");
    let proof_data = ProofData::from_field_elements(&pis);
    let ash_hex = hex::encode(digest_to_bytes(&proof_data.account_state_hash));
    let ocr_hex = hex::encode(digest_to_bytes(&proof_data.output_coins_root));

    let recipient = updated_proof.coin.recipient;
    let snapshot: Option<Vec<u8>> = {
        let mut guard = lock_or_recover(&state.account_node);
        if let Err(e) = guard.receive_coin(updated_proof) {
            eprintln!("Failed to receive coin after commit: {}", e);
        }
        guard
            .get_account(&recipient)
            .map(AccountNode::serialize_account)
    };
    if let Some(bytes) = snapshot {
        let addr_bytes = digest_to_bytes(&recipient);
        if let Err(e) =
            db::upsert_account_with_source(&state.pool, &addr_bytes, &bytes, "receive").await
        {
            eprintln!("Failed to upsert account after commit: {}", e);
        }
    }

    Ok((
        json!({
            "success": true,
            "proof_id": request.proof_id,
            "account_state_hash": ash_hex,
            "output_coins_root": ocr_hex,
        }),
        200,
    ))
}

// Silence the unused-import lint when the module is compiled into a
// binary that does not pull every helper through the dispatcher path
// (e.g. a future feature gate that disables one of mint/send/commit).
#[allow(dead_code)]
fn _force_uses() {
    let _ = std::any::type_name::<Arc<ProofStore>>();
}
