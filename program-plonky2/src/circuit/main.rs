//! Monolithic state-transition circuit for zkCoins (Plonky2 backend).
//!
//! Mirrors `program/src/main.rs` (the SP1 entrypoint), but built as a
//! Plonky2 cyclic-recursive circuit per [`SPEC.md`] §8 / §10 and the
//! `ROADMAP.md` Step 5 plan.
//!
//! ## Stage status
//!
//! - **5a — recursion plumbing PoC**: done in commit `83fa0c1`,
//!   superseded by 5b.
//! - **5b — Initial branch with real predicate**: done in commit
//!   `d167237`.
//! - **5c — AccountUpdate branch**: done in commit `bba6470`. SPEC §8
//!   (a) + (b) wired, `coin_history` carry-over, mint exception
//!   masked.
//! - **5c+ — CommitmentMerkleProofs in-circuit** ✅ this revision.
//!   SPEC §8 (c)(d)(e) wired against fixed-shape SMT + MMR proofs.
//!   Specifically: (c) is `account_state.hash() ==
//!   mp.commitment_account_state_hash` via element-wise difference
//!   masked with `condition`; (d) is `mp.verify_commitment(history_root)`,
//!   which is an in-circuit SMT inclusion of `commitment = h(asth || ocr)`
//!   in `commitment_root` followed by MMR inclusion of
//!   `h(commitment_root || commitment_root_mmr_sibling)` in `history_root`;
//!   (e) is `mp.verify_previous_root(prev.commitment_history_root,
//!   history_root)`, i.e. MMR inclusion of `h(previous_root_history_proof.0
//!   || prev.commitment_history_root)` in `history_root`.
//!   Every (c)(d)(e) check is masked: each `connect_hashes(computed,
//!   expected)` is re-targeted as `connect_hashes(computed,
//!   select_hash(condition, expected_witness, computed))`. When
//!   `condition = false` the `select` collapses to `computed` and the
//!   constraint is trivially satisfied; when `condition = true` it
//!   reduces to the honest check.
//! - **5d / 5e** — see ROADMAP "In Progress" section.
//!
//! ## Public-input layout (unchanged from 5b)
//!
//! 16 `ProofData` field elements + verifier-data slots. Layout per
//! [`crate::types::ProofData::to_field_elements`]:
//!
//! | slot range | meaning                  |
//! |------------|--------------------------|
//! | 0..4       | account_state_hash       |
//! | 4..8       | output_coins_root        |
//! | 8..12      | commitment_history_root  |
//! | 12..16     | coin_history_root        |
//!
//! ## Fixed-shape requirements
//!
//! The circuit consumes:
//! - One SMT inclusion proof of depth [`TREE_DEPTH`] = 256.
//! - Two MMR inclusion proofs of depth [`MMR_PROOF_PATH_LEN`] =
//!   `MMR_MAX_DEPTH - 1` = 31.
//!
//! Off-circuit producers must extend their (variable-depth) proofs to
//! these fixed depths before witnessing — see
//! [`crate::merkle::merkle_mountain_range::MMRProof::extend_to`] and
//! [`crate::merkle::merkle_mountain_range::MerkleMountainRange::root_extended`]
//! for the MMR helper. The SMT is already uncompressed-fixed-depth by
//! construction (see the SMT redesign commit).
//!
//! ## Branch selection via `condition`
//!
//! - `false` → Initial (dummy inner; cyclic verify uses dummy; all
//!   AccountUpdate-only constraints — state continuity, (c)(d)(e),
//!   coin_history carry-over — are masked off).
//! - `true`  → AccountUpdate (real prev proof in inner slot; all
//!   AccountUpdate-only constraints fire; mint exception masked off).

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

use crate::circuit::mmr::mmr_inclusion_root;
use crate::circuit::smt::{hash_up_full_path, key_bits_msb_first, smt_inclusion_root};
use crate::hash::{digest_from_bytes, HashDigest, ZERO_HASH};
use crate::inputs::CommitmentMerkleProofs;
use crate::merkle::merkle_mountain_range::MMR_MAX_DEPTH;
use crate::merkle::sparse_merkle_tree::{NonInclusionProof, DEFAULT_HASHES, TREE_DEPTH};
use crate::types::{AccountState, Coin, PublicKey, MINTING_ADDRESS};
use crate::{C, D, F};

/// Public-input count carried by the `ProofData` payload:
/// `4 (account_state_hash) + 4 (output_coins_root) + 4 (commitment_history_root) + 4 (coin_history_root)`.
///
/// Mirrors [`crate::types::ProofData::to_field_elements`]'s output length;
/// the verifier-data slots added by `add_verifier_data_public_inputs`
/// follow these and are not counted here.
pub const N_PROOF_DATA_PUBLIC_INPUTS: usize = 16;

/// Fixed in-circuit MMR proof path length. Equal to
/// `MMR_MAX_DEPTH - 1` because an MMR proof has one sibling per level
/// from the leaf's parent (level 1) to the root (level
/// `MMR_MAX_DEPTH - 1`).
pub const MMR_PROOF_PATH_LEN: usize = MMR_MAX_DEPTH - 1;

/// Number of in-coin slots the circuit reserves. The state transition
/// processes `MAX_IN_COINS` slots in fixed order; inactive slots are
/// no-ops (masked by their per-slot `active` bit). Matches SPEC §13's
/// production target. Each extra slot adds ~512 Poseidon hashes
/// (the in-circuit SMT non-inclusion + insert walks at `TREE_DEPTH =
/// 256`) plus ~80 arithmetic gates for the recipient + balance
/// checks. The cyclic-recursion `common_data_for_recursion_c`
/// padding must be sized to accommodate the resulting outer-circuit
/// gate count — see that function for the current setting.
pub const MAX_IN_COINS: usize = 8;

/// Number of out-coin slots the circuit reserves. Each active slot
/// inserts the coin's identifier into the running `output_coins_root`
/// SMT and subtracts its amount from the running balance with an
/// underflow check. After the out-coin loop, the slot's
/// `out_coin.identifier` is asserted to equal
/// `Poseidon(interim_account_state_hash || slot_index)`, mirroring
/// the off-circuit [`crate::types::calculate_coin_identifier`].
/// Matches SPEC §13's production target of 8. Each extra slot costs
/// ~512 Poseidon hashes + ~80 arithmetic gates; the cyclic-recursion
/// `common_data_for_recursion_c` padding must be sized to accommodate
/// the resulting outer-circuit gate count.
pub const MAX_OUT_COINS: usize = 8;

/// Build the `CommonCircuitData` that the cyclic circuit references
/// when verifying its own prior proof.
///
/// Faithful port of Plonky2 1.1.0's own
/// `recursion::cyclic_recursion::tests::common_data_for_recursion`:
///
/// 1. An empty circuit, to seed `data.common`.
/// 2. A circuit that calls `verify_proof` once against the seed; this
///    establishes a verifier shape stable enough to be its own input.
/// 3. A third pass that verifies once and pads the gate set up to
///    2^12 gates with `NoopGate`. The padding fixes the circuit size
///    so the cyclic recursion fixed-point is reachable.
///
/// The final `.common` is the `CommonCircuitData` we hand to
/// `conditionally_verify_cyclic_proof_or_dummy`. It encodes everything
/// the verifier needs to know about the circuit it's about to verify
/// (gate set, public-input count, FRI parameters).
///
/// **Why faithful-port and not the BitVM/zkCoins reference variant:**
/// BitVM was on Plonky2 0.2.0; its `common_data_for_recursion` used
/// 2–3 `verify_proof` calls per pass plus a `ConstantGate`. In
/// Plonky2 1.1.0 that shape no longer matches what
/// `conditionally_verify_cyclic_proof_or_dummy` produces, and the
/// outer `builder.build::<C>()` fails with "Failed to build circuit"
/// (gate-set / public-input shape mismatch). The 1.1.0 canonical
/// shape — one verify_proof + NoopGate padding to 2^12 — is what the
/// library's own tests use.
fn common_data_for_recursion_c() -> CommonCircuitData<F, D> {
    // Pass 1: empty seed circuit.
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    // Pass 2: verify the seed circuit once.
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    // Pass 3: verify once and pad to `INNER_PAD_BITS` gates with
    // NoopGate. The padding fixes the inner circuit's `degree_bits`
    // and MUST be ≥ ceil(log2(outer.num_gates)) for cyclic recursion
    // to build. Outer circuit size as of stage 5d-next-3 (full
    // production parameters):
    //   - 8 in-coin slots × ~512 SMT hashes ≈ 4 k
    //   - 8 out-coin slots × ~512 SMT hashes ≈ 4 k
    //   - 5c+ commitment proofs (SMT 256 + 2× MMR 31) ≈ 0.3 k
    //   - apply_coin + identifier derivation + 3 account-state hashes ≈ 0.2 k
    //   - cyclic-verify shape + NoopGate padding to power of 2
    // Total ≈ 8-10 k gates → `INNER_PAD_BITS = 14` (1 << 14 = 16384)
    // gives generous headroom.
    const INNER_PAD_BITS: usize = 14;
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << INNER_PAD_BITS {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}

/// Element-wise `select` over a `HashOutTarget`. Returns `if_true` if
/// `cond` is true, else `if_false`. Used to mask off conditional
/// constraints by retargetting `connect_hashes(computed, expected)` to
/// `connect_hashes(computed, select_hash(cond, expected_witness,
/// computed))` — when `cond = false` the resulting target collapses to
/// `computed` and the constraint is trivially satisfied.
fn select_hash(
    builder: &mut CircuitBuilder<F, D>,
    cond: BoolTarget,
    if_true: HashOutTarget,
    if_false: HashOutTarget,
) -> HashOutTarget {
    let mut out = [builder.zero(); 4];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = builder.select(cond, if_true.elements[i], if_false.elements[i]);
    }
    HashOutTarget { elements: out }
}

/// Witness targets for one out-coin slot. Each `StateTransitionCircuit`
/// reserves [`MAX_OUT_COINS`] of these and processes them after the
/// in-coins loop. An active slot:
/// - proves SMT non-inclusion of `out_coin_identifier` at the running
///   `output_coins_root` and computes the new root after inserting it;
/// - subtracts the coin's amount from the running balance with a
///   64-bit underflow check;
/// - asserts `out_coin_identifier == Poseidon(interim_asth ||
///   slot_index)` where `interim_asth` is the account-state hash
///   computed after the in-coins loop with the INITIAL pubkey
///   (mirroring the off-circuit `calculate_coin_identifier`).
///
/// Inactive slots are masked no-ops on all three constraints.
pub struct OutCoinSlotTargets {
    /// 1 → this slot is processed; 0 → no-op.
    pub active: BoolTarget,
    /// Coin's identifier. Must equal `Poseidon(interim_asth || index)`
    /// for an active slot; the in-circuit equality check is masked.
    pub out_coin_identifier: HashOutTarget,
    /// Lower 32 bits of the coin's amount.
    pub out_coin_amount_lo: Target,
    /// Upper 32 bits of the coin's amount.
    pub out_coin_amount_hi: Target,
    /// 256 SMT siblings proving non-inclusion of `out_coin_identifier`
    /// at the running `output_coins_root` *before* the insert.
    pub nip_path: Vec<HashOutTarget>,
}

/// Witness targets for one in-coin slot. Each `StateTransitionCircuit`
/// reserves [`MAX_IN_COINS`] of these and processes them in order; an
/// `active = false` slot is a no-op that passes both `coin_history_root`
/// and `account_state.balance` through unchanged.
///
/// Per SPEC §8 stage 5d (after the 5d-next apply_coin extension) wires
/// the **coin-history side** of the in-coins predicate (SMT
/// non-inclusion-then-insert) plus the per-coin `apply_coin` semantics
/// (`coin.recipient == account.owner` and a balance-overflow-checked
/// add). The source-side checks (recursive verification of the source
/// proof, SMT inclusion of `coin.identifier` in
/// `source.output_coins_root`, and SPEC §8 (c)(d)(e) for the source's
/// own commitment) are DEFERRED to stage 5d-next-3.
pub struct InCoinSlotTargets {
    /// 1 → this slot inserts `coin_identifier` into `coin_history_root`
    /// and applies the coin to the running balance.
    /// 0 → slot is a no-op (all in-circuit constraints masked off).
    pub active: BoolTarget,
    /// Coin's unique identifier. Used both as the SMT *key* (its 256
    /// bits select the leaf position) and the SMT *value* (so the
    /// coin_history SMT acts as a SET membership structure).
    pub coin_identifier: HashOutTarget,
    /// Recipient address the coin claims to be sent to. The
    /// `apply_coin` predicate enforces `recipient == account.owner` —
    /// only the owning account can absorb a coin. Masked by `active`.
    pub coin_recipient: HashOutTarget,
    /// Lower 32 bits of the coin's amount (u64 packed as 2× 32-bit
    /// limbs, matching the off-circuit `AccountState::hash` layout).
    pub coin_amount_lo: Target,
    /// Upper 32 bits of the coin's amount.
    pub coin_amount_hi: Target,
    /// 256 SMT siblings proving non-inclusion of `coin_identifier` at
    /// `coin_history_root` *before* the insert. The same path is then
    /// used to compute the new root after inserting the coin.
    pub nip_path: Vec<HashOutTarget>,
}

/// Witness targets for the SPEC §8 `CommitmentMerkleProofs` predicate,
/// bundled so they can be threaded through [`StateTransitionCircuit`]
/// and [`set_cmp_witness`] in one shot.
///
/// Sizes are pinned to the fixed-shape constants
/// ([`TREE_DEPTH`] for the SMT, [`MMR_PROOF_PATH_LEN`] for the MMR
/// proofs) so the verifier circuit has a stable `circuit_digest`.
pub struct CommitmentMerkleProofsTargets {
    /// SMT root containing the prev proof's commitment leaf.
    pub commitment_root: HashOutTarget,
    /// SMT key at which the commitment is stored (= hash of prev pubkey).
    pub smt_key: HashOutTarget,
    /// 256 sibling hashes along the SMT path (level 0 = topmost).
    pub smt_path: Vec<HashOutTarget>,
    /// MMR-proof (d) index: leaf position of `(commitment_root,
    /// commitment_root_mmr_sibling)` in the history MMR.
    pub mmr_a_index: Target,
    /// MMR-proof (d) path: 31 sibling hashes.
    pub mmr_a_path: Vec<HashOutTarget>,
    /// The previous MMR root at the time `commitment_root` was folded
    /// in — paired with `commitment_root` to form the MMR leaf for (d).
    pub commitment_root_mmr_sibling: HashOutTarget,
    /// The SMT root committed to the MMR alongside `prev.commitment_history_root`
    /// for proof (e).
    pub prev_smt_in_mmr_leaf: HashOutTarget,
    /// MMR-proof (e) index.
    pub mmr_b_index: Target,
    /// MMR-proof (e) path: 31 sibling hashes.
    pub mmr_b_path: Vec<HashOutTarget>,
    /// Witness for SPEC §8 (c): the account-state-hash committed to by
    /// the prev proof. Constrained to equal `account_state_hash`
    /// in-circuit (under `condition`).
    pub commitment_account_state_hash: HashOutTarget,
    /// Witness for the second half of the commitment preimage:
    /// `commitment = h(asth || ocr)`. Constrained implicitly by the
    /// SMT inclusion check — the commitment value computed in-circuit
    /// must match what the SMT stores.
    pub commitment_out_coins_root: HashOutTarget,
}

/// Handle to the built state-transition circuit plus the witness
/// targets a caller needs to populate when proving.
///
/// `data.verifier_only.circuit_digest` is the verifier-key digest that
/// gets pinned as a public input via [`Self::verifier_data_target`];
/// binding this digest is what makes the recursion *cyclic*: a proof of
/// this circuit can only be verified by this same circuit.
pub struct StateTransitionCircuit {
    /// Built circuit (proving + verification keys, common data).
    pub data: CircuitData<F, C, D>,
    /// Verifier shape that recursive inner proofs are checked against.
    /// Equal to `data.common` up to the cyclic-recursion fixed-point.
    pub common_data: CommonCircuitData<F, D>,
    /// Public-input slots reserved for the verifier-key digest +
    /// constants-sigmas cap (set via `set_verifier_data_target` each
    /// prove).
    pub verifier_data_target: VerifierCircuitTarget,
    /// Branch selector. `false` → Initial (dummy inner), `true` →
    /// AccountUpdate (real inner). Free witness as of Stage 5c.
    pub condition: BoolTarget,
    /// Inner proof slot. Initial uses [`cyclic_base_proof`] dummy;
    /// AccountUpdate uses a real prev `ProofWithPublicInputs`.
    pub inner_proof_target: ProofWithPublicInputsTarget<D>,
    /// 16 public-input slots for `ProofData::to_field_elements`.
    pub proof_data_pis: [Target; N_PROOF_DATA_PUBLIC_INPUTS],
    /// Witness target: `account_state.owner` (4 field elements).
    pub owner: HashOutTarget,
    /// Witness target: balance lower 32 bits.
    pub balance_lo: Target,
    /// Witness target: balance upper 32 bits.
    pub balance_hi: Target,
    /// Witness targets: 33-byte compressed pubkey packed as 5×56-bit
    /// limbs (the last limb holds the trailing 5 bytes + 3 zero pads).
    pub pubkey_limbs: [Target; 5],
    /// Witness target: the current commitment-history root.
    pub history_root: HashOutTarget,
    /// CommitmentMerkleProofs witness bundle. Constraints fire only
    /// when `condition = true` (AccountUpdate branch).
    pub cmp: CommitmentMerkleProofsTargets,
    /// `MAX_IN_COINS` in-coin slot witnesses processed in order.
    /// Active slots advance `coin_history_root` via SMT non-inclusion
    /// + insert; inactive slots pass it through unchanged.
    pub in_coin_slots: Vec<InCoinSlotTargets>,
    /// `MAX_OUT_COINS` out-coin slot witnesses processed in order
    /// after the in-coins loop. Active slots advance
    /// `output_coins_root` and subtract the coin amount from the
    /// running balance.
    pub out_coin_slots: Vec<OutCoinSlotTargets>,
    /// 5×56-bit limbs of the new account public key the proof rotates
    /// to. The FINAL `account_state_hash` (committed to `ProofData`)
    /// uses these limbs; `pubkey_limbs` (the INITIAL pubkey) is used
    /// only for SPEC §8 (b)+(c) checks and for the interim hash
    /// driving out-coin identifier derivation.
    pub next_public_key_limbs: [Target; 5],
}

/// Build the Stage-5c+ state-transition circuit.
///
/// Beyond the 5b/5c predicate, this revision wires SPEC §8 (c)(d)(e)
/// against fixed-shape SMT + MMR inclusion proofs. See module docstring
/// for the constraint breakdown and the masking pattern.
pub fn build_circuit() -> StateTransitionCircuit {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Regular public inputs first — must precede
    // `add_verifier_data_public_inputs` per Plonky2 contract.
    let proof_data_pis: [Target; N_PROOF_DATA_PUBLIC_INPUTS] =
        std::array::from_fn(|_| builder.add_virtual_public_input());

    let mut common_data = common_data_for_recursion_c();
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();

    let condition = builder.add_virtual_bool_target_safe();
    let inner_proof_target = builder.add_virtual_proof_with_pis(&common_data);

    // Extract prev's ProofData fields from the inner proof's PI slots.
    let prev_account_state_hash = HashOutTarget {
        elements: [
            inner_proof_target.public_inputs[0],
            inner_proof_target.public_inputs[1],
            inner_proof_target.public_inputs[2],
            inner_proof_target.public_inputs[3],
        ],
    };
    let prev_commitment_history_root = HashOutTarget {
        elements: [
            inner_proof_target.public_inputs[8],
            inner_proof_target.public_inputs[9],
            inner_proof_target.public_inputs[10],
            inner_proof_target.public_inputs[11],
        ],
    };
    let prev_coin_history_root = HashOutTarget {
        elements: [
            inner_proof_target.public_inputs[12],
            inner_proof_target.public_inputs[13],
            inner_proof_target.public_inputs[14],
            inner_proof_target.public_inputs[15],
        ],
    };

    // ===== Witness AccountState + history =====

    let owner = builder.add_virtual_hash();
    let balance_lo = builder.add_virtual_target();
    let balance_hi = builder.add_virtual_target();
    builder.range_check(balance_lo, 32);
    builder.range_check(balance_hi, 32);

    let pubkey_limbs: [Target; 5] = std::array::from_fn(|_| {
        let t = builder.add_virtual_target();
        builder.range_check(t, 56);
        t
    });

    let history_root = builder.add_virtual_hash();

    // is_minting = element-wise AND of (owner.elements[i] == MINTING_ADDRESS.elements[i]).
    let minting_addr = builder.constant_hash(HashOut {
        elements: MINTING_ADDRESS.elements,
    });
    let mut is_minting = builder._true();
    for i in 0..4 {
        let elem_eq = builder.is_equal(owner.elements[i], minting_addr.elements[i]);
        is_minting = builder.and(is_minting, elem_eq);
    }
    let not_minting = builder.not(is_minting);
    let not_condition = builder.not(condition);

    // Mint exception (Initial-only):
    let mint_mask = builder.mul(not_condition.target, not_minting.target);
    let mul_lo = builder.mul(mint_mask, balance_lo);
    builder.assert_zero(mul_lo);
    let mul_hi = builder.mul(mint_mask, balance_hi);
    builder.assert_zero(mul_hi);

    // Compute in-circuit account_state_hash. Layout per
    // AccountState::hash: owner (4) + balance_lo + balance_hi + pubkey (5).
    let mut state_elements: Vec<Target> = Vec::with_capacity(11);
    state_elements.extend_from_slice(&owner.elements);
    state_elements.push(balance_lo);
    state_elements.push(balance_hi);
    state_elements.extend_from_slice(&pubkey_limbs);
    let account_state_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(state_elements);

    // SPEC §8 (b) — state continuity (AccountUpdate-only):
    for i in 0..4 {
        let diff = builder.sub(
            account_state_hash.elements[i],
            prev_account_state_hash.elements[i],
        );
        let masked = builder.mul(condition.target, diff);
        builder.assert_zero(masked);
    }

    // ===== CommitmentMerkleProofs witness bundle =====

    let cmp = CommitmentMerkleProofsTargets {
        commitment_root: builder.add_virtual_hash(),
        smt_key: builder.add_virtual_hash(),
        smt_path: (0..TREE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect(),
        mmr_a_index: builder.add_virtual_target(),
        mmr_a_path: (0..MMR_PROOF_PATH_LEN)
            .map(|_| builder.add_virtual_hash())
            .collect(),
        commitment_root_mmr_sibling: builder.add_virtual_hash(),
        prev_smt_in_mmr_leaf: builder.add_virtual_hash(),
        mmr_b_index: builder.add_virtual_target(),
        mmr_b_path: (0..MMR_PROOF_PATH_LEN)
            .map(|_| builder.add_virtual_hash())
            .collect(),
        commitment_account_state_hash: builder.add_virtual_hash(),
        commitment_out_coins_root: builder.add_virtual_hash(),
    };

    // SPEC §8 (c): account_state_hash == cmp.commitment_account_state_hash,
    // masked with `condition`.
    for i in 0..4 {
        let diff = builder.sub(
            account_state_hash.elements[i],
            cmp.commitment_account_state_hash.elements[i],
        );
        let masked = builder.mul(condition.target, diff);
        builder.assert_zero(masked);
    }

    // SPEC §8 (d), first half: commitment = h(asth || ocr), SMT inclusion
    // of `commitment` at `smt_key` in `commitment_root`.
    let mut commitment_input = Vec::with_capacity(8);
    commitment_input.extend_from_slice(&cmp.commitment_account_state_hash.elements);
    commitment_input.extend_from_slice(&cmp.commitment_out_coins_root.elements);
    let commitment = builder.hash_n_to_hash_no_pad::<PoseidonHash>(commitment_input);

    let smt_key_bits = key_bits_msb_first(&mut builder, cmp.smt_key);
    let smt_computed_root = smt_inclusion_root(
        &mut builder,
        commitment,
        cmp.smt_key,
        &smt_key_bits,
        &cmp.smt_path,
    );
    let smt_target_root = select_hash(
        &mut builder,
        condition,
        cmp.commitment_root,
        smt_computed_root,
    );
    builder.connect_hashes(smt_computed_root, smt_target_root);

    // SPEC §8 (d), second half: MMR inclusion of
    // h(commitment_root || commitment_root_mmr_sibling) in history_root.
    let mut mmr_a_leaf_input = Vec::with_capacity(8);
    mmr_a_leaf_input.extend_from_slice(&cmp.commitment_root.elements);
    mmr_a_leaf_input.extend_from_slice(&cmp.commitment_root_mmr_sibling.elements);
    let mmr_a_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(mmr_a_leaf_input);
    let mmr_a_index_bits = builder.split_le(cmp.mmr_a_index, MMR_PROOF_PATH_LEN);
    let mmr_a_computed =
        mmr_inclusion_root(&mut builder, mmr_a_leaf, &mmr_a_index_bits, &cmp.mmr_a_path);
    let mmr_a_target = select_hash(&mut builder, condition, history_root, mmr_a_computed);
    builder.connect_hashes(mmr_a_computed, mmr_a_target);

    // SPEC §8 (e): MMR inclusion of
    // h(prev_smt_in_mmr_leaf || prev.commitment_history_root) in history_root.
    let mut mmr_b_leaf_input = Vec::with_capacity(8);
    mmr_b_leaf_input.extend_from_slice(&cmp.prev_smt_in_mmr_leaf.elements);
    mmr_b_leaf_input.extend_from_slice(&prev_commitment_history_root.elements);
    let mmr_b_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(mmr_b_leaf_input);
    let mmr_b_index_bits = builder.split_le(cmp.mmr_b_index, MMR_PROOF_PATH_LEN);
    let mmr_b_computed =
        mmr_inclusion_root(&mut builder, mmr_b_leaf, &mmr_b_index_bits, &cmp.mmr_b_path);
    let mmr_b_target = select_hash(&mut builder, condition, history_root, mmr_b_computed);
    builder.connect_hashes(mmr_b_computed, mmr_b_target);

    // Coin-history carry-over: starting value picks prev's
    // coin_history_root for AccountUpdate, empty SMT root for Initial.
    let empty_root = builder.constant_hash(DEFAULT_HASHES[0]);
    let empty_leaf_default = builder.constant_hash(DEFAULT_HASHES[TREE_DEPTH]);
    let mut running_coin_history_elements = [builder.zero(); 4];
    for (i, slot) in running_coin_history_elements.iter_mut().enumerate() {
        *slot = builder.select(
            condition,
            prev_coin_history_root.elements[i],
            empty_root.elements[i],
        );
    }
    let mut running_coin_history = HashOutTarget {
        elements: running_coin_history_elements,
    };

    // Per-slot in-coin processing. Each active slot:
    //   - proves SMT non-inclusion of `coin_identifier` at
    //     `running_coin_history` and inserts it (set-membership SMT);
    //   - asserts `coin_recipient == account.owner` (apply_coin);
    //   - adds `coin_amount` to the running balance with a 32-bit
    //     limb-by-limb add + carry, asserting no top-level overflow.
    // Inactive slots are masked no-ops on both `coin_history_root` and
    // `(balance_lo, balance_hi)`.
    let in_coin_slots: Vec<InCoinSlotTargets> = (0..MAX_IN_COINS)
        .map(|_| InCoinSlotTargets {
            active: builder.add_virtual_bool_target_safe(),
            coin_identifier: builder.add_virtual_hash(),
            coin_recipient: builder.add_virtual_hash(),
            coin_amount_lo: {
                let t = builder.add_virtual_target();
                builder.range_check(t, 32);
                t
            },
            coin_amount_hi: {
                let t = builder.add_virtual_target();
                builder.range_check(t, 32);
                t
            },
            nip_path: (0..TREE_DEPTH)
                .map(|_| builder.add_virtual_hash())
                .collect(),
        })
        .collect();

    // Running balance evolves through the slots; starts at the
    // witnessed `(balance_lo, balance_hi)` — which is INITIAL state
    // per SPEC §8 (the balance the prev proof committed to on
    // AccountUpdate, or the start balance on Initial).
    let mut running_balance_lo = balance_lo;
    let mut running_balance_hi = balance_hi;
    let two_pow_32 = builder.constant(F::from_canonical_u64(1u64 << 32));

    for slot in &in_coin_slots {
        let coin_id_bits = key_bits_msb_first(&mut builder, slot.coin_identifier);

        // --- Coin-history non-inclusion + insert (masked) ---
        let computed_old = hash_up_full_path(
            &mut builder,
            empty_leaf_default,
            &coin_id_bits,
            &slot.nip_path,
        );
        let target_old = select_hash(
            &mut builder,
            slot.active,
            running_coin_history,
            computed_old,
        );
        builder.connect_hashes(computed_old, target_old);

        let mut new_leaf_input = Vec::with_capacity(8);
        new_leaf_input.extend_from_slice(&slot.coin_identifier.elements);
        new_leaf_input.extend_from_slice(&slot.coin_identifier.elements);
        let new_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(new_leaf_input);
        let computed_new = hash_up_full_path(&mut builder, new_leaf, &coin_id_bits, &slot.nip_path);
        running_coin_history = select_hash(
            &mut builder,
            slot.active,
            computed_new,
            running_coin_history,
        );

        // --- Recipient check (masked) ---
        // `active * (coin_recipient[i] - owner[i]) == 0` for i in 0..4.
        for i in 0..4 {
            let diff = builder.sub(slot.coin_recipient.elements[i], owner.elements[i]);
            let masked = builder.mul(slot.active.target, diff);
            builder.assert_zero(masked);
        }

        // --- Balance addition with overflow check (masked) ---
        // u64 balance = balance_hi * 2^32 + balance_lo. Add active *
        // coin_amount via limb-by-limb with carry; assert top-level
        // overflow is zero. For inactive slots, masked_amount is 0 and
        // the carry/overflow bits settle to zero, leaving the running
        // balance unchanged.
        //
        // `split_le(sum, 33)` decomposes a value in [0, 2^33) into 33
        // bits; bits are auto-witnessed by Plonky2's `BaseSumGate`
        // generator. The high bit at index 32 is the carry / overflow.
        // We reconstitute `new_lo = sum_lo - 2^32 * carry` via
        // subtraction, which is exactly the low 32 bits of `sum_lo`.
        let active_t = slot.active.target;
        let masked_amount_lo = builder.mul(active_t, slot.coin_amount_lo);
        let masked_amount_hi = builder.mul(active_t, slot.coin_amount_hi);

        let sum_lo = builder.add(running_balance_lo, masked_amount_lo);
        let lo_bits = builder.split_le(sum_lo, 33);
        let carry = lo_bits[32];
        let carry_shifted = builder.mul(two_pow_32, carry.target);
        let new_lo = builder.sub(sum_lo, carry_shifted);

        let sum_hi_pre = builder.add(running_balance_hi, masked_amount_hi);
        let sum_hi = builder.add(sum_hi_pre, carry.target);
        let hi_bits = builder.split_le(sum_hi, 33);
        let overflow = hi_bits[32];
        let overflow_shifted = builder.mul(two_pow_32, overflow.target);
        let new_hi = builder.sub(sum_hi, overflow_shifted);
        // No top-level overflow allowed.
        builder.assert_zero(overflow.target);

        running_balance_lo = new_lo;
        running_balance_hi = new_hi;
    }

    let output_coin_history_root = running_coin_history;

    // ===== Out-coins processing =====
    //
    // Per SPEC §8 step 3, the out-coins loop:
    // 1. For each (out_coin, ncl_proof): verify non-inclusion in the
    //    running `output_coins_root`, insert the identifier, subtract
    //    the amount from the running balance with an underflow check.
    // 2. Compute `interim_asth = H(owner || running_balance ||
    //    pubkey_limbs)` — the account-state hash at this point, with
    //    the INITIAL pubkey (no rotation yet).
    // 3. For each (i, out_coin): assert `out_coin.identifier ==
    //    H(interim_asth || u32(i))`, mirroring the off-circuit
    //    `calculate_coin_identifier`.
    // 4. Rotate pubkey: the FINAL `account_state_hash` (= the public
    //    output) uses `next_public_key_limbs` in place of
    //    `pubkey_limbs`.
    //
    // All in-circuit checks are masked by each slot's `active` bit,
    // so an empty out-coins loop is a no-op (running root stays at
    // `DEFAULT_HASHES[0]`, balance unchanged, identifier check
    // trivially satisfied).

    let next_public_key_limbs: [Target; 5] = std::array::from_fn(|_| {
        let t = builder.add_virtual_target();
        builder.range_check(t, 56);
        t
    });

    let out_coin_slots: Vec<OutCoinSlotTargets> = (0..MAX_OUT_COINS)
        .map(|_| OutCoinSlotTargets {
            active: builder.add_virtual_bool_target_safe(),
            out_coin_identifier: builder.add_virtual_hash(),
            out_coin_amount_lo: {
                let t = builder.add_virtual_target();
                builder.range_check(t, 32);
                t
            },
            out_coin_amount_hi: {
                let t = builder.add_virtual_target();
                builder.range_check(t, 32);
                t
            },
            nip_path: (0..TREE_DEPTH)
                .map(|_| builder.add_virtual_hash())
                .collect(),
        })
        .collect();

    let mut running_output_coins_root = empty_root;

    for slot in &out_coin_slots {
        let id_bits = key_bits_msb_first(&mut builder, slot.out_coin_identifier);

        // --- SMT non-inclusion + insert into running_output_coins_root ---
        let computed_old =
            hash_up_full_path(&mut builder, empty_leaf_default, &id_bits, &slot.nip_path);
        let target_old = select_hash(
            &mut builder,
            slot.active,
            running_output_coins_root,
            computed_old,
        );
        builder.connect_hashes(computed_old, target_old);

        let mut new_leaf_input = Vec::with_capacity(8);
        new_leaf_input.extend_from_slice(&slot.out_coin_identifier.elements);
        new_leaf_input.extend_from_slice(&slot.out_coin_identifier.elements);
        let new_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(new_leaf_input);
        let computed_new = hash_up_full_path(&mut builder, new_leaf, &id_bits, &slot.nip_path);
        running_output_coins_root = select_hash(
            &mut builder,
            slot.active,
            computed_new,
            running_output_coins_root,
        );

        // --- Balance subtraction with underflow check (masked) ---
        // `balance_u64 = balance_hi * 2^32 + balance_lo` and same for
        // `amount_u64`. `diff = balance_u64 - active * amount_u64`
        // must be in `[0, 2^64)` — `split_le(diff, 64)` constrains
        // exactly that. When inactive, `active * amount = 0` so
        // `diff = balance_u64` (unchanged) and the bits trivially
        // decompose it.
        let balance_u64 = builder.mul_add(running_balance_hi, two_pow_32, running_balance_lo);
        let amount_lo_masked = builder.mul(slot.active.target, slot.out_coin_amount_lo);
        let amount_hi_masked = builder.mul(slot.active.target, slot.out_coin_amount_hi);
        let amount_u64 = builder.mul_add(amount_hi_masked, two_pow_32, amount_lo_masked);
        let diff = builder.sub(balance_u64, amount_u64);
        let diff_bits = builder.split_le(diff, 64);
        // Recompose into 32-bit halves. `le_sum` weights bits by
        // ascending powers of 2 starting at 0; the [0..32) slice gives
        // the low 32 bits and [0..32) of the [32..64) slice gives the
        // high half (also weighted from 2^0 because `le_sum` doesn't
        // know about offsets — that's the intended bottom-up sum).
        let new_lo = builder.le_sum(diff_bits[..32].iter());
        let new_hi = builder.le_sum(diff_bits[32..].iter());
        running_balance_lo = new_lo;
        running_balance_hi = new_hi;
    }

    let final_balance_lo = running_balance_lo;
    let final_balance_hi = running_balance_hi;

    // Interim account-state hash: owner + post-subtraction balance +
    // INITIAL pubkey. Drives out-coin identifier derivation.
    let mut interim_state_elements: Vec<Target> = Vec::with_capacity(11);
    interim_state_elements.extend_from_slice(&owner.elements);
    interim_state_elements.push(final_balance_lo);
    interim_state_elements.push(final_balance_hi);
    interim_state_elements.extend_from_slice(&pubkey_limbs);
    let interim_account_state_hash =
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(interim_state_elements);

    // Identifier derivation per out-coin slot.
    // Expected: out_coin.identifier == H(interim_asth || u32(slot_index))
    // (matches off-circuit [`crate::types::calculate_coin_identifier`]).
    // Masked by `active` so inactive slots' identifiers don't need to
    // match anything.
    for (i, slot) in out_coin_slots.iter().enumerate() {
        let i_const = builder.constant(F::from_canonical_u32(i as u32));
        let mut id_input = Vec::with_capacity(5);
        id_input.extend_from_slice(&interim_account_state_hash.elements);
        id_input.push(i_const);
        let computed_id = builder.hash_n_to_hash_no_pad::<PoseidonHash>(id_input);
        for j in 0..4 {
            let diff = builder.sub(
                slot.out_coin_identifier.elements[j],
                computed_id.elements[j],
            );
            let masked = builder.mul(slot.active.target, diff);
            builder.assert_zero(masked);
        }
    }

    // FINAL account-state hash: owner + post-subtraction balance + NEW
    // pubkey. Committed as `ProofData.account_state_hash`. If the
    // caller wants no rotation (e.g., Initial / Account-update without
    // out-coins), they set `next_public_key_limbs` to the same value
    // as `pubkey_limbs` and the final hash matches the initial-pubkey
    // hash.
    let mut final_state_elements: Vec<Target> = Vec::with_capacity(11);
    final_state_elements.extend_from_slice(&owner.elements);
    final_state_elements.push(final_balance_lo);
    final_state_elements.push(final_balance_hi);
    final_state_elements.extend_from_slice(&next_public_key_limbs);
    let final_account_state_hash =
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(final_state_elements);

    // Connect `ProofData` public inputs slot-by-slot.
    for i in 0..4 {
        builder.connect(proof_data_pis[i], final_account_state_hash.elements[i]);
        builder.connect(proof_data_pis[4 + i], running_output_coins_root.elements[i]);
        builder.connect(proof_data_pis[8 + i], history_root.elements[i]);
        builder.connect(proof_data_pis[12 + i], output_coin_history_root.elements[i]);
    }

    // Cyclic verification.
    builder
        .conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &inner_proof_target,
            &common_data,
        )
        .expect("conditionally_verify_cyclic_proof_or_dummy: common_data is well-formed by construction");

    let data = builder.build::<C>();
    StateTransitionCircuit {
        data,
        common_data,
        verifier_data_target,
        condition,
        inner_proof_target,
        proof_data_pis,
        owner,
        balance_lo,
        balance_hi,
        pubkey_limbs,
        history_root,
        cmp,
        in_coin_slots,
        out_coin_slots,
        next_public_key_limbs,
    }
}

/// Set the witnesses for the `AccountState` fields. Shared between
/// [`prove_initial`] and [`prove_account_update`] because both branches
/// witness the same fields in the same way.
fn set_account_state_witness(
    pw: &mut PartialWitness<F>,
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
) {
    pw.set_hash_target(circuit.owner, account_state.owner)
        .unwrap();

    let balance = account_state.balance;
    pw.set_target(
        circuit.balance_lo,
        F::from_canonical_u32((balance & 0xFFFF_FFFF) as u32),
    )
    .unwrap();
    pw.set_target(
        circuit.balance_hi,
        F::from_canonical_u32((balance >> 32) as u32),
    )
    .unwrap();

    for (i, chunk) in account_state.public_key.chunks(7).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        pw.set_target(
            circuit.pubkey_limbs[i],
            F::from_canonical_u64(u64::from_le_bytes(buf)),
        )
        .unwrap();
    }
}

/// Set the witnesses for the `CommitmentMerkleProofs` bundle.
///
/// Used by both proving paths:
/// - `prove_initial` calls this with a *dummy* `cmp` (typically
///   `CommitmentMerkleProofs::dummy()`), since the masked constraints
///   are trivially satisfied with `condition = false` for any witness.
/// - `prove_account_update` calls this with the real `cmp` matching
///   the prev proof and current history.
fn set_cmp_witness(
    pw: &mut PartialWitness<F>,
    circuit: &StateTransitionCircuit,
    cmp: &CommitmentMerkleProofs,
) {
    pw.set_hash_target(circuit.cmp.commitment_root, cmp.commitment_root)
        .unwrap();
    pw.set_hash_target(
        circuit.cmp.smt_key,
        digest_from_bytes(&cmp.commitment_proof.key),
    )
    .unwrap();
    assert_eq!(
        cmp.commitment_proof.siblings.len(),
        TREE_DEPTH,
        "CommitmentMerkleProofs: SMT inclusion proof must be padded to TREE_DEPTH siblings"
    );
    for (i, sib) in cmp.commitment_proof.siblings.iter().enumerate() {
        pw.set_hash_target(circuit.cmp.smt_path[i], *sib).unwrap();
    }
    pw.set_target(
        circuit.cmp.mmr_a_index,
        F::from_canonical_u32(cmp.commitment_root_history_proof.index),
    )
    .unwrap();
    assert_eq!(
        cmp.commitment_root_history_proof.path.len(),
        MMR_PROOF_PATH_LEN,
        "CommitmentMerkleProofs: MMR proof (d) must be extended to MMR_PROOF_PATH_LEN siblings"
    );
    for (i, sib) in cmp.commitment_root_history_proof.path.iter().enumerate() {
        pw.set_hash_target(circuit.cmp.mmr_a_path[i], *sib).unwrap();
    }
    pw.set_hash_target(
        circuit.cmp.commitment_root_mmr_sibling,
        cmp.commitment_root_mmr_sibling,
    )
    .unwrap();
    pw.set_hash_target(
        circuit.cmp.prev_smt_in_mmr_leaf,
        cmp.previous_root_history_proof.0,
    )
    .unwrap();
    pw.set_target(
        circuit.cmp.mmr_b_index,
        F::from_canonical_u32(cmp.previous_root_history_proof.1.index),
    )
    .unwrap();
    assert_eq!(
        cmp.previous_root_history_proof.1.path.len(),
        MMR_PROOF_PATH_LEN,
        "CommitmentMerkleProofs: MMR proof (e) must be extended to MMR_PROOF_PATH_LEN siblings"
    );
    for (i, sib) in cmp.previous_root_history_proof.1.path.iter().enumerate() {
        pw.set_hash_target(circuit.cmp.mmr_b_path[i], *sib).unwrap();
    }
    pw.set_hash_target(
        circuit.cmp.commitment_account_state_hash,
        cmp.commitment_account_state_hash,
    )
    .unwrap();
    pw.set_hash_target(
        circuit.cmp.commitment_out_coins_root,
        cmp.commitment_out_coins_root,
    )
    .unwrap();
}

/// Build a syntactically-valid but semantically-empty
/// `CommitmentMerkleProofs` for use as the dummy witness in
/// [`prove_initial`]. Every field gets a deterministic placeholder
/// (mostly `ZERO_HASH`); the masked constraints in the circuit ignore
/// the values when `condition = false`.
fn dummy_cmp() -> CommitmentMerkleProofs {
    use crate::merkle::merkle_mountain_range::MMRProof;
    use crate::merkle::sparse_merkle_tree::InclusionProof;
    CommitmentMerkleProofs {
        commitment_root: ZERO_HASH,
        commitment_proof: InclusionProof {
            key: [0u8; 32],
            siblings: vec![ZERO_HASH; TREE_DEPTH],
        },
        commitment_root_history_proof: MMRProof::new(vec![ZERO_HASH; MMR_PROOF_PATH_LEN], 0),
        commitment_root_mmr_sibling: ZERO_HASH,
        previous_root_history_proof: (
            ZERO_HASH,
            MMRProof::new(vec![ZERO_HASH; MMR_PROOF_PATH_LEN], 0),
        ),
        commitment_account_state_hash: ZERO_HASH,
        commitment_out_coins_root: ZERO_HASH,
    }
}

/// Set the witnesses for one in-coin slot. Used by both proving paths:
/// inactive slots get a dummy non-inclusion proof against an arbitrary
/// (zeroed) `coin_history_root` plus zero recipient/amount; the masked
/// checks are satisfied vacuously by the slot's `active = false` bit.
fn set_in_coin_slot_witness(
    pw: &mut PartialWitness<F>,
    slot: &InCoinSlotTargets,
    active: bool,
    coin_identifier: HashDigest,
    coin_recipient: HashDigest,
    coin_amount: u64,
    nip: &NonInclusionProof,
) {
    pw.set_bool_target(slot.active, active).unwrap();
    pw.set_hash_target(slot.coin_identifier, coin_identifier)
        .unwrap();
    pw.set_hash_target(slot.coin_recipient, coin_recipient)
        .unwrap();
    pw.set_target(
        slot.coin_amount_lo,
        F::from_canonical_u32((coin_amount & 0xFFFF_FFFF) as u32),
    )
    .unwrap();
    pw.set_target(
        slot.coin_amount_hi,
        F::from_canonical_u32((coin_amount >> 32) as u32),
    )
    .unwrap();
    assert_eq!(
        nip.siblings.len(),
        TREE_DEPTH,
        "InCoinSlot: non-inclusion proof must be padded to TREE_DEPTH siblings"
    );
    for (i, sib) in nip.siblings.iter().enumerate() {
        pw.set_hash_target(slot.nip_path[i], *sib).unwrap();
    }
}

/// Build a dummy `Coin` for populating inactive in-coin slot
/// witnesses. The slot's `active = false` bit masks off the
/// recipient and balance-update constraints, so the values are
/// irrelevant — `ZERO_HASH` identifier / `ZERO_HASH` recipient /
/// `amount = 0` is the cheapest placeholder.
fn dummy_coin() -> Coin {
    Coin {
        identifier: ZERO_HASH,
        recipient: ZERO_HASH,
        amount: 0,
    }
}

/// Set the witnesses for one out-coin slot. Inactive slots use the
/// `dummy_coin` + `dummy_non_inclusion_proof` placeholders.
fn set_out_coin_slot_witness(
    pw: &mut PartialWitness<F>,
    slot: &OutCoinSlotTargets,
    active: bool,
    out_coin_identifier: HashDigest,
    out_coin_amount: u64,
    nip: &NonInclusionProof,
) {
    pw.set_bool_target(slot.active, active).unwrap();
    pw.set_hash_target(slot.out_coin_identifier, out_coin_identifier)
        .unwrap();
    pw.set_target(
        slot.out_coin_amount_lo,
        F::from_canonical_u32((out_coin_amount & 0xFFFF_FFFF) as u32),
    )
    .unwrap();
    pw.set_target(
        slot.out_coin_amount_hi,
        F::from_canonical_u32((out_coin_amount >> 32) as u32),
    )
    .unwrap();
    assert_eq!(
        nip.siblings.len(),
        TREE_DEPTH,
        "OutCoinSlot: non-inclusion proof must be padded to TREE_DEPTH siblings"
    );
    for (i, sib) in nip.siblings.iter().enumerate() {
        pw.set_hash_target(slot.nip_path[i], *sib).unwrap();
    }
}

/// Set the witnesses for the rotated public key. Used by all prove
/// paths. If the caller doesn't want pubkey rotation (e.g., Initial
/// proof without out-coins), pass `account_state.public_key` to keep
/// the final `account_state_hash` aligned with the off-circuit
/// `AccountState::hash`.
fn set_next_public_key_witness(
    pw: &mut PartialWitness<F>,
    circuit: &StateTransitionCircuit,
    next_public_key: &PublicKey,
) {
    for (i, chunk) in next_public_key.chunks(7).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        pw.set_target(
            circuit.next_public_key_limbs[i],
            F::from_canonical_u64(u64::from_le_bytes(buf)),
        )
        .unwrap();
    }
}

/// Build a dummy `NonInclusionProof` for populating inactive in-coin
/// slot witnesses. Every sibling is `ZERO_HASH`; the slot's `active`
/// bit being `false` masks off the in-circuit checks regardless.
fn dummy_non_inclusion_proof() -> NonInclusionProof {
    NonInclusionProof {
        key: [0u8; 32],
        root: ZERO_HASH,
        siblings: vec![ZERO_HASH; TREE_DEPTH],
    }
}

/// Prove the Initial-branch state transition for a given `account_state`
/// and `history_root`.
///
/// All `MAX_IN_COINS` slots are populated with inactive dummies — Stage 5d
/// could in principle allow Init proofs to also receive in-coins (per
/// SPEC §8 the Initial branch falls through to the in-coins loop), but
/// the test fixtures here demonstrate only the empty-in-coins case.
/// To prove an Initial proof with active in-coin slots, use
/// [`prove_initial_with_in_coins`].
pub fn prove_initial(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let dummy_nip = dummy_non_inclusion_proof();
    let dummy_coin = dummy_coin();
    let inactive_slots: Vec<(bool, &Coin, &NonInclusionProof)> = (0..MAX_IN_COINS)
        .map(|_| (false, &dummy_coin, &dummy_nip))
        .collect();
    prove_initial_with_in_coins(circuit, account_state, history_root, &inactive_slots)
}

/// Like [`prove_initial`] but with caller-supplied in-coin slot
/// witnesses. Each tuple is `(active, &coin, &non_inclusion_proof)`;
/// the caller MUST supply exactly `MAX_IN_COINS` tuples. Inactive slots
/// can pass the [`dummy_coin`] / [`dummy_non_inclusion_proof`]
/// placeholders regardless of the current `coin_history_root` and
/// running balance — the slot's `active = false` bit masks all
/// in-circuit checks.
pub fn prove_initial_with_in_coins(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
) -> Result<ProofWithPublicInputs<F, C, D>> {
    assert_eq!(
        in_coins.len(),
        MAX_IN_COINS,
        "prove_initial_with_in_coins: caller must supply exactly MAX_IN_COINS slot witnesses"
    );
    let dummy_nip = dummy_non_inclusion_proof();
    let inactive_out_coins: Vec<(bool, HashDigest, u64, &NonInclusionProof)> = (0..MAX_OUT_COINS)
        .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
        .collect();
    prove_initial_with_in_and_out_coins(
        circuit,
        account_state,
        history_root,
        in_coins,
        &inactive_out_coins,
        &account_state.public_key,
    )
}

/// Like [`prove_initial`] but with caller-supplied in-coin AND
/// out-coin slot witnesses, plus an explicit `next_public_key` the
/// account rotates to. Each `out_coins` tuple is
/// `(active, out_coin_identifier, amount, &non_inclusion_proof)`.
/// The caller MUST supply exactly `MAX_IN_COINS` in-coin tuples and
/// exactly `MAX_OUT_COINS` out-coin tuples.
pub fn prove_initial_with_in_and_out_coins(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
    out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
    next_public_key: &PublicKey,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    assert_eq!(
        in_coins.len(),
        MAX_IN_COINS,
        "prove_initial_with_in_and_out_coins: caller must supply exactly MAX_IN_COINS in-coin slot witnesses"
    );
    assert_eq!(
        out_coins.len(),
        MAX_OUT_COINS,
        "prove_initial_with_in_and_out_coins: caller must supply exactly MAX_OUT_COINS out-coin slot witnesses"
    );
    let mut pw = PartialWitness::new();
    pw.set_bool_target(circuit.condition, false).unwrap();
    set_account_state_witness(&mut pw, circuit, account_state);
    pw.set_hash_target(circuit.history_root, history_root)
        .unwrap();
    set_cmp_witness(&mut pw, circuit, &dummy_cmp());
    for (slot_targets, (active, coin, nip)) in circuit.in_coin_slots.iter().zip(in_coins.iter()) {
        set_in_coin_slot_witness(
            &mut pw,
            slot_targets,
            *active,
            coin.identifier,
            coin.recipient,
            coin.amount,
            nip,
        );
    }
    for (slot_targets, (active, identifier, amount, nip)) in
        circuit.out_coin_slots.iter().zip(out_coins.iter())
    {
        set_out_coin_slot_witness(&mut pw, slot_targets, *active, *identifier, *amount, nip);
    }
    set_next_public_key_witness(&mut pw, circuit, next_public_key);

    // Dummy inner proof for the cyclic-recursion slot.
    let inner_pis = std::iter::empty::<(usize, F)>().collect();
    pw.set_proof_with_pis_target::<C, D>(
        &circuit.inner_proof_target,
        &cyclic_base_proof(&circuit.common_data, &circuit.data.verifier_only, inner_pis),
    )
    .unwrap();
    pw.set_verifier_data_target(&circuit.verifier_data_target, &circuit.data.verifier_only)
        .unwrap();

    circuit.data.prove(pw)
}

/// Prove an AccountUpdate transition consuming `prev` as the recursive
/// inner proof plus a [`CommitmentMerkleProofs`] witnessing that `prev`
/// is published in the global history at `history_root`.
///
/// The proof's history-side fields (SMT inclusion path, MMR inclusion
/// paths) must be pre-padded to the fixed shape the circuit expects:
/// - `commitment_proof.siblings.len() == TREE_DEPTH = 256`
/// - `commitment_root_history_proof.path.len() == MMR_PROOF_PATH_LEN = 31`
/// - `previous_root_history_proof.1.path.len() == MMR_PROOF_PATH_LEN = 31`
///
/// The `history_root` parameter must be
/// `mmr.root_extended(MMR_PROOF_PATH_LEN)` for the same MMR depth
/// (see [`crate::merkle::merkle_mountain_range::MerkleMountainRange::root_extended`]).
pub fn prove_account_update(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    prev: &ProofWithPublicInputs<F, C, D>,
    cmp: &CommitmentMerkleProofs,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let dummy_nip = dummy_non_inclusion_proof();
    let dummy_coin = dummy_coin();
    let inactive_slots: Vec<(bool, &Coin, &NonInclusionProof)> = (0..MAX_IN_COINS)
        .map(|_| (false, &dummy_coin, &dummy_nip))
        .collect();
    prove_account_update_with_in_coins(
        circuit,
        account_state,
        history_root,
        prev,
        cmp,
        &inactive_slots,
    )
}

/// Like [`prove_account_update`] but with caller-supplied in-coin slot
/// witnesses. See [`prove_initial_with_in_coins`] for the contract on
/// the `in_coins` slice.
pub fn prove_account_update_with_in_coins(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    prev: &ProofWithPublicInputs<F, C, D>,
    cmp: &CommitmentMerkleProofs,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
) -> Result<ProofWithPublicInputs<F, C, D>> {
    assert_eq!(
        in_coins.len(),
        MAX_IN_COINS,
        "prove_account_update_with_in_coins: caller must supply exactly MAX_IN_COINS slot witnesses"
    );
    let dummy_nip = dummy_non_inclusion_proof();
    let inactive_out_coins: Vec<(bool, HashDigest, u64, &NonInclusionProof)> = (0..MAX_OUT_COINS)
        .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
        .collect();
    prove_account_update_with_in_and_out_coins(
        circuit,
        account_state,
        history_root,
        prev,
        cmp,
        in_coins,
        &inactive_out_coins,
        &account_state.public_key,
    )
}

/// Like [`prove_account_update`] but with caller-supplied in-coin AND
/// out-coin slot witnesses, plus an explicit `next_public_key`.
#[allow(clippy::too_many_arguments)]
pub fn prove_account_update_with_in_and_out_coins(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    prev: &ProofWithPublicInputs<F, C, D>,
    cmp: &CommitmentMerkleProofs,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
    out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
    next_public_key: &PublicKey,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    assert_eq!(
        in_coins.len(),
        MAX_IN_COINS,
        "prove_account_update_with_in_and_out_coins: caller must supply exactly MAX_IN_COINS in-coin slot witnesses"
    );
    assert_eq!(
        out_coins.len(),
        MAX_OUT_COINS,
        "prove_account_update_with_in_and_out_coins: caller must supply exactly MAX_OUT_COINS out-coin slot witnesses"
    );
    let mut pw = PartialWitness::new();
    pw.set_bool_target(circuit.condition, true).unwrap();
    set_account_state_witness(&mut pw, circuit, account_state);
    pw.set_hash_target(circuit.history_root, history_root)
        .unwrap();
    set_cmp_witness(&mut pw, circuit, cmp);
    for (slot_targets, (active, coin, nip)) in circuit.in_coin_slots.iter().zip(in_coins.iter()) {
        set_in_coin_slot_witness(
            &mut pw,
            slot_targets,
            *active,
            coin.identifier,
            coin.recipient,
            coin.amount,
            nip,
        );
    }
    for (slot_targets, (active, identifier, amount, nip)) in
        circuit.out_coin_slots.iter().zip(out_coins.iter())
    {
        set_out_coin_slot_witness(&mut pw, slot_targets, *active, *identifier, *amount, nip);
    }
    set_next_public_key_witness(&mut pw, circuit, next_public_key);
    pw.set_proof_with_pis_target::<C, D>(&circuit.inner_proof_target, prev)
        .unwrap();
    pw.set_verifier_data_target(&circuit.verifier_data_target, &circuit.data.verifier_only)
        .unwrap();

    circuit.data.prove(pw)
}

/// Verify a state-transition proof, including the cross-check that its
/// embedded verifier-data digest matches the circuit's own.
pub fn verify(
    circuit: &StateTransitionCircuit,
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<()> {
    check_cyclic_proof_verifier_data(proof, &circuit.data.verifier_only, &circuit.data.common)?;
    circuit.data.verify(proof.clone())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{digest_to_bytes, hash_bytes, hash_concat};
    use crate::inputs::CommitmentMerkleProofs;
    use crate::merkle::merkle_mountain_range::MerkleMountainRange;
    use crate::merkle::sparse_merkle_tree::SparseMerkleTree;
    use crate::types::ProofData;

    fn dummy_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        for (i, b) in pk.iter_mut().enumerate().skip(1) {
            *b = seed.wrapping_add(i as u8);
        }
        pk
    }

    fn pis_as_proof_data(proof: &ProofWithPublicInputs<F, C, D>) -> ProofData {
        let pis: [F; N_PROOF_DATA_PUBLIC_INPUTS] = proof.public_inputs
            [..N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .unwrap();
        ProofData::from_field_elements(&pis)
    }

    /// Test helper: build a `MAX_IN_COINS`-length slot array with the
    /// first slot active (`(true, coin, nip)`) and all remaining slots
    /// inactive (`(false, dummy_coin, dummy_nip)`). Callers must pin
    /// the dummy values in local variables so their references outlive
    /// the returned vector.
    fn slots_first_active<'a>(
        coin: &'a Coin,
        nip: &'a NonInclusionProof,
        dummy_coin: &'a Coin,
        dummy_nip: &'a NonInclusionProof,
    ) -> Vec<(bool, &'a Coin, &'a NonInclusionProof)> {
        let mut v = Vec::with_capacity(MAX_IN_COINS);
        v.push((true, coin, nip));
        for _ in 1..MAX_IN_COINS {
            v.push((false, dummy_coin, dummy_nip));
        }
        v
    }

    /// Stage 5c+ Initial-side smoke test (unchanged behaviour from 5c):
    /// a non-mint account with `balance = 0` is accepted, and the
    /// public-input `ProofData` matches the off-circuit reconstruction.
    /// The CommitmentMerkleProofs witness is the empty dummy.
    #[test]
    fn stage_5c_plus_initial_non_mint_zero_balance_accepted() {
        let circuit = build_circuit();
        let account_state = AccountState::new(dummy_pubkey(7));
        assert_ne!(account_state.owner, *MINTING_ADDRESS);

        let history_root = hash_bytes(b"history@5c+-init");
        let proof = prove_initial(&circuit, &account_state, history_root).expect("prove initial");
        verify(&circuit, &proof).expect("verify initial");

        let recovered = pis_as_proof_data(&proof);
        assert_eq!(recovered.account_state_hash, account_state.hash());
        assert_eq!(recovered.coin_history_root, DEFAULT_HASHES[0]);
    }

    /// Mint exception under the masked predicate.
    #[test]
    fn stage_5c_plus_initial_mint_with_balance_accepted() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(99));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 21_000_000_000_000;

        let history_root = hash_bytes(b"history@5c+-mint");
        let proof = prove_initial(&circuit, &account_state, history_root).expect("prove mint");
        verify(&circuit, &proof).expect("verify mint");
    }

    /// Mint-exception negative.
    #[test]
    fn stage_5c_plus_initial_non_mint_nonzero_balance_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(7));
        assert_ne!(account_state.owner, *MINTING_ADDRESS);
        account_state.balance = 1;

        let history_root = hash_bytes(b"history@5c+-illegal");
        assert!(prove_initial(&circuit, &account_state, history_root).is_err());
    }

    /// Build a `CommitmentMerkleProofs` witness for an Initial → AccountUpdate
    /// chain on the same account state.
    ///
    /// The off-circuit setup mirrors what the server scanner would do:
    /// 1. Build the commitment value `c = h(asth || ocr)` for the prev proof.
    /// 2. Build the SMT containing `(pk_hash → c)`.
    /// 3. Fold the SMT root into the history MMR alongside the empty prev
    ///    MMR root.
    /// 4. Build extended MMR proofs (a) and (e) at depth
    ///    `MMR_PROOF_PATH_LEN`.
    ///
    /// Returns `(cmp, extended_history_root)`.
    fn build_test_commitment_witness(
        prev_asth: HashDigest,
        prev_ocr: HashDigest,
    ) -> (CommitmentMerkleProofs, HashDigest) {
        // SMT key derived from the prev pubkey hash (placeholder bytes).
        let pk_hash = hash_bytes(b"5c+-test-pubkey");
        let pk_key = digest_to_bytes(&pk_hash);

        // Commitment value committed to in the SMT.
        let commitment = hash_concat(&prev_asth, &prev_ocr);

        let mut smt = SparseMerkleTree::new();
        smt.insert(pk_key, commitment).unwrap();
        let smt_root = smt.root();
        let (smt_inclusion, _) = smt.generate_inclusion_proof(&pk_key).unwrap();

        // History MMR: fold `(smt_root, ZERO_HASH)` as the first leaf.
        // The bootstrap pattern: Init was proved against the empty
        // history (`prev.commitment_history_root == ZERO_HASH`), so the
        // (e) MMR leaf `h(smt_root || prev.commitment_history_root)`
        // coincides with the (d) MMR leaf `h(smt_root || prev_mmr_root)`.
        // Both MMR proofs point to the same MMR leaf at index 0.
        let prev_mmr_root = ZERO_HASH;
        let mmr_leaf = hash_concat(&smt_root, &prev_mmr_root);
        let mut mmr = MerkleMountainRange::new();
        mmr.append(mmr_leaf);
        let history_root_extended = mmr.root_extended(MMR_PROOF_PATH_LEN);
        let mmr_proof = mmr.get_proof(0).unwrap().extend_to(MMR_PROOF_PATH_LEN);
        assert!(mmr_proof.verify(mmr_leaf, history_root_extended));

        let cmp = CommitmentMerkleProofs {
            commitment_root: smt_root,
            commitment_proof: smt_inclusion,
            commitment_root_history_proof: mmr_proof.clone(),
            commitment_root_mmr_sibling: prev_mmr_root,
            previous_root_history_proof: (smt_root, mmr_proof),
            commitment_account_state_hash: prev_asth,
            commitment_out_coins_root: prev_ocr,
        };
        (cmp, history_root_extended)
    }

    /// Primary 5c+ positive test: an Initial → AccountUpdate chain with a
    /// real `CommitmentMerkleProofs` witness. The prev proof's commitment
    /// is published in the SMT, the SMT is folded into the MMR, and the
    /// AccountUpdate proof verifies the (c)(d)(e) chain in-circuit.
    #[test]
    fn stage_5c_plus_initial_then_account_update_with_commitment_proofs() {
        let circuit = build_circuit();

        // Initial proof: mint account.
        let mut account_state = AccountState::new(dummy_pubkey(11));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1_000_000;

        // Bootstrap pattern: Init commits to the EMPTY history
        // (`prev.commitment_history_root == ZERO_HASH`); after Init the
        // server folds its commitment into the MMR, giving the
        // post-fold `history_root_extended` against which Update is
        // proved. The fixture matches that exact layout — (e)'s leaf
        // shape `h(smt_root || ZERO_HASH)` coincides with (d)'s leaf.
        let prev_asth = account_state.hash();
        let prev_ocr = DEFAULT_HASHES[0];
        let (cmp, history_root_extended) = build_test_commitment_witness(prev_asth, prev_ocr);

        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");
        verify(&circuit, &init_proof).expect("verify init");

        let update_proof = prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
        )
        .expect("prove update");
        verify(&circuit, &update_proof).expect("verify update");

        // Carry-over: update.coin_history_root == init.coin_history_root.
        let init_pd = pis_as_proof_data(&init_proof);
        let update_pd = pis_as_proof_data(&update_proof);
        assert_eq!(update_pd.coin_history_root, init_pd.coin_history_root);
        assert_eq!(update_pd.account_state_hash, account_state.hash());
        assert_eq!(update_pd.commitment_history_root, history_root_extended);
    }

    /// Stage 5c+ negative: AccountUpdate where the current account_state
    /// hashes to something different from prev's `account_state_hash` →
    /// rejected by (b).
    #[test]
    fn stage_5c_plus_account_update_state_discontinuity_rejected() {
        let circuit = build_circuit();

        let mut prev_state = AccountState::new(dummy_pubkey(42));
        prev_state.owner = *MINTING_ADDRESS;
        prev_state.balance = 500;

        let prev_asth = prev_state.hash();
        let (cmp, history_root_extended) =
            build_test_commitment_witness(prev_asth, DEFAULT_HASHES[0]);
        let prev_proof = prove_initial(&circuit, &prev_state, ZERO_HASH).expect("prove prev init");

        // Try to update with a DIFFERENT account_state.
        let mut next_state = prev_state.clone();
        next_state.balance += 1;
        assert!(prove_account_update(
            &circuit,
            &next_state,
            history_root_extended,
            &prev_proof,
            &cmp
        )
        .is_err());
    }

    /// Stage 5c+ negative (c): AccountUpdate where mp.commitment_account_state_hash
    /// is lied about so it no longer matches `account_state.hash()`.
    #[test]
    fn stage_5c_plus_account_update_wrong_commitment_account_state_hash_rejected() {
        let circuit = build_circuit();

        let mut account_state = AccountState::new(dummy_pubkey(123));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;

        let true_asth = account_state.hash();
        let (mut cmp, history_root_extended) =
            build_test_commitment_witness(true_asth, DEFAULT_HASHES[0]);

        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");

        // Mutate ONLY the witnessed commitment_account_state_hash; leave
        // the SMT (which still contains the honest commitment) intact.
        // (c) catches the mismatch via the masked equality constraint.
        cmp.commitment_account_state_hash = hash_bytes(b"lying-asth");

        assert!(prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp
        )
        .is_err());
    }

    /// Build-time assertion: `set_cmp_witness` rejects a `cmp` whose
    /// SMT inclusion proof is short of `TREE_DEPTH` siblings — the
    /// in-circuit gadget is built against a fixed 256-level shape, so
    /// a malformed witness would silently skip levels.
    #[test]
    #[should_panic(expected = "SMT inclusion proof must be padded to TREE_DEPTH siblings")]
    fn stage_5c_plus_set_cmp_witness_panics_on_short_smt_path() {
        let circuit = build_circuit();
        let mut cmp = dummy_cmp();
        cmp.commitment_proof.siblings.truncate(TREE_DEPTH - 1);
        let mut pw = PartialWitness::new();
        set_cmp_witness(&mut pw, &circuit, &cmp);
    }

    /// Build-time assertion: `set_cmp_witness` rejects a `cmp` whose
    /// MMR (d) path is short of `MMR_PROOF_PATH_LEN` siblings.
    #[test]
    #[should_panic(expected = "MMR proof (d) must be extended to MMR_PROOF_PATH_LEN siblings")]
    fn stage_5c_plus_set_cmp_witness_panics_on_short_mmr_a_path() {
        let circuit = build_circuit();
        let mut cmp = dummy_cmp();
        cmp.commitment_root_history_proof
            .path
            .truncate(MMR_PROOF_PATH_LEN - 1);
        let mut pw = PartialWitness::new();
        set_cmp_witness(&mut pw, &circuit, &cmp);
    }

    /// Build-time assertion: `set_cmp_witness` rejects a `cmp` whose
    /// MMR (e) path is short of `MMR_PROOF_PATH_LEN` siblings.
    #[test]
    #[should_panic(expected = "MMR proof (e) must be extended to MMR_PROOF_PATH_LEN siblings")]
    fn stage_5c_plus_set_cmp_witness_panics_on_short_mmr_b_path() {
        let circuit = build_circuit();
        let mut cmp = dummy_cmp();
        cmp.previous_root_history_proof
            .1
            .path
            .truncate(MMR_PROOF_PATH_LEN - 1);
        let mut pw = PartialWitness::new();
        set_cmp_witness(&mut pw, &circuit, &cmp);
    }

    /// Stage 5d positive: Initial proof with one active in-coin slot.
    /// The slot inserts `coin_identifier` into the (initially empty)
    /// coin_history SMT and applies the coin (recipient = owner,
    /// balance += amount). The output `ProofData` must match the
    /// off-circuit results: `coin_history_root` equals
    /// `nip.insert(coin_identifier)`; `account_state_hash` equals the
    /// hash of the FINAL state (initial balance + coin.amount).
    #[test]
    fn stage_5d_initial_with_one_active_in_coin() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(11));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;

        let history_root = hash_bytes(b"history@5d-in-coin");

        // Off-circuit non-inclusion proof for `coin_identifier` in the
        // empty SMT (root = DEFAULT_HASHES[0]).
        let coin_identifier = hash_bytes(b"5d-coin-1");
        let coin_key = digest_to_bytes(&coin_identifier);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();
        assert!(nip.verify(), "off-circuit non-inclusion sanity");
        let expected_new_coin_history = nip.insert(coin_identifier);

        // Coin with recipient = account.owner and a small amount that
        // can't overflow the running balance.
        let coin = Coin {
            identifier: coin_identifier,
            recipient: account_state.owner,
            amount: 42,
        };
        let mut final_account_state = account_state.clone();
        final_account_state.balance += coin.amount;

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&coin, &nip, &dummy_c, &dummy_nip);
        let proof = prove_initial_with_in_coins(&circuit, &account_state, history_root, &in_coins)
            .expect("prove init with in-coin");
        verify(&circuit, &proof).expect("verify");

        let recovered = pis_as_proof_data(&proof);
        assert_eq!(recovered.coin_history_root, expected_new_coin_history);
        assert_eq!(recovered.account_state_hash, final_account_state.hash());
    }

    /// Stage 5d negative: a tampered non-inclusion path on an active
    /// slot must fail to prove (the `connect_hashes(computed_old,
    /// running)` constraint rejects).
    #[test]
    fn stage_5d_initial_with_tampered_nip_path_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(11));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;

        let coin_identifier = hash_bytes(b"5d-tampered");
        let coin_key = digest_to_bytes(&coin_identifier);
        let empty_smt = SparseMerkleTree::new();
        let mut nip = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();
        // Tamper a sibling — the recomputed root won't match
        // `DEFAULT_HASHES[0]` and the in-circuit check fires.
        nip.siblings[0] = hash_bytes(b"lying-sibling");

        let coin = Coin {
            identifier: coin_identifier,
            recipient: account_state.owner,
            amount: 0,
        };
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&coin, &nip, &dummy_c, &dummy_nip);
        assert!(prove_initial_with_in_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
        )
        .is_err());
    }

    /// Stage 5d apply_coin negative: an in-coin with `recipient !=
    /// account.owner` is rejected by the recipient-equality
    /// constraint.
    #[test]
    fn stage_5d_initial_in_coin_wrong_recipient_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(11));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;

        let coin_identifier = hash_bytes(b"5d-wrong-recipient");
        let coin_key = digest_to_bytes(&coin_identifier);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();

        let coin = Coin {
            identifier: coin_identifier,
            // Lie: this coin is addressed to a different account.
            recipient: hash_bytes(b"some-other-owner"),
            amount: 1,
        };
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&coin, &nip, &dummy_c, &dummy_nip);
        assert!(prove_initial_with_in_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
        )
        .is_err());
    }

    /// Stage 5d apply_coin negative: adding a coin whose amount would
    /// overflow `u64` is rejected by the balance-overflow-check.
    #[test]
    fn stage_5d_initial_in_coin_overflow_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(11));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = u64::MAX;

        let coin_identifier = hash_bytes(b"5d-overflow");
        let coin_key = digest_to_bytes(&coin_identifier);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();

        let coin = Coin {
            identifier: coin_identifier,
            recipient: account_state.owner,
            // u64::MAX + 1 overflows.
            amount: 1,
        };
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&coin, &nip, &dummy_c, &dummy_nip);
        assert!(prove_initial_with_in_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
        )
        .is_err());
    }

    /// Test helper: build a `MAX_OUT_COINS`-length out-coin slot
    /// array with the first slot active (`(true, identifier, amount,
    /// nip)`) and the rest inactive.
    fn out_slots_first_active<'a>(
        identifier: HashDigest,
        amount: u64,
        nip: &'a NonInclusionProof,
        dummy_nip: &'a NonInclusionProof,
    ) -> Vec<(bool, HashDigest, u64, &'a NonInclusionProof)> {
        let mut v = Vec::with_capacity(MAX_OUT_COINS);
        v.push((true, identifier, amount, nip));
        for _ in 1..MAX_OUT_COINS {
            v.push((false, ZERO_HASH, 0u64, dummy_nip));
        }
        v
    }

    /// Stage 5d-next-3 positive: Initial proof emits one out-coin.
    /// The interim account-state hash (post in-coins, before pubkey
    /// rotation) drives `out_coin_identifier = H(interim_asth || 0)`.
    /// Output `ProofData`:
    /// - `account_state_hash` is the FINAL hash (with the rotated
    ///   pubkey and the post-subtraction balance);
    /// - `output_coins_root` is the SMT after inserting the
    ///   out-coin's identifier;
    /// - `coin_history_root` is `DEFAULT_HASHES[0]` (no in-coins).
    #[test]
    fn stage_5d_next_3_initial_with_one_active_out_coin() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(21));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 100;

        // Per SPEC §8 `send_coins`, the interim account-state hash
        // (used for identifier derivation) is computed AFTER balance
        // subtractions but BEFORE pubkey rotation. So for an out-coin
        // amount of 30, the interim balance is 70 and the interim
        // pubkey is the INITIAL one.
        let out_coin_amount: u64 = 30;
        let mut interim_account_state = account_state.clone();
        interim_account_state.balance -= out_coin_amount;
        let interim_asth = interim_account_state.hash();
        let expected_out_id = crate::types::calculate_coin_identifier(interim_asth, 0);

        // Off-circuit: non-inclusion of expected_out_id in empty SMT.
        let out_id_key = digest_to_bytes(&expected_out_id);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();
        let expected_out_root = nip.insert(expected_out_id);

        // Rotate pubkey: next_public_key chosen by the prover.
        let next_pubkey = dummy_pubkey(122);

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect::<Vec<_>>();
        let out_coins = out_slots_first_active(expected_out_id, out_coin_amount, &nip, &dummy_nip);

        let history_root = hash_bytes(b"history@5d-next-3-out");
        let proof = prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            history_root,
            &in_coins,
            &out_coins,
            &next_pubkey,
        )
        .expect("prove init with out-coin");
        verify(&circuit, &proof).expect("verify");

        let recovered = pis_as_proof_data(&proof);

        // FINAL account_state: balance = 100 - 30 = 70, with rotated pubkey.
        let mut final_account_state = interim_account_state.clone();
        final_account_state.public_key = next_pubkey;
        assert_eq!(recovered.account_state_hash, final_account_state.hash());
        assert_eq!(recovered.output_coins_root, expected_out_root);
        assert_eq!(recovered.coin_history_root, DEFAULT_HASHES[0]);
        assert_eq!(recovered.commitment_history_root, history_root);
    }

    /// Stage 5d-next-3 negative: out-coin whose `identifier` does not
    /// equal `H(interim_asth || index)` is rejected by the masked
    /// identifier-equality constraint.
    #[test]
    fn stage_5d_next_3_initial_out_coin_wrong_identifier_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(22));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 100;

        // A lying identifier that is NOT `H(interim_asth || 0)`.
        let lying_id = hash_bytes(b"5d-next-3-lying-out-id");
        let out_id_key = digest_to_bytes(&lying_id);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect::<Vec<_>>();
        let out_coins = out_slots_first_active(lying_id, 1, &nip, &dummy_nip);

        let next_pubkey = account_state.public_key;
        assert!(prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
            &out_coins,
            &next_pubkey,
        )
        .is_err());
    }

    /// Stage 5d-next-3 negative: out-coin amount exceeding the
    /// account balance is rejected by the underflow check.
    #[test]
    fn stage_5d_next_3_initial_out_coin_underflow_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(23));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 5; // less than the requested out-coin amount

        // Compute the expected identifier so identifier-eq passes; the
        // underflow check is what should fire.
        let interim_asth = account_state.hash();
        let expected_out_id = crate::types::calculate_coin_identifier(interim_asth, 0);
        let out_id_key = digest_to_bytes(&expected_out_id);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect::<Vec<_>>();
        let out_coins = out_slots_first_active(expected_out_id, 10, &nip, &dummy_nip);

        let next_pubkey = account_state.public_key;
        assert!(prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
            &out_coins,
            &next_pubkey,
        )
        .is_err());
    }

    /// Build-time assertion: `set_out_coin_slot_witness` rejects a
    /// non-inclusion proof of the wrong length.
    #[test]
    #[should_panic(
        expected = "OutCoinSlot: non-inclusion proof must be padded to TREE_DEPTH siblings"
    )]
    fn stage_5d_next_3_set_out_coin_slot_witness_panics_on_short_nip_path() {
        let circuit = build_circuit();
        let mut nip = dummy_non_inclusion_proof();
        nip.siblings.truncate(TREE_DEPTH - 1);
        let mut pw = PartialWitness::new();
        set_out_coin_slot_witness(
            &mut pw,
            &circuit.out_coin_slots[0],
            true,
            ZERO_HASH,
            0,
            &nip,
        );
    }

    /// Build-time assertion: out-coin slot count guard on
    /// `prove_initial_with_in_and_out_coins`.
    #[test]
    #[should_panic(
        expected = "prove_initial_with_in_and_out_coins: caller must supply exactly MAX_OUT_COINS out-coin slot witnesses"
    )]
    fn stage_5d_next_3_prove_initial_panics_on_wrong_out_slot_count() {
        let circuit = build_circuit();
        let account_state = AccountState::new(dummy_pubkey(7));
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect::<Vec<_>>();
        let _ = prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            ZERO_HASH,
            &in_coins,
            &[], // 0 out-coin slots, expected MAX_OUT_COINS
            &account_state.public_key,
        );
    }

    /// Build-time assertion: in-coin slot count guard on
    /// `prove_initial_with_in_and_out_coins`.
    #[test]
    #[should_panic(
        expected = "prove_initial_with_in_and_out_coins: caller must supply exactly MAX_IN_COINS in-coin slot witnesses"
    )]
    fn stage_5d_next_3_prove_initial_panics_on_wrong_in_slot_count() {
        let circuit = build_circuit();
        let account_state = AccountState::new(dummy_pubkey(7));
        let dummy_nip = dummy_non_inclusion_proof();
        let out_coins = (0..MAX_OUT_COINS)
            .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
            .collect::<Vec<_>>();
        let _ = prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            ZERO_HASH,
            &[], // 0 in-coin slots, expected MAX_IN_COINS
            &out_coins,
            &account_state.public_key,
        );
    }

    /// Build-time assertion: in-coin slot count guard on
    /// `prove_account_update_with_in_and_out_coins`.
    #[test]
    #[should_panic(
        expected = "prove_account_update_with_in_and_out_coins: caller must supply exactly MAX_IN_COINS in-coin slot witnesses"
    )]
    fn stage_5d_next_3_prove_account_update_panics_on_wrong_in_slot_count() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(8));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;
        let (cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");
        let dummy_nip = dummy_non_inclusion_proof();
        let out_coins = (0..MAX_OUT_COINS)
            .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
            .collect::<Vec<_>>();
        let _ = prove_account_update_with_in_and_out_coins(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            &[], // wrong: expected MAX_IN_COINS
            &out_coins,
            &account_state.public_key,
        );
    }

    /// Build-time assertion: out-coin slot count guard on
    /// `prove_account_update_with_in_and_out_coins`.
    #[test]
    #[should_panic(
        expected = "prove_account_update_with_in_and_out_coins: caller must supply exactly MAX_OUT_COINS out-coin slot witnesses"
    )]
    fn stage_5d_next_3_prove_account_update_panics_on_wrong_out_slot_count() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(9));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;
        let (cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect::<Vec<_>>();
        let _ = prove_account_update_with_in_and_out_coins(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            &in_coins,
            &[], // wrong: expected MAX_OUT_COINS
            &account_state.public_key,
        );
    }

    /// Build-time assertion: `set_in_coin_slot_witness` rejects a
    /// non-inclusion proof of the wrong length — the in-circuit gadget
    /// expects exactly `TREE_DEPTH` siblings.
    #[test]
    #[should_panic(
        expected = "InCoinSlot: non-inclusion proof must be padded to TREE_DEPTH siblings"
    )]
    fn stage_5d_set_in_coin_slot_witness_panics_on_short_nip_path() {
        let circuit = build_circuit();
        let mut nip = dummy_non_inclusion_proof();
        nip.siblings.truncate(TREE_DEPTH - 1);
        let mut pw = PartialWitness::new();
        set_in_coin_slot_witness(
            &mut pw,
            &circuit.in_coin_slots[0],
            true,
            ZERO_HASH,
            ZERO_HASH,
            0,
            &nip,
        );
    }

    /// Build-time assertion: `prove_initial_with_in_coins` rejects a
    /// caller that doesn't supply exactly `MAX_IN_COINS` slot witnesses.
    #[test]
    #[should_panic(
        expected = "prove_initial_with_in_coins: caller must supply exactly MAX_IN_COINS slot witnesses"
    )]
    fn stage_5d_prove_initial_panics_on_wrong_slot_count() {
        let circuit = build_circuit();
        let account_state = AccountState::new(dummy_pubkey(7));
        let _ = prove_initial_with_in_coins(
            &circuit,
            &account_state,
            ZERO_HASH,
            &[], // 0 slots, expected MAX_IN_COINS = 1
        );
    }

    /// Build-time assertion: `prove_account_update_with_in_coins`
    /// rejects a caller that doesn't supply exactly `MAX_IN_COINS`
    /// slot witnesses.
    #[test]
    #[should_panic(
        expected = "prove_account_update_with_in_coins: caller must supply exactly MAX_IN_COINS slot witnesses"
    )]
    fn stage_5d_prove_account_update_panics_on_wrong_slot_count() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(11));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;
        let (cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");
        let _ = prove_account_update_with_in_coins(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            &[], // 0 slots, expected MAX_IN_COINS = 1
        );
    }

    /// Stage 5e (SPEC §13): tampered MMR-(d) path — proof that the
    /// commitment_root sits in `history_root` is invalid. The
    /// in-circuit check rejects.
    #[test]
    fn stage_5e_account_update_tampered_mmr_a_path_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(31));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;

        let (mut cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");
        cmp.commitment_root_history_proof.path[0] = hash_bytes(b"lying-mmr-a-sib");
        assert!(prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp
        )
        .is_err());
    }

    /// Stage 5e (SPEC §13): tampered MMR-(e) path — proof that prev's
    /// committed history is a prefix of `history_root` is invalid.
    #[test]
    fn stage_5e_account_update_tampered_mmr_b_path_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(32));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;

        let (mut cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");
        cmp.previous_root_history_proof.1.path[0] = hash_bytes(b"lying-mmr-b-sib");
        assert!(prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp
        )
        .is_err());
    }

    /// Stage 5e (SPEC §13): wrong `commitment_root_mmr_sibling` — the
    /// MMR-(d) leaf no longer hashes to the witnessed `commitment_root`
    /// path, so the MMR-(d) verification fails.
    #[test]
    fn stage_5e_account_update_wrong_mmr_sibling_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(33));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;

        let (mut cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");
        cmp.commitment_root_mmr_sibling = hash_bytes(b"lying-prev-mmr-root");
        assert!(prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp
        )
        .is_err());
    }

    /// Stage 5e (SPEC §13): AccountUpdate proved against a
    /// `history_root` that the real MMR does not match. With (d)+(e)
    /// wired, both MMR proofs would have to reconstruct to the lying
    /// `history_root` — they can't, so the proof fails.
    #[test]
    fn stage_5e_account_update_wrong_history_root_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(34));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;

        let (cmp, _real_history_root) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");
        // Lie about the history_root — neither MMR proof reconstructs to it.
        let lying_history_root = hash_bytes(b"lying-history");
        assert!(prove_account_update(
            &circuit,
            &account_state,
            lying_history_root,
            &init_proof,
            &cmp
        )
        .is_err());
    }

    /// Stage 5d-next-3 integration: a single Initial proof that
    /// exercises BOTH the in-coins AND the out-coins loops in one
    /// transition. Validates the full SPEC §8 flow composes
    /// correctly:
    ///
    /// 1. Mint account with initial balance 100.
    /// 2. One active in-coin (id `i1`, amount 30, recipient = owner)
    ///    — running balance becomes 130, coin_history advances.
    /// 3. One active out-coin (id derived from the
    ///    *interim* account-state hash, amount 50, sent to a
    ///    rotated pubkey) — running balance becomes 80,
    ///    output_coins_root advances.
    /// 4. Final `ProofData.account_state_hash` reflects the rotated
    ///    pubkey and balance 80.
    #[test]
    fn stage_5d_next_3_initial_combined_in_and_out_coin() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(60));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 100;

        // ===== In-coin side =====
        let in_coin_id = hash_bytes(b"5d-combined-in");
        let in_coin_key = digest_to_bytes(&in_coin_id);
        let empty_smt = SparseMerkleTree::new();
        let in_nip = empty_smt.generate_non_inclusion_proof(in_coin_key).unwrap();
        let in_coin = Coin {
            identifier: in_coin_id,
            recipient: account_state.owner,
            amount: 30,
        };
        let expected_coin_history_root = in_nip.insert(in_coin_id);

        // ===== Out-coin side =====
        // Post-in-coins, pre-out-coin balance is 130; the in-circuit
        // running balance subtracts 50 → 80; interim_asth uses balance
        // 80 + INITIAL pubkey.
        let out_coin_amount: u64 = 50;
        let mut interim_account_state = account_state.clone();
        interim_account_state.balance = account_state.balance + in_coin.amount - out_coin_amount;
        let interim_asth = interim_account_state.hash();
        let expected_out_id = crate::types::calculate_coin_identifier(interim_asth, 0);

        let out_id_key = digest_to_bytes(&expected_out_id);
        let out_nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();
        let expected_output_coins_root = out_nip.insert(expected_out_id);

        let next_pubkey = dummy_pubkey(160);

        // ===== Slot arrays =====
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&in_coin, &in_nip, &dummy_c, &dummy_nip);
        let out_coins =
            out_slots_first_active(expected_out_id, out_coin_amount, &out_nip, &dummy_nip);

        let history_root = hash_bytes(b"history@5d-combined");
        let proof = prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            history_root,
            &in_coins,
            &out_coins,
            &next_pubkey,
        )
        .expect("prove init combined");
        verify(&circuit, &proof).expect("verify");

        let recovered = pis_as_proof_data(&proof);

        // FINAL account_state: balance = 80, pubkey = next_pubkey.
        let mut final_account_state = interim_account_state.clone();
        final_account_state.public_key = next_pubkey;
        assert_eq!(recovered.account_state_hash, final_account_state.hash());
        assert_eq!(recovered.output_coins_root, expected_output_coins_root);
        assert_eq!(recovered.commitment_history_root, history_root);
        assert_eq!(recovered.coin_history_root, expected_coin_history_root);
    }

    /// Stage 5d-next-3 integration: AccountUpdate proof that uses
    /// BOTH the in-coins AND out-coins loops on top of an Init prev.
    /// Mirrors `stage_5d_next_3_initial_combined_in_and_out_coin` but
    /// exercises the cyclic-recursion path (`condition = true`) +
    /// the SPEC §8 (c)(d)(e) CommitmentMerkleProofs chain alongside
    /// the apply_coin and send_coins logic.
    #[test]
    fn stage_5d_next_3_account_update_combined_in_and_out_coin() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(61));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 100;

        let (cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");
        verify(&circuit, &init_proof).expect("verify init");

        let in_coin_id = hash_bytes(b"5d-combined-update-in");
        let in_coin_key = digest_to_bytes(&in_coin_id);
        let empty_smt = SparseMerkleTree::new();
        let in_nip = empty_smt.generate_non_inclusion_proof(in_coin_key).unwrap();
        let in_coin = Coin {
            identifier: in_coin_id,
            recipient: account_state.owner,
            amount: 30,
        };
        let expected_coin_history_root = in_nip.insert(in_coin_id);

        let out_coin_amount: u64 = 50;
        let mut interim_account_state = account_state.clone();
        interim_account_state.balance =
            account_state.balance + in_coin.amount - out_coin_amount;
        let interim_asth = interim_account_state.hash();
        let expected_out_id = crate::types::calculate_coin_identifier(interim_asth, 0);
        let out_id_key = digest_to_bytes(&expected_out_id);
        let out_nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();
        let expected_output_coins_root = out_nip.insert(expected_out_id);

        let next_pubkey = dummy_pubkey(161);

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&in_coin, &in_nip, &dummy_c, &dummy_nip);
        let out_coins =
            out_slots_first_active(expected_out_id, out_coin_amount, &out_nip, &dummy_nip);

        let update_proof = prove_account_update_with_in_and_out_coins(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            &in_coins,
            &out_coins,
            &next_pubkey,
        )
        .expect("prove account_update combined");
        verify(&circuit, &update_proof).expect("verify update");

        let recovered = pis_as_proof_data(&update_proof);
        let mut final_account_state = interim_account_state.clone();
        final_account_state.public_key = next_pubkey;
        assert_eq!(recovered.account_state_hash, final_account_state.hash());
        assert_eq!(recovered.output_coins_root, expected_output_coins_root);
        assert_eq!(recovered.commitment_history_root, history_root_extended);
        assert_eq!(recovered.coin_history_root, expected_coin_history_root);
    }

    /// Stage 5e SPEC §13 — double-spend: two active in-coin slots
    /// presenting the SAME `coin_identifier`. The first slot inserts
    /// into the coin_history SMT successfully. The second slot's
    /// non-inclusion proof must be against the post-first-insert
    /// root, but the coin IS now in that root, so any non-inclusion
    /// proof against it is necessarily invalid — the in-circuit
    /// `connect_hashes(computed_old, running)` check catches the lie.
    #[test]
    fn stage_5e_double_spend_same_coin_twice_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(50));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 100;

        // First in-coin: non-inclusion in empty SMT.
        let coin_id = hash_bytes(b"5e-double-spend");
        let coin_key = digest_to_bytes(&coin_id);
        let empty_smt = SparseMerkleTree::new();
        let nip1 = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();

        // Pretend-second in-coin: SAME identifier. The honest prover
        // can't generate a non-inclusion proof against the
        // post-first-insert root (the coin IS there now), so we
        // supply the SAME proof as `nip1`. That proof is valid for
        // the pre-insert (empty) root but invalid for the
        // post-insert running root — the in-circuit check fires on
        // slot 2 because `computed_old == empty_root` but
        // `running_coin_history` has advanced to the post-insert
        // root.
        let coin1 = Coin {
            identifier: coin_id,
            recipient: account_state.owner,
            amount: 1,
        };
        let coin2 = Coin {
            identifier: coin_id,
            recipient: account_state.owner,
            amount: 1,
        };
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let mut in_coins: Vec<(bool, &Coin, &NonInclusionProof)> = Vec::with_capacity(MAX_IN_COINS);
        in_coins.push((true, &coin1, &nip1));
        in_coins.push((true, &coin2, &nip1));
        for _ in 2..MAX_IN_COINS {
            in_coins.push((false, &dummy_c, &dummy_nip));
        }

        assert!(prove_initial_with_in_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
        )
        .is_err());
    }

    /// Stage 5c+ negative (d): AccountUpdate where the SMT inclusion path
    /// has been tampered with. (d) catches it via `connect_hashes`.
    #[test]
    fn stage_5c_plus_account_update_tampered_smt_path_rejected() {
        let circuit = build_circuit();

        let mut account_state = AccountState::new(dummy_pubkey(77));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1;

        let true_asth = account_state.hash();
        let (mut cmp, history_root_extended) =
            build_test_commitment_witness(true_asth, DEFAULT_HASHES[0]);

        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH).expect("prove init");

        // Tamper a sibling deep in the SMT path — the computed
        // commitment_root will differ from the witnessed one.
        cmp.commitment_proof.siblings[0] = hash_bytes(b"lying-sibling");

        assert!(prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp
        )
        .is_err());
    }
}
