//! Monolithic state-transition circuit for zkCoins (Plonky2 backend).
//!
//! Mirrors `program/src/main.rs` (the SP1 entrypoint), but built as a
//! Plonky2 cyclic-recursive circuit per [`SPEC.md`] §8 / §10 and the
//! `ROADMAP.md` Step 5 plan.
//!
//! ## Stage status
//!
//! - **5a — recursion plumbing PoC**: done in commit `83fa0c1`,
//!   superseded by 5b. Counter payload, `condition`-toggled cycle.
//! - **5b — Initial branch with real predicate**: done in commit
//!   `d167237`. 16-element `ProofData` payload, in-circuit Poseidon
//!   `AccountState::hash`, mint exception, `condition` pinned `false`.
//! - **5c — AccountUpdate branch** ✅ this revision. `condition` is
//!   free; when `true`, the `conditionally_verify_cyclic_proof_or_dummy`
//!   call binds the inner proof to *this* circuit (SPEC §8 (a)). The
//!   inner proof's `ProofData` public inputs are extracted from
//!   `inner_proof_target.public_inputs[0..16]` and used to enforce
//!   state continuity (SPEC §8 (b): `H(account_state) ==
//!   prev.account_state_hash`) and `coin_history` carry-over
//!   (`output.coin_history_root == prev.coin_history_root`). The mint
//!   exception is masked with `!condition` so it only applies to
//!   Initial proofs. **NOT YET WIRED:** SPEC §8 (c)(d)(e) — the
//!   `CommitmentMerkleProofs` predicate that proves the prev proof was
//!   published in the global history MMR. Without (c)(d)(e), a
//!   malicious prover could craft an account-update chain on top of a
//!   `prev` that was never published. Stage 5c+ closes this gap with
//!   in-circuit SMT + MMR inclusion proofs of `CommitmentMerkleProofs`.
//! - **5c+ / 5d / 5e** — see ROADMAP "In Progress" section.
//!
//! ## What the AccountUpdate branch enforces today (Stage 5c)
//!
//! Per SPEC §8 the AccountUpdate proof's predicate is:
//!
//! ```text
//! prev := verify_proof(inputs.prev_proof_public_values, vk)
//! assert vk == prev.vk                          // (a) — cyclic_verify
//! assert account_state.hash() == prev.account_state_hash    // (b) — wired
//! mp := inputs.prev_proof_history_proofs
//! assert account_state.hash() == mp.commitment_account_state_hash  // (c) — DEFERRED to 5c+
//! assert mp.verify_commitment(history_root)                        // (d) — DEFERRED to 5c+
//! assert mp.verify_previous_root(prev.commitment_history_root, history_root)  // (e) — DEFERRED to 5c+
//! output.coin_history_root := prev.coin_history_root
//! ```
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
//! ## Branch selection via `condition`
//!
//! `condition` is now a witnessed `BoolTarget` (not pinned). Convention:
//! - `false` → Initial branch (no prior proof; dummy in inner slot)
//! - `true`  → AccountUpdate branch (real prev proof in inner slot)
//!
//! The two-branch output selection uses `builder.select(condition,
//! account_update_value, initial_value)` for `coin_history_root`. The
//! mint-exception constraint is masked with `!condition` so it only
//! applies to Initial. The state-continuity constraint is masked with
//! `condition` so it only applies to AccountUpdate.
//!
//! ## Range-checks on witnessed limbs
//!
//! `account_state.balance` and `account_state.public_key` are packed
//! into field elements off-circuit via
//! [`crate::types::AccountState::hash`] using fixed limb widths
//! (32-bit halves for balance, 56-bit chunks for the 33-byte pubkey).
//! The in-circuit version range-checks each witnessed limb to the same
//! bound — without that, a malicious prover could supply out-of-range
//! limbs that compute a perfectly valid `account_state_hash` but cannot
//! be reproduced by the off-circuit `AccountState::hash`. The
//! range-checks make in-circuit and off-circuit hashes provably agree.

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

use crate::merkle::sparse_merkle_tree::DEFAULT_HASHES;
use crate::types::{AccountState, MINTING_ADDRESS};
use crate::{C, D, F};

/// Public-input count carried by the `ProofData` payload:
/// `4 (account_state_hash) + 4 (output_coins_root) + 4 (commitment_history_root) + 4 (coin_history_root)`.
///
/// Mirrors [`crate::types::ProofData::to_field_elements`]'s output length;
/// the verifier-data slots added by `add_verifier_data_public_inputs`
/// follow these and are not counted here.
pub const N_PROOF_DATA_PUBLIC_INPUTS: usize = 16;

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

    // Pass 3: verify once and pad to 2^12 gates with NoopGate. This is
    // the gate-set shape `conditionally_verify_cyclic_proof_or_dummy`
    // expects in Plonky2 1.1.0.
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << 12 {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
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
}

/// Build the Stage-5c state-transition circuit.
///
/// Layout:
/// - 16 public inputs (`ProofData::to_field_elements`), registered before
///   `add_verifier_data_public_inputs()` per the Plonky2 API contract.
/// - Verifier-data public inputs (4 hash elements + cap), added by
///   `add_verifier_data_public_inputs()`.
/// - One inner proof target (dummy or real per `condition`).
///
/// Constraints:
/// 1. **Public-input layout.** The 16 `ProofData` slots get connected
///    to the in-circuit computed values per the table in the module
///    docstring.
/// 2. **Mint exception (Initial-only).** `!condition * !is_minting *
///    balance_limb == 0` for each balance limb. Folding two booleans
///    into one mask: `init_and_not_minting = (1 - condition) *
///    (1 - is_minting)`. Then `init_and_not_minting * balance_limb ==
///    0`.
/// 3. **State continuity (AccountUpdate-only).** `condition *
///    (account_state_hash[i] - prev_account_state_hash[i]) == 0` for
///    each of the 4 hash elements. When `condition = false`, the
///    constraint is trivially satisfied; the dummy inner proof's
///    public_inputs[0..4] are unconstrained so prev can be anything.
/// 4. **Coin-history carry-over.** Output's `coin_history_root` =
///    `select(condition, prev.coin_history_root, DEFAULT_HASHES[0])`.
/// 5. **Cyclic verification.** `conditionally_verify_cyclic_proof_or_dummy`
///    binds vk via `circuit_digest`; this is SPEC §8 (a).
///
/// Returns the built circuit unconditionally. Per [`MIGRATION_RESEARCH.md`]
/// §7.13 the `Result<()>` from `conditionally_verify_cyclic_proof_or_dummy`
/// is `.expect()`-ed because its only Err path is malformed
/// `common_data`, which is impossible here (we construct `common_data`
/// via the three-pass helper).
pub fn build_circuit() -> StateTransitionCircuit {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Regular public inputs first — must precede
    // `add_verifier_data_public_inputs` per Plonky2 contract.
    let proof_data_pis: [Target; N_PROOF_DATA_PUBLIC_INPUTS] =
        std::array::from_fn(|_| builder.add_virtual_public_input());

    // Build common_data BEFORE add_verifier_data_public_inputs, then
    // pin num_public_inputs AFTER, matching Plonky2 1.1.0's own
    // `recursion::cyclic_recursion::tests::test_cyclic_recursion`.
    let mut common_data = common_data_for_recursion_c();
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();

    // Stage 5c: `condition` is a free witness. Caller passes `true`
    // for AccountUpdate (real prev proof) or `false` for Initial
    // (dummy inner).
    let condition = builder.add_virtual_bool_target_safe();
    let inner_proof_target = builder.add_virtual_proof_with_pis(&common_data);

    // Extract prev's ProofData public inputs from the inner proof's
    // public-input slots. Slot layout matches our own (we verify
    // *this* circuit recursively).
    let prev_account_state_hash = HashOutTarget {
        elements: [
            inner_proof_target.public_inputs[0],
            inner_proof_target.public_inputs[1],
            inner_proof_target.public_inputs[2],
            inner_proof_target.public_inputs[3],
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

    // Mint exception (Initial-only): mask = (!condition) AND (!is_minting).
    // Implemented as multiplication of the boolean targets — both are
    // {0, 1} so the product is {0, 1}.
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

    // State continuity (AccountUpdate-only):
    // `condition * (account_state_hash[i] - prev_account_state_hash[i]) == 0`.
    for i in 0..4 {
        let diff = builder.sub(
            account_state_hash.elements[i],
            prev_account_state_hash.elements[i],
        );
        let masked = builder.mul(condition.target, diff);
        builder.assert_zero(masked);
    }

    // Coin-history carry-over: output is `prev.coin_history_root` when
    // condition=true, else `DEFAULT_HASHES[0]`.
    let empty_root = builder.constant_hash(DEFAULT_HASHES[0]);
    let mut output_coin_history_root_elements = [builder.zero(); 4];
    for (i, slot) in output_coin_history_root_elements.iter_mut().enumerate() {
        *slot = builder.select(
            condition,
            prev_coin_history_root.elements[i],
            empty_root.elements[i],
        );
    }
    let output_coin_history_root = HashOutTarget {
        elements: output_coin_history_root_elements,
    };

    // Connect `ProofData` public inputs slot-by-slot.
    for i in 0..4 {
        builder.connect(proof_data_pis[i], account_state_hash.elements[i]);
        builder.connect(proof_data_pis[4 + i], empty_root.elements[i]);
        builder.connect(proof_data_pis[8 + i], history_root.elements[i]);
        builder.connect(proof_data_pis[12 + i], output_coin_history_root.elements[i]);
    }

    // Cyclic verification: binds the inner proof to *this* circuit's
    // `circuit_digest` when condition=true; passes through a dummy
    // when condition=false.
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

/// Prove the Initial-branch state transition for a given `account_state`
/// and `history_root`.
///
/// Sets `condition = false`, supplies a [`cyclic_base_proof`] dummy in
/// the inner-proof slot, and runs the prover.
///
/// On success the proof's public inputs are
/// [`crate::types::ProofData::to_field_elements`] with
/// `account_state_hash = account_state.hash()`,
/// `output_coins_root = coin_history_root = DEFAULT_HASHES[0]`, and
/// `commitment_history_root = history_root`.
pub fn prove_initial(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashOut<F>,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = PartialWitness::new();
    pw.set_bool_target(circuit.condition, false).unwrap();
    set_account_state_witness(&mut pw, circuit, account_state);
    pw.set_hash_target(circuit.history_root, history_root)
        .unwrap();

    // Dummy inner proof. Initial reads no inner public inputs in
    // Stage 5c (prev is masked out by condition=false), so empty seed.
    // `cyclic_base_proof` consumes `hashbrown::HashMap`; `.collect()`
    // infers the right type from the function signature.
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
/// inner proof.
///
/// Sets `condition = true`. The cyclic-verification machinery enforces
/// that `prev` was generated by *this same circuit* (SPEC §8 (a)).
/// Stage 5c additionally enforces:
/// - **(b)** state continuity: `account_state.hash() ==
///   prev.public_inputs[0..4]`.
/// - **coin_history carry-over**: the output ProofData's
///   `coin_history_root` equals `prev.public_inputs[12..16]`.
///
/// Stage 5c does NOT enforce SPEC §8 (c)(d)(e) — the
/// `CommitmentMerkleProofs` predicate proving `prev` was published in
/// the global history MMR. That landed in Stage 5c+ (see module
/// docstring).
pub fn prove_account_update(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashOut<F>,
    prev: &ProofWithPublicInputs<F, C, D>,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = PartialWitness::new();
    pw.set_bool_target(circuit.condition, true).unwrap();
    set_account_state_witness(&mut pw, circuit, account_state);
    pw.set_hash_target(circuit.history_root, history_root)
        .unwrap();
    pw.set_proof_with_pis_target::<C, D>(&circuit.inner_proof_target, prev)
        .unwrap();
    pw.set_verifier_data_target(&circuit.verifier_data_target, &circuit.data.verifier_only)
        .unwrap();

    circuit.data.prove(pw)
}

/// Verify a state-transition proof, including the cross-check that its
/// embedded verifier-data digest matches the circuit's own.
///
/// Wraps [`check_cyclic_proof_verifier_data`] (binds the proof to
/// *this* circuit, not just any circuit with compatible common data)
/// and [`CircuitData::verify`] (the standard Plonky2 verification path).
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
    use crate::hash::hash_bytes;
    use crate::types::ProofData;

    fn dummy_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02; // compressed even-y prefix
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

    /// Stage 5c smoke test for the Initial branch: a non-mint account
    /// with `balance = 0` is accepted. Same shape as the 5b test but
    /// with `condition` now a free witness rather than pinned.
    #[test]
    fn stage_5c_initial_non_mint_zero_balance_accepted() {
        let circuit = build_circuit();
        let account_state = AccountState::new(dummy_pubkey(7));
        assert_ne!(account_state.owner, *MINTING_ADDRESS);

        let history_root = hash_bytes(b"history@5c-init");
        let proof = prove_initial(&circuit, &account_state, history_root).expect("prove initial");
        verify(&circuit, &proof).expect("verify initial");

        let recovered = pis_as_proof_data(&proof);
        let expected = ProofData {
            account_state_hash: account_state.hash(),
            output_coins_root: DEFAULT_HASHES[0],
            commitment_history_root: history_root,
            coin_history_root: DEFAULT_HASHES[0],
        };
        assert_eq!(recovered, expected);
    }

    /// Stage 5c mint exception: an account whose `owner ==
    /// MINTING_ADDRESS` may carry any starting balance.
    #[test]
    fn stage_5c_initial_mint_with_balance_accepted() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(99));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 21_000_000_000_000;

        let history_root = hash_bytes(b"history@5c-mint");
        let proof = prove_initial(&circuit, &account_state, history_root).expect("prove mint");
        verify(&circuit, &proof).expect("verify mint");

        let recovered = pis_as_proof_data(&proof);
        assert_eq!(recovered.account_state_hash, account_state.hash());
        assert_eq!(recovered.coin_history_root, DEFAULT_HASHES[0]);
    }

    /// Stage 5c negative: non-mint account with balance != 0 → rejected
    /// (mint exception still binds in the Initial branch).
    #[test]
    fn stage_5c_initial_non_mint_nonzero_balance_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(7));
        assert_ne!(account_state.owner, *MINTING_ADDRESS);
        account_state.balance = 1;

        let history_root = hash_bytes(b"history@5c-illegal");
        assert!(prove_initial(&circuit, &account_state, history_root).is_err());
    }

    /// Stage 5c primary test: an Initial → AccountUpdate chain. Builds a
    /// minting Initial proof, then proves an AccountUpdate that keeps the
    /// same `account_state` (state continuity holds) and verifies the
    /// resulting recursive proof. The recursive proof's
    /// `coin_history_root` must equal the prev's (carry-over).
    #[test]
    fn stage_5c_initial_then_account_update_chain() {
        let circuit = build_circuit();

        // Initial proof: mint account with non-zero balance.
        let mut account_state = AccountState::new(dummy_pubkey(11));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 1_000_000;

        let history_root = hash_bytes(b"history@5c-chain");
        let init_proof = prove_initial(&circuit, &account_state, history_root).expect("prove init");
        verify(&circuit, &init_proof).expect("verify init");

        // AccountUpdate: same account_state (continuity), same history.
        // Stage 5c does not yet enforce CommitmentMerkleProofs, so the
        // identical history_root is acceptable here.
        let update_proof =
            prove_account_update(&circuit, &account_state, history_root, &init_proof)
                .expect("prove update");
        verify(&circuit, &update_proof).expect("verify update");

        // Carry-over: the update's coin_history_root must equal the
        // init's coin_history_root (which is DEFAULT_HASHES[0]).
        let init_pd = pis_as_proof_data(&init_proof);
        let update_pd = pis_as_proof_data(&update_proof);
        assert_eq!(update_pd.coin_history_root, init_pd.coin_history_root);
        assert_eq!(update_pd.account_state_hash, account_state.hash());
    }

    /// Stage 5c negative: AccountUpdate where the current account_state
    /// hashes to something different from prev's `account_state_hash` →
    /// rejected by the state-continuity constraint.
    #[test]
    fn stage_5c_account_update_state_discontinuity_rejected() {
        let circuit = build_circuit();

        // Build a prev proof for one account_state.
        let mut prev_state = AccountState::new(dummy_pubkey(42));
        prev_state.owner = *MINTING_ADDRESS;
        prev_state.balance = 500;
        let history_root = hash_bytes(b"history@5c-disc");
        let prev_proof =
            prove_initial(&circuit, &prev_state, history_root).expect("prove prev init");

        // Try to update with a DIFFERENT account_state. Continuity must fail.
        let mut next_state = prev_state.clone();
        next_state.balance += 1; // changes account_state_hash
        assert!(prove_account_update(&circuit, &next_state, history_root, &prev_proof).is_err());
    }
}
