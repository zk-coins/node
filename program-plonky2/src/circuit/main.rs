//! Monolithic state-transition circuit for zkCoins (Plonky2 backend).
//!
//! Mirrors `program/src/main.rs` (the SP1 entrypoint), but built as a
//! Plonky2 cyclic-recursive circuit per [`SPEC.md`] §8 / §10 and the
//! `ROADMAP.md` Step 5 plan.
//!
//! ## Stage status
//!
//! - **5a — recursion plumbing PoC**: done in commit `83fa0c1`. The
//!   counter payload from that stage is gone; the lessons (canonical
//!   `common_data_for_recursion_c`, the `.expect()` pattern on
//!   unreachable `Result<()>` calls) are carried forward.
//! - **5b — Initial branch with real predicate** ✅ this revision. The
//!   public input is now the full [`crate::types::ProofData`]
//!   (16 field elements). The Initial-proof predicate per SPEC §8
//!   (mint exception, empty `coin_history`, empty `output_coins_root`,
//!   `commitment_history_root` carry-over) is enforced in-circuit.
//!   `condition` is constrained to `false`, so the cyclic
//!   inner-proof slot is always the dummy — Stage 5c lifts that
//!   constraint and wires the AccountUpdate predicate.
//! - **5c/5d/5e** — see ROADMAP "In Progress" section.
//!
//! ## What "Initial branch" means at this stage
//!
//! Per SPEC §8 the Initial proof is the base case of the recursion
//! chain: it does not consume a prior account proof and it does not
//! process input coins. With no `in_coins` and no `out_coins`, the
//! predicate reduces to:
//!
//! ```text
//! // Mint exception: only the MINTING_ADDRESS may carry a starting balance.
//! assert (owner == MINTING_ADDRESS) || (balance == 0)
//!
//! // Empty SMT roots for both the per-account coin-history and the
//! // global output-coins SMT (level 0 = root of an empty SMT).
//! coin_history_root  := DEFAULT_HASHES[0]
//! output_coins_root  := DEFAULT_HASHES[0]
//!
//! commit ProofData {
//!     account_state_hash:      H(account_state),
//!     output_coins_root:       DEFAULT_HASHES[0],
//!     commitment_history_root: history_root,    // witnessed
//!     coin_history_root:       DEFAULT_HASHES[0],
//! }
//! ```
//!
//! `history_root` is a pure witness at this stage; SPEC §8's
//! AccountUpdate branch is where it gets bound to a real MMR via
//! `CommitmentMerkleProofs` (Stage 5c).
//!
//! ## Cyclic recursion shape
//!
//! Even though the Initial proof does not recursively verify a prior
//! proof, the cyclic-verification machinery is wired up the same way as
//! Stage 5a — `add_verifier_data_public_inputs`,
//! `conditionally_verify_cyclic_proof_or_dummy::<C>`, the three-pass
//! [`common_data_for_recursion_c`]. The only differences from 5a are:
//!
//! - the public-input payload (16-element `ProofData` vs the 1-element
//!   counter), and
//! - `condition` is constrained to be `false` so the inner proof slot
//!   must be a dummy.
//!
//! Keeping the cyclic shape now means Stage 5c can add the
//! AccountUpdate predicate without rebuilding the recursion plumbing.
//! The `circuit_digest` will still change between 5b and 5c because
//! Stage 5c adds gates; that's expected — the digest is only
//! contractually stable *within* one stage.
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
    /// Bit toggling base case (false → Initial branch, dummy inner) vs
    /// recursive cycle (true → AccountUpdate, real inner). Stage 5b
    /// constrains it to `false`; Stage 5c lifts that constraint.
    pub condition: BoolTarget,
    /// Inner proof slot. For Stage 5b, always populated by
    /// [`cyclic_base_proof`] at prove time.
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

/// Build the Stage-5b Initial-branch state-transition circuit.
///
/// Layout:
/// - 16 public inputs (`ProofData::to_field_elements`), registered before
///   `add_verifier_data_public_inputs()` per the Plonky2 API contract.
/// - Verifier-data public inputs (4 hash elements + cap), added by
///   `add_verifier_data_public_inputs()`.
/// - One inner proof target (dummy at this stage).
///
/// The Initial-branch predicate (see module docstring) is enforced via:
/// - `is_minting = (owner == MINTING_ADDRESS)`, computed by AND-ing the
///   four element-wise `is_equal` checks.
/// - `(1 - is_minting) * balance_limb == 0` for each balance limb,
///   which forces `balance == 0` when `owner != MINTING_ADDRESS`.
/// - In-circuit Poseidon hash of `owner || balance_limbs || pubkey_limbs`
///   to derive `account_state_hash`, connected to public-input slot 0..4.
/// - The remaining `ProofData` slots are constants
///   (`DEFAULT_HASHES[0]`) or the witnessed `history_root`.
///
/// Returns the built circuit unconditionally. Like Stage 5a,
/// `conditionally_verify_cyclic_proof_or_dummy`'s `Result<()>` is
/// `.expect()`-ed: per [`MIGRATION_RESEARCH.md`] §7.13 the only Err
/// path is malformed `common_data`, which is impossible here because
/// we construct `common_data` via the three-pass helper.
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

    // Cyclic recursion: `condition` toggles Initial (false) vs
    // AccountUpdate (true). Stage 5b is Initial-only, so we pin it to
    // false. The slot is still a virtual BoolTarget (rather than
    // `builder._false()`) to keep the gate count identical to what
    // Stage 5c will use when condition is free; this minimises drift
    // in the verifier-data digest shape between stages.
    let condition = builder.add_virtual_bool_target_safe();
    let zero = builder.zero();
    builder.connect(condition.target, zero);

    let inner_proof_target = builder.add_virtual_proof_with_pis(&common_data);

    // ===== Initial-branch predicate =====

    // Witness AccountState fields.
    let owner = builder.add_virtual_hash();
    let balance_lo = builder.add_virtual_target();
    let balance_hi = builder.add_virtual_target();
    // Range-check to match off-circuit `u64_to_limbs` (two 32-bit halves).
    builder.range_check(balance_lo, 32);
    builder.range_check(balance_hi, 32);

    let pubkey_limbs: [Target; 5] = std::array::from_fn(|_| {
        let t = builder.add_virtual_target();
        // Off-circuit `pubkey_to_limbs` packs 7 bytes per limb (56 bits).
        // The last limb only holds 5 bytes + 3 zero pads, but 56-bit
        // is a conservative upper bound that covers every limb.
        builder.range_check(t, 56);
        t
    });

    let history_root = builder.add_virtual_hash();

    // is_minting = AND over element-wise equalities of owner vs MINTING_ADDRESS.
    let minting_addr = builder.constant_hash(HashOut {
        elements: MINTING_ADDRESS.elements,
    });
    let mut is_minting = builder._true();
    for i in 0..4 {
        let elem_eq = builder.is_equal(owner.elements[i], minting_addr.elements[i]);
        is_minting = builder.and(is_minting, elem_eq);
    }
    let not_minting = builder.not(is_minting);

    // Mint exception: if not minting, both balance limbs must be zero.
    let nm_times_lo = builder.mul(not_minting.target, balance_lo);
    builder.assert_zero(nm_times_lo);
    let nm_times_hi = builder.mul(not_minting.target, balance_hi);
    builder.assert_zero(nm_times_hi);

    // Compute account_state_hash in-circuit. Match the off-circuit layout in
    // `AccountState::hash`: owner (4) + balance_lo + balance_hi + pubkey (5)
    // = 11 field elements, single `hash_no_pad`.
    let mut state_elements: Vec<Target> = Vec::with_capacity(11);
    state_elements.extend_from_slice(&owner.elements);
    state_elements.push(balance_lo);
    state_elements.push(balance_hi);
    state_elements.extend_from_slice(&pubkey_limbs);
    let account_state_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(state_elements);

    // Empty SMT root for both `output_coins_root` and `coin_history_root`.
    let empty_root = builder.constant_hash(DEFAULT_HASHES[0]);

    // Connect `ProofData` public inputs slot-by-slot. Layout matches
    // `crate::types::ProofData::to_field_elements`.
    for i in 0..4 {
        builder.connect(proof_data_pis[i], account_state_hash.elements[i]);
        builder.connect(proof_data_pis[4 + i], empty_root.elements[i]);
        builder.connect(proof_data_pis[8 + i], history_root.elements[i]);
        builder.connect(proof_data_pis[12 + i], empty_root.elements[i]);
    }

    // Cyclic verification. With condition pinned false the inner proof
    // is always a dummy; we still wire the gate so the digest shape
    // matches Stage 5c. The Err path is unreachable by construction
    // (see docstring), so `.expect()` is the right call here.
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

/// Prove the Initial-branch state transition for a given `account_state`
/// and `history_root`.
///
/// At Stage 5b the AccountUpdate branch is unreachable (`condition` is
/// pinned false), so only the Initial case is provable. The function
/// populates every witness target, supplies a `cyclic_base_proof`
/// dummy in the inner-proof slot, and runs the prover.
///
/// On success the proof's public inputs are
/// [`crate::types::ProofData::to_field_elements`] for a `ProofData`
/// whose `account_state_hash` is `account_state.hash()` and whose
/// `output_coins_root` / `coin_history_root` are both
/// `DEFAULT_HASHES[0]`.
pub fn prove_initial(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashOut<F>,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = PartialWitness::new();

    // `condition` is constrained to false in-circuit, but we still set
    // the witness explicitly so prover bookkeeping is unambiguous.
    pw.set_bool_target(circuit.condition, false).unwrap();

    // Owner = account_state.owner (a HashDigest = HashOut<F>).
    pw.set_hash_target(circuit.owner, account_state.owner)
        .unwrap();

    // Balance limbs: low/high 32 bits of the u64 balance.
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

    // Pubkey limbs: 5 little-endian 7-byte chunks (last has 5 bytes).
    for (i, chunk) in account_state.public_key.chunks(7).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        pw.set_target(
            circuit.pubkey_limbs[i],
            F::from_canonical_u64(u64::from_le_bytes(buf)),
        )
        .unwrap();
    }

    pw.set_hash_target(circuit.history_root, history_root)
        .unwrap();

    // Dummy inner proof. Initial branch reads none of its public inputs,
    // so we seed an empty map (all dummy public inputs are 0).
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

    /// Stage 5b smoke test: a non-mint account with `balance = 0`
    /// is accepted, and the public-input `ProofData` exactly equals
    /// the off-circuit reconstruction. This is the canonical
    /// Initial-proof path for a freshly created (non-mint) account.
    #[test]
    fn stage_5b_initial_non_mint_zero_balance_accepted() {
        let circuit = build_circuit();
        let account_state = AccountState::new(dummy_pubkey(7));
        assert_eq!(
            account_state.balance, 0,
            "AccountState::new must seed balance to 0"
        );
        // Sanity: owner is the hash of the initial pubkey, not the
        // MINTING_ADDRESS placeholder.
        assert_ne!(account_state.owner, *MINTING_ADDRESS);

        let history_root = hash_bytes(b"history@5b-non-mint");
        let proof = prove_initial(&circuit, &account_state, history_root).expect("prove initial");
        verify(&circuit, &proof).expect("verify initial");

        let pis: [F; N_PROOF_DATA_PUBLIC_INPUTS] = proof.public_inputs
            [..N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .unwrap();
        let recovered = ProofData::from_field_elements(&pis);
        let expected = ProofData {
            account_state_hash: account_state.hash(),
            output_coins_root: DEFAULT_HASHES[0],
            commitment_history_root: history_root,
            coin_history_root: DEFAULT_HASHES[0],
        };
        assert_eq!(recovered, expected);
    }

    /// Stage 5b mint exception: an account whose `owner ==
    /// MINTING_ADDRESS` may carry any starting balance. This exercises
    /// the `is_minting` predicate's *true* branch (the
    /// `not_minting * balance == 0` constraint is trivially satisfied).
    #[test]
    fn stage_5b_initial_mint_with_balance_accepted() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(99));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 21_000_000_000_000;

        let history_root = hash_bytes(b"history@5b-mint");
        let proof = prove_initial(&circuit, &account_state, history_root).expect("prove mint");
        verify(&circuit, &proof).expect("verify mint");

        let pis: [F; N_PROOF_DATA_PUBLIC_INPUTS] = proof.public_inputs
            [..N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .unwrap();
        let recovered = ProofData::from_field_elements(&pis);
        assert_eq!(recovered.account_state_hash, account_state.hash());
        assert_eq!(recovered.output_coins_root, DEFAULT_HASHES[0]);
        assert_eq!(recovered.commitment_history_root, history_root);
        assert_eq!(recovered.coin_history_root, DEFAULT_HASHES[0]);
    }

    /// Stage 5b counter-example: a non-mint account with `balance != 0`
    /// must be rejected by the mint-exception constraint. This is the
    /// minimum negative test that proves the constraint actually
    /// binds — the full negative-test matrix from SPEC §13 lands in
    /// Stage 5e.
    #[test]
    fn stage_5b_initial_non_mint_nonzero_balance_rejected() {
        let circuit = build_circuit();
        let mut account_state = AccountState::new(dummy_pubkey(7));
        // Confirm the precondition (non-mint owner) and force a
        // non-zero balance that would normally only be legal for
        // MINTING_ADDRESS.
        assert_ne!(account_state.owner, *MINTING_ADDRESS);
        account_state.balance = 1;

        let history_root = hash_bytes(b"history@5b-illegal");
        // The prover MUST refuse this witness because the
        // `not_minting * balance_lo == 0` constraint is unsatisfied
        // (not_minting = 1, balance_lo = 1 → 1 ≠ 0).
        assert!(prove_initial(&circuit, &account_state, history_root).is_err());
    }
}
