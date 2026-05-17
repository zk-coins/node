//! Source-proof aggregator circuit (Stage 5d-next-5).
//!
//! Bundles up to [`MAX_IN_COINS`] in-coin source proofs into one
//! aggregated proof that the outer [`crate::circuit::main`] circuit can
//! verify with a single regular (non-cyclic) `verify_proof` call.
//!
//! ## Why this exists
//!
//! Per SPEC §8 step 2 the in-coins predicate requires, per slot, a
//! recursive verification of the source state-transition proof.
//! Plonky2 1.1.0 limits a cyclic-recursion outer circuit (one whose
//! `common_data` includes `ConstantGate` because of multiple
//! `verify_proof` calls) to exactly ONE
//! `conditionally_verify_cyclic_proof_or_dummy` per build: a second
//! call's internal `dummy_circuit` rebuild fails the
//! `assert_eq!(&circuit.common, common_data)` shape check at
//! `dummy_circuit.rs:116`. See `MIGRATION_RESEARCH.md` §7.21.
//!
//! The aggregator pattern resolves this:
//!
//! - **Aggregator** (this module) is NOT cyclic — it does not call
//!   `add_verifier_data_public_inputs`. Its own `common_data` is fixed
//!   at build time. It performs `MAX_IN_COINS`
//!   `conditionally_verify_proof` calls (the non-cyclic conditional
//!   variant), which select between a real source proof and a
//!   hand-rolled dummy. Because no `_or_dummy` is involved, the
//!   `dummy_circuit` assertion never fires.
//!
//! - **Outer** (the state-transition circuit, [`crate::circuit::main`])
//!   stays at exactly one `conditionally_verify_cyclic_proof_or_dummy`
//!   for `prev_account` (unchanged Stage 5d-next-3 shape) plus one
//!   regular `verify_proof` for the aggregator proof. The regular
//!   `verify_proof` does NOT invoke `dummy_circuit`, so the multi-verify
//!   Plonky2 limitation is sidestepped.
//!
//! ## Fixed-point: lazy verifier_data with connect-back
//!
//! The aggregator verifies proofs of the state-transition circuit. But
//! the state-transition's `verifier_only.circuit_digest` cannot be
//! pinned at aggregator build time without a chicken-and-egg fixed-point.
//! Resolution per [`STAGE_5D_NEXT_5_AGGREGATOR.md`]:
//!
//! - At aggregator build time, the state-transition verifier_data is a
//!   `add_virtual_verifier_data` target with NO constant pin.
//! - The aggregator exposes the witnessed st verifier_data as additional
//!   public inputs (digest + constants_sigmas_cap).
//! - At outer build time, after the cyclic verify wires up the outer's
//!   own `verifier_data_target`, the outer extracts the aggregator's
//!   claimed st verifier_data from the aggregator's public inputs and
//!   `connect_hashes`-binds it to its own. A wrong-vk aggregator proof
//!   then fails at outer verify.
//!
//! ## Per-slot dummy
//!
//! `conditionally_verify_proof` (non-`_or_dummy` variant) takes two
//! `(proof, vd)` pairs and verifies the one selected by the condition.
//! For the dummy "branch" (inactive slots) the aggregator passes:
//!
//! - `proof_b`: a virtual proof target witnessed at prove time with
//!   `cyclic_base_proof(st_common, st_verifier_only, empty_pis)` — the
//!   same dummy Stage 5d-next-3's `prove_initial` uses for the cyclic
//!   slot when `condition = false`.
//! - `vd_b`: a `constant_verifier_data` from a one-shot
//!   `dummy_circuit::<F, C, D>(st_common)` instance. The dummy circuit
//!   is the one against which `cyclic_base_proof` actually verifies.
//!
//! The dummy circuit's `verifier_only.circuit_digest` is deterministic
//! given `st_common`, so pinning it as a constant in the aggregator is
//! safe — `cyclic_base_proof` will always produce a proof verifiable
//! against this same dummy verifier.
//!
//! ## Public-input layout
//!
//! ```text
//! [0                          .. MAX_IN_COINS * PER_SLOT_PIS]:
//!     For each slot i (0-indexed):
//!         [i*17 + 0..i*17 + 16]:  source's ProofData (16 elements)
//!         [i*17 + 16]:            slot's `active` bit (0 or 1)
//! [MAX_IN_COINS * 17 ..        + 4]:
//!     state-transition vk circuit_digest (4 elements)
//! [MAX_IN_COINS * 17 + 4 ..    + 4 + 4 * cap_elements]:
//!     state-transition vk constants_sigmas_cap (4 elements per cap entry)
//! ```
//!
//! `cap_elements = 1 << cap_height`. For
//! `CircuitConfig::standard_recursion_config()` (`cap_height = 4`),
//! `cap_elements = 16`, so the cap occupies `4 * 16 = 64` elements.
//! Total aggregator PIs: `8 * 17 + 4 + 64 = 204`.

use anyhow::Result;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
    VerifierOnlyCircuitData,
};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::dummy_circuit::{cyclic_base_proof, dummy_circuit};

use crate::circuit::main::{MAX_IN_COINS, N_PROOF_DATA_PUBLIC_INPUTS};
use crate::{C, D, F};

/// Number of public-input slots per source slot the aggregator exposes:
/// 16 `ProofData` field elements + 1 `active` bit.
pub const PER_SLOT_PIS: usize = N_PROOF_DATA_PUBLIC_INPUTS + 1;

/// Public-input slots holding the state-transition verifier-key digest.
pub const N_ST_VK_DIGEST_PIS: usize = 4;

/// Number of elements in the state-transition verifier-key
/// constants-sigmas cap. With
/// [`CircuitConfig::standard_recursion_config`] this is
/// `1 << cap_height = 16`, each element being a `HashOut` of 4 field
/// elements → 64 public-input slots total.
///
/// Computed at runtime from the supplied `st_common` rather than
/// hard-coded, so changes to the recursion config remain consistent
/// without manual edits.
pub fn n_st_sigmas_cap_pis(st_common: &CommonCircuitData<F, D>) -> usize {
    4 * st_common.config.fri_config.num_cap_elements()
}

/// Total number of public inputs the aggregator exposes:
/// `MAX_IN_COINS * PER_SLOT_PIS + N_ST_VK_DIGEST_PIS + n_st_sigmas_cap_pis(st_common)`.
pub fn total_aggregator_pis(st_common: &CommonCircuitData<F, D>) -> usize {
    MAX_IN_COINS * PER_SLOT_PIS + N_ST_VK_DIGEST_PIS + n_st_sigmas_cap_pis(st_common)
}

/// Per-slot witness targets the prover populates: real source proof
/// (proof_a) + dummy proof (proof_b) + `active` bit. The dummy proof
/// target is set to a `cyclic_base_proof` at prove time regardless of
/// `active`; only when `active = false` is it actually verified.
pub struct AggregatorSlotTargets {
    pub active: BoolTarget,
    /// "Real" proof, verified when `active = true`.
    pub real_proof: ProofWithPublicInputsTarget<D>,
    /// Dummy proof, verified when `active = false`. Witnessed with
    /// `cyclic_base_proof(st_common, st_verifier_only, _)` at prove time.
    pub dummy_proof: ProofWithPublicInputsTarget<D>,
}

/// Handle to the built aggregator circuit + the witness targets a
/// caller needs to populate when proving.
pub struct SourceAggregatorCircuit {
    pub data: CircuitData<F, C, D>,
    /// `st_common` the aggregator was built against. Outer integration
    /// needs this to thread the dummy-proof witness through `cyclic_base_proof`.
    pub st_common: CommonCircuitData<F, D>,
    /// Cached dummy-circuit verifier_only. Constant-baked into the
    /// aggregator as `dummy_vd_target`. Cached here so `prove_aggregator`
    /// doesn't rebuild it.
    pub dummy_st_verifier_only: VerifierOnlyCircuitData<C, D>,
    pub slots: Vec<AggregatorSlotTargets>,
    /// Virtual target for the SHARED state-transition verifier_data.
    /// Exposed as PIs so the outer can `connect_hashes`-bind it to its
    /// own `verifier_data_target`.
    pub st_verifier_data: VerifierCircuitTarget,
}

/// Build the aggregator circuit.
///
/// `st_common` is the state-transition circuit's `CommonCircuitData`
/// (cyclic fixed-point shape). Used to size virtual proof targets and
/// to construct the one-shot dummy circuit whose verifier_only is baked
/// in as the inactive-slot's verifier_data.
///
/// The build is NON-CYCLIC: the aggregator does not call
/// `add_verifier_data_public_inputs`. Its `common_data` is determined
/// at build time and is what the outer circuit's `verify_proof(agg)`
/// must match.
pub fn build_source_aggregator_circuit(
    st_common: &CommonCircuitData<F, D>,
) -> SourceAggregatorCircuit {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // One-shot dummy circuit for the inactive-slot branch. `cyclic_base_proof`
    // produces proofs verifiable against THIS dummy circuit's verifier_only,
    // not the state-transition circuit's own. So we pin the dummy's
    // verifier_only as a constant in the aggregator.
    //
    // Safe because `dummy_circuit` is deterministic in `st_common`: same
    // `st_common` always produces the same dummy `verifier_only` digest.
    let dummy_st_circuit = dummy_circuit::<F, C, D>(st_common);
    let dummy_vd_target = builder.constant_verifier_data(&dummy_st_circuit.verifier_only);

    // SHARED state-transition verifier_data: one virtual target binding
    // every "real" slot to the same source-circuit identity. Exposed as
    // PIs so the outer can later prove `claimed_st_vd ==
    // outer.verifier_data_target`.
    let st_verifier_data =
        builder.add_virtual_verifier_data(st_common.config.fri_config.cap_height);

    let mut slots = Vec::with_capacity(MAX_IN_COINS);

    for _ in 0..MAX_IN_COINS {
        let active = builder.add_virtual_bool_target_safe();
        let real_proof = builder.add_virtual_proof_with_pis(st_common);
        let dummy_proof = builder.add_virtual_proof_with_pis(st_common);

        builder.conditionally_verify_proof::<C>(
            active,
            &real_proof,
            &st_verifier_data,
            &dummy_proof,
            &dummy_vd_target,
            st_common,
        );

        // Per-slot PIs: 16 elements of `real_proof.public_inputs[0..16]`
        // (the source's `ProofData`) + 1 element for `active`.
        for i in 0..N_PROOF_DATA_PUBLIC_INPUTS {
            builder.register_public_input(real_proof.public_inputs[i]);
        }
        builder.register_public_input(active.target);

        slots.push(AggregatorSlotTargets {
            active,
            real_proof,
            dummy_proof,
        });
    }

    // State-transition verifier_data PIs (after all slot PIs).
    builder.register_public_inputs(&st_verifier_data.circuit_digest.elements);
    for h in &st_verifier_data.constants_sigmas_cap.0 {
        builder.register_public_inputs(&h.elements);
    }

    let data = builder.build::<C>();
    SourceAggregatorCircuit {
        data,
        st_common: st_common.clone(),
        dummy_st_verifier_only: dummy_st_circuit.verifier_only,
        slots,
        st_verifier_data,
    }
}

/// Per-slot witness for [`prove_aggregator`].
///
/// For inactive slots, pass `(false, None)` — the prover fills both
/// proof targets with `cyclic_base_proof` and the slot's
/// `conditionally_verify_proof` selects the dummy branch.
pub struct AggregatorSlotWitness<'a> {
    pub active: bool,
    /// Real source proof. MUST be present when `active = true`; ignored
    /// when `active = false`.
    pub real_proof: Option<&'a ProofWithPublicInputs<F, C, D>>,
}

/// Prove the aggregator circuit.
///
/// `st_verifier_only` is the state-transition circuit's actual
/// verifier_only — needed so `cyclic_base_proof` can populate the
/// cyclic-vk PI slots of the dummy proof. (The state-transition
/// circuit's PIs include the cyclic vk; `cyclic_base_proof` initialises
/// those slots from `st_verifier_only`.)
///
/// `slot_witnesses.len()` must equal [`MAX_IN_COINS`]. Each entry's
/// `real_proof` is required when `active = true` — its
/// `public_inputs[0..16]` become the slot's exposed source-`ProofData`
/// in the aggregator's public inputs.
pub fn prove_aggregator(
    aggregator: &SourceAggregatorCircuit,
    st_verifier_only: &VerifierOnlyCircuitData<C, D>,
    slot_witnesses: &[AggregatorSlotWitness],
) -> Result<ProofWithPublicInputs<F, C, D>> {
    assert_eq!(
        slot_witnesses.len(),
        MAX_IN_COINS,
        "prove_aggregator: caller must supply exactly MAX_IN_COINS slot witnesses"
    );

    let mut pw = PartialWitness::new();

    // Witness the shared st_verifier_data with the ACTUAL state-transition
    // verifier_only. For active slots, `conditionally_verify_proof`
    // verifies the real source proof against this vd.
    pw.set_verifier_data_target(&aggregator.st_verifier_data, st_verifier_only)
        .unwrap();

    // Pre-build a single dummy proof shared across all slots'
    // `dummy_proof` targets. cyclic_base_proof is deterministic in
    // (st_common, st_verifier_only, pis) so this is the proof every
    // inactive `conditionally_verify_proof` branch sees.
    let empty_pis = std::iter::empty::<(usize, F)>().collect();
    let dummy_proof =
        cyclic_base_proof::<F, C, D>(&aggregator.st_common, st_verifier_only, empty_pis);

    for (slot_targets, witness) in aggregator.slots.iter().zip(slot_witnesses.iter()) {
        pw.set_bool_target(slot_targets.active, witness.active)
            .unwrap();

        // Always witness `dummy_proof` with the dummy. Branch select
        // ignores it when active = true.
        pw.set_proof_with_pis_target::<C, D>(&slot_targets.dummy_proof, &dummy_proof)
            .unwrap();

        // `real_proof` target: if active, use caller-supplied real
        // source proof; if inactive, fill with dummy so the SELECT op's
        // inputs are well-defined (verify_proof only consumes the
        // selected branch, so the dummy is harmless here).
        let real = match (witness.active, witness.real_proof) {
            (true, Some(p)) => p,
            (true, None) => panic!(
                "prove_aggregator: active slot must supply a real_proof"
            ),
            (false, _) => &dummy_proof,
        };
        pw.set_proof_with_pis_target::<C, D>(&slot_targets.real_proof, real)
            .unwrap();
    }

    aggregator.data.prove(pw)
}

/// Verify the aggregator's proof against its own circuit data.
/// Useful for unit testing the aggregator in isolation.
pub fn verify_aggregator(
    aggregator: &SourceAggregatorCircuit,
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<()> {
    aggregator.data.verify(proof.clone())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::main::{build_circuit, prove_initial};
    use crate::hash::hash_bytes;
    use crate::types::{AccountState, MINTING_ADDRESS};
    use plonky2::field::types::Field;

    /// Smoke test: build the aggregator against the state-transition
    /// circuit's `common_data`, prove with all slots inactive, verify.
    ///
    /// All inactive: every `conditionally_verify_proof` selects the
    /// dummy branch, which the prover witnesses with `cyclic_base_proof`.
    /// No real source proof is required.
    ///
    /// Confirms the architecture works around the Plonky2 1.1.0
    /// `_or_dummy` blocker (§7.21):
    /// - aggregator's `conditionally_verify_proof` (non-`_or_dummy`)
    ///   doesn't invoke the offending `dummy_circuit` assertion;
    /// - `cyclic_base_proof(st_common)` succeeds because `st_common`
    ///   is the Stage 5d-next-3 working shape (1 verify, no
    ///   `ConstantGate` mismatch).
    #[test]
    fn aggregator_smoke_all_inactive() {
        let st_circuit = build_circuit();
        let aggregator = build_source_aggregator_circuit(&st_circuit.common_data);

        // Sanity: the aggregator's PIs match the documented layout.
        let expected_pis = total_aggregator_pis(&st_circuit.common_data);
        assert_eq!(
            aggregator.data.common.num_public_inputs, expected_pis,
            "aggregator PI count must match total_aggregator_pis"
        );

        let slot_witnesses: Vec<AggregatorSlotWitness> = (0..MAX_IN_COINS)
            .map(|_| AggregatorSlotWitness {
                active: false,
                real_proof: None,
            })
            .collect();

        let proof = prove_aggregator(&aggregator, &st_circuit.data.verifier_only, &slot_witnesses)
            .expect("prove aggregator with all inactive slots");
        verify_aggregator(&aggregator, &proof).expect("verify aggregator proof");

        // Inactive slots: ProofData PIs are zero (cyclic_base_proof
        // populates only the cyclic-vk slots, which sit AFTER the
        // ProofData slots in the state-transition's PI layout), and
        // active bit is zero.
        for i in 0..MAX_IN_COINS {
            for j in 0..N_PROOF_DATA_PUBLIC_INPUTS {
                assert_eq!(
                    proof.public_inputs[i * PER_SLOT_PIS + j],
                    F::default(),
                    "inactive slot {i} ProofData[{j}] must be zero"
                );
            }
            assert_eq!(
                proof.public_inputs[i * PER_SLOT_PIS + N_PROOF_DATA_PUBLIC_INPUTS],
                F::default(),
                "inactive slot {i} active bit must be zero"
            );
        }
    }

    fn dummy_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        for (i, b) in pk.iter_mut().enumerate().skip(1) {
            *b = seed.wrapping_add(i as u8);
        }
        pk
    }

    /// Positive: one slot active with a real Initial source proof.
    ///
    /// Validates the active path of `conditionally_verify_proof`:
    /// the aggregator's verify_proof against the SHARED
    /// `st_verifier_data` (witnessed with the real state-transition
    /// `verifier_only`) accepts the source proof, and its `ProofData`
    /// PIs surface unchanged in the aggregator's slot-0 PIs.
    #[test]
    fn aggregator_one_active_slot_with_init_source() {
        let st_circuit = build_circuit();
        let aggregator = build_source_aggregator_circuit(&st_circuit.common_data);

        // Build a real Initial source proof: mint account with balance.
        let mut source_account = AccountState::new(dummy_pubkey(31));
        source_account.owner = *MINTING_ADDRESS;
        source_account.balance = 1_000_000;
        let source_history_root = hash_bytes(b"aggregator-init-source");
        let source_proof = prove_initial(&st_circuit, &source_account, source_history_root)
            .expect("prove init source");

        // Slot 0 active, others inactive.
        let mut slot_witnesses: Vec<AggregatorSlotWitness> = Vec::with_capacity(MAX_IN_COINS);
        slot_witnesses.push(AggregatorSlotWitness {
            active: true,
            real_proof: Some(&source_proof),
        });
        for _ in 1..MAX_IN_COINS {
            slot_witnesses.push(AggregatorSlotWitness {
                active: false,
                real_proof: None,
            });
        }

        let proof = prove_aggregator(&aggregator, &st_circuit.data.verifier_only, &slot_witnesses)
            .expect("prove aggregator with one active source");
        verify_aggregator(&aggregator, &proof).expect("verify aggregator");

        // Slot-0 PIs surface the source proof's `ProofData`.
        for j in 0..N_PROOF_DATA_PUBLIC_INPUTS {
            assert_eq!(
                proof.public_inputs[j], source_proof.public_inputs[j],
                "slot 0 PI[{j}] must mirror source proof's ProofData[{j}]"
            );
        }
        assert_eq!(
            proof.public_inputs[N_PROOF_DATA_PUBLIC_INPUTS],
            F::ONE,
            "slot 0 active bit must be 1"
        );

        // Other slots' active bits must be 0.
        for i in 1..MAX_IN_COINS {
            assert_eq!(
                proof.public_inputs[i * PER_SLOT_PIS + N_PROOF_DATA_PUBLIC_INPUTS],
                F::default(),
                "inactive slot {i} active bit must be zero"
            );
        }
    }
}
