//! Monolithic state-transition circuit for zkCoins (Plonky2 backend).
//!
//! Mirrors `program/src/main.rs` (the SP1 entrypoint), but built as a
//! Plonky2 cyclic-recursive circuit per [`SPEC.md`] §10 and the
//! `ROADMAP.md` Step 5 plan.
//!
//! ## Stage 5a — recursion plumbing PoC
//!
//! Per the `R1` mitigation in `ROADMAP.md` ("Start step 5 with the
//! simplest possible 'I verify myself with a trivial payload' circuit
//! before adding the real predicate"), this initial revision wires the
//! cyclic-recursion machinery in isolation:
//!
//! - One public input: a `counter` field element that increments each
//!   cycle. Base case sets `counter = 0`; each recursive cycle binds
//!   `counter == prev.counter + 1`.
//! - `add_verifier_data_public_inputs()` pins the verifier-key digest as
//!   public input (the `circuit_digest` half is what `vk` in `ProofData`
//!   will eventually carry — see SPEC §10).
//! - `conditionally_verify_cyclic_proof_or_dummy::<C>` handles the
//!   Initial-vs-recursive branch. When `condition == false`, a
//!   `cyclic_base_proof` dummy stands in for the inner proof.
//!
//! This stage carries no `AccountState`, no SMT/MMR, no `ProofData`.
//! Subsequent stages (5b–5d, tracked on the branch) replace the counter
//! payload with the real state-transition predicate while keeping the
//! same overall recursion skeleton. The two stage-5a tests below
//! exercise the base proof and one recursive cycle — that is what we
//! mean by "validates the recursion plumbing in isolation".
//!
//! The three-pass `common_data_for_recursion_c` helper is ported from
//! Plonky2 1.1.0's own canonical test
//! (`recursion::cyclic_recursion::tests::common_data_for_recursion`)
//! and is required because Plonky2 cyclic recursion needs a
//! `CommonCircuitData` whose `circuit_digest` is stable across builds
//! before the real circuit can reference itself. The BitVM/zkCoins
//! reference (`MIGRATION_RESEARCH.md` §1) uses a different shape for
//! the older Plonky2 0.2.0 API — see the helper's docstring for why
//! we deviated.

use anyhow::Result;
use plonky2::gates::noop::NoopGate;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

use crate::{C, D, F};

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

/// Handle to the built cyclic circuit plus the witness targets a caller
/// needs to populate when proving.
///
/// The `data` field carries the verifier-key digest in
/// `data.verifier_only.circuit_digest`; binding this digest as a public
/// input (via `verifier_data_target`) is what makes the recursion
/// *cyclic*: a proof of this circuit can only be verified by this same
/// circuit.
pub struct CyclicCircuit {
    /// Built circuit (proving + verification keys, common data).
    pub data: CircuitData<F, C, D>,
    /// Verifier shape that recursive inner proofs are checked against.
    /// Equal to `data.common` up to the cyclic-recursion fixed-point.
    pub common_data: CommonCircuitData<F, D>,
    /// Public-input slots reserved for the verifier-key digest +
    /// constants-sigmas cap (set via
    /// `set_verifier_data_target` each prove).
    pub verifier_data_target: VerifierCircuitTarget,
    /// Witness bit toggling base case (false) vs recursive cycle (true).
    pub condition: BoolTarget,
    /// Inner proof slot. For the base case, populated by
    /// [`cyclic_base_proof`]; for recursive cycles, the prior real proof.
    pub inner_proof_target: ProofWithPublicInputsTarget<D>,
    /// The single Stage-5a public input: `counter`.
    pub counter: Target,
}

/// Build the Stage-5a cyclic circuit.
///
/// Layout:
/// - One public input (`counter`), registered before
///   `add_verifier_data_public_inputs()` per the Plonky2 API contract.
/// - Verifier-data public inputs (4 hash elements + cap), added by
///   `add_verifier_data_public_inputs()`.
/// - One inner proof target whose own first public input (also `counter`)
///   feeds the cycle.
///
/// The cycle predicate is:
/// ```text
/// counter == if condition { inner.counter + 1 } else { 0 }
/// ```
///
/// `conditionally_verify_cyclic_proof_or_dummy` ensures: when `condition`
/// is true the inner proof must verify against this same circuit; when
/// false the slot is filled with a dummy.
///
/// Returns the built circuit unconditionally — does not propagate the
/// `Result` of `conditionally_verify_cyclic_proof_or_dummy` because that
/// only fails when `common_data` is malformed, which is impossible here
/// (we construct `common_data` via the three-pass helper above). Per
/// [`MIGRATION_RESEARCH.md`] §7.9, unreachable error paths use `.expect`
/// to avoid coverage debt.
pub fn build_cyclic_circuit() -> CyclicCircuit {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Regular public input(s) first — must precede
    // `add_verifier_data_public_inputs` per Plonky2 contract.
    let counter = builder.add_virtual_public_input();

    // Build the common_data BEFORE add_verifier_data_public_inputs, then
    // pin num_public_inputs AFTER, matching Plonky2 1.1.0's own
    // `recursion::cyclic_recursion::tests::test_cyclic_recursion`.
    let mut common_data = common_data_for_recursion_c();
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();

    let condition = builder.add_virtual_bool_target_safe();
    let inner_proof_target = builder.add_virtual_proof_with_pis(&common_data);
    let inner_counter = inner_proof_target.public_inputs[0];

    // counter = if condition then inner_counter + 1 else 0
    let one = builder.one();
    let inner_plus_one = builder.add(inner_counter, one);
    let zero = builder.zero();
    let actual_counter = builder.select(condition, inner_plus_one, zero);
    builder.connect(counter, actual_counter);

    builder
        .conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &inner_proof_target,
            &common_data,
        )
        .expect("conditionally_verify_cyclic_proof_or_dummy: common_data is well-formed by construction");

    let data = builder.build::<C>();
    CyclicCircuit {
        data,
        common_data,
        verifier_data_target,
        condition,
        inner_proof_target,
        counter,
    }
}

/// Prove the base case (no prior cycle).
///
/// Sets `condition = false` and supplies a [`cyclic_base_proof`] dummy in
/// the inner-proof slot. The dummy seeds the inner `counter` to 0; the
/// cycle predicate then forces the outer `counter` to 0 as well.
pub fn prove_base(circuit: &CyclicCircuit) -> Result<ProofWithPublicInputs<F, C, D>> {
    use plonky2::field::types::Field;
    let mut pw = PartialWitness::new();
    pw.set_bool_target(circuit.condition, false).unwrap();

    // The dummy proof's public inputs are mostly don't-cares except for
    // the counter slot, which must be 0 so the base-case predicate
    // `counter == if false { … } else { 0 }` is satisfiable.
    // `cyclic_base_proof` consumes a `hashbrown::HashMap` (Plonky2's
    // dep, not `std`), so we let `collect()` infer the right type.
    let inner_initial_values = [F::ZERO];
    let inner_pis = inner_initial_values.into_iter().enumerate().collect();
    pw.set_proof_with_pis_target::<C, D>(
        &circuit.inner_proof_target,
        &cyclic_base_proof(&circuit.common_data, &circuit.data.verifier_only, inner_pis),
    )
    .unwrap();
    pw.set_verifier_data_target(&circuit.verifier_data_target, &circuit.data.verifier_only)
        .unwrap();

    circuit.data.prove(pw)
}

/// Prove one recursive cycle, consuming `prev` as the inner proof.
///
/// Sets `condition = true` so the predicate binds
/// `counter == prev.counter + 1`. The cyclic verification machinery
/// enforces that `prev` was generated by *this same circuit*
/// (`circuit_digest` match).
pub fn prove_recursive(
    circuit: &CyclicCircuit,
    prev: &ProofWithPublicInputs<F, C, D>,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = PartialWitness::new();
    pw.set_bool_target(circuit.condition, true).unwrap();
    pw.set_proof_with_pis_target::<C, D>(&circuit.inner_proof_target, prev)
        .unwrap();
    pw.set_verifier_data_target(&circuit.verifier_data_target, &circuit.data.verifier_only)
        .unwrap();

    circuit.data.prove(pw)
}

/// Verify a cyclic proof, including the cross-check that its embedded
/// verifier-data digest matches the circuit's own.
///
/// Wraps both [`check_cyclic_proof_verifier_data`] (binds the proof to
/// *this* circuit, not just any circuit with compatible common data) and
/// [`CircuitData::verify`] (the standard Plonky2 verification path).
pub fn verify(circuit: &CyclicCircuit, proof: &ProofWithPublicInputs<F, C, D>) -> Result<()> {
    check_cyclic_proof_verifier_data(proof, &circuit.data.verifier_only, &circuit.data.common)?;
    circuit.data.verify(proof.clone())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;

    /// Stage 5a base proof: condition=false → inner is a dummy →
    /// counter must end at 0. Validates that the recursion plumbing
    /// accepts and verifies a "first proof in the chain" without
    /// consuming any real inner proof.
    #[test]
    fn stage_5a_base_proof_round_trip() {
        let circuit = build_cyclic_circuit();
        let proof = prove_base(&circuit).expect("prove base");
        assert_eq!(
            proof.public_inputs[0],
            F::ZERO,
            "base case must set counter = 0"
        );
        verify(&circuit, &proof).expect("verify base");
    }

    /// Stage 5a recursive cycle: base → one cycle → counter = 1.
    /// This is the critical test for R1 — it proves that the
    /// `circuit_digest` is stable enough that a proof of the circuit
    /// can itself be verified inside the same circuit, and that the
    /// cycle predicate (`counter = inner.counter + 1`) is enforced.
    #[test]
    fn stage_5a_recursive_proof_round_trip() {
        let circuit = build_cyclic_circuit();
        let base = prove_base(&circuit).expect("prove base");
        let cycle1 = prove_recursive(&circuit, &base).expect("prove cycle 1");
        assert_eq!(
            cycle1.public_inputs[0],
            F::ONE,
            "one cycle must set counter = 1"
        );
        verify(&circuit, &cycle1).expect("verify cycle 1");
    }
}
