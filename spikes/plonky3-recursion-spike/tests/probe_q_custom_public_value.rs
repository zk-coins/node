//! Probe Q — a custom AIR's PUBLIC VALUE crosses a batch-recursion layer (overturns
//! the scoped NO-GO).
//!
//! Probes D/G/H found `air_public_targets = [0,0,0]` and concluded "no per-instance
//! value channel across a batch layer". That finding was **scoped too narrowly**: it
//! only exercised the three PRIMITIVE tables (Const/Public/Alu, which structurally emit
//! zero AIR public values) and `CircuitBuilder` public inputs (which live in the
//! committed Public *table*). Upstream PR #407 ("feat: support public values", merged
//! 2026-03-19, **present in our pinned rev 524665d**) wires per-instance AIR public
//! values of NON-PRIMITIVE / raw AIRs through to the next layer's `air_public_targets`.
//!
//! This probe replicates upstream `recursion/tests/preprocessing.rs::
//! test_batch_verifier_with_public_values` (+ the wrong-value negative) IN OUR CRATE:
//! a custom `PublicValueAir` (`num_public_values() = 1`) is proved with `prove_batch`
//! and verified in-circuit via `verify_batch_circuit`; its public value surfaces as a
//! constrainable `air_public_target` and is SOUNDLY BOUND.
//!
//!   * POSITIVE: correct public value → the in-circuit batch verifier runs.
//!   * NEGATIVE: a wrong claimed public value → rejected (`run()` errors).
//!
//! Green ⇒ a per-instance value DOES cross a batch layer ⇒ the cross-layer value
//! channel that the IVC needs EXISTS (via a public-value-emitting AIR), and the
//! migration NO-GO is overturned for this construction. Uses BabyBear (the exact
//! upstream pattern); the mechanism is field-generic.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::{InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness};
use p3_recursion::{
    BatchStarkVerifierInputsBuilder, FriVerifierParams, Poseidon2Config, verify_batch_circuit,
};
use p3_test_utils::baby_bear_params::*;
use p3_test_utils::test_fri_scalars;

type InnerFri = FriProofTargets<
    F,
    Challenge,
    RecExtensionValMmcs<
        F,
        Challenge,
        DIGEST_ELEMS,
        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
    >,
    InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
    Witness<F>,
>;

/// A raw AIR with one PUBLIC VALUE: trace width 2, constraint `local[0] == public[0]`
/// on the first row. The public value is bound to a committed trace cell.
#[derive(Clone, Copy)]
struct PublicValueAir {
    rows: usize,
}

impl PublicValueAir {
    fn generate_trace<Val: Field>(&self) -> (RowMajorMatrix<Val>, Vec<Val>) {
        let width = 2;
        let mut values = Val::zero_vec(self.rows * width);
        for row in 0..self.rows {
            let idx = row * width;
            values[idx] = Val::from_usize(row + 42);
            values[idx + 1] = Val::from_usize(row + 1);
        }
        let pv = values[0];
        (RowMajorMatrix::new(values, width), vec![pv])
    }
}

impl<Val: Field> BaseAir<Val> for PublicValueAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder> Air<AB> for PublicValueAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local0 = local[0];
        let pis = builder.public_values();
        let pi0 = pis[0];
        builder.when_first_row().assert_eq(local0, pi0);
    }
}

/// Verify a `PublicValueAir` batch proof in-circuit, claiming `claimed_pv` as the
/// public value. Returns Err if the in-circuit run fails.
fn verify_with_claimed_pv(claimed_pv: F) -> Result<(), String> {
    let n = 1 << 3;
    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::unsafe_arithmetic_only_for_tests(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
    );
    let config = make_test_config();
    let perm = default_babybear_poseidon2_16();

    let pv_air = PublicValueAir { rows: n };
    let (pv_trace, pv_vals) = pv_air.generate_trace::<F>();
    let pvs = [pv_vals];

    let instances = vec![StarkInstance {
        air: &pv_air,
        trace: &pv_trace,
        public_values: pvs[0].clone(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let common_data = &prover_data.common;
    let batch_proof = prove_batch(&config, &instances, &prover_data);
    verify_batch(&config, &[pv_air], &batch_proof, &pvs, common_data)
        .map_err(|e| format!("native verify: {e:?}"))?;

    let lookup_gadget = LogUpGadget::new();
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let air_public_counts = vec![1usize];
    let vi = BatchStarkVerifierInputsBuilder::<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
        &mut cb,
        &batch_proof,
        common_data,
        &air_public_counts,
    );

    // The public value IS surfaced as a constrainable target across the batch layer:
    // exactly one instance, with exactly one per-instance public target (NOT [0,0,0]).
    assert_eq!(vi.air_public_targets.len(), 1, "one instance");
    assert_eq!(
        vi.air_public_targets[0].len(),
        1,
        "the custom AIR's public value MUST surface as 1 air_public_target (not [0,0,0])"
    );

    verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &[pv_air],
        &mut cb,
        &vi.proof_targets,
        &vi.air_public_targets,
        &fri_verifier_params,
        &vi.common_data,
        &lookup_gadget,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .map_err(|e| format!("build verifier: {e:?}"))?;

    let circuit = cb.build().map_err(|e| format!("build: {e:?}"))?;
    let mut runner = circuit.runner();
    // Claim `claimed_pv` as the public value (correct or tampered).
    let claimed = [vec![claimed_pv]];
    let (public_inputs, private_inputs) = vi.pack_values(&claimed, &batch_proof, common_data);
    runner
        .set_public_inputs(&public_inputs)
        .map_err(|e| format!("set pub: {e:?}"))?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(|e| format!("set priv: {e:?}"))?;
    runner.run().map_err(|e| format!("run: {e:?}"))?;
    Ok(())
}

#[test]
fn probe_q_custom_public_value() {
    // The committed public value is trace[0] = 42 (row 0: from_usize(0 + 42)).
    let correct = F::from_usize(42);

    // POSITIVE: correct public value surfaces across the batch layer and verifies.
    verify_with_claimed_pv(correct)
        .expect("a custom AIR's public value MUST cross the batch layer and verify");

    // NEGATIVE: a wrong claimed public value is rejected — the value is SOUNDLY BOUND
    // across the layer (this is the cross-layer value channel the IVC needs).
    assert!(
        verify_with_claimed_pv(F::from_usize(999)).is_err(),
        "a wrong claimed public value must be REJECTED across the batch layer"
    );
}
