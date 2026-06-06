//! Probe H — Option 1 (carry the threaded value as an AIR public value) feasibility.
//!
//! The Phase-1-authorize decision (MIGRATION_PLONKY3.md §6) offers Option 1 (AIR
//! public values, "fast") vs Option 2 (commit + hash re-bind, "sound") for threading
//! `prev_account`/ProofData across the IVC chain. This probe determines empirically
//! whether Option 1 is achievable at all.
//!
//! A recursion layer is a `p3-circuit` CircuitBuilder verifier circuit proved with
//! batch-stark. To thread a value via Option 1 it would have to surface as a
//! constrainable `air_public_target` in the NEXT layer. Two avenues:
//!   * Avenue 1 (CircuitBuilder public input): already shown dead by
//!     `probe_d_multilayer_carry` — `air_public_targets = [0,0,0]` (CircuitBuilder
//!     public inputs live in the committed Public table, not as AIR public values).
//!   * Avenue 2 (inject via `RecursionInput::BatchStark.table_public_inputs`): tested
//!     here. `into_recursion_input` zeroes this; we instead pass a NON-empty value
//!     claiming the counter, and check whether the layer can be built/proved.
//!
//! RESULT (pinned): Avenue 2 also fails — you cannot inject public inputs the proof
//! does not structurally have. Combined with `probe_d_multilayer_carry`, **Option 1
//! is not feasible on this rev**; Option 2 (commit + hash re-bind) is the only path.
//! This is escalated as a hard Phase-5 architecture finding.

use p3_recursion::{BatchOnly, ProveNextLayerParams, RecursionInput, build_and_prove_next_layer};
use p3_test_utils::goldilocks_params::F;
use plonky3_recursion_spike::goldilocks_rec::{
    ConfigWithFriParams, config_with_fri_params, default_fri_params, goldilocks_backend,
    prove_base_counter,
};

#[test]
fn probe_h_option1_air_public_values() {
    use p3_field::PrimeCharacteristicRing;

    let fp = default_fri_params();
    let config = config_with_fri_params(&fp);
    let backend = goldilocks_backend();

    // Layer 0: base counter proof committing to step count = 8 (a CircuitBuilder
    // public input). We want to thread "8" forward as an AIR public value.
    let output = prove_base_counter(8, &config, &fp);
    let num_tables = output.0.proof.opened_values.instances.len();

    // Sanity: the honest (empty) input that the high-level chain uses builds fine.
    let honest = output.into_recursion_input::<BatchOnly>();
    let params = ProveNextLayerParams::default();
    build_and_prove_next_layer::<ConfigWithFriParams, BatchOnly, _, 2>(
        &honest, &config, &backend, &params,
    )
    .expect("the honest empty-PI layer must build+prove");

    // Avenue 2: try to INJECT a non-empty public input claiming the counter value,
    // so the next layer could read it as an air_public_target. Put "8" on table 0.
    let mut injected: Vec<Vec<F>> = vec![vec![]; num_tables];
    injected[0] = vec![F::from_u64(8)];
    let tampered: RecursionInput<'_, ConfigWithFriParams, BatchOnly> = RecursionInput::BatchStark {
        proof: &output.0,
        common_data: &output.0.stark_common,
        table_public_inputs: injected,
    };

    let result = build_and_prove_next_layer::<ConfigWithFriParams, BatchOnly, _, 2>(
        &tampered, &config, &backend, &params,
    );

    // Option 1 verdict: you cannot inject a public input the batch proof does not
    // structurally carry — the layer build/prove must reject the mismatched count.
    assert!(
        result.is_err(),
        "Option 1 expectation: injecting a non-existent public input must fail \
         (the value cannot be surfaced as an AIR public value). If this ever SUCCEEDS, \
         Option 1 may have become viable on a new rev — revisit the Phase-1 decision."
    );
}
