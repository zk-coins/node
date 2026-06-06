//! Probe A — IVC / cyclic recursion with a base case (MIGRATION_PLONKY3.md §5, P0-T2).
//!
//! Maps the zkCoins `prev_account` cyclic-recursion pattern onto `p3-recursion`'s
//! layered `prove_next_layer` chain:
//!   * Layer 0 = base counter proof (NO predecessor — this is the base case).
//!   * Layer k>0 = a verifier circuit that verifies layer k-1's proof, itself proved.
//!
//! PASS (per the doc):
//!   1. the layer-N proof verifies, and
//!   2. the per-layer verifier-circuit shape reaches a CONSTANT fixed point (true
//!      IVC, no unbounded growth) — the `p3-recursion` analogue of Plonky2's
//!      `common_data_for_recursion` fixed point.

use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_recursion::{BatchOnly, ProveNextLayerParams, build_next_layer_circuit, prove_next_layer};
use plonky3_recursion_spike::goldilocks_rec::{
    ConfigWithFriParams, config_with_fri_params, default_fri_params, goldilocks_backend,
    prove_base_counter, verify_recursion_output,
};

#[test]
fn probe_a_ivc() {
    let fp = default_fri_params();
    let config = config_with_fri_params(&fp);
    let backend = goldilocks_backend();

    // Layer 0: the base case is simply a real proof with no predecessor — the
    // counter circuit proved with batch-stark. p3-recursion needs no special
    // "_or_dummy" base primitive: the chain just starts from a real proof.
    let mut output = prove_base_counter(8, &config, &fp);

    // Recompose NPO lanes (1) must match the backend's default; mirror the
    // upstream example's layer table-packing.
    let layer_table_packing = TablePacking::new(1, 3)
        .with_fri_params(fp.log_final_poly_len, fp.log_blowup)
        .with_npo_lanes(NpoTypeId::recompose(), 1);

    const NUM_LAYERS: usize = 4;
    let mut witness_counts: Vec<u32> = Vec::new();

    for layer in 1..=NUM_LAYERS {
        let params = ProveNextLayerParams {
            table_packing: layer_table_packing.clone(),
            constraint_profile: ConstraintProfile::Standard,
        };
        let input = output.into_recursion_input::<BatchOnly>();

        let (vc, vr) = build_next_layer_circuit::<ConfigWithFriParams, BatchOnly, _, 2>(
            &input, &config, &backend,
        )
        .unwrap_or_else(|e| panic!("build layer {layer} circuit: {e:?}"));
        witness_counts.push(vc.witness_count);

        let t = std::time::Instant::now();
        let out = prove_next_layer::<ConfigWithFriParams, BatchOnly, _, 2>(
            &input, &vc, &vr, &config, &backend, &params, None,
        )
        .unwrap_or_else(|e| panic!("prove layer {layer}: {e:?}"));
        let prove_ms = t.elapsed().as_millis();

        verify_recursion_output(&out, &config, &params.table_packing)
            .unwrap_or_else(|e| panic!("verify layer {layer}: {e}"));

        // P0-T5 diagnostics: per-layer verifier-circuit witness count + prove time.
        eprintln!(
            "probe_a layer {layer}: witness_count={} prove_ms={prove_ms}",
            vc.witness_count
        );

        output = out;
    }
    eprintln!("probe_a witness_counts = {witness_counts:?}");

    // PASS criterion 2: shape stabilises (constant per-layer shape => true IVC).
    let n = witness_counts.len();
    assert!(
        witness_counts[n - 1] == witness_counts[n - 2],
        "IVC verifier-circuit shape must reach a constant fixed point; \
         per-layer witness_counts = {witness_counts:?}"
    );
}
