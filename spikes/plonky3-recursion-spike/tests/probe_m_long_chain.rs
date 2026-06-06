//! Probe M — long IVC chains (depth 50).
//!
//! `probe_a_ivc` validated the fixed point over 4 layers. This probe drives a 50-layer
//! recursion chain to confirm the constant-shape fixed-point assumption HOLDS AT DEPTH
//! (the verifier-circuit `witness_count` stays constant once stabilised, with no slow
//! drift), every layer verifies, and to measure cumulative prove latency. Run under
//! `/usr/bin/time -l` for peak RSS. Slow by design.

use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_recursion::{BatchOnly, ProveNextLayerParams, build_next_layer_circuit, prove_next_layer};
use plonky3_recursion_spike::goldilocks_rec::{
    ConfigWithFriParams, config_with_fri_params, default_fri_params, goldilocks_backend,
    prove_base_counter, verify_recursion_output,
};

#[test]
fn probe_m_long_chain() {
    const DEPTH: usize = 50;
    let fp = default_fri_params();
    let config = config_with_fri_params(&fp);
    let backend = goldilocks_backend();
    let params = ProveNextLayerParams {
        table_packing: TablePacking::new(1, 3)
            .with_fri_params(fp.log_final_poly_len, fp.log_blowup)
            .with_npo_lanes(NpoTypeId::recompose(), 1),
        constraint_profile: ConstraintProfile::Standard,
    };

    let mut output = prove_base_counter(8, &config, &fp);
    let mut witness_counts: Vec<u32> = Vec::with_capacity(DEPTH);
    let t0 = std::time::Instant::now();

    for layer in 1..=DEPTH {
        let input = output.into_recursion_input::<BatchOnly>();
        let (vc, vr) = build_next_layer_circuit::<ConfigWithFriParams, BatchOnly, _, 2>(
            &input, &config, &backend,
        )
        .unwrap_or_else(|e| panic!("build layer {layer}: {e:?}"));
        witness_counts.push(vc.witness_count);
        let out = prove_next_layer::<ConfigWithFriParams, BatchOnly, _, 2>(
            &input, &vc, &vr, &config, &backend, &params, None,
        )
        .unwrap_or_else(|e| panic!("prove layer {layer}: {e:?}"));
        // EVERY layer must verify.
        verify_recursion_output(&out, &config, &params.table_packing)
            .unwrap_or_else(|e| panic!("verify layer {layer}: {e}"));
        output = out;
    }

    let total_s = t0.elapsed().as_secs_f64();
    let last = *witness_counts.last().unwrap();
    let stable_from = witness_counts
        .iter()
        .position(|&w| w == last)
        .expect("a fixed point exists");

    // The fixed point must be reached early and then hold CONSTANT all the way to
    // depth 50 — no unbounded growth, no slow drift.
    assert!(
        stable_from <= 5,
        "fixed point should stabilise within ~5 layers; counts = {witness_counts:?}"
    );
    assert!(
        witness_counts[stable_from..].iter().all(|&w| w == last),
        "the IVC fixed point must hold constant to depth {DEPTH}; counts = {witness_counts:?}"
    );

    eprintln!(
        "probe_m: depth={DEPTH} stabilised_at_layer={} fixed_witness_count={last} \
         total_prove_s={total_s:.1} per_layer_avg_s={:.2}",
        stable_from + 1,
        total_s / DEPTH as f64
    );
}
