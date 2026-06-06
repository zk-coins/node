//! Probe I — real-circuit-sized cost projection.
//!
//! The toy bench (`probe_a_ivc`) measured the recursion-layer cost over a TRIVIAL
//! inner proof (~8 gates): ≈4.65 s/stabilized layer, ≈1 GB. The real zkCoins
//! state-transition circuit is far larger: ≈2^16 rows / ≈50k gates / ≈4500 Poseidon
//! hashes, with a measured Plonky2 warm-prove of 4.35 s p50 / 3.9 GB RSS on M5 Max
//! (`scripts/bench/results/m5-max-2026-06-02-probe_r2.json`; `MIGRATION_RESEARCH.md`
//! §7.17). The warm-prove budget is ≤5 s warm / ≤1 s ideal / <64 GB.
//!
//! This probe scales the recursion-layer measurement up to a real-sized inner proof
//! (a ≈2^16-gate base circuit) and reports the per-layer prove time + circuit size,
//! so the Phase-5 recursion overhead can be projected against the budget. Run under
//! `/usr/bin/time -l` to capture peak RSS.
//!
//! Honest caveat: the synthetic base is an ARITHMETIC (counter-add) circuit of the
//! target gate count. The real circuit's constraints are Poseidon-heavy (heavier per
//! row), so these numbers are an indicative recursion-overhead FLOOR for that size,
//! not a full replica of the real prove cost (which is already measured at 4.35 s).

use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_recursion::{BatchOnly, ProveNextLayerParams, build_next_layer_circuit, prove_next_layer};
use plonky3_recursion_spike::goldilocks_rec::{
    ConfigWithFriParams, config_with_fri_params, default_fri_params, goldilocks_backend,
    prove_base_counter, verify_recursion_output,
};

/// Measure: base-proof prove time, first recursion-layer witness_count + prove time,
/// for a base circuit of `gates` arithmetic gates.
fn measure(gates: u64) {
    let fp = default_fri_params();
    let config = config_with_fri_params(&fp);
    let backend = goldilocks_backend();

    let t0 = std::time::Instant::now();
    let output = prove_base_counter(gates, &config, &fp);
    let base_ms = t0.elapsed().as_millis();

    let layer_table_packing = TablePacking::new(1, 3)
        .with_fri_params(fp.log_final_poly_len, fp.log_blowup)
        .with_npo_lanes(NpoTypeId::recompose(), 1);
    let params = ProveNextLayerParams {
        table_packing: layer_table_packing,
        constraint_profile: ConstraintProfile::Standard,
    };

    let input = output.into_recursion_input::<BatchOnly>();
    let (vc, vr) =
        build_next_layer_circuit::<ConfigWithFriParams, BatchOnly, _, 2>(&input, &config, &backend)
            .expect("build layer");
    let wc = vc.witness_count;

    let t1 = std::time::Instant::now();
    let out = prove_next_layer::<ConfigWithFriParams, BatchOnly, _, 2>(
        &input, &vc, &vr, &config, &backend, &params, None,
    )
    .expect("prove layer");
    let layer_ms = t1.elapsed().as_millis();

    verify_recursion_output(&out, &config, &params.table_packing).expect("verify layer");

    eprintln!(
        "probe_i: base_gates={gates} base_prove_ms={base_ms} layer1_witness_count={wc} layer1_prove_ms={layer_ms}"
    );
}

#[test]
fn probe_i_cost_projection() {
    // Toy (matches probe_a scale) and real-sized (~2^16 gates ≈ the real state
    // transition) to show how the recursion-layer cost scales with inner-proof size.
    measure(1 << 4);
    measure(1 << 12);
    measure(1 << 16);
}
