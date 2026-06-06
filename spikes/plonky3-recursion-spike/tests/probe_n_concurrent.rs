//! Probe N — concurrent proving load.
//!
//! A real service proves many requests at once. This probe spawns 4 independent
//! proving workloads on separate threads — each proves a base circuit AND a recursion
//! layer, then verifies — and asserts every one succeeds. Validates the prover is
//! usable under concurrency (no shared-state corruption, no panics). Run under
//! `/usr/bin/time -l` to capture peak RSS across all 4 concurrent provers.

use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_recursion::{BatchOnly, ProveNextLayerParams, build_next_layer_circuit, prove_next_layer};
use plonky3_recursion_spike::goldilocks_rec::{
    ConfigWithFriParams, config_with_fri_params, default_fri_params, goldilocks_backend,
    prove_base_counter, verify_recursion_output,
};

/// One independent proving workload: base proof of `gates` + one recursion layer + verify.
fn workload(gates: u64) -> Result<u32, String> {
    let fp = default_fri_params();
    let config = config_with_fri_params(&fp);
    let backend = goldilocks_backend();

    let output = prove_base_counter(gates, &config, &fp);
    let params = ProveNextLayerParams {
        table_packing: TablePacking::new(1, 3)
            .with_fri_params(fp.log_final_poly_len, fp.log_blowup)
            .with_npo_lanes(NpoTypeId::recompose(), 1),
        constraint_profile: ConstraintProfile::Standard,
    };
    let input = output.into_recursion_input::<BatchOnly>();
    let (vc, vr) =
        build_next_layer_circuit::<ConfigWithFriParams, BatchOnly, _, 2>(&input, &config, &backend)
            .map_err(|e| format!("build: {e:?}"))?;
    let wc = vc.witness_count;
    let out = prove_next_layer::<ConfigWithFriParams, BatchOnly, _, 2>(
        &input, &vc, &vr, &config, &backend, &params, None,
    )
    .map_err(|e| format!("prove: {e:?}"))?;
    verify_recursion_output(&out, &config, &params.table_packing)
        .map_err(|e| format!("verify: {e}"))?;
    Ok(wc)
}

#[test]
fn probe_n_concurrent() {
    let sizes = [1u64 << 8, 1 << 9, 1 << 10, 1 << 11];
    let handles: Vec<_> = sizes
        .into_iter()
        .map(|g| std::thread::spawn(move || workload(g)))
        .collect();

    let mut ok = 0;
    for h in handles {
        let res = h.join().expect("worker thread must not panic");
        res.expect("each concurrent proving workload must verify");
        ok += 1;
    }
    assert_eq!(ok, 4, "all 4 concurrent provers must succeed");
    eprintln!("probe_n: 4 concurrent prove+recurse+verify workloads all succeeded");
}
