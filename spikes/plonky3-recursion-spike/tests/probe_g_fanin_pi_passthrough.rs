//! Probe G — per-leaf PI passthrough from a REAL aggregation (the integrated
//! fan-in-8 prerequisite).
//!
//! P0-T3's full form needs the per-leaf ProofData of the source-aggregator to
//! surface in the OUTER state-transition circuit, where inactive slots are masked
//! (§7.17, proved standalone in `probe_e_active_masking`). The load-bearing question:
//! can the per-leaf public inputs of a REAL 2-to-1 aggregation be read by the outer
//! circuit that verifies the aggregation proof?
//!
//! An aggregation output is itself a batch proof of a CircuitBuilder verifier
//! circuit. Per Probes D/H, such proofs expose NO public inputs as `air_public_targets`.
//! This probe confirms it for the aggregation case directly: aggregate two leaves with
//! DISTINCT committed values (8 and 5), verify the aggregation proof in an outer
//! circuit, and assert the leaf values are NOT recoverable (`air_public_targets`
//! total == 0).
//!
//! RESULT (pinned): the per-leaf PIs do NOT pass through. Building the full
//! integrated fan-in-8 is therefore blocked at the first cross-layer hop — the same
//! Phase-5 limitation as Probe H. Escalated; the masking (Probe E) must consume the
//! per-leaf values via the Option-2 (commit + re-bind) construction, not via
//! aggregation public inputs.

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::NpoTypeId;
use p3_circuit::ops::{GoldilocksD2Width8, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit_prover::TableProver;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_lookup::logup::LogUpGadget;
use p3_recursion::pcs::fri::{InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::verifier::verify_p3_batch_proof_circuit;
use p3_recursion::{PcsRecursionBackend, Poseidon2Config, ProveNextLayerParams};
use p3_test_utils::goldilocks_params::{
    Challenge, DIGEST_ELEMS, F, MyCompress, MyHash, RATE, WIDTH,
};
use plonky3_recursion_spike::goldilocks_rec::{
    ConfigWithFriParams, InnerFri, aggregate_two, config_with_fri_params,
    create_fri_verifier_params, default_fri_params, default_goldilocks_poseidon2_8,
    goldilocks_backend, prove_base_counter,
};

// The aggregation output is a recursion layer proved over the degree-2 extension,
// so its `proof.ext_degree` is 2 (vs 1 for a base proof).
const TRACE_D: usize = 2;

#[test]
fn probe_g_fanin_pi_passthrough() {
    let fp = default_fri_params();
    let config = config_with_fri_params(&fp);
    let backend = goldilocks_backend();
    let params = ProveNextLayerParams {
        table_packing: TablePacking::new(1, 3)
            .with_fri_params(fp.log_final_poly_len, fp.log_blowup)
            .with_npo_lanes(NpoTypeId::recompose(), 1),
        constraint_profile: ConstraintProfile::Standard,
    };

    // Two leaves with DISTINCT committed values, aggregated for real (2-to-1).
    let o_a = prove_base_counter(8, &config, &fp);
    let o_b = prove_base_counter(5, &config, &fp);
    let agg = aggregate_two(&o_a, &o_b, &config, &backend, &params);
    let common = agg.1.common_data();

    // Verify the aggregation proof in an outer circuit and inspect air_public_targets.
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        default_goldilocks_poseidon2_8(),
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let fri_params = create_fri_verifier_params(&fp);
    let lookup_gadget = LogUpGadget::new();
    // The aggregation output has Poseidon2 + recompose NPO tables; get their provers
    // from the backend.
    let provers: Vec<Box<dyn TableProver<ConfigWithFriParams>>> = PcsRecursionBackend::<
        ConfigWithFriParams,
        p3_recursion::BatchOnly,
        2,
    >::non_primitive_provers(
        &backend, 2
    );

    let (verifier_inputs, _op_ids) = verify_p3_batch_proof_circuit::<
        ConfigWithFriParams,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        LogUpGadget,
        Poseidon2Config,
        WIDTH,
        RATE,
        TRACE_D,
    >(
        &config,
        &mut cb,
        &agg.0,
        &fri_params,
        common,
        &lookup_gadget,
        Poseidon2Config::GOLDILOCKS_D2_W8,
        &provers,
    )
    .expect("build aggregation-output verifier circuit");

    let total: usize = verifier_inputs
        .air_public_targets
        .iter()
        .map(|t| t.len())
        .sum();
    eprintln!("probe_g: aggregation-output air_public_targets total = {total}");

    // The per-leaf committed values (8, 5) are NOT exposed to the outer circuit.
    assert_eq!(
        total, 0,
        "per-leaf PIs from a real aggregation are NOT surfaced as air_public_targets; \
         the integrated fan-in-8 passthrough is blocked (Phase-5 Option-2 territory). \
         If this becomes non-zero on a new rev, the integrated passthrough may be viable."
    );
}
