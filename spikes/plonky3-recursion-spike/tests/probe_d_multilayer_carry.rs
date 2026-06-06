//! Probe D (part 2) — does a public input CARRY across a batch-recursion layer?
//!
//! Probe D part 1 proved the threading-binding primitive at a uni-stark
//! verification boundary. The remaining gate-critical question for a real
//! multi-layer IVC chain: when an outer layer verifies an inner BATCH proof, are
//! the inner circuit's public inputs exposed as constrained `air_public_targets`
//! (so the value can be threaded onward), or are they zeroed?
//!
//! This matters because Plonky2 cyclic recursion threads public inputs natively
//! (that is how zkCoins' ProofData / prev_account propagates). We verify a base
//! counter circuit (which has a public input = its step count) via the lower-level
//! `verify_p3_batch_proof_circuit` and inspect `air_public_targets`.

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{GoldilocksD2Width8, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit_prover::TableProver;
use p3_lookup::logup::LogUpGadget;
use p3_recursion::Poseidon2Config;
use p3_recursion::pcs::fri::{InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::verifier::verify_p3_batch_proof_circuit;
use p3_test_utils::goldilocks_params::{
    Challenge, DIGEST_ELEMS, F, MyCompress, MyHash, RATE, WIDTH,
};
use plonky3_recursion_spike::goldilocks_rec::{
    ConfigWithFriParams, InnerFri, config_with_fri_params, create_fri_verifier_params,
    default_fri_params, prove_base_counter,
};

const TRACE_D: usize = 1;

#[test]
fn probe_d_multilayer_carry() {
    let fp = default_fri_params();
    let config = config_with_fri_params(&fp);

    // Base layer: a counter circuit with ONE public input = step count (8).
    let output = prove_base_counter(8, &config, &fp);
    let common = output.1.common_data();

    // Build an outer circuit that verifies the base BATCH proof.
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        plonky3_recursion_spike::goldilocks_rec::default_goldilocks_poseidon2_8(),
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let fri_params = create_fri_verifier_params(&fp);
    let lookup_gadget = LogUpGadget::new();
    // The base counter circuit has no Poseidon2/recompose NPO tables, so no NPO
    // provers are needed to verify it.
    let provers: Vec<Box<dyn TableProver<ConfigWithFriParams>>> = vec![];

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
        &output.0,
        &fri_params,
        common,
        &lookup_gadget,
        Poseidon2Config::GOLDILOCKS_D2_W8,
        &provers,
    )
    .expect("build batch verifier circuit");

    let counts: Vec<usize> = verifier_inputs
        .air_public_targets
        .iter()
        .map(|t| t.len())
        .collect();
    let total: usize = counts.iter().sum();
    eprintln!("probe_d_carry: per-table air_public_targets counts = {counts:?}, total = {total}");

    // EMPIRICAL FINDING (pinned): when an outer layer verifies an inner BATCH proof
    // of a `CircuitBuilder` circuit, the inner circuit's public inputs are NOT
    // surfaced as constrainable `air_public_targets` — every per-table count is 0.
    //
    // Consequence: the high-level batch-recursion chain (Probe A's shape, via
    // `into_recursion_input` which also zeroes `table_public_inputs`) does NOT
    // propagate a public input across layers. This DIFFERS from Plonky2 cyclic
    // recursion, which threads public inputs natively (how zkCoins' ProofData /
    // prev_account propagates today). The threading *binding* primitive works at a
    // uni-stark verification boundary (see `probe_d_pi_threading`), but composing it
    // across the full IVC chain needs a construction that re-exposes the threaded
    // value at each layer. This is escalated to the operator as a gate-relevant,
    // protocol-touching characteristic — NOT silently treated as solved.
    assert_eq!(
        total, 0,
        "observed inner public inputs are NOT exposed across a batch layer; if this \
         becomes non-zero upstream, the multi-layer threading story changes — revisit"
    );
}
