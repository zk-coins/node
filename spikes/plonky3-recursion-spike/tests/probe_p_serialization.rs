//! Probe P — proof serialization round-trip (node-integration property).
//!
//! The node persists proof blobs (`MIGRATION_PLONKY3.md` Phase 6 P6-T3). This probe —
//! not one of the original six, added because it's a real checkable property they don't
//! cover — confirms a recursion proof survives a bincode serialize → deserialize round
//! trip byte-for-byte AND still verifies, and that a truncated blob is rejected.

use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::batch_stark_prover::BatchStarkProof;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_recursion::{BatchOnly, ProveNextLayerParams, build_next_layer_circuit, prove_next_layer};
use plonky3_recursion_spike::goldilocks_rec::{
    ConfigWithFriParams, config_with_fri_params, default_fri_params, goldilocks_backend,
    prove_base_counter, verify_batch_proof, verify_recursion_output,
};

#[test]
fn probe_p_serialization() {
    let fp = default_fri_params();
    let config = config_with_fri_params(&fp);
    let backend = goldilocks_backend();
    let params = ProveNextLayerParams {
        table_packing: TablePacking::new(1, 3)
            .with_fri_params(fp.log_final_poly_len, fp.log_blowup)
            .with_npo_lanes(NpoTypeId::recompose(), 1),
        constraint_profile: ConstraintProfile::Standard,
    };

    // A representative recursion proof.
    let output = prove_base_counter(8, &config, &fp);
    let input = output.into_recursion_input::<BatchOnly>();
    let (vc, vr) =
        build_next_layer_circuit::<ConfigWithFriParams, BatchOnly, _, 2>(&input, &config, &backend)
            .expect("build layer");
    let out = prove_next_layer::<ConfigWithFriParams, BatchOnly, _, 2>(
        &input, &vc, &vr, &config, &backend, &params, None,
    )
    .expect("prove layer");
    verify_recursion_output(&out, &config, &params.table_packing).expect("baseline verify");

    // Serialize → deserialize → re-serialize: byte-stable round trip.
    let bytes = bincode::serialize(&out.0).expect("serialize proof");
    assert!(!bytes.is_empty(), "serialized proof must be non-empty");
    let proof2: BatchStarkProof<ConfigWithFriParams> =
        bincode::deserialize(&bytes).expect("deserialize proof");
    let bytes2 = bincode::serialize(&proof2).expect("re-serialize");
    assert_eq!(
        bytes, bytes2,
        "serialization round-trip must be byte-stable"
    );

    // The deserialized proof still verifies.
    verify_batch_proof(&proof2, &config, &params.table_packing)
        .expect("deserialized proof must still verify");

    // NEGATIVE: a truncated blob must not deserialize into a usable proof.
    let truncated = &bytes[..bytes.len() / 2];
    assert!(
        bincode::deserialize::<BatchStarkProof<ConfigWithFriParams>>(truncated).is_err(),
        "a truncated proof blob must be rejected on deserialization"
    );

    eprintln!(
        "probe_p: recursion proof serialized to {} bytes; round-trips byte-stable + verifies",
        bytes.len()
    );
}
