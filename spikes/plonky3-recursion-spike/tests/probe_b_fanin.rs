//! Probe B — fan-in aggregation with variable active count (MIGRATION_PLONKY3.md §5, P0-T3).
//!
//! The doc flags this as the most likely blocker: `p3-recursion`'s aggregation is
//! strictly 2-to-1, with NO native "conditionally verify proof or dummy" primitive.
//! This probe answers the load-bearing questions:
//!   * Does 2-to-1 aggregation of two same-AIR batch proofs verify, with per-leaf
//!     proofs surfacing? (the fan-in primitive)
//!   * Does it COMPOSE into a fixed-shape tree (depth-2 here = fan-in-4; the zkCoins
//!     MAX_IN_COINS=8 case is one more level, depth-3)?
//!
//! Variable active count: since there is no conditional-verify, an "inactive" slot
//! is padded with a real (cheap) proof, and the active/inactive distinction is
//! carried as a public input and masked in the CONSUMER circuit (see Probe C and
//! MIGRATION_RESEARCH.md §7.17) — NOT inside the aggregation. This probe includes
//! one such padding leaf to show the mechanism.

use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_recursion::ProveNextLayerParams;
use plonky3_recursion_spike::goldilocks_rec::{
    aggregate_two, config_with_fri_params, default_fri_params, goldilocks_backend,
    prove_base_counter, verify_recursion_output,
};

#[test]
fn probe_b_fanin() {
    let fp = default_fri_params();
    let config = config_with_fri_params(&fp);
    let backend = goldilocks_backend();
    let params = ProveNextLayerParams {
        table_packing: TablePacking::new(1, 3)
            .with_fri_params(fp.log_final_poly_len, fp.log_blowup)
            .with_npo_lanes(NpoTypeId::recompose(), 1),
        constraint_profile: ConstraintProfile::Standard,
    };

    // 4 leaves. Leaf d is a padding/"inactive slot" proof (still a real proof —
    // there is no conditional-verify primitive). All leaves share the same circuit
    // shape so the two level-1 aggregates have identical shape at level 2.
    let o_a = prove_base_counter(8, &config, &fp);
    let o_b = prove_base_counter(8, &config, &fp);
    let o_c = prove_base_counter(8, &config, &fp);
    let o_d_padding = prove_base_counter(8, &config, &fp);

    // Level 1: two 2-to-1 aggregations.
    let agg_ab = aggregate_two(&o_a, &o_b, &config, &backend, &params);
    let agg_cd = aggregate_two(&o_c, &o_d_padding, &config, &backend, &params);

    // Level 2: aggregate the two aggregates into a single fan-in-4 root proof.
    let agg_root = aggregate_two(&agg_ab, &agg_cd, &config, &backend, &params);

    // PASS: the fan-in-4 root proof verifies.
    verify_recursion_output(&agg_root, &config, &params.table_packing)
        .expect("fan-in-4 aggregation root must verify");
}
