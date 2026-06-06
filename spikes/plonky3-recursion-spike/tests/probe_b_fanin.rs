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
//! SCOPE — what this probe does and does NOT prove. It proves the load-bearing
//! capability: 2-to-1 aggregation of same-AIR batch proofs works and composes into
//! a FIXED-SHAPE tree (fan-in-4 here; fan-in-8 is one more level). It does NOT
//! exercise variable active count: all four leaves are real, identical proofs, no
//! per-leaf PI is surfaced, and no active bit is masked. The variable-active-count
//! strategy — pad inactive slots with real proofs and mask them via an active bit
//! in the CONSUMER circuit (the §7.17 `select_hash` pattern, whose binding
//! primitive is proven in `probe_c_vk_binding`) — is Phase-5 construction and is
//! NOT demonstrated by this spike. It is carried as a Phase-5 risk in the memo.

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

    // 4 real leaves, identical shape so the two level-1 aggregates have identical
    // shape at level 2. (No leaf is "inactive" here — variable active count is out
    // of scope for this probe; see the module doc.)
    let o_a = prove_base_counter(8, &config, &fp);
    let o_b = prove_base_counter(8, &config, &fp);
    let o_c = prove_base_counter(8, &config, &fp);
    let o_d = prove_base_counter(8, &config, &fp);

    // Level 1: two 2-to-1 aggregations.
    let agg_ab = aggregate_two(&o_a, &o_b, &config, &backend, &params);
    let agg_cd = aggregate_two(&o_c, &o_d, &config, &backend, &params);

    // Level 2: aggregate the two aggregates into a single fan-in-4 root proof.
    let agg_root = aggregate_two(&agg_ab, &agg_cd, &config, &backend, &params);

    // PASS: the fan-in-4 root proof verifies.
    verify_recursion_output(&agg_root, &config, &params.table_packing)
        .expect("fan-in-4 aggregation root must verify");
}
