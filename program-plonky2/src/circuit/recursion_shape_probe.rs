//! Diagnostic probes for the Plonky2 1.1.0 `dummy_circuit` shape
//! mismatch (`MIGRATION_RESEARCH.md` §7.21 + §7.22).
//!
//! Builds Stage 5d-next-3's pass-3 common (1 `verify_proof`, no
//! aggregator) and a Stage 5d-next-5 candidate pass-3 common (2
//! `verify_proof`s — cyclic + aggregator), and dumps both `gates`
//! lists side-by-side along with whether `dummy_circuit` succeeds for
//! each. Intended to run as a one-shot `#[test]` so the gate-set
//! delta — which determines whether Phase 2a's outer integration can
//! land at all — is visible from a single command.
//!
//! Not part of the production circuit. Lives behind `#[cfg(test)]`.

#![cfg(test)]
#![cfg_attr(coverage_nightly, coverage(off))]

use plonky2::field::types::Field;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
use plonky2::recursion::dummy_circuit::dummy_circuit;

use crate::circuit::main::{MAX_IN_COINS, N_PROOF_DATA_PUBLIC_INPUTS};
use crate::circuit::source_aggregator::{
    build_source_aggregator_circuit, N_ST_VK_DIGEST_PIS, PER_SLOT_PIS,
};
use crate::{C, D, F};

/// Inner-circuit pad-bits Stage 5d-next-3 ships with.
const PAD_BITS_BASELINE: usize = 14;

/// Target num_public_inputs for the state-transition circuit:
/// 16 ProofData + 4 vk digest + 4 × cap_elements sigmas_cap.
fn st_num_pis() -> usize {
    let cap_elements = CircuitConfig::standard_recursion_config()
        .fri_config
        .num_cap_elements();
    16 + 4 + 4 * cap_elements
}

/// Stage 5d-next-3 pass-3 helper (one `verify_proof`, no aggregator).
/// Returns the produced common with `num_public_inputs` overridden to
/// 84 — the value the outer's `build_circuit` patches in before
/// passing to `_or_dummy`.
fn pass_3_one_verify() -> CommonCircuitData<F, D> {
    // Pass 1
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    // Pass 2: one verify_proof
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    // Pass 3: one verify_proof + pad
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << PAD_BITS_BASELINE {
        builder.add_gate(NoopGate, vec![]);
    }
    let mut common = builder.build::<C>().common;
    common.num_public_inputs = st_num_pis();
    common
}

/// Stage 5d-next-5 candidate pass-3 + `num_forced_constants`
/// distinct constants wired into harmless `builder.mul(c, zero)`
/// operations. Used to probe whether explicit constant pressure
/// forces `ConstantGate` emission. `0` means no forced constants
/// (equivalent to [`pass_3_two_verify`]).
///
/// **Conclusion from the first probe run:** this approach does NOT
/// work — every value of `num_forced_constants` from 1 up to 256 has
/// pass-3 absorbing the constants into existing `ArithmeticGate`
/// instances without ever emitting a standalone `ConstantGate`. The
/// function is kept as documented dead-end research; the working fix
/// is the explicit `ConstantGate::new(2)` injection in
/// [`pass_3_two_verify`]`(_, force_constant_gate = true)`.
#[allow(dead_code)]
fn pass_3_two_verify_forced(
    pad_bits: usize,
    num_forced_constants: usize,
) -> CommonCircuitData<F, D> {
    let bootstrap = pass_3_one_verify();
    let aggregator = build_source_aggregator_circuit(&bootstrap);

    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &vd, &data.common);
    let agg_proof = builder.add_virtual_proof_with_pis(&aggregator.data.common);
    let agg_vd =
        builder.add_virtual_verifier_data(aggregator.data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&agg_proof, &agg_vd, &aggregator.data.common);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &vd, &data.common);
    let agg_proof = builder.add_virtual_proof_with_pis(&aggregator.data.common);
    let agg_vd =
        builder.add_virtual_verifier_data(aggregator.data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&agg_proof, &agg_vd, &aggregator.data.common);

    // Forced constants: each `builder.constant` returns a virtual
    // target tied to a compile-time value; using it in a `mul` with
    // zero (= a no-op arithmetic op that nevertheless references the
    // constant target) prevents the optimiser from eliding it.
    if num_forced_constants > 0 {
        let zero = builder.zero();
        for i in 0..num_forced_constants {
            // Distinct values force distinct constant targets.
            let c = builder.constant(F::from_canonical_u64(0xdead_beef_0000_0000u64 ^ i as u64));
            let _ = builder.mul(c, zero);
        }
    }

    while builder.num_gates() < 1 << pad_bits {
        builder.add_gate(NoopGate, vec![]);
    }
    let mut common = builder.build::<C>().common;
    common.num_public_inputs = st_num_pis();
    common
}

/// Stage 5d-next-5 candidate pass-3: two `verify_proof`s (one cyclic,
/// one against the aggregator's common). Returns common with
/// `num_public_inputs` overridden to 84.
///
/// `force_constant_gate = true` adds one explicit `ConstantGate{num_consts: 2}`
/// instance in pass-3 just before the noop pad. The purpose is to
/// ensure pass-3's `gates` list includes `ConstantGate` even when the
/// caller's two `verify_proof` calls have produced enough
/// `ArithmeticGate` instances to absorb all constant pressure (the
/// 1-verify baseline naturally emits one; the 2-verify candidate
/// doesn't — see the probe summary).
fn pass_3_two_verify(pad_bits: usize, force_constant_gate: bool) -> CommonCircuitData<F, D> {
    // Bootstrap aggregator against pass-3-one-verify shape (the
    // working Stage 5d-next-3 baseline). The aggregator's
    // `dummy_circuit(st_common)` succeeds for this baseline shape, so
    // the bootstrap build is safe.
    let bootstrap = pass_3_one_verify();
    let aggregator = build_source_aggregator_circuit(&bootstrap);

    // Pass 1
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    // Pass 2: cyclic verify + aggregator verify
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &vd, &data.common);
    let agg_proof = builder.add_virtual_proof_with_pis(&aggregator.data.common);
    let agg_vd =
        builder.add_virtual_verifier_data(aggregator.data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&agg_proof, &agg_vd, &aggregator.data.common);
    let data = builder.build::<C>();

    // Pass 3: same shape + optional explicit ConstantGate + pad
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &vd, &data.common);
    let agg_proof = builder.add_virtual_proof_with_pis(&aggregator.data.common);
    let agg_vd =
        builder.add_virtual_verifier_data(aggregator.data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&agg_proof, &agg_vd, &aggregator.data.common);
    if force_constant_gate {
        // Inject one ConstantGate{num_consts:2} instance so the gates
        // list mirrors what `dummy_circuit`'s rebuild produces (the
        // rebuild always allocates a ConstantGate for its PI-handling
        // constants). The two slots hold trivial zeros — the gate
        // instance is the point, not the constants themselves.
        builder.add_gate(ConstantGate::new(2), vec![F::ZERO, F::ZERO]);
    }
    while builder.num_gates() < 1 << pad_bits {
        builder.add_gate(NoopGate, vec![]);
    }
    let mut common = builder.build::<C>().common;
    common.num_public_inputs = st_num_pis();
    common
}

fn dump_summary(label: &str, c: &CommonCircuitData<F, D>) {
    println!("\n=== {label} ===");
    println!(
        "  degree_bits = {}, num_public_inputs = {}, num_constants = {}",
        c.fri_params.degree_bits, c.num_public_inputs, c.num_constants
    );
    println!("  gates ({}):", c.gates.len());
    for (i, g) in c.gates.iter().enumerate() {
        println!("    [{i:2}] {}", g.0.id());
    }
    // SelectorsInfo's `selector_indices` and `groups` are private. Use
    // the public Debug impl.
    println!("  selectors_info: {:?}", c.selectors_info);
}

fn try_dummy_circuit(label: &str, c: &CommonCircuitData<F, D>) -> bool {
    use std::panic::AssertUnwindSafe;
    println!("\n--- dummy_circuit({label}) attempt ---");
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = dummy_circuit::<F, C, D>(c);
    }));
    let ok = result.is_ok();
    println!("  → {}", if ok { "OK" } else { "PANIC (shape mismatch)" });
    ok
}

#[test]
fn dump_pass_3_gates_lists_for_inspection() {
    let baseline = pass_3_one_verify();
    dump_summary("Stage 5d-next-3 baseline (1 verify, pad 14)", &baseline);
    let ok_baseline = try_dummy_circuit("baseline", &baseline);

    let two_verify_pad14 = pass_3_two_verify(14, false);
    dump_summary(
        "Phase 2a candidate (2 verify, pad 14, no forced ConstantGate)",
        &two_verify_pad14,
    );
    let ok_2v_14 = try_dummy_circuit("2-verify pad 14", &two_verify_pad14);

    // The decisive test: same shape, but with one explicit
    // `ConstantGate` instance injected into pass-3 so its gates list
    // matches `dummy_circuit`'s rebuild.
    let two_verify_pad14_cg = pass_3_two_verify(14, true);
    dump_summary(
        "Phase 2a candidate (2 verify, pad 14, +ConstantGate)",
        &two_verify_pad14_cg,
    );
    let ok_2v_14_cg = try_dummy_circuit("2-verify pad 14 +CG", &two_verify_pad14_cg);

    println!(
        "\n=== summary === baseline_ok={ok_baseline}, 2v_14={ok_2v_14}, 2v_14_with_constant_gate={ok_2v_14_cg}"
    );
}

/// Minimal outer that mimics the Phase-2a structure WITHOUT the
/// Stage 5d-next-3 constraint gates (SMT/CMP/in-coin/out-coin) — just
/// the new bits: PI registration, `verify_proof(aggregator)`,
/// `connect_hashes` for vk binding, explicit `ConstantGate` injection,
/// and the cyclic `_or_dummy` at the end. Used by the diagnostic
/// below to identify which `CommonCircuitData` axis diverges between
/// helper-pass-3 and outer's actual built common.
///
/// `common_data` is the helper-pass-3 output that the `_or_dummy`
/// call uses as its goal data. The test below extracts the actual
/// outer.common via `try_build_with_options` and diffs against it.
fn build_minimal_outer_for_diagnostic(
    aggregator_data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    mut common_data: CommonCircuitData<F, D>,
) -> (CommonCircuitData<F, D>, CommonCircuitData<F, D>, bool) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Register ProofData public inputs first.
    for _ in 0..N_PROOF_DATA_PUBLIC_INPUTS {
        builder.add_virtual_public_input();
    }

    // Cyclic verifier_data target (this also registers the cyclic vk PIs).
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();

    // verify_proof(aggregator) + connect_hashes for vk binding.
    let agg_proof = builder.add_virtual_proof_with_pis(&aggregator_data.common);
    let agg_vd = builder.constant_verifier_data(&aggregator_data.verifier_only);
    builder.verify_proof::<C>(&agg_proof, &agg_vd, &aggregator_data.common);

    let st_vk_offset = MAX_IN_COINS * PER_SLOT_PIS;
    let claimed_st_digest = HashOutTarget {
        elements: [
            agg_proof.public_inputs[st_vk_offset],
            agg_proof.public_inputs[st_vk_offset + 1],
            agg_proof.public_inputs[st_vk_offset + 2],
            agg_proof.public_inputs[st_vk_offset + 3],
        ],
    };
    builder.connect_hashes(claimed_st_digest, verifier_data_target.circuit_digest);

    let sigmas_cap_offset = st_vk_offset + N_ST_VK_DIGEST_PIS;
    for (i, cap_hash) in verifier_data_target
        .constants_sigmas_cap
        .0
        .iter()
        .enumerate()
    {
        let base = sigmas_cap_offset + 4 * i;
        let claimed = HashOutTarget {
            elements: [
                agg_proof.public_inputs[base],
                agg_proof.public_inputs[base + 1],
                agg_proof.public_inputs[base + 2],
                agg_proof.public_inputs[base + 3],
            ],
        };
        builder.connect_hashes(claimed, *cap_hash);
    }

    // Explicit ConstantGate injection (matches helper-pass-3's
    // injection so the gates list has ConstantGate).
    builder.add_gate(ConstantGate::new(2), vec![F::ZERO, F::ZERO]);

    // Cyclic verification — sets `goal_common_data = common_data`.
    let condition = builder.add_virtual_bool_target_safe();
    let inner_proof_target = builder.add_virtual_proof_with_pis(&common_data);
    builder
        .conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &inner_proof_target,
            &common_data,
        )
        .expect("conditionally_verify_cyclic_proof_or_dummy: well-formed");

    // try_build returns (data, success). success=false signals the
    // goal_data check failed — but the resulting data.common still
    // tells us what the outer ACTUALLY built.
    let (data, success) = builder.try_build_with_options::<C>(true);
    (common_data, data.common, success)
}

fn print_field_diff<T: std::fmt::Debug + PartialEq>(name: &str, a: &T, b: &T) {
    if a != b {
        println!("    [DIFF] {name}:");
        println!("        helper  = {a:?}");
        println!("        outer   = {b:?}");
    } else {
        println!("    [ok  ] {name}: same");
    }
}

/// Inner of the diagnostic: builds helper-pass-3 and minimal outer at
/// the given pad_bits and reports if try_build succeeds + degree
/// comparison. Returns (helper_degree, outer_degree, success).
fn diag_at_pad_bits(pad_bits: usize) -> (usize, usize, bool) {
    let mut bootstrap = pass_3_one_verify();
    bootstrap.num_public_inputs = st_num_pis();
    let _agg_v0 = build_source_aggregator_circuit(&bootstrap);

    let helper_common = pass_3_two_verify(pad_bits, true);
    let mut helper_for_agg = helper_common.clone();
    helper_for_agg.num_public_inputs = st_num_pis();
    let agg_v1 = build_source_aggregator_circuit(&helper_for_agg);

    let (helper_common_final, outer_common, success) =
        build_minimal_outer_for_diagnostic(&agg_v1.data, helper_for_agg.clone());

    (
        helper_common_final.fri_params.degree_bits,
        outer_common.fri_params.degree_bits,
        success,
    )
}

#[test]
#[ignore = "diagnostic only; rebuilds full outer + aggregator twice"]
fn dump_phase_2a_outer_vs_helper_diff() {
    // Step 1: bootstrap aggregator against Stage 5d-next-3 shape.
    let mut bootstrap = pass_3_one_verify();
    bootstrap.num_public_inputs = st_num_pis();
    let _agg_v0 = build_source_aggregator_circuit(&bootstrap);

    // Step 2: compute helper-pass-3 common with aggregator + ConstantGate.
    let helper_common = pass_3_two_verify(16, true);

    // Step 3: rebuild aggregator against the helper-pass-3 common so
    // its source-proof targets are sized correctly.
    let mut helper_for_agg = helper_common.clone();
    helper_for_agg.num_public_inputs = st_num_pis();
    let agg_v1 = build_source_aggregator_circuit(&helper_for_agg);

    // Step 4: build the minimal outer with _or_dummy(helper-pass-3).
    let (helper_common_final, outer_common, success) =
        build_minimal_outer_for_diagnostic(&agg_v1.data, helper_for_agg.clone());

    println!("\n=== Phase 2a outer-vs-helper diagnostic (try_build success = {success}) ===");

    print_field_diff("config", &helper_common_final.config, &outer_common.config);
    print_field_diff(
        "fri_params.degree_bits",
        &helper_common_final.fri_params.degree_bits,
        &outer_common.fri_params.degree_bits,
    );
    print_field_diff(
        "fri_params.hiding",
        &helper_common_final.fri_params.hiding,
        &outer_common.fri_params.hiding,
    );
    print_field_diff(
        "fri_params.reduction_arity_bits",
        &helper_common_final.fri_params.reduction_arity_bits,
        &outer_common.fri_params.reduction_arity_bits,
    );
    let helper_gate_ids: Vec<String> = helper_common_final.gates.iter().map(|g| g.0.id()).collect();
    let outer_gate_ids: Vec<String> = outer_common.gates.iter().map(|g| g.0.id()).collect();
    print_field_diff("gates (by id)", &helper_gate_ids, &outer_gate_ids);
    print_field_diff(
        "selectors_info",
        &format!("{:?}", helper_common_final.selectors_info),
        &format!("{:?}", outer_common.selectors_info),
    );
    print_field_diff(
        "quotient_degree_factor",
        &helper_common_final.quotient_degree_factor,
        &outer_common.quotient_degree_factor,
    );
    print_field_diff(
        "num_gate_constraints",
        &helper_common_final.num_gate_constraints,
        &outer_common.num_gate_constraints,
    );
    print_field_diff(
        "num_constants",
        &helper_common_final.num_constants,
        &outer_common.num_constants,
    );
    print_field_diff(
        "num_public_inputs",
        &helper_common_final.num_public_inputs,
        &outer_common.num_public_inputs,
    );
    print_field_diff("k_is", &helper_common_final.k_is, &outer_common.k_is);
    print_field_diff(
        "num_partial_products",
        &helper_common_final.num_partial_products,
        &outer_common.num_partial_products,
    );

    assert!(
        success,
        "Phase 2a outer-vs-helper diagnostic: try_build success was false — \
         a CommonCircuitData axis diverges. Check the [DIFF] lines above."
    );
}

/// Sweep helper-pass-3's `INNER_PAD_BITS` across {14, 15, 16, 17}
/// and report (helper_degree, outer_degree, success) for each. The
/// goal: find the pad-bits value at which helper-degree == minimal-
/// outer-degree (only condition `try_build` accepts). Once we know
/// which pad-bits matches the minimal outer's natural degree, the
/// FULL outer (with all Stage 5d-next-3 constraint gates) needs the
/// same pad — possibly bumped by 1 to absorb the extra gate count.
#[test]
#[ignore = "diagnostic only; expensive — rebuilds aggregator + outer 4 times"]
fn dump_phase_2a_pad_bits_sweep() {
    println!("\n=== pad_bits sweep: helper-degree vs minimal-outer-degree ===");
    for pad_bits in [14usize, 15, 16, 17] {
        let (h, o, ok) = diag_at_pad_bits(pad_bits);
        println!(
            "  pad_bits = {pad_bits:<2}  helper_degree = {h}  minimal_outer_degree = {o}  success = {ok}"
        );
    }
}
