//! Diagnostic probes for the Plonky2 1.1.0 `dummy_circuit` shape
//! mismatch (`MIGRATION_RESEARCH.md` §7.21,
//! `STAGE_5D_NEXT_5_AGGREGATOR.md`).
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
use plonky2::gates::noop::NoopGate;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
use plonky2::recursion::dummy_circuit::dummy_circuit;

use crate::circuit::source_aggregator::build_source_aggregator_circuit;
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
fn pass_3_two_verify(pad_bits: usize) -> CommonCircuitData<F, D> {
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

    // Pass 3: same shape + pad
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &vd, &data.common);
    let agg_proof = builder.add_virtual_proof_with_pis(&aggregator.data.common);
    let agg_vd =
        builder.add_virtual_verifier_data(aggregator.data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&agg_proof, &agg_vd, &aggregator.data.common);
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

    let two_verify_pad14 = pass_3_two_verify(14);
    dump_summary("Phase 2a candidate (2 verify, pad 14)", &two_verify_pad14);
    let ok_2v_14 = try_dummy_circuit("2-verify pad 14", &two_verify_pad14);

    println!("\n=== summary so far === baseline_ok={ok_baseline}, 2v_14={ok_2v_14}");

    // Force-constants probe: how many distinct constants forced
    // through a `mul(c, zero)` chain trigger ConstantGate emission?
    for n in [1usize, 4, 16, 64, 256] {
        let candidate = pass_3_two_verify_forced(14, n);
        let label = format!("2 verify + {n} forced constants (pad 14)");
        dump_summary(&label, &candidate);
        let ok = try_dummy_circuit(&label, &candidate);
        println!("\n  →→→ forced_n={n}: ok={ok}");
    }
}
