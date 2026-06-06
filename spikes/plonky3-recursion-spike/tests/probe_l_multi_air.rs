//! Probe L — multi-AIR coexistence in one verifier circuit.
//!
//! The real port verifies heterogeneous inner proofs in one outer circuit (the
//! state-transition proof AND the source-aggregator proof). This probe validates
//! that two DIFFERENT AIRs can be verified in a single `p3-circuit` verifier circuit
//! with their public inputs kept cleanly distinct and individually bound.
//!
//! AIR A = `CounterAir` (state-transition-like: public inputs `[start, last]`).
//! AIR B = `ConstPrepAir` (aggregator-like: a preprocessed/“vk”-bearing AIR).
//! Both are verified uni-stark in one circuit. POSITIVE: both correct → run OK, and
//! A's `air_public_targets` are bound to A's committed values (not B's). NEGATIVE:
//! feeding A's verifier B's public inputs (cross-wiring) is rejected.

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{GoldilocksD2Width8, generate_poseidon2_trace, generate_recompose_trace};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::pcs::fri::{InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::set_fri_mmcs_private_data;
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{Poseidon2Config, verify_p3_uni_proof_circuit};
use p3_test_utils::goldilocks_params::{
    Challenge, ChallengeMmcs, DIGEST_ELEMS, F, MyCompress, MyConfig, MyHash, MyMmcs, RATE, WIDTH,
};
use p3_uni_stark::{prove, prove_with_preprocessed, setup_preprocessed};
use p3_util::log2_strict_usize;
use plonky3_recursion_spike::goldilocks_rec::{InnerFri, make_uni_verify_config};
use plonky3_recursion_spike::{
    ConstPrepAir, CounterAir, counter_public_inputs, generate_const_main_trace,
    generate_counter_trace,
};

/// Build a circuit verifying BOTH inner proofs. `wrong_a_pis` cross-wires A's verifier
/// with B's public input value (the soundness negative).
fn verify_both(cross_wire_a: bool) -> Result<(), String> {
    let (config, perm, fri_vp) = make_uni_verify_config();
    const ROWS: usize = 1 << 3;

    // AIR A: counter, PI [5, 12].
    let air_a = CounterAir;
    let pis_a = counter_public_inputs::<F>(5, ROWS);
    let proof_a = prove(
        &config,
        &air_a,
        generate_counter_trace::<F>(5, ROWS),
        &pis_a,
    );

    // AIR B: ConstPrepAir k=77, preprocessed vk.
    let air_b = ConstPrepAir { k: 77, rows: ROWS };
    let (prep_b, vk_b) =
        setup_preprocessed(&config, &air_b, log2_strict_usize(ROWS)).expect("prep B");
    let proof_b = prove_with_preprocessed(
        &config,
        &air_b,
        generate_const_main_trace::<F>(77, ROWS),
        &[],
        Some(&prep_b),
    );

    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    // Verifier inputs for A and B (separate target sets — kept distinct).
    let vi_a = StarkVerifierInputsBuilder::<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
        &mut cb, &proof_a, None, pis_a.len(),
    );
    let vi_b = StarkVerifierInputsBuilder::<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
        &mut cb, &proof_b, Some(&vk_b.commitment), 0,
    );

    let op_a = verify_p3_uni_proof_circuit::<
        CounterAir,
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        _,
        WIDTH,
        RATE,
    >(
        &config,
        &air_a,
        &mut cb,
        &vi_a.proof_targets,
        &vi_a.air_public_targets,
        &None,
        &fri_vp,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .map_err(|e| format!("verify A: {e:?}"))?;

    let op_b = verify_p3_uni_proof_circuit::<
        ConstPrepAir,
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        _,
        WIDTH,
        RATE,
    >(
        &config,
        &air_b,
        &mut cb,
        &vi_b.proof_targets,
        &vi_b.air_public_targets,
        &vi_b.preprocessed_commit,
        &fri_vp,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .map_err(|e| format!("verify B: {e:?}"))?;

    let circuit = cb.build().map_err(|e| format!("build: {e:?}"))?;
    let mut r = circuit.runner();

    // Pack A with EITHER its own pis (correct) or a cross-wired wrong value.
    let a_pis_used = if cross_wire_a {
        vec![F::from_u64(77), pis_a[1]] // claim A.start == B's k (wrong)
    } else {
        pis_a.clone()
    };
    let (mut pubs, mut privs) = vi_a.pack_values(&a_pis_used, &proof_a, &None);
    let (pb, prb) = vi_b.pack_values(&[], &proof_b, &Some(vk_b.commitment.clone()));
    pubs.extend(pb);
    privs.extend(prb);

    r.set_public_inputs(&pubs)
        .map_err(|e| format!("set pub: {e:?}"))?;
    r.set_private_inputs(&privs)
        .map_err(|e| format!("set priv: {e:?}"))?;
    set_fri_mmcs_private_data::<
        F,
        Challenge,
        ChallengeMmcs,
        MyMmcs,
        MyHash,
        MyCompress,
        DIGEST_ELEMS,
    >(
        &mut r,
        &op_a,
        &proof_a.opening_proof,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .map_err(|e| format!("mmcs A: {e}"))?;
    set_fri_mmcs_private_data::<
        F,
        Challenge,
        ChallengeMmcs,
        MyMmcs,
        MyHash,
        MyCompress,
        DIGEST_ELEMS,
    >(
        &mut r,
        &op_b,
        &proof_b.opening_proof,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .map_err(|e| format!("mmcs B: {e}"))?;
    r.run().map_err(|e| format!("run: {e:?}"))?;
    Ok(())
}

#[test]
fn probe_l_multi_air() {
    // POSITIVE: two different AIRs verify together, PIs kept distinct + bound.
    verify_both(false).expect("two heterogeneous AIRs must co-verify in one circuit");
    // NEGATIVE: cross-wiring A's public input to B's value is rejected — the two
    // AIRs' public inputs are independently bound, not conflated.
    assert!(
        verify_both(true).is_err(),
        "cross-wiring AIR A's public input must be rejected (PIs are per-AIR bound)"
    );
}
