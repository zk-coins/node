//! Probe F — vk-equality connect-back (MIGRATION_PLONKY3.md §5, P0-T4 literal text).
//!
//! zkCoins' outer state-transition `connect_hashes`-binds the aggregator's claimed
//! source-vk to its own cyclic vk. The load-bearing question: in `p3-recursion`,
//! can the outer circuit BIND an inner proof's verification key to an EXPECTED
//! value, and REJECT a deliberately wrong-vk inner proof?
//!
//! A uni-stark's "vk" with preprocessed columns IS the preprocessed commitment.
//! `ConstPrepAir { k }` has a preprocessed column constant `k`, so two instances
//! (k=42 vs k=99) have different preprocessed commitments = different vks but the
//! SAME shape. The verifier circuit `connect`s the inner preprocessed commitment
//! targets to an expected value (the Plonky2 `connect_hashes` analogue). Cases:
//!   * POSITIVE: proof_42 bound to vk_42 — internal verify OK and vk connect OK.
//!   * NEGATIVE: proof_99 bound to vk_42 — proof_99 is INTERNALLY VALID against
//!     vk_99 (STARK verify passes); only the connect to vk_42 rejects it.
//!   * CONTROL: proof_99 with NO binding — accepted. This proves the NEGATIVE's
//!     rejection is PURELY the vk binding, not a shape/verify artifact.

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{GoldilocksD2Width8, generate_poseidon2_trace, generate_recompose_trace};
use p3_recursion::pcs::fri::{InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::set_fri_mmcs_private_data;
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::traits::Recursive;
use p3_recursion::{Poseidon2Config, verify_p3_uni_proof_circuit};
use p3_test_utils::goldilocks_params::{
    Challenge, ChallengeMmcs, DIGEST_ELEMS, F, MyCompress, MyConfig, MyHash, MyMmcs, RATE, WIDTH,
};
use p3_uni_stark::{
    PreprocessedVerifierKey, Proof, prove_with_preprocessed, setup_preprocessed,
    verify_with_preprocessed,
};
use p3_util::log2_strict_usize;
use plonky3_recursion_spike::goldilocks_rec::{InnerFri, make_uni_verify_config};
use plonky3_recursion_spike::{ConstPrepAir, generate_const_main_trace};

const ROWS: usize = 1 << 3;

/// Verify `proof` against `vk` inside a fresh verifier circuit. If `bind_vk` is
/// `Some(expected)`, additionally `connect` the inner preprocessed commitment to
/// `expected` (the vk-equality binding). Returns Err if the circuit run fails.
fn verify_in_circuit(
    bind_vk: Option<&[Challenge]>,
    vk: &PreprocessedVerifierKey<MyConfig>,
    proof: &Proof<MyConfig>,
) -> Result<(), String> {
    let (config, perm, fri_verifier_params) = make_uni_verify_config();
    // The eval AIR is k-independent (constraint is `m == p`), so any ConstPrepAir
    // of the right shape works for symbolic constraints.
    let air = ConstPrepAir { k: 42, rows: ROWS };

    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let vi = StarkVerifierInputsBuilder::<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
        &mut cb,
        proof,
        Some(&vk.commitment),
        0,
    );

    let op_ids = verify_p3_uni_proof_circuit::<
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
        &air,
        &mut cb,
        &vi.proof_targets,
        &vi.air_public_targets,
        &vi.preprocessed_commit,
        &fri_verifier_params,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .map_err(|e| format!("build verifier: {e:?}"))?;

    if let Some(expected) = bind_vk {
        let commit = vi
            .preprocessed_commit
            .as_ref()
            .expect("ConstPrepAir has a preprocessed commitment");
        let mut idx = 0;
        for entry in &commit.cap_targets {
            for &t in entry.iter() {
                let c = cb.alloc_const(expected[idx], "expected vk element");
                cb.connect(t, c);
                idx += 1;
            }
        }
        assert_eq!(idx, expected.len(), "connected every vk commitment element");
    }

    let circuit = cb.build().map_err(|e| format!("circuit build: {e:?}"))?;
    let (pubs, privs) = vi.pack_values(&[], proof, &Some(vk.commitment.clone()));
    let mut r = circuit.runner();
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
        &op_ids,
        &proof.opening_proof,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .map_err(|e| format!("set mmcs: {e}"))?;
    r.run().map_err(|e| format!("run: {e:?}"))?;
    Ok(())
}

#[test]
fn probe_f_vk_binding() {
    let (config, _perm, _fri) = make_uni_verify_config();
    let log_h = log2_strict_usize(ROWS);

    // Two AIRs, same shape, different preprocessed constant => different vks.
    let air_a = ConstPrepAir { k: 42, rows: ROWS };
    let air_b = ConstPrepAir { k: 99, rows: ROWS };

    let (prep_a, vk_a) = setup_preprocessed(&config, &air_a, log_h).expect("air_a preprocessed");
    let (prep_b, vk_b) = setup_preprocessed(&config, &air_b, log_h).expect("air_b preprocessed");

    let proof_a = prove_with_preprocessed(
        &config,
        &air_a,
        generate_const_main_trace::<F>(42, ROWS),
        &[],
        Some(&prep_a),
    );
    let proof_b = prove_with_preprocessed(
        &config,
        &air_b,
        generate_const_main_trace::<F>(99, ROWS),
        &[],
        Some(&prep_b),
    );

    // Sanity: each proof verifies against its OWN vk, and the two vks differ.
    assert!(verify_with_preprocessed(&config, &air_a, &proof_a, &[], Some(&vk_a)).is_ok());
    assert!(verify_with_preprocessed(&config, &air_b, &proof_b, &[], Some(&vk_b)).is_ok());

    let vk_a_vals =
        <MerkleCapTargets<F, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(&vk_a.commitment);
    let vk_b_vals =
        <MerkleCapTargets<F, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(&vk_b.commitment);
    assert_ne!(
        vk_a_vals, vk_b_vals,
        "different preprocessed constant must yield different vk commitments"
    );

    // POSITIVE: correct vk (proof_42 bound to vk_42) is accepted.
    verify_in_circuit(Some(&vk_a_vals), &vk_a, &proof_a)
        .expect("correct-vk inner proof must be accepted by the vk-equality connect");

    // NEGATIVE: wrong vk (proof_99 bound to vk_42) is rejected.
    assert!(
        verify_in_circuit(Some(&vk_a_vals), &vk_b, &proof_b).is_err(),
        "deliberately wrong-vk inner proof must be REJECTED by the vk-equality connect-back"
    );

    // CONTROL: proof_99 with NO binding is accepted — proves the NEGATIVE rejection
    // is purely the vk binding, not an internal-verify or shape artifact.
    verify_in_circuit(None, &vk_b, &proof_b)
        .expect("unbound proof_99 must verify in-circuit (it is internally valid)");
}
