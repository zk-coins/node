//! Probe O — soundness spot-check of the recursion-verifier API.
//!
//! All the other probes rely on `verify_p3_uni_proof_circuit` + `set_fri_mmcs_private_data`
//! genuinely REJECTING bad inputs (not vacuously accepting). This probe attacks the
//! verifier itself with mismatched cryptographic data and asserts the in-circuit
//! verification fails — confirming the FRI/Merkle check is real, so the negative
//! assertions in Probes C/D/F/L/J are trustworthy.
//!
//! Negatives:
//!  * wrong FRI private data — feed proof B's `opening_proof` (Merkle paths) into a
//!    verifier circuit built for proof A → the in-circuit Merkle verification fails.
//!  * tampered public input — claim a different committed value → rejected (re-confirms
//!    `probe_c` against this exact harness).

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
use p3_uni_stark::{Proof, prove};
use plonky3_recursion_spike::goldilocks_rec::{InnerFri, make_uni_verify_config};
use plonky3_recursion_spike::{CounterAir, counter_public_inputs, generate_counter_trace};

const ROWS: usize = 1 << 3;

/// Build a verifier for `proof_a` (committing `pis_a`), then run it with the supplied
/// public-input claim, and the FRI private data taken from `mmcs_proof` (which may be a
/// DIFFERENT proof of the same shape — the soundness attack).
fn run_with(
    proof_a: &Proof<MyConfig>,
    pis_a: &[F],
    claim: &[F],
    mmcs_proof: &Proof<MyConfig>,
) -> Result<(), String> {
    let (config, perm, fri_vp) = make_uni_verify_config();
    let air = CounterAir;
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let vi = StarkVerifierInputsBuilder::<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
        &mut cb, proof_a, None, pis_a.len(),
    );
    let op = verify_p3_uni_proof_circuit::<
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
        &air,
        &mut cb,
        &vi.proof_targets,
        &vi.air_public_targets,
        &None,
        &fri_vp,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .map_err(|e| format!("build: {e:?}"))?;

    let circuit = cb.build().map_err(|e| format!("build: {e:?}"))?;
    // pack with proof_a but the supplied public-input claim.
    let (pubs, privs) = vi.pack_values(claim, proof_a, &None);
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
        &op,
        &mmcs_proof.opening_proof,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .map_err(|e| format!("mmcs: {e}"))?;
    r.run().map_err(|e| format!("run: {e:?}"))?;
    Ok(())
}

#[test]
fn probe_o_soundness() {
    let (config, _p, _f) = make_uni_verify_config();
    let air = CounterAir;
    let pis_a = counter_public_inputs::<F>(5, ROWS); // [5, 12]
    let proof_a = prove(&config, &air, generate_counter_trace::<F>(5, ROWS), &pis_a);
    let pis_b = counter_public_inputs::<F>(9, ROWS); // [9, 16], same shape, different proof
    let proof_b = prove(&config, &air, generate_counter_trace::<F>(9, ROWS), &pis_b);

    // BASELINE positive: correct proof + correct claim + own mmcs data → accepted.
    run_with(&proof_a, &pis_a, &pis_a, &proof_a).expect("correct proof must verify (baseline)");

    // SOUNDNESS NEGATIVE 1: wrong FRI private data (proof B's Merkle paths) into proof
    // A's verifier → the in-circuit Merkle/FRI verification must fail.
    assert!(
        run_with(&proof_a, &pis_a, &pis_a, &proof_b).is_err(),
        "mismatched FRI private data must be REJECTED (verification is not vacuous)"
    );

    // SOUNDNESS NEGATIVE 2: tampered public-input claim → rejected.
    let wrong_claim = vec![F::from_u64(999), pis_a[1]];
    assert!(
        run_with(&proof_a, &pis_a, &wrong_claim, &proof_a).is_err(),
        "a tampered public-input claim must be REJECTED"
    );
}
