//! Probe C — vk / public-input binding across layers (MIGRATION_PLONKY3.md §5, P0-T4).
//!
//! zkCoins' outer state-transition circuit binds an inner proof's claimed
//! verifier key / public inputs (the aggregator's source-vk, the propagated
//! ProofData PIs). The load-bearing question: in `p3-recursion`, is an inner
//! proof's commitment + public inputs reachable as CONSTRAINED circuit targets,
//! so a proof that doesn't match the expected (vk, PIs) is REJECTED by the outer?
//!
//! This probe uses the low-level in-circuit verifier `verify_p3_uni_proof_circuit`
//! over the CounterAir and asserts:
//!   * POSITIVE: a correct (proof, public_inputs) pair runs the verifier circuit
//!     to completion (accepted).
//!   * NEGATIVE: the SAME verifier circuit fed mismatched public inputs (claiming
//!     a different committed value than the proof actually proves) FAILS — i.e.
//!     the inner proof's public inputs are genuinely bound, not free.

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
use p3_uni_stark::prove;
use plonky3_recursion_spike::goldilocks_rec::{InnerFri, make_uni_verify_config};
use plonky3_recursion_spike::{CounterAir, counter_public_inputs, generate_counter_trace};

#[test]
fn probe_c_vk_binding() {
    let (config, perm, fri_verifier_params) = make_uni_verify_config();
    let air = CounterAir;

    // Inner proof: counter of 16 rows starting at 7. Its committed public inputs
    // are [7, 22].
    let n = 1 << 4;
    let start = 7u64;
    let trace = generate_counter_trace::<F>(start, n);
    let pis = counter_public_inputs::<F>(start, n);
    let proof = prove(&config, &air, trace, &pis);

    // Build ONE in-circuit verifier for this proof shape.
    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        perm,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let verifier_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(&mut circuit_builder, &proof, None, pis.len());

    let mmcs_op_ids = verify_p3_uni_proof_circuit::<
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
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        &fri_verifier_params,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .expect("build uni-stark verifier circuit");

    let circuit = circuit_builder.build().expect("verifier circuit builds");

    // POSITIVE: correct public inputs -> verifier circuit runs to completion.
    {
        let (public_inputs, private_inputs) = verifier_inputs.pack_values(&pis, &proof, &None);
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set pub");
        runner
            .set_private_inputs(&private_inputs)
            .expect("set priv");
        set_fri_mmcs_private_data::<
            F,
            Challenge,
            ChallengeMmcs,
            MyMmcs,
            MyHash,
            MyCompress,
            DIGEST_ELEMS,
        >(
            &mut runner,
            &mmcs_op_ids,
            &proof.opening_proof,
            Poseidon2Config::GOLDILOCKS_D2_W8,
        )
        .expect("set mmcs private data");
        runner
            .run()
            .expect("correct proof + correct public inputs must verify in-circuit");
    }

    // NEGATIVE: claim a DIFFERENT public input ([99, 22] instead of [7, 22]). The
    // inner proof's public inputs are bound by the verifier circuit, so the run
    // must fail (the claimed PI cannot be substituted for free).
    {
        let wrong_pis = vec![F::from_u64(99), pis[1]];
        let (public_inputs, private_inputs) =
            verifier_inputs.pack_values(&wrong_pis, &proof, &None);
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).expect("set pub");
        runner
            .set_private_inputs(&private_inputs)
            .expect("set priv");
        set_fri_mmcs_private_data::<
            F,
            Challenge,
            ChallengeMmcs,
            MyMmcs,
            MyHash,
            MyCompress,
            DIGEST_ELEMS,
        >(
            &mut runner,
            &mmcs_op_ids,
            &proof.opening_proof,
            Poseidon2Config::GOLDILOCKS_D2_W8,
        )
        .expect("set mmcs private data");
        let result = runner.run();
        assert!(
            result.is_err(),
            "mismatched inner public inputs must be REJECTED by the verifier circuit \
             (vk/PI binding); instead the run succeeded"
        );
    }
}
