//! Probe D — cross-layer public-input threading (MIGRATION_PLONKY3.md §5, P0-T2 crit. 2).
//!
//! The IVC chain must carry a value forward across layers (the zkCoins
//! `prev_account` / ProofData propagation): layer N's outer circuit reads the
//! inner proof's public input and re-exposes a constrained function of it for the
//! next layer. The high-level `into_recursion_input::<BatchOnly>()` zeroes the
//! threaded public inputs; this probe takes the lower-level path where the inner
//! proof's public inputs ARE exposed (`air_public_targets`) and threads them.
//!
//! Construction: an outer verifier circuit over an inner counter proof (PI
//! `[start, last]`) exposes `air_public_targets`, then THREADS a value to the next
//! layer with the IVC relation `next_start = last + 1`, bound to a circuit-exposed
//! `next_start` public input. Cases:
//!   * POSITIVE: `next_start = last + 1` accepted.
//!   * NEGATIVE: a wrong `next_start` (≠ last+1) is rejected — the inner PI is
//!     genuinely threaded/bound, not free.
//!   * CONTROL: with the threading connect removed, the wrong `next_start` is
//!     accepted — proving the rejection is purely the threading bind.

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

/// Build an outer verifier circuit over `proof` (committing to `pis = [start,
/// last]`). If `thread`, additionally bind a `next_start` public input to
/// `last + 1` (the IVC thread). Set `next_start` to `claimed_next` and run.
fn thread_and_run(
    thread: bool,
    pis: &[F],
    proof: &Proof<MyConfig>,
    claimed_next: u64,
) -> Result<(), String> {
    let (config, perm, fri_verifier_params) = make_uni_verify_config();
    let air = CounterAir;

    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let vi = StarkVerifierInputsBuilder::<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
        &mut cb, proof, None, pis.len(),
    );

    let op_ids = verify_p3_uni_proof_circuit::<
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
        &fri_verifier_params,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
    .map_err(|e| format!("build verifier: {e:?}"))?;

    // The value handed to the next layer (allocated AFTER the verifier's own
    // public inputs, so it is the last public input).
    let next_start = cb.alloc_public_input("next_start");
    if thread {
        // IVC thread: next_start == inner.last + 1. `air_public_targets[1]` is the
        // inner proof's `last`, bound to the proof by the verifier above.
        let one = cb.alloc_const(Challenge::ONE, "one");
        let expected_next = cb.add(vi.air_public_targets[1], one);
        cb.connect(next_start, expected_next);
    }

    let circuit = cb.build().map_err(|e| format!("circuit build: {e:?}"))?;

    let (mut pubs, privs) = vi.pack_values(pis, proof, &None);
    pubs.push(Challenge::from_u64(claimed_next)); // next_start value, appended last
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
fn probe_d_pi_threading() {
    let (config, _perm, _fri) = make_uni_verify_config();
    let air = CounterAir;

    // Inner counter proof: start=5, 8 rows => PI = [5, 12]. The threaded next
    // layer start is therefore last + 1 = 13.
    let n = 1 << 3;
    let start = 5u64;
    let trace = generate_counter_trace::<F>(start, n);
    let pis = counter_public_inputs::<F>(start, n);
    let proof = prove(&config, &air, trace, &pis);
    let correct_next = start + (n as u64 - 1) + 1; // 13

    // POSITIVE: correctly threaded next value accepted.
    thread_and_run(true, &pis, &proof, correct_next)
        .expect("correctly threaded next-layer value must be accepted");

    // NEGATIVE: a wrong threaded value is rejected (the inner PI is bound).
    assert!(
        thread_and_run(true, &pis, &proof, 999).is_err(),
        "a wrong threaded next-layer value must be REJECTED (PI is threaded/bound)"
    );

    // CONTROL: without the threading connect, the wrong value is accepted —
    // proving the NEGATIVE rejection is purely the threading bind.
    thread_and_run(false, &pis, &proof, 999)
        .expect("without the threading connect, any next value is accepted");
}
