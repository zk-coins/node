//! Probe J — Option 2 (commit + hash re-bind) end-to-end feasibility.
//!
//! Option 2 was the *only* remaining cross-layer-threading construction after Option
//! 1 was killed (Probes G/H). It needs two things: (a) a per-layer commit+rebind
//! PRIMITIVE — compute `hash(V)` in-circuit and bind a witnessed `V` to a committed
//! digest; and (b) a way for layer N+1 to READ layer N's committed digest so it can
//! rebind. This probe tests both.
//!
//! PART 1 (this test): the in-circuit Poseidon2 hash-bind primitive is real and
//! binding — `connect(hash(V1), hash(V2))` holds iff `V1 == V2`. Real Poseidon2
//! permutation executed in `runner.run()`; positive (same preimage) accepted,
//! negative (different preimage) rejected. So Option 2's per-layer building block
//! works.
//!
//! PART 2 (the wall, established empirically by `probe_d_multilayer_carry`,
//! `probe_g_fanin_pi_passthrough`, `probe_h_option1_air_public_values`): a batch
//! proof exposes NO per-instance value/digest as a constrainable target
//! (`air_public_targets = [0,0,0]`; only whole-trace Merkle-root commitments are
//! exposed, from which a single committed digest cannot be extracted/bound). So
//! layer N+1 cannot read layer N's committed digest, and the primitive **cannot
//! compose across the batch-recursion chain**.
//!
//! CONCLUSION: Option 2's per-layer commit primitive is expressible, but multi-layer
//! Option-2 threading is NOT achievable on this rev — confirming the cross-layer
//! state IVC (zkCoins `prev_account` carry) is structurally unbuildable here. This is
//! the migration's NO-GO pivot, escalated to the operator.

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{
    GoldilocksD2Width8, Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_field::PrimeCharacteristicRing;
use p3_test_utils::goldilocks_params::{Challenge, F};

/// Build a circuit that hashes two witnessed preimages with the in-circuit Poseidon2
/// gadget and `connect`s the two digests element-wise, then run it with `(v1, v2)`.
/// Returns Err if the run fails (i.e. the digests differ).
fn hash_bind(v1: u64, v2: u64) -> Result<(), String> {
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
        plonky3_recursion_spike::goldilocks_rec::default_goldilocks_poseidon2_8(),
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let a = cb.alloc_public_input("v1");
    let b = cb.alloc_public_input("v2");

    let cfg = Poseidon2Config::GOLDILOCKS_D2_W8;
    let h1 = cb
        .add_hash_slice(&cfg, &[a], true)
        .map_err(|e| format!("hash1: {e:?}"))?;
    let h2 = cb
        .add_hash_slice(&cfg, &[b], true)
        .map_err(|e| format!("hash2: {e:?}"))?;

    // Bind the two digests element-wise: holds iff hash(v1) == hash(v2).
    assert_eq!(h1.len(), h2.len());
    for (x, y) in h1.iter().zip(h2.iter()) {
        cb.connect(*x, *y);
    }

    let circuit = cb.build().map_err(|e| format!("build: {e:?}"))?;
    let mut r = circuit.runner();
    r.set_public_inputs(&[Challenge::from_u64(v1), Challenge::from_u64(v2)])
        .map_err(|e| format!("set pub: {e:?}"))?;
    r.run().map_err(|e| format!("run: {e:?}"))?;
    Ok(())
}

#[test]
fn probe_j_option2_rebind() {
    // PART 1 — the per-layer commit+rebind PRIMITIVE works (real in-circuit Poseidon2):
    // POSITIVE: identical preimage => identical digest => the hash-bind holds.
    hash_bind(42, 42).expect("hash(V) must bind to hash(V) (commit+rebind primitive)");

    // NEGATIVE: a wrong forwarded value => different digest => the hash-bind rejects.
    assert!(
        hash_bind(42, 99).is_err(),
        "a mismatched preimage (wrong forwarded value) must be REJECTED by the hash bind"
    );
    assert!(
        hash_bind(0, 1).is_err(),
        "even adjacent values must produce distinct digests rejected by the bind"
    );

    // PART 2 — the wall: this primitive needs layer N+1 to READ layer N's committed
    // digest to rebind it. That is structurally impossible across a batch layer:
    // `probe_d_multilayer_carry` (air_public_targets = [0,0,0]),
    // `probe_h_option1_air_public_values` (injecting a public input is rejected), and
    // `probe_g_fanin_pi_passthrough` (aggregation exposes 0 per-leaf values) all show
    // no per-instance value/digest is exposed across a batch-recursion layer — only
    // whole-trace Merkle-root commitments, from which a single committed digest cannot
    // be extracted or bound. So the commit+rebind cannot chain past the first
    // (uni-stark) hop. Multi-layer Option-2 threading is NOT achievable on this rev.
}
