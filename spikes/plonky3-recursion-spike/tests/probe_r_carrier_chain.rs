//! Probe R — an end-to-end carrier-table IVC chain: a counter value V is threaded
//! across >= 4 recursion layers via the PUBLIC-VALUE channel (MIGRATION_PLONKY3.md
//! §5, the IVC `prev_account` value-carry that the real circuit needs).
//!
//! Probe Q established the *single-layer* fact: a custom AIR with
//! `num_public_values() > 0`, proved with `prove_batch`, surfaces its public value
//! as a NON-EMPTY, SOUNDLY-BOUND `air_public_target` in the next layer's
//! `verify_batch_circuit`. Probe R CHAINS that fact: it builds a real IVC chain
//! where layer N's carried value V_N is cryptographically threaded into layer N+1,
//! which re-emits V_{N+1} = V_N + 1 for the next layer, for 4 layers (V_0..V_3).
//!
//! ## Construction (B — lower-level, manual chain over `prove_batch`)
//!
//! Each layer N is a real `prove_batch` BatchProof of a single `CarrierAir`
//! instance whose TWO public values are `[v_in, v_out]`, with the increment
//! `v_out == v_in + 1` enforced NATIVELY inside the carrier AIR (and bound to
//! committed trace cells). Layer N commits `[V_{N-1}, V_N]` (layer 0 commits
//! `[V_0 - 1, V_0]`, i.e. its `v_in` is unconstrained-against-a-predecessor — it is
//! the base case).
//!
//! The cross-layer bind (the IVC step linking layer N to layer N+1) is a single
//! `CircuitBuilder` that:
//!   1. verifies layer N's carrier proof in-circuit (`verify_batch_circuit`),
//!      surfacing `V_N = prev.air_public_targets[0][1]`, cryptographically bound to
//!      layer N's proof;
//!   2. verifies layer N+1's carrier proof in-circuit, surfacing
//!      `v_in^{N+1} = cur.air_public_targets[0][0]`, bound to layer N+1's proof;
//!   3. CONNECTS them: `prev.air_public_targets[0][1] == cur.air_public_targets[0][0]`.
//!
//! Running that link circuit proves V_N (from proof N) == v_in of proof N+1, and
//! each carrier internally forces v_out = v_in + 1, so chaining links 0->1->2->3
//! proves V_3 = V_0 + 3 with every value threaded through a real proof's
//! public-value channel. This is the cross-layer value channel the IVC needs.
//!
//!   * POSITIVE: the full 0->1->2->3 chain links; the carried value is provably
//!     V_3 == V_0 + 3 (asserted on the concrete values bound by each proof).
//!   * NEGATIVE 1 (forwarded value): a link whose layer N+1 claims a v_in that does
//!     NOT equal layer N's V_out is REJECTED (the forward bind is sound).
//!   * NEGATIVE 2 (carrier bind): a carrier proof that claims a public value its
//!     committed trace did not commit is REJECTED at `prove_batch`/`verify_batch`
//!     time (the carrier soundly binds its public value to the trace).
//!
//! Uses BabyBear (the exact upstream public-value pattern, matching Probe Q); the
//! mechanism is field-generic.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{BatchProof, ProverData, StarkInstance, prove_batch, verify_batch};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::{InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness};
use p3_recursion::{
    BatchStarkVerifierInputsBuilder, FriVerifierParams, Poseidon2Config, verify_batch_circuit,
};
use p3_test_utils::baby_bear_params::*;
use p3_test_utils::test_fri_scalars;

type InnerFri = FriProofTargets<
    F,
    Challenge,
    RecExtensionValMmcs<
        F,
        Challenge,
        DIGEST_ELEMS,
        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
    >,
    InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
    Witness<F>,
>;

/// A carrier AIR with TWO public values `[v_in, v_out]` and the increment
/// `v_out == v_in + 1` enforced natively. Trace width 2: row 0 holds
/// `[v_in, v_out]`, bound to the public values on the first row.
#[derive(Clone, Copy)]
struct CarrierAir {
    rows: usize,
}

impl CarrierAir {
    /// Trace committing `v_in = v` and `v_out = v + 1` on row 0. The public values
    /// returned are `[v_in, v_out]` (taken from the committed cells), so a HONEST
    /// carrier always satisfies `v_out == v_in + 1`.
    fn honest_trace<Val: Field>(&self, v: Val) -> (RowMajorMatrix<Val>, Vec<Val>) {
        let width = 2;
        let mut values = Val::zero_vec(self.rows * width);
        for row in 0..self.rows {
            let idx = row * width;
            // v_in / v_out columns: only row 0 is constrained against the PIs and the
            // increment; later rows just hold a valid (in, in+1) pair so the
            // transition-free AIR is satisfied everywhere.
            values[idx] = v;
            values[idx + 1] = v + Val::ONE;
        }
        let pvs = vec![values[0], values[1]];
        (RowMajorMatrix::new(values, width), pvs)
    }
}

impl<Val: Field> BaseAir<Val> for CarrierAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        2
    }
}

impl<AB: AirBuilder> Air<AB> for CarrierAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let v_in = local[0];
        let v_out = local[1];
        let pis = builder.public_values();
        let pi_in = pis[0];
        let pi_out = pis[1];
        // Public values are bound to the committed trace cells on the first row...
        builder.when_first_row().assert_eq(v_in, pi_in);
        builder.when_first_row().assert_eq(v_out, pi_out);
        // ...and the carrier natively enforces the +1 increment.
        builder
            .when_first_row()
            .assert_eq(v_out, v_in + AB::Expr::ONE);
    }
}

fn fri_params() -> FriVerifierParams {
    let scalars = test_fri_scalars();
    FriVerifierParams::unsafe_arithmetic_only_for_tests(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
    )
}

/// One layer of the chain: a real `prove_batch` carrier proof committing
/// `[v_in, v_out]`. `v_in` and `v_out` are the *claimed* public values (so a caller
/// can deliberately claim a wrong pair to exercise the carrier-bind negative).
struct Layer {
    proof: BatchProof<MyConfig>,
    air: CarrierAir,
    pvs: [Vec<F>; 1],
    prover_data: ProverData<MyConfig>,
}

impl Layer {
    fn common(&self) -> &p3_batch_stark::CommonData<MyConfig> {
        &self.prover_data.common
    }
}

/// Prove a carrier layer. The committed trace always encodes `(v, v+1)`; `claimed`
/// is the public-value pair handed to `prove_batch`/`verify_batch`. With
/// `claimed = (v, v+1)` this is an honest layer; any other `claimed` is a tampered
/// carrier whose native verify must reject.
fn prove_layer(v: F, claimed: (F, F)) -> Result<Layer, String> {
    let n = 1 << 3;
    let config = make_test_config();
    let air = CarrierAir { rows: n };
    let (trace, _honest_pvs) = air.honest_trace::<F>(v);
    let pvs = [vec![claimed.0, claimed.1]];

    let instances = vec![StarkInstance {
        air: &air,
        trace: &trace,
        public_values: pvs[0].clone(),
    }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    verify_batch(&config, &[air], &proof, &pvs, &prover_data.common)
        .map_err(|e| format!("native verify: {e:?}"))?;
    Ok(Layer {
        proof,
        air,
        pvs,
        prover_data,
    })
}

/// Allocate a carrier proof's batch-verifier inputs into `cb` and run
/// `verify_batch_circuit`, returning the verifier-inputs builder (so the caller can
/// read `air_public_targets` and pack values). Asserts the carrier surfaces exactly
/// two per-instance public targets (NOT `[0,0,0]`).
type Vi = BatchStarkVerifierInputsBuilder<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>;

fn add_carrier_verifier(cb: &mut CircuitBuilder<Challenge>, layer: &Layer) -> Result<Vi, String> {
    let config = make_test_config();
    let lookup_gadget = LogUpGadget::new();
    let air_public_counts = vec![2usize];
    let vi = Vi::allocate(cb, &layer.proof, layer.common(), &air_public_counts);
    assert_eq!(vi.air_public_targets.len(), 1, "one carrier instance");
    assert_eq!(
        vi.air_public_targets[0].len(),
        2,
        "the carrier's two public values MUST surface as 2 air_public_targets (not [0,0,0])"
    );
    verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &[layer.air],
        cb,
        &vi.proof_targets,
        &vi.air_public_targets,
        &fri_params(),
        &vi.common_data,
        &lookup_gadget,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .map_err(|e| format!("build verifier: {e:?}"))?;
    Ok(vi)
}

/// The IVC link circuit between two carrier proofs `prev` and `cur`: verify BOTH
/// in one circuit and (if `bind`) connect `prev.v_out == cur.v_in`. Run it; returns
/// Err if the in-circuit run fails (i.e. the link is rejected).
fn run_link(prev: &Layer, cur: &Layer, bind: bool) -> Result<(), String> {
    let perm = default_babybear_poseidon2_16();
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let prev_vi = add_carrier_verifier(&mut cb, prev)?;
    let cur_vi = add_carrier_verifier(&mut cb, cur)?;

    if bind {
        // IVC thread: layer N's emitted v_out is layer N+1's consumed v_in.
        cb.connect(
            prev_vi.air_public_targets[0][1],
            cur_vi.air_public_targets[0][0],
        );
    }

    let circuit = cb.build().map_err(|e| format!("build: {e:?}"))?;
    let mut runner = circuit.runner();

    let (mut pubs, mut privs) = prev_vi.pack_values(&prev.pvs, &prev.proof, prev.common());
    let (cur_pubs, cur_privs) = cur_vi.pack_values(&cur.pvs, &cur.proof, cur.common());
    pubs.extend(cur_pubs);
    privs.extend(cur_privs);
    runner
        .set_public_inputs(&pubs)
        .map_err(|e| format!("set pub: {e:?}"))?;
    runner
        .set_private_inputs(&privs)
        .map_err(|e| format!("set priv: {e:?}"))?;
    runner.run().map_err(|e| format!("run: {e:?}"))?;
    Ok(())
}

#[test]
fn probe_r_carrier_chain() {
    // V_0 = 10. The chain threads V_0 -> V_1 -> V_2 -> V_3 with each layer's carrier
    // committing (V_{k-1}, V_k) and natively enforcing V_k = V_{k-1} + 1.
    let v0 = 10u32;

    // Build 4 honest layers (depth 4: layers 0,1,2,3 => 3 IVC links).
    // Layer k commits [v_{k-1}, v_k] = [v0+k-1, v0+k].
    let layers: Vec<Layer> = (0..4)
        .map(|k| {
            let v_in = F::from_u32(v0 + k) - F::ONE; // v0 + k - 1
            prove_layer(v_in, (v_in, v_in + F::ONE))
                .unwrap_or_else(|e| panic!("prove honest layer {k}: {e}"))
        })
        .collect();

    // POSITIVE: every IVC link 0->1, 1->2, 2->3 verifies end-to-end.
    for k in 0..3 {
        run_link(&layers[k], &layers[k + 1], true)
            .unwrap_or_else(|e| panic!("honest link {k}->{}: {e}", k + 1));
    }

    // The carried value is provably V_3 == V_0 + 3: each carrier's committed v_out is
    // bound to its proof (Probe Q soundness) and each link binds v_out(N) == v_in(N+1),
    // while each carrier enforces v_out == v_in + 1. Assert the concrete values.
    let v3_out = layers[3].pvs[0][1];
    assert_eq!(
        v3_out,
        F::from_u32(v0 + 3),
        "layer-3 carried value must be V_0 + 3 (counter threaded across 4 layers)"
    );
    // And the forward-linkage of committed values holds across the whole chain.
    for k in 0..3 {
        assert_eq!(
            layers[k].pvs[0][1],
            layers[k + 1].pvs[0][0],
            "committed v_out(layer {k}) must equal v_in(layer {})",
            k + 1
        );
    }

    // NEGATIVE 1 (forwarded value): a layer 1 that claims a WRONG v_in (one that does
    // NOT equal layer 0's v_out) must be REJECTED by the link bind. Build a layer
    // whose carrier honestly commits (v0+5, v0+6) — a valid carrier, but the WRONG
    // successor of layer 0 (which emitted v0). Linking 0 -> wrong must fail.
    let wrong_in = F::from_u32(v0 + 5);
    let wrong_successor = prove_layer(wrong_in, (wrong_in, wrong_in + F::ONE))
        .expect("a valid-but-wrong-successor carrier still proves natively");
    assert!(
        run_link(&layers[0], &wrong_successor, true).is_err(),
        "a link whose successor v_in != predecessor v_out must be REJECTED (forward bind sound)"
    );
    // CONTROL: without the bind, the same mismatched pair is accepted — proving the
    // rejection is purely the IVC thread bind, not some unrelated failure.
    run_link(&layers[0], &wrong_successor, false)
        .expect("without the IVC bind, a mismatched pair is accepted (control)");

    // NEGATIVE 2 (carrier bind): a carrier proof that CLAIMS a public value its trace
    // did not commit must be REJECTED at prove/verify time. The trace commits
    // (v0, v0+1) but we claim v_out = v0+999 — the carrier's first-row bind rejects it.
    let v = F::from_u32(v0);
    let tampered = prove_layer(v, (v, F::from_u32(v0 + 999)));
    assert!(
        tampered.is_err(),
        "a carrier claiming a public value it did not commit must be REJECTED (carrier soundly binds its PV)"
    );
}
