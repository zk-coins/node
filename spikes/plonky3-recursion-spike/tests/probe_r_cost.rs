//! Probe R-cost — the carrier-table IVC chain's per-link cost at REAL-circuit
//! inner scale.
//!
//! Probe R (`probe_r_carrier_chain.rs`) established the *mechanism*: a depth-4
//! IVC chain where each layer is a real `prove_batch` `CarrierAir` proof carrying
//! `[v_in, v_out]`, and each IVC link verifies two adjacent carriers in one
//! `CircuitBuilder` (`verify_batch_circuit`) and connects `v_out(N) == v_in(N+1)`.
//! But Probe R ran every carrier at a TOY inner size (`rows = 1 << 3`): the link
//! cost it measured is the verifier-circuit floor, NOT the cost of recursing over
//! a real-circuit-sized inner proof.
//!
//! Probe I (`probe_i_cost_projection.rs`) established the *bare-layer* baseline:
//! a single recursion layer over a ~2^16-gate inner proof costs ≈3.2 s / ≈1.4 GB
//! (Goldilocks `prove_next_layer`). That is the bare recursion overhead with NO
//! carrier/public-value threading and NO two-proofs-per-link IVC construction.
//!
//! THIS probe closes the gap: it re-runs the Probe-R carrier chain with each
//! layer's inner `CarrierAir` trace SCALED UP toward the real ~2^16-row state
//! transition (`rows = 1 << 16`), keeping the carrier public-value threading
//! (`[v_in, v_out]`, `v_out == v_in + 1`, cross-layer `connect`) fully intact, and
//! measures:
//!   * per-LAYER base build+prove+verify (`prove_batch` of a 2^16-row carrier);
//!   * per-LINK build+prove(witness-gen)+verify (the IVC step: two
//!     `verify_batch_circuit`s + the carry `connect`, run to completion);
//!   * the whole-test peak RSS (capture via `/usr/bin/time -l`).
//!
//! It then reports the DELTA the carrier + chain construction adds over Probe I's
//! bare ≈3.2 s / ≈1.4 GB, and renders a VERDICT against the ≤5 s warm-prove budget
//! per state transition (one transition ≈ one inner carrier prove + one IVC link).
//!
//! The scaling lever is purely the carrier trace HEIGHT: STARK prove cost
//! (LDE/FFT + Merkle commit + FRI) is dominated by trace height, so a 2^16-row
//! carrier is a faithful inner-proof-size proxy for the real ~2^16-row circuit
//! (same honest caveat as Probe I: the synthetic constraints are lighter per row
//! than the real Poseidon-heavy circuit, so this is an overhead FLOOR for that
//! size, not a full replica of the real prove cost).
//!
//! Uses BabyBear, matching Probe R, for consistency.

use std::time::Instant;

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
/// `v_out == v_in + 1` enforced natively (identical to Probe R's `CarrierAir`,
/// but the trace HEIGHT `rows` is the scaling lever for inner-proof size). Trace
/// width 2: row 0 holds `[v_in, v_out]`, bound to the public values on the first
/// row; later rows just hold a valid `(in, in+1)` pair so the transition-free AIR
/// is satisfied at every one of the `rows` rows.
#[derive(Clone, Copy)]
struct CarrierAir {
    rows: usize,
}

impl CarrierAir {
    fn honest_trace<Val: Field>(&self, v: Val) -> (RowMajorMatrix<Val>, Vec<Val>) {
        let width = 2;
        let mut values = Val::zero_vec(self.rows * width);
        for row in 0..self.rows {
            let idx = row * width;
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
        builder.when_first_row().assert_eq(v_in, pi_in);
        builder.when_first_row().assert_eq(v_out, pi_out);
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

/// Prove one honest carrier layer at `rows` inner trace height, returning the
/// layer and the base build+prove+verify wall time in milliseconds.
fn prove_layer_timed(v: F, rows: usize) -> (Layer, u128) {
    let config = make_test_config();
    let air = CarrierAir { rows };
    let claimed = (v, v + F::ONE);

    let t0 = Instant::now();
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
        .expect("native carrier verify");
    let ms = t0.elapsed().as_millis();

    (
        Layer {
            proof,
            air,
            pvs,
            prover_data,
        },
        ms,
    )
}

type Vi = BatchStarkVerifierInputsBuilder<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>;

fn add_carrier_verifier(cb: &mut CircuitBuilder<Challenge>, layer: &Layer) -> Vi {
    let config = make_test_config();
    let lookup_gadget = LogUpGadget::new();
    let air_public_counts = vec![2usize];
    let vi = Vi::allocate(cb, &layer.proof, layer.common(), &air_public_counts);
    assert_eq!(vi.air_public_targets.len(), 1, "one carrier instance");
    assert_eq!(
        vi.air_public_targets[0].len(),
        2,
        "the carrier's two public values MUST surface as 2 air_public_targets"
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
    .expect("build carrier verifier");
    vi
}

/// One IVC link between adjacent carriers: build the link circuit (two
/// `verify_batch_circuit`s + the `v_out(prev) == v_in(cur)` carry `connect`) and
/// run it (witness-generation — `runner.run()` — which executes the in-circuit
/// verification of BOTH inner carrier proofs and the carry bind). Returns the
/// build + witness-gen wall time in ms. Panics if the link is rejected.
///
/// CAVEAT: this is the link's witness-GENERATION, exactly as Probe R defines the
/// link — it is NOT a STARK *prove* of the link circuit. Probe I, by contrast,
/// measures `prove_next_layer` (a full STARK prove of the recursion layer). So the
/// two are different stages of the pipeline and the link time below is a floor,
/// not the eventual recursion-layer prove cost.
fn run_link_timed(prev: &Layer, cur: &Layer) -> u128 {
    let t0 = Instant::now();
    let perm = default_babybear_poseidon2_16();
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let prev_vi = add_carrier_verifier(&mut cb, prev);
    let cur_vi = add_carrier_verifier(&mut cb, cur);

    // IVC thread: layer N's emitted v_out is layer N+1's consumed v_in.
    cb.connect(
        prev_vi.air_public_targets[0][1],
        cur_vi.air_public_targets[0][0],
    );

    let circuit = cb.build().expect("build link circuit");
    let mut runner = circuit.runner();

    let (mut pubs, mut privs) = prev_vi.pack_values(&prev.pvs, &prev.proof, prev.common());
    let (cur_pubs, cur_privs) = cur_vi.pack_values(&cur.pvs, &cur.proof, cur.common());
    pubs.extend(cur_pubs);
    privs.extend(cur_privs);
    runner.set_public_inputs(&pubs).expect("set pub");
    runner.set_private_inputs(&privs).expect("set priv");
    runner.run().expect("run link");
    t0.elapsed().as_millis()
}

/// Probe-I bare-layer baseline (Goldilocks `prove_next_layer` over a ~2^16-gate
/// inner proof), for the carrier-construction delta.
const PROBE_I_LAYER_MS: u128 = 3200;
const PROBE_I_RSS_GB: f64 = 1.4;

/// One full state TRANSITION in this IVC construction = one inner carrier prove
/// (`prove_batch` at real inner size) + one IVC link (`verify_batch_circuit` ×2 +
/// carry connect). This is the warm-prove cost the ≤5 s budget gates.
const WARM_BUDGET_MS: u128 = 5000;

#[test]
fn probe_r_cost() {
    // Scale each carrier's inner trace toward the real ~2^16-row state transition.
    // 1<<16 rows = real-circuit inner-proof size proxy.
    let rows = 1usize << 16;
    let v0 = 10u32;

    eprintln!(
        "probe_r_cost: inner CarrierAir rows = {rows} (1<<{}), field = BabyBear, depth-4 chain",
        rows.trailing_zeros()
    );

    // Build 4 honest layers at the scaled inner size, timing each base carrier
    // prove. Layer k commits [v0+k-1, v0+k]; carrier forces v_out = v_in + 1.
    let mut layers = Vec::with_capacity(4);
    let mut base_ms_each = Vec::with_capacity(4);
    for k in 0..4u32 {
        let v_in = F::from_u32(v0 + k) - F::ONE; // v0 + k - 1
        let (layer, ms) = prove_layer_timed(v_in, rows);
        eprintln!("probe_r_cost: layer {k} base prove (rows={rows}) = {ms} ms");
        base_ms_each.push(ms);
        layers.push(layer);
    }

    // Time every IVC link 0->1, 1->2, 2->3 (each: 2× verify_batch_circuit at the
    // scaled inner size + the carry connect, run to completion).
    let mut link_ms_each = Vec::with_capacity(3);
    for k in 0..3 {
        let ms = run_link_timed(&layers[k], &layers[k + 1]);
        eprintln!(
            "probe_r_cost: IVC link {k}->{} build+witness-gen (in-circuit verify, NOT a STARK prove) = {ms} ms",
            k + 1
        );
        link_ms_each.push(ms);
    }

    // The carry value is still provably V_3 == V_0 + 3 at the scaled size: the
    // threading is intact, only the inner trace grew.
    assert_eq!(
        layers[3].pvs[0][1],
        F::from_u32(v0 + 3),
        "layer-3 carried value must be V_0 + 3 (threading intact at scaled size)"
    );

    // --- Aggregate + DELTA vs Probe I --------------------------------------
    let n_layers = base_ms_each.len() as u128;
    let n_links = link_ms_each.len() as u128;
    let base_avg = base_ms_each.iter().sum::<u128>() / n_layers;
    let link_avg = link_ms_each.iter().sum::<u128>() / n_links;
    // One transition = one inner carrier prove + one IVC link.
    let transition_ms = base_avg + link_avg;

    eprintln!("probe_r_cost: ===== SUMMARY =====");
    eprintln!("probe_r_cost: per-layer base carrier prove (avg over {n_layers}) = {base_avg} ms");
    eprintln!(
        "probe_r_cost: per-link IVC witness-gen (avg over {n_links})       = {link_avg} ms  (in-circuit verify, NOT a STARK prove)"
    );
    eprintln!("probe_r_cost: per-TRANSITION (inner prove + IVC link)        = {transition_ms} ms");
    eprintln!(
        "probe_r_cost: Probe I bare-layer baseline                    = {PROBE_I_LAYER_MS} ms / {PROBE_I_RSS_GB} GB (a full prove_next_layer STARK prove)"
    );
    eprintln!(
        "probe_r_cost: DELTA transition vs Probe I bare layer         = {} ms ({:+} ms vs the {PROBE_I_LAYER_MS} ms bare floor)",
        transition_ms,
        transition_ms as i128 - PROBE_I_LAYER_MS as i128
    );
    eprintln!(
        "probe_r_cost: NOTE — Probe I's layer = a STARK PROVE of the recursion layer; this probe's link = witness-GEN only, so the link figure is a floor, not the eventual link-prove cost."
    );
    eprintln!(
        "probe_r_cost: peak RSS: capture via `/usr/bin/time -l cargo nextest run probe_r_cost --no-capture` (compare vs Probe I {PROBE_I_RSS_GB} GB)"
    );

    // --- VERDICT against the ≤5 s warm-prove budget ------------------------
    if transition_ms <= WARM_BUDGET_MS {
        eprintln!(
            "probe_r_cost: VERDICT = WITHIN BUDGET — per-transition {transition_ms} ms <= {WARM_BUDGET_MS} ms warm budget"
        );
    } else {
        eprintln!(
            "probe_r_cost: VERDICT = !!! BLOWS BUDGET !!! — per-transition {transition_ms} ms > {WARM_BUDGET_MS} ms warm budget (over by {} ms / {:.2}x)",
            transition_ms - WARM_BUDGET_MS,
            transition_ms as f64 / WARM_BUDGET_MS as f64
        );
    }

    // The test PASSES on measurement regardless of the verdict — the budget call
    // is a reported finding, not a hard assertion (the chain still proves sound).
}
