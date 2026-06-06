//! Probe AC — the `MAX_IN_COINS` **fan-in sweep**: how does the in-circuit
//! source-aggregation STARK-prove cost scale as you reduce the number of
//! in-coins a send may consume, and how far does that pull `/api/send` toward
//! (or under) Plonky2?
//!
//! # The one protocol-level lever
//!
//! Probe X measured the production fan-in (8 source carriers + 1 predecessor /
//! IVC carrier) recursion-overhead STARK-prove at **4.0 s non-zk / 6.7 s zk**
//! and found it DOMINATES the full populated `/api/send` prove — erasing the
//! Probe-T single-transition win. Probe AB then swept the *circuit-side* levers
//! (inner hash, ZK-only-outer, cheaper inner FRI) and found the dominant
//! inner-hash win is already banked, leaving the cheaper-inner-FRI lever
//! (q=48 -> 64-bit inner) as the only non-trivial circuit-side reduction
//! (~2.4x on the aggregation in Probe AB's run).
//!
//! Probe AC turns the remaining knob: **`MAX_IN_COINS` itself**. The aggregator
//! verifies one `verify_batch_circuit` per in-coin slot, and each such verifier
//! sub-circuit adds committed AREA that must be STARK-proved. So the aggregation
//! cost is, to first order, a baseline (the predecessor/IVC verifier + the
//! poseidon2/recompose table overhead) PLUS a per-source term times the fan-in.
//! Reducing `MAX_IN_COINS` from 8 removes per-source verifier areas directly.
//!
//! **This is the ONE lever that is PROTOCOL-visible, not circuit-internal.**
//! `MAX_IN_COINS` caps how many in-coins a single send can consume. Lowering it
//! is an operator/protocol decision with a user-facing cost: a wallet holding
//! many small coins must either consolidate first (an extra send) or split a
//! payment across more sends when it needs more than `MAX_IN_COINS` inputs. So
//! the payoff measured here is bought with a real protocol restriction — this
//! probe quantifies BOTH sides so the operator can make the call honestly.
//!
//! # What is swept
//!
//! Fan-in N ∈ {1, 2, 4, 8} source carriers + 1 predecessor (IVC) carrier. For
//! each N we build the N+1 aggregator recursion circuit (the exact Probe-X
//! construction: in-circuit `verify_batch_circuit` per inner proof, per-source
//! `active`-bit mask in Probe E's allocation order, IVC carry select+connect),
//! STARK-prove it via the low-level `prove_all_tables` path (NOT #436's broken
//! high-level multi-layer API — see Probe X's module doc for the #436 boundary),
//! verify every proof, and measure warm p50/p90 + peak RSS.
//!
//! The sweep is run twice:
//!
//!   1. **Production-strength** inner FRI (`new_benchmark`: blowup-1, 100
//!      queries, 16-bit query PoW => 116 conjectured bits) — matching Probe X.
//!      This is the headline curve.
//!   2. **Cheaper-inner-FRI** (Probe AB's lever: 48 queries => 64 conjectured
//!      bits `[VERIFY]`) — so the COMBINATION of the two levers
//!      (smaller MAX_IN_COINS + cheaper inner FRI) is visible, e.g. the
//!      N=4 + q=48 corner.
//!
//! All proofs verify (hard gate). Packing type + thread count printed.
//!
//! # The flat single-layer shape (faithful + conservative)
//!
//! As in Probe X: a flat single-layer aggregator that verifies all N+1 inner
//! proofs in one circuit has prove-cost = sum of the in-circuit verifier areas.
//! A 2-to-1 fan-in tree over the N sources verifies the SAME N proofs but splits
//! them across intermediate layers that ALSO must be STARK-proved and re-verified
//! — strictly MORE total work. So each flat N+1 figure is the faithful
//! single-aggregator-layer cost AND a conservative lower bound on a tree.
//!
//! # Recomposition
//!
//! `/api/send` ~= Probe T transition (0.31 s) + AC aggregation prove (per N) +
//! Plonky3 node overhead (5.6 s), vs Plonky2 ~10 s live / 4.35 s warm
//! single-prove.
//!
//! # The honest verdict
//!
//! Stated plainly at the end: how far does reducing `MAX_IN_COINS` pull
//! `/api/send` toward / under Plonky2; whether the cost is linear or sublinear
//! in fan-in (i.e. how large the fixed baseline is vs the per-source term);
//! whether `MAX_IN_COINS = 4` or `= 2`, COMBINED with cheaper-inner-FRI (AB),
//! yields a clear deployable win; and at what protocol cost (fewer in-coins per
//! send). The test PASSES on successful measurement + verification regardless of
//! the speed outcome.

use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_batch_stark::{
    BatchProof, ProverData, StarkGenericConfig, StarkInstance, prove_batch, verify_batch,
};
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::NonPrimitiveOpId;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit_prover::batch_stark_prover::{poseidon2_air_builders, recompose_air_builders};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking,
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::{InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness, set_fri_mmcs_private_data};
use p3_recursion::{
    BatchStarkVerifierInputsBuilder, FriVerifierParams, Poseidon2Config, verify_batch_circuit,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

// --------------------------------------------------------------------------
// BabyBear recursion config — Poseidon2 field-native MMCS for the inner carrier
// proofs (the SAME `MyMmcs` Probe X / AB use), parameterised by inner FRI so the
// sweep can run at production strength (q=100, 116-bit) AND at the Probe-AB
// cheaper-inner-FRI setting (q=48, 64-bit).
// --------------------------------------------------------------------------
type F = BabyBear;
const D: usize = 4;
const WIDTH: usize = 16;
const RATE: usize = 8;
const DIGEST_ELEMS: usize = 8;
type Challenge = BinomialExtensionField<F, D>;
type Dft = Radix2DitParallel<F>;
type Perm = Poseidon2BabyBear<WIDTH>;
type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
type MyMmcs = MerkleTreeMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    MyHash,
    MyCompress,
    2,
    DIGEST_ELEMS,
>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

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

/// FRI configuration for the carrier proofs and the matching in-circuit
/// verifier. Probe AC runs the WHOLE recursion (inner carrier proofs + outer
/// aggregation prove) at one config per sweep: the production row uses `PROD`
/// (matching Probe X exactly, where inner and outer share `new_benchmark`), the
/// cheaper-FRI row uses `Q48` end-to-end. `num_queries` is the dominant
/// in-circuit (and STARK-proved) area driver, so this knob is what the
/// cheaper-inner-FRI lever turns. (Probe AB instead pinned a full-strength outer
/// and varied only the inner; here we vary both together so the production row
/// is the faithful Probe-X reproduction and the cheaper row is the clean
/// best-case combination — both are honest, just different reference points,
/// stated in the verdict.)
#[derive(Clone, Copy)]
struct InnerFriCfg {
    /// FRI `num_queries` for the inner proofs (the in-circuit-opening driver).
    num_queries: usize,
    /// FRI `log_blowup` for the inner proofs.
    log_blowup: usize,
    /// Query proof-of-work bits.
    query_pow_bits: usize,
    /// Commit proof-of-work bits.
    commit_pow_bits: usize,
    /// `log_final_poly_len`.
    log_final_poly_len: usize,
    /// Human label.
    label: &'static str,
}

impl InnerFriCfg {
    /// Production-strength inner FRI = Probe X baseline: `new_benchmark`
    /// (blowup-1, 100 queries, 16-bit query PoW => 1*100 + 16 = 116 bits).
    const PROD: Self = Self {
        num_queries: 100,
        log_blowup: 1,
        query_pow_bits: 16,
        commit_pow_bits: 0,
        log_final_poly_len: 0,
        label: "production new_benchmark (blowup=1, q=100, 116-bit)",
    };

    /// Probe-AB cheaper inner FRI: 48 queries (1*48 + 16 = 64 conjectured bits).
    /// A plausible recursion-inner setting if the composition argument holds
    /// `[VERIFY]`.
    const Q48: Self = Self {
        num_queries: 48,
        label: "cheaper inner FRI (blowup=1, q=48, 64-bit [VERIFY])",
        ..Self::PROD
    };

    fn conjectured_bits(&self) -> usize {
        self.log_blowup * self.num_queries + self.query_pow_bits
    }

    /// Build a concrete (non-hiding) `FriParameters` from this config.
    fn fri_params(&self, mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
        FriParameters {
            log_blowup: self.log_blowup,
            log_final_poly_len: self.log_final_poly_len,
            max_log_arity: 1,
            num_queries: self.num_queries,
            commit_proof_of_work_bits: self.commit_pow_bits,
            query_proof_of_work_bits: self.query_pow_bits,
            mmcs,
        }
    }
}

/// Build a BabyBear `MyConfig` under the given inner FRI config.
fn make_config(cfg: &InnerFriCfg) -> MyConfig {
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = MyMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = cfg.fri_params(challenge_mmcs);
    let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
    MyConfig::new(pcs, Challenger::new(perm))
}

/// In-circuit FRI verifier params matching the inner FRI config, with real MMCS
/// verification (`with_mmcs`, Poseidon2 — the sound production path, NOT Probe
/// R's arithmetic-only). The scalar knobs do NOT include `num_queries`: the
/// in-circuit verifier processes whatever number of query openings the proof
/// actually carries, so the cheaper-inner-FRI lever (fewer queries) is driven
/// entirely by the inner proof shape.
fn fri_verifier_params(cfg: &InnerFriCfg) -> FriVerifierParams {
    FriVerifierParams::with_mmcs(
        cfg.log_blowup,
        cfg.log_final_poly_len,
        cfg.commit_pow_bits,
        cfg.query_pow_bits,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
}

// --------------------------------------------------------------------------
// CarrierAir — Probe R/X two-public-value carrier `[v_in, v_out]` with the
// native `v_out == v_in + 1` increment. The inner proof the recursion circuit
// verifies; each source coin and the predecessor account is one such carrier.
// --------------------------------------------------------------------------
#[derive(Clone, Copy)]
struct CarrierAir {
    rows: usize,
}

impl CarrierAir {
    fn honest_trace(&self, v: F) -> RowMajorMatrix<F> {
        let width = 2;
        let mut values = F::zero_vec(self.rows * width);
        for row in 0..self.rows {
            let idx = row * width;
            values[idx] = v;
            values[idx + 1] = v + F::ONE;
        }
        RowMajorMatrix::new(values, width)
    }
}

impl BaseAir<F> for CarrierAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        2
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for CarrierAir {
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

/// A produced inner carrier proof + everything the recursion circuit needs.
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

/// Prove one honest carrier layer at `rows` inner trace height under `config`.
fn prove_layer(config: &MyConfig, v: F, rows: usize) -> Layer {
    let air = CarrierAir { rows };
    let trace = air.honest_trace(v);
    let pvs = [vec![v, v + F::ONE]];
    let instances = vec![StarkInstance {
        air: &air,
        trace: &trace,
        public_values: pvs[0].clone(),
    }];
    let prover_data = ProverData::from_instances(config, &instances);
    let proof = prove_batch(config, &instances, &prover_data);
    verify_batch(config, &air_slice(&air), &proof, &pvs, &prover_data.common)
        .expect("native carrier verify");
    Layer {
        proof,
        air,
        pvs,
        prover_data,
    }
}

fn air_slice(air: &CarrierAir) -> [CarrierAir; 1] {
    [*air]
}

type Vi = BatchStarkVerifierInputsBuilder<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>;

/// Allocate one carrier proof into `cb` and run `verify_batch_circuit` against
/// it under the (real-MMCS) verifier params. Returns the verifier-inputs builder
/// AND the MMCS op-ids the in-circuit FRI verifier produced (for the
/// Merkle-opening private data at witness-gen time, the sound `with_mmcs` path).
fn add_carrier_verifier(
    config: &MyConfig,
    vparams: &FriVerifierParams,
    cb: &mut CircuitBuilder<Challenge>,
    layer: &Layer,
) -> (Vi, Vec<NonPrimitiveOpId>) {
    let lookup_gadget = LogUpGadget::new();
    let air_public_counts = vec![2usize];
    let vi = Vi::allocate(cb, &layer.proof, layer.common(), &air_public_counts);
    assert_eq!(vi.air_public_targets.len(), 1, "one carrier instance");
    assert_eq!(
        vi.air_public_targets[0].len(),
        2,
        "carrier's two public values must surface"
    );
    let mmcs_op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        config,
        &air_slice(&layer.air),
        cb,
        &vi.proof_targets,
        &vi.air_public_targets,
        vparams,
        &vi.common_data,
        &lookup_gadget,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .expect("build carrier verifier (real MMCS)");
    (vi, mmcs_op_ids)
}

/// Set the FRI MMCS private data for one verified inner proof on the runner.
fn set_mmcs_for(
    runner: &mut p3_circuit::CircuitRunner<'_, Challenge>,
    op_ids: &[NonPrimitiveOpId],
    layer: &Layer,
) {
    set_fri_mmcs_private_data::<
        F,
        Challenge,
        ChallengeMmcs,
        MyMmcs,
        MyHash,
        MyCompress,
        DIGEST_ELEMS,
    >(
        runner,
        op_ids,
        &layer.proof.opening_proof,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .expect("set MMCS private data");
}

/// Result of building + STARK-proving the aggregator recursion circuit at one
/// fan-in N under one inner FRI config.
struct ProveResult {
    fan_in: usize,
    build_ms: f64,
    cold_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    rss_mb: f64,
    witness_count: usize,
}

/// Build the fan-in `N + 1` aggregator recursion circuit (N source carriers + 1
/// predecessor / IVC carrier), then STARK-PROVE it. `fan_in` = N source slots;
/// the circuit is fixed-shape at exactly N slots (this is what lowering
/// `MAX_IN_COINS` to N would produce). All N source slots are active (worst
/// case), mirroring Probe X / AB's all-active measurement.
///
/// Steps (the production recursion shape, identical to Probe X but with N slots):
///   1. Verify the predecessor (IVC) carrier in-circuit, surfacing `V_prev`.
///   2. For each of N source slots: verify its carrier in-circuit, surface
///      `[v_in, v_out]`, apply the `active`-bit mask in the Probe-E allocation
///      order (verifier inputs, then this slot's `active` public input).
///   3. Connect the IVC carry (cost-faithful select+connect; value-semantics
///      proven sound in Probe R).
///   4. Compile to tables and STARK-prove via the low-level `prove_all_tables`
///      path (NOT #436's high-level API). Verify the proof, warm p50/p90 + RSS.
fn prove_aggregator(cfg: &InnerFriCfg, inner_rows: usize, fan_in: usize) -> ProveResult {
    assert!(fan_in >= 1, "fan-in must be >= 1 source slot");
    let config = make_config(cfg);
    let vparams = fri_verifier_params(cfg);

    // --- inner carrier proofs: 1 predecessor + N sources -------------------
    let predecessor = prove_layer(&config, F::from_u32(100), inner_rows);
    let sources: Vec<Layer> = (0..fan_in)
        .map(|i| prove_layer(&config, F::from_u32(200 + i as u32), inner_rows))
        .collect();

    // --- build the aggregator recursion circuit ----------------------------
    let t_build = Instant::now();
    let perm = default_babybear_poseidon2_16();
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    // 1. predecessor (IVC) carrier verified in-circuit.
    let (pred_vi, pred_op_ids) = add_carrier_verifier(&config, &vparams, &mut cb, &predecessor);

    // 2. N source carriers verified in-circuit, each with an active-bit mask in
    //    the Probe-E allocation order (verifier inputs first, then this slot's
    //    `active` public input — the per-source allocation-order fix Probe X's
    //    module doc notes, reproduced in the pack_values ordering below).
    let mut source_vis = Vec::with_capacity(fan_in);
    let mut source_op_ids = Vec::with_capacity(fan_in);
    let mut active_inputs = Vec::with_capacity(fan_in);
    for (i, src) in sources.iter().enumerate() {
        let (src_vi, src_ids) = add_carrier_verifier(&config, &vparams, &mut cb, src);
        let v_out = src_vi.air_public_targets[0][1];
        let active = cb.alloc_public_input("active");
        cb.assert_bool(active);
        // expected emitted value for an honest active slot i = (200 + i) + 1.
        let expected = cb.alloc_const(Challenge::from(F::from_u32(201 + i as u32)), "expected");
        let masked = cb.select(active, expected, v_out);
        cb.connect(v_out, masked);
        source_vis.push(src_vi);
        source_op_ids.push(src_ids);
        active_inputs.push(active);
    }

    // 3. IVC carry: cost-faithful select+connect threading the predecessor's
    //    emitted value through a select gate (committed work). Value-semantics
    //    (pred_v_out == aggregated source in) proven sound in Probe R; here we
    //    measure COST. Binds source[0]'s v_in -> the carry, gated on slot 0.
    let pred_v_out = pred_vi.air_public_targets[0][1];
    let src0_v_in = source_vis[0].air_public_targets[0][0];
    let carry = cb.select(active_inputs[0], src0_v_in, pred_v_out);
    let _ = carry; // threaded as committed work; value-semantics proven in R.

    let circuit = cb.build().expect("aggregator circuit builds");
    let build_ms = t_build.elapsed().as_secs_f64() * 1e3;
    let witness_count = circuit.public_flat_len;

    // --- compile to tables (NPO preprocessors for poseidon2 + recompose) ----
    let table_packing = TablePacking::new(1, 8);
    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::default()),
    ];
    let mut air_builders = poseidon2_air_builders::<_, D>();
    air_builders.extend(recompose_air_builders(1, false));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<MyConfig, _, D>(
            &circuit,
            &table_packing,
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("airs and degrees for aggregator");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    // --- pack public/private inputs + MMCS private data --------------------
    // All N source slots active (worst case). Public inputs are over the
    // challenge (extension) field. We pack in EXACT allocation order:
    // predecessor verifier inputs, then for each source (verifier inputs, then
    // its `active` public input).
    let (mut pubs, mut privs) =
        pred_vi.pack_values(&predecessor.pvs, &predecessor.proof, predecessor.common());
    for (i, src_vi) in source_vis.iter().enumerate() {
        let (s_pub, s_priv) =
            src_vi.pack_values(&sources[i].pvs, &sources[i].proof, sources[i].common());
        pubs.extend(s_pub);
        privs.extend(s_priv);
        pubs.push(Challenge::ONE); // active = 1 for every slot (worst case).
    }

    let run_witness = || {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&pubs).expect("set pub");
        runner.set_private_inputs(&privs).expect("set priv");
        set_mmcs_for(&mut runner, &pred_op_ids, &predecessor);
        for (i, ids) in source_op_ids.iter().enumerate() {
            set_mmcs_for(&mut runner, ids, &sources[i]);
        }
        runner.run().expect("aggregator witness-gen")
    };

    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(make_config(cfg)).with_table_packing(table_packing);
    prover.register_poseidon2_table::<D>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<D>(false);

    // --- cold STARK-prove + verify -----------------------------------------
    let traces = run_witness();
    let t_cold = Instant::now();
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("STARK-prove aggregator recursion circuit");
    let cold_ms = t_cold.elapsed().as_secs_f64() * 1e3;
    prover
        .verify_all_tables(&proof)
        .expect("verify aggregator recursion proof");

    // --- warmup + warm p50/p90 over WARM_RUNS ------------------------------
    let traces_warm = run_witness();
    let _ = prover
        .prove_all_tables(&traces_warm, &circuit_prover_data)
        .expect("warmup prove");
    const WARM_RUNS: usize = 5;
    let mut times = Vec::with_capacity(WARM_RUNS);
    for _ in 0..WARM_RUNS {
        let traces_run = run_witness();
        let t = Instant::now();
        let p = prover
            .prove_all_tables(&traces_run, &circuit_prover_data)
            .expect("warm prove");
        times.push(t.elapsed().as_secs_f64() * 1e3);
        prover.verify_all_tables(&p).expect("warm verify");
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());

    ProveResult {
        fan_in,
        build_ms,
        cold_ms,
        p50_ms: quantile(&times, 0.50),
        p90_ms: quantile(&times, 0.90),
        rss_mb: peak_rss_mb(),
        witness_count,
    }
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// Peak resident-set size in MB. `ru_maxrss` is BYTES on macOS (KB on Linux).
fn peak_rss_mb() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(rc, 0, "getrusage failed");
    let max_rss = usage.ru_maxrss as f64;
    if cfg!(target_os = "macos") {
        max_rss / (1u64 << 20) as f64
    } else {
        (max_rss * 1024.0) / (1u64 << 20) as f64
    }
}

// --------------------------------------------------------------------------
// Composition anchors (from Probe T / X / AB and the migration research).
// --------------------------------------------------------------------------
/// Current production fan-in cap (the value Probe AC sweeps DOWN from).
const MAX_IN_COINS_CURRENT: usize = 8;
/// Probe T single state-transition warm-prove, ms.
const PROBE_T_TRANSITION_MS: f64 = 312.0;
/// Plonky3 node overhead (non-prove) on a populated `/api/send`, ms.
const NODE_OVERHEAD_MS: f64 = 5600.0;
/// Plonky2 warm single-prove baseline, ms.
const PLONKY2_WARM_MS: f64 = 4350.0;
/// Plonky2 live populated `/api/send`, ms.
const PLONKY2_LIVE_SEND_MS: f64 = 10_000.0;

/// Recomposed `/api/send` estimate = Probe T transition + AC aggregation +
/// Plonky3 node overhead.
fn recomposed_send_ms(aggregation_ms: f64) -> f64 {
    PROBE_T_TRANSITION_MS + aggregation_ms + NODE_OVERHEAD_MS
}

/// The fan-in values to sweep (source coins). N=8 is the current `MAX_IN_COINS`.
const FAN_INS: [usize; 4] = [1, 2, 4, 8];

#[test]
fn probe_ac_max_in_coins_sweep() {
    let packing_type = core::any::type_name::<<F as Field>::Packing>();
    let scalar_type = core::any::type_name::<F>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = rayon::current_num_threads();

    println!("\n===== Probe AC: MAX_IN_COINS fan-in sweep (the one protocol-level lever) =====");
    println!("shape          : 1 predecessor (IVC) carrier + N source carriers (N swept),");
    println!("                 flat single-layer verify_batch_circuit + active masks + IVC carry.");
    println!(
        "stage measured : STARK-PROVE of the recursion circuit (prove_all_tables, low-level path)."
    );
    println!(
        "inner verifier : FriVerifierParams::with_mmcs (REAL in-circuit MMCS opening checks)."
    );
    println!(
        "inner hash     : Poseidon2 field-native MMCS (circuit-friendly; matches Probe X/AB)."
    );
    println!("all source slots active (worst case), matching Probe X / AB.");
    println!("BabyBear::Packing : {packing_type}");
    println!("  -> SIMD packing active: {packing_active} (vs scalar {scalar_type})");
    println!("rayon threads     : {threads}");
    println!(
        "anchors           : ProbeT {PROBE_T_TRANSITION_MS:.0} ms transition | node overhead {NODE_OVERHEAD_MS:.0} ms"
    );
    println!(
        "                    Plonky2 {PLONKY2_WARM_MS:.0} ms warm / {PLONKY2_LIVE_SEND_MS:.0} ms live /api/send"
    );
    println!(
        "PROTOCOL COST     : lowering MAX_IN_COINS to N caps a send at N in-coins; a wallet with"
    );
    println!(
        "                    >N small coins must consolidate first (extra send) or split payment."
    );

    // Inner carrier trace height (recursion-circuit cost is verifier-area
    // driven, ~independent of inner trace height; matches Probe X / AB).
    let inner_rows = 1usize << 10;
    println!(
        "inner carrier rows: {inner_rows} (1<<{}) | sweeping N in {:?} (current MAX_IN_COINS={MAX_IN_COINS_CURRENT})",
        inner_rows.trailing_zeros(),
        FAN_INS
    );

    let configs = [InnerFriCfg::PROD, InnerFriCfg::Q48];

    // results[config_idx] = Vec of (ProveResult) over FAN_INS.
    let mut all_results: Vec<(InnerFriCfg, Vec<ProveResult>)> = Vec::new();

    for cfg in &configs {
        println!(
            "\n--- sweep @ inner+verifier FRI = {} ({} bits) ---",
            cfg.label,
            cfg.conjectured_bits()
        );
        let mut rows = Vec::with_capacity(FAN_INS.len());
        for &n in &FAN_INS {
            let r = prove_aggregator(cfg, inner_rows, n);
            println!(
                "  N={:<2} (N+1={:<2} verified): build={:.1}ms cold={:.1}ms warm_p50={:.1}ms p90={:.1}ms rss={:.0}MB public_flat_len={}",
                r.fan_in,
                r.fan_in + 1,
                r.build_ms,
                r.cold_ms,
                r.p50_ms,
                r.p90_ms,
                r.rss_mb,
                r.witness_count
            );
            rows.push(r);
        }
        all_results.push((*cfg, rows));
    }

    // The N=8 production-strength figure is the Probe-X-equivalent reference.
    let prod_rows = &all_results[0].1;
    let q48_rows = &all_results[1].1;
    let n8_prod = prod_rows
        .iter()
        .find(|r| r.fan_in == MAX_IN_COINS_CURRENT)
        .expect("N=8 production row")
        .p50_ms;

    // ----------------------------------------------------------------------
    // Sweep table: aggregation p50, reduction vs N=8, recomposed /api/send.
    // ----------------------------------------------------------------------
    println!("\n===================== Probe AC sweep results (warm, p50) =====================");
    println!("(reduction vs N=8 measured WITHIN the same FRI config; send = ProbeT + agg + node)");
    println!(
        "{:<26} {:>3} {:>10} {:>11} {:>13} {:>10}",
        "inner FRI", "N", "agg_p50", "vs N=8", "send_est", "rss_MB"
    );
    let print_block = |label: &str, rows: &[ProveResult]| {
        let n8 = rows
            .iter()
            .find(|r| r.fan_in == MAX_IN_COINS_CURRENT)
            .map(|r| r.p50_ms)
            .unwrap_or(f64::NAN);
        for r in rows {
            let reduction = n8 / r.p50_ms;
            let send = recomposed_send_ms(r.p50_ms);
            println!(
                "{:<26} {:>3} {:>9.0}ms {:>10.2}x {:>11.0}ms {:>10.0}",
                label, r.fan_in, r.p50_ms, reduction, send, r.rss_mb
            );
        }
    };
    print_block("production (q=100,116b)", prod_rows);
    print_block("cheaper-FRI (q=48,64b)", q48_rows);

    // ----------------------------------------------------------------------
    // Linearity read: is the cost linear or sublinear in fan-in?
    // Per-source slope = (p50(N=8) - p50(N=1)) / (8 - 1); fixed baseline ~=
    // p50(N=1) minus one per-source term, i.e. predecessor + table overhead.
    // ----------------------------------------------------------------------
    println!("\n------------------------- scaling read (production FRI) ----------------------");
    let p1 = prod_rows[0].p50_ms; // N=1
    let p8 = prod_rows[3].p50_ms; // N=8
    let per_source = (p8 - p1) / (MAX_IN_COINS_CURRENT as f64 - 1.0);
    // Extrapolated fixed baseline (N=0: predecessor verifier + poseidon2/
    // recompose tables) = p1 - per_source.
    let fixed_baseline = p1 - per_source;
    println!(
        "N=1 agg = {p1:.0} ms ; N=8 agg = {p8:.0} ms ; per-source slope ~= {per_source:.0} ms/coin"
    );
    println!(
        "extrapolated fixed baseline (predecessor verifier + tables, N=0) ~= {fixed_baseline:.0} ms"
    );
    if fixed_baseline > per_source {
        println!(
            "=> SUBLINEAR in fan-in: a large fixed baseline ({fixed_baseline:.0} ms) dominates the"
        );
        println!(
            "   per-source term ({per_source:.0} ms). Cutting MAX_IN_COINS removes per-source area"
        );
        println!("   but cannot fall below the fixed baseline — diminishing returns below N~2-4.");
    } else {
        println!(
            "=> roughly LINEAR / per-source-dominated: per-source term ({per_source:.0} ms) >= fixed"
        );
        println!(
            "   baseline ({fixed_baseline:.0} ms). Each in-coin removed buys close to a full slot."
        );
    }

    // ----------------------------------------------------------------------
    // Combined-lever corner: N=4 + cheaper inner FRI (the brief's key point).
    // ----------------------------------------------------------------------
    let n4_prod = prod_rows[2].p50_ms;
    let n4_q48 = q48_rows[2].p50_ms;
    let n2_q48 = q48_rows[1].p50_ms;
    println!("\n--------------------- combined lever: MAX_IN_COINS + cheaper-FRI -------------");
    println!(
        "N=8 production (Probe-X-equiv) : agg {n8_prod:.0} ms -> send {:.0} ms",
        recomposed_send_ms(n8_prod)
    );
    println!(
        "N=4 production                 : agg {n4_prod:.0} ms -> send {:.0} ms",
        recomposed_send_ms(n4_prod)
    );
    println!(
        "N=4 + cheaper-FRI (q=48,64b)   : agg {n4_q48:.0} ms -> send {:.0} ms",
        recomposed_send_ms(n4_q48)
    );
    println!(
        "N=2 + cheaper-FRI (q=48,64b)   : agg {n2_q48:.0} ms -> send {:.0} ms",
        recomposed_send_ms(n2_q48)
    );

    // ----------------------------------------------------------------------
    // Verdict vs Plonky2 across the sweep.
    // ----------------------------------------------------------------------
    println!("\n========================= verdict vs Plonky2 ================================");
    let verdict = |label: &str, agg_ms: f64| {
        let send_ms = recomposed_send_ms(agg_ms);
        let (rel_warm, fac_warm) = if send_ms < PLONKY2_WARM_MS {
            ("FASTER", PLONKY2_WARM_MS / send_ms)
        } else {
            ("SLOWER", send_ms / PLONKY2_WARM_MS)
        };
        let (rel_live, fac_live) = if send_ms < PLONKY2_LIVE_SEND_MS {
            ("FASTER", PLONKY2_LIVE_SEND_MS / send_ms)
        } else {
            ("SLOWER", send_ms / PLONKY2_LIVE_SEND_MS)
        };
        println!(
            "  {label:<32} send {send_ms:.0} ms: vs warm {PLONKY2_WARM_MS:.0} -> {rel_warm} {fac_warm:.2}x | vs live {PLONKY2_LIVE_SEND_MS:.0} -> {rel_live} {fac_live:.2}x"
        );
    };
    verdict("N=8 production (current)", n8_prod);
    verdict("N=4 production", n4_prod);
    verdict("N=2 production", prod_rows[1].p50_ms);
    verdict("N=1 production", p1);
    verdict("N=4 + cheaper-FRI", n4_q48);
    verdict("N=2 + cheaper-FRI", n2_q48);
    verdict("N=1 + cheaper-FRI", q48_rows[0].p50_ms);

    // ----------------------------------------------------------------------
    // The honest bottom line.
    // ----------------------------------------------------------------------
    const MARGIN_BAND: f64 = 1.20;
    println!("\n=============================== BOTTOM LINE ==================================");
    println!("MAX_IN_COINS is the ONE protocol-level lever: each in-coin slot is one in-circuit");
    println!(
        "verify_batch_circuit whose committed area must be STARK-proved. Sweeping N in {FAN_INS:?}:"
    );
    println!(
        "  per-source slope ~= {per_source:.0} ms/coin over a fixed baseline ~= {fixed_baseline:.0} ms"
    );
    println!("  (predecessor verifier + poseidon2/recompose tables — present even at N=1).");

    // Does ANY combined config clear the warm bar, and at what N?
    let best_send = recomposed_send_ms(q48_rows[0].p50_ms.min(n2_q48).min(n4_q48));
    let best_label = if recomposed_send_ms(n4_q48) < PLONKY2_WARM_MS {
        "N=4 + cheaper-FRI"
    } else if recomposed_send_ms(n2_q48) < PLONKY2_WARM_MS {
        "N=2 + cheaper-FRI"
    } else if recomposed_send_ms(q48_rows[0].p50_ms) < PLONKY2_WARM_MS {
        "N=1 + cheaper-FRI"
    } else {
        "(none clears the warm bar)"
    };

    let send_n4_q48 = recomposed_send_ms(n4_q48);
    if send_n4_q48 < PLONKY2_WARM_MS {
        println!(
            "VERDICT: MAX_IN_COINS=4 COMBINED with cheaper-inner-FRI pulls /api/send to {send_n4_q48:.0} ms"
        );
        println!(
            "  — UNDER Plonky2's warm single-prove {PLONKY2_WARM_MS:.0} ms. A CLEAR DEPLOYABLE WIN, at the"
        );
        println!(
            "  protocol cost of capping a send at 4 in-coins (vs 8). Wallets with >4 small coins"
        );
        println!("  consolidate first or split — the operator's tradeoff, quantified above.");
    } else if send_n4_q48 < PLONKY2_LIVE_SEND_MS {
        let fac_live = PLONKY2_LIVE_SEND_MS / send_n4_q48;
        println!(
            "VERDICT: MAX_IN_COINS=4 + cheaper-inner-FRI pulls /api/send to {send_n4_q48:.0} ms — FASTER"
        );
        println!("  than Plonky2's LIVE {PLONKY2_LIVE_SEND_MS:.0} ms send by {fac_live:.2}x,");
        if send_n4_q48 / PLONKY2_WARM_MS < MARGIN_BAND {
            println!(
                "  and within ~noise of the {PLONKY2_WARM_MS:.0} ms warm single-prove (~WASH on warm)."
            );
        } else {
            println!(
                "  but still SLOWER than the {PLONKY2_WARM_MS:.0} ms warm single-prove. The node overhead"
            );
            println!(
                "  ({NODE_OVERHEAD_MS:.0} ms) now dominates the recomposed send, so shrinking the aggregation"
            );
            println!(
                "  further (N=2/N=1) yields diminishing send-level returns. Best clearing config:"
            );
            println!("    {best_label} -> send {best_send:.0} ms.");
        }
        println!(
            "  Protocol cost: capping a send at 4 in-coins. The win is real vs LIVE Plonky2 but the"
        );
        println!(
            "  warm-prove bar is gated by node overhead, not the prove — see verdict table above."
        );
    } else {
        println!(
            "VERDICT: even MAX_IN_COINS=4 + cheaper-inner-FRI leaves /api/send at {send_n4_q48:.0} ms,"
        );
        println!(
            "  SLOWER than Plonky2's live {PLONKY2_LIVE_SEND_MS:.0} ms. Reducing in-coins alone does not"
        );
        println!(
            "  clear the bar at this overhead; best clearing config: {best_label} (send {best_send:.0} ms)."
        );
    }
    println!(
        "Reading the curve: returns from cutting MAX_IN_COINS are {} (per-source {per_source:.0} ms vs",
        if fixed_baseline > per_source {
            "SUBLINEAR"
        } else {
            "near-linear"
        }
    );
    println!(
        "  fixed {fixed_baseline:.0} ms). The fixed baseline (predecessor + tables) is the floor no"
    );
    println!(
        "  in-coin reduction can cross — N=1 still pays it. Combine with cheaper-inner-FRI (AB)"
    );
    println!("  for the lowest aggregation, then the recomposed send is gated by the 5.6 s node");
    println!(
        "  overhead, NOT the prove. Faithful single-aggregator-layer shape (a 2-to-1 tree costs"
    );
    println!("  strictly more, so these are conservative lower bounds). All proofs verified.");
    println!("==============================================================================\n");

    // Hard gates: full sweep measured + verified (verify inside each prove path).
    assert_eq!(all_results.len(), 2, "must measure both FRI configs");
    for (_, rows) in &all_results {
        assert_eq!(rows.len(), FAN_INS.len(), "all fan-ins measured");
        for r in rows {
            assert!(r.p50_ms > 0.0, "fan-in N={} measured", r.fan_in);
        }
    }
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got {packing_type}"
    );
}
