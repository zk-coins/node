//! Probe X′ — the **decisive lever test** for the Plonky3 send-side speed case.
//!
//! # The lever
//!
//! Probe X measured the production aggregator (8 source carriers + 1
//! predecessor/IVC carrier) as a **flat 8+1**: nine INDEPENDENT in-circuit
//! `verify_batch_circuit`s, each its own full in-circuit FRI verifier, costs
//! summed. The headline was ~4.0 s non-zk / ~6.7 s zk for the recursion-prove
//! alone, which makes the full populated `/api/send` a wash-or-loss vs Plonky2.
//! The whole migration's user-facing-latency case hinges on whether that
//! aggregation cost can be cut. Probe X′ measures the best achievable
//! reduction — real proving, real numbers, honest if it does NOT help.
//!
//! The hypothesis: the 8 source proofs are all proofs of the **same
//! source-coin circuit shape (same AIR / same vk)**, differing only in
//! witness/public values. Probe X verified them as 8 separate batch proofs
//! (each its own commitment → its own in-circuit FRI verifier). Can verifying 8
//! same-shape proofs amortize the FRI/Merkle verifier structure?
//!
//! # The a/b framing (read BOTH; they answer different questions)
//!
//! * **X′-a — lower bound / best case.** Prove the 8 sources as ONE batched
//!   `prove_batch` (8 `StarkInstance`s → one batched trace commitment, one FRI
//!   opening proof), then verify THAT proof in-circuit with a SINGLE
//!   `verify_batch_circuit` over an 8-instance `airs` slice. The in-circuit FRI
//!   verifier structure (the expensive Merkle-opening / FRI-folding sub-circuit)
//!   is instantiated **once** and shared across all 8 instances. This is the
//!   theoretical floor: it bounds how much the verifier *structure* costs vs the
//!   per-proof *opening* work. It is only physically realisable IF the protocol
//!   could batch the 8 sources at prove time.
//!
//! * **X′-b — realistic.** In the REAL protocol the 8 source proofs come from
//!   DIFFERENT prior transactions, proved independently at different times
//!   (different challengers, different commitments). They are NOT one batch and
//!   cannot be retroactively re-batched without re-proving them. X′-b proves 8
//!   **independent** batch proofs (as in reality) and verifies them in-circuit
//!   with whatever amortization the recursion API genuinely allows for same-vk
//!   proofs. The honest question this answers: can independent same-vk proofs
//!   share the in-circuit verifier? The API (`verify_batch_circuit` consumes one
//!   `BatchProofTargets` per `BatchProof`, each carrying its own commitment and
//!   FRI opening proof) forces **one verifier instantiation per independent
//!   proof** — so X′-b is structurally Probe X. We measure it to CONFIRM that,
//!   not assume it.
//!
//! # The honest verdict this probe must deliver
//!
//! If X′-a ≪ Probe X but X′-b ≈ Probe X, the conclusion is precise and
//! unspun: **batching the same-vk verifier structure is a real saving, but it is
//! UNREACHABLE for the send path** because the protocol's sources are
//! independent and cannot be retroactively batched. In that case batching does
//! NOT rescue the send-side speed case, and the only live lever is reducing
//! `MAX_IN_COINS` (fewer in-coins per send). The probe states this plainly.
//!
//! # What is measured
//!
//! For each framing × {non-zk `new_benchmark` blowup-1, zk `new_benchmark_zk`
//! blowup-2}: circuit-build wall-time, cold STARK-prove, warm p50/p90 over 5
//! runs after a warmup, peak RSS. The recursion circuit is **STARK-PROVED**
//! (`prove_all_tables`, the low-level #436-free path Probe X uses) and verified
//! — real proof, not witness-gen. Then the **reduction factor vs Probe X's flat
//! 8+1** (4.0 s non-zk / 6.7 s zk) is computed per framing, and the full
//! `/api/send` estimate is recomposed (Probe T 0.31 s + X′ aggregation + node
//! overhead 5.6 s) with the rescued/not-rescued verdict.
//!
//! The test PASSES on successful measurement + verification regardless of the
//! speed verdict — the verdict is data, not a gate.

use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_batch_stark::{
    BatchProof, ProverData, StarkGenericConfig, StarkInstance, prove_batch, verify_batch,
};
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ExprId;
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
// BabyBear recursion config — IDENTICAL to Probe X (production crypto config:
// BabyBear, real in-circuit MMCS verification, new_benchmark / new_benchmark_zk
// FRI). Reused verbatim so the X′ numbers are directly comparable to X's.
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

/// Which production-tuned FRI parameter set to use for the inner carrier proofs
/// (and, matched exactly, the in-circuit verifier params).
#[derive(Clone, Copy)]
enum FriChoice {
    /// `new_benchmark`: blowup-1, 100 queries, 16-bit query PoW. Production
    /// non-zk headline.
    BenchBlowup1,
    /// `new_benchmark_zk`: blowup-2, 100 queries, 16-bit query PoW. True-ZK FRI.
    BenchZkBlowup2,
}

impl FriChoice {
    fn label(self) -> &'static str {
        match self {
            FriChoice::BenchBlowup1 => "new_benchmark (blowup=1, non-zk)",
            FriChoice::BenchZkBlowup2 => "new_benchmark_zk (blowup=2, zk)",
        }
    }

    fn fri_params(self, mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
        match self {
            FriChoice::BenchBlowup1 => FriParameters::new_benchmark(mmcs),
            FriChoice::BenchZkBlowup2 => FriParameters::new_benchmark_zk(mmcs),
        }
    }

    fn verifier_scalars(self) -> (usize, usize, usize, usize) {
        let p = match self {
            FriChoice::BenchBlowup1 => FriParameters::<()>::new_benchmark(()),
            FriChoice::BenchZkBlowup2 => FriParameters::<()>::new_benchmark_zk(()),
        };
        (
            p.log_blowup,
            p.log_final_poly_len,
            p.commit_proof_of_work_bits,
            p.query_proof_of_work_bits,
        )
    }
}

/// Build a BabyBear `MyConfig` under the given production FRI choice.
fn make_config(fri: FriChoice) -> MyConfig {
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = MyMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = fri.fri_params(challenge_mmcs);
    let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
    MyConfig::new(pcs, Challenger::new(perm))
}

/// In-circuit FRI verifier params MATCHING the inner proof's FRI choice, with
/// **real MMCS verification enabled** (`with_mmcs`) — the sound production path.
fn fri_verifier_params(fri: FriChoice) -> FriVerifierParams {
    let (log_blowup, log_final_poly_len, commit_pow_bits, query_pow_bits) = fri.verifier_scalars();
    FriVerifierParams::with_mmcs(
        log_blowup,
        log_final_poly_len,
        commit_pow_bits,
        query_pow_bits,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
}

// --------------------------------------------------------------------------
// CarrierAir — Probe X / Probe R's two-public-value carrier `[v_in, v_out]`
// with the native `v_out == v_in + 1` increment. Unchanged: it is the inner
// proof the recursion circuit verifies. Each source coin and the predecessor
// account is one such carrier (same AIR / same vk — exactly the same-shape
// property X′ tests for amortization).
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

/// A produced inner batch proof + everything the recursion circuit needs to
/// allocate and verify it. May contain ONE instance (independent carrier, as in
/// X′-b / Probe X) or MANY instances (the batched X′-a source bundle).
struct InnerProof {
    proof: BatchProof<MyConfig>,
    /// One `CarrierAir` per instance (all same shape; distinct only by trace).
    airs: Vec<CarrierAir>,
    /// One public-value vector per instance.
    pvs: Vec<Vec<F>>,
    prover_data: ProverData<MyConfig>,
}

impl InnerProof {
    fn common(&self) -> &p3_batch_stark::CommonData<MyConfig> {
        &self.prover_data.common
    }
    fn num_instances(&self) -> usize {
        self.airs.len()
    }
}

/// Prove ONE batch proof containing `values.len()` carrier instances, all of the
/// same `CarrierAir` shape, at `rows` inner trace height. With `values.len() ==
/// 1` this is an independent single-carrier proof (X′-b / Probe X). With
/// `values.len() == 8` this is the X′-a batched-source bundle: a SINGLE
/// `prove_batch` → one trace commitment → one FRI opening proof for all 8.
fn prove_inner(config: &MyConfig, values: &[F], rows: usize) -> InnerProof {
    let airs: Vec<CarrierAir> = values.iter().map(|_| CarrierAir { rows }).collect();
    let traces: Vec<RowMajorMatrix<F>> = values.iter().map(|&v| airs[0].honest_trace(v)).collect();
    let pvs: Vec<Vec<F>> = values.iter().map(|&v| vec![v, v + F::ONE]).collect();

    let instances: Vec<StarkInstance<'_, MyConfig, CarrierAir>> = (0..values.len())
        .map(|i| StarkInstance {
            air: &airs[i],
            trace: &traces[i],
            public_values: pvs[i].clone(),
        })
        .collect();

    let prover_data = ProverData::from_instances(config, &instances);
    let proof = prove_batch(config, &instances, &prover_data);
    verify_batch(config, &airs, &proof, &pvs, &prover_data.common)
        .expect("native carrier batch verify (production FRI)");

    InnerProof {
        proof,
        airs,
        pvs,
        prover_data,
    }
}

type Vi = BatchStarkVerifierInputsBuilder<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>;

/// Allocate ONE inner batch proof (1 or N instances) into `cb` and run a SINGLE
/// `verify_batch_circuit` over ALL its instances under the (real-MMCS) verifier
/// params. For an N-instance proof this instantiates the in-circuit FRI verifier
/// structure ONCE and shares it across the N instances — the X′-a amortization.
/// Returns the verifier-inputs builder and the MMCS op-ids (for private data).
fn add_inner_verifier(
    config: &MyConfig,
    vparams: &FriVerifierParams,
    cb: &mut CircuitBuilder<Challenge>,
    inner: &InnerProof,
) -> (Vi, Vec<NonPrimitiveOpId>) {
    let lookup_gadget = LogUpGadget::new();
    let air_public_counts = vec![2usize; inner.num_instances()];
    let vi = Vi::allocate(cb, &inner.proof, inner.common(), &air_public_counts);
    assert_eq!(
        vi.air_public_targets.len(),
        inner.num_instances(),
        "one public-value target group per inner instance"
    );
    for tgt in &vi.air_public_targets {
        assert_eq!(tgt.len(), 2, "each carrier surfaces its [v_in, v_out]");
    }
    let mmcs_op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        config,
        &inner.airs,
        cb,
        &vi.proof_targets,
        &vi.air_public_targets,
        vparams,
        &vi.common_data,
        &lookup_gadget,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .expect("build inner verifier (real MMCS)");
    (vi, mmcs_op_ids)
}

/// Set the FRI MMCS private data for one verified inner proof on the runner.
fn set_mmcs_for(
    runner: &mut p3_circuit::CircuitRunner<'_, Challenge>,
    op_ids: &[NonPrimitiveOpId],
    inner: &InnerProof,
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
        &inner.proof.opening_proof,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .expect("set MMCS private data");
}

/// Production fan-in: 8 source in-coin slots + 1 predecessor (IVC) carrier.
const MAX_IN_COINS: usize = 8;

/// Which framing to build.
#[derive(Clone, Copy, PartialEq)]
enum Framing {
    /// X′-a: 8 sources proved as ONE batched proof (8 instances), verified
    /// in-circuit with a SINGLE `verify_batch_circuit`. + 1 predecessor proof.
    /// Total in-circuit verifiers: 2 (one 8-instance, one 1-instance).
    BatchedLowerBound,
    /// X′-b: 8 INDEPENDENT source proofs, each verified by its own
    /// `verify_batch_circuit`. + 1 predecessor proof. Total in-circuit
    /// verifiers: 9 — structurally identical to Probe X's flat 8+1.
    IndependentRealistic,
}

impl Framing {
    fn tag(self) -> &'static str {
        match self {
            Framing::BatchedLowerBound => "X'-a batched (lower bound)",
            Framing::IndependentRealistic => "X'-b independent (realistic)",
        }
    }
}

/// Result of building + STARK-proving one framing's aggregator recursion circuit.
struct ProveResult {
    build_ms: f64,
    cold_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    rss_mb: f64,
    witness_count: usize,
    /// Number of in-circuit `verify_batch_circuit` instantiations.
    num_in_circuit_verifiers: usize,
}

/// Build the chosen framing's aggregator recursion circuit, then STARK-PROVE it.
///
/// Both framings verify the SAME total work — 8 source carriers + 1 predecessor
/// carrier, with the per-source `active`-bit mask (Probe E) and the IVC carry
/// select (Probe R). They differ ONLY in how the 8 sources are packaged:
///   * `BatchedLowerBound` — 8 sources as one batch proof, ONE verifier;
///   * `IndependentRealistic` — 8 independent proofs, 8 verifiers.
fn prove_framing(fri: FriChoice, inner_rows: usize, framing: Framing) -> ProveResult {
    let config = make_config(fri);
    let vparams = fri_verifier_params(fri);

    // --- inner carrier proofs ---------------------------------------------
    // Predecessor account carrier: V_prev = 100 (-> emits 101). Always its own
    // independent proof (the predecessor is genuinely a different prior tx).
    let predecessor = prove_inner(&config, &[F::from_u32(100)], inner_rows);

    // Source carriers: active slot i carries (200 + i) -> emits (201 + i).
    let source_values: Vec<F> = (0..MAX_IN_COINS)
        .map(|i| F::from_u32(200 + i as u32))
        .collect();

    // X′-a: ONE 8-instance batch proof. X′-b: 8 independent 1-instance proofs.
    let batched_sources: Option<InnerProof> = match framing {
        Framing::BatchedLowerBound => Some(prove_inner(&config, &source_values, inner_rows)),
        Framing::IndependentRealistic => None,
    };
    let independent_sources: Vec<InnerProof> = match framing {
        Framing::BatchedLowerBound => Vec::new(),
        Framing::IndependentRealistic => source_values
            .iter()
            .map(|&v| prove_inner(&config, &[v], inner_rows))
            .collect(),
    };

    // --- build the aggregator recursion circuit ----------------------------
    let t_build = Instant::now();
    let perm = default_babybear_poseidon2_16();
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    // 1. predecessor (IVC) carrier verified in-circuit (one instance).
    let (pred_vi, pred_op_ids) = add_inner_verifier(&config, &vparams, &mut cb, &predecessor);

    // 2. the 8 sources, verified in-circuit per framing. We collect, per source
    //    slot, the (v_in, v_out) public-value targets so the active-mask and IVC
    //    carry below are applied IDENTICALLY in both framings (so the only cost
    //    difference is the verifier packaging, never the masking work).
    //
    // CRITICAL: a public input's flat index is fixed at ALLOCATION time, and the
    // packed `pubs` vector must list values in that exact order. The per-source
    // `active` bit is therefore allocated IMMEDIATELY AFTER that source's
    // verifier inputs (in the realistic framing, interleaved one per source; in
    // the batched framing, all 8 after the single shared verifier) so allocation
    // order == packing order. (`alloc_const`/`select`/`connect` produce internal
    // wires, not public inputs, so they do not affect public-input ordering.)
    let mut src_v_in: Vec<ExprId> = Vec::with_capacity(MAX_IN_COINS);
    let mut active_inputs: Vec<ExprId> = Vec::with_capacity(MAX_IN_COINS);
    let mut verifier_inputs: Vec<Vi> = Vec::new();
    let mut verifier_op_ids: Vec<Vec<NonPrimitiveOpId>> = Vec::new();
    let mut num_in_circuit_verifiers = 1usize; // predecessor

    // Apply the Probe E active-bit mask for source slot `i` against its surfaced
    // `v_out` target: active=1 -> v_out must equal expected (honest check fires);
    // active=0 -> connect(v_out, v_out) (slot masked off, any value ok).
    let apply_mask = |cb: &mut CircuitBuilder<Challenge>, i: usize, v_out: ExprId| -> ExprId {
        let active = cb.alloc_public_input("active");
        cb.assert_bool(active);
        let expected = cb.alloc_const(Challenge::from(F::from_u32(201 + i as u32)), "expected");
        let masked = cb.select(active, expected, v_out);
        cb.connect(v_out, masked);
        active
    };

    match framing {
        Framing::BatchedLowerBound => {
            let bundle = batched_sources.as_ref().expect("batched bundle present");
            let (vi, ids) = add_inner_verifier(&config, &vparams, &mut cb, bundle);
            num_in_circuit_verifiers += 1; // ONE verifier for all 8 sources
            // Collect v_in/v_out first (immutable borrow of vi), then apply masks.
            let slots: Vec<(ExprId, ExprId)> = vi
                .air_public_targets
                .iter()
                .map(|inst| (inst[0], inst[1]))
                .collect();
            verifier_inputs.push(vi);
            verifier_op_ids.push(ids);
            for (i, (v_in, v_out)) in slots.into_iter().enumerate() {
                src_v_in.push(v_in);
                active_inputs.push(apply_mask(&mut cb, i, v_out));
            }
        }
        Framing::IndependentRealistic => {
            for (i, src) in independent_sources.iter().enumerate() {
                let (vi, ids) = add_inner_verifier(&config, &vparams, &mut cb, src);
                num_in_circuit_verifiers += 1; // one verifier per source
                let v_in = vi.air_public_targets[0][0];
                let v_out = vi.air_public_targets[0][1];
                verifier_inputs.push(vi);
                verifier_op_ids.push(ids);
                src_v_in.push(v_in);
                active_inputs.push(apply_mask(&mut cb, i, v_out));
            }
        }
    }
    assert_eq!(src_v_in.len(), MAX_IN_COINS, "8 source slots surfaced");

    // 3. IVC carry select (Probe R thread), IDENTICAL across framings: thread
    //    pred_v_out through a select gate bound to source[0]'s v_in (committed
    //    carry work; value-semantics proven in Probe R, COST modelled here).
    let pred_v_out = pred_vi.air_public_targets[0][1];
    let carry = cb.select(active_inputs[0], src_v_in[0], pred_v_out);
    let _ = carry;

    let circuit = cb.build().expect("aggregator circuit builds");
    let build_ms = t_build.elapsed().as_secs_f64() * 1e3;
    let witness_count = circuit.public_flat_len;

    // --- compile to tables -------------------------------------------------
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

    // --- pack public/private inputs (allocation order) ---------------------
    // The predecessor verifier inputs come first; then for each source slot the
    // verifier inputs followed by that slot's `active` public input — except in
    // the batched framing where the 8 sources share ONE verifier-inputs builder
    // whose 8 public-value groups precede the 8 interleaved `active` bits.
    let active_bits: Vec<Challenge> = (0..MAX_IN_COINS).map(|_| Challenge::ONE).collect(); // worst case: all 8 active

    let (mut pubs, mut privs) =
        pred_vi.pack_values(&predecessor.pvs, &predecessor.proof, predecessor.common());

    match framing {
        Framing::BatchedLowerBound => {
            // ONE verifier-inputs builder packs all 8 source public-value groups.
            let bundle = batched_sources.as_ref().expect("batched bundle present");
            let vi = &verifier_inputs[0];
            let (s_pub, s_priv) = vi.pack_values(&bundle.pvs, &bundle.proof, bundle.common());
            pubs.extend(s_pub);
            privs.extend(s_priv);
            // Then the 8 `active` public inputs (allocated after the verifier).
            for &bit in &active_bits {
                pubs.push(bit);
            }
        }
        Framing::IndependentRealistic => {
            // Per source: verifier inputs, then that slot's `active` bit.
            for (i, vi) in verifier_inputs.iter().enumerate() {
                let src = &independent_sources[i];
                let (s_pub, s_priv) = vi.pack_values(&src.pvs, &src.proof, src.common());
                pubs.extend(s_pub);
                privs.extend(s_priv);
                pubs.push(active_bits[i]);
            }
        }
    }

    // witness-gen closure (fresh traces per prove; sets MMCS private data).
    let run_witness = || {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&pubs).expect("set pub");
        runner.set_private_inputs(&privs).expect("set priv");
        set_mmcs_for(&mut runner, &pred_op_ids, &predecessor);
        match framing {
            Framing::BatchedLowerBound => {
                let bundle = batched_sources.as_ref().expect("batched bundle present");
                set_mmcs_for(&mut runner, &verifier_op_ids[0], bundle);
            }
            Framing::IndependentRealistic => {
                for (i, ids) in verifier_op_ids.iter().enumerate() {
                    set_mmcs_for(&mut runner, ids, &independent_sources[i]);
                }
            }
        }
        runner.run().expect("aggregator witness-gen")
    };

    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(make_config(fri)).with_table_packing(table_packing);
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
        build_ms,
        cold_ms,
        p50_ms: quantile(&times, 0.50),
        p90_ms: quantile(&times, 0.90),
        rss_mb: peak_rss_mb(),
        witness_count,
        num_in_circuit_verifiers,
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
// Composition anchors (shared with Probe X).
// --------------------------------------------------------------------------
/// Probe T's single state-transition warm-prove (BabyBear + production FRI).
const PROBE_T_TRANSITION_MS: f64 = 312.0;
/// Plonky3 node-side overhead outside the prove (serialization, DB, SMT, etc.).
const NODE_OVERHEAD_MS: f64 = 5600.0;
/// Plonky2 single-prove baseline (M5-class), warm p50.
const PLONKY2_SINGLE_MS: f64 = 4350.0;
/// Live populated `/api/send` Plonky2 prove incl. node overhead (R2 baseline).
const PLONKY2_LIVE_SEND_MS: f64 = 10_000.0;
/// Probe X's flat 8+1 recursion-prove p50, non-zk (blowup-1).
const PROBE_X_FLAT_NONZK_MS: f64 = 4000.0;
/// Probe X's flat 8+1 recursion-prove p50, zk (blowup-2).
const PROBE_X_FLAT_ZK_MS: f64 = 6700.0;

fn probe_x_flat(fri: FriChoice) -> f64 {
    match fri {
        FriChoice::BenchBlowup1 => PROBE_X_FLAT_NONZK_MS,
        FriChoice::BenchZkBlowup2 => PROBE_X_FLAT_ZK_MS,
    }
}

#[test]
fn probe_x_prime_batched_aggregator() {
    let packing_type = core::any::type_name::<<F as Field>::Packing>();
    let scalar_type = core::any::type_name::<F>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = rayon::current_num_threads();

    println!(
        "\n===== Probe X′: batched-aggregator lever test (8 same-vk sources + 1 predecessor) ====="
    );
    println!("X'-a (lower bound): 8 sources as ONE batch proof, verified in-circuit ONCE.");
    println!("X'-b (realistic)  : 8 INDEPENDENT proofs (as in reality), one verifier each.");
    println!("stage measured    : STARK-PROVE of the recursion circuit (prove_all_tables).");
    println!("inner verifier    : FriVerifierParams::with_mmcs (REAL in-circuit MMCS checks).");
    println!("BabyBear::Packing : {packing_type}");
    println!("  -> SIMD packing active: {packing_active} (vs scalar {scalar_type})");
    println!("rayon threads     : {threads}");
    println!(
        "Probe X anchor    : flat 8+1 = {PROBE_X_FLAT_NONZK_MS:.0} ms non-zk / {PROBE_X_FLAT_ZK_MS:.0} ms zk"
    );

    let inner_rows = 1usize << 10;
    println!("------------------------------------------------------------------------------");
    println!(
        "inner carrier rows: {inner_rows} (1<<{}) | all {MAX_IN_COINS} source slots active (worst case)",
        inner_rows.trailing_zeros()
    );

    let fris = [FriChoice::BenchBlowup1, FriChoice::BenchZkBlowup2];
    let framings = [Framing::BatchedLowerBound, Framing::IndependentRealistic];

    // results[(framing_idx, fri_idx)]
    let mut results: Vec<(Framing, FriChoice, ProveResult)> = Vec::new();
    for &framing in &framings {
        for &fri in &fris {
            println!("\n--- {} | FRI = {} ---", framing.tag(), fri.label());
            let r = prove_framing(fri, inner_rows, framing);
            println!(
                "  in-circuit verifiers={} | build={:.1}ms cold={:.1}ms warm_p50={:.1}ms p90={:.1}ms rss={:.0}MB",
                r.num_in_circuit_verifiers, r.build_ms, r.cold_ms, r.p50_ms, r.p90_ms, r.rss_mb
            );
            println!("  circuit public_flat_len={}", r.witness_count);
            results.push((framing, fri, r));
        }
    }

    // --- results table -----------------------------------------------------
    println!("\n=========================== Probe X′ results (warm) ==========================");
    println!(
        "{:<30} {:<22} {:>4} {:>8} {:>8} {:>8} {:>8}",
        "framing", "FRI", "vfy", "cold", "p50", "p90", "rss_MB"
    );
    for (framing, fri, r) in &results {
        println!(
            "{:<30} {:<22} {:>4} {:>8.1} {:>8.1} {:>8.1} {:>8.0}",
            framing.tag(),
            fri.label(),
            r.num_in_circuit_verifiers,
            r.cold_ms,
            r.p50_ms,
            r.p90_ms,
            r.rss_mb
        );
    }

    // --- reduction factor vs Probe X flat 8+1, per framing × fri -----------
    println!("\n=================== reduction factor vs Probe X flat 8+1 =====================");
    let get = |fr: Framing, choice: FriChoice| -> &ProveResult {
        &results
            .iter()
            .find(|(f, c, _)| {
                *f == fr && core::mem::discriminant(c) == core::mem::discriminant(&choice)
            })
            .expect("result present")
            .2
    };
    for &framing in &framings {
        for &fri in &fris {
            let r = get(framing, fri);
            let flat = probe_x_flat(fri);
            let factor = flat / r.p50_ms;
            println!(
                "{:<30} {:<22} p50={:>7.0} ms vs flat {:>5.0} ms  ->  {:.2}x {}",
                framing.tag(),
                fri.label(),
                r.p50_ms,
                flat,
                factor,
                if factor >= 1.05 {
                    "REDUCTION"
                } else if factor <= 0.95 {
                    "WORSE"
                } else {
                    "~same as flat"
                }
            );
        }
    }

    // --- recomposed full /api/send estimate, per framing -------------------
    println!("\n============= recomposed full /api/send (T + X′ + node overhead) =============");
    println!(
        "anchors: Probe T transition {PROBE_T_TRANSITION_MS:.0} ms + node overhead {NODE_OVERHEAD_MS:.0} ms"
    );
    println!(
        "targets: beat Plonky2 single-prove {PLONKY2_SINGLE_MS:.0} ms AND live /api/send {PLONKY2_LIVE_SEND_MS:.0} ms"
    );
    for &framing in &framings {
        for &fri in &fris {
            let r = get(framing, fri);
            let full = PROBE_T_TRANSITION_MS + r.p50_ms + NODE_OVERHEAD_MS;
            let vs_live = if full < PLONKY2_LIVE_SEND_MS {
                format!(
                    "FASTER than live send ({:.2}x)",
                    PLONKY2_LIVE_SEND_MS / full
                )
            } else {
                format!(
                    "SLOWER than live send ({:.2}x)",
                    full / PLONKY2_LIVE_SEND_MS
                )
            };
            println!(
                "{:<30} {:<22} full send = {:>7.0} ms  ({})",
                framing.tag(),
                fri.label(),
                full,
                vs_live
            );
        }
    }

    // --- the honest verdict -----------------------------------------------
    let a_nonzk = get(Framing::BatchedLowerBound, FriChoice::BenchBlowup1);
    let b_nonzk = get(Framing::IndependentRealistic, FriChoice::BenchBlowup1);
    let a_factor = PROBE_X_FLAT_NONZK_MS / a_nonzk.p50_ms;
    let b_factor = PROBE_X_FLAT_NONZK_MS / b_nonzk.p50_ms;
    let b_full = PROBE_T_TRANSITION_MS + b_nonzk.p50_ms + NODE_OVERHEAD_MS;

    println!("\n=============================== BOTTOM LINE ==================================");
    println!(
        "X'-a batched lower bound (non-zk): {:.0} ms  = {:.2}x reduction vs flat {:.0} ms.",
        a_nonzk.p50_ms, a_factor, PROBE_X_FLAT_NONZK_MS
    );
    println!(
        "X'-b realistic independent (non-zk): {:.0} ms = {:.2}x vs flat {:.0} ms.",
        b_nonzk.p50_ms, b_factor, PROBE_X_FLAT_NONZK_MS
    );
    println!(
        "in-circuit verifiers: X'-a = {} (one 8-instance + predecessor), X'-b = {} (flat 8+1).",
        a_nonzk.num_in_circuit_verifiers, b_nonzk.num_in_circuit_verifiers
    );

    // Is the same-vk amortization realisable for the SEND path? Only if X′-b
    // (the realistic, independent-proof framing) — not just X′-a — beats flat.
    const REALISABLE_BAND: f64 = 1.10; // >10% off flat counts as a real saving
    let b_amortizes = b_factor >= REALISABLE_BAND;
    let a_amortizes = a_factor >= REALISABLE_BAND;

    println!("\nIs same-vk verifier amortization GENUINELY achievable via the API?");
    if a_amortizes && !b_amortizes {
        println!(
            "  X'-a shows the batched verifier IS cheaper ({:.2}x) — but ONLY when the 8 sources",
            a_factor
        );
        println!("  are proved as one batch. X'-b (independent proofs, as in reality) is ~flat:");
        println!(
            "  {:.2}x. The API verifies one BatchProof per `verify_batch_circuit` (each carries its",
            b_factor
        );
        println!(
            "  own commitment + FRI opening proof), so INDEPENDENT same-vk proofs CANNOT share"
        );
        println!(
            "  the in-circuit verifier. In the real protocol the 8 sources come from different"
        );
        println!(
            "  prior transactions, proved at different times — they are NOT one batch and cannot"
        );
        println!("  be retroactively re-batched without re-proving them.");
        println!(
            "\n  VERDICT: batching does NOT rescue the send-side speed case. The batched floor"
        );
        println!(
            "  (X'-a) is unreachable for /api/send. The realistic figure (X'-b) ≈ Probe X, so the"
        );
        let b_full_zk = PROBE_T_TRANSITION_MS
            + get(Framing::IndependentRealistic, FriChoice::BenchZkBlowup2).p50_ms
            + NODE_OVERHEAD_MS;
        println!(
            "  recomposed full send is {:.0} ms non-zk / {:.0} ms zk — a WASH vs Plonky2's live {:.0} ms",
            b_full, b_full_zk, PLONKY2_LIVE_SEND_MS
        );
        println!(
            "  (non-zk {:.2}x, within noise) and a LOSS in true-ZK ({:.2}x slower); both are far above",
            PLONKY2_LIVE_SEND_MS / b_full,
            b_full_zk / PLONKY2_LIVE_SEND_MS
        );
        println!(
            "  Plonky2's {:.0} ms single-prove. The Probe-T transition win ({:.0} ms) is swamped by the",
            PLONKY2_SINGLE_MS, PROBE_T_TRANSITION_MS
        );
        println!("  8-source recursion. The only live send-side lever is reducing MAX_IN_COINS");
        println!("  (fewer in-coins per send) — NOT same-vk batching, which is unreachable here.");
    } else if b_amortizes {
        println!(
            "  X'-b (realistic, independent proofs) ALSO beats flat: {:.2}x. The recursion API DOES",
            b_factor
        );
        println!(
            "  let independent same-vk proofs share verifier structure — a genuine send-side win."
        );
        println!(
            "  Recomposed realistic full send = {:.0} ms vs Plonky2 live {:.0} ms.",
            b_full, PLONKY2_LIVE_SEND_MS
        );
    } else {
        println!(
            "  Neither framing beats flat materially (X'-a {:.2}x, X'-b {:.2}x): batching the same-vk",
            a_factor, b_factor
        );
        println!(
            "  verifier structure does not reduce the STARK-prove cost. The cost is in the FRI"
        );
        println!("  opening work, which scales with the number of distinct openings regardless of");
        println!("  packaging. Batching does NOT rescue the send case; MAX_IN_COINS is the lever.");
    }
    println!("==============================================================================\n");

    // Test passes on successful measurement + verification (verdict is data).
    assert_eq!(
        results.len(),
        framings.len() * fris.len(),
        "all framings × FRI measured"
    );
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got {packing_type}"
    );
}
