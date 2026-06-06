//! Probe AE — the **final composed measurement**: the RECOMMENDED Plonky3
//! best-config for the zkCoins full send-prove, proved end-to-end and reduced
//! to ONE honest number. This is where the pre-port research lands.
//!
//! # What this probe answers
//!
//! "Under the config the whole research recommends — BabyBear, the Probe-T
//! transition tables, and the Probe-AC/AB N=4+1 aggregation at cheaper-inner-FRI
//! q=48 — how long does the COMPLETE Plonky3 send-prove take, end to end, with
//! real proving and real verification? And what is that versus Plonky2's 4.35 s
//! warm single-prove and ~10 s live `/api/send`?"
//!
//! Nothing here is re-derived. The recommended config was established by the
//! earlier probes and is reused verbatim:
//!
//!   * **Field: BabyBear.** Probe AD ruled out KoalaBear (2.1x slower on the
//!     dominant aggregation prove).
//!   * **Transition: Probe T's representative tables** — the degree-7
//!     `VectorizedPoseidon2Air` sized to ~4500 Poseidon2 perms (1024 rows) PLUS
//!     a degree-3 arithmetic table at the realistic-anchor height 2^13, proved
//!     as ONE batched FRI proof (Probe T's faithful approach (a)).
//!   * **Aggregation: N=4 sources + 1 IVC predecessor** (`MAX_IN_COINS = 4`, the
//!     protocol-lever point Probe AC isolated) verified IN-CIRCUIT with real
//!     MMCS opening checks, at **cheaper-inner-FRI q=48 (64-bit inner,
//!     `[VERIFY]`)** per Probe AB. Proved via the low-level `prove_all_tables`
//!     path (the #436-safe recipe).
//!
//! # Can the whole thing be ONE `prove_batch`? No — and here is the precise why.
//!
//! The two table-sets live under two GENUINELY INCOMPATIBLE STARK configs, so a
//! single shared batch is not possible; Probe AE is therefore the TIGHTEST
//! TWO-PROVE PIPELINE, and states so plainly:
//!
//!   * The **transition** tables are committed under Probe T's `HidingFriPcs`
//!     over a **Keccak**-sponge `MerkleTreeHidingMmcs` (`SerializingChallenger32`,
//!     `BinomialExtensionField<BabyBear,4>`, blowup-2 ZK FRI). They are custom
//!     hand-written AIRs (`VectorizedPoseidon2Air` + `ArithAir`) proved with
//!     `p3_batch_stark::prove_batch`.
//!   * The **aggregation** circuit is committed under Probe AC's
//!     `TwoAdicFriPcs` over a **Poseidon2 field-native** `MerkleTreeMmcs`
//!     (`DuplexChallenger`, blowup-1 inner FRI). It is a `p3-circuit`
//!     `CircuitBuilder` compiled to its primitive tables and proved with
//!     `BatchStarkProver::prove_all_tables`.
//!
//! These differ in the MMCS hash (Keccak vs Poseidon2), the PCS type
//! (`HidingFriPcs` vs `TwoAdicFriPcs`), the challenger (`SerializingChallenger32`
//! vs `DuplexChallenger`), the FRI strength, and — decisively — the PROVER ENTRY
//! POINT (`prove_batch` over hand-AIRs vs `prove_all_tables` over a compiled
//! circuit). `prove_batch` cannot ingest a `CircuitBuilder`'s tables and
//! `prove_all_tables` cannot ingest hand-written `Air`s under a foreign PCS. A
//! single `prove_batch` would require ONE config + ONE AIR-type + ONE prover for
//! both halves — which does not exist across these two stacks. The faithful
//! production shape is therefore two proofs run back-to-back, exactly as the
//! real node would: prove the transition, then prove the aggregation that folds
//! the in-coins. Probe AE measures their COMBINED wall-time as the single
//! send-prove number, and cross-checks it against the sum-of-parts estimate.
//!
//! (Note: even in a hypothetical unified stack the aggregation's INNER carrier
//! proofs must be produced BEFORE the aggregator can verify them in-circuit, so
//! a true one-shot batch is precluded by the recursion data-dependency too, not
//! only by the config mismatch. The two-prove pipeline is the honest shape.)
//!
//! # The hiding (ZK) headline question
//!
//! The brief asks for the non-zk headline plus the hiding delta if cheap. The
//! transition half already runs under TRUE ZK (`HidingFriPcs`,
//! `num_random_codewords = 4`) — that is Probe T's recommended config, so the
//! transition number is INTRINSICALLY the hiding one (no cheaper non-hiding
//! transition is part of the recommendation). The aggregation half is measured
//! non-zk (matching Probe AC/AB/X, where the recursion prove is non-hiding and
//! hiding is an outer-layer concern). The composed headline is thus
//! "hiding-transition + non-zk-aggregation", the faithful production mix, and
//! the verdict states this explicitly rather than papering a uniform label over
//! two different halves. Probe W already quantified the pure hiding delta on a
//! transition-class table as a small additive term; it is cited, not re-run
//! here (re-running it would not change the composed number, which already
//! includes the hiding transition).
//!
//! # What is measured
//!
//! For the transition prove, the aggregation prove, and the COMPOSED pipeline:
//! build wall-time, cold prove, warm p50/p90 over >=5 runs (after a warmup), and
//! peak RSS. Every proof is verified (hard gate). Packing type + thread count
//! printed. The composed warm series is built by running BOTH proves
//! back-to-back inside each timed iteration, so p50/p90 are of the real
//! end-to-end send-prove, not a post-hoc sum.
//!
//! # Verdict policy
//!
//! PASSES on successful measurement + verification of every proof. The
//! faster/slower verdicts vs Plonky2 are REPORTED findings, never asserts — an
//! unfavourable datum is surfaced honestly. The two `[VERIFY]` conditions the
//! headline rests on are restated in full at the end:
//!   1. the 64-bit inner-FRI composition argument (q=48 inner), and
//!   2. the `MAX_IN_COINS = 4` protocol change.

use std::sync::Arc;
use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
// --- transition (Probe T) crypto stack ------------------------------------
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    BABYBEAR_S_BOX_DEGREE, BabyBear, GenericPoseidon2LinearLayersBabyBear, Poseidon2BabyBear,
    default_babybear_poseidon2_16,
};
use p3_batch_stark::{
    BatchProof, ProverData as BatchProverData, StarkGenericConfig, StarkInstance, prove_batch,
    verify_batch,
};
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{Circuit, CircuitBuilder, NonPrimitiveOpId, Traces};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProof, poseidon2_air_builders, recompose_air_builders,
};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking,
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_poseidon2_air::{RoundConstants, VectorizedPoseidon2Air};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::{InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness, set_fri_mmcs_private_data};
use p3_recursion::{
    BatchStarkVerifierInputsBuilder, FriVerifierParams, Poseidon2Config, verify_batch_circuit,
};
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher, TruncatedPermutation,
};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::SmallRng;

// ==========================================================================
// PART 1 — Transition prove config (Probe T recipe, verbatim).
// ==========================================================================
const WIDTH: usize = 16;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS; // 4
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16; // 13
const VECTOR_LEN: usize = 1 << 3; // 8 perms / row
const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE; // 7
const SBOX_REGISTERS: usize = 1;

type Val = BabyBear;
type TChallenge = BinomialExtensionField<Val, 4>;

type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type TCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type TValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    TCompress,
    SmallRng,
    2,
    4,
    4,
>;
type TChallengeMmcs = ExtensionMmcs<Val, TChallenge, TValMmcs>;
type TChallenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type TDft = p3_dft::Radix2DitParallel<BabyBear>;
type TPcs = HidingFriPcs<Val, TDft, TValMmcs, TChallengeMmcs, SmallRng>;
type TConfig = StarkConfig<TPcs, TChallenge, TChallenger>;

/// Degree-7 cryptographic Poseidon2 hash AIR (Probe T / V).
type HashAir = VectorizedPoseidon2Air<
    Val,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
    VECTOR_LEN,
>;

/// Real circuit's approximate Poseidon2 permutation count.
const REAL_HASH_PERMS: usize = 4500;
/// Realistic-anchor arith table height (Probe T's low sweep end = the anchor).
const ARITH_HEIGHT: usize = 1 << 13;
const ARITH_WIDTH: usize = 16;
const CONSTRAINTS_PER_ROW: usize = 12;

#[derive(Clone, Copy, Debug)]
struct ArithAir;

impl<F> BaseAir<F> for ArithAir {
    fn width(&self) -> usize {
        ARITH_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for ArithAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice().to_vec();
        let next = main.next_slice().to_vec();
        let mut t = builder.when_transition();
        // 8 degree-3 transition constraints: next[i] == local[i+1]^3.
        for i in 0..8 {
            let x: AB::Expr = local[i + 1].into();
            let x3 = x.clone() * x.clone() * x;
            t.assert_eq(next[i], x3);
        }
        // 4 linear-coupling constraints: next[8+j] == local[j] + local[8+j].
        for j in 0..4 {
            let coupled: AB::Expr = local[j].into() + local[8 + j].into();
            t.assert_eq(next[8 + j], coupled);
        }
    }
}

/// Witness trace satisfying `ArithAir` exactly (Probe T's generator).
fn arith_trace(height: usize) -> RowMajorMatrix<Val> {
    assert!(height.is_power_of_two());
    let mut values = vec![Val::ZERO; height * ARITH_WIDTH];
    for (c, slot) in values.iter_mut().enumerate().take(ARITH_WIDTH) {
        *slot = Val::from_u64((c as u64) + 1);
    }
    for r in 1..height {
        let (prev, cur) = values.split_at_mut(r * ARITH_WIDTH);
        let prev = &prev[(r - 1) * ARITH_WIDTH..r * ARITH_WIDTH];
        let cur = &mut cur[..ARITH_WIDTH];
        for i in 0..8 {
            let x = prev[i + 1];
            cur[i] = x * x * x;
        }
        for j in 0..4 {
            cur[8 + j] = prev[j] + prev[8 + j];
        }
        for (k, slot) in cur.iter_mut().enumerate().skip(12) {
            *slot = prev[k] + Val::ONE;
        }
    }
    RowMajorMatrix::new(values, ARITH_WIDTH)
}

/// Multi-table enum AIR for the batched transition proof (Probe T).
#[derive(Clone)]
enum TableAir {
    Hash(Arc<HashAir>),
    Arith(ArithAir),
}

impl BaseAir<Val> for TableAir {
    fn width(&self) -> usize {
        match self {
            TableAir::Hash(a) => BaseAir::<Val>::width(a.as_ref()),
            TableAir::Arith(a) => BaseAir::<Val>::width(a),
        }
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for TableAir
where
    HashAir: Air<AB>,
    ArithAir: Air<AB>,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            TableAir::Hash(a) => a.as_ref().eval(builder),
            TableAir::Arith(a) => a.eval(builder),
        }
    }
}

fn build_transition_config() -> (TConfig, usize) {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = TCompress::new(u64_hash);
    let val_mmcs = TValMmcs::new(field_hash, compress, 0, SmallRng::seed_from_u64(2));
    let challenge_mmcs = TChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_benchmark_zk(challenge_mmcs);
    let log_blowup = fri_params.log_blowup;
    let dft = TDft::default();
    let pcs = TPcs::new(dft, val_mmcs, fri_params, 4, SmallRng::seed_from_u64(3));
    let challenger = TChallenger::from_hasher(vec![], byte_hash);
    (TConfig::new(pcs, challenger), log_blowup)
}

fn build_hash_air() -> HashAir {
    let mut rng = SmallRng::seed_from_u64(1);
    VectorizedPoseidon2Air::new(RoundConstants::from_rng(&mut rng))
}

fn next_pow2(n: usize) -> usize {
    n.max(2).next_power_of_two()
}

fn log2(n: usize) -> usize {
    n.trailing_zeros() as usize
}

/// Prepared transition prover state (built once, reused across warm runs).
struct TransitionProver {
    config: TConfig,
    airs: [TableAir; 2],
    prover_data: BatchProverData<TConfig>,
    hash_trace: RowMajorMatrix<Val>,
    arith_trace: RowMajorMatrix<Val>,
    build_ms: f64,
}

impl TransitionProver {
    /// Build config, AIRs, traces, and the batch `ProverData` (the build stage).
    fn build() -> Self {
        let t0 = Instant::now();
        let (config, log_blowup) = build_transition_config();
        assert_eq!(log_blowup, 2, "new_benchmark_zk must be blowup-2");
        let hash_air = Arc::new(build_hash_air());

        let hash_perms_capacity = next_pow2(REAL_HASH_PERMS.div_ceil(VECTOR_LEN)) * VECTOR_LEN;
        let hash_trace = hash_air.generate_vectorized_trace_rows(hash_perms_capacity, log_blowup);
        let arith_trace = arith_trace(ARITH_HEIGHT);

        let airs = [TableAir::Hash(hash_air), TableAir::Arith(ArithAir)];
        let prover_data: BatchProverData<TConfig> = BatchProverData::from_airs_and_degrees(
            &config,
            &airs,
            &[
                log2(hash_trace.height()) + config.is_zk(),
                log2(arith_trace.height()) + config.is_zk(),
            ],
        );
        let build_ms = t0.elapsed().as_secs_f64() * 1e3;
        Self {
            config,
            airs,
            prover_data,
            hash_trace,
            arith_trace,
            build_ms,
        }
    }

    /// One batched transition prove (NOT verified — caller verifies when needed).
    fn prove(&self) -> BatchProof<TConfig> {
        let pvs = vec![vec![], vec![]];
        let traces: [&RowMajorMatrix<Val>; 2] = [&self.hash_trace, &self.arith_trace];
        let instances = StarkInstance::new_multiple(&self.airs, &traces, &pvs);
        prove_batch(&self.config, &instances, &self.prover_data)
    }

    fn verify(&self, proof: &BatchProof<TConfig>) {
        let pvs = vec![vec![], vec![]];
        verify_batch(
            &self.config,
            &self.airs,
            proof,
            &pvs,
            &self.prover_data.common,
        )
        .expect("Probe AE transition proof must verify");
    }

    fn hash_rows(&self) -> usize {
        self.hash_trace.height()
    }
}

// ==========================================================================
// PART 2 — Aggregation prove config (Probe AC recipe @ q=48, N=4+1).
// ==========================================================================
type F = BabyBear;
const D: usize = 4;
const A_RATE: usize = 8;
const DIGEST_ELEMS: usize = 8;
type AChallenge = BinomialExtensionField<F, D>;
type ADft = Radix2DitParallel<F>;
type Perm = Poseidon2BabyBear<WIDTH>;
type AHash = PaddingFreeSponge<Perm, WIDTH, A_RATE, DIGEST_ELEMS>;
type ACompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
type AMmcs =
    MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, AHash, ACompress, 2, DIGEST_ELEMS>;
type AChallengeMmcs = ExtensionMmcs<F, AChallenge, AMmcs>;
type AChallenger = DuplexChallenger<F, Perm, WIDTH, A_RATE>;
type APcs = TwoAdicFriPcs<F, ADft, AMmcs, AChallengeMmcs>;
type AConfig = StarkConfig<APcs, AChallenge, AChallenger>;

type InnerFri = FriProofTargets<
    F,
    AChallenge,
    RecExtensionValMmcs<F, AChallenge, DIGEST_ELEMS, RecValMmcs<F, DIGEST_ELEMS, AHash, ACompress>>,
    InputProofTargets<F, AChallenge, RecValMmcs<F, DIGEST_ELEMS, AHash, ACompress>>,
    Witness<F>,
>;

/// Cheaper-inner-FRI: 48 queries (1*48 + 16 = 64 conjectured bits) — Probe AB's
/// `[VERIFY]` lever, the recommended aggregation FRI.
const Q48_NUM_QUERIES: usize = 48;
const Q48_LOG_BLOWUP: usize = 1;
const Q48_QUERY_POW_BITS: usize = 16;
const Q48_COMMIT_POW_BITS: usize = 0;
const Q48_LOG_FINAL_POLY_LEN: usize = 0;

fn q48_conjectured_bits() -> usize {
    Q48_LOG_BLOWUP * Q48_NUM_QUERIES + Q48_QUERY_POW_BITS
}

fn q48_fri_params(mmcs: AChallengeMmcs) -> FriParameters<AChallengeMmcs> {
    FriParameters {
        log_blowup: Q48_LOG_BLOWUP,
        log_final_poly_len: Q48_LOG_FINAL_POLY_LEN,
        max_log_arity: 1,
        num_queries: Q48_NUM_QUERIES,
        commit_proof_of_work_bits: Q48_COMMIT_POW_BITS,
        query_proof_of_work_bits: Q48_QUERY_POW_BITS,
        mmcs,
    }
}

fn make_agg_config() -> AConfig {
    let perm = default_babybear_poseidon2_16();
    let hash = AHash::new(perm.clone());
    let compress = ACompress::new(perm.clone());
    let val_mmcs = AMmcs::new(hash, compress, 0);
    let challenge_mmcs = AChallengeMmcs::new(val_mmcs.clone());
    let fri_params = q48_fri_params(challenge_mmcs);
    let pcs = APcs::new(ADft::default(), val_mmcs, fri_params);
    AConfig::new(pcs, AChallenger::new(perm))
}

fn agg_fri_verifier_params() -> FriVerifierParams {
    FriVerifierParams::with_mmcs(
        Q48_LOG_BLOWUP,
        Q48_LOG_FINAL_POLY_LEN,
        Q48_COMMIT_POW_BITS,
        Q48_QUERY_POW_BITS,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
}

/// Probe R/X carrier AIR — `[v_in, v_out]` with native `v_out == v_in + 1`.
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

struct Layer {
    proof: BatchProof<AConfig>,
    air: CarrierAir,
    pvs: [Vec<F>; 1],
    prover_data: BatchProverData<AConfig>,
}

impl Layer {
    fn common(&self) -> &p3_batch_stark::CommonData<AConfig> {
        &self.prover_data.common
    }
}

fn prove_layer(config: &AConfig, v: F, rows: usize) -> Layer {
    let air = CarrierAir { rows };
    let trace = air.honest_trace(v);
    let pvs = [vec![v, v + F::ONE]];
    let instances = vec![StarkInstance {
        air: &air,
        trace: &trace,
        public_values: pvs[0].clone(),
    }];
    let prover_data = BatchProverData::from_instances(config, &instances);
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

type Vi = BatchStarkVerifierInputsBuilder<AConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>;

fn add_carrier_verifier(
    config: &AConfig,
    vparams: &FriVerifierParams,
    cb: &mut CircuitBuilder<AChallenge>,
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
    let mmcs_op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, A_RATE>(
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

fn set_mmcs_for(
    runner: &mut p3_circuit::CircuitRunner<'_, AChallenge>,
    op_ids: &[NonPrimitiveOpId],
    layer: &Layer,
) {
    set_fri_mmcs_private_data::<
        F,
        AChallenge,
        AChallengeMmcs,
        AMmcs,
        AHash,
        ACompress,
        DIGEST_ELEMS,
    >(
        runner,
        op_ids,
        &layer.proof.opening_proof,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .expect("set MMCS private data");
}

/// Prepared aggregation prover state for N=4+1 @ q48 (built once, reused warm).
struct AggregationProver {
    prover: BatchStarkProver<AConfig>,
    circuit_prover_data: CircuitProverData<AConfig>,
    circuit: Circuit<AChallenge>,
    pubs: Vec<AChallenge>,
    privs: Vec<AChallenge>,
    pred: Layer,
    sources: Vec<Layer>,
    pred_op_ids: Vec<NonPrimitiveOpId>,
    source_op_ids: Vec<Vec<NonPrimitiveOpId>>,
    build_ms: f64,
    witness_count: usize,
}

/// Number of source in-coin slots (the recommended `MAX_IN_COINS`).
const FAN_IN: usize = 4;

impl AggregationProver {
    /// Build the N=4+1 aggregator recursion circuit @ q48 and all prover state.
    fn build() -> Self {
        let config = make_agg_config();
        let vparams = agg_fri_verifier_params();
        let inner_rows = 1usize << 10;

        // inner carrier proofs: 1 predecessor + N sources.
        let pred = prove_layer(&config, F::from_u32(100), inner_rows);
        let sources: Vec<Layer> = (0..FAN_IN)
            .map(|i| prove_layer(&config, F::from_u32(200 + i as u32), inner_rows))
            .collect();

        let t_build = Instant::now();
        let perm = default_babybear_poseidon2_16();
        let mut cb = CircuitBuilder::new();
        cb.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<AChallenge, BabyBearD4Width16>,
            perm,
        );
        cb.enable_recompose::<F>(generate_recompose_trace::<F, AChallenge>);

        // 1. predecessor (IVC) carrier verified in-circuit.
        let (pred_vi, pred_op_ids) = add_carrier_verifier(&config, &vparams, &mut cb, &pred);

        // 2. N source carriers, each with an active-bit mask (Probe E order).
        let mut source_vis = Vec::with_capacity(FAN_IN);
        let mut source_op_ids = Vec::with_capacity(FAN_IN);
        let mut active_inputs = Vec::with_capacity(FAN_IN);
        for (i, src) in sources.iter().enumerate() {
            let (src_vi, src_ids) = add_carrier_verifier(&config, &vparams, &mut cb, src);
            let v_out = src_vi.air_public_targets[0][1];
            let active = cb.alloc_public_input("active");
            cb.assert_bool(active);
            let expected =
                cb.alloc_const(AChallenge::from(F::from_u32(201 + i as u32)), "expected");
            let masked = cb.select(active, expected, v_out);
            cb.connect(v_out, masked);
            source_vis.push(src_vi);
            source_op_ids.push(src_ids);
            active_inputs.push(active);
        }

        // 3. IVC carry: cost-faithful select+connect (value-semantics in Probe R).
        let pred_v_out = pred_vi.air_public_targets[0][1];
        let src0_v_in = source_vis[0].air_public_targets[0][0];
        let carry = cb.select(active_inputs[0], src0_v_in, pred_v_out);
        let _ = carry;

        let circuit = cb.build().expect("aggregator circuit builds");
        let build_ms = t_build.elapsed().as_secs_f64() * 1e3;
        let witness_count = circuit.public_flat_len;

        // compile to tables.
        let table_packing = TablePacking::new(1, 8);
        let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
            Box::new(Poseidon2Preprocessor),
            Box::new(RecomposePreprocessor::default()),
        ];
        let mut air_builders = poseidon2_air_builders::<_, D>();
        air_builders.extend(recompose_air_builders(1, false));
        let (airs_degrees, primitive_columns, non_primitive_columns) =
            get_airs_and_degrees_with_prep::<AConfig, _, D>(
                &circuit,
                &table_packing,
                &npo_prep,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .expect("airs and degrees for aggregator");
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

        // pack public/private inputs (all N source slots active, worst case).
        let (mut pubs, mut privs) = pred_vi.pack_values(&pred.pvs, &pred.proof, pred.common());
        for (i, src_vi) in source_vis.iter().enumerate() {
            let (s_pub, s_priv) =
                src_vi.pack_values(&sources[i].pvs, &sources[i].proof, sources[i].common());
            pubs.extend(s_pub);
            privs.extend(s_priv);
            pubs.push(AChallenge::ONE); // active = 1 for every slot.
        }

        let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
        let prover_data = BatchProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
        let circuit_prover_data =
            CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
        let mut prover = BatchStarkProver::new(make_agg_config()).with_table_packing(table_packing);
        prover.register_poseidon2_table::<D>(Poseidon2Config::BABY_BEAR_D4_W16);
        prover.register_recompose_table::<D>(false);

        Self {
            prover,
            circuit_prover_data,
            circuit,
            pubs,
            privs,
            pred,
            sources,
            pred_op_ids,
            source_op_ids,
            build_ms,
            witness_count,
        }
    }

    /// Generate witness traces (part of each prove iteration, as in Probe AC).
    fn run_witness(&self) -> Traces<AChallenge> {
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&self.pubs).expect("set pub");
        runner.set_private_inputs(&self.privs).expect("set priv");
        set_mmcs_for(&mut runner, &self.pred_op_ids, &self.pred);
        for (i, ids) in self.source_op_ids.iter().enumerate() {
            set_mmcs_for(&mut runner, ids, &self.sources[i]);
        }
        runner.run().expect("aggregator witness-gen")
    }

    /// One aggregation prove (witness-gen + prove_all_tables). NOT verified.
    fn prove(&self) -> BatchStarkProof<AConfig> {
        let traces = self.run_witness();
        self.prover
            .prove_all_tables(&traces, &self.circuit_prover_data)
            .expect("STARK-prove aggregator recursion circuit")
    }

    fn verify(&self, proof: &BatchStarkProof<AConfig>) {
        self.prover
            .verify_all_tables(proof)
            .expect("verify aggregator recursion proof");
    }
}

// ==========================================================================
// Shared helpers.
// ==========================================================================
const WARM_RUNS: usize = 5;

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

#[derive(Clone, Copy)]
struct Stage {
    build_ms: f64,
    cold_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    rss_mb: f64,
}

// ==========================================================================
// Composition anchors (from the prior probes / migration research).
// ==========================================================================
/// Probe T single state-transition warm-prove reference, ms (sum-of-parts).
const PROBE_T_TRANSITION_MS: f64 = 312.0;
/// Probe AC N=4 @ q48 aggregation reference, ms (sum-of-parts).
const PROBE_AC_N4Q48_MS: f64 = 980.0;
/// Plonky3 node overhead (non-prove) on a populated `/api/send`, ms.
const NODE_OVERHEAD_MS: f64 = 5600.0;
/// Plonky2 warm single-prove baseline, ms.
const PLONKY2_WARM_MS: f64 = 4350.0;
/// Plonky2 live populated `/api/send`, ms.
const PLONKY2_LIVE_SEND_MS: f64 = 10_000.0;

#[test]
fn probe_ae_best_config() {
    let packing_type = core::any::type_name::<<Val as Field>::Packing>();
    let scalar_type = core::any::type_name::<Val>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = rayon::current_num_threads();

    println!("\n========= Probe AE: the RECOMMENDED best-config full send-prove =========");
    println!("FINAL composed measurement — real proving, real verification, one honest number.");
    println!("config (reused, NOT re-derived):");
    println!("  field      : BabyBear (Probe AD ruled out KoalaBear, 2.1x slower on aggregation)");
    println!("  transition : Probe T degree-7 Poseidon2 hash table (~4500 perms) + degree-3 arith");
    println!("               2^13, ONE prove_batch under HidingFriPcs/Keccak (TRUE ZK, blowup-2)");
    println!("  aggregation: N=4 sources + 1 IVC predecessor (MAX_IN_COINS=4), in-circuit");
    println!("               verify_batch_circuit @ cheaper-inner-FRI q=48 (64-bit [VERIFY]),");
    println!("               prove_all_tables low-level path, TwoAdicFriPcs/Poseidon2 (non-zk)");
    println!("BabyBear::Packing : {packing_type}");
    println!("  -> SIMD packing active: {packing_active} (vs scalar {scalar_type})");
    println!("rayon threads     : {threads}");
    println!(
        "Plonky2 baseline  : {PLONKY2_WARM_MS:.0} ms warm single-prove / {PLONKY2_LIVE_SEND_MS:.0} ms live /api/send"
    );
    println!("---------------------------------------------------------------------------");
    println!("WHY TWO PROVES, NOT ONE BATCH: the transition (HidingFriPcs/Keccak, hand-AIRs,");
    println!("prove_batch) and the aggregation (TwoAdicFriPcs/Poseidon2, compiled CircuitBuilder,");
    println!("prove_all_tables) are different StarkConfigs with different MMCS/PCS/challenger and");
    println!("different prover ENTRY POINTS. No single prove_batch ingests both. Also the inner");
    println!(
        "carrier proofs must exist before the aggregator can verify them (recursion data-dep)."
    );
    println!(
        "=> the faithful production shape is the TIGHTEST TWO-PROVE PIPELINE, measured below."
    );

    // ---- build both provers (the build stage) ----------------------------
    let transition = TransitionProver::build();
    let aggregation = AggregationProver::build();
    println!("---------------------------------------------------------------------------");
    println!(
        "transition  : hash table {} rows (degree-7) + arith 2^{} ({} cols x {} deg-3 c/row)",
        transition.hash_rows(),
        log2(ARITH_HEIGHT),
        ARITH_WIDTH,
        CONSTRAINTS_PER_ROW
    );
    println!(
        "aggregation : N={}+1 verified, q=48 ({} conjectured bits), public_flat_len={}",
        FAN_IN,
        q48_conjectured_bits(),
        aggregation.witness_count
    );

    // ---- transition: cold + warm -----------------------------------------
    let t = Instant::now();
    let tproof = transition.prove();
    let t_cold = t.elapsed().as_secs_f64() * 1e3;
    transition.verify(&tproof);
    let _ = transition.prove(); // warmup
    let mut t_times = Vec::with_capacity(WARM_RUNS);
    let mut last_t = None;
    for _ in 0..WARM_RUNS {
        let t = Instant::now();
        let p = transition.prove();
        t_times.push(t.elapsed().as_secs_f64() * 1e3);
        last_t = Some(p);
    }
    transition.verify(&last_t.unwrap());
    t_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let transition_stage = Stage {
        build_ms: transition.build_ms,
        cold_ms: t_cold,
        p50_ms: quantile(&t_times, 0.50),
        p90_ms: quantile(&t_times, 0.90),
        rss_mb: peak_rss_mb(),
    };

    // ---- aggregation: cold + warm ----------------------------------------
    let t = Instant::now();
    let aproof = aggregation.prove();
    let a_cold = t.elapsed().as_secs_f64() * 1e3;
    aggregation.verify(&aproof);
    let _ = aggregation.prove(); // warmup
    let mut a_times = Vec::with_capacity(WARM_RUNS);
    let mut last_a = None;
    for _ in 0..WARM_RUNS {
        let t = Instant::now();
        let p = aggregation.prove();
        a_times.push(t.elapsed().as_secs_f64() * 1e3);
        last_a = Some(p);
    }
    aggregation.verify(&last_a.unwrap());
    a_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let aggregation_stage = Stage {
        build_ms: aggregation.build_ms,
        cold_ms: a_cold,
        p50_ms: quantile(&a_times, 0.50),
        p90_ms: quantile(&a_times, 0.90),
        rss_mb: peak_rss_mb(),
    };

    // ---- COMPOSED: both proves back-to-back in each timed iteration -------
    // This is the real end-to-end send-prove. Cold = first composed run;
    // warm p50/p90 measure the genuine pipeline, not a post-hoc sum.
    let t = Instant::now();
    let ct0 = transition.prove();
    let ca0 = aggregation.prove();
    let composed_cold = t.elapsed().as_secs_f64() * 1e3;
    transition.verify(&ct0);
    aggregation.verify(&ca0);
    // warmup composed iteration.
    let _ = transition.prove();
    let _ = aggregation.prove();
    let mut c_times = Vec::with_capacity(WARM_RUNS);
    let mut last_ct = None;
    let mut last_ca = None;
    for _ in 0..WARM_RUNS {
        let t = Instant::now();
        let ct = transition.prove();
        let ca = aggregation.prove();
        c_times.push(t.elapsed().as_secs_f64() * 1e3);
        last_ct = Some(ct);
        last_ca = Some(ca);
    }
    transition.verify(&last_ct.unwrap());
    aggregation.verify(&last_ca.unwrap());
    c_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let composed_stage = Stage {
        build_ms: transition.build_ms + aggregation.build_ms,
        cold_ms: composed_cold,
        p50_ms: quantile(&c_times, 0.50),
        p90_ms: quantile(&c_times, 0.90),
        rss_mb: peak_rss_mb(),
    };

    // ---- results table ----------------------------------------------------
    println!("\n========================= Probe AE results (warm) =========================");
    println!(
        "{:<22} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "stage", "build", "cold", "warm_p50", "warm_p90", "rss_MB"
    );
    let print_stage = |label: &str, s: &Stage| {
        println!(
            "{:<22} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>9.0}",
            label, s.build_ms, s.cold_ms, s.p50_ms, s.p90_ms, s.rss_mb
        );
    };
    print_stage("transition (T, ZK)", &transition_stage);
    print_stage("aggregation (AC q48)", &aggregation_stage);
    print_stage("COMPOSED send-prove", &composed_stage);

    // ---- (a) batch-vs-sum-of-parts ---------------------------------------
    let measured_sum = transition_stage.p50_ms + aggregation_stage.p50_ms;
    let estimate_sum = PROBE_T_TRANSITION_MS + PROBE_AC_N4Q48_MS;
    println!("\n------------------------- (a) composed vs sum-of-parts -------------------------");
    println!(
        "sum-of-parts ESTIMATE  : T {PROBE_T_TRANSITION_MS:.0} ms + AC N=4 q48 {PROBE_AC_N4Q48_MS:.0} ms = {estimate_sum:.0} ms"
    );
    println!(
        "measured parts (here)  : transition {:.0} ms + aggregation {:.0} ms = {measured_sum:.0} ms",
        transition_stage.p50_ms, aggregation_stage.p50_ms
    );
    println!("COMPOSED measured p50  : {:.0} ms", composed_stage.p50_ms);
    // The two proves are distinct stacks run sequentially (no shared FRI commit
    // to fold), so batching cannot beat the sum — the composed time IS ~= the
    // sum of the two stages. Stated plainly rather than spun.
    let overhead = composed_stage.p50_ms - measured_sum;
    if composed_stage.p50_ms <= measured_sum * 1.05 {
        println!(
            "=> composed ~= sum of parts (delta {overhead:+.0} ms, <=5%). Two distinct STARK stacks"
        );
        println!(
            "   run sequentially share NO FRI commit/query work, so batching CANNOT beat the sum;"
        );
        println!("   the honest send-prove number is the sequential total, as measured.");
    } else {
        println!(
            "=> composed {overhead:+.0} ms vs measured sum (sequential overhead / RSS pressure)."
        );
    }

    // ---- (b) prove vs Plonky2 4.35 s warm single-prove -------------------
    println!("\n--------------- (b) composed send-prove vs Plonky2 4.35 s warm ---------------");
    let prove_p50 = composed_stage.p50_ms;
    let (prove_rel, prove_fac) = if prove_p50 < PLONKY2_WARM_MS {
        ("FASTER", PLONKY2_WARM_MS / prove_p50)
    } else {
        ("SLOWER", prove_p50 / PLONKY2_WARM_MS)
    };
    println!(
        "composed Plonky3 full send-prove = {prove_p50:.0} ms warm p50 -> {prove_rel} than Plonky2's"
    );
    println!(
        "  {PLONKY2_WARM_MS:.0} ms warm single-prove by {prove_fac:.2}x (apples-to-apples single-prove)."
    );

    // ---- (c) recomposed e2e /api/send vs Plonky2 ~10 s live --------------
    let e2e_ms = composed_stage.p50_ms + NODE_OVERHEAD_MS;
    let e2e_s = e2e_ms / 1000.0;
    let (e2e_rel, e2e_fac) = if e2e_ms < PLONKY2_LIVE_SEND_MS {
        ("FASTER", PLONKY2_LIVE_SEND_MS / e2e_ms)
    } else {
        ("SLOWER", e2e_ms / PLONKY2_LIVE_SEND_MS)
    };
    println!("\n------------- (c) recomposed e2e /api/send vs Plonky2 ~10 s live -------------");
    println!(
        "e2e /api/send = composed prove {:.0} ms + node overhead {NODE_OVERHEAD_MS:.0} ms = {e2e_ms:.0} ms ({e2e_s:.2} s)",
        composed_stage.p50_ms
    );
    println!(
        "  -> {e2e_rel} than Plonky2's live ~{:.0} s send by {e2e_fac:.2}x.",
        PLONKY2_LIVE_SEND_MS / 1000.0
    );

    // ---- THE VERDICT LINE the whole research ends on ---------------------
    println!("\n================================ VERDICT ===================================");
    println!(
        "Under the recommended config, the Plonky3 full send-prove is {prove_p50:.0} ms = {prove_fac:.2}x"
    );
    println!(
        "{prove_rel} than Plonky2's 4.35 s warm single-prove; the e2e /api/send is {e2e_s:.2} s ="
    );
    println!("{e2e_fac:.2}x {e2e_rel} than Plonky2's ~10 s live send.");
    println!("This headline rests on TWO [VERIFY] conditions, restated in full:");
    println!(
        "  [VERIFY] 1 — 64-bit inner-FRI composition argument: the aggregation's inner carrier"
    );
    println!(
        "               proofs use q=48 (1*48 + 16-bit PoW = 64 conjectured bits) inner FRI. This"
    );
    println!(
        "               is sound ONLY if the recursion composition tolerates a 64-bit inner layer"
    );
    println!(
        "               under a full-strength outer — an UNVERIFIED cryptographic assumption that"
    );
    println!("               a cryptographer must sign off before deployment.");
    println!(
        "  [VERIFY] 2 — MAX_IN_COINS=4 protocol change: the aggregation verifies 4 source slots,"
    );
    println!(
        "               not the current 8. This is a PROTOCOL restriction (a send caps at 4 in-"
    );
    println!(
        "               coins; wallets with more small coins consolidate first or split the send)."
    );
    println!(
        "Transition half runs TRUE ZK (HidingFriPcs); aggregation half is non-zk (outer-layer"
    );
    println!(
        "hiding is a separate, small additive term — see Probe W). The composed headline is the"
    );
    println!(
        "faithful production mix: hiding transition + non-zk recursion, both proofs verified."
    );
    println!("===========================================================================\n");

    // ---- hard gates: measured + verified ---------------------------------
    assert!(transition_stage.p50_ms > 0.0, "transition measured");
    assert!(aggregation_stage.p50_ms > 0.0, "aggregation measured");
    assert!(composed_stage.p50_ms > 0.0, "composed measured");
    // Composed must be at least as large as either part (sequential pipeline).
    assert!(
        composed_stage.p50_ms >= transition_stage.p50_ms,
        "composed >= transition part"
    );
    assert!(
        composed_stage.p50_ms >= aggregation_stage.p50_ms,
        "composed >= aggregation part"
    );
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got {packing_type}"
    );
}
