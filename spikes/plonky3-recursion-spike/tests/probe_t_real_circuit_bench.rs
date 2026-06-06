//! Probe T — the **central** Plonky3-migration cost estimate for zkCoins.
//!
//! # What this probe answers
//!
//! "If we port the real zkCoins state-transition circuit to Plonky3 + BabyBear
//! under TRUE production cryptography, how long does proving take, and is it
//! faster or slower than the current Plonky2 baseline (4.35 s warm p50 on an
//! Apple M5 Max)?" That single number decides the migration.
//!
//! # The honesty boundary — READ THIS, it is not blurred anywhere below
//!
//! The real circuit is ~7800 LOC of Plonky2 (`program-plonky2/src/circuit/`:
//! `main.rs` 3882, `smt.rs`, `sparse_merkle_tree.rs`, `source_aggregator.rs`,
//! `merkle/`). A literal semantic port = migration Phases 1-8 = weeks of work.
//! **Probe T does NOT port the business logic.** It builds a *cost-faithful
//! representative workload* that reproduces the real circuit's prove-cost
//! DRIVERS, not its meaning:
//!
//! * Poseidon2 permutation count (~4500 hashes),
//! * non-hash constraint-gate count (~50k gates: SMT/MMR path checks, range
//!   checks, field arithmetic),
//! * committed trace AREA (width x height per table),
//! * constraint DEGREE (degree-7 cryptographic S-box),
//! * the ZK commitment scheme (Keccak-hiding MMCS + HidingFriPcs).
//!
//! Prove cost in a FRI-STARK is governed by exactly those quantities: trace
//! dimensions x constraint degree x commitment scheme. Business-logic
//! constraints (balance conservation, nullifier uniqueness, SMT membership
//! semantics) add gates *within* these tables — they change WHICH field
//! elements are constrained, not the trace area or the degree class. So this
//! workload is a faithful proxy for prove COST, and an explicit NON-proxy for
//! correctness/soundness of the real statement. Every artifact labels it so.
//!
//! # The table model
//!
//! The real circuit is a multi-table computation: a hash-dense part plus a
//! non-hash arithmetic-dense part. Probe T models it with two AIR tables:
//!
//! 1. **Hash table** — the Probe V degree-7 `VectorizedPoseidon2Air` sized to
//!    ~4500 permutations. Production params (`MAX_IN/OUT_COINS = 8`,
//!    `INNER_PAD_BITS = 15`) put the real circuit at ~4500 Poseidon2 hashes.
//!    The vectorized AIR packs `VECTOR_LEN = 8` perms/row, so 4500 perms ->
//!    ceil(4500/8) = 563 rows, rounded up to the next power of two = 2^10 = 1024
//!    rows (= 8192 perms of capacity; the real count sits just under this).
//!
//! 2. **Non-hash arithmetic table** — a generic AIR with several
//!    multiplicative + linear constraints per row, modelling the ~50k non-hash
//!    gates. Because the real port's exact table layout is unknown, the
//!    non-hash table HEIGHT is swept over {2^13, 2^14, 2^15, 2^16}. This
//!    BRACKETS the real circuit: the true layout's committed area sits inside
//!    this range. Each row carries `ARITH_WIDTH` columns and
//!    `CONSTRAINTS_PER_ROW` degree-bounded constraints, so the constraint count
//!    at height H is `H * CONSTRAINTS_PER_ROW`; at 2^13 that already exceeds
//!    50k, so the sweep's LOW end is the realistic-gate anchor and the high end
//!    is a deliberate over-estimate ceiling.
//!
//! # How the two tables are combined (approaches a / b / c)
//!
//! The brief offers three ways to combine; establishing which actually
//! verifies under degree-7 + HidingFriPcs is itself a finding.
//!
//! * **(a) real multi-table `prove_batch`** (p3-batch-stark): ONE batched FRI
//!   proof over both tables. This is the faithful production shape (the real
//!   migration would batch all tables into one proof). Probe T runs this as
//!   the headline number. Establishing that `prove_batch` accepts the degree-7
//!   `VectorizedPoseidon2Air` + a custom arithmetic AIR under a `HidingFriPcs`
//!   config is the key empirical result — see the module doc verdict.
//!
//! * **(b) separate proofs, summed** = prove the hash table and the arithmetic
//!   table as two INDEPENDENT uni-stark proofs and SUM their warm times. Two
//!   separate proofs cost strictly MORE than one batched proof (duplicated FRI
//!   commit/query/PoW overhead), so this sum is a conservative UPPER BOUND on
//!   the real (batched) circuit. Probe T runs this too, as a cross-check and a
//!   guaranteed-working fallback, and labels it an upper bound.
//!
//! Probe T reports BOTH (a) and (b) per sweep size. The verdict uses (a) (the
//! faithful batched cost) as the primary estimate and (b) as the upper-bound
//! sanity rail.
//!
//! # Production-crypto config (reused verbatim from Probe V — confirmed to
//! verify at degree-7)
//!
//! * AIR: `VectorizedPoseidon2Air<.., SBOX_DEGREE=7, SBOX_REGISTERS=1,
//!   VECTOR_LEN=8>` (cryptographic BabyBear round counts: 4 half-full, 13
//!   partial).
//! * MMCS: `MerkleTreeHidingMmcs` over the Keccak sponge (`PaddingFreeSponge<
//!   KeccakF,25,17,4>` + `CompressionFunctionFromHasher`), `SmallRng` masking.
//! * PCS: `HidingFriPcs<.., SmallRng>`, `num_random_codewords = 4` (TRUE ZK).
//! * Challenger: `SerializingChallenger32<Val, HashChallenger<u8,
//!   Keccak256Hash, 32>>`.
//! * FRI: `FriParameters::new_benchmark_zk` (log_blowup 2, 100 queries, 16-bit
//!   PoW). Field BabyBear, challenge `BinomialExtensionField<BabyBear,4>`.
//!
//! # Verdict policy
//!
//! PASSES on successful measurement + verification of every proof. The
//! faster/slower verdict vs Plonky2 (4.35 s) is a REPORTED finding, not an
//! assert — a slower result is a datum to surface honestly, never to hide or
//! spin. The hard asserts are: every proof verifies, and `prove_batch` (a)
//! works under degree-7 + hiding (or, if it does not, the test fails with the
//! precise blocker so the orchestrator records it).

use std::sync::Arc;
use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    BABYBEAR_S_BOX_DEGREE, BabyBear, GenericPoseidon2LinearLayersBabyBear,
};
use p3_batch_stark::{ProverData, StarkGenericConfig, StarkInstance, prove_batch, verify_batch};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2_air::{RoundConstants, VectorizedPoseidon2Air};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

// --------------------------------------------------------------------------
// Crypto config (Probe V recipe — verbatim).
// --------------------------------------------------------------------------
const WIDTH: usize = 16;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS; // 4
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16; // 13
const VECTOR_LEN: usize = 1 << 3; // 8 perms / row
const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE; // 7
const SBOX_REGISTERS: usize = 1;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;

type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    SmallRng,
    2,
    4,
    4,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = p3_dft::Radix2DitParallel<BabyBear>;
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SmallRng>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// The degree-7 cryptographic Poseidon2 hash AIR (Probe V's `Air7`).
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

// --------------------------------------------------------------------------
// Real-circuit cost anchors.
// --------------------------------------------------------------------------
/// Real circuit's approximate Poseidon2 permutation count.
const REAL_HASH_PERMS: usize = 4500;
/// Real circuit's approximate non-hash gate (constraint) count.
const REAL_NONHASH_GATES: usize = 50_000;
/// Plonky2 measured baseline (M5 Max) for the real zkCoins state-transition.
const PLONKY2_P50_MS: f64 = 4350.0;
const PLONKY2_RSS_MB: f64 = 3900.0;

// --------------------------------------------------------------------------
// Non-hash arithmetic AIR — a cost model for the ~50k non-hash gates.
// --------------------------------------------------------------------------
//
// A generic table with `ARITH_WIDTH` columns. Per row it enforces
// `CONSTRAINTS_PER_ROW` constraints.
//
// **Degree choice — degree 3, deliberately and faithfully.** The hash table's
// degree-7 S-box is committable only because the vectorized Poseidon2 AIR adds
// a witness column per S-box (`SBOX_REGISTERS = 1`) that *decomposes* each
// `x^7` into chained low-degree steps, so its true per-constraint degree stays
// bounded — a raw `x^7` identity in a plain AIR is NOT committable under this
// FRI config (blowup 2 caps the constraint degree; an unregistered degree-7
// constraint fails the OOD check with `OodEvaluationMismatch`). More to the
// point, the real circuit's ~50k NON-hash gates are dominated by LOW-degree
// work: range checks, boolean checks, Merkle/SMT path equalities and field
// add/mul — almost all degree 2-3. The degree-7 cost lives in the Poseidon2
// hash table, which Probe T models with the real degree-7 AIR. So degree-3
// constraints here are the cost-faithful choice; forcing degree-7 would
// OVERSTATE the non-hash cost and misrepresent the real layout.
//
// Each constraint references real adjacent trace cells (`next[i] = local[i+1]^3`
// plus linear coupling), so it is genuine committed work the prover cannot fold
// away. The witness is generated to satisfy every constraint exactly.
const ARITH_WIDTH: usize = 16;
/// Degree-bounded constraints enforced per row. With `ARITH_WIDTH = 16` we pair
/// columns (i, i+1) for i in 0..8 (degree-3 each) and add 4 linear-coupling
/// constraints => 12 constraints/row. At height 2^13 that is 12 * 8192 ~= 98k
/// constraints (>50k); the sweep's LOW end already over-covers the real gate
/// count, the high end is a ceiling.
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
            let x3 = x.clone() * x.clone() * x; // x^3
            t.assert_eq(next[i], x3);
        }
        // 4 linear-coupling constraints: next[8+j] == local[j] + local[8+j].
        for j in 0..4 {
            let coupled: AB::Expr = local[j].into() + local[8 + j].into();
            t.assert_eq(next[8 + j], coupled);
        }
    }
}

/// Generate a witness trace of `height` rows that EXACTLY satisfies `ArithAir`.
/// Row r+1 is computed from row r so all transition constraints hold; the last
/// row is unconstrained (no `next`). Deterministic from a seed.
fn arith_trace(height: usize) -> RowMajorMatrix<Val> {
    assert!(height.is_power_of_two());
    let mut values = vec![Val::ZERO; height * ARITH_WIDTH];
    // Seed row 0 with small non-zero, distinct values.
    for (c, slot) in values.iter_mut().enumerate().take(ARITH_WIDTH) {
        *slot = Val::from_u64((c as u64) + 1);
    }
    for r in 1..height {
        let (prev, cur) = values.split_at_mut(r * ARITH_WIDTH);
        let prev = &prev[(r - 1) * ARITH_WIDTH..r * ARITH_WIDTH];
        let cur = &mut cur[..ARITH_WIDTH];
        for i in 0..8 {
            let x = prev[i + 1];
            cur[i] = x * x * x; // x^3
        }
        for j in 0..4 {
            cur[8 + j] = prev[j] + prev[8 + j];
        }
        // Columns 12..16 are free; fill deterministically so the table is dense.
        for (k, slot) in cur.iter_mut().enumerate().skip(12) {
            *slot = prev[k] + Val::ONE;
        }
    }
    RowMajorMatrix::new(values, ARITH_WIDTH)
}

// --------------------------------------------------------------------------
// Multi-table enum AIR for approach (a) — real `prove_batch`.
// --------------------------------------------------------------------------
//
// batch-stark requires ONE `A: Air + Clone` type for all instances. The
// degree-7 `VectorizedPoseidon2Air` is not `Clone` (holds non-Clone round
// constants), so it is wrapped in `Arc` and dispatched through an enum that is
// generic over the builder. `Arc<HashAir>` makes the enum cheaply `Clone`
// while `eval`/`width` deref straight through to the underlying AIR — zero
// semantic change to either table.
#[derive(Clone)]
enum TableAir {
    Hash(Arc<HashAir>),
    Arith(ArithAir),
}

// `HashAir`'s `BaseAir`/`Air` are implemented only for the concrete BabyBear
// `Val` (its linear layers are `GenericPoseidon2LinearLayersBabyBear`), so the
// enum wrapper is also `Val`-concrete. batch-stark only instantiates these
// builders with `AB::F = Val`, so `AB::F = Val` is the right (and only) bound.
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

// --------------------------------------------------------------------------
// Config + RSS helpers (Probe V recipe).
// --------------------------------------------------------------------------
fn build_config() -> (MyConfig, usize) {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);

    let val_mmcs = ValMmcs::new(field_hash, compress, 0, SmallRng::seed_from_u64(2));
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters::new_benchmark_zk(challenge_mmcs);
    let log_blowup = fri_params.log_blowup;

    let dft = Dft::default();
    let pcs = Pcs::new(dft, val_mmcs, fri_params, 4, SmallRng::seed_from_u64(3));

    let challenger = Challenger::from_hasher(vec![], byte_hash);
    (MyConfig::new(pcs, challenger), log_blowup)
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

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// Build the degree-7 hash AIR (deterministic constants).
fn build_hash_air() -> HashAir {
    let mut rng = SmallRng::seed_from_u64(1);
    VectorizedPoseidon2Air::new(RoundConstants::from_rng(&mut rng))
}

/// Round `n` up to the next power of two (>= 2 for FRI).
fn next_pow2(n: usize) -> usize {
    n.max(2).next_power_of_two()
}

// --------------------------------------------------------------------------
// Timing helpers.
// --------------------------------------------------------------------------
const WARM_RUNS: usize = 5;

struct Timing {
    build_ms: f64,
    cold_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    rss_mb: f64,
}

/// (a) Real batched proof over BOTH tables. Times the WHOLE batch
/// (build = ProverData/keygen; cold = first prove; warm = p50/p90 over
/// `WARM_RUNS`). Verifies the proof.
fn run_batch(
    config: &MyConfig,
    hash_air: Arc<HashAir>,
    hash_trace: &RowMajorMatrix<Val>,
    arith_trace: &RowMajorMatrix<Val>,
) -> Timing {
    let airs = [TableAir::Hash(hash_air), TableAir::Arith(ArithAir)];

    let t0 = Instant::now();
    let prover_data: ProverData<MyConfig> = ProverData::from_airs_and_degrees(
        config,
        &airs,
        &[
            log2(hash_trace.height()) + config.is_zk(),
            log2(arith_trace.height()) + config.is_zk(),
        ],
    );
    let build_ms = t0.elapsed().as_secs_f64() * 1e3;
    let common = &prover_data.common;
    let pvs = vec![vec![], vec![]];
    let traces: [&RowMajorMatrix<Val>; 2] = [hash_trace, arith_trace];
    let instances = StarkInstance::new_multiple(&airs, &traces, &pvs);

    // Cold prove (first, untimed-warmup-free).
    let t = Instant::now();
    let proof = prove_batch(config, &instances, &prover_data);
    let cold_ms = t.elapsed().as_secs_f64() * 1e3;
    verify_batch(config, &airs, &proof, &pvs, common).expect("Probe T batch proof must verify");

    // Warmup (untimed), then WARM_RUNS timed.
    let _ = prove_batch(config, &instances, &prover_data);
    let mut times = Vec::with_capacity(WARM_RUNS);
    let mut last = None;
    for _ in 0..WARM_RUNS {
        let t = Instant::now();
        let proof = prove_batch(config, &instances, &prover_data);
        times.push(t.elapsed().as_secs_f64() * 1e3);
        last = Some(proof);
    }
    let proof = last.unwrap();
    verify_batch(config, &airs, &proof, &pvs, common)
        .expect("Probe T batch warm proof must verify");

    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Timing {
        build_ms,
        cold_ms,
        p50_ms: quantile(&times, 0.50),
        p90_ms: quantile(&times, 0.90),
        rss_mb: peak_rss_mb(),
    }
}

/// (b) A single uni-stark proof over one AIR+trace (used to time hash and
/// arith tables independently; their warm sum is the conservative upper bound).
fn run_single<A>(config: &MyConfig, air: &A, trace: &RowMajorMatrix<Val>) -> Timing
where
    A: for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, MyConfig>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, MyConfig>>
        + Air<p3_uni_stark::SymbolicAirBuilder<Val>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>,
{
    let t = Instant::now();
    let proof = prove(config, air, trace.clone(), &[]);
    let cold_ms = t.elapsed().as_secs_f64() * 1e3;
    verify(config, air, &proof, &[]).expect("Probe T single proof must verify");

    let _ = prove(config, air, trace.clone(), &[]); // warmup
    let mut times = Vec::with_capacity(WARM_RUNS);
    let mut last = None;
    for _ in 0..WARM_RUNS {
        let t = Instant::now();
        let proof = prove(config, air, trace.clone(), &[]);
        times.push(t.elapsed().as_secs_f64() * 1e3);
        last = Some(proof);
    }
    verify(config, air, &last.unwrap(), &[]).expect("Probe T single warm proof must verify");

    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Timing {
        build_ms: 0.0,
        cold_ms,
        p50_ms: quantile(&times, 0.50),
        p90_ms: quantile(&times, 0.90),
        rss_mb: peak_rss_mb(),
    }
}

fn log2(n: usize) -> usize {
    n.trailing_zeros() as usize
}

#[test]
fn probe_t_real_circuit_bench() {
    let packing_type = core::any::type_name::<<Val as Field>::Packing>();
    let scalar_type = core::any::type_name::<Val>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = rayon::current_num_threads();

    println!("\n============== Probe T: real-circuit Plonky3 prove-cost estimate ==============");
    println!("PROXY BOUNDARY: cost-faithful workload (hash count + gate count + area + degree +");
    println!("ZK commitment). NOT a semantic port — no balance/nullifier/SMT-membership logic.");
    println!("config (Probe V, verified at degree-7): VectorizedPoseidon2Air<.., SBOX_DEGREE=7,");
    println!("  SBOX_REGISTERS=1, VECTOR_LEN=8> | MerkleTreeHidingMmcs(Keccak) | HidingFriPcs");
    println!(
        "  num_random_codewords=4 (TRUE ZK) | FRI new_benchmark_zk (blowup=2,100q,16-bit PoW)"
    );
    println!("BabyBear::Packing : {packing_type}");
    println!("  -> SIMD packing active: {packing_active} (vs scalar {scalar_type})");
    println!("rayon threads     : {threads}");
    println!(
        "Plonky2 baseline  : {PLONKY2_P50_MS:.0} ms warm p50 / {PLONKY2_RSS_MB:.0} MB (real circuit, M5 Max)"
    );

    // One-time config + AIR build — the Plonky3 analog of Plonky2's cold
    // circuit-build (8.2 s on M5 Max). Plonky3 has no circuit-compilation step:
    // the config is a handful of hasher/PCS constructions and the AIR is a few
    // round constants, so this should be milliseconds — itself a finding.
    let t_setup = Instant::now();
    let (config, log_blowup) = build_config();
    let hash_air = Arc::new(build_hash_air());
    let config_build_ms = t_setup.elapsed().as_secs_f64() * 1e3;
    assert_eq!(log_blowup, 2, "new_benchmark_zk must be blowup-2");
    println!(
        "config+AIR build  : {config_build_ms:.2} ms (Plonky3 analog of Plonky2 cold circuit-build 8200 ms)"
    );

    // --- Hash table: ~4500 perms -> power-of-two row count -----------------
    let hash_perms_capacity = next_pow2(REAL_HASH_PERMS.div_ceil(VECTOR_LEN)) * VECTOR_LEN;
    let hash_trace = hash_air.generate_vectorized_trace_rows(hash_perms_capacity, log_blowup);
    let hash_rows = hash_trace.height();
    println!("------------------------------------------------------------------------------");
    println!(
        "hash table  : ~{REAL_HASH_PERMS} real perms -> {hash_perms_capacity} perms capacity = {hash_rows} rows (degree-7)"
    );

    // Hash table standalone timing (shared across all sweep points: the hash
    // table size is fixed; only the arith table is swept).
    let hash_single = run_single(&config, hash_air.as_ref(), &hash_trace);
    println!(
        "  hash standalone: cold={:.1}ms warm_p50={:.1}ms p90={:.1}ms rss={:.0}MB",
        hash_single.cold_ms, hash_single.p50_ms, hash_single.p90_ms, hash_single.rss_mb
    );

    // --- Sweep the non-hash arithmetic table height -----------------------
    let sweep: [usize; 4] = [1 << 13, 1 << 14, 1 << 15, 1 << 16];
    println!(
        "arith table : {ARITH_WIDTH} cols x {CONSTRAINTS_PER_ROW} degree-3 constraints/row; sweep heights {sweep:?}"
    );
    println!(
        "  (real ~{REAL_NONHASH_GATES} non-hash gates; constraints at height H = H*{CONSTRAINTS_PER_ROW})"
    );
    println!("==============================================================================");

    struct Row {
        height: usize,
        constraints: usize,
        arith: Timing,
        batch: Timing,
        sum_p50: f64,
        sum_p90: f64,
    }
    let mut rows = Vec::new();

    for &h in &sweep {
        let arith_trace = arith_trace(h);
        let constraints = h * CONSTRAINTS_PER_ROW;
        println!(
            "\n--- arith height 2^{} = {} rows ({} constraints) ---",
            log2(h),
            h,
            constraints
        );

        // (b) arith table standalone.
        let arith = run_single(&config, &ArithAir, &arith_trace);
        println!(
            "  (b) arith standalone : cold={:.1}ms warm_p50={:.1}ms p90={:.1}ms rss={:.0}MB",
            arith.cold_ms, arith.p50_ms, arith.p90_ms, arith.rss_mb
        );
        let sum_p50 = hash_single.p50_ms + arith.p50_ms;
        let sum_p90 = hash_single.p90_ms + arith.p90_ms;
        println!(
            "  (b) UPPER BOUND sum  : warm_p50={sum_p50:.1}ms p90={sum_p90:.1}ms (hash {:.1} + arith {:.1})",
            hash_single.p50_ms, arith.p50_ms
        );

        // (a) real batched proof over both tables.
        let batch = run_batch(&config, hash_air.clone(), &hash_trace, &arith_trace);
        println!(
            "  (a) BATCHED prove    : build={:.1}ms cold={:.1}ms warm_p50={:.1}ms p90={:.1}ms rss={:.0}MB",
            batch.build_ms, batch.cold_ms, batch.p50_ms, batch.p90_ms, batch.rss_mb
        );

        rows.push(Row {
            height: h,
            constraints,
            arith,
            batch,
            sum_p50,
            sum_p90,
        });
    }

    // --- Result table ------------------------------------------------------
    println!("\n========================= Probe T results table ==============================");
    println!(
        "{:<10} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "arith_h",
        "constr",
        "(a)build",
        "(a)cold",
        "(a)p50",
        "(a)p90",
        "(a)rss",
        "arithRss",
        "(b)sum50",
        "(b)sum90"
    );
    for r in &rows {
        println!(
            "2^{:<8} {:>9} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>9.0} {:>9.0} {:>9.1} {:>9.1}",
            log2(r.height),
            r.constraints,
            r.batch.build_ms,
            r.batch.cold_ms,
            r.batch.p50_ms,
            r.batch.p90_ms,
            r.batch.rss_mb,
            r.arith.rss_mb,
            r.sum_p50,
            r.sum_p90,
        );
    }

    // --- Verdict per sweep size -------------------------------------------
    println!("\n=============== net real-circuit estimate vs Plonky2 (4.35 s warm) ===========");
    println!("Primary estimate = (a) batched warm p50; (b) summed = conservative upper bound.");
    for r in &rows {
        let a = r.batch.p50_ms;
        let (verdict, factor) = if a < PLONKY2_P50_MS {
            ("FASTER", PLONKY2_P50_MS / a)
        } else {
            ("SLOWER", a / PLONKY2_P50_MS)
        };
        println!(
            "arith 2^{:<2}: (a) p50={:>8.1}ms -> {} than Plonky2 by {:.2}x | (b) upper bound p50={:>8.1}ms",
            log2(r.height),
            a,
            verdict,
            factor,
            r.sum_p50,
        );
    }

    // --- Honest bottom line -----------------------------------------------
    // Most-likely real layout: the arithmetic constraint count at the LOW sweep
    // end (2^13 => ~98k constraints) already exceeds the real ~50k non-hash
    // gate count, so the real circuit's non-hash committed area sits between
    // 2^13 and 2^14. We take 2^13 as the realistic anchor and 2^14 as a safe
    // upper estimate; 2^15/2^16 are deliberate ceilings.
    let realistic = &rows[0]; // 2^13
    println!("\n=============================== BOTTOM LINE ===================================");
    println!(
        "Most-likely real layout: arith ~2^13-2^14 (real ~{REAL_NONHASH_GATES} gates < {} constraints",
        realistic.constraints
    );
    println!("at 2^13). Anchor = 2^13 batched (a).");
    {
        let a = realistic.batch.p50_ms;
        if a < PLONKY2_P50_MS {
            println!(
                "VERDICT: Plonky3+BabyBear (TRUE production crypto) is FASTER than Plonky2 by {:.2}x",
                PLONKY2_P50_MS / a
            );
            println!("  ({a:.0} ms vs 4350 ms) at the realistic layout.");
        } else {
            println!(
                "VERDICT: Plonky3+BabyBear (TRUE production crypto) is SLOWER than Plonky2 by {:.2}x",
                a / PLONKY2_P50_MS
            );
            println!("  ({a:.0} ms vs 4350 ms) at the realistic layout. NOT spun as a win.");
            println!(
                "  Recovery levers (circuit-side only, NOT hardware): fewer Poseidon2 hashes;"
            );
            println!(
                "  smaller MAX_IN_COINS; circuit-level constraint optimization; KoalaBear field;"
            );
            println!("  dropping in-coin recursion.");
        }
    }
    println!("(a) real multi-table prove_batch WORKS with HidingFriPcs + degree-7: confirmed by");
    println!("    successful verify_batch above. This is the faithful production proof shape.");
    println!("==============================================================================\n");

    assert_eq!(rows.len(), 4, "must have 4 sweep points");
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got {packing_type}"
    );
}
