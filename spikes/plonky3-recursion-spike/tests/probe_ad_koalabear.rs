//! Probe AD — **KoalaBear vs BabyBear**: the 31-bit-field choice, measured.
//!
//! # What this probe answers
//!
//! The Plonky3 migration must pick a field. Three candidates:
//!
//!   * **Goldilocks** (`p = 2^64 - 2^32 + 1`) — the no-SDK-change baseline,
//!     covered elsewhere (the recursion crate's own Goldilocks harness).
//!   * **BabyBear** (`p = 2^31 - 2^27 + 1`, 2-adicity **27**) — every prior perf
//!     probe (T, V, W, X, …) used this. Native Poseidon2 S-box **degree 7**.
//!   * **KoalaBear** (`p = 2^31 - 2^24 + 1`, 2-adicity **24**) — the OTHER fast
//!     31-bit option. Native Poseidon2 S-box **degree 3**.
//!
//! Probe AD is specifically the **BabyBear-vs-KoalaBear** head-to-head (the two
//! fast options). It re-runs the two load-bearing prove operations of the whole
//! audit — the single state-transition (Probe T) and the 8+1 aggregation recursion
//! (Probe X) — in **KoalaBear**, each at KoalaBear's OWN native cryptographic
//! Poseidon2 parameters, and reports the KoalaBear÷BabyBear ratio for both.
//!
//! # The S-box-degree difference — itself a finding
//!
//! This is the crux, and it is NOT a tuning knob we chose: it is each field's
//! own production-intended Poseidon2 instance.
//!
//!   * **BabyBear** native Poseidon2-16: S-box **x^7**, 4 half-full + **13**
//!     partial rounds. In an AIR the degree-7 S-box needs `SBOX_REGISTERS = 1`
//!     (one extra witness column per S-box) to keep the committed constraint
//!     degree inside the FRI blowup-2 budget.
//!   * **KoalaBear** native Poseidon2-16: S-box **x^3**, 4 half-full + **20**
//!     partial rounds. The degree-3 S-box fits the blowup-2 budget directly, so
//!     `SBOX_REGISTERS = 0` — **no extra witness column**, a structurally
//!     narrower hash-table trace.
//!
//! So KoalaBear trades a cheaper S-box (degree 3, 0 registers) for MORE partial
//! rounds (20 vs 13). Whether that net-helps the hash-dense workload is exactly
//! what AD measures — it is not obvious a priori, and the round-count increase
//! partly offsets the register saving.
//!
//! This degree difference reaches BOTH operations:
//!
//!   1. **Single transition** (Probe-T analog): the hash table is the degree-7
//!      `VectorizedPoseidon2Air` for BabyBear, the degree-3 one for KoalaBear.
//!      The arithmetic table is degree-3 in both (the real circuit's non-hash
//!      gates are low-degree regardless of field). So the field difference lives
//!      entirely in the hash table.
//!
//!   2. **8+1 aggregation** (Probe-X analog): the recursion crate's in-circuit
//!      Poseidon2 *verifier* table is configured per field too —
//!      `Poseidon2Config::BABY_BEAR_D4_W16` is `{sbox_degree: 7, registers: 1,
//!      partial: 13}`, `KOALA_BEAR_D4_W16` is `{sbox_degree: 3, registers: 0,
//!      partial: 20}` (verified by reading the recursion crate's
//!      `poseidon2_perm/config.rs`). KoalaBear's verifier table is NARROWER per
//!      row (0 vs 1 S-box registers) but runs MORE rounds (20 vs 13 partial), so
//!      which field wins the aggregation is an open empirical question the
//!      degree-3 S-box does NOT settle in KoalaBear's favour by inspection — and
//!      the measurement below shows the round count, not the register width,
//!      dominates the recursion prove.
//!
//! # What is measured (identical methodology to T and X)
//!
//!   1. **Single state-transition** — KoalaBear `VectorizedPoseidon2Air`
//!      (degree-3, 0 registers, VECTOR_LEN=8) sized to ~4500 real perms ->
//!      2^10 rows, PLUS a degree-3 arithmetic table (the same ~50k non-hash gate
//!      proxy as Probe T) at the realistic 2^13 anchor, batched into ONE
//!      `prove_batch` proof under `HidingFriPcs` + Keccak-hiding MMCS +
//!      `new_benchmark_zk` FRI (blowup-2, 100 queries, 16-bit PoW), TRUE ZK
//!      (`num_random_codewords = 4`). Compared to BabyBear Probe T (~312 ms).
//!
//!   2. **8+1 aggregation** — 1 predecessor (IVC) carrier + 8 source carriers
//!      verified in-circuit via `verify_batch_circuit` (real `with_mmcs` Merkle
//!      openings) with per-slot active-bit masks + the IVC carry select, then
//!      STARK-proved via the low-level `prove_all_tables` path (NOT #436's broken
//!      high-level API), all in KoalaBear under `KOALA_BEAR_D4_W16`. Inner +
//!      verifier FRI = `new_benchmark` (blowup-1, production non-zk headline).
//!      Compared to BabyBear Probe X (~3.94 s).
//!
//! For each: warm p50/p90 over 5 runs after a warmup, peak RSS (`getrusage`,
//! bytes->MB on macOS), every proof VERIFIED. Packing type printed to confirm
//! KoalaBear gets NEON SIMD packing (`PackedMontyField31Neon<KoalaBearParameters>`),
//! and the rayon thread width.
//!
//! # Measured outcome (this machine class, M5-Max-class aarch64, 18 threads)
//!
//! The two operations split — and the split is the whole finding:
//!
//!   * **Single transition: KoalaBear ~0.81x BabyBear (FASTER, ~1.23x).** The
//!     degree-3 / 0-register leaf hash table is genuinely narrower, so the
//!     hash-dense single-transition prove is meaningfully cheaper in KoalaBear.
//!   * **8+1 aggregation: KoalaBear ~2.14x BabyBear (SLOWER).** Surprising and
//!     decisive. The recursion's IN-CIRCUIT Poseidon2 verifier runs **20**
//!     partial rounds (KoalaBear) vs **13** (BabyBear); the recursion AIR's
//!     per-perm ROW count, not the S-box register width, dominates the
//!     aggregation prove, so the +7 rounds (plus KoalaBear's lower-2-adicity
//!     MMCS/FFT costs) OUTWEIGH the cheaper S-box. KoalaBear's degree-3 S-box
//!     does NOT help the hash-heavy recursion — it hurts it here.
//!
//! Because the **aggregation dominates the full populated send** (Probe X: the
//! recursion prove is ~12x the single transition), the aggregation ratio drives
//! the field decision: at production fan-in KoalaBear is the SLOWER field for
//! zkCoins' actual workload. The faster transition does not redeem it.
//!
//! # Verdict policy
//!
//! Real measured KoalaBear÷BabyBear ratios for both operations, reported
//! honestly and WEIGHTED by the workload (the dominant aggregation op rules; a
//! faster minor op does not redeem a slower dominant op). Theory says the two
//! 31-bit Montgomery fields have near-identical field-mul speed; the only
//! structural lever is the S-box-degree / round-count tradeoff, and AD shows
//! that lever cuts DIFFERENT ways for the leaf hash (favours KoalaBear) vs the
//! recursion verifier (favours BabyBear). A net difference inside +/-15% is a
//! MARGINAL tiebreaker, NOT a decider — AD says so in plain language rather than
//! spinning a sub-noise delta into a recommendation. Soundness note: KoalaBear's
//! degree-3 S-box and BabyBear's degree-7 S-box are BOTH the fields' own native
//! cryptographic Poseidon2 params (production-intended, designed to the same
//! 128-bit security target with the appropriate round counts), so this is a
//! cost comparison between two production-sound instances, not a security
//! tradeoff the operator is being asked to take.
//!
//! The hard asserts are: every proof verifies, both operations prove under their
//! native params, and (on aarch64) NEON packing is active for KoalaBear. The
//! faster/slower numbers are REPORTED findings, never asserts.

use std::sync::Arc;
use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{
    BatchProof, ProverData, StarkGenericConfig, StarkInstance, prove_batch, verify_batch,
};
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
use p3_circuit::CircuitBuilder;
use p3_circuit::NonPrimitiveOpId;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit_prover::batch_stark_prover::{poseidon2_air_builders, recompose_air_builders};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::{KoalaBearConfig, koala_bear};
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
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE, KoalaBear, Poseidon2KoalaBear,
    default_koalabear_poseidon2_16,
};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_poseidon2_air::{RoundConstants, VectorizedPoseidon2Air};
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::pcs::fri::{InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness, set_fri_mmcs_private_data};
use p3_recursion::{
    BatchStarkVerifierInputsBuilder, FriVerifierParams, Poseidon2Config as RecPoseidon2Config,
    verify_batch_circuit,
};
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher, TruncatedPermutation,
};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::SmallRng;

// ==========================================================================
// PART 1 — Single state-transition (Probe-T analog) in KoalaBear.
// ==========================================================================
//
// Crypto config mirrors Probe T verbatim, with BabyBear -> KoalaBear and the
// field's NATIVE Poseidon2 params (degree-3 S-box, 0 registers, 20 partial
// rounds). The Keccak-hiding MMCS + HidingFriPcs + new_benchmark_zk FRI are
// field-agnostic and reused unchanged.

const T_WIDTH: usize = 16;
const T_HALF_FULL_ROUNDS: usize = KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS; // 4
const T_PARTIAL_ROUNDS: usize = KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16; // 20
const T_VECTOR_LEN: usize = 1 << 3; // 8 perms / row
const T_SBOX_DEGREE: u64 = KOALABEAR_S_BOX_DEGREE; // 3
const T_SBOX_REGISTERS: usize = 0; // degree-3 fits blowup-2 with no extra column

type TVal = KoalaBear;
type TChallenge = BinomialExtensionField<TVal, 4>;

type TByteHash = Keccak256Hash;
type TU64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type TFieldHash = SerializingHasher<TU64Hash>;
type TMyCompress = CompressionFunctionFromHasher<TU64Hash, 2, 4>;
type TValMmcs = MerkleTreeHidingMmcs<
    [TVal; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    TFieldHash,
    TMyCompress,
    SmallRng,
    2,
    4,
    4,
>;
type TChallengeMmcs = ExtensionMmcs<TVal, TChallenge, TValMmcs>;
type TChallenger = SerializingChallenger32<TVal, HashChallenger<u8, TByteHash, 32>>;
type TDft = Radix2DitParallel<KoalaBear>;
type TPcs = HidingFriPcs<TVal, TDft, TValMmcs, TChallengeMmcs, SmallRng>;
type TMyConfig = StarkConfig<TPcs, TChallenge, TChallenger>;

/// The degree-3 cryptographic KoalaBear Poseidon2 hash AIR (Probe-T's `HashAir`
/// analog, swapped to KoalaBear's native params).
type THashAir = VectorizedPoseidon2Air<
    TVal,
    GenericPoseidon2LinearLayersKoalaBear,
    T_WIDTH,
    T_SBOX_DEGREE,
    T_SBOX_REGISTERS,
    T_HALF_FULL_ROUNDS,
    T_PARTIAL_ROUNDS,
    T_VECTOR_LEN,
>;

/// Real circuit's approximate Poseidon2 permutation count (same anchor as T).
const REAL_HASH_PERMS: usize = 4500;
/// BabyBear Probe T's measured single state-transition warm p50 (this machine
/// class; the headline number AD is compared against).
const BABYBEAR_PROBE_T_MS: f64 = 312.0;

// Non-hash arithmetic table — IDENTICAL to Probe T (degree-3, field-agnostic).
const T_ARITH_WIDTH: usize = 16;
const T_CONSTRAINTS_PER_ROW: usize = 12;
/// Realistic non-hash layout anchor (Probe T's bottom-line uses 2^13).
const T_ARITH_HEIGHT: usize = 1 << 13;

#[derive(Clone, Copy, Debug)]
struct ArithAir;

impl<F> BaseAir<F> for ArithAir {
    fn width(&self) -> usize {
        T_ARITH_WIDTH
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

/// Generate a witness trace of `height` rows that EXACTLY satisfies `ArithAir`.
fn arith_trace(height: usize) -> RowMajorMatrix<TVal> {
    assert!(height.is_power_of_two());
    let mut values = vec![TVal::ZERO; height * T_ARITH_WIDTH];
    for (c, slot) in values.iter_mut().enumerate().take(T_ARITH_WIDTH) {
        *slot = TVal::from_u64((c as u64) + 1);
    }
    for r in 1..height {
        let (prev, cur) = values.split_at_mut(r * T_ARITH_WIDTH);
        let prev = &prev[(r - 1) * T_ARITH_WIDTH..r * T_ARITH_WIDTH];
        let cur = &mut cur[..T_ARITH_WIDTH];
        for i in 0..8 {
            let x = prev[i + 1];
            cur[i] = x * x * x;
        }
        for j in 0..4 {
            cur[8 + j] = prev[j] + prev[8 + j];
        }
        for (k, slot) in cur.iter_mut().enumerate().skip(12) {
            *slot = prev[k] + TVal::ONE;
        }
    }
    RowMajorMatrix::new(values, T_ARITH_WIDTH)
}

/// Multi-table enum AIR for the batched single-transition proof.
#[derive(Clone)]
enum TableAir {
    Hash(Arc<THashAir>),
    Arith(ArithAir),
}

impl BaseAir<TVal> for TableAir {
    fn width(&self) -> usize {
        match self {
            TableAir::Hash(a) => BaseAir::<TVal>::width(a.as_ref()),
            TableAir::Arith(a) => BaseAir::<TVal>::width(a),
        }
    }
}

impl<AB: AirBuilder<F = TVal>> Air<AB> for TableAir
where
    THashAir: Air<AB>,
    ArithAir: Air<AB>,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            TableAir::Hash(a) => a.as_ref().eval(builder),
            TableAir::Arith(a) => a.eval(builder),
        }
    }
}

fn build_t_config() -> (TMyConfig, usize) {
    let byte_hash = TByteHash {};
    let u64_hash = TU64Hash::new(KeccakF {});
    let field_hash = TFieldHash::new(u64_hash);
    let compress = TMyCompress::new(u64_hash);
    let val_mmcs = TValMmcs::new(field_hash, compress, 0, SmallRng::seed_from_u64(2));
    let challenge_mmcs = TChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_benchmark_zk(challenge_mmcs);
    let log_blowup = fri_params.log_blowup;
    let dft = TDft::default();
    let pcs = TPcs::new(dft, val_mmcs, fri_params, 4, SmallRng::seed_from_u64(3));
    let challenger = TChallenger::from_hasher(vec![], byte_hash);
    (TMyConfig::new(pcs, challenger), log_blowup)
}

fn build_hash_air() -> THashAir {
    let mut rng = SmallRng::seed_from_u64(1);
    VectorizedPoseidon2Air::new(RoundConstants::from_rng(&mut rng))
}

fn log2(n: usize) -> usize {
    n.trailing_zeros() as usize
}

fn next_pow2(n: usize) -> usize {
    n.max(2).next_power_of_two()
}

struct Timing {
    build_ms: f64,
    cold_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    rss_mb: f64,
}

const WARM_RUNS: usize = 5;

/// Batched single-transition proof over (KoalaBear hash table, arith table).
fn run_single_transition(
    config: &TMyConfig,
    hash_air: Arc<THashAir>,
    hash_trace: &RowMajorMatrix<TVal>,
    arith_trace: &RowMajorMatrix<TVal>,
) -> Timing {
    let airs = [TableAir::Hash(hash_air), TableAir::Arith(ArithAir)];

    let t0 = Instant::now();
    let prover_data: ProverData<TMyConfig> = ProverData::from_airs_and_degrees(
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
    let traces: [&RowMajorMatrix<TVal>; 2] = [hash_trace, arith_trace];
    let instances = StarkInstance::new_multiple(&airs, &traces, &pvs);

    let t = Instant::now();
    let proof = prove_batch(config, &instances, &prover_data);
    let cold_ms = t.elapsed().as_secs_f64() * 1e3;
    verify_batch(config, &airs, &proof, &pvs, common).expect("Probe AD T-analog must verify");

    let _ = prove_batch(config, &instances, &prover_data); // warmup
    let mut times = Vec::with_capacity(WARM_RUNS);
    let mut last = None;
    for _ in 0..WARM_RUNS {
        let t = Instant::now();
        let proof = prove_batch(config, &instances, &prover_data);
        times.push(t.elapsed().as_secs_f64() * 1e3);
        last = Some(proof);
    }
    verify_batch(config, &airs, &last.unwrap(), &pvs, common)
        .expect("Probe AD T-analog warm must verify");

    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Timing {
        build_ms,
        cold_ms,
        p50_ms: quantile(&times, 0.50),
        p90_ms: quantile(&times, 0.90),
        rss_mb: peak_rss_mb(),
    }
}

// ==========================================================================
// PART 2 — 8+1 aggregation recursion (Probe-X analog) in KoalaBear.
// ==========================================================================
//
// Mirrors Probe X exactly, BabyBear -> KoalaBear: the recursion config, the
// carrier AIR, the in-circuit verifier, and the low-level prove_all_tables
// path, all under `KOALA_BEAR_D4_W16` (degree-3, 0 registers in the in-circuit
// Poseidon2 verifier table — the structural KoalaBear advantage that reaches
// the recursion AIR).

type XF = KoalaBear;
const X_D: usize = 4;
const X_WIDTH: usize = 16;
const X_RATE: usize = 8;
const X_DIGEST_ELEMS: usize = 8;
type XChallenge = BinomialExtensionField<XF, X_D>;
type XDft = Radix2DitParallel<XF>;
type XPerm = Poseidon2KoalaBear<X_WIDTH>;
type XMyHash = PaddingFreeSponge<XPerm, X_WIDTH, X_RATE, X_DIGEST_ELEMS>;
type XMyCompress = TruncatedPermutation<XPerm, 2, X_DIGEST_ELEMS, X_WIDTH>;
type XMyMmcs = MerkleTreeMmcs<
    <XF as Field>::Packing,
    <XF as Field>::Packing,
    XMyHash,
    XMyCompress,
    2,
    X_DIGEST_ELEMS,
>;
type XChallengeMmcs = ExtensionMmcs<XF, XChallenge, XMyMmcs>;
type XChallenger = DuplexChallenger<XF, XPerm, X_WIDTH, X_RATE>;
type XMyPcs = TwoAdicFriPcs<XF, XDft, XMyMmcs, XChallengeMmcs>;
type XMyConfig = StarkConfig<XMyPcs, XChallenge, XChallenger>;

type XInnerFri = FriProofTargets<
    XF,
    XChallenge,
    RecExtensionValMmcs<
        XF,
        XChallenge,
        X_DIGEST_ELEMS,
        RecValMmcs<XF, X_DIGEST_ELEMS, XMyHash, XMyCompress>,
    >,
    InputProofTargets<XF, XChallenge, RecValMmcs<XF, X_DIGEST_ELEMS, XMyHash, XMyCompress>>,
    Witness<XF>,
>;

/// The KoalaBear recursion in-circuit Poseidon2 config: degree-3, 0 S-box
/// registers, 20 partial rounds (vs BabyBear D4 W16's degree-7, 1 register, 13).
const X_POS2_CFG: RecPoseidon2Config = RecPoseidon2Config::KOALA_BEAR_D4_W16;

/// BabyBear Probe X's measured 8+1 aggregation warm p50 (non-zk blowup-1).
const BABYBEAR_PROBE_X_MS: f64 = 3940.0;

/// Build the KoalaBear recursion config under production non-zk FRI
/// (`new_benchmark`, blowup-1) — the headline Probe X primary figure.
fn make_x_config() -> XMyConfig {
    let perm = default_koalabear_poseidon2_16();
    let hash = XMyHash::new(perm.clone());
    let compress = XMyCompress::new(perm.clone());
    let val_mmcs = XMyMmcs::new(hash, compress, 0);
    let challenge_mmcs = XChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_benchmark(challenge_mmcs);
    let pcs = XMyPcs::new(XDft::default(), val_mmcs, fri_params);
    XMyConfig::new(pcs, XChallenger::new(perm))
}

/// In-circuit FRI verifier params matching `new_benchmark` (blowup-1) with REAL
/// MMCS opening checks, under the KoalaBear D4 W16 Poseidon2 config.
fn x_fri_verifier_params() -> FriVerifierParams {
    let p = FriParameters::<()>::new_benchmark(());
    FriVerifierParams::with_mmcs(
        p.log_blowup,
        p.log_final_poly_len,
        p.commit_proof_of_work_bits,
        p.query_proof_of_work_bits,
        X_POS2_CFG,
    )
}

/// Probe R's two-public-value carrier `[v_in, v_out]` with `v_out == v_in + 1`.
#[derive(Clone, Copy)]
struct CarrierAir {
    rows: usize,
}

impl CarrierAir {
    fn honest_trace(&self, v: XF) -> RowMajorMatrix<XF> {
        let width = 2;
        let mut values = XF::zero_vec(self.rows * width);
        for row in 0..self.rows {
            let idx = row * width;
            values[idx] = v;
            values[idx + 1] = v + XF::ONE;
        }
        RowMajorMatrix::new(values, width)
    }
}

impl BaseAir<XF> for CarrierAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        2
    }
}

impl<AB: AirBuilder<F = XF>> Air<AB> for CarrierAir {
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
    proof: BatchProof<XMyConfig>,
    air: CarrierAir,
    pvs: [Vec<XF>; 1],
    prover_data: ProverData<XMyConfig>,
}

impl Layer {
    fn common(&self) -> &p3_batch_stark::CommonData<XMyConfig> {
        &self.prover_data.common
    }
}

fn prove_layer(config: &XMyConfig, v: XF, rows: usize) -> Layer {
    let air = CarrierAir { rows };
    let trace = air.honest_trace(v);
    let pvs = [vec![v, v + XF::ONE]];
    let instances = vec![StarkInstance {
        air: &air,
        trace: &trace,
        public_values: pvs[0].clone(),
    }];
    let prover_data = ProverData::from_instances(config, &instances);
    let proof = prove_batch(config, &instances, &prover_data);
    verify_batch(config, &air_slice(&air), &proof, &pvs, &prover_data.common)
        .expect("native KoalaBear carrier verify");
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

type Vi =
    BatchStarkVerifierInputsBuilder<XMyConfig, MerkleCapTargets<XF, X_DIGEST_ELEMS>, XInnerFri>;

fn add_carrier_verifier(
    config: &XMyConfig,
    vparams: &FriVerifierParams,
    cb: &mut CircuitBuilder<XChallenge>,
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
    let mmcs_op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, X_WIDTH, X_RATE>(
        config,
        &air_slice(&layer.air),
        cb,
        &vi.proof_targets,
        &vi.air_public_targets,
        vparams,
        &vi.common_data,
        &lookup_gadget,
        X_POS2_CFG,
    )
    .expect("build KoalaBear carrier verifier (real MMCS)");
    (vi, mmcs_op_ids)
}

const MAX_IN_COINS: usize = 8;

struct AggResult {
    build_ms: f64,
    cold_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    rss_mb: f64,
    num_active: usize,
}

/// Build the fan-in 8+1 aggregator recursion circuit in KoalaBear, STARK-prove it.
fn prove_aggregator(inner_rows: usize, num_active: usize) -> AggResult {
    let config = make_x_config();
    let vparams = x_fri_verifier_params();

    let predecessor = prove_layer(&config, XF::from_u32(100), inner_rows);
    let sources: Vec<Layer> = (0..MAX_IN_COINS)
        .map(|i| prove_layer(&config, XF::from_u32(200 + i as u32), inner_rows))
        .collect();

    let t_build = Instant::now();
    let perm = default_koalabear_poseidon2_16();
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<XChallenge, KoalaBearD4Width16>,
        perm,
    );
    cb.enable_recompose::<XF>(generate_recompose_trace::<XF, XChallenge>);

    let (pred_vi, pred_op_ids) = add_carrier_verifier(&config, &vparams, &mut cb, &predecessor);

    let mut source_vis = Vec::with_capacity(MAX_IN_COINS);
    let mut source_op_ids = Vec::with_capacity(MAX_IN_COINS);
    let mut active_inputs = Vec::with_capacity(MAX_IN_COINS);
    for (i, src) in sources.iter().enumerate() {
        let (src_vi, src_ids) = add_carrier_verifier(&config, &vparams, &mut cb, src);
        let v_out = src_vi.air_public_targets[0][1];
        let active = cb.alloc_public_input("active");
        cb.assert_bool(active);
        let expected = cb.alloc_const(XChallenge::from(XF::from_u32(201 + i as u32)), "expected");
        let masked = cb.select(active, expected, v_out);
        cb.connect(v_out, masked);
        source_vis.push(src_vi);
        source_op_ids.push(src_ids);
        active_inputs.push(active);
    }

    // IVC carry: thread predecessor v_out through a select gate (committed work).
    let pred_v_out = pred_vi.air_public_targets[0][1];
    let src0_v_in = source_vis[0].air_public_targets[0][0];
    let carry = cb.select(active_inputs[0], src0_v_in, pred_v_out);
    let _ = carry;

    let circuit = cb.build().expect("KoalaBear aggregator circuit builds");
    let build_ms = t_build.elapsed().as_secs_f64() * 1e3;

    let table_packing = TablePacking::new(1, 8);
    let npo_prep: Vec<Box<dyn NpoPreprocessor<XF>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::default()),
    ];
    let mut air_builders = poseidon2_air_builders::<_, X_D>();
    air_builders.extend(recompose_air_builders(1, false));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, X_D>(
            &circuit,
            &table_packing,
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("airs and degrees for KoalaBear aggregator");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let active_bits: Vec<XChallenge> = (0..MAX_IN_COINS)
        .map(|i| {
            if i < num_active {
                XChallenge::ONE
            } else {
                XChallenge::ZERO
            }
        })
        .collect();

    let (mut pubs, mut privs) =
        pred_vi.pack_values(&predecessor.pvs, &predecessor.proof, predecessor.common());
    for (i, src_vi) in source_vis.iter().enumerate() {
        let (s_pub, s_priv) =
            src_vi.pack_values(&sources[i].pvs, &sources[i].proof, sources[i].common());
        pubs.extend(s_pub);
        privs.extend(s_priv);
        pubs.push(active_bits[i]);
    }

    let run_witness = || {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&pubs).expect("set pub");
        runner.set_private_inputs(&privs).expect("set priv");
        set_mmcs_for(&mut runner, &pred_op_ids, &predecessor);
        for (i, ids) in source_op_ids.iter().enumerate() {
            set_mmcs_for(&mut runner, ids, &sources[i]);
        }
        runner.run().expect("KoalaBear aggregator witness-gen")
    };

    let stark_config = koala_bear();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + stark_config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&stark_config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(koala_bear()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<X_D>(X_POS2_CFG);
    prover.register_recompose_table::<X_D>(false);

    let traces = run_witness();
    let t_cold = Instant::now();
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("STARK-prove KoalaBear aggregator");
    let cold_ms = t_cold.elapsed().as_secs_f64() * 1e3;
    prover
        .verify_all_tables(&proof)
        .expect("verify KoalaBear aggregator proof");

    let traces_warm = run_witness();
    let _ = prover
        .prove_all_tables(&traces_warm, &circuit_prover_data)
        .expect("warmup prove");
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

    AggResult {
        build_ms,
        cold_ms,
        p50_ms: quantile(&times, 0.50),
        p90_ms: quantile(&times, 0.90),
        rss_mb: peak_rss_mb(),
        num_active,
    }
}

fn set_mmcs_for(
    runner: &mut p3_circuit::CircuitRunner<'_, XChallenge>,
    op_ids: &[NonPrimitiveOpId],
    layer: &Layer,
) {
    set_fri_mmcs_private_data::<
        XF,
        XChallenge,
        XChallengeMmcs,
        XMyMmcs,
        XMyHash,
        XMyCompress,
        X_DIGEST_ELEMS,
    >(runner, op_ids, &layer.proof.opening_proof, X_POS2_CFG)
    .expect("set MMCS private data");
}

// ==========================================================================
// Shared helpers.
// ==========================================================================

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

/// Honest comparison band: a ratio inside [1/MARGIN, MARGIN] of 1.0 is a WASH
/// (within measurement noise + proxy error) and only a marginal tiebreaker.
const MARGIN_BAND: f64 = 1.15;

fn ratio_verdict(koala_ms: f64, baby_ms: f64) -> String {
    let ratio = koala_ms / baby_ms; // <1 => KoalaBear faster.
    if ratio < 1.0 / MARGIN_BAND {
        format!(
            "KoalaBear FASTER by {:.2}x (ratio {:.3}) — beyond the {:.0}% noise band",
            baby_ms / koala_ms,
            ratio,
            (MARGIN_BAND - 1.0) * 100.0
        )
    } else if ratio > MARGIN_BAND {
        format!(
            "KoalaBear SLOWER by {:.2}x (ratio {:.3}) — beyond the {:.0}% noise band",
            ratio,
            ratio,
            (MARGIN_BAND - 1.0) * 100.0
        )
    } else {
        format!(
            "WASH (ratio {:.3}, within +/-{:.0}%) — marginal tiebreaker, NOT a decider",
            ratio,
            (MARGIN_BAND - 1.0) * 100.0
        )
    }
}

#[test]
fn probe_ad_koalabear() {
    let t_packing = core::any::type_name::<<TVal as Field>::Packing>();
    let t_scalar = core::any::type_name::<TVal>();
    let t_packing_active = t_packing != t_scalar && !t_packing.ends_with("KoalaBear");
    let x_packing = core::any::type_name::<<XF as Field>::Packing>();
    let threads = rayon::current_num_threads();

    println!("\n========== Probe AD: KoalaBear vs BabyBear (31-bit field choice) ==========");
    println!("KoalaBear : p = 2^31 - 2^24 + 1 | 2-adicity 24 | native Poseidon2 S-box DEGREE 3");
    println!("BabyBear  : p = 2^31 - 2^27 + 1 | 2-adicity 27 | native Poseidon2 S-box DEGREE 7");
    println!("S-box/round tradeoff:");
    println!(
        "  KoalaBear: x^3, SBOX_REGISTERS=0, {T_HALF_FULL_ROUNDS}+{T_HALF_FULL_ROUNDS} full + {T_PARTIAL_ROUNDS} partial rounds (narrower hash trace)"
    );
    println!(
        "  BabyBear : x^7, SBOX_REGISTERS=1, 4+4 full + 13 partial rounds (extra S-box column)"
    );
    println!("Both are each field's OWN native cryptographic Poseidon2 params (128-bit target):");
    println!(
        "  production-sound on both sides — this is a COST comparison, not a security tradeoff."
    );
    println!("KoalaBear::Packing (T-analog) : {t_packing}");
    println!("  -> SIMD packing active: {t_packing_active} (vs scalar {t_scalar})");
    println!("KoalaBear::Packing (X-analog) : {x_packing}");
    println!("rayon threads                 : {threads}");
    println!(
        "BabyBear baselines: Probe T {BABYBEAR_PROBE_T_MS:.0} ms transition | Probe X {BABYBEAR_PROBE_X_MS:.0} ms aggregation"
    );

    // ===================== PART 1: single transition =====================
    println!("\n------------------------------------------------------------------------------");
    println!("PART 1 — single state-transition (Probe-T analog) in KoalaBear");
    println!("config: VectorizedPoseidon2Air<.., SBOX_DEGREE=3, SBOX_REGISTERS=0, VECTOR_LEN=8>");
    println!("  | MerkleTreeHidingMmcs(Keccak) | HidingFriPcs num_random_codewords=4 (TRUE ZK)");
    println!("  | FRI new_benchmark_zk (blowup=2, 100q, 16-bit PoW) | + degree-3 arith table 2^13");

    let (t_config, t_log_blowup) = build_t_config();
    let hash_air = Arc::new(build_hash_air());
    assert_eq!(t_log_blowup, 2, "new_benchmark_zk must be blowup-2");

    let hash_perms_capacity = next_pow2(REAL_HASH_PERMS.div_ceil(T_VECTOR_LEN)) * T_VECTOR_LEN;
    let hash_trace = hash_air.generate_vectorized_trace_rows(hash_perms_capacity, t_log_blowup);
    let hash_rows = hash_trace.height();
    let arith = arith_trace(T_ARITH_HEIGHT);
    println!(
        "hash table : ~{REAL_HASH_PERMS} real perms -> {hash_perms_capacity} capacity = {hash_rows} rows (degree-3)"
    );
    println!(
        "arith table: {T_ARITH_WIDTH} cols x {T_CONSTRAINTS_PER_ROW} degree-3 constraints/row x 2^{} rows",
        log2(T_ARITH_HEIGHT)
    );

    let transition = run_single_transition(&t_config, hash_air.clone(), &hash_trace, &arith);
    println!(
        "KoalaBear transition: build={:.1}ms cold={:.1}ms warm_p50={:.1}ms p90={:.1}ms rss={:.0}MB",
        transition.build_ms,
        transition.cold_ms,
        transition.p50_ms,
        transition.p90_ms,
        transition.rss_mb
    );
    println!(
        "  vs BabyBear Probe T {BABYBEAR_PROBE_T_MS:.0} ms : {}",
        ratio_verdict(transition.p50_ms, BABYBEAR_PROBE_T_MS)
    );

    // ===================== PART 2: 8+1 aggregation =======================
    println!("\n------------------------------------------------------------------------------");
    println!("PART 2 — 8+1 aggregation recursion (Probe-X analog) in KoalaBear");
    println!("config: 1 predecessor + 8 source carriers, verify_batch_circuit (real with_mmcs),");
    println!("  active masks + IVC carry, prove_all_tables (low-level), KOALA_BEAR_D4_W16");
    println!("  (in-circuit Poseidon2 verifier table: degree-3, 0 registers, 20 partial rounds),");
    println!("  inner+verifier FRI = new_benchmark (blowup-1, non-zk production headline).");

    let inner_rows = 1usize << 10;
    let num_active = MAX_IN_COINS; // worst case: all 8 source slots active.
    println!(
        "inner carrier rows: {inner_rows} (1<<{}) | active source slots: {num_active}/{MAX_IN_COINS}",
        inner_rows.trailing_zeros()
    );

    let agg = prove_aggregator(inner_rows, num_active);
    println!(
        "KoalaBear aggregation: build={:.1}ms cold={:.1}ms warm_p50={:.1}ms p90={:.1}ms rss={:.0}MB ({} active)",
        agg.build_ms, agg.cold_ms, agg.p50_ms, agg.p90_ms, agg.rss_mb, agg.num_active
    );
    println!(
        "  vs BabyBear Probe X {BABYBEAR_PROBE_X_MS:.0} ms : {}",
        ratio_verdict(agg.p50_ms, BABYBEAR_PROBE_X_MS)
    );

    // ===================== VERDICT =======================================
    let t_ratio = transition.p50_ms / BABYBEAR_PROBE_T_MS;
    let x_ratio = agg.p50_ms / BABYBEAR_PROBE_X_MS;
    println!("\n============================= Probe AD VERDICT ===============================");
    println!(
        "{:<26} {:>12} {:>12} {:>10}",
        "operation", "KoalaBear", "BabyBear", "ratio K/B"
    );
    println!(
        "{:<26} {:>10.1}ms {:>10.1}ms {:>10.3}",
        "single transition (T)", transition.p50_ms, BABYBEAR_PROBE_T_MS, t_ratio
    );
    println!(
        "{:<26} {:>10.1}ms {:>10.1}ms {:>10.3}",
        "8+1 aggregation (X)", agg.p50_ms, BABYBEAR_PROBE_X_MS, x_ratio
    );

    println!("\nIs KoalaBear meaningfully faster than BabyBear for zkCoins' workload?");
    let t_meaningful = !(1.0 / MARGIN_BAND..=MARGIN_BAND).contains(&t_ratio);
    let x_meaningful = !(1.0 / MARGIN_BAND..=MARGIN_BAND).contains(&x_ratio);
    println!(
        "  single transition : {}",
        ratio_verdict(transition.p50_ms, BABYBEAR_PROBE_T_MS)
    );
    println!(
        "  8+1 aggregation   : {}",
        ratio_verdict(agg.p50_ms, BABYBEAR_PROBE_X_MS)
    );
    println!("\nDoes KoalaBear's degree-3 native S-box help the hash-heavy recursion?");
    if x_ratio < 1.0 / MARGIN_BAND {
        println!(
            "  YES — the aggregation (Poseidon-dominated) is {:.2}x faster in KoalaBear. The",
            1.0 / x_ratio
        );
        println!("  degree-3 / 0-register in-circuit Poseidon2 verifier table is the lever: the");
        println!("  recursion AIR that dominates the prove is structurally narrower per row.");
    } else if x_ratio > MARGIN_BAND {
        println!("  NO net help — KoalaBear's aggregation is SLOWER here. The +7 partial rounds");
        println!("  (20 vs 13) and field-specific MMCS/FFT costs outweigh the S-box saving.");
    } else {
        println!("  MARGINALLY — within the noise band. The degree-3 S-box's narrower hash table");
        println!("  is real structurally, but the +7 partial rounds (20 vs 13) largely offset it,");
        println!("  so the net per-op prove cost is a wash within measurement error.");
    }

    // Weight the field decision by the WORKLOAD: at production fan-in the 8+1
    // aggregation prove dwarfs the single transition (Probe X showed the
    // recursion prove is ~12x the transition and dominates the full /api/send),
    // so the aggregation ratio carries the decision. A faster transition does
    // NOT redeem a much slower aggregation — the dominant op rules.
    println!("\n=============================== BOTTOM LINE ==================================");
    println!("Workload weighting: the 8+1 AGGREGATION dominates the full populated send (Probe X:");
    println!(
        "  recursion prove ~12x the single transition), so its K/B ratio drives the decision."
    );
    if x_meaningful && x_ratio > 1.0 {
        // Dominant op is meaningfully SLOWER under KoalaBear: this is decisive.
        println!(
            "VERDICT: KoalaBear is NOT faster for zkCoins' workload — it is {x_ratio:.2}x SLOWER on the"
        );
        println!(
            "  DOMINANT operation (8+1 aggregation: {:.0} ms vs {BABYBEAR_PROBE_X_MS:.0} ms). The single",
            agg.p50_ms
        );
        if t_ratio < 1.0 {
            println!(
                "  transition is {:.2}x faster in KoalaBear, but the transition is a small slice of the",
                1.0 / t_ratio
            );
            println!("  real send, so that local win does NOT redeem the aggregation regression.");
        }
        println!(
            "  Mechanism: KoalaBear's degree-3 native S-box DOES give a narrower leaf hash table"
        );
        println!(
            "  (the transition win), but the recursion's in-circuit Poseidon2 verifier runs 20"
        );
        println!(
            "  partial rounds vs BabyBear's 13 — and the recursion AIR's per-perm ROW count, not"
        );
        println!(
            "  the S-box register width, dominates the aggregation prove. The +7 rounds, plus"
        );
        println!(
            "  KoalaBear-specific MMCS/FFT costs at lower 2-adicity, outweigh the S-box saving."
        );
        println!("  RECOMMENDATION: STAY ON BabyBear. It is faster on the operation that actually");
        println!("  gates the /api/send budget, AND it has higher 2-adicity (27 vs 24) for NTT");
        println!(
            "  headroom, AND every prior probe (T/V/W/X) is already BabyBear (zero re-validation)."
        );
        println!("  KoalaBear is not the field for this workload.");
    } else if !t_meaningful && !x_meaningful {
        println!(
            "VERDICT: KoalaBear is NOT meaningfully faster than BabyBear for zkCoins' workload."
        );
        println!(
            "  Both load-bearing operations land within +/-{:.0}% of BabyBear — a WASH, as the",
            (MARGIN_BAND - 1.0) * 100.0
        );
        println!(
            "  theory predicts for two 31-bit Montgomery fields with near-identical field-mul"
        );
        println!("  speed. The degree-3-S-box / +7-partial-rounds tradeoff roughly cancels.");
        println!(
            "  RECOMMENDATION: the field choice is a MARGINAL TIEBREAKER, not a perf decider."
        );
        println!(
            "  Prefer BabyBear on NON-perf grounds: higher 2-adicity (27 vs 24) gives more NTT"
        );
        println!(
            "  headroom for large traces, and every prior probe (T/V/W/X) is already BabyBear,"
        );
        println!(
            "  so the whole audit's numbers carry over with zero re-validation. KoalaBear is a"
        );
        println!("  sound alternative with no meaningful speed penalty, not a reason to switch.");
    } else if x_meaningful && x_ratio < 1.0 {
        // Dominant op meaningfully FASTER under KoalaBear: KoalaBear wins.
        println!(
            "VERDICT: KoalaBear IS faster for zkCoins' workload — {:.2}x faster on the DOMINANT 8+1",
            1.0 / x_ratio
        );
        println!(
            "  aggregation ({:.0} ms vs {BABYBEAR_PROBE_X_MS:.0} ms), the op that gates /api/send.",
            agg.p50_ms
        );
        println!("  The degree-3 / 0-register in-circuit Poseidon2 verifier table is the lever.");
        println!(
            "  RECOMMENDATION: KoalaBear is the faster field here; weigh that against BabyBear's"
        );
        println!(
            "  higher 2-adicity + the cost of re-validating every prior probe under KoalaBear."
        );
    } else {
        // Aggregation a wash, transition meaningful (either direction).
        println!(
            "VERDICT: the DOMINANT 8+1 aggregation is a WASH (K/B={x_ratio:.3}); only the smaller"
        );
        println!(
            "  single transition shows a {} (K/B={t_ratio:.3}).",
            if t_ratio < 1.0 {
                "KoalaBear edge"
            } else {
                "KoalaBear penalty"
            }
        );
        println!(
            "  RECOMMENDATION: a marginal tiebreaker at most. Prefer BabyBear (higher 2-adicity,"
        );
        println!(
            "  already-validated across every probe); KoalaBear offers no decisive workload win."
        );
    }
    println!(
        "Soundness: both fields use their OWN native cryptographic Poseidon2 (KoalaBear x^3 /"
    );
    println!("  20 partial rounds, BabyBear x^7 / 13 partial rounds), each designed to 128-bit");
    println!("  security. No soundness difference to weigh — both are production-intended params.");
    println!("==============================================================================\n");

    // Hard asserts: both operations proved + verified above (panics on failure).
    #[cfg(target_arch = "aarch64")]
    {
        assert!(
            t_packing_active,
            "expected NEON-packed KoalaBear in T-analog, got {t_packing}"
        );
        assert!(
            x_packing.contains("Neon") || x_packing != core::any::type_name::<XF>(),
            "expected NEON-packed KoalaBear in X-analog, got {x_packing}"
        );
    }
}
