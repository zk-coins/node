//! Probe V — explicit **cryptographic degree-7** BabyBear Poseidon2 bench.
//!
//! # Why this probe exists
//!
//! Probe S (`probe_s_fair_bench.rs`) benchmarked BabyBear Poseidon2 prover
//! speed with the **degree-3** S-box (`x^3`) — the same low-degree S-box
//! Plonky3's own non-vectorized AIR end-to-end tests use. It did so because at
//! the pinned Plonky3 rev the *non-vectorized* `Poseidon2Air` with the
//! cryptographic degree-7 S-box (`x^7`) fails verification with
//! `OodEvaluationMismatch` under the plain `TwoAdicFriPcs` + Poseidon2-MMCS +
//! `DuplexChallenger` path. Probe S's review then *estimated* — from quotient
//! arithmetic alone — that degree-7 would inflate total prove time by roughly
//! **1.5–2.5× (up to ~3×)** over degree-3, but never measured it.
//!
//! This probe measures the real number. It runs the **WORKING upstream
//! degree-7 recipe** — the one in
//! `poseidon2-air/examples/prove_poseidon2_baby_bear_keccak_zk.rs`, which DOES
//! verify at degree-7 — and reports degree-7 p50/p90/RSS at the same trace
//! heights Probe S used, plus the real degree-7 ÷ degree-3 ratio.
//!
//! ## The working degree-7 config (exact recipe — Probe T reuses this)
//!
//! The non-vectorized + plain-`TwoAdicFriPcs` path does NOT verify at
//! degree-7 (confirmed by Probe S's bisection). The path that DOES:
//!
//! * **AIR.** `VectorizedPoseidon2Air<.., SBOX_DEGREE = 7, SBOX_REGISTERS = 1,
//!   .., VECTOR_LEN = 8>` — the *vectorized* AIR (one trace row encodes
//!   `VECTOR_LEN` permutations). `SBOX_REGISTERS = 1` adds one witness column
//!   per S-box so the per-constraint degree stays bounded even at `x^7`; this
//!   is what makes the OOD check pass where the non-vectorized degree-7 AIR
//!   fails. Round counts are the *cryptographic* BabyBear constants
//!   (`BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16` = 13, not the test AIR's 20).
//! * **MMCS.** `MerkleTreeHidingMmcs<[Val; KECCAK_VECTOR_LEN], [u64; …], …>`
//!   over the **Keccak** byte-hash sponge (`PaddingFreeSponge<KeccakF, 25, 17,
//!   4>` + `CompressionFunctionFromHasher`), with a `SmallRng` masking source
//!   — i.e. the leaves are *hidden* by random rows. (`MerkleTreeHidingMmcs` is
//!   the hiding analogue of the plain `MerkleTreeMmcs`.)
//! * **PCS.** `HidingFriPcs<.., SmallRng>` with `num_random_codewords = 4` —
//!   the **true zero-knowledge** FRI PCS (random masking codewords appended
//!   to the committed polynomials). This is real ZK, not the blowup-2 proxy.
//! * **Challenger.** `SerializingChallenger32<Val, HashChallenger<u8,
//!   Keccak256Hash, 32>>` — the byte-oriented challenger that pairs with the
//!   Keccak MMCS (NOT the `DuplexChallenger` Probe S used).
//! * **FRI.** `FriParameters::new_benchmark_zk` (log_blowup = 2, 100 queries,
//!   16-bit PoW) — the production zk FRI preset.
//!
//! Because this config is *itself* the upstream hiding/ZK example, Probe V's
//! degree-7 numbers are also a degree-7 **HidingFriPcs** point — the real ZK
//! cost. Probe W (`probe_w_hiding_fri.rs`) isolates the hiding-vs-proxy delta.
//!
//! ## Comparability to Probe S
//!
//! Probe S's headline rows used a **different** MMCS/PCS (Poseidon2 Merkle
//! MMCS, plain `TwoAdicFriPcs`) than this probe's Keccak/Hiding path, so a
//! naive degree-7 ÷ degree-3 ratio would conflate two independent variables
//! (S-box degree AND hash family AND hiding). To compare like-for-like, this
//! probe ALSO runs a **degree-3** point on the *identical* Keccak +
//! `HidingFriPcs` + `new_benchmark_zk` config (same AIR type, same MMCS, same
//! PCS, same FRI — only `SBOX_DEGREE` differs). That degree-3-on-this-path
//! number is the honest denominator for the degree-7 ÷ degree-3 ratio. We
//! also print Probe S's degree-3 `new_benchmark_zk` (blowup-2 proxy) p50 for
//! context, clearly labelled as a *different-MMCS* reference, not the ratio
//! denominator.
//!
//! ## Sizing
//!
//! The vectorized AIR packs `VECTOR_LEN = 8` permutations per trace row, so
//! `generate_vectorized_trace_rows(num_perms, log_blowup)` yields a trace of
//! height `num_perms / VECTOR_LEN`. To match Probe S's trace heights we size
//! `num_perms = height * VECTOR_LEN`:
//!
//! * height 2^13 (Probe S hash-matched lower bound) -> num_perms = 2^16
//! * height 2^15 (Probe S middle)                   -> num_perms = 2^18
//! * height 2^16 (Probe S hash-saturated upper)     -> num_perms = 2^19
//!
//! Both `num_perms` and the realized trace height are reported.
//!
//! ## Verdict policy
//!
//! PASSES on successful measurement + proof verification (every degree-7 and
//! degree-3 proof must verify). The speed ratio and the Plonky2 (4.35 s)
//! comparison are **reported findings**, not asserts — a slow result is a
//! datum to investigate, not to hide. The one hard assert beyond verification
//! is that the degree-7 config actually verifies: if it did not, that would be
//! a precise blocker for Probe T and the test would fail loudly.

use std::time::Instant;

use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    BABYBEAR_S_BOX_DEGREE, BabyBear, GenericPoseidon2LinearLayersBabyBear,
};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2_air::{RoundConstants, VectorizedPoseidon2Air};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

// --- Shared AIR / round-count shape (degree-independent) --------------------
const WIDTH: usize = 16;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS; // 4
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16; // 13 (cryptographic)
/// Permutations packed into one trace row by the vectorized AIR.
const VECTOR_LEN: usize = 1 << 3; // 8

// S-box (DEGREE, REGISTERS) pairs. The upstream `generate_sbox` only accepts
// the *optimal* register count for each degree: degree-7 needs one extra
// witness column (`SBOX_REGISTERS = 7,1`), degree-3 needs none (`3,0`). Using
// each degree's optimal register count is the honest like-for-like comparison
// (both AIRs are built the canonical way for their degree); forcing `(3,1)`
// panics with "Unexpected (DEGREE, REGISTERS)".
/// Cryptographic S-box degree for BabyBear Poseidon2 (= 7), optimal regs = 1.
const SBOX_DEGREE_CRYPTO: u64 = BABYBEAR_S_BOX_DEGREE;
const SBOX_REGISTERS_CRYPTO: usize = 1;
/// Low-degree S-box for the like-for-like denominator (same path, degree 3,
/// optimal regs = 0).
const SBOX_DEGREE_TEST: u64 = 3;
const SBOX_REGISTERS_TEST: usize = 0;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;

// Keccak byte-hash MMCS, exactly as the upstream zk example. The MMCS packing
// width is `p3_keccak::VECTOR_LEN`, which is arch-gated (2 under NEON with
// `-Ctarget-cpu=native`, 1 on the scalar fallback) — using the constant keeps
// this correct on every target.
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

/// Vectorized degree-7 (cryptographic) AIR.
type Air7 = VectorizedPoseidon2Air<
    Val,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE_CRYPTO,
    SBOX_REGISTERS_CRYPTO,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
    VECTOR_LEN,
>;
/// Vectorized degree-3 AIR on the IDENTICAL Keccak + Hiding + FRI path — the
/// honest like-for-like denominator for the degree-7 ÷ degree-3 ratio.
type Air3 = VectorizedPoseidon2Air<
    Val,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE_TEST,
    SBOX_REGISTERS_TEST,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
    VECTOR_LEN,
>;

/// Plonky2 measured baseline (M5 Max) for the real zkCoins state-transition.
const PLONKY2_P50_MS: f64 = 4350.0;
const PLONKY2_RSS_MB: f64 = 3900.0;

/// Probe S degree-3 reference p50s (ms, M5 Max), Poseidon2-MMCS plain-PCS
/// path — a *different-MMCS* reference, printed for context only, NOT the
/// ratio denominator (the in-probe degree-3 Keccak/Hiding point is).
/// Indexed by trace height: 2^13, 2^15, 2^16, all `new_benchmark_zk` (zk
/// proxy, blowup=2). Set to `None` until Probe S's zk-proxy numbers are wired
/// by the orchestrator; the report degrades gracefully when absent.
const PROBE_S_DEG3_ZK_PROXY_MS: [Option<f64>; 3] = [None, None, None];

/// Build the shared Keccak/Hiding/FRI config (setup — excluded from timing).
/// Returns `(config, log_blowup)`. The AIR is built separately per degree.
fn build_config() -> (MyConfig, usize) {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);

    // Distinct deterministic seeds for the masking RNGs (MMCS / PCS) so the
    // hiding rows are reproducible. WARNING mirrors upstream: SmallRng is for
    // benchmarking only, never production hiding.
    let val_mmcs = ValMmcs::new(field_hash, compress, 0, SmallRng::seed_from_u64(2));
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters::new_benchmark_zk(challenge_mmcs);
    let log_blowup = fri_params.log_blowup;

    let dft = Dft::default();
    let pcs = Pcs::new(dft, val_mmcs, fri_params, 4, SmallRng::seed_from_u64(3));

    let challenger = Challenger::from_hasher(vec![], byte_hash);
    let config = MyConfig::new(pcs, challenger);
    (config, log_blowup)
}

/// Peak resident-set size of this process, in MB. `ru_maxrss` is **bytes** on
/// macOS (KB on Linux); this probe runs on macOS. High-water mark over the
/// whole process lifetime.
fn peak_rss_mb() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(rc, 0, "getrusage failed");
    let max_rss_bytes = usage.ru_maxrss as f64;
    if cfg!(target_os = "macos") {
        max_rss_bytes / (1u64 << 20) as f64
    } else {
        (max_rss_bytes * 1024.0) / (1u64 << 20) as f64
    }
}

struct RunResult {
    degree: u64,
    num_perms: usize,
    rows: usize,
    trace_gen_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    min_ms: f64,
    max_ms: f64,
    rss_mb: f64,
}

/// p-quantile (nearest-rank) of an already-sorted slice.
fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

/// Time `prove()` for one degree at one size. Protocol mirrors Probe S:
/// 1 untimed warmup prove (+verify), then 5 timed proves; report p50/p90.
/// Trace generation is timed separately. The last proof is verified as a hard
/// correctness gate — a degree-7 verification failure aborts the test.
fn run_point<Air>(
    config: &MyConfig,
    air: &Air,
    degree: u64,
    num_perms: usize,
    log_blowup: usize,
) -> RunResult
where
    Air: p3_air::Air<p3_uni_stark::SymbolicAirBuilder<Val>>
        + for<'a> p3_air::Air<p3_uni_stark::ProverConstraintFolder<'a, MyConfig>>
        + for<'a> p3_air::Air<p3_uni_stark::VerifierConstraintFolder<'a, MyConfig>>
        // In debug builds `prove` additionally requires the
        // `DebugConstraintBuilder` bound (it runs an in-prover constraint
        // sanity check); release builds drop it. `cargo clippy` compiles in
        // debug, so the bound must be present. Listing it unconditionally is
        // harmless in release — these AIRs always implement it.
        + for<'a> p3_air::Air<p3_air::DebugConstraintBuilder<'a, Val>>,
    Air: VectorizedTrace,
{
    const TIMED_RUNS: usize = 5;

    let t0 = Instant::now();
    let trace = air.gen_vectorized(num_perms, log_blowup);
    let trace_gen_ms = t0.elapsed().as_secs_f64() * 1e3;
    let rows = trace.height();

    // Warmup (untimed).
    {
        let proof = prove(config, air, trace.clone(), &[]);
        verify(config, air, &proof, &[]).expect("degree-7/3 warmup proof must verify");
    }

    let mut times_ms = Vec::with_capacity(TIMED_RUNS);
    let mut last_proof = None;
    for _ in 0..TIMED_RUNS {
        let trace_run = trace.clone();
        let t = Instant::now();
        let proof = prove(config, air, trace_run, &[]);
        times_ms.push(t.elapsed().as_secs_f64() * 1e3);
        last_proof = Some(proof);
    }

    let proof = last_proof.expect("at least one timed run");
    verify(config, air, &proof, &[]).expect("Probe V proof must verify");

    times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50_ms = quantile(&times_ms, 0.50);
    let p90_ms = quantile(&times_ms, 0.90);
    let min_ms = times_ms[0];
    let max_ms = times_ms[times_ms.len() - 1];

    RunResult {
        degree,
        num_perms,
        rows,
        trace_gen_ms,
        p50_ms,
        p90_ms,
        min_ms,
        max_ms,
        rss_mb: peak_rss_mb(),
    }
}

/// Tiny adapter so `run_point` can call `generate_vectorized_trace_rows` over
/// either degree's concrete AIR type without a generic-method bound salad.
trait VectorizedTrace {
    fn gen_vectorized(
        &self,
        num_perms: usize,
        log_blowup: usize,
    ) -> p3_matrix::dense::RowMajorMatrix<Val>;
}
impl VectorizedTrace for Air7 {
    fn gen_vectorized(
        &self,
        num_perms: usize,
        log_blowup: usize,
    ) -> p3_matrix::dense::RowMajorMatrix<Val> {
        self.generate_vectorized_trace_rows(num_perms, log_blowup)
    }
}
impl VectorizedTrace for Air3 {
    fn gen_vectorized(
        &self,
        num_perms: usize,
        log_blowup: usize,
    ) -> p3_matrix::dense::RowMajorMatrix<Val> {
        self.generate_vectorized_trace_rows(num_perms, log_blowup)
    }
}

#[test]
fn probe_v_degree7_bench() {
    let packing_type = core::any::type_name::<<Val as Field>::Packing>();
    let scalar_type = core::any::type_name::<Val>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    println!("\n================= Probe V: degree-7 BabyBear Poseidon2 bench ==================");
    println!("config recipe (Probe T reuses verbatim):");
    println!("  AIR  : VectorizedPoseidon2Air<.., SBOX_DEGREE=7, SBOX_REGISTERS=1, VECTOR_LEN=8>");
    println!("  MMCS : MerkleTreeHidingMmcs<[Val; p3_keccak::VECTOR_LEN], …> (Keccak sponge)");
    println!("  PCS  : HidingFriPcs<.., SmallRng>  num_random_codewords=4  (TRUE zero-knowledge)");
    println!("  CHAL : SerializingChallenger32<Val, HashChallenger<u8, Keccak256Hash, 32>>");
    println!("  FRI  : FriParameters::new_benchmark_zk (log_blowup=2, 100 queries, 16-bit PoW)");
    println!("BabyBear::Packing: {packing_type}");
    println!("  -> SIMD packing active: {packing_active} (vs scalar {scalar_type})");
    println!(
        "p3_keccak::VECTOR_LEN (MMCS pack): {}",
        p3_keccak::VECTOR_LEN
    );
    println!("rayon threads    : {threads}");
    println!(
        "Plonky2 baseline : {PLONKY2_P50_MS:.0} ms p50 / {PLONKY2_RSS_MB:.0} MB RSS (real circuit, M5 Max)"
    );
    println!("------------------------------------------------------------------------------");

    // (trace_height, num_perms = height * VECTOR_LEN, note).
    let sizes: [(usize, usize, &str); 3] = [
        (
            1 << 13,
            (1 << 13) * VECTOR_LEN,
            "2^13 rows (Probe S hash-matched lower bound)",
        ),
        (
            1 << 15,
            (1 << 15) * VECTOR_LEN,
            "2^15 rows (Probe S middle)",
        ),
        (
            1 << 16,
            (1 << 16) * VECTOR_LEN,
            "2^16 rows (Probe S hash-saturated upper)",
        ),
    ];

    let (config, log_blowup) = build_config();
    assert_eq!(log_blowup, 2, "new_benchmark_zk must be blowup-2");

    // Build both AIRs once (deterministic constants; same seed for both so the
    // only difference between the degree-3 and degree-7 runs is SBOX_DEGREE).
    let air7: Air7 = {
        let mut rng = SmallRng::seed_from_u64(1);
        VectorizedPoseidon2Air::new(RoundConstants::from_rng(&mut rng))
    };
    let air3: Air3 = {
        let mut rng = SmallRng::seed_from_u64(1);
        VectorizedPoseidon2Air::new(RoundConstants::from_rng(&mut rng))
    };

    let mut deg7 = Vec::new();
    let mut deg3 = Vec::new();
    for &(height, num_perms, note) in &sizes {
        println!("running degree-7: target_height={height} num_perms={num_perms} [{note}]");
        let r7 = run_point(&config, &air7, 7, num_perms, log_blowup);
        println!(
            "  deg7 rows={:>6} trace_gen={:>8.1}ms  p50={:>8.1}ms p90={:>8.1}ms (min {:>8.1}/max {:>8.1})  rss={:>7.1}MB",
            r7.rows, r7.trace_gen_ms, r7.p50_ms, r7.p90_ms, r7.min_ms, r7.max_ms, r7.rss_mb
        );
        deg7.push(r7);

        println!("running degree-3 (same path, ratio denominator): num_perms={num_perms}");
        let r3 = run_point(&config, &air3, 3, num_perms, log_blowup);
        println!(
            "  deg3 rows={:>6} trace_gen={:>8.1}ms  p50={:>8.1}ms p90={:>8.1}ms (min {:>8.1}/max {:>8.1})  rss={:>7.1}MB",
            r3.rows, r3.trace_gen_ms, r3.p50_ms, r3.p90_ms, r3.min_ms, r3.max_ms, r3.rss_mb
        );
        deg3.push(r3);
    }

    // --- Result table -------------------------------------------------------
    println!("\n========================= Probe V results (warm, p50/p90) ====================");
    println!(
        "{:<6} {:<8} {:<10} {:>10} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "deg", "rows", "num_perms", "tracegen", "p50_ms", "p90_ms", "min_ms", "max_ms", "rss_MB"
    );
    let print_row = |r: &RunResult| {
        println!(
            "{:<6} {:<8} {:<10} {:>10.1} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>9.1}",
            r.degree,
            r.rows,
            r.num_perms,
            r.trace_gen_ms,
            r.p50_ms,
            r.p90_ms,
            r.min_ms,
            r.max_ms,
            r.rss_mb
        );
    };
    for (r7, r3) in deg7.iter().zip(deg3.iter()) {
        print_row(r7);
        print_row(r3);
    }

    // --- degree-7 ÷ degree-3 ratio (SAME Keccak+Hiding+FRI path) ------------
    println!("\n=========== degree-7 ÷ degree-3 ratio (identical MMCS+PCS+FRI) ===============");
    println!("Probe S review estimated ~1.5-2.5x (up to ~3x) from quotient arithmetic. Measured:");
    for (i, (r7, r3)) in deg7.iter().zip(deg3.iter()).enumerate() {
        let ratio = r7.p50_ms / r3.p50_ms;
        let ref_note = match PROBE_S_DEG3_ZK_PROXY_MS[i] {
            Some(ms) => format!(" | Probe-S deg3 zk-proxy (diff MMCS) ref: {ms:.1}ms"),
            None => String::new(),
        };
        println!(
            "rows={:>6}  deg7 p50={:>8.1}ms / deg3 p50={:>8.1}ms = {:.2}x{}",
            r7.rows, r7.p50_ms, r3.p50_ms, ratio, ref_note
        );
    }

    // --- vs Plonky2 at degree-7 --------------------------------------------
    println!("\n===================== degree-7 vs Plonky2 (4.35 s p50) =======================");
    for r7 in &deg7 {
        let speedup = PLONKY2_P50_MS / r7.p50_ms;
        let verdict = if r7.p50_ms < PLONKY2_P50_MS {
            "FASTER"
        } else {
            "NOT FASTER"
        };
        println!(
            "deg7 rows={:>6}  p50={:>8.1}ms  {:>10} ({:.2}x speed vs Plonky2)",
            r7.rows, r7.p50_ms, verdict, speedup
        );
    }
    println!("==============================================================================\n");

    assert_eq!(deg7.len(), 3, "must have 3 degree-7 points");
    assert_eq!(deg3.len(), 3, "must have 3 degree-3 points");
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got scalar packing {packing_type}"
    );
}
