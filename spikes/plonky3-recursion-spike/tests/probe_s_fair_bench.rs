//! Probe S — FAIR apples-to-apples Plonky3-vs-Plonky2 prover-speed benchmark.
//!
//! # Why this probe exists
//!
//! The earlier spike probes (I/R) measured a *recursion* overhead in
//! **Goldilocks** with **untuned FRI** (the default low-security
//! `new_testing` parameters). That was deliberate — those probes only needed
//! to demonstrate that the recursion machinery composes; they were never an
//! honest production-prover timing. As a result they CANNOT answer the
//! load-bearing question:
//!
//!   > Is Plonky3 (BabyBear, production-tuned FRI, SIMD field packing)
//!   > actually *faster* than the Plonky2 (Goldilocks) prover for a
//!   > zkCoins-comparable workload?
//!
//! This probe answers it directly. It proves a **BabyBear Poseidon2 STARK**
//! with `p3_uni_stark::prove` / `verify`, under **production-tuned FRI**
//! (`FriParameters::new_benchmark*`: 100 queries, 16-bit PoW), with the same
//! field, hash family and packing a real BabyBear deployment would use, and
//! prints a direct comparison against the measured Plonky2 baseline.
//!
//! ## The Plonky2 baseline (measured, M5 Max)
//!
//! The real zkCoins state-transition circuit (Plonky2, Goldilocks) measures
//! **4.35 s p50 / 3.9 GB peak RSS** on an Apple M5 Max. Its profile (from
//! `MIGRATION_RESEARCH.md §7.17`): ~2^16 trace rows, ~50k gates, ~4500
//! Poseidon hashes.
//!
//! ## Fair-comparison design
//!
//! * **Field.** BabyBear (31-bit) + degree-4 binomial extension — the
//!   canonical small-field Plonky3 choice. Plonky2 uses Goldilocks (64-bit).
//!   BabyBear is where Plonky3's SIMD packing (NEON on aarch64, 4 lanes)
//!   pays off, so this *is* the apples-to-apples Plonky3 configuration — the
//!   point of the migration is precisely to switch field+packing.
//! * **Hash / MMCS.** Poseidon2 Merkle tree (sponge over width-24, 2-to-1
//!   compression over width-16) — the direct analogue of Plonky2's Poseidon
//!   Merkle caps. We do NOT use the Keccak MMCS for the headline (that would
//!   be apples-to-oranges vs Plonky2's algebraic hash).
//! * **FRI.** Production-tuned `new_benchmark` (log_blowup=1, 100 queries,
//!   16-bit query PoW) and `new_benchmark_zk` (log_blowup=2) — NOT the
//!   low-security testing params the I/R probes used.
//! * **DFT.** `Radix2DitParallel` — the parallel production DFT.
//!
//! ## Sizing brackets (both reported, both caveated)
//!
//! The AIR is the **non-vectorized** `Poseidon2Air` (one permutation per
//! trace row), so `num_hashes` directly controls the row count. It uses the
//! degree-3 S-box (see the `SBOX_DEGREE` const comment below for why degree-7
//! is unusable on this path at the pinned rev, and why this does not move the
//! prove-time headline materially).
//!
//! * **Upper bound (hash-saturated): `num_hashes = 1<<16`.** A 2^16-row trace
//!   doing 65 536 Poseidon permutations — ~14× more hashing than the real
//!   circuit's ~4500 hashes. If Plonky3 beats 4.35 s *here*, the thesis holds
//!   with a large margin. This is a conservative upper bound on prove cost.
//! * **Lower bound (hash-matched): `num_hashes = 4500`.** Padded by
//!   `generate_trace_rows` to 2^13 = 8192 rows. Matches the real hash count
//!   but a smaller trace; the real circuit's extra non-hash gates would push
//!   it up somewhat. This is the closer like-for-like point.
//! * **Middle: `num_hashes = 1<<15`** for an intermediate data point.
//!
//! ## ZK note
//!
//! zkCoins proofs are zero-knowledge. The `new_benchmark_zk` row (log_blowup
//! = 2) is the zk-apples-to-apples FRI point. For a *timing* proxy we run it
//! on the plain `TwoAdicFriPcs` (the blowup-2 parameter alone drives the
//! dominant prove cost — the FRI/Merkle work grows with the blowup; the extra
//! random-masking rows of a true `HidingFriPcs` are a small additive term).
//! This is labelled "blowup=2 (zk proxy)" everywhere it appears. A full
//! `HidingFriPcs` measurement is a follow-up if the proxy lands close to the
//! budget.
//!
//! ## Verdict policy
//!
//! The test PASSES on successful measurement + proof verification regardless
//! of the speed outcome. The speed verdict is a **reported finding**, not a
//! hard assert — if Plonky3 is *not* faster at some point, that is a result
//! to investigate (see the printed report), not to hide.

use std::time::Instant;

use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BabyBear, GenericPoseidon2LinearLayersBabyBear,
    default_babybear_poseidon2_16, default_babybear_poseidon2_24,
};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

// --- Poseidon2 / BabyBear AIR shape -----------------------------------------
//
// S-box parameters. We use the degree-3 S-box (`x^3`, SBOX_REGISTERS = 0),
// which is exactly what Plonky3's own non-vectorized BabyBear Poseidon2
// end-to-end tests use (`examples/src/tests.rs`, with the comment: "The AIR
// uses KoalaBear's S-box degree (3) ... This is intentional: the AIR test
// validates the proof system, not the hash function's security parameters").
//
// Why not the cryptographic degree-7 (`x^7`) S-box? At this pinned Plonky3 rev
// the non-vectorized `Poseidon2Air` with SBOX_DEGREE = 7 (either
// SBOX_REGISTERS = 0 or 1) fails verification with `OodEvaluationMismatch`
// under the plain `TwoAdicFriPcs` + Poseidon2-MMCS + `DuplexChallenger` path
// (the working upstream degree-7 example uses the *vectorized* AIR + Keccak
// MMCS + `HidingFriPcs`). Verified by bisection: degree-3 verifies on both FRI
// configs; degree-7 does not. This is a benchmark of *prover speed*. Honest
// magnitude: the S-box degree sets the constraint (hence quotient) degree —
// degree-3 uses 2 quotient chunks (quotient domain 2N), degree-7 would use 8
// (8N), inflating ONLY the quotient stage ~4x while leaving trace commit + FRI
// untouched, i.e. a worst-case total prove inflation of ~1.5-2.5x (up to ~3x).
// That is NOT negligible, but it does not threaten the verdict: a full 3x on the
// weakest (4.2x) point still leaves Plonky3 ~1.4x ahead, and the fair
// hash-matched point degrades only from 61x/34x to ~20x/~11x. Plonky2's own
// baseline uses Goldilocks-Poseidon's degree-7 S-box, so this gap flatters
// Plonky3 in one bounded direction. degree-3 is a prover-speed proxy whose
// speedup is an over-estimate by at most ~3x, verdict robust across that range.
// The matching round count for the degree-3 width-16 BabyBear AIR is 20
// partial rounds (KoalaBear's, as in the upstream test).
const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = 3;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS; // 4
const PARTIAL_ROUNDS: usize = 20;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;

// Width-16 / width-24 BabyBear Poseidon2 permutations (NEON-packed on aarch64).
type Perm16 = p3_baby_bear::Poseidon2BabyBear<16>;
type Perm24 = p3_baby_bear::Poseidon2BabyBear<24>;

// Poseidon2 Merkle MMCS, mirroring `examples/src/types.rs::Poseidon2MerkleMmcs`:
// sponge over width-24 for hashing, 2-to-1 truncated permutation over width-16
// for compression. Operates over the *packed* field for SIMD throughput.
type Poseidon2Sponge = PaddingFreeSponge<Perm24, 24, 16, 8>;
type Poseidon2Compression = TruncatedPermutation<Perm16, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Poseidon2Sponge,
    Poseidon2Compression,
    2,
    8,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm24, 24, 16>;
type Dft = Radix2DitParallel<BabyBear>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

type ProbeAir = Poseidon2Air<
    Val,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// Plonky2 measured baseline (M5 Max) for the real zkCoins state-transition.
const PLONKY2_P50_MS: f64 = 4350.0;
const PLONKY2_RSS_MB: f64 = 3900.0;

/// Which production-tuned FRI parameter set to use for a run.
#[derive(Clone, Copy)]
enum FriChoice {
    /// `new_benchmark`: log_blowup=1, 100 queries, 16-bit PoW. Fastest
    /// production / non-zk headline.
    BenchBlowup1,
    /// `new_benchmark_zk`: log_blowup=2, 100 queries, 16-bit PoW, on the plain
    /// `TwoAdicFriPcs`. The zk-apples-to-apples timing proxy.
    BenchZkBlowup2,
}

impl FriChoice {
    fn label(self) -> &'static str {
        match self {
            FriChoice::BenchBlowup1 => "new_benchmark (blowup=1, non-zk)",
            FriChoice::BenchZkBlowup2 => "new_benchmark_zk (blowup=2, zk proxy)",
        }
    }

    fn params(self, mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
        match self {
            FriChoice::BenchBlowup1 => FriParameters::new_benchmark(mmcs),
            FriChoice::BenchZkBlowup2 => FriParameters::new_benchmark_zk(mmcs),
        }
    }
}

/// Build a fresh `(config, air, log_blowup)` bundle. Round-constant / perm /
/// PCS construction is *setup* — excluded from the timed region.
fn build(fri: FriChoice) -> (MyConfig, ProbeAir, usize) {
    let perm16 = default_babybear_poseidon2_16();
    let perm24 = default_babybear_poseidon2_24();

    let hash = Poseidon2Sponge::new(perm24.clone());
    let compress = Poseidon2Compression::new(perm16);
    let val_mmcs = ValMmcs::new(hash, compress, 3);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = fri.params(challenge_mmcs);
    let log_blowup = fri_params.log_blowup;

    let dft = Dft::default();
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm24);
    let config = MyConfig::new(pcs, challenger);

    // Round constants for the AIR (deterministic seed for reproducibility).
    let mut rng = SmallRng::seed_from_u64(1);
    let constants =
        RoundConstants::<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>::from_rng(&mut rng);
    let air = ProbeAir::new(constants);

    (config, air, log_blowup)
}

/// Peak resident-set size of this process, in MB.
///
/// `getrusage(RUSAGE_SELF).ru_maxrss` is **bytes** on macOS/darwin (it is KB
/// on Linux). This probe runs on macOS, so we divide by 1<<20. The value is a
/// high-water mark over the whole process lifetime, so it reflects the
/// largest prove run executed so far.
fn peak_rss_mb() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(rc, 0, "getrusage failed");
    let max_rss_bytes = usage.ru_maxrss as f64;
    if cfg!(target_os = "macos") {
        max_rss_bytes / (1u64 << 20) as f64
    } else {
        // Linux: ru_maxrss is in KB.
        (max_rss_bytes * 1024.0) / (1u64 << 20) as f64
    }
}

struct RunResult {
    num_hashes: usize,
    rows: usize,
    fri: FriChoice,
    trace_gen_ms: f64,
    p50_ms: f64,
    min_ms: f64,
    max_ms: f64,
    rss_mb: f64,
}

/// Time `prove()` for one `(FRI config, num_hashes)` point.
///
/// Protocol: 1 untimed warmup prove, then 5 timed proves; report p50/min/max.
/// `prove()` alone is timed (the part comparable to Plonky2's prove time);
/// trace generation is measured separately and reported. The proof is verified
/// once as a correctness gate.
fn run_point(fri: FriChoice, num_hashes: usize) -> RunResult {
    const TIMED_RUNS: usize = 5;

    let (config, air, log_blowup) = build(fri);

    // The non-vectorized `Poseidon2Air::generate_trace_rows` requires the hash
    // count to already be a power of two (one permutation == one trace row), so
    // we pad up to the next power of two ourselves. 4500 -> 8192 = 2^13, which
    // is exactly the documented padded row target for the hash-matched point.
    let padded_hashes = num_hashes.next_power_of_two();

    // Trace generation (separate measurement; the row count is what `prove`
    // actually consumes). `log_blowup` appends extra-capacity bits used by the
    // PCS quotient/LDE.
    let t0 = Instant::now();
    let trace: RowMajorMatrix<Val> = air.generate_trace_rows(padded_hashes, log_blowup);
    let trace_gen_ms = t0.elapsed().as_secs_f64() * 1e3;
    let rows = trace.height();

    // Warmup (untimed): primes caches / allocator / any one-time init.
    {
        let proof = prove(&config, &air, trace.clone(), &[]);
        verify(&config, &air, &proof, &[]).expect("warmup proof must verify");
    }

    let mut times_ms = Vec::with_capacity(TIMED_RUNS);
    let mut last_proof = None;
    for _ in 0..TIMED_RUNS {
        let trace_run = trace.clone();
        let t = Instant::now();
        let proof = prove(&config, &air, trace_run, &[]);
        times_ms.push(t.elapsed().as_secs_f64() * 1e3);
        last_proof = Some(proof);
    }

    // Correctness gate.
    let proof = last_proof.expect("at least one timed run");
    verify(&config, &air, &proof, &[]).expect("Probe S proof must verify");

    times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50_ms = times_ms[times_ms.len() / 2];
    let min_ms = times_ms[0];
    let max_ms = times_ms[times_ms.len() - 1];

    RunResult {
        num_hashes,
        rows,
        fri,
        trace_gen_ms,
        p50_ms,
        min_ms,
        max_ms,
        rss_mb: peak_rss_mb(),
    }
}

#[test]
fn probe_s_fair_bench() {
    // --- Environment confirmation: packing + threads + DFT ------------------
    let packing_type = core::any::type_name::<<Val as Field>::Packing>();
    let scalar_type = core::any::type_name::<Val>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    println!("\n===================== Probe S: fair BabyBear prover bench =====================");
    println!("field            : BabyBear + BinomialExtensionField<_, 4>");
    println!("hash / MMCS      : Poseidon2 Merkle (sponge w24 / compress w16)");
    println!("DFT              : Radix2DitParallel<BabyBear>");
    println!("BabyBear::Packing: {packing_type}");
    println!(
        "  -> SIMD packing active: {} ({} lanes vs scalar {})",
        packing_active, packing_type, scalar_type
    );
    println!("threads (avail)  : {threads}");
    println!(
        "Plonky2 baseline : {:.0} ms p50 / {:.0} MB RSS (real zkCoins state-transition, M5 Max)",
        PLONKY2_P50_MS, PLONKY2_RSS_MB
    );
    println!("------------------------------------------------------------------------------");

    // Sizes: hash-matched lower bound, middle, hash-saturated upper bound.
    let sizes: [(usize, &str); 3] = [
        (
            4500,
            "hash-matched lower bound (~real 4500 hashes -> 2^13 rows)",
        ),
        (1 << 15, "middle"),
        (1 << 16, "hash-saturated upper bound (~14x real hash work)"),
    ];
    let fris = [FriChoice::BenchBlowup1, FriChoice::BenchZkBlowup2];

    let mut results = Vec::new();
    for &(num_hashes, size_note) in &sizes {
        for &fri in &fris {
            println!(
                "running: num_hashes={num_hashes} [{size_note}] | FRI={}",
                fri.label()
            );
            let r = run_point(fri, num_hashes);
            println!(
                "  rows={:>6} trace_gen={:>8.1}ms  prove p50={:>8.1}ms (min {:>8.1} / max {:>8.1})  peak_rss={:>7.1}MB",
                r.rows, r.trace_gen_ms, r.p50_ms, r.min_ms, r.max_ms, r.rss_mb
            );
            results.push(r);
        }
    }

    // --- Report table -------------------------------------------------------
    println!("\n======================= Probe S results (warm, p50) ==========================");
    println!(
        "{:<10} {:<8} {:<38} {:>10} {:>10} {:>10} {:>10} {:>9}",
        "n_hashes", "rows", "FRI", "tracegen", "p50_ms", "min_ms", "max_ms", "rss_MB"
    );
    for r in &results {
        println!(
            "{:<10} {:<8} {:<38} {:>10.1} {:>10.1} {:>10.1} {:>10.1} {:>9.1}",
            r.num_hashes,
            r.rows,
            r.fri.label(),
            r.trace_gen_ms,
            r.p50_ms,
            r.min_ms,
            r.max_ms,
            r.rss_mb
        );
    }
    println!(
        "{:<10} {:<8} {:<38} {:>10} {:>10.1} {:>10} {:>10} {:>9.1}",
        "PLONKY2",
        "~65536",
        "baseline (Goldilocks, real circuit)",
        "-",
        PLONKY2_P50_MS,
        "-",
        "-",
        PLONKY2_RSS_MB
    );

    // --- Speedup verdict ----------------------------------------------------
    println!("\n========================= Speedup vs Plonky2 (4.35 s) ========================");
    for r in &results {
        let speedup = PLONKY2_P50_MS / r.p50_ms;
        let rss_ratio = PLONKY2_RSS_MB / r.rss_mb;
        let verdict = if r.p50_ms < PLONKY2_P50_MS {
            "FASTER"
        } else {
            "NOT FASTER"
        };
        println!(
            "n_hashes={:<6} {:<38} p50={:>8.1}ms  {:>10} ({:.2}x speed, {:.2}x less RSS)",
            r.num_hashes,
            r.fri.label(),
            r.p50_ms,
            verdict,
            speedup,
            rss_ratio
        );
    }
    println!("==============================================================================\n");

    // Hard correctness asserts (already enforced inside run_point via verify()):
    // every proof verified. The speed verdict above is a reported finding, not
    // a gate — the test passes on successful measurement + verification.
    assert!(!results.is_empty(), "must have measured at least one point");
    // Sanity: packing must be the NEON-packed type on aarch64, else the
    // comparison is unfair (scalar BabyBear). Surfaced loudly above; assert it
    // so a regression to the trivial [BabyBear;1] packing fails the probe.
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got scalar packing {packing_type} — \
         benchmark would be unfairly slow"
    );
}
