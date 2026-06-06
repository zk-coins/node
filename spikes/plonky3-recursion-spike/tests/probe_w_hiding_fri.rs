//! Probe W — REAL `HidingFriPcs` vs the blowup-2 "zk proxy": the honesty delta.
//!
//! # Why this probe exists
//!
//! Probe S's zero-knowledge timing row was a **proxy**: it ran the
//! `new_benchmark_zk` FRI preset (log_blowup = 2) on the *plain*,
//! non-hiding `TwoAdicFriPcs` + `MerkleTreeMmcs`, on the argument that "the
//! blowup-2 parameter alone drives the dominant prove cost; the extra
//! random-masking rows of a true `HidingFriPcs` are a small additive term."
//! That argument was asserted, never measured.
//!
//! This probe measures it. It proves the **same** degree-7 BabyBear Poseidon2
//! STARK under TWO configurations that differ in *exactly one axis* — whether
//! the commitment scheme hides — and reports the delta:
//!
//! * **PROXY (Probe S's zk row):** plain `MerkleTreeMmcs` + plain
//!   `TwoAdicFriPcs`, `new_benchmark_zk` (blowup = 2). NOT zero-knowledge —
//!   the blowup-2 FRI is a *timing* stand-in for ZK, with no masking rows.
//! * **REAL HIDING (true ZK):** `MerkleTreeHidingMmcs` (random masking rows in
//!   every Merkle leaf) + `HidingFriPcs` (`num_random_codewords = 4` random
//!   masking codewords), same `new_benchmark_zk` blowup-2 FRI.
//!
//! Everything else is held identical: BabyBear field + degree-4 extension, the
//! **same Keccak byte-hash family** (`PaddingFreeSponge<KeccakF, …>` +
//! `CompressionFunctionFromHasher`), the same `SerializingChallenger32`, the
//! same `VectorizedPoseidon2Air<.., SBOX_DEGREE = 7, SBOX_REGISTERS = 1, ..>`,
//! the same `Radix2DitParallel` DFT, the same blowup-2 FRI preset. The ONLY
//! difference is hiding-vs-plain on the MMCS + PCS. So the measured p50 delta
//! is the **true cost of zero-knowledge hiding**, and the ratio
//! `real_hiding / proxy` tells us whether Probe S's proxy was honest.
//!
//! Probe S's proxy used the *Poseidon2* Merkle MMCS, not Keccak; this probe
//! deliberately uses Keccak for BOTH arms so the proxy-vs-real comparison is
//! clean (one variable). The absolute numbers here are therefore the Keccak
//! path's, directly comparable to Probe V (same recipe); the headline of W is
//! the *ratio*, which is hash-family-robust.
//!
//! ## Honesty verdict policy
//!
//! If `real_hiding / proxy` is within a small factor (say <= ~1.3x), Probe S's
//! proxy was honest: the blowup dominates and the masking overhead is the
//! "small additive term" Probe S claimed. If it is materially larger, the
//! proxy under-reported the true ZK cost and that is a precise finding for
//! Probe T's budget. Either way the number is REPORTED — the test passes on
//! successful measurement + verification of both arms.
//!
//! ## Sizing
//!
//! Measured at trace heights 2^13 (the real circuit's hash-matched point) and
//! 2^16 (hash-saturated upper bound), matching Probe S / Probe V. The
//! vectorized AIR packs `VECTOR_LEN = 8` permutations per row, so
//! `num_perms = height * 8`.

use std::time::Instant;

use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    BABYBEAR_S_BOX_DEGREE, BabyBear, GenericPoseidon2LinearLayersBabyBear,
};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_poseidon2_air::{RoundConstants, VectorizedPoseidon2Air};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

// --- Shared AIR shape (degree-7 cryptographic S-box, optimal regs = 1) ------
const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE; // 7
const SBOX_REGISTERS: usize = 1;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS; // 4
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16; // 13
const VECTOR_LEN: usize = 1 << 3; // 8

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;

// --- Shared Keccak byte-hash primitives (identical in both arms) ------------
type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = p3_dft::Radix2DitParallel<BabyBear>;

// --- PROXY arm: plain (non-hiding) MMCS + plain TwoAdicFriPcs ----------------
type PlainValMmcs = MerkleTreeMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    2,
    4,
>;
type PlainChallengeMmcs = ExtensionMmcs<Val, Challenge, PlainValMmcs>;
type PlainPcs = TwoAdicFriPcs<Val, Dft, PlainValMmcs, PlainChallengeMmcs>;
type PlainConfig = StarkConfig<PlainPcs, Challenge, Challenger>;

// --- REAL arm: hiding MMCS + HidingFriPcs (true zero-knowledge) --------------
type HidingValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    MyCompress,
    SmallRng,
    2,
    4,
    4,
>;
type HidingChallengeMmcs = ExtensionMmcs<Val, Challenge, HidingValMmcs>;
type HidingPcs = HidingFriPcs<Val, Dft, HidingValMmcs, HidingChallengeMmcs, SmallRng>;
type HidingConfig = StarkConfig<HidingPcs, Challenge, Challenger>;

// --- The (shared) degree-7 vectorized AIR -----------------------------------
type ProbeAir = VectorizedPoseidon2Air<
    Val,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
    VECTOR_LEN,
>;

/// Build the degree-7 AIR (deterministic constants).
fn build_air() -> ProbeAir {
    let mut rng = SmallRng::seed_from_u64(1);
    VectorizedPoseidon2Air::new(RoundConstants::from_rng(&mut rng))
}

/// Build the PROXY (plain, non-hiding) config + log_blowup. Setup only.
fn build_proxy() -> (PlainConfig, usize) {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);

    let val_mmcs = PlainValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = PlainChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters::new_benchmark_zk(challenge_mmcs);
    let log_blowup = fri_params.log_blowup;

    let dft = Dft::default();
    let pcs = PlainPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(vec![], byte_hash);
    (PlainConfig::new(pcs, challenger), log_blowup)
}

/// Build the REAL HIDING (true ZK) config + log_blowup. Setup only.
fn build_hiding() -> (HidingConfig, usize) {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);

    let val_mmcs = HidingValMmcs::new(field_hash, compress, 0, SmallRng::seed_from_u64(2));
    let challenge_mmcs = HidingChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters::new_benchmark_zk(challenge_mmcs);
    let log_blowup = fri_params.log_blowup;

    let dft = Dft::default();
    let pcs = HidingPcs::new(dft, val_mmcs, fri_params, 4, SmallRng::seed_from_u64(3));
    let challenger = Challenger::from_hasher(vec![], byte_hash);
    (HidingConfig::new(pcs, challenger), log_blowup)
}

/// Peak resident-set size of this process, in MB. `ru_maxrss` is bytes on
/// macOS (KB on Linux); this probe runs on macOS.
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
    arm: &'static str,
    rows: usize,
    p50_ms: f64,
    p90_ms: f64,
    min_ms: f64,
    max_ms: f64,
    rss_mb: f64,
}

/// p-quantile (nearest-rank) of an already-sorted slice.
fn quantile(sorted: &[f64], q: f64) -> f64 {
    let rank = (q * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

/// Number of timed `prove()` runs per point (after one untimed warmup).
const TIMED_RUNS: usize = 5;

/// Turn a vector of timed prove durations into a `RunResult`.
fn summarize(arm: &'static str, rows: usize, mut times_ms: Vec<f64>) -> RunResult {
    times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    RunResult {
        arm,
        rows,
        p50_ms: quantile(&times_ms, 0.50),
        p90_ms: quantile(&times_ms, 0.90),
        min_ms: times_ms[0],
        max_ms: times_ms[times_ms.len() - 1],
        rss_mb: peak_rss_mb(),
    }
}

// The PROXY and REAL arms use different concrete `StarkConfig`s, so each gets
// its own timing function. The bodies are identical save the config type;
// keeping them concrete avoids the `StarkGenericConfig` associated-type
// gymnastics a single generic helper would require (the `Domain::Val` of a
// generic SC does not unify with `BabyBear` without extra bounds the call
// sites cannot satisfy cleanly). Protocol: 1 untimed warmup prove (+verify),
// 5 timed proves; final proof verified as a hard correctness gate.

/// Time the PROXY (plain `TwoAdicFriPcs`, blowup-2) arm.
fn time_proxy(config: &PlainConfig, air: &ProbeAir, trace: &RowMajorMatrix<Val>) -> RunResult {
    {
        let proof = prove(config, air, trace.clone(), &[]);
        verify(config, air, &proof, &[]).expect("proxy warmup proof must verify");
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
    verify(config, air, &last_proof.expect("at least one run"), &[])
        .expect("proxy proof must verify");
    summarize("PROXY (blowup-2)", trace.height(), times_ms)
}

/// Time the REAL HIDING (`HidingFriPcs`, true ZK) arm.
fn time_hiding(config: &HidingConfig, air: &ProbeAir, trace: &RowMajorMatrix<Val>) -> RunResult {
    {
        let proof = prove(config, air, trace.clone(), &[]);
        verify(config, air, &proof, &[]).expect("hiding warmup proof must verify");
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
    verify(config, air, &last_proof.expect("at least one run"), &[])
        .expect("hiding proof must verify");
    summarize("REAL HidingFriPcs", trace.height(), times_ms)
}

fn print_row(r: &RunResult) {
    println!(
        "{:<22} rows={:>6}  p50={:>8.1}ms p90={:>8.1}ms (min {:>8.1}/max {:>8.1})  rss={:>7.1}MB",
        r.arm, r.rows, r.p50_ms, r.p90_ms, r.min_ms, r.max_ms, r.rss_mb
    );
}

#[test]
fn probe_w_hiding_fri() {
    let packing_type = core::any::type_name::<<Val as Field>::Packing>();
    let scalar_type = core::any::type_name::<Val>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    println!("\n============ Probe W: real HidingFriPcs vs blowup-2 zk-proxy delta ============");
    println!("held identical across both arms:");
    println!("  field BabyBear + ext4 | AIR VectorizedPoseidon2Air deg7 regs1 vlen8");
    println!("  Keccak hash family | SerializingChallenger32 | Radix2DitParallel DFT");
    println!("  FRI new_benchmark_zk (log_blowup=2, 100 queries, 16-bit PoW)");
    println!("the ONLY difference between arms:");
    println!("  PROXY : MerkleTreeMmcs       + TwoAdicFriPcs  (NON-hiding, no masking)");
    println!("  REAL  : MerkleTreeHidingMmcs + HidingFriPcs   (num_random_codewords=4, TRUE ZK)");
    println!("BabyBear::Packing: {packing_type}");
    println!("  -> SIMD packing active: {packing_active} (vs scalar {scalar_type})");
    println!("p3_keccak::VECTOR_LEN: {}", p3_keccak::VECTOR_LEN);
    println!("threads (avail)  : {threads}");
    println!("------------------------------------------------------------------------------");

    // (trace_height, note). Real-circuit hash-matched + hash-saturated upper.
    let sizes: [(usize, &str); 2] = [
        (1 << 13, "2^13 rows (real-circuit hash-matched)"),
        (1 << 16, "2^16 rows (hash-saturated upper bound)"),
    ];

    let air = build_air();
    let (proxy_config, proxy_blowup) = build_proxy();
    let (hiding_config, hiding_blowup) = build_hiding();
    assert_eq!(proxy_blowup, 2, "proxy must be blowup-2 (new_benchmark_zk)");
    assert_eq!(
        hiding_blowup, 2,
        "hiding must be blowup-2 (new_benchmark_zk)"
    );

    let mut rows_out = Vec::new();
    for &(height, note) in &sizes {
        let num_perms = height * VECTOR_LEN;
        println!("running size {height} rows (num_perms={num_perms}) [{note}]");

        // Same trace for both arms at this size (same AIR, same blowup-2 LDE).
        let trace = air.generate_vectorized_trace_rows(num_perms, proxy_blowup);

        let proxy = time_proxy(&proxy_config, &air, &trace);
        print_row(&proxy);
        let real = time_hiding(&hiding_config, &air, &trace);
        print_row(&real);

        rows_out.push((height, proxy, real));
    }

    // --- Hiding-vs-proxy delta table ---------------------------------------
    println!("\n=================== Probe W: hiding-vs-proxy delta (p50) ======================");
    println!(
        "{:<8} {:>12} {:>12} {:>10} {:>12}",
        "rows", "proxy_p50", "hiding_p50", "delta_x", "abs_add_ms"
    );
    for (height, proxy, real) in &rows_out {
        let ratio = real.p50_ms / proxy.p50_ms;
        let add_ms = real.p50_ms - proxy.p50_ms;
        println!(
            "{:<8} {:>12.1} {:>12.1} {:>10.2} {:>12.1}",
            height, proxy.p50_ms, real.p50_ms, ratio, add_ms
        );
    }

    // --- Honesty verdict ----------------------------------------------------
    println!("\n========================= Probe S proxy honesty verdict ======================");
    println!("Probe S claimed: blowup dominates; true-hiding masking is a 'small additive term'.");
    const HONEST_THRESHOLD: f64 = 1.30;
    for (height, proxy, real) in &rows_out {
        let ratio = real.p50_ms / proxy.p50_ms;
        let verdict = if ratio <= HONEST_THRESHOLD {
            "HONEST (hiding overhead small)"
        } else {
            "PROXY UNDER-REPORTS (hiding non-trivial)"
        };
        println!(
            "rows={:>6}  real/proxy = {:.2}x  -> {} (threshold {:.2}x)",
            height, ratio, verdict, HONEST_THRESHOLD
        );
    }
    println!("==============================================================================\n");

    assert_eq!(rows_out.len(), 2, "must have measured both sizes");
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got scalar packing {packing_type}"
    );
}
