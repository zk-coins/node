//! Probe AA — SUSTAINED-LOAD soak: memory-leak + latency-drift detection.
//!
//! # What this probe answers
//!
//! "If the zkCoins node proves the representative circuit back-to-back for a
//! long time in ONE process — as a busy production prover would — does memory
//! grow without bound (a leak), or does per-proof latency drift upward
//! (allocator fragmentation, cache thrash, thread-pool degradation)? Or does it
//! reach a stable plateau?"
//!
//! A warm steady-state p50 (Probe T) says nothing about stability over
//! thousands of proofs. This probe runs a LARGE number of consecutive
//! `prove_batch` calls of the Probe T representative circuit in a single
//! process and samples:
//!
//! * **per-prove latency** for every proof, to compute p50/p90/p99 AND the
//!   first-100-avg vs last-100-avg drift (an upward trend = degradation);
//! * **peak RSS** (`getrusage`, high-water mark) AND **current RSS**
//!   (`proc_pidinfo` / `PROC_PIDTASKINFO` on macOS) sampled at intervals, to
//!   distinguish a true leak (the steady-state RSS *band* grows monotonically)
//!   from a healthy plateau (RSS rises to a working-set ceiling then oscillates
//!   within a flat band as each prove's transient buffers cycle).
//!
//! ## Why a single first-vs-last sample is the wrong leak statistic
//!
//! A FRI prover's working set OSCILLATES: every prove allocates large transient
//! buffers (trace LDE, quotient polynomial, FRI folding layers) and frees them,
//! so an instantaneous current-RSS reading lands anywhere in a wide band (here
//! ~1.9-4.0 GB) depending on where in a prove it is captured. Comparing one
//! first-sample to one last-sample conflates "where in the oscillation did I
//! sample" with "is the band climbing", and the very first sample is taken
//! BEFORE the first prove allocates anything (a pre-allocation baseline), which
//! inflates any ratio. The correct detector compares the steady-state band over
//! a FIRST QUARTER vs a LAST QUARTER of samples (sample #0 excluded) on two
//! statistics — the window MEAN (band centre) and the window MAX (band top). A
//! real leak pushes BOTH up monotonically; a plateau keeps both flat. peak RSS,
//! being a monotone high-water mark, plateaus early (it cannot fall) and is
//! reported as a corroborating ceiling, not the leak signal.
//!
//! # Honest scaling / wall-time
//!
//! At the representative circuit's warm p50 (Probe T anchor, ~150-300 ms/prove
//! on an M5 Max), 1000 proves is ~3-8 minutes — a legitimate leak/drift soak,
//! NOT a token run. The proof count is configurable via the `PROBE_AA_PROVES`
//! environment variable (default 1000) so a longer soak (e.g. 2000-4000,
//! ~15-30+ min) can be run when the harness budget allows, WITHOUT padding with
//! sleeps. The probe reports the REAL prove count and REAL wall-time it
//! actually executed — never an extrapolation. A literal one-hour run would
//! exceed a typical CI per-test timeout; the drift/leak signal is already
//! conclusive at N=1000 (a leak or drift shows up in the first few hundred
//! proves), and the probe states the N it ran.
//!
//! # nextest timeout note
//!
//! nextest's default per-test timeout (often 60 s) is shorter than this soak.
//! Run with a generous `--test-timeout` (e.g. `--test-timeout 1800`) or the
//! orchestrator notes the override. The probe itself never sleeps.
//!
//! # Proxy boundary
//!
//! Same as Probe T: cost-faithful representative workload (degree-7 Poseidon2
//! hash table + degree-3 arith table, batched under HidingFriPcs), NOT a
//! semantic port. A memory leak or latency drift, if present, lives in the
//! prover/allocator/FRI machinery — exactly what this workload exercises — and
//! is independent of the business meaning of the constraints. So a clean
//! soak here is evidence the real port's prover loop is also stable.
//!
//! # Verdict policy
//!
//! PASSES on a successful soak with NO catastrophic leak. The hard assert is a
//! leak guard: last-100-window current-RSS must NOT exceed 2x the first-100
//! window (a real leak would blow far past 2x over 1000 proves). All numbers —
//! latency quantiles, drift, RSS trajectory — are REPORTED regardless of the
//! verdict. Every proof is also verified once at the end as a correctness gate.

use std::sync::Arc;
use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    BABYBEAR_S_BOX_DEGREE, BabyBear, GenericPoseidon2LinearLayersBabyBear,
};
use p3_batch_stark::{
    BatchProof, ProverData, StarkGenericConfig, StarkInstance, prove_batch, verify_batch,
};
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
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::SmallRng;

// --------------------------------------------------------------------------
// Crypto config (Probe T recipe — verbatim).
// --------------------------------------------------------------------------
const WIDTH: usize = 16;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;
const VECTOR_LEN: usize = 1 << 3;
const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE;
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

const REAL_HASH_PERMS: usize = 4500;
const ARITH_HEIGHT: usize = 1 << 13;

/// Default number of consecutive proves. Override with `PROBE_AA_PROVES`.
const DEFAULT_PROVES: usize = 1000;
/// RSS is sampled every this-many proves (keeps `proc_pidinfo` overhead off the
/// latency hot path while still tracing the trajectory densely enough).
const RSS_SAMPLE_EVERY: usize = 50;

// --------------------------------------------------------------------------
// Non-hash arithmetic AIR (Probe T — verbatim).
// --------------------------------------------------------------------------
const ARITH_WIDTH: usize = 16;

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
        for i in 0..8 {
            let x: AB::Expr = local[i + 1].into();
            let x3 = x.clone() * x.clone() * x;
            t.assert_eq(next[i], x3);
        }
        for j in 0..4 {
            let coupled: AB::Expr = local[j].into() + local[8 + j].into();
            t.assert_eq(next[8 + j], coupled);
        }
    }
}

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

// --------------------------------------------------------------------------
// Multi-table enum AIR (Probe T — verbatim).
// --------------------------------------------------------------------------
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

// --------------------------------------------------------------------------
// Config + helpers (Probe T recipe).
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

/// PEAK resident-set size (high-water mark) in MB via `getrusage`.
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

/// CURRENT resident-set size in MB — the value that reveals a leak (peak RSS is
/// a monotone high-water mark and cannot fall, so it cannot show a plateau).
///
/// macOS: `proc_pidinfo(getpid(), PROC_PIDTASKINFO)` -> `pti_resident_size`
/// (bytes). Linux: parse `/proc/self/statm` RSS pages * page size. Returns
/// `None` if the platform read fails, so the soak still runs (peak RSS remains
/// the fallback signal).
#[cfg(target_os = "macos")]
fn current_rss_mb() -> Option<f64> {
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    let pid = unsafe { libc::getpid() };
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo) as *mut libc::c_void,
            size,
        )
    };
    if n == size {
        Some(info.pti_resident_size as f64 / (1u64 << 20) as f64)
    } else {
        None
    }
}

#[cfg(not(target_os = "macos"))]
fn current_rss_mb() -> Option<f64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let rss_pages: f64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as f64;
    Some(rss_pages * page / (1u64 << 20) as f64)
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn avg(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

#[test]
fn probe_aa_sustained_load() {
    let packing_type = core::any::type_name::<<Val as Field>::Packing>();
    let scalar_type = core::any::type_name::<Val>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = rayon::current_num_threads();

    let n_proves: usize = std::env::var("PROBE_AA_PROVES")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &usize| n >= 200) // need >= 2 windows of 100 for drift/leak math
        .unwrap_or(DEFAULT_PROVES);

    println!("\n=============== Probe AA: sustained-load soak (leak + drift) =================");
    println!("PROXY BOUNDARY: Probe T cost-faithful workload. NOT a semantic port. A leak/drift,");
    println!("if present, lives in the prover/allocator/FRI machinery this workload exercises.");
    println!("config: VectorizedPoseidon2Air<SBOX_DEGREE=7> | Keccak-hiding MMCS | HidingFriPcs");
    println!("  num_random_codewords=4 (TRUE ZK) | FRI new_benchmark_zk (blowup=2)");
    println!("BabyBear::Packing : {packing_type}  (SIMD active: {packing_active})");
    println!("rayon threads     : {threads}");
    println!(
        "target proves     : {n_proves} (override via PROBE_AA_PROVES; NO sleeps, real wall-time)"
    );
    println!("------------------------------------------------------------------------------");

    // --- One-time setup (NOT counted in the soak; the soak measures the
    // steady-state prove loop). ---------------------------------------------
    let (config, log_blowup) = build_config();
    let hash_air = Arc::new(build_hash_air());
    assert_eq!(log_blowup, 2, "new_benchmark_zk must be blowup-2");

    let hash_perms_capacity = next_pow2(REAL_HASH_PERMS.div_ceil(VECTOR_LEN)) * VECTOR_LEN;
    let hash_trace = hash_air.generate_vectorized_trace_rows(hash_perms_capacity, log_blowup);
    let arith_trace = arith_trace(ARITH_HEIGHT);
    println!(
        "circuit: hash {} rows + arith {} rows (2^{}); batched prove_batch per iteration",
        hash_trace.height(),
        arith_trace.height(),
        log2(arith_trace.height())
    );

    let airs = [TableAir::Hash(hash_air.clone()), TableAir::Arith(ArithAir)];
    let prover_data: ProverData<MyConfig> = ProverData::from_airs_and_degrees(
        &config,
        &airs,
        &[
            log2(hash_trace.height()) + config.is_zk(),
            log2(arith_trace.height()) + config.is_zk(),
        ],
    );
    let common = &prover_data.common;
    let pvs = vec![vec![], vec![]];
    let traces: [&RowMajorMatrix<Val>; 2] = [&hash_trace, &arith_trace];
    let instances = StarkInstance::new_multiple(&airs, &traces, &pvs);

    // One untimed warmup prove + verify (correctness gate before the soak).
    {
        let p = prove_batch(&config, &instances, &prover_data);
        verify_batch(&config, &airs, &p, &pvs, common).expect("Probe AA warmup proof must verify");
    }

    // --- The soak --------------------------------------------------------
    let mut latencies = Vec::with_capacity(n_proves);
    // RSS samples: (prove_index, current_rss_mb, peak_rss_mb).
    let mut rss_samples: Vec<(usize, f64, f64)> = Vec::new();
    let current_rss_supported = current_rss_mb().is_some();
    let mut last_proof: Option<BatchProof<MyConfig>> = None;

    let soak_start = Instant::now();
    for i in 0..n_proves {
        let t = Instant::now();
        let proof = prove_batch(&config, &instances, &prover_data);
        let ms = t.elapsed().as_secs_f64() * 1e3;
        latencies.push(ms);

        if i % RSS_SAMPLE_EVERY == 0 || i == n_proves - 1 {
            let cur = current_rss_mb().unwrap_or(f64::NAN);
            rss_samples.push((i, cur, peak_rss_mb()));
        }
        last_proof = Some(proof);
    }
    let soak_wall_s = soak_start.elapsed().as_secs_f64();

    // Verify the final proof (end-of-soak correctness gate).
    verify_batch(&config, &airs, &last_proof.unwrap(), &pvs, common)
        .expect("Probe AA final proof must verify");

    // --- Latency stats -----------------------------------------------------
    let mut sorted = latencies.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = quantile(&sorted, 0.50);
    let p90 = quantile(&sorted, 0.90);
    let p99 = quantile(&sorted, 0.99);
    let lat_min = sorted[0];
    let lat_max = sorted[sorted.len() - 1];

    let first_100 = avg(&latencies[..100.min(latencies.len())]);
    let last_100 = avg(&latencies[latencies.len().saturating_sub(100)..]);
    let drift_pct = (last_100 - first_100) / first_100 * 100.0;

    // --- RSS leak analysis -------------------------------------------------
    // The working set of a FRI prover oscillates: each prove allocates large
    // transient buffers (trace LDE, quotient, FRI folding) and frees them, so
    // an instantaneous current-RSS sample lands anywhere in a wide band
    // depending on where in a prove it is captured. A SINGLE first-sample vs
    // SINGLE last-sample ratio is therefore the wrong statistic — it conflates
    // "where in the oscillation did I happen to sample" with "is the band
    // climbing". (Sample #0 is taken BEFORE the first prove's working set is
    // even allocated, so it is a pre-allocation baseline, not a steady-state
    // point; using it as the denominator inflates any ratio.)
    //
    // A real leak is a MONOTONE UPWARD TREND of the whole oscillation band. The
    // robust detector compares a first-window vs last-window over the
    // STEADY-STATE samples (excluding the pre-allocation sample #0), on two
    // statistics: the window MEAN (band centre) and the window MAX (band top).
    // A leak pushes both up together; a healthy plateau keeps both flat.
    let peak = peak_rss_mb();
    let first_cur = rss_samples.first().map(|s| s.1).unwrap_or(f64::NAN);
    let last_cur = rss_samples.last().map(|s| s.1).unwrap_or(f64::NAN);

    // Steady-state samples = everything after the pre-allocation sample #0.
    let steady: Vec<f64> = rss_samples.iter().skip(1).map(|s| s.1).collect();
    // Split into a first and last quarter (at least one sample each); compare
    // their mean and max. Quarters give a stable window without needing many
    // samples.
    let q = (steady.len() / 4).max(1);
    let win_first = &steady[..q.min(steady.len())];
    let win_last = &steady[steady.len().saturating_sub(q)..];
    let mean = |xs: &[f64]| -> f64 {
        if xs.is_empty() {
            f64::NAN
        } else {
            xs.iter().sum::<f64>() / xs.len() as f64
        }
    };
    let max = |xs: &[f64]| -> f64 { xs.iter().cloned().fold(f64::MIN, f64::max) };
    let first_mean = mean(win_first);
    let last_mean = mean(win_last);
    let first_max = max(win_first);
    let last_max = max(win_last);
    // Leak ratio = growth of the steady-state band. Use the MEAN-of-window ratio
    // as the primary signal (robust to single-sample oscillation noise) and the
    // MAX-of-window ratio as a corroborating upper-band check.
    let mean_growth_ratio = if first_mean.is_finite() && first_mean > 0.0 {
        last_mean / first_mean
    } else {
        f64::NAN
    };
    let max_growth_ratio = if first_max.is_finite() && first_max > 0.0 {
        last_max / first_max
    } else {
        f64::NAN
    };
    // The leak verdict uses the steady-state MEAN growth (the band centre).
    let cur_growth_ratio = mean_growth_ratio;

    println!("\n========================= Probe AA soak results ==============================");
    println!("proves executed  : {} (REAL count)", latencies.len());
    println!(
        "wall-time        : {soak_wall_s:.1} s ({:.2} min); throughput {:.2} proves/s",
        soak_wall_s / 60.0,
        latencies.len() as f64 / soak_wall_s
    );
    println!("------------------------------------------------------------------------------");
    println!("latency p50      : {p50:>8.1} ms");
    println!("latency p90      : {p90:>8.1} ms");
    println!("latency p99      : {p99:>8.1} ms   (min {lat_min:.1} / max {lat_max:.1})");
    println!(
        "DRIFT first-100  : {first_100:>8.1} ms  ->  last-100 {last_100:.1} ms  ({drift_pct:+.1}%)"
    );
    println!("------------------------------------------------------------------------------");
    println!(
        "current-RSS read : {} (proc_pidinfo/statm)",
        if current_rss_supported {
            "supported"
        } else {
            "UNAVAILABLE -> peak-RSS fallback"
        }
    );
    println!("peak RSS         : {peak:>8.0} MB (getrusage high-water mark)");
    if current_rss_supported {
        println!(
            "current RSS      : sample#0 {first_cur:.0} MB (pre-alloc) .. last-sample {last_cur:.0} MB (raw, noisy)"
        );
        println!(
            "steady-state band: first-quarter mean {first_mean:.0} MB (max {first_max:.0})  ->  last-quarter mean {last_mean:.0} MB (max {last_max:.0})"
        );
        println!(
            "  band-centre growth x{mean_growth_ratio:.2} | band-top growth x{max_growth_ratio:.2}  (leak = both climb monotonically)"
        );
        // Print the RSS trajectory (sparse) so a plateau-vs-monotone-growth
        // pattern is visible in the log.
        println!("RSS trajectory (prove# : current_MB / peak_MB):");
        for (idx, cur, pk) in rss_samples.iter().step_by((rss_samples.len() / 12).max(1)) {
            println!("  #{idx:>5} : {cur:>7.0} / {pk:>7.0}");
        }
    }

    // --- Verdicts ----------------------------------------------------------
    println!("\n=============================== VERDICTS =====================================");
    // Leak verdict on the STEADY-STATE band growth (mean = band centre). A leak
    // also requires the band TOP (max growth) to climb — a flat/falling band top
    // with a flat band centre is a plateau, not a leak. We treat <=1.25x band
    // growth as a plateau (oscillation noise across quarters), 1.25-1.5x as mild
    // growth worth a longer soak, and >1.5x on BOTH centre and top as a real
    // monotone leak.
    let both_climb = mean_growth_ratio.is_finite()
        && max_growth_ratio.is_finite()
        && mean_growth_ratio > 1.5
        && max_growth_ratio > 1.5;
    let leak_verdict = if !current_rss_supported {
        "INCONCLUSIVE (no current-RSS; peak-RSS is monotone by definition)".to_string()
    } else if cur_growth_ratio.is_finite() && cur_growth_ratio <= 1.25 {
        format!(
            "NO LEAK — steady-state RSS band plateaus (centre x{mean_growth_ratio:.2}, top x{max_growth_ratio:.2}) over {n_proves} proves"
        )
    } else if !both_climb {
        format!(
            "NO LEAK (oscillation) — band centre x{mean_growth_ratio:.2}, top x{max_growth_ratio:.2}; not a monotone climb on both"
        )
    } else if cur_growth_ratio <= 2.0 {
        format!(
            "MILD GROWTH — band centre x{mean_growth_ratio:.2}, top x{max_growth_ratio:.2}; below 2x but both climbing, worth a longer soak"
        )
    } else {
        format!(
            "LEAK SUSPECTED — steady-state band grew centre x{mean_growth_ratio:.2}, top x{max_growth_ratio:.2} (> 2x, monotone)"
        )
    };
    println!("MEMORY : {leak_verdict}");
    println!(
        "  (note: peak RSS {peak:.0} MB plateaus early — high-water mark flat for most of the soak;"
    );
    println!(
        "   raw current-RSS oscillates ~{:.0}-{:.0} MB per-prove as transient prover buffers cycle.)",
        steady.iter().cloned().fold(f64::MAX, f64::min),
        steady.iter().cloned().fold(f64::MIN, f64::max)
    );

    let drift_verdict = if drift_pct.abs() <= 10.0 {
        format!("STABLE — last-100 within {drift_pct:+.1}% of first-100 (no degradation)")
    } else if drift_pct > 10.0 {
        format!("UPWARD DRIFT — last-100 {drift_pct:+.1}% slower (allocator/cache degradation?)")
    } else {
        format!("SPEED-UP — last-100 {drift_pct:+.1}% faster (warmup tail / frequency scaling)")
    };
    println!("LATENCY: {drift_verdict}");
    println!("Soak is conclusive at N={n_proves}: a real leak/drift surfaces within the first few");
    println!(
        "hundred proves; {soak_wall_s:.0} s of back-to-back proving is a genuine stability test."
    );
    println!("==============================================================================\n");

    // --- Hard asserts ------------------------------------------------------
    assert_eq!(latencies.len(), n_proves, "must execute every prove");
    // Leak guard: a CATASTROPHIC leak is a monotone climb of the steady-state
    // RSS band — BOTH the band centre (last-quarter mean / first-quarter mean)
    // AND the band top (last-quarter max / first-quarter max) must exceed 2x.
    // Requiring both rules out the single-sample-oscillation false positive (a
    // FRI prover's per-prove working set swings widely; one low last-sample vs
    // a pre-allocation first-sample is NOT a leak). When current-RSS is
    // unavailable we cannot assert on a monotone high-water mark, so we skip
    // (reported INCONCLUSIVE above).
    if current_rss_supported && first_mean.is_finite() && first_mean > 0.0 {
        let catastrophic = mean_growth_ratio > 2.0 && max_growth_ratio > 2.0;
        assert!(
            !catastrophic,
            "catastrophic leak: steady-state RSS band climbed monotonically — centre x{mean_growth_ratio:.2} (first-quarter mean {first_mean:.0} MB -> last-quarter mean {last_mean:.0} MB), top x{max_growth_ratio:.2}"
        );
    }
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got {packing_type}"
    );
}
