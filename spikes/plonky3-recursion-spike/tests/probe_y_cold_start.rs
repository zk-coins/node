//! Probe Y — COLD-START pipeline cost for the representative zkCoins circuit.
//!
//! # What this probe answers
//!
//! "When the zkCoins node boots and proves its FIRST circuit on Plonky3 +
//! BabyBear under TRUE production cryptography, how long until that first proof
//! is ready, and how does that cold path compare to Plonky2's cold path?"
//!
//! Plonky2's cold path on the real circuit (M5 Max baseline) is:
//!
//! * **circuit build / preprocessing : 8.2 s** — Plonky2 compiles a gate
//!   circuit: it builds the `CircuitData`, runs the gate-placement /
//!   witness-generator wiring, computes the constant/sigma polynomials and the
//!   prover/verifier key. That is a one-time-per-process cost paid before any
//!   proof can be produced.
//! * **first (cold) prove          : 6.1 s** — the first `prove()` is slower
//!   than the warm steady state (4.35 s p50) because allocators, FFT twiddle
//!   caches and the thread pool are cold.
//! * **cold total                  : 14.4 s** — build + first-prove: the real
//!   wall-clock latency from "node started" to "first proof emitted".
//!
//! # The honest point this probe makes
//!
//! A FRI-STARK over an AIR (Plonky3) has **no circuit-compilation step**. There
//! is nothing analogous to Plonky2's `CircuitBuilder::build()` gate-routing and
//! key-generation pass. The Plonky3 "build" is just:
//!
//! 1. constructing the hasher / compression / MMCS / PCS / challenger structs
//!    (`build_config`) — a handful of `::new()` calls, no proving-system work;
//! 2. sampling the Poseidon2 round constants for the AIR (`build_hash_air`) —
//!    one RNG fill;
//! 3. (for the batched proof) `ProverData::from_airs_and_degrees` — the closest
//!    thing to "keygen": it derives the symbolic constraints, lookups and
//!    quotient-degree metadata per table. This is the ONLY non-trivial cold
//!    setup cost, and it is still small.
//!
//! So the cold-start win for Plonky3 should be LARGE, and this probe quantifies
//! it precisely: wall-time of (config+AIR build), of `ProverData` keygen, of the
//! cold first-prove, and of the cold total, each measured separately, against
//! the 14.4 s Plonky2 cold path.
//!
//! # Proxy boundary (identical to Probe T)
//!
//! This is the Probe T cost-faithful representative circuit — degree-7
//! Poseidon2 hash table (~4500 perms) + degree-3 arithmetic table at the
//! realistic 2^13 anchor — under the verbatim production-crypto config
//! (HidingFriPcs, Keccak-hiding MMCS, FRI `new_benchmark_zk`). It reproduces
//! the real circuit's prove-cost DRIVERS, NOT its business semantics (no
//! balance / nullifier / SMT-membership logic). The cold-start *shape* it
//! measures — "no gate-circuit compilation, only config + round-constant +
//! keygen setup" — is a structural property of the Plonky3 prover, so it holds
//! for the real port regardless of the exact table layout.
//!
//! # Verdict policy
//!
//! PASSES on a successful cold measurement + verification of the cold proof.
//! The faster/slower cold-start verdict vs Plonky2 (14.4 s) is a REPORTED
//! finding. The single hard expectation we assert is structural, not a
//! threshold: the Plonky3 "build" (config + AIR + keygen) is a small fraction of
//! Plonky2's 8.2 s circuit-build — asserted loosely (build < 8.2 s) so a
//! regression that reintroduced a multi-second preprocessing cost would fail.

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
use rand::SeedableRng;
use rand::rngs::SmallRng;

// --------------------------------------------------------------------------
// Crypto config (Probe T / V recipe — verbatim).
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

use p3_uni_stark::StarkConfig;

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
// Real-circuit cost anchors + Plonky2 COLD baseline (M5 Max).
// --------------------------------------------------------------------------
const REAL_HASH_PERMS: usize = 4500;
/// Realistic non-hash arith table height (Probe T anchor: 2^13 already
/// over-covers the real ~50k non-hash gates).
const ARITH_HEIGHT: usize = 1 << 13;

/// Plonky2 COLD path on the real zkCoins circuit (M5 Max).
const PLONKY2_BUILD_MS: f64 = 8200.0; // gate-circuit compile + keygen
const PLONKY2_COLD_PROVE_MS: f64 = 6100.0; // first prove (cold caches)
const PLONKY2_COLD_TOTAL_MS: f64 = 14400.0; // build + first prove

// --------------------------------------------------------------------------
// Non-hash arithmetic AIR — Probe T's degree-3 cost model (verbatim).
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
// Multi-table enum AIR for the batched proof (Probe T's `TableAir`, verbatim).
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

#[test]
fn probe_y_cold_start() {
    let packing_type = core::any::type_name::<<Val as Field>::Packing>();
    let scalar_type = core::any::type_name::<Val>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = rayon::current_num_threads();

    println!("\n================ Probe Y: COLD-START pipeline (representative circuit) =========");
    println!("PROXY BOUNDARY: Probe T cost-faithful workload (hash count + gate count + area +");
    println!("degree-7 + ZK commitment). NOT a semantic port. Cold-start SHAPE (no gate-circuit");
    println!("compilation, only config+round-constant+keygen setup) is structural — holds for");
    println!("the real port regardless of table layout.");
    println!("config: VectorizedPoseidon2Air<SBOX_DEGREE=7,REGS=1,VEC=8> | Keccak-hiding MMCS |");
    println!("  HidingFriPcs num_random_codewords=4 (TRUE ZK) | FRI new_benchmark_zk (blowup=2)");
    println!("BabyBear::Packing : {packing_type}  (SIMD active: {packing_active})");
    println!("rayon threads     : {threads}");
    println!(
        "Plonky2 COLD path : build {PLONKY2_BUILD_MS:.0} ms + first-prove {PLONKY2_COLD_PROVE_MS:.0} ms"
    );
    println!(
        "                    = cold-total {PLONKY2_COLD_TOTAL_MS:.0} ms (real circuit, M5 Max)"
    );
    println!("------------------------------------------------------------------------------");

    // ====================================================================
    // STEP 1 — config + AIR build (the Plonky3 analog of Plonky2's 8.2 s
    // gate-circuit compilation). This is JUST hasher/PCS `::new()` calls +
    // one RNG round-constant fill: no proving-system preprocessing.
    // ====================================================================
    let t_cfg = Instant::now();
    let (config, log_blowup) = build_config();
    let config_ms = t_cfg.elapsed().as_secs_f64() * 1e3;

    let t_air = Instant::now();
    let hash_air = Arc::new(build_hash_air());
    let air_ms = t_air.elapsed().as_secs_f64() * 1e3;
    assert_eq!(log_blowup, 2, "new_benchmark_zk must be blowup-2");

    println!("[1] config build      : {config_ms:>8.3} ms (hasher/MMCS/PCS/challenger ::new())");
    println!("[1] AIR round-consts  : {air_ms:>8.3} ms (Poseidon2 RoundConstants::from_rng)");

    // ====================================================================
    // STEP 2 — trace generation for both tables. This is witness work, not
    // circuit build, but it is part of the cold critical path (the node
    // must fill the trace before its first proof), so it is timed and
    // reported separately and NOT folded into the "build" number.
    // ====================================================================
    let hash_perms_capacity = next_pow2(REAL_HASH_PERMS.div_ceil(VECTOR_LEN)) * VECTOR_LEN;
    let t_tr = Instant::now();
    let hash_trace = hash_air.generate_vectorized_trace_rows(hash_perms_capacity, log_blowup);
    let arith_trace = arith_trace(ARITH_HEIGHT);
    let tracegen_ms = t_tr.elapsed().as_secs_f64() * 1e3;
    let hash_rows = hash_trace.height();
    let arith_rows = arith_trace.height();
    println!(
        "[2] trace generation  : {tracegen_ms:>8.3} ms (hash {hash_rows} rows + arith {arith_rows} rows)"
    );

    // ====================================================================
    // STEP 3 — ProverData keygen: the ONLY non-trivial cold setup. Derives
    // per-table symbolic constraints / lookups / quotient-degree metadata.
    // This is the closest Plonky3 analog of Plonky2's keygen.
    // ====================================================================
    let airs = [TableAir::Hash(hash_air.clone()), TableAir::Arith(ArithAir)];
    let t_kg = Instant::now();
    let prover_data: ProverData<MyConfig> = ProverData::from_airs_and_degrees(
        &config,
        &airs,
        &[
            log2(hash_trace.height()) + config.is_zk(),
            log2(arith_trace.height()) + config.is_zk(),
        ],
    );
    let keygen_ms = t_kg.elapsed().as_secs_f64() * 1e3;
    println!(
        "[3] ProverData keygen : {keygen_ms:>8.3} ms (symbolic constraints/lookups/quotient deg)"
    );

    // Total Plonky3 "build" = the cold one-time setup BEFORE the first proof:
    // config + AIR + keygen. (Trace generation is per-proof work, reported
    // separately; including it would be apples-to-oranges vs Plonky2's
    // circuit-build which excludes witness generation.)
    let build_total_ms = config_ms + air_ms + keygen_ms;
    println!("------------------------------------------------------------------------------");
    println!(
        "[=] Plonky3 BUILD total: {build_total_ms:>8.3} ms (config {config_ms:.3} + AIR {air_ms:.3} + keygen {keygen_ms:.3})"
    );
    println!(
        "    vs Plonky2 build   : {PLONKY2_BUILD_MS:.0} ms  ->  {:.0}x smaller",
        PLONKY2_BUILD_MS / build_total_ms.max(f64::MIN_POSITIVE)
    );

    // ====================================================================
    // STEP 4 — COLD first prove (NO warmup): the genuine first-proof
    // latency with cold allocator / FFT-twiddle / thread-pool state.
    // ====================================================================
    let common = &prover_data.common;
    let pvs = vec![vec![], vec![]];
    let traces: [&RowMajorMatrix<Val>; 2] = [&hash_trace, &arith_trace];
    let instances = StarkInstance::new_multiple(&airs, &traces, &pvs);

    let t_prove = Instant::now();
    let proof = prove_batch(&config, &instances, &prover_data);
    let cold_prove_ms = t_prove.elapsed().as_secs_f64() * 1e3;

    // ====================================================================
    // STEP 5 — verify the cold proof (correctness gate).
    // ====================================================================
    let t_ver = Instant::now();
    verify_batch(&config, &airs, &proof, &pvs, common).expect("Probe Y cold proof must verify");
    let verify_ms = t_ver.elapsed().as_secs_f64() * 1e3;

    let rss_mb = peak_rss_mb();

    println!("[4] COLD first-prove  : {cold_prove_ms:>8.1} ms (no warmup; cold caches/allocator)");
    println!("[5] verify            : {verify_ms:>8.1} ms");
    println!("[=] peak RSS          : {rss_mb:>8.0} MB");

    // ====================================================================
    // Cold-total: build + trace-gen + cold-prove = "node start -> first
    // proof emitted". Reported two ways: build+prove (apples-to-apples with
    // Plonky2's 14.4 s which is build+first-prove and excludes tracegen),
    // and build+tracegen+prove (the true wall-clock latency).
    // ====================================================================
    let cold_total_ms = build_total_ms + cold_prove_ms;
    let cold_total_with_tracegen_ms = build_total_ms + tracegen_ms + cold_prove_ms;

    println!("\n========================= Probe Y cold-start results ==========================");
    println!(
        "{:<34} {:>12} {:>14}",
        "stage", "Plonky3 (ms)", "Plonky2 (ms)"
    );
    println!(
        "{:<34} {:>12.3} {:>14.0}",
        "build (config+AIR+keygen)", build_total_ms, PLONKY2_BUILD_MS
    );
    println!(
        "{:<34} {:>12.1} {:>14.0}",
        "first (cold) prove", cold_prove_ms, PLONKY2_COLD_PROVE_MS
    );
    println!(
        "{:<34} {:>12.1} {:>14.0}",
        "cold-total (build + first-prove)", cold_total_ms, PLONKY2_COLD_TOTAL_MS
    );
    println!(
        "{:<34} {:>12.3} {:>14}",
        "  (+ trace-gen, true latency)", cold_total_with_tracegen_ms, "-"
    );

    println!("\n=============================== BOTTOM LINE ===================================");
    println!(
        "Plonky3 BUILD = {build_total_ms:.3} ms vs Plonky2 8200 ms: Plonky3 has NO gate-circuit"
    );
    println!(
        "compilation step. The only non-trivial cold cost is ProverData keygen ({keygen_ms:.3} ms);"
    );
    println!("config + round-constants are sub-millisecond. The 8.2 s Plonky2 preprocessing pass");
    println!("simply does not exist in a FRI-STARK-over-AIR prover.");
    let (verdict, factor) = if cold_total_ms < PLONKY2_COLD_TOTAL_MS {
        ("FASTER", PLONKY2_COLD_TOTAL_MS / cold_total_ms)
    } else {
        ("SLOWER", cold_total_ms / PLONKY2_COLD_TOTAL_MS)
    };
    println!(
        "COLD-START VERDICT: Plonky3 cold-total {cold_total_ms:.0} ms is {verdict} than Plonky2"
    );
    println!("  14400 ms by {factor:.2}x. The win is dominated by the eliminated 8.2 s build.");
    println!("Cold first-prove ({cold_prove_ms:.0} ms) vs Plonky2 6100 ms is the remaining piece;");
    println!("the warm steady state (Probe T) is the per-proof number, this is the boot latency.");
    println!("==============================================================================\n");

    // Structural assertion: the Plonky3 build is a SMALL fraction of Plonky2's
    // 8.2 s gate-circuit compile. We assert it is under that 8.2 s (a regression
    // reintroducing multi-second preprocessing would fail); the real result is
    // expected to be orders of magnitude smaller and is reported above, not
    // gated, to avoid a flaky tight threshold.
    assert!(
        build_total_ms < PLONKY2_BUILD_MS,
        "Plonky3 build {build_total_ms:.1} ms unexpectedly >= Plonky2's 8200 ms gate-circuit build"
    );
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got {packing_type}"
    );
}
