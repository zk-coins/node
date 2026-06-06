//! Probe Z — prove-vs-VERIFY asymmetry + on-chain / recursive verifier sketch.
//!
//! # What this probe measures
//!
//! For the Probe T representative circuit (degree-7 Poseidon2 hash table +
//! degree-3 arith table, batched under HidingFriPcs / Keccak-hiding MMCS / FRI
//! `new_benchmark_zk`), it measures the three numbers that characterise the
//! prover/verifier asymmetry of a FRI-STARK:
//!
//! 1. **verify() wall-time** — p50 over several `verify_batch` runs of the
//!    representative proof (warm).
//! 2. **serialized proof size** — the `BatchProof` `bincode`-serialized, in
//!    bytes. This is what the node persists and what a recursion layer must
//!    re-hash and re-check.
//! 3. **prove ÷ verify ratio** — how much cheaper verification is than proving.
//!
//! # Why the asymmetry matters for zkCoins (the on-chain / recursive sketch)
//!
//! ## zkCoins does NOT verify proofs on Bitcoin.
//!
//! This is the load-bearing honesty point and it is cross-referenced from Doc 2
//! (wire/storage format). Bitcoin has no general STARK verifier opcode and
//! zkCoins does not attempt one. The ON-CHAIN footprint of a zkCoins state
//! transition is a **Schnorr-signed inscription** committing to the new state
//! root — a constant-size signature + commitment, NOT a proof verification. The
//! chain witnesses *that a transition was authorised*, not *that the proof is
//! valid*. So "verify cost on Bitcoin" is **N/A by design** — there is no
//! in-consensus verifier to cost.
//!
//! ## Where the verifier actually runs — two places, both measured/cited here.
//!
//! * **(A) Native node-side verify.** The zkCoins node verifies each proof
//!   before accepting/relaying a transition. This is exactly the
//!   `verify_batch` wall-time this probe measures (the p50 below). It runs once
//!   per transition on commodity CPU and is the cheap leg of the asymmetry.
//!
//! * **(B) In-circuit / recursive verify.** zkCoins aggregates transitions by
//!   RECURSION: each layer's circuit *verifies the previous layer's proof
//!   inside the AIR*. That in-circuit verifier is NOT the native verify measured
//!   here — it is a circuit that re-expresses FRI/Merkle/Poseidon2 checks as
//!   constraints, and its cost is the *proving* cost of the next layer. That
//!   cost is quantified by **Probe X** (the full aggregator carrier chain) and
//!   the recursion cost-projection probes (I/R). The relevant takeaway from
//!   THIS probe for recursion is: **every recursion layer pays one verify's
//!   worth of work, re-expressed as constraints**, and it must re-hash a proof
//!   of the size measured below. A small native-verify + a compact proof are
//!   exactly what keep the per-layer recursion overhead bounded.
//!
//! ## Future light-client / on-chain-verification ambition.
//!
//! If zkCoins ever wanted real on-chain or light-client verification (e.g. a
//! covenant-enabled Bitcoin soft-fork, or an EVM/L2 verifier contract), the
//! cost that matters is the native verify measured here PLUS the proof size:
//! a light client downloads the proof (the byte count below) and runs the
//! verifier (the p50 below). A STARK proof is large (tens-to-hundreds of KB)
//! relative to a Groth16 SNARK (~200 B), so a STARK light-client pays in
//! bandwidth, not in verifier time. This probe reports the exact bytes so that
//! tradeoff is grounded in a measured number, not a guess. (A succinct on-chain
//! story would require a final SNARK-wrap layer — out of scope here; flagged.)
//!
//! # Proxy boundary
//!
//! Same as Probe T: cost-faithful representative workload, NOT a semantic port.
//! The verify cost and proof size scale with the committed trace area + FRI
//! query count + proof openings, which this workload reproduces; they do not
//! depend on the business meaning of the constraints.
//!
//! # Verdict policy
//!
//! PASSES on successful measurement + verification. The verify p50, proof size
//! and ratio are REPORTED findings. Hard asserts: the proof verifies, and a
//! TAMPERED proof is rejected (a verifier that accepts garbage is worthless —
//! we corrupt one serialized byte and require `verify_batch` to fail).

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

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

const PROVE_RUNS: usize = 5;
const VERIFY_RUNS: usize = 20;

#[test]
fn probe_z_verifier() {
    let packing_type = core::any::type_name::<<Val as Field>::Packing>();
    let scalar_type = core::any::type_name::<Val>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = rayon::current_num_threads();

    println!("\n============= Probe Z: prove-vs-verify asymmetry + on-chain sketch ============");
    println!("PROXY BOUNDARY: Probe T cost-faithful workload. NOT a semantic port.");
    println!("config: VectorizedPoseidon2Air<SBOX_DEGREE=7> | Keccak-hiding MMCS | HidingFriPcs");
    println!(
        "  num_random_codewords=4 (TRUE ZK) | FRI new_benchmark_zk (blowup=2,100q,16-bit PoW)"
    );
    println!("BabyBear::Packing : {packing_type}  (SIMD active: {packing_active})");
    println!("rayon threads     : {threads}");
    println!("------------------------------------------------------------------------------");

    // --- Build the representative batched proof (the same shape as Probe T's
    // realistic 2^13 anchor). ----------------------------------------------
    let (config, log_blowup) = build_config();
    let hash_air = Arc::new(build_hash_air());
    assert_eq!(log_blowup, 2, "new_benchmark_zk must be blowup-2");

    let hash_perms_capacity = next_pow2(REAL_HASH_PERMS.div_ceil(VECTOR_LEN)) * VECTOR_LEN;
    let hash_trace = hash_air.generate_vectorized_trace_rows(hash_perms_capacity, log_blowup);
    let arith_trace = arith_trace(ARITH_HEIGHT);
    println!(
        "circuit: hash {} rows (degree-7) + arith {} rows (2^{}); batched prove_batch",
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

    // --- Measure PROVE (warm p50) ------------------------------------------
    let _ = prove_batch(&config, &instances, &prover_data); // warmup
    let mut prove_times = Vec::with_capacity(PROVE_RUNS);
    let mut proof: Option<BatchProof<MyConfig>> = None;
    for _ in 0..PROVE_RUNS {
        let t = Instant::now();
        let p = prove_batch(&config, &instances, &prover_data);
        prove_times.push(t.elapsed().as_secs_f64() * 1e3);
        proof = Some(p);
    }
    let proof = proof.unwrap();
    prove_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let prove_p50 = quantile(&prove_times, 0.50);

    // Correctness gate.
    verify_batch(&config, &airs, &proof, &pvs, common).expect("Probe Z proof must verify");

    // --- Measure VERIFY (warm p50 over many runs) --------------------------
    // Verify is fast, so we take more samples for a stable p50.
    let _ = verify_batch(&config, &airs, &proof, &pvs, common); // warmup
    let mut verify_times = Vec::with_capacity(VERIFY_RUNS);
    for _ in 0..VERIFY_RUNS {
        let t = Instant::now();
        verify_batch(&config, &airs, &proof, &pvs, common).expect("verify must succeed");
        verify_times.push(t.elapsed().as_secs_f64() * 1e3);
    }
    verify_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let verify_p50 = quantile(&verify_times, 0.50);
    let verify_p90 = quantile(&verify_times, 0.90);
    let verify_min = verify_times[0];

    // --- Serialized proof size ---------------------------------------------
    let proof_bytes = bincode::serialize(&proof).expect("serialize BatchProof");
    let proof_len = proof_bytes.len();

    // Round-trip + tampering check (verifier soundness gate).
    let proof_rt: BatchProof<MyConfig> =
        bincode::deserialize(&proof_bytes).expect("deserialize BatchProof");
    verify_batch(&config, &airs, &proof_rt, &pvs, common).expect("round-tripped proof must verify");

    // Corrupt one byte in the middle of the blob; the deserialized proof must
    // fail to verify (or fail to deserialize). A verifier that accepts a
    // tampered proof is unsound.
    let mut tampered = proof_bytes.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xFF;
    let tamper_rejected = match bincode::deserialize::<BatchProof<MyConfig>>(&tampered) {
        Ok(bad) => verify_batch(&config, &airs, &bad, &pvs, common).is_err(),
        Err(_) => true, // failed to deserialize == rejected
    };

    // --- prove / verify ratio ----------------------------------------------
    let ratio = prove_p50 / verify_p50;

    println!("\n========================= Probe Z results ====================================");
    println!("prove  warm p50  : {prove_p50:>10.2} ms (batched, both tables)");
    println!(
        "verify warm p50  : {verify_p50:>10.2} ms  (p90 {verify_p90:.2} / min {verify_min:.2})"
    );
    println!("prove / verify   : {ratio:>10.1}x  (verify is {ratio:.0}x cheaper than prove)");
    println!(
        "proof size       : {proof_len:>10} bytes ({:.1} KB, bincode of BatchProof)",
        proof_len as f64 / 1024.0
    );
    println!("tamper rejected  : {tamper_rejected} (1-byte corruption must fail verify)");

    println!("\n============== on-chain / recursive verifier sketch (HONEST) =================");
    println!("zkCoins does NOT verify proofs on Bitcoin. On-chain = a Schnorr inscription");
    println!("committing the new state root (constant-size sig+commitment, see Doc 2). There is");
    println!("NO in-consensus STARK verifier to cost: on-chain verify cost = N/A by design.");
    println!("The verifier runs in TWO places:");
    println!("  (A) NATIVE node-side verify : {verify_p50:.2} ms per transition (measured above).");
    println!("      Cheap leg of the asymmetry; runs once per accepted/relayed transition.");
    println!("  (B) IN-CIRCUIT / recursive verify : each recursion layer re-expresses FRI/Merkle/");
    println!("      Poseidon2 checks as constraints and PROVES them -> its cost is the next");
    println!("      layer's PROVING cost (quantified by Probe X + cost-projection I/R), NOT the");
    println!("      native verify here. Takeaway for recursion: every layer pays ~one verify's");
    println!(
        "      work as constraints AND must re-hash a {:.0} KB proof. Compact proof + cheap",
        proof_len as f64 / 1024.0
    );
    println!("      native verify keep per-layer recursion overhead bounded.");
    println!("Future light-client / on-chain ambition: a light client downloads the proof");
    println!(
        "  ({proof_len} B) and runs the verifier ({verify_p50:.2} ms). STARK proofs are LARGE vs a"
    );
    println!("  ~200 B Groth16 SNARK, so the cost is BANDWIDTH not verifier-time. Real succinct");
    println!(
        "  on-chain verification would need a final SNARK-wrap layer (out of scope, flagged)."
    );
    println!("==============================================================================\n");

    // Hard asserts: the verifier is sound on this proof.
    assert!(
        verify_p50 > 0.0,
        "verify must have measured a positive time"
    );
    assert!(proof_len > 0, "serialized proof must be non-empty");
    assert!(
        tamper_rejected,
        "verifier accepted a tampered proof — UNSOUND"
    );
    assert!(
        ratio > 1.0,
        "expected prove to cost more than verify (asymmetry), got ratio {ratio:.2}"
    );
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got {packing_type}"
    );
}
