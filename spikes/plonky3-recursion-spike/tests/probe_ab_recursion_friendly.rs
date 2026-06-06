//! Probe AB — can a **recursion-friendly** config pull the 8+1 source
//! aggregation STARK-prove (Probe X: 4.0 s non-zk / 6.7 s zk) out of the
//! wash, so `/api/send` clears Plonky2?
//!
//! Probe X measured the production fan-in (8 source carriers + 1 predecessor /
//! IVC carrier) recursion-overhead STARK-prove and found it DOMINATES the full
//! populated `/api/send` prove — erasing the Probe-T single-transition win and
//! making the migration a wash/loss on speed. Probe AB tests three independent
//! recursion-friendliness levers against the exact Probe-X baseline, then a
//! combined best-config, with REAL proving and HONEST numbers — including
//! levers that turn out not to help, and configs that won't verify.
//!
//! # Lever 1 — circuit-friendly inner hash (Poseidon2-MMCS vs Keccak-MMCS)
//!
//! The brief's hypothesis: Probe X's inner carrier proofs commit with a Keccak
//! MMCS, and the in-circuit `verify_batch_circuit` RE-COMPUTES that hash for
//! every Merkle opening; in-circuit Keccak is ~10-50x more constraints than
//! in-circuit Poseidon2, so switching the inner MMCS to a field-native
//! Poseidon2 hash should be the dominant win.
//!
//! **Finding (measured + read from the stack): this win is ALREADY BANKED, and
//! a Keccak inner MMCS is not even verifiable by this recursion verifier.**
//!
//!   * Probe X's inner carrier config (`MyMmcs`) is
//!     `MerkleTreeMmcs<.., PaddingFreeSponge<Poseidon2BabyBear<16>, ..>, ..>` —
//!     i.e. a **Poseidon2** field-native MMCS, NOT Keccak. The 8+1 baseline
//!     already commits its inner proofs with Poseidon2.
//!   * The in-circuit verifier (`verify_batch_circuit`,
//!     `FriVerifierParams::with_mmcs(.., Poseidon2Config::BABY_BEAR_D4_W16)`)
//!     recomputes openings with the in-circuit **Poseidon2** permutation table
//!     (`p3-poseidon2-circuit-air`). The recursion stack hardwires this: the
//!     in-circuit MMCS recomputation (`recursion/src/pcs/mmcs.rs`) is written
//!     against a `PermConfig` (Poseidon1/Poseidon2) only — there is no
//!     in-circuit Keccak MMCS gadget. A Keccak-MMCS inner proof therefore
//!     CANNOT be verified by `verify_batch_circuit` at all (the verifier would
//!     have no gadget to recompute the leaf hashes against). That is a
//!     **blocker**, reported precisely below, not a measurable lever.
//!
//! So Lever 1's win is real in the GENERAL recursion-design sense (a hypothetical
//! Keccak-inner recursion would be far costlier in-circuit), but for THIS stack
//! the cost was never paid: the baseline is the Poseidon2-MMCS config. Probe AB
//! confirms the in-circuit hash the baseline uses is Poseidon2 and reports the
//! Keccak path as a non-verifying config. The dominant win Lever 1 chases is the
//! Probe-X baseline itself — there is no further headroom on this axis.
//!
//! # Lever 2 — ZK-only-outer (non-hiding inner verifications)
//!
//! The 8 inner source verifications do NOT need to be zero-knowledge — only the
//! final OUTER proof on the public record does. Probe X's "zk" row was a
//! blowup-2 *proxy* (`new_benchmark_zk` on the plain, non-hiding `TwoAdicFriPcs`
//! inner): it inflated the inner-proof blowup to 2 as a ZK timing stand-in. The
//! recursion architecture (`recursion/tests/zk_aggregation.rs`) is exactly
//! "ZK-only-outer": inner proofs are produced, their verification circuits
//! composed, and the OUTER aggregation proof is what carries (or doesn't carry)
//! hiding. This probe measures the cost a TRUE hiding inner (`HidingFriPcs`
//! over the same Poseidon2 MMCS, `num_random_codewords = 4` random masking
//! codewords — the upstream recursion ZK shape) ADDS to the aggregation
//! versus the non-hiding inner — i.e. the cost ZK-only-outer SAVES by keeping
//! the 8+1 inner verifications non-hiding. The non-hiding-inner figure is the
//! Probe-X non-zk baseline; the saving is `(hiding-inner) - (non-hiding-inner)`.
//!
//!   * `[VERIFY]` SOUNDNESS (Doc 3): non-hiding inner layers under a hiding
//!     outer is the standard recursion shape, but Doc 3 lists "zk-soundness of
//!     non-hiding inner layers" as `[VERIFY]`. Probe AB MEASURES the cost; an
//!     auditor must sign off that a non-hiding inner composed under a hiding
//!     outer leaks nothing about the witness before deployment.
//!
//! # Lever 3 — cheaper inner FRI (fewer queries on the recursed proofs)
//!
//! The inner proofs' FRI `num_queries` determines how many Merkle openings the
//! in-circuit verifier must recompute+check, which is the dominant in-circuit
//! (and therefore STARK-proved) area. The outer proof keeps full strength
//! (`new_benchmark`, 116 conjectured bits). The inner proofs use a lighter FRI
//! (fewer queries). Conjectured soundness bits (ethSTARK):
//!   `bits = log_blowup * num_queries + query_pow_bits`.
//!   * baseline inner = `new_benchmark`: 1*100 + 16 = **116 bits**.
//!   * inner @ 48 queries: 1*48 + 16 = **64 bits**.
//!   * inner @ 30 queries: 1*30 + 16 = **46 bits**.
//!
//!   * `[VERIFY]` SOUNDNESS: a recursion INNER layer can in principle run at
//!     fewer bits than the outer if the composition argument shows the outer
//!     proof's soundness dominates the end-to-end bound. Probe AB reports the
//!     cost reduction AND the inner-layer bit level at each setting; the auditor
//!     must clear the composition argument (`[VERIFY]`) before any sub-100-bit
//!     inner FRI ships. 64-bit inner is a plausible recursion setting; 46-bit is
//!     reported as a cost-floor data point, NOT a deployment recommendation.
//!
//! # Combined best config
//!
//! Poseidon2-inner-MMCS (already the baseline) + ZK-only-outer (non-hiding
//! inner, the baseline non-zk inner) + cheaper-inner-FRI (48-query inner, 64-bit
//! `[VERIFY]`), aggregated under a full-strength non-hiding outer. Reported as
//! the recursion-friendly floor for the 8+1 aggregation.
//!
//! # What is measured
//!
//! For each config: 8+1 aggregator recursion-circuit STARK-prove warm p50/p90
//! over >= 5 runs after warmup, cold prove, build wall-time, peak RSS
//! (`getrusage`). Every proof is verified (hard gate). Packing type + thread
//! count printed. Reduction factor vs the Probe-X baseline and the recomposed
//! `/api/send` estimate are reported per config.
//!
//! # Recomposition
//!
//! `/api/send` ~= Probe T transition (0.31 s) + AB aggregation prove + node
//! overhead (5.6 s), vs Plonky2 ~10 s live / 4.35 s warm single-prove.
//!
//! # The honest verdict
//!
//! Stated plainly at the end: does the combined recursion-friendly config pull
//! `/api/send` clearly under Plonky2, and by how much — or is the dominant win
//! (Lever 1) already banked in the Probe-X baseline, leaving only the modest
//! query-count and the ZK-only-outer savings, which do NOT change the verdict?
//! The test PASSES on successful measurement + verification regardless of the
//! speed outcome.

use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_batch_stark::{
    BatchProof, ProverData, StarkGenericConfig, StarkInstance, prove_batch, verify_batch,
};
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
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
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::{
    HidingFriProofTargets, InputProofTargets, MerkleCapTargets, RecValMmcs,
};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness, set_fri_mmcs_private_data};
use p3_recursion::{
    BatchStarkVerifierInputsBuilder, FriVerifierParams, Poseidon2Config, verify_batch_circuit,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::SmallRng;

// --------------------------------------------------------------------------
// BabyBear recursion config — Poseidon2 field-native MMCS for the inner carrier
// proofs (NOT Keccak). This is the SAME `MyMmcs` Probe X uses, made explicit
// here to document Lever 1's finding: the inner hash the in-circuit verifier
// recomputes is already Poseidon2.
// --------------------------------------------------------------------------
type F = BabyBear;
const D: usize = 4;
const WIDTH: usize = 16;
const RATE: usize = 8;
const DIGEST_ELEMS: usize = 8;
type Challenge = BinomialExtensionField<F, D>;
type Dft = Radix2DitParallel<F>;
type Perm = Poseidon2BabyBear<WIDTH>;
/// Field-native Poseidon2 sponge hash — the circuit-friendly inner hash.
type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
/// Poseidon2 Merkle MMCS (Lever 1: already field-native, not Keccak).
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

/// Non-hiding inner-proof FRI target type (Lever 2: ZK-only-outer keeps inner
/// non-hiding; this is the baseline inner shape).
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

// --- Hiding (true ZK) inner config — Lever 2's "cost of ZK-on-inner" arm. ----
// Same Poseidon2 hash family AND the same `MyMmcs` Merkle MMCS; the ONLY
// difference vs the non-hiding inner is `HidingFriPcs` (which adds random
// masking codewords) instead of `TwoAdicFriPcs`. This matches the upstream
// recursion ZK shape (`recursion/tests/zk_aggregation.rs`): hiding is achieved
// by the PCS, not by a hiding MMCS, so the in-circuit verifier reuses the same
// `RecValMmcs` recompute path.
type HidingPcs = HidingFriPcs<F, Dft, MyMmcs, ChallengeMmcs, SmallRng>;
type HidingConfig = StarkConfig<HidingPcs, Challenge, Challenger>;

/// Hiding inner-proof FRI target type — wraps the non-hiding inner FRI proof
/// targets plus the random-opened-values the hiding PCS adds.
type InnerFriHiding = HidingFriProofTargets<
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

/// Inner-proof FRI configuration for the recursed (inner) carrier proofs.
/// The OUTER aggregation proof is always full-strength non-hiding `new_benchmark`.
#[derive(Clone, Copy)]
struct InnerFriCfg {
    /// FRI `num_queries` for the inner proofs (the in-circuit-opening driver).
    num_queries: usize,
    /// FRI `log_blowup` for the inner proofs.
    log_blowup: usize,
    /// Query proof-of-work bits.
    query_pow_bits: usize,
    /// Commit proof-of-work bits.
    commit_pow_bits: usize,
    /// `log_final_poly_len`.
    log_final_poly_len: usize,
    /// Human label.
    label: &'static str,
}

impl InnerFriCfg {
    /// The Probe-X non-zk baseline inner FRI: `new_benchmark` (blowup-1, 100
    /// queries, 16-bit query PoW => 116 conjectured bits).
    const BASELINE: Self = Self {
        num_queries: 100,
        log_blowup: 1,
        query_pow_bits: 16,
        commit_pow_bits: 0,
        log_final_poly_len: 0,
        label: "baseline new_benchmark (blowup=1, q=100, 116-bit)",
    };

    /// Cheaper inner FRI: 48 queries (1*48 + 16 = 64 conjectured bits). A
    /// plausible recursion-inner setting if the composition argument holds.
    const Q48: Self = Self {
        num_queries: 48,
        label: "cheaper inner FRI (blowup=1, q=48, 64-bit [VERIFY])",
        ..Self::BASELINE
    };

    /// Cost-floor data point: 30 queries (1*30 + 16 = 46 bits). Reported for the
    /// curve shape, NOT a deployment recommendation.
    const Q30: Self = Self {
        num_queries: 30,
        label: "cost-floor inner FRI (blowup=1, q=30, 46-bit [VERIFY])",
        ..Self::BASELINE
    };

    fn conjectured_bits(&self) -> usize {
        self.log_blowup * self.num_queries + self.query_pow_bits
    }

    /// Build a concrete (non-hiding) `FriParameters` from this config.
    fn fri_params(&self, mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
        FriParameters {
            log_blowup: self.log_blowup,
            log_final_poly_len: self.log_final_poly_len,
            max_log_arity: 1,
            num_queries: self.num_queries,
            commit_proof_of_work_bits: self.commit_pow_bits,
            query_proof_of_work_bits: self.query_pow_bits,
            mmcs,
        }
    }

    /// Build a concrete hiding `FriParameters` from this config (reuses the
    /// same `ChallengeMmcs` as the non-hiding path; hiding is in the PCS).
    fn fri_params_hiding(&self, mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
        FriParameters {
            log_blowup: self.log_blowup,
            log_final_poly_len: self.log_final_poly_len,
            max_log_arity: 1,
            num_queries: self.num_queries,
            commit_proof_of_work_bits: self.commit_pow_bits,
            query_proof_of_work_bits: self.query_pow_bits,
            mmcs,
        }
    }
}

/// Build a non-hiding BabyBear `MyConfig` under the given inner FRI config.
fn make_config(cfg: &InnerFriCfg) -> MyConfig {
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = MyMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = cfg.fri_params(challenge_mmcs);
    let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
    MyConfig::new(pcs, Challenger::new(perm))
}

/// Build a hiding (true ZK) BabyBear config under the given inner FRI config.
fn make_hiding_config(cfg: &InnerFriCfg) -> HidingConfig {
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = MyMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = cfg.fri_params_hiding(challenge_mmcs);
    // num_random_codewords = 4 (matches Probe W's true-ZK arm).
    let pcs = HidingPcs::new(
        Dft::default(),
        val_mmcs,
        fri_params,
        4,
        SmallRng::seed_from_u64(0xAB02),
    );
    HidingConfig::new(pcs, Challenger::new(perm))
}

/// In-circuit FRI verifier params matching the inner FRI config, with real MMCS
/// verification (`with_mmcs`, Poseidon2 — Lever 1: field-native, the only
/// in-circuit hash the recursion verifier supports). The scalar knobs do NOT
/// include `num_queries`: the in-circuit verifier processes whatever number of
/// query openings the proof actually carries, so the cheaper-inner-FRI lever
/// (fewer queries) is driven entirely by the inner proof shape.
fn fri_verifier_params(cfg: &InnerFriCfg) -> FriVerifierParams {
    FriVerifierParams::with_mmcs(
        cfg.log_blowup,
        cfg.log_final_poly_len,
        cfg.commit_pow_bits,
        cfg.query_pow_bits,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
}

// --------------------------------------------------------------------------
// CarrierAir — Probe R/X two-public-value carrier `[v_in, v_out]` with
// `v_out == v_in + 1`. The inner proof the recursion circuit verifies.
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

fn air_slice(air: &CarrierAir) -> [CarrierAir; 1] {
    [*air]
}

// ==========================================================================
// NON-HIDING inner path (baseline + cheaper-inner-FRI + combined).
// ==========================================================================

/// A non-hiding inner carrier proof + everything the recursion circuit needs.
struct Layer {
    proof: BatchProof<MyConfig>,
    air: CarrierAir,
    pvs: [Vec<F>; 1],
    prover_data: ProverData<MyConfig>,
}

impl Layer {
    fn common(&self) -> &p3_batch_stark::CommonData<MyConfig> {
        &self.prover_data.common
    }
}

/// Prove one honest non-hiding carrier layer.
fn prove_layer(config: &MyConfig, v: F, rows: usize) -> Layer {
    let air = CarrierAir { rows };
    let trace = air.honest_trace(v);
    let pvs = [vec![v, v + F::ONE]];
    let instances = vec![StarkInstance {
        air: &air,
        trace: &trace,
        public_values: pvs[0].clone(),
    }];
    let prover_data = ProverData::from_instances(config, &instances);
    let proof = prove_batch(config, &instances, &prover_data);
    verify_batch(config, &air_slice(&air), &proof, &pvs, &prover_data.common)
        .expect("native carrier verify (non-hiding inner)");
    Layer {
        proof,
        air,
        pvs,
        prover_data,
    }
}

type Vi = BatchStarkVerifierInputsBuilder<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>;

/// Allocate one non-hiding carrier proof into `cb` and run `verify_batch_circuit`.
fn add_carrier_verifier(
    config: &MyConfig,
    vparams: &FriVerifierParams,
    cb: &mut CircuitBuilder<Challenge>,
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
    let mmcs_op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
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
    .expect("build carrier verifier (Poseidon2 MMCS)");
    (vi, mmcs_op_ids)
}

/// Set FRI MMCS private data for one non-hiding inner proof.
fn set_mmcs_for(
    runner: &mut p3_circuit::CircuitRunner<'_, Challenge>,
    op_ids: &[NonPrimitiveOpId],
    layer: &Layer,
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
        &layer.proof.opening_proof,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .expect("set MMCS private data (non-hiding)");
}

// ==========================================================================
// HIDING inner path (Lever 2: cost of ZK-on-inner, the cost ZK-only-outer saves).
// ==========================================================================

/// A hiding (true ZK) inner carrier proof.
struct HidingLayer {
    proof: BatchProof<HidingConfig>,
    air: CarrierAir,
    pvs: [Vec<F>; 1],
    prover_data: ProverData<HidingConfig>,
}

impl HidingLayer {
    fn common(&self) -> &p3_batch_stark::CommonData<HidingConfig> {
        &self.prover_data.common
    }
}

/// Prove one honest hiding carrier layer.
fn prove_layer_hiding(config: &HidingConfig, v: F, rows: usize) -> HidingLayer {
    let air = CarrierAir { rows };
    let trace = air.honest_trace(v);
    let pvs = [vec![v, v + F::ONE]];
    let instances = vec![StarkInstance {
        air: &air,
        trace: &trace,
        public_values: pvs[0].clone(),
    }];
    let prover_data = ProverData::from_instances(config, &instances);
    let proof = prove_batch(config, &instances, &prover_data);
    verify_batch(config, &air_slice(&air), &proof, &pvs, &prover_data.common)
        .expect("native carrier verify (hiding inner)");
    HidingLayer {
        proof,
        air,
        pvs,
        prover_data,
    }
}

type ViHiding = BatchStarkVerifierInputsBuilder<
    HidingConfig,
    MerkleCapTargets<F, DIGEST_ELEMS>,
    InnerFriHiding,
>;

/// Allocate one hiding carrier proof into `cb` and run `verify_batch_circuit`.
fn add_carrier_verifier_hiding(
    config: &HidingConfig,
    vparams: &FriVerifierParams,
    cb: &mut CircuitBuilder<Challenge>,
    layer: &HidingLayer,
) -> (ViHiding, Vec<NonPrimitiveOpId>) {
    let lookup_gadget = LogUpGadget::new();
    let air_public_counts = vec![2usize];
    let vi = ViHiding::allocate(cb, &layer.proof, layer.common(), &air_public_counts);
    assert_eq!(vi.air_public_targets.len(), 1, "one carrier instance");
    assert_eq!(vi.air_public_targets[0].len(), 2, "two public values");
    let mmcs_op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
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
    .expect("build carrier verifier (hiding inner)");
    (vi, mmcs_op_ids)
}

/// Set FRI MMCS private data for one hiding inner proof. The hiding PCS opening
/// proof is `(random_opened_values, inner_fri_proof)`; pass the inner part `.1`.
fn set_mmcs_for_hiding(
    runner: &mut p3_circuit::CircuitRunner<'_, Challenge>,
    op_ids: &[NonPrimitiveOpId],
    layer: &HidingLayer,
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
        &layer.proof.opening_proof.1,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .expect("set MMCS private data (hiding)");
}

/// Production fan-in: 8 source in-coin slots + 1 predecessor (IVC) carrier.
const MAX_IN_COINS: usize = 8;

/// Result of building + STARK-proving the aggregator recursion circuit.
struct ProveResult {
    build_ms: f64,
    cold_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    rss_mb: f64,
    witness_count: usize,
}

/// Shared outer-prove machinery: given the built circuit, compiled tables and
/// packed inputs (closure producing fresh traces), STARK-prove warm/cold and
/// return timings. Outer proof is always full-strength non-hiding.
fn measure_outer_prove(
    circuit: &p3_circuit::Circuit<Challenge>,
    run_witness: impl Fn() -> p3_circuit::Traces<Challenge>,
    build_ms: f64,
    witness_count: usize,
) -> ProveResult {
    let outer_cfg = InnerFriCfg::BASELINE; // outer = full strength, non-hiding.
    let config = make_config(&outer_cfg);
    let table_packing = TablePacking::new(1, 8);
    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::default()),
    ];
    let mut air_builders = poseidon2_air_builders::<_, D>();
    air_builders.extend(recompose_air_builders(1, false));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<MyConfig, _, D>(
            circuit,
            &table_packing,
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("airs and degrees for aggregator");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &ext_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover =
        BatchStarkProver::new(make_config(&outer_cfg)).with_table_packing(table_packing);
    prover.register_poseidon2_table::<D>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<D>(false);

    // cold prove + verify.
    let traces = run_witness();
    let t_cold = Instant::now();
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("STARK-prove aggregator recursion circuit");
    let cold_ms = t_cold.elapsed().as_secs_f64() * 1e3;
    prover
        .verify_all_tables(&proof)
        .expect("verify aggregator recursion proof");

    // warmup.
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
    }
}

/// Build the fan-in `8 + 1` aggregator recursion circuit with NON-HIDING inner
/// proofs at inner FRI `cfg`, then STARK-PROVE it (outer = full strength).
/// Covers: baseline (cfg = BASELINE), cheaper-inner-FRI (Q48/Q30), combined.
fn prove_aggregator_nonhiding(cfg: &InnerFriCfg, inner_rows: usize) -> ProveResult {
    let config = make_config(cfg);
    let vparams = fri_verifier_params(cfg);

    // inner carrier proofs: 1 predecessor + 8 sources.
    let predecessor = prove_layer(&config, F::from_u32(100), inner_rows);
    let sources: Vec<Layer> = (0..MAX_IN_COINS)
        .map(|i| prove_layer(&config, F::from_u32(200 + i as u32), inner_rows))
        .collect();

    let t_build = Instant::now();
    let perm = default_babybear_poseidon2_16();
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let (pred_vi, pred_op_ids) = add_carrier_verifier(&config, &vparams, &mut cb, &predecessor);

    let mut source_vis = Vec::with_capacity(MAX_IN_COINS);
    let mut source_op_ids = Vec::with_capacity(MAX_IN_COINS);
    let mut active_inputs = Vec::with_capacity(MAX_IN_COINS);
    for (i, src) in sources.iter().enumerate() {
        let (src_vi, src_ids) = add_carrier_verifier(&config, &vparams, &mut cb, src);
        let v_out = src_vi.air_public_targets[0][1];
        let active = cb.alloc_public_input("active");
        cb.assert_bool(active);
        let expected = cb.alloc_const(Challenge::from(F::from_u32(201 + i as u32)), "expected");
        let masked = cb.select(active, expected, v_out);
        cb.connect(v_out, masked);
        source_vis.push(src_vi);
        source_op_ids.push(src_ids);
        active_inputs.push(active);
    }

    // IVC carry (cost-faithful select+connect, value-semantics proven in Probe R).
    let pred_v_out = pred_vi.air_public_targets[0][1];
    let src0_v_in = source_vis[0].air_public_targets[0][0];
    let carry = cb.select(active_inputs[0], src0_v_in, pred_v_out);
    let _ = carry;

    let circuit = cb.build().expect("aggregator circuit builds");
    let build_ms = t_build.elapsed().as_secs_f64() * 1e3;
    let witness_count = circuit.public_flat_len;

    // pack inputs: all 8 source slots active (worst case).
    let (mut pubs, mut privs) =
        pred_vi.pack_values(&predecessor.pvs, &predecessor.proof, predecessor.common());
    for (i, src_vi) in source_vis.iter().enumerate() {
        let (s_pub, s_priv) =
            src_vi.pack_values(&sources[i].pvs, &sources[i].proof, sources[i].common());
        pubs.extend(s_pub);
        privs.extend(s_priv);
        pubs.push(Challenge::ONE); // active = 1 for every slot.
    }

    let run_witness = || {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&pubs).expect("set pub");
        runner.set_private_inputs(&privs).expect("set priv");
        set_mmcs_for(&mut runner, &pred_op_ids, &predecessor);
        for (i, ids) in source_op_ids.iter().enumerate() {
            set_mmcs_for(&mut runner, ids, &sources[i]);
        }
        runner.run().expect("aggregator witness-gen")
    };

    measure_outer_prove(&circuit, run_witness, build_ms, witness_count)
}

/// Build the fan-in `8 + 1` aggregator with HIDING (true ZK) inner proofs at
/// inner FRI `cfg`, then STARK-PROVE it (outer = full strength non-hiding).
/// Lever 2's "cost of ZK-on-inner" arm: the cost ZK-only-outer SAVES.
fn prove_aggregator_hiding(cfg: &InnerFriCfg, inner_rows: usize) -> ProveResult {
    let config = make_hiding_config(cfg);
    let vparams = fri_verifier_params(cfg);

    let predecessor = prove_layer_hiding(&config, F::from_u32(100), inner_rows);
    let sources: Vec<HidingLayer> = (0..MAX_IN_COINS)
        .map(|i| prove_layer_hiding(&config, F::from_u32(200 + i as u32), inner_rows))
        .collect();

    let t_build = Instant::now();
    let perm = default_babybear_poseidon2_16();
    let mut cb = CircuitBuilder::new();
    cb.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    cb.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let (pred_vi, pred_op_ids) =
        add_carrier_verifier_hiding(&config, &vparams, &mut cb, &predecessor);

    let mut source_vis = Vec::with_capacity(MAX_IN_COINS);
    let mut source_op_ids = Vec::with_capacity(MAX_IN_COINS);
    let mut active_inputs = Vec::with_capacity(MAX_IN_COINS);
    for (i, src) in sources.iter().enumerate() {
        let (src_vi, src_ids) = add_carrier_verifier_hiding(&config, &vparams, &mut cb, src);
        let v_out = src_vi.air_public_targets[0][1];
        let active = cb.alloc_public_input("active");
        cb.assert_bool(active);
        let expected = cb.alloc_const(Challenge::from(F::from_u32(201 + i as u32)), "expected");
        let masked = cb.select(active, expected, v_out);
        cb.connect(v_out, masked);
        source_vis.push(src_vi);
        source_op_ids.push(src_ids);
        active_inputs.push(active);
    }

    let pred_v_out = pred_vi.air_public_targets[0][1];
    let src0_v_in = source_vis[0].air_public_targets[0][0];
    let carry = cb.select(active_inputs[0], src0_v_in, pred_v_out);
    let _ = carry;

    let circuit = cb.build().expect("hiding aggregator circuit builds");
    let build_ms = t_build.elapsed().as_secs_f64() * 1e3;
    let witness_count = circuit.public_flat_len;

    let (mut pubs, mut privs) =
        pred_vi.pack_values(&predecessor.pvs, &predecessor.proof, predecessor.common());
    for (i, src_vi) in source_vis.iter().enumerate() {
        let (s_pub, s_priv) =
            src_vi.pack_values(&sources[i].pvs, &sources[i].proof, sources[i].common());
        pubs.extend(s_pub);
        privs.extend(s_priv);
        pubs.push(Challenge::ONE);
    }

    let run_witness = || {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&pubs).expect("set pub");
        runner.set_private_inputs(&privs).expect("set priv");
        set_mmcs_for_hiding(&mut runner, &pred_op_ids, &predecessor);
        for (i, ids) in source_op_ids.iter().enumerate() {
            set_mmcs_for_hiding(&mut runner, ids, &sources[i]);
        }
        runner.run().expect("hiding aggregator witness-gen")
    };

    measure_outer_prove(&circuit, run_witness, build_ms, witness_count)
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
// Composition anchors (from Probe X / the migration research).
// --------------------------------------------------------------------------
/// Probe X non-zk baseline aggregation prove (8+1), ms.
const PROBE_X_NONZK_MS: f64 = 4000.0;
/// Probe X zk (blowup-2 proxy) baseline aggregation prove, ms.
const PROBE_X_ZK_MS: f64 = 6700.0;
/// Probe T single state-transition warm-prove, ms.
const PROBE_T_TRANSITION_MS: f64 = 312.0;
/// Plonky3 node overhead (non-prove) on a populated `/api/send`, ms.
const NODE_OVERHEAD_MS: f64 = 5600.0;
/// Plonky2 warm single-prove baseline, ms.
const PLONKY2_WARM_MS: f64 = 4350.0;
/// Plonky2 live populated `/api/send`, ms.
const PLONKY2_LIVE_SEND_MS: f64 = 10_000.0;

/// Recomposed `/api/send` estimate = Probe T transition + AB aggregation +
/// node overhead.
fn recomposed_send_ms(aggregation_ms: f64) -> f64 {
    PROBE_T_TRANSITION_MS + aggregation_ms + NODE_OVERHEAD_MS
}

#[test]
fn probe_ab_recursion_friendly() {
    let packing_type = core::any::type_name::<<F as Field>::Packing>();
    let scalar_type = core::any::type_name::<F>();
    let packing_active = packing_type != scalar_type && !packing_type.ends_with("BabyBear");
    let threads = rayon::current_num_threads();

    println!("\n===== Probe AB: recursion-friendly 8+1 aggregation (vs Probe X baseline) =====");
    println!("shape          : 1 predecessor (IVC) carrier + {MAX_IN_COINS} source carriers,");
    println!("                 flat single-layer verify_batch_circuit + active masks + IVC carry.");
    println!(
        "stage measured : STARK-PROVE of the recursion circuit (prove_all_tables, low-level)."
    );
    println!("inner hash     : Poseidon2 field-native MMCS (Lever 1: already circuit-friendly).");
    println!("in-circuit hash: Poseidon2 (BABY_BEAR_D4_W16) — the ONLY hash the recursion");
    println!("                 verifier supports; a Keccak inner MMCS is NOT verifiable here.");
    println!("BabyBear::Packing : {packing_type}");
    println!("  -> SIMD packing active: {packing_active} (vs scalar {scalar_type})");
    println!("rayon threads     : {threads}");
    println!(
        "Probe X baseline  : {PROBE_X_NONZK_MS:.0} ms non-zk / {PROBE_X_ZK_MS:.0} ms zk (8+1 aggregation)"
    );
    println!(
        "Plonky2 anchors   : {PLONKY2_WARM_MS:.0} ms warm single / {PLONKY2_LIVE_SEND_MS:.0} ms live /api/send"
    );

    // Inner carrier trace height (recursion-circuit cost is verifier-area
    // driven, ~independent of inner trace height; matches Probe X).
    let inner_rows = 1usize << 10;
    println!(
        "inner carrier rows: {inner_rows} (1<<{}) | active source slots: {MAX_IN_COINS}/{MAX_IN_COINS} (worst case)",
        inner_rows.trailing_zeros()
    );

    // ----------------------------------------------------------------------
    // Lever 1 — circuit-friendly inner hash: Poseidon2-MMCS vs Keccak-MMCS.
    // The baseline below IS the Poseidon2-MMCS config. The Keccak-MMCS config
    // is a non-verifying blocker, reported (not measured).
    // ----------------------------------------------------------------------
    println!("\n--- Lever 1: circuit-friendly inner hash (Poseidon2 vs Keccak MMCS) ---");
    println!(
        "  Baseline inner MMCS = MerkleTreeMmcs<.., PaddingFreeSponge<Poseidon2BabyBear<16>>>"
    );
    println!("    => the inner carrier proofs ALREADY commit with a field-native Poseidon2 hash.");
    println!("  In-circuit verify_batch_circuit recomputes leaf hashes via the Poseidon2 circuit");
    println!("    permutation table only (recursion/src/pcs/mmcs.rs is PermConfig-based).");
    println!("  BLOCKER: a Keccak-MMCS inner proof has NO in-circuit recompute gadget in this");
    println!("    recursion stack -> it cannot be verified by verify_batch_circuit at all. The");
    println!(
        "    ~10-50x in-circuit Keccak penalty is therefore NOT in the baseline (never paid);"
    );
    println!("    Lever 1's dominant win is ALREADY BANKED in the Probe-X Poseidon2 baseline.");

    // ----------------------------------------------------------------------
    // Measure the configs.
    // ----------------------------------------------------------------------
    // (a) BASELINE: Poseidon2-MMCS inner, full inner FRI, non-hiding (= Probe X non-zk).
    println!(
        "\n[measure] baseline (Poseidon2-MMCS, {})",
        InnerFriCfg::BASELINE.label
    );
    let baseline = prove_aggregator_nonhiding(&InnerFriCfg::BASELINE, inner_rows);
    print_result(
        "baseline",
        &baseline,
        InnerFriCfg::BASELINE.conjectured_bits(),
    );

    // (b) Lever 2 — cost of ZK-on-inner (hiding inner) vs non-hiding inner.
    //     non-hiding inner = baseline; hiding inner = this measurement.
    println!("\n[measure] Lever 2: ZK-on-inner cost (HidingFriPcs inner, full FRI)");
    let hiding_inner = prove_aggregator_hiding(&InnerFriCfg::BASELINE, inner_rows);
    print_result(
        "hiding-inner",
        &hiding_inner,
        InnerFriCfg::BASELINE.conjectured_bits(),
    );

    // (c) Lever 3 — cheaper inner FRI: 48 queries (64-bit) and 30 queries (46-bit).
    println!("\n[measure] Lever 3: cheaper inner FRI q=48 (64-bit [VERIFY])");
    let q48 = prove_aggregator_nonhiding(&InnerFriCfg::Q48, inner_rows);
    print_result("inner-FRI q=48", &q48, InnerFriCfg::Q48.conjectured_bits());

    println!("\n[measure] Lever 3 floor: cheaper inner FRI q=30 (46-bit [VERIFY])");
    let q30 = prove_aggregator_nonhiding(&InnerFriCfg::Q30, inner_rows);
    print_result("inner-FRI q=30", &q30, InnerFriCfg::Q30.conjectured_bits());

    // (d) Combined best config: Poseidon2-MMCS (baseline) + ZK-only-outer
    //     (non-hiding inner = baseline) + cheaper-inner-FRI (q=48, 64-bit).
    //     Note: combined == Q48 here, because the Poseidon2-MMCS win is already
    //     in the baseline and ZK-only-outer == non-hiding inner == the baseline
    //     inner shape. We re-measure under the combined label for a clean number.
    println!("\n[measure] COMBINED best (Poseidon2-MMCS + ZK-only-outer + inner FRI q=48)");
    let combined = prove_aggregator_nonhiding(&InnerFriCfg::Q48, inner_rows);
    print_result("COMBINED", &combined, InnerFriCfg::Q48.conjectured_bits());

    // ----------------------------------------------------------------------
    // Per-lever reduction factors vs Probe X (4.0 s non-zk).
    // ----------------------------------------------------------------------
    println!("\n======================= Probe AB reduction factors ==========================");
    println!("(reduction factor = Probe X non-zk baseline {PROBE_X_NONZK_MS:.0} ms / config p50)");
    let measured_baseline = baseline.p50_ms;
    println!(
        "{:<30} {:>10} {:>10} {:>14}",
        "config", "p50_ms", "vs ProbeX", "inner-bits"
    );
    let report = |name: &str, r: &ProveResult, bits: usize| {
        let factor = PROBE_X_NONZK_MS / r.p50_ms;
        println!(
            "{:<30} {:>10.0} {:>9.2}x {:>14}",
            name, r.p50_ms, factor, bits
        );
    };
    report(
        "baseline (Poseidon2-MMCS)",
        &baseline,
        InnerFriCfg::BASELINE.conjectured_bits(),
    );
    report(
        "Lever2 hiding-inner (ZK-on-in)",
        &hiding_inner,
        InnerFriCfg::BASELINE.conjectured_bits(),
    );
    report(
        "Lever3 inner-FRI q=48",
        &q48,
        InnerFriCfg::Q48.conjectured_bits(),
    );
    report(
        "Lever3 floor inner-FRI q=30",
        &q30,
        InnerFriCfg::Q30.conjectured_bits(),
    );
    report(
        "COMBINED best",
        &combined,
        InnerFriCfg::Q48.conjectured_bits(),
    );

    // Lever-specific deltas relative to the MEASURED baseline (not the Probe X
    // constant) so the lever effects are isolated from cross-machine drift.
    println!("\n----------------- per-lever effect vs MEASURED baseline ----------------------");
    println!(
        "Lever 1 (Poseidon2 vs Keccak MMCS): win ALREADY BANKED in baseline (Keccak inner does"
    );
    println!("  not verify in this stack) -> 0 further headroom on this axis.");
    let zk_on_inner_delta = hiding_inner.p50_ms - measured_baseline;
    let zk_on_inner_factor = hiding_inner.p50_ms / measured_baseline;
    println!(
        "Lever 2 (ZK-only-outer): hiding inner costs {:.0} ms vs non-hiding {:.0} ms (+{:.0} ms, {:.2}x).",
        hiding_inner.p50_ms, measured_baseline, zk_on_inner_delta, zk_on_inner_factor
    );
    println!(
        "  => keeping the 8+1 inner verifications NON-hiding SAVES ~{:.0} ms ({:.2}x). [VERIFY soundness]",
        zk_on_inner_delta.max(0.0),
        zk_on_inner_factor
    );
    let q48_factor = measured_baseline / q48.p50_ms;
    let q30_factor = measured_baseline / q30.p50_ms;
    println!(
        "Lever 3 (cheaper inner FRI): q=48 -> {:.2}x vs baseline (64-bit), q=30 -> {:.2}x (46-bit).",
        q48_factor, q30_factor
    );
    println!(
        "  [VERIFY] inner-layer bits < outer (116) requires the composition argument cleared."
    );

    // ----------------------------------------------------------------------
    // Recomposed /api/send verdict.
    // ----------------------------------------------------------------------
    println!("\n==================== recomposed /api/send (T + AB + node) ====================");
    println!(
        "formula: send = ProbeT {PROBE_T_TRANSITION_MS:.0} ms + AB aggregation + node overhead {NODE_OVERHEAD_MS:.0} ms"
    );
    let send_baseline = recomposed_send_ms(baseline.p50_ms);
    let send_combined = recomposed_send_ms(combined.p50_ms);
    let send_q30 = recomposed_send_ms(q30.p50_ms);
    println!(
        "baseline  : agg {:.0} ms -> send {:.0} ms",
        baseline.p50_ms, send_baseline
    );
    println!(
        "COMBINED  : agg {:.0} ms -> send {:.0} ms",
        combined.p50_ms, send_combined
    );
    println!(
        "q=30 floor: agg {:.0} ms -> send {:.0} ms (46-bit inner, NOT a deployment rec)",
        q30.p50_ms, send_q30
    );

    let verdict = |label: &str, send_ms: f64| {
        let (rel_warm, fac_warm) = if send_ms < PLONKY2_WARM_MS {
            ("FASTER", PLONKY2_WARM_MS / send_ms)
        } else {
            ("SLOWER", send_ms / PLONKY2_WARM_MS)
        };
        let (rel_live, fac_live) = if send_ms < PLONKY2_LIVE_SEND_MS {
            ("FASTER", PLONKY2_LIVE_SEND_MS / send_ms)
        } else {
            ("SLOWER", send_ms / PLONKY2_LIVE_SEND_MS)
        };
        println!(
            "  {label:<10} send {send_ms:.0} ms: vs Plonky2 warm {PLONKY2_WARM_MS:.0} -> {rel_warm} {fac_warm:.2}x | vs live {PLONKY2_LIVE_SEND_MS:.0} -> {rel_live} {fac_live:.2}x"
        );
    };
    println!("\nverdict vs Plonky2:");
    verdict("baseline", send_baseline);
    verdict("COMBINED", send_combined);
    verdict("q=30", send_q30);

    // ----------------------------------------------------------------------
    // The honest bottom line.
    // ----------------------------------------------------------------------
    const MARGIN_BAND: f64 = 1.20;
    println!("\n=============================== BOTTOM LINE ==================================");
    println!("Lever 1 (circuit-friendly inner hash) is the brief's predicted dominant win — but");
    println!("for THIS recursion stack it is ALREADY BANKED: the Probe-X baseline commits inner");
    println!("proofs with Poseidon2 MMCS and the in-circuit verifier is Poseidon2-only (a Keccak");
    println!("inner MMCS does not even verify here). So there is no further win to harvest on the");
    println!("dominant axis; the baseline is the recursion-friendly-hash config.");
    println!(
        "Lever 2 (ZK-only-outer) SAVES ~{:.0} ms ({:.2}x) by keeping the 8 inner verifications",
        (hiding_inner.p50_ms - measured_baseline).max(0.0),
        hiding_inner.p50_ms / measured_baseline
    );
    println!("  non-hiding [VERIFY soundness of non-hiding inner under hiding outer].");
    println!(
        "Lever 3 (cheaper inner FRI) gives {:.2}x at 64-bit / {:.2}x at 46-bit inner [VERIFY].",
        q48_factor, q30_factor
    );
    println!(
        "COMBINED best aggregation p50 = {:.0} ms (vs Probe X {PROBE_X_NONZK_MS:.0} ms => {:.2}x).",
        combined.p50_ms,
        PROBE_X_NONZK_MS / combined.p50_ms
    );
    let send_combined_factor_live = PLONKY2_LIVE_SEND_MS / send_combined;
    if send_combined < PLONKY2_WARM_MS {
        println!(
            "VERDICT: recursion-friendly config pulls /api/send to {send_combined:.0} ms — UNDER even"
        );
        println!(
            "  Plonky2's warm single-prove {PLONKY2_WARM_MS:.0} ms. The speed case is RESTORED."
        );
    } else if send_combined < PLONKY2_LIVE_SEND_MS {
        println!(
            "VERDICT: recursion-friendly config pulls /api/send to {send_combined:.0} ms — FASTER than"
        );
        println!(
            "  Plonky2's LIVE {PLONKY2_LIVE_SEND_MS:.0} ms send by {send_combined_factor_live:.2}x, but"
        );
        if send_combined / PLONKY2_WARM_MS < MARGIN_BAND {
            println!(
                "  still ~WASH vs the {PLONKY2_WARM_MS:.0} ms warm single-prove. PARTIAL recovery."
            );
        } else {
            println!(
                "  SLOWER than the {PLONKY2_WARM_MS:.0} ms warm single-prove. PARTIAL recovery only:"
            );
            println!(
                "  the dominant Lever-1 win was already in the baseline, so the remaining levers"
            );
            println!(
                "  (ZK-only-outer + cheaper inner FRI) do not clear the warm bar at 8+1 fan-in."
            );
        }
    } else {
        println!(
            "VERDICT: even the combined recursion-friendly config leaves /api/send at {send_combined:.0} ms,"
        );
        println!(
            "  SLOWER than Plonky2's live {PLONKY2_LIVE_SEND_MS:.0} ms send. The recursion overhead at 8+1"
        );
        println!("  fan-in is NOT recoverable by these circuit-side levers. Stated plainly.");
    }
    println!("Faithful single-aggregator-layer shape; a 2-to-1 tree costs strictly more, so these");
    println!(
        "are conservative lower bounds. All proofs verified. Outer proof = full-strength FRI."
    );
    println!("==============================================================================\n");

    // Hard gates: every config measured + verified (verification is inside each
    // prove path via verify_all_tables; reaching here means all passed).
    assert!(baseline.p50_ms > 0.0, "baseline measured");
    assert!(hiding_inner.p50_ms > 0.0, "hiding-inner measured");
    assert!(q48.p50_ms > 0.0, "q48 measured");
    assert!(q30.p50_ms > 0.0, "q30 measured");
    assert!(combined.p50_ms > 0.0, "combined measured");
    #[cfg(target_arch = "aarch64")]
    assert!(
        packing_active,
        "expected NEON-packed BabyBear, got {packing_type}"
    );
}

/// Print one measured config row.
fn print_result(name: &str, r: &ProveResult, inner_bits: usize) {
    println!(
        "  {name:<16}: build={:.1}ms cold={:.1}ms warm_p50={:.1}ms p90={:.1}ms rss={:.0}MB | public_flat_len={} inner_bits={}",
        r.build_ms, r.cold_ms, r.p50_ms, r.p90_ms, r.rss_mb, r.witness_count, inner_bits
    );
}
