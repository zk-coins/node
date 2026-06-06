//! Goldilocks recursion harness for the Phase 0 spike.
//!
//! This module reproduces — for Goldilocks (D=2, Poseidon2 width 8, rate 4) — the
//! minimal config + backend wiring that `Plonky3-recursion`'s own
//! `recursive_fibonacci` example uses, but stripped of the CLI/macro machinery so
//! the spike's probes (A/B/C) can call the high-level `build_and_prove_next_layer`
//! / `build_and_prove_aggregation_layer` API directly.
//!
//! The one non-obvious requirement: `build_and_prove_next_layer`'s config must
//! implement `FriRecursionConfig` (not just `StarkGenericConfig`), because the
//! backend needs the FRI verifier params and the in-circuit Poseidon2/recompose
//! NPO setup. `ConfigWithFriParams` is that config; its `FriRecursionConfig` impl
//! is transcribed from the example's `define_field_module_types!` Goldilocks path.

use std::sync::Arc;

use p3_batch_stark::ProverData;
use p3_circuit::CircuitBuilder;
use p3_circuit::CircuitRunner;
use p3_circuit::NonPrimitiveOpId;
use p3_circuit::ops::{
    GoldilocksD2Width8, Poseidon2Params, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking};
use p3_commit::Pcs;
use p3_field::BasedVectorSpace;
use p3_fri::FriParameters;
use p3_lookup::logup::LogUpGadget;
use p3_recursion::pcs::fri::{FriVerifierParams, InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness, set_fri_mmcs_private_data};
use p3_recursion::traits::{RecursiveAir, RecursivePcs};
use p3_recursion::verifier::VerificationError;
use p3_recursion::{
    BatchOnly, FriRecursionBackend, FriRecursionBackendForExt, FriRecursionConfig, Poseidon2Config,
    ProveNextLayerParams, RecursionInput, RecursionOutput, build_and_prove_aggregation_layer,
};
use p3_test_utils::goldilocks_params::{
    ChallengeMmcs, Challenger, Dft, MyCompress, MyConfig, MyHash, MyMmcs, MyPcs,
    Poseidon2Goldilocks,
};
use p3_uni_stark::{StarkGenericConfig, Val};
use rand::SeedableRng;
use rand::rngs::SmallRng;

pub use p3_test_utils::goldilocks_params::{Challenge, DIGEST_ELEMS, F};

/// The opening-proof targets type for our Goldilocks FRI PCS, mirroring the
/// `InnerFriGeneric` alias in the recursion crate's own tests.
pub type InnerFri = FriProofTargets<
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

/// Backend type for Goldilocks D=2, Poseidon2 width 8 / rate 4.
pub type GoldilocksBackend = FriRecursionBackendForExt<2, 8, 4, Poseidon2Config>;

/// FRI parameter bundle (mirrors the example's `FriParams`).
#[derive(Debug, Clone, Copy)]
pub struct FriParams {
    pub log_blowup: usize,
    pub max_log_arity: usize,
    pub cap_height: usize,
    pub log_final_poly_len: usize,
    pub commit_pow_bits: usize,
    pub query_pow_bits: usize,
}

/// Spike defaults: modest FRI params that keep prove times low while exercising
/// the real Merkle/FRI verifier path in-circuit.
pub fn default_fri_params() -> FriParams {
    FriParams {
        log_blowup: 2,
        max_log_arity: 2,
        cap_height: 0,
        log_final_poly_len: 1,
        commit_pow_bits: 0,
        query_pow_bits: 8,
    }
}

/// Deterministic Goldilocks Poseidon2 permutation (seed 1), matching the
/// recursion crate's own Goldilocks tests so prover and verifier agree.
pub fn default_goldilocks_poseidon2_8() -> Poseidon2Goldilocks<8> {
    let mut rng = SmallRng::seed_from_u64(1);
    Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng)
}

/// A Goldilocks STARK config that also carries FRI verifier params so it can be
/// used as the `FriRecursionConfig` for `build_and_prove_next_layer`.
#[derive(Clone)]
pub struct ConfigWithFriParams {
    config: Arc<MyConfig>,
    fri_verifier_params: FriVerifierParams,
    disable_recompose_npo: bool,
}

impl core::ops::Deref for ConfigWithFriParams {
    type Target = MyConfig;
    fn deref(&self) -> &MyConfig {
        &self.config
    }
}

impl StarkGenericConfig for ConfigWithFriParams {
    type Challenge = Challenge;
    type Challenger = Challenger;
    type Pcs = MyPcs;
    fn pcs(&self) -> &MyPcs {
        self.config.pcs()
    }
    fn initialise_challenger(&self) -> Challenger {
        self.config.initialise_challenger()
    }
}

impl FriRecursionConfig for ConfigWithFriParams
where
    MyPcs: RecursivePcs<
            ConfigWithFriParams,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            InnerFri,
            MerkleCapTargets<F, DIGEST_ELEMS>,
            <MyPcs as Pcs<Challenge, Challenger>>::Domain,
        >,
{
    type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
    type InputProof =
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>;
    type OpeningProof = InnerFri;
    type RawOpeningProof = <MyPcs as Pcs<Challenge, Challenger>>::Proof;
    const DIGEST_ELEMS: usize = 4;

    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Challenge>,
    ) -> Result<(), VerificationError> {
        let perm = default_goldilocks_poseidon2_8();
        circuit.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
            generate_poseidon2_trace::<Challenge, GoldilocksD2Width8>,
            perm,
        );
        if self.disable_recompose_npo {
            circuit.noop_enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
        } else {
            circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
        }
        if <GoldilocksD2Width8 as Poseidon2Params>::D == 1
            && <Challenge as BasedVectorSpace<F>>::DIMENSION > 1
        {
            circuit.set_recompose_coeff_ctl_for_decompose_links(true);
        }
        Ok(())
    }

    fn pcs_verifier_params(
        &self,
    ) -> &<MyPcs as RecursivePcs<
        ConfigWithFriParams,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        <MyPcs as Pcs<Challenge, Challenger>>::Domain,
    >>::VerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        runner: &mut CircuitRunner<'_, Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
    ) -> Result<(), &'static str> {
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
            opening_proof,
            Poseidon2Config::GOLDILOCKS_D2_W8,
        )
    }
}

fn create_config(fp: &FriParams, security_level: usize) -> MyConfig {
    let perm = default_goldilocks_poseidon2_8();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = MyMmcs::new(hash, compress, fp.cap_height);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let num_queries = (security_level - fp.query_pow_bits) / fp.log_blowup;

    let fri_params = FriParameters {
        max_log_arity: fp.max_log_arity,
        log_blowup: fp.log_blowup,
        log_final_poly_len: fp.log_final_poly_len,
        num_queries,
        commit_proof_of_work_bits: fp.commit_pow_bits,
        query_proof_of_work_bits: fp.query_pow_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    MyConfig::new(pcs, challenger)
}

fn create_fri_verifier_params(fp: &FriParams) -> FriVerifierParams {
    FriVerifierParams::with_mmcs(
        fp.log_blowup,
        fp.log_final_poly_len,
        fp.commit_pow_bits,
        fp.query_pow_bits,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    )
}

/// Build the recursion config for the given FRI params at security level 100.
pub fn config_with_fri_params(fp: &FriParams) -> ConfigWithFriParams {
    ConfigWithFriParams {
        config: Arc::new(create_config(fp, 100)),
        fri_verifier_params: create_fri_verifier_params(fp),
        disable_recompose_npo: false,
    }
}

/// Config bundle for the low-level single-proof in-circuit verifier
/// (`verify_p3_uni_proof_circuit`), used by Probe C. Mirrors the recursion
/// crate's own `recursion/tests/goldilocks.rs::make_config`.
pub fn make_uni_verify_config() -> (MyConfig, Poseidon2Goldilocks<8>, FriVerifierParams) {
    let perm = default_goldilocks_poseidon2_8();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = MyMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters::new_testing(challenge_mmcs, 0);
    let fri_verifier_params = FriVerifierParams::with_mmcs(
        fri_params.log_blowup,
        fri_params.log_final_poly_len,
        fri_params.commit_proof_of_work_bits,
        fri_params.query_proof_of_work_bits,
        Poseidon2Config::GOLDILOCKS_D2_W8,
    );
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm.clone());
    let config = MyConfig::new(pcs, challenger);
    (config, perm, fri_verifier_params)
}

/// The Goldilocks recursion backend.
pub fn goldilocks_backend() -> GoldilocksBackend {
    FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>()
}

/// Verify a recursion output's batch proof (reconstructs a prover with the same
/// table packing + registered tables, then `verify_all_tables`).
pub fn verify_recursion_output(
    output: &RecursionOutput<ConfigWithFriParams>,
    config: &ConfigWithFriParams,
    table_packing: &TablePacking,
) -> Result<(), String> {
    let mut prover =
        BatchStarkProver::new(config.clone()).with_table_packing(table_packing.clone());
    prover.register_poseidon2_table::<2>(Poseidon2Config::GOLDILOCKS_D2_W8);
    prover.register_recompose_table::<2>(false);
    prover
        .verify_all_tables(&output.0)
        .map_err(|e| format!("verify_all_tables failed: {e:?}"))
}

/// 2-to-1 aggregation: prove a single layer that verifies BOTH `left` and `right`
/// (each a batch proof). This is the fan-in primitive; an N-way fan-in is a tree
/// of these (depth ⌈log2 N⌉).
pub fn aggregate_two(
    left: &RecursionOutput<ConfigWithFriParams>,
    right: &RecursionOutput<ConfigWithFriParams>,
    config: &ConfigWithFriParams,
    backend: &GoldilocksBackend,
    params: &ProveNextLayerParams,
) -> RecursionOutput<ConfigWithFriParams> {
    let li = left.into_recursion_input::<BatchOnly>();
    let ri = right.into_recursion_input::<BatchOnly>();
    build_and_prove_aggregation_layer::<ConfigWithFriParams, BatchOnly, BatchOnly, _, 2>(
        &li, &ri, config, backend, params, None,
    )
    .expect("2-to-1 aggregation")
}

/// Prove a base "counter" circuit (`acc = 0; acc += 1` × `steps`, committed to a
/// public input equal to `steps`) with the batch-stark prover, and wrap it as a
/// `RecursionOutput` ready to be recursed over. This is the layer-0 of an IVC chain.
pub fn prove_base_counter(
    steps: u64,
    config: &ConfigWithFriParams,
    fp: &FriParams,
) -> RecursionOutput<ConfigWithFriParams> {
    use p3_field::PrimeCharacteristicRing;
    use std::rc::Rc;

    let mut builder = CircuitBuilder::new();
    let expected = builder.alloc_public_input("expected");
    let mut acc = builder.alloc_const(F::ZERO, "c0");
    let one = builder.alloc_const(F::ONE, "one");
    for _ in 0..steps {
        acc = builder.add(acc, one);
    }
    builder.connect(acc, expected);
    let base_circuit = builder.build().expect("base circuit builds");

    let table_packing_0 =
        TablePacking::new(1, 1).with_fri_params(fp.log_final_poly_len, fp.log_blowup);

    let traces_0 = {
        let mut runner = base_circuit.runner();
        runner
            .set_public_inputs(&[F::from_u64(steps)])
            .expect("set base public inputs");
        runner.run().expect("run base circuit")
    };

    let (airs_degrees_0, primitive_columns_0, non_primitive_columns_0) =
        get_airs_and_degrees_with_prep::<ConfigWithFriParams, F, 1>(
            &base_circuit,
            &table_packing_0,
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .expect("airs and degrees for base");
    let (airs_0, degrees_0): (Vec<_>, Vec<usize>) = airs_degrees_0.into_iter().unzip();
    let ext_degrees_0: Vec<usize> = degrees_0.iter().map(|&d| d + config.is_zk()).collect();
    let prover_data_0 = ProverData::from_airs_and_degrees(config, &airs_0, &ext_degrees_0);
    let circuit_prover_data_0 =
        CircuitProverData::new(prover_data_0, primitive_columns_0, non_primitive_columns_0);
    let prover_0 = BatchStarkProver::new(config.clone()).with_table_packing(table_packing_0);
    let proof_0 = prover_0
        .prove_all_tables(&traces_0, &circuit_prover_data_0)
        .expect("prove base circuit");
    prover_0
        .verify_all_tables(&proof_0)
        .expect("verify base proof");

    RecursionOutput(proof_0, Rc::new(circuit_prover_data_0))
}
