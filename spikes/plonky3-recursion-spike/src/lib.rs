//! Phase 0 recursion-feasibility spike for the Plonky2 -> Plonky3 migration.
//!
//! See `MIGRATION_PLONKY3.md` §5. This crate is a throwaway probe: it proves
//! (or disproves) that `Plonky3/Plonky3-recursion` can express the three
//! composition patterns the zkCoins state-transition circuit depends on,
//! *in Goldilocks*, using trivial counter AIRs rather than the real circuit.
//!
//! Patterns under test:
//!   * Probe A — IVC / cyclic recursion with a base case (`prove_next_layer` chain).
//!   * Probe B — fan-in-8 aggregation with a variable active count.
//!   * Probe C — verification-key / public-input binding across layers.
//!
//! The crate links against the pinned `p3-recursion` (and its `p3-circuit`,
//! `p3-circuit-prover`, `p3-poseidon2-circuit-air` siblings) so that "the spike
//! compiles against the pinned recursion lib" — the P0-T1 acceptance — is a
//! real, mechanically-checked fact, not an aspiration. The probe tests then
//! exercise the actual recursion APIs.

// Goldilocks recursion harness (config + backend + base-prove helpers) used by
// the probe tests. Exercises p3-recursion / p3-circuit / p3-circuit-prover.
pub mod goldilocks_rec;

// p3-poseidon2-circuit-air is only used directly by the KoalaBear fan-in probe;
// keep it force-linked so P0-T1's "compiles against the pinned recursion lib"
// covers the whole dependency set.
use p3_poseidon2_circuit_air as _;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

/// A minimal counter AIR over a single column `c`, enforcing `next = cur + 1`.
///
/// Public values: `[start, last]`.
///   * first row:      `c == start`
///   * each transition: `c' == c + 1`
///   * last row:       `c == last`
///
/// This is the trivial circuit the whole spike recurses over — small enough to
/// keep prove times low, structured enough that a recursion layer verifying it
/// has a real (non-degenerate) verifier circuit.
#[derive(Clone, Copy, Debug, Default)]
pub struct CounterAir;

impl<F> BaseAir<F> for CounterAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        2
    }
}

impl<AB: AirBuilder> Air<AB> for CounterAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let start = pis[0];
        let last = pis[1];

        let local = main.current_slice();
        let next = main.next_slice();
        let c = local[0];
        let c_next = next[0];

        builder.when_first_row().assert_eq(c, start);
        builder
            .when_transition()
            .assert_eq(c_next, c + AB::Expr::ONE);
        builder.when_last_row().assert_eq(c, last);
    }
}

/// Build the `n`-row counter trace starting at `start`: rows are
/// `start, start+1, …, start+n-1`. `n` must be a power of two.
pub fn generate_counter_trace<F: PrimeField64>(start: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two(), "trace height must be a power of two");
    let mut values = F::zero_vec(n);
    for (i, v) in values.iter_mut().enumerate() {
        *v = F::from_u64(start + i as u64);
    }
    RowMajorMatrix::new(values, 1)
}

/// The public inputs a counter proof of `n` rows starting at `start` commits to.
pub fn counter_public_inputs<F: PrimeField64>(start: u64, n: usize) -> Vec<F> {
    vec![F::from_u64(start), F::from_u64(start + (n as u64 - 1))]
}

/// A minimal AIR WITH a preprocessed column whose constant value `k` IS the
/// verification key (the preprocessed commitment is a function of `k`). Used by
/// Probe F: two instances with different `k` have different preprocessed
/// commitments (= different vks), so binding the inner vk = binding `k`.
///
/// Layout: one main column `m`, one preprocessed column `p` (constant `k`).
/// Constraint: `m == p` on every row (so a valid main trace is all-`k`).
#[derive(Clone, Copy, Debug)]
pub struct ConstPrepAir {
    pub k: u64,
    pub rows: usize,
}

impl<F: Field> BaseAir<F> for ConstPrepAir {
    fn width(&self) -> usize {
        1
    }

    fn preprocessed_width(&self) -> usize {
        1
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(RowMajorMatrix::new(vec![F::from_u64(self.k); self.rows], 1))
    }
}

impl<AB: AirBuilder> Air<AB> for ConstPrepAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let prep = builder.preprocessed();
        let m = main.current_slice()[0];
        let p = prep.current_slice()[0];
        builder.assert_eq(m, p);
    }
}

/// The (all-`k`, `rows`×1) main trace that satisfies `ConstPrepAir { k, rows }`.
pub fn generate_const_main_trace<F: Field>(k: u64, rows: usize) -> RowMajorMatrix<F> {
    RowMajorMatrix::new(vec![F::from_u64(k); rows], 1)
}

#[cfg(test)]
mod config {
    //! Goldilocks STARK config, mirroring `Plonky3-recursion`'s own
    //! `recursion/tests/goldilocks.rs::make_config` so the spike proves over
    //! exactly the field/hash/FRI parameters the recursion lib expects.

    use p3_fri::FriParameters;
    use p3_test_utils::goldilocks_params::*;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    pub use p3_test_utils::goldilocks_params::{F, MyConfig};

    pub fn default_goldilocks_poseidon2_8() -> Perm {
        let mut rng = SmallRng::seed_from_u64(1);
        Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng)
    }

    pub fn make_config() -> MyConfig {
        let perm = default_goldilocks_poseidon2_8();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let val_mmcs = MyMmcs::new(hash, compress, 0);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let dft = Dft::default();
        let fri_params = FriParameters::new_testing(challenge_mmcs, 0);
        let pcs = MyPcs::new(dft, val_mmcs, fri_params);
        let challenger = Challenger::new(perm.clone());
        MyConfig::new(pcs, challenger)
    }
}

#[cfg(test)]
mod tests {
    use super::config::{F, make_config};
    use super::*;
    use p3_uni_stark::{prove, verify};

    /// P0-T1: the trivial counter AIR proves and verifies via `p3-uni-stark`
    /// over Goldilocks. This is the spike's foundation — every probe builds a
    /// recursion layer on top of a proof produced exactly like this.
    #[test]
    fn base_air_round_trips() {
        let config = make_config();
        let air = CounterAir;

        let n = 1 << 4;
        let start = 7u64;
        let trace = generate_counter_trace::<F>(start, n);
        let pis = counter_public_inputs::<F>(start, n);

        let proof = prove(&config, &air, trace, &pis);
        verify(&config, &air, &proof, &pis).expect("counter proof must verify");
    }
}
