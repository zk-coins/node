//! Probe E — variable-active-count masking (MIGRATION_PLONKY3.md §5, P0-T3;
//! MIGRATION_RESEARCH.md §7.15/§7.17).
//!
//! zkCoins processes 0..MAX_IN_COINS=8 input slots in a FIXED-shape circuit: each
//! slot carries an `active` bit, and inactive slots are made vacuously satisfied by
//! masking. The load-bearing pattern (§7.17) is
//!   `connect(computed, select(active, expected, computed))`
//! which, for active=0, reduces to `connect(computed, computed)` (any witness
//! accepted — the slot is masked off), and for active=1 enforces
//! `computed == expected` (the honest per-slot check fires).
//!
//! This probe builds the full 8-slot masked consumer circuit over the Goldilocks
//! base field, proves it for real with batch-stark, and asserts:
//!   * POSITIVE: active slots carry correct values, inactive slots carry GARBAGE —
//!     accepted (garbage is masked away). Real STARK proof produced + verified.
//!   * NEGATIVE A: an active slot with a wrong value is rejected.
//!   * NEGATIVE B (active-bit flip): flipping a garbage slot from inactive→active
//!     changes the verdict to REJECT (the garbage is no longer masked).
//!   * CONTROL: flipping it back to inactive re-masks the garbage → accepted.

use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_test_utils::goldilocks_params::F;
use plonky3_recursion_spike::goldilocks_rec::{
    config_with_fri_params, default_fri_params, prove_and_verify_no_npo,
};

const SLOTS: usize = 8;

/// The value slot `i` must carry when it is active.
fn expected_value(i: usize) -> u64 {
    100 + i as u64
}

/// Build the fixed-shape 8-slot masked consumer circuit. Public inputs, in order:
/// `[claimed_0, active_0, claimed_1, active_1, …]`.
fn build_masking_circuit() -> Circuit<F> {
    let mut cb = CircuitBuilder::new();
    for i in 0..SLOTS {
        let claimed = cb.alloc_public_input("claimed");
        let active = cb.alloc_public_input("active");
        cb.assert_bool(active);
        let expected = cb.alloc_const(F::from_u64(expected_value(i)), "expected");
        // §7.17: active=0 -> connect(claimed, claimed) (garbage allowed);
        //        active=1 -> connect(claimed, expected) (honest check fires).
        let masked = cb.select(active, expected, claimed);
        cb.connect(claimed, masked);
    }
    cb.build().expect("masking circuit builds")
}

fn slots_to_pubs(slots: &[(u64, u64)]) -> Vec<F> {
    let mut v = Vec::with_capacity(slots.len() * 2);
    for &(claimed, active) in slots {
        v.push(F::from_u64(claimed));
        v.push(F::from_u64(active));
    }
    v
}

#[test]
fn probe_e_active_masking() {
    let fp = default_fri_params();
    let config = config_with_fri_params(&fp);
    let circuit = build_masking_circuit();

    // POSITIVE: slots 0,1,2 active+correct; slots 3..8 inactive with GARBAGE (777).
    let positive: Vec<(u64, u64)> = (0..SLOTS)
        .map(|i| {
            if i < 3 {
                (expected_value(i), 1)
            } else {
                (777, 0)
            }
        })
        .collect();
    prove_and_verify_no_npo(&circuit, &slots_to_pubs(&positive), &config, &fp)
        .expect("active-correct + inactive-garbage must verify (garbage masked away)");

    // NEGATIVE A: an active slot carries a wrong value.
    let mut neg_a = positive.clone();
    neg_a[0] = (999, 1);
    assert!(
        prove_and_verify_no_npo(&circuit, &slots_to_pubs(&neg_a), &config, &fp).is_err(),
        "an active slot with a wrong value must be REJECTED"
    );

    // NEGATIVE B (active-bit flip): an inactive garbage slot is flipped to active.
    let mut neg_b = positive.clone();
    neg_b[3] = (777, 1); // 777 != expected(3) = 103
    assert!(
        prove_and_verify_no_npo(&circuit, &slots_to_pubs(&neg_b), &config, &fp).is_err(),
        "flipping an active bit on a garbage slot must change the verdict to REJECT"
    );

    // CONTROL: flip that bit back to inactive — the garbage is re-masked, accepted.
    let mut control = neg_b.clone();
    control[3] = (777, 0);
    prove_and_verify_no_npo(&circuit, &slots_to_pubs(&control), &config, &fp)
        .expect("flipping the active bit back to inactive re-masks the garbage -> accepted");
}
