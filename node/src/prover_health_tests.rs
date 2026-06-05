//! Unit tests for [`ProverHealth`]. Pure, build-free, no database —
//! drives every method and the threshold boundary exhaustively so the
//! gated `prover_health.rs` reaches 100% lines + functions.

use super::*;

#[test]
fn new_starts_healthy() {
    let h = ProverHealth::new();
    assert!(!h.is_failing());
}

#[test]
fn below_threshold_is_not_failing_and_does_not_arm() {
    let h = ProverHealth::new();
    // One short of the threshold: never failing, never arms.
    for _ in 0..(PROVE_FAILURE_THRESHOLD - 1) {
        assert!(!h.note_failure());
        assert!(!h.is_failing());
    }
}

#[test]
fn crossing_threshold_arms_exactly_once_then_stays_failing() {
    let h = ProverHealth::new();
    for _ in 0..(PROVE_FAILURE_THRESHOLD - 1) {
        assert!(!h.note_failure());
    }
    // The failure that reaches the threshold arms (returns true) once.
    assert!(h.note_failure());
    assert!(h.is_failing());
    // Further failures keep it failing but do NOT re-arm.
    assert!(!h.note_failure());
    assert!(!h.note_failure());
    assert!(h.is_failing());
}

#[test]
fn success_clears_the_streak() {
    let h = ProverHealth::new();
    for _ in 0..(PROVE_FAILURE_THRESHOLD - 1) {
        h.note_failure();
    }
    h.note_success();
    assert!(!h.is_failing());
    // After a reset the streak must climb from scratch — the first
    // post-reset failure does not re-arm.
    assert!(!h.note_failure());
    assert!(!h.is_failing());
}

#[test]
fn success_while_failing_recovers() {
    let h = ProverHealth::new();
    for _ in 0..PROVE_FAILURE_THRESHOLD {
        h.note_failure();
    }
    assert!(h.is_failing());
    h.note_success();
    assert!(!h.is_failing());
}
