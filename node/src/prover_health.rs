//! Runtime prover-health signal.
//!
//! ## Why this exists
//!
//! Two gaps surfaced when the DEV node's mint prover went down on
//! 2026-06-05 and stayed down for ~100 min, undetected:
//!
//! 1. **`/health/ready` lied.** It reported `prover: ready` the entire
//!    time, because that flag only reflects the one-shot boot *warmup*
//!    (`AppState::prover_warm`), never whether real mint/send proves are
//!    actually succeeding. The deploy smoke-test and any orchestration
//!    keyed on readiness therefore could not see the outage.
//!
//! 2. **Steady-state staleness never self-healed.** The boot self-heal
//!    only runs the canary recursion on the no-persisted-digest adoption
//!    branch (`self_heal::reset_decision`); with a persisted digest equal
//!    to the live one it takes the `Keep` fast path. But a constraint-only
//!    circuit change — or any other event that leaves persisted proofs
//!    unable to recurse while the `circuit_digest` is byte-identical
//!    (documented in migration 0015 / `self_heal.rs`) — breaks every prove
//!    with the digest unchanged, so `Keep` is taken forever and no restart
//!    recovers it.
//!
//! ## What this does
//!
//! Tracks the number of *consecutive* "prove failed" job outcomes the
//! dispatcher observes (reset to zero by the first success). At
//! [`PROVE_FAILURE_THRESHOLD`] consecutive failures the prover is treated
//! as **systemically failing**, which the dispatcher acts on twice:
//!
//! * `/health/ready` reports `prover: failing` + 503 (gap 1) — the outage
//!   becomes visible to the deploy smoke-test / orchestration / alerting.
//! * the dispatcher clears the persisted circuit digest (gap 2), which
//!   *arms* the boot self-heal: the next restart finds no persisted
//!   digest, runs the canary recursion, and resets to genesis **iff the
//!   canary confirms the persisted proofs are actually stale**
//!   (`Compatible` / `NoSample` → no reset, no data loss). Clearing the
//!   digest is therefore safe — it forces the authoritative re-check, it
//!   does not itself wipe anything.
//!
//! The streak counter is the only state; it lives behind an `AtomicU64`
//! so the readiness handler can read it without taking a lock and the
//! single-worker dispatcher can update it on every job outcome.

use std::sync::atomic::{AtomicU64, Ordering};

/// Number of *consecutive* `prove failed` job outcomes at which the
/// prover is treated as systemically failing.
///
/// A single state-transition prove is a multi-second operation, so three
/// in an unbroken row is tens of seconds of nothing-but-failure — well
/// past any one-off bad input or transient, and the streak resets to zero
/// the moment a prove succeeds. Small enough that a real outage trips it
/// within one wallet's worth of retries; large enough that an isolated
/// `prove failed` (e.g. a single corrupt request) never arms the
/// self-heal.
pub(crate) const PROVE_FAILURE_THRESHOLD: u64 = 3;

/// Consecutive-prove-failure tracker shared (via `Arc`) between the job
/// dispatcher (writer) and the `/health/ready` handler (reader).
#[derive(Debug, Default)]
pub(crate) struct ProverHealth {
    consecutive_failures: AtomicU64,
}

impl ProverHealth {
    /// A fresh tracker with a zero failure streak.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record a successful prove. Clears the failure streak so a later
    /// burst has to reach the threshold from scratch.
    pub(crate) fn note_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
    }

    /// Record a `prove failed` job outcome.
    ///
    /// Returns `true` exactly once per outage — on the failure that first
    /// reaches [`PROVE_FAILURE_THRESHOLD`] — so the caller fires the
    /// one-shot "arm the boot self-heal" side effect (clearing the
    /// persisted digest) a single time rather than on every subsequent
    /// failure. Later failures past the threshold keep
    /// [`Self::is_failing`] true but return `false`.
    pub(crate) fn note_failure(&self) -> bool {
        let streak = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        streak == PROVE_FAILURE_THRESHOLD
    }

    /// Whether proves are systemically failing (streak at or past the
    /// threshold). Consumed by `/health/ready`.
    pub(crate) fn is_failing(&self) -> bool {
        self.consecutive_failures.load(Ordering::SeqCst) >= PROVE_FAILURE_THRESHOLD
    }
}

#[cfg(test)]
#[path = "prover_health_tests.rs"]
mod tests;
