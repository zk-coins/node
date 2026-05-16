//! Plonky2 circuit gadgets for the zkCoins state-transition predicate.
//!
//! Each gadget mirrors a piece of off-circuit logic in this crate (see
//! `hash`, `merkle`, `types`) and adds the constraints required to prove
//! the same invariant in-circuit. Gadgets do not stand alone — they are
//! composed in the monolithic state-transition circuit (lands in a later
//! commit; see `MIGRATION_RESEARCH.md` §6 step 5).

pub mod mmr;
pub mod smt;
mod util;
