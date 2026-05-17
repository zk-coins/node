//! Plonky2 circuit gadgets for the zkCoins state-transition predicate.
//!
//! Each gadget in [`mmr`] / [`smt`] mirrors a piece of off-circuit logic
//! in this crate (see `hash`, `merkle`, `types`) and adds the
//! constraints required to prove the same invariant in-circuit. The
//! [`main`] module composes those gadgets into the monolithic
//! state-transition circuit per [`SPEC.md`] §8 and `ROADMAP.md` Step 5.

pub mod main;
pub mod mmr;
pub mod smt;
mod util;
