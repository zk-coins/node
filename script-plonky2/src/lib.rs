//! High-level host-side prover wrapper for the Plonky2 state-transition
//! circuit. Companion to the SP1-era `script/` crate.
//!
//! ## Architecture
//!
//! - [`Prover`] owns the heavy `StateTransitionCircuit` build (one
//!   per process — typically created at server startup).
//! - [`Prover::prove_initial`] / [`Prover::prove_account_update`] are
//!   thin convenience wrappers over the low-level
//!   [`zkcoins_program_plonky2::circuit::main`] APIs that thread
//!   through the common Init/Update arguments without re-exposing
//!   slot-witness construction.
//! - [`Prover::verify`] runs both the circuit-data verification AND
//!   the cyclic-verifier-data digest cross-check that
//!   [`zkcoins_program_plonky2::circuit::main::verify`] performs
//!   internally.
//!
//! ## Toolchain
//!
//! This crate inherits its nightly toolchain from
//! [`program-plonky2/rust-toolchain.toml`](../program-plonky2/rust-toolchain.toml)
//! via a symlink — Plonky2 requires `feature(specialization)`.
//! Callers from stable-toolchain crates (e.g. the SP1-era `server/`
//! crate) must invoke this via a subprocess boundary (a `[[bin]]`
//! target ships in a future iteration).

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use anyhow::Result;
use plonky2::plonk::proof::ProofWithPublicInputs;

use zkcoins_program_plonky2::circuit::main::{
    build_circuit, prove_account_update, prove_account_update_with_in_and_out_coins,
    prove_account_update_with_in_and_out_coins_and_sources, prove_account_update_with_in_coins,
    prove_initial, prove_initial_with_in_and_out_coins,
    prove_initial_with_in_and_out_coins_and_sources, prove_initial_with_in_coins, verify,
    StateTransitionCircuit,
};
use zkcoins_program_plonky2::hash::HashDigest;
use zkcoins_program_plonky2::inputs::CommitmentMerkleProofs;
use zkcoins_program_plonky2::merkle::sparse_merkle_tree::NonInclusionProof;
use zkcoins_program_plonky2::types::{AccountState, Coin, PublicKey};
use zkcoins_program_plonky2::{C, D, F};

// Re-export so server callers don't have to depend on
// `zkcoins-program-plonky2` directly for the source-witness type.
pub use zkcoins_program_plonky2::circuit::main::InCoinSourceWitness;

/// Type alias: a single state-transition proof carrying the
/// `ProofData` public inputs plus the cyclic verifier-data digest.
pub type Proof = ProofWithPublicInputs<F, C, D>;

/// Host-side prover. Owns the built state-transition circuit
/// (proving + verification keys, common data) so that successive
/// `prove_*` calls amortise the ~10 s build cost.
///
/// The circuit is cyclic — its `verifier_data.circuit_digest` is
/// pinned in every proof's public inputs, enforcing that all proofs
/// the server emits are verifiable by the SAME circuit instance.
pub struct Prover {
    pub circuit: StateTransitionCircuit,
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover {
    /// Build the state-transition circuit. Expensive (~10 s wall on
    /// the M3 Ultra at production parameters: `MAX_IN_COINS` =
    /// `MAX_OUT_COINS` = 8, `INNER_PAD_BITS_STAGE_5D_NEXT_5 = 15`
    /// — Phase 2b outer at degree 16). Call once per process and
    /// share via `Arc<Prover>` across request handlers; the
    /// fixed-point loop that converges aggregator + outer common
    /// inside `build_circuit` runs on each instantiation.
    pub fn new() -> Self {
        Self {
            circuit: build_circuit(),
        }
    }

    /// Prove an Initial-branch state transition with all in-coin
    /// slots inactive and no out-coins.
    pub fn prove_initial(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
    ) -> Result<Proof> {
        prove_initial(&self.circuit, account_state, history_root)
    }

    /// Prove an Initial-branch transition with caller-supplied
    /// in-coin slot witnesses. Each tuple is
    /// `(active, &coin, &non_inclusion_proof)`. The caller MUST
    /// supply exactly `MAX_IN_COINS` tuples.
    ///
    /// Delegates through to the `_and_sources` core with all-`None`
    /// sources — only suitable for transitions whose `in_coins` are
    /// ALL inactive. Active in-coin slots require the
    /// [`Self::prove_initial_with_in_and_out_coins_and_sources`]
    /// variant.
    pub fn prove_initial_with_in_coins(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
    ) -> Result<Proof> {
        prove_initial_with_in_coins(&self.circuit, account_state, history_root, in_coins)
    }

    /// Full-control Initial-branch prove: in-coin tuples, out-coin
    /// tuples, and explicit `next_public_key` rotation. Each
    /// `out_coins` tuple is
    /// `(active, out_coin_identifier, amount, &non_inclusion_proof)`.
    /// Delegates to the `_and_sources` variant with all-`None`
    /// sources — only suitable for transitions whose `in_coins` are
    /// ALL inactive. Active in-coin slots require the
    /// [`Self::prove_initial_with_in_and_out_coins_and_sources`]
    /// variant.
    pub fn prove_initial_with_in_and_out_coins(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
        out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
        next_public_key: &PublicKey,
    ) -> Result<Proof> {
        prove_initial_with_in_and_out_coins(
            &self.circuit,
            account_state,
            history_root,
            in_coins,
            out_coins,
            next_public_key,
        )
    }

    /// Prove an AccountUpdate transition consuming `prev` as the
    /// recursive inner proof, with all in-coin slots inactive.
    pub fn prove_account_update(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        prev: &Proof,
        cmp: &CommitmentMerkleProofs,
    ) -> Result<Proof> {
        prove_account_update(&self.circuit, account_state, history_root, prev, cmp)
    }

    /// Prove an AccountUpdate transition with caller-supplied
    /// in-coin slot witnesses.
    ///
    /// Delegates through to the `_and_sources` core with all-`None`
    /// sources — only suitable for transitions whose `in_coins` are
    /// ALL inactive. Active in-coin slots require the
    /// [`Self::prove_account_update_with_in_and_out_coins_and_sources`]
    /// variant.
    pub fn prove_account_update_with_in_coins(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        prev: &Proof,
        cmp: &CommitmentMerkleProofs,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
    ) -> Result<Proof> {
        prove_account_update_with_in_coins(
            &self.circuit,
            account_state,
            history_root,
            prev,
            cmp,
            in_coins,
        )
    }

    /// Full-control AccountUpdate prove: in-coin tuples, out-coin
    /// tuples, and explicit `next_public_key` rotation. Delegates to
    /// the `_and_sources` variant with all-`None` sources — only
    /// suitable for transitions whose `in_coins` are ALL inactive.
    /// Active in-coin slots require the
    /// [`Self::prove_account_update_with_in_and_out_coins_and_sources`]
    /// variant.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_account_update_with_in_and_out_coins(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        prev: &Proof,
        cmp: &CommitmentMerkleProofs,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
        out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
        next_public_key: &PublicKey,
    ) -> Result<Proof> {
        prove_account_update_with_in_and_out_coins(
            &self.circuit,
            account_state,
            history_root,
            prev,
            cmp,
            in_coins,
            out_coins,
            next_public_key,
        )
    }

    /// Stage 5d-next-5 Phase 2b Initial-branch prove with per-slot
    /// source witnesses for active in-coins. `sources.len()` must
    /// equal `MAX_IN_COINS`; `Some(_)` ↔ active source proof,
    /// `None` ↔ inactive slot.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_initial_with_in_and_out_coins_and_sources(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
        out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
        next_public_key: &PublicKey,
        sources: &[Option<InCoinSourceWitness>],
    ) -> Result<Proof> {
        prove_initial_with_in_and_out_coins_and_sources(
            &self.circuit,
            account_state,
            history_root,
            in_coins,
            out_coins,
            next_public_key,
            sources,
        )
    }

    /// Stage 5d-next-5 Phase 2b AccountUpdate-branch prove with
    /// per-slot source witnesses for active in-coins. Symmetric
    /// shape with [`Self::prove_initial_with_in_and_out_coins_and_sources`].
    #[allow(clippy::too_many_arguments)]
    pub fn prove_account_update_with_in_and_out_coins_and_sources(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        prev: &Proof,
        cmp: &CommitmentMerkleProofs,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
        out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
        next_public_key: &PublicKey,
        sources: &[Option<InCoinSourceWitness>],
    ) -> Result<Proof> {
        prove_account_update_with_in_and_out_coins_and_sources(
            &self.circuit,
            account_state,
            history_root,
            prev,
            cmp,
            in_coins,
            out_coins,
            next_public_key,
            sources,
        )
    }

    /// Verify a proof against the prover's circuit. Runs both
    /// `check_cyclic_proof_verifier_data` (cross-check that the
    /// proof's pinned `circuit_digest` matches this circuit's own)
    /// and the underlying Plonky2 `data.verify`.
    pub fn verify(&self, proof: &Proof) -> Result<()> {
        verify(&self.circuit, proof)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use zkcoins_program_plonky2::types::MINTING_ADDRESS;

    fn dummy_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        for (i, b) in pk.iter_mut().enumerate().skip(1) {
            *b = seed.wrapping_add(i as u8);
        }
        pk
    }

    /// Smoke test: build a `Prover`, prove an empty Init transition,
    /// verify it. Validates the wrapper compiles + threads through
    /// the underlying program-plonky2 APIs end-to-end.
    ///
    /// Heavy (~3-15 min wall at production parameters MAX=8); flagged
    /// `#[ignore]` so the routine `cargo test` sweep skips it. Run
    /// explicitly via `cargo test --release prover_init_roundtrip --
    /// --ignored --nocapture`.
    #[test]
    #[ignore]
    fn prover_init_roundtrip() {
        let prover = Prover::new();
        let mut account_state = AccountState::new(dummy_pubkey(7));
        account_state.owner = *MINTING_ADDRESS;
        account_state.balance = 100;

        let history_root = zkcoins_program_plonky2::hash::hash_bytes(b"prover-test-history");
        let proof = prover
            .prove_initial(&account_state, history_root)
            .expect("prove initial");
        prover.verify(&proof).expect("verify");
    }
}
