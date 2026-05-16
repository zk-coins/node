//! Higher-level inputs to the state-transition circuit: `ProofType`,
//! `CommitmentMerkleProofs`, and `ProgramInputs`.
//!
//! Ports `program/src/lib.rs` (the SP1 host-side data shapes) modulo
//! Plonky2-specific changes:
//!
//! - `verification_key` is dropped here — Plonky2 binds the circuit digest
//!   via `add_verifier_data_public_inputs` at circuit-build time, not as a
//!   witness field. The monolithic circuit (Step 5) will handle that wiring.
//! - `prev_proof_public_values` and `in_coin_proofs_public_values` (raw byte
//!   blobs in SP1) become typed `ProofData` values. The actual recursive
//!   proof artifacts are passed to the prover separately as
//!   `ProofWithPublicInputs<F, C, D>` — not in this struct.

use crate::hash::{hash_concat, HashDigest};
use crate::merkle::merkle_mountain_range::MMRProof;
use crate::merkle::sparse_merkle_tree::{InclusionProof, NonInclusionProof};
use crate::types::{AccountState, Coin, ProofData, PublicKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofType {
    InitialProof,
    AccountUpdateProof,
}

/// Merkle proofs that link a single past proof (account or coin) to the
/// current global commitment-history root.
///
/// Off-circuit verification methods mirror the SP1 implementation; the
/// in-circuit gadget for the same predicate will land in the monolithic
/// circuit module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentMerkleProofs {
    /// Root of the commitment SMT in which `commitment_proof` proves
    /// inclusion.
    pub commitment_root: HashDigest,
    /// Inclusion proof: `commitment` is at `commitment_pk` in the SMT.
    pub commitment_proof: InclusionProof,
    /// MMR proof: `(commitment_root || prev_mmr_root)` is at some leaf of
    /// the commitment-history MMR.
    pub commitment_root_history_proof: MMRProof,
    /// The previous MMR root at the time `commitment_root` was folded in.
    pub commitment_root_mmr_sibling: HashDigest,
    /// MMR proof that the PRIOR proof's history root is also in the MMR —
    /// the `.0` is the SMT root that was folded with that prior root.
    pub previous_root_history_proof: (HashDigest, MMRProof),
    /// The opened account-state hash committed by the witnessed proof.
    pub commitment_account_state_hash: HashDigest,
    /// The opened output-coins root committed by the witnessed proof.
    pub commitment_out_coins_root: HashDigest,
}

impl CommitmentMerkleProofs {
    /// `commitment = H(asth || ocr)`, the value stored in the commitment SMT.
    pub fn commitment(&self) -> HashDigest {
        hash_concat(
            &self.commitment_account_state_hash,
            &self.commitment_out_coins_root,
        )
    }

    fn verify_commitment_root(&self, commitment_history_root: HashDigest) -> bool {
        self.commitment_root_history_proof.verify(
            hash_concat(&self.commitment_root, &self.commitment_root_mmr_sibling),
            commitment_history_root,
        )
    }

    /// Returns true iff this commitment is included in the global commitment
    /// history at `commitment_history_root`.
    pub fn verify_commitment(&self, commitment_history_root: HashDigest) -> bool {
        let valid_smt = self
            .commitment_proof
            .verify(self.commitment(), self.commitment_root);
        let valid_in_history = self.verify_commitment_root(commitment_history_root);
        valid_smt && valid_in_history
    }

    /// Returns true iff `previous_root` extends consistently to
    /// `commitment_history_root` via the prior MMR leaf.
    pub fn verify_previous_root(
        &self,
        previous_root: HashDigest,
        commitment_history_root: HashDigest,
    ) -> bool {
        self.previous_root_history_proof.1.verify(
            hash_concat(&self.previous_root_history_proof.0, &previous_root),
            commitment_history_root,
        )
    }
}

/// Private witness inputs to the state-transition circuit.
///
/// All recursive proof artifacts (the actual `ProofWithPublicInputs<F, C, D>`
/// objects) are passed to the prover separately; this struct only carries
/// the data that gets witnessed into the circuit as field elements.
#[derive(Clone, Debug)]
pub struct ProgramInputs {
    pub proof_type: ProofType,
    pub account_state: AccountState,
    pub current_history_root: HashDigest,

    /// The previous account proof's public output. Required for
    /// `AccountUpdateProof`, absent for `InitialProof`.
    pub prev_proof_public_values: Option<ProofData>,
    /// Witness chaining the previous account proof to the current history.
    /// Required for `AccountUpdateProof`.
    pub prev_proof_history_proofs: Option<CommitmentMerkleProofs>,

    pub in_coins: Vec<Coin>,
    /// Public output of each in-coin's source send proof, parallel-indexed
    /// with `in_coins`.
    pub in_coin_proofs_public_values: Vec<ProofData>,
    /// Witness chaining each in-coin's source send proof to current history.
    pub in_coin_proofs_history_proofs: Vec<CommitmentMerkleProofs>,
    /// Non-inclusion proofs of each in-coin into the account's own
    /// coin-history SMT before insertion.
    pub in_coin_proofs_non_inclusion_proofs: Vec<NonInclusionProof>,
    /// Inclusion proofs that each in-coin is in its source's
    /// `out_coins_root`.
    pub in_coins_inclusion_proofs: Vec<InclusionProof>,

    pub out_coins: Vec<Coin>,
    /// Running non-inclusion proofs used to build `out_coins_root`.
    pub out_coin_proofs: Vec<NonInclusionProof>,
    pub next_public_key: PublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_bytes;
    use crate::merkle::merkle_mountain_range::MerkleMountainRange;
    use crate::merkle::sparse_merkle_tree::SparseMerkleTree;

    fn dummy_pk() -> PublicKey {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        pk
    }

    #[test]
    fn proof_type_round_trip() {
        // Tiny sanity test: variants compare by identity.
        let a = ProofType::InitialProof;
        let b = ProofType::InitialProof;
        let c = ProofType::AccountUpdateProof;
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn commitment_value_matches_off_circuit_definition() {
        let asth = hash_bytes(b"asth");
        let ocr = hash_bytes(b"ocr");
        let proofs = CommitmentMerkleProofs {
            commitment_root: hash_bytes(b"sr"),
            commitment_proof: InclusionProof {
                key: [0u8; 32],
                siblings: vec![],
            },
            commitment_root_history_proof: MMRProof::new(vec![], 0),
            commitment_root_mmr_sibling: hash_bytes(b"prev_mmr"),
            previous_root_history_proof: (hash_bytes(b"prev_smt"), MMRProof::new(vec![], 0)),
            commitment_account_state_hash: asth,
            commitment_out_coins_root: ocr,
        };
        assert_eq!(proofs.commitment(), hash_concat(&asth, &ocr));
    }

    /// End-to-end off-circuit witness construction: build a commitment SMT +
    /// MMR pair, derive a `CommitmentMerkleProofs`, verify it against the
    /// history root. This is the data shape the circuit will consume.
    #[test]
    fn verify_commitment_against_built_history() {
        // 1. Place a fake commitment (pk -> H(asth||ocr)) in the SMT.
        let pk_hash = hash_bytes(b"pubkey-hash");
        let mut pk_key = [0u8; 32];
        for (i, e) in pk_hash.elements.iter().enumerate() {
            pk_key[i * 8..(i + 1) * 8].copy_from_slice(&e.0.to_be_bytes());
        }

        let asth = hash_bytes(b"asth");
        let ocr = hash_bytes(b"ocr");
        let commitment = hash_concat(&asth, &ocr);

        let mut smt = SparseMerkleTree::new();
        smt.insert(pk_key, commitment).unwrap();
        let smt_root = smt.root();
        let (inc_proof, _) = smt.generate_inclusion_proof(&pk_key).unwrap();

        // 2. Fold smt_root into an MMR. The leaf is H(smt_root || prev_mmr_root)
        //    where prev_mmr_root is ZERO_HASH on first fold.
        let prev_mmr_root = crate::hash::ZERO_HASH;
        let leaf = hash_concat(&smt_root, &prev_mmr_root);
        let mut mmr = MerkleMountainRange::new();
        mmr.append(leaf);
        let history_root = mmr.root();
        let mmr_proof = mmr.get_proof(0).unwrap();

        let proofs = CommitmentMerkleProofs {
            commitment_root: smt_root,
            commitment_proof: inc_proof,
            commitment_root_history_proof: mmr_proof,
            commitment_root_mmr_sibling: prev_mmr_root,
            previous_root_history_proof: (smt_root, MMRProof::new(vec![], 0)),
            commitment_account_state_hash: asth,
            commitment_out_coins_root: ocr,
        };

        assert!(proofs.verify_commitment(history_root));
    }

    #[test]
    fn program_inputs_initial_proof_optional_fields() {
        let inputs = ProgramInputs {
            proof_type: ProofType::InitialProof,
            account_state: AccountState::new(dummy_pk()),
            current_history_root: crate::hash::ZERO_HASH,
            prev_proof_public_values: None,
            prev_proof_history_proofs: None,
            in_coins: vec![],
            in_coin_proofs_public_values: vec![],
            in_coin_proofs_history_proofs: vec![],
            in_coin_proofs_non_inclusion_proofs: vec![],
            in_coins_inclusion_proofs: vec![],
            out_coins: vec![],
            out_coin_proofs: vec![],
            next_public_key: dummy_pk(),
        };
        // The shape compiles and the InitialProof branch leaves prev_* None.
        assert!(matches!(inputs.proof_type, ProofType::InitialProof));
        assert!(inputs.prev_proof_public_values.is_none());
        assert!(inputs.prev_proof_history_proofs.is_none());
    }
}
