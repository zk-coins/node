use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use shared::commitment::Commitment;
use sqlx::PgPool;
use std::collections::HashMap;
use zkcoins_program::circuit::main::MMR_PROOF_PATH_LEN;
use zkcoins_program::hash::{hash_concat, HashDigest, ZERO_HASH};
use zkcoins_program::merkle::merkle_mountain_range::{MMRProof, MerkleMountainRange};
use zkcoins_program::merkle::sparse_merkle_tree::{InclusionProof, SparseMerkleTree};

use crate::db;

/// State stores both a Sparse Merkle Tree (for individual commitments)
/// and a Merkle Mountain Range (for accumulating SMT roots).
#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    /// The Sparse Merkle Tree to store individual commitments
    pub smt: SparseMerkleTree,
    /// The Merkle Mountain Range to accumulate SMT roots
    pub mmr: MerkleMountainRange,
    /// Maps previous MMR roots to (SMT root, leaf index) pairs
    pub root_indices: HashMap<HashDigest, (HashDigest, usize)>,
    /// The previous MMR root
    pub prev_mmr_root: HashDigest,
}

/// Error type for `State::load_from_pg`. Distinguishes database errors
/// (connectivity, schema mismatch) from on-disk-blob corruption
/// (bincode rejected the SMT or MMR payload) so the bootstrap caller
/// can react accordingly.
#[derive(Debug)]
pub enum LoadStateError {
    /// The Postgres call itself failed (connect, query, decode).
    Db(sqlx::Error),
    /// The SMT/MMR bincode blob in Postgres could not be deserialized.
    Deserialize(bincode::Error),
}

impl std::fmt::Display for LoadStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadStateError::Db(e) => write!(f, "database error: {}", e),
            LoadStateError::Deserialize(e) => write!(f, "state blob deserialize: {}", e),
        }
    }
}

impl std::error::Error for LoadStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadStateError::Db(e) => Some(e),
            LoadStateError::Deserialize(e) => Some(e),
        }
    }
}

impl From<sqlx::Error> for LoadStateError {
    fn from(e: sqlx::Error) -> Self {
        LoadStateError::Db(e)
    }
}

impl From<bincode::Error> for LoadStateError {
    fn from(e: bincode::Error) -> Self {
        LoadStateError::Deserialize(e)
    }
}

impl State {
    /// Creates a new state with an empty SMT of the default depth and an empty MMR.
    pub fn new() -> Self {
        State {
            smt: SparseMerkleTree::new(),
            mmr: MerkleMountainRange::new(),
            root_indices: HashMap::new(),
            prev_mmr_root: ZERO_HASH,
        }
    }

    /// Updates the state by inserting a set of commitments into the SMT,
    /// then appending a new leaf to the MMR that combines the new SMT root
    /// and the previous MMR root.
    ///
    /// Returns the new MMR root.
    ///
    /// After a successful call, the freshly-inserted `root_indices`
    /// entry is uniquely identifiable as
    /// `(self.prev_mmr_root, self.root_indices[&self.prev_mmr_root])`
    /// — the function writes `self.prev_mmr_root` and inserts using the
    /// same value as the map key, in that order, immediately before
    /// `self.mmr.append`. Callers that need to persist this entry
    /// (Phase C: `db::insert_root_index`) read it back from `self`
    /// rather than threading a pool into this synchronous method, which
    /// would force every test caller to grow a Postgres dependency.
    pub fn update(&mut self, commitments: &[Commitment]) -> Result<HashDigest, &'static str> {
        // 1. Insert all commitments into the SMT
        for commitment in commitments {
            // Use the public key as the key for the tree (hashed)
            let key_bytes = commitment.public_key.serialize();
            let key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&key_bytes).to_byte_array();

            // Store the BIP-340 message digest (32 raw bytes) reinterpreted
            // as a Poseidon `HashOut<F>` — `digest_from_bytes` is the
            // canonical inverse of `digest_to_bytes` (round-trip safe).
            let message_bytes = commitment.get_account_state_hash();
            let message_data = zkcoins_program::hash::digest_from_bytes(&message_bytes);

            // Update the SMT with just the message
            self.smt.insert(key, message_data)?;
        }

        // 2. Get the current SMT root
        let smt_root = self.smt.root();

        // 3. Create a new leaf that combines the SMT root and previous MMR
        // root. Uses Poseidon `hash_concat` (architectural invariant:
        // Poseidon everywhere in Merkle structures). Replaces the
        // SP1-era SHA256.
        //
        // The previous MMR root is recorded in its *extended* form
        // (`mmr.root_extended(MMR_PROOF_PATH_LEN)`) because every
        // downstream consumer — the public output of a Plonky2 proof
        // (`commitment_history_root` in `ProofData`), the in-circuit
        // CMP sibling (`commitment_root_mmr_sibling`), and the
        // `root_indices` lookup at the next AccountUpdate — works in
        // the extended representation that the circuit's fixed-depth
        // invariant demands. Using the natural root anywhere along
        // that chain produces a hash that the circuit can't reconcile
        // with the public input, surfacing as a witness-partition
        // conflict at prove time.
        let prev_mmr_root = self.mmr.root_extended(MMR_PROOF_PATH_LEN);
        self.prev_mmr_root = prev_mmr_root;

        let leaf = hash_concat(&smt_root, &prev_mmr_root);

        let leaf_index = self.mmr.leaf_count();
        self.root_indices
            .insert(prev_mmr_root, (smt_root, leaf_index));

        // 4. Append the new leaf to the MMR
        self.mmr.append(leaf);

        // 5. Return the new MMR root
        Ok(self.mmr.root())
    }

    /// Gets an inclusion proof for a leaf in the MMR that was created with the given previous MMR root.
    pub fn get_mmr_inclusion_proof(
        &self,
        prev_mmr_root: HashDigest,
    ) -> Result<(HashDigest, MMRProof), &'static str> {
        match self.root_indices.get(&prev_mmr_root) {
            Some(&(smt_root, index)) => self.mmr.get_proof(index).map(|proof| (smt_root, proof)),
            None => Err("Couldn't find MMR inclusion proof"),
        }
    }

    /// Gets an inclusion proof for a specific commitment in the SMT,
    /// along with an inclusion proof of the current SMT root in the MMR.
    pub fn get_commitment_proof(
        &self,
        public_key: &PublicKey,
    ) -> Result<(HashDigest, InclusionProof, HashDigest, MMRProof), &'static str> {
        let key_bytes = public_key.serialize();
        let key: [u8; 32] = bitcoin::hashes::sha256::Hash::hash(&key_bytes).to_byte_array();

        let (smt_proof, commitment) = self.smt.generate_inclusion_proof(&key)?;

        let smt_root = self.smt.root();

        let leaf_count = self.mmr.leaf_count();
        if leaf_count == 0 {
            return Err("MMR leaf count = 0");
        }
        let latest_leaf_index = leaf_count - 1;

        let mmr_proof = self.mmr.get_proof(latest_leaf_index)?;

        Ok((commitment, smt_proof, smt_root, mmr_proof))
    }

    /// Load the SMT and MMR blobs from Postgres and rebuild a `State`,
    /// then rehydrate `root_indices` and `prev_mmr_root` from the
    /// dedicated `mmr_root_index` table (migration `0004`).
    ///
    /// Phase C of the state-layer hardening series. Before this code
    /// landed, `root_indices` was treated as a pure runtime memoization
    /// and silently reset to empty on every restart — which broke any
    /// account whose latest proof referenced a `commitment_history_root`
    /// produced before the restart (`get_mmr_inclusion_proof` returned
    /// `Err`, `/api/mint` surfaced 422 `Unable to get mmr inclusion
    /// proof for the previous root`). The map is now persisted per
    /// successful `update()` and rebuilt here.
    ///
    /// `prev_mmr_root` is restored from the highest-`leaf_index` entry
    /// in the loaded map — that entry's KEY is precisely the value the
    /// last successful `update()` wrote to `self.prev_mmr_root`
    /// (`update` inserts using `prev_mmr_root` as the key and the
    /// current `leaf_count` as the leaf_index, in that order, immediately
    /// before `mmr.append`). On a fresh database the table is empty,
    /// `root_indices` stays empty, and `prev_mmr_root` stays
    /// `ZERO_HASH` exactly like `State::new`.
    pub async fn load_from_pg(pool: &PgPool) -> Result<Self, LoadStateError> {
        let mut state = Self::new();
        if let Some(data) = db::load_smt(pool).await? {
            state.smt = bincode::deserialize(&data)?;
        }
        if let Some(data) = db::load_mmr(pool).await? {
            state.mmr = bincode::deserialize(&data)?;
        }
        let entries = db::load_root_indices(pool).await?;
        // The DB ORDER BY leaf_index means `entries` is monotonic; the
        // last element is the one whose KEY is the most recently written
        // `prev_mmr_root`. Drain it in order, capturing the last KEY as
        // we go so we don't have to re-scan the assembled HashMap.
        let mut last_key: Option<HashDigest> = None;
        for (prev_root, smt_root, leaf_index) in entries {
            // `leaf_index` came back as `u64` and was previously checked
            // non-negative by `db::load_root_indices`. The production
            // target is 64-bit (Linux x86_64 / aarch64), so the cast is
            // provably infallible — `usize::try_from` would only fail on
            // a 32-bit target, which we don't ship. `debug_assert!`
            // guards the hypothetical 32-bit dev build without forcing
            // an uncoverable error branch on the production target,
            // which the Coverage Gate (100% lines+functions on
            // `state.rs`) cannot exercise.
            debug_assert!(
                leaf_index <= usize::MAX as u64,
                "mmr_root_index.leaf_index {} does not fit in usize on this target",
                leaf_index
            );
            let leaf_usize = leaf_index as usize;
            state.root_indices.insert(prev_root, (smt_root, leaf_usize));
            last_key = Some(prev_root);
        }
        if let Some(prev) = last_key {
            state.prev_mmr_root = prev;
        }
        Ok(state)
    }

    /// Serialize the SMT and MMR to bincode blobs for `persist_state_tx`.
    ///
    /// Returned tuple is `(smt_bytes, mmr_bytes)`. The caller is
    /// expected to hand these straight to `db::persist_state_tx`
    /// together with the corresponding block hash.
    ///
    /// `bincode::serialize` on these structures is infallible in
    /// practice (no `Serialize` impl in the SMT/MMR trees returns Err),
    /// but the error path is propagated as a `bincode::Error` rather
    /// than panicked over so a future schema change that introduces a
    /// fallible branch surfaces as a recoverable error.
    pub fn serialize_for_persist(&self) -> Result<(Vec<u8>, Vec<u8>), bincode::Error> {
        let smt_bytes = bincode::serialize(&self.smt)?;
        let mmr_bytes = bincode::serialize(&self.mmr)?;
        Ok((smt_bytes, mmr_bytes))
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
