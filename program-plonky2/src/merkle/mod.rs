//! Merkle structures over Poseidon: sparse Merkle tree (SMT) for the
//! per-account coin history and the global commitment SMT, and a
//! Merkle mountain range (MMR) for the global commitment history.
//!
//! Algorithms mirror `program/src/merkle/` (SHA256 version) exactly;
//! only the hash is swapped to Poseidon over Goldilocks. The byte-level
//! key indexing (`[u8; 32]`) is preserved so the in-circuit gadget can
//! use the same MSB-first bit selector path as the off-circuit code.

pub mod sparse_merkle_tree;
