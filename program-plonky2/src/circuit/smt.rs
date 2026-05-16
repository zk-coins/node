//! In-circuit sparse Merkle tree gadgets.
//!
//! Off-circuit equivalents live in
//! [`crate::merkle::sparse_merkle_tree`]; this module ports their
//! verification logic to Plonky2 constraints.
//!
//! ## Key encoding
//!
//! The SMT key is a 256-bit value. Off-circuit it is held as `[u8; 32]`,
//! MSB-first per byte. In-circuit it is held as a `HashOutTarget` (4
//! Goldilocks elements). The two representations are interconverted via
//! the big-endian-per-element scheme in `crate::hash::digest_to_bytes` /
//! `digest_from_bytes`. As a consequence, bit 0 of the key (the topmost
//! tree-selector) is the most-significant bit of `key.elements[0]`.
//!
//! ## Variable-depth proofs
//!
//! The off-circuit SMT uses path compression: a single-leaf subtree at
//! level L stores `leaf_hash` rather than a `hash_concat` of children, and
//! `generate_inclusion_proof` breaks early once it detects this. The
//! resulting proof has `K <= TREE_DEPTH` siblings.
//!
//! The gadgets here accept a path of any length `K` and hash up exactly
//! `K` levels. This is sufficient for unit tests that drive the gadget
//! with proofs straight from the off-circuit `SparseMerkleTree`. The
//! monolithic state-transition circuit (Step 5 in `ROADMAP.md`) will
//! eventually need fixed-length paths padded by the host; that scaffolding
//! lands in a later commit.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::util::swap_if;

/// Decompose a `HashOutTarget` representing a 256-bit key into 256 bits in
/// the canonical MSB-first ordering used by `crate::merkle::sparse_merkle_tree::get_bit`.
///
/// Bit `i` of the result equals `get_bit(digest_to_bytes(key), i)`. In
/// other words: `result[0]` is the most-significant bit of byte 0 of the
/// big-endian serialisation of `key.elements[0]`.
pub fn key_bits_msb_first<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key: HashOutTarget,
) -> Vec<BoolTarget> {
    let mut bits = Vec::with_capacity(256);
    for element in key.elements.iter() {
        // split_le yields bit 0 (LSB) first; reverse to MSB-first.
        let mut le_bits = builder.split_le(*element, 64);
        le_bits.reverse();
        bits.extend(le_bits);
    }
    bits
}

/// Verify an SMT inclusion proof in-circuit.
///
/// Off-circuit equivalent:
/// [`crate::merkle::sparse_merkle_tree::InclusionProof::verify`].
///
/// `path[0]` is the sibling at level 1 (just below root), and
/// `path[path.len() - 1]` is the deepest sibling. Walking up from the
/// leaf: at iteration `i` of consuming `path` in reverse, the gadget
/// selects branch order using `key_bits[path.len() - 1 - i]`.
///
/// `key_bits` is the full 256-bit MSB-first decomposition (use
/// [`key_bits_msb_first`] to produce it); only the first `path.len()`
/// entries are read.
pub fn verify_smt_inclusion<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOutTarget,
    key: HashOutTarget,
    key_bits: &[BoolTarget],
    path: &[HashOutTarget],
    expected_root: HashOutTarget,
) {
    assert!(
        key_bits.len() >= path.len(),
        "verify_smt_inclusion: key_bits must cover at least path.len() levels"
    );

    // leaf_hash = Poseidon(leaf || key) — matches off-circuit `leaf_hash`.
    let mut input = Vec::with_capacity(8);
    input.extend_from_slice(&leaf.elements);
    input.extend_from_slice(&key.elements);
    let mut current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);

    let k = path.len();
    for (i, sibling) in path.iter().rev().enumerate() {
        let bit = key_bits[k - 1 - i];
        let (left, right) = swap_if(builder, bit, current, *sibling);
        let mut input = Vec::with_capacity(8);
        input.extend_from_slice(&left.elements);
        input.extend_from_slice(&right.elements);
        current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
    }

    builder.connect_hashes(current, expected_root);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{digest_from_bytes, hash_bytes, HashDigest, ZERO_HASH};
    use crate::merkle::sparse_merkle_tree::SparseMerkleTree;
    use crate::{C, D, F};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;

    /// Build a tree with `keys`, generate an inclusion proof for `target_key`,
    /// witness it through the in-circuit gadget, prove, verify.
    fn round_trip(keys: &[[u8; 32]], values: &[HashDigest], target_key: [u8; 32]) {
        // Off-circuit SMT
        let mut tree = SparseMerkleTree::new();
        for (k, v) in keys.iter().zip(values.iter()) {
            tree.insert(*k, *v).unwrap();
        }
        let target_value = tree.get(&target_key).unwrap();
        let (proof, _) = tree.generate_inclusion_proof(&target_key).unwrap();
        assert!(
            proof.verify(target_value, tree.root()),
            "off-circuit sanity"
        );
        let depth = proof.siblings.len();

        // Circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let leaf_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..depth).map(|_| builder.add_virtual_hash()).collect();
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        verify_smt_inclusion(&mut builder, leaf_t, key_t, &key_bits, &path_t, root_t);
        let data = builder.build::<C>();

        // Witness
        let mut pw = PartialWitness::new();
        pw.set_hash_target(leaf_t, target_value).unwrap();
        pw.set_hash_target(key_t, digest_from_bytes(&target_key))
            .unwrap();
        pw.set_hash_target(root_t, tree.root()).unwrap();
        for (i, sib) in proof.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        let proof_with_pis = data.prove(pw).expect("prove failed");
        data.verify(proof_with_pis).expect("verify failed");
    }

    /// Two-leaf tree that diverges at bit 0 — produces the smallest possible
    /// proof (one sibling).
    #[test]
    fn smt_inclusion_two_leaves_bit0_divergent() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x80; // bit 0 = 1
        let v0 = hash_bytes(b"v0");
        let v1 = hash_bytes(b"v1");
        round_trip(&[k0, k1], &[v0, v1], k0);
        round_trip(&[k0, k1], &[v0, v1], k1);
    }

    /// Two-leaf tree that diverges at bit 7 — proof length 8.
    #[test]
    fn smt_inclusion_two_leaves_bit7_divergent() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x01; // bit 7 = 1 (LSB of byte 0)
        let v0 = hash_bytes(b"v0");
        let v1 = hash_bytes(b"v1");
        round_trip(&[k0, k1], &[v0, v1], k0);
        round_trip(&[k0, k1], &[v0, v1], k1);
    }

    /// Three-leaf tree, all queries.
    #[test]
    fn smt_inclusion_three_leaves() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x40; // bit 1 = 1
        let mut k2 = [0u8; 32];
        k2[0] = 0xC0; // bits 0,1 = 1,1
        let vs = [hash_bytes(b"v0"), hash_bytes(b"v1"), hash_bytes(b"v2")];
        round_trip(&[k0, k1, k2], &vs, k0);
        round_trip(&[k0, k1, k2], &vs, k1);
        round_trip(&[k0, k1, k2], &vs, k2);
    }

    /// Tampered leaf value must not be provable against an honest root.
    #[test]
    fn smt_inclusion_tampered_leaf_fails() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x80;
        let v0 = hash_bytes(b"v0");
        let v1 = hash_bytes(b"v1");

        let mut tree = SparseMerkleTree::new();
        tree.insert(k0, v0).unwrap();
        tree.insert(k1, v1).unwrap();
        let (proof, _) = tree.generate_inclusion_proof(&k0).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let leaf_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..proof.siblings.len())
            .map(|_| builder.add_virtual_hash())
            .collect();
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        verify_smt_inclusion(&mut builder, leaf_t, key_t, &key_bits, &path_t, root_t);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        // Wrong leaf value: ZERO_HASH instead of v0.
        pw.set_hash_target(leaf_t, ZERO_HASH).unwrap();
        pw.set_hash_target(key_t, digest_from_bytes(&k0)).unwrap();
        pw.set_hash_target(root_t, tree.root()).unwrap();
        for (i, sib) in proof.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        assert!(data.prove(pw).is_err(), "tampered leaf must not prove");
    }
}
