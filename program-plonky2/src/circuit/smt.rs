//! In-circuit sparse Merkle tree gadgets.
//!
//! Off-circuit equivalents live in
//! [`crate::merkle::sparse_merkle_tree`]; this module ports their
//! verification logic to Plonky2 constraints.
//!
//! ## Fixed depth
//!
//! All gadgets here operate on a **fixed [`TREE_DEPTH`]** path. The
//! off-circuit SMT (uncompressed variant) produces 256-sibling proofs
//! regardless of how sparsely the tree is populated, and the in-circuit
//! gadget always hashes through 256 levels. This is required for
//! Plonky2 cyclic recursion: the `circuit_digest` must be stable
//! across builds, which means the verifier shape cannot depend on
//! variable proof lengths.
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
//! Index convention for `key_bits` / `path`:
//! - `key_bits[level]` is the bit at MSB-index `level` (matches
//!   off-circuit `get_bit(key, level)`); `level = 0` is the topmost
//!   (root-level selector) and `level = TREE_DEPTH - 1` is the deepest.
//! - `path[level]` is the sibling of the node on `key`'s branch at
//!   `level + 1`; `level = 0` is the topmost sibling and
//!   `level = TREE_DEPTH - 1` is the deepest (just above the leaf).

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::util::swap_if;
use crate::merkle::sparse_merkle_tree::TREE_DEPTH;

/// Decompose a `HashOutTarget` representing a 256-bit key into 256 bits in
/// the canonical MSB-first ordering used by
/// [`crate::merkle::sparse_merkle_tree::get_bit`].
///
/// Bit `i` of the result equals `get_bit(digest_to_bytes(key), i)`. In
/// other words: `result[0]` is the most-significant bit of byte 0 of the
/// big-endian serialisation of `key.elements[0]`.
pub fn key_bits_msb_first<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key: HashOutTarget,
) -> Vec<BoolTarget> {
    let mut bits = Vec::with_capacity(TREE_DEPTH);
    for element in key.elements.iter() {
        // split_le yields bit 0 (LSB) first; reverse to MSB-first.
        let mut le_bits = builder.split_le(*element, 64);
        le_bits.reverse();
        bits.extend(le_bits);
    }
    bits
}

/// Hash from `start` (a depth-`TREE_DEPTH` value) up to the root through
/// `path`. At each `level ∈ [TREE_DEPTH - 1, 0]` the sibling at `path[level]`
/// is combined with the running hash, ordering chosen by `key_bits[level]`.
///
/// Returns the resulting root-level hash. This is the common engine for
/// every SMT proof gadget below: only the starting hash differs (leaf
/// hash for inclusion / insert-new, empty-leaf default for
/// non-inclusion / insert-old).
///
/// Exposed so external callers (e.g. the monolithic state-transition
/// circuit in `circuit/main.rs`) can build masked variants of the
/// inclusion / non-inclusion checks by reusing this engine with a
/// custom `start` value and then connecting the result to a
/// `select`-masked target.
pub fn hash_up_full_path<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    start: HashOutTarget,
    key_bits: &[BoolTarget],
    path: &[HashOutTarget],
) -> HashOutTarget {
    assert_eq!(
        path.len(),
        TREE_DEPTH,
        "hash_up_full_path: path must have exactly TREE_DEPTH siblings"
    );
    assert!(
        key_bits.len() >= TREE_DEPTH,
        "hash_up_full_path: key_bits must cover at least TREE_DEPTH levels"
    );
    let mut current = start;
    for level in (0..TREE_DEPTH).rev() {
        let bit = key_bits[level];
        let sibling = path[level];
        let (left, right) = swap_if(builder, bit, current, sibling);
        let mut input = Vec::with_capacity(8);
        input.extend_from_slice(&left.elements);
        input.extend_from_slice(&right.elements);
        current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
    }
    current
}

/// Compute the SMT leaf-hash `Poseidon(leaf_value || key)`. Used by
/// every inclusion / insert gadget. Shared as a helper so the same
/// 8-element absorption order is preserved everywhere.
fn smt_leaf_hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf_value: HashOutTarget,
    key: HashOutTarget,
) -> HashOutTarget {
    let mut input = Vec::with_capacity(8);
    input.extend_from_slice(&leaf_value.elements);
    input.extend_from_slice(&key.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(input)
}

/// Compute the SMT root from an inclusion proof in-circuit, without
/// constraining it to any expected value. Caller responsibility is to
/// connect the returned `HashOutTarget` to its expected root (possibly
/// via [`builder.connect_hashes`] or a masked / `select`-based path,
/// e.g. when the inclusion check should only fire under a guard
/// condition).
///
/// `key_bits` must contain the full 256-bit MSB-first decomposition of
/// `key` (use [`key_bits_msb_first`]); `path` must have exactly
/// [`TREE_DEPTH`] sibling hashes.
pub fn smt_inclusion_root<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOutTarget,
    key: HashOutTarget,
    key_bits: &[BoolTarget],
    path: &[HashOutTarget],
) -> HashOutTarget {
    let start = smt_leaf_hash(builder, leaf, key);
    hash_up_full_path(builder, start, key_bits, path)
}

/// Verify an SMT inclusion proof in-circuit.
///
/// Off-circuit equivalent:
/// [`crate::merkle::sparse_merkle_tree::InclusionProof::verify`].
pub fn verify_smt_inclusion<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOutTarget,
    key: HashOutTarget,
    key_bits: &[BoolTarget],
    path: &[HashOutTarget],
    expected_root: HashOutTarget,
) {
    let computed = smt_inclusion_root(builder, leaf, key, key_bits, path);
    builder.connect_hashes(computed, expected_root);
}

/// Verify an SMT non-inclusion proof in-circuit.
///
/// Off-circuit equivalent:
/// [`crate::merkle::sparse_merkle_tree::NonInclusionProof::verify`].
///
/// The proof witnesses that `key`'s leaf slot at depth [`TREE_DEPTH`]
/// holds the empty-leaf default value (`DEFAULT_HASHES[TREE_DEPTH]`).
/// `empty_leaf_default` is that constant, witnessed by the caller; the
/// gadget hashes it up through `path` and `key_bits` and asserts the
/// result equals `expected_root`.
pub fn verify_smt_non_inclusion<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key_bits: &[BoolTarget],
    path: &[HashOutTarget],
    expected_root: HashOutTarget,
    empty_leaf_default: HashOutTarget,
) {
    // `key` itself is not a parameter — its branch information is fully
    // captured by `key_bits` (the caller produces the bits via
    // `key_bits_msb_first`). The non-inclusion predicate is simply:
    // "the leaf slot at `key` holds the empty-leaf default".
    let computed = hash_up_full_path(builder, empty_leaf_default, key_bits, path);
    builder.connect_hashes(computed, expected_root);
}

/// Verify an SMT non-inclusion proof AND compute the new root after
/// inserting `(new_value, key)` at that key, asserting equality with
/// `expected_new_root`.
///
/// Off-circuit equivalent:
/// [`crate::merkle::sparse_merkle_tree::NonInclusionProof::verify_and_insert`].
///
/// Both the old and new roots are computed by hashing up the same
/// `path` siblings; only the starting hash differs:
/// - Old-root walk starts from `empty_leaf_default`
///   (= `DEFAULT_HASHES[TREE_DEPTH]`) and must match `expected_old_root`.
/// - New-root walk starts from `Poseidon(new_value || key)` and must
///   match `expected_new_root`.
#[allow(clippy::too_many_arguments)]
pub fn verify_smt_insert<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    new_value: HashOutTarget,
    key: HashOutTarget,
    key_bits: &[BoolTarget],
    path: &[HashOutTarget],
    expected_old_root: HashOutTarget,
    expected_new_root: HashOutTarget,
    empty_leaf_default: HashOutTarget,
) {
    // Old-root verification (mirrors verify_smt_non_inclusion).
    let old_computed = hash_up_full_path(builder, empty_leaf_default, key_bits, path);
    builder.connect_hashes(old_computed, expected_old_root);

    // New-root computation: same path, leaf-hash starting point.
    let new_start = smt_leaf_hash(builder, new_value, key);
    let new_computed = hash_up_full_path(builder, new_start, key_bits, path);
    builder.connect_hashes(new_computed, expected_new_root);
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{digest_from_bytes, hash_bytes, HashDigest, ZERO_HASH};
    use crate::merkle::sparse_merkle_tree::{SparseMerkleTree, DEFAULT_HASHES};
    use crate::{C, D, F};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;

    /// Builds a fresh 256-level SMT-inclusion-verify circuit, witnesses
    /// it, proves, verifies. Used by every inclusion positive-case test
    /// to keep the build-witness boilerplate in one place.
    fn inclusion_round_trip(keys: &[[u8; 32]], values: &[HashDigest], target_key: [u8; 32]) {
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
        assert_eq!(proof.siblings.len(), TREE_DEPTH);

        // Circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let leaf_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..TREE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect();
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

    /// Two-leaf tree that diverges at bit 0 — smallest possible
    /// divergence; siblings list contains real values at levels 0..
    /// and defaults elsewhere.
    #[test]
    fn smt_inclusion_two_leaves_bit0_divergent() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x80; // bit 0 = 1
        let v0 = hash_bytes(b"v0");
        let v1 = hash_bytes(b"v1");
        inclusion_round_trip(&[k0, k1], &[v0, v1], k0);
        inclusion_round_trip(&[k0, k1], &[v0, v1], k1);
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
        inclusion_round_trip(&[k0, k1, k2], &vs, k0);
        inclusion_round_trip(&[k0, k1, k2], &vs, k1);
        inclusion_round_trip(&[k0, k1, k2], &vs, k2);
    }

    /// Build a non-inclusion round-trip for `lookup`.
    fn non_inclusion_round_trip(tree: &SparseMerkleTree, lookup: [u8; 32]) {
        let nip = tree.generate_non_inclusion_proof(lookup).unwrap();
        assert!(nip.verify(), "off-circuit sanity");
        assert_eq!(nip.siblings.len(), TREE_DEPTH);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let key_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let empty_leaf_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..TREE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect();
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        verify_smt_non_inclusion(&mut builder, &key_bits, &path_t, root_t, empty_leaf_t);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(key_t, digest_from_bytes(&nip.key))
            .unwrap();
        pw.set_hash_target(root_t, nip.root).unwrap();
        pw.set_hash_target(empty_leaf_t, DEFAULT_HASHES[TREE_DEPTH])
            .unwrap();
        for (i, sib) in nip.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        let proof_with_pis = data.prove(pw).expect("prove failed");
        data.verify(proof_with_pis).expect("verify failed");
    }

    /// Non-inclusion in an empty tree: every sibling is a default, and
    /// the empty-leaf seed walks all the way up to `DEFAULT_HASHES[0]`.
    #[test]
    fn smt_non_inclusion_empty_tree() {
        let tree = SparseMerkleTree::new();
        non_inclusion_round_trip(&tree, [1u8; 32]);
    }

    /// Non-inclusion in a tree that already contains other leaves. The
    /// path siblings are a mix of real values (along the populated
    /// branches) and defaults.
    #[test]
    fn smt_non_inclusion_with_other_leaves() {
        let mut tree = SparseMerkleTree::new();
        let mut k0 = [0u8; 32];
        k0[0] = 0x80;
        tree.insert(k0, hash_bytes(b"v0")).unwrap();

        let mut k1 = [0u8; 32];
        k1[0] = 0x40;
        tree.insert(k1, hash_bytes(b"v1")).unwrap();

        // Lookup a third key not in the tree.
        let mut lookup = [0u8; 32];
        lookup[0] = 0x10;
        non_inclusion_round_trip(&tree, lookup);
    }

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
        let path_t: Vec<HashOutTarget> = (0..TREE_DEPTH)
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

    /// Tampered non-inclusion: present an empty-leaf default with the
    /// wrong value (e.g. ZERO_HASH instead of DEFAULT_HASHES[TREE_DEPTH]).
    /// The walk produces a different root and verification fails.
    #[test]
    fn smt_non_inclusion_wrong_empty_leaf_default_fails() {
        let tree = SparseMerkleTree::new();
        let nip = tree.generate_non_inclusion_proof([1u8; 32]).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let key_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let empty_leaf_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..TREE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect();
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        verify_smt_non_inclusion(&mut builder, &key_bits, &path_t, root_t, empty_leaf_t);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(key_t, digest_from_bytes(&nip.key))
            .unwrap();
        pw.set_hash_target(root_t, nip.root).unwrap();
        // Lie: claim the empty-leaf default is ZERO_HASH instead of the
        // protocol-defined domain-separated seed.
        pw.set_hash_target(empty_leaf_t, ZERO_HASH).unwrap();
        for (i, sib) in nip.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }
        assert!(
            data.prove(pw).is_err(),
            "wrong empty-leaf default must not prove"
        );
    }

    /// Insert round-trip helper. Builds the gadget, witnesses the
    /// inputs, proves and verifies.
    fn insert_round_trip(
        tree: &SparseMerkleTree,
        nip: &crate::merkle::sparse_merkle_tree::NonInclusionProof,
        new_value: HashDigest,
    ) {
        let expected_new_root = nip.verify_and_insert(new_value).expect("off-circuit");

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let new_value_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let old_root_t = builder.add_virtual_hash();
        let new_root_t = builder.add_virtual_hash();
        let empty_leaf_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..TREE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect();
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        verify_smt_insert(
            &mut builder,
            new_value_t,
            key_t,
            &key_bits,
            &path_t,
            old_root_t,
            new_root_t,
            empty_leaf_t,
        );
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(new_value_t, new_value).unwrap();
        pw.set_hash_target(key_t, digest_from_bytes(&nip.key))
            .unwrap();
        pw.set_hash_target(old_root_t, tree.root()).unwrap();
        pw.set_hash_target(new_root_t, expected_new_root).unwrap();
        pw.set_hash_target(empty_leaf_t, DEFAULT_HASHES[TREE_DEPTH])
            .unwrap();
        for (i, sib) in nip.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        let proof_with_pis = data.prove(pw).expect("prove failed");
        data.verify(proof_with_pis).expect("verify failed");
    }

    #[test]
    fn smt_insert_into_empty_tree() {
        let tree = SparseMerkleTree::new();
        let nip = tree.generate_non_inclusion_proof([1u8; 32]).unwrap();
        insert_round_trip(&tree, &nip, hash_bytes(b"new"));
    }

    #[test]
    fn smt_insert_into_populated_tree() {
        let mut tree = SparseMerkleTree::new();
        let mut k0 = [0u8; 32];
        k0[0] = 0x80;
        tree.insert(k0, hash_bytes(b"v0")).unwrap();
        let mut k1 = [0u8; 32];
        k1[0] = 0x40;
        tree.insert(k1, hash_bytes(b"v1")).unwrap();

        // Insert a third key.
        let mut new_key = [0u8; 32];
        new_key[31] = 0x01;
        let nip = tree.generate_non_inclusion_proof(new_key).unwrap();
        insert_round_trip(&tree, &nip, hash_bytes(b"v2"));
    }

    /// Tampered new-leaf value: the gadget computes a new_root from the
    /// lying `new_value` that doesn't match the honest `expected_new_root`
    /// witnessed alongside it; `connect_hashes` fails.
    #[test]
    fn smt_insert_tampered_new_value_fails() {
        let tree = SparseMerkleTree::new();
        let nip = tree.generate_non_inclusion_proof([1u8; 32]).unwrap();
        let honest_new_value = hash_bytes(b"honest");
        let expected_new_root = nip.verify_and_insert(honest_new_value).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let new_value_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let old_root_t = builder.add_virtual_hash();
        let new_root_t = builder.add_virtual_hash();
        let empty_leaf_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..TREE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect();
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        verify_smt_insert(
            &mut builder,
            new_value_t,
            key_t,
            &key_bits,
            &path_t,
            old_root_t,
            new_root_t,
            empty_leaf_t,
        );
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        // Lie: a different new_value than the one the expected_new_root was computed for.
        pw.set_hash_target(new_value_t, hash_bytes(b"lie")).unwrap();
        pw.set_hash_target(key_t, digest_from_bytes(&nip.key))
            .unwrap();
        pw.set_hash_target(old_root_t, tree.root()).unwrap();
        pw.set_hash_target(new_root_t, expected_new_root).unwrap();
        pw.set_hash_target(empty_leaf_t, DEFAULT_HASHES[TREE_DEPTH])
            .unwrap();
        for (i, sib) in nip.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        assert!(data.prove(pw).is_err(), "tampered new_value must not prove");
    }

    /// Tampered expected_new_root: the gadget computes the new root from
    /// the honest new_value but the witnessed `expected_new_root` is a
    /// different digest. `connect_hashes` fails.
    #[test]
    fn smt_insert_tampered_expected_new_root_fails() {
        let tree = SparseMerkleTree::new();
        let nip = tree.generate_non_inclusion_proof([1u8; 32]).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let new_value_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let old_root_t = builder.add_virtual_hash();
        let new_root_t = builder.add_virtual_hash();
        let empty_leaf_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..TREE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect();
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        verify_smt_insert(
            &mut builder,
            new_value_t,
            key_t,
            &key_bits,
            &path_t,
            old_root_t,
            new_root_t,
            empty_leaf_t,
        );
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(new_value_t, hash_bytes(b"new")).unwrap();
        pw.set_hash_target(key_t, digest_from_bytes(&nip.key))
            .unwrap();
        pw.set_hash_target(old_root_t, tree.root()).unwrap();
        // Lie: a random digest as the claimed new_root.
        pw.set_hash_target(new_root_t, hash_bytes(b"unrelated"))
            .unwrap();
        pw.set_hash_target(empty_leaf_t, DEFAULT_HASHES[TREE_DEPTH])
            .unwrap();
        for (i, sib) in nip.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        assert!(
            data.prove(pw).is_err(),
            "tampered expected_new_root must not prove"
        );
    }

    /// Build-time assertion: path of wrong length panics
    /// (`hash_up_full_path` checks `path.len() == TREE_DEPTH`).
    #[test]
    #[should_panic(expected = "path must have exactly TREE_DEPTH siblings")]
    fn smt_inclusion_short_path_panics() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let leaf_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..3).map(|_| builder.add_virtual_hash()).collect();
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        verify_smt_inclusion(&mut builder, leaf_t, key_t, &key_bits, &path_t, root_t);
    }

    /// Build-time assertion: key_bits too short panics.
    #[test]
    #[should_panic(expected = "key_bits must cover at least TREE_DEPTH levels")]
    fn smt_inclusion_short_key_bits_panics() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let leaf_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..TREE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect();
        // Only 2 bits — fewer than the TREE_DEPTH path.
        let bit0 = builder.add_virtual_bool_target_safe();
        let bit1 = builder.add_virtual_bool_target_safe();
        verify_smt_inclusion(&mut builder, leaf_t, key_t, &[bit0, bit1], &path_t, root_t);
    }
}
