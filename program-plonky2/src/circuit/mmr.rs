//! In-circuit Merkle mountain range inclusion verification.
//!
//! Off-circuit equivalent: [`crate::merkle::merkle_mountain_range::MMRProof::verify`].
//!
//! The gadget verifies that `leaf` connects to `expected_root` along
//! `path`, where each path step's swap orientation is selected by one bit of
//! `index` (LSB-first). The depth is fixed by `path.len()`; the host MUST
//! pad shorter proofs to the circuit's configured `MAX_MMR_DEPTH` with
//! `ZERO_HASH` siblings, and zero-pad the corresponding high bits of
//! `index`. Padding entries are no-ops: a sibling of `ZERO_HASH` at a level
//! above the real tree top is exactly what the off-circuit MMR `root()`
//! would have hashed against, so the chain extends consistently.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::util::swap_if;

/// Compute the MMR root from an inclusion proof in-circuit, without
/// constraining it to any expected root. Caller is responsible for
/// connecting the returned `HashOutTarget` to its expected value.
///
/// `index_bits` must have the same length as `path` and represent the
/// LSB-first bit decomposition of the leaf's index (within the
/// fixed-shape MMR depth chosen by the caller).
pub fn mmr_inclusion_root<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOutTarget,
    index_bits: &[BoolTarget],
    path: &[HashOutTarget],
) -> HashOutTarget {
    assert_eq!(
        index_bits.len(),
        path.len(),
        "mmr_inclusion_root: index_bits and path must have equal length"
    );
    let mut current = leaf;
    for (bit, sibling) in index_bits.iter().zip(path.iter()) {
        let (left, right) = swap_if(builder, *bit, current, *sibling);
        let mut input = Vec::with_capacity(8);
        input.extend_from_slice(&left.elements);
        input.extend_from_slice(&right.elements);
        current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
    }
    current
}

/// Verify an MMR inclusion proof in-circuit.
///
/// Adds constraints that fail the proof unless `leaf` hashes up through
/// `path` (with sibling ordering driven by the LSB-first bits of `index`)
/// to `expected_root`.
pub fn verify_mmr_inclusion<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOutTarget,
    index_bits: &[BoolTarget],
    path: &[HashOutTarget],
    expected_root: HashOutTarget,
) {
    let current = mmr_inclusion_root(builder, leaf, index_bits, path);
    builder.connect_hashes(current, expected_root);
}

/// Convenience helper: bit-decompose `index` (LSB-first, fixed-width) and
/// call [`verify_mmr_inclusion`]. `width` MUST match `path.len()`.
pub fn verify_mmr_inclusion_with_index<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOutTarget,
    index: Target,
    path: &[HashOutTarget],
    expected_root: HashOutTarget,
) {
    let index_bits = builder.split_le(index, path.len());
    verify_mmr_inclusion(builder, leaf, &index_bits, path, expected_root);
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{hash_bytes, HashDigest, ZERO_HASH};
    use crate::merkle::merkle_mountain_range::MerkleMountainRange;
    use crate::{C, D, F};
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;

    /// Build a tree of `n` leaves (off-circuit), pick a leaf index, build a
    /// matching in-circuit MMR-inclusion proof, prove it, verify it.
    fn round_trip(n: usize, leaf_to_check: usize) {
        // Off-circuit MMR
        let mut tree = MerkleMountainRange::new();
        let leaves: Vec<HashDigest> = (0..n)
            .map(|i| hash_bytes(format!("leaf{i}").as_bytes()))
            .collect();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        let proof = tree.get_proof(leaf_to_check).unwrap();
        let depth = proof.path.len();

        // Circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let leaf_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let index_t = builder.add_virtual_target();
        let path_t: Vec<HashOutTarget> = (0..depth).map(|_| builder.add_virtual_hash()).collect();
        verify_mmr_inclusion_with_index(&mut builder, leaf_t, index_t, &path_t, root_t);

        // Make the leaf + index + root + path public so the test asserts on them.
        builder.register_public_inputs(&leaf_t.elements);
        builder.register_public_inputs(&root_t.elements);
        builder.register_public_input(index_t);

        let data = builder.build::<C>();

        // Witness
        let mut pw = PartialWitness::new();
        pw.set_hash_target(leaf_t, leaves[leaf_to_check]).unwrap();
        pw.set_hash_target(root_t, tree.root()).unwrap();
        pw.set_target(index_t, F::from_canonical_u32(proof.index))
            .unwrap();
        for (i, sib) in proof.path.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        let proof_with_pis = data.prove(pw).expect("prove failed");
        data.verify(proof_with_pis).expect("verify failed");
    }

    #[test]
    fn mmr_inclusion_single_leaf() {
        round_trip(1, 0);
    }

    #[test]
    fn mmr_inclusion_two_leaves() {
        round_trip(2, 0);
        round_trip(2, 1);
    }

    #[test]
    fn mmr_inclusion_growing_tree() {
        for n in 1..=8 {
            for i in 0..n {
                round_trip(n, i);
            }
        }
    }

    #[test]
    #[should_panic(expected = "index_bits and path must have equal length")]
    fn mismatched_bits_and_path_panics() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let leaf_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        // 3 path entries, 2 bits → mismatch should hit the assertion message.
        let path_t: Vec<HashOutTarget> = (0..3).map(|_| builder.add_virtual_hash()).collect();
        let bit0 = builder.add_virtual_bool_target_safe();
        let bit1 = builder.add_virtual_bool_target_safe();
        verify_mmr_inclusion(&mut builder, leaf_t, &[bit0, bit1], &path_t, root_t);
    }

    #[test]
    fn tampered_root_fails_proving() {
        let mut tree = MerkleMountainRange::new();
        tree.append(hash_bytes(b"leaf0"));
        tree.append(hash_bytes(b"leaf1"));
        let proof = tree.get_proof(0).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let leaf_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let index_t = builder.add_virtual_target();
        let path_t: Vec<HashOutTarget> = (0..proof.path.len())
            .map(|_| builder.add_virtual_hash())
            .collect();
        verify_mmr_inclusion_with_index(&mut builder, leaf_t, index_t, &path_t, root_t);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(leaf_t, hash_bytes(b"leaf0")).unwrap();
        // Wrong root: ZERO_HASH instead of tree.root().
        pw.set_hash_target(root_t, ZERO_HASH).unwrap();
        pw.set_target(index_t, F::from_canonical_u32(proof.index))
            .unwrap();
        for (i, sib) in proof.path.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        // Witness construction succeeds; proof generation must fail because
        // the connect_hashes constraint is unsatisfied.
        assert!(data.prove(pw).is_err(), "tampered root must not prove");
    }
}
