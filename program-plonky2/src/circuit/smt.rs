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

/// Verify a non-inclusion proof in-circuit.
///
/// Off-circuit equivalent:
/// [`crate::merkle::sparse_merkle_tree::NonInclusionProof::verify`].
///
/// The proof distinguishes two cases (off-circuit a Rust `if`):
/// - **Case A** (empty subtree): `key == other_key` and `other_value`
///   equals `DEFAULT_HASHES[path.len()]`.
/// - **Case B** (path-compressed sibling leaf): `key != other_key`, and
///   the verifier hashes `leaf_hash(other_value, other_key)` up `path`.
///
/// In-circuit the branch is replaced with a witness boolean and a
/// `select` over the two possible starting hashes; the asserted
/// invariants of each branch are enforced via product-equals-zero
/// constraints so the witness can never lie about which case applies.
///
/// Navigation up the path uses `other_key`'s bits at each level — in
/// case A this is identical to `key`'s bits; in case B both keys share
/// the same prefix down to (but not including) the divergence level,
/// where path compression terminates.
///
/// `default_at_path_depth` is the value of `DEFAULT_HASHES[path.len()]`
/// passed as a witness; the caller is responsible for sourcing it from
/// the off-circuit constants.
#[allow(clippy::too_many_arguments)]
pub fn verify_smt_non_inclusion<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key: HashOutTarget,
    other_key: HashOutTarget,
    other_value: HashOutTarget,
    other_key_bits: &[BoolTarget],
    path: &[HashOutTarget],
    expected_root: HashOutTarget,
    default_at_path_depth: HashOutTarget,
) {
    assert!(
        other_key_bits.len() >= path.len(),
        "verify_smt_non_inclusion: other_key_bits must cover at least path.len() levels"
    );

    // is_case_a = (key == other_key), element-wise AND.
    let eqs: Vec<BoolTarget> = (0..4)
        .map(|i| builder.is_equal(key.elements[i], other_key.elements[i]))
        .collect();
    let eq01 = builder.and(eqs[0], eqs[1]);
    let eq23 = builder.and(eqs[2], eqs[3]);
    let is_case_a = builder.and(eq01, eq23);

    // Case-A invariant: is_case_a → other_value == default_at_path_depth.
    // Enforce by `is_case_a * (other_value[i] - default[i]) == 0` per element.
    for i in 0..4 {
        let diff = builder.sub(other_value.elements[i], default_at_path_depth.elements[i]);
        let product = builder.mul(is_case_a.target, diff);
        builder.assert_zero(product);
    }

    // Two possible starting hashes:
    //   case A: other_value (which equals the default by the invariant above)
    //   case B: leaf_hash(other_value, other_key) = Poseidon(other_value || other_key)
    let mut leaf_b_input = Vec::with_capacity(8);
    leaf_b_input.extend_from_slice(&other_value.elements);
    leaf_b_input.extend_from_slice(&other_key.elements);
    let current_b = builder.hash_n_to_hash_no_pad::<PoseidonHash>(leaf_b_input);

    let mut current_elements = [builder.zero(); 4];
    for (i, elt) in current_elements.iter_mut().enumerate() {
        *elt = builder.select(is_case_a, other_value.elements[i], current_b.elements[i]);
    }
    let mut current = HashOutTarget {
        elements: current_elements,
    };

    // Walk up `path.len()` levels using other_key's bits.
    let k = path.len();
    for (i, sibling) in path.iter().rev().enumerate() {
        let bit = other_key_bits[k - 1 - i];
        let (left, right) = swap_if(builder, bit, current, *sibling);
        let mut input = Vec::with_capacity(8);
        input.extend_from_slice(&left.elements);
        input.extend_from_slice(&right.elements);
        current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
    }

    builder.connect_hashes(current, expected_root);
}

/// Verify an SMT non-inclusion proof AND compute the new root after
/// inserting `(new_value, key)` at that key, asserting equality with
/// `expected_new_root`.
///
/// Off-circuit equivalent:
/// [`crate::merkle::sparse_merkle_tree::NonInclusionProof::verify_and_insert`].
///
/// The gadget unifies the two non-inclusion cases (mirroring the
/// off-circuit `if self.key == self.leaf.0 { … } else { … }` branch in
/// `NonInclusionProof::insert`) via the same `is_case_a` selector used
/// by [`verify_smt_non_inclusion`]:
///
/// - **Case A** (empty subtree, `key == other_key`): the new leaf takes
///   the place of the default at depth `path.len()`. New root =
///   `leaf_hash(new_value, key)` hashed up `path.len()` levels using
///   the existing siblings. The caller passes `extension` of length 0.
/// - **Case B** (path-compressed neighbour, `key != other_key`): the
///   existing leaf and the new leaf must be uncompressed down to the
///   first level `D` where their keys diverge. The caller supplies
///   `extension` of length `E = D - path.len() >= 1` (the off-circuit
///   `insert` builds this by pushing `DEFAULT_HASHES[K+1..D+1]`). New
///   root = ordered-pair of the two leaf hashes at divergence depth `D`,
///   hashed up using `extension` followed by `path`.
///
/// `default_at_path_depth` is `DEFAULT_HASHES[path.len()]`, witnessed by
/// the caller. The case-A invariant `is_case_a → other_value ==
/// DEFAULT_HASHES[path.len()]` is enforced as a product-equals-zero
/// constraint, identical to [`verify_smt_non_inclusion`].
///
/// `key_bits` and `other_key_bits` are full 256-bit MSB-first
/// decompositions (use [`key_bits_msb_first`]). `key_bits` must be
/// strictly longer than `path.len() + extension.len()` (the divergence
/// bit at level `D` is read from `key_bits[D]`); `other_key_bits` must
/// cover at least `path.len()` levels.
#[allow(clippy::too_many_arguments)]
pub fn verify_smt_insert<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    new_value: HashOutTarget,
    key: HashOutTarget,
    other_key: HashOutTarget,
    other_value: HashOutTarget,
    key_bits: &[BoolTarget],
    other_key_bits: &[BoolTarget],
    path: &[HashOutTarget],
    extension: &[HashOutTarget],
    expected_old_root: HashOutTarget,
    expected_new_root: HashOutTarget,
    default_at_path_depth: HashOutTarget,
) {
    let k = path.len();
    let e = extension.len();
    let combined_len = k + e;
    assert!(
        other_key_bits.len() >= k,
        "verify_smt_insert: other_key_bits must cover at least path.len() levels"
    );
    assert!(
        key_bits.len() > combined_len,
        "verify_smt_insert: key_bits must cover at least path.len() + extension.len() + 1 levels"
    );

    // is_case_a = (key == other_key), element-wise AND of four `is_equal`.
    let eqs: Vec<BoolTarget> = (0..4)
        .map(|i| builder.is_equal(key.elements[i], other_key.elements[i]))
        .collect();
    let eq01 = builder.and(eqs[0], eqs[1]);
    let eq23 = builder.and(eqs[2], eqs[3]);
    let is_case_a = builder.and(eq01, eq23);

    // Case-A invariant: is_case_a → other_value == default_at_path_depth.
    for i in 0..4 {
        let diff = builder.sub(other_value.elements[i], default_at_path_depth.elements[i]);
        let product = builder.mul(is_case_a.target, diff);
        builder.assert_zero(product);
    }

    // ===== Old-root verify (mirrors verify_smt_non_inclusion) =====
    let mut other_leaf_input = Vec::with_capacity(8);
    other_leaf_input.extend_from_slice(&other_value.elements);
    other_leaf_input.extend_from_slice(&other_key.elements);
    let other_leaf_h = builder.hash_n_to_hash_no_pad::<PoseidonHash>(other_leaf_input);

    let mut verify_start_elements = [builder.zero(); 4];
    for (i, elt) in verify_start_elements.iter_mut().enumerate() {
        *elt = builder.select(is_case_a, other_value.elements[i], other_leaf_h.elements[i]);
    }
    let mut verify_current = HashOutTarget {
        elements: verify_start_elements,
    };
    for (i, sibling) in path.iter().rev().enumerate() {
        let bit = other_key_bits[k - 1 - i];
        let (left, right) = swap_if(builder, bit, verify_current, *sibling);
        let mut input = Vec::with_capacity(8);
        input.extend_from_slice(&left.elements);
        input.extend_from_slice(&right.elements);
        verify_current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
    }
    builder.connect_hashes(verify_current, expected_old_root);

    // ===== New-root computation =====
    // new_leaf_h = Poseidon(new_value || key) — always computed (used by both cases).
    let mut new_leaf_input = Vec::with_capacity(8);
    new_leaf_input.extend_from_slice(&new_value.elements);
    new_leaf_input.extend_from_slice(&key.elements);
    let new_leaf_h = builder.hash_n_to_hash_no_pad::<PoseidonHash>(new_leaf_input);

    // Case A starting hash: new_leaf_h itself (sits at depth `k`).
    let start_a = new_leaf_h;

    // Case B starting hash: ordered pair of (new_leaf_h, other_leaf_h) at
    // divergence depth `combined_len`. Off-circuit:
    //   if get_bit(key, siblings.len()) { hash_concat(sibling, leaf) }
    //   else                            { hash_concat(leaf, sibling) }
    // i.e. div_bit=1 puts new leaf on the right (sibling/other on left),
    // div_bit=0 puts new leaf on the left.
    let div_bit = key_bits[combined_len];
    let (b_left, b_right) = swap_if(builder, div_bit, new_leaf_h, other_leaf_h);
    let mut pair_input = Vec::with_capacity(8);
    pair_input.extend_from_slice(&b_left.elements);
    pair_input.extend_from_slice(&b_right.elements);
    let start_b = builder.hash_n_to_hash_no_pad::<PoseidonHash>(pair_input);

    // start = select(is_case_a, start_a, start_b)
    let mut start_elements = [builder.zero(); 4];
    for (i, elt) in start_elements.iter_mut().enumerate() {
        *elt = builder.select(is_case_a, start_a.elements[i], start_b.elements[i]);
    }
    let mut new_current = HashOutTarget {
        elements: start_elements,
    };

    // Walk up: extension siblings first (deepest), then path siblings.
    // Combined slice = path ++ extension so that iter().rev() yields
    // extension[E-1..0] then path[K-1..0] — matching the off-circuit
    // `siblings.pop()` order after the divergence-padding push loop.
    let mut combined: Vec<HashOutTarget> = Vec::with_capacity(combined_len);
    combined.extend_from_slice(path);
    combined.extend_from_slice(extension);
    for (i, sibling) in combined.iter().rev().enumerate() {
        let bit = key_bits[combined_len - 1 - i];
        let (left, right) = swap_if(builder, bit, new_current, *sibling);
        let mut input = Vec::with_capacity(8);
        input.extend_from_slice(&left.elements);
        input.extend_from_slice(&right.elements);
        new_current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
    }
    builder.connect_hashes(new_current, expected_new_root);
}

#[cfg_attr(coverage_nightly, coverage(off))]
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

    /// Non-inclusion of a key that lands in an empty subtree (case A).
    /// Insert a single key; look up the OPPOSITE first-bit key —
    /// `generate_non_inclusion_proof` returns an empty-subtree witness at
    /// level 0 (path.len() == 0), with sibling_leaf = (lookup_key, root).
    /// We exercise the gadget with a slightly less degenerate input: insert
    /// two keys, look up a third in the empty branch beyond their fork.
    #[test]
    fn smt_non_inclusion_case_a_empty_subtree() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x40; // bit 1 = 1
                      // Lookup a key that goes branch=1 at bit 0 — neither k0 nor k1 is
                      // there; the subtree on that side is empty at level 0.
        let mut lookup = [0u8; 32];
        lookup[0] = 0x80; // bit 0 = 1

        let mut tree = SparseMerkleTree::new();
        tree.insert(k0, hash_bytes(b"v0")).unwrap();
        tree.insert(k1, hash_bytes(b"v1")).unwrap();
        let nip = tree.generate_non_inclusion_proof(lookup).unwrap();
        assert!(nip.verify(), "off-circuit sanity");
        assert_eq!(nip.key, nip.leaf.0, "this scenario should be case A");

        circuit_round_trip(&tree, &nip);
    }

    /// Non-inclusion when the chase loop runs (case B): lookup key lands
    /// in a subtree where exactly one other leaf is path-compressed.
    #[test]
    fn smt_non_inclusion_case_b_path_compressed_neighbour() {
        let k0 = [0u8; 32]; // first bit = 0
                            // Lookup goes the same first-bit-way as k0 (bit 0 = 0), but diverges
                            // somewhere deeper. Off-circuit, this triggers the chase which
                            // returns sibling_leaf = (k0, hash_bytes(b"v0")).
        let mut lookup = [0u8; 32];
        lookup[31] = 0x01;

        let mut tree = SparseMerkleTree::new();
        tree.insert(k0, hash_bytes(b"v0")).unwrap();
        let nip = tree.generate_non_inclusion_proof(lookup).unwrap();
        assert!(nip.verify(), "off-circuit sanity");
        assert_ne!(nip.key, nip.leaf.0, "this scenario should be case B");

        circuit_round_trip(&tree, &nip);
    }

    /// Helper: witness an off-circuit NonInclusionProof into the gadget.
    fn circuit_round_trip(
        tree: &SparseMerkleTree,
        nip: &crate::merkle::sparse_merkle_tree::NonInclusionProof,
    ) {
        use crate::merkle::sparse_merkle_tree::DEFAULT_HASHES;

        let path_len = nip.siblings.len();
        let default_at_depth = DEFAULT_HASHES[path_len];

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let key_t = builder.add_virtual_hash();
        let other_key_t = builder.add_virtual_hash();
        let other_value_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let default_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> =
            (0..path_len).map(|_| builder.add_virtual_hash()).collect();
        let other_key_bits = key_bits_msb_first(&mut builder, other_key_t);
        verify_smt_non_inclusion(
            &mut builder,
            key_t,
            other_key_t,
            other_value_t,
            &other_key_bits,
            &path_t,
            root_t,
            default_t,
        );
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(key_t, digest_from_bytes(&nip.key))
            .unwrap();
        pw.set_hash_target(other_key_t, digest_from_bytes(&nip.leaf.0))
            .unwrap();
        pw.set_hash_target(other_value_t, nip.leaf.1).unwrap();
        pw.set_hash_target(root_t, tree.root()).unwrap();
        pw.set_hash_target(default_t, default_at_depth).unwrap();
        for (i, sib) in nip.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        let proof_with_pis = data.prove(pw).expect("prove failed");
        data.verify(proof_with_pis).expect("verify failed");
    }

    /// A tampered other_value in case A must not prove (the invariant
    /// `is_case_a * (other_value - default) == 0` catches it).
    #[test]
    fn smt_non_inclusion_case_a_wrong_default_fails() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x40;
        let mut lookup = [0u8; 32];
        lookup[0] = 0x80;

        let mut tree = SparseMerkleTree::new();
        tree.insert(k0, hash_bytes(b"v0")).unwrap();
        tree.insert(k1, hash_bytes(b"v1")).unwrap();
        let nip = tree.generate_non_inclusion_proof(lookup).unwrap();
        assert_eq!(nip.key, nip.leaf.0);

        let path_len = nip.siblings.len();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let key_t = builder.add_virtual_hash();
        let other_key_t = builder.add_virtual_hash();
        let other_value_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let default_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> =
            (0..path_len).map(|_| builder.add_virtual_hash()).collect();
        let other_key_bits = key_bits_msb_first(&mut builder, other_key_t);
        verify_smt_non_inclusion(
            &mut builder,
            key_t,
            other_key_t,
            other_value_t,
            &other_key_bits,
            &path_t,
            root_t,
            default_t,
        );
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(key_t, digest_from_bytes(&nip.key))
            .unwrap();
        pw.set_hash_target(other_key_t, digest_from_bytes(&nip.leaf.0))
            .unwrap();
        // Lie: claim other_value is non-default.
        pw.set_hash_target(other_value_t, hash_bytes(b"lie"))
            .unwrap();
        pw.set_hash_target(root_t, tree.root()).unwrap();
        pw.set_hash_target(
            default_t,
            crate::merkle::sparse_merkle_tree::DEFAULT_HASHES[path_len],
        )
        .unwrap();
        for (i, sib) in nip.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        assert!(
            data.prove(pw).is_err(),
            "case-A invariant must reject non-default other_value"
        );
    }

    /// Tampered leaf value must not be provable against an honest root.
    #[test]
    #[should_panic(expected = "key_bits must cover at least path.len() levels")]
    fn smt_inclusion_short_key_bits_panics() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let leaf_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..3).map(|_| builder.add_virtual_hash()).collect();
        // Only 2 bits — fewer than the 3-step path.
        let bit0 = builder.add_virtual_bool_target_safe();
        let bit1 = builder.add_virtual_bool_target_safe();
        verify_smt_inclusion(&mut builder, leaf_t, key_t, &[bit0, bit1], &path_t, root_t);
    }

    #[test]
    #[should_panic(expected = "other_key_bits must cover at least path.len() levels")]
    fn smt_non_inclusion_short_key_bits_panics() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let key_t = builder.add_virtual_hash();
        let other_key_t = builder.add_virtual_hash();
        let other_value_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let default_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..3).map(|_| builder.add_virtual_hash()).collect();
        let bit0 = builder.add_virtual_bool_target_safe();
        let bit1 = builder.add_virtual_bool_target_safe();
        verify_smt_non_inclusion(
            &mut builder,
            key_t,
            other_key_t,
            other_value_t,
            &[bit0, bit1],
            &path_t,
            root_t,
            default_t,
        );
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

    // ===== verify_smt_insert tests =====
    //
    // Each fixture is paired with a shared `insert_round_trip` helper that
    // computes the off-circuit `verify_and_insert` result, derives the
    // case-B padding (matching the off-circuit `insert` push loop), and
    // witnesses the gadget. The positive-case tests assert the gadget's
    // computed new root matches off-circuit; the negative-case tests
    // assert that tampered inputs fail to prove.

    /// Compute the Case-B extension siblings exactly as `NonInclusionProof::insert`
    /// does (the `while get_bit(key, sim_len) == get_bit(other_key, sim_len)` loop).
    /// Returns an empty vec for Case A (`nip.key == nip.leaf.0`).
    fn case_b_extension(
        nip: &crate::merkle::sparse_merkle_tree::NonInclusionProof,
    ) -> Vec<HashDigest> {
        use crate::merkle::sparse_merkle_tree::{get_bit, DEFAULT_HASHES};
        let mut ext = Vec::new();
        if nip.key != nip.leaf.0 {
            let mut sim_len = nip.siblings.len();
            while get_bit(&nip.key, sim_len) == get_bit(&nip.leaf.0, sim_len) {
                ext.push(DEFAULT_HASHES[sim_len + 1]);
                sim_len += 1;
            }
        }
        ext
    }

    /// Build the insert gadget against an off-circuit non-inclusion proof,
    /// witness all inputs (using `expected_new_root` from off-circuit
    /// `verify_and_insert`), prove, and verify. Returns the
    /// `CircuitData` and the `PartialWitness` so negative tests can
    /// inject mutations before calling `prove`.
    fn build_insert_circuit_and_witness(
        tree: &SparseMerkleTree,
        nip: &crate::merkle::sparse_merkle_tree::NonInclusionProof,
        new_value: HashDigest,
        expected_new_root: HashDigest,
    ) -> (
        plonky2::plonk::circuit_data::CircuitData<F, C, D>,
        PartialWitness<F>,
    ) {
        use crate::merkle::sparse_merkle_tree::DEFAULT_HASHES;

        let path_len = nip.siblings.len();
        let default_at_depth = DEFAULT_HASHES[path_len];
        let extension_values = case_b_extension(nip);
        let ext_len = extension_values.len();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let new_value_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let other_key_t = builder.add_virtual_hash();
        let other_value_t = builder.add_virtual_hash();
        let old_root_t = builder.add_virtual_hash();
        let new_root_t = builder.add_virtual_hash();
        let default_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> =
            (0..path_len).map(|_| builder.add_virtual_hash()).collect();
        let extension_t: Vec<HashOutTarget> =
            (0..ext_len).map(|_| builder.add_virtual_hash()).collect();
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        let other_key_bits = key_bits_msb_first(&mut builder, other_key_t);
        verify_smt_insert(
            &mut builder,
            new_value_t,
            key_t,
            other_key_t,
            other_value_t,
            &key_bits,
            &other_key_bits,
            &path_t,
            &extension_t,
            old_root_t,
            new_root_t,
            default_t,
        );
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(new_value_t, new_value).unwrap();
        pw.set_hash_target(key_t, digest_from_bytes(&nip.key))
            .unwrap();
        pw.set_hash_target(other_key_t, digest_from_bytes(&nip.leaf.0))
            .unwrap();
        pw.set_hash_target(other_value_t, nip.leaf.1).unwrap();
        pw.set_hash_target(old_root_t, tree.root()).unwrap();
        pw.set_hash_target(new_root_t, expected_new_root).unwrap();
        pw.set_hash_target(default_t, default_at_depth).unwrap();
        for (i, sib) in nip.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }
        for (i, ext) in extension_values.iter().enumerate() {
            pw.set_hash_target(extension_t[i], *ext).unwrap();
        }

        (data, pw)
    }

    fn insert_round_trip(
        tree: &SparseMerkleTree,
        nip: &crate::merkle::sparse_merkle_tree::NonInclusionProof,
        new_value: HashDigest,
    ) {
        let expected_new_root = nip.verify_and_insert(new_value).expect("off-circuit");
        let (data, pw) = build_insert_circuit_and_witness(tree, nip, new_value, expected_new_root);
        let proof_with_pis = data.prove(pw).expect("prove failed");
        data.verify(proof_with_pis).expect("verify failed");
    }

    /// Case A — lookup lands in an empty subtree at depth 2; insert there
    /// places the new leaf at the same depth, hashing up with the existing
    /// two siblings.
    #[test]
    fn smt_insert_case_a_empty_subtree() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x40;
        let mut lookup = [0u8; 32];
        lookup[0] = 0x80;

        let mut tree = SparseMerkleTree::new();
        tree.insert(k0, hash_bytes(b"v0")).unwrap();
        tree.insert(k1, hash_bytes(b"v1")).unwrap();
        let nip = tree.generate_non_inclusion_proof(lookup).unwrap();
        assert_eq!(nip.key, nip.leaf.0, "this scenario should be case A");

        insert_round_trip(&tree, &nip, hash_bytes(b"new"));
    }

    /// Case B — 2-leaf tree where the path-compressed neighbour diverges
    /// from the lookup at the level *just below* the non-inclusion proof
    /// (E = 0). Smallest possible Case B: K = 1, E = 0, total walk = 1.
    #[test]
    fn smt_insert_case_b_shallow_divergence() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x80; // bit 0 = 1
        let mut lookup = [0u8; 32];
        lookup[0] = 0xC0; // bits 0,1 = 1,1 — same first bit as k1, diverges at bit 1

        let mut tree = SparseMerkleTree::new();
        tree.insert(k0, hash_bytes(b"v0")).unwrap();
        tree.insert(k1, hash_bytes(b"v1")).unwrap();
        let nip = tree.generate_non_inclusion_proof(lookup).unwrap();
        assert_ne!(nip.key, nip.leaf.0, "this scenario should be case B");

        insert_round_trip(&tree, &nip, hash_bytes(b"new"));
    }

    /// Case B with a non-zero extension — 1-leaf tree where the new key
    /// shares the first 31 bytes with k0 and diverges in the last byte at
    /// bit 248. K = 0, E ≈ 248. Slower than the shallow test but exercises
    /// the extension-padding walk.
    #[test]
    fn smt_insert_case_b_deep_divergence() {
        let k0 = [0u8; 32];
        let mut lookup = [0u8; 32];
        lookup[31] = 0x80; // bit 248 = 1 — diverges from k0 at bit 248

        let mut tree = SparseMerkleTree::new();
        tree.insert(k0, hash_bytes(b"v0")).unwrap();
        let nip = tree.generate_non_inclusion_proof(lookup).unwrap();
        assert_ne!(nip.key, nip.leaf.0, "this scenario should be case B");
        assert!(
            !case_b_extension(&nip).is_empty(),
            "deep divergence must produce extension siblings"
        );

        insert_round_trip(&tree, &nip, hash_bytes(b"new"));
    }

    /// Tampered new-leaf value: the gadget computes a new_root from the
    /// lying `new_value` that doesn't match the honest `expected_new_root`
    /// witnessed alongside it; `connect_hashes` fails.
    #[test]
    fn smt_insert_tampered_new_value_fails() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x40;
        let mut lookup = [0u8; 32];
        lookup[0] = 0x80;

        let mut tree = SparseMerkleTree::new();
        tree.insert(k0, hash_bytes(b"v0")).unwrap();
        tree.insert(k1, hash_bytes(b"v1")).unwrap();
        let nip = tree.generate_non_inclusion_proof(lookup).unwrap();
        let honest_new_value = hash_bytes(b"honest");
        let expected_new_root = nip.verify_and_insert(honest_new_value).unwrap();

        let (data, pw) =
            build_insert_circuit_and_witness(&tree, &nip, hash_bytes(b"lie"), expected_new_root);
        assert!(data.prove(pw).is_err(), "tampered new_value must not prove");
    }

    /// Tampered expected_new_root — same setup as the positive Case A test
    /// but witness a wrong target root. `connect_hashes` fails.
    #[test]
    fn smt_insert_tampered_expected_new_root_fails() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x40;
        let mut lookup = [0u8; 32];
        lookup[0] = 0x80;

        let mut tree = SparseMerkleTree::new();
        tree.insert(k0, hash_bytes(b"v0")).unwrap();
        tree.insert(k1, hash_bytes(b"v1")).unwrap();
        let nip = tree.generate_non_inclusion_proof(lookup).unwrap();

        let (data, pw) = build_insert_circuit_and_witness(
            &tree,
            &nip,
            hash_bytes(b"new"),
            // Honest new_root would be `nip.verify_and_insert(...)`; we
            // hand the gadget an unrelated digest instead.
            hash_bytes(b"unrelated-root"),
        );
        assert!(
            data.prove(pw).is_err(),
            "tampered expected_new_root must not prove"
        );
    }

    /// Case-A invariant: if `other_value` is not the default at the path
    /// depth, the gadget rejects (mirrors the off-circuit
    /// `if self.leaf.1 != DEFAULT_HASHES[siblings.len()] return Err`).
    #[test]
    fn smt_insert_case_a_wrong_default_fails() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x40;
        let mut lookup = [0u8; 32];
        lookup[0] = 0x80;

        let mut tree = SparseMerkleTree::new();
        tree.insert(k0, hash_bytes(b"v0")).unwrap();
        tree.insert(k1, hash_bytes(b"v1")).unwrap();
        let nip = tree.generate_non_inclusion_proof(lookup).unwrap();
        assert_eq!(nip.key, nip.leaf.0);

        // Compute the would-be expected_new_root with the honest other_value,
        // then witness a lying other_value.
        let new_value = hash_bytes(b"new");
        let expected_new_root = nip.verify_and_insert(new_value).unwrap();
        let path_len = nip.siblings.len();
        let default_at_depth = crate::merkle::sparse_merkle_tree::DEFAULT_HASHES[path_len];

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let new_value_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let other_key_t = builder.add_virtual_hash();
        let other_value_t = builder.add_virtual_hash();
        let old_root_t = builder.add_virtual_hash();
        let new_root_t = builder.add_virtual_hash();
        let default_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> =
            (0..path_len).map(|_| builder.add_virtual_hash()).collect();
        let extension_t: Vec<HashOutTarget> = Vec::new(); // Case A
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        let other_key_bits = key_bits_msb_first(&mut builder, other_key_t);
        verify_smt_insert(
            &mut builder,
            new_value_t,
            key_t,
            other_key_t,
            other_value_t,
            &key_bits,
            &other_key_bits,
            &path_t,
            &extension_t,
            old_root_t,
            new_root_t,
            default_t,
        );
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(new_value_t, new_value).unwrap();
        pw.set_hash_target(key_t, digest_from_bytes(&nip.key))
            .unwrap();
        pw.set_hash_target(other_key_t, digest_from_bytes(&nip.leaf.0))
            .unwrap();
        // Lie: claim other_value is non-default while is_case_a = true.
        pw.set_hash_target(other_value_t, hash_bytes(b"lie"))
            .unwrap();
        pw.set_hash_target(old_root_t, tree.root()).unwrap();
        pw.set_hash_target(new_root_t, expected_new_root).unwrap();
        pw.set_hash_target(default_t, default_at_depth).unwrap();
        for (i, sib) in nip.siblings.iter().enumerate() {
            pw.set_hash_target(path_t[i], *sib).unwrap();
        }

        assert!(
            data.prove(pw).is_err(),
            "case-A invariant must reject non-default other_value"
        );
    }

    /// Gadget-build assertion: key_bits must be strictly longer than
    /// path.len() + extension.len() so the divergence-bit lookup
    /// `key_bits[combined_len]` is in bounds.
    #[test]
    #[should_panic(expected = "key_bits must cover at least path.len() + extension.len() + 1")]
    fn smt_insert_short_key_bits_panics() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let new_value_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let other_key_t = builder.add_virtual_hash();
        let other_value_t = builder.add_virtual_hash();
        let old_root_t = builder.add_virtual_hash();
        let new_root_t = builder.add_virtual_hash();
        let default_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..3).map(|_| builder.add_virtual_hash()).collect();
        let extension_t: Vec<HashOutTarget> = Vec::new();
        let bit0 = builder.add_virtual_bool_target_safe();
        let bit1 = builder.add_virtual_bool_target_safe();
        let bit2 = builder.add_virtual_bool_target_safe();
        let other_key_bits = key_bits_msb_first(&mut builder, other_key_t);
        // 3 key_bits with combined_len = 3 → not strictly greater.
        verify_smt_insert(
            &mut builder,
            new_value_t,
            key_t,
            other_key_t,
            other_value_t,
            &[bit0, bit1, bit2],
            &other_key_bits,
            &path_t,
            &extension_t,
            old_root_t,
            new_root_t,
            default_t,
        );
    }

    /// Gadget-build assertion: other_key_bits must cover path.len() so the
    /// old-root walk can read `other_key_bits[k - 1 - i]`.
    #[test]
    #[should_panic(expected = "other_key_bits must cover at least path.len() levels")]
    fn smt_insert_short_other_key_bits_panics() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let new_value_t = builder.add_virtual_hash();
        let key_t = builder.add_virtual_hash();
        let other_key_t = builder.add_virtual_hash();
        let other_value_t = builder.add_virtual_hash();
        let old_root_t = builder.add_virtual_hash();
        let new_root_t = builder.add_virtual_hash();
        let default_t = builder.add_virtual_hash();
        let path_t: Vec<HashOutTarget> = (0..3).map(|_| builder.add_virtual_hash()).collect();
        let extension_t: Vec<HashOutTarget> = Vec::new();
        let key_bits = key_bits_msb_first(&mut builder, key_t);
        let bit0 = builder.add_virtual_bool_target_safe();
        let bit1 = builder.add_virtual_bool_target_safe();
        verify_smt_insert(
            &mut builder,
            new_value_t,
            key_t,
            other_key_t,
            other_value_t,
            &key_bits,
            &[bit0, bit1], // only 2 — fewer than path.len() = 3
            &path_t,
            &extension_t,
            old_root_t,
            new_root_t,
            default_t,
        );
    }
}
