//! Shared circuit helpers reused across gadgets.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Element-wise conditional swap of two `HashOutTarget`s.
///
/// `bit == 0` → returns `(a, b)` unchanged.
/// `bit == 1` → returns `(b, a)` swapped.
///
/// Used by every Merkle gadget that walks bit-indexed paths up to a root.
pub(crate) fn swap_if<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bit: BoolTarget,
    a: HashOutTarget,
    b: HashOutTarget,
) -> (HashOutTarget, HashOutTarget) {
    let mut left = [builder.zero(); 4];
    let mut right = [builder.zero(); 4];
    for i in 0..4 {
        left[i] = builder.select(bit, b.elements[i], a.elements[i]);
        right[i] = builder.select(bit, a.elements[i], b.elements[i]);
    }
    (
        HashOutTarget { elements: left },
        HashOutTarget { elements: right },
    )
}
