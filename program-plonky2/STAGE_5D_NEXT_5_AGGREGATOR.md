# Stage 5d-next-5 — source-side verification via aggregator pattern

Tracking document for the per-in-coin recursive verification work
(SPEC §8 step 2). Refers back to the deferred Stage 5d-next-4 context
in `MIGRATION_RESEARCH.md` §7.21 and the original design notes in
`STAGE_5D_NEXT_4_DESIGN.md` (Option B / aggregator pattern).

This document is intended to be **self-contained** so a fresh session
can pick up Phase 2b without re-deriving anything from chat history.

## Status snapshot

| Phase | Scope | Result |
|------:|-------|--------|
| 1 | Aggregator skeleton + smoke + active-slot test | **Done.** Merged via #22 onto `feat/plonky2-migration`. |
| Phase-1 coverage gap | `should_panic` test for `prove_aggregator`'s invalid-witness arm | **Done in this PR** (fast — no circuit build needed). |
| 2a probe | Empirical investigation of the Plonky2 1.1.0 `dummy_circuit` shape mismatch + cyclic fixed-point divergence | **Done in this PR.** `src/circuit/recursion_shape_probe.rs`. |
| 2a | Outer-circuit integration (`verify_proof(agg)` + `connect_hashes` + ConstantGate-injection shape lock) | **DONE in this PR** (commit `b5be37a`). |
| 2b | Per-slot source-side SMT inclusion + CMP (c)(d)(e) chain + coupling check | **Not started.** Plan in [§Phase 2b plan](#phase-2b-plan-self-contained-for-the-next-session). |
| 3 | 4 cyclic positives + 3 new SPEC §13 negatives + 100 % line coverage | **Not started.** Plan in [§Phase 3 plan](#phase-3-plan). |

### What's in this PR

- `src/circuit/recursion_shape_probe.rs` — `#[cfg(test)]`
  diagnostic module that empirically derived both fixes:
  - `pass_3_two_verify(_, force_constant_gate = true)`: showed that
    explicit `builder.add_gate(ConstantGate::new(2), …)` in pass-3
    makes pass-3's gates list match `dummy_circuit`'s rebuild.
  - `build_minimal_outer_for_diagnostic(_, _)` + `try_build_with_options`:
    isolated the second divergence to `fri_params.degree_bits`.
  - `dump_phase_2a_pad_bits_sweep` (`#[ignore]`d): showed the
    empirical relation `helper_degree = pad_bits + 1`, pinning
    `INNER_PAD_BITS_STAGE_5D_NEXT_5 = 14`.
- `src/circuit/source_aggregator.rs` — factored
  `assert_slot_witnesses_valid` out of `prove_aggregator`, replaced
  the in-loop `panic!` with `unreachable!`, added two fast
  `#[should_panic]` tests for the witness-contract violations.
- `src/circuit/main.rs` — Phase 2a integration:
  - `INNER_PAD_BITS_STAGE_5D_NEXT_3 = 14` (renamed; previously inline
    `const INNER_PAD_BITS`)
  - `INNER_PAD_BITS_STAGE_5D_NEXT_5 = 14` (deliberately same — the
    cyclic fixed-point check requires
    `outer_degree == helper_degree`, see [§Why pad bits 14](#why-pad-bits-14))
  - `state_transition_num_pis()` (helper): `N_PROOF_DATA_PUBLIC_INPUTS
    + 4 + 4 × cap_elements = 84` for the standard recursion config
  - `common_data_for_recursion_c_inner(aggregator, inner_pad_bits)`:
    generalised helper supporting the Stage 5d-next-5 2-verify shape
  - `StateTransitionCircuit` gains `aggregator: SourceAggregatorCircuit`
    and `aggregator_proof_target: ProofWithPublicInputsTarget<D>`
  - `build_circuit()` runs a 2-iteration fixed-point on the
    aggregator + outer common, asserts convergence, then builds the
    outer with `verify_proof(aggregator_proof, …)` +
    `connect_hashes` + explicit `ConstantGate::new(2)` injection +
    the unchanged `_or_dummy` cyclic verify
  - `set_aggregator_proof_witness(_, _, source_proofs)`: factored
    witness setter, called by both leaf prove functions. Phase 2a
    callers pass `&[]` for all-inactive aggregator proofs; Phase 2b
    will populate.

### What's NOT in this PR — and where to pick up

- **Phase 2b**: per-slot SMT inclusion of `coin.identifier` in
  `source.output_coins_root`, SPEC §8 (c)(d)(e) chain for the
  source's commitment in `history_root`, coupling check. See
  [§Phase 2b plan](#phase-2b-plan-self-contained-for-the-next-session).
- **Phase 3**: 4 cyclic positives + 3 SPEC §13 negatives + 100 %
  line coverage. See [§Phase 3 plan](#phase-3-plan).
- **No `cargo llvm-cov --fail-under-lines 100`** on this branch.

## The two empirical insights that make Phase 2a work

### Insight 1: `ConstantGate::new(2)` injection (probe-verified)

When `common_data_for_recursion_c_inner` is called with two
`verify_proof` calls (one cyclic, one against the aggregator), pass-3's
`ArithmeticGate` instances absorb every routed constant — no standalone
`ConstantGate` ever gets allocated by `builder.build::<C>()`. But
`dummy_circuit`'s rebuild ALWAYS emits one (its hard-coded `- 2`
NoopGate reservation reserves a row for `PublicInputGate +
ConstantGate`). The `assert_eq!(&circuit.common, common_data)` at
`plonky2-1.1.0/src/recursion/dummy_circuit.rs:116` then panics.

Probe data (`recursion_shape_probe::dump_pass_3_gates_lists_for_inspection`):

| Helper variant | `gates.len()` | `ConstantGate`? | `dummy_circuit` |
|---|---:|---|---|
| Stage 5d-next-3 baseline (1 verify, pad 14) | 13 | ✓ | **OK** |
| 2 verify, pad 14, no injection | 12 | ✗ | **PANIC** |
| 2 verify + 1/4/16/64/256 forced constants via `mul(c, zero)` | 12 | ✗ | **PANIC** |
| **2 verify + explicit `ConstantGate::new(2)` injection, pad 14** | **13** | **✓** | **OK** |

The fix lives in `common_data_for_recursion_c_inner`'s pass 3:

```rust
if let Some(agg) = aggregator {
    let agg_proof = builder.add_virtual_proof_with_pis(&agg.common);
    let agg_vd = builder.constant_verifier_data(&agg.verifier_only);
    builder.verify_proof::<C>(&agg_proof, &agg_vd, &agg.common);
    // Inject one `ConstantGate{num_consts:2}` so pass-3's gates list
    // matches `dummy_circuit`'s rebuild. Zero constants — only the
    // gate-instance existence matters for the gate-set equality check.
    builder.add_gate(ConstantGate::new(2), vec![F::ZERO, F::ZERO]);
}
```

The OUTER must do the same right before its `_or_dummy` call:

```rust
// Shape lock — must match the helper's pass-3 injection.
builder.add_gate(ConstantGate::new(2), vec![F::ZERO, F::ZERO]);

builder
    .conditionally_verify_cyclic_proof_or_dummy::<C>(condition, &inner_proof_target, &common_data)
    .expect("…");
```

### Insight 2: `INNER_PAD_BITS_STAGE_5D_NEXT_5 = 14` (sweep-verified)

Once `dummy_circuit` accepts the gate-set, the cyclic fixed-point
check at `plonk/circuit_builder.rs:1067` (`goal_data != common`) is
still strict: it requires `outer.common == helper-pass-3 common`
field-by-field. The `build_minimal_outer_for_diagnostic` + field-diff
exercise isolated the only diverging axis to `fri_params.degree_bits`.

The pad-bits sweep then exposed the empirical relation:

| `pad_bits` | `helper_degree` | minimal-outer-degree | success |
|---:|---:|---:|---|
| 14 | 15 | 14 | false |
| 15 | 16 | 14 | false |
| 16 | 17 | 14 | false |
| 17 | 18 | 14 | false |

So `helper_degree = pad_bits + 1`. The minimal outer (without Stage
5d-next-3 constraint gates) sits at degree 14. The FULL outer adds
the Stage 5d-next-3 base ~10 k gates + `_or_dummy`'s
`conditionally_verify_proof` ~10 k → ~30 k gates → degree 15. So
`pad_bits = 14` makes helper-degree (15) match full-outer-degree
(15), passing the cyclic fixed-point check.

### Why pad bits 14 (not 15+) for Stage 5d-next-5

Phase 2b will add per-slot SMT + CMP gates that grow the outer's
gate count. If outer crosses 2^15 = 32768 gates, its degree bumps
to 16 and `pad_bits = 14` no longer matches. Estimated Phase-2b
contribution: ~20 k gates (8 slots × ~2.5 k each). Outer at ~50 k
total → degree 16. Then `pad_bits = 15` would be needed.

**Action item for Phase 2b**: once the per-slot gates are wired,
re-run `dump_phase_2a_pad_bits_sweep` to confirm whether the FULL
outer's degree is still 15 (keep `pad_bits = 14`) or rolled to 16
(bump to `pad_bits = 15`). If the latter, the helper's pad-bits
constant needs updating.

## Phase 2b plan (self-contained for the next session)

### Goal

Wire SPEC §8 step 2's per-in-coin source-side checks into the outer
state-transition circuit, using the aggregator's PIs as the trusted
source for `source.output_coins_root`, `source.commitment_history_root`,
and `source.account_state_hash`.

### Per-slot source-side constraints (all masked by `slot.active`)

For slot `i` in `0..MAX_IN_COINS`:

1. **Extract source `ProofData` from aggregator PIs** at offset
   `i * PER_SLOT_PIS`:
   - `source.account_state_hash` = PIs `[i*17 + 0..i*17 + 4]`
   - `source.output_coins_root`   = PIs `[i*17 + 4..i*17 + 8]`
   - `source.commitment_history_root` = PIs `[i*17 + 8..i*17 + 12]`
   - `source.coin_history_root`   = PIs `[i*17 + 12..i*17 + 16]` (unused for §8 step 2)
2. **Extract `claimed_active`** from PI `[i*17 + 16]` and assert
   `claimed_active == slot.active.target` (no mask — both sides are
   bits, agg's verify_proof already constrained it).
3. **SMT inclusion** of `coin.identifier` in `source.output_coins_root`:
   - leaf value = `h(coin.identifier || coin.identifier)` (matches the
     set-membership SMT convention used by Stage 5d-next-3 in the
     coin-history loop)
   - SMT key bits via `key_bits_msb_first(coin.identifier)`
   - `smt_inclusion_root(leaf, key, key_bits, source_smt_path)` →
     computed_root
   - `connect_hashes(computed_root, select_hash(slot.active,
     source.output_coins_root, computed_root))` — masked
4. **SPEC §8 (c)**: `source.account_state_hash == source_cmp.commitment_account_state_hash`:
   - element-wise `builder.sub` → `mul(slot.active, diff)` →
     `assert_zero` for each of the 4 elements (same pattern as
     existing prev-account CMP (c) check)
5. **SPEC §8 (d) first half**: SMT inclusion of `commitment =
   h(asth || ocr)` in `source_cmp.commitment_root` (analogous to
   existing prev-account (d), but with the source's CMP).
6. **SPEC §8 (d) second half**: MMR inclusion of
   `h(commitment_root || commitment_root_mmr_sibling)` in
   `history_root`.
7. **SPEC §8 (e)**: MMR inclusion of `h(prev_smt_in_mmr_leaf ||
   source.commitment_history_root)` in `history_root`.
8. **Coupling**: `source.output_coins_root ==
   source_cmp.commitment_out_coins_root` element-wise masked check.

### New witness targets per slot

Extend `InCoinSlotTargets` in `src/circuit/main.rs`:

```rust
pub struct InCoinSlotTargets {
    // ... existing fields (active, coin_identifier, coin_recipient,
    //     coin_amount_lo, coin_amount_hi, nip_path) ...

    /// 256 SMT siblings proving inclusion of `coin.identifier` in
    /// `source.output_coins_root`. Masked by `active`.
    pub source_inclusion_path: Vec<HashOutTarget>,
    /// CMP bundle for the source's commitment chain in
    /// `history_root`. Same shape as the existing `cmp:
    /// CommitmentMerkleProofsTargets` field on the outer.
    pub source_cmp: CommitmentMerkleProofsTargets,
}
```

In `build_circuit`'s in-coin slot construction loop, add these
target allocations.

### New prove signatures

The existing `prove_*_with_in_and_out_coins` functions are the leaf
functions. Add a NEW variant for Phase 2b that takes source
witnesses, e.g.:

```rust
pub fn prove_account_update_with_in_and_out_coins_and_sources(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    prev: &ProofWithPublicInputs<F, C, D>,
    cmp: &CommitmentMerkleProofs,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
    out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
    next_public_key: &PublicKey,
    // Per active in-coin slot:
    //   (slot_index, source_proof, source_inclusion_proof, source_cmp)
    source_witnesses: &[(usize, &ProofWithPublicInputs<F, C, D>,
                          &InclusionProof, &CommitmentMerkleProofs)],
) -> Result<ProofWithPublicInputs<F, C, D>> { … }
```

The existing `prove_*_with_in_and_out_coins` should delegate with
`&[]` for `source_witnesses`. Phase 2a's `set_aggregator_proof_witness`
already takes `source_proofs` — Phase 2b just wires those through
from the new prove function.

For inactive slots (`active = false`), witness with dummy values
(`ZERO_HASH` for everything, dummy SMT path). The masked checks pass
vacuously.

### Witness setters to add

- `set_source_inclusion_witness(&mut pw, &slot.source_inclusion_path,
  &InclusionProof)`: writes the 256 siblings. Mirrors
  `set_in_coin_slot_witness`'s NIP-path handling.
- `set_source_cmp_witness(&mut pw, &slot.source_cmp,
  &CommitmentMerkleProofs)`: mirrors the existing `set_cmp_witness`
  for prev-account.

### Gate-count budget for Phase 2b

Per slot:
- SMT inclusion (256 hashes): ~1 k gates
- CMP chain (SMT 256 + MMR 31 × 2): ~1.5 k gates
- Coupling + (c) check: ~10 gates
- → ~2.5 k gates per slot × 8 slots = **~20 k gates added to outer**.

Outer total: ~30 k (Phase 2a) + ~20 k (Phase 2b) = ~50 k → degree 16.

Then `INNER_PAD_BITS_STAGE_5D_NEXT_5` must bump from 14 to 15
(`helper_degree = pad_bits + 1 = 16` matching full outer's 16).

### Order of operations for Phase 2b in `build_circuit`

The per-slot source-side checks should be added AFTER the existing
in-coin slot loop (which already wires coin-history-side check +
apply_coin) and BEFORE the aggregator-verify call. The aggregator
proof target's PIs need to be accessible inside the loop — easiest
to hoist `aggregator_proof_target` construction and the `verify_proof(agg)`
call BEFORE the in-coin loop, then add per-slot source checks
inside the loop, and put `connect_hashes` + `ConstantGate` injection
+ `_or_dummy` after as before.

## Phase 3 plan

### 4 cyclic positives

1. Init with all-inactive in-coins (regression for Stage 5d-next-3
   path).
2. Init with 1 active in-coin + real source proof (smoke test for
   Phase 2b active path).
3. Update with all-inactive in-coins (Stage 5d-next-3 regression).
4. Update with 1 active in-coin + real source proof (full Phase 2b
   smoke + chain validation).

### 3 SPEC §13 negatives

1. **Source proof not in history**: tamper `source_cmp.mmr_b_path`
   (the (e) MMR path) → MMR-(e) verification fails.
2. **Coin identifier not in source's `output_coins_root`**: tamper
   `source_inclusion_path` → SMT inclusion fails.
3. **Wrong vk on aggregator**: build aggregator against an unrelated
   state-transition circuit's verifier_only, feed its proof to outer
   → `connect_hashes(claimed_st_digest, outer_vd.digest)` rejects.

### Coverage

Re-run `cargo llvm-cov --fail-under-lines 100 -- --test-threads=1`.
Expect 3-5 hours wall on M3 Ultra. The Phase-1 coverage gap test
(panic-path on `assert_slot_witnesses_valid`) is already at 0.00 s
wall, so it doesn't bottleneck the run.

## Architecture (target end state — per issue #19)

Both boxes are now implemented as of this PR's Phase 2a (`b5be37a`).
Phase 2b adds the per-slot source-side gates within the outer
state-transition circuit (bottom box, "Per in-coin slot" section).

```
┌─────────────────────────────────────────────────────────────┐
│ SourceAggregatorCircuit (NON-CYCLIC)         [PHASE 1, MERGED]│
│                                                             │
│   For each slot i in 0..MAX_IN_COINS:                       │
│     active[i]: BoolTarget                                   │
│     real_proof[i]: ProofWithPublicInputsTarget              │
│     dummy_proof[i]: ProofWithPublicInputsTarget             │
│     conditionally_verify_proof::<C>(                        │
│       active[i],                                            │
│       real_proof[i], st_verifier_data,        ← shared      │
│       dummy_proof[i], dummy_vd_target,        ← constant    │
│       st_common,                                            │
│     )                                                       │
│                                                             │
│   PIs:                                                      │
│     [i*17 .. i*17 + 16]: source ProofData                   │
│     [i*17 + 16]: active bit                                 │
│     [MAX_IN_COINS*17 .. + 4]: st verifier_data digest       │
│     [MAX_IN_COINS*17 + 4 ..]: st verifier_data sigmas_cap   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ aggregator_proof
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Outer StateTransitionCircuit (CYCLIC)        [PHASE 2a, DONE] │
│                                                             │
│   conditionally_verify_cyclic_proof_or_dummy(               │
│     condition, prev_account_proof, common_data,             │
│   )                                                         │
│                                                             │
│   verify_proof::<C>(                                        │
│     aggregator_proof,                                       │
│     aggregator_verifier_data,   ← constant_verifier_data    │
│     aggregator_common,                                      │
│   )                                                         │
│                                                             │
│   connect_hashes(claimed_st_digest, outer_vd.digest)        │
│   connect_hashes(claimed_st_cap, outer_vd.cap)              │
│                                                             │
│   builder.add_gate(ConstantGate::new(2), [0, 0])  ← shape lock│
│                                                             │
│   Per in-coin slot                            [PHASE 2b]:   │
│     SMT inclusion of coin_identifier in                     │
│       source.output_coins_root                              │
│     SPEC §8 (c)(d)(e) chain for source.commitment in        │
│       history_root                                          │
│     source.output_coins_root ==                             │
│       source_cmp.commitment_out_coins_root                  │
└─────────────────────────────────────────────────────────────┘
```

## Open files / locations

- `src/circuit/source_aggregator.rs` — aggregator circuit + 4 tests
  (smoke, active-slot, 2 panic-path).
- `src/circuit/main.rs` — Stage 5d-next-5 outer (Phase 2a integrated).
- `src/circuit/recursion_shape_probe.rs` — diagnostic probe
  (`#[cfg(test)]` only; not in production circuit graph).
- `src/circuit/mod.rs` — module declarations.
- `MIGRATION_RESEARCH.md` §7.21 — original Plonky2 1.1.0 deferral
  context (now superseded by this document's empirical findings).
- `STAGE_5D_NEXT_4_DESIGN.md` — original Option B architectural
  notes; the current implementation matches the "Aggregator built
  against fixed shape, vk binding via connect_hashes" design but
  with the additional ConstantGate + pad-bits constraints derived
  empirically.

## Benchmark

`cargo test --release --lib …` on an Apple M3 (24 GB), single-threaded:

- `stage_5c_plus_initial_non_mint_zero_balance_accepted` (Phase 2a
  smoke regression): ~45 s wall.
- `stage_5c_plus_initial_then_account_update_with_commitment_proofs`
  (init → update chain): ~40 s wall.
- 4 aggregator tests combined (smoke + active-slot + 2 panic-path):
  ~116 s wall.
- `dump_phase_2a_pad_bits_sweep` (`#[ignore]`d diagnostic, 4 rebuilds
  of aggregator + outer): ~6 min wall.

Phase 2b will roughly DOUBLE per-test wall time because each prove
adds 8 source-proof verifications inside the aggregator + 8 SMT/CMP
witnesses on the outer side.

## How to verify Phase 2a from scratch (smoke procedure for the next session)

```bash
# 1. Confirm the diagnostic + sweep still reproduce.
cd program-plonky2
cargo test --release --lib circuit::recursion_shape_probe::dump_pass_3_gates_lists_for_inspection -- --nocapture
# Expect: baseline_ok=true, 2v_14=false, 2v_14_with_constant_gate=true

cargo test --release --lib circuit::recursion_shape_probe::dump_phase_2a_pad_bits_sweep -- --ignored --nocapture
# Expect: pad_bits=N → helper_degree=N+1 for all N in {14, 15, 16, 17}

# 2. Confirm Phase 2a smokes (both Stage 5d-next-3 positives green).
cargo test --release --lib stage_5c_plus_initial_non_mint_zero_balance_accepted -- --nocapture
cargo test --release --lib stage_5c_plus_initial_then_account_update_with_commitment_proofs -- --nocapture

# 3. Confirm aggregator tests still green.
cargo test --release --lib circuit::source_aggregator::tests:: -- --test-threads=1
```

If any of the above fails, the Phase 2a integration regressed —
check the commit log for `b5be37a` and the diff against the parent
to see what changed.
