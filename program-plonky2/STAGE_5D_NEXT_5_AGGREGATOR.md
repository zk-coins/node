# Stage 5d-next-5 — source-side verification via aggregator pattern

Tracking document for the per-in-coin recursive verification work
(SPEC §8 step 2). Refers back to the deferred Stage 5d-next-4 context
in `MIGRATION_RESEARCH.md` §7.21 and the original design notes in
`STAGE_5D_NEXT_4_DESIGN.md` (Option B / aggregator pattern).

This document captures the **complete end state** of Stage 5d-next-5
across Phase 1, Phase 2a, Phase 2b, and Phase 3 — useful both as a
post-merge reference and as a self-contained pickup for follow-on
work that extends the architecture (e.g. multi-source slots,
production MMR fixtures, etc.).

## Status snapshot

| Phase | Scope | Result |
|------:|-------|--------|
| 1 | Aggregator skeleton + smoke + active-slot test | **Done.** Merged via #22 onto `feat/plonky2-migration`. |
| Phase-1 coverage gap | `should_panic` test for `prove_aggregator`'s invalid-witness arm | **Done in PR #23** (fast — no circuit build needed). |
| 2a probe | Empirical investigation of the Plonky2 1.1.0 `dummy_circuit` shape mismatch + cyclic fixed-point divergence | **Done in PR #23.** `src/circuit/recursion_shape_probe.rs`. |
| 2a | Outer-circuit integration (`verify_proof(agg)` + `connect_hashes` + ConstantGate-injection shape lock) | **Done in PR #23** (commit `b5be37a`). |
| 2b | Per-slot source-side SMT inclusion + CMP (c)(d)(e) chain + coupling check + active-bit binding | **Done in PR #23** (this revision). |
| 3 | Positive coverage (4 cases) + 3 SPEC §13 negatives | **Done in PR #23** (this revision). |

### Final architecture (everything implemented as of this PR)

```
┌─────────────────────────────────────────────────────────────┐
│ SourceAggregatorCircuit (NON-CYCLIC)              [PHASE 1] │
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
│ Outer StateTransitionCircuit (CYCLIC)         [PHASE 2a+2b] │
│                                                             │
│   verify_proof::<C>(  ← hoisted above in-coin loop          │
│     aggregator_proof,                                       │
│     aggregator_verifier_data,   ← constant_verifier_data    │
│     aggregator_common,                                      │
│   )                                                         │
│                                                             │
│   connect_hashes(claimed_st_digest, outer_vd.digest)        │
│   connect_hashes(claimed_st_cap, outer_vd.cap)              │
│                                                             │
│   Per in-coin slot i (Phase 2b):                            │
│     connect(slot.active, aggregator.slot[i].active_pi)      │
│     SMT inclusion of coin_identifier in                     │
│       source.output_coins_root         (masked by .active)  │
│     Coupling: source.output_coins_root ==                   │
│       source_cmp.commitment_out_coins_root                  │
│     SPEC §8 (c)(d)(e) chain for source.commitment in        │
│       outer's history_root                                  │
│                                                             │
│   conditionally_verify_cyclic_proof_or_dummy(               │
│     condition, prev_account_proof, common_data,             │
│   )                                                         │
│                                                             │
│   builder.add_gate(ConstantGate::new(2), [0, 0])  ← shape   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Two empirical insights pinned by `recursion_shape_probe`

### Insight 1: `ConstantGate::new(2)` injection (probe-verified)

`common_data_for_recursion_c_inner` calls two `verify_proof`s in pass 2
and 3 (one cyclic, one against the aggregator). Pass-3's `ArithmeticGate`
instances absorb every routed constant — no standalone `ConstantGate`
ever gets allocated by `builder.build::<C>()`. But `dummy_circuit`'s
rebuild ALWAYS emits one (its hard-coded `- 2` NoopGate reservation
reserves a row for `PublicInputGate + ConstantGate`). The
`assert_eq!(&circuit.common, common_data)` at
`plonky2-1.1.0/src/recursion/dummy_circuit.rs:116` then panics.

Probe data (`recursion_shape_probe::dump_pass_3_gates_lists_for_inspection`):

| Helper variant | `gates.len()` | `ConstantGate`? | `dummy_circuit` |
|---|---:|---|---|
| Stage 5d-next-3 baseline (1 verify, pad 14) | 13 | ✓ | **OK** |
| 2 verify, pad 14, no injection | 12 | ✗ | **PANIC** |
| 2 verify + 1/4/16/64/256 forced constants via `mul(c, zero)` | 12 | ✗ | **PANIC** |
| **2 verify + explicit `ConstantGate::new(2)` injection, pad 14** | **13** | **✓** | **OK** |

Fix lives in `common_data_for_recursion_c_inner`'s pass 3 — see the
function for the in-source comment.

### Insight 2: `INNER_PAD_BITS_STAGE_5D_NEXT_5` (sweep-verified)

Once `dummy_circuit` accepts the gate-set, the cyclic fixed-point
check at `plonk/circuit_builder.rs:1067` (`goal_data != common`) is
still strict: it requires `outer.common == helper-pass-3 common`
field-by-field. The `build_minimal_outer_for_diagnostic` + field-diff
exercise isolated the only diverging axis to `fri_params.degree_bits`,
exposing the empirical relation:

`helper_degree = pad_bits + 1`

So the helper's pad-bits must match `outer_degree - 1` to converge.

| Stage | outer gate count (approx) | outer_degree | required `pad_bits` |
|---|---:|---:|---:|
| 5d-next-3 (1 verify, no source-side) | ~10 k | 14 | 13 |
| 5d-next-5 Phase 2a (2 verify, no source-side gates) | ~30 k | 15 | **14** |
| 5d-next-5 Phase 2b (2 verify + 8 source slots × {SMT + CMP}) | ~50 k | 16 | **15** |
| Hypothetical future stage crossing 2^16 | > 65 k | 17 | 16 |

`INNER_PAD_BITS_STAGE_5D_NEXT_5 = 15` is what makes
`helper_degree = 16` match the full outer's `degree_bits = 16`.

### Re-running the sweep

If any future change crosses a power-of-two gate-count threshold,
rerun `dump_phase_2a_pad_bits_sweep` and bump `pad_bits`:

```bash
cd program-plonky2
cargo test --release --lib circuit::recursion_shape_probe::dump_phase_2a_pad_bits_sweep \
  -- --ignored --nocapture
```

Note: the sweep uses a MINIMAL outer (no real Stage 5d-next-3 / 5d-next-5
constraints). It establishes the `helper_degree = pad_bits + 1`
relation. The full outer's degree must then be measured directly via
`circuit.data.common.fri_params.degree_bits` and compared.

## Phase 2b implementation details

### Per-slot source-side constraints (in `build_circuit`, inside the
in-coin loop, after the existing 5d-next-3 coin-history + apply_coin
checks)

For slot `i ∈ 0..MAX_IN_COINS`:

1. **Extract source `ProofData` from aggregator PIs** at offset
   `i * PER_SLOT_PIS`:
   - `source.account_state_hash`        = PIs `[i*17 + 0..i*17 + 4]`
   - `source.output_coins_root`         = PIs `[i*17 + 4..i*17 + 8]`
   - `source.commitment_history_root`   = PIs `[i*17 + 8..i*17 + 12]`
   - (`source.coin_history_root` at PIs `[i*17 + 12..i*17 + 16]` —
     unused for SPEC §8 step 2)
2. **Active-bit binding**: `slot.active.target == aggregator.slot[i].active_pi`.
   Strict `builder.connect` — both sides are bools, so this enforces
   the in-coin loop and the aggregator stay in lockstep. There is no
   way to consume an in-coin without a verified source proof.
3. **SMT inclusion** of `coin.identifier` in `source.output_coins_root`:
   leaf value = `h(coin.identifier || coin.identifier)` (set-membership
   convention, matching the source's own out-coin SMT insertion at
   `hash_up_full_path(new_leaf = h(id || id), id_bits, nip_path)`),
   using `hash_up_full_path` directly (NOT `smt_inclusion_root`, which
   would add an extra `smt_leaf_hash` step and break the binding).
4. **Coupling**: `source.output_coins_root == source_cmp.commitment_out_coins_root`,
   masked element-wise (`mul(active, diff) → assert_zero`).
5. **SPEC §8 (c)**: `source.account_state_hash == source_cmp.commitment_account_state_hash`,
   masked element-wise.
6. **SPEC §8 (d), first half**: SMT inclusion of `commitment =
   h(commitment_account_state_hash || commitment_out_coins_root)`
   at `source_cmp.smt_key` in `source_cmp.commitment_root`, masked.
7. **SPEC §8 (d), second half**: MMR inclusion of
   `h(source_cmp.commitment_root || source_cmp.commitment_root_mmr_sibling)`
   at `source_cmp.mmr_a_index` in the outer's `history_root`, masked.
8. **SPEC §8 (e)**: MMR inclusion of
   `h(source_cmp.prev_smt_in_mmr_leaf || source.commitment_history_root)`
   at `source_cmp.mmr_b_index` in the outer's `history_root`, masked.

### New public API

```rust
pub struct InCoinSourceWitness<'a> {
    pub source_proof: &'a ProofWithPublicInputs<F, C, D>,
    pub source_inclusion: &'a InclusionProof,
    pub source_cmp: &'a CommitmentMerkleProofs,
}

pub fn prove_initial_with_in_and_out_coins_and_sources(
    circuit, account_state, history_root,
    in_coins, out_coins, next_public_key,
    sources: &[Option<InCoinSourceWitness>],  // MAX_IN_COINS entries
) -> Result<ProofWithPublicInputs<F, C, D>>;

pub fn prove_account_update_with_in_and_out_coins_and_sources(
    circuit, account_state, history_root, prev, cmp,
    in_coins, out_coins, next_public_key,
    sources: &[Option<InCoinSourceWitness>],
) -> Result<ProofWithPublicInputs<F, C, D>>;
```

The existing all-inactive `prove_*_with_in_and_out_coins` entry points
delegate with `&[None; MAX_IN_COINS]`. Callers with active in-coin
slots **must** use the `_and_sources` variants — otherwise the
`connect(slot.active, aggregator.slot.active_pi)` constraint fires.

### Witness setters added

- `set_source_inclusion_witness(pw, slot, &InclusionProof)`: writes
  the 256 SMT siblings proving `coin.identifier ∈ source.output_coins_root`.
- `set_cmp_targets_witness(pw, &CommitmentMerkleProofsTargets, &CommitmentMerkleProofs)`:
  refactored out of the existing `set_cmp_witness` so it can be reused
  for the per-slot `source_cmp` bundle.
- `set_per_slot_source_witnesses`: walks `sources` and writes the
  per-slot inclusion + cmp (dummies for `None` entries).
- `set_aggregator_proof_witness_from_sources`: builds the aggregator
  proof from `sources` (every `Some(_)` → active aggregator slot).

### `dummy_inclusion_proof()`

A new helper symmetrical to `dummy_cmp` / `dummy_non_inclusion_proof` —
deterministic 256-sibling `ZERO_HASH` placeholder for inactive slots'
`source_inclusion_path`.

### Multi-leaf MMR test fixture insight

Both `build_test_source_witness` (1-leaf MMR, Phase 2b Initial smoke)
and `build_test_source_and_prev_witnesses` (2-leaf MMR, Phase 2b
AccountUpdate smoke) ship with this PR. The 2-leaf MMR fixture is
nontrivial: with BOTH the consumer-prev proof AND the source proof
having `commitment_history_root = ZERO_HASH` (bootstrap), only ONE of
them can use the bootstrap-shaped (e) leaf `h(? || ZERO_HASH)` at its
own MMR index. The fixture resolves this by folding consumer-prev
FIRST (so consumer's leaf is the unique `h(? || ZERO_HASH)`-shaped
leaf at index 0) and source SECOND at index 1, then having source's
(e) "borrow" consumer's bootstrap leaf at index 0 via
`source_cmp.prev_smt_in_mmr_leaf = consumer_smt_root` and
`source_cmp.previous_root_history_proof.1 = consumer_mmr_proof`.
This is a TEST-FIXTURE peculiarity; production producers proving
against a non-empty history don't hit it because they have richer
non-bootstrap MMR shapes available.

## Phase 3 — test coverage

### Positives (4 cases, all covered)

| Case | Test |
|---|---|
| Init, all-inactive in-coins | `stage_5c_plus_initial_non_mint_zero_balance_accepted` |
| Init, 1 active in-coin + real source proof | `stage_5d_next_5_phase_2b_initial_with_one_active_in_coin_and_source` |
| Update, all-inactive in-coins | `stage_5c_plus_initial_then_account_update_with_commitment_proofs` |
| Update, 1 active in-coin + real source proof | `stage_5d_next_5_phase_2b_account_update_combined_in_and_out_coin_with_source` |

A fifth integration test —
`stage_5d_next_5_phase_2b_initial_combined_in_and_out_coin_with_source` —
exercises Init + active in-coin + active out-coin + source in a
single transition, validating the full §8 flow composes.

### SPEC §13 negatives (3 cases, all covered)

| Attack | Constraint that catches it | Test |
|---|---|---|
| Source's commitment not in `history_root` (tamper MMR-(e) path) | masked `connect_hashes(mmr_b_computed, history_root)` | `stage_5d_next_5_phase_3_source_not_in_history_rejected` |
| Coin identifier not in source's `output_coins_root` (tamper SMT path) | masked `connect_hashes(source_inclusion_computed, source_output_coins_root)` | `stage_5d_next_5_phase_3_coin_not_in_source_ocr_rejected` |
| Wrong `st_verifier_data` witnessed in aggregator | `connect_hashes(claimed_st_digest, outer_vd.circuit_digest)` | `stage_5d_next_5_phase_3_wrong_st_vk_on_aggregator_rejected` |

The wrong-vk negative is non-trivial to construct because the
aggregator's `conditionally_verify_proof` would normally reject a
wrong-vk source proof at aggregator prove-time. The test exploits the
all-inactive case: with no slot active, the aggregator never actually
uses the witnessed `st_verifier_data` for verification (only the
constant-baked `dummy_vd_target` for the dummy branch), so the
aggregator can be proved with a LYING `st_verifier_data`. The lie
then surfaces at the outer's `connect_hashes`.

## Open files / locations

- `src/circuit/source_aggregator.rs` — aggregator circuit + 4 tests
  (smoke, active-slot, 2 panic-path).
- `src/circuit/main.rs` — Stage 5d-next-5 outer (Phase 2a + 2b
  integrated). The in-coin loop hosts the per-slot source-side gates;
  the aggregator-verify is hoisted above the loop so its PIs are
  accessible.
- `src/circuit/recursion_shape_probe.rs` — diagnostic probe
  (`#[cfg(test)]` only; not in production circuit graph). Includes
  `dump_pass_3_gates_lists_for_inspection`,
  `dump_phase_2a_outer_vs_helper_diff` (`#[ignore]`d), and
  `dump_phase_2a_pad_bits_sweep` (`#[ignore]`d).
- `src/circuit/mod.rs` — module declarations.
- `MIGRATION_RESEARCH.md` §7.21 — original Plonky2 1.1.0 deferral
  context (now superseded by this document's empirical findings).
- `STAGE_5D_NEXT_4_DESIGN.md` — original Option B architectural
  notes; the current implementation matches the "Aggregator built
  against fixed shape, vk binding via connect_hashes" design plus the
  empirically-derived `ConstantGate` injection and pad-bits constraint.

## Benchmark

`cargo test --release --lib …` on an Apple M3 (24 GB), single-threaded:

- `stage_5c_plus_initial_non_mint_zero_balance_accepted` (all-inactive
  Phase 2b smoke): **~40 s** wall.
- `stage_5c_plus_initial_then_account_update_with_commitment_proofs`
  (init → update chain, all-inactive in-coins): **~53 s** wall.
- `stage_5d_next_5_phase_2b_initial_with_one_active_in_coin_and_source`
  (Init + 1 active in-coin from source): **~99 s** wall (one extra
  Init prove for source = ~40 s + consumer prove ~50 s).
- `stage_5d_next_5_phase_2b_account_update_combined_in_and_out_coin_with_source`
  (Update + in-coin + out-coin + source, 2-leaf MMR): **~154 s** wall
  (source Init + consumer prev Init + consumer Update).
- Phase 3 negatives: each ~50–55 s wall (one source Init + one
  consumer prove, except the wrong-vk negative which skips the source
  build entirely via the all-inactive shortcut).
- `dump_phase_2a_pad_bits_sweep` (`#[ignore]`d diagnostic, 4 rebuilds
  of aggregator + minimal outer): **~138 s** wall.

## How to verify Phase 2a + 2b + 3 from scratch

```bash
cd program-plonky2

# 1. Phase 2a probe (no Phase 2b dependencies).
cargo test --release --lib \
  circuit::recursion_shape_probe::dump_pass_3_gates_lists_for_inspection \
  -- --nocapture
# Expect: baseline_ok=true, 2v_14=false, 2v_14_with_constant_gate=true

cargo test --release --lib \
  circuit::recursion_shape_probe::dump_phase_2a_pad_bits_sweep \
  -- --ignored --nocapture
# Expect: pad_bits=N → helper_degree=N+1 for all N in {14, 15, 16, 17}

# 2. Phase 2a smokes (all-inactive in-coins; Stage 5d-next-3 regression).
cargo test --release --lib \
  stage_5c_plus_initial_non_mint_zero_balance_accepted \
  -- --nocapture
cargo test --release --lib \
  stage_5c_plus_initial_then_account_update_with_commitment_proofs \
  -- --nocapture

# 3. Phase 2b positives (active in-coin slots + real source proofs).
cargo test --release --lib stage_5d_next_5_phase_2b -- --nocapture --test-threads=2

# 4. Phase 3 negatives.
cargo test --release --lib stage_5d_next_5_phase_3 -- --nocapture --test-threads=2

# 5. Aggregator regression (Phase 1).
cargo test --release --lib circuit::source_aggregator::tests::
```
