# Stage 5d-next-5 — source-side verification via aggregator pattern

Tracking document for the per-in-coin recursive verification work (SPEC
§8 step 2). Refers back to the deferred Stage 5d-next-4 context in
`MIGRATION_RESEARCH.md` §7.21 and the original design notes in
`STAGE_5D_NEXT_4_DESIGN.md` (Option B / aggregator pattern).

## Status

| Phase | Scope | Result |
|------:|-------|--------|
| 1 | Aggregator skeleton + smoke test | **Done.** Two tests green, ~36 s wall combined. |
| 2a | Outer-circuit integration (`verify_proof(agg)` + `connect_hashes`) | **Blocked** on Plonky2 1.1.0 `dummy_circuit` shape mismatch. Attempt reverted. |
| 2b | Per-slot source-side SMT + CMP gadgets | Blocked behind 2a. |
| 3 | Positives + 3 SPEC §13 negatives + 100 % coverage | Blocked behind 2. |

The aggregator (Phase 1) is correct in isolation. The remaining
blocker is in the **outer** state-transition circuit: integrating a
non-cyclic `verify_proof(aggregator)` alongside the cyclic
`conditionally_verify_cyclic_proof_or_dummy` for `prev_account`
requires `common_data_for_recursion_c` to model a SECOND
`verify_proof`. That breaks the dummy-circuit shape match the cyclic
recursion depends on, in a way that the original deferral
(`MIGRATION_RESEARCH.md` §7.21) anticipated but did not yet solve.

## Architecture (per the issue)

```
┌─────────────────────────────────────────────────────────────┐
│ SourceAggregatorCircuit (NON-CYCLIC, built ONCE per outer)  │
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
│ Outer StateTransitionCircuit (CYCLIC on prev_account)       │
│                                                             │
│   conditionally_verify_cyclic_proof_or_dummy(               │
│     condition,                                              │
│     prev_account_proof,                                     │
│     common_data,                ← cyclic fixed-point        │
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
│   Per in-coin slot (Phase 2b):                              │
│     SMT inclusion of coin_identifier in                     │
│       source.output_coins_root                              │
│     SPEC §8 (c)(d)(e) chain for source.commitment in        │
│       history_root                                          │
│     source.output_coins_root ==                             │
│       source_cmp.commitment_out_coins_root                  │
└─────────────────────────────────────────────────────────────┘
```

### Why the aggregator pattern is needed

Plonky2 1.1.0's `_or_dummy` builds an internal `dummy_circuit` against
the outer's `common_data` and asserts the rebuild's `circuit.common`
matches what was passed in. With multiple `verify_proof` calls or
extensive constant usage in the outer, `common_data.gates` ends up
NOT-matching `dummy_circuit`'s reproduction — historically because
`dummy_circuit` always emits a `ConstantGate` for its noop budget while
some outer shapes can route their constants without one (or vice
versa). The Plonky2 1.1.0 contract is effectively: **the outer's
`common_data` must match `dummy_circuit(common_data)`'s rebuild
shape**, which is fragile.

Stage 5d-next-3's outer (1 cyclic verify, no extra `verify_proof`)
sits in a shape that happens to match. Adding a second `verify_proof`
in the outer (for the aggregator) shifts the shape — see
"Phase 2 blocker" below.

### Why this works around the multi-`_or_dummy` issue

- The aggregator is non-cyclic — no `add_verifier_data_public_inputs`
  call, no recursive shape-fixed-point. Its `common_data` is just what
  `builder.build()` produces.
- The aggregator's `conditionally_verify_proof` is the non-cyclic
  conditional verifier (does NOT call `dummy_circuit`).
- The dummy branch's verifier_data is `constant_verifier_data(&dummy_circuit(st_common).verifier_only)`,
  and the inactive-slot proof witness is `cyclic_base_proof(st_common, st_verifier_only, _)`
  — the same one Stage 5d-next-3 uses for the `condition=false` inner
  in `prove_initial`. Both rely on `dummy_circuit(st_common)`
  succeeding, which it does for Stage 5d-next-3's working
  `common_data` shape.

## Phase 1: aggregator skeleton — **shipped**

Files added:

- `src/circuit/source_aggregator.rs` (~280 lines, including 2 tests)
- `src/circuit/mod.rs` — re-exports the module

Public API:

```rust
pub struct SourceAggregatorCircuit {
    pub data: CircuitData<F, C, D>,
    pub st_common: CommonCircuitData<F, D>,
    pub dummy_st_verifier_only: VerifierOnlyCircuitData<C, D>,
    pub slots: Vec<AggregatorSlotTargets>,
    pub st_verifier_data: VerifierCircuitTarget,
}

pub fn build_source_aggregator_circuit(
    st_common: &CommonCircuitData<F, D>,
) -> SourceAggregatorCircuit;

pub fn prove_aggregator(
    aggregator: &SourceAggregatorCircuit,
    st_verifier_only: &VerifierOnlyCircuitData<C, D>,
    slot_witnesses: &[AggregatorSlotWitness],
) -> Result<ProofWithPublicInputs<F, C, D>>;
```

PI layout: `[per-slot ProofData (16) + active (1)] × MAX_IN_COINS` then
`[st vk digest (4)] + [st vk sigmas_cap (4 × cap_elements)]`. Total
`MAX_IN_COINS * 17 + 4 + 4 * 16 = 204` PIs for the standard recursion
config.

Tests (release, single-threaded):

| Test | What it validates | Wall |
|------|-------------------|------|
| `aggregator_smoke_all_inactive` | 8 inactive slots, no real source proofs. Confirms dummy-branch + `cyclic_base_proof` integration. | ~16 s |
| `aggregator_one_active_slot_with_init_source` | Slot 0 active with a real Initial state-transition proof. Confirms active branch + PI surface. | ~36 s combined |

The smoke test confirms the architectural workaround: aggregator's
`conditionally_verify_proof` + hand-rolled dummy doesn't trigger the
`dummy_circuit` shape assertion that broke `MIGRATION_RESEARCH.md`
§7.21 Attempt A.

## Phase 2a: outer integration — **blocked**

### What was attempted

1. Generalised `common_data_for_recursion_c` to optionally model a
   second `verify_proof` (for the aggregator) in passes 2 and 3, with
   a bumped `INNER_PAD_BITS` (14 → 16).
2. Added an aggregator field to `StateTransitionCircuit`. `build_circuit`
   would:
   - Compute a bootstrap `st_common` via the existing helper (Stage
     5d-next-3 shape) with `num_public_inputs` pre-set to 84.
   - Build the aggregator once against the bootstrap shape, yielding
     `agg_common`.
   - Re-compute `st_common` via the generalised helper including
     `verify_proof(agg_common)`.
   - Rebuild the aggregator against the new `st_common`.
   - Assert fixed-point convergence (`st_common_v1 == st_common_v2`).
   - Build the outer with `verify_proof(aggregator_proof, ...)` +
     `connect_hashes` between the aggregator's claimed st verifier_data
     and the outer's own `verifier_data_target`.
3. Wired `set_aggregator_proof_witness(_)` into the two leaf prove
   functions (Phase 2a always passes empty `source_proofs`, so the
   aggregator proof is all-inactive).

### The blocker

The second-iteration aggregator build calls
`dummy_circuit::<F, C, D>(new_st_common)` (inside
`build_source_aggregator_circuit`). The assertion at
`plonky2-1.1.0/src/recursion/dummy_circuit.rs:116` fires:

```
assertion `left == right` failed
  left:  gates = [NoopGate, ConstantGate {num_consts: 2}, PoseidonMdsGate, ..., PoseidonGate]  (13 gates)
         selector_indices = [0,0,0,0,0,0,0, 1,1,1,1, 2,2]
         selector_groups  = [0..7, 7..11, 11..13]

  right: gates = [NoopGate, PoseidonMdsGate, ..., PoseidonGate]  (12 gates)
         selector_indices = [0,0,0,0,0,0, 1,1,1,1, 2,2]
         selector_groups  = [0..6, 6..10, 10..12]
```

Same `degree_bits = 17`, same `num_constants = 5`, same
`num_public_inputs = 84`. The ONLY difference: `dummy_circuit`'s
rebuild emits an explicit `ConstantGate` instance, while the helper's
pass-3 output absorbs its constants into other gates' constant slots
(particularly `ArithmeticGate { num_ops: 20 }`'s 40 constant slots per
instance) and never emits a standalone `ConstantGate`.

Plonky2's `dummy_circuit` is hard-coded to budget for a
`ConstantGate` (`num_noop_gate = degree - num_public_inputs.div_ceil(8) - 2`,
where the `- 2` accounts for `PublicInputGate + ConstantGate`). So
whenever the passed-in `common_data.gates` does NOT contain
`ConstantGate`, the assertion fires.

Stage 5d-next-3's working pass 3 (with exactly ONE `verify_proof`) DID
end up with `ConstantGate` in its gates list — empirically, the single
verify's constants overflowed ArithmeticGate's absorptive capacity.
Adding a SECOND `verify_proof` (for the aggregator) somehow shifts the
constant distribution so that all constants fit in other gates' slots
and `ConstantGate` is no longer emitted by `builder.build()`.

### Attempted workarounds (all failed)

1. **Bumped `INNER_PAD_BITS` 14 → 16.** Just adds NoopGates; doesn't
   affect constant routing.
2. **Registered the 84 outer PIs in pass 3.** Adds `PublicInputGate`
   to the gates list but doesn't change the constant routing
   sufficiently to force `ConstantGate`.
3. **Added 64 distinct `builder.constant(F::from_canonical_u64(_))`
   calls in pass 3.** The constants are virtual targets — if nothing
   consumes them, Plonky2 optimises them away. Even when wired to
   public inputs, the constants get absorbed into ArithmeticGate slots
   without forcing `ConstantGate`.

The fundamental issue is that Plonky2 1.1.0 doesn't expose a way to
**force** `ConstantGate` emission in `builder.build()` — the emission
is a function of how constants happen to route through other gates.
Achieving a deterministic match with `dummy_circuit`'s shape requires
either:

- a Plonky2 patch (per `MIGRATION_RESEARCH.md` §7.21 option 2), or
- finding a circuit shape where pass 3's emitted gates list happens to
  match `dummy_circuit`'s rebuild for the new (post-aggregator-verify)
  common_data.

## Recommendations for the next session

In order of decreasing leverage:

1. **Plonky2 upstream patch.** Update `dummy_circuit` to mirror the
   passed-in `common_data.gates` exactly — i.e., skip `ConstantGate`
   emission when `!common_data.gates.contains(&ConstantGate { .. })`.
   Per `dummy_circuit.rs:99–117`, this likely means making
   `num_noop_gate` conditional and adjusting which gate types are
   instantiated. A small, contained PR.

2. **Aggregator built against a "synthetic" `st_common`.** Don't model
   the aggregator's `verify_proof` in `common_data_for_recursion_c`.
   Keep the outer's `common_data` at Stage 5d-next-3 shape (1 verify,
   no `ConstantGate` issue) and *pretend* the aggregator's verify is
   absorbed into the NoopGate budget. The trick: the aggregator's
   verify_proof adds gates the outer ACTUALLY uses, but `common_data`
   doesn't model them — so the cyclic verify constraint
   `outer.common == common_data` fails. Workable only if NoopGate
   absorbs the entire delta AND the gate-type set happens to remain
   stable. Has to be probed empirically.

3. **Defer source-side verify entirely.** For zk-coins's server-heavy
   MVP architecture, source validity can be enforced off-circuit by
   the trusted server only folding commitments of validly-proved
   transitions into the history MMR (see `MIGRATION_RESEARCH.md`
   §7.21's "Decision" rationale). The aggregator can ship as a
   future-facing artifact: tests + smoke check live in the codebase
   without blocking the MVP timeline.

The aggregator skeleton (Phase 1) is ready to merge regardless of
which option is pursued for Phase 2. Its smoke + active-slot tests
exercise the dummy-branch architecture and the active-slot PI
surface; both will be needed when the outer integration is solved.

## Open files / locations

- `src/circuit/source_aggregator.rs` — aggregator circuit + 2 tests
- `src/circuit/mod.rs` — module declaration
- `MIGRATION_RESEARCH.md` §7.21 — Plonky2 1.1.0 deferral context
- `STAGE_5D_NEXT_4_DESIGN.md` — original architectural notes (this
  document supersedes §"The hard architectural decision" with the
  Phase 1 outcome)

## Benchmark

Apple M3 Ultra, `cargo test --release`:

- Aggregator + state-transition build: ~10 s.
- All-inactive aggregator prove + verify: ~6 s.
- Active-slot positive (state-transition `prove_initial` + aggregator
  prove + verify): ~20 s combined.

These are within the budget; the Phase 2 blocker is purely a circuit
shape constraint, not a performance one.
