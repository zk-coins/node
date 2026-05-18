# Stage 5d-next-5 — source-side verification via aggregator pattern

Tracking document for the per-in-coin recursive verification work
(SPEC §8 step 2). Refers back to the deferred Stage 5d-next-4 context
in `MIGRATION_RESEARCH.md` §7.21 and the original design notes in
`STAGE_5D_NEXT_4_DESIGN.md` (Option B / aggregator pattern).

## Status snapshot

| Phase | Scope | Result |
|------:|-------|--------|
| 1 | Aggregator skeleton + smoke + active-slot test | **Done.** Landed via #22, currently on `feat/plonky2-migration`. |
| Phase-1 coverage gap | `should_panic` test for `prove_aggregator`'s invalid-witness arm | **Done in this PR** (fast — no circuit build needed, 0.00 s wall). |
| 2a probe | Empirical investigation of the Plonky2 1.1.0 `dummy_circuit` shape mismatch | **Done in this PR.** `src/circuit/recursion_shape_probe.rs` is a `#[cfg(test)]`-gated diagnostic module that reproduces and characterises the blocker. |
| 2a probe — partial breakthrough | Explicit `ConstantGate::new(2)` injection in pass-3 makes `dummy_circuit(_)` succeed | **Done in this PR.** Probe variant `pass_3_two_verify(_, force_constant_gate = true)` produces 13 gates incl. `ConstantGate` and `dummy_circuit(_)` returns OK. |
| 2a | Outer-circuit integration (`verify_proof(agg)` + `connect_hashes`) | **Still blocked, deeper than expected.** With the ConstantGate-injection trick the `dummy_circuit` half is solved, but the full outer's `build()` still fails the cyclic fixed-point check at `circuit_builder.rs:1067` (`goal_data != common`) — divergence on a shape axis other than `gates`. Diagnosis recommendation in "Recommendations for the next session" below. Attempted integration into `build_circuit` reverted on this branch. |
| 2b | Per-slot source-side SMT inclusion + CMP (c)(d)(e) chain + coupling check | **Not started.** Strictly blocked behind 2a. |
| 3 | Restored 4 cyclic positives + 3 new SPEC §13 negatives + 100 % line coverage | **Not started.** Blocked behind 2. |

### What's in this PR (Phase-1 follow-up)

- `src/circuit/recursion_shape_probe.rs` — `#[cfg(test)]` diagnostic
  that builds Stage 5d-next-3's pass-3 common (1 `verify_proof`) and
  several Stage 5d-next-5 candidate commons (2 `verify_proof`s with
  varying pad, forced-constant counts, and an explicit
  `ConstantGate::new(2)` injection), dumps each gates list, and runs
  `dummy_circuit(_)` to record which shapes pass / fail the
  assertion at `plonky2-1.1.0/src/recursion/dummy_circuit.rs:116`.
  The `pass_3_two_verify_forced` helper is kept as `#[allow(dead_code)]`
  documented dead-end research; the working fix (`force_constant_gate
  = true` in `pass_3_two_verify`) is empirically verified to make
  pass-3 + `dummy_circuit` agree.
- `src/circuit/source_aggregator.rs` — extracted
  `assert_slot_witnesses_valid` from `prove_aggregator`, replaced the
  in-loop `panic!` with `unreachable!` (the upfront validation makes
  it genuinely unreachable), and added two fast `#[should_panic]`
  tests for the slot-count and active-but-missing-real-proof
  contracts (Phase-1 coverage gap closed).
- This file (`STAGE_5D_NEXT_5_AGGREGATOR.md`) — updates the post-#22
  snapshot with the ConstantGate-injection breakthrough on the
  `dummy_circuit` half, AND the remaining (different) cyclic
  fixed-point divergence the outer-integration attempt revealed.

### What's NOT in this PR (still deferred)

- No edits to `src/circuit/main.rs`. The outer state-transition
  circuit still does not consume an aggregator proof. The Phase-1
  aggregator remains a standalone artifact reachable only via its own
  unit tests + the probe module — exactly as it was on
  `feat/plonky2-migration` after #22.
- Per-slot source-side gates (Phase 2b).
- The 7 production-criterion tests from the issue (Phase 3).
- `cargo llvm-cov --fail-under-lines 100`.
- Any change to `script-plonky2/`, `server/`, `shared/`, root
  `Cargo.toml` / `rust-toolchain`, `ROADMAP.md`, `SESSION_STATE.md`,
  `STEP7_PREP.md`, or `MIGRATION_RESEARCH.md`.

## Probe findings (empirical, this PR)

Run via:

```text
cd program-plonky2 && cargo test --release --lib \
  circuit::recursion_shape_probe::dump_pass_3_gates_lists_for_inspection \
  -- --nocapture --test-threads=1
```

Output (paraphrased — full transcript reproducible from the test):

| Helper variant | `gates.len()` | `ConstantGate` present? | `dummy_circuit` result |
|----------------|---:|---|---|
| Stage 5d-next-3 baseline (1 verify, pad 14) | **13** | **yes**, position `[1]` | **OK** ✓ |
| 2 verify, pad 14 | 12 | no | **PANIC** — shape mismatch |
| 2 verify, pad 15 | 12 | no | **PANIC** |
| 2 verify, pad 16 | 12 | no | **PANIC** |
| 2 verify + 1 forced `builder.constant`, pad 14 | 12 | no | **PANIC** |
| 2 verify + 4 forced constants, pad 14 | 12 | no | **PANIC** |
| 2 verify + 16 forced constants, pad 14 | 12 | no | **PANIC** |
| 2 verify + 64 forced constants, pad 14 | 12 | no | **PANIC** |
| 2 verify + 256 forced constants, pad 14 | 12 | no | **PANIC** |

The probe demonstrates:

1. **Stage 5d-next-3's 1-`verify_proof` pass-3 is the only naturally
   `ConstantGate`-emitting configuration.** This is what makes the
   cyclic recursion's `_or_dummy` self-test succeed in #22's smoke +
   active-slot tests.

2. **Adding a second `verify_proof` to pass 3 deterministically
   removes `ConstantGate` from the gates list** unless the helper
   explicitly injects one. Tested:
   - `INNER_PAD_BITS` (14 / 15 / 16) — all fail without injection;
   - `builder.constant + builder.mul(c, zero)` chain at N = 1 / 4 /
     16 / 64 / 256 distinct constants — all fail (the constants get
     absorbed by `ArithmeticGate`'s coefficient slots instead of
     forcing a `ConstantGate` allocation);
   - **Explicit `builder.add_gate(ConstantGate::new(2), …)`
     injection in pass-3 — SUCCEEDS for the isolated
     `dummy_circuit(_)` check.** The 2-verify pass-3 then has 13
     gates including `ConstantGate`, matching `dummy_circuit`'s
     rebuild.

3. The mismatch in the failing cases fires inside
   `dummy_circuit(common_data)` (which `_or_dummy` and
   `cyclic_base_proof` both call). `dummy_circuit` unconditionally
   subtracts 2 from its NoopGate budget to leave room for
   `PublicInputGate` + `ConstantGate`; its rebuild therefore emits
   `ConstantGate` even when the passed `common_data.gates` doesn't
   list it. The `assert_eq!(&circuit.common, common_data)` at
   `dummy_circuit.rs:116` then fails.

4. **The ConstantGate injection trick fixes the isolated
   `dummy_circuit` mismatch but is NOT sufficient for the full outer
   integration.** When `build_circuit()` is extended with the
   `verify_proof(aggregator)` + `connect_hashes` wiring AND the
   matching `ConstantGate::new(2)` injection in both pass-3 (helper)
   and the outer's `build_circuit` body, the cyclic fixed-point still
   fails — but at a different site: `plonk/circuit_builder.rs:1067`
   (`Failed to build circuit`), which checks `goal_data != common`
   after the outer's full `build()`. So pass-3's output matches
   `dummy_circuit`'s rebuild (probe ✓), but it does NOT match the
   real outer's `build()` output. The remaining divergence (between
   pass-3 modeled and outer actual) is on a different shape axis —
   likely `quotient_degree_factor`, `k_is`, or `selectors_info`
   composition driven by the outer's 10 k constraint gates from
   SMT / CMP / in-coins / out-coins. Diagnosing this needs a side-by-
   side dump of pass-3-common vs. partial-outer-common, which the
   current probe doesn't (yet) do.

## Upstream Plonky2 1.1.0 patch (still applicable for the
## `dummy_circuit` half of the problem)

The `dummy_circuit` half of the blocker has a clean upstream fix.
The CYCLIC-fixed-point half (`circuit_builder.rs:1067`) is a
separate, deeper problem that the upstream patch doesn't address
on its own.

Two minimal-diff options for the `dummy_circuit` fix:

### Option P1 — gate-aware NoopGate budget (preferred)

In `plonky2/src/recursion/dummy_circuit.rs`,
`pub fn dummy_circuit<F, C, const D>(common_data: ...)`:

```rust
// BEFORE:
// "Need to account for public input hashing, a `PublicInputGate` and a `ConstantGate`."
let num_noop_gate = degree - common_data.num_public_inputs.div_ceil(8) - 2;

// AFTER:
let has_constant_gate = common_data
    .gates
    .iter()
    .any(|g| g.0.id().starts_with("ConstantGate"));
// Reserve 1 row for PublicInputGate always, 1 row for ConstantGate
// only if the target common has one. Without this conditional, the
// rebuild's gate set diverges from `common_data` whenever the latter
// has no standalone ConstantGate (e.g. when constants are fully
// absorbed by other gates' coefficient slots).
let constant_reserve = if has_constant_gate { 1 } else { 0 };
let num_noop_gate =
    degree - common_data.num_public_inputs.div_ceil(8) - 1 - constant_reserve;
```

With `constant_reserve = 0`, the dummy circuit has more NoopGate
rows, no spare row for a freshly-allocated `ConstantGate`, and Plonky2's
constant-routing falls back to packing constants into existing gates'
coefficient slots — the same path the helper's pass-3 already takes.

The downside: if `dummy_circuit` is given a `common_data` with no
`ConstantGate` AND with constant pressure that genuinely doesn't fit
in other gates' slots, the rebuild fails at `builder.build()` time
(can't materialise a constant). For our case (`common_data` produced
by the helper, whose constants we know fit by construction), this
isn't a concern.

### Option P2 — drop the assertion

In `plonky2/src/recursion/dummy_circuit.rs`:

```rust
// BEFORE:
let circuit = builder.build::<C>();
assert_eq!(&circuit.common, common_data);

// AFTER:
let circuit = builder.build::<C>();
debug_assert_eq!(&circuit.common, common_data);
```

Cheaper diff but riskier. The assertion catches genuine shape bugs in
upstream Plonky2 itself; downgrading to `debug_assert_eq!` keeps that
benefit in `cfg(debug_assertions)` while letting our release-mode
cyclic recursion build through. The caller then has to tolerate the
fact that `dummy_proof + dummy_vd` no longer EXACTLY conform to
`common_data` — for the verify-proof-against-witnessed-vd path this
is fine (the verify constrains the proof shape via `common_data`
directly, regardless of the dummy's own `verifier_only.common`).

### Distribution

Once the patch lands as a fork:

```toml
# program-plonky2/Cargo.toml
[dependencies]
plonky2 = { git = "https://github.com/zk-coins/plonky2-1.1-fork.git", rev = "<sha>" }
```

This stays scoped to `program-plonky2/` and does not touch the
root workspace `Cargo.toml` (forbidden by the issue's scope rules).
Once Phase 2a lands, the override can stay until a release of
plonky2 ≥ 1.2 picks up the fix.

## Recommendations for the next session

In strict priority order:

1. **Diagnose the `circuit_builder.rs:1067` shape divergence.** With
   the `ConstantGate::new(2)` injection (probe-verified to fix the
   `dummy_circuit` half), the outer's full `build()` still fails the
   `goal_data != common` cyclic fixed-point check. The divergence is
   on a shape axis other than `gates` — likely
   `quotient_degree_factor`, `k_is`, `num_partial_products`, or
   `selectors_info` groups. Concrete debug step: extend
   `recursion_shape_probe` with a `partial_outer_common` builder
   that mirrors `build_circuit` up to but NOT including the cyclic
   `_or_dummy` call, then `try_build_with_options` and compare
   `goal_data` (= helper's pass-3 output) vs. the returned `common`
   field-by-field. The diff will pinpoint the axis.
2. **Once 2a unblocks: implement Phase 2b** — per-slot SMT inclusion
   of `coin.identifier` in `source.output_coins_root`, SPEC §8
   (c)(d)(e) for the source's commitment in `history_root`, coupling
   `source.output_coins_root == source_cmp.commitment_out_coins_root`.
   All masked by `slot.active`. The aggregator's PI layout is
   already finalised for this.
3. **Phase 3 tests.** 4 cyclic positives (Init / Update × no-source /
   with-source) + 3 negatives (source proof not in history; coin id
   not in source's `output_coins_root`; wrong source vk caught by
   `connect_hashes` on the claimed st verifier_data).
4. **`cargo llvm-cov --fail-under-lines 100`** on the activated
   surface.

### Fallback if the divergence axis turns out to be intractable

The `MIGRATION_RESEARCH.md` §7.21 "Decision" rationale still stands:
zkCoins's server-heavy MVP can satisfy SPEC §8 step 2 off-circuit by
having the trusted server only fold commitments of validly-proved
transitions into the history MMR. In that case the aggregator
(Phase 1, on `feat/plonky2-migration`) stays as a future-facing
artifact and `build_circuit` skips the `verify_proof(aggregator)`
plumbing entirely — only the per-slot SMT + CMP gadgets get added,
and the source's `output_coins_root` becomes a prover-witnessed input
rather than an aggregator-exposed PI. This was specifically
attempted in §7.21 "Attempt B" and also hit a cyclic-fixed-point
mismatch, but with a single-`verify_proof` shape that probe
verified is `dummy_circuit`-compatible — the divergence in that case
is more likely solvable with empirical pad/gate-set tuning.

## Aggregator architecture (target end state — per issue #19)

The aggregator box (top) is implemented and merged via #22. The outer
box (bottom) is the Phase 2 target, blocked per above. The diagram
stays here so the next session has a self-contained reference.

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
                              │ aggregator_proof  (not yet
                              │  consumed by outer; see Phase 2a)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Outer StateTransitionCircuit (CYCLIC)        [PHASE 2, BLOCKED]│
│                                                             │
│   conditionally_verify_cyclic_proof_or_dummy(               │
│     condition,                                              │
│     prev_account_proof,                                     │
│     common_data,                ← cyclic fixed-point        │
│   )                                                         │
│                                                             │
│   verify_proof::<C>(                          [PHASE 2a]    │
│     aggregator_proof,                                       │
│     aggregator_verifier_data,   ← constant_verifier_data    │
│     aggregator_common,                                      │
│   )                                                         │
│                                                             │
│   connect_hashes(claimed_st_digest, outer_vd.digest)        │
│   connect_hashes(claimed_st_cap, outer_vd.cap)              │
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
- `src/circuit/recursion_shape_probe.rs` — diagnostic probe
  (`#[cfg(test)]` only, not in the production circuit graph).
- `src/circuit/mod.rs` — module declarations.
- `MIGRATION_RESEARCH.md` §7.21 — Plonky2 1.1.0 deferral context.
- `STAGE_5D_NEXT_4_DESIGN.md` — original architectural notes.

## Benchmark

`cargo test --release --lib circuit::source_aggregator::tests::`
on an Apple M3 (24 GB), single-threaded — these will scale up on the
production Mac Studio M3 Ultra:

- Smoke (`stage_5d_next_5_aggregator_smoke_all_inactive`) alone:
  ~15–20 s. Dominated by the Stage-5d-next-3 outer
  `build_circuit()` call.
- Active-slot test
  (`stage_5d_next_5_aggregator_one_active_slot_with_init_source`)
  adds a real `prove_initial` source proof; combined wall for both
  tests ~30–80 s depending on cache + machine load.
- Both new panic-path tests
  (`stage_5d_next_5_aggregator_assert_witnesses_panics_on_*`):
  **0.00 s wall combined** — they validate the witness contract
  without touching any circuit data.
- Probe (`dump_pass_3_gates_lists_for_inspection`): ~5–8 min wall on
  M3 (builds the aggregator 6× to test the forced-constant ladder;
  bootstraps once, rebuilds the helper passes per variant).

The Phase 2 blocker is purely a circuit-shape constraint, not a
performance one; wall times stay well within the issue's budget.
