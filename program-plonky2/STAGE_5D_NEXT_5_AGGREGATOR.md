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
| 2a | Outer-circuit integration (`verify_proof(agg)` + `connect_hashes`) | **Still blocked.** The probe rules out every in-tree workaround (pad-bit variation, PI registration, 1/4/16/64/256 forced constants). Requires an upstream Plonky2 1.1.0 patch — sketch below. |
| 2b | Per-slot source-side SMT inclusion + CMP (c)(d)(e) chain + coupling check | **Not started.** Strictly blocked behind 2a — the per-slot gates only have a place to live once the aggregator is wired into the outer's PI extraction. |
| 3 | Restored 4 cyclic positives + 3 new SPEC §13 negatives + 100 % line coverage | **Not started.** Blocked behind 2. The 4 positives and 3 negatives the issue enumerates need the source-side gadgets in 2b to be meaningful. |

### What's in this PR (Phase-1 follow-up)

- `src/circuit/recursion_shape_probe.rs` — `#[cfg(test)]` diagnostic
  that builds Stage 5d-next-3's pass-3 common (1 `verify_proof`) and
  several Stage 5d-next-5 candidate commons (2 `verify_proof`s with
  varying pad and forced-constant counts), dumps each gates list, and
  runs `dummy_circuit(_)` to record which shapes pass / fail the
  assertion at `plonky2-1.1.0/src/recursion/dummy_circuit.rs:116`.
- `src/circuit/source_aggregator.rs` — extracted
  `assert_slot_witnesses_valid` from `prove_aggregator`, replaced the
  in-loop `panic!` with `unreachable!` (the upfront validation makes
  it genuinely unreachable), and added two fast `#[should_panic]`
  tests for the slot-count and active-but-missing-real-proof
  contracts (Phase-1 coverage gap closed).
- This file (`STAGE_5D_NEXT_5_AGGREGATOR.md`) — replaces the "Phase 1
  only, Phase 2 blocked" snapshot from #22 with the post-probe
  understanding + concrete upstream-patch path.

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

1. **Stage 5d-next-3's 1-`verify_proof` pass-3 is the only known
   in-tree configuration that emits `ConstantGate`.** This is what
   makes the cyclic recursion's `_or_dummy` self-test succeed in
   #22's smoke + active-slot tests.

2. **Adding a second `verify_proof` to pass 3 deterministically
   removes `ConstantGate` from the gates list**, regardless of:
   - `INNER_PAD_BITS` (tested 14 / 15 / 16);
   - the number of explicit `builder.constant` calls subsequently
     consumed by `builder.mul(c, zero)` (tested 1 / 4 / 16 / 64 / 256
     distinct constants).

   The first verify_proof's constants overflow `ArithmeticGate`'s
   constant slots and force a standalone `ConstantGate` instance to
   be allocated at build time. Adding a second `verify_proof` adds
   ~40 more `ArithmeticGate` instances, each with 40 constant slots,
   which absorbs the constant pressure entirely — no `ConstantGate`
   ever gets allocated by `builder.build()`.

3. The mismatch fires inside `dummy_circuit(common_data)` (which
   `_or_dummy` and `cyclic_base_proof` both call). `dummy_circuit`
   unconditionally subtracts 2 from its NoopGate budget to leave room
   for `PublicInputGate` + `ConstantGate`; its rebuild therefore
   emits `ConstantGate` even when the passed `common_data.gates`
   doesn't list it. The `assert_eq!(&circuit.common, common_data)` at
   `dummy_circuit.rs:116` then fails.

4. **No in-tree workaround exists.** The selector-group structure of
   the 2-`verify_proof` pass-3 is `[0..6, 6..10, 10..12]`, vs.
   `[0..7, 7..11, 11..13]` for the 1-verify baseline — i.e., one gate
   is missing from selector group 0 specifically (the
   `ConstantGate`). Forcing more constants into the circuit shifts
   constants among existing arithmetic gates without ever causing a
   standalone `ConstantGate` instance.

## Upstream Plonky2 1.1.0 patch (proposed)

The fix has to live in `plonky2-1.1.0`. Two minimal-diff options:

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

1. **Land the Plonky2 fork.** Either P1 or P2 from above. Without it,
   no in-tree work on `main.rs` will get past `builder.build()` for
   the cyclic outer with `verify_proof(aggregator)` added.
2. **Phase 2a outer integration.** Wire `verify_proof(aggregator)`
   into `build_circuit` + add `connect_hashes` for the claimed
   state-transition `verifier_data`. Use Phase 1's aggregator
   skeleton verbatim — its public API is finalised.
3. **Phase 2b per-slot source-side gates.** SMT inclusion of
   `coin.identifier` in `source.output_coins_root`, SPEC §8 (c)(d)(e)
   for the source's commitment in `history_root`, coupling
   `source.output_coins_root == source_cmp.commitment_out_coins_root`.
   All masked by `slot.active`.
4. **Phase 3 tests.** 4 cyclic positives (Init / Update × no-source /
   with-source) + 3 negatives (source proof not in history; coin id
   not in source's `output_coins_root`; wrong source vk caught by
   `connect_hashes` on the claimed st verifier_data).
5. **`cargo llvm-cov --fail-under-lines 100`** on the activated
   surface.

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
