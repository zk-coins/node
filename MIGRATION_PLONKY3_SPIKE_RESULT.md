# Plonky3 Recursion Feasibility Spike — Result (Phase 0 Go/No-Go)

**Status:** ✅ **GO.**
**Date:** 2026-06-06. **Host:** Apple M5 Max, 128 GB (single Apple-Silicon host, no CUDA).
**Companion to:** `MIGRATION_PLONKY3.md` §5 (Phase 0). This memo is the Phase-0 gate
artifact required by P0-T6.

## Pins probed

| Repo | Rev |
|---|---|
| `Plonky3/Plonky3-recursion` | `524665d0c2e1d294722c064786ae11dff8d9f33b` (HEAD 2026-06-06) |
| `Plonky3/Plonky3` | `56952503e1401a62982ceaf952c5e4a829b61803` (the rev `Plonky3-recursion` is built against) |

The Plonky3-main rev is **not** a free choice: `Plonky3-recursion`'s workspace pins
exactly this rev, and the recursion crates share types with it, so any other rev
yields two incompatible copies of the `p3-*` types. Use this exact pair.

## Spike crate

`spikes/plonky3-recursion-spike/` — its own workspace (edition 2024), `exclude`d
from the root zkcoins workspace so the heavy Plonky3 git deps never enter the
`node`/`shared` build or CI. Throwaway; deleted once the real port lands.

Tests (all green, `cargo nextest run -p plonky3-recursion-spike`):

| Test | Proves | Result |
|---|---|---|
| `base_air_round_trips` (P0-T1) | foundation: counter AIR proves+verifies via p3-uni-stark over Goldilocks | ✅ 0.01 s |
| `probe_a_ivc` (P0-T2) | IVC structure (layer verifies predecessor) + constant-shape fixed point | ✅ 15.3 s |
| `probe_b_fanin` (P0-T3) | 2-to-1 aggregation composes into a fixed-shape fan-in tree | ✅ 14.2 s |
| `probe_c_vk_binding` (P0-T4) | inner-proof **public-input** binding (accept correct / reject mismatched) | ✅ 0.01 s |

**Scope note (read before the GO):** the spike proves the three *mechanisms*
(layered IVC with a fixed point, 2-to-1 tree composition, in-circuit PI binding).
Three things the spec's §5 PASS text names are deliberately **NOT** exercised here
and are carried as Phase-5 construction (flagged per-probe below): explicit
cross-layer PI *threading* (P0-T2 crit. 2), variable-active-count *masking*
(P0-T3), and *vk-equality* connect-back as opposed to PI binding (P0-T4). The
gate is GO because each of those is in-repo construction on a proven primitive,
not an upstream capability gap.

## The single most important finding

**`p3-recursion`'s model is fundamentally different from Plonky2's, and the
migration plan must absorb that — but it is NOT upstream-blocked.**

Plonky2 ships turnkey cyclic recursion (`conditionally_verify_cyclic_proof_or_dummy`,
`cyclic_base_proof`): one fixed-point circuit verifies a proof of *itself*, with a
boolean selecting base-vs-recursive. `p3-recursion` has **none of that**. Instead it
is a **layered circuit-builder model**:

- You build a `p3-circuit` `CircuitBuilder` verifier sub-circuit
  (`verify_p3_uni_proof_circuit` / `verify_p3_batch_proof_circuit`,
  `recursion/src/verifier/`), then prove *that* circuit with the batch-stark
  prover. That proved verifier circuit is "the next layer".
- The high-level API `build_and_prove_next_layer` / `build_and_prove_aggregation_layer`
  (`recursion/src/recursion.rs:468,735`) wraps build+prove.
- There is **no** `_or_dummy` primitive and **no** conditional-verify gadget
  (confirmed by exhaustive search of the recursion + circuit crates).
- Aggregation is **strictly 2-to-1** (`recursion.rs:735`, `left`/`right` only).

Consequence for the real port: the zkCoins recursion contract maps onto this model,
but **not by copying the Plonky2 shapes** (§7.21/§7.22's `_or_dummy`/connect-back
workarounds were Plonky2-specific and must be re-derived, exactly as
`MIGRATION_PLONKY3.md` Phase 5 already warns).

## Per-probe verdict

### Probe A — IVC / cyclic with base case → **SUPPORTED** (structure + fixed point; PI threading is Phase 5)

- **API:** `build_next_layer_circuit` + `prove_next_layer` + chaining via
  `RecursionOutput::into_recursion_input::<BatchOnly>()` (`recursion.rs:99,263,365`).
- **Base case:** trivially expressible — the chain just *starts* from a real proof
  (the counter circuit proved with batch-stark). No predecessor / no dummy needed.
  The absence of a Plonky2-style `_or_dummy` is **not** a blocker here, because the
  base case is "layer 0 = a real proof", not "a recursive layer that conditionally
  skips its predecessor".
- **Constant shape (true IVC):** verified empirically. The verifier-circuit
  `witness_count` GROWS for the first layers then reaches a **fixed point**:
  `[25567, 104630, 107957, 107957]`. Layers 3 and 4 are identical — this is the
  IVC fixed point, the direct analogue of Plonky2's `common_data_for_recursion`
  (`MIGRATION_RESEARCH.md §7.12`). Per-layer cost does **not** grow with depth.
- **Cross-check:** upstream `recursive_fibonacci --field goldilocks
  --num-recursive-layers 5` runs green on this exact rev/host (peak RSS 0.51 GB).
- **NOT proven here (P0-T2 criterion 2 — "counter PI provably threaded from
  base"):** the high-level chain via `into_recursion_input::<BatchOnly>()` carries
  **empty** `table_public_inputs` (`recursion.rs:108`), so the probe demonstrates
  IVC *structure* + constant shape, but does **not** thread a constrained counter
  PI across layers. The enabling primitive (binding an inner proof's PIs as
  constrained outer targets) is proven separately in Probe C. Explicit cross-layer
  PI propagation (the zkCoins ProofData / `prev_account` value carry) is **Phase-5
  construction**, not claimed as demonstrated.

**zkCoins mapping:** the `prev_account` IVC becomes a batch→batch layer chain where
each transition's proof is the predecessor of the next. The first transition is the
base (no predecessor). The `condition` that selected Init-vs-Update inside one cyclic
Plonky2 circuit becomes a structural choice (start the chain vs. extend it). This is
a **redesign of the recursion topology**, decided locally, no SPEC change.

### Probe B — fan-in tree composition → **SUPPORTED**; variable active count → **Phase-5 construction (NOT exercised in the spike)**

- **What the probe PROVES (API):** `build_and_prove_aggregation_layer`
  (`recursion.rs:735`), strictly 2-to-1. Verified that a **depth-2 tree (fan-in-4)**
  of 2-to-1 aggregations of same-AIR batch proofs composes into a fixed-shape root
  that verifies. `MAX_IN_COINS = 8` is one more level (depth-3, 7 aggregations) —
  mechanically identical. The probe uses **four real, identical leaves**; it surfaces
  no per-leaf PI and masks no active bit.
- **What the probe does NOT prove (P0-T3's "variable active count, per-leaf PIs +
  active bit"):** there is **no native conditional-verify** primitive, so the
  intended strategy is to **pad** inactive source slots with real (cheap) proofs and
  carry the active/inactive flag as a public input that is **masked in the consumer
  (outer state-transition) circuit** — the `select_hash` per-slot masking of
  `MIGRATION_RESEARCH.md §7.15/§7.17`, applied in the `p3-circuit` builder
  (`select`/`connect`, `circuit/src/builder/`). The masking *binding primitive* is
  proven in Probe C, but the spike does **not** exercise an actually-masked inactive
  slot or per-leaf PI surfacing. **This is Phase-5 construction.**
- **Why GO despite the gap:** the 2-to-1 restriction is an ergonomics cost (build
  the tree yourself), and the masking relies only on `select`/`connect` (proven to
  exist) + PI binding (proven in Probe C). There is **no upstream capability gap** —
  it is in-repo work, mapping the §7.17 pattern (which Plonky2 already used: the
  aggregator verified 8 slots and masked inactive ones, §7.22) onto the `p3-circuit`
  builder.
- **Cost risk (carry into Phase 5):** padding means up to 8 real proofs even when few
  slots are active. On the real source AIR this is the dominant cost and the place
  the warm-prove budget is most likely to bite — measure it early in Phase 5, on the
  real AIR, not late.

**This was flagged as the most likely blocker. The blocking concern (can N-way
fan-in be expressed at all?) is resolved — it composes. The remaining work
(variable-active masking) is construction on proven primitives, not a gap.**

### Probe C — public-input binding → **SUPPORTED**; vk-equality connect-back → **Phase-5 construction**

- **What the probe PROVES:** an inner proof's **public inputs** are bound in the
  verifier circuit — a mismatched PI claim is rejected. It does **not** feed a
  "deliberately wrong-vk inner proof" (P0-T4's literal text); the inner *vk*-equality
  `connect` that zkCoins' outer→aggregator binding needs is built on the same
  exposed-targets mechanism but is **in-repo Phase-5 work, not demonstrated here**.
- **API:** `verify_p3_uni_proof_circuit` (`recursion/src/verifier/`) +
  `StarkVerifierInputsBuilder` (`recursion/src/public_inputs.rs`), which expose the
  inner proof's commitment and `air_public_targets` as `p3-circuit` `Target`s that
  can be `connect`-ed/`select`-ed.
- **Empirical binding:** the probe builds an in-circuit verifier for a CounterAir
  proof and shows POSITIVE (correct public inputs verify) **and** NEGATIVE
  (claiming `[99, 22]` instead of the committed `[7, 22]` is **rejected** —
  `runner.run()` errors). The inner proof's public inputs are genuinely bound, not
  substitutable.

**zkCoins mapping:** the outer→aggregator vk connect-back and ProofData PI
propagation (Plonky2 `connect_hashes` of claimed-st-vk to own cyclic vk) become
`connect`s of the exposed inner commitment/PI targets in the outer verifier circuit.
Expressible; must be built explicitly (upstream tests verify proofs but don't
demonstrate the cross-layer vk-equality `connect`, so this is in-repo work, not an
upstream feature to wait on).

## Measured cost (P0-T5)

See `scripts/bench/results/plonky3-spike-m5-max-2026-06-06.md`. Summary:

- **Per stabilized recursion layer:** ≈ 4.65 s prove, witness_count 107 957
  (trivial counter AIR, untuned FRI params — an overhead floor, not a real-circuit
  projection).
- **Peak RSS:** ≈ 1.04 GB (full spike suite); ≈ 0.51 GB (upstream 5-layer example).
  ~50–60× under the 64 GB budget.
- No external/CUDA hardware used or needed.

## Gate decision

**GO.** The three load-bearing *mechanisms* are empirically proven in Goldilocks on
the pinned rev — layered IVC with a constant-shape fixed point (A), 2-to-1
aggregation composing into a fixed-shape tree (B), and in-circuit public-input
binding (C). The three §5 items the spike does **not** exercise — cross-layer PI
threading (A), variable-active-count masking (B), and vk-equality connect-back (C) —
are each **in-repo Phase-5 construction on a proven primitive**, not an upstream
capability gap. No probe is blocked by a `p3-recursion` limitation. Proceed to Phase 1.

No upstream issue needs filing for the gate. **Do not** fork/patch `p3-recursion`.
The three deferred constructions above are folded into the Phase-5 risk below.

## Risks carried into Phases 1–8 (none gate-blocking, all to watch)

1. **Upstream is unaudited and pre-1.0** (`README`: "hasn't been audited yet … do
   not recommend for production"), edition 2024, git-only, actively iterating.
   We pin a rev; treat any rev bump as a deliberate, re-tested change.
2. **Recursion topology is a redesign, not a port.** Phases 5 (recursion +
   aggregator) is the highest-risk phase: the source-aggregator vk-binding and the
   variable-active-count masking must be re-derived in the `p3-circuit` builder, not
   copied from §7.21/§7.22.
3. **Padding cost in the aggregator** (Probe B) is the place the warm-prove budget
   is most likely to bite; measure on the real source AIR in Phase 5, not late.
4. **Protocol-visibility guard.** None of this touches `SPEC.md` semantics (the proof
   system is invisible on-chain). The migration changes the proof *format*, which is
   closed-env-only (no on-chain proof, DEV+PRD, no third-party integrators). Any
   change that would alter verification *semantics* → **STOP and escalate** per
   `MIGRATION_PLONKY3.md` §16.

## Revised effort estimate (Phases 1–8)

`ROADMAP.md` estimated 2–4 weeks for the cutover. That assumed "primarily plumbing".
The spike shows the field/hash port is indeed plumbing, but the **recursion +
aggregator redesign (Phases 4–5) is genuinely new construction** on an AIR-based,
batch-stark, manually-masked model. Honest revised range: **5–8 weeks** of careful,
fully-tested work, front-loaded on Phases 4–5. Phases 1–3 (skeleton, field/hash,
Merkle) are low-risk and could land in the first ~2 weeks.

## Recommended field decision for Phase 9

**Stay Goldilocks-on-Plonky3 for the whole port (Phases 1–8); defer
KoalaBear/BabyBear to a separate Phase 9 — and only run Phase 9 if Phase 8's
`probe_r2` bench misses the warm-prove budget AND a usable Apple-Silicon (Metal) GPU
path materializes.** Rationale:

- Memory/recursion-overhead on Goldilocks is comfortable (≈1 GB, ≈4.65 s/layer
  floor). No memory pressure motivates a smaller field.
- The small-field perf win is a **CUDA** story; our host has no CUDA and Plonky3's
  Metal support is not established (`MIGRATION_RESEARCH.md §7.11`). The BabyBear/
  KoalaBear motivation reduces to "Plonky3-native ecosystem".
- `p3-recursion`'s KoalaBear support is the *more* exercised path (its examples
  default to KoalaBear, D=4, width-16), so a later field swap is low-friction — one
  variable moved in isolation, exactly as `MIGRATION_PLONKY3.md` §2 mandates.
