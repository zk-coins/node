# Plonky3 Recursion Feasibility Spike — Result (Phase 0 Go/No-Go)

**Status:** ✅ **GO — with ONE escalated finding** (cross-layer public-input
propagation; see §"Escalated finding"). All three §5 PASS items are now exercised
empirically with real proving and positive+negative assertions.
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

Tests (all 8 green, `cargo nextest run -p plonky3-recursion-spike`):

| Test | Proves (real proving, ✅ = pos+neg asserted) | Result |
|---|---|---|
| `base_air_round_trips` (P0-T1) | counter AIR proves+verifies via p3-uni-stark / Goldilocks | ✅ |
| `probe_a_ivc` (P0-T2) | IVC structure (layer verifies predecessor) + constant-shape fixed point | ✅ |
| `probe_b_fanin` (P0-T3) | 2-to-1 aggregation composes into a fixed-shape fan-in tree | ✅ |
| `probe_c_vk_binding` | inner-proof public-input binding (accept correct / reject mismatched) | ✅ |
| `probe_d_pi_threading` (P0-T2 crit. 2) | **cross-layer PI threading binding** — inner PI threaded to an outer carried value with an IVC relation; wrong value rejected | ✅ |
| `probe_d_multilayer_carry` | **the escalated finding** — batch proofs do NOT expose inner public inputs across a layer (`air_public_targets = [0,0,0]`) | ⚠️ pinned |
| `probe_e_active_masking` (P0-T3) | **variable-active-count masking** (§7.17) — 8 slots, active bit, `select`/`connect`; active-bit flip changes the verdict; real STARK proof | ✅ |
| `probe_f_vk_binding` (P0-T4) | **vk-equality connect-back** — wrong-vk inner proof (internally valid against its own vk) rejected by the binding; control confirms | ✅ |

Each `✅` test asserts BOTH a positive (correct → accepted) and a negative
(tampered/wrong → rejected), and most add a CONTROL isolating the cause of the
rejection. Nothing is a mock; every rejection is a real `run()`/prove failure.

## The single most important architectural finding

**`p3-recursion`'s model is fundamentally different from Plonky2's, and the
migration plan must absorb that.**

Plonky2 ships turnkey cyclic recursion (`conditionally_verify_cyclic_proof_or_dummy`,
`cyclic_base_proof`): one fixed-point circuit verifies a proof of *itself*, with a
boolean selecting base-vs-recursive, **and threads public inputs natively**.
`p3-recursion` has **none of that**. It is a **layered circuit-builder model**:

- You build a `p3-circuit` verifier sub-circuit (`verify_p3_uni_proof_circuit` /
  `verify_p3_batch_proof_circuit`), then prove *that* circuit with the batch-stark
  prover. That proved verifier circuit is "the next layer".
- High-level `build_and_prove_next_layer` / `build_and_prove_aggregation_layer`
  (`recursion.rs:468,735`) wrap build+prove.
- **No** `_or_dummy` primitive, **no** conditional-verify gadget (exhaustive search).
- Aggregation is **strictly 2-to-1** (`recursion.rs:735`).
- **Public inputs are NOT auto-propagated across layers** (the escalated finding).

## Escalated finding — cross-layer public-input propagation ⚠️ OPERATOR DECISION

This is the one place the spike hit a real wall, and per `MIGRATION_PLONKY3.md` §16
it is escalated rather than papered over. It is **protocol-touching** (it concerns
how zkCoins threads `prev_account` / ProofData through the IVC chain).

**What works (`probe_d_pi_threading`):** the threading *binding primitive*. An outer
circuit verifying an inner uni-stark proof exposes the inner public inputs as
constrained targets (`air_public_targets`), and can thread a value forward
(`next_start = inner.last + 1`) bound to an outer-exposed public input. A wrong
threaded value is rejected; a control without the bind accepts it. So routing an
inner PI to an outer carried value, soundly, is demonstrated end-to-end.

**What does NOT work (`probe_d_multilayer_carry`):** when an outer layer verifies an
inner **batch** proof of a `CircuitBuilder` circuit, that circuit's public inputs are
**not** surfaced as `air_public_targets` — every per-table count is `0`. The
high-level chain (`into_recursion_input::<BatchOnly>()`) additionally zeroes
`table_public_inputs` (`recursion.rs:108`). So a value threaded into one batch layer
is **not readable by the next layer** through this path. This DIFFERS from Plonky2,
where cyclic recursion threads public inputs natively.

**Why this matters:** zkCoins' `prev_account` IVC must carry account state across all
transitions. The binding primitive exists, but composing it across the full chain
needs a construction that **re-exposes the threaded value at each layer** — e.g.,
structuring each layer's carried value as an AIR public value, or committing it and
re-deriving it. The obvious high-level path does not do this.

**Assessment:** NOT an upstream "impossible" (the primitive works; this is a
construction problem), but NOT free either. It is the **load-bearing open question
for the IVC topology in Phase 4–5**, and the operator (protocol owner) should weigh
it before the port commits. Options, fastest→safest:
1. Build each transition's threaded outputs as AIR public values so the next layer's
   `air_public_targets` carries them (needs a custom AIR-shaped layer, not a plain
   `CircuitBuilder` circuit).
2. Commit the threaded value into the proof and re-verify it via a Merkle/hash bind
   each layer (more gates, clearly sound).
3. Re-examine whether a newer `Plonky3-recursion` rev exposes per-layer public-input
   propagation (revisit on rev bump; `probe_d_multilayer_carry` is pinned to catch it).

## Per-probe verdict

### Probe A — IVC structure + fixed point → **SUPPORTED**
Layered chain via `build_next_layer_circuit`/`prove_next_layer` +
`into_recursion_input::<BatchOnly>()`. Base case = a real layer-0 proof (no `_or_dummy`
needed). Constant shape proven: witness_count `[25567, 104630, 107957, 107957]` reaches
a fixed point (analogue of Plonky2 `common_data_for_recursion`, §7.12). Cross-checked
by the upstream `recursive_fibonacci --field goldilocks` example. PI threading across
this chain is the escalated finding above.

### Probe B — fan-in tree composition → **SUPPORTED**
`build_and_prove_aggregation_layer`, strictly 2-to-1; a depth-2 fan-in-4 tree composes
into a fixed-shape root that verifies. `MAX_IN_COINS=8` is one more level. The variable
active count is handled by Probe E's masking (below), not inside the aggregation.

### Probe C / Probe F — public-input binding + vk-equality connect-back → **SUPPORTED**
- C: an inner proof's public inputs are bound — a mismatched PI claim is rejected.
- F: **vk-equality connect-back exercised end-to-end.** Two `ConstPrepAir` instances
  (k=42 vs k=99) have different preprocessed commitments (= different vks). The verifier
  circuit `connect`s the inner preprocessed-commitment targets to vk_42. A proof from
  vk_99 — which is INTERNALLY VALID against vk_99 — is rejected **solely** by the vk
  bind (a control accepts it unbound). This is the Plonky2 `connect_hashes` analogue,
  proven.

### Probe E — variable-active-count masking → **SUPPORTED**
The §7.17 `connect(computed, select(active, expected, computed))` pattern, on an 8-slot
fixed-shape consumer circuit, **proved for real with batch-stark**. Active+correct slots
accepted with inactive slots carrying GARBAGE (masked away); an active slot with a wrong
value rejected; flipping a garbage slot's active bit to 1 flips the verdict to reject;
flipping back re-masks. The active bit genuinely gates the per-slot check.

(Note: the masked slot *values* in Probe E are provided as consumer inputs. Sourcing
them from a real aggregation's per-leaf PIs is subject to the same cross-layer
public-input limitation as the escalated finding — i.e. the port surfaces them via the
chosen threading construction, then masks.)

## Measured cost (P0-T5)

See `scripts/bench/results/plonky3-spike-m5-max-2026-06-06.md`:
- **Per stabilized recursion layer:** ≈ 4.65 s prove, witness_count 107 957 (trivial
  counter AIR, untuned FRI — an overhead floor, not a real-circuit projection).
- **Peak RSS:** ≈ 1.04 GB (full suite); ≈ 0.51 GB (upstream 5-layer example). ~50–60×
  under the 64 GB budget. No external/CUDA hardware used or needed.

## Gate decision

**GO**, conditioned on the operator accepting the escalated cross-layer
public-input-propagation finding as Phase-4/5 design work (Option 1/2 above). All
three §5 PASS items — PI threading binding, variable-active-count masking, vk-equality
connect-back — are empirically exercised with real proving and positive+negative
assertions, alongside the IVC fixed point and fan-in composition. No probe is blocked
by an *impossible* upstream limitation. The one real wall (no auto public-input
propagation across batch layers) is a construction problem, not a capability gap, but
it is load-bearing for the IVC and is the operator's call.

**Do not** fork/patch `p3-recursion`. No upstream issue is filed for the gate;
`probe_d_multilayer_carry` is pinned to detect if a rev bump changes the propagation
behavior.

## Risks carried into Phases 1–8

1. **Cross-layer PI propagation (escalated finding)** — the top risk; resolve the IVC
   threading construction in Phase 4 before building Phase 5.
2. **Upstream is unaudited and pre-1.0**, edition 2024, git-only, actively iterating.
   Pin a rev; treat any bump as a deliberate, re-tested change.
3. **Recursion topology is a redesign, not a port.** Phase 5 (recursion + aggregator):
   the source-aggregator vk-binding and active-count masking must be re-derived in the
   `p3-circuit` builder (Probes E/F prove the primitives), not copied from §7.21/§7.22.
4. **Padding cost in the aggregator** (Probe B): up to 8 real proofs even when few slots
   are active; measure on the real source AIR early in Phase 5.
5. **Protocol-visibility guard.** None of this touches `SPEC.md` semantics (proof system
   invisible on-chain). The migration changes the proof *format* (closed-env-only). Any
   change to verification *semantics* → STOP and escalate per `MIGRATION_PLONKY3.md` §16.

## Revised effort estimate (Phases 1–8)

`ROADMAP.md` estimated 2–4 weeks ("primarily plumbing"). The field/hash port is indeed
plumbing, but the **recursion + aggregator redesign (Phases 4–5) is genuinely new
construction** — and the cross-layer threading question adds design risk. Honest revised
range: **6–9 weeks**, front-loaded on Phases 4–5; Phases 1–3 (skeleton, field/hash,
Merkle) are low-risk and could land in the first ~2 weeks.

## Recommended field decision for Phase 9

**Stay Goldilocks-on-Plonky3 for the whole port (Phases 1–8); defer KoalaBear/BabyBear
to a separate Phase 9** — and only run Phase 9 if Phase 8's `probe_r2` bench misses the
warm-prove budget AND a usable Apple-Silicon (Metal) GPU path materializes. Goldilocks
memory/overhead is comfortable (≈1 GB, ≈4.65 s/layer floor); the small-field win is a
CUDA story our host can't use; `p3-recursion`'s KoalaBear path is the more-exercised one,
so a later swap is low-friction (one variable, per `MIGRATION_PLONKY3.md` §2).
