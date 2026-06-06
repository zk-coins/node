# Plonky3 Recursion Feasibility Spike — Result (Phase 0 Go/No-Go)

**Status:** ⚠️ **CONDITIONAL GO.** All §5 PASS items exercised empirically (real
proving, pos+neg). Two findings are now *resolved into hard constraints* before
Phase 1 (Probes G/H/I): (1) cross-layer PI propagation via AIR public values is **not
achievable on this rev** (the shipped table provers emit no AIR public values; the only
theoretical avenue is a bespoke custom NPO-table prover, which is no cheaper or sounder
than Option 2) → Phase-5 **must** use the commit+hash re-bind construction ("Option
2"); the Phase-1-authorize choice is no longer free. (2) The recursion-layer cost at
real circuit scale (≈3.2 s/layer) plus the mandatory Option-2 overhead puts the
**≤5 s warm-prove budget at material risk** — measure on the real circuit early in
Phase 5. See §"Resolved finding" and §"Cost projection".
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

Tests (all 11 green, `cargo nextest run -p plonky3-recursion-spike`):

| Test | Proves (real proving, ✅ = pos+neg asserted) | Result |
|---|---|---|
| `base_air_round_trips` (P0-T1) | counter AIR proves+verifies via p3-uni-stark / Goldilocks | ✅ |
| `probe_a_ivc` (P0-T2 crit. 1) | IVC structure (layer verifies predecessor) + constant-shape fixed point — does NOT itself thread a PI (that is crit. 2, below) | ✅ |
| `probe_b_fanin` (P0-T3) | 2-to-1 aggregation composes into a fixed-shape fan-in tree | ✅ |
| `probe_c_vk_binding` | inner-proof public-input binding (accept correct / reject mismatched) | ✅ |
| `probe_d_pi_threading` (P0-T2 crit. 2) | **cross-layer PI threading binding** — inner PI threaded to an outer carried value with an IVC relation; wrong value rejected | ✅ |
| `probe_d_multilayer_carry` | **the resolved finding** — batch proofs do NOT expose inner public inputs across a layer (`air_public_targets = [0,0,0]`) | ⚠️ pinned |
| `probe_e_active_masking` (P0-T3) | **variable-active-count masking** (§7.17) — 8 slots, active bit, `select`/`connect`; active-bit flip changes the verdict; real STARK proof | ✅ |
| `probe_f_vk_binding` (P0-T4) | **vk-equality connect-back** — wrong-vk inner proof (internally valid against its own vk) rejected by the binding; control confirms | ✅ |
| `probe_h_option1_air_public_values` | **Option 1 dead** — injecting a non-existent public input (`table_public_inputs`) is rejected; combined with `probe_d_multilayer_carry`, AIR-public-value threading is impossible | 🛑 pinned |
| `probe_g_fanin_pi_passthrough` | **per-leaf PI passthrough dead** — a real 2-to-1 aggregation's leaf values are NOT exposed to the outer (`air_public_targets = 0`); integrated fan-in-8 blocked at the first hop | 🛑 pinned |
| `probe_i_cost_projection` | **cost at real scale** — recursion layer over a ≈2^16-gate inner proof: ≈3.2 s/layer, witness_count 44 912, ≈1.4 GB | 📊 |

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
- **Public inputs are NOT auto-propagated across layers** (the resolved finding).

## Resolved finding — cross-layer public-input propagation → Option 2 is MANDATORY 🛑

This is **protocol-touching** (it governs how zkCoins threads `prev_account` /
ProofData through the IVC chain). The earlier round left the threading construction
as a TBD choice between Option 1 (AIR public values, "fast") and Option 2 (commit +
hash re-bind, "sound"). **Probes G and H now resolve it empirically: Option 1 is
dead; Option 2 is the only path.** This was worth nailing down before Phase 1.

**The binding primitives all work** (real proving): threading a value across a
*single* uni-stark verification boundary (`probe_d_pi_threading`), masking inactive
slots (`probe_e_active_masking`), and vk-equality binding (`probe_f_vk_binding`).

**But cross-layer value passthrough is structurally absent** — confirmed three ways:
- `probe_d_multilayer_carry`: verifying an inner **batch** proof exposes
  `air_public_targets = [0,0,0]` — a `CircuitBuilder` circuit's public inputs live in
  the committed Public *table*, never as AIR public values (`batch_stark_prover.rs`
  pushes `public_storage.push(Vec::new())` for every primitive table).
- `probe_h_option1_air_public_values`: the only other Option-1 avenue — injecting a
  non-empty `RecursionInput::BatchStark.table_public_inputs` — is **rejected** at
  build/prove (you cannot claim a public input the proof does not structurally have).
- `probe_g_fanin_pi_passthrough`: a **real** 2-to-1 aggregation's per-leaf values are
  likewise not surfaced to the outer (`air_public_targets = 0`). So the integrated
  fan-in-8 (per-leaf ProofData → outer → masked) is blocked at the first hop.

**Consequence (hard, decided before Phase 1):** Option 1 (AIR public values) is NOT
achievable on this rev. Threading `prev_account`/ProofData across the IVC chain **and**
surfacing source-aggregator per-leaf ProofData into the outer state-transition both
**require Option 2**: commit the carried value(s) into each layer's proof and re-bind
them via an in-circuit hash/Merkle check on the next layer. This is sound and
expressible (the binding primitives are proven), but it adds gates/cost per layer —
folded into the cost risk below. Option 3 stays a passive catch: `probe_d_multilayer_carry`
and `probe_h_…` are pinned, so a future `Plonky3-recursion` rev that propagates public
inputs natively turns them red and reopens the cheaper path.

## Per-probe verdict

### Probe A — IVC structure + fixed point → **SUPPORTED**
Layered chain via `build_next_layer_circuit`/`prove_next_layer` +
`into_recursion_input::<BatchOnly>()`. Base case = a real layer-0 proof (no `_or_dummy`
needed). Constant shape proven: witness_count `[25567, 104630, 107957, 107957]` reaches
a fixed point (analogue of Plonky2 `common_data_for_recursion`, §7.12). Cross-checked
by the upstream `recursive_fibonacci --field goldilocks` example. PI threading across
this chain is the resolved finding above.

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
public-input limitation as the resolved finding — i.e. the port surfaces them via the
chosen threading construction, then masks.)

## Cost projection (P0-T5 + Probe I)

Real reference (Plonky2, measured): the full state-transition warm-prove is **4.35 s
p50 / 3.9 GB RSS** on M5 Max at MAX_IN_COINS=8 (`scripts/bench/results/m5-max-2026-06-02-probe_r2.json`);
circuit ≈ **2^16 rows / ~50k gates / ~4500 Poseidon hashes** (`MIGRATION_RESEARCH.md`
§7.17). Budget: warm ≤ 5 s, ideal ≤ 1 s, < 64 GB.

`probe_i_cost_projection` scales the recursion-layer measurement to real inner-proof
size (a ≈2^16-gate base) — recursion overhead grows **sub-linearly** with inner size:

| base gates | base prove | layer-1 witness_count | layer-1 prove |
|---:|---:|---:|---:|
| 2^4 (toy) | 8 ms | 27 002 | 1.18 s |
| 2^12 | 150 ms | 38 569 | 2.32 s |
| **2^16 (real-sized)** | 2.37 s | 44 912 | **3.19 s** |

Peak RSS for the full spike suite ≈ 1.4 GB (≈50× under budget). Earlier per-stabilized-
layer figure (≈4.65 s, witness_count 107 957) is for a chain that has re-recursed
several times; the single layer over a real-sized proof is ≈3.2 s.

**Budget assessment (material risk):** one recursion layer over a real-sized proof is
≈3.2 s — a large fraction of the 5 s warm budget **before** the (Plonky3) base
state-transition prove and **before** the now-mandatory Option-2 commit+hash overhead
per layer. The numbers above are an *arithmetic floor* (the real circuit's Poseidon
constraints are heavier per row). So the warm-prove budget is at genuine risk and
**must be measured on the real circuit + Option-2 early in Phase 5** — if it exceeds
5 s, the design knobs are level (reduce MAX_IN_COINS, fewer in-coin recursions,
folding), never external hardware (`MIGRATION_RESEARCH.md` §7.11). Not a definitive
blow (base prove TBD, FRI params untuned), but not comfortable headroom either.

## Gate decision

**CONDITIONAL GO.** Every §5 PASS item is empirically exercised with real proving and
positive+negative assertions (PI threading binding, active-count masking, vk-equality
connect-back, IVC fixed point, fan-in composition). The migration is feasible. Two
constraints are now *known and hardened before Phase 1* rather than discovered mid-port:

1. **Option 2 is mandatory** (Probes G/H). Cross-layer value passthrough via AIR public
   values is structurally impossible on this rev, so the IVC `prev_account`/ProofData
   carry **and** the source-aggregator per-leaf surfacing must use commit+hash re-bind.
   The Phase-1-authorize "Option 1 vs 2" choice is therefore decided: **Option 2.**
2. **Warm-prove budget is at material risk** (Probe I). A real-scale recursion layer is
   ≈3.2 s, and Option-2 adds per-layer hashing on top of the base prove. This must be
   measured on the real circuit early in Phase 5; if > 5 s, apply design knobs.

The gate is GO because neither is an *impossible* upstream limitation — both are
construction/cost facts with known mitigations. It is *conditional* because the
operator should accept (a) Option 2 as the committed threading construction and (b)
an early Phase-5 budget checkpoint with a fallback plan, before the port commits to
Phases 4–5. If the early budget check fails, that is a real NO-GO trigger to revisit.

**Do not** fork/patch `p3-recursion`. No upstream issue is filed; `probe_d_multilayer_carry`
and `probe_h_option1_air_public_values` are pinned to detect a rev that changes the
propagation behavior (which would reopen the cheaper Option 1).

## Risks carried into Phases 1–8

1. **Option 2 threading overhead + warm-prove budget (top risk).** Option 2 is mandatory
   (Probes G/H) and the recursion layer is ≈3.2 s at real scale (Probe I). Measure the
   real circuit + Option-2 against the 5 s budget at the START of Phase 5; design knobs
   if it exceeds. This is the gate's conditional.
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
