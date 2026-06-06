# Plonky3 Recursion Feasibility Spike — Result (Phase 0 Go/No-Go)

> 🟢 **SUPERSEDED — gate is GO (2026-06-06, later same day).** The NO-GO below was **scoped
> too narrowly** and is **overturned**. `probe_q_custom_public_value` proved a custom AIR
> with `num_public_values() > 0` surfaces a soundly-bound per-instance value across a batch
> layer (upstream PR #407, already in our pinned rev), and **`probe_r_carrier_chain` then
> threaded a counter end-to-end across a real depth-4 IVC chain** via that channel
> (`V_3 == V_0 + 3`; wrong forwarded value rejected; wrong carrier bind rejected). The
> `[0,0,0]` finding held only for the primitive tables / `CircuitBuilder` public inputs that
> probes D/G/H/J tested. **CHOSEN DIRECTION: Path 1+5 — custom public-value-emitting (carrier)
> tables** (stays in the Plonky3-STARK family, minimal delta from the Plonky2 IVC model, no
> protocol change). Rationale + 9-path analysis: **`MIGRATION_PLONKY3_SOLUTIONS_RESEARCH.md`**;
> end-to-end proof: PR #214. **Cost (`probe_r_cost`):** the carrier threading + in-circuit
> two-proof verification adds **no** measurable overhead on top of the bare recursion floor —
> at the real `2^16`-row inner scale the base carrier `prove_batch` is ≈271 ms/layer and the
> IVC link's witness-gen ≈2 ms, peak RSS ≈91 MB. The number that actually gates the ≤5 s warm
> budget is the eventual STARK-*prove* of the link circuit (Probe I's ≈3.2 s class, ~1.8 s
> headroom) — **within budget**, not yet incurred in Probe R's witness-gen-only link. The
> probes below remain correct for the constructions they tested.

## Fair Performance Comparison (Probe S, corrected by V/W)

**RESOLVED (T/X/X′/U): a mixed verdict — big wins on cold-start/memory/mint, a wash-or-loss
on `/api/send`.** Probe S's first headline (4–61×) was ~5× too optimistic (degree-3 + zk-proxy;
corrected by V/W); the real single transition is 10–14× faster (T), but the 8-way source
aggregation dominates the full send and is NOT reducible by batching (X′) — so `/api/send` is a
wash (non-zk) / loss (zk), while mint is ~2× and cold-start 38.7×. The full picture is built up
below and summarised in `docs/migration/PLONKY3_MIGRATION_AUDIT_SUMMARY.md`. Probes I/R measured a
*recursion overhead* in **Goldilocks** with **untuned (testing) FRI** — a
feasibility check, not a production-prover timing. **Probe S**
(`tests/probe_s_fair_bench.rs`) measured a **BabyBear Poseidon2 STARK** under
tuned FRI, Poseidon2-Merkle MMCS, parallel DFT, confirmed **NEON packing**
(`PackedMontyField31Neon`, 18 threads). But Probe S used a **degree-3 S-box** and
a **blowup-2 zk-PROXY**, both of which understate the real production cost —
**Probes V and W measured the true cost of each, and the correction is large.**

**Probe S (degree-3, zk-proxy) — OPTIMISTIC, superseded for the zk rows by Probe W:**

| Workload | FRI | Plonky3 p50 | Speedup |
|---|---|---:|---:|
| hash-matched (~4500 hashes, 2^13 rows) | non-zk (blowup 1) | 71 ms | 61× |
| middle (2^15 rows) | non-zk | 303 ms | 14× |
| hash-saturated (2^16) | non-zk | 570 ms | 7.6× |
| *(zk rows used a blowup-2 proxy — see Probe W correction below)* | | | |

**Probe V — degree-7 (the cryptographic S-box) costs 1.66–1.69× over degree-3**
(stable across sizes; at the low end of the 1.5–2.5× review estimate — confirmed,
not refuted). **Probe W — true `HidingFriPcs` (real ZK with random masking rows)
costs 2.9–3.0× over the blowup-2 proxy** — masking roughly TRIPLES prove time; the
proxy was NOT a "small additive term" and Probe S's zk rows were ~3× too fast.

**Corrected production config (degree-7 + true HidingFriPcs + Keccak MMCS),
measured in Probe V/W vs Plonky2 4.35 s:**

| Trace height | degree-7 + hiding p50 | vs Plonky2 4.35 s |
|---|---:|---:|
| 2^13 (hash-matched ~4500) | **1419 ms** | **3.07× faster** ✅ |
| 2^15 | 5910 ms | 0.74× (slower) ⚠️ |
| 2^16 (hash-saturated) | 12033 ms | 0.36× (much slower) 🔴 |

**What it means:** the combined correction is ~1.67× (degree) × ~3× (hiding) ≈ **5×**
on Probe S's optimistic numbers. Plonky3 still wins decisively at the real
**hash count** (~2^13 height → 3.07× under full production crypto), but at a
hash-saturated 2^16-height trace the production config is SLOWER than Plonky2. The
real zkCoins circuit is a *batch* of a ~2^13-height hash table **plus** a ~2^16-height
non-hash table — so the net result depends on the real table mix, which **Probe T**
measures directly (degree-7 + HidingFriPcs, full multi-table). Until Probe T lands,
the honest statement is: **promising at the real hash count, not a guaranteed win at
full circuit size.** Methodology + caveats:
`scripts/bench/results/plonky3-vs-plonky2-fair-m5-max-2026-06-06.md`;
degree-7 = `probe_v_degree7_bench`, true-hiding = `probe_w_hiding_fri`.

### Probe T resolution — the real circuit IS faster (V/W "2^16 slower" was hash-saturation)

`probe_t_real_circuit_bench` resolves the pending verdict by modelling the REAL circuit's
*actual* cost mix under TRUE production crypto — a real multi-table `prove_batch` (which
**does** work with HidingFriPcs + mixed degree, an empirical finding) of a degree-7 Poseidon2
hash table sized to ~4500 hashes (~175 ms standalone) **plus** a degree-3 arithmetic table for
the ~50k non-hash gates (those are real-circuit-faithfully degree 2–3: comparisons, range,
boolean, field-mul — the high-degree cost lives only in the hash S-box, correctly placed in
the hash table). Result vs Plonky2 **4.35 s warm**:

| Non-hash table | constraints | warm p50 | net vs Plonky2 | RSS |
|---|---:|---:|---:|---:|
| 2^13 (realistic — already >50k gates) | 98 304 | **312 ms** | **13.95× faster** | 1.1 GB |
| 2^14 | 196 608 | 449 ms | 9.69× | 1.7 GB |
| 2^15 | 393 216 | 735 ms | 5.92× | 1.9 GB |
| 2^16 (inflated ceiling) | 786 432 | 1307 ms | 3.33× | 2.1 GB |

Config/AIR build = **0.07 ms** (vs Plonky2's 8.2 s cold circuit-build — a ~10⁵× setup win).
**Why this differs from V/W's "2^16 = 12 s slower":** V/W ran the WHOLE 2^16-height trace as the
degree-7 `VectorizedPoseidon2Air` (8 lanes → ~2^19 Poseidon perms — hash-SATURATED, ~115× the
real hash work). The real circuit has only ~4500 hashes (a ~1024-row table) plus a cheap
degree-3 arithmetic bulk — so V/W's 2^16 point was never the real circuit. **Honest
qualification:** Probe T is the **single state-transition** prove cost. The full populated
`/api/send` prove additionally verifies the predecessor proof in-circuit (IVC carrier) and the
up-to-8-way source aggregator — that recursion overhead is **Probe X**, and the end-to-end node
number is **Probe U**; both sit on TOP of these figures. Net so far: **the core transition is
~10–14× faster under true production crypto; the full-pipeline verdict follows X + U.**

### Full-pipeline net verdict (Probes X / Y / Z / AA / U) — honest, mixed

**Probe X (recursion/aggregation, 8 sources + 1 IVC, REAL in-circuit STARK-prove via the
low-level `prove_all_tables` path — #436 is NOT a blocker):** the in-circuit verification of
the 8-way source aggregator + IVC predecessor costs **4.0 s (non-zk) / 6.7 s (zk)** warm — it
**dominates** the prove (the single transition is ~7% of it). The recursion verifier is
hash-heavy (in-circuit FRI/Merkle), and hashing benefits far less from BabyBear's small field
than raw arithmetic does — so the per-transition win does NOT carry into recursion.

**Composed `/api/send` (T+X+node-overhead, Probe U projection):** **~9.9 s non-zk (≈ wash vs
Plonky2's ~10 s) / ~12.6 s zk (slower).** With the real Poseidon-heavy inner circuit (heavier
than the carrier proxy, so Probe X is a *lower bound*), the full send likely tips **slower**.
**`/api/mint`** (recursion-light, no 8-way aggregation) projects **~2× faster**. 

**The unambiguous wins:** **Probe Y cold-start = 38.7× faster** (372 ms vs Plonky2's 14.4 s —
Plonky3 has ~no circuit-build: 1.46 ms vs 8.2 s); **peak RSS** consistently **1–2 GB vs 3.9 GB**;
**Probe AA** 1000-prove soak shows **+2.7 % latency drift (stable), no memory leak**, RSS
plateaus. **Probe Z:** native verify 9.6 ms, proof **1.76 MB** (large — a STARK-size cost),
prove÷verify ≈ 33×; zkCoins verifies nothing on-chain (Schnorr-only, Doc 2), so verify cost is
node-side + per-recursion-layer.

**Honest bottom line:** the migration is **not a uniform speed win**. It is a large win on
**cold-start, memory, mint, and operational stability**, a **wash-or-loss on the user-facing
`/api/send`** (recursion-dominated), at the cost of **larger proofs (1.76 MB)** and an SDK/field
change if BabyBear is chosen (Doc 2). **RECOVERY (Probes AB–AE, see `scripts/bench/results/plonky3-recursion-reduction-m5-max-2026-06-06.md`): cheaper-inner-FRI (2.4×, 64-bit `[VERIFY]`) + MAX_IN_COINS=4 (~2×, protocol decision) compose to send-prove 1.31 s = 3.32× faster / e2e 1.45× (Probe AE) — the wash holds only at today's unchanged protocol. KoalaBear ruled out (AD).** The batching lever is RESOLVED — Probe X′
(`probe_x_prime_batched_aggregator`) ruled it out:** co-proving the 8 sources as one batch
would cut the aggregation **4.1×** (978 ms non-zk / 1664 ms zk — the theoretical floor), but
the protocol cannot retroactively batch sources proved by different prior transactions, and
for 8 INDEPENDENT proofs the API instantiates one full in-circuit FRI verifier each — measured
**1.00–1.01× vs Probe X, exactly flat**. So the only live send-side lever is **reducing
`MAX_IN_COINS`** (protocol-visible — operator decision), or future upstream recursion
improvements. Full numbers: `scripts/bench/results/plonky3-probe-{t,u}-*.md`;
X = `probe_x_aggregator_recursion`, X′ = `probe_x_prime_batched_aggregator`,
Y = `probe_y_cold_start`, Z = `probe_z_verifier`, AA = `probe_aa_sustained_load`.

**Status (historical, superseded — see banner above):** 🛑 NO-GO for the migration *as
specified* (replicating zkCoins' cross-layer state IVC on this `Plonky3-recursion` rev), as
read before Probe Q/R. Probe J + an adversarial review
of all escape routes confirm that **neither Option 1 (AIR public values) nor Option 2
(commit + hash re-bind) can thread a value across a batch-recursion layer** — there is
no per-instance value channel; only whole-trace Merkle-cap commitments are exposed, and
those cannot bind a chosen value without a fork or protocol redesign. The per-layer
commit+rebind *primitive* works (`probe_j_option2_rebind`), but it cannot **compose**
across the chain, so the `prev_account`/ProofData IVC carry is **structurally
unbuildable** here. The non-recursive parts (field/hash/Merkle/single state-transition)
remain portable, but the recursion contract — the heart of the architecture — does not.
See §"NO-GO finding" and §"Gate decision".

> Earlier rounds read CONDITIONAL GO assuming Option 2 was viable; Probe J disproves
> that. This memo now records NO-GO with the escape routes that would reopen it.
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

Tests (all 33 green, `cargo nextest run -p plonky3-recursion-spike`):

| Test | Proves (real proving, ✅ = pos+neg asserted) | Result |
|---|---|---|
| `base_air_round_trips` (P0-T1) | counter AIR proves+verifies via p3-uni-stark / Goldilocks | ✅ |
| `probe_a_ivc` (P0-T2 crit. 1) | IVC structure (layer verifies predecessor) + constant-shape fixed point — does NOT itself thread a PI (that is crit. 2, below) | ✅ |
| `probe_b_fanin` (P0-T3) | 2-to-1 aggregation composes into a fixed-shape fan-in tree | ✅ |
| `probe_c_vk_binding` | inner-proof public-input binding (accept correct / reject mismatched) | ✅ |
| `probe_d_pi_threading` (P0-T2 crit. 2) | **cross-layer PI threading binding** — inner PI threaded to an outer carried value with an IVC relation; wrong value rejected | ✅ |
| `probe_d_multilayer_carry` | **the NO-GO finding** — batch proofs do NOT expose inner public inputs across a layer (`air_public_targets = [0,0,0]`) | ⚠️ pinned |
| `probe_e_active_masking` (P0-T3) | **variable-active-count masking** (§7.17) — 8 slots, active bit, `select`/`connect`; active-bit flip changes the verdict; real STARK proof | ✅ |
| `probe_f_vk_binding` (P0-T4) | **vk-equality connect-back** — wrong-vk inner proof (internally valid against its own vk) rejected by the binding; control confirms | ✅ |
| `probe_h_option1_air_public_values` | **Option 1 dead** — injecting a non-existent public input (`table_public_inputs`) is rejected; combined with `probe_d_multilayer_carry`, AIR-public-value threading is impossible | 🛑 pinned |
| `probe_g_fanin_pi_passthrough` | **per-leaf PI passthrough dead** — a real 2-to-1 aggregation's leaf values are NOT exposed to the outer (`air_public_targets = 0`); integrated fan-in-8 blocked at the first hop | 🛑 pinned |
| `probe_i_cost_projection` | **cost at real scale** — recursion layer over a ≈2^16-gate inner proof: ≈3.2 s/layer, witness_count 44 912, ≈1.4 GB | 📊 |
| `probe_j_option2_rebind` | **Option 2 primitive works, cannot compose** — in-circuit Poseidon2 hash-bind binds `hash(V)`/rejects mismatches; but no committed digest is readable across a batch layer → multi-layer Option 2 impossible | 🛑 the NO-GO |
| `probe_l_multi_air` | **multi-AIR coexistence** — two different AIRs (state-transition-like + aggregator-like) co-verify in one circuit, PIs distinct + bound; cross-wiring rejected | ✅ |
| `probe_m_long_chain` | **long IVC chain (depth 50)** — fixed point holds CONSTANT (witness_count 107 957) to depth 50; every layer verifies; 232.8 s total (~4.66 s/layer), peak RSS ~1.39 GB (flat — no memory accumulation) | 📊 |
| `probe_n_concurrent` | **concurrent load** — 4 independent prove+recurse+verify workloads on threads all succeed; peak RSS ~1.38 GB | ✅ |
| `probe_o_soundness` | **soundness spot-check** — mismatched FRI private data (a different proof's Merkle paths) rejected; tampered public input rejected → the verifier is not vacuous | ✅ |
| `probe_p_serialization` | **proof serialization** — recursion proof bincode round-trips byte-stable (~363 KB) + still verifies; truncated blob rejected | ✅ |
| `probe_q_custom_public_value` | **overturns the NO-GO** — a custom AIR with `num_public_values()>0` surfaces a soundly-bound per-instance value across a batch layer (`air_public_targets[0].len()==1`); value 42 verifies, 999 rejected (BabyBear, upstream PR #407) | ✅ |
| `probe_r_carrier_chain` | **chosen direction, end-to-end** — depth-4 carrier-table IVC chain threads a counter `V_3 == V_0+3`; each link verifies both adjacent carriers in-circuit + `connect`s the carry; wrong forwarded value rejected (WitnessConflict, w/ control), wrong carrier bind rejected (OodEvaluationMismatch) | ✅ |
| `probe_r_cost` | **cost @ real scale** — carrier chain at `2^16`-row inner size: base ≈271 ms/layer, IVC-link witness-gen ≈2 ms, peak RSS ≈91 MB; per-transition floor ≈273 ms; budget-gating link STARK-prove ≈3.2 s class (within ≤5 s warm, ~1.8 s headroom) | ✅ |
| `probe_s_fair_bench` | **fair Plonky3-vs-Plonky2 prover speed** — BabyBear Poseidon2 STARK, tuned FRI, Poseidon2-MMCS, NEON packing: degree-3/zk-proxy headline (corrected by V/W below) (see §"Fair Performance Comparison") | ✅📊 |
| `probe_v_degree7_bench` | **degree-7 (cryptographic) S-box cost** — real degree-7÷degree-3 ratio = 1.66–1.69× (stable); confirms the review estimate | ✅📊 |
| `probe_w_hiding_fri` | **true HidingFriPcs vs zk-proxy** — real ZK masking costs 2.9–3.0× over the blowup-2 proxy; the Probe S zk-proxy was ~3× too fast | ✅📊 |
| `probe_t_real_circuit_bench` | **real-circuit cost estimate** — multi-table `prove_batch` (degree-7 hash + degree-3 arith + HidingFriPcs): single transition ~312 ms = 10–14× faster; build 0.07 ms | ✅📊 |
| `probe_x_aggregator_recursion` | **recursion overhead, 8+1 fan-in** — real in-circuit STARK-prove 4.0 s (non-zk) / 6.7 s (zk); dominates the prove, ≈erases the per-transition win on `/api/send` (#436 not a blocker) | ✅📊 |
| `probe_y_cold_start` | **cold-start** — build+first-prove 372 ms vs Plonky2 14.4 s = 38.7× faster (no circuit-build step) | ✅📊 |
| `probe_z_verifier` | **verifier asymmetry** — verify 9.6 ms, proof 1.76 MB, prove÷verify ≈ 33×; tamper rejected | ✅📊 |
| `probe_aa_sustained_load` | **sustained-load soak** — 1000 proves / 5.43 min: +2.7 % latency drift (stable), RSS plateaus, no leak | ✅📊 |
| `probe_x_prime_batched_aggregator` | **batching lever resolved** — co-proved sources would cut aggregation 4.1× (978 ms/1664 ms floor) but is protocol-unreachable; 8 INDEPENDENT proofs = 1.00–1.01× vs Probe X (flat) → only live lever is MAX_IN_COINS | ✅📊 |
| `probe_ab_recursion_friendly` | **recursion levers** — cheaper-inner-FRI q48 = 2.4× (64-bit, `[VERIFY]`); Poseidon2-inner-MMCS already baseline (Keccak-inner unverifiable in-circuit); ZK-only-outer ≈ 0 | ✅📊 |
| `probe_ac_max_in_coins_sweep` | **fan-in sweep 1/2/4/8** — aggregation ≈ 448 ms/coin + 350 ms base, near-linear; N=4 halves it (protocol lever, no soundness question) | ✅📊 |
| `probe_ad_koalabear` | **field comparison** — KoalaBear transition 1.26× faster BUT aggregation 2.1× SLOWER (20 vs 13 partial rounds) → stay BabyBear | ✅📊 |
| `probe_ae_best_config` | **composed best config** — N=4 + q48: send-prove **1.31 s = 3.32× faster** than Plonky2; e2e 6.91 s = 1.45×; conditional on 2 `[VERIFY]`s | ✅📊 |

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
- **Public inputs are NOT auto-propagated across layers** (the NO-GO finding).

## NO-GO finding — cross-layer state threading is structurally unbuildable 🛑

This is **the gate's pivot** and it is **protocol-touching** (it governs how zkCoins
threads `prev_account` / ProofData through the IVC chain). Earlier rounds narrowed the
construction to Option 2 (commit + hash re-bind); **Probe J + an adversarial review of
every escape route now show Option 2 cannot compose either** → the migration as
specified is NO-GO.

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

**Why Option 2 also fails (`probe_j_option2_rebind` + adversarial review):** Option 2
needs layer N to commit `hash(V)` and layer N+1 to READ that digest and re-bind it. The
per-layer commit+rebind *primitive* is real — `add_hash_slice` computes a Poseidon2
digest in-circuit and `connect` binds it (`hash(V)==hash(V)` accepted, mismatches
rejected). **But layer N+1 cannot read layer N's committed digest.** A batch proof
exposes only whole-trace Merkle-cap commitments (`proof_targets`), never a per-instance
value; the FRI openings are at Fiat–Shamir-random points (no fixed binding); the
preprocessed (vk) commitment is per-circuit-static (can't carry per-instance state); and
the shipped NPO table provers all hardcode empty `public_values` with no public
registration path to emit one. An adversarial pass over all six escape routes (trace
opening, vk channel, custom NPO table, aggregation PIs, two-proof binding, upstream
precedent) found none that binds a value across a batch layer without forking upstream
or redesigning the protocol.

**Consequence:** Option 1 AND Option 2 are dead. zkCoins' cross-layer state IVC (the
`prev_account` carry, and the source-aggregator per-leaf ProofData surfacing) is
**structurally unbuildable** on this `Plonky3-recursion` rev. The threading/masking/vk
*binding primitives* all work in isolation — what is missing is any **per-instance value
channel across a batch-recursion layer**, which Plonky2 cyclic recursion provided
natively and Plonky3 does not.

**Escape routes (what would reopen a GO):**
1. **Upstream feature** — a maintained `Plonky3-recursion` rev that exposes per-instance
   public inputs across batch layers (e.g. a value-emitting NPO backend; the
   `PcsRecursionBackend`/`FriRecursionConfig` traits are NOT sealed). `probe_d_multilayer_carry`,
   `probe_h_…`, `probe_g_…` are pinned (`= 0`) and turn red the moment this changes.
2. **Protocol redesign** — an architecture that does not require threading state across
   recursion layers (out of scope for a backend *port*; escalate to the operator).
3. **Fork upstream** — explicitly out of scope per `MIGRATION_PLONKY3.md` §16.

## Per-probe verdict

### Probe A — IVC structure + fixed point → **SUPPORTED**
Layered chain via `build_next_layer_circuit`/`prove_next_layer` +
`into_recursion_input::<BatchOnly>()`. Base case = a real layer-0 proof (no `_or_dummy`
needed). Constant shape proven: witness_count `[25567, 104630, 107957, 107957]` reaches
a fixed point (analogue of Plonky2 `common_data_for_recursion`, §7.12). Cross-checked
by the upstream `recursive_fibonacci --field goldilocks` example. PI threading across
this chain is the NO-GO finding above.

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
public-input limitation as the NO-GO finding — i.e. the port surfaces them via the
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

## Mechanism robustness (Probes L–P) — recorded for a future re-evaluation

Beyond the gate question, these validate that the `p3-recursion` mechanism is robust for
the *non-threading* uses (aggregation, single-hop verification) that a redesigned
architecture or a future upstream might still rely on:
- **Multi-AIR coexistence** (`probe_l`): two heterogeneous AIRs verify in one circuit
  with independently-bound public inputs (cross-wiring rejected).
- **Depth** (`probe_m`): a 50-layer chain holds the constant-shape fixed point
  (witness_count 107 957) with **flat ~1.39 GB RSS** (no per-layer memory accumulation);
  latency is linear at ~4.66 s/layer.
- **Concurrency** (`probe_n`): 4 simultaneous prove+verify workloads all succeed
  (~1.38 GB peak) — the prover is usable under a service's concurrent load.
- **Soundness** (`probe_o`): the in-circuit verifier genuinely rejects mismatched FRI
  data and tampered public inputs — so every negative assertion in this suite is a real
  rejection, not a vacuous accept.
- **Serialization** (`probe_p`): a recursion proof bincode round-trips byte-stable
  (~363 KB) and still verifies (node-persistence-ready).

None of these change the NO-GO — they confirm the recursion *engine* is solid; what is
missing is only the cross-layer value channel.

## Gate decision (historical, superseded — see top banner; the live decision is 🟢 GO via Path 1+5)

🛑 **NO-GO for the migration as specified.** Every §5 *binding primitive* is empirically
proven (PI threading binding, active-count masking, vk-equality connect-back, IVC fixed
point, fan-in composition) — but they all operate **within a layer or across the single
uni-stark hop**. The one thing the zkCoins recursion contract requires and this rev
cannot provide is a **per-instance value channel across a batch-recursion layer**:
- Option 1 (AIR public values) — dead (`probe_h`, `probe_g`, `probe_d_multilayer_carry`).
- Option 2 (commit + hash re-bind) — the primitive works (`probe_j`) but cannot compose,
  because layer N+1 cannot read layer N's committed digest (adversarial review of all
  escape routes: none binds a value across a batch layer without a fork or redesign).

So `prev_account`/ProofData threading across the IVC chain is **structurally unbuildable**
here. A backend *port* that preserves the recursion contract (`SPEC.md`, `MIGRATION_PLONKY3.md`
§1) cannot be completed on this rev. **Do not start Phases 4–5.** Phases 1–3 (field/hash/
Merkle/single non-recursive state-transition) would still port, but they are not useful
without the recursion they feed.

**Decision is the operator's** (`MIGRATION_PLONKY3.md` §16 — protocol-touching). Options:
1. ~~**Hold** — revisit when `Plonky3-recursion` exposes cross-layer public inputs.~~
   **SUPERSEDED:** the capability is already present (PR #407, on the pinned rev) — it was
   not missing upstream, it was simply not exercised by the stock-table probes. See the
   banner at the top and `MIGRATION_PLONKY3_SOLUTIONS_RESEARCH.md` (Path 1+5: GO via custom
   public-value-emitting tables).
2. **Protocol redesign** — re-architect to avoid cross-layer state threading. Out of
   scope for a backend port; a separate design effort the operator must commission.
3. **Fork upstream** — explicitly excluded by §16.

**Do not** fork/patch `p3-recursion`. No upstream issue is filed; `probe_d_multilayer_carry`,
`probe_h_option1_air_public_values`, and `probe_g_fanin_pi_passthrough` are pinned (`= 0`)
to flip red the moment a rev restores cross-layer value propagation.

## Risks (moot under NO-GO, recorded for a future re-evaluation if an escape route opens)

These applied to the CONDITIONAL-GO reading and are kept for the day the cross-layer
blocker is lifted upstream (escape route 1). **Under the current NO-GO they do not gate
anything** — the migration does not start.

1. **Warm-prove budget (would-be top risk if Option 2 ever composed).** A real-scale
   recursion layer is ≈3.2 s (Probe I) and any commit+re-bind construction adds per-layer
   hashing on top of the base prove (Plonky2 base already 4.35 s). If an upstream rev ever
   reopens cross-layer threading, measure the real circuit + re-bind against the 5 s budget
   FIRST; design knobs (reduce `MAX_IN_COINS`, folding) if it exceeds.
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

## Effort estimate (moot under NO-GO)

`ROADMAP.md` estimated 2–4 weeks ("primarily plumbing"). Phases 1–3 (skeleton, field/
hash, Merkle) are low-risk plumbing (~2 weeks). But **Phases 4–5 cannot be completed at
all** on this rev (no cross-layer state threading), so any full-port estimate is moot
until escape route 1 (upstream) or 2 (redesign) changes the picture. The spike itself —
which is what answered this — was the right ≤1-week investment to avoid weeks of doomed
porting.

## Recommended field decision for Phase 9

**Stay Goldilocks-on-Plonky3 for the whole port (Phases 1–8); defer KoalaBear/BabyBear
to a separate Phase 9** — and only run Phase 9 if Phase 8's `probe_r2` bench misses the
warm-prove budget AND a usable Apple-Silicon (Metal) GPU path materializes. Goldilocks
memory/overhead is comfortable (≈1 GB, ≈4.65 s/layer floor); the small-field win is a
CUDA story our host can't use; `p3-recursion`'s KoalaBear path is the more-exercised one,
so a later swap is low-friction (one variable, per `MIGRATION_PLONKY3.md` §2).
