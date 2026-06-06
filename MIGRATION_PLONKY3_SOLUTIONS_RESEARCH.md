# Plonky3 Migration — Solution-Space Research (post-NO-GO)

**Status:** 🟢 **The NO-GO is OVERTURNED.** The Phase-0 gate recorded NO-GO ("no
per-instance value channel across a batch-recursion layer"). That finding was **scoped
too narrowly** — it only tested the primitive tables (Const/Public/Alu) and
`CircuitBuilder` public inputs. **`probe_q_custom_public_value` empirically proves the
channel exists:** a custom AIR with `num_public_values() = 1` proved with `prove_batch`
and verified in-circuit via `verify_batch_circuit` surfaces its public value as a
non-empty `air_public_target` (NOT `[0,0,0]`) and binds it soundly across the batch layer
(correct value accepted, wrong value rejected). This rides on upstream **PR #407 "feat:
support public values"** (merged 2026-03-19, **already in our pinned rev `524665d`**).

**There are now two viable paths**, plus a fallback ladder. This document enumerates and
assesses all nine, with links, repo pointers, and the empirical evidence.
**Date:** 2026-06-06. **Companion to:** `MIGRATION_PLONKY3_SPIKE_RESULT.md` (the gate),
`MIGRATION_PLONKY3.md` (the plan).

---

## TL;DR — ranked

| # | Path | Verdict | Effort | Risk |
|---|---|---|---|---|
| **1+5** | **Plonky3 + custom public-value-emitting tables** (stay on the chosen stack) | ✅ **viable — channel proven (Probe Q)** | medium (~400–650 LOC carrier table + IVC glue) | recursion lib unaudited; chaining + cost still to validate |
| **3** | **Folding / Sonobe (Nova/CycleFold)** — native IVC | ✅ **viable — `z_i→z_{i+1}` is the native primitive** | medium-high (port circuit to arkworks `FCircuit`) | experimental/unaudited; ≤5 s latency unproven |
| 2 | Upstream PR (self-authored) for an ergonomic "mark circuit PI as public output" API | ✅ plausible additive PR atop #407 | low-medium + review cycle | upstream cadence; needs-rfc |
| 7 | RISC Zero / OpenVM (zkVM, committed cross-segment state) | ✅ shipped but heavyweight | high (rewrite to guest) | prover wants GPU; ≤5 s on CPU optimistic |
| 4 | Hybrid: keep Plonky2 recursion, Plonky3 elsewhere | ⚠️ low-value | low | doesn't solve the migration goal |
| 6 | Protocol redesign (off-circuit continuity via trusted node) | ⚠️ possible, reduces soundness scope | medium | weakens the trust model; protocol-owner call |
| 8 | Fork + maintain Plonky3-recursion | ⚠️ excluded by §16; surfaced for completeness | medium + rebase burden | maintenance tax |
| 9 | Creative (Stwo/Cairo, Triton-VM, Halo2-accumulation) | ⚠️ paradigm rewrites | high | latency/maturity unproven |

**Recommendation:** pursue **Path 1+5** (it keeps the chosen Plonky3 stack and the channel
is empirically proven) behind a small **carrier-table IVC-chain spike** (the immediate next
probe), while **benchmarking Path 3 (Sonobe)** in parallel as the architecturally-cleanest
IVC fallback. Plonky2 stays in production until one clears a latency gate.

---

## The pivot: what Probe Q changes

The gate's NO-GO rested on `air_public_targets = [0,0,0]` when verifying an inner batch
proof. The narrow scope: that is the behavior of the **three primitive tables** and of
**`CircuitBuilder` public inputs** (which route to the committed *Public* table, never to
AIR public values). It is **not** the behavior of a **non-primitive / raw AIR that
declares `num_public_values() > 0`**:

- Upstream `recursion/src/verifier/batch_stark.rs` builds `air_public_counts` from
  `entry.public_values.len()` per non-primitive table, and `BatchStarkVerifierInputsBuilder::allocate`
  allocates exactly that many circuit public inputs as `air_public_targets`
  (`recursion/src/public_inputs.rs`). The recursive AIR's `public_values()[i]` resolves
  straight to that target (`circuit/src/symbolic/targets.rs`).
- Soundness is framework-enforced: native `verify_batch` checks
  `public_values.len() == num_public_values()`, and both the native and recursive
  constraint folders bind the public value into the AIR constraints. Upstream's own
  `test_batch_verifier_wrong_public_values` is a `#[should_panic(WitnessConflict)]`.
- **`probe_q_custom_public_value` reproduces this in our crate** (BabyBear, the exact
  upstream pattern): `air_public_targets[0].len() == 1`, correct value verifies, wrong
  value (999 vs the committed 42) is rejected.

So the per-instance, cross-layer, **soundly-bound** value channel the IVC needs **exists
today on our pinned rev**. What remains is *construction*: emit the threaded
`prev_account`/ProofData digest as such a public value at each layer and read it at the
next — exactly the IVC contract Plonky2 cyclic recursion gives natively.

---

## Path 1 + 5 — Plonky3 with custom public-value-emitting tables (RECOMMENDED)

**Status: viable; the channel is empirically proven; the IVC chaining is a public-API
construction (no fork).**

The construction (traced concretely through the public API — every type on the path is
`pub`/unsealed):
1. The state-transition circuit's threaded output (the `prev_account`/ProofData digest) is
   emitted as an **AIR public value** — either a raw AIR (`probe_q` pattern) or a custom
   non-primitive "carrier" table inside the p3-circuit verifier, registered via
   `PcsRecursionBackend::non_primitive_provers`. Required public traits: `TableProver`,
   `BatchAir` (4 builder impls), `NpoPreprocessor`/`NpoAirBuilder`, `PcsRecursionBackend`/
   `FriRecursionConfig`. `BatchTableInstance.public_values` and
   `NonPrimitiveTableEntry.public_values` are public fields.
2. The next layer's `verify_p3_batch_proof_circuit` reads those as `air_public_targets`
   and `connect`s them to thread `V_{N+1} = f(V_N)` (the masking from `probe_e` and the
   vk-binding from `probe_f` plug in here).
3. The uni-stark variant is the **lowest-risk start** — `verify_p3_uni_proof_circuit`
   already exposes inner public inputs (proven end-to-end in `probe_d_pi_threading`).

**Effort:** ~400–650 LOC for the carrier table + per-pattern IVC glue (Subagent code-trace
estimate). **Open items to validate before committing:** (a) chaining the carrier across
≥2 batch recursion layers (the next probe — Probe R); (b) the real warm-prove cost with
the carrier overhead (Probe I gave ≈3.2 s/bare-layer; the carrier adds a small table);
(c) upstream issue [#436](https://github.com/Plonky3/Plonky3-recursion/issues/436)
("Multi-Layer Recursion WitnessConflict at layer ≥2", closed without MRE) — validate our
chain does not hit it. **Risk:** the recursion lib is unaudited/pre-1.0 (pin a rev).

Pointers: PR [#407](https://github.com/Plonky3/Plonky3-recursion/pull/407); upstream tests
`recursion/tests/preprocessing.rs::test_batch_verifier_with_public_values`; our
`probe_q_custom_public_value`, `probe_d_pi_threading`.

## Path 2 — self-authored upstream PR (ergonomic API atop #407)

A small additive feature: a `CircuitBuilder` API to mark a target as a public *output*
that the prover collects into the instance's `public_values`. The hard 80% (sound
cross-layer value binding) already merged in #407; this is a convenience bridge. Nobody has
proposed it. Plausible self-authored PR (with a `needs-rfc` cycle; maintainers Robin Salen
/ Thomas Coratger, active repo). **Not on the critical path** — Path 1+5 already works
without it; pursue only if the carrier-table ergonomics prove painful.

## Path 3 — Folding / Sonobe (Nova/CycleFold) — the native IVC (STRONG ALTERNATIVE)

Sonobe's `FCircuit<F>` trait **is** the account-transition contract:
`generate_step_constraints(cs, i, z_i, external_inputs) -> z_{i+1}` — state threading and
"verify the previous proof" are folded into the IVC construction itself; you delete the
hand-built recursion plumbing. Pure Rust (arkworks), CPU-friendly (curve-based, no GPU, no
Goldilocks-FFT memory wall), Poseidon in-circuit, Schnorr stays off-circuit via
`external_inputs`. **Risks:** experimental/unaudited (audit in progress, Nova/CycleFold
only); SuperNova non-uniform IVC (distinct mint/send/commit transitions) not yet wired
([#144](https://github.com/privacy-scaling-explorations/sonobe/issues/144)); **≤5 s
warm-prove for a 2^16 step is unverified** — a per-step latency spike is the hard gate.
Pointers: [sonobe](https://github.com/privacy-scaling-explorations/sonobe),
[FCircuit](https://github.com/privacy-scaling-explorations/sonobe/blob/main/folding-schemes/src/frontend/mod.rs),
[docs](https://sonobe.pse.dev/). This is the cleanest architectural fit and the only option
where IVC state-threading is the *native* primitive rather than re-derived.

## Path 4 — Hybrid (Plonky2 recursion + Plonky3 components)

Keep Plonky2's working cyclic recursion; use Plonky3 only for non-recursive components.
Low-value: it doesn't achieve the migration's goal (move off maintenance-mode Plonky2 for
the recursion), and mixing two proof systems adds integration cost for no clear benefit.
Surfaced for completeness; not recommended.

## Path 6 — Protocol redesign (off-circuit continuity via the trusted node)

zkCoins is node-heavy with a trusted node (`feedback_zkcoins_server_heavy_architecture`).
`MIGRATION_RESEARCH.md` §7.21/§7.22 already enforce one cross-proof property — "the in-coin
came from a valid prior transition" — **off-circuit** (the node only folds commitments of
validly-proved transitions into the history MMR). The same lever could enforce
`prev_account` continuity off-circuit: the node verifies each transition's proof and checks
`new.prev_account_hash == previous.account_state_hash` outside the circuit, rather than via
in-circuit cross-layer threading. **This sidesteps the recursion-threading problem
entirely** but **reduces the in-circuit soundness scope** (continuity becomes a
trusted-node invariant, not a ZK-enforced one) — a protocol-owner decision, and only
acceptable under the closed-test-env / single-trusted-node MVP assumption. Concrete sketch:
each transition is a standalone proof (no IVC chain); the node maintains the account-state
chain and the history MMR; in-circuit checks cover only the single transition's validity +
the SMT/MMR inclusion of the witnessed prior state. **This is the cheapest path that needs
no recursion threading at all** and aligns with the existing §7.22 MVP posture — worth the
operator's serious consideration alongside Path 1+5.

## Path 7 — Other ZK systems (zkVMs)

- **RISC Zero** — mature, audited; `journal` + `SystemState` + `env::verify` give committed
  cross-continuation state (can model account-IVC). But Metal-GPU is default-on; CPU-only is
  a deliberate, slow downgrade; ≤5 s for a 2^16-equivalent + recursive verify is optimistic.
  Full rewrite to a RISC-V guest. [docs.rs/risc0-zkvm](https://docs.rs/risc0-zkvm/).
- **OpenVM** — cleanest explicit committed-state model (leaf verifier asserts boundary-state
  consistency); newer, GPU-oriented. [whitepaper](https://openvm.dev/whitepaper.pdf).
- **SP1** — mature but GPU-leaning, and **zkCoins deliberately left SP1** ("no upstream
  momentum for our needs") — do not return.
- **Jolt** — *architecturally avoids recursion* (wrong tool for verify-prev + thread-state).
- All zkVMs = large rewrite + heavier prover. A fallback if the account model is better
  expressed as a program than a circuit; not preferred over Path 1+5 / Path 3.

## Path 8 — Fork + maintain (excluded by §16, surfaced for the operator)

No existing fork solves cross-layer PI. A fork would carry the Path-2 feature out-of-tree
against a fast-moving upstream (frequent rebases). **Pros:** full control, no upstream wait.
**Cons:** maintenance tax, diverges from a `needs-rfc` upstream that would likely accept the
feature anyway, explicitly excluded by `MIGRATION_PLONKY3.md` §16. Inferior to Path 1+5
(which needs no fork) and Path 2 (which upstreams it). Only if Path-2's API is needed before
upstream merges.

## Path 9 — Creative / out-of-the-box

- **Stwo / Cairo** (StarkWare, M31, **production-mature, on Starknet mainnet**): recursion
  via the Cairo verifier; state threading expressed at the Cairo-program level. Large rewrite
  to Cairo/AIR; latency unproven for ≤5 s. [s-two](https://starkware.co/blog/s-two-prover/).
- **Triton-VM** (Neptune): recursive STARK designed for fast recursive verification (ships a
  constant-size chain-validation IVC); full recursion still roadmap; you inherit a VM.
- **Halo2 accumulation** (atomic/split): a genuine IVC mechanism, but found implementations
  are research-grade (~300 s prover — far over budget); you'd re-build what Sonobe packages.
- **Binius64**: recursion unshipped + Intel-GFNI-centric (weak on Apple Silicon).
- **WHIR**: a PCS, not a stack — a future component, not adoptable as an IVC framework.

---

## Recommended next steps (empirical)

1. **Probe R (next):** chain a custom carrier table across ≥2 batch recursion layers — emit
   a threaded counter as a public value from layer N, read+rethread it at layer N+1, assert
   the value is carried end-to-end and a wrong forwarded value is rejected. This converts
   Path 1+5 from "channel proven" to "IVC proven". Watch for upstream
   [#436](https://github.com/Plonky3/Plonky3-recursion/issues/436).
2. **Cost:** measure warm-prove with the carrier overhead at real (2^16) scale.
3. **In parallel:** a Sonobe per-step latency spike (Path 3) — the ≤5 s gate decides whether
   folding is the better long-term substrate.
4. Keep Plonky2 in production until one path clears latency + (for Path 3) maturity.

The gate is **GO via Path 1+5** (channel empirically proven), with Path 3 as the
architecturally-cleanest alternative and Path 6 as the cheapest redesign — the operator
chooses among them. Probes D/G/H/J remain valid: they correctly bound the *high-level API /
stock-table* behavior; Probe Q identifies the supported construction they did not test.
