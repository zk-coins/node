# Migration Plan: Plonky2 → Plonky3

**Status:** proposed work plan — execution-ready task specification.
**Audience:** the engineer/agent executing the migration locally (Mac Studio M3 Ultra **or** M5 MacBook Pro, single host, no external CUDA).
**Authoritative companions:** `ROADMAP.md` §"Post-MVP Path: Plonky3", `MIGRATION_RESEARCH.md` §7.11/§7.12/§7.14/§7.21/§7.22, `SPEC.md` (implementation-agnostic protocol spec). This document is the *how*; those are the *why*.

---

## 0. How to use this document

1. **Read §1–§3 fully before touching code.** They define what must NOT change and how to work.
2. **Phase 0 (§5) is a HARD GATE.** Do not start Phase 1+ until Phase 0 passes its acceptance criteria. If Phase 0 hits an upstream gap, **STOP and report** — do not patch upstream, do not work around it silently.
3. Work **one phase = one feature branch = one draft PR against `staging`** (see §3). Finish and merge a phase before starting the next, unless explicitly parallelizable (noted per phase).
4. Every task lists: **files**, **acceptance**, **local verification command**. A task is done only when its local command is green.
5. When a task says "port", it means: reproduce identical protocol semantics on the Plonky3 backend — not redesign. `SPEC.md` is frozen for this migration.

---

## 1. Scope & non-negotiables

### What this migration IS
A backend swap of the proving system from **Plonky2 (Poseidon-Goldilocks)** to **Plonky3**, preserving 100% of protocol semantics defined in `SPEC.md`. New crates `program-plonky3` / `prover-plonky3` are built alongside the existing `program-plonky2` / `script-plonky2`, which are deleted only after parity is proven (§Phase 8).

### What MUST NOT change (verify against these at every phase)
- **On-chain format.** Bitcoin stores only a Schnorr inscription with txid prefix `4242`. The proof system is invisible on-chain. No change to inscription encoding.
- **Schnorr boundary (`SPEC.md` §5.4).** Wallet signs `SHA256(serialize(asth) ‖ serialize(ocr))`. secp256k1 stays off-circuit. The ONLY thing that may change here is the *byte serialization* of `asth`/`ocr` digests if the field changes (see Phase 7) — and that requires a coordinated `zk-coins/sdk` bump.
- **Protocol constants.** `MAX_IN_COINS = 8`, `MAX_OUT_COINS = 8`, `TREE_DEPTH = 256`, ProofData public-input semantics. (Their *encoding* into field elements may change with the field; their *meaning* does not.)
- **Account/coin model, SMT/MMR structure, ProofData layout** as specified in `SPEC.md`.
- **The 121 circuit tests** in `program-plonky2/src/**` define the behavioral contract. Their Plonky3 equivalents must assert the same protocol facts.

### Decision authority
Anything account-specific or protocol-visible: if unsure, it stays identical to `SPEC.md`. Implementation-internal choices (limb packing, gate selection, recursion topology): decide locally, document inline, do not escalate.

---

## 2. Field & hash sequencing decision (READ — this shapes the whole plan)

Two independent risk axes must be **decoupled**, both in the spike and in the real port:

- **Axis A — recursion/API:** Plonky3's circuit + recursion model is fundamentally different from Plonky2's (AIR-based, external `p3-recursion` lib). This is the load-bearing risk.
- **Axis B — field/hash:** Goldilocks (64-bit, 4-element digest, D=2) → KoalaBear/BabyBear (31-bit, 8-element digest, D=4/5). Mechanical but pervasive (limb packing, digest width).

**Mandated sequencing — do NOT collapse these:**

1. **Phase 0 spike in Goldilocks.** `p3-recursion` supports Goldilocks (`p3-goldilocks` is in its deps). Proving recursion works in *the same field you have today* isolates Axis A from Axis B. If recursion fails even in Goldilocks, the field choice is irrelevant and the whole migration is upstream-blocked.
2. **Phases 1–6 port in Goldilocks-on-Plonky3.** Minimal-diff: same field, same digest width, Poseidon2 instead of Poseidon, Plonky3 API instead of Plonky2 API. Get all tests green here first.
3. **Phase 9 (separate, optional follow-up) field swap to KoalaBear/BabyBear.** Only after Goldilocks-on-Plonky3 is fully green. This is where the small-field/Poseidon2 perf win and any future GPU path live. It is a focused, well-bounded change at that point, not entangled with the API port.

Rationale: every prior incident in `MIGRATION_RESEARCH.md` §7 came from entangling shape/field/recursion changes. Keep one variable moving at a time.

---

## 3. Working rules (apply to EVERY PR in this migration)

- **Language:** code, comments, commits, PR text in **English**. (Operator-facing chat may be German; the repo is English.)
- **No AI attribution** in commits or PRs (no footer, no `Co-Authored-By`).
- **Base branch: `staging`.** Per `CONTRIBUTING.md`: feature PRs target `staging`, never `develop`/`main` (both protected, auto-PR only).
- **All PRs are drafts** (`gh pr create --repo zk-coins/node --base staging --draft …`). Maintainer flips to ready.
- **Branch naming:** `feat/plonky3-<phase>-<slug>` (e.g. `feat/plonky3-p0-recursion-spike`).
- **No force-push**, even on side branches. Fixes are new commits.
- **Local green before push — in this order** (mirrors CI; never push on a local red):
  1. `cargo fmt --all -- --check`
  2. `cargo clippy --all-targets --all-features -- -D warnings`
  3. `cargo build --release`
  4. Tests for the touched crate(s) (see per-phase commands)
- **Per-PR review loop (3-subagent default):** implementer + quality-reviewer + logic-reviewer, loop until both report `PASS_CLEAN` AND PR CI is green; PR stays draft until then.
- **Coverage:** `develop` must stay 100% green. New Plonky3 code carries the same diff-coverage bar as the rest of the repo; the heavy gate runs `cargo llvm-cov nextest --release`.

---

## 4. Pre-flight (one-time local setup)

| Item | Command / value |
|---|---|
| Toolchain | nightly (pinned in `rust-toolchain`). `rustup toolchain install nightly` |
| Coverage tool | `cargo install cargo-llvm-cov cargo-nextest` |
| Postgres (node tests) | `docker run -d --name zkcoins-pg -e POSTGRES_USER=zkcoins -e POSTGRES_PASSWORD=zkpw -e POSTGRES_DB=zkcoins -p 5433:5432 postgres:16` then `export DATABASE_URL=postgres://zkcoins:zkpw@127.0.0.1:5433/zkcoins` |
| Baseline | On a clean checkout of `staging`: `cargo nextest run -p zkcoins-program-plonky2` → record pass count (expect 121) and wall time. This is the parity target. |
| Prove-time bench | `cargo run --release --bin probe_r2 -- --persist` → writes JSON under `scripts/bench/results/`. Record warm-prove p50 as the perf baseline. |

---

## 5. Phase 0 — Recursion Feasibility Spike  ⛔ HARD GATE

**Goal:** prove that `p3-recursion` can express the three composition patterns zkCoins depends on, **in Goldilocks**, using trivial AIRs (a counter circuit) — NOT the real state-transition circuit. This de-risks the whole migration before any real porting cost is spent.

**Crate:** new throwaway crate `spikes/plonky3-recursion-spike/` (excluded from the workspace's default members or added as a clearly-marked spike member). Not in the `program-plonky3` path.

**Dependencies (git-pin — `p3-recursion` is NOT on crates.io):**
```toml
[dependencies]
p3-recursion      = { git = "https://github.com/Plonky3/Plonky3-recursion", rev = "<PIN_HEAD_COMMIT>" }
p3-uni-stark      = { git = "https://github.com/Plonky3/Plonky3-recursion", rev = "<SAME_REV>" }
p3-batch-stark    = { git = "https://github.com/Plonky3/Plonky3-recursion", rev = "<SAME_REV>" }
p3-goldilocks     = { git = "https://github.com/Plonky3/Plonky3-recursion", rev = "<SAME_REV>" }
p3-circuit        = { git = "https://github.com/Plonky3/Plonky3-recursion", rev = "<SAME_REV>" }
p3-circuit-prover = { git = "https://github.com/Plonky3/Plonky3-recursion", rev = "<SAME_REV>" }
# Poseidon2 in-circuit: p3-poseidon2-circuit-air (same rev)
```
Resolve `<PIN_HEAD_COMMIT>` to the current `main` HEAD of `Plonky3/Plonky3-recursion` and pin it. Record the rev in the PR description. Never use a floating `branch`.

### The contract to reproduce (mapped from current code)

| Pattern | Current Plonky2 implementation | `p3-recursion` candidate API |
|---|---|---|
| **A — IVC / cyclic with base case** | `main.rs::common_data_for_recursion_c` + `conditionally_verify_cyclic_proof_or_dummy` (single fixed-point, NoopGate pad to `1<<12`) | `prove_next_layer` chain + `into_recursion_input::<BatchOnly>()` |
| **B — fan-in-8, variable active count** | `source_aggregator.rs`: 8× `conditionally_verify_proof`, dummy via `cyclic_base_proof`, per-slot `active` bit, `total_aggregator_pis = 236` | `build_aggregation_layer_circuit` (2-to-1 tree, depth 3) **or** `p3-batch-stark` |
| **C — vk + PI binding across layers** | outer `connect_hashes`-binds aggregator's claimed st-vk to its own cyclic vk; 20-element ProofData PIs propagated | expose inner vk/commitment as constrained PI in outer |

### Tasks

**P0-T1 — Spike crate skeleton + dependency resolution.**
Files: `spikes/plonky3-recursion-spike/{Cargo.toml,src/lib.rs}`.
Acceptance: crate compiles against the pinned `p3-recursion`; a trivial counter AIR (`next = cur + 1`) proves and verifies via `p3-uni-stark` over Goldilocks.
Verify: `cargo nextest run -p plonky3-recursion-spike base_air_round_trips`.

**P0-T2 — Probe A (IVC/cyclic with base case).**
Build a 3-layer chain: layer 0 = base (no predecessor), layer 1 verifies layer 0, layer 2 verifies layer 1, carrying a constrained counter PI from the base.
PASS: layer-2 proof verifies; counter PI = 2 provably threaded from base; per-layer proof shape/time is constant (true IVC, no growth).
FAIL: shape grows per layer, OR no way to express a base case without a predecessor proof (this is the `_or_dummy` equivalent — its absence is a hard blocker).
Verify: `cargo nextest run -p plonky3-recursion-spike probe_a_ivc`.

**P0-T3 — Probe B (fan-in-8, variable active count).**
Aggregate 8 leaf proofs into one, for k ∈ {0, 1, 8} real leaves with the rest padded/dummy; expose per-leaf PIs + an `active` bit.
PASS: aggregate verifies for all k; per-leaf PIs surface correctly; a fixed-shape padding mechanism exists (2-to-1 tree depth 3, or batch-stark with a validity flag).
FAIL: no "conditionally verify or dummy" primitive → variable count forces 8 real proofs (no padding), or batch-stark cannot verify N proofs of the *same* AIR with per-proof PIs. **This is the most likely blocker — probe it first after P0-T1.**
Verify: `cargo nextest run -p plonky3-recursion-spike probe_b_fanin`.

**P0-T4 — Probe C (vk/PI binding across layers).**
Expose the inner proof's vk/commitment as a PI in the outer and constrain it; feed a deliberately wrong-vk inner proof.
PASS: wrong-vk proof is rejected by the outer; correct-vk accepted.
FAIL: inner vk is not reachable as a constrainable PI → no `connect_hashes` equivalent.
Verify: `cargo nextest run -p plonky3-recursion-spike probe_c_vk_binding`.

**P0-T5 — Measure single-layer recursion cost on the local host.**
Record wall-clock prove time + peak RSS for one recursion layer (Probe A layer 1) on the executing machine (M3 Ultra and/or M5).
Acceptance: numbers written into the PR body and into `scripts/bench/results/plonky3-spike-<host>-<date>.md`.
Why: directly informs the ≤5 s / ≤1 s warm-prove budget (`CONTRIBUTING.md` §hardware) and whether any GPU path is even needed.

**P0-T6 — Go/No-Go memo.**
File: `MIGRATION_PLONKY3_SPIKE_RESULT.md` (new).
Contents: per-probe `supported / blocked / workaround` with code pointers; measured prove time + RSS; for any FAIL, a linked upstream issue in `Plonky3/Plonky3-recursion` (search the 18 open issues first); a revised effort estimate for Phases 1–8; recommended field decision for Phase 9.

### Phase 0 GATE criteria
- **GO:** Probes A, B, C all PASS (or have a documented in-repo workaround needing no upstream change). Proceed to Phase 1.
- **NO-GO (upstream-gated):** any probe blocked by a `p3-recursion` gap. STOP. Do not start Phase 1. File/link the upstream issue, set a re-check date, report to the operator. Do not patch or fork `p3-recursion` as part of this migration.

> **Recorded Phase 0 result (2026-06-06, see `MIGRATION_PLONKY3_SPIKE_RESULT.md`):**
> **CONDITIONAL GO.** All §5 PASS items were exercised empirically with real proving +
> positive/negative assertions (PI-threading binding, variable-active-count masking,
> vk-equality connect-back), plus the IVC fixed point and fan-in composition. Two
> findings are now *resolved into hard constraints before Phase 1*:
> 1. **Cross-layer PI threading — RESOLVED to Option 2 (mandatory).** The high-level
>    batch recursion does **not** propagate public inputs across layers
>    (`probe_d_multilayer_carry`: `air_public_targets = [0,0,0]`). Option 1 (carry the
>    value as an AIR public value) is **not achievable on this rev** — proven by
>    `probe_h_option1_air_public_values` (injecting a non-existent public input is
>    rejected) and `probe_g_fanin_pi_passthrough` (a real aggregation surfaces 0 per-leaf
>    values to the outer). So Option 2 (commit + hash/Merkle re-bind each layer) is the
>    **only feasible path** for both the `prev_account` IVC carry and the source-aggregator
>    per-leaf surfacing. Not a NO-GO (Option 2 is sound and expressible; the binding
>    primitives are proven), but no longer a free choice.
> 2. **Warm-prove budget at material risk.** A recursion layer over a real-sized
>    (~2^16-gate) inner proof is ≈3.2 s / ≈1.4 GB (`probe_i_cost_projection`); Option 2
>    adds per-layer hashing on top of the base prove (Plonky2 base is already 4.35 s).
>    The ≤5 s warm budget must be measured on the real circuit early in Phase 5.
> See the §6 Phase-1-authorize block and §10 P5-T1 / §10 budget note.

### Phase 0 abort/timebox
- Hard timebox: **5 working days.** This is a feasibility probe, not a port.
- Distinguish "holding it wrong" from "upstream gap": every FAIL must point to a concrete API location or an existing upstream issue.

---

## 6. Phase 1 — New crate skeleton

Prereq: Phase 0 = GO.

### Phase-1-authorize decision — cross-layer PI threading → RESOLVED: Option 2

This was an open choice (Option 1 AIR-public-values vs Option 2 commit+hash). **Phase 0
resolved it empirically: Option 2 is the only feasible path.** The high-level batch
recursion does **not** propagate public inputs across layers — a `CircuitBuilder`
circuit's public inputs live in the committed Public *table*, never as AIR public values:
- `probe_d_multilayer_carry`: verifying an inner batch proof exposes `air_public_targets = [0,0,0]`.
- `probe_h_option1_air_public_values`: the only other Option-1 avenue — injecting a
  non-empty `RecursionInput::BatchStark.table_public_inputs` — is **rejected** (you cannot
  claim a public input the proof does not structurally have).
- `probe_g_fanin_pi_passthrough`: a **real** 2-to-1 aggregation surfaces 0 per-leaf values
  to the outer.

**Decision (no longer free): Option 2 — commit the carried value(s) into each layer's
proof and re-bind them via an in-circuit hash/Merkle check on the next layer.** This
applies to BOTH the `prev_account`/ProofData IVC carry (P5-T1) AND the source-aggregator
per-leaf ProofData surfacing (P5-T2/T3). The threading/masking/vk *binding primitives*
are proven (`probe_d_pi_threading`, `probe_e_active_masking`, `probe_f_vk_binding`), so
Option 2 is construction, not a feasibility risk — but it adds gates per layer (see the
§10 budget note).

> **Option 3 (passive, still armed):** `probe_d_multilayer_carry` and
> `probe_h_option1_air_public_values` are pinned. A future `Plonky3-recursion` rev that
> propagates public inputs natively turns those assertions red — that would reopen the
> cheaper Option 1 and should trigger a re-evaluation here.

**P1-T1 — Create `program-plonky3` crate.**
Files: `program-plonky3/{Cargo.toml,src/lib.rs}`; add to workspace `members`.
Mirror `program-plonky2`'s module layout (`circuit/`, `merkle/`, `hash.rs`, `inputs.rs`, `types.rs`) as empty stubs.
Set the prelude: `F`, `C`, `D`, hash config — **Goldilocks + Poseidon2** (Plonky3), per §2 step 2.
Acceptance: a prelude smoke test (build trivial circuit, prove, verify) passes, mirroring `program-plonky2/src/lib.rs::prelude_round_trips_a_proof`.
Verify: `cargo nextest run -p zkcoins-program-plonky3 prelude_round_trips_a_proof`.

**P1-T2 — Create `prover-plonky3` crate.**
Files: `prover-plonky3/{Cargo.toml,src/lib.rs}` mirroring `script-plonky2` (subprocess `[[bin]]` boundary as documented in `script-plonky2/src/lib.rs`).
Acceptance: compiles; exposes the same prove-fn surface names as `script-plonky2` (initial / account_update / with_in_coins / …) as stubs returning `unimplemented!()`.
Verify: `cargo build -p zkcoins-prover-plonky3`.

---

## 7. Phase 2 — Field elements, hash, packing primitives

**P2-T1 — `types.rs` port.**
Port `HashDigest`, `Address`, `Amount`, `AssetId`, `AccountState`, `Coin`, `ProofData` to the Plonky3 field types.
Goldilocks-on-Plonky3 keeps the 4-element digest → minimal change vs `program-plonky2/src/types.rs`.
Acceptance: serialization round-trips byte-identically to the Plonky2 version for the same logical values (cross-check test against `program-plonky2`).
Verify: `cargo nextest run -p zkcoins-program-plonky3 types::`.

**P2-T2 — `hash.rs` port (Poseidon → Poseidon2).**
Port `hash_bytes`, `ZERO_HASH`, digest helpers to Poseidon2 over Goldilocks.
⚠️ `MIGRATION_RESEARCH.md` §7.1: guard the Poseidon zero-state collision in SMT defaults — re-verify the same defense holds under Poseidon2.
Acceptance: known-answer tests for the hash; SMT default-leaf collision test ported and green.
Verify: `cargo nextest run -p zkcoins-program-plonky3 hash::`.

**P2-T3 — `inputs.rs` port.**
Witness-input plumbing; align with Plonky3 witness generation.
Acceptance: input structs build the same logical witness as Plonky2.
Verify: `cargo nextest run -p zkcoins-program-plonky3 inputs::`.

---

## 8. Phase 3 — Merkle gadgets

**P3-T1 — Sparse Merkle Tree (`merkle/sparse_merkle_tree.rs`, 648 LOC).**
Port inclusion / non-inclusion / insert gadgets; keep `TREE_DEPTH = 256`.
⚠️ `MIGRATION_RESEARCH.md` §7.2 (variable vs fixed depth), §7.14 (path-compressed SMTs incompatible with cyclic recursion — keep fixed-depth), §7.15 (`select_hash` masking).
Acceptance: all SMT tests ported and green; non-inclusion + insert positive/negative cases preserved.
Verify: `cargo nextest run -p zkcoins-program-plonky3 sparse_merkle_tree`.

**P3-T2 — Merkle Mountain Range (`merkle/merkle_mountain_range.rs` + `circuit/mmr.rs`).**
Port MMR inclusion; ⚠️ §7.16 (`root_extended`/`extend_to` for fixed-depth verification). MMR is built off-circuit by the scanner — keep that boundary.
Acceptance: MMR tests ported and green.
Verify: `cargo nextest run -p zkcoins-program-plonky3 mmr`.

---

## 9. Phase 4 — State-transition circuit (single-proof, no recursion yet)

**P4-T1 — Port `circuit/main.rs` build path WITHOUT recursion** (3882 LOC; the non-recursive core first).
Reproduce: public-input layout (`N_PROOF_DATA_PUBLIC_INPUTS = 20`), in/out-coin slot logic (`MAX_IN_COINS`/`MAX_OUT_COINS = 8`), per-slot `active`-bit masking (§7.17), `account_state.hash` lifecycle (§7.19).
Explicitly EXCLUDE for now: `conditionally_verify_cyclic_proof_or_dummy`, aggregator verification, `add_verifier_data_public_inputs`.
Acceptance: `prove_initial` (no in-coins, no recursion) proves and verifies; ProofData PIs match the Plonky2 layout semantically.
Verify: `cargo nextest run -p zkcoins-program-plonky3 prove_initial`.

**P4-T2 — Port the remaining non-recursive prove entrypoints.**
`prove_initial_with_in_coins`, `prove_initial_with_in_and_out_coins`, the `prove_account_update*` non-source variants.
Acceptance: each ported entrypoint's tests green.
Verify: `cargo nextest run -p zkcoins-program-plonky3 prove_account_update`.

---

## 10. Phase 5 — Recursion + aggregator  (topology dictated by Phase 0 result)

This phase implements the patterns proven feasible in Phase 0. The concrete API choices follow the Go/No-Go memo (`MIGRATION_PLONKY3_SPIKE_RESULT.md`).

> ⚠️ **Phase-5 budget risk (measure FIRST, before building P5-T2/T3).** A recursion
> layer over a real-sized (~2^16-gate) inner proof is ≈3.2 s / ≈1.4 GB
> (`probe_i_cost_projection`) — and that is the **single-layer lower bound** on an
> *arithmetic* toy circuit. The mandatory Option-2 commit + hash/Merkle re-bind (below)
> **adds Poseidon gates per layer** on top, and the real state-transition constraints are
> Poseidon-heavy (the Plonky2 base prove is already 4.35 s). The ≤5 s warm-prove budget is
> at material risk. **Build a minimal real-circuit + Option-2 prototype and measure warm-
> prove p50 at the very start of Phase 5.** If it exceeds 5 s, apply design knobs (reduce
> `MAX_IN_COINS`, drop in-coin recursion, folding) before porting the full aggregator —
> never external hardware (`MIGRATION_RESEARCH.md §7.11`). A failed budget check here is a
> real NO-GO trigger to revisit the topology.

**P5-T1 — Cyclic/IVC for `prev_account`.**
Replace `conditionally_verify_cyclic_proof_or_dummy` + `common_data_for_recursion_c` with the Phase-0-proven IVC construction (`p3-recursion` layer chain). Preserve the base-case (first transition, no predecessor).
⚠️ **Cross-layer PI threading is RESOLVED to Option 2 (§6).** The high-level batch recursion does **not** auto-propagate public inputs across layers, and Option 1 (AIR public values) is empirically dead (`probe_h_option1_air_public_values`, `probe_g_fanin_pi_passthrough`). Therefore carry the `prev_account`/ProofData value by **committing it into each layer's proof and re-binding it via an in-circuit hash/Merkle check on the next layer** (Option 2). The threading binding primitive is proven (`probe_d_pi_threading`); do **not** assume native public-input propagation.
Acceptance: a 2-transition account history proves and verifies; the cyclic vk binding holds; per-transition proof shape constant; **the threaded `prev_account` value is provably carried across both transitions** via the Option-2 commit+re-bind.
Verify: `cargo nextest run -p zkcoins-program-plonky3 cyclic`.

**P5-T2 — Source aggregator (fan-in-8).**
Port `source_aggregator.rs` semantics: bundle up to `MAX_IN_COINS = 8` source proofs, expose per-slot ProofData (20) + `active` bit, total PIs = `8·21 + 4 + cap`. Use the Phase-0-proven fan-in approach (2-to-1 tree, depth 3 — `probe_b_fanin`).
⚠️ **Per-leaf ProofData does NOT auto-surface from the aggregation to the outer** (`probe_g_fanin_pi_passthrough`: aggregation output exposes 0 per-leaf values). Surface each slot's ProofData into the outer via the **same Option-2 commit+re-bind** as P5-T1 (commit the per-leaf ProofData, re-bind in the outer), then apply the per-slot `active`-bit masking (`probe_e_active_masking` proves the §7.17 masking primitive). Padding (inactive slots = cheap real proofs) is unchanged from the Plonky2 design.
⚠️ §7.21/§7.22: the Plonky2 single-`_or_dummy` limitation and the lazy-verifier-data connect-back were Plonky2-specific. Re-derive the equivalent fixed-point/binding under `p3-recursion`; do not copy the Plonky2 workaround blindly.
Acceptance: aggregator smoke (all-inactive) + one-active-slot-with-real-source tests ported and green.
Verify: `cargo nextest run -p zkcoins-program-plonky3 aggregator`.

**P5-T3 — Outer verifies aggregator + vk connect-back (Pattern C).**
Wire the outer state-transition to verify the aggregator proof once and bind the aggregator's claimed source-vk to the outer's own (Phase-0 Probe C construction).
Acceptance: a wrong-vk aggregator proof is rejected at outer verify; correct path proves end-to-end.
Verify: `cargo nextest run -p zkcoins-program-plonky3 prove_*_with_in_and_out_coins_and_sources`.

---

## 11. Phase 6 — Prover wiring + node integration

**P6-T1 — Implement `prover-plonky3` prove fns** (replace the Phase-1 stubs) calling the `program-plonky3` circuit.
Acceptance: subprocess prove boundary works; output `CoinProof` (bincode) deserializes node-side.
Verify: `cargo nextest run -p zkcoins-prover-plonky3`.

**P6-T2 — Rewire `node` to the Plonky3 prover** behind the existing call sites (`node/src/flow.rs`, `router.rs`, `account_node.rs`, `job_dispatcher.rs`).
Per `ROADMAP.md` R5: closed test environment → **replace, no dual-backend feature flag**. Delete the Plonky2 call path in this step (not a later cleanup).
Acceptance: node builds; all node tests green against the Plonky3 prover (needs Postgres, see §4).
Verify: `cargo llvm-cov nextest --release -p node -p shared --all-features --show-missing-lines`.

**P6-T3 — Proof-bytes storage note.**
`node/src/runtime.rs`/`db.rs`: proof blobs are large; the Plonky3 proof size differs. Verify storage assumptions still hold; adjust column/size comments only (no schema change unless a test fails).
Acceptance: persistence tests green.

---

## 12. Phase 7 — Serialization boundary + SDK coordination

Only relevant if the digest byte-encoding changes. In **Goldilocks-on-Plonky3 (Phases 1–8)** the 4×8-byte digest is unchanged → **no SDK change in this phase**. This phase becomes load-bearing only in Phase 9 (field swap).

**P7-T1 — Assert Schnorr-message bytes are byte-identical** to the Plonky2 build for the same logical `(asth, ocr)`.
Acceptance: a cross-backend test confirms `SHA256(serialize(asth)‖serialize(ocr))` is identical → wallet signatures remain valid, no `zk-coins/sdk` change needed.
Verify: `cargo nextest run -p shared commitment`.

(If Phase 9 changes the field: open a coordinated `zk-coins/sdk` PR bumping the `asth`/`ocr` serialization, merged in lockstep with the node change. Closed env, DEV+PRD only — no third-party integrators.)

---

## 13. Phase 8 — Parity, coverage, bench, decommission Plonky2

**P8-T1 — Test parity.** Every behavioral assertion from the 121 `program-plonky2` tests has a green `program-plonky3` equivalent.
Verify: `cargo nextest run -p zkcoins-program-plonky3` (count ≥ Plonky2 baseline).

**P8-T2 — Coverage gate.** Diff coverage meets the repo bar.
Verify: `cargo llvm-cov nextest --release -p node -p shared -p zkcoins-program-plonky3 --all-features --show-missing-lines`.

**P8-T3 — Perf bench.** Re-run `probe_r2`; compare warm-prove p50 vs the Plonky2 baseline recorded in §4. Write `scripts/bench/results/plonky3-vs-plonky2-<host>-<date>.md`.
Acceptance: numbers recorded (a regression is acceptable to report, not to hide — Goldilocks-on-Plonky3 may not beat tuned Plonky2 until Phase 9's small-field swap).

**P8-T4 — Decommission Plonky2.** Delete `program-plonky2/` and `script-plonky2/`; update `shared/Cargo.toml` dependency (`zkcoins-program` → `program-plonky3`); scrub stale references in docs (`SPEC.md`, `ROADMAP.md`, `CONTRIBUTING.md`, `README.md`).
Acceptance: workspace builds with no Plonky2 dependency; `grep -ri plonky2 --include=*.rs` returns nothing in source.
Verify: `cargo build --release && cargo nextest run`.

---

## 14. Phase 9 — (optional, separate decision) field swap to KoalaBear / BabyBear

Do NOT start until Phase 8 is merged and green. This is where the small-field + Poseidon2 perf win (and any future CUDA/GPU path) lives. Scoped follow-up:
- Swap `F` to KoalaBear (or BabyBear), `D` to 4/5, digest 4→8 elements.
- Rework `types.rs`/`hash.rs`/both Merkle modules for 8-element digests and new limb packing (`MIGRATION_RESEARCH.md` §7.4 canonical-reduction safety).
- Execute Phase 7's coordinated `zk-coins/sdk` serialization bump.
- Re-run Phases 7–8 acceptance.
Field choice (KoalaBear vs BabyBear vs Goldilocks-stay) is decided in the Phase-0 memo + Phase-8 bench, not here.

---

## 15. Whole-migration acceptance

- [ ] Phase 0 GO memo merged.
- [ ] All 121+ circuit behaviors green on Plonky3.
- [ ] All node/shared tests green on Plonky3 (Postgres-backed).
- [ ] Coverage gate green on `develop`.
- [ ] `probe_r2` bench recorded (Plonky3 vs Plonky2).
- [ ] No `plonky2` dependency remains in the workspace.
- [ ] On-chain inscription format unchanged; SDK signatures still valid (or SDK bumped in lockstep if Phase 9 ran).
- [ ] `MIGRATION_RESEARCH.md` foot-guns (§7.x) each re-checked under Plonky3 and noted.

## 16. Stop / escalate

- **Upstream gap in `p3-recursion`** (Phase 0 NO-GO, or a Phase-5 regression): STOP, link the upstream issue, report. Do not fork/patch upstream within this migration.
- **A protocol-visible change becomes necessary** (would alter `SPEC.md` semantics): STOP and escalate — out of scope for a backend swap.
- **Same reviewer objection unresolved after 2 attempts:** escalate to the operator.
