# Plonky3 Carrier-Table-Chain — Cryptographic Audit Specification (Doc 3)

**Status:** Audit-ready specification of the *carrier-table IVC composition* used to
thread per-instance state across recursion layers in the zkCoins Plonky3 backend.
**Scope:** the composition mechanism only — see §6 (Non-goals). **Date:** 2026-06-06.

**Companion documents:**
- `MIGRATION_PLONKY3_SPIKE_RESULT.md` — Phase-0 gate memo (GO via Path 1+5).
- `MIGRATION_PLONKY3_SOLUTIONS_RESEARCH.md` — Path-1+5 rationale and 9-path analysis.
- `PLONKY3_UPSTREAM_MAINTENANCE.md` (Doc 4) — upstream pinning / TCB maintenance.
- `PLONKY3_CUTOVER_PLAYBOOK.md` (Doc 1) — cutover plan.

This document is written for an external cryptographic auditor. It defines the
construction precisely, gives a layered soundness argument, lists the explicit
security assumptions the auditor must accept or challenge, and provides a concrete
review checklist. Symbol names are real and refer to the upstream `Plonky3-recursion`
API and to the spike probes (`spikes/plonky3-recursion-spike/tests/`). Anything not
directly verifiable from the spike code is marked `[VERIFY: …]`.

---

## 0. Pinned trusted base

The construction rides on two pinned upstream revisions. They are **not** independent
choices: `Plonky3-recursion`'s workspace pins exactly the `Plonky3`-main rev below, and
the recursion crates share `p3-*` types with it.

| Repo | Rev | Role |
|---|---|---|
| `Plonky3/Plonky3-recursion` | `524665d0c2e1d294722c064786ae11dff8d9f33b` | carrier mechanism (`prove_batch` / `verify_batch_circuit`, PR #407 public values) |
| `Plonky3/Plonky3` | `56952503e1401a62982ceaf952c5e4a829b61803` | core `p3-*` (field, FRI, AIR, batch-STARK) that the recursion rev is built against |

The per-instance public-value channel that the whole construction depends on is
upstream **PR #407 ("feat: support public values", merged 2026-03-19)**, present in the
`Plonky3-recursion` rev `524665d`. (Note: PR #407 is a `Plonky3-recursion` PR resolved
in `524665d`; `56952503` is the companion `Plonky3`-main rev — the construction does not
depend on a Plonky3-main public-values PR.)

The construction deliberately uses the **low-level** `prove_batch` / `verify_batch_circuit`
API and **not** the high-level `build_and_prove_next_layer`, which is how it avoids
upstream issue **#436** ("Multi-Layer Recursion WitnessConflict at layer ≥2", closed
without MRE). The auditor should confirm the real ported chain stays on the low-level API
(see §5 checklist item C-9).

> **The pinned upstream `p3-recursion` / `p3` code is UNAUDITED and pre-1.0.** It is part
> of the Trusted Computing Base of this construction (§4). Doc 4 covers pin maintenance;
> this audit must treat the upstream prover/verifier/FRI/Poseidon2 code as either trusted
> or in-scope for a separate audit.

---

## 1. Construction definition

### 1.1 Notation

- `F` — the base field (BabyBear in the probes; the mechanism is field-generic).
- `E` — the challenge / cross-layer extension field over `F` (`Challenge`).
- A *carrier AIR* `C` is an `Air` with `num_public_values() = m` (m ≥ 1) whose public
  values are bound, by a first-row constraint, to committed trace cells.
- `V_N` — the carried state value emitted by layer `N` (in the probes a counter; in the
  real port the `prev_account` / ProofData digest, see §1.6).
- `π_N` — the batch-STARK proof of layer `N`'s carrier (`BatchProof`).
- `vk_N` — the verifier key (for a uni-stark / preprocessed AIR, the preprocessed
  commitment).

### 1.2 The carrier AIR

The canonical carrier in `probe_r_carrier_chain.rs` is `CarrierAir`:

- **Width:** 2 (trace columns `[v_in, v_out]`).
- **Public-value count:** `num_public_values() = 2` → public values `[v_in, v_out]`.
- **Constraints** (`Air::eval`, all gated by `when_first_row()`):
  1. `v_in  == public_values[0]`  — first-row bind of `pi_in` to committed cell `local[0]`.
  2. `v_out == public_values[1]`  — first-row bind of `pi_out` to committed cell `local[1]`.
  3. `v_out == v_in + 1`          — the state-transition relation (here: increment-by-one).

Generalized: constraint 3 is replaced by the real per-transition relation
`v_out == T(v_in, witness)` where `T` is the zkCoins state-update relation. Constraints 1
and 2 are the **public-value binding** — they pin each declared public value to a specific
committed trace cell, so the public value cannot float free of the proof's trace.

The minimal single-public-value variant is `PublicValueAir` in
`probe_q_custom_public_value.rs` (width 2, `num_public_values() = 1`, single first-row bind
`local[0] == public_values[0]`). It isolates the per-instance public-value channel without
the transition relation.

### 1.3 Proving a layer (`prove_batch`)

A layer is one `prove_batch` `BatchProof` of a single `StarkInstance` of the carrier:

```
instances     = [ StarkInstance { air: &C, trace, public_values: [v_in, v_out] } ]
prover_data   = ProverData::from_instances(&config, &instances)
π             = prove_batch(&config, &instances, &prover_data)
```

`verify_batch(&config, &[C], &π, &pvs, &prover_data.common)` is the native check. The
honest trace commits `(v, v+1)` on row 0; `public_values` is the *claimed* pair handed to
`prove_batch`/`verify_batch`. If the claimed pair disagrees with the committed cells, the
first-row bind (1)/(2) makes the constraint system unsatisfiable and `verify_batch`
rejects — this is the carrier-bind negative (Probe R NEGATIVE 2: claiming `v_out = v+999`
against a `(v, v+1)` trace fails at prove/verify time).

### 1.4 Verifying a layer in the next layer (`verify_batch_circuit`)

The next layer is a `p3-circuit` `CircuitBuilder` that verifies `π_N` in-circuit:

```
let vi = BatchStarkVerifierInputsBuilder::allocate(&mut cb, &π_N, common, &air_public_counts);
verify_batch_circuit(&config, &[C], &mut cb, &vi.proof_targets,
                     &vi.air_public_targets, &fri_params, &vi.common_data,
                     &lookup_gadget, Poseidon2Config::BABY_BEAR_D4_W16)?;
```

`air_public_counts = [m]` declares how many per-instance public values the inner carrier
emits. After `allocate`, the inner proof's public values surface as **constrainable
circuit targets**:

- `vi.air_public_targets.len() == 1` (one carrier instance),
- `vi.air_public_targets[0].len() == m` (the carrier's `m` public values — for the
  primitive tables this would be `[0,0,0]`; the carrier makes it non-empty).

For `CarrierAir`, `air_public_targets[0] = [ target(v_in), target(v_out) ]`. These targets
are bound by `verify_batch_circuit` to the inner committed trace via the same constraint
the inner proof carries (the first-row bind), so constraining a target is equivalent to
constraining the inner committed cell (§2b).

### 1.5 Chaining layers (`connect`)

The IVC link between layer `N` (`prev`) and layer `N+1` (`cur`) is a single circuit that:

1. verifies `prev`'s carrier in-circuit → surfaces `V_N = prev.air_public_targets[0][1]`
   (the inner `v_out`);
2. verifies `cur`'s carrier in-circuit → surfaces `v_in^{N+1} = cur.air_public_targets[0][0]`
   (the inner `v_in`);
3. **threads** them: `cb.connect(prev.air_public_targets[0][1], cur.air_public_targets[0][0])`.

`connect(a, b)` forces `a == b` in the witness (a DSU-style union of the two targets — see
§2c). Because each carrier internally enforces `v_out == v_in + 1` (constraint 3), chaining
links `0→1→2→3` proves `V_3 == V_0 + 3` with every intermediate value threaded through a
real proof's public-value channel. Probe R asserts the concrete carried value
(`V_3 == V_0 + 3`) and the forward linkage `pvs[k].v_out == pvs[k+1].v_in` for every link.

### 1.6 The real use (per-slot ProofData + active mask)

In the real zkCoins port the carried value is not a counter but the
`prev_account` / ProofData digest threaded across the account-update IVC chain, and the
relation `T` is the real state-update. The source aggregator surfaces per-slot ProofData
through the **same carrier channel** plus an `active`-bit mask (`MIGRATION_RESEARCH.md`
§7.17, exercised in `probe_e_active_masking.rs`): for each of `MAX_IN_COINS = 8` fixed
slots,

```
masked = cb.select(active, expected, claimed);   // §7.17
cb.connect(claimed, masked);
```

`active = 0` reduces to `connect(claimed, claimed)` (slot masked off; garbage accepted);
`active = 1` enforces `claimed == expected` (the per-slot check fires). The auditor must
verify the active-mask construction does not provide a bypass for *active* slots (§5,
C-6). The vk-equality connect-back (§1.7) plugs in alongside the mask in the aggregator.

### 1.7 vk binding (`connect`-back)

To prevent a wrong-circuit substitution (an inner proof that is internally valid against a
*different* verifier key), the outer circuit `connect`s the inner proof's verifier-key
targets (for a preprocessed/uni-stark AIR, the preprocessed-commitment targets,
`vi.preprocessed_commit.cap_targets`) to the expected `vk` value. This is the Plonky2
`connect_hashes` analogue. `probe_f_vk_binding.rs` proves it end-to-end: `proof_99` (valid
against `vk_99`) bound to `vk_42` is rejected purely by the `connect`, while an unbound
`proof_99` is accepted (control isolating the bind as the cause).

---

## 2. Soundness argument

**Core claim.** An accepting IVC link chain of depth `n` proves that the state relation
`T` held at every step (`V_{k} = T(V_{k-1}, ·)` for `1 ≤ k ≤ n`) and that the carried value
was genuinely threaded (`v_out` of layer `k` equals `v_in` of layer `k+1`), under the
security assumptions of §3.

The argument is layered (a)–(e).

### (a) Per-layer public-value binding

A carrier proof's public value is soundly bound to its committed trace by **two**
ingredients:

1. **The first-row AIR constraint.** `CarrierAir::eval` asserts `local[0] == public_values[0]`
   and `local[1] == public_values[1]` under `when_first_row()`. A satisfying assignment must
   therefore have the declared public values equal to the committed row-0 cells. There is no
   satisfying trace in which a public value differs from its bound cell.
2. **STARK/FRI soundness of `prove_batch`.** The committed cells are fixed by the
   trace-Merkle commitment in `π`, and the constraint system (including the first-row binds)
   is checked at the FRI-random out-of-domain point. An adversary who commits one trace but
   claims a different public value produces an unsatisfiable constraint system; `verify_batch`
   rejects it except with the FRI/STARK soundness error (Probe R NEGATIVE 2; upstream's own
   `test_batch_verifier_wrong_public_values` is `#[should_panic(WitnessConflict)]`).

**Assumption used:** FRI is sound at the chosen parameters, and the AIR constraint system is
both complete (honest carriers pass) and sound (the binds (1)/(2) and the relation (3) are
the *only* satisfying constraints — there is no under-constrained public value). The
auditor must independently confirm completeness/soundness of the *real* ported AIR (§5 C-1).

### (b) Cross-layer surfacing

`verify_batch_circuit` faithfully exposes the inner proof's public value as
`air_public_targets`. The mechanism (PR #407): the upstream batch verifier builds
`air_public_counts` from each non-primitive table's `public_values.len()`, and
`BatchStarkVerifierInputsBuilder::allocate` allocates exactly that many circuit public-input
targets as `air_public_targets`. Inside `verify_batch_circuit`, the recursive constraint
folder evaluates the inner AIR's constraints — including the first-row bind — over these
targets. Therefore an outer constraint placed on `air_public_targets[i][j]` is equivalent to
a constraint on the inner committed cell that (a) binds: the surfaced target *is* the inner
public value, which *is* the inner committed cell. Probe Q proves this directly
(`air_public_targets[0].len() == 1`; claiming `42` verifies, `999` is rejected); Probe R
re-confirms it at `m = 2`.

**Assumption used:** the upstream `verify_batch_circuit` recursive verifier is a faithful
in-circuit re-encoding of the native `verify_batch` (this is the unaudited-TCB assumption,
§3/§4). If upstream's recursive folder diverged from the native folder on public values, the
surfacing could be unsound; the auditor must treat upstream verification logic as
trusted-or-audited.

### (c) Threading

`connect(prev.v_out, cur.v_in)` forces continuity. In `p3-circuit`, `connect(a, b)` unions
the two targets in a disjoint-set structure and requires them to carry equal witness values;
a witness that assigns them different values is rejected at run time with `WitnessConflict`.
A wrong forwarded value is therefore unsatisfiable: Probe R NEGATIVE 1 builds a
*valid-but-wrong-successor* carrier (honest `(v0+5, v0+6)`) and links it after layer 0
(which emitted `v0`); the link fails because `connect(v0, v0+5)` is a witness conflict. The
**control** — running the identical mismatched pair *without* the `connect` — is accepted,
proving the rejection is purely the IVC thread bind and not an unrelated artifact.

**Assumption used:** `connect`'s equality is enforced (DSU union is sound) — part of the
`p3-circuit` TCB.

### (d) Base case + induction (IVC)

- **Base case.** Layer 0 is a real carrier proof whose `v_in` has *no* predecessor to bind
  against; it commits `[V_0 - 1, V_0]` and only its `v_out = V_0` is consumed downstream.
  The base case is established by the carrier proof itself (no `_or_dummy` primitive is used;
  `p3-recursion` has none — see the gate memo).
- **Inductive step.** Given an accepting link `k → k+1`, (a) binds `V_k` and `v_in^{k+1}` to
  their respective proofs, (b) surfaces them, (c) forces `V_k == v_in^{k+1}`, and the carrier
  relation forces `v_out^{k+1} == T(v_in^{k+1}, ·)`. By induction over `0 → 1 → … → n`, the
  relation held at every step and the value threaded continuously.
- **Fixed-shape requirement.** IVC soundness requires a **constant proof shape per layer**
  (every link circuit has the same shape so the verifier key is stable). The spike confirms
  the fixed point (`probe_a_ivc`: witness counts reach a constant `107957`; `probe_m`: depth
  50 holds the constant shape with flat RSS). The real port must hold this fixed point; a
  shape that drifts per layer would break the inductive vk stability (§5 C-8).

### (e) vk binding

The verifier-key equality `connect`-back (§1.7) prevents a wrong-circuit substitution. Each
link constrains the inner proof's vk targets to the expected circuit's vk. An adversary
supplying a proof of a *different* circuit (internally valid against its own vk) is rejected
by the vk `connect`, even though the inner STARK verification passes. `probe_f_vk_binding`
proves exactly this (reject `proof_99` bound to `vk_42`; control accepts it unbound).
Without this bind, the inductive step (d) would only prove "*some* accepting carrier exists",
not "the *intended* carrier circuit ran".

---

## 3. Security assumptions (explicit — accept or challenge)

An auditor must accept (or challenge) each of the following. These are the assumptions on
which the §2 soundness argument rests.

1. **FRI / STARK soundness at the production FRI parameters.** The carried-value binding and
   every in-circuit verification reduce to FRI soundness. The production parameters (blowup,
   query count, proof-of-work grinding bits, final-poly length) must give the target security
   level. **The spike probes do NOT use production FRI params** — they use
   `FriVerifierParams::unsafe_arithmetic_only_for_tests(...)` fed by `test_fri_scalars()`
   (`log_blowup`, `commit_pow_bits = 0`, `query_pow_bits`, etc.), at `security_level = 100`
   `[VERIFY: the production target is 100-bit conjectured FRI security; confirm the intended
   target and that production params meet it]`. The proxy-vs-production FRI gap is itself an
   audit item (§5 C-4). Note the standard caveat: FRI's *provable* soundness is weaker than
   its *conjectured* soundness; state which is being relied upon.

2. **Small-field soundness margin (BabyBear + extension).** BabyBear is a ~31-bit prime
   field. Per-query / per-challenge soundness error is governed by the size of the field over
   which challenges are drawn — the **challenge extension field `E`**, not the 31-bit base
   field. The construction draws challenges and surfaces the cross-layer value over `E`
   `[VERIFY: the recursion config uses extension degree d for challenges — the spike sets
   `.for_extension_degree::<2>()` in one path; confirm the production extension degree and
   that |E| = |F|^d ≈ 2^(31·d) gives an adequate per-challenge soundness margin, e.g. d ≥ 4
   for a comfortable margin, with enough FRI queries to reach the target bits]`. **This is one
   of the most load-bearing assumptions** — a too-small extension degree silently erodes the
   per-challenge soundness and the whole chain's security with it.

3. **Collision-resistance of the Merkle / sponge hash.** Trace and FRI commitments are Merkle
   trees over a hash. The production hash is **Keccak** (`PaddingFreeSponge<KeccakF, 25, 17, 4>`
   in the production-config probes V/W); the in-circuit Poseidon2 path uses
   `Poseidon2Config::BABY_BEAR_D4_W16`. Collision-resistance of the committed hash is assumed;
   a collision would let an adversary equivocate on a committed trace cell and break (a).

4. **Degree-7 cryptographic S-box (must ship).** The Poseidon2 permutation securing the
   commitments must use the **cryptographic round counts and the degree-7 S-box (`x^7`)** —
   `VectorizedPoseidon2Air` with `SBOX_DEGREE = 7`, `SBOX_REGISTERS = 1`, and the real
   BabyBear constants (`BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16 = 13`, full rounds per
   `BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS`), as measured in `probe_v_degree7_bench`. **A
   degree-3 S-box (`x^3`) is NOT cryptographically safe and MUST NOT ship** — Probe S used
   degree-3 only as a benchmarking proxy and explicitly understated cost. The auditor must
   confirm the production config is degree-7 with cryptographic round counts (§5 C-10), and
   that the hiding/ZK FRI (`HidingFriPcs`, Probe W) is enabled where ZK is required.

5. **Unaudited upstream in the TCB.** `p3-recursion` and `p3` (the pinned revs in §0) are
   **unaudited and pre-1.0**. The native `prove_batch`/`verify_batch`, the recursive
   `verify_batch_circuit`, the FRI prover/verifier, the Poseidon2 gadget, and the `p3-circuit`
   `connect`/DSU machinery are all in the TCB. The auditor must either trust this code or audit
   it as part of this engagement; a pin bump (Doc 4) is a re-audit trigger.

---

## 4. Trusted Computing Base

The soundness of the construction depends on, and only on:

1. The **carrier AIR** definitions (the ported `T` relation + first-row binds) — *in scope
   for this audit*, but the per-transition business relation `T` is a **separate** audit
   scope (§6).
2. The **link-circuit construction** (which targets are `connect`ed, the active mask, the vk
   bind) — *in scope*.
3. **Upstream `p3-recursion` / `p3`** at the pinned revs (native + recursive verifier, FRI,
   Poseidon2, `p3-circuit`) — **unaudited; trusted or separately audited** (§3.5, Doc 4).
4. The **FRI / field / hash parameters** chosen for production (§3.1–§3.4).

A defect in any of these can break soundness. Items 1–2 are the zkCoins-authored surface;
items 3–4 are the upstream/parameter surface.

---

## 5. What the auditor should check (checklist)

- **C-1 — AIR constraint completeness (no under-constrained public value).** For the real
  ported carrier(s), confirm every declared public value is bound by a first-row (or
  otherwise sound) constraint to a *specific* committed cell, that the bind is on the **right**
  cell (carried value, not an adjacent column), and that the transition relation `T` is fully
  constrained (no free witness that lets `v_out` take an unintended value). The probes bind
  `local[0]/local[1]`; the real AIR must be re-checked.
- **C-2 — carrier-bind soundness.** Confirm a carrier cannot declare a public value its trace
  did not commit (Probe R NEGATIVE 2 in the real AIR): claiming a wrong public value must fail
  at `prove_batch`/`verify_batch`.
- **C-3 — `connect` continuity (no discontinuous value).** Confirm there is no satisfying
  witness for a link with `prev.v_out != cur.v_in` (Probe R NEGATIVE 1 + control). Verify the
  `connect` targets the correct indices (`[0][1]` ↔ `[0][0]`) in the real wiring.
- **C-4 — FRI parameter soundness margin.** Re-derive the security bits from the production
  blowup / queries / PoW bits / final-poly length; confirm they meet the target and that the
  spike's `unsafe_arithmetic_only_for_tests` params are NOT used in production.
- **C-5 — field / extension soundness.** Confirm |E| (extension degree × |BabyBear|) gives an
  adequate per-challenge soundness margin for the chain depth and query count (§3.2). This is
  the small-field item — scrutinize it.
- **C-6 — active-mask bypass.** In the aggregator, confirm `select(active, expected, claimed)`
  + `connect(claimed, masked)` has **no aliasing path** that lets an *active* slot pass with a
  wrong value, no way to forge the `active` bit (it is asserted boolean,
  `cb.assert_bool(active)`), and that masking an inactive slot cannot leak into an active
  binding.
- **C-7 — Fiat–Shamir transcript binding.** Confirm the challenger **absorbs all public
  values** (and the vk / commitments) before deriving challenges, so the surfaced public value
  is bound into the transcript and cannot be chosen after the challenges. Check serialization
  is transcript-stable (`probe_p_serialization`: byte-stable bincode round-trip, truncated blob
  rejected).
- **C-8 — fixed proof shape.** Confirm the link circuit reaches a constant shape / fixed point
  across the chain (vk stable per layer); a per-layer shape drift breaks induction (§2d).
- **C-9 — low-level API / issue #436.** Confirm the real chain uses `prove_batch` /
  `verify_batch_circuit` (not `build_and_prove_next_layer`) and does not regress into upstream
  issue #436 at depth ≥ 2.
- **C-10 — degree-7 + hiding in production.** Confirm the shipped permutation is degree-7 with
  cryptographic round counts and that ZK is provided by `HidingFriPcs` where required (§3.4).
- **C-11 — proxy-vs-real gap.** Probes T/Q/R use **representative** carrier AIRs (counter /
  single value). The real ported circuit's constraints (balance conservation, nullifiers, the
  full state-update `T`) are **NOT** exercised by these probes and must be audited separately
  (§6). The composition mechanism is what the probes establish; the per-transition logic is not.
- **C-12 — vk binding present at every hop.** Confirm the vk-equality `connect`-back (§1.7) is
  wired at every IVC link and aggregator leaf, not just the first (otherwise a wrong-circuit
  proof could be substituted at an unguarded hop).

---

## 6. Known limitations / non-goals

- **This spec covers the carrier-chain *composition* only.** It does **not** audit the
  per-transition business logic: balance conservation, nullifier uniqueness, ownership /
  signature checks, the Merkle-membership of accounts, or the concrete state-update relation
  `T`. Those are a **separate audit scope** against the real ported circuit and `SPEC.md`.
- **The probes prove the mechanism, not the full circuit.** `probe_q` / `probe_r` use a
  counter (`v_out == v_in + 1`) as a stand-in for the real `T`; `probe_e` uses synthetic slot
  values. A green probe demonstrates that *a* value is soundly threaded and masked — it does
  not certify that the real `T` is correctly or completely constrained (that is C-1 / C-11 /
  §6 separate scope).
- **Upstream is trusted-or-separately-audited** (§3.5, §4). This document does not audit the
  `p3-recursion` / `p3` internals; it states where they enter the TCB.
- **Performance is out of scope here** but gates feasibility (see the gate memo: degree-7 +
  hiding FRI is ~5× over the optimistic proxy; promising at the real hash count, not a
  guaranteed win at full circuit size — tracked by Probe T). Performance does not affect
  soundness.

---

## 7. Summary for the auditor

The carrier-table chain threads a per-instance value across recursion layers by (i) emitting
it as an AIR **public value** bound to a committed trace cell (first-row constraint), (ii)
surfacing it across a batch layer as a constrainable `air_public_target` via
`verify_batch_circuit` (PR #407), and (iii) `connect`-ing successive layers' carried values
to force continuity, with a per-hop **vk** `connect`-back to pin the circuit identity. The
probes establish each link of this argument with positive + negative + control assertions
and real proving (no mocks). The soundness of the *mechanism* follows from FRI/STARK
soundness, the small-field/extension margin, hash collision-resistance, the degree-7
cryptographic permutation, and the correctness of the unaudited upstream verifier — the five
assumptions of §3, of which the **small-field/extension soundness margin** and the
**unaudited upstream in the TCB** are the two the auditor should scrutinize hardest.
