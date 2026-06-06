# Plonky3 Migration — Full Audit Summary (2026-06-06)

**Host:** Apple M5 Max, 128 GB. **Pins:** `Plonky3` @ `56952503…`, `Plonky3-recursion` @ `524665d…`.
**Scope:** 13 empirical probes (T, U, V, W, X, X′, Y, Z, AA + recursion-reduction AB/AC/AD/AE —
all real proving except U, a labelled projection) + 5 engineering docs. **33 spike tests green.**

> **HEADLINE + APPLIED RESOLUTIONS.** Three design decisions are resolved here (heuristic:
> the variant most consistent with the existing project), not left open:
> 1. **Field = BabyBear** (KoalaBear ruled out by AD).
> 2. **MAX_IN_COINS stays 8** — reducing a user-facing feature for prove-time is NOT consistent
>    with the project (Plonky2-Prod runs 8; all wallets/SDK are calibrated to 8; a UX regression
>    for speed is not professional). The N=4 lever is therefore **not pursued**.
> 3. **Port (Phases 1–8) = HOLD** — this engagement is research-only by mandate; no port started.
>
> With MAX_IN_COINS kept at 8, the recommended config is **N=8 + 64-bit inner FRI**: `/api/send`
> send-prove **1.93 s = 2.25× faster** than Plonky2 (4.35 s), e2e **~7.5 s ≈ 1.3× faster** than
> the ~10 s live. The 64-bit inner FRI is a **port-phase conditional gate** (queued auditor
> recursion-composition sign-off — consistent with Plonky2-Goldilocks's own 64-bit posture);
> in research mode it is not a blocker. So the wash recovers **without any UX regression**.

## The honest verdict in one table

| Dimension | Plonky2 (measured) | Plonky3 (measured/projected) | Verdict |
|---|---:|---:|---|
| Single state-transition warm prove | 4.35 s | **0.31 s** (T, production crypto) | **10–14× faster** ✅ |
| Recursion/aggregation 8+1, q=100 (in-circuit STARK-prove) | (included in 4.35 s) | **4.0 s** non-zk (X) | dominates 🔴 |
| `/api/send` prove, **N=8 q=100** (today, no change) | 4.35 s | **4.25 s** | wash 🟡 |
| `/api/send` prove, **N=8 q=48** (RECOMMENDED — keep 8 + 64-bit inner) | 4.35 s | **1.93 s** | **2.25× faster** ✅ |
| `/api/send` **e2e** (recommended config) | ~10 s | **~7.5 s** | **~1.3× faster** ✅ |
| *(N=4 q=48 = 1.31 s / 3.32× — NOT pursued: rejects MAX_IN_COINS=8→4 UX regression)* | | | |
| Full `/api/mint` populated e2e | ~7 s | **~3–5 s** (U, projection) | **~2× faster** ✅ |
| Cold start (build + first prove) | 14.4 s | **0.37 s** (Y) | **38.7× faster** ✅ |
| Circuit build | 8.2 s | **1.5 ms** (Y) | ~5600× ✅ |
| Peak RSS | 3.94 GB | 0.7–2.3 GB | **~2× lighter** ✅ |
| Verify (native) | — | 9.6 ms; proof **1.76 MB** (Z) | proof size is a cost ⚠️ |
| 1000-prove soak | — | +2.7 % drift, no leak (AA) | **stable** ✅ |
| Field: KoalaBear vs BabyBear | — | aggregation 2.1× slower (AD) | **stay BabyBear** |

**Why the send was a wash — and how it recovers (without a UX regression):** the recursion
verifier is hash-dominated (in-circuit FRI/Merkle), so the per-transition small-field win
doesn't carry. The applied fix shrinks the recursion work via **fewer inner FRI queries**
(q=100→48 = 2.4×, inner soundness 116→64 bits, a port-phase auditor gate) while **keeping
MAX_IN_COINS=8** (the N=4 slot-reduction lever is rejected — it would degrade user UX for
speed). That alone lifts `/api/send` from wash to **2.25× faster prove / ~1.3× e2e**. Probe X is
a **lower bound** (carrier-proxy inner proofs are lighter than the real circuit), so
real-circuit figures may be higher; the recommended config should be re-measured on the ported
circuit during Phase 5.

## Feasibility (unchanged GO)

The carrier-table-chain construction (Path 1+5) **works end-to-end**: cross-layer state
threading (probe_q/r), full 8+1 aggregation STARK-prove via the low-level
`prove_all_tables` path (probe_x — upstream **#436 is not a blocker** for this route),
mixed-degree multi-table `prove_batch` under HidingFriPcs (probe_t). Public-API-only, no fork.

## What the migration buys today — and what it doesn't

**Buys:** 38.7× cold-start (operational restarts, scaling, dev velocity), ~2× memory,
~2× faster mint, no-leak stability, an actively-developed backend (future GPU/perf),
and the carrier construction proven sound (audit spec: Doc 3).
**Buys (with the applied resolutions — keep MAX_IN_COINS=8, 64-bit inner FRI as a port-phase
gate):** a faster `/api/send` — **2.25× prove / ~1.3× e2e**, with NO UX regression. (The richer
3.32× tier would need MAX_IN_COINS=4, which is rejected.) At today's protocol fully unchanged
(q=100) it stays a wash. Costs: 1.76 MB proofs (vs Plonky2's ~100 KB class `[VERIFY: exact
Plonky2 proof size]`), an unaudited upstream in the TCB (Doc 4), and an SDK/Schnorr-boundary
change for BabyBear (Doc 2 — Goldilocks-on-Plonky3 avoids the SDK change but forfeits most of
the field-driven speed win; KoalaBear ruled out by Probe AD).

## The lever analysis — RESOLVED (Probes X′, AB, AC, AD, AE)

Full detail: `scripts/bench/results/plonky3-recursion-reduction-m5-max-2026-06-06.md`.
- **Same-vk batching (X′) — DEAD.** Independent source proofs can't share the in-circuit FRI
  verifier (1.00–1.01× vs flat); the 4.1× co-proving floor is protocol-unreachable.
- **Circuit-friendly inner hash (AB) — already banked.** The baseline already uses Poseidon2
  inner-MMCS; `verify_batch_circuit` is Poseidon2-only. Zero headroom (it was never lost).
- **ZK-only-outer (AB) — ≈ 0 ms.** Hiding vs non-hiding inner verification is within noise.
- **Cheaper inner FRI (AB) — REAL, 2.4×.** q=100→48 (inner 116→64 bits). `[VERIFY-1]`: needs a
  recursion-composition soundness argument (full-strength outer dominating 64-bit inners).
- **MAX_IN_COINS (AC) — REAL, near-linear (~448 ms/coin).** 8→4 ≈ halves aggregation, no
  soundness question. `[VERIFY-2]`: protocol-visible (sends cap at 4 in-coins).
- **KoalaBear (AD) — RULED OUT.** Transition 1.26× faster but the dominant aggregation 2.1×
  slower (20 vs 13 partial rounds in the recursion verifier). **Stay BabyBear.**
- **Composed best config (AE):** MAX_IN_COINS=4 + q=48 → send-prove **1.31 s (3.32× faster)**,
  e2e **6.91 s (1.45×)**. Residual e2e floor = the **~5.6 s prover-agnostic node overhead**
  (out of prover scope — a separate optimization workstream).

**Conclusion: the send-side speed case IS recoverable WITHOUT a UX regression** — via the
64-bit inner-FRI lever alone (2.25× prove / ~1.3× e2e), keeping MAX_IN_COINS=8. The earlier
"wash" holds only at today's fully-unchanged protocol (q=100).

## Applied resolutions (heuristic: most consistent with the existing project)

These are **decided**, not open escalations:

1. **Field: BabyBear** — KoalaBear ruled out by AD (aggregation 2.1× slower). Goldilocks-on-Plonky3
   avoids the SDK bump but forfeits the win. BabyBear needs a coordinated `zk-coins/sdk`/Schnorr
   bump (Doc 2); on-chain `4242` format is unaffected.
2. **MAX_IN_COINS: KEEP 8** — reducing a user-facing feature for prove-time is inconsistent with
   the project (Plonky2-Prod runs 8; wallets/SDK calibrated to 8). The N=4 lever (3.32×) is **not
   pursued**; a speed-for-UX trade is not professional here.
3. **64-bit inner FRI: conditional gate, queued to the port phase.** It needs a cryptographer's
   recursion-composition sign-off (`[VERIFY-1]`, Doc 3 auditor checklist) — but it is consistent
   with Plonky2-Goldilocks's own 64-bit security posture, so it is the recommended target, gated
   on that sign-off at port time. In research mode it is **not a blocker**.
4. **Port (Phases 1–8): HOLD.** This engagement is research-only by explicit mandate ("we don't
   start a migration, only research"). No port was started; HOLD is the only consistent answer.
   When/if a port is authorized later, it proceeds on the operational wins
   (cold-start/memory/mint/stability) plus the no-UX-regression 2.25× send-prove win, with the
   64-bit inner-FRI sign-off as its first gate.

## Artefact index

- Probes: `spikes/plonky3-recursion-spike/tests/probe_{t,v,w,x,y,z,aa,ab,ac,ad,ae}*.rs` (+ q/r/s/x_prime and 17 earlier; 33 tests green)
- Bench memos: `scripts/bench/results/plonky3-probe-{t,u}-*.md`, `plonky3-vs-plonky2-fair-*.md`, `plonky3-recursion-reduction-*.md`
- Gate memo: `MIGRATION_PLONKY3_SPIKE_RESULT.md` (banner + §Fair Performance Comparison)
- Docs: `docs/migration/PLONKY3_{CUTOVER_PLAYBOOK,FORMAT_MIGRATION,CARRIER_TABLE_AUDIT_SPEC,UPSTREAM_MAINTENANCE}.md`
- Plan: `MIGRATION_PLONKY3.md` (PR #211); chosen direction + e2e proof: PR #214.

**Honesty boundary (applies to every number above):** Probes T/X/U use cost-faithful
representative workloads (right hash count, gate count, degree, commitment, fan-in) —
NOT the semantically-ported circuit (that is Phases 1–8). U is a composition of measured
parts, not a live wired service. Each artefact carries its own boundary statement.
