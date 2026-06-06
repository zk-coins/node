# Plonky3 Migration — Full Audit Summary (2026-06-06)

**Host:** Apple M5 Max, 128 GB. **Pins:** `Plonky3` @ `56952503…`, `Plonky3-recursion` @ `524665d…`.
**Scope:** 8 empirical probes (T, U, V, W, X, Y, Z, AA — all real proving except U, a labelled
projection) + 4 engineering docs (cutover, format, audit-spec, upstream). 28 spike tests green.

## The honest verdict in one table

| Dimension | Plonky2 (measured) | Plonky3 (measured/projected) | Verdict |
|---|---:|---:|---|
| Single state-transition warm prove | 4.35 s | **0.31 s** (T, production crypto) | **10–14× faster** ✅ |
| Recursion/aggregation 8+1 (in-circuit STARK-prove) | (included in 4.35 s) | **4.0 s** non-zk / **6.7 s** zk (X) | **dominates; erases the win** 🔴 |
| Full `/api/send` populated e2e | ~10 s | **~9.9 s** non-zk / ~12.6 s zk (U, projection) | **wash / slower** 🔴 |
| Full `/api/mint` populated e2e | ~7 s | **~3–5 s** (U, projection) | **~2× faster** ✅ |
| Cold start (build + first prove) | 14.4 s | **0.37 s** (Y) | **38.7× faster** ✅ |
| Circuit build | 8.2 s | **1.5 ms** (Y) | ~5600× ✅ |
| Peak RSS | 3.94 GB | 1–2.3 GB (T/X) | **~2× lighter** ✅ |
| Verify (native) | — | 9.6 ms; proof **1.76 MB** (Z) | proof size is a cost ⚠️ |
| 1000-prove soak | — | +2.7 % drift, no leak (AA) | **stable** ✅ |
| degree-7 vs degree-3 S-box | — | 1.66–1.69× (V) | estimate confirmed |
| true ZK (HidingFriPcs) vs proxy | — | 2.9–3.0× (W) | **zk-proxy was ~3× too fast** |

**Why the send is a wash:** the recursion verifier is hash-dominated (in-circuit FRI/Merkle),
and hashing benefits far less from BabyBear's small field than raw arithmetic. The
per-transition win (arithmetic-heavy) does not carry into the aggregation (hash-heavy).
Probe X is a **lower bound** (carrier-proxy inner proofs are lighter than the real circuit),
so the real send likely tips slower.

## Feasibility (unchanged GO)

The carrier-table-chain construction (Path 1+5) **works end-to-end**: cross-layer state
threading (probe_q/r), full 8+1 aggregation STARK-prove via the low-level
`prove_all_tables` path (probe_x — upstream **#436 is not a blocker** for this route),
mixed-degree multi-table `prove_batch` under HidingFriPcs (probe_t). Public-API-only, no fork.

## What the migration buys today — and what it doesn't

**Buys:** 38.7× cold-start (operational restarts, scaling, dev velocity), ~2× memory,
~2× faster mint, no-leak stability, an actively-developed backend (future GPU/perf),
and the carrier construction proven sound (audit spec: Doc 3).
**Does not buy:** a faster `/api/send` — the user-facing headline latency — under the
measured flat-8+1 aggregation. Costs: 1.76 MB proofs (vs Plonky2's ~100 KB class
`[VERIFY: exact Plonky2 proof size]`), an unaudited upstream in the TCB (Doc 4), and an
SDK/Schnorr-boundary change if BabyBear is chosen (Doc 2 — Goldilocks-on-Plonky3 avoids
the SDK change but forfeits most of the field-driven speed win).

## The decisive open lever — Probe X′ (recommended before any go/no-go on speed grounds)

Probe X measured a **flat 8+1** (nine independent in-circuit verifiers, costs summed).
The aggregation cost is the whole ballgame; the candidate reductions, in value order:
1. **Batch the 8 source verifications into one shared verifier table / one FRI instance**
   (amortise Merkle/FRI constraint work across slots).
2. **Reduce `MAX_IN_COINS`** (8 → 4 halves the dominant term; protocol-visible — operator call).
3. Cheaper inner-proof FRI profile (fewer queries on inner layers, full strength outer only).
4. ZK only on the outermost layer (inner layers non-hiding; cuts the 6.7 s zk figure toward 4 s)
   `[VERIFY: zk-soundness of non-hiding inner layers — auditor question, Doc 3]`.
5. KoalaBear; circuit-level hash reduction.
If X′ cuts aggregation ~3–4×, `/api/send` flips to a clear win and the migration's speed
case is restored.

## Operator decisions now on the table

1. **Field:** BabyBear (fast, needs SDK bump per Doc 2) vs Goldilocks-on-Plonky3 (no SDK
   change, much smaller speed win). The data favours BabyBear **iff** the send-side
   aggregation lever (X′) lands.
2. **Proceed/hold on the port (Phases 1–8):** the audit supports proceeding for
   cold-start/memory/mint/stability reasons alone, but if the justification is send
   latency, run Probe X′ first.
3. **MAX_IN_COINS:** any reduction is protocol-visible — explicit operator approval needed.

## Artefact index

- Probes: `spikes/plonky3-recursion-spike/tests/probe_{t,v,w,x,y,z,aa}_*.rs` (+ q/r/s and 17 earlier)
- Bench memos: `scripts/bench/results/plonky3-probe-{t,u}-*.md`, `plonky3-vs-plonky2-fair-*.md`
- Gate memo: `MIGRATION_PLONKY3_SPIKE_RESULT.md` (banner + §Fair Performance Comparison)
- Docs: `docs/migration/PLONKY3_{CUTOVER_PLAYBOOK,FORMAT_MIGRATION,CARRIER_TABLE_AUDIT_SPEC,UPSTREAM_MAINTENANCE}.md`
- Plan: `MIGRATION_PLONKY3.md` (PR #211); chosen direction + e2e proof: PR #214.

**Honesty boundary (applies to every number above):** Probes T/X/U use cost-faithful
representative workloads (right hash count, gate count, degree, commitment, fan-in) —
NOT the semantically-ported circuit (that is Phases 1–8). U is a composition of measured
parts, not a live wired service. Each artefact carries its own boundary statement.
