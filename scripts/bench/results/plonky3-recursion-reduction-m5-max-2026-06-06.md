# Plonky3 recursion-cost reduction — pre-port research (Probes AB/AC/AD/AE)

**Host:** Apple M5 Max, 128 GB. **Date:** 2026-06-06. **Field:** BabyBear (NEON-packed), 18 threads.
**Question:** the full-audit verdict left `/api/send` a **wash** (recursion-dominated, Probe X:
8+1 aggregation = 4.0 s). Can any lever pull it out — without starting the port?

## Answer: YES — staged by condition. The send-side speed case is recoverable.

| Config | Aggregation | Send-prove (T + agg) | vs Plonky2 4.35 s warm | e2e send vs ~10 s live | Condition |
|---|---:|---:|---:|---:|---|
| N=8, q=100 (today's protocol, full strength) | 3.94 s | 4.25 s | **wash (1.02×)** | wash | none |
| N=4, q=100 *(NOT pursued — UX regression rejected)* | 1.95 s | 2.26 s | 1.9× | 1.27× | protocol: MAX_IN_COINS 8→4 |
| **N=8, q=48 (RECOMMENDED — keep MAX_IN_COINS=8)** | 1.62 s | **1.93 s** | **2.25× faster** | **~1.3×** | auditor gate (port phase): 64-bit inner FRI |
| N=4, q=48 *(NOT pursued, Probe AE composed)* | 1.00 s | 1.31 s | 3.32× | 1.45× (6.91 s) | both above |
| N=1, q=48 (floor) | 0.40 s | 0.71 s | — | 1.58× (floor) | both + heavy UX cost |

The AE number is a real composed measurement (both proves back-to-back per timed iteration,
transition half TRUE ZK via HidingFriPcs; all proofs verified), not a sum of estimates
(batch-vs-sum delta < 5% — the two STARK stacks share no FRI work, so the sum is honest).

## Per-lever findings (each isolated empirically)

1. **cheaper-inner-FRI (Probe AB) — THE effective lever: 2.4×.** Inner-proof FRI queries drive
   the in-circuit Merkle-opening count ~linearly: q=100→48 gives 2.41× (inner soundness
   116→64 conjectured bits), q→30 gives 3.97× (46 bits — data point only, NOT deployable).
   `[VERIFY-1]` the recursion composition argument (full-strength outer dominating 64-bit
   inners) needs a cryptographer's sign-off before deployment (Doc 3 auditor checklist).
2. **MAX_IN_COINS sweep (Probe AC) — near-linear protocol lever.** ≈ 448 ms/source-coin over a
   ≈ 350 ms fixed base (IVC predecessor + NPO tables). 8→4 halves the aggregation. No
   soundness question — purely the protocol/UX decision `[VERIFY-2]`: sends cap at 4 in-coins
   (wallets consolidate first or split the send).
3. **Poseidon2 inner-MMCS (Probe AB) — already banked, zero headroom.** The Probe-X baseline
   ALREADY commits inner proofs with the field-native Poseidon2 MMCS; `verify_batch_circuit`
   is Poseidon2-only (a Keccak-MMCS inner proof cannot be verified in-circuit at all on this
   rev). The hoped-for "circuit-friendly hash" win was never lost.
4. **ZK-only-outer (Probe AB) — ≈ 0 ms.** Hiding-vs-non-hiding inner verification measures
   0.98–1.04× (within noise; +900 MB RSS for hiding inners). Adopt-or-not is free either way.
5. **KoalaBear (Probe AD) — ruled OUT, decisively.** Split result: transition 1.26× FASTER
   (native degree-3 S-box, narrower leaf table), but the dominant 8+1 aggregation **2.1×
   SLOWER** — its recursion-verifier Poseidon2 runs 20 partial rounds vs BabyBear's 13, and
   2-adicity 24 < 27. Both fields NEON-pack identically. **Stay on BabyBear.**

## The residual bound

Below ~1 s aggregation the e2e send is **dominated by the ≈ 5.6 s prover-agnostic node
overhead** (state/SMT, broadcast, signing round-trip — measured as live-minus-prove on
Plonky2). The circuit/protocol levers cannot touch it; the e2e floor is ≈ 6.3 s until the
node path itself is optimized (out of prover scope, separate workstream).

## Revised migration verdict — APPLIED RESOLUTIONS (supersedes the "wash" headline)

Decisions applied per the consistency heuristic (not open escalations):
- **MAX_IN_COINS: KEEP 8.** Reducing a user-facing feature for prove-time is inconsistent with
  the project (Plonky2-Prod runs 8; wallets/SDK calibrated to 8). N=4 rows above are measured
  data, NOT pursued.
- **RECOMMENDED config: N=8 + 64-bit inner FRI (q=48):** send-prove **1.93 s = 2.25× faster**,
  e2e **~7.5 s ≈ 1.3× faster** — recovery WITHOUT a UX regression. The 64-bit inner FRI is a
  **port-phase conditional gate** (queued auditor recursion-composition sign-off; consistent
  with Plonky2-Goldilocks's own 64-bit posture) — not a research blocker.
- **Field: BabyBear** (KoalaBear ruled out by AD; Goldilocks forfeits the field-driven win and
  only avoids the SDK bump, Doc 2).
- **Port (Phases 1–8): HOLD** — research-only mandate; no port started.

Tests: `probe_ab_recursion_friendly`, `probe_ac_max_in_coins_sweep`, `probe_ad_koalabear`,
`probe_ae_best_config` (33 spike tests green). Shapes are flat single-aggregator-layer —
a 2-to-1 tree costs strictly more, so all figures are conservative lower bounds. Probes are
cost-faithful proxies, not the semantic port (Phases 1–8); no port was started.
