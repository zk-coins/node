# Probe U — end-to-end `/api/send` + `/api/mint` Plonky3 projection (M5 Max)

**Host:** Apple M5 Max, 128 GB. **Date:** 2026-06-06.
**Status:** PROJECTION, not a live measurement. See honesty boundary below.

## Honesty boundary — why this is a projection, not a live swap

The literal task ("port the HTTP handler prove-path, replace the prover, measure
end-to-end against Mutinynet") requires a **working ported Plonky3 prover wired into
the node service**. That prover does not exist — building it is migration Phases 1–8
(weeks; the real circuit is ~7800 LOC of Plonky2). There is nothing to plug into
`/api/send` yet. So Probe U **composes measured parts** into an honest end-to-end
estimate rather than faking a live number:

- **prove cost** = measured Probes T (single transition) + X (8+1 recursion/aggregation), under BabyBear + production crypto.
- **node overhead** (network, state read/write, SMT/MMR growth, Bitcoin broadcast, signing round-trip) = derived from the measured Plonky2 live-vs-prove gap.

## Measured inputs

| Quantity | Value | Source |
|---|---|---|
| Plonky2 warm full-prove (MAX_IN_COINS=8) p50 | 4.35 s | `probe_r2` (README baseline) |
| Plonky2 live `/api/send` populated p50 | ~10 s | README baseline |
| Plonky2 live `/api/mint` populated p50 | ~7 s | README baseline |
| ⇒ **node overhead (send)** = 10 − 4.35 | **≈ 5.6 s** | derived |
| Plonky3 single state-transition (Probe T, non-zk) | 0.31 s | `probe_t_real_circuit_bench` |
| Plonky3 recursion/aggregation 8+1 (Probe X, non-zk) | 4.0 s | `probe_x_aggregator_recursion` |
| Plonky3 recursion/aggregation 8+1 (Probe X, zk/hiding) | 6.7 s | `probe_x_aggregator_recursion` |

The node overhead is **prover-agnostic** (it's I/O + chain + crypto-signing, unchanged
by the proof backend), so it carries across unchanged.

## Projection

**`/api/send` (populated, 8 in-coins → recursion-heavy):**

| Backend | prove | + overhead | **e2e** | vs Plonky2 ~10 s |
|---|---:|---:|---:|---:|
| Plonky2 (today) | 4.35 s | 5.6 s | **~10 s** | 1× |
| Plonky3 non-zk | 0.31 + 4.0 = 4.3 s | 5.6 s | **~9.9 s** | ~wash |
| Plonky3 zk (hiding) | 0.31 + 6.7 = 7.0 s | 5.6 s | **~12.6 s** | **slower** |

**`/api/mint` (few/no source in-coins → recursion-LIGHT):** mint does not aggregate 8
source proofs, so the Probe-X aggregation cost mostly does not apply — the mint prove
is dominated by the single transition (Probe T class) plus at most the IVC predecessor
verify (1, not 8+1). Estimate the mint prove at ~0.3–1.5 s (T + one IVC verify) rather
than the full 4 s aggregation:

| Backend | prove (est.) | + overhead (~2.6 s) | **e2e** | vs Plonky2 ~7 s |
|---|---:|---:|---:|---:|
| Plonky2 (today) | ~4.4 s | 2.6 s | **~7 s** | 1× |
| Plonky3 non-zk | ~0.3–1.5 s | 2.6 s | **~3–4 s** | **~2× faster** |
| Plonky3 zk | ~0.5–2.5 s | 2.6 s | **~3–5 s** | faster |

(Mint overhead ≈ 7 − 4.4 ≈ 2.6 s; mint touches less state than send.)

## Honest verdict

- **`/api/send` is recursion-dominated → roughly a WASH (non-zk) or SLOWER (zk).** The
  per-transition 10–14× win (Probe T) is consumed by the 8-way in-circuit aggregation
  (Probe X). With the real Poseidon-heavy inner circuit (heavier than the carrier proxy),
  the full send likely tips **slower** than Plonky2.
- **`/api/mint` is recursion-light → likely ~2× faster.** This is a real e2e win.
- **Cold-start (Probe Y) is 38.7× faster** regardless of operation — no circuit-build.
- The user-facing headline latency (`/api/send`) is therefore **not improved by the
  migration today**; the wins are cold-start, memory, mint, and future-proofing.

## The decisive lever (future work)

Probe X used a **flat 8+1** in-circuit verification (sum of 9 verifier areas). The
single biggest recovery lever is **batching the 8 source-proof verifications into one
shared verifier table / one FRI instance** instead of 9 independent ones, and/or
reducing `MAX_IN_COINS`. If the aggregation cost can be cut ~3–4×, the full send flips
to a clear win. This is the highest-value next probe (call it Probe X′) and should be
run before committing to the migration on speed grounds. Other levers: KoalaBear,
dropping in-coin recursion, circuit-level hash reduction — never external hardware.

## Caveats
- Projection composes independent measurements; a real wired prover may differ (shared
  setup, witness-gen overlap). Treat ±20% as the band.
- The carrier proxy's inner proofs are lighter than the real circuit → Probe X is a
  **lower bound** on the real recursion cost → the send verdict is, if anything,
  optimistic.
