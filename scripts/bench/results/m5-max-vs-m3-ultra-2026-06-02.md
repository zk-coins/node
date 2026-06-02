# M5 Max vs M3 Ultra — Plonky2 prover wall times (2026-06-02)

First Apple M5 Max run of `probe_r2` against the same `git_sha`-era
binary the M3 Ultra baseline was taken on. Bench harness:
`probe_r2 --warm-calls 5` (Release profile, mimalloc, MAX_IN_COINS =
MAX_OUT_COINS = 8, INNER_PAD_BITS = 15).

## Hardware

| Field | dfxdev (M3 Ultra) | M5ME (M5 Max) |
|---|---|---|
| Chip | Apple M3 Ultra | Apple M5 Max |
| Cores | 28 (20 Performance + 8 Efficiency) | 18 (6 Super + 12 Performance) |
| Total RAM | 96 GB | 128 GB |
| OS | macOS | macOS 26.5.1 |
| Arch | aarch64 | aarch64 |

## Wall-time results (`probe_r2` — synthetic, no HTTP)

| Metric | M3 Ultra | M5 Max | Δ | Budget |
|---|---:|---:|---:|---:|
| `circuit_build_wall_ms` | 14 214 | **8 245** | **−42 %** | (no budget) |
| `prove_cold_wall_ms` | 7 012 | **6 129** | **−13 %** | — |
| cold start total (build + prove_cold) | 21 226 | **14 374** | **−32 %** | ≤ 30 000 |
| `prove_warm_p50_ms` (over 5 calls) | 4 777 | **4 350** | **−9 %** | ≤ 5 000 |
| `prove_warm_p90_ms` | 4 805 | **4 409** | **−8 %** | — |
| `prove_warm_p99_ms` | 4 805 | **4 409** | **−8 %** | — |
| `peak_rss_kb` | 4 111 648 | **3 937 504** | **−4 %** | ≤ 67 108 864 |
| `verify_wall_ms` | 3 | 2 | — | — |

All three R2 budgets pass on both machines. M5 Max is faster across
the board, with the biggest delta on the largely single-threaded
`circuit_build` (−42 %). On the parallelisable `prove_warm` sweep the
gap narrows to −9 % — the M3 Ultra's 28-core layout closes most of
the per-core speed gap when the workload is fully Rayon-bound.

## HTTP-level `/api/mint` sweep (M5 Max only)

10 sequential POSTs to `/api/mint` against the `zkcoins/node:beta`
image booted via
[`DFXServer/server/infrastructure/benchmarks/zkcoins-node/`](https://github.com/DFXServer/server/tree/develop/infrastructure/benchmarks/zkcoins-node)
on M5ME. Unfunded publisher → broadcast always returns 503; proof is
still generated end-to-end (the 503 lives downstream of the prover).
Empty initial state; each iteration grows the SMT by one entry.

| n | min | p50 | p90 | p99 | max | mean |
|---:|---:|---:|---:|---:|---:|---:|
| 10 | 6.611 s | **6.906 s** | 7.056 s | 7.111 s | 7.118 s | 6.879 s |

The HTTP-level mint wall-time on M5 Max is **~6.9 s**, of which
roughly 4.3 s is the warm prove call (from `probe_r2`) and ~2.5 s is
HTTP routing + SMT lookup + broadcast attempt to
`https://mutinynet.com/api`. The slight upward drift over the 10
iterations (6.61 → 7.12 s) is consistent with the growing SMT
witness; on a populated production state this overhead is expected
to be substantially higher (the dfxdev mint p50 ≈ 40 s baseline
captured 2026-05-30 reflects that fully-loaded state, not the
synthetic / empty-state numbers reported here).

## Files

* `m5me-2026-06-02-probe_r2.json` — full `probe_r2` JSON report
* `m5me-2026-06-02-http-mint-sweep.csv` — raw sweep CSV
* Both runs are also persisted into `r2_probe_runs` on the dfxdev
  zkCoins Postgres (host IDs 1 = dfxdev, 2 = M5ME).
