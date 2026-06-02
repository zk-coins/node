# Bench Results

Wall-time per proof type per hardware target.

## Results

All times are p50 unless noted. `—` = not measured on that device.
Synthetic = `probe_r2` binary (lower bound, no HTTP/scanner/broadcast).
Live = real `/api/mint` and `/api/send` HTTP round-trips.

| Proof phase | Apple M3 Ultra | Apple M5 Max | Δ |
|---|---:|---:|---:|
| Circuit build (cold, mostly single-threaded) | 14.2 s | **8.2 s** | **−42 %** |
| First prove (cold, includes Rayon spin-up) | 7.0 s | **6.1 s** | **−13 %** |
| **Warm prove** (synthetic, steady state) — **p50** | 4.78 s | **4.35 s** | **−9 %** |
| Warm prove (synthetic) — p90 | 4.81 s | 4.41 s | −8 % |
| `/api/mint` HTTP, empty state, 1 recipient — p50 | — | 6.91 s | — |
| `/api/mint` HTTP, populated production — p50 | 8.7 s | (~7 s estimated) | — |
| `/api/send` HTTP, populated production — p50 | 11 s | (~10 s estimated) | — |
| Peak RSS during full sweep | 4.0 GiB | 3.85 GiB | −4 % |

| Hardware | Chip | Cores | RAM | Source |
|---|---|---|---|---|
| Apple M3 Ultra | M3 Ultra | 28 (20 P + 8 E) | 96 GB | r2_probe_runs host_id 1, 2026-05-31 (`probe_r2`); production HTTP from 2026-05-30 request_log sweep (post PR #144) |
| Apple M5 Max | M5 Max | 18 (6 Super + 12 Performance) | 128 GB | r2_probe_runs host_id 2, 2026-06-02 (`probe_r2`); HTTP sweep `m5-max-2026-06-02-http-mint-sweep.csv` |

### Reading the table

- **Synthetic warm prove** is the cleanest cross-hardware number — no HTTP, no SMT growth, no broadcast. Reflects raw prover speed at production circuit params (`MAX_IN_COINS = MAX_OUT_COINS = 8`, `INNER_PAD_BITS = 15`).
- **Live HTTP** is what users feel — proof + state lookup + broadcast attempt. The empty-state M5 number (6.91 s) is a floor; the populated-state production numbers (8.7 s mint, 11 s send) are the realistic experience.
- The M5 estimate for populated state is **the M3 production number × the synthetic ratio (M5/M3 = 0.91)**. Treat it as a ballpark — re-measure on a populated M5 deployment to confirm.

### Verdict

M5 Max is faster than M3 Ultra on every phase, but the win is **uneven**: huge on single-threaded circuit build (−42 %), modest on Rayon-bound warm prove (−9 %). The Plonky2 prover is not embarrassingly parallel — per-core speed beats core count on the latency path. **All three R2 budgets pass on both machines.**

**Caveat:** the ROADMAP-step-9 ideal target is **≤ 1 s warm prove**. Neither chip is close — both are in the 4–5 s range synthetic, 9–11 s live. The next real 10× will come from **Plonky3 or circuit-level optimisation**, not from newer Apple silicon. Per-generation hardware gains (M3 → M5 → M7) are unlikely to clear the ideal-budget gap on their own.

---

## Files in this directory

Two measurement methods live side-by-side:

1. **`*-probe_r2.json`** — pure proof timings from `node/src/bin/probe_r2.rs`. No HTTP, no chain-scanner, no broadcast. Matches the JSON schema emitted by `probe_r2 --output ...`.
2. **`*-http-mint-sweep.csv`** — wall-clock observations from POSTing to `/api/mint` against a live `zkcoins/node:beta` container pointed at the public Mutinynet Esplora endpoints. Format: `iter,addr,http_status,wall_seconds`.
3. **`<chip>-vs-<chip>-<date>.md`** — comparison summary across two hardware targets.

Both measurement methods persist to the same `r2_probe_*` Postgres tables (migration 0013) when run with `--persist`, so cross-host comparisons are also queryable via SQL.

## How to add a new entry

1. Build the binary on the target machine:
   ```sh
   cargo build --release -p node --bin probe_r2
   ```
2. Run with persistence + JSON output. Filename identifies the **chip generation**, not the host:
   ```sh
   RUST_LOG=warn ./target/release/probe_r2 \
       --warm-calls 5 \
       --output scripts/bench/results/<chip>-$(date +%Y-%m-%d)-probe_r2.json \
       --persist \
       --notes "<chip + RAM + arch summary, no hostname>" \
       --tags <chip>,native
   ```
   (requires `DATABASE_URL` reachable to a DB with migration 0013 applied.)
3. Optionally exercise the live HTTP path via a Mutinynet bench compose and capture a sweep CSV.
4. Before committing: **scrub the JSON `hostname` field** — replace with a generic label (e.g. `workstation-1`, `m3-ultra-host`). The persisted DB row keeps the raw fingerprint for SQL queries.
5. Update the results tables above and open a PR.
