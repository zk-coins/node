# Bench Results

Hardware benchmarks for the Plonky2 prover hot path, keyed by the
hardware fingerprint and the `git_sha` of the binary measured.

Two complementary measurement methods live side-by-side here:

1. **`*-probe_r2.json`** — pure proof timings from
   `node/src/bin/probe_r2.rs`. No HTTP, no chain-scanner, no
   broadcast. The deliberate lower bound. Matches the JSON schema
   emitted by `probe_r2 --output ...`.
2. **`*-http-mint-sweep.csv`** — wall-clock observations from
   POSTing to `/api/mint` against a live `zkcoins/node:beta`
   container booted via
   [`DFXServer/server/infrastructure/benchmarks/zkcoins-node/`](https://github.com/DFXServer/server/tree/develop/infrastructure/benchmarks/zkcoins-node).
   Includes proof generation + state lookups + broadcast attempt.
   Captures the full HTTP path on top of the proof time. Format:
   `iter,addr,http_status,wall_seconds`.

Both methods persist to the same `r2_probe_*` Postgres tables
(migration 0013) when run with `--persist` against the DEV DB,
so cross-host comparisons are also queryable via SQL.

## Current entries

| Date | Host | Chip | Cores | RAM | git_sha | probe_r2 warm p50 |
|---|---|---|---|---|---|---|
| 2026-05-31 | dfxdev.local | Apple M3 Ultra | 28 (20P + 8E) | 96 GB | (unknown, post #144) | 4777 ms |
| 2026-06-02 | M5ME.local | Apple M5 Max | 18 (6 Super + 12 Performance) | 128 GB | 6e8b7ab | 4350 ms |

## How to add a new entry

1. Build the binary on the target machine:
   ```sh
   cargo build --release -p node --bin probe_r2
   ```
2. Run with persistence enabled and JSON output:
   ```sh
   RUST_LOG=warn ./target/release/probe_r2 \
       --warm-calls 5 \
       --output scripts/bench/results/$(hostname)-$(date +%Y-%m-%d)-probe_r2.json \
       --persist \
       --notes "<hardware summary>" \
       --tags <chip>,native
   ```
   (requires `DATABASE_URL` reachable to a DB that has migration 0013
   applied — the DEV stack on `dfxdev` works.)
3. Optionally exercise the live HTTP path via the bench compose in
   `DFXServer/server/infrastructure/benchmarks/zkcoins-node/` and
   capture a sweep CSV.
4. Commit the JSON + CSV here and update the table above.
