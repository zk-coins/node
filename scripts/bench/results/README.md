# Bench Results

Hardware benchmarks for the Plonky2 prover hot path, keyed by chip
generation and the `git_sha` of the binary measured.

Two complementary measurement methods live side-by-side here:

1. **`*-probe_r2.json`** — pure proof timings from
   `node/src/bin/probe_r2.rs`. No HTTP, no chain-scanner, no
   broadcast. The deliberate lower bound. Matches the JSON schema
   emitted by `probe_r2 --output ...`.
2. **`*-http-mint-sweep.csv`** — wall-clock observations from
   POSTing to `/api/mint` against a live `zkcoins/node:beta`
   container booted from a minimal compose pointing at the public
   Mutinynet Esplora endpoints. Includes proof generation + state
   lookups + broadcast attempt. Format:
   `iter,addr,http_status,wall_seconds`.

Both methods persist to the same `r2_probe_*` Postgres tables
(migration 0013) when run with `--persist`, so cross-host
comparisons are queryable via SQL.

## Current entries

| Date | Chip | Cores | RAM | git_sha | probe_r2 warm p50 |
|---|---|---|---|---|---|
| 2026-05-31 | Apple M3 Ultra | 28 (20P + 8E) | 96 GB | (post #144) | 4777 ms |
| 2026-06-02 | Apple M5 Max | 18 (6 Super + 12 Performance) | 128 GB | 6e8b7ab | 4350 ms |

Host identity is intentionally omitted from this table — only the
chip generation and aggregate hardware shape are relevant for the
comparison. The persisted DB row carries the full fingerprint.

## How to add a new entry

1. Build the binary on the target machine:
   ```sh
   cargo build --release -p node --bin probe_r2
   ```
2. Run with persistence enabled and JSON output. Use a filename that
   identifies the **chip generation**, not the host:
   ```sh
   RUST_LOG=warn ./target/release/probe_r2 \
       --warm-calls 5 \
       --output scripts/bench/results/<chip>-$(date +%Y-%m-%d)-probe_r2.json \
       --persist \
       --notes "<chip + RAM + arch summary, no hostname>" \
       --tags <chip>,native
   ```
   (requires `DATABASE_URL` reachable to a DB with migration 0013
   applied.)
3. Optionally exercise the live HTTP path via a local Mutinynet
   bench compose and capture a sweep CSV.
4. Before committing, **scrub the JSON `hostname` field** — replace
   with a generic label (e.g. `workstation-1`, `m3-ultra-host`).
   Commit only the scrubbed file; the persisted DB row keeps the
   raw fingerprint for SQL queries.
5. Update the table above and open a PR.
