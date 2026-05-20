# Contributing to zkCoins Server

This guide covers everything you need to develop, test, and deploy the zkCoins backend.

The first section, "Working on the Plonky2 Migration", documents the project invariants, the decision recipe for "should this go in the MVP?", the pre-push checklist, and the known foot-guns. It applies to all work on `develop` after the 2026-05-18 SP1 → Plonky2 cutover. The rest of this file is the dev guide for day-to-day server work.

---

## Working on the Plonky2 Migration

Canonical entry point for any session (agent or human) picking up the
codebase without prior context. The Plonky2 migration (PR [#17](https://github.com/zk-coins/server/pull/17))
merged on 2026-05-18; this section captures the project invariants that
survive the migration. Read this section, then dive into the linked
documents in the order given below.

### Reading order

1. **This section** — invariants, decision recipe, gates.
2. **[`ROADMAP.md`](./ROADMAP.md)** — live status table, per-step plans,
   effort, risk register, post-MVP Plonky3 path.
3. **[`SPEC.md`](./SPEC.md)** — what the protocol *does*. Glossary,
   divergences from the paper (§15), full circuit spec.
4. **[`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md)** — why we
   chose what we chose. §3 (11 divergences), §5 (6 locked-in design
   decisions), **§7 Lessons Learned** (11 gotchas — required reading
   before touching the affected code areas).
5. **[`program-plonky2/CONTRIBUTING.md`](./program-plonky2/CONTRIBUTING.md)**
   — operational handoff for the migration crate: toolchain,
   build/test/lint, coverage gate, gadget-authoring pattern.

### Project invariants (non-negotiable)

The five constraints below are decided and apply across every PR on
`develop`.

1. **Server-side compute architecture.** The server generates every ZK
   proof, holds every Merkle tree, broadcasts every Taproot inscription.
   The wallet holds only the user's private key and signs BIP-340 Schnorr
   over `SHA256(serialize(asth) ‖ serialize(ocr))`. No in-browser
   Poseidon, no wasm-Plonky2 verifier, no in-app ZK gadget.
2. **Closed test environment** — DEV *and* PRD. No external users, no
   real money, no migration of existing state. Step 7 of the ROADMAP
   deleted the SP1 path outright; no Cargo feature flag, no dual
   backend. At cutover (PR [#17](https://github.com/zk-coins/server/pull/17), 2026-05-18) the server state files
   were wiped and the new Plonky2 server started fresh.
3. **Hardware target: Mac Studio M3 Ultra, 96 GB unified RAM, single
   host.** All on-box compute resources are available (Performance +
   Efficiency cores, the integrated Apple GPU reachable via Metal,
   Neural Engine, AMX). **No external hardware** (no NVIDIA, no CUDA,
   no GPU farms). **No external cloud proving services** (no Succinct
   Prover Network, no AWS GPU, no Lambda Labs). Note: Plonky2 today
   has no Metal backend, so the integrated GPU is effectively idle for
   proving — that's a library property, not a constraint we imposed.
   Performance budget: warm proof ≤ 5 s (target ≤ 1 s), cold-start
   ≤ 30 s, memory peak < 64 GB.
4. **MVP = minimal feature surface + 100% test coverage.** Simultaneous,
   not alternative. "Minimal" reduces the surface; "100%" keeps what
   remains clean. Gate: `cargo llvm-cov --fail-under-lines 100 -- --test-threads=1`
   from inside the affected crate. Current state on `program-plonky2`:
   100% lines / functions / regions, 115 default-run tests (+ 2
   `#[ignore]`d `recursion_shape_probe` diagnostics). The authoritative
   coverage gate for `server` runs in CI on the self-hosted M3 Ultra
   runner (`.github/workflows/ci.yaml`, `Coverage Gate` job, gated
   behind the `ci:full` label on PRs). See `ROADMAP.md` § "Done" for
   the live test count and breakdown.
5. **Plonky2 is bridge tech; Plonky3 is the long-term destination.**
   But we do not preemptively adopt BabyBear / Poseidon2 inside this
   migration — see `MIGRATION_RESEARCH.md` §5 (decisions) and ROADMAP
   "Considered alternative".

### Decision recipe — should this go in the MVP?

Run this checklist in order on every proposed change. Stop at the
first "no".

1. **Is X on the critical path for the one-shot user loop?** (create
   account → mint → send → receive → balance) If no, defer to post-MVP.
2. **Does X compromise invariant 1 (server-side compute)?** If yes,
   redesign so all heavy compute is server-side.
3. **Does X require external hardware or cloud services (invariant 3)?**
   If yes, redesign.
4. **Does X assume migration logic (invariant 2)?** If yes, redesign
   to "replace not migrate" or defer until mainnet launch.
5. **Can X be tested to 100% coverage including negative paths
   (invariant 4)?** If not, refactor or gate behind a Cargo feature.
6. **Does X drift from the divergence list (`SPEC.md` §15)?** If yes,
   updating the divergence list is part of the PR.

If all six pass, X enters the MVP. Update `ROADMAP.md` Status-at-a-Glance
and the relevant `### Step N` section *in the same PR*.

### Pre-push checklist

The repo-level pre-push hook (`.githooks/pre-push`) runs `cargo fmt
--check`, `cargo clippy` (all three feature scopes), and `cargo
check --workspace --all-features` automatically. The full test +
coverage gate for `server` and `shared` runs in CI on the
self-hosted M3 Ultra runner — push and keep working, do not block
the terminal on the suite.

When touching `program-plonky2/` specifically, also run the local
sweep + coverage gate **before** opening / updating the PR — the
cyclic-recursion sweep is not in CI yet (decision tracked in [issue #50](https://github.com/zk-coins/server/issues/50)):

```bash
cd program-plonky2
cargo test --release --lib -- --test-threads=1
cargo llvm-cov --release --fail-under-lines 100 -- --test-threads=1
```

After push, poll CI until it goes green; if red, investigate and
fix — never abandon a red CI run.

### Branch hygiene

- No force-pushes, even to side branches.
- No `--no-verify` on commits.
- No squashing by the agent — the maintainer squashes at merge time if needed.
- Maintainers merge PRs; agents open them as drafts.
- Doc-only commits to `ROADMAP.md` / `SPEC.md` / `MIGRATION_RESEARCH.md`
  / `CONTRIBUTING.md` / `program-plonky2/CONTRIBUTING.md` that just
  correct or extend these files are not individually listed in
  `ROADMAP.md` "Done" — they're in `git log`.

### Where to put new knowledge

When you discover a new gotcha or take a new decision, the right home is:

| Type of knowledge | Where |
| --- | --- |
| Protocol-level fact (circuit invariant, public-input change) | `SPEC.md` |
| Why we chose / didn't choose something | `MIGRATION_RESEARCH.md` §5 or §7 |
| New status / step / risk | `ROADMAP.md` |
| Toolchain or workflow detail for the migration crate | `program-plonky2/CONTRIBUTING.md` |
| Cross-cutting invariant for the whole project | This section |

Don't duplicate prose across files — the second copy will drift.
Link from one to the other.

### Common foot-guns (already encountered)

Condensed pointers into [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md) §7:

1. Don't seed `DEFAULT_HASHES[TREE_DEPTH]` with `ZERO_HASH` in
   Poseidon SMTs — structural collision (§7.1).
2. `pw.set_target(t, v)` returns `Result` in plonky2 1.x — must
   handle (§7.3).
3. Pack 7 bytes per Goldilocks element, never 8 — modulus safety (§7.4).
4. Defensive bounds checks: use `Option::get().copied().unwrap_or(...)`,
   not explicit `if/else` — keeps coverage at 100% (§7.9).
5. Every `#[cfg(test)] mod tests` needs `#[cfg_attr(coverage_nightly, coverage(off))]` (§7.10).
6. No external GPU / cloud assumption in performance plans — single
   Mac Studio M3 Ultra (§7.11).
7. Kill orphan `cargo test` binaries after long circuit-test runs —
   they leak 30+ GB of swap (§7.6).
8. `gh` in background tasks needs `--repo <owner>/<repo>` (§7.7).

---

## Quick Start

```bash
git clone https://github.com/zk-coins/server.git
cd server
USERNAME_DOMAIN=test.zkcoins.local cargo run -p server
# Server starts on http://0.0.0.0:4242
```

## Local Development with Postgres

The Postgres state-layer added in PR-A1 expects a running PostgreSQL
instance to be reachable at `DATABASE_URL`. The module is not wired
into the bootstrap yet (PR-A2 + PR-A3 land that), so you can develop
without it — but to run the `db_tests` locally you do need either
Docker available (the tests spin up a Postgres 17 container via
`testcontainers-modules`) or a manually-started Postgres.

Manual Postgres for ad-hoc query work:

```bash
docker run --name zkcoins-pg \
  -e POSTGRES_PASSWORD=dev \
  -p 5432:5432 \
  -d postgres:17
export DATABASE_URL=postgres://postgres:dev@localhost:5432/postgres

# Apply the migrations against the running instance:
cargo install sqlx-cli --no-default-features --features rustls,postgres
cd server
sqlx migrate run
```

Run the `db_tests` (Docker required, runs `postgres:17` per test):

```bash
cargo test -p server db -- --test-threads=1
```

The schema lives in `server/migrations/0001_initial.sql`. After
changing it, drop the local database (`docker rm -f zkcoins-pg`) and
re-run `sqlx migrate run` against a fresh instance — there is no
`down` migration in the MVP, the migration set is forward-only.

## Setup

After cloning, enable the repo's pre-push hook. The hook runs `cargo
fmt --check`, `cargo clippy` (all three feature scopes), and `cargo
check --workspace --all-features` — fast enough that it stays out of
the way (< 30 s warm, < 2 min cold) while still flagging lint and
type regressions before they reach a CI runner.

```bash
git config core.hooksPath .githooks
```

The authoritative test + coverage gate runs in CI on a self-hosted
M3 Ultra runner (issue #40, `.github/workflows/ci.yaml`), not in
this hook. CI takes 60-90 min for a Rust change but does not block
your terminal — you push, you keep working, the runner reports back
via PR check status.

Wall budgets on warm cache:

| Stage                          | Wall      | Where     |
|--------------------------------|-----------|-----------|
| Pre-push hook (lint + check)   | < 30 s    | local     |
| Server + shared tests          | 60-90 min | CI runner |
| Coverage gate (100% scope)     | + 60 min  | CI runner |

When preparing a release PR to `main`, run the circuit sweep manually
— only the `server` + `shared` test sweep is gated in CI (decision
on the cyclic sweep is tracked in [issue #50](https://github.com/zk-coins/server/issues/50)):

```bash
cargo test -p zkcoins-program-plonky2 --release --lib -- --test-threads=1
```

You can bypass the hook with `git push --no-verify` in genuine
emergencies. CI is the real gate, so a bypassed lint failure surfaces
at the PR check level instead — and `develop` must be 100% green
before any main-merge.

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Rust | nightly (pinned via `rust-toolchain`) | Required for Plonky2 (`feature(specialization)`) |
| Bitcoin node | — | Required for blockchain scanning (or use Esplora API) |

## Project Structure

```
server/
├── server/                # Axum REST API server
│   └── src/
│       ├── main.rs        # Entry point, chain scanner, bind address
│       ├── server.rs      # REST endpoints (mint, send, balance, proof)
│       ├── account_server.rs  # Account management, coin proofs, prover calls
│       ├── state.rs       # Sparse Merkle Tree + Merkle Mountain Range
│       ├── scanner.rs     # Bitcoin block scanner (Taproot Inscriptions)
│       └── publisher.rs   # Inscription broadcaster (commit/reveal, prefix 4242)
├── shared/                # Shared types (Commitment, Invoice, ClientAccount)
│   └── src/
│       ├── lib.rs         # Types, key derivation, crypto helpers
│       └── commitment.rs  # Schnorr commitment (sign + verify)
├── program-plonky2/       # Plonky2 + Poseidon cyclic-recursion state-transition circuit
│   └── src/
│       ├── lib.rs         # Prelude: F, C, D type aliases
│       ├── hash.rs        # Poseidon HashDigest + byte conversions
│       ├── types.rs       # AccountState, Coin, ProofData, MINTING_ADDRESS placeholder
│       ├── inputs.rs      # ProgramInputs, CommitmentMerkleProofs
│       ├── merkle/        # Poseidon-based SMT + MMR
│       └── circuit/       # build_circuit + per-stage gadgets + aggregator
├── script-plonky2/        # Host-side Plonky2 prover wrapper (zkcoins-prover-plonky2)
│   └── src/lib.rs         # Prover struct: prove_initial / prove_account_update
├── Cargo.toml             # Workspace root (nightly toolchain, no SP1 patches)
├── Dockerfile             # Multi-stage Rust build (linux/arm64, FEATURES build-arg)
└── rust-toolchain         # Pinned nightly date (matches program-plonky2)
```

## Git Workflow

### Branches

| Branch | Purpose | Deploy target |
|---|---|---|
| `develop` | Default branch, active development | DEV server |
| `main` | Production releases | PRD server |

- **Push to `develop` via feature branch + PR** (branch ruleset active)
- **`main` is protected** — changes only via PR
- Never force-push, never amend

### Commit Messages

English, concise, *what* not *how*:

```
# Good
Bind to 0.0.0.0 instead of 127.0.0.1 for Docker access
Decouple server from SP1: optional zkvm feature, stub prover
Add rand features to bitcoin dependency

# Bad
fix build
wip
update
```

## Code Style

### Rust

- **Edition 2021**, `opt-level = 3` for dev (heavy crypto)
- **`cargo fmt`** before every commit
- **`cargo clippy`** — treat warnings as errors
- **No `unwrap()` in production paths** — use `?` or `expect("descriptive message")`
- **No `println!`** — use `tracing::info!`, `tracing::warn!`, etc.

### Naming

| Item | Convention | Example |
|---|---|---|
| Crate | kebab-case | `zkcoins-program-plonky2` |
| Module | snake_case | `account_server` |
| Struct | PascalCase | `AccountState`, `CoinProof` |
| Function | snake_case | `process_block`, `send_coins` |
| Constant | SCREAMING_SNAKE | `ACCOUNT_SERVER_ADDR` |

### Error Handling

```rust
// Good — propagate with context
let block = fetch_block(hash).map_err(|e| anyhow!("Failed to fetch block {}: {}", hash, e))?;

// Bad — panic in production
let block = fetch_block(hash).unwrap();
```

### Dependencies

- Workspace dependencies in root `Cargo.toml` — individual crates reference `{ workspace = true }`
- Pin exact versions for security-critical crates (`bitcoin`, `sha2`)
- `plonky2 = "1.1.0"` from crates.io; no `[patch.crates-io]` entries

## Architecture

### Request Flow

```
Client Request → Axum Router → server.rs (endpoint) → account_server.rs (logic)
                                                          ├── Prover (Plonky2)
                                                          ├── State (SMT + MMR)
                                                          └── Publisher (Bitcoin)
```

### Key Patterns

**Thread-safe state:** All shared state is `Arc<Mutex<State>>`. The server acquires a lock, reads/writes, releases.

**Account model:** Each account is `Address → Account` in a HashMap:
```rust
struct Account {
    proof: Option<Proof>,
    coin_queue: Vec<CoinProof>,
    coin_history: SparseMerkleTree,
    balance: u64,
}
```

**Prover:** `zkcoins_prover_plonky2::Prover` (in `script-plonky2/src/lib.rs`)
wraps the cyclic state-transition circuit. `Prover::new()` builds the
circuit once; `prove_initial` / `prove_account_update` (with their
`_with_in_coins` / `_with_in_and_out_coins_and_sources` variants) drive
individual transitions. No mock/stub backend — the only build is the
Plonky2 prover.

### Bitcoin Integration

The server continuously scans the Bitcoin blockchain:

1. `scanner.rs` polls Esplora every 30 seconds
2. Filters transactions by prefix `4242` in Taproot witness
3. Deserializes `Commitment` structs (Schnorr-signed)
4. `state.rs` inserts valid commitments into SMT, appends to MMR

The publisher (`publisher.rs`) creates Taproot Inscriptions:
- Commit/reveal pattern (two transactions)
- Data split into 520-byte chunks (max push size)
- Broadcasts via Esplora API

### Plonky2 State-Transition Circuit

The `program-plonky2/` crate defines the Zero-Knowledge proof logic.
The full SPEC §8 predicate (cyclic recursion, MMR + SMT inclusion,
in-coin source-side aggregator pattern from Stage 5d-next-5, out-coin
identifier derivation, pubkey rotation) lives in `circuit/main.rs`.
`MAX_IN_COINS = MAX_OUT_COINS = 8`. See
[`MIGRATION_RESEARCH.md` §7.22](./MIGRATION_RESEARCH.md#722-stage-5d-next-5-source-side-verification-via-aggregator-pattern--codified-resolves-721)
for the architecture writeup and `program-plonky2/SESSION_STATE.md`
for the historical pickup record.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ESPLORA_URL` | `https://mutinynet.com/api` | Esplora API endpoint (electrs or public) |
| `IS_MAINNET` | `false` | `true` for Bitcoin Mainnet, `false` for Mutinynet/Signet |
| `NETWORK_NAME` | `Mutinynet` / `Mainnet` | Human-readable name returned by `/api/info` |
| `USERNAME_DOMAIN` | _(required, no default)_ | External hostname returned by `/api/info`; server panics on startup if unset (see PR [#36](https://github.com/zk-coins/server/pull/36) for the regression that introduced the global panic hook) |
| `PUBLISHER_KEY` | test key | 32-byte hex private key for inscription publishing. **Required on mainnet** |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

## Docker

```bash
docker build -t zkcoin/server .
docker run -p 4242:4242 \
  --network bitcoin \
  -e ESPLORA_URL=http://electrs-mainnet:3000 \
  -e USERNAME_DOMAIN=zkcoins.app \
  zkcoin/server
```

Docker builds use nightly Rust auto-installed via the workspace `rust-toolchain` — no Succinct toolchain, no zkVM target.

## Persistent State

The server writes the following files under its data volume (`/data` in the container, `zkcoins_server-data` Docker volume on the DEV / PRD hosts). Together they define the recoverable state:

| File                       | Format                         | Purpose                                                                                                                                |
| -------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `smt.bin`                  | bincode `SparseMerkleTree`     | Sparse Merkle Tree of every commitment ever processed (key = sha256(public_key), leaf = account_state_hash).                            |
| `mmr.bin`                  | bincode `MerkleMountainRange`  | Append-only Merkle Mountain Range of `hash(smt_root ‖ prev_mmr_root)` leaves; one entry per processed commitment.                       |
| `mmr.bin.prev_root`        | 32 bytes                       | The previous MMR root, kept separately so the SMT/MMR pair stays atomically consistent across restarts.                                 |
| `latest_block.bin`         | 32 bytes (block hash)          | Last Bitcoin block whose inscriptions were fully processed and persisted. Scanner resumes from `latest_block + 1` after a restart.      |
| `accounts.bin`             | bincode `HashMap<Address, Account>` | Server-side account ledger — per-address balance, coin_queue, coin_history (SMT), and latest proof. Includes the minting account.        |
| `usernames.bin`            | bincode `UsernameStore`        | Gated by `usernames` Cargo feature. Bidirectional map of claimed usernames ↔ addresses.                                                |
| `minting_num_pubkeys.bin`  | 4 bytes LE u32                 | Gated by `faucet`. Counter of how many mint commitments have been issued; **must** survive restart, otherwise the next mint sends a stale `prev_commitment_pubkey` and `send_coins` returns `prev_commitment_pubkey required for account update`. |
| `proofs/<id>.bin`          | bincode `CoinProof`            | Individual per-send proof + commitment, indexed by `proof_id`. Append-only.                                                            |

`atomic_write` is used for every write (tempfile + rename). A crash between writes can still leave `latest_block.bin` lagging the SMT/MMR pair; the scanner is now tolerant of this — `state.update` errors are logged (see `main.rs::scan_for_inscriptions` callback) rather than propagated as panics.

### DEV state recovery

If the DEV server gets into a bad state (panic loop, mint failures with `prev_commitment_pubkey required`, balance never rising after a successful mint, etc.), the recovery procedure is to wipe the data volume:

```bash
# On the host running the server (DEV or PRD):
docker stop zkcoins-server
docker run --rm -v zkcoins_server-data:/data alpine sh -c 'rm -f /data/*.bin /data/*.bin.prev_root'
docker start zkcoins-server
```

The server starts from genesis on next boot: `Creating new State / No accounts file found / No saved block hash found / fetching latest from Esplora`. Past test wallets are abandoned on-chain (they're random) but the SMT is re-built from the chain tip onwards. This is **destructive** — never run it on PRD without a known-needed reason.

The E2E regen workflow on the app repo wipes this state before every run as part of the per-PR cadence in `app/e2e/README.md § 11.3`.

### Bitcoin Node

The server needs a Bitcoin node with an Esplora-compatible indexer (electrs). In production, it connects via the shared Docker network `bitcoin` to `electrs-mainnet:3000` (DEV: `electrs-mutinynet:3000`). The underlying bitcoind requires:
- `txindex=1`
- `rest=1`
- `server=1`

See [docs.zkcoins.app/infrastructure/backend](https://docs.zkcoins.app/infrastructure/backend) for full setup.

## CI/CD

| Workflow | Trigger | Action |
|---|---|---|
| `ci.yaml` (Lint & Build) | Ready PR → develop, push to develop | `cargo fmt --check`, clippy (MVP + all-features + program lib), build (MVP + all-features) on `ubuntu-latest`. |
| `ci.yaml` (Server + Shared Tests) | Ready PR → develop with `ci:full` label, push to develop | `cargo test -p server -p shared --release --all-features` on a self-hosted M3 Ultra runner (issue #40). |
| `ci.yaml` (Coverage Gate) | Ready PR → develop with `ci:full` label, push to develop | `cargo llvm-cov` with the 100% line + function gate, MVP scope, on the same self-hosted runner. |
| `deploy-dev.yaml` | Push to develop | Docker build (ARM64) → push `zkcoin/server:beta` → deploy to DEV |
| `deploy-prd.yaml` | Push to main | Docker build (ARM64) → push `zkcoin/server:latest` → deploy to PRD |
| `auto-release-pr.yaml` | Push to develop | Creates Release PR (develop → main) |

**Draft PRs** skip every `ci.yaml` job — the workflow fires once the
PR is marked ready-for-review.

**Heavy jobs** (`Server + Shared Tests`, `Coverage Gate`) additionally
require the `ci:full` label on a ready PR. Apply the label when the
PR is in shape to run against the authoritative ~60-90 min M3 Ultra
gate; remove it before the next push to keep the runner free for
other work. `Lint & Build` (fast, GitHub-hosted, free) keeps running
on every ready-PR push.

`push to develop` always runs the full gate — the post-merge run on
`develop` is the source of truth, and `deploy-dev.yaml` consumes its
result via the auto-release PR's check rollup.

To stop a Heavy run that is already executing, removing the `ci:full`
label is *not* enough — the workflow isolates label events into their
own concurrency group so an unrelated label toggle doesn't cancel an
in-flight 60-min run. If you need to free the runner immediately, use
`gh run cancel <run-id>` (the run id is on the PR's checks tab).

Build time is ~5 minutes (Rust compilation on ARM64).

## Related Repos

- [zk-coins/app](https://github.com/zk-coins/app) — Web application (frontend)
- [zk-coins/docs](https://github.com/zk-coins/docs) — Documentation (docs.zkcoins.app)
