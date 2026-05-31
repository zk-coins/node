# Contributing to zkCoins Node

This guide covers everything you need to develop, test, and deploy the zkCoins backend.

The first section, "Working on the Plonky2 Migration", documents the project invariants, the decision recipe for "should this go in the MVP?", the pre-push checklist, and the known foot-guns. It applies to all work on `develop` after the 2026-05-18 SP1 → Plonky2 cutover. The rest of this file is the dev guide for day-to-day node work.

---

## Working on the Plonky2 Migration

Canonical entry point for any session (agent or human) picking up the
codebase without prior context. The Plonky2 migration (PR [#17](https://github.com/zk-coins/node/pull/17))
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

### No polling — events only

Bitcoin / Esplora signals on the node's hot path are subscribed to,
never polled. The scanner consumes block events from the Esplora-
compatible WebSocket stream (`scanner_ws.rs`, `ESPLORA_WS_URL` —
required env var, no default; see README §Configuration); the
publisher broadcasts the commit and reveal transactions back-to-back
via REST and never sleeps or polls between them. The previous 30-s
tip-poll gated `/api/mint` and `/api/send` visibility by up to a full
block-time + poll-interval (issue #84); event-driven ingestion brings
that down to the WS round-trip.

Historical note: issue #84 originally replaced a fixed 5 s
`PROPAGATION_WAIT_SECS` sleep with a WS `track-tx` wait + REST
safety-net. PR [#144](https://github.com/zk-coins/node/pull/144)
removed that path and replaced it with direct sequential
`client.broadcast(commit) → client.broadcast(reveal)`. A later
re-analysis (see `MIGRATION_RESEARCH.md` § 7.24) established that
the publisher's subscribe frame had been sent in the wrong wire
format — `{"action":"track-tx","data":"<txid>"}` — whereas the
mempool.js convention and `mempool/backend:v3.3.1`'s
`websocket-handler.ts` both expect `{"track-tx":"<txid>"}` as a
top-level key. The backend silently dropped the malformed frame, so
the WS wait always timed out and the REST safety-net always
confirmed the tx as already on-chain (16/16 fallbacks in the 72 h
DEV `request_log` sample, 0 not-found, 0 errors). PR #144 stands
on independent grounds: in the in-cluster topology (node, electrs,
bitcoind share the Docker `bitcoin` network) bitcoind's
local-mempool accept already orders the two POSTs race-free, and
the closed-test-env model (no external Esplora) means there is no
upstream to subscribe against in the first place. The
architecture is documented here; the wire-format bug is recorded
for the historical record, not as a justification.

Where it applies:

- `node/src/scanner.rs` — pure inscription parsing, no polling.
- `node/src/scanner_runtime.rs` — block-walk loop, drains the WS-fed channel.
- `node/src/scanner_ws.rs` — WS subscriber + reconnect-with-backoff.
- `node/src/scanner_ws_parse.rs` — pure WS frame parsers.
- `node/src/publisher.rs` — direct sequential commit→reveal broadcast.

Where it does NOT apply: integration tests
(`node/tests/api_remote.rs`), health-readiness probes, and any
self-host operator code outside the four files above.

CI enforces this with a `grep` step inside the `Lint & Build` job in
`.github/workflows/ci.yaml`:

```bash
grep -rEn 'tokio::time::(sleep|sleep_until|interval)|std::thread::sleep' \
  node/src/scanner.rs \
  node/src/scanner_runtime.rs \
  node/src/scanner_ws.rs \
  node/src/scanner_ws_parse.rs \
  node/src/publisher.rs \
  | grep -v 'scanner-polling-ok:'
```

Any match without the `scanner-polling-ok:` token on the same line
fails the build with a pointer to issue #84. The token is a plain
comment marker — not an `#[allow(...)]` attribute, which would have
been mistakable for a real lint suppression — and is the documented
per-line opt-out for genuinely justified exceptions (today: the
WS-reconnect backoff in `scanner_ws` and the bounded HTTP-retry
sleep in `scanner_runtime`). The same line must carry a comment
explaining WHY this particular sleep is not a chain-tip poll. New
uses require either changing the design or extending this section
with the rationale.

The publisher's previous per-broadcast `track-tx` reconnect-with-
backoff inside `scanner_ws.rs` is no longer in the file — it was
removed alongside the WS wait itself (see historical note above).

### Project invariants (non-negotiable)

The five constraints below are decided and apply across every PR on
`develop`.

1. **Node-side compute architecture.** The node generates every ZK
   proof, holds every Merkle tree, broadcasts every Taproot inscription.
   The wallet holds only the user's private key and signs BIP-340 Schnorr
   over `SHA256(serialize(asth) ‖ serialize(ocr))`. No in-browser
   Poseidon, no wasm-Plonky2 verifier, no in-app ZK gadget.
2. **Closed test environment** — DEV *and* PRD. No external users, no
   real money, no migration of existing state. Step 7 of the ROADMAP
   deleted the SP1 path outright; no Cargo feature flag, no dual
   backend. At cutover (PR [#17](https://github.com/zk-coins/node/pull/17), 2026-05-18) the node state files
   were wiped and the new Plonky2 node started fresh.
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
   coverage gate for `node` runs in CI on the self-hosted M3 Ultra
   runner (`.github/workflows/ci.yaml`, `Coverage Gate` job, gated
   behind the `ci:full` label on PRs). See `ROADMAP.md` § "Done" for
   the live test count and breakdown.
5. **Plonky2 is bridge tech; Plonky3 is the long-term destination.**
   But we do not preemptively adopt BabyBear / Poseidon2 inside this
   migration — see `MIGRATION_RESEARCH.md` §5 (decisions) and ROADMAP
   "Considered alternative".
6. **`num_pubkeys` only advances after on-chain broadcast — never
   before.** The mint and commit flows must follow prepare → broadcast
   → commit ordering: build the prover witness on a clone, attempt
   the inscription broadcast first, and only on broadcast success
   commit the bumped `minting_meta.num_pubkeys` (with an optimistic
   `... WHERE num_pubkeys = $expected_prev` clause) together with the
   mutated account snapshots in a single sqlx transaction. The
   broadcast-then-commit ordering is load-bearing; any future
   refactor that moves a `minting_meta` UPDATE, an `accounts` UPSERT,
   or an in-memory `receive_coin` above the broadcast call re-
   introduces the state-desync class fixed in
   [zk-coins/node#89](https://github.com/zk-coins/node/issues/89).
   Startup invariant check in `runtime::check_minting_state_invariant`
   enforces the corollary at boot: every `pubkey_idx ∈
   0..num_pubkeys` MUST have a commitment in the SMT, no flag
   override — operator recovery is via the `reset_state` workflow.

### Decision recipe — should this go in the MVP?

Run this checklist in order on every proposed change. Stop at the
first "no".

1. **Is X on the critical path for the one-shot user loop?** (create
   account → mint → send → receive → balance) If no, defer to post-MVP.
2. **Does X compromise invariant 1 (node-side compute)?** If yes,
   redesign so all heavy compute is node-side.
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
coverage gate for `node` and `shared` runs in CI on the self-hosted
M3 Ultra runner pool — push and keep working, do not block the
terminal on the suite.

When touching `program-plonky2/` specifically, also run the local
sweep + coverage gate **before** opening / updating the PR — the
cyclic-recursion sweep is not in CI yet (decision tracked in [issue #50](https://github.com/zk-coins/node/issues/50)):

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
git clone https://github.com/zk-coins/node.git
cd node
USERNAME_DOMAIN=test.zkcoins.local cargo run -p node
# Node starts on http://0.0.0.0:4242
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
cd node
sqlx migrate run
```

Run the `db_tests` (Docker required, runs `postgres:17` per test):

```bash
cargo test -p node db -- --test-threads=1
```

The schema lives in `node/migrations/0001_initial.sql`. After
changing it, drop the local database (`docker rm -f zkcoins-pg`) and
re-run `sqlx migrate run` against a fresh instance — there is no
`down` migration in the MVP, the migration set is forward-only.

R2-probe results land in `r2_probe_runs` (+ `r2_probe_hosts` /
`r2_probe_warm_calls`) added by migration `0013_r2_probe_results.sql`.
The `r2_probe_runs_summary` view drives `GET
/api/admin/r2-probe/history`; the `probe_r2` binary writes via
`--persist` when `DATABASE_URL` is set. See `node/src/r2_probe.rs`
for the persistence module and the schema rationale.

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
M3 Ultra runner pool (issue #40, `.github/workflows/ci.yaml`), not
in this hook. CI takes 60-90 min for a Rust change but does not
block your terminal — you push, you keep working, the pool reports
back via PR check status.

Wall budgets on warm cache:

| Stage                          | Wall      | Where     |
|--------------------------------|-----------|-----------|
| Pre-push hook (lint + check)   | < 30 s    | local     |
| Node + shared tests            | 60-90 min | CI runner |
| Coverage gate (100% scope)     | + 60 min  | CI runner |

When preparing a release PR to `main`, run the circuit sweep manually
— only the `node` + `shared` test sweep is gated in CI (decision
on the cyclic sweep is tracked in [issue #50](https://github.com/zk-coins/node/issues/50)):

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
node/
├── node/                  # Axum REST API
│   └── src/
│       ├── main.rs        # Entry point, chain scanner, bind address
│       ├── router.rs      # REST endpoints (mint, send, balance, proof)
│       ├── account_node.rs  # Account management, coin proofs, prover calls
│       ├── state.rs       # Sparse Merkle Tree + Merkle Mountain Range
│       ├── scanner.rs     # Bitcoin block scanner (Taproot Inscriptions)
│       ├── scanner_ws.rs  # Esplora WebSocket subscriber (event-driven, issue #84)
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
| `staging` | Integration buffer — feature PRs land here first | none |
| `develop` | Active development, promoted from `staging` in batches | DEV node |
| `main` | Production releases, promoted from `develop` | PRD node |

- **Open feature PRs against `staging`** (not `develop`) — `staging` is the integration buffer where multiple feature branches accumulate before being batched into a single `develop` promotion. This keeps `develop` clean for DEV-deploy churn and gives reviewers a smaller blast radius per merge.
- **`develop` and `main` are protected** — direct pushes are rejected. `develop` accepts only the auto-PR from `staging`; `main` accepts only the auto-PR from `develop`. Hotfixes still go through `staging` so the same review path applies.
- **`develop` is auto-PR'd from `staging`** by `auto-release-pr-staging.yaml` whenever new commits land on `staging`. Merge that PR to promote the batch to DEV. Promote PRs intentionally skip the `ci:full` label — heavy M3 Ultra tests stay reserved for the develop → main Release PR.
- **`main` is auto-PR'd from `develop`** by `auto-release-pr.yaml` (with `ci:full` applied automatically). Merge to release to PRD.
- Never force-push, never amend.

### Commit Messages

English, concise, *what* not *how*:

```
# Good
Bind to 0.0.0.0 instead of 127.0.0.1 for Docker access
Decouple node from SP1: optional zkvm feature, stub prover
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
| Module | snake_case | `account_node` |
| Struct | PascalCase | `AccountState`, `CoinProof` |
| Function | snake_case | `process_block`, `send_coins` |
| Constant | SCREAMING_SNAKE | `ACCOUNT_NODE_ADDR` |

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
Client Request → Axum Router → router.rs (endpoint) → account_node.rs (logic)
                                                          ├── Prover (Plonky2)
                                                          ├── State (SMT + MMR)
                                                          └── Publisher (Bitcoin)
```

### Key Patterns

**Thread-safe state:** All shared state is `Arc<Mutex<State>>`. The node acquires a lock, reads/writes, releases.

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

The node continuously scans the Bitcoin blockchain:

1. `scanner_ws.rs` subscribes to the mempool.space-compatible WebSocket
   (`ESPLORA_WS_URL`) and pushes block events into a channel; no
   chain-tip polling (issue #84, see "No polling — events only" above)
2. `scanner_runtime.rs` drains the channel and hands each block to
   `scanner.rs`, which filters transactions by prefix `4242` in the
   Taproot witness
3. Deserializes `Commitment` structs (Schnorr-signed)
4. `state.rs` inserts valid commitments into SMT, appends to MMR

The publisher (`publisher.rs`) creates Taproot Inscriptions:
- Commit/reveal pattern (two transactions)
- Data split into 520-byte chunks (max push size)
- Broadcasts via Esplora REST: commit and reveal POSTs run back to
  back with no inter-tx wait. Sequencing is provided by bitcoind's
  local-mempool accept (node, electrs, bitcoind share the Docker
  `bitcoin` network), not by a WS `track-tx` subscription.

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

The node reads its configuration exclusively from environment variables;
no `.env` file is loaded by the process. The table below covers every
variable the node actually reads (`node/src/lib.rs`, `runtime.rs`,
`scanner_ws.rs`, `publisher.rs`). Required variables panic the bootstrap
on startup if unset — there is no silent fallback.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | _(required, no default)_ | Postgres connection string for the state-layer (e.g. `postgresql://zkcoins:<pw>@postgres:5432/zkcoins`). Node panics on startup if unset. |
| `PUBLISHER_KEY` | _(required, no default)_ | 32-byte hex private key for Taproot inscription publishing. **Required on every network — DEV, signet, and mainnet.** No fallback default exists: the previous `1234…` placeholder was a publicly-known test key that drainer bots swept within minutes of any on-chain top-up (4 historical drains confirmed). Node panics on startup if unset. Generate locally via `openssl rand -hex 32`. In any deployed environment, source it from your secret manager — **never commit a real key**. |
| `USERNAME_DOMAIN` | _(required, no default)_ | External hostname returned by `/api/info`; node panics on startup if unset (see PR [#36](https://github.com/zk-coins/node/pull/36) for the regression that introduced the global panic hook). |
| `POSTGRES_PASSWORD` | _(required, no default for the DB container)_ | Read by the Postgres container, not by the node process itself; the node's `DATABASE_URL` already embeds the password. Listed here because it is part of the local-dev bootstrap (see `Local Development with Postgres` below). |
| `IS_MAINNET` | _(required, no default)_ | Exact string `true` or `false`; any other value panics. Truthy values like `1`, `TRUE`, `yes` are rejected to prevent silent misconfiguration. |
| `ESPLORA_URL` | _(required, no default)_ | HTTP Esplora endpoint (electrs or public-compatible) for the chain this stage serves. Empty string is treated as unset and panics. |
| `ESPLORA_WS_URL` | _(required, no default)_ | Esplora-compatible WebSocket endpoint consumed by `scanner_ws` (issue #84). Empty string is treated as unset and panics. Previous Mutinynet default was removed because it coupled the deploy to a public third-party host. |
| `NETWORK_NAME` | `Mutinynet` / `Mainnet` | Human-readable name returned by `/api/info`. Derived from `IS_MAINNET` if unset. Purely cosmetic — no behavioural effect. |
| `PROOFS_DIR` | `./proofs` | Directory for per-proof bincode files (see `Persistent State` below). |
| `SCANNER_INITIAL_SETTLE_TIMEOUT_MS` | (runtime-defined) | Override for the scanner's initial-settle deadline; see `runtime.rs`. |
| `ZKCOINS_SKIP_BOOTSTRAP_WARMUP` | `false` | When `1`/`true`, skip the background Plonky2 prover warmup task at startup. Sets `prover_warm = true` immediately so `/health/ready` returns 200 the moment the listener binds. Set in the runtime smoke tests so pre-push wall stays bounded; production deploys leave it unset. See **Bootstrap timing** below. |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`). |

### Bootstrap timing

The node bootstraps the HTTP listener and the Plonky2 prover in a
specific sequence so the API is reachable as quickly as possible:

1. `~0.1 s` — `TcpListener::bind` returns. `/health` (liveness) is now
   200. The listener accepts connections and `axum::serve` starts
   draining them.
2. `~0.1 s` — `tokio::task::spawn_blocking` is launched with
   `AccountNode::warmup_prover`, a synthetic discardable
   `prove_initial` that wakes the Rayon worker pool and the AOT-
   compiled Plonky2 evaluator caches. The task runs CPU-bound on a
   blocking-pool thread so the tokio worker that owns `axum::serve` is
   not starved.
3. `~21 s` — `warmup_prover` returns Ok. The background task flips
   `prover_warm = true`. `/health/ready` now returns 200 with
   `prover: ready`.

While step 3 is in progress, `/health/ready` returns 503 with
`{"ready":false,"failures":["prover"],"status":"starting","prover":"warming"}`.
A load balancer (or Kuma monitor) keyed on the readiness endpoint
keeps traffic on the previous-generation pod through the warmup
window — the new pod's `/health` still returns 200 so the container
runtime does not restart it.

A user request that lands BEFORE the warmup completes still serves
correctly — it just pays the ~7 s cold-prove tax instead of the
steady-state ~5 s p50. The trade-off vs. the previous synchronous
shape (PR #147, closed): API offline time per deploy stays ~0.1 s
instead of ~21 s; the cold-tax shifts from the first
post-deploy user request to whichever request arrives during the
warmup window.

Empirical numbers (dfxdev R2 probe, 2026-05-31):

| Stage | Wall (ms) | Notes |
|---|---|---|
| `circuit_build_wall_ms` | 14214 | `Prover::new()` — paid by `load_from_pg` BEFORE the listener binds. |
| `prove_cold_wall_ms`    |  7012 | First prove call after build — what the background warmup pays. |
| `prove_warm p50`        |  4777 | Steady state — every request after the warmup task flips the flag. |

Set `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1` to skip the warmup task entirely.
Used by the runtime smoke tests in `runtime_tests.rs`; production
deploys leave it unset.

### Minimal local-dev env

All chain-shaping vars are required — there are no defaults. Set them
explicitly, even for local dev:

```bash
export DATABASE_URL="postgresql://postgres:dev@localhost:5432/postgres"
export PUBLISHER_KEY="$(openssl rand -hex 32)"
export USERNAME_DOMAIN="test.zkcoins.local"
export IS_MAINNET="false"
export ESPLORA_URL="http://localhost:3000"           # your local electrs
export ESPLORA_WS_URL="ws://localhost:8999/api/v1/ws"  # your local mempool/backend, or any Esplora-compatible WS
cargo run -p node
```

For any deployed environment, the real values live in your secret manager
of choice and are passed into the node container as env vars at startup.

## Docker

```bash
docker build -t zkcoins/node .
docker run -p 4242:4242 \
  --network bitcoin \
  -e ESPLORA_URL=http://electrs-mainnet:3000 \
  -e USERNAME_DOMAIN=zkcoins.app \
  zkcoins/node
```

Docker builds use nightly Rust auto-installed via the workspace `rust-toolchain` — no Succinct toolchain, no zkVM target.

## Persistent State

After the PR-A1/PR-A2/PR-A3 Postgres migration series, all persistent node state lives in a Postgres 17 database (`DATABASE_URL` env var). The only on-disk state remaining is the per-proof file store. The state-layer schema (`node/migrations/*.sql`) is applied idempotently on every boot by `db::connect_and_migrate`.

| Location                                | Format                                                     | Purpose                                                                                                                                                                                                                                                                          |
| --------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `smt_state` row (singleton, `id = 1`)   | bincode `SparseMerkleTree` in a `BYTEA` column             | Sparse Merkle Tree of every commitment ever processed (key = sha256(public_key), leaf = account_state_hash).                                                                                                                                                                     |
| `mmr_state` row (singleton, `id = 1`)   | bincode `MerkleMountainRange` in a `BYTEA` column          | Append-only Merkle Mountain Range of `hash(smt_root ‖ prev_mmr_root)` leaves; one entry per processed commitment.                                                                                                                                                                |
| `latest_block` row (singleton, `id = 1`) | 32-byte block hash in a `BYTEA` column                     | Last Bitcoin block whose inscriptions were fully processed and persisted. Scanner resumes from `latest_block + 1` after a restart. Written in the same `BEGIN; UPSERT; UPSERT; UPSERT; COMMIT` transaction as the SMT and MMR (issue #11 fix).                                   |
| `accounts` table (one row per address)  | 32-byte `address` PRIMARY KEY + bincode `Account` `BYTEA`  | Node-side account ledger — per-address balance, coin_queue, coin_history (SMT), and latest proof. Includes the minting account. Upserted per mutation by the send / receive / mint handlers.                                                                                  |
| `usernames` table (one row per name)    | `TEXT` name PRIMARY KEY + 32-byte `address` `BYTEA`        | Bidirectional map of claimed usernames ↔ addresses. Race-free claims via `INSERT … ON CONFLICT (name) DO NOTHING`. Always present — usernames are permanent MVP.                                                                                                                  |
| `minting_meta` row (singleton, `id = 1`) | `BIGINT` num_pubkeys                                       | Counter of how many mint commitments have been issued; **must** survive restart, otherwise the next mint sends a stale `prev_commitment_pubkey` and `send_coins` returns `prev_commitment_pubkey required for account update`. Always present — mint is permanent MVP.            |
| `proofs/<id>.bin` (on-disk file)        | bincode `CoinProof`                                        | Individual per-send proof + commitment, indexed by `proof_id`. Append-only. **Not** in Postgres because the per-proof blobs are large Plonky2 proof bytes and the directory layout makes recovery trivial. Path configurable via `PROOFS_DIR` (default `./proofs`).               |

Writes are atomic at the row / transaction level (`ON CONFLICT DO UPDATE` for singleton rows, the BEGIN/COMMIT block in `db::persist_state_tx` for the SMT/MMR/latest-block trio). Per-proof file writes still use a write-to-temp + rename pattern inside `ProofStore::persist_proof_bytes`. The pre-migration `smt.bin` / `mmr.bin` / `latest_block.bin` / `accounts.bin` / `usernames.bin` / `minting_num_pubkeys.bin` sibling files no longer exist, and the previous `main.rs::atomic_write` helper has been removed.

### DEV state recovery

If the DEV node gets into a bad state (panic loop, mint failures with `prev_commitment_pubkey required`, balance never rising after a successful mint, etc.), the recovery procedure is to truncate the Postgres state-layer tables (and drop the on-disk proofs directory):

```bash
# On the host running the node (DEV or PRD):
docker stop zkcoins-node
# Truncate every state-layer table. _sqlx_migrations is intentionally
# left in place so connect_and_migrate skips re-applying the schema.
docker exec -i zkcoins-postgres psql -U zkcoins -d zkcoins -c \
  'TRUNCATE accounts, usernames, smt_state, mmr_state, latest_block, minting_meta;'
# Drop the per-proof files (proof_id state resets at next boot).
docker run --rm -v zkcoins_node-data:/data alpine sh -c 'rm -rf /data/proofs'
docker start zkcoins-node
```

The node starts from genesis on next boot: `Loaded State from Postgres` (empty), `Loaded AccountNode from Postgres` (empty), `No saved block hash found, fetching latest from Esplora`. Past test wallets are abandoned on-chain (they're random) but the SMT is re-built from the chain tip onwards. This is **destructive** — never run it on PRD without a known-needed reason.

The E2E regen workflow on the app repo wipes this state before every run as part of the per-PR cadence in `app/e2e/README.md § 11.3`.

### Bitcoin Core

The node needs Bitcoin Core with an Esplora-compatible indexer (electrs). In production, it connects via the shared Docker network `bitcoin` to `electrs-mainnet:3000` (DEV: `electrs-mutinynet:3000`). The underlying bitcoind requires:
- `txindex=1`
- `rest=1`
- `server=1`

See [docs.zkcoins.app/infrastructure/backend](https://docs.zkcoins.app/infrastructure/backend) for full setup.

## CI/CD

| Workflow | Trigger | Action |
|---|---|---|
| `ci.yaml` (Lint & Build) | Ready PR → develop, push to develop | `cargo fmt --check`, clippy (MVP + all-features + program lib), build (MVP + all-features) on `ubuntu-latest`. |
| `ci.yaml` (Node + Shared Tests) | Ready PR → develop with `ci:full` label, push to develop | `cargo nextest run -p node -p shared --release --all-features --test-threads 1 -E 'not binary(api_remote)'` on the self-hosted M3 Ultra runner pool (issue #40). |
| `ci.yaml` (Coverage Gate) | Ready PR → develop with `ci:full` label, push to develop | `cargo llvm-cov nextest` with the 100% line + function gate, MVP scope, on the same runner pool. |
| `deploy-dev.yaml` | Push to develop | Docker build (ARM64) → push `zkcoins/node:beta` → deploy to DEV |
| `deploy-prd.yaml` | Push to main | Docker build (ARM64) → push `zkcoins/node:latest` → deploy to PRD |
| `auto-release-pr-staging.yaml` | Push to staging | Creates Promote PR (staging → develop) |
| `auto-release-pr.yaml` | Push to develop | Creates Release PR (develop → main) with `ci:full` label |

**Draft PRs** skip every `ci.yaml` job — the workflow fires once the
PR is marked ready-for-review.

**Heavy jobs** (`Node + Shared Tests`, `Coverage Gate`) additionally
require the `ci:full` label on a ready PR. Apply the label when the
PR is in shape to run against the authoritative ~60-90 min M3 Ultra
gate; remove it before the next push to keep an agent free for other
work. `Lint & Build` (fast, GitHub-hosted, free) keeps running on
every ready-PR push.

`push to develop` always runs the full gate — the post-merge run on
`develop` is the source of truth, and `deploy-dev.yaml` consumes its
result via the auto-release PR's check rollup.

To stop a Heavy run that is already executing, removing the `ci:full`
label is *not* enough — the workflow isolates label events into their
own concurrency group so an unrelated label toggle doesn't cancel an
in-flight 60-min run. If you need to free an agent immediately, use
`gh run cancel <run-id>` (the run id is on the PR's checks tab).

Build time is ~5 minutes (Rust compilation on ARM64).

## Related Repos

- [zk-coins/app](https://github.com/zk-coins/app) — Web application (frontend)
- [zk-coins/docs](https://github.com/zk-coins/docs) — Documentation (docs.zkcoins.app)
