# Contributing to zkCoins Server

This guide covers everything you need to develop, test, and deploy the zkCoins backend.

If you arrived here while working on the `feat/plonky2-migration` branch (or any of its successors), read § "Working on the Plonky2 Migration" *first* — it covers project invariants, the decision recipe for "should this go in the MVP?", a pre-push checklist, and the known foot-guns. The rest of this file is the long-standing dev guide for the `develop`/SP1 branch.

---

## Working on the Plonky2 Migration

Canonical entry point for any session (agent or human) picking up the
`feat/plonky2-migration` branch without prior context. Read this section,
then dive into the linked documents in the order given below.

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
this migration branch.

1. **Server-side compute architecture.** The server generates every ZK
   proof, holds every Merkle tree, broadcasts every Taproot inscription.
   The wallet holds only the user's private key and signs BIP-340 Schnorr
   over `SHA256(serialize(asth) ‖ serialize(ocr))`. No in-browser
   Poseidon, no wasm-Plonky2 verifier, no in-app ZK gadget.
2. **Closed test environment** — DEV *and* PRD. No external users, no
   real money, no migration of existing state. Step 7 of the ROADMAP
   deletes the SP1 path outright; no Cargo feature flag, no dual
   backend. On cutover the server state files are wiped and the new
   Plonky2 server starts fresh.
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
   100% lines / functions / regions, 72 tests. See `ROADMAP.md`
   § "Done" for the live test count and breakdown.
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

From inside the affected crate (use `program-plonky2/` for the
migration code; workspace root for `program`/`server`/`shared`/`script`):

```bash
cargo build
cargo test -- --test-threads=1
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo llvm-cov --fail-under-lines 100 -- --test-threads=1   # only for program-plonky2 currently
```

All five must pass. After push, poll CI until it goes green; if red,
investigate and fix — never abandon a red CI run.

### Branch hygiene

- No force-pushes, even to side branches.
- No `--no-verify` on commits.
- No squashing by the agent — Cyrill squashes at merge time if needed.
- Cyrill merges PRs; agents open them as drafts.
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
SP1_PROVER=mock cargo run -p server
# Server starts on http://0.0.0.0:4242
```

## Setup

After cloning, enable the repo's pre-push hook. This runs the full local
verification (fmt, clippy, build, test, 100% coverage gate) before every
`git push`. CI itself only runs lint + build, because the full suite is
~8 min on an M3 Ultra and was hitting the 75-min ubuntu-latest timeout
(see issue #30).

```bash
git config core.hooksPath .githooks
```

You can bypass with `git push --no-verify` in genuine emergencies, but
develop must be 100% green before any main-merge — if you bypass, you
own the breakage.

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Rust | 1.81+ | Build toolchain (pinned via `rust-toolchain`) |
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
├── program/               # SP1 zkVM circuit (Zero-Knowledge proof logic)
│   └── src/
│       ├── lib.rs         # Types: AccountState, Coin, ProofData, ProgramInputs
│       ├── main.rs        # zkVM entrypoint (gated behind "zkvm" feature)
│       └── merkle/        # SMT + MMR implementations
├── script/                # Prover wrapper (stub for Docker, real SP1 for local)
│   └── src/lib.rs         # Prover struct: create_account(), update_account()
├── Cargo.toml             # Workspace root
├── Dockerfile             # Multi-stage Rust build
└── rust-toolchain         # Pinned Rust version (1.81.0)
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
| Crate | kebab-case | `zkcoins-program` |
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
- SP1 patches in `[patch.crates-io]` — only in the full workspace, removed in the Docker stub

## Architecture

### Request Flow

```
Client Request → Axum Router → server.rs (endpoint) → account_server.rs (logic)
                                                          ├── Prover (stub/SP1)
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

**Prover abstraction:** The `Prover` trait has two implementations:
- **Stub** (`script/src/lib.rs`) — returns mock proofs, compiles without SP1 toolchain
- **Real SP1** — requires the `succinct` Rust toolchain and SP1 SDK (not used in Docker)

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

### SP1 zkVM Circuit

The `program/` crate defines the Zero-Knowledge proof logic. It compiles to two targets:

| Target | Feature | Use |
|---|---|---|
| Native (x86/ARM) | default (no `zkvm`) | Library — types and Merkle trees used by server |
| RISC-V (SP1) | `zkvm` | zkVM binary — actual proof execution |

The `zkvm` feature gates the SP1 entrypoint and all `sp1_zkvm::` calls.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SP1_PROVER` | `mock` | `mock` (no proof), `cpu`, `cuda`, or `network` |
| `ESPLORA_URL` | `https://mutinynet.com/api` | Esplora API endpoint (electrs or public) |
| `IS_MAINNET` | `false` | `true` for Bitcoin Mainnet, `false` for Mutinynet/Signet |
| `NETWORK_NAME` | `Mutinynet` | Human-readable network name (returned by `/api/info`) |
| `PUBLISHER_KEY` | test key | 32-byte hex private key for inscription publishing. **Required on mainnet** |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

## Docker

```bash
docker build -t zkcoin/server .
docker run -p 4242:4242 \
  --network bitcoin \
  -e SP1_PROVER=mock \
  -e ESPLORA_URL=http://electrs-mainnet:3000 \
  zkcoin/server
```

The pre-built ELF (`elf/zkcoins-program`) is committed to the repo, so Docker builds do not require the Succinct toolchain — only standard Rust.

## Persistent State

The server writes the following files under its data volume (`/data` in the container, `zkcoins_server-data` Docker volume on dfxdev/dfxprd). Together they define the recoverable state:

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
# On the host running the server (e.g. dfxdev):
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
| `ci.yaml` | PR → develop, push to develop | `cargo fmt --check`, clippy (MVP + all-features + program lib), build (MVP + all-features). **Tests and coverage are NOT in CI** — see Setup above and issue #30. |
| `deploy-dev.yaml` | Push to develop | Docker build (ARM64) → push `zkcoin/server:beta` → deploy to DEV |
| `deploy-prd.yaml` | Push to main | Docker build (ARM64) → push `zkcoin/server:latest` → deploy to PRD |
| `auto-release-pr.yaml` | Push to develop | Creates Release PR (develop → main) |

Build time is ~5 minutes (Rust compilation on ARM64).

## Related Repos

- [zk-coins/app](https://github.com/zk-coins/app) — Web application (frontend)
- [zk-coins/docs](https://github.com/zk-coins/docs) — Documentation (docs.zkcoins.app)
