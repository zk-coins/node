# CLAUDE.md — zkCoins Server

Rust/Axum backend for zkcoins.app: account management, ZK proof generation, Bitcoin blockchain scanning, and nullifier publishing.

## Tech Stack

Rust 1.81 (pinned via `rust-toolchain`), Axum, SP1 zkVM (stub prover in Docker), Sparse Merkle Tree + Merkle Mountain Range, Bitcoin Taproot Inscriptions via Esplora API.

## Workspace Crates

| Crate | Path | Purpose |
|---|---|---|
| `server` | `server/` | Axum REST API, chain scanner, publisher |
| `program` | `program/` | SP1 zkVM circuit types (AccountState, Coin, ProofData), SMT + MMR |
| `shared` | `shared/` | Shared types (Commitment, Invoice, ClientAccount), crypto helpers |
| `script` | `script/` | Prover wrapper (stub for Docker, real SP1 for local) |

## Local Dev

```bash
# Run server (mock proofs, no SP1 toolchain needed)
SP1_PROVER=mock cargo run -p server
# Server starts on http://0.0.0.0:4242

# Build all crates
cargo build

# Run tests
cargo test

# Format (required before every commit)
cargo fmt

# Lint (treat warnings as errors)
cargo clippy
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SP1_PROVER` | `mock` | `mock` (stub) or `local` (real SP1) |
| `ESPLORA_URL` | `https://mutinynet.com/api` | Bitcoin node API |
| `BITCOIN_RPC_USER` | — | Bitcoin Core RPC username |
| `BITCOIN_RPC_PASSWORD` | — | Bitcoin Core RPC password |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check (`ok`) |
| `/api/mint` | POST | Mint coins (faucet) |
| `/api/send` | POST | Transfer coins |
| `/api/balance?address=<hex>` | GET | Query balance |
| `/api/proof/:id` | GET | Download coin proof (binary) |

## Git Workflow

- **`develop`** = default branch, active development, deploys to DEV
- **`main`** = protected, production releases, deploys to PRD
- Always create a feature branch from `develop`, open a PR to `develop`
- Never push directly to `main` or `develop`
- Never force-push, never amend
- Commit messages: English, concise, describe *what* not *how*

## Pre-Commit Checks

1. `cargo fmt` — format code
2. `cargo clippy` — no warnings allowed
3. `cargo build` — must compile
4. `cargo test` — must pass

## Code Conventions

- Edition 2021, `opt-level = 3` for dev builds (heavy crypto)
- No `unwrap()` in production paths — use `?` or `expect("descriptive message")`
- No `println!` — use `tracing::info!`, `tracing::warn!`, etc.
- Workspace dependencies in root `Cargo.toml`, crates reference `{ workspace = true }`
- Thread-safe state: `Arc<Mutex<State>>`

## Docker

```bash
docker build -t zkcoin/server .
docker run -p 4242:4242 --network bitcoin -e SP1_PROVER=mock zkcoin/server
```

- Image: `zkcoin/server` (`beta` = DEV, `latest` = PRD)
- ARM64 builds, ~5 min compile time
- Dockerfile removes `script` crate to avoid SP1 toolchain dependency

## CI/CD

| Workflow | Trigger | Action |
|---|---|---|
| `deploy-dev.yaml` | Push to develop | Build + push `zkcoin/server:beta` + deploy DEV |
| `deploy-prd.yaml` | Push to main | Build + push `zkcoin/server:latest` + deploy PRD |
| `auto-release-pr.yaml` | Push to develop | Creates Release PR (develop -> main) |

## Related Repos

| Repo | Purpose |
|---|---|
| [zk-coins/app](https://github.com/zk-coins/app) | Web frontend (PWA) |
| [zk-coins/docs](https://github.com/zk-coins/docs) | Documentation (docs.zkcoins.app) |
| [zk-coins/marketing](https://github.com/zk-coins/marketing) | Marketing website |
| [zk-coins/research](https://github.com/zk-coins/research) | Protocol research, paper PDF |
