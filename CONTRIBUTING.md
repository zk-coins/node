# Contributing to zkCoins Server

This guide covers everything you need to develop, test, and deploy the zkCoins backend.

## Quick Start

```bash
git clone https://github.com/zk-coins/server.git
cd server
SP1_PROVER=mock cargo run -p server
# Server starts on http://127.0.0.1:4242
```

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
| `SP1_PROVER` | `mock` | `mock` (stub proofs) or `local` (real SP1) |
| `ESPLORA_URL` | `https://mutinynet.com/api` | Bitcoin node API |
| `BITCOIN_RPC_USER` | — | Bitcoin Core RPC username |
| `BITCOIN_RPC_PASSWORD` | — | Bitcoin Core RPC password |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

## Docker

```bash
docker build -t zkcoin/server .
docker run -p 4242:4242 \
  --network bitcoin \
  -e SP1_PROVER=mock \
  -e ESPLORA_URL=http://bitcoind-mainnet:8332 \
  zkcoin/server
```

The Dockerfile removes the `script` crate from the workspace (via `sed`) to avoid requiring the SP1 toolchain. The stub prover in `script/src/lib.rs` provides the same API surface with mock proofs.

### Bitcoin Node

The server needs a Bitcoin node. In production, it connects via the shared Docker network `bitcoin` to `bitcoind-mainnet:8332`. Requirements:
- `txindex=1`
- `rest=1`
- `server=1`

See [docs.zkcoins.app/infrastructure/backend](https://docs.zkcoins.app/infrastructure/backend) for full setup.

## CI/CD

| Workflow | Trigger | Action |
|---|---|---|
| `deploy-dev.yaml` | Push to develop | Docker build (ARM64) → push `zkcoin/server:beta` → deploy to DEV |
| `deploy-prd.yaml` | Push to main | Docker build (ARM64) → push `zkcoin/server:latest` → deploy to PRD |
| `auto-release-pr.yaml` | Push to develop | Creates Release PR (develop → main) |

Build time is ~5 minutes (Rust compilation on ARM64).

## API Reference

| Endpoint | Method | Description | Success |
|---|---|---|---|
| `/api/mint` | POST | Mint coins from minting account | `{ proof_id }` |
| `/api/send` | POST | Transfer coins between accounts | `{ proof_id }` |
| `/api/balance?address=<hex>` | GET | Query account balance | `{ balance }` |
| `/api/proof/:id` | GET | Download coin proof (binary) | Binary data |

## Related Repos

- [zk-coins/app](https://github.com/zk-coins/app) — Web application (frontend)
- [zk-coins/docs](https://github.com/zk-coins/docs) — Documentation (docs.zkcoins.app)
