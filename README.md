# zkCoins Server

Rust/Axum backend for [zkcoins.app](https://zkcoins.app) — account management, ZK proof generation, Bitcoin blockchain scanning, and nullifier publishing.

## Live

| Environment | URL | Image |
|---|---|---|
| **PRD** | [api.zkcoins.app](https://api.zkcoins.app) | `zkcoin/server:latest` |
| **DEV** | [dev-api.zkcoins.app](https://dev-api.zkcoins.app) | `zkcoin/server:beta` |

## Stack

| Layer | Technology | Why |
|---|---|---|
| Language | Rust 1.81 | Same as ZK circuits, memory safety, performance |
| Web framework | Axum | Built on Tokio, idiomatic async Rust |
| ZK Proofs | SP1 zkVM (stub) | Write proofs in standard Rust, no DSL |
| Data structures | SMT + MMR | Non-inclusion proofs + append-only history |
| Bitcoin | Taproot Inscriptions | 64-byte nullifiers, Esplora API scanning |
| Bitcoin node | bitcoind-mainnet | Shared Docker network `bitcoin`, port 8332 |

Full rationale: [docs.zkcoins.app/tech-decisions](https://docs.zkcoins.app/tech-decisions)

## Running

Requires access to a Bitcoin node. See [Backend docs](https://docs.zkcoins.app/infrastructure/backend).

```bash
SP1_PROVER=mock cargo run -p server
# Server starts on http://0.0.0.0:4242
```

## API

| Endpoint | Method | Description | Response |
|---|---|---|---|
| `/health` | GET | Health check | `ok` (200) |
| `/api/mint` | POST | Mint coins (faucet) | `{ proof_id }` |
| `/api/send` | POST | Transfer coins | `{ proof_id }` |
| `/api/balance?address=<hex>` | GET | Query balance | `{ balance }` |
| `/api/proof/:id` | GET | Download coin proof | Binary |

## Project Structure

```
server/                # Axum REST API
├── src/
│   ├── main.rs        # Entry point, chain scanner, bind 0.0.0.0:4242
│   ├── server.rs      # REST endpoints + /health
│   ├── account_server.rs  # Account logic, coin proofs, prover calls
│   ├── state.rs       # Sparse Merkle Tree + Merkle Mountain Range
│   ├── scanner.rs     # Bitcoin block scanner (30s polling, prefix 4242)
│   └── publisher.rs   # Taproot Inscription broadcaster (commit/reveal)
shared/                # Shared types (Commitment, Invoice, ClientAccount)
program/               # SP1 zkVM circuit types (AccountState, Coin, ProofData)
│   └── src/merkle/    # SMT + MMR implementations
script/                # Prover (stub — returns mock proofs, no SP1 dependency)
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SP1_PROVER` | `mock` | `mock` (stub) or `local` (real SP1) |
| `ESPLORA_URL` | `https://mutinynet.com/api` | Bitcoin node API |
| `BITCOIN_RPC_USER` | — | Bitcoin Core RPC username |
| `BITCOIN_RPC_PASSWORD` | — | Bitcoin Core RPC password |
| `RUST_LOG` | `info` | Log level |

## Docker

```bash
docker build -t zkcoin/server .
docker run -p 4242:4242 \
  --network bitcoin \
  -e SP1_PROVER=mock \
  -e ESPLORA_URL=http://bitcoind-mainnet:8332 \
  zkcoin/server
```

The stub prover (`script/src/lib.rs`) removes the SP1 dependency — no succinct toolchain needed for Docker builds.

## CI/CD

| Workflow | Trigger | Action |
|---|---|---|
| `deploy-dev.yaml` | Push develop | Docker (ARM64) → `zkcoin/server:beta` → dfxdev |
| `deploy-prd.yaml` | Push main | Docker (ARM64) → `zkcoin/server:latest` → dfxprd |
| `auto-release-pr.yaml` | Push develop | Creates Release PR (develop → main) |

Build time: ~5 minutes (Rust compilation on ARM64).

## Open Tasks

- [ ] CORS headers (allow frontend to call API directly)
- [ ] Real SP1 proofs (replace stub prover with GPU/Succinct network)
- [ ] Explorer endpoints (`/api/stats`, `/api/nullifiers`)
- [ ] Publisher key from environment variable (currently hardcoded)
- [ ] Light client support

## Related

| Repo | Purpose |
|---|---|
| [zk-coins/app](https://github.com/zk-coins/app) | Web application (frontend, PWA) |
| [zk-coins/docs](https://github.com/zk-coins/docs) | Documentation ([docs.zkcoins.app](https://docs.zkcoins.app)) |

## Protocol

Based on [Shielded CSV](https://eprint.iacr.org/2025/068) by Jonas Nick (Blockstream), Liam Eagen (Alpen Labs), Robin Linus (ZeroSync). Server code derived from [ZeroSync/ZKCoins](https://github.com/ZeroSync/ZKCoins).

## License

MIT
