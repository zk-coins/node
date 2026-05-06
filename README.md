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
| ZK Proofs | SP1 zkVM | Write proofs in standard Rust, no DSL |
| Data structures | SMT + MMR | Non-inclusion proofs + append-only history |
| Bitcoin | Taproot Inscriptions | 64-byte nullifiers, Esplora API scanning |
| Bitcoin index | electrs (Esplora) | Esplora REST API via shared Docker network `bitcoin` |

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
| `/api/info` | GET | Network info | `{ network }` |
| `/api/mint` | POST | Mint coins (faucet) | `{ proof_id }` |
| `/api/send` | POST | Transfer coins | `{ proof_id }` |
| `/api/balance?address=<hex>` | GET | Query balance | `{ balance }` |
| `/api/address` | GET | Generate receive addresses | `{ addresses }` |
| `/api/receive` | POST | Receive coins from sender | `{ success }` |
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
script/                # Prover (real SP1 zkVM — create_account, update_account)
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SP1_PROVER` | `mock` | `mock` (no proof), `cpu`, `cuda`, or `network` |
| `ESPLORA_URL` | `https://mutinynet.com/api` | Esplora API endpoint (electrs or public) |
| `IS_MAINNET` | `false` | `true` for Bitcoin Mainnet, `false` for Mutinynet/Signet |
| `NETWORK_NAME` | `Mutinynet` | Human-readable network name (returned by `/api/info`) |
| `PUBLISHER_KEY` | test key | 32-byte hex private key for inscription publishing. **Required on mainnet** — server panics if default test key is used |
| `RUST_LOG` | `info` | Log level |

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

## CI/CD

| Workflow | Trigger | Action |
|---|---|---|
| `deploy-dev.yaml` | Push develop | Docker (ARM64) → `zkcoin/server:beta` → DEV server |
| `deploy-prd.yaml` | Push main | Docker (ARM64) → `zkcoin/server:latest` → PRD server |
| `auto-release-pr.yaml` | Push develop | Creates Release PR (develop → main) |

Build time: ~5 minutes (Rust compilation on ARM64).

## Proving Strategy

Staged scaling for the SP1 prover:

| Stage | When to move | Configuration |
|---|---|---|
| **1. CPU (current)** | Baseline | `SP1_PROVER=cpu` running on Mac Studio M3 Ultra, 96 GB unified memory. Measure `update_account` / `create_account` latency under real load before scaling further. |
| **2. Succinct Prover Network** | CPU latency becomes a bottleneck | `SP1_PROVER=network` — no hardware commitment, requires PROVE token deposit and accepts token-price exposure. See [docs.succinct.xyz](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart). |
| **3. Self-hosted CUDA** | Network volume too costly or PROVE exposure undesirable | `SP1_PROVER=cuda` on x86 Linux with NVIDIA GPU (Compute Capability ≥ 8.6, ≥ 24 GB VRAM — RTX 4090 / 5090 / RTX 6000 Ada). Apple Silicon is not supported. |

Skip stages only with concrete latency or cost data, not assumptions.

## Open Tasks

- [x] CORS headers (allow frontend to call API directly)
- [x] Real SP1 proofs (CPU prover live on DEV/PRD)
- [ ] GPU acceleration (`SP1_PROVER=cuda`) or Succinct Prover Network
- [ ] Explorer endpoints (`/api/stats`, `/api/nullifiers`)
- [x] Publisher key from environment variable
- [ ] Light client support

## Related

| Repo | Purpose |
|---|---|
| [zk-coins/app](https://github.com/zk-coins/app) | Web application (frontend, PWA) |
| [zk-coins/docs](https://github.com/zk-coins/docs) | Documentation ([docs.zkcoins.app](https://docs.zkcoins.app)) |
| [zk-coins/research](https://github.com/zk-coins/research) | Protocol research, upstream repos, paper PDF |

## Protocol

Based on [Shielded CSV](https://eprint.iacr.org/2025/068) by Jonas Nick (Blockstream), Liam Eagen (Alpen Labs), Robin Linus (ZeroSync). Server code derived from [ZeroSync/ZKCoins](https://github.com/ZeroSync/ZKCoins).

## License

MIT
