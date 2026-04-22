# zkCoins Server

Rust/Axum backend for [zkcoins.app](https://zkcoins.app) — account management, ZK proof generation, Bitcoin blockchain scanning, and nullifier publishing.

## Stack

- Rust 1.81, Axum (async web framework)
- SP1 zkVM (Succinct) for Zero-Knowledge proofs
- Sparse Merkle Tree + Merkle Mountain Range
- Bitcoin Taproot Inscriptions via Esplora API

## Running

```bash
SP1_PROVER=mock cargo run -p server
# Server starts on http://127.0.0.1:4242
```

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/mint` | POST | Mint coins (testnet faucet) |
| `/api/send` | POST | Transfer coins between accounts |
| `/api/balance` | GET | Query account balance |
| `/api/proof/:id` | GET | Download coin proof |

## Docker

```bash
docker build -t zkcoins-server .
docker run -p 4242:4242 -e SP1_PROVER=mock zkcoins-server
```

## Related Repos

- [zk-coins/app](https://github.com/zk-coins/app) — Web application
- [zk-coins/docs](https://github.com/zk-coins/docs) — Documentation (docs.zkcoins.app)

## License

MIT
