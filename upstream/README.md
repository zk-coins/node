# Upstream References

Git submodules of the original repositories that zkCoins is built on. These are **read-only references** — we don't modify them.

## Repositories

| Directory | Source | Description |
|---|---|---|
| `ShieldedCSV/` | [ShieldedCSV/ShieldedCSV](https://github.com/ShieldedCSV/ShieldedCSV) | Paper reference code (Rust). PCD Compliance Predicate — the protocol specification in code form. All crypto primitives are `unimplemented!()`. |
| `ZeroSync-ZKCoins/` | [ZeroSync/ZKCoins](https://github.com/ZeroSync/ZKCoins) | **Our primary upstream.** Functional prototype with SP1 zkVM, WASM client, Axum server, Taproot Inscriptions. Our `server/`, `shared/`, `program/` crates are derived from this. |
| `rust-bitcoincore-rpc/` | [ZeroSync/rust-bitcoincore-rpc](https://github.com/ZeroSync/rust-bitcoincore-rpc) | Fork with `submitpackage` RPC updates for Bitcoin Core integration. |
| `BitVM-zkCoins/` | [BitVM/zkCoins](https://github.com/BitVM/zkCoins) | Historical Plonky2 recursive circuit experiments. Predecessor to ZeroSync implementation. |

## Usage

Submodules are not cloned by default. To fetch them:

```bash
git submodule update --init --recursive
```

## Why Submodules

- The upstream code is the reference for our implementation
- Developers can `grep` and `diff` against the original
- AI coding tools (Claude Code) have immediate access to upstream context
- No separate clone step needed
