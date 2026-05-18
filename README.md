# zkCoins Server

Rust/Axum backend for [zkcoins.app](https://zkcoins.app) — account management, ZK proof generation, Bitcoin blockchain scanning, and nullifier publishing.

## Live

| Environment | URL                                                | Image                  |
| ----------- | -------------------------------------------------- | ---------------------- |
| **PRD**     | [api.zkcoins.app](https://api.zkcoins.app)         | `zkcoin/server:latest` |
| **DEV**     | [dev-api.zkcoins.app](https://dev-api.zkcoins.app) | `zkcoin/server:beta`   |

## Stack

| Layer           | Technology           | Why                                                  |
| --------------- | -------------------- | ---------------------------------------------------- |
| Language        | Rust 1.81            | Same as ZK circuits, memory safety, performance      |
| Web framework   | Axum                 | Built on Tokio, idiomatic async Rust                 |
| ZK Proofs       | SP1 zkVM             | Write proofs in standard Rust, no DSL                |
| Data structures | SMT + MMR            | Non-inclusion proofs + append-only history           |
| Bitcoin         | Taproot Inscriptions | 64-byte nullifiers, Esplora API scanning             |
| Bitcoin index   | electrs (Esplora)    | Esplora REST API via shared Docker network `bitcoin` |

Full rationale: [docs.zkcoins.app/tech-decisions](https://docs.zkcoins.app/tech-decisions)

## Contributing

**New PRs may only merge into `develop` if test coverage is 100% on the activated surface.** Code behind a Cargo feature (`address-list`, `faucet`, `usernames`, `lnurl`) is excluded from the MVP measurement — feature-gated routes do not need to be tested as long as the feature stays off in the PRD build. Concretely:

- `cargo llvm-cov -p server` (no `--all-features`) must report 100% lines, statements, branches, and functions on the MVP build. CI enforces this with `--fail-under-lines 100`. The current baseline is below 100% — the regression-block threshold is set to the current measured value and the goal is to lift it to 100% via follow-up PRs.
- Defensive code that genuinely cannot be reached in unit tests (e.g. the publisher's Bitcoin-broadcast path that requires a signet/regtest node, the `main.rs` runtime bootstrap) is excluded from the measured scope at the file level rather than tested.
- The branch is protected on GitHub: a PR cannot be merged while CI is red.

The same rule applies to `zk-coins/app` (gated `NEXT_PUBLIC_ENABLE_*` flags are excluded from the measured scope).

## Features

API endpoints, background services, their activation status, and the tests that cover them.

**Status legend** (current behaviour): `always` = endpoint/service always compiled in · `env` = behavior controlled by a runtime env var · `feature` = compiled in only when the named Cargo feature is enabled at build time, otherwise excluded from the binary · `planned` = listed in Open Tasks, not yet implemented.

**Triage legend** (MVP testing decision): `mvp` = in MVP scope, must reach full test coverage before launch · `gate` = not in MVP scope; hidden behind a Cargo feature, default off, no test coverage required · `planned` = not in scope for MVP.

**Coverage legend:** unit % refers to `cargo-llvm-cov` line coverage of the module that implements the function (latest run, `SP1_PROVER=mock` with `--all-features`). `—` means no test exists.

| Function                             | Trigger                               | Status                   | Triage  | Tests                         |
| ------------------------------------ | ------------------------------------- | ------------------------ | ------- | ----------------------------- |
| Health check                         | `GET /health`                         | always                   | mvp     | 75% (server)                  |
| Network info                         | `GET /api/info`                       | env¹                     | mvp     | 75% (server)                  |
| Get balance                          | `GET /api/balance?address=<hex>`      | always                   | mvp     | 75% (server)                  |
| List all addresses                   | `GET /api/address`                    | feature (`address-list`) | gate    | 75% (server)                  |
| Mint coins (faucet, single-phase)    | `POST /api/mint`                      | feature (`faucet`)²      | gate    | 91% (account)                 |
| Send — phase 1 (generate proof)      | `POST /api/send`                      | env²                     | mvp     | 75% (server)                  |
| Send — phase 2 (commit + broadcast)  | `POST /api/commit`                    | env³                     | mvp     | 75% (server) · 0% (publisher) |
| Receive coin                         | `POST /api/receive`                   | always                   | mvp     | 91% (account)                 |
| Download coin proof                  | `GET /api/proof/:id`                  | always                   | mvp     | 75% (server)                  |
| Claim username                       | `POST /api/username/claim`            | feature (`usernames`)    | gate    | 98% (username)                |
| Resolve username                     | `GET /api/username/resolve/:username` | feature (`usernames`)    | gate    | 98% (username)                |
| LNURL-Pay metadata                   | `GET /.well-known/lnurlp/:username`   | feature (`lnurl`)        | gate    | 75% (server)                  |
| LNURL-Pay callback                   | `GET /lnurl/pay/:username`            | feature (`lnurl`)        | gate    | 75% (server)                  |
| Bitcoin block scanner (background)   | Loop in `main.rs`, 30 s poll          | env⁴                     | mvp     | 51% (scanner) · 4% (main)     |
| State persistence (SMT/MMR write)    | Scanner callback on commitment match  | always                   | mvp     | 97% (state)                   |
| Taproot inscription broadcast        | Called by `/api/commit`               | env³                     | mvp     | 0% (publisher)                |
| Publisher UTXO lookup                | Internal, before broadcast            | env³                     | mvp     | 0% (publisher)                |
| Explorer endpoints (`/api/stats`, …) | n/a                                   | planned                  | planned | —                             |
| Light client support                 | n/a                                   | planned                  | planned | —                             |

¹ `NETWORK_NAME` env var controls the string returned. `IS_MAINNET=true` flips the default to `"Mainnet"`.
² Proof generation routes through SP1. `SP1_PROVER=mock` skips real proving; `cpu`/`cuda`/`network` perform actual proving (latency and resource cost vary by stage — see [Proving Strategy](#proving-strategy)).
³ Requires `PUBLISHER_KEY` set to a real funded key and `ESPLORA_URL` reachable. With the default test key the server panics on `IS_MAINNET=true` startup; on testnet it accepts the call but broadcast will fail without funded UTXOs.
⁴ Scanner depends on `ESPLORA_URL` being reachable; on connection failure it backs off and retries.

### Cargo features

All non-MVP routes are gated by Cargo features so the disabled handler functions, helper structs, and `AppState` fields are excluded from the binary at compile time. With a feature off, the route is never registered and the fallback responds with `404`. There is no runtime path that can reach a disabled handler. Defaults are empty (fail-closed): the PRD image build passes no features, the DEV image build passes all four.

| Feature        | Gates                                                                                                                                                 |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `address-list` | `GET /api/address`                                                                                                                                    |
| `faucet`       | `POST /api/mint`, `MintRequest`, `AppState::minting_account`                                                                                          |
| `usernames`    | `POST /api/username/claim`, `GET /api/username/resolve/:u`, `ClaimUsernameRequest`, `UsernameStore::{claim,save_to_file}`, `AppState::usernames_path` |
| `lnurl`        | `GET /.well-known/lnurlp/:u`, `GET /lnurl/pay/:u` (depends on `usernames`)                                                                            |

Build the MVP-only binary (PRD): `cargo build --release -p server`. Build with everything enabled (DEV / tests): `cargo build --release -p server --all-features`. The Docker `FEATURES` build arg accepts a comma-separated list and is forwarded to `cargo build --features`.

### Triage gaps

Features tagged `mvp` whose current test coverage is insufficient — these block "100% on activated features":

- **Send — phase 2 (commit + broadcast)** — only error-path tests (`commit_missing_body`, `commit_nonexistent_proof_id`); no happy-path test that exercises the publisher
- **Download coin proof** — only 404 path tested; no test for the happy-path binary stream
- **Bitcoin block scanner** — parsing helpers covered (`scanner.rs` 51%); no integration test against a real Bitcoin block
- **Taproot inscription broadcast** — `publisher.rs` 0%, no tests at all (would need signet/regtest + funded publisher key)
- **Publisher UTXO lookup** — `publisher.rs` 0%, no tests

### Details

#### Health check

- **Module:** `server.rs::main_app` route handler
- **Behaviour:** returns the literal string `"ok"` with HTTP 200
- **Tests:** `server.rs::tests::health_returns_ok`

#### Network info

- **Module:** `server.rs::info_handler`
- **Behaviour:** returns `{ "network": NETWORK_NAME }`. `NETWORK_NAME` defaults to `Mutinynet` when `IS_MAINNET=false`, `Mainnet` when `true`
- **Tests:** `server.rs::tests::info_returns_network_name`

#### Get balance

- **Module:** `server.rs::get_balance_handler` → `account_server.rs::AccountServer::get_account_balance`
- **Behaviour:** address parsed as hex pubkey, looks up the account. Returns `{ balance, username? }`. A well-formed address with no on-chain activity yields `200 OK` with `balance: 0` (canonical zero state, not 404). The minting address returns `u64::MAX`. Malformed input — invalid hex, wrong length, or a missing `address` query parameter — returns `422`
- **Tests:** `server.rs::tests::balance_*` (6 tests covering happy path, unknown address with and without a claimed username, invalid hex, missing param, wrong length)

#### List all addresses

- **Module:** `server.rs::get_address_handler` → `account_server.rs::AccountServer::get_addresses`
- **Behaviour:** returns all known addresses as hex strings. Intended for explorer/debug use, not user-facing
- **Tests:** `server.rs::tests::address_returns_list`

#### Mint coins (faucet, single-phase)

- **Module:** `server.rs::mint_handler` → `account_server.rs::send_coins` with the server-held minting account
- **Behaviour:** server signs commitment itself (no client roundtrip) using the minting key
- **Proof generation:** `zkcoins_prover::Prover::create_account` (or `update_account` for the receiver) under SP1
- **Tests:** `account_server.rs::tests::test_create_minting_account`, `test_mint_single_invoice`, `test_mint_repro_live_setup`

#### Send — phase 1 (generate proof)

- **Module:** `server.rs::send_coin_handler` → `verify_send_signature` (Schnorr over `SHA256(account_address || recipient || amount || timestamp)`, ±5 min skew) → `account_server.rs::send_coins`
- **Behaviour:** returns `{ proof_id, account_state_hash, output_coins_root }`. Proof is persisted under `data/proofs/<id>.bin` for later commit
- **Tests:** request-layer tests in `server.rs::tests::send_*` and `send_signature_*` (12 tests covering parser, signature verification, replay). Proof generation itself is not exercised — tests run with `SP1_PROVER=mock`

#### Send — phase 2 (commit + broadcast)

- **Module:** `server.rs::commit_handler` → `publisher.rs::create_and_broadcast_inscription`
- **Behaviour:** verifies the client's Schnorr commitment, builds a Taproot commit+reveal tx pair, mines a txid prefix `4242` (max 400 000 attempts in `publisher.rs::inscription_txs`), broadcasts both txs, then calls `account_server.rs::receive_coin` to deliver the coin to the recipient
- **Tests:** `server.rs::tests::commit_missing_body_returns_error`, `commit_nonexistent_proof_id_returns_404`. **No happy-path broadcast test** — would require a live Bitcoin signet/regtest

#### Receive coin

- **Module:** `server.rs::receive_coin_handler` → `account_server.rs::receive_coin`
- **Behaviour:** replay-protected via per-account `coin_history` SMT
- **Tests:** `account_server.rs::tests::test_receive_duplicate_coin_rejected`, `test_receive_updates_balance`

#### Download coin proof

- **Module:** `server.rs::get_proof_handler` → `ProofStore::get_proof`
- **Behaviour:** streams the binary serialised `CoinProof` (`Vec<u8>` from bincode) with content-type `application/octet-stream`
- **Tests:** `server.rs::tests::proof_not_found_returns_404`

#### Claim username

- **Module:** `server.rs::claim_username_handler` → `username.rs::UsernameStore::claim`
- **Behaviour:** verifies Schnorr signature over `SHA256(username || pubkey || timestamp)` (5 min skew); writes to `usernames.bin` (atomic)
- **Tests:** `server.rs::tests::claim_username_*` (3 tests) + `username.rs::tests::*` (8 tests covering valid charset, duplicates, persistence)

#### Resolve username

- **Module:** `server.rs::resolve_username_handler` → `username.rs::UsernameStore::resolve`
- **Behaviour:** if exact username unknown, falls back to hex prefix matching against known addresses. Case-insensitive
- **Tests:** `server.rs::tests::resolve_unknown_username_returns_404`, `resolve_minting_address_by_hex_prefix`, `username.rs::tests::resolve_is_case_insensitive`

#### LNURL-Pay metadata and callback

- **Module:** `server.rs::lnurlp_handler`, `server.rs::lnurl_callback_handler`
- **Behaviour:** thin stub implementation of [LNURL-pay](https://github.com/lnurl/luds/blob/luds/06.md). Metadata returned for known usernames; callback returns a phase-2 error (not wired to a real BOLT-11 invoice generator yet)
- **Tests:** `server.rs::tests::lnurlp_known_address_returns_pay_request`, `lnurlp_unknown_user_returns_404`, `lnurl_pay_callback_returns_phase2_error`

#### Bitcoin block scanner

- **Module:** `scanner.rs::scan_for_inscriptions` / `InscriptionScanner::scan_from_block`. Loop spawned from `main.rs::main`. State saved between runs in `data/latest_block.bin`
- **Behaviour:** polls Esplora; filters txs by txid prefix `4242`; extracts Taproot inscription content via `extract_inscription_content`; deserialises as `Commitment`; calls callback in `main.rs` which verifies the signature and updates state
- **Tests:** `scanner.rs::tests::parse_valid_inscription_into_commitment`, `reject_invalid_inscription_data`, `verify_commitment_signature_after_deserialization`, `parse_multi_chunk_inscription`. **No integration test** with a real Bitcoin block

#### State persistence (SMT/MMR write)

- **Module:** `state.rs::State::update` (atomic writes via `atomic_write` helper)
- **Behaviour:** on each verified commitment: append SMT root to MMR, persist `smt.bin`, `mmr.bin`, `latest_block.bin`
- **Tests:** `state.rs::tests::*` (9 tests covering single + multiple updates, persistence roundtrip, proof generation/verification, empty MMR edge cases)

#### Taproot inscription broadcast and Publisher UTXO lookup

- **Module:** `publisher.rs::create_and_broadcast_inscription`, `inscription_txs`, `broadcast_inscription_txs`, `get_publisher_utxo`
- **Behaviour:** `inscription_txs` mines the commit txid prefix `4242` (uses random nonce loop, up to 400 000 attempts). `get_publisher_utxo` filters Esplora UTXOs for the publisher's Taproot address, requires ≥ 800 sats
- **Tests:** **none** — would require a live signet/regtest node and a funded publisher key

#### Planned

- **Explorer endpoints (`/api/stats`, `/api/nullifiers`)** — to power the `zkcoins.space` companion app
- **Light client support** — let wallets verify nullifier set membership without scanning the chain themselves

### Configuration

| Variable        | Default                     | Effect                                                                                                                                                        |
| --------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SP1_PROVER`    | `cpu`                       | `mock` (no real proofs, instant), `cpu`, `cuda`, `network`. Tests run with `mock`.                                                                            |
| `ESPLORA_URL`   | `https://mutinynet.com/api` | Esplora API endpoint (electrs or public)                                                                                                                      |
| `IS_MAINNET`    | `false`                     | `true` for Bitcoin Mainnet, `false` for Mutinynet/Signet                                                                                                      |
| `NETWORK_NAME`  | `Mutinynet` / `Mainnet`     | Human-readable name returned by `/api/info`. Default depends on `IS_MAINNET`                                                                                  |
| `PUBLISHER_KEY` | test key                    | 32-byte hex private key for inscription publishing. **Required on mainnet** — server panics on startup if default test key is detected with `IS_MAINNET=true` |
| `RUST_LOG`      | `info`                      | Log level                                                                                                                                                     |

Runtime config above shapes _behaviour_ of compiled-in routes. _Which_ routes are compiled in is decided at build time by Cargo features — see [Cargo features](#cargo-features).

### Background services

Spawned from `main.rs::main`:

1. **REST server** (`tokio::spawn` of `start_rest_server`) — Axum app bound to `0.0.0.0:4242`
2. **Block scanner** (driven directly in main, not spawned) — `scan_for_inscriptions` runs an infinite loop polling Esplora every 30 s and writing state on each verified commitment

### Tests

| Stack            | Command                                                   | What it covers                                                                                             |
| ---------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `cargo test`     | `SP1_PROVER=mock cargo test -p server`                    | 45 tests covering only MVP code paths — what the PRD binary actually contains                              |
| `cargo test`     | `SP1_PROVER=mock cargo test -p server --all-features`     | 58 tests including the gated `address-list`, `faucet`, `usernames`, and `lnurl` routes                     |
| `cargo-llvm-cov` | `SP1_PROVER=mock cargo llvm-cov -p server --all-features` | Line coverage (latest run: **69.0% lines · 55.0% regions · 76.4% functions**) — measured with all gates on |

Per-module line coverage (latest run, all features):

| Module              | Tests | Line % |
| ------------------- | ----- | ------ |
| `server.rs`         | 37    | 74.55% |
| `account_server.rs` | 6     | 91.12% |
| `state.rs`          | 9     | 97.01% |
| `username.rs`       | 8     | 98.29% |
| `scanner.rs`        | 4     | 50.99% |
| `publisher.rs`      | 0     | 0.00%  |
| `main.rs`           | 0     | 4.33%  |

`publisher.rs` and `main.rs` are untested by design — they require a live Bitcoin node and a funded publisher key. CI runs both the MVP build (`cargo build/clippy`) and the all-features build, plus `cargo test --all-features`. Coverage is collected ad-hoc, not in CI.

## Running

Requires access to a Bitcoin node. See [Backend docs](https://docs.zkcoins.app/infrastructure/backend).

```bash
SP1_PROVER=mock cargo run -p server
# Server starts on http://0.0.0.0:4242
```

## Two-Phase Send Flow

User sends require a two-phase flow because the server doesn't hold sender private keys:

1. **`POST /api/send`** — server generates ZK proof, returns `proof_id` + `account_state_hash` + `output_coins_root`
2. **Client signs commitment** — `Schnorr(hash_concat(account_state_hash, output_coins_root))` with BIP-32 key at `numPubkeys`
3. **`POST /api/commit`** — server verifies commitment, broadcasts Taproot inscription, delivers coin to recipient via `receive_coin`

Mint uses a single-phase flow (server holds the minting account key).

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
├── src/merkle/        # SMT + MMR implementations
script/                # Prover (real SP1 zkVM — create_account, update_account)
```

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

| Workflow               | Trigger      | Action                                               |
| ---------------------- | ------------ | ---------------------------------------------------- |
| `deploy-dev.yaml`      | Push develop | Docker (ARM64) → `zkcoin/server:beta` → DEV server   |
| `deploy-prd.yaml`      | Push main    | Docker (ARM64) → `zkcoin/server:latest` → PRD server |
| `auto-release-pr.yaml` | Push develop | Creates Release PR (develop → main)                  |

Build time: ~5 minutes (Rust compilation on ARM64).

## Proving Strategy

Staged scaling for the SP1 prover:

| Stage                          | When to move                                            | Configuration                                                                                                                                                                                        |
| ------------------------------ | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **0. Mock (DEV)**              | Development & testing                                   | `SP1_PROVER=mock` — no real proofs, instant responses. Required on DEV because CPU prover causes OOM (SP1 `update_account` exceeds available memory).                                                |
| **1. CPU (PRD)**               | Production baseline                                     | `SP1_PROVER=cpu` running on Mac Studio M3 Ultra, 96 GB unified memory. `create_account` works, `update_account` needs memory tuning.                                                                 |
| **2. Succinct Prover Network** | CPU latency becomes a bottleneck                        | `SP1_PROVER=network` — no hardware commitment, requires PROVE token deposit and accepts token-price exposure. See [docs.succinct.xyz](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart). |
| **3. Self-hosted CUDA**        | Network volume too costly or PROVE exposure undesirable | `SP1_PROVER=cuda` on x86 Linux with NVIDIA GPU (Compute Capability ≥ 8.6, ≥ 24 GB VRAM — RTX 4090 / 5090 / RTX 6000 Ada). Apple Silicon is not supported.                                            |

Skip stages only with concrete latency or cost data, not assumptions.

## Open Tasks

- [ ] GPU acceleration (`SP1_PROVER=cuda`) or Succinct Prover Network
- [ ] Explorer endpoints (`/api/stats`, `/api/nullifiers`)
- [ ] Light client support

## Related

| Repo                                                      | Purpose                                                      |
| --------------------------------------------------------- | ------------------------------------------------------------ |
| [zk-coins/app](https://github.com/zk-coins/app)           | Web application (frontend, PWA)                              |
| [zk-coins/docs](https://github.com/zk-coins/docs)         | Documentation ([docs.zkcoins.app](https://docs.zkcoins.app)) |
| [zk-coins/research](https://github.com/zk-coins/research) | Protocol research, upstream repos, paper PDF                 |

## Design Documents

| Document                                                | Scope                                                                                                          | Status |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------ |
| [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) | Trustless LN ↔ zkCoins atomic swap design (HTLC on inscription funding tx)                                     | Draft  |
| [`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md)                  | BTC ↔ zkCoins trustless mint/burn bridge — landscape, BitVM2 / Glock / Mosaic comparison, N=100 federation target | Draft  |
| [`BRIDGE_MVP.md`](./BRIDGE_MVP.md)                      | Engineering spec for the bridge MVP — 8 phases, file-by-file, 5–7 months effort estimate                       | Draft  |

These documents describe the bridge and swap roadmap. They
presuppose the Plonky2 migration currently on `feat/plonky2-migration`
(PR #17) and cross-reference `SPEC.md`, `MIGRATION_RESEARCH.md`, and
`ROADMAP.md`, which currently live on that branch.

## Protocol

Based on [Shielded CSV](https://eprint.iacr.org/2025/068) by Jonas Nick (Blockstream), Liam Eagen (Alpen Labs), Robin Linus (ZeroSync). Server code derived from [ZeroSync/ZKCoins](https://github.com/ZeroSync/ZKCoins).

## License

MIT
