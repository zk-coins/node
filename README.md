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
| Language        | Rust nightly         | Required for Plonky2 (`feature(specialization)`)     |
| Web framework   | Axum                 | Built on Tokio, idiomatic async Rust                 |
| ZK Proofs       | Plonky2 + Poseidon-Goldilocks (cyclic recursion) | Server-side, no zkVM, no external prover dependency  |
| Data structures | SMT + MMR (Poseidon) | Non-inclusion proofs + append-only history           |
| Bitcoin         | Taproot Inscriptions | 64-byte nullifiers, Esplora API scanning             |
| Bitcoin index   | electrs (Esplora)    | Esplora REST API via shared Docker network `bitcoin` |

Full rationale: [docs.zkcoins.app/tech-decisions](https://docs.zkcoins.app/tech-decisions)

## Trust Model

Proof generation runs **inside this server process**. `AccountServer::send_coins` (`server/src/account_server.rs`) calls `self.prover.prove_account_update_with_in_and_out_coins_and_sources(...)` (and the `prove_initial_*` variant for first-time accounts) on every send / receive / mint. ZK proving requires the full private witness, so the server sees, in cleartext:

- Sender, recipient, and amount of every coin movement
- The complete in-coin / out-coin / source-aggregator slot layout per account
- Account history roots, Merkle proofs, and inclusion-proof witnesses
- Usernames and their bound coin sets (`UsernameStore`)
- Postgres rows persisting all of the above (`server/migrations/000{1,2}_*.sql`)

The **on-chain footprint stays private** — Plonky2 ensures that the public outputs (nullifiers, history roots, Taproot inscriptions) carry no readable transaction data. Block explorers and chain analytics see only opaque 64-byte commitments. The trust boundary is therefore the **server operator**, not the chain.

| | Hosted (`api.zkcoins.app`) | Self-hosted |
| --- | --- | --- |
| On-chain privacy (vs. block explorers) | ✅ | ✅ |
| Operator sees plaintext transaction data | ❌ Yes — DFX runs the hosted node | ✅ No |
| Setup effort | ✅ None | ⚠️ Postgres + electrs + Bitcoin node |

**If you need full transaction privacy, run your own server.** Every release is shipped as `zkcoin/server:latest` (see [Live](#live)), the build recipe is [`Dockerfile`](./Dockerfile), and runtime knobs are documented in [Configuration](#configuration). Point the [zkcoins.app](https://zkcoins.app) client at your self-hosted instance for end-to-end self-custody of transaction data.

## Contributing

**New PRs may only merge into `develop` if test coverage is 100% on the activated surface.** Code behind a Cargo feature (`address-list`, `usernames`, `lnurl`) is excluded from the MVP measurement — feature-gated routes do not need to be tested because both DEV and PRD ship the MVP-only binary with every Cargo feature off. (Mint is part of the MVP and is permanently compiled in — no Cargo feature gate.) Concretely:

- `cargo llvm-cov -p server` (no `--all-features`) must report 100% lines + 100% functions on the activated MVP surface. CI enforces this with `--fail-under-lines 100 --fail-under-functions 100` in the `Coverage Gate (100% lines + functions)` job. The current `develop` baseline is at the gate.
- Defensive code that genuinely cannot be reached in unit tests (e.g. the publisher's Bitcoin-broadcast path that requires a signet/regtest node, the `main.rs` runtime bootstrap) is excluded from the measured scope at the file level rather than tested.
- The branch is protected on GitHub: a PR cannot be merged while CI is red.

The same rule applies to `zk-coins/app` (gated `NEXT_PUBLIC_ENABLE_*` flags are excluded from the measured scope).

## Features

API endpoints, background services, their activation status, and the tests that cover them.

**Status legend** (current behaviour): `always` = endpoint/service always compiled in · `env` = behavior controlled by a runtime env var · `feature` = compiled in only when the named Cargo feature is enabled at build time, otherwise excluded from the binary · `planned` = listed in Open Tasks, not yet implemented.

**Triage legend** (MVP testing decision): `mvp` = in MVP scope, must reach full test coverage before launch · `gate` = not in MVP scope; hidden behind a Cargo feature, default off, no test coverage required · `planned` = not in scope for MVP.

**Coverage legend:** unit % refers to `cargo-llvm-cov` line coverage of the module that implements the function. The MVP-scope per-module summary is in § "Test stack" below; the authoritative live numbers are in the `Coverage Gate` CI job. `—` means no test exists.

| Function                             | Trigger                               | Status                   | Triage  | Tests                         |
| ------------------------------------ | ------------------------------------- | ------------------------ | ------- | ----------------------------- |
| Health check                         | `GET /health`                         | always                   | mvp     | 100% (server)                  |
| Network info                         | `GET /api/info`                       | env¹                     | mvp     | 100% (server)                  |
| Get balance                          | `GET /api/balance?address=<hex>`      | always                   | mvp     | 100% (server)                  |
| List all addresses                   | `GET /api/address`                    | feature (`address-list`) | gate    | 100% (server)                  |
| Mint coins (single-phase)            | `POST /api/mint`                      | always²                  | mvp     | 100% (account_server)                 |
| Send — phase 1 (generate proof)      | `POST /api/send`                      | env²                     | mvp     | 100% (server)                  |
| Send — phase 2 (commit + broadcast)  | `POST /api/commit`                    | env³                     | mvp     | 100% (server) · 0% (publisher) |
| Receive coin                         | `POST /api/receive`                   | always                   | mvp     | 100% (account_server)                 |
| Download coin proof                  | `GET /api/proof/:id`                  | always                   | mvp     | 100% (server)                  |
| Claim username                       | `POST /api/username/claim`            | feature (`usernames`)    | gate    | 100% (username)                |
| Resolve username                     | `GET /api/username/resolve/:username` | feature (`usernames`)    | gate    | 100% (username)                |
| LNURL-Pay metadata                   | `GET /.well-known/lnurlp/:username`   | feature (`lnurl`)        | gate    | 100% (server)                  |
| LNURL-Pay callback                   | `GET /lnurl/pay/:username`            | feature (`lnurl`)        | gate    | 100% (server)                  |
| Bitcoin block scanner (background)   | Loop in `main.rs`, 30 s poll          | env⁴                     | mvp     | 100% (scanner) · — (main, excluded) |
| State persistence (SMT/MMR write)    | Scanner callback on commitment match  | always                   | mvp     | 100% (state)                   |
| Taproot inscription broadcast        | Called by `/api/commit`               | env³                     | mvp     | 0% (publisher)                |
| Publisher UTXO lookup                | Internal, before broadcast            | env³                     | mvp     | 0% (publisher)                |
| Explorer endpoints (`/api/stats`, …) | n/a                                   | planned                  | planned | —                             |
| Light client support                 | n/a                                   | planned                  | planned | —                             |

¹ `NETWORK_NAME` env var controls the string returned. `IS_MAINNET=true` flips the default to `"Mainnet"`.
² Proof generation routes through the Plonky2 cyclic-recursion circuit. Single host, single Rust process — no zkVM, no external prover service. Mac Studio M3 Ultra is the production hardware target (96 GB unified memory, no external GPU). See [Proving Strategy](#proving-strategy).
³ Requires `PUBLISHER_KEY` set to a real funded key and `ESPLORA_URL` reachable. With the default test key the server panics on `IS_MAINNET=true` startup; on testnet it accepts the call but broadcast will fail without funded UTXOs — DEV and PRD both return `503 SERVICE_UNAVAILABLE` to the client on broadcast failure (the historic `DEV_SKIP_BROADCAST_FAILURE` env-gate that silently swallowed these failures was removed once DEV and PRD were unified on the MVP-only binary; the DEV publisher wallet therefore has to be funded for E2E paths).
⁴ Scanner depends on `ESPLORA_URL` being reachable; on connection failure it backs off and retries.

### Cargo features

All non-MVP routes are gated by Cargo features so the disabled handler functions, helper structs, and `AppState` fields are excluded from the binary at compile time. With a feature off, the route is never registered and the fallback responds with `404`. There is no runtime path that can reach a disabled handler. Defaults are empty (fail-closed): **both the DEV and the PRD image builds pass no features**, so the two environments run the identical MVP-only binary. The Cargo flags exist for self-hosters who want to compile a binary with a specific non-MVP subset enabled, and for future per-feature rollouts when an individual feature is deemed ready for production.

| Feature        | Gates                                                                                                                                                 |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `address-list` | `GET /api/address`                                                                                                                                    |
| `usernames`    | `POST /api/username/claim`, `GET /api/username/resolve/:u`, `ClaimUsernameRequest`, `UsernameStore::{claim,save_to_file}`, `AppState::usernames_path` |
| `lnurl`        | `GET /.well-known/lnurlp/:u`, `GET /lnurl/pay/:u` (depends on `usernames`)                                                                            |

Build the MVP-only binary (DEV + PRD ship this): `cargo build --release -p server`. Build with every feature enabled (CI clippy + tests + self-host opt-in): `cargo build --release -p server --all-features`. The Docker `FEATURES` build arg accepts a comma-separated list and is forwarded to `cargo build --features`; both `deploy-dev.yaml` and `deploy-prd.yaml` leave it empty.

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
- **Behaviour:** returns `{ network, capabilities: { address_list, faucet, usernames, lnurl }, username_domain }`. `network` defaults to `Mutinynet` when `IS_MAINNET=false`, `Mainnet` when `true`. `capabilities.{address_list,usernames,lnurl}` each reflect whether the corresponding Cargo feature was compiled into this binary, letting clients gate UI on a single server-side source of truth instead of parallel build-time env flags. `capabilities.faucet` is hardcoded `true` — mint is permanent MVP — and is retained only for back-compat with wallet clients that deserialise the shape. `username_domain` is the external hostname this server serves; **required env var** (server panics on startup if unset). PRD sets `USERNAME_DOMAIN=zkcoins.app`, DEV sets `USERNAME_DOMAIN=dev.zkcoins.app` — distinct from `network` because the same chain can be served from two isolated external hostnames, and the client renders `<hex|username>@<domain>` from this field
- **Tests:** `server.rs::tests::info_returns_network_name_capabilities_and_username_domain`, `server.rs::tests::info_serialization_format_is_stable`

#### Get balance

- **Module:** `server.rs::get_balance_handler` → `account_server.rs::AccountServer::get_account_balance`
- **Behaviour:** address parsed as hex pubkey, looks up the account. Returns `{ balance, username? }`. A well-formed address with no on-chain activity yields `200 OK` with `balance: 0` (canonical zero state, not 404). The minting address returns `u64::MAX`. Malformed input — invalid hex, wrong length, or a missing `address` query parameter — returns `422`
- **Tests:** `server.rs::tests::balance_*` (6 tests covering happy path, unknown address with and without a claimed username, invalid hex, missing param, wrong length)

#### List all addresses

- **Module:** `server.rs::get_address_handler` → `account_server.rs::AccountServer::get_addresses`
- **Behaviour:** returns all known addresses as hex strings. Intended for explorer/debug use, not user-facing
- **Tests:** `server.rs::tests::address_returns_list`

#### Mint coins (single-phase)

- **Module:** `server.rs::mint_handler` → `account_server.rs::send_coins` with the server-held minting account
- **Behaviour:** server signs commitment itself (no client roundtrip) using the minting key
- **Proof generation:** `zkcoins_prover::Prover` (the Plonky2 wrapper in [`script-plonky2/`](./script-plonky2/)) — `prove_initial` for new accounts, `prove_account_update` for receivers
- **Tests:** `account_server.rs::tests::test_create_minting_account`, `test_mint_single_invoice`, `test_mint_repro_live_setup`

#### Send — phase 1 (generate proof)

- **Module:** `server.rs::send_coin_handler` → `verify_send_signature` (Schnorr over `SHA256(account_address || recipient || amount || timestamp)`, ±5 min skew) → `account_server.rs::send_coins`
- **Behaviour:** returns `{ proof_id, account_state_hash, output_coins_root }`. Proof is persisted under `data/proofs/<id>.bin` for later commit
- **Tests:** request-layer tests in `server.rs::tests::send_*` and `send_signature_*` (12 tests covering parser, signature verification, replay). Proof generation itself is not exercised — the Plonky2 cyclic-recursion build is too slow for unit tests (~3–15 min per prove at production parameters); positive proofs are exercised in `program-plonky2/` directly

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
- **Behaviour:** verifies Schnorr signature over `SHA256(username || pubkey || timestamp)` (5 min skew); persists to the Postgres `usernames` table via `db::claim_username` (`INSERT … ON CONFLICT DO NOTHING`)
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

- **Module:** `state.rs::State::update` + scanner callback in `main.rs` → `db::persist_state_tx`
- **Behaviour:** on each verified commitment: append SMT root to MMR, then atomically upsert the SMT bytes, MMR bytes, and last-processed block hash inside a single `BEGIN; UPSERT; UPSERT; UPSERT; COMMIT` against Postgres (issue #11 fix). Replaces the pre-migration `smt.bin` / `mmr.bin` / `latest_block.bin` sibling files
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
| `ESPLORA_URL`   | `https://mutinynet.com/api` | Esplora API endpoint (electrs or public)                                                                                                                      |
| `IS_MAINNET`    | `false`                     | `true` for Bitcoin Mainnet, `false` for Mutinynet/Signet                                                                                                      |
| `NETWORK_NAME`  | `Mutinynet` / `Mainnet`     | Human-readable name returned by `/api/info`. Default depends on `IS_MAINNET`                                                                                  |
| `USERNAME_DOMAIN` | _(required, no default)_  | External hostname returned by `/api/info`. The client renders `<hex\|username>@<domain>` from this. **Server panics on startup if unset.** PRD sets `zkcoins.app`, DEV sets `dev.zkcoins.app` — silent fallback would let a misconfigured stage reproduce the cross-network routing bug (#95) |
| `PUBLISHER_KEY` | test key                    | 32-byte hex private key for inscription publishing. **Required on mainnet** — server panics on startup if default test key is detected with `IS_MAINNET=true` |
| `RUST_LOG`      | `info`                      | Log level                                                                                                                                                     |

Runtime config above shapes _behaviour_ of compiled-in routes. _Which_ routes are compiled in is decided at build time by Cargo features — see [Cargo features](#cargo-features).

### Background services

Spawned from `main.rs::main`:

1. **REST server** (`tokio::spawn` of `start_rest_server`) — Axum app bound to `0.0.0.0:4242`
2. **Block scanner** (driven directly in main, not spawned) — `scan_for_inscriptions` runs an infinite loop polling Esplora every 30 s and writing state on each verified commitment

### Tests

| Stack            | Command                                       | What it covers                                                                                             |
| ---------------- | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `cargo test`     | `cargo test -p server`                        | MVP code paths — what the DEV + PRD binary actually contains                                               |
| `cargo test`     | `cargo test -p server --all-features`         | Including the gated `address-list`, `usernames`, and `lnurl` routes                                        |
| `cargo-llvm-cov` | `cargo llvm-cov -p server`                    | Coverage gate enforced by CI: 100% lines + functions on the activated MVP surface                          |

Per-module coverage (CI-gated):

| Module              | Line + function % | Notes                                                                              |
| ------------------- | ----------------- | ---------------------------------------------------------------------------------- |
| `account_server.rs` | 100%              | send-coins flow, account ledger, scanner integration                               |
| `scanner.rs`        | 100%              | Bitcoin block / inscription scanner                                                |
| `server.rs`         | 100%              | REST handlers + request validation                                                 |
| `state.rs`          | 100%              | Poseidon-based SMT + MMR                                                           |
| `username.rs`       | 100%              | Username claim / resolve / LNURL                                                   |
| `publisher.rs`      | excluded          | Bitcoin commit/reveal broadcasting — needs live signet/regtest node                |
| `main.rs`           | excluded          | Runtime bootstrap                                                                  |
| `*_runtime.rs`      | excluded          | Background-loop wrappers; covered indirectly via integration tests against handlers |

`publisher.rs`, `main.rs`, and the `*_runtime.rs` wrappers are excluded by design — they require a live Bitcoin node, a funded publisher key, or a bound TCP socket, none of which fit in a unit test. The exclusion list is encoded in the CI gate's `--ignore-filename-regex`; everything else is held at 100% lines + 100% functions. CI runs the MVP build, the all-features build, `cargo test --all-features` on the self-hosted M3 Ultra runner, and the `Coverage Gate (100% lines + functions)` job.

## Running

Requires access to a Bitcoin node. See [Backend docs](https://docs.zkcoins.app/infrastructure/backend).

```bash
cargo run -p server
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
server/                  # Axum REST API
├── src/
│   ├── main.rs          # Entry point, chain scanner, bind 0.0.0.0:4242
│   ├── server.rs        # REST endpoints + /health
│   ├── account_server.rs  # Account logic, coin proofs, prover calls
│   ├── state.rs         # Sparse Merkle Tree + Merkle Mountain Range
│   ├── scanner.rs       # Bitcoin block scanner (30s polling, prefix 4242)
│   └── publisher.rs     # Taproot Inscription broadcaster (commit/reveal)
shared/                  # Shared types (Commitment, Invoice, ClientAccount)
program-plonky2/         # Cyclic-recursion state-transition circuit (Plonky2 + Poseidon)
├── src/
│   ├── circuit/         # `build_circuit` + per-stage gadgets
│   ├── hash.rs          # Poseidon-Goldilocks helpers (HashDigest, digest_to_bytes…)
│   ├── merkle/          # Poseidon-based SMT + MMR
│   ├── types.rs         # AccountState, Coin, ProofData
│   └── inputs.rs        # CommitmentMerkleProofs, ProofType
script-plonky2/          # Host-side prover wrapper (Prover struct)
```

The last SP1 zkVM / SHA256 state is preserved at tag `v0.last-sp1` for historical reference. Recover with `git checkout v0.last-sp1 -- program/ script/`.

## Docker

```bash
docker build -t zkcoin/server .
docker run -p 4242:4242 \
  --network bitcoin \
  -e ESPLORA_URL=http://electrs-mainnet:3000 \
  zkcoin/server
```

Docker builds use nightly Rust auto-installed via `rust-toolchain` (no external toolchain needed). The Dockerfile lives at the repo root; `.github/workflows/deploy-dev.yaml` builds `zkcoin/server:beta` for `linux/arm64` and deploys to the DEV host on every push to `develop`.

## CI/CD

| Workflow               | Trigger      | Action                                               |
| ---------------------- | ------------ | ---------------------------------------------------- |
| `deploy-dev.yaml`      | Push develop | Docker (ARM64) → `zkcoin/server:beta` → DEV server   |
| `deploy-prd.yaml`      | Push main    | Docker (ARM64) → `zkcoin/server:latest` → PRD server |
| `auto-release-pr.yaml` | Push develop | Creates Release PR (develop → main)                  |

Build time: ~5 minutes (Rust compilation on ARM64).

## Proving Strategy

zkCoins is **server-heavy**: a single trusted server generates all proofs, the wallet holds only the private key and signs BIP-340 Schnorr over `SHA256(serialize(asth) ‖ serialize(ocr))`. There is no in-browser Poseidon, no wasm-Plonky2 verifier, no in-app ZK gadget. See [`SPEC.md`](./SPEC.md) §13 + the memory `feedback_zkcoins_server_side_compute` for the full rationale.

**Hardware target: Mac Studio M3 Ultra** (96 GB unified RAM, single host). All on-box compute is available: Performance + Efficiency cores, the integrated Apple Silicon GPU (via Metal — currently unused because Plonky2 ships CPU + CUDA backends only), Neural Engine, AMX. **Not available**: external GPU accelerators (no NVIDIA, no CUDA), no cloud prover services (no Succinct Prover Network, no AWS GPU). Performance budget is what the M3 Ultra delivers; if a design overshoots, the design changes — we do not add external hardware.

Current cyclic-recursion proof times at production parameters (`MAX_IN_COINS = MAX_OUT_COINS = 8`, `INNER_PAD_BITS = 14`): 3–15 min wall per `prove_*` call. See [`program-plonky2/SESSION_STATE.md`](./program-plonky2/SESSION_STATE.md) for the detailed test-time table.

## Open Tasks

- [ ] Step 9: signet end-to-end roundtrip against `dev.zkcoins.app` (create account → mint → send → receive)
- [ ] Step 9: R2 performance measurement on the M3 Ultra (warm proof ≤ 5 s target ≤ 1 s; cold ≤ 30 s; peak mem < 64 GB)
- [ ] Pre-mainnet hardening: D2/D10 (hiding recipient), D7 (reorg safety), D8 (per-coin nullifier-accum) — see `SPEC.md` §15
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

These documents describe the bridge and swap roadmap. They build on
the Plonky2 migration that landed via PR [#17](https://github.com/zk-coins/server/pull/17)
on 2026-05-18 and cross-reference `SPEC.md`, `MIGRATION_RESEARCH.md`,
and `ROADMAP.md`.

## Protocol

Based on [Shielded CSV](https://eprint.iacr.org/2025/068) by Jonas Nick (Blockstream), Liam Eagen (Alpen Labs), Robin Linus (ZeroSync). Server code derived from [ZeroSync/ZKCoins](https://github.com/ZeroSync/ZKCoins).

## License

MIT
