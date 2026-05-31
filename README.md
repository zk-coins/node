# zkCoins Node

[![Docker Image Version](https://img.shields.io/docker/v/zkcoins/node/latest?logo=docker&label=zkcoins%2Fnode&color=2496ED)](https://hub.docker.com/r/zkcoins/node)
[![Docker Pulls](https://img.shields.io/docker/pulls/zkcoins/node?logo=docker&color=2496ED)](https://hub.docker.com/r/zkcoins/node)

Rust/Axum backend for [zkcoins.app](https://zkcoins.app) — account management, ZK proof generation, Bitcoin blockchain scanning, and nullifier publishing.

Container images: **[hub.docker.com/r/zkcoins/node](https://hub.docker.com/r/zkcoins/node)**

## Live

| Environment | URL                                                | Bitcoin chain | Image                                                                                |
| ----------- | -------------------------------------------------- | ------------- | ------------------------------------------------------------------------------------ |
| **PRD**     | [api.zkcoins.app](https://api.zkcoins.app)         | Mainnet       | [`zkcoins/node:latest`](https://hub.docker.com/r/zkcoins/node/tags?name=latest)      |
| **DEV**     | [dev-api.zkcoins.app](https://dev-api.zkcoins.app) | Mutinynet     | [`zkcoins/node:beta`](https://hub.docker.com/r/zkcoins/node/tags?name=beta)          |

## Stack

| Layer           | Technology           | Why                                                  |
| --------------- | -------------------- | ---------------------------------------------------- |
| Language        | Rust nightly         | Required for Plonky2 (`feature(specialization)`)     |
| Web framework   | Axum                 | Built on Tokio, idiomatic async Rust                 |
| ZK Proofs       | Plonky2 + Poseidon-Goldilocks (cyclic recursion) | Node-side, no zkVM, no external prover dependency    |
| Data structures | SMT + MMR (Poseidon) | Non-inclusion proofs + append-only history           |
| Bitcoin         | Taproot Inscriptions | 64-byte nullifiers, Esplora API scanning             |
| Bitcoin index   | electrs (Esplora)    | Esplora REST API via shared Docker network `bitcoin` |

Full rationale: [docs.zkcoins.app/tech-decisions](https://docs.zkcoins.app/tech-decisions)

## Trust Model

Proof generation runs **inside this node process**. `AccountNode::send_coins` (`node/src/account_node.rs`) calls `self.prover.prove_account_update_with_in_and_out_coins_and_sources(...)` (and the `prove_initial_*` variant for first-time accounts) on every send / receive / mint. ZK proving requires the full private witness, so the node sees, in cleartext:

- Sender, recipient, and amount of every coin movement
- The complete in-coin / out-coin / source-aggregator slot layout per account
- Account history roots, Merkle proofs, and inclusion-proof witnesses
- Usernames and their bound coin sets (`UsernameStore`)
- Postgres rows persisting all of the above (`node/migrations/000{1,2}_*.sql`)

The **on-chain footprint stays private** — Plonky2 ensures that the public outputs (nullifiers, history roots, Taproot inscriptions) carry no readable transaction data. Block explorers and chain analytics see only opaque 64-byte commitments. The trust boundary is therefore the **node operator**, not the chain.

| | Hosted (`api.zkcoins.app`) | Self-hosted |
| --- | --- | --- |
| On-chain privacy (vs. block explorers) | ✅ | ✅ |
| Operator sees plaintext transaction data | ❌ Yes — `api.zkcoins.app` is operated by [zkcoins.app](https://zkcoins.app) | ✅ No |
| Setup effort | ✅ None | ⚠️ Postgres + electrs + Bitcoin node |

**If you need full transaction privacy, run your own node.** Every release is shipped as `zkcoins/node:latest` (see [Live](#live)), the build recipe is [`Dockerfile`](./Dockerfile), and runtime knobs are documented in [Configuration](#configuration). Point the [zkcoins.app](https://zkcoins.app) client at your self-hosted instance for end-to-end self-custody of transaction data.

## Contributing

**New PRs may only merge into `develop` if test coverage is 100% on the activated surface.** Code behind a Cargo feature (`address-list`, `lnurl`) is excluded from the MVP measurement — feature-gated routes do not need to be tested because both DEV and PRD ship the MVP-only binary with every Cargo feature off. (Mint and usernames are part of the MVP and are permanently compiled in — no Cargo feature gate.) Concretely:

- `cargo llvm-cov -p node` (no `--all-features`) must report 100% lines + 100% functions on the activated MVP surface. CI enforces this with `--fail-under-lines 100 --fail-under-functions 100` in the `Coverage Gate (100% lines + functions)` job. The current `develop` baseline is at the gate.
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
| Health check                         | `GET /health`                         | always                   | mvp     | 100% (router)                  |
| Network info                         | `GET /api/info`                       | env¹                     | mvp     | 100% (router)                  |
| Get balance                          | `GET /api/balance?address=<hex>`      | always                   | mvp     | 100% (router)                  |
| List per-address history             | `GET /api/history?address=<hex>&limit=<n>&offset=<n>` | always   | mvp     | 100% (router)                  |
| List all addresses                   | `GET /api/address`                    | feature (`address-list`) | gate    | 100% (router)                  |
| Admit mint job                       | `POST /api/jobs/mint`                 | always²                  | mvp     | 100% (router)                  |
| Admit send job (phase 1)             | `POST /api/jobs/send`                 | env²                     | mvp     | 100% (router)                  |
| Attach signed commit (phase 2)       | `POST /api/jobs/:id/commit`           | env³                     | mvp     | 100% (router) · 0% (flow)      |
| Poll job status                      | `GET /api/jobs/:id`                   | always                   | mvp     | 100% (router)                  |
| Stream job phase events (SSE)        | `GET /api/jobs/:id/stream`            | always                   | mvp     | 100% (router)                  |
| Cancel queued job                    | `POST /api/jobs/:id/cancel`           | always                   | mvp     | 100% (router)                  |
| Receive coin                         | `POST /api/receive`                   | always                   | mvp     | 100% (account_node)                 |
| Download coin proof                  | `GET /api/proof/:id`                  | always                   | mvp     | 100% (router)                  |
| Claim username                       | `POST /api/username/claim`            | always                   | mvp     | 100% (username)                |
| Resolve username                     | `GET /api/username/resolve/:username` | always                   | mvp     | 100% (username)                |
| LNURL-Pay metadata                   | `GET /.well-known/lnurlp/:username`   | feature (`lnurl`)        | gate    | 100% (router)                  |
| LNURL-Pay callback                   | `GET /lnurl/pay/:username`            | feature (`lnurl`)        | gate    | 100% (router)                  |
| Bitcoin block scanner (background)   | WS subscription in `scanner_ws.rs`    | env⁴                     | mvp     | 100% (scanner) · — (main, excluded) |
| State persistence (SMT/MMR write)    | Scanner callback on commitment match  | always                   | mvp     | 100% (state)                   |
| Taproot inscription broadcast        | Called by dispatcher (`flow.rs`)      | env³                     | mvp     | 0% (publisher)                |
| Publisher UTXO lookup                | Internal, before broadcast            | env³                     | mvp     | 0% (publisher)                |
| OpenAPI 3.x spec                     | `GET /openapi.json`                   | always                   | mvp     | 100% (openapi_smoke)           |
| Swagger UI                           | `GET /docs`                           | always                   | mvp     | 100% (openapi_smoke)           |
| Explorer endpoints (`/api/stats`, …) | n/a                                   | planned                  | planned | —                             |
| Light client support                 | n/a                                   | planned                  | planned | —                             |

¹ `NETWORK_NAME` env var controls the string returned. `IS_MAINNET=true` flips the default to `"Mainnet"`.
² Proof generation routes through the Plonky2 cyclic-recursion circuit. Single host, single Rust process — no zkVM, no external prover service. Mac Studio M3 Ultra is the production hardware target (96 GB unified memory, no external GPU). See [Proving Strategy](#proving-strategy).
³ Requires `PUBLISHER_KEY` set to a real funded key and `ESPLORA_URL` reachable. With the default test key the node panics on `IS_MAINNET=true` startup; on testnet it accepts the call but broadcast will fail without funded UTXOs — DEV and PRD both return `503 SERVICE_UNAVAILABLE` to the client on broadcast failure (the historic `DEV_SKIP_BROADCAST_FAILURE` env-gate that silently swallowed these failures was removed once DEV and PRD were unified on the MVP-only binary; the DEV publisher wallet therefore has to be funded for E2E paths).
⁴ Scanner depends on `ESPLORA_URL` (REST, used for the per-block `get_block_txids` / `get_tx` lookups and for the post-reconnect tip anchor) AND `ESPLORA_WS_URL` (WebSocket, used by `scanner_ws` to receive new-tip events — issue #84). Both are required env vars with no default; see [Configuration](#configuration) for per-stage values. On connection failure the WS subscriber reconnects with exponential backoff capped at 30 s.

### Cargo features

All non-MVP routes are gated by Cargo features so the disabled handler functions, helper structs, and `AppState` fields are excluded from the binary at compile time. With a feature off, the route is never registered and the fallback responds with `404`. There is no runtime path that can reach a disabled handler. Defaults are empty (fail-closed): **both the DEV and the PRD image builds pass no features**, so the two environments run the identical MVP-only binary. The Cargo flags exist for self-hosters who want to compile a binary with a specific non-MVP subset enabled, and for future per-feature rollouts when an individual feature is deemed ready for production.

| Feature        | Gates                                                                                                                                                 |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `address-list` | `GET /api/address`                                                                                                                                    |
| `lnurl`        | `GET /.well-known/lnurlp/:u`, `GET /lnurl/pay/:u`                                                                                                     |

Build the MVP-only binary (DEV + PRD ship this): `cargo build --release -p node`. Build with every feature enabled (CI clippy + tests + self-host opt-in): `cargo build --release -p node --all-features`. The Docker `FEATURES` build arg accepts a comma-separated list and is forwarded to `cargo build --features`; both `deploy-dev.yaml` and `deploy-prd.yaml` leave it empty.

### Triage gaps

Features tagged `mvp` whose current test coverage is insufficient — these block "100% on activated features":

- **Send — phase 2 (commit + broadcast)** — only error-path tests (`commit_missing_body`, `commit_nonexistent_proof_id`); no happy-path test that exercises the publisher
- **Download coin proof** — only 404 path tested; no test for the happy-path binary stream
- **Bitcoin block scanner** — parsing helpers covered (`scanner.rs` 51%); no integration test against a real Bitcoin block
- **Taproot inscription broadcast** — `publisher.rs` 0%, no tests at all (would need signet/regtest + funded publisher key)
- **Publisher UTXO lookup** — `publisher.rs` 0%, no tests

### Details

#### Health check

- **Module:** `router.rs::main_app` route handler
- **Behaviour:** returns the literal string `"ok"` with HTTP 200
- **Tests:** `router.rs::tests::health_returns_ok`

#### Network info

- **Module:** `router.rs::info_handler`
- **Behaviour:** returns `{ network, capabilities: { address_list, faucet, usernames, lnurl }, username_domain }`. `network` defaults to `Mutinynet` when `IS_MAINNET=false`, `Mainnet` when `true`. `capabilities.{address_list,lnurl}` each reflect whether the corresponding Cargo feature was compiled into this binary, letting clients gate UI on a single node-side source of truth instead of parallel build-time env flags. `capabilities.{faucet,usernames}` are hardcoded `true` — mint and usernames are permanent MVP — and are retained only for back-compat with wallet clients that deserialise the shape. `username_domain` is the external hostname this node serves; **required env var** (node panics on startup if unset). PRD sets `USERNAME_DOMAIN=zkcoins.app`, DEV sets `USERNAME_DOMAIN=dev.zkcoins.app` — distinct from `network` because the same chain can be served from two isolated external hostnames, and the client renders `<hex|username>@<domain>` from this field
- **Tests:** `router.rs::tests::info_returns_network_name_capabilities_and_username_domain`, `router.rs::tests::info_serialization_format_is_stable`

#### Get balance

- **Module:** `router.rs::get_balance_handler` → `account_node.rs::AccountNode::get_account_balance`
- **Behaviour:** address parsed as hex pubkey, looks up the account. Returns `{ balance, username? }`. A well-formed address with no on-chain activity yields `200 OK` with `balance: 0` (canonical zero state, not 404). The minting address returns `u64::MAX`. Malformed input — invalid hex, wrong length, or a missing `address` query parameter — returns `422`
- **Tests:** `router.rs::tests::balance_*` (6 tests covering happy path, unknown address with and without a claimed username, invalid hex, missing param, wrong length)

#### List all addresses

- **Module:** `router.rs::get_address_handler` → `account_node.rs::AccountNode::get_addresses`
- **Behaviour:** returns all known addresses as hex strings. Intended for explorer/debug use, not user-facing
- **Tests:** `router.rs::tests::address_returns_list`

#### Mint coins (single-phase)

- **Module:** `router.rs::mint_handler` → `account_node.rs::send_coins` with the node-held minting account
- **Behaviour:** node signs commitment itself (no client roundtrip) using the minting key
- **Proof generation:** `zkcoins_prover::Prover` (the Plonky2 wrapper in [`script-plonky2/`](./script-plonky2/)) — `prove_initial` for new accounts, `prove_account_update` for receivers
- **Tests:** `account_node.rs::tests::test_create_minting_account`, `test_mint_single_invoice`, `test_mint_repro_live_setup`

#### Send — phase 1 (generate proof)

- **Module:** `router.rs::send_coin_handler` → `verify_send_signature` (Schnorr over `SHA256(account_address || recipient || amount || timestamp)`, ±5 min skew) → `account_node.rs::send_coins`
- **Behaviour:** returns `{ proof_id, account_state_hash, output_coins_root }`. Proof is persisted under `data/proofs/<id>.bin` for later commit
- **Tests:** request-layer tests in `router.rs::tests::send_*` and `send_signature_*` (12 tests covering parser, signature verification, replay). Proof generation itself is not exercised — the Plonky2 cyclic-recursion build is too slow for unit tests (~3–15 min per prove at production parameters); positive proofs are exercised in `program-plonky2/` directly

#### Send — phase 2 (commit + broadcast)

- **Module:** `router.rs::commit_handler` → `publisher.rs::create_and_broadcast_inscription`
- **Behaviour:** verifies the client's Schnorr commitment, builds a Taproot commit+reveal tx pair, mines a txid prefix `4242` (max 400 000 attempts in `publisher.rs::inscription_txs`), broadcasts both txs, then calls `account_node.rs::receive_coin` to deliver the coin to the recipient
- **Tests:** `router.rs::tests::commit_missing_body_returns_error`, `commit_nonexistent_proof_id_returns_404`. **No happy-path broadcast test** — would require a live Bitcoin signet/regtest

#### Receive coin

- **Module:** `router.rs::receive_coin_handler` → `account_node.rs::receive_coin`
- **Behaviour:** replay-protected via per-account `coin_history` SMT
- **Tests:** `account_node.rs::tests::test_receive_duplicate_coin_rejected`, `test_receive_updates_balance`

#### Download coin proof

- **Module:** `router.rs::get_proof_handler` → `ProofStore::get_proof`
- **Behaviour:** streams the binary serialised `CoinProof` (`Vec<u8>` from bincode) with content-type `application/octet-stream`
- **Tests:** `router.rs::tests::proof_not_found_returns_404`

#### Claim username

- **Module:** `router.rs::claim_username_handler` → `username.rs::UsernameStore::claim`
- **Behaviour:** verifies Schnorr signature over `SHA256(username || pubkey || timestamp)` (5 min skew); persists to the Postgres `usernames` table via `db::claim_username` (`INSERT … ON CONFLICT DO NOTHING`)
- **Tests:** `router.rs::tests::claim_username_*` (3 tests) + `username.rs::tests::*` (8 tests covering valid charset, duplicates, persistence)

#### Resolve username

- **Module:** `router.rs::resolve_username_handler` → `username.rs::UsernameStore::resolve`
- **Behaviour:** if exact username unknown, falls back to hex prefix matching against known addresses. Case-insensitive
- **Tests:** `router.rs::tests::resolve_unknown_username_returns_404`, `resolve_minting_address_by_hex_prefix`, `username.rs::tests::resolve_is_case_insensitive`

#### LNURL-Pay metadata and callback

- **Module:** `router.rs::lnurlp_handler`, `router.rs::lnurl_callback_handler`
- **Behaviour:** thin stub implementation of [LNURL-pay](https://github.com/lnurl/luds/blob/luds/06.md). Metadata returned for known usernames; callback returns a phase-2 error (not wired to a real BOLT-11 invoice generator yet)
- **Tests:** `router.rs::tests::lnurlp_known_address_returns_pay_request`, `lnurlp_unknown_user_returns_404`, `lnurl_pay_callback_returns_phase2_error`

#### Bitcoin block scanner

- **Module:** `scanner.rs::scan_for_inscriptions` / `InscriptionScanner::scan_from_block`. Loop spawned from `main.rs::main`. State saved between runs in `data/latest_block.bin`
- **Behaviour:** subscribes to the Esplora WebSocket (`scanner_ws.rs`, `ESPLORA_WS_URL`) for new tip events; drains the resulting mpsc channel in `scanner_runtime.rs`, walking forward through `block_status.next_best`; filters txs by txid prefix `4242`; extracts Taproot inscription content via `extract_inscription_content`; deserialises as `Commitment`; calls callback in `main.rs` which verifies the signature and updates state. Polling was removed in [issue #84](https://github.com/zk-coins/node/issues/84); see [CONTRIBUTING.md § "No polling — events only"](./CONTRIBUTING.md#no-polling--events-only) for the CI lint that enforces this
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

| Variable          | Default                    | Effect                                                                                                                                                        |
| ----------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `IS_MAINNET`      | _(required, no default)_   | Exact string `true` or `false` — anything else panics. PRD sets `true`, DEV sets `false`. Drives the `Network` enum (Mainnet vs Signet) used for address derivation. Truthy values like `1`, `TRUE`, `yes` are rejected to prevent silent misconfiguration. |
| `ESPLORA_URL`     | _(required, no default)_   | HTTP Esplora endpoint for the chain this stage serves. On the `api.zkcoins.app` stack: PRD `http://electrs-mainnet:3000`, DEV `http://electrs-mutinynet:3000`. Self-host: your electrs URL. Empty string is treated as unset.                                       |
| `ESPLORA_WS_URL`  | _(required, no default)_   | Esplora-compatible WebSocket endpoint consumed by `scanner_ws` (issue #84). On the `api.zkcoins.app` stack: PRD `wss://mempool.space/api/v1/ws`, DEV `ws://mempool-api-mutinynet:8999/api/v1/ws` (self-hosted mempool/backend sidecar). Empty string is treated as unset.                    |
| `NETWORK_NAME`    | `Mutinynet` / `Mainnet`    | Human-readable name returned by `/api/info`. Default depends on `IS_MAINNET`. Purely cosmetic — has no behavioural effect on the scanner, publisher, or address derivation.                                                                              |
| `USERNAME_DOMAIN` | _(required, no default)_   | External hostname returned by `/api/info`. The client renders `<hex\|username>@<domain>` from this. **Node panics on startup if unset.** PRD sets `zkcoins.app`, DEV sets `dev.zkcoins.app` — silent fallback would let a misconfigured stage reproduce the cross-network routing bug (#95) |
| `PUBLISHER_KEY`   | _(required, no default)_   | 32-byte hex private key for inscription publishing. Node panics on startup if unset. On `IS_MAINNET=true` an additional check refuses the well-known test key.                                                                                            |
| `RUST_LOG`        | `info`                     | Log level                                                                                                                                                     |

**Why so many required env vars.** Earlier versions of this table listed Mutinynet defaults for the three chain-shaping vars (`IS_MAINNET`, `ESPLORA_URL`, `ESPLORA_WS_URL`). They were silent footguns: a Mainnet deployment that forgot one would scan Mutinynet while answering `/api/info` as Mainnet, with `/health/ready` green throughout (5-s HTTP retry loop on the scanner — issue #84). On the Mutinynet path the WS default coupled the deploy to a public third-party host we do not operate. Making both paths explicit-or-panic — the same pattern as `USERNAME_DOMAIN`, `PUBLISHER_KEY`, and `DATABASE_URL` — removes both classes of bug. A mechanical guardrail (`node/tests/no_chain_hardcodes.rs`) prevents the literal URLs from creeping back into the source.

Runtime config above shapes _behaviour_ of compiled-in routes. _Which_ routes are compiled in is decided at build time by Cargo features — see [Cargo features](#cargo-features).

### Background services

Spawned from `main.rs::main`:

1. **REST API** (`tokio::spawn` of `start_rest_node`) — Axum app bound to `0.0.0.0:4242`
2. **Block scanner** (driven directly in main, not spawned) — `scan_for_inscriptions` consumes new tips from the WS-fed `mpsc<BlockHash>` channel produced by `scanner_ws::run_scanner_ws` (spawned as a tokio task at startup) and writes state on each verified commitment. No fixed-interval polling — see [issue #84](https://github.com/zk-coins/node/issues/84)

### Tests

| Stack            | Command                                       | What it covers                                                                                             |
| ---------------- | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `cargo test`     | `cargo test -p node`                        | MVP code paths — what the DEV + PRD binary actually contains                                               |
| `cargo test`     | `cargo test -p node --all-features`         | Including the gated `address-list` and `lnurl` routes                                                      |
| `cargo-llvm-cov` | `cargo llvm-cov -p node`                    | Coverage gate enforced by CI: 100% lines + functions on the activated MVP surface                          |

Per-module coverage (CI-gated):

| Module              | Line + function % | Notes                                                                              |
| ------------------- | ----------------- | ---------------------------------------------------------------------------------- |
| `account_node.rs` | 100%              | send-coins flow, account ledger, scanner integration                               |
| `scanner.rs`        | 100%              | Bitcoin block / inscription scanner                                                |
| `router.rs`         | 100%              | REST handlers + request validation                                                 |
| `state.rs`          | 100%              | Poseidon-based SMT + MMR                                                           |
| `username.rs`       | 100%              | Username claim / resolve / LNURL                                                   |
| `publisher.rs`      | excluded          | Bitcoin commit/reveal broadcasting — needs live signet/regtest node                |
| `main.rs`           | excluded          | Runtime bootstrap                                                                  |
| `*_runtime.rs`      | excluded          | Background-loop wrappers; covered indirectly via integration tests against handlers |
| `scanner_ws.rs`     | excluded          | WS subscriber + reconnect loop; the pure helper `parse_ws_frame` is unit-tested, the I/O loop is covered by in-process WS-server tests |

`publisher.rs`, `main.rs`, the `*_runtime.rs` wrappers, and `scanner_ws.rs` are excluded by design — they require a live Bitcoin node, a funded publisher key, a bound TCP socket, or an upstream WebSocket peer, none of which fit in a unit test. The exclusion list is encoded in the CI gate's `--ignore-filename-regex`; everything else is held at 100% lines + 100% functions. CI runs the MVP build, the all-features build, `cargo nextest run -p node -p shared --release --all-features --test-threads 1 -E 'not binary(api_remote)'` on the self-hosted M3 Ultra runner pool, and the `Coverage Gate (100% lines + functions)` job.

## Running

Requires access to a Bitcoin node. See [Backend docs](https://docs.zkcoins.app/infrastructure/backend).

```bash
cargo run -p node
# Node starts on http://0.0.0.0:4242
```

## Job-API send flow

User sends are admitted to the Job-API and driven by the background dispatcher (PR1, June 2026 — `migrations/0014_jobs.sql` + `src/job_dispatcher.rs`). The wallet never holds an HTTP connection across the ~5 s prove call; each step is a separate poll-friendly request:

1. **`POST /api/jobs/send`** (with `Idempotency-Key` header) — admit the send job. Returns `202` + `{job_id, status: "queued"}` immediately. The dispatcher picks the row up and runs the ZK prove.
2. **Poll `GET /api/jobs/:id` every ~2 s** — wallet observes `queued → proving → awaiting_signature`. When `status = awaiting_signature`, the body carries `proof_id` so the wallet can `GET /api/proof/:id` to download the proof, sign `Schnorr(hash_concat(account_state_hash, output_coins_root))` with the BIP-32 key at `numPubkeys`, and...
3. **`POST /api/jobs/:id/commit`** — attach the signed commitment. Returns `200` + `{status: "broadcasting"}`. The dispatcher broadcasts the Taproot inscription and `state.update`s the recipient; the next poll observes `status = completed` with the cached result body.

Mint follows the same admit-then-poll pattern (`POST /api/jobs/mint`) — single-phase under the hood because the node holds the minting key, so `awaiting_signature` is skipped and the job transitions `queued → proving → broadcasting → completed` directly.

Cancellation: `POST /api/jobs/:id/cancel` only succeeds while the job is `queued` (no prove cost paid yet). Past that, the dispatcher has already committed sunk cost and the row is no longer cancellable.

## Project Structure

```
node/                    # Axum REST API
├── src/
│   ├── main.rs          # Entry point, chain scanner, bind 0.0.0.0:4242
│   ├── router.rs        # REST endpoints + /health
│   ├── runtime.rs       # Bootstrap: lazy_statics, Postgres pool, REST listener
│   ├── account_node.rs  # Account logic, coin proofs, prover calls
│   ├── state.rs         # Sparse Merkle Tree + Merkle Mountain Range
│   ├── scanner.rs       # Bitcoin block scanner (event-driven via scanner_ws, prefix 4242)
│   ├── scanner_ws.rs    # Esplora WebSocket subscriber (issue #84, replaces 30 s polling)
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
docker build -t zkcoins/node .
docker run -p 4242:4242 \
  --network bitcoin \
  -e ESPLORA_URL=http://electrs-mainnet:3000 \
  zkcoins/node
```

Docker builds use nightly Rust auto-installed via `rust-toolchain` (no external toolchain needed). The Dockerfile lives at the repo root; `.github/workflows/deploy-dev.yaml` builds `zkcoins/node:beta` for `linux/arm64` and deploys to the DEV host on every push to `develop`.

## CI/CD

| Workflow               | Trigger      | Action                                               |
| ---------------------- | ------------ | ---------------------------------------------------- |
| `deploy-dev.yaml`      | Push develop | Docker (ARM64) → `zkcoins/node:beta` → DEV node     |
| `deploy-prd.yaml`      | Push main    | Docker (ARM64) → `zkcoins/node:latest` → PRD node   |
| `auto-release-pr.yaml` | Push develop | Creates Release PR (develop → main)                  |

Build time: ~5 minutes (Rust compilation on ARM64).

## Proving Strategy

zkCoins is **node-heavy**: a single trusted node generates all proofs, the wallet holds only the private key and signs BIP-340 Schnorr over `SHA256(serialize(asth) ‖ serialize(ocr))`. There is no in-browser Poseidon, no wasm-Plonky2 verifier, no in-app ZK gadget. See [`SPEC.md`](./SPEC.md) §13 + the memory `feedback_zkcoins_server_side_compute` for the full rationale.

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
the Plonky2 migration that landed via PR [#17](https://github.com/zk-coins/node/pull/17)
on 2026-05-18 and cross-reference `SPEC.md`, `MIGRATION_RESEARCH.md`,
and `ROADMAP.md`.

## Protocol

Based on [Shielded CSV](https://eprint.iacr.org/2025/068) by Jonas Nick (Blockstream), Liam Eagen (Alpen Labs), Robin Linus (ZeroSync). Node code derived from [ZeroSync/ZKCoins](https://github.com/ZeroSync/ZKCoins).

## License

MIT
