# Plonky2 Migration Roadmap

Living tracker for the SP1 → Plonky2 + Poseidon migration. **Updated on
every commit to `develop`** — if this file is stale relative to recent
commits, that is a bug. The migration PR ([#17](https://github.com/zk-coins/node/pull/17))
merged 2026-05-18; Steps 1–8 are done and Step 9 is partially done
(DEV live, signet e2e roundtrip + R2 performance measurement remain).

Source documents:

- [`CONTRIBUTING.md`](./CONTRIBUTING.md) § "Working on the Plonky2 Migration" — **start here for fresh sessions.** Onboarding, project invariants, decision recipe, pre-push checklist, foot-gun summary, navigation aid for everything below.
- [`SPEC.md`](./SPEC.md) — protocol specification (the *what*).
- [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md) — analysis of the upstream references + design decisions + **§7 Lessons Learned during implementation** (the *why* + *what bit us*).
- [`program-plonky2/CONTRIBUTING.md`](./program-plonky2/CONTRIBUTING.md) — operational handoff: toolchain, build/test/lint commands, runtime characteristics, pitfalls (the *how to actually hack on this*).
- This file — execution plan, status, estimates (the *when and how-overview*).

---

## Status at a Glance

Legend: ✅ done · 🟡 in progress · ⏳ todo. Effort estimates are
person-days at full focus; multiply for part-time work.

| # | Step | Status | Effort | Risk |
| - | ---- | ------ | ------ | ---- |
| 1 | Reconcile `SPEC.md` with paper divergences | ✅ done | — | — |
| 2 | Scaffold `program-plonky2/` standalone crate | ✅ done | — | — |
| 3a | Port off-circuit Poseidon hash + byte conversion | ✅ done | — | — |
| 3b | Port off-circuit sparse Merkle tree to Poseidon | ✅ done | — | low (regression covered) |
| 3c | Port off-circuit MMR to Poseidon | ✅ done | — | — |
| 3d | Port off-circuit `AccountState`/`Coin`/`ProofData` | ✅ done | — | — |
| 4a | In-circuit MMR inclusion gadget | ✅ done | — | — |
| 4b | In-circuit SMT inclusion gadget | ✅ done | — | — |
| 4c | In-circuit SMT non-inclusion gadget (verify only) | ✅ done | — | — |
| 4c+ | In-circuit SMT insert gadget (new-root computation) | ✅ done | — | — |
| 4d | Port `ProgramInputs` + `CommitmentMerkleProofs` types | ✅ done | — | — |
| 5 | Monolithic state-transition circuit (recursion, padding, vk-pin) | ✅ done (5a/5b/5c/5c+/5d/5d-next-3/5d-next-5). Stage 5d-next-5 source-side cyclic verify landed via PR [#23](https://github.com/zk-coins/node/pull/23) — aggregator pattern + Phase 2b per-slot SMT inclusion + SPEC §8 (c)(d)(e) chain + 3 §13 negatives. See [`MIGRATION_RESEARCH.md` §7.22](./MIGRATION_RESEARCH.md#722-stage-5d-next-5-source-side-verification-via-aggregator-pattern--codified-resolves-721) for the empirical insights (`ConstantGate::new(2)` injection + `helper_degree = pad_bits + 1` sweep). | — | — |
| 6 | `script-plonky2/` host-side prover wrapper | ✅ done (`d96bb62`) | — | — |
| 7 | Node: **replace** SP1 path with Plonky2 (no feature flag, no dual backend) | ✅ done — `send_coins` performs **in-circuit source-side validation via Stage 5d-next-5 Phase 2 aggregator** (PR [#23](https://github.com/zk-coins/node/pull/23)); off-circuit pre-checks retained as defense-in-depth (microsecond-level fast-fail before the minute-scale prove). Initial node cut (`c71c9fc`) ran off-circuit-only because Phase 2 was deferred; the in-circuit wiring landed via the Step-7 follow-up. Dockerfile re-introduced (`dac0179`). 106 node tests pass on the MVP build, 119 with `--all-features` (32 baseline + 10 inline error-path in `d6a3cb9` + 64 ported SP1-era fixtures re-enabled in `account_node_tests.rs` / `router_tests.rs` + 13 feature-gated). Smoke-test verified end-to-end (`cargo run` + `/health` + `/api/info`, block scanner connects). | — | — |
| 8 | App / wallet: Schnorr-signing boundary, node-API integration | ✅ done — `zk-coins/app` ships `wasm.createCommitment(xpriv, num_pubkeys, asth_hex, ocr_hex)` (in `app/rust/client/src/lib.rs`) signing `SHA256(asth ‖ ocr)` via BIP-340 Schnorr (D11). Two-phase send: `/api/send` (Phase 1, proof) → `/api/commit` (Phase 2, signature). API client in `app/src/lib/api/client.ts` covers `info` / `balance` / `send` / `commit` / `mint` / `username/*` endpoints exactly matching API routes registered at `node/src/router.rs:1261–1289`. WASM mock + Vitest coverage gate already enforced in app repo. | — | — |
| 9 | DEV deployment + end-to-end roundtrip on signet | 🟡 DEV live — PR [#17](https://github.com/zk-coins/node/pull/17) merged 2026-05-18 21:50 UTC; auto-deploy via `.github/workflows/deploy-dev.yaml` landed `zkcoins/node:beta` on `dev-api.zkcoins.app`. `/health` → 200 `ok`; `/api/info` → 200 with `{network:"Mutinynet", capabilities:{address_list, faucet, usernames, lnurl: true}, username_domain:"dev.zkcoins.app"}` (post-[#73](https://github.com/zk-coins/node/pull/73) `address_list` and `lnurl` are `false` because DEV ships the MVP-only binary identical to PRD; `faucet` and `usernames` are hardcoded `true` — mint and usernames are permanent MVP, not feature-gated; the `usernames` Cargo feature was later removed outright — see PR [#76](https://github.com/zk-coins/node/pull/76)). Bootstrap-unblock fix in PR [#36](https://github.com/zk-coins/node/pull/36) (explicit `MINTING_ADDRESS` override + global panic hook + smoke test + deploy-dev post-curl-retry; see [`MIGRATION_RESEARCH.md` §7.23](./MIGRATION_RESEARCH.md#723-minting_address-panic-in-tokiospawn-ed-task-swallows-node-bootstrap--medium-codified)). Deploy concurrency guards + PRD smoke test in PR [#51](https://github.com/zk-coins/node/pull/51). DEV/PRD parity (drop DEV-only Cargo features + remove `DEV_SKIP_BROADCAST_FAILURE` env-gate) in PR [#73](https://github.com/zk-coins/node/pull/73). **Remaining:** ① e2e roundtrip (create account → mint → send → receive) on signet from `dev.zkcoins.app`; ② R2 measurement on M3 Ultra (warm ≤ 5 s, ideal ≤ 1 s; cold ≤ 30 s; peak mem < 64 GB); ③ reactive: redesign per R2 if the budget is missed. | 2–4 d | medium |
| — | Pre-mainnet blockers: D2/D10 (recipient hiding), D7 (reorg safety), D8 (per-coin nullifier-accum) | ⏳ todo | **+2–3 weeks** | high (real protocol redesign) |

**MVP status:** Steps 1–8 ✅ done. Step 9 partially done — DEV is live and serving traffic; signet e2e roundtrip and the R2 performance measurement on M3 Ultra remain. **Remaining engineering effort: 0 d** for the migration itself; **remaining ops effort: ~2–4 d** for the e2e probe campaign + R2 budget check. If the R2 budget holds on first measurement, the migration is complete and the project moves to the pre-mainnet hardening track.

### Definition of "MVP"

For this project, an "MVP" is **minimum viable** in two simultaneous senses, both non-negotiable:

1. **Minimal feature surface.** Only what's needed for one complete user loop (create account → mint → send → receive → balance updates). No feature-bloat. If a capability is not on the critical path for that loop, it does not enter the MVP — see SPEC.md §15's deferred items.
2. **100% test coverage on the activated surface.** Same standard as the SP1/SHA256 codebase (see README.md "Contributing"). Code that is gated OFF in the MVP build (Cargo features `address-list`, `lnurl` — disabled in both DEV and PRD images since PR [#73](https://github.com/zk-coins/node/pull/73)) is excluded; everything else MUST be tested. Mint and usernames are part of the MVP and are permanently compiled in (no `faucet` or `usernames` Cargo feature), so they count toward the activated surface. `cargo llvm-cov --fail-under-lines 100 -- --test-threads=1` is the gate (run from inside the affected crate; `--test-threads=1` keeps circuit-test memory peaks predictable on the M3 Ultra).

These two requirements are not in tension — the first reduces the surface, the second keeps what remains clean. "MVP" is never an excuse to skip tests; it's an excuse to skip *features*. Negative tests (asserting that invalid witnesses are rejected) are mandatory for every gadget and every state-transition path.

### Architecture summary

The architecture is **node-side compute**: the node generates all ZK proofs; the wallet holds only the private key and signs BIP-340 Schnorr over `SHA256(serialize(asth) ‖ serialize(ocr))`. There is no in-browser Poseidon, no wasm-Plonky2 verifier, no in-app ZK gadget.

**Hardware target: Mac Studio M3 Ultra, 96 GB unified RAM, single host.** All on-box compute is available: Performance and Efficiency cores, the integrated Apple Silicon GPU (via Metal), Neural Engine, AMX. What is **not** available: external hardware accelerators (no NVIDIA, CUDA, GPU farms) and external cloud proving services (no Succinct Prover Network, no AWS GPU, no Lambda Labs). Performance budget is what the M3 Ultra delivers; if a design overshoots, the design changes — we do not add external hardware. Note: Plonky2 currently has no Metal / Apple-Silicon-GPU backend, so the integrated GPU is effectively idle for proving. That is a library property (Plonky2 ships CPU + CUDA only), not a constraint we imposed; if a Metal backend becomes available it's fair game.

zkCoins is in a **closed test environment** (DEV *and* PRD). No external users, no real money, no existing user-base to migrate. Step 7 therefore **replaces** the SP1 path outright rather than running a dual backend: SP1 modules are deleted, node starts with a clean Poseidon SMT/MMR state, no Cargo feature flag, no migration helpers. This is reflected in the lower effort estimates for step 7 (2–3 d instead of 3–5 d) and the dropped risk for R5.

Pre-mainnet hardening adds another 2–3 weeks on top.

---

## Done

Commit refs (newest first). Doc-only commits to ROADMAP / SPEC /
MIGRATION_RESEARCH / CONTRIBUTING are not individually listed once
they merely correct or extend this file — see `git log` for the
exhaustive history.

- [`d6a3cb9`](./../../commit/d6a3cb9) — test(account_node): 10 inline error-path tests (Account::new, get_minting_account_address Ok+Err, get_account_balance Ok+Err, load_from_file Err+missing-path, save+load roundtrip, send_coins Unknown account + Insufficient funds). Total test count 32 → 42. account_node.rs body still excluded from CI coverage gate (full SP1-era test-fixture port is a separate follow-up). state_tests.rs clippy auto-fixed in the same commit.
- [`dac0179`](./../../commit/dac0179) — feat(docker): Dockerfile for the Plonky2 node (Step 9 prep). `rust:bookworm` base + rustup auto-installs nightly via `rust-toolchain`. Multi-stage build, FEATURES build-arg, debian-bookworm-slim runtime, EXPOSE 4242. Local release build verified clean (1m 26s on M3 Ultra). Smoke run end-to-end: `cargo run --release -p node` + `curl /health` → `ok`, `curl /api/info` → `{"network":"Mutinynet"}`, block scanner connects + processes Mutinynet tip.
- [`c71c9fc`](./../../commit/c71c9fc) — feat(step-7): `send_coins` wired to the Plonky2 `Prover` wrapper. Off-circuit source-side validation (in-coin in source's output_coins_root + source commitment in history MMR) replaces Stage 5d-next-5 Phase 2 (deferred post-MVP, blocked on Plonky2 1.1.0 ConstantGate shape mismatch — see `MIGRATION_RESEARCH.md` §7.22 for the eventual resolution). MMR proof paths in `get_merkle_proofs` now extended to `MMR_PROOF_PATH_LEN`; history_root passed to prover is `state.mmr.root_extended(MMR_PROOF_PATH_LEN)`. Init vs AccountUpdate branch on `account.proof` + `DEV_SKIP_BROADCAST_FAILURE` env-var bypass preserved. The env-var bypass was later removed in PR [#73](https://github.com/zk-coins/node/pull/73) once DEV and PRD were unified on the MVP-only binary. Test re-enable (account_node_tests + router_tests modules disabled at include-point) is a separate follow-up.
- [`19dcecf`](./../../commit/19dcecf) — fix(ci): relax coverage scope to skip account_node.rs + router.rs during Step-7 migration (their test modules are gated off pending Stage 5d-next-5 merge); new `test_get_mmr_inclusion_proof_known_root_returns_ok` to keep state.rs at 100% line / function coverage.
- [`ee0ef4b`](./../../commit/ee0ef4b) — fix(ci+node): CI workflow rewritten for nightly toolchain + Plonky2 crate names; node clippy `-D warnings` cleanup (feature-gated structs `#[cfg(...)]`, deprecated `to_inner` → `to_keypair`, `unimplemented!` block replaced with explicit `Err` to avoid `diverging_sub_expression`); coverage timeout 30m → 60m.
- [`00adbb4`](./../../commit/00adbb4) — feat(step-7): workspace toolchain unification (stable → nightly, root absorbs `program-plonky2/` + `script-plonky2/`) + node-side import migration. `program/` + `script/` SP1 crates deleted. shared/node use the Plonky2-era modules (`hash`, `types`, `inputs`); `[u8;32]` → `HashOut<F>` boundary conversions via `digest_from_bytes` / `digest_to_bytes`; MMR leaf hash switched from SHA256 to Poseidon `hash_concat`. `account_node::send_coins` body wrapped in `unimplemented!` pending Prover-API integration after Stage 5d-next-5 merge. 31 node tests passing (scanner, state, username, etc.); `account_node_tests` + `router_tests` modules disabled at include point.
- [`b76bd39`](./../../commit/b76bd39) — feat(program-plonky2): step 7 prep — serde derives + persistence helpers (SMT/MMR/types/inputs all get `Serialize`/`Deserialize`; `save_merkle_tree` / `load_merkle_tree` / `save_mmr` / `load_mmr` ported from SP1-era helpers; 4 new tests for round-trip + missing-path I/O errors; `[u8; 33]` pubkey worked around with inline `BigArray33` helper to dodge serde's N≤32 derive limit)
- [`d96bb62`](./../../commit/d96bb62) — feat(script-plonky2): step 6 — host-side prover wrapper around `StateTransitionCircuit` (new crate `script-plonky2/` with `Prover` struct + `prove_initial` / `prove_account_update` / `verify` thin wrappers; mirrors the SP1-era `script/` crate shape; nightly toolchain via rust-toolchain.toml symlink to program-plonky2)
- [`c1df545`](./../../commit/c1df545) — docs: defer Stage 5d-next-4 source-side cyclic verify to 5d-next-5 (post-MVP) — Plonky2 1.1.0's `dummy_circuit` can't reproduce `ConstantGate`-containing common_data shapes (Approach A) AND the in-circuit data-only fallback hit `goal_data != common` mismatch at build (Approach B); the trusted node folding only validly-proved commitments into history MMR makes Stage 5d-next-3 + prev_account CMP sufficient for node-heavy MVP. See MIGRATION_RESEARCH §7.21.
- [`6ea965a`](./../../commit/6ea965a) — docs: finalise session pickup — §7.20 + test-confirmation + verification checklist
- [`7db536d`](./../../commit/7db536d) — docs: session-state pickup notes for next agent
- [`50a1bd9`](./../../commit/50a1bd9) — test: speed up account_update panic-tests via cyclic_base_proof (~25 min wall saved per full sweep)
- [`8fab78a`](./../../commit/8fab78a) — test: combined in-and-out integration test on AccountUpdate (mirror of `d292855` on the cyclic-recursion + CommitmentMerkleProofs path)
- [`05c17f8`](./../../commit/05c17f8) — docs(SPEC): note MAX_OUT_COINS in the constants table
- [`a502b8f`](./../../commit/a502b8f) — test: cover assert_eq panics on the *_in_and_out_coins wrappers (3 new should_panic tests for `prove_*_with_in_and_out_coins`)
- [`508ec9c`](./../../commit/508ec9c) — docs(ROADMAP): refresh commit list + test count after MAX_OUT_COINS=8 bump
- [`d292855`](./../../commit/d292855) — test: combined in-and-out integration test (one Initial proof exercising both in-coins and out-coins loops in a single transition; validates running-balance mutations and interim/final account_state_hash distinction compose correctly)
- [`56f3a05`](./../../commit/56f3a05) — feat: stage 5d-next-3-bump — MAX_OUT_COINS to 8 (mirrors MAX_IN_COINS at SPEC §13's production target; INNER_PAD_BITS bumped 13 → 14)
- [`1943316`](./../../commit/1943316) — docs: stage 5d-next-4 design doc for source verification
- [`6b5a885`](./../../commit/6b5a885) — feat: stage 5d-next-3 — out-coins processing
- [`b2b82e7`](./../../commit/b2b82e7) — feat: stage 5d-next-2 — bump MAX_IN_COINS to 8
- [`0195f71`](./../../commit/0195f71) — feat: stage 5d-next — apply_coin (recipient + balance + overflow). Per-slot witnesses extended with `coin_recipient`, `coin_amount_lo`, `coin_amount_hi`. Active slots assert `coin_recipient == account.owner` and `balance += coin_amount` with overflow check via `split_le(sum, 33)`. Running balance threaded through `MAX_IN_COINS` slots; final balance fed to a second Poseidon hash for the public `ProofData.account_state_hash`. New tests: positive (1 active in-coin, balance increases by 42, final hash matches off-circuit `apply_coin`); negatives (wrong recipient rejected, overflow rejected).
- [`7db3c29`](./../../commit/7db3c29) — feat: stage 5d (minimal) + 5e (partial) — in-coin slot processing for coin_history + four SPEC §13 negative tests. 5d adds `MAX_IN_COINS = 1` const, `InCoinSlotTargets` per slot (`active`, `coin_identifier`, 256-sibling `nip_path`), per-slot SMT non-inclusion + insert into `coin_history_root` masked by `active`, new `prove_initial_with_in_coins` / `prove_account_update_with_in_coins` wrappers, and 5 tests (1 positive + 1 negative + 3 panic guards). 5e adds 4 negative tests against the existing 5c+ predicates.
- [`2ce36ce`](./../../commit/2ce36ce) — test: cover assert_eq panic messages in set_cmp_witness (3 should_panic tests restoring 100% line coverage after 5c+)
- [`4bc5f2f`](./../../commit/4bc5f2f) — feat: stage 5c+ — `CommitmentMerkleProofs` in-circuit (SPEC §8 (c)(d)(e); fixed-shape SMT inclusion at `TREE_DEPTH = 256` + 2× MMR inclusion at `MMR_PROOF_PATH_LEN = 31`; new `MMR_MAX_DEPTH = 32` const + `MMRProof::extend_to(depth)` + `MerkleMountainRange::root_extended(depth)` off-circuit helpers; new `select_hash` masking pattern so every constraint fires only when `condition = true`; `dummy_cmp()` placeholder used by `prove_initial` to populate the unused fields; tests: positive bootstrap chain (Init→Update with full CommitmentMerkleProofs verify) plus negatives for (b), (c), (d).)
- [`4f317fe`](./../../commit/4f317fe) — refactor: SMT redesign to uncompressed fixed-256 paths (off-circuit `InclusionProof` / `NonInclusionProof` always carry exactly `TREE_DEPTH = 256` siblings; path compression removed from `insert` and proof generation; `NonInclusionProof.leaf` field dropped — non-inclusion now witnesses the empty-leaf default at the depth-256 slot; in-circuit `verify_smt_inclusion` / `verify_smt_non_inclusion` / `verify_smt_insert` reduced to a single `hash_up_full_path` engine; case A/B branch and `extension` parameter gone.)
- [`bba6470`](./../../commit/bba6470) — feat: stage 5c — AccountUpdate branch (condition now a free witness; cyclic verify binds SPEC §8 (a); state continuity (b) via `condition * (account_state_hash - prev.account_state_hash) == 0`; coin_history carry-over via `select(condition, prev.coin_history_root, DEFAULT_HASHES[0])`; mint exception masked with `!condition`; 5 tests incl. Initial→AccountUpdate chain and state-discontinuity rejection; SPEC §8 (c)(d)(e) MMR/SMT history checks DEFERRED to stage 5c+)
- [`d167237`](./../../commit/d167237) — feat: stage 5b — Initial-branch state-transition predicate (`circuit/main.rs` rewritten: counter payload replaced by 16-element `ProofData`, mint exception + empty-SMT roots + in-circuit Poseidon `AccountState::hash`, condition pinned `false`; 3 tests: mint accepted, non-mint zero-balance accepted, non-mint nonzero-balance rejected)
- [`83fa0c1`](./../../commit/83fa0c1) — feat: stage 5a — cyclic recursion plumbing PoC (`circuit/main.rs`, 2 tests: base + 1 recursive cycle; superseded by stage 5b)
- [`6cf949c`](./../../commit/6cf949c) — feat: SMT insert verify gadget (8 tests: 3 positive incl. deep-divergence Case B, 3 negative incl. case-A invariant, 2 build-time assertion panics)
- [`79bd39e`](./../../commit/79bd39e) — docs: hardware target — M3 Ultra single host, no external hardware, no cloud prover (later corrected to note the integrated Apple GPU IS available, just unused by Plonky2 today)
- [`e14d9df`](./../../commit/e14d9df) — feat: 100% test coverage on program-plonky2 (16 new tests + MMR refactor + coverage(off) annotations)
- [`2b6f2cb`](./../../commit/2b6f2cb) — docs: consistency review pass — fix stale counts, add glossary, reconcile §6
- [`401f813`](./../../commit/401f813) — docs(ROADMAP): closed test env — replace SP1, don't migrate
- [`cd94f85`](./../../commit/cd94f85) — docs: CONTRIBUTING + §7 Lessons Learned (8 entries)
- [`4cf98ac`](./../../commit/4cf98ac) — docs(ROADMAP): Plonky3 as post-MVP path; document rejected alternative
- [`1967087`](./../../commit/1967087) — docs(ROADMAP): node-side compute, drop wasm Poseidon
- [`2fed8f0`](./../../commit/2fed8f0) — feat: port `ProgramInputs` + `CommitmentMerkleProofs` (4 tests)
- [`9ba03bc`](./../../commit/9ba03bc) — feat: SMT non-inclusion verify gadget (3 tests + 1 negative)
- [`8002ce3`](./../../commit/8002ce3) — feat: SMT inclusion gadget + `circuit/util` (4 tests)
- [`5c92a62`](./../../commit/5c92a62) — docs: initial ROADMAP
- [`15d45c9`](./../../commit/15d45c9) — feat: MMR inclusion gadget (4 tests)
- [`e1af850`](./../../commit/e1af850) — feat: AccountState/Coin/ProofData (8 tests)
- [`c28e279`](./../../commit/c28e279) — feat: MMR to Poseidon (8 tests)
- [`6215009`](./../../commit/6215009) — feat: SMT to Poseidon + zero-state collision fix (12 tests)
- [`984580f`](./../../commit/984580f) — feat: Poseidon hash module (5 tests)
- [`8fa6a92`](./../../commit/8fa6a92) — chore: toolchain pin + lock §5 decisions
- [`72c3b78`](./../../commit/72c3b78) — feat: scaffold `program-plonky2/` standalone crate
- [`049ec3e`](./../../commit/049ec3e) — docs: SPEC reconciled with paper, §15 divergences
- [`57cdce4`](./../../commit/57cdce4) — docs: migration research
- [`496c652`](./../../commit/496c652) — docs: circuit specification

**Test count on this branch:** 103 (all green on nightly-2025-04-15).
Breakdown: `prelude` 1 · `hash` 5 · `merkle::smt` 19 · `merkle::mmr` 14 ·
`types` 10 · `inputs` 5 · `circuit::mmr` 5 · `circuit::smt` 12 ·
`circuit::main` 32.

**Coverage:** **100% lines, 100% functions, 100% regions** on `program-plonky2/`
as measured by `cargo llvm-cov --fail-under-lines 100`. Test modules
are annotated with `#[cfg_attr(coverage_nightly, coverage(off))]` so
assertion-message-string regions inside tests don't pollute the
production-surface measurement. Defensive `else ZERO_HASH` branches
in the MMR were collapsed into `.get().copied().unwrap_or(...)` so the
unreachable bounds-check shares one region with the success path
rather than carrying its own perpetually-uncovered branch.

---

## In Progress

**Step 5 — Monolithic state-transition circuit** (✅ done, broken into
stages, each landed as its own reviewable commit; preserved below as
the historical record):

- **5a — recursion plumbing PoC** ✅ done in [`83fa0c1`](./../../commit/83fa0c1),
  superseded by 5b. `circuit/main.rs` skeleton with
  `conditionally_verify_cyclic_proof_or_dummy`,
  `add_verifier_data_public_inputs`, three-pass
  `common_data_for_recursion`, and a counter payload (`counter = if
  condition { inner.counter + 1 } else { 0 }`). The R1 evidence that
  cyclic recursion + `circuit_digest` pinning work in our Plonky2
  1.1.0 setup. Tests and payload replaced in 5b.
- **5b — Initial branch with real predicate** ✅ done in
  [`d167237`](./../../commit/d167237). Counter payload replaced by
  16-element `ProofData` public output. In-circuit Poseidon
  `AccountState::hash` (with 32-bit balance limbs and 56-bit pubkey
  limbs, both range-checked), `is_minting` predicate via element-wise
  `is_equal` AND, mint exception enforced as `(1 - is_minting) *
  balance_limb == 0`, `output_coins_root` and `coin_history_root`
  constants from `DEFAULT_HASHES[0]`. `condition` constrained to
  `false`. Three tests in `circuit::main`.
- **5c — AccountUpdate branch** ✅ done in this revision. `condition`
  is now a free witness. `conditionally_verify_cyclic_proof_or_dummy`
  binds SPEC §8 (a) (same circuit via `circuit_digest`). State
  continuity (b) enforced as `condition * (account_state_hash[i] -
  prev.account_state_hash[i]) == 0` for each of the 4 hash elements.
  `coin_history_root` carry-over via `select(condition,
  prev.coin_history_root, DEFAULT_HASHES[0])`. Mint exception masked
  with `(1 - condition) * (1 - is_minting)` so it only applies to
  Initial. 5 tests in `circuit::main`: 3 Initial-side from 5b plus a
  full Initial→AccountUpdate chain (recursive verify works
  end-to-end) and an AccountUpdate state-discontinuity rejection.
  **SPEC §8 (c)(d)(e) — `CommitmentMerkleProofs` predicate proving
  prev was published in the global history MMR — is NOT YET WIRED.
  Stage 5c+ closes that gap.**
- **5c+ — CommitmentMerkleProofs in-circuit** ✅ done in commit
  [`4bc5f2f`](./../../commit/4bc5f2f). SPEC §8 (c)(d)(e) all wired via
  in-circuit SMT inclusion (`TREE_DEPTH = 256`) + 2× MMR inclusion
  (`MMR_PROOF_PATH_LEN = 31`). Coverage-fix in
  [`2ce36ce`](./../../commit/2ce36ce).
- **5d — in-coin slots (minimal)** ✅ done in this revision.
  `MAX_IN_COINS = 1` (production target is 8 per SPEC §13; bumping
  the constant is mechanical). Per slot the circuit reserves an
  `active` bit, a `coin_identifier`, and a 256-sibling
  `nip_path`. Active slots prove SMT non-inclusion of
  `coin_identifier` at the running `coin_history_root` and compute
  the new root after inserting `coin_identifier` (used both as key
  and as leaf value, making `coin_history` a set-membership SMT).
  Inactive slots are masked no-ops. The `coin_history_root` running
  value is chained through all slots and emitted as
  `ProofData.coin_history_root`. **NOT YET WIRED (defer to 5d+):**
  recursive verification of each in-coin's source proof, SMT
  inclusion of `coin.identifier` in `source.output_coins_root`, the
  source's own CommitmentMerkleProofs, and the apply_coin balance /
  recipient update on `AccountState`. Without these, in-coins are
  unsound (a prover can claim any `coin_identifier` was sent to
  them); 5d+ closes the gap. New tests in `circuit::main`: positive
  Init-with-1-active-in-coin into empty coin_history; tampered nip
  path rejected; 3 panic guards (`nip_path` length, slot count for
  `prove_initial_with_in_coins`, slot count for
  `prove_account_update_with_in_coins`).
- **5d-next — apply_coin semantics** ✅ done in this revision.
  Per-slot witnesses extended: `coin_recipient: HashOutTarget`,
  `coin_amount_lo: Target`, `coin_amount_hi: Target` (both
  range-checked to 32 bits). Per slot, masked by `active`:
  - Recipient check `active * (coin_recipient[i] - owner[i]) == 0`
    for each of 4 hash elements.
  - Balance add with overflow check via `split_le(sum, 33)`: bits
    auto-witnessed by Plonky2's `BaseSumGate` generator; bit 32 is
    the carry / overflow. `new_lo = sum_lo - 2^32 * carry`,
    `sum_hi = balance_hi + active * coin_amount_hi + carry`,
    `new_hi = sum_hi - 2^32 * overflow`, `assert overflow == 0`.
  - Running balance threaded through slots; final balance feeds a
    second `Poseidon(owner || final_balance_lo || final_balance_hi ||
    pubkey_limbs)` for the FINAL `account_state_hash` in `ProofData`.
    The earlier `account_state_hash` (from initial balance) keeps
    serving SPEC §8 (b) state-continuity and (c) commitment-witness
    checks. Tests: positive 1-active-in-coin with `coin.amount = 42`
    increments balance and matches off-circuit `apply_coin` hash;
    `recipient != owner` rejected; `amount` causing balance overflow
    rejected.

- **5d-next-2 — bump `MAX_IN_COINS` to 8** ✅ done in this revision.
  `MAX_IN_COINS` const is now 8. `common_data_for_recursion_c`
  padding bumped to `INNER_PAD_BITS = 13` (`1 << 13 = 8192` gates)
  to accommodate the larger outer circuit. Test helper
  `slots_first_active(&coin, &nip, &dummy_coin, &dummy_nip)` builds
  a `MAX_IN_COINS`-length slot array with the first slot active.
  All 4 `prove_*_with_in_coins` tests refactored to use it; build
  and prove confirmed for `stage_5d_initial_with_one_active_in_coin`
  (188s wall).

- **5d-next-3 — out-coins processing** ✅ done in this revision.
  `MAX_OUT_COINS = 1` slot reserved (mechanical bump to 8 later).
  Per slot witnesses: `active`, `out_coin_identifier`,
  `out_coin_amount_lo/hi`, `nip_path`. Per slot constraints (masked
  by `active`):
  - SMT non-inclusion + insert into `running_output_coins_root`
    (mirroring the in-coins coin_history pattern, but for the new
    `output_coins_root`).
  - Balance subtraction with **underflow check** via
    `split_le(diff, 64)` (vs. overflow check `split_le(sum, 33)` for
    in-coins addition).
  - `out_coin_identifier == Poseidon(interim_account_state_hash ||
    u32(slot_index))` — mirrors off-circuit
    [`crate::types::calculate_coin_identifier`].

  Pubkey rotation: new `next_public_key_limbs` witness. The FINAL
  `account_state_hash` (committed as `ProofData.account_state_hash`)
  uses the NEW pubkey; the interim hash (used for identifier
  derivation) uses the INITIAL pubkey, per SPEC §8 step 3 ordering.

  API: new `prove_initial_with_in_and_out_coins` /
  `prove_account_update_with_in_and_out_coins` for full caller
  control. The existing `prove_initial` / `prove_account_update`
  wrappers default `next_public_key = account_state.public_key`
  (no rotation) and all-inactive out-coin slots.

  Tests: positive `stage_5d_next_3_initial_with_one_active_out_coin`
  (one out-coin emits, balance decreases by amount, pubkey rotates,
  output_coins_root matches off-circuit insert); two negatives
  (wrong identifier, underflow); two panic guards (nip-path length,
  out-slot count).

- **5d-next-5 — source-side verification via aggregator pattern** ✅
  done via PR [#23](https://github.com/zk-coins/node/pull/23).
  Architecture: non-cyclic [`SourceAggregatorCircuit`](program-plonky2/src/circuit/source_aggregator.rs)
  bundles up to `MAX_IN_COINS` source proofs via per-slot
  `conditionally_verify_proof`; the outer state-transition circuit
  verifies the aggregator proof once via `verify_proof` and binds its
  claimed state-transition `verifier_data` to its own via
  `connect_hashes`. Per-slot SPEC §8 step 2 gates fire inside the
  in-coin loop: SMT inclusion of `coin.identifier` in
  `source.output_coins_root`, OCR coupling, SPEC §8 (c)(d)(e) chain
  for source's commitment in `history_root`, strict
  `connect(slot.active, aggregator.slot[i].active_pi)` so no in-coin
  can be consumed without a verified source. Two Plonky2 1.1.0
  shape-mismatch blockers were resolved empirically: explicit
  `ConstantGate::new(2)` injection in the helper's pass-3, and
  `INNER_PAD_BITS_STAGE_5D_NEXT_5 = 15` (`helper_degree = pad_bits +
  1`). Probes characterising both insights live in
  [`src/circuit/recursion_shape_probe.rs`](program-plonky2/src/circuit/recursion_shape_probe.rs).
  Full end-state in
  [`MIGRATION_RESEARCH.md` §7.22](./MIGRATION_RESEARCH.md#722-stage-5d-next-5-source-side-verification-via-aggregator-pattern--codified-resolves-721).
- **5e — negative tests from SPEC §13** ✅ done — all 11 negatives
  covered (the previously-deferred 3 source-side negatives landed
  with Stage 5d-next-5 Phase 3). Covered:
  - Initial non-mint balance ≠ 0 → rejected (`stage_5c_plus_initial_non_mint_nonzero_balance_rejected`).
  - Initial mint accepted (`stage_5c_plus_initial_mint_with_balance_accepted`, returns coin_history_root = DEFAULT_HASHES[0]).
  - Account update mismatched state hash → rejected (`stage_5c_plus_account_update_state_discontinuity_rejected`).
  - Prev's commitment_history_root not in current MMR → 4 tests:
    `stage_5e_account_update_tampered_mmr_a_path_rejected`,
    `stage_5e_account_update_tampered_mmr_b_path_rejected`,
    `stage_5e_account_update_wrong_mmr_sibling_rejected`,
    `stage_5e_account_update_wrong_history_root_rejected`.
  - Double-spend (same in-coin twice in coin_history) → rejected
    (`stage_5e_double_spend_same_coin_twice_rejected`).
  - Out-coin identifier mismatch → rejected
    (`stage_5d_next_3_initial_out_coin_wrong_identifier_rejected`).
  - Sum of outputs > balance (underflow) → rejected
    (`stage_5d_next_3_initial_out_coin_underflow_rejected`).
  - Sum of input amounts overflow → rejected
    (`stage_5d_initial_in_coin_overflow_rejected`).
  - Wrong recipient on in-coin → rejected
    (`stage_5d_initial_in_coin_wrong_recipient_rejected`).

  Newly covered by Stage 5d-next-5 Phase 3 (PR #23):
  - Input coin whose source-proof is not in commitment history →
    `stage_5d_next_5_phase_3_source_not_in_history_rejected`.
  - Input coin whose identifier is not in source's `output_coins_root`
    → `stage_5d_next_5_phase_3_coin_not_in_source_ocr_rejected`.
  - Wrong `vk` on recursive source proof →
    `stage_5d_next_5_phase_3_wrong_st_vk_on_aggregator_rejected`.

  Original (pre-stage-5b) wording: Overflow, underflow,
  wrong vk, double-spend, wrong identifier, mismatched
  account_state_hash, etc.

Each stage carries the 100 % line coverage gate before commit.

---

## Next (in order)

### Step 5 — Monolithic state-transition circuit — ✅ done (see *In Progress* above for the historical breakdown)
**Effort:** 3–5 days (actual).
**Files:** `program-plonky2/src/circuit/main.rs` (new) — the equivalent of `program/src/main.rs`.
**Scope:** assemble all gadgets into the full circuit; implement Initial vs. AccountUpdate branch via `conditionally_verify_cyclic_proof_or_dummy`; fix `MAX_IN_COINS = 8`; pin `vk` via `add_verifier_data_public_inputs`; commit `ProofData` as 16-element public output.
**Test plan (100% coverage gate applies):**
  - Single send (1 in-coin → 1 out-coin) — initial proof path.
  - Two sequential sends — update-proof recursion.
  - All 11 negative cases from SPEC §13 (overflow, underflow, wrong vk, double-spend, wrong identifier, mismatched account_state_hash, etc.). Each is a separate `assert!(data.prove(pw).is_err())` test.
  - `cargo llvm-cov` on the new circuit module must be 100% lines + branches.
**Risk:** **High.** First real test of Plonky2 cyclic recursion with our public-input shape. The BitVM reference's toy IVC pattern is the only existing example; correctness depends on identical `circuit_digest` between build passes (two-pass `common_data_for_recursion` trick).

### Step 6 — `script-plonky2/` prover host
**Effort:** 1–2 days.
**Files:** new crate `script-plonky2/`.
**Mirror of:** `script/src/lib.rs::Prover`.
**Test plan (100% coverage gate applies):**
  - End-to-end through `create_account` and `update_account` paths.
  - Error path: malformed inputs rejected.
  - `cargo llvm-cov` on the prover wrapper must be 100%.
**Risk:** Low. Plonky2 prover API is simpler than SP1's.

### Step 7 — Node: replace SP1 with Plonky2 (no dual backend)
**Effort:** 2–3 days.
**Files:** `node/src/account_node.rs`, `node/src/state.rs`, `node/src/scanner.rs`, `node/src/router.rs`. Plus delete the SP1-specific imports and replace the old `program/` and `script/` references with `program-plonky2/` + `script-plonky2/`.
**Strategy:** closed test environment means no migration. Stop the running DEV/PRD node, delete the existing SMT/MMR data files (`smt.bin`, `mmr.bin`, `accounts.bin`, `latest_block.bin`), start the new Plonky2-based node with a fresh state. No Cargo feature flag, no compatibility shim, no parallel-deploy.
**Key challenge:** the Schnorr commitment message stays `SHA256(serialize(asth) ‖ serialize(ocr))` per §5.4 of `MIGRATION_RESEARCH.md`, so the scanner converts Poseidon outputs to bytes before SHA256 → BIP-340 verify.
**Test plan (100% coverage gate applies):** the same `cargo llvm-cov -p node --fail-under-lines 100` gate that already enforces this on the SP1 build carries over. Every handler, every error path, every scanner state transition that lives in the PRD-feature-set must be covered. The current SP1 coverage baseline (see README.md table) is the floor to maintain.
**Risk:** Low. Mechanical port, no compatibility surface area.

### Step 8 — App / wallet — ✅ done
**Status:** Pre-existing app-repo wiring already matches the new Plonky2 node contract — no code change required for the MVP.
**Files in `zk-coins/app`:**
  - `rust/client/src/lib.rs` — `create_commitment(xpriv, num_pubkeys, asth_hex, ocr_hex)` (BIP-340 Schnorr over `SHA256(asth ‖ ocr)`, returns `{public_key, signature, message}` JSON).
  - `src/app/send/page.tsx` — Phase 1 (`/api/send`) + Phase 2 (`/api/commit`) two-step send flow with in-flight commit persistence + retry.
  - `src/lib/api/client.ts` — typed client for every API route registered in `node/src/router.rs` (`info`, `balance`, `send`, `commit`, `mint`, `username/claim`, `username/resolve`, `address`).
  - `src/__tests__/app/send-pipeline.test.tsx` — round-trip + retry + idempotency unit tests (mocked WASM).
  - `src/__tests__/lib/api/contract.live.test.ts` — schema-conformance probes against a live API.
**Why nothing changed in the wallet for the Plonky2 cutover:** the wallet operates strictly above the node-side ZK boundary. It signs `SHA256(asth ‖ ocr)` — both 32-byte hex blobs supplied by the node — with secp256k1. Whether the node computed `asth`/`ocr` via SP1+SHA256 or Plonky2+Poseidon is opaque to the wallet, and `digest_to_bytes` on the node side already serialises Poseidon `HashOut<F>` into the same 32-byte shape (see `program-plonky2/src/hash.rs:48`).
**Test gate:** existing Vitest coverage gate in `zk-coins/app` (per that repo's CONTRIBUTING.md). No new gate.
**Remaining open question for Step 9 verification:** that `signature_verifies_after_app_send` lands as an e2e probe against the live DEV node. This is part of Step 9, not Step 8.

### Step 9 — DEV deployment + e2e — 🟡 DEV live, e2e + R2 pending
**Done:**
  - PR [#17](https://github.com/zk-coins/node/pull/17) merged 2026-05-18 21:50 UTC. Auto-deploy via `.github/workflows/deploy-dev.yaml` pushed `zkcoins/node:beta` to Docker Hub and deployed to the DEV host. Bootstrap fix in PR [#36](https://github.com/zk-coins/node/pull/36) (explicit `MINTING_ADDRESS` override + global panic hook + smoke test + deploy-dev post-curl-retry — see [`MIGRATION_RESEARCH.md` §7.23](./MIGRATION_RESEARCH.md#723-minting_address-panic-in-tokiospawn-ed-task-swallows-node-bootstrap--medium-codified)).
  - `https://dev-api.zkcoins.app/health` → 200 `ok`; `https://dev-api.zkcoins.app/api/info` → 200 with `{network:"Mutinynet", capabilities:{address_list, faucet, usernames, lnurl: true}, username_domain:"dev.zkcoins.app"}` (post-[#73](https://github.com/zk-coins/node/pull/73) `address_list` and `lnurl` are `false` because DEV ships the MVP-only binary identical to PRD; `faucet` and `usernames` are hardcoded `true` — mint and usernames are permanent MVP, not feature-gated; the `usernames` Cargo feature was later removed outright — see PR [#76](https://github.com/zk-coins/node/pull/76)).
  - Deploy hardening: PR [#51](https://github.com/zk-coins/node/pull/51) added deploy-dev + deploy-prd concurrency guards and a PRD smoke test.
  - DEV/PRD parity: PR [#73](https://github.com/zk-coins/node/pull/73) dropped the DEV-only Cargo features (`address-list`, `faucet`, `usernames`, `lnurl`) and removed the `DEV_SKIP_BROADCAST_FAILURE` env-gate so the two environments run the identical MVP-only binary. A follow-up refactor removed the `faucet` Cargo feature outright — mint is permanent MVP and ships unconditionally in every build — and a further refactor removed the `usernames` Cargo feature so usernames are permanent MVP and ship unconditionally too (PR [#76](https://github.com/zk-coins/node/pull/76)).
**Remaining:**
  1. e2e roundtrip on signet from `dev.zkcoins.app`: create account → mint → send → recipient receives. Success criterion: one happy-path + one failure-path per route. Tracked via a follow-up GitHub issue.
  2. Real performance measurement on the M3 Ultra. R2 budget: warm proof ≤ 5 s, ideally ≤ 1 s; cold-start ≤ 30 s including circuit-data load; peak mem < 64 GB during proving. Plonky2 currently runs CPU-only on Apple Silicon (no Metal backend); that's the operative baseline.
  3. If budget is missed: redesign per R2 (reduce `MAX_IN_COINS`, drop in-coin recursion, or switch to folding). **NOT** add external hardware or move to a cloud prover — the closed-environment + single-host constraint is non-negotiable.
**Test plan:** the authoritative coverage gate runs in CI on the self-hosted M3 Ultra runner pool (`.github/workflows/ci.yaml`, jobs `Node + Shared Tests` and `Coverage Gate`, gated behind the `ci:full` label per PR [#48](https://github.com/zk-coins/node/pull/48)); the pre-push hook only enforces fmt + clippy + `cargo check`. Step 9 verifies integration, not unit coverage. e2e success criterion: every endpoint round-trips under realistic conditions (one happy-path traversal per route plus at least one failure path per route).
**Risk:** Medium. First real exposure of the cyclic-recursive prover to production hardware under realistic load. If the budget holds, MVP is done.

---

## Pre-Mainnet Hardening

These are not MVP scope but block mainnet, per `SPEC.md` §15.

| # | Item | Effort |
| - | ---- | ------ |
| D2/D10 | Hiding recipient commitments (`Commitment::commit(acct_id, rand)`) — fixes coin-linkability | 1 week |
| D7 | Conditional-noop on reorg (gracefully degrade when claimed nullifier-accum no longer a prefix) | 4–5 days |
| D8 | Per-coin nullifier-accum snapshot — recipients verify coin age locally | 2–3 days |
| Tests | Paper-derived test suite from `MIGRATION_RESEARCH.md` §3 (A-SEC, ToSAcc prefix, half-aggregate Schnorr, etc.) | 1 week |

**Total pre-mainnet add-on: ~2–3 weeks.**

---

## Long-term positioning

Plonky2 is bridge technology. Post-MVP (after step 9): Plonky3 evaluation. Field/hash choice then via planned migration, not via ad-hoc drift.

---

## Risk Register

### R1 — Plonky2 cyclic recursion correctness (high)
**What can go wrong:** Step 5 fails because `circuit_digest` isn't stable between the two `common_data_for_recursion` passes, or the public-input layout in `add_verifier_data_public_inputs` is misaligned.
**Mitigation:** Start step 5 with the simplest possible "I verify myself with a trivial payload" circuit before adding the real predicate. Validates the recursion plumbing in isolation.
**Trigger to escalate:** if 1 day of debugging step 5 doesn't produce a verifying proof, escalate to the maintainers / the Plonky2 community.

### R2 — 1-second proof target unreachable on M3 Ultra (medium)
**What can go wrong:** Real circuit with 1+8 recursive verifies is too large for sub-second proving on the target hardware.
**Hardware constraint:** Mac Studio M3 Ultra, 96 GB RAM, single host. The integrated Apple GPU is on the box and would be usable IF Plonky2 had a Metal backend — it doesn't, so de facto we're on CPU. External hardware (NVIDIA, CUDA, GPU farms) and external cloud provers (Succinct Network, AWS, etc.) are off the table. If proof time overshoots, the design changes; we do not add external hardware.
**Mitigation knobs (all design-level):**
  (a) reduce `MAX_IN_COINS`;
  (b) drop recursion of in-coin proofs (replace with off-circuit nullifier-set check; this is a protocol change);
  (c) switch to a folding scheme (Nova / HyperNova / similar) that's CPU-native;
  (d) opportunistic: if a Plonky2 Metal backend becomes available, evaluate.
**Explicitly OFF the table:** discrete NVIDIA / CUDA hardware (we have an Apple Silicon box, not an x86 + NVIDIA host), Succinct Prover Network (violates closed-test-env + no-external-services rule), Apple Neural Engine / AMX as custom-kernel targets (we won't author the kernels ourselves).
**Trigger to escalate:** measured proof time > 5 s on M3 Ultra. Wallet-side performance is N/A — proving is node-side; the wallet's send-flow latency = proof time + network roundtrip.

### R3 — (removed)
Was: "Wasm Poseidon too slow." No longer applicable — the wallet performs no Poseidon hashing (node-side compute architecture). The wallet's only crypto is BIP-340 Schnorr signing of a SHA256 digest, which WebCrypto handles natively.

### R4 — Pre-mainnet hardening pushes timeline (high)
**What can go wrong:** D2/D10 hiding recipient is a real protocol change, not a patch. May require re-doing step 5 if it doesn't fit the existing circuit shape.
**Mitigation:** Decide before mainnet whether to ship the MVP variant first (linkable recipients, documented) and harden later, or harden now. Currently planning the former (per §5.5 in MIGRATION_RESEARCH).
**Trigger to escalate:** if regulatory or PR feedback flags linkability before MVP launch.

### R5 — SP1 stays in the workspace forever (mitigated by closed-env strategy)
**What was the worry:** dual-backend Cargo feature flag would let SP1 linger because there's no forcing event to remove it.
**Mitigation in place:** zkCoins is in a closed test environment (DEV + PRD), so step 7 doesn't introduce a feature flag — it deletes the SP1 path outright as part of the rewire. There is no parallel-backend phase, therefore no "follow-up cleanup PR" needed. Risk reduced from medium to low.

### R6 — Plonky2 itself becomes the new dead-end (medium, long horizon)
**What can go wrong:** Plonky2 is in maintenance mode at 0xPolygonZero. Plonky3 is where active development goes (new gate sets, BabyBear field, Poseidon2 hash, GPU paths). If we ignore Plonky3 indefinitely we end up where SP1 left us — on a stack with no upstream momentum.
**Mitigation:** Treat Plonky2 as **bridge technology**, not the final destination. See *Post-MVP path: Plonky3* below.
**Trigger to escalate:** Plonky2 upstream goes 12 months without a release, OR Plonky3 reaches feature parity for our use-case (recursion + BIP-340-Schnorr boundary).

---

## Post-MVP Path: Plonky3

Plonky2 is the **MVP bridge**, not the long-term substrate. After step 9
succeeds we schedule a Plonky3 evaluation. Concretely:

- **Field:** Plonky3 default is **BabyBear** (`p = 2^31 - 2^27 + 1`).
  Smaller field, GPU-friendlier in general — but the GPU paths in
  practice mean *CUDA*, which our M3 Ultra host can't run. Apple
  Silicon GPU support would have to come via Metal in the prover
  library; that's not the typical Plonky3-BabyBear GPU pitch. The
  motivation for BabyBear here therefore reduces to "matches SP1's
  choice / Plonky3-native"; Plonky2 we use Goldilocks because that's
  Plonky2's mature default.
- **Hash:** Plonky3 default is **Poseidon2** (~2× faster than the
  original Poseidon used in Plonky2).
- **Gadget reuse:** algorithmic structure (SMT, MMR, ProofData layout,
  recursion contract) stays. The Plonky3 port is primarily plumbing —
  re-typing field elements, swapping the hash function, adjusting limb
  packing for BabyBear's smaller modulus.
- **Estimated effort for Plonky3 cutover:** 2–4 weeks. Field and hash
  change cost ~20% of that; the rest is Plonky3's different API
  (recursion patterns, gate sets, witness generation).
- **Trigger to start:** Plonky3 reaches feature parity for recursion +
  our public-input layout. Currently (2026-05) it is close but the
  recursion ergonomics are still under active iteration.

### Considered alternative — adopt BabyBear + Poseidon2 inside Plonky2 *now*

A reviewer suggested switching to BabyBear field and Poseidon2 hash
already during this Plonky2 migration so that the Plonky3 cutover later
becomes "pure glue code". Rejected for v1:

1. **Plonky2 + BabyBear is fork-land.** `plonky2` 1.1.0 on crates.io is
   Goldilocks-only. BabyBear support exists in community forks
   (`plonky2-goldibear`-style) but those carry less upstream momentum
   than the canonical Goldilocks build. We'd trade one upstream-mature
   stack for one less-mature stack, with no MVP benefit.
2. **Poseidon2 in Plonky2 needs custom implementation.** The crate's
   `PoseidonHash` is Poseidon1. Poseidon2 means either hand-rolling the
   permutation or pulling another community crate. Custom crypto code
   in the MVP path is exactly what we want to avoid.
3. **Migration cost now is non-trivial.** Switching to BabyBear means
   re-doing `hash.rs`, `types.rs`, both Merkle modules (Goldilocks's
   2-limb u64 → BabyBear's 3-limb u64, 4-element digest → 8-element
   digest, ProofData re-shape, etc.). Roughly 3–4 days of work that
   produces no end-user-visible change.
4. **Plonky3 cutover later is not "glue code" anyway.** Plonky3's API
   (recursion ergonomics, gate sets, witness generation) is meaningfully
   different from Plonky2's. The field/hash choice contributes maybe 20%
   of that work; the rest happens either way. Switching field early
   shrinks the eventual diff by maybe one day, at the cost of slower MVP
   delivery.

The decision is reversible: if the Plonky3 evaluation post-step-9 shows
a clean enough path, we can do the field+hash switch *as part of* that
migration with no extra structural cost.

---

## Update Protocol

Whenever a commit lands on this branch:

1. If the commit completes a step → flip its row in *Status at a Glance* to ✅ and move its entry under *Done*.
2. If the commit partially completes a step → flip to 🟡 and note progress under *In Progress*.
3. If new tasks emerge → add a row in *Next* or *Pre-Mainnet Hardening* with effort estimate.
4. If the commit invalidates an estimate → revise the *Effort* column.
5. If the commit hits or escalates a risk → update the relevant *Risk Register* entry.

Stale roadmap = broken roadmap. If a commit changes scope and this file
isn't updated, the next reviewer should reject the PR until it is.
