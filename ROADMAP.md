# Plonky2 Migration Roadmap

Living tracker for the SP1 → Plonky2 + Poseidon migration on branch
`feat/plonky2-migration`. **Updated on every commit to this branch** — if
this file is stale relative to recent commits, that is a bug.

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
| 5 | Monolithic state-transition circuit (recursion, padding, vk-pin) | 🟡 in progress | **3–5 d** | **high** (vk-pin correctness, first real recursion test) |
| 6 | `script-plonky2/` host-side prover wrapper | ⏳ todo | 1–2 d | low |
| 7 | Server: **replace** SP1 path with Plonky2 (no feature flag, no dual backend) | ⏳ todo | 2–3 d | low (closed test env — no migration logic needed) |
| 8 | App / wallet: Schnorr-signing boundary, server-API integration | ⏳ todo | 1–2 d | low (server-side compute architecture — no wasm-crypto migration) |
| 9 | DEV deployment + end-to-end roundtrip on signet | ⏳ todo | 3–5 d | medium |
| — | Pre-mainnet blockers: D2/D10 (recipient hiding), D7 (reorg safety), D8 (per-coin nullifier-accum) | ⏳ todo | **+2–3 weeks** | high (real protocol redesign) |

**MVP total (steps 1–9): ~2.5–4 weeks full-time** assuming no major surprises in step 5 (Plonky2 recursion vk-pinning).

### Definition of "MVP"

For this project, an "MVP" is **minimum viable** in two simultaneous senses, both non-negotiable:

1. **Minimal feature surface.** Only what's needed for one complete user loop (create account → mint → send → receive → balance updates). No feature-bloat. If a capability is not on the critical path for that loop, it does not enter the MVP — see SPEC.md §15's deferred items.
2. **100% test coverage on the activated surface.** Same standard as the SP1/SHA256 codebase (see README.md "Contributing"). Code that is gated OFF in the PRD build (Cargo features like `address-list`, `faucet`, `usernames`, `lnurl`) is excluded; everything else MUST be tested. `cargo llvm-cov --fail-under-lines 100 -- --test-threads=1` is the gate (run from inside the affected crate; `--test-threads=1` keeps circuit-test memory peaks predictable on the M3 Ultra).

These two requirements are not in tension — the first reduces the surface, the second keeps what remains clean. "MVP" is never an excuse to skip tests; it's an excuse to skip *features*. Negative tests (asserting that invalid witnesses are rejected) are mandatory for every gadget and every state-transition path.

### Architecture summary

The architecture is **server-side compute**: the server generates all ZK proofs; the wallet holds only the private key and signs BIP-340 Schnorr over `SHA256(serialize(asth) ‖ serialize(ocr))`. There is no in-browser Poseidon, no wasm-Plonky2 verifier, no in-app ZK gadget.

**Hardware target: Mac Studio M3 Ultra, 96 GB unified RAM, single host.** All on-box compute is available: Performance and Efficiency cores, the integrated Apple Silicon GPU (via Metal), Neural Engine, AMX. What is **not** available: external hardware accelerators (no NVIDIA, CUDA, GPU farms) and external cloud proving services (no Succinct Prover Network, no AWS GPU, no Lambda Labs). Performance budget is what the M3 Ultra delivers; if a design overshoots, the design changes — we do not add external hardware. Note: Plonky2 currently has no Metal / Apple-Silicon-GPU backend, so the integrated GPU is effectively idle for proving. That is a library property (Plonky2 ships CPU + CUDA only), not a constraint we imposed; if a Metal backend becomes available it's fair game.

zkCoins is in a **closed test environment** (DEV *and* PRD). No external users, no real money, no existing user-base to migrate. Step 7 therefore **replaces** the SP1 path outright rather than running a dual backend: SP1 modules are deleted, server starts with a clean Poseidon SMT/MMR state, no Cargo feature flag, no migration helpers. This is reflected in the lower effort estimates for step 7 (2–3 d instead of 3–5 d) and the dropped risk for R5.

Pre-mainnet hardening adds another 2–3 weeks on top.

---

## Done

Commit refs (newest first). Doc-only commits to ROADMAP / SPEC /
MIGRATION_RESEARCH / CONTRIBUTING are not individually listed once
they merely correct or extend this file — see `git log` for the
exhaustive history.

- (next commit) — docs(ROADMAP): refresh test count + combined-test entry after `d292855`.
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
- [`1967087`](./../../commit/1967087) — docs(ROADMAP): server-side compute, drop wasm Poseidon
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

**Test count on this branch:** 102 (all green on nightly-2025-04-15).
Breakdown: `prelude` 1 · `hash` 5 · `merkle::smt` 19 · `merkle::mmr` 14 ·
`types` 10 · `inputs` 5 · `circuit::mmr` 5 · `circuit::smt` 12 ·
`circuit::main` 31.

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

**Step 5 — Monolithic state-transition circuit** (🟡, broken into five
stages so each lands as its own reviewable commit on the branch):

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

- **5d-next-4 — source-side verification for in-coins** ⏳ (heaviest
  remaining). Each in-coin requires recursively verifying its source
  proof (another `StateTransitionCircuit` instance), then asserting
  SPEC §8: `cp.output_coins_root` contains `coin.identifier` (SMT
  inclusion); `cp.commitment_history_root` is a prefix of current
  `history_root` (a CommitmentMerkleProofs (d)+(e) instance per
  in-coin); `cp.output_coins_root == mp.commitment_out_coins_root`.
  Requires multiple `conditionally_verify_cyclic_proof_or_dummy`
  calls — the Plonky2 1.1.0 cyclic-recursion machinery accepts only
  one inner proof per call, so we either iterate it `MAX_IN_COINS +
  1` times (once for prev_account, once per in-coin) or fold all
  inner proofs through a recursive aggregator first.
  `common_data_for_recursion_c` shape must match the outer circuit's
  actual verify_proof count; scale the helper accordingly.
- **5e — negative tests from SPEC §13** ✅ done for everything the
  current circuit can express (1 of 11 still pending the deferred
  5d-next-4 source verification). Covered:
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

  **Still deferred** (depends on 5d-next-4 source verification):
  - Input coin whose source-proof is not in commitment history.
  - Input coin whose identifier is not in source's `output_coins_root`.
  - Wrong `vk` on recursive source proof.

  Original (pre-stage-5b) wording: Overflow, underflow,
  wrong vk, double-spend, wrong identifier, mismatched
  account_state_hash, etc.

Each stage carries the 100 % line coverage gate before commit.

---

## Next (in order)

### Step 5 — Monolithic state-transition circuit — 🟡 **in progress** (see *In Progress* above)
**Effort:** 3–5 days.
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

### Step 7 — Server: replace SP1 with Plonky2 (no dual backend)
**Effort:** 2–3 days.
**Files:** `server/src/account_server.rs`, `server/src/state.rs`, `server/src/scanner.rs`, `server/src/server.rs`. Plus delete the SP1-specific imports and replace the old `program/` and `script/` references with `program-plonky2/` + `script-plonky2/`.
**Strategy:** closed test environment means no migration. Stop the running DEV/PRD server, delete the existing SMT/MMR data files (`smt.bin`, `mmr.bin`, `accounts.bin`, `latest_block.bin`), start the new Plonky2-based server with a fresh state. No Cargo feature flag, no compatibility shim, no parallel-deploy.
**Key challenge:** the Schnorr commitment message stays `SHA256(serialize(asth) ‖ serialize(ocr))` per §5.4 of `MIGRATION_RESEARCH.md`, so the scanner converts Poseidon outputs to bytes before SHA256 → BIP-340 verify.
**Test plan (100% coverage gate applies):** the same `cargo llvm-cov -p server --fail-under-lines 100` gate that already enforces this on the SP1 build carries over. Every handler, every error path, every scanner state transition that lives in the PRD-feature-set must be covered. The current SP1 coverage baseline (see README.md table) is the floor to maintain.
**Risk:** Low. Mechanical port, no compatibility surface area.

### Step 8 — App / wallet
**Effort:** 1–2 days.
**Files:** `zk-coins/app` repo (separate). Mostly server-API integration.
**Scope:** The wallet only needs:
  - BIP-340 Schnorr signing over `SHA256(serialize(asth) ‖ serialize(ocr))` (WebCrypto's SHA256 + a secp256k1 library — no Poseidon).
  - Display of balance / send-quotes / receive-confirmations from the server API.
  - No in-app ZK proof generation, verification, or Merkle hashing.
**Test plan (100% coverage gate applies):** same Jest/Vitest coverage gate that already applies to `zk-coins/app` (see that repo's README). Signing logic, message serialisation, API client, and error paths all covered. UI integration tests for the user loop (create account → send → receive).
**Risk:** Low. The wallet trusts the server for ZK correctness — this is the
explicit zkCoins architectural choice (server-side compute).

### Step 9 — DEV deployment + e2e
**Effort:** 3–5 days.
**Plan:**
  - Build `zkcoin/server-plonky2:beta`, deploy to `dfxdev`.
  - Wallet at `dev-app.zkcoins.app` points at it.
  - Roundtrip: create account → mint → send → recipient receives.
  - Measure: cold-start proof time, warm proof time, memory usage.
**Test plan (100% coverage gate applies for code; e2e separately):**
  - Coverage of all server endpoints exercised by the wallet during the e2e roundtrip must already be 100% from step 7's gate; this step verifies the integration, not the unit coverage.
  - e2e success criteria: every endpoint round-trips under realistic conditions (one happy-path traversal per route plus at least one failure path per route).
  - Performance budget on the M3 Ultra (96 GB, single-host): warm proof ≤ 5 s, ideally ≤ 1 s; cold-start (first-proof after server boot) ≤ 30 s including circuit-data load; memory peak < 64 GB during proving (leaves 32 GB for OS, scanner, REST, OS cache). Plonky2's current CPU-only execution on Apple Silicon is the operative baseline since there is no Metal backend.
  - If the budget is missed: redesign per R2 (reduce MAX_IN_COINS, drop in-coin recursion, or switch to folding). **NOT** add external hardware or move to a cloud prover.
**Risk:** Medium. First real exposure to the full stack under realistic load on the actual production hardware.

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
**Trigger to escalate:** if 1 day of debugging step 5 doesn't produce a verifying proof, ask Robin / the Plonky2 community.

### R2 — 1-second proof target unreachable on M3 Ultra (medium)
**What can go wrong:** Real circuit with 1+8 recursive verifies is too large for sub-second proving on the target hardware.
**Hardware constraint:** Mac Studio M3 Ultra, 96 GB RAM, single host. The integrated Apple GPU is on the box and would be usable IF Plonky2 had a Metal backend — it doesn't, so de facto we're on CPU. External hardware (NVIDIA, CUDA, GPU farms) and external cloud provers (Succinct Network, AWS, etc.) are off the table. If proof time overshoots, the design changes; we do not add external hardware.
**Mitigation knobs (all design-level):**
  (a) reduce `MAX_IN_COINS`;
  (b) drop recursion of in-coin proofs (replace with off-circuit nullifier-set check; this is a protocol change);
  (c) switch to a folding scheme (Nova / HyperNova / similar) that's CPU-native;
  (d) opportunistic: if a Plonky2 Metal backend becomes available, evaluate.
**Explicitly OFF the table:** discrete NVIDIA / CUDA hardware (we have an Apple Silicon box, not an x86 + NVIDIA host), Succinct Prover Network (violates closed-test-env + no-external-services rule), Apple Neural Engine / AMX as custom-kernel targets (we won't author the kernels ourselves).
**Trigger to escalate:** measured proof time > 5 s on M3 Ultra. Wallet-side performance is N/A — proving is server-side; the wallet's send-flow latency = proof time + network roundtrip.

### R3 — (removed)
Was: "Wasm Poseidon too slow." No longer applicable — the wallet performs no Poseidon hashing (server-side compute architecture). The wallet's only crypto is BIP-340 Schnorr signing of a SHA256 digest, which WebCrypto handles natively.

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
