# Plonky2 Migration Roadmap

Living tracker for the SP1 → Plonky2 + Poseidon migration on branch
`feat/plonky2-migration`. **Updated on every commit to this branch** — if
this file is stale relative to recent commits, that is a bug.

Source documents:

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
| 4c+ | In-circuit SMT insert gadget (new-root computation) | ⏳ todo | 1 d | medium (fixed-depth padding) |
| 4d | Port `ProgramInputs` + `CommitmentMerkleProofs` types | ✅ done | — | — |
| 5 | Monolithic state-transition circuit (recursion, padding, vk-pin) | ⏳ todo | **3–5 d** | **high** (vk-pin correctness, first real recursion test) |
| 6 | `script-plonky2/` host-side prover wrapper | ⏳ todo | 1–2 d | low |
| 7 | Server: **replace** SP1 path with Plonky2 (no feature flag, no dual backend) | ⏳ todo | 2–3 d | low (closed test env — no migration logic needed) |
| 8 | App / wallet: Schnorr-signing boundary, server-API integration | ⏳ todo | 1–2 d | low (server-side compute architecture — no wasm-crypto migration) |
| 9 | DEV deployment + end-to-end roundtrip on signet | ⏳ todo | 3–5 d | medium |
| — | Pre-mainnet blockers: D2/D10 (recipient hiding), D7 (reorg safety), D8 (per-coin nullifier-accum) | ⏳ todo | **+2–3 weeks** | high (real protocol redesign) |

**MVP total (steps 1–9): ~2.5–4 weeks full-time** assuming no major surprises in step 5 (Plonky2 recursion vk-pinning).

### Definition of "MVP"

For this project, an "MVP" is **minimum viable** in two simultaneous senses, both non-negotiable:

1. **Minimal feature surface.** Only what's needed for one complete user loop (create account → mint → send → receive → balance updates). No feature-bloat. If a capability is not on the critical path for that loop, it does not enter the MVP — see SPEC.md §15's deferred items.
2. **100% test coverage on the activated surface.** Same standard as the SP1/SHA256 codebase (see README.md "Contributing"). Code that is gated OFF in the PRD build (Cargo features like `address-list`, `faucet`, `usernames`, `lnurl`) is excluded; everything else MUST be tested. `cargo llvm-cov --fail-under-lines 100` is the gate.

These two requirements are not in tension — the first reduces the surface, the second keeps what remains clean. "MVP" is never an excuse to skip tests; it's an excuse to skip *features*. Negative tests (asserting that invalid witnesses are rejected) are mandatory for every gadget and every state-transition path.

### Architecture summary

The architecture is **server-side compute**: the server generates all ZK proofs; the wallet holds only the private key and signs BIP-340 Schnorr over `SHA256(serialize(asth) ‖ serialize(ocr))`. There is no in-browser Poseidon, no wasm-Plonky2 verifier, no in-app ZK gadget. Performance is sized for server hardware (M3 Ultra baseline; GPU / Succinct Prover Network as upgrade paths), not laptop or mobile.

zkCoins is in a **closed test environment** (DEV *and* PRD). No external users, no real money, no existing user-base to migrate. Step 7 therefore **replaces** the SP1 path outright rather than running a dual backend: SP1 modules are deleted, server starts with a clean Poseidon SMT/MMR state, no Cargo feature flag, no migration helpers. This is reflected in the lower effort estimates for step 7 (2–3 d instead of 3–5 d) and the dropped risk for R5.

Pre-mainnet hardening adds another 2–3 weeks on top.

---

## Done

Commit refs (newest first). Doc-only commits to ROADMAP / SPEC /
MIGRATION_RESEARCH / CONTRIBUTING are not individually listed once
they merely correct or extend this file — see `git log` for the
exhaustive history.

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

**Test count on this branch:** 64 (all green on nightly-2025-04-15).
Breakdown: `hash` 5 · `merkle::smt` 19 · `merkle::mmr` 11 · `types` 10 ·
`inputs` 5 · `circuit::mmr` 5 · `circuit::smt` 9.

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

*(none — every "done" line is committed and on the branch.)*

---

## Next (in order)

### Step 4c+ — SMT insert gadget (new-root computation)
**Effort:** ~1 day.
**Files:** `program-plonky2/src/circuit/smt.rs` (extends the existing module).
**Mirror of:** `NonInclusionProof::insert` / `verify_and_insert`.
**Test plan (100% coverage gate applies):**
  - After non-inclusion verify, also assert the computed new-root matches the off-circuit `verify_and_insert` result. Both case A (empty subtree) and case B (path-compressed neighbour).
  - Negative: tampered new leaf or wrong padding rejected.
**Risk:** Medium. The off-circuit insert has a variable-length default-hash padding loop driven by where `key` and `other_key` diverge. In-circuit either: (a) compute the divergence depth as a witness and conditionally hash up to `TREE_DEPTH` always, or (b) require the host to pre-pad the path to a fixed depth. Plan: (b), introduced together with the monolithic circuit's fixed-shape padding.

### Step 5 — Monolithic state-transition circuit
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
  - Performance budget: cold-start proof ≤ 30 s, warm proof ≤ 5 s on M3 Ultra (R2 escalation trigger). Numbers ≤ these unblock the MVP; better numbers postpone GPU/Network considerations.
**Risk:** Medium. First real exposure to the full stack under realistic load.

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

### R2 — 1-second proof target unreachable on server hardware (medium)
**What can go wrong:** Real circuit with 1+8 recursive verifies is too large for sub-second proving even on M3 Ultra (or our eventual GPU host).
**Mitigation:** Measure as soon as step 5 has any working proof. Knobs to turn: (a) reduce `MAX_IN_COINS`, (b) drop recursion of in-coin proofs (replace with off-circuit nullifier-set check, requires protocol change), (c) switch to a folding scheme, (d) move proving to GPU or Succinct Prover Network.
**Trigger to escalate:** measured proof time > 5s on M3 Ultra. Wallet-side performance is N/A — proving is server-side; the wallet's send-flow latency = proof time + network roundtrip.

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
  Smaller field, GPU-friendlier, matches SP1's choice (which we are
  leaving). Plonky2 we use Goldilocks because that's Plonky2's mature
  default; Plonky3 switches us back to a small-field stack.
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
