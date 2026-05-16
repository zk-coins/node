# Plonky2 Migration Roadmap

Living tracker for the SP1 → Plonky2 + Poseidon migration on branch
`feat/plonky2-migration`. **Updated on every commit to this branch** — if
this file is stale relative to recent commits, that is a bug.

Source documents:

- [`SPEC.md`](./SPEC.md) — protocol specification (the *what*).
- [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md) — analysis of the upstream references + design decisions (the *why*).
- This file — execution plan, status, estimates (the *when and how*).

---

## Status at a Glance

| # | Step | Status | Effort | Risk |
| - | ---- | ------ | ------ | ---- |
| 1 | Reconcile `SPEC.md` with paper divergences | ✅ done | — | — |
| 2 | Scaffold `program-plonky2/` standalone crate | ✅ done | — | — |
| 3a | Port off-circuit Poseidon hash + byte conversion | ✅ done | — | — |
| 3b | Port off-circuit sparse Merkle tree to Poseidon | ✅ done | — | low (regression covered) |
| 3c | Port off-circuit MMR to Poseidon | ✅ done | — | — |
| 3d | Port off-circuit `AccountState`/`Coin`/`ProofData` | ✅ done | — | — |
| 4a | In-circuit MMR inclusion gadget | ✅ done | — | — |
| 4b | In-circuit SMT inclusion gadget | ⏳ todo | 0.5 d | low |
| 4c | In-circuit SMT non-inclusion + insert gadget | ⏳ todo | 1–2 d | **medium** (chase-loop complexity in-circuit) |
| 4d | Port `ProgramInputs` + `CommitmentMerkleProofs` types | ⏳ todo | 1 d | low |
| 5 | Monolithic state-transition circuit (recursion, padding, vk-pin) | ⏳ todo | **3–5 d** | **high** (vk-pin correctness, first real recursion test) |
| 6 | `script-plonky2/` host-side prover wrapper | ⏳ todo | 1–2 d | low |
| 7 | Server: rewire `account_server` + `state` + `scanner` to Poseidon | ⏳ todo | **3–5 d** | medium (Schnorr boundary, scanner SMT key) |
| 8 | App / wallet: wasm Poseidon implementation or bindings | ⏳ todo | **3–5 d** | medium (browser performance) |
| 9 | DEV deployment + end-to-end roundtrip on signet | ⏳ todo | 3–5 d | medium |
| — | Pre-mainnet blockers: D2/D10 (recipient hiding), D7 (reorg safety), D8 (per-coin nullifier-accum) | ⏳ todo | **+2–3 weeks** | high (real protocol redesign) |

**MVP total (steps 1–9): ~4–6 weeks full-time** assuming no major surprises in step 5 (Plonky2 recursion vk-pinning).

Pre-mainnet hardening adds another 2–3 weeks on top.

---

## Done

Commit refs (newest first):

- [`15d45c9`](./../../commit/15d45c9) — feat: MMR inclusion gadget (4 circuit tests, prove+verify pass)
- [`e1af850`](./../../commit/e1af850) — feat: AccountState/Coin/ProofData/calculate_coin_identifier (field-element layouts)
- [`c28e279`](./../../commit/c28e279) — feat: MMR to Poseidon (8 tests)
- [`6215009`](./../../commit/6215009) — feat: SMT to Poseidon + chase-loop zero-state collision fix (11 tests, incl. regression guard)
- [`984580f`](./../../commit/984580f) — feat: Poseidon hash module (5 tests)
- [`8fa6a92`](./../../commit/8fa6a92) — chore: toolchain pin + lock §5 decisions
- [`72c3b78`](./../../commit/72c3b78) — feat: scaffold `program-plonky2/` standalone crate
- [`049ec3e`](./../../commit/049ec3e) — docs: reconcile SPEC with paper, add §15 divergences
- [`57cdce4`](./../../commit/57cdce4) — docs: add migration research
- [`496c652`](./../../commit/496c652) — docs: add circuit specification

**Test count on this branch:** 37 (all green on nightly-2025-04-15).

---

## In Progress

*(none — every "done" line is committed and on the branch.)*

---

## Next (in order)

### Step 4b — SMT inclusion gadget
**Effort:** ~0.5 day.
**Files:** `program-plonky2/src/circuit/smt.rs` (new).
**Mirror of:** `merkle::sparse_merkle_tree::InclusionProof::verify`.
**Test plan:** off-circuit `SparseMerkleTree::generate_inclusion_proof` → witness in circuit → prove → verify. Tampered-leaf negative case.
**Risk:** Low. Same structure as `verify_mmr_inclusion`, but key bit selection is MSB-first (already established in `get_bit`).

### Step 4c — SMT non-inclusion + insert gadget
**Effort:** 1–2 days.
**Files:** `program-plonky2/src/circuit/smt.rs` (extends 4b).
**Mirror of:** `NonInclusionProof::verify` and `NonInclusionProof::insert`.
**Test plan:** generate non-inclusion proofs off-circuit, witness + prove + verify. Specifically include the iter=1 zero-state corner case from the SMT regression guard.
**Risk:** Medium. The "padding with default hashes" loop is data-dependent — needs in-circuit handling that doesn't branch on witness values. Likely solved by fixing `MAX_DEPTH` and conditionally selecting default vs. provided hash per level.

### Step 4d — Port `ProgramInputs` + `CommitmentMerkleProofs`
**Effort:** ~1 day.
**Files:** `program-plonky2/src/types.rs` (extend) + `program-plonky2/src/circuit/inputs.rs` (new for target counterparts).
**Mirror of:** `program/src/lib.rs::ProgramInputs` + `CommitmentMerkleProofs`.
**Test plan:** field-element round-trip tests, mirroring the existing `ProofData` round-trip test.
**Risk:** Low. Pure data types, no circuit logic.

### Step 5 — Monolithic state-transition circuit
**Effort:** 3–5 days.
**Files:** `program-plonky2/src/circuit/main.rs` (new) — the equivalent of `program/src/main.rs`.
**Scope:** assemble all gadgets into the full circuit; implement Initial vs. AccountUpdate branch via `conditionally_verify_cyclic_proof_or_dummy`; fix `MAX_IN_COINS = 8`; pin `vk` via `add_verifier_data_public_inputs`; commit `ProofData` as 16-element public output.
**Test plan:**
  - Single send (1 in-coin → 1 out-coin) — initial proof path.
  - Two sequential sends — update-proof recursion.
  - Negative cases from SPEC §13 (overflow, wrong vk, double-spend, wrong identifier).
**Risk:** **High.** First real test of Plonky2 cyclic recursion with our public-input shape. The BitVM reference's toy IVC pattern is the only existing example; correctness depends on identical `circuit_digest` between build passes (two-pass `common_data_for_recursion` trick).

### Step 6 — `script-plonky2/` prover host
**Effort:** 1–2 days.
**Files:** new crate `script-plonky2/`.
**Mirror of:** `script/src/lib.rs::Prover`.
**Risk:** Low. Plonky2 prover API is simpler than SP1's.

### Step 7 — Server rewire
**Effort:** 3–5 days.
**Files:** `server/src/account_server.rs`, `server/src/state.rs`, `server/src/scanner.rs`, `server/src/server.rs` — all need Poseidon-side variants behind a Cargo feature flag.
**Key challenge:** the Schnorr commitment message stays `SHA256(serialize(asth) ‖ serialize(ocr))` per §5.4 of `MIGRATION_RESEARCH.md`, so the scanner converts Poseidon outputs to bytes before SHA256 → BIP-340 verify.
**Risk:** Medium. Many touchpoints, but each one is mechanical.

### Step 8 — App / wallet wasm
**Effort:** 3–5 days.
**Files:** `zk-coins/app` repo (separate). Add Poseidon hashing to the wasm crypto module.
**Key challenge:** Browser performance. Pure-Rust Poseidon via wasm-bindgen is the obvious starting point; benchmark before committing.
**Risk:** Medium. If browser-side Poseidon is too slow we may need a wasm-optimised variant.

### Step 9 — DEV deployment + e2e
**Effort:** 3–5 days.
**Plan:**
  - Build `zkcoin/server-plonky2:beta`, deploy to `dfxdev`.
  - Wallet at `dev-app.zkcoins.app` points at it.
  - Roundtrip: create account → mint → send → recipient receives.
  - Measure: cold-start proof time, warm proof time, memory usage.
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

## Risk Register

### R1 — Plonky2 cyclic recursion correctness (high)
**What can go wrong:** Step 5 fails because `circuit_digest` isn't stable between the two `common_data_for_recursion` passes, or the public-input layout in `add_verifier_data_public_inputs` is misaligned.
**Mitigation:** Start step 5 with the simplest possible "I verify myself with a trivial payload" circuit before adding the real predicate. Validates the recursion plumbing in isolation.
**Trigger to escalate:** if 1 day of debugging step 5 doesn't produce a verifying proof, ask Robin / the Plonky2 community.

### R2 — 1-second proof target unreachable (medium)
**What can go wrong:** Real circuit with 1+8 recursive verifies is too large for sub-second proving on a laptop.
**Mitigation:** Measure as soon as step 5 has any working proof. Knobs to turn: (a) reduce `MAX_IN_COINS`, (b) drop recursion of in-coin proofs (replace with off-circuit nullifier-set check, requires protocol change), (c) switch to a folding scheme.
**Trigger to escalate:** measured proof time > 5s on M3 Ultra.

### R3 — Wasm Poseidon too slow (medium)
**What can go wrong:** Browser hashing for SMT path computation makes the wallet feel sluggish.
**Mitigation:** Profile early in step 8. Consider Poseidon2 (faster) or precompute SMT paths server-side.
**Trigger to escalate:** wallet send flow > 3s perceived.

### R4 — Pre-mainnet hardening pushes timeline (high)
**What can go wrong:** D2/D10 hiding recipient is a real protocol change, not a patch. May require re-doing step 5 if it doesn't fit the existing circuit shape.
**Mitigation:** Decide before mainnet whether to ship the MVP variant first (linkable recipients, documented) and harden later, or harden now. Currently planning the former (per §5.5 in MIGRATION_RESEARCH).
**Trigger to escalate:** if regulatory or PR feedback flags linkability before MVP launch.

### R5 — SP1 stays in the workspace forever (low)
**What can go wrong:** We don't fully cut over and end up maintaining both backends indefinitely.
**Mitigation:** Step 7 introduces a Cargo feature flag — but the goal is to delete the SP1 path once Plonky2 is in DEV. Schedule the deletion as a follow-up PR after step 9 succeeds.

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
