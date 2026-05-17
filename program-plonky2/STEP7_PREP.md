# Step 7 Prep — SP1 → Plonky2 Server Cutover Inventory

Read-only inventory of every place in the existing SP1-era server code
that must change for **Step 7** (replace SP1 with Plonky2; no Cargo
feature flag, no dual backend, no migration — see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md) § "Working on the Plonky2
Migration" / closed-test-env invariant).

Produced alongside the parallel Step 5 (monolithic circuit) work to
avoid editing files Step 5 is also touching. Pure reference; once Step
5 + Step 6 land, this file should be folded into the actual Step 7 PR
and deleted.

---

## Strict classification

| Tag | Meaning |
| --- | --- |
| 🔧 mechanical | Pure import swap or rename; no design decision. |
| 🧩 layout-dependent | Touches `ProofData` / proof-bytes layout — must align with whatever Step 5 commits as the canonical field-element serialisation. Can't be finalised until Step 5 lands. |
| 🛠 new work | Adds something that doesn't exist yet in `program-plonky2/`. Real engineering, not just a rename. |
| ⚙ decision | Requires a design call that isn't pre-determined by the ROADMAP. |

---

## File-by-file inventory

### 1. `server/src/account_server.rs`

| Where | Current | What it becomes | Tag |
| ----- | ------- | --------------- | --- |
| L9–16 | `use zkcoins_program::…;` (merkle types, `AccountState`, `Coin`, `CoinTemplate`, `CommitmentMerkleProofs`, `ProgramInputsBuilder`, `ProofData`, `ProofType`, `calculate_coin_identifier`) | `use zkcoins_program_plonky2::…;` (same items; `ProgramInputsBuilder` may not exist in the same form — Step 5 will introduce its target/witness equivalent) | 🔧 + ⚙ |
| L17 | `use zkcoins_prover::{Proof, Prover};` | `use zkcoins_prover_plonky2::{Proof, Prover};` (Step 6 creates this crate) | 🔧 |
| L132 | `coin_proof.proof.public_values.clone().read::<ProofData>()` (SP1 stdin replay) | `coin_proof.proof.public_inputs_as_proof_data()` or direct field-element deserialise (Step 5 fixes the format) | 🧩 |
| L201 | `previous_proof.public_values.read::<ProofData>()` | Same as L132 | 🧩 |
| L379–380 | `bincode::deserialize::<ProofData>(&proof.public_values.to_vec())` | Same as L132 (no `to_vec` round trip needed if `ProofData` is already a field-element struct) | 🧩 |

### 2. `server/src/server.rs`

| Where | Current | What it becomes | Tag |
| ----- | ------- | --------------- | --- |
| L20 | `use zkcoins_prover::Proof;` | `use zkcoins_prover_plonky2::Proof;` | 🔧 |
| L15 | `use shared::{Invoice, ProofData};` | unchanged — `ProofData` stays in `shared`, but its underlying definition (re-exported from `zkcoins_program_plonky2`) changes | 🧩 (downstream of `shared/`) |
| L172, L190, L341 | `bincode::serialize/deserialize` of `CoinProof` (which contains `Proof`) | mostly unchanged — `CoinProof` is opaque-bytes serialised; only fails if the new `Proof` type isn't `serde::Serialize` | 🧩 |
| L431–432 | `bincode::deserialize::<ProofData>(&coin_proofs[0].proof.public_values.to_vec())` | aligns with L132 of `account_server.rs` — once Step 5 ships the canonical `ProofData::from_proof(&Proof)`, this becomes a one-liner | 🧩 |
| L44–49 | SHA256 over Schnorr message | unchanged — that's BIP-340, stays | — |

### 3. `server/src/state.rs`

| Where | Current | What it becomes | Tag |
| ----- | ------- | --------------- | --- |
| L8–10 | `use zkcoins_program::merkle::merkle_mountain_range::{MMRProof, MerkleMountainRange};` + `…::sparse_merkle_tree::{load_merkle_tree, save_merkle_tree, InclusionProof, SparseMerkleTree};` | `use zkcoins_program_plonky2::merkle::…;` — **but `load_merkle_tree`/`save_merkle_tree` do not exist yet in `program-plonky2`** | 🔧 + 🛠 |
| L12 | `use zkcoins_program::merkle::{HashDigest, ZERO_HASH};` | `use zkcoins_program_plonky2::hash::{HashDigest, ZERO_HASH};` | 🔧 |
| L66–71 | SHA256 hashing of `(smt_root \|\| prev_mmr_root)` for the MMR leaf | **Decision pending**: switch to `hash_concat` (Poseidon) for consistency with the rest of the in-circuit world, OR keep SHA256 for cross-chain readability. The MMR leaves are not in-circuit yet, but they will be once Step 5's monolithic circuit reads `commitment_history_root` from a witness chain. Aligning the off-circuit MMR leaf hash with the in-circuit one means this MUST be Poseidon. | ⚙ → 🔧 once decided |

### 4. `server/src/scanner.rs`

No SP1 references. **Zero changes** unless Step 5 changes the on-chain commitment format (it doesn't per the architectural invariant — Taproot inscription `4242` prefix stays).

### 5. `server/src/main.rs`

| Where | Current | What it becomes | Tag |
| ----- | ------- | --------------- | --- |
| L22–26 | State-file path constants | unchanged | — |
| L90–91 | `State::load_from_files(SMT_PATH, MMR_PATH)` | unchanged signature; depends on persistence helpers existing in `program-plonky2` (see file 3) | 🛠 downstream |
| L200 | `state.save_to_files(SMT_PATH, MMR_PATH)` | same | 🛠 downstream |

### 6. `server/src/publisher.rs`

No SP1 references. **Zero changes.** Taproot inscription publishing is hash-agnostic.

### 7. `server/Cargo.toml`

| Where | Current | What it becomes | Tag |
| ----- | ------- | --------------- | --- |
| L17–18 | `zkcoins-prover = { path = "../script/" }` and `zkcoins-program = { path = "../program/" }` | `zkcoins-prover = { path = "../script-plonky2/" }` and `zkcoins-program = { path = "../program-plonky2/" }` (renames optional — could keep the dep names and just repoint paths) | 🔧 |

### 8. `shared/src/lib.rs` and `shared/src/commitment.rs`

| Where | Current | What it becomes | Tag |
| ----- | ------- | --------------- | --- |
| `lib.rs` L13–14 | `use zkcoins_program::…;` | `use zkcoins_program_plonky2::…;` | 🔧 |
| `lib.rs` L19 | `pub use zkcoins_program::ProofData;` | `pub use zkcoins_program_plonky2::ProofData;` | 🔧 |
| `commitment.rs` L7 | `use zkcoins_program::merkle::HashDigest;` | `use zkcoins_program_plonky2::hash::HashDigest;` | 🔧 |
| `commitment.rs` SHA256 usage | BIP-340 Schnorr message | unchanged | — |

### 9. `script/src/lib.rs`

| Where | Current | What it becomes | Tag |
| ----- | ------- | --------------- | --- |
| Entire file | SP1 prover wrapper (`EnvProver`, `SP1Stdin`, `SP1ProvingKey`, …) | **DELETE the file's contents** once Step 6 ships `script-plonky2`. Two options: (a) delete the `script/` crate from workspace entirely, (b) replace its contents with a re-export of `zkcoins_prover_plonky2` for one PR's worth of churn-protection. Recommendation: (a). | ⚙ |

### 10. Root `Cargo.toml`

| Where | Current | What it becomes | Tag |
| ----- | ------- | --------------- | --- |
| L2–6 | `members = ["program", "script", "server", "shared"]` | `members = ["program-plonky2", "script-plonky2", "server", "shared"]` if going all-in. Alternative: keep `program` for the off-circuit types we still rely on (but they're already ported to `program-plonky2`, so this is dead). Recommendation: rename in one step. | 🔧 + ⚙ |
| L7–11 | `exclude = ["program-plonky2"]` (the nightly-toolchain workaround) | **remove the exclude** — `program-plonky2` becomes a workspace member. **But this means the whole workspace needs to support its nightly toolchain.** Two options: (i) move everything to nightly (probably safe since SP1 is being deleted), (ii) keep `program-plonky2` separate and have `server` depend on it via path-with-exclude trick. Recommendation: (i) — the SP1 reason for stable-1.81 is gone after this step. | ⚙ |
| L23 | `sp1-sdk = "4.0.0"` workspace dep | **delete** | 🔧 |
| L32–50 | 18× `[patch.crates-io]` SP1 patches | **delete** | 🔧 |

### 11. Root `rust-toolchain`

| Where | Current | What it becomes | Tag |
| ----- | ------- | --------------- | --- |
| L2 | `channel = "1.81.0"` | Two options: (i) `channel = "nightly-2025-04-15"` to match `program-plonky2/rust-toolchain.toml` and unify the workspace, (ii) keep stable for `server`/`shared` if they don't need nightly features. Recommendation: (i) once SP1 is gone, the stable-pin justification is gone too. | ⚙ |

### 12. Test infrastructure

| Where | Current | What it becomes | Tag |
| ----- | ------- | --------------- | --- |
| `.github/workflows/ci.yaml` | invokes `SP1_PROVER=mock cargo test`, `cargo llvm-cov --fail-under-lines …` | rewrite to drop `SP1_PROVER`, point at the new crates, keep the 100%-coverage gate (now applies to a different test surface) | 🔧 |
| `README.md` | extensive SP1 docs (proving strategy, `SP1_PROVER` table, etc.) | rewrite per Step 9; Step 7 itself can leave it for that step | — |
| Test fixtures that hard-code `SP1_PROVER=mock` | (multiple) | drop the env-var dependency entirely | 🔧 |

### 13. State-file cutover checklist

On cutover (after Step 7's image is built and ready to deploy):

```bash
# On dfxdev and dfxprd:
sudo systemctl stop zkcoin-server
rm /var/lib/zkcoin/smt.bin /var/lib/zkcoin/mmr.bin /var/lib/zkcoin/mmr.bin.prev_root /var/lib/zkcoin/latest_block.bin
# accounts.bin — Cyrill's call: delete to force fresh accounts, or keep with the caveat that all stored proofs are now invalid
# usernames.bin, minting_num_pubkeys.bin — fine to keep, no crypto dependency
# proofs/*.bin — delete; old proofs are SP1 format, useless to the new server
sudo systemctl start zkcoin-server
```

The state-file cleanup is part of the deploy runbook, not Step 7's
code changes.

---

## Aggregate estimate

| Category | Files affected | Effort |
| -------- | -------------- | ------ |
| 🔧 Mechanical renames / import swaps | account_server.rs, server.rs, state.rs (partial), shared/{lib.rs, commitment.rs}, server/Cargo.toml, root Cargo.toml | ~45 min |
| 🧩 Layout-dependent (waits for Step 5's `ProofData::from_proof`) | account_server.rs (3 sites), server.rs (1 site) | ~30 min once Step 5 is final |
| 🛠 New work (must build, not just rename) | persistence helpers (`save_to_file` / `load_from_file`) for the new SMT and MMR — serde-derive support for `HashOut<F>` may need a feature flag on plonky2 | ~3–4 hours |
| ⚙ Open decisions | (i) MMR-leaf hash SHA256 vs Poseidon (file 3 L66–71); (ii) script/ crate fate; (iii) workspace toolchain unification | ~2 hours of discussion + execution |
| State file cleanup | runbook only, not code | trivial |

**Realistic Step 7 estimate: 1–1.5 days full-time** (vs. the ROADMAP's 2–3 days). The 🛠 persistence-helper work is the only real engineering; the rest is renames and three deserialisation rewrites.

The estimate moves to the lower end if Step 5 ships `ProofData::from_proof(&Proof)` as a public helper (eliminating the 🧩 work).

---

## Dependencies on Step 5

The following Step 7 items become fully concrete only after Step 5 lands:

1. **`ProofData` deserialisation API**: Step 5's monolithic circuit
   defines the canonical public-input layout. Step 7 picks up
   whatever shape that becomes; until then, the deserialisation
   sites in `account_server.rs` (L132, L201, L379) and `server.rs`
   (L431) are unknown shape.
2. **`ProgramInputsBuilder` equivalent**: SP1's builder for circuit
   inputs has a Plonky2 analogue that Step 5 will introduce as a
   target-set + a host-side witness setter. Step 7's `send_coins`
   path uses this.
3. **Persistence helpers**: Step 7 should not block on these — they
   can be implemented as part of Step 7 itself.

---

## Open design decisions for Step 7

1. **MMR leaf hash off-circuit:** SHA256 (current) vs Poseidon. Argument for Poseidon: consistency with in-circuit, no boundary inside the MMR. Argument for SHA256: smaller dependency surface, matches the existing scanner. **Recommendation:** Poseidon — the architectural invariant is "Poseidon everywhere in Merkle structures".

2. **`script/` crate fate:** keep as compat shim or delete? **Recommendation:** delete entirely. No external callers; the closed-test-env invariant says replace, not preserve.

3. **Workspace toolchain unification:** keep `rust-toolchain` stable for the `server`/`shared` crates, or move everything to nightly to match `program-plonky2`? **Recommendation:** move everything to nightly (SP1's stable-pin reason is gone after this step), but verify nothing in `server`/`shared` breaks on nightly first.

These three decisions are not blockers for starting Step 7 work — they
just need to be settled before the PR is opened for review.
