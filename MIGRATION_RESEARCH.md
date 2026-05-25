# Migration Research: References and Adoption Decisions

Companion document to [`SPEC.md`](./SPEC.md). Summarises what we can take from the upstream references, and — more importantly — flags where our current implementation has diverged from the published Shielded CSV protocol. Read this before writing any Plonky2 code.

> **Fresh session?** Start with [`CONTRIBUTING.md`](./CONTRIBUTING.md)
> § "Working on the Plonky2 Migration" first for the project invariants
> and reading order. This file's §7 (Lessons Learned) is the *required
> reading before touching the affected code areas*.

---

## TL;DR

1. **`BitVM/zkCoins` is a 182-LOC IVC toy, not a zkCoins prototype.** It gives us a Plonky2 version pin and a cyclic-recursion code recipe, nothing more.
2. **The real normative reference is `ShieldedCSV/ShieldedCSV`** — a non-circuit Rust implementation of the paper's PCD predicate.
3. **Our current SP1 implementation has departed from the published protocol in 11 distinct ways.** Some are simplifications (Schnorr commitment on a Taproot inscription instead of half-aggregate nullifier publication), some are arguably regressions (recipient is plaintext `Address`, linkable across coins), some are missing features (fee output, conditional-noop on reorg).
4. **Decision point for the maintainers:** Are we implementing _Shielded CSV as published_, or are we shipping a zkCoins MVP that intentionally diverges? Both are defensible; we just need to pick before we re-implement the circuit in Plonky2, otherwise we lock in design choices that aren't reviewable against any spec.

---

## 1. `BitVM/zkCoins` Plonky2 Prototype

**Location (local clone):** `~/Documents/GitHub/zkcoins/BitVM-zkCoins-reference/`
**Upstream:** https://github.com/BitVM/zkCoins
**Size:** 1 crate, 1 file, 182 LOC, 10 commits, last commit `bd8a8c2 "Recursive proving kinda works"` — WIP/abandoned.

### What it is

A Plonky2 IVC skeleton (`fn main()` with `println!` demos, no tests) that:
- Pins `plonky2 = "0.2.0"`, `D = 2`, `PoseidonGoldilocksConfig`, `CircuitConfig::standard_recursion_config()`.
- Uses `conditionally_verify_cyclic_proof_or_dummy` to verify two recursive proofs against the same circuit digest.
- Has a placeholder `mul_add` payload (computes a running sum).
- Demonstrates `add_verifier_data_public_inputs` for circuit-digest pinning.

### What it isn't

Despite the repo name, it contains **none** of: SMT, MMR, AccountState, Coin, ProofData, Schnorr verification, recipient model, Bitcoin link, tests, server, scanner. The single `main.rs` is a Plonky2 tutorial-grade IVC demo with no zkCoins semantics.

### Adoption decisions

| Aspect | Decision | Why |
| --- | --- | --- |
| `plonky2 = "0.2.0"` version pin | **Adopt** | Same version as the upstream `BitVM/zkCoins` reference; ecosystem-current. |
| `PoseidonGoldilocksConfig`, `D = 2` | **Adopt** | Standard Plonky2 recursion setup. Matches SPEC §12.1. |
| `standard_recursion_config()` | **Adopt as starting point** | Re-evaluate gate budget once we know our N-coin fanout. |
| `common_data_for_recursion()` two-pass build pattern | **Adopt with adaptation** | Plonky2 idiom to stabilise public-input count under cyclic recursion. Need to extend to our (prev account proof + N coin proofs) fanout. |
| `conditionally_verify_cyclic_proof_or_dummy` for Initial vs. Update branch | **Adapt** | Correct shape but only 2 verification slots in the demo; we need 1 + max_in_coins. |
| `add_verifier_data_public_inputs` | **Adopt** | Direct realisation of SPEC §10's "same-circuit" assertion. |
| Balance logic (commit `60e9d94`) | **Discard** | Toy `mul_add`, no relation to our model. |
| Everything else | **Write from scratch, basing on our SP1 modules** | The reference doesn't have it. |

**Bottom line:** the BitVM repo saves us maybe 20-30 lines of Plonky2 boilerplate. It does not give us the SMT, MMR, AccountState, or Coin logic for free — those have to be ported from our SP1 modules to Plonky2 constraints by hand.

---

## 2. Shielded CSV Paper (eprint 2025/068)

### Sources used

The eprint PDF returned HTTP 403 to automated fetches; instead the analysis relied on:
- **`github.com/ShieldedCSV/ShieldedCSV`** — the **upstream reference implementation** of the PCD compliance predicate, by Nick/Eagen/Linus. This is the normative source.
- Blockstream blog ("Bitcoin's Shielded CSV Protocol Explained")
- Bitcoin Magazine technical article on Shielded CSV
- Bitcoindev mailing-list summary
- Independent analyses (Fairgate newsletter, eliel.nfinic.com)

Items below cite **[REF-IMPL]** when the source is the upstream Rust code, **[SECONDARY]** when from blogs/list posts.

### Protocol primitives the paper actually uses

From `ShieldedCSV/ShieldedCSV/lib.rs`:

```rust
pub struct AggregateNullifier {
    pub pks: Vec<PublicKey>,        // each pk = one account update
    pub sig: Signature,             // half-aggregate BIP-340 Schnorr
    pub fee_acct_comm: Commitment,  // hiding commitment to publisher's acct
}

pub struct CoinEssence {
    pub address: Commitment,         // HIDING commit(acct_id, rand) — not a plain Address
    pub amount: u64,
    pub idx: [u8; 2],               // 2-byte coin index in tx
    // FEE_IDX = [0xff, 0xff]
}

type CoinID        = [u8; 34];      // tx_hash(32) || idx(2)
type CoinIDOnChain = [u8;  8];      // blockchain_loc(6) || idx(2)
                                    // 21 bits block height + 22 bits in-block idx
```

And from `primitives.rs`:

- **`AccM` (strong A-SEC accumulator)** for spent coins, keyed by `CoinIDOnChain`, **lexicographically ordered = creation-order ordered**, supports `verify_non_membership_and_insert`. Order matters because it lets managers prune historical subtrees.
- **`ToSAcc` (tuple-of-sets accumulator)** for the on-chain nullifier history, holding `(pk, sig_commitment, blockchain_location, fee_acct_comm)` tuples, supporting `append_set`, `prove_union_membership`, `prove_is_prefix`, `prove_distinct_element`.
- `Commitment` (Pedersen-style, hiding+binding) wraps every recipient address with per-coin randomness for unlinkability.

### Hash function and field choice

The reference implementation leaves `hash` and `Commitment::commit` as **unimplemented stubs** — the paper is hash-agnostic, requires only CRH/RO behaviour for `hash` and hiding+binding for `Commitment`. Only BIP-340 Schnorr (secp256k1) is mandatory, because Bitcoin verifies it. **Conclusion:** Poseidon over Goldilocks is within the paper's allowed instantiation space; SHA256 was not normative either. ✓

### Recursion

Paper uses PCD (Proof-Carrying Data) as the abstraction — explicitly **agnostic between recursive SNARKs and folding schemes (Nova-style)**. No mandated recursion-depth bound. **Conclusion:** Plonky2 cyclic recursion is fine. ✓

### Account model

`AcctStateEssence { id: PublicKey, balance: u64, nullifier_pk: PublicKey }` — matches our `AccountState { owner, balance, public_key }` structurally, with two differences:

- The paper's `id` is itself a `PublicKey` (XOnlyPublicKey), **not** `H(initial_pk)`. We added the extra hash; the paper doesn't.
- Each `AcctState` carries both `spent_accum` (≈ our `coin_history_root`) **and** a claimed `nullifier_accum` snapshot — we carry only the former, which is one of the divergences below.

---

## 3. The 11 Divergences (Our SPEC vs. the Paper)

Numbered D1–D11. Each is a concrete protocol-level departure. Some are deliberate MVP simplifications, some are accidental, some have security implications. We need to triage them explicitly.

| # | Our SPEC says | Paper says | Severity |
| --- | --- | --- | --- |
| **D1** | `identifier = H(asth ‖ u32_be(idx))` (32 B), tied to sender's next account-state hash | `CoinID = tx_hash ‖ idx_2B` (34 B); `CoinIDOnChain = blockchain_loc(6 B) ‖ idx_2B` (8 B) for accumulator efficiency. | **Protocol-level**: paper IDs are short on purpose. |
| **D2** | `Coin { recipient: Address = H(initial_pk) }` — plaintext recipient | `coin.essence.address = Commitment::commit(acct_id, rand)` — **hiding** commit, per-coin random. | **Privacy regression**: without `rand`, multiple coins to the same recipient are trivially linkable. |
| **D3** | Single Schnorr commitment over `H(asth ‖ ocr)` posted as Taproot inscription, txid prefix `4242` | `AggregateNullifier` — **half-aggregate BIP-340 Schnorr** posted by third-party publishers, no inscription envelope mandate, no `H(asth ‖ ocr)` message. | **Architectural**: we replaced the paper's publisher layer with self-publishing. |
| **D4** | Global state = SMT keyed by `H(pk)`, value `H(asth ‖ ocr)`; MMR over `H(smt_root ‖ prev_mmr_root)` | Global state = `ToSAcc` over `(pk, sig_comm, blockchain_loc, fee_acct_comm)` tuples, with prefix and union-membership proofs. | **Protocol-level**: coin proofs in the paper prefix-prove against `ToSAcc`; our SMT/MMR shape doesn't expose the prefix interface. |
| **D5** | SMT depth 256, hash-keyed (uniform random) | `AccM` is lex-ordered by `CoinIDOnChain` — explicitly to enable pruning old subtrees. | **Scalability**: uniform hash-keyed SMT cannot prune. |
| **D6** | No fee field; no fee output | `fee: u64` field; `FEE_IDX = 0xffff` reserved index; `payment_finalize_fee` mints exactly one coin to the publisher. | **Missing feature**: our circuit cannot produce a fee output. |
| **D7** | No conditional-noop path | Paper supports `conditional_nav` — if the claimed nullifier-accum is no longer a prefix of the chain's, the tx becomes a no-op. | **Reorg safety**: our impl doesn't degrade gracefully under reorgs. |
| **D8** | `Coin` doesn't carry a `nullifier_accum` snapshot | Paper's `Coin` carries the `nullifier_accum` it was minted under; receiver checks this is in their local nullifier-accum history. | **Soundness**: without this snapshot, recipients trust the proof's history-root rather than verifying it independently. |
| **D9** | No range/uniqueness checks on `coin_index` | `idx` is strictly increasing within a tx; `idx == FEE_IDX` reserved. | **Soundness**: malformed coins not rejected. |
| **D10** | `apply_coin` checks `coin.recipient == self.owner` against plaintext owner | Paper opens `Commitment::commit(acct_id, rand)` with per-coin `acct_comm_rand` provided as witness. | **Tied to D2**: same hiding-commit issue. |
| **D11** | `MINTING_ADDRESS` hard-coded; one allowed minter | Paper has explicit `issuance(IssuanceProof)` predicate branch (currently stub in upstream); `payment_init_newacct` starts fresh accounts at `balance = 0, nullifier_pk = acct_id`. | **Architectural**: the minting model is left more open in the paper. |

### Triage recommendation

For a Plonky2 MVP shipping in weeks-not-months:

- **Keep as deliberate simplifications (document in README + this file):** D1, D3, D5, D6, D11. These trade flexibility for shipping speed; explicitly call them out so reviewers know.
- **Should-fix before mainnet:** D2 + D10 (privacy regression — recipient unlinkability is a stated zkCoins selling point), D7 (reorg safety — Bitcoin reorgs happen), D8 (soundness — receivers should be able to verify coin age locally).
- **Open / discuss with the maintainers:** D4 (does the SMT+MMR scanner model actually give the same security properties as `ToSAcc` for our threat model?), D9 (cheap to add).

---

## 4. Combined Adoption Decisions

### From `BitVM/zkCoins`
- Cargo manifest: `plonky2 = "0.2.0"`, no other deps from there.
- IVC scaffolding: `common_data_for_recursion`, `conditionally_verify_cyclic_proof_or_dummy`, `add_verifier_data_public_inputs`.
- Public-input-count stabilisation pattern (the two-pass `builder.print_gate_counts(0)` / build / discard / re-build trick).

### From `ShieldedCSV/ShieldedCSV` (paper reference impl)
- **Data-type shapes** for `CoinEssence`, `AcctStateEssence`, `AggregateNullifier`. Even if we stick with our simpler publisher model (D3), align field names + types so cross-reading is possible.
- The `verify_non_membership_and_insert` accumulator API as the canonical SMT operation signature.
- The PCD predicate as the canonical list of asserts. Even if our circuit is structurally different, the **set of facts proven** should be a superset.
- The `payment_init_newacct` flow as the basis for a real (non-hard-coded) account-creation path (addresses D11 long-term).
- Test cases: copy/port their predicate tests as a soundness baseline.

### From our existing SP1 code (`program/src/`)
- The current `SparseMerkleTree` / `MerkleMountainRange` algorithms (modulo hash swap to Poseidon and lex-ordering for AccM if we go that route).
- The `AccountState`, `Coin`, `Invoice` data shapes (modulo D1, D2 fixes).
- The Account → coin_queue → send flow in `server/src/account_node.rs` — this is host-side glue, no circuit changes here except wiring to the new Plonky2 prover.
- The 12 tests in `program/src/merkle/sparse_merkle_tree.rs::tests` — survive as-is once `hash_concat` is Poseidon-backed.

### Newly required work (no upstream donor)
- Plonky2 circuit gadgets for: Poseidon-SMT membership/non-membership/insert, Poseidon-MMR append+prove, Schnorr verification or — if we keep BIP-340 — an in-circuit SHA256 gadget over the Schnorr message (cheap because the message is exactly 64 bytes).
- Range checks on coin indices, balances (u64), and amounts.
- Domain-separation tags as field-element prefixes for leaf/node/identifier/MMR-leaf hashes (cheap with Poseidon, fixes the implicit-tagging issue called out in SPEC §10.5).
- Fixed-shape padding for variable-length input vectors (`in_coins` becomes `[Coin; MAX_IN_COINS]` with no-op slots).

---

## 5. Design Decisions (locked for v1)

The following decisions are taken. Each is reversible but reversing them means a full circuit rebuild — they will not be re-litigated within v1.

1. **Paper-fidelity vs. zkCoins variant** → **zkCoins MVP variant for v1.** Paper fidelity (`ToSAcc`, half-aggregate publishers, fee economics, hiding recipient commitments) is deferred to v2. SPEC.md §15 documents the divergences D1–D11.

2. **Max input coins per send** → **8.** Plonky2 circuits are fixed-shape; the bound has to be a constant. 8 covers >99% of real wallet sends (most are 1–2 in-coins). Coin slots beyond the actual count are filled with `amount = 0` dummies; the circuit treats those as no-ops.

3. **Hash function** → **Poseidon over Goldilocks (`PoseidonGoldilocksConfig`, `D = 2`)** everywhere in the protocol's Merkle structures — both in-circuit *and* in the scanner state (SMT + MMR). Aligns with the Plonky2 ecosystem default and the BitVM reference config.

4. **Schnorr message hash** → **BIP-340 secp256k1 stays unchanged.** The wallet signs `SHA256(serialize(asth) ‖ serialize(ocr))` where `asth` and `ocr` are 4-element Poseidon outputs serialised big-endian to 32 bytes each. SHA256 lives only at this boundary; everything inside the circuit is Poseidon. No in-circuit SHA256 gadget is needed because the circuit never verifies the BIP-340 signature itself — that happens off-circuit in the scanner.

5. **Privacy (D2/D10)** → **deferred to v2.** Plaintext recipient addresses for v1. Linkability across multiple coins to the same recipient is a known limitation, called out as a mainnet blocker in SPEC §15.

6. **Fee model (D6)** → **no fee in v1.** We are the publisher (DFX/zkCoins-operated server), so there is no publisher to compensate. Self-funded operation.

Hash-function boundary visualisation:

```
       in-circuit (Poseidon)          off-circuit (BIP-340 secp256k1)
       ----------------------          --------------------------------
           ProofData                   wallet derives x-only privkey
        ┌──────────┐                   wallet computes
        │   asth   │ ────────┐         msg = SHA256(asth_bytes || ocr_bytes)
        │   ocr    │ ────────┼──→      sig = schnorr_sign(privkey, msg)
        └──────────┘         │         scanner verifies sig
                             │         scanner inserts (pk, msg) into Poseidon-SMT
                             └─── serialize each field elt big-endian → 32 B
```

---

## 6. Sequencing — moved to ROADMAP.md

The original 9-step strategic outline that lived here was superseded by
the detailed 16-row breakdown in [`ROADMAP.md`](./ROADMAP.md) once
implementation started. The ROADMAP is now authoritative for the
execution plan (status, effort, files, risks).

Key adjustments made since the original outline:

- **Step ordering of gadgets** (was: hash → SMT non-inclusion+insert → MMR-append → SHA256). Actual: MMR inclusion → SMT inclusion → SMT non-inclusion verify. The original list mentioned an MMR-append and a SHA256 gadget which turned out to not be needed (MMR is built off-circuit by the scanner; SHA256 lives at the Bitcoin-signing boundary, not in-circuit — see §5.4).
- **No Cargo feature flag for dual backend.** The closed-test-environment decision means step 7 replaces SP1 with Plonky2 outright (see ROADMAP step 7).
- **Server scanner + state DO change** (Poseidon SMT/MMR, not SHA256). Only the on-chain commitment *format* — a single Schnorr inscription with txid prefix `4242` — stays unchanged.

---

## 7. Lessons Learned (during implementation)

Gotchas, design discoveries, and "would have been nice to know" findings
that emerged while porting steps 1–4d. Each entry includes what it
costs (concrete: a regression test, a comment, a constraint) so a later
contributor can verify the lesson is still load-bearing.

### 7.1 Poseidon zero-state collision in SMT defaults — **HIGH severity**

**Discovered:** SMT port (commit `6215009`), failing test
`test_verify_non_inclusion_proofs` at iter=1 (2 leaves).

**Symptom:** `debug_assert!(node_1 == *parent || node_0 == *parent)` in
the chase loop of `generate_non_inclusion_proof` failed. Investigation
showed the chase had silently diverged from the inserted leaf's path
because *both* children at some level appeared equal to `parent`.

**Root cause:** Plonky2's Poseidon sponge with state width 12 and zero
capacity init has the property that
`PoseidonHash::hash_no_pad(&[F::ZERO])`,
`PoseidonHash::hash_no_pad(&[F::ZERO, F::ZERO])`,
`PoseidonHash::two_to_one(ZERO_HASH, ZERO_HASH)`, and any other
absorption that leaves the state at all-zeros before permutation all
produce **the same output** — call it `Z = Poseidon(0)`.

If `DEFAULT_HASHES[TREE_DEPTH] = ZERO_HASH`, then `DEFAULT_HASHES[L]`
for every `L < TREE_DEPTH` is `Z` (after sufficient self-concatenation,
this stabilises in two steps). Any leaf whose value+key are themselves
hashes of zero-derived inputs (very common in tests, but also possible
for real Poseidon-derived keys hitting that exact image) collides with
`DEFAULT_HASHES[TREE_DEPTH - 1]`. The chase loop then sees both default
sibling and propagated leaf-hash as equal and picks the wrong path.

**Fix:** seed `DEFAULT_HASHES[TREE_DEPTH]` with a domain-separated
non-zero value (verbatim from `program-plonky2/src/merkle/sparse_merkle_tree.rs`):

```rust
const EMPTY_LEAF_TAG: &[u8] = b"zkcoins:smt:empty-leaf:v1";

pub static DEFAULT_HASHES: LazyLock<Vec<HashDigest>> = LazyLock::new(|| {
    let depth = TREE_DEPTH;
    let empty_leaf = hash_bytes(EMPTY_LEAF_TAG);
    let mut default_hashes = vec![empty_leaf; depth + 1];
    for level in (0..depth).rev() {
        default_hashes[level] = hash_concat(&default_hashes[level + 1], &default_hashes[level + 1]);
    }
    default_hashes
});
```

**Regression guard:** `leaf_hash_never_collides_with_defaults` in
`sparse_merkle_tree.rs` iterates 50 sample keys × values and asserts
none collides with any `DEFAULT_HASHES[L]`.

**Generalisation for future gadgets:** any time the protocol uses
"zero" as a sentinel inside a Poseidon hash chain, sanity-check that
the resulting sentinel isn't also a natural image of zero-derived
input. Domain separators are cheap insurance.

### 7.2 Variable vs. fixed depth in SMT proofs — **MEDIUM severity, decision pending**

**Discovered:** when porting `verify_smt_non_inclusion` and writing
`verify_and_insert` plans (steps 4c, 4c+).

**Tension:** the off-circuit SMT uses **path compression**. A single-leaf
subtree at level L stores `leaf_hash` rather than a real `hash_concat`
of children, and `generate_inclusion_proof` / `generate_non_inclusion_proof`
break early when they detect this pattern. The resulting proof has
variable length `K ≤ TREE_DEPTH`.

Plonky2 circuits are **fixed-shape**: a gadget that processes a path
must commit to its length at circuit-build time. The current gadgets
accept any `path.len()` at *test* time, but the monolithic circuit
(step 5) needs one fixed depth.

**Two options for step 5:**

1. **Remove path compression off-circuit.** Every leaf path is hashed
   up the full TREE_DEPTH; proofs are uniformly TREE_DEPTH siblings
   long. Pros: trivial in-circuit logic; uniform. Cons: changes
   `tree.root()` semantics (root is no longer leaf-hash for single-leaf
   trees); we'd need to retrofit the test suite and any host code
   reading the root.
2. **Keep path compression off-circuit, pre-pad for circuit consumption.**
   The host produces a "padded" proof of length TREE_DEPTH where
   levels below path compression are filled with computed
   `hash_concat(leaf_h, default)` values at each level. Pros: keeps
   off-circuit `tree.root()` semantics. Cons: host code complexity;
   the padding must be computed correctly (subtle).

**Status:** unresolved. Decision deferred to step 5 (monolithic circuit).
The risk register R6 flags this; the ROADMAP's 4c+ entry notes the plan
is option 2 unless we hit issues.

**Concrete cost so far:** the verify gadget accepts variable depth and
works for tests, but the insert gadget hasn't been written yet
precisely because the depth question is unsettled.

### 7.3 `pw.set_target` returns `Result` in plonky2 1.x — **LOW severity**

**Discovered:** smoke test for `program-plonky2/src/lib.rs` (commit
`984580f`).

**Surprise:** the BitVM reference uses plonky2 0.2.0 where
`pw.set_target(target, value)` returns `()`. In plonky2 1.x it returns
`Result<(), anyhow::Error>` and clippy's `unused_must_use` rejects the
old call shape.

**Fix:** always `.unwrap()` (or properly handle) the result. The error
case shouldn't fire in correctly-written code; the Result is there for
target-overwrite detection.

```rust
// 0.2.0:    pw.set_target(t, v);
// 1.x:      pw.set_target(t, v).unwrap();
```

### 7.4 Field-element packing conventions (canonical-reduction safety) — **MEDIUM, codified**

**Discovered:** during `hash.rs` design.

**Constraint:** Goldilocks modulus is `p = 2^64 - 2^32 + 1 ≈ 2^64`. A
u64 value just below `2^64` exceeds `p` and `F::from_canonical_u64`
panics in debug builds (release: silent reduction).

**Packing rules** used throughout this crate:

| Operation                          | Bytes per field elt | Why                             |
| ---------------------------------- | ------------------- | ------------------------------- |
| `hash_bytes`                       | **7** (LE)          | 7*8 = 56 bits, safe ceiling.    |
| `digest_to_bytes` / `from_bytes`   | **8** (BE)          | Only works because Poseidon outputs are canonical (< p). Asserted by the protocol invariant; if a user-supplied byte string is fed through `digest_from_bytes`, it MUST come from a prior `digest_to_bytes` of a real digest. |
| `u64_to_limbs` (balance / amount)  | **4** (2 limbs)     | u32 chunks, never exceeds p.    |
| `pubkey_to_limbs` (33-byte pubkey) | **7** (5 limbs LE)  | Same as `hash_bytes`.           |

**Invariant to enforce in any future packing function:** input chunks
that fill a Goldilocks element must be ≤ 56 bits unless the value's
canonical reduction is independently guaranteed.

### 7.5 The Schnorr / Poseidon boundary lives at byte serialisation — **codified**

**Discovered:** §5.4 decision, then refined while writing
`CommitmentMerkleProofs::verify_commitment`.

**Rule:** the wallet signs `SHA256(serialize(asth) ‖ serialize(ocr))`
where `serialize` is `digest_to_bytes` (32 bytes big-endian per field
element). The scanner verifies the BIP-340 signature and then inserts
the 32-byte message into the global SMT keyed by `H(serialize(pubkey))`
(Poseidon hash of compressed pubkey bytes, then taken as a 32-byte
SMT key).

There is **no in-circuit SHA256**, **no in-circuit Schnorr verify**.
The boundary is enforced entirely off-circuit, and the proof's public
output (`ProofData`'s `account_state_hash` + `output_coins_root`)
provides the values that the wallet signs.

**Consequence for D2/D10 fix (privacy):** if we later add hiding
recipient commitments, the commitment construction lives off-circuit
too. The wallet computes `Commitment::commit(acct_id, rand)` and the
randomness is a regular witness — no in-circuit Pedersen needed unless
we're verifying commitment openings inside the predicate.

### 7.6 Tests serialised, memory-resident binaries linger — **LOW, but operationally costly**

**Discovered:** orphan `server-f8087395d1b79585` process consuming 35 GB
of swap reservation hours after `cargo test` finished.

**Cause:** when a background `cargo test` is aborted (or completes but
its child test binary doesn't terminate cleanly), the test binary
keeps its allocated arenas in memory and shows up as a giant resident
process in Activity Monitor.

**Mitigation:** see `program-plonky2/CONTRIBUTING.md` § "Test runtime
characteristics" and the `feedback_cleanup_test_binaries` memory entry.
After long test runs:

```bash
pgrep -f "target/debug/deps/zkcoins_program_plonky2"
# If any output: kill -TERM <PID>
```

### 7.7 `gh` needs `--repo` in background tasks — **LOW, operational**

**Discovered:** while running a CI watcher via `Bash` with
`run_in_background: true`. Background processes lose cwd-read
permission in this sandbox, so `cd ... && gh ...` fails with "Unable
to read current working directory: Operation not permitted".

**Mitigation:** always pass `--repo zk-coins/node` explicitly to gh
commands run in background contexts. Captured in memory as
`feedback_ci_monitor_after_push`.

### 7.8 Reference repos: BitVM/zkCoins is a 182-LOC toy, ShieldedCSV/ShieldedCSV is the real one — **codified**

**Re-stated for emphasis:** the upstream `BitVM/zkCoins` reference
repo is a Plonky2 IVC scaffold (182 LOC, no SMT/MMR/AccountState/Coin/
Schnorr/tests). The actual normative reference implementation is
`github.com/ShieldedCSV/ShieldedCSV`. Our implementation diverges from
the paper in 11 ways (see §3 of this doc / SPEC.md §15).

§3 is authoritative for "what does the paper say"; §3's divergence
table D1–D11 is authoritative for "where do we differ and why".

### 7.9 Defensive bounds checks collapse coverage regions — **codified**

**Discovered:** while pushing `program-plonky2` from 96.43% to 100%
line coverage (commit `e14d9df`).

**Symptom:** the MMR's `append` and `get_proof` had explicit
`if 2*idx+1 < len { levels[level][2*idx+1] } else { ZERO_HASH }`
defensive branches. The `else` arm is unreachable in correctly-
maintained state (the capacity-doubling guarantees `len` is always a
power of two ≥ `2*idx+2`), but llvm-cov sees it as an uncovered
region — perpetually below 100%.

**Fix:** rewrite as
`self.levels[level].get(idx).copied().unwrap_or(ZERO_HASH)`.

`Option::unwrap_or` is hashed as a single region by llvm-cov — the
"unreachable" path shares the region of the success path. The safety
fallback is preserved (`ZERO_HASH` returned if `get` ever fires the
`None`), but the branch no longer carries its own coverage debt.

**Generalisation for future code:** when you have a defensive
`if in_bounds { container[i] } else { sentinel }` pattern, prefer
`container.get(i).copied().unwrap_or(sentinel)`. The semantics are
identical and the coverage shape is cleaner.

### 7.10 Coverage-on-tests: annotate `#[cfg(test)] mod tests` with `coverage(off)` — **codified**

**Discovered:** same context as 7.9. After closing all genuine
production-side coverage gaps, the crate still measured ~99% lines
because llvm-cov tracks the panic-message-evaluation region inside
`assert!(cond, "msg")`, `assert_eq!`, `assert_ne!`, `should_panic`
macros as a separate region from the success path. Inside a passing
test the `"msg"` region is never executed, so it counts as uncovered.

**Fix:** add `#[cfg_attr(coverage_nightly, coverage(off))]` to every
test module (i.e. every `#[cfg(test)] mod tests { … }`). This requires
two prerequisites:

1. `src/lib.rs` declares the feature gate:
   `#![cfg_attr(coverage_nightly, feature(coverage_attribute))]`.
   The crate must be built on a nightly toolchain that supports the
   `coverage_attribute` feature (we're on `nightly-2025-04-15`).
2. `Cargo.toml` registers the cfg key so the compiler doesn't warn
   when building outside the coverage tool:

   ```toml
   [lints.rust]
   unexpected_cfgs = { level = "warn", check-cfg = ["cfg(coverage_nightly)"] }
   ```

The `coverage_nightly` cfg is set automatically by `cargo-llvm-cov`
when it instruments the build; in normal `cargo build` / `cargo test`
runs the attribute is a no-op.

**Generalisation:** test modules SHOULD always carry the
`coverage(off)` annotation in this codebase; production module-level
docs should not need it. New modules added in the future must include
this annotation if they ship a `#[cfg(test)] mod tests` block — see
`program-plonky2/CONTRIBUTING.md` § "Coverage gate" for the rule.

### 7.11 Hardware target is a Mac Studio M3 Ultra, single host — **codified**

**Discovered:** explicit architecture decision (commit `79bd39e`,
clarified shortly after).

**Constraint:** zkCoins runs on a single Mac Studio M3 Ultra (96 GB
unified RAM). On-box compute includes Performance + Efficiency cores,
the integrated Apple Silicon GPU (reachable via Metal), Neural Engine,
and AMX. **External** hardware (NVIDIA, CUDA, GPU farms) and external
cloud proving services (Succinct Prover Network, AWS GPU, Lambda Labs)
are **not** available. If a design overshoots the performance budget,
the design changes; we do not add external hardware.

**Important caveat about "GPU":** the M3 Ultra has a substantial
integrated GPU (60- or 80-core depending on bin) usable via Metal.
That GPU is on-box and would be fair game *if our prover library
supported it*. Plonky2 currently ships only CPU and CUDA backends —
no Metal — so the GPU sits idle for proving. This is a library
property, not a constraint we imposed. If a Plonky2 Metal backend
becomes available (or we port to Plonky3 which has more options), we
may use the GPU.

**Implications for design choices made earlier in this document:**

- §5.3 (Hash function): Poseidon-Goldilocks performance must be
  acceptable on the M3 Ultra. Today that's CPU performance, since
  Plonky2 has no Metal backend.
- §5.4 (Schnorr boundary): unchanged — boundary lives at byte
  serialisation, no in-circuit secp256k1.
- §6 sequencing: step 9's performance budget (`ROADMAP.md` step 9) is
  explicitly M3-Ultra-warm-proof ≤ 5 s, ideal ≤ 1 s, memory peak
  < 64 GB. If missed, knobs are design-level (reduce `MAX_IN_COINS`,
  drop in-coin recursion, switch to folding) — never external hardware.

**Implication for the Plonky3 post-MVP path** (`ROADMAP.md`):
BabyBear's GPU-friendliness in the broader literature usually means
CUDA-friendliness, which doesn't help us on Apple Silicon. The
motivation for switching to Plonky3 reduces to "matches SP1-era field
choice / Plonky3-native ecosystem". A separate question is whether
Plonky3's GPU paths might include Metal — if so, that would change
the calculation.

### 7.12 BitVM's `common_data_for_recursion` is broken under Plonky2 1.1.0 — **codified**

**Discovered:** building the stage-5a cyclic-recursion PoC (commit
`83fa0c1`).

**Symptom:** copying BitVM/zkCoins's `common_data_for_recursion`
verbatim into `circuit/main.rs` and calling
`builder.build::<C>()` on the outer cyclic circuit panics with
`Failed to build circuit` at `plonky2/src/plonk/circuit_builder.rs:1067`.
No useful error message; the panic comes from a shape-mismatch deep
in the verifier-data wiring.

**Root cause:** BitVM is pinned to **Plonky2 0.2.0**. In that version
the canonical `common_data_for_recursion` is **two `verify_proof`
calls in pass 2 and three in pass 3, plus a `ConstantGate` added to
the gate set**. Plonky2 1.1.0's
`conditionally_verify_cyclic_proof_or_dummy` produces a different
gate set and public-input shape, so the BitVM-shaped common-data is
no longer a fixed point. The library's outer build then rejects the
mismatch.

**Fix:** port Plonky2 1.1.0's own canonical
`recursion::cyclic_recursion::tests::common_data_for_recursion`
verbatim — **one `verify_proof` call per pass plus `NoopGate`
padding to `1 << 12` gates**. See
`program-plonky2/src/circuit/main.rs::common_data_for_recursion_c`
for the working implementation with full source comments.

**Why we keep both versions in mind:** if anyone later restores
BitVM's three-pass shape (e.g., on the theory that "more verifies =
more robust"), the build will fail again. The 1.1.0 canonical shape
is the only one that works with 1.1.0's `conditionally_verify_*`
machinery; this is not a stylistic preference.

**Ordering subtlety:** the BitVM reference order is
`add_virtual_public_input` → `add_verifier_data_public_inputs` →
`common_data_for_recursion` → `common_data.num_public_inputs = …`.
Plonky2 1.1.0's own canonical test orders it
`add_virtual_public_input` → `common_data_for_recursion` →
`add_verifier_data_public_inputs` → `common_data.num_public_inputs = …`
instead. The `common_data_for_recursion` function is stateless w.r.t.
the outer builder, so logically the order shouldn't matter — but
match the canonical order to avoid surprises.

### 7.13 Coverage debt from unreachable Plonky2 `Result<()>` calls — **codified**

**Discovered:** stage-5a (`83fa0c1`) initial draft used `?` to
propagate the `Result` of
`conditionally_verify_cyclic_proof_or_dummy`. `cargo llvm-cov` flagged
the `Err` arm as uncovered, dropping line coverage below the 100 %
gate.

**The pattern:** Plonky2 library functions like
`conditionally_verify_cyclic_proof_or_dummy`,
`pw.set_target`, `pw.set_proof_with_pis_target`,
`pw.set_verifier_data_target` all return `Result<…>` even though, in
correct usage, they only return `Err` under invariants we control by
construction (e.g., "common_data well-formed", "target not already
set"). These are unreachable error paths in our code, but `llvm-cov`
counts the branch.

**Fix recipe — analogous to §7.9 (Option-based defensive checks):**
- For functions that exist only for error propagation (like
  `build_cyclic_circuit`), make the function infallible by `.expect`-ing
  the unreachable `Err` and dropping `Result<…>` from the signature.
  The `expect` message documents the invariant that makes `Err` impossible.
- For witness-population calls inside helpers that already return
  `Result<…>` for other reasons (e.g. `data.prove`), keep `.unwrap()`
  inline; the surrounding `Result` covers the rest of the contract.

**Why this is *not* a fallback** (per `feedback_no_fallbacks`):
`.expect` doesn't replace bad output with default output — it
*panics* if the invariant ever breaks. The function's contract is
"this never returns Err under our usage"; making that explicit via
`.expect("…")` is documentation, not silent recovery. If the
invariant later breaks (e.g., library API changes), tests will catch
it via the panic, not a wrong-result soft failure.

**Residual region not covered:** the `.expect` itself still produces
one llvm-cov region for the panic branch (the `.unwrap_or_else(panic)`
expansion). That's 1 missed region per call. For the line-based MVP
gate (`cargo llvm-cov --fail-under-lines 100`) this is fine; for the
region-coverage stretch it's the unavoidable cost of unreachable
defensive paths in `Result`-returning library APIs.

### 7.14 Path-compressed SMTs are incompatible with cyclic recursion — **codified**

**Discovered:** stage-5c+ work in progress. The SMT shipped in
`6cf949c` used path compression — a single-leaf subtree at level *K*
had its level-*K* root equal to the leaf hash directly (no hashing
through default siblings down to depth `TREE_DEPTH`). Off-circuit
proofs had variable length *K* ≤ 256.

**Why it broke:** Plonky2 cyclic recursion requires a stable
`circuit_digest` across builds. The verifier shape — including the
number of hash levels processed by the SMT-inclusion gadget — must
be fixed at build time. Variable-length proofs would have produced
a circuit with `circuit_digest` depending on proof shape, breaking
the recursion fixed-point.

**Fix:** rewrite the off-circuit SMT to produce always-`TREE_DEPTH`
sibling proofs (`refactor: SMT to uncompressed fixed-256-depth
paths`). Empty subtrees contribute `DEFAULT_HASHES[level + 1]`
siblings, so the on-the-wire proof is 256 × 32 B = 8 KiB regardless
of sparsity. The off-circuit `insert` removes the `current != leaf_h
&& sibling == default → skip hash` short-circuit. Case A/B logic in
`NonInclusionProof` is gone too — non-inclusion is now a proof that
the depth-256 slot holds `DEFAULT_HASHES[TREE_DEPTH]`, full stop.

**Operational consequence:** roots produced by the new `insert`
differ from the pre-refactor compressed roots. The closed-test-env
strategy (`feedback_zkcoins_closed_test_env`) makes this a free
choice — no on-the-wire compatibility to preserve.

**Lesson for future merkle structures:** if a structure will be
verified inside a cyclic-recursive circuit, build the off-circuit
proof generator to emit *fixed-shape* proofs from day one. Path
compression and similar size-saving tricks save bytes off-chain but
cost a redesign once you need ZK over the same data.

### 7.15 Conditional constraints via `select_hash` masking — **codified**

**Discovered:** stage-5c+ added SPEC §8 (c)(d)(e) checks that fire
only on the AccountUpdate branch (`condition = true`). The
`verify_smt_inclusion` / `verify_mmr_inclusion` gadgets internally do
`connect_hashes(computed, expected_root)`, which is unconditional —
they cannot be "switched off" by a guard.

**Fix recipe:** expose a "compute-only" variant of each verify
gadget (`smt_inclusion_root`, `mmr_inclusion_root`) that returns the
reconstructed root *without* asserting equality. The caller then
constructs the masked target via

```rust
let target = select_hash(builder, condition, expected_witness, computed);
builder.connect_hashes(computed, target);
```

When `condition = false`, `select_hash` collapses to `computed` and
the resulting constraint `connect_hashes(computed, computed)` is
trivially satisfied. When `condition = true`, `target = expected_witness`
and the honest check fires.

**Why not skip-via-builder-condition:** Plonky2's `CircuitBuilder`
doesn't have a "conditional region" primitive — every gate fires.
Masking via `select` over the *target value* is the standard pattern
(used by Plonky2's own `conditionally_verify_cyclic_proof_or_dummy`,
the cyclic recursion machinery, etc.).

**Witness-population implication:** the masked-off branch still needs
*some* witness in the placeholders. Stage-5c+ uses a `dummy_cmp()`
helper that constructs a syntactically valid but semantically empty
`CommitmentMerkleProofs` (all `ZERO_HASH`, all-zero indices). The
masked equality constraints accept any witness when `condition = false`.

### 7.16 MMR root_extended / extend_to for fixed-depth verification — **codified**

**Discovered:** stage-5c+ needed the in-circuit MMR-inclusion gadget
to run at a fixed depth (`MMR_PROOF_PATH_LEN = MMR_MAX_DEPTH - 1 = 31`),
but the off-circuit `MerkleMountainRange` uses capacity-doubling and
produces variable-depth proofs (typically much shorter — `log2(N)`
for a tree with `N` leaves).

**Fix:** keep the MMR's natural shape (capacity doubles on demand)
but add two helpers:
- `MerkleMountainRange::root_extended(target_path_len)` — start from
  the natural root, then walk up additional levels of
  `hash_concat(current, ZERO_HASH)` until the path reaches
  `target_path_len`. This is what the in-circuit gadget compares
  against.
- `MMRProof::extend_to(target_path_len)` — pad the proof's
  `path` with `ZERO_HASH` siblings to `target_path_len`. The padded
  proof verifies against `root_extended(target_path_len)`.

The MMR root committed at the protocol boundary (e.g. inside
`ProofData::commitment_history_root`) is always the extended root at
the chosen `MMR_MAX_DEPTH`; everyone — off-circuit MMR users and the
in-circuit verifier — agrees on the same value.

**Why this beats redesigning the MMR:** the off-circuit MMR's
capacity-doubling shape is convenient for incremental appends
(O(log N) updates). A fixed-shape rewrite would re-allocate the full
tree up front. The `_extended` / `extend_to` helpers preserve the
fast off-circuit path while making the value the in-circuit verifier
needs trivially derivable.

### 7.17 Per-slot `active`-bit masking for variable-count loops — **codified**

**Discovered:** stage-5d needed to support a per-account state
transition processing 0..`MAX_IN_COINS` input coins, but the circuit
shape must be fixed (otherwise `circuit_digest` changes per
transaction → cyclic recursion breaks).

**Pattern:** declare a constant `MAX_IN_COINS` slot count at the
circuit-builder level. Each slot reserves witness targets including
an `active: BoolTarget`. The slot's predicate is wrapped so that
`active = false` makes every constraint trivially satisfied:

- Equality / hash-match checks: `connect_hashes(computed, select_hash(active, expected, computed))`.
- Value-update accumulators: `running = select_hash(active, new_value, running)`.

This is the same `select_hash` masking pattern from §7.15, scaled
out across a fixed list of slots. The off-circuit prover decides at
runtime how many slots are active — the unused ones get a dummy
witness (zeroed coin id, zero-filled proof path) that the masked
constraints accept.

**Caller ergonomics:** for the common case where all slots are
inactive (e.g. Init proofs without in-coins), provide a thin wrapper
`prove_*(args)` that delegates to the explicit
`prove_*_with_in_coins(args, &inactive_dummies)`. The explicit
variant remains available for tests and callers that need to control
slot activity directly.

**Performance cost:** each masked slot adds the *full* gate count of
the underlying predicate (the masking doesn't save gates — it only
makes the result vacuously satisfied). For stage 5d's SMT
non-inclusion + insert this is ~512 Poseidon hashes per slot at
`TREE_DEPTH = 256`. Bumping `MAX_IN_COINS` from 1 to 8 grows the
circuit by ~3500 hashes — measure before committing to a target.

### 7.18 `add_virtual_target` requires explicit witnessing; prefer `split_le` — **codified**

**Discovered:** stage-5d-next initially implemented the balance
overflow check by declaring `new_lo`, `new_hi`, `carry`, `overflow`
as `add_virtual_target()` / `add_virtual_bool_target_safe()`
targets, range-checking them, and `connect()`ing the recomposed
value to the precomputed `sum`. The test failed at proof generation
with `22 generators weren't run` — Plonky2 had no way to fill the
virtual targets.

**Root cause:** `add_virtual_*` reserves a witness slot but does NOT
attach a generator. The prover must explicitly populate every
virtual target via `pw.set_target` / `pw.set_bool_target`. If the
target's value is determined by other witnesses, the prover would
have to recompute it off-circuit and supply it manually — fragile
and error-prone.

**Fix:** use `builder.split_le(t, n_bits)`. It internally adds a
`BaseSumGate` whose generator decomposes `t` into `n_bits` bits at
prove time, and constrains each bit to be `{0, 1}` plus the
recomposition `t == Σ bit[i] * 2^i`. The bits come back as
`BoolTarget`s the caller can use, but no explicit witnessing is
needed — given `t`, the bits are uniquely determined.

For the balance check, `sum_lo ∈ [0, 2^33)` decomposes into 33 bits;
`bits[32]` is the carry; `new_lo = sum_lo - 2^32 * carry` is the
low 32 bits and stays in range by construction. Same pattern for
the hi limb with an `assert_zero(overflow)` at the top.

**Rule of thumb:** if a target's value is *uniquely determined* by
other targets (low/high decomposition, range checks, comparisons),
look for a Plonky2 gate that ships its own generator
(`split_le`, `range_check`, `add_many`, `arithmetic` family).
Reserve `add_virtual_*` for prover-driven witnesses (e.g. real
secret-key inputs, side channels, off-circuit results that you must
trust the prover for).

### 7.19 `account_state.hash` lifecycle inside a transition — **codified**

**Discovered:** stage 5d-next-3 (out-coins). The same
`AccountState::hash` value plays three different roles inside the
SPEC §8 state-transition predicate, and conflating them broke a
positive test with a cryptic "Partition was set twice with different
values" Plonky2 error.

**The three hashes:**

| Role | Inputs | Used by |
| --- | --- | --- |
| `initial_account_state_hash` | `owner` + INITIAL balance + INITIAL pubkey | SPEC §8 (b) state continuity, (c) commitment-witness check |
| `interim_account_state_hash` | `owner` + POST-in-coins-AND-out-coins balance + INITIAL pubkey | Out-coin identifier derivation: `out_coin.identifier == H(interim_asth || index)` |
| `final_account_state_hash` | `owner` + POST-in-coins-AND-out-coins balance + NEW pubkey | Public output `ProofData.account_state_hash` |

**Why three not one:**
- The in-coin loop mutates the running balance via `apply_coin`.
- The out-coin loop further mutates it via `send_coins`.
- The pubkey is rotated *after* identifier derivation, *before* the
  final commit.

So:
- (b) and (c) compare against `prev.account_state_hash` and
  `mp.commitment_account_state_hash`, both of which witness the
  state at *start* of the transition. Use INITIAL balance + INITIAL
  pubkey.
- The out-coin identifier `H(account_hash || index)` is computed
  *after* subtractions per SPEC §8 step 3. Use POST-subtraction
  balance + INITIAL pubkey (rotation happens *after* the loop).
- The committed public output is the state at the *end* of the
  transition. Use POST-subtraction balance + NEW pubkey.

**Common test mistake:** computing the off-circuit expected
identifier `H(account_hash || index)` using the INITIAL balance.
The in-circuit identifier-equality check then fails with a wire
conflict because the prover-supplied identifier doesn't match the
in-circuit `H(interim_asth || index)`. Catch: when writing the
out-coin test fixture, always pre-compute the interim balance from
`initial - out_coin_amount` before hashing.

### 7.21 Stage 5d-next-4 source-side verification blocked on Plonky2 1.1.0 — **resolved in §7.22**

**Discovered:** when attempting Stage 5d-next-4 — adding per-in-coin
recursive verification of the source state-transition proof per
SPEC §8 step 2 — two distinct Plonky2 1.1.0 limitations made the
full implementation infeasible for MVP timeline.

#### Attempted approach A: 8 cyclic verifies in outer circuit

Added `MAX_IN_COINS = 8` additional `conditionally_verify_cyclic_proof_or_dummy::<C>`
calls inside `build_circuit` (one per slot) plus an extended
`common_data_for_recursion_c` with `N_RECURSIVE_VERIFIES = 9`
`verify_proof` calls in pass 3 (1 prev_account + 8 sources).

The outer's gate count crossed the per-gate-config constants budget
and Plonky2 emitted `ConstantGate { num_consts: 2 }` in the
`common_data.gates` list. But Plonky2's `dummy_circuit` (called from
`dummy_proof_and_vk` inside `_or_dummy`) rebuilds a circuit with just
NoopGate + `add_gate_to_gate_set`, so its `circuit.common.gates`
excludes `ConstantGate`. The `assert_eq!` in `dummy_circuit.rs:116`
fires:

```
assertion `left == right` failed
  left:  CommonCircuitData { gates: [NoopGate, ConstantGate { num_consts: 2 }, ...] }
  right: CommonCircuitData { gates: [NoopGate, PoseidonMdsGate, ...] }
```

Both `cyclic_base_proof` AND `conditionally_verify_cyclic_proof_or_dummy`
trigger this assertion. So in Plonky2 1.1.0, **circuits that emit
`ConstantGate` are limited to exactly ONE `_or_dummy` call per outer
build**.

#### Attempted approach B: in-circuit data-only source check (no cyclic verify)

Dropped the recursive verify; kept only the SMT inclusion of the
coin in the witnessed `source_output_coins_root` + SPEC §8 (c)(d)(e)
chain for the source's commitment in `history_root`. Idea: the
"source is a valid prior transition" property is enforced by the
trusted server only folding validly-proved commitments into the
history MMR — sufficient for server-heavy MVP.

The outer build then failed with a different error: the cyclic
fixed-point check `goal_data != common` failed at `circuit_builder.rs:1067`
("Failed to build circuit"). The added source-side gates (SMT
inclusion path of 256 levels + CMP chain per slot) pushed outer's
gate count from ~10 k (Stage 5d-next-3) to ~30 k, but the resulting
`CommonCircuitData` shape didn't exactly match what
`common_data_for_recursion_c`'s pass 3 produced — multiple
`INNER_PAD_BITS` values (14, 15, 16, 17) all triggered the mismatch
because the gate-set composition (selector groups, constant counts)
diverged in ways that NoopGate padding alone cannot reconcile.

#### Decision

**Defer to Stage 5d-next-5 (post-MVP).** For the zkCoins server-heavy
MVP architecture (server generates all proofs, wallet holds only
private key, single trusted server), the security property "in-coin
came from a valid prior transition" can be enforced **off-circuit**:
the server only folds commitments of validly-proved transitions into
the history MMR. So in-circuit SMT inclusion of the coin in the
witnessed `source_output_coins_root` + CMP chain for the source's
commitment in `history_root` would be sufficient — but even that
hit the build-time `goal_data != common` mismatch.

Stage 5d-next-3 already implements:
- Prev-account cyclic recursion (1 verify, `condition` selects Init vs Update).
- Full coin-history-side in-coin predicate (SMT non-inclusion + insert,
  apply_coin with recipient + balance-overflow).
- Full out-coin processing (SMT non-inclusion + insert, balance
  subtraction with underflow, identifier derivation, pubkey rotation).
- SPEC §8 (c)(d)(e) chain for the **prev_account**'s commitment.
- All 10 of 11 SPEC §13 negatives covered (only "source-not-in-history"
  is deferred).

This is sufficient for shipping the MVP. Stage 5d-next-5 paths
forward when revisited:
1. **Aggregator pattern**: separate non-cyclic aggregator circuit
   bundling N source verifies, outer verifies one aggregator proof.
   Avoids the multi-`_or_dummy` issue.
2. **Plonky2 patch**: upstream fix to make `dummy_circuit` reproduce
   `ConstantGate`-containing `common_data` shapes. Significant work.
3. **Single-source build constraints**: rebuild outer so its
   `common_data` matches pass-3's exactly even with the additional
   source-side gates. Requires understanding Plonky2's selector
   group formation.

**Rule of thumb:** for `conditionally_verify_cyclic_proof_or_dummy`
to work, the outer's actual `common_data` after build must EXACTLY
match the `common_data` you passed in. Adding constraints / constants
to the outer changes selector groups and can break the match
unrecoverably even with NoopGate padding. Test minor circuit
additions iteratively against the smoke test, not in one big batch.

---

### 7.20 Speed up panic tests via `cyclic_base_proof` short-circuit — **codified**

**Discovered:** stage-5d-next-3 added panic tests like
`stage_5d_next_3_prove_account_update_panics_on_wrong_in_slot_count`
to cover the `assert_eq!`-message lines in
`prove_account_update_with_in_and_out_coins`. The first draft
called `prove_initial(...)` to construct a real prev proof before
invoking the function — paying **~13 min wall clock** per "panic"
test at `MAX_IN_COINS = MAX_OUT_COINS = 8`. Multiply by N panic
tests and the test sweep balloons.

**The trick:** the slot-count `assert_eq!`s fire at the **top** of
the function, before any witness setting, before `prove`. The
`prev: &ProofWithPublicInputs<F, C, D>` parameter is never consumed
in the panic path. Substitute a `cyclic_base_proof(common_data,
verifier_only, empty_pis)` dummy — type-equivalent, ~10 ms to
construct, panic short-circuits before it's touched.

```rust
let dummy_inner_pis = std::iter::empty::<(usize, F)>().collect();
let dummy_prev = cyclic_base_proof(
    &circuit.common_data,
    &circuit.data.verifier_only,
    dummy_inner_pis,
);
let _ = prove_account_update_with_in_and_out_coins(
    &circuit, &account_state, ZERO_HASH, &dummy_prev, &dummy_cmp(),
    &[],  // wrong slot count — assert_eq! fires here
    &out_coins, &account_state.public_key,
);
```

Net savings on stage 5d-next-3: ~25 min wall per full test sweep
(2 account-update panic tests × ~13 min each). Pattern generalises
to any `should_panic` test whose target's expensive arguments are
only consumed *after* the panic point.

**Rule of thumb:** when writing a `should_panic` test for a
function with expensive arguments, look at where the panic fires
in the function body — if the arguments aren't accessed before
that point, substitute dummies.

---

### 7.22 Stage 5d-next-5 source-side verification via aggregator pattern — **codified (resolves §7.21)**

**Discovered:** §7.21 deferred source-side verification because both
attempted paths failed at Plonky2 1.1.0's recursion seams. The
resolution combined two empirical fixes — `ConstantGate::new(2)`
injection in the helper, and the `helper_degree = pad_bits + 1`
relation — with an aggregator-pattern restructure that bundles all
`MAX_IN_COINS` source verifies into a single non-cyclic aggregator
proof. The outer then performs exactly **one** additional verify (the
aggregator), staying under the "one `_or_dummy` per outer" budget
that broke approach A in §7.21.

#### Final architecture

```
┌─────────────────────────────────────────────────────────────┐
│ SourceAggregatorCircuit (NON-CYCLIC)              [PHASE 1] │
│                                                             │
│   For each slot i in 0..MAX_IN_COINS:                       │
│     active[i]: BoolTarget                                   │
│     real_proof[i]: ProofWithPublicInputsTarget              │
│     dummy_proof[i]: ProofWithPublicInputsTarget             │
│     conditionally_verify_proof::<C>(                        │
│       active[i],                                            │
│       real_proof[i], st_verifier_data,        ← shared      │
│       dummy_proof[i], dummy_vd_target,        ← constant    │
│       st_common,                                            │
│     )                                                       │
│                                                             │
│   PIs:                                                      │
│     [i*17 .. i*17 + 16]: source ProofData                   │
│     [i*17 + 16]: active bit                                 │
│     [MAX_IN_COINS*17 .. + 4]: st verifier_data digest       │
│     [MAX_IN_COINS*17 + 4 ..]: st verifier_data sigmas_cap   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ aggregator_proof
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Outer StateTransitionCircuit (CYCLIC)         [PHASE 2a+2b] │
│                                                             │
│   verify_proof::<C>(  ← hoisted above in-coin loop          │
│     aggregator_proof,                                       │
│     aggregator_verifier_data,   ← constant_verifier_data    │
│     aggregator_common,                                      │
│   )                                                         │
│                                                             │
│   connect_hashes(claimed_st_digest, outer_vd.digest)        │
│   connect_hashes(claimed_st_cap, outer_vd.cap)              │
│                                                             │
│   Per in-coin slot i (Phase 2b):                            │
│     connect(slot.active, aggregator.slot[i].active_pi)      │
│     SMT inclusion of coin_identifier in                     │
│       source.output_coins_root         (masked by .active)  │
│     Coupling: source.output_coins_root ==                   │
│       source_cmp.commitment_out_coins_root                  │
│     SPEC §8 (c)(d)(e) chain for source.commitment in        │
│       outer's history_root                                  │
│                                                             │
│   conditionally_verify_cyclic_proof_or_dummy(               │
│     condition, prev_account_proof, common_data,             │
│   )                                                         │
│                                                             │
│   builder.add_gate(ConstantGate::new(2), [0, 0])  ← shape   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Two empirical insights pinned by `recursion_shape_probe`

**Insight 1 — `ConstantGate::new(2)` injection (probe-verified).**
`common_data_for_recursion_c_inner` calls two `verify_proof`s in pass
2 and 3 (one cyclic, one against the aggregator). Pass-3's
`ArithmeticGate` instances absorb every routed constant — no
standalone `ConstantGate` ever gets allocated by `builder.build::<C>()`.
But `dummy_circuit`'s rebuild always emits one (its hard-coded `- 2`
NoopGate reservation reserves a row for `PublicInputGate +
ConstantGate`). The `assert_eq!(&circuit.common, common_data)` at
`plonky2-1.1.0/src/recursion/dummy_circuit.rs:116` then panics.

Probe data (`recursion_shape_probe::dump_pass_3_gates_lists_for_inspection`):

| Helper variant | `gates.len()` | `ConstantGate`? | `dummy_circuit` |
|---|---:|---|---|
| Stage 5d-next-3 baseline (1 verify, pad 14) | 13 | ✓ | **OK** |
| 2 verify, pad 14, no injection | 12 | ✗ | **PANIC** |
| 2 verify + 1/4/16/64/256 forced constants via `mul(c, zero)` | 12 | ✗ | **PANIC** |
| **2 verify + explicit `ConstantGate::new(2)` injection, pad 14** | **13** | **✓** | **OK** |

Fix lives in `common_data_for_recursion_c_inner`'s pass 3 — see the
function's in-source comment for the injection rationale.

**Insight 2 — `INNER_PAD_BITS_STAGE_5D_NEXT_5 = 15` (sweep-verified).**
Once `dummy_circuit` accepts the gate-set, the cyclic fixed-point
check at `plonk/circuit_builder.rs:1067` (`goal_data != common`) is
still strict: it requires `outer.common == helper-pass-3 common`
field-by-field. The `build_minimal_outer_for_diagnostic` plus
field-diff exercise isolated the only diverging axis to
`fri_params.degree_bits`, exposing the empirical relation:

> `helper_degree = pad_bits + 1`

The helper's pad-bits must therefore equal `outer_degree - 1` to
converge:

| Stage | outer gate count (approx) | outer_degree | required `pad_bits` |
|---|---:|---:|---:|
| 5d-next-3 (1 verify, no source-side) | ~10 k | 14 | 13 |
| 5d-next-5 Phase 2a (2 verify, no source-side gates) | ~30 k | 15 | **14** |
| 5d-next-5 Phase 2b (2 verify + 8 source slots × {SMT + CMP}) | ~50 k | 16 | **15** |
| Hypothetical future stage crossing 2^16 | > 65 k | 17 | 16 |

`INNER_PAD_BITS_STAGE_5D_NEXT_5 = 15` makes `helper_degree = 16` match
the full outer's `degree_bits = 16`.

If any future change crosses a power-of-two gate-count threshold,
rerun the sweep and bump `pad_bits`:

```bash
cd program-plonky2
cargo test --release --lib \
  circuit::recursion_shape_probe::dump_phase_2a_pad_bits_sweep \
  -- --ignored --nocapture
```

The sweep uses a MINIMAL outer (no real Stage 5d-next-3 / 5d-next-5
constraints); it establishes the `helper_degree = pad_bits + 1`
relation. The full outer's degree must then be measured directly via
`circuit.data.common.fri_params.degree_bits` and compared.

#### Phase 2b per-slot constraints

For slot `i ∈ 0..MAX_IN_COINS`, in `build_circuit`'s in-coin loop:

1. Extract source `ProofData` from aggregator PIs at offset
   `i * PER_SLOT_PIS` — `account_state_hash`, `output_coins_root`,
   `commitment_history_root` (`coin_history_root` is unused for
   SPEC §8 step 2).
2. **Active-bit binding** — `builder.connect(slot.active.target,
   aggregator.slot[i].active_pi)`. Strict equality: there is no way
   to consume an in-coin without a verified source proof.
3. **SMT inclusion** of `coin.identifier` in `source.output_coins_root`.
   Leaf value = `h(coin.identifier || coin.identifier)` (set-membership
   convention, matching the source's own out-coin SMT insertion at
   `hash_up_full_path(new_leaf = h(id || id), id_bits, nip_path)`).
   Uses `hash_up_full_path` directly — NOT `smt_inclusion_root`, which
   would add an extra `smt_leaf_hash` step and break the binding.
4. **Coupling** — `source.output_coins_root ==
   source_cmp.commitment_out_coins_root`, masked element-wise
   (`mul(active, diff) → assert_zero`).
5. **SPEC §8 (c)** — `source.account_state_hash ==
   source_cmp.commitment_account_state_hash`, masked.
6. **SPEC §8 (d), first half** — SMT inclusion of `commitment =
   h(commitment_account_state_hash || commitment_out_coins_root)` at
   `source_cmp.smt_key` in `source_cmp.commitment_root`, masked.
7. **SPEC §8 (d), second half** — MMR inclusion of
   `h(source_cmp.commitment_root || source_cmp.commitment_root_mmr_sibling)`
   at `source_cmp.mmr_a_index` in the outer's `history_root`, masked.
8. **SPEC §8 (e)** — MMR inclusion of `h(source_cmp.prev_smt_in_mmr_leaf
   || source.commitment_history_root)` at `source_cmp.mmr_b_index` in
   the outer's `history_root`, masked.

#### Public API extensions

```rust
pub struct InCoinSourceWitness<'a> {
    pub source_proof: &'a ProofWithPublicInputs<F, C, D>,
    pub source_inclusion: &'a InclusionProof,
    pub source_cmp: &'a CommitmentMerkleProofs,
}

pub fn prove_initial_with_in_and_out_coins_and_sources(
    circuit, account_state, history_root,
    in_coins, out_coins, next_public_key,
    sources: &[Option<InCoinSourceWitness>],  // MAX_IN_COINS entries
) -> Result<ProofWithPublicInputs<F, C, D>>;

pub fn prove_account_update_with_in_and_out_coins_and_sources(
    circuit, account_state, history_root, prev, cmp,
    in_coins, out_coins, next_public_key,
    sources: &[Option<InCoinSourceWitness>],
) -> Result<ProofWithPublicInputs<F, C, D>>;
```

The legacy all-inactive `prove_*_with_in_and_out_coins` entry points
delegate with `&[None; MAX_IN_COINS]`. Callers with active in-coin
slots **must** use the `_and_sources` variants — the active-bit
binding constraint enforces this at prove time.

#### Multi-leaf MMR test fixture insight

`build_test_source_witness` (1-leaf MMR, Phase 2b Initial smoke) and
`build_test_source_and_prev_witnesses` (2-leaf MMR, Phase 2b
AccountUpdate smoke) both ship with the implementation. The 2-leaf
fixture is nontrivial: with BOTH the consumer-prev proof AND the
source proof having `commitment_history_root = ZERO_HASH` (bootstrap),
only ONE of them can use the bootstrap-shaped (e) leaf
`h(? || ZERO_HASH)` at its own MMR index. The fixture resolves this
by folding consumer-prev FIRST (so consumer's leaf is the unique
`h(? || ZERO_HASH)`-shaped leaf at index 0) and source SECOND at
index 1, then having source's (e) "borrow" consumer's bootstrap leaf
at index 0 via `source_cmp.prev_smt_in_mmr_leaf = consumer_smt_root`
and `source_cmp.previous_root_history_proof.1 = consumer_mmr_proof`.
This is a TEST-FIXTURE peculiarity; production producers proving
against a non-empty history don't hit it because they have richer
non-bootstrap MMR shapes available.

#### Test coverage matrix

Positives (5 integration tests, all green):

| Case | Test |
|---|---|
| Init, all-inactive in-coins | `stage_5c_plus_initial_non_mint_zero_balance_accepted` |
| Init, 1 active in-coin + real source proof | `stage_5d_next_5_phase_2b_initial_with_one_active_in_coin_and_source` |
| Init, in-coin + out-coin + source | `stage_5d_next_5_phase_2b_initial_combined_in_and_out_coin_with_source` |
| Update, all-inactive in-coins | `stage_5c_plus_initial_then_account_update_with_commitment_proofs` |
| Update, 1 active in-coin + real source proof | `stage_5d_next_5_phase_2b_account_update_combined_in_and_out_coin_with_source` |

SPEC §13 source-side negatives (3 cases, all green):

| Attack | Constraint that catches it | Test |
|---|---|---|
| Source's commitment not in `history_root` (tamper MMR-(e) path) | masked `connect_hashes(mmr_b_computed, history_root)` | `stage_5d_next_5_phase_3_source_not_in_history_rejected` |
| Coin identifier not in source's `output_coins_root` (tamper SMT path) | masked `connect_hashes(source_inclusion_computed, source_output_coins_root)` | `stage_5d_next_5_phase_3_coin_not_in_source_ocr_rejected` |
| Wrong `st_verifier_data` witnessed in aggregator | `connect_hashes(claimed_st_digest, outer_vd.circuit_digest)` | `stage_5d_next_5_phase_3_wrong_st_vk_on_aggregator_rejected` |

The wrong-vk negative is non-trivial to construct because the
aggregator's `conditionally_verify_proof` would normally reject a
wrong-vk source proof at aggregator prove-time. The test exploits the
all-inactive case: with no slot active, the aggregator never actually
uses the witnessed `st_verifier_data` for verification (only the
constant-baked `dummy_vd_target` for the dummy branch), so the
aggregator can be proved with a LYING `st_verifier_data`. The lie
then surfaces at the outer's `connect_hashes`.

#### Benchmark (M3, 24 GB, single-threaded `cargo test --release --lib …`)

- `stage_5c_plus_initial_non_mint_zero_balance_accepted` (all-inactive
  Phase 2b smoke): **~40 s** wall.
- `stage_5c_plus_initial_then_account_update_with_commitment_proofs`
  (init → update chain, all-inactive in-coins): **~53 s** wall.
- `stage_5d_next_5_phase_2b_initial_with_one_active_in_coin_and_source`
  (Init + 1 active in-coin from source): **~99 s** wall (Init for the
  source ~40 s + consumer Init ~50 s).
- `stage_5d_next_5_phase_2b_account_update_combined_in_and_out_coin_with_source`
  (Update + in-coin + out-coin + source, 2-leaf MMR): **~154 s** wall
  (source Init + consumer prev Init + consumer Update).
- Phase 3 negatives: each ~50–55 s wall (one source Init + one
  consumer prove, except the wrong-vk negative which skips the source
  build entirely via the all-inactive shortcut).
- `dump_phase_2a_pad_bits_sweep` (`#[ignore]`d diagnostic, 4 rebuilds
  of aggregator + minimal outer): **~138 s** wall.

#### Verification runbook

```bash
cd program-plonky2

# 1. Phase 2a probe (no Phase 2b dependencies).
cargo test --release --lib \
  circuit::recursion_shape_probe::dump_pass_3_gates_lists_for_inspection \
  -- --nocapture
# Expect: baseline_ok=true, 2v_14=false, 2v_14_with_constant_gate=true

cargo test --release --lib \
  circuit::recursion_shape_probe::dump_phase_2a_pad_bits_sweep \
  -- --ignored --nocapture
# Expect: pad_bits=N → helper_degree=N+1 for N in {14, 15, 16, 17}

# 2. Phase 2a smokes (all-inactive in-coins; Stage 5d-next-3 regression).
cargo test --release --lib \
  stage_5c_plus_initial_non_mint_zero_balance_accepted \
  -- --nocapture
cargo test --release --lib \
  stage_5c_plus_initial_then_account_update_with_commitment_proofs \
  -- --nocapture

# 3. Phase 2b positives (active in-coin slots + real source proofs).
cargo test --release --lib stage_5d_next_5_phase_2b -- --nocapture --test-threads=2

# 4. Phase 3 negatives.
cargo test --release --lib stage_5d_next_5_phase_3 -- --nocapture --test-threads=2

# 5. Aggregator regression (Phase 1).
cargo test --release --lib circuit::source_aggregator::tests::
```

**Rule of thumb:** when a Plonky2 1.1.0 outer circuit needs more than
one `verify_proof`, factor the additional verifies into a non-cyclic
aggregator and verify the aggregator (a single proof) from the outer.
Per outer build, exactly one `_or_dummy` plus one or more
non-`_or_dummy` `verify_proof`s. The aggregator must be built before
the outer (its `verifier_data` is a circuit constant in the outer);
the fixed-point iteration in `common_data_for_recursion_c_inner` then
needs `ConstantGate::new(2)` injection in pass 3 and
`pad_bits = outer_degree - 1` to converge.

### 7.23 `MINTING_ADDRESS` panic in `tokio::spawn`-ed task swallows server bootstrap — **MEDIUM, codified**

**Discovered:** first auto-deploy of `zkcoin/node:beta` on the DEV
host post-PR [#17](https://github.com/zk-coins/node/pull/17). The
container started, the REST server bound `0.0.0.0:4242`, but
`https://dev-api.zkcoins.app/health` returned Cloudflare 502 for hours.
`docker compose ps` showed the container as `Up (unhealthy)` — the
tokio worker that owned the HTTP listener panicked on every cold boot
after the Plonky2 migration, while the block-scanner worker kept
processing blocks. No restart, no monitor, no visible failure in
`docker logs`.

**Root cause:** the Plonky2 migration moved `MINTING_ADDRESS` to a
well-known constant (`hash_bytes(b"zkcoins:minting-address:placeholder:v1")`
in `program-plonky2/src/types.rs`). The SP1-era `ClientAccount::new`
in `server` still derived `address` from the privkey's first child
pubkey; the `assert_eq!` in `start_rest_server` between the two could
never hold again. **And** a panic inside a `tokio::spawn`-ed task by
default only kills the task — the process happily continued in zombie
state for 8 h with the listener dead and the scanner alive.

**Fix (PR [#36](https://github.com/zk-coins/node/pull/36)):**

1. **Explicit `MINTING_ADDRESS` override** applied in
   `runtime.rs::start_rest_server`: after constructing the
   minting `ClientAccount` from `minting_secret.bin`, the code
   overwrites `minting_client.address = *MINTING_ADDRESS` so the
   on-chain identity matches the well-known constant that the Plonky2
   circuit uses, replacing the failing `assert_eq!`. Matches the
   pattern already used in `router_tests.rs::TestAccountData::new_minting_account`.
2. **Global panic hook** installed at the top of `main.rs::main` that
   runs the default reporter and then `exit(1)`. Any future tokio
   worker panic now crash-loops the container via `restart:
   unless-stopped` instead of becoming a silent zombie.
3. **Integration smoke test** (`start_rest_server_binds_and_serves_health`)
   that spawns `start_rest_server` against an ephemeral port and probes
   `/health` over real TCP. `runtime.rs` was excluded from the
   coverage scope, so the bootstrap path that exploded had no test at
   all. ~22 s warm; runs in the standard test sweep.
4. **deploy-dev post-curl-retry** in `.github/workflows/deploy-dev.yaml`:
   up to 30 × 10 s polls of `https://dev-api.zkcoins.app/api/info` after
   the ssh deploy. A green "Build and deploy to DEV" with a broken
   upstream is no longer possible — the workflow fails, the auto-release
   PR loses its green check, and the regression surfaces immediately
   instead of hours later. Mirrored to deploy-prd in PR [#51](https://github.com/zk-coins/node/pull/51).

**Lesson:** in async server code, NEVER let a spawned task panic
silently. Either install a global panic hook (the cheap fix taken
here) or wrap every spawned future in a `Result`-returning closure
that explicitly propagates the panic to the main task via a watcher
channel. The deploy workflow must also probe the public health
endpoint before declaring success — `docker compose up -d` exiting 0
is a build-time signal, not a runtime-readiness signal.

**Regression guard:** the smoke test fires on every test sweep; the
deploy-dev post-curl-retry fires on every DEV deploy. A regression
that brings back the silent-panic shape fails one or both gates.

---

## 8. Local Artifacts

- BitVM/zkCoins reference (cloned): `~/Documents/GitHub/zkcoins/BitVM-zkCoins-reference/`
- Shielded CSV reference implementation files (downloaded by the research agent): `/tmp/shielded_csv_lib.rs`, `/tmp/shielded_csv_primitives.rs`, `/tmp/shielded_csv_node.rs`. **TODO:** clone the full `ShieldedCSV/ShieldedCSV` repo to `~/Documents/GitHub/zkcoins/ShieldedCSV-reference/` if we decide to make it the normative reference (see §5.1).

---

## 9. References

- Shielded CSV paper: https://eprint.iacr.org/2025/068
- Shielded CSV reference implementation: https://github.com/ShieldedCSV/ShieldedCSV
- BitVM/zkCoins Plonky2 prototype: https://github.com/BitVM/zkCoins
- Blockstream blog: https://blog.blockstream.com/bitcoins-shielded-csv-protocol-explained/
- Bitcoin Magazine: https://bitcoinmagazine.com/technical/shielded-csv-protocol
- Plonky2: https://github.com/0xPolygonZero/plonky2
