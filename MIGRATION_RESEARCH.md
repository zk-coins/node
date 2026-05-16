# Migration Research: References and Adoption Decisions

Companion document to [`SPEC.md`](./SPEC.md). Summarises what we can take from the upstream references, and — more importantly — flags where our current implementation has diverged from the published Shielded CSV protocol. Read this before writing any Plonky2 code.

---

## TL;DR

1. **`BitVM/zkCoins` is a 182-LOC IVC toy, not a zkCoins prototype.** It gives us a Plonky2 version pin and a cyclic-recursion code recipe, nothing more.
2. **The real normative reference is `ShieldedCSV/ShieldedCSV`** — a non-circuit Rust implementation of the paper's PCD predicate.
3. **Our current SP1 implementation has departed from the published protocol in 11 distinct ways.** Some are simplifications (Schnorr commitment on a Taproot inscription instead of half-aggregate nullifier publication), some are arguably regressions (recipient is plaintext `Address`, linkable across coins), some are missing features (fee output, conditional-noop on reorg).
4. **Decision point for Robin / Cyrill:** Are we implementing _Shielded CSV as published_, or are we shipping a zkCoins MVP that intentionally diverges? Both are defensible; we just need to pick before we re-implement the circuit in Plonky2, otherwise we lock in design choices that aren't reviewable against any spec.

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
| `plonky2 = "0.2.0"` version pin | **Adopt** | Same version Robin used; ecosystem-current. |
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
- **Discuss with Robin:** D4 (does the SMT+MMR scanner model actually give the same security properties as `ToSAcc` for our threat model?), D9 (cheap to add).

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
- The Account → coin_queue → send flow in `server/src/account_server.rs` — this is host-side glue, no circuit changes here except wiring to the new Plonky2 prover.
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

**Mitigation:** always pass `--repo zk-coins/server` explicitly to gh
commands run in background contexts. Captured in memory as
`feedback_ci_monitor_after_push`.

### 7.8 Reference repos: BitVM/zkCoins is a 182-LOC toy, ShieldedCSV/ShieldedCSV is the real one — **codified**

**Re-stated for emphasis:** the `BitVM/zkCoins` repo Robin pointed us
at is a Plonky2 IVC scaffold (182 LOC, no SMT/MMR/AccountState/Coin/
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

**Discovered:** explicit architecture decision (commit `79bd39e`).

**Constraint:** zkCoins runs on a single Mac Studio M3 Ultra (96 GB
unified RAM, Apple Silicon CPU). No discrete GPU. No external cloud
proving service (no Succinct Prover Network, no AWS GPU, no Lambda
Labs). If a design overshoots the performance budget, the design
changes; we do not add hardware.

**Implications for design choices made earlier in this document:**

- §5.3 (Hash function): Poseidon-Goldilocks performance must be
  acceptable on Apple Silicon CPU. Plonky2 has no GPU path anyway, so
  this constraint is structurally compatible.
- §5.4 (Schnorr boundary): unchanged — boundary lives at byte
  serialisation, no in-circuit secp256k1.
- §6 sequencing: step 9's performance budget (`ROADMAP.md` step 9) is
  explicitly M3-Ultra-warm-proof ≤ 5 s, ideal ≤ 1 s, memory peak
  < 64 GB. If missed, knobs are design-level (reduce `MAX_IN_COINS`,
  drop in-coin recursion, switch to folding) — never hardware.

**Implication for the Plonky3 post-MVP path** (`ROADMAP.md`):
BabyBear's GPU-friendliness is a generic benefit that does **not**
apply to us. The motivation for switching to Plonky3 reduces to
"matches SP1-era field choice / Plonky3-native ecosystem"; the
performance argument is significantly weaker on CPU-only hardware.

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
