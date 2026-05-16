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

## 5. Open Decisions for Cyrill / Robin

These must be resolved before Plonky2 implementation starts; they are not Plonky2-specific but they all affect the circuit's public-input shape, which means relitigating them later costs another full rebuild.

1. **Paper-fidelity vs. zkCoins variant.** Are we implementing Shielded CSV as published (with `ToSAcc`, fee output, half-aggregate publisher, hiding recipient commitments), or are we shipping a zkCoins MVP that deliberately diverges? Decide explicitly. _If divergent_, our `SPEC.md` must rephrase the §14 reference from "Based on" to "Inspired by" and list the divergences (use D1–D11 above).

2. **Max input coins per send.** Plonky2 circuits are fixed-shape. Need a hard ceiling. Suggest 8.

3. **Hash function final choice.** Poseidon over Goldilocks (D=2) is the assumed default, but Robin may have a preference (Poseidon2? PoseidonBN254 for EVM compatibility?). Pin before writing.

4. **Schnorr message hash.** Keep SHA256 (BIP-340-native, secp256k1 wallets compatible) and accept an in-circuit SHA256 gadget? Or move to a Poseidon-friendly signature (EdDSA over Tweedledum etc.)?

5. **Privacy goal**. Are we fixing D2/D10 (hiding recipient commitments) before mainnet, or accepting linkability for v1 and patching later?

6. **Fee model**. Are we shipping without fees (D6) — and if so, how do publishers get paid? Subsidy?

---

## 6. Recommended Sequencing

Assuming the answer to §5.1 is "zkCoins MVP variant for now, paper-fidelity later":

1. **Reconcile `SPEC.md` with this document.** Add a "Divergences from eprint 2025/068" section listing D1–D11 with rationale for each.
2. **New crate `program-plonky2/`** parallel to `program/`. Cargo features `sp1-backend` (default for now) and `plonky2-backend` so we can build both during the transition.
3. **Port `SparseMerkleTree` and `MerkleMountainRange` to Poseidon.** Keep API; replace `hash_concat` (and rename to `hash_node`). Re-run existing 12 tests.
4. **Implement the Plonky2 circuit gadgets.** Smallest first: Poseidon-hash gadget (already in plonky2), then SMT non-inclusion-and-insert gadget, then MMR-append gadget, then SHA256 gadget for Schnorr message hashing.
5. **Build the monolithic `program-plonky2/src/lib.rs` circuit.** Port `program/src/main.rs` assertion-by-assertion. Use `conditionally_verify_cyclic_proof_or_dummy` for the Initial vs. Update branch. Pad `in_coins` to `MAX_IN_COINS`.
6. **Wire the new prover into `script/src/lib.rs`.** Behind the cargo feature flag.
7. **Update `server/src/account_server.rs`** to call the new prover for sends. The on-chain commitment format stays unchanged for v1 (still single Schnorr over `H(asth ‖ ocr)`), so scanner + state don't need to change.
8. **Run the test suite from §13 of SPEC.md + the paper-derived tests from §3 of this doc.** All must pass before merging into `develop`.
9. **Deploy `:beta` to DEV** and verify the wallet round-trips a real send within 1 second of click → proof returned.

Steps 3-5 are the bulk of the work; everything else is wiring.

---

## 7. Local Artifacts

- BitVM/zkCoins reference (cloned): `~/Documents/GitHub/zkcoins/BitVM-zkCoins-reference/`
- Shielded CSV reference implementation files (downloaded by the research agent): `/tmp/shielded_csv_lib.rs`, `/tmp/shielded_csv_primitives.rs`, `/tmp/shielded_csv_node.rs`. **TODO:** clone the full `ShieldedCSV/ShieldedCSV` repo to `~/Documents/GitHub/zkcoins/ShieldedCSV-reference/` if we decide to make it the normative reference (see §5.1).

---

## 8. References

- Shielded CSV paper: https://eprint.iacr.org/2025/068
- Shielded CSV reference implementation: https://github.com/ShieldedCSV/ShieldedCSV
- BitVM/zkCoins Plonky2 prototype: https://github.com/BitVM/zkCoins
- Blockstream blog: https://blog.blockstream.com/bitcoins-shielded-csv-protocol-explained/
- Bitcoin Magazine: https://bitcoinmagazine.com/technical/shielded-csv-protocol
- Plonky2: https://github.com/0xPolygonZero/plonky2
