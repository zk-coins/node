# zkCoins Circuit Specification

This document specifies the zkCoins state-transition circuit (currently implemented for SP1 in `program/src/main.rs`) and the surrounding off-circuit responsibilities. It is **implementation-agnostic**: it does not mandate SP1, SHA256, or any particular proof system. It is intended as a starting point for porting the circuit to other proof systems (e.g. Plonky2 with an algebraic hash such as Poseidon) while preserving protocol semantics.

> **Scope note.** This spec describes the **zkCoins MVP variant** of the Shielded CSV protocol, not the paper as published. It deliberately departs from [eprint 2025/068](https://eprint.iacr.org/2025/068) in 11 concrete ways — see §15 "Divergences from Shielded CSV (paper)" below, and [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md) for full analysis against the upstream reference implementation at [`ShieldedCSV/ShieldedCSV`](https://github.com/ShieldedCSV/ShieldedCSV).
>
> **New here?** Start with [`CONTRIBUTING.md`](./CONTRIBUTING.md) § "Working on the Plonky2 Migration" for the project invariants, decision recipe, and reading order. This spec is the *what*; CONTRIBUTING is the *how to navigate*.

The reference implementation lives in:

- `program/src/lib.rs` — types and pure helpers (compiled both as host and as zkVM guest)
- `program/src/main.rs` — circuit entry point
- `program/src/merkle/sparse_merkle_tree.rs` — SMT
- `program/src/merkle/merkle_mountain_range.rs` — MMR
- `script/src/lib.rs` — host-side SP1 prover wrapper
- `server/src/account_server.rs` — input preparation (host)
- `server/src/state.rs` — global state (SMT + MMR)
- `shared/src/commitment.rs` — Schnorr commitment used to bind a proof to an on-chain inscription

---

## 1. Goal

A zkCoins coin transfer produces a recursive SNARK that proves:

1. The sender's **account state** transition is consistent with the input coins (sum of inputs ≥ sum of outputs, no overflow).
2. Each input coin was produced by a previous valid send proof (recursive verification).
3. Each input coin has not been spent before in this account (non-inclusion in the account's coin history, then inserted).
4. Each input coin's parent commitment is included in the **global commitment history** (so the chain ordering is authoritative).
5. The output coins have deterministic, content-addressed identifiers derived from the next account state.
6. A public `ProofData` summary is committed: the new account state hash, the new output-coins root, the global commitment-history root, and the new coin-history root.

The proof is then "registered" on-chain by publishing a Schnorr commitment over `H(account_state_hash || output_coins_root)` as a Taproot inscription with txid prefix `4242`. The scanner picks up this commitment and inserts it into the global SMT, after which the global MMR root advances.

---

## Glossary

Abbreviations and shorthand used throughout this spec and the surrounding documents (`MIGRATION_RESEARCH.md`, `ROADMAP.md`, `program-plonky2/CONTRIBUTING.md`, source comments).

| Term | Expansion | Meaning |
| ---- | --------- | ------- |
| **asth** | account state hash | `H(AccountState)` — the digest committed by a send proof as its post-state. |
| **ocr** | output coins root | The Merkle root of the SMT containing the send's output coin identifiers. |
| **vk** | verifying key | The proof system's verifier key. In Plonky2 it's the `circuit_digest`; pinned via `add_verifier_data_public_inputs`. |
| **pk** | public key | secp256k1 compressed pubkey, 33 bytes. For account commitments, rotates per send. |
| **SMT** | Sparse Merkle Tree | Binary tree of depth 256 (one level per key bit), used for the per-account coin history, the per-send output coins tree, and the global commitment SMT. |
| **MMR** | Merkle Mountain Range | (Misnomer in this codebase: actually a capacity-doubling padded Merkle tree.) Append-only structure holding the global commitment history. |
| **PCD** | Proof-Carrying Data | Recursive-proof composition abstraction used by the Shielded CSV paper; in Plonky2 we instantiate this with cyclic SNARK recursion. |
| **NIP** | NonInclusionProof | Witness that a key is *not* in an SMT. Two cases off-circuit: case A (empty subtree) and case B (path-compressed sibling leaf). |
| **IP** | InclusionProof | Witness that a key *is* in an SMT, with its associated value. |
| **D1–D11** | Divergences | Numbered list of differences between this implementation and Shielded CSV eprint 2025/068 (`MIGRATION_RESEARCH.md` §3, summarised in SPEC §15). |
| **R1–R6** | Risks | Numbered entries in the ROADMAP risk register. |
| **MAX_IN_COINS** | — | `= 8`. Fixed bound on input coins per send (Plonky2 circuit is fixed-shape; see decision §5.2 in MIGRATION_RESEARCH). |
| **MAX_OUT_COINS** | — | `= 8`. Fixed bound on output coins per send; same fixed-shape rationale as `MAX_IN_COINS`. |
| **TREE_DEPTH** | — | `= 256`. SMT depth (one level per key bit). |
| **Step N** | — | Refers to the corresponding row in ROADMAP's *Status at a Glance* table. |
| **BIP-340** | — | Bitcoin Schnorr signature scheme over secp256k1. The wallet uses BIP-340 to sign `SHA256(serialize(asth) ‖ serialize(ocr))`. |
| **Goldilocks** | — | The 64-bit prime field used by Plonky2 (`p = 2^64 - 2^32 + 1`). |
| **Poseidon** | — | Algebraic hash function we use for all Merkle node hashing and the field-element commitment of `AccountState`. |

---

## 2. Conventions and Types

### 2.1 Hash function

Let `H : bytes → F^n` denote the protocol-wide hash function. In the reference implementation `H` is SHA256 (`HashDigest = [u8; 32]`). In a Plonky2 port, `H` should be an algebraic hash (e.g. Poseidon over the Goldilocks field, output 4 field elements ≡ 256 bits of security with appropriate parameters). Once chosen, `H` MUST be used consistently in:

- All Merkle tree node hashes (`hash_concat`)
- The leaf-encoding rule (see §4.1)
- `AccountState::hash` (account commitment digest)
- `calculate_coin_identifier`
- The "commitment message" hashed before Schnorr signing (`H(account_state_hash || output_coins_root)`)
- The State's MMR-leaf rule (`H(smt_root || prev_mmr_root)`)
- The SMT key-derivation for a Bitcoin pubkey: `key = H(serialize_compressed(pubkey))`

There is **no domain separation between "leaf hashing" and "internal node hashing"** in the SMT today, except that the very bottom leaf is `hash_concat(value, key)` and a domain-separated `hash_leaf(0x00 || data)` is used only for the DEFAULT_HASHES seed. A clean Plonky2 port SHOULD introduce explicit domain separation tags as field-element prefixes to avoid second-preimage ambiguity. See §10 for migration guidance.

### 2.2 Primitive types

| Type            | Meaning                                                                            |
| --------------- | ---------------------------------------------------------------------------------- |
| `HashDigest`    | Output of `H`. Fixed-size byte string (32 bytes for SHA256, 4 field elts for Poseidon). |
| `Address`       | `HashDigest` derived as `H(initial_public_key_bytes)`.                             |
| `Amount`        | `u64`. Coin amounts are non-negative integers; circuit MUST check `checked_add`/`checked_sub`. |
| `PublicKey`     | Compressed secp256k1 pubkey, 33 bytes. Schnorr signatures (BIP-340) use x-only.    |
| `VerifyingKey`  | Identifier of the proof system's verifying key. SP1 uses `[u32; 8]`. Plonky2 would use the circuit's `VerifierOnlyCircuitData` digest. |

### 2.3 Coin identifier rule

```
identifier := H(account_state_hash || u32_be(coin_index))
```

where `account_state_hash` is the **sender's next** account state hash (after balance is decremented but **before** the public key is rotated to `next_public_key`), and `coin_index` is the 0-based index of the coin in the `out_coins` vector. This makes coin identifiers deterministic and content-addressed, which is what allows the circuit to enforce uniqueness and non-malleability without needing a per-coin signature.

---

## 3. Account Model

### 3.1 `AccountState`

```
AccountState {
    owner:      Address          // = H(initial_public_key_bytes), never changes
    balance:    u64
    public_key: PublicKey        // current commitment pubkey (rotates each send)
}
```

`AccountState::hash` MUST be a deterministic, canonical encoding hashed with `H`. The reference uses `bincode::serialize` followed by SHA256; a Plonky2 port SHOULD use a fixed field-element layout: `[owner_limbs..., balance_low, balance_high, pubkey_x_limbs..., pubkey_y_parity]` and a single Poseidon call.

### 3.2 Coin

```
Coin {
    identifier: HashDigest       // = H(sender_next_account_state_hash || u32_be(index))
    recipient:  Address          // recipient's account owner
    amount:     Amount
}
```

### 3.3 Account transitions inside the circuit

- **`apply_coin(coin)`** (used for input coins): assert `coin.recipient == self.owner`, `self.balance = self.balance.checked_add(coin.amount)`. Overflow MUST cause the proof to fail.
- **`send_coins(out_coins, out_proofs, next_public_key)`** (used after applying all input coins):
  - Build the `out_coins_root` by inserting each `out_coin.identifier` into an initially empty SMT, witnessed by a non-inclusion proof per coin. The circuit MUST assert `out_coins_root == current_root` before each insert (i.e. each proof witnesses the running root).
  - Decrement `self.balance` by each coin's amount with `checked_sub`; underflow MUST cause the proof to fail.
  - After all inserts: compute `account_hash := H(self)` and assert `coin.identifier == H(account_hash || u32_be(i))` for every output coin `i`.
  - Finally rotate the account's `public_key` to `next_public_key`.
  - Return `out_coins_root`.

---

## 4. Merkle Structures

### 4.1 Sparse Merkle Tree (SMT)

- **Depth:** `TREE_DEPTH = 256`. The Poseidon-Goldilocks port keeps this — a `HashDigest` is 4 Goldilocks elements × 64 bits = 256 bits when serialised, so 256 levels exactly cover the key's bit space. Implementations on smaller fields (e.g. BabyBear, 31 bits) would pack the key into more limbs but typically keep the depth at 256 (full-key-bit-tree); see `program-plonky2/src/merkle/sparse_merkle_tree.rs::TREE_DEPTH`.
- **Key:** a `HashDigest`. Bit `i` is the MSB-first selector at level `i` (level 0 = root, level `TREE_DEPTH` = leaf).
- **Leaf encoding:** `leaf_hash = H(value || key)`. The `value` is itself a `HashDigest`.
- **Default leaf** at level `TREE_DEPTH`: `H(0x00 || ε)` (domain-separated empty leaf in the reference; Plonky2 SHOULD pick a fixed sentinel field-element constant).
- **Default internal hashes:** `DEFAULT_HASHES[level] = H(DEFAULT_HASHES[level+1] || DEFAULT_HASHES[level+1])`.
- **Inclusion proof** = `(key, siblings[0..TREE_DEPTH])`. Verifier reconstructs the root from `H(value, key)` upwards, using bit `i` of `key` (MSB-first) to decide ordering: bit=0 → `(current, sibling)`, bit=1 → `(sibling, current)`.
- **Non-inclusion proof** = `(key, root, siblings, leaf=(other_key, other_value))`. Two cases:
  1. **Empty subtree case:** `other_key == key` AND `other_value == DEFAULT_HASHES[siblings.len()]`. Verifier hashes that default leaf upwards.
  2. **Occupied sibling case:** `other_key != key` (assert). Verifier hashes `H(other_value, other_key)` upwards along `other_key`'s path. By the SMT invariant this proves no leaf with `key` is present along the same prefix.
- **Insert via non-inclusion proof:** the verifier-and-inserter recomputes the new root by extending the proof with default-hash padding down to the first differing bit between `key` and `other_key`, then hashes both leaves upward. This MUST yield the new root deterministically.

### 4.2 Merkle Mountain Range (MMR)

In the reference this is actually a **fixed-shape padded Merkle tree** with capacity doubling, not a classical MMR. The name is historical; the structure used is simpler.

- Capacity is the next power of two ≥ leaf-count, starting at 2.
- Missing leaves are padded with `ZERO_HASH` (= 32 zero bytes, or the zero field element).
- Internal nodes: `node = H(left || right)`. Missing right siblings are `ZERO_HASH`.
- The root advances when a leaf is appended; capacity doubles when the tree fills (no re-hashing, just resize).
- **Proof** = `(index, path)` where `path[level]` is the sibling at each level from leaf to (level just below) root. Verifier: if `index` is even at this level, `H(current || sibling)`; else `H(sibling || current)`; `index /= 2`.

---

## 5. Global Commitment Format and History

### 5.1 Off-chain "commitment" (`shared::commitment::Commitment`)

A `Commitment` produced by the client is:

```
Commitment {
    public_key: PublicKey                  // commitment pubkey (= account's current pk)
    signature:  Schnorr(BIP-340)           // over msg_hash (see below)
    message:    bytes                      // the raw 32-byte H(asth || ocr) digest (no double-hashing)
}
```

The signed message is `H(account_state_hash || output_coins_root)` where both inputs are `HashDigest`s. If a Plonky2 port keeps SHA256 _here_ for compatibility with secp256k1 Schnorr, that is fine — but the `account_state_hash` and `output_coins_root` operands themselves are produced by `H` and so MUST match the chosen circuit hash. Mismatching the two will break the scanner ↔ circuit link.

### 5.2 Global state (`server::state::State`)

- `smt: SparseMerkleTree` — keyed by `H(serialize_compressed(commitment_pubkey))`, value = `H(account_state_hash || output_coins_root)` (`Commitment::get_account_state_hash()` — misleading name, it's actually the message digest).
- `mmr: MerkleMountainRange` — leaves are `H(smt_root || prev_mmr_root)`.
- `prev_mmr_root: HashDigest` — the MMR root just before the most recent SMT update was folded in.
- `root_indices: Map<prev_mmr_root → (smt_root, leaf_index)>` — host-side lookup, not part of the protocol.

#### `State::update(commitments)`

For each `Commitment c`:

1. `key := H(serialize_compressed(c.public_key))`
2. `value := c.message` (= `H(asth || ocr)`)
3. `smt.insert(key, value)` — fails if key already present with a different value (replay/inconsistency).

After all inserts:

4. `smt_root := smt.root()`
5. `prev_mmr_root := mmr.root()` (capture, then update `self.prev_mmr_root`)
6. `leaf := H(smt_root || prev_mmr_root)`
7. `mmr.append(leaf)`
8. Return `mmr.root()` (the new global commitment-history root).

This is the contract that the scanner enforces, and the circuit's `verify_commitment` / `verify_previous_root` assume.

---

## 6. `CommitmentMerkleProofs`

A bundle of Merkle witnesses linking one **proof** (account or coin) to the current global history root. Provided as a hint to the circuit; the circuit verifies them.

```
CommitmentMerkleProofs {
    commitment_root:                HashDigest      // SMT root containing this commitment
    commitment_proof:               InclusionProof  // proves commitment in that SMT
    commitment_root_history_proof:  MMRProof        // proves SMT root is in the MMR (paired w/ prev_mmr_root)
    commitment_root_mmr_sibling:    HashDigest      // = prev_mmr_root at the time this commitment was folded
    previous_root_history_proof:    (HashDigest, MMRProof)  // proves the previous MMR root is also in the MMR
    commitment_account_state_hash:  HashDigest      // claimed asth, opened
    commitment_out_coins_root:      HashDigest      // claimed ocr, opened
}
```

### Verifier rules

- `commitment_proof.verify(H(commitment_account_state_hash || commitment_out_coins_root), commitment_root)` MUST hold.
- `commitment_root_history_proof.verify(H(commitment_root || commitment_root_mmr_sibling), current_history_root)` MUST hold.
- `previous_root_history_proof.1.verify(H(previous_root_history_proof.0 || prev_proof_history_root), current_history_root)` MUST hold, where `prev_proof_history_root` is the `commitment_history_root` committed by the prior proof we are verifying.

This chain is what enforces **monotonicity of history**: a new proof must extend the same history its inputs came from.

---

## 7. Program Inputs (`ProgramInputs`)

These are passed to the circuit on stdin (SP1) or as private witness (Plonky2). All fields are private witnesses except those re-derived from the public output (`ProofData`).

```
ProgramInputs {
    proof_type:           InitialProof | AccountUpdateProof
    verification_key:     VerifyingKey                          // self-hash for recursion (see §9)
    account_state:        AccountState                           // sender's state BEFORE this send
    current_history_root: HashDigest                             // claimed global MMR root

    // Only present for AccountUpdateProof
    prev_proof_public_values:  Option<ProofData_bytes>           // prior account proof's public output
    prev_proof_history_proofs: Option<CommitmentMerkleProofs>    // witness that prior proof was committed on-chain

    // Per input coin (in_coins[i])
    in_coins:                              [Coin]
    in_coin_proofs_public_values:          [ProofData_bytes]     // each coin's source proof public output
    in_coin_proofs_history_proofs:         [CommitmentMerkleProofs]  // witnesses each source proof was committed
    in_coin_proofs_non_inclusion_proofs:   [NonInclusionProof]       // witnesses each coin is unseen in own coin_history
    in_coins_inclusion_proofs:             [InclusionProof]          // witnesses each coin is in source's out_coins_root

    // Outputs
    out_coins:        [Coin]
    out_coin_proofs:  [NonInclusionProof]   // running non-inclusion proofs into the new (initially empty) out_coins_tree
    next_public_key:  PublicKey             // sender's rotated key
}
```

For the recursive proofs (`prev_proof_public_values` and each `in_coin_proofs_public_values`), the host MUST also supply the actual recursive proof artifact (in SP1: `SP1Stdin::write_proof`). In Plonky2 these become `ProofWithPublicInputsTarget`s and are verified by `verify_proof::<C>(...)` against a fixed `verifier_data` digest.

---

## 8. Circuit Logic

The circuit reads `ProgramInputs`, performs all asserts and field updates, and commits a single `ProofData` as public output.

```
fn main(inputs: ProgramInputs):
    vk            := inputs.verification_key
    account_state := inputs.account_state          // mutable local
    history_root  := inputs.current_history_root

    // 1. Coin-history root: either default (initial proof) or carried from prev account proof.
    coin_history_root := match inputs.proof_type:
        InitialProof:
            // Mint exception: the special MINTING_ADDRESS may have any starting balance.
            if account_state.owner != MINTING_ADDRESS:
                assert account_state.balance == 0
            DEFAULT_HASHES[0]

        AccountUpdateProof:
            // Recursively verify the previous account proof.
            prev := verify_proof(inputs.prev_proof_public_values, vk)
            assert vk == prev.vk                                              // (a) same circuit
            assert account_state.hash() == prev.account_state_hash           // (b) state continuity
            mp := inputs.prev_proof_history_proofs
            assert account_state.hash() == mp.commitment_account_state_hash  // (c) opening matches witness
            assert mp.verify_commitment(history_root)                        // (d) commitment in history
            assert mp.verify_previous_root(prev.commitment_history_root, history_root)  // (e) extends prior history
            prev.coin_history_root

    // 2. Apply each input coin (in order).
    for (i, coin) in inputs.in_coins.iter().enumerate():
        cp := verify_proof(inputs.in_coin_proofs_public_values[i], vk)        // recursive
        assert vk == cp.vk
        // Source's out_coins_root must contain this coin.
        assert inputs.in_coins_inclusion_proofs[i].verify(coin.identifier, cp.output_coins_root)
        // Source's commitment must be in the global history.
        mp := inputs.in_coin_proofs_history_proofs[i]
        assert cp.output_coins_root == mp.commitment_out_coins_root
        assert mp.verify_commitment(history_root)
        assert mp.verify_previous_root(cp.commitment_history_root, history_root)
        // Coin must be unseen in own coin_history and inserted there.
        nip := inputs.in_coin_proofs_non_inclusion_proofs[i]
        assert coin_history_root == nip.root
        coin_history_root := nip.verify_and_insert(coin.identifier)
        account_state := account_state.apply_coin(coin)                       // assert recipient == owner, checked_add

    // 3. Build new out_coins_root and rotate pubkey.
    out_coins_root := account_state.send_coins(
        inputs.out_coins, inputs.out_coin_proofs, inputs.next_public_key
    )
    // send_coins internally:
    //   - For each (out_coin, ncl_proof):
    //         assert out_coins_root_running == ncl_proof.root
    //         out_coins_root_running := ncl_proof.insert(out_coin.identifier)
    //         balance := balance.checked_sub(out_coin.amount)        // assert no underflow
    //   - Compute account_hash := H(account_state)
    //   - For each (i, out_coin):
    //         assert out_coin.identifier == H(account_hash || u32_be(i))
    //   - account_state.public_key := next_public_key

    // 4. Commit public output.
    commit(ProofData {
        vk:                       vk,
        account_state_hash:       account_state.hash(),
        output_coins_root:        out_coins_root,
        commitment_history_root:  history_root,
        coin_history_root:        coin_history_root,
    })
```

### Note on the minting account

`MINTING_ADDRESS` is a `HashDigest` constant. In the SP1/SHA256 build it is a hard-coded `[u8; 32]` (the SHA256 of a fixed pubkey, see `program/src/lib.rs`). In the Plonky2/Poseidon build it is currently a domain-separated placeholder (`hash_bytes(b"zkcoins:minting-address:placeholder:v1")`, see `program-plonky2/src/types.rs::MINTING_ADDRESS`); the server will replace it with `hash_bytes(serialize(real_minting_pubkey))` when wiring step 7. The minting key itself is generated fresh per backend — the closed test environment means we are not bound to the SP1 minting key.

---

## 9. Public Output (`ProofData`)

```
ProofData {
    vk:                      VerifyingKey
    account_state_hash:      HashDigest
    output_coins_root:       HashDigest
    commitment_history_root: HashDigest
    coin_history_root:       HashDigest
}
```

`vk` is the **circuit's own verifying-key digest**. It's used to enforce that a recursively verified proof was generated by the exact same circuit (preventing a different circuit from forging public values).

In SP1 this is `vk.hash_u32()` (the verifying key reduced to `[u32; 8]`). In Plonky2 the standard pattern is to pass a public input that pins `verifier_data.circuit_digest`. The host MUST hard-code this digest in the on-chain protocol params and the scanner.

---

## 10. Recursion Contract

The circuit verifies recursive proofs of itself. Two requirements:

1. **Same circuit:** every recursively verified proof's `vk` field MUST equal the verifier's own `vk`.
2. **Public-value binding:** when verifying a recursive proof, the verifier MUST bind the entire `ProofData` it just consumed (`account_state_hash`, `output_coins_root`, `commitment_history_root`, `coin_history_root`) into the rest of the circuit logic. In SP1 this is automatic via `sp1_zkvm::lib::verify::verify_sp1_proof(&vkey, &public_values_digest)`. In Plonky2 this requires connecting each public input of the recursive `ProofTarget` to the corresponding local target.

For the **initial proof** there is no prior account proof to verify. The circuit takes the `InitialProof` branch, asserts `balance == 0` (except for `MINTING_ADDRESS`), and seeds `coin_history_root` with `DEFAULT_HASHES[0]`.

---

## 11. Off-Circuit Responsibilities

### 11.1 Server (`server::account_server::send_coins`)

1. Look up the sender's `Account` (its coin queue, prior account proof, and own coin_history SMT).
2. For each queued `CoinProof`:
   - Build a `CommitmentMerkleProofs` for the **coin's source proof** (witness it's on-chain).
   - Build a `NonInclusionProof` against the account's own coin_history (proves replay safety) and insert into it.
   - Carry over the per-coin `InclusionProof` (the proof that the coin was in its source's `out_coins_root`).
3. Build the `out_coins` from invoices, with deterministic identifiers derived from the **next** account state hash.
4. Build per-out-coin running `NonInclusionProof`s against an empty SMT.
5. If a prior account proof exists, build a `CommitmentMerkleProofs` for it and choose `AccountUpdateProof`; else choose `InitialProof`.
6. Call the prover. On success: persist the proof, clear `coin_queue`, set `balance := balance + queued_balance - invoiced_amount`, store the proof as the new `account.proof`.
7. Return the `CoinProof`s (one per output coin), each containing the new proof + inclusion proof into the new `out_coins_root`. The recipient client later POSTs these to `/api/receive`.

### 11.2 Client (`shared::ClientAccount::create_commitment`)

Given a fresh server response `(proof_id, account_state_hash, output_coins_root)`:

1. Sign `H(account_state_hash || output_coins_root)` with the **current** commitment private key (BIP-32 derivation index = `num_pubkeys - 1` in the reference).
2. POST `(proof_id, commitment)` to `/api/commit`. The server attaches this commitment to the proof, builds a Taproot commit+reveal tx pair whose commit-tx txid begins with `4242`, and broadcasts.

### 11.3 Scanner (`server::scanner`)

1. Poll Esplora (or any Bitcoin tx source).
2. Filter txs whose txid hex starts with `4242`.
3. Extract Taproot inscription payload (`extract_inscription_content`).
4. Deserialize as `Commitment`.
5. Verify the Schnorr signature (`Commitment::verify`).
6. Forward to `State::update([commitment])` and persist `latest_block`.

The block height/order is implicitly authoritative: whoever lands first in the SMT wins. Replay is prevented by the SMT's reject-on-duplicate-key rule.

---

## 12. Migration Notes: Porting to Plonky2 + Poseidon

This list captures the non-trivial decisions a port must make. None of them are optional.

1. **Pick `H`.** Recommended: Poseidon over Goldilocks (`F = GF(2^64 - 2^32 + 1)`), width 12, full+partial rounds per the standard parameter set. `HashDigest` becomes 4 field elements (≡ 256-bit security with appropriate rate).

2. **Re-derive `MINTING_ADDRESS`.** Plonky2 port has it as a domain-separated placeholder (`program-plonky2/src/types.rs::MINTING_ADDRESS`). Step 7 of `ROADMAP.md` is when the server generates a fresh minting keypair and replaces the placeholder with `hash_bytes(serialize(real_minting_pubkey))`. Closed test environment — see `MIGRATION_RESEARCH.md` §7 — means no requirement to match the SP1 minting key.

3. **`AccountState` hashing.** Drop `bincode + SHA256`. Define a canonical field-element layout (e.g. `[owner_limbs(4), balance_lo, balance_hi, pubkey_x_limbs(4), pubkey_parity]`) and hash with Poseidon. Both circuit and host MUST agree.

4. **SMT depth.** Set `TREE_DEPTH` to the bit-length of `HashDigest` in the new field. For Poseidon-256 over Goldilocks treated as 4×64-bit limbs, you can either keep depth 256 (key = bits of all 4 limbs) or move to a smaller depth and accept a tiny non-injectivity probability (not recommended). Recommended: keep 256 with explicit big-endian limb ordering.

5. **Add domain separation.** Replace the current leaf rule `H(value, key)` and internal-node rule `H(left, right)` with tagged variants: `H(LEAF_TAG, value, key)` and `H(NODE_TAG, left, right)`. This is essentially free in algebraic-hash circuits and removes a class of second-preimage edge cases the SHA256 version papers over.

6. **Schnorr message hashing.** secp256k1 BIP-340 Schnorr signs SHA256(msg). You have two choices:
   - **Keep secp256k1 + SHA256 for the signature only.** The signed *message* becomes `SHA256(account_state_hash || output_coins_root)` where `account_state_hash` and `output_coins_root` are 32-byte serializations of Poseidon outputs. This keeps wallet UX and Bitcoin-native signing unchanged.
   - **Switch to an in-circuit-friendly signature** (e.g. EdDSA over a Plonky2-friendly curve). Cheaper to verify in-circuit, but breaks Bitcoin-native key reuse.
   For an MVP, keep option (1).

7. **Verifying-key binding.** Replace `vk: [u32; 8]` with the Plonky2 `circuit_digest` (a `HashOut`). Bind this as a public input on every recursive verification step.

8. **Public-value serialization.** SP1's `bincode::serialize(&ProofData)` doesn't apply. Define `ProofData` as a flat array of field elements committed in order. The hash committed by `verify_proof` is the Poseidon hash of those public inputs.

9. **MMR `ZERO_HASH`.** Replace with the zero field element (or the additive identity in the chosen group). Adjust `DEFAULT_HASHES` derivation accordingly.

10. **`u32_be(coin_index)` in identifier.** Replace with one field element (range-checked to `< 2^32`) for in-circuit efficiency.

11. **Number-of-input-coins bound.** SP1 lets `in_coins.len()` be dynamic at proving time. Plonky2 circuits are fixed-shape — pick a max (e.g. 8 input coins per send, padded with dummy "amount = 0" coins). The circuit MUST treat amount-zero coins as no-ops (skip non-inclusion insertion, skip apply, but still consume one slot of fixed-size arrays).

12. **No `panic!`, no `expect!`.** In Plonky2 every "fail the proof" path becomes a constraint. Replace `Result<_, &'static str>` host code with explicit asserts inside the circuit. Note in particular: `checked_add`/`checked_sub`/`balance == 0`/`recipient == owner`/`coin.identifier == expected_identifier`.

13. **Don't trust the `verify_previous_root` shortcut in the host.** `account_server.rs::get_merkle_proofs` currently has a `let _ = proofs.verify_previous_root(...)` comment claiming it's redundant. That assumption holds only because the SP1 circuit re-checks it. The Plonky2 circuit MUST also re-check it.

---

## 13. Invariants the Tests Should Encode

A test-suite for the ported circuit MUST cover at minimum:

- **Initial proof, non-mint, balance != 0** → proof rejected.
- **Initial proof, mint** → proof accepted; coin_history_root is `DEFAULT_HASHES[0]`.
- **Account update, mismatched `account_state.hash()` vs prev `account_state_hash`** → rejected.
- **Account update, prev's `commitment_history_root` not in current MMR** → rejected.
- **Input coin whose source-proof is not in commitment history** → rejected.
- **Input coin whose identifier is not in source's `output_coins_root`** → rejected.
- **Double-spend: same input coin twice in coin_history** → rejected.
- **Output coin with `identifier != H(account_hash || index)`** → rejected.
- **Sum of outputs > balance + sum of inputs** → rejected (underflow).
- **Overflow on sum of input amounts** → rejected.
- **Wrong `vk` on recursive proof** → rejected.

---

## 14. References

- Shielded CSV paper — Jonas Nick, Liam Eagen, Robin Linus. https://eprint.iacr.org/2025/068
- Shielded CSV reference implementation (normative) — https://github.com/ShieldedCSV/ShieldedCSV
- `BitVM/zkCoins` Plonky2 prototype (IVC scaffold only) — https://github.com/BitVM/zkCoins
- Current SP1 implementation — this repository, `program/src/main.rs`
- Migration research and divergence analysis — [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md)

---

## 15. Divergences from Shielded CSV (paper)

This implementation differs from the published Shielded CSV protocol in 11 concrete ways. Each is either a deliberate MVP simplification, a deferred feature, or a privacy/soundness gap that must be closed before mainnet. The detailed analysis lives in [`MIGRATION_RESEARCH.md`](./MIGRATION_RESEARCH.md) §3. Summary table:

| #   | This SPEC                                                            | Paper                                                                    | Class            | Status               |
| --- | -------------------------------------------------------------------- | ------------------------------------------------------------------------ | ---------------- | -------------------- |
| D1  | `identifier = H(asth ‖ u32_be(idx))` (32 B)                          | `CoinID = tx_hash ‖ idx` (34 B), `CoinIDOnChain = blockchain_loc ‖ idx` (8 B) | Architectural    | Accepted for MVP     |
| D2  | `Coin.recipient = Address` (plaintext)                              | `coin.essence.address = Commitment::commit(acct_id, rand)` (hiding)      | **Privacy**      | **Must fix pre-mainnet** |
| D3  | Single Schnorr commitment in Taproot inscription, txid prefix `4242` | Half-aggregate BIP-340 Schnorr `AggregateNullifier` via third-party publishers | Architectural    | Accepted for MVP     |
| D4  | Global state = SMT(`H(pk)` → `H(asth ‖ ocr)`) + MMR over `H(smt_root ‖ prev_mmr_root)` | `ToSAcc` tuple-of-sets over `(pk, sig_comm, blockchain_loc, fee_acct_comm)` with prefix proofs | Architectural    | Discuss with Robin   |
| D5  | SMT depth 256, hash-keyed (uniform)                                  | `AccM` lex-ordered by `CoinIDOnChain` for subtree pruning                | Scalability      | Re-evaluate at scale |
| D6  | No fee field, no fee output                                          | `fee: u64` + `FEE_IDX = 0xffff` reserved coin index for publisher payout | Missing feature  | Deferred             |
| D7  | No conditional-noop on reorg                                         | `conditional_nav` degrades tx to no-op if claimed nullifier-accum no longer prefix | **Reorg safety** | **Must fix pre-mainnet** |
| D8  | `Coin` carries no `nullifier_accum` snapshot                         | `Coin` carries snapshot; receiver verifies it's in their local history  | **Soundness**    | **Must fix pre-mainnet** |
| D9  | No range/uniqueness checks on `coin_index`                           | `idx` strictly increasing within tx; `idx == FEE_IDX` reserved          | Soundness        | Cheap fix            |
| D10 | `apply_coin` checks `coin.recipient == self.owner` plaintext         | Opens `Commitment::commit(acct_id, rand)` with witnessed `acct_comm_rand` | **Privacy**      | **Tied to D2**       |
| D11 | `MINTING_ADDRESS` hard-coded                                         | `payment_init_newacct` for fresh accounts; `issuance(IssuanceProof)` branch | Architectural    | Deferred             |

**Bottom line:** D2/D10, D7, D8 are blockers for mainnet (privacy + soundness + reorg safety). D6 is a UX/economics blocker (no fee → no publisher incentive). The rest are documented departures from paper fidelity that the MVP accepts.
