# Bridge MVP — Engineering Spec

**Status:** Engineering specification. No code yet. Companion to
[`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md) (strategy / landscape) and
[`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) (LN swap layer).

**Authoritative source for:** the MVP scope, the locked technical
decisions, the implementation order, the test plan, and the
non-goals.

**Audience:** The engineers implementing the MVP. This is the
file-by-file, phase-by-phase plan; it presupposes the strategic
decisions made in `BITVM_BRIDGE.md` §12–§13.

> **Branch note.** This document presupposes the Plonky2 migration
> currently on `feat/plonky2-migration` (PR #17). `SPEC.md`,
> `MIGRATION_RESEARCH.md`, and `ROADMAP.md` live on that branch and
> will resolve on `develop` only after PR #17 lands. Until then, view
> cross-references against `feat/plonky2-migration`.

---

## 1. Scope

This document specifies the **MVP engineering plan** for a trustless
BTC ↔ zkCoins bridge. It covers:

- The MVP definition (what's in, what's deferred)
- Three locked technical decisions
- An eight-phase implementation plan, file-by-file
- The test plan per phase
- A risk register
- Open implementation questions

**MVP goal:** the *technology* is built. The federation is initially
**3 nodes in the same data centre, all operated by a single
organisation**. This proves the cryptographic and protocol-level
correctness of the bridge mechanism. The same code, with a 5–15
node federation of independent organisations, becomes a real
trustless bridge — that deployment is a separate operational
concern, not an engineering one.

It does **not** cover:

- Federation member recruitment (business-development; out of scope)
- Production hardening beyond the 100%-coverage MVP gate
- Operational runbooks for federation operators
- BitVM3 / Glock / Mosaic implementations (deferred per
  `BITVM_BRIDGE.md` §13 hedging strategy)

---

## 2. MVP Definition

Per `feedback_zkcoins_mvp_definition`, MVP means **minimal feature
surface** AND **100% test coverage on the activated surface**, both
non-negotiable.

### 2.1 In scope

- **Peg-in flow:** user deposits BTC, receives a freshly minted
  zkCoin to a specified `recipient` address
- **Peg-out flow:** user burns a zkCoin, receives BTC to a specified
  L1 address, fronted by an operator with later reimbursement
- **N-of-N MuSig2 federation** with N=3 nodes (configurable; tested
  with N=3 in MVP)
- **Cooperative key-path spending** for the funded vault UTXO when
  all signers cooperate (most peg-ins)
- **Operator-fronted payouts** with KickOff / Challenge /
  Assert / Disprove state machine
- **Bitcoin Light Client gadget** for verifying that a deposit is in
  the canonical chain at depth ≥ 6
- **Fraud-proof game** (BitVM2-style) — full implementation, even if
  in MVP the only adversary is a test fixture
- **End-to-end integration test** on Bitcoin signet (preferable to
  regtest because of more realistic block timing; regtest is
  fallback)

### 2.2 Deferred

- Glock / Mosaic backends (after Plonky2 → Groth16 wrapping is solid
  for BitVM2, swap is mechanical)
- BTC denomination flexibility (MVP: fixed denominations e.g.
  0.01 BTC, 0.1 BTC, 1 BTC)
- Watchtower payment incentives (MVP: watchtowers are part of the
  3-node federation, paid out-of-band)
- Multi-coin peg-outs in a single burn (MVP: one burn per peg-out)
- Production trusted setup ceremony (MVP: single-contributor SRS
  marked "DO NOT USE IN PRODUCTION")
- **Federation scaling beyond N=3.** Target federation size for the
  production bridge is **N=100 independent members** with a 1-of-N
  setup-honesty assumption (1 honest key deletion suffices). N=100
  is the practical upper bound of BitVM2's framework today per
  Bitlayer's analysis (*"in practice the value of n can be 100"*).
  Beyond N=100 is open research and not a current goal. Intermediate
  milestones expected: N=10 → N=30 → N=100. Each step is a separate
  setup ceremony with all new members. Federation-member recruitment
  is a business-development concern, not engineering, and out of MVP
  scope.

### 2.3 Out of scope (post-MVP, may need separate spec)

- Liquid-style federated bridge as interim before BitVM2
- Bridge upgrade to Glock or Mosaic
- Cross-bridge interoperability (peg-out from this bridge to peg-in
  to another)
- Privacy upgrades for peg-in / peg-out (the user's L1 BTC address
  is visible by construction; mitigations in `BITVM_BRIDGE.md` §9.3
  are out of MVP scope)

---

## 3. Locked Technical Decisions

These are fixed for v1. Reversing any of them means a non-trivial
re-design.

### 3.1 Bridge construction: BitVM2 (Citrea-Clementine style)

- Mainnet-deployed (Citrea since 2026-01-27)
- Reusable tooling (`chainwayxyz/bitvm-zk-verifier`)
- 1-of-N honesty trust model
- Trade-off: ~2.6 MB Assert transaction, vs. 5 kB with Glock

Glock and Mosaic are **explicitly deferred** to a future bridge-version-2.
The MVP abstracts the verifier behind a trait so that switching is a
later config change.

### 3.2 Bitcoin Light Client: recursive Plonky2 sub-proof

A separate Plonky2 circuit verifies a chain of Bitcoin headers
(SHA256d + target-bits) and outputs `(tip_hash, cumulative_work)`. The
`IssuanceProof` branch then **recursively verifies** that
light-client proof and asserts that a specific UTXO (txid, vout, amount)
is in a block whose header is part of the verified chain at depth
≥ 6.

This is preferred over inlining SHA256d directly into the `IssuanceProof`
circuit because:

- SHA256d in Plonky2 ≈ 262k gates per hash; 6 confirms ≈ 3M gates
  extra per IssuanceProof — sub-second budget broken
- Recursive verification cost is approximately constant once
  warmed up
- The light-client sub-proof is reusable for other future use cases
  (e.g., zkCoins-side observation of arbitrary Bitcoin events)

### 3.3 Trusted setup for Groth16 wrapping: single-contributor SRS for MVP

- The Plonky2 → Groth16 wrapper requires a Groth16 trusted setup
- For MVP with N=3 single-operator nodes, a single-contributor SRS
  is acceptable: every node already trusts the others (same operator)
- The SRS file is committed to the repo with a clear marker:
  ```
  ⚠️  DO NOT USE IN PRODUCTION
  This SRS was generated by a single contributor for MVP testing.
  Replace before any multi-organisation federation deployment.
  ```
- Replacement: ~30–60 contributor ceremony before the first real
  federation deployment. Tooling reused from Citrea's open-source
  ceremony software.

---

## 4. Phase 1 — Circuit Extension (`IssuanceProof` + `BurnProof`)

### 4.1 Goal

Add two new `ProofType` variants to the state-transition circuit,
implementing the Shielded-CSV-paper-aligned `issuance(IssuanceProof)`
and the new `BurnProof` branches.

### 4.2 Files touched

| File | Change |
| ---- | ------ |
| `program-plonky2/src/types.rs` | Extend `ProofType` enum with `Issuance` and `Burn` variants; extend `ProofData` with optional fields for issuance/burn metadata |
| `program-plonky2/src/inputs.rs` | Extend `ProgramInputs` with `peg_in_witness: Option<PegInWitness>` and `burn_witness: Option<BurnWitness>` fields |
| `program-plonky2/src/circuit/issuance.rs` | **new** — `IssuanceProof` circuit branch |
| `program-plonky2/src/circuit/burn.rs` | **new** — `BurnProof` circuit branch |
| `program-plonky2/src/circuit/main.rs` | Extend `conditionally_verify_cyclic_proof_or_dummy` dispatch to handle Initial / AccountUpdate / Issuance / Burn |
| `program-plonky2/src/circuit/mod.rs` | Wire in new modules |

### 4.3 IssuanceProof predicate

The circuit asserts:

```
Given:
  account_state:        AccountState (new account, owner = recipient address)
  peg_in_witness:       PegInWitness { lcp_proof, utxo_outpoint, amount, recipient_commitment }
  prev_peg_in_consumed_root: HashDigest
  new_peg_in_consumed_root:  HashDigest
  non_inclusion_proof:  NonInclusionProof of peg-in into peg_in_consumed_smt

Asserts:
  1. lcp_proof.verify(verifier_data_bitcoin_lcp) — recursive Plonky2 verify
     of the Bitcoin Light Client sub-proof
  2. utxo_outpoint is included in lcp_proof.confirmed_utxos at depth ≥ 6
  3. peg_in_witness.amount equals the UTXO's amount
  4. peg_in_witness.recipient_commitment matches the user's intended
     zkCoins address (binding: witness commitment in the Taproot leaf
     of the deposit script hashes to recipient_commitment)
  5. account_state.balance == amount − bridge_fee_constant
  6. account_state.owner == recipient_commitment.address
  7. non_inclusion_proof.verify(utxo_outpoint, prev_peg_in_consumed_root)
  8. non_inclusion_proof.insert(utxo_outpoint) == new_peg_in_consumed_root
  9. Emit ProofData with new state and the new peg_in_consumed_root

Result: a new account with the deposit amount minus fees, provably
backed by a confirmed on-chain UTXO that cannot be reused.
```

### 4.4 BurnProof predicate

```
Given:
  account_state:           AccountState (existing account, has coins)
  in_coins:                Vec<Coin> (coins being burned; sum_amount = burn_amount)
  in_coins_inclusion_proofs: inclusion proofs for each in_coin
  in_coins_history_proofs: same as for normal AccountUpdate
  burn_witness:            BurnWitness { btc_recipient_address, withdrawal_nonce }
  prev_burned_coins_root:  HashDigest
  new_burned_coins_root:   HashDigest
  burn_insert_proofs:      NonInclusionProof per in_coin into burned_coins_smt

Asserts:
  1. Each in_coin is verified the same way as in AccountUpdate
     (source-proof inclusion, history-root containment, coin-history
     non-inclusion + insert)
  2. account_state.balance is decremented by sum(in_coin.amount) using
     checked_sub
  3. burn_witness.withdrawal_nonce is fresh (not in withdrawal_nonces_smt;
     inserted as part of this proof — or alternatively: nonce is the
     hash of the burn proof's public values, deterministic uniqueness)
  4. Each in_coin.identifier is inserted into burned_coins_smt via
     burn_insert_proofs, producing new_burned_coins_root
  5. No new out_coins are created
  6. account_state.public_key is rotated to next_public_key (same as
     normal send)
  7. Emit ProofData including burn_amount, btc_recipient, and
     withdrawal_nonce as part of public values

Result: the coins are consumed; the bridge can use the public output
to construct a Bitcoin Payout transaction to the burner.
```

### 4.5 New types

```rust
// program-plonky2/src/types.rs additions

pub enum ProofType {
    InitialProof,
    AccountUpdateProof,
    IssuanceProof,    // NEW
    BurnProof,        // NEW
}

pub struct PegInWitness {
    pub lcp_proof: Plonky2ProofTarget,           // recursive LCP proof
    pub utxo_txid: HashDigest,
    pub utxo_vout: u32,
    pub utxo_amount: u64,
    pub recipient_commitment: RecipientCommitment,
}

pub struct RecipientCommitment {
    pub address: Address,            // = H(initial_pubkey)
    pub randomness: HashDigest,      // hiding commitment randomness; even
                                     // for plaintext-recipient MVP we
                                     // carry this for forward-compat
                                     // with D2/D10
}

pub struct BurnWitness {
    pub btc_recipient_address: [u8; 32],  // Bitcoin address (Taproot)
    pub withdrawal_nonce: HashDigest,
}
```

### 4.6 Test plan (Phase 1)

Per `feedback_zkcoins_mvp_definition`, 100% coverage gate applies.

Positive:
- **IssuanceProof base case:** valid LCP, valid UTXO, fresh
  non-inclusion → proof accepts; ProofData contains new state with
  amount − fee.
- **IssuanceProof for second user:** second peg-in to a different
  account with a different UTXO → still accepts, peg_in_consumed_smt
  grows correctly.
- **BurnProof single coin:** burn one input coin → accepts; output
  has zero out_coins; account.balance decremented; coin in
  burned_coins_smt.
- **BurnProof multiple coins:** burn two input coins summing to
  burn_amount → accepts; both in burned_coins_smt.
- **IssuanceProof then BurnProof for same account:** full mint → burn
  cycle.

Negative (each is a separate test, must assert `data.prove(pw).is_err()`):
- **IssuanceProof with invalid LCP:** rejected.
- **IssuanceProof with UTXO at depth < 6:** rejected.
- **IssuanceProof with amount mismatch:** account claims amount ≠ UTXO
  amount → rejected.
- **IssuanceProof with recipient mismatch:** account.owner ≠
  recipient_commitment.address → rejected.
- **IssuanceProof reusing a peg-in:** second IssuanceProof with same
  utxo_outpoint → non-inclusion check fails → rejected.
- **BurnProof with wrong coin source:** in_coin not in source's
  out_coins_root → rejected.
- **BurnProof with double-burn:** burn the same coin twice → second
  attempt's insert into burned_coins_smt fails → rejected.
- **BurnProof with wrong balance update:** account.balance not
  decremented correctly → rejected.

Estimated effort: **3–4 weeks**, risk medium (first time defining
new ProofType variants; recursive LCP verification needs Phase 2
to be at least partially done).

---

## 5. Phase 2 — Bitcoin Light Client Gadget

### 5.1 Goal

A Plonky2 circuit that, given a chain of Bitcoin block headers,
verifies that:

- Each header's hash satisfies its target (proof-of-work valid)
- Each header chains correctly to the previous one (prev_block_hash
  match)
- The cumulative work is computed correctly
- A claimed UTXO is included in a transaction in one of the headers
  via Merkle proof against the header's `merkle_root`

### 5.2 Files touched

| File | Change |
| ---- | ------ |
| `program-plonky2/src/circuit/lcp/mod.rs` | **new** — light client proof module |
| `program-plonky2/src/circuit/lcp/header.rs` | **new** — single-header verify (SHA256d + target) |
| `program-plonky2/src/circuit/lcp/chain.rs` | **new** — multi-header chain verify with cumulative work |
| `program-plonky2/src/circuit/lcp/spv.rs` | **new** — SPV/Merkle inclusion of a tx in a block |
| `program-plonky2/src/circuit/lcp/main.rs` | **new** — top-level LCP circuit; outputs (tip_hash, cumulative_work, confirmed_utxos_root) |
| `program-plonky2/src/circuit/sha256.rs` | **new** — Plonky2 SHA256 gadget (or import from polymerdao/plonky2-sha256) |

### 5.3 SHA256 gadget — buy or build

**Option A: import [polymerdao/plonky2-sha256](https://github.com/polymerdao/plonky2-sha256).**

- Pros: existing implementation, known working
- Cons: dependency on a third-party crate; older Plonky2 version
  (0.2.0, our codebase is on 1.1.0); ~262k gates per hash
- Action: fork into our tree, upgrade to 1.1.0, vendor as a sub-module

**Option B: write our own.**

- Pros: full control, matches our coverage standards
- Cons: 1–2 weeks of high-precision arithmetic-circuit work; SHA256
  bit-twiddling is error-prone
- Action: only if Option A's upgrade to 1.1.0 turns out to be > 1 week

→ **Default: Option A.** Fork to `program-plonky2/src/circuit/sha256/`
   and upgrade in-place.

### 5.4 LCP public output

```rust
pub struct LCPPublicValues {
    pub tip_block_hash:       HashDigest,
    pub cumulative_work:      [u32; 8],          // 256-bit big-int
    pub starting_block_hash:  HashDigest,        // genesis or last-checkpoint
    pub confirmed_utxos_root: HashDigest,        // Merkle root of all UTXOs
                                                 // proven via SPV in this proof
}
```

The `confirmed_utxos_root` is the SMT root of all UTXOs the LCP claims
are confirmed. When the `IssuanceProof` recursively verifies the LCP,
it checks one specific UTXO's inclusion in this root.

### 5.5 Block-batch sizing

Naïve LCP verifies the full Bitcoin chain from genesis on every
issuance — infeasible (~750k blocks as of 2026). Real solutions:

- **Checkpointed LCP:** the circuit starts from a hard-coded
  checkpoint block hash, verifies only blocks since the checkpoint.
  Checkpoint updated by federation governance periodically.
- **Recursive accumulating LCP:** each LCP proof verifies the previous
  LCP proof and extends it. The "tip" of the chain advances as new
  blocks come in. New peg-ins use the current LCP proof.

→ **MVP: checkpointed LCP.** The checkpoint is updated weekly by
the bridge operator; this is acceptable because the bridge trusts
its own operator to advance the checkpoint, not for security but
for liveness. Security comes from the SHA256d/target verification
covering all post-checkpoint blocks.

### 5.6 Test plan (Phase 2)

Positive:
- **Single block:** verify one valid header → accepts; cumulative
  work matches expected.
- **Chain of 6 blocks:** verify a sequence; tip_hash and
  cumulative_work computed correctly.
- **SPV inclusion:** verify a tx is in a block's Merkle tree.
- **Recursive LCP:** prove LCP_1, then prove LCP_2 = LCP_1 +
  extension; the recursive proof accepts.

Negative:
- **Invalid PoW:** header hash > target → rejected.
- **Broken chain:** header[N].prev_block_hash ≠ hash(header[N−1]) →
  rejected.
- **Wrong cumulative work:** off-by-one error in difficulty
  accumulation → rejected.
- **Wrong SPV:** Merkle proof with wrong sibling → rejected.

Estimated effort: **3–5 weeks**, risk **high** for two reasons:

- SHA256d performance in Plonky2 — if proving time blows up despite
  recursive sub-proofs, we may need to look at Plonky3 (Poseidon2 is
  also faster but doesn't help with SHA256d; the only mitigation is
  a smaller block batch per recursive step)
- First time integrating an external proof system component (SHA256
  gadget) — version compatibility risk

---

## 6. Phase 3 — State Extension

### 6.1 Goal

Extend `server::state::State` to track peg-in consumption,
burn records, and pending payouts.

### 6.2 Files touched

| File | Change |
| ---- | ------ |
| `server/src/state.rs` | Add 3 new fields, persist/load, expose query methods |
| `server/src/state_tests.rs` | Tests for new state operations |

### 6.3 New fields

```rust
struct State {
    // existing fields unchanged: smt, mmr, prev_mmr_root, root_indices
    
    pub peg_in_consumed_smt:   SparseMerkleTree,  // key = utxo_outpoint hash
                                                  // value = peg-in metadata hash
    pub burned_coins_smt:      SparseMerkleTree,  // key = coin.identifier
                                                  // value = burn metadata hash
    pub pending_payouts:       BTreeMap<HashDigest, PendingPayout>,
                                                  // key = withdrawal_nonce
}

struct PendingPayout {
    pub burn_proof_id:    ProofId,
    pub btc_recipient:    [u8; 32],
    pub amount:           u64,
    pub status:           PayoutStatus,
    pub assigned_operator: Option<OperatorId>,
    pub created_block:    u64,        // signet block height at burn-inscription
}

enum PayoutStatus {
    PendingAssignment,
    Assigned,
    Fronted { payout_txid: HashDigest, kickoff_txid: Option<HashDigest> },
    Completed,
    TimedOut,           // operator did not front within 64 blocks; ready for re-assignment
    Disputed { challenge_txid: HashDigest },
    Slashed,
}
```

### 6.4 Persistence

Follow the existing pattern in `server/src/state.rs`: bincode-serialised
binary files alongside `smt.bin` / `mmr.bin`. Names:

- `peg_in_consumed_smt.bin`
- `burned_coins_smt.bin`
- `pending_payouts.bin`

Per `feedback_zkcoins_closed_test_env`, no migration code is needed —
on first server start with this code, all three files are created
fresh.

### 6.5 Test plan (Phase 3)

Coverage on `State` extensions:

- Insert into `peg_in_consumed_smt` → root advances; subsequent
  non-inclusion proof for same utxo fails.
- Insert into `burned_coins_smt` → same.
- Add `pending_payouts` entry → retrievable by nonce.
- State transitions: PendingAssignment → Assigned → Fronted →
  Completed.
- Persistence round-trip: write to disk, read back, equal state.

Estimated effort: **1 week**, risk **low** (mechanical extension).

---

## 7. Phase 4 — N-of-N MuSig2 Signer Node

### 7.1 Goal

A daemon that:

- Participates in the federation's MuSig2 key aggregation at setup
- Pre-signs all spending paths of the bridge transaction graph
- Cooperatively signs vault outputs for peg-ins
- Provides signing services for cooperative peg-outs

### 7.2 Where the code lives

This is **not** in `zk-coins/server` directly — it's a separate
crate that the server binary depends on. Proposed:

```
zk-coins/server/
    crates/
        bridge-signer/        ← new crate
            src/
                lib.rs
                musig2.rs
                pre_signing.rs
                tx_graph.rs
                signer_protocol.rs
            Cargo.toml
```

(Alternative: separate repo `zk-coins/bridge-signer`. MVP: keep in
the server tree to avoid premature repo proliferation. Memory note:
zkCoins works in `zk-coins/*` org with direct-to-develop pushes
per `feedback_zkcoins_direct_develop`.)

### 7.3 Library choices

- **MuSig2:** [`secp256k1-musig2`](https://docs.rs/secp256k1/) once
  it lands (Rust-Bitcoin community); or fork `rust-secp256k1`'s
  experimental musig branch
- **Bitcoin tx construction:** `rust-bitcoin` (canonical)
- **PSBT manipulation:** `rust-bitcoin`'s PSBT support
- **Network:** simple TCP+protobuf or HTTP JSON, MVP doesn't need a
  protocol-level standardisation

### 7.4 The tx graph

At federation setup, the signers pre-sign the following templates
for each peg-in denomination:

1. **MovetoVault:** spends the user's deposit → operational vault
   UTXO. Parameterised on (deposit_utxo, user_zkcoins_address).
2. **Payout:** spends vault → user_btc_recipient. Parameterised on
   (burn_nonce, btc_recipient, amount). Uses
   `SIGHASH_SINGLE|ANYONECANPAY` so any operator can add a fee input.
3. **KickOff:** operator's reimbursement claim. Spends operator's
   bond UTXO + claims vault output.
4. **Challenge, Assert, Disprove:** BitVM2 fraud-proof state machine.
5. **Take1, Take2:** operator's eventual reimbursement paths after
   challenge window or successful defence.
6. **Burn:** punitive tx that destroys operator's bond on a
   successful disprove.

For MVP with N=3 and a small set of denominations (say 0.01, 0.1, 1
BTC), the total pre-signed transaction count is ~6 templates × 3
denominations = ~18 base templates. Manageable.

### 7.5 The setup ceremony (MVP version)

1. All three signers generate fresh keypairs
2. MuSig2 key aggregation → `vault_aggregated_pubkey`
3. Each signer generates and exchanges nonce commitments for every
   pre-signed transaction
4. Each signer signs every template; partial signatures aggregated
5. Each signer **deletes the per-signer private key** (MVP demo:
   logs a "deleted" message; production: actually zeroes memory and
   removes any persisted private-key file)
6. Aggregated signatures stored persistently

### 7.6 Operations

After setup, the signers participate in:

- **MovetoVault signing:** when a user's deposit lands on Bitcoin,
  signers cooperate to broadcast the pre-signed MovetoVault tx that
  binds the deposit to the user's zkCoins address
- **Cooperative payout:** if all signers are online during a peg-out,
  they cooperatively sign a direct vault→user Payout, bypassing the
  operator-fronting path

### 7.7 Test plan (Phase 4)

Positive:
- 3-node MuSig2 setup: aggregated pubkey computed identically by all
  3
- Pre-signing one template: all 3 produce valid partial sigs;
  aggregation yields a valid BIP-340 sig
- Pre-signing all 18 templates: completes within reasonable time
  (target: < 30s)
- MovetoVault cooperation: 3-node test signs and broadcasts on
  regtest; transaction confirms

Negative:
- One node refuses to sign: aggregation fails gracefully (returns
  Error, not panic)
- One node provides a corrupt partial sig: detection via verification
  before aggregation
- Replay of a pre-signed nonce: detected, rejected

Estimated effort: **3–4 weeks**, risk **medium** (MuSig2 + Bitcoin
tx construction is well-understood territory but precise pre-signing
of a complex tx graph has been tricky historically; reference Citrea
Clementine's `signer` crate as starting point).

---

## 8. Phase 5 — Operator + Watchtower Daemons

### 8.1 Goal

The **operator** daemon advances peg-outs from its own BTC balance
and claims reimbursement via KickOff. The **watchtower** daemon
monitors Bitcoin for fraudulent operator claims and posts challenges.

In MVP, the same 3 nodes run both daemons.

### 8.2 Files touched

```
zk-coins/server/
    crates/
        bridge-operator/      ← new crate
            src/
                lib.rs
                payout.rs
                kickoff.rs
                bond.rs
        bridge-watchtower/    ← new crate
            src/
                lib.rs
                monitor.rs
                challenge.rs
                disprove.rs
```

### 8.3 Operator flow

```
1. Subscribe to `pending_payouts` events from server (see Phase 6)
2. On PendingAssignment with status changing to Assigned:
   a. Verify the burn-proof landed (zkCoins state confirms)
   b. Verify own BTC balance ≥ amount + fees
   c. Construct the Payout tx (add own input as fee, sign)
   d. Broadcast Payout tx to Bitcoin
   e. Wait for confirmation
   f. Update server: payout fulfilled (txid)
3. Submit KickOff tx claiming vault reimbursement
4. Wait for 36-block challenge window
   a. If no challenge: post NoChallenge tx after timelock, retrieve
      reimbursement
   b. If challenged: enter BitVM2 dispute (Assert + Disprove)
```

### 8.4 Watchtower flow

```
1. Subscribe to Bitcoin chain (rust-bitcoin chain notifier)
2. On any KickOff tx detected:
   a. Verify: does the corresponding pending_payout exist on zkCoins?
   b. Verify: does the Payout tx claimed by KickOff actually exist
      on Bitcoin?
   c. If either check fails: this is a fraudulent KickOff. Post
      Challenge tx within the challenge window.
3. On Assert tx (operator's response to Challenge):
   a. Run our local Groth16 verifier on the asserted computation
   b. If wrong: post Disprove tx, slashing operator's bond
```

### 8.5 Bonds

For MVP with 3 trusted nodes, bonds can be dust (~10000 sat) — the
slashing is symbolic. Production-grade bonds match peg-out
denominations.

### 8.6 Test plan (Phase 5)

Positive:
- Happy path peg-out: user burns, operator pays, no challenge, kickoff
  succeeds.
- Two parallel peg-outs: both operators advance; both reimbursements
  complete.

Negative (essential to validate the fraud-proof game works):
- **Malicious operator simulation:** operator posts KickOff for a
  payout they did not fund → watchtower detects, posts Challenge →
  operator cannot produce valid Assert → Disprove fires → bond
  slashed.
- **Operator times out on fronting:** assigned operator does not
  broadcast Payout within 64 blocks → server reassigns.
- **Network partition:** simulate Bitcoin node disconnect for an
  operator during KickOff → operator retries on reconnect.

Estimated effort: **3 weeks**, risk **medium** (state-machine
correctness, especially fraud-proof game; reference Citrea's
operator + watchtower implementations).

---

## 9. Phase 6 — Bridge-Aware Server

### 9.1 Goal

Extend `zk-coins/server` HTTP API with peg-in and peg-out endpoints.

### 9.2 Files touched

| File | Change |
| ---- | ------ |
| `server/src/bridge.rs` | **new** — bridge module |
| `server/src/server.rs` | Add bridge endpoints to router |
| `server/src/server_runtime.rs` | Wire bridge state into runtime |

### 9.3 Endpoints

```
GET  /api/bridge/quote
       Returns current peg-in and peg-out fees, denominations
       supported, estimated wait times.

POST /api/bridge/peg-in/initiate
       Body: { recipient_zkcoins_address, denomination, refund_btc_pubkey }
       Returns: { deposit_taproot_address, refund_timeout_block }
       Server records the pending peg-in; user makes the Bitcoin deposit.

POST /api/bridge/peg-in/finalize
       Body: { deposit_txid, deposit_vout, lcp_proof_bytes }
       Server verifies the LCP, runs the prover to generate
       IssuanceProof, returns ProofId to user; user signs the
       commitment and POSTs it back via the standard /api/commit.

POST /api/bridge/peg-out/burn
       Body: { source_coins[], btc_recipient_address }
       Server runs the prover to generate BurnProof, returns ProofId
       and withdrawal_nonce.

GET  /api/bridge/peg-out/status?nonce={nonce}
       Returns current PayoutStatus.

POST /api/bridge/peg-out/payout-template
       (Operator-only.) Returns the unsigned Payout template ready
       for fee-input addition.

POST /api/bridge/peg-out/fronted
       (Operator-only.) Notify that an operator broadcast a Payout
       tx; server marks PendingPayout as Fronted.
```

### 9.4 Test plan (Phase 6)

Per `feedback_zkcoins_mvp_definition`: 100% coverage on the activated
endpoints.

- Each endpoint with happy-path input → correct response
- Each endpoint with malformed input → 400-class error, no state
  change
- Each endpoint with operator/user role mismatch → 403
- Race conditions: concurrent peg-out initiations on the same coin
  set → second rejected with conflict

Estimated effort: **2 weeks**, risk **low** (standard HTTP API
extension).

---

## 10. Phase 7 — Plonky2 → Groth16 Wrapping

### 10.1 Goal

For BitVM2 to verify our state-transition proof on Bitcoin, the proof
needs to be in Groth16. Our circuit is Plonky2. The standard pattern
(Citrea, GOAT) is: prove the Plonky2 verifier circuit in Groth16,
then BitVM2 verifies the resulting Groth16 proof.

### 10.2 Files touched

| File | Change |
| ---- | ------ |
| `crates/bridge-groth16/` | **new crate** — Plonky2 → Groth16 wrapper |
| `crates/bridge-groth16/src/wrap.rs` | Implement Plonky2 verifier as a Groth16 circuit |
| `crates/bridge-groth16/src/srs.rs` | Trusted setup SRS loading / validation |
| `crates/bridge-groth16/srs/mvp_srs.bin` | The MVP single-contributor SRS — **DO NOT USE IN PRODUCTION** |

### 10.3 Approach

Two viable paths:

**Path A: arkworks-based Plonky2 verifier in Groth16.** Implement the
Plonky2 verifier (Poseidon hashing, FRI proximity checks, etc.) as
an arkworks Groth16 circuit. Reuse and modify the gnark-style
verifier patterns Citrea uses for RiscZero → Groth16.

**Path B: Aggregate via a STARK-friendly intermediate.** Plonky2 →
RiscZero → Groth16. Adds latency but reuses Citrea's exact toolchain.

→ **MVP: Path A.** Direct wrap. Effort estimate is roughly comparable
   to Path B and avoids an extra dependency.

### 10.4 Trusted setup ceremony

For MVP: single contributor (the lead dev). The SRS file is committed
to the repo with the warning marker (§3.3).

Production replacement: run a ceremony with 30–60 contributors using
`chainwayxyz`'s ceremony software (open-sourced as part of Citrea's
Risc0-to-BitVM ceremony). Each contributor adds randomness; only one
honest contributor is needed for the resulting SRS to be secure.

### 10.5 Test plan (Phase 7)

- Wrap a small Plonky2 proof in Groth16 → wrapping completes; the
  Groth16 proof verifies against the SRS.
- Wrap a state-transition proof from `IssuanceProof` → Groth16 proof
  has the expected public values (asth, ocr, peg-in-consumed-root,
  etc.).
- Negative: wrap a malformed Plonky2 proof → wrapping fails with
  clear error.

Estimated effort: **3–4 weeks**, risk **medium-high** (most novel
cryptographic engineering of the MVP; the Plonky2 verifier circuit
is non-trivial in Groth16; mitigation: study Citrea's open-sourced
Risc0-to-BitVM verifier).

---

## 11. Phase 8 — Integration Test on Signet

### 11.1 Goal

3-node end-to-end run on Bitcoin signet (or regtest): peg-in, send
within zkCoins, peg-out. Demonstrate the full happy path and at least
one fraud-proof challenge.

### 11.2 Setup

- 3 Linux VMs, each running:
  - Bitcoin signet node (synced)
  - `zk-coins/server` instance configured for bridge mode
  - `bridge-signer`, `bridge-operator`, `bridge-watchtower` daemons
- Shared regtest or signet Bitcoin network
- A test client that drives peg-ins and peg-outs

### 11.3 Test scenarios

1. **Happy peg-in:** test client deposits 0.1 BTC on signet → 3 nodes
   cooperatively MovetoVault → LCP advances → IssuanceProof generated
   → zkCoins minted.
2. **Happy peg-out:** test client burns 0.1 BTC worth of zkCoins →
   operator fronts → KickOff → no challenge → operator reimbursed.
3. **Internal zkCoins send between two test users.**
4. **Adversarial peg-out:** simulate a malicious operator that posts
   KickOff for a non-existent payout → watchtower posts Challenge →
   Disprove succeeds → bond slashed → recoverable state.
5. **Cooperative peg-out (all 3 signers online):** bypass operator
   fronting; direct vault → user payout.
6. **Refund path:** simulate federation outage; test client deposits,
   federation fails to MovetoVault for 200 blocks → test client uses
   refund leaf to recover deposit.

### 11.4 Success criteria

- All 6 scenarios complete on signet within reasonable timing
- No double-spends, no stuck funds, no unauthorised mints
- Each scenario covered by automated integration test in the CI
  pipeline
- Coverage gate maintained on all touched server/bridge code

Estimated effort: **3–4 weeks** integration + debugging, risk
**medium-high** (first full-stack run; expect timing and
state-machine bugs).

---

## 12. Aggregate Effort and Risk Register

### 12.1 Total effort

| Phase | Effort | Risk |
| ----- | ------ | ---- |
| 1 — Circuit extension | 3–4 weeks | Medium |
| 2 — Bitcoin Light Client | 3–5 weeks | High |
| 3 — State extension | 1 week | Low |
| 4 — MuSig2 signer | 3–4 weeks | Medium |
| 5 — Operator + watchtower | 3 weeks | Medium |
| 6 — Bridge-aware server | 2 weeks | Low |
| 7 — Plonky2 → Groth16 | 3–4 weeks | Medium-high |
| 8 — Integration on signet | 3–4 weeks | Medium-high |
| **Total** | **21–28 weeks ≈ 5–7 months** | — |

Assumes Plonky2 migration (PR #17) is complete before Phase 1
starts. If parallelised carefully, Phases 1–3 can begin while PR #17
finishes (since they don't depend on the server-side replace step).

### 12.2 Risk register

- **B1 — SHA256d in Plonky2 too slow.** Phase 2.
  *Mitigation:* recursive sub-proofs with small batch sizes;
  worst-case fall back to a STARK-friendly LCP (Risc0 / sp1)
  externally verified.
- **B2 — Plonky2 → Groth16 wrapping cost.** Phase 7.
  *Mitigation:* study Citrea's verifier; if it's too custom, fall
  back to Path B (intermediate Risc0).
- **B3 — MuSig2 production-readiness.** Phase 4.
  *Mitigation:* if `rust-secp256k1` MuSig2 is not stable, vendor
  a known-good fork; reference Citrea's signer.
- **B4 — Fraud-proof game state-machine bugs.** Phases 5 + 8.
  *Mitigation:* extensive negative testing (scenario 4 in Phase 8);
  cross-reference Citrea's operator implementation.
- **B5 — Bitcoin tx fee market spikes.** Phase 8.
  *Mitigation:* MVP uses signet (fees ≈ 0); production design
  includes fee bump mechanisms (RBF, CPFP). Out of MVP scope.
- **B6 — Light Client checkpoint becomes stale.** Phase 2.
  *Mitigation:* document checkpoint update procedure; out of MVP
  automation scope.

---

## 13. Open Implementation Questions

1. **MVP denominations.** Three? Five? `BITVM_BRIDGE.md` §12.8 covers
   the trade-off. Suggest: `{0.01, 0.1, 1.0} BTC` for MVP.

2. **Refund timeout for peg-in.** Strata uses 200 blocks (~33h).
   Match.

3. **Challenge window for peg-out.** Strata uses 36 blocks (~6h).
   Citrea Clementine uses 1.5 days. For MVP: 36 blocks to keep
   testing fast.

4. **Where does `bridge-signer` live?** In-tree under
   `server/crates/` or separate repo? MVP: in-tree.

5. **How is the LCP checkpoint advanced?** Manual operator commit
   for MVP. Automation = post-MVP.

6. **What happens on an LCP that hasn't been refreshed?** Reject the
   IssuanceProof; user retries after operator refreshes the LCP.
   Worst case: 1 day operator response time.

7. **Auditability surface for "total BTC in vault vs zkCoins
   outstanding".** Bridge dashboard endpoint. Useful but
   out-of-MVP-scope for circuit correctness; add post-Phase 8.

8. **What happens if Plonky2 step 5 (cyclic recursion plumbing, the
   blocker on `feat/plonky2-migration`) hits issues?** This MVP
   plan assumes step 5 lands cleanly. If it doesn't, the recursive
   LCP architecture in Phase 2 cannot work either and we'd need to
   rethink. Trigger: re-evaluate Phase 2 if step 5a's panic on
   `circuit_digest` mismatch (`MIGRATION_RESEARCH.md` §7.12)
   recurs at scale.

---

## 14. Non-Goals (Restated)

So nobody scope-creeps:

- Federation diversity / multi-org recruitment — **not in MVP**
- BitVM3 / Glock / Mosaic — **not in MVP**
- Production trusted setup ceremony — **not in MVP**
- Real economic operator bonds — **not in MVP**
- Auditability dashboard — **post-MVP**
- Bridge → Bridge interoperability — **post-MVP**
- Privacy hardening of peg-in / peg-out — **post-MVP**, depends on
  D2/D10 closure first

---

## 15. References

- [`BITVM_BRIDGE.md`](./BITVM_BRIDGE.md) — strategic context, landscape,
  why BitVM2 for v1
- [`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md) — LN swap layer
  that this bridge enables
- `SPEC.md` — protocol specification (D11 will close with this MVP).
  Currently on `feat/plonky2-migration`.
- `MIGRATION_RESEARCH.md` — Plonky2 lessons (§7.12 cyclic-recursion
  gotcha specifically relevant to Phase 2). Currently on
  `feat/plonky2-migration`.
- `ROADMAP.md` — `feat/plonky2-migration` progress; this MVP starts
  after step 9. Currently on `feat/plonky2-migration`.
- [Citrea Clementine bridge docs](https://docs.citrea.xyz/essentials/clementine-trust-minimized-bitcoin-bridge)
- [BitVM Groth16 Verifier Toolkit (chainwayxyz)](https://github.com/chainwayxyz/bitvm-zk-verifier)
- [polymerdao/plonky2-sha256](https://github.com/polymerdao/plonky2-sha256)
- [Strata bridge docs (BitVM2 reference impl)](https://docs.alpenlabs.io/how-alpen-works/bitcoin-bridge)

---

## 16. Change Log

| Date | Change |
| ---- | ------ |
| 2026-05-17 | Initial draft. |
| 2026-05-17 | §2.2: add "Federation scaling beyond N=3" as deferred item with production target N=100 (1-of-N strict, practical upper bound of BitVM2 framework). Beyond N=100 noted as open research, not current goal. |
| 2026-05-17 | Consistency audit pass: add branch note at the top explaining that `SPEC.md` / `MIGRATION_RESEARCH.md` / `ROADMAP.md` currently live on `feat/plonky2-migration` only; downgrade hyperlinks to those files to plain references (with branch annotation) in §15 References. |
| 2026-05-17 | Audit round 3: harmonise header structure (Status / Authoritative source / Audience / Branch note). Remove "DFX-operated" wording in §2.1 and §3.3 — replaced with generic "single-organisation" wording for consistency with the rest of the repo. |
