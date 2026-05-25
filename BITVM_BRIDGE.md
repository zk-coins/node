# BitVM Bridge — Trustless Mint/Burn for zkCoins

**Status:** Design draft. No code yet. Companion to `SPEC.md`
(specifically D11), `MIGRATION_RESEARCH.md`, `ROADMAP.md`, and
[`LIGHTNING_ATOMIC_SWAP.md`](./LIGHTNING_ATOMIC_SWAP.md).

**Authoritative source for:** how zkCoins removes the operator-controlled
mint (D11) by binding mint operations to provable BTC custody on Bitcoin
L1 via a BitVM2-style bridge.

**Audience:** Engineers and stakeholders evaluating zkCoins's path from
MVP-with-trusted-issuer to mainnet-with-cryptographic-issuance.

> **Branch note.** This document presupposes the Plonky2 migration
> currently on `feat/plonky2-migration` (PR #17). `SPEC.md`,
> `MIGRATION_RESEARCH.md`, and `ROADMAP.md` live on that branch and
> will resolve on `develop` only after PR #17 lands. Until then, view
> cross-references against `feat/plonky2-migration`.

---

## 1. Scope

This document specifies what it would take to make zkCoins coin issuance
**trustless** by replacing the hard-coded `MINTING_ADDRESS` with a
BitVM2-bridge-anchored mint mechanism. Concretely:

- The exact trust model of BitVM2 bridges as deployed by Citrea
  (Clementine) and others as of 2026-05
- How a BitVM2 bridge would integrate with the zkCoins state-transition
  circuit
- What new circuit branch (`IssuanceProof` per Shielded CSV paper) needs
  to exist
- The federation setup, trusted setup ceremony, and operational burden
- The peg-in (BTC → zkCoin) and peg-out (zkCoin → BTC) flows
- Trust assumptions in plain terms (where 1-of-N suffices, where N-of-N
  is required, where the user trusts no one)
- Open issues, cost estimates, and what it does *not* solve

It does **not** cover:

- BitVM1 (superseded by BitVM2 for bridges)
- BitVM3 (research-stage, not production-ready as of 2026-05)
- Non-bridge BitVM use cases (general computation)
- Lightning swap layer — that lives in `LIGHTNING_ATOMIC_SWAP.md`

---

## 2. The Problem Restated

### 2.1 D11 today

Per `program/src/lib.rs:70-73` and `program/src/main.rs:78-83`, the
`InitialProof` branch of the state-transition circuit contains:

```rust
ProofType::InitialProof => {
    if account_state.owner != MINTING_ADDRESS {
        assert_eq!(account_state.balance, 0, "Starting balance has to be 0.")
    }
    DEFAULT_HASHES[0]
}
```

Anyone holding the private key to the public key whose hash is
`MINTING_ADDRESS` can produce an `InitialProof` with arbitrary starting
balance — effectively unlimited mint authority. There is no on-chain
binding, no cap, no audit constraint.

In the closed-test environment (`feedback_zkcoins_closed_test_env`) and
under the MVP-publisher self-issuance model (`MIGRATION_RESEARCH.md`
§5.6) this is acceptable. It is **not** acceptable for any mainnet
launch that claims trust-minimised properties over the issued asset.

### 2.2 What "trustless mint" means here

The user of a zkCoin must be able to verify, without trusting any
single party, that **the total supply of zkCoins outstanding does not
exceed the BTC locked in publicly verifiable on-chain custody**.

Equivalently: every coin in circulation must trace its provenance back
to a BTC peg-in on Bitcoin L1, and the protocol must prevent
inflationary mints.

### 2.3 What BitVM2 provides

BitVM2 (specifically the Clementine bridge architecture as deployed by
Citrea) provides exactly this binding: a Bitcoin-L1-anchored mechanism
where:

- BTC enters the bridge via deposit into an N-of-N MuSig Taproot vault
- A side-system mint is authorised only when a Bitcoin Light Client
  proof shows the deposit is final
- Withdrawals back to Bitcoin require fronting by operators and are
  optimistically verified, with on-chain disproof via Groth16 SNARK
  verification baked into Bitcoin script

Trust model: **1-of-N honesty per role**. As long as one signer deletes
their key honestly at setup, one operator advances payouts honestly,
and one challenger watches for fraud, the bridge holds.

---

## 3. BitVM2 / Clementine — Architecture in Detail

This section is a precise read of the Citrea Clementine implementation
as of 2026-05. References at the end.

> **2026 context** (added 2026-05-17): BitVM2 is currently the only
> trustless-bridge construction with a live mainnet deployment (Citrea
> launched 2026-01-27). Three credible successors have emerged in
> 2025–2026 — BitVM3-RSA (withdrawn after security flaw), Glock by
> Alpen Labs (research/testnet-stage), and Mosaic by Eagen et al.
> (research-stage, full Rust implementation). All three use garbled
> circuits + cut-and-choose + adaptor signatures to push BitVM2's
> on-chain Assert footprint down by 100–1000×. See §12 for a survey
> of these alternatives and what it means for zkCoins's bridge choice.
> The fundamentals of §3 (peg-in/peg-out flow, roles, 1-of-N honesty
> assumption) remain identical across all BitVM-family bridges; the
> innovations target the fraud-proof step specifically.

### 3.1 Roles

| Role | Function | Quorum |
| ---- | -------- | ------ |
| **User** | Initiates peg-in (locks BTC) or peg-out (burns side-chain asset) | — |
| **Signers** | Pre-sign every spending path of every UTXO in the bridge graph at setup. Must delete keys after presigning. | N-of-N MuSig (all participate) |
| **Operators** | Front BTC payouts to peg-out users from their own funds; later reimbursed from the vault | 1-of-N — any operator can serve any payout |
| **Watchtowers** | Monitor Bitcoin chain and bridge state; publish header-chain proofs during disputes | 1-of-N |
| **Challengers** | Permissionless — anyone can detect and challenge fraudulent operator claims | Permissionless |

Hierarchy: every Signer is also an Operator and Watchtower; Challengers
can be anyone (no membership required).

### 3.2 Setup ceremony — N-of-N MuSig

Once per bridge deployment, the N signers must:

1. Generate fresh Schnorr keypairs
2. Aggregate to a MuSig2 vault key
3. Construct the **entire transaction graph** of allowed spending
   paths: peg-in `MovetoVault`, peg-out `Payout`, `KickOff`,
   `Challenge`, `Assert`, `Disprove`, `Take1`, `Take2`, `Burn`,
   timeout refunds
4. Pre-sign all of these with the N-of-N MuSig
5. **Delete the per-signer private keys**

The deletion step is the security crux. As long as **at least one
signer actually deletes**, no future coalition can spend the vault
outside the pre-signed paths. This is the **"1-of-N honesty"
assumption**.

### 3.3 Groth16 verifier on Bitcoin

For fraud-proof verification, BitVM2 implements a **Groth16 verifier in
Bitcoin script**, split into sub-programs each small enough to fit in
a Bitcoin block. When an operator's claim is challenged, the operator
must commit to intermediate computation states on-chain. A challenger
who detects a wrong intermediate state executes the corresponding
sub-program on-chain to disprove the operator's claim.

This requires:

- A **trusted setup ceremony** for the Groth16 SRS. Citrea ran theirs
  with 63 contributors from RiscZero, StarkWare, Aztec, Celestia,
  Babylon, Nansen, etc. — `MIGRATION_RESEARCH.md`-grade table.
- The proven statement: the operator's payout transaction is included
  in a finalized Bitcoin chain with accumulated work greater than the
  watchtower's submitted header chain.

### 3.4 Peg-in flow (BTC → bridged asset)

```
Step 1. User deposit: User sends BTC to a Taproot address with two
        leaves:
          - Bridge leaf: spendable by the N-of-N MuSig signature,
            with witness binding to the user's side-chain receiving
            address
          - Refund leaf: spendable by user after 200 blocks (CSV)

Step 2. Vault transfer: Signers cooperatively spend the deposit into
        the operational vault UTXO using the pre-signed MovetoVault
        transaction. The pre-signature binds the spend to exactly
        the right operational vault path — no signer can divert.

Step 3. Confirmation wait: Vault transfer needs 6+ Bitcoin confirms.

Step 4. Mint authorization: The side-chain (zkCoins in our case)
        reads the Bitcoin Light Client proof and confirms the
        MovetoVault tx is in the finalized chain. The mint amount
        equals the deposit amount minus fees, credited to the user's
        side-chain address.
```

The refund path protects the user against bridge stalls — if the
signers fail to advance the deposit within 200 blocks, the user
recovers via the refund leaf.

### 3.5 Peg-out flow (bridged asset → BTC)

```
Step 1. Burn: User invokes the side-chain's burn function. On Citrea
        this is `safeWithdraw` on a contract; for zkCoins it would be
        a coin-send to a designated BURN_ADDRESS or — paper-aligned —
        a dedicated BurnProof predicate branch (§6.3).

Step 2. Payout request: User submits a Payout transaction template
        signed with SIGHASH_SINGLE|ANYONECANPAY, identifying their
        BTC receiving address and amount.

Step 3a. Optimistic path: If all N Signers are online and cooperative,
         they collectively sign the Payout, releasing BTC from the
         vault directly to the user. ~12 hours typical wait for signer
         convening.

Step 3b. Operator-fronted path: If signers don't convene in 12 hours,
         an Operator funds the user out of their own wallet by adding
         their own input to the Payout template and broadcasting.
         User gets BTC immediately.

Step 4. Operator reimbursement (only path 3b):
          - Operator posts KickOff tx claiming reimbursement from
            the vault, citing the peg-out they fronted
          - Challenge window opens (1.5 days)
          - Watchtowers + permissionless challengers can verify the
            KickOff against the actual chain
          - If no valid challenge: Operator posts NoChallenge tx
            after timelock, retrieves reimbursement from vault
          - If valid challenge: BitVM2 Groth16 verifier runs on-chain;
            operator must produce ZK Light Client Proof showing their
            committed chain has greater cumulative work AND includes
            the legitimate payout
          - Honest operator wins; malicious operator's entire bond is
            slashed and they're ejected from the set

Step 5. The same Payout template cannot be used twice — anti-replay.
```

### 3.6 Key timeouts and security parameters

| Parameter | Value | Why |
| --------- | ----- | --- |
| Peg-in refund timeout | 200 Bitcoin blocks (~33 hours) | User recovers funds if bridge stalls |
| Optimistic payout convening window | 12 hours | Signer assembly time before operator-fronted path activates |
| Challenge window | 1.5 days (~216 blocks) | Permissionless dispute initiation |
| Security analysis horizon | 2 weeks | Maximum reorg attempt window |
| Hash rate adversary cap | < 45% | Below which the chain proof remains correct |

### 3.7 Trust assumptions in plain terms

A user holding bridged BTC trusts that:

- **At least one of N signers deleted their keys** at setup (after
  pre-signing). With Citrea's federation of ~20 members from
  competing organisations, the probability of zero honest deletions
  is extremely low but non-zero — this is the residual trust.
- **At least one operator** is willing to advance peg-outs (else
  liveness — funds are not stolen but become inaccessible until any
  operator returns).
- **At least one watchtower or challenger** is monitoring (else
  fraudulent operator claims can succeed unchallenged).
- **Bitcoin's < 45% adversary assumption** holds for the 2-week
  challenge horizon (standard Bitcoin assumption).

These are weaker assumptions than any federated bridge (Liquid, RSK)
and stronger than any client-side-verifying chain (which has no bridge
at all).

---

## 4. What Changes in zkCoins

### 4.1 Circuit changes (`program/`, `program-plonky2/`)

A new `ProofType` variant, paper-aligned with the Shielded CSV
`issuance(IssuanceProof)` branch:

```rust
pub enum ProofType {
    InitialProof,
    AccountUpdateProof,
    IssuanceProof,        // NEW
    BurnProof,            // NEW — counterpart for peg-out
}
```

The `IssuanceProof` branch replaces the current `MINTING_ADDRESS`
bypass. Instead of trusting `owner == MINTING_ADDRESS`, the circuit
verifies a **Bitcoin Light Client Proof (LCP)** witnessing that:

- A specific peg-in UTXO (identified by txid and vout) has been
  confirmed at depth ≥ 6 in the Bitcoin chain
- The peg-in UTXO's amount equals the issuance amount
- The peg-in UTXO has not been used as the basis of any prior
  `IssuanceProof` (uniqueness — tracked in a new
  `peg_in_consumed_smt`)
- The peg-in UTXO's witness data binds to the recipient zkCoins
  address (so only the intended recipient can mint against that
  deposit)

The `BurnProof` branch handles the peg-out side:

- A coin is "consumed" by producing a `BurnProof` against it
- The proof emits a public output containing
  `(burn_amount, btc_recipient, withdrawal_nonce)` that the bridge
  operator picks up to construct the Bitcoin Payout transaction
- The burned coin's identifier is added to a `burned_coins_smt` so
  it cannot be double-burned

### 4.2 New state structures (`node/src/state.rs`)

Three additions to the global state:

```rust
struct State {
    // ... existing fields (smt, mmr, prev_mmr_root, root_indices)

    // NEW: peg-ins that have been consumed by an IssuanceProof
    peg_in_consumed_smt: SparseMerkleTree,

    // NEW: coins that have been burned (peg-out initiated)
    burned_coins_smt: SparseMerkleTree,

    // NEW: pending peg-outs waiting for operator fronting
    pending_payouts: Map<BurnNonce, PendingPayout>,
}
```

### 4.3 New off-circuit responsibilities

The scanner gains:

- Watching the bridge vault UTXO and any deposits to it
- Maintaining a local Bitcoin Light Client (header chain + cumulative
  work) — likely implemented via SP1's `bitcoin-spv` precompile or an
  equivalent in Plonky2
- Detecting peg-out completion (operator broadcasts Payout tx),
  marking pending payouts as completed

### 4.4 Federation participation

This is the heaviest organisational change. zkCoins becomes a **member
of a BitVM2 federation**, which requires:

- Coordinating with N-1 other federation members at setup
- Participating in the trusted setup ceremony for the Groth16 verifier
- Continuously running a signer node, operator node, watchtower node
- Maintaining operator collateral (BTC bond)

Realistically, zkCoins cannot operate a single-member "federation" of
size 1 and call itself trustless. The minimum credible size is ~5–7
members from independent organisations. Citrea uses ~20.

### 4.5 What does NOT change

- The zkCoins coin model itself (`Coin { identifier, recipient,
  amount }`) — D11 fix does not require D2 fix
- The Schnorr/SHA256 boundary at the wallet (BIP-340 still off-circuit)
- The SMT/MMR scanner architecture for normal sends
- The Lightning atomic swap design — `LIGHTNING_ATOMIC_SWAP.md`
  remains correct, and a swap liquidity provider becomes anyone
  with bridge deposit/withdraw capability instead of relying on a
  single sole minter

---

## 5. Detailed Flow A: Peg-In (BTC → zkCoin)

### 5.1 Pre-conditions

- User has BTC on Bitcoin L1
- User has a zkCoins account (knows their `recipient = H(initial_pubkey)`)
- Bridge federation is operational, vault UTXO exists, all
  pre-signatures in place

### 5.2 Protocol steps

```
Step 1. User constructs a deposit tx with a Taproot output containing
        two leaves:
          - Bridge leaf: vault_musig_pubkey, with witness commitment
            to user's zkcoins recipient address
          - Refund leaf: user_pubkey + 200-block CSV
        User broadcasts.

Step 2. Bridge federation observes the deposit. Signers cooperatively
        spend it into the operational vault UTXO using the pre-signed
        MovetoVault transaction (the pre-signature is parameterised
        on the user's zkcoins address, embedded in the deposit's
        witness commitment).

Step 3. MovetoVault tx confirms (≥6 confirms). At this point the
        peg-in is finalized on Bitcoin.

Step 4. User (or their wallet, or any helper service) generates a
        Bitcoin Light Client Proof showing MovetoVault is in the
        canonical chain at depth ≥ 6.

Step 5. User submits to a zkCoins server an IssuanceProof request:
          - Their account state (initial, balance = 0)
          - The Bitcoin LCP for MovetoVault
          - The peg-in UTXO outpoint
          - The non-inclusion proof against peg_in_consumed_smt

Step 6. zkCoins server (or the user's own prover, in a more
        decentralised future) generates the IssuanceProof:
          - Verifies the Bitcoin LCP
          - Verifies the deposit amount equals the requested mint
          - Verifies the witness commitment binds the deposit to
            this account
          - Verifies non-inclusion in peg_in_consumed_smt and inserts
          - Emits ProofData with the user's new account state
            (balance = deposit_amount − bridge_fee) and the standard
            commitment_history / coin_history fields

Step 7. User signs the Schnorr commitment H(asth ‖ ocr) (same as any
        send). User or their operator publishes the inscription.
        Scanner picks up, state updates.

Step 8. User now has zkCoins backed by the locked BTC. Total supply
        increased by exactly the deposit amount.
```

### 5.3 Refund path

If Step 2 doesn't happen within 200 blocks (e.g., federation offline
or unwilling to process this deposit), the user spends the deposit
back to themselves via the refund leaf. No interaction with zkCoins
needed.

### 5.4 Failure modes

| Failure | Recovery |
| ------- | -------- |
| Federation refuses to MovetoVault | Refund leaf after 200 blocks |
| Vault sweeps multiple deposits without proper mint authorisation | Pre-signing prevents this (vault can only spend via pre-signed paths) |
| User's LCP is forged or stale | Circuit re-verifies LCP from headers; forgery requires breaking PoW |
| Bitcoin reorg removes MovetoVault | LCP becomes invalid; user retries after deeper confirmation |
| zkCoins server malicious — refuses to generate IssuanceProof | User goes to another zkCoins server (server-side compute is replicable; any party with the protocol can mint). This requires multiple zkCoins servers to exist; currently single-server. |

### 5.5 The "user pays an operator to mint" alternative

The above puts proof generation on the user side (or their chosen
zkCoins server). A simpler MVP variant: the federation includes
zkCoins-server operators who automatically generate the IssuanceProof
when they see a confirmed MovetoVault. This is more centralised but
operationally simpler. Trade-off documented as open question §10.

---

## 6. Detailed Flow B: Peg-Out (zkCoin → BTC)

### 6.1 Pre-conditions

- User has zkCoins they wish to redeem for BTC
- Vault has sufficient BTC inventory to fund the payout
- At least one operator is online and has sufficient liquid BTC to
  front the payout

### 6.2 Protocol steps

```
Step 1. User produces a BurnProof against their coin(s):
          - Inputs: coin(s) to burn, valid inclusion proofs from
            their source proofs
          - Public outputs: ProofData { burn_amount, btc_recipient,
            withdrawal_nonce, ... }
          - The burn registers each coin in burned_coins_smt

Step 2. User publishes the burn inscription (same `4242`-prefix
        Taproot mechanism as a regular send). Scanner picks up, state
        updates burned_coins_smt and registers the pending payout in
        the bridge's pending_payouts queue.

Step 3. User signs a Payout transaction template:
          - Output: btc_recipient gets burn_amount − fees
          - Input slot: SIGHASH_SINGLE|ANYONECANPAY, signed by user;
            requires an operator to add their own funding input
        User submits this template to the bridge.

Step 4. Optimistic path (12-hour signer convening):
          - Signers verify the BurnProof landed and pending_payouts
            has the corresponding entry
          - Signers collectively sign the Payout against the vault
          - User receives BTC; vault is reduced

Step 5. Operator-fronted path (if optimistic path stalls):
          - An operator adds their UTXO as input, signs, broadcasts
          - User receives BTC immediately
          - Operator initiates reimbursement via KickOff
          - Challenge window 1.5 days
          - If no challenge: operator claims reimbursement from
            vault
          - If challenged: BitVM2 game decides; honest operator
            wins, malicious one is slashed

Step 6. Bridge marks the pending_payout as completed; the same
        BurnProof cannot trigger another payout (replay protection
        via withdrawal_nonce uniqueness in pending_payouts).
```

### 6.3 The BurnProof — circuit specifics

The `BurnProof` branch in the circuit:

- Asserts at least one input coin
- Asserts no output coins (or only a "change" output coin for the
  amount minus burn)
- Asserts `burn_amount > 0` and `burn_amount ≤ sum_inputs`
- Asserts each burned coin's identifier is inserted into
  `burned_coins_smt`
- Asserts `withdrawal_nonce` is a fresh value (e.g., random
  field-element committed at burn time, never seen before in
  `withdrawal_nonces_smt`)
- Emits `btc_recipient` as 20- or 32-byte Bitcoin address as a public
  output field

### 6.4 Failure modes

| Failure | Recovery |
| ------- | -------- |
| User burns but signers/operators refuse to pay | Fraud — the BurnProof is on-chain (in zkCoins state), the user has a permanent record. After protocol-defined dispute window, governance recourse via federation slashing. Recommended: hard timeout — if 30 days without payout, the burn entry expires and can be re-issued as a fresh mint to the user (requires extra circuit branch, not in v1) |
| Operator double-claims reimbursement | KickOff replay protection — same Payout template can't be used twice; BitVM2 enforces |
| Operator fronts and is slashed for fraud | User already received their BTC (the Payout completed before challenge window); operator loses bond. Bridge is intact. |
| Vault doesn't have enough BTC | Pre-condition failure; bridge must reject burn requests above vault capacity, or queue them |

---

## 7. Sequencing — What Comes Before What

A realistic implementation sequence:

| Phase | Item | Effort | Dependencies |
| ----- | ---- | ------ | ------------ |
| 0 | Plonky2 cutover complete (`feat/plonky2-migration` merged) | Already in progress | — |
| 0 | D2/D10 (hiding recipient) and D7 (reorg safety) closed | Pre-mainnet hardening, 2–3 weeks | — |
| 1 | Decide bridge model: BitVM2 vs Liquid-style federation | Strategy decision | — |
| 2a | Federation recruitment — ~5–7 independent organisations agree to participate | Org-level — months | Decision in Phase 1 |
| 2b | Trusted setup ceremony for Groth16 | 2–4 weeks elapsed, ~63 contributor invitations | 2a |
| 3 | Bitcoin Light Client gadget in circuit | 2–3 weeks | Phase 0 |
| 4 | `IssuanceProof` circuit branch | 2 weeks | Phase 0, Phase 3 |
| 5 | `BurnProof` circuit branch | 1–2 weeks | Phase 0 |
| 6 | Bridge server-side state (peg_in_consumed_smt, burned_coins_smt, pending_payouts) | 1 week | Phase 4, Phase 5 |
| 7 | Federation node software (signer + operator + watchtower roles) | 4–6 weeks | Phase 2a, Phase 6 |
| 8 | Integration testing with all federation members on signet | 2–4 weeks | Phase 7 |
| 9 | Mainnet launch | TBD | Phase 8 |

**Aggregate effort:** 4–6 months engineering for the zkCoins-specific
code (Phases 3–6), plus 2–6 months for federation coordination and
trusted setup (Phases 2a–2b). Realistically 6–9 months elapsed time
to a credible mainnet bridge.

This is **substantial** — comparable to Citrea's bridge timeline. It
also fundamentally changes zkCoins from a single-operator MVP into a
multi-party federated infrastructure project.

---

## 8. Realistic Alternatives at Lower Cost

Not every product needs full BitVM2. Three lower-cost alternatives,
ordered from most to least trust-minimised:

### 8.1 Liquid-style federation (Liquid Network, Blockstream)

A k-of-n multisig federation holds the BTC. Mints are authorised by
the federation's signing. No on-chain fraud proofs; trust is "honest
majority of federation".

- **Trust model:** k-of-n (typically 11-of-15 for Liquid)
- **Effort:** weeks (just multisig + a side-chain mint authorisation
  flow)
- **Trade-off:** explicitly trusts the federation majority; if k
  members collude, BTC can be stolen

This is **what a single-organisation issuer could realistically run
today** with existing infrastructure. It is **not** trustless in the
BitVM2 sense, but it is trust-distributed and well-understood by the
market.

### 8.2 Optimistic bridge with permissionless challenge (no SNARK on Bitcoin)

A 1-of-n optimistic bridge where withdrawals can be challenged for
a window, but the challenge mechanism is off-chain (challenger
publishes a fact and the federation slashes operators by
governance), not via Bitcoin script SNARK verification.

- **Trust model:** 1-of-n honesty assumption, but recourse is
  governance not cryptography
- **Effort:** 2–4 months
- **Trade-off:** cheaper than BitVM2 but legally/socially harder to
  enforce slashing

### 8.3 Federated peg with hardware-secured signers

The k-of-n federation runs HSMs that enforce policy in firmware (e.g.,
"only sign payouts that match a corresponding burn observed in the
side-chain state"). Adds hardware-level enforcement to 8.1.

- **Trust model:** k-of-n federation + HSM vendor + firmware
- **Effort:** 1–3 months
- **Trade-off:** depends on HSM security, vendor trust

### 8.4 Recommendation

For a single-organisation-led zkCoins launch, **8.1 (Liquid-style)
is the realistic short-term path**. BitVM2 is the long-term
aspiration but requires federation recruitment and trusted setup
ceremony coordination that do not fit a self-funded single-org
timeline.

The migration path is clean: a Liquid-style bridge in v2 can be
upgraded to a BitVM2 bridge in v3 by replacing the trust model at
the federation layer without changing the circuit's `IssuanceProof`
contract.

---

## 9. Privacy Implications

### 9.1 Peg-in observability

The user's deposit on Bitcoin L1 is visible. Anyone watching the
bridge vault UTXO sees:

- The deposit amount
- The user's Bitcoin address(es) used to fund
- The MovetoVault tx and its timing
- Eventually, the corresponding inscription on Bitcoin (via the
  `4242` prefix) — even if the recipient address inside is hidden
  (post-D2/D10), the temporal correlation of "deposit X confirmed
  at time T, inscription Y appeared at time T+δ" is observable.

This is **a privacy regression compared to a fully off-chain mint**
where the user could mint without Bitcoin L1 exposure. It is **a
privacy improvement compared to L1 BTC** (after the mint, all
subsequent zkCoins transfers are private off-chain).

### 9.2 Peg-out observability

Symmetric. The user's BTC withdrawal address is on L1. The temporal
correlation of "burn at time T, BTC arrives at user's address at time
T+δ" links the on-chain zkCoins burn with the destination address.

### 9.3 Mitigations

- **Stealth peg-in:** the witness commitment to the recipient address
  in the deposit's Taproot leaf can use a hiding commitment with
  per-deposit randomness. Bridge federation sees the commitment but
  not the actual recipient address. This is a privacy gain only if
  the recipient address is also hidden in the issued coin (i.e., D2
  is fixed).
- **Per-deposit fresh addresses:** the user uses a fresh Bitcoin
  address for each deposit. Standard hygiene.
- **Coinjoin on peg-out:** the user mixes their burned BTC payout
  with others via a separate coinjoin step after withdrawal. Adds
  latency but breaks the on-chain link.

### 9.4 Net assessment

zkCoins-with-bridge has **less privacy than zkCoins-without-bridge**
(the bridge adds L1 touch points), but **more privacy than any other
BTC L2 with a bridge** because intra-zkCoins transfers remain fully
private off-chain. The privacy story is "BTC enters the shielded
zone, moves privately, BTC exits the shielded zone" — comparable to
Zcash's t/z address model.

---

## 10. Open Questions

1. **Who pays for proof generation in Phase 4–5?** Server-side
   (zkCoins operator) is operationally simpler; user-side
   (decentralised) is more trustless. Default: server-side for v1
   with a clear migration path to user-side later.

2. **Federation size and composition.** Minimum credible: 5
   independent orgs. Target: 15+ for parity with Liquid. Who? Other
   Swiss-regulated crypto entities, exchanges, custody providers,
   academic institutions. This is mostly a business-development
   question, not engineering.

3. **Trusted setup ceremony logistics.** Coordinate with the BitVM
   community for a shared SRS, or run a zkCoins-specific ceremony?
   Citrea ran theirs because their predicate (RiscZero → Groth16) is
   specific. zkCoins's predicate is also specific (Plonky2 verifier
   wrapper → Groth16), so likely a dedicated ceremony — but the
   ceremony tooling itself is reusable from Citrea's open-source
   release.

4. **Liquidity bootstrapping.** Operators need BTC inventory to front
   peg-outs. Where does it come from? Self-funded by federation
   members, with fee compensation. The initiating operator can
   plausibly bootstrap with reasonable inventory before recruiting
   further federation members.

5. **Fee model.** Bridge fees per peg-in and peg-out. Should match
   market rates (Liquid is 0% currently; Citrea has small fees).
   Trade-off between user adoption and federation sustainability.

6. **Audit-friendly accounting.** The bridge needs a public, real-time
   view of "total BTC in vault" vs "total zkCoins outstanding" so any
   user can verify the bridge is solvent. This is a side-chain
   indexer feature, not a protocol feature, but it should ship at
   launch to avoid trust-by-default concerns.

7. **Plonky2 → Groth16 wrapping.** The BitVM2 verifier is Groth16.
   The zkCoins predicate runs in Plonky2. There must be a wrapping
   step: prove the Plonky2 verifier in Groth16, so Bitcoin can
   verify the wrapped Groth16 proof via BitVM2. This wrapping step
   is the same pattern Citrea uses (RiscZero → Groth16). Tooling
   from `chainwayxyz/bitvm-zk-verifier` is the starting point.

8. **What does "trustless" mean to our users?** The legal/compliance
   framing matters. Even BitVM2 is "1-of-N honest" — not
   "cryptographically impossible to cheat". Marketing-correctness
   requires care.

9. **Interaction with Lightning swap layer.** Once a bridge exists,
   the swap design in `LIGHTNING_ATOMIC_SWAP.md` can be enhanced:
   instead of an operator providing zkCoins liquidity from their own
   inventory, the operator could trigger a fresh peg-in within the
   swap flow. This reduces operator capital requirements but
   increases per-swap latency (peg-in takes 33h refund window).
   Likely worth modelling but not implementing.

---

## 11. Comparison Tables

### 11.1 Trust models compared

| Model | Trust assumption | Slashing | Compute-on-Bitcoin |
| ----- | ---------------- | -------- | ------------------ |
| Today (D11) | 100% trust in the single operator-minter | None | None |
| Liquid-style federation | k-of-n federation honest majority | Off-chain governance | None |
| Optimistic + governance dispute | 1-of-n + governance recourse | Off-chain | None |
| BitVM2 / Clementine | 1-of-n setup honesty + 1-of-n watchtower | On-chain via Bitcoin Groth16 verifier (~2.6 MB Assert) | Yes (Groth16) |
| BitVM3 (cut-and-choose) | Same as BitVM2 + cut-and-choose security | On-chain via Garbled-Circuit Disprove (~60 kB Assert, ~200 B Disprove) | Yes (DV-SNARK / GC) |
| Glock (Alpen Labs) | Same as BitVM2 + cut-and-choose | On-chain DV-SNARK based Disprove (~5 kB Assert, 430–550× cheaper than BitVM2) | Yes (DV-SNARK / GC) |
| Mosaic (Eagen et al.) | Same as BitVM2 + cut-and-choose | On-chain footprint **independent of N** (cut-and-choose copies) via polynomial label correlation + adaptor sigs | Yes (DV-SNARK / GC) |
| Native Bitcoin (theoretical) | 0 trust | n/a | n/a |

### 11.2 BitVM family + competing GC-based verifiers (state as of 2026-05)

| Construction | Year | Status | Onchain dispute cost | Bridge deployed where |
| ------------ | ---- | ------ | -------------------- | --------------------- |
| BitVM1 | 2023-10 | Superseded | Very high (interactive multi-round) | Theoretical only |
| BitVM2 | 2024-08 | **Mainnet production** | ~2.6 MB Assert tx | Citrea Clementine (mainnet since 2026-01-27); GOAT (testnet V3 since 2026-01-28); Alpen Strata (signet, 10 BTC fixed denomination) |
| BitVM3-RSA | 2025-07 | **Withdrawn** — security flaw found by Eagen / Fairgate | ~60 kB Assert, ~200 B Disprove | None |
| BitVM3-CC (cut-and-choose) | 2026 | Research / early demo | ~$10.91 dispute on mainnet (BOB) | BOB roadmap |
| Glock (Alpen Labs) | 2025-08 | Research → testnet | 430–550× cheaper than BitVM2 (DV-SNARK based) | Strata bridge transition planned; Starknet partnership announced |
| Mosaic (Eagen et al.) | 2026-04 | Research, full protocol spec + Rust impl | On-chain footprint **independent of N copies** (polynomial label correlation) | None yet |

**Reading guide:**

- **For a launch today** (zkCoins or any other side-system): BitVM2 is
  the only choice with a live, production-tested implementation
  (Clementine). Citrea has been in mainnet since 2026-01-27. Tooling,
  trusted setup ceremony output, and operational documentation all
  exist.
- **For a launch in 6–12 months**: Glock and Mosaic both have credible
  implementations and academic peer review going. Either could mature
  to production status by then. Both are 100–1000× cheaper on-chain
  than BitVM2 and use the same 1-of-N honesty trust model with
  cut-and-choose security.
- **Avoid**: BitVM3-RSA (broken). Plain garbled-circuit constructions
  without cut-and-choose (not malicious-secure).

### 11.3 Realistic timelines

| Target | Effort | Realistic launch |
| ------ | ------ | --------------- |
| Liquid-style federated bridge | 2–3 months | Q3–Q4 2026 |
| BitVM2 bridge (zkCoins-only federation) | 6–9 months | Q1 2027 |
| BitVM2 bridge (multi-org federation) | 9–18 months | Late 2027 |
| Glock-based bridge | depends on Glock production-readiness | Q2–Q4 2027 (if Glock stabilises) |
| Mosaic-based bridge | depends on Mosaic production-readiness | Q3 2027+ (still in research, full Rust impl exists) |

---

## 12. Beyond BitVM2 — The 2026 Verification Landscape

This section was added after the initial draft. It documents the
post-BitVM2 alternatives that emerged in 2025–2026 and explains why
the strategic recommendation in §13 (Bottom Line) still defaults to
BitVM2 today despite the alternatives being more efficient.

### 12.1 What changed since BitVM2

BitVM2 (Linus et al., 2024-08) shipped as a Bitcoin-script Groth16
verifier split into sub-programs small enough to fit individual
Bitcoin transactions. The Assert transaction — the on-chain message
where the operator commits to the intermediate computation states —
is roughly 2.6 MB. At Bitcoin's economic block space cost, this is
expensive but not prohibitive for high-value bridges where peg-out
volume can absorb the fee.

Three follow-up constructions in 2025–2026 attack the Assert size
specifically by replacing the on-chain Groth16 verifier with a
garbled-circuit-based fraud-proof mechanism. The garbled circuit
itself is too large to put on Bitcoin directly, so the constructions
post commitments and use cut-and-choose + adaptor signatures to
ensure that revealing the on-chain signature also reveals enough
information to disprove a fraudulent claim.

### 12.2 BitVM3 — RSA construction (2025-07) — **withdrawn**

The first attempt to use garbled circuits on Bitcoin for bridges. The
original BitVM3 paper by Robin Linus proposed an RSA-based binding
between garbled-circuit labels and Bitcoin signatures. Achieved ~60 kB
Assert and ~200 B Disprove on paper.

**Status:** withdrawn. Liam Eagen (later author of Glock) and Fairgate
Labs identified core security flaws in the RSA construction. The
paper was retracted. **Do not build on this.**

Subsequent work continues under the BitVM3 banner using cut-and-choose
rather than the broken RSA binding — see BitVM3-CC by BOB and others.

### 12.3 BitVM3-CC (cut-and-choose) — BOB implementation

BOB's engineering team implemented a cut-and-choose variant of BitVM3
on Bitcoin mainnet, using Verifiable Secret Sharing Schemes (VSSS)
and adaptor signatures. Demonstrates a ~$10.91 dispute cost on
mainnet, with the Assert transaction ~87% cheaper than BitVM2.

The construction is essentially a more careful cousin of the original
BitVM3-RSA, replacing the broken RSA binding with multi-copy
cut-and-choose where the prover commits to N garbled-circuit copies
and the verifier opens t of them to check honest garbling.

**Status:** demonstrated on mainnet by BOB, but the broader
"BitVM3-CC" research line is still maturing. Reasonable to track as
a credible 2027 alternative but too early to commit to.

### 12.4 Glock — Garbled Locks for Bitcoin (Alpen Labs, 2025-08)

**Paper:** [eprint 2025/1485](https://eprint.iacr.org/2025/1485),
Liam Eagen, Alpen Labs.

**Core idea.** Combine garbled circuits with a novel and very compact
**designated-verifier SNARK (DV-SNARK)** to bind the garbled circuit's
input/output labels directly to Bitcoin lock data. The DV-SNARK is
constructed over binary elliptic curves, which Eagen argues have
"nice synergies" with the garbled-circuit scheme.

**Why it's smaller than BitVM2.** BitVM2 verifies Groth16, which is a
universal SNARK and requires a verifier circuit of fixed substantial
size when reduced to Bitcoin script. Glock's DV-SNARK is designed for
a single specified verifier (the bridge contract), so it's
specialised and much smaller. Combined with garbled-circuit fraud
proofs, total on-chain footprint per dispute is in the few-kB range
rather than MB.

**Architecture sketch.**

- **Setup:** federation runs cut-and-choose for honesty of N garbled
  copies. t copies are opened publicly to prove honesty; the
  remaining N-t are used for actual fraud-proof evaluation.
- **Operator commits to a peg-out claim** by posting a signature
  whose adaptor binds to a label of the garbled circuit.
- **If the claim is wrong:** the corresponding garbled-circuit
  evaluation reveals a secret that lets anyone reconstruct a "fraud
  signature" — punishing the operator on-chain.
- **If the claim is right:** no further on-chain interaction needed;
  the operator's adaptor signature settles after timelock.

**Efficiency.** Claimed 430–550× on-chain efficiency over BitVM2.
Concretely: instead of a 2.6 MB Assert transaction, Glock's
disprove-related on-chain footprint is in the few-kB range.

**Status (2026-05).**

- Paper published August 2025
- Alpen Labs is building Glock into their Strata bridge as the
  successor to the current BitVM2-based Strata bridge implementation
- Starknet announced a strategic partnership with Alpen Labs in
  October 2025 to use Glock as Starknet's BTC bridge primitive
- **No mainnet deployment yet.** Strata's BitVM2 bridge runs on
  Bitcoin signet only as of 2026-05; Glock transition is on the
  roadmap, not live.
- Research is active and the academic peer-review pipeline
  is moving — multiple follow-up papers (Mosaic, Argo) build on or
  refine Glock's primitives.

**What this means for zkCoins.** Glock is the **most attractive 2026
alternative** to BitVM2 if zkCoins is willing to wait. Its 1-of-N
trust model is identical to BitVM2's; its on-chain cost is 100–1000×
lower; and the construction is by the same team that wrote the
Shielded CSV paper (Eagen, Linus). The fit is essentially perfect.

The risk: it has not yet been deployed on mainnet by anyone. Glock
**does require a circuit-specific trusted setup** — its DV-SNARK is
instantiated with Pari (Eagen et al., eprint 2024/1245), and the
Pari paper states explicitly: *"Pari requires a circuit-specific
trusted setup, but the relevant prior work (namely, Groth16) also
requires such a setup."* So the setup-coordination burden is
comparable to BitVM2/Groth16, not eliminated. The advantage of
Glock over BitVM2 is on-chain efficiency and proof size (Pari is
the smallest known SNARK at 160 bytes), not setup transparency.

### 12.5 Mosaic — Practical Malicious Security for Garbled Circuits on Bitcoin (Eagen et al., 2026-04)

**Paper:** [eprint 2026/812](https://eprint.iacr.org/2026/812),
Khambhati, Tiwari, Bajracharya, Bista, Eagen, Lewe, Feickert.

**Core idea.** Where Glock uses DV-SNARKs to achieve compactness,
Mosaic stays with traditional Groth16 verifier circuit but achieves
malicious security via **cut-and-choose with polynomial label
correlation**. The trick: labels across all N garbled copies are
arranged as evaluations of a degree-t polynomial. The t shares
revealed during cut-and-choose fall one short of the reconstruction
threshold. Adaptor signatures ensure that the prover's on-chain
witness commitment reveals the missing share as a byproduct. The
evaluator can then reconstruct labels for all unchallenged copies by
interpolation.

**Killer feature.** The on-chain footprint is **independent of N**
(the number of garbled copies used for cut-and-choose). Other
cut-and-choose constructions need to post per-copy data on-chain
that scales with N. Mosaic eliminates this scaling.

**Practical.** Full protocol specification, Rust implementation,
instantiated for trust-minimized Bitcoin bridging with a Groth16
verifier circuit.

**Status (2026-05).**

- Paper published April 2026
- Rust implementation exists (open-source per paper)
- No production deployment yet
- Same author family as Glock and Shielded CSV (Eagen)
- Cleanly compatible with the existing Groth16-verifier ecosystem
  (Plonky2 → Groth16 wrapping pipeline that Citrea uses works
  unchanged)

**What this means for zkCoins.** Mosaic is **the cleanest drop-in
replacement** for BitVM2 because it keeps Groth16 as the verifier and
therefore reuses the entire BitVM2 toolchain (trusted setup ceremony,
Groth16 prover tools, `chainwayxyz/bitvm-zk-verifier`). It just cuts
the Assert transaction footprint by a large factor.

The risk: it's the youngest of the three (April 2026 paper). Has not
seen the same testnet hours as Glock or production hours as BitVM2.

### 12.6 Production state of major BitVM bridges (2026-05)

| Bridge | Side-system | Construction | Status |
| ------ | ----------- | ------------ | ------ |
| Clementine | Citrea | BitVM2 | **Mainnet since 2026-01-27** |
| GOAT Network bridge | GOAT Network | BitVM2 variant | **Testnet V3 since 2026-01-28** (permissionless-exit-first design) |
| Strata bridge | Alpen | BitVM2 (Glock transition planned) | **Signet only**, 10 BTC fixed denomination, 64-block operator timeout, 36-block challenge |
| BOB bridge | BOB | BitVM3-CC | Mainnet demo (cost-reduction proof of concept) |
| Bitlayer bridge | Bitlayer | BitVM2 variant | Mainnet |

**Reading guide.** As of May 2026, **only BitVM2 (and direct variants)
have any mainnet exposure**. Everything garbled-circuit-based —
BitVM3-CC, Glock, Mosaic — is at most demo or testnet. This will
likely change over Q3–Q4 2026 as Strata and BOB push their Glock /
BitVM3-CC bridges toward mainnet.

### 12.7 Strategic implication for zkCoins

If we were starting bridge implementation **today**:

- BitVM2 / Clementine fork. Battle-tested, mainnet-proven, with
  reusable trusted setup output. Trade-off: 2.6 MB Assert tx (~$60–200
  at common fee rates).

If we were starting bridge implementation **in Q3–Q4 2026**:

- Wait for Strata's Glock transition or BOB's BitVM3-CC mainnet
  hardening, then fork from there. Trade-off: more time before
  zkCoins has a bridge, much cheaper on-chain dispute resolution.

If we want to **hedge**:

- Implement against an abstract "garbled-bridge-verifier" trait, with
  BitVM2 as the v1 implementation and Glock/Mosaic as drop-in
  replacements when one of them stabilises. The circuit-side
  `IssuanceProof` and `BurnProof` contracts (§4) are identical in
  any case — only the off-circuit Bitcoin scripting changes.

The hedge is probably the right answer if implementation does not
have to start this quarter. If implementation must start now and
mainnet within a year, BitVM2 is forced.

### 12.8 The "BTC denomination" question

A practical note often overlooked: BitVM-family bridges typically
require **fixed-denomination deposits** because the pre-signed
transaction graph is parameterised on the deposit amount. Strata
uses 10 BTC fixed denomination on testnet; Citrea uses similar
quantisation on mainnet.

For zkCoins, this means peg-ins would come in fixed chunks (e.g.,
0.1 BTC, 1 BTC, 10 BTC) rather than arbitrary amounts. Users wanting
smaller amounts would peg in 0.1 BTC and split internally; users
wanting larger amounts would peg in multiple chunks.

This is a UX consideration, not a protocol constraint. The Lightning
swap design (`LIGHTNING_ATOMIC_SWAP.md`) is unaffected — it operates
on arbitrary amounts because it consumes/produces zkCoins state
which has no minimum increment.

---

## 13. Bottom Line

- **D11 is the biggest unaddressed trust gap in zkCoins.** It is more
  significant than D2 (recipient hiding), D7 (reorg safety), or D8
  (per-coin nullifier) for an end-user-trust perspective. A user can
  tolerate a small privacy gap or a small reorg-safety gap; they
  cannot tolerate "the issuer can print unlimited supply".

- **BitVM2 / Clementine is the only mainnet-deployed trustless bridge
  as of 2026-05.** Citrea has been live since 2026-01-27. Tooling,
  trusted setup ceremony output, and operational documentation all
  exist. If a bridge must ship within 12 months, this is the only
  feasible cryptographic option.

- **Glock and Mosaic are the credible 2026 successors** (both authored
  by the Eagen line of researchers, same family as Shielded CSV
  itself). Glock is the 430–550× more efficient alternative using
  DV-SNARKs (Alpen Labs, Strata bridge transition planned); Mosaic
  keeps Groth16 but cuts on-chain footprint independently of N
  cut-and-choose copies (April 2026 paper with Rust impl). Neither
  has mainnet exposure yet. See §12 for the full landscape.

- **BitVM3-RSA was withdrawn** after security flaws were identified
  by Eagen / Fairgate. The "BitVM3" name continues under the BitVM3-CC
  (cut-and-choose) variant, which is what BOB demonstrated on mainnet.

- **The realistic short-term path is a Liquid-style federated
  bridge.** It is implementable in months, provides meaningful
  trust distribution, and can be upgraded to BitVM2 / Glock / Mosaic
  later without protocol-layer changes — the `IssuanceProof` and
  `BurnProof` circuit contracts (§4) are agnostic to the bridge
  construction.

- **The realistic 1-year cryptographic path is BitVM2.** Federation
  recruitment and trusted setup ceremony coordination are the
  bottleneck, not engineering.

- **The realistic 2-year cryptographic path is Glock or Mosaic.** If
  bridge implementation can wait into 2027, the on-chain efficiency
  upgrade is worth the wait. The hedge: build the circuit side now,
  pick the verifier construction when one of Glock/Mosaic has 6+
  months of testnet history.

- **`LIGHTNING_ATOMIC_SWAP.md` is unaffected.** The swap design's
  mathematical atomicity holds regardless of how mints work. What
  changes is the supply-side honesty of the underlying asset.

- **D11 fix belongs in the pre-mainnet hardening block of `ROADMAP.md`.**
  Currently it is not listed there. This is a documentation gap that
  should be corrected.

- **Federation target: N=100 independent members.** The MVP runs with
  N=3 (same data centre, all operated by a single organisation —
  engineering correctness only, not real trust distribution). The
  production target is
  N=100, the practical upper bound of the BitVM2 framework today per
  Bitlayer's analysis (*"in practice the value of n can be 100"*).
  Strict 1-of-N honesty: 1 honest key deletion among 100 independent
  setup members suffices. Going beyond N=100 is open research
  (Bitlayer: *"It is necessary to research a permissionless
  multi-party OP challenge protocol that could expand BitVM's
  existing 1-of-n trust model to 1-of-N, where N is much larger
  than n"*) and not a current goal. Federation-member recruitment
  to N=100 is business-development, not engineering. Intermediate
  milestones expected: N=10 → N=30 → N=100. See `BRIDGE_MVP.md` §2.2.

---

## 14. References

### BitVM2 and Clementine (production-grade)
- [BitVM2 paper (Linus, Aumayr, Avarikioti, Maffei, Moreno-Sanchez, eprint 2025/1158)](https://eprint.iacr.org/2025/1158.pdf)
- [BitVM2 site](https://bitvm.org/bitvm2.html)
- [Citrea Clementine bridge docs](https://docs.citrea.xyz/essentials/clementine-trust-minimized-bitcoin-bridge)
- [Citrea Risc0-to-BitVM Trusted Setup Ceremony announcement](https://www.blog.citrea.xyz/citrea-completes-the-first-ever-trusted-setup-ceremony-for-zk-proofs-used-in-bitvm/)
- [BitVM Groth16 Verifier Toolkit (chainwayxyz)](https://github.com/chainwayxyz/bitvm-zk-verifier)
- [BitVM GitHub org](https://github.com/BitVM/BitVM)
- [Fairgate review of BitVM2 Linus24 bridge](https://www.fairgate.io/post/3-a-review-of-the-the-bitvm2-based-linus24-bridge)
- [Bitlayer BitVM bridge analysis](https://blog.bitlayer.org/BitVM_Bridge_Becomes_Practical/)

### BitVM3 and cut-and-choose successors
- [BitVM3 paper (eprint 2026/933)](https://eprint.iacr.org/2026/933.pdf) — includes both withdrawn RSA construction and cut-and-choose variants
- [BOB BitVM3 cut-and-choose announcement](https://www.gobob.xyz/blog/bob-lowers-onchain-costs-for-bitvm3)
- [Fairgate Computing on Bitcoin newsletter](https://www.fairgate.io/newsletter/) — ongoing coverage

### Glock (Alpen Labs)
- [Glock: Garbled Locks for Bitcoin (Eagen, eprint 2025/1485)](https://eprint.iacr.org/2025/1485)
- [Glock paper PDF mirror (Alpen)](https://cdn.prod.website-files.com/67cfca80708eb505376820af/68a3e174eaff71d197ac4080_glock.pdf)
- [Glock: A new standard for verification on Bitcoin (Alpen blog)](https://www.alpenlabs.io/blog/glock-verification-on-bitcoin)
- [Efficient verifiable cut-and-choose for Glock (Alpen HackMD)](https://hackmd.io/@alpen/B1QfSSO5gg)
- [Starknet × Alpen partnership announcement (Glock as Starknet BTC bridge)](https://www.starknet.io/blog/starknet-alpen-bitcoin-glock/)
- [Strata bridge docs (currently BitVM2)](https://docs.alpenlabs.io/how-alpen-works/bitcoin-bridge)

### Mosaic
- [Mosaic: Practical Malicious Security for Garbled Circuits on Bitcoin (eprint 2026/812)](https://eprint.iacr.org/2026/812)

### Survey / market context
- [Bitcoin L2s in 2026: A Reality Check (hozk.io)](https://www.hozk.io/articles/bitcoin-l2s-in-2026-a-reality-check)
- [State of Bitcoin: BitVM3, Glock & Bitcoin Dollar (Bitfinity)](https://www.blog.bitfinity.network/state-of-bitcoin-bitvm3-glock-bitcoin-dollar/)

### Shielded CSV / zkCoins context
- [Shielded CSV paper §"Issuance" predicate branch](https://eprint.iacr.org/2025/068)
- `SPEC.md` §15 D11 — this repo
- `MIGRATION_RESEARCH.md` §5.6 — self-funded MVP publisher

---

## 15. Change Log

| Date | Change |
| ---- | ------ |
| 2026-05-17 | Initial draft. |
| 2026-05-17 | Add §12 "Beyond BitVM2 — 2026 Verification Landscape" covering BitVM3-RSA withdrawal, BitVM3-CC (BOB), Glock (Alpen Labs), Mosaic (Eagen et al.). Update §3 with 2026-landscape note. Update §11.1 / §11.2 / §11.3 comparison tables. Update §13 Bottom Line with hedging strategy. Refactor references into themed groups. |
| 2026-05-17 | §13 Bottom Line: add explicit production federation target of N=100 (practical upper bound of BitVM2 framework per Bitlayer). Beyond N=100 noted as open research, not current goal. |
| 2026-05-17 | Consistency audit pass: §12.4 — correct the Glock trusted-setup claim (Glock's DV-SNARK is instantiated with Pari which requires a circuit-specific trusted setup, comparable to Groth16; the previous "the DV-SNARK might not require a setup" wording was wrong). Add a branch note at the top explaining that `SPEC.md` / `MIGRATION_RESEARCH.md` / `ROADMAP.md` currently live on `feat/plonky2-migration` only. |
| 2026-05-17 | Audit round 2: §6.2 Step 1 — fix proof-name inconsistency ("WithdrawalProof" was a one-off term; renamed to `BurnProof` consistent with §6.3 and §4.1) and correct the §5.2 cross-reference to §6.3. |
| 2026-05-17 | Audit round 3: harmonise header structure (Status / Authoritative source / Audience / Branch note). Remove organisation-specific "DFX" references in §4.5, §8.1, §8.4, §10.4, §11.1, and §13 — replaced with generic operator/issuer wording for consistency with the rest of the repo. |
